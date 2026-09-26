//! Streaming guarantees for large manifests (spec §K S4: a 100 GiB manifest
//! must be written with streamed pages, and this test tightens that to 16 TB).
//!
//! The sink below discards every sealed page, so peak memory is the only thing
//! this test measures: `VmHWM` must not grow by more than a small fraction of
//! the manifest it wrote.

use lr_core::Result;
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_crypto::page::StreamId;
use lr_format::{BlockEntry, BlockManifestHeader, ENTRY_LEN, PageSink, PageStream, STATE_STORED};

const META_KEY: [u8; 32] = [0x44; 32];
const KIND: AeadKind = AeadKind::Aes256Gcm;

/// A page sink that keeps nothing but counters.
struct CountingSink {
    pages: u64,
    ciphertext_bytes: u64,
    page_numbers_seen: u64,
    last_page_no: Option<u64>,
    nonces: NonceSeq,
}

impl Default for CountingSink {
    fn default() -> Self {
        Self {
            pages: 0,
            ciphertext_bytes: 0,
            page_numbers_seen: 0,
            last_page_no: None,
            nonces: NonceSeq::new(),
        }
    }
}

impl PageSink for CountingSink {
    fn write_page(&mut self, _stream: StreamId, page_no: u64, page: &[u8]) -> Result<()> {
        if let Some(last) = self.last_page_no {
            assert_eq!(page_no, last + 1, "page numbers must be consecutive");
        }
        self.last_page_no = Some(page_no);
        self.page_numbers_seen += 1;
        self.pages += 1;
        self.ciphertext_bytes += page.len() as u64;
        Ok(())
    }

    fn meta_nonces(&mut self) -> &mut NonceSeq {
        &mut self.nonces
    }
}

fn vm_hwm_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .expect("VmHWM value");
        }
    }
    panic!("VmHWM missing from /proc/self/status");
}

fn header_block() -> BlockManifestHeader {
    BlockManifestHeader {
        chunk_size: 1024 * 1024,
        chunk_count: 0,
        entry_count: 0,
        used_extent_count: 0,
        used_bytes: 0,
        fs_type: "ext4".to_owned(),
        fs_uuid: String::new(),
        label: String::new(),
    }
}

/// Write `entries` chunk entries and return the sink plus the payload bytes the
/// stream produced.
fn stream_entries(entries: u64) -> (CountingSink, u64) {
    let mut header = header_block();
    header.chunk_count = entries;
    header.entry_count = entries;

    // The header is tiny; measuring it separately lets the assertion be exact.
    let mut header_bytes = Vec::new();
    header.write(&mut header_bytes, false).expect("header");

    let mut sink = CountingSink::default();
    {
        let mut stream = PageStream::new(&mut sink, StreamId::Manifest, KIND, META_KEY);
        stream.write(&header_bytes).expect("header");
        let entry = BlockEntry {
            state: STATE_STORED,
            member: 0,
            hash: [0x5a; 32],
            offset: 4096,
            stored_len: 1024,
        };
        // Write in batches: the page-splitting path is identical, but the test
        // spends its time in the codec instead of in per-call overhead.
        const BATCH: u64 = 4096;
        let encoded = entry.encode().expect("entry");
        let mut batch = Vec::with_capacity(BATCH as usize * ENTRY_LEN);
        for _ in 0..BATCH {
            batch.extend_from_slice(&encoded);
        }
        let mut remaining = entries;
        while remaining > 0 {
            let take = remaining.min(BATCH) as usize;
            stream.write(&batch[..take * ENTRY_LEN]).expect("entries");
            remaining -= take as u64;
        }
        stream.finish().expect("finish");
    }
    (sink, header_bytes.len() as u64 + entries * ENTRY_LEN as u64)
}

/// Exactly how many payload bytes a block manifest of `entries` needs.
fn expected_payload(entries: u64) -> u64 {
    let mut header = header_block();
    header.chunk_count = entries;
    header.entry_count = entries;
    let mut bytes = Vec::new();
    header.write(&mut bytes, false).expect("header");
    bytes.len() as u64 + entries * ENTRY_LEN as u64
}

#[test]
fn entries_written_one_by_one_produce_the_same_bytes() {
    // Small enough to write entry by entry, which is how the engine does it.
    const ENTRIES: u64 = 1000;
    let expected = expected_payload(ENTRIES);
    let mut sink = CountingSink::default();
    {
        let mut header = header_block();
        header.chunk_count = ENTRIES;
        header.entry_count = ENTRIES;
        let mut stream = PageStream::new(&mut sink, StreamId::Manifest, KIND, META_KEY);
        header.write(&mut stream, false).expect("header");
        let entry = BlockEntry {
            state: STATE_STORED,
            member: 0,
            hash: [0x5a; 32],
            offset: 4096,
            stored_len: 1024,
        };
        for _ in 0..ENTRIES {
            entry.write(&mut stream).expect("entry");
        }
        stream.finish().expect("finish");
    }
    assert_eq!(
        sink.ciphertext_bytes,
        expected + sink.pages * (lr_crypto::page::PAGE_OVERHEAD as u64)
    );
}

/// 16 TiB at 1 MiB chunks. Ignored by default because the unoptimised dev
/// profile encrypts the 736 MiB manifest at only a few MB/s; run it as
/// `cargo test -p lr-format --release --test streaming -- --ignored --nocapture`.
#[test]
#[ignore = "large; run with --release"]
fn a_sixteen_terabyte_manifest_streams_in_constant_memory() {
    // 16 TiB at 1 MiB chunks is 16 777 216 entries, about 736 MiB of manifest.
    const ENTRIES: u64 = 16 * 1024 * 1024;
    let before = vm_hwm_kib();
    let (sink, payload) = stream_entries(ENTRIES);
    let after = vm_hwm_kib();

    assert_eq!(payload, expected_payload(ENTRIES));
    let expected_pages = payload.div_ceil(lr_format::DEFAULT_PAGE_LEN as u64);
    assert_eq!(sink.pages, expected_pages, "one page per 1 MiB of manifest");
    assert_eq!(sink.page_numbers_seen, sink.pages);
    assert_eq!(
        sink.ciphertext_bytes,
        payload + sink.pages * (lr_crypto::page::PAGE_OVERHEAD as u64),
        "every payload byte plus per-page overhead must have been written"
    );
    assert!(
        sink.ciphertext_bytes > 700 * 1024 * 1024,
        "the manifest is large"
    );

    let growth_kib = after.saturating_sub(before);
    assert!(
        growth_kib < 128 * 1024,
        "peak RSS grew by {growth_kib} KiB while streaming {payload} bytes; \
         streamed pages must not be buffered"
    );
}

#[test]
fn the_spec_100_gib_case_is_written_completely() {
    // 100 GiB at 1 MiB chunks is 102 400 entries.
    const ENTRIES: u64 = 100 * 1024;
    let expected = expected_payload(ENTRIES);
    let (sink, payload) = stream_entries(ENTRIES);
    assert_eq!(
        payload, expected,
        "header plus 46 bytes per entry, nothing else"
    );
    assert_eq!(
        sink.pages,
        payload.div_ceil(lr_format::DEFAULT_PAGE_LEN as u64)
    );
    assert!(payload < 8 * 1024 * 1024, "a 100 GiB manifest is a few MiB");
}
