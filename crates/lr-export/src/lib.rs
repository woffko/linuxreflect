//! Read-only block export (spec §B, §K S13).
//!
//! Two halves: a newstyle NBD server ([`nbd`]) that serves a
//! [`backend::BlockBackend`] read-only, and the kernel side ([`session`]) that
//! attaches it with `nbd-client` and mounts the filesystem with the read-only
//! options the spec prescribes. `lr-cli export mount` and the daemon's
//! `ExportImage` both drive these.

pub mod backend;
pub mod nbd;
pub mod session;

pub use backend::{BlockBackend, FileBackend, ImageBackend};
pub use nbd::{ExportConfig, serve_connection, serve_unix};
pub use session::{ExportState, mount_options, mount_read_only, unmount};

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use crate::backend::BlockBackend;
    use crate::nbd::{
        CMD_DISC, CMD_READ, CMD_WRITE, ERR_PERM, ExportConfig, FLAG_C_FIXED_NEWSTYLE,
        FLAG_C_NO_ZEROES, FLAG_READ_ONLY, IHAVEOPT, NBDMAGIC, OPT_GO, OPT_INFO, REP_ACK, REP_MAGIC,
        REQUEST_MAGIC, SIMPLE_REPLY_MAGIC,
    };

    /// A backend with a known byte pattern.
    struct Pattern {
        size: u64,
    }

    impl BlockBackend for Pattern {
        fn size_bytes(&self) -> u64 {
            self.size
        }

        fn read_at(&self, offset: u64, buffer: &mut [u8]) -> lr_core::Result<()> {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = ((offset + index as u64) % 251) as u8;
            }
            Ok(())
        }
    }

    fn put_u16(stream: &mut UnixStream, value: u16) {
        stream.write_all(&value.to_be_bytes()).expect("write");
    }

    fn put_u32(stream: &mut UnixStream, value: u32) {
        stream.write_all(&value.to_be_bytes()).expect("write");
    }

    fn put_u64(stream: &mut UnixStream, value: u64) {
        stream.write_all(&value.to_be_bytes()).expect("write");
    }

    fn get_u16(stream: &mut UnixStream) -> u16 {
        let mut bytes = [0u8; 2];
        stream.read_exact(&mut bytes).expect("read");
        u16::from_be_bytes(bytes)
    }

    fn get_u32(stream: &mut UnixStream) -> u32 {
        let mut bytes = [0u8; 4];
        stream.read_exact(&mut bytes).expect("read");
        u32::from_be_bytes(bytes)
    }

    fn get_u64(stream: &mut UnixStream) -> u64 {
        let mut bytes = [0u8; 8];
        stream.read_exact(&mut bytes).expect("read");
        u64::from_be_bytes(bytes)
    }

    fn start_server(size: u64, config: ExportConfig) -> (UnixStream, std::thread::JoinHandle<()>) {
        let (client, server) = UnixStream::pair().expect("pair");
        let backend: Arc<dyn BlockBackend> = Arc::new(Pattern { size });
        let stop = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn(move || {
            crate::nbd::serve_connection(server, backend, &config, &stop).expect("serve");
        });
        (client, handle)
    }

    /// Drive the handshake and choose the export with `NBD_OPT_GO`.
    fn negotiate(stream: &mut UnixStream, name: &str) {
        assert_eq!(get_u64(stream), NBDMAGIC);
        assert_eq!(get_u64(stream), IHAVEOPT);
        let _flags = get_u16(stream);
        put_u32(stream, FLAG_C_FIXED_NEWSTYLE | FLAG_C_NO_ZEROES);
        // NBD_OPT_GO with an INFO_EXPORT request.
        put_u64(stream, IHAVEOPT);
        put_u32(stream, OPT_GO);
        let mut data = Vec::new();
        data.extend_from_slice(&(name.len() as u32).to_be_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        put_u32(stream, data.len() as u32);
        stream.write_all(&data).expect("write");

        // REP_INFO (export size + flags) then REP_ACK.
        assert_eq!(get_u64(stream), REP_MAGIC);
        assert_eq!(get_u32(stream), OPT_GO);
        assert_eq!(get_u32(stream), crate::nbd::REP_INFO);
        let length = get_u32(stream);
        let mut payload = vec![0u8; length as usize];
        stream.read_exact(&mut payload).expect("read");
        assert_eq!(get_u64(stream), REP_MAGIC);
        assert_eq!(get_u32(stream), OPT_GO);
        assert_eq!(get_u32(stream), REP_ACK);
        assert_eq!(get_u32(stream), 0);
    }

    fn read_command(stream: &mut UnixStream, handle: u64, offset: u64, length: u32) -> Vec<u8> {
        put_u32(stream, REQUEST_MAGIC);
        put_u16(stream, 0);
        put_u16(stream, CMD_READ);
        put_u64(stream, handle);
        put_u64(stream, offset);
        put_u32(stream, length);
        assert_eq!(get_u32(stream), SIMPLE_REPLY_MAGIC);
        assert_eq!(get_u32(stream), 0, "read error");
        assert_eq!(get_u64(stream), handle);
        let mut data = vec![0u8; length as usize];
        stream.read_exact(&mut data).expect("read");
        data
    }

    #[test]
    fn a_go_negotiation_serves_reads() {
        let (mut client, server) = start_server(1024 * 1024, ExportConfig::default());
        negotiate(&mut client, "");
        let data = read_command(&mut client, 7, 100, 64);
        for (index, byte) in data.iter().enumerate() {
            assert_eq!(*byte, ((100 + index as u64) % 251) as u8);
        }
        request_disc(&mut client);
        server.join().expect("join");
    }

    fn request_disc(stream: &mut UnixStream) {
        put_u32(stream, REQUEST_MAGIC);
        put_u16(stream, 0);
        put_u16(stream, CMD_DISC);
        put_u64(stream, 1);
        put_u64(stream, 0);
        put_u32(stream, 0);
        stream.flush().expect("flush");
    }

    #[test]
    fn writes_are_refused_and_read_only_is_advertised() {
        let (mut client, server) = start_server(64 * 1024, ExportConfig::default());
        negotiate(&mut client, "");
        // WRITE must come back with EPERM and no data.
        put_u32(&mut client, REQUEST_MAGIC);
        put_u16(&mut client, 0);
        put_u16(&mut client, CMD_WRITE);
        put_u64(&mut client, 11);
        put_u64(&mut client, 0);
        put_u32(&mut client, 512);
        assert_eq!(get_u32(&mut client), SIMPLE_REPLY_MAGIC);
        assert_eq!(get_u32(&mut client), ERR_PERM);
        assert_eq!(get_u64(&mut client), 11);
        request_disc(&mut client);
        server.join().expect("join");
    }

    #[test]
    fn the_export_advertises_read_only() {
        let config = ExportConfig::default();
        assert_ne!(config.transmission_flags() & FLAG_READ_ONLY, 0);
        let writable = ExportConfig {
            read_only: false,
            ..ExportConfig::default()
        };
        assert_eq!(writable.transmission_flags() & FLAG_READ_ONLY, 0);
    }

    #[test]
    fn info_negotiation_works_without_go() {
        let (mut client, server) = start_server(4096, ExportConfig::default());
        assert_eq!(get_u64(&mut client), NBDMAGIC);
        assert_eq!(get_u64(&mut client), IHAVEOPT);
        let _flags = get_u16(&mut client);
        put_u32(&mut client, FLAG_C_FIXED_NEWSTYLE | FLAG_C_NO_ZEROES);
        // NBD_OPT_INFO with no requested infos still answers with ACK.
        put_u64(&mut client, IHAVEOPT);
        put_u32(&mut client, OPT_INFO);
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        put_u32(&mut client, data.len() as u32);
        client.write_all(&data).expect("write");
        // A zero info count means the default set, which starts with the
        // export size. `nbd-client` relies on this.
        let mut saw_export = false;
        let mut saw_block_size = false;
        loop {
            assert_eq!(get_u64(&mut client), REP_MAGIC);
            assert_eq!(get_u32(&mut client), OPT_INFO);
            let reply = get_u32(&mut client);
            let length = get_u32(&mut client);
            let mut payload = vec![0u8; length as usize];
            client.read_exact(&mut payload).expect("read");
            if reply == REP_ACK {
                break;
            }
            assert_eq!(reply, crate::nbd::REP_INFO);
            // A `NBD_REP_INFO` payload begins with the info type.
            let info = u16::from_be_bytes([payload[0], payload[1]]);
            match info {
                crate::nbd::INFO_EXPORT => {
                    assert_eq!(u64::from_be_bytes(payload[2..10].try_into().unwrap()), 4096);
                    saw_export = true;
                }
                crate::nbd::INFO_BLOCK_SIZE => saw_block_size = true,
                other => panic!("unexpected info type {other}"),
            }
        }
        assert!(saw_export, "the default set must include the export size");
        assert!(saw_block_size, "and the block sizes");
        // Still in the option loop: now GO.
        put_u64(&mut client, IHAVEOPT);
        put_u32(&mut client, OPT_GO);
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        put_u32(&mut client, data.len() as u32);
        client.write_all(&data).expect("write");
        assert_eq!(get_u64(&mut client), REP_MAGIC);
        assert_eq!(get_u32(&mut client), OPT_GO);
        assert_eq!(get_u32(&mut client), crate::nbd::REP_INFO);
        let length = get_u32(&mut client);
        let mut payload = vec![0u8; length as usize];
        client.read_exact(&mut payload).expect("read");
        assert_eq!(get_u64(&mut client), REP_MAGIC);
        assert_eq!(get_u32(&mut client), OPT_GO);
        assert_eq!(get_u32(&mut client), REP_ACK);
        let _ = get_u32(&mut client);
        request_disc(&mut client);
        server.join().expect("join");
    }
}
