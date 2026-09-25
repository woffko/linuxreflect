//! Command-line option parsing shared by the CLI and the daemon (spec §J.1).
//!
//! The daemon receives the same strings the CLI accepts (a chunk size, a
//! compression spec, a member type), so both must parse them identically;
//! putting the parsers here is what keeps the two front ends from drifting.

use std::path::Path;

use lr_core::{Error, Result};

use crate::backup::{BadSectorPolicy, Compression, MemberType};
use crate::keys::Encryption;
use crate::keystore::{load_passphrase_file, passphrase_file_path, resolve_passphrase};

/// Parse `512KiB`, `4MiB`, `1GiB` or a plain byte count.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a malformed or overflowing size.
pub fn parse_size(text: &str) -> Result<u64> {
    let text = text.trim();
    let (digits, multiplier) = if let Some(rest) = text.strip_suffix("GiB") {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = text.strip_suffix("MiB") {
        (rest, 1024 * 1024)
    } else if let Some(rest) = text.strip_suffix("KiB") {
        (rest, 1024)
    } else if let Some(rest) = text.strip_suffix('B') {
        (rest, 1)
    } else {
        (text, 1)
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| Error::unsupported(format!("`{text}` is not a size (try `1MiB`)")))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| Error::unsupported(format!("size `{text}` overflows")))
}

/// Parse `zstd:<level>` or `none`.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown scheme or a level outside the
/// format's range.
pub fn parse_compression(text: &str) -> Result<Compression> {
    let text = text.trim().to_ascii_lowercase();
    if text == "none" {
        return Ok(Compression::None);
    }
    let level = text
        .strip_prefix("zstd:")
        .ok_or_else(|| Error::unsupported("compression must be `zstd:<level>` or `none`"))?;
    let level: i32 = level
        .parse()
        .map_err(|_| Error::unsupported(format!("`{level}` is not a zstd level")))?;
    if !(lr_format::MIN_ZSTD_LEVEL..=lr_format::MAX_ZSTD_LEVEL).contains(&level) {
        return Err(Error::unsupported(format!(
            "zstd level {level} is outside {}..={}",
            lr_format::MIN_ZSTD_LEVEL,
            lr_format::MAX_ZSTD_LEVEL
        )));
    }
    Ok(Compression::Zstd { level })
}

/// Parse `full`, `incremental` or `differential`.
///
/// # Errors
/// Returns [`Error::Unsupported`] for any other value.
pub fn parse_member_type(text: &str) -> Result<MemberType> {
    match text.trim().to_ascii_lowercase().as_str() {
        "" | "full" => Ok(MemberType::Full),
        "incremental" => Ok(MemberType::Incremental),
        "differential" => Ok(MemberType::Differential),
        other => Err(Error::unsupported(format!(
            "`{other}` is not a chain member type (full, incremental, differential)"
        ))),
    }
}

/// Parse `abort` or `record`.
///
/// # Errors
/// Returns [`Error::Unsupported`] for any other value.
pub fn parse_bad_sector(text: &str) -> Result<BadSectorPolicy> {
    match text.trim().to_ascii_lowercase().as_str() {
        "" | "abort" => Ok(BadSectorPolicy::Abort),
        "record" => Ok(BadSectorPolicy::Record),
        other => Err(Error::unsupported(format!(
            "`{other}` is not a bad-sector policy (abort, record)"
        ))),
    }
}

/// The provider name from `--snapshot`, ignoring `auto`.
#[must_use]
/// Imaging mode selection (spec §D.1, §J.1 `--mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Choose from the source: a directory becomes a file image.
    Auto,
    /// Fixed chunks over used blocks.
    Block,
    /// CDC chunks over a `btrfs send` stream.
    Stream,
    /// CDC chunks per file over a directory tree.
    File,
}

/// Parse a `--mode` value.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown mode name.
pub fn parse_mode(text: &str) -> Result<Mode> {
    match text {
        "" | "auto" => Ok(Mode::Auto),
        "block" => Ok(Mode::Block),
        "stream" => Ok(Mode::Stream),
        "file" => Ok(Mode::File),
        other => Err(Error::unsupported(format!(
            "unknown mode `{other}`; use auto, block, stream or file"
        ))),
    }
}

/// Parse a `--snapshot` value; `auto` and an empty string mean "decide".
#[must_use]
pub fn parse_snapshot(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || text == "auto" {
        None
    } else {
        Some(text.to_owned())
    }
}

/// Encryption for a new image: `--no-encrypt` or a passphrase file.
///
/// # Errors
/// Propagates passphrase-file errors.
pub fn backup_encryption(no_encrypt: bool, passphrase_file: Option<&Path>) -> Result<Encryption> {
    if no_encrypt {
        return Ok(Encryption::NoEncrypt);
    }
    let passphrase = resolve_passphrase(passphrase_file)?;
    Ok(Encryption::Passphrase(passphrase))
}

/// Encryption for reading an image: a passphrase only when one is configured.
///
/// The superblock records whether the image is encrypted, so a missing
/// passphrase is reported by the engine with a clear message.
///
/// # Errors
/// Propagates passphrase-file errors.
pub fn restore_encryption(passphrase_file: Option<&Path>) -> Result<Encryption> {
    match passphrase_file_path(passphrase_file) {
        Some(path) => Ok(Encryption::Passphrase(load_passphrase_file(&path)?)),
        None => Ok(Encryption::NoEncrypt),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_bad_sector, parse_compression, parse_member_type, parse_size, parse_snapshot,
    };
    use crate::backup::{BadSectorPolicy, Compression, MemberType};

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("1MiB").expect("size"), 1024 * 1024);
        assert_eq!(parse_size(" 256KiB").expect("size"), 256 * 1024);
        assert_eq!(parse_size("4096B").expect("size"), 4096);
        assert_eq!(parse_size("42").expect("size"), 42);
        assert!(parse_size("4MiBx").is_err());
        assert!(parse_size("9999999999999999999999GiB").is_err());
    }

    #[test]
    fn compression_parses() {
        assert_eq!(parse_compression("none").expect("none"), Compression::None);
        assert_eq!(
            parse_compression("zstd:9").expect("zstd"),
            Compression::Zstd { level: 9 }
        );
        assert_eq!(
            parse_compression(" ZSTD:3 ").expect("zstd"),
            Compression::Zstd { level: 3 }
        );
        assert!(parse_compression("zstd:99").is_err());
        assert!(parse_compression("lz4").is_err());
    }

    #[test]
    fn member_types_and_policies_parse() {
        assert_eq!(parse_member_type("full").expect("full"), MemberType::Full);
        assert_eq!(
            parse_member_type("Incremental").expect("incr"),
            MemberType::Incremental
        );
        assert_eq!(
            parse_member_type("differential").expect("diff"),
            MemberType::Differential
        );
        assert!(parse_member_type("synthetic").is_err());
        assert_eq!(
            parse_bad_sector("record").expect("record"),
            BadSectorPolicy::Record
        );
        assert_eq!(
            parse_bad_sector("abort").expect("abort"),
            BadSectorPolicy::Abort
        );
        assert!(parse_bad_sector("ignore").is_err());
    }

    #[test]
    fn snapshot_auto_means_none() {
        assert_eq!(parse_snapshot("auto"), None);
        assert_eq!(parse_snapshot(""), None);
        assert_eq!(parse_snapshot(" lvm "), Some("lvm".to_owned()));
    }
}
