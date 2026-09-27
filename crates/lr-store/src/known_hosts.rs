//! `known_hosts` host-key verification (spec §B, §L.1).
//!
//! An SSH connection is only as trustworthy as the server key it is pinned to,
//! so an unknown host is refused unless the user explicitly opted out. The file
//! format is OpenSSH's: `host[,host] keytype base64`, with `[host]:port` for
//! non-default ports and `|1|salt|hash` (HMAC-SHA1) for hashed host names,
//! which is what `HashKnownHosts yes` writes by default on Debian and Ubuntu.
//!
//! As in OpenSSH, a line applies to a host only through a positive pattern,
//! and a matching `!pattern` excludes the host from that line. A key on a
//! matching `@revoked` line is refused wherever the line stands, a
//! `@cert-authority` line trusts no plain key (certificates are not
//! supported), and any other marker makes the file unusable (R13).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use lr_core::{Error, Result};
use sha1::Sha1;

/// What a line's leading `@` marker says about its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// No marker: the key is trusted for the hosts.
    None,
    /// `@revoked`: the key must never be accepted for the hosts.
    Revoked,
    /// `@cert-authority`: the key signs host certificates, which are not
    /// supported, so it trusts nothing here.
    CertAuthority,
}

/// One usable `known_hosts` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The line's marker.
    pub marker: Marker,
    /// Host patterns, or one hashed pattern (`|1|salt|hash`).
    pub hosts: BTreeSet<String>,
    /// Key algorithm name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// Base64 key blob.
    pub blob: String,
}

/// Verifies server keys against a `known_hosts` file.
pub struct HostKeyVerifier {
    entries: Vec<Entry>,
    host: String,
    port: u16,
    insecure: bool,
}

impl std::fmt::Debug for HostKeyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostKeyVerifier")
            .field("entries", &self.entries.len())
            .field("host", &self.host)
            .field("port", &self.port)
            .field("insecure", &self.insecure)
            .finish()
    }
}

impl HostKeyVerifier {
    /// Load the verifier for one server.
    ///
    /// `known_hosts` defaults to `~/.ssh/known_hosts`; a missing file merely
    /// means every host is unknown (and therefore refused).
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when verification is required but no path
    /// can be determined, and propagates read errors other than "not found".
    pub fn load(host: &str, port: u16, known_hosts: Option<&Path>, insecure: bool) -> Result<Self> {
        if insecure {
            tracing::warn!(
                host,
                "host-key verification is disabled; the connection can be intercepted"
            );
            return Ok(Self {
                entries: Vec::new(),
                host: host.to_owned(),
                port,
                insecure: true,
            });
        }
        let path = match known_hosts {
            Some(path) => path.to_path_buf(),
            None => default_known_hosts().ok_or_else(|| {
                Error::unsupported(
                    "no known_hosts file: pass --known-hosts or set HOME; \
                     use --insecure-ignore-host-key only for tests",
                )
            })?,
        };
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => parse(&text)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(Error::Io(error)),
        };
        Ok(Self {
            entries,
            host: host.to_owned(),
            port,
            insecure: false,
        })
    }

    /// `true` when this key may be trusted for the server: a line without a
    /// marker lists it for the host, and no `@revoked` line does.
    #[must_use]
    pub fn verify(&self, algorithm: &str, blob: &str) -> bool {
        if self.insecure {
            return true;
        }
        let mut trusted = false;
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.matches(&self.host, self.port, algorithm, blob))
        {
            match entry.marker {
                Marker::Revoked => {
                    tracing::error!(host = %self.host, "the server key is revoked in known_hosts");
                    return false;
                }
                Marker::None => trusted = true,
                Marker::CertAuthority => {}
            }
        }
        trusted
    }

    /// The file this verifier was built from, for diagnostics.
    #[must_use]
    pub fn explain(&self) -> String {
        if self.insecure {
            return "host-key verification disabled".to_owned();
        }
        format!("{} entries for {}", self.entries.len(), self.host)
    }
}

impl Entry {
    fn matches(&self, host: &str, port: u16, algorithm: &str, blob: &str) -> bool {
        if self.algorithm != algorithm || self.blob != blob {
            return false;
        }
        if self.hosts.iter().any(|pattern| pattern.starts_with("|1|")) {
            return self
                .hosts
                .iter()
                .any(|pattern| hashed_matches(pattern, host, port));
        }
        // A negated pattern that matches excludes the host; otherwise the
        // host needs a positive pattern (OpenSSH `match_hostname`).
        let mut positive = false;
        for pattern in &self.hosts {
            match pattern.strip_prefix('!') {
                Some(negated) if plain_matches(negated, host, port) => return false,
                Some(_) => {}
                None => positive |= plain_matches(pattern, host, port),
            }
        }
        positive
    }
}

/// Match a `host` or `[host]:port` pattern.
fn plain_matches(pattern: &str, host: &str, port: u16) -> bool {
    if let Some(inner) = pattern.strip_prefix('[').and_then(|p| p.split_once(']')) {
        let (name, rest) = inner;
        let pattern_port = rest.strip_prefix(':').and_then(|p| p.parse().ok());
        return name == host && pattern_port == Some(port);
    }
    // An unqualified name matches any port.
    glob_matches(pattern, host)
}

fn glob_matches(pattern: &str, host: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == host,
        Some((prefix, suffix)) => {
            host.starts_with(prefix)
                && host.ends_with(suffix)
                && host.len() >= prefix.len() + suffix.len()
        }
    }
}

/// Verify a `|1|salt|hash` line: HMAC-SHA1(salt, hostname).
fn hashed_matches(pattern: &str, host: &str, port: u16) -> bool {
    let mut parts = pattern.split('|');
    if parts.next() != Some("") || parts.next() != Some("1") {
        return false;
    }
    let (Some(salt), Some(expected)) = (parts.next(), parts.next()) else {
        return false;
    };
    let Ok(salt) = base64_decode(salt) else {
        return false;
    };
    let candidates = [host.to_owned(), format!("[{host}]:{port}")];
    candidates.iter().any(|candidate| {
        let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else {
            return false;
        };
        mac.update(candidate.as_bytes());
        base64_encode(&mac.finalize().into_bytes()) == expected
    })
}

fn default_known_hosts() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".ssh/known_hosts"))
}

/// Parse a `known_hosts` file, ignoring comments and lines without a key.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a marker other than `@revoked` and
/// `@cert-authority`: a line whose meaning is unknown must not be skipped,
/// because it might have been meant to revoke a key.
pub fn parse(text: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut marker = Marker::None;
        if line.starts_with('@') {
            let (word, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            marker = match word {
                "@revoked" => Marker::Revoked,
                "@cert-authority" => Marker::CertAuthority,
                other => {
                    return Err(Error::unsupported(format!(
                        "known_hosts line {} has the unknown marker {other}; refusing to \
                         guess what it means",
                        number + 1
                    )));
                }
            };
            line = rest.trim_start();
        }
        let mut fields = line.split_whitespace();
        let (Some(hosts), Some(algorithm), Some(blob)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        entries.push(Entry {
            marker,
            hosts: hosts.split(',').map(str::to_owned).collect(),
            algorithm: algorithm.to_owned(),
            blob: blob.to_owned(),
        });
    }
    Ok(entries)
}

/// Minimal base64 (standard alphabet, padding optional) for `known_hosts`.
fn base64_decode(text: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let Some(value) = ALPHABET.iter().position(|candidate| *candidate == byte) else {
            return Err(Error::corrupt("known_hosts contains invalid base64"));
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut buffer = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            buffer |= u32::from(*byte) << (16 - index * 8);
        }
        for index in 0..4 {
            if index <= chunk.len() {
                let value = (buffer >> (18 - index * 6)) & 0x3f;
                out.push(ALPHABET[value as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{HostKeyVerifier, base64_decode, base64_encode, parse};

    const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIK6l7f5m1c0k1Q9m0M7yQ0SgYI3Xc2f4b1m6oX9r";
    const OTHER: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKeyBlobForTheSameServer1111";

    fn verifier(text: &str, host: &str, port: u16) -> HostKeyVerifier {
        let entries = parse(text).expect("parse");
        HostKeyVerifier {
            entries,
            host: host.to_owned(),
            port,
            insecure: false,
        }
    }

    #[test]
    fn plain_entries_match_host_and_port() {
        let text = format!("nas.local ssh-ed25519 {ED25519}\n");
        let checker = verifier(&text, "nas.local", 22);
        assert!(checker.verify("ssh-ed25519", ED25519));
        assert!(
            !checker.verify("ssh-ed25519", OTHER),
            "a different key is refused"
        );
        assert!(!verifier(&text, "other.local", 22).verify("ssh-ed25519", ED25519));

        let ported = format!("[nas.local]:2222 ssh-ed25519 {ED25519}\n");
        assert!(verifier(&ported, "nas.local", 2222).verify("ssh-ed25519", ED25519));
        assert!(
            !verifier(&ported, "nas.local", 22).verify("ssh-ed25519", ED25519),
            "a port-qualified entry only matches that port"
        );
    }

    #[test]
    fn multiple_hosts_and_wildcards_are_supported() {
        let text =
            format!("nas.local,nas ssh-ed25519 {ED25519}\n*.example.com ssh-ed25519 {ED25519}\n");
        assert!(verifier(&text, "nas", 22).verify("ssh-ed25519", ED25519));
        assert!(verifier(&text, "a.example.com", 22).verify("ssh-ed25519", ED25519));
        assert!(!verifier(&text, "example.com", 22).verify("ssh-ed25519", ED25519));
    }

    #[test]
    fn hashed_entries_match() {
        // Hash the way OpenSSH does: HMAC-SHA1(salt, host), base64.
        let salt = b"0123456789abcdef";
        let hash = {
            use hmac::{Mac as _, digest::KeyInit as _};
            let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(salt).expect("hmac");
            mac.update(b"nas.local");
            base64_encode(&mac.finalize().into_bytes())
        };
        let text = format!(
            "|1|{}|{} ssh-ed25519 {ED25519}\n",
            base64_encode(salt),
            hash
        );
        assert!(verifier(&text, "nas.local", 22).verify("ssh-ed25519", ED25519));
        assert!(!verifier(&text, "other.local", 22).verify("ssh-ed25519", ED25519));
    }

    #[test]
    fn comments_are_skipped() {
        let entries = parse("# comment\n\n").expect("parse");
        assert!(entries.is_empty());
    }

    /// A line matches only through a positive pattern, and a matching
    /// negated pattern excludes the host whatever else the line says (R13).
    #[test]
    fn negations_exclude_and_never_include() {
        let text = format!("!evil.local,*.local ssh-ed25519 {ED25519}\n");
        assert!(verifier(&text, "nas.local", 22).verify("ssh-ed25519", ED25519));
        assert!(
            !verifier(&text, "evil.local", 22).verify("ssh-ed25519", ED25519),
            "a negated host is excluded although *.local matches it"
        );
        let only_negated = format!("!evil.local ssh-ed25519 {ED25519}\n");
        assert!(
            !verifier(&only_negated, "nas.local", 22).verify("ssh-ed25519", ED25519),
            "a line without a positive match trusts nobody"
        );
    }

    /// A revoked key is refused wherever its line stands (R13).
    #[test]
    fn a_revoked_key_is_refused_in_any_order() {
        for text in [
            format!("nas.local ssh-ed25519 {ED25519}\n@revoked nas.local ssh-ed25519 {ED25519}\n"),
            format!("@revoked nas.local ssh-ed25519 {ED25519}\nnas.local ssh-ed25519 {ED25519}\n"),
            format!("@revoked * ssh-ed25519 {ED25519}\nnas.local ssh-ed25519 {ED25519}\n"),
        ] {
            assert!(
                !verifier(&text, "nas.local", 22).verify("ssh-ed25519", ED25519),
                "{text}"
            );
        }
        let other_revoked =
            format!("@revoked nas.local ssh-ed25519 {OTHER}\nnas.local ssh-ed25519 {ED25519}\n");
        assert!(verifier(&other_revoked, "nas.local", 22).verify("ssh-ed25519", ED25519));
    }

    /// A certificate authority line does not trust a plain key, and an
    /// unknown marker makes the file unusable instead of being skipped (R13).
    #[test]
    fn markers_fail_closed() {
        let authority = format!("@cert-authority *.local ssh-ed25519 {ED25519}\n");
        assert!(!verifier(&authority, "nas.local", 22).verify("ssh-ed25519", ED25519));
        let unknown = format!("@trusted nas.local ssh-ed25519 {ED25519}\n");
        let error = parse(&unknown).expect_err("an unknown marker is refused");
        assert!(error.to_string().contains("@trusted"), "{error}");
    }

    #[test]
    fn base64_round_trips() {
        for input in [&b""[..], b"a", b"ab", b"abc", b"abcd", &[0xff; 12]] {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode(&encoded).expect("decode"), input, "{encoded}");
        }
    }

    #[test]
    fn insecure_mode_accepts_everything_but_says_so() {
        let checker = HostKeyVerifier {
            entries: Vec::new(),
            host: "nas.local".to_owned(),
            port: 22,
            insecure: true,
        };
        assert!(checker.verify("ssh-ed25519", OTHER));
        assert!(checker.explain().contains("disabled"));
    }
}
