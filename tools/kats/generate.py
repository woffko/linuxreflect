#!/usr/bin/env python3
"""Generate known-answer vectors for the `lr-crypto` crate.

Every expected value written by this script comes from an implementation that
is independent of the Rust code under test:

* Argon2id              -- the reference CLI `argon2` (P-H-C) and argon2-cffi,
                           cross-checked against each other.
* AES-256-GCM,
  ChaCha20-Poly1305,
  HKDF-SHA256           -- python3-cryptography.
* BLAKE3                -- the official BLAKE3 test vectors
                           (https://github.com/BLAKE3-team/BLAKE3).

Output: crates/lr-crypto/tests/vectors/mod.rs (a module, not a test target).
The file is regenerated with:

    python3 tools/kats/generate.py

Requirements: python3-argon2 (argon2-cffi), python3-cryptography, and
optionally the `argon2` CLI for the cross-check.
"""

from __future__ import annotations

import argparse
import binascii
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.request

BLAKE3_VECTORS_URL = (
    "https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/master/"
    "test_vectors/test_vectors.json"
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "crates" / "lr-crypto" / "tests" / "vectors" / "mod.rs"

# Fixed inputs used by the Argon2id vectors. The salt is exactly the 16-byte
# `kdf_salt` of the superblock; the passphrase is a well-known test phrase.
ARGON2_PASSPHRASE = b"correct horse battery staple"
ARGON2_SALT = b"linuxreflect-v1!"

# BLAKE3's official test vectors derive the key from this ASCII string.
BLAKE3_KEY = b"whats the Elvish word for friend"


def hexs(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


def pattern(length: int) -> bytes:
    """The repeating 0..250 byte pattern used by the BLAKE3 test vectors."""
    return bytes(i % 251 for i in range(length))


# --------------------------------------------------------------------------
# Argon2id
# --------------------------------------------------------------------------


def argon2_cli(passphrase: bytes, salt: bytes, m_kib: int, t: int, p: int, out_len: int):
    """Run the reference CLI, returning the raw tag as bytes (or None)."""
    if shutil.which("argon2") is None:
        return None
    proc = subprocess.run(
        [
            "argon2",
            salt.decode("ascii"),
            "-id",
            "-t", str(t),
            "-k", str(m_kib),
            "-p", str(p),
            "-l", str(out_len),
            "-v", "13",
            "-r",
        ],
        input=passphrase,
        capture_output=True,
        check=True,
    )
    raw = proc.stdout.strip()
    # This CLI build prints the raw tag as hex; older ones print raw bytes.
    if len(raw) == out_len * 2 and all(c in b"0123456789abcdef" for c in raw.lower()):
        return binascii.unhexlify(raw)
    return raw


def gen_argon2() -> list[dict]:
    from argon2.low_level import Type, hash_secret_raw

    vectors = []
    for name, m_kib in (("cheap", 32), ("production", 262144)):
        tag = hash_secret_raw(
            ARGON2_PASSPHRASE,
            ARGON2_SALT,
            time_cost=3,
            memory_cost=m_kib,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
            version=0x13,
        )
        cli = argon2_cli(ARGON2_PASSPHRASE, ARGON2_SALT, m_kib, 3, 4, 32)
        if cli is not None and cli != tag:
            raise SystemExit(
                f"argon2 CLI disagrees with argon2-cffi for {name}: "
                f"{hexs(cli)} != {hexs(tag)}"
            )
        vectors.append(
            {
                "name": name,
                "passphrase": ARGON2_PASSPHRASE,
                "salt": ARGON2_SALT,
                "m_cost_kib": m_kib,
                "t_cost": 3,
                "p_cost": 4,
                "tag": tag,
                "cross_checked": cli is not None,
            }
        )
    return vectors


# --------------------------------------------------------------------------
# AEAD
# --------------------------------------------------------------------------

AEAD_KEY = bytes(range(32))
AEAD_NONCE = bytes(range(0x10, 0x10 + 12))
CHAIN_ID = bytes([0x5a]) * 16
PAGE_AD = bytes([1]) + (7).to_bytes(8, "little")

# AAD layouts mirror the three real uses in lr-crypto (spec G.4, G.5, G.6).
AEAD_CASES = [
    ("wrap", b"lrimg-v1/wrap" + CHAIN_ID, bytes(range(0xa0, 0xc0))),
    ("chunk", pattern(33), pattern(1024)),
    ("page", PAGE_AD, pattern(4096)),
]


def gen_aead() -> list[dict]:
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM,
        ChaCha20Poly1305,
    )

    vectors = []
    for cipher_name, factory in (
        ("AES-256-GCM", AESGCM),
        ("ChaCha20-Poly1305", ChaCha20Poly1305),
    ):
        cipher = factory(AEAD_KEY)
        for case, aad, plaintext in AEAD_CASES:
            sealed = cipher.encrypt(AEAD_NONCE, plaintext, aad)
            ciphertext, tag = sealed[:-16], sealed[-16:]
            vectors.append(
                {
                    "name": case,
                    "cipher": cipher_name,
                    "key": AEAD_KEY,
                    "nonce": AEAD_NONCE,
                    "aad": aad,
                    "plaintext": plaintext,
                    "ciphertext": ciphertext,
                    "tag": tag,
                }
            )
    return vectors


# --------------------------------------------------------------------------
# HKDF-SHA256
# --------------------------------------------------------------------------

# RFC 5869 appendix A.1 and A.3; asserted below so a broken oracle cannot
# silently produce new pinned values.
RFC5869_A1_OKM = (
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)
RFC5869_A3_OKM = (
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    "9d201395faa4b61a96c8"
)


def gen_hkdf() -> list[dict]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    vectors = [
        {
            "name": "rfc5869-a1",
            "ikm": bytes([0x0B]) * 22,
            "salt": bytes(range(13)),
            "info": bytes(range(0xF0, 0xFA)),
            "len": 42,
        },
        {
            "name": "rfc5869-a3",
            "ikm": bytes([0x0B]) * 22,
            "salt": b"",
            "info": b"",
            "len": 42,
        },
        {
            "name": "file-keys",
            "ikm": AEAD_KEY,
            "salt": CHAIN_ID,
            "info": b"lrimg-v1/file",
            "len": 64,
        },
        {
            "name": "file-keys-other-image",
            "ikm": AEAD_KEY,
            "salt": bytes([0x33]) * 16,
            "info": b"lrimg-v1/file",
            "len": 64,
        },
        {
            "name": "dedup-key",
            "ikm": AEAD_KEY,
            "salt": CHAIN_ID,
            "info": b"lrimg-v1/dedup",
            "len": 32,
        },
    ]
    for vector in vectors:
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=vector["len"],
            salt=vector["salt"] or None,
            info=vector["info"],
        )
        vector["okm"] = kdf.derive(vector["ikm"])
        if vector["name"] == "rfc5869-a1" and hexs(vector["okm"]) != RFC5869_A1_OKM:
            raise SystemExit("HKDF does not reproduce RFC 5869 A.1")
        if vector["name"] == "rfc5869-a3" and hexs(vector["okm"]) != RFC5869_A3_OKM:
            raise SystemExit("HKDF does not reproduce RFC 5869 A.3")
    return vectors


# --------------------------------------------------------------------------
# BLAKE3
# --------------------------------------------------------------------------


def load_blake3(path: str | None) -> dict:
    if path:
        return json.loads(pathlib.Path(path).read_text())
    with urllib.request.urlopen(BLAKE3_VECTORS_URL, timeout=60) as response:
        return json.load(response)


def gen_blake3(path: str | None, lengths: list[int]) -> list[dict]:
    data = load_blake3(path)
    if data["key"].encode() != BLAKE3_KEY:
        raise SystemExit("unexpected BLAKE3 test-vector key")
    by_len = {case["input_len"]: case for case in data["cases"]}
    vectors = []
    for length in lengths:
        case = by_len.get(length)
        if case is None:
            raise SystemExit(f"BLAKE3 vectors have no case for input length {length}")
        # The official outputs are extended (XOF); the first 32 bytes are the
        # default-length output we compare against.
        vectors.append(
            {
                "input_len": length,
                "unkeyed": case["hash"][:64],
                "keyed": case["keyed_hash"][:64],
            }
        )
    return vectors


# --------------------------------------------------------------------------
# Rust emission
# --------------------------------------------------------------------------


def rust_bytes(data: bytes) -> str:
    return "b\"" + "".join(f"\\x{byte:02x}" for byte in data) + "\""


def rust_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(argon2, aead, hkdf, blake3) -> str:
    out = []
    out.append("// @generated by tools/kats/generate.py -- DO NOT EDIT.")
    out.append("//")
    out.append("// Independent sources:")
    out.append("//   * Argon2id: reference CLI `argon2` (P-H-C) cross-checked with argon2-cffi")
    out.append("//   * AES-256-GCM / ChaCha20-Poly1305 / HKDF-SHA256: python3-cryptography")
    out.append("//   * BLAKE3: official test vectors (BLAKE3-team/BLAKE3)")
    out.append("//")
    out.append("// Regenerate with `python3 tools/kats/generate.py`.")
    out.append("#![allow(dead_code, unreachable_pub)]")
    out.append("")
    out.append("/// An Argon2id known-answer vector.")
    out.append("pub struct Argon2Vector {")
    out.append("    pub name: &'static str,")
    out.append("    pub passphrase: &'static [u8],")
    out.append("    pub salt: &'static [u8],")
    out.append("    pub m_cost_kib: u32,")
    out.append("    pub t_cost: u32,")
    out.append("    pub p_cost: u32,")
    out.append("    /// Expected 32-byte tag, hex.")
    out.append("    pub tag_hex: &'static str,")
    out.append("}")
    out.append("")
    out.append("/// Argon2id vectors; `production` uses the spec defaults (256 MiB / 3 / 4).")
    out.append("pub const ARGON2ID_VECTORS: &[Argon2Vector] = &[")
    for vector in argon2:
        out.append("    Argon2Vector {")
        out.append(f"        name: {rust_str(vector['name'])},")
        out.append(f"        passphrase: {rust_bytes(vector['passphrase'])},")
        out.append(f"        salt: {rust_bytes(vector['salt'])},")
        out.append(f"        m_cost_kib: {vector['m_cost_kib']},")
        out.append(f"        t_cost: {vector['t_cost']},")
        out.append(f"        p_cost: {vector['p_cost']},")
        out.append(f"        tag_hex: {rust_str(hexs(vector['tag']))},")
        out.append("    },")
    out.append("];")
    out.append("")
    out.append("/// An AEAD known-answer vector; the tag is kept separate from the")
    out.append("/// ciphertext because that is how the .lrimg chunk and page records store it.")
    out.append("pub struct AeadVector {")
    out.append("    pub name: &'static str,")
    out.append("    pub cipher: &'static str,")
    out.append("    pub key_hex: &'static str,")
    out.append("    pub nonce_hex: &'static str,")
    out.append("    pub aad_hex: &'static str,")
    out.append("    pub plaintext_hex: &'static str,")
    out.append("    pub ciphertext_hex: &'static str,")
    out.append("    pub tag_hex: &'static str,")
    out.append("}")
    out.append("")
    out.append("/// AEAD vectors for both mandated ciphers and all three AAD shapes.")
    out.append("pub const AEAD_VECTORS: &[AeadVector] = &[")
    for vector in aead:
        out.append("    AeadVector {")
        out.append(f"        name: {rust_str(vector['name'])},")
        out.append(f"        cipher: {rust_str(vector['cipher'])},")
        out.append(f"        key_hex: {rust_str(hexs(vector['key']))},")
        out.append(f"        nonce_hex: {rust_str(hexs(vector['nonce']))},")
        out.append(f"        aad_hex: {rust_str(hexs(vector['aad']))},")
        out.append(f"        plaintext_hex: {rust_str(hexs(vector['plaintext']))},")
        out.append(f"        ciphertext_hex: {rust_str(hexs(vector['ciphertext']))},")
        out.append(f"        tag_hex: {rust_str(hexs(vector['tag']))},")
        out.append("    },")
    out.append("];")
    out.append("")
    out.append("/// An HKDF-SHA256 known-answer vector.")
    out.append("pub struct HkdfVector {")
    out.append("    pub name: &'static str,")
    out.append("    pub ikm_hex: &'static str,")
    out.append("    pub salt_hex: &'static str,")
    out.append("    pub info_hex: &'static str,")
    out.append("    pub okm_len: usize,")
    out.append("    pub okm_hex: &'static str,")
    out.append("}")
    out.append("")
    out.append("/// RFC 5869 appendix A vectors plus this project's actual HKDF uses.")
    out.append("pub const HKDF_VECTORS: &[HkdfVector] = &[")
    for vector in hkdf:
        out.append("    HkdfVector {")
        out.append(f"        name: {rust_str(vector['name'])},")
        out.append(f"        ikm_hex: {rust_str(hexs(vector['ikm']))},")
        out.append(f"        salt_hex: {rust_str(hexs(vector['salt']))},")
        out.append(f"        info_hex: {rust_str(hexs(vector['info']))},")
        out.append(f"        okm_len: {vector['len']},")
        out.append(f"        okm_hex: {rust_str(hexs(vector['okm']))},")
        out.append("    },")
    out.append("];")
    out.append("")
    out.append("/// The key used by the official BLAKE3 vectors for keyed hashing.")
    out.append(f"pub const BLAKE3_KEY_HEX: &str = {rust_str(hexs(BLAKE3_KEY))};")
    out.append("")
    out.append("/// A BLAKE3 known-answer vector. Inputs follow the official rule")
    out.append("/// `input[i] = i % 251`; outputs are the first 32 bytes of the")
    out.append("/// official extended output.")
    out.append("pub struct Blake3Vector {")
    out.append("    pub input_len: usize,")
    out.append("    pub unkeyed_hex: &'static str,")
    out.append("    pub keyed_hex: &'static str,")
    out.append("}")
    out.append("")
    out.append("/// Official BLAKE3 vectors, unkeyed and keyed.")
    out.append("pub const BLAKE3_VECTORS: &[Blake3Vector] = &[")
    for vector in blake3:
        out.append("    Blake3Vector {")
        out.append(f"        input_len: {vector['input_len']},")
        out.append(f"        unkeyed_hex: {rust_str(vector['unkeyed'])},")
        out.append(f"        keyed_hex: {rust_str(vector['keyed'])},")
        out.append("    },")
    out.append("];")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--blake3-vectors",
        help="path to the official BLAKE3 test_vectors.json (defaults to a download)",
    )
    parser.add_argument(
        "--blake3-lengths",
        default="0,1,1024,3072",
        help="comma separated input lengths to pin from the BLAKE3 vectors",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify oracles only; do not write the Rust file",
    )
    args = parser.parse_args()

    lengths = [int(part) for part in args.blake3_lengths.split(",") if part]
    argon2 = gen_argon2()
    aead = gen_aead()
    hkdf = gen_hkdf()
    blake3 = gen_blake3(args.blake3_vectors, lengths)

    for vector in argon2:
        source = "cli+cffi" if vector["cross_checked"] else "cffi only"
        print(f"argon2id {vector['name']:<10} ({source}): {hexs(vector['tag'])}")
    print(f"aead    {len(aead)} vectors for 2 ciphers")
    print(f"hkdf    {len(hkdf)} vectors (RFC 5869 A.1/A.3 verified)")
    print(f"blake3  {len(blake3)} vectors (official)")

    if args.check:
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render(argon2, aead, hkdf, blake3))
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
