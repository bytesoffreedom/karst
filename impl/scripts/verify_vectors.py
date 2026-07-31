#!/usr/bin/env python3
"""An INDEPENDENT reading of KARST's ratchet key schedule (QA-4).

This file exists to disagree with the Rust implementation when the two readings differ. It shares
no code with it: HKDF and HMAC are built here from `hashlib` alone, and every constant below was
transcribed from the written rules rather than from the Rust source, so a misread specification
shows up as a mismatch instead of as two implementations being confidently wrong together.

That distinction is the entire point. A test written by the author of the code inherits the
author's misunderstanding — it catches a typo and cannot catch a misconception, because both sides
of its comparison come from the same reading.

Scope, and why it stops where it does: ChaCha20-Poly1305 is not in the Python standard library, and
importing a package would put a third party's reading of RFC 8439 exactly where an independent
reading is meant to be. HKDF-SHA256 and HMAC-SHA256 are stdlib, so the derivation chain is covered
in full — and the derivation chain is where a misreading is both most likely and most silent, since
wrong keys agree with themselves forever.

Usage: verify_vectors.py <vectors.json>   (exit 0 = agreement, 1 = disagreement)
"""
import hashlib
import hmac as _hmac
import json
import sys

# ── The rules, transcribed ───────────────────────────────────────────────────
# Ratchet key schedule (crypto/src/ratchet.rs documents each of these):
#   routing_contrib : HKDF-SHA256(salt=none, ikm=dh)  info="karst-routing-contrib-v1"  -> 32
#   KDF_RK          : HKDF-SHA256(salt=rk,   ikm=dh)  info="KARST-ratchet-rk-v1"       -> 64
#                     split as (new_rk, chain_key)
#   KDF_CK          : mk = HMAC-SHA256(ck, 0x01) ; next_ck = HMAC-SHA256(ck, 0x02)
#   message_aead    : HKDF-SHA256(salt=header_salt, ikm=mk) info="KARST-ratchet-msg-v2" -> 44
#                     split as (key[32], nonce[12])
#   AAD             : b"KARST-ratchet-v2" || dh[32] || pn:u32-LE || n:u32-LE || salt[16]
ROUTING_INFO = b"karst-routing-contrib-v1"
RK_INFO = b"KARST-ratchet-rk-v1"
MSG_INFO = b"KARST-ratchet-msg-v2"
AAD_DOMAIN = b"KARST-ratchet-v2"
SALT_LEN = 16


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hkdf(salt: bytes | None, ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869. `salt=None` means HashLen zero bytes, matching `Hkdf::new(None, ikm)`.

    Worth recording that this particular detail CANNOT be got wrong: HMAC zero-pads any key
    shorter than its block size, so an empty salt and 32 zero bytes are the same key. I first
    wrote this docstring claiming the two differ, tried to prove it by breaking the check, and the
    check correctly refused to fail. Verifying a claim can also correct the claim."""
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac_sha256(salt, ikm)
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def derive(name: str) -> str:
    """Recompute one named vector. Inputs mirror the fixed test inputs on the Rust side."""
    rk, dh, ck, mk = b"\x11" * 32, b"\x22" * 32, b"\x33" * 32, b"\x44" * 32
    salt = b"\x55" * SALT_LEN

    if name == "routing_contrib":
        return hkdf(None, dh, ROUTING_INFO, 32).hex()
    if name.startswith("kdf_rk."):
        okm = hkdf(rk, dh, RK_INFO, 64)
        return (okm[:32] if name.endswith("new_rk") else okm[32:]).hex()
    if name == "kdf_ck.mk":
        return hmac_sha256(ck, b"\x01").hex()
    if name == "kdf_ck.next_ck":
        return hmac_sha256(ck, b"\x02").hex()
    if name.startswith("message_aead."):
        okm = hkdf(salt, mk, MSG_INFO, 44)
        return (okm[:32] if name.endswith("key") else okm[32:44]).hex()
    if name == "aad":
        header_dh = b"\x66" * 32
        pn = (0x01020304).to_bytes(4, "little")
        n = (0x05060708).to_bytes(4, "little")
        return (AAD_DOMAIN + header_dh + pn + n + salt).hex()
    raise KeyError(f"no independent derivation for {name!r} — a vector was added without one")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1]) as f:
        vectors = json.load(f)
    if not vectors:
        print("FAIL: no vectors — a file that verifies nothing must not pass")
        return 1

    bad = 0
    for name, expected in sorted(vectors.items()):
        got = derive(name)
        if got != expected:
            print(f"DISAGREE {name}\n  rust:   {expected}\n  python: {got}")
            bad += 1
    if bad:
        print(f"\n{bad} of {len(vectors)} vectors differ. One of the two readings is wrong — and "
              f"which one is not decidable from here, so do not simply regenerate the file.")
        return 1
    print(f"{len(vectors)} vectors agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
