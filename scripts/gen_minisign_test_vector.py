"""Regenerates the minisign vectors the updater tests use.

The vectors live in src-tauri/src/commands/updater.rs (TEST_MINISIGN_PUBKEY,
TEST_SIG_GOOD, TEST_SIG_OTHER_BLOB, TEST_SIG_RELEASE_1_8_0). They are signed
with a fixed-seed Ed25519 key, so the output is deterministic.

    python scripts/gen_minisign_test_vector.py
        print every vector, including the release-comment vector
    python scripts/gen_minisign_test_vector.py --release-tag v1.9.1
        print the release-comment vector for another tag instead of v1.8.0
    python scripts/gen_minisign_test_vector.py --check [PATH]
        compare the generated vectors with the constants in updater.rs (or in
        PATH) and exit 1 on any difference

Needs PyNaCl (`pip install pynacl`).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys

from nacl.bindings import crypto_sign_seed_keypair
from nacl.signing import SigningKey

seed = hashlib.sha256(b"sshspan-test-seed-v1").digest()
pk, sk = crypto_sign_seed_keypair(seed)
key_id = hashlib.blake2b(pk, digest_size=8).digest()
sk_obj = SigningKey(seed)
assert bytes(sk_obj.verify_key) == pk

# The payloads the updater tests sign (TEST_BLOB, and the "other" blob that
# must fail against it).
TEST_BLOB = b"SSHSpan minisign unit-test payload"
OTHER_BLOB = b"tampered bytes"
# The tag the release-comment test vector is signed for.
TEST_RELEASE_TAG = "v1.8.0"
DEFAULT_UPDATER_RS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "src-tauri",
    "src",
    "commands",
    "updater.rs",
)


def make_sig(data: bytes, tc_body: bytes = b"sshspan-updater-test") -> str:
    blake = hashlib.blake2b(data, digest_size=64).digest()
    s = sk_obj.sign(blake)
    sig = bytes(s.signature)
    g = sk_obj.sign(sig + tc_body)
    gsig = bytes(g.signature)
    return (
        "untrusted comment: signature from minisign secret key\n"
        + base64.b64encode(b"ED" + key_id + sig).decode()
        + "\ntrusted comment: "
        + tc_body.decode()
        + "\n"
        + base64.b64encode(gsig).decode()
    )


def release_comment(tag: str) -> bytes:
    """The trusted comment the release workflow signs every installer with.

    release.yml runs `minisign -t "SSHSpan release ${GITHUB_REF_NAME}"`, and the
    updater (release_trusted_comment in updater.rs) requires exactly
    "SSHSpan release v<version>" for the release the download URL names, so a
    validly signed older build cannot be installed as a newer one.
    """
    return b"SSHSpan release v" + tag.strip().lstrip("v").encode()


def pub_b64() -> str:
    return base64.b64encode(b"Ed" + key_id + pk).decode()


def vectors() -> dict[str, str]:
    """Constant name in updater.rs -> the text the tests expect."""
    return {
        "TEST_MINISIGN_PUBKEY": pub_b64(),
        "TEST_SIG_GOOD": make_sig(TEST_BLOB),
        "TEST_SIG_OTHER_BLOB": make_sig(OTHER_BLOB),
        "TEST_SIG_RELEASE_1_8_0": make_sig(TEST_BLOB, release_comment(TEST_RELEASE_TAG)),
    }


def check(path: str) -> int:
    """Compare every vector with its constant in the Rust source; 0 when all match."""
    with open(path, encoding="utf-8") as f:
        # rustc reads a CRLF inside a string literal as LF.
        source = f.read().replace("\r\n", "\n")
    status = 0
    for name, want in vectors().items():
        found = re.search(r'const %s: &str = "([^"]*)";' % name, source)
        if not found:
            print("MISSING   %s: no such constant in %s" % (name, path))
            status = 1
        elif found.group(1) != want:
            print("MISMATCH  %s" % name)
            print("  generated: %r" % want)
            print("  in file:   %r" % found.group(1))
            status = 1
        else:
            print("ok        %s" % name)
    return status


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Regenerate the updater's minisign test vectors.")
    parser.add_argument(
        "--release-tag",
        default=TEST_RELEASE_TAG,
        help="tag for the release-comment vector (default: %(default)s, the one the tests use)",
    )
    parser.add_argument(
        "--check",
        nargs="?",
        const=DEFAULT_UPDATER_RS,
        metavar="PATH",
        help="compare with the constants in updater.rs (or PATH) instead of printing",
    )
    args = parser.parse_args(argv)
    if args.check is not None:
        return check(args.check)

    print("PUB_B64:", pub_b64())
    print("=== SIG good (payload) ===")
    print(make_sig(TEST_BLOB))
    print("=== SIG for other blob ===")
    print(make_sig(OTHER_BLOB))
    print("=== SIG with the release trusted comment (%s) ===" % args.release_tag)
    print(make_sig(TEST_BLOB, release_comment(args.release_tag)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
