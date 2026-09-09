import base64
import hashlib

from nacl.bindings import crypto_sign_seed_keypair
from nacl.signing import SigningKey

seed = hashlib.sha256(b"sshspan-test-seed-v1").digest()
pk, sk = crypto_sign_seed_keypair(seed)
key_id = hashlib.blake2b(pk, digest_size=8).digest()
sk_obj = SigningKey(seed)
assert bytes(sk_obj.verify_key) == pk


def make_sig(data, tc_body=b"sshspan-updater-test"):
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


print("PUB_B64:", base64.b64encode(b"Ed" + key_id + pk).decode())
print("=== SIG good (payload) ===")
print(make_sig(b"SSHSpan minisign unit-test payload"))
print("=== SIG for other blob ===")
print(make_sig(b"tampered bytes"))
