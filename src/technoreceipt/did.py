from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MULTICODEC_ED25519_PUB = b"\xed\x01"
_SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}")


def _b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _ALPHABET[remainder] + encoded
    zeroes = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * zeroes + (encoded or ("" if zeroes else "1"))


def _b58decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + _ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\0" * zeroes + raw


def public_did(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "did:key:z" + _b58encode(_MULTICODEC_ED25519_PUB + raw)


def public_key_from_did(did: str) -> Ed25519PublicKey:
    prefix = "did:key:z"
    if not did.startswith(prefix):
        raise ValueError("expected an Ed25519 did:key")
    decoded = _b58decode(did[len(prefix) :])
    if not decoded.startswith(_MULTICODEC_ED25519_PUB) or len(decoded) != 34:
        raise ValueError("unsupported or malformed did:key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def create_key(path: Path, passphrase: bytes) -> str:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing key: {path}")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    path.chmod(0o600)
    return public_did(key.public_key())


def load_key(path: Path, passphrase: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("key is not Ed25519")
    return key


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_receipt(unsigned: dict, key: Ed25519PrivateKey) -> dict:
    payload = canonical_bytes(unsigned)
    signature = base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("=")
    return {
        **unsigned,
        "proof": {
            "algorithm": "Ed25519",
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "signature": signature,
        },
    }


def verify_receipt(receipt: dict) -> None:
    proof = receipt.get("proof")
    signer = receipt.get("signer")
    if not isinstance(proof, dict) or not isinstance(signer, str):
        raise TypeError("receipt is missing signer or proof")
    if proof.get("algorithm") != "Ed25519":
        raise ValueError("unsupported proof algorithm")
    unsigned = {key: value for key, value in receipt.items() if key != "proof"}
    payload = canonical_bytes(unsigned)
    if hashlib.sha256(payload).hexdigest() != proof.get("payload_sha256"):
        raise ValueError("payload hash mismatch")
    signature_text = proof.get("signature")
    if not isinstance(signature_text, str) or not _SIGNATURE_RE.fullmatch(signature_text):
        raise ValueError("malformed Ed25519 signature")
    signature = base64.urlsafe_b64decode(signature_text + "==")
    public_key_from_did(signer).verify(signature, payload)
