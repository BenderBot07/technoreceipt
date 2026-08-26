from __future__ import annotations

import re
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .did import public_did, sign_receipt

_GITHUB_USER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")


def create_github_binding(github_user: str, key: Ed25519PrivateKey) -> dict:
    """Bind one GitHub account name to the signing DID in a signed portable artifact."""
    if not _GITHUB_USER.fullmatch(github_user):
        raise ValueError("invalid GitHub user name")
    signer = public_did(key.public_key())
    return sign_receipt(
        {
            "binding_version": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "github_user": github_user,
            "signer": signer,
            "statement": (
                f"The holder of {signer} binds this key to the GitHub account "
                f"{github_user} for TechnoReceipt evidence."
            ),
            "limitations": [
                "The signature proves control of the DID key, not control of the GitHub account.",
                "Publish this file in a repository owned by the named GitHub account to provide the reciprocal public relationship.",
                "A copied file remains a valid DID statement but is not a GitHub-account proof at the copied location.",
            ],
        },
        key,
    )
