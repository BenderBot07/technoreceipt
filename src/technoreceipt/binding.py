from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .did import public_did, sign_receipt, verify_receipt

_GITHUB_USER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_IMMUTABLE_BLOB = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9_.-]+)/blob/"
    r"(?P<commit>[0-9a-fA-F]{40})/(?P<path>[^?#]+)"
)


class FileClient(Protocol):
    def file_bytes(self, owner: str, repo: str, path: str, ref: str) -> bytes: ...


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


def verify_github_binding_url(url: str, client: FileClient) -> dict:
    """Verify a signed binding at an immutable file URL owned by its named GitHub user."""
    match = _IMMUTABLE_BLOB.fullmatch(url)
    if not match:
        raise ValueError("binding URL must be a GitHub blob URL pinned to a 40-character commit")
    fields = match.groupdict()
    raw = client.file_bytes(fields["owner"], fields["repo"], fields["path"], fields["commit"])
    binding = json.loads(raw)
    if not isinstance(binding, dict):
        raise TypeError("binding file must contain one JSON object")
    verify_receipt(binding)
    github_user = binding.get("github_user")
    if not isinstance(github_user, str) or github_user.lower() != fields["owner"].lower():
        raise ValueError("binding names a GitHub user other than the repository owner")
    if binding.get("binding_version") != 1:
        raise ValueError("unsupported binding version")
    return {
        "github_user": github_user,
        "signer": binding["signer"],
        "source_url": url,
        "payload_sha256": binding["proof"]["payload_sha256"],
    }
