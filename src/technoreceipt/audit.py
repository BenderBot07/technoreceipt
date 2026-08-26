from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Protocol

from .evidence import assess, project_relationship
from .github import GitHubRef, parse_url

_GITHUB_URL = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/(?:issues|pull|commit)/[A-Za-z0-9_.-]+)?(?![/A-Za-z0-9_.-])"
)


class SnapshotClient(Protocol):
    def snapshot(self, ref: GitHubRef) -> dict: ...


def _sha(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def extract_github_urls(text: str) -> list[str]:
    """Return unique supported GitHub artifact URLs in first-seen order."""
    urls = (match.group(0).rstrip(".,;:!?)]}") for match in _GITHUB_URL.finditer(text))
    return list(dict.fromkeys(urls))


def audit_room_snapshot(
    view: dict, client: SnapshotClient, github_bindings: dict[str, str] | None = None
) -> dict:
    """Audit GitHub evidence pairings found in a Technocore room JSON snapshot."""
    messages = view.get("messages")
    if not isinstance(messages, list):
        raise TypeError("room snapshot must contain a messages array")

    findings: list[dict] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        text = message.get("text")
        if not isinstance(text, str):
            continue
        for url in extract_github_urls(text):
            author = message.get("from")
            finding = {
                "seq": message.get("seq"),
                "ts": message.get("ts"),
                "from": author,
                "signed": isinstance(author, str) and author.startswith("did:key:"),
                "message_text": text,
                "url": url,
            }
            try:
                snapshot = client.snapshot(parse_url(url))
                related, reason = project_relationship(snapshot)
                finding.update(
                    {
                        "status": "related" if related else "unrelated",
                        "reason": reason,
                        "artifact": {
                            "repository": snapshot.get("repository"),
                            "type": snapshot.get("type"),
                            "author": snapshot.get("author"),
                            "title": snapshot.get("title"),
                            "updated_at": snapshot.get("updated_at"),
                            "snapshot_sha256": _sha(snapshot),
                        },
                    }
                )
                bound_user = (github_bindings or {}).get(str(author))
                if bound_user:
                    checks = assess(snapshot, text, bound_user)["checks"]
                    finding["github_binding"] = {
                        "github_user": bound_user,
                        "actor_relationship": checks["actor_relationship"],
                        "claim_supported": checks["claim_supported"],
                    }
            except (RuntimeError, TypeError, ValueError) as exc:
                finding.update({"status": "error", "reason": str(exc)})
            findings.append(finding)

    counts = {status: 0 for status in ("related", "unrelated", "error")}
    for finding in findings:
        counts[finding["status"]] += 1
    return {
        "audit_version": 4,
        "created_at": datetime.now(UTC).isoformat(),
        "room": view.get("room"),
        "room_snapshot_sha256": _sha(view),
        "message_count": len(messages),
        "evidence_url_count": len(findings),
        "counts": counts,
        "verified_github_bindings": [
            {"signer": signer, "github_user": user}
            for signer, user in sorted((github_bindings or {}).items())
        ],
        "findings": findings,
        "limitations": [
            "Related means the GitHub artifact is in the official repository or mentions Technocore itself.",
            "This does not prove DID-to-GitHub ownership, usefulness, intent, or reward eligibility.",
            "Signed records identify Technocore's signed lane, but the read API omits signatures so the room record cannot be re-verified offline.",
            "A room snapshot may be incomplete because Technocore is an ephemeral bounded ring.",
        ],
    }
