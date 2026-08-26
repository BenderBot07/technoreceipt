from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime

_PROJECT_RE = re.compile(
    r"(?:\btechnocore\b|technocore\.chat|flop-labs/technocore-chat|\bflop labs\b)",
    re.IGNORECASE,
)
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}", re.IGNORECASE)
_STOP = {
    "and",
    "are",
    "but",
    "contribution",
    "did",
    "for",
    "from",
    "github",
    "have",
    "into",
    "issue",
    "labs",
    "pull",
    "repo",
    "that",
    "the",
    "their",
    "this",
    "technocore",
    "with",
}
_OFFICIAL_REPO = "flop-labs/technocore-chat"


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _WORD_RE.findall(text) if token.lower() not in _STOP}


def _sha(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def project_relationship(snapshot: dict) -> tuple[bool, str]:
    """Classify whether the inspected artifact itself is connected to Technocore."""
    repository = str(snapshot.get("repository", "")).lower()
    if repository == _OFFICIAL_REPO:
        return True, "official_repository"
    title_body = f"{snapshot.get('title', '')}\n{snapshot.get('body', '')}"
    if _PROJECT_RE.search(title_body):
        return True, "artifact_mentions_technocore"
    return False, "artifact_has_no_technocore_relationship"


def assess(snapshot: dict, claim: str, claimed_by: str) -> dict:
    title_body = f"{snapshot.get('title', '')}\n{snapshot.get('body', '')}"
    comments = snapshot.get("comments") if isinstance(snapshot.get("comments"), list) else []
    project_related, _ = project_relationship(snapshot)
    official_target = str(snapshot.get("repository", "")).lower() == _OFFICIAL_REPO
    author_match = str(snapshot.get("author", "")).lower() == claimed_by.lower()
    relevant_comment_authors = {
        str(comment.get("author", "")).lower()
        for comment in comments
        if isinstance(comment, dict) and _PROJECT_RE.search(str(comment.get("body", "")))
    }
    commenter_match = claimed_by.lower() in relevant_comment_authors

    # A comment can establish participation in the official repository. It cannot turn an
    # unrelated third-party issue into Technocore evidence merely by dropping the keyword there.
    actor_relationship = author_match or (official_target and commenter_match)
    claim_terms = _tokens(claim)
    evidence_terms = _tokens(title_body)
    if official_target:
        evidence_terms |= {
            term
            for comment in comments
            if isinstance(comment, dict)
            and str(comment.get("author", "")).lower() == claimed_by.lower()
            for term in _tokens(str(comment.get("body", "")))
        }
    overlapping_terms = sorted(claim_terms & evidence_terms)
    required_overlap = min(2, len(claim_terms))
    claim_supported = required_overlap > 0 and len(overlapping_terms) >= required_overlap

    checks = {
        "artifact_exists": True,
        "project_relationship": project_related,
        "actor_relationship": actor_relationship,
        "claim_supported": claim_supported,
    }
    verdict = "verified" if all(checks.values()) else "insufficient"
    public_snapshot = {
        **{key: value for key, value in snapshot.items() if key != "comments"},
        "comment_count": len(comments),
        "relevant_comment_authors": sorted(relevant_comment_authors),
    }
    return {
        "receipt_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "claim": claim,
        "claimed_by": claimed_by,
        "source": public_snapshot,
        "source_snapshot_sha256": _sha(snapshot),
        "checks": checks,
        "matched_claim_terms": overlapping_terms,
        "verdict": verdict,
        "limitations": [
            "This verifies public evidence and authorship relationships, not usefulness or reward eligibility.",
            "The source hash proves what was inspected; GitHub content can later change or disappear.",
        ],
    }
