from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technoreceipt.audit import audit_room_snapshot, extract_github_urls
from technoreceipt.did import public_did, public_key_from_did, sign_receipt, verify_receipt
from technoreceipt.evidence import assess
from technoreceipt.github import parse_url


def _snapshot(**overrides: object) -> dict:
    value = {
        "type": "issues",
        "url": "https://github.com/flop-labs/technocore-chat/issues/66",
        "repository": "flop-labs/technocore-chat",
        "author": "alice",
        "title": "Keep signed records independently verifiable",
        "body": "Persist the Ed25519 signature on signed messages.",
        "state": "open",
        "updated_at": "2026-08-25T00:00:00Z",
        "comments": [],
    }
    value.update(overrides)
    return value


def test_official_authored_contribution_verifies() -> None:
    result = assess(_snapshot(), "persist Ed25519 signatures on signed messages", "alice")
    assert result["verdict"] == "verified"
    assert result["checks"] == {
        "artifact_exists": True,
        "project_relationship": True,
        "actor_relationship": True,
        "claim_supported": True,
    }


def test_arbitrary_third_party_issue_is_rejected() -> None:
    snapshot = _snapshot(
        repository="apache/texera",
        author="someone-else",
        title="Improve Spark connector retries",
        body="Ordinary database retry behavior.",
        comments=[{"author": "farmer", "body": "technocore contribution", "url": "x"}],
    )
    result = assess(snapshot, "Technocore signed-write recovery report", "farmer")
    assert result["verdict"] == "insufficient"
    assert result["checks"]["project_relationship"] is False
    assert result["checks"]["actor_relationship"] is False


def test_official_comment_can_prove_actor_relationship() -> None:
    snapshot = _snapshot(
        author="maintainer",
        comments=[
            {
                "author": "alice",
                "body": "I reproduced the Ed25519 signature retention bug in Technocore.",
                "url": "x",
            }
        ],
    )
    result = assess(snapshot, "reproduced Ed25519 signature retention", "alice")
    assert result["verdict"] == "verified"


def test_signed_receipt_is_offline_verifiable_and_tamper_evident() -> None:
    key = Ed25519PrivateKey.generate()
    unsigned = assess(_snapshot(), "persist Ed25519 signatures", "alice")
    unsigned["signer"] = public_did(key.public_key())
    receipt = sign_receipt(unsigned, key)
    verify_receipt(receipt)

    tampered = copy.deepcopy(receipt)
    tampered["claim"] = "different claim"
    with pytest.raises(ValueError, match="payload hash mismatch"):
        verify_receipt(tampered)


def test_receipt_rejects_unknown_algorithm() -> None:
    key = Ed25519PrivateKey.generate()
    unsigned = assess(_snapshot(), "persist Ed25519 signatures", "alice")
    unsigned["signer"] = public_did(key.public_key())
    receipt = sign_receipt(unsigned, key)
    receipt["proof"]["algorithm"] = "not-ed25519"
    with pytest.raises(ValueError, match="unsupported proof algorithm"):
        verify_receipt(receipt)


def test_did_round_trip() -> None:
    key = Ed25519PrivateKey.generate()
    did = public_did(key.public_key())
    original = key.public_key().public_bytes_raw()
    assert public_key_from_did(did).public_bytes_raw() == original


@pytest.mark.parametrize(
    "url,kind",
    [
        ("https://github.com/flop-labs/technocore-chat", "repository"),
        ("https://github.com/flop-labs/technocore-chat/issues/66", "issues"),
        ("https://github.com/flop-labs/technocore-chat/pull/93", "pull"),
        ("https://github.com/flop-labs/technocore-chat/commit/abc123", "commit"),
    ],
)
def test_parse_supported_urls(url: str, kind: str) -> None:
    assert parse_url(url).kind == kind


class _FakeGitHub:
    def snapshot(self, ref: object) -> dict:
        repo = f"{ref.owner}/{ref.repo}"
        if repo == "flop-labs/technocore-chat":
            return _snapshot(repository=repo, title="Technocore issue")
        return _snapshot(
            repository=repo,
            title="Performance regression alert",
            body="An unrelated website performance report.",
        )


def test_extract_github_urls_deduplicates_and_ignores_trailing_punctuation() -> None:
    url = "https://github.com/flop-labs/technocore-chat/issues/149"
    assert extract_github_urls(f"Proof: {url}. Duplicate: {url})") == [url]


def test_audit_room_snapshot_separates_related_and_unrelated_evidence() -> None:
    view = {
        "room": "technocore",
        "messages": [
            {
                "seq": 1,
                "ts": "2026-08-26T18:00:00Z",
                "from": "did:key:z6MkExample",
                "text": "Proof https://github.com/flop-labs/technocore-chat/issues/149",
            },
            {
                "seq": 2,
                "from": "did:key:z6MkFarmer",
                "text": "Proof https://github.com/example/site/issues/42",
            },
        ],
    }
    report = audit_room_snapshot(view, _FakeGitHub())
    assert report["counts"] == {"related": 1, "unrelated": 1, "error": 0}
    assert [finding["status"] for finding in report["findings"]] == [
        "related",
        "unrelated",
    ]
    assert report["findings"][1]["reason"] == "artifact_has_no_technocore_relationship"
    assert report["audit_version"] == 2
    assert report["findings"][0]["ts"] == "2026-08-26T18:00:00Z"
    assert report["findings"][0]["message_text"].startswith("Proof https://github.com/")


def test_audit_report_can_be_signed_verified_and_detects_tampering() -> None:
    key = Ed25519PrivateKey.generate()
    report = audit_room_snapshot({"room": "technocore", "messages": []}, _FakeGitHub())
    report["signer"] = public_did(key.public_key())
    signed = sign_receipt(report, key)
    verify_receipt(signed)

    tampered = copy.deepcopy(signed)
    tampered["counts"]["related"] = 1
    with pytest.raises(ValueError, match="payload hash mismatch"):
        verify_receipt(tampered)


def test_audit_room_snapshot_requires_messages_array() -> None:
    with pytest.raises(TypeError, match="messages array"):
        audit_room_snapshot({"room": "technocore"}, _FakeGitHub())
