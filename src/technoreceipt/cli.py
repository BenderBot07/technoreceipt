from __future__ import annotations

import argparse
import binascii
import getpass
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .audit import audit_room_snapshot
from .binding import create_github_binding, verify_github_binding_url
from .did import create_key, load_key, public_did, sign_receipt, verify_receipt
from .evidence import assess
from .github import GitHubClient, parse_url


def _passphrase(confirm: bool = False) -> bytes:
    env = os.getenv("TECHNORECEIPT_KEY_PASSPHRASE")
    if env:
        first = env.encode()
        confirm = False
    else:
        first = getpass.getpass("Key passphrase: ").encode()
    if confirm and first != getpass.getpass("Confirm passphrase: ").encode():
        raise SystemExit("passphrases do not match")
    if len(first) < 12:
        raise SystemExit("passphrase must be at least 12 characters")
    return first


def _json(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SystemExit("expected a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(prog="technoreceipt")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="create an encrypted isolated Ed25519 DID")
    keygen.add_argument("--key", type=Path, required=True)

    inspect = commands.add_parser("inspect", help="inspect and assess a GitHub contribution")
    inspect.add_argument("url")
    inspect.add_argument("--claim", required=True)
    inspect.add_argument("--claimed-by", required=True)

    issue = commands.add_parser("issue", help="create a signed contribution receipt")
    issue.add_argument("url")
    issue.add_argument("--claim", required=True)
    issue.add_argument("--claimed-by", required=True)
    issue.add_argument("--key", type=Path, required=True)
    issue.add_argument("--out", type=Path, required=True)

    verify = commands.add_parser("verify", help="verify a receipt without network access")
    verify.add_argument("receipt", type=Path)

    bind = commands.add_parser(
        "bind-github", help="create a DID-signed statement naming one GitHub account"
    )
    bind.add_argument("--github", required=True)
    bind.add_argument("--key", type=Path, required=True)
    bind.add_argument("--out", type=Path, required=True)

    verify_binding = commands.add_parser(
        "verify-github-binding",
        help="verify a DID binding at an immutable GitHub file URL",
    )
    verify_binding.add_argument("url")

    audit = commands.add_parser(
        "audit-room", help="check GitHub evidence pairings in a Technocore room snapshot"
    )
    audit.add_argument("snapshot", type=Path)
    audit.add_argument("--out", type=Path)
    audit.add_argument(
        "--key",
        type=Path,
        help="sign the audit for offline verification with an encrypted Ed25519 key",
    )

    args = parser.parse_args()
    if args.command == "keygen":
        print(create_key(args.key, _passphrase(confirm=True)))
        return
    if args.command == "verify":
        try:
            verify_receipt(_json(args.receipt))
        except (binascii.Error, TypeError, ValueError, InvalidSignature) as exc:
            raise SystemExit(f"INVALID: {exc}") from exc
        print("VALID")
        return
    if args.command == "bind-github":
        key = load_key(args.key, _passphrase())
        try:
            binding = create_github_binding(args.github, key)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if args.out.exists():
            raise SystemExit(f"refusing to overwrite existing binding: {args.out}")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(binding, indent=2, ensure_ascii=False) + "\n")
        print(f"bound {binding['signer']} to GitHub user {binding['github_user']}: {args.out}")
        return
    if args.command == "verify-github-binding":
        try:
            result = verify_github_binding_url(args.url, GitHubClient())
        except (
            binascii.Error,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            InvalidSignature,
        ) as exc:
            raise SystemExit(f"INVALID GITHUB BINDING: {exc}") from exc
        print(f"VALID GITHUB BINDING: {result['github_user']} <-> {result['signer']}")
        return
    if args.command == "audit-room":
        report = audit_room_snapshot(_json(args.snapshot), GitHubClient())
        if args.key:
            key = load_key(args.key, _passphrase())
            report["signer"] = public_did(key.public_key())
            report = sign_receipt(report, key)
        rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.out:
            if args.out.exists():
                raise SystemExit(f"refusing to overwrite existing report: {args.out}")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(rendered)
            print(
                f"audited {report['evidence_url_count']} evidence URLs: "
                f"{report['counts']['related']} related, "
                f"{report['counts']['unrelated']} unrelated, "
                f"{report['counts']['error']} errors -> {args.out}"
            )
        else:
            print(rendered, end="")
        return

    snapshot = GitHubClient().snapshot(parse_url(args.url))
    assessment = assess(snapshot, args.claim, args.claimed_by)
    if args.command == "inspect":
        print(json.dumps(assessment, indent=2, ensure_ascii=False))
        return
    key = load_key(args.key, _passphrase())
    assessment["signer"] = public_did(key.public_key())
    receipt = sign_receipt(assessment, key)
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite existing receipt: {args.out}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n")
    print(f"{receipt['verdict']}: {args.out}")


if __name__ == "__main__":
    main()
