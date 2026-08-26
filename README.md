# TechnoReceipt

TechnoReceipt creates compact, DID-signed receipts for public Technocore contribution evidence.
It is deliberately narrower than a reputation score: it checks that a GitHub artifact exists,
relates to Technocore, has a public relationship to the claimed GitHub user, and supports meaningful
terms in the claim. It does **not** decide whether work is useful or whether FLOP Labs
will reward it.

The first abuse case is fabricated proof links: an unrelated third-party issue cannot become valid
evidence just because someone posts its URL or adds a comment containing the word “Technocore.”

## Safety properties

- The signer is an isolated Ed25519 `did:key`, not a crypto wallet.
- Private keys are encrypted PKCS#8 files, created with mode `0600` and never sent to a model/server.
- Receipts are canonical JSON, SHA-256 hashed, and Ed25519 signed.
- `verify` is offline. It needs only the receipt and the public DID embedded in it.
- GitHub content is snapshotted and hashed; later edits do not silently rewrite the receipt.

## Use

```bash
uv sync --group dev

# Create an isolated key. The passphrase is prompted and must be 12+ characters.
uv run technoreceipt keygen --key private/technoreceipt.pem

# Inspect before signing.
uv run technoreceipt inspect \
  https://github.com/flop-labs/technocore-chat/issues/66 \
  --claim "persist Ed25519 signatures on signed messages" \
  --claimed-by alice

# Issue and independently verify a receipt.
uv run technoreceipt issue <github-url> --claim "..." --claimed-by <github-user> \
  --key private/technoreceipt.pem --out contribution.receipt.json
uv run technoreceipt verify contribution.receipt.json
```

Audit a captured Technocore room window for GitHub links that do not support the claimed
Technocore relationship:

```bash
curl -s 'https://technocore.chat/r/technocore?limit=200&format=json' > room.json
uv run technoreceipt audit-room room.json --out audit.json

# Sign the whole audit so another reader can verify it offline.
uv run technoreceipt audit-room room.json --key private/technoreceipt.pem \
  --out audit.signed.json
uv run technoreceipt verify audit.signed.json
```

The audit hashes both the room snapshot and each inspected GitHub snapshot. It labels a pairing
`related` only when the artifact lives in `flop-labs/technocore-chat` or its own title/body mentions
Technocore. It deliberately does not infer that a DID controls a GitHub account or decide whether
the work is useful. Without `--key` the output remains an unsigned local report; with `--key`, the
signer DID and Ed25519 proof cover the full report, including every finding and snapshot hash. Each
finding preserves the public room timestamp and exact message text beside the inspected URL, so a
reader can review what the link was presented as without recovering the already-moving room tail.

Set `GITHUB_TOKEN` only if public API rate limits are too low. TechnoReceipt never asks for a wallet,
seed phrase, exchange credential, or GitHub write permission.

For non-interactive local use, the key passphrase can be supplied in
`TECHNORECEIPT_KEY_PASSPHRASE`. Do not commit or log that environment variable.

## Verdict rules

A receipt is `verified` only when all four checks pass:

1. GitHub returned the artifact.
2. It is in `flop-labs/technocore-chat`, or its author-created title/body explicitly references
   Technocore.
3. The claimed GitHub user authored the artifact, or made a relevant comment in the official repo.
4. The claim has at least two meaningful overlapping terms with the actor-relevant evidence (or all
   terms when the claim itself contains only one meaningful term).

Anything else is `insufficient`, with each failed check preserved in the signed receipt.
