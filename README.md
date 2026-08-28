# Resolution Receipt for Technocore

[![verify](https://github.com/chugarchugarr/resolution-receipt-technocore/actions/workflows/verify.yml/badge.svg)](https://github.com/chugarchugarr/resolution-receipt-technocore/actions/workflows/verify.yml)

Latest certified exit: **PASS**. Bundle integrity: **PASS**.

This repository contains two linked, signed runs:

1. v0.1.0 identified that Technocore verifies a transport signature on write but
   omits it from the public JSON response. Its bounded result remains `FAIL`.
2. v0.2.0 resolves that gap without changing Technocore. It places a second,
   domain-separated Ed25519 envelope inside the text that Technocore preserves.
   A reader can verify the stored record using only the public response. Its
   bounded result is `PASS`.

Created and issued by Joseph Lerma. Technocore is used for coordination and
signed publication. GitHub holds the durable artifacts.

## Upstream relationship and attribution

This repository is Joseph Lerma / `chugarchugarr`'s independent reproduction,
client-layer mitigation, and signed evidence record for the problem described in
[Technocore issue #66](https://github.com/flop-labs/technocore-chat/issues/66).

The related native server implementation is
[flop-labs/technocore-chat PR #93](https://github.com/flop-labs/technocore-chat/pull/93).
PR #93 is authored and maintained by `undefinedquillharbor3417`, not by
`chugarchugarr`. It is not represented here as Joseph's code, PR, or an upstream
acceptance of this repository. The relationship is complementary: this repository
preserves the independent FAIL→PASS evidence; PR #93 pursues the native server-side
fix.

## Latest run

Task: determine whether a self-contained signed Technocore record can be
independently re-verified using only the current public JSON room response.

The live record is in
[`resolution-pass-697b4af00819`](https://technocore.chat/r/resolution-pass-697b4af00819?format=json).

| Test | Result | What was established |
|---|---|---|
| T1 | `PASS` | Fresh worker DID; embedded and transport signatures both verify |
| T2 | `PASS` | One accepted write; public response preserved DID, nonce, and text |
| T3 | `PASS` | Separate verifier validated the record from public response data only |
| T4 | `PASS` | Text, signer, nonce, and room mutations were all rejected |

| Latest signed artifact | Canonical SHA-256 |
|---|---|
| Manifest | `sha256:a628be233cf8dd4dbe48d9ab0f3b274cfe0d281833ca4cec2f5cb1fd7f85f008` |
| Worker claim | `sha256:16284ddd4632836292d67c4a6c83ac35b3401348fbeb43403d4ffda370a39dbe` |
| Verifier verdict | `sha256:f4a0618013ae39b8f1bca776407acbe231b9a779aac84eb5525563eb94daa320` |
| Final receipt | `sha256:0249a7821641b502445bf6bee3dd305d65f01fea8fffc994355d16582ff39f61` |
| Release attestation | `sha256:51a175e8facdd8982e75dfc50f6f650f588372a940ee14f9b1d850f2d28159c6` |

The complete v0.2.0 run is documented in [`public/v2/`](public/v2/README.md).

## Mechanism

The client signs this payload as a `technocore-record` object:

```json
{
  "body": "public message",
  "nonce": "decimal nonce",
  "room": "room name"
}
```

The signed canonical JSON envelope is encoded as URL-safe base64 with the
prefix `rr1.` and sent as Technocore's text. The normal Technocore signature
still authorizes the write. The embedded signature remains in the stored text.

On read, the public verifier:

1. decodes the `rr1.` envelope;
2. verifies its Ed25519 signature from the embedded `did:key`;
3. requires that DID to equal the response `from` field;
4. requires the embedded room and nonce to equal the response context; and
5. returns the signed body only after every binding passes.

This proves integrity and key control for the self-contained record. It does
not establish legal identity, factual truth, consensus, settlement, token
value, or airdrop eligibility.

## Verify

```bash
uv run resolution-receipt verify-bundle \
  --manifest public/v2/manifest.signed.json \
  --claim public/v2/claim.signed.json \
  --verdict public/v2/verdict.signed.json \
  --receipt public/v2/receipt.signed.json

uv run resolution-receipt verify-technocore-record \
  --room resolution-pass-697b4af00819 \
  --input public/v2/evidence/technocore-record.json

uv run python scripts/audit_release.py
uv run python -m unittest discover -s tests -v
```

The release audit verifies both histories. Expected latest results are
`latest_bundle_integrity: PASS` and `latest_certified_exit: PASS`.

## Historical finding

The original v0.1.0 receipt remains immutable at
[`public/receipt.signed.json`](public/receipt.signed.json). Its `FAIL` result
proved the server response alone cannot reconstruct Technocore's discarded
transport signature. The v0.2.0 manifest binds directly to that original
receipt hash and certifies the client-layer remedy instead of rewriting history.

The source inspection remains pinned to official Technocore commit
[`8bd794b`](https://github.com/flop-labs/technocore-chat/commit/8bd794b953d7b3fbcff71f4db2e3257f68d144c3).

## Privacy boundary

The public repository contains only fixed task contracts, observable evidence,
generic cryptographic verification code, signatures, hashes, test results, and
certified exits. It contains no private policy text, private key, salt, private
example, hidden operating logic, or queryable decision service.

A salted commitment binds both runs to the same sealed private policy without
revealing that policy or its salt. The public verifier has no access to either.

## Reuse

The signing and verification core is MIT-licensed and task-independent. Agents
can use `technocore-record-request` to create self-contained records and
`verify-technocore-record` to verify a public response without any private
material from these runs.
