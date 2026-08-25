# Resolution Receipt for Technocore

[![verify](https://github.com/chugarchugarr/resolution-receipt-technocore/actions/workflows/verify.yml/badge.svg)](https://github.com/chugarchugarr/resolution-receipt-technocore/actions/workflows/verify.yml)

This repository contains one bounded, independently verifiable task record. It
uses isolated Ed25519 `did:key` identities, canonical JSON, signed role
statements, and SHA-256 content references. The durable record lives here;
Technocore is used only for coordination and signed publication.

Created and issued by Joseph Lerma. This repository is the complete public
technical artifact; it contains no private evaluation system.

## What this proves

- who signed the task manifest, worker claim, verifier verdict, and final receipt;
- whether any signed object or referenced artifact changed;
- whether the worker and verifier used different DIDs;
- whether the certified exit matches the verifier's `PASS`, `FAIL`, or
  `UNRESOLVED` result.

It does **not** prove that a DID is a legal identity, that a signed assertion is
true merely because it is signed, or that Technocore is a trust or consensus
system. The repository contains no general decision engine.

## The bounded task

Determine whether a signed Technocore room record can be independently
re-verified using only the current public server response. The signed manifest
defines the exact constraints, evidence, tests, authority boundary, and stopping
condition.

This task matters because Technocore currently verifies signatures on write. A
durable response that retains the signature could also be checked later by a
reader who was not present at ingestion.

## Certified result

`FAIL` for the bounded task; `PASS` for receipt integrity.

The worker's fresh DID produced one valid signed write. Technocore accepted it,
and the JSON read returned the same full DID, nonce, and text. The returned
record did not contain the signature, so a reader cannot perform Ed25519
verification from that response alone. The independent verifier therefore
marked T1/T2 `PASS` and T3/T4 `FAIL`, with no disagreement.

The signed coordination record was published in room
[`resolution-2332dba3f6ba`](https://technocore.chat/r/resolution-2332dba3f6ba?format=json).
Technocore is ephemeral; the JSON evidence preserved in this repository is the
run record.

| Signed artifact | Canonical SHA-256 |
|---|---|
| Manifest | `sha256:2e637823f7675abb339019de341f29d176a34bbb04656daec5ed13ea76e94724` |
| Worker claim | `sha256:681ab2dfbd1f3b563b0c129262246d5ba93959862923df7596108bf6529c0af0` |
| Verifier verdict | `sha256:ded4591808872d40a86651cbe13c0d008c17c7ff7c2e91742210b40acc0af5ea` |
| Final receipt | `sha256:e8a6afaa9d8e6113fe367ef5a4cc661d1f4cae755edbd7136be769729494952b` |
| Release attestation | `sha256:d923c6ae7677619b206b7055d897f9e5d0e147ef4d6eb03e5b897ba67821d1e6` |

The source inspection is pinned to official Technocore commit
[`8bd794b`](https://github.com/flop-labs/technocore-chat/commit/8bd794b953d7b3fbcff71f4db2e3257f68d144c3).

## Verify

```bash
uv run resolution-receipt verify-bundle \
  --manifest public/manifest.signed.json \
  --claim public/claim.signed.json \
  --verdict public/verdict.signed.json \
  --receipt public/receipt.signed.json
```

Expected output contains two distinct conclusions:

- `integrity: PASS` means the receipt bundle's signatures and references verify.
- `certified_exit` is the bounded task result and may independently be `PASS`,
  `FAIL`, or `UNRESOLVED`.

Use `uv run python -m unittest discover -s tests` to run the test suite without
installing the package globally.

Run the release audit to verify the bundle, issuer continuity, publication
request, artifact hashes, and tracked-file privacy boundary together:

```bash
uv run python scripts/audit_release.py
```

GitHub Actions runs both checks on every push and pull request.

## Privacy boundary

The public artifact discloses only the fixed task contract, public evidence,
role signatures, hashes, and result. A salted commitment binds the issuer to a
sealed private policy without publishing that policy or its salt. The
commitment is not proof of the policy's quality; it only enables a future
selective disclosure to be matched to this run.

Private policy material and private keys are excluded by `.gitignore`. Do not
commit `.private/`, key files, seeds, environment files, private examples, or
undisclosed operating material.

## Protocol notes

- Canonical JSON: UTF-8, lexicographically sorted keys, no extra whitespace,
  no duplicate keys, no floating-point values, interoperable integers only.
- Role signatures: domain-separated Ed25519 over the object kind and canonical
  payload.
- Technocore writes: Ed25519 over `<room>|<nonce>|<text>`, matching the current
  public Technocore signer.
- Content references: `sha256:` plus the digest of canonical JSON.

The verifier is intentionally a separate role with a fresh DID. Anyone can run
the public verifier without access to any private material.

## Reuse

The signing and verification core is MIT-licensed and task-independent. A new
task can define its own public promise and evidence contract without gaining
access to this run's sealed policy, keys, or salt.
