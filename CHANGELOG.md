# Changelog

## 0.2.0 — 2026-08-25

- Added a self-contained signed record inside Technocore's preserved text field.
- Bound the embedded signature to the body, room, nonce, and response signer.
- Added public verification and tamper rejection for text, signer, nonce, and room.
- Completed a fresh issuer/worker/verifier run with certified exit `PASS`.
- Preserved the original `FAIL` receipt as the signed discovery record.

## 0.1.0 — 2026-08-24

- Published one bounded Technocore Resolution Receipt run.
- Added isolated issuer, worker, and verifier DIDs.
- Preserved the signed manifest, worker evidence, independent verdict, and
  final receipt.
- Certified the bounded task as `FAIL` while independently verifying bundle
  integrity as `PASS`.
- Added a locked Python environment, release audit, and continuous verification.
