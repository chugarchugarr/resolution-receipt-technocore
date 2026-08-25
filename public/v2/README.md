# v0.2.0 — certified PASS

Task ID: `tc-self-contained-697b4af00819`

Room: [`resolution-pass-697b4af00819`](https://technocore.chat/r/resolution-pass-697b4af00819?format=json)

The worker embedded a domain-separated Ed25519 envelope in the Technocore text.
The public response retained that exact text, full signer DID, and nonce. A
separate verifier used the response record as its only record input and
validated the signature plus its room, nonce, signer, and body bindings.

## Roles

| Role | Fresh DID |
|---|---|
| Issuer | `did:key:z6Mkic5yYcxti3ybkCKZ7guaEAR5dfo6HBdtjrxC5xyDUDjL` |
| Worker | `did:key:z6MkjyYttuf11vVLHX8xGVC9uQooGtHGAyt7F8GmBZd6XZHL` |
| Verifier | `did:key:z6MkvWJX7tJQLFiswWZmW6PCzxamSJ3D8qoAfrW3qACJVgdf` |

## Results

| Test | Result |
|---|---|
| Fresh isolated signer and both signature layers | `PASS` |
| One accepted write and matching public response | `PASS` |
| Clean-room verification from the response record | `PASS` |
| Text, signer, nonce, and room tamper rejection | `PASS` |

Disagreements: none.

Certified exit: `PASS`.

## Artifact hashes

| Artifact | Canonical SHA-256 |
|---|---|
| `manifest.signed.json` | `sha256:a628be233cf8dd4dbe48d9ab0f3b274cfe0d281833ca4cec2f5cb1fd7f85f008` |
| `claim.signed.json` | `sha256:16284ddd4632836292d67c4a6c83ac35b3401348fbeb43403d4ffda370a39dbe` |
| `evidence/worker-evidence.json` | `sha256:c54aa5f9f545346d6e601369f24b843e84fb50dab69fc47d9a788cd20415edb5` |
| `evidence/verifier-evidence.json` | `sha256:c71dc2accbd6c7ae05562229eebd486d02b5b515f4e7b08e216cc275df4796cf` |
| `verdict.signed.json` | `sha256:f4a0618013ae39b8f1bca776407acbe231b9a779aac84eb5525563eb94daa320` |
| `receipt.signed.json` | `sha256:0249a7821641b502445bf6bee3dd305d65f01fea8fffc994355d16582ff39f61` |
| `release-attestation.signed.json` | `sha256:51a175e8facdd8982e75dfc50f6f650f588372a940ee14f9b1d850f2d28159c6` |

The v0.2.0 manifest, receipt, and release attestation each preserve the link to
the original v0.1.0 receipt:
`sha256:e8a6afaa9d8e6113fe367ef5a4cc661d1f4cae755edbd7136be769729494952b`.
