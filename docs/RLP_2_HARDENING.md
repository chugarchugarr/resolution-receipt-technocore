# RLP-2 hardening pass

Status: experimental reference implementation under adversarial review.

This hardening pass preserves RLP-1 as the unchanged bounded-resolution kernel and closes trust-boundary gaps found after the first RLP-2 implementation.

## Enforced invariants

### Adapter identity

When a native verification adapter is present, its Python source digest must exactly match the signed `method_digest` before it can influence a verification result. A verifier cannot silently substitute a different callable under the same method name.

This digest covers the adapter callable source presented to the verifier. It does **not** prove the transitive dependency closure, interpreter, remote services, or operating environment. Those remain part of the external adapter packaging and deployment boundary.

### Verification spec/result binding

Stored verification results are checked against the exact signed verification spec. `method`, `method_digest`, and `claims_digest` must match the corresponding spec before a stored result can be accepted.

### Scope monotonicity

`effective_scope` may never exceed `original_scope`.

If scope changes, containment must be mechanically established by the accepted scope adapter. A changed effective scope cannot accompany an RLP-1 `SURVIVED` target; the human target must also be `NARROWED`. Unknown containment is rejected rather than treated as permission.

### RLP-1 bootstrap authority

RLP-1 had no resolver-authority semantics. Therefore an RLP-1 signer cannot become an operative RLP-2 authority merely by writing an RLP-2 policy that names itself.

For the reference implementation, an RLP-1 -> RLP-2 successor using `EXACT`, `ANY_OF`, `ALL_OF`, or `THRESHOLD` remains `UNRESOLVED` for authority. An operative bootstrap requires `EXTERNAL` authority policy whose referenced authority evidence is natively `VERIFIED`.

This does not retroactively make the RLP-1 signer authoritative.

### Integrated action path

`verify_and_decide_action(...)` accepts the signed lineage and derives lineage integrity, resolution state, authority state, effective scope, and exact head internally before evaluating action policy.

The caller cannot inject `AUTHORIZED`, `SURVIVED`, `PASS`, or an arbitrary head into this path.

The lower-level pure policy function remains available for testing and composition, but it is not the safe end-to-end entry point.

### Fork abstention

`verify_rlp2_heads(...)` verifies multiple candidate lineages without choosing one.

If more than one distinct valid head remains, the head set is `FORK_UNRESOLVED`. `verify_and_decide_action_heads(...)` returns `HOLD` until another explicit convergence mechanism resolves the competing heads.

No branch is silently erased.

### Standalone successor structure

A signed RLP-2 successor may be checked structurally without supplying its predecessor, but predecessor continuity cannot be established until the predecessor is supplied. In particular, a standalone successor claiming an RLP-1 predecessor cannot promote bootstrap authority beyond `UNRESOLVED`.

## Adversarial matrix

The executable tests now cover:

- adapter substitution;
- verification result/spec substitution;
- invalid and unresolved evidence;
- EXACT, ANY_OF, ALL_OF, THRESHOLD, and EXTERNAL authority modes;
- unauthorized resolvers;
- authorized and unauthorized authority-policy rotation;
- RLP-1 self-bootstrap prevention;
- externally anchored RLP-1 bootstrap;
- scope broadening rejection;
- scope/target mismatch rejection;
- lineage rewriting;
- standalone successor structural verification;
- integrated lineage-to-action derivation; and
- unresolved competing heads forcing `HOLD`.

## Boundaries that remain external

This pass does not claim to solve:

- correctness of a foreign protocol adapter;
- transitive software-supply-chain identity for adapter dependencies;
- availability of foreign evidence;
- real-world identity;
- Sybil resistance;
- social legitimacy of an external authority root;
- domain-specific freshness, finality, expiry, or revocation semantics;
- convergence policy for competing heads; or
- proof that a permitted action was actually executed.

Those are separate evidence/policy layers and must not be silently inferred by RLP-2.

## Operational boundary

Within the declared adapter and authority assumptions, the hardened safe path is:

```text
signed lineage
  -> verify native evidence
  -> verify adapter identity binding
  -> recompute RLP-1 resolution
  -> enforce scope monotonicity
  -> derive resolver authority
  -> detect unresolved forks
  -> evaluate action policy
  -> PERMIT / DENY / HOLD
```

`PERMIT` remains permission, not manifestation. Actual execution must later appear as new independently verifiable evidence if it is to enter a successor resolution.
