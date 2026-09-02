# RLP-2: Policy-Bound Resolution Lineage

Status: experimental external profile.

RLP-2 extends RLP-1 without replacing its resolution semantics. RLP-1 remains the deterministic bounded-resolution kernel. RLP-2 adds three explicit layers around that kernel:

1. native evidence verification;
2. resolver authority policy; and
3. deterministic action policy.

The complete path is:

```text
evidence
  -> native verification
  -> resolver authority
  -> required checks
  -> RLP-1 resolution state
  -> action policy
  -> PERMIT / DENY / HOLD
```

The layers are deliberately orthogonal. A structurally valid conclusion may be unauthorized. An authorized conclusion may remain unresolved. An authorized surviving conclusion may still fail to authorize a proposed action.

## 1. State spaces

### Evidence verification

Each evidence object has one of:

- `VERIFIED`
- `INVALID`
- `UNRESOLVED`

A `PASS` or `FAIL` required check cannot rely on evidence whose native-verification state is not `VERIFIED`.

RLP-2 does not define universal semantics for GitHub, x402, ERCs, CI systems, attestations, or other foreign protocols. A named verification adapter owns those native semantics. The record binds the adapter identifier, a digest identifying the adapter/version chosen by the producer, the claims digest, and the resulting verification state.

An independent verifier can recompute those results when it has the same declared adapter. A verifier that lacks an adapter cannot promote missing verification into `VERIFIED`.

### Resolver authority

Authority has one of:

- `AUTHORIZED`
- `UNAUTHORIZED`
- `UNRESOLVED`

Supported reference-policy modes are:

- `EXACT`: one named principal;
- `ANY_OF`: any named principal;
- `ALL_OF`: every named principal;
- `THRESHOLD`: at least `m` of the named principals;
- `EXTERNAL`: a named principal plus explicitly identified natively verified authority evidence.

The record signer must separately sign the canonical RLP-2 resolution body as an authority approval. Additional authority principals can sign the same body digest. Threshold and all-of policies therefore operate on cryptographically real approvals, not merely a declared signer list.

A valid Ed25519 signature does not imply authority. The signer can produce a structurally valid record whose resolution is `SURVIVED` while its separate authority state is `UNAUTHORIZED`.

### Resolution

RLP-1's four-state function is unchanged:

| Required-check condition | Resolution |
| --- | --- |
| any required `FAIL` | `FAILED` |
| otherwise any required `UNRESOLVED` | `UNRESOLVED` |
| all required checks `PASS` and effective target differs | `NARROWED` |
| all required checks `PASS` and target is unchanged | `SURVIVED` |

RLP-2 calls the existing RLP-1 implementation to derive this state. Authority, action policy, signer reputation, payment, or downstream consequences do not modify the resolution-state function.

### Action decision

An action policy produces:

- `PERMIT`
- `DENY`
- `HOLD`

`HOLD` is first-class abstention. Absence of an applicable rule is `HOLD`, not permission.

The reference action gate requires `AUTHORIZED`. It can also require that the requested action's machine-readable scope be contained inside the current effective resolved scope.

A decision binds both:

- the exact RLP-2 lineage-head digest; and
- the exact action-policy digest.

A decision therefore cannot silently migrate to a later resolution head or a changed policy.

## 2. Machine-readable scope

RLP-2 adds `original_scope` and `effective_scope` beside the human-readable targets.

A scope has:

```json
{
  "adapter": "string-set/v1",
  "value": ["alpha", "beta"]
}
```

The reference implementation includes:

- `exact/v1`: requested scope must equal effective scope;
- `string-set/v1`: every requested string must occur in the effective set.

Unknown or incompatible scope adapters resolve containment as `UNRESOLVED`. This prevents a natural-language `NARROWED` state from silently authorizing a broader machine action.

## 3. Authority-policy continuity

Authority cannot be changed by simply editing the current policy.

Every RLP-2 body binds `authority_policy_digest`. When a successor changes that digest, the successor must carry separate transition approvals over:

```text
current body digest
+ previous authority-policy digest
+ new authority-policy digest
```

Those transition approvals are evaluated under the **previous** authority policy.

The rule is:

```text
new policy != old policy
=> old policy must authorize the transition
```

This prevents a signer from making itself authoritative by replacing the authority policy that excluded it.

An RLP-1 -> RLP-2 transition is treated as profile bootstrap rather than a policy rotation because RLP-1 did not contain an RLP-2 authority policy to authorize such a change. RLP-2 does not retroactively claim RLP-1 authority.

## 4. Append-only lineage

RLP-2 preserves RLP-1's non-erasing correction model.

Every successor binds the hash of the exact preceding signed resolution and records the predecessor profile (`RLP-1` or `RLP-2`). Subject and original target remain immutable across a lineage. A successor must provide a non-empty revision reason.

Reality may move the operative conclusion in any evidence-supported direction, including:

```text
SURVIVED -> UNRESOLVED
SURVIVED -> FAILED
FAILED -> NARROWED
UNRESOLVED -> SURVIVED
```

The previous conclusion remains part of history.

## 5. RLP-1 compatibility

RLP-2 does not rewrite or deprecate RLP-1 objects.

A lineage may contain one RLP-1 record as its preserved ancestor followed by RLP-2 successors. RLP-2 then supplies verification, authority, scope, and action-policy semantics prospectively.

This makes RLP-1 the resolution kernel inside RLP-2 rather than a discarded protocol generation.

## 6. Operative meaning

RLP-2 deliberately does not create a fifth combined resolution state.

Instead a consumer reads orthogonal dimensions, for example:

```text
SURVIVED + AUTHORIZED
SURVIVED + UNAUTHORIZED
UNRESOLVED + AUTHORIZED
FAILED + AUTHORIZED
```

This preserves information that a single flattened `VALID/INVALID` state would destroy.

For action purposes, an operative path requires at least:

```text
lineage integrity = PASS
native evidence required by resolved checks = VERIFIED
authority = AUTHORIZED
action policy = matching
scope = allowed when required
```

If a required term cannot be established, the reference action gate abstains with `HOLD`.

## 7. What RLP-2 proves

Within its declared cryptographic, adapter, and policy assumptions, RLP-2 can establish:

- signed-object integrity;
- exact evidence binding;
- declared native-verification method and result;
- recomputation of native verification when the adapter is available;
- cryptographically real resolver approvals;
- authority derivation under an exact policy;
- threshold and all-of authority;
- deterministic RLP-1 resolution-state derivation;
- authorized authority-policy evolution;
- append-only predecessor continuity;
- deterministic action-policy evaluation; and
- binding of an action decision to an exact resolution head and policy.

## 8. What RLP-2 does not prove

RLP-2 is not a universal truth oracle.

It does not inherently prove:

- that a foreign verifier implementation is correct;
- that the evidence set contains every fact in the world;
- real-world identity beyond what an external identity system establishes;
- Sybil resistance;
- moral or political legitimacy;
- usefulness;
- economic value;
- absence of collusion;
- correctness of a badly specified authority policy;
- correctness of a badly specified action policy; or
- that an authorized action was actually executed.

Those boundaries are intentional.

## 9. Inheritance boundary

RLP-2 distinguishes a transmissible resolved state from manifested downstream behavior.

A resolution can become available to downstream actors without proving that any actor inherited it. A later action decision can permit inheritance without proving execution. Only an observed downstream action, preserved as new evidence, establishes manifested behavior.

The resulting loop is:

```text
reality
 -> evidence
 -> verification
 -> authority
 -> bounded resolution
 -> preserved lineage
 -> action gate
 -> manifested action
 -> new reality
 -> new evidence
 -> successor resolution
```

This keeps four concepts separate:

- available inheritance;
- latent inheritance;
- manifested behavior; and
- retrospective attribution.

## 10. Reference implementation

Modules:

- `resolution_receipt.verification` — native adapter boundary;
- `resolution_receipt.authority` — authority policy, approvals, and policy transitions;
- `resolution_receipt.resolution` — unchanged RLP-1 resolution kernel;
- `resolution_receipt.scope` — machine scope comparison;
- `resolution_receipt.policy` — deterministic action gate;
- `resolution_receipt.rlp2` — policy-bound record signing and lineage verification.

Schemas:

- `schema/rlp2-policy-bound.schema.json`
- `schema/rlp2-authority-policy.schema.json`
- `schema/rlp2-action-policy.schema.json`

The executable test matrix covers native evidence failure, unresolved evidence, unauthorized resolvers, threshold authority, authorized and unauthorized authority-policy rotation, history rewriting, narrowed scope, action permission/denial/hold, and RLP-1 ancestry.

## 11. Core invariant

RLP-2's operational invariant is:

```text
PERMIT
=> lineage integrity
   AND required native verification
   AND resolver authority
   AND bounded resolution
   AND matching action policy
   AND required scope containment
```

No unresolved required term is silently promoted to permission.

RLP-1 answers:

> What bounded conclusion follows from the declared checks, and what conclusion did it supersede?

RLP-2 answers:

> What evidence was actually verified, who had authority to resolve it, what bounded conclusion followed, what policy permits that conclusion to be inherited as action, and can the entire path be independently reconstructed without rewriting history?
