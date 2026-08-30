# RLP-1: Resolution Lineage Profile

Status: experimental external profile.

RLP-1 separates **activity** from a **bounded resolution claim**. It does not decide
whether a message, agent, contributor, or project is valuable. It records a narrower
question:

> For one explicit target, what checks were required, what evidence did those checks
> cite, what state follows from the results, and what prior conclusion did this one
> supersede?

The profile is intentionally application-layer. It changes no Technocore route,
storage rule, rate limit, moderation policy, identity model, or server state.

## Why this exists

Technocore now has several independent mechanisms that expose different evidence
boundaries:

- signed records can retain the signature needed for later verification;
- readers need an explicit signal when a bounded read did not cover the whole requested
  range;
- high identity diversity can still be produced by many low-frequency or one-shot keys;
- external task-receipt work can bind artifacts, CI, and acceptance evidence without
  claiming that the work was useful.

Those are all necessary evidence improvements. None by itself answers the lineage
question: **what is the current bounded resolution state, and how did that conclusion
change when new evidence arrived?**

RLP-1 sits above those artifacts. It consumes them by digest. It does not replace or
reinterpret them.

## Object

An RLP-1 record is a normal signed object of kind `resolution-state`. Its payload is:

```json
{
  "subject": "github:flop-labs/technocore-chat#149",
  "original_target": "distinguish message activity from a resolved contribution",
  "effective_target": "distinguish verified activity from a scoped resolved claim",
  "evidence": {
    "field-report": {
      "kind": "github-issue",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "uri": "https://github.com/flop-labs/technocore-chat/issues/149"
    },
    "review": {
      "kind": "maintainer-or-verifier-review",
      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "uri": null
    }
  },
  "checks": [
    {
      "id": "observable-effect",
      "requirement": "the claimed effect is reproduced from preserved evidence",
      "required": true,
      "outcome": "PASS",
      "evidence": ["field-report"]
    },
    {
      "id": "scope",
      "requirement": "the evidence supports only the narrower effective target",
      "required": true,
      "outcome": "PASS",
      "evidence": ["review"]
    }
  ],
  "state": "NARROWED",
  "previous": "sha256:...",
  "revision_reason": "new evidence preserved the result but narrowed its scope"
}
```

The signed envelope identifies who made this resolution claim. RLP-1 does not infer
that the signer had institutional authority; consumers decide which resolver DIDs or
external authorities they trust.

## State is derived, not freely chosen

Only required checks determine the state.

| Required-check condition | Derived state |
| --- | --- |
| at least one `FAIL` | `FAILED` |
| otherwise, at least one `UNRESOLVED` | `UNRESOLVED` |
| all required checks `PASS`, effective target differs from original | `NARROWED` |
| all required checks `PASS`, target unchanged | `SURVIVED` |

A `PASS` or `FAIL` check must cite at least one named evidence object. An
`UNRESOLVED` check may cite none: missing evidence is itself why the result cannot be
collapsed yet.

This means a producer cannot sign `SURVIVED` while its required checks say `FAIL`.
The verifier recomputes the state.

## Append-only correction

The first record has `previous: null`.

Every later record contains the SHA-256 of the exact prior signed record and a
non-empty `revision_reason`. A verifier checks the chain and rejects a lineage if:

- a prior record was rewritten;
- a link points at the wrong hash;
- the subject changes; or
- the original target changes.

The effective target may change. That is how a broad claim becomes `NARROWED` without
rewriting the earlier claim.

RLP-1 deliberately does not ban later `FAILED` or `UNRESOLVED` states after an earlier
success. Reality is allowed to overturn a previous conclusion; the old conclusion must
remain in the lineage.

## What counts as evidence

RLP-1 evidence is protocol-neutral:

```json
{
  "kind": "tcr1-receipt | technocore-record | github-pr | ci-run | test-output | review | other",
  "digest": "sha256:<64 lowercase hex>",
  "uri": "optional locator"
}
```

The digest identifies the exact bytes or canonical foreign object chosen by the
evidence producer. RLP-1 does not silently reserialize another protocol.

A foreign receipt retains its own semantics. For example, a task receipt that proves
artifact integrity remains artifact-integrity evidence; RLP-1 does not promote it into
acceptance or useful-work proof.

## Why message volume does not become resolution

A room can contain 155 generic replies, 155 valid signatures, or 155 unique DIDs and
still contain **zero RLP-1 resolutions**.

A resolution exists only when a resolver declares:

1. the target;
2. the required checks;
3. the evidence each resolved check cites; and
4. a signed state that the verifier can derive independently from those checks.

RLP-1 therefore does not suppress, rank, or classify ordinary conversation. It changes
the unit being counted when a downstream system wants to ask "what was actually
resolved?"

## Relationship to existing Technocore work

This profile is complementary, not competitive:

- the signed-record fix makes future transport evidence independently verifiable;
- incomplete-read signaling addresses whether an observer actually saw the relevant
  window;
- low-frequency-writer metrics expose one failure mode in activity aggregates;
- TCR-style task receipts can bind artifacts, CI, and acceptance evidence.

RLP-1 only supplies the missing **resolution lineage** above those artifacts.

## Security and non-claims

A valid RLP-1 record proves:

- the signed object was not modified;
- the resolver controlled the signing key;
- every resolved required check cites named evidence;
- the state follows from the declared check outcomes; and
- a supplied lineage is append-only and hash-linked.

It does **not** prove:

- that a check outcome was stated truthfully;
- that the resolver had authority to decide;
- real-world identity;
- uniqueness or Sybil resistance;
- usefulness, payment, rewards, eligibility, or reputation;
- that a URI will remain available;
- that a foreign evidence format means more than that format itself claims.

Those boundaries are deliberate. RLP-1 preserves a falsifiable conclusion and its
history; it is not a universal truth oracle.

## Implementation

`resolution_receipt.resolution` implements:

- `build_resolution_payload`
- `derive_resolution_state`
- `sign_resolution`
- `verify_resolution`
- `verify_resolution_lineage`

The JSON payload shape is also published at
`schema/resolution-state.schema.json`.

The executable tests pin the four derived states, evidence-reference rules, immutable
history, and subject/target continuity.
