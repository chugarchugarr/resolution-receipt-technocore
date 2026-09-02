# Resolution Continuity / Generality Hypothesis

Status: experimental falsification package.

This document locks the architecture under test. It is deliberately stronger than a safety-wrapper description and deliberately weaker than a claim that AGI has been demonstrated.

## Thesis

A candidate architecture for general intelligence is an invariant resolution process that can enter heterogeneous environments without forcing those environments into one ontology or consensus system.

The invariant loop is:

```text
WORLD
  -> OBSERVE
  -> EVIDENCE
  -> NATIVE VERIFICATION
  -> RLP-1 BOUNDED RESOLUTION
  -> RLP-2 AUTHORITY / SCOPE / ACTION GATE
  -> PERMIT | DENY | HOLD
  -> PROPOSED ACTION
  -> MANIFESTED REALITY
  -> NEW EVIDENCE
  -> RE-ENTRY
```

The hypothesis is not that RLP-1 or RLP-2 alone is AGI. The hypothesis is that **domain-general resolution plus domain-general continuation** is a candidate architectural requirement for AGI.

## Fixed roles

### RLP-1 — resolution memory

RLP-1 remains unchanged. It answers what bounded conclusion follows from declared checks and evidence, while preserving non-erasing correction lineage.

### RLP-2 — safe resolution-to-action control

RLP-2 verifies evidence through exact adapters, separates authority from resolution, enforces scope monotonicity, detects unresolved forks, and derives `PERMIT`, `DENY`, or `HOLD` from the signed lineage.

### Resolution Continuity — manifestation closure

Resolution Continuity adds no new truth state. It packages the safe RLP-2 decision as a signed object and binds later independently verified manifestation evidence back to the exact decision, request, and destination.

Its governing invariant is:

```text
PERMIT != EXECUTED
```

A system may only say that an action manifested when new native evidence verifies against the exact decision binding.

If manifestation occurs after `DENY` or `HOLD`, the event is preserved as a policy violation. Reality is never rewritten to protect the policy model.

## Operational distinctions

The implementation exposes these as separate facts:

- resolution available;
- action permitted;
- action manifested;
- manifestation bound to the exact decision;
- manifestation compliant with or violating the decision.

This operationalizes the distinction between available inheritance, permitted inheritance, manifested behavior, and retrospective binding.

A bound manifestation proves that the observed event is linked to the exact decision object under the declared adapter semantics. It does not prove subjective intent, consciousness, or metaphysical causation.

## Generality criterion

Let domain implementations be `D1 ... Dn` and the fixed kernel be `K`.

The architecture survives a new domain when:

```text
K is unchanged
adapters change
policies change
scopes change
evidence changes
```

The architecture is falsified as a domain-general resolution architecture when materially different domains repeatedly require changes to the RLP-1/RLP-2/continuity kernel rather than only adapters or policies.

The first executable test pack uses three deliberately unrelated evidence shapes:

1. GitHub-like pull-request state;
2. ledger/checkpoint state;
3. agent tool-execution state.

These are protocol-shape falsification fixtures, not claims of production-native GitHub, Ethereum, or agent-runtime authenticity. Production adapters must independently establish the native semantics of their source systems.

## AGI falsification program

The stronger AGI thesis survives only if the same loop can eventually operate across unrelated environments while preserving all of the following:

1. native evidence semantics;
2. bounded uncertainty rather than forced answers;
3. non-erasing correction;
4. explicit resolver authority;
5. bounded action scope;
6. safe abstention;
7. separation of permission from manifestation;
8. observation of consequences as new evidence; and
9. re-entry without kernel redesign.

The thesis weakens if the architecture works only for software-like domains, only for signed digital evidence, or only when a human silently performs the missing resolution work outside the model.

## Complete continuity formula

For world state `W_t`:

```text
W_t
 -> E_t
 -> V_t
 -> R_t (RLP-1)
 -> A_t / P_t (RLP-2)
 -> D_t
 -> X_t
 -> M_t
 -> W_(t+1)
 -> E_(t+1)
```

with:

```text
D_t = PERMIT
=> verified lineage
   AND required native verification
   AND bounded resolution
   AND resolver authority
   AND allowed scope
   AND matching action policy
   AND no unresolved fork
```

and separately:

```text
D_t = PERMIT does not imply M_t exists.
```

Manifestation is established only by new independently verifiable evidence bound to the exact action decision.

## What this package proves if tests pass

A passing package proves only that the reference implementation preserves the declared invariants for its executable fixtures and that the same kernel can process the current unrelated test domains without code changes to the kernel.

It does not prove AGI, universal domain generality, adapter correctness for every external protocol, consciousness, human-equivalent competence, or safe deployment in arbitrary physical systems.

Those remain empirical questions.
