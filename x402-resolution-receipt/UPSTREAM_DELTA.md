# Upstream delta for x402 #2833

Reference proof: this directory (`npm test`).

Compared against:

- x402 v2 core `exact` flow
- approved `offer-receipt` extension
- x402-foundation/x402#1921 operation-bound receipts
- x402-foundation/x402#2833 and the StelarDigital/x402-receipts v0.5.1 reference work

## Explicitly excluded from the novelty claim

This proposal does **not** claim request/response hashing, `payment_requirements_sha256`, delivery status, settlement verification, buyer countersignatures, canonical envelope digests, Merkle/EAS anchoring, or reputation scoring. Those are already covered or actively developed in the existing work.

## Surviving delta

### 1. Issuance-time signer authority evidence

The approved Offer/Receipt extension already distinguishes signature validity from signer authorization and recommends preserving temporally immutable authorization evidence when mutable DID/DNS state changes after key rotation.

The remaining implementation primitive is a concrete carried/referenceable authority-evidence object: enough evidence to establish that the signing key was authorized **at issuance time**, without consulting current mutable state.

The proof rotates the current service key and still validates the earlier authorization from preserved signed evidence.

### 2. Independent verifier findings as signed evidence

The proof binds:

```text
verifierId
rulesetDigest
evidenceRoot
result
reason
observedAt
```

under the independent verifier's signature.

The demo uses `SURVIVED / NARROWED / FAILED / UNRESOLVED` as reference semantics only. Those labels are **not** proposed as mandatory x402 policy. The protocol-level primitive is the signed binding between verifier identity, exact ruleset, exact evidence set, and finding.

### 3. Non-erasing correction links

A new resolution carries `previousResolutionId` and may supersede a prior conclusion without deleting or mutating it.

This is distinct from Merkle/EAS existence or ordering anchors. Anchoring establishes that an artifact existed; correction semantics establish how a later finding relates to an earlier finding while leaving both independently replayable.

The proof demonstrates `SURVIVED -> FAILED` while the first signed resolution remains valid and addressable.

## Boundary

The fixture consumes an x402 v2 `exact`:

```text
PaymentRequired -> PaymentPayload -> successful SettlementResponse
```

It deliberately does not reimplement EIP-3009/RPC settlement and does not claim a live payment.

## Proposed upstream question

Would these three evidence primitives fit best as a small composable extension to the existing receipt work, or should they remain an application-layer resolution envelope above `delivery-receipt`?
