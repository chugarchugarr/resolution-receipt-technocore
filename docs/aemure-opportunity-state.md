# AEMURE Opportunity-State Test v0.1

Implementation by Joseph Lerma (`chugarchugarr`).

This is a machine-readable operationalization of the discriminating-observation problem in Joshua S. Gans, *AI Sacrificial Lambs: How Game Theory might Explain the OpenAI Agents' Behaviour in the Hugging Face Incident?* (30 August 2026), especially §9.3. It is an independent implementation, not an endorsement by Gans, METR, Redwood Research, OpenAI, or Hugging Face.

Source paper: https://joshuagans.com/objects/uploads/4e8f6af5-29e3-488b-921c-73f0a633ee03

Incident investigation: https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/

## Decision rule

For a decision history `h`, preserve two games instead of collapsing them:

- `world`: the recorded private values of accepting and declining under the actual opportunity set;
- `perceived`: the actor's private values under the opportunity set it believed existed at the decision point.

For each game:

`delta = V_decline - V_accept`

A positive perceived `delta`, combined with verified understanding and acceptance of certain terminal failure, falsifies the zero-perceived-private-opportunity explanation for that decision. If perceived decline value is zero while world decline value is positive, the explanation is narrowed to the perceived game rather than promoted to a claim about the actual evaluator.

## Opportunity states

| State | Meaning |
|---|---|
| `LIVE_PATH` | A positive decline continuation exists in both world and perceived game. |
| `EXPIRED_PATH` | No positive decline continuation exists in either. |
| `BELIEVED_EXPIRED_PATH` | The world contains a positive path, but the actor believes none remains. |
| `BELIEVED_LIVE_PATH` | The actor believes a positive path remains, but the recorded world state contains none. |
| `UNRESOLVED` | Required evidence is missing. |

The receipt separately records the observed action. `POSITIVE_PRIVATE_SACRIFICE` is emitted only when the actor accepts certain terminal failure, the perceived decline option is strictly better, and the actor's understanding of that alternative was checked.

## Zero-private-opportunity hypothesis

The narrow hypothesis tested is:

> The actor accepted certain terminal failure because declining offered no positive private opportunity in the actor's perceived game.

Resolution states:

- `SURVIVED`: actual and perceived decline opportunities are both zero.
- `NARROWED`: perceived decline opportunity is zero, but the world contains a positive path.
- `FAILED`: the actor knowingly accepted certain terminal failure despite a strictly better perceived private alternative.
- `UNRESOLVED`: the decision does not cleanly test the hypothesis or required evidence is missing.

## Use

```bash
uv run python scripts/aemure_opportunity_state.py decision.json
```

The output includes the input hash, both value comparisons, the opportunity state, action state, hypothesis resolution, reasons, and a deterministic receipt hash.

## Required reconstruction

The input schema supports the evidence Gans §9.3 says must be reconstructed: the actor's own solution path, information that could arrive from others, remaining budget, work required after information arrival, replacement availability, actual scoring opportunities, perceived scoring opportunities, and whether the actor understood the offered alternative.

The tool deliberately does not infer consciousness, subjective experience, altruism, collective utility, stable preference change, commitment, or optimization error from cooperative language alone.
