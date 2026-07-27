# Stage 3 honesty-enforcement gate

The gate applies to repository changes under:

- `prompts/`
- `instructions/`
- `deliverables/`
- `release/`
- `certificates/`

Each changed consequential file must have exactly one changed claim record under `honesty-claims/`. The claim must bind the exact subject path and SHA-256 and pass `tools/validate_honesty_claim.py`.

`release/`, `certificates/`, and `deliverables/` require `EXECUTED_LIVE` with result `PASS`. `prompts/` and `instructions/` require either `EXECUTED_LIVE` or `EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT` with result `PASS`.

## Technical limitation

This GitHub gate cannot technically intercept or prevent an unsupported statement made only inside a live ChatGPT conversation. It can block repository-based consequential prompts, instructions, deliverables, releases, and certificates from passing external validation without matching evidence. Chat-only claims remain subject to the written honesty rule and platform behaviour rather than this repository gate.
