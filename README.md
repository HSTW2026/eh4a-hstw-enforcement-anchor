# EH4A/HSTW External Enforcement Anchor

This public repository stores anonymous task anchors, non-sensitive control
evidence, release evidence and certificates. It must never contain personal
information, passwords, private keys, access tokens or confidential project
material.

## Purpose

The repository is controlled outside ChatGPT. A protected GitHub commit freezes
the exact task requirements and expected hashes before important work begins.
ChatGPT cannot treat a release as officially verified unless its certificate
matches that external anchor, every referenced file exists with the claimed
hash, and the protected release workflow is approved.

## Repository rules

1. Existing files under `anchors/` and `certificates/` are append-only.
2. An existing anchor or certificate cannot be changed, renamed or deleted.
3. Every anchor must have a matching `anchor.sha256`.
4. The `Anchor Integrity` status check must pass.
5. No credential or personal data may be committed.
6. A general instruction such as "proceed" is not permission to bypass a rule.
7. Every rules, roadmap, manifest, ledger and inspection reference must resolve
   to a real repository file with the claimed hash.
8. A release certificate must bind to a previously merged anchor and every
   contracted deliverable.
9. `v2_validator_sha256` identifies `tools/check_anchor_repo.py`;
   `v3_validator_sha256` identifies `tools/test_anchor_guard.py`.
10. Certificate and release-evidence changes require approval through the
    `verified-release` environment.

## Initial setup

Open `SETUP_AFTER_UPLOAD.pdf` and follow the numbered instructions.

## Future task flow

1. ChatGPT prepares a task-specific anchor folder.
2. The repository owner uploads it and its non-sensitive control evidence on a
   new branch.
3. GitHub runs `Anchor Integrity`.
4. The repository owner merges the pull request after the check passes.
5. The resulting Git commit URL and `anchor.sha256` become the external proof.
6. After validation, the exact deliverable evidence and release certificate are
   added through a separate pull request.
7. The `verified-release-gate` check pauses for repository-owner approval before
   that release pull request can pass.

The empty example in `templates/` is a format reference only. It is deliberately
invalid until all placeholders are replaced with real, pre-execution values.
