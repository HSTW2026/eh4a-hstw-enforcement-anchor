# EH4A/HSTW External Enforcement Anchor

This repository stores only anonymous task anchors, hashes and release
certificates. It must never contain project artwork, personal information,
passwords, private keys or access tokens.

## Purpose

The repository is controlled outside ChatGPT. A protected GitHub commit freezes
the exact task requirements and expected hashes before important work begins.
ChatGPT cannot treat a release as officially verified unless its certificate
matches that external anchor.

## Repository rules

1. Existing files under `anchors/` and `certificates/` are append-only.
2. An existing anchor or certificate cannot be changed, renamed or deleted.
3. Every anchor must have a matching `anchor.sha256`.
4. The `Anchor Integrity` status check must pass.
5. No credential or personal data may be committed.
6. A general instruction such as "proceed" is not permission to bypass a rule.

## Initial setup

Open `SETUP_AFTER_UPLOAD.pdf` and follow the numbered instructions.

## Future task flow

1. ChatGPT prepares a task-specific anchor folder.
2. The repository owner uploads it on a new branch.
3. GitHub runs `Anchor Integrity`.
4. The repository owner merges the pull request after the check passes.
5. The resulting Git commit URL and `anchor.sha256` become the external proof.
6. After validation, the release certificate is added through a separate pull
   request.

The empty example in `templates/` is a format reference only. It is deliberately
invalid until all placeholders are replaced with real, pre-execution values.
