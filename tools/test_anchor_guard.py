#!/usr/bin/env python3
"""Regression tests for the repository anchor guard."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

SOURCE_GUARD = Path(__file__).with_name("check_anchor_repo.py")
ZERO = "0" * 64


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def valid_anchor(anchor_id: str) -> dict:
    ref = {"path": "release/example.txt", "sha256": ZERO}
    ledger = {
        "path": "ledgers/example.jsonl",
        "sha256": ZERO,
        "head_hash": ZERO,
    }
    return {
        "schema_version": "3.0",
        "anchor_id": anchor_id,
        "rules": dict(ref),
        "roadmap": dict(ref),
        "manifest": dict(ref),
        "deliverable_contracts": [
            {
                "id": "DELIVERABLE-001",
                "path": "deliverables/example.pdf",
                "type": "PDF",
                "expected_filename": "example.pdf",
                "expected_page_count": 1,
                "min_body_font_pt": 14,
            }
        ],
        "inspection_receipts": [],
        "response_required": True,
        "permissions_policy": "DENY_UNSIGNED",
        "trial": None,
        "ledger_heads": {
            "decisions": dict(ledger),
            "attempts": dict(ledger),
            "failures": dict(ledger),
            "outputs": dict(ledger),
        },
    }


def add_anchor(root: Path, task_id: str) -> None:
    folder = root / "anchors" / task_id
    anchor = folder / "anchor.json"
    write_json(anchor, valid_anchor(task_id))
    digest = hashlib.sha256(anchor.read_bytes()).hexdigest()
    (folder / "anchor.sha256").write_text(
        f"{digest}  anchor.json\n",
        encoding="ascii",
    )


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout.strip()


def new_repo() -> Path:
    root = Path(tempfile.mkdtemp(prefix="anchor-guard-test-"))
    (root / "tools").mkdir()
    shutil.copy2(SOURCE_GUARD, root / "tools" / "check_anchor_repo.py")
    (root / ".gitignore").write_text("*.token\n", encoding="utf-8")
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Anchor Test")
    git(root, "config", "user.email", "anchor-test@example.invalid")
    return root


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


def run_guard(root: Path, before: str = "0" * 40) -> bool:
    env = dict(os.environ)
    env.update(GITHUB_EVENT_NAME="push", GITHUB_BEFORE=before)
    proc = subprocess.run(
        ["python3", "tools/check_anchor_repo.py"],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.returncode == 0


def test_valid_initial() -> bool:
    root = new_repo()
    try:
        add_anchor(root, "TASK-VALID-001")
        commit_all(root, "valid initial anchor")
        return run_guard(root)
    finally:
        shutil.rmtree(root)


def test_tamper_rejected() -> bool:
    root = new_repo()
    try:
        add_anchor(root, "TASK-TAMPER-001")
        before = commit_all(root, "baseline")
        anchor = root / "anchors" / "TASK-TAMPER-001" / "anchor.json"
        payload = json.loads(anchor.read_text(encoding="utf-8"))
        payload["response_required"] = False
        write_json(anchor, payload)
        commit_all(root, "tamper")
        return not run_guard(root, before)
    finally:
        shutil.rmtree(root)


def test_secret_rejected() -> bool:
    root = new_repo()
    try:
        add_anchor(root, "TASK-SECRET-001")
        (root / "Gittoken.txt").write_text("github_pat_" + "A" * 60, encoding="utf-8")
        commit_all(root, "secret fixture")
        return not run_guard(root)
    finally:
        shutil.rmtree(root)


def test_new_anchor_accepted() -> bool:
    root = new_repo()
    try:
        add_anchor(root, "TASK-ADD-001")
        before = commit_all(root, "baseline")
        add_anchor(root, "TASK-ADD-002")
        commit_all(root, "append anchor")
        return run_guard(root, before)
    finally:
        shutil.rmtree(root)


def test_delete_rejected() -> bool:
    root = new_repo()
    try:
        add_anchor(root, "TASK-DELETE-001")
        before = commit_all(root, "baseline")
        folder = root / "anchors" / "TASK-DELETE-001"
        (folder / "anchor.json").unlink()
        (folder / "anchor.sha256").unlink()
        folder.rmdir()
        commit_all(root, "delete anchor")
        return not run_guard(root, before)
    finally:
        shutil.rmtree(root)


def test_invalid_certificate_rejected() -> bool:
    root = new_repo()
    try:
        add_anchor(root, "TASK-CERT-001")
        certificate = root / "certificates" / "TASK-CERT-001"
        certificate.mkdir(parents=True)
        write_json(
            certificate / "release_certificate.json",
            {
                "certificate_version": "3.0",
                "result": "DELIVERED",
                "record_sha256": ZERO,
                "external_anchor_sha256": ZERO,
                "v2_validator_sha256": ZERO,
                "v3_validator_sha256": ZERO,
                "deliverables": [],
            },
        )
        (certificate / "certificate.sha256").write_text(
            f"{ZERO}  release_certificate.json\n",
            encoding="ascii",
        )
        commit_all(root, "invalid certificate")
        return not run_guard(root)
    finally:
        shutil.rmtree(root)


def main() -> int:
    tests = [
        ("valid initial anchor accepted", test_valid_initial),
        ("tampered anchor rejected", test_tamper_rejected),
        ("credential file rejected", test_secret_rejected),
        ("new anchor addition accepted", test_new_anchor_accepted),
        ("deleted anchor rejected", test_delete_rejected),
        ("invalid certificate rejected", test_invalid_certificate_rejected),
    ]
    failures: list[str] = []
    for label, test in tests:
        try:
            result = test()
        except Exception as exc:
            result = False
            label = f"{label} ({type(exc).__name__}: {exc})"
        print(f"{'PASS' if result else 'FAIL'}: {label}")
        if not result:
            failures.append(label)
    print(f"RESULT: {len(tests) - len(failures)}/{len(tests)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
