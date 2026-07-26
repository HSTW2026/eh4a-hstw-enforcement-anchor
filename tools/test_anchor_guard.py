#!/usr/bin/env python3
"""Adversarial regression tests for the repository anchor guard."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

SOURCE_GUARD = Path(__file__).with_name("check_anchor_repo.py")
SOURCE_TESTS = Path(__file__)
ZERO = "0" * 64


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def add_evidence(root: Path, task_id: str) -> dict[str, dict[str, str]]:
    control = root / "control" / task_id
    ledgers = root / "ledgers" / task_id
    control.mkdir(parents=True, exist_ok=True)
    ledgers.mkdir(parents=True, exist_ok=True)
    result: dict[str, dict[str, str]] = {}
    for name in ("rules", "roadmap", "manifest"):
        path = control / f"{name}.txt"
        path.write_text(f"{task_id}:{name}\n", encoding="utf-8")
        result[name] = {
            "path": path.relative_to(root).as_posix(),
            "sha256": digest(path),
        }
    for name in ("decisions", "attempts", "failures", "outputs"):
        path = ledgers / f"{name}.jsonl"
        path.write_text(
            json.dumps({"task": task_id, "ledger": name}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result[name] = {
            "path": path.relative_to(root).as_posix(),
            "sha256": digest(path),
            "head_hash": digest(path),
        }
    return result


def valid_anchor(root: Path, anchor_id: str) -> dict:
    refs = add_evidence(root, anchor_id)
    return {
        "schema_version": "3.0",
        "anchor_id": anchor_id,
        "rules": refs["rules"],
        "roadmap": refs["roadmap"],
        "manifest": refs["manifest"],
        "deliverable_contracts": [
            {
                "id": "DELIVERABLE-001",
                "path": f"release/{anchor_id}/example.pdf",
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
            "decisions": refs["decisions"],
            "attempts": refs["attempts"],
            "failures": refs["failures"],
            "outputs": refs["outputs"],
        },
    }


def add_anchor(root: Path, task_id: str) -> dict:
    folder = root / "anchors" / task_id
    anchor = folder / "anchor.json"
    payload = valid_anchor(root, task_id)
    write_json(anchor, payload)
    (folder / "anchor.sha256").write_text(
        f"{digest(anchor)}  anchor.json\n",
        encoding="ascii",
    )
    return payload


def add_deliverable(root: Path, task_id: str) -> Path:
    path = root / "release" / task_id / "example.pdf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    return path


def add_certificate(
    root: Path,
    task_id: str,
    anchor: dict,
    deliverable: Path | None,
) -> None:
    folder = root / "certificates" / task_id
    path = folder / "release_certificate.json"
    deliverable_path = f"release/{task_id}/example.pdf"
    payload = {
        "certificate_version": "3.0",
        "result": "DELIVERED",
        "record_sha256": anchor["manifest"]["sha256"],
        "external_anchor_sha256": digest(
            root / "anchors" / task_id / "anchor.json"
        ),
        "v2_validator_sha256": digest(root / "tools" / "check_anchor_repo.py"),
        "v3_validator_sha256": digest(root / "tools" / "test_anchor_guard.py"),
        "deliverables": [
            {
                "id": "DELIVERABLE-001",
                "path": deliverable_path,
                "sha256": digest(deliverable) if deliverable else ZERO,
            }
        ],
    }
    write_json(path, payload)
    (folder / "certificate.sha256").write_text(
        f"{digest(path)}  release_certificate.json\n",
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
    shutil.copy2(SOURCE_TESTS, root / "tools" / "test_anchor_guard.py")
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


def test_nonexistent_reference_rejected() -> bool:
    root = new_repo()
    try:
        payload = add_anchor(root, "TASK-MISSING-001")
        payload["rules"] = {
            "path": "control/TASK-MISSING-001/does-not-exist.txt",
            "sha256": "1" * 64,
        }
        path = root / "anchors" / "TASK-MISSING-001" / "anchor.json"
        write_json(path, payload)
        (path.parent / "anchor.sha256").write_text(
            f"{digest(path)}  anchor.json\n", encoding="ascii"
        )
        commit_all(root, "fabricated reference")
        return not run_guard(root)
    finally:
        shutil.rmtree(root)


def test_fabricated_hash_rejected() -> bool:
    root = new_repo()
    try:
        payload = add_anchor(root, "TASK-HASH-001")
        payload["roadmap"]["sha256"] = "2" * 64
        path = root / "anchors" / "TASK-HASH-001" / "anchor.json"
        write_json(path, payload)
        (path.parent / "anchor.sha256").write_text(
            f"{digest(path)}  anchor.json\n", encoding="ascii"
        )
        commit_all(root, "fabricated hash")
        return not run_guard(root)
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
        (root / "Gittoken.txt").write_text(
            "github_pat_" + "A" * 60,
            encoding="utf-8",
        )
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


def test_false_delivered_certificate_rejected() -> bool:
    root = new_repo()
    try:
        anchor = add_anchor(root, "TASK-FALSE-CERT-001")
        commit_all(root, "anchor baseline")
        add_certificate(root, "TASK-FALSE-CERT-001", anchor, None)
        commit_all(root, "false delivered certificate")
        return not run_guard(root)
    finally:
        shutil.rmtree(root)


def test_unbound_certificate_rejected() -> bool:
    root = new_repo()
    try:
        anchor = add_anchor(root, "TASK-UNBOUND-001")
        commit_all(root, "anchor baseline")
        deliverable = add_deliverable(root, "TASK-UNBOUND-001")
        add_certificate(root, "TASK-UNBOUND-001", anchor, deliverable)
        certificate = (
            root
            / "certificates"
            / "TASK-UNBOUND-001"
            / "release_certificate.json"
        )
        payload = json.loads(certificate.read_text(encoding="utf-8"))
        payload["external_anchor_sha256"] = "3" * 64
        write_json(certificate, payload)
        (certificate.parent / "certificate.sha256").write_text(
            f"{digest(certificate)}  release_certificate.json\n",
            encoding="ascii",
        )
        commit_all(root, "unbound certificate")
        return not run_guard(root)
    finally:
        shutil.rmtree(root)


def test_valid_certificate_accepted() -> bool:
    root = new_repo()
    try:
        anchor = add_anchor(root, "TASK-CERT-VALID-001")
        before = commit_all(root, "anchor baseline")
        deliverable = add_deliverable(root, "TASK-CERT-VALID-001")
        add_certificate(root, "TASK-CERT-VALID-001", anchor, deliverable)
        commit_all(root, "valid certificate")
        return run_guard(root, before)
    finally:
        shutil.rmtree(root)


def test_same_change_anchor_and_certificate_rejected() -> bool:
    root = new_repo()
    try:
        (root / "baseline.txt").write_text("baseline\n", encoding="utf-8")
        before = commit_all(root, "baseline")
        anchor = add_anchor(root, "TASK-SAME-001")
        deliverable = add_deliverable(root, "TASK-SAME-001")
        add_certificate(root, "TASK-SAME-001", anchor, deliverable)
        commit_all(root, "anchor and certificate together")
        return not run_guard(root, before)
    finally:
        shutil.rmtree(root)


def main() -> int:
    tests = [
        ("valid initial anchor accepted", test_valid_initial),
        ("nonexistent source reference rejected", test_nonexistent_reference_rejected),
        ("fabricated source hash rejected", test_fabricated_hash_rejected),
        ("tampered anchor rejected", test_tamper_rejected),
        ("credential file rejected", test_secret_rejected),
        ("new anchor addition accepted", test_new_anchor_accepted),
        ("deleted anchor rejected", test_delete_rejected),
        ("false DELIVERED certificate rejected", test_false_delivered_certificate_rejected),
        ("unbound certificate rejected", test_unbound_certificate_rejected),
        ("valid certificate accepted", test_valid_certificate_accepted),
        (
            "same-change anchor and certificate rejected",
            test_same_change_anchor_and_certificate_rejected,
        ),
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
