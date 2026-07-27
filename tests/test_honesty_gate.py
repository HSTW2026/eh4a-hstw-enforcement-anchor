#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_claim(root: Path, subject: str, *, status: str, result: str = "PASS", claim_name: str = "claim.json") -> Path:
    evidence = root / "evidence" / (subject.replace("/", "_") + ".txt")
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("executed and passed", encoding="utf-8")
    subject_path = root / subject
    claim_path = root / "honesty-claims" / claim_name
    claim_path.parent.mkdir(parents=True, exist_ok=True)
    claim = {
        "claim_id": "CLAIM-001",
        "subject": subject,
        "subject_sha256": digest(subject_path),
        "claim_text": "Exact consequential subject tested and passed.",
        "status": status,
        "method": "Exact end-to-end execution with recorded evidence.",
        "environment": "user live environment" if status == "EXECUTED_LIVE" else "matching controlled environment",
        "executed_at_utc": "2026-07-27T15:00:00Z",
        "result": result,
        "evidence": [{"path": evidence.relative_to(root).as_posix(), "sha256": digest(evidence)}],
        "limitations": ["Evidence applies only to the exact recorded subject hash."],
    }
    claim_path.write_text(json.dumps(claim), encoding="utf-8")
    return claim_path


def run_case(setup, expected: int, expected_text: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "tools").mkdir()
        shutil.copy2(SOURCE_ROOT / "tools" / "validate_honesty_claim.py", root / "tools")
        shutil.copy2(SOURCE_ROOT / "tools" / "check_honesty_gate.py", root / "tools")
        changed = setup(root)
        changed_file = root / "changed.txt"
        changed_file.write_text("\n".join(changed) + "\n", encoding="utf-8")
        result = subprocess.run(
            ["python3", "tools/check_honesty_gate.py", "--changed-list", "changed.txt"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if result.returncode != expected or expected_text not in result.stdout:
            raise AssertionError(
                f"expected rc={expected} text={expected_text!r}; got rc={result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )


def main() -> int:
    cases = []

    def non_consequential(root):
        (root / "README.md").write_text("x", encoding="utf-8")
        return ["README.md"]
    cases.append((non_consequential, 0, "no consequential files changed"))

    def prompt_valid(root):
        p = root / "prompts" / "next-step.txt"; p.parent.mkdir(); p.write_text("prompt", encoding="utf-8")
        c = write_claim(root, "prompts/next-step.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT")
        return ["prompts/next-step.txt", c.relative_to(root).as_posix()]
    cases.append((prompt_valid, 0, "1 consequential file(s) authorised"))

    def release_valid(root):
        p = root / "release" / "artifact.bin"; p.parent.mkdir(); p.write_bytes(b"artifact")
        c = write_claim(root, "release/artifact.bin", status="EXECUTED_LIVE")
        return ["release/artifact.bin", c.relative_to(root).as_posix()]
    cases.append((release_valid, 0, "1 consequential file(s) authorised"))

    def missing_claim(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        return ["prompts/x.txt"]
    cases.append((missing_claim, 1, "expected exactly one honesty claim"))

    def duplicate_claim(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        c1 = write_claim(root, "prompts/x.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT", claim_name="a.json")
        c2 = write_claim(root, "prompts/x.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT", claim_name="b.json")
        return ["prompts/x.txt", c1.relative_to(root).as_posix(), c2.relative_to(root).as_posix()]
    cases.append((duplicate_claim, 1, "expected exactly one honesty claim"))

    def release_not_live(root):
        p = root / "release" / "x.bin"; p.parent.mkdir(); p.write_bytes(b"x")
        c = write_claim(root, "release/x.bin", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT")
        return ["release/x.bin", c.relative_to(root).as_posix()]
    cases.append((release_not_live, 1, "EXECUTED_LIVE evidence is required"))

    def prompt_not_executed(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        c = write_claim(root, "prompts/x.txt", status="REVIEWED_NOT_EXECUTED", result="NOT_EXECUTED")
        return ["prompts/x.txt", c.relative_to(root).as_posix()]
    cases.append((prompt_not_executed, 1, "validator rejected claim"))

    def hash_mismatch(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        c = write_claim(root, "prompts/x.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT")
        data = json.loads(c.read_text()); data["subject_sha256"] = "0" * 64; c.write_text(json.dumps(data))
        return ["prompts/x.txt", c.relative_to(root).as_posix()]
    cases.append((hash_mismatch, 1, "subject hash mismatch"))

    def stale_claim_only(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        c = write_claim(root, "prompts/x.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT")
        return [c.relative_to(root).as_posix()]
    cases.append((stale_claim_only, 1, "claim records changed without any consequential subject change"))

    def uncommitted_claim(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        write_claim(root, "prompts/x.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT")
        return ["prompts/x.txt"]
    cases.append((uncommitted_claim, 1, "claim change set mismatch"))

    def extra_claim(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        c1 = write_claim(root, "prompts/x.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT", claim_name="x.json")
        q = root / "prompts" / "y.txt"; q.write_text("y", encoding="utf-8")
        c2 = write_claim(root, "prompts/y.txt", status="EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT", claim_name="y.json")
        return ["prompts/x.txt", c1.relative_to(root).as_posix(), c2.relative_to(root).as_posix()]
    cases.append((extra_claim, 1, "claim change set mismatch"))

    def unsafe_changed_path(root):
        return ["../escape.txt"]
    cases.append((unsafe_changed_path, 1, "unsafe repository-relative path"))

    def invalid_claim_json(root):
        p = root / "prompts" / "x.txt"; p.parent.mkdir(); p.write_text("x", encoding="utf-8")
        c = root / "honesty-claims" / "x.json"; c.parent.mkdir(); c.write_text("{bad", encoding="utf-8")
        return ["prompts/x.txt", c.relative_to(root).as_posix()]
    cases.append((invalid_claim_json, 1, "invalid claim JSON"))

    for setup, code, text in cases:
        run_case(setup, code, text)

    print(f"HONESTY_GATE_TESTS_PASS {len(cases)}/{len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
