#!/usr/bin/env python3
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools/validate_honesty_claim.py"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path: Path) -> str:
    return path.absolute().relative_to(ROOT.absolute()).as_posix()


def run(claim: dict, subject: Path) -> subprocess.CompletedProcess[str]:
    claim_path = subject.parent / "claim.json"
    claim_path.write_text(json.dumps(claim), encoding="utf-8")
    return subprocess.run(
        ["python3", str(VALIDATOR), relative(claim_path), relative(subject)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def base(subject: Path, evidence: Path) -> dict:
    return {
        "claim_id": "C-001",
        "subject": relative(subject),
        "subject_sha256": digest(subject),
        "claim_text": "Exact prompt tested in a matching controlled environment.",
        "status": "EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT",
        "method": "Exact end-to-end execution with recorded exit status.",
        "environment": "Matching controlled environment.",
        "executed_at_utc": "2026-07-27T12:00:00Z",
        "result": "PASS",
        "evidence": [{"path": relative(evidence), "sha256": digest(evidence)}],
        "limitations": ["Not execution on the user live machine."],
    }


def expect(name: str, claim: dict, subject: Path, expected: int) -> None:
    result = run(claim, subject)
    if result.returncode != expected:
        raise AssertionError(
            f"{name}: expected {expected}, got {result.returncode}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )


def main() -> int:
    tests_root = ROOT / "tests"
    with tempfile.TemporaryDirectory(dir=tests_root) as temp_dir:
        directory = Path(temp_dir)
        subject = directory / "prompt.txt"
        evidence = directory / "result.txt"
        subject.write_text("do exact thing", encoding="utf-8")
        evidence.write_text("pass", encoding="utf-8")

        cases: list[tuple[str, dict, int]] = []
        valid = base(subject, evidence)
        cases.append(("valid controlled execution", valid, 0))

        changed = dict(valid)
        changed["subject_sha256"] = "0" * 64
        cases.append(("subject hash mismatch", changed, 1))

        changed = dict(valid)
        changed["subject"] = "/absolute/path.txt"
        cases.append(("absolute subject path", changed, 1))

        changed = dict(valid)
        changed["subject"] = "../prompt.txt"
        cases.append(("subject traversal", changed, 1))

        changed = dict(valid)
        changed["evidence"] = [{"path": relative(evidence), "sha256": "0" * 64}]
        cases.append(("evidence hash mismatch", changed, 1))

        changed = dict(valid)
        changed["evidence"] = [{"path": "../outside.txt", "sha256": digest(evidence)}]
        cases.append(("evidence traversal", changed, 1))

        changed = dict(valid)
        changed["evidence"] = [valid["evidence"][0], valid["evidence"][0]]
        cases.append(("duplicate evidence", changed, 1))

        changed = dict(valid)
        changed["status"] = "REVIEWED_NOT_EXECUTED"
        changed["result"] = "NOT_EXECUTED"
        cases.append(("review called tested", changed, 1))

        changed = dict(valid)
        changed["status"] = "SIMULATION_ONLY"
        changed["result"] = "NOT_EXECUTED"
        changed["claim_text"] = "Validated in the user live environment."
        cases.append(("simulation called live", changed, 1))

        changed = dict(valid)
        changed["status"] = "REVIEWED_NOT_EXECUTED"
        changed["result"] = "PASS"
        changed["claim_text"] = "Review completed without execution."
        cases.append(("non-executed pass result", changed, 1))

        changed = dict(valid)
        changed["limitations"] = []
        cases.append(("empty limitations", changed, 1))

        changed = dict(valid)
        changed["limitations"] = [""]
        cases.append(("blank limitation", changed, 1))

        changed = dict(valid)
        changed.pop("method")
        cases.append(("missing field", changed, 1))

        changed = dict(valid)
        changed["extra"] = "unexpected"
        cases.append(("unknown field", changed, 1))

        changed = dict(valid)
        changed["claim_id"] = "x"
        cases.append(("invalid claim id", changed, 1))

        changed = dict(valid)
        changed["executed_at_utc"] = "yesterday"
        cases.append(("invalid timestamp", changed, 1))

        changed = dict(valid)
        changed["status"] = "EXECUTED_LIVE"
        changed["environment"] = "test environment"
        cases.append(("live status without live environment", changed, 1))

        changed = dict(valid)
        changed["status"] = "EXECUTED_LIVE"
        changed["environment"] = "user live environment: Windows repository"
        cases.append(("valid live execution", changed, 0))

        changed = dict(valid)
        changed["result"] = "UNKNOWN"
        cases.append(("invalid result", changed, 1))

        for name, claim, expected in cases:
            expect(name, claim, subject, expected)

        symlink = directory / "evidence-link.txt"
        try:
            symlink.symlink_to(evidence)
        except (OSError, NotImplementedError):
            pass
        else:
            changed = dict(valid)
            changed["evidence"] = [{"path": relative(symlink), "sha256": digest(evidence)}]
            expect("symlink evidence", changed, subject, 1)
            cases.append(("symlink evidence", changed, 1))

        print(f"HONESTY_CONTROL_TESTS_PASS {len(cases)}/{len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
