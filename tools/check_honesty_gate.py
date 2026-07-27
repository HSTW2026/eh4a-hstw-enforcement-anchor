#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_honesty_claim.py"
CONSEQUENTIAL_ROOTS = ("release/", "certificates/", "deliverables/", "prompts/", "instructions/")
LIVE_REQUIRED_ROOTS = ("release/", "certificates/", "deliverables/")
CLAIMS_ROOT = ROOT / "honesty-claims"


def fail(message: str) -> None:
    print(f"DELIVERY_BLOCKED_HONESTY_GATE: {message}")
    raise SystemExit(1)


def safe_rel(value: str, label: str) -> str:
    if not value or "\\" in value:
        fail(f"{label}: invalid repository-relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] == ".git":
        fail(f"{label}: unsafe repository-relative path")
    return pure.as_posix()


def changed_from_git(base_ref: str) -> list[str]:
    command = ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base_ref}...HEAD"]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"git diff failed: {result.stderr.strip()}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def changed_from_file(path: Path) -> list[str]:
    if not path.is_file():
        fail("changed-list file does not exist")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_claims() -> list[tuple[Path, dict]]:
    if not CLAIMS_ROOT.exists():
        return []
    claims: list[tuple[Path, dict]] = []
    for path in sorted(CLAIMS_ROOT.rglob("*.json")):
        if path.is_symlink():
            fail(f"{path.relative_to(ROOT)}: symlink claim files are not permitted")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(f"{path.relative_to(ROOT)}: invalid claim JSON: {exc}")
        if not isinstance(data, dict):
            fail(f"{path.relative_to(ROOT)}: claim must be an object")
        claims.append((path, data))
    return claims


def validate_claim(path: Path, subject: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), path.relative_to(ROOT).as_posix(), subject],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"{path.relative_to(ROOT)}: validator rejected claim: {result.stdout.strip()} {result.stderr.strip()}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--base-ref")
    source.add_argument("--changed-list", type=Path)
    args = parser.parse_args()

    raw_changed = changed_from_git(args.base_ref) if args.base_ref else changed_from_file(args.changed_list)
    changed = sorted({safe_rel(item, "changed file") for item in raw_changed})
    consequential = [path for path in changed if path.startswith(CONSEQUENTIAL_ROOTS)]

    claims = load_claims()
    indexed: dict[str, list[tuple[Path, dict]]] = {}
    for claim_path, claim in claims:
        subject = claim.get("subject")
        if isinstance(subject, str):
            indexed.setdefault(subject, []).append((claim_path, claim))

    if not consequential:
        if claims:
            changed_claims = {p for p in changed if p.startswith("honesty-claims/") and p.endswith(".json")}
            stale = [p.relative_to(ROOT).as_posix() for p, _ in claims if p.relative_to(ROOT).as_posix() in changed_claims]
            if stale:
                fail("claim records changed without any consequential subject change")
        print("HONESTY_GATE_PASS: no consequential files changed")
        return 0

    for subject in consequential:
        matches = indexed.get(subject, [])
        if len(matches) != 1:
            fail(f"{subject}: expected exactly one honesty claim, found {len(matches)}")
        claim_path, _ = matches[0]
        claim = validate_claim(claim_path, subject)
        if claim.get("result") != "PASS":
            fail(f"{subject}: honesty claim result must be PASS")
        if subject.startswith(LIVE_REQUIRED_ROOTS):
            if claim.get("status") != "EXECUTED_LIVE":
                fail(f"{subject}: EXECUTED_LIVE evidence is required")
        elif claim.get("status") not in {"EXECUTED_LIVE", "EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT"}:
            fail(f"{subject}: executed evidence is required")

    changed_claim_paths = {
        path for path in changed if path.startswith("honesty-claims/") and path.endswith(".json")
    }
    required_claim_paths = {
        path.relative_to(ROOT).as_posix() for subject in consequential for path, _ in indexed[subject]
    }
    if changed_claim_paths != required_claim_paths:
        missing = sorted(required_claim_paths - changed_claim_paths)
        extra = sorted(changed_claim_paths - required_claim_paths)
        fail(f"claim change set mismatch; missing={missing}; extra={extra}")

    print(f"HONESTY_GATE_PASS: {len(consequential)} consequential file(s) authorised")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
