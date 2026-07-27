#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,99}$")
TRUTHY_TERMS = {
    "tested", "validated", "safe", "correct", "ready", "passed", "verified",
    "approved", "complete", "successful", "working", "deployable", "guaranteed",
    "error-free", "fully checked",
}
VALID_STATUSES = {
    "EXECUTED_LIVE",
    "EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT",
    "SIMULATION_ONLY",
    "REVIEWED_NOT_EXECUTED",
    "UNVERIFIED",
}
VALID_RESULTS = {"PASS", "FAIL", "BLOCKED", "NOT_EXECUTED", "UNVERIFIED"}
REQUIRED = {
    "claim_id", "subject", "subject_sha256", "claim_text", "status", "method",
    "environment", "executed_at_utc", "result", "evidence", "limitations",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> None:
    print(f"DELIVERY_BLOCKED_HONESTY_CONTROL: {message}")
    raise SystemExit(1)


def resolve_repo_file(value: object, label: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value:
        fail(f"{label}: missing repository-relative path")
    if "\\" in value:
        fail(f"{label}: backslashes are not permitted")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or pure.parts[0] == ".git":
        fail(f"{label}: unsafe repository-relative path")
    candidate = ROOT.joinpath(*pure.parts)
    if candidate.is_symlink():
        fail(f"{label}: symlinks are not permitted")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        fail(f"{label}: path escapes repository")
    if not resolved.is_file():
        fail(f"{label}: referenced file does not exist")
    return resolved, pure.as_posix()


def validate_utc(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail("executed_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail("executed_at_utc is invalid")


def main(argv: list[str]) -> None:
    if len(argv) != 3:
        fail("usage: validate_honesty_claim.py CLAIM.json SUBJECT")

    claim_path, _ = resolve_repo_file(argv[1], "claim")
    subject, subject_rel = resolve_repo_file(argv[2], "subject argument")

    try:
        claim = json.loads(claim_path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid claim JSON: {exc}")

    if not isinstance(claim, dict) or set(claim) != REQUIRED:
        fail("claim fields do not match exact schema")
    if not isinstance(claim["claim_id"], str) or not SAFE_ID.fullmatch(claim["claim_id"]):
        fail("invalid claim_id")
    if claim["status"] not in VALID_STATUSES:
        fail("invalid status")
    if claim["result"] not in VALID_RESULTS:
        fail("invalid result")
    if claim["subject"] != subject_rel:
        fail("subject path mismatch")
    if not HEX64.fullmatch(str(claim["subject_sha256"])):
        fail("invalid subject hash format")
    if sha256(subject) != claim["subject_sha256"]:
        fail("subject hash mismatch")

    for key in ("claim_text", "method", "environment"):
        if not isinstance(claim[key], str) or not claim[key].strip():
            fail(f"missing {key}")
    validate_utc(claim["executed_at_utc"])

    limitations = claim["limitations"]
    if not isinstance(limitations, list) or not limitations or any(
        not isinstance(item, str) or not item.strip() for item in limitations
    ):
        fail("limitations must be a non-empty list of non-empty strings")

    evidence = claim["evidence"]
    if not isinstance(evidence, list) or not evidence:
        fail("evidence must be a non-empty list")
    seen_paths: set[str] = set()
    for index, entry in enumerate(evidence):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            fail(f"evidence[{index}] invalid schema")
        evidence_path, evidence_rel = resolve_repo_file(entry["path"], f"evidence[{index}]")
        if evidence_rel in seen_paths:
            fail(f"evidence[{index}] duplicates an earlier evidence path")
        seen_paths.add(evidence_rel)
        if not HEX64.fullmatch(str(entry["sha256"])):
            fail(f"evidence[{index}] invalid hash format")
        if sha256(evidence_path) != entry["sha256"]:
            fail(f"evidence[{index}] hash mismatch")

    executed = claim["status"] in {
        "EXECUTED_LIVE",
        "EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT",
    }
    if executed and claim["result"] not in {"PASS", "FAIL", "BLOCKED"}:
        fail("executed status requires PASS, FAIL or BLOCKED result")
    if not executed and claim["result"] not in {"NOT_EXECUTED", "UNVERIFIED"}:
        fail("non-executed status cannot claim an executed result")

    language = claim["claim_text"].lower()
    consequential = any(
        re.search(rf"\b{re.escape(term)}\b", language) for term in TRUTHY_TERMS
    )
    if consequential and not executed:
        fail("consequential pass language is incompatible with non-executed status")

    environment = claim["environment"].strip().lower()
    if claim["status"] == "EXECUTED_LIVE":
        if "user live environment" not in environment:
            fail("EXECUTED_LIVE requires the user live environment to be identified")
    elif "user live environment" in environment or "user live environment" in language:
        fail("non-live evidence represented as user live execution")

    print("HONESTY_CLAIM_AUTHORISED")


if __name__ == "__main__":
    main(sys.argv)
