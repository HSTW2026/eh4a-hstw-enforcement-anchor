#!/usr/bin/env python3
"""Fail-closed integrity checks for the EH4A/HSTW anchor repository."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,99}$")
REQUIRED_ANCHOR_FIELDS = {
    "schema_version",
    "anchor_id",
    "rules",
    "roadmap",
    "manifest",
    "deliverable_contracts",
    "inspection_receipts",
    "response_required",
    "permissions_policy",
    "trial",
    "ledger_heads",
}
REQUIRED_LEDGER_NAMES = {"decisions", "attempts", "failures", "outputs"}
PROTECTED_PREFIXES = ("anchors/", "certificates/")
REQUIRED_CERTIFICATE_FIELDS = {
    "certificate_version",
    "result",
    "record_sha256",
    "external_anchor_sha256",
    "v2_validator_sha256",
    "v3_validator_sha256",
    "deliverables",
}
SECRET_NAME = re.compile(
    r"(^|/)(\.env($|\.)|.*(?:token|password|secret|private.?key).*)",
    re.IGNORECASE,
)
SECRET_CONTENT = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
]


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, errors: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{path.relative_to(ROOT)}: invalid JSON: {exc}", errors)
        return None


def check_ref(ref: Any, label: str, errors: list[str]) -> None:
    if not isinstance(ref, dict):
        fail(f"{label}: must be an object", errors)
        return
    for field in ("path", "sha256"):
        if not isinstance(ref.get(field), str) or not ref[field]:
            fail(f"{label}: missing {field}", errors)
    value = ref.get("sha256")
    if isinstance(value, str) and not HEX64.fullmatch(value):
        fail(f"{label}: sha256 must be 64 lowercase hexadecimal characters", errors)


def check_contract(contract: Any, label: str, errors: list[str]) -> str | None:
    if not isinstance(contract, dict):
        fail(f"{label}: must be an object", errors)
        return None
    deliverable_id = contract.get("id")
    if not isinstance(deliverable_id, str) or not SAFE_ID.fullmatch(deliverable_id):
        fail(f"{label}: invalid id", errors)
        return None
    for field in ("path", "type", "expected_filename"):
        if not isinstance(contract.get(field), str) or not contract[field]:
            fail(f"{label}: missing {field}", errors)
    kind = contract.get("type")
    if kind == "PDF":
        if not isinstance(contract.get("expected_page_count"), int) or contract[
            "expected_page_count"
        ] < 1:
            fail(f"{label}: invalid expected_page_count", errors)
        if not isinstance(contract.get("min_body_font_pt"), (int, float)) or contract[
            "min_body_font_pt"
        ] < 14:
            fail(f"{label}: min_body_font_pt must be at least 14", errors)
    elif kind == "ZIP":
        members = contract.get("expected_members")
        hashes = contract.get("expected_member_hashes")
        if not isinstance(members, list) or not members:
            fail(f"{label}: expected_members must be a non-empty list", errors)
        if not isinstance(hashes, dict) or set(hashes) != set(members or []):
            fail(f"{label}: expected_member_hashes must cover every member exactly", errors)
        elif any(not isinstance(v, str) or not HEX64.fullmatch(v) for v in hashes.values()):
            fail(f"{label}: invalid member hash", errors)
    else:
        fail(f"{label}: unsupported deliverable type {kind!r}", errors)
    return deliverable_id


def check_anchor(anchor_path: Path, errors: list[str]) -> None:
    relative = anchor_path.relative_to(ROOT)
    anchor = load_json(anchor_path, errors)
    if not isinstance(anchor, dict):
        return
    if set(anchor) != REQUIRED_ANCHOR_FIELDS:
        fail(f"{relative}: fields must match the Revision 3 schema exactly", errors)
        return
    if anchor.get("schema_version") != "3.0":
        fail(f"{relative}: schema_version must be 3.0", errors)
    if not isinstance(anchor.get("anchor_id"), str) or not SAFE_ID.fullmatch(
        anchor["anchor_id"]
    ):
        fail(f"{relative}: invalid anchor_id", errors)
    for name in ("rules", "roadmap", "manifest"):
        check_ref(anchor.get(name), f"{relative}:{name}", errors)
    if anchor.get("permissions_policy") != "DENY_UNSIGNED":
        fail(f"{relative}: permissions_policy must be DENY_UNSIGNED", errors)
    if anchor.get("response_required") is not True:
        fail(f"{relative}: response_required must be true", errors)

    contracts = anchor.get("deliverable_contracts")
    if not isinstance(contracts, list) or not contracts:
        fail(f"{relative}: deliverable_contracts must be a non-empty list", errors)
    else:
        ids = [
            check_contract(row, f"{relative}:contract[{index}]", errors)
            for index, row in enumerate(contracts)
        ]
        clean_ids = [value for value in ids if value is not None]
        if len(clean_ids) != len(set(clean_ids)):
            fail(f"{relative}: duplicate deliverable contract id", errors)

    receipts = anchor.get("inspection_receipts")
    if not isinstance(receipts, list):
        fail(f"{relative}: inspection_receipts must be a list", errors)
    else:
        for index, receipt in enumerate(receipts):
            check_ref(receipt, f"{relative}:inspection_receipts[{index}]", errors)

    ledgers = anchor.get("ledger_heads")
    if not isinstance(ledgers, dict) or set(ledgers) != REQUIRED_LEDGER_NAMES:
        fail(f"{relative}: ledger_heads must contain all four required ledgers", errors)
    else:
        for name, ref in ledgers.items():
            check_ref(ref, f"{relative}:ledger_heads:{name}", errors)
            if not isinstance(ref, dict) or not isinstance(ref.get("head_hash"), str):
                fail(f"{relative}:ledger_heads:{name}: missing head_hash", errors)
            elif not HEX64.fullmatch(ref["head_hash"]):
                fail(f"{relative}:ledger_heads:{name}: invalid head_hash", errors)

    trial = anchor.get("trial")
    if trial is not None:
        expected_trial = {
            "record_path",
            "record_sha256",
            "anchor_path",
            "anchor_sha256",
            "profiles",
        }
        if not isinstance(trial, dict) or set(trial) != expected_trial:
            fail(f"{relative}: invalid controlled-trial binding", errors)
        else:
            for field in ("record_sha256", "anchor_sha256"):
                if not isinstance(trial[field], str) or not HEX64.fullmatch(trial[field]):
                    fail(f"{relative}:trial:{field}: invalid hash", errors)
            if not isinstance(trial["profiles"], list) or not trial["profiles"]:
                fail(f"{relative}:trial:profiles must be a non-empty list", errors)

    digest_file = anchor_path.with_name("anchor.sha256")
    if not digest_file.is_file():
        fail(f"{relative}: missing anchor.sha256", errors)
    else:
        expected = f"{sha256(anchor_path)}  anchor.json"
        actual = digest_file.read_text(encoding="ascii", errors="replace").strip()
        if actual != expected:
            fail(f"{digest_file.relative_to(ROOT)}: hash does not match anchor.json", errors)


def check_certificate(certificate_path: Path, errors: list[str]) -> None:
    relative = certificate_path.relative_to(ROOT)
    certificate = load_json(certificate_path, errors)
    if not isinstance(certificate, dict):
        return
    if set(certificate) != REQUIRED_CERTIFICATE_FIELDS:
        fail(f"{relative}: fields must match the Revision 3 certificate exactly", errors)
        return
    if certificate.get("certificate_version") != "3.0":
        fail(f"{relative}: certificate_version must be 3.0", errors)
    if certificate.get("result") != "DELIVERED":
        fail(f"{relative}: result must be DELIVERED", errors)
    for field in (
        "record_sha256",
        "external_anchor_sha256",
        "v2_validator_sha256",
        "v3_validator_sha256",
    ):
        value = certificate.get(field)
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            fail(f"{relative}:{field}: invalid hash", errors)
    rows = certificate.get("deliverables")
    if not isinstance(rows, list) or not rows:
        fail(f"{relative}: deliverables must be a non-empty list", errors)
    else:
        ids: list[str] = []
        for index, row in enumerate(rows):
            label = f"{relative}:deliverables[{index}]"
            if not isinstance(row, dict) or set(row) != {"id", "path", "sha256"}:
                fail(f"{label}: invalid fields", errors)
                continue
            if not isinstance(row["id"], str) or not SAFE_ID.fullmatch(row["id"]):
                fail(f"{label}: invalid id", errors)
            else:
                ids.append(row["id"])
            if not isinstance(row["path"], str) or not row["path"]:
                fail(f"{label}: missing path", errors)
            if not isinstance(row["sha256"], str) or not HEX64.fullmatch(
                row["sha256"]
            ):
                fail(f"{label}: invalid sha256", errors)
        if len(ids) != len(set(ids)):
            fail(f"{relative}: duplicate deliverable id", errors)

    digest_file = certificate_path.with_name("certificate.sha256")
    if not digest_file.is_file():
        fail(f"{relative}: missing certificate.sha256", errors)
    else:
        expected = f"{sha256(certificate_path)}  release_certificate.json"
        actual = digest_file.read_text(encoding="ascii", errors="replace").strip()
        if actual != expected:
            fail(
                f"{digest_file.relative_to(ROOT)}: hash does not match "
                "release_certificate.json",
                errors,
            )


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [ROOT / item.decode() for item in proc.stdout.split(b"\0") if item]


def check_secrets(errors: list[str]) -> None:
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            fail(f"{relative}: symbolic links are prohibited", errors)
            continue
        if SECRET_NAME.search(relative) and relative != ".gitignore":
            fail(f"{relative}: credential-like filename is prohibited", errors)
            continue
        if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            continue
        data = path.read_bytes()
        for pattern in SECRET_CONTENT:
            if pattern.search(data):
                fail(f"{relative}: credential-like content is prohibited", errors)
                break


def check_layout(errors: list[str]) -> None:
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith("anchors/") and relative != "anchors/.gitkeep":
            parts = Path(relative).parts
            if len(parts) != 3 or parts[2] not in {"anchor.json", "anchor.sha256"}:
                fail(f"{relative}: unexpected anchor-repository path", errors)
        if relative.startswith("certificates/") and relative != "certificates/.gitkeep":
            parts = Path(relative).parts
            if len(parts) != 3 or parts[2] not in {
                "release_certificate.json",
                "certificate.sha256",
            }:
                fail(f"{relative}: unexpected certificate-repository path", errors)


def changed_paths(errors: list[str]) -> list[tuple[str, str]]:
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    base: str | None = None
    if event == "pull_request":
        base_ref = os.environ.get("GITHUB_BASE_REF")
        if base_ref:
            subprocess.run(
                ["git", "fetch", "--no-tags", "origin", base_ref],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            proc = subprocess.run(
                ["git", "merge-base", "HEAD", f"origin/{base_ref}"],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            base = proc.stdout.strip()
    elif event == "push":
        before = os.environ.get("GITHUB_BEFORE", "")
        if before and before != "0" * 40:
            base = before
    if not base:
        return []
    proc = subprocess.run(
        ["git", "diff", "--name-status", "--find-renames", f"{base}..HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    changes: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        status = parts[0]
        paths = parts[1:]
        for item in paths:
            changes.append((status, item))
    return changes


def check_append_only(errors: list[str]) -> None:
    for status, path in changed_paths(errors):
        if path.startswith(PROTECTED_PREFIXES) and not status.startswith("A"):
            fail(f"{path}: anchors and certificates are append-only ({status})", errors)


def main() -> int:
    errors: list[str] = []
    if not (ROOT / ".git").exists():
        fail("repository metadata is unavailable", errors)
    try:
        check_secrets(errors)
        check_layout(errors)
        for anchor in sorted((ROOT / "anchors").glob("*/anchor.json")):
            check_anchor(anchor, errors)
        for certificate in sorted(
            (ROOT / "certificates").glob("*/release_certificate.json")
        ):
            check_certificate(certificate, errors)
        check_append_only(errors)
    except Exception as exc:
        fail(f"validator crashed closed: {type(exc).__name__}: {exc}", errors)

    if errors:
        print("ANCHOR INTEGRITY: REJECT")
        for item in errors:
            print(f"- {item}")
        return 1
    print("ANCHOR INTEGRITY: ACCEPT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
