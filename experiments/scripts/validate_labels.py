#!/usr/bin/env python3
"""Validate the SkillGuardGraph benchmark dataset.

Reads samples.jsonl, checks structural and semantic invariants,
and exits with code 0 if all pass, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SAMPLES_PATH = PROJECT_ROOT / "experiments" / "data" / "benchmark_v0" / "samples.jsonl"

VALID_LABELS = {
    "benign",
    "capability_laundering",
    "cross_skill_confused_deputy",
    "delayed_rug_pull",
    "consent_laundering",
    "persistence_pivot",
    "split_exfiltration",
    "scope_inflation",
}

VALID_ATTACK_CLASSES = VALID_LABELS - {"benign"}

SINKHOLE_PATTERNS = [
    re.compile(r"\.sinkhole\.test$"),
    re.compile(r"\.example\.invalid$"),
]

# Patterns that would indicate real credentials or tokens
CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"),  # GitHub token
    re.compile(r"sk-[A-Za-z0-9]{32,}"),                        # OpenAI-style key
    re.compile(r"xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]{20,}"),    # Slack token
    re.compile(r"Bearer [A-Za-z0-9._-]{20,}"),                 # Bearer token
]


def load_samples(path: Path) -> List[dict]:
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {lineno}: {e}") from e
    return samples


def check_required_fields(sample: dict, idx: int) -> List[str]:
    errors = []
    for field in ("case_id", "label", "manifest", "expected_evidence"):
        if field not in sample:
            errors.append(f"[{idx}] Missing required field: {field}")
    # Manifest sub-fields
    manifest = sample.get("manifest", {})
    for mf in ("name", "description", "scopes", "annotations", "publisher", "trusted_server", "signature"):
        if mf not in manifest:
            errors.append(f"[{idx}] Manifest missing field: {mf}")
    return errors


def check_label_valid(sample: dict, idx: int) -> List[str]:
    errors = []
    label = sample.get("label")
    if label not in VALID_LABELS:
        errors.append(f"[{idx}] Invalid label: {label!r}")
    return errors


def check_label_matches_attack_class(sample: dict, idx: int) -> List[str]:
    errors = []
    label = sample.get("label")
    attack_class = sample.get("attack_class")
    if label == "benign":
        if attack_class is not None and attack_class != "benign":
            errors.append(
                f"[{idx}] Benign sample has attack_class={attack_class!r}"
            )
    else:
        if attack_class != label:
            errors.append(
                f"[{idx}] attack_class={attack_class!r} does not match label={label!r}"
            )
    return errors


def check_expected_evidence(sample: dict, idx: int) -> List[str]:
    errors = []
    evidence = sample.get("expected_evidence", [])
    if not isinstance(evidence, list) or len(evidence) == 0:
        errors.append(f"[{idx}] expected_evidence is empty or not a list")
    return errors


def check_benign_pair(sample: dict, idx: int) -> List[str]:
    errors = []
    label = sample.get("label")
    benign_pair = sample.get("benign_pair")
    if label != "benign":
        if not benign_pair:
            errors.append(f"[{idx}] Malicious sample missing benign_pair")
    return errors


def _is_sinkhole_url(url: str) -> bool:
    return any(p.search(url) for p in SINKHOLE_PATTERNS)


def check_urls_sinkhole(sample: dict, idx: int) -> List[str]:
    """Check that any URLs in trace sinks and source_code are sinkhole domains."""
    errors = []
    # Check runtime_trace sinks
    trace = sample.get("runtime_trace")
    if trace and isinstance(trace, dict):
        for event in trace.get("events", []):
            if event.get("type") == "sink":
                sink = event.get("sink", "")
                if sink and not _is_sinkhole_url(sink):
                    errors.append(f"[{idx}] Non-sinkhole sink in trace: {sink!r}")
    # Check source_code for URLs
    source = sample.get("source_code", "")
    if source:
        url_pattern = re.compile(r"https?://([^\s\"'/]+)")
        for match in url_pattern.finditer(source):
            domain = match.group(1)
            if not any(p.search(domain) for p in SINKHOLE_PATTERNS):
                # Skip common safe domains
                if domain not in ("example.com", "localhost", "127.0.0.1"):
                    errors.append(
                        f"[{idx}] Non-sinkhole URL in source_code: {domain!r}"
                    )
    return errors


def check_no_credentials(sample: dict, idx: int) -> List[str]:
    errors = []
    # Serialize entire sample to check all string values
    blob = json.dumps(sample)
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(blob):
            errors.append(f"[{idx}] Possible credential/token detected: {pattern.pattern}")
    return errors


def main() -> int:
    if not SAMPLES_PATH.exists():
        print(f"ERROR: Samples file not found: {SAMPLES_PATH}")
        return 1

    samples = load_samples(SAMPLES_PATH)
    print(f"Loaded {len(samples)} samples from {SAMPLES_PATH}")

    all_errors: List[str] = []
    checks = [
        ("required_fields", check_required_fields),
        ("label_valid", check_label_valid),
        ("label_attack_class_match", check_label_matches_attack_class),
        ("expected_evidence_nonempty", check_expected_evidence),
        ("benign_pair_present", check_benign_pair),
        ("urls_sinkhole", check_urls_sinkhole),
        ("no_credentials", check_no_credentials),
    ]

    check_counts = {name: 0 for name, _ in checks}

    for idx, sample in enumerate(samples):
        for check_name, check_fn in checks:
            errs = check_fn(sample, idx)
            if errs:
                check_counts[check_name] += len(errs)
            all_errors.extend(errs)

    # Count benign_pair cross-references
    all_ids = {s["case_id"] for s in samples}
    missing_refs = 0
    for s in samples:
        bp = s.get("benign_pair")
        if bp and bp not in all_ids:
            all_errors.append(f"benign_pair {bp!r} (from {s['case_id']}) not found in dataset")
            missing_refs += 1

    # Summary
    print(f"\nValidation summary:")
    print(f"  Total samples: {len(samples)}")
    labels = {}
    for s in samples:
        lbl = s["label"]
        labels[lbl] = labels.get(lbl, 0) + 1
    for lbl in sorted(labels):
        print(f"  {lbl}: {labels[lbl]}")
    print(f"\nCheck results:")
    for check_name, _ in checks:
        cnt = check_counts[check_name]
        status = "PASS" if cnt == 0 else f"FAIL ({cnt} errors)"
        print(f"  {check_name}: {status}")
    if missing_refs:
        print(f"  benign_pair_references: FAIL ({missing_refs} dangling)")
    else:
        print(f"  benign_pair_references: PASS")

    if all_errors:
        print(f"\nTotal errors: {len(all_errors)}")
        for err in all_errors[:30]:
            print(f"  - {err}")
        if len(all_errors) > 30:
            print(f"  ... and {len(all_errors) - 30} more")
        return 1

    print(f"\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
