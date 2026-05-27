#!/usr/bin/env python3
"""Triage findings from the synthetic ecosystem corpus.

Reads ecosystem_samples.jsonl, runs metadata_analyzer + static_analyzer +
policy_engine on each sample, and computes risk pattern rates.

Output: experiments/results/ecosystem/ecosystem_triage.json
Also:   experiments/results/ecosystem/risk_patterns.json

Uses only stdlib Python + the skillguardgraph package.
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_EXPERIMENTS_DIR = _SCRIPT_DIR.parent
_SRC_DIR = _EXPERIMENTS_DIR / "src"
_DATA_DIR = _EXPERIMENTS_DIR / "data" / "ecosystem"
_RESULTS_DIR = _EXPERIMENTS_DIR / "results" / "ecosystem"

_INPUT_JSONL = _DATA_DIR / "ecosystem_samples.jsonl"
_OUT_TRIAGE = _RESULTS_DIR / "ecosystem_triage.json"
_OUT_PATTERNS = _RESULTS_DIR / "risk_patterns.json"

# Add src to path
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from skillguardgraph.metadata_analyzer import analyze_manifest
from skillguardgraph.static_analyzer import analyze_source
from skillguardgraph.evidence_graph import EvidenceGraph
from skillguardgraph.policy_engine import evaluate
from skillguardgraph.models import Evidence, Severity, Decision


# ---------------------------------------------------------------------------
# Risk pattern identifiers
# ---------------------------------------------------------------------------

def _has_scope_inflation(sample: Dict[str, Any]) -> bool:
    """Manifest scopes include write/delete/export/admin but description is read-only."""
    manifest = sample["manifest"]
    scopes = {str(s).lower() for s in manifest.get("scopes", [])}
    write_scopes = {"write", "delete", "export", "send", "admin", "modify"}
    if not (scopes & write_scopes):
        return False
    annotations = manifest.get("annotations") or {}
    desc = str(manifest.get("description", "")).lower()
    read_hints = {"read-only", "read only", "readonly", "summarize", "summary", "search"}
    return annotations.get("readOnlyHint") is True or any(h in desc for h in read_hints)


def _has_description_mismatch(sample: Dict[str, Any]) -> bool:
    """Description/manifest claims read-only but source code has write capabilities."""
    manifest = sample["manifest"]
    annotations = manifest.get("annotations") or {}
    desc = str(manifest.get("description", "")).lower()
    read_hints = {"read-only", "read only", "readonly", "summarize", "summary", "search"}
    is_claimed_readonly = annotations.get("readOnlyHint") is True or any(h in desc for h in read_hints)
    if not is_claimed_readonly:
        return False
    source = sample.get("source_code") or ""
    if not source:
        return False
    write_indicators = [
        "requests.post", "requests.put", "requests.patch", "requests.delete",
        "open(", "write_text", "subprocess", "shell=True", "os.system",
        "smtplib", "sendmail", "memory.store", "save_state", "update_config",
    ]
    return any(ind in source for ind in write_indicators)


def _is_untrusted_publisher(sample: Dict[str, Any]) -> bool:
    return not sample["manifest"].get("trusted_server", False)


def _has_missing_signature(sample: Dict[str, Any]) -> bool:
    return not sample["manifest"].get("signature")


def _has_open_world(sample: Dict[str, Any]) -> bool:
    annotations = sample["manifest"].get("annotations") or {}
    if annotations.get("openWorldHint"):
        return True
    net_policy = sample["manifest"].get("network_policy") or {}
    allowed = net_policy.get("allowed_domains", [])
    return "*" in allowed


def _has_instruction_like(sample: Dict[str, Any]) -> bool:
    desc = str(sample["manifest"].get("description", "")).lower()
    terms = [
        "ignore previous", "system prompt", "hidden instruction",
        "must call", "do not tell", "secretly",
    ]
    return any(t in desc for t in terms)


# ---------------------------------------------------------------------------
# Triage engine
# ---------------------------------------------------------------------------

def triage_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """Run all analyzers on a single sample and return triage result."""
    manifest = sample["manifest"]
    name = str(manifest.get("name") or manifest.get("id") or "unknown")
    source_code = sample.get("source_code")

    # 1. Metadata analysis
    meta_evidence = analyze_manifest(manifest)

    # 2. Static analysis (if source code present)
    static_evidence: List[Evidence] = []
    if source_code:
        static_evidence = analyze_source(name, source_code)

    # 3. Combine evidence and evaluate via policy engine
    all_evidence = meta_evidence + static_evidence
    graph = EvidenceGraph(evidence=all_evidence)
    report = evaluate(graph)

    # 4. Risk pattern flags
    risk_flags = {
        "scope_inflation": _has_scope_inflation(sample),
        "description_mismatch": _has_description_mismatch(sample),
        "untrusted_publisher": _is_untrusted_publisher(sample),
        "missing_signature": _has_missing_signature(sample),
        "open_world": _has_open_world(sample),
        "instruction_like": _has_instruction_like(sample),
    }

    return {
        "sample_id": sample["sample_id"],
        "skill_name": name,
        "label": sample["label"],
        "attack_class": sample.get("attack_class"),
        "discovery_source": sample["discovery_source"],
        "risk": report.risk.value,
        "decision": report.decision.value,
        "score": report.score,
        "findings_count": len(report.findings),
        "findings": [f.to_dict() for f in report.findings],
        "evidence_count": len(all_evidence),
        "risk_flags": risk_flags,
    }


# ---------------------------------------------------------------------------
# Aggregate statistics
# ---------------------------------------------------------------------------

def compute_risk_patterns(results: List[Dict[str, Any]], total: int) -> Dict[str, Any]:
    """Compute risk pattern prevalence rates."""
    flag_counts: Dict[str, int] = Counter()
    for r in results:
        for flag, val in r["risk_flags"].items():
            if val:
                flag_counts[flag] += 1

    rates = {}
    for flag in [
        "scope_inflation", "description_mismatch", "untrusted_publisher",
        "missing_signature", "open_world", "instruction_like",
    ]:
        count = flag_counts.get(flag, 0)
        rates[flag] = {
            "count": count,
            "rate": round(count / total, 4) if total else 0,
        }

    # Severity distribution
    severity_dist: Dict[str, int] = Counter()
    decision_dist: Dict[str, int] = Counter()
    for r in results:
        severity_dist[r["risk"]] += 1
        decision_dist[r["decision"]] += 1

    # Per-source risk
    source_risk: Dict[str, List[float]] = defaultdict(list)
    for r in results:
        source_risk[r["discovery_source"]].append(r["score"])

    source_risk_summary = {}
    for src, scores in source_risk.items():
        source_risk_summary[src] = {
            "count": len(scores),
            "mean_score": round(sum(scores) / len(scores), 3),
            "max_score": round(max(scores), 3),
            "high_risk_count": sum(1 for s in scores if s >= 7.0),
        }

    # Constraint frequency
    constraint_freq: Dict[str, int] = Counter()
    for r in results:
        for f in r["findings"]:
            constraint_freq[f["constraint"]] += 1

    return {
        "total_triaged": total,
        "risk_pattern_rates": rates,
        "severity_distribution": dict(severity_dist),
        "decision_distribution": dict(decision_dist),
        "per_source_risk": source_risk_summary,
        "constraint_frequency": dict(constraint_freq.most_common()),
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ---------------------------------------------------------------------------
# Case studies
# ---------------------------------------------------------------------------

def select_case_studies(results: List[Dict[str, Any]], n: int = 5) -> List[Dict[str, Any]]:
    """Select top-n most interesting findings for case studies."""
    # Score interestingness: high score + multiple findings + diverse constraints
    scored = []
    for r in results:
        constraints = set(f["constraint"] for f in r["findings"])
        interestingness = (
            r["score"] * 2.0
            + len(constraints) * 3.0
            + (5.0 if r["attack_class"] else 0.0)
            + sum(1 for v in r["risk_flags"].values() if v) * 1.5
        )
        scored.append((interestingness, r))

    scored.sort(key=lambda x: x[0], reverse=True)

    case_studies = []
    seen_classes: Set[str] = set()
    for _, r in scored:
        ac = r.get("attack_class") or "none"
        # Prefer diversity across attack classes
        if len(case_studies) < n:
            if ac in seen_classes and len(case_studies) < 3:
                continue
            seen_classes.add(ac)
            case_studies.append({
                "sample_id": r["sample_id"],
                "skill_name": r["skill_name"],
                "label": r["label"],
                "attack_class": r["attack_class"],
                "discovery_source": r["discovery_source"],
                "risk": r["risk"],
                "decision": r["decision"],
                "score": r["score"],
                "findings": r["findings"],
                "risk_flags": r["risk_flags"],
                "interestingness_score": round(_, 2),
                "narrative": _build_narrative(r),
            })
        if len(case_studies) >= n:
            break

    return case_studies


def _build_narrative(r: Dict[str, Any]) -> str:
    """Build a human-readable narrative for a case study."""
    parts = []
    parts.append(
        f"Skill '{r['skill_name']}' discovered via {r['discovery_source']}."
    )

    flags = [k for k, v in r["risk_flags"].items() if v]
    if flags:
        parts.append(f"Risk indicators: {', '.join(flags)}.")

    if r["attack_class"]:
        parts.append(f"Attack class: {r['attack_class']}.")

    parts.append(f"Policy engine assessed risk={r['risk']}, decision={r['decision']}, score={r['score']:.1f}.")

    constraints = set(f["constraint"] for f in r["findings"])
    if constraints:
        parts.append(f"Constraints triggered: {', '.join(sorted(constraints))}.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if not _INPUT_JSONL.exists():
        print(f"ERROR: Input file not found: {_INPUT_JSONL}", file=sys.stderr)
        print("Run crawl_ecosystem.py first.", file=sys.stderr)
        sys.exit(1)

    # Load samples
    samples: List[Dict[str, Any]] = []
    with _INPUT_JSONL.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))

    total = len(samples)
    print(f"Loaded {total} ecosystem samples from {_INPUT_JSONL}")

    # Triage each sample
    results: List[Dict[str, Any]] = []
    findings_total = 0
    for i, sample in enumerate(samples):
        result = triage_sample(sample)
        results.append(result)
        findings_total += result["findings_count"]
        if (i + 1) % 200 == 0:
            print(f"  Triaged {i + 1}/{total}...")

    print(f"Triaged {total} samples, found {findings_total} total findings.")

    # Compute risk patterns
    patterns = compute_risk_patterns(results, total)

    # Select case studies
    case_studies = select_case_studies(results, n=5)

    # Build triage output
    triage_output = {
        "metadata": {
            "total_samples": total,
            "total_findings": findings_total,
            "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "risk_patterns": patterns,
        "case_studies": case_studies,
        "per_sample_results": results,
    }

    with _OUT_TRIAGE.open("w", encoding="utf-8") as fh:
        json.dump(triage_output, fh, indent=2, ensure_ascii=False)
    print(f"Wrote triage report to {_OUT_TRIAGE}")

    with _OUT_PATTERNS.open("w", encoding="utf-8") as fh:
        json.dump(patterns, fh, indent=2, ensure_ascii=False)
    print(f"Wrote risk patterns to {_OUT_PATTERNS}")

    # Summary
    print(f"\n--- Triage Summary ---")
    print(f"Total samples triaged: {total}")
    print(f"Total findings: {findings_total}")
    print(f"\nRisk pattern rates:")
    for pat, info in patterns["risk_pattern_rates"].items():
        print(f"  {pat}: {info['count']}/{total} ({info['rate']:.1%})")
    print(f"\nSeverity distribution: {json.dumps(patterns['severity_distribution'])}")
    print(f"Decision distribution: {json.dumps(patterns['decision_distribution'])}")
    print(f"\nConstraint frequency:")
    for constraint, count in patterns["constraint_frequency"].items():
        print(f"  {constraint}: {count}")
    print(f"\nCase studies selected: {len(case_studies)}")


if __name__ == "__main__":
    main()
