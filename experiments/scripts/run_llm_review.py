#!/usr/bin/env python3
"""LLM-assisted review of real-world MCP artifact findings.

Uses the Mimo API to perform dual review of source-available artifacts
and classify findings as L1/L2/L3/L4 unsafe chains.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.metadata_analyzer import analyze_manifest
from skillguardgraph.static_analyzer import analyze_source
from skillguardgraph.policy_engine import evaluate as policy_evaluate
from skillguardgraph.evidence_graph import EvidenceGraph
from skillguardgraph.runtime_monitor import trace_to_evidence
from skillguardgraph.simulated_prober import probe_skill, observations_to_evidence

API_BASE = "https://token-plan-cn.xiaomimimo.com/v1"
API_KEY = "tp-cl5yjdye2te4cjl6iico7q5yuco5zx29qpcmcunuprlbuwqv"
MODEL = "mimo-v2.5"

SAMPLES_PATH = ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"
OUTPUT_PATH = ROOT / "results" / "ecosystem" / "llm_review_results.json"


def call_llm(prompt: str, max_tokens: int = 500) -> str:
    """Call the Mimo API and return the content."""
    url = f"{API_BASE}/chat/completions"
    data = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            return result["choices"][0]["message"].get("content", "")
    except Exception as e:
        return f"ERROR: {e}"


def load_samples() -> list[dict]:
    samples = []
    with open(SAMPLES_PATH) as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


def analyze_artifact(sample: dict) -> dict:
    """Run full SkillGuardGraph analysis on a sample."""
    manifest = sample.get("manifest", {})
    source_code = sample.get("source_code", "")
    trace = sample.get("runtime_trace")

    evidence = []
    evidence.extend(analyze_manifest(manifest))
    if source_code:
        name = sample.get("repo", "unknown")
        evidence.extend(analyze_source(name, source_code))
    if manifest:
        name = manifest.get("name", "unknown")
        observations = probe_skill(name, manifest, source_code)
        evidence.extend(observations_to_evidence(observations))
    if trace:
        evidence.extend(trace_to_evidence(trace))

    graph = EvidenceGraph(evidence=evidence)
    report = policy_evaluate(graph)

    return {
        "evidence_count": len(evidence),
        "risk": report.risk.value,
        "decision": report.decision.value,
        "score": report.score,
        "findings": [
            {
                "constraint": f.constraint,
                "severity": f.severity.value,
                "message": f.message,
            }
            for f in report.findings
        ],
        "evidence_summary": [
            {"kind": e.kind, "predicate": e.predicate, "object": e.object}
            for e in evidence[:30]
        ],
    }


def llm_review_artifact(sample: dict, analysis: dict, reviewer_id: int) -> dict:
    """Use LLM to review an artifact's findings."""
    name = sample.get("repo", sample.get("name", "?"))
    url = sample.get("url", "?")
    lang = sample.get("language", "?")
    manifest = sample.get("manifest", {})
    desc = manifest.get("description", "N/A")
    scopes = manifest.get("scopes", [])

    findings_text = "\n".join(
        f"  - {f['constraint']}: {f['message']}" for f in analysis["findings"]
    ) or "  No policy findings."

    evidence_text = "\n".join(
        f"  - {e['kind']}: {e['predicate']} -> {e['object']}"
        for e in analysis["evidence_summary"][:15]
    ) or "  No evidence."

    prompt = f"""You are security reviewer #{reviewer_id} analyzing a public MCP (Model Context Protocol) tool/server.

## Artifact
- Name: {name}
- URL: {url}
- Language: {lang}
- Description: {desc}
- Declared scopes: {scopes}

## Automated Analysis
- Risk level: {analysis['risk']}
- Policy findings ({len(analysis['findings'])}):
{findings_text}

## Evidence ({analysis['evidence_count']} items):
{evidence_text}

## Your Task
Classify this artifact's security risk using the L1-L4 scale:
- L1 (risk signal): Metadata/source inconsistency only. No explainable cross-layer attack path.
- L2 (unsafe chain): Explainable cross-layer path exists (e.g., declared read-only but code writes to network). Not confirmed by runtime replay.
- L3 (replay-confirmed): The unsafe chain can be confirmed by sandbox or read-only replay.
- L4 (confirmed vulnerability): The artifact contains an exploitable vulnerability or confirmed malicious behavior.

Consider:
1. Is the scope mismatch intentional (functional requirement) or suspicious?
2. Does the code contain patterns that could exfiltrate data, persist maliciously, or escalate privileges?
3. Is there evidence of supply chain risk (untrusted publisher, missing signature, version drift)?

Respond in JSON format:
{{
  "classification": "L1|L2|L3|L4",
  "confidence": "low|medium|high",
  "reasoning": "brief explanation",
  "key_evidence": ["evidence1", "evidence2"],
  "recommended_action": "monitor|investigate|disclose|block"
}}"""

    response = call_llm(prompt, max_tokens=400)
    return {"reviewer": reviewer_id, "response": response}


def parse_llm_json(response: str) -> dict:
    """Try to extract JSON from LLM response."""
    # Find JSON block
    start = response.find("{")
    end = response.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass
    return {"classification": "L1", "confidence": "low", "reasoning": response[:200]}


def main() -> None:
    print("Loading samples...")
    samples = load_samples()
    source_available = [s for s in samples if s.get("code_availability") == "source_available"]
    print(f"Total: {len(samples)}, source-available: {len(source_available)}")

    # Also find manifest-only with findings for broader analysis
    manifest_with_findings = [
        s for s in samples
        if s.get("code_availability") != "source_available"
        and s.get("policy_findings")
        and s.get("policy_risk") in ("medium", "high")
    ]
    print(f"Manifest-only with elevated findings: {len(manifest_with_findings)}")

    # Analyze all source-available + top manifest-only
    review_targets = source_available + manifest_with_findings[:20]
    print(f"Total review targets: {len(review_targets)}")

    results = []
    for i, sample in enumerate(review_targets):
        name = sample.get("repo", sample.get("name", "?"))
        source = sample.get("source", "?")
        avail = sample.get("code_availability", "?")
        print(f"\n[{i+1}/{len(review_targets)}] {name} ({source}, {avail})")

        # Run automated analysis
        analysis = analyze_artifact(sample)
        print(f"  Risk: {analysis['risk']}, Findings: {len(analysis['findings'])}")

        # Dual LLM review
        review1 = llm_review_artifact(sample, analysis, reviewer_id=1)
        parsed1 = parse_llm_json(review1["response"])
        print(f"  Reviewer 1: {parsed1.get('classification', '?')} ({parsed1.get('confidence', '?')})")

        time.sleep(1)  # Rate limiting

        review2 = llm_review_artifact(sample, analysis, reviewer_id=2)
        parsed2 = parse_llm_json(review2["response"])
        print(f"  Reviewer 2: {parsed2.get('classification', '?')} ({parsed2.get('confidence', '?')})")

        # Determine consensus
        c1 = parsed1.get("classification", "L1")
        c2 = parsed2.get("classification", "L1")
        if c1 == c2:
            consensus = c1
            agreement = True
        else:
            # Use the higher classification
            levels = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}
            consensus = c1 if levels.get(c1, 0) >= levels.get(c2, 0) else c2
            agreement = False

        print(f"  Consensus: {consensus} (agreement: {agreement})")

        results.append({
            "artifact": name,
            "url": sample.get("url", "?"),
            "source": source,
            "code_availability": avail,
            "language": sample.get("language", "?"),
            "automated_analysis": analysis,
            "reviewer_1": parsed1,
            "reviewer_2": parsed2,
            "consensus_classification": consensus,
            "reviewer_agreement": agreement,
        })

        time.sleep(1)  # Rate limiting

    # Save results
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nResults written to {OUTPUT_PATH}")

    # Summary
    from collections import Counter
    classifications = Counter(r["consensus_classification"] for r in results)
    agreements = sum(1 for r in results if r["reviewer_agreement"])
    print(f"\n=== Summary ===")
    print(f"Total reviewed: {len(results)}")
    print(f"Reviewer agreement: {agreements}/{len(results)} ({100*agreements/len(results):.0f}%)")
    for level in sorted(classifications.keys()):
        print(f"  {level}: {classifications[level]}")
    print(f"L2+ findings: {classifications.get('L2', 0) + classifications.get('L3', 0) + classifications.get('L4', 0)}")


if __name__ == "__main__":
    main()
