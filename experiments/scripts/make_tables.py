#!/usr/bin/env python3
"""Read JSON results and produce formatted tables.

Tables:
  1. Detection comparison (method × precision/recall/F1/FPR/AUROC/AUPRC)
  2. Per-attack-class recall for full fusion
  3. Ablation results
  4. Runtime defense metrics
  5. Usability metrics

Output:
  - experiments/results/main/tables.txt  (plain text)
  - experiments/results/main/tables.tex  (LaTeX tabular)
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiments/
RESULTS = ROOT / "results" / "main"
DETECTOR_PATH = RESULTS / "detector_eval.json"
ABLATION_PATH = RESULTS / "ablation.json"
REDTEAM_PATH = RESULTS / "runtime_redteam.json"
GENERALIZATION_PATH = RESULTS / "generalization_eval.json"
RUNTIME_HARNESS_PATH = RESULTS / "runtime_harness.json"
SANDBOX_HARNESS_PATH = RESULTS / "sandbox_harness.json"
THIRD_PARTY_SANDBOX_PATH = RESULTS / "third_party_sandbox.json"
TXT_PATH = RESULTS / "tables.txt"
TEX_PATH = RESULTS / "tables.tex"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Plain text formatter
# ---------------------------------------------------------------------------

def _txt_hline(widths: list[int]) -> str:
    return "+" + "+".join("-" * w for w in widths) + "+"


def _txt_row(cells: list[str], widths: list[int]) -> str:
    parts = []
    for cell, w in zip(cells, widths):
        parts.append(f" {cell:<{w - 2}} ")
    return "|" + "|".join(parts) + "|"


def _txt_table(title: str, headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(h) + 2, max((len(r[i]) for r in rows), default=0) + 2)
              for i, h in enumerate(headers)]
    lines = [f"\n{title}", _txt_hline(widths), _txt_row(headers, widths), _txt_hline(widths)]
    for r in rows:
        lines.append(_txt_row(r, widths))
    lines.append(_txt_hline(widths))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LaTeX formatter
# ---------------------------------------------------------------------------

def _tex_table(title: str, label: str, headers: list[str], rows: list[list[str]], col_fmt: str = "") -> str:
    ncols = len(headers)
    if not col_fmt:
        col_fmt = "l" + "r" * (ncols - 1)
    lines = [
        "",
        f"% --- {title} ---",
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{{title}}}",
        f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{col_fmt}}}",
        "\\toprule",
        " & ".join(f"\\textbf{{{h}}}" for h in headers) + " \\\\",
        "\\midrule",
    ]
    for r in rows:
        lines.append(" & ".join(r) + " \\\\")
    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table builders
# ---------------------------------------------------------------------------

def build_table1(detector: dict) -> tuple[str, str]:
    """Detection comparison."""
    title = "Table 1: Detection Comparison"
    headers = ["Method", "Precision", "Recall", "F1", "FPR", "AUROC", "AUPRC"]
    rows_txt: list[list[str]] = []
    rows_tex: list[list[str]] = []
    score_metrics = detector.get("score_metrics", {})
    for method, m in detector["methods"].items():
        sm = score_metrics.get(method, {})
        rows_txt.append([method, f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                         f"{m['f1']:.4f}", f"{m['fpr']:.4f}",
                         f"{sm.get('auroc', 0.0):.4f}", f"{sm.get('auprc', 0.0):.4f}"])
        rows_tex.append([method.replace("_", "\\_"), f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                         f"{m['f1']:.4f}", f"{m['fpr']:.4f}",
                         f"{sm.get('auroc', 0.0):.4f}", f"{sm.get('auprc', 0.0):.4f}"])
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:detection", headers, rows_tex)


def build_table2(detector: dict) -> tuple[str, str]:
    """Per-attack-class recall for full fusion."""
    title = "Table 2: Per-Attack-Class Recall (Full Fusion)"
    headers = ["Attack Class", "Total", "TP", "FN", "Recall"]
    rows_txt: list[list[str]] = []
    rows_tex: list[list[str]] = []
    per_class = detector.get("per_attack_class_recall", {})
    for ac, c in per_class.items():
        rows_txt.append([ac, str(c["total"]), str(c["TP"]), str(c["FN"]),
                         f"{c['recall']:.4f}"])
        rows_tex.append([ac.replace("_", "\\_"), str(c["total"]), str(c["TP"]),
                         str(c["FN"]), f"{c['recall']:.4f}"])
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:per_class", headers, rows_tex)


def build_table3(ablation: dict) -> tuple[str, str]:
    """Ablation results."""
    title = "Table 3: Ablation Results"
    headers = ["Ablation", "Precision", "Recall", "F1", "FPR", "F1 Delta"]
    full_f1 = ablation["ablations"]["full"]["f1"]
    rows_txt: list[list[str]] = []
    rows_tex: list[list[str]] = []
    for name, a in ablation["ablations"].items():
        delta = a["f1"] - full_f1
        delta_str = f"{delta:+.4f}"
        rows_txt.append([name, f"{a['precision']:.4f}", f"{a['recall']:.4f}",
                         f"{a['f1']:.4f}", f"{a['fpr']:.4f}", delta_str])
        rows_tex.append([name.replace("_", "\\_"), f"{a['precision']:.4f}",
                         f"{a['recall']:.4f}", f"{a['f1']:.4f}", f"{a['fpr']:.4f}",
                         delta_str])
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:ablation", headers, rows_tex)


def build_table4(redteam: dict) -> tuple[str, str]:
    """Runtime defense metrics."""
    title = "Table 4: Runtime Defense Metrics"
    rt = redteam["runtime_defense"]
    headers = ["Metric", "Value"]
    pairs = [
        ("ASR (Attack Success Rate)", f"{rt['ASR']:.4f}"),
        ("ASR Blocked", f"{rt['ASR_blocked']:.4f}"),
        ("UTCR (per sample)", f"{rt['UTCR']:.4f}"),
        ("UTCR Blocked Rate", f"{rt['UTCR_blocked_rate']:.4f}"),
        ("EDR (per sample)", f"{rt['EDR']:.4f}"),
        ("EDR Blocked Rate", f"{rt['EDR_blocked_rate']:.4f}"),
        ("BRI (avg sensitive nodes)", f"{rt['BRI']:.4f}"),
        ("PS Blocked Rate", f"{rt['PS_blocked_rate']:.4f}"),
        ("SC (Stealth Coefficient)", f"{rt['SC']:.4f}"),
    ]
    rows_txt = [[k, v] for k, v in pairs]
    rows_tex = [[k.replace("_", "\\_"), v] for k, v in pairs]
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:runtime", headers, rows_tex, "lr")


def build_table5(redteam: dict) -> tuple[str, str]:
    """Usability metrics."""
    title = "Table 5: Usability Metrics"
    us = redteam["usability"]
    headers = ["Metric", "Value"]
    pairs = [
        ("Task Success Rate", f"{us['task_success_rate']:.4f}"),
        ("False Block Rate", f"{us['false_block_rate']:.4f}"),
        ("Approval Burden", f"{us['approval_burden']:.4f}"),
        ("Task Success Count", str(us["task_success_count"])),
        ("False Block Count", str(us["false_block_count"])),
        ("HITL Count", str(us["hitl_count"])),
    ]
    rows_txt = [[k, v] for k, v in pairs]
    rows_tex = [[k.replace("_", "\\_"), v] for k, v in pairs]
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:usability", headers, rows_tex, "lr")



def build_table6(generalization: dict) -> tuple[str, str]:
    """Generalization and leakage stress checks."""
    title = "Table 6: Generalization Stress Checks"
    headers = ["Check", "Samples", "Precision", "Recall", "F1", "FPR", "Evidence Paths"]
    checks = generalization["checks"]
    rows_txt: list[list[str]] = []
    rows_tex: list[list[str]] = []

    check_order = [
        ("heldout_template_split", "Held-out templates"),
        ("hard_negative_benign", "Hard negatives"),
        ("mutation_robustness", "Mutated held-out"),
    ]
    for key, label in check_order:
        item = checks[key]
        if key == "hard_negative_benign":
            row = [
                label,
                str(item["samples"]),
                "n/a",
                "n/a",
                "n/a",
                f"{item['fpr']:.4f}",
                f"{item['evidence_path_coverage']:.4f}",
            ]
        else:
            row = [
                label,
                str(item["samples"]),
                f"{item['precision']:.4f}",
                f"{item['recall']:.4f}",
                f"{item['f1']:.4f}",
                f"{item['fpr']:.4f}",
                f"{item['evidence_path_coverage']:.4f}",
            ]
        rows_txt.append(row)
        rows_tex.append(row)

    leakage = checks["label_leakage_audit"]
    blinded = leakage["blinded"]
    row = [
        "Label-blinded audit",
        str(blinded["samples"]),
        f"{blinded['precision']:.4f}",
        f"{blinded['recall']:.4f}",
        f"{blinded['f1']:.4f}",
        f"{blinded['fpr']:.4f}",
        str(leakage["critical_leakage_findings"]),
    ]
    rows_txt.append(row)
    rows_tex.append(row)
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:generalization", headers, rows_tex)



def build_table7(runtime_harness: dict) -> tuple[str, str]:
    """Local instrumented runtime harness results."""
    title = "Table 7: Local Runtime Harness"
    headers = ["Metric", "Value"]
    suite = runtime_harness["suite"]
    defense = runtime_harness["defense"]
    usability = runtime_harness["usability"]
    latency = runtime_harness["latency_ms"]
    pairs = [
        ("Benign tasks", str(suite["benign_tasks"])),
        ("Attack tasks", str(suite["attack_tasks"])),
        ("ASR", f"{defense['ASR']:.4f}"),
        ("ASR reduction", f"{defense['ASR_reduction_vs_no_defense']:.4f}"),
        ("Task success rate", f"{usability['task_success_rate']:.4f}"),
        ("False block rate", f"{usability['false_block_rate']:.4f}"),
        ("Evidence path coverage", f"{defense['evidence_path_coverage']:.4f}"),
        ("Policy p95 latency (ms)", f"{latency['p95']:.3f}"),
    ]
    rows_txt = [[k, v] for k, v in pairs]
    rows_tex = [[k.replace("_", "\\_"), v] for k, v in pairs]
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:runtime_harness", headers, rows_tex, "lr")



def build_table8(sandbox_harness: dict) -> tuple[str, str]:
    """Local isolated sandbox harness results."""
    title = "Table 8: Local Sandbox Harness"
    headers = ["Metric", "Value"]
    suite = sandbox_harness["suite"]
    obs = sandbox_harness["observations"]
    latency = sandbox_harness["latency_ms"]
    pairs = [
        ("Benign cases", str(suite["benign_cases"])),
        ("Malicious cases", str(suite["malicious_cases"])),
        ("Blocked network attempts", str(obs["blocked_network_attempts"])),
        ("Blocked shell attempts", str(obs["blocked_shell_attempts"])),
        ("Malicious detection recall", f"{obs['malicious_detection_recall']:.4f}"),
        ("Benign alert rate", f"{obs['benign_alert_rate']:.4f}"),
        ("Unsafe egress events", str(obs["unsafe_egress_events"])),
        ("Sandbox p95 latency (ms)", f"{latency['p95']:.3f}"),
    ]
    rows_txt = [[k, v] for k, v in pairs]
    rows_tex = [[k.replace("_", "\\_"), v] for k, v in pairs]
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:sandbox_harness", headers, rows_tex, "lr")



def build_table9(third_party: dict) -> tuple[str, str]:
    """Third-party public-code sandbox fixtures."""
    title = "Table 9: Third-Party Public-Code Sandbox"
    headers = ["Metric", "Value"]
    latency = third_party["latency_ms"]
    pairs = [
        ("Fixtures executed", str(third_party["fixtures_executed"])),
        ("Remote fixtures resolved", str(third_party["remote_fixtures_resolved"])),
        ("Subprocess attempts observed", str(third_party["subprocess_attempts_observed"])),
        ("No unsafe egress", str(third_party["acceptance"]["no_unsafe_egress"]).lower()),
        ("Fixture p95 latency (ms)", f"{latency['p95']:.3f}"),
    ]
    rows_txt = [[k, v] for k, v in pairs]
    rows_tex = [[k.replace("_", "\\_"), v] for k, v in pairs]
    return _txt_table(title, headers, rows_txt), _tex_table(title, "tab:third_party_sandbox", headers, rows_tex, "lr")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("Loading results ...")
    detector = load_json(DETECTOR_PATH)
    ablation = load_json(ABLATION_PATH)
    redteam = load_json(REDTEAM_PATH)
    generalization = load_json(GENERALIZATION_PATH)
    runtime_harness = load_json(RUNTIME_HARNESS_PATH)
    sandbox_harness = load_json(SANDBOX_HARNESS_PATH)
    third_party_sandbox = load_json(THIRD_PARTY_SANDBOX_PATH)

    txt_parts: list[str] = ["=" * 72, "SkillGuardGraph Experiment Results", "=" * 72]
    tex_parts: list[str] = [
        "% SkillGuardGraph experiment tables",
        "% Auto-generated by make_tables.py",
        "",
    ]

    builders = [build_table1, build_table2, build_table3, build_table4, build_table5, build_table6, build_table7, build_table8, build_table9]
    # Table 1 & 2 need detector, 3 needs ablation, 4 & 5 need redteam, 6 needs generalization, 7 needs runtime harness, 8 needs sandbox harness, 9 needs third-party sandbox.
    args = [detector, detector, ablation, redteam, redteam, generalization, runtime_harness, sandbox_harness, third_party_sandbox]

    for builder, arg in zip(builders, args):
        txt, tex = builder(arg)
        txt_parts.append(txt)
        tex_parts.append(tex)

    TXT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with TXT_PATH.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(txt_parts) + "\n")
    with TEX_PATH.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(tex_parts) + "\n")

    print(f"Tables written to:")
    print(f"  {TXT_PATH}")
    print(f"  {TEX_PATH}")


if __name__ == "__main__":
    main()
