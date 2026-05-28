SkillGuardGraph - Cross-Layer Evidence Fusion for Malicious Skill Defense in LLM Agent Ecosystems

面向 CCF-A 安全系统论文的研究包：**跨层证据融合检测与约束执行，用于大模型 Agent 生态中的恶意 Skill 防御**。

> **Claim boundary:** See [`docs/claim_boundary.md`](docs/claim_boundary.md) for the precise boundary between what the artifact can and cannot claim. The primary evaluation is on a synthetic benchmark; real-ecosystem evidence is passive catalog-level measurement only.

本包已按论文研发流程重新整理为三个主目录：

```text
skillguardgraph/
├── docs/          # idea、威胁模型、benchmark、实验计划、CCF-A 评分、审稿策略
├── paper/         # 论文草稿、LaTeX 骨架、参考文献、相关工作矩阵、图示
└── experiments/   # 可运行实验代码、配置、合成样例、测试、脚本
```

## 快速阅读顺序

1. `docs/optimized_idea_zh.md`
2. `docs/threat_taxonomy_zh.md`
3. `paper/draft_en.md`
4. `paper/draft_zh_outline.md`
5. `experiments/README.md`
6. `docs/experiment_plan_zh.md`
7. `docs/ccf_a_scorecard_zh.md`
8. `docs/claim_boundary.md`

## 快速运行

```bash
cd experiments
python -m venv .venv
source .venv/bin/activate
pip install -e .
python scripts/run_demo.py
python -m pytest -q
```

也可以不安装包，直接使用：

```bash
cd experiments
PYTHONPATH=src python scripts/run_demo.py
PYTHONPATH=src python -m pytest -q
```

## Research Thesis

The core claim is NOT "stack detectors together," but:

> Malicious skills exploit cross-layer trust gaps across metadata, implementation, permission, runtime provenance, approval, persistence, and version update. Defense must unify evidence into a typed evidence graph and enforce source-aware, permission-aware, version-aware constraints.

**Current claim boundary:** SkillGuardGraph demonstrates typed evidence fusion with cross-layer constraints on a synthetic benchmark (4,010 samples, 7 attack classes) and passive public MCP ecosystem measurement (1,000 artifacts, 6 sources). Real-world deployment validation and confirmed vulnerability claims remain future work. See [`docs/claim_boundary.md`](docs/claim_boundary.md).

## Safety and Ethics

Experiment code operates under strict safety constraints:

- Synthetic benchmark data uses fake credentials and sinkhole domains (`*.example.invalid`, `*.sinkhole.test`);
- Real ecosystem measurement is passive metadata/source collection only;
- No real credentials are used; no operational payloads are generated;
- Runtime and sandbox harnesses execute only repository-controlled toy cases, curated public-code fixtures, or bounded source-available package/repo cases under isolation;
- See [`artifact/SECURITY_ETHICS.md`](artifact/SECURITY_ETHICS.md) for full ethics guidance.

## Current Status

- **Prototype:** Fully functional with typed evidence graph, C1-C7 constraints, fusion engine, and policy enforcer.
- **Synthetic benchmark:** 4,010 samples (1,000 benign + 3,010 malicious across 7 attack classes).
- **Evaluation:** Detection comparison (8 methods), ablation (6 variants), runtime red-team, local harness (105+105 tasks), sandbox harness, third-party/corpus/GitHub/TypeScript sandbox suites, significance tests, generalization stress checks, independent benchmark, latency, bootstrap CI, failure analysis.
- **Ecosystem measurement:** 1,000 main batch + 2k/3k/5k/10k supplementary batches across 6 public sources.
- **Paper:** Complete draft in `paper/main.tex` with all sections.
- **Claim boundary:** See [`docs/claim_boundary.md`](docs/claim_boundary.md).
