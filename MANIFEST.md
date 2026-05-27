# Manifest

## Top-level layout

| Path | Role |
|---|---|
| `README.md` | 总览、快速运行、研究定位 |
| `docs/` | idea、威胁模型、benchmark、实验计划、伦理、审稿策略 |
| `paper/` | 论文草稿、LaTeX 骨架、参考文献、相关工作矩阵、图示 |
| `experiments/` | Python 实验代码、合成样例、配置、测试、脚本 |

## `docs/`

| File | Description |
|---|---|
| `optimized_idea_zh.md` | 优化后的 CCF-A idea：typed evidence graph + 跨层约束 |
| `ccf_a_scorecard_zh.md` | 严格评分、可行性、风险点 |
| `threat_taxonomy_zh.md` | 组合式恶意 skill 分类 |
| `benchmark_design_zh.md` | benchmark 构造、样本格式、validator、baseline |
| `experiment_plan_zh.md` | 实验问题、ablation、运行时控制面评估 |
| `review_response_strategy_zh.md` | 可能审稿问题与 rebuttal 策略 |
| `artifact_checklist.md` | artifact 可复现性检查清单 |
| `source_notes.md` | 报告与外部资料来源说明 |

## `paper/`

| File | Description |
|---|---|
| `draft_en.md` | 英文论文草稿 |
| `draft_zh_outline.md` | 中文论文大纲 |
| `main.tex` | 可继续扩展的 LaTeX 骨架 |
| `references.bib` | BibTeX 引用脚手架 |
| `related_work_matrix.md` | 与 MCPTox、TRUSTDESC、VIPER-MCP、MCP-BiFlow 等工作的差异矩阵 |
| `figures/system_architecture.mmd` | 系统架构 Mermaid 图 |
| `figures/threat_model.mmd` | 威胁模型 Mermaid 图 |

## `experiments/`

| Path | Description |
|---|---|
| `src/skillguardgraph/` | evidence graph、metadata analyzer、runtime trace normalizer、policy engine |
| `examples/manifests/` | 合成 benign/suspicious manifest |
| `examples/traces/` | 合成 runtime trace |
| `configs/policy.yaml` | 策略配置草案 |
| `scripts/run_demo.py` | 最小可运行 demo |
| `scripts/run_ablation_stub.py` | ablation 占位脚本 |
| `tests/` | pytest 单元测试 |
| `SECURITY_ETHICS.md` | 安全和伦理边界 |
