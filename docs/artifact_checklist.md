# Artifact Checklist

该清单用于把当前研究包推进为安全会议 artifact。

## Structure

- [x] 顶层拆分为 `docs/`、`paper/`、`experiments/`。
- [x] `paper/` 中保留论文草稿、LaTeX 骨架、引用和图示。
- [x] `experiments/` 中保留代码、配置、示例、测试和运行脚本。
- [x] `docs/` 中保留威胁模型、benchmark、实验计划、评分和审稿策略。

## Reproducibility

- [x] 提供 `experiments/README.md`。
- [x] 提供 `experiments/Makefile`（支持 Windows 和 Linux）。
- [x] 提供 `scripts/run_demo.py`。
- [x] 提供 pytest 单元测试（73 tests，覆盖 C1-C7 正负例与 analyzer schema edge cases）。
- [x] 提供 benchmark generation seed（`seed=42`，在 `build_benchmark.py` 中硬编码）。
- [x] 提供完整 ablation runner（`run_ablation.py`，6 种配置）。
- [x] 提供结果聚合与图表生成脚本（`make_tables.py`）。
- [x] 提供 latency 测量脚本（`run_latency.py`）。
- [x] 提供 bootstrap CI 脚本（`run_bootstrap_ci.py`，1000 replicates）。
- [x] 提供 label validation 脚本（`validate_labels.py`）。
- [x] 提供 `Dockerfile` 和 `environment.yml`。
- [x] 提供真实 corpus 获取脚本（`experiments/scripts/crawl_real_ecosystem.py`，默认只做被动公开元数据/源码采集）。

## Safety

- [x] 示例只使用 synthetic data。
- [x] 外发目标只使用 sinkhole 标签。
- [x] 不包含真实 token、真实账号或真实外联。
- [x] 不包含可直接攻击真实系统的 payload。
- [x] sandbox prober 明确标注为 simulated（不执行 untrusted code）。
- [x] `SECURITY_ETHICS.md` 完整。
- [x] 真实漏洞测量 responsible disclosure SOP（`docs/disclosure_log_template.md` 与 `artifact/SECURITY_ETHICS.md`）。

## Review-readiness

- [x] 有 naive union baseline 的明确对比位置。
- [x] 有 weighted voting baseline。
- [x] 有 metadata-only、static-only、sandbox-only、runtime-only ablation。
- [x] 有 sequence constraint ablation。
- [x] 有 CCF-A 风险评分。
- [x] 有统计显著性检验（bootstrap 95% CI）。
- [x] 有 FPR 分析（当前 fusion FPR = 0.000，bootstrap 95% CI [0.000, 0.000]）。
- [x] 有 latency 测量（total pipeline p50 = 0.3ms，p95 = 0.4ms）。
- [x] 有 per-attack-class recall 报告。
- [x] 论文有相关工作对比表。
- [ ] 需要补齐真实生态测量运行结果（已有真实 corpus 入口脚本；当前报告仍主要是 synthetic measurement）。
- [x] 需要补齐 failure case analysis（`experiments/scripts/run_failure_analysis.py`，`experiments/results/main/failure_analysis.json`）。
- [x] 需要补齐 AUROC/AUPRC 指标（`experiments/results/main/detector_eval.json` 的 `score_metrics`）。

## CI

- [x] GitHub Actions CI（`.github/workflows/ci.yml`）。
- [x] 多 Python 版本测试（3.10-3.13）。
- [x] reproduce pipeline 在 CI 中运行。
- [x] 结果文件作为 artifact 上传。
