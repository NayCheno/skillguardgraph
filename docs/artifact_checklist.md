# Artifact Checklist

该清单用于把当前研究包推进为安全会议 artifact。

## Structure

- [x] 顶层拆分为 `docs/`、`paper/`、`experiments/`。
- [x] `paper/` 中保留论文草稿、LaTeX 骨架、引用和图示。
- [x] `experiments/` 中保留代码、配置、示例、测试和运行脚本。
- [x] `docs/` 中保留威胁模型、benchmark、实验计划、评分和审稿策略。

## Reproducibility

- [x] 提供 `experiments/README.md`。
- [x] 提供 `experiments/Makefile`。
- [x] 提供 `scripts/run_demo.py`。
- [x] 提供 pytest 单元测试。
- [ ] 提供真实 corpus 获取脚本。
- [ ] 提供 benchmark generation seed 与样本版本号。
- [ ] 提供完整 ablation runner。
- [ ] 提供结果聚合与图表生成脚本。

## Safety

- [x] 示例只使用 synthetic data。
- [x] 外发目标只使用 sinkhole 标签。
- [x] 不包含真实 token、真实账号或真实外联。
- [x] 不包含可直接攻击真实系统的 payload。
- [ ] 动态沙箱需要在后续实现中强制网络隔离与假凭证。
- [ ] 真实漏洞测量需要补充 responsible disclosure SOP。

## Review-readiness

- [x] 有 naive union baseline 的明确对比位置。
- [x] 有 metadata-only、code-only、sandbox-only、runtime-only ablation 计划。
- [x] 有 CCF-A 风险评分。
- [ ] 需要补齐真实数据规模、统计显著性检验、FPR 分析。
