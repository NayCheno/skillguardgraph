# SkillGuardGraph

面向 CCF-A 安全系统论文的研究包：**跨层证据融合检测与约束执行，用于大模型 Agent 生态中的恶意 Skill 防御**。

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

## 研究定位

核心主张不是“把若干 detector 串起来”，而是：

> 恶意 skill 的关键风险通常发生在跨 metadata、implementation、permission、runtime provenance、approval、persistence 与 version update 的组合链路中。防御应将这些证据统一到 typed evidence graph，并在图上执行来源感知、权限感知、版本感知的约束。

## 安全边界

实验代码只处理合成 manifest 与合成 runtime trace：

- 不访问真实外部网络；
- 不处理真实凭证；
- 不生成可操作攻击 payload；
- 动态沙箱模块是 placeholder；
- 所有示例均使用 synthetic data 与 sinkhole 标签。

## 输出目标

该包可作为三类后续工作的起点：

- 论文：将 `paper/` 扩展为 CCS / S&P / USENIX Security / NDSS 风格系统安全论文；
- 实验：将 `experiments/` 扩展为真实 MCP/tool corpus 测量与 ablation；
- Artifact：将 `docs/artifact_checklist.md` 与 `experiments/Makefile` 扩展为可复现实验包。
