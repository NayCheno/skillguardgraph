# SkillGuardGraph Roadmap

> 目标：将“组合式恶意 skill 检测”从简单的 detector pipeline 提升为可投稿 CCF-A 安全会议的系统研究：**跨层证据图 + 组合攻击基准 + 源感知运行时约束 + 可复现实验 artifact**。

## 0. 项目定位

### 0.1 研究主张

恶意 skill 的核心风险不是单个 manifest、单段代码或单次 tool call，而是横跨 **注册、安装、调用、返回、审批、记忆/配置写入、版本更新** 的组合攻击链。单层防御可以降低局部风险，但无法稳定识别以下跨层失配：

- 元数据声称只读，但实现或运行时出现写入、外联、持久化行为；
- 低信任来源进入模型上下文后影响高权限工具调用；
- 用户审批界面被污染，导致“审批存在但语义失真”；
- 读敏感数据与外发动作被拆分到多个 skill，单个 skill 看起来都不恶意；
- 上架或审批时 benign，后续版本更新触发权限漂移或行为漂移。

因此，本项目的论文核心不写成“静态分析 + LLM 审查 + 沙箱 + 审计”的串联，而写成：

> **A source-aware, permission-aware, version-aware evidence-fusion system for detecting and containing cross-layer malicious skill behaviors in LLM agent ecosystems.**

### 0.2 目标论文形态

| 项 | 定位 |
|---|---|
| 目标方向 | 系统安全 / Agent 安全 / 软件供应链安全 |
| 目标 venue | CCS / IEEE S&P / USENIX Security / NDSS 风格的 CCF-A 安全系统论文 |
| 论文贡献 | 新威胁模型 + 新 benchmark + 新系统 + 真实生态测量 + ablation |
| 非目标 | 只做 prompt detector、只做 LLM judge、只做工程流水线集成 |
| 最关键证明 | Evidence graph fusion 必须显著优于单层 detector 和 naive union |

## 1. Roadmap 总览

建议按 **30 周** 做完整 CCF-A 版本；若资源有限，可压缩成 **16 周最小可投原型**，但生态测量与 artifact 质量会下降。

| 阶段 | 周期 | 主要目标 | 核心产出 | Go/No-Go 判断 |
|---|---:|---|---|---|
| P0. Scope Freeze | W1 | 固化研究问题、指标、威胁边界 | RQ、threat scope、metric spec | 是否能明确区别于“工程组合” |
| P1. Related Work & Taxonomy | W1-W3 | 系统梳理 MCP/tool poisoning、prompt injection、agent governance | related work matrix、taxonomy v1 | 是否找到清晰 novelty gap |
| P2. Benchmark v0 | W3-W7 | 构造组合式恶意 skill 基准 | benign/malicious skill corpus、label schema | 是否覆盖 ≥7 类组合攻击 |
| P3. Evidence Graph Spec | W4-W8 | 定义 typed graph、跨层约束、证据路径 | graph schema、constraint DSL | 是否能表达跨层失配 |
| P4. Analyzer & Monitor v0 | W6-W13 | 实现 metadata/static/sandbox/runtime 四类证据采集 | analyzer modules、trace schema | 单层 detector 是否可复现基线 |
| P5. Fusion & Enforcement | W10-W16 | 实现融合判定和运行时控制策略 | risk scorer、policy engine | 是否优于 naive union |
| P6. Main Evaluation | W14-W22 | 完成检测、ablation、成本、可用性实验 | tables、plots、statistical tests | FPR、task success、latency 是否可接受 |
| P7. Ecosystem Measurement | W16-W24 | 对真实开源 MCP/tool 生态做规模化测量 | ecosystem report、case studies | 是否产生真实 insight 或漏洞样本 |
| P8. Paper & Artifact | W20-W28 | 写论文、整理 artifact、准备伦理材料 | paper draft、artifact package | 是否达到 functional/reusable artifact 标准 |
| P9. Submission & Iteration | W28-W30 | 内审、定稿、投稿、准备 rebuttal | submission package、rebuttal notes | 是否具备 CCF-A 竞争力 |

## 2. 研究问题规划

| RQ | 问题 | 对应实验 |
|---|---|---|
| RQ1 | 单层检测在组合式恶意 skill 上失败在哪里？ | per-layer detector evaluation |
| RQ2 | 跨层证据图能否识别 metadata、实现、权限、运行时之间的不一致？ | graph constraint evaluation |
| RQ3 | evidence fusion 是否显著优于 naive union / voting ensemble？ | ablation against fusion baselines |
| RQ4 | 源感知运行时约束能否降低 ASR、UTCR、EDR、BRI、PS、SC？ | runtime red-team evaluation |
| RQ5 | 在真实 MCP/tool 生态中，跨层失配和权限漂移是否普遍存在？ | ecosystem measurement |

## 3. 关键里程碑

### M0 — 论文故事线冻结

**时间：W1**

交付：

- 一页式 thesis：为什么不是 pipeline，而是 cross-layer evidence fusion；
- RQ1-RQ5；
- 目标攻击类别与非目标范围；
- 指标定义：ASR、UTCR、EDR、BRI、PS、SC、FPR、task success、latency、approval burden。

达标标准：

- 能用 3 句话解释相对 MCPTox、TRUSTDESC、MCPShield、VIPER-MCP、MCP-BiFlow 的差异；
- 任一合作者读完后不会把项目理解成“把几个 detector 串起来”。

### M1 — Taxonomy 与 benchmark 协议冻结

**时间：W3-W4**

交付：

- 生命周期维度：registration、installation、invocation、tool result、approval、persistence、update；
- 攻击维度：capability laundering、cross-skill confused deputy、consent laundering、delayed rug-pull、persistence pivot、split exfiltration、scope inflation；
- label schema：attack type、trigger boundary、data source、sink、required permission、expected evidence path、success condition。

达标标准：

- 至少覆盖 7 个攻击类；
- 每类都有 benign pair、malicious pair、预期检测证据、预期防御动作；
- 所有攻击样本使用假凭证、sinkhole 域名、合成数据，不能包含可直接滥用真实系统的 payload。

### M2 — Evidence Graph v0

**时间：W6-W8**

交付：

- typed node：Skill、Version、Metadata、CodeSlice、RuntimeEvent、DataObject、TrustLabel、SensitivityLabel、PolicyDecision；
- typed edge：declares、implements、observes、flows_to、calls、requires_scope、signed_by、updated_from、approved_by；
- constraint library：capability consistency、source-aware information flow、cross-tool exfiltration、version drift、approval integrity。

达标标准：

- 能从一个 manifest、一个 static report、一个 runtime trace 生成统一 graph；
- 至少 5 条约束能在单元测试中触发；
- 每个 high-risk 判定能返回 evidence path，而不是只返回分数。

### M3 — Analyzer & sandbox v0

**时间：W10-W13**

交付：

- metadata analyzer：description/schema/scope/action tags；
- implementation analyzer：capability extraction、sink/source identification、taint-style lightweight flow；
- sandbox prober：离线任务、假数据、sinkhole、文件/网络/API/记忆写入监控；
- runtime monitor：tool-call chain、source label、approval text、output flow。

达标标准：

- 每个模块有 smoke test；
- 能跑完至少 100 个 benign + 100 个 malicious 样本；
- 能生成统一 JSONL trace；
- 能统计 per-layer precision/recall/FPR/latency。

### M4 — Fusion engine v1

**时间：W14-W16**

交付：

- constraint-based risk scorer；
- policy action：allow、degrade、sandbox-only、HITL、deny、quarantine、rollback；
- naive union、weighted voting、LLM judge、sandbox-only 等 baseline。

达标标准：

- fusion 在组合攻击集上的 recall 高于最佳单层 detector；
- fusion 的 FPR 低于 naive union；
- 至少 80% high-risk alert 有可读证据链；
- 对 benign task 的成功率损失可控。

### M5 — Main evaluation 完成

**时间：W18-W22**

交付：

- 主结果表；
- ablation 表；
- defense impact 表；
- latency/token/cost 表；
- 误报/漏报案例分析。

达标标准：

- 每个 RQ 都有对应实验结果；
- 主要结论有置信区间或 bootstrap 统计；
- 不只报告 recall，还报告 precision、FPR、task success、latency、approval burden；
- 若 fusion 不显著优于 naive union，则转为 measurement paper 或缩小 claim。

### M6 — 真实生态测量完成

**时间：W20-W24**

交付：

- 开源 MCP/tool/server 样本采集脚本；
- ecosystem measurement table；
- suspicious pattern taxonomy；
- 若发现真实漏洞，完成 responsible disclosure 草案。

达标标准：

- 最小目标：≥1,000 个真实开源 skill/tool/server；
- 强目标：≥5,000 个真实样本；
- 至少输出 3 类真实生态风险模式，例如 scope inflation、description-code mismatch、open-world tool overreach；
- 不对真实第三方系统执行破坏性调用。

### M7 — Paper & artifact 冻结

**时间：W26-W28**

交付：

- 论文完整 draft；
- artifact README、Dockerfile/Makefile、data cards、ethics statement；
- reproducibility scripts；
- appendix：attack taxonomy、constraint definitions、dataset schema。

达标标准：

- `make smoke`、`make reproduce-main`、`make tables` 可运行；
- 所有主结果可从 artifact 重新生成；
- 数据、代码、实验命令、预期输出、依赖版本完整记录；
- artifact 至少达到 ACM “Functional” 级别的 documented、consistent、complete、exercisable 要求。

## 4. 工作流拆分

| 工作流 | 目标 | 主要产出 | 与其他工作流的依赖 |
|---|---|---|---|
| WS-A Threat & Benchmark | 定义攻击与评测对象 | taxonomy、dataset、labels | 依赖 P1；供给 WS-B/WS-D |
| WS-B Evidence Graph | 抽象跨层证据与约束 | schema、constraint DSL、evidence path | 依赖 WS-A；供给 WS-C/WS-D |
| WS-C Analyzer & Enforcement | 采集证据并执行策略 | analyzers、monitor、policy engine | 依赖 WS-B；供给 WS-D |
| WS-D Evaluation | 证明有效性与可用性 | metrics、tables、plots、case studies | 依赖 WS-A/B/C |
| WS-E Paper & Artifact | 产出可投稿论文和复现实验包 | paper、artifact、ethics | 依赖所有工作流 |

## 5. 最小可投版本与强版本

### 5.1 最小可投版本

适合资源有限或时间压缩到 16 周时：

- 5 类组合攻击；
- 300-500 个 benign skill/tool 样本；
- 1,000-2,000 个 malicious variants；
- metadata + runtime trace + policy fusion；
- 轻量 static analysis；
- 小规模真实生态测量；
- 论文主张偏“new benchmark + evidence fusion prototype”。

风险：CCF-A 新颖性可能只到 borderline，因为规模和系统深度不足。

### 5.2 强版本

建议冲 CCF-A：

- 7-9 类组合攻击；
- ≥5,000 个真实开源 MCP/tool/server 样本；
- ≥3,000 个 benchmark variants；
- metadata + static + sandbox + runtime + version drift 完整融合；
- 与 naive union、LLM judge、TRUSTDESC-style description rewriting、SAST、sandbox-only 等充分对比；
- 真实生态 case studies 或 responsible disclosure；
- 可复现 artifact。

优势：能从“工程拼接”变成“系统研究 + 生态测量”。

## 6. 关键风险与应对

| 风险 | 表现 | 应对 |
|---|---|---|
| 创新性不足 | 审稿人认为只是 detector pipeline | 强调 graph constraint、evidence path、跨层不一致、fusion-vs-union ablation |
| 与 MCPShield/TRUSTDESC 重叠 | 被认为已有 probing 或 trusted description | 明确本项目覆盖 metadata、实现、权限、运行时、审批、版本漂移的统一图模型 |
| 误报率高 | 企业场景不可用 | 加入 trust label、sensitivity label、policy degrade；避免“任一告警即封禁” |
| 动态沙箱覆盖不足 | 难触发延迟/条件攻击 | 用 red-team task templates、mutation、synthetic triggers、trace replay 提高覆盖 |
| 生态样本质量差 | 开源项目不完整、重复、不可运行 | 分层统计：manifest-only、source-available、runnable、verified |
| 伦理风险 | 攻击样本被误用 | 使用合成数据、假凭证、sinkhole；不发布可直接攻击真实服务的 payload |
| 时间不足 | paper 和 artifact 同时延期 | W12 之后每两周冻结一个主表；W20 开始写 paper，不等实验全部结束 |

## 7. Go/No-Go 门槛

| 时间点 | 必须满足 | 不满足时的调整 |
|---|---|---|
| W4 | taxonomy 明确、benchmark label schema 可用 | 降级为 survey/measurement，不进入系统实现 |
| W8 | graph 能表达至少 5 类跨层约束 | 缩小为 permission/source-flow 专项论文 |
| W14 | analyzer 能稳定产生统一 trace | 放弃完整静态分析，优先 runtime fusion |
| W18 | fusion 明显优于 naive union | 重写 claim，改为 benchmark + measurement |
| W22 | FPR/task success/latency 达到可部署阈值 | 改为 offline admission system，不主张 runtime deployment |
| W26 | paper 主线、主表、artifact 全部闭环 | 推迟投稿或投系统/AI 安全 workshop 预热 |

## 8. 预期最终交付物

```text
skillguardgraph/
├── docs/
│   ├── roadmap.md
│   ├── plan.md
│   ├── threat_taxonomy_zh.md
│   ├── benchmark_design_zh.md
│   ├── experiment_plan_zh.md
│   └── artifact_checklist.md
├── paper/
│   ├── main.tex
│   ├── draft_en.md
│   ├── references.bib
│   └── figures/
└── experiments/
    ├── src/skillguardgraph/
    ├── configs/
    ├── data/
    ├── scripts/
    ├── tests/
    └── results/
```

最终应能支持三类用户：

1. 审稿人：能理解问题、方法、实验、局限与伦理；
2. 复现实验者：能用 artifact 跑出主结果；
3. 企业安全团队：能迁移 graph schema、policy engine 和审计字段到内部 skill catalog。

## 9. 参考依据

- 上传报告：《恶意 Skill 在大模型 Agent 生态中的风险、检测与治理》。该报告将恶意 skill 定义为覆盖元数据、实现、依赖、返回结果、记忆写入和配置侧通道的能力单元，并建议使用发布前审查、签名/信誉、最小权限、来源隔离、运行时策略与审计追踪的分层体系。
- NIST AI RMF Generative AI Profile: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- OWASP LLM01 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- OWASP LLM06 Excessive Agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- MCP Tools specification: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- ACM Artifact Review and Badging: https://www.acm.org/publications/policies/artifact-review-and-badging-current
