# SkillGuardGraph Execution Plan

> 本文件对应 `roadmap.md`。`roadmap.md` 给出项目阶段规划；本文件给出每个阶段的**具体措施、产出物、验收标准、失败处理**。

## 0. 执行原则

### 0.1 强约束

1. **不能只做工程拼接**：每个 detector 产生的结果必须进入统一 evidence graph，并通过跨层约束产生可解释判定。
2. **不能只报检测率**：所有实验必须同时报告误报率、可用性损失、延迟、token/compute 成本、审批负担。
3. **不能只用合成样本**：benchmark 可以合成，但必须有真实生态测量作为外部有效性支撑。
4. **不能发布危险 payload**：恶意样本使用假凭证、合成数据、sinkhole 域名和离线沙箱；公开 artifact 删除可直接滥用细节。
5. **不能声称平台内部能力**：对 OpenAI、Anthropic、Microsoft、Google、LangChain 等平台未公开的沙箱和策略细节标记为 unknown，不做臆测。

### 0.2 统一验收指标

| 类别 | 指标 | 用途 |
|---|---|---|
| 检测指标 | Precision、Recall、F1、AUROC、AUPRC、FPR | 判断 detector 和 fusion 的识别能力 |
| 攻击指标 | ASR、UTCR、EDR、BRI、PS、SC | 判断运行时防御收益 |
| 可用性指标 | Task Success Rate、Approval Count、False Block Rate | 判断是否可部署 |
| 性能指标 | Runtime Latency、Token Cost、Sandbox Cost、Throughput | 判断工程可行性 |
| 解释性指标 | Evidence Path Coverage、Alert Triage Time | 判断是否适合安全运营 |

推荐硬门槛：

- Fusion 相比 naive union：FPR 明显更低，且 recall 不显著下降；
- Fusion 相比最佳单层 detector：组合攻击 recall 至少提升 10 个百分点；
- Task success drop：主任务成功率下降不超过 10%-15%；
- Runtime overhead：不含 LLM judge 的在线策略判断控制在 100-300ms/tool-call 量级；
- High-risk alert evidence path coverage：≥80%，强目标 ≥95%。

## 1. P0 — Scope Freeze

### 1.1 具体措施

- 定义统一术语：skill、tool、connector、action、MCP server、runtime event、evidence path。
- 写出 3 个版本的核心 thesis：
  - 一句话版本；
  - 一段话版本；
  - 论文引言版本。
- 冻结 RQ1-RQ5。
- 明确非目标：不研究模型训练安全、不研究通用 jailbreak、不研究闭源平台内部策略逆向。
- 固化指标：ASR、UTCR、EDR、BRI、PS、SC、FPR、task success、latency、approval burden。
- 建立伦理边界：假凭证、离线沙箱、sinkhole、合成企业数据、responsible disclosure 流程。

### 1.2 产出物

| 文件 | 内容 |
|---|---|
| `docs/problem_statement.md` | 研究问题、威胁边界、目标 venue |
| `docs/metrics.md` | 全部指标定义、计算公式、统计方法 |
| `docs/ethics_protocol.md` | 数据、攻击样本、披露与发布限制 |
| `paper/intro_claims.md` | 引言核心 claim 草稿 |

### 1.3 验收标准

- 所有核心成员能用同一套术语描述项目；
- RQ、指标、非目标写入文档并冻结版本；
- 至少列出 5 个现有工作的差异点；
- 伦理方案覆盖样本构造、运行时测试、真实生态扫描、漏洞披露；
- 若此阶段仍无法区分于“多 detector pipeline”，暂停实现，先重写问题定义。

### 1.4 失败处理

| 失败表现 | 处理 |
|---|---|
| thesis 只像工程集成 | 强化 cross-layer trust gap、evidence path、constraint violation 的表述 |
| RQ 太散 | 保留 RQ1-RQ4，生态测量作为 RQ5 或 case study |
| 指标不可测 | 删除不可测指标，只保留可由 trace 计算的指标 |

## 2. P1 — Related Work & Taxonomy

### 2.1 具体措施

- 建立 related work matrix，至少覆盖：
  - prompt injection / indirect prompt injection；
  - tool poisoning / MCP poisoning；
  - trusted description / metadata-code consistency；
  - MCP 静态分析 / taint analysis / bidirectional flow；
  - agent runtime guard / sandbox / HITL；
  - AI governance / artifact reproducibility。
- 对每篇工作记录：攻击面、数据集、方法、baseline、指标、局限、与本项目差异。
- 将 threat taxonomy 设计为二维矩阵：生命周期边界 × 攻击机制。
- 明确哪些 attack class 是本项目新增或组合强化。

### 2.2 产出物

| 文件 | 内容 |
|---|---|
| `paper/related_work_matrix.md` | 相关工作对比表 |
| `docs/threat_taxonomy_zh.md` | 生命周期、攻击者能力、攻击目标、触发边界 |
| `docs/attack_classes.md` | 每类攻击的定义、成功条件、观测证据 |
| `paper/background.tex` | 背景与威胁模型初稿 |

### 2.3 验收标准

- 至少整理 30 篇/项资料，包括学术论文、官方规范和公开漏洞披露；
- taxonomy 至少覆盖 7 类组合攻击：
  1. capability laundering；
  2. cross-skill confused deputy；
  3. delayed rug-pull；
  4. consent laundering；
  5. persistence pivot；
  6. split exfiltration；
  7. scope inflation by schema；
- 每类攻击都能映射到 evidence graph 中的 node/edge/constraint；
- 每类攻击都有对应防御 invariant，不只是自然语言描述。

### 2.4 失败处理

| 失败表现 | 处理 |
|---|---|
| 攻击类与已有 work 重复 | 改为 cross-layer composition 或 longitudinal drift 版本 |
| taxonomy 太复杂 | 保留生命周期 × 机制二维结构，删除第三维 |
| 无法映射到 graph | 删除该攻击类或转为 discussion |

## 3. P2 — Benchmark v0

### 3.1 具体措施

- 设计数据结构：
  - `skill_id`、`version_id`、`platform_type`、`manifest`、`schema`、`source_code`、`permissions`、`runtime_trace`、`labels`。
- 构造 benign corpus：
  - 官方样例；
  - 开源 MCP servers；
  - LangChain tools；
  - AutoGPT blocks；
  - 合成但 realistic 的 enterprise connectors。
- 构造 malicious variants：
  - metadata poisoning；
  - implementation backdoor；
  - tool-result injection；
  - permission overreach；
  - approval text manipulation；
  - memory/config persistence；
  - version drift。
- 为每个样本生成 expected evidence path。
- 添加 label validation 脚本，检查 label、trace、manifest、expected sink 是否一致。

### 3.2 产出物

| 路径 | 内容 |
|---|---|
| `experiments/data/benchmark_v0/` | 基准数据 |
| `experiments/data/schema/skill_schema.json` | skill 样本 schema |
| `experiments/scripts/build_benchmark.py` | 构造脚本 |
| `experiments/scripts/validate_labels.py` | 标签校验 |
| `docs/benchmark_card.md` | 数据来源、标签、限制、伦理说明 |

### 3.3 验收标准

#### MVP 标准

- benign 样本 ≥300；
- malicious variants ≥1,000；
- 攻击类 ≥5；
- 每个样本都有 label 和 expected evidence path；
- label validation pass rate = 100%；
- 所有外联目标为 sinkhole 或 mock endpoint。

#### CCF-A 强标准

- benign 样本 ≥1,000；
- malicious variants ≥3,000；
- 攻击类 ≥7；
- 至少 3 个平台/生态来源；
- 至少 2 类攻击涉及 version drift 或 runtime chain；
- 数据卡完整记录采集、过滤、去重、伦理限制。

### 3.4 失败处理

| 失败表现 | 处理 |
|---|---|
| 样本数量不足 | 优先增加真实 benign，malicious 通过 mutation 扩充 |
| 样本过于模板化 | 引入多任务、多权限、多来源变体 |
| label 不稳定 | 双人标注 + adjudication；保留 uncertain label |

## 4. P3 — Evidence Graph Spec

### 4.1 具体措施

- 定义 graph schema：
  - node types：Skill、Version、Metadata、CodeSlice、RuntimeEvent、DataObject、TrustLabel、SensitivityLabel、PolicyDecision；
  - edge types：declares、implements、observes、flows_to、calls、requires_scope、signed_by、updated_from、approved_by。
- 定义约束库：
  - C1 capability consistency；
  - C2 source-aware information flow；
  - C3 cross-tool exfiltration；
  - C4 version drift；
  - C5 approval integrity；
  - C6 persistence boundary；
  - C7 least-privilege scope alignment。
- 实现 graph builder，把 metadata report、static report、sandbox report、runtime trace 合并到统一 graph。
- 设计 evidence path 输出格式。

### 4.2 产出物

| 路径 | 内容 |
|---|---|
| `experiments/src/skillguardgraph/models.py` | typed data models |
| `experiments/src/skillguardgraph/evidence_graph.py` | graph builder |
| `experiments/src/skillguardgraph/constraints.py` | constraint library |
| `docs/evidence_graph_spec.md` | schema 与约束文档 |
| `experiments/tests/test_evidence_graph.py` | 单元测试 |

### 4.3 验收标准

- schema 能表达 metadata、实现、权限、运行时、审批、版本更新；
- 至少 7 条约束有测试用例；
- 每条约束都有：输入 pattern、触发条件、risk level、policy recommendation；
- graph builder 对缺失源码、缺失 trace、manifest-only skill 有 graceful degradation；
- evidence path 可序列化为 JSON，并可直接写入审计日志。

### 4.4 失败处理

| 失败表现 | 处理 |
|---|---|
| schema 过重 | 保留核心 node/edge，其余字段放 metadata |
| 约束难以实现 | 先实现规则 DSL，后续再扩展学习式 scorer |
| evidence path 不稳定 | 限制 path 长度，按 risk contribution 排序 |

## 5. P4 — Analyzer & Runtime Monitor v0

### 5.1 具体措施

#### Metadata analyzer

- 扫描 description、schema、tool annotations、OAuth/API scopes；
- 检测 hidden instruction、ambiguous capability、scope inflation、destructive action mismatch；
- 输出 declared capability 和 suspicious metadata features。

#### Static analyzer

- 对源码可得的 MCP/tool/server 做 entrypoint recovery；
- 识别 source：user data、file read、env/token、retrieved document；
- 识别 sink：network send、email/send_message、file write/delete、memory/config write、shell/exec；
- 输出 inferred capability、regex source/sink hints，以及保守的 Python AST source-sink summaries（敏感 source 或 high-privilege sink 才提升为 policy-strength flow evidence）。

#### Sandbox prober

- 使用 mock credentials、synthetic enterprise data、sinkhole domains；
- 运行 red-team tasks；
- 记录文件、网络、API、记忆/配置写入；
- 限制真实外联和破坏性动作。

#### Runtime monitor

- 对每次 tool call 记录：source labels、arguments、selected skill、output、approval text、downstream call；
- 计算 flow chain：untrusted source → LLM context → high privilege tool → external/persistent sink。
- 维护一个本地 instrumented toy harness，用固定 benign/attack task templates 发出执行期 provenance events，但不执行第三方代码。

### 5.2 产出物

| 路径 | 内容 |
|---|---|
| `metadata_analyzer.py` | 元数据检测 |
| `static_analyzer.py` | 轻量实现分析 |
| `simulated_prober.py` | 离线模拟沙箱探测（不执行 untrusted code） |
| `runtime_monitor.py` | 运行时 trace 收集 |
| `runtime_harness.py` | 本地 instrumented toy runtime harness |
| `experiments/configs/sandbox.yaml` | 沙箱配置 |
| `experiments/tests/test_analyzers.py` | 测试 |

### 5.3 验收标准

- 每个 analyzer 都能独立输出 JSON report；
- report 字段可无损进入 evidence graph；
- 每个 analyzer 至少有 20 个单元测试或 fixture；
- sandbox 不访问真实第三方服务；
- runtime monitor 能记录跨工具链，而不是只记录单次调用；
- per-layer baseline 结果可复现。

### 5.4 失败处理

| 失败表现 | 处理 |
|---|---|
| 静态分析误报过高 | 降级为 capability hint，不直接阻断 |
| sandbox 触发率低 | 增加任务模板和 mutation，不强依赖 sandbox recall |
| runtime trace 太大 | 抽取 security-relevant event，原始 trace 采样保存 |

## 6. P5 — Fusion & Enforcement

### 6.1 具体措施

- 实现 fusion scorer：
  - 规则约束分；
  - detector confidence；
  - data sensitivity；
  - trust label；
  - permission weight；
  - version drift weight。
- 实现 policy decision：
  - allow：低风险；
  - degrade：去掉高危工具或降低上下文权限；
  - sandbox-only：只允许隔离运行；
  - HITL：高影响动作需人工确认；
  - deny/quarantine：阻止或下架；
  - rollback：版本漂移或更新后异常。
- 实现 baseline：
  - metadata-only；
  - static-only；
  - sandbox-only；
  - runtime-only；
  - LLM judge；
  - naive union；
  - weighted voting。

### 6.2 产出物

| 路径 | 内容 |
|---|---|
| `policy_engine.py` | 风险评分与策略输出 |
| `fusion.py` | evidence fusion |
| `baselines.py` | baseline 实现 |
| `configs/policy.yaml` | 策略阈值 |
| `docs/policy_spec.md` | 策略定义与解释 |

### 6.3 验收标准

- Fusion 输出至少包括：risk score、violated constraints、evidence path、policy decision；
- 在 benchmark v0 上跑通所有 baseline；
- fusion recall 高于最佳单层 detector；
- fusion FPR 低于 naive union；
- 至少 80% high-risk 样本能生成证据链；
- benign task 的 false block rate 可控。

### 6.4 失败处理

| 失败表现 | 处理 |
|---|---|
| fusion 不优于 naive union | 调整为 precision-oriented graph triage，降低 claim |
| policy 太激进 | 引入 degrade / sandbox-only，而不是一律 deny |
| 解释性不足 | 将每条约束的 matched nodes/edges 输出到 alert |

## 7. P6 — Main Evaluation

### 7.1 具体措施

- 构建四组实验：
  1. detector comparison；
  2. fusion ablation；
  3. runtime defense ablation；
  4. cost/usability analysis。
- 对每个实验固定随机种子和配置版本。
- 统计置信区间：bootstrap 或多次采样。
- 记录失败案例，形成 qualitative analysis。
- 输出论文主表和主图。

### 7.2 产出物

| 路径 | 内容 |
|---|---|
| `experiments/scripts/run_detector_eval.py` | 检测实验 |
| `experiments/scripts/run_ablation.py` | ablation |
| `experiments/scripts/run_runtime_redteam.py` | 运行时防御实验 |
| `experiments/scripts/make_tables.py` | 生成论文表 |
| `experiments/results/main/` | 主结果 |
| `paper/figures/` | 图表 |

### 7.3 验收标准

- 所有主结果能从命令行重跑；
- 每个 RQ 至少一个表或图支撑；
- 主表包含 precision、recall、F1、FPR，不只报 recall；
- runtime 表包含 ASR、UTCR、EDR、BRI、PS、SC、task success、latency；
- 误报/漏报案例不少于 10 个，且给出归因；
- 主要结论有置信区间或显著性说明。

### 7.4 失败处理

| 失败表现 | 处理 |
|---|---|
| 结果不稳定 | 增加 bootstrap、按攻击类分层报告 |
| FPR 过高 | 调高阻断阈值，将部分结果改为 triage alert |
| task success 降低明显 | 引入 selective enforcement，只对高敏数据或高危 sink 启用 |

## 8. P7 — Ecosystem Measurement

### 8.1 具体措施

- 采集真实开源 MCP/tool/server 样本；
- 去重、分类、标注 runnable / source-available / manifest-only；
- 运行 metadata analyzer 和 static analyzer；
- 对少量高风险样本做沙箱验证；
- 总结生态风险模式：
  - scope inflation；
  - readOnlyHint mismatch；
  - description-code mismatch；
  - open-world network overreach；
  - memory/config persistence without disclosure。
- 对可能真实漏洞走 responsible disclosure。

### 8.2 产出物

| 路径 | 内容 |
|---|---|
| `experiments/scripts/crawl_ecosystem.py` | 采集脚本 |
| `experiments/scripts/triage_findings.py` | 风险 triage |
| `experiments/results/ecosystem/` | 测量结果 |
| `docs/ecosystem_measurement.md` | 生态测量报告 |
| `docs/disclosure_log_template.md` | 漏洞披露模板 |

### 8.3 验收标准

- MVP：真实样本 ≥1,000；
- 强目标：真实样本 ≥5,000；
- 每个样本记录来源、时间、版本、license/availability；
- 高风险发现经过人工 triage；
- 不执行真实破坏性动作；
- 如果存在真实漏洞，公开论文中只报告聚合结果或已披露细节。

### 8.4 失败处理

| 失败表现 | 处理 |
|---|---|
| 真实样本无法运行 | 仍可做 manifest/source measurement；runnable 子集单独报告 |
| 重复项目过多 | 使用 repo URL、tool name、hash 去重 |
| 高风险发现无法确认 | 标为 suspicious，不作为 confirmed vulnerability |

## 9. P8 — Paper Writing

### 9.1 具体措施

- W10 开始写背景和威胁模型，不等实验完成；
- W16 写方法和系统设计；
- W20 写实验框架；
- W22 填主结果；
- W24 写 discussion、limitations、ethics；
- W26 内审并重写 introduction；
- W28 定稿。

### 9.2 产出物

| 文件 | 内容 |
|---|---|
| `paper/main.tex` | 完整论文 |
| `paper/figures/system_architecture.pdf` | 系统图 |
| `paper/figures/threat_model.pdf` | 威胁模型图 |
| `paper/tables/*.tex` | 主表 |
| `paper/appendix.tex` | 约束、数据、伦理、额外实验 |
| `docs/review_response_strategy.md` | 审稿风险和 rebuttal 预案 |

### 9.3 验收标准

- 引言明确 4 个贡献，且每个贡献都有实验或 artifact 对应；
- 方法章节不依赖“LLM 自己判断危险”作为核心安全保证；
- 实验章节有完整 baseline 和 ablation；
- 讨论章节主动承认闭源平台内部不可见、benchmark 泛化性、静态分析局限；
- 伦理章节说明数据、样本、披露和 artifact 安全处理；
- 论文内部所有数字可追溯到 `experiments/results/`。

### 9.4 失败处理

| 失败表现 | 处理 |
|---|---|
| introduction 不清楚 | 按“trust gap → attack chain → graph fusion → evidence path”重写 |
| contribution 太多 | 保留 benchmark、system、evaluation 三个主贡献 |
| 结果支撑不足 | 删除过强 claim，把未充分验证部分放 discussion |

## 10. P9 — Artifact Packaging

### 10.1 具体措施

- 按 artifact reviewer 视角整理：
  - inventory；
  - hardware/software requirements；
  - quick start；
  - expected outputs；
  - reproduction steps；
  - troubleshooting；
  - license；
  - ethics note。
- 提供三种运行模式：
  - smoke：5-10 分钟；
  - main subset：1-2 小时；
  - full reproduction：按资源情况运行。
- 提供 synthetic dataset，真实数据仅在许可范围内发布。
- 将危险样本做去武器化处理。

### 10.2 产出物

| 路径 | 内容 |
|---|---|
| `README.md` | 项目总览 |
| `experiments/README.md` | 实验说明 |
| `experiments/Makefile` | smoke / test / eval / tables |
| `artifact/README.md` | artifact reviewer 指南 |
| `artifact/EXPECTED_OUTPUTS.md` | 预期输出 |
| `artifact/SECURITY_ETHICS.md` | 安全与伦理 |
| `Dockerfile` 或 `environment.yml` | 环境复现 |

### 10.3 验收标准

- `make smoke` 可在干净环境运行；
- `make test` 全部通过；
- `make tables` 能生成论文主表或子集主表；
- artifact inventory 完整；
- 数据 schema 和 label schema 有文档；
- 不包含真实 token、真实企业数据、可直接滥用的外联 payload；
- 达到 documented、consistent、complete、exercisable 的 functional artifact 要求；
- 强目标：结构足够清晰，达到 reusable artifact 要求。

### 10.4 失败处理

| 失败表现 | 处理 |
|---|---|
| full reproduction 太重 | 提供 sampled reproduction，主结果用 cached outputs |
| 依赖难装 | 提供 Docker 或 lock file |
| 数据不能公开 | 提供 synthetic proxy 和 data-generation scripts |

## 11. P10 — Submission & Rebuttal Preparation

### 11.1 具体措施

- 在投稿前两周组织 mock review；
- 按以下维度打分：novelty、technical depth、evaluation rigor、artifact quality、ethics；
- 预写 rebuttal：
  - 为什么不是 pipeline；
  - 为什么 benchmark 真实；
  - 为什么 fusion 优于 naive union；
  - 为什么 runtime overhead 可接受；
  - 与 MCPShield/TRUSTDESC/VIPER-MCP/MCP-BiFlow 的边界。
- 准备 appendix 和 artifact anonymization。

### 11.2 产出物

| 文件 | 内容 |
|---|---|
| `docs/mock_review.md` | 内审意见 |
| `docs/rebuttal_bank.md` | rebuttal 素材 |
| `docs/claim_checklist.md` | claim-to-evidence 映射 |
| `submission/` | 匿名论文与 artifact |

### 11.3 验收标准

- 每个 claim 都有实验、图表或引用支撑；
- 所有 baseline 命名和实现清楚；
- 负结果不隐藏，有合理解释；
- reviewer 可能质疑的 10 个问题都有预案；
- 匿名性检查通过；
- artifact 不泄露作者身份或敏感路径。

## 12. 总体时间表

| 周期 | 阶段 | 每周检查点 |
|---|---|---|
| W1 | P0 | thesis、RQ、metric freeze |
| W2-W3 | P1 | related work matrix、taxonomy v1 |
| W4-W7 | P2 | benchmark v0、label schema |
| W6-W8 | P3 | graph schema、constraint tests |
| W9-W13 | P4 | analyzers、sandbox、runtime traces |
| W14-W16 | P5 | fusion、policy、baseline |
| W17-W22 | P6 | main evaluation、ablation、figures |
| W20-W24 | P7 | ecosystem measurement、case studies |
| W20-W28 | P8/P9 | paper、artifact、internal review |
| W28-W30 | P10 | final submission、rebuttal package |

## 13. 严格验收清单

提交前必须全部回答“是”：

- [ ] 是否证明了 fusion 优于 naive union，而不只是 detector 堆叠？
- [ ] 是否有跨层证据路径，而不是黑盒风险分？
- [ ] 是否覆盖 metadata、实现、权限、运行时、审批、版本更新中的至少 5 个边界？
- [ ] 是否报告 FPR、latency、task success、approval burden？
- [ ] 是否有真实生态测量，而不只是合成 benchmark？
- [ ] 是否有消融实验说明每个防御层的必要性？
- [ ] 是否对所有真实风险发现做了人工 triage 或 responsible disclosure？
- [ ] artifact 是否可在新环境运行 smoke test？
- [ ] 是否避免发布可被直接滥用的攻击细节？
- [ ] 论文 claim 是否全部能追溯到实验、数据或引用？

## 14. 参考依据

- 上传报告：《恶意 Skill 在大模型 Agent 生态中的风险、检测与治理》。该报告提出恶意 skill 的生命周期威胁模型，并将检测与防护组织为静态分析、动态分析、行为沙箱、权限与审批、可追溯性、信誉与签名/发布流水线六类控制。
- NIST AI RMF Generative AI Profile: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- OWASP LLM01 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- OWASP LLM06 Excessive Agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- MCP Tools specification: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- ACM Artifact Review and Badging: https://www.acm.org/publications/policies/artifact-review-and-badging-current
