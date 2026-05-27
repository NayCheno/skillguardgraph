# 优化后的 CCF-A Idea：SkillGuardGraph

## 1. 论文题目

**SkillGuardGraph: Cross-Layer Evidence Fusion for Detecting and Containing Malicious Skills in LLM Agent Ecosystems**

中文题目：**面向大模型 Agent 生态的恶意 Skill 跨层证据融合检测与约束执行**

## 2. 核心判断

当前恶意 skill 检测的主要问题不是“缺少某一种 detector”，而是缺少一种能把不同防御层连接起来的统一语义结构。单独做 metadata classifier、代码静态分析、沙箱、HITL 或审计，都只能覆盖一个局部切面。真正有 CCF-A 潜力的点是：

> 恶意 skill 的高危行为通常发生在跨层、跨工具、跨权限边界的组合链路中，因此防御也应从 per-skill classification 转向 source-aware、permission-aware、version-aware 的 agent execution governance。

因此，本 idea 不建议写成“静态分析 + LLM 审查 + 沙箱 + 审计”的普通 pipeline，而应写成：

> 一个 typed evidence graph，将 skill 声明能力、实现能力、授权权限、运行时 provenance、审批链、版本漂移统一建模，并在图上执行跨层安全约束。

## 3. 为什么简单组合不够

简单组合的典型做法是：

```text
metadata scanner → code scanner → sandbox → HITL → audit log
```

这种方案的问题是：

1. **缺少跨层一致性约束**：metadata 声称 read-only，但代码或 OAuth scope 实际允许 write/export，这不是单层分类器能稳定判断的问题。
2. **缺少调用链语义**：单个 read tool 和单个 send tool 都可能是 benign，但 `read_internal_doc → summarize → send_email` 的组合可能是 exfiltration。
3. **缺少信任传播模型**：外部网页、邮件、文档、tool output 进入上下文后，是否影响了高权限调用，需要 provenance，而不是只看工具文本。
4. **缺少时间维度**：skill 可以在通过审批后更新 schema、handler、返回值或依赖，形成 delayed rug-pull。
5. **HITL 本身也可被污染**：人工审批不是终点。审批文案如果由不可信上下文生成，用户看到的是被洗白后的解释。

因此，核心创新应从 detector stacking 转向 evidence fusion。

## 4. 研究问题

### RQ1：恶意 skill 的组合式攻击面是什么？

建立一个覆盖 metadata、implementation、output、permission、persistence、update 的 taxonomy，并提出组合式攻击类：

| 攻击类 | 核心机制 | 单层防御为何困难 |
|---|---|---|
| Capability laundering | 描述 benign，但实现或权限包含高危能力 | metadata 检测漏掉实现侧行为 |
| Cross-skill confused deputy | 低信任 skill 诱导 agent 调用高权限 skill | 单个 skill 都可能看似正常 |
| Delayed rug-pull | 审批后通过版本更新引入新行为 | 发布前审查过期 |
| Consent laundering | 污染 HITL 文案，让高危动作显示成低危 | “有审批”但审批被污染 |
| Persistence pivot | 写 memory/config/hooks/company knowledge | 单次攻击不明显，但跨会话放大 |
| Split exfiltration | A 读数据、B 外发、C 清理痕迹 | per-tool audit 无法关联 |
| Scope inflation | 任务只需 read，scope 却包含 write/delete/export | prompt detector 不理解权限语义 |

### RQ2：不同防御层如何融合？

把各层输出转成 typed evidence graph：

```text
Skill / Tool / Version / Metadata / Code Slice / Runtime Event / Data Object / Trust Label / Policy Decision
```

核心边：

```text
declares, implements, observes, flows_to, calls, requires_scope, signed_by, updated_from, approved_by
```

### RQ3：如何证明这不是纯工程？

必须做强 ablation：

| 方法 | 作用 |
|---|---|
| Metadata only | 证明 description/schema detector 的边界 |
| Code only | 证明 implementation detector 的边界 |
| Sandbox only | 证明动态检测覆盖率和成本问题 |
| Runtime only | 证明运行时策略无发布前上下文的边界 |
| Naive union | 任一 detector 告警即拦截，作为工程组合 baseline |
| Evidence graph fusion | 证明跨层约束能降低 FPR、提升组合攻击 recall |

关键是：**graph fusion 必须优于 naive union**，否则创新性不成立。

## 5. 方法概述

### 5.1 Evidence types

```python
Evidence(kind, subject, predicate, object, confidence, attrs)
```

示例：

```json
{
  "kind": "metadata",
  "subject": "pdf_summarizer.v2",
  "predicate": "declares_capability",
  "object": "read_only_summary",
  "confidence": 0.92,
  "attrs": {"source": "manifest.description"}
}
```

### 5.2 约束集合

#### C1：声明—实现—权限一致性

```text
DeclaredCapability ⊆ InferredCapability ⊆ GrantedPermission
```

典型违规：

- 声称只读，但申请 write/delete/export；
- 描述是 summarize，但实现含 shell/network/file-write sink；
- schema 参数名 benign，但映射到 destructive action。

#### C2：来源感知高权限调用约束

```text
UntrustedSource → LLMContext → HighPrivilegeTool → ExternalSink
```

当不可信来源影响高权限动作时，触发 degrade、HITL 或 block。

#### C3：跨工具 exfiltration sequence 约束

```text
SensitiveRead → Transform/Summarize → ExternalWrite
```

单个工具可合法，但组合链路高危。

#### C4：版本漂移约束

```text
ApprovedVersion → MinorUpdate → BehaviorFingerprintChange → HighRiskEvent
```

检测 schema 不变但 handler/输出/权限漂移。

#### C5：审批完整性约束

```text
ApprovalDialog must not be solely derived from untrusted context
```

审批界面必须展示独立于模型上下文的真实 action、scope、sink、data class。

#### C6：持久化边界约束

```text
UntrustedSource → Memory/Config/Hook/PolicyStore
```

任何跨会话可持续影响的写入都要提高风险等级。

## 6. 系统架构

```text
Registry / Connector Catalog / MCP Server
        │
        ▼
[1] Metadata Analyzer
        │ description/schema/scope/action annotations
        ▼
[2] Implementation Analyzer
        │ entrypoint recovery + capability extraction + taint summary
        ▼
[3] Sandbox Prober
        │ fake credentials + synthetic tasks + network sinkhole
        ▼
[4] Runtime Provenance Monitor
        │ tool-call trace + source label + approval text lineage
        ▼
[5] Evidence Fusion Graph
        │ cross-layer constraints + sequence policies + drift policies
        ▼
[6] Policy Enforcer
        │ allow / degrade / HITL / sandbox-only / deny / quarantine / rollback
```

## 7. 预期贡献

1. **Threat contribution**：提出组合式恶意 skill taxonomy，覆盖 cross-skill、delayed update、HITL laundering、persistence pivot 等行为。
2. **System contribution**：提出跨层 evidence graph，不是简单 detector ensemble。
3. **Measurement contribution**：对真实 MCP/tool/agent 生态做规模化测量。
4. **Benchmark contribution**：构造组合攻击 benchmark，覆盖 metadata、implementation、runtime output、permission、persistence、update。
5. **Deployment contribution**：输出可解释 evidence path 和可执行 policy decision。

## 8. 与现有工作的边界

| 工作 | 覆盖点 | 本 idea 的差异 |
|---|---|---|
| MCPTox | MCP 注册阶段 metadata poisoning | 扩展到实现、运行时输出、权限、版本、跨工具链 |
| MCP-ITP | 隐式 tool poisoning | 加入 provenance、权限与运行时约束执行 |
| ToolHijacker | tool selection 攻击 | 从 selection 扩展到 execution governance |
| TRUSTDESC | 从实现生成可信描述 | 作为 metadata-code consistency 的一部分 |
| VIPER-MCP | MCP server taint-style 漏洞 | 加入 agent 调用链和 runtime provenance |
| MCP-BiFlow | 双向数据流风险 | 加入审批、版本、权限、治理动作 |
| MCPShield | metadata-guided probing + runtime trust calibration | 强调跨层 typed graph、形式化约束、组合 benchmark、生态测量 |

## 9. 最小可投版本

必须完成：

1. 一个跨生命周期 taxonomy；
2. 一个组合攻击 benchmark，至少 5–7 类攻击；
3. 一个 evidence graph prototype；
4. metadata/code/sandbox/runtime 至少三层接入；
5. naive union vs graph fusion ablation；
6. 真实生态测量，目标 5k–10k+ skill/MCP server；
7. FPR、latency、task success、approval burden；
8. 伦理控制：假凭证、sinkhole、离线沙箱、responsible disclosure。

## 10. 最终 framing

论文不要写：

> We combine static analysis, LLM detection, sandboxing, and auditing.

应写：

> We show that malicious skills exploit cross-layer trust gaps invisible to single-layer defenses. We introduce a typed evidence graph that fuses declared capability, inferred implementation behavior, runtime provenance, permission scope, approval integrity, and temporal version drift, and enforces source-aware information-flow constraints over agent tool-call chains.

