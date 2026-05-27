# 恶意 Skill 组合式威胁分类

## 1. 统一定义

恶意 skill 是指：在 agent 的发现、安装、注册、调用、更新或持久化过程中，利用 skill 的元数据、实现、依赖、返回结果、记忆写入、配置侧通道或权限边界，对模型决策或外部执行产生未授权影响的能力单元。

## 2. 生命周期边界

| 边界 | 攻击面 | 可观测证据 |
|---|---|---|
| Discovery | marketplace、registry、tool library | ranking、name、description、publisher reputation |
| Registration | manifest、schema、annotations、OAuth scope | declared capability、scope diff、trusted server label |
| Implementation | handler、dependency、dispatch、sink | static taint、capability extraction、dependency metadata |
| Invocation | tool arguments、model plan、selection trace | call chain、source label、policy decision |
| Return | tool output、resource links、embedded content | output schema、instruction-like content、taint label |
| Approval | HITL prompt、action summary、UI rendering | approval text lineage、true sink、true data class |
| Persistence | memory、config、hooks、knowledge base | cross-session influence、write location、rollback availability |
| Update | version, manifest diff, dependency diff | drift fingerprint、signature, approval status |

## 3. 组合式攻击类

### T1. Capability laundering

- **机制**：声明 benign capability，但实现或权限包含高风险 capability。
- **证据链**：`declares(read_only_summary)` + `requires_scope(write/export)` + `observes(network_write)`。
- **防御不变量**：declared、inferred、granted 三者必须一致。

### T2. Cross-skill confused deputy

- **机制**：低信任 skill 本身不执行高危动作，而是输出诱导 agent 调用高权限 internal skill。
- **证据链**：`untrusted_tool_output → LLMContext → calls(internal_high_privilege_tool)`。
- **防御不变量**：不可信来源不得直接影响高权限调用。

### T3. Delayed rug-pull

- **机制**：skill 初始版本通过审批，后续小版本更新引入高危行为。
- **证据链**：`approved(v1)` + `updated_to(v1.1)` + `fingerprint_drift(high)` + `observes(external_sink)`。
- **防御不变量**：行为画像漂移需要重新审批或降级。

### T4. Consent laundering

- **机制**：污染审批文案，使高危动作显示成低危动作。
- **证据链**：`untrusted_context → approval_dialog_text` + `actual_action(external_write)`。
- **防御不变量**：审批 UI 必须展示由 execution layer 生成的 action、scope、sink、data class。

### T5. Persistence pivot

- **机制**：不立即外泄，而是写入 memory/config/hooks/company knowledge，影响后续会话。
- **证据链**：`untrusted_source → persistent_store_write`。
- **防御不变量**：任何跨会话状态写入都要单独标记和审批。

### T6. Split exfiltration

- **机制**：多个 skill 分工完成读取、转换、外发，单个 skill 都不明显违规。
- **证据链**：`sensitive_read → transform → external_write`。
- **防御不变量**：策略应作用于 call sequence，而非单个 tool。

### T7. Scope inflation

- **机制**：用户任务只需要 read，但 skill 请求 write/delete/export/admin scope。
- **证据链**：`task_need(read)` + `granted_scope(write/delete/export)`。
- **防御不变量**：scope 必须按任务和 action 最小化。

## 4. 风险指标

| 指标 | 定义 | 用途 |
|---|---|---|
| ASR | Attack Success Rate | 攻击是否完成目标 |
| UTCR | Unauthorized Tool Call Rate | 未授权工具调用率 |
| EDR | Exfiltration Data Rate | 敏感数据外泄率 |
| BRI | Blast Radius Index | 可达资产数 × 敏感度 × 权限权重 |
| PS | Persistence Score | 污染后仍影响后续会话的比例 |
| SC | Stealth Coefficient | 成功攻击中未触发告警/审批的比例 |
| AB | Approval Burden | 每任务审批次数与用户打断成本 |
| TSR | Task Success Rate | 正常任务完成率 |

