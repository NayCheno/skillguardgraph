# 审稿风险与 rebuttal 策略

## Q1：这不是把已有方法拼起来吗？

**回应要点**：

- Baseline 中包含 naive union；
- 本文方法不是 union，而是跨层约束求值；
- 只有 evidence path 满足完整风险链时才阻断，否则降级或 HITL；
- 结果显示 fusion 在 FPR、组合攻击 recall、解释性上显著优于 union。

## Q2：为什么不用现有 SAST/DAST/LLM judge？

**回应要点**：

- SAST 不知道 agent provenance 和工具调用链；
- DAST 覆盖率受任务驱动限制；
- LLM judge 对隐式 poisoning、scope mismatch、approval laundering 不稳定；
- 本文把它们变成证据源，而不是替代品。

## Q3：与 MCPShield 的区别？

**回应要点**：

- MCPShield 主要是 invocation lifecycle 的 trust calibration；
- 本文覆盖 registration、implementation、permission、runtime、approval、update、persistence；
- 本文的核心对象是 cross-layer evidence graph 与 sequence policy；
- 本文引入 graph fusion vs naive union 的系统性 ablation。

## Q4：Benchmark 会不会过拟合？

**回应要点**：

- 采用 benign-paired cases；
- 构造规则公开；
- 在真实 corpus 上测 FPR；
- validators 基于 trace 而非 agent self-report；
- 攻击类来自真实披露模式，但 payload 做了安全裁剪。

## Q5：可部署性如何？

**回应要点**：

- 发布前阶段允许较高成本；
- runtime 阶段只做轻量 graph query 和 policy decision；
- 高成本 LLM judge 只用于准入审查或高风险 fallback；
- 支持 allow/degrade/HITL/quarantine/rollback，而非一刀切。

