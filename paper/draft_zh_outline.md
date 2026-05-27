# 中文论文大纲：SkillGuardGraph

## 标题

面向大模型 Agent 生态的恶意 Skill 跨层证据融合检测与约束执行

## 摘要要点

- Skill 是 agent 生态中的外部能力单元，连接权限、数据与执行器。
- 现有防御多是单层：元数据审查、源码分析、沙箱、HITL、审计。
- 恶意 skill 的关键风险是组合式：跨层、跨工具、跨权限、跨版本。
- 本文提出 typed evidence graph，将声明能力、实现行为、运行时 provenance、权限、审批和版本漂移融合。
- 在图上执行来源感知、权限感知和版本感知的安全约束。
- 通过组合攻击 benchmark 和真实生态测量证明优于 naive union。

## 章节结构

1. 引言
   - Agent skill 生态扩张；
   - 单点 prompt defense 不足；
   - 组合攻击链示例；
   - 贡献总结。
2. 背景
   - Skill 定义；
   - MCP 作为代表协议；
   - 平台型与框架型生态差异。
3. 威胁模型
   - 资产；
   - 攻击者能力；
   - 生命周期入口；
   - 非目标。
4. 组合式恶意行为分类
   - capability laundering；
   - cross-skill confused deputy；
   - delayed rug-pull；
   - consent laundering；
   - persistence pivot；
   - split exfiltration；
   - scope inflation。
5. SkillGuardGraph 设计
   - evidence item；
   - graph schema；
   - analyzer modules；
   - policy enforcer。
6. 安全约束
   - C1 声明—实现—权限一致性；
   - C2 来源感知高权限调用；
   - C3 跨工具 exfiltration sequence；
   - C4 版本漂移；
   - C5 审批完整性；
   - C6 持久化边界。
7. Benchmark 与实验
   - 数据集；
   - baselines；
   - metrics；
   - ablation；
   - 真实生态测量。
8. 结果
   - 组合攻击检测；
   - naive union 对比；
   - FPR/latency/approval burden；
   - case studies。
9. 讨论
   - 部署模式；
   - 平台限制；
   - 伦理披露。
10. 相关工作
11. 结论

## 贡献写法

- 不要强调“用了更多 detector”；
- 强调“跨层证据图 + 可验证约束 + 组合攻击 benchmark + 真实生态测量”。

