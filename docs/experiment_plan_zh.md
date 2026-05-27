# 实验计划

## 1. 实验目标

证明 SkillGuardGraph 的贡献不是“简单组合检测器”，而是跨层证据融合带来的实质收益。

核心实验问题：

- **EQ1**：组合式攻击是否能绕过单层检测？
- **EQ2**：evidence graph fusion 是否优于 naive union？
- **EQ3**：系统是否能保持低误报、低延迟和高正常任务成功率？
- **EQ4**：真实生态中是否存在大量可观测的跨层不一致？

## 2. 实验一：Benchmark effectiveness

### Setup

- 数据：benign + malicious paired cases。
- 方法：metadata-only、code-only、sandbox-only、runtime-only、naive union、graph fusion。
- 输出：Precision、Recall、F1、FPR、constraint attribution。

### 预期结果

- 单层方法在单一攻击类上表现尚可，但对 cross-skill、HITL laundering、update drift 漏检明显。
- naive union recall 高，但 FPR 高。
- graph fusion 在 recall 接近 naive union 的同时降低 FPR。

## 3. 实验二：Runtime containment

### Setup

- 多步任务：办公检索、代码修复、知识库问答、文件整理、邮件草拟。
- 攻击载体：网页、邮件、文档、tool output、project config、memory/config update。
- 防御阶梯：

```text
No defense
+ least privilege
+ source isolation
+ runtime policy
+ approval integrity
+ graph fusion
```

### 指标

- ASR、UTCR、EDR、BRI、PS、SC；
- Task Success Rate；
- Approval Burden；
- latency overhead。

## 4. 实验三：Ablation

| Ablation | 目的 |
|---|---|
| remove metadata evidence | 看声明层作用 |
| remove implementation evidence | 看源码/能力恢复作用 |
| remove provenance labels | 看来源感知作用 |
| remove sequence policy | 看跨工具链检测作用 |
| remove drift policy | 看版本更新检测作用 |
| remove approval integrity | 看 HITL 污染风险 |

## 5. 实验四：真实生态测量

### Corpus

- 公开 MCP server/tool repositories；
- LangChain tools / agent templates；
- AutoGPT block samples；
- 官方 app/action/connector samples；
- 企业内部可选匿名样本。

### 测量项

- description vs scope mismatch；
- read-only annotation vs destructive capability；
- sensitive source to external sink path；
- unbounded tool output to model context；
- version drift after approval；
- missing publisher/signature/approval metadata。

### 输出

- 按生态分类的风险分布；
- 高置信 case studies；
- responsible disclosure 统计；
- false positive audit。

## 6. 成功门槛

| 指标 | 目标 |
|---|---:|
| 组合攻击 recall | ≥ 85% |
| benign FPR | ≤ 5–8% |
| graph fusion FPR 相对 naive union 下降 | ≥ 20% |
| task success drop | ≤ 10–15% |
| runtime policy latency | ≤ 100–300ms/tool-call，不含 LLM judge |
| evidence attribution rate | ≥ 90% high-risk verdict 有完整 evidence path |

