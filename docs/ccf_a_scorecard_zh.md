# CCF-A 严格评分与可行性评估

## 1. 目标 venue

首选：USENIX Security、CCS、IEEE S&P、NDSS。备选：RAID、ACSAC、AsiaCCS、WWW/ICSE SE-security track。

该工作更适合写成系统安全论文，而不是纯 ML benchmark 论文。核心评审标准包括：

- 是否有新威胁模型；
- 是否有明确技术创新，而非工程拼装；
- 是否有真实生态测量；
- 是否有强 baseline 和 ablation；
- 是否有部署成本和误报分析；
- 是否能复现。

## 2. 严格评分

| 维度 | 分数 | 评价 |
|---|---:|---|
| 问题重要性 | 9.0/10 | Agent + skill/MCP 生态快速扩张，风险真实且高影响。 |
| 新颖性 | 7.0/10 | 分层防御不新；跨层 evidence graph + 组合攻击链可增强新颖性。 |
| 技术深度 | 7.5/10 | 需要形式化约束、信息流建模、因果链，不应停留在 pipeline。 |
| 实验可行性 | 8.0/10 | 公开 MCP 生态和已有 benchmark 可用；闭源平台只能做黑盒或案例分析。 |
| CCF-A 命中率 | 7.0/10 | 有潜力，但容易被质疑为工程集成。 |
| Artifact 价值 | 8.0/10 | 若能发布 benchmark、scanner、policy schema、trace validator，会加分。 |
| 风险 | 6.5/10 | 与 MCPShield、TRUSTDESC、VIPER-MCP、MCP-BiFlow 存在重叠，需要明确边界。 |

**综合严格分：7.4/10。**

## 3. 三种版本的投稿概率

| 版本 | 严格分 | 判断 |
|---|---:|---|
| Naive pipeline：静态 + LLM + 沙箱 + 审计 | 5.8/10 | 工程感强，CCF-A 风险高。 |
| Evidence graph + 新组合攻击 benchmark | 7.4/10 | Borderline 到 weak accept 潜力。 |
| 10k+ 生态测量 + 真实漏洞 + fusion 显著优于 naive union | 8.2/10 | 有 CCF-A 竞争力。 |

## 4. 主要拒稿风险

### R1：被认为是工程拼装

**风险**：审稿人认为所有层已有，你只是接起来。

**缓解**：

- 用 typed graph 和约束定义证明不是简单 union；
- 做 `naive union` baseline；
- 展示 graph fusion 在 FPR、组合攻击 recall、解释性上的优势。

### R2：与 MCPShield 重叠

**风险**：MCPShield 已有 probing + runtime cognition。

**缓解**：

- 强调 evidence graph 是跨 metadata、implementation、permission、approval、version drift 的统一结构；
- MCPShield 作为 runtime trust calibration baseline；
- 加入 cross-skill sequence 和 approval integrity，这不是单 server probing。

### R3：攻击 benchmark 不够真实

**风险**：构造样本被认为 toy。

**缓解**：

- 从真实 MCP servers/tools 采样；
- 对良性任务保持 task success；
- 使用 trace validator，而不是 agent self-report；
- 对高风险发现做人工审计。

### R4：误报过高

**风险**：安全系统不可部署。

**缓解**：

- 只对跨层证据链高置信触发 block；
- 低置信输出 degrade/HITL，而不是 deny；
- 报告 approval burden、latency、developer workflow cost。

### R5：伦理问题

**风险**：恶意 skill 研究可能被认为有滥用风险。

**缓解**：

- 不发布可直接攻击真实系统的 payload；
- 所有动态实验使用 fake credentials、offline sandbox、sinkhole；
- 真实漏洞走 responsible disclosure。

## 5. 时间规划

| 阶段 | 周期 | 产出 |
|---|---:|---|
| S0：文献与平台定位 | 2 周 | taxonomy、related work matrix、baseline 列表 |
| S1：数据采集 | 3–4 周 | benign skill/MCP corpus、metadata schema、version metadata |
| S2：攻击 benchmark | 4 周 | 5–7 类组合攻击、validator、ethics filter |
| S3：系统实现 | 6–8 周 | metadata analyzer、code analyzer adapter、sandbox prober、runtime monitor、graph engine |
| S4：实验 | 4–6 周 | ablation、生态测量、FPR、latency、task success |
| S5：论文写作 | 4 周 | full draft、artifact appendix、review response plan |

## 6. 最值得优先做的三件事

1. **先做 graph fusion vs naive union 的小规模 proof**：如果没有优势，就不值得扩大。
2. **先做组合攻击 taxonomy 和 trace validator**：这是 novelty 的核心。
3. **先做真实生态测量**：如果能发现真实不一致和风险链，论文说服力会显著提高。

## 7. Go / No-Go 条件

### Go

满足任意两项即可继续冲 CCF-A：

- graph fusion 相比 naive union 在组合攻击 recall 上提升 ≥ 15%，FPR 下降 ≥ 20%；
- 在真实生态中发现 ≥ 50 个高置信跨层不一致或 unsafe sequence；
- 新 benchmark 被现有方法明显漏检；
- 系统 overhead 可控，runtime 决策 < 300ms/tool-call，不含 LLM judge。

### No-Go

出现以下情况应降级到 B 类或 workshop：

- graph fusion 与 naive union 差异不显著；
- benchmark 主要依赖人工构造 prompt；
- FPR > 10–15% 且无法通过 policy tuning 降低；
- 没有真实生态测量。

