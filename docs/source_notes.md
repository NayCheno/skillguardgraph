# Source Notes

This package was drafted from three evidence groups.

## 1. Uploaded report

- `恶意 Skill 在大模型 Agent 生态中的风险、检测与治理.pdf`
- Key imported ideas:
  - skill as a cross-platform term covering actions, apps, connectors, MCP, tools, graphs, blocks, agents, and extensions;
  - single-point prompt defense is insufficient;
  - recommended layered lifecycle controls: pre-publication review, signature/reputation, least privilege, source isolation, runtime policy, audit;
  - metrics: ASR, UTCR, EDR, BRI, PS, SC;
  - experiment direction: malicious skill benchmark, runtime red-team, control-plane ablation, ethical controls.

## 2. Official or standards-like sources

- Model Context Protocol specification: https://modelcontextprotocol.io/specification/2025-03-26
- MCP Tools documentation: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- OWASP MCP Tool Poisoning: https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
- NIST AI RMF GenAI Profile: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- OpenAI app/admin controls: https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-in-connectors-enterprise-edu-and-team
- CCF Network and Information Security recommended venues: https://www.ccf.org.cn/Academic_Evaluation/NIS/

## 3. Research sources used for positioning

- MCPTox: https://ojs.aaai.org/index.php/AAAI/article/view/40895
- ToolHijacker: https://arxiv.org/abs/2504.19793
- MCP-ITP: https://arxiv.org/abs/2601.07395
- TRUSTDESC: https://arxiv.org/abs/2604.07536
- VIPER-MCP: https://arxiv.org/abs/2605.21392
- MCP-BiFlow: https://arxiv.org/abs/2605.07836
- MCPShield: https://arxiv.org/abs/2602.14281

