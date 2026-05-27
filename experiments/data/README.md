# Data Directory

放置 benchmark 样本与真实 corpus 的位置。

当前包只包含 `examples/` 中的合成 manifest 和合成 runtime trace。后续真实数据接入建议：

- `data/benign_real/`: 公开 MCP servers、tools、agent templates。
- `data/benign_synthetic/`: 合成良性 paired cases。
- `data/malicious_synthetic/`: 安全裁剪后的恶意 skill cases。
- `data/metadata/`: 样本版本、来源、hash、license、disclosure 状态。

不要放入真实凭证、真实企业数据、真实用户日志或未披露漏洞细节。
