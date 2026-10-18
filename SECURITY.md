# Security Policy

## 支持范围

| 版本 | 支持 |
|---|---|
| 0.1.x | ✅ |

## 报告漏洞

请不要在公开 Issue 中披露可利用细节。优先使用 GitHub 的 **Private vulnerability reporting**
（仓库 → Security → Report a vulnerability）；若不可用，请先开一个不含细节的 Issue 说明
「需要私下报告安全问题」，维护者会给出私密渠道。

报告时请尽量包含：

- 插件版本 / DSH 版本 / Node 版本；
- 触发自动放行的完整 `tool/call` 参数（命令、`sandbox_permissions`、preset）；
- 期望行为与实际行为，以及为什么这构成越权；
- 可复现的最小样例（可脱敏）。

## 安全边界（请先读）

本插件是**审批层**的窄口自动化，不是系统级沙箱：

1. 只在 engineering preset 会话、且命令严格匹配白名单时自动放行 `danger-full-access`。
2. 被放行的命令确实以完整权限运行；插件不提供额外的内核级隔离。
3. 工作区生成脚本的静态扫描是启发式 denylist，不能保证没有绕过；受信任脚本目录是信任根。
4. 读取类操作在 DSH 沙箱下本就不受限；凭据路径由拒绝清单拦截。
5. 完整威胁模型与残余风险见 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)。

如果你需要「模型生成的任意脚本都绝对不能碰到工作区外文件」这种保证，请使用操作系统级
隔离（独立用户/虚拟机/容器）而不是本插件。

## 安全设计原则

- **fail-closed**：判定异常 / 字段缺失 / 解析失败 / 对不上工具调用 → 一律交还人工审批。
- **最小放行**：只碰 `pwsh`/`write`/`edit` 的 `danger-full-access`，其它工具永不自动放行。
- **审计**：每次自动放行写本地 JSONL；`/swapproval off` 可随时本会话紧急关闭。
- **预算**：每会话/每回合上限，超限恢复弹窗。
