# Changelog

## 0.1.3 — 2026-10-18

首个公开发布版本。

### 安全能力

- 只在 `engineering` preset 会话自动放行，且仅限 `pwsh` / `write` / `edit` 的
  `danger-full-access` 提权；其余全部交还人工审批（fail-closed）。
- 判定依据为会话日志中的真实 `tool/call` 参数，不信任模型填写的 justification。
- SW 证据必须是可操作证据（受信任脚本 / `SLDWORKS.exe` / `SldWorks.Application` COM /
  `Get-Process SLDWORKS` / `DSH_SW_EXE` + python），纯文本输出不算。
- 命令拒绝清单（删除/覆盖、注册表、服务、网络、安装、`cmd /c`、`Invoke-Expression`、
  `Add-Type`、`taskkill`、凭据路径、宏执行、非 SW COM ProgID 等）与 cmdlet 白名单。
- 工作区模型生成脚本静态扫描（SW/COM 特征、import 白名单、危险 API、COM ProgID、
  受信任路径字面量、反射等）。
- 受信任脚本 SHA-256 钉住；篡改/缺失 → 转人工审批；`/swapproval rehash` 重新学习。
- 每会话 / 每回合自动放行预算；超限恢复弹窗。
- 本地审计日志（`audit.jsonl`）与插件状态（`status.json`）。
- `/swapproval status|on|off|log [n]|rehash` 命令。

### 验证

- 574 个测试用例，0 fail（单元 / 胶水集成 / 独立红队对抗）。
- 116 条真实历史审批脱敏语料：危险命令 45/45 全部 ask、0 放行。
- 独立安全审查结论：通过（无 P0/P1 阻塞项）；残余风险见 SECURITY-REVIEW.md。
