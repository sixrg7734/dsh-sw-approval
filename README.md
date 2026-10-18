# dsh-sw-approval

**给 DeepSeek Harness（DSH）用的「SolidWorks 建模安全自动审批」插件。**

SW 建模时 SolidWorks 的 COM 在受限沙箱下无法工作（`CO_E_SERVER_EXEC_FAILURE`，甚至启动即崩），
所以 DSH 每一步都要把终端提权到 `danger-full-access`；一次建模会话可能出现几十次人工审批，
你没盯着的时候流程就卡住了。

本插件在 `approval/request` 这一层做**窄口自动放行**：只有能证明是 SolidWorks 建模、且严格匹配
白名单的命令才替你说一次「允许本次」；其它任何操作仍然照常弹窗。
它**不是** `danger-full-access + approval: never` 的全局放权。

> Safe, narrow auto-approval for SolidWorks workflows in DSH. It never disables the sandbox
> or the approval system globally: only strictly allowlisted SolidWorks escalations are
> auto-approved, everything else fails closed to the human prompt.
如果这个插件帮到了你，欢迎点个⭐Star
---

## ✨ 功能

- **只对工程模式（关于工程模式请看 https://github.com/fyjgtddco/DSH-SW-and-CAD ）会话生效**，其它会话完全不受影响。
- 自动放行对象仅限 `pwsh` / `write` / `edit` 的 **`danger-full-access` 提权**。
- 判定依据是会话日志里**真实的 `tool/call` 参数**，不是模型写的 justification。
- SW 证据必须是**可操作证据**：受信任脚本、启动 `SLDWORKS.exe`、`SldWorks.Application` COM、
  `Get-Process SLDWORKS`、`DSH_SW_EXE` + python 脚本等；纯输出文本里的 "SldWorks" 不算。
- 危险命令拒绝清单：删除/覆盖、注册表、服务/计划任务、联网/下载/安装、`cmd /c`、
  `Invoke-Expression`、`Add-Type`、`taskkill`、凭据路径、宏执行、非 SW COM ProgID 等。
- 模型生成的 `build_*.py` 会先做静态扫描（必须有 SW/COM 特征；禁止 `subprocess/ctypes/shutil/
  winreg/urllib/requests/反射/os 破坏 API/FSO 等`）。
- **受信任脚本 SHA-256 钉住**：授权脚本被改写/缺失 → 该脚本转人工审批。
- 每会话 500 次、每回合 80 次自动放行上限；超限恢复弹窗。
- 本地审计日志 + `/swapproval` 命令（status / on / off / log / rehash）。
- 判定异常、字段缺失、解析失败 → **一律 fail-closed 交还人工审批**。

## 🔒 安全模型（摘要）

| 闸门 | 规则 |
|---|---|
| 会话 | preset ∈ `presets`（默认仅 `engineering`） |
| 工具 | 只处理 `pwsh` / `write` / `edit` |
| 提权目标 | 只处理 `danger-full-access` |
| 命令 | 必须有可操作 SW 证据 + 全部 cmdlet 在白名单 + 命中拒绝清单即弹窗 |
| 脚本 | 工程 tools 下授权脚本按哈希钉住信任；工作区脚本必须静态扫描通过 |
| 写文件 | 只放行工作区与 `extraWriteRoots` 内的 `write/edit`；不含受信任脚本目录 |
| 预算 | 每会话/每回合限额，超限全部人工审批 |
| 兜底 | 任何异常 → `next()`（人工审批） |

完整威胁模型、攻击矩阵与残余风险见 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)；
判定规则源码级契约见 [DESIGN.md](DESIGN.md)。

## 📦 环境要求

- Windows（路径语义为 win32；其它平台未验证）
- DeepSeek Harness **0.2.x**（`engines.dsh: >=0.2.0-rc.1 <0.3.0`）
- Node.js **>= 22**（插件本身零第三方依赖）
- 一个可用的 `engineering` agent preset（含 `tools/sw_bridge.py` 等；默认路径
  `%USERPROFILE%\.dsh\.agent-presets\engineering`，可配置）

## 🚀 安装

```bash
git clone https://github.com/<your-name>/dsh-sw-approval.git
```

在 DSH 里用 `plugin_manager` 以本地目录安装（把路径换成你 clone 下来的绝对路径）：

```text
plugin_manager { action: "install_bundle", target: "<绝对路径>/dsh-sw-approval" }
```

安装后 profile 的 `cordis.patch.yml` 会插入一行 `dsh-sw-approval`。
宿主插件是进程级配置，**需要重启 / 重载 DSH** 才生效。

> 插件以 `link:` 方式引用仓库目录：之后修改源码也不会被热加载，重启 DSH 才会加载新代码。

## ⚙️ 配置

在 profile 的 `cordis.patch.yml`（或插件设置）里覆盖任意子集；未写字段用默认值：

```yaml
- id: dsh-sw-approval
  name: dsh-sw-approval
  config:
    enabled: true
    presets: [engineering]                     # 想覆盖其它预设需显式加入（不推荐）
    engineeringRoot: 'C:\Users\<you>\.dsh\.agent-presets\engineering'
    solidworksExe: 'D:\SolidWorks 2026\SOLIDWORKS\SLDWORKS.exe'
    authorizedScripts: [sw_bridge.py, swapi.py, physics_bridge.py, visual_check.py,
                        workflow_gate.py, mode_gate.py, mode2_flow.py, defense_gate.py, ask_user.py]
    workspaceScriptNames: []                   # 空数组 = 任意 cwd 下 .py 经静态扫描通过即可
    extraWriteRoots: []                        # 允许 write/edit 提权写入的额外目录（谨慎）
    scanWorkspaceScripts: true
    maxAutoApprovalsPerSession: 500
    maxAutoApprovalsPerTurn: 80
    auditDir: 'C:\Users\<you>\.dsh\sw-approval'
```

## 🧭 使用

- 平时不用管：engineering 会话里白名单 SW 提权直接通过，其它操作照常弹窗。
- `/swapproval status`：查看是否生效、本会话放行次数、最后命中规则、审计路径。
- `/swapproval off` / `on`：本会话紧急暂停 / 恢复自动审批。
- `/swapproval log [n]`：查看本会话最近 n 次自动放行。
- `/swapproval rehash`：正常更新工程预设/授权脚本后重新学习受信任脚本哈希。
- 审计：`%USERPROFILE%\.dsh\sw-approval\audit.jsonl`
- 状态：`%USERPROFILE%\.dsh\sw-approval\status.json`（确认插件已加载）

## 🧪 测试

```bash
node --test --experimental-test-isolation=none test/policy.test.mjs test/plugin.test.mjs test/adversarial.test.mjs
```

或 `npm test`。测试只用 `node:` 内建，无需安装依赖。

- `test/policy.test.mjs`：判定规则单测 + 116 条真实历史审批**脱敏**语料
- `test/plugin.test.mjs`：胶水层集成测试（prepend、preset、callId、预算、/off、审计、哈希/rehash、fail-closed）
- `test/adversarial.test.mjs`：独立红队对抗套件（注入、路径穿越、编码绕过、脚本 API 绕过等）

## ⚠️ 已知局限 / 残余风险

1. **B6 静态扫描本质是启发式**：它能挡住已知危险 API，但不能数学证明没有新绕过。
   真正边界仍是进程级最小权限；本插件只降低「审批疲劳」，不能替代系统级隔离。
2. **受信任脚本目录是信任根**：`engineeringRoot\tools` 下被列入 `authorizedScripts` 的脚本
   按可信代码处理；哈希钉住只能发现改写，不能阻止一次性恶意脚本通过扫描。
3. **读取类命令**在具备 SW 可操作证据时仍可读工作区外文件（DSH 沙箱本身不限读；
   凭据路径已被拒绝清单拦截）。
4. **只对本机 DSH 0.2.x 验证**：升级 DSH 后请重跑测试并确认 `approval/request` 签名未变。
5. 一些合法但罕见脚本可能因保守 token 被误判为 ask；人工批准一次即可。

## 🗂 目录结构

```
dsh-sw-approval/
├── index.js              # Host 插件胶水：审批拦截、预算、preset、哈希钉住、审计、/swapproval
├── lib/policy.js         # 纯函数判定引擎（零 import、零 IO）
├── cordis.patch.yml      # DSH bundle 补丁（插入插件行与默认配置）
├── locale/{zh,en}.json   # 插件市场/设置页显示文案
├── icon.svg
├── DESIGN.md             # 判定规则契约
├── SECURITY-REVIEW.md    # 独立安全审查报告
├── SECURITY.md           # 漏洞报告与安全范围
└── test/                 # 单元 / 集成 / 对抗测试与脱敏 fixture
```

## 📄 许可证

[MIT](LICENSE)

> 本项目与 Dassault Systèmes（SolidWorks）、DSH-SW-and-CAD、fyjgtddco及 DeepSeek 官方无隶属关系；
> SolidWorks 是其各自权利人的商标。
