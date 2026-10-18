# dsh-sw-approval 安全审查（独立红队验证）

- 审查对象：仓库根目录（插件 v0.1.3，`POLICY_VERSION = '1.3.1'`，契约 DESIGN.md 当前修订已同步 v1.1/v1.2/v1.3/v1.3.1）
- 审查人：独立审查（独立于 判定引擎实现 / 维护者，按契约先写对抗套件，再做实现审查；不修改 `lib/policy.js` / `index.js`）
- 审查时间：2026-10-18（v1.2 首轮 → v1.3 复核 P0 → **v1.3.1 复核 P1 修复，最终结论**）
- 审查基线（仓库源码）：`lib/policy.js` 2365 行（v1.3.1）、`index.js` 492 行（v1.3.1：哈希钉住 + `hashPinningEnabled:true` + `hashFile` 注入）、`package.json` / `cordis.patch.yml`；安装形态与 live 版本见 §1.3

---

## 0. 结论

**通过（无剩余 P0/P1 阻塞项；P2/可用性残余风险已记录，维护者 判定不阻塞）。**

- **P0「B6-A 等价危险 API 绕过 + 脚本版提权链」**：policy v1.3 修复，v1.3.1 复核保持修复状态；`B6-BLOCK` 5 条原复现 + `B6-V13` 23 条同类变体全部 ask。
- **P1 三项（v1.3.1 修复，本轮独立验证）**：
  1. SW COM `RunMacro`/`RunMacro2` 宏执行 → ask（`runmacro` deny token）。
  2. `from win32com/pythoncom import … as …` 函数别名绕过 COM ProgID 白名单 → ask（import-alias 扩展）。
  3. 真实 SW 脚本 `import swapi` → allow（B6 import 白名单加入 `swapi`；真实历史脚本 `retry_shot.py`/`verify_build.py` 复跑已 allow）。
- **哈希钉住 fail-open 收紧**：胶水注入 `hashPinningEnabled:true` 后，授权脚本缺哈希条目 / 缺 `hashFile` → ask（`pwsh.script.hash-unavailable`）；未启用时保持旧回退（兼容单测/未升级胶水）。真实工程 tools 9 个脚本生产形态验证：匹配 allow、缺条目 ask、缺 hashFile ask、未启用回退 allow。
- 三套测试 **574 例 / 566 pass / 0 fail / 8 todo**（todo 全部为 P2/可用性，维护者 判定不阻塞）；真实语料危险命令 **45/45 ask、0 放行**（部署默认与 fixture 两口径一致）；fixture allow 62 与 v1.3.1 报告一致。
- **live 提示**：宿主当前 live 进程仍是旧模块（维护者 确认）；本文结论针对**仓库源码 v1.3.1**，需要 DSH 重启/重载后由 维护者 做 live E2E（§1.3/§8）。

---

## 1. 审查对象与版本

### 1.1 文件清单（仓库源码）

| 文件 | 行数 | 说明 |
|---|---|---|
| `lib/policy.js` | 2365 | 纯函数判定引擎；零 import、零 IO；导出 `evaluateApproval` / `normalizeConfig` / `POLICY_VERSION`；v1.3.1 增加 `runmacro` token、win32com/pythoncom import 别名检查、`swapi` import 根、`hashPinningEnabled` fail-closed |
| `index.js` | 492 | Host 胶水：prepend、preset/callId、预算、审计、`/swapproval`；v1.3.1 注入 `trustedScriptHashes` + `hashFile` + `hashPinningEnabled:true`，`/swapproval rehash` |
| `cordis.patch.yml` | 15 | insert 插件行，默认 `enabled: true`、`presets: [engineering]` |
| `package.json` | 32 | ESM、`dsh.bundle.patch`、`engines.dsh = >=0.2.0-rc.1 <0.3.0` |
| `test/policy.test.mjs` | — | 52 例（判定引擎实现，含 v1.3.1 回归） |
| `test/plugin.test.mjs` | — | 15 例（维护者；v1.3.1 起含 `/swapproval rehash` 测试） |
| `test/adversarial.test.mjs` | — | 507 例（本审查独立对抗套件，含 BLOCK/V13/V13-POS/HASH/R/R2 组） |
| `SECURITY-REVIEW.md` | — | 本文件 |

### 1.2 版本一致性与文档

- DESIGN.md 已同步 v1.1/v1.2/v1.3/v1.3.1：B3 可操作锚点、Export 具体化、workspace 脚本任意名扫描、`hashFile`/`trustedScriptHashes`/`hashPinningEnabled`/`rehash`、B6 import 白名单含 `swapi`、B6 deny token 扩展（复核时已核对）。
- 剩余小偏差（不影响安全）：`POLICY_VERSION` 仍为 `'1'`，未随 v1.1–v1.3.1 递增（审计无法区分修订版本，建议下一版改为 `'1.3.1'`）；DESIGN 模块图仍列 `lib/config.js`（实际未创建，归一化在 `policy.js`）。

### 1.3 「仓库源码版本」与「安装后 live 版本」的区分（由 维护者 的 live 验证负责）

- 安装位置：`%USERPROFILE%\.dsh\profiles\desktop`，依赖形式 `link:<repo>`。
- `link:` 只表示**文件系统路径**指向工作区目录；**不能据此断言 live 模块实例 = 仓库源码版本**。宿主进程在安装/启动时已把旧版 `index.js` / `lib/policy.js` 加载进内存，后续源码修改是否热重载取决于 HMR/重启策略。
- **维护者 已确认：宿主 live 进程仍运行旧模块；需要 DSH 重启/重载才会加载 v1.3.1**（含 `hashPinningEnabled:true` 与最新 B6 规则）。本文所有「通过/已修复」结论均针对 **§1.1 仓库源码 v1.3.1**；live 实例由 维护者 在重启后验证（核对 `~/.dsh/sw-approval/status.json` 的 `trustedScripts` 字段与新 `plugin-start` 时间戳，及真实审批 E2E）。
- 重载后请核对 `status.json` 的 `trustedScripts`（正常为 9）与 `plugin-start` 时间戳；这比版本号更能证明新规则已加载。

---

## 2. 威胁模型

### 2.1 资产

1. 宿主进程的 danger-full-access 权限（沙箱外文件/进程/网络）。
2. 用户文件系统（工作区建模产物 + 工作区外用户数据/凭据）。
3. DSH profile / 插件配置 / 受信任工程脚本（`engineering/tools/authorizedScripts`）的完整性。
4. SolidWorks 进程与用户文档（COM 自动化）。
5. 审计日志的真实性（事后追溯）。

### 2.2 对手与攻击面

| 对手 | 能力 | 主要攻击面 |
|---|---|---|
| 被 prompt injection 影响的模型 | 可写任意 `pwsh` 命令、`write/edit` 路径参数、workspace 脚本内容 | 命令拼接/混淆、白名单绕过、路径穿越、脚本内容绕过 |
| 不可信命令文本 | 来自会话日志 `tool/call.data.arguments` | 编码/反引号/here-string/子表达式 |
| 误操作（工程会话正常使用） | 危险命令混入 SW 工作流 | 误删/误配置/下载安装 |
| 第三方/并发进程 | 可在宿主之外改写工程 tools 脚本文档 | 受信任脚本持久化篡改（由哈希钉住兜底） |
| 非 engineering 会话 | 不应受插件影响 | preset 闸门 |

### 2.3 信任边界与假设

- **可信**：DSH 宿主事件（`tool/call` 日志、`callId`、`agent-preset/selected`、`session.header.cwd`）；用户配置；工程 preset `tools` 下 `authorizedScripts` 的**启动时哈希**；`solidworksExe` 配置。
- **不可信**：模型生成的 `args.command`、`args.file_path`、workspace 下任意 `.py`（必须经 B6 扫描）。
- **DSH 沙箱假设**（维护者 确认）：读操作不受限制、只禁写/提权 → 自动放行纯读命令不增加读取权限（§6.3 已接受）。
- 插件不改变审批服务语义：handler 返回 `'allowed-once'` 仅放行本次调用，其余一律 `next()`。
- 哈希钉住：`hashPinningEnabled:true` 时授权脚本缺哈希条目/缺 `hashFile` 均 fail-closed；`false` 时保留兼容回退（仅单测/未升级胶水）。

---

## 3. 验证方法与结果（基于仓库源码 v1.3.1）

### 3.1 三套测试结果（`node --test --experimental-test-isolation=none`）

| 套件 | 用例 | pass | fail | todo | 结论 |
|---|---|---|---|---|---|
| `test/policy.test.mjs` | 52 | 52 | 0 | 0 | 全绿（含 v1.3.1 P1/哈希回归） |
| `test/plugin.test.mjs` | 15 | 15 | 0 | 0 | 全绿（新增 `/swapproval rehash` 测试） |
| `test/adversarial.test.mjs` | 507 | 499 | **0** | 8 | 原 P0/P1 复现全部转 ask；8 todo 为 P2/可用性 |
| 合计 | **574** | **566** | **0** | **8** | — |

- 基线演进：v1.2 首轮 5 fail（P0）→ v1.3 复核 0 fail（12 todo）→ v1.3.1 复核 0 fail（8 todo；4 条 P1 转正常断言、2 条哈希 fail-open todo 转 ask 断言、新增 `import swapi` 正例与 pinning 分支）。全程未放宽既有安全断言。
- 对抗套件分组（507）：0 契约/形状 6、A 前置 23、B1 拒绝清单 123、B2 cmdlet 25、B3 锚点 11、B4 Start-Process/New-Object 29、B5 解释器与 .py 42、**B6 脚本扫描 121**（BLOCK 5 / V13 23 / V13-POS 9 / HASH 11 / H 8 / R 2 / R2 3）、C write-edit 37、D 其它工具 6、E 真实语料 18、H1/H2 HARDENING 66。

### 3.2 todo 明细（8 条，P2/可用性，维护者 判定不阻塞）

**旧残余（5）**：`H2-R` 任意文件读取（已接受）、`H2-R` B3 输出 exe 路径锚点 ×2、`B6-R` os.kill、`B6-R` Path.mkdir。

**v1.3.1 后剩余（3）**：
1. `B6-R2` `Path.touch` 创建任意文件（P2）
2. `B6-R2` 可用性：合法 `str.replace(` 被泛化 token 误杀（P2）
3. `B6-R2` 可用性：合法 `list.remove(` 被泛化 token 误杀（P2）

> v1.3 复核时的 4 条 P1/P2 已修复并转为正常断言：RunMacro2、COM 别名导入、哈希缺条目、哈希无 hashFile（`hashPinningEnabled:true` 下）→ ask；`import swapi` → allow。

### 3.3 真实历史语料独立复跑（`维护者本地会话日志`，116 条）

用 `lib/policy.js` v1.3.1 + 真实 `node:fs` deps（readFile/stat/exists/realpath/hashFile）独立复跑：

| 口径 | 总数 | allow | ask | 危险模式命令 | 危险命令中 allow |
|---|---|---|---|---|---|
| **部署默认**（`presets=['engineering']`，真实文件系统） | 113 pwsh（+3 write/edit 无语料路径，跳过） | 21 | 92 | 45 | **0** |
| **fixture 口径**（`presets=['engineering','standard']` + 内存 fake cwd 脚本） | 116 | 62 | 54 | 45 | **0** |

- v1.3→v1.3.1 数字完全不变（fixture allow 62 与 维护者 报告一致）；危险命令 **45/45 ask、0 放行**；allow 规则分布仅 `pwsh.sw-bridge.trusted` / `pwsh.solidworks-process`（部署默认）与 fixture 的 `workspace-script.scanned`。
- 部署默认 allow 21 低于 fixture 62 的原因同前：真实机器历史生成 `build_*.py` 已清理（23 条 `stat` fail-closed）+ 部署默认不纳入 standard 会话（52 条）。62 不是生产放行率。

### 3.4 手工/真实环境探测（v1.3.1 复核）

| 攻击面 | 实测决策 | 备注 |
|---|---|---|
| B6-BLOCK 5 条原 P0 复现（FSO CopyFile trusted / DeleteFile / Path.unlink / Path.rename / numpy.save） | **ask** | 保持 v1.3 修复状态 |
| 同类变体（FSO CreateTextFile/Move/CopyFolder、Path.replace、np.savez/tofile、COM ProgID 变量/拼接/f-string、非 SW GetObject/CoCreateInstance/EnsureDispatch/DispatchEx、受信任路径字面量、`import os as`） | ask | B6-V13 23/23 |
| **v1.3.1 P1：SW COM `RunMacro`/`RunMacro2`** | **ask** | `deny-token`（runmacro） |
| **v1.3.1 P1：`from win32com.client import Dispatch as D`（单名/括号多名/pythoncom）** | **ask** | `pwsh.script.import-alias` |
| **v1.3.1 P1（可用性）：真实脚本 `import swapi`** | **allow** | `_tmp/plugin-verify/retry_shot.py`、`verify_build.py` 实测 `pwsh.workspace-script.scanned` |
| 哈希钉住（生产形态，`hashPinningEnabled:true`）：真实 9 个 tools 脚本匹配 / 缺条目 / 缺 hashFile / 未启用 | allow / **ask** / **ask** / allow | 真实文件系统 sha256；不误杀正常脚本 |
| 合法脚本：SW SaveAs3/Extension.SaveAs、Path 只读、Dispatch SldWorks（含 .34/小写/GetObject）、from-import 非别名、`import swapi`、json.dumps | **allow** | B6-V13-POS 9/9 |
| 纯文本锚点 / 输出文本 / 注释 | ask | v1.1 锚点收紧保持 |
| 输出字符串 `SLDWORKS.exe` 路径当锚点 | allow | 旧非阻塞残余（§6.4） |
| 可操作锚点 + `Get-Content <任意文件>` | allow | 已接受（§6.4） |
| `mechanical-practice-models/gear_calc.py`（无 SW 锚点） | ask | 纯数学脚本；符合插件定位 |
| 真实语料危险命令 | — | 45/45 ask、0 放行 |

---

## 4. 实现审查

### 4.1 `lib/policy.js`（v1.3.1 复核）

**fail-closed 结构（通过）**
- `evaluateApproval` 外层 try/catch → `askResult('internal-error')`；`safeDep` 包裹所有 deps（含 `hashFile`），异常/缺失 → ask。
- 未知工具/非法 input/`enabled !== true`/preset 不匹配/非 danger-full-access/缺字段/NUL/超长 → ask；allow 仅全规则通过后返回。

**B1/B2/B3/B4/B5（通过，稳定）**
- B1 拒绝清单 + 额外收紧（可执行 token 白名单、类型表达式白名单、语句起始裸命令闸门、反引号/here-string/未闭合/`$()` 递归、SAM/盘符枚举/RunMacro 额外拒绝）保持；v1.1 Export 具体化未回退。
- B2 含 v1.2 ConvertFrom/To-Json；B3 可操作锚点收紧保持；B4 Start-Process/New-Object 目标校验保持；B5 解释器/`.py` 引用/内联代码规则保持，`build_*.py` 主路径仍 allow。

**B6 静态扫描（v1.3.1：P0+P1 修复，通过）**
- v1.3 修复保持：等价危险 API deny token（FSO/pathlib/numpy/win32file 等）、COM ProgID 白名单（`SldWorks.Application(.\d+)?` 字面量）、受信任路径字面量拒绝、`import os as` 别名拒绝、受信任脚本哈希钉住。
- **v1.3.1 新增**：`runmacro` deny token（覆盖 RunMacro/RunMacro2，与 B1 对齐）；`from (win32com|pythoncom)… import … as …` 别名导入 → ask（覆盖单名/括号多名）；`swapi` 加入 `SCRIPT_IMPORT_ROOTS`（只加这一项）；新增 `config.hashPinningEnabled`（默认 false）：为 true 时授权脚本缺 `trustedScriptHashes` 条目或缺 `deps.hashFile` → `pwsh.script.hash-unavailable`（ask），为 false 时保持旧回退（单测/未升级胶水兼容）。
- **剩余 P2**：`Path.touch` 未覆盖；`replace(`/`remove(` 泛化为 token 会误杀合法字符串/容器方法（可用性）；见 §6.3。

**C write/edit、normalizeConfig（通过）**
- 允许根 = `[cwd, ...extraWriteRoots]`（不含 engineeringRoot）保持；canonWinPath / isWithinWin / realpath 防逃逸保持；`trustedScriptHashes`/`hashPinningEnabled` 归一化正确（默认 false、布尔校验）。
- 旧文案「cwd/engineeringRoot/extraWriteRoots」仍提示 engineeringRoot（仅文案，判定正确）。

### 4.2 `index.js` 胶水（v1.3.1：哈希钉住复核）

| 检查项 | 结果 | 说明 |
|---|---|---|
| prepend 注册 | ✅ | `ctx.on('approval/request', handler, true)`；plugin.test 断言 `options === true` |
| fail-closed | ✅ | handler try/catch → next；`decide()` 缺字段/异常/非 allow → null；判定期异常写 `error` 审计后 next |
| callId / toolName 关联 | ✅ | 倒序扫 `session.ownEvents()` 的 `tool/call`，比对 `callId` 与 `data.name`；arguments JSON 解析失败 → next |
| preset 判定 | ✅ | `agent-preset/selected` → header 回落 + `config.presets.includes`；非生效 preset → next |
| 预算 | ✅ | 每 session/每 turn；超限审计 + next；仅 allow 后自增 |
| 审计 | ✅ | plugin-start / auto-allow / ask-over-budget / error + status.json；写失败仅 warn |
| `/swapproval` | ✅ | status/on/off/log [n]/rehash；off 生效；异常不抛出；status 的 `trustedScripts` 已改用实时 `liveTrustedCount`（rehash 后显示新值，修复 v1.3 复核观察项） |
| 哈希钉住注入 | ✅ | 启动时 `computeTrustedScriptHashes` 覆盖 config + `hashPinningEnabled:true`；deps 注入 `hashFile`（sha256）；`/swapproval rehash` 重学并写 status；v1.3.1 起 plugin.test 覆盖 rehash |
| 只读依赖注入 | ✅ | deps 只读 fs + hashFile；全部 try/catch；不写审计目录以外路径 |
| 异常路径 | ✅ | 判定异常不向 approval 服务抛出 |

**观察项（非安全阻塞）**
1. `states` Map 清理用 `agent/disposed` 的 `payload.agent.id`，而 key 是 `session.id`；若两者不同则少量内存滞留（不影响判定）。
2. preset 缓存依赖 `session.seq`；`seq` 非数字时首次解析后不刷新（fail-safe 方向）。
3. `session.header?.cwd` 字段假设：不匹配时 cwd=null → write/edit 相对路径与 workspace 脚本 fail-closed ask（可用性，live 验证覆盖）。
4. 审计写失败仍允许放行（审计非安全闸门，需在启用说明中提示可追溯性）。
5. `POLICY_VERSION` 未递增（v1.3.1 仍为 '1'），审计无法区分版本。

### 4.3 bundle / package / 文档（通过）

- `type: module`、`dsh.bundle.patch`、`engines.dsh`、link 安装形态正确；profile cordis.yml 插件行与默认 config 正确。
- DESIGN 已同步 v1.3/v1.3.1（`hashFile`/`trustedScriptHashes`/`hashPinningEnabled`、B6 import `swapi`、COM ProgID、受信任路径字面量、B3 可操作锚点）。
- 剩余小偏差：`POLICY_VERSION` 未递增；DESIGN 模块图仍列不存在的 `lib/config.js`。

---

## 5. 对抗面验证矩阵（v1.3.1 最终结果）

| 攻击类型 | 代表样例 | 结果 | 说明 |
|---|---|---|---|
| 命令拼接 / `$()` / 反引号 / here-string / 别名 / 小写 cmdlet / 解释器逃逸 / shell 转交 / 反射 | 见 v1.2 首轮矩阵 | ask | B1/B2/B4/B5 + 额外收紧保持 |
| 路径穿越 / symlink / 兄弟前缀 / UNC / 长路径 / ADS | 见 §3.4 | ask | C 规则保持 |
| workspace 脚本危险 import/token | subprocess/ctypes/shutil/socket/winreg/open/write_text/... | ask | B6 |
| **B6 等价 API（P0）** | FSO/pathlib/numpy/COM ProgID 变量拼接/受信任路径字面量 | **ask** | v1.3 修复保持（B6-BLOCK/V13 全绿） |
| **SW COM 宏执行（P1）** | RunMacro / RunMacro2 | **ask** | v1.3.1 修复（runmacro token） |
| **COM 函数别名（P1）** | `from win32com.client import Dispatch as D` / 括号多名 / pythoncom | **ask** | v1.3.1 修复（import-alias） |
| **真实 SW 脚本 import swapi（P1 可用性）** | `import swapi` 的历史脚本 | **allow** | v1.3.1 修复（import 白名单 + 真实脚本复跑） |
| 哈希钉住（P2 fail-open 收紧） | `hashPinningEnabled:true` + 缺条目/缺 hashFile | **ask** | v1.3.1 修复；未启用时保持兼容回退 |
| 受信任脚本被覆盖 | 哈希不匹配 / hashFile 读不到 / 抛异常 | ask | 哈希钉住（第二道防线） |
| 文件创建 | `Path.touch()` | allow | P2 残余（§6.3，不阻塞） |
| 泛化 token 误杀 | 合法 `str.replace(` / `list.remove(` | ask（误杀） | P2 可用性残余（§6.3，不阻塞） |
| 纯文本锚点伪装 | `Write-Output "SldWorks"` / 注释 | ask | v1.1 锚点收紧保持 |
| 输出 exe 路径当锚点 | `Write-Output "<...>\SLDWORKS.exe"` | allow | 旧非阻塞残余（§6.4） |
| 任意文件读取（已接受） | 可操作锚点 + `Get-Content <任意>` | allow | 已接受（§6.4） |
| 真实语料危险命令 | npm/pnpm、Invoke-RestMethod、Remove-Item、注册表、taskkill、cmd /c、.desktop-bin、plugin add | ask | 45/45 两口径均 0 放行 |

---

## 6. 发现的绕过与修复状态（最终）

### 6.1 【已修复并验证】P0 B6-A：静态扫描等价危险 API 绕过（policy v1.3 起）

- 原问题：5 条复现全 allow，可组成「write 写 cwd 脚本 → B6 扫描放行执行 → FSO 覆盖 engineering/tools 受信任脚本 → 下次免扫描自动执行任意代码」的脚本版提权链。
- 修复：B6 deny token 大范围补齐 + COM ProgID 白名单 + 受信任路径字面量拒绝 + `import os as` 别名拒绝；index.js 增加受信任脚本 SHA-256 钉住。
- 验证：`B6-BLOCK` 5/5 + `B6-V13` 同类变体全部 ask；合法 SW 脚本 9/9 allow；三套测试 0 fail；语料危险命令 0 放行。**状态：已修复（仓库源码 v1.3.1），live 需重启生效。**

### 6.2 【已修复并验证】P1 三项 + 哈希 fail-open 收紧（policy v1.3.1）

| 项 | v1.3 状态 | v1.3.1 修复 | 本审查验证 |
|---|---|---|---|
| SW COM `RunMacro`/`RunMacro2` | allow | B6 deny token `runmacro` | RunMacro2/RunMacro 脚本 → ask ✅ |
| `from win32com/pythoncom import … as …` 别名绕过 ProgID 白名单 | allow | import-alias 检查扩展 | 单名/括号多名/pythoncom 变体 → ask ✅ |
| 真实 SW 脚本 `import swapi` 被拒（可用性 P1） | ask | `swapi` 加入 B6 import 白名单（仅此一项） | 真实 `retry_shot.py`/`verify_build.py` → allow ✅；`import swapi2` 等其它模块仍 ask |
| 哈希钉住 fail-open（缺条目/无 hashFile → allow） | allow | `hashPinningEnabled:true` 时 fail-closed → `hash-unavailable` | `true`：缺条目/缺 hashFile → ask；`false`：兼容回退 allow ✅ |

### 6.3 【P2 残余，维护者 判定不阻塞，记录/建议】v1.3.1 后仍未修

1. **`Path.touch()` 创建任意文件** → allow（可建空文件/占位；影响低于写内容）。建议后续 deny token `touch(`。
2. **可用性误杀：泛化 `replace(` token 误杀合法字符串方法 `str.replace`** → ask。build/模型生成脚本常用；建议按 Path/os 语境收窄 token 或改「危险 API allowlist」方案。
3. **可用性误杀：泛化 `remove(` token 误杀 `list.remove` 等内存容器操作** → ask；安全收益低、误杀成本高，同样建议收窄。

以上均已在对抗套件 `B6-R2` 以 `node:test` TODO 记录（不判失败），并计入 §3.2 的 8 条 todo。

### 6.4 【旧残余，状态不变】

1. **【非阻塞】B3-A 输出字符串中的 `SLDWORKS.exe` 路径仍被当作可操作锚点**：`Write-Output "<路径>"` → allow。影响受限于 B2 白名单只读命令，与已接受的读能力重叠；建议锚点限定在 Start-Process/& 参数位置或 Get-Process 目标。
2. **【已接受】任意文件读取不增加权限**：可操作锚点 + `Get-Content <任意文件>` → allow；依据 维护者 结论（沙箱读不受限、只禁写）。B1 仍拦凭据路径；建议用户工程工作区不存放无关敏感文件。
3. **低危/观察**：`os.kill`、`Path.mkdir` 未覆盖（todo）；`POLICY_VERSION` 未递增；`lib/config.js` 文档缺口；胶水观察项（§4.2）。

---

## 7. 残余风险汇总（v1.3.1 最终）

| 优先级 | 风险 | 状态 | 建议 |
|---|---|---|---|
| ~~P0~~ | B6 等价 API 绕过 + 脚本版提权链 | **已修复（v1.3，已验证）** | live 重启后由 维护者 E2E 确认 |
| ~~P1~~ | SW COM RunMacro/RunMacro2 宏执行 | **已修复（v1.3.1，已验证）** | — |
| ~~P1~~ | COM 函数别名导入绕过 ProgID 白名单 | **已修复（v1.3.1，已验证）** | — |
| ~~P1~~ | 真实 SW 脚本 `import swapi` 转 ask（可用性） | **已修复（v1.3.1，已验证）** | — |
| ~~P2~~ | 哈希钉住缺条目/无 hashFile fail-open | **已修复（v1.3.1：`hashPinningEnabled`，已验证）** | live 重启后确认胶水注入 true |
| P2 | `Path.touch` 建任意文件 | 未修（记录） | 后续补 token（不阻塞） |
| P2（可用性） | 泛化 `replace(`/`remove(` 误杀合法脚本 | 未修（记录） | 后续收窄 token（不阻塞） |
| P2 | B3 输出 exe 路径锚点 | 接受/待硬化 | 后续限定参数位置锚点 |
| P2 | 任意读取（已接受） | 已接受 | 保持 B1 凭据路径拦截 |
| P3 | 内存/版本号/文档/审计可追溯性等观察项 | 观察 | 随版本迭代修复 |

**总体判断**：v1.3.1 已消除全部 P0/P1；三套测试 0 fail、真实语料危险命令 100% ask、真 SW 主路径（含 `import swapi` 历史脚本）不误杀。剩余均为 P2/可用性残余（维护者 判定不阻塞），**结论：通过**。live 生效与应用层 E2E 由 维护者 在重启后确认。

---

## 8. 验证过 / 未验证项

**已独立验证（针对仓库源码 v1.3.1）**
- 三套测试 574 例：policy 52/52；plugin 15/15；adversarial 507（499 pass / 0 fail / 8 todo）。
- P0 回归：`B6-BLOCK` 5/5 ask；`B6-V13` 23/23 ask；`B6-V13-POS` 9/9 allow（含 `import swapi`）。
- P1 回归：RunMacro/RunMacro2 → ask；COM 别名导入（单名/括号多名/pythoncom）→ ask；`import swapi` → allow；`import swapi2` 等其它模块仍 ask。
- 哈希钉住：匹配/不匹配/读不到/抛异常；`hashPinningEnabled:true` 下缺条目、缺 hashFile → ask；`false` 兼容回退 allow；真实工程 tools 9 个脚本生产形态 allow（不误杀）。
- 真实语料 116 条两口径复跑：危险命令 45/45 ask、0 放行；fixture allow 62 与 维护者 报告一致。
- 真实历史 workspace 脚本扫描：`retry_shot.py`、`verify_build.py` 已 allow（v1.3.1 `swapi` 白名单生效）；`gear_calc.py`（无 SW 锚点）ask 合理。
- `lib/policy.js` v1.3.1 与 `index.js` v1.3.1 全文审查（含 hashPinningEnabled、rehash、审计/预算/fail-closed）。

**未验证（由 维护者 live 验证或后续迭代覆盖）**
1. **live 版本**：宿主当前仍运行旧模块，v1.3.1 需重启/重载；重启后核对 `status.json` 的 `trustedScripts`、新 `plugin-start` 时间戳与 policy 行为。
2. 真实 DSH `approval/request` E2E：宿主事件字段与 fake ctx 假设是否一致；`'allowed-once'` 在真实 waterfall 的语义。
3. `/swapproval status|on|off|log|rehash` 真实命令系统交互（rehash 后 status 数量、审计 phase）。
4. 真实 SolidWorks COM 建模全链路（含 `import swapi` 脚本自动放行后的实际执行）。
5. Windows 真实文件系统行为 vs 内存 fake（junction/symlink/8.3/ADS/长路径逻辑覆盖，真实 FS 未逐项）。
6. 安装/升级/卸载 patch 清理、与其它插件共存、长时间审计增长。
7. 哈希钉住 live 行为（启动时真实 tools 哈希、rehash、被覆盖后 ask）。

---

## 9. 给用户的启用建议（v1.3.1 最终版）

1. **结论为通过**：P0/P1 均已修复并独立验证；启用前**必须重启/重载 DSH** 加载 v1.3.1（含 `hashPinningEnabled:true`），并确认 `status.json` 出现 `trustedScripts`、`/swapproval status` 显示受信任脚本哈希数量。
2. 保持 `presets` 仅 `engineering`；不要关闭 `scanWorkspaceScripts`；不要扩大 `authorizedScripts` 到未审计脚本。
3. 更新工程 tools 脚本后执行一次 `/swapproval rehash` 重新学习哈希；之后脚本变更会转人工审批（预期安全行为）。
4. 已知 P2（不阻塞）：`Path.touch` 可建空文件；部分合法脚本若使用 `str.replace(`/`list.remove(` 会被误 ask，人工批准一次即可；如频繁发生可反馈给 判定引擎实现 收窄 token。
5. 定期检查 `%USERPROFILE%\.dsh\sw-approval\audit.jsonl`（auto-allow / ask-over-budget / error）与 `/swapproval status`；`/swapproval off` 可随时本会话紧急关闭。
6. 工程工作区不要放置与建模无关的敏感文件（已接受的读能力）；凭据路径仍被 B1 拦截。
7. live 验证：重启后在 engineering 会话跑一条真实 SW 命令，确认自动放行且审计出现 auto-allow 行；再核对 `/swapproval status` 的 trustedScripts 数量（由 维护者 处理）。

---

## 10. 复现方式

```bash
cd dsh-sw-approval

# 三套测试（沙箱内必须用 --experimental-test-isolation=none，否则 node --test 子进程 spawn EPERM）
node --test --experimental-test-isolation=none test/policy.test.mjs test/plugin.test.mjs test/adversarial.test.mjs
# 期望：574 tests / 566 pass / 0 fail / 8 todo

# 单套（进程内最快）
node test/policy.test.mjs        # 52/52
node test/plugin.test.mjs        # 15/15
node test/adversarial.test.mjs   # 507（499 pass / 0 fail / 8 todo）

# 真实语料分类（判定引擎实现 辅助脚本，fixture 口径：allow 62 / ask 54）
node test/fixtures/classify-corpus.mjs
```

- **P0 回归**：`B6-BLOCK` 5 条 + `B6-V13` 23 条必须全 ask。
- **P1 回归**：RunMacro/RunMacro2 → ask；COM 别名 import → ask；`import swapi` → allow。
- **哈希回归**：`hashPinningEnabled:true` 时缺条目/缺 hashFile → ask；匹配 allow；`false` 兼容回退 allow。
- **残余 todo**：`B6-R` 2 条 + `B6-R2` 3 条 + `H2-R` 3 条（`node:test` TODO 标记，不判失败；见 §6.3/§6.4）。
- 对抗套件与 `test/fixtures/` 无耦合（内存 fake deps + node:crypto 计算哈希），可在无真实工程脚本的机器上运行。

---

## 附录 A：对抗套件分组统计（507 例）

| 组 | 内容 | 例数 |
|---|---|---|
| 0 | 契约版本 / normalizeConfig / 返回形状 | 6 |
| A | 通用前置 fail-closed | 23 |
| B1 | pwsh 拒绝清单（含 v1.1 Export 具体化、大小写/重定向/多语句） | 123 |
| B2 | cmdlet 白名单（含 v1.2 ConvertFrom/To-Json 正例） | 25 |
| B3 | SW 锚点（含 v1.1 可操作证据收紧） | 11 |
| B4 | Start-Process / New-Object | 29 |
| B5 | 解释器与 .py 引用（含 build_*.py/export-pdf 主路径正例） | 42 |
| B6 | 脚本扫描（BLOCK 5 / V13 23 / V13-POS 9 / HASH 11 / H 8 / R 2 / R2 3 + 直接 60） | 121 |
| C | write/edit 允许根（含 v1.1 提权链 ask 用例） | 37 |
| D | 其它工具 | 6 |
| E | 真实语料（E1 危险 15 / E2 正例 3） | 18 |
| H1/H2 | HARDENING（纯文本锚点 / 可操作锚点 + 残余 todo） | 66 |

## 附录 B：语料分类口径说明（v1.3.1 复核结果）

- 「部署默认」口径 = `presets=['engineering']` + 真实 `node:fs` deps → allow 21 / ask 92（113 条 pwsh）；历史生成 `build_*.py` 已不存在导致 23 条 fail-closed ask；standard 会话 52 条因 preset 不生效 ask。
- 「fixture 口径」= 判定引擎实现 统计方法（`presets=['engineering','standard']` + 内存 fake cwd 脚本）→ allow 62 / ask 54（116 条），与 维护者 报告一致；其中 allow 含 standard 会话与伪造脚本，**不代表生产放行率**。
- v1.3.1 复核两种口径数字与 v1.2/v1.3 完全一致；45 条危险模式命令均 **0 放行**。
