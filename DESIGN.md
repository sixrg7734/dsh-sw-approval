# dsh-sw-approval — 设计契约（v1）

> 目标：为 DSH 写一个**安全**的「SW 建模自动审批」插件。
> 用户在 engineering（工程模式）会话里做 SolidWorks 建模，几乎每一步 `pwsh` 都要提权
> `danger-full-access`（沙箱下 SolidWorks COM 不可用），一次会话可达 37 次审批。
> 插件在 `approval/request` waterfall 上**只对严格匹配 SW 白名单的命令**返回 `allowed-once`，
> 其余全部 `next()`（照常弹窗）。不是全局 `approval: never`，不是 danger-full-access 预设。

## 硬约束

1. **不得改动 DSH 自带文件/其它插件**；插件只读宿主公开 API 与会话日志。
2. 自动放行判定失败、异常、未知 → 一律 `next()`（fail-closed 到人工审批），禁止抛异常（否则 approval 服务会当成 unavailable 直接拒绝）。
3. 不写工作区之外的日志以外路径；审计目录默认 `%USERPROFILE%\.dsh\sw-approval\`。
4. 仅对 `presets` 配置里的会话 preset 生效（默认 `['engineering']`，用户选定）。
5. 只自动放行 `pwsh` 的 `danger-full-access` 提权，以及 `write`/`edit` 对允许根目录内路径的提权。
6. 别的工具（plugin_manager、web、registry、删除类命令等）永不自动放行。

## 模块划分

```
dsh-sw-approval/
├── package.json          (维护者)
├── cordis.patch.yml      (维护者)  → insert 插件行 + 默认配置
├── index.js              (维护者)  → Host 插件胶水：事件、预算、preset、哈希钉住、审计、/swapproval
├── lib/policy.js         (判定引擎实现) → 纯函数判定引擎 + normalizeConfig，零 import、零 IO
├── locale/en.json / zh.json, icon.svg, README.md   (维护者)
├── test/policy.test.mjs  (判定引擎实现)
├── test/fixtures/*.json  (判定引擎实现, 由 维护者本地会话日志 脱敏而来)
├── test/plugin.test.mjs  (维护者, fake ctx 集成测试)
├── test/adversarial.test.mjs (独立审查)
└── SECURITY-REVIEW.md    (独立审查)
```

## lib/policy.js 契约

```js
// 纯函数；不 import 任何包；不使用 node: 内建以外的依赖；不做 IO（文件内容由 deps 注入）
export const POLICY_VERSION = '1';

/**
 * @param {object} input
 *   toolName: 'pwsh'|'write'|'edit'|string
 *   args: object            // 从会话日志 tool/call.data.arguments JSON.parse 得到
 *   preset: string|null     // 已由胶水解析好的会话 preset
 *   cwd: string|null        // 会话工作区绝对路径
 *   sessionId: string
 * @param {object} deps
 *   readFile(path): string|null       // 读 UTF-8 文本；读不到返回 null
 *   stat(path): {isFile:boolean,size:number}|null
 *   exists(path): boolean
 *   realpath(path): string|null       // 解析失败返回 null
 *   hashFile(path): string|null       // v1.3：SHA-256 hex；可选，缺失时退回旧行为
 * @param {object} config   // 已归一化（见下）；v1.3 起含 trustedScriptHashes
 * @returns {{
 *   decision: 'allow'|'ask',
 *   rule: string,           // 命中规则 id，如 'pwsh.sw-bridge.trusted'
 *   detail: string,         // 人类可读（中文），会进审计
 *   summary?: string,       // 命令/路径摘要（审计用，≤500 字符）
 *   checks?: object         // 调试信息（可选）
 * }}
 */
export function evaluateApproval(input, deps, config) { ... }

export function normalizeConfig(raw, env) { ... }  // env: {homedir, platform}
```

### 归一化配置默认值

```js
{
  enabled: true,
  presets: ['engineering'],
  engineeringRoot: '<homedir>/.dsh/.agent-presets/engineering',
  engineeringToolsDir: '<engineeringRoot>/tools',
  authorizedScripts: [
    'sw_bridge.py','swapi.py','physics_bridge.py','visual_check.py',
    'workflow_gate.py','mode_gate.py','mode2_flow.py','defense_gate.py','ask_user.py'
  ],
  workspaceScriptNames: [], // 空数组 = 任意 cwd 下 .py 只要 B6 静态扫描通过就放行；非空 = 仅这些文件名可扫描后放行
  // 注：v1.1 起 workspaceScriptNames 默认空数组（真实语料大量 build_*.py / probe_views.py，靠 B6 扫描兜底）
  solidworksExe: 'D:\\SolidWorks 2026\\SOLIDWORKS\\SLDWORKS.exe',
  extraWriteRoots: [],
  scanWorkspaceScripts: true,
  maxAutoApprovalsPerSession: 500,
  maxAutoApprovalsPerTurn: 80,
  maxCommandChars: 120000,
  maxScriptBytes: 524288,
  trustedScriptHashes: {},     // v1.3：{ basename: sha256hex }；由胶水启动时计算并注入
  hashPinningEnabled: false,   // v1.3.1：胶水注入 true；为 true 时授权脚本缺哈希条目/缺 hashFile 也必须 ask
  auditDir: '<homedir>/.dsh/sw-approval'
}
```

### 受信任脚本哈希钉住（v1.3，胶水负责计算）

`index.js` 启动时对 `engineeringToolsDir` 下 `authorizedScripts` 逐个计算 SHA-256，写入
`config.trustedScriptHashes`，并注入 `deps.hashFile`。政策引擎判定「授权脚本」时，若该脚本
配置了哈希，必须实际哈希一致才 allow；不一致/读不到 → ask。这样即使 B6 静态扫描被绕过、
模型覆盖了 `sw_bridge.py`，下一次「受信任脚本免扫描」也会因哈希变化转人工审批。正常更新工程
预设后用 `/swapproval rehash` 重新学习。`deps.hashFile` 缺失时政策引擎退回按路径信任（仅测试用）。

`normalizeConfig` 接受用户 patch 的任意子集；未知字段忽略；路径统一 `path.win32` 风格字符串（保留盘符）。

## 判定规则

### A. 通用前置（不满足 → ask）

1. `config.enabled === true`；
2. `presets.includes(preset)`；
3. 有 `req.callId` 且能在会话日志里找到对应 `tool/call` 事件（胶水负责，找不到 → ask）；
4. `args.sandbox_permissions === 'danger-full-access'`（pwsh/write/edit 都只处理这一档；其它提权目标 → ask）。

### B. `pwsh`

`args.command` 必须是 string，长度 ≤ `maxCommandChars`，无 `\0`。

**B1. 拒绝清单（任一命中 → ask）**，大小写不敏感，正则词边界：

- 破坏性：`Remove-Item`, `Remove-ItemProperty`, `Clear-Content`, `Clear-RecycleBin`, `Move-Item`, `Copy-Item`, `Rename-Item`, `New-Item`, `Set-Content`, `Add-Content`, `Out-File`, `Set-Item`, `Set-ItemProperty`, `New-ItemProperty`, `Format-Volume`, `diskpart`, `del `, `rmdir`, `Remove-`, `Clear-`
  （v1.1 订正：**删掉泛化 `Export-*`**，只拒绝具体危险 cmdlet `Export-Csv|Export-Clixml|Export-PfxCertificate|Export-Certificate`；否则 `sw_bridge.py export-pdf` 这类真 SW 命令会被误杀）
- 注册表：`HKLM`, `HKCU`, `HKEY_`, `Registry::`, `reg (add|delete|import|export)`, `regedit`, `New-PSDrive`
- 服务/计划任务/提权：`sc(\.exe)? (create|delete|config|start|stop)`, `net (user|localgroup|share|session|start)`, `schtasks`, `*-Service`, `Set-ExecutionPolicy`, `Enable-PSRemoting`, `winrm`, `netsh`, `Add-MpPreference`, `Set-MpPreference`, `bcdedit`, `powercfg`
- 网络/下载/安装：`Invoke-WebRequest`, `Invoke-RestMethod`, `curl`, `wget`, `Start-BitsTransfer`, `ssh`, `scp`, `ftp`, `telnet`, `npm`, `pnpm`, `yarn`, `pip`, `winget`, `choco`, `msiexec`, `corepack`, `Install-`, `Uninstall-`, `certutil`, `bitsadmin`
- 代码执行/反射：`Invoke-Expression`, `iex`, `Start-Job`, `Register-ObjectEvent`, `Add-Type`, `ScriptBlock`, `New-Object System.`, `[System.`, `[IO.`, `[Convert]`, `[Text.`, `[Reflection`, `-EncodedCommand`, `mshta`, `wscript`, `cscript`, `psexec`
- 进程/会话：`taskkill`, `Stop-Process`, `shutdown`, `Restart-Computer`, `logoff`
- 凭据/敏感：`.credentials`, `.ssh`, `id_rsa`, `Cookies`, `Login Data`, `.aws`, `.git-credentials`, `password`, `apikey`, `api_key`, `token`
- 文件重定向：`>`/`>>` 后接盘符/UNC/`$env:`（`2>&1` 不算）
- `cmd /c`, `cmd /k`, `wmic`

**B2. 白名单 cmdlet**：抽取 `\b[A-Z][A-Za-z]+-[A-Z][A-Za-z]+\b`，必须全部 ∈
`Get-ChildItem, Get-Item, Get-ItemProperty, Get-Process, Get-Content, Get-Date, Get-Command, Get-Unique, Select-Object, Select-String, Where-Object, ForEach-Object, Sort-Object, Measure-Object, Format-Table, Format-List, Out-String, Out-Null, Write-Output, Write-Host, Write-Warning, Start-Sleep, Test-Path, Resolve-Path, Split-Path, Join-Path, ConvertFrom-Json, ConvertTo-Json, [math]::Round 例外`
`New-Object` / `Start-Process` 由 B4/B5 单独校验。不在白名单 → ask。

**B3. SW 锚点（v1.1 起必须是「可操作证据」，纯文本不算）**：命令必须至少满足一项：
1. 引用受信任（engineeringToolsDir 下 authorizedScripts）或经 B6 扫描放行的 SW 脚本；
2. 经 B4 校验的 `Start-Process` 指向 solidworksExe，或 `New-Object -ComObject SldWorks.Application`；
3. `&` 调用字面 SolidWorks 主程序；
4. 引用 `SLDWORKS.exe` 路径；
5. `Get-Process ... SLDWORKS`（含 Where-Object 过滤）；
6. `DSH_SW_EXE` 赋值 + 调用 python 脚本。
纯 `Write-Output "SldWorks"`、字符串输出、注释文本 → 不算锚点，ask。

**B4. Start-Process / New-Object**：
- 每个 `Start-Process` 目标（直接字符串或先赋值的 `$var`）必须等于 `solidworksExe`（大小写/斜杠归一），否则 ask；
- 只允许 `New-Object -ComObject SldWorks.Application` 这一种 `New-Object`，其它 ask。

**B5. 解释器与脚本**：
- 命令中所有 `&` 调用的目标必须是：(a) `$var`，而该 var 在本命令内被赋值为允许的 python.exe 或 solidworksExe；(b) 字面量 python.exe；(c) 字面量 solidworksExe；其它 ask。
- 允许的 python.exe：路径匹配 `[\\/]dependencies[\\/]python[\\/]python\.exe$`，或 `$PY` 的赋值匹配该规则，或 `python` 裸命令（仅当命令中所有 `.py` 引用都是受信任脚本且无 `-c`/`-` 内联代码）。
- 抽取命令中所有 `.py` 引用（含 `$VAR\...py` 变量前缀，用命令内 `$VAR="..."` 赋值展开；展开失败/`%ENV%` → ask）。每个引用必须满足：
  - 在 `engineeringToolsDir` 下且 basename ∈ `authorizedScripts` → 受信任，直接放行；
  - 在会话 cwd 下（`workspaceScriptNames` 为空表示任意名字，非空则必须命中名单）→ 静态扫描（B6）通过才放行；
  - 其它 → ask。
- 特别地：`sw_bridge.py run <script.py>` 这类「受信任 bridge + 模型生成脚本」必须走 B6 扫描放行，
  否则 SW 建模主路径（模型写 build_*.py 再交给 bridge 执行）会全部掉回人工审批。
- 命令里出现 `-c` / here-string 内联 Python（`@"`…`"@`、`-c "..."`）→ ask（v1 不支持内联代码自动放行）。

**B6. 生成脚本静态扫描**（workspace 脚本，`scanWorkspaceScripts=true` 时）：
- `stat` 必须是文件、≤ maxScriptBytes、前 4KB 无 NUL；
- 必须含 SW 锚点（`win32com|pythoncom|SldWorks|SLDWORKS|sw_bridge|DSH_SW_EXE|swapi`）；
- import 白名单（解析 `import x` / `from x import`，允许根：`win32com, pythoncom, pywintypes, math, json, sys, os, time, datetime, re, pathlib, glob, collections, itertools, typing, dataclasses, struct, copy, decimal, fractions, io, traceback, statistics, random, uuid, numpy, swapi`）；出现其它 import → ask；
  v1.3.1：`from (win32com|pythoncom)… import … as …` 函数别名导入 → ask（防 `Dispatch as D` 绕过 ProgID 白名单）；
- 拒绝 token：`subprocess, os.system, os.popen, os.spawn, os.exec, ctypes, winreg, shutil, socket, urllib, requests, httpx, aiohttp, ftplib, paramiko, telnetlib, smtplib, webbrowser, importlib, builtins, pickle, marshal, eval(, exec(, __import__, os.remove, os.unlink, os.rmdir, os.rename, os.replace, AppData, .credentials, .ssh, id_rsa, Cookies, Login Data, password, apikey, api_key, token`
  v1.3.1 追加：`runmacro`（RunMacro/RunMacro2 宏执行）、`filesystemobject`/`scripting.`/`wscript.`/`shell.application`/`xmlhttp`/`winhttp`/`adodb.stream`、`unlink(`/`rmdir(`/`removedirs(`/`rmtree(`/`rename(`/`renames(`/`replace(`/`mkdir(`/`makedirs(`/`chmod(`/`symlink(`/`truncate(`/`remove(`/`kill(`/`putenv(`、`numpy.save`/`np.save`/`savez(`/`tofile(`/`fromfile(`、`win32file`/`win32api`/`win32process`/`win32security`/`win32event`、反射 dunder/`vars(`/`globals(`/`setattr(` 等；`import os as` 别名 → ask；脚本内容出现 `.agent-presets` / `.dsh\profiles` / `sw_bridge.py` 字面量 → ask。
- COM ProgID 白名单（v1.3）：`win32com/pythoncom` 的 `Dispatch/DispatchEx/EnsureDispatch/GetObject/CoCreateInstance` 只允许字符串字面量 `SldWorks.Application`（可带 `.版本` 后缀）；变量/拼接/f-string/其它 COM → ask。
  → 任一命中 → ask。
- 读不到/解析异常 → ask。

### C. `write` / `edit`

- `args.file_path` 必须是非空 string；
- 目标路径：绝对路径；相对路径按 `cwd` 解析；规范化后不得越出允许根；
- 允许根 = `[cwd, ...extraWriteRoots]`（**v1.1 起不含 engineeringRoot**：否则「先自动放行写 engineering\tools\sw_bridge.py 覆盖可信脚本、再自动放行执行」构成提权链）；用 `realpath(最近存在的父目录)` + basename 防 symlink 逃逸；大小写不敏感（Windows）；
- 路径落在允许根内 → allow（rule `fs.within-allowed-root`），否则 ask。
- 不做任何删除/移动语义（这些工具本身也不删除）。

## 胶水（index.js）职责

1. `ctx.on('approval/request', handler, true)`（**prepend**，必须排在 UI 应答者之前；handler 内 try/catch 后 `return next()`）；
2. 从 `req.agent.session` 取日志：
   - 找 `callId` 对应 `tool/call`（倒序扫 `session.ownEvents()`，JSON.parse(arguments) 失败 → ask）；
   - 解析 preset：倒序找 `agent-preset/selected` 的 `event.data.agentPreset`，回落 `session.header.agentPreset`；
   - 当前 turn：倒序找 `turn/start` 的 `data.turn`；
3. 预算：每 session 计数 + 每 turn（turn 变化重置）计数；超限 → ask + 审计；
4. 每 session 状态 Map（key=sessionId）：`{ disabledByUser, autoApproved, lastRule, lastAt, perTurn:{turn,count} }`；
5. 审计：`<auditDir>/audit.jsonl`，每行 `{ts, type:'auto-allow'|'ask-over-budget'|'error'|'plugin-start', sessionId, preset, tool, rule, detail, summary, turn}`；启动时写一行 `plugin-start`（含版本/配置摘要），供安装后验证插件确实加载；
6. `/swapproval` 命令（`ctx.inject(['commands'], …)`）：
   - `status`：enabled、presets、本会话 preset、本会话是否被 /off、计数、最后命中规则、审计路径；
   - `off` / `on`：本会话暂停/恢复自动放行；
   - `log [n]`：显示本会话最近 n 条自动放行；
   - 返回 `{kind:'success', text}`。
7. 日志用 `ctx.logger.info/warn`（若可用）；任何异常吞掉并 `return next()`。

## 测试/验收

- `node --test test/policy.test.mjs test/plugin.test.mjs`（DSH 自带 node 或 PATH node 均可跑；只用 node: 内建）。
- policy 测试语料：`维护者本地会话日志`（116 条真实历史审批，字段 command/path/preset/tool）。期望：
  - 所有真 SW 命令（含 sw_bridge/工程 preset 脚本/workspace SW 脚本/启动 SLDWORKS/读 SW 注册表探针）→ 判定合理（能放行的尽量放行，但内联 python/危险命令必须 ask）；
  - 非 SW 命令（npm/pnpm 安装、Invoke-RestMethod、Remove-Item 删除、注册表修改、taskkill、写 .desktop-bin、plugin 安装）→ **全部 ask**；
  - 对抗样例：`Get-ChildItem; Remove-Item ...`、`python "$R\tools\sw_bridge.py"; calc.exe`、`$(...)`、反引号、`Start-Process cmd`、路径 `..\..\Windows`、symlink、`sw_bridge.py` 字符串出现在注释里但实际跑别的命令 —— 全部 ask。
- 验收人：独立审查 独立写对抗测试并 review；维护者 负责安装后 live 验证（插件加载、审计行、/swapproval status 可用）。
