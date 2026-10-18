// dsh-sw-approval — 纯函数判定引擎（policy v1）
//
// 契约来源：DESIGN.md「lib/policy.js 契约」「判定规则」。
//
// 硬性实现约束：
//   1. 零 import、零 IO、零进程/env/全局可变状态；当前时间/文件系统全部由调用方注入。
//   2. 导出：evaluateApproval(input, deps, config) / normalizeConfig(raw, env) / POLICY_VERSION。
//   3. evaluateApproval 绝不抛异常：任何内部错误一律折返 { decision: 'ask' }（fail-closed，
//      交还人工审批）。胶水层仍会再包一层 try/catch。
//   4. allow 只在「所有规则全部通过」时返回；未知/缺字段/解析失败 → ask。
//
// deps（由胶水注入，测试用内存 fake）：
//   readFile(path): string|null   —— UTF-8 文本，读不到返回 null
//   stat(path): {isFile:boolean,size:number}|null
//   exists(path): boolean
//   realpath(path): string|null  —— 解析失败返回 null
//   hashFile(path): string|null  —— 可选；v1.3 受信任脚本哈希钉住用（sha256 hex）。
//                                  缺失时退回「只按 engineeringToolsDir + authorizedScripts」旧行为。
//
// 说明：本文件是安全判定引擎，注释里「更严格」的地方都是相对 DESIGN 文字规则的收紧，
// 不会放宽任何一条规则；与契约的偏差集中记录在交付报告与单元测试注释中。

export const POLICY_VERSION = '1.3.1';

// ---------------------------------------------------------------------------
// 默认配置 / 常量（与 DESIGN.md「归一化配置默认值」一致）
// ---------------------------------------------------------------------------

const DEFAULT_PRESETS = ['engineering'];

const DEFAULT_AUTHORIZED_SCRIPTS = [
  'sw_bridge.py',
  'swapi.py',
  'physics_bridge.py',
  'visual_check.py',
  'workflow_gate.py',
  'mode_gate.py',
  'mode2_flow.py',
  'defense_gate.py',
  'ask_user.py',
];

// v1.1：默认空数组 = 会话 cwd 下任意 .py 只要 B6 静态扫描通过即可放行；
// 非空数组 = 仅这些文件名可经 B6 扫描后放行（保留用户收紧能力）。
const DEFAULT_WORKSPACE_SCRIPTS = [];

const DEFAULT_SOLIDWORKS_EXE = 'D:\\SolidWorks 2026\\SOLIDWORKS\\SLDWORKS.exe';

// B2：允许出现的 PowerShell cmdlet（小写比较）。Start-Process / New-Object 由 B4 单独校验。
const CMDLET_WHITELIST = new Set([
  'get-childitem',
  'get-item',
  'get-itemproperty',
  'get-process',
  'get-content',
  'get-date',
  'get-command',
  'get-unique',
  'select-object',
  'select-string',
  'where-object',
  'foreach-object',
  'sort-object',
  'measure-object',
  'format-table',
  'format-list',
  'out-string',
  'out-null',
  'write-output',
  'write-host',
  'write-warning',
  'start-sleep',
  'test-path',
  'resolve-path',
  'split-path',
  'join-path',
  // v1.2：只读内存 JSON 序列化 cmdlet（无文件/系统副作用），真实 SW 命令大量使用
  'convertfrom-json',
  'convertto-json',
]);

// 命令位置白名单：白名单 cmdlet + 单独校验的 New-Object/Start-Process + python + 内置关键字/别名。
// 这是契约 B2（cmdlet 白名单）的安全延伸：契约只校验 Xxx-Yyy 形状的 cmdlet，裸命令
// （calc.exe / whoami / powershell …）不在其覆盖范围，这里额外要求命令位置只出现已知安全项。
const COMMAND_KEYWORDS = new Set([
  'if',
  'elseif',
  'else',
  'foreach',
  'for',
  'while',
  'do',
  'until',
  'try',
  'catch',
  'finally',
  'function',
  'filter',
  'param',
  'return',
  'throw',
  'break',
  'continue',
  'exit',
  'switch',
  'begin',
  'process',
  'end',
  'in',
  'using',
  'class',
  'enum',
  'trap',
  'data',
  'dynamicparam',
  'default',
]);

// 安全别名（小写）：echo=Write-Output；head/tail 是文本截断（真实工程语料里用到 head）。
const SAFE_ALIASES = new Set(['echo', 'head', 'tail']);

const PYTHON_EXE_RE = /(?:^|[\\/])dependencies[\\/]python[\\/]python\.exe$/i;

// B3：SolidWorks 锚点已按 v1.1 改为「可操作证据」（见 analyzeCommand 中的 operationalSwEvidence），
// 不再用纯文本正则把输出字符串里的 SldWorks/SLDWORKS 当锚点；B6 脚本扫描仍用 SCRIPT_SW_ANCHOR_RE。

// B6：workspace 脚本静态扫描
const SCRIPT_SW_ANCHOR_RE = /win32com|pythoncom|SldWorks|SLDWORKS|sw_bridge|DSH_SW_EXE|swapi/i;

const SCRIPT_IMPORT_ROOTS = new Set([
  'win32com',
  'pythoncom',
  'pywintypes',
  'math',
  'json',
  'sys',
  'os',
  'time',
  'datetime',
  're',
  'pathlib',
  'glob',
  'collections',
  'itertools',
  'typing',
  'dataclasses',
  'struct',
  'copy',
  'decimal',
  'fractions',
  'io',
  'traceback',
  'statistics',
  'random',
  'uuid',
  'numpy',
  // v1.3.1：真实历史 SW 脚本会 import swapi（工程 tools 下授权脚本），只加这一项
  'swapi',
]);

const SCRIPT_DENY_TOKENS = [
  'subprocess',
  'os.system',
  'os.popen',
  'os.spawn',
  'os.exec',
  'ctypes',
  'winreg',
  'shutil',
  'socket',
  'urllib',
  'requests',
  'httpx',
  'aiohttp',
  'ftplib',
  'paramiko',
  'telnetlib',
  'smtplib',
  'webbrowser',
  'importlib',
  'builtins',
  'pickle',
  'marshal',
  'eval(',
  'exec(',
  '__import__',
  'getattr(',
  'open(',
  'write_text',
  'write_bytes',
  'popen(',
  'os.startfile',
  'from os import',
  'sys.modules',
  'os.environ',
  'wscript.',
  'wscript.shell',
  'shell.application',
  // v1.3：等价危险 API（B6 静态扫描绕过面）
  'filesystemobject',
  'scripting.',
  'xmlhttp',
  'winhttp',
  'adodb.stream',
  'unlink(',
  'rmdir(',
  'removedirs(',
  'rmtree(',
  'rename(',
  'renames(',
  'replace(',
  'mkdir(',
  'makedirs(',
  'chmod(',
  'symlink(',
  'truncate(',
  'remove(',
  'os.kill',
  'kill(',
  'putenv(',
  'numpy.save',
  'np.save',
  'savez(',
  'tofile(',
  'fromfile(',
  'win32file',
  'win32api',
  'win32process',
  'win32security',
  'win32event',
  // v1.3.1（P1-a）：SW COM 宏执行（RunMacro / RunMacro2）等价任意代码执行
  'runmacro',
  // 额外加固：反射/间接执行与危险 dunder（B6 静态扫描仍属启发式，尽量抬高绕过成本）
  'vars(',
  'setattr(',
  'delattr(',
  'globals(',
  'locals(',
  'compile(',
  '__subclasses__',
  '__bases__',
  '__mro__',
  '__globals__',
  '__code__',
  '__closure__',
  '__getattribute__',
  '__dict__',
  'os.remove',
  'os.unlink',
  'os.rmdir',
  'os.rename',
  'os.replace',
  'appdata',
  '.credentials',
  '.ssh',
  'id_rsa',
  'cookies',
  'login data',
  'password',
  'apikey',
  'api_key',
  'token',
];

const EXECUTABLE_EXT_RE = /\.(?:exe|com|bat|cmd|ps1|msi|vbs|wsf|js)\b/i;

// B1 拒绝清单。所有匹配都在「去注释后的命令文本」上做，大小写不敏感。
// id 只用于审计/测试（规则名的一部分），命中任意一条即 ask。
const DENY_RULES = [
  // 破坏性文件操作
  { id: 'remove-item', re: /\bremove-item(?:property)?\b/i },
  { id: 'clear-content', re: /\bclear-content\b/i },
  { id: 'clear-recyclebin', re: /\bclear-recyclebin\b/i },
  { id: 'move-item', re: /\bmove-item\b/i },
  { id: 'copy-item', re: /\bcopy-item\b/i },
  { id: 'rename-item', re: /\brename-item\b/i },
  { id: 'new-item', re: /\bnew-item(?:property)?\b/i },
  { id: 'set-content', re: /\bset-content\b/i },
  { id: 'add-content', re: /\badd-content\b/i },
  { id: 'out-file', re: /\bout-file\b/i },
  // v1.1：只拒绝具体危险的导出 cmdlet，不再用泛化 Export-*（否则真 SW 命令
  // `sw_bridge.py export-pdf` 会被误杀）。大小写不敏感，按 cmdlet 形状匹配。
  { id: 'export-csv', re: /\bexport-csv\b/i },
  { id: 'export-clixml', re: /\bexport-clixml\b/i },
  { id: 'export-pfxcertificate', re: /\bexport-pfxcertificate\b/i },
  { id: 'export-certificate', re: /\bexport-certificate\b/i },
  { id: 'set-item', re: /\bset-item(?:property)?\b/i },
  { id: 'format-volume', re: /\bformat-volume\b/i },
  { id: 'diskpart', re: /\bdiskpart\b/i },
  { id: 'del', re: /\bdel\s+/i },
  { id: 'rmdir', re: /\brmdir\b/i },
  { id: 'remove-generic', re: /\bremove-[a-z]+\b/i },
  { id: 'clear-generic', re: /\bclear-[a-z]+\b/i },
  // 注册表
  { id: 'registry-hive', re: /\b(?:hklm|hkcu)\b/i },
  { id: 'registry-hkey', re: /\bhkey_/i },
  { id: 'registry-provider', re: /registry::/i },
  { id: 'reg-exe', re: /\breg(?:\.exe)?\s+(?:add|delete|import|export)\b/i },
  { id: 'regedit', re: /\bregedit\b/i },
  { id: 'new-psdrive', re: /\bnew-psdrive\b/i },
  // 服务 / 计划任务 / 提权 / 安全策略
  { id: 'sc', re: /\bsc(?:\.exe)?\s+(?:create|delete|config|start|stop)\b/i },
  { id: 'net', re: /\bnet(?:\.exe)?\s+(?:user|localgroup|share|session|start)\b/i },
  { id: 'schtasks', re: /\bschtasks\b/i },
  { id: 'service-cmdlet', re: /\b[a-z]+-service\b/i },
  { id: 'set-executionpolicy', re: /\bset-executionpolicy\b/i },
  { id: 'enable-psremoting', re: /\benable-psremoting\b/i },
  { id: 'winrm', re: /\bwinrm\b/i },
  { id: 'netsh', re: /\bnetsh\b/i },
  { id: 'mp-preference', re: /\b(?:add|set)-mppreference\b/i },
  { id: 'bcdedit', re: /\bbcdedit\b/i },
  { id: 'powercfg', re: /\bpowercfg\b/i },
  // 网络 / 下载 / 安装
  { id: 'invoke-webrequest', re: /\binvoke-webrequest\b/i },
  { id: 'invoke-restmethod', re: /\binvoke-restmethod\b/i },
  { id: 'curl', re: /\bcurl\b/i },
  { id: 'wget', re: /\bwget\b/i },
  { id: 'bits-transfer', re: /\bstart-bitstransfer\b/i },
  { id: 'ssh', re: /\bssh\b/i },
  { id: 'scp', re: /\bscp\b/i },
  { id: 'ftp', re: /\bftp\b/i },
  { id: 'telnet', re: /\btelnet\b/i },
  { id: 'npm', re: /\bnpm\b/i },
  { id: 'pnpm', re: /\bpnpm\b/i },
  { id: 'yarn', re: /\byarn\b/i },
  { id: 'pip', re: /\bpip\b/i },
  { id: 'winget', re: /\bwinget\b/i },
  { id: 'choco', re: /\bchoco\b/i },
  { id: 'msiexec', re: /\bmsiexec\b/i },
  { id: 'corepack', re: /\bcorepack\b/i },
  { id: 'install-', re: /\binstall-[a-z]+\b/i },
  { id: 'uninstall-', re: /\buninstall-[a-z]+\b/i },
  { id: 'certutil', re: /\bcertutil\b/i },
  { id: 'bitsadmin', re: /\bbitsadmin\b/i },
  // 代码执行 / 反射
  { id: 'invoke-expression', re: /\binvoke-expression\b/i },
  { id: 'iex', re: /\biex\b/i },
  { id: 'start-job', re: /\bstart-job\b/i },
  { id: 'register-objectevent', re: /\bregister-objectevent\b/i },
  { id: 'add-type', re: /\badd-type\b/i },
  { id: 'scriptblock', re: /\bscriptblock\b/i },
  { id: 'new-object-system', re: /\bnew-object\s+system\./i },
  { id: 'system-type', re: /\[system\./i },
  { id: 'io-type', re: /\[io\./i },
  { id: 'convert-type', re: /\[convert\]/i },
  { id: 'text-type', re: /\[text\./i },
  { id: 'reflection-type', re: /\[reflection/i },
  { id: 'encoded-command', re: /-encodedcommand\b/i },
  { id: 'mshta', re: /\bmshta\b/i },
  { id: 'wscript', re: /\bwscript\b/i },
  { id: 'cscript', re: /\bcscript\b/i },
  { id: 'psexec', re: /\bpsexec\b/i },
  // 进程 / 会话
  { id: 'taskkill', re: /\btaskkill\b/i },
  { id: 'stop-process', re: /\bstop-process\b/i },
  { id: 'shutdown', re: /\bshutdown\b/i },
  { id: 'restart-computer', re: /\brestart-computer\b/i },
  { id: 'logoff', re: /\blogoff\b/i },
  // 凭据 / 敏感数据
  { id: 'credentials-dir', re: /\.credentials\b/i },
  { id: 'ssh-dir', re: /\.ssh\b/i },
  { id: 'id-rsa', re: /\bid_rsa\b/i },
  { id: 'cookies', re: /\bcookies\b/i },
  { id: 'login-data', re: /\blogin data\b/i },
  { id: 'aws', re: /\.aws\b/i },
  { id: 'git-credentials', re: /\.git-credentials\b/i },
  { id: 'windows-credential-store', re: /\\config\\(?:sam|system|security)\b/i },
  { id: 'password', re: /\bpassword\b/i },
  { id: 'apikey', re: /\bapikey\b/i },
  { id: 'api-key', re: /\bapi_key\b/i },
  { id: 'token', re: /\btoken\b/i },
  // SolidWorks 宏执行（COM RunMacro/RunMacro2）等价于任意代码执行
  { id: 'sw-macro', re: /\brunmacro[0-9]*\b/i },
  // 枚举盘符根目录（对 SW 建模没有正当用途，额外收紧）
  {
    id: 'read-drive-root',
    re: /\bget-(?:childitem|item|content|itemproperty)\b[^\r\n;|]*?(?:^|[\s(])['"]?[A-Za-z]:[\\/]?['"]?(?=\s|\)|$|;|\|)/i,
  },
  // 输出重定向到盘符 / UNC / 环境变量（2>&1 不算）
  { id: 'redirect', re: /(?:>>?)\s*(?:[A-Za-z]:[\\/]|\\\\|\$env:)/i },
  // 命令解释器
  { id: 'cmd', re: /\bcmd(?:\.exe)?\s+\/[ck]\b/i },
  { id: 'wmic', re: /\bwmic\b/i },
];

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function truncate(text, max) {
  const value = typeof text === 'string' ? text : String(text ?? '');
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function makeSummary(text) {
  const value = typeof text === 'string' ? text : '';
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > 500 ? flat.slice(0, 500) : flat;
}

function allowResult(rule, detail, summary, checks) {
  const result = { decision: 'allow', rule, detail: String(detail) };
  result.summary = typeof summary === 'string' ? makeSummary(summary) : '';
  if (checks !== undefined) result.checks = checks;
  return result;
}

function askResult(rule, detail, summary, checks) {
  const result = { decision: 'ask', rule, detail: String(detail) };
  result.summary = typeof summary === 'string' ? makeSummary(summary) : '';
  if (checks !== undefined) result.checks = checks;
  return result;
}

function safeDep(deps, name, arg) {
  try {
    if (!deps || typeof deps[name] !== 'function') return { ok: false, value: null };
    const value = deps[name](arg);
    return { ok: true, value: value === undefined ? null : value };
  } catch {
    return { ok: false, value: null };
  }
}

// ---------------------------------------------------------------------------
// Windows 路径工具（不 import node:path；统一 win32 语义、大小写不敏感）
// ---------------------------------------------------------------------------

/**
 * 规范化绝对 Windows 路径：正斜杠转反斜杠、解析 . 与 ..、盘符大写、去掉尾部分隔符。
 * 相对路径 / 驱动器相对路径（C:foo）/ 根相对路径（\foo）返回 null（保守，调用方转 ask）。
 */
function canonWinPath(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (trimmed === '') return null;
  let s = trimmed.replace(/\//g, '\\');
  let prefix;
  let rest;
  const driveMatch = /^([A-Za-z]):(.*)$/.exec(s);
  if (/^\\\\/.test(s)) {
    prefix = '\\\\';
    rest = s.replace(/^\\+/, '');
  } else if (driveMatch) {
    prefix = `${driveMatch[1].toUpperCase()}:`;
    rest = driveMatch[2];
    if (!rest.startsWith('\\')) return null; // C:foo 是驱动器相对路径 → 保守拒绝
    rest = rest.replace(/^\\+/, '');
  } else {
    return null; // 相对路径或根相对路径
  }
  const segments = [];
  for (const segment of rest.split('\\')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (segments.length === 0) return null; // 越过根 → 无效
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  if (prefix === '\\\\') {
    if (segments.length < 1) return null;
    return `\\\\${segments.join('\\')}`;
  }
  return `${prefix}\\${segments.join('\\')}`;
}

/** 把用户输入解析成绝对规范化路径：绝对路径直接用；相对路径按 cwd 解析。 */
function resolveUserPath(inputPath, cwd) {
  if (typeof inputPath !== 'string') return null;
  if (inputPath.includes('\0')) return null;
  const trimmed = inputPath.trim();
  if (trimmed === '') return null;
  const unified = trimmed.replace(/\//g, '\\');
  if (/^[A-Za-z]:/.test(unified) || /^\\\\/.test(unified)) return canonWinPath(unified);
  if (/^\\/.test(unified)) return null; // \foo（根相对）无法判定盘符 → 保守拒绝
  const base = canonWinPath(cwd);
  if (!base) return null;
  return canonWinPath(base.endsWith('\\') ? `${base}${unified}` : `${base}\\${unified}`);
}

function isWithinWin(child, root) {
  if (typeof child !== 'string' || typeof root !== 'string') return false;
  const c = child.toLowerCase();
  const r = root.toLowerCase();
  if (c === r) return true;
  const prefix = r.endsWith('\\') ? r : `${r}\\`;
  return c.startsWith(prefix);
}

function parentWinPath(canon) {
  if (typeof canon !== 'string') return null;
  const trimmed = canon.replace(/\\+$/, '');
  if (trimmed === '') return null;
  if (/^[A-Za-z]:$/.test(trimmed)) return null; // 盘符根没有父目录
  const index = trimmed.lastIndexOf('\\');
  if (index < 0) return null;
  const head = trimmed.slice(0, index);
  if (/^[A-Za-z]:$/.test(head)) return `${head}\\`;
  if (head === '') return null;
  if (/^\\\\[^\\]+$/.test(head)) return null; // UNC \\server 根
  return head;
}

function baseNameWin(canon) {
  if (typeof canon !== 'string') return null;
  const trimmed = canon.replace(/\\+$/, '');
  const index = trimmed.lastIndexOf('\\');
  const base = index < 0 ? trimmed : trimmed.slice(index + 1);
  return base === '' ? null : base;
}

function normalizeSlashKey(value) {
  return String(value ?? '').replace(/\//g, '\\').toLowerCase();
}

function samePath(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ca = canonWinPath(a);
  const cb = canonWinPath(b);
  if (!ca || !cb) return normalizeSlashKey(a) === normalizeSlashKey(b);
  return ca.toLowerCase() === cb.toLowerCase();
}

// ---------------------------------------------------------------------------
// normalizeConfig
// ---------------------------------------------------------------------------

function pickString(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function pickPath(value, fallback) {
  const text = pickString(value);
  if (text !== null) {
    const canon = canonWinPath(text);
    if (canon !== null) return canon;
  }
  return fallback;
}

function pickStringArray(value, fallback) {
  if (!Array.isArray(value)) return fallback.slice();
  const out = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (trimmed !== '' && !out.includes(trimmed)) out.push(trimmed);
  }
  return out;
}

function pickPositiveInt(value, fallback) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return value;
  return fallback;
}

function pickBoolean(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

/**
 * v1.3：受信任脚本哈希钉住配置。输入形如 { 'sw_bridge.py': '<sha256hex>' }。
 * key 统一成 basename 小写（也接受完整路径），value 去空白转小写；非法项忽略。
 */
function pickTrustedScriptHashes(value) {
  const out = {};
  if (!isPlainObject(value)) return out;
  for (const [rawKey, rawHash] of Object.entries(value)) {
    if (typeof rawHash !== 'string') continue;
    const normalizedKey = String(rawKey).replace(/\//g, '\\');
    const base = (baseNameWin(normalizedKey) ?? normalizedKey).trim().toLowerCase();
    const hash = rawHash.trim().toLowerCase();
    if (base === '' || hash === '') continue;
    out[base] = hash;
  }
  return out;
}

/**
 * 归一化用户配置：任意子集 + 未知字段忽略；返回判定引擎使用的完整配置。
 * env: { homedir, platform }（由胶水注入，便于测试）。
 */
export function normalizeConfig(raw, env) {
  const source = isPlainObject(raw) ? raw : {};
  const environment = isPlainObject(env) ? env : {};
  const homedir = typeof environment.homedir === 'string' ? canonWinPath(environment.homedir) : null;
  const dshDir = homedir ? canonWinPath(`${homedir}\\.dsh`) : null;
  const defaultEngineeringRoot = dshDir
    ? canonWinPath(`${dshDir}\\.agent-presets\\engineering`)
    : null;
  const engineeringRoot = pickPath(source.engineeringRoot, defaultEngineeringRoot);
  const engineeringToolsDir = pickPath(
    source.engineeringToolsDir,
    engineeringRoot ? canonWinPath(`${engineeringRoot}\\tools`) : null,
  );
  const extraWriteRoots = [];
  if (Array.isArray(source.extraWriteRoots)) {
    for (const item of source.extraWriteRoots) {
      const canon = typeof item === 'string' ? canonWinPath(item) : null;
      if (canon !== null && !extraWriteRoots.includes(canon)) extraWriteRoots.push(canon);
    }
  }
  return {
    enabled: pickBoolean(source.enabled, true),
    presets: pickStringArray(source.presets, DEFAULT_PRESETS),
    engineeringRoot,
    engineeringToolsDir,
    authorizedScripts: pickStringArray(source.authorizedScripts, DEFAULT_AUTHORIZED_SCRIPTS),
    trustedScriptHashes: pickTrustedScriptHashes(source.trustedScriptHashes),
    // v1.3.1：默认 false（policy 单测/未升级胶水保持旧行为）；维护者会在 index.js 注入 true。
    hashPinningEnabled: pickBoolean(source.hashPinningEnabled, false),
    workspaceScriptNames: pickStringArray(source.workspaceScriptNames, DEFAULT_WORKSPACE_SCRIPTS),
    solidworksExe: pickPath(source.solidworksExe, DEFAULT_SOLIDWORKS_EXE),
    extraWriteRoots,
    scanWorkspaceScripts: pickBoolean(source.scanWorkspaceScripts, true),
    maxAutoApprovalsPerSession: pickPositiveInt(source.maxAutoApprovalsPerSession, 500),
    maxAutoApprovalsPerTurn: pickPositiveInt(source.maxAutoApprovalsPerTurn, 80),
    maxCommandChars: pickPositiveInt(source.maxCommandChars, 120000),
    maxScriptBytes: pickPositiveInt(source.maxScriptBytes, 524288),
    auditDir: pickPath(source.auditDir, dshDir ? canonWinPath(`${dshDir}\\sw-approval`) : null),
  };
}

// ---------------------------------------------------------------------------
// 命令解析：去注释 / 字符串 / 变量赋值 / token 流 / 子表达式 / here-string
// ---------------------------------------------------------------------------

/**
 * 匹配 $() 子表达式：从 '(' 所在下标开始，返回右括号之后的下标；不匹配返回 -1。
 * 跳过单/双引号字符串与反引号转义。
 */
function findMatchingParen(text, openIndex) {
  let depth = 0;
  let i = openIndex;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      i += 1;
      while (i < text.length) {
        const c = text[i];
        if (c === '`') {
          i += 2;
          continue;
        }
        if (c === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === "'") {
      i += 1;
      while (i < text.length) {
        const c = text[i];
        if (c === "'") {
          if (text[i + 1] === "'") {
            i += 2;
            continue;
          }
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === '(') {
      depth += 1;
      i += 1;
      continue;
    }
    if (ch === ')') {
      depth -= 1;
      i += 1;
      if (depth === 0) return i;
      continue;
    }
    i += 1;
  }
  return -1;
}

/**
 * 解析一条 PowerShell 命令：
 *   clean    —— 去注释（注释字符替换为空格，长度/下标不变），保留字符串原文
 *   masked   —— 在 clean 基础上把字符串内容也替换为空格（只用于抽取「代码部分」）
 *   tokens   —— 轻量 token 流（word/parameter/var/string/number/op/...）
 *   assignments —— 命令内 $var = "..." 赋值（用于展开脚本/解释器路径）
 *   issues   —— here-string / 反引号转义 / $() 子表达式 / 未闭合字符串
 */
function parseCommand(command) {
  const length = command.length;
  const cleanChars = command.split('');
  const maskedChars = command.split('');
  const tokens = [];
  const assignments = [];
  const subexpressions = [];
  const hereStrings = [];
  const backticks = [];
  const unterminated = [];

  let i = 0;
  while (i < length) {
    const ch = command[i];

    if (ch === '\r' || ch === '\n') {
      tokens.push({ type: 'newline', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      let j = i;
      while (j < length && command[j] !== '\n') {
        cleanChars[j] = ' ';
        maskedChars[j] = ' ';
        j += 1;
      }
      i = j;
      continue;
    }
    // PowerShell 块注释 <# ... #>：必须按注释处理，否则攻击者可用它把危险命令
    // 从拒绝清单/语句扫描里藏掉（<# x #>; Remove-Item ...）。
    if (ch === '<' && command[i + 1] === '#') {
      const closing = command.indexOf('#>', i + 2);
      const end = closing >= 0 ? closing + 2 : length;
      if (closing < 0) unterminated.push(i);
      for (let k = i; k < end; k += 1) {
        cleanChars[k] = ' ';
        maskedChars[k] = ' ';
      }
      i = end;
      continue;
    }
    // here-string：@" / @' 后必须换行
    if (ch === '@' && (command[i + 1] === '"' || command[i + 1] === "'")) {
      const header = /^@(["'])[ \t]*\r?\n/.exec(command.slice(i));
      if (header !== null) {
        const quote = header[1];
        const closing = `\n${quote}@`;
        const closingIndex = command.indexOf(closing, i + header[0].length);
        const end = closingIndex >= 0 ? closingIndex + closing.length : length;
        if (closingIndex < 0) unterminated.push(i);
        hereStrings.push({ start: i });
        for (let k = i; k < end; k += 1) maskedChars[k] = ' ';
        tokens.push({ type: 'string', value: command.slice(i, end), hereString: true, start: i, end });
        i = end;
        continue;
      }
    }
    // @( / @{ —— 数组/哈希子表达式
    if (ch === '@' && (command[i + 1] === '(' || command[i + 1] === '{')) {
      tokens.push({ type: 'expr-start', value: command[i + 1], start: i, end: i + 2 });
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      let j = i + 1;
      let value = '';
      let closed = false;
      while (j < length) {
        const c = command[j];
        if (quote === '"' && c === '`') {
          if (j + 1 < length) {
            value += command[j + 1];
            j += 2;
            continue;
          }
          j += 1;
          continue;
        }
        // 双引号内的 $() 会被执行：抽出来单独做二级校验
        if (quote === '"' && c === '$' && command[j + 1] === '(') {
          const close = findMatchingParen(command, j + 1);
          if (close > 0) {
            subexpressions.push({ inner: command.slice(j + 2, close - 1), start: j });
            j = close;
            continue;
          }
        }
        if (quote === '"' && c === '"') {
          j += 1;
          closed = true;
          break;
        }
        if (quote === "'" && c === "'") {
          if (command[j + 1] === "'") {
            value += "'";
            j += 2;
            continue;
          }
          j += 1;
          closed = true;
          break;
        }
        value += c;
        j += 1;
      }
      if (!closed) unterminated.push(i);
      for (let k = i; k < j; k += 1) maskedChars[k] = ' ';
      tokens.push({ type: 'string', value, quote, closed, start: i, end: j });
      i = j;
      continue;
    }
    if (ch === '$' && command[i + 1] === '(') {
      const close = findMatchingParen(command, i + 1);
      if (close > 0) {
        subexpressions.push({ inner: command.slice(i + 2, close - 1), start: i });
        tokens.push({ type: 'subexpr', value: command.slice(i + 2, close - 1), start: i, end: close });
        i = close;
        continue;
      }
      unterminated.push(i);
      tokens.push({ type: 'op', value: '$', start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '`') {
      backticks.push({ start: i });
      cleanChars[i] = ' ';
      maskedChars[i] = ' ';
      i += 1;
      continue;
    }
    if (ch === ';') {
      tokens.push({ type: 'sep', value: ';', start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '|') {
      tokens.push({ type: 'pipe', value: '|', start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '{') {
      tokens.push({ type: 'block-open', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '}') {
      tokens.push({ type: 'block-close', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '(') {
      tokens.push({ type: 'paren-open', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === ')') {
      tokens.push({ type: 'paren-close', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '&') {
      tokens.push({ type: 'amp', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '>') {
      let j = i + 1;
      let value = '>';
      if (command[j] === '>') {
        value = '>>';
        j += 1;
      }
      tokens.push({ type: 'redirect', value, start: i, end: j });
      i = j;
      continue;
    }
    if (ch === '<') {
      tokens.push({ type: 'redirect', value: '<', start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === '=') {
      tokens.push({ type: 'assign', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (ch === ',') {
      tokens.push({ type: 'comma', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    // 参数 token：-FilePath / -ErrorAction / -lt …（'-' 后紧跟字母）
    if (ch === '-' && /[A-Za-z]/.test(command[i + 1] ?? '')) {
      let j = i + 1;
      while (j < length && /[A-Za-z0-9_]/.test(command[j])) j += 1;
      tokens.push({ type: 'word', value: command.slice(i, j), parameter: true, start: i, end: j });
      i = j;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      if (command[j] === '{') {
        while (j < length && command[j] !== '}') j += 1;
        j += 1;
      } else {
        while (j < length && /[A-Za-z0-9_:.]/.test(command[j])) j += 1;
      }
      tokens.push({ type: 'var', value: command.slice(i, j), start: i, end: j });
      i = j;
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let j = i;
      while (j < length && /[0-9.]/.test(command[j])) j += 1;
      tokens.push({ type: 'number', value: command.slice(i, j), start: i, end: j });
      i = j;
      continue;
    }
    if ('+-*/%!?:.'.includes(ch)) {
      tokens.push({ type: 'op', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    // 普通单词
    let j = i;
    while (j < length && !/[\s;|(){}'"$&<>=,`#]/.test(command[j])) j += 1;
    if (j === i) {
      tokens.push({ type: 'op', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }
    tokens.push({ type: 'word', value: command.slice(i, j), start: i, end: j });
    i = j;
  }

  const clean = cleanChars.join('');
  const masked = maskedChars.join('');
  collectAssignments(clean, assignments);

  return {
    clean,
    masked,
    tokens,
    assignments,
    subexpressions,
    hereStrings,
    backticks,
    unterminated,
  };
}

/** 收集命令内 $var = <字面量> 赋值；值含 $env:/相对/未知结构时保留原文（后续展开失败即 ask）。 */
function collectAssignments(clean, out) {
  const re =
    /\$([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(?:"((?:[^"`]|`[\s\S])*)"|'([^']*)'|(\$env:[A-Za-z_][A-Za-z0-9_]*)|([^\s;|(){}]+))/g;
  let match;
  while ((match = re.exec(clean)) !== null) {
    const name = match[1].toLowerCase();
    let value;
    if (match[2] !== undefined) value = match[2].replace(/`([\s\S])/g, '$1');
    else if (match[3] !== undefined) value = match[3];
    else if (match[4] !== undefined) value = match[4];
    else value = match[5] ?? '';
    out.push({ name, value, index: match.index });
  }
}

function simpleVarName(tokenValue) {
  const match = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(tokenValue);
  return match === null ? null : match[1].toLowerCase();
}

/** 取在 atIndex 之前最后一次赋值；若同名变量在命令内被赋过不同值 → 返回 null（保守拒绝）。 */
function resolveVarValue(name, atIndex, assignments) {
  if (name === null) return null;
  const list = assignments.filter((item) => item.name === name);
  if (list.length === 0) return null;
  const before = list.filter((item) => item.index < atIndex);
  if (before.length === 0) return null;
  const values = new Set(list.map((item) => item.value));
  if (values.size > 1) return null;
  return before[before.length - 1];
}

/** 递归展开文本中的 $VAR / ${VAR}；失败（未知变量、$env:、%ENV%、残留变量）返回 null。 */
function expandVariables(text, atIndex, assignments, depth) {
  if (typeof text !== 'string') return null;
  if (depth > 6) return null;
  if (/%[A-Za-z_][A-Za-z0-9_]*%/.test(text)) return null;
  if (/\$\{?env:/i.test(text)) return null;
  let unresolved = false;
  const expanded = text.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (whole, braced, plain) => {
      const name = (braced ?? plain).toLowerCase();
      const assignment = resolveVarValue(name, atIndex, assignments);
      if (assignment === null) {
        unresolved = true;
        return whole;
      }
      const value = expandVariables(assignment.value, assignment.index, assignments, depth + 1);
      if (value === null) {
        unresolved = true;
        return whole;
      }
      return value;
    },
  );
  if (unresolved) return null;
  // 展开后仍残留 $（未知变量/${env:...} 等）→ 视为无法解析，保守转人工审批
  if (expanded.includes('$')) return null;
  return expanded;
}

// ---------------------------------------------------------------------------
// 通用小判定
// ---------------------------------------------------------------------------

function isPythonExecutable(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim().replace(/\//g, '\\');
  if (PYTHON_EXE_RE.test(trimmed)) return true;
  const lower = trimmed.toLowerCase();
  return lower === 'python' || lower === 'python.exe';
}

function isSolidworksExecutable(value, config) {
  if (typeof value !== 'string' || typeof config.solidworksExe !== 'string') return false;
  return samePath(value, config.solidworksExe);
}

/** 是否引用了 SLDWORKS.exe（配置路径或任意以 SLDWORKS.exe 结尾的路径）。 */
function isSolidworksExeLike(value, config) {
  if (typeof value !== 'string') return false;
  if (isSolidworksExecutable(value, config)) return true;
  const normalized = value.trim().replace(/\//g, '\\');
  return /(?:^|[\\/])sldworks\.exe$/i.test(normalized);
}

/** 是否存在真实的 SW 进程查询：Get-Process ... SLDWORKS（含管道里的 Where-Object 过滤）。 */
function hasGetProcessWithSldworks(parsed) {
  const tokens = parsed.tokens;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token.type !== 'word' || token.value.toLowerCase() !== 'get-process') continue;
    for (let j = i + 1; j < tokens.length; j += 1) {
      const next = tokens[j];
      if (next.type === 'newline' || next.type === 'sep' || next.type === 'block-close') break;
      if ((next.type === 'word' || next.type === 'string') && /sldworks/i.test(String(next.value))) return true;
    }
  }
  return false;
}

// v1.3：SLDWORKS.exe 路径只在「只读路径探测 cmdlet 的实参」位置算锚点证据，
// 不再把 Write-Output "<SLDWORKS.exe 路径>" 这类纯输出文本当锚点（防任意白名单命令搭便车）。
const SW_EXE_PROBE_CMDLETS = new Set([
  'test-path',
  'get-item',
  'get-itemproperty',
  'resolve-path',
  'split-path',
  'get-command',
]);

function hasSolidworksExeProbe(parsed, config) {
  const tokens = parsed.tokens;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token.type !== 'word' || !SW_EXE_PROBE_CMDLETS.has(token.value.toLowerCase())) continue;
    for (let j = i + 1; j < tokens.length; j += 1) {
      const next = tokens[j];
      if (
        next.type === 'newline' ||
        next.type === 'sep' ||
        next.type === 'pipe' ||
        next.type === 'block-close'
      ) {
        break;
      }
      if ((next.type === 'string' || next.type === 'word') && isSolidworksExeLike(next.value, config)) return true;
    }
  }
  return false;
}

function isAllowedExecutableToken(value, config) {
  return isPythonExecutable(value) || isSolidworksExecutable(value, config);
}

// ---------------------------------------------------------------------------
// 静态检查
// ---------------------------------------------------------------------------

function matchDenyRule(clean) {
  for (const rule of DENY_RULES) {
    if (rule.re.test(clean)) return rule;
  }
  return null;
}

/** 从字符串 token / 裸词 token 中提取可能的可执行文件引用（容忍路径里有空格）。 */
function executableCandidates(value) {
  const trimmed = String(value ?? '').trim();
  if (trimmed === '') return [];
  const whole = trimmed.replace(/^["']+|["']+$/g, '');
  if (EXECUTABLE_EXT_RE.test(whole)) return [whole];
  const out = [];
  for (const piece of trimmed.split(/\s+/)) {
    const cleaned = piece.replace(/^[([{,'"`]+|[)\]},;:'"`]+$/g, '');
    if (EXECUTABLE_EXT_RE.test(cleaned)) out.push(cleaned);
  }
  return out;
}

/** 额外收紧：任何 .exe/.cmd/.ps1 等可执行文件 token，只有 python.exe / solidworksExe 能通过。 */
function checkExecutableTokens(parsed, config) {
  for (const token of parsed.tokens) {
    if (token.type !== 'word' && token.type !== 'string') continue;
    for (const candidate of executableCandidates(token.value)) {
      if (isAllowedExecutableToken(candidate, config)) continue;
      return {
        rule: 'pwsh.executable.not-allowed',
        detail: `命令中引用了未授权的可执行文件「${truncate(candidate, 120)}」`,
      };
    }
  }
  return null;
}

// PowerShell 里的 .NET 类型表达式（[Type]::Method）可以执行任意代码（例如
// [PowerShell]::Create().AddScript(...)、[AppDomain]、[Diagnostics.Process] 等），
// 契约 B1 只点名了少数危险前缀；这里额外收紧为「类型名必须在安全白名单内」。
const SAFE_TYPE_EXPRESSIONS = new Set([
  'math',
  'string',
  'int',
  'int16',
  'int32',
  'int64',
  'long',
  'uint',
  'uint16',
  'uint32',
  'uint64',
  'ulong',
  'double',
  'float',
  'single',
  'decimal',
  'bool',
  'boolean',
  'char',
  'byte',
  'sbyte',
  'array',
  'hashtable',
  'ordered',
  'regex',
  'pscustomobject',
  'void',
  'object',
  'datetime',
  'timespan',
  'version',
  'guid',
  'uri',
  'xml',
]);

function checkTypeExpressions(parsed) {
  for (const token of parsed.tokens) {
    if (token.type !== 'word' || !token.value.startsWith('[')) continue;
    const match = /^\[([A-Za-z_][A-Za-z0-9_.]*)/.exec(token.value);
    if (match === null) continue;
    const name = match[1].toLowerCase();
    if (SAFE_TYPE_EXPRESSIONS.has(name) || name.startsWith('math.')) continue;
    return {
      rule: 'pwsh.type-expression',
      detail: `命令包含未列入安全白名单的 .NET 类型表达式「[${match[1]}]」（可能用于反射/任意代码执行），转人工审批`,
    };
  }
  return null;
}

function checkCmdlets(parsed) {
  const found = parsed.masked.match(/\b[A-Z][A-Za-z]+-[A-Z][A-Za-z]+\b/g) ?? [];
  for (const cmdlet of found) {
    const lower = cmdlet.toLowerCase();
    if (CMDLET_WHITELIST.has(lower)) continue;
    if (lower === 'new-object' || lower === 'start-process') continue; // 由 B4 单独校验
    return {
      rule: 'pwsh.cmdlet.not-whitelisted',
      detail: `命令包含白名单之外的 PowerShell cmdlet「${cmdlet}」`,
    };
  }
  return null;
}

/**
 * 命令位置扫描：契约 B2 只约束 Xxx-Yyy cmdlet，裸命令（calc.exe / whoami / powershell）会漏。
 * 这里额外要求「语句起始位置」的裸词只能是白名单 keyword/别名/python 或已知安全可执行文件。
 */
function walkStatementCommands(tokens) {
  const problems = [];
  const commandIndices = new Set();
  const contextStack = [];
  const isTopHash = () => contextStack.length > 0 && contextStack[contextStack.length - 1] === 'hash';
  let expectCommand = true;
  // 区分「赋值右侧」与「语句起始」：$x = "C:\...\python.exe" 是值，不是命令调用；
  // 而 $x = python script.py 这类未加引号的 RHS 仍然是命令。
  let afterAssign = false;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    const cameFromAssign = afterAssign;
    switch (token.type) {
      case 'newline':
      case 'sep':
      case 'pipe':
        expectCommand = true;
        afterAssign = false;
        continue;
      case 'assign':
        // 哈希字面量（@{...}）里 '=' 后是表达式；其它位置 '=' 后的 RHS 可能是命令（$x = python ...）
        afterAssign = !isTopHash();
        expectCommand = afterAssign;
        continue;
      case 'block-open':
        contextStack.push('block');
        expectCommand = true;
        afterAssign = false;
        continue;
      case 'paren-open':
        contextStack.push('paren');
        expectCommand = true;
        afterAssign = false;
        continue;
      case 'block-close':
      case 'paren-close':
        if (contextStack.length > 0 && ['block', 'hash', 'paren'].includes(contextStack[contextStack.length - 1])) {
          contextStack.pop();
        }
        expectCommand = false;
        afterAssign = false;
        continue;
      case 'comma':
      case 'redirect':
        expectCommand = false;
        afterAssign = false;
        continue;
      case 'expr-start':
        if (token.value === '{') {
          contextStack.push('hash');
          expectCommand = false;
        } else {
          contextStack.push('paren');
          expectCommand = true;
        }
        afterAssign = false;
        continue;
      case 'amp': {
        const previous = tokens[i - 1];
        const isRedirect = previous !== undefined && (previous.type === 'redirect' || previous.type === 'amp');
        if (!isRedirect) {
          expectCommand = false;
          if (i + 1 < tokens.length) {
            commandIndices.add(i + 1);
            i += 1; // 跳过调用目标（由 B5 单独校验）
          }
          afterAssign = false;
          continue;
        }
        expectCommand = false;
        afterAssign = false;
        continue;
      }
      case 'op':
        afterAssign = false;
        // 语句起始位置的 '.' / '/' 是 dot-source 或相对路径调用（PowerShell 里可执行 .ps1/可执行文件），
        // 契约没有对应白名单，一律转人工审批。
        if (expectCommand && (token.value === '.' || token.value === '/')) {
          problems.push({
            rule: 'pwsh.dot-source',
            detail: `语句起始位置出现「${token.value}」，疑似 dot-source / 相对路径调用，转人工审批`,
          });
          expectCommand = false;
          continue;
        }
        expectCommand = token.value === '-' || token.value === '!' || token.value === '+';
        continue;
      case 'string':
        afterAssign = false;
        // 语句起始位置的 python.exe 字面量是命令调用；赋值 RHS 的字符串只是值
        if (expectCommand && !cameFromAssign && isPythonExecutable(token.value)) {
          commandIndices.add(i);
          expectCommand = false;
          continue;
        }
        expectCommand = false;
        continue;
      case 'var':
      case 'number':
      case 'subexpr':
        expectCommand = false;
        afterAssign = false;
        continue;
      case 'word':
      default: {
        if (!expectCommand) continue;
        if (token.parameter) {
          // 语句起始就出现参数（例如 if(-not ...) 内层）：按表达式处理
          expectCommand = false;
          continue;
        }
        const lower = token.value.toLowerCase();
        if (CMDLET_WHITELIST.has(lower) || COMMAND_KEYWORDS.has(lower) || SAFE_ALIASES.has(lower)) {
          commandIndices.add(i);
          expectCommand = false;
          continue;
        }
        if (lower === 'new-object' || lower === 'start-process' || lower === 'python' || lower === 'python.exe') {
          commandIndices.add(i);
          expectCommand = false;
          continue;
        }
        if (token.value.startsWith('[')) {
          // 类型/静态表达式（危险类型已由 B1 拒绝清单覆盖）
          expectCommand = false;
          continue;
        }
        // 哈希字面量的键（word 紧跟 '='）是表达式，不是命令
        if (isTopHash() && tokens[i + 1] !== undefined && tokens[i + 1].type === 'assign') {
          expectCommand = false;
          continue;
        }
        problems.push({
          rule: 'pwsh.unknown-command',
          detail: `语句起始位置出现未信任的裸命令「${truncate(token.value, 80)}」`,
        });
        expectCommand = false;
        continue;
      }
    }
  }
  return { problems, commandIndices };
}

function tokenAsValue(token) {
  if (token === undefined) return { ok: false, value: null };
  if (token.type === 'string') return { ok: true, value: token.value };
  if (token.type === 'word') return { ok: true, value: token.value };
  if (token.type === 'number') return { ok: true, value: token.value };
  if (token.type === 'var') return { ok: true, value: null }; // 需要调用方解析
  return { ok: false, value: null };
}

/** B4：Start-Process 目标必须是 SolidWorks 主程序（字面量或命令内 ${var}）。 */
function checkStartProcess(parsed, config) {
  const tokens = parsed.tokens;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token.type !== 'word' || token.value.toLowerCase() !== 'start-process') continue;
    let targetToken = null;
    let j = i + 1;
    while (j < tokens.length) {
      const current = tokens[j];
      if (
        current.type === 'newline' ||
        current.type === 'sep' ||
        current.type === 'pipe' ||
        current.type === 'block-close'
      ) {
        break;
      }
      if (current.type === 'word' && current.parameter) {
        if (current.value.toLowerCase() === '-filepath') {
          const next = tokens[j + 1];
          if (next !== undefined && ['string', 'word', 'var', 'number'].includes(next.type)) {
            targetToken = next;
            j += 2;
            continue;
          }
          j += 1;
          continue;
        }
        j += 1;
        if (tokens[j] !== undefined && ['string', 'word', 'var', 'number'].includes(tokens[j].type)) j += 1;
        continue;
      }
      if (targetToken === null && ['string', 'word', 'var', 'number'].includes(current.type)) {
        targetToken = current;
        j += 1;
        continue;
      }
      j += 1;
    }
    if (targetToken === null) {
      return {
        rule: 'pwsh.start-process.target-unknown',
        detail: 'Start-Process 未给出可解析的目标（-FilePath 或位置参数），转人工审批',
        swProcess: true,
      };
    }
    let value = null;
    if (targetToken.type === 'var') {
      const name = simpleVarName(targetToken.value);
      const assignment = resolveVarValue(name, targetToken.start, parsed.assignments);
      if (assignment !== null) value = expandVariables(assignment.value, assignment.index, parsed.assignments, 0);
    } else {
      value = tokenAsValue(targetToken).value;
    }
    if (value === null) {
      return {
        rule: 'pwsh.start-process.target-unknown',
        detail: 'Start-Process 的目标变量无法在命令内解析，转人工审批',
        swProcess: true,
      };
    }
    if (!isSolidworksExecutable(value, config)) {
      return {
        rule: 'pwsh.start-process.target',
        detail: `Start-Process 目标不是 SolidWorks 主程序：「${truncate(value, 120)}」`,
        swProcess: true,
      };
    }
  }
  return null;
}

/** B4：New-Object 只允许 `New-Object -ComObject SldWorks.Application`。 */
function checkNewObject(parsed) {
  const tokens = parsed.tokens;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token.type !== 'word' || token.value.toLowerCase() !== 'new-object') continue;
    const comToken = tokens[i + 1];
    const valueToken = tokens[i + 2];
    if (
      comToken === undefined ||
      comToken.type !== 'word' ||
      !comToken.parameter ||
      comToken.value.toLowerCase() !== '-comobject'
    ) {
      return {
        rule: 'pwsh.new-object',
        detail: 'New-Object 只允许 New-Object -ComObject SldWorks.Application 这一种形式',
      };
    }
    if (valueToken === undefined) {
      return { rule: 'pwsh.new-object', detail: 'New-Object -ComObject 缺少 COM 类型名' };
    }
    const value = valueToken.type === 'string' || valueToken.type === 'word' ? valueToken.value.trim() : '';
    if (!/^sldworks\.application$/i.test(value)) {
      return {
        rule: 'pwsh.new-object',
        detail: `New-Object -ComObject 的类型不是 SldWorks.Application（${truncate(value, 80)}）`,
      };
    }
    const after = tokens[i + 3];
    if (after !== undefined) {
      const boundary =
        after.type === 'newline' ||
        after.type === 'sep' ||
        after.type === 'pipe' ||
        after.type === 'block-close' ||
        after.type === 'paren-close' ||
        after.type === 'comma';
      if (!boundary) {
        return {
          rule: 'pwsh.new-object',
          detail: 'New-Object -ComObject SldWorks.Application 后带有契约未允许的额外参数',
        };
      }
    }
  }
  return null;
}

/** B5：& 调用目标必须是允许的 python.exe 或 solidworksExe（字面量或命令内 ${var}）。 */
function resolveCallTarget(parsed, targetToken) {
  if (targetToken === undefined) return { ok: false, value: null };
  if (targetToken.type === 'var') {
    const name = simpleVarName(targetToken.value);
    const assignment = resolveVarValue(name, targetToken.start, parsed.assignments);
    if (assignment === null) return { ok: false, value: null };
    const value = expandVariables(assignment.value, assignment.index, parsed.assignments, 0);
    if (value === null) return { ok: false, value: null };
    return { ok: true, value };
  }
  if (targetToken.type === 'string' || targetToken.type === 'word') {
    return { ok: true, value: targetToken.value };
  }
  return { ok: false, value: null };
}

function checkCallOperator(parsed, config) {
  const tokens = parsed.tokens;
  const kinds = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token.type !== 'amp') continue;
    const previous = tokens[i - 1];
    if (previous !== undefined && (previous.type === 'redirect' || previous.type === 'amp')) continue;
    const target = tokens[i + 1];
    if (target === undefined) {
      return {
        rule: 'pwsh.interpreter.missing',
        detail: '命令以 & 结尾但没有调用目标，转人工审批',
        kinds,
        python: false,
        solidworks: false,
      };
    }
    const resolved = resolveCallTarget(parsed, target);
    if (!resolved.ok || resolved.value === null) {
      return {
        rule: 'pwsh.interpreter.not-allowed',
        detail: '& 调用的目标变量无法在命令内解析，转人工审批',
        kinds,
        python: false,
        solidworks: false,
      };
    }
    const value = resolved.value;
    if (isPythonExecutable(value)) {
      kinds.push('python');
      continue;
    }
    if (isSolidworksExecutable(value, config)) {
      kinds.push('solidworks');
      continue;
    }
    return {
      rule: 'pwsh.interpreter.not-allowed',
      detail: `& 调用的目标不是允许的 python.exe/SolidWorks：「${truncate(value, 120)}」`,
      kinds,
      python: false,
      solidworks: false,
    };
  }
  return {
    kinds,
    python: kinds.includes('python'),
    solidworks: kinds.includes('solidworks'),
  };
}

/** 抽取命令（字符串 token / 裸词 token）中所有 .py 引用。 */
function extractPyRefs(parsed) {
  const refs = [];
  for (const token of parsed.tokens) {
    if (token.type === 'string') {
      if (!/\.py\b/i.test(token.value)) continue;
      const re = /[^\s"'`;|()<>{}]*\.py\b/gi;
      let match;
      while ((match = re.exec(token.value)) !== null) {
        refs.push({ text: match[0], index: token.start });
      }
    } else if (token.type === 'word' && /\.py$/i.test(token.value)) {
      refs.push({ text: token.value, index: token.start });
    }
  }
  return refs;
}

/** 提取函数调用第一个实参原文（跳过嵌套括号与字符串）；解析失败返回 null。 */
function firstCallArgument(text, openParenIndex) {
  let depth = 0;
  let i = openParenIndex;
  let quote = null;
  const start = openParenIndex + 1;
  while (i < text.length) {
    const ch = text[i];
    if (quote !== null) {
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      i += 1;
      continue;
    }
    if (ch === '(') {
      depth += 1;
      i += 1;
      continue;
    }
    if (ch === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(start, i);
      i += 1;
      continue;
    }
    if (ch === ',' && depth === 1) return text.slice(start, i);
    i += 1;
  }
  return null;
}

/** 取「纯字符串字面量」的值（支持 r/u/b 前缀；f-string / 变量 / 拼接 → null）。 */
function literalStringValue(text) {
  const trimmed = String(text ?? '').trim();
  const prefix = /^(?:[rRuUbB]{0,2})(['"])/u.exec(trimmed);
  if (prefix === null) return null;
  const quote = prefix[1];
  const start = prefix[0].length;
  if (trimmed.length <= start || trimmed[trimmed.length - 1] !== quote) return null;
  const body = trimmed.slice(start, trimmed.length - 1);
  if (body.includes('\\')) return null;
  if (body.includes(quote)) return null;
  return body;
}

const COM_CREATE_CALL_RE = /\b(?:EnsureDispatch|DispatchEx|Dispatch|GetObject|CoCreateInstance)\s*\(/gi;
const SLDWORKS_PROGID_RE = /^SldWorks\.Application(?:\.\d+)?$/i;

/**
 * v1.3：win32com/pythoncom 的 COM 创建调用只允许 ProgID 字面量
 * `SldWorks.Application`（可带版本后缀，如 SldWorks.Application.34）。
 * ProgID 是变量/拼接/f-string/其它 COM 对象 → ask。
 */
function checkComProgidCalls(content) {
  COM_CREATE_CALL_RE.lastIndex = 0;
  let match;
  while ((match = COM_CREATE_CALL_RE.exec(content)) !== null) {
    const openParenIndex = match.index + match[0].length - 1;
    const rawArg = firstCallArgument(content, openParenIndex);
    if (rawArg === null) {
      return {
        ok: false,
        rule: 'pwsh.script.com-progid',
        detail: `脚本中的 ${match[1]}( 调用无法解析参数，转人工审批`,
      };
    }
    const progId = literalStringValue(rawArg);
    if (progId === null) {
      return {
        ok: false,
        rule: 'pwsh.script.com-progid',
        detail: `脚本中 ${match[1]}( 的 ProgID 不是字符串字面量（变量/拼接/f-string 均不放行），转人工审批`,
      };
    }
    if (!SLDWORKS_PROGID_RE.test(progId)) {
      return {
        ok: false,
        rule: 'pwsh.script.com-progid',
        detail: `脚本中 ${match[1]}( 的 COM ProgID 不是 SldWorks.Application：「${truncate(progId, 120)}」，转人工审批`,
      };
    }
  }
  return null;
}

/** v1.3：脚本内容出现受信任路径字面量 → ask（防止改写/覆盖可信脚本或引用受信任路径）。 */
function checkTrustedPathLiterals(content) {
  const lower = content.toLowerCase();
  if (lower.includes('.agent-presets') || lower.includes('sw_bridge.py')) {
    return {
      ok: false,
      rule: 'pwsh.script.trusted-path',
      detail: '脚本内容引用了受信任路径字面量（.agent-presets / sw_bridge.py），转人工审批',
    };
  }
  if (/\.dsh[\\/]+profiles/i.test(content)) {
    return {
      ok: false,
      rule: 'pwsh.script.trusted-path',
      detail: '脚本内容引用了受信任路径字面量（.dsh\\profiles），转人工审批',
    };
  }
  return null;
}

/** v1.3 / v1.3.1：禁止可绕过静态检查的别名导入。 */
function checkImportAliases(content) {
  if (/\bimport\s+os\s+as\b/i.test(content)) {
    return {
      ok: false,
      rule: 'pwsh.script.import-alias',
      detail: '脚本使用 `import os as ...` 别名导入，无法静态确认安全，转人工审批',
    };
  }
  // v1.3.1（P1-b）：`from win32com.client import Dispatch as D` 可绕过 COM ProgID 白名单。
  // 覆盖单行/多名字/括号跨行形式。
  const comFromImportRe =
    /\bfrom\s+(?:win32com|pythoncom)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s+import\s*(?:\([^)]*\)|[^\r\n]*)/gi;
  let match;
  while ((match = comFromImportRe.exec(content)) !== null) {
    if (/\bas\b/i.test(match[0])) {
      return {
        ok: false,
        rule: 'pwsh.script.import-alias',
        detail: '脚本从 win32com/pythoncom 使用 `... import ... as ...` 别名导入（可绕过 COM ProgID 白名单），转人工审批',
      };
    }
  }
  return null;
}

/** B6：workspace 脚本静态扫描。 */
function scanWorkspaceScript(absPath, deps, config) {
  const statResult = safeDep(deps, 'stat', absPath);
  if (!statResult.ok || !isPlainObject(statResult.value)) {
    return { ok: false, rule: 'pwsh.script.stat', detail: `无法 stat 脚本文件：${truncate(absPath, 200)}` };
  }
  if (statResult.value.isFile !== true) {
    return { ok: false, rule: 'pwsh.script.stat', detail: `脚本路径不是普通文件：${truncate(absPath, 200)}` };
  }
  const size = Number(statResult.value.size);
  const maxScriptBytes =
    Number.isSafeInteger(config.maxScriptBytes) && config.maxScriptBytes > 0 ? config.maxScriptBytes : 524288;
  if (!Number.isFinite(size) || size < 0 || size > maxScriptBytes) {
    return {
      ok: false,
      rule: 'pwsh.script.size',
      detail: `脚本大小超过上限 ${maxScriptBytes} 字节：${truncate(absPath, 200)}`,
    };
  }
  const contentResult = safeDep(deps, 'readFile', absPath);
  if (!contentResult.ok || typeof contentResult.value !== 'string') {
    return { ok: false, rule: 'pwsh.script.read', detail: `无法读取脚本内容：${truncate(absPath, 200)}` };
  }
  const content = contentResult.value;
  if (content.includes('\0')) {
    return { ok: false, rule: 'pwsh.script.binary', detail: `脚本文本含 NUL 字节，疑似二进制伪装：${truncate(absPath, 200)}` };
  }
  if (!SCRIPT_SW_ANCHOR_RE.test(content)) {
    return { ok: false, rule: 'pwsh.script.anchor', detail: '脚本内没有任何 SolidWorks 锚点，转人工审批' };
  }
  const importRe = /\b(?:from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import|import\s+([A-Za-z_][A-Za-z0-9_.]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_.]*)*))/g;
  let match;
  while ((match = importRe.exec(content)) !== null) {
    const modules = match[1] !== undefined ? [match[1]] : (match[2] ?? '').split(',');
    for (const rawModule of modules) {
      const module = rawModule.trim();
      if (module === '') continue;
      const root = module.split('.')[0].toLowerCase();
      if (!SCRIPT_IMPORT_ROOTS.has(root)) {
        return { ok: false, rule: 'pwsh.script.import', detail: `脚本 import 了白名单之外的模块「${module}」，转人工审批` };
      }
    }
  }
  const aliasFail = checkImportAliases(content);
  if (aliasFail !== null) return aliasFail;
  const trustedPathFail = checkTrustedPathLiterals(content);
  if (trustedPathFail !== null) return trustedPathFail;
  const comFail = checkComProgidCalls(content);
  if (comFail !== null) return comFail;
  const lower = content.toLowerCase();
  for (const denyToken of SCRIPT_DENY_TOKENS) {
    if (lower.includes(denyToken)) {
      return { ok: false, rule: 'pwsh.script.deny-token', detail: `脚本包含被禁止的 token「${denyToken}」，转人工审批` };
    }
  }
  return { ok: true, kind: 'workspace', detail: 'workspace 脚本静态扫描通过' };
}

/**
 * B5：.py 引用分类。每个引用必须满足：
 *   - 在 engineeringToolsDir 下且 basename ∈ authorizedScripts → 受信任；
 *   - 在会话 cwd 下且 basename ∈ workspaceScriptNames → B6 静态扫描通过才放行；
 *   - 其它 → ask。
 */
function classifyPyRefs(parsed, input, deps, config, options) {
  const result = {
    ok: true,
    refs: [],
    trusted: false,
    workspace: false,
  };
  // v1.1：只有命令真的调用了 python（脚本执行语境）时，.py 引用才有意义。
  // 否则形如 `Write-Output "sw_bridge.py"` 的纯输出文本会被误当成脚本引用，
  // 在 workspaceScriptNames 默认 [] 后更会被误扫描放行。
  if (options === undefined || options.pythonUsed !== true) return result;
  const authorized = new Set(
    (Array.isArray(config.authorizedScripts) ? config.authorizedScripts : []).map((item) => item.toLowerCase()),
  );
  const workspaceNames = new Set(
    (Array.isArray(config.workspaceScriptNames) ? config.workspaceScriptNames : []).map((item) => item.toLowerCase()),
  );
  const toolsDir = typeof config.engineeringToolsDir === 'string' ? config.engineeringToolsDir : null;
  const cwd = typeof input.cwd === 'string' ? canonWinPath(input.cwd) : null;
  for (const ref of extractPyRefs(parsed)) {
    const expanded = expandVariables(ref.text, ref.index, parsed.assignments, 0);
    if (expanded === null) {
      return {
        ...result,
        ok: false,
        rule: 'pwsh.script.var-unresolved',
        detail: `脚本引用中的变量无法展开：「${truncate(ref.text, 120)}」`,
      };
    }
    let raw = expanded.trim();
    if (raw === '' || raw.includes('\0')) {
      return {
        ...result,
        ok: false,
        rule: 'pwsh.script.path-invalid',
        detail: `脚本引用展开后为空或含 NUL：「${truncate(ref.text, 120)}」`,
      };
    }
    const absPath = resolveUserPath(raw, input.cwd);
    if (absPath === null) {
      return {
        ...result,
        ok: false,
        rule: 'pwsh.script.path-invalid',
        detail: `脚本引用不是可解析的绝对 Windows 路径：「${truncate(raw, 160)}」`,
      };
    }
    const base = (baseNameWin(absPath) ?? '').toLowerCase();
    if (toolsDir !== null && isWithinWin(absPath, toolsDir) && authorized.has(base)) {
      // v1.3 受信任脚本哈希钉住：打断「B6 扫描放行写脚本 → 覆盖工程 tools 下受信任脚本 → 免扫描执行」的持久化提权链。
      const hashes = isPlainObject(config.trustedScriptHashes) ? config.trustedScriptHashes : {};
      const expectedHash = typeof hashes[base] === 'string' ? hashes[base].trim().toLowerCase() : null;
      const pinningEnabled = config.hashPinningEnabled === true;
      const hashFileAvailable = typeof deps?.hashFile === 'function';
      // v1.3.1（fail-closed）：开启哈希钉住后，缺条目 / 胶水没注入 hashFile 都不允许回退信任。
      if (pinningEnabled && expectedHash === null) {
        return {
          ...result,
          ok: false,
          rule: 'pwsh.script.hash-unavailable',
          detail: `hashPinningEnabled=true 但受信任脚本缺少哈希条目，转人工审批：${truncate(absPath, 200)}`,
        };
      }
      if (pinningEnabled && !hashFileAvailable) {
        return {
          ...result,
          ok: false,
          rule: 'pwsh.script.hash-unavailable',
          detail: `hashPinningEnabled=true 但 deps 未提供 hashFile，无法校验受信任脚本，转人工审批：${truncate(absPath, 200)}`,
        };
      }
      if (expectedHash !== null && hashFileAvailable) {
        const hashResult = safeDep(deps, 'hashFile', absPath);
        if (!hashResult.ok || typeof hashResult.value !== 'string') {
          return {
            ...result,
            ok: false,
            rule: 'pwsh.script.hash-unavailable',
            detail: `受信任脚本哈希读取失败，转人工审批：${truncate(absPath, 200)}`,
          };
        }
        const actualHash = hashResult.value.trim().toLowerCase();
        if (actualHash !== expectedHash) {
          return {
            ...result,
            ok: false,
            rule: 'pwsh.script.hash-mismatch',
            detail: `受信任脚本哈希不匹配（可能已被覆盖），转人工审批：${truncate(absPath, 200)}`,
          };
        }
      }
      // hashPinningEnabled=false 时保持旧回退行为（便于 policy 纯函数单测 / 未升级的胶水）。
      result.trusted = true;
      result.refs.push({ path: absPath, kind: 'trusted' });
      continue;
    }
    // v1.1：workspaceScriptNames 为空数组 = cwd 下任意 .py 均可进入 B6 静态扫描；
    // 非空数组 = 只允许名单内文件名（保留用户收紧能力）。
    const workspaceNameAllowed = workspaceNames.size === 0 || workspaceNames.has(base);
    if (cwd !== null && isWithinWin(absPath, cwd) && workspaceNameAllowed) {
      if (config.scanWorkspaceScripts === false) {
        result.workspace = true;
        result.refs.push({ path: absPath, kind: 'workspace-unscanned' });
        continue;
      }
      const scanned = scanWorkspaceScript(absPath, deps, config);
      if (!scanned.ok) {
        return { ...result, ok: false, rule: scanned.rule, detail: scanned.detail };
      }
      result.workspace = true;
      result.refs.push({ path: absPath, kind: 'workspace' });
      continue;
    }
    return {
      ...result,
      ok: false,
      rule: 'pwsh.script.untrusted',
      detail: `脚本不在受信任范围内（必须是工程 preset tools 下的授权脚本，或会话 cwd 下经 B6 扫描的脚本）：「${truncate(raw, 200)}」`,
    };
  }
  return result;
}

/** 从 tokens[start] 起（到语句边界为止）找 .py 脚本参数；找到返回 true。 */
function hasScriptArgumentAfter(tokens, start) {
  for (let j = start; j < tokens.length; j += 1) {
    const token = tokens[j];
    if (
      token.type === 'newline' ||
      token.type === 'sep' ||
      token.type === 'pipe' ||
      token.type === 'block-close' ||
      token.type === 'paren-close'
    ) {
      return false;
    }
    if (token.type === 'string' && /\.py\b/i.test(token.value)) return true;
    if (token.type === 'word' && /\.py$/i.test(token.value)) return true;
  }
  return false;
}

/** python 参数里出现了独立的「-」→ 从 stdin 读取脚本执行（等价于任意代码）。 */
function hasStdinDashAfter(tokens, start) {
  for (let j = start; j < tokens.length; j += 1) {
    const token = tokens[j];
    if (
      token.type === 'newline' ||
      token.type === 'sep' ||
      token.type === 'pipe' ||
      token.type === 'block-close' ||
      token.type === 'paren-close'
    ) {
      return false;
    }
    if (token.type === 'op' && token.value === '-') {
      const next = tokens[j + 1];
      const isLongOptionTail =
        next !== undefined &&
        next.type === 'word' &&
        next.parameter === true &&
        String(next.value).startsWith('-');
      if (!isLongOptionTail) return true;
    }
  }
  return false;
}

/**
 * 找出命令里所有 python 调用（命令位置 / & 目标 / python.exe 字面量），并要求
 * 每一次调用都显式绑定 .py 脚本参数（禁止交互式/管道 stdin 执行）。
 */
function collectPythonInvocations(parsed, callInfo) {
  const invocations = [];
  const { commandIndices } = walkStatementCommands(parsed.tokens);
  for (const index of commandIndices) {
    const token = parsed.tokens[index];
    if (token === undefined) continue;
    if (token.type === 'word' && (token.value.toLowerCase() === 'python' || token.value.toLowerCase() === 'python.exe')) {
      invocations.push({
        index,
        hasScript: hasScriptArgumentAfter(parsed.tokens, index + 1),
        stdin: hasStdinDashAfter(parsed.tokens, index + 1),
      });
      continue;
    }
    if (token.type === 'string' && isPythonExecutable(token.value)) {
      invocations.push({
        index,
        hasScript: hasScriptArgumentAfter(parsed.tokens, index + 1),
        stdin: hasStdinDashAfter(parsed.tokens, index + 1),
      });
    }
  }
  for (let i = 0; i < parsed.tokens.length; i += 1) {
    const token = parsed.tokens[i];
    if (token.type !== 'amp') continue;
    const previous = parsed.tokens[i - 1];
    if (previous !== undefined && (previous.type === 'redirect' || previous.type === 'amp')) continue;
    const target = parsed.tokens[i + 1];
    if (target === undefined) continue;
    const resolved = resolveCallTarget(parsed, target);
    if (!resolved.ok || resolved.value === null || !isPythonExecutable(resolved.value)) continue;
    invocations.push({
      index: i + 1,
      hasScript: hasScriptArgumentAfter(parsed.tokens, i + 2),
      stdin: hasStdinDashAfter(parsed.tokens, i + 2),
    });
  }
  return invocations;
}

/** 检查 python 调用的内联代码参数（-c / -m）。 */
function checkInlinePythonFlags(parsed, pythonUsed) {
  if (!pythonUsed) return null;
  for (const token of parsed.tokens) {
    if (token.type === 'word' && token.parameter) {
      const lower = token.value.toLowerCase();
      if (lower === '-c' || lower === '-m' || lower === '-command' || lower === '-encodedcommand') {
        return {
          rule: 'pwsh.inline-python',
          detail: `python 调用附带内联/模块执行参数「${token.value}」，v1 不自动放行`,
        };
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// pwsh 判定
// ---------------------------------------------------------------------------

/**
 * 一条命令的完整静态分析（顶层与 $() 子表达式复用）。
 * 返回 null（通过）或 { fail }。
 */
function analyzeCommand(parsed, input, deps, config, options) {
  const depth = options.depth ?? 0;
  // 解析层结构（未闭合字符串/反引号混淆/here-string）
  if (parsed.unterminated.length > 0) {
    return { fail: { rule: 'pwsh.parse-error', detail: '命令包含未闭合的字符串或子表达式，无法安全解析' } };
  }
  if (parsed.hereStrings.length > 0) {
    return { fail: { rule: 'pwsh.inline-code', detail: '命令包含 here-string 内联代码块，v1 不自动放行' } };
  }
  if (parsed.backticks.length > 0) {
    return { fail: { rule: 'pwsh.escape-sequence', detail: '命令在字符串之外使用反引号转义，疑似混淆，转人工审批' } };
  }

  // B1 拒绝清单
  const deny = matchDenyRule(parsed.clean);
  if (deny !== null) {
    return {
      fail: { rule: `pwsh.deny.${deny.id}`, detail: `命中危险命令拒绝清单（${deny.id}），转人工审批` },
    };
  }

  // 额外收紧：未授权可执行文件
  const executableFail = checkExecutableTokens(parsed, config);
  if (executableFail !== null) return { fail: executableFail };

  // 额外收紧：.NET 类型表达式（反射/任意代码执行通道）
  const typeExpressionFail = checkTypeExpressions(parsed);
  if (typeExpressionFail !== null) return { fail: typeExpressionFail };

  // B2 白名单 cmdlet
  const cmdletFail = checkCmdlets(parsed);
  if (cmdletFail !== null) return { fail: cmdletFail };

  // 额外收紧：语句起始位置的裸命令
  const walk = walkStatementCommands(parsed.tokens);
  if (walk.problems.length > 0) return { fail: walk.problems[0] };

  // B4 Start-Process / New-Object
  const startProcessFail = checkStartProcess(parsed, config);
  if (startProcessFail !== null) return { fail: startProcessFail };
  const newObjectFail = checkNewObject(parsed);
  if (newObjectFail !== null) return { fail: newObjectFail };

  // B5 & 调用目标
  const callInfo = checkCallOperator(parsed, config);
  if (callInfo.rule !== undefined) return { fail: callInfo };

  // B5 python 调用 / 内联代码 / 每次调用必须绑定 .py 脚本参数
  const pythonInvocations = collectPythonInvocations(parsed, callInfo);
  const pythonUsed = pythonInvocations.length > 0;
  const inlineFail = checkInlinePythonFlags(parsed, pythonUsed);
  if (inlineFail !== null) return { fail: inlineFail };
  if (pythonInvocations.some((invocation) => invocation.stdin === true)) {
    return {
      fail: {
        rule: 'pwsh.inline-python',
        detail: 'python 以「-」从 stdin 读取代码执行，v1 不自动放行',
      },
    };
  }
  if (pythonInvocations.some((invocation) => invocation.hasScript !== true)) {
    return {
      fail: {
        rule: 'pwsh.python.script-required',
        detail: 'python 调用没有绑定 .py 脚本参数（禁止交互式/管道 stdin 执行），v1 不自动放行',
      },
    };
  }

  // B5 .py 引用（仅在脚本执行语境下分类）
  const scriptInfo = classifyPyRefs(parsed, input, deps, config, { pythonUsed });
  if (scriptInfo.ok !== true) return { fail: scriptInfo };
  if (pythonUsed && scriptInfo.refs.length === 0) {
    return {
      fail: {
        rule: 'pwsh.python.script-required',
        detail: 'python 调用没有绑定任何受信任脚本，v1 不自动放行',
      },
    };
  }

  // B3 SolidWorks 锚点（v1.1 收紧 / v1.3 再收紧，仅顶层要求）。
  // 锚点必须是「可操作证据」，纯输出字符串/注释里的 SldWorks/SolidWorks/SLDWORKS 不算：
  //   1) 受信任/已 B6 扫描脚本引用；
  //   2) 经验证的 Start-Process / New-Object（B4 已通过）；
  //   3) & 调用字面 SolidWorks 主程序；
  //   4) 对 SLDWORKS.exe 路径的只读探测（Test-Path/Get-Item 等 cmdlet 的实参）；
  //   5) Get-Process ... SLDWORKS 这类真实进程查询（含管道 Where-Object 过滤）；
  //   6) DSH_SW_EXE 环境赋值 + python 脚本调用。
  const hasSwProcessInvocation = [...walk.commandIndices].some((index) => {
    const token = parsed.tokens[index];
    return (
      token !== undefined &&
      token.type === 'word' &&
      (token.value.toLowerCase() === 'start-process' || token.value.toLowerCase() === 'new-object')
    );
  });
  const hasSwExeProbe = hasSolidworksExeProbe(parsed, config);
  const hasGetProcessEvidence = hasGetProcessWithSldworks(parsed);
  const hasDshSwExeEvidence = pythonUsed && /\bDSH_SW_EXE\b/i.test(parsed.clean);
  const swProcessTokenSeen = hasSwProcessInvocation || callInfo.solidworks === true;
  const operationalSwEvidence =
    swProcessTokenSeen ||
    hasSwExeProbe ||
    scriptInfo.trusted ||
    scriptInfo.workspace ||
    hasGetProcessEvidence ||
    hasDshSwExeEvidence;
  if (options.requireAnchor === true && !operationalSwEvidence) {
    return {
      fail: {
        rule: 'pwsh.anchor',
        detail:
          '命令没有可操作的 SolidWorks 证据（授权/扫描脚本、Start-Process/New-Object、SLDWORKS.exe 只读探测、Get-Process SLDWORKS、DSH_SW_EXE+python）；纯输出文本/注释不算锚点，转人工审批',
      },
    };
  }

  // $() 子表达式二级校验（防止在字符串/表达式里夹带命令）
  if (depth < 4) {
    for (const sub of parsed.subexpressions) {
      const subParsed = parseCommand(sub.inner);
      const nested = analyzeCommand(subParsed, input, deps, config, { depth: depth + 1, requireAnchor: false });
      if (nested.ok !== true) {
        return {
          fail: {
            rule: 'pwsh.subexpression',
            detail: `$() 子表达式内含不允许的内容：${nested.fail.detail}`,
          },
        };
      }
    }
  }

  return {
    ok: true,
    flags: {
      trustedScript: scriptInfo.trusted,
      workspaceScript: scriptInfo.workspace,
      pythonUsed,
      swProcess: swProcessTokenSeen,
    },
  };
}

function evaluatePwsh(input, deps, config) {
  const args = isPlainObject(input.args) ? input.args : {};
  const command = args.command;
  if (typeof command !== 'string' || command.trim() === '') {
    return askResult('pwsh.command-missing', 'pwsh 调用缺少 args.command 字符串，转人工审批');
  }
  if (command.includes('\0')) {
    return askResult('pwsh.command-nul', '命令包含 NUL 字节，转人工审批', command);
  }
  const maxCommandChars =
    Number.isSafeInteger(config.maxCommandChars) && config.maxCommandChars > 0 ? config.maxCommandChars : 120000;
  if (command.length > maxCommandChars) {
    return askResult(
      'pwsh.command-too-long',
      `命令长度 ${command.length} 超过上限 ${maxCommandChars}，转人工审批`,
      command,
    );
  }

  const parsed = parseCommand(command);
  const analyzed = analyzeCommand(parsed, input, deps, config, { depth: 0, requireAnchor: true });
  if (analyzed.ok !== true) {
    return askResult(analyzed.fail.rule, analyzed.fail.detail, command);
  }

  const flags = analyzed.flags;
  let rule = 'pwsh.sw-command';
  let detail = '命令命中 SolidWorks 白名单规则，允许一次性自动放行';
  if (flags.trustedScript) {
    rule = 'pwsh.sw-bridge.trusted';
    detail = '调用工程 preset tools 下的授权 SolidWorks 脚本，允许一次性自动放行';
  } else if (flags.workspaceScript) {
    rule = 'pwsh.workspace-script.scanned';
    detail = '调用 workspace 白名单脚本且静态扫描通过，允许一次性自动放行';
  } else if (flags.swProcess) {
    rule = 'pwsh.solidworks-process';
    detail = '仅启动/连接 SolidWorks 进程或读取其状态的只读命令，允许一次性自动放行';
  }
  return allowResult(rule, detail, command, {
    policyVersion: POLICY_VERSION,
    preset: input.preset,
    pythonUsed: flags.pythonUsed,
  });
}

// ---------------------------------------------------------------------------
// write / edit 判定
// ---------------------------------------------------------------------------

function existsViaDeps(pathValue, deps) {
  const result = safeDep(deps, 'exists', pathValue);
  if (!result.ok) return null; // 依赖异常 → 保守拒绝
  return result.value === true;
}

/**
 * symlink 逃逸防护：取「最近存在的父目录」的 realpath，再把不存在的尾部拼回去。
 * 任何依赖异常/解析失败 → null（调用方转 ask）。
 */
function resolveRealTarget(targetCanon, deps) {
  let current = targetCanon;
  const missing = [];
  for (let guard = 0; guard < 64; guard += 1) {
    const exists = existsViaDeps(current, deps);
    if (exists === null) return null;
    if (exists) {
      const real = safeDep(deps, 'realpath', current);
      if (!real.ok || typeof real.value !== 'string') return null;
      const canonReal = canonWinPath(real.value);
      if (canonReal === null) return null;
      if (missing.length === 0) return canonReal;
      return canonWinPath(`${canonReal}\\${missing.join('\\')}`);
    }
    const base = baseNameWin(current);
    const parent = parentWinPath(current);
    if (base === null || parent === null || parent === current) return null;
    missing.unshift(base);
    current = parent;
  }
  return null;
}

function evaluateFs(input, deps, config) {
  const args = isPlainObject(input.args) ? input.args : {};
  const filePath = args.file_path;
  if (typeof filePath !== 'string' || filePath.trim() === '') {
    return askResult(`${input.toolName}.path-missing`, `${input.toolName} 调用缺少 args.file_path，转人工审批`);
  }
  if (filePath.includes('\0')) {
    return askResult('fs.path-nul', '目标路径包含 NUL 字节，转人工审批', filePath);
  }
  const cwd = typeof input.cwd === 'string' ? canonWinPath(input.cwd) : null;
  const resolved = resolveUserPath(filePath, input.cwd);
  if (resolved === null) {
    return askResult('fs.path-invalid', `无法把目标解析为绝对 Windows 路径：「${truncate(filePath, 200)}」`, filePath);
  }

  const roots = [];
  const pushRoot = (value) => {
    const canon = typeof value === 'string' ? canonWinPath(value) : null;
    if (canon !== null && !roots.includes(canon)) roots.push(canon);
  };
  pushRoot(cwd);
  // v1.1【提权链修复】：允许根不包含 engineeringRoot。否则模型可以先用 write 工具
  // 自动放行覆盖 engineering\tools\sw_bridge.py（受信任脚本），再自动放行执行它 →
  // 任意代码 full access。engineeringRoot 只用于「读取/信任」判定，不再作为写入根。
  for (const extra of Array.isArray(config.extraWriteRoots) ? config.extraWriteRoots : []) pushRoot(extra);
  if (roots.length === 0) {
    return askResult('fs.no-roots', '没有可用的写入允许根，转人工审批', filePath);
  }
  if (!roots.some((root) => isWithinWin(resolved, root))) {
    return askResult(
      'fs.outside-allowed-root',
      `目标路径不在允许根内（cwd/engineeringRoot/extraWriteRoots），转人工审批：「${truncate(resolved, 240)}」`,
      filePath,
    );
  }

  // realpath 防 symlink 逃逸：最近存在父目录 + 尾部拼接后仍必须落在允许根的 realpath 内
  const realTarget = resolveRealTarget(resolved, deps);
  if (realTarget === null) {
    return askResult('fs.realpath-unavailable', '无法解析目标路径的 realpath（或路径不存在），转人工审批', filePath);
  }
  let realRoots = [];
  for (const root of roots) {
    const exists = existsViaDeps(root, deps);
    if (exists === null) {
      return askResult('fs.realpath-unavailable', '无法确认允许根是否存在，转人工审批', filePath);
    }
    if (!exists) {
      realRoots.push(root);
      continue;
    }
    const real = safeDep(deps, 'realpath', root);
    if (!real.ok || typeof real.value !== 'string') {
      return askResult('fs.realpath-unavailable', '无法解析允许根的 realpath，转人工审批', filePath);
    }
    const canonReal = canonWinPath(real.value);
    if (canonReal === null) {
      return askResult('fs.realpath-unavailable', '允许根 realpath 不是绝对 Windows 路径，转人工审批', filePath);
    }
    realRoots.push(canonReal);
  }
  realRoots = Array.from(new Set(realRoots));
  if (!realRoots.some((root) => isWithinWin(realTarget, root))) {
    return askResult(
      'fs.symlink-escape',
      `目标的 realpath 不在允许根的 realpath 内（疑似 symlink 逃逸），转人工审批：「${truncate(realTarget, 240)}」`,
      filePath,
    );
  }

  return allowResult(
    'fs.within-allowed-root',
    `${input.toolName} 目标在允许根内（含 realpath 校验），允许一次性自动放行`,
    filePath,
    { policyVersion: POLICY_VERSION, preset: input.preset },
  );
}

// ---------------------------------------------------------------------------
// 对外入口
// ---------------------------------------------------------------------------

/**
 * 判定一次提权审批请求。
 * @param {object} input { toolName, args, preset, cwd, sessionId }
 * @param {object} deps  { readFile, stat, exists, realpath }
 * @param {object} config 已由 normalizeConfig 归一化的配置
 * @returns {{decision:'allow'|'ask', rule:string, detail:string, summary:string, checks?:object}}
 */
export function evaluateApproval(input, deps, config) {
  try {
    return evaluateApprovalInner(input, deps, config);
  } catch (error) {
    return askResult('internal-error', `判定引擎内部异常，已兜底转人工审批：${truncate(String(error), 200)}`);
  }
}

function evaluateApprovalInner(input, deps, config) {
  if (!isPlainObject(input)) {
    return askResult('common.input-invalid', '审批请求 input 不是对象，转人工审批');
  }
  const cfg = isPlainObject(config) ? config : {};
  const args = isPlainObject(input.args) ? input.args : {};

  // A1 启用开关
  if (cfg.enabled !== true) {
    return askResult('common.disabled', '插件配置 enabled !== true，转人工审批');
  }
  // A2 会话 preset
  const preset = typeof input.preset === 'string' ? input.preset : null;
  if (preset === null || !Array.isArray(cfg.presets) || !cfg.presets.includes(preset)) {
    return askResult('common.preset', `会话 preset（${preset ?? '未知'}）不在生效 preset 列表内，转人工审批`);
  }
  // A3 callId/会话日志关联由胶水负责（policy 拿不到会话日志），这里只校验其已解析结果的存在性约定。
  // A4 只处理 danger-full-access 档
  if (args.sandbox_permissions !== 'danger-full-access') {
    return askResult(
      'common.escalation',
      `只自动放行 danger-full-access 提权，当前为「${truncate(String(args.sandbox_permissions ?? '未提供'), 80)}」，转人工审批`,
    );
  }

  const toolName = typeof input.toolName === 'string' ? input.toolName : '';
  if (toolName === 'pwsh') return evaluatePwsh(input, deps, cfg);
  if (toolName === 'write' || toolName === 'edit') return evaluateFs(input, deps, cfg);
  return askResult('common.tool-not-auto-approvable', `工具「${truncate(toolName, 80)}」不在自动放行范围，转人工审批`);
}
