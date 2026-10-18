// dsh-sw-approval — Host 半（v0.1.0）
//
// 设计目标（安全第一）：
//   1. 只在 engineering（工程模式）会话里生效；其它会话完全不动。
//   2. 只在 approval/request waterfall 上、且请求来自「严格匹配白名单的 SW 命令」时
//      返回 'allowed-once'；其它一切情况调用 next()，交还正常人工审批。
//   3. 判定依据是会话日志里真实的 tool/call 参数（不是模型写的 justification）。
//   4. 任何异常、缺字段、找不到调用、解析失败 → next()（fail-closed）。
//   5. 每会话/每回合有放行上限；/swapproval off 可随时在本会话紧急关闭。
//   6. 每次自动放行写本地审计日志（默认 %USERPROFILE%\.dsh\sw-approval\audit.jsonl）。
//
// 判定规则本体在 lib/policy.js（纯函数、可单测）；本文件只做 DSH 胶水。

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { evaluateApproval, normalizeConfig, POLICY_VERSION } from './lib/policy.js';

export const name = 'sw-approval';

export const PLUGIN_VERSION = '0.1.3';

/** 审计/状态文件所属插件版本；/swapproval status 会显示。 */
const MAX_COMMAND_PREVIEW = 400;

/** 读取会话自有事件（插件只依赖公开的 Session 方法；失败按空数组处理）。 */
function sessionEvents(session) {
  try {
    if (typeof session?.ownEvents !== 'function') return [];
    const events = session.ownEvents();
    return Array.isArray(events) ? events : [];
  } catch {
    return [];
  }
}

/** 在会话事件里倒序找 callId 对应的 tool/call。 */
function findToolCall(events, callId) {
  const wanted = String(callId);
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event?.type !== 'tool/call') continue;
    if (String(event.data?.callId) === wanted) return event;
  }
  return undefined;
}

/** 解析会话当前 preset：倒序找 agent-preset/selected，回落 session.header.agentPreset。 */
function resolvePreset(session, events) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event?.type !== 'agent-preset/selected') continue;
    const preset = event.data?.agentPreset;
    if (typeof preset === 'string' && preset.length > 0) return preset;
  }
  const headerPreset = session?.header?.agentPreset;
  return typeof headerPreset === 'string' && headerPreset.length > 0 ? headerPreset : null;
}

/** 解析当前 turn 序号（用于每回合预算）。 */
function resolveTurn(events) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event?.type !== 'turn/start') continue;
    const turn = Number(event.data?.turn);
    return Number.isSafeInteger(turn) && turn >= 0 ? turn : 0;
  }
  return 0;
}

/** tool/call 的 arguments 是 JSON 字符串；解析失败返回 undefined（判 ask）。 */
function parseCallArguments(call) {
  const raw = call?.data?.arguments;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }
  if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  return undefined;
}

function previewOf(text) {
  const value = typeof text === 'string' ? text : '';
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > MAX_COMMAND_PREVIEW ? `${flat.slice(0, MAX_COMMAND_PREVIEW)}…` : flat;
}

/**
 * 给受信任的 engineering 脚本做 SHA-256 钉住。
 *
 * 若模型（或其它进程）把 `engineering\tools\sw_bridge.py` 等授权脚本改写了，
 * 哈希会失配 → 政策引擎对该脚本的提权一律转人工审批，打断
 * 「写脚本→扫描放行→覆盖可信脚本→下次免扫描执行」的持久化提权链。
 * 用户正常更新工程预设后输入 `/swapproval rehash` 或重启 DSH 即可重新学习。
 */
function computeTrustedScriptHashes(config) {
  const hashes = {};
  const dir = config.engineeringToolsDir;
  if (typeof dir !== 'string' || dir.length === 0) return hashes;
  for (const name of config.authorizedScripts ?? []) {
    try {
      const file = path.join(dir, name);
      const stat = fs.statSync(file);
      if (!stat.isFile()) continue;
      hashes[name] = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    } catch {
      /* 缺失/不可读 → 不钉住；政策引擎会在需要时按 fail-closed 处理 */
    }
  }
  return hashes;
}

/** 本地审计：插件自有状态目录；写失败只告警，绝不影响审批主流程。 */
function createAudit(config, ctx) {
  const enabled = typeof config.auditDir === 'string' && config.auditDir.length > 0;
  const auditPath = enabled ? path.join(config.auditDir, 'audit.jsonl') : null;
  const statusPath = enabled ? path.join(config.auditDir, 'status.json') : null;
  let ready = false;
  const warn = (message) => {
    try {
      ctx?.logger?.warn?.(`sw-approval: ${message}`);
    } catch {
      /* logging must never break approvals */
    }
  };
  const ensure = () => {
    if (!enabled) return false;
    if (ready) return true;
    try {
      fs.mkdirSync(config.auditDir, { recursive: true });
      ready = true;
      return true;
    } catch (error) {
      warn(`cannot create audit dir ${config.auditDir}: ${String(error)}`);
      return false;
    }
  };
  const record = (entry) => {
    if (!ensure() || auditPath === null) return;
    try {
      fs.appendFileSync(auditPath, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, 'utf8');
    } catch (error) {
      warn(`cannot append audit: ${String(error)}`);
    }
  };
  const writeStatus = (extra) => {
    if (!ensure() || statusPath === null) return;
    try {
      fs.writeFileSync(
        statusPath,
        `${JSON.stringify({ ts: new Date().toISOString(), plugin: 'dsh-sw-approval', version: PLUGIN_VERSION, policyVersion: POLICY_VERSION, pid: process.pid, ...extra }, null, 2)}\n`,
        'utf8',
      );
    } catch (error) {
      warn(`cannot write status: ${String(error)}`);
    }
  };
  return { record, writeStatus, auditPath, enabled };
}

export function apply(ctx, rawConfig = {}) {
  let config;
  try {
    config = normalizeConfig(rawConfig ?? {}, { homedir: os.homedir(), platform: process.platform });
  } catch (error) {
    try {
      ctx?.logger?.warn?.(`sw-approval: invalid config, plugin stays inactive: ${String(error)}`);
    } catch {
      /* ignore */
    }
    return;
  }
  if (config.enabled !== true) {
    try {
      ctx?.logger?.info?.('sw-approval: disabled by config');
    } catch {
      /* ignore */
    }
    return;
  }

  // 受信任 engineering 脚本的哈希钉住（写后重算由 /swapproval rehash 触发）。
  // hashPinningEnabled=true 让政策引擎在「授权脚本缺哈希条目」时也转人工审批，
  // 避免工程目录整体失联时静默回退到「按路径信任」。
  config = { ...config, trustedScriptHashes: computeTrustedScriptHashes(config), hashPinningEnabled: true };
  const trustedScriptCount = Object.keys(config.trustedScriptHashes).length;

  const audit = createAudit(config, ctx);
  audit.writeStatus({
    phase: 'start',
    presets: config.presets,
    engineeringRoot: config.engineeringRoot,
    solidworksExe: config.solidworksExe,
    trustedScripts: trustedScriptCount,
    auditPath: audit.auditPath,
    maxAutoApprovalsPerSession: config.maxAutoApprovalsPerSession,
    maxAutoApprovalsPerTurn: config.maxAutoApprovalsPerTurn,
  });
  audit.record({ type: 'plugin-start', presets: config.presets, engineeringRoot: config.engineeringRoot, trustedScripts: trustedScriptCount });
  try {
    ctx?.logger?.info?.(`sw-approval: active (presets=${config.presets.join(',') || '(none)'}, engineeringRoot=${config.engineeringRoot}, trustedScripts=${trustedScriptCount})`);
  } catch {
    /* ignore */
  }

  /** 只读 fs 能力注入给纯函数判定引擎；全部捕获异常，读不到就是 null。 */
  const deps = {
    readFile(filePath) {
      try {
        return fs.readFileSync(filePath, 'utf8');
      } catch {
        return null;
      }
    },
    stat(filePath) {
      try {
        const stat = fs.statSync(filePath);
        return { isFile: stat.isFile(), size: stat.size };
      } catch {
        return null;
      }
    },
    exists(filePath) {
      try {
        fs.accessSync(filePath);
        return true;
      } catch {
        return false;
      }
    },
    realpath(filePath) {
      try {
        return fs.realpathSync.native ? fs.realpathSync.native(filePath) : fs.realpathSync(filePath);
      } catch {
        return null;
      }
    },
    hashFile(filePath) {
      try {
        return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
      } catch {
        return null;
      }
    },
  };

  /** 每会话状态：/off、计数、预算、最后命中。 */
  const states = new Map();
  const stateOf = (session) => {
    const key = String(session?.id ?? '');
    let state = states.get(key);
    if (state === undefined) {
      state = {
        disabled: false,
        sessionCount: 0,
        turn: 0,
        turnCount: 0,
        lastRule: null,
        lastAt: null,
        preset: null,
        presetSeq: -1,
      };
      states.set(key, state);
    }
    return state;
  };

  /**
   * 判定一次审批请求：返回命中的放行结果，或 null 表示交还人工审批。
   * 该函数只读会话日志 + 只读文件，不修改任何 DSH 状态。
   */
  const decide = (req) => {
    if (req === null || typeof req !== 'object') return null;
    const session = req.agent?.session;
    if (session === undefined || session === null) return null;
    const sessionId = String(session.id ?? '');
    const state = stateOf(session);
    if (state.disabled) return null;

    const events = sessionEvents(session);
    const seq = typeof session.seq === 'number' ? session.seq : -1;
    let preset = state.preset;
    if (state.presetSeq !== seq) {
      preset = resolvePreset(session, events);
      state.preset = preset;
      state.presetSeq = seq;
    }
    if (typeof preset !== 'string' || !config.presets.includes(preset)) return null;

    if (req.callId === undefined || req.callId === null) return null;
    const call = findToolCall(events, req.callId);
    if (call === undefined) return null;
    // 注意：findToolCall 返回的是 session 事件本身，工具名在 event.data.name。
    const toolName = call.data?.name;
    if (typeof toolName !== 'string' || toolName !== req.toolName) return null;

    const args = parseCallArguments(call);
    if (args === undefined) return null;

    const turn = resolveTurn(events);
    if (state.turn !== turn) {
      state.turn = turn;
      state.turnCount = 0;
    }
    if (state.sessionCount >= config.maxAutoApprovalsPerSession || state.turnCount >= config.maxAutoApprovalsPerTurn) {
      audit.record({
        type: 'ask-over-budget',
        sessionId,
        preset,
        tool: toolName,
        turn,
        sessionCount: state.sessionCount,
        turnCount: state.turnCount,
      });
      return null;
    }

    const input = {
      toolName,
      args,
      preset,
      cwd: typeof session.header?.cwd === 'string' ? session.header.cwd : null,
      sessionId,
    };
    const result = evaluateApproval(input, deps, config);
    if (result === null || typeof result !== 'object' || result.decision !== 'allow') return null;

    state.sessionCount += 1;
    state.turnCount += 1;
    state.lastRule = typeof result.rule === 'string' ? result.rule : 'allow';
    state.lastAt = Date.now();
    audit.record({
      type: 'auto-allow',
      sessionId,
      preset,
      tool: toolName,
      rule: state.lastRule,
      detail: typeof result.detail === 'string' ? result.detail : '',
      summary: previewOf(result.summary ?? args.command ?? args.file_path),
      turn,
      sessionCount: state.sessionCount,
      turnCount: state.turnCount,
    });
    return result;
  };

  // prepend=true：必须排在 UI 应答者（把请求转发给浏览器的人工审批）之前。
  ctx.on(
    'approval/request',
    async (req, next) => {
      try {
        const hit = decide(req);
        if (hit !== null) return 'allowed-once';
      } catch (error) {
        // 判定异常绝不能让审批服务把它当成 unaavailable 拒绝；回落人工审批。
        try {
          audit.record({
            type: 'error',
            sessionId: String(req?.agent?.id ?? ''),
            tool: typeof req?.toolName === 'string' ? req.toolName : '',
            message: error instanceof Error ? error.message : String(error),
          });
        } catch {
          /* ignore */
        }
      }
      return next();
    },
    true,
  );

  // 会话销毁时清掉内存状态（只是缓存清理，不影响安全）。
  ctx.on('agent/disposed', (payload) => {
    try {
      const id = payload?.agent?.id;
      if (id !== undefined && id !== null) states.delete(String(id));
    } catch {
      /* ignore */
    }
  });

  /**
   * /swapproval 命令：用户可随时查看状态、暂停/恢复本会话、查看审计。
   * 命令处理器只读插件内存与审计文件，不触发任何审批。
   */
  const commandHandler = (invocation) => {
    try {
      const session = invocation?.agent?.session;
      const state = session !== undefined && session !== null ? stateOf(session) : null;
      const sessionId = String(session?.id ?? '');
      const raw = String(invocation?.rawInput ?? '').trim();
      const parts = raw.length === 0 ? [] : raw.split(/\s+/u);
      const action = (parts[0] ?? 'status').toLowerCase();

      if (action === 'on' || action === 'off') {
        if (state === null) return { kind: 'error', text: '/swapproval: 当前会话不可用' };
        state.disabled = action === 'off';
        return {
          kind: 'success',
          text:
            action === 'off'
              ? '已在本会话暂停 SW 自动审批：后续所有审批都会正常弹窗，直到 /swapproval on。'
              : '已在本会话恢复 SW 自动审批（仍只放行严格白名单内的 SW 命令）。',
        };
      }

      if (action === 'log') {
        const count = Math.min(Math.max(Number.parseInt(parts[1] ?? '10', 10) || 10, 1), 50);
        if (!audit.enabled || audit.auditPath === null) {
          return { kind: 'success', text: '审计日志未启用（config.auditDir 为空）。' };
        }
        let lines = [];
        try {
          const content = fs.readFileSync(audit.auditPath, 'utf8');
          lines = content.split('\n').filter((line) => line.trim().length > 0);
        } catch {
          return { kind: 'success', text: '暂无审计日志。' };
        }
        const matched = [];
        for (let index = lines.length - 1; index >= 0 && matched.length < count; index -= 1) {
          try {
            const entry = JSON.parse(lines[index]);
            if (entry.sessionId === sessionId && entry.type === 'auto-allow') matched.push(entry);
          } catch {
            /* ignore malformed line */
          }
        }
        if (matched.length === 0) return { kind: 'success', text: '本会话还没有自动放行记录。' };
        const body = matched
          .reverse()
          .map((entry, index) => `${index + 1}. ${entry.ts ?? '?'} [${entry.rule ?? '?'}] ${entry.summary ?? ''}`)
          .join('\n');
        return { kind: 'success', text: `本会话最近 ${matched.length} 次自动放行：\n${body}` };
      }

      if (action === 'rehash') {
        const hashes = computeTrustedScriptHashes(config);
        config = { ...config, trustedScriptHashes: hashes };
        const count = Object.keys(hashes).length;
        audit.writeStatus({
          phase: 'rehash',
          presets: config.presets,
          engineeringRoot: config.engineeringRoot,
          trustedScripts: count,
        });
        return {
          kind: 'success',
          text: `已重新学习 ${count} 个受信任 engineering 脚本的 SHA-256（正常更新工程预设后使用；之后这些脚本变更会转人工审批）。`,
        };
      }

      if (action !== 'status') {
        return { kind: 'error', text: '用法：/swapproval [status|on|off|log [n]|rehash]' };
      }

      const events = session !== undefined && session !== null ? sessionEvents(session) : [];
      const preset = session !== undefined && session !== null ? resolvePreset(session, events) : null;
      const lastAt = state?.lastAt ? new Date(state.lastAt).toISOString() : '无';
      const liveTrustedCount = Object.keys(config.trustedScriptHashes ?? {}).length;
      const lines = [
        'SW 安全自动审批（dsh-sw-approval）',
        `  插件版本：${PLUGIN_VERSION}（policy v${POLICY_VERSION}）`,
        `  生效预设：${config.presets.join(', ') || '(空)'}`,
        `  当前会话预设：${preset ?? '未知'}${state?.disabled ? '（本会话已 /swapproval off）' : ''}`,
        `  本会话自动放行：${state?.sessionCount ?? 0} 次；本回合：${state?.turnCount ?? 0} 次`,
        `  最后命中：${state?.lastRule ?? '无'} @ ${lastAt}`,
        `  判定根目录：${config.engineeringRoot}`,
        `  受信任脚本哈希：${liveTrustedCount} 个${liveTrustedCount === 0 ? '（缺失时 trusted 脚本会转人工审批）' : ''}`,
        `  SolidWorks：${config.solidworksExe}`,
        `  审计日志：${audit.auditPath ?? '(未启用)'}`,
        '  说明：只自动放行 SW 白名单命令的 danger-full-access 提权；其它操作照常弹窗。',
      ];
      return { kind: 'success', text: lines.join('\n') };
    } catch (error) {
      return { kind: 'error', text: `/swapproval 执行失败：${error instanceof Error ? error.message : String(error)}` };
    }
  };

  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.commands.register({
      name: 'swapproval',
      description: 'SW 自动审批：查看状态/暂停/恢复/审计/重学哈希（status|on|off|log [n]|rehash）',
      input: { hint: '[status|on|off|log [n]|rehash]' },
      handler: commandHandler,
    });
  });
}
