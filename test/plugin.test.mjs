// dsh-sw-approval 胶水层集成测试（fake Cordis ctx + fake Agent/Session）
// 只依赖 node: 内建；验证：prepend 注册、preset 闸门、callId 关联、预算、/off、审计、fail-closed。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { apply } from '../index.js';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const ENG_ROOT = path.join(TEST_DIR, 'fixtures', 'eng');
const AUDIT_DIR = path.join(TEST_DIR, '.audit');
const PY = path.join(ENG_ROOT, 'dependencies', 'python', 'python.exe');
const SW_BRIDGE = path.join(ENG_ROOT, 'tools', 'sw_bridge.py');
const SW_EXE = 'D:\\SolidWorks 2026\\SOLIDWORKS\\SLDWORKS.exe';

function baseConfig(overrides = {}) {
  return {
    enabled: true,
    presets: ['engineering'],
    engineeringRoot: ENG_ROOT,
    solidworksExe: SW_EXE,
    auditDir: AUDIT_DIR,
    maxAutoApprovalsPerSession: 500,
    maxAutoApprovalsPerTurn: 80,
    ...overrides,
  };
}

/** 构造一次 pwsh danger-full-access 审批请求所需的 fake 世界。 */
function world({ preset = 'engineering', command, toolName = 'pwsh', callId = 'c1', turn = 1, sessionId = 's1' } = {}) {
  const events = [
    { type: 'turn/start', data: { turn } },
    {
      type: 'tool/call',
      data: {
        turn,
        step: 1,
        callId,
        name: toolName,
        arguments: JSON.stringify({
          command,
          description: 'sw step',
          sandbox_permissions: 'danger-full-access',
          justification: 'sw modeling',
        }),
      },
    },
  ];
  const session = {
    id: sessionId,
    seq: events.length,
    header: { cwd: TEST_DIR, agentPreset: preset },
    ownEvents() {
      return events;
    },
  };
  const agent = { id: sessionId, session };
  return { agent, session, events, request: { agent, toolName, callId, reason: 'escalate' } };
}

function install(config) {
  const listeners = [];
  const commands = [];
  const ctx = {
    logger: { info() {}, warn() {} },
    on(name, listener, options) {
      listeners.push({ name, listener, options });
      return () => {};
    },
    inject(_services, callback) {
      callback({ commands: { register(definition) { commands.push(definition); return () => {}; } } });
      return () => {};
    },
  };
  apply(ctx, config);
  const approval = listeners.find((entry) => entry.name === 'approval/request');
  assert.ok(approval, 'approval/request listener must be registered');
  return { approval, commands, listeners };
}

const ALLOW_COMMAND = `& "${PY}" "${SW_BRIDGE}" status`;

test('engineering 会话中白名单 SW 命令 → allowed-once，且不调用 next', async () => {
  const { approval } = install(baseConfig());
  const { request } = world({ command: ALLOW_COMMAND });
  let nextCalls = 0;
  const outcome = await approval.listener(request, async () => {
    nextCalls += 1;
    return 'unavailable';
  });
  assert.equal(outcome, 'allowed-once');
  assert.equal(nextCalls, 0);
});

test('approval listener 以 prepend 注册（必须先于 UI 应答者）', () => {
  const { approval } = install(baseConfig());
  assert.equal(approval.options, true);
});

test('非 engineering preset → next（人工审批）', async () => {
  const { approval } = install(baseConfig());
  const { request } = world({ preset: 'standard', command: ALLOW_COMMAND });
  let nextCalls = 0;
  const outcome = await approval.listener(request, async () => {
    nextCalls += 1;
    return 'rejected';
  });
  assert.equal(outcome, 'rejected');
  assert.equal(nextCalls, 1);
});

test('非 SW 命令 → next', async () => {
  const { approval } = install(baseConfig());
  const { request } = world({ command: 'Remove-Item -Recurse -Force C:\\Windows\\Temp\\x' });
  let nextCalls = 0;
  const outcome = await approval.listener(request, async () => {
    nextCalls += 1;
    return 'unavailable';
  });
  assert.equal(outcome, 'unavailable');
  assert.equal(nextCalls, 1);
});

test('缺 callId → next', async () => {
  const { approval } = install(baseConfig());
  const { request } = world({ command: ALLOW_COMMAND });
  request.callId = undefined;
  let nextCalls = 0;
  const outcome = await approval.listener(request, async () => {
    nextCalls += 1;
    return 'unavailable';
  });
  assert.equal(outcome, 'unavailable');
  assert.equal(nextCalls, 1);
});

test('toolName 与日志里的 tool/call 不一致 → next', async () => {
  const { approval } = install(baseConfig());
  const { request } = world({ command: ALLOW_COMMAND });
  request.toolName = 'write';
  let nextCalls = 0;
  await approval.listener(request, async () => {
    nextCalls += 1;
    return 'unavailable';
  });
  assert.equal(nextCalls, 1);
});

test('日志里找不到对应 tool/call → next', async () => {
  const { approval } = install(baseConfig());
  const { request } = world({ command: ALLOW_COMMAND });
  request.callId = 'does-not-exist';
  let nextCalls = 0;
  await approval.listener(request, async () => {
    nextCalls += 1;
    return 'unavailable';
  });
  assert.equal(nextCalls, 1);
});

test('每会话预算用尽后 → next（仍走人工审批）', async () => {
  const { approval } = install(baseConfig({ maxAutoApprovalsPerSession: 1 }));
  for (let index = 0; index < 2; index += 1) {
    const { request } = world({ command: ALLOW_COMMAND });
    let nextCalls = 0;
    const outcome = await approval.listener(request, async () => {
      nextCalls += 1;
      return 'unavailable';
    });
    if (index === 0) {
      assert.equal(outcome, 'allowed-once');
      assert.equal(nextCalls, 0);
    } else {
      assert.equal(outcome, 'unavailable');
      assert.equal(nextCalls, 1);
    }
  }
});

test('/swapproval off 后本会话不再自动放行，/on 后恢复', async () => {
  const { approval, commands } = install(baseConfig());
  const { request } = world({ command: ALLOW_COMMAND, sessionId: 's-off' });
  const invocation = { agent: request.agent, rawInput: 'off', commandId: 'cmd-1', attachments: [], signal: new AbortController().signal };
  const command = commands.find((entry) => entry.name === 'swapproval');
  assert.ok(command, '/swapproval 必须注册');
  const offResult = command.handler(invocation);
  assert.equal(offResult.kind, 'success');

  let nextCalls = 0;
  const outcome = await approval.listener(request, async () => {
    nextCalls += 1;
    return 'unavailable';
  });
  assert.equal(outcome, 'unavailable');
  assert.equal(nextCalls, 1);

  const status = command.handler({ ...invocation, rawInput: 'status' });
  assert.equal(status.kind, 'success');
  assert.match(status.text, /swapproval off/);

  command.handler({ ...invocation, rawInput: 'on' });
  const { request: request2 } = world({ command: ALLOW_COMMAND, sessionId: 's-off' });
  const outcome2 = await approval.listener(request2, async () => 'unavailable');
  assert.equal(outcome2, 'allowed-once');
});

test('判定过程抛异常时 fail-closed 返回 next，且不向审批服务抛错', async () => {
  const { approval } = install(baseConfig());
  const brokenSession = {
    id: 's-broken',
    seq: 3,
    header: { cwd: TEST_DIR, agentPreset: 'engineering' },
    ownEvents() {
      throw new Error('boom');
    },
  };
  const request = { agent: { id: 's-broken', session: brokenSession }, toolName: 'pwsh', callId: 'c1' };
  let nextCalls = 0;
  const outcome = await approval.listener(request, async () => {
    nextCalls += 1;
    return 'allowed-once';
  });
  assert.equal(outcome, 'allowed-once');
  assert.equal(nextCalls, 1);
});

test('审计日志与 status.json 写入本地审计目录', () => {
  const { approval } = install(baseConfig());
  const { request } = world({ command: ALLOW_COMMAND, sessionId: 's-audit' });
  return approval.listener(request, async () => 'unavailable').then(() => {
    const auditPath = path.join(AUDIT_DIR, 'audit.jsonl');
    const statusPath = path.join(AUDIT_DIR, 'status.json');
    assert.ok(fs.existsSync(auditPath), 'audit.jsonl should exist');
    assert.ok(fs.existsSync(statusPath), 'status.json should exist');
    const lines = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
    assert.ok(lines.some((entry) => entry.type === 'plugin-start'));
    assert.ok(lines.some((entry) => entry.type === 'auto-allow' && entry.sessionId === 's-audit' && entry.rule));
  });
});

test('配置 enabled:false 时插件不注册审批监听器', () => {
  const listeners = [];
  const ctx = {
    logger: { info() {}, warn() {} },
    on(name, listener, options) { listeners.push({ name, listener, options }); return () => {}; },
    inject() { return () => {}; },
  };
  apply(ctx, baseConfig({ enabled: false }));
  assert.equal(listeners.find((entry) => entry.name === 'approval/request'), undefined);
});

test('/swapproval status 显示受信任脚本哈希数量', () => {
  const { commands } = install(baseConfig());
  const command = commands.find((entry) => entry.name === 'swapproval');
  const result = command.handler({
    agent: { id: 's-status', session: { id: 's-status', seq: 0, header: { cwd: TEST_DIR, agentPreset: 'engineering' }, ownEvents: () => [] } },
    rawInput: 'status',
    commandId: 'cmd-3',
    attachments: [],
    signal: new AbortController().signal,
  });
  assert.equal(result.kind, 'success');
  assert.match(result.text, /受信任脚本哈希：1 个/);
});

test('/swapproval rehash 重新学习受信任脚本哈希', () => {
  const { commands } = install(baseConfig());
  const command = commands.find((entry) => entry.name === 'swapproval');
  const result = command.handler({
    agent: { id: 's-rehash', session: { id: 's-rehash', seq: 0, header: { cwd: TEST_DIR, agentPreset: 'engineering' }, ownEvents: () => [] } },
    rawInput: 'rehash',
    commandId: 'cmd-4',
    attachments: [],
    signal: new AbortController().signal,
  });
  assert.equal(result.kind, 'success');
  assert.match(result.text, /重新学习 1 个受信任 engineering 脚本/);
});

test('/swapproval log 返回本会话最近自动放行记录', async () => {
  const { approval, commands } = install(baseConfig());
  // 审计是追加式文件，跨多次测试运行会累积；用本次唯一的 sessionId 保证断言稳定。
  const sessionId = `s-log-${process.pid}-${Date.now()}`;
  const { request } = world({ command: ALLOW_COMMAND, sessionId });
  await approval.listener(request, async () => 'unavailable');
  const command = commands.find((entry) => entry.name === 'swapproval');
  const result = command.handler({
    agent: request.agent,
    rawInput: 'log 5',
    commandId: 'cmd-2',
    attachments: [],
    signal: new AbortController().signal,
  });
  assert.equal(result.kind, 'success');
  assert.match(result.text, /最近 1 次自动放行/);
});
