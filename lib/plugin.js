import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const name = 'agent-recycle-guard';
export const inject = ['tools'];

// 防护脚本随包分发，位置相对本文件固定，无需任何配置。
const guardPath = fileURLToPath(new URL('../guard/guard.py', import.meta.url));
// 已验证可用的 python 命令（可能带启动器参数，如 py -3），进程内缓存。
let resolvedPython = null;

/**
 * 探测可用的 python 解释器：依次尝试 PATH 中的 python / python3 / py 启动器，
 * 以及 Windows 常见安装位置，全部通过真实启动子进程验证，避免只查文件名。
 * 用户可通过插件 config.python 显式指定，跳过探测。
 */
function detectPython(config) {
  if (config?.python && typeof config.python === 'string') return Promise.resolve([config.python]);
  if (resolvedPython) return Promise.resolve(resolvedPython);
  const candidates = [
    ['python'],
    ['python3'],
    ['py', '-3'],
    // 常见安装位置兜底（存在性由探测子进程验证，不存在只是探测失败）。
    [path.join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Python', 'Python312', 'python.exe')],
    [path.join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Python', 'Python311', 'python.exe')],
    [path.join(process.env.SystemDrive ?? 'C:', 'Python312', 'python.exe')],
  ];
  return new Promise(resolve => {
    let index = 0;
    const tryNext = () => {
      if (index >= candidates.length) {
        // 全部失败：返回首选候选，由后续真实调用报出可读错误（fail-closed）。
        resolve(['python']);
        return;
      }
      const candidate = candidates[index++];
      const child = spawn(candidate[0], ['-c', 'import sys; sys.exit(0)'], { windowsHide: true, stdio: 'ignore' });
      const fail = () => { child.kill(); tryNext(); };
      const timer = setTimeout(fail, 5000);
      child.on('error', () => { clearTimeout(timer); tryNext(); });
      child.on('close', code => {
        clearTimeout(timer);
        if (code === 0) {
          resolvedPython = candidate;
          resolve(candidate);
        } else tryNext();
      });
    };
    tryNext();
  });
}

/** 子进程只分析 JSON；不在宿主插件中直接执行文件回收，以保留原工具沙箱。 */
async function inspect(event, config, signal) {
  const python = await detectPython(config);
  return new Promise((resolve, reject) => {
    const child = spawn(python[0], [...python.slice(1), '-X', 'utf8', guardPath, 'analyze', '--agent', 'dsh'], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], signal,
    });
    let output = '';
    child.stdout.setEncoding('utf8');
    const timer = setTimeout(() => child.kill(), 20000);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.stdout.on('data', chunk => {
      output += chunk;
      if (output.length > 262144) child.kill();
    });
    child.stderr.resume();
    child.on('close', code => {
      clearTimeout(timer);
      try {
        if (code !== 0) throw new Error('安全解析程序退出异常。');
        const decision = JSON.parse(output);
        if (!['allow', 'deny', 'rewrite'].includes(decision.action)) throw new Error('非法解析决策。');
        resolve(decision);
      } catch (error) { reject(error); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(event));
  });
}

/** 新调用重新经过原生工具权限及沙箱检查，不修改已冻结的原调用参数。 */
export function apply(ctx, config) {
  const decisions = new Map();
  ctx.on('tools/pre-execute', async (exec, next) => {
    const gate = await next();
    if (gate.kind !== 'allow' && gate.kind !== 'ask') return gate;
    if (!exec.arguments || typeof exec.arguments !== 'object' || !('command' in exec.arguments || 'cmd' in exec.arguments)) return gate;
    try {
      const definition = ctx.tools.get(exec.name, exec.agent);
      const decision = await inspect({tool_name: exec.name, tool_input: exec.arguments, cwd: exec.agent?.session?.header?.cwd, persistent: definition?.output?.schema?.type === 'string'}, config, exec.signal);
      decisions.set(exec.token, decision);
      if (decision.action === 'deny') return {kind: 'deny', reason: decision.reason};
      return gate;
    } catch (error) {
      return {kind: 'deny', reason: '删除防护检查失败，已阻止命令：' + error.message};
    }
  });
  ctx.on('tools/execute', async (exec, next) => {
    if (!exec.arguments || typeof exec.arguments !== 'object' || !('command' in exec.arguments || 'cmd' in exec.arguments)) return next();
    const decision = decisions.get(exec.token);
    decisions.delete(exec.token);
    if (!decision) return {isError: true, error: {message: '缺少删除防护检查，已阻止命令。'}, content: [{type: 'text', text: '缺少删除防护检查，已阻止命令。'}]};
    if (decision.action === 'allow') return next();
    if (decision.action !== 'rewrite' || !decision.input || typeof (decision.input.command ?? decision.input.cmd) !== 'string') {
      return {isError: true, error: {message: '非法删除转换结果。'}, content: [{type: 'text', text: '非法删除转换结果。'}]};
    }
    return ctx.tools.execute({
      callId: 'recycle-' + randomUUID(), rootCallId: exec.rootCallId,
      name: exec.name, arguments: decision.input, agent: exec.agent,
      parent: exec.token, signal: exec.signal,
    });
  });
  // 被其他策略拒绝的调用可能不进入 execute；在最终结果事件释放解析缓存。
  ctx.on('tools/result', exec => { decisions.delete(exec.token); });
}
