import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureRuntime } from './runtime.js';

export const name = 'agent-recycle-guard';
export const inject = ['tools', 'shell'];

// 防护脚本随包分发，位置相对本文件固定，无需任何配置。
const guardPath = fileURLToPath(new URL('../guard/guard.py', import.meta.url));
/** 子进程只分析 JSON；不在宿主插件中直接执行文件回收，以保留原工具沙箱。 */
async function inspect(event, config, signal) {
  const python = await ensureRuntime(config);
  return new Promise((resolve, reject) => {
    const child = spawn(python, ['-X', 'utf8', guardPath, 'analyze', '--agent', 'dsh'], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], signal,
      env: {...process.env, ...event.env},
    });
    let output = '';
    child.stdout.setEncoding('utf8');
    // 首次运行可能正在下载隔离 Python；等待其显式成功或失败，不能用分析超时绕过初始化。
    const timer = setTimeout(() => child.kill(), 960000);
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
      // DSH 本地执行器每条命令启动新进程；输出 schema 不能用于判断持久终端。
      // resolve 是只读的执行规格解析，使用同一 workdir，保留工具原始参数与沙箱。
      const shell = ctx.shell;
      const spec = shell?.resolve?.({command: exec.arguments.command ?? exec.arguments.cmd, workdir: exec.arguments.workdir, env: exec.arguments.env});
      const dialect = exec.name === 'pwsh' || exec.name === 'powershell' || shell?.pwshPath
        ? 'powershell' : exec.arguments.shell ?? config?.shell ?? 'bash';
      const decision = await inspect({tool_name: exec.name, tool_input: exec.arguments,
        cwd: exec.agent?.session?.header?.cwd ?? process.cwd(), execution_cwd: spec?.workdir ? path.resolve(spec.workdir) : undefined,
        shell: dialect, env: spec?.env ?? exec.arguments.env}, config, exec.signal);
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
