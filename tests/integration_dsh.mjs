// 使用真实 DSH 工具管线，工具体只记录参数，危险原文永远不交给 Shell。
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL, fileURLToPath} from 'node:url';
import {cpSync, mkdtempSync, mkdirSync, writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';

const repo = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const require = createRequire(process.env.DSH_PACKAGE_JSON ?? path.join(repo, 'package.json'));
const load = name => import(pathToFileURL(require.resolve(name)).href);
const {Context, Service} = await load('@deepseek-ai/cordis');
const {ToolRuntime, defineTool} = await load('@deepseek-ai/dsh-tools');
const {SystemPrompt} = await load('@deepseek-ai/dsh-system-prompt');
const root = mkdtempSync(path.join(process.env.GUARD_TEST_TMP ?? os.tmpdir(), 'agent-recycle-dsh-'));
const workspace = path.join(root, 'workspace');
mkdirSync(workspace);
const other = path.join(root, 'other');
mkdirSync(other);
cpSync(path.join(repo, 'guard'), path.join(root, 'guard'), {recursive: true, filter: source => !source.includes(`${path.sep}logs`) && !source.endsWith('runtime.json')});
cpSync(path.join(repo, 'lib'), path.join(root, 'lib'), {recursive: true});
cpSync(path.join(repo, 'requirements.txt'), path.join(root, 'requirements.txt'));
writeFileSync(path.join(root, 'package.json'), '{"type":"module"}');
// 不写 runtime.json，也不提供 Python 配置，真实验证默认安装的自动准备流程。
writeFileSync(path.join(workspace, 'victim.txt'), '测试文件');
writeFileSync(path.join(workspace, '.hidden.ps1'), "Remove-Item -LiteralPath 'victim.txt'");
writeFileSync(path.join(workspace, '.hidden.cmd'), '@echo off\ndel victim.txt');
writeFileSync(path.join(workspace, 'code.py'), "from os import remove as zap\nzap('victim.txt')");
writeFileSync(path.join(workspace, 'cwd-code.py'), "print('安全的会话目录同名文件')");
writeFileSync(path.join(other, 'cwd-code.py'), "from os import remove as zap\nzap('victim.txt')");
const plugin = await import(pathToFileURL(path.join(root, 'lib', 'plugin.js')));
const ctx = new Context();
new SystemPrompt(ctx, {});
new ToolRuntime(ctx);
// 执行器只解析工作目录，不启动进程；Shell 依赖按真实 Cordis 服务机制注册。
class RecordingShell extends Service {
  constructor(context) { super(context, 'shell'); }
  resolve(request) { return {...request, workdir: request.workdir ?? workspace}; }
}
new RecordingShell(ctx);
ctx.plugin(plugin, {});
await new Promise(resolve => setTimeout(resolve, 25));
const seen = [];
for (const name of ['pwsh', 'exec_command']) {
  ctx.tools.register(defineTool({name, description: '删除防护集成记录工具',
    parameters: {command: {type: 'string', required: true}, shell: {type: 'string'}, workdir: {type: 'string'}},
    output: {schema: {type: 'string'}, render: (_args, value) => [{type: 'text', text: value}]},
    execute: async args => {seen.push(args.command); return args.command;}}));
}
const agent = {ctx: ctx.extend(), session: {header: {cwd: workspace}}, parent: undefined};
const cases = [
  ['普通查询', 'Get-Date', 'allow', 'pwsh', 'powershell'],
  ['多行变量删除', "$taskTarget = Join-Path (Get-Location) 'victim.txt'\nRemove-Item $taskTarget -Recurse -Force", 'rewrite', 'pwsh', 'powershell'],
  ['脚本点号名称', "& './.hidden.ps1'", 'rewrite', 'pwsh', 'powershell'],
  ['数据读取', 'Get-Content ./.hidden.ps1', 'allow', 'pwsh', 'powershell'],
  ['Python导入别名', 'python code.py', 'deny', 'pwsh', 'powershell'],
  ['Bash多行变量', 'taskTarget=victim.txt\nrm -f "$taskTarget"', 'rewrite', 'exec_command', 'bash'],
  ['CMD点号脚本', '.hidden.cmd', 'deny', 'exec_command', 'cmd'],
  ['外部危险删除', 'git clean -fd', 'deny', 'pwsh', 'powershell'],
  ['实际工作目录优先', 'python cwd-code.py', 'deny', 'pwsh', 'powershell', other],
];
try {
  for (const [label, command, action, name, shell, workdir] of cases) {
    const before = seen.length;
    const result = await ctx.tools.execute({callId: randomUUID(), name, arguments: {command, shell, ...(workdir ? {workdir} : {})}, agent, signal: new AbortController().signal});
    if (action === 'deny') {
      assert.equal(result.isError, true, JSON.stringify(result));
      assert.equal(seen.length, before);
    } else {
      assert.equal(result.isError, false, JSON.stringify(result));
      assert.equal(seen.length, before + 1);
      assert.equal(seen.at(-1) === command, action === 'allow');
    }
    console.log('通过：' + label);
  }
  ctx.on('tools/pre-execute', () => ({kind: 'deny', reason: '原生权限策略拒绝'}));
  const before = seen.length;
  const result = await ctx.tools.execute({callId: randomUUID(), name: 'pwsh', arguments: {command: 'Get-Date', shell: 'powershell'}, agent, signal: new AbortController().signal});
  assert.equal(result.isError, true);
  assert.equal(seen.length, before);
  console.log('通过：原生权限拒绝不能被防护放行');
} finally {
  await ctx.fiber.dispose();
}
console.log('DSH 集成验证通过；未执行危险原文。');
