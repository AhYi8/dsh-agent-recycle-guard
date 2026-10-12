// 真实冷启动验证（可选）：清空真实缓存后调用 ensureRuntime，确认走 DSH 内置 Python 路线。
// 会清空 ~/.cache/dsh-agent-recycle-guard 并真实联网下载依赖，仅在显式设置 GUARD_DSH_COLD_TEST=1 时执行。
if (process.env.GUARD_DSH_COLD_TEST !== '1') {
  console.log('跳过：设置 GUARD_DSH_COLD_TEST=1 后才会执行真实冷启动验证（会清空缓存并联网）。');
  process.exit(0);
}
import {rm, mkdir, readFile, readdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createRuntime} from '../lib/runtime.js';

const cacheDir = path.join(os.homedir(), '.cache', 'dsh-agent-recycle-guard');
await rm(cacheDir, {recursive: true, force: true});
await mkdir(cacheDir, {recursive: true});
console.log('缓存已清空：', cacheDir);
const t0 = Date.now();
const runtime = createRuntime({notify: message => console.log('[notify]', message)});
const python = await runtime();
console.log('就绪解释器：', python);
console.log('耗时(秒)：', ((Date.now() - t0) / 1000).toFixed(1));
console.log('复用缓存：', await createRuntime({})() === python);
// uv 目录不应存在（DSH 路线不下载 uv）
import {stat} from 'node:fs/promises';
let uvExists = false;
try { uvExists = (await readdir(cacheDir)).some(name => name.startsWith('uv-')); } catch {}
const entries = await readFile(path.join(cacheDir), 'utf8').catch(() => '');
console.log('uv 目录存在：', uvExists);
// venv 依赖自检
import {spawn} from 'node:child_process';
await new Promise((resolve, reject) => {
  const child = spawn(python, ['-I', '-X', 'utf8', '-c',
    "import bashlex, send2trash, importlib.metadata as m;"
    + "exec('from win32com.shell import shell' if __import__('sys').platform == 'win32' else '');"
    + "assert m.version('bashlex') == '0.18'; print('依赖自检 OK')"],
    {stdio: 'inherit'});
  child.on('close', code => code === 0 ? resolve() : reject(Error('自检失败 ' + code)));
  child.on('error', reject);
});
console.log('冷启动验证通过');
