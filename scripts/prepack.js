// npm pack 前清理本地运行产物：引导生成的 runtime.json / logs / __pycache__，
// 并把 recycle.cmd 恢复为占位符（安装后首运行会按真实 python 重新生成）。
import { rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const guardDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'guard');
for (const junk of ['runtime.json', 'logs', '__pycache__']) {
  rmSync(path.join(guardDir, junk), { recursive: true, force: true });
}
writeFileSync(path.join(guardDir, 'recycle.cmd'),
  '@echo off\r\nrem 占位启动器：首次运行 guard.py 时会按真实 python 路径重新生成本文件。\r\npython -X utf8 "%~dp0guard.py" recycle --payload "%~1"\r\nexit /b %errorlevel%\r\n');
console.log('prepack: 已清理运行产物并重置 recycle.cmd 占位符');
