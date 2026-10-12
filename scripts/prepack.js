// npm pack 前：把 recycle.cmd 恢复为占位符（安装后首运行会按真实 python 重新生成）。
// 不删除任何运行产物；若本地 recycle.cmd 是已配置的真实启动器（含绝对 python 路径），
// 先备份到 recycle.cmd.pack-backup，由 postpack 在打包结束后恢复——打包过程
// 不得修改真实运行文件。
import { copyFileSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const packageDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const guardDir = path.join(packageDir, 'guard');
const launcher = path.join(guardDir, 'recycle.cmd');
const backup = path.join(guardDir, 'recycle.cmd.pack-backup');
const placeholder = '@echo off\r\nrem 占位启动器：首次运行 guard.py 时会按真实 python 路径重新生成本文件。\r\npython -X utf8 "%~dp0guard.py" recycle --payload "%~1"\r\nexit /b %errorlevel%\r\n';

// 本地/CI 跑过 pytest 后 tests/__pycache__ 会被 files 目录项带入 tgz，打包前清理。
for (const pycache of ['tests/__pycache__', 'guard/__pycache__']) {
  rmSync(path.join(packageDir, pycache), {recursive: true, force: true});
}

if (existsSync(launcher) && readFileSync(launcher, 'utf8') !== placeholder) {
  copyFileSync(launcher, backup);
  console.log('prepack: 已备份真实 recycle.cmd，打包后由 postpack 恢复');
}
writeFileSync(launcher, placeholder);
console.log('prepack: 已重置 recycle.cmd 占位符');
