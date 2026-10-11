// npm pack 后：恢复 prepack 备份的真实 recycle.cmd（若存在备份）。
import { renameSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const guardDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'guard');
const backup = path.join(guardDir, 'recycle.cmd.pack-backup');
if (existsSync(backup)) {
  renameSync(backup, path.join(guardDir, 'recycle.cmd'));
  console.log('postpack: 已恢复真实 recycle.cmd');
}
