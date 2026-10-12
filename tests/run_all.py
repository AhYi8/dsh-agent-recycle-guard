"""按当前产品契约运行回归与真实回收测试，任一失败即非零退出。"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
# 独立目录避免覆盖旧素材，也避免 Windows 非 Unicode 用户名环境变量问题。
base = tempfile.mkdtemp(prefix='agent-recycle-test-')
env = {**os.environ, 'PYTHONUTF8': '1'}
raise SystemExit(subprocess.call([sys.executable, '-X', 'utf8', '-m', 'pytest',
                                 str(root/'tests'), '-q', '--basetemp', str(Path(base)/'pytest')],
                                cwd=root, env=env))
