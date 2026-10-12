"""只执行经过检查的回收命令，验证真实回收项目；不执行原删除载荷。"""
import json
from pathlib import Path
import subprocess
import sys

import pytest
from test_guard import guard, analyze, require_pwsh


def receipts_from(stdout):
    rows = []
    for line in stdout.splitlines():
        if line.strip().startswith('{'):
            try:
                rows.extend(json.loads(line).get('receipts', []))
            except ValueError:
                pass
    return rows


def confirm_trash(guard, original, content, output):
    assert not original.exists()
    receipts = receipts_from(output)
    assert any(row['original'] == str(original) for row in receipts), output
    if sys.platform == 'win32':
        receipt = next(row for row in receipts if row['original'] == str(original))
        recycled = Path(receipt['recycled'])
        assert recycled.exists() and '$recycle.bin' in str(recycled).lower()
        assert recycled.read_bytes() == content
    elif sys.platform.startswith('linux'):
        # CI 与本机验证使用独立 XDG 回收区，核对文件及 freedesktop 元数据。
        import os
        from urllib.parse import unquote
        trash = Path(os.environ['XDG_DATA_HOME']) / 'Trash'
        entries = [p for p in (trash / 'info').glob('*.trashinfo') if 'Path=' + str(original) in unquote(p.read_text())]
        assert entries, '未找到对应 .trashinfo 回收元数据。'
        assert any((trash / 'files' / p.name.removesuffix('.trashinfo')).read_bytes() == content for p in entries)
    elif sys.platform == 'darwin':
        fresh = set((Path.home() / '.Trash').iterdir()) - guard.test_trash_before
        assert any(p.is_file() and p.read_bytes() == content for p in fresh), '未确认 macOS 新增回收项目。'


@pytest.mark.parametrize('text', [
    "$taskTarget = Join-Path (Get-Location) 'victim.txt'\nRemove-Item $taskTarget -Recurse -Force",
    "Get-ChildItem -Filter 'victim.txt' | Remove-Item -Force",
    "foreach ($taskTarget in @('victim.txt')) { Remove-Item $taskTarget -Force }",
])
def test_actual_powershell_recycles_with_receipt(guard, text, monkeypatch):
    require_pwsh(guard)
    if sys.platform.startswith('linux'):
        monkeypatch.setenv('XDG_DATA_HOME', str(guard.test_workspace.parent / 'xdg'))
    target = guard.test_workspace / 'victim.txt'
    original = target.read_bytes()
    decision = analyze(guard, text)
    assert decision['action'] == 'rewrite'
    rewritten = decision['input']['command']
    assert analyze(guard, rewritten)['action'] == 'allow'
    run = subprocess.run([guard.test_cfg['pwsh'], '-NoProfile', '-NonInteractive', '-Command', rewritten],
                         cwd=guard.test_workspace, capture_output=True, encoding='utf-8', timeout=45)
    assert run.returncode == 0, run.stderr
    confirm_trash(guard, target, original, run.stdout)


def test_actual_shell_runtime_accepts_options_after_mode(guard, monkeypatch):
    if sys.platform.startswith('linux'):
        monkeypatch.setenv('XDG_DATA_HOME', str(guard.test_workspace.parent / 'xdg'))
    target = guard.test_workspace / 'victim.txt'
    original = target.read_bytes()
    run = subprocess.run([sys.executable, '-X', 'utf8', str(guard.ROOT / 'guard.py'), 'shell-runtime',
                          '--dialect', 'bash', '--name', 'rm', '--', '-f', 'victim.txt'],
                         cwd=guard.test_workspace, capture_output=True, encoding='utf-8', timeout=30)
    assert run.returncode == 0, run.stderr
    confirm_trash(guard, target, original, run.stdout)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows Git Bash 参数传递验证。')
def test_actual_git_bash_runtime_paths(guard):
    import os
    executable = os.environ.get('GUARD_BASH')
    if not executable:
        pytest.skip('未配置 Git Bash 执行器。')
    target = guard.test_workspace / 'victim.txt'
    original = target.read_bytes()
    decision = analyze(guard, 'taskTarget=victim.txt\nrm -f "$taskTarget"', 'bash')
    assert decision['action'] == 'rewrite'
    assert analyze(guard, decision['input']['command'], 'bash')['action'] == 'allow'
    run = subprocess.run([executable, '-c', decision['input']['command']], cwd=guard.test_workspace,
                         capture_output=True, encoding='utf-8', timeout=30)
    assert run.returncode == 0, run.stderr
    confirm_trash(guard, target, original, run.stdout)


@pytest.mark.skipif(sys.platform == 'win32', reason='Bash 端到端在 Linux/macOS 执行；Windows 使用 PowerShell。')
def test_actual_bash_variable_and_changed_directory(guard, monkeypatch):
    if sys.platform.startswith('linux'):
        monkeypatch.setenv('XDG_DATA_HOME', str(guard.test_workspace.parent / 'xdg'))
    target = guard.test_workspace / 'victim.txt'
    original = target.read_bytes()
    text = 'cd "' + str(guard.test_workspace) + '"\ntaskTarget=victim.txt\nrm -f "$taskTarget"'
    decision = analyze(guard, text, 'bash')
    assert decision['action'] == 'rewrite'
    assert analyze(guard, decision['input']['command'], 'bash')['action'] == 'allow'
    run = subprocess.run(['/bin/bash', '-c', decision['input']['command']], capture_output=True, encoding='utf-8', timeout=30)
    assert run.returncode == 0, run.stderr
    confirm_trash(guard, target, original, run.stdout)


def test_actual_rewritten_ps1_ascii_wrapper(guard, monkeypatch):
    require_pwsh(guard)
    if sys.platform.startswith('linux'):
        monkeypatch.setenv('XDG_DATA_HOME', str(guard.test_workspace.parent / 'xdg'))
    target = guard.test_workspace / 'victim.txt'
    original = target.read_bytes()
    (guard.test_workspace / '中文.ps1').write_text("$taskTarget='victim.txt'\nRemove-Item $taskTarget -Force", encoding='utf-8')
    decision = analyze(guard, "& './中文.ps1'")
    assert decision['action'] == 'rewrite'
    rewritten = decision['input']['command']
    assert analyze(guard, rewritten)['action'] == 'allow'
    run = subprocess.run([guard.test_cfg['pwsh'], '-NoProfile', '-NonInteractive', '-Command', rewritten],
                         cwd=guard.test_workspace, capture_output=True, encoding='utf-8', timeout=45)
    assert run.returncode == 0, run.stderr
    confirm_trash(guard, target, original, run.stdout)
