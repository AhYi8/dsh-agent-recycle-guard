"""新契约回归：直接删除必须改写，脚本尽力检查，回收失败不得永久删除。"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'guard'
sys.path.insert(0, str(SOURCE))
import shell_commands
from script_checks import python_deletes


@pytest.fixture
def guard(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    spec = importlib.util.spec_from_file_location('test_recycle_guard', SOURCE / 'guard.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    root = tmp_path / 'guard'
    root.mkdir()
    for filename in [p.name for p in SOURCE.glob('*.py')] + ['parse_powershell.ps1', 'recycle_powershell.ps1', 'recycle_powershell_impl.ps1']:
        (root / filename).write_bytes((SOURCE / filename).read_bytes())
    monkeypatch.setattr(module, 'ROOT', root)
    monkeypatch.setattr(module, 'SETTINGS', root / 'runtime.json')
    pwsh = os.environ.get('GUARD_PWSH') or shutil.which('pwsh') or shutil.which('powershell')
    if not pwsh and sys.platform == 'win32':
        pwsh = str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    cfg = {'python': sys.executable, 'pwsh': pwsh or '', 'install_dir': str(root), 'protected': [str(Path.home())]}
    (root / 'runtime.json').write_text(json.dumps(cfg, ensure_ascii=False), encoding='utf-8')
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'victim.txt').write_text('可恢复的测试内容', encoding='utf-8')
    module.test_cfg, module.test_workspace = cfg, workspace
    if sys.platform == 'darwin':
        trash = Path.home() / '.Trash'
        module.test_trash_before = set(trash.iterdir()) if trash.exists() else set()
    return module


def analyze(guard, text, dialect='powershell', agent='dsh'):
    event = {'tool_name': 'pwsh' if dialect == 'powershell' else 'exec_command',
             'tool_input': {'command': text, 'shell': dialect}, 'cwd': str(guard.test_workspace)}
    return guard.analyze(event, agent, guard.test_cfg)


def require_pwsh(guard):
    if not guard.test_cfg['pwsh']:
        pytest.skip('当前平台未安装 PowerShell，仅跳过 PowerShell 运行时测试。')


@pytest.mark.parametrize('text', [
    "$taskTarget = Join-Path (Get-Location) 'victim.txt'\nRemove-Item $taskTarget -Force",
    "$taskTarget = 'victim.txt'\nRemove-Item $taskTarget -Recurse -Force",
    "Get-ChildItem -Filter '*.txt' | Remove-Item -Force",
    "foreach ($taskTarget in @('victim.txt')) { Remove-Item $taskTarget -Force }",
    "Write-Output '开始'; Remove-Item -LiteralPath 'victim.txt'; Write-Output '完成'",
])
def test_multiline_powershell_rewrites_and_converges(guard, text):
    require_pwsh(guard)
    first = analyze(guard, text)
    assert first['action'] == 'rewrite'
    rewritten = first['input']['command']
    tree, _ = guard.parse_ps(rewritten, guard.test_cfg)
    assert not any(guard.ps_command_kind(site['name']) == 'delete' for site in tree['commands'])
    assert analyze(guard, rewritten)['action'] == 'allow'


@pytest.mark.parametrize('text', [
    "Remove-Item 'victim.txt'; git clean -fd",
    "Remove-Item 'victim.txt'; [IO.File]::Delete('other.txt')",
    "Invoke-Expression 'Remove-Item victim.txt'",
])
def test_unsupported_direct_deletion_is_denied(guard, text):
    require_pwsh(guard)
    with pytest.raises(guard.GuardError):
        analyze(guard, text)


@pytest.mark.parametrize('text', [
    'rm -f victim.txt',
    'target=victim.txt\nrm -f "$target"',
    'for target in *.txt; do rm -f "$target"; done',
    'printf ready; /bin/rm -- victim.txt',
    "r''m victim.txt",
])
def test_bash_deletion_rewrites_and_converges(guard, text):
    result = analyze(guard, text, 'bash')
    assert result['action'] == 'rewrite'
    rewritten = result['input']['command']
    assert 'shell-runtime' in rewritten
    assert analyze(guard, rewritten, 'bash')['action'] == 'allow'


@pytest.mark.parametrize('text', ['command rm victim.txt', 'git clean -fd', 'find . -delete', 'eval "$code"'])
def test_bash_unsupported_deletion_is_denied(guard, text):
    with pytest.raises(guard.GuardError):
        analyze(guard, text, 'bash')


@pytest.mark.parametrize('name', ['.hidden.ps1', 'job=one.ps1', '中文 空格.ps1'])
def test_powershell_script_names_do_not_skip_content(guard, name):
    require_pwsh(guard)
    (guard.test_workspace / name).write_text("Remove-Item -LiteralPath 'victim.txt'", encoding='utf-8')
    result = analyze(guard, "& './" + name + "'")
    assert result['action'] == 'rewrite'
    assert analyze(guard, result['input']['command'])['action'] == 'allow'
    frozen = list((guard.ROOT / 'logs/rewritten').glob('*.ps1'))
    assert len(frozen) == 1 and frozen[0].read_bytes().isascii()
    assert not frozen[0].read_bytes().startswith(b'\xef\xbb\xbf')
    assert analyze(guard, "Get-Content './" + name + "'")['action'] == 'allow'


@pytest.mark.parametrize('suffix', ['.py', '.python', '.txt', '.js'])
def test_python_interpreter_selects_language_not_suffix(guard, suffix):
    require_pwsh(guard)
    (guard.test_workspace / ('code' + suffix)).write_text("from os import remove as zap\nzap('victim.txt')", encoding='utf-8')
    with pytest.raises(guard.GuardError, match='Python'):
        analyze(guard, 'python code' + suffix)


def test_node_destructured_delete_is_detected(guard):
    require_pwsh(guard)
    (guard.test_workspace / 'code.cjs').write_text("const {unlink} = require('fs'); unlink('victim.txt', () => {});", encoding='utf-8')
    with pytest.raises(guard.GuardError, match='JavaScript'):
        analyze(guard, 'node code.cjs')


@pytest.mark.parametrize('command', ['.hidden.cmd', 'call .hidden.cmd'])
def test_cmd_hidden_script_is_checked(guard, command):
    (guard.test_workspace / '.hidden.cmd').write_text('@echo off\ndel victim.txt', encoding='utf-8')
    with pytest.raises(guard.GuardError, match='批处理'):
        analyze(guard, command, 'cmd')


def test_cmd_interpreter_must_not_discard_script_rewrite(guard):
    (guard.test_workspace / 'cleanup.sh').write_text('rm -f victim.txt', encoding='utf-8')
    with pytest.raises(guard.GuardError, match='CMD.*解释器'):
        analyze(guard, 'bash cleanup.sh', 'cmd')


def test_cmd_direct_multiline_rewrites(guard):
    text = '@echo off\nset "taskTarget=victim.txt"\ndel /f "%taskTarget%"'
    result = analyze(guard, text, 'cmd')
    assert result['action'] == 'rewrite'
    assert 'shell-runtime' in result['input']['command']
    assert analyze(guard, result['input']['command'], 'cmd')['action'] == 'allow'


def test_powershell_command_launcher_checks_all_arguments(guard):
    require_pwsh(guard)
    (guard.test_workspace / 'wipe.ps1').write_text("Remove-Item -LiteralPath 'victim.txt'", encoding='utf-8')
    result = analyze(guard, "pwsh -Command 'Write-Output SAFE;' 'Get-Date;' ./wipe.ps1")
    assert result['action'] == 'rewrite'
    assert analyze(guard, result['input']['command'])['action'] == 'allow'


@pytest.mark.parametrize('text, expected', [
    ('import os; os.remove("x")', True),
    ('import os as fs; fs.remove("x")', True),
    ('from os import unlink as zap; zap("x")', True),
    ('import shutil as s; s.rmtree("x")', True),
    ('from pathlib import Path; Path("x").unlink()', True),
    ('print("os.remove(x)")', False),
])
def test_python_detection_distinguishes_calls_from_data(text, expected):
    assert python_deletes(text) is expected


def test_runtime_uses_actual_cwd_and_expanded_argv(guard, monkeypatch):
    monkeypatch.chdir(guard.test_workspace)
    spec = shell_commands.runtime_spec(['-f', 'victim.txt'], 'bash', 'rm', guard.test_cfg, guard)
    assert spec['cwd'] == str(guard.test_workspace)
    assert spec['paths'] == [{'path': 'victim.txt', 'glob': False}]


def test_runtime_refuses_expansion_into_directory_without_recursive_flag(guard, monkeypatch):
    monkeypatch.chdir(guard.test_workspace)
    (guard.test_workspace / 'folder').mkdir()
    with pytest.raises(guard.GuardError, match='目录'):
        shell_commands.runtime_spec(['folder'], 'bash', 'rm', guard.test_cfg, guard)


def test_posix_trash_failure_never_falls_back_to_delete(guard, monkeypatch):
    import send2trash
    monkeypatch.setattr(guard, 'IS_WINDOWS', False)
    monkeypatch.setattr(guard, 'checked_path', lambda raw, cwd, cfg: Path(cwd) / raw)
    monkeypatch.setattr(send2trash, 'send2trash', lambda path: (_ for _ in ()).throw(OSError('回收区不可用')))
    spec = {'paths': [{'path': 'victim.txt', 'glob': False}], 'recursive': False,
            'missing_ok': False, 'files_only': False, 'dirs_only': False, 'cwd': str(guard.test_workspace)}
    with pytest.raises(OSError, match='回收区不可用'):
        guard.recycle(spec, guard.test_cfg)
    assert (guard.test_workspace / 'victim.txt').read_text(encoding='utf-8') == '可恢复的测试内容'
