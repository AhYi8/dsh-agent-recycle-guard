"""路径、协议、脚本入口及回收失败的边界回归。"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from test_guard import guard, analyze, require_pwsh
from script_checks import Inspector


@pytest.mark.parametrize('event', [None, [], {'tool_input': []}, {'tool_name':'pwsh','tool_input':{'command':4}}, {'tool_name':'pwsh','tool_input':{'command':'a'*131073}}])
def test_illegal_tool_input_is_rejected(guard, event):
    with pytest.raises(guard.GuardError):
        guard.analyze(event, 'dsh', guard.test_cfg)


@pytest.mark.parametrize('event', [{}, {'tool_name':'read_file','tool_input':{'path':'x'}}, {'tool_name':'pwsh','tool_input':{}}])
def test_non_command_tools_are_unchanged(guard, event):
    assert guard.analyze(event,'dsh',guard.test_cfg)['action']=='allow'


@pytest.mark.parametrize('path', ['', '../victim.txt', '/', 'bad\npath'])
def test_invalid_target_paths_rejected(guard, path):
    with pytest.raises(guard.GuardError):
        guard.checked_path(path, str(guard.test_workspace), guard.test_cfg)


def test_install_and_home_ancestors_are_protected(guard):
    assert guard.protected(guard.ROOT, guard.test_cfg)
    assert guard.protected(guard.ROOT.parent, guard.test_cfg)
    assert guard.protected(Path.home(), guard.test_cfg)
    assert not guard.protected(guard.test_workspace/'victim.txt',guard.test_cfg)


@pytest.mark.parametrize('update', [{'paths':[]},{'paths':[{}]},{'recursive':1},{'cwd':'relative'},{'unknown':True}])
def test_invalid_recycle_request_rejected(guard, update):
    spec={'paths':[{'path':'victim.txt','glob':False}],'recursive':False,'missing_ok':False,'files_only':False,'dirs_only':False,'cwd':str(guard.test_workspace)}
    spec.update(update)
    with pytest.raises(guard.GuardError):
        guard.resolve_targets(spec,guard.test_cfg)


def test_folder_without_recursive_permission_is_preserved(guard):
    folder=guard.test_workspace/'folder'
    folder.mkdir()
    (folder/'child').write_text('保留',encoding='utf-8')
    spec={'paths':[{'path':'folder','glob':False}],'recursive':False,'missing_ok':False,'files_only':False,'dirs_only':False,'cwd':str(guard.test_workspace)}
    with pytest.raises(guard.GuardError,match='递归'):
        guard.resolve_targets(spec,guard.test_cfg)
    assert (folder/'child').exists()


def test_target_glob_and_parent_deduplication(guard):
    folder=guard.test_workspace/'folder'
    folder.mkdir()
    (folder/'child.txt').write_text('保留',encoding='utf-8')
    spec={'paths':[{'path':'folder','glob':False},{'path':'folder/child.txt','glob':False}],'recursive':True,'missing_ok':False,'files_only':False,'dirs_only':False,'cwd':str(guard.test_workspace)}
    assert guard.resolve_targets(spec,guard.test_cfg)==[folder]
    spec['paths']=[{'path':'*.txt','glob':True}]
    assert guard.resolve_targets(spec,guard.test_cfg)==[guard.test_workspace/'victim.txt']


def test_unmatched_force_target_is_safe_empty_set(guard):
    spec={'paths':[{'path':'missing.txt','glob':False}],'recursive':False,'missing_ok':True,'files_only':False,'dirs_only':False,'cwd':str(guard.test_workspace)}
    assert guard.resolve_targets(spec,guard.test_cfg)==[]


@pytest.mark.parametrize('command', ['Remove-Item victim.txt -WhatIf', "Remove-Item -LiteralPath 'victim.txt'", "Remove-Item -LiteralPath 'missing.txt'"])
def test_simple_delete_and_whatif(guard, command):
    require_pwsh(guard)
    if 'missing' in command:
        with pytest.raises(guard.GuardError,match='不存在'):
            analyze(guard,command)
        return
    result=analyze(guard,command)
    assert result['action']=='rewrite'
    assert analyze(guard,result['input']['command'])['action']=='allow'
    assert (guard.test_workspace/'victim.txt').exists()


@pytest.mark.parametrize('command', ['python -c "from os import remove as zap; zap(\'victim.txt\')"', 'node --eval "const {rm} = require(\'fs\'); rm(\'victim.txt\', () => {});"', 'cmd /c python code.py'])
def test_inline_and_cmd_wrapped_interpreters(guard,command):
    require_pwsh(guard)
    (guard.test_workspace/'code.py').write_text("import os; os.remove('victim.txt')",encoding='utf-8')
    with pytest.raises(guard.GuardError):
        analyze(guard,command)


@pytest.mark.parametrize('command', ['python code.py','python -m pip --version','Get-Content code.py'])
def test_clean_scripts_and_data_remain_usable(guard,command):
    require_pwsh(guard)
    (guard.test_workspace/'code.py').write_text("print('安全')",encoding='utf-8')
    assert analyze(guard,command)['action']=='allow'


def test_nested_powershell_script_is_rewritten(guard):
    require_pwsh(guard)
    (guard.test_workspace/'inner.ps1').write_text("Remove-Item -LiteralPath 'victim.txt'",encoding='utf-8')
    (guard.test_workspace/'outer.ps1').write_text("& './inner.ps1'\nWrite-Output done",encoding='utf-8')
    result=analyze(guard,"& './outer.ps1'")
    assert result['action']=='rewrite'
    assert analyze(guard,result['input']['command'])['action']=='allow'


def test_script_and_direct_delete_are_both_rewritten(guard):
    require_pwsh(guard)
    (guard.test_workspace/'inner.ps1').write_text("Remove-Item -LiteralPath 'victim.txt'",encoding='utf-8')
    result=analyze(guard,"& './inner.ps1'; Remove-Item -LiteralPath 'victim.txt'")
    assert result['action']=='rewrite'
    tree,_=guard.parse_ps(result['input']['command'],guard.test_cfg)
    assert not any(guard.ps_command_kind(site['name'])=='delete' for site in tree['commands'])
    assert analyze(guard,result['input']['command'])['action']=='allow'


@pytest.mark.parametrize('content', ["Write-Output $PSScriptRoot; Remove-Item victim.txt", "Write-Output ${PSCommandPath}; Remove-Item victim.txt"])
def test_changed_script_location_semantics_are_rejected(guard,content):
    require_pwsh(guard)
    (guard.test_workspace/'rooted.ps1').write_text(content,encoding='utf-8')
    with pytest.raises(guard.GuardError,match='原位置'):
        analyze(guard,"& './rooted.ps1'")


def test_bash_script_rewrite_and_source_rejection(guard):
    (guard.test_workspace/'wipe.sh').write_text('rm -f victim.txt',encoding='utf-8')
    result=analyze(guard,'bash wipe.sh','bash')
    assert result['action']=='rewrite'
    assert analyze(guard,result['input']['command'],'bash')['action']=='allow'
    with pytest.raises(guard.GuardError,match='source'):
        analyze(guard,'source wipe.sh','bash')


def test_inline_bash_and_read_only_commands(guard):
    result=analyze(guard,"bash -c 'rm -f victim.txt'",'bash')
    assert result['action']=='rewrite'
    assert analyze(guard,result['input']['command'],'bash')['action']=='allow'
    assert analyze(guard,"printf 'rm -f x'",'bash')['action']=='allow'


@pytest.mark.parametrize('command',['if exist victim.txt del victim.txt','d^el victim.txt','cmd /c del victim.txt'])
def test_complex_cmd_deletion_is_rejected(guard,command):
    with pytest.raises(guard.GuardError):
        analyze(guard,command,'cmd')


def test_unreadable_large_and_unknown_encoding_script_limits(guard):
    event={'tool_input':{},'cwd':str(guard.test_workspace)}
    checker=Inspector(guard,guard.test_cfg,event,'dsh')
    assert checker.content(guard.test_workspace/'missing.py') is None
    large=guard.test_workspace/'large.py'
    large.write_bytes(b'x'*131073)
    assert checker.content(large) is None
    large.write_bytes(b'\x81\x82')
    assert checker.content(large) is None
    large.write_bytes('print(1)'.encode('utf-16'))
    assert checker.content(large)=='print(1)'


def test_precise_guard_entry_not_directory_exemption(guard):
    args=[{'value':str(guard.ROOT/'guard.py')},{'value':'shell-runtime'}]
    assert guard.is_guard_call(sys.executable,args,guard.test_cfg)
    assert not guard.is_guard_call(sys.executable,[{'value':str(guard.ROOT/'other.py')},{'value':'shell-runtime'}],guard.test_cfg)


@pytest.mark.parametrize('agent',['codex','claude'])
def test_optional_agent_protocols_keep_rewrite(guard,agent):
    require_pwsh(guard)
    event={'tool_name':'pwsh','tool_input':{'command':"$taskTarget='victim.txt'; Remove-Item $taskTarget -Force"},'cwd':str(guard.test_workspace)}
    run=subprocess.run([sys.executable,'-X','utf8',str(guard.ROOT/'guard.py'),'hook','--agent',agent],input=json.dumps(event),capture_output=True,encoding='utf-8',timeout=25)
    assert run.returncode==0,run.stderr
    result=json.loads(run.stdout)['hookSpecificOutput']
    assert result['permissionDecision']=='allow'
    assert 'recycle_powershell.ps1' in result['updatedInput']['command']
