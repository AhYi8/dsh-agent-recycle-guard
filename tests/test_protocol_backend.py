"""验证钩子协议、配置引导和回收后端失败契约。"""
import base64
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from test_guard import guard, analyze, require_pwsh


def request(guard):
    return {'paths':[{'path':'victim.txt','glob':False}], 'recursive':False,'missing_ok':False,
            'files_only':False,'dirs_only':False,'cwd':str(guard.test_workspace)}


@pytest.mark.parametrize('content',['{}','{无效JSON', '[]'])
def test_invalid_config_is_rebuilt(guard,monkeypatch,content):
    guard.SETTINGS.write_text(content,encoding='utf-8')
    monkeypatch.setattr(guard.shutil,'which',lambda name:guard.test_cfg['pwsh'] or '/usr/bin/pwsh')
    result=guard.config()
    assert result['python'] and result['install_dir']==str(guard.ROOT)
    assert result['protected']==[str(Path.home())]
    assert json.loads(guard.SETTINGS.read_text(encoding='utf-8'))==result


def test_existing_config_uses_current_isolated_python(guard):
    settings = dict(guard.test_cfg, python='旧机器的失效解释器')
    guard.SETTINGS.write_text(json.dumps(settings), encoding='utf-8')
    result = guard.config()
    assert result['python'] == sys.executable.replace('\\', '/')
    assert result['protected'] == settings['protected']
    assert json.loads(guard.SETTINGS.read_text(encoding='utf-8'))['python'] == result['python']


def test_config_without_powershell_is_usable_on_posix(guard,monkeypatch):
    monkeypatch.setattr(guard,'SETTINGS',guard.ROOT/'fresh.json')
    monkeypatch.setattr(guard,'IS_WINDOWS',False)
    monkeypatch.setattr(guard.shutil,'which',lambda name:None)
    assert guard.config()['pwsh']==''


def test_config_without_powershell_fails_on_windows(guard,monkeypatch):
    monkeypatch.setattr(guard,'SETTINGS',guard.ROOT/'fresh.json')
    monkeypatch.setattr(guard,'IS_WINDOWS',True)
    monkeypatch.setattr(guard.shutil,'which',lambda name:None)
    with pytest.raises(guard.GuardError,match='PowerShell'):
        guard.config()


@pytest.mark.parametrize('result',[SimpleNamespace(returncode=1,stdout=b''), SimpleNamespace(returncode=0,stdout=b'{}'), SimpleNamespace(returncode=0,stdout=b'{"limitExceeded":true}')])
def test_invalid_parser_response_fails_closed(guard,monkeypatch,result):
    monkeypatch.setattr(guard.subprocess,'run',lambda *args,**kwargs:result)
    with pytest.raises(guard.GuardError):
        guard.parse_ps('Get-Date',dict(guard.test_cfg,pwsh='configured-pwsh'))


@pytest.mark.parametrize('raw', ['{"tool_name":"pwsh","tool_input":[]}', '不是JSON', 'x'*262145], ids=['参数类型错误','无效JSON','超过长度上限'])
def test_cli_analysis_errors_return_deny(guard,monkeypatch,capsys,raw):
    monkeypatch.setattr(sys,'argv',['guard.py','analyze','--agent','dsh'])
    monkeypatch.setattr(sys,'stdin',io.StringIO(raw))
    assert guard.main()==0
    assert json.loads(capsys.readouterr().out)['action']=='deny'


@pytest.mark.parametrize('mode',['analyze','hook'])
def test_cli_allow_contract(guard,monkeypatch,capsys,mode):
    monkeypatch.setattr(sys,'argv',['guard.py',mode,'--agent','dsh'])
    monkeypatch.setattr(sys,'stdin',io.StringIO('{}'))
    assert guard.main()==0
    result=json.loads(capsys.readouterr().out)
    assert result==({'action':'allow'} if mode=='analyze' else {'guardAllow':True})


def test_cli_recycle_payload_contract(guard,monkeypatch,capsys):
    payload=base64.b64encode(json.dumps(request(guard)).encode()).decode().rstrip('=')
    monkeypatch.setattr(sys,'argv',['guard.py','recycle','--payload',payload])
    monkeypatch.setattr(guard,'recycle',lambda spec,cfg:[{'original':str(guard.test_workspace/'victim.txt'),'verified':True}])
    assert guard.main()==0
    assert json.loads(capsys.readouterr().out)['receipts'][0]['verified']


@pytest.mark.parametrize('mode,args',[('recycle',['--payload','invalid!']),('shell-runtime',['--dialect','bash','--name','wipe','--','victim.txt']),('runtime',[])])
def test_cli_runtime_error_never_runs_original(guard,monkeypatch,capsys,mode,args):
    monkeypatch.setattr(sys,'argv',['guard.py',mode,*args])
    monkeypatch.setattr(sys,'stdin',io.StringIO('{}'))
    assert guard.main()==2
    assert '阻止' in capsys.readouterr().err
    assert (guard.test_workspace/'victim.txt').exists()


def test_cli_runtime_verified_payload(guard,monkeypatch,capsys):
    cfg = guard.config()
    payload=base64.b64encode(json.dumps(request(guard)).encode()).decode().rstrip('=')
    monkeypatch.setattr(sys,'argv',['guard.py','runtime','--agent','dsh'])
    monkeypatch.setattr(sys,'stdin',io.StringIO('{}'))
    monkeypatch.setattr(guard,'analyze',lambda *args,**kwargs:{'action':'rewrite','input':{'command':guard.recycle_command(payload,'powershell',cfg)}})
    monkeypatch.setattr(guard,'recycle',lambda spec,cfg:[{'original':str(guard.test_workspace/'victim.txt')}])
    assert guard.main()==0
    assert json.loads(capsys.readouterr().out)['receipts']


def test_cli_audit_failure_changes_rewrite_to_deny(guard,monkeypatch,capsys):
    monkeypatch.setattr(sys,'argv',['guard.py','analyze'])
    monkeypatch.setattr(sys,'stdin',io.StringIO('{}'))
    monkeypatch.setattr(guard,'analyze',lambda *args,**kwargs:{'action':'rewrite','input':{'command':'safe'}})
    monkeypatch.setattr(guard,'audit',lambda record:(_ for _ in ()).throw(OSError('不可写')))
    assert guard.main()==0
    assert json.loads(capsys.readouterr().out)['action']=='deny'


@pytest.mark.skipif(sys.platform!='win32',reason='Windows COM 回调契约只在 Windows 验证。')
def test_windows_sink_refuses_permanent_delete(guard):
    from win32com.shell import shellcon
    from win32com.server.exception import COMException
    sink=guard.make_sink()
    with pytest.raises(COMException):
        sink.PreDeleteItem(0,None)
    assert sink.rejected
    allowed=guard.make_sink()
    allowed.PreDeleteItem(shellcon.TSF_DELETE_RECYCLE_IF_POSSIBLE,None)
    assert not allowed.rejected
    allowed.PostDeleteItem(0,None,-1,None)
    assert allowed.rejected


@pytest.mark.skipif(sys.platform!='win32',reason='Windows COM 后端失败只在 Windows 验证。')
@pytest.mark.parametrize('aborted,failed,receipt',[(True,False,None),(False,True,None),(False,False,None),(False,False,'C:/invalid-receipt')])
def test_windows_backend_requires_valid_receipt(guard,monkeypatch,aborted,failed,receipt):
    import pythoncom
    from win32com.shell import shell
    operation=SimpleNamespace(SetOperationFlags=lambda flags:None,DeleteItem=lambda item,sink:None,
                              PerformOperations=lambda:1 if failed else 0,GetAnyOperationsAborted=lambda:aborted)
    monkeypatch.setattr(pythoncom,'CoCreateInstance',lambda *args:operation)
    monkeypatch.setattr(pythoncom,'WrapObject',lambda *args:None)
    monkeypatch.setattr(shell,'SHCreateItemFromParsingName',lambda *args:None)
    monkeypatch.setattr(guard,'make_sink',lambda:SimpleNamespace(rejected=False,receipt=receipt))
    with pytest.raises(guard.GuardError):
        guard.recycle(request(guard),guard.test_cfg)
    assert (guard.test_workspace/'victim.txt').exists()


@pytest.mark.parametrize('mode,name,args', [('bash','rm',['--bad','victim.txt']),('bash','unlink',['a','b']),('cmd','del',['/s','victim.txt']),('powershell','Remove-Item',['-Bad','victim.txt'])])
def test_unrecognized_delete_options_are_rejected(guard,mode,name,args):
    parts=[guard.Part(name)]+[guard.Part(arg,parameter=mode=='powershell' and arg.startswith('-')) for arg in args]
    with pytest.raises(guard.GuardError):
        guard.delete_spec(parts,mode)


@pytest.mark.parametrize('path',['con.txt','nul','C:\\test\\a.','\\\\server\\share\\x','C:\\file:stream'])
@pytest.mark.skipif(sys.platform!='win32',reason='仅 Windows 路径限制。')
def test_windows_special_paths_rejected(guard,path):
    with pytest.raises(guard.GuardError):
        guard.checked_path(path,str(guard.test_workspace),guard.test_cfg)
