"""Agent Shell 删除防护：静态解析、协议适配与严格回收，不提供永久删除退路。"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parent
SETTINGS = ROOT / "runtime.json"
DELETE_NAMES = {"rm", "unlink", "rmdir", "rd", "del", "erase", "remove-item", "ri"}
# 此处仅用于发现需要进一步解析或拒绝的语义，不用正则替换原命令。
DANGER = re.compile(r"(?i)(?<![\w-])(?:rm|unlink|rmdir|rd|del|erase|remove-item|ri|shred|sdelete|removefile|removedirectory)(?![\w-])|\b(?:deletefile|deletefolder|rmtree|rimraf)\b|(?:\.|::)\s*(?:delete|unlink|rmdir|rm|remove)(?:sync|async)?\s*\(|\bfind\b[^\n]*(?:-delete|-exec)|\bgit\b[^\n]*\b(?:clean|rm|reset|restore)\b|\brobocopy\b[^\n]*/(?:mir|purge)\b|\brsync\b[^\n]*--delete|\b(?:format|diskpart|clear-recyclebin|remove-partition|clear-disk|initialize-disk)\b")
OPAQUE = re.compile(r"(?i)\b(?:invoke-expression|iex|eval)\b|-(?:encodedcommand|enc|ec|e)(?=\s)|\bbase64\b[^\n]*(?:--decode|\s-d\b)")
SHELL_NAMES = {"bash", "powershell", "pwsh", "exec_command", "shell", "shell_command", "run_shell_command", "run_terminal_cmd", "monitor"}
PS_DELETE_NAMES = DELETE_NAMES - {"unlink"}
# 复杂调用使用允许清单，而非枚举永远列不全的外部删除程序。
PS_COMPANIONS = {"get-childitem", "gci", "dir", "ls", "get-item", "gi", "test-path", "get-location", "pwd", "set-location", "cd", "chdir", "write-output", "write-host", "echo", "get-date", "select-object", "select", "where-object", "where", "?", "foreach-object", "%", "sort-object", "sort", "measure-object", "join-path", "split-path", "format-table", "format-list", "format-wide", "format-custom", "format-hex", "ft", "fl", "fw", "fc", "out-null", "out-string", "out-default", "out-host", "group-object", "compare-object", "get-content", "gc", "select-string", "sls", "get-member", "gm"}
PS_TEXT_TOOLS = {"rg", "grep", "printf"}


class GuardError(Exception):
    """无法安全转换时使用明确拒绝，原始命令不得继续执行。"""


@dataclass(frozen=True)
class Part:
    value: str
    quoted: bool = False
    parameter: bool = False
    group: int = 0


def config():
    # 零配置安装即用：首次运行自动引导 runtime.json 与 recycle.cmd。
    # 机器相关路径（python、pwsh、安装目录、受保护路径）就地探测生成，
    # 之后以既有文件为准，不覆盖用户手工调整。
    settings = None
    if SETTINGS.exists():
        try:
            settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            settings = None
        # 文件存在但字段不完整（如空对象）时必须重建：不能因文件存在就认定引导完成。
        if not isinstance(settings, dict) or not all(
                isinstance(settings.get(k), (str, list)) and settings.get(k) for k in ("python", "pwsh", "install_dir", "protected")):
            settings = None
    if settings is None:
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if not pwsh:
            raise GuardError("未找到 PowerShell（pwsh/powershell），无法初始化删除防护。")
        settings = {
            "python": sys.executable.replace("\\", "/"),
            "pwsh": pwsh.replace("\\", "/"),
            "install_dir": str(ROOT),
            # 默认把整个用户主目录列为受保护路径，与既有安装的防护强度一致。
            "protected": [str(Path.home())],
        }
        SETTINGS.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
        # recycle.cmd 需要真实 python 路径；按当前解释器生成启动器。
        (ROOT / "recycle.cmd").write_bytes(
            ('@echo off\r\n"' + sys.executable + '" -X utf8 "%~dp0guard.py" recycle --payload "%~1"\r\nexit /b %errorlevel%\r\n').encode("utf-8")
        )
    return settings


def base_name(name):
    return re.split(r"[/\\]", str(name).lower())[-1].removesuffix(".exe").removesuffix(".cmd")


def looks_dangerous(command):
    # 同时发现 PowerShell 的反引号及 Shell 的转义/拼接命令名。
    normalized = command.replace("`", "").replace("\\\n", "")
    # 普通格式参数不是磁盘格式化命令，避免 Get-Date -Format 等读取操作误报。
    normalized = re.sub(r"(?i)(?<![\w-])-format\b", "-displaypattern", normalized)
    # Format-Table/List 等格式化输出 cmdlet 同样不是磁盘格式化，避免纯查询管道被误判。
    normalized = re.sub(r"(?i)(?<![\w-])format-(?:table|list|wide|custom|hex)(?![\w.-])", "formatted-output", normalized)
    joined = re.sub(r"['\"\\]", "", normalized)
    extra = re.compile(r"(?i)(?<![\w-])(?:delete|remove|remove-[a-z]+)(?![\w-])")
    return bool(DANGER.search(normalized) or DANGER.search(joined) or extra.search(normalized) or extra.search(joined))


def parse_ps(command, cfg):
    result = subprocess.run(
        [cfg["pwsh"], "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(ROOT / "parse_powershell.ps1")],
        # Windows 文本模式会把 LF 转成 CRLF，导致 AST 位置与原文不一致；按字节传输。
        input=command.encode("utf-8"), capture_output=True, timeout=12, check=False,
    )
    if result.returncode:
        raise GuardError("PowerShell 静态解析失败，已阻止命令。")
    try:
        data = json.loads(result.stdout)
        return data, [Part(**p) for p in data["parts"]]
    except (ValueError, TypeError, KeyError) as error:
        raise GuardError("解析器返回了非法结果。") from error


def parse_literal(command, dialect):
    """仅接收一条静态命令，保留引号信息以区分 Bash 通配符。"""
    parts, buf = [], []
    quote, quoted, active = None, False, False
    i = 0
    while i < len(command):
        char = command[i]
        if quote:
            if char == quote:
                quote = None
            elif dialect == "cmd" and char in "%!^":
                raise GuardError("CMD 引号不能阻止变量展开，已拒绝不确定路径。")
            elif dialect == "bash" and quote == '"' and char in "$`":
                raise GuardError("删除参数包含动态展开。")
            elif dialect == "bash" and quote == '"' and char == "\\" and i + 1 < len(command) and command[i + 1] in '\\"$`':
                i += 1
                buf.append(command[i])
            else:
                buf.append(char)
        elif char in ("'", '"') and (dialect != "cmd" or char == '"'):
            if dialect == "bash" and any(c in "*?[" for c in buf):
                raise GuardError("不支持混合引用的通配符路径。")
            quote, quoted, active = char, True, True
        elif dialect == "bash" and (char == "#" and not active or char == "~" and not active):
            raise GuardError("删除参数中的注释或用户目录展开须改为明确路径。")
        elif dialect == "bash" and quoted and char in "*?[":
            raise GuardError("不支持混合引用的通配符路径。")
        elif char in "\r\n;|&()<>" or (dialect == "bash" and char in "$`{}") or (dialect == "cmd" and char in "%!^=,"):
            raise GuardError("复合命令、重定向或动态删除不能安全转换；请拆成单条字面量删除。")
        elif char.isspace():
            if active:
                parts.append(Part("".join(buf), quoted))
                buf, quoted, active = [], False, False
        elif dialect == "bash" and char == "\\":
            i += 1
            if i == len(command):
                raise GuardError("删除命令以不完整的转义结束。")
            if command[i] in "*?[":
                raise GuardError("不猜测转义通配符；请使用完整引用的字面量路径。")
            buf.append(command[i])
            active = True
        else:
            buf.append(char)
            active = True
        i += 1
    if quote:
        raise GuardError("删除命令引号不完整。")
    if active:
        parts.append(Part("".join(buf), quoted))
    return parts


def delete_spec(parts, dialect):
    name = base_name(parts[0].value)
    if name not in DELETE_NAMES:
        raise GuardError("检测到嵌套或不支持的删除语义，已阻止原命令。")
    recursive, missing_ok, literal, end_options = False, False, False, False
    paths = []
    dry_run = False
    path_parameter, awaiting_path, target_group = False, False, None
    for p in parts[1:]:
        value, low = p.value, p.value.lower()
        if dialect == "powershell":
            if awaiting_path and p.parameter:
                raise GuardError("路径参数缺少字面量值。")
            if p.parameter:
                if low in ("-path", "-literalpath", "-lp"):
                    if path_parameter or paths:
                        raise GuardError("不支持重复路径参数或显式与位置路径混用。")
                    path_parameter, awaiting_path = True, True
                    literal = low != "-path"
                elif low in ("-recurse", "-r"):
                    recursive = True
                elif low == "-force":
                    pass
                elif low == "-whatif":
                    dry_run = True
                else:
                    raise GuardError("不支持此 PowerShell 删除选项；已阻止原命令：" + value)
                continue
            if value.startswith(("-", "~")):
                raise GuardError("以选项符号或用户目录展开开头的路径需改为明确绝对路径。")
            if target_group is not None and p.group != target_group:
                raise GuardError("多个路径请放在同一个静态数组中，避免参数绑定歧义。")
            target_group, awaiting_path = p.group, False
            paths.append({"path": value, "glob": not literal})
            continue
        if name == "unlink" and not end_options and value.startswith("-") and value != "--":
            raise GuardError("unlink 不支持此删除选项。")
        if dialect == "bash" and name in {"rmdir", "rd"} and not end_options and value.startswith("-") and value not in {"--", "-v", "--verbose"}:
            raise GuardError("rmdir 不支持此选项；不将非法选项扩大为递归删除。")
        if not end_options and value == "--" and dialect == "bash":
            end_options = True
        elif not end_options and dialect == "bash" and value.startswith("-"):
            if value in ("--recursive", "--force", "--dir", "--verbose"):
                recursive |= value == "--recursive"
                missing_ok |= value == "--force"
            elif re.fullmatch(r"-[rfRdv]+", value):
                recursive |= bool(set(value) & {"r", "R"})
                missing_ok |= "f" in value
            else:
                raise GuardError("不支持此删除选项；已阻止原命令：" + value)
        elif not end_options and dialect == "cmd" and value.startswith("/"):
            if low == "/s" and name in {"rd", "rmdir"}:
                recursive = True
            elif low != "/q" and not (low == "/f" and name in {"del", "erase"}):
                raise GuardError("不支持此 CMD 删除选项；已阻止原命令：" + value)
        else:
            paths.append({"path": value, "glob": not literal and (dialect != "bash" or not p.quoted)})
    if not paths or awaiting_path:
        raise GuardError("删除命令缺少明确路径。")
    if name == "unlink" and len(paths) != 1:
        raise GuardError("unlink 只能接收一个路径。")
    return {"paths": paths, "recursive": recursive, "missing_ok": missing_ok, "files_only": dialect == "cmd" and name in {"del", "erase"}, "dirs_only": name in {"rmdir", "rd"} and dialect != "powershell"}, dry_run


def resolve_cwd(value, session_cwd):
    if not isinstance(session_cwd, str) or not os.path.isabs(session_cwd):
        raise GuardError("缺少可信的绝对工作目录，已阻止删除。")
    if ".." in re.split(r"[\\/]", session_cwd) or isinstance(value, str) and ".." in re.split(r"[\\/]", value):
        raise GuardError("工作目录不能包含父目录跳转。")
    if value is None:
        return os.path.abspath(session_cwd)
    if not isinstance(value, str) or not value:
        raise GuardError("非法工作目录。")
    return os.path.abspath(os.path.join(session_cwd, value))


def protected(path, cfg):
    target = os.path.normcase(str(path))
    # 不允许删除防护程序、配置以及这些路径的祖先；工作目录内的其他文件不豁免。
    for value in [cfg["install_dir"], *cfg["protected"]]:
        value = os.path.normcase(os.path.abspath(value))
        if target == value or value.startswith(target.rstrip("\\/") + os.sep):
            return True
        if value == os.path.normcase(os.path.abspath(cfg["install_dir"])) and target.startswith(value + os.sep):
            return True
    return False


def checked_path(raw, cwd, cfg):
    if not isinstance(raw, str) or not raw or len(raw) > 240 or any(ord(c) < 32 for c in raw):
        raise GuardError("路径为空、过长或包含控制字符。")
    raw = raw.replace("/", "\\")
    if raw.startswith("\\\\") or raw.startswith("\\?") or re.search(r"[:<>|\"]", raw[2:]) or (":" in raw and not re.match(r"^[A-Za-z]:\\", raw)):
        raise GuardError("仅支持本地文件系统路径，不支持 UNC、设备路径、数据流或其他 Provider。")
    if raw.startswith("\\"):
        raise GuardError("请使用完整盘符路径，避免根相对路径歧义。")
    components = re.split(r"[\\/]", raw[3:] if re.match(r"^[A-Za-z]:", raw) else raw)
    # 先折叠 .. 会掩盖经过目录联接的真实遍历顺序，直接拒绝以收紧边界。
    if ".." in components:
        raise GuardError("删除路径不能包含父目录跳转，请使用明确绝对路径。")
    if any(c not in {"", ".", ".."} and (c.endswith((".", " ")) or re.match(r"(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", c)) for c in components):
        raise GuardError("拒绝 Windows 保留名称或尾部点/空格路径。")
    path = Path(os.path.abspath(os.path.join(cwd, raw)))
    if str(path) == path.anchor or protected(path, cfg):
        raise GuardError("拒绝删除磁盘根、用户目录、防护程序或受保护配置。")
    if any(p.lower() in {"$recycle.bin", "recycler", "system volume information"} for p in path.parts):
        raise GuardError("拒绝操作系统回收区或卷管理目录。")
    import ctypes
    if ctypes.windll.kernel32.GetDriveTypeW(path.anchor) != 3:
        raise GuardError("仅支持有回收能力的本地固定磁盘。")
    for ancestor in [path, *path.parents]:
        if ancestor.exists() or ancestor.is_symlink():
            attrs = ancestor.lstat().st_file_attributes
            if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise GuardError("拒绝符号链接、目录联接或其他重解析路径。")
    return path


def resolve_targets(spec, cfg, deep=True):
    if not isinstance(spec, dict) or set(spec) != {"paths", "recursive", "missing_ok", "files_only", "dirs_only", "cwd"}:
        raise GuardError("非法回收请求结构。")
    if not isinstance(spec["cwd"], str) or not os.path.isabs(spec["cwd"]):
        raise GuardError("回收请求缺少绝对工作目录。")
    if ".." in re.split(r"[\\/]", spec["cwd"]):
        raise GuardError("回收工作目录不能包含父目录跳转。")
    if any(type(spec[k]) is not bool for k in ("recursive", "missing_ok", "files_only", "dirs_only")):
        raise GuardError("回收选项必须为布尔类型。")
    if not isinstance(spec["paths"], list) or not 1 <= len(spec["paths"]) <= 1000:
        raise GuardError("路径数量必须在 1 至 1000 之间。")
    targets = []
    for entry in spec["paths"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "glob"} or type(entry["glob"]) is not bool:
            raise GuardError("非法路径项。")
        raw = entry["path"]
        path = checked_path(raw, spec["cwd"], cfg)
        wildcard = entry["glob"] and any(x in str(path) for x in "*?[")
        if not entry["glob"] and any(x in str(path) for x in "*?"):
            raise GuardError("Windows 字面量文件名不能包含通配符。")
        if wildcard:
            if any(x in str(path.parent) for x in "*?[") or "[" in path.name:
                raise GuardError("仅支持末级文件名中的 * 和 ?，复杂通配符已阻止。")
            candidates = sorted((p for p in path.parent.iterdir() if fnmatch.fnmatch(p.name.lower(), path.name.lower())), key=str)
        else:
            candidates = [path] if path.exists() else []
        if not candidates and not spec["missing_ok"]:
            raise GuardError("路径不存在或未匹配到文件：" + str(path))
        for candidate in candidates:
            candidate = checked_path(str(candidate), spec["cwd"], cfg)
            if spec["files_only"] and candidate.is_dir():
                raise GuardError("CMD del 的目录语义不转换，请使用明确的文件列表。")
            if spec["dirs_only"] and not candidate.is_dir():
                raise GuardError("rmdir/rd 目标不是目录。")
            if candidate.is_dir():
                if not spec["recursive"] and next(candidate.iterdir(), None) is not None:
                    raise GuardError("非空目录需要明确的递归选项。")
                count = 0
                for directory, dirs, files in os.walk(candidate, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)) if deep else []:
                    for name in dirs + files:
                        count += 1
                        if count > 200000:
                            raise GuardError("目录超过安全扫描上限，已阻止删除。")
                        checked_path(str(Path(directory) / name), spec["cwd"], cfg)
            if candidate not in targets:
                targets.append(candidate)
            if len(targets) > 1000:
                raise GuardError("通配符展开超过 1000 个目标，已阻止删除。")
    # 父目录已包含的子路径只回收一次，避免后续操作指向已消失的文件。
    return [p for p in targets if not any(q in p.parents for q in targets)]


def ps_command_kind(name):
    name = str(name).lower()
    if name.startswith("microsoft.powershell.management\\"):
        name = name.split("\\", 1)[1]
    if name in PS_DELETE_NAMES:
        return "delete"
    if name in PS_COMPANIONS:
        return "safe"
    return "unknown"


def replace_ps_deletes(ast, command, event=None):
    """校验并把文本中的 PowerShell 删除调用替换为回收入口；无删除调用时返回 None。

    同时服务内联命令与 .ps1 脚本内容：只替换实际删除调用位置，
    不注入全局函数，也不执行输入来推测路径。
    """
    runner = str(ROOT / "recycle_powershell.ps1").replace("\\", "/")
    sites = ast["commands"]
    trusted = [s for s in sites if s["name"] == runner]
    deletes = [s for s in sites if ps_command_kind(s["name"]) == "delete"]
    kinds = [ps_command_kind(s["name"]) for s in sites]
    known = all(kind != "unknown" or site["name"] == runner or
                not deletes and not trusted and str(site["name"]).lower() in PS_TEXT_TOOLS
                for site, kind in zip(sites, kinds))
    if ast["unsafe"] or not known or any(s["invocation"] == "Dot" for s in sites):
        raise GuardError("复杂 PowerShell 命令包含不支持的程序、方法、定义或状态修改；请拆开执行。")
    for site in deletes + trusted:
        allowed = {"path", "literalpath", "lp", "recurse", "r", "force", "whatif", "confirm"}
        canonical = [{"lp": "literalpath", "r": "recurse"}.get(p, p) for p in site["parameters"]]
        if site["splat"] or not set(site["parameters"]) <= allowed or len(canonical) != len(set(canonical)):
            raise GuardError("复杂删除不支持歧义参数、重复参数或参数展开，请使用明确参数名。")
    if not deletes:
        return None
    if event is not None:
        data = event.get("tool_input", event.get("toolInput", {}))
        resolve_cwd(data.get("workdir", data.get("cwd")) if isinstance(data, dict) else None, event.get("cwd"))
    # PowerShell 的 Extent 偏移以 UTF-16 为单位，不能直接用 Python 的 Unicode 索引。
    encoded = command.encode("utf-16-le")
    for site in sorted(deletes, key=lambda s: s["start"], reverse=True):
        replacement = ("" if site["invocation"] == "Ampersand" else "& ") + "'" + runner.replace("'", "''") + "'"
        encoded = encoded[:site["start"] * 2] + replacement.encode("utf-16-le") + encoded[site["end"] * 2:]
    return encoded.decode("utf-16-le")


def rewrite_ps_calls(ast, command, data, key, agent, event):
    """内联命令入口：复用 replace_ps_deletes，产出工具输入级改写决策。"""
    runner = str(ROOT / "recycle_powershell.ps1").replace("\\", "/")
    sites = ast["commands"]
    deletes = [s for s in sites if ps_command_kind(s["name"]) == "delete"]
    trusted = [s for s in sites if s["name"] == runner]
    if deletes or trusted:
        resolve_cwd(data.get("workdir", data.get("cwd")), event.get("cwd"))
    updated_text = replace_ps_deletes(ast, command)
    if updated_text is None:
        # 删除字样仅在数据中出现，或所有删除调用已替换；仍检查整条命令，不能前缀即放行。
        return {"action": "allow"}
    updated = dict(data)
    updated[key] = updated_text
    if agent == "codex":
        updated["command"] = updated[key]
    return {"action": "rewrite", "input": updated, "reason": "已将实际 PowerShell 文件删除调用替换为回收入口；变量与管道目标在执行时校验。"}


SCRIPT_EXTS = {".ps1", ".cmd", ".bat"}


def script_target(parts):
    r"""定位命令中的第一个本地脚本文件引用，返回 (下标, 原始引用) 或 None。

    覆盖三类形态：直接调用 .\cleanup.ps1、powershell -File x.ps1、
    以及 PowerShell/CMD 中运行 .cmd/.bat 批处理。
    """
    if not parts:
        return None
    first = parts[0].value.lower()
    head = base_name(parts[0].value)
    if head in {"powershell", "pwsh"}:
        for i, p in enumerate(parts[1:], 1):
            if p.value.lower() in ("-file", "-f") and i + 1 < len(parts):
                nxt = parts[i + 1].value.lower()
                if nxt.endswith(".ps1"):
                    return i + 1, parts[i + 1].value
                if nxt.endswith((".cmd", ".bat")):
                    return i + 1, parts[i + 1].value
        return None
    for i, p in enumerate(parts):
        if p.value.lower().endswith((".cmd", ".bat", ".ps1")):
            return i, p.value
    return None


QUOTED_SPAN = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")


def collect_script_refs(command):
    r"""从命令原文收集全部本地脚本引用。

    引号内的整段提取（带空格、方括号的路径如 '.\wipe space.ps1'、
    '.\syntax-special\[wipe].ps1' 不能被空格/括号拆词破坏）；引号外再按
    Shell 分隔符扫描，覆盖多语句、条件块、-File/-Command 包装等形态。
    反引号转义按语义剔除（`wi`pe.ps1` → wipe.ps1）。
    未加引号却含方括号的路径是 PowerShell 通配符语义，无法证明指向
    哪个文件，直接拒绝。
    """
    refs = []

    def _add(token, quoted):
        token = token.strip("\"'") if quoted else token
        if not token or token.startswith("-") or token in refs:
            return
        if not quoted and ("[" in token or "]" in token):
            raise GuardError("未引用的方括号路径是通配符语义，无法确定实际脚本，已拒绝。")
        if token.lower().endswith((".ps1", ".cmd", ".bat")):
            refs.append(token)

    unquoted = command.replace("`", "")
    for span in QUOTED_SPAN.finditer(unquoted):
        _add(span.group(0), True)
    stripped = QUOTED_SPAN.sub(" ", unquoted)
    for token in re.split(r"[\s;|&()\[\]{}]+", stripped):
        _add(token, False)
    return refs


def resolve_script_ref(ref, cwd, extra_dir=None, dialect="powershell"):
    """把脚本引用解析为实际执行文件路径；找不到返回 None（交由 Shell 自行报错）。

    按 Shell 的真实查找语义绑定被检查的文件，避免"检查 A、执行 B"：
    - cmd.exe：当前目录优先（含 PATHEXT 逐个扩展名），再走 PATH；
    - PowerShell：裸名不搜当前目录，只按 PATH；
    - 带路径分隔符的引用按会话目录（嵌套时按脚本所在目录）解析。
    """
    if not isinstance(ref, str) or not ref or len(ref) > 240 or ".." in re.split(r"[\\/]", ref):
        raise GuardError("脚本引用为空、过长或包含父目录跳转。")
    raw = ref.replace("/", "\\")
    bare = not re.search(r"[\\/]", ref)

    def _existing(joined):
        path = Path(joined)
        if path.is_file() and re.match(r"^[A-Za-z]:\\", str(path)):
            return path
        return None

    if bare:
        found = shutil.which(raw)
        if dialect == "cmd":
            # cmd.exe 语义：当前目录（PATHEXT 逐个尝试）优先于 PATH。
            for ext in (".cmd", ".bat", ".ps1"):
                hit = _existing(os.path.abspath(os.path.join(cwd, raw + ext)))
                if hit is not None:
                    return hit
            if found and re.match(r"^[A-Za-z]:\\", str(Path(found))):
                return Path(found)
            return None
        # PowerShell 裸名不搜当前目录；PATH 找不到时命令本就无法执行。
        if found and re.match(r"^[A-Za-z]:\\", str(Path(found))):
            return Path(found)
        return None
    candidates = [os.path.abspath(os.path.join(cwd, raw))]
    if extra_dir is not None:
        candidates.append(os.path.abspath(os.path.join(extra_dir, raw)))
    for joined in candidates:
        hit = _existing(joined)
        if hit is not None:
            return hit
    return None


def read_script_content(path):
    """读取脚本全文；过大或不可读均拒绝（读取失败不能成为放行条件）。"""
    try:
        content = path.read_text(encoding="utf-8-sig")
    except (OSError, ValueError):
        raise GuardError("无法读取脚本内容以验证删除安全性。")
    if len(content.encode("utf-8")) > 131072:
        raise GuardError("脚本过大，无法在检查阶段完整验证。")
    return content


def inspect_script_file(path, cfg, event, script_cwd, depth=0):
    """对已解析到盘符路径的脚本做静态删除检查。

    .ps1：危险时返回改写后的冻结副本路径（调用方决定改写或拒绝），干净返回 None。
    .cmd/.bat：剔除 ^ 转义后匹配删除语义，含删除即拒绝（批处理无法安全改写）；
    嵌套引用其他脚本时递归检查（深度上限 3）。
    注意：冻结副本仅降低检查与执行之间被篡改的窗口，不能视为完全不可变。
    """
    if depth > 3:
        raise GuardError("脚本嵌套引用超过安全深度。")
    content = read_script_content(path)
    ext = path.suffix.lower()
    runner = str(ROOT / "recycle_powershell.ps1").replace("\\", "/")
    if ext in (".cmd", ".bat"):
        # CMD 的 ^ 转义可以拆分关键词（d^el、^ 续行拼接）；先拒绝无法静态
        # 验证的形态，再按去转义文本匹配删除语义。变量拼接命令名（%a%%b%）、
        # 延迟展开（!a!）与 ^ 续行无法证明安全，一律拒绝。
        if re.search(r"\^\s*(?:\r?\n|$)", content):
            raise GuardError("批处理包含 ^ 续行或行尾转义，无法静态验证，已拒绝执行。")
        if re.search(r"![A-Za-z_]\w*!", content):
            raise GuardError("批处理包含延迟展开变量，无法静态验证，已拒绝执行。")
        plain = content.replace("^", "")
        if re.search(r"(?im)^\s*@?\s*(?:call\s+)?%[^%\r\n]{1,64}%", plain):
            raise GuardError("批处理命令名使用变量拼接，无法静态验证，已拒绝执行。")
        if re.search(r"(?i)\bcall\s+%[^%\r\n]{1,64}%", plain):
            raise GuardError("批处理 call 目标使用变量拼接，无法静态验证，已拒绝执行。")
        if OPAQUE.search(plain) or looks_dangerous(plain) or re.search(
                r"(?i)(?<![\w-])(?:del|erase|rd|rmdir)(?![\w-])", plain):
            raise GuardError("批处理脚本包含删除或不可静态验证的语义，已拒绝执行；请改写为等价 PowerShell 命令。")
        for ref in collect_script_refs(plain):
            nested = resolve_script_ref(ref, script_cwd, path.parent, dialect="cmd")
            # 嵌套脚本若需要改写（返回冻结副本），批处理无法替换其执行路径，必须拒绝。
            if nested is not None and ROOT not in nested.parents:
                if inspect_script_file(nested, cfg, event, script_cwd, depth + 1):
                    raise GuardError("批处理引用的嵌套脚本包含删除调用，外层无法替换执行副本，已拒绝执行。")
        return None
    ast, _ = parse_ps(content, cfg)
    if ast["dynamic"] or OPAQUE.search(content):
        raise GuardError("脚本包含动态调用或编码命令，无法验证删除安全性，已拒绝执行。")
    if ast["errors"]:
        raise GuardError("脚本存在语法错误，已拒绝执行。")
    runner = str(ROOT / "recycle_powershell.ps1").replace("\\", "/")
    danger = looks_dangerous(content) or any(
        base_name(n) in DELETE_NAMES or base_name(n).startswith("remove-") for n in ast["names"] if n)
    # 嵌套引用按脚本自身全文收集（覆盖 pwsh -File/-Command 包装、cmd /c、
    # 直接调用等形态），相对引用按脚本所在目录解析；嵌套需要改写时外层无法
    # 替换其运行时调用点，只能整体拒绝。
    for ref in collect_script_refs(content):
        if runner in ref:
            continue
        nested = resolve_script_ref(ref, str(path.parent), dialect="powershell")
        if nested is not None and ROOT not in nested.parents:
            if inspect_script_file(nested, cfg, event, script_cwd, depth + 1):
                raise GuardError("脚本引用的嵌套脚本包含删除调用，外层无法替换执行副本，已拒绝执行；请单独执行该脚本。")
    if not danger:
        # 干净脚本不要求改写白名单，$PSScriptRoot 等自身目录引用照常放行。
        return None
    if re.search(r"(?i)\$\{?(?:psscriptroot|pscommandpath)\}?", content):
        # 冻结副本位于防护目录，$PSScriptRoot/$PSCommandPath 语义会改变，无法安全执行。
        raise GuardError("脚本依赖自身目录（$PSScriptRoot/$PSCommandPath），冻结副本会改变语义，已拒绝执行。")
    updated = replace_ps_deletes(ast, content, event)
    if updated is None:
        raise GuardError("脚本包含删除语义但无法安全改写，已拒绝执行。")
    # 冻结改写后的内容再执行：分析与执行之间原脚本被改动不影响执行内容。
    digest = hashlib.sha256(updated.encode("utf-8")).hexdigest()[:16]
    folder = ROOT / "logs" / "rewritten"
    folder.mkdir(parents=True, exist_ok=True)
    frozen = folder / (path.stem + "." + digest + ".ps1")
    if frozen.exists():
        frozen.chmod(0o644)
    # PowerShell 5.1 对无 BOM 脚本按 ANSI 解码，中文路径会变乱码；必须带 BOM 写入。
    frozen.write_text(updated, encoding="utf-8-sig")
    frozen.chmod(0o444)
    return str(frozen).replace("\\", "/")


def frozen_replacement(frozen, idx, parts):
    """构造外层命令中的冻结副本引用：直接调用需 & 前缀，参数位置仅加引号。"""
    quoted = "'" + frozen.replace("'", "''") + "'"
    if parts[idx].quoted:
        return frozen.replace("'", "''")
    if idx == 0:
        return "& " + quoted
    return quoted


def inspect_bare_commands(command, cfg, event, script_cwd, dialect):
    """裸命令名（无扩展名）可能经 PATHEXT/PATH 解析为脚本；逐个探测并检查内容。

    cmd.exe 会对裸名按当前目录+PATHEXT 搜索；PowerShell 裸名走 PATH。
    解析到含删除调用的脚本时，裸名无法安全替换为冻结副本，直接拒绝。
    """
    seen = set()
    for token in re.split(r"[\s;|&\"'()`\[\]{}]+", command.replace("`", "")):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", token) or "." in token:
            continue
        if token.lower() in seen:
            continue
        seen.add(token.lower())
        targets = []
        if dialect == "cmd":
            for ext in (".cmd", ".bat"):
                candidate = Path(os.path.abspath(os.path.join(script_cwd, token + ext)))
                if candidate.is_file():
                    targets.append(candidate)
        found = shutil.which(token)
        if found and Path(found).suffix.lower() in (".cmd", ".bat", ".ps1"):
            targets.append(Path(found))
        for target in targets:
            if ROOT in target.parents:
                continue
            if inspect_script_file(target, cfg, event, script_cwd):
                raise GuardError("裸命令名解析到包含删除调用的脚本，无法安全替换执行副本，已拒绝；请用显式路径单独执行。")


def analyze(event, agent, cfg):
    if not isinstance(event, dict):
        raise GuardError("钩子输入必须为对象。")
    data = event.get("tool_input", event.get("toolInput", {}))
    if not isinstance(data, dict):
        raise GuardError("工具参数必须为对象。")
    tool = event.get("tool_name", event.get("toolName", ""))
    if base_name(tool) not in SHELL_NAMES:
        return {"action": "allow"}
    key = "command" if "command" in data else "cmd" if "cmd" in data else None
    if key is None:
        return {"action": "allow"}
    command = data[key]
    if not isinstance(command, str) or len(command.encode("utf-8")) > 131072:
        raise GuardError("命令必须是长度受限的字符串。")
    launcher = str(ROOT / "recycle.cmd").replace("\\", "/")
    for prefix in ("& '" + launcher.replace("'", "''") + "' ", '"' + launcher + '" '):
        if command.startswith(prefix) and re.fullmatch(r"[A-Za-z0-9+/]{1,6000}", command[len(prefix):]):
            # 精确的安全入口仍在执行时校验载荷，不能把编码载荷里的偶然词段当作 Shell 删除。
            return {"action": "allow"}
    name = base_name(tool)
    shell = str(data.get("shell", "")).lower()
    dialect = "powershell" if name in {"pwsh", "powershell"} or "powershell" in shell or "pwsh" in shell else "cmd" if "cmd" in shell else "bash"
    if agent == "codex" and not shell:
        dialect = "powershell"
    if agent == "zcode" and dialect == "bash" and not shell and "\\" in command and not command.lstrip().lower().startswith(("del ", "erase ", "rd ")):
        # ZCode 的 Bash 名称不能证明实际 Shell；歧义路径不允许按错误转义规则解释。
        if looks_dangerous(command):
            raise GuardError("当前 ZCode 工具未说明实际 Shell；删除路径请使用正斜杠，避免反斜杠转义歧义。")
    danger = looks_dangerous(command)
    if dialect == "powershell":
        ast, parts = parse_ps(command, cfg)
        danger |= any(base_name(n) in DELETE_NAMES or base_name(n).startswith("remove-") for n in ast["names"] if n)
        runner = str(ROOT / "recycle_powershell.ps1").replace("\\", "/")
        wrapped = runner in ast["names"]
        if ast["dynamic"] or OPAQUE.search(command):
            raise GuardError("动态命令名无法证明安全，已阻止调用。")
        # 脚本拦截：全文扫描命令中的本地 .ps1/.cmd/.bat 引用（覆盖多语句、
        # 条件块、-File/-Command 包装等复杂外层），读取内容逐个检查。
        refs = collect_script_refs(command)
        if refs:
            script_cwd = resolve_cwd(data.get("workdir", data.get("cwd")), event.get("cwd"))
            hit = script_target(parts) if parts else None
            for ref in refs:
                resolved = resolve_script_ref(ref, script_cwd)
                # 防护目录内文件（回收入口/已改写的冻结副本）与不存在的引用跳过
                # 内容检查（后者由 Shell 报错）。
                if resolved is None or ROOT in resolved.parents:
                    continue
                frozen = inspect_script_file(resolved, cfg, event, script_cwd)
                if not frozen:
                    continue
                # 只有“单条命令、调用位置（直接执行或 -File/-f 包装）、引用可在原文中
                # 字面定位”才改写执行冻结副本；参数位置（Get-Content/Copy-Item 等会改变
                # 读取或复制语义）、复杂外层、反引号转义名一律拒绝，
                # 避免字符串替换找不到目标导致的重复改写循环。
                invoked = hit is not None and (hit[0] == 0 or (
                    base_name(parts[0].value) in {"powershell", "pwsh"}
                    and hit[0] >= 2 and parts[hit[0] - 1].value.lower() in ("-file", "-f")))
                replaceable = invoked and hit[1] == ref and ref in command
                if not replaceable:
                    raise GuardError("命令引用的脚本包含删除调用，当前上下文无法安全改写，已拒绝；请单独执行该脚本。")
                updated = dict(data)
                updated[key] = command.replace(ref, frozen_replacement(frozen, hit[0], parts), 1)
                if updated[key] == command:
                    raise GuardError("脚本改写未能改变原命令，已拒绝执行。")
                if agent == "codex":
                    updated["command"] = updated[key]
                return {"action": "rewrite", "input": updated, "reason": "脚本包含删除调用，已替换为删除改写后的冻结副本执行；原脚本不会被直接执行。"}
        # 裸命令名经 PATHEXT/PATH 可能解析为脚本，同样需要内容检查。
        inspect_bare_commands(command, cfg, event, resolve_cwd(data.get("workdir", data.get("cwd")), event.get("cwd")), "powershell")
        if not danger and not wrapped:
            return {"action": "allow"}
        if ast["errors"]:
            raise GuardError("PowerShell 语法错误，已阻止命令。")
        if not ast["simple"] or wrapped:
            return rewrite_ps_calls(ast, command, data, key, agent, event)
    else:
        if OPAQUE.search(command):
            raise GuardError("动态执行或编码命令无法核实删除语义，已阻止。")
        # 脚本拦截（CMD/Bash 方言）：全文扫描脚本引用并检查内容；
        # 此方言下不做冻结改写（批处理无法安全改写），危险即整体拒绝。
        refs = collect_script_refs(command)
        if refs:
            script_cwd = resolve_cwd(data.get("workdir", data.get("cwd")), event.get("cwd"))
            for ref in refs:
                resolved = resolve_script_ref(ref, script_cwd, dialect=dialect)
                if resolved is None or ROOT in resolved.parents:
                    continue
                # 此方言下不做冻结改写（批处理无法安全改写）；嵌套脚本需要改写时
                # 外层无法替换其执行路径，必须拒绝而非丢弃检查结果。
                if inspect_script_file(resolved, cfg, event, script_cwd):
                    raise GuardError("命令引用的脚本包含删除调用，此 Shell 下无法改写执行副本，已拒绝；请单独执行该脚本。")
        inspect_bare_commands(command, cfg, event, resolve_cwd(data.get("workdir", data.get("cwd")), event.get("cwd")), dialect)
        if not danger:
            return {"action": "allow"}
        parts = parse_literal(command, dialect)
        # ZCode 的 Bash 可选择 CMD；del/rd 的斜杠开关按 CMD 解析，但执行替换走通用 launcher。
        if agent == "zcode" and parts and base_name(parts[0].value) in {"del", "erase", "rd"}:
            dialect = "cmd"
            parts = parse_literal(command, dialect)
    if not parts or name not in SHELL_NAMES:
        raise GuardError("此工具的删除命令不支持安全改写，已阻止。")
    if base_name(parts[0].value) in {"echo", "printf", "write-output", "write-host", "rg", "grep"}:
        return {"action": "allow"}
    if dialect == "powershell" and parts[0].value.lower().endswith((".exe", ".cmd", ".bat")):
        raise GuardError("外部删除程序的参数规则不按 PowerShell 别名解释，已拒绝。")
    spec, dry_run = delete_spec(parts, dialect)
    if dry_run:
        updated = dict(data)
        updated[key] = "Write-Output '删除防护：预演，未执行删除。'"
        if agent == "codex":
            updated["command"] = updated[key]
        return {"action": "rewrite", "input": updated, "reason": "删除预演已转换为安全提示，未执行原命令。"}
    spec["cwd"] = resolve_cwd(data.get("workdir", data.get("cwd")), event.get("cwd"))
    # Bash 的 /c/... 是 Windows 路径；/mnt/c 是 WSL，不猜测映射。
    for entry in spec["paths"]:
        if dialect == "bash" and entry["path"].rstrip("/").split("/")[-1] in {".", ".."}:
            raise GuardError("Bash 删除命令不能回收点目录目标。")
        if dialect == "bash" and re.match(r"^/[A-Za-z]/", entry["path"]):
            entry["path"] = entry["path"][1] + ":/" + entry["path"][3:]
        elif dialect == "bash" and entry["path"].startswith("/"):
            raise GuardError("不支持此 POSIX/WSL 绝对路径映射。")
    if agent == "dsh" and event.get("persistent"):
        if any(not os.path.isabs(entry["path"]) for entry in spec["paths"]):
            raise GuardError("持久 Shell 的当前目录可能变化，删除必须使用绝对路径。")
    # 在检查阶段冻结目标集合，避免执行前新增文件被通配符额外选中。
    if dialect == "bash":
        frozen = []
        for entry in spec["paths"]:
            path = checked_path(entry["path"], spec["cwd"], cfg)
            if entry["glob"] and any(c in str(path) for c in "*?["):
                if any(c in str(path.parent) for c in "*?[") or "[" in path.name or "**" in path.name:
                    raise GuardError("仅支持末级文件名中的简单 Bash 通配符。")
                candidates = sorted((p for p in path.parent.iterdir() if
                    (not p.name.startswith(".") or path.name.startswith(".")) and
                    fnmatch.fnmatchcase(p.name, path.name)), key=str)
                if not candidates and not spec["missing_ok"]:
                    raise GuardError("Bash 通配符未匹配到目标。")
                frozen.extend({"path": str(p), "glob": False} for p in candidates)
            else:
                frozen.append({"path": str(path), "glob": False})
        spec["paths"] = frozen
    if dialect == "cmd" and any(any(c in p["path"] for c in "*?") for p in spec["paths"]):
        raise GuardError("CMD 通配符与普通匹配规则不同，请列出明确路径。")
    if any(p["glob"] and "`" in p["path"] for p in spec["paths"]):
        raise GuardError("不支持路径中的 PowerShell 通配符转义。")
    targets = resolve_targets(spec, cfg, deep=False) if spec["paths"] else []
    if dialect == "bash" and base_name(parts[0].value) in {"rm", "unlink"} and not spec["recursive"]:
        option_parts = parts[1:next((i for i, p in enumerate(parts) if p.value == "--"), len(parts))]
        allow_empty_dir = base_name(parts[0].value) == "rm" and any(p.value == "--dir" or re.fullmatch(r"-[rfRdv]*d[rfRdv]*", p.value) for p in option_parts)
        if not allow_empty_dir and any(p.is_dir() for p in targets):
            raise GuardError("此 Bash 删除命令未允许目录目标。")
    explicit_force = any(p.parameter and p.value.lower() == "-force" for p in parts) if dialect == "powershell" else any(p.value.lower() == "/f" for p in parts[1:])
    if dialect in {"powershell", "cmd"}:
        # 回收整个目录会包含隐藏后代，原命令未显式允许时不能扩大操作范围。
        hidden_mask = stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM
        def check_attributes(path):
            attrs = path.lstat().st_file_attributes
            if not explicit_force and (attrs & hidden_mask or not path.is_dir() and attrs & stat.FILE_ATTRIBUTE_READONLY):
                raise GuardError("原命令未明确允许隐藏、系统或只读目标，已拒绝回收。")
            if dialect == "cmd" and attrs & hidden_mask:
                raise GuardError("CMD 隐藏或系统目标的属性选择语义不转换，请使用明确的 PowerShell 删除。")
        for target in targets:
            check_attributes(target)
            if target.is_dir() and spec["recursive"]:
                count = 0
                for directory, dirs, files in os.walk(target, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
                    for child in dirs + files:
                        count += 1
                        if count > 200000:
                            raise GuardError("目录超过安全扫描上限，已阻止删除。")
                        path = checked_path(str(Path(directory) / child), spec["cwd"], cfg)
                        check_attributes(path)
    if targets:
        spec["paths"] = [{"path": str(p), "glob": False} for p in targets]
    else:
        # 无目标的 -f 只能成为安全空操作，不能保留可能稍后匹配新文件的模式。
        updated = dict(data)
        updated[key] = "Write-Output '删除防护：没有匹配目标。'" if dialect == "powershell" else "echo 删除防护：没有匹配目标。"
        if agent == "codex":
            updated["command"] = updated[key]
        return {"action": "rewrite", "input": updated, "reason": "未匹配目标，已转换为空操作。"}
    # CMD 把未引用的等号视为参数分隔符；使用无填充 Base64 并在解码时恢复填充。
    payload = base64.b64encode(json.dumps(spec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    if len(payload) > 6000:
        raise GuardError("回收请求超过命令行安全长度。")
    # launcher 不带动态原始文本；绝对路径加 ASCII Base64 避免二次解释用户参数。
    if dialect == "powershell":
        replacement = "& '" + launcher.replace("'", "''") + "' " + payload
    else:
        replacement = '"' + launcher + '" ' + payload
    updated = dict(data)
    updated[key] = replacement
    if agent == "codex":
        updated["command"] = replacement
    return {"action": "rewrite", "input": updated, "reason": "文件删除已替换为严格 Windows 回收操作；原命令不会执行。"}


def audit(record):
    folder = ROOT / "logs"
    folder.mkdir(exist_ok=True)
    record = {"time": datetime.now(timezone.utc).isoformat(), **record}
    with (folder / (datetime.now().strftime("%Y-%m-%d") + ".jsonl")).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def make_sink():
    """回收回调单独构造，便于验证永久删除请求必定被拒绝。"""
    from win32com.shell import shell, shellcon
    from win32com.server.exception import COMException
    from send2trash.win.IFileOperationProgressSink import FileOperationProgressSink

    class StrictSink(FileOperationProgressSink):
        def __init__(self):
            super().__init__()
            self.receipt = None
            self.rejected = False

        def PreDeleteItem(self, flags, item):
            # 回收不可用时 Shell 可能再次请求永久删除，必须抛异常而非仅返回 HRESULT。
            if not flags & shellcon.TSF_DELETE_RECYCLE_IF_POSSIBLE:
                self.rejected = True
                raise COMException("已阻止不可回收的删除。", scode=-2147467259)

        def PostDeleteItem(self, flags, item, hr_delete, newly_created):
            if hr_delete < 0 or not newly_created:
                self.rejected = True
                return
            self.receipt = newly_created.GetDisplayName(shellcon.SIGDN_FILESYSPATH)

    return StrictSink()


def recycle(spec, cfg):
    """现代 Shell COM 接口；禁止降级到永久删除或旧版删除 API。"""
    import pythoncom
    from win32com.shell import shell, shellcon

    targets = resolve_targets(spec, cfg)
    receipts = []

    pythoncom.CoInitialize()
    try:
        for path in targets:
            # 再次检查路径，缩小分析与执行之间的竞态窗口。
            checked_path(str(path), spec["cwd"], cfg)
            sink = make_sink()
            operation = pythoncom.CoCreateInstance(shell.CLSID_FileOperation, None, pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IFileOperation)
            flags = shellcon.FOF_NOCONFIRMATION | shellcon.FOF_NOERRORUI | shellcon.FOF_SILENT | shellcon.FOFX_EARLYFAILURE | 0x20000000 | 0x00080000
            operation.SetOperationFlags(flags)
            item = shell.SHCreateItemFromParsingName(str(path), None, shell.IID_IShellItem)
            operation.DeleteItem(item, pythoncom.WrapObject(sink, shell.IID_IFileOperationProgressSink))
            result = operation.PerformOperations()
            if result or operation.GetAnyOperationsAborted() or sink.rejected or not sink.receipt:
                raise GuardError("回收未被确认成功，已停止后续操作；绝不改用永久删除。")
            recycled = Path(sink.receipt)
            if not recycled.exists() or "$recycle.bin" not in str(recycled).lower() or not recycled.name.startswith("$R"):
                raise GuardError("Windows 未返回有效回收站项目，已停止后续操作。")
            receipt = {"original": str(path), "recycled": sink.receipt}
            receipts.append(receipt)
            audit({"action": "recycled", **receipt})
    finally:
        pythoncom.CoUninitialize()
    return receipts


def main():
    parser = argparse.ArgumentParser(description="Agent 文件删除回收防护")
    parser.add_argument("mode", choices=["hook", "analyze", "recycle", "runtime"])
    parser.add_argument("--agent", choices=["codex", "claude", "zcode", "dsh"], default="codex")
    parser.add_argument("--payload")
    args = parser.parse_args()
    try:
        cfg = config()
        if args.mode == "recycle":
            if not args.payload or len(args.payload) > 16000:
                raise GuardError("非法回收载荷长度。")
            spec = json.loads(base64.b64decode(args.payload + "=" * (-len(args.payload) % 4), validate=True).decode("utf-8"))
            receipts = recycle(spec, cfg)
            print(json.dumps({"message": "已移动到 Windows 回收站。", "receipts": receipts}, ensure_ascii=False))
            return 0
        raw = sys.stdin.read(262145)
        if len(raw) > 262144:
            raise GuardError("钩子输入超过安全长度。")
        # 5.1 原生进程管道可能附带 UTF-8 BOM；只接受开头一个标记，其他输入校验不变。
        decision = analyze(json.loads(raw.removeprefix("\ufeff")), args.agent, cfg)
        if args.mode == "runtime":
            # 运行时由脚本生成单条字面量请求，只接受本程序输出的直接回收命令。
            launcher = str(ROOT / "recycle.cmd").replace("\\", "/")
            prefix = "& '" + launcher.replace("'", "''") + "' "
            replacement = decision.get("input", {}).get("command", "")
            if decision["action"] != "rewrite" or not replacement.startswith(prefix):
                raise GuardError(decision.get("reason", "运行时请求没有转换为直接回收。"))
            payload = replacement[len(prefix):]
            request = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True).decode("utf-8"))
            receipts = recycle(request, cfg)
            print(json.dumps({"message": "已移动到 Windows 回收站。", "receipts": receipts}, ensure_ascii=False))
            return 0
    except Exception as error:
        reason = "删除防护已阻止操作：" + str(error)
        if args.mode in {"recycle", "runtime"}:
            print(reason, file=sys.stderr)
            return 2
        decision = {"action": "deny", "reason": reason}
    if decision["action"] != "allow":
        # 不保存整个原始命令，避免命令中的凭据进入日志。
        try:
            audit({"action": decision["action"], "agent": args.agent, "reason": decision.get("reason", "")})
        except OSError:
            decision = {"action": "deny", "reason": "审计记录失败，已阻止原命令。"}
    if args.mode == "analyze":
        print(json.dumps(decision, ensure_ascii=False))
    elif decision["action"] == "allow":
        # 启动器验证成功标记后抑制输出，避免把只读检查变成权限审批放行。
        print(json.dumps({"guardAllow": True}))
    else:
        output = {"hookEventName": "PreToolUse", "permissionDecision": "deny" if decision["action"] == "deny" else "allow", "permissionDecisionReason": decision["reason"]}
        if decision["action"] == "rewrite":
            output["updatedInput"] = decision["input"]
        print(json.dumps({"hookSpecificOutput": output}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
