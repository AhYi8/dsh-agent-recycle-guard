"""Bash 使用现成语法树定位删除；参数由真实 Shell 展开后交给回收执行器。"""
import os
from pathlib import Path
import shlex
import re


DELETE_NAMES = {"rm", "unlink", "rmdir"}
EXTERNAL_DELETERS = {"shred", "sdelete", "diskpart", "cipher", "mkfs", "wipefs"}


def commands(text, guard):
    try:
        import bashlex
    except ImportError as error:
        raise guard.GuardError("缺少 Bash 解析依赖，请运行 python -m pip install -r requirements.txt。") from error
    try:
        trees = bashlex.parse(text)
    except (ValueError, NotImplementedError, bashlex.errors.ParsingError) as error:
        raise guard.GuardError("Bash 语法无法可靠解析，已阻止命令。") from error
    found = []

    class Collector(bashlex.ast.nodevisitor):
        def visitcommand(self, node, parts):
            words = [p for p in parts if p.kind == "word"]
            if words:
                found.append((node, words))

    visitor = Collector()
    for tree in trees:
        visitor.visit(tree)
    if len(found) > 1000:
        raise guard.GuardError("命令调用数量超过安全上限。")
    return found


def runtime_prefix(cfg, guard, dialect, name):
    argv = [cfg["python"], str(guard.ROOT / "guard.py"), "shell-runtime", "--dialect", dialect, "--name", name, "--"]
    if dialect == "cmd":
        # 原始参数保留在原命令里，由 cmd 自己完成变量及引号展开。
        return " ".join('"' + value + '"' if i < 2 else value for i, value in enumerate(argv))
    if guard.IS_WINDOWS:
        argv[:2] = [value.replace('\\', '/') for value in argv[:2]]
    return " ".join(shlex.quote(value) for value in argv)


def rewrite_bash(text, cfg, guard, inspect_entry=None):
    changes = []
    for node, words in commands(text, guard):
        head = words[0]
        if head.parts:
            raise guard.GuardError("动态 Bash 命令名无法核实，已阻止执行。")
        name = Path(head.word).name
        args = [word.word for word in words[1:]]
        if name in DELETE_NAMES:
            changes.append((head.pos[0], head.pos[1], runtime_prefix(cfg, guard, "bash", name)))
        elif name == 'alias' and any('=' in arg and guard.looks_dangerous(arg.split('=', 1)[1]) for arg in args):
            raise guard.GuardError("删除别名无法可靠追踪，请直接调用普通删除命令。")
        elif name in EXTERNAL_DELETERS or name.startswith("mkfs."):
            raise guard.GuardError("外部抹除程序无法转为回收，已阻止执行。")
        elif name in {"command", "env", "sudo", "exec", "xargs", "find", "git", "rsync"} and guard.looks_dangerous(" ".join([name, *args])):
            raise guard.GuardError("包装或外部程序中的删除无法安全改写，已阻止执行。")
        elif name in {"eval", "source", "."}:
            # source 是脚本加载入口，交由有限的内容检查；eval 的载荷无法绑定。
            if name == "eval":
                raise guard.GuardError("动态 Shell 代码无法核实，已阻止执行。")
            if inspect_entry:
                inspect_entry(name, words[1:], node)
        elif inspect_entry:
            replacement = inspect_entry(head.word, words[1:], node)
            if replacement:
                changes.append(replacement)
    updated = text
    for start, end, replacement in sorted(changes, reverse=True):
        updated = updated[:start] + replacement + updated[end:]
    return updated if changes else None


def runtime_spec(args, dialect, name, cfg, guard):
    if name not in ({"del", "erase", "rd", "rmdir"} if dialect == "cmd" else DELETE_NAMES):
        raise guard.GuardError("非法运行时删除名称。")
    # Shell 已完成展开；不把文件名中的空格、美元符号或通配符再解释一遍。
    parts = [guard.Part(name)] + [guard.Part(arg, quoted=True) for arg in args]
    spec, _ = guard.delete_spec(parts, dialect)
    spec["cwd"] = os.getcwd()
    if dialect == "bash":
        allow_dirs = name == "rmdir" or spec["recursive"] or any(arg == "--dir" or arg.startswith("-") and "d" in arg for arg in args)
        if not allow_dirs:
            for entry in spec["paths"]:
                if guard.checked_path(entry["path"], spec["cwd"], cfg).is_dir():
                    raise guard.GuardError("原 rm/unlink 未允许目录目标，不扩大为目录回收。")
    return spec


def rewrite_cmd(text, cfg, guard, inspect_entry=None):
    """只改写独立的 CMD 删除语句；条件、循环与转义删除拒绝而非猜测。"""
    pieces = []
    quoted, start = False, 0
    for i, char in enumerate(text):
        if char == '"':
            quoted = not quoted
        if not quoted and char in "\n&|":
            pieces.append((start, text[start:i]))
            start = i + 1
    pieces.append((start, text[start:]))
    changes = []
    for offset, piece in pieces:
        match = re.match(r'\s*@?("[^\"]*"|[^\s]+)', piece)
        if not match:
            continue
        head = match.group(1)
        name = Path(head.strip('"')).name.lower().removesuffix(".exe")
        try:
            tokens = shlex.split(piece, posix=False)
        except ValueError:
            tokens = []
        if tokens and guard.is_guard_call(head.strip('"'), [{'value': value.strip('"')} for value in tokens[1:]], cfg):
            continue
        if name in {"rem", "::", "echo", "set", "setlocal", "endlocal"}:
            continue
        if name in {"del", "erase", "rd", "rmdir"}:
            if "^" in piece or "|" in text:
                raise guard.GuardError("带转义或管道的 CMD 删除无法安全改写，请拆为普通删除调用。")
            changes.append((offset + match.start(1), offset + match.end(1), runtime_prefix(cfg, guard, "cmd", name)))
        elif guard.looks_dangerous(piece.replace("^", "")):
            raise guard.GuardError("复杂 CMD 或外部程序中的删除无法安全改写，已阻止执行。")
        elif inspect_entry:
            try:
                tokens = shlex.split(piece, posix=False)
            except ValueError:
                continue
            replacement = inspect_entry(head, tokens[1:], (offset, piece))
            if replacement:
                changes.append(replacement)
    updated = text
    for start, end, replacement in sorted(changes, reverse=True):
        updated = updated[:start] + replacement + updated[end:]
    return updated if changes else None
