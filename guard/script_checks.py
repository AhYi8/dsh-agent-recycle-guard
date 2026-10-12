"""脚本采用有限、尽力的内容检查；不试图证明任意语言或所有加载链安全。"""
import ast
import base64
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil


LANGUAGES = {"python": "python", "python3": "python", "py": "python", "node": "javascript", "deno": "javascript", "bun": "javascript", "bash": "bash", "sh": "bash"}
SCRIPT_SUFFIXES = {".ps1": "powershell", ".cmd": "cmd", ".bat": "cmd", ".py": "python", ".python": "python", ".pyw": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".sh": "bash"}
JS_DELETE = re.compile(r"\b(?:unlink|rmdir|rm)(?:Sync)?\s*\(|\brimraf\b|\[\s*['\"](?:unlink|rmdir|rm)(?:Sync)?['\"]\s*\]\s*\(")
PS_FROZEN = re.compile(r"# AgentRecycleGuard UTF-8\n& \(\[ScriptBlock\]::Create\(\[Text.Encoding\]::UTF8.GetString\(\[Convert\]::FromBase64String\('([A-Za-z0-9+/=]+)'\)\)\)\) @args\n\Z")


def python_deletes(content):
    """用标准库 AST 跟踪常见导入别名，不引入 Python 静态分析框架。"""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return bool(re.search(r"\b(?:remove|unlink|rmdir|rmtree)\s*\(", content))
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update({item.asname or item.name: item.name for item in node.names})
        elif isinstance(node, ast.ImportFrom):
            aliases.update({item.asname or item.name: (node.module or "") + "." + item.name for item in node.names})
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name) and aliases.get(function.id) in {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}:
            return True
        if isinstance(function, ast.Attribute):
            if function.attr in {"unlink", "rmdir"}:
                return True
            if isinstance(function.value, ast.Name) and aliases.get(function.value.id, function.value.id) + "." + function.attr in {"os.remove", "shutil.rmtree"}:
                return True
    return False


class Inspector:
    def __init__(self, guard, cfg, event, agent, depth=0):
        self.guard, self.cfg, self.event, self.agent, self.depth = guard, cfg, event, agent, depth
        self.cwd = guard.execution_cwd(event, event.get("tool_input", {}))

    def resolve(self, ref, shell, argument=False):
        if not ref or any(symbol in ref for symbol in ("$", "%", "`")):
            return None
        ref = ref.strip('"')
        path = Path(ref)
        # 解释器文件参数始终以执行 cwd 为基准，与 Shell 查找命令的规则不同。
        if argument or path.is_absolute() or "/" in ref or "\\" in ref:
            path = path if path.is_absolute() else Path(self.cwd) / ref
            candidates = [path]
            if shell == "powershell":
                candidates.append(Path(str(path) + ".ps1"))
            elif shell == "cmd":
                candidates.extend(Path(str(path) + ext) for ext in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if ext)
            return next((p for p in candidates if p.is_file()), None)
        if shell == "cmd" and (Path(self.cwd) / ref).is_file():
            return Path(self.cwd) / ref
        found = shutil.which(ref)
        if not found and shell == "powershell":
            found = shutil.which(ref + ".ps1")
        return Path(found) if found and Path(found).is_file() else None

    def content(self, path):
        try:
            raw = path.read_bytes()
            if len(raw) > 131072:
                return None
            if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
                return raw.decode('utf-16')
            return raw.decode('utf-8-sig')
        except (OSError, UnicodeError):
            # 脚本是尽力检查；大文件与未知编码的限制明确记入文档，不造成普遍误拒。
            return None

    def freeze(self, text, language):
        folder = self.guard.ROOT / "logs" / "rewritten"
        folder.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        suffix = {"powershell": ".ps1", "bash": ".sh", "cmd": ".cmd"}[language]
        if language == "powershell":
            # 文件保持无 BOM；ASCII 外壳显式按 UTF-8 解码，兼容 PowerShell 5.1 中文。
            payload = base64.b64encode(text.encode('utf-8')).decode('ascii')
            text = "# AgentRecycleGuard UTF-8\n& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload + "')))) @args\n"
        path = folder / (digest + suffix)
        path.write_text(text, encoding='utf-8', newline='')
        if language == 'bash':
            path.chmod(0o700)
        return path

    def inspect(self, path, language=None):
        language = language or SCRIPT_SUFFIXES.get(path.suffix.lower())
        if language is None or self.depth >= 3:
            return None
        if path.resolve() == (self.guard.ROOT / "recycle_powershell.ps1").resolve():
            return None
        content = self.content(path)
        if content is None:
            return None
        if language == "python":
            if python_deletes(content):
                raise self.guard.GuardError("Python 脚本包含已识别的删除 API，请改用回收命令。")
            return None
        if language == "javascript":
            if JS_DELETE.search(content):
                raise self.guard.GuardError("JavaScript 脚本包含已识别的删除 API，请改用回收命令。")
            return None
        wrapper = PS_FROZEN.fullmatch(content) if language == "powershell" else None
        if wrapper:
            content = base64.b64decode(wrapper.group(1), validate=True).decode('utf-8')
        event = {**self.event, 'shell': language, 'tool_name': 'pwsh' if language == 'powershell' else 'exec_command', 'tool_input': {'command': content, 'shell': language}, 'cwd': self.cwd}
        result = self.guard.analyze(event, self.agent, self.cfg, _depth=self.depth + 1)
        if result['action'] == 'deny':
            raise self.guard.GuardError(result['reason'])
        if result['action'] != 'rewrite':
            return None
        if wrapper:
            raise self.guard.GuardError("执行副本仍含未改写删除，已阻止执行。")
        if language == 'powershell' and re.search(r"(?i)\$\{?(?:PSScriptRoot|PSCommandPath)\b", content):
            raise self.guard.GuardError("含删除脚本依赖原位置，不能安全替换执行副本。")
        if language == 'cmd':
            # 批处理副本可能改变 %~dp0 与 goto/call 的作用域，第一阶段只拦截不改写。
            raise self.guard.GuardError("批处理脚本包含删除调用，请改用 PowerShell 回收命令。")
        if language == 'bash' and re.search(r'\$0\b|\$\{?BASH_SOURCE\b', content):
            raise self.guard.GuardError("含删除的 Shell 脚本依赖原位置，请提交独立回收命令。")
        return self.freeze(result['input']['command'], language)

    def interpreter(self, name, args):
        language = LANGUAGES.get(name)
        if not language:
            return None
        values = [arg.get('value', '') for arg in args]
        for i, value in enumerate(values):
            if value in {'-c', '-e', '--eval'} and i + 1 < len(args):
                content = values[i + 1]
                if language == 'python' and python_deletes(content) or language == 'javascript' and JS_DELETE.search(content):
                    raise self.guard.GuardError("解释器内联代码包含已识别的删除 API。")
                if language == 'bash':
                    event = {**self.event, 'shell': 'bash', 'tool_name': 'bash', 'tool_input': {'command': content, 'shell': 'bash'}}
                    result = self.guard.analyze(event, self.agent, self.cfg, _depth=self.depth + 1)
                    if result['action'] == 'rewrite':
                        return i + 1, result['input']['command'], True
                return None
            if value in {'-m', '-', '--help', '--version', '-V'}:
                return None
            if value.startswith('-'):
                continue
            if language == 'javascript' and name in {'deno', 'bun'} and value in {'run', 'exec'}:
                continue
            if not value or args[i].get('opaque'):
                return None
            path = self.resolve(value, 'bash', argument=True)
            if path:
                frozen = self.inspect(path, language)
                if frozen:
                    return i, str(frozen), False
            return None
        return None

    def powershell(self, text, tree):
        changes = []
        for site in tree['commands']:
            name = site.get('name') or ''
            head = self.guard.base_name(name)
            args = site.get('args') or []
            if head == 'cmd':
                index = next((i for i, arg in enumerate(args) if arg.get('value', '').lower() in {'/c', '/k'}), None)
                if index is not None:
                    payload = args[index + 1:]
                    if any(arg.get('opaque') for arg in payload):
                        raise self.guard.GuardError("CMD 包装含动态执行参数，请拆成独立调用。")
                    content = ' '.join(arg['value'] for arg in payload)
                    event = {**self.event, 'shell': 'cmd', 'tool_name': 'exec_command', 'tool_input': {'command': content, 'shell': 'cmd'}}
                    result = self.guard.analyze(event, self.agent, self.cfg, _depth=self.depth + 1)
                    if result['action'] == 'rewrite':
                        # CMD 与 PowerShell 的引号不能互换；有删除时要求单独调用。
                        raise self.guard.GuardError("CMD 包装中的删除无法保留引号语义，请单独调用 CMD 或使用 Remove-Item。")
                continue
            if head in {'powershell', 'pwsh'}:
                if any(arg.get('value', '').lower() in {'-encodedcommand', '-enc', '-ec'} for arg in args):
                    raise self.guard.GuardError("编码 PowerShell 载荷无法核实，已阻止执行。")
                index = next((i for i, arg in enumerate(args) if re.fullmatch(r'(?i)-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?', arg.get('value', ''))), None)
                if index is not None and index + 1 < len(args):
                    payload = args[index + 1:]
                    if any(arg.get('opaque') for arg in payload):
                        raise self.guard.GuardError("PowerShell 内层代码是动态参数，无法安全改写。")
                    content = ' '.join(arg['value'] for arg in payload)
                    event = {**self.event, 'shell': 'powershell', 'tool_name': 'pwsh', 'tool_input': {'command': content, 'shell': 'powershell'}}
                    result = self.guard.analyze(event, self.agent, self.cfg, _depth=self.depth + 1)
                    if result['action'] == 'rewrite':
                        changes.append((payload[0]['start'], payload[-1]['end'], "'" + result['input']['command'].replace("'", "''") + "'"))
                    continue
                index = next((i + 1 for i, arg in enumerate(args[:-1]) if re.fullmatch(r'(?i)-f(?:i(?:l(?:e)?)?)?', arg.get('value', ''))), None)
                if index is not None:
                    path = self.resolve(args[index].get('value', ''), 'powershell', argument=True)
                    if path:
                        frozen = self.inspect(path)
                        if frozen:
                            changes.append((args[index]['start'], args[index]['end'], "'" + str(frozen).replace("'", "''") + "'"))
                continue
            if self.guard.is_guard_call(name, args, self.cfg):
                continue
            action = self.interpreter(head, args)
            if action:
                index, value, _inline = action
                changes.append((args[index]['start'], args[index]['end'], "'" + value.replace("'", "''") + "'"))
                continue
            if head in LANGUAGES or head in {'set-location', 'cd', 'push-location', 'pushd'}:
                continue
            path = self.resolve(name, 'powershell')
            if path:
                frozen = self.inspect(path)
                if frozen:
                    if site.get('invocation') == 'Dot':
                        raise self.guard.GuardError("点源含删除脚本无法保留作用域，请单独执行。")
                    replacement = "'" + str(frozen).replace("'", "''") + "'"
                    if site.get('invocation') != 'Ampersand':
                        replacement = '& ' + replacement
                    changes.append((site['start'], site['end'], replacement))
        updated = text
        for start, end, replacement in sorted(changes, reverse=True):
            encoded = updated.encode('utf-16-le')
            updated = (encoded[:start * 2] + replacement.encode('utf-16-le') + encoded[end * 2:]).decode('utf-16-le')
        return updated if changes else None

    def bash_entry(self, name, words, node):
        args = [{'value': word.word, 'opaque': bool(word.parts)} for word in words]
        if self.guard.is_guard_call(name, args, self.cfg):
            return None
        action = self.interpreter(Path(name).name, args)
        if action:
            index, value, _inline = action
            return (*words[index].pos, shlex.quote(value))
        path = self.resolve(words[0].word, 'bash', argument=True) if name in {'source', '.'} and words else self.resolve(name, 'bash')
        if path:
            frozen = self.inspect(path)
            if frozen:
                if name in {'source', '.'}:
                    raise self.guard.GuardError("source 含删除脚本无法保留作用域，请单独执行。")
                return node.parts[0].pos[0], node.parts[0].pos[1], shlex.quote(str(frozen))
        return None

    def cmd_entry(self, name, values, location):
        args = [{'value': value.strip('"')} for value in values]
        if self.guard.is_guard_call(name.strip('"'), args, self.cfg):
            return None
        if name.lower() == 'call' and values:
            path = self.resolve(values[0].strip('"'), 'cmd', argument=True)
        elif name.lower() in {'cmd', 'cmd.exe'} and values:
            index = next((i for i, value in enumerate(values) if value.lower() in {'/c', '/k'}), None)
            if index is not None:
                content = ' '.join(values[index + 1:])
                event = {**self.event, 'shell': 'cmd', 'tool_name': 'exec_command', 'tool_input': {'command': content, 'shell': 'cmd'}}
                result = self.guard.analyze(event, self.agent, self.cfg, _depth=self.depth + 1)
                if result['action'] == 'rewrite':
                    raise self.guard.GuardError("嵌套 CMD 删除不能保留引号语义，请拆为独立调用。")
            return None
        else:
            action = self.interpreter(self.guard.base_name(name.strip('"')), args)
            if action:
                # 不能丢弃解释器的改写结果而执行原脚本；CMD 引号语义不在此分支转换。
                raise self.guard.GuardError("CMD 解释器调用包含需改写的删除，请独立调用对应 Shell。")
            path = self.resolve(name.strip('"'), 'cmd')
        if path:
            self.inspect(path)
        return None
