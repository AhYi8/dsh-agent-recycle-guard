# dsh-agent-recycle-guard

DSH（DeepSeek Harness）删除防护插件：拦截 Agent 会话中的 `rm` / `del` / `Remove-Item` / `git clean` 等一切可静态识别的删除命令，把"永久删除"强制改写为**转入 Windows 回收站**，不提供永久删除退路（fail-closed）。

**安装即用、零配置**：python、PowerShell、脚本路径全部在首次运行时自动探测与自定位，无需修改任何配置文件。

## 安装

在 DSH 插件市场 / 插件管理器中安装，或手动安装：

```
dsh plugin install dsh-agent-recycle-guard
```

或在 profile 的 `node_modules` 中安装本包后，把 `cordis.patch.yml` 中的 insert 行合入 profile 补丁（通过插件管理器安装会自动完成）。

安装后新开一个会话即生效。

## 工作方式

- 挂载 `tools/pre-execute` 与 `tools/execute`：每次命令执行前，子进程 `guard.py analyze --agent dsh` 做纯 JSON 决策（allow / deny / rewrite），不在插件进程中直接操作文件，保留 DSH 原生权限与沙箱检查。
- 简单字面量删除 → 直接改写为 `recycle.cmd`（base64 载荷，COM `IFileOperation` 严格回收，回执 `$R…` 文件可验证）。
- 复杂 PowerShell（管道、变量、循环）→ AST 定位删除调用点，改写为 `recycle_powershell.ps1` 运行时逐项校验回收。
- 无法静态证明安全性的命令（`Invoke-Expression`、外部删除程序混合等）→ 整条拒绝。
- 本地 `.ps1` / `.cmd` / `.bat` 脚本：执行前读取内容检查，`.ps1` 含删除时替换为改写后的冻结副本执行（详见下方边界）。
- 改写后的命令作为新调用重新走完整的权限与沙箱检查，`pre-execute` 与 `execute` 之间用 token 配对，缺检查记录直接拒绝。

## 零配置引导

首次运行时 `guard.py` 自动在本包 `guard/` 目录生成：

- `runtime.json`：探测到的 python（当前解释器）、pwsh（PATH 中 `pwsh` 或 `powershell`）、安装目录、受保护路径（默认整个用户主目录）。
- `recycle.cmd`：按当前 python 解释器生成的回收启动器。

如需覆盖 python 路径，可在 profile 的 `cordis.patch.yml` 追加同 id（`agent-recycle-guard`）顶层行携带 `config: { python: <绝对路径> }`。

## 边界（有意保留的 fail-closed）

- 本地 `.ps1` / `.cmd` / `.bat` 脚本执行前会读取内容检查（含多语句、条件块、`pwsh -File/-Command` 包装、带空格的引号路径、PATH 裸名、省略扩展名的裸命令名等引用形态；嵌套脚本递归检查）：`.ps1` 含删除调用且处于可直接改写的调用位置时替换为"删除转回收站"的冻结副本再执行（副本按内容哈希命名并设只读，降低检查与执行之间被篡改的窗口，但同一用户仍可撤销只读，不构成安全隔离边界）；含删除但处于无法替换的位置（参数位置、嵌套调用、其他 Shell 包装）整体拒绝；依赖 `$PSScriptRoot` / `$PSCommandPath` 的**含删除**脚本拒绝；批处理含删除语义或无法静态验证的形态（`d^el` 转义、变量拼接命令名、延迟展开、`^` 续行）整体拒绝。
- 裸名脚本按对应 Shell 的真实查找语义绑定检查对象：PowerShell 裸名只按 PATH；cmd 裸名当前目录（PATHEXT）优先于 PATH——避免"检查 A、执行 B"。
- 未加引号的方括号路径（`.\[wipe].ps1`）是 PowerShell 通配符语义，无法确定实际文件，直接拒绝。
- 其他外部脚本内部删除（如 `python cleanup.py`）、MCP 文件工具、编辑器删文件：命令文本与脚本语义不可见，无法拦截。
- 持久终端切换目录后，会话记录的工作目录可能过期，脚本解析可能定位到同名错误文件；已知残留风险。
- `Invoke-Expression` / `-EncodedCommand` 不可见载荷、外部程序自删（`git clean`、自带 rm.exe）：放行等于无防护，维持拒绝。
- 仅支持 Windows（依赖回收站与 PowerShell）。

## 卸载

通过插件管理器卸载本包并新开会话即可；生成的 `runtime.json`、`recycle.cmd`、`logs/` 随包目录一并移除。

## 许可

MIT
