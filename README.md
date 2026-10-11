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
- 改写后的命令作为新调用重新走完整的权限与沙箱检查，`pre-execute` 与 `execute` 之间用 token 配对，缺检查记录直接拒绝。

## 零配置引导

首次运行时 `guard.py` 自动在本包 `guard/` 目录生成：

- `runtime.json`：探测到的 python（当前解释器）、pwsh（PATH 中 `pwsh` 或 `powershell`）、安装目录、受保护路径（默认整个用户主目录）。
- `recycle.cmd`：按当前 python 解释器生成的回收启动器。

如需覆盖 python 路径，可在 profile 的 `cordis.patch.yml` 追加同 id（`agent-recycle-guard`）顶层行携带 `config: { python: <绝对路径> }`。

## 边界（有意保留的 fail-closed）

- 外部脚本内部删除（如 `python cleanup.py`）、MCP 文件工具、编辑器删文件：命令文本不可见，无法拦截。
- `Invoke-Expression` / `-EncodedCommand` 不可见载荷、外部程序自删（`git clean`、自带 rm.exe）：放行等于无防护，维持拒绝。
- 仅支持 Windows（依赖回收站与 PowerShell）。

## 卸载

通过插件管理器卸载本包并新开会话即可；生成的 `runtime.json`、`recycle.cmd`、`logs/` 随包目录一并移除。

## 许可

MIT
