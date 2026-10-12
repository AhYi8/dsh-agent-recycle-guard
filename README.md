# DSH 删除防护

Agent 直接提交的常见删除命令改为系统回收站操作；执行脚本前做有限的内容检查。优先支持 DSH，支持 Windows、Linux 与 macOS 的回收后端，不提供永久删除兜底。

## 安装

安装到 DSH 后直接使用，默认无需填写配置、预装 Python 或手动安装 Python 依赖。Windows 使用系统自带 PowerShell 5.1 或已有 PowerShell 7；Linux/macOS 的 Bash 删除不依赖 PowerShell，执行 `.ps1` 时仍需相应平台的 PowerShell。

```text
dsh plugin install dsh-agent-recycle-guard
```

运行环境按以下优先级自动准备，均无需管理员权限、不执行远程安装脚本、不依赖 npm 安装生命周期脚本：

1. **DSH 内置 Python（默认路线）**：复用 DSH 宿主自带的托管 Python（`~/.dsh/dsh-runtimes/*/dependencies/python`，要求 3.10+ 且带 pip），用它创建隔离 venv，只从 PyPI 镜像补装缺失依赖，**不下载任何可执行文件**。
2. **uv 自动准备（兜底路线）**：找不到内置 Python 时，下载固定版本 uv（核对内置 SHA-256），由 uv 准备隔离的 Python 3.12 与依赖；uv 与托管 Python 从 GitHub 官方发布下载并使用系统代理。

Python 依赖先依次尝试清华、阿里云、腾讯云 PyPI 镜像，均失败后回退官方 PyPI。运行环境缓存位于用户目录 `.cache/dsh-agent-recycle-guard`，同进程并发只准备一次，跨进程环境锁由插件管理。后续会话核对缓存依赖后复用，已准备好的环境无需重复联网；依赖清单变化、DSH 升级替换内置 Python 或缓存失效时自动重建。准备期间命令等待检查；准备失败时阻止命令，下次调用可重试。DSH 宿主内首次使用仅需能访问至少一个 PyPI 源；离线且没有缓存时无法自动准备。支持 Windows/Linux/macOS 的 x64、arm64，Linux 同时支持 glibc 与 musl。

高级用户可通过 `config.python` 指定解释器绝对路径，或用 `config.pypiIndex`（或环境变量 `AGENT_RECYCLE_GUARD_PYPI_INDEX`）指定 HTTPS simple 索引，插件仍自动准备隔离依赖；这些都不是必填配置。安装或更新后新开 DSH 会话。尚未发布的源码改动不改变 npm 上旧版本的安装行为。

插件默认按 DSH 执行器解析工作目录，PowerShell 工具使用 PowerShell 语义，其他工具默认 Bash。非标准 CMD 工具可通过 `config.shell: cmd` 配置，已有工具参数 `shell` 也受支持。插件检查改写后的调用仍经过 DSH 原有权限和沙箱；不在宿主插件里绕过沙箱执行回收。

## 直接命令：严格处理删除

PowerShell 通过 AST 定位 `Remove-Item` 及常见别名，保留变量、循环、管道和伴随命令，把删除调用替换为回收入口。例如：

```powershell
$taskHome = Join-Path $dev 'tmp-dshhome'
Remove-Item $taskHome -Recurse -Force
```

`$HOME` 是 PowerShell 内置只读变量，示例使用独立变量。运行时按真实工作目录解析目标，不能因为路径在检查时还不存在就误拒。`-WhatIf` 保留为预演。

Bash 使用 bashlex AST 定位 `rm`、`unlink`、`rmdir`，只替换命令头，变量、通配符、循环和多行仍由原 Shell 展开。回收执行器接收已展开的参数，不再次解释代码。CMD 支持独立或多行 `del`、`erase`、`rd`、`rmdir`；复杂条件、循环、转义删除与嵌套包装无法可靠改写时拒绝，提示拆为普通调用。

`git clean`、磁盘抹除、`.NET Delete()`、动态删除别名、无法核实的动态/编码命令等不改写为回收，而是拒绝。拒绝意味着原始删除不会执行。此插件不是操作系统级隔离，不能阻止任意外部程序内部隐藏的文件操作。

## 执行脚本：尽力检查，控制复杂度

按执行位置识别脚本并读内容，合法文件名不按点号、等号或中文排除；`Get-Content wipe.ps1` 等数据读取不检查文件里的删除语句。

| 脚本 | 处理 |
|---|---|
| `.ps1` | 复用直接命令检查；发现可改写删除则执行改写副本，兼容变量和多行 |
| `.cmd` / `.bat` | 检查常见删除及子脚本，发现删除时拒绝，避免改变 `%~dp0`、`call/goto` 语义 |
| Python / `.python` | 标准库 AST 检查 `os.remove/unlink/rmdir`、`shutil.rmtree`、`Path.unlink/rmdir` 及常见导入别名；发现则拒绝 |
| JavaScript / TypeScript | 有限规则检查 `unlink/rm/rmdir`、同步调用、常见解构调用与 `rimraf`；发现则拒绝 |
| Bash 脚本 | AST 检查并生成删除转回收的副本；内联 `bash -c` 同样处理 |

解释器的脚本参数以实际执行目录解析，语言由解释器决定。例如 `python code.txt` 仍按 Python 检查。PowerShell `-File` 和 `-Command`、常见脚本嵌套调用会进入同一套有限检查。递归最多三层，文本最多 128 KiB；未知编码、超大文件、动态加载、Python 模块和深层导入超出尽力检查范围，可能放行。脚本不承诺全量覆盖，避免演变为通用程序验证器。

改写副本仅绑定被改写的脚本内容，干净脚本继续执行原文件；同用户并发修改、动态 PATH/cwd、模块与外部程序内部加载仍可能漏检。含删除且依赖 `$PSScriptRoot`、`$PSCommandPath`、`BASH_SOURCE` 等原位置的脚本，以及需保留点源作用域的调用会拒绝，提示改成独立删除命令。PowerShell 副本为无 BOM 的 ASCII 外壳，显式解码 UTF-8 内容，兼容 5.1 中文路径。

CMD 包装解释器时，如果脚本需要改写为回收副本则拒绝，提示独立调用对应 Shell；不能丢弃改写结果而继续执行原脚本。

## 回收行为

- Windows：使用 COM `IFileOperation`，拒绝永久删除请求，核对回收站项目回执。
- Linux/macOS：使用 Send2Trash 的平台后端；回收区不可用或权限不足时返回错误，不调用永久删除 API 兜底。Linux 无桌面环境时仍可使用 freedesktop 回收目录；恢复可通过回收元数据完成。
- 根目录、用户目录本身、防护目录及其祖先、回收区、符号链接或 Windows 重解析路径受保护；递归目录会先校验内容与扫描上限。
- 删除选项无法保持语义时拒绝，不把非递归删除扩大为整目录回收。

运行配置和改写副本在插件 `guard/runtime.json`、`guard/logs/` 生成。不要手工改运行配置以放宽受保护范围。日志仅记录决策与回收结果，不保存整条命令。

## 验证与维护

```text
python -m pip install -r requirements-dev.txt
node --test tests/runtime.test.mjs
python -X utf8 tests/run_all.py
```

测试按新产品契约严格断言 `allow/rewrite/deny`，覆盖直接命令、多行、脚本入口、解释器参数、回收失败无永久删除退路，以及真实回收站回执。真实回收测试只操作独立测试目录里创建的文件。旧的“任意脚本都必须证明安全”探针已由当前契约回归替换。

`.github/workflows/test.yml` 提供 Windows/Linux/macOS 测试矩阵。工作区内添加矩阵不等于 CI 已运行；平台实际验证状态以测试输出和交付说明为准。

已安装 DSH 的开发机还可执行 `node tests/integration_dsh.mjs`，使用真实 Cordis 工具管线与只记录参数的测试工具。若 DSH 未在仓库的依赖搜索路径中，设置 `DSH_PACKAGE_JSON` 为其 `package.json` 绝对路径；`GUARD_PYTHON`、`GUARD_PWSH` 可指定测试解释器，`GUARD_TEST_TMP` 可指定独立测试目录。Windows Git Bash 端到端测试通过 `GUARD_BASH` 指定执行器，未配置时仅跳过这项。

`guard.py hook --agent claude` 保留 PreToolUse JSON 协议，`--agent codex` 的原有入口也保留；本次不自动修改 Codex/Claude 的安装配置，它们的版本及钩子能力需单独验证。DSH 是优先适配对象。

## 卸载

在 DSH 插件管理器卸载并新开会话。插件运行目录的清理由插件管理器负责，回收站中的用户文件不随卸载删除。

参考：[uv 自动准备 Python](https://docs.astral.sh/uv/guides/install-python/)、[uv 缓存与并发](https://docs.astral.sh/uv/concepts/cache/)、[Send2Trash](https://github.com/arsenetar/send2trash)、[bashlex](https://github.com/idank/bashlex)、[DSH](https://github.com/deepseek-ai/deepseek-harness)。许可：MIT。
