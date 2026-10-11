# 入口是纯 ASCII，显式按 UTF-8 加载本实现，兼容旧终端且无需 BOM。
# 根目录由入口传入：动态创建的脚本块没有可靠的 PSScriptRoot。
# 每个删除调用单独进入此脚本，不覆盖全局函数，不影响持久终端的后续命令。
[CmdletBinding(DefaultParameterSetName='Path')]
param(
    [Parameter(Mandatory, Position=0, ValueFromPipeline, ParameterSetName='Path')][object[]]$Path,
    [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName='LiteralPath')][Alias('PSPath','lp')][string[]]$LiteralPath,
    [Alias('r')][switch]$Recurse,
    [switch]$Force,
    [switch]$WhatIf,
    [switch]$Confirm,
    [Parameter(Mandatory)][string]$GuardRoot
)
begin {
    $settings = Get-Content -LiteralPath (Join-Path $GuardRoot 'runtime.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = $encoding
    $OutputEncoding = $encoding
    if ($Confirm) { throw '删除防护不发起交互确认，请拆成明确的删除调用。' }
}
process {
    # 当前目录在执行时读取，不能使用会话初始目录猜测 cd 或持久终端的实际位置。
    $location = Get-Location
    if ($location.Provider.Name -ne 'FileSystem') { throw '删除防护仅支持文件系统工作目录。' }
    $inputs = if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') { $LiteralPath } else { $Path }
    $items = @()
    foreach ($target in $inputs) {
        if ($target -is [System.IO.FileSystemInfo]) {
            $items += Get-Item -LiteralPath $target.FullName -Force:$Force -ErrorAction Stop
        } elseif ($target -is [string] -and $target.Length -gt 0) {
            if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
                $items += Get-Item -LiteralPath $target -Force:$Force -ErrorAction Stop
            } else {
                $items += Get-Item -Path $target -Force:$Force -ErrorAction Stop
            }
        } else { throw '删除防护的路径必须为非空字符串或文件系统项目。' }
    }
    if ($items.Count -eq 0) { throw '删除防护未匹配到目标，未执行任何删除。' }
    if ($items.Count -gt 1000) { throw '删除目标超过 1000 项，已阻止操作。' }
    foreach ($item in $items) {
        if ($item -isnot [System.IO.FileSystemInfo]) { throw '删除防护拒绝非文件系统目标，不执行原删除。' }
    }
    if ($WhatIf) {
        Write-Output '删除防护：预演，未执行删除。'
    } else {
        # 生成字面量检查请求，绝不使用 Invoke-Expression 执行拼接文本。
        $quoted = @($items | ForEach-Object { "'" + $_.FullName.Replace("'", "''") + "'" })
        $command = 'Remove-Item -LiteralPath ' + ($quoted -join ',')
        if ($Recurse) { $command += ' -Recurse' }
        if ($Force) { $command += ' -Force' }
        $request = @{tool_name='pwsh'; tool_input=@{command=$command}; cwd=$location.ProviderPath} | ConvertTo-Json -Depth 5 -Compress
        $output = $request | & $settings.python -X utf8 (Join-Path $GuardRoot 'guard.py') runtime --agent dsh
        if ($LASTEXITCODE -ne 0) { throw '删除防护回收失败，已停止当前调用；没有永久删除兜底。' }
        $text = $output -join "`n"
        if (-not $text.Trim()) { throw '删除防护执行器没有返回回收回执。' }
        Write-Output $text
    }
}
