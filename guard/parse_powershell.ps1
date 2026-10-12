# 只解析语法树，不执行输入；参数取值必须是静态字面量。
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$source = [Console]::In.ReadToEnd()
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
$commands = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]}, $true))
$names = @($commands | ForEach-Object { $_.GetCommandName() })
# 复杂删除只开放明确的语法子集；方法调用、定义、环境修改会使静态替换的边界失效。
$unsafe = $false
$commandSites = @()
foreach ($command in $commands) {
    $head = $command.CommandElements[0]
    $parameters = @($command.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName.ToLowerInvariant() })
    $splat = @($command.FindAll({param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Splatted}, $true)).Count -gt 0
    # 参数字面量：供调用方识别 -File/-Command 包装与解释器入口的脚本路径。
    # 非字面量参数标记 opaque，调用方不得对其做任何"看起来安全"的推断。
    $args_ = @()
    foreach ($element in @($command.CommandElements | Select-Object -Skip 1)) {
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            $argValue = $element.Argument
            if ($null -eq $argValue) {
                $args_ += @{value = '-' + $element.ParameterName; quoted = $false; parameter = $true; opaque = $false; start = $element.Extent.StartOffset; end = $element.Extent.EndOffset}
            } elseif ($argValue -is [System.Management.Automation.Language.StringConstantExpressionAst] -or ($argValue -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $argValue.NestedExpressions.Count -eq 0)) {
                # start/end 是参数值（而非参数名）的原文区间，供精确改写。
                $args_ += @{value = $argValue.Value; quoted = $true; parameter = $true; opaque = $false; start = $argValue.Extent.StartOffset; end = $argValue.Extent.EndOffset}
            } else {
                $args_ += @{value = ''; quoted = $false; parameter = $true; opaque = $true; start = $null; end = $null}
            }
        } elseif ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $args_ += @{value = $element.Value; quoted = $element.StringConstantType.ToString() -ne 'BareWord'; parameter = $false; opaque = $false; start = $element.Extent.StartOffset; end = $element.Extent.EndOffset}
        } elseif ($element -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $element.NestedExpressions.Count -eq 0) {
            $args_ += @{value = $element.Value; quoted = $true; parameter = $false; opaque = $false; start = $element.Extent.StartOffset; end = $element.Extent.EndOffset}
        } else {
            $args_ += @{value = ''; quoted = $false; parameter = $false; opaque = $true; start = $null; end = $null}
        }
    }
    $commandSites += @{name = $command.GetCommandName(); start = $head.Extent.StartOffset; end = $head.Extent.EndOffset; invocation = $command.InvocationOperator.ToString(); parameters = $parameters; splat = $splat; args = $args_}
    if ($command.Redirections.Count -gt 0) { $unsafe = $true }
}
$nodes = @($ast.FindAll({param($n) $true}, $true))
$limitExceeded = $nodes.Count -gt 10000 -or $commands.Count -gt 1000
if ($limitExceeded) { $unsafe = $true }
$envAssigns = @()
$dangerousMembers = @()
foreach ($node in $nodes) {
    if ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
        if ($node.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $node.Member.Value -match '^(?i:delete|deletefile|deletefolder|remove|unlink|rmdir)(sync|async)?$') {
            $dangerousMembers += $node.Extent.Text
        }
    }
    if ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
        $node -is [System.Management.Automation.Language.TypeDefinitionAst] -or
        $node -is [System.Management.Automation.Language.ConvertExpressionAst] -or
        $node -is [System.Management.Automation.Language.TypeExpressionAst] -or
        $node -is [System.Management.Automation.Language.AttributeAst] -or
        $node -is [System.Management.Automation.Language.ParamBlockAst] -or
        $node -is [System.Management.Automation.Language.UsingStatementAst] -or
        $node -is [System.Management.Automation.Language.TrapStatementAst] -or
        ($node -is [System.Management.Automation.Language.PipelineAst] -and $node.Background)) { $unsafe = $true }
    if ($node -is [System.Management.Automation.Language.NamedBlockAst] -and $node.BlockKind.ToString() -in @('Begin', 'Process', 'Clean')) { $unsafe = $true }
    if ($node -is [System.Management.Automation.Language.AssignmentStatementAst]) {
        if ($node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -match '^(?i:env:)?path(ext)?$') {
            # PATH/PATHEXT 赋值单独上报：调用方需据此拒绝依赖原 PATH 解析的后续调用。
            $envAssigns += $node.Left.VariablePath.UserPath
        }
        if ($node.Left -isnot [System.Management.Automation.Language.VariableExpressionAst] -or
            $node.Left.VariablePath.UserPath -match ':|^(?:ErrorActionPreference|PSDefaultParameterValues|PSModuleAutoLoadingPreference|ExecutionContext|PSCmdlet|env|args|input|PSScriptRoot|PSCommandPath)$') { $unsafe = $true }
    }
    if ($node -is [System.Management.Automation.Language.UnaryExpressionAst] -and $node.TokenKind.ToString() -match 'PlusPlus|MinusMinus') {
        if ($node.Child -isnot [System.Management.Automation.Language.VariableExpressionAst] -or $node.Child.VariablePath.UserPath -match ':') { $unsafe = $true }
    }
}
$simple = $false
$parts = @()
if ($commands.Count -eq 1 -and $null -eq $ast.BeginBlock -and $null -eq $ast.ProcessBlock -and $null -eq $ast.CleanBlock -and $null -eq $ast.ParamBlock -and $ast.EndBlock.Traps.Count -eq 0 -and $ast.EndBlock.Statements.Count -eq 1) {
    $statement = $ast.EndBlock.Statements[0]
    $simple = $statement -is [System.Management.Automation.Language.PipelineAst] -and -not $statement.Background -and $statement.PipelineElements.Count -eq 1 -and $statement.PipelineElements[0] -eq $commands[0] -and $commands[0].Redirections.Count -eq 0
    $group = 0
    foreach ($element in $commands[0].CommandElements) {
        $group++
        if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and $null -eq $element.Argument) {
            $parts += @{value = '-' + $element.ParameterName; quoted = $false; parameter = $true; group = $group}
        } elseif ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $parts += @{value = $element.Value; quoted = $element.StringConstantType.ToString() -ne 'BareWord'; parameter = $false; group = $group}
        } elseif ($element -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $element.NestedExpressions.Count -eq 0) {
            $parts += @{value = $element.Value; quoted = $true; parameter = $false; group = $group}
        } elseif ($element -is [System.Management.Automation.Language.ArrayLiteralAst]) {
            foreach ($item in $element.Elements) {
                if ($item -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $parts += @{value = $item.Value; quoted = $true; parameter = $false; group = $group}
                } else { $simple = $false }
            }
        } else { $simple = $false }
    }
}
@{names = $names; commands = $commandSites; unsafe = $unsafe; simple = $simple; parts = $parts; errors = @($errors | ForEach-Object {$_.Message}); dynamic = @($names | Where-Object {$null -eq $_}).Count -gt 0; envAssigns = $envAssigns; dangerousMembers = $dangerousMembers; limitExceeded = $limitExceeded} | ConvertTo-Json -Depth 6 -Compress
