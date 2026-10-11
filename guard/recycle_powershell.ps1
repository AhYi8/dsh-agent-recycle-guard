[CmdletBinding(DefaultParameterSetName='Path')]
param(
    [Parameter(Mandatory, Position=0, ValueFromPipeline, ParameterSetName='Path')][object[]]$Path,
    [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName='LiteralPath')][Alias('PSPath','lp')][string[]]$LiteralPath,
    [Alias('r')][switch]$Recurse,
    [switch]$Force,
    [switch]$WhatIf,
    [switch]$Confirm
)
begin {
    $implementationPath = Join-Path $PSScriptRoot 'recycle_powershell_impl.ps1'
    $implementation = [ScriptBlock]::Create([IO.File]::ReadAllText($implementationPath, [Text.Encoding]::UTF8))
}
process {
    & $implementation @PSBoundParameters -GuardRoot $PSScriptRoot
}
