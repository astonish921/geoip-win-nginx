<#
================================================================================
 Test-GeoIpBlock.ps1  -  离线校验某个 IP 会不会被拦截（不需要 nginx、不需要联网）
--------------------------------------------------------------------------------
 作用：按 nginx geo 模块的语义（最长前缀匹配）解析 blocklist.conf，
       判断给定 IP 命中的是「放行」还是「拦截」，用于上线前自测、故障排查。

 示例：
   .\Test-GeoIpBlock.ps1 -Ip 8.8.8.8                       # 看是否被拦
   .\Test-GeoIpBlock.ps1 -Ip 114.114.114.114, 2400:3200::1
   .\Test-GeoIpBlock.ps1 -IpFile .\ip-list.txt            # 每行一个 IP
   .\Test-GeoIpBlock.ps1 -Ip 1.2.3.4 -ConfigPath C:\nginx\geoip\blocklist.conf
================================================================================
#>
[CmdletBinding()]
param(
    [string[]]$Ip,
    [string]$IpFile,
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'

$scriptDir = $null
if ($PSCommandPath) { $scriptDir = Split-Path -Parent $PSCommandPath }
elseif ($MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

if (-not $ConfigPath) {
    $candidates = New-Object System.Collections.ArrayList
    if ($scriptDir) {
        [void]$candidates.Add((Join-Path $scriptDir 'blocklist.conf'))
        [void]$candidates.Add((Join-Path (Split-Path $scriptDir -Parent) 'geoip\blocklist.conf'))
    }
    [void]$candidates.Add('C:\nginx\geoip\blocklist.conf')
    $ConfigPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) {
    throw "找不到 blocklist.conf，请用 -ConfigPath 指定（例如 C:\nginx\geoip\blocklist.conf）"
}

# 传的是目录时（如 -DryRun 快照目录 _dryrun\20261103-114120），自动取其中的 blocklist.conf
if (Test-Path -LiteralPath $ConfigPath -PathType Container) {
    $direct = Join-Path $ConfigPath 'blocklist.conf'
    if (-not (Test-Path -LiteralPath $direct)) {
        # 目录里没有（例如传的是 _dryrun 根目录），取子目录中最新的一份
        $latest = Get-ChildItem -LiteralPath $ConfigPath -Directory |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'blocklist.conf') } |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) { $direct = Join-Path $latest.FullName 'blocklist.conf' }
    }
    if (-not (Test-Path -LiteralPath $direct -PathType Leaf)) {
        throw "目录里没有 blocklist.conf：$ConfigPath"
    }
    $ConfigPath = $direct
}

# ---------- 解析配置文件 ----------
$entries = New-Object System.Collections.ArrayList
$default = '0'
$lineNo = 0
foreach ($raw in [System.IO.File]::ReadAllLines($ConfigPath)) {
    $lineNo++
    $l = $raw.Trim()
    if (-not $l) { continue }
    if ($l.StartsWith('#')) { continue }

    $m = [regex]::Match($l, '^default\s+(\S+)\s*;')
    if ($m.Success) { $default = $m.Groups[1].Value; continue }

    $m = [regex]::Match($l, '^([0-9A-Fa-f:\.]+/\d+)\s+(\S+)\s*;')
    if (-not $m.Success) { continue }

    $net = $m.Groups[1].Value
    $val = $m.Groups[2].Value
    $parts = $net.Split('/')
    $addr = $null
    try { $addr = [System.Net.IPAddress]::Parse($parts[0]) } catch { continue }
    $prefix = [int]$parts[1]
    [void]$entries.Add([pscustomobject]@{
        Network = $net
        Bytes   = $addr.GetAddressBytes()
        Family  = $addr.AddressFamily
        Prefix  = $prefix
        Value   = $val
    })
}

Write-Host ("加载 {0} 条规则（default = {1}），来自 {2}" -f $entries.Count, $default, $ConfigPath) -ForegroundColor DarkGray

function Test-PrefixMatch {
    param([byte[]]$A, [byte[]]$B, [int]$Prefix)
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    $full = [math]::Floor($Prefix / 8)
    for ($i = 0; $i -lt $full; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    $rem = $Prefix % 8
    if ($rem -gt 0) {
        $mask = (0xFF -shl (8 - $rem)) -band 0xFF
        if (($A[$full] -band $mask) -ne ($B[$full] -band $mask)) { return $false }
    }
    return $true
}

# ---------- 待测 IP ----------
$targets = New-Object System.Collections.ArrayList
if ($Ip) { foreach ($x in ($Ip -join ',').Split(',')) { if ($x.Trim()) { [void]$targets.Add($x.Trim()) } } }
if ($IpFile) {
    if (-not (Test-Path -LiteralPath $IpFile)) { throw "IP 列表文件不存在：$IpFile" }
    foreach ($l in [System.IO.File]::ReadAllLines($IpFile)) {
        $t = $l.Trim()
        if (-not $t) { continue }
        if ($t.StartsWith('#')) { continue }
        [void]$targets.Add($t)
    }
}
if ($targets.Count -eq 0) { throw '请用 -Ip 或 -IpFile 指定至少一个 IP' }

Write-Host ''
foreach ($t in $targets) {
    $addr = $null
    try { $addr = [System.Net.IPAddress]::Parse($t) } catch {
        Write-Host ("{0,-42} 无法解析为 IP" -f $t) -ForegroundColor Yellow
        continue
    }
    $bytes = $addr.GetAddressBytes()
    $family = $addr.AddressFamily

    $best = $null
    $bestPrefix = -1
    foreach ($e in $entries) {
        if ($e.Family -ne $family) { continue }
        if ($e.Prefix -le $bestPrefix) { continue }
        if (Test-PrefixMatch -A $e.Bytes -B $bytes -Prefix $e.Prefix) {
            $best = $e
            $bestPrefix = $e.Prefix
        }
    }

    $value   = if ($best) { $best.Value } else { $default }
    $hitText = if ($best) { $best.Network } else { 'default' }
    $verdict = if ($value -eq '1') { '拦截 (BLOCK)' } else { '放行 (PASS)' }
    $color   = if ($value -eq '1') { 'Red' } else { 'Green' }

    Write-Host ("{0,-42} {1,-10} 命中 {2,-22} -> {3}" -f $t, $verdict, $hitText, ("geoip_block=" + $value)) -ForegroundColor $color
}
Write-Host ''
Write-Host '提示：geo 变量为 1 时由 server{} 里的 if ($geoip_block) { return 403; } 拦截。' -ForegroundColor DarkGray
