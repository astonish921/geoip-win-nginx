<#
================================================================================
 install-task.ps1  -  注册 / 卸载「MaxMind GeoIP 每周更新」计划任务
--------------------------------------------------------------------------------
 默认：每周三 04:30（MaxMind 的 GeoLite2 通常在周二、周五发布新版本，
       周三跑可以稳拿周二的版本；想跟得更紧用 -Days Tuesday,Friday）

 示例：
   # 安装（默认周三 04:30，SYSTEM 身份，错过后自动补跑）
   .\install-task.ps1 -NginxDir C:\nginx

   # 每周二、周五各跑一次
   .\install-task.ps1 -NginxDir C:\nginx -Days Tuesday,Friday

   # 用指定账号跑（需要该账号有 nginx 目录读写权限）
   .\install-task.ps1 -NginxDir C:\nginx -UserId "DOMAIN\svc_nginx" -UserPassword "***"

   # 查看 / 立即测试 / 卸载
   .\install-task.ps1 -Show
   .\install-task.ps1 -RunNow
   .\install-task.ps1 -Remove
================================================================================
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'MaxMind-GeoIP-Weekly-Update',
    [string]$NginxDir,
    [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
    [string[]]$Days = @('Wednesday'),
    [string]$Time = '04:30',
    [string]$UserId = 'SYSTEM',
    [string]$UserPassword,
    [string]$ScriptPath,
    [string]$ConfigPath,
    [switch]$Remove,
    [switch]$Show,
    [switch]$RunNow
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot 在 param() 默认值里不一定可用，改在脚本体里解析
$scriptDir = $null
if ($PSCommandPath) { $scriptDir = Split-Path -Parent $PSCommandPath }
elseif ($MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptPath -and $scriptDir) { $ScriptPath = Join-Path $scriptDir 'geoip-update.ps1' }
if (-not $ConfigPath -and $scriptDir) { $ConfigPath = Join-Path $scriptDir 'geoip.config.json' }

function Write-Step { param([string]$m) Write-Host ('[*] ' + $m) -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host ('[+] ' + $m) -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host ('[!] ' + $m) -ForegroundColor Yellow }

try {
    if ($Show) {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $t) { Write-Warn2 "未找到任务 $TaskName"; exit 3 }
        $i = Get-ScheduledTaskInfo -TaskName $TaskName
        $t | Select-Object TaskName, State, @{n = 'Trigger'; e = { $_.Triggers | ForEach-Object { $_.StartBoundary } } } | Format-List
        Write-Host ('上次运行: ' + $i.LastRunTime + '  结果: 0x' + ('{0:X}' -f $i.LastTaskResult))
        Write-Host ('下次运行: ' + $i.NextRunTime)
        exit 0
    }

    if ($Remove) {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Ok "已删除计划任务 $TaskName"
        } else {
            Write-Warn2 "任务 $TaskName 不存在"
        }
        exit 0
    }

    if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "找不到主脚本：$ScriptPath" }

    $argList = '-NoProfile -ExecutionPolicy Bypass -File "' + $ScriptPath + '"'
    if (Test-Path -LiteralPath $ConfigPath) {
        $argList += ' -ConfigPath "' + $ConfigPath + '"'
    }
    if ($NginxDir) { $argList += ' -NginxDir "' + $NginxDir + '"' }

    Write-Step "计划任务    : $TaskName"
    Write-Step "执行命令    : powershell.exe $argList"
    Write-Step "触发时间    : 每周 $($Days -join ',') $Time"

    $cmd = Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue
    if ($cmd) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList

        $hh, $mm = $Time.Split(':')
        $at = (Get-Date).Date.AddHours([int]$hh).AddMinutes([int]$mm)
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Days -At $at

        $settings = New-ScheduledTaskSettingsSet `
            -StartWhenAvailable `
            -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries

        if ($UserId -eq 'SYSTEM') {
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'MaxMind GeoLite2 周更 + nginx 拦截配置生成' -Force | Out-Null
            Write-Ok "已注册（SYSTEM 身份，最高权限，错过后自动补跑）"
        } else {
            if (-not $UserPassword) { throw '使用 -UserId 指定非 SYSTEM 账号时必须同时提供 -UserPassword' }
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description 'MaxMind GeoLite2 周更 + nginx 拦截配置生成' -User $UserId -Password $UserPassword -RunLevel Highest -Force | Out-Null
            Write-Ok "已注册（账号身份 $UserId）"
        }
    } else {
        # 兜底：老系统用 schtasks
        $tr = 'powershell.exe ' + $argList
        $day = ($Days | ForEach-Object { $_.Substring(0, 3).ToUpper() }) -join ','
        $args2 = @('/Create', '/TN', $TaskName, '/TR', $tr, '/SC', 'WEEKLY', '/D', $day, '/ST', $Time, '/RU', $UserId, '/RL', 'HIGHEST', '/F')
        & schtasks.exe @args2
        if ($LASTEXITCODE -ne 0) { throw "schtasks 注册失败（退出码 $LASTEXITCODE）" }
        Write-Ok '已通过 schtasks 注册'
    }

    if ($RunNow) {
        Start-ScheduledTask -TaskName $TaskName
        Write-Ok '已触发一次立即运行（可用 -Show 查看结果）'
    }

    Write-Host ''
    Write-Host '提示：首次上线建议先手工跑一次演练，确认拦截范围无误后再交给计划任务：' -ForegroundColor Yellow
    Write-Host ('  powershell -NoProfile -ExecutionPolicy Bypass -File "' + $ScriptPath + '" -NginxDir ' + $NginxDir + ' -DryRun') -ForegroundColor Gray
    exit 0
} catch {
    Write-Host ('[x] ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
