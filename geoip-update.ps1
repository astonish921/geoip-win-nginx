<#
================================================================================
 geoip-update.ps1  -  MaxMind GeoLite2 每周自动更新 + nginx(Windows) 拦截配置生成
--------------------------------------------------------------------------------
 适用环境 : Windows Server 2012 / 2012 R2 + nginx for Windows (官方 zip 版)
 PowerShell: 4.0 及以上语法（不依赖 PS5 的 Expand-Archive / ::new() 等）

 背景（务必理解）:
   nginx 官方 Windows 版【不包含 GeoIP 模块】，原文见 http://nginx.org/en/docs/windows.html
   "provides almost the same functionality as a UNIX version of nginx except for
    XSLT filter, image filter, GeoIP module, and embedded Perl language."
   因此 Windows 上的 nginx 既不能读 .dat（ngx_http_geoip_module），也不能读 .mmdb
   （ngx_http_geoip2_module，第三方模块，Windows 版无法加载）。
   本脚本因此走"数据预处理"路线：
      1) 每周从 MaxMind 拉取 GeoLite2-Country-CSV（用于生成 CIDR）与 GeoLite2-Country.mmdb（归档备用）
      2) 用 CSV 生成"国家 -> CIDR 清单"，写成 nginx geo 模块可直接 include 的配置文件
      3) nginx -t 校验通过后原子替换并 reload，失败自动回滚

 输出文件（位于 -DataDir，默认 <nginx>\geoip）:
   blocklist.conf     可直接 include 的 geo 块（1=拦截 0=放行）
   networks.txt       纯 CIDR 清单（每行一个），供其它程序/审计使用
   meta.json          本次生成的数据版本、条目数、校验值
   GeoLite2-Country.mmdb   二进制库（Windows 上的 nginx 用不到，供其它程序使用/未来迁移）
   _logs\             运行日志
   _snapshots\        历史快照（保留 -KeepSnapshots 份）

 示例:
   # 首次演练（不落盘、不 reload，只打印统计）
   .\geoip-update.ps1 -NginxDir C:\nginx -DryRun

   # 只允许中国大陆 + 港澳台
   .\geoip-update.ps1 -NginxDir C:\nginx -Countries CN,HK,MO,TW

   # 反向：放行全球、只拦某几个国家
   .\geoip-update.ps1 -NginxDir C:\nginx -Mode DenyList -Countries RU,US

   # 断网自测：用本地 zip 跑完整流程
   .\geoip-update.ps1 -NginxDir C:\nginx -LocalCsvZip D:\tmp\GeoIP-CSV.zip -SkipNginxTest -DryRun
================================================================================
#>

[CmdletBinding()]
param(
    # 配置文件路径（可选，JSON）。优先级：命令行参数 > 环境变量 > 配置文件
    # 留空 = 自动取脚本同目录下的 geoip.config.json
    [string]$ConfigPath,

    # nginx 安装目录（含 nginx.exe 与 conf\nginx.conf）
    [string]$NginxDir,

    # 数据输出目录，默认 <NginxDir>\geoip
    [string]$DataDir,

    # nginx 的 Windows 服务名（如 nginx_fa）。nginx 以服务/SYSTEM 方式运行时，
    # 交互式 nginx -s reload 会 OpenEvent Access denied；配置此参数后 reload 失败
    # 会自动改为重启该服务让配置生效（也可写进 geoip.config.json 的 "nginxService"）
    [string]$NginxService,

    # MaxMind 账号（Basic Auth 的用户名）与 License Key
    [string]$AccountId,
    [string]$LicenseKey,

    # AllowOnly = 只放行 -Countries 中的国家，其余全拦（默认，适合"拦截国外IP"）
    # DenyList  = 放行全球，只拦 -Countries 中的国家
    [ValidateSet('AllowOnly', 'DenyList')]
    [string]$Mode = 'AllowOnly',

    # ISO 3166-1 两位国家码。注意：MaxMind 数据中 HK / MO / TW 是独立国家码，
    # 需要一并放行中国大陆时请写成 CN,HK,MO,TW
    [string[]]$Countries = @('CN'),

    # 始终放行的网段（内网、办公出口、监控探针等）。AllowOnly 模式下自动追加私有网段
    [string[]]$AlwaysAllow = @(),

    # 为 true 时不自动追加私有网段（仅 AllowOnly 模式生效）
    [switch]$NoDefaultPrivateRanges,

    # 数据版本
    [string]$EditionCsv  = 'GeoLite2-Country-CSV',
    [string]$EditionMmdb = 'GeoLite2-Country',

    # 无需 mmdb 时跳过（只生成 CIDR 配置）
    [switch]$SkipMmdb,

    # 快照保留份数
    [int]$KeepSnapshots = 6,

    # 安全阀：生成的 CIDR 条目少于此值则判定为异常，拒绝替换配置
    [int]$MinNetworks = 200,

    # 安全阀：新条目数低于上次的该比例时拒绝替换（防止上游数据异常把站点全封死）
    [int]$MinRatioPercent = 50,

    # 只做校验与 reload 之外的动作
    [switch]$NoReload,
    [switch]$SkipNginxTest,

    # 离线模式：指定本地 CSV zip / mmdb tar.gz，完全不联网（用于自测与内网分发）
    [string]$LocalCsvZip,
    [string]$LocalMmdbArchive,

    # 演练：生成到临时目录，不替换、不 reload
    [switch]$DryRun,

    # 保留工作目录（排查用；-DryRun 时默认保留）
    [switch]$KeepWorkDir,

    # 读取上次已更新的构建日期，若一致则跳过（省一次下载额度）
    [switch]$SkipIfSameBuild,

    [string]$LogFile
)

$ErrorActionPreference = 'Stop'
$script:Version = '1.0.0'
$script:LogPath = $null
$script:Steps   = New-Object System.Collections.ArrayList

# ==============================================================================
# 基础工具
# ==============================================================================
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'DEBUG')][string]$Level = 'INFO'
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = '[' + $ts + '] [' + $Level.PadRight(5) + '] ' + $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line }
    }

    if ($script:LogPath) {
        try {
            [System.IO.File]::AppendAllText($script:LogPath, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
        } catch { }
    }
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Write-TextFileNoBom {
    param([string]$Path, [string]$Text)
    # nginx 对配置文件的 BOM 比较敏感，统一写 UTF-8 无 BOM
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        Write-Log "配置文件解析失败：$Path -> $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Test-IsIPv6Network {
    param([string]$Network)
    return ($Network.IndexOf(':') -ge 0)
}

# ==============================================================================
# HTTP 下载：处理 MaxMind 的 R2 预签名跳转
#   2024-01 起 MaxMind 全部改用 R2 预签名 URL（302 -> cloudflarestorage.com）。
#   坑：.NET 的 HttpWebRequest 默认会把 Authorization 头带到新主机，
#       而预签名 URL 再带 Basic Auth 会被 S3 判为签名冲突（400/403）。
#       因此这里手工跟随一次跳转，第二跳不带认证头。
# ==============================================================================
function Initialize-Tls {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    } catch {
        try {
            # .NET 4.0 的枚举里没有 Tls12 名字，直接给数值 3072
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]3072
        } catch {
            Write-Log '无法启用 TLS 1.2，Windows Server 2012 需安装 .NET 4.5+ 并启用 TLS 1.2 客户端协议' 'WARN'
        }
    }
    try { [System.Net.ServicePointManager]::Expect100Continue = $false } catch { }
}

function Get-BasicAuthHeader {
    param([string]$User, [string]$Pass)
    $pair  = $User + ':' + $Pass
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    return 'Basic ' + [System.Convert]::ToBase64String($bytes)
}

function Invoke-WebRequestSafe {
    <#
      返回 PSCustomObject：StatusCode / Headers(hashtable) / ContentLength
      不自动跟随跳转；手工跟一跳（不带认证头）。
    #>
    param(
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$OutFile,
        [ValidateSet('GET', 'HEAD')][string]$Method = 'GET',
        [int]$MaxRedirect = 3
    )

    $current = $Uri
    $auth    = $Headers

    for ($hop = 0; $hop -le $MaxRedirect; $hop++) {
        $req = [System.Net.HttpWebRequest]::Create($current)
        $req.Method = $Method
        $req.Timeout = 120000
        $req.ReadWriteTimeout = 300000
        $req.AllowAutoRedirect = $false
        $req.UserAgent = 'geoip-update-ps/' + $script:Version
        foreach ($k in $auth.Keys) { $req.Headers[$k] = $auth[$k] }

        try {
            $resp = $req.GetResponse()
        } catch [System.Net.WebException] {
            $wex = $_.Exception
            if ($wex.Response -ne $null) {
                $code = [int]$wex.Response.StatusCode
                $loc  = $wex.Response.Headers['Location']
                if (($code -ge 300) -and ($code -lt 400) -and $loc) {
                    $current = $loc
                    $auth    = @{}          # 关键：跳转后不再带认证头
                    continue
                }
                $body = ''
                try {
                    $sr = New-Object -TypeName System.IO.StreamReader -ArgumentList $wex.Response.GetResponseStream()
                    $body = $sr.ReadToEnd(); $sr.Close(); $wex.Response.Close()
                } catch { }
                throw ("HTTP $code $($wex.Message) $body").Trim()
            }
            throw $wex.Message
        }

        $code = [int]$resp.StatusCode
        if (($code -ge 300) -and ($code -lt 400)) {
            $loc = $resp.Headers['Location']
            $resp.Close()
            if (-not $loc) { throw "HTTP $code 但缺少 Location 头" }
            $current = $loc
            $auth    = @{}
            continue
        }

        $len     = $resp.ContentLength
        $hLast   = $resp.Headers['Last-Modified']
        $hDisp   = $resp.Headers['Content-Disposition']
        if ($OutFile -and $Method -eq 'GET') {
            $fs = [System.IO.File]::Create($OutFile)
            try {
                $stream = $resp.GetResponseStream()
                $buf = New-Object byte[] 81920
                while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
                    $fs.Write($buf, 0, $n)
                }
            } finally {
                $fs.Close()
                $resp.Close()
            }
        } elseif ($OutFile -and $Method -eq 'HEAD') {
            $resp.Close()
        } else {
            $sr = New-Object -TypeName System.IO.StreamReader -ArgumentList $resp.GetResponseStream()
            $text = $sr.ReadToEnd()
            $sr.Close(); $resp.Close()
            return [pscustomobject]@{ StatusCode = $code; Headers = @{}; ContentLength = 0; Content = $text }
        }

        return [pscustomobject]@{
            StatusCode    = $code
            ContentLength = $len
            Headers       = @{ 'Last-Modified' = $hLast; 'Content-Disposition' = $hDisp }
            Content       = $null
        }
    }
    throw '重定向次数过多'
}

function Get-MaxMindUrl {
    param(
        [string]$EditionId,
        [string]$Suffix,
        [string]$AccountId,
        [string]$LicenseKey
    )
    if ($AccountId) {
        # 现行端点（2024 起）：Basic Auth
        return 'https://download.maxmind.com/geoip/databases/' + $EditionId + '/download?suffix=' + $Suffix
    }
    # 旧端点：license_key 走查询串，仍会 302 到 R2
    return 'https://download.maxmind.com/app/geoip_download?edition_id=' + $EditionId +
           '&license_key=' + [System.Uri]::EscapeDataString($LicenseKey) + '&suffix=' + $Suffix
}

function Save-MaxMindFile {
    param(
        [string]$EditionId,
        [string]$Suffix,
        [string]$OutFile,
        [string]$AccountId,
        [string]$LicenseKey,
        [int]$Retry = 3
    )
    $uri = Get-MaxMindUrl -EditionId $EditionId -Suffix $Suffix -AccountId $AccountId -LicenseKey $LicenseKey
    $hdr = @{}
    if ($AccountId) { $hdr['Authorization'] = Get-BasicAuthHeader -User $AccountId -Pass $LicenseKey }

    for ($i = 1; $i -le $Retry; $i++) {
        try {
            Write-Log "下载 $EditionId ($Suffix) 第 $i 次尝试 ..." 'DEBUG'
            $r = Invoke-WebRequestSafe -Uri $uri -Headers $hdr -OutFile $OutFile -Method 'GET'
            if (-not (Test-Path -LiteralPath $OutFile)) { throw '下载后文件不存在' }
            $size = (Get-Item -LiteralPath $OutFile).Length
            if ($size -lt 1024) { throw "文件过小（$size 字节），疑似返回了错误页" }
            Write-Log ("下载完成：{0} ({1:N0} 字节)" -f (Split-Path $OutFile -Leaf), $size) 'OK'
            return $r
        } catch {
            $msg = $_.Exception.Message
            Write-Log "第 $i 次下载失败：$msg" 'WARN'
            if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
            if ($i -lt $Retry) { Start-Sleep -Seconds (5 * $i) }
            else { throw "下载 $EditionId 失败（已重试 $Retry 次）：$msg" }
        }
    }
}

function Get-RemoteChecksum {
    param([string]$EditionId, [string]$Suffix, [string]$AccountId, [string]$LicenseKey)
    try {
        $uri = Get-MaxMindUrl -EditionId $EditionId -Suffix $Suffix -AccountId $AccountId -LicenseKey $LicenseKey
        $hdr = @{}
        if ($AccountId) { $hdr['Authorization'] = Get-BasicAuthHeader -User $AccountId -Pass $LicenseKey }
        $r = Invoke-WebRequestSafe -Uri $uri -Headers $hdr -Method 'GET'
        $txt = [string]$r.Content
        if (-not $txt) { return $null }
        $first = ($txt.Trim() -split '\s+')[0]
        if ($first -match '^[0-9a-fA-F]{64}$') { return $first.ToLower() }
        return $null
    } catch {
        Write-Log "获取 $EditionId.$Suffix 校验值失败（不致命）：$($_.Exception.Message)" 'WARN'
        return $null
    }
}

# ==============================================================================
# 解压：zip 用 .NET ZipFile；tar.gz 用 GZipStream + 极简 ustar 解析（不依赖 tar.exe）
# ==============================================================================
function Expand-ZipArchive {
    param([string]$ZipPath, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    New-Directory $Destination
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $Destination)
}

function Expand-TarGzArchive {
    param([string]$TarGzPath, [string]$Destination)
    New-Directory $Destination

    $bytes = [System.IO.File]::ReadAllBytes($TarGzPath)
    $inMs  = New-Object System.IO.MemoryStream
    $inMs.Write($bytes, 0, $bytes.Length)
    $inMs.Position = 0

    $gz    = New-Object System.IO.Compression.GZipStream -ArgumentList @($inMs, [System.IO.Compression.CompressionMode]::Decompress)
    $outMs = New-Object System.IO.MemoryStream
    try {
        $gz.CopyTo($outMs)
    } finally {
        $gz.Close(); $inMs.Close()
    }
    $tar = $outMs.ToArray()
    $outMs.Close()

    $ascii   = [System.Text.Encoding]::ASCII
    $offset  = 0
    $files   = 0
    $pendingLongName = $null

    while (($offset + 512) -le $tar.Length) {
        $nameBytes = $ascii.GetString($tar, $offset, 100).TrimEnd([char]0)
        # 归档结尾是连续两个全零块
        if ([string]::IsNullOrWhiteSpace($nameBytes) -and ($tar[$offset] -eq 0)) { break }

        $sizeStr = $ascii.GetString($tar, $offset + 124, 12).Trim([char]0, ' ')
        $size    = 0
        if ($sizeStr) {
            try { $size = [System.Convert]::ToInt64($sizeStr, 8) } catch { $size = 0 }
        }
        $type    = [char]$tar[$offset + 156]
        $dataAt  = $offset + 512
        $next    = $dataAt + $size
        $next    = $dataAt + [int]([Math]::Ceiling($size / 512.0) * 512)

        if ($type -eq 'L') {                      # GNU 长文件名
            $pendingLongName = $ascii.GetString($tar, $dataAt, [int]$size).TrimEnd([char]0)
        } elseif ($type -eq 'x' -or $type -eq 'g' -or $type -eq 'K') {
            # pax 扩展头，忽略
        } elseif ($type -eq '0' -or $type -eq [char]0 -or $type -eq '7') {
            $full = $nameBytes
            if ($pendingLongName) { $full = $pendingLongName; $pendingLongName = $null }
            if ($full -and $size -gt 0) {
                $leaf = ($full -replace '\\', '/').Split('/')[-1]
                if ($leaf) {
                    $target = Join-Path $Destination $leaf
                    $buf = New-Object byte[] $size
                    [System.Array]::Copy($tar, $dataAt, $buf, 0, $size)
                    [System.IO.File]::WriteAllBytes($target, $buf)
                    $files++
                }
            }
        } elseif ($type -eq '5') {
            $pendingLongName = $null
        }

        if ($next -le $offset) { break }
        $offset = $next
    }

    Write-Log "tar.gz 解出 $files 个文件" 'DEBUG'
    if ($files -eq 0) { throw 'tar.gz 解析未得到任何文件（格式异常）' }
}

# ==============================================================================
# CSV -> CIDR
# ==============================================================================
function Get-CsvHeaderMap {
    param([string]$HeaderLine)
    $map = @{}
    $fields = $HeaderLine.TrimEnd("`r").Split(',')
    for ($i = 0; $i -lt $fields.Length; $i++) {
        $map[$fields[$i].Trim()] = $i
    }
    return $map
}

function Get-CsvFieldByIndex {
    param([string]$Line, [int]$Index)
    if ($Index -le 0) {
        $p = $Line.IndexOf(',')
        if ($p -lt 0) { return $Line }
        return $Line.Substring(0, $p)
    }
    $pos = 0; $cur = 0
    while ($cur -lt $Index) {
        $p = $Line.IndexOf(',', $pos)
        if ($p -lt 0) { return '' }
        $pos = $p + 1; $cur++
    }
    $q = $Line.IndexOf(',', $pos)
    if ($q -lt 0) { return $Line.Substring($pos) }
    return $Line.Substring($pos, $q - $pos)
}

function Get-TargetGeonameIds {
    <#
      从 Locations-en.csv 里筛出目标国家的 geoname_id 集合。
      该文件只有几百行，直接 Import-Csv 更稳（不怕列顺序变化）。
    #>
    param([string]$LocationsCsv, [string[]]$IsoCodes)

    $want = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $IsoCodes) {
        if ($c) { [void]$want.Add($c.Trim().ToUpperInvariant()) }
    }

    $ids  = New-Object 'System.Collections.Generic.HashSet[string]'
    $hit  = New-Object 'System.Collections.Generic.HashSet[string]'
    $rows = Import-Csv -LiteralPath $LocationsCsv -Encoding UTF8

    foreach ($r in $rows) {
        $iso = ''
        if ($r.PSObject.Properties['country_iso_code']) { $iso = [string]$r.country_iso_code }
        if (-not $iso) { continue }
        if ($want.Contains($iso.Trim().ToUpperInvariant())) {
            $gid = [string]$r.geoname_id
            if ($gid) { [void]$ids.Add($gid.Trim()) }
            [void]$hit.Add($iso.Trim().ToUpperInvariant())
        }
    }

    foreach ($c in $want) {
        if (-not $hit.Contains($c)) { Write-Log "警告：国家码 $c 在 MaxMind 数据中未找到" 'WARN' }
    }
    Write-Log ("目标国家 {0} -> 命中 geoname_id {1} 个" -f (($want -join ','), $ids.Count)) 'DEBUG'
    return $ids
}

function Convert-BlocksCsvToNetworks {
    <#
      流式解析 Blocks-IPv4/IPv6.csv（IPv4 版本约 400MB+ / 数百万行），
      只保留 geoname_id 命中目标集合的行。逐行 IndexOf 取值，避免 Split 的开销与内存峰值。
    #>
    param(
        [string]$CsvPath,
        [System.Collections.Generic.HashSet[string]]$GeonameIds,
        [System.Collections.Generic.HashSet[string]]$Sink,
        [ref]$Stat
    )

    $reader = New-Object System.IO.StreamReader -ArgumentList $CsvPath
    $rows = 0; $kept = 0
    try {
        $headerLine = $reader.ReadLine()
        if (-not $headerLine) { throw "空文件：$CsvPath" }
        $hmap = Get-CsvHeaderMap -HeaderLine $headerLine

        if (-not $hmap.ContainsKey('network')) { throw "CSV 缺少 network 列：$CsvPath" }
        $iNet = $hmap['network']
        $iGid = -1
        if ($hmap.ContainsKey('geoname_id'))                  { $iGid = $hmap['geoname_id'] }
        $iReg = -1
        if ($hmap.ContainsKey('registered_country_geoname_id')) { $iReg = $hmap['registered_country_geoname_id'] }
        if ($iGid -lt 0 -and $iReg -lt 0) { throw "CSV 缺少 geoname_id 列：$CsvPath" }

        # 快路径：network 在第 0 列、geoname_id 在第 1 列（GeoLite2 现状），避免函数调用开销
        $fast = ($iNet -eq 0 -and $iGid -eq 1)

        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line.Length -eq 0) { continue }
            $rows++

            if ($fast) {
                $p1 = $line.IndexOf(',')
                if ($p1 -le 0) { continue }
                $p2 = $line.IndexOf(',', $p1 + 1)
                if ($p2 -le $p1) { continue }
                $gid = $line.Substring($p1 + 1, $p2 - $p1 - 1)
                if (-not $GeonameIds.Contains($gid)) {
                    # 回退到 registered_country_geoname_id
                    if ($iReg -ge 0) {
                        $p3 = $line.IndexOf(',', $p2 + 1)
                        if ($p3 -gt $p2) {
                            $gid = $line.Substring($p2 + 1, $p3 - $p2 - 1)
                        } else { $gid = $line.Substring($p2 + 1) }
                    }
                    if (-not $GeonameIds.Contains($gid)) { continue }
                }
                $net = $line.Substring(0, $p1)
            } else {
                $net = (Get-CsvFieldByIndex -Line $line -Index $iNet).Trim()
                $gid = ''
                if ($iGid -ge 0) { $gid = (Get-CsvFieldByIndex -Line $line -Index $iGid).Trim() }
                if (-not $GeonameIds.Contains($gid)) {
                    $gid2 = ''
                    if ($iReg -ge 0) { $gid2 = (Get-CsvFieldByIndex -Line $line -Index $iReg).Trim() }
                    if (-not $GeonameIds.Contains($gid2)) { continue }
                }
            }

            if ($net -and $Sink.Add($net)) { $kept++ }
        }
    } finally {
        $reader.Dispose()
    }

    Write-Log ("{0}：扫描 {1:N0} 行，命中 {2:N0} 个网段" -f (Split-Path $CsvPath -Leaf), $rows, $kept) 'INFO'
    $Stat.Value = @{ Rows = $rows; Kept = $kept }
}

# ==============================================================================
# 生成 nginx 配置
# ==============================================================================
function New-GeoBlockContent {
    param(
        [string]$Mode,
        [string[]]$Countries,
        [System.Collections.Generic.List[string]]$Networks,
        [hashtable]$Meta
    )

    $sb = New-Object System.Text.StringBuilder
    $defaultValue = '1'
    $listValue    = '0'
    $modeText     = 'AllowOnly（只放行下列国家，其余全部拦截）'
    if ($Mode -eq 'DenyList') {
        $defaultValue = '0'
        $listValue    = '1'
        $modeText     = 'DenyList（放行全球，只拦截下列国家）'
    }

    [void]$sb.AppendLine('# ==============================================================================')
    [void]$sb.AppendLine('# MaxMind GeoLite2 -> nginx geo 模块配置（由 geoip-update.ps1 自动生成，请勿手改）')
    [void]$sb.AppendLine('# 生成时间 : ' + $Meta.GeneratedAt)
    [void]$sb.AppendLine('# 数据版本 : ' + $Meta.Edition + ' build ' + $Meta.BuildDate)
    [void]$sb.AppendLine('# 模式     : ' + $modeText)
    [void]$sb.AppendLine('# 国家码   : ' + ($Countries -join ', '))
    [void]$sb.AppendLine('# 条目数   : ' + $Networks.Count + ' （值 1 = 拦截，0 = 放行）')
    [void]$sb.AppendLine('# 用法     : 在 http{} 内 include 本文件，然后在 server{} 内 if ($geoip_block) { return 403; }')
    [void]$sb.AppendLine('# ==============================================================================')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('geo $geoip_block {')
    [void]$sb.AppendLine('    default ' + $defaultValue + ';')
    [void]$sb.AppendLine('')

    foreach ($n in $Networks) {
        [void]$sb.Append('    ')
        [void]$sb.Append($n)
        [void]$sb.Append(' ')
        [void]$sb.Append($listValue)
        [void]$sb.AppendLine(';')
    }

    [void]$sb.AppendLine('}')
    # .conf 统一用 LF：nginx 能处理 CRLF，但 LF 更保险也更省体积
    return $sb.ToString().Replace("`r`n", "`n")
}

# ==============================================================================
# nginx 交互
# ==============================================================================
function Resolve-NginxDir {
    param([string]$Given)
    if ($Given) {
        if (Test-Path -LiteralPath $Given) { return (Get-Item -LiteralPath $Given).FullName.TrimEnd('\', '/') }
        return $Given
    }

    # 未指定：尝试从正在运行的 nginx 进程反查
    $p = Get-Process -Name nginx -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) {
        try {
            $exe = $p.Path
            if ($exe) { return (Split-Path $exe -Parent).TrimEnd('\', '/') }
        } catch { }
    }
    return $null
}

function Invoke-NginxTest {
    param([string]$Prefix, [string]$NginxExe)
    $p = $Prefix.Replace('\', '/').TrimEnd('/') + '/'
    Write-Log "执行 nginx -t（prefix=$p）" 'INFO'
    # 注意：PS4.0 + $ErrorActionPreference='Stop' 时，原生命令 stderr 重定向（2>&1）的第一行
    # 会被包装成终止性 NativeCommandError（nginx -t 即使成功输出也全走 stderr），导致误判失败。
    # 因此调用期间临时放宽为 Continue，取完输出与退出码再恢复。
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out  = @(& $NginxExe -p $p -c conf/nginx.conf -t 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    foreach ($l in $out) { Write-Log ("  nginx: " + $l) 'DEBUG' }
    if ($code -ne 0) {
        return [pscustomobject]@{ Ok = $false; Output = ($out -join "`r`n") }
    }
    return [pscustomobject]@{ Ok = $true; Output = ($out -join "`r`n") }
}

function Invoke-NginxReload {
    param([string]$Prefix, [string]$NginxExe)
    $p = $Prefix.Replace('\', '/').TrimEnd('/') + '/'
    Write-Log '执行 nginx -s reload' 'INFO'
    # 同上：避免 PS4.0 下 stderr 重定向触发终止性错误
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out  = @(& $NginxExe -p $p -c conf/nginx.conf -s reload 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    foreach ($l in $out) { Write-Log ("  nginx: " + $l) 'DEBUG' }
    if ($code -ne 0) { throw ("nginx reload 失败（退出码 $code）：" + ($out -join ' ')) }
}

# ==============================================================================
# 主流程
# ==============================================================================
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$workDir = $null
$lockHandle = $null
$exitCode = 0

try {
    Write-Log ('=' * 78) 'INFO'
    Write-Log "MaxMind GeoIP 更新开始（脚本 v$($script:Version)，PowerShell $($PSVersionTable.PSVersion)）" 'INFO'

    # ---------- 1. 配置合并 ----------
    # 注意：$PSScriptRoot 在 param() 默认值里不一定可用，这里在脚本体里解析
    $scriptDir = $null
    if ($PSCommandPath) { $scriptDir = Split-Path -Parent $PSCommandPath }
    elseif ($MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $ConfigPath -and $scriptDir) { $ConfigPath = Join-Path $scriptDir 'geoip.config.json' }

    $cfg = Read-JsonFile -Path $ConfigPath
    if ($cfg) { Write-Log "已加载配置：$ConfigPath" 'DEBUG' }

    function Get-Setting {
        param($ParamValue, $EnvName, $CfgName, $Default)
        if ($ParamValue -ne $null -and "$ParamValue" -ne '') { return $ParamValue }
        if ($EnvName) {
            $v = [System.Environment]::GetEnvironmentVariable($EnvName)
            if ($v) { return $v }
        }
        if ($cfg -and $cfg.PSObject.Properties[$CfgName]) {
            $v = $cfg.$CfgName
            if ($v -ne $null -and "$v" -ne '') { return $v }
        }
        return $Default
    }

    $AccountId  = Get-Setting $AccountId  'MAXMIND_ACCOUNT_ID'  'accountId'  $null
    $LicenseKey = Get-Setting $LicenseKey 'MAXMIND_LICENSE_KEY' 'licenseKey' $null
    $NginxDir   = Get-Setting $NginxDir   'GEOIP_NGINX_DIR'    'nginxDir'   $null
    $DataDir    = Get-Setting $DataDir    $null                'dataDir'    $null
    $NginxService = Get-Setting $NginxService $null            'nginxService' $null

    if ($cfg) {
        if (-not $PSBoundParameters.ContainsKey('Countries') -and $cfg.PSObject.Properties['countries'] -and $cfg.countries) {
            $Countries = @($cfg.countries)
        }
        if (-not $PSBoundParameters.ContainsKey('Mode') -and $cfg.PSObject.Properties['mode'] -and $cfg.mode) {
            $Mode = [string]$cfg.mode
        }
        if (-not $PSBoundParameters.ContainsKey('AlwaysAllow') -and $cfg.PSObject.Properties['alwaysAllow'] -and $cfg.alwaysAllow) {
            $AlwaysAllow = @($cfg.alwaysAllow)
        }
        if ($cfg.PSObject.Properties['keepSnapshots'] -and $cfg.keepSnapshots -and -not $PSBoundParameters.ContainsKey('KeepSnapshots')) {
            $KeepSnapshots = [int]$cfg.keepSnapshots
        }
        if ($cfg.PSObject.Properties['minNetworks'] -and $cfg.minNetworks -and -not $PSBoundParameters.ContainsKey('MinNetworks')) {
            $MinNetworks = [int]$cfg.minNetworks
        }
        if ($cfg.PSObject.Properties['skipMmdb'] -and $cfg.skipMmdb) { $SkipMmdb = $true }
    }

    # 归一化：用 -File 从计划任务/cmd 调用时，"-Countries CN,HK" 会以单个字符串传入，
    # 这里统一按 , ; 空白 拆开并去重，保证 .ps1 直接调用与 -File 调用行为一致
    if ($Countries) {
        $Countries = @($Countries -split '[,;\s]+' | Where-Object { $_ } |
            ForEach-Object { $_.Trim().ToUpperInvariant() } | Select-Object -Unique)
    }
    if ($AlwaysAllow) {
        $AlwaysAllow = @($AlwaysAllow -split '[,;\s]+' | Where-Object { $_ } |
            ForEach-Object { $_.Trim() } | Select-Object -Unique)
    }

    $NginxDir = Resolve-NginxDir -Given $NginxDir
    if (-not $NginxDir) { throw '未指定 -NginxDir，且无法从运行中的 nginx 进程推断安装目录' }
    if ($Mode -ne 'AllowOnly' -and $Mode -ne 'DenyList') { throw "无效的 -Mode：$Mode（仅支持 AllowOnly / DenyList）" }
    if (-not (Test-Path -LiteralPath $NginxDir)) { throw "nginx 目录不存在：$NginxDir" }
    $NginxExe = Join-Path $NginxDir 'nginx.exe'

    if (-not $DataDir) { $DataDir = Join-Path $NginxDir 'geoip' }
    New-Directory $DataDir
    $logDir = Join-Path $DataDir '_logs'
    New-Directory $logDir
    if (-not $LogFile) { $LogFile = Join-Path $logDir 'update.log' }
    $script:LogPath = $LogFile

    Write-Log "nginx 目录 : $NginxDir"
    Write-Log "数据目录   : $DataDir"
    if ($NginxService) { Write-Log "nginx 服务 : $NginxService（reload 失败时自动重启该服务）" }
    Write-Log ("模式       : {0} / 国家 {1}" -f $Mode, ($Countries -join ','))

    if (-not $LocalCsvZip) {
        if (-not $LicenseKey) {
            throw '缺少 MaxMind LicenseKey：请用 -LicenseKey、环境变量 MAXMIND_LICENSE_KEY 或 geoip.config.json 提供（免费注册 https://www.maxmind.com/en/geolite2/signup 后生成）'
        }
        if (-not $AccountId) {
            Write-Log '未提供 AccountId，将回退到旧版下载端点（仅用 license_key，仍可用但不推荐）' 'WARN'
        }
    }

    # 私有网段（AllowOnly 模式默认放行，避免把内网探针/管理口一起封死）
    $privateRanges = @()
    if ($Mode -eq 'AllowOnly' -and -not $NoDefaultPrivateRanges) {
        $privateRanges = @(
            '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
            '::1/128', 'fc00::/7', 'fe80::/10'
        )
    }

    # ---------- 2. 互斥锁 ----------
    $lockPath = Join-Path $DataDir '.update.lock'
    if (Test-Path -LiteralPath $lockPath) {
        $age = (Get-Date) - (Get-Item -LiteralPath $lockPath).LastWriteTime
        if ($age.TotalHours -lt 6) {
            throw "已有更新进程在运行（锁文件 $lockPath，$([int]$age.TotalMinutes) 分钟前创建）。若确认是残留，请手工删除该文件"
        }
        Write-Log '发现过期锁文件，自动覆盖' 'WARN'
        Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
    }
    $lockHandle = [System.IO.File]::Create($lockPath)
    Write-Log '已获取更新锁' 'DEBUG'

    # ---------- 3. 工作目录 ----------
    $stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $subDir  = '_work'
    if ($DryRun) { $subDir = '_dryrun' }
    $workDir = Join-Path $DataDir ($subDir + '\' + $stamp)
    New-Directory $workDir
    $dlDir   = Join-Path $workDir 'download'
    $exDir   = Join-Path $workDir 'extract'
    New-Directory $dlDir
    New-Directory $exDir

    # ---------- 4. 取得数据 ----------
    Initialize-Tls
    $csvZipPath   = $null
    $mmdbTarPath  = $null
    $csvShaActual = $null
    $mmdbShaActual = $null

    if ($LocalCsvZip) {
        if (-not (Test-Path -LiteralPath $LocalCsvZip)) { throw "本地 CSV zip 不存在：$LocalCsvZip" }
        $csvZipPath = (Resolve-Path -LiteralPath $LocalCsvZip).Path
        Write-Log "离线模式：使用本地 CSV zip $csvZipPath" 'WARN'
    } else {
        $csvZipPath = Join-Path $dlDir ($EditionCsv + '.zip')
        $remoteSha  = Get-RemoteChecksum -EditionId $EditionCsv -Suffix 'zip.sha256' -AccountId $AccountId -LicenseKey $LicenseKey
        Save-MaxMindFile -EditionId $EditionCsv -Suffix 'zip' -OutFile $csvZipPath -AccountId $AccountId -LicenseKey $LicenseKey | Out-Null
        $csvShaActual = (Get-FileHash -LiteralPath $csvZipPath -Algorithm SHA256).Hash.ToLower()
        if ($remoteSha) {
            if ($remoteSha -ne $csvShaActual) { throw "校验失败：$EditionCsv 期望 $remoteSha，实际 $csvShaActual" }
            Write-Log 'SHA256 校验通过' 'OK'
        } else {
            Write-Log "无远端校验值可比对，本地 SHA256 = $csvShaActual" 'WARN'
        }
    }

    if (-not $SkipMmdb) {
        if ($LocalMmdbArchive) {
            if (-not (Test-Path -LiteralPath $LocalMmdbArchive)) { throw "本地 mmdb 归档不存在：$LocalMmdbArchive" }
            $mmdbTarPath = (Resolve-Path -LiteralPath $LocalMmdbArchive).Path
            Write-Log "离线模式：使用本地 mmdb 归档 $mmdbTarPath" 'WARN'
        } elseif (-not $LocalCsvZip) {
            $mmdbTarPath = Join-Path $dlDir ($EditionMmdb + '.tar.gz')
            $remoteSha2  = Get-RemoteChecksum -EditionId $EditionMmdb -Suffix 'tar.gz.sha256' -AccountId $AccountId -LicenseKey $LicenseKey
            Save-MaxMindFile -EditionId $EditionMmdb -Suffix 'tar.gz' -OutFile $mmdbTarPath -AccountId $AccountId -LicenseKey $LicenseKey | Out-Null
            $mmdbShaActual = (Get-FileHash -LiteralPath $mmdbTarPath -Algorithm SHA256).Hash.ToLower()
            if ($remoteSha2) {
                if ($remoteSha2 -ne $mmdbShaActual) { throw "校验失败：$EditionMmdb 期望 $remoteSha2，实际 $mmdbShaActual" }
                Write-Log 'mmdb SHA256 校验通过' 'OK'
            }
        }
    }

    # ---------- 5. 解压并定位 CSV ----------
    Write-Log '解压 CSV 归档 ...'
    $csvRoot = Join-Path $exDir 'csv'
    Expand-ZipArchive -ZipPath $csvZipPath -Destination $csvRoot

    $ipv4 = Get-ChildItem -LiteralPath $csvRoot -Recurse -Filter '*-Blocks-IPv4.csv' | Select-Object -First 1
    $ipv6 = Get-ChildItem -LiteralPath $csvRoot -Recurse -Filter '*-Blocks-IPv6.csv' | Select-Object -First 1
    $loc  = Get-ChildItem -LiteralPath $csvRoot -Recurse -Filter '*-Locations-en.csv' | Select-Object -First 1
    if (-not $ipv4 -or -not $loc) { throw 'CSV 归档结构异常：缺少 Blocks-IPv4.csv 或 Locations-en.csv' }

    # 构建日期从目录名 GeoLite2-Country-CSV_YYYYMMDD 中取
    $buildDate = 'unknown'
    $m = [regex]::Match($ipv4.FullName, '_(\d{8})[\\/]')
    if ($m.Success) { $buildDate = $m.Groups[1].Value }

    $mmdbOut = $null
    if ($mmdbTarPath) {
        Write-Log '解压 mmdb 归档 ...'
        $mmdbRoot = Join-Path $exDir 'mmdb'
        Expand-TarGzArchive -TarGzPath $mmdbTarPath -Destination $mmdbRoot
        $mmdbFile = Get-ChildItem -LiteralPath $mmdbRoot -Filter '*.mmdb' | Select-Object -First 1
        if (-not $mmdbFile) { throw 'tar.gz 中未找到 .mmdb 文件' }
        $mmdbOut = Join-Path $DataDir 'GeoLite2-Country.mmdb'
        Write-Log ("mmdb 就绪：{0}（{1:N1} MB）" -f $mmdbFile.Name, ($mmdbFile.Length / 1MB)) 'OK'
        $script:Steps.Add('mmdb') | Out-Null
    }

    # ---------- 6. 解析 CSV ----------
    Write-Log ("数据构建日期：{0}" -f $buildDate)
    $prevMetaPath = Join-Path $DataDir 'meta.json'
    $prevMeta = Read-JsonFile -Path $prevMetaPath
    if ($SkipIfSameBuild -and $prevMeta -and $prevMeta.buildDate -eq $buildDate) {
        Write-Log "本地已是 build $buildDate，按 -SkipIfSameBuild 跳过后续处理" 'OK'
        return
    }

    $gids = Get-TargetGeonameIds -LocationsCsv $loc.FullName -IsoCodes $Countries
    if ($gids.Count -eq 0) { throw "没有任何国家码命中，请检查 -Countries（当前：$($Countries -join ',')）" }

    $sink = New-Object 'System.Collections.Generic.HashSet[string]'
    $stat4 = @{}; $stat6 = @{}
    Convert-BlocksCsvToNetworks -CsvPath $ipv4.FullName -GeonameIds $gids -Sink $sink -Stat ([ref]$stat4)
    if ($ipv6) {
        Convert-BlocksCsvToNetworks -CsvPath $ipv6.FullName -GeonameIds $gids -Sink $sink -Stat ([ref]$stat6)
    } else {
        Write-Log '未找到 IPv6 Blocks 文件，仅处理 IPv4' 'WARN'
    }

    foreach ($r in ($privateRanges + $AlwaysAllow)) {
        if ($r) { [void]$sink.Add($r.Trim()) }
    }

    $networks = New-Object 'System.Collections.Generic.List[string]'
    foreach ($n in $sink) { $networks.Add($n) }
    $networks.Sort([System.StringComparer]::Ordinal)

    $countV6 = 0
    foreach ($n in $networks) { if (Test-IsIPv6Network $n) { $countV6++ } }
    $countV4  = $networks.Count - $countV6
    $countAll = $networks.Count

    Write-Log ("生成网段：共 {0:N0} 条（IPv4 {1:N0} / IPv6 {2:N0}）" -f $countAll, $countV4, $countV6) 'OK'

    # ---------- 7. 安全阀 ----------
    if ($countAll -lt $MinNetworks) {
        throw ("网段数量 {0} 低于阈值 {1}，判定为数据异常，拒绝替换配置（可用 -MinNetworks 调整）" -f $countAll, $MinNetworks)
    }
    if ($prevMeta -and $prevMeta.counts -and $prevMeta.counts.total -gt 0) {
        $prevTotal = [int]$prevMeta.counts.total
        $ratio = [math]::Round(100.0 * $countAll / $prevTotal, 1)
        if ($ratio -lt $MinRatioPercent) {
            throw ("新数据网段数 {0} 仅为上次 {1} 的 {2}%，低于安全阈值 {3}%，已中止（可用 -MinRatioPercent 调整）" -f $countAll, $prevTotal, $ratio, $MinRatioPercent)
        }
        Write-Log ("与上次对比：{0} -> {1}（{2}%）" -f $prevTotal, $countAll, $ratio) 'DEBUG'
    }

    # ---------- 8. 写文件 ----------
    $meta = @{
        GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        Edition     = $EditionCsv
        BuildDate   = $buildDate
    }
    $confText = New-GeoBlockContent -Mode $Mode -Countries $Countries -Networks $networks -Meta $meta

    $newConf = Join-Path $workDir 'blocklist.conf'
    $newTxt  = Join-Path $workDir 'networks.txt'
    Write-TextFileNoBom -Path $newConf -Text $confText
    Write-TextFileNoBom -Path $newTxt  -Text (($networks -join "`r`n") + "`r`n")

    $metaObj = [ordered]@{
        scriptVersion = $script:Version
        generatedAt   = (Get-Date).ToString('o')
        edition       = $EditionCsv
        buildDate     = $buildDate
        mode          = $Mode
        countries     = @($Countries)
        alwaysAllow   = @($privateRanges + $AlwaysAllow)
        counts        = [ordered]@{ total = $countAll; ipv4 = $countV4; ipv6 = $countV6; rowsScannedV4 = $stat4.Rows; rowsScannedV6 = $stat6.Rows }
        checksums     = [ordered]@{ csvZipSha256 = $csvShaActual; mmdbTarGzSha256 = $mmdbShaActual }
        nginx         = [ordered]@{ dir = $NginxDir; reloaded = $false }
        host          = $env:COMPUTERNAME
    }
    $newMeta = Join-Path $workDir 'meta.json'
    Write-TextFileNoBom -Path $newMeta -Text ($metaObj | ConvertTo-Json -Depth 6)
    Write-Log "配置已生成到临时目录：$workDir" 'DEBUG'

    if ($DryRun) {
        Write-Log '--- DryRun：以下为生成结果摘要 ---' 'WARN'
        Write-Log ("生成结果目录：" + $workDir) 'WARN'
        Write-Log ("blocklist.conf 前 12 行：`r`n" + (($confText -split "`n" | Select-Object -First 12) -join "`r`n")) 'WARN'
        Write-Log ("networks.txt 前 5 条：" + (($networks | Select-Object -First 5) -join ', ')) 'WARN'
        # 演练目录带时间戳、每次新建，且含完整下载与解压文件；只保留最近 3 次，避免无限累积
        $oldRuns = Get-ChildItem -LiteralPath (Join-Path $DataDir '_dryrun') -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        if ($oldRuns -and (@($oldRuns).Count -gt 3)) {
            $oldRuns | Select-Object -Skip 3 | ForEach-Object {
                Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Log ("演练目录清理：_dryrun 仅保留最近 3 份") 'DEBUG'
        }
        Write-Log 'DryRun 结束，未修改任何线上文件' 'WARN'
        return
    }

    # ---------- 9. 部署（备份 -> 替换 -> nginx -t -> reload，失败回滚）----------
    $backupDir = Join-Path $DataDir ('_backup\' + $stamp)
    New-Directory $backupDir
    $managed = @('blocklist.conf', 'networks.txt', 'meta.json')
    foreach ($f in $managed) {
        $src = Join-Path $DataDir $f
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $backupDir $f) -Force }
    }
    if ($mmdbOut -and (Test-Path -LiteralPath $mmdbOut)) {
        Copy-Item -LiteralPath $mmdbOut -Destination (Join-Path $backupDir 'GeoLite2-Country.mmdb') -Force
    }
    Write-Log "旧文件已备份到 $backupDir" 'DEBUG'

    $rollback = {
        param($Reason)
        Write-Log "部署失败，开始回滚：$Reason" 'ERROR'
        foreach ($f in $managed) {
            $b = Join-Path $backupDir $f
            $t = Join-Path $DataDir $f
            if (Test-Path -LiteralPath $b) {
                Copy-Item -LiteralPath $b -Destination $t -Force
            } elseif (Test-Path -LiteralPath $t) {
                # 首次部署时没有旧文件可还原，直接移除这次写入的新文件，避免留下未经验证的配置
                Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue
            }
        }
        $bMmdb = Join-Path $backupDir 'GeoLite2-Country.mmdb'
        if ((Test-Path -LiteralPath $bMmdb) -and $mmdbOut) { Copy-Item -LiteralPath $bMmdb -Destination $mmdbOut -Force }
        if (-not $NoReload -and (Test-Path -LiteralPath $NginxExe)) {
            try {
                $t2 = Invoke-NginxTest -Prefix $NginxDir -NginxExe $NginxExe
                if ($t2.Ok) { Invoke-NginxReload -Prefix $NginxDir -NginxExe $NginxExe; Write-Log '回滚后配置已 reload' 'WARN' }
                else { Write-Log '回滚后 nginx -t 仍失败，请人工介入' 'ERROR' }
            } catch { Write-Log "回滚后 nginx 校验/重载失败：$($_.Exception.Message)" 'ERROR' }
        }
    }

    try {
        if ($mmdbOut) { Copy-Item -LiteralPath (Get-ChildItem -LiteralPath (Join-Path $exDir 'mmdb') -Filter '*.mmdb' | Select-Object -First 1).FullName -Destination $mmdbOut -Force }
        Copy-Item -LiteralPath $newConf -Destination (Join-Path $DataDir 'blocklist.conf') -Force
        Copy-Item -LiteralPath $newTxt  -Destination (Join-Path $DataDir 'networks.txt') -Force
        Copy-Item -LiteralPath $newMeta -Destination (Join-Path $DataDir 'meta.json') -Force
        Write-Log '配置文件已替换' 'DEBUG'

        if (-not $SkipNginxTest) {
            if (-not (Test-Path -LiteralPath $NginxExe)) { throw "未找到 $NginxExe，无法执行 nginx -t。若只想生成数据请加 -SkipNginxTest" }
            $t = Invoke-NginxTest -Prefix $NginxDir -NginxExe $NginxExe
            if (-not $t.Ok) { throw ('nginx -t 失败：' + $t.Output) }
            Write-Log 'nginx -t 通过' 'OK'
        }

        if ($NoReload) {
            Write-Log '按 -NoReload 跳过 reload，新配置将在下次 nginx 重启/reload 后生效' 'WARN'
        } elseif (-not (Test-Path -LiteralPath $NginxExe)) {
            Write-Log "未找到 $NginxExe，无法 reload；数据文件已就绪，nginx 下次 reload/启动时生效" 'WARN'
        } elseif (Get-Process -Name nginx -ErrorAction SilentlyContinue) {
            try {
                Invoke-NginxReload -Prefix $NginxDir -NginxExe $NginxExe
                Write-Log 'nginx 已 reload，新规则生效' 'OK'
                $metaObj.nginx.reloaded = $true
            } catch {
                # reload 只是"通知信号"失败：配置已通过 nginx -t，文件保留不回滚
                # 常见于 nginx 以服务/SYSTEM 身份运行，而本脚本以交互会话执行（OpenEvent Access denied）
                Write-Log ("reload 失败（配置已更新且 nginx -t 通过，不回滚）：" + $_.Exception.Message) 'ERROR'
                if ($NginxService) {
                    # 按配置的服务名兜底：重启服务使配置生效（秒级中断）
                    Write-Log ("按 -NginxService 重启服务 {0} ..." -f $NginxService) 'WARN'
                    try {
                        Restart-Service -Name $NginxService -Force -ErrorAction Stop
                        $svc = Get-Service -Name $NginxService -ErrorAction SilentlyContinue
                        if ($svc -and $svc.Status -eq 'Running') {
                            Write-Log ("服务 {0} 已重启，新规则生效" -f $NginxService) 'OK'
                            $metaObj.nginx.reloaded = $true
                        } else {
                            Write-Log ("服务 {0} 重启后状态异常（{1}），请人工检查" -f $NginxService, $svc.Status) 'ERROR'
                        }
                    } catch {
                        Write-Log ("重启服务 {0} 失败：{1}；请手动执行：net stop {0} && net start {0}" -f $NginxService, $_.Exception.Message) 'ERROR'
                    }
                } else {
                    Write-Log '请手动重载或重启 nginx 使规则生效：用与启动 nginx 相同的账户/权限执行 nginx -s reload，或重启 nginx 服务' 'ERROR'
                }
            }
            Write-TextFileNoBom -Path (Join-Path $DataDir 'meta.json') -Text ($metaObj | ConvertTo-Json -Depth 6)
        } else {
            Write-Log 'nginx 进程未运行，跳过 reload（配置在下次启动时生效）' 'WARN'
        }
    } catch {
        & $rollback $_.Exception.Message
        throw
    }

    # ---------- 10. 快照与清理 ----------
    $snapDir = Join-Path $DataDir ('_snapshots\' + $buildDate)
    New-Directory $snapDir
    Copy-Item -LiteralPath (Join-Path $DataDir 'blocklist.conf') -Destination (Join-Path $snapDir 'blocklist.conf') -Force
    Copy-Item -LiteralPath (Join-Path $DataDir 'meta.json')      -Destination (Join-Path $snapDir 'meta.json') -Force

    $snaps = Get-ChildItem -LiteralPath (Join-Path $DataDir '_snapshots') -Directory | Sort-Object LastWriteTime -Descending
    if ($snaps.Count -gt $KeepSnapshots) {
        $snaps | Select-Object -Skip $KeepSnapshots | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Log ("快照清理：保留最近 {0} 份" -f $KeepSnapshots) 'DEBUG'
    }
    $backs = Get-ChildItem -LiteralPath (Join-Path $DataDir '_backup') -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($backs -and $backs.Count -gt $KeepSnapshots) {
        $backs | Select-Object -Skip $KeepSnapshots | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $sw.Stop()
    Write-Log ('=' * 78) 'INFO'
    Write-Log ("更新成功：{0} 条网段，build {1}，耗时 {2:N1} 秒" -f $countAll, $buildDate, $sw.Elapsed.TotalSeconds) 'OK'
    $exitCode = 0
} catch {
    $sw.Stop()
    Write-Log ("更新失败：" + $_.Exception.Message) 'ERROR'
    if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
        Write-Log ("  位置：第 " + $_.InvocationInfo.ScriptLineNumber + " 行") 'ERROR'
    }
    Write-Log ("耗时 {0:N1} 秒" -f $sw.Elapsed.TotalSeconds) 'ERROR'
    $exitCode = 1
} finally {
    if ($lockHandle) { try { $lockHandle.Close() } catch { } }
    $lockPath2 = Join-Path $DataDir '.update.lock'
    if (Test-Path -LiteralPath $lockPath2) { Remove-Item -LiteralPath $lockPath2 -Force -ErrorAction SilentlyContinue }
    if ($workDir -and -not $DryRun -and -not $KeepWorkDir -and (Test-Path -LiteralPath $workDir)) {
        try { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
}

exit $exitCode
