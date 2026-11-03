# Windows Server 2012 + nginx：按国家拦截国外 IP（GeoLite2 每周自动更新）

> 目标：每周自动从 MaxMind 拉取 mmdb，让 nginx 在 Windows 上按国家码拦截境外来源 IP。
> 环境：Windows Server 2012 / 2012 R2 + nginx for Windows（官方 zip 版）+ PowerShell 4.0。

---

## 0. 结论先行

1. **nginx 官方 Windows 版没有 GeoIP 模块**，mmdb 和 .dat 都读不了。原文（<http://nginx.org/en/docs/windows.html>）：
   > "It provides almost the same functionality as a UNIX version of nginx **except for** XSLT filter, image filter, **GeoIP module**, and embedded Perl language."

   而读 mmdb 的 `ngx_http_geoip2_module` 是第三方模块，Windows 版既不能 `load_module` 也无法用官方二进制加载 → **Windows 上不存在"nginx 直读 mmdb"这条路**。

2. 所以本方案把"地理判定"提前到**数据预处理阶段**：每周下载 GeoLite2 的 mmdb（归档备用）**和同版本的 CSV**，用 CSV 把"中国 → 全部 CIDR 网段"算出来，生成 nginx `geo` 模块可直接 `include` 的配置，命中就 `return 403`。
   `geo` 模块是 nginx 标准模块，Windows 版有；它内部是 radix 树，几万条规则也是常数级开销。

3. **已实测通过**（本机用官方 nginx 1.28.3 for Windows 验证）：
   - `nginx -t` 通过（1460 条规则）；
   - 命中拦截来源：`GET /` → **403**；
   - 例外路径 `/healthz`、`/.well-known/acme-challenge/` → **未被拦**（404，说明 map 例外生效）；
   - 放行的来源：`GET /` → **200**；
   - `-s reload` / `-s quit` 均返回 0。

---

## 1. 数据流

```
 MaxMind 下载站 ──┬─ GeoLite2-Country.tar.gz ──► GeoLite2-Country.mmdb   （归档，给其它程序/未来迁移用）
 (Basic Auth)     │
                  └─ GeoLite2-Country-CSV.zip ─┬─ Blocks-IPv4.csv  ┐
                     (含 SHA256 校验)          ├─ Blocks-IPv6.csv   ├─► 过滤出 CN 的 CIDR
                                               └─ Locations-en.csv ┘        │
                                                                          ▼
                                                     nginx\geoip\blocklist.conf
                                                     geo $geoip_block { default 1; 1.2.3.0/24 0; ... }
                                                                          │
                                              nginx -t 通过 ──► 替换 + nginx -s reload
                                                     │ 失败 ──► 自动回滚旧文件
```

为什么用 CSV 而不是解析 mmdb：mmdb 是二叉搜索树二进制格式，枚举全部网段得自己写遍历器（PowerShell 里跑几百万节点不现实）；MaxMind 官方也明确说 **CSV 版只支持直接下载**（不能用 geoipupdate），CSV 才是"批量导出网段"的正确来源。两者同一份数据、同一天构建，结果一致。

---

## 2. MaxMind 侧的 6 个关键事实（照抄容易踩）

| # | 事实 | 说明 |
|---|---|---|
| 1 | 必须注册账号 + License Key | GeoLite2 免费但需注册（<https://www.maxmind.com/en/geolite2/signup>），下载要 Basic Auth：`账号ID:LicenseKey` |
| 2 | 现行端点 | `GET https://download.maxmind.com/geoip/databases/{edition}/download?suffix={suffix}`，edition 如 `GeoLite2-Country` / `GeoLite2-Country-CSV` |
| 3 | suffix 取值 | 二进制用 `tar.gz`，CSV 用 `zip`；校验文件是 `tar.gz.sha256` / `zip.sha256` |
| 4 | 2024 起全部走 R2 预签名 302 | 会跳到 `mm-prod-geoip-databases...r2.cloudflarestorage.com`。**坑**：跳转时若把 `Authorization` 头一起带过去，S3 会判签名冲突报 400/403 → 脚本手工跟一跳并丢掉认证头 |
| 5 | 强制 TLS 1.2+ | Server 2012 需 .NET 4.5+，脚本显式设 `SecurityProtocol = Tls12` |
| 6 | 更新频率 / 限额 | GeoLite2 每周约两次（周二、周五）；HEAD 查构建日期不占下载额度，GET 计入 24h 限额（超限 429） |

许可：GeoLite2 允许商用但要求署名，站点上要保留类似
`This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com`。

---

## 3. 文件清单

| 文件 | 作用 |
|---|---|
| `geoip-update.ps1` | 主脚本：下载 → 校验 → 转 CIDR → 生成配置 → nginx -t → reload → 失败回滚 |
| `geoip.config.json` | 配置（账号、LicenseKey、国家码、白名单） |
| `install-task.ps1` | 注册/卸载/查看/立即运行 Windows 计划任务 |
| `run-geoip-update.bat` | 计划任务的包装器（带日志重定向） |
| `Test-GeoIpBlock.ps1` | 离线判断某个 IP 会不会被拦（按 nginx geo 的最长前缀匹配语义） |
| `nginx-snippets\geoip-block.conf` | nginx 侧要粘的配置 + 说明 |

脚本产出（默认在 `C:\nginx\geoip\`）：

```
blocklist.conf            可直接 include 的 geo 块（1=拦截 0=放行）
networks.txt              纯 CIDR 清单，供审计/其它程序
meta.json                 数据构建日期、条目数、SHA256、是否已 reload
GeoLite2-Country.mmdb     二进制库（Windows 的 nginx 用不到，见第 12 节）
_logs\update.log          运行日志
_snapshots\<build日期>\    历史快照（默认保留 6 份）
_backup\<时间戳>\          每次替换前的备份（回滚用）
```

---

## 4. 部署步骤（重要，已实操可以 20261103）

```powershell
# 0) 把整个目录放到服务器，例如 C:\geoip-tools\，然后以管理员身份打开 PowerShell

# 1) 填配置：accountId 是你的 MaxMind 账号 ID（数字），licenseKey 是那串长 key
notepad C:\geoip-tools\geoip.config.json

注意：`如果geoip.config.json里已经填写了nginxDir，如下的命令中可以省略 -NginxDir 参数`
# 2) 演练：只生成不落盘（会打印前 12 行结果，产物在 <nginx>\geoip\_dryrun\<运行时间戳>\，仅保留最近 3 次）
cd C:\geoip-tools
.\geoip-update.ps1 -NginxDir C:\nginx -DryRun

# 3) 自测：拿几个已知 IP 验证判定（这一步能救命，见第 7 节）
#    时间戳每次运行都不同，直接传 _dryrun 根目录会自动取最新一次的结果
.\Test-GeoIpBlock.ps1 -ConfigPath C:\nginx\geoip\_dryrun -Ip 8.8.8.8,114.114.114.114,1.2.3.4

# 4) 按 nginx-snippets\geoip-block.conf 改 nginx.conf（见第 5 节）

# 5) 正式跑一次
.\geoip-update.ps1 -NginxDir C:\nginx

# 6) 注册每周任务（默认周三 04:30，SYSTEM 身份，错过自动补跑）
.\install-task.ps1 -NginxDir C:\nginx
```

> 若首次执行 `.\xxx.ps1` 被策略拦住：`powershell -ExecutionPolicy Bypass -File .\geoip-update.ps1 ...`

---

## 5. nginx 配置

`http{}` 内加三块（完整注释版见 `nginx-snippets\geoip-block.conf`）：

```nginx
include C:/nginx/geoip/blocklist.conf;      # geo $geoip_block {...}，由脚本生成

map $request_uri $geoip_exempt {
    default                         0;
    ~^/healthz                      1;
    ~^/\.well-known/acme-challenge/ 1;
}

map "$geoip_block$geoip_exempt" $geoip_deny {
    "10"    1;
    default 0;
}
```

每个对外 `server{}` 开头：

```nginx
if ($geoip_deny) {
    return 403;      # 想更"隐身"用 return 444;（直接断连不回包）
}
```

要点：
- `if` 里**只写 `return`** 是官方认可的少数安全用法（不要在里面放 proxy_pass 之类）。
- 用 `geo` 而不是 `allow/deny`：`ngx_http_access_module` 是逐条线性比对，上万条规则每个请求都要扫一遍；`geo` 走 radix 树。
- 上游有 CDN/SLB 时**必须先 realip**，否则拿到的是 CDN 节点 IP（`real_ip_header X-Forwarded-For;`）。realip 在 POST_READ 阶段执行，早于 rewrite 阶段的 `if`，顺序没问题。

---

## 6. 验证（三招）

```powershell
# 1) 当前线上配置到底怎么判定某个 IP（离线、不依赖 nginx）
.\Test-GeoIpBlock.ps1 -Ip 8.8.8.8 -Ip 114.114.114.114

# 2) nginx 语法（脚本每次更新都会自动跑，失败会回滚）
C:\nginx\nginx.exe -p C:/nginx/ -c conf/nginx.conf -t

# 3) 真实请求（从境外机器或境外代理访问）
curl -I http://example.com/              # 期望 403
curl -I http://example.com/healthz       # 期望非 403
```

---

## 7. 上线前必读的 7 个坑

1. **自锁**：如果后台管理页也挂在同一个 nginx 上，而你人在境外/VPN，会把自己关在门外。先把公司/家固定出口 IP 写进 `alwaysAllow`。
2. **Let's Encrypt / ZeroSSL 签不了证书**：HTTP-01 校验节点遍布全球，必须豁免 `/.well-known/acme-challenge/`（示例配置已含）。
3. **CDN / 回源**：见第 5 节 realip；否则拦截基于 CDN 节点 IP，结果不可控。
4. **海外业务回调**：Stripe/PayPal/微信海外、App Store 审核、Google/Bing 爬虫都会被拦。搜索引擎建议单独放过（UA 或 IP 段）。
5. **港澳台是独立国家码**：MaxMind 数据里 `CN / HK / MO / TW` 是四个不同的 ISO 码。要一并放行就写 `-Countries CN,HK,MO,TW`，默认只写 `CN`。
6. **私网必放行**：`AllowOnly` 模式默认自动追加 `127/8、10/8、172.16/12、192.168/16、::1、fc00::/7、fe80::/10`，避免把内网探针、健康检查打死（`-NoDefaultPrivateRanges` 可关）。
7. **别用空清单覆盖线上**：脚本内置两道闸——条目数低于 `MinNetworks`（默认 200）、或低于上次的 50%，直接中止并回滚，防止一次坏下载把站点全封。

---

## 8. 定时任务

```powershell
.\install-task.ps1 -NginxDir C:\nginx                          # 周三 04:30
.\install-task.ps1 -NginxDir C:\nginx -Days Tuesday,Friday      # 跟 MaxMind 节奏
.\install-task.ps1 -Show                                        # 看上次/下次运行
.\install-task.ps1 -RunNow                                      # 立即跑一次
.\install-task.ps1 -Remove                                      # 卸载
```

任务设置：SYSTEM 最高权限、`StartWhenAvailable`（错过补跑）、`MultipleInstances=IgnoreNew`（不并发）、超时 2 小时。

---

## 9. 常用命令

```powershell
# 改放行国家（改完不用等下周，立刻生效）
.\geoip-update.ps1 -NginxDir C:\nginx -Countries CN,HK,MO,TW

# 反过来：放行全球，只拦某几国
.\geoip-update.ps1 -NginxDir C:\nginx -Mode DenyList -Countries RU,US

# 只生成、不 reload（先人工看一眼）
.\geoip-update.ps1 -NginxDir C:\nginx -NoReload

# 完全离线（内网分发：把 zip 拷进内网再本地生成）
.\geoip-update.ps1 -NginxDir C:\nginx -LocalCsvZip D:\pkg\GeoLite2-Country-CSV.zip

# 手动回滚到某个快照
Copy-Item C:\nginx\geoip\_snapshots\20261103\blocklist.conf C:\nginx\geoip\blocklist.conf -Force
C:\nginx\nginx.exe -p C:/nginx/ -c conf/nginx.conf -t ; C:\nginx\nginx.exe -p C:/nginx/ -c conf/nginx.conf -s reload
```

主脚本参数速查：`-DryRun` `-NoReload` `-SkipNginxTest` `-SkipMmdb` `-SkipIfSameBuild` `-KeepSnapshots N` `-MinNetworks N` `-MinRatioPercent N` `-AlwaysAllow 1.2.3.0/24` `-LocalCsvZip` `-LocalMmdbArchive` `-KeepWorkDir`。

---

## 10. 排错表

| 现象 | 原因 / 处理 |
|---|---|
| `缺少 MaxMind LicenseKey` | 配置没填或环境变量 `MAXMIND_LICENSE_KEY` 未设 |
| `401 / 403` from download | 账号 ID 与 key 不匹配、订阅过期；未填 `accountId` 时走旧端点也可能 403，建议填全 |
| `429 Too Many Requests` | 触发下载限额/被限流，降低频率、别手工反复跑 |
| `HTTPS 请求失败 / 基础连接已关闭` | Server 2012 未启用 TLS 1.2（.NET 4.5+ 或注册表开启 Schannel 客户端 TLS1.2） |
| 下载后 `文件过小` | 拿到的是错误页（多为 302 后认证头冲突），脚本已按"跟一跳丢认证头"处理；复查代理是否改写响应 |
| `nginx -t 失败` | 脚本会打印 nginx 原始输出并自动回滚；常见是 include 路径写错、`blocklist.conf` 被手工改坏 |
| `nginx reload 失败` | nginx 未运行、或 `-p` 前缀不对；确认 `C:\nginx\nginx.exe -p C:/nginx/ -c conf/nginx.conf -s reload` 能成功 |
| 规则生成了但没拦住 | 未 include、`if` 没加、或 `geoip_deny` 变量名不一致；先用 `Test-GeoIpBlock.ps1` 确认规则本身，再看 `nginx -t` |
| 全站 403 | 清单被 `default 1` 覆盖但网段列表为空/错误；看 `meta.json` 的 counts，用快照回滚 |
| 计划任务返回 `0x1` | 看 `logs\task.log` 与 `<dataDir>\_logs\update.log` |

---

## 11. 以后想真正"直读 mmdb"

只有一条干净路径：nginx 跑在 **Linux**（或前面加一台 Linux 反代），编译 `ngx_http_geoip2_module`：

```nginx
http {
    geoip2 /data/geoip/GeoLite2-Country.mmdb {
        $geoip2_country_code country iso_code;
    }
    map $geoip2_country_code $geoip_deny { default 1; CN 0; HK 0; MO 0; TW 0; }
}
```

脚本每周照旧把 `GeoLite2-Country.mmdb` 落在 `C:\nginx\geoip\`，迁移时直接把这个文件带走即可——这也是为什么即便 Windows 上 nginx 用不到 mmdb，脚本仍然每周拉它。
