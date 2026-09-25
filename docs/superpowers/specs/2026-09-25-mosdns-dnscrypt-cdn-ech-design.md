# Ubuntu 动态 DHCP DNS、DNSCrypt 境外分流、CDN 优选与 ECH 设计规范

- 日期：2026-09-25
- 状态：已完成交互评审和书面自检，等待用户复核
- 目标系统：Ubuntu 22.04 LTS、24.04 LTS、26.04 LTS
- 架构：原生 systemd
- 核心组件：定制 MOSDNS v5、dnscrypt-proxy、CDN 测速/选择器、NetworkManager DHCP bridge

## 1. 摘要

本项目在单台 Ubuntu Desktop 上构建一个仅供本机使用的安全 DNS 网关：

1. NetworkManager 自动捕获家用路由器通过 DHCP 下发的 DNS。
2. 中国域名集合使用该动态 DHCP DNS，不硬编码任何中国公共 DNS。
3. 非中国域名使用可自定义的 DNSCrypt v2 上游，默认 Quad9 Secure。
4. 识别 Cloudflare 与用户指定的 CloudFront 域名，并可替换为优选 IPv4。
5. 每日默认 03:00 或手动执行低流量测速，原子更新优选结果。
6. 支持手动固定 IPv4；固定 IP 失败时逐级回退。
7. 仅对用户明确指定的 Cloudflare 域名强制 ECH。
8. ECH 严格模式通过 DNS fail-closed 阻止未取得 ECH 的连接，不做 TLS MITM。
9. Firefox 不配置 DoH，不安装或信任自签 CA。
10. 仅处理 IPv4 优选；成功改写时抑制相应 AAAA 响应。
11. 系统测试在一次性 Podman 虚拟机和 Ubuntu 容器内完成，不污染开发宿主机。

ClearDNS 不进入最终运行链路。现有实现与本项目在分流、缓存和 hosts 功能上高度重叠，并默认包含被本项目禁止的中国公共 DNS。

## 2. 目标

### 2.1 功能目标

- 保留路由器动态下发的运营商/路由器 DNS，不要求用户填写 `114.114.114.114`、`119.29.29.29` 或其他中国公共 DNS。
- 按中国域名集合进行国内外 DNS 分流。
- 境外普通查询只通过 DNSCrypt 上游发送。
- 默认 Quad9 Secure DNSCrypt v2，支持用户替换 resolver stamp 和策略。
- Cloudflare 全局优选与 CloudFront 域名级优选。
- 每日自动测速和手动测速/应用。
- 延迟与带宽联合排序，同时优先考虑丢包和抖动。
- 自动、手动固定、last-known-good 和原始 DNS 回退。
- 动态 ECHConfig 获取、缓存、轮换和严格/回退策略。
- Ubuntu 22.04、24.04、26.04，amd64 与 arm64。
- 可审计、可回滚、无境外查询泄漏。

### 2.2 安全目标

- 不建立 DNS 回环。
- 境外上游失败时不回退到 DHCP DNS 或明文公共 DNS。
- 不使用 `insecure_skip_verify`。
- 不进行 TLS 中间人解密或证书签发。
- 不创建本地 DoH 服务。
- 不修改 Firefox Secure DNS/DoH 设置。
- 响应被修改后不得继续声称 DNSSEC 已验证。
- 配置和状态更新必须原子化，损坏时保留 last-known-good。

## 3. 非目标

- 不向局域网客户端提供 DNS 服务。
- 不提供旁路由、网关或透明代理。
- 不做 HTTP/TLS MITM。
- 不做明文 SNI DPI；防泄漏采用 DNS 连接前 fail-closed。
- 不支持 CloudFront ECH 注入。
- 不为所有 Cloudflare 域名自动强制 ECH。
- 不扫描完整 CloudFront 公共 CIDR。
- 不将“延迟前十内带宽前十”宣传为全部候选的全局带宽排名。
- 不在默认配置中提供任何中国公共 DNS。
- 不自动安装 ClearDNS 或 Docker 服务。

## 4. 已确认的关键决策

| 主题 | 决策 |
|---|---|
| 部署范围 | 单台 Ubuntu Desktop，本机 loopback 使用 |
| 桌面网络 | NetworkManager + systemd-resolved |
| DHCP DNS | 自动捕获 DHCP4/DHCP6 原始 DNS，动态热更新 |
| 境外上游 | 默认 Quad9 Secure DNSCrypt v2；用户可完全替换 |
| 中国域名 | 可更新域名集合 + 用户自定义规则 |
| IPv4/IPv6 优选 | 仅 IPv4；成功改写 A 时返回空 AAAA |
| Cloudflare | 官方 CIDR + 用户候选，自动全局识别与替换 |
| CloudFront | 只处理用户配置并逐域名验证的域名 |
| 测速流量 | 每日默认硬上限 100 MiB |
| 自动时间 | 每日 03:00，本地时区，可配置，支持补跑 |
| 手动 IP | 固定优先，可回退到 last-known-good 和原 DNS |
| 强制 ECH 域名 | 用户手动维护的明确 allowlist |
| ECH 失败策略 | 用户可选 `strict` 或 `fallback` |
| Firefox | 不设置 DoH；Firefox 129+ 通过系统解析器读取 HTTPS RR |
| 防泄漏 | 强制 ECH 域名不返回 A/AAAA，只允许 HTTPS RR+ECH 连接 |
| 部署方式 | 原生 systemd |
| 测试方式 | 当前机开发；Podman 一次性 VM/容器测试 |

## 5. 总体架构

```text
运营商 DNS
    │
    │ 家用路由器通过 LAN DHCP 下发
    ▼
NetworkManager
    ├─ mosdns-dhcp-bridge 捕获原始 DHCP DNS
    │      └─ 原子更新 /run/mosdns/dhcp-upstreams.json
    │
    └─ 关闭 auto-dns，仅让 systemd-resolved 使用 127.0.0.1
                         │
                         ▼
systemd-resolved 127.0.0.53:53
                         │
                         ▼
MOSDNS v5 127.0.0.1:53 UDP/TCP
    ├─ 中国域名集合
    │      └─ dhcp_forward → 动态 DHCP DNS
    ├─ 其他域名
    │      └─ 127.0.0.1:15353
    │             └─ dnscrypt-proxy → Quad9 DNSCrypt v2
    └─ cdn_rewrite
           ├─ A 优选 IPv4 替换
           ├─ AAAA 抑制
           ├─ HTTPS/ECH 改写
           └─ CloudFront 域名级映射

mosdns-cdnctl
    ├─ 候选获取
    ├─ 延迟/带宽测试
    ├─ 排序与健康验证
    ├─ 自动/手动状态
    └─ 原子写 cdn-selector.json

cdn_rewrite 插件运行时观察 selector generation 并热更新
```

## 6. 组件设计

### 6.1 `mosdns-router.service`

- 运行用户：`mosdns`。
- 监听：`127.0.0.1:53/UDP` 和 `127.0.0.1:53/TCP`。
- 不监听 LAN 地址。
- 包含两个定制插件：
  - `dhcp_forward`：读取 DHCP DNS 状态，支持运行时原子切换。
  - `cdn_rewrite`：执行 CDN 分类、A/AAAA/HTTPS/ECH 改写。
- 使用 MOSDNS v5.3.4 作为初始上游基线。
- 国内与国外使用独立缓存。
- 通过 systemd `AmbientCapabilities=CAP_NET_BIND_SERVICE` 绑定 53 端口。

### 6.2 `dnscrypt-proxy.service`

- 运行用户：非 root 的 `dnscrypt-proxy` 用户。
- 监听：`127.0.0.1:15353/UDP` 和 `127.0.0.1:15353/TCP`。
- 默认选择 Quad9 Secure DNSCrypt v2 IPv4 resolver。
- 默认不使用 ECS。
- 支持多个 Quad9 IPv4 stamp endpoint，并允许用户替换为其他 DNSCrypt stamp。
- 使用完整 DNS stamp；禁止把裸 IP 当作 DNSCrypt 身份配置。
- `ignore_system_dns=true`。
- DNSCrypt provider 名称的 bootstrap 查询与普通用户查询分离；resolver certificate 仍由 stamp 内 provider public key 验证。
- 初始上游版本固定为 dnscrypt-proxy 2.1.18。
- 关闭 dnscrypt-proxy 缓存，由 MOSDNS 统一负责普通查询缓存。

### 6.3 `mosdns-cdnctl`

独立的控制与优化 CLI，不作为常驻服务运行。日常查询无需管理员权限；安装、pin、紧急恢复等操作可由管理员通过 `sudo` 显式授权。提供：

```text
update-lists
validate
test
apply
pin
unpin
status
health-check
emergency-rollback
```

- 自动任务和手动任务使用相同入口。
- 使用文件锁防止并发。
- `test` 默认只生成报告，不自动应用。
- `apply` 校验报告后才更新 selector。
- `status` 不输出完整 ECHConfig 或其他敏感材料。

### 6.4 `mosdns-dhcp-bridge`

- 由 NetworkManager dispatcher 以 root 执行。
- 处理 `up`、`dhcp4-change`、`dhcp6-change`、`down`。
- 新版 `dns-change` 可作为增强事件，但三版共同事件集必须独立工作。
- 只读取 NetworkManager 状态、验证地址并发布运行时文件。
- 不直接编辑 MOSDNS 配置。
- 不调用外网下载器。
- 地址未变化时不执行状态切换。

### 6.5 定时服务

- `mosdns-cdn-optimizer.service/timer`
  - 每日默认 03:00 调用 `mosdns-cdnctl test --apply`。
  - `Persistent=true`，支持自定义时间和补跑。
- `mosdns-cdn-health.service/timer`
  - 默认每 2 分钟执行一次低流量 winner 健康检查。
  - 连续 3 次失败后执行回退。
- `mosdns-list-check.service/timer`
  - 检查中国域名集合和 CDN 官方数据是否有更新。
  - 不自动接受域名规则变更；只生成候选和通知报告。
- `mosdns-router.service`
  - 启动不依赖 `network-online.target`。
  - 无网络或 DHCP 状态缺失时仍监听，相应分支按策略失败。
- `dnscrypt-proxy.service`
  - 在 `mosdns-router.service` 之前启动。

## 7. 配置和状态布局

```text
/etc/mosdns/
├── config.yaml
├── policy.yaml
├── dnscrypt-proxy.toml
├── candidates/
│   ├── cloudflare.txt
│   └── cloudfront/
│       └── domains.yaml
└── force-ech-domains.txt

/var/lib/mosdns/
├── lists/
│   ├── cn-domains.txt
│   └── source-lock.json
├── results/
│   └── latest.json
└── runtime/
    ├── cdn-selector.json
    └── ech-state.json

/run/mosdns/
└── dhcp-upstreams.json
```

### 7.1 权限

- `/etc/mosdns/`：root 可写，服务用户只读。
- `/var/lib/mosdns/`：服务控制用户可写。
- `/run/mosdns/`：DHCP bridge 与服务组可写。
- 配置文件不得包含私钥、证书或浏览器数据。
- 日志进入 journald。

### 7.2 初始策略默认值

| 配置项 | 默认值 |
|---|---|
| `foreign.default_provider` | Quad9 Secure DNSCrypt v2 |
| `foreign.ecs` | 关闭 |
| `schedule` | `03:00` |
| `cdn.ip_version` | IPv4 |
| `cdn.suppress_aaaa` | 开启 |
| `cdn.cloudflare.max_candidates` | 512 |
| `cdn.bandwidth.daily_budget` | 100 MiB |
| `cdn.bandwidth.per_candidate_limit` | 10 MiB 或 3 秒 |
| `cdn.latency_candidate_count` | 10 |
| `cdn.combined.latency_top` | 3 |
| `cdn.combined.bandwidth_top` | 3 |
| `cdn.switch_improvement_percent` | 10% |
| `cdn.health.interval` | 2 分钟 |
| `cdn.health.failure_threshold` | 3 次 |
| `ech.enabled` | 开启 |
| `ech.failure_policy` | `strict` |
| `ech.stale_grace` | 15 分钟 |
| `dhcp.failure_policy` | 停用当前接口，不使用 stale 上游 |
| `cache.persistent_dump` | 关闭 |

用户可以在 `policy.yaml` 中修改这些值。涉及安全边界的 `ech.failure_policy` 和 `dhcp.failure_policy` 修改必须经过 `mosdns-cdnctl validate`。

## 8. 动态 DHCP DNS

### 8.1 网络拓扑语义

运营商可能通过 PPPoE 或 WAN DHCP 向家用路由器提供 DNS。家用路由器再通过 LAN DHCP 将一个或多个 DNS 地址下发给 Ubuntu。Ubuntu 需要保存的是“路由器当前下发的 DNS”，不应推断其属于哪一家运营商。

### 8.2 数据源优先级

1. NetworkManager DHCP4/DHCP6 原始配置对象。
2. dispatcher 提供的 `DHCP4_DOMAIN_NAME_SERVERS` 和 `DHCP6_DOMAIN_NAME_SERVERS`。
3. `nmcli device show` 的 `IP4.DNS` 与 `IP6.DNS`。
4. `resolvectl dns` 作为最后回退，并过滤所有本地地址。

设置 `ignore-auto-dns` 后，不能只依赖 resolved 当前 DNS 列表获取原始 DHCP DNS。

### 8.3 验证与过滤

- 删除无效地址和重复项。
- 删除 `127.0.0.0/8`、`::1`、`127.0.0.53`、`127.0.0.54`。
- 删除 MOSDNS 和 dnscrypt-proxy 自己的监听地址。
- IPv6 link-local DNS 保留正确接口 scope。
- 状态文件保存接口、连接 UUID、地址族、地址、获取时间和验证来源。

### 8.4 热更新流程

1. 收集原始 DHCP DNS。
2. 与当前状态比较。
3. 未变化时退出。
4. 验证候选集合。
5. 写入同目录临时文件并 `fsync`。
6. 原子 rename 到正式路径。
7. `dhcp_forward` 为新查询切换上游。
8. 递增 generation 并清理国内缓存。
9. 已发出的旧查询允许使用旧上游完成。

### 8.5 故障策略

- 状态为空：国内分支 fail-closed。
- 可配置使用 last-known-good，但必须标记 stale 并记录年龄。
- 不因 DHCP DNS 不可用而自动加入任何公共 DNS。
- 接口 down 时保留最后一个已验证状态，还是立即停用，由 `dhcp_failure_policy` 控制；默认立即停用当前接口，保留持久化 last-known-good 供诊断。

## 9. DNS 分流

### 9.1 规则优先级

```text
用户强制国内规则
→ 用户强制国外规则
→ 中国域名集合
→ 默认国外
```

### 9.2 中国域名集合

- 初始来源：`v2fly/domain-list-community` 的 `cn` 数据。
- 首次发布必须固定一个已审核 commit 和 SHA-256。
- 后续更新只能通过显式 `update-lists --accept` 接受。
- 转换结果为 MOSDNS 可识别的 `domain:` 表达式。
- 更新失败时保留 last-known-good。
- 用户可以完全替换远程列表。
- 不复制源列表中的任何 DNS 地址到 MOSDNS 配置。

### 9.3 缓存

- 国内、国外缓存分离。
- 不持久化 LAN 私网 DHCP DNS。
- 不使用跨 WAN 的 cache dump。
- generation 变化后清理受影响缓存。
- ECHConfig、selector 或 DHCP 上游变化不能继续返回旧 generation 响应。

## 10. CDN 识别和响应改写

### 10.1 Cloudflare

候选和分类数据来自 Cloudflare 官方 IP API。分类响应时：

1. 解析 CNAME 链。
2. 收集所有可用终端 A 记录。
3. 只有全部终端地址属于 Cloudflare 官方 CIDR，且不存在混合 CDN endpoint 时，判定为 Cloudflare。
4. GeoIP、ASN 名称或单一命中地址不能单独作为判定条件。
5. Cloudflare 官方 CIDR 还包含其他 Cloudflare 服务地址；CIDR 命中不等于该地址能服务目标域名，候选必须通过实际 Host/SNI/证书验证。
6. Cloudflare 优选 IPv4 可以用于通过分类的域名。
7. 非强制 ECH 域名将 A 替换为当前优选 IPv4，并返回空 AAAA。

### 10.2 CloudFront

CloudFront 只处理用户配置的域名和测试档案：

- 域名
- 验证 URL
- 端口
- 期望状态码
- 期望响应头
- 可选响应体标记
- 候选 IP 或候选域名
- 是否允许特定状态码

CloudFront 公共 CIDR 只能用于产生粗筛候选。以下条件全部满足才视为域名可用：

- SNI 为目标域名。
- 证书验证成功并覆盖目标域名。
- HTTP Host 为目标域名。
- 状态码符合配置。
- 响应头或响应体标记符合目标 distribution。
- 最终 CloudFront 响应头可识别。

一个 distribution 的 winner 不能应用到其他 distribution。

### 10.3 混合 CDN

当 CNAME 链或终端 A 记录显示多个 CDN 提供商时：

- 默认不改写。
- 不向其中一个 provider 注入另一个 provider 的 ECHConfig。
- 日志记录 `mixed_cdn` 原因。
- 用户可通过显式域名规则覆盖默认行为。

### 10.4 DNSSEC 和 EDNS

当 A、AAAA 或 HTTPS RR 被修改时：

- 删除覆盖被修改 RRset 的 RRSIG。
- 清除 AD bit。
- 不保留与新数据不一致的 NSEC/NSEC3 证明。
- 未修改的响应保持原始 DNSSEC 语义。
- 测试必须覆盖 DO/CD 查询。

## 11. CDN 测速和选择

### 11.1 候选来源

Cloudflare：

- Cloudflare 官方 IPv4 CIDR。
- 用户固定 IP。
- 用户优选域名解析结果。
- last-known-good winner 和回退 IP。

CloudFront：

- 用户域名档案中的固定 IP。
- 用户候选域名解析结果。
- 该域名的 last-known-good。
- 默认不扫描完整官方 CloudFront CIDR。

### 11.2 扫描限制

- 默认最多产生 512 个 Cloudflare 粗筛候选。
- 对官方大网段按 `/24` 进行确定性抽样，并使用每日 seed 轮换抽样地址。
- 用户清单中的地址总是加入，不受官方抽样数限制。
- TCP、TLS 和 HTTP 探测使用独立并发限制。
- HTTPing 遵守低并发要求，避免被识别为扫描。
- 任何自动候选数量上限均可由用户降低或提高。

### 11.3 100 MiB 测速流程

1. 对候选执行多次 TCP 443 探测。
2. 对 TCP 可用候选执行带目标 Host/SNI 的 TLS/HTTP 验证。
3. 过滤证书、Host、状态码、响应特征和超时错误。
4. 按 p50 延迟、抖动和探测失败率选出延迟前 10。
5. 对这 10 个候选分别执行一次带宽测试。
6. 每个候选最多下载 10 MiB 或持续 3 秒，先达到者停止。
7. 每日总下载量硬限制 100 MiB。
8. 如果有效候选不足 10 个，报告明确记录有效数量，不伪造排名。
9. 带宽使用实际传输字节除以有效传输时间。
10. 带宽前十仅指延迟前十集合内的带宽排名。

### 11.4 联合排序

最终集合：

```text
LatencyTop3 ∪ BandwidthTop3
```

默认评分：

```text
45% 延迟百分位排名
45% 带宽百分位排名
10% 丢包与抖动惩罚
```

新 winner 必须：

- 通过域名级健康验证。
- 至少优于当前 winner 10%。
- 在切换前再次完成一次低流量验证。
- 原子写入 selector。
- 递增 generation 并清理缓存。

旧 winner 保留为第一回退，不立即删除。

### 11.5 调度

- 默认 `OnCalendar=*-*-* 03:00:00`。
- 使用本机时区。
- `Persistent=true`，错过时间后开机补跑。
- 可在 `policy.yaml` 修改时间。
- 手动测试和自动任务共享文件锁。
- 手动 `apply` 可明确覆盖自动任务结果。

### 11.6 手动固定

```bash
sudo mosdns-cdnctl pin 203.0.113.10
```

手动模式规则：

- 手动 IP 优先于自动结果。
- Cloudflare 手动 IP 必须通过 provider 代表域名和所有强制 ECH 域名的验证。
- CloudFront 手动 IP 必须通过每个相关域名的验证。
- 失败时回退顺序：手动 IP → last-known-good → 原始 DNS。
- `unpin` 恢复自动选择。
- 手动状态跨重启持久化。

### 11.7 健康检查

- 定时执行低流量 TLS/HTTP 健康检查。
- 健康检查使用实际 Host/SNI，不使用裸 IP HTTP 请求作为最终证明。
- 连续失败达到阈值后，winner 标记不健康并执行回退。
- 严格 ECH 域名不健康时保持阻断。
- 回退模式使用 last-known-good 或原始 DNS。
- 健康检查不下载大文件。

## 12. ECH 设计

### 12.1 范围

强制 ECH 只适用于 `/etc/mosdns/force-ech-domains.txt` 中的域名：

- 域名由用户明确添加。
- 不根据 Cloudflare IP 自动添加。
- 不支持 CloudFront。
- Meta 或其他 CDN 不在首版范围。

### 12.2 ECHConfig 来源

- 默认动态查询 `cloudflare-ech.com` 的 HTTPS RR。
- 用户可增加其他明确的 ECHConfig 来源域名。
- 查询必须通过境外 DNSCrypt 路径完成。
- ECH 来源查询直接调用境外上游，不重新进入主 sequence 或 `cdn_rewrite`，避免分类和改写递归。
- 不使用公共 Total-ECH Worker 作为生产上游。
- 不永久硬编码某次取得的 ECHConfig。
- 解析并验证 ECH version、KEM、cipher suite、`public_name` 和 `config_id`。
- 按上游 TTL 缓存，并在过期前刷新。
- 严格模式可配置有限 stale grace；超出 grace 后阻断。
- 不同来源返回不一致配置时，严格模式不使用它们。

### 12.3 严格模式

对 allowlist 域名：

```text
A      → NOERROR，无 Answer
AAAA   → NOERROR，无 Answer
HTTPS  → 可连接 ServiceMode
         target = "."
         ipv4hint = 当前优选 IPv4
         alpn = 上游支持值
         ech = 动态 ECHConfig
         mandatory = ech
```

改写规则：

- 从可用的上游 HTTPS RR 保留兼容 SvcParam。
- 删除不兼容 endpoint 和冲突 IPv6 hint。
- 优选 IPv4 未通过健康检查时不提供该 endpoint。
- ECHConfig 不可用或验证失败时返回失败，不恢复 A/AAAA。
- 不支持 HTTPS RR/ECH 的客户端无法连接该域名，这是严格模式的预期行为。

### 12.4 回退模式

对 allowlist 域名：

```text
A      → 当前优选 IPv4；不健康时使用 last-known-good 或原 IP
AAAA   → 空
HTTPS  → 有有效 ECHConfig 时注入；否则保留可用上游响应
```

用户可以独立设置：

- DNS 响应回退策略。
- Firefox `network.dns.echconfig.fallback_to_origin_when_all_failed` 偏好建议。

项目不自动修改 Firefox profile。

### 12.5 Firefox 无 DoH

- 要求 Firefox 129 或更高版本。
- Firefox 通过系统解析器查询 HTTPS RR。
- 不设置 Firefox DoH。
- 不安装 CA。
- 不进行 TLS MITM。
- 严格模式依靠空 A/AAAA，使未取得 HTTPS RR/ECH 的客户端无法连接。
- 首次启用严格模式前提示清理旧 A 缓存或重启 Firefox，因为已有缓存无法由 DNS 立即撤回。
- 当前 Firefox 原生 HTTPS RR 路径仍可能出现查询与建连竞态；项目通过 fail-closed 将竞态结果从明文连接变为连接失败，但仍在测试报告中记录客户端缺陷状态。

## 13. 状态和 generation

`cdn-selector.json` 至少包含：

- schema version
- generation
- mode：auto、manual、disabled
- provider
- winner IP
- winner proof expiry
- fallback IP
- CloudFront 域名映射
- 最近成功验证时间
- 最近失败原因
- 配置摘要哈希

`ech-state.json` 至少包含：

- schema version
- generation
- 来源域名
- 获取时间
- TTL 到期时间
- stale grace 到期时间
- ECHConfig 哈希
- public name
- 状态：fresh、stale、invalid

状态更新规则：

- 同目录临时文件。
- 完整写入并 `fsync`。
- JSON/schema 校验。
- 原子 rename。
- 失败时不覆盖 last-known-good。
- 状态变化触发对应缓存清理。

## 14. 错误处理

| 故障 | 行为 |
|---|---|
| Quad9 全部不可达 | 境外返回失败，不回退 DHCP DNS |
| DNSCrypt provider certificate 异常 | 保持证书验证，报告错误，不绕过 |
| DHCP DNS 为空 | 中国分支 fail-closed |
| DHCP DNS 变化失败 | 保持上一状态或按策略停用，不加入公共 DNS |
| 新优选 IP 验证失败 | 保留当前 winner |
| 手动 IP 验证失败 | winner → last-known-good → 原 DNS |
| ECH 来源失败 | strict 阻断；fallback 使用原 HTTPS RR |
| ECHConfig 来源不一致 | strict 阻断；fallback 标记不可用 |
| selector 文件损坏 | 使用上一份已验证状态 |
| 配置语法错误 | 拒绝切换，保留现有运行配置 |
| MOSDNS 停止 | 本机 DNS fail-closed，不自动启用原 DNS |
| Firefox 低于 129 | 优选继续工作，ECH 标记不可用 |
| 磁盘空间不足 | 保留旧状态，停止新结果写入并报警 |
| 同时触发自动/手动任务 | 文件锁串行化，手动请求不丢失 |

## 15. 安全和隐私

### 15.1 网络边界

- 所有服务仅监听 loopback。
- 不开放 LAN DNS。
- 不用 nftables 拦截普通流量。
- 不进行 SNI DPI。
- 不劫持 Firefox 流量。

### 15.2 凭据和验证

- 不使用 `insecure_skip_verify`。
- 所有测试 URL 验证证书。
- CloudFront 测试保持 SNI 与 Host 一致。
- DNSCrypt 使用完整 stamp 和 provider public key。
- 不通过关闭时间戳检查处理证书错误。

### 15.3 日志

默认记录：

- 服务健康和上游状态。
- DHCP DNS 集合变化时间与接口。
- generation 和 selector 变化。
- 测速摘要。
- ECHConfig 到期和哈希，不记录完整值。
- 缓存、回滚和错误原因。

默认不记录：

- 逐条 DNS 查询。
- Firefox 浏览历史。
- TLS 内容。
- 完整 ECHConfig。

### 15.4 外部风险和限制

- ECH 隐藏真实 SNI 不会被本地网络和 ISP 看到，但目标网站仍能看到访问者真实 IP；ECH 不用于绕过地域或账户限制。
- Cloudflare 共享 ECHConfig 是同一 front door 内的条件性部署行为，不是跨区域、跨 IP 池的永久兼容承诺。
- 将 Cloudflare-proxied 域名流量发送到未分配给该域名的 Cloudflare IP 可能受 Cloudflare 服务条款限制；部署者应自行核对最新条款。本规范不提供法律意见。
- strict ECH 会阻断不支持 HTTPS RR/ECH 的应用，这是防泄漏策略，不是透明兼容模式。
- Firefox 缓存中的旧 A 记录无法被 DNS 立即撤回；首次切换 strict 前必须完成缓存清理或重启。

## 16. 兼容性和安装

### 16.1 支持矩阵

| Ubuntu | 最低基线 | 架构 |
|---|---|---|
| 22.04 LTS | NetworkManager 1.36、systemd 249 | amd64、arm64 |
| 24.04 LTS | NetworkManager 1.46、systemd 255 | amd64、arm64 |
| 26.04 LTS | NetworkManager 1.54.3、systemd 259.5 | amd64、arm64 |

### 16.2 版本探测

安装器通过 `/etc/os-release` 识别系统，并探测：

- NetworkManager 与 dispatcher。
- systemd-resolved。
- `/etc/resolv.conf` 链接。
- 活动连接。
- Firefox 版本。
- CPU 架构。
- 端口占用。
- systemd capability。

不使用 24.04/26.04 专属功能作为三版共同前提。

### 16.3 二进制

- 初始 MOSDNS 基线：v5.3.4。
- 初始 dnscrypt-proxy：2.1.18。
- Go 定制二进制使用固定 Go 1.25.x 工具链。
- 产出静态 amd64/arm64 二进制。
- 使用官方发布或源码构建输入的 SHA-256。
- 不使用 Ubuntu 26.04 中较旧的 dnscrypt-proxy 2.1.14 作为行为基线。
- 版本升级不自动替换配置和状态。

### 16.4 systemd 加固

适用于长期服务：

- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `ProtectKernelTunables=true`
- `ProtectKernelModules=true`
- `ProtectControlGroups=true`
- 限制 address family 为 AF_UNIX、AF_INET、AF_INET6
- 独立 `ReadWritePaths=/var/lib/mosdns /run/mosdns`

### 16.5 安装和卸载

- 修改 NetworkManager 前创建 root-only 备份。
- 备份中记录本项目 marker。
- 卸载仅恢复仍带 marker 且未被用户修改的配置。
- 提供独立紧急恢复命令。
- 配置带 schema version。
- 升级前执行迁移测试。
- 软件包更新不覆盖 selector、ECH 状态或用户候选。

## 17. Podman 隔离测试

### 17.1 原则

- 当前开发机只用于编辑、单元测试、静态构建和生成测试制品。
- 不在当前宿主机运行项目安装器。
- 不修改宿主机 NetworkManager、systemd-resolved、`/etc/resolv.conf` 或 Firefox。
- 所有系统安装、升级、卸载和恢复在一次性 Podman 虚拟机中的 Ubuntu systemd 容器运行。
- 不挂载宿主机 `/etc`、`/run` 或 `/var` 到目标容器。
- 源码只读挂载；测试状态放在 VM 私有卷。

### 17.2 容器拓扑

```text
一次性 Podman VM
├── mock-router
│   ├── DHCP server
│   ├── 国内 DNS
│   └── DNS 可动态变化/断开
├── Ubuntu 22.04 systemd target
├── Ubuntu 24.04 systemd target
├── Ubuntu 26.04 systemd target
├── mock Cloudflare/CloudFront TLS server
└── dig/curl/Firefox test clients
```

### 17.3 镜像和架构

- 使用 Ubuntu 官方镜像固定 digest。
- 容器以 systemd 为 PID 1。
- amd64 三版在 x86_64 测试 VM 中执行。
- arm64 使用原生 arm64 runner 或完整 aarch64 虚拟机。
- QEMU 用户态模拟只能标记为兼容性测试，不能替代原生 arm64 验收。
- 记录 Podman、VM、kernel、Ubuntu image digest 和架构。

### 17.4 自动化测试

#### 单元测试

- 国内外规则优先级。
- CNAME 与混合 CDN 分类。
- A、AAAA、HTTPS/SVCB wire 编解码。
- ECHConfig 验证、TTL 和轮换。
- strict/fallback 响应。
- DNSSEC RRSIG 和 AD 处理。
- 选择评分、预算和 pin 回退。
- 原子状态更新和 generation。

#### 集成测试

- 国内查询只到 DHCP mock。
- 境外查询只到 DNSCrypt 路径。
- DHCP 变化无需重启 MOSDNS。
- dnscrypt-proxy 停止后境外 fail-closed。
- UDP 截断后转 TCP。
- selector/ECH/DHCP 变化后缓存失效。
- 100 MiB 预算不可绕过。
- 手动和自动任务互斥。
- 卸载和紧急恢复无残留。

#### Firefox/ECH

- Firefox 官方 tarball 在测试 VM 中运行，不依赖 snapd。
- 不设置 DoH。
- strict 域名 A/AAAA 为空，HTTPS RR 包含 ECH。
- 支持 ECH 的 Firefox 成功连接。
- 不支持 HTTPS RR/ECH 的客户端无法连接 strict 域名。
- fallback 模式按策略连接。
- 记录 Firefox 原生 HTTPS RR 竞态的测试结果。

#### 故障注入

- Quad9 超时。
- DHCP DNS 不可达。
- 路由器重启。
- ECH 来源超时/错误格式。
- 非法候选和空候选。
- 状态文件截断和并发写。
- 时间错误。
- 磁盘不足。
- 服务和主机重启。

### 17.5 宿主机污染检查

测试前后记录宿主机：

- NetworkManager 连接摘要。
- resolved 配置和状态摘要。
- `/etc/resolv.conf` 链接。
- systemd unit 列表。
- 监听端口。
- Firefox profile 摘要。

除源码构建缓存和明确允许的 Podman 工具数据外，不允许变化。测试结束销毁 VM、容器、网络和卷。

## 18. 完成标准

以下条件全部满足才可声明完成：

1. Ubuntu 22.04、24.04、26.04 安装和服务测试通过。
2. amd64 和 arm64 原生验收通过。
3. 动态 DHCP DNS 无需硬编码中国公共 DNS。
4. 中国域名只走 DHCP DNS。
5. 非中国域名只走 DNSCrypt。
6. 境外 DNSCrypt 全部失败时无明文或 DHCP 回退泄漏。
7. Cloudflare 优选响应通过 Host/SNI/证书验证。
8. CloudFront 只在逐域名验证通过后改写。
9. 测速每日消耗不超过 100 MiB。
10. 延迟前十、带宽排名、联合评分和 winner 切换符合本规范。
11. 手动 pin 及两级回退工作正常。
12. 强制 ECH allowlist 生效。
13. strict 模式无 ECH 时无法取得可用 A/AAAA。
14. fallback 模式按策略回退。
15. Firefox 全程未设置 DoH、未安装 CA、未被 MITM。
16. 状态损坏不会覆盖 last-known-good。
17. 安装、升级、卸载和紧急恢复测试通过。
18. Podman 测试前后宿主机网络和 Firefox 状态无污染。
19. 配置中不存在硬编码中国公共 DNS。
20. 全部测试报告明确列出环境、版本、架构和未完成项；未运行的 arm64 或真实网络项目不得标记为通过。

## 19. 关键参考

### MOSDNS

- https://github.com/IrineSistiana/mosdns
- https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v5
- https://github.com/IrineSistiana/mosdns/releases/tag/v5.3.4

### dnscrypt-proxy / Quad9

- https://github.com/DNSCrypt/dnscrypt-proxy
- https://dnscrypt.info/doc
- https://github.com/DNSCrypt/dnscrypt-resolvers
- https://quad9.net/service/service-addresses-and-features/
- https://github.com/Quad9DNS/dnscrypt-settings

### NetworkManager / systemd-resolved

- https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html
- https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html
- https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html
- https://man7.org/linux/man-pages/man1/resolvectl.1.html

### CDN

- https://www.cloudflare.com/ips/
- https://developers.cloudflare.com/api/resources/ips/methods/list/
- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
- https://ip-ranges.amazonaws.com/ip-ranges.json
- https://github.com/XIU2/CloudflareSpeedTest

### ECH

- https://www.rfc-editor.org/rfc/rfc9460.html
- https://www.rfc-editor.org/rfc/rfc9848.html
- https://www.rfc-editor.org/rfc/rfc9849.html
- https://developers.cloudflare.com/ssl/edge-certificates/ech/
- https://github.com/XTLS/BBS/issues/13
- https://github.com/RememberOurPromise/Total-ECH
- https://bugzilla.mozilla.org/show_bug.cgi?id=2052430

### Ubuntu

- https://documentation.ubuntu.com/release-notes/22.04/
- https://documentation.ubuntu.com/release-notes/24.04/
- https://documentation.ubuntu.com/release-notes/26.04/
