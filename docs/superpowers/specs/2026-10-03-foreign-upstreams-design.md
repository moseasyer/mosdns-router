# 境外上游多路可配、连通性检测与缓存时间可调 —— 设计规范

- 日期：2026-10-03
- 状态：已完成交互评审，等待用户复核书面规范
- 前置：`2026-09-25-mosdns-dnscrypt-cdn-ech-design.md` §2.1「默认 Quad9 Secure DNSCrypt v2，支持用户替换 resolver stamp 和策略」中「支持」二字至今没有实现
- 涉及组件：`internal/config`、`internal/mosdnsconfig`、`internal/dnscrypt`、`cmd/mosdns-cdnctl`、`packaging/man`

## 1. 摘要

境外（国外）分支的上游今天焊死在 `tcp://127.0.0.1:15353` 一个地址上。它是 `internal/mosdnsconfig/render.go:186` `ProductionPaths()` 里的一个 Go 常量，既不是策略字段也不是渲染参数。本规范把它变成一个**策略里可配的列表**：

1. 默认两条上游：本包自带的 DNSCrypt Quad9，和一条 mosdns 自己拨号的 DoQ Quad9。
2. 每个条目是 `dnscrypt`（走本包的 dnscrypt-proxy）或 `upstream`（走 mosdns，支持 mosdns 接受的所有 scheme）。
3. 多条上游默认竞速，而不是 mosdns 的随机单选。
4. `mosdns-cdnctl check-upstream` 真的建上游、发查询、报结果。
5. 缓存记录时间可配（mosdns 自带 `ttl` 插件），`mosdns-cdnctl flush-cache` 可清空。
6. **DNSCrypt stamp 值仍留在 conffile**，不搬进策略。

## 2. 现状与它的硬约束

这一节每一条都是从代码读出来的，不是推断；每一条都约束了后面的设计。

### 2.1 ECH 上游必须是 `tcp://`

`plugin/executable/cdn_rewrite/cdn_rewrite.go:353` `refuseUnsafeUpstream` 在构造期拒绝一切非 `tcp` 的 scheme，并拒绝没有显式 scheme 的地址。理由写在 `:345-352`：

> mosdns v5.3.4 的 stock UDP upstream 会重发一秒未应答的查询，并能丢掉在它开始等待之前就到达的应答，这就是境外分支拿到一个 TCP listener 的原因。ECH fetch 没有客户端在看它，所以丢一个查询就是一个强制 ECH 域名在上一把 key 的整个有效期里 fail closed，而构造期的拒绝是唯一能把它说出口的地方。

**后果**：DoH/DoT/DoQ 可以进 forward 列表，**不能**当 ECH 的来源。这是设计里最硬的一条约束。

### 2.2 mosdns v5.3.4 接受的 scheme

模块源码在 `/home/ubuntu/go/pkg/mod/github.com/!irine!sistiana/mosdns/v5@v5.3.4/pkg/upstream/upstream.go:274-553`：

| scheme | 行 | 默认端口 |
|---|---|---|
| `""`（空，即裸 `host[:port]`）与 `udp` | `:275` | 53 |
| `tcp` | `:315` | 53 |
| `tls` | `:353` | 853 |
| `https` | `:402` | 443 |
| `quic` 与 `doq` | `:483` | 853 |
| 其他 | `:551` | `unsupported protocol` |

`upstream.go:131-156` 在 switch 之前还有一层归一：`tcp+pipeline` / `tls+pipeline` 映射到 `tcp`/`tls` 并打开 pipeline，`h3` 映射到 `https` 并打开 HTTP/3。**没有 `sdns://`** —— DNSCrypt 对 mosdns 不可能，这是独立进程的硬理由，不是本项目的选择。

### 2.3 `concurrent` 默认 1，而 1 是随机挑

`plugin/executable/forward/forward.go:248-254`：`concurrent` 默认 1，硬上限 3（`maxConcurrentQueries`）。`forward.go:265-267`：

```go
r := rand.IntN(len(us))
... us[(r+i)%len(us)]
```

**随机起点 + 顺序轮转，不是竞速。** 多条上游要真冗余必须 `concurrent ≥ 2`。本仓自己的 `plugin/executable/dhcp_forward/dhcp_forward.go:30-32` 就用 2。

### 2.4 域名上游会绕成死循环

这台机器唯一的解析器就是路由器自己（安装事务把 NetworkManager 指向 `127.0.0.1:53`）。`quic://dns.quad9.net:853` 里的 `dns.quad9.net` 无处可解析。

`internal/dnscrypt/config.go:62` 已经解过这个问题：`bootstrap_resolvers = ["9.9.9.9:53", "149.112.112.9:53"]`，并在注释里说明 bootstrap **不是查询路径**。同样的机制、同样的取值。

### 2.5 `lazy_cache_ttl` 不是 TTL

`plugin/executable/cache/cache.go:198`：

```go
cachedResp, lazyHit := getRespFromCache(msgKey, c.backend, c.args.LazyCacheTTL > 0, expiredMsgTtl)
```

第三个参数是**布尔**。开了只是让已过期的条目以 `expiredMsgTtl = 5`（`cache.go:64`）的 TTL 返回并在后台刷新。`getRespFromCache`（`utils.go:136-161`）里条目过期时间另有来源，与 `LazyCacheTTL` 无关。

**所以「用户可以更改 DNS 记录缓存时间」不能靠 `lazy_cache_ttl`。** mosdns 有专门的 `ttl` 插件（`plugin/executable/ttl/ttl.go`），`NewTTL(fix, min, max)`，`Exec` 里按 fix/min/max 改写每条记录的 TTL。

### 2.6 `ApplyMaximumTTL(m, 0)` 会把 TTL 设成 0

`pkg/dnsutils/msg.go:101-103`：

```go
if maximum {
    if hdr.Ttl > ttl { hdr.Ttl = ttl }
}
```

`ttl == 0` 意味着**每条记录都变成 0**，不是「无上限」。`ttl.go:90` 的 `if t.max > 0` 守卫避免了这一点——**只要不把 max 渲染出去**。

而 `configs/mosdns.yaml` 是逐字节比对的（`internal/mosdnsconfig/render_test.go:905` `TestCommittedMosdnsConfigIsExactlyTheRenderedDefault`），所以「策略不变 ⇒ 文档不变」是一条必须保持的性质。

### 2.7 cache flush 已经存在，只是够不着

`plugin/executable/cache/cache.go:320-324` 注册了 `GET /flush`，`:108` 无条件 `bp.RegAPI(c.Api())`，`coremain/plugin.go:199-201` 把它挂在 `/plugins/<tag>` 下，即 `/plugins/foreign_cache/flush`。

服务端只在配置带 `api.http` 时启动（`coremain/mosdns.go:67`），而本项目的渲染文档只有 `log` 和 `plugins` 两个键（`internal/mosdnsconfig/render.go:198-201`）。**加一个字段就能用，不是新机制。**

### 2.8 15353 焊在五个地方

`internal/dnscrypt/config.go:27`、`internal/mosdnsconfig/render.go:186`、`installer/mosdns_installer.py:314`、生成的 YAML、生成的 TOML。`internal/dnscrypt/config.go:56` 的 netprobe 超时注释记着一次**实测的** 60s 对 60s 冲突，依赖这个端口/超时的配对。

### 2.9 dnscrypt stamp 只能手改 conffile

`dnscrypt.Render(policy, stamps)` 的 `stamps` 参数在全仓只有一个非测试调用点，`cmd/mosdns-cdnctl/render.go:195` 硬传 `dnscrypt.Defaults()`。策略里没有 stamp 字段，`render` 也没有对应 flag。`cmd/mosdns-cdnctl/render.go:175-179` 把这写成了有意的设计，并指出文档化的逃生口是手改 conffile。

**本规范保留这个逃生口**（见 §3.1）。

## 3. 决策

### 3.1 stamp 值留在 conffile，条目列表进策略

**决策**：策略新增 `foreign.upstreams` 列表，每个条目声明**用哪个上游**；`dnscrypt` 条目的**stamp 值**仍写在 `/etc/mosdns/dnscrypt-proxy.toml`。

**理由**：

- stamp 是一个 `sdns://` 的 base64 blob，它的内容是「哪个 provider 的哪把钥匙」，与「路由器往哪儿发查询」是两个决定。放进策略会让 `dnscrypt-proxy.toml` 变成生成产物，而 `packaging/debian/conffiles:44-45` 明确把它列为操作员预期会编辑的 conffile。
- `mosdns-cdnctl validate` 对两者关系的处理可以是**校验而非阻塞**：条目列表说「有一个 dnscrypt 条目」，conffile 说「这个条目背后是这些 stamp」。两者不一致时报出来，但不拒绝安装。
- 反过来（全部进策略）会让 `validate` 变成阻塞性的，并拿掉一个已经存在的逃生口。

**代价**：新增一个 DNSCrypt provider 仍然要手改 conffile 并重启 `dnscrypt-proxy`。这一点会写进文档，不含糊。

### 3.2 条目形状

```yaml
foreign:
  default_provider: "Quad9 Secure DNSCrypt v2"
  ecs: false
  concurrent: 2
  upstreams:
    - kind: dnscrypt
      name: quad9-dnscrypt
    - kind: upstream
      name: quad9-doq
      addr: quic://dns.quad9.net:853
      bootstrap:
        - 9.9.9.9:53
        - 149.112.112.9:53
```

| 字段 | 必需 | 默认 | 说明 |
|---|---|---|---|
| `kind` | 是 | — | `dnscrypt` 或 `upstream` |
| `name` | 是 | — | 唯一，出现在报告、错误和 GUI 里 |
| `enabled` | 否 | `true` | 关闭而不是删除，配置不丢 |
| `addr` | `upstream` 必填；`dnscrypt` 禁止 | — | mosdns 上游 URL |
| `bootstrap` | 否 | Quad9 两个明文地址 | 只解析该上游自己的域名 |

`name` 的作用是让 `check-upstream quad9-doq` 和错误消息能指名道姓，而不是让人从一串 URL 里猜。

### 3.3 `concurrent` 默认 2

**决策**：`foreign.concurrent` 默认 2，可配 1..3。

**理由**：§2.3 —— 1 是随机单选，多条上游在 1 之下是负载均衡而不是冗余。本仓的 `dhcp_forward` 已经是 2。3 是 mosdns 自己的硬上限，再高会被它静默截断。

**文档要说的话**：`1` 不是「更安全」而是「没有故障转移」。

### 3.4 校验规则

全部在 `config.Policy.Validate()`，`internal/config/policy.go`。

1. 至少一个条目，且至少一个 `enabled`。
2. `dnscrypt` 条目至多一个。
3. `name` 非空、唯一、且只含 `[a-z0-9-]`（它会进日志和报告）。
4. `upstream` 条目的 `addr`：
   - `url.Parse` 成功；
   - **scheme 非空**，且 ∈ {`udp`,`tcp`,`tcp+pipeline`,`tls`,`tls+pipeline`,`https`,`h3`,`quic`,`doq`}；
   - 无 userinfo / path / query / fragment（path 允许且仅允许 `/`）；
   - host 是 IP 字面量或合法主机名，且**不是** loopback / unspecified / link-local；
   - port ≠ 53。
5. **无 scheme 的裸地址一律拒绝**，理由写进错误信息：它会默默变成 `udp://`，而 `udp` 正是 §2.1 实测拒绝掉的传输。给一个专门的错误类型。
6. `bootstrap` 每项是 `IP:port`，不是 loopback。
7. **ECH 来源规则**：启用条目里必须存在一个能当 ECH 来源的——启用的 `dnscrypt` 条目，或第一条 `addr` scheme 为 `tcp` 的启用 `upstream`。否则拒绝，错误信息点名 ECH 并说明后果（强制 ECH 域名会在 key 过期后 fail closed）。
8. `concurrent` ∈ 1..3。

第 7 条是整个设计里唯一一处「配置错了会让强制 ECH 静默失效」的地方，必须在渲染前拦住。

### 3.5 中国公共解析器检查扩到新条目

`internal/mosdnsconfig/render.go:743` `scanForChinesePublicDNS` 今天扫整份文档，拒绝 `chinesePublicDNSAddresses`（`:115-120`）里的五个地址——`223.5.5.5`、`223.6.6.6`、`119.29.29.29`、`114.114.114.114`、`180.76.76.76`——出现在任何位置。

新条目渲染进同一份文档，所以这个检查自动覆盖它们。**不需要新代码**，但需要一条测试断言新条目确实被扫到——否则「自动覆盖」只是一句没被验证的话。

### 3.6 渲染

`internal/mosdnsconfig/render.go`。

**`foreign_forward`**：`upstreams` 变成每条启用的 `upstream` 条目一个 `addr`，按策略顺序。`dnscrypt` 条目不产生 `forward` 条目——它是 `mosdnsconfig` 之外的东西，路由器通过 `127.0.0.1:15353` 拨号，而那个地址是 `dnscrypt` 条目的**渲染产物**。

**新增**：渲染器必须知道 DNSCrypt listener 的地址，而它今天来自 `Paths.ForeignListener`（值是 `ProductionPaths()` 里的常量 `tcp://127.0.0.1:15353`）。

改法：`dnscrypt` 条目**不携带地址**——地址是 dnscrypt 自己的常量。`internal/dnscrypt` 导出一个 `ListenAddress()`（或把 `listenAddress` 变成导出的），`mosdnsconfig` 在策略有启用的 `dnscrypt` 条目时用它。**这样两份文档不可能对不上**，而这正是今天 `TestTheForeignListenerIsWhereTheCommittedDNSCryptProxyListens`（`render_test.go:941`）守住的东西。

`Paths.ForeignListener` **保留，并且非空时优先**——它是集成测试的注入缝（`tests/integration/routing_test.go:457` 就是用它指向 mock 解析器的）。`ProductionPaths()` 把它置空，生产路径因此从条目推导，既有调用点一个不改。

**`cdn_rewrite.foreign_upstream`**（ECH 来源）：`dnscrypt` 条目启用 → 它的 listener；否则第一条启用的 `tcp://` 条目的 `addr`。校验已在 §3.4(7) 保证这里一定有一个。

**`forward.args.concurrent`**：策略值。

**`api.http`**：`127.0.0.1:15354`，仅 loopback。新增常量，理由与 15353 同（不需要特权，且非特权端口）。

**`foreign_ttl`**：见 §3.7。

### 3.7 缓存时间：`ttl` 插件的位置与陷阱

**策略**：

```yaml
foreign_cache:
  size: 1024          # 今天已是渲染常量 1024
  ttl_max: 0          # 0 = 不夹紧（上游 TTL 原样）
  ttl_min: 0          # 0 = 不抬升
```

**渲染**：当 `ttl_max` 或 `ttl_min` 非零时，在插件表里 `foreign_forward` **之后**追加

```yaml
  - tag: foreign_ttl
    type: ttl
    args:
      max: <ttl_max>     # ttl_max 为 0 时整个键不出现
      min: <ttl_min>     # ttl_min 为 0 时整个键不出现
```

**位置的理由**：插件表顺序决定 next 链。今天是 `cdn_rewrite → foreign_cache → … → foreign_forward`，cache 未命中时它内部调 next 拿到 forward 的答案再存。把 `foreign_ttl` 放在 `foreign_forward` 之后，链变成 `cache → forward → ttl`，于是**缓存存的是夹紧后的值**，命中时返回的也是夹紧后的值。这正是「用户改缓存时间」的语义。

如果放在 cache 之前，夹紧只作用于出口，路由器自己的缓存仍按上游 TTL 过期——那不是用户要的东西。

**陷阱**：`ttl_max: 0` 时**整个插件不渲染**，因为 `ApplyMaximumTTL(m, 0)` 会把每条记录设成 TTL 0（§2.6）。这样「策略不变 ⇒ 文档逐字节不变」得以保持。

**`min` 与 `max` 同时非零的语义**：先抬升到 min 再压到 max。`ttl.go:88-93` 就是这个顺序，所以 `min > max` 的配置会让结果恒为 max。这不额外拒绝，但文档要说明。

**`foreign_cache.size`** 变成策略字段，默认仍是 1024（`render.go:70` 今天把它写成常量并注明「不是实测值」）。

### 3.8 `check-upstream`

新 verb：`mosdns-cdnctl check-upstream [NAME | --all]`

对每条启用条目：

1. `dnscrypt` 条目 → 对它的 listener 建一个 `tcp://` 上游（和 ECH 同一条路，所以这个检查也覆盖了 ECH 的可达性）。
2. `upstream` 条目 → 对它的 `addr` 建上游，带上它的 `bootstrap`。
3. 各问一次 `example.com` 的 A 记录，测 rcode 与耗时。

**探测名用 `example.com`**：IANA 保留名，任何递归解析器都必须回答，而且它测的是「传输通 + 解析通」，不掺入任何一家的策略或过滤。用 Cloudflare 或 Google 的名字会把「这家拒绝了 example.com」和「网络不通」混在一起。

**为什么要有这个 verb**：GUI 的「检测通不通」按钮和操作员手测需要同一条代码路径。它写标准输出、逐条一行，退出 0 表示全部可达、非 0 表示有不可达的条目。

### 3.9 `flush-cache`

新 verb：`mosdns-cdnctl flush-cache` → `GET http://127.0.0.1:15354/plugins/foreign_cache/flush`（§2.7）。

**安装器不探测 15354**。它不在安装的关键路径上——flush 是操作员动作，失败了自己会报。而且 `check_ports` 今天只看 53 和 15353，多一个端口就多一处需要在安装事务里等的东西。

**API 只绑 loopback**，与本包「只有 loopback listener」的承诺一致，`installer/tests/test_units.py:1358` 的 loopback 扫描会继续通过。

## 4. 明确不变的部分

写下来是为了让后来的人知道这些是有意的，不是漏掉的。

1. **15353 不动**，`dnscrypt-proxy.service` 照旧运行，安装器照旧要求它在 `127.0.0.1:15353` 应答（`installer/mosdns_installer.py:3811-3824` 的 `wait_for_dns(LOCAL_DNS, RESOLVER_PORT)`）。
2. **禁用 `dnscrypt` 条目不会停掉那个 unit。** 它只是让路由器不再往那儿发查询。停不停是操作员自己的决定，`systemctl disable dnscrypt-proxy`。这条会写进 man page。
3. **`refuseUnsafeUpstream` 继续要求 ECH 来源必须是 `tcp://`**，一个字不改。
4. **stamp 集合仍是操作员的 conffile**（§3.1）。
5. **`dnscrypt.Render` 的签名不变**，listen 地址仍是常量（15353 不动，§4.1）。
6. **国内分支完全不受影响** —— `dhcp_forward` 那套动态上游是另一条路径、另一个机制，不动。
7. **没有新增 systemd unit，没有新增 timer。**

## 5. 会被打破的测试，以及它们要改成守住什么

**原则**：预期改变的断言要**改写成守住新性质**，不是删掉。这个仓反复吃过「断言形状而不是性质」的亏。

### 5.1 Go — `internal/mosdnsconfig/render_test.go`

| 现有 | 现在断言 | 改成断言 |
|---|---|---|
| `TestTheForeignForwardUsesOnlyTheDNSCryptListenerOverTCP` `:606` | `len(Upstreams) != 1` 就失败 | 每个启用的 `upstream` 条目产生恰好一个 upstream，顺序与策略一致，**且没有条目产生非 `tcp` 的 ECH 来源** |
| `TestTheECHKeyIsFetchedThroughTheSameListenerTheForeignBranchDials` `:568` | 两个地址相等且只有一个 | 两个地址相等；新增一个「禁用 dnscrypt 条目时 ECH 来源落到第一条 `tcp://` 条目」的对照 |
| `TestTheForeignListenerIsWhereTheCommittedDNSCryptProxyListens` `:941` | forward 的 addr == toml 的 listen | 保留，并加一条「`dnscrypt` 条目的渲染产物就是 toml 里那个地址」 |
| `TestCommittedMosdnsConfigIsExactlyTheRenderedDefault` `:905` | 逐字节 | 保留——这是「策略不变 ⇒ 文档不变」的唯一守卫 |
| `TestRenderedRoutingNamesEachPluginExactlyOnceInLoadOrder` `:179` | 插件表严格解码 | 测试侧 `rendered` 类型加 `API` 字段；插件表新增 `foreign_ttl`（仅在夹紧生效时） |
| `TestForeignPathAnswersFromTheCacheBeforeItForwards` `:406` | 五条规则 | 保留原样 + 新增「`foreign_ttl` 在 `foreign_forward` 之后」 |
| `TestRenderedConfigLoadsInAMosdnsInstance` `:986` | 恰好 1 次 TCP、0 次 UDP | 改成「并发为 2 时两个上游各被问过，且答案来自先应答的那个」 |
| `TestRenderRefusesListenersThatWouldCollide` `:812` | 四个冲突用例 | 保留；新增「没有 ECH 来源的策略被拒绝」 |
| `TestNoAddressButLoopbackIsCommitted` `:970` | 每个点分十进制都是 127.0.0.1 | 保留——它会自动覆盖 bootstrap 地址和 15354 |

新增：`TestEveryForeignUpstreamIsCheckedForAChinesePublicResolver`（§3.5）、`TestATtlClampIsNotRenderedWhenThePolicyAsksForNone`（§2.6 的陷阱）、`TestThePolicyAndTheCommittedDocumentAgreeOnTheEntryCount`。

### 5.2 Go — 其他

- `plugin/executable/cdn_rewrite/cdn_rewrite_test.go:2633` `TestAnUnsafeECHUpstreamIsRefused`：**不动**。§4.3 说这个拒绝不变，所以这个测试也不变。
- `internal/dnscrypt/config_test.go` 全部 13 个：**不动**，除了 `TestRenderUsesOnlyTheSuppliedStamps` 需要加一条「新增的策略字段不影响 stamp 集合」。
- `cmd/mosdns-cdnctl/render_test.go`：两个文档的逐字节断言会因为 `mosdns.yaml` 变而需要重生成，`dnscrypt-proxy.toml` 不变。
- `tests/integration/routing_test.go:1296` `TestAForeignQueryReachesTheResolverOnlyOverTCP`：断言恰好 1 次 TCP。改成「两个上游都被配置，且答案来自其中一个」。

### 5.3 Python

- `installer/tests/test_units.py:1363` `test_the_routing_document_forwards_to_the_loopback_resolver`：对 `upstreams` 列表做等值断言。改成「列表等于策略里启用的 `upstream` 条目」。
- `installer/tests/test_units.py:1358` loopback 扫描：会自动覆盖 15354 和 bootstrap 地址，无需改。
- `installer/tests/test_preflight.py`、`test_transaction.py`、`test_uninstall.py`：15353 相关的全部不动（§4.1）。

### 5.4 Podman

`scenarios/foreign_override.py`、`install_test.py`、`routing_test.py`、`watchdog_test.py` 以及 `tests/test_*.py` 里所有 `SHIPPED_LISTENER` / `RESOLVER_PORT` / `tcp://127.0.0.1:15353` 的字面量。这些**测试夹具**基本不用改——DNSCrypt listener 没动（§4.1），它们指向的东西仍然对。

**不需要为新增的 DoQ 条目做 override**，理由是 §8.2 量过的那件事：单元按设计没有到外网的路由，所以那条 DoQ 条目在单元里必然不可达，而 `concurrent: 2` 下**一次查询在第一个非错误答案到达时就返回**（`forward.go:302-319`），每次尝试还有自己独立的 5 秒上下文（`forward.go:272`），所以一个死掉的上游不增加延迟。DNSCrypt 那条被 `foreign_override.py` 指向 mock，仍然可达，答案仍然有。

**要新增的是一条断言**：单元里必须有一个用例证明「两条上游中一条不可达时查询仍然成功」。这是这个规范在 Podman 层唯一真正的新性质，也是 `concurrent: 2` 值得存在的理由；没有它，`concurrent` 就只是没人验证过的一个数字。

## 6. 实施顺序

每一步都可独立验证、独立提交。

1. **策略 schema + 校验**（`internal/config/policy.go`）：新字段、`Validate()` 的八条规则、ECH 来源规则。测试：每条规则一个用例，加上「一个把 §3.4 每条规则都违反一遍」的表驱动用例。
2. **渲染**（`internal/mosdnsconfig/render.go`）：forward 列表、`concurrent`、ECH 来源推导、`api.http`。测试：§5.1 的表格。
3. **`check-upstream`**：新 verb + 报告格式。测试：一个假上游矩阵（可达 / 不可达 / 拒绝 / 超时），每种一条。
4. **缓存 TTL + `flush-cache`**：`foreign_cache` 策略字段、`foreign_ttl` 插件渲染、flush verb。测试：§2.6 陷阱的用例 + 一个真的起 mosdns 实例验证 flush 生效的集成用例。
5. **改写既有测试**（§5.1–5.3）。
6. **Podman 夹具**（§5.4）：给单元里的 DoQ 条目加一个指向 mock 的 override。
7. **文档**：`mosdns-cdnctl(1)` 新增上游章节；`foreign.default_provider` 那句要改（它今天只被插进 `dnscrypt-proxy.toml` 的一句注释里，`internal/dnscrypt/config.go:212`）；`mosdns-router(8)` 的 FILES 要写 `policy.yaml` 的新形状。

## 7. 这个规范不做的事

写下来是为了让后来的人不去找它们。

1. **不做上游健康检查与自动摘除。** 多个上游是静态列表，`concurrent: 2` 让一次查询里两个都可能被问，但没有任何机制因为一个持续失败而把它移出列表。
2. **不做按上游的 ECS、DNSSEC 或过滤策略。** `foreign.ecs` 今天只被 `dnscrypt.Render` 读一次并对 DNSCrypt 拒绝（`internal/dnscrypt/config.go:121`），多上游之后它对 `upstream` 条目**完全无约束**。这是一个已知的洞，不是本规范引入的；本规范不修，也不假装它不存在。
3. **不改 DNSCrypt stamp 的验证。** `dnscrypt.validateStamp` 今天检查 sdns:// 前缀、IPv4 `IP:port`、32 字节公钥、DNSSEC 与 NoLog 属性。新增的 stamp 走同一条路。
4. **不给国内分支做任何改动。**
5. **不做上游的延迟排序或自动择优。** `concurrent: 2` 是竞速取先应答者，不是「挑最快的那条常驻」。
6. **不引入 systemd 的任何新单元。** 连通性检测是按需的，不是定时的。

## 8. 未决与已知风险

1. **`quic://dns.quad9.net:853` 在中国的可达性没有实测过。** Quad9 的 DoQ 端点在 2026-10-03 从这台机器（境外网络）可以解析，但本项目面对的用户在国内。默认值选它是因为它是 Quad9 的加密路径、与 DNSCrypt 同一家、同一个信任根；**如果它在某条国内线路上不通，`check-upstream` 会立刻说出来，而 `concurrent: 2` 与 DNSCrypt 那条一起保证了不会因此没有解析器。**
2. **`concurrent: 2` 的代价是每次查询多一次出站尝试，不是延迟。** 量过 `forward.go:255-320`：每次尝试拿自己独立的 `context.Background()` 加 5 秒超时（`:272`），而收集循环在**第一个非错误答案**到达时就返回（`:302-319`），所以一个不可达的上游不拖慢答案。它确实要付的账是：每个查询多一次注定超时的尝试，以及 mosdns 为每一次失败打一行 `Warn` 带上游名（`:274-280`）——**一个长期死掉的上游会按查询量刷日志**。这是真实代价，文档会写明，并说明 `concurrent: 1` 怎么关掉它。

   一条顺带查清、但与本规范无关的行为：`forward.go:311` 只在**最后一次**尝试上接受非 SUCCESS 的 rcode，所以 `concurrent: 2` 下某一个上游返回 SERVFAIL 会自动改问另一个。这是上游想要的语义，但它意味着一个「拒绝」和一个「不可达」在客户端看来是一样的。
3. **被改写的既有测试有二十余处**（§5）。每一处都要判断「它守的性质在新形状下是否还成立」，这是工作量的大头，也是最容易在不注意的时候把一个真实门禁删掉的地方。
4. **`api.http` 是这个包第一个 HTTP 监听。** 它只绑 loopback，`test_every_listener_the_configs_name_is_loopback` 会守住这一点，但这个先例本身值得在 review 里被明确看一眼。
