# 列表自动更新，以及让 `schedule` 成为一个真的字段

设计文档，2026-10-05。待评审。

## 背景：三个事实

**`policy.yaml` 的 `schedule` 是死字段。** `internal/config/policy.go:103` 校验它是合法
`HH:MM`，然后没有任何代码消费它 —— Go 侧不读（`grep '\.Schedule\b'` 只命中那处校验），Python
侧不读。真正决定运行时刻的是 `packaging/systemd/mosdns-list-check.timer` 里硬编码的
`OnCalendar=*-*-* 03:30:00`。**操作员把 policy 里的 `03:00` 改成 `05:00`，什么都不会发生。**

**China 列表从不自动更新。** `mosdns-list-check.timer` 每天 03:30 跑的是
`update-lists --check`，它自己的帮助文本写着 `writes nothing`。唯一的更新入口是
`update-lists --pin-remote`，而没有任何 unit、脚本或定时器自动跑它。实测当前状态：

    locked-commit: a5731758ed6b...   (2026-09-25)
    remote-commit: 63777333b7dd1...   (2026-10-04)
    up-to-date: false
    退出码: 0

**没有回退路径。** `--pin-remote` 接受的是上游 default branch 的**当前 HEAD**，
不能指定旧 commit。`pin` / `unpin` 两个动词是给 CDN 选择器用的，与列表无关。所以一次坏提交被
接受之后，没有办法退回去。

## 目标

1. `schedule` 变成一个改了就会生效的字段。
2. China 列表和 Cloudflare range 各有一个自动更新开关，**默认都关**，写在 `policy.yaml`。
3. 自动更新 china 列表时保留上一个 pin，并且能退回去。
4. 自动更新的任何失败都不改变已经发布的内容。

不在范围内：改变"pin 住每一样可远端取的东西"这个立场。自动更新是**由操作员明确打开的**，
默认关闭，所以这个立场没有被推翻，只是给了一个受控的例外。

## 设计

### 一、`schedule` 由 policy 渲染进 systemd timer

`mosdns-list-check.timer` 成为**第六个生成物**，和 `/etc/mosdns/mosdns.yaml`、
`/etc/mosdns/dnscrypt-proxy.toml` 同一个契约：

- `internal/mosdnsconfig` 增加一个渲染函数，把 policy 的 `schedule` 写成 `OnCalendar=*-*-* HH:MM:00`
- 仓库里提交渲染结果 `configs/mosdns-list-check.timer`，并有一条测试逐字节比对
  —— 和 `test_the_shipped_documents_are_the_ones_this_repository_reviewed` 同型
- `mosdns-cdnctl render` 除了那两份文档之外，也渲染这个 unit，并 `daemon-reload`
- `scripts/build-deb.sh` 在 bwrap 那一步渲染它进 staging tree，让包里的 unit 与 policy 一致

**为什么不是"timer 每小时跑、服务读 policy 自己判到没到"**：那样 23 次空跑和 1 次真跑在
日志里长得一样，而"看不出区别"正是不缺陷的定义。

**为什么不是"删掉这个字段"**：那不解决能力问题。操作员想改运行时间就该能在配置里改。

**已知的代价**：改了 policy 之后要 `render` 一次并 `daemon-reload` 才生效，和另外两份
生成文档的契约一样。这意味着"改了配置没生效"这个失败模式是存在的 —— 但它对那两份文档已经
存在了，这是同一个已知契约，不是新的坑。

**默认值改为 `03:30`**。这个字段过去是虚构的，而实际生效的是 03:30。让默认值说真话，
而不是借机把行为提前 30 分钟。

### 二、两个开关

`configs/policy.yaml` 新增：

```yaml
schedule: "03:30"
lists:
  china:
    automatic: false
  cloudflare:
    automatic: false
```

两个开关**分开**，理由是它们的风险等级不同：Cloudflare range 是 API 发布的地址段文档，
不影响"哪些名字走哪条路"，只影响 CDN 重写选哪个边缘节点；china 列表是人工策划的
`data/cn`，上游**任何**提交都会改变分流依据。捆在一起意味着打开低风险的那个会同时打开
高风险的那个。

沿用 `watchdog.yaml` 里 `automatic: true` 的既有先例 —— 这是这个项目第二处"唯一的无人值守
动作由一个布尔开关控制"，形状保持一致。

### 三、china 自动更新做什么

一次运行（由现有的 `mosdns-list-check.timer` 触发，`OnCalendar` 现在来自 policy）依次：

1. 读 policy 的 `lists.china.automatic`；`false` 时只做现有的 `--check` 报告
2. `true` 时：把当前的 `source-lock.json` 归档为 `source-lock.previous.json`
3. fetch 上游 default branch HEAD，按现有的 pin 规则校验（仓库 + commit + 两个摘要）
4. 校验通过才发布；**任何一步失败都退出非零，且已经发布的列表一个字节都不动**
5. 发布成功后才替换 `source-lock.json`，并清掉过期的 `.previous`

第 4 条是硬要求。`rules.Publish` 已经是"先全部校验再 rename"，但归档和发布之间的任何失败
都必须回到"当前 pin 仍然完整"这个状态。

### 四、回退

`--pin-remote` 从"只接受 HEAD"扩展为接受一个可选的 commit 参数：

    update-lists --pin-remote            # 上游当前 HEAD（今天的行为）
    update-lists --pin-remote <commit>   # 指定 commit

归档的 `source-lock.previous.json` 记录了上一个 pin 的完整四元组（仓库、commit、归档摘要、
列表摘要），所以回退不需要重新下载就能验证目标 commit 是不是曾经被 pin 过。

### 五、Cloudflare 自动更新

同一个开关为 `true` 时，在同一次运行里追加现有的 `--refresh-ranges`。它已经存在、已经在
安装时跑过一次、失败已经不动已发布的前缀列表。这一项**不需要新逻辑**，只需要被定时器按
policy 调用。

### 六、门禁

- `configs/mosdns-list-check.timer` 与渲染结果逐字节比对（新增）
- `schedule` 渲染出的 `OnCalendar` 与 policy 的值一致（新增）
- `policy.yaml` 里 `lists.china.automatic` 和 `lists.cloudflare.automatic` 默认都是 `false`
  （新增，防止有人顺手把默认打开）
- 归档 / 发布 / 回退三条路径各有测试，含"发布失败后当前 pin 与列表都不变"
- **变异验证**：把渲染出的 `OnCalendar` 改成别的时刻，渲染比对测试必须转红；把某个
  `automatic` 改成 `true`，默认值门禁必须转红

## 之后的动作（不在本设计内，但据此执行）

1. Actions 编译
2. 建新仓库 `mosdns-router-ng`，内容逐字复制，**只有仓库名不同，内部名字一律不改**
3. 在那里 Actions 编译
4. 在那里建 Release（由 `publish-release.yml` 完成）
5. 确认 **Release 的 deb 与它对应的那次 Actions build 的 deb 逐字节一致**

第 5 条已经成立：发布工作流下载那次 run 的 artifact 并重新断言，不重新编译。
所以**构建不需要改** —— `BUILD_TIME` 保持墙上时钟，两次不同的构建仍然不同，
而这与"release 等于它对应的那次 build"无关。

`mosdns-router-ng` 的后果要说清：它会产出**同名同版本**的包（包名、用户、组名、产物文件名
全部与 `mosdns-router` 相同），机器上无法凭包名区分来源。它的工作流用自己的
`GITHUB_TOKEN`，不会修改 `mosdns-router` 那个仓库。

## 风险与代价

| | |
|---|---|
| 自动更新 china 列表 | 上游任意提交会改变分流依据，无人审查。这是操作员明确打开的交换，不是默认行为 |
| `schedule` 变成生成物 | 新增一个生成物和一条比对测试；"改了配置没重新 render"成为该字段的已知失败模式 |
| `--pin-remote` 接受任意 commit | 一个 commit 参数进入一个会改变路由的命令。必须保持"指定 commit 也要过摘要校验" |
| 归档上一个 pin | 多一个文件要写、要清、要保证不会被当成当前 pin 读 |
| 默认值改成 03:30 | `configs/policy.yaml` 的这一行会变，与 `03:00` 不同 |