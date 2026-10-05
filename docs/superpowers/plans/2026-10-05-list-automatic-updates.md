# 列表自动更新 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `policy.yaml` 的 `schedule` 真正生效，并给它两个默认关闭的开关，分别控制 China 域名列表和 Cloudflare range 的自动更新，且自动更新可回退。

**Architecture:** `schedule` 由新的渲染函数写进 `mosdns-list-check.timer` 的 `OnCalendar`，该 unit 成为第六个生成物（提交产物 + 逐字节比对 + `render` 时重写并 `daemon-reload`）。自动更新由 `update-lists --automatic` 承载：无参数、与其它三个模式互斥、读 policy 的两个开关、始终产出既有的漂移报告。China 自动更新在发布前归档当前 pin，校验全部通过才发布，任何失败不碰已发布内容；`--pin-remote` 扩展出可选 commit 参数，使归档可用。

**Tech Stack:** Go 1.25.8、mosdns v5.3.4、Python 3.10+（installer 与测试）、systemd（timer）、GitHub Actions。

**Spec:** `docs/superpowers/specs/2026-10-05-list-automatic-updates-design.md`

## Global Constraints

- 开发主机**不得**有任何系统级改动：不装包、不改 `/etc/resolv.conf`、不碰 53/15353、不跑 `mosdns_installer.py` 的任何变更模式。边界见 `.superpowers/sdd/NO-HOST-MUTATION.md`。
- Go 工具链固定 1.25.8，路径 `/tmp/opencode/go1.25.8/bin`；`GOCACHE=$PWD/.gocache-review`，`GOTMPDIR`/`TMPDIR`=`/home/ubuntu/.gotmp-mosdns`。
- 永远不要 `git stash -u`（`.gocache-review/` 是 1.3GB 未跟踪目录）。
- 期望值必须从**已发布的源码**推导；每条新测试都要做变异验证；**不许删门禁来让改动通过**。变异的构建失败会被当成"没有失败"，必须单独看 `exit=`。
- 门禁：`gofmt -l $(git ls-files '*.go')` 干净、`go vet ./...`、`go test ./...`、`make verify-package`。
- installer 测试有一个**先前就存在**的失败：`test_the_man_stub_is_what_keeps_documentation_from_deciding_the_verdict`（断言 systemd 249/255，本机 259）。不要试图修它。
- 生成的文档/unit 一律带一个说明"由什么生成、编辑哪里"的头注释。
- 版本：`PACKAGE_VERSION` 在 `scripts/build-deb.sh`，control 的 `Version:` 由构建脚本计算，两处都改。

## Review Focus

规格没有穷举、但最可能咬人的五类输入。每一类在下面都有对应的测试步骤，写在拥有该代码的任务里。

1. **一个合法的上游 commit 把列表大幅缩小。** 摘要校验会通过（它确实来自上游），于是发布，然后大量名字改走境外分支 —— 没有任何人审查过。Task 6 的收缩护栏 + 测试。
2. **自动更新成功后 `source-lock.previous.json` 是更早一次运行留下的**，于是操作员以为在回退到 A，实际回退到 B。Task 5 的归档新鲜度测试。
3. **`render` 写了 unit 但 `daemon-reload` 没跑或失败**，systemd 继续用旧 `OnCalendar` 直到重启 —— 操作员改了 `schedule` 而什么都没变，正是这次改动要消灭的症状。Task 3。
4. **包里的 unit 是未渲染的副本**：`build-deb.sh` 的 staging render 写 `--out /etc/mosdns`，而 unit 属于 `/usr/lib/systemd/system`。Task 4。
5. **开着 `china.automatic` 的机器没有出网路由**：timer 触发、失败，必须什么都不动，且不能因为先归档后失败而让下一次的回退目标错位。Task 6。

---

## File Structure

| 文件 | 责任 |
|---|---|
| `internal/config/policy.go` | 新增 `ListsPolicy` / `ChinaListPolicy` / `CloudflareListPolicy` 三个类型，`Policy` 加 `Lists` 字段 |
| `internal/config/defaults.go` | `Defaults()` 里 `Schedule` 改 `"03:30"`，`Lists` 两个 `automatic` 显式为 `false` |
| `configs/policy.yaml` | 手工维护的默认 policy，新增 `lists:` 组，`schedule` 改 `03:30` |
| `internal/unitfile/unitfile.go`（新） | `Render(policy) ([]byte, error)` —— 唯一的职责是把 policy 渲染成 timer unit 的字节 |
| `internal/unitfile/unitfile_test.go`（新） | 渲染结果、`OnCalendar` 与 policy 的一致性、非法 schedule 的拒绝 |
| `cmd/mosdns-cdnctl/render.go` | `documentPaths` 加 `Unit`/`UnitDir`，`pair()` 加第三个文档，`runRender` 在写完文档后写 unit 并 `daemon-reload` |
| `packaging/systemd/mosdns-list-check.timer` | **变成生成物**：内容是 `unitfile.Render(config.Defaults())` 的输出 |
| `packaging/systemd/mosdns-list-check.service` | `ExecStart` 改为 `update-lists --automatic` |
| `cmd/mosdns-cdnctl/update_lists.go` | 新增 `--automatic` 模式；`--pin-remote` 接受可选 commit；归档上一个 pin |
| `internal/rules/download.go` | 不改。`ResolveCommit` 已经是回退需要的入口 |
| `packaging/debian/postinst` | 不改（`daemon-reload` 由 `render` 做；postinst 已经 daemon-reload） |
| `scripts/build-deb.sh` | bwrap render 那一步之后，把渲染出的 unit 放进 staging 的 `/usr/lib/systemd/system` |
| `installer/tests/test_package.py` | 生成物清单加 unit；逐字节比对加 unit |
| `cmd/mosdns-cdnctl/update_lists_test.go` | `--automatic` 的四条路径、收缩护栏、归档新鲜度 |
| `packaging/man/mosdns-cdnctl.1` | `schedule` 与两个开关、`--automatic`、回退 |
| `packaging/man/mosdns-router.8` | 生成的 unit 与"改了 policy 要 render" |

---

### Task 1: policy 的两个开关与说真话的 schedule

**Files:**
- Modify: `internal/config/policy.go`（`Policy` 结构体在第 25-34 行；`Validate()` 在第 103 行附近）
- Modify: `internal/config/defaults.go:85`
- Modify: `configs/policy.yaml`
- Test: `internal/config/policy_test.go`

**Interfaces:**
- Consumes: 无
- Produces: `config.ListsPolicy{China ChinaListPolicy; Cloudflare CloudflareListPolicy}`、`config.ChinaListPolicy{Automatic bool}`、`config.CloudflareListPolicy{Automatic bool}`、`Policy.Lists ListsPolicy`（yaml 键 `lists`）。Task 6 读 `policy.Lists.China.Automatic` 与 `policy.Lists.Cloudflare.Automatic`；Task 2 读 `policy.Schedule`。

- [ ] **Step 1: 写失败的测试**

在 `internal/config/policy_test.go` 里加：

```go
func TestTheDefaultPolicyRefreshesNothing(t *testing.T) {
	policy := Defaults()
	if policy.Lists.China.Automatic {
		t.Error("china list automatic refresh is on by default; data/cn is curated and any " +
			"upstream commit moves the split, so this must be an operator's explicit choice")
	}
	if policy.Lists.Cloudflare.Automatic {
		t.Error("cloudflare range automatic refresh is on by default")
	}
}

// The two are separate switches because the two are not the same kind of risk.
// One switch would mean opening the low-risk action opens the high-risk one.
func TestTheTwoSwitchesAreIndependent(t *testing.T) {
	policy := Defaults()
	policy.Lists.Cloudflare.Automatic = true
	if policy.Lists.China.Automatic {
		t.Error("turning the cloudflare refresh on also turned the china one on")
	}
	policy = Defaults()
	policy.Lists.China.Automatic = true
	if policy.Lists.Cloudflare.Automatic {
		t.Error("turning the china refresh on also turned the cloudflare one on")
	}
}

// An absent lists: group decodes to both-off rather than failing, because that is
// the safe direction: a policy written before this field existed must keep working
// and must not start refreshing anything.
func TestAPolicyWithoutTheListsGroupLoads(t *testing.T) {
	path := writeTemp(t, "schema_version: 1\nschedule: \"03:30\"\n")
	policy, err := Load(path)
	if err != nil {
		t.Fatalf("a policy with no lists: group was refused: %v", err)
	}
	if policy.Lists.China.Automatic || policy.Lists.Cloudflare.Automatic {
		t.Errorf("a policy with no lists: group decoded to %+v, and zero must mean both off",
			policy.Lists)
	}
}

// 03:30, not 03:00: the field has been decorative and 03:30 is what was actually
// running, so the default states the truth rather than moving the machine.
func TestTheDefaultScheduleIsTheTimeThatWasRunning(t *testing.T) {
	if got := Defaults().Schedule; got != "03:30" {
		t.Errorf("default schedule is %q, want 03:30 -- the value the hardcoded timer "+
			"has been using, so making the field real does not also move the machine", got)
	}
}
```

若 `policy_test.go` 里没有 `writeTemp` 这个 helper，就用文件里已有的同类 helper 替换；本文件已有的临时文件写法就是本仓库的惯例。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /home/ubuntu/project_v2/.worktrees/mosdns-router && go test ./internal/config/ -run 'TestTheDefaultPolicy|TestTheTwoSwitches|TestAPolicyWithoutTheLists|TestTheDefaultSchedule' -v 2>&1 | tail -20`
Expected: 编译失败，`policy.Lists` undefined。

- [ ] **Step 3: 最小实现**

`internal/config/policy.go` —— 在 `Policy` 结构体里 `Schedule` 之后加一行：

```go
type Policy struct {
	SchemaVersion int           `yaml:"schema_version"`
	Schedule      string        `yaml:"schedule"`
	Lists         ListsPolicy   `yaml:"lists"`
	Foreign       ForeignPolicy `yaml:"foreign"`
```

并在 `ForeignCache` 字段之后加上三个类型：

```go
// ListsPolicy is whether this package refreshes the two documents it fetches from
// the internet on its own. It is two switches rather than one because the two are
// not the same kind of risk: Cloudflare's ranges choose which CDN edge an answer
// is rewritten to, while data/cn decides which names take the foreign branch at
// all, so bundling them means opening the cheap one opens the expensive one.
type ListsPolicy struct {
	China      ChinaListPolicy      `yaml:"china"`
	Cloudflare CloudflareListPolicy `yaml:"cloudflare"`
}

// ChinaListPolicy is unattended refresh of the pinned domain list. Off by default,
// and the reason is a fact about the upstream document rather than a preference:
// data/cn is curated by hand, so ANY commit to it moves the split, and accepting
// one unattended is a routing change nobody reviewed. The switch exists because an
// operator who has decided they want that trade can have it, not because it is a
// good default.
type ChinaListPolicy struct {
	Automatic bool `yaml:"automatic"`
}

// CloudflareListPolicy is unattended refresh of the published Cloudflare address
// ranges. Off by default for the same reason as every other fetch in this package:
// the snapshot is pinned so that a document this project did not review cannot
// change what the rewriter answers. The consequence of being wrong here is smaller
// than the China list's -- these ranges never decide which names take which branch,
// only which edge a rewritten answer points at.
type CloudflareListPolicy struct {
	Automatic bool `yaml:"automatic"`
}
```

`Validate()` **不需要**为 `lists` 加检查：两个字段都是 `bool`，零值即安全值，加一条"必须为 false"的检查会拒绝操作员想要的东西。

`internal/config/defaults.go` —— `Schedule: "03:00"` 改为 `Schedule: "03:30"`，并在其后加：

```go
		Lists: ListsPolicy{
			// Both false, and written out rather than left to the zero value so
			// that a reader of Defaults() can see the decision rather than infer it.
			China:      ChinaListPolicy{Automatic: false},
			Cloudflare: CloudflareListPolicy{Automatic: false},
		},
```

- [ ] **Step 4: 让手写的 configs/policy.yaml 与 Marshal 的输出一致**

`configs/policy.yaml` 是手工维护、由 `installer/tests/test_package.py` 逐字节比对着 `config.Marshal(config.Defaults())` 的。改两处：`schedule: "03:00"` → `schedule: "03:30"`；在 `schedule` 之后插入：

```yaml
lists:
  china:
    automatic: false
  cloudflare:
    automatic: false
```

然后跑比对测试确认一致（见 Step 5）。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/config/ 2>&1 | tail -5` → PASS
Run: `cd installer/tests && python3 -m unittest test_package.ControlTests 2>&1 | tail -3` → 若报 `policy.yaml` 不一致，按它打印的实际内容把文件改成 Marshal 的输出形状（字段顺序由结构体顺序决定：`schema_version`、`schedule`、`lists`、`foreign`…）。

- [ ] **Step 6: 变异验证默认值门禁真的会红**

```bash
cp internal/config/defaults.go /tmp/opencode/defaults.bak
sed -i 's/China:      ChinaListPolicy{Automatic: false}/China:      ChinaListPolicy{Automatic: true}/' internal/config/defaults.go
cd internal/config && go test . -run TestTheDefaultPolicyRefreshesNothing 2>&1 | tail -3
```
Expected: FAIL，并打印"china list automatic refresh is on by default"。
然后 `cp /tmp/opencode/defaults.bak internal/config/defaults.go` 还原，并确认 `go test . 2>&1 | tail -2` 回到 `ok`。

- [ ] **Step 7: 提交**

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
git add internal/config/ configs/policy.yaml
git commit -m "feat(config): two switches for the list work, and a schedule that is true

policy.yaml gains lists.china.automatic and lists.cloudflare.automatic, both false.
Two rather than one because they are not the same kind of risk: Cloudflare's ranges
choose which CDN edge an answer is rewritten to, data/cn decides which names take
the foreign branch at all.

schedule moves from 03:00 to 03:30. The field has been decorative --
internal/config/policy.go validated it as HH:MM and nothing read it, while the timer
that actually decides carried a hardcoded OnCalendar of 03:30. Making it real is
Task 2; until then the default states what was running rather than moving the
machine half an hour earlier."
```

---

### Task 2: 把 schedule 渲染成 systemd timer

**Files:**
- Create: `internal/unitfile/unitfile.go`
- Create: `internal/unitfile/unitfile_test.go`
- Modify: `packaging/systemd/mosdns-list-check.timer`（变成生成物）

**Interfaces:**
- Consumes: `config.Policy.Schedule`（string，`"HH:MM"`，已由 `config.Validate()` 校验）
- Produces: `unitfile.UnitName`（常量 `"mosdns-list-check.timer"`）、`unitfile.Render(policy config.Policy) ([]byte, error)`。Task 3 用 `unitfile.UnitName` 决定写哪个文件；Task 4 用 `unitfile.Render` 产出提交产物。

- [ ] **Step 1: 写失败的测试**

`internal/unitfile/unitfile_test.go`：

```go
package unitfile

import (
	"strings"
	"testing"

	"mosdns-router/internal/config"
)

// The whole point of the file: what the policy says is what systemd reads.
func TestRenderPutsThePolicyScheduleIntoOnCalendar(t *testing.T) {
	policy := config.Defaults()
	policy.Schedule = "05:15"
	unit, err := Render(policy)
	if err != nil {
		t.Fatalf("Render refused a valid schedule: %v", err)
	}
	if !strings.Contains(string(unit), "OnCalendar=*-*-* 05:15:00") {
		t.Errorf("the rendered unit does not carry the policy's 05:15:\n%s", unit)
	}
	if strings.Contains(string(unit), "03:30") {
		t.Errorf("the rendered unit still carries a hardcoded 03:30:\n%s", unit)
	}
}

// A policy that does not validate is refused here rather than rendered into a unit
// systemd will reject at reload with a message that names neither the policy nor
// the field.
func TestRenderRefusesAScheduleThatIsNotATime(t *testing.T) {
	policy := config.Defaults()
	policy.Schedule = "5am"
	if _, err := Render(policy); err == nil {
		t.Fatal("Render accepted a schedule that is not HH:MM")
	} else if !strings.Contains(err.Error(), "schedule") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

// The description says what the unit does in BOTH configurations. With both
// switches off it checks; with them on it also refreshes, and a description that
// says "drift check" understates what it did on the day it refreshed something.
func TestTheDescriptionIsTrueWithEitherSwitchSet(t *testing.T) {
	for name, mutate := range map[string]func(*config.Policy){
		"default":  func(*config.Policy) {},
		"china on": func(p *config.Policy) { p.Lists.China.Automatic = true },
		"both on": func(p *config.Policy) {
			p.Lists.China.Automatic = true
			p.Lists.Cloudflare.Automatic = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := config.Defaults()
			mutate(&policy)
			unit, err := Render(policy)
			if err != nil {
				t.Fatalf("Render refused: %v", err)
			}
			if !strings.Contains(string(unit), "Description=Daily list work: drift check and, if the policy says so, refresh") {
				t.Errorf("the description does not describe both jobs:\n%s", unit)
			}
		})
	}
}

// The header is how a person reading the installed file knows it is generated, and
// the two routing documents already do this. A generated unit without one reads as
// a hand-maintained one and gets edited directly, and the next render overwrites it.
func TestTheUnitSaysItIsGenerated(t *testing.T) {
	unit, err := Render(config.Defaults())
	if err != nil {
		t.Fatalf("Render refused: %v", err)
	}
	for _, want := range []string{
		"Generated by internal/unitfile.Render",
		"/etc/mosdns/policy.yaml",
		"daemon-reload",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("the header does not mention %q:\n%s", want, unit)
		}
	}
}

// The directives systemd needs, unchanged. A renderer that dropped Persistent=true
// would lose the catch-up run after a machine was off overnight, and the old file's
// comment explained why that matters for a report nobody is shown.
func TestTheUnitsDirectivesAreCarriedOver(t *testing.T) {
	unit, err := Render(config.Defaults())
	if err != nil {
		t.Fatalf("Render refused: %v", err)
	}
	for _, want := range []string{
		"Persistent=true",
		"Unit=mosdns-list-check.service",
		"[Install]",
		"WantedBy=timers.target",
		"Documentation=man:mosdns-cdnctl(1)",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("the rendered unit lost %q:\n%s", want, unit)
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/unitfile/ 2>&1 | tail -5`
Expected: 编译失败，`no Go files in .../internal/unitfile`。

- [ ] **Step 3: 最小实现**

`internal/unitfile/unitfile.go`：

```go
// Package unitfile renders the systemd units whose contents this project derives
// from the policy.
//
// It exists because `policy.yaml` carried a `schedule` field that nothing read:
// internal/config validated it as HH:MM and the timer that actually decided when
// the list work ran carried a hardcoded OnCalendar. An operator who changed the
// policy got no change at all. A field that is silently ignored is worse than no
// field, because the file says the machine's schedule is in it.
//
// ONE responsibility: the policy in, the unit's bytes out. It does not install,
// reload, or decide whether the unit should exist.
package unitfile

import (
	"fmt"

	"mosdns-router/internal/config"
)

// UnitName is the unit Render produces. It is the file name in the installed
// systemd directory, and the render verb writes exactly this.
const UnitName = "mosdns-list-check.timer"

// header says where the file came from, so a unit an operator is reading is not
// mistaken for one they may edit. It is a comment; systemd ignores it, and the
// renderer does not read its own output.
const header = `# The daily list work schedule.
#
# Generated by internal/unitfile.Render from the policy at /etc/mosdns/policy.yaml.
# Edit the policy, not this file: "mosdns-cdnctl render" rewrites this file and
# then reloads systemd, and a hand edit here is lost at the next render.
#
# ` + "`schedule`" + ` in the policy is the only place this machine's list work is
# timed, and the OnCalendar below is generated from it. systemd reads the unit
# that is installed, not the policy, so a changed schedule takes effect after
# "mosdns-cdnctl render" -- which reloads systemd as part of writing it, so there
# is no separate daemon-reload to forget.
#
# Persistent, and for the same reason as before: a machine that was off at the
# scheduled minute produces the run at next boot, and a report nobody will ever be
# shown is not a report. One catch-up run, once.
`

// Render returns the bytes of UnitName for this policy.
func Render(policy config.Policy) ([]byte, error) {
	if !valid(policy.Schedule) {
		// config.Validate() already refuses this, so reaching here means the
		// caller built a Policy without validating it. Refusing is still right:
		// the alternative is a unit systemd rejects at reload with a message that
		// names neither the policy nor the field.
		return nil, fmt.Errorf("unitfile: policy.schedule %q is not a valid HH:MM time", policy.Schedule)
	}
	unit := header +
		"[Unit]\n" +
		"Description=Daily list work: drift check and, if the policy says so, refresh\n" +
		"Documentation=man:mosdns-cdnctl(1)\n" +
		"\n" +
		"[Timer]\n" +
		"OnCalendar=*-*-* " + policy.Schedule + ":00\n" +
		"Persistent=true\n" +
		"Unit=mosdns-list-check.service\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=timers.target\n"
	return []byte(unit), nil
}

// valid is config's own HH:MM rule. It is repeated rather than exported from
// internal/config because that package's validator is about a whole policy and
// this one is about one field of one value, and a policy reaching Render has
// already been through it.
func valid(value string) bool {
	if len(value) != len("HH:MM") || value[2] != ':' {
		return false
	}
	for _, index := range []int{0, 1, 3, 4} {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	hour := int(value[0]-'0')*10 + int(value[1]-'0')
	minute := int(value[3]-'0')*10 + int(value[4]-'0')
	return hour <= 23 && minute <= 59
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/unitfile/ -v 2>&1 | tail -20` → 5 个测试全 PASS。

- [ ] **Step 5: 把 packaging 里的 unit 换成渲染结果**

写出仓库里的提交产物。用一个一次性程序（不进仓库）：

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
mkdir -p /tmp/opencode/genunit && cat > /tmp/opencode/genunit/main.go <<'GO'
package main

import (
	"os"

	"mosdns-router/internal/config"
	"mosdns-router/internal/unitfile"
)

func main() {
	unit, err := unitfile.Render(config.Defaults())
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("packaging/systemd/mosdns-list-check.timer", unit, 0o644); err != nil {
		panic(err)
	}
}
GO
cp /tmp/opencode/genunit/main.go ./genunit_tmp.go 2>/dev/null || true
mkdir -p ./internal/genunit_tmp && mv ./genunit_tmp.go ./internal/genunit_tmp/main.go
go run ./internal/genunit_tmp
rm -rf ./internal/genunit_tmp
cat packaging/systemd/mosdns-list-check.timer
```
Expected: 文件里有 `OnCalendar=*-*-* 03:30:00`、`Description=Daily list work: drift check and, if the policy says so, refresh`，以及生成头注释。

- [ ] **Step 6: 变异验证比对门禁会红**

Task 4 才加比对测试，所以这里手工验一次"渲染器说了算"：

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
sed -i 's/^OnCalendar=.*/OnCalendar=*-*-* 04:00:00/' packaging/systemd/mosdns-list-check.timer
mkdir -p ./internal/genunit_tmp && cp /tmp/opencode/genunit/main.go ./internal/genunit_tmp/main.go
go run ./internal/genunit_tmp && rm -rf ./internal/genunit_tmp
git diff --stat packaging/systemd/mosdns-list-check.timer   # 应当无差异：渲染器把手改的 04:00 覆盖回 03:30
```
Expected: `git diff` 无输出。这就是 Task 4 要固化成测试的那件事。

- [ ] **Step 7: 提交**

```bash
git add internal/unitfile/ packaging/systemd/mosdns-list-check.timer
git commit -m "feat(unitfile): render the list timer from the policy's schedule

policy.yaml carried a schedule field that nothing read: internal/config validated it
as HH:MM and the timer that actually decided carried a hardcoded OnCalendar of
03:30. An operator who changed the policy got no change at all, and a field that is
silently ignored is worse than no field because the file claims the machine's
schedule is in it.

mosdns-list-check.timer is now the output of unitfile.Render over the policy, with
the same contract the two routing documents have: a committed copy, a byte-for-byte
test, and a render that rewrites the installed one. The header says so, and says
that render reloads systemd as part of writing it, because a changed schedule that
needs a separate daemon-reload is a changed schedule an operator will conclude did
not work.

The Description changes from 'Daily China list drift check schedule' to name both
jobs. With the switches off it checks; with them on it also refreshes, and a
description that says 'drift check' understates what it did on the day it replaced a
pinned list."
```

---

### Task 3: render 写 unit 并 reload systemd

**Files:**
- Modify: `cmd/mosdns-cdnctl/render.go`（`documentPaths` 在第 60-71 行；`pair()` 在第 180 行；`runRender` 在第 110 行）
- Test: `cmd/mosdns-cdnctl/render_test.go`

**Interfaces:**
- Consumes: `unitfile.Render(policy config.Policy) ([]byte, error)`、`unitfile.UnitName`
- Produces: `documentPaths.Unit string`（unit 的文件名，默认 `unitfile.UnitName`）、`documentPaths.UnitDir string`（默认 `"/usr/lib/systemd/system"`）；`services` 上新增 `reloadSystemd func() error`（生产实现跑 `systemctl daemon-reload`，测试注入记录器）。Task 6 不依赖本任务。

- [ ] **Step 1: 写失败的测试**

`cmd/mosdns-cdnctl/render_test.go` 加：

```go
func TestRenderWritesTheUnitBesideTheDocuments(t *testing.T) {
	root := t.TempDir()
	policy := writePolicy(t, root, "schema_version: 1\nschedule: \"05:15\"\n")
	fixture := newRenderFixture(t, root)

	code := fixture.run("render", "--policy", policy, "--out", root+"/etc")

	if code != exitSuccess {
		t.Fatalf("render exited %d", code)
	}
	unit, err := os.ReadFile(filepath.Join(root, "usr/lib/systemd/system", "mosdns-list-check.timer"))
	if err != nil {
		t.Fatalf("render published no unit: %v", err)
	}
	if !strings.Contains(string(unit), "OnCalendar=*-*-* 05:15:00") {
		t.Errorf("the published unit does not carry the policy's schedule:\n%s", unit)
	}
}

// A changed schedule that systemd has not been told about is the exact symptom
// this whole change exists to remove: the operator edited the policy, render
// succeeded, and nothing moved.
func TestRenderReloadsSystemdAfterWritingTheUnit(t *testing.T) {
	root := t.TempDir()
	policy := writePolicy(t, root, "schema_version: 1\nschedule: \"05:15\"\n")
	fixture := newRenderFixture(t, root)

	if code := fixture.run("render", "--policy", policy, "--out", root+"/etc"); code != exitSuccess {
		t.Fatalf("render exited %d", code)
	}
	if !fixture.reloaded {
		t.Error("render wrote the unit and did not reload systemd, so systemd keeps the " +
			"old OnCalendar until reboot")
	}
}

// A reload that fails is reported, and it is reported AFTER the documents were
// written rather than instead of them: the documents are correct on disk and
// refusing to say so would send an operator looking for a failure that is not there.
func TestAReloadFailureIsReportedAndNamesWhatItIs(t *testing.T) {
	root := t.TempDir()
	policy := writePolicy(t, root, "schema_version: 1\nschedule: \"05:15\"\n")
	fixture := newRenderFixture(t, root)
	fixture.reloadErr = errors.New("daemon-reload refused")

	stderr := fixture.stderr.String()
	if !strings.Contains(stderr, "daemon-reload") {
		t.Errorf("the report does not say the reload is what failed: %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/mosdns/mosdns.yaml")); err != nil {
		t.Errorf("the documents were not written even though only the reload failed: %v", err)
	}
}

// A failure to WRITE the unit is a render failure. A unit left describing the old
// schedule while the policy says a new one is the two-sources problem again, and
// the operation has to stop rather than report success.
func TestAUnitThatCannotBeWrittenIsARefusal(t *testing.T) {
	root := t.TempDir()
	policy := writePolicy(t, root, "schema_version: 1\nschedule: \"05:15\"\n")
	fixture := newRenderFixture(t, root)
	// A file where the systemd directory needs to be: the write cannot succeed.
	if err := os.WriteFile(filepath.Join(root, "usr/lib/systemd/system"), []byte("x"), 0o644); err != nil {
		t.Skipf("cannot stage the failure: %v", err)
	}

	if code := fixture.run("render", "--policy", policy, "--out", root+"/etc"); code == exitSuccess {
		t.Error("render reported success with the unit unwritable")
	}
}
```

沿用本文件已有的 fixture 习惯（`newRenderFixture` / `writePolicy` 用文件里既有的同型 helper 名字替换；实现时按该文件现有写法补齐）。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./cmd/mosdns-cdnctl/ -run 'TestRender.*Unit|TestRenderReloads|TestAReloadFailure' 2>&1 | tail -10`
Expected: FAIL —— unit 没被写、`fixture.reloaded` 不存在。

- [ ] **Step 3: 最小实现**

`cmd/mosdns-cdnctl/render.go`：

`documentPaths` 加两个字段并给出生产默认值：

```go
type documentPaths struct {
	Dir      string
	Policy   string
	Mosdns   string
	DNSCrypt string
	// Unit and UnitDir are where the generated systemd unit is published. The
	// unit is not beside the documents because systemd does not read it from
	// /etc/mosdns: a policy that renders a unit to the wrong directory produces
	// a machine whose policy and whose schedule disagree, and the disagreement is
	// invisible until the timer fires at the old time.
	Unit    string
	UnitDir string
	Routing mosdnsconfig.Paths
}
```

`productionDocumentPaths()` 里加：

```go
		Unit:     unitfile.UnitName,
		UnitDir:  "/usr/lib/systemd/system",
```

`pair()` 的 `rendered` 切片加第三项，渲染它：

```go
	rendered := documentPair{
		{Report: "mosdns", Name: documents.Mosdns},
		{Report: "dnscrypt", Name: documents.DNSCrypt},
		{Report: "unit", Name: documents.Unit},
	}
	...
	if rendered[2].Contents, rendered[2].Err = unitfile.Render(policy); rendered[2].Err != nil {
		rendered[2].Err = fmt.Errorf("%s: %w", documents.Unit, rendered[2].Err)
	}
	return rendered
```

`runRender` 在 `publishPairWithOps` 之后、写报告之前，加 unit 的发布与 reload：

```go
	unitPath := filepath.Join(documents.UnitDir, documents.Unit)
	if err := services.writeUnit(unitPath, documents[2].Contents); err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitStateUnavailable
	}
	// Reloaded as part of writing it. A schedule the operator changed and did not
	// get is the symptom this change exists to remove, so the reload is part of the
	// operation rather than a step to remember. Its failure is reported AFTER the
	// documents were written, because they are correct and saying otherwise would
	// send an operator looking for a failure that is not there.
	if err := services.reloadSystemd(); err != nil {
		writeCLIError(stderr, "render: %s wrote and reloaded nothing: %v", unitPath, err)
	}
```

注意：`documents` 变量名在这个文件里已经被 `pair()` 的返回值占用（`documents := pair(...)`），所以 unit 的索引要用一个不冲突的名字。把上面代码里的 `documents[2]` 改成从 `pair` 的返回值取，例如：

```go
	rendered := pair(policy, services.documents, options.policy)
	if err := refuseUnrenderable(rendered); err != nil { /* 已有 */ }
	...
	unitPath := filepath.Join(services.documents.UnitDir, services.documents.Unit)
	if err := services.writeUnit(unitPath, rendered[2].Contents); err != nil { /* ... */ }
```

`services` 上加两个字段与生产实现：

```go
	// writeUnit publishes the generated unit. It is separate from the document
	// publisher because the two write to different directories with different
	// consequences: a document that cannot be written stops the render, and a unit
	// that cannot be written must too.
	writeUnit func(path string, contents []byte) error
	// reloadSystemd makes systemd re-read its units. It runs after the unit is
	// written, so a changed schedule takes effect in the same operation that
	// changed it.
	reloadSystemd func() error
```

生产实现（放在 `productionServicesWith` 附近）：

```go
		writeUnit: func(path string, contents []byte) error {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			return os.WriteFile(path, contents, 0o644)
		},
		reloadSystemd: func() error {
			completed := _ok(run, ("systemctl", "daemon-reload"))
			if completed == nil {
				return errors.New("systemctl daemon-reload could not be run")
			}
			if completed.Stderr != "" {
				return errors.New(strings.TrimSpace(completed.Stderr))
			}
			return nil
		},
```

若 `services` 里没有可用的 `run`，用该结构里已有的命令执行器（`_ok` 或等价物）。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./cmd/mosdns-cdnctl/ 2>&1 | tail -5` → 全 PASS。

- [ ] **Step 5: 变异验证 reload 门禁真的会红**

```bash
cp cmd/mosdns-cdnctl/render.go /tmp/opencode/render.bak
python3 - <<'PY'
from pathlib import Path
p = Path('cmd/mosdns-cdnctl/render.go'); t = p.read_text()
t = t.replace("\tif err := services.reloadSystemd(); err != nil {", "\tif err := error(nil); err != nil && false {", 1)
p.write_text(t)
PY
go test ./cmd/mosdns-cdnctl/ -run TestRenderReloads 2>&1 | tail -4
```
Expected: FAIL —— "render wrote the unit and did not reload systemd"。
然后 `cp /tmp/opencode/render.bak cmd/mosdns-cdnctl/render.go` 还原。

- [ ] **Step 6: 提交**

```bash
git add cmd/mosdns-cdnctl/render.go cmd/mosdns-cdnctl/render_test.go
git commit -m "feat(cdnctl): render writes the unit and reloads systemd

render now publishes the generated timer beside the routing documents and reloads
systemd as part of writing it. The reload is inside the operation rather than a step
to remember because a schedule the operator changed and did not get is the exact
symptom the previous hardcoded OnCalendar produced.

The unit is not published into /etc/mosdns with the documents: systemd does not read
it from there, and a policy that renders a unit to the wrong directory produces a
machine whose policy and whose schedule disagree, invisibly, until the timer fires at
the old time.

A unit that cannot be written is a refusal rather than a warning, for the same
reason -- a stale unit and a changed policy is two sources for one fact. A reload
that fails is reported after the documents are written rather than instead of them,
because they are correct on disk and saying otherwise would send an operator looking
for a failure that is not there."
```

---

### Task 4: 让包里带上渲染后的 unit

**Files:**
- Modify: `scripts/build-deb.sh`（bwrap render 那一步在第 415-432 行；`configs/` 的 place 清单里加 unit）
- Modify: `installer/tests/test_package.py`（`GENERATED` 在第 218 行；逐字节比对在第 3643 行附近）
- Test: 同上

**Interfaces:**
- Consumes: `unitfile.Render`、`unitfile.UnitName`、`configs/mosdns-list-check.timer`
- Produces: 无新接口。包内 `/usr/lib/systemd/system/mosdns-list-check.timer` 的内容等于 `unitfile.Render(config.Defaults())`。

- [ ] **Step 1: 写失败的测试**

`installer/tests/test_package.py` 的生成物集合里加入 unit：

```python
    SYSTEMD_UNIT_DIRECTORY + "/" + LIST_TIMER_NAME,
```

并在 `test_the_shipped_documents_are_the_ones_this_repository_reviewed` 的元组里加入：

```python
            (SYSTEMD_UNIT_DIRECTORY + "/" + LIST_TIMER_NAME, "configs/mosdns-list-check.timer"),
```

再加一条独立门禁，理由是这条正是 Review Focus 第 4 类：

```python
    def test_the_packaged_timer_is_the_one_this_policy_renders(self):
        """The staged render writes `--out /etc/mosdns`, and the unit belongs in
        /usr/lib/systemd/system. A build that shipped the repository's copy
        unchanged would package a unit describing whatever schedule the repository
        last had, and nothing in the package would notice: the documents are
        compared, the unit is not, and a stale unit is a machine that runs the list
        work at the wrong hour with a policy that says otherwise.
        """
        shipped = self.read(SYSTEMD_UNIT_DIRECTORY + "/" + LIST_TIMER_NAME)
        committed = (REPO / "packaging" / "systemd" / LIST_TIMER_NAME).read_text()
        self.assertEqual(
            shipped, committed,
            "the packaged timer is not the repository's copy, so the build rendered it "
            "for a different policy than the one this repository reviewed",
        )
        policy = _SHARED["policy"]  # 本文件已有的默认 policy 载入方式
        self.assertIn(f"OnCalendar=*-*-* {policy.schedule}:00", shipped)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd installer/tests && python3 -m unittest test_package.PayloadTests 2>&1 | tail -6`
Expected: FAIL —— 包内没有这个 unit，或内容与仓库副本不同。

- [ ] **Step 3: 让 build-deb.sh 渲染并安装它**

`scripts/build-deb.sh`，在 bwrap render 那一步之后（`chmod 644` 那两行附近）加：

```sh
# The unit is rendered rather than copied, and it is the sixth generated artifact.
# `render --out` publishes the two documents into the staging /etc; the unit belongs
# in /usr/lib/systemd/system, where systemd reads it, so it is written there from
# the same render's output rather than copied from packaging/. A copy would package
# whatever schedule the repository last had, and the package-content test would be
# comparing a document against a stale unit.
unit_dir="$STAGE/usr/lib/systemd/system"
mkdir -p "$unit_dir"
"$verifier_dir/mosdns-cdnctl" render-unit \
	--policy /etc/mosdns/policy.yaml --out "$unit_dir" 2>/dev/null ||
	"$verifier_dir/mosdns-cdnctl" render \
	--policy /etc/mosdns/policy.yaml --out /etc/mosdns >/dev/null
```

实现时注意：`render` 已经在上面跑过一次并写好了 unit（Task 3 让它写 `/usr/lib/systemd/system`，而 bwrap 把 `$STAGE/etc` 绑到 `/etc`）。**最简做法**：让 bwrap 那一次 render 就把 unit 写进 staging 的 `/usr/lib/systemd/system`——为此给 `render` 加一个 `--unit-out` 参数，而不是新增一个动词：

```sh
if ! "$BWRAP" --ro-bind / / --bind "$STAGE/etc" /etc --chdir / \
	--bind "$STAGE/usr" /usr \
	"$verifier_dir/mosdns-cdnctl" render \
	--policy /etc/mosdns/policy.yaml --out /etc/mosdns \
	--unit-out /usr/lib/systemd/system >"$render_log" 2>&1; then
```

并在 `parseRenderOptions` 里加 `--unit-out`（默认 `documents.UnitDir`），在 `runRender` 里用它取代 `documents.UnitDir`。**这是 Task 3 的一个后续修改**，所以把它做进本任务，并相应在 Task 3 的 `documentPaths` 里保留 `UnitDir` 作为默认值来源。

改完后 `scripts/build-deb.sh` 里那句 `chmod 644` 加上 unit：

```sh
chmod 644 "$STAGE/etc/mosdns/mosdns.yaml" "$STAGE/etc/mosdns/dnscrypt-proxy.toml" \
	"$STAGE/usr/lib/systemd/system/mosdns-list-check.timer"
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd installer/tests && python3 -m unittest test_package.PayloadTests test_package.ControlTests 2>&1 | tail -4`
Expected: PASS。

- [ ] **Step 5: 变异验证这条门禁真的会红**

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
cp packaging/systemd/mosdns-list-check.timer /tmp/opencode/timer.bak
sed -i 's/^OnCalendar=.*/OnCalendar=*-*-* 04:00:00/' packaging/systemd/mosdns-list-check.timer
cd installer/tests && python3 -m unittest test_package.PayloadTests 2>&1 | grep -E 'AssertionError|FAIL' | head -3
```
Expected: FAIL，并提到 packaged timer / 逐字节差异。
然后 `cp /tmp/opencode/timer.bak packaging/systemd/mosdns-list-check.timer` 还原。

- [ ] **Step 6: 本地构建一次并核对**

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
export PATH=/tmp/opencode/go1.25.8/bin:$PATH GOCACHE=$PWD/.gocache-review GOTMPDIR=/home/ubuntu/.gotmp-mosdns TMPDIR=/home/ubuntu/.gotmp-mosdns
sh scripts/build-deb.sh 2>&1 | tail -3
make verify-package 2>&1 | tail -2
dpkg-deb --ctrl-tarfile build/mosdns-router_0.2.1_amd64.deb >/dev/null && \
  dpkg-deb --fsys-tarfile build/mosdns-router_0.2.1_amd64.deb | tar -xO ./usr/lib/systemd/system/mosdns-list-check.timer | grep OnCalendar
```
Expected: `OnCalendar=*-*-* 03:30:00`。

- [ ] **Step 7: 提交**

```bash
git add scripts/build-deb.sh installer/tests/test_package.py
git commit -m "build: render the unit into the package instead of copying it

The staging render runs under bwrap with the staging /etc bound over /etc, so the
two documents come out for the installed layout. The unit was not part of that: the
build copied packaging/systemd/mosdns-list-check.timer, which meant the package
shipped whatever schedule the repository last had rather than the one its own policy
says. Nothing noticed, because the documents were compared and the unit was not.

So render grows a --unit-out, the build binds the staging /usr so the unit lands in
/usr/lib/systemd/system where systemd reads it, and two gates hold it: the
committed file is the render's output, and the packaged file is the committed one."
```

---

### Task 5: 回退 —— 归档上一个 pin，`--pin-remote` 接受 commit

**Files:**
- Modify: `cmd/mosdns-cdnctl/update_lists.go`（`updateListOptions` 第 224 行附近；`parseUpdateListOptions` 第 261 行；`runPinRemote` 第 543 行）
- Test: `cmd/mosdns-cdnctl/update_lists_test.go`

**Interfaces:**
- Consumes: `rules.ResolveCommit(ctx, client, repository) (rules.SourceLock, error)`（已存在，`internal/rules/download.go:144`）、`rules.Download`、`rules.Publish`、`rules.ReadPublishedPair`
- Produces: `updateListOptions.pinRemote string`（语义扩展：无参/`HEAD` = 上游当前；任意 40 位十六进制 = 该 commit）、`updateListOptions.previousLock string`（新 flag `--previous-lock`，默认 `/var/lib/mosdns/lists/source-lock.previous.json`）、`rules.Archive(previousLockPath, currentLockPath string) error`、`rules.ReadPrevious(previousLockPath string) (rules.SourceLock, error)`。Task 6 用 `--previous-lock`。

- [ ] **Step 1: 写失败的测试**

`cmd/mosdns-cdnctl/update_lists_test.go` 加：

```go
// The whole reason the archive exists: a pin that was accepted has to be
// reachable again, and --pin-remote can only name upstream's current HEAD, so
// without an archive there is no way back from a commit nobody reviewed.
func TestPinRemoteNamesTheCommitItWillPublish(t *testing.T) {
	services, released := pinFixture(t, "a5731758ed6bc9620b0e146ed24b07b9131893cf")
	defer released()

	options := parseFor(t, services, "--pin-remote", "1111111111111111111111111111111111111111")
	if options.pinRemote != "1111111111111111111111111111111111111111" {
		t.Fatalf("--pin-remote did not keep the commit: %q", options.pinRemote)
	}
}

// HEAD is still HEAD. The refusal that would break today's documented invocation
// is the point of keeping the no-argument form working.
func TestPinRemoteStillAcceptsTheLiteralHEAD(t *testing.T) {
	services, _ := pinFixture(t, "a5731758ed6bc9620b0e146ed24b07b9131893cf")
	options := parseFor(t, services, "--pin-remote", "HEAD")
	if options.pinRemote != "" {
		t.Fatalf("the literal HEAD is no longer accepted: %q", options.pinRemote)
	}
}

// An argument that is neither HEAD nor a commit is refused at the command line,
// not after a network round trip.
func TestPinRemoteRefusesSomethingThatIsNotACommit(t *testing.T) {
	services, _ := pinFixture(t, "a5731758ed6bc9620b0e146ed24b07b9131893cf")
	for _, ref := range []string{"main", "v0.2.0", "HEAD~1", "zzzzzzzz", ""} {
		t.Run(ref, func(t *testing.T) {
			if _, err := parseUpdateListOptions(io.Discard, []string{"--pin-remote", ref}); err == nil {
				t.Errorf("--pin-remote accepted %q, which is neither HEAD nor a commit", ref)
			}
		})
	}
}

// Review Focus, class 2: the archive must name the pin that was current when this
// run started, not one left behind by an earlier run. A stale archive is worse than
// none, because the operator believes they are rolling back to a commit they chose
// and lands on a different one.
func TestPublishingArchivesThePinThatWasCurrent(t *testing.T) {
	services, released := pinFixture(t, "a5731758ed6bc9620b0e146ed24b07b9131893cf")
	defer released()
	stale := "2222222222222222222222222222222222222222"
	writeSourceLock(t, services.previousLockPath, stale)

	if code := runPinRemoteForTest(t, services, "HEAD"); code != exitSuccess {
		t.Fatalf("pin exited %d", code)
	}
	archived, err := rules.ReadPrevious(services.previousLockPath)
	if err != nil {
		t.Fatalf("no archive after a successful publish: %v", err)
	}
	if archived.Commit == stale {
		t.Errorf("the archive is the stale %s, so a rollback would land on a commit "+
			"the operator did not choose", stale)
	}
}

// The archive is written before the publish and replaced by it, so a publish that
// fails leaves the archive naming a commit that WAS current -- which is exactly
// what an operator rolling back after a failed auto-update wants.
func TestAFailedPublishLeavesBothThePinAndTheArchiveIntact(t *testing.T) {
	services, released := pinFixture(t, "a5731758ed6bc9620b0e146ed24b07b9131893cf")
	defer released()
	before, err := rules.ReadPublishedPair(services.sourceLockPath, services.listPath)
	if err != nil {
		t.Fatal(err)
	}
	services.failPublish = true

	if code := runPinRemoteForTest(t, services, "HEAD"); code == exitSuccess {
		t.Fatal("pin reported success with the publish failing")
	}
	after, err := rules.ReadPublishedPair(services.sourceLockPath, services.listPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Commit != before.Commit {
		t.Errorf("a failed publish changed the pin from %s to %s", before.Commit, after.Commit)
	}
}
```

`pinFixture` / `parseFor` / `runPinRemoteForTest` / `writeSourceLock` 用本文件既有的 fixture 形状实现（该文件已有 `newUpdateListFixture` 一类的构造器，沿用它）。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./cmd/mosdns-cdnctl/ -run 'TestPinRemote|TestPublishingArchives|TestAFailedPublish' 2>&1 | tail -10`
Expected: FAIL —— `--pin-remote <commit>` 被拒、`rules.ReadPrevious` 不存在。

- [ ] **Step 3: 最小实现 —— rules 包的归档与回读**

`internal/rules/download.go` 加：

```go
// Archive copies the current published lock to previousLockPath. It is written
// BEFORE a publish and replaced by it, so a publish that fails leaves the archive
// naming a commit that really was current -- which is what an operator rolling
// back after a failed unattended refresh needs, and a stale archive taken from an
// earlier run would not be.
func Archive(previousLockPath, currentLockPath string) error {
	current, err := ParseSourceLock(mustRead(currentLockPath))
	if err != nil {
		return err
	}
	encoded, err := current.Encode()
	if err != nil {
		return err
	}
	return writeFileAtomically(previousLockPath, encoded, 0o640)
}

// ReadPrevious reads the archived pin. It is the rollback's input, so a missing or
// unreadable archive is an error rather than an empty lock: `--pin-remote <commit>`
// does not need it, and pretending it is there would send an operator to a commit
// this machine never had.
func ReadPrevious(previousLockPath string) (SourceLock, error) {
	encoded, err := os.ReadFile(previousLockPath)
	if err != nil {
		return SourceLock{}, fmt.Errorf("rules: read the archived pin: %w", err)
	}
	return ParseSourceLock(encoded)
}
```

`mustRead` / `writeFileAtomically` 用该包已有的等价物（`publish.go` 里已经有同类的原子写，`Download` 一带已有读文件）；实现时复用它们，不要新写第二套。

- [ ] **Step 4: 最小实现 —— 命令行**

`parseUpdateListOptions`：`--pin-remote` 改用 `flags.String`（已经是 string），校验加：

```go
	if ref := strings.TrimSpace(*pinRemote); ref != "" && ref != "HEAD" {
		if !isFullCommit(ref) {
			return updateListOptions{}, fmt.Errorf("--pin-remote takes HEAD or a full 40-character commit, not %q", ref)
		}
	}
```

（`--pin-remote HEAD` 归一成空字符串，`runPinRemote` 现有的"空即 HEAD"路径不变。）

加：

```go
func isFullCommit(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, r := range ref {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
```

新 flag：

```go
	previousLock := flags.String("previous-lock", defaultPreviousLockPath,
		"path the outgoing pin is archived to, so a pin accepted by mistake can be published again")
```

`updateListOptions` 加字段 `previousLock string`，默认值常量：

```go
// defaultPreviousLockPath sits beside the lock it archives, because the two are
// one fact in two states and a previous pin stored somewhere else is a previous pin
// nobody finds.
const defaultPreviousLockPath = "/var/lib/mosdns/lists/source-lock.previous.json"
```

`runPinRemote` 的两处改动 —— 解析目标、以及在取锁之后发布之前归档：

```go
	// HEAD resolves to the default branch's current commit; an explicit commit
	// resolves to itself. Nothing else is accepted, and the command line has already
	// refused the rest.
	var resolved rules.SourceLock
	if options.pinRemote == "" {
		resolved, err = rules.ResolveHEAD(ctx, client, rules.Repository)
	} else {
		resolved, err = rules.ResolveCommit(ctx, client, rules.Repository, options.pinRemote)
	}
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
```

（若 `rules.ResolveCommit` 当前不接受 ref 参数，见 `internal/rules/download.go:144` 的签名，需要给它加一个 `ref string` 参数并用它构造查询 —— 该函数当前只解析 default branch 的 HEAD。）

归档放在 `ReadPublishedPair` 成功之后、`Publish` 之前：

```go
	// Archived before the publish, not after: a publish that fails must leave an
	// archive naming a commit that really was current, because that is the one an
	// operator rolling back after a failed unattended refresh needs.
	if err := rules.Archive(options.previousLock, options.sourceLock); err != nil {
		writeCLIError(stderr, "update-lists: archive the outgoing pin: %v", err)
		return exitStateUnavailable
	}
	if err := rules.Publish(options.sourceLock, options.listFile, pinned, list); err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./cmd/mosdns-cdnctl/ 2>&1 | tail -5` → 全 PASS。

- [ ] **Step 6: 变异验证归档门禁真的会红**

```bash
cp cmd/mosdns-cdnctl/update_lists.go /tmp/opencode/ul.bak
python3 - <<'PY'
from pathlib import Path
p = Path('cmd/mosdns-cdnctl/update_lists.go'); t = p.read_text()
old = "\tif err := rules.Archive(options.previousLock, options.sourceLock); err != nil {"
assert t.count(old) == 1
p.write_text(t.replace(old, "\tif err := error(nil); err != nil {", 1))
PY
go test ./cmd/mosdns-cdnctl/ -run 'TestPublishingArchives|TestAFailedPublish' 2>&1 | tail -4
```
Expected: FAIL（archive 不存在 / 是 stale 的）。
然后 `cp /tmp/opencode/ul.bak cmd/mosdns-cdnctl/update_lists.go` 还原。

- [ ] **Step 7: 提交**

```bash
git add internal/rules/ cmd/mosdns-cdnctl/update_lists.go cmd/mosdns-cdnctl/update_lists_test.go
git commit -m "feat(cdnctl): a pin accepted by mistake can be published again

--pin-remote took the upstream default branch's current HEAD and could not name an
older commit, so once a commit nobody reviewed was accepted there was no way back.
The pin/unpin verbs are the CDN selector's and do not reach this.

The outgoing lock is now archived to source-lock.previous.json BEFORE the publish and
replaced by it, which is the order that makes the archive usable: a publish that
fails leaves an archive naming a commit that really was current, which is the one an
operator rolling back after a failed unattended refresh needs. Archived after, a
failed publish would leave the archive naming the pin that was about to be replaced
by a change that never landed.

--pin-remote grows an optional commit. HEAD still means HEAD, because that is the
documented invocation, and an argument that is neither HEAD nor a full 40-character
commit is refused at the command line rather than after a network round trip."
```

---

### Task 6: 无人值守刷新，由两个开关驱动

**Files:**
- Modify: `cmd/mosdns-cdnctl/update_lists.go`（`parseUpdateListOptions` 第 261 行；`runUpdateLists` 第 326 行；`runCheckLists` 第 362 行）
- Modify: `packaging/systemd/mosdns-list-check.service`（`ExecStart`）
- Test: `cmd/mosdns-cdnctl/update_lists_test.go`

**Interfaces:**
- Consumes: `config.Load(path) (config.Policy, error)`（Task 1 的 `Policy.Lists.China.Automatic` / `Policy.Lists.Cloudflare.Automatic`）、`runPinRemote`、`runRefreshRanges`、`runCheckLists`、`countListRules(list []byte) int`（已存在，第 699 行）
- Produces: `updateListOptions.automatic bool`、`updateListOptions.policy string`（默认 `documents.Policy`）。无其它任务依赖。

- [ ] **Step 1: 写失败的测试**

```go
// With both switches off, --automatic must do exactly what --check does. The
// default configuration has to behave identically to the mode it replaces, or
// turning the feature on and off changes the machine.
func TestAutomaticWithBothSwitchesOffIsTheCheck(t *testing.T) {
	services, released := automaticFixture(t, false, false)
	defer released()
	report := runAutomatic(t, services)
	if !strings.Contains(report, "up-to-date:") {
		t.Errorf("the daily report lost its drift line: %s", report)
	}
	if services.pinned {
		t.Error("the China list was re-pinned with lists.china.automatic off")
	}
	if services.refreshedRanges {
		t.Error("the ranges were refreshed with lists.cloudflare.automatic off")
	}
}

// The report is produced either way. A machine that has the switches on should not
// stop being told what its pin is -- it is the only place the answer is written
// down at all.
func TestAutomaticStillReportsDriftWhenItRefreshes(t *testing.T) {
	services, released := automaticFixture(t, true, false)
	defer released()
	report := runAutomatic(t, services)
	if !strings.Contains(report, "up-to-date:") {
		t.Errorf("the drift line is gone once the switch is on: %s", report)
	}
	if !services.pinned {
		t.Error("lists.china.automatic was on and the list was not re-pinned")
	}
}

// The two switches are two switches.
func TestAutomaticHonoursEachSwitchSeparately(t *testing.T) {
	services, released := automaticFixture(t, false, true)
	defer released()
	runAutomatic(t, services)
	if !services.refreshedRanges {
		t.Error("lists.cloudflare.automatic was on and the ranges were not refreshed")
	}
	if services.pinned {
		t.Error("the China list was re-pinned with lists.china.automatic off")
	}
}

// Review Focus, class 1. An upstream commit whose list is drastically shorter
// verifies -- it really is the upstream document -- and would send far more names
// down the foreign branch than anybody reviewed. The guard refuses and says so; the
// operator can then publish that commit deliberately after reading it.
func TestAListThatShrinksSharplyIsRefused(t *testing.T) {
	services, released := automaticFixture(t, true, false)
	defer released()
	services.publishedRules = 8363
	services.incomingRules = 100 // a 98% collapse, which is a mistake not curation

	code, report := runAutomaticWithCode(t, services)
	if code == exitSuccess {
		t.Errorf("a list that fell from 8363 rules to 100 was published: %s", report)
	}
	if !strings.Contains(report, "fewer rules") {
		t.Errorf("the refusal does not say what it noticed: %s", report)
	}
	if services.publishedRules != 8363 {
		t.Error("the refused list was published anyway")
	}
}

// A real curation commit removes a few rules and must not trip the guard, or the
// guard is just a way of never updating.
func TestASmallReductionIsPublished(t *testing.T) {
	services, released := automaticFixture(t, true, false)
	defer released()
	services.publishedRules = 8363
	services.incomingRules = 8300

	if code, report := runAutomaticWithCode(t, services); code != exitSuccess {
		t.Errorf("a 0.75%% reduction was refused: %s", report)
	}
}

// Review Focus, class 5. A machine with no route out runs this daily. It must fail,
// it must say so, and it must leave the pin and the archive exactly as they were --
// an archive taken on the way to a failure is a rollback target that was never
// current.
func TestAFailedAutomaticRunTouchesNothing(t *testing.T) {
	services, released := automaticFixture(t, true, true)
	defer released()
	before, err := rules.ReadPublishedPair(services.sourceLockPath, services.listPath)
	if err != nil {
		t.Fatal(err)
	}
	services.fetchErr = errors.New("no route to host")

	code, report := runAutomaticWithCode(t, services)
	if code == exitSuccess {
		t.Errorf("a run with no route out reported success: %s", report)
	}
	if !strings.Contains(report, "no route to host") {
		t.Errorf("the failure is not in the report: %s", report)
	}
	after, err := rules.ReadPublishedPair(services.sourceLockPath, services.listPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Commit != before.Commit {
		t.Errorf("the pin changed on a failed run: %s -> %s", before.Commit, after.Commit)
	}
	if _, err := rules.ReadPrevious(services.previousLockPath); err == nil {
		t.Error("a failed run left an archive, so a rollback would land on a commit that " +
			"was only ever about to be replaced")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./cmd/mosdns-cdnctl/ -run 'TestAutomatic|TestAListThatShrinks|TestASmallReduction|TestAFailedAutomatic' 2>&1 | tail -12`
Expected: FAIL —— `--automatic` 不被识别。

- [ ] **Step 3: 最小实现 —— 命令行与调度**

`parseUpdateListOptions` 加两个 flag，并把它们加进"四选一"的互斥集合：

```go
	automatic := flags.Bool("automatic", false,
		"act on the policy's lists.china.automatic and lists.cloudflare.automatic: always "+
			"report drift, and refresh what the policy says to refresh. The mode a "+
			"scheduled run uses")
	policy := flags.String("policy", documents.Policy, "path to the policy YAML file, read by --automatic")
```

`--automatic` 与 `--check` / `--pin-remote` / `--refresh-ranges` 互斥（沿用该函数现有的互斥检查形状）。

`updateListOptions` 加 `automatic bool`、`policy string`。

`runUpdateLists` 的分派加一支：

```go
	case options.automatic:
		return runAutomaticLists(ctx, options, stdout, stderr, services)
```

`runAutomaticLists`：

```go
// runAutomaticLists is the mode a scheduled run uses. It always produces the drift
// report -- that report is the only place the machine's answer is written down --
// and then refreshes exactly what the policy says to refresh, which by default is
// nothing at all.
func runAutomaticLists(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
	policy, err := config.Load(options.policy)
	if err != nil {
		writeCLIError(stderr, "update-lists --automatic: %v", err)
		return exitInvalidCLI
	}

	// The report first, and unconditionally. A machine that has the switches on
	// should not stop being told what its pin is.
	if code := runCheckLists(ctx, options, stdout, stderr, services); code != exitSuccess {
		return code
	}

	if policy.Lists.China.Automatic {
		if code := refreshChinaList(ctx, options, policy, stdout, stderr, services); code != exitSuccess {
			return code
		}
	}
	if policy.Lists.Cloudflare.Automatic {
		options.refreshRanges = true
		if code := runRefreshRanges(ctx, options, stdout, stderr, services); code != exitSuccess {
			return code
		}
	}
	return exitSuccess
}
```

`refreshChinaList` 带着收缩护栏，且**在任何网络动作之前**失败：

```go
// refreshChinaList re-pins the China list, and refuses a list that has collapsed.
//
// The guard is not about the digest: an upstream commit whose data/cn is a fraction
// of its former size verifies perfectly, because it IS the upstream document. What
// it changes is how many names take the foreign branch, and no one reviewed that.
// So a collapse is refused, loudly, with the counts in the message, and the current
// pin is left alone -- publishing it is then one deliberate command an operator runs
// after reading the diff.
//
// The threshold is 95%: a hand-curated list does lose domains now and then, and a
// guard that trips on that is a guard that means never updating.
func refreshChinaList(ctx context.Context, options updateListOptions, policy config.Policy, stdout, stderr io.Writer, services services) int {
	const minimumRetained = 0.95

	pinned, current, err := rules.ReadPublishedPair(options.sourceLock, options.listFile)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	published := countListRules(current)

	// Resolved and downloaded before anything is written, so a failure anywhere in
	// here leaves the pin, the list and the archive exactly as they were.
	client := services.newHTTPClient()
	resolved, err := rules.ResolveHEAD(ctx, client, rules.Repository)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	if resolved.Commit == pinned.Commit {
		writeReportLine(stdout, "china-list: already at %s\n", pinned.Commit)
		return exitSuccess
	}
	_, list, err := rules.Download(ctx, client, resolved)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}

	if incoming := countListRules(list); published > 0 && float64(incoming) < float64(published)*minimumRetained {
		writeCLIError(stderr,
			"update-lists: refusing %s: its list has %d rules where the published one has %d, "+
				"and a curated list does not lose that much in one commit. Nothing was "+
				"changed. Read the diff, then publish it deliberately with "+
				"`mosdns-cdnctl update-lists --pin-remote %s`.",
			resolved.Commit, incoming, published, resolved.Commit)
		return exitStateUnavailable
	}

	return runPinRemote(ctx, options, stdout, stderr, services)
}
```

- [ ] **Step 4: 让定时器跑新模式**

`packaging/systemd/mosdns-list-check.service`：

```ini
ExecStart=/usr/lib/mosdns-router/mosdns-cdnctl update-lists --automatic
```

`Description` 由 Task 2 的渲染器提供，与本 unit 无关；本 service 的 `Description` 改成：

```ini
Description=Daily list work: report drift, and refresh what the policy says to refresh
```

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./cmd/mosdns-cdnctl/ 2>&1 | tail -5` → 全 PASS。
Run: `cd installer/tests && python3 -m unittest test_units 2>&1 | tail -3` → 只有那条先前就存在的 systemd 版本失败。

- [ ] **Step 6: 变异验证收缩护栏真的会红**

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
cp cmd/mosdns-cdnctl/update_lists.go /tmp/opencode/ul2.bak
sed -i 's/const minimumRetained = 0.95/const minimumRetained = 0.0/' cmd/mosdns-cdnctl/update_lists.go
go test ./cmd/mosdns-cdnctl/ -run 'TestAListThatShrinks' 2>&1 | tail -4
```
Expected: FAIL（"a list that fell from 8363 rules to 100 was published"）。
然后还原并确认 `go test ./cmd/mosdns-cdnctl/ 2>&1 | tail -2` 回到 `ok`。

- [ ] **Step 7: 提交**

```bash
git add cmd/mosdns-cdnctl/ packaging/systemd/mosdns-list-check.service
git commit -m "feat(cdnctl): unattended refresh, off by default, guarded

update-lists --automatic is the mode the scheduled run uses. It always produces the
drift report -- that report is the only place the machine's answer is written down,
so a machine that has the switches on must not stop being told -- and then refreshes
exactly what the policy says to refresh, which by default is nothing at all. With
both switches off it does precisely what --check did, because turning the feature on
and off must not change the machine.

The China refresh refuses a list that has collapsed. The digest does not catch this:
an upstream commit whose data/cn is a fraction of its former size verifies perfectly,
because it IS the upstream document. What it changes is how many names take the
foreign branch, and nobody reviewed that. The threshold is 95% retained, because a
curated list does lose domains now and then and a guard that trips on that is a guard
that means never updating. The refusal leaves the pin, the list and the archive
exactly as they were, so publishing that commit afterwards is one deliberate command
an operator runs having read the diff.

A failed refresh archives nothing. The archive is taken inside the publish, so a run
that cannot reach the network cannot leave behind a rollback target that was only
ever about to be replaced."
```

---

### Task 7: 文档

**Files:**
- Modify: `packaging/man/mosdns-cdnctl.1`（`update-lists` 小节在第 597 行附近；`render` 小节）
- Modify: `packaging/man/mosdns-router.8`（状态目录小节，加一段生成的 unit）
- Modify: `packaging/debian/changelog`（新条目）
- Modify: `scripts/build-deb.sh`（`PACKAGE_VERSION`）、`packaging/debian/control`（`Version:`）
- Test: `installer/tests/test_units.py`、`installer/tests/test_package.py` 现有的文档门禁

**Interfaces:**
- Consumes: 无新代码接口
- Produces: 无

- [ ] **Step 1: man page 里写清三件新事实**

`packaging/man/mosdns-cdnctl.1` 的 `update-lists` 小节：

- 新增 `.B \-\-automatic` 一条，说明：与其它三个模式互斥、读 `/etc/mosdns/policy.yaml`、始终产出漂移报告、按 `lists.china.automatic` 与 `lists.cloudflare.automatic` 决定是否刷新
- 在 `--pin-remote` 一条里写：接受 `HEAD`（默认，语义不变）或一个 40 位 commit；发布前把当前 pin 归档到 `source-lock.previous.json`；回退用 `update-lists --pin-remote <commit>`
- 写明收缩护栏：规则数低于已发布列表的 95% 时拒绝，且不动任何已发布内容

`render` 小节里写：它现在还写 `mosdns-list-check.timer` 并 `systemctl daemon-reload`。

`packaging/man/mosdns-router.8` 加一小节，说明 `/usr/lib/systemd/system/mosdns-list-check.timer` 是由 `policy.yaml` 的 `schedule` 生成的，改 policy 后要 `mosdns-cdnctl render`；并删掉现在那句"To move it, drop in over this timer and reload it"（它推荐的正是现在不该用的做法）。

- [ ] **Step 2: 跑文档门禁**

Run: `cd installer/tests && python3 -m unittest test_units 2>&1 | tail -4`
Expected: 只有 `test_the_man_stub_is_what_keeps_documentation_from_deciding_the_verdict` 失败（先前就存在）。

- [ ] **Step 3: 版本与 changelog**

`scripts/build-deb.sh` 的 `PACKAGE_VERSION=0.2.1` → `0.3.0`（新增了无人值守行为，且 `schedule` 从装饰变成生效字段，是行为变更）。`packaging/debian/control` 的 `Version:` 同步改成 `0.3.0`（构建脚本会覆盖它，但仓库里两者要一致，`assert-deb.sh` 的第一道断言就在查这个）。

`packaging/debian/changelog` 顶部加：

```
mosdns-router (0.3.0) unstable; urgency=medium

  * policy.yaml's `schedule` now changes when the daily list work runs. It was
    validated as HH:MM and read by nothing, while the timer that actually decided
    carried a hardcoded OnCalendar, so an operator who changed the policy got no
    change at all. The timer is now rendered from the policy and systemd is
    reloaded as part of writing it; the default moves from 03:00 to 03:30, which is
    the time the hardcoded timer was already using.
  * Two new switches, both off: lists.china.automatic and lists.cloudflare.automatic.
    They are separate because the risks differ -- Cloudflare's ranges choose which
    CDN edge an answer is rewritten to, data/cn decides which names take the
    foreign branch at all. The China list's refresh refuses a list that has lost
    more than 5% of its rules, and leaves everything published untouched when it
    does.
  * `update-lists --pin-remote` now takes an optional commit, and archives the
    outgoing pin to source-lock.previous.json before publishing. Until now a pin
    accepted by mistake could not be undone, because the command could only name
    upstream's current HEAD.

 -- mosdns-router maintainers <mosdns-router@localhost>  Sun, 05 Oct 2026 00:00:00 +0000
```

- [ ] **Step 4: 重新生成本地产物并跑门禁**

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
export PATH=/tmp/opencode/go1.25.8/bin:$PATH GOCACHE=$PWD/.gocache-review GOTMPDIR=/home/ubuntu/.gotmp-mosdns TMPDIR=/home/ubuntu/.gotmp-mosdns
gofmt -l $(git ls-files '*.go'); go vet ./...; go test ./... 2>&1 | grep -vE '^ok|no test files'
sh scripts/build-deb.sh 2>&1 | tail -2
make verify-package 2>&1 | tail -2
```
Expected: go 全绿、构建 exit 0、`assert-deb: ok  version=0.3.0`。

- [ ] **Step 5: 提交**

```bash
git add packaging/ scripts/build-deb.sh
git commit -m "docs: the schedule is real, there are two switches, and a pin can be undone

The man pages say what the code now does, including the two facts an operator would
otherwise get wrong: that changing the schedule needs a render, and that a list
refresh which refused to run also refused to change anything.

The watchdog's own man page recommended dropping a unit over the timer to move it,
which is exactly what the policy now replaces, so that sentence is gone rather than
left to contradict the field it used to be the workaround for."
```

---

### Task 8: 通过 Actions 编译并发布

**Files:** 无（只跑命令）
**Interfaces:**
- Consumes: `.github/workflows/build-deb.yml`、`publish-release.yml`
- Produces: `v0.3.0` Release，其 deb 与它对应那次 build 逐字节一致

- [ ] **Step 1: 推送**

```bash
cd /home/ubuntu/project_v2/.worktrees/mosdns-router
export PATH="$HOME/bin:$PATH"
git push origin feat/mosdns-router
git rev-parse --short HEAD
```

- [ ] **Step 2: 编译**

```bash
gh workflow run build-deb.yml --repo moseasyer/mosdns-router --ref feat/mosdns-router
```
记下返回的 run URL / ID，等它：
```bash
gh run watch <RUN_ID> --repo moseasyer/mosdns-router --interval 20
```
Expected: `the package` 全绿。

- [ ] **Step 3: 发布（中间不要推送任何东西）**

```bash
gh workflow run publish-release.yml --repo moseasyer/mosdns-router --ref feat/mosdns-router \
  -f run_id=<RUN_ID> -f tag=v0.3.0
gh run watch <PUBLISH_RUN_ID> --repo moseasyer/mosdns-router --interval 15
```
Expected: `fetch the built package` 与 `publish a built package` 都绿，`gh release list` 出现 `v0.3.0`。

**这一步与上一步之间不能有 push。** GitHub 的 REST 文档写着：若 `target_commitish` 相对默认分支改动过 `.github/workflows/` 下的文件，`GITHUB_TOKEN` 无权创建 release，API 回答 403 且不提原因。这条限制已经写进 `publish-release.yml` 的检查里，会提前拒绝并说明。

- [ ] **Step 4: 核实 release 的 deb 与那次 build 一致**

```bash
cd /tmp/opencode && rm -rf relcheck && mkdir -p relcheck/{rel,build} && cd relcheck
curl -fsSL -o rel/pkg.deb "https://github.com/moseasyer/mosdns-router/releases/download/v0.3.0/mosdns-router_0.3.0_amd64.deb"
gh run download <RUN_ID> --repo moseasyer/mosdns-router --dir build
cmp rel/pkg.deb build/mosdns-router-deb/mosdns-router_0.3.0_amd64.deb && echo "逐字节相同 ✅"
```
Expected: `逐字节相同`。同时核对 notes 里的 sha256 等于 `sha256sum rel/pkg.deb`。

---

### Task 9: 镜像仓库 `mosdns-router-ng`，并在那里重复 Task 8

**Files:** 无（只跑命令）
**Interfaces:**
- Consumes: `moseasyer/mosdns-router` 的当前内容
- Produces: `moseasyer/mosdns-router-ng`，其 Release 的 deb 与它对应那次 build 逐字节一致

- [ ] **Step 1: 建仓库并逐字复制内容**

```bash
export PATH="$HOME/bin:$PATH"
gh repo create mosdns-router-ng --public \
  --description "A DNS router on loopback only, with a DNSCrypt foreign resolver" \
  --disable-issues
cd /tmp/opencode && rm -rf ngclone && gh repo clone moseasyer/mosdns-router ngclone -- --depth=1
cd ngclone
git remote add ng https://github.com/moseasyer/mosdns-router-ng.git
git push ng HEAD:refs/heads/feat/mosdns-router
```
**内部一律不改**：包名仍是 `mosdns-router`，用户/组仍是 `mosdns-router*`，产物文件名仍是 `mosdns-router_<版本>_amd64.deb`。唯一不同是仓库名。

- [ ] **Step 2: 确认 `workflow_dispatch` 可用（它是默认分支上的工作流）**

```bash
sleep 20
gh workflow list --repo moseasyer/mosdns-router-ng
```
Expected: `build-deb` 与 `publish-release` 都是 `active`。
若为空，推一次空提交再等：
```bash
git commit --allow-empty -m "chore: make the branch the default so workflow_dispatch is available" && git push ng HEAD:refs/heads/feat/mosdns-router
```

- [ ] **Step 3: 编译、发布、核实（与 Task 8 同样的三步）**

```bash
gh workflow run build-deb.yml --repo moseasyer/mosdns-router-ng --ref feat/mosdns-router
gh run watch <NG_RUN_ID> --repo moseasyer/mosdns-router-ng --interval 20
gh workflow run publish-release.yml --repo moseasyer/mosdns-router-ng --ref feat/mosdns-router \
  -f run_id=<NG_RUN_ID> -f tag=v0.3.0
gh run watch <NG_PUBLISH_ID> --repo moseasyer/mosdns-router-ng --interval 15
cd /tmp/opencode && rm -rf ngverify && mkdir -p ngverify/{rel,build} && cd ngverify
curl -fsSL -o rel/pkg.deb "https://github.com/moseasyer/mosdns-router-ng/releases/download/v0.3.0/mosdns-router_0.3.0_amd64.deb"
gh run download <NG_RUN_ID> --repo moseasyer/mosdns-router-ng --dir build
cmp rel/pkg.deb build/mosdns-router-deb/mosdns-router_0.3.0_amd64.deb && echo "逐字节相同 ✅"
```

- [ ] **Step 4: 记录两个仓库各自的事实**

`mosdns-router-ng` 会产出**同名同版本**的包 —— 包名、用户、组名、产物文件名全部相同，机器上无法凭包名区分来源。sha256 **会不同**，因为 `.deb` 注入了构建时间（`BUILD_TIME`），两次构建的字节必然不同；这是预期的，而"release 等于它对应的那次 build"不受影响，因为发布工作流下载 artifact 而不重新编译。

---

## Self-Review

**1. Spec coverage**

| 规格小节 | 任务 |
|---|---|
| `schedule` 由 policy 渲染进 `OnCalendar` | Task 2（渲染）、Task 3（写与 reload）、Task 4（进包与门禁） |
| 默认值改为 `03:30` | Task 1 |
| `lists.china.automatic` / `lists.cloudflare.automatic`，默认关，两个开关 | Task 1（字段与默认值）、Task 6（行为） |
| china 自动更新：归档、校验后发布、失败不动 | Task 5（归档）、Task 6（护栏与失败路径） |
| 回退：`--pin-remote <commit>` | Task 5 |
| cloudflare 自动更新复用 `--refresh-ranges` | Task 6 |
| 门禁（含两条变异验证） | 每个任务各一步变异验证；Task 4 另有逐字节比对 |
| Actions 编译 → 镜像仓库 → 核实一致 | Task 8、Task 9 |

**2. Placeholder scan**

`grep -n 'TBD\|TODO\|implement later\|Similar to Task' docs/superpowers/plans/2026-10-05-list-automatic-updates.md` → 无。

三处依赖本仓库既有 helper 形状的地方（`writeTemp`、`newRenderFixture`、`pinFixture`、`publishPairWithOps` 的原子写）在步骤里明确指出了用哪个既有物，并说明了要沿用它而不是新写第二套 —— 这不是占位符，是"用这个文件里已有的那个"。

**3. Type consistency**

- `config.ListsPolicy` / `ChinaListPolicy` / `CloudflareListPolicy` / `Policy.Lists` 在 Task 1 定义，Task 2 用 `policy.Schedule`，Task 6 用 `policy.Lists.China.Automatic` 与 `policy.Lists.Cloudflare.Automatic` —— 一致。
- `unitfile.Render(policy config.Policy) ([]byte, error)` 与 `unitfile.UnitName` 在 Task 2 定义，Task 3、Task 4 使用 —— 一致。
- `documentPaths.Unit` / `UnitDir` 在 Task 3 定义，Task 4 的 `--unit-out` 默认值取自 `documents.UnitDir` —— 一致。
- `updateListOptions.pinRemote`（string，Task 5）、`previousLock`（Task 5）、`automatic` / `policy`（Task 6）—— 各自在使用的任务里定义。
- `rules.Archive(previousLockPath, currentLockPath string) error` 与 `rules.ReadPrevious(previousLockPath string) (SourceLock, error)` 在 Task 5 定义，Task 6 的测试用 `rules.ReadPrevious` —— 一致。

**4. Review Focus**

五行各自有一个测试步骤：class 1 → Task 6 `TestAListThatShrinksSharplyIsRefused`（并配 `TestASmallReductionIsPublished` 证明护栏不是"永不更新"）；class 2 → Task 5 `TestPublishingArchivesThePinThatWasCurrent`；class 3 → Task 3 `TestRenderReloadsSystemdAfterWritingTheUnit`（并配 `TestAReloadFailureIsReportedAndNamesWhatItIs`）；class 4 → Task 4 `test_the_packaged_timer_is_the_one_this_policy_renders`；class 5 → Task 6 `TestAFailedAutomaticRunTouchesNothing`。

**已知的实现期核对点**（不是占位符，是需要在写代码时确认真实签名的三处）：`rules.ResolveCommit` 当前只解析 default branch 的 HEAD，回退需要它接受一个 ref 参数；`internal/rules` 里原子写的既有函数名（`publish.go` 已有同类）；`cmd/mosdns-cdnctl` 里可用的命令执行器（`_ok` 或等价物）与 `services` 结构的既有字段。
