"""The policed flag names are checked against *podman's own* vocabulary.

`lib/podman.py` refuses a target container the host it runs on, and it does so by
comparing flag names against three policies. That is only sound while the policed
names and podman's names are the same set, and the two drift: podman has aliases,
and an alias is a second spelling of a policed flag that a name-keyed guard cannot
see.

**This is not hypothetical — it was the finding of a review.** `podman-run(1)`
declares the pair in one heading:

```text
.SS \\fB--network\\fP=\\fImode\\fP, \\fB--net\\fP
    Set the network mode for the container.
```

and pflag accepts either spelling, so `extra_args=["--net", "host"]` reached the
target through a name the policed table did not contain. It landed *after* the
wrapper's own `--network <net>` and `--network` is a `stringArray`, so the target
would have ended up on both the bridge and the host network. The other ten
policed names were checked one at a time by hand; only this one has an alias.

**The hand check does not scale**, which is the reason this file exists. A
reviewer probing every policed name by hand found one alias; nothing in the
repository would have found the next one. So the check is derived from podman's
own documentation instead, and it runs as part of the suite.

## What is derived, and what is not

The names are derived from **`podman-run(1)`**, which is where a container's flags
are documented, and the alias is the other long flag on the same `.SS` line. A
short flag (`-v`, `-p`) is not an alias here: pflag treats `--flag` and `--flag=`
as one name with two value spellings, whereas `--net` and `--network` are two
*names* for one flag, and only the second kind defeats a name-keyed guard.

Two things this file deliberately does **not** do:

* **It does not consult `podman run --help`.** `--net` is absent from that
  output, so a guard built on it would have found nothing. It is not a superset
  of the vocabulary either: measured on this host, `podman run --ns=x --help` and
  `podman run --namespace=x --help` both exit 0, while `podman-run(1)` documents
  those two names only under `podman ps`, where they are a boolean about
  *displaying* namespaces and grant a target nothing. The help text is therefore
  neither a superset nor a subset, and cannot be the oracle in either direction.
* **It does not try to enumerate podman's whole flag set.** There is no
  supported way to ask a pflag program for the names it has registered, so
  "does any *other* policed name have an alias" cannot be answered by
  enumeration. It is answered two ways that can be: the documentation is parsed
  for every alias of every policed name, and every alias the table claims is then
  asked of pflag directly.

**The limit of that, stated rather than implied.** Documentation plus a
behavioural probe finds the aliases podman *documents* and cannot find one it
does not, so a policed flag that gained a second name only in the code would not
be caught here. The manual check for that, which is what the reviewer did, is one
command per policed name and is worth repeating when podman is upgraded:

```console
$ for f in --privileged --cgroupns --network --net --pid --ipc --uts --userns \
           --cap-add --device --security-opt --volumes-from; do
>   printf '%-16s ' "$f"
>   { podman run "$f=x" --help || podman run "$f" --help; } >/dev/null 2>&1 \
>     && echo 'ACCEPTED' || echo 'unknown'
> done
```

The `||` is not decoration and its absence was a recorded defect. `--privileged`
is a **boolean**, so `podman run --privileged=x --help` exits non-zero with
`invalid argument "x" for "--privileged" flag: strconv.ParseBool` — pflag
*registered* the name and then failed to parse the value. A loop that reads exit
status alone calls that `unknown` for a flag podman accepts, and a contributor
following the guidance above would have gone looking for a phantom alias. So the
bare form is asked second, and either form answering is a name podman has; the
value-taking names never reach the bare probe, where `--help` is spent as their
value and podman then refuses for want of an image (exit 125, nothing started).
`pflag_knows` above is the same two probes, and it does not read exit status at
all — it looks for `unknown flag`, which is the only answer that means *not
registered*.

Run it against the new podman first and the documented set second, and a name
that answers `ACCEPTED` in one and not the other is an alias nobody wrote down.

## The eleven names, not the seven

Both cases below iterate `POLICED_CONTAINER_FLAGS` — the value-keyed policed
table, the families refused whatever their value, and `--cap-add` — rather than
the value-keyed table alone. **The first version of this file iterated the
latter**, and the claim it made, that it covered the policed names, was true of
seven names out of eleven: `--device`, `--security-opt`, `--volumes-from` and
`--cap-add` were policed by a name-keyed check that this file's derivation never
looked at, so an alias of any of them would have reached the same position
`--net` did and this file would have reported nothing. All eleven are policed by
the same guard and all eleven are names podman has, so all eleven are checked
against podman's own documentation here. The set is derived in
`lib/podman.py` from the three constants that police it, and
`test_policed_container_flags_covers_every_name_the_guard_refuses` in
`test_command.py` holds that derivation to the guard's own body — this case
iterates a set, and a set that stopped matching the code would still pass.

**Thirteen now, and two of them carry a short form.** Task 3 added `--publish`
and `--publish-all` to the families, which is the plan's "do not publish ports
to the host" made structural: publishing the mock router on port 53 would
collide with the operator's resolved. `podman-run(1)` gives them `-p` and `-P`,
and pflag registers those as separate names for the flags — so
`PODMAN_FLAG_ALIASES` now holds short forms, and the short-form case below
changed its invariant from "no policed flag has a short form" to "every short
form is resolved". The first of those is a claim about podman rather than about
the guard, and it became false; a guard that still asserted it would go red on a
correct policy, which is the failure mode this file has already produced once
elsewhere. No count is asserted anywhere here: the set is derived, which is the
entire reason for deriving it.

## It is a skipping case, and the skip says so

Podman is not installed on every machine that checks out this repository, and
this harness refuses to install it (see `docs/testing.md`). So this case skips
where podman is absent — loudly, with the one-line command a contributor runs by
hand, rather than passing on an empty reading. A skip is not a pass: the cases
that do not depend on podman — the table-closure guard and
`test_policed_container_flags_covers_every_name_the_guard_refuses` — are in
`test_command.py` and always run, and the second of those is what holds the set
this file iterates to the guard that polices it.
"""

import gzip
import re
import subprocess
import sys
import unittest
from pathlib import Path

# The harness is used from a source checkout, so its library directory is the
# import root, and it is set up here rather than inherited: a case that only
# imports when another case's module happened to run first is a case that cannot
# be run on its own, which is how it is run when it fails.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from podman import (  # noqa: E402
    FORBIDDEN_CONTAINER_FLAG_NAMES,
    FORBIDDEN_CONTAINER_FLAGS,
    PODMAN_FLAG_ALIASES,
    POLICED_CONTAINER_FLAGS,
)

# The man page that documents a container's flags, and the directory searched
# for it. Podman installs one page per subcommand, and the run page is the one
# that carries every flag this harness polices -- `container run` shares its
# flag set and the two pages document the same options.
MAN_SECTION_DIRS = (Path("/usr/share/man/man1"), Path("/usr/local/share/man/man1"))
MAN_PAGE_GLOB = "podman-run.1.gz"

# `--network =mode , --net`, after the roff escapes are stripped. Only a *long*
# flag is an alias: `-a` is the short form of `--attach`, not a second name for
# it, and a value or a type in the heading is not a flag at all.
LONG_FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
# A single-dash short form, which pflag registers as its own name for the flag.
SHORT_FLAG = re.compile(r"(?<![\w-])(-[a-zA-Z])(?![\w-])")
# `Error: unknown flag: --netzzz` -- how pflag says a name it has never heard of.
UNKNOWN_FLAG = re.compile(r"unknown (shorthand )?flag")


def man_page_text():
    """The run page's text, or None where podman's documentation is not installed."""
    for directory in MAN_SECTION_DIRS:
        page = directory / MAN_PAGE_GLOB
        if page.is_file():
            return gzip.decompress(page.read_bytes()).decode("utf-8", "replace")
    return None


def documented_options(page_text):
    """Every option the run page declares, as canonical name -> aliases.

    Parsed from the roff rather than from rendered output because rendering needs
    `man`, which is not installed everywhere either, and because a heading is a
    single line: `--network=mode, --net` is one declaration of one flag with two
    names, and a rendered page would have lost the association.

    An option with no alias is present with an **empty** set, which is the whole
    point: the caller needs to tell "this flag has one name" from "this flag is
    not documented here", and a parser that only recorded the multi-name headings
    could not. That distinction is what stops this case from passing on a podman
    that stopped documenting a policed flag at all.

    The first long flag on a heading is taken to be the option's own name and the
    rest to be its aliases. Podman writes them canonical-first; a heading that
    did not would be a documentation defect rather than a fact about the flag
    set, and the case below reports the absence of a heading rather than guessing.
    """
    options: dict[str, set[str]] = {}
    for line in page_text.splitlines():
        if not line.startswith(".SS "):
            continue
        names = LONG_FLAG.findall(line.replace("\\fP", " ").replace("\\fB", ""))
        if not names:
            continue
        options[names[0]] = set(names[1:])
    return options


def pflag_knows(spelling):
    """Whether this podman's pflag accepts `spelling` as a run option.

    Asked of the binary rather than of the documentation, because the two
    disagree in both directions: `--net` is documented and absent from `--help`,
    and `--ns` is accepted and documented only under `podman ps`. `--help` is
    what makes pflag report an unknown name, and it exits before doing anything
    else, so this starts no container and touches no host state.

    **Both probe forms, because one flag name does not answer to the other.**
    `--privileged` is a boolean, so `podman run --privileged=x --help` exits
    non-zero with `invalid argument "x" for "--privileged" flag:
    strconv.ParseBool` -- a *parse* failure, not an unknown name. Reading exit
    status calls that `unknown` for a flag podman accepts, and the manual command
    at the top of this file used to do exactly that. Every other policed name
    takes a value, so the bare form cannot be the only probe either:
    `podman run --cgroupns --help` spends `--help` as the value of `--cgroupns`
    and then refuses for want of an image (exit 125), which starts nothing. So:
    the `=x` form first, the bare form second, and *either* answering is a name
    podman has.

    A name podman does not have answers `unknown flag` in both, which is the only
    answer that means *not registered* and the only one this reads -- so the
    two-probe form is what makes this helper and the manual command ask the same
    question, rather than a fix to a bug in the helper. `test_the_probe_asks_a_
    boolean_flag_in_the_form_a_boolean_answers` holds the asymmetry open.
    """
    for probe in (f"{spelling}=x", spelling):
        completed = subprocess.run(
            ["podman", "run", probe, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if not UNKNOWN_FLAG.search(completed.stdout + completed.stderr):
            return True
    return False


def documented_short_forms(page_text: str) -> dict[str, str]:
    """Every long flag the run page gives a short form, as name -> short.

    A heading is one line, so `--publish=…, -p=…` is a single declaration of a
    single flag with two names -- and the association between them is the whole
    point. Rendering the page would lose it, and `podman run --help` is not a
    superset of the documented set (`--net` is absent from it), so the roff is
    the only oracle that keeps the pair together.

    Only a *short* form is recorded, and only for a heading whose own name is a
    long flag: `-a` beside `--attach` is the short form of the same flag, not a
    second name, which is the same distinction the alias table above is built on.
    """
    forms: dict[str, str] = {}
    for line in page_text.splitlines():
        if not line.startswith(".SS "):
            continue
        text = line.replace("\\fP", " ").replace("\\fB", "")
        longs = LONG_FLAG.findall(text)
        if not longs:
            continue
        shorts = SHORT_FLAG.findall(text)
        if shorts:
            forms.setdefault(longs[0], shorts[0])
    return forms


def unresolved_short_forms(page_text: str, policed, aliases) -> list[str]:
    """`"name / short"` for every policed flag whose short form is not resolved.

    The predicate the gate asserts, kept out of the case so a control can be run
    against it: a detector that cannot report the defect is a comment, and the
    two directions -- a short form that is resolved, and one that is not -- have
    to be distinguishable or the control proves nothing.
    """
    documented = documented_short_forms(page_text)
    return sorted(
        f"{name} / {documented[name]}"
        for name in policed
        if name in documented and aliases.get(documented[name]) != name
    )


class PodmanVocabularyTest(unittest.TestCase):
    """Every spelling podman has for a policed flag reaches the policy."""

    def setUp(self):
        self.page = man_page_text()
        if self.page is None:
            raise unittest.SkipTest(
                "podman's man pages are not installed here, so its flag vocabulary cannot be "
                "read. This case SKIPS rather than passing on an empty reading -- a guard that "
                "cannot run must not read as a guard that found nothing. To run it by hand: "
                f"zcat {MAN_SECTION_DIRS[0]}/{MAN_PAGE_GLOB} | grep '^\\.SS ' | grep -- '--'"
            )

    def test_every_alias_podman_documents_for_a_policed_flag_is_canonicalised(self):
        """The gate. An alias the table does not know is a hole in the guard.

        For each policed name, the run page's own heading is read and every other
        long flag on that heading is an alias. Each one must appear in
        `PODMAN_FLAG_ALIASES` and must canonicalise to the name it is an alias
        of. This is the check that fails when podman grows a second name for a
        policed flag, and it is derived from podman's documentation rather than
        from the table, so it cannot agree with itself.

        Over `POLICED_CONTAINER_FLAGS` -- **all eleven policed names**, not the
        seven in the value-keyed table. The four that were outside the first
        version of this case are policed by a check keyed on the raw name, so
        they were outside this case *and* outside the no-short-form case below:
        a future alias of `--device` would have reached a name-keyed check that
        could not see it, and this case would have said nothing. All eleven have
        a heading in `podman-run(1)` (measured: `--cap-add`, `--cgroupns`,
        `--device`, `--ipc`, `--network`, `--pid`, `--privileged`,
        `--security-opt`, `--userns`, `--uts`, `--volumes-from`), and the
        `undocumented` assertion below is what keeps that true.
        """
        aliases = documented_options(self.page)
        policed = set(POLICED_CONTAINER_FLAGS)
        undocumented = sorted(policed - set(aliases))
        self.assertEqual(
            undocumented,
            [],
            "these policed flags have no .SS heading in podman-run(1), so this case cannot check "
            "their aliases -- the guard has gone blind rather than found nothing",
        )
        missing: list[str] = []
        for name in sorted(policed):
            for other in sorted(aliases[name]):
                if PODMAN_FLAG_ALIASES.get(other) != name:
                    missing.append(
                        f"{other!r} is documented as an alias of {name!r} in "
                        f"{MAN_PAGE_GLOB} and pflag accepts it, but PODMAN_FLAG_ALIASES maps it "
                        f"to {PODMAN_FLAG_ALIASES.get(other)!r}, so a target given {other} would "
                        f"reach the host through a name the policed table does not contain"
                    )
        self.assertEqual(missing, [], "an alias of a policed flag is not policed:\n" + "\n".join(missing))
        # And the specific pair this file was written for, named so the failure a
        # future reader has to diagnose is a readable sentence and not a diff.
        self.assertEqual(PODMAN_FLAG_ALIASES.get("--net"), "--network")

    def test_every_alias_the_table_claims_is_one_this_podman_really_has(self):
        """The table is closed in the other direction too.

        An alias podman has since dropped would be an entry that reads like
        coverage and provides none: an operator who is refused `--net` and then
        finds podman no longer accepts it has been sent to fix the wrong thing.
        So each entry is asked of pflag directly, and a misspelling of it is
        asked of pflag as well, which is what makes this a test of podman rather
        than of the check that `--netzzz` is not a flag.

        The alias must also canonicalise to a name the policy governs **and** be
        a name this file's own derivation covers: the first half is a table that
        refuses something, the second is a name whose future aliases would be
        checked. An alias of a family or of `--cap-add` is policed by a
        name-keyed check, which the closure in `test_command.py` now
        canonicalises, so both halves are needed rather than one -- and "the
        policy" has to be the **union** of the three mechanisms rather than the
        value-keyed table alone. A family is policed by name and has no refused
        value to be a key of, so `-p` canonicalises to `--publish`, which is in
        the families tuple and not in the table: checked against the table, the
        first version of this assertion reported the port policy as an alias of
        nothing, which is the failure mode of a guard that is right about podman
        and wrong about its own module.
        """
        self.assertTrue(PODMAN_FLAG_ALIASES, "the alias table cannot be empty: --net is in it")
        policed = set(POLICED_CONTAINER_FLAGS)
        for alias, canonical in sorted(PODMAN_FLAG_ALIASES.items()):
            with self.subTest(alias=alias):
                self.assertTrue(
                    pflag_knows(alias),
                    f"podman does not accept {alias!r}, so mapping it onto {canonical!r} is an "
                    f"entry that reads like coverage and provides none",
                )
                self.assertIn(canonical, policed)
                self.assertIn(
                    alias,
                    FORBIDDEN_CONTAINER_FLAG_NAMES,
                    f"{alias!r} is a policed alias and so belongs in the set a refusal prints, "
                    f"which is what the operator is told to avoid",
                )
        self.assertTrue(
            policed >= set(FORBIDDEN_CONTAINER_FLAGS),
            "the policed surface cannot be smaller than the table it is derived from",
        )

    def test_no_policed_flag_has_a_short_form_the_name_lookup_would_miss(self):
        """The generalisation of the finding, derived rather than guessed.

        `--net` was one second name for one policed flag. A *short* form is the
        same hazard by a different route: pflag registers `-v` and `--volume` as
        two names for one flag, so `-p` is a second name for `--publish` and the
        guard's name lookup has to resolve it. Two policed flags carry one today
        and they are the two that would reach this host's resolver:

        ```text
        .SS \\fB--publish\\fP, \\fB-p\\fP=\\fI[[ip:][hostPort]:]containerPort[/protocol]\\fP
        .SS \\fB--publish-all\\fP, \\fB-P\\fP
        ```

        **The invariant is therefore "every short form is resolved", not "no
        short form exists".** The first version of this case asserted the second
        -- that no policed flag carries a short form -- and adding the port
        policy to a podman that documents both spellings made it go red on a
        correct file. That is the same failure mode the class docstring records
        for the block-walking detector: a guard that fails on correct code is
        how the next person learns to ignore it. So the check is over the
        documentation, derived, and it reports a short form the table does not
        resolve -- with both names in the message, because "a policed flag has a
        short form" without saying which is a shrug.

        Over all policed names, for the reason the case above gives: a short form
        of `--device` or of `--cap-add` defeats the name lookup exactly as a long
        alias of it does.
        """
        documented = documented_short_forms(self.page)
        unresolved = sorted(
            f"{name} / {short}"
            for name in POLICED_CONTAINER_FLAGS
            for short in [documented.get(name, "")] if short
            and PODMAN_FLAG_ALIASES.get(short) != name
        )
        self.assertEqual(
            unresolved,
            [],
            "a policed flag has a short form the name lookup does not resolve, and pflag accepts "
            "both, so a target handed the short one reaches the host through a name the policed "
            f"table does not contain: {unresolved}",
        )

    def test_the_short_form_detector_reports_a_policed_flag_it_cannot_resolve(self):
        """The control, so the case above is not satisfied by a detector that reports nothing.

        Two halves. The first asks the detector about a policed name the real
        page does not carry a short form for, and requires that it reports
        nothing -- so a detector that reported everything would fail here rather
        than passing the gate above. The second is the planted defect: a page
        whose `.SS` heading gives a policed flag a short form the table does not
        know, which the gate must report with both names.
        """
        documented = documented_short_forms(self.page)
        self.assertIsNone(
            documented.get("--privileged"),
            "podman now documents a short form for --privileged; the case above must learn it "
            "rather than the detector below keeping quiet about it",
        )
        planted = "\n".join([
            ".SS \\fB--device\\fP, \\fB-d\\fP=device",
            ".SS \\fB--privileged\\fP",
        ])
        found = unresolved_short_forms(planted, ["--device"], PODMAN_FLAG_ALIASES)
        self.assertEqual(found, ["--device / -d"],
                         "a short form the alias table does not resolve was not reported")
        # And the control: with the short form in the table, the same page is clean.
        self.assertEqual(
            unresolved_short_forms(planted, ["--device"], {"-d": "--device"}),
            [],
            "the detector reported a short form that the alias table does resolve",
        )

    def test_the_probe_this_file_relies_on_can_reject_a_spelling(self):
        """A control, so the case above is not satisfied by a probe that says yes.

        `pflag_knows` is a subprocess that reports whether a name is registered.
        A probe that always answered "yes" would make the table-closure case pass
        unconditionally, which is the defect this repository has already committed
        twice: a case that cannot manufacture the failure it was written to catch
        is a comment. So the probe is asked about a misspelling, and asked about
        both the alias and the misspelling in the same breath -- if podman ever
        answered "unknown flag" for a name it does have, this fails and the gate
        above is not read as having passed.
        """
        self.assertTrue(pflag_knows("--net"), "the documented alias is no longer accepted")
        self.assertFalse(
            pflag_knows("--netzzz"),
            "podman accepted a misspelling of a policed flag's alias, so pflag_knows cannot "
            "distinguish a registered name from an unregistered one and every gate built on it "
            "is vacuous",
        )
        self.assertFalse(pflag_knows("--networ"), "pflag abbreviates flag names; this gate assumes it does not")

    def test_the_probe_asks_a_boolean_flag_in_the_form_a_boolean_answers(self):
        """The control for the defect the recorded command had, planted.

        `--privileged` is the one policed name that takes no value, and a probe
        that asks it the value form gets a *parse* failure rather than an
        unknown-name failure:

        ```console
        $ podman run --privileged=x --help; echo $?
        Error: invalid argument "x" for "--privileged" flag: strconv.ParseBool: parsing "x": ...
        125
        $ podman run --privileged --help >/dev/null; echo $?
        0
        ```

        So the one-probe version read exit status and answered `unknown` for a
        flag podman accepts -- the exact shape of a phantom alias, which is what
        the manual command at the top of this file used to tell a contributor to
        go and look for. `pflag_knows` asks the bare form second, and this case
        holds the asymmetry open so the fix cannot be quietly reverted: if the
        bare form stops being the one that answers, the assertion below fails
        here rather than in a phantom-alias hunt.
        """
        valued = subprocess.run(
            ["podman", "run", "--privileged=x", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        bare = subprocess.run(
            ["podman", "run", "--privileged", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            bare.returncode,
            0,
            "the bare form of a policed boolean no longer answers -- this podman differs from the "
            "one the probe was measured against, and the second probe is now asking the wrong "
            "question",
        )
        self.assertIn(
            "strconv.ParseBool",
            valued.stdout + valued.stderr,
            "the value form of a boolean no longer fails to parse; if it now exits 0 the second "
            "probe in pflag_knows is unnecessary and the note at the top of this file is stale",
        )
        # Neither probe says "unknown flag" for it -- pflag registered the name
        # and objected to the value -- so `pflag_knows`, which reads that one
        # answer and not the exit status, gets it right.
        self.assertNotRegex(valued.stdout + valued.stderr, UNKNOWN_FLAG)
        self.assertTrue(
            pflag_knows("--privileged"),
            "a policed boolean answers neither probe, so pflag_knows cannot see it and the "
            "closure above is blind to every alias a boolean might grow",
        )


if __name__ == "__main__":
    unittest.main()
