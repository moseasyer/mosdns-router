"""The policed flag names are checked against *podman's own* vocabulary.

`lib/podman.py` refuses a target container the host it runs on, and it does so by
looking names up in a table. That is only sound while the table's names and
podman's names are the same set, and the two drift: podman has aliases, and an
alias is a second spelling of a policed flag that a name-keyed guard cannot see.

**This is not hypothetical — it was the finding of a review.** `podman-run(1)`
declares the pair in one heading:

```text
.SS \\fB--network\\fP=\\fImode\\fP, \\fB--net\\fP
    Set the network mode for the container.
```

and pflag accepts either spelling, so `extra_args=["--net", "host"]` reached the
target through a name the policed table did not contain. It landed *after* the
wrapper's own `--network <net>` and `--network` is a `stringArray`, so the target
would have ended up on both the bridge and the host network. The other seven
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
>   podman run "$f=x" --help >/dev/null 2>&1 && echo 'ACCEPTED' || echo 'unknown'
> done
```

Run it against the new podman first and the documented set second, and a name
that answers `ACCEPTED` in one and not the other is an alias nobody wrote down.

## It is a skipping case, and the skip says so

Podman is not installed on every machine that checks out this repository, and
this harness refuses to install it (see `docs/testing.md`). So this case skips
where podman is absent — loudly, with the one-line command a contributor runs by
hand, rather than passing on an empty reading. A skip is not a pass: the case
that does not depend on podman, the table-closure guard, is in
`test_command.py` and always runs.
"""

import gzip
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

# The harness is used from a source checkout, so its library directory is the
# import root, and it is set up here rather than inherited: a case that only
# imports when another case's module happened to run first is a case that cannot
# be run on its own, which is how it is run when it fails.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from podman import FORBIDDEN_CONTAINER_FLAGS, PODMAN_FLAG_ALIASES  # noqa: E402

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
    """
    completed = subprocess.run(
        ["podman", "run", f"{spelling}=x", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return not UNKNOWN_FLAG.search(completed.stdout + completed.stderr)


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
        """
        aliases = documented_options(self.page)
        undocumented = sorted(set(FORBIDDEN_CONTAINER_FLAGS) - set(aliases))
        self.assertEqual(
            undocumented,
            [],
            "these policed flags have no .SS heading in podman-run(1), so this case cannot check "
            "their aliases -- the guard has gone blind rather than found nothing",
        )
        missing: list[str] = []
        for name in sorted(FORBIDDEN_CONTAINER_FLAGS):
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
        """
        self.assertTrue(PODMAN_FLAG_ALIASES, "the alias table cannot be empty: --net is in it")
        for alias, canonical in sorted(PODMAN_FLAG_ALIASES.items()):
            with self.subTest(alias=alias):
                self.assertTrue(
                    pflag_knows(alias),
                    f"podman does not accept {alias!r}, so mapping it onto {canonical!r} is an "
                    f"entry that reads like coverage and provides none",
                )
                self.assertIn(canonical, FORBIDDEN_CONTAINER_FLAGS)

    def test_no_policed_flag_has_a_short_form_the_name_lookup_would_miss(self):
        """The generalisation of the finding, derived rather than guessed.

        `--net` was one second name for one policed flag. A *short* form is the
        same hazard by a different route: pflag registers `-v` and `--volume` as
        two names for one flag, so `-n`, if `--network` ever grew one, would be a
        host-namespace request the guard's name lookup would not see -- and
        `canonical_flag_name` resolves only the names in its table, so it would
        not help either.

        So this asserts the invariant over the documentation rather than trusting
        that nobody thought of it: **no policed flag may carry a short form.**
        Today none does, and a podman that added one fails here with the pair
        named, which is the point at which `PODMAN_FLAG_ALIASES` (or whatever
        mechanism the fix takes) has to learn about it.
        """
        shorts: dict[str, str] = {}
        for line in self.page.splitlines():
            if not line.startswith(".SS "):
                continue
            text = line.replace("\\fP", " ").replace("\\fB", "")
            longs = LONG_FLAG.findall(text)
            if not longs:
                continue
            found = SHORT_FLAG.findall(text)
            if found:
                shorts[longs[0]] = found[0]
        with_short_form = sorted(
            f"{name} / {shorts[name]}" for name in FORBIDDEN_CONTAINER_FLAGS if name in shorts
        )
        self.assertEqual(
            with_short_form,
            [],
            "a policed flag has a short form, which pflag accepts as a second name and the "
            "name-keyed lookup does not see",
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


if __name__ == "__main__":
    unittest.main()
