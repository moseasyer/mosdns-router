"""The harness's own suite has to be countable, or a claim about it is a guess.

`unittest` discovers a test method by name and runs it. Two methods with the
same name in one class is not an error, not a warning, and not a failure: the
later definition silently replaces the earlier one, and the suite reports "OK"
with one case fewer than the file declares. Nothing in the output says a test was
dropped. The same is true one scope up: a subclass that defines a name its base
class already defines runs the subclass's and never the base's.

That is not hypothetical in this project. `ArgumentArrayTest` had two
`test_exec_passes_the_command_as_separate_arguments` methods -- one for
`podman run` and one for `podman exec` -- and the second replaced the first.
The lost case held the only assertion in the whole tree of the measured target
flags (`--systemd=always`, `--cgroupns=private`, the three `--cap-add` values
and `-d`), and the report claimed every array was "asserted as literals in
`ArgumentArrayTest`". Stripping those five flags from the wrapper left 82 tests
passing. A claim about a test was not backed by a test running.

The second instance was the same shape one commit earlier: a control that could
not manufacture the defect it was written to catch. Both say the same thing about
how this project keeps claiming things, so the class of defect gets a guard
rather than the one instance getting a rename.

**The enumeration is the point.** A test that only asserted "this file's case
names are unique" would be a check of today's file. What has to be true is that
the set of cases the *source* declares is the set of cases `unittest` actually
runs, so this module walks three things and compares them:

* the **AST** of every discovered test file, which is the only place a shadowed
  definition is still visible -- by the time a module is imported, the earlier
  definition has already been overwritten and there is nothing left to compare;
* the **files** `unittest` discovery actually loaded, so a test file added later
  is scanned and counted without anybody remembering to list it;
* the **classes and methods** those loaded modules carry, compared through each
  class's real MRO, which is the thing `unittest` itself walks.

Each of the three has a defect it alone can see, and the last one is what a
reviewer counted by hand. Nothing here is derived from a hand-maintained list,
because a hand-maintained list is the fourth thing that can drift: the first
version of this module named its files in a tuple, and a fourth test file was
added to the suite and was discovered, run, and **not scanned**.

## The equality is the guard, and there is no count floor

`assertEqual(declared, loaded)` is asserted as an equality. What was there
before was a floor -- `assertGreaterEqual(total, 150)` -- under a docstring that
claimed an equality, and a floor cannot fail on a case that went *missing*; it
can only notice one that was added. Measured on this tree, deleting a whole
twenty-case class left 194 declared against a floor of 150, so the floor was
not holding the property its docstring described and there is no version of a
fixed number that would. The guard that a fixed number was standing in for --
"the parser actually read something" -- is held per module below, where a failure
names the file that read nothing.

What the equality does hold is the loss that is *silent*: a case that still
exists in the source and does not run. **In every shape that loss can take** --
a case nested in a function, and a case defined under a block statement. Both were
blind spots in the detector rather than in the equality: the equality can only
compare the sets it is given, so a case in neither set satisfies it. `case_functions`
therefore descends into function bodies *and* into every `ast` node that can hold a
statement list -- `if`/`try`/`except*`/`with`/`for`/`while` and their `else`,
`except`/`except*` and `finally` clauses, and each `match` arm's own body -- and every
one of those shapes is planted in a case below. A keyword node added by a future
Python release needs adding to `BLOCKS` with a plant; that is a forward condition, not
a recorded fact about 3.10.

The limit that remains is a **class nested inside a function**, and it is a silent
one: `unittest` collects a `TestCase` from a module's attributes, and a class defined
inside a function never becomes one, so its cases are in neither set.

Two further shapes are open obligations rather than claims, and neither is red on
anything in the tree today:

- A class under a **module-level block** that **inherits** cases from a case-carrying
  base. The block branch walks the class's *own* methods, while `loaded_case_ids`
  counts through the MRO and `declared_case_ids` unions inherited names only for
  module-level classes -- so `loaded - declared` is non-empty and the gate goes red
  on a **correct** file. A platform-conditional class subclassing a shared base is
  the most plausible real instance. "The two sides agree by construction" below holds
  only for a class with no inherited cases.
- The `<block>` qualifier is wrong for anything inside a **class body**: a method
  defined under an `if` in a class body *does* run, and is declared with a `<block>`
  qualifier, so both differences go non-empty on a correct file. Pre-existing at
  module-class scope, and newly reachable one level deeper by the block branch.

The two halves were conflated until this round and both were wrong. A class under a
**module-level block** is collected -- measured, `if` and `with` both, three of three
-- and the previous text called it unreachable while the consequence was the opposite
one: `loaded - declared` was non-empty, so a platform-conditional test class made the
gate go **red**. Every other blind spot in this module made a real loss pass; that one
made a correct file fail, which is how the next person learns to ignore a guard. The
shape is now walked, qualified by the class's own name.
"""

import ast
import sys
import textwrap
import types
import re
import unittest
from pathlib import Path
from typing import Iterable

TESTS_DIR = Path(__file__).resolve().parent

# Every `ast` node that can hold a statement, and therefore a `def`.
#
# `ast.Match` and `ast.TryStar` are here because a case under a `match` arm or an
# `except*` clause is exactly as unreachable as one under an `if`, and the module
# docstring claims every shape is caught. They were missing -- the docstring said
# "every one of those shapes is planted in a case below" and `match` was in neither
# the list nor the plants -- and a claim of completeness that names no exception is
# a claim that is false the first time somebody uses a keyword added in 3.10. Every
# one of them is planted now, which is the only thing that keeps that claim honest.
#
# **A class is not in this list, and the reason is not that a class is unreachable.**
# A class under a *module-level* block is a module attribute, so `unittest` collects
# it and its cases; a class inside a *function* is not. The two halves are handled
# in different places -- the block branch below walks a class's cases, and a class
# inside a function is the stated gap -- and the old comment here claimed both were
# unreachable, which is the opposite of what happens for the common one.
BLOCKS = (
    ast.If,
    ast.Try,
    ast.TryStar,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Match,
)


def case_functions(body, *, nested: bool = False) -> list[tuple[str, int]]:
    """Every `test_*` function in one scope, with its line.

    **Nesting is followed, and the reason is a live defect.** This used to stop at
    the immediate scope, and its docstring said a nested function "is not a case" --
    which is true of what `unittest` collects and irrelevant to what the *source*
    declares. The difference matters because the guard compares those two things: a
    `def test_*` orphaned into a module-level function appeared in neither the
    declared set nor the loaded set, the sets agreed, and the guard passed on a
    **six-case loss** -- in `test_images.py`, the very file whose fix round had
    created it. A source that declares a case nothing runs is the defect this whole
    module exists for, and a detector that cannot see the declaration cannot find it.

    So a `test_*` inside a `test_*`-less function is reported too, carrying the
    **name of the function it is inside**. That is what makes the report actionable:
    "containerfiles.test_x" says both what is wrong and where, where a bare name
    would send a reader looking for a case that does not exist anywhere.

    **Compound-statement bodies are descended into as well, and that is the same
    defect reached a different way.** This used to descend into a function body and
    stop, so a `def test_*` inside an `if`, a `try`, a `with`, a `for`, a `while` --
    or two of them nested -- was in neither the declared nor the loaded set, the
    equality was satisfied, and the live check reported the tree clean. A reviewer
    planted one in a real module and got green. A `def` is a `def`: `unittest` cannot
    reach it, so the source declares a case that does not run, and the only question
    is how deeply to look.

    `<block>` is the qualifier for a case that has no enclosing *name* to report.
    "containerfiles.test_x" points at a function; "`<block>`.test_x" says the case is
    somewhere under a block and leaves the reader to find it, which is the honest
    answer -- the alternative is inventing a path that does not exist in the source.
    The case name and line are in the report either way, and the live check below
    quotes the line it is on.
    """
    found: list[tuple[str, int]] = []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test"):
                found.append((node.name, node.lineno))
                continue
            if nested:
                continue
            for name, lineno in case_functions(node.body, nested=True):
                found.append((f"{node.name}.{name}", lineno))
            continue
        # A `def` under a block has no enclosing name; every block level shares one
        # qualifier, so the qualifier says "under a block" rather than pretending to
        # name a scope. A `case` found this way is unreachable either way -- the
        # qualifier makes it a *difference* against `loaded`, which is what the
        # equality needs, and it cannot be the name of a collected case.
        if isinstance(node, BLOCKS):
            for body in block_bodies(node):
                for name, lineno in case_functions(body, nested=nested):
                    found.append((f"<block>.{name}", lineno))
                # A class met *inside* a block, at a scope unittest collects from. It
                # is a module attribute, so `loadTestsFromModule` finds it and its
                # cases are in `loaded`; not declaring them put `loaded - declared`
                # in the difference and failed the gate on a correct file. The
                # qualifier is the class's own name -- `UnderIf.test_a` -- because that
                # is the shape `loaded_case_ids` reports, and the two sides have to
                # agree on the shape or the equality is red for a bad reason.
                #
                # Reached only from the block branch, so a class at module scope is not
                # walked twice: `declared_case_ids_in` has its own loop for those, and
                # a duplicate is harmless to a set but is one more place the two lists
                # can disagree.
                for member in body:
                    if isinstance(member, ast.ClassDef):
                        for method, _ in case_functions(member.body):
                            found.append((f"{member.name}.{method}", member.lineno))
    return found


def block_bodies(node) -> list:
    """Every list of statements a block node can hold a `def` in.

    Not just `node.body`. An `if` has an `orelse`, a `try` has `handlers`, an
    `orelse` and a `finalbody`, a `for` and a `while` have an `orelse`, and a `def`
    under any of them is exactly as unreachable as one under the `if`. Walking
    `body` alone is the version of this that finds six of the seven forms and looks
    complete -- the `else:` branch is where a case goes when someone writes it to run
    on the other platform, which is the most likely reason to write one at all.
    """
    bodies = [node.body] if hasattr(node, "body") else []
    for attribute in ("orelse", "finalbody"):
        extra = getattr(node, attribute, None)
        if extra:
            bodies.append(extra)
    bodies += [handler.body for handler in getattr(node, "handlers", None) or []]
    # `match` has no `body` of its own -- its statements are in each arm's `body`,
    # which is why a `def` under a `case` clause was invisible while every other
    # keyword was covered. Hence the `hasattr` above rather than `node.body`.
    bodies += [arm.body for arm in getattr(node, "cases", None) or []]
    return bodies


def duplicate_case_names(source: str, origin: str) -> list[str]:
    """The case names `source` defines twice in one scope, as readable text.

    Reads the source rather than the imported module on purpose: by the time a
    module is imported, the second definition has already overwritten the first
    and there is nothing left to compare. The report names the file, the name
    and both lines, because a reader who has to find it by hand will not
    otherwise know which of two similar lines is the one that ate the other.
    """
    tree = ast.parse(source, filename=origin)
    scopes: list[tuple[str, list[ast.stmt]]] = [("<module>", tree.body)]
    scopes += [
        (node.name, node.body)
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    ]
    duplicates: list[str] = []
    for scope_name, body in scopes:
        seen: dict[str, int] = {}
        for name, lineno in case_functions(body):
            if name in seen:
                duplicates.append(
                    f"{origin}: {name!r} is defined in {scope_name} at line {seen[name]} "
                    f"and again at line {lineno}; unittest runs only the second one"
                )
            seen[name] = lineno
    return duplicates


def declared_case_ids_in(tree: ast.Module, module_name: str) -> set[str]:
    """Every case id `tree` declares, in exactly the shape `loaded_case_ids` uses.

    Two shapes of id, and the difference between them is the whole point: a case in
    a class is `module.Class.case`, and a case in a function is `module.function.case`
    -- the same three components, so a case `unittest` cannot collect is a **difference**
    in `declared - loaded` rather than a name in neither set. That is what went wrong:
    `case_functions` stopped at the immediate scope, so six cases orphaned into a
    module-level helper were in neither set, the sets agreed, and the equality below
    passed on the loss. The dot is also what makes the report findable, because
    `containerfiles.test_x` names the function the case is stuck inside.
    """
    ids = {f"{module_name}.{name}" for name, _ in case_functions(tree.body)}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            ids |= {
                f"{module_name}.{node.name}.{method}"
                for method, _ in case_functions(node.body)
            }
    return ids


def declared_cases(path: Path) -> list[tuple[str, int]]:
    """Every case `path` declares, module scope and class scope together."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    declared = case_functions(tree.body)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            declared += case_functions(node.body)
    return declared


# -- the loaded side, which is what unittest actually ran ----------------------


def _flatten(suite) -> list:
    """A `unittest.TestSuite` as a flat list of its cases, recursively."""
    cases: list = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            cases += _flatten(item)
        else:
            cases.append(item)
    return cases


def loaded_modules() -> dict:
    """The test modules `unittest` discovery actually loaded, by file name.

    Derived from discovery rather than from a list, so a file added to the suite
    is in here without anybody editing this module. `discover` is the same call
    the gate `python3 -m unittest discover -s tests/podman/tests` makes, with the
    same top-level directory, so the two answer the same question.

    It imports the modules, which they are already imported as -- the running
    suite is made of them -- so this starts nothing and runs nothing.
    """
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(TESTS_DIR), pattern="test_*.py", top_level_dir=str(TESTS_DIR)
    )
    modules: dict = {}
    for case in _flatten(suite):
        module = type(case).__module__
        modules.setdefault(module, sys.modules[module])
    return modules


def loaded_case_ids(modules) -> set[str]:
    """Every case `unittest` would *collect* from these modules.

    This is `unittest`'s own rule, not an approximation of it: for each
    `TestCase` subclass, a name is collected if `test` starts it and some class in
    the **MRO** defines it, and it is collected **once**, under the subclass. The
    MRO is why a case defined in a base and shadowed in a subclass silently
    loses the base's -- the base's definition is never reached, because the
    subclass's comes first.

    That is exactly what makes the comparison below worth having, and it is why
    this function and `declared_case_ids` are written independently: the declared
    side counts `def test_` in the source, and this side counts what the runner
    collects, so a shadow is a difference rather than something both sides
    agree on.
    """
    ids: set[str] = set()
    for module_name, module in modules.items():
        for attribute in vars(module).values():
            if not isinstance(attribute, type) or not issubclass(attribute, unittest.TestCase):
                continue
            for name in unittest.TestLoader().getTestCaseNames(attribute):
                ids.add(f"{module_name}.{attribute.__name__}.{name}")
    return ids


def declared_case_ids(modules) -> set[str]:
    """Every case the same modules' *source* declares, in the same shape."""
    ids: set[str] = set()
    for module_name, module in modules.items():
        path = Path(module.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        ids |= declared_case_ids_in(tree, module_name)
        # A base class defined in another module contributes its cases to the
        # subclasses that inherit them, so a module that imports a TestCase base
        # from elsewhere would otherwise look like it declared fewer than it
        # runs. The class-name half of the id is the subclass's own, which is
        # what unittest reports.
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            for base in inherited_case_names(node, module):
                ids.add(f"{module_name}.{node.name}.{base}")
    return ids


# The escape hatch, and it is **empty on purpose**: a base class that has to carry
# cases names itself here, and the case below turns an addition into a failure that
# somebody has to look at.
#
# The obvious alternative -- exempting any class whose name ends in `TestCase`,
# the convention this suite already uses for the four bases it has -- is exactly
# the wrong opt-in, and this tree says so. `SetupScriptTestCase` ends in
# `TestCase`, carried three cases, and is subclassed by three classes, so those
# three cases ran nine extra times while its own docstring claimed "the cases are
# not inherited". A name a base can end up with by accident cannot be the thing
# that records a decision about it.
DELIBERATE_CASE_BASES: frozenset[str] = frozenset()


def inheriting_case_bases(
    cases: dict[str, list[str]], bases: dict[str, list[str]]
) -> list[tuple[str, str]]:
    """(base, child) for every class inheriting another class's cases silently.

    `cases` maps a class name to the case names it declares; `bases` maps a class
    name to the names of its **direct** bases, so two classes in one module are
    not inheritance. A (base, child) pair is reported when `child` really derives
    from `base` and `base` **declares** a case -- which is the whole defect, since
    `unittest` collects an inherited case once per subclass: a base with three
    cases and three subclasses runs those cases nine times more than they were
    written, and a failure is then a failure in three places under three sets of
    dials.

    Sorted, so a report does not depend on dictionary order.
    """
    reported: list[tuple[str, str]] = []
    for child, parents in bases.items():
        for base in parents:
            if base != child and cases.get(base):
                reported.append((base, child))
    return sorted(reported)



def inherited_case_names(node: ast.ClassDef, module) -> set[str]:
    """The case names `node` inherits, resolved through the real MRO.

    The AST gives the base *names*; the imported module gives the classes. The
    module's own scope is searched first, then any module it imported, so a base
    declared in a sibling file -- which is how a shared `PodmanTestCase` is
    written -- is found. A base that cannot be resolved is *not* skipped
    silently: the equality case below fails on the difference, so a base defined
    somewhere this function cannot see is a missing case rather than a passing
    one.
    """
    own = {n for n, _ in case_functions(node.body)}
    found: set[str] = set()
    for base in node.bases:
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", None)
        klass = next(
            (v for v in vars(module).values() if isinstance(v, type) and v.__name__ == name),
            None,
        )
        if klass is None:
            for candidate in list(sys.modules.values()):
                other = getattr(candidate, name, None)
                if isinstance(other, type) and issubclass(other, unittest.TestCase):
                    klass = other
                    break
        if klass is None:
            continue
        for ancestor in klass.__mro__:
            found |= {n for n in vars(ancestor) if n.startswith("test")} - own
    return found


class SuiteShapeTest(unittest.TestCase):
    """Every case this project writes about the harness actually runs."""

    def test_no_two_cases_in_one_scope_share_a_name(self):
        """The guard. A shadowed case is otherwise invisible.

        `unittest` reports a suite that ran; it does not report a suite whose
        cases were replaced by later definitions of the same name. A reviewer
        counting `def test_` methods against the run count is how the shadowing
        was found the first time, and this makes the count a gate rather than a
        thing somebody has to remember to check.
        """
        duplicates: list[str] = []
        for module_name, module in loaded_modules().items():
            path = Path(module.__file__)
            duplicates += duplicate_case_names(
                path.read_text(encoding="utf-8"), path.name
            )
        self.assertEqual(
            duplicates, [],
            "unittest silently keeps the last definition of a duplicated case name:\n"
            + "\n".join(duplicates),
        )

    def test_a_subclass_may_not_shadow_a_case_its_base_class_defines(self):
        """One scope up, which is the limit of the scope check above.

        The per-scope check is honest about its own reach: a name defined in a
        `Base` and again in a `Child` is not a duplicate in either scope, so it
        reports nothing -- while `unittest` runs the `Child`'s and never the
        `Base`'s, which is the defect this case is about. The AST is not asked
        about the MRO here, because the AST does not know it: the loaded classes
        are, because their MRO is the very thing `unittest` walks. A name that
        appears in more than one class of one MRO is reported with both classes
        named, so the reader is told which definition ate which.
        """
        shadowed: list[str] = []
        for module_name, module in loaded_modules().items():
            for attribute in vars(module).values():
                if not isinstance(attribute, type) or not issubclass(attribute, unittest.TestCase):
                    continue
                owners: dict[str, list[str]] = {}
                for klass in attribute.__mro__:
                    for name in vars(klass):
                        if name.startswith("test"):
                            owners.setdefault(name, []).append(f"{klass.__module__}.{klass.__name__}")
                for name, classes in owners.items():
                    if len(classes) > 1:
                        shadowed.append(
                            f"{module_name}: {attribute.__name__} inherits {name!r} from "
                            f"{' and '.join(classes)}; unittest runs the last one and never the "
                            f"first"
                        )
        self.assertEqual(shadowed, [], "a case is shadowed through inheritance:\n" + "\n".join(shadowed))

    def test_a_case_nested_in_a_function_is_reported_as_a_loss(self):
        """**Planted, then required to be caught.** The shape of this round's defect.

        The source below is the real one: a module-level helper that ends with a
        `return` and then defines six `test_*` functions underneath it, which is
        what happened in `test_images.py` when a patch inserted the helper at column
        zero inside a class body. The suite went on reporting `OK` and six cases
        stopped running, so the *declared - loaded* difference was empty and the
        guard was green.

        Three halves, and the second is the one that would have caught the original:
        the detector **sees** the nested names, and the report **names the function
        they are inside** -- a bare case name is a name a reader cannot find in the
        file. The third is the same loss behind a **compound statement**, which is a
        different blind spot in the same function and was found by planting one.
        """
        planted = """
import os


def containerfiles(directory=None):
    return sorted(directory.glob("*.Containerfile"))

    def test_a_case_orphaned_into_a_helper(self):
        assert True

    def test_another_one_orphaned_with_it(self):
        assert True


if os.environ.get("ONLY_WINDOWS"):
    def test_a_case_orphaned_behind_a_conditional(self):
        assert True
else:
    def test_another_case_behind_the_else(self):
        assert True

try:
    def test_a_case_orphaned_behind_a_try(self):
        assert True
except ImportError:
    pass

with open(__file__) as handle:
    def test_a_case_orphaned_behind_a_with(self):
        assert True

for _ in range(1):
    def test_a_case_orphaned_behind_a_loop(self):
        assert True

while False:
    def test_a_case_orphaned_behind_a_while(self):
        assert True

match 3:
    case 1 | 2:
        def test_a_case_orphaned_behind_a_match_case(self):
            assert True
    case _:
        def test_another_case_behind_a_match_case(self):
            assert True

try:
    pass
except* ValueError:
    def test_a_case_orphaned_behind_an_except_star(self):
        assert True

if True:
    if True:
        def test_a_case_two_compound_statements_deep(self):
            assert True


class ResolverTest(unittest.TestCase):
    def test_a_real_case(self):
        assert True
"""
        found = declared_case_ids_in(ast.parse(planted, filename="planted.py"), "planted")
        self.assertIn(
            "planted.containerfiles.test_a_case_orphaned_into_a_helper", found,
            "the detector does not see a case nested in a module-level function, so the "
            "declared-minus-loaded equality is empty on a real six-case loss",
        )
        self.assertIn(
            "planted.containerfiles.test_another_one_orphaned_with_it", found,
            "the detector found one nested case and missed the other, so a partial "
            "recovery would look complete",
        )
        # The real case is still found, under its own class -- so a case in a class
        # and a case in a function come back in the same shape and one is a
        # difference rather than neither.
        self.assertIn("planted.ResolverTest.test_a_real_case", found)

        # **And the same loss behind a compound statement, which is the shape the
        # function-body branch does not reach.** `case_functions` descended into a
        # non-`test_*` *function* and stopped there, so a `def test_*` inside an
        # `if`, a `try`, a `with`, a `for`, a `while` -- or two blocks deep -- was in
        # neither the declared nor the loaded set and the equality passed on it, and
        # the live check below reported the tree clean while a reviewer had one
        # planted in it. Every form is planted, and required by name, so a fix that
        # descends into `if` but not `try` is a partial fix that looks complete.
        # The qualifier is repeated once per block, so a case two blocks deep comes
        # back as `<block>.<block>.test_x` and the report says how far down it is. That
        # is the first version of the fix that got it right, and it is worth holding
        # rather than flattening: a flat qualifier would find the case and hide the
        # depth, and "how deep is the thing nobody can reach" is a question worth
        # answering for free.
        for name in (
            "test_a_case_orphaned_behind_a_conditional",
            "test_another_case_behind_the_else",
            "test_a_case_orphaned_behind_a_try",
            "test_a_case_orphaned_behind_a_with",
            "test_a_case_orphaned_behind_a_loop",
            "test_a_case_orphaned_behind_a_while",
            "<block>.test_a_case_two_compound_statements_deep",
            "test_a_case_orphaned_behind_a_match_case",
            "test_another_case_behind_a_match_case",
            "test_a_case_orphaned_behind_an_except_star",
        ):
            with self.subTest(case=name):
                self.assertIn(
                    f"planted.<block>.{name}", found,
                    f"a case defined behind a compound statement ({name}) is invisible to the "
                    "detector, so declared-minus-loaded is empty on the loss and both this "
                    "case and the equality pass on it",
                )

    def test_the_equality_reports_a_nested_case_as_declared_but_not_loaded(self):
        """The same shape, through the equality the guard actually asserts.

        A detector that finds the nested names is only half a fix: the guard's
        assertion is `declared - loaded == set()`, so the nested names have to be in
        `declared` and absent from `loaded` for the loss to surface. Computed here on
        the planted source, with the loaded side supplied by the one real case.
        """
        planted_source = """
def containerfiles():
    return []

    def test_orphaned(self):
        assert True


class RealCases(unittest.TestCase):
    def test_the_real_one(self):
        assert True
"""
        declared = declared_case_ids_in(
            ast.parse(planted_source, filename="planted.py"), "planted"
        )
        loaded = {"planted.RealCases.test_the_real_one"}
        self.assertEqual(
            declared - loaded,
            {"planted.containerfiles.test_orphaned"},
            "a case nested in a function did not surface as a declared-but-not-loaded "
            "difference, so the guard's equality is satisfied on a loss",
        )

    def test_this_tree_has_no_case_nested_in_a_function(self):
        """The live check, over every discovered module rather than over a fixture.

        The planted sources above prove the detector works. This is the one that
        would have caught the real loss before a reviewer found it, and it is
        deliberately an assertion about *this* tree: it is a gate, and a gate that
        has never fired is a gate nobody knows works.
        """
        orphans: list[str] = []
        for module_name, module in loaded_modules().items():
            path = Path(module.__file__)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for owner in [n for n in tree.body if isinstance(n, ast.FunctionDef)]:
                for name, lineno in case_functions(owner.body, nested=True):
                    orphans.append(
                        f"{path.name}:{lineno} {name} is defined inside "
                        f"{owner.name}(), so unittest never collects it"
                    )
            # And the block-shaped half, walked from the module's own statements: a
            # `def test_*` under an `if`/`try`/`with`/`for`/`while` is in neither set
            # and this is the only assertion that would say so.
            for name, lineno in case_functions(tree.body):
                if name.startswith("<block>."):
                    orphans.append(
                        f"{path.name}:{lineno} {name.split('.', 1)[1]} is defined under a "
                        "block statement, so unittest never collects it"
                    )
        self.assertEqual(
            orphans, [],
            "a case is defined where unittest cannot reach it -- inside a function, or under "
            "a block statement -- so the source declares a case that never runs:\n"
            + "\n".join(orphans),
        )

    def test_a_class_under_a_block_is_collected_and_therefore_declared(self):
        """**A legitimate shape that made the gate go red.** The last round's residual.

        `test_suite_shape.py` said the remaining limit was "a class nested inside a
        function or a block -- it is unreachable too". Measured, that is backwards
        for the common half: a class under a **module-level** `if`/`with` is a
        module attribute, so `unittest` collects it, its cases are in `loaded`, and
        `case_functions` did not put them in `declared`. So `loaded - declared` was
        non-empty and `test_the_declared_cases_are_exactly_the_cases_that_run` failed
        on a perfectly ordinary platform-conditional test class.

        That is the opposite failure to the one this module was written for. Every
        other blind spot here made a real loss pass; this one made a correct file
        fail, and a guard that fails on correct code is how the next person learns to
        ignore it.

        **The shape is now handled, not merely described.** `case_functions` walks a
        class's cases when it meets the class inside a block, and qualifies them by
        the class's own name -- `UnderIf.test_a`, the same shape `loaded_case_ids`
        reports -- so the two sides agree by construction rather than by luck.

        The load side is `unittest`'s own collection, not a hand-written list, so the
        case cannot assert a shape the runner does not actually collect. The `with`
        arm is planted too, because `with` is a module-level block like `if` and the
        two are not the same node type.
        """
        planted = textwrap.dedent(
            """
            import unittest

            if True:
                class UnderIf(unittest.TestCase):
                    def test_a(self):
                        assert True

                    def test_b(self):
                        assert True

            with open("/dev/null") as handle:
                class UnderWith(unittest.TestCase):
                    def test_c(self):
                        assert True
            """
        )
        module = types.ModuleType("planted")
        exec(compile(planted, "planted.py", "exec"), module.__dict__)  # noqa: S102
        loaded = {
            f"planted.{type(case).__name__}.{case._testMethodName}"
            for case in _flatten(unittest.TestLoader().loadTestsFromModule(module))
        }
        self.assertEqual(
            len(loaded), 3,
            f"unittest did not collect the classes under the blocks, so this case is not "
            f"about the shape it claims to be: it collected {sorted(loaded)}",
        )
        declared = declared_case_ids_in(
            ast.parse(planted, filename="planted.py"), "planted"
        )
        self.assertEqual(
            declared - loaded, set(),
            "the declared side is missing cases the runner collects, so a correct file fails "
            f"the gate: declared {sorted(declared - loaded)}, loaded {sorted(loaded)}",
        )
        self.assertEqual(
            loaded - declared, set(),
            "the runner collects cases the declared side does not have, so a legitimate "
            f"class under a block fails the gate: {sorted(loaded - declared)}",
        )

    def test_a_class_carrying_cases_may_not_be_subclassed_without_a_deliberate_decision(self):
        """**Planted, then required to be caught.** The second blind spot.

        The MRO case reports a name appearing in more than one class of an MRO -- a
        shadow. A subclass that shadows nothing inherits every case of its base and
        is reported by nothing, so `class SomeTest(CommandLineTest)` would run all
        of `CommandLineTest`'s cases a second time, and the ones that failed would
        fail for a reason in the subclass's `setUp` rather than in the code under
        test. That is not hypothetical: it is what this round's own
        `MatrixProducesEvidenceTest` did before it was fixed.

        The opt-in is **`DELIBERATE_CASE_BASES`, a named constant that is empty
        today**, and not the `*TestCase` naming convention this suite already uses
        for its four bases. That is not a preference; the naming convention is what
        let the defect exist here. `SetupScriptTestCase` ends in `TestCase`, carried
        three cases, and is subclassed by three classes -- so those three cases ran
        nine extra times, and its own docstring claimed "the cases are not
        inherited". A suffix a base can acquire by accident cannot record a decision,
        and the constant makes opting in a two-place edit rather than an accident.
        """
        # A base nobody subclasses is not an inheritance problem, and two classes in
        # one module are not inheritance either -- `bases` is the edge list, not the
        # module's roster, which is what made the first version of this rule report
        # every class in `test_report.py` as inheriting every other.
        self.assertEqual(
            inheriting_case_bases(
                {"Helper": ["test_a"], "Other": ["test_b"]}, {"Other": []}
            ),
            [],
            "a base that no class subclasses is not an inheritance problem",
        )
        # The planted defect: a subclass silently inheriting a class's cases. The
        # two-class shape is the real one -- `SetupScriptTestCase` and one of its
        # three subclasses -- and the reported pair is ordered (base, child) so the
        # report says which definition is being run again.
        self.assertEqual(
            inheriting_case_bases(
                {"CommandLineTest": ["test_a", "test_b"], "SomeTest": ["test_c"]},
                {"SomeTest": ["CommandLineTest"]},
            ),
            [("CommandLineTest", "SomeTest")],
            "a subclass silently inheriting a class's cases is not reported",
        )
        # The control: a case-free base is the normal shape of a shared harness, so
        # a rule that reported those would report every base in the tree.
        self.assertEqual(
            inheriting_case_bases(
                {"EntryPointTestCase": [], "SomethingElse": ["test_b"]},
                {"SomethingElse": ["EntryPointTestCase"]},
            ),
            [],
            "a case-free base is a shared harness, which is what a base is for",
        )
        # And a subclass inheriting a case-free base is reported by nothing, which
        # is the point: `CommandLineTest` inheriting `EntryPointTestCase`'s helpers
        # is the tree as it should look.
        self.assertEqual(
            inheriting_case_bases(
                {"EntryPointTestCase": [], "CommandLineTest": ["test_a"]},
                {"CommandLineTest": ["EntryPointTestCase"]},
            ),
            [],
            "a subclass of a case-free base is the intended shape and must not be reported",
        )

    def test_no_class_in_this_tree_silently_inherits_a_class_that_carries_cases(self):
        """The live check, over the real classes and their real `__bases__`.

        This is the case that found the live instance: `SetupScriptTestCase` held
        three cases and three subclasses, so three cases ran nine extra times while
        the class's own docstring claimed "the cases are not inherited". It is
        asserted over the loaded classes rather than over the AST because
        inheritance is a property of the imported classes -- the same reason the MRO
        case above asks the objects and not the tree.
        """
        offenders: list[str] = []
        for module_name, module in loaded_modules().items():
            classes = {
                klass.__name__: sorted(
                    member for member in vars(klass) if member.startswith("test")
                )
                for klass in vars(module).values()
                if isinstance(klass, type) and issubclass(klass, unittest.TestCase)
            }
            bases = {
                klass.__name__: [parent.__name__ for parent in klass.__bases__]
                for klass in vars(module).values()
                if isinstance(klass, type) and issubclass(klass, unittest.TestCase)
            }
            for base, child in inheriting_case_bases(classes, bases):
                if base in DELIBERATE_CASE_BASES:
                    continue
                offenders.append(
                    f"{module_name}: {child} inherits {base}'s cases "
                    f"{classes[base]} without a recorded decision, so each runs once "
                    f"per subclass under {child}'s dials"
                )
        self.assertEqual(
            offenders, [],
            "a class silently inherits another class's cases, so every one of them runs "
            "once more per subclass:\n" + "\n".join(offenders),
        )

    def test_no_base_is_currently_opted_in_to_carrying_cases(self):
        """The opt-in is empty, and adding a name is a two-place edit.

        `DELIBERATE_CASE_BASES` exists so a base that genuinely has to carry cases
        can, but nothing in this tree does: every base here is a case-free harness
        (`PodmanTestCase`, `EntryPointTestCase`, `SnapshotTestCase`,
        `SetupScriptTestCase`) whose whole purpose is to share setup. This is the
        tripwire that makes the escape hatch a decision -- naming a class in the
        constant turns *this* red, so the opt-in cannot be added silently and then
        quietly inherited by the next class. If a future base really must carry
        cases, this is the line that has to change, and changing it is the record.
        """
        self.assertEqual(
            sorted(DELIBERATE_CASE_BASES), [],
            "a base was opted in to carrying cases; the reason belongs in the comment "
            "above the constant and in the docstring of the class that carries them",
        )

    def test_the_declared_cases_are_exactly_the_cases_that_run(self):
        """The equality, in both directions, and derived from discovery.

        This is the assertion whose absence was the defect. What was there was
        `assertGreaterEqual(total, 150)` plus `assertGreater(per_file, 0)`, while
        the docstring above claimed the suite's count agreed with the count the
        source declares. A floor cannot make that claim and cannot fail on a case
        that went missing -- only on one that was added -- so it passed with a
        file dropped from a hand-maintained list, and, measured, it still passed
        with a whole twenty-case class deleted (214 declared became 194, far above
        150). **There is deliberately no count floor here any more**, because there
        is no property a fixed number states: the per-module check below is the
        real "the parser read something" guard, and it names the module that read
        nothing, which a total could not.

        Equality catches what is actually silent, which is the loss of a case that
        still exists: a shadowed definition, a class of `test_*` methods that does
        not subclass `TestCase` and is therefore never collected, a base class
        whose cases are unreachable. It is asserted in a form that names the
        difference rather than counting, and it is derived from discovery, so a
        test file added later is in both halves without anybody editing anything.
        """
        modules = loaded_modules()
        declared = declared_case_ids(modules)
        loaded = loaded_case_ids(modules)
        self.assertEqual(
            declared - loaded,
            set(),
            "the source declares cases no class in the MRO carries -- a shadowed definition, a "
            "class unittest will not collect, a case in a base class this module cannot resolve, "
            "or a parse that read the wrong file",
        )
        self.assertEqual(
            loaded - declared,
            set(),
            "a class carries cases the source does not declare -- a base class from another "
            "module that inherited_case_names could not resolve, or a stale module object",
        )

    def test_the_enumeration_reads_the_real_files_and_sees_their_cases(self):
        """Every discovered module was parsed, and produced its own cases.

        Without this, a detector that parsed nothing would report no duplicates,
        the equality would be satisfied by two empty sets, and the guard would
        pass on an empty reading. So it is held per module rather than as a total,
        because a total cannot say *which* file it failed to read.

        The file set is the discovered one, not a list: this file is in it because
        discovery found it, and so is every other `test_*.py` beside it. A fourth
        test file was added to this suite during Fix Round 2 and the previous
        version of this module -- which named its files in a tuple -- did not
        scan it, which is the reason there is no list here.
        """
        modules = loaded_modules()
        self.assertIn(__name__, modules)
        for module_name, module in modules.items():
            with self.subTest(module=module_name):
                self.assertEqual(
                    Path(module.__file__).parent,
                    TESTS_DIR,
                    f"{module_name} was discovered from outside {TESTS_DIR}",
                )
                self.assertGreater(
                    len(declared_cases(Path(module.__file__))),
                    0,
                    f"{module_name} declares no cases, so nothing in this module can see it",
                )
        self.assertIn(
            "test_no_two_cases_in_one_scope_share_a_name",
            [name for name, _ in declared_cases(TESTS_DIR / "test_suite_shape.py")],
        )

    def test_the_detector_reports_a_duplicate_it_is_meant_to_report(self):
        """A guard that cannot fail is a comment.

        The source below is the shape that actually happened: one case name,
        twice, in one class body, the first of them the only assertion of the
        measured target flag set. The detector has to name both lines, and it
        has to stay quiet about a name reused in a *different* class, which is
        legitimate and which a naive global count would fail on every run.
        """
        shadowed = '''
class ArgumentArrayTest:
    def test_exec_passes_the_command_as_separate_arguments(self):
        assert run

    def test_run_container_returns_the_container_id(self):
        assert True

    def test_exec_passes_the_command_as_separate_arguments(self):
        assert exec


class SubprocessSafetyTest:
    def test_exec_passes_the_command_as_separate_arguments(self):
        assert another
'''
        reported = duplicate_case_names(shadowed, "shadowed.py")
        self.assertEqual(len(reported), 1)
        self.assertIn("test_exec_passes_the_command_as_separate_arguments", reported[0])
        self.assertIn("ArgumentArrayTest", reported[0])
        # Both lines are named, so a reader is told which definition ate which
        # rather than being left to find two similar lines by hand.
        expected = [
            number
            for number, line in enumerate(shadowed.splitlines(), start=1)
            if line.strip().startswith("def test_exec_passes")
        ]
        self.assertEqual(
            sorted(int(found) for found in re.findall(r"line (\d+)", reported[0])),
            expected[:2],
        )
        # The same name in a second class is not a duplicate, and the detector
        # says so by not mentioning it: a naive global count would fail on every
        # run of this module.
        first_scope_only = shadowed.split("class SubprocessSafetyTest")[0]
        self.assertEqual(
            len(duplicate_case_names(first_scope_only, "one.py")),
            1,
            "a name reused in a different class must not be reported",
        )

    def test_the_inheritance_check_finds_a_base_class_shadow(self):
        """The control for the MRO case, on the shape that would be missed.

        A `Base` and a `Child` that define the same case name is *not* a
        duplicate in either scope, so the per-scope detector above must stay quiet
        about it -- and it does, which is why the second detector exists. Both
        halves are asserted here, on a constructed pair, because a case that only
        ran against the live tree would pass on a tree where no base class defines
        anything, which is the state of this one.
        """
        base = type("Base", (unittest.TestCase,), {"test_a_case": lambda self: None})
        child = type("Child", (base,), {"test_a_case": lambda self: None})
        owners: dict[str, list[str]] = {}
        for klass in child.__mro__:
            for name in vars(klass):
                if name.startswith("test"):
                    owners.setdefault(name, []).append(klass.__name__)
        self.assertEqual(
            owners["test_a_case"],
            ["Child", "Base"],
            "the constructed pair must reproduce what the MRO case looks for, or that case "
            "is checking nothing",
        )
        # And the per-scope detector is silent on the same shape, which is the
        # limit its own docstring states -- one scope, not one hierarchy.
        self.assertEqual(
            duplicate_case_names("class Base:\n    def test_a_case(self):\n        pass\n", "base.py"),
            [],
            "the per-scope detector must stay quiet here, or it would fail on every subclass "
            "that legitimately overrides a base case -- which is how a guard gets deleted",
        )

    def test_a_file_that_cannot_be_parsed_fails_the_guard_rather_than_passing_it(self):
        """A syntax error in a harness test file must not read as "no duplicates".

        A detector that swallowed the parse error would turn a broken file into
        a green guard, which is the exact shape of the failure this module
        exists to stop: silence read as success.
        """
        with self.assertRaises(SyntaxError):
            duplicate_case_names("def test_x(:\n", "broken.py")


if __name__ == "__main__":
    unittest.main()
