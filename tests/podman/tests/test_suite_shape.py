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
exists in the source and does not run.
"""

import ast
import sys
import re
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent


def case_functions(body) -> list[tuple[str, int]]:
    """Every `test_*` function defined directly in one scope, with its line.

    "Directly" is the important word: a nested function or a helper class is
    not a case, and neither is a method of a class nested in a method.
    """
    return [
        (node.name, node.lineno)
        for node in body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    ]


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
        for name, _ in case_functions(tree.body):
            ids.add(f"{module_name}.{name}")
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for method, _ in case_functions(node.body):
                    ids.add(f"{module_name}.{node.name}.{method}")
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
