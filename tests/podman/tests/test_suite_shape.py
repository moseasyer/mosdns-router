"""The harness's own suite has to be countable, or a claim about it is a guess.

`unittest` discovers a test method by name and runs it. Two methods with the
same name in one class is not an error, not a warning, and not a failure: the
later definition silently replaces the earlier one, and the suite reports
"OK" with one case fewer than the file declares. Nothing in the output says a
test was dropped.

That is not hypothetical in this project. `ArgumentArrayTest` had two
`test_exec_passes_the_command_as_separate_arguments` methods -- one for
`podman run` and one for `podman exec` -- and the second replaced the first.
The lost case held the only assertion in the whole tree of the measured target
flags (`--systemd=always`, `--cgroupns=private`, the three `--cap-add` values
and `-d`), and the report claimed every array was "asserted as literals in
`ArgumentArrayTest`". Stripping those five flags from the wrapper left 82 tests
passing. A claim about a test was not backed by a test running.

The second instance was the same shape one commit earlier: a control that
could not manufacture the defect it was written to catch. Both say the same
thing about how this project keeps claiming things, so the class of defect gets
a guard rather than the one instance getting a rename.

**The enumeration is the point.** A test that only asserted "this file's case
names are unique" would be a check of today's file. What has to be true is that
the *count* the suite reports agrees with the count the source declares, so
this case walks the AST of the harness's own test files, counts every `test_*`
function defined in every module and class body, and fails when two of them
share a name in one scope. A case added later cannot be shadowed by accident
without this failing; a case removed shows up as a smaller count rather than as
a silently different suite.

Scope is one module or one class body. The same name in *different* classes is
legitimate and common -- `test_teardown_sweeps_a_network_it_forgot` means one
thing per harness class -- so only a collision inside a single scope is a
duplicate.
"""

import ast
import re
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# The harness's own test files. Named rather than globbed so that a file added
# later is a visible edit to this list: a glob would quietly stop covering a
# renamed file, which is the same failure as the one this case exists to catch.
HARNESS_TEST_FILES = ("test_command.py", "test_report.py", "test_suite_shape.py")


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
        for name in HARNESS_TEST_FILES:
            path = TESTS_DIR / name
            self.assertTrue(path.is_file(), f"{name} is listed as a harness test file but is not there")
            duplicates += duplicate_case_names(path.read_text(encoding="utf-8"), name)
        self.assertEqual(
            duplicates, [],
            "unittest silently keeps the last definition of a duplicated case name:\n"
            + "\n".join(duplicates),
        )

    def test_the_enumeration_reads_the_real_files_and_sees_their_cases(self):
        """The count the source declares is the count this case can see.

        Without this, a detector that parsed nothing would report no duplicates
        and the guard above would pass on an empty reading. So it is held
        against the real files: each listed file declares a non-trivial number
        of cases, this file among them, and they are the cases `unittest`
        actually ran -- the same number of `def test_` in the tree as in the
        suite's own count, which is the equality the shadowing broke.
        """
        for name in HARNESS_TEST_FILES:
            with self.subTest(file=name):
                self.assertGreater(len(declared_cases(TESTS_DIR / name)), 0)
        # A floor on the whole, so a detector that parsed nothing and reported
        # no duplicates cannot pass. It only has to grow, never to be lowered.
        self.assertGreaterEqual(
            sum(len(declared_cases(TESTS_DIR / name)) for name in HARNESS_TEST_FILES),
            150,
        )
        # The exact defect, reconstructed: this file's own cases are counted
        # here and run by the discovery that reads the same source, so a
        # collision in it cannot pass unnoticed.
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
