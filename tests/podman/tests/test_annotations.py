"""Every public annotation in the harness resolves, in all five modules.

`from __future__ import annotations` defers an annotation's evaluation to the point
where something asks for it, and the thing that asks is rarely the import. So an
annotation can name a type the module never imported, every case that imports the
module passes, `python3 -m unittest` passes, and `make verify` passes -- because the
gate runs no Python linter. The suite was green over exactly that in
`lib/snapshot.py`: `SubprocessRunner.__init__` annotated
`extra_env: Mapping[str, str] | None` and the module imported
`Callable, Iterable, Sequence`.

It is not inert. `typing.get_type_hints` raised `NameError`, and it takes out every
annotation-derived tool for the module at once -- a validator, a documentation
generator, anything that builds a signature. The cost of the check is one call per
public callable, which is why it is here rather than in a linter nobody has added.

**All five modules, not one.** The finding was specific to `lib/snapshot.py` and the
first version of this case checked `lib/snapshot.py` alone, which closed the instance
and left the identical exposure in the other four -- all of which also defer their
annotations. A check that names one file is a check that has to be extended every time
somebody remembers, and this project's record is that nobody remembers.

The list is written out rather than globbed, because the modules are five known
things and a glob over `lib/*.py` would silently skip `run.py`, which lives one
directory up. The `CONTROL` below is what makes "it found nothing" mean something.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tests" / "podman"

sys.path.insert(0, str(HARNESS / "lib"))

# (module name, path, is it a package directory's script) -- `run.py` is loaded from
# its path because it is a script, not an importable module name.
MODULES = [
    ("snapshot", HARNESS / "lib" / "snapshot.py"),
    ("podman", HARNESS / "lib" / "podman.py"),
    ("images", HARNESS / "lib" / "images.py"),
    ("report", HARNESS / "lib" / "report.py"),
]


def _load_run():
    spec = importlib.util.spec_from_file_location("run", HARNESS / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run"] = module
    spec.loader.exec_module(module)
    return module


def public_targets(module) -> list:
    """The callables whose annotations a consumer might resolve.

    A module's `__all__` when it has one, because that is the surface it declares;
    otherwise every public name. A class contributes itself, its `__init__` and its
    `__call__`, because those are where a signature usually lives -- the finding in
    `lib/snapshot.py` was on a constructor, which `vars(module)` scanning by name
    alone would have missed if the class had not been in `__all__`.
    """
    import inspect

    names = getattr(module, "__all__", None) or [
        name for name in vars(module) if not name.startswith("_")
    ]
    targets = []
    for name in names:
        member = getattr(module, name, None)
        if inspect.isclass(member):
            targets.append((f"{name}", member))
            for method in ("__init__", "__call__"):
                if method in vars(member):
                    targets.append((f"{name}.{method}", vars(member)[method]))
        elif callable(member):
            targets.append((name, member))
    return targets


class PublicAnnotationTest(unittest.TestCase):
    """Every public annotation in the harness names something that is in scope."""

    def test_no_public_annotation_names_a_type_the_module_does_not_import(self):
        import typing

        modules = [(name, importlib.import_module(name)) for name, _ in MODULES]
        modules.append(("run", _load_run()))

        unresolved: list[str] = []
        checked = 0
        for module_name, module in modules:
            for label, target in public_targets(module):
                checked += 1
                try:
                    typing.get_type_hints(target)
                except NameError as error:
                    unresolved.append(f"{module_name}.{label}: {error}")
        self.assertEqual(
            unresolved, [],
            "a public annotation names something the module does not import, so anything that "
            "resolves hints -- a validator, a doc generator, get_type_hints itself -- raises "
            f"NameError on this module ({checked} targets checked):\n" + "\n".join(unresolved),
        )

    def test_the_check_actually_visits_the_modules_it_names(self):
        """121 targets across five modules today; a check that visits nothing is green.

        The number is not the point and must not be held as a floor -- that is the
        shape of check the previous round removed. The point is that each module
        contributed *something*, so an import that silently failed cannot turn this
        case into a no-op: `podman` is imported by name and `run` is loaded from its
        path, and either can fail without raising.
        """
        import typing

        for module_name, path in MODULES:
            with self.subTest(module=module_name):
                self.assertTrue(
                    path.is_file(), f"{module_name} is named here but {path} is not there"
                )
                module = importlib.import_module(module_name)
                targets = public_targets(module)
                self.assertTrue(
                    targets, f"{module_name} contributed no targets, so nothing was checked"
                )
                for label, target in targets:
                    typing.get_type_hints(target)
        self.assertTrue((HARNESS / "run.py").is_file())
        self.assertTrue(
            public_targets(_load_run()), "run.py contributed no targets, so nothing was checked"
        )

    def test_the_control_the_check_is_not_vacuous(self):
        """A hint that cannot resolve has to be found, or the cases above prove nothing.

        A local function annotated with a name that is not in scope is the smallest
        thing that raises `NameError` from `get_type_hints`. It is here so a future
        edit that turns the check into a no-op -- a `try` that swallows, a list that
        comes back empty, a target list that is empty -- is caught. The second half
        is the negative: a hint that *does* resolve must come back with no complaint,
        or a case that expects `NameError` is satisfied by any code at all.
        """
        import typing

        unresolvable: dict = {}
        exec(  # noqa: S102 - the smallest possible unresolvable annotation
            "def annotated(value: NotImportedAnywhere | None = None):\n    return value\n",
            unresolvable,
        )
        with self.assertRaises(NameError):
            typing.get_type_hints(unresolvable["annotated"])

        resolvable: dict = {}
        exec(  # noqa: S102 - and the smallest possible resolvable one
            "def annotated(value: int | None = None):\n    return value\n",
            resolvable,
        )
        self.assertEqual(typing.get_type_hints(resolvable["annotated"]), {"value": int | None})
