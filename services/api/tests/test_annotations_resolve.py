"""Every type annotation in the API's endpoint modules names something that is imported.

The API runs on Python 3.11, which looks an annotation up the moment a function is defined; newer Pythons (3.14, which this was developed on) look it up lazily, so a missing import
"works" in the tests and then crashes the API on start (a missing ``Any`` did exactly that). This resolves every annotation explicitly, so the tests catch it on any Python version.
"""

import importlib
import inspect
import pkgutil
import typing

import app.api.v1.endpoints as endpoints_pkg
import pytest


def _modules():
    for info in pkgutil.iter_modules(endpoints_pkg.__path__):
        yield info.name


@pytest.mark.parametrize("name", sorted(_modules()))
def test_every_annotation_in_the_module_resolves(name):
    module = importlib.import_module(f"app.api.v1.endpoints.{name}")
    unresolved = []
    for attr, obj in vars(module).items():
        if getattr(obj, "__module__", None) != module.__name__ or not (inspect.isfunction(obj) or inspect.isclass(obj)):
            continue
        targets = [obj]
        if inspect.isclass(obj):
            targets += [m for m in vars(obj).values() if inspect.isfunction(m)]
        for target in targets:
            try:
                typing.get_type_hints(target, include_extras=True)
            except NameError as exc:
                unresolved.append(f"{attr}: {exc}")
            except Exception:  # noqa: BLE001 - only a name that is not defined is this test's concern
                pass
    assert not unresolved, f"{name} uses names it does not import: {unresolved}"
