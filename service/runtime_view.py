import importlib
from typing import TYPE_CHECKING

from contracts import NativeRuntime

_backend = importlib.import_module("container")

if not isinstance(_backend, NativeRuntime):
    raise RuntimeError("Native runtime does not implement the required interface")

runtime: NativeRuntime = _backend

if TYPE_CHECKING:
    import runtime as production
    from contracts import ProductionRuntime

    _production_contract: ProductionRuntime = production
