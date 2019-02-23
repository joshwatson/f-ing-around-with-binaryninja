# This script requires python 3
__all__ = ["UnlockVisitor", "SEHState"]

from binaryninja import PluginCommand, BinaryView, Function
from .unlockvisitor import UnlockVisitor
from .state import SEHState

def run_unlock(view: BinaryView, function: Function):
    u = UnlockVisitor(function, function.start)
    u.start()

PluginCommand.register_for_function(
    "Run unlock",
    "Run unlock",
    run_unlock,
    is_valid=lambda v, f: "obfuscated" in v.file.filename,
)