from binaryninja import (
    BinaryView,
    LowLevelILFunction,
    LowLevelILInstruction,
    PluginCommand,
)
from binaryninjaui import DockHandler, LinearView

from . import hooks
from . import emulatorui
from . import memory
from .memory import EmulatorMemoryModel, rewrite_segments
from .stack import EmulatorStackModel

emulatorui.addDockWidget()
memory.addDockWidget()


def load_emulator(view, il):
    emulator = view.session_data.get("emulator")
    if emulator is None:
        return

    dock_handler = DockHandler.getActiveDockHandler()
    if dock_handler is None:
        return

    view.session_data["emulator.memory.view"] = rewrite_segments(view)
    model = EmulatorMemoryModel(view)
    view.session_data["emulator.memory.model"] = model
    view.session_data["emulator.memory.widget"].setModel(model)

    model = EmulatorStackModel(view)
    view.session_data['emulator.stack.widget'].setModel(model)

    memory_dock_widget = view.session_data['emulator.memory.dockWidget']
    memory_dock_widget.linear_view = LinearView(
        view.session_data['emulator.memory.view'], None
    )
    memory_dock_widget.layout.addWidget(memory_dock_widget.linear_view)

    dock_handler.setVisible("BNIL Emulator", True)


def add_hook(view: BinaryView, instruction: LowLevelILInstruction) -> None:
    emulator = view.session_data.get("emulator")
    if emulator is None:
        return

    hooks.add_hook(emulator, instruction)


def add_function_hook(view: BinaryView, function: LowLevelILFunction) -> None:
    emulator = view.session_data.get("emulator")
    if emulator is None:
        return

    hooks.add_function_hook(emulator, function)


def remove_hook(view: BinaryView, instruction: LowLevelILInstruction) -> None:
    emulator = view.session_data.get("emulator")
    if emulator is None:
        return

    hooks.remove_hook(emulator, instruction)


def remove_function_hook(
    view: BinaryView, function: LowLevelILFunction
) -> None:
    emulator = view.session_data.get("emulator")
    if emulator is None:
        return

    hooks.remove_function_hook(emulator, function)


PluginCommand.register_for_low_level_il_function(
    "Emulator\\Load", "Load Emulator", load_emulator
)

PluginCommand.register_for_low_level_il_instruction(
    "Emulator\\Add Hook",
    "Add an emulator hook for this LLIL instruction",
    add_hook,
)

PluginCommand.register_for_low_level_il_function(
    "Emulator\\Add Function Hook",
    "Add an emulator hook for this LLIL function",
    add_function_hook,
)

PluginCommand.register_for_low_level_il_instruction(
    "Emulator\\Remove Hook",
    "Remove an emulator hook for this LLIL instruction",
    remove_hook,
)

PluginCommand.register_for_low_level_il_function(
    "Emulator\\Remove Function Hook",
    "Remove an emulator hook for this LLIL function",
    remove_function_hook,
)


def map_memory(view, start, length, flags):
    emulator = view.session_data.get("emulator")
    if emulator is None:
        return

    emulator.map_memory(start, length, flags)
