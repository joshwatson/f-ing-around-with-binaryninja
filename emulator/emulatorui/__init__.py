from binaryninja import PluginCommand, worker_enqueue, BackgroundTaskThread
from binaryninjaui import DockHandler

from .emulatorui import addDockWidget
from .memory import rewrite_segments, EmulatorMemoryModel

addDockWidget()


def load_emulator(view):
    emulator = view.session_data.get('emulator')
    if emulator is None:
        return

    dock_handler = DockHandler.getActiveDockHandler()
    if dock_handler is None:
        return

    view.session_data['emulator.memory.view'] = rewrite_segments(view)
    model = EmulatorMemoryModel(view)
    view.session_data['emulator.memory.model'] = model
    view.session_data['emulator.memory.widget'].setModel(
        model
    )

    dock_handler.setVisible('BNIL Emulator', True)


PluginCommand.register(
    'Emulator\\Load',
    'Load Emulator',
    load_emulator
)


def map_memory(view, start, length, flags):
    emulator = view.session_data.get('emulator')
    if emulator is None:
        return

    emulator.map_memory(start, length, flags)
