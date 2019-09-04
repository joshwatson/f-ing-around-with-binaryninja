from binaryninjaui import DockContextHandler, DockHandler
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QGridLayout, QWidget

from .binja_emulator import BinaryNinjaEmulator
from .buttons import EmulatorButtonsWidget
from .memory import EmulatorMemoryView
from .registers import RegisterEmulatorView


class EmulatorDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, view):
        try:
            QWidget.__init__(self, parent)
            DockContextHandler.__init__(self, self, name)

            layout = QGridLayout(self)
            self.registers_view = RegisterEmulatorView(None, view)
            self.memory_view = EmulatorMemoryView(None, view)

            # TODO
            # Implement a view that shows the top 0x100 bytes of the stack
            # OR....OR...let's make a "local variables" view

            self.button_widget = EmulatorButtonsWidget(self, view)

            layout.addWidget(self.button_widget, 0, 0, Qt.AlignLeft)
            layout.addWidget(self.memory_view, 1, 0)
            layout.addWidget(self.registers_view, 1, 1)

            self.registers_view.horizontalHeader().setStretchLastSection(True)

            self.view = view
            self.view_frame = None
            self.emulator = BinaryNinjaEmulator(view, self)

            dock_handler = DockHandler.getActiveDockHandler()
            dock_handler.setVisible('BNIL Emulator', False)
        except Exception as e:
            print(e)

    def notifyViewChanged(self, view_frame):
        self.view_frame = view_frame

    @staticmethod
    def create_widget(name, parent, data=None):
        return EmulatorDockWidget(parent, name, data)


def addDockWidget():
    if len(QApplication.allWidgets()) == 0:
        return

    mw = QApplication.allWidgets()[0].window()
    dock_handler = mw.findChild(DockHandler, '__DockHandler')
    dock_handler.addDockWidget(
        "BNIL Emulator",
        EmulatorDockWidget.create_widget,
        Qt.TopDockWidgetArea,
        Qt.Horizontal,
        False
    )
