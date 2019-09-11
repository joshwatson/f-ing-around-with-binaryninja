from PySide2.QtWidgets import QTableView
from PySide2.QtCore import QAbstractTableModel, Qt
from PySide2.QtGui import QFont
from binaryninja import Settings


# TODO
# Handle temp registers
class RegisterEmulatorModel(QAbstractTableModel):
    def __init__(self, view):
        super().__init__()
        self.view = view

        if view.arch is None:
            view.session_data['emulator.registers'] = []

        view.session_data['emulator.registers'] = [
            (r, 0) for r in view.arch.full_width_regs
        ]

        view.session_data['emulator.registers.model'] = self

        self.font_name = Settings().get_string('ui.font.name')
        self.font_size = Settings().get_integer('ui.font.size')

    def rowCount(self, parent):
        if self.view.arch is None:
            return 0
        return len(self.view.arch.full_width_regs)

    def columnCount(self, parent):
        return 2

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.CheckStateRole:
            return None

        if role == Qt.FontRole:
            return QFont(self.font_name, self.font_size)

        regs = self.view.session_data['emulator.registers']
        if len(regs) == 0 and index.row() == 0:
            return None

        if regs[index.row()][index.column()] is None:
            return None

        elif index.column() == 0:
            return regs[index.row()][0]
        else:
            return hex(regs[index.row()][1])

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation != Qt.Orientation.Horizontal:
            return None

        if role != Qt.DisplayRole:
            return None

        if section == 0:
            return 'Register'
        elif section == 1:
            return 'Value'
        else:
            return None

    def setData(self, index, value, role=Qt.EditRole):
        if self.view.arch is None:
            return False

        emulator = self.view.session_data['emulator']
        regs = self.view.session_data['emulator.registers']

        if value.startswith('0x'):
            try:
                value = int(value, 16)
            except ValueError:
                return False
        elif value.isnumeric():
            value = int(value)
        else:
            return False

        emulator.write_register(regs[index.row()][0], value)
        return True

    def flags(self, index):
        if index.column() == 1:
            return Qt.ItemIsEditable | Qt.ItemIsEnabled | Qt.ItemIsSelectable
        elif index.row() >= len(self.view.session_data['emulator.registers']):
            return Qt.ItemIsEditable | Qt.ItemIsEnabled | Qt.ItemIsSelectable
        else:
            return Qt.NoItemFlags

    def startUpdate(self):
        self.beginResetModel()

    def endUpdate(self):
        self.endResetModel()


class RegisterEmulatorView(QTableView):
    def __init__(self, parent, view):
        super().__init__(parent)
        self.parent = parent
        self.view = view
        self.setModel(RegisterEmulatorModel(view))
        self.horizontalHeader().show()
        self.view.session_data['emulator.registers.widget'] = self
