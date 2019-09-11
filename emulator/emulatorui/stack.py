from binaryninja import (BinaryDataNotification, BinaryReader,
                         BinaryView, BinaryViewType, Settings)
from PySide2.QtCore import QAbstractTableModel, Qt
from PySide2.QtGui import QFont
from PySide2.QtWidgets import QHeaderView, QTableView


class EmulatorStackModel(QAbstractTableModel, BinaryDataNotification):
    def __init__(self, view: BinaryView):
        QAbstractTableModel.__init__(self)
        BinaryDataNotification.__init__(self)
        try:
            self.view = view
            self.view.session_data['emulator.stack.model'] = self

            self.memory_view = view.session_data.get('emulator.memory.view')

            self.font_name = Settings().get_string('ui.font.name')
            self.font_size = Settings().get_integer('ui.font.size')

            if self.memory_view is None:
                return

            self.memory_view.register_notification(self)

            self.br = BinaryReader(self.memory_view, self.view.endianness)

            if self.view.address_size == 1:
                self.br.read_ptr = self.br.read8
            elif self.view.address_size == 2:
                self.br.read_ptr = self.br.read16
            elif self.view.address_size == 4:
                self.br.read_ptr = self.br.read32
            elif self.view.address_size == 8:
                self.br.read_ptr = self.br.read64
        except Exception as e:
            print(e.msg)

        self.stack = []

    def rowCount(self, parent):
        return 0x100 / self.view.address_size

    def columnCount(self, parent):
        return 2

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.CheckStateRole:
            return None

        if role == Qt.FontRole:
            return QFont(self.font_name, self.font_size)

        size = len(self.stack)

        if 0 == size or size < index.row():
            return

        return hex(self.stack[index.row()][index.column()])

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Orientation.Vertical:
            return None

        if role != Qt.DisplayRole:
            return None

        return ['Address', 'Value'][
            section
        ]

    def setData(self, index, value, role=Qt.EditRole):
        if self.view.arch is None:
            return False

        emulator = self.view.session_data['emulator']

        if value.startswith('0x'):
            try:
                value = int(value, 16)
            except ValueError:
                return False
        elif value.isnumeric():
            value = int(value)
        else:
            return False

        offset = self.stack[index.row()][0]

        emulator.write_memory(offset, value, self.view.address_size)

        return True

    def flags(self, index):
        if index.column() == 1:
            return Qt.ItemIsEditable | Qt.ItemIsEnabled | Qt.ItemIsSelectable
        else:
            return Qt.NoItemFlags

    def data_written(self, view: BinaryView, offset: int, length: int) -> None:
        sp = self.view.arch.stack_pointer

        emulator = self.view.session_data['emulator']

        try:
            stack_pointer = emulator.read_register(sp)
        except Exception as e:
            print(e)
            self.stack = []
            return

        if offset > stack_pointer + 0x100 or offset < stack_pointer:
            return

        self.update(stack_pointer)

    def update(self, stack_pointer):
        self.beginResetModel()
        self.br.seek(stack_pointer)

        self.stack = []
        for i in range(0, 0x100, self.view.address_size):
            self.stack.append((self.br.offset, self.br.read_ptr()))
        self.endResetModel()


class EmulatorStackView(QTableView):
    def __init__(self, parent, view):
        super().__init__(parent)
        self.parent = parent
        self.view = view
        self.view.session_data['emulator.stack.widget'] = self
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
