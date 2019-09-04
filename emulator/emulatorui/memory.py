from binaryninja import (BackgroundTaskThread, BinaryDataNotification,
                         BinaryView, BinaryViewType, SegmentFlag, Settings)
from PySide2.QtCore import QAbstractTableModel, Qt
from PySide2.QtGui import QFont
from PySide2.QtWidgets import QHeaderView, QTableView


class EmulatorMemoryModel(QAbstractTableModel, BinaryDataNotification):
    def __init__(self, view: BinaryView):
        QAbstractTableModel.__init__(self)
        BinaryDataNotification.__init__(self)
        self.view = view
        self.memory_view = view.session_data.get('emulator.memory.view')

        self.font_name = Settings().get_string('ui.font.name')
        self.font_size = Settings().get_integer('ui.font.size')

        if self.memory_view is None:
            return

        self.memory_view.register_notification(self)

        if self.view.session_data.get('emulator.memory') is None:
            self.view.session_data['emulator.memory'] = [
                seg for seg in self.memory_view.segments
            ]

    def rowCount(self, parent):
        rows = self.view.session_data.get('emulator.memory')
        if rows is None:
            return 0

        return len(rows)

    def columnCount(self, parent):
        return 5

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.CheckStateRole:
            return None

        if role == Qt.FontRole:
            return QFont(self.font_name, self.font_size)

        memory = self.view.session_data.get('emulator.memory')
        if memory is None:
            return

        row = memory[index.row()]

        if index.column() == 0:
            return hex(row.start)

        elif index.column() == 1:
            return hex(row.end)

        elif index.column() == 2:
            return hex(row.data_offset)

        elif index.column() == 3:
            return hex(row.data_length)

        elif index.column() == 4:
            return (
                f'{"r" if row.readable else "-"}'
                f'{"w" if row.writable else "-"}'
                f'{"x" if row.executable else "-"}'
            )

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Orientation.Vertical:
            return None

        if role != Qt.DisplayRole:
            return None

        return ['Start', 'End', 'Data Offset', 'Data Length', 'Flags'][
            section
        ]

    def data_inserted(self, view, offset, length):
        self.beginResetModel()
        self.view.session_data['emulator.memory'] = [
            seg for seg in self.memory_view.segments
        ]
        self.endResetModel()
        return super().data_inserted(view, offset, length)

    def data_removed(self, view, offset, length):
        self.beginResetModel()
        self.view.session_data['emulator.memory'] = [
            seg for seg in self.memory_view.segments
        ]
        self.endResetModel()
        return super().data_removed(view, offset, length)

    def data_written(self, view, offset, length):
        self.beginResetModel()
        self.view.session_data['emulator.memory'] = [
            seg for seg in self.memory_view.segments
        ]
        self.endResetModel()
        return super().data_written(view, offset, length)


class EmulatorMemoryView(QTableView):
    def __init__(self, parent, view):
        super().__init__(parent)
        self.parent = parent
        self.view = view
        self.view.session_data['emulator.memory.widget'] = self
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)


def rewrite_segments(view: BinaryView):
    class EmulatorBackgroundTask(BackgroundTaskThread):
        def __init__(self, view):
            self.view = view
            super().__init__()

        def run(self):
            self.view.update_analysis_and_wait()

    new_raw_view = BinaryView()
    current_addr = 0
    for segment in view.segments:
        segment_data = view.read(segment.start, segment.data_length)
        segment_data += b'\x00'*(len(segment) - segment.data_length)
        new_raw_view.write(current_addr, segment_data)
        current_addr += len(segment_data)

    print(f'{len(new_raw_view):x}')

    new_view = BinaryViewType['Mapped'].create(new_raw_view)
    new_view.remove_auto_segment(0, len(new_raw_view))
    t = EmulatorBackgroundTask(new_view)
    t.start()
    t.join()
    print(new_view.segments)

    current_addr = 0
    for segment in view.segments:
        print(f'{segment.start:x}->{len(segment):x} | {current_addr:x}->{len(segment):x}')

        new_view.add_user_segment(
            segment.start,
            len(segment),
            current_addr,
            len(segment),
            (
                (SegmentFlag.SegmentReadable if segment.readable else 0) |
                (SegmentFlag.SegmentWritable if segment.writable else 0) |
                (SegmentFlag.SegmentExecutable if segment.executable else 0)
            )
        )

        current_addr += len(segment)

    return new_view
