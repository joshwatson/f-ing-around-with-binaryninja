from PySide2.QtWidgets import QHBoxLayout, QWidget, QPushButton
from PySide2.QtCore import SIGNAL, QObject
from PySide2.QtGui import QFont, QFontMetrics
from binaryninja import Settings, get_form_input, AddressField, ChoiceField, log, HighlightStandardColor
from binaryninjaui import FileContext, UIContext, ViewFrame
from emulator.errors import UninitializedRegisterError, UnimplementedOperationError


class EmulatorButton(QPushButton):
    def __init__(self, view, label, callback):
        super().__init__(label)
        self.callback = callback
        self.view = view

        font_name = Settings().get_string('ui.font.name')
        font_size = Settings().get_integer('ui.font.size')
        button_font = QFont(font_name, font_size)
        fm = QFontMetrics(button_font)
        self.setFont(button_font)
        self.setFixedWidth(fm.horizontalAdvance(label) + 10)

        QObject.connect(self, SIGNAL('clicked()'), self.callback)


class EmulatorButtonsWidget(QWidget):
    def __init__(self, parent, view):
        super().__init__(parent)

        self.start_button = EmulatorButton(view, '⏯', self.start)
        self.map_memory_button = EmulatorButton(view, '🗺', self.map_memory)
        self.unmap_memory_button = EmulatorButton(view, '🚮', self.unmap_memory)
        self.view_memory_button = EmulatorButton(view, '📈', self.view_memory)
        self.add_hook_button = EmulatorButton(view, '🎣', self.add_hook)

        self.button_layout = QHBoxLayout(self)
        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.map_memory_button)
        self.button_layout.addWidget(self.unmap_memory_button)
        self.button_layout.addWidget(self.view_memory_button)
        self.button_layout.addWidget(self.add_hook_button)

    def start(self):
        ctx = self.parent().view_frame.actionContext()
        emulator = self.parent().emulator

        if ctx.lowLevelILFunction is not None:
            function = ctx.lowLevelILFunction
            if ctx.instrIndex == 0xffffffffffffffff:
                il = function[0]
            else:
                il = function[ctx.instrIndex]
        elif ctx.mediumLevelILFunction is not None:
            if ctx.instrIndex == 0xffffffffffffffff:
                il = ctx.mediumLevelILFunction[0].llil.non_ssa_form
            else:
                il = ctx.mediumLevelILFunction[ctx.instrIndex].llil.non_ssa_form
        elif ctx.function is not None:
            function = ctx.function
            il = function.get_low_level_il_at(ctx.address)

        emulator.set_next_instr_index(
            il.function, il.instr_index
        )
        emulator.current_function = il.function

        il_start = il.instr_index
        exits = il.function.source_function.get_low_level_il_exits_at(
            il.address
        )
        il_exit = max(
            exits
        ) if exits else il_start

        next_il = il
        while (il.function == emulator.current_function and
                il_start <= emulator.current_instr_index <= il_exit):

            try:
                emulator.execute(next_il)
            except UninitializedRegisterError as e:
                print(f'UninitializedRegisterError: {e.reg}')
                break
            except UnimplementedOperationError as e:
                print(f'UnimplementedOperationError: {e.op!r}')
                break

            next_il = emulator.current_function[emulator.current_instr_index]
        else:
            emulator.view.navigate(emulator.view.file.view, next_il.address)

    def map_memory(self):
        start = AddressField('Start (hex):')
        length = AddressField('Length (hex):')
        flags = ChoiceField(
            'Flags',
            [
                '---',
                '--x',
                '-w-',
                '-wx',
                'r--',
                'r-x',
                'rw-',
                'rwx'
            ]
        )
        get_form_input([start, length, flags], 'Map Memory')
        self.parent().emulator.map_memory(
            start.result,
            length.result,
            flags.result
        )

    def unmap_memory(self):
        start = AddressField('Start (hex):')
        length = AddressField('Length (hex):')
        get_form_input([start, length], 'Unmap Memory')

        self.parent().emulator.unmap_memory(start.result, length.result)

    def view_memory(self):
        memory_view = self.parent().view.session_data['emulator.memory.view']

        fc = FileContext(memory_view.file, memory_view)
        vf = ViewFrame(None, fc, 'Hex')

        ctx = UIContext.activeContext()
        ctx.createTabForWidget('Emulator Memory', vf)

    def add_hook(self):
        emulator = self.parent().view.session_data['emulator']

        ctx = UIContext.activeContext()

        content = ctx.contentActionHandler()
        action_context = content.actionContext()

        llil = action_context.lowLevelILFunction
        instr_index = action_context.instrIndex

        if None in (llil, instr_index) or instr_index == 0xffffffffffffffff:
            log.log_alert('LLIL Function/Instruction not selected!')
            return

        handler = ctx.globalActions()
        hook_options = [
            a
            for a in handler.getAllValidActions()
            if 'Snippets\\' in a and
            'emulator' in a.lower()
        ]
        snippets = ChoiceField(
            'Snippets:',
            hook_options
        )

        get_form_input([snippets], 'Add Hook')

        choice = hook_options[snippets.result]

        instruction = llil[instr_index]

        emulator.add_hook(instruction, choice)

        instruction.function.source_function.set_auto_instr_highlight(
            instruction.address,
            HighlightStandardColor.BlackHighlightColor
        )
