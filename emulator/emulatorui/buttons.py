import time

from binaryninja import (AddressField, BackgroundTaskThread, ChoiceField,
                         HighlightStandardColor, Settings,
                         execute_on_main_thread_and_wait, get_form_input, log)
from binaryninjaui import FileContext, LinearView, UIContext, ViewFrame
from emulator.errors import (UnimplementedOperationError,
                             UninitializedRegisterError)
from PySide2.QtCore import SIGNAL, QObject
from PySide2.QtGui import QFont, QFontMetrics
from PySide2.QtWidgets import QHBoxLayout, QPushButton, QWidget

from .hooks import add_hook, remove_hook
from .memory import EmulatorMemoryModel, rewrite_segments
from .stack import EmulatorStackModel
from .registers import RegisterEmulatorModel


class EmulatorRunTaskThread(BackgroundTaskThread):
    def __init__(self, widget, emulator, il):
        self.widget = widget
        self.emulator = emulator
        self.starting_il = il
        super().__init__()

    def run(self):
        il = self.starting_il
        view = self.emulator.view
        self.emulator.set_next_instr_index(il.function, il.instr_index)
        self.widget.running = True
        while self.widget.running:
            if (il.function, il.instr_index) in self.emulator.breakpoints:
                il.function.source_function.set_user_instr_highlight(
                    il.address,
                    HighlightStandardColor.NoHighlightColor
                )
                view.navigate(view.file.view, il.address)
                break

            if self.widget.execute_one_instruction(self.emulator, il):
                il = self.emulator.current_function[
                    self.emulator.current_instr_index
                ]
            else:
                break

        print('Complete')


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
        self.view = view
        self.view.session_data['emulator.buttons.widget'] = self
        self.running = False

        self.reset_button = EmulatorButton(view, '♻️', self.reset)
        self.reset_button.setToolTip('Reset emulator')
        self.run_button = EmulatorButton(view, '▶️', self.run)
        self.run_button.setToolTip('Run emulator')
        self.run_to_button = EmulatorButton(view, '⏭', self.run_to)
        self.run_to_button.setToolTip('Run to set location')
        self.set_stop_button = EmulatorButton(view, '⏹', self.set_stop)
        self.set_stop_button.setToolTip('Set stop location on address')
        self.pause_button = EmulatorButton(view, '⏸', self.pause)
        self.pause_button.setToolTip('Pause emulator')
        self.step_button = EmulatorButton(view, '⏯', self.step)
        self.step_button.setToolTip('Step one disassembly instruction')
        self.map_memory_button = EmulatorButton(view, '🗺', self.map_memory)
        self.map_memory_button.setToolTip('Map virtual memory')
        self.unmap_memory_button = EmulatorButton(view, '🚮', self.unmap_memory)
        self.unmap_memory_button.setToolTip('Unmap virtual memory')
        self.view_memory_button = EmulatorButton(view, '📈', self.view_memory)
        self.view_memory_button.setToolTip('Open memory view')
        self.add_hook_button = EmulatorButton(view, '🎣', self.add_hook)
        self.add_hook_button.setToolTip('Add instruction hook')
        self.remove_hook_button = EmulatorButton(view, '🐟', self.remove_hook)
        self.remove_hook_button.setToolTip('Remove instruction hook')

        self.button_layout = QHBoxLayout(self)
        self.button_layout.addWidget(self.reset_button)
        self.button_layout.addWidget(self.run_button)
        self.button_layout.addWidget(self.pause_button)
        self.button_layout.addWidget(self.run_to_button)
        self.button_layout.addWidget(self.set_stop_button)
        self.button_layout.addWidget(self.step_button)
        self.button_layout.addWidget(self.map_memory_button)
        self.button_layout.addWidget(self.unmap_memory_button)
        self.button_layout.addWidget(self.view_memory_button)
        self.button_layout.addWidget(self.add_hook_button)
        self.button_layout.addWidget(self.remove_hook_button)

    def get_context(self):
        ctx = self.parent().view_frame.actionContext()

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
                il = ctx.mediumLevelILFunction[
                    ctx.instrIndex
                ].llil.non_ssa_form
        elif ctx.function is not None:
            function = ctx.function
            il = function.get_low_level_il_at(ctx.address)

        return il

    def run(self):
        emulator = self.view.session_data['emulator']

        il = self.get_context()

        task = EmulatorRunTaskThread(self, emulator, il)
        task.start()

    def pause(self):
        self.running = False

    def run_to(self):
        pass

    def set_stop(self):
        il = self.get_context()

        emulator = self.view.session_data['emulator']

        emulator.breakpoints.add((il.function, il.instr_index))

        il.function.source_function.set_auto_instr_highlight(
            il.address,
            HighlightStandardColor.RedHighlightColor
        )

    def reset(self):
        self.running = False
        emulator = self.view.session_data['emulator']
        if (emulator.current_function is not None and
                emulator.current_instr_index is not None):
            current_il = emulator.current_function[
                emulator.current_instr_index
            ]

            emulator.current_function.source_function.set_auto_instr_highlight(
                current_il.address,
                HighlightStandardColor.NoHighlightColor
            )

        self.view.session_data["emulator.memory.view"] = rewrite_segments(
            self.view
        )
        model = EmulatorMemoryModel(self.view)
        self.view.session_data["emulator.memory.model"] = model
        self.view.session_data["emulator.memory.widget"].setModel(model)

        model = EmulatorStackModel(self.view)
        self.view.session_data['emulator.stack.widget'].setModel(model)

        model = RegisterEmulatorModel(self.view)
        self.view.session_data['emulator.registers.widget'].setModel(model)
        self.view.session_data['emulator.registers.widget'].update()

    def step(self):
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
                il = ctx.mediumLevelILFunction[
                    ctx.instrIndex
                ].llil.non_ssa_form
        elif ctx.function is not None:
            function = ctx.function
            il = function.get_low_level_il_at(ctx.address)

        emulator.set_next_instr_index(
            il.function, il.instr_index
        )

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
            if not self.execute_one_instruction(emulator, next_il):
                break
            if emulator.current_instr_index < len(emulator.current_function):
                next_il = emulator.current_function[
                    emulator.current_instr_index
                ]
        else:
            emulator.view.navigate(emulator.view.file.view, next_il.address)

    def execute_one_instruction(self, emulator, il):
        try:
            emulator.execute(il)
        except UninitializedRegisterError as e:
            print(f'UninitializedRegisterError: {e.reg}')
            return False
        except UnimplementedOperationError as e:
            print(f'UnimplementedOperationError: {e.op!r}')
            return False

        return True

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

        ctx = UIContext.activeContext()
        linear_view = LinearView(memory_view, None)
        memory_view.register_notification(linear_view)
        ctx.createTabForWidget('Emulator Memory', linear_view)

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

        add_hook(emulator, llil[instr_index])

    def remove_hook(self):
        emulator = self.parent().view.session_data['emulator']

        ctx = UIContext.activeContext()

        content = ctx.contentActionHandler()
        action_context = content.actionContext()

        llil = action_context.lowLevelILFunction
        instr_index = action_context.instrIndex

        if None in (llil, instr_index) or instr_index == 0xffffffffffffffff:
            log.log_alert('LLIL Function/Instruction not selected!')
            return

        remove_hook(emulator, llil[instr_index])
