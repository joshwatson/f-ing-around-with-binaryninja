from binaryninja import (
    BinaryView,
    Endianness,
    ImplicitRegisterExtend,
    SegmentFlag,
    LowLevelILInstruction,
    LowLevelILFunction,
    HighlightStandardColor,
)
from binaryninjaui import UIContext
from emulator import Executor, InvalidMemoryError, UninitializedRegisterError, InvalidInstructionError


class BinaryNinjaEmulator(Executor):
    def __init__(self, view: BinaryView, ui_widget):
        self.view = view
        self.ui_widget = ui_widget
        self.view.session_data["emulator"] = self
        self.current_instr_index = None
        self.current_highlight = None
        self.current_function = None
        self.hooks = {}

    def read_register(self, reg_name: str) -> int:
        regs = dict(self.view.session_data.get("emulator.registers", {}))

        register = self.view.arch.regs.get(reg_name)

        if register is None:
            raise UninitializedRegisterError(register)

        full_width_reg = register.full_width_reg

        if regs[full_width_reg] is None:
            raise UninitializedRegisterError(register)

        if reg_name == full_width_reg:
            return regs[reg_name]

        offset = register.offset
        size = register.size

        mask = (1 << (offset * 8)) - 1
        mask ^= (1 << ((size + offset) * 8)) - 1

        value = regs[full_width_reg]

        value &= mask

        value >>= offset * 8

        return value

    def write_register(self, reg_name: str, value: int):
        registers = self.view.session_data.get("emulator.registers", [])
        if not registers:
            self.view.session_data["emulator.registers"] = registers

        regs = {
            r[0]: (i, r[1])
            for i, r in enumerate(
                self.view.session_data.get("emulator.registers", [])
            )
        }
        register = self.view.arch.regs[reg_name]

        size = register.size
        offset = register.offset
        extend = register.extend
        full_width_reg = register.full_width_reg

        if full_width_reg == reg_name:
            if not regs:
                regs[reg_name] = (0, None)
            self.view.session_data["emulator.registers.model"].startUpdate()
            registers[regs[reg_name][0]] = (reg_name, value)
            self.view.session_data["emulator.registers.model"].endUpdate()
            return

        full_width_value = self.read_register(full_width_reg)

        mask = (1 << (offset * 8)) - 1
        mask ^= (1 << ((size + offset) * 8)) - 1
        shifted_value = value << (offset * 8)
        masked_value = shifted_value & mask

        full_width_size = self.view.arch.regs[full_width_reg].size

        full_width_mask = (1 << (full_width_size * 8)) - 1
        full_width_mask ^= mask

        if extend == ImplicitRegisterExtend.NoExtend:
            full_width_value = masked_value | (
                full_width_mask & full_width_value
            )

        elif extend == ImplicitRegisterExtend.ZeroExtendToFullWidth:
            full_width_value = masked_value | (
                full_width_value & ((1 << ((size + offset) * 8)) - 1)
            )

        elif extend == ImplicitRegisterExtend.SignExtendToFullWidth:
            sign_bit = shifted_value & (1 << ((size + offset - 1) * 8))
            full_width_value = masked_value | (
                full_width_value & ((1 << ((size + offset) * 8)) - 1)
            )
            if sign_bit:
                full_width_value |= full_width_mask ^ (
                    (1 << ((size + offset) * 8)) - 1
                )

        if not regs:
            regs[full_width_reg] = (full_width_reg, full_width_value)

        self.view.session_data["emulator.registers.model"].startUpdate()
        registers[regs[full_width_reg][0]] = (full_width_reg, full_width_value)
        self.view.session_data["emulator.registers.model"].endUpdate()

    def read_memory(self, address: int, size: int) -> int:
        memory = self.view.session_data.get("emulator.memory.view")
        if memory is None:
            raise KeyError("Memory View not found")

        value = memory.read(address, size)

        if value is None or len(value) < size:
            raise InvalidMemoryError(address, size)

        return int.from_bytes(
            value,
            (
                "little"
                if self.view.endianness == Endianness.LittleEndian
                else "big"
            ),
        )

    def write_memory(self, address: int, value: int, size: int) -> None:
        memory = self.view.session_data.get("emulator.memory.view")
        if memory is None:
            raise KeyError("Memory View not found")

        value_bytes = value.to_bytes(
            size,
            (
                "little"
                if self.view.endianness == Endianness.LittleEndian
                else "big"
            ),
        )

        if memory.write(address, value_bytes) != len(value_bytes):
            raise InvalidMemoryError(address, len(value_bytes))

    def map_memory(self, start: int, length: int, flags: SegmentFlag) -> bool:
        memory = self.view.session_data.get("emulator.memory.view")
        if memory is None:
            raise KeyError("Memory View not found")

        data_offset = len(memory.parent_view)
        memory.parent_view.write(data_offset, bytes(length))
        memory.add_user_segment(start, length, data_offset, length, flags)
        return True

    def unmap_memory(self, start: int, length: int) -> None:
        memory: BinaryView = self.view.session_data.get("emulator.memory.view")
        if memory is None:
            raise KeyError("Memory View not found")

        # TODO
        # Implement page tables oh god
        # Otherwise we're gonna blow up memory every time we map
        # something and unmap it
        self.view.session_data["emulator.memory.model"].beginResetModel()
        memory.remove_user_segment(start, length)
        self.view.session_data["emulator.memory.model"].endResetModel()

    def execute(self, il: LowLevelILInstruction):
        function = self.hooks.get(il.function, {})
        hook = function.get(il.instr_index)

        if hook is None:
            super().execute(il)
            return

        ctx = UIContext.contextForWidget(
            self.view.session_data['emulator.memory.widget']
        )

        handler = ctx.contentActionHandler()
        handler.executeAction(hook)

        if self.current_instr_index == il.instr_index:
            self.set_next_instr_index(il.function, il.instr_index + 1)

    def set_next_instr_index(
        self, llil: LowLevelILFunction, instr_index: int
    ) -> None:
        self.current_instr_index = instr_index

        if self.current_highlight is not None:
            function, addr = self.current_highlight

            function.set_user_instr_highlight(
                addr, HighlightStandardColor.NoHighlightColor
            )

        llil.source_function.set_user_instr_highlight(
            llil[instr_index].address,
            HighlightStandardColor.OrangeHighlightColor,
        )
        self.current_highlight = (
            llil.source_function, llil[instr_index].address
        )

    def invoke_call(self, il: LowLevelILInstruction, dest: int) -> None:
        # emulate a call:
        # 1. get return address
        # 2. store return address at stack pointer
        # 3. decrement stack pointer by address_size
        # 4. set self.current_instr_index to 0

        # Step 1: get return address
        return_address = self.current_function[il.instr_index + 1].address

        # Step 2: store return address at stack pointer
        sp = self.read_register(self.view.arch.stack_pointer)
        self.write_memory(sp, return_address, self.view.arch.address_size)

        # Step 3: decrement the stack pointer by address_size
        self.write_register(
            self.view.arch.stack_pointer, sp - self.view.arch.address_size
        )

        # Step 4: set self.current_instr_index to 0
        self.current_instr_index = 0
        self.current_function = self.view.get_function_at(dest).llil

        self.set_next_instr_index(self.current_function, 0)

    def invoke_return(self, target: int) -> None:
        functions = self.view.get_functions_containing(target)
        if functions is None or len(functions) == 0:
            raise InvalidInstructionError(target)

        function = functions[0]

        llil = function.llil

        instr = function.get_low_level_il_at(target)

        self.set_next_instr_index(llil, instr.instr_index)

    def add_hook(self, instruction: LowLevelILInstruction, hook: str):
        function = self.hooks.get(instruction.function, {})
        function[instruction.instr_index] = hook
        self.hooks[instruction.function] = function
