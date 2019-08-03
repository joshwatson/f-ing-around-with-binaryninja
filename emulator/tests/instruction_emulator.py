from typing import Dict, Tuple, Union

from binaryninja import (Architecture, BinaryView,
                         ImplicitRegisterExtend)
from emulator import Executor, State
from emulator.errors import UninitializedRegisterError


class InstructionEmulator(Executor):
    def __init__(
        self,
        view: BinaryView,
        regs: Dict[str, int] = None,
        memory: Union[Dict[Tuple[int, int], bytes], None] = None
    ):
        if regs is None:
            regs = {}
        if memory is None:
            memory = {}
        self._state = State(view, regs, memory)

    def read_register(self, reg_name: str) -> int:
        register = self._state.view.arch.regs[reg_name]

        if reg_name not in self._state.regs:
            raise UninitializedRegisterError(register)

        full_width_reg = register.full_width_reg

        if reg_name == full_width_reg:
            return self._state.regs[reg_name]

        offset = register.offset
        size = register.size

        mask = (1 << (offset * 8)) - 1
        mask ^= (1 << ((size + offset) * 8)) - 1

        value = self._state.regs[full_width_reg]

        value &= mask

        value >>= offset * 8

        return value

    def write_register(self, reg_name: str, value: int):
        register = self._state.view.arch.regs[reg_name]

        size = register.size
        offset = register.offset
        extend = register.extend
        full_width_reg = register.full_width_reg

        if full_width_reg == reg_name:
            self._state.regs[reg_name] = value
            return

        full_width_value = self.read_register(full_width_reg)

        mask = (1 << (offset * 8)) - 1
        mask ^= (1 << ((size + offset) * 8)) - 1
        shifted_value = value << (offset * 8)
        masked_value = shifted_value & mask

        full_width_size = self._state.view.arch.regs[full_width_reg].size

        full_width_mask = (1 << (full_width_size * 8)) - 1
        full_width_mask ^= mask

        if extend == ImplicitRegisterExtend.NoExtend:
            full_width_value = (
                masked_value | (full_width_mask & full_width_value)
            )

        elif extend == ImplicitRegisterExtend.ZeroExtend:
            full_width_value = (
                masked_value | (
                    full_width_value & ((1 << ((size + offset) * 8)) - 1)
                )
            )

        elif extend == ImplicitRegisterExtend.SignExtend:
            sign_bit = shifted_value & (1 << ((size + offset - 1) * 8))
            full_width_value = (
                masked_value | (
                    full_width_value & ((1 << ((size + offset) * 8)) - 1)
                )
            )
            if sign_bit:
                full_width_value |= full_width_mask ^ ((1 << ((size + offset) * 8)) - 1)

        self._state.regs[full_width_reg] = full_width_value


if __name__ == '__main__':
    bv = BinaryView()

    # bv.write(0, b'\x89\xd8\x90\x90\x90')
    # bv.write(0, b'\xb8\x01\x00\x00\x00')
    bv.write(0, b'\x01 \xa0\xe3')

    # bv.platform = Architecture['x86'].standalone_platform
    bv.platform = Architecture['armv7'].standalone_platform

    bv.create_user_function(0)

    bv.update_analysis_and_wait()

    function = bv.get_function_at(0)

    emu = InstructionEmulator(bv, {'r2': 1337})

    print(emu._state.regs)

    emu.execute(function.llil[0])

    print(emu._state.regs)
