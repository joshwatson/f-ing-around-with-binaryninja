from binaryninja import (Architecture, InstructionInfo, InstructionTextToken,
                         RegisterInfo, InstructionTextTokenType, BranchType, ILRegister)
from collections import defaultdict

opcodes = defaultdict(
    lambda: 'hlt', 
    {
        1: "set",
        2: "get",
        3: "xor"
    }
)

class VMArch(Architecture):
    name = "VMArch"

    address_size = 1
    default_int_size = 1
    max_instr_length = 3

    stack_pointer = 's'

    regs = {
        'k': RegisterInfo('k', 1),
        'c':   RegisterInfo('c', 1),
        's':   RegisterInfo('s', 1)
    }

    def parse_instruction(self, data, addr):
        opcode, offset, value = data[:3]

        return opcode, offset, value, 3

    def get_instruction_info(self, data, addr):
        opcode, offset, value, length = self.parse_instruction(data, addr)

        info = InstructionInfo()
        info.length = length

        if opcodes[opcode] == 'hlt':
            info.add_branch(BranchType.FunctionReturn)

        return info

    def get_instruction_text(self, data, addr):
        opcode, offset, value, length = self.parse_instruction(data, addr)

        tokens = []

        op = opcodes[opcode]

        # create the opcode token
        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.InstructionToken,
                f'{op:<.6s}', value=opcode
            )
        )

        # create the offset token
        if op != 'hlt':
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken,
                    f'  {offset}', value=offset, size=1
                )
            )

        if op == 'set':
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    f'  {value}', value=value, size=1
                )
            )

        return tokens, length

    def get_instruction_low_level_il(self, data, addr, il):
        opcode, offset, value, length = self.parse_instruction(data, addr)

        op = opcodes[opcode]

        # [offset].b = value
        if op == 'set':
            il.append(
                il.store(1, il.const(1, offset), il.const(1, value))
            )

        # c = [offset].b
        elif op == 'get':
            il.append(
                il.set_reg(
                    1, 'c',
                    il.load(
                        1, il.const(1, offset)
                    )
                )
            )

        # [offset].b = [offset].b ^ c
        elif op == 'xor':
            il.append(
                il.set_reg(
                    1, 'k',
                    il.load(1, il.const(1, offset))
                )
            )
            il.append(
                il.store(
                    1, il.const(1, offset),
                    il.xor_expr(
                        1, il.reg(1, 'k'), il.reg(1, 'c')
                    )
                )
            )
        elif op == 'hlt':
            il.append(il.no_ret())

        return length

VMArch.register()