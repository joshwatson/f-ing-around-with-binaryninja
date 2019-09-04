import abc

from .errors import UnimplementedOperationError

from binaryninja import (ILRegister, LowLevelILInstruction,
                         LowLevelILOperation, LowLevelILOperationAndSize)


class Executor:
    @abc.abstractmethod
    def read_register(self, reg: str) -> int:
        pass

    @abc.abstractmethod
    def write_register(self, reg: str, value: int) -> None:
        pass

    @abc.abstractmethod
    def read_memory(self, address: int, size: int) -> int:
        pass

    @abc.abstractmethod
    def write_memory(self, address: int, value: int, size: int) -> None:
        pass

    @abc.abstractmethod
    def set_next_instr_index(self, il: LowLevelILInstruction, instr_index: int) -> None:
        pass

    @abc.abstractmethod
    def invoke_call(self, il: LowLevelILInstruction, dest: int) -> None:
        pass

    @abc.abstractmethod
    def invoke_return(self, target: int) -> None:
        pass

    def execute(self, il: LowLevelILInstruction):
        stack1 = il.prefix_operands
        stack2 = []

        while stack1:
            # print(f'stack1: {stack1}')
            # print(f'stack2: {stack2}')
            op: LowLevelILOperationAndSize = stack1.pop()

            if not isinstance(op, LowLevelILOperationAndSize):
                stack2.append(op)
                continue

            if op.operation == LowLevelILOperation.LLIL_SET_REG:
                dest = stack2.pop()
                value, _ = stack2.pop()
                self.write_register(dest.name, value)

            elif op.operation in (
                LowLevelILOperation.LLIL_CONST,
                LowLevelILOperation.LLIL_CONST_PTR,
            ):
                # nothing to do here, because the top of the stack
                # is an integer
                assert isinstance(stack2[-1], int)
                constant = stack2.pop()
                stack2.append((constant, op.size))

            elif op.operation == LowLevelILOperation.LLIL_REG:
                assert isinstance(stack2[-1], ILRegister)
                reg = stack2.pop()
                value = self.read_register(reg.name)
                stack2.append((value, op.size))

            elif op.operation == LowLevelILOperation.LLIL_LOAD:
                src, size = stack2.pop()
                result = self.read_memory(src, op.size)
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_STORE:
                dest, size = stack2.pop()
                src, size = stack2.pop()
                self.write_memory(dest, src, op.size)

            elif op.operation == LowLevelILOperation.LLIL_SUB:
                left, _ = stack2.pop()
                right, _ = stack2.pop()
                result = (left - right) & ((1 << (op.size * 8)) - 1)
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_ADD:
                left, _ = stack2.pop()
                right, _ = stack2.pop()
                result = (left + right) & ((1 << (op.size * 8)) - 1)
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_PUSH:
                value, _ = stack2.pop()
                sp = self.read_register(
                    il.function.source_function.arch.stack_pointer
                )
                self.write_memory(sp, value, op.size)
                self.write_register(
                    il.function.source_function.arch.stack_pointer,
                    sp - op.size
                )

            elif op.operation == LowLevelILOperation.LLIL_POP:
                sp = self.read_register(
                    il.function.source_function.arch.stack_pointer
                )
                result = self.read_memory(sp, op.size)

                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_CALL:
                dest, _ = stack2.pop()
                self.invoke_call(il, dest)

            elif op.operation == LowLevelILOperation.LLIL_GOTO:
                dest = stack2.pop()
                self.set_next_instr_index(il.function, dest)

            elif op.operation == LowLevelILOperation.LLIL_CMP_SGE:
                left, _ = stack2.pop()
                if left & (1 << ((op.size - 1) * 8)):
                    left += -(1 << (op.size * 8))
                right, _ = stack2.pop()
                if right & (1 << ((op.size - 1) * 8)):
                    right += -(1 << (op.size * 8))
                print(f'{left:x} s>= {right:x}')
                result = left >= right
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_CMP_E:
                left, _ = stack2.pop()
                if left & (1 << ((op.size - 1) * 8)):
                    left += -(1 << (op.size * 8))
                right, _ = stack2.pop()
                if right & (1 << ((op.size - 1) * 8)):
                    right += -(1 << (op.size * 8))
                print(f'{left:x} == {right:x}')
                result = left == right
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_CMP_NE:
                left, _ = stack2.pop()
                if left & (1 << ((op.size - 1) * 8)):
                    left += -(1 << (op.size * 8))
                right, _ = stack2.pop()
                if right & (1 << ((op.size - 1) * 8)):
                    right += -(1 << (op.size * 8))
                print(f'{left:x} == {right:x}')
                result = left != right
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_IF:
                condition, _ = stack2.pop()
                true = stack2.pop()
                false = stack2.pop()
                if condition:
                    self.set_next_instr_index(il.function, true)
                else:
                    self.set_next_instr_index(il.function, false)

            elif op.operation == LowLevelILOperation.LLIL_AND:
                left, _ = stack2.pop()
                right, _ = stack2.pop()

                result = left & right
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_OR:
                left, _ = stack2.pop()
                right, _ = stack2.pop()
                result = left | right
                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_SX:
                src, size = stack2.pop()

                if src & (1 << (size * 8 - 1)):
                    src |= ((1 << (op.size * 8)) - 1) ^ ((1 << (size * 8)) - 1)

                stack2.append((src, op.size))

            elif op.operation == LowLevelILOperation.LLIL_ROL:
                left, size = stack2.pop()
                right, size = stack2.pop()

                result = (left << right) & ((1 << op.size * 8) - 1)
                result |= (left & (((1 << op.size * 8) - 1) ^ ((1 << right) - 1))) >> ((op.size * 8) - right)

                stack2.append((result, op.size))

            elif op.operation == LowLevelILOperation.LLIL_RET:
                sp = self.read_register(
                    il.function.source_function.arch.stack_pointer
                )
                return_address = self.read_memory(
                    sp, il.function.source_function.arch.address_size
                )

                self.invoke_return(return_address)

            else:
                raise UnimplementedOperationError(op)

        # increment to the next IL instruction if it wasn't modified
        if il.instr_index == self.current_instr_index:
            self.set_next_instr_index(il.function, il.instr_index + 1)