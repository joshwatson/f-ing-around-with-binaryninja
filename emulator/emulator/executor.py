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
    def read_memory(self, address: int, size: int) -> bytes:
        pass

    @abc.abstractmethod
    def write_memory(self, address: int, value: bytes) -> None:
        pass

    def execute(self, il: LowLevelILInstruction):
        stack1 = il.prefix_operands
        stack2 = []

        while stack1:
            print(f'stack1: {stack1}')
            print(f'stack2: {stack2}')
            op: LowLevelILOperationAndSize = stack1.pop()
            print(f'op: {op}')

            if not isinstance(op, LowLevelILOperationAndSize):
                stack2.append(op)
                continue

            if op.operation == LowLevelILOperation.LLIL_SET_REG:
                dest = stack2.pop()
                value = stack2.pop()
                self.write_register(dest.name, value)

            elif op.operation == LowLevelILOperation.LLIL_CONST:
                # nothing to do here, because the top of the stack
                # is an integer
                assert isinstance(stack2[-1], int)

            elif op.operation == LowLevelILOperation.LLIL_REG:
                assert isinstance(stack2[-1], ILRegister)
                reg = stack2.pop()
                value = self.read_register(reg.name)
                stack2.append(value)

            elif op.operation == LowLevelILOperation.LLIL_LOAD:
                src = stack2.pop()
                result = self.read_memory(src, op.size)
                stack2.append(result)

            elif op.operation == LowLevelILOperation.LLIL_STORE:
                dest = stack2.pop()
                src = stack2.pop()
                self.write_memory(dest, src)

            else:
                raise UnimplementedOperationError(op)
