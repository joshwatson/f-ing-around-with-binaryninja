class UninitializedRegisterError(Exception):
    def __init__(self, reg):
        self.reg = reg
        super().__init__()


class UnimplementedOperationError(Exception):
    def __init__(self, op):
        self.op = op
        super().__init__()


class InvalidInstructionError(Exception):
    def __init__(self, instr):
        self.instr = instr
        super().__init__()


class InvalidMemoryError(Exception):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
