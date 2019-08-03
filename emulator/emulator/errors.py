class UninitializedRegisterError(Exception):
    def __init__(self, reg):
        self.reg = reg
        super().__init__()


class UnimplementedOperationError(Exception):
    def __init__(self, op):
        self.op = op
        super().__init__()
