from binaryninja import (Architecture, BinaryReader, BinaryWriter,
                         PluginCommand, log_alert)

class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):
        method_name = 'visit_{}'.format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            value = None
        return value

class VMVisitor(BNILVisitor):
    def __init__(self, view):
        super(VMVisitor, self).__init__()

        self.view = view
        self.bw = BinaryWriter(view)
        self.br = BinaryReader(view)

        self.regs = {r: 0 for r in Architecture['VMArch'].regs}

    def visit_LLIL_STORE(self, expr):
        dest = self.visit(expr.dest)
        src = self.visit(expr.src)

        if None not in (dest, src):
            self.bw.seek(dest)
            self.bw.write8(src)

    def visit_LLIL_CONST(self, expr):
        return expr.constant

    def visit_LLIL_CONST_PTR(self, expr):
        return expr.constant

    def visit_LLIL_SET_REG(self, expr):
        dest = expr.dest.name
        src = self.visit(expr.src)

        if src is not None:
            self.regs[dest] = src

    def visit_LLIL_LOAD(self, expr):
        src = self.visit(expr.src)

        if src is not None:
            self.br.seek(src)
            return self.br.read8()

    def visit_LLIL_XOR(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if None not in (left, right):
            return left ^ right

    def visit_LLIL_REG(self, expr):
        src = expr.src

        return self.regs[src.name]

    def visit_LLIL_NORET(self, expr):
        log_alert("VM Halted.")

def run_emulator(view):
    v = VMVisitor(view)
    for il in view.llil_instructions:
        v.visit(il)

PluginCommand.register(
    'Emulate VMArch',
    'Emulate VMArch LLIL',
    run_emulator,
    lambda view: view.arch == Architecture['VMArch']
)
