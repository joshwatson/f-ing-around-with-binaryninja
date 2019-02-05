from binaryninja import MediumLevelILInstruction, RegisterValueType

from ..bnilvisitor import BNILVisitor
from ..logging import log_debug
from .analyze_unwind import analyze_unwind

class NullDerefVisitor(BNILVisitor):
    def visit_MLIL_SX(self, expr):
        return self.visit(expr.src)

    visit_MLIL_LOAD = visit_MLIL_SX

    def visit_MLIL_CONST_PTR(self, expr):
        return expr.constant

    visit_MLIL_CONST = visit_MLIL_CONST_PTR

def analyze_exception_handler_set_var(self, expr: MediumLevelILInstruction):
    log_debug('analyze_exception_handler_set_var')

    if self.fs in expr.src.prefix_operands:
        log_debug('!!!!! FOUND FS !!!!!')
        self.push_seh = True
        return

    if self.seh:
        if NullDerefVisitor().visit(expr.src) == 0:
            self.in_exception = True
            target = self.seh.pop()
            if target:
                self.view.write(expr.address, self.view.arch.assemble(f"jmp 0x{target:x}", expr.address))
                self.target_queue.put(target)
                return True

        # not a null deref, so let's check the next instruction
        return

    else:
        return self.visit(expr.src)

def analyze_exception_handler_store(self, expr: MediumLevelILInstruction):
    log_debug('analyze_exception_handler_store')

    if self.push_seh:
        sp = self.function.get_reg_value_at(expr.address, self.view.arch.stack_pointer)
        seh = self.function.get_stack_contents_at(expr.address, sp.offset + self.address_size, self.address_size)
        if seh.type == RegisterValueType.ConstantValue:
            self.seh.append(seh.value)
            self.push_seh = False
        else:
            # something else is going on here. stop so we can
            # examine it
            return False

    elif self.in_exception:
        return self.analyze_unwind(expr)

    elif self.unwinding and self.fs in expr.dest.prefix_operands:
        log_debug('This is where you should nop fs')
        fs_uses = expr.function.get_var_uses(self.fs)
        self.unwinding = False
        for use in fs_uses:
            fs_use_il = expr.function[use]
            self.view.convert_to_nop(fs_use_il.address)
        return