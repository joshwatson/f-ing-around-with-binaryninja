from binaryninja import MediumLevelILInstruction, Type

from ..bnilvisitor import BNILVisitor
from ..logging import log_debug

class JumpVisitor(BNILVisitor):
    def visit_MLIL_JUMP(self, expr):
        return self.visit(expr.dest)

    def visit_MLIL_LOAD(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_CONST_PTR(self, expr):
        return expr.constant

    visit_MLIL_CONST = visit_MLIL_CONST_PTR

def analyze_indirect_jump(self, expr: MediumLevelILInstruction):
    log_debug("analyze_indirect_jump")
    jump_value = JumpVisitor().visit(expr)

    if jump_value is None:
        log_debug("Jump target not constant")
        return False

    indirect_type = Type.int(self.view.arch.address_size, False)
    indirect_type.const = True

    if not self.view.is_offset_readable(jump_value):
        log_debug("Jump target is not readable")
        return False

    self.view.define_user_data_var(jump_value, indirect_type)
    self.target_queue.put(expr.address)
    return False