from binaryninja import (
    MediumLevelILOperation,
    RegisterValueType,
    MediumLevelILInstruction,
    VariableSourceType
)

from ..bnilvisitor import BNILVisitor
from ..logging import log_debug


def analyze_unwind(self, expr: MediumLevelILInstruction):
    log_debug("analyze_unwind")

    if expr.src.value.type not in (
        RegisterValueType.ConstantPointerValue,
        RegisterValueType.ConstantValue,
    ):
        return False

    visitor = UnwindVisitor()
    is_stack_var = visitor.visit(expr)

    if is_stack_var is not False:
        log_debug("Stack manipulation found; Starting unwind...")
        self.in_exception = False
        self.unwinding = True
        next_il = expr.function[expr.instr_index + 1]

        self.view.convert_to_nop(is_stack_var)

        patch_value = self.view.arch.assemble(
            f"jmp 0x{expr.src.value.value:x}", next_il.address
        )
        if self.view.get_instruction_length(next_il.address) >= len(patch_value):
            self.view.write(
                next_il.address,
                patch_value,
            )

            self.target_queue.put(next_il.address)

            self.view.convert_to_nop(expr.address)

            if hasattr(visitor, 'nop_address'):
                self.view.convert_to_nop(visitor.nop_address)

            return True
        else:
            log_debug(f'{next_il.address:x} is not big enough for a patch')
            return False

    log_debug("This store does not manipulate the unwind.")
    return False


class UnwindVisitor(BNILVisitor):
    def visit_MLIL_STORE(self, expr):
        function = expr.function

        if expr.dest.operation != MediumLevelILOperation.MLIL_VAR:
            return False

        dest_ssa = expr.dest.ssa_form.src

        return self.visit(function[function.get_ssa_var_definition(dest_ssa)])

    def visit_MLIL_SET_VAR(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_ADD(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return left or right

    visit_MLIL_SUB = visit_MLIL_ADD

    def visit_MLIL_CONST(self, expr):
        if expr.constant == 0xb8:
            self.nop_address = expr.address
        return False

    def visit_MLIL_VAR(self, expr):
        function = expr.function
        var = expr.src
        if var.source_type == VariableSourceType.StackVariableSourceType:
            return expr.address
        else:
            var_ssa = expr.ssa_form.src
            return self.visit(function[function.get_ssa_var_definition(var_ssa)])

