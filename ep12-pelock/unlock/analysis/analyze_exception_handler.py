from binaryninja import (
    MediumLevelILInstruction,
    RegisterValueType,
    Variable,
    SSAVariable,
    VariableSourceType,
    MediumLevelILOperation,
    LowLevelILOperation,
)

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
    log_debug("analyze_exception_handler_set_var")

    if self.fs in expr.src.prefix_operands:
        self.push_seh = True
        return

    if self.seh:
        if NullDerefVisitor().visit(expr.src) == 0:
            self.in_exception = True
            target = self.seh.pop()
            if target:
                self.view.write(
                    expr.address,
                    self.view.arch.assemble(f"jmp 0x{target:x}", expr.address),
                )
                self.target_queue.put(target)
                return True

        # not a null deref, so let's check the next instruction
        return

    elif self.look_for_pop:
        if (
            expr.dest.storage == self.view.arch.get_reg_index("esp")
            and expr.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF
            and expr.src.llil.non_ssa_form.operation == LowLevelILOperation.LLIL_ADD
        ):
            self.look_for_pop = False
            self.view.convert_to_nop(expr.address)
            self.target_queue.put(expr.function[expr.instr_index + 1].address)
            return True
    else:
        return self.visit(expr.src)


def analyze_exception_handler_store(self, expr: MediumLevelILInstruction):
    log_debug("analyze_exception_handler_store")

    if self.push_seh:
        sp = self.function.get_reg_value_at(expr.address, self.view.arch.stack_pointer)
        seh = self.function.get_stack_contents_at(
            expr.address, sp.offset + self.address_size, self.address_size
        )
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
        # Change our state in the state machine
        self.unwinding = False

        # Find all of the uses of the fs segment
        fs_uses = expr.function.get_var_uses(self.fs)

        # Collect the stack offset to find where the second pointer of the
        # exception handler frame was created
        max_offset = (float("-inf"), None)
        for use in fs_uses:
            fs_use_il = expr.function[use]

            # Get the previous push, and any math done on that push as well
            # so we can remove it
            saved_eh = self.function.get_reg_value_at(fs_use_il.address, "esp")
            max_offset = max(max_offset, (saved_eh.offset, fs_use_il))

        saved_eh_var = Variable(
            self.function, VariableSourceType.StackVariableSourceType, 0, max_offset[0]
        )
        saved_eh_ssa = SSAVariable(
            saved_eh_var, max_offset[1].get_ssa_var_version(saved_eh_var)
        )

        saved_eh_defs = [expr.function.get_ssa_var_definition(saved_eh_ssa)]
        current_def = expr.function[saved_eh_defs[0]]

        while saved_eh_var in current_def.src.prefix_operands:
            saved_eh_defs.append(
                expr.function.get_ssa_var_definition(
                    SSAVariable(saved_eh_var, saved_eh_ssa.version - 1)
                )
            )
            current_def = expr.function[saved_eh_defs[-1]]

        # NOP everything out
        # 1. NOP out the uses of the fs register
        for use in fs_uses:
            fs_use_il = expr.function[use]
            self.view.convert_to_nop(fs_use_il.address)

        # 2. NOP out the push of the saved exception handler
        for _def in saved_eh_defs:
            self.view.convert_to_nop(expr.function[_def].address)

        # Move to the next state, where we look for the pop
        self.look_for_pop = True
        self.target_queue.put(expr.function[expr.instr_index + 1].address)

        return True
