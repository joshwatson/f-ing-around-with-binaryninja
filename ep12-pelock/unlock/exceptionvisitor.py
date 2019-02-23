from binaryninja import (
    MediumLevelILInstruction,
    RegisterValueType,
    Variable,
    SSAVariable,
    VariableSourceType,
    MediumLevelILOperation,
    LowLevelILOperation,
)

from .state import SEHState
from .bnilvisitor import BNILVisitor
from .logging import log_debug

class NullDerefVisitor(BNILVisitor):
    def visit_MLIL_SX(self, expr):
        return self.visit(expr.src)

    visit_MLIL_LOAD = visit_MLIL_SX

    def visit_MLIL_CONST_PTR(self, expr):
        return expr.constant

    visit_MLIL_CONST = visit_MLIL_CONST_PTR

class ExceptionVisitor(BNILVisitor):
    def __init__(self, unlock):
        self.unlock = unlock
        self.state = SEHState.NoException
        self.seh = []
        self.enter_location = None
        super().__init__()

    def visit_MLIL_STORE(self, expr):
        unlock = self.unlock

        log_debug("ExceptionVisitor.visit_MLIL_STORE")
        log_debug(f"{unlock.function.start:x} {self.state!r}")

        if self.state == SEHState.PushSeh:
            sp = unlock.function.get_reg_value_at(expr.address, unlock.view.arch.stack_pointer)
            seh = unlock.function.get_stack_contents_at(
                expr.address, sp.offset + unlock.address_size, unlock.address_size
            )
            if seh.type == RegisterValueType.ConstantValue:
                log_debug("pushing seh {seh.value:x}")
                self.seh.append(seh.value)
                self.state = SEHState.Seh
            else:
                # something else is going on here. stop so we can
                # examine it
                return False

        elif self.state == SEHState.InException:
            return self.visit_unwind(expr)

        elif self.state == SEHState.Unwinding and unlock.fs in expr.dest.prefix_operands:
            # Change our state in the state machine

            # Find all of the uses of the fs segment
            fs_uses = expr.function.get_var_uses(unlock.fs)

            # Collect the stack offset to find where the second pointer of the
            # exception handler frame was created
            max_offset = (float("-inf"), None)
            for use in fs_uses:
                fs_use_il = expr.function[use]

                # Get the previous push, and any math done on that push as well
                # so we can remove it
                saved_eh = unlock.function.get_reg_value_at(fs_use_il.address, "esp")
                max_offset = max(max_offset, (saved_eh.offset, fs_use_il))

            saved_eh_var = Variable(
                unlock.function, VariableSourceType.StackVariableSourceType, 0, max_offset[0]
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

            instr_to_queue = expr.function[fs_uses[0]]

            # NOP everything out
            # 1. NOP out the uses of the fs register
            for use in fs_uses:
                fs_use_il = expr.function[use]
                unlock.convert_to_nop(fs_use_il.address)

            # 2. NOP out the push of the saved exception handler
            for _def in saved_eh_defs:
                unlock.convert_to_nop(expr.function[_def].address)

            # 3. NOP out the enter instruction we used
            unlock.convert_to_nop(self.enter_location)

            # Move to the next state, where we look for the pop
            self.state = SEHState.LookingForPop

            # Find the next instruction to queue
            unlock.queue_prev_block(instr_to_queue)

            return True

    def visit_MLIL_SET_VAR(self, expr):
        unlock = self.unlock
        log_debug("ExceptionVisitor.visit_MLIL_SET_VAR")
        log_debug(f"{unlock.function.start:x} {self.state!r}")

        if self.state == SEHState.NoException and unlock.fs in expr.src.prefix_operands:
            self.state = SEHState.PushSeh
            return

        if self.state == SEHState.Seh and self.seh:
            if NullDerefVisitor().visit(expr.src) == 0:
                self.state = SEHState.InException
                target = self.seh.pop()
                if target:
                    log_debug(f"Manipulating the stack")
                    self.enter_location = expr.address
                    unlock.view.write(
                        expr.address,
                        unlock.view.arch.assemble(
                            f"enter 0xb4, 0\njmp 0x{target:x}", expr.address
                        ),
                    )
                    unlock.target_queue.put(target)
                    return True

            # not a null deref, so let's check the next instruction
            return

        elif self.state == SEHState.LookingForPop:
            log_debug(f"looking for pop: {expr}")
            if (
                expr.dest.storage == unlock.view.arch.get_reg_index("esp")
                and expr.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF
                and expr.src.llil.non_ssa_form.operation == LowLevelILOperation.LLIL_ADD
            ):
                log_debug("Pop found")
                self.state = SEHState.NoException
                unlock.convert_to_nop(expr.address)
                unlock.target_queue.put(expr.function[expr.instr_index + 1].address)
                return True
        else:
            return unlock.visit(expr.src)

    def visit_unwind(self, expr):
        log_debug("ExceptionVisitor.visit_unwind")
        log_debug(f"{self.unlock.function.start:x} {self.state!r}")

        unlock = self.unlock

        if expr.src.value.type not in (
            RegisterValueType.ConstantPointerValue,
            RegisterValueType.ConstantValue,
        ):
            return

        visitor = UnwindVisitor()
        is_stack_var = visitor.visit(expr)

        if is_stack_var is not False:
            log_debug("Stack manipulation found; Starting unwind...")
            self.state = SEHState.Unwinding
            next_il = expr.function[expr.instr_index + 1]
            unlock.convert_to_nop(is_stack_var)

            patch_value = unlock.view.arch.assemble(
                f"jmp 0x{expr.src.value.value:x}", next_il.address
            )
            if unlock.view.get_instruction_length(next_il.address) >= len(patch_value):
                unlock.view.write(next_il.address, patch_value)

                unlock.target_queue.put(next_il.address)
                unlock.convert_to_nop(expr.address)

                if hasattr(visitor, "nop_address"):
                    unlock.convert_to_nop(visitor.nop_address)

                return True
            else:
                log_debug(f"{next_il.address:x} is not big enough for a patch")
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
        if expr.constant == 0xB8:
            log_debug("Found the 0xb8")
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

    