from binaryninja import (
    MediumLevelILInstruction,
    BinaryView,
    Function,
    Type,
    MediumLevelILOperation,
    LowLevelILOperation,
    RegisterValueType,
    Variable,
    VariableSourceType,
    SSAVariable,
    MediumLevelILBasicBlock,
    BinaryDataNotification
)

from ..bnilvisitor import BNILVisitor
from ..logging import log_debug
from ..state import SEHState


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


def analyze_possible_call(self, expr: MediumLevelILInstruction):
    log_debug("analyze_possible_call")

    if self.phase == 1:
        return

    # When we're in an exception, there's extra executable addresses on the stack.
    # So, if we're in an exception-based obfuscation, there won't be any calls.
    if self.exception_visitors[self.function.start].state != SEHState.NoException:
        return

    log_debug(f'{self.function.start:x} {self.exception_visitors[self.function.start].state!r}')

    if expr.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
        return

    if expr.llil.dest.operation != LowLevelILOperation.LLIL_REG_SSA:
        return

    target_reg = expr.llil.dest.src.reg.name

    current_esp = self.function.get_reg_value_at(expr.address, "esp")

    if current_esp.type != RegisterValueType.StackFrameOffset:
        return

    ret_addr = self.function.get_stack_contents_at(expr.address, current_esp.offset, 4)

    if ret_addr.type not in (
        RegisterValueType.ConstantValue,
        RegisterValueType.ConstantPointerValue,
    ):
        return

    if not self.view.is_offset_executable(ret_addr.value):
        return

    log_debug(f"{ret_addr.value:x} is executable")

    # If we got to here, then this is a tail call. Let's define the call
    patch_value = self.view.arch.assemble(f"call {target_reg}", expr.address)

    if self.view.get_instruction_length(expr.address) < len(patch_value):
        log_debug(f"{expr.address:x} is too small for call instruction")
        return

    self.view.write(expr.address, patch_value)

    # Find the return address variable and remove it
    return_addr_var = Variable(
        self.function, VariableSourceType.StackVariableSourceType, 0, current_esp.offset
    )

    # get the IL instructions of the definitions instead of the indices
    return_addr_definitions = list(
        map(
            expr.function.__getitem__,
            expr.function.get_var_definitions(return_addr_var),
        )
    )

    current_bb = next(
        bb
        for bb in expr.function.basic_blocks
        if bb.start <= expr.instr_index < bb.end
    )

    for instr in return_addr_definitions:
        # get the IL basic block of this definition
        instr_bb: MediumLevelILBasicBlock = next(
            bb
            for bb in expr.function.basic_blocks
            if bb.start <= instr.instr_index < bb.end
        )

        if instr_bb in current_bb.dominators:
            self.convert_to_nop(instr.address)

    # queue the return address for analysis
    self.queue_prev_block(return_addr_definitions[0])

    # queue the function start as well
    from ..exceptionvisitor import ExceptionVisitor

    self.exception_visitors[expr.dest.constant] = ExceptionVisitor(self)
    self.target_queue.put(expr.dest.constant)

    # Change the phase back to 1
    self.prev_phase = self.phase
    self.phase = 1

    return True