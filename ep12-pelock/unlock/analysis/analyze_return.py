from binaryninja import (
    MediumLevelILOperation,
    RegisterValueType,
    Architecture,
    MediumLevelILInstruction,
    MediumLevelILFunction,
    log_warn,
)

from ..logging import log_debug

def analyze_return(self, expr: MediumLevelILInstruction):
    arch: Architecture = self.view.arch
    mmlil: MediumLevelILFunction = self.function.llil.mapped_medium_level_il

    # Step 1: retrieve address of the ret
    ret_addr = expr.address

    # Step 2: calculate the address to jump to
    current_sp: RegisterValueType = self.function.get_reg_value_at(
        ret_addr, arch.stack_pointer
    )

    if current_sp.type != RegisterValueType.StackFrameOffset:
        log_debug(f'{current_sp.type!r} != RegisterValueType.StackFrameOffset')
        return False

    current_sp: int = current_sp.offset

    next_jump_value: RegisterValueType = self.function.get_stack_contents_at(
        ret_addr, current_sp, arch.address_size
    )

    if next_jump_value.type == RegisterValueType.ConstantValue:
        next_jump_addr: int = next_jump_value.value
    else:
        log_debug(f"next_jump_value is not a constant: {next_jump_value.type!r}")
        return False

    # Step 3: identify the start of this primitive – we assume that the
    # return address is either pushed directly onto the stack, or it is
    # put on the stack and then some operation is performed on it, in which
    # the return address will always be on the left side of said operation.
    ret_il_ssa = expr.ssa_form
    jump_variable_ssa = ret_il_ssa.dest.src

    jump_variable_def = mmlil.get_ssa_var_definition(jump_variable_ssa)

    if jump_variable_ssa is None:
        log_debug("wtf why is this magically None?")
        log_debug(f"{ret_il_ssa}")
        return False

    jump_il = mmlil[jump_variable_def]
    while jump_il.src.operation != MediumLevelILOperation.MLIL_CONST:
        new_var_ssa = jump_il.src.left.ssa_form.src
        jump_il = mmlil[mmlil.get_ssa_var_definition(new_var_ssa)]

    # Step 4: Patch the binary to jump to the return address
    patch_addr = jump_il.address
    patch_value = arch.assemble(f"jmp 0x{next_jump_addr:x}", patch_addr)

    # Ensure there is enough space in this primitive to patch it
    if (ret_addr - patch_addr) < len(patch_value):
        log_warn(
            f"Not enough space to patch {patch_addr:x}; need {len(patch_value)} bytes"
        )
        return False

    self.view.write(patch_addr, patch_value)
    log_debug(f"Patched {patch_addr:x} with new jump target")

    # log_debug(f"adding {next_jump_addr:x} to target queue")
    # self.target_queue.put(next_jump_addr)

    # return True

    return self.queue_prev_block(jump_il)
