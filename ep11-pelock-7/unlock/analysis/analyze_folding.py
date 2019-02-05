from binaryninja import log_debug, LowLevelILOperation, Variable, VariableSourceType, SSAVariable, SSARegister

def analyze_constant_folding(self, expr):
    log_debug("analyze_constant_folding")

    llil = expr.function.non_ssa_form

    reg_value = expr.value

    log_debug(f"folding {expr.src} into {reg_value.value:x}")

    reg_ssa = expr.src

    reg_def = llil[llil.get_ssa_reg_definition(reg_ssa)]

    log_debug(f'register defined at {reg_def.address:x}')

    dependent_regs = []

    next_il = reg_def

    while next_il:
        log_debug(f'{next_il}: {next_il.src.prefix_operands}')
        for operand in next_il.ssa_form.src.prefix_operands:
            if isinstance(operand, SSARegister) and operand.reg.index == reg_ssa.reg.index:
                next_il = llil[llil.get_ssa_reg_definition(operand)]
                dependent_regs.append(next_il.address)
                break
        else:
            next_il = None

    # Convert the final one into the assignment
    patch_value = self.view.arch.assemble(
        f'mov {expr.src.reg.name}, 0x{reg_value.value:x}',
        reg_def.address
    )

    if self.view.get_instruction_length(reg_def.address) < len(patch_value):
        log_debug(f"{reg_def.address:x} is too few bytes to patch")
        return False

    # First, convert to NOPs and *then* write the patch
    self.view.convert_to_nop(reg_def.address)
    self.view.write(reg_def.address, patch_value)

    # Nop all of the previous assignments
    for addr in dependent_regs:
        self.view.convert_to_nop(addr)

    # place the last address on the queue, to fold
    # all the NOPs and GOTOs
    if dependent_regs:
        self.target_queue.put(dependent_regs[-1])
        return True
    else:
        return



def analyze_goto_folding(self, expr):
    log_debug("analyze_goto_folding")
    llil = expr.function.llil

    llil_jump = expr.llil.non_ssa_form
    log_debug(f"llil_jump = {llil_jump}")

    if llil_jump is None:
        log_debug("We don't have a corresponding LLIL instr?!")
        return False

    final_target = llil[llil_jump.dest]
    log_debug(f"final_target = {final_target}")

    while final_target.operation == LowLevelILOperation.LLIL_GOTO:
        final_target = llil[final_target.dest]
        log_debug(f"final_target = {final_target}")

    if llil_jump.dest == final_target.instr_index:
        return final_target.mmlil.instr_index

    patch_value = self.view.arch.assemble(
        f"jmp 0x{final_target.address:x}", expr.address
    )

    self.view.write(expr.address, patch_value)

    self.target_queue.put(final_target.address)

    return False
