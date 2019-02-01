from binaryninja import log_debug, LowLevelILOperation


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
