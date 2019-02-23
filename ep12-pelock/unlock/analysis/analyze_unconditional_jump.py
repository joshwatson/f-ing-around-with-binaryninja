from binaryninja import (
    MediumLevelILOperation,
    MediumLevelILFunction,
    RegisterValueType,
    Variable,
    ILBranchDependence,
    MediumLevelILInstruction,
)
from itertools import chain
from ..bnilvisitor import BNILVisitor
from ..logging import log_debug

cmp_pairs = {
    MediumLevelILOperation.MLIL_CMP_E: MediumLevelILOperation.MLIL_CMP_NE,
    MediumLevelILOperation.MLIL_CMP_NE: MediumLevelILOperation.MLIL_CMP_E,
    MediumLevelILOperation.MLIL_CMP_UGT: MediumLevelILOperation.MLIL_CMP_ULE,
    MediumLevelILOperation.MLIL_CMP_ULE: MediumLevelILOperation.MLIL_CMP_UGT,
    MediumLevelILOperation.MLIL_CMP_UGE: MediumLevelILOperation.MLIL_CMP_ULT,
    MediumLevelILOperation.MLIL_CMP_ULT: MediumLevelILOperation.MLIL_CMP_UGE,
    MediumLevelILOperation.MLIL_CMP_SGE: MediumLevelILOperation.MLIL_CMP_SLT,
    MediumLevelILOperation.MLIL_CMP_SLT: MediumLevelILOperation.MLIL_CMP_SGE,
    MediumLevelILOperation.MLIL_CMP_SGT: MediumLevelILOperation.MLIL_CMP_SLE,
    MediumLevelILOperation.MLIL_CMP_SLE: MediumLevelILOperation.MLIL_CMP_SGT,
    MediumLevelILOperation.MLIL_NOT: MediumLevelILOperation.MLIL_VAR,
    MediumLevelILOperation.MLIL_VAR: MediumLevelILOperation.MLIL_NOT,
    MediumLevelILOperation.MLIL_AND: MediumLevelILOperation.MLIL_OR,
    MediumLevelILOperation.MLIL_OR: MediumLevelILOperation.MLIL_AND,
}


def analyze_unconditional_jump(self, expr: MediumLevelILInstruction):
    log_debug("analyze_unconditional_jump")

    function = self.function
    view = self.view
    mmlil = expr.function

    seen_count = self.seen.get(expr.address, 0)
    log_debug(f"Analyzing {expr.address:x} : {seen_count} times")
    if seen_count > 10:
        log_debug(f"{expr.address:x} has been seen too many times")
        return expr.true

    # double check to see if it's solvable:
    if expr.condition.value.type == RegisterValueType.ConstantValue:
        if expr.condition.value.value == 0:
            # patch to never jump
            pass
        else:
            # patch to always jump
            pass

    # step 2: get our mlil basic block
    for bb in mmlil.basic_blocks:
        if bb.start <= expr.instr_index < bb.end:
            first_jump_bb = bb
            break
    else:
        log_debug("Couldn't find basic block")
        return False

    # step 3: look for all the returns
    returns = []

    for idx in range(expr.instr_index + 1, len(mmlil)):
        current_il = mmlil[idx]
        if current_il.operation in (
            MediumLevelILOperation.MLIL_RET,
            MediumLevelILOperation.MLIL_RET_HINT,
            MediumLevelILOperation.MLIL_UNDEF,
            MediumLevelILOperation.MLIL_JUMP,
        ) or (
            current_il.operation == MediumLevelILOperation.MLIL_GOTO
            and len(current_il.branch_dependence) > 1
        ):
            returns.append(current_il)
        idx += 1

    # step 4: find the unconditional jump
    # TODO: switch not_unconditional to a set and do the difference
    unconditional_target = (
        mmlil[expr.true]
        if expr.instr_index not in mmlil[expr.true].branch_dependence
        else None
    )
    not_unconditional = []

    for ret in returns:
        if ret.branch_dependence:
            not_unconditional.append(ret)
        else:
            unconditional_target = ret

    if unconditional_target is None:
        original_target = expr.address
        false_target = mmlil[expr.false].address

        # try to get the BinaryView to trigger analysis when we leave
        false_seen_target = self.seen.get(false_target, 0)
        if false_seen_target < 10:
            log_debug(f"{false_target:x} seen {false_seen_target}")
            self.target_queue.put(false_target)
            self.target_queue.put(original_target)
            return False

        log_debug(f"{false_target:x} has been seen too many times")
        return expr.true

    # get the basic block for the unconditional ret
    bb = get_mmlil_bb(mmlil, unconditional_target.instr_index)

    # make sure first jump dominates
    if first_jump_bb not in bb.dominators:
        log_debug(f"first_jump_bb not in bb.dominators for {bb[0].address:x}")
        return False

    # find the ret that is dependent on first jump and another jump
    # and both need to have the same type of branch

    for ret in not_unconditional:
        dependence = ret.branch_dependence
        second_jump = next(
            (
                mmlil[i]
                for i in sorted(dependence)
                if (
                    i != expr.instr_index
                    and expr.instr_index in mmlil[i].branch_dependence
                )
            ),
            None,
        )
        if second_jump is None:
            continue

        if expr.instr_index not in dependence:
            continue

        # same type of branch
        if dependence[expr.instr_index] != dependence[second_jump.instr_index]:
            continue

        bb = get_mmlil_bb(mmlil, ret.instr_index)
        break
    else:
        log_debug("Didn't find a ret")
        return False

    if second_jump is None:
        log_debug("Second Jump is None")
        return False

    if expr.condition.operation == MediumLevelILOperation.MLIL_VAR:
        # This could be an if (flag:o) and an if (!(flag:o))
        if second_jump.condition.operation != MediumLevelILOperation.MLIL_NOT:
            first_jump_condition = mmlil[
                mmlil.get_ssa_var_definition(expr.ssa_form.condition.src)
            ].src
        else:
            first_jump_condition = expr.condition
    else:
        first_jump_condition = expr.condition

    if second_jump.condition.operation == MediumLevelILOperation.MLIL_VAR:
        if expr.condition.operation != MediumLevelILOperation.MLIL_NOT:
            second_jump_condition = mmlil[
                mmlil.get_ssa_var_definition(second_jump.ssa_form.condition.src)
            ].src
        else:
            second_jump_condition = second_jump.condition
    else:
        second_jump_condition = second_jump.condition

    # make sure the comparisons are opposites
    if cmp_pairs[first_jump_condition.operation] != second_jump_condition.operation:
        log_debug("Comparisons didn't match")
        return False

    # make sure the operands are the same
    first_ops = ConditionVisitor().visit(first_jump_condition)
    second_ops = ConditionVisitor().visit(second_jump_condition)

    if isinstance(first_ops, Variable):
        if first_ops != second_ops:
            log_debug("first_ops != second_ops")
            return False
    elif not all(o in second_ops for o in first_ops):
        log_debug("not all(o in second_ops for o in first_ops)")
        return False

    # we have found our two jumps and the unconditional!
    patch_addr = expr.address

    patch_bb = next(bb for bb in function if bb.start <= patch_addr < bb.end)

    branch_type = dependence[expr.instr_index]

    if branch_type == ILBranchDependence.FalseBranchDependent:
        target = mmlil[expr.true].address

        patch_value = view.arch.always_branch(
            view.read(patch_addr, view.get_instruction_length(patch_addr)), patch_addr
        )
    else:
        target = mmlil[expr.false].address

        patch_value = view.arch.never_branch(
            view.read(patch_addr, view.get_instruction_length(patch_addr)), patch_addr
        )

    if (patch_bb.end - patch_addr) < len(patch_value):
        log_debug("not enough space", repr(patch_value))
        return False

    view.write(patch_addr, patch_value)

    self.target_queue.put(target)

    return True


bb_cache = {}


def get_mmlil_bb(mmlil: MediumLevelILFunction, idx: int):
    return next(bb for bb in mmlil.basic_blocks if bb.start <= idx < bb.end)


class ConditionVisitor(BNILVisitor):
    def visit_MLIL_CMP_E(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if not isinstance(left, tuple):
            left = (left,)
        if not isinstance(right, tuple):
            right = (right,)

        # return a single tuple of all variables and constants
        return tuple(chain(left, right))

    visit_MLIL_CMP_NE = visit_MLIL_CMP_E
    visit_MLIL_CMP_UGT = visit_MLIL_CMP_E
    visit_MLIL_CMP_ULE = visit_MLIL_CMP_E
    visit_MLIL_CMP_UGE = visit_MLIL_CMP_E
    visit_MLIL_CMP_ULT = visit_MLIL_CMP_E
    visit_MLIL_CMP_SGT = visit_MLIL_CMP_E
    visit_MLIL_CMP_SLE = visit_MLIL_CMP_E
    visit_MLIL_CMP_SGE = visit_MLIL_CMP_E
    visit_MLIL_CMP_SLT = visit_MLIL_CMP_E

    def visit_MLIL_VAR(self, expr):
        return expr.src

    def visit_MLIL_NOT(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_CONST(self, expr):
        return expr.constant

    def visit_MLIL_AND(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return left, right

    visit_MLIL_OR = visit_MLIL_AND

    visit_MLIL_CONST_PTR = visit_MLIL_CONST
