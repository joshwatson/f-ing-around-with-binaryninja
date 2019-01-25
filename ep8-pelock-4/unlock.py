from binaryninja import (
    AnalysisCompletionEvent,
    Architecture,
    BasicBlock,
    BinaryDataNotification,
    BinaryView,
    Function,
    ILBranchDependence,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    RegisterValueType,
    Variable,
    VariableSourceType,
    BackgroundTaskThread,
    log_info,
    worker_enqueue,
    PluginCommand,
    BinaryReader,
)
from functools import partial
from itertools import chain
import operator as op


class UnlockCompletionEvent(AnalysisCompletionEvent):
    def __init__(self, function):
        self.function = function
        super(UnlockCompletionEvent, self).__init__(
            function.view, UnlockCompletionEvent.check_next
        )

    def check_next(self):
        # log_info("in completion event")
        checker = partial(check_next, self.view, self.function)
        worker_enqueue(checker)


def check_next(view, function):
    # log_info("in check_next")
    if "next" in function.session_data:
        target_queue = function.session_data["next"]
    else:
        target_queue = list()
        function.session_data["next"] = target_queue
    # for i in target_queue:
    #     print(f'{i:x}', sep=' ')
    # print()
    next_target = None
    while target_queue:
        next_target = target_queue.pop(0)
        if next_target is None:
            continue
        # log_info(f'{next_target:x} is next target')
        valid = view.navigate(view.file.view, next_target)
        # log_info(f'Attempt to navigate to {next_target:x}: {valid}')
        if not valid:
            next_target = None
            continue
        else:
            break
    if next_target is None:
        return

    UnlockTaskThread(function, next_target).start()


class UnlockTaskThread(BackgroundTaskThread):
    push_seh = False
    seh = []

    def __init__(self, function, addr):
        super(UnlockTaskThread, self).__init__(
            initial_progress_text=f"Analyzing {addr:x}", can_cancel=True
        )
        self.addr = addr
        self.function = function
        self.view = function.view

    def run(self):
        log_info(f"run for {self.addr:x} started")
        function = self.function
        il = function.get_low_level_il_at(self.addr).mapped_medium_level_il

        mmlil = il.function

        fs = Variable(
            function,
            VariableSourceType.RegisterVariableSourceType,
            0,
            function.arch.get_reg_index("fs"),
            "fs",
        )

        func = None
        UnlockCompletionEvent(function)
        while func is None:
            print(f"Analyzing {il.instr_index}: {il}")
            if il.operation in (
                MediumLevelILOperation.MLIL_RET,
                MediumLevelILOperation.MLIL_RET_HINT,
            ):
                func = unret
            elif il.operation == MediumLevelILOperation.MLIL_JUMP:
                # is the jump target a constant in memory?
                func = goto_var
            elif il.operation == MediumLevelILOperation.MLIL_IF:
                # is this a stosb or something similar?
                exits = function.get_low_level_il_exits_at(il.address)
                if len(exits) > 1:
                    il_exit = max(exits) + 1
                    il = function.low_level_il[il_exit].mapped_medium_level_il
                    continue

                # is this an opaque predicate?
                if il.condition.value.type == RegisterValueType.ConstantValue:
                    func = unopaque

                # try to deobfuscate an unconditional jump
                else:
                    func = unjmp
            elif il.operation == MediumLevelILOperation.MLIL_GOTO:
                il = mmlil[il.dest]
            elif fs in il.prefix_operands:
                if self.push_seh:
                    print("!!!!!!! FOUND FS !!!!!!!!!!")
                    if il.operation != MediumLevelILOperation.MLIL_STORE:
                        # something else is going on here. stop so we can
                        # examine it
                        return

                    esp = function.get_reg_value_at(il.address, "esp")
                    seh = function.get_stack_contents_at(il.address, esp.offset + 4, 4)
                    if seh.type == RegisterValueType.ConstantValue:
                        self.seh.append(seh.value)
                        self.push_seh = False
                        il = mmlil[il.instr_index + 1]
                    else:
                        # something else is going on here. stop so we can
                        # examine it
                        return
                else:
                    # clear the target queue
                    self.push_seh = True
                    il = mmlil[il.instr_index + 1]
            elif il.operation == MediumLevelILOperation.MLIL_SET_VAR and self.seh:
                func = partial(check_null_deref, seh=self.seh)
            else:
                try:
                    if il.operation == MediumLevelILOperation.MLIL_UNDEF:
                        function.reanalyze()
                        return
                    il = mmlil[il.instr_index + 1]
                except:
                    function.reanalyze()
                    return

        seen[il.address] = seen.get(il.address, 0) + 1
        run(func, il)
        log_info(f"run for {il.address:x} finished")


class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):
        method_name = "visit_{}".format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            print(expression.operation)
            value = None
        return value


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


bb_cache = {}

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


class JumpVisitor(BNILVisitor):
    def visit_MLIL_JUMP(self, expr):
        return self.visit(expr.dest)

    def visit_MLIL_LOAD(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_CONST_PTR(self, expr):
        return expr.constant

    visit_MLIL_CONST = visit_MLIL_CONST_PTR


def goto_var(il: MediumLevelILInstruction):
    function = il.function.source_function
    view = function.view

    jump_value = JumpVisitor().visit(il)

    if jump_value is None:
        # print("Jump target not constant")
        function.reanalyze()
        return

    br = BinaryReader(view)
    br.seek(jump_value)
    if view.arch.address_size == 4:
        target = br.read32le()
    elif view.arch.address_size == 8:
        target = br.read64le()
    else:
        # wtf????
        function.reanalyze()
        return

    function.set_user_indirect_branches(il.address, [(view.arch, target)])
    function.reanalyze()
    return target


def unret(il: MediumLevelILInstruction):
    global bb_cache
    bb_cache = {}

    function = il.function.source_function
    # Step 1: find the return
    ret_addr = il.address
    log_info(f"{il} {il.address:x}")
    # Step 2: calculate the address to jump to
    current_esp = function.get_reg_value_at(ret_addr, "esp")
    # log_info(repr(current_esp))
    current_esp = current_esp.offset
    next_jump_value = function.get_stack_contents_at(ret_addr, current_esp, 4)
    if next_jump_value.type == RegisterValueType.ConstantValue:
        next_jump_addr = next_jump_value.value
    else:
        # print("Return value isn't constant")
        function.reanalyze()
        return

    # Step 3: Identify the start
    # print("Step 3")
    ret_il_ssa = il.ssa_form
    mmlil = il.function
    jump_variable_ssa = ret_il_ssa.dest.src
    jump_il = mmlil[mmlil.get_ssa_var_definition(jump_variable_ssa)]
    while jump_il.src.operation != MediumLevelILOperation.MLIL_CONST:
        new_var_ssa = jump_il.src.left.ssa_form.src
        jump_il = mmlil[mmlil.get_ssa_var_definition(new_var_ssa)]

    # Step 4: Patch the binary to jump
    # print("Step 4")
    patch_addr = jump_il.address
    view = function.view

    patch_value = view.arch.assemble(f"jmp 0x{next_jump_addr:x}", patch_addr)

    if (ret_addr - patch_addr) < len(patch_value):
        print("Not enough space", hex(patch_addr), len(patch_value))
        return

    view.write(patch_addr, patch_value)

    return next_jump_addr


seen = {}


def return_and_reanalyze(function: Function, result=None):
    function.reanalyze()
    return result


class NullDerefVisitor(BNILVisitor):
    def visit_MLIL_SX(self, expr):
        return self.visit(expr.src)

    visit_MLIL_LOAD = visit_MLIL_SX

    def visit_MLIL_CONST_PTR(self, expr):
        return expr.constant

    visit_MLIL_CONST = visit_MLIL_CONST_PTR


def check_null_deref(il: MediumLevelILInstruction, seh: list = None):
    if seh is None:
        return
    function = il.function.source_function
    view = function.view
    if NullDerefVisitor().visit(il.src) == 0:
        target = seh.pop()
        if target:
            view.write(view.arch.assemble(f"jmp 0x{target:x}", il.address))
            return target

    return return_and_reanalyze(function)

def unjmp(first_jump: MediumLevelILInstruction):
    function = first_jump.function.source_function
    view = function.view
    mmlil = first_jump.function

    seen_count = seen.get(first_jump.address, 0)
    print(f"Analyzing {first_jump.address:x} : {seen_count} times")
    if seen_count > 10:
        return return_and_reanalyze(function)

    # double check to see if it's solvable:
    if first_jump.condition.value.type == RegisterValueType.ConstantValue:
        if first_jump.condition.value.value == 0:
            # patch to never jump
            pass
        else:
            # patch to always jump
            pass

    # step 2: get our mlil basic block
    # print("Step 2")
    for bb in mmlil.basic_blocks:
        if bb.start <= first_jump.instr_index < bb.end:
            first_jump_bb = bb
            break
    else:
        return

    # step 3: look for all the returns
    # print("Step 3")
    returns = []

    for idx in range(first_jump.instr_index + 1, len(mmlil)):
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
    # print("Step 4")
    unconditional_target = None
    not_unconditional = []

    for ret in returns:
        if ret.branch_dependence:
            not_unconditional.append(ret)
        else:
            unconditional_target = ret

    if unconditional_target is None:
        original_target = first_jump.address
        false_target = mmlil[first_jump.false].address

        # try to get the BinaryView to trigger analysis when we leave
        # print("Adding false branch to queue")

        false_seen_target = seen.get(false_target, 0)
        if false_seen_target < 10:
            print(f"{false_target:x} seen {false_seen_target}")
            return return_and_reanalyze(function, [false_target, original_target])

        return return_and_reanalyze(function)

    # get the basic block for the unconditional ret
    bb = get_mmlil_bb(mmlil, unconditional_target.instr_index)

    # make sure first jump dominates
    # print("Step 5")
    if first_jump_bb not in bb.dominators:
        # print("first_jump_bb not in bb.dominators")
        function.reanalyze()
        return

    # find the ret that is dependent on first jump and another jump
    # and both need to have the same type of branch
    # print("Step 6")

    for ret in not_unconditional:
        dependence = ret.branch_dependence
        second_jump = next(
            (
                mmlil[i]
                for i in sorted(dependence)
                if (
                    i != first_jump.instr_index
                    and first_jump.instr_index in mmlil[i].branch_dependence
                )
            ),
            None,
        )
        if second_jump is None:
            continue

        if first_jump.instr_index not in dependence:
            continue

        # same type of branch
        if dependence[first_jump.instr_index] != dependence[second_jump.instr_index]:
            continue

        bb = get_mmlil_bb(mmlil, ret.instr_index)
        break
    else:
        # print("Didn't find a ret")
        return

    if second_jump is None:
        # print("Second Jump is None")
        return

    # print("Step 7")
    if first_jump.condition.operation == MediumLevelILOperation.MLIL_VAR:
        # This could be an if (flag:o) and an if (!(flag:o))
        if second_jump.condition.operation != MediumLevelILOperation.MLIL_NOT:
            first_jump_condition = mmlil[
                mmlil.get_ssa_var_definition(first_jump.ssa_form.condition.src)
            ].src
        else:
            first_jump_condition = first_jump.condition
    else:
        first_jump_condition = first_jump.condition

    if second_jump.condition.operation == MediumLevelILOperation.MLIL_VAR:
        if first_jump.condition.operation != MediumLevelILOperation.MLIL_NOT:
            second_jump_condition = mmlil[
                mmlil.get_ssa_var_definition(second_jump.ssa_form.condition.src)
            ].src
        else:
            second_jump_condition = second_jump.condition
    else:
        second_jump_condition = second_jump.condition

    # make sure the comparisons are opposites
    if cmp_pairs[first_jump_condition.operation] != second_jump_condition.operation:
        return

    # make sure the operands are the same
    # print("Step 8")
    # print(f'{first_jump_condition.address:x}, {second_jump_condition.address:x}')
    first_ops = ConditionVisitor().visit(first_jump_condition)
    second_ops = ConditionVisitor().visit(second_jump_condition)

    if isinstance(first_ops, Variable):
        if first_ops != second_ops:
            return
    elif not all(o in second_ops for o in first_ops):
        return

    # we have found our two jumps and the unconditional!
    patch_addr = first_jump.address

    patch_bb = next(bb for bb in function if bb.start <= patch_addr < bb.end)

    branch_type = dependence[first_jump.instr_index]

    if branch_type == ILBranchDependence.FalseBranchDependent:
        target = mmlil[first_jump.true].address
        # print(f'Jumping to {target:x}')

        patch_value = view.arch.always_branch(
            view.read(patch_addr, view.get_instruction_length(patch_addr)), patch_addr
        )
    else:
        target = mmlil[first_jump.false].address
        # print(f'Jumping to {target:x}')

        patch_value = view.arch.never_branch(
            view.read(patch_addr, view.get_instruction_length(patch_addr)), patch_addr
        )

    if (patch_bb.end - patch_addr) < len(patch_value):
        # print("not enough space", repr(patch_value))
        return

    view.write(patch_addr, patch_value)

    return target


def unopaque(il: MediumLevelILInstruction):
    # we can 'always branch' this
    function = il.function.source_function
    view = function.view

    if il.condition.value.value != 0:
        view.always_branch(il.address)
        return il.function[il.true].address
    elif il.condition.value.value == 0:
        view.never_branch(il.address)
        return il.function[il.false].address
    else:
        return return_and_reanalyze(function)


def get_mmlil_bb(mmlil: MediumLevelILFunction, idx: int):
    if idx not in bb_cache:
        bb_cache[idx] = next(
            bb for bb in mmlil.basic_blocks if bb.start <= idx < bb.end
        )
    return bb_cache[idx]


def run(func, il: MediumLevelILInstruction):
    source_function = il.function.source_function
    view = source_function.view
    view.begin_undo_actions()
    target = func(il)
    view.commit_undo_actions()
    if "next" in source_function.session_data:
        target_queue = source_function.session_data["next"]
    else:
        target_queue = list()
    if isinstance(target, int):
        target_queue.append(target)
    elif isinstance(target, list):
        target_queue += target
    source_function.session_data["next"] = target_queue


def run_unlock(view, function):
    u = UnlockTaskThread(function, function.start)
    u.start()


PluginCommand.register_for_function(
    "Run unlock",
    "Run unlock",
    run_unlock,
    is_valid=lambda v, f: "obfuscated" in v.file.filename,
)
