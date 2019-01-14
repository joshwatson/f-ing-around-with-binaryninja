from binaryninja import (AnalysisCompletionEvent, BasicBlock,
                         MediumLevelILOperation, RegisterValueType, Variable,
                         VariableSourceType, Architecture, ILBranchDependence)

class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):
        method_name = 'visit_{}'.format(expression.operation.name)
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

        return left, right

    visit_MLIL_CMP_NE = visit_MLIL_CMP_E

    def visit_MLIL_VAR(self, expr):
        return expr.src

    def visit_MLIL_CONST(self, expr):
        return expr.constant

    visit_MLIL_CONST_PTR = visit_MLIL_CONST

bb_cache = {}

cmp_pairs = {
    MediumLevelILOperation.MLIL_CMP_E: MediumLevelILOperation.MLIL_CMP_NE,
    MediumLevelILOperation.MLIL_CMP_NE: MediumLevelILOperation.MLIL_CMP_E
}

def unret(bb : BasicBlock):
    global bb_cache
    bb_cache = {}

    function = bb.function
    # Step 1: find the return
    ret_addr = bb.end - 1
    # Step 2: calculate the address to jump to
    current_esp = function.get_reg_value_at(ret_addr, 'esp').offset
    next_jump_value = function.get_stack_contents_at(
        ret_addr,
        current_esp,
        4
    )
    if next_jump_value.type == RegisterValueType.ConstantValue:
        next_jump_addr = next_jump_value.value
    else:
        return
    # Step 3: Identify the start
    ret_il_ssa = function.get_low_level_il_at(ret_addr).mapped_medium_level_il.ssa_form
    mmlil = function.llil.mapped_medium_level_il
    jump_variable_ssa = ret_il_ssa.dest.src
    il = mmlil[mmlil.get_ssa_var_definition(jump_variable_ssa)]
    while il.src.operation != MediumLevelILOperation.MLIL_CONST:
        new_var_ssa = il.src.left.ssa_form.src
        il = mmlil[mmlil.get_ssa_var_definition(new_var_ssa)]
    # Step 4: Patch the binary to jump
    patch_addr = il.address
    view = function.view

    patch_value = view.arch.assemble(f'jmp 0x{next_jump_addr:x}', patch_addr)

    if (ret_addr - patch_addr) < len(patch_value):
        return

    view.write(
        patch_addr,
        patch_value
    )

def unjmp(basic_block):
    global bb_cache
    bb_cache = {}

    function = basic_block.function
    view = function.view
    mmlil = function.llil.mapped_medium_level_il
    current_il = mmlil[
        function.get_low_level_il_at(
            basic_block.start
        ).mapped_medium_level_il.instr_index
    ]

    # step 1: find a conditional jmp
    while current_il.operation != MediumLevelILOperation.MLIL_IF:
        current_il = mmlil[current_il.instr_index+1]

    first_jump = current_il

    # step 2: get our mlil basic block
    for bb in mmlil.basic_blocks:
        if bb.start <= current_il.instr_index < bb.end:
            first_jump_bb = bb
            break
    else:
        return
    
    # step 3: look for all the returns
    returns = []

    for idx in range(current_il.instr_index+1, len(mmlil)):
        current_il = mmlil[idx]
        if (current_il.operation in 
                (MediumLevelILOperation.MLIL_RET,
                 MediumLevelILOperation.MLIL_RET_HINT)):
            returns.append(current_il)
        idx += 1
    
    # step 4: find the unconditional jump
    # TODO: switch not_unconditional to a set and do the difference
    unconditional_target = None
    not_unconditional = []
    
    for ret in returns:
        if ret.branch_dependence:
            not_unconditional.append(ret)
        else:
            unconditional_target = ret

    if unconditional_target is None:
        return

    # get the basic block for the unconditional ret
    bb = get_mmlil_bb(mmlil, unconditional_target.instr_index)
    
    # make sure first jump dominates
    if first_jump_bb not in bb.dominators:
        return

    # find the ret that is dependent on first jump and another jump
    # and both need to have the same type of branch
    for ret in not_unconditional:
        dependence = ret.branch_dependence

        # same type of branch
        if len({branch for branch in dependence.values()}) != 1:
            continue

        # exactly two branches
        if len(dependence) != 2:
            continue
        
        # first jump is one of the branches
        if first_jump.instr_index not in dependence:
            continue

        bb = get_mmlil_bb(mmlil, ret.instr_index)
        break
    else:
        return

    second_jump = next(mmlil[i] for i in dependence if i != first_jump.instr_index)

    if second_jump is None:
        return

    if first_jump.condition not in cmp_pairs:
        first_jump_condition = mmlil[
            mmlil.get_ssa_var_definition(first_jump.ssa_form.condition.src)
        ].src
    else:
        first_jump_condition = first_jump.condition

    if second_jump.condition not in cmp_pairs:
        second_jump_condition = mmlil[
            mmlil.get_ssa_var_definition(second_jump.ssa_form.condition.src)
        ].src
    else:
        second_jump_condition = second_jump.condition

    # make sure the comparisons are opposites
    if cmp_pairs[first_jump_condition.operation] != second_jump_condition.operation:
        return
    
    # make sure the operands are the same
    first_ops = ConditionVisitor().visit(first_jump_condition)
    second_ops = ConditionVisitor().visit(second_jump_condition)

    if (first_ops[0] not in second_ops or
            first_ops[1] not in second_ops):
        return

    # we have found our two jumps and the unconditional!
    branch_type = next(iter(dependence.values()))

    if branch_type == ILBranchDependence.FalseBranchDependent:
        target = mmlil[first_jump.true].address
        print(f'Jumping to {target:x}')
    else:
        target = mmlil[first_jump.false].address
        print(f'Jumping to {target:x}')

    print("here?")

    patch_addr = first_jump_condition.address

    patch_bb = next(bb for bb in function if bb.start <= patch_addr < bb.end)

    patch_value = view.arch.assemble(f'jmp 0x{target:x}', patch_addr)

    if (patch_bb.end - patch_addr) < len(patch_value):
        print("not enough space")
        return

    view.write(
        patch_addr,
        patch_value
    )

def get_mmlil_bb(mmlil, idx):
    if idx not in bb_cache:
        bb_cache[idx] = next(bb for bb in mmlil.basic_blocks
            if bb.start <= idx < bb.end)
    return bb_cache[idx]