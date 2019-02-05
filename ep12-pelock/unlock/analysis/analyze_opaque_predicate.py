from binaryninja import MediumLevelILInstruction

def analyze_opaque_predicate(self, expr: MediumLevelILInstruction):
    # we can 'always branch' this
    mmlil = expr.function

    if expr.condition.value.value != 0:
        self.view.always_branch(expr.address)
        self.target_queue.put(mmlil[expr.true].address)
        return True
    elif expr.condition.value.value == 0:
        self.view.never_branch(expr.address)
        self.target_queue.put(mmlil[expr.false].address)
        return True
    else:
        return False