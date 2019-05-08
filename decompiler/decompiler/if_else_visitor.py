from .bnilvisitor import BNILVisitor

class IfVisitor(BNILVisitor):
    def __init__(self, original_condition):
        self.to_visit = original_condition

    def find_else(self, other):
        while self.to_visit is not None:
            current_expr, self.to_visit = self.visit(self.to_visit)
            if current_expr is not None:
                visitor = ElseVisitor(current_expr)

                match = visitor.visit(other)
                if match is not None:
                    return match

    def visit_MLIL_AND(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if left is not None:
            return left[0], expr.right
        
        if right is not None:
            return right[0], expr.left

        return None, None

    visit_MLIL_OR = visit_MLIL_AND

    def visit_MLIL_NOT(self, expr):
        return expr.src.expr_index, None

    def visit_MLIL_CMP_E(self, expr):
        return expr.expr_index, None

    visit_MLIL_CMP_NE = visit_MLIL_CMP_E
    visit_MLIL_CMP_UGT = visit_MLIL_CMP_E
    visit_MLIL_CMP_ULE = visit_MLIL_CMP_E
    visit_MLIL_CMP_UGE = visit_MLIL_CMP_E
    visit_MLIL_CMP_ULT = visit_MLIL_CMP_E
    visit_MLIL_CMP_SGT = visit_MLIL_CMP_E
    visit_MLIL_CMP_SLE = visit_MLIL_CMP_E
    visit_MLIL_CMP_SGE = visit_MLIL_CMP_E
    visit_MLIL_CMP_SLT = visit_MLIL_CMP_E

    def visit_MLIL_CONST(self, expr):
        return expr.expr_index, None

class ElseVisitor(BNILVisitor):
    def __init__(self, expr_to_find):
        self.expr_to_find = expr_to_find

    def visit_MLIL_AND(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if left is not None:
            return left

        if right is not None:
            return right

    visit_MLIL_OR = visit_MLIL_AND

    def visit_MLIL_NOT(self, expr):
        if expr.src.expr_index == self.expr_to_find:
            return expr.expr_index

    def visit_MLIL_CMP_E(self, expr):
        if expr.expr_index == self.expr_to_find:
            return expr.expr_index

    visit_MLIL_CMP_NE = visit_MLIL_CMP_E
    visit_MLIL_CMP_UGT = visit_MLIL_CMP_E
    visit_MLIL_CMP_ULE = visit_MLIL_CMP_E
    visit_MLIL_CMP_UGE = visit_MLIL_CMP_E
    visit_MLIL_CMP_ULT = visit_MLIL_CMP_E
    visit_MLIL_CMP_SGT = visit_MLIL_CMP_E
    visit_MLIL_CMP_SLE = visit_MLIL_CMP_E
    visit_MLIL_CMP_SGE = visit_MLIL_CMP_E
    visit_MLIL_CMP_SLT = visit_MLIL_CMP_E