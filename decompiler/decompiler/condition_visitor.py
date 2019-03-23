from .bnilvisitor import BNILVisitor

from binaryninja import (Variable, VariableSourceType)

from z3 import (BitVec, And, Or, Not, Solver, simplify)

def make_variable(var: Variable):
    if var.name == '':
        if var.source_type == VariableSourceType.RegisterVariableSourceType:
            var.name = var.function.arch.get_reg_by_index(var.storage)
        else:
            raise NotImplementedError()
    return BitVec(var.name, var.width)

class ConditionVisitor(BNILVisitor):
    def simplify(self, condition):
        return simplify(self.visit(condition))

    def visit_MLIL_CMP_E(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return left == right

    def visit_MLIL_CMP_NE(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return left != right

    def visit_MLIL_VAR(self, expr):
        return make_variable(expr.src)

    def visit_MLIL_CONST(self, expr):
        return expr.constant

    def visit_MLIL_NOT(self, expr):
        return Not(self.visit(expr.src))

    def visit_MLIL_AND(self, expr):
        return And(*self.visit_both_sides(expr))

    def visit_MLIL_OR(self, expr):
        return Or(*self.visit_both_sides(expr))

    def visit_both_sides(self, expr):
        return self.visit(expr.left), self.visit(expr.right)

    visit_MLIL_CONST_PTR = visit_MLIL_CONST