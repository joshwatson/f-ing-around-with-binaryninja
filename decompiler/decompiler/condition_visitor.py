from .bnilvisitor import BNILVisitor
from functools import reduce

from binaryninja import (Variable, VariableSourceType)

from z3 import (BitVec, And, Or, Not, Solver, Tactic, Extract, UGT, ULE, Array, BitVecSort, Concat, Bool)

def make_variable(var: Variable):
    if var.name == '':
        if var.source_type == VariableSourceType.RegisterVariableSourceType:
            var.name = var.function.arch.get_reg_by_index(var.storage)
        else:
            raise NotImplementedError()
    return BitVec(var.name, var.type.width * 8)

def make_load(src, size):
    mem = Array('mem', BitVecSort(32), BitVecSort(8))

    load_bytes = [mem[src+i] for i in range(0, size)]

    return Concat(*load_bytes)

class ConditionVisitor(BNILVisitor):
    def simplify(self, condition):
        return reduce(
            And,
            Tactic('ctx-solver-simplify')(self.visit(condition))[0]
        )
            
            

    def visit_MLIL_CMP_E(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return left == right

    def visit_MLIL_CMP_NE(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return left != right

    def visit_MLIL_CMP_SLE(self, expr):
        left, right = self.visit_both_sides(expr)

        return left <= right

    def visit_MLIL_CMP_SGT(self, expr):
        left, right = self.visit_both_sides(expr)

        return left > right

    def visit_MLIL_CMP_SGE(self, expr):
        left, right = self.visit_both_sides(expr)

        return left >= right

    def visit_MLIL_CMP_UGT(self, expr):
        left, right = self.visit_both_sides(expr)

        return UGT(left, right)

    def visit_MLIL_CMP_ULE(self, expr):
        left, right = self.visit_both_sides(expr)

        return ULE(left, right)

    def visit_MLIL_LOAD(self, expr):
        src = self.visit(expr.src)
        return make_load(src, expr.size)

    def visit_MLIL_VAR_FIELD(self, expr):
        src = make_variable(expr.src)
        offset = expr.offset
        size = expr.size

        return Extract(((offset+size)*8)-1, (offset*8), src)

    def visit_MLIL_VAR(self, expr):
        return make_variable(expr.src)

    def visit_MLIL_CONST(self, expr):
        if expr.size == 0 and expr.constant in (0, 1):
            return Bool('b') == Bool('b') if expr.constant else Bool('b') != Bool('b')
        return expr.constant

    def visit_MLIL_NOT(self, expr):
        return Not(self.visit(expr.src))

    def visit_MLIL_AND(self, expr):
        return And(*self.visit_both_sides(expr))

    def visit_MLIL_OR(self, expr):
        return Or(*self.visit_both_sides(expr))

    def visit_MLIL_ADD(self, expr):
        left, right = self.visit_both_sides(expr)
        return left + right

    def visit_MLIL_ADDRESS_OF(self, expr):
        return BitVec(f'&{expr.src.name}', (expr.size * 8) if expr.size else expr.function.source_function.view.address_size * 8)

    def visit_MLIL_LSL(self, expr):
        left, right = self.visit_both_sides(expr)
        return left << right

    def visit_both_sides(self, expr):
        return self.visit(expr.left), self.visit(expr.right)

    visit_MLIL_CONST_PTR = visit_MLIL_CONST