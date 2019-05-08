from z3 import BitVecNumRef, BitVecRef, Bool, Not

from binaryninja import (Function, InstructionTextToken,
                         InstructionTextTokenType, TypeClass,
                         VariableSourceType, log_debug)

negations = {
    '<=': '>',
    '==': '!=',
    '>': '<=',
    '>=': '<',
    '<': '>='
}

class ConstraintVisitor:
    def __init__(self, function: Function):
        self._function = function
        self._in_not = False

    def visit(self, expression):
        method_name = f"visit_{expression.__class__.__name__}"
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            print(f'visit_{method_name} missing')
            value = None
        return value

    def visit_BoolRef(self, expr):
        if expr.num_args() == 2:
            if self._in_not:
                operation = negations.get(f"{expr.decl()!s}")
                if operation is None:
                    operation = f"{expr.decl()!s}"
                    self._in_not = False
            else:
                operation = f"{expr.decl()!s}"
            left = self.visit(expr.arg(0))
            right = self.visit(expr.arg(1))

            return (
                (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            "("
                        )
                    ] if expr.decl().name() in ('and', 'or') else []
                ) +
                left + 
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        f" {operation} "
                    )
                ] +
                right +
                (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            ")"
                        )
                    ] if expr.decl().name() in ('and', 'or') else []
                )
            )


        elif expr.num_args() == 1:
            if expr.decl().name() == 'not':
                self._in_not = True
            arg = self.visit(expr.arg(0))
            result = (
                (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            f"!("
                        )
                    ] if not self._in_not else []
                )+
                arg +
                (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            ")"
                        )
                    ] if not self._in_not else []
                )
            )

            self._in_not = False
            return result

        else:
            return [
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    f"{expr.decl().name()}",
                    value=1 if expr.decl().name() == 'true' else 0
                )
            ]

    def visit_BitVecNumRef(self, expr):
        return [
            InstructionTextToken(
                InstructionTextTokenType.IntegerToken,
                str(expr.as_long()),
                expr.as_long(),
                size=expr.size() // 8
            )
        ]

    def visit_BitVecRef(self, expr):
        member = None
        if expr.decl().name() == 'extract':
            end, start = expr.params()
            size = (end - start + 1) // 8
            var_name = expr.arg(0).decl().name()

            var = next(
                (
                    v
                    for v in self._function.vars
                    if v.name == var_name
                ),
                0
            )

            type_ = var.type

            if type_.type_class == TypeClass.NamedTypeReferenceClass:
                type_ = self._function.view.types[type_.named_type_reference.name]

            if type_.type_class == TypeClass.StructureTypeClass:
                member = next(
                    (
                        m
                        for m in var.structure.members
                        if m.offset == start
                    ),
                    None
                )
                member_name = member.name

            elif var.source_type == VariableSourceType.RegisterVariableSourceType:
                member = next(
                    (
                        subregister
                        for subregister in self._function.arch.regs.values()
                        if (
                            subregister.full_width_reg == self._function.arch.get_reg_name(var.storage) and
                            subregister.size == size and
                            subregister.offset == start
                        )
                    ),
                    None
                )
                member_name = self._function.arch.get_reg_name(member.index)

            if member is None:
                # TODO: Convert the extract into (blah) & ~((1<<start)-1)
                print(f"member is None {expr!r}")

        elif expr.decl().name().startswith('mem('):
            print(expr)
            return []

        else:
            var = next(
                (
                    v
                    for v in self._function.vars
                    if v.name == expr.decl().name()
                ),
                None
            )


        return (
            [
                InstructionTextToken(
                    InstructionTextTokenType.LocalVariableToken,
                    var.name,
                    var.identifier
                )
            ] + 
            (
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        "."
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.RegisterToken,
                        member_name,
                        var.identifier
                    )
                ] if member is not None else []
            ) 
        )

