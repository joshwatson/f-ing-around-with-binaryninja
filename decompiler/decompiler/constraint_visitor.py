from binaryninja import (
    Function,
    InstructionTextToken,
    InstructionTextTokenType,
    TypeClass,
    VariableSourceType,
    log_debug,
    log_info
)

negations = {
    "<=": ">",
    "==": "!=",
    ">": "<=",
    ">=": "<",
    "<": ">=",
    "u<=": "u>",
    "u>": "u<=",
    "u>=": "u<",
    "u<": "u>="
}

unsigned_ops = {
    'ULE': 'u<=',
    'ULT': 'u<',
    'UGE': 'u>=',
    'UGT': 'u>'
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
            log_info(f"visit_{method_name} missing")
            value = None
        return value

    def visit_BoolRef(self, expr):
        if expr.num_args() == 2:
            orig_operation = f'{expr.decl()!s}'
            if orig_operation.startswith('U'):
                orig_operation = unsigned_ops[orig_operation]

            if self._in_not:
                operation = negations.get(orig_operation)
                if operation is None:
                    operation = orig_operation
                    self._in_not = False
            else:
                operation = orig_operation

            left = self.visit(expr.arg(0))
            right = self.visit(expr.arg(1))

            return (
                (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            "("
                        )
                    ]
                    if expr.decl().name() in ("and", "or")
                    else []
                )
                + left
                + [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f" {operation} "
                    )
                ]
                + right
                + (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            ")"
                        )
                    ]
                    if expr.decl().name() in ("and", "or")
                    else []
                )
            )

        elif expr.num_args() == 1:
            if expr.decl().name() == "not":
                self._in_not = True
            arg = self.visit(expr.arg(0))
            result = (
                (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            "!("
                        )
                    ]
                    if not self._in_not
                    else []
                )
                + arg
                + (
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            ")"
                        )
                    ]
                    if not self._in_not
                    else []
                )
            )

            self._in_not = False
            return result

        elif expr.num_args() > 2:
            result = [
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    "("
                )
            ]
            for arg in range(expr.num_args()):
                result += self.visit(expr.arg(arg))
                if arg < expr.num_args() - 1:
                    result.append(
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            f" {expr.decl()!s} "
                        )
                    )

            result.append(
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ")"
                )
            )

            return result

        else:
            return [
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    f"{expr.decl().name()}",
                    value=1 if expr.decl().name() == "true" else 0,
                )
            ]

    def visit_BitVecNumRef(self, expr):
        return [
            InstructionTextToken(
                InstructionTextTokenType.IntegerToken,
                str(expr.as_long()),
                expr.as_long(),
                size=expr.size() // 8,
            )
        ]

    def visit_BitVecRef(self, expr):
        member = None
        var = None

        if expr.decl().name() == 'bvadd':
            left = self.visit(expr.arg(0))
            right = self.visit(expr.arg(1))

            return (
                left +
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        ' + '
                    )
                ] +
                right
            )

        if expr.decl().name() == "extract":
            end, start = expr.params()
            size = (end - start + 1) // 8
            var_name = expr.arg(0).decl().name()

            var = next(
                (v for v in self._function.vars if v.name == var_name),
                0
            )

            if var == 0:
                return self.visit(expr.arg(0))

            type_ = var.type

            if type_.type_class == TypeClass.NamedTypeReferenceClass:
                type_ = self._function.view.types[
                    type_.named_type_reference.name
                ]

            if type_.type_class == TypeClass.StructureTypeClass:
                member = next(
                    (m for m in var.structure.members if m.offset == start),
                    None
                )
                member_name = member.name

            elif (var.source_type ==
                    VariableSourceType.RegisterVariableSourceType):
                member = next(
                    (
                        subregister
                        for subregister in self._function.arch.regs.values()
                        if (
                            subregister.full_width_reg
                            == self._function.arch.get_reg_name(var.storage)
                            and subregister.size == size
                            and subregister.offset == start
                        )
                    ),
                    None,
                )

                if member is not None:
                    member_name = self._function.arch.get_reg_name(
                        member.index
                    )

            if member is None:
                mask = ((1 << (end+1)) - 1) ^ ((1 << (start)) - 1)

                return [
                    InstructionTextToken(
                        InstructionTextTokenType.LocalVariableToken,
                        var.name,
                        var.identifier
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        ' & '
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        hex(mask),
                        mask
                    )
                ]

        elif expr.decl().name() == 'select':
            log_debug(f"{expr.arg(0)}[{expr.arg(1)}]")
            return (
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        '*('
                    )
                ] + self.visit(expr.arg(1)) +
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        ')'
                    )
                ]
            )

        elif expr.decl().name() == 'concat':
            log_debug(f'{expr.num_args()}')

            if expr.num_args() > 2:
                raise NotImplementedError(
                    f"I don't know how to handle this: {expr}"
                )

            left, right = expr.arg(0), expr.arg(1)

            max_size = expr.size()

            shift = right.size()

            left_size = left.size()

            end, start = left.params()

            if left_size + shift != max_size:
                raise NotImplementedError(
                    (
                        f'This should never happen! '
                        f'{left_size} + {shift} != {max_size}'
                    )
                )

            if start != 0:
                left_tokens = self.visit(left)
            else:
                left_tokens = self.visit(left.arg(0))

            return (
                left_tokens +
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        ' << '
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        str(shift),
                        shift
                    )
                ]
            )

        else:
            var_name = expr.decl().name()
            if var_name[0] == '&':
                var_name = var_name[1:]
            var = next(
                (
                    v
                    for v in self._function.vars
                    if v.name == var_name
                ),
                None
            )

        if var is None:
            log_debug(f"var is None: {expr.decl().name()}")

            return [
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    '<Unknown token>'
                )
            ]

        return (
            [
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    '&'
                )
            ]
            if expr.decl().name()[0] == '&'
            else []
        ) + (
            [
                InstructionTextToken(
                    InstructionTextTokenType.LocalVariableToken,
                    var.name,
                    var.identifier
                )
            ]
        ) + (
            [
                InstructionTextToken(InstructionTextTokenType.TextToken, "."),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken,
                    member_name,
                    var.identifier
                ),
            ]
            if member is not None
            else []
        )
