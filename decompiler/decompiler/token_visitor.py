from itertools import chain

from binaryninja import (InstructionTextToken, InstructionTextTokenType,
                         MediumLevelILOperation, SymbolType, TypeClass,
                         Variable)

from .bnilvisitor import BNILVisitor


class TokenVisitor(BNILVisitor):
    def visit(self, expr):
        value = super().visit(expr)

        if value is None:
            return expr.tokens
        else:
            return value

    def visit_MLIL_STORE(self, expr):
        tokens = ArrayTokenVisitor().visit(expr.dest)

        if not isinstance(tokens, list):
            dest_tokens = self.visit(expr.dest)
            # Add the '*'
            tokens = [
                InstructionTextToken(InstructionTextTokenType.TextToken, "*")
            ]

            if len(dest_tokens) == 1:
                tokens.extend(dest_tokens)
            else:
                tokens.extend(
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, "("
                        ),
                        *dest_tokens,
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, ")"
                        ),
                    ]
                )

        src_tokens = self.visit(expr.src)

        tokens.extend(
            [
                InstructionTextToken(
                    InstructionTextTokenType.TextToken, " = "
                ),
                *src_tokens,
            ]
        )

        return tokens

    def visit_MLIL_LOAD(self, expr):
        src_tokens = ArrayTokenVisitor().visit(expr.src)

        if isinstance(src_tokens, list):
            return src_tokens

        src_tokens = self.visit(expr.src)

        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, "*")
        ]

        if len(src_tokens) == 1:
            tokens.extend(src_tokens)
        else:
            tokens.extend(
                [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, "("
                    ),
                    *src_tokens,
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, ")"
                    ),
                ]
            )
        
        return tokens

    def visit_MLIL_SET_VAR(self, expr):
        src_tokens = self.visit(expr.src)

        return [
            InstructionTextToken(
                InstructionTextTokenType.LocalVariableToken,
                expr.dest.name,
                expr.dest.identifier
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' = '
            ),
            *src_tokens
        ]

    def visit_MLIL_SET_VAR_FIELD(self, expr):
        src_tokens = self.visit(expr.src)

        dest = expr.dest
        offset = expr.offset
        size = expr.size

        if dest.type.width == size and offset == 0:
            return [
                InstructionTextToken(
                    InstructionTextTokenType.LocalVariableToken,
                    expr.dest.name,
                    expr.dest.identifier
                ),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ' = '
                ),
                *src_tokens
            ]

    def visit_MLIL_VAR_FIELD(self, expr):
        src = expr.src
        offset = expr.offset
        size = expr.size

        if src.type.width == size and offset == 0:
            return [
                InstructionTextToken(
                    InstructionTextTokenType.LocalVariableToken,
                    expr.src.name,
                    expr.src.identifier
                )
            ]

    def visit_MLIL_CALL(self, expr):
        print(f'visit_MLIL_CALL: {expr}')
        output = [
            InstructionTextToken(
                InstructionTextTokenType.LocalVariableToken,
                v.name,
                v.identifier
            )
            for v in expr.output
        ]
        dest = self.visit(expr.dest)
        params = [self.visit(p) for p in expr.params]

        for p in params[:-1]:
            p.append(
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ', '
                )
            )

        print(f'output: {output}')
        print(f'dest: {dest}')
        print(f'params: {list(chain(*params))}')

        return [
            *output,
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' = ' if output else ''
            ),
            *dest,
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                '('
            ),
            *chain(*params),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ')'
            )
        ]

    def visit_MLIL_MUL(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        return [
            *left,
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' * '
            ),
            *right
        ]

    def visit_MLIL_CONST_PTR(self, expr):
        print(f'MLIL_CONST_PTR: {expr.constant:x}')
        view = expr.function.source_function.view
        symbol = view.get_symbol_at(expr.constant)
        string = view.get_string_at(expr.constant)

        if string is not None:
            return [
                InstructionTextToken(
                    InstructionTextTokenType.StringToken,
                    repr(string.value),
                    string.start
                )
            ]

        elif symbol is not None:
            NormalSymbols = (SymbolType.FunctionSymbol, SymbolType.DataSymbol)
            ImportSymbols = (
                SymbolType.ImportedFunctionSymbol,
                SymbolType.ImportedDataSymbol
            )

            return [
                InstructionTextToken(
                    (
                        InstructionTextTokenType.CodeSymbolToken
                        if symbol.type in NormalSymbols
                        else InstructionTextTokenType.ImportToken
                        if symbol.type in ImportSymbols
                        else InstructionTextTokenType.PossibleAddressToken
                    ),
                    symbol.short_name,
                    expr.constant,
                    size=expr.size,
                    address=expr.address
                )
            ]

    visit_MLIL_CONST = visit_MLIL_CONST_PTR
    visit_MLIL_IMPORT = visit_MLIL_CONST_PTR


class ArrayTokenVisitor(BNILVisitor):
    def visit_MLIL_CONST(self, expr):
        return expr.constant

    visit_MLIL_CONST_PTR = visit_MLIL_CONST

    def visit_MLIL_VAR(self, expr):
        return expr.src

    def visit_MLIL_VAR_FIELD(self, expr):
        # TODO this is not going to work potentially
        return expr.src

    def visit_MLIL_LSL(self, expr):
        return self.visit(expr.left), self.visit(expr.right)

    def visit_MLIL_ADDRESS_OF(self, expr):
        return expr.src

    def visit_MLIL_ADD(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if (
            not isinstance(left, Variable) or
            (
                left.type.type_class != TypeClass.ArrayTypeClass and
                left.type.type_class != TypeClass.PointerTypeClass and
                expr.left.operation != MediumLevelILOperation.MLIL_ADDRESS_OF
            )
        ):
            return

        if isinstance(right, int):
            element_width = left.type.element_type.width
            index = element_width // right
        elif isinstance(right, tuple):
            index_shift = right[1]
            index = right[0]

        return [
            InstructionTextToken(
                InstructionTextTokenType.LocalVariableToken,
                left.name,
                left.identifier
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                '['
            ),
            InstructionTextToken(
                InstructionTextTokenType.LocalVariableToken,
                index.name,
                index.identifier
            ) if isinstance(index, Variable)
            else InstructionTextToken(
                InstructionTextTokenType.IntegerToken,
                str(index),
                index
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ']'
            )
        ]
