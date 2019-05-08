# Copyright (c) 2019 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from collections import namedtuple
from itertools import repeat

from binaryninja import InstructionTextToken, MediumLevelILBasicBlock, Settings
from binaryninja.enums import (
    DisassemblyOption,
    InstructionTextTokenType,
    LinearDisassemblyLineType,
)
from binaryninja.function import DisassemblyTextLine, DisassemblyTextRenderer
from binaryninja.lineardisassembly import LinearDisassemblyLine
from binaryninja.mediumlevelil import MediumLevelILOperation
from binaryninjaui import TokenizedTextView, TokenizedTextViewHistoryEntry, ViewType
from PySide2.QtCore import Qt

from .mlil_ast import MediumLevelILAst
from .nodes import (
    MediumLevelILAstCondNode,
    MediumLevelILAstElseNode,
    MediumLevelILAstSeqNode,
    MediumLevelILAstSwitchNode,
    MediumLevelILAstLoopNode,
    MediumLevelILAstBasicBlockNode,
    MediumLevelILAstBreakNode
)
from .constraint_visitor import ConstraintVisitor

from functools import cmp_to_key


class LinearMLILView(TokenizedTextView):
    def __init__(self, parent, data):
        super(LinearMLILView, self).__init__(parent, data)
        self.data = data
        self.function = data.entry_function
        if self.function is not None:
            self.setFunction(self.function)
            self.updateLines()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

    def generateLines(self):
        if self.function is None:
            return []

        mlil = self.function.mlil

        # Set up IL display options
        renderer = DisassemblyTextRenderer(mlil)
        # renderer.settings.set_option(DisassemblyOption.ShowAddress)
        renderer.settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)

        ast = MediumLevelILAst(mlil)
        ast.generate()

        # Function header
        result = []
        result.append(
            LinearDisassemblyLine(
                LinearDisassemblyLineType.FunctionHeaderStartLineType,
                self.function,
                None,
                0,
                DisassemblyTextLine([], self.function.start),
            )
        )
        result.append(
            LinearDisassemblyLine(
                LinearDisassemblyLineType.FunctionHeaderLineType,
                self.function,
                None,
                0,
                DisassemblyTextLine(self.function.type_tokens, self.function.start),
            )
        )
        result.append(
            LinearDisassemblyLine(
                LinearDisassemblyLineType.FunctionHeaderEndLineType,
                self.function,
                None,
                0,
                DisassemblyTextLine([], self.function.start),
            )
        )

        line_index = 0
        for il in ast.root.block:
            if (il.instr_index == ast.root.block[-1].instr_index) and il.operation in (
                MediumLevelILOperation.MLIL_IF,
                MediumLevelILOperation.MLIL_JUMP_TO,
                MediumLevelILOperation.MLIL_GOTO,
                MediumLevelILOperation.MLIL_NORET,
            ):
                continue

            il_lines, _ = renderer.get_disassembly_text(il.instr_index)
            for line in il_lines:
                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        line,
                    )
                )
                line_index += 1

        to_visit = [
            (n, 0)
            for header, n in sorted(
                ast._regions.items(), key=cmp_to_key(lambda i, j: 1 if ast.reaching_conditions.get((i[0], j[0])) is None else 1 if i.start > j.start else -1), reverse=True
            )
        ]

        prev_indent = 0
        indent = 0
        last_il = il
        use_else_condition = False
        while to_visit:
            current_node, indent = to_visit.pop()

            if indent < prev_indent:
                for i in range(prev_indent-4, indent-4, -4):
                    result.append(
                        LinearDisassemblyLine(
                            LinearDisassemblyLineType.CodeDisassemblyLineType,
                            self.function,
                            last_il.il_basic_block,
                            line_index,
                            DisassemblyTextLine(
                                [
                                    InstructionTextToken(
                                        InstructionTextTokenType.TextToken,
                                        f'{" "*i}}}',
                                    )
                                ],
                                last_il.address,
                            ),
                        )
                    )

            if isinstance(current_node, MediumLevelILAstSeqNode):
                if isinstance(current_node, MediumLevelILAstElseNode):
                    il_line = DisassemblyTextLine([], current_node.header.start)

                    if use_else_condition:
                        il_line.tokens += [
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, f'{" "*indent}'
                            ),
                            InstructionTextToken(InstructionTextTokenType.KeywordToken, "if"),
                            InstructionTextToken(InstructionTextTokenType.TextToken, " ("),
                            *current_node.condition.tokens,
                            InstructionTextToken(InstructionTextTokenType.TextToken, ") {"),
                        ]

                        result.append(
                            LinearDisassemblyLine(
                                LinearDisassemblyLineType.CodeDisassemblyLineType,
                                self.function,
                                il.il_basic_block,
                                line_index,
                                il_line,
                            )
                        )
                    else:
                        il_line.tokens += [
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, f'{" "*indent}'
                            ),
                            InstructionTextToken(
                                InstructionTextTokenType.KeywordToken, "else"
                            ),
                            InstructionTextToken(InstructionTextTokenType.TextToken, " {"),
                        ]

                        result.append(
                            LinearDisassemblyLine(
                                LinearDisassemblyLineType.CodeDisassemblyLineType,
                                self.function,
                                current_node.header,
                                line_index,
                                il_line,
                            )
                        )

                    indent += 4
                    line_index += 1

                if isinstance(current_node.header, MediumLevelILBasicBlock):
                    for il in current_node.header:
                        if (
                            il.instr_index == current_node.header.end - 1
                        ) and il.operation in (
                            MediumLevelILOperation.MLIL_IF,
                            MediumLevelILOperation.MLIL_JUMP_TO,
                            MediumLevelILOperation.MLIL_GOTO,
                            MediumLevelILOperation.MLIL_NORET,
                        ):
                            continue

                        il_lines, length = renderer.get_disassembly_text(il.instr_index)

                        for line in il_lines:
                            line.tokens.insert(
                                0,
                                InstructionTextToken(
                                    InstructionTextTokenType.TextToken, f'{" "*indent}'
                                ),
                            )

                            result.append(
                                LinearDisassemblyLine(
                                    LinearDisassemblyLineType.CodeDisassemblyLineType,
                                    self.function,
                                    il.il_basic_block,
                                    line_index,
                                    line,
                                )
                            )

                elif isinstance(current_node.header, MediumLevelILAstBreakNode):
                    il_line = DisassemblyTextLine([], current_node.header.address)

                    il_line.tokens += [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, f'{" "*indent}'
                        ),
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, "break"
                        )
                    ]

                    result.append(
                        LinearDisassemblyLine(
                            LinearDisassemblyLineType.CodeDisassemblyLineType,
                            self.function,
                            il.il_basic_block,
                            line_index,
                            il_line,
                        )
                    )

                line_index += 1

                to_visit += zip(reversed(current_node.children), repeat(indent))

            elif isinstance(current_node, MediumLevelILAstBasicBlockNode):
                for il in current_node.block:
                    if (
                        il.instr_index == current_node.block.end - 1
                    ) and il.operation in (
                        MediumLevelILOperation.MLIL_IF,
                        MediumLevelILOperation.MLIL_JUMP_TO,
                        MediumLevelILOperation.MLIL_GOTO,
                        MediumLevelILOperation.MLIL_NORET,
                    ):
                        continue

                    il_lines, length = renderer.get_disassembly_text(il.instr_index)

                    for line in il_lines:
                        line.tokens.insert(
                            0,
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, f'{" "*indent}'
                            ),
                        )

                        result.append(
                            LinearDisassemblyLine(
                                LinearDisassemblyLineType.CodeDisassemblyLineType,
                                self.function,
                                il.il_basic_block,
                                line_index,
                                line,
                            )
                        )

                        line_index += 1

            elif isinstance(current_node, MediumLevelILBasicBlock):
                for il in current_node:
                    if (
                        il.instr_index == current_node.end - 1
                    ) and il.operation in (
                        MediumLevelILOperation.MLIL_IF,
                        MediumLevelILOperation.MLIL_JUMP_TO,
                        MediumLevelILOperation.MLIL_GOTO,
                        MediumLevelILOperation.MLIL_NORET,
                    ):
                        continue

                    il_lines, length = renderer.get_disassembly_text(il.instr_index)

                    for line in il_lines:
                        line.tokens.insert(
                            0,
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, f'{" "*indent}'
                            ),
                        )

                        result.append(
                            LinearDisassemblyLine(
                                LinearDisassemblyLineType.CodeDisassemblyLineType,
                                self.function,
                                il.il_basic_block,
                                line_index,
                                line,
                            )
                        )

                        line_index += 1

            elif isinstance(current_node, MediumLevelILAstCondNode):
                use_else_condition = False

                condition = ConstraintVisitor(self.function).visit(current_node.condition)

                il_line = DisassemblyTextLine([], current_node.address)

                if current_node[True] is not None:
                    il_line.tokens += [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, f'{" "*indent}'
                        ),
                        InstructionTextToken(InstructionTextTokenType.KeywordToken, "if"),
                        InstructionTextToken(InstructionTextTokenType.TextToken, " ("),
                        *condition,
                        InstructionTextToken(InstructionTextTokenType.TextToken, ") {"),
                    ]

                    result.append(
                        LinearDisassemblyLine(
                            LinearDisassemblyLineType.CodeDisassemblyLineType,
                            self.function,
                            il.il_basic_block,
                            line_index,
                            il_line,
                        )
                    )

                line_index += 1

                to_visit.append((current_node[False], indent))

                if current_node[True] is not None:
                    to_visit.append((current_node[True], indent + 4))
                else:
                    use_else_condition = True

            elif isinstance(current_node, MediumLevelILAstBreakNode):
                il_line = DisassemblyTextLine([], current_node.address)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, "break"
                    )
                ]

                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

            elif isinstance(current_node, MediumLevelILAstLoopNode):
                if current_node.condition is not None:
                    condition = ConstraintVisitor(self.function).visit(current_node.condition)

                    il_line = DisassemblyTextLine([], current_node.loop[0].address)

                    il_line.tokens += [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, f'{" "*indent}'
                        ),
                        InstructionTextToken(
                            InstructionTextTokenType.KeywordToken, "while"
                        ),
                        InstructionTextToken(InstructionTextTokenType.TextToken, " ("),
                        *condition,
                        InstructionTextToken(InstructionTextTokenType.TextToken, ") {"),
                    ]

                    result.append(
                        LinearDisassemblyLine(
                            LinearDisassemblyLineType.CodeDisassemblyLineType,
                            self.function,
                            il.il_basic_block,
                            line_index,
                            il_line,
                        )
                    )

                    line_index += 1

                else:
                    raise NotImplementedError("Don't know how to do this yet")

                indent += 4

                for il in current_node.loop:
                    if (
                        il.instr_index == current_node.loop.end - 1
                    ) and il.operation in (
                        MediumLevelILOperation.MLIL_IF,
                        MediumLevelILOperation.MLIL_JUMP_TO,
                        MediumLevelILOperation.MLIL_GOTO,
                        MediumLevelILOperation.MLIL_NORET,
                    ):
                        continue

                    il_lines, length = renderer.get_disassembly_text(il.instr_index)

                    for line in il_lines:
                        line.tokens.insert(
                            0,
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, f'{" "*indent}'
                            ),
                        )

                        result.append(
                            LinearDisassemblyLine(
                                LinearDisassemblyLineType.CodeDisassemblyLineType,
                                self.function,
                                il.il_basic_block,
                                line_index,
                                line,
                            )
                        )

                        line_index += 1

                to_visit += zip(reversed(current_node.children), repeat(indent))

            elif isinstance(current_node, MediumLevelILAstSwitchNode):
                il_line = DisassemblyTextLine([], current_node.switch.address)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.KeywordToken, "switch"
                    ),
                    InstructionTextToken(InstructionTextTokenType.TextToken, " ("),
                    *current_node.switch.tokens,
                    InstructionTextToken(InstructionTextTokenType.TextToken, ") {"),
                ]

                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

                to_visit += zip(
                    reversed(sorted(current_node.cases.items(), key=lambda i: i[0])),
                    repeat(indent + 4),
                )

            elif isinstance(current_node, tuple):
                il_line = DisassemblyTextLine(
                    [], current_node[1].header.source_block.start
                )

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(InstructionTextTokenType.OpcodeToken, "case "),
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        str(current_node[0]),
                        current_node[0],
                    ),
                    InstructionTextToken(InstructionTextTokenType.TextToken, " {"),
                ]

                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

                to_visit += [(current_node[1], indent + 4)]

            prev_indent = indent
            last_il = il

        if indent != 0:
            for i in range(indent, 0, -4):
                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        last_il.il_basic_block,
                        line_index,
                        DisassemblyTextLine(
                            [
                                InstructionTextToken(
                                    InstructionTextTokenType.TextToken, f'{" "*(i-4)}}}'
                                )
                            ],
                            last_il.address,
                        ),
                    )
                )
                line_index += 1

        result.append(
            LinearDisassemblyLine(
                LinearDisassemblyLineType.FunctionEndLineType,
                self.function,
                last_il.il_basic_block,
                line_index,
                DisassemblyTextLine([], last_il.instr_index),
            )
        )

        return result

    def updateLines(self):
        self.setUpdatedLines(self.generateLines())

    def navigate(self, addr):
        # Find correct function based on most recent use
        block = self.data.get_recent_basic_block_at(addr)
        if block is None:
            # If function isn't done analyzing yet, it may have a function start but no basic blocks
            func = self.data.get_recent_function_at(addr)
        else:
            func = block.function

        if func is None:
            # No function contains this address, fail navigation in this view
            return False

        self.function = func
        self.setFunction(self.function)
        self.setLines(self.generateLines())
        return True

    def getHistoryEntry(self):
        class LinearMLILHistoryEntry(TokenizedTextViewHistoryEntry):
            def __init__(self, function):
                super(LinearMLILHistoryEntry, self).__init__()
                self.function = function

        result = LinearMLILHistoryEntry(self.function)
        self.populateDefaultHistoryEntry(result)
        return result

    def navigateToHistoryEntry(self, entry):
        if hasattr(entry, "function"):
            self.function = entry.function
            self.setFunction(self.function)
            self.updateLines()
        super(LinearMLILView, self).navigateToHistoryEntry(entry)


# View type for the new view
class LinearMLILViewType(ViewType):
    def __init__(self):
        super(LinearMLILViewType, self).__init__("Linear MLIL", "Linear MLIL")
        settings = Settings()
        settings.register_group('linearmlil', 'Linear MLIL')
        settings.register_setting(
            'linearmlil.priority', 
            (
            '''{
                "description": "Set the priority for the Linear MLIL view.",
                "title": "View Priority",
                "default" : 100,
                "type" : "number",
                "id" : "priority"
            }'''
            )
        )

    def getPriority(self, data, filename):
        if data.executable:
            # Higher priority will make this view the default
            priority = Settings().get_integer('linearmlil.priority', data)
            return priority
        return 0

    def create(self, data, view_frame):
        return LinearMLILView(view_frame, data)
