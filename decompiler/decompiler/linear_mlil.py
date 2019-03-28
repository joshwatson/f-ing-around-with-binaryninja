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

from binaryninja.function import DisassemblyTextRenderer, DisassemblyTextLine
from binaryninja.datarender import InstructionTextToken
from binaryninja.mediumlevelil import MediumLevelILOperation
from binaryninja.lineardisassembly import LinearDisassemblyLine
from binaryninja.enums import LinearDisassemblyLineType, DisassemblyOption, InstructionTextTokenType
from binaryninjaui import TokenizedTextView, TokenizedTextViewHistoryEntry, ViewType

from collections import namedtuple
from itertools import repeat

from .mlil_ast import MediumLevelILAst
from .nodes import MediumLevelILAstCondNode, MediumLevelILAstSeqNode, MediumLevelILAstSwitchNode


class LinearMLILView(TokenizedTextView):
    def __init__(self, parent, data):
        super(LinearMLILView, self).__init__(parent, data)
        self.data = data
        self.function = data.entry_function
        if self.function is not None:
            self.setFunction(self.function)
            self.updateLines()

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
        result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionHeaderStartLineType,
            self.function, None, 0, DisassemblyTextLine([], self.function.start)))
        result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionHeaderLineType,
            self.function, None, 0, DisassemblyTextLine(self.function.type_tokens, self.function.start)))
        result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionHeaderEndLineType,
            self.function, None, 0, DisassemblyTextLine([], self.function.start)))

        line_index = 0
        for il in ast.root.block:
            if ((il.instr_index == ast.root.block[-1].instr_index) and
                    il.operation in (
                        MediumLevelILOperation.MLIL_IF,
                        MediumLevelILOperation.MLIL_JUMP_TO,
                        MediumLevelILOperation.MLIL_GOTO,
                        MediumLevelILOperation.MLIL_NORET
                    )):
                    continue

            il_lines, length = renderer.get_disassembly_text(il.instr_index)
            for line in il_lines:
                result.append(LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType,
                    self.function, il.il_basic_block, line_index, line))
                line_index += 1

        to_visit = [
            (n, 0)
            for header, n in sorted(
                ast._regions.items(), key=lambda i: i[0].start, reverse=True
            )
        ]

        prev_indent = 0
        last_il = il
        while to_visit:
            current_node, indent = to_visit.pop()

            if indent < prev_indent:
                result.append(LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType,
        			self.function, last_il.il_basic_block, line_index, DisassemblyTextLine([], last_il.instr_index)))

            if isinstance(current_node, MediumLevelILAstSeqNode):
                for il in current_node.header:
                    if (il.instr_index == current_node.header.end - 1) and il.operation in (
                        MediumLevelILOperation.MLIL_IF,
                        MediumLevelILOperation.MLIL_JUMP_TO,
                        MediumLevelILOperation.MLIL_GOTO,
                        MediumLevelILOperation.MLIL_NORET
                    ):
                        continue

                    il_lines, length = renderer.get_disassembly_text(il.instr_index)

                    for line in il_lines:
                        line.tokens.insert(
                            0,
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken,
                                f'{" "*indent}'
                            )
                        )

                        result.append(
                            LinearDisassemblyLine(
                                LinearDisassemblyLineType.CodeDisassemblyLineType,
                                self.function,
                                il.il_basic_block,
                                line_index,
                                line
                            )
                        )

                        line_index += 1

                to_visit += zip(reversed(current_node.children), repeat(indent))

            elif isinstance(current_node, MediumLevelILAstCondNode):
                il_line = DisassemblyTextLine([], current_node.condition.instr_index)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.KeywordToken,
                        "if"
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                            " ("
                    ),
                    *current_node.condition.tokens,
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                            "):"
                    )
                ]

                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line
                    )
                )

                line_index += 1

                to_visit += zip(reversed(current_node.children), repeat(indent + 4))

            elif isinstance(current_node, MediumLevelILAstSwitchNode):
                il_line = DisassemblyTextLine([], current_node.switch.instr_index)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.KeywordToken,
                        "switch"
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                            " ("
                    ),
                    *current_node.switch.tokens,
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                            "):"
                    ),
                ]

                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line
                    )
                )

                line_index += 1

                to_visit += zip(reversed(sorted(current_node.cases.items(), key=lambda i: i[0])), repeat(indent + 4))

            elif isinstance(current_node, tuple):
                il_line = DisassemblyTextLine([], current_node[1].start)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.OpcodeToken,
                        "case "
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        str(current_node[0]),
                        current_node[0]
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                            ":"
                    ),
                ]

                result.append(
                    LinearDisassemblyLine(
                        LinearDisassemblyLineType.CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line
                    )
                )

                line_index += 1

                to_visit += [(current_node[1], indent + 4)]

            prev_indent = indent
            last_il = il

        # Display IL instructions in order
        # lastAddr = self.function.start
        # lastBlock = None
        # lineIndex = 0
        # for block in il:
        # 	if lastBlock is not None:
        # 		# Blank line between basic blocks
        # 		result.append(LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType,
        # 			self.function, block, 0, DisassemblyTextLine([], lastAddr)))
        # 	for i in block:
        # 		lines, length = renderer.get_disassembly_text(i.instr_index)
        # 		lastAddr = i.address
        # 		lineIndex = 0
        # 		for line in lines:
        # 			result.append(LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType,
        # 				self.function, block, lineIndex, line))
        # 			lineIndex += 1
        # 	lastBlock = block

        result.append(LinearDisassemblyLine(LinearDisassemblyLineType.FunctionEndLineType,
            self.function, last_il.il_basic_block, line_index, DisassemblyTextLine([], last_il.instr_index)))

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
        if hasattr(entry, 'function'):
            self.function = entry.function
            self.setFunction(self.function)
            self.updateLines()
        super(LinearMLILView, self).navigateToHistoryEntry(entry)


# View type for the new view
class LinearMLILViewType(ViewType):
    def __init__(self):
        super(LinearMLILViewType, self).__init__("Linear MLIL", "Linear MLIL")

    def getPriority(self, data, filename):
        if data.executable:
            # Use high priority so that this view is picked by default
            return 100
        return 0

    def create(self, data, view_frame):
        return LinearMLILView(view_frame, data)
