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

from itertools import repeat

from z3 import Not, is_false

from binaryninja import (
    BinaryDataNotification,
    InstructionTextToken,
    RegisterValueType,
    Settings,
    log_debug,
    Variable,
)
from binaryninja.enums import (
    # DisassemblyOption,
    InstructionTextTokenType,
    LinearDisassemblyLineType,
)
from binaryninja.function import DisassemblyTextLine, DisassemblyTextRenderer
from binaryninja.lineardisassembly import LinearDisassemblyLine
from binaryninja.mediumlevelil import MediumLevelILOperation
from binaryninjaui import (
    TokenizedTextView,
    TokenizedTextViewHistoryEntry,
    ViewType,
)
from PySide2.QtCore import Qt

from .constraint_visitor import ConstraintVisitor
from .mlil_ast import MediumLevelILAst
from .nodes import MediumLevelILAstElseNode
from .token_visitor import TokenVisitor

_CodeDisassemblyLineType = LinearDisassemblyLineType.CodeDisassemblyLineType


class LinearMLILView(TokenizedTextView, BinaryDataNotification):
    def __init__(self, parent, data):
        super(LinearMLILView, self).__init__(parent, data)
        BinaryDataNotification.__init__(self)
        self.data = data

        self.data.register_notification(self)

        self.function = data.get_recent_function_at(data.offset)
        if self.function is None:
            self.function = data.entry_function

        self.function_cache = {}
        if self.function is not None:
            self.setFunction(self.function)
        self.updateLines()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

    def generateLines(self):
        if self.function is None:
            return []

        if self.function in self.function_cache:
            return self.function_cache[self.function]

        mlil = self.function.mlil

        # Set up IL display options
        renderer = DisassemblyTextRenderer(mlil)
        # renderer.settings.set_option(DisassemblyOption.ShowAddress)
        # renderer.settings.set_option(
        #     DisassemblyOption.ShowVariableTypesWhenAssigned
        # )

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
                DisassemblyTextLine(
                    self.function.type_tokens, self.function.start
                ),
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

        # add variables
        for var in self.function.vars:
            var_line = DisassemblyTextLine([], 0)

            var_line.tokens += var.type.get_tokens_before_name()
            var_line.tokens += [
                InstructionTextToken(InstructionTextTokenType.TextToken, " "),
                InstructionTextToken(
                    InstructionTextTokenType.LocalVariableToken,
                    var.name,
                    var.identifier,
                ),
                InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            ]
            var_line.tokens += var.type.get_tokens_after_name()

            result.append(
                LinearDisassemblyLine(
                    LinearDisassemblyLineType.LocalVariableLineType,
                    self.function,
                    None,
                    0,
                    var_line,
                )
            )

        result.append(
            LinearDisassemblyLine(
                LinearDisassemblyLineType.LocalVariableListEndLineType,
                self.function,
                None,
                0,
                DisassemblyTextLine([], 0),
            )
        )

        line_index = 0

        to_visit = [(ast.regions[0][1], 0)]

        prev_indent = 0
        indent = 0
        il = self.function.mlil[0]
        last_il = self.function.mlil[0]
        do_while = []
        while to_visit:
            current_node, indent = to_visit.pop()

            if indent < prev_indent:
                for i in range(prev_indent - 4, indent - 4, -4):
                    il_line = DisassemblyTextLine(
                        [
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken,
                                f'{" "*i}}}',
                            )
                        ],
                        last_il.address,
                    )

                    if do_while and do_while[-1][0] == i:
                        condition = do_while.pop()[1]
                        il_line.tokens += [
                            InstructionTextToken(
                                InstructionTextTokenType.KeywordToken, " while"
                            ),
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, "("
                            ),
                            *condition,
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, ")"
                            ),
                        ]

                    result.append(
                        LinearDisassemblyLine(
                            _CodeDisassemblyLineType,
                            self.function,
                            last_il.il_basic_block,
                            line_index,
                            il_line,
                        )
                    )

            if current_node.type == "seq":
                to_visit += zip(reversed(current_node.nodes), repeat(indent))

            elif current_node.type == "block":
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

                    il_lines, _ = renderer.get_disassembly_text(il.instr_index)

                    for line in il_lines:

                        new_tokens = TokenVisitor().visit(il)

                        line.tokens = [
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken,
                                f'{" "*indent}',
                            ),
                            *new_tokens
                        ]                            

                        result.append(
                            LinearDisassemblyLine(
                                _CodeDisassemblyLineType,
                                self.function,
                                il.il_basic_block,
                                line_index,
                                line,
                            )
                        )

                        line_index += 1

            elif current_node.type == "break":
                il_line = DisassemblyTextLine([], current_node.address)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, "break"
                    ),
                ]

                result.append(
                    LinearDisassemblyLine(
                        _CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

            elif current_node.type == "cond":
                if is_false(current_node.condition):
                    continue

                if current_node[True] is not None:
                    condition = ConstraintVisitor(self.function).visit(
                        current_node.condition
                    )
                elif current_node[False] is not None:
                    condition = ConstraintVisitor(self.function).visit(
                        Not(current_node.condition)
                    )

                il_line = DisassemblyTextLine([], current_node.address)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.KeywordToken, "if"
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, " ("
                    ),
                    *condition,
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, ") {"
                    ),
                ]

                result.append(
                    LinearDisassemblyLine(
                        _CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

                if current_node[False] is not None:
                    to_visit.append((current_node[False], indent + 4))

                    # Append a node that will tell us that the next node is
                    # an else block
                    if current_node[True] is not None:
                        to_visit.append(
                            (
                                MediumLevelILAstElseNode(
                                    self, current_node.address
                                ),
                                indent,
                            )
                        )

                if current_node[True] is not None:
                    to_visit.append((current_node[True], indent + 4))

            elif current_node.type == "else":
                il_line = DisassemblyTextLine([], current_node.address)

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.KeywordToken, "else"
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, " {"
                    ),
                ]

                result.append(
                    LinearDisassemblyLine(
                        _CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

            elif current_node.type == "loop":
                condition = ConstraintVisitor(self.function).visit(
                    current_node.condition
                )

                il_line = DisassemblyTextLine([], current_node.address)

                il_line.tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    )
                )

                if current_node.loop_type in ("while", "endless"):
                    il_line.tokens += [
                        InstructionTextToken(
                            InstructionTextTokenType.KeywordToken, "while"
                        ),
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, " ("
                        ),
                        *condition,
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, ") {"
                        ),
                    ]
                elif current_node.loop_type == "dowhile":
                    il_line.tokens += [
                        InstructionTextToken(
                            InstructionTextTokenType.KeywordToken, "do"
                        ),
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, " {"
                        ),
                    ]

                    do_while.append((indent, condition))

                result.append(
                    LinearDisassemblyLine(
                        _CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

                to_visit += zip(
                    reversed(current_node.body.nodes), repeat(indent + 4)
                )

            elif current_node.type == "switch":
                il_line = DisassemblyTextLine([], current_node.address)

                condition = ConstraintVisitor(self.function).visit(
                    current_node.switch
                )

                il_line.tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f'{" "*indent}'
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.KeywordToken, "switch"
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, " ("
                    ),
                    *condition,
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, ") {"
                    ),
                ]

                result.append(
                    LinearDisassemblyLine(
                        _CodeDisassemblyLineType,
                        self.function,
                        il.il_basic_block,
                        line_index,
                        il_line,
                    )
                )

                line_index += 1

                to_visit += zip(
                    reversed(current_node.cases), repeat(indent + 4)
                )

            elif current_node.type == "case":
                il_line = DisassemblyTextLine([], current_node.address)

                for idx, v in enumerate(current_node.value):
                    il_line.tokens += [
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, f'{" "*indent}'
                        ),
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, "case "
                        ),
                        (
                            InstructionTextToken(
                                InstructionTextTokenType.IntegerToken,
                                str(v),
                                v
                            ) if v != 'default' else
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, v
                            )
                        )
                    ]

                    if idx == len(current_node.value) - 1:
                        il_line.tokens.append(
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, " {"
                            )
                        )

                    result.append(
                        LinearDisassemblyLine(
                            _CodeDisassemblyLineType,
                            self.function,
                            il.il_basic_block,
                            line_index,
                            il_line,
                        )
                    )

                    line_index += 1

                    il_line = DisassemblyTextLine([], current_node.address)

                to_visit += zip(
                    reversed(current_node.nodes), repeat(indent + 4)
                )

            prev_indent = indent
            last_il = il

        if indent != 0:
            for i in range(indent, 0, -4):
                result.append(
                    LinearDisassemblyLine(
                        _CodeDisassemblyLineType,
                        self.function,
                        last_il.il_basic_block,
                        line_index,
                        DisassemblyTextLine(
                            [
                                InstructionTextToken(
                                    InstructionTextTokenType.TextToken,
                                    f'{" "*(i-4)}}}',
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

        self.function_cache[self.function] = result

        log_debug("generateLines finished")

        return result


    def eliminate_unused_vars(self, lines):
        log_debug("eliminate_unused_vars")

        lines_to_remove = []
        instructions_removed = True
        indices_removed = set()
        untracked_variables = set()

        while instructions_removed:
            instructions_removed = False

            for line in lines:
                if line.type != _CodeDisassemblyLineType:
                    continue

                contents: DisassemblyTextLine = line.contents

                il = contents.il_instruction

                if il is None:
                    used_vars = [
                        Variable.from_identifier(
                            self.function, t.value
                        )
                        for t in contents.tokens
                        if t.type
                        == InstructionTextTokenType.LocalVariableToken
                    ]

                    # no variables? Don't care
                    if not used_vars:
                        continue

                    for var in used_vars:
                        # we'll be conservative and save all definitions
                        # of a particular Variable since we can't be sure
                        # of the SSA version here
                        untracked_variables.update(
                            set(
                                (
                                    i.instr_index
                                    for i in self.function.mlil.get_var_definitions(var)
                                )
                            )
                        )

                    continue

                elif (
                    il.instr_index in indices_removed or
                    il.instr_index in untracked_variables
                ):
                    # We want to skip this if it's already been removed or
                    # We know we don't want to remove it
                    continue

                if il.operation == MediumLevelILOperation.MLIL_SET_VAR:
                    # does this var have any uses later on? If not, let's
                    # remove it from the lines
                    uses = il.function.get_ssa_var_uses(il.ssa_form.dest)

                    if not uses:
                        lines_to_remove.append(line)
                        indices_removed.add(il.instr_index)
                        instructions_removed = True
                    elif all(
                        use.instr_index in indices_removed for use in uses
                    ):
                        lines_to_remove.append(line)
                        indices_removed.add(il.instr_index)
                        instructions_removed = True
                    else:
                        for use in uses:
                            if (
                                use.operation
                                == MediumLevelILOperation.MLIL_JUMP_TO
                            ):
                                dest_values = use.dest.possible_values
                                # if this is a jump table of some sort, then we
                                # can remove it
                                if dest_values.type in (
                                    RegisterValueType.InSetOfValues,
                                    RegisterValueType.LookupTableValue,
                                    RegisterValueType.NotInSetOfValues,
                                    RegisterValueType.SignedRangeValue,
                                    RegisterValueType.UnsignedRangeValue,
                                ):
                                    lines_to_remove.append(line)
                                    indices_removed.add(il.instr_index)
                                    instructions_removed = True

        for line in lines:
            if (line.type ==
                    LinearDisassemblyLineType.LocalVariableLineType):
                var = next(
                    Variable.from_identifier(self.function, t.value)
                    for t in line.contents.tokens
                    if (t.type ==
                        InstructionTextTokenType.LocalVariableToken)
                )
                defs = self.function.mlil.get_var_definitions(var)
                if var in self.function.parameter_vars.vars:
                    continue
                elif (not defs and
                        not self.function.mlil.get_var_uses(var)):
                    lines_to_remove.append(line)
                elif all(
                    d.instr_index in indices_removed
                    for d in defs
                ):
                    lines_to_remove.append(line)

        for line in lines_to_remove:
            lines.remove(line)

        return lines

    def function_updated(self, view, function):
        log_debug('function_updated')
        if function in self.function_cache:
            del self.function_cache[function]

        # if function == self.function:
        #     self.updateLines()

    function_update_requested = function_updated

    def updateLines(self):
        log_debug("updateLines")
        lines = self.generateLines()
        lines = self.eliminate_unused_vars(lines)
        self.setUpdatedLines(lines)
        log_debug("updateLines finished")

    def navigate(self, addr):
        # Find correct function based on most recent use
        block = self.data.get_recent_basic_block_at(addr)
        if block is None:
            # If function isn't done analyzing yet, it may have a function
            # start but no basic blocks
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
        settings.register_group("linearmlil", "Linear MLIL")
        settings.register_setting(
            "linearmlil.priority",
            (
                """{
                "description": "Set the priority for the Linear MLIL view.",
                "title": "View Priority",
                "default" : 100,
                "type" : "number",
                "id" : "priority"
            }"""
            ),
        )
        settings.register_setting(
            "linearmlil.debug",
            (
                """{
                    "description": "Turn on debug reports for Linear MLIL view.",
                    "title": "Show Debug Graphs",
                    "default": true,
                    "type": "boolean",
                    "id": "debug"
                }
                """
            )
        )

    def getPriority(self, data, filename):
        if data.executable:
            # Higher priority will make this view the default
            priority = Settings().get_integer("linearmlil.priority", data)
            return priority
        return 0

    def create(self, data, view_frame):
        return LinearMLILView(view_frame, data)
