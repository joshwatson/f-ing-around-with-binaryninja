from binaryninja import (BinaryView, DisassemblyTextLine,
                         DisassemblyTextRenderer, FlowGraph, FlowGraphNode,
                         InstructionTextToken, InstructionTextTokenType,
                         log_info, log_error, BranchType, MediumLevelILOperation)
from collections import namedtuple
from itertools import repeat

from .mlil_ast import MediumLevelILAst
from .nodes import MediumLevelILAstCondNode, MediumLevelILAstSeqNode, MediumLevelILAstSwitchNode

class MlilLinear(FlowGraph):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.il_function = function.mlil

        self.uses_block_highlights = False
        self.uses_instruction_highlights = True
        self.includes_user_comments = True
        self.allows_patching = False
        self.shows_secondary_reg_highlighting = True

    def populate_nodes(self):
        il = self.il_function
        il_renderer = DisassemblyTextRenderer(il)

        node = FlowGraphNode(self)
        self.append(node)

        ast = MediumLevelILAst(self.il_function)
        ast.generate()
        
        for il in ast.root.block:
            if il.instr_index != ast.root.block.end - 1:
                il_lines, length = il_renderer.get_disassembly_text(il.instr_index)
                node.lines += il_lines

        to_visit = [
            (n, 0)
            for header, n in sorted(
                ast._regions.items(), key=lambda i: i[0].start, reverse=True
            )
        ]

        prev_indent = 0

        while to_visit:
            current_node, indent = to_visit.pop()

            if indent < prev_indent:
                node.lines += [DisassemblyTextLine([])]

            if isinstance(current_node, MediumLevelILAstSeqNode):
                for il in current_node.header:
                    if (il.instr_index == current_node.header.end - 1) and il.operation not in (
                        MediumLevelILOperation.MLIL_RET,
                        MediumLevelILOperation.MLIL_RET_HINT,
                    ):
                        continue

                    il_lines, length = il_renderer.get_disassembly_text(il.instr_index)

                    for line in il_lines:
                        line.tokens.insert(
                            0,
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken,
                                f'{" "*indent}'
                            )
                        )

                    node.lines += il_lines

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

                node.lines += [il_line]

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

                node.lines += [il_line]

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

                node.lines += [il_line]

                to_visit += [(current_node[1], indent + 4)]

            prev_indent = indent

    def update(self):
        return MlilLinear(self.function)

try:
    from binaryninjaui import FlowGraphWidget, ViewFrame, ViewType

    class MlilLinearView(FlowGraphWidget):
        def __init__(self, parent: ViewFrame, data: BinaryView):
            self.data = data
            self.function = data.entry_function
            if self.function is None:
                graph = None
            else:
                graph = MlilLinear(self.function)

            super().__init__(parent, data, graph)

        def navigate(self, addr):
            block = self.data.get_recent_basic_block_at(addr)
            if block is None:
                func = self.data.get_recent_function_at(addr)
            else:
                func = block.function

            if func is None:
                return False

            return self.navigateToFunction(func, addr)

        def navigateToFunction(self, func, addr):
            if func == self.function:
                self.showAddress(addr, True)
                return True

            self.function = func
            graph = MlilLinear(func)
            self.setGraph(graph, addr)
            return True


    class MlilLinearViewType(ViewType):
        def __init__(self):
            super().__init__('MLIL Linear', 'Linear MLIL View')

        def getPriority(self, data, filename):
            if data.executable:
                return 100
            return 0

        def create(self, data, view_frame):
            return MlilLinearView(view_frame, data)

except ImportError:
    pass