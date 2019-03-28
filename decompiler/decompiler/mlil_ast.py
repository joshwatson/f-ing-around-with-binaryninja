from __future__ import annotations

from collections import deque
from functools import reduce
from itertools import repeat

from binaryninja import (
    MediumLevelILOperation,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILBasicBlock,
    BranchType,
    Variable,
    VariableSourceType,
    ILBranchDependence,
    InstructionTextTokenType,
    PossibleValueSet,
    RegisterValueType
)

from .region import Region
from .nodes import (
    MediumLevelILAstNode,
    MediumLevelILAstSeqNode,
    MediumLevelILAstCondNode,
    MediumLevelILAstBasicBlockNode,
    MediumLevelILAstSwitchNode
)
from .condition_visitor import ConditionVisitor


class MediumLevelILAst(object):
    def __init__(self, function: MediumLevelILFunction):
        self._function = function
        self.view = function.source_function.view
        self._nodes = {}
        self._root = MediumLevelILAstBasicBlockNode(self, function.basic_blocks[0])
        self._dominated = None
        self._regions = {}
        self._reaching_conditions = None

    def __getitem__(self, bb) -> MediumLevelILAstNode:
        return self._nodes[bb]

    def __setitem__(self, bb, node) -> None:
        self._nodes[bb] = node

    def pop(self, bb) -> MediumLevelILAstNode:
        self._nodes.pop(bb)

    def __contains__(self, bb) -> bool:
        return bb in self._nodes

    @property
    def function(self) -> MediumLevelILFunction:
        return self._function

    @property
    def root(self) -> MediumLevelILAstNode:
        return self._root

    @root.setter
    def root(self, new_root: MediumLevelILAstNode):
        if not isinstance(new_root, MediumLevelILAstNode):
            raise TypeError(
                f"new_root must be a MediumLevelILAstNode, got {type(new_root)}"
            )
        self._root = new_root

    @property
    def dominated(self) -> dict:
        return dict(self._dominated)

    @property
    def cycles(self) -> set:
        return set(self._cycles)

    @property
    def regions(self):
        return sorted(self._regions.items(), key=lambda i: i[0].start)

    @property
    def nodes(self):
        return dict(self._nodes)

    # this is a modified version of Algorithm 1 in "no more gotos"
    @property
    def reaching_conditions(self):
        if self._reaching_conditions is not None:
            return self._reaching_conditions

        basic_blocks = self._function.basic_blocks

        reaching_conditions = {}

        for bb in reversed(basic_blocks):
            for d in bb.dominators:
                # skip the simple case of a node being its own dominator
                if d == bb:
                    continue

                edges = d.outgoing_edges

                # we are tracking edges rather than nodes
                dfs_stack = []

                visited_edges = set()

                while edges:
                    e = edges.pop()

                    nt = e.target

                    if e not in visited_edges:
                        # add the edges of this node to the DFS
                        edges += nt.outgoing_edges

                        # mark the edge as visited so we don't visit it again
                        visited_edges.add(e)

                        # push the edge onto the stack
                        dfs_stack = dfs_stack + [e]

                        # if this is the end of the slice, then add it to the list
                        if nt == bb and dfs_stack:
                            reaching_conditions[(d, bb)] = reaching_conditions.get(
                                (d, bb), list()
                            )
                            reaching_conditions[(d, bb)].append(dfs_stack)

                    # if the current node already has a slice to the target, but the
                    # target node isn't in the dfs stack, then we must have found
                    # a cycle. We don't care about the conditions of the cycle, just
                    # the simple exit condition.
                    elif (nt, bb) in reaching_conditions and e not in dfs_stack:
                        reaching_conditions[(d, bb)] = reaching_conditions.get(
                            (d, bb), list()
                        )
                        reaching_conditions[(d, bb)].append(dfs_stack)

                    # if all of the descendants of a node have been visited, then pop it off the stack
                    while len(dfs_stack) and all(
                        descendant in visited_edges
                        for descendant in dfs_stack[-1].target.outgoing_edges
                    ):
                        dfs_stack = dfs_stack[:-1]

        self._reaching_conditions = reaching_conditions

        return reaching_conditions

    def generate(self):
        # step 1: identify cycles
        self._cycles = {
            e.target
            for bb in self.function.basic_blocks
            for e in bb.outgoing_edges
            if e.back_edge
        }

        # step 2: generate the list of what each bb dominates
        self._dominated = self._generate_dominated()

        # step 3: find all the regions
        self._regions = self._find_regions()

        # step 4: iterate through the regions and structure them
        self._structure_regions()

        # step 5: order the regions
        self.order_regions()

    def _generate_dominated(self):
        basic_blocks = self.function.basic_blocks
        dominated = {bb: set() for bb in basic_blocks}

        for bb in basic_blocks:
            for d in bb.dominators:
                dominated[d].add(bb)

        return dominated

    def _find_regions(self):
        basic_blocks = self._function.basic_blocks

        regions = self._regions

        for bb in reversed(basic_blocks):
            if bb.start == 0:
                continue

            if bb not in self._cycles:
                if next((e for e in bb.outgoing_edges if e.back_edge), None):
                    # a back edge node isn't going to be the root of a region
                    continue

                is_switch = False
                if bb[-1].operation == MediumLevelILOperation.MLIL_JUMP_TO:
                    switch = bb[-1].dest.possible_values.mapping
                    cases = {regions[next(b for b in self._function.basic_blocks if b.source_block.start == t)]: v for v, t in switch.items()}

                    is_switch = True

                    # TODO: figure out fall through cases
                    switch_condition = self._find_switch_condition(bb[-1].dest, switch.keys())
                    switch_node = MediumLevelILAstSwitchNode(self, switch_condition)

                # bb must be the head of an acyclic region (for the moment)
                possible_region = self.dominated[bb]

                for c in self._cycles:
                    if c in possible_region:
                        possible_region = possible_region - self.dominated[c]

                # remove any nodes dominated by existing regions
                for r in regions:
                    if r in possible_region:
                        possible_region = possible_region - self.dominated[r]
                        possible_region.add(r)

                # remove any sub regions from our list of regions
                nodes = []
                for r in possible_region:
                    if r in regions:
                        sub_region = regions[r]

                        if sub_region.acyclic:
                            if (self.generate_reaching_condition_MLIL(bb, r)):
                                new_node = self.convert_region_to_cond(bb, sub_region)
                            else:
                                new_node = self.convert_region_to_seq(sub_region)
                        else:
                            new_node = self.convert_region_to_loop(sub_region)

                        if not is_switch:
                            nodes.append(new_node)
                        else:
                            if r not in cases:
                                nodes.append(new_node)
                            else:
                                switch_node[cases[r]] = new_node

                        del regions[r]
                    else:
                        nodes.append(r)

                if is_switch:
                    nodes.append(switch_node)

                new_region = Region(
                    self, MediumLevelILAstBasicBlockNode(self, bb), nodes=nodes
                )
                
                new_region = self.structure_acyclic_region(bb, new_region)
            else:
                possible_region = self.dominated[bb]

                final_region = possible_region

                for r in possible_region:
                    if next((e for e in r.outgoing_edges if e.back_edge), None):
                        final_region = final_region - self.dominated[r]

                        # add r back to possible_region since it was in both
                        final_region.add(r)

                new_region = Region(
                    self,
                    MediumLevelILAstBasicBlockNode(self, bb),
                    acyclic=False,
                    nodes=[
                        MediumLevelILAstBasicBlockNode(self, pr)
                        for pr in final_region
                    ],
                )

                new_region = self.structure_cyclic_region(bb, new_region)

            regions[bb] = new_region

        return regions

    def _find_switch_condition(self, dest, cases):
        def check_ranges(ranges, cases):
            for r in ranges:
                for i in range(r.start, r.end, r.step):
                    if i not in cases:
                        return False

            return True

        to_visit = dest.operands
        while to_visit:
            current_operand = to_visit.pop()
            if not isinstance(current_operand, MediumLevelILInstruction):
                continue

            to_visit += current_operand.operands

            pv = current_operand.possible_values
            if not isinstance(pv, PossibleValueSet):
                continue

            if pv.type not in (
                RegisterValueType.UnsignedRangeValue,
                RegisterValueType.SignedRangeValue,
                RegisterValueType.InSetOfValues
            ):
                continue

            if pv.type != RegisterValueType.InSetOfValues:
                if not check_ranges(pv.ranges, cases):
                    continue
                else:
                    return current_operand

            # If it's InSetOfValues, check to make sure
            # all of the values are in pv.values
            if (all(v in cases for v in pv.values) and
                    len(cases) == len(pv.values)):
                return current_operand
            else:
                continue

    def _structure_regions(self):
        for header, region in sorted(self._regions.items(), key=lambda i: i[0].start):
            if region.acyclic:
                self.structure_acyclic_region(header, region)
            else:
                self.structure_cyclic_region(header, region)

    def convert_region_to_seq(self, sub_region):
        new_seq = MediumLevelILAstSeqNode(self, sub_region.header.block)

        for n in sub_region.nodes:
            new_seq.append(
                MediumLevelILAstBasicBlockNode(self, n)
                if isinstance(n, MediumLevelILBasicBlock)
                else n
            )

        return new_seq

    def convert_region_to_cond(self, bb, sub_region):
        reaching_condition = self.generate_reaching_condition_MLIL(
            bb, sub_region.header.block
        )

        new_cond = MediumLevelILAstCondNode(self, reaching_condition)
        
        new_seq = self.convert_region_to_seq(sub_region)

        new_cond.append(new_seq)
            
        return new_cond

    def convert_region_to_loop(self, sub_region):
        raise NotImplementedError("Loops aren't supported yet")

    def structure_acyclic_region(self, region_header, region):
        return Region(
            self,
            MediumLevelILAstBasicBlockNode(self, region_header),
            nodes=[
                n
                for n in sorted(region.nodes, key=lambda i: i.start)
            ]
        )

    def structure_cyclic_region(self, region_header, region):
        raise NotImplementedError("Loops aren't implemented yet")

    def order_regions(self):

        for header, node in self._regions.items():
            header_dependence = header[0].branch_dependence

            if not header_dependence:
                continue

            if len(header_dependence) > 1:
                raise NotImplementedError()

            for idx, branch in header_dependence.items():
                if branch == ILBranchDependence.TrueBranchDependent:
                    new_region_node = MediumLevelILAstCondNode(
                        self, self._function[idx].condition
                    )
                elif branch == ILBranchDependence.FalseBranchDependent:
                    false_expr = MediumLevelILInstruction(
                        self._function,
                        self._function.expr(
                            MediumLevelILOperation.MLIL_NOT,
                            self._function[idx].condition.expr_index,
                        ).index,
                    )
                    new_region_node = MediumLevelILAstCondNode(self, false_expr)
                else:
                    raise NotImplementedError("I have never seen this")

            if node.acyclic:
                node = self.convert_region_to_seq(node)
            else:
                node = self.convert_region_to_loop(node)

            new_region_node.append(node)

            self._regions[header] = new_region_node

    def generate_reaching_condition_MLIL(self, region_header, bb):
        or_exprs = []

        start = region_header

        if isinstance(bb, MediumLevelILAstSeqNode):
            end = bb.header
        if isinstance(bb, MediumLevelILAstCondNode):
            end = bb[True].header
        elif isinstance(bb, Region):
            end = bb.header.block
        else:
            end = bb

        for condition in self.reaching_conditions[(start, end)]:
            and_exprs = []
            for edge in condition:
                # if the edge isn't in the branch_dependence, we
                # can ignore it for the reaching conditions
                if edge.source.end - 1 not in end[0].branch_dependence:
                    continue

                # we also ignore unconditional branches
                if edge.type == BranchType.UnconditionalBranch:
                    continue

                if edge.type == BranchType.TrueBranch:
                    and_exprs.append(edge.source[-1].condition.expr_index)
                elif edge.type == BranchType.FalseBranch:
                    and_exprs.append(
                        self._function.expr(
                            MediumLevelILOperation.MLIL_NOT,
                            edge.source[-1].condition.expr_index,
                        ).index
                    )
            if and_exprs:
                or_exprs.append(
                    reduce(
                        lambda i, j: self._function.expr(
                            MediumLevelILOperation.MLIL_AND, i, j
                        ).index,
                        and_exprs,
                    )
                )

        return MediumLevelILInstruction(
            self._function,
            reduce(
                lambda i, j: self._function.expr(
                    MediumLevelILOperation.MLIL_OR, i, j
                ).index,
                or_exprs,
            ),
        ) if or_exprs else None

    def __str__(self):
        output = ""
        for il in self.root.block:
            if il.instr_index != self.root.block.end - 1:
                output += f"{il}\n"

        to_visit = [
            (node, 0)
            for header, node in sorted(
                self._regions.items(), key=lambda i: i[0].start, reverse=True
            )
        ]

        prev_indent = 0

        while to_visit:
            node, indent = to_visit.pop()

            if indent < prev_indent:
                output += "\n"

            if isinstance(node, MediumLevelILAstSeqNode):
                for il in node.header:
                    if (il.instr_index == node.header.end - 1) and il.operation not in (
                        MediumLevelILOperation.MLIL_RET,
                        MediumLevelILOperation.MLIL_RET_HINT,
                    ):
                        continue
                    tokens = ""
                    for t in il.tokens:
                        if t.type != InstructionTextTokenType.PossibleAddressToken:
                            tokens += t.text
                        elif self.view.get_symbols(t.value, 1):
                            tokens += self.view.get_symbols(t.value, 1)[0].name
                        elif self.view.get_function_at(t.value):
                            tokens += self.view.get_function_at(t.value).name
                        else:
                            tokens += t.text
                    output += f'{" "*indent}{tokens}\n'
                to_visit += zip(reversed(node.children), repeat(indent))

            elif isinstance(node, MediumLevelILAstCondNode):
                output += f'{" "*indent}if ({node.condition}) then:\n'
                to_visit += zip(reversed(node.children), repeat(indent + 4))

            elif isinstance(node, MediumLevelILAstSwitchNode):
                output += f'{" "*indent}switch({node.switch}):\n'
                to_visit += zip(reversed(sorted(node.cases.items(), key=lambda i: i[0])), repeat(indent + 4))

            elif isinstance(node, tuple):
                output += f'{" "*indent}case {node[0]}:\n'
                to_visit += [(node[1], indent + 4)]

            prev_indent = indent

        return output
