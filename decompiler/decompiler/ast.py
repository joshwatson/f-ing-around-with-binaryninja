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
)

from .condition_visitor import ConditionVisitor


def get_dominated(basic_blocks):
    dominated = {bb: set() for bb in basic_blocks}

    for bb in basic_blocks:
        for d in bb.dominators:
            dominated[d].add(bb)

    return dominated


class MediumLevelILAst(object):
    def __init__(self, function: MediumLevelILFunction):
        self._function = function
        self.view = function.source_function.view
        self._nodes = {}
        self._root = MediumLevelILAstBasicBlockNode(self, function.basic_blocks[0])
        self._dominated = None
        self._regions = {}
        self._reaching_conditions = None

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

    def _generate_dominated(self):
        basic_blocks = self.function.basic_blocks
        dominated = {bb: set() for bb in basic_blocks}

        for bb in basic_blocks:
            for d in bb.dominators:
                dominated[d].add(bb)

        return dominated

    def _find_regions(self):
        basic_blocks = self._function.basic_blocks

        regions = {}

        for bb in reversed(basic_blocks):
            if bb.start == 0:
                continue
            if bb not in self._cycles:
                if next((e for e in bb.outgoing_edges if e.back_edge), None):
                    # a back edge node isn't going to be the root of a region
                    continue

                # bb must be the head of an acyclic region (for the moment)
                possible_region = self.dominated[bb]
                for c in self._cycles:
                    if c in possible_region:
                        possible_region = possible_region - self.dominated[c]

                # remove any sub regions from our list of regions
                nodes = []
                for r in possible_region:
                    if r in regions:
                        sub_region = regions[r]

                        possible_region.remove(r)
                        possible_region.add(self.convert_region_to_seq(sub_region))

                        nodes.append(sub_region)

                        del regions[r]
                    else:
                        nodes.append(r)

                new_region = Region(
                    self,
                    MediumLevelILAstBasicBlockNode(self, bb),
                    nodes=nodes
                )

            else:
                possible_region = self.dominated[bb]

                for r in possible_region:
                    if next((e for e in r.outgoing_edges if e.back_edge), None):
                        possible_region = possible_region - self.dominated[r]

                        # add r back to possible_region since it was in both
                        possible_region.add(r)

                new_region = Region(
                    self,
                    MediumLevelILAstBasicBlockNode(self, bb),
                    acyclic=False,
                    nodes=[
                        MediumLevelILAstBasicBlockNode(self, pr)
                        for pr in possible_region
                    ]
                )

            regions[bb] = new_region

        return regions

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
                if isinstance(n, MediumLevelILBasicBlock) else n
            )

        return new_seq

    def structure_acyclic_region(self, region_header, region):
        ordered_region = sorted(region, key=lambda i: i.start)

        region_node = MediumLevelILAstSeqNode(self, region_header)

        for current_node in ordered_region:
            if current_node == region_header:
                continue
            reaching_condition = self.generate_reaching_condition_MLIL(
                region_header, current_node
            )
            new_cond_node = MediumLevelILAstCondNode(self, reaching_condition)

            if isinstance(current_node, Region):
                new_seq = MediumLevelILAstSeqNode(self, current_node.header.block)
                for n in current_node.nodes:
                    new_seq.append(n)
                new_cond_node.append(new_seq)
            else:
                new_cond_node.append(MediumLevelILAstSeqNode(self, current_node))
            region_node.append(new_cond_node)

        self._regions[region_header] = region_node

    def structure_cyclic_region(self, region_header, region):
        pass

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

            new_region_node.append(node)

            self._regions[header] = new_region_node

    def generate_reaching_condition_MLIL(self, region_header, bb):
        or_exprs = []

        for condition in self.reaching_conditions[(region_header, bb if isinstance(bb, MediumLevelILBasicBlock) else bb.header.block)]:
            and_exprs = []
            for edge in condition:
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
        )

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

            prev_indent = indent

        return output


class MediumLevelILAstNode(object):
    def __init__(self, ast: MediumLevelILAst):
        self._children = deque()
        self._ast = ast

    def prepend(self, child: MediumLevelILAstNode):
        self._children.appendleft(child)

    def append(self, child: MediumLevelILAstNode):
        self._children.append(child)

    @property
    def children(self) -> list:
        return list(self._children)

    @property
    def ast(self) -> MediumLevelILAst:
        return self._ast


class MediumLevelILAstSeqNode(MediumLevelILAstNode):
    def __init__(self, ast: MediumLevelILAst, header: MediumLevelILBasicBlock):
        if not isinstance(header, MediumLevelILBasicBlock):
            raise TypeError(
                f"header should be a MediumLevelILBasicBlock, got {type(header)}"
            )
        super().__init__(ast)
        self._header = header

    @property
    def start(self):
        return self._header.start

    @property
    def header(self):
        return self._header

    def __str__(self):
        return f"<seq: header={self._header}, {len(self.children)} children>"

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False

        return self.header == other.header

    def __hash__(self):
        return hash(self.header)


class MediumLevelILAstCondNode(MediumLevelILAstNode):
    def __init__(self, ast: MediumLevelILAst, condition: MediumLevelILInstruction):
        self._condition = condition
        super().__init__(ast)

    @property
    def condition(self) -> MediumLevelILInstruction:
        return self._condition

    def __repr__(self):
        return f"<cond: {self.condition}, {len(self.children)} children>"

    def __getitem__(self, key):
        if key:
            return self._children[0]
        else:
            return self._children[1]


class MediumLevelILAstLoopNode(MediumLevelILAstNode):
    pass


class MediumLevelILAstSwitchNode(MediumLevelILAstNode):
    pass


class MediumLevelILAstBasicBlockNode(MediumLevelILAstNode):
    def __init__(self, ast: MediumLevelILAst, bb: MediumLevelILBasicBlock):
        super().__init__(ast)
        self._bb = bb

    @property
    def block(self) -> MediumLevelILBasicBlock:
        return self._bb

    @property
    def start(self) -> int:
        return self._bb.start

    def __eq__(self, other):
        if isinstance(other, MediumLevelILBasicBlock):
            return self.block == other

        if not isinstance(other, type(self)):
            return False

        return self.block == other.block

    def __hash__(self):
        return hash(self.block)

    def __repr__(self):
        return f'<bb block={self.block}>'

class Region(object):
    def __init__(
        self,
        ast: MediumLevelILAst,
        header: MediumLevelILAstBasicBlockNode,
        acyclic=True,
        nodes=None,
    ):
        self._acyclic = acyclic
        self._header = header
        self._nodes = [] if nodes is None else nodes
        self._ast = ast

    @property
    def acyclic(self):
        return self._acyclic

    @property
    def header(self):
        return self._header

    @property
    def start(self):
        return self._header.block.start

    @property
    def nodes(self):
        return list(self._nodes)

    def append(self, node):
        if not isinstance(node, MediumLevelILAstNode):
            raise TypeError(f'node should be a MediumLevelILAstNode, got {type(node)}')

        self._nodes.append(node)

    def __iter__(self):
        yield self._header
        for n in self.nodes:
            yield n

    def __eq__(self, other):
        if isinstance(other, MediumLevelILBasicBlock):
            return self._header == other
        if not isinstance(other, type(self)):
            return False
        
        return self._header == other._header

    def __hash__(self):
        return hash(self.header.block)

    def __repr__(self):
        return f'<Region header={self._header} {len(self.nodes)} nodes>'
