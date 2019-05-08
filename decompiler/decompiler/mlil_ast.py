from __future__ import annotations

from collections import deque
from functools import cmp_to_key, reduce
from itertools import product, repeat, chain

from z3 import And, Not, Or, is_true, simplify, Bool

from binaryninja import (BranchType, ILBranchDependence,
                         InstructionTextTokenType, MediumLevelILBasicBlock,
                         MediumLevelILFunction, MediumLevelILInstruction,
                         MediumLevelILOperation, PossibleValueSet,
                         RegisterValueType, Variable, VariableSourceType,
                         log_info)

from .condition_visitor import ConditionVisitor
from .if_else_visitor import IfVisitor
from .nodes import (MediumLevelILAstBasicBlockNode, MediumLevelILAstBreakNode,
                    MediumLevelILAstCondNode, MediumLevelILAstElseNode,
                    MediumLevelILAstLoopNode, MediumLevelILAstNode,
                    MediumLevelILAstSeqNode, MediumLevelILAstSwitchNode)
from .region import Region


class MediumLevelILAst(object):
    def __init__(self, function: MediumLevelILFunction):
        self._function = function
        self.view = function.source_function.view
        self._nodes = {}
        self._root = MediumLevelILAstBasicBlockNode(self, function.basic_blocks[0])
        self._dominated = None
        self._regions = {}
        self._reaching_conditions = {}
        self._reaching_constraints = {}

        self.view.session_data['CurrentAST'] = self

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
        return sorted(
            self._regions.items(), 
            key=cmp_to_key(
                lambda i, j: 1 if self.reaching_conditions.get(
                    (i[0], j[0])
                ) is None else -1
            )
        )

    @property
    def nodes(self):
        return dict(self._nodes)

    def calculate_reaching_conditions(self):
        reaching_conditions = {}

        for ns, ne in product(reversed(self._function.basic_blocks), repeat=2):
            if ns == ne:
                continue

            log_info(f"({ns}, {ne})")

            dfs_stack = []
            visited_edges = set()
            visited_nodes = set()
            edges = ns.outgoing_edges

            while edges:
                e = edges.pop()

                # if e.back_edge:
                #     continue

                log_info(f"    {e.source} -> {e.target}")

                nt = e.target

                if e.back_edge:
                    visited_edges.add(e)


                elif e not in visited_edges and nt not in visited_nodes:
                    log_info(f"    adding edge to edges")
                    edges += nt.outgoing_edges
                    visited_edges.add(e)

                    dfs_stack = dfs_stack + [e]

                    if nt == ne and dfs_stack:
                        log_info("    adding finished slice")
                        reaching_conditions[(ns, ne)] = reaching_conditions.get(
                            (ns, ne), list()
                        )
                        reaching_conditions[(ns, ne)].append(dfs_stack)

                elif (nt, ne) in reaching_conditions and e not in dfs_stack:
                    log_info("    hit simple path, adding finished slice")
                    reaching_conditions[(ns, ne)] = reaching_conditions.get(
                        (ns, ne), list()
                    )
                    reaching_conditions[(ns, ne)].append(dfs_stack)
                    visited_edges.add(e)

                while len(dfs_stack) and all(
                    descendant in visited_edges
                    for descendant in dfs_stack[-1].target.outgoing_edges
                ):
                    log_info(f"    popping {dfs_stack[-1]}")
                    dfs_stack = dfs_stack[:-1]
            
            if (ns, ne) in reaching_conditions:
                log_info(f"finished slices: {reaching_conditions[(ns, ne)]}")
                log_info("-----------")

        self._reaching_conditions = reaching_conditions


    # this is a modified version of Algorithm 1 in "no more gotos"
    @property
    def reaching_conditions(self):
        return dict(self._reaching_conditions)

    @property
    def reaching_constraints(self):
        return dict(self._reaching_constraints)

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

        # step 2a: generate the reaching conditions
        self.calculate_reaching_conditions()

        # step 2b: generate the z3 constraints of these conditions
        self.generate_reaching_constraints()

        # step 3: find all the regions
        self._regions = self._find_regions()

        # step 4: iterate through the regions and structure them
        self._structure_regions()

        # step 5: order the regions
        self.order_regions()

        # step 6: merge if/else statements
        self._merge_if_else()

        # step 7: refine loops
        self._refine_loops()

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
                possible_region = sorted(
                    list(self.dominated[bb]),
                    key=cmp_to_key(
                        lambda i, j: 1 if self.reaching_conditions.get(
                            (i, j)
                        ) is None else -1
                    ),
                    reverse=True
                )

                # TODO: double check this to make sure it's actually removing regions
                # like it's supposed to
                # remove any sub regions from our list of regions
                nodes = []
                while possible_region:
                    r = possible_region.pop()

                    if r == bb:
                        continue

                    if r in regions:
                        sub_region = regions[r]

                        if sub_region.acyclic:
                            # reaching_condition = self.generate_reaching_condition_MLIL(bb, r)
                            reaching_constraint = self._reaching_constraints.get((bb, r))

                            if (
                                reaching_constraint is not None and 
                                any(
                                    self._reaching_constraints.get((x, r)) is None
                                    for x in regions if x != r
                                )
                            ):
                                new_node = self.convert_region_to_cond(bb, sub_region)
                            else:
                                new_node = self.convert_region_to_seq(sub_region)
                        else:
                            new_node = self.convert_region_to_loop(sub_region)
                            

                        if new_node is not None and (not is_switch or r not in cases):
                            nodes.append(new_node)
                        elif new_node is not None:
                            switch_node[cases[r]] = new_node

                        to_remove = list(sub_region)
                        while to_remove:
                            sub = to_remove.pop()
                            if isinstance(sub, MediumLevelILAstNode):
                                to_remove += sub.children
                                if isinstance(sub, MediumLevelILAstSeqNode):
                                    possible_region.remove(sub.header) if sub.header in possible_region else None
                                if isinstance(sub, MediumLevelILAstLoopNode):
                                    possible_region.remove(sub.loop) if sub.loop in possible_region else None
                                if isinstance(sub, MediumLevelILAstCondNode):
                                    possible_region.remove(sub[True]) if sub[True] in possible_region else None
                                    possible_region.remove(sub[False]) if sub[False] in possible_region else None
                            elif isinstance(sub, MediumLevelILAstBasicBlockNode):
                                possible_region.remove(sub.block)

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

                # Section C.1 in whitepaper: Initial Loop Nodes and Successors
                latching_nodes = {e.source for e in bb.incoming_edges if e.back_edge}

                loop_slice = {n for l in latching_nodes if bb != l for s in self.reaching_conditions[(bb, l)] for n in s}
                loop_nodes = set()
                loop_nodes.add(bb)
                for e in loop_slice:
                    loop_nodes.add(e.target)
                    loop_nodes.add(e.source)

                successor_nodes = {e.target for n in loop_nodes for e in n.outgoing_edges if e.target not in loop_nodes}

                print(f"original successor_nodes: {successor_nodes}")

                # Section C.2 in whitepaper: Successor Refinement and Loop Membership
                # TODO: modify this to ensure there is a final successor if one exists,
                # specifically, we want any return statement to be a successor....maybe?
                while len(successor_nodes) > 1:
                    new = set()
                    old = set()
                    for successor in successor_nodes:
                        if bb in successor.dominators and successor.immediate_dominator in loop_nodes:
                            loop_nodes.add(successor)
                            old.add(successor)
                            new = new & {e.target for e in successor.outgoing_edges}

                    if old:
                        successor_nodes = successor_nodes - old

                    if new:
                        successor_nodes = set(*successor_nodes, *new)
                    else:
                        break

                print(f"final successor_nodes: {successor_nodes}")

                # remove any regions that are in the loop nodes
                nodes = []
                for r in loop_nodes:
                    if r in regions:
                        sub_region = regions[r]

                        if sub_region.acyclic:
                            if (self._reaching_constraints.get((bb, r)) is not None):
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
                        if bb == r:
                            continue

                        reaching_constraint = self._reaching_constraints.get((bb, r))
                        if reaching_constraint is not None:
                            new_node = MediumLevelILAstCondNode(self, reaching_constraint, bb[-1].address)
                            new_node[True] = MediumLevelILAstSeqNode(self, r)
                        else:
                            new_node = MediumLevelILAstSeqNode(self, r)

                        nodes.append(new_node)

                for successor in successor_nodes:
                    reaching_constraint = self._reaching_constraints.get((bb, successor))
                    break_node = MediumLevelILAstCondNode(self, reaching_constraint, bb[-1].address)
                    break_node[True] = MediumLevelILAstSeqNode(self, MediumLevelILAstBreakNode(self, successor))
                    nodes.append(break_node)

                new_region = Region(
                    self,
                    MediumLevelILAstBasicBlockNode(self, bb),
                    acyclic=False,
                    nodes=nodes,
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
        for header, region in sorted(
            self._regions.items(),
            key=cmp_to_key(
                lambda i, j: 1 if self.reaching_conditions.get(
                    (i[0], j[0])
                ) is None else -1
            )
        ):
            if region.acyclic:
                self.structure_acyclic_region(header, region)
            else:
                self.structure_cyclic_region(header, region)

    def convert_region_to_seq(self, sub_region):
        new_seq = MediumLevelILAstSeqNode(self, sub_region.header.block)

        for n in sub_region.nodes:
            if isinstance(n, MediumLevelILAstSeqNode):
                new_seq.append(n.header)
                new_seq._children += [
                    MediumLevelILAstBasicBlockNode(self, bb)
                    if isinstance(bb, MediumLevelILBasicBlock)
                    else bb
                    for bb in n.children
                ]
            elif isinstance(n, MediumLevelILBasicBlock):
                new_seq.append(MediumLevelILAstBasicBlockNode(self, n))
            else:
                new_seq.append(n)

        return new_seq

    def convert_region_to_cond(self, bb, sub_region):
        reaching_constraint = self._reaching_constraints.get((bb, sub_region.header.block))

        new_cond = MediumLevelILAstCondNode(self, reaching_constraint, bb[-1].address)
        
        new_seq = self.convert_region_to_seq(sub_region)

        new_cond[True] = new_seq
            
        return new_cond

    def convert_region_to_loop(self, sub_region: Region):

        loop_condition = simplify(Bool('a') == Bool('a'))
        
        new_loop = MediumLevelILAstLoopNode(self, sub_region.header.block, loop_condition)
        new_loop._children = sub_region.nodes

        return new_loop

    def structure_acyclic_region(self, region_header, region):
        return Region(
            self,
            MediumLevelILAstBasicBlockNode(self, region_header),
            nodes=[
                n
                for n in sorted(
                    region.nodes,
                    key=cmp_to_key(
                        lambda i, j: 1 if self.reaching_conditions.get(
                            (i, j)
                        ) is None else -1
                    )
                )
            ]
        )

    def structure_cyclic_region(self, region_header, region):
        return Region(
            self,
            MediumLevelILAstBasicBlockNode(self, region_header),
            nodes=[
                n
                for n in sorted(
                    region.nodes,
                    key=cmp_to_key(
                        lambda i, j: 1 if self.reaching_conditions.get(
                            (i, j)
                        ) is None or i.start > j.start else -1
                    )
                )
            ],
            acyclic=False
        )

    def _merge_if_else(self):
        nodes_to_remove = self.find_if_else_for_node(self.root, self._regions.values())

        for region in list(self._regions.keys()):
            if self._regions[region] in nodes_to_remove:
                del self._regions[region]

        for region in self._regions.values():
            if isinstance(region, MediumLevelILAstSeqNode):
                nodes_to_remove = self.find_if_else_for_node(region.header, region.children)

            for n in nodes_to_remove:
                region._children.remove(n) if n in region._children else None

            nodes_to_check = region.children

            while nodes_to_check:
                node = nodes_to_check.pop()

                if node is None:
                    continue

                nodes_to_remove = []

                if isinstance(node, MediumLevelILAstSeqNode):
                    nodes_to_remove = self.find_if_else_for_node(node.header, node._children)

                if isinstance(node, MediumLevelILAstLoopNode):
                    nodes_to_remove = self.find_if_else_for_node(node.loop, node._children)


                for n in nodes_to_remove:
                    node._children.remove(n)

                if isinstance(node, MediumLevelILAstNode):
                    nodes_to_check += node.children

    def find_if_else_for_node(self, header: MediumLevelILBasicBlock, nodes: list):
        nodes_to_check = list(nodes)

        nodes_to_remove = []

        while nodes_to_check:
            ni = nodes_to_check.pop()

            if not isinstance(ni, MediumLevelILAstCondNode):
                continue

            for nj in nodes_to_check:
                if not isinstance(nj, MediumLevelILAstCondNode):
                    continue

                if ni.start == nj.start:
                    continue

                cni = ni.condition
                cnj = nj.condition

                if is_true(simplify(cni == Not(cnj))):
                    if cni.decl().name() == 'not':
                        self._make_if_else(nj, ni)
                        nodes_to_check.remove(nj)
                        nodes_to_remove.append(ni)
                    else:
                        self._make_if_else(ni, nj)
                        nodes_to_check.remove(nj)
                        nodes_to_remove.append(nj)
                    break

        return nodes_to_remove

    def _make_if_else(self, ni: MediumLevelILAstCondNode, nj: MediumLevelILAstCondNode):
        ni[False] = MediumLevelILAstElseNode(self, nj.condition, nj[True], ni.address)

    def order_regions(self):
        for header, node in sorted(
            list(self._regions.items()),
            key=cmp_to_key(
                lambda i, j: 1 if self.reaching_conditions.get(
                    (i[0], j[0])
                ) is None else -1
            )
        ):
            reaching_constraint = self._reaching_constraints.get(
                (self._function.basic_blocks[0], header)
            )

            if is_true(reaching_constraint):
                reaching_constraint = None
            elif not self._function[node.start].branch_dependence:
                reaching_constraint = None

            if node.acyclic:
                node = self.convert_region_to_seq(node)
            else:
                node = self.convert_region_to_loop(node)

            if reaching_constraint is not None:
                new_region_node = MediumLevelILAstCondNode(
                    self,
                    reaching_constraint,
                    self._function.basic_blocks[0][-1].address
                )
                new_region_node[True] = node
            else:
                new_region_node = node

            self._regions[header] = new_region_node

    def generate_reaching_constraints(self):
        visitor = ConditionVisitor()

        for (start, end), reaching_condition in self.reaching_conditions.items():
            or_exprs = []

            for condition in reaching_condition:
                and_exprs = []

                for edge in condition:
                    if edge.type == BranchType.UnconditionalBranch:
                        continue

                    if edge.type == BranchType.TrueBranch:
                        and_exprs.append(visitor.simplify(edge.source[-1].condition))

                    elif edge.type == BranchType.FalseBranch:
                        and_exprs.append(
                            simplify(
                                Not(
                                    visitor.simplify(edge.source[-1].condition)
                                )
                            )
                        )

                if and_exprs:
                    or_exprs.append(reduce(And, and_exprs))

            if or_exprs:
                self._reaching_constraints[(start, end)] = simplify(reduce(Or, or_exprs))

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
                if isinstance(node, MediumLevelILAstElseNode):
                    output += f'{" "*indent}else:\n'
                    indent += 4

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
                to_visit.append((node[False], indent))
                to_visit.append((node[True], indent + 4))

            elif isinstance(node, MediumLevelILAstSwitchNode):
                output += f'{" "*indent}switch({node.switch}):\n'
                to_visit += zip(reversed(sorted(node.cases.items(), key=lambda i: i[0])), repeat(indent + 4))

            elif isinstance(node, tuple):
                output += f'{" "*indent}case {node[0]}:\n'
                to_visit += [(node[1], indent + 4)]

            prev_indent = indent

        return output

    def _refine_loops(self):
        to_visit = [r for r in self._regions.values()]

        visited = set()

        while to_visit:
            node = to_visit.pop()

            if isinstance(node, MediumLevelILBasicBlock):
                continue

            if node in visited:
                print(f"wtf, why have I visited {node} already")
                break

            to_visit += [c for c in node.children if c is not None]

            if isinstance(node, MediumLevelILAstLoopNode):
                print(f"{node}")

                while_condition = self._check_while(node)
                if while_condition is not None:
                    print(f"{node} is a while loop")
                    node.type = 'while'
                    node.condition = simplify(Not(while_condition))
                    node._children.pop(0)

                    # Flatten condition nodes that have the same condition
                    # as the loop condition
                    for idx, child in enumerate(node.children):
                        if (isinstance(child, MediumLevelILAstCondNode) and
                                is_true(simplify(child.condition == node.condition)) and
                                child[False] is None):
                            node._children[idx] = child[True]

                elif self._check_do_while(node):
                    pass

    def _check_while(self, loop_node: MediumLevelILAstLoopNode):
        if loop_node.type != 'endless':
            return None

        if not isinstance(loop_node.children[0], MediumLevelILAstCondNode):
            return None

        print(f"{loop_node.children[0][True].header}")

        if isinstance(loop_node.children[0][True].header, MediumLevelILAstBreakNode):
            return loop_node.children[0].condition

        return None

    
    def _check_do_while(self, loop_node: MediumLevelILAstLoopNode) -> bool:
        pass