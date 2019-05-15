from __future__ import annotations

from collections import deque
from functools import cmp_to_key, reduce
from itertools import product, repeat, chain

from z3 import And, Not, Or, is_true, simplify, Bool, BoolVal, Tactic

from binaryninja import (
    BranchType,
    ILBranchDependence,
    InstructionTextTokenType,
    MediumLevelILBasicBlock,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    PossibleValueSet,
    RegisterValueType,
    Variable,
    VariableSourceType,
    log_debug, log_info
)

from .condition_visitor import ConditionVisitor
from .if_else_visitor import IfVisitor
from .nodes import (
    MediumLevelILAstBasicBlockNode,
    MediumLevelILAstBreakNode,
    MediumLevelILAstCondNode,
    MediumLevelILAstElseNode,
    MediumLevelILAstLoopNode,
    MediumLevelILAstNode,
    MediumLevelILAstSeqNode,
    MediumLevelILAstSwitchNode,
)
from .region import Region

_true_condition = simplify(Bool('a') == Bool('a'))

class MediumLevelILAst(object):
    def __init__(self, function: MediumLevelILFunction):
        self._function = function
        self.view = function.source_function.view
        self._nodes = {}
        self._root = MediumLevelILAstBasicBlockNode(self, function.basic_blocks[0])
        self._regions = {}
        self._reaching_conditions = {}
        self._reaching_constraints = {}

        self.view.session_data["CurrentAST"] = self

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
    def cycles(self) -> set:
        return set(self._cycles)

    @property
    def regions(self):
        return sorted(
            self._regions.items(),
            key=cmp_to_key(
                lambda i, j: 1
                if self.reaching_conditions.get((i[0], j[0])) is None
                else -1
            ),
        )

    @property
    def nodes(self):
        return dict(self._nodes)

    def calculate_reaching_conditions(self):
        reaching_conditions = {}

        for ns, ne in product(reversed(self._function.basic_blocks), repeat=2):
            if ns == ne:
                continue

            log_debug(f"({ns}, {ne})")

            dfs_stack = []
            visited_edges = set()
            visited_nodes = set()
            edges = ns.outgoing_edges

            while edges:
                e = edges.pop()

                log_debug(f"    {e.source} -> {e.target}")

                nt = e.target

                if e.back_edge:
                    visited_edges.add(e)

                elif e not in visited_edges and nt not in visited_nodes:
                    log_debug(f"    adding edge to edges")
                    edges += nt.outgoing_edges
                    visited_edges.add(e)

                    dfs_stack = dfs_stack + [e]

                    if nt == ne and dfs_stack:
                        log_debug("    adding finished slice")
                        reaching_conditions[(ns, ne)] = reaching_conditions.get(
                            (ns, ne), list()
                        )
                        reaching_conditions[(ns, ne)].append(dfs_stack)

                elif (nt, ne) in reaching_conditions and e not in dfs_stack:
                    log_debug("    hit simple path, adding finished slice")
                    reaching_conditions[(ns, ne)] = reaching_conditions.get(
                        (ns, ne), list()
                    )
                    for rc in reaching_conditions[(nt, ne)]:
                        reaching_conditions[(ns, ne)].append(dfs_stack + rc)
                    visited_edges.add(e)

                while len(dfs_stack) and all(
                    descendant in visited_edges
                    for descendant in dfs_stack[-1].target.outgoing_edges
                ):
                    log_debug(f"    popping {dfs_stack[-1]}")
                    dfs_stack = dfs_stack[:-1]

            if (ns, ne) in reaching_conditions:
                log_debug(f"finished slices: {reaching_conditions[(ns, ne)]}")
                log_debug("-----------")

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

        # step 2a: generate the reaching conditions
        self.calculate_reaching_conditions()

        # step 2b: generate the z3 constraints of these conditions
        self.generate_reaching_constraints()

        # step 3: find all the regions
        self._regions = self._find_regions()

        # step 6: merge if/else statements
        self._merge_if_else()

        # # step 7: refine loops
        self._refine_loops()

    def _find_regions(self):
        basic_blocks = self._function.basic_blocks

        regions = self._regions

        bb_queue = sorted(MediumLevelILAstBasicBlockNode(self, b) for b in basic_blocks)

        log_debug(f"{bb_queue}")

        while bb_queue:
            bb = bb_queue.pop().block

            if bb not in self._cycles:
                if next((e for e in bb.outgoing_edges if e.back_edge), None):
                    # a back edge node isn't going to be the root of a region
                    continue

                current_node = None

                log_debug(f"creating region for {bb.start}")

                if bb[-1].operation == MediumLevelILOperation.MLIL_JUMP_TO:
                    switch = bb[-1].dest.possible_values.mapping
                    cases = {
                        next(
                                b
                                for b in self._function.basic_blocks
                                if b.source_block.start == t
                        ): v
                        for v, t in switch.items()
                    }

                    log_info(f"{cases}")

                    # TODO: figure out fall through cases
                    switch_condition = self._find_switch_condition(
                        bb[-1].dest, switch.keys()
                    )
                    current_node = MediumLevelILAstSwitchNode(
                        self, switch_condition, bb[-1].instr_index, bb[-1].address
                    )
                else:
                    current_node = MediumLevelILAstSeqNode(self)

                # bb must be the head of an acyclic region (for the moment)
                possible_region = {
                    MediumLevelILAstBasicBlockNode(self, pr)
                    for pr in self._function.basic_blocks
                    if (bb, pr) in self.reaching_conditions
                }

                # TODO: double check this to make sure it's actually removing regions
                # like it's supposed to
                # remove any sub regions from our list of regions
                nodes = [MediumLevelILAstBasicBlockNode(self, bb)]

                regions_in_this_region = {r for r in possible_region if r.block in self._regions}

                log_debug(f"regions_in_this_region: {regions_in_this_region}")

                possible_region = possible_region - regions_in_this_region

                log_debug(f"possible_region: {possible_region}")

                for r in regions_in_this_region:
 
                    r_has_multiple_incoming = len(r.block.incoming_edges) > 1

                    log_debug(f"{r} r_has_multiple_constraints: {r_has_multiple_incoming}")
                    log_debug(f"{r} bb in r.block.dominators: {bb in r.block.dominators}")

                    sub_region = regions[r.block]

                    if not r_has_multiple_incoming or bb in r.block.dominators:
                        del regions[r.block]

                        if sub_region.type != "loop":
                            reaching_constraint = self._reaching_constraints.get(
                                (bb, r.block)
                            )

                            if is_true(reaching_constraint):
                                reaching_constraint = None

                            # This is now a condition if:
                            # a) a reaching constraint exists and
                            # b) at least one other region can't reach it?
                            # TODO: make sure b is actually correct
                            if reaching_constraint is not None:
                                new_node = MediumLevelILAstCondNode(
                                    self,
                                    reaching_constraint,
                                    r.block.incoming_edges[0].source[-1],
                                    sub_region
                                )

                            # otherwise it's just a sequence still. In fact, we can probably
                            # just bring these into the original region
                            else:
                                new_node = sub_region
                        else:
                            # loops are just loops still
                            new_node = sub_region

                        if new_node is not None:
                            if current_node.type != "switch":
                                nodes.append(new_node)
                            else:
                                if r.block not in cases:
                                    regions[r.block] = new_node
                                else:
                                    current_node[cases[r.block]] = new_node


                    if sub_region.type == 'seq':
                        to_remove = sub_region.nodes
                    elif sub_region.type == 'loop':
                        to_remove = sub_region.body.nodes
                    else:
                        raise TypeError(
                            "I don't know why I got a "
                            f"{type(sub_region)} for a sub_region"
                        )

                    while to_remove:
                        sub = to_remove.pop()

                        if sub.type == 'seq':
                            to_remove += sub.nodes
                        
                        if sub.type == 'loop':
                            to_remove += sub.body.nodes

                        if sub.type == 'cond':
                            to_remove.append(sub[True])

                        if sub.type == 'block':
                            if sub in possible_region:
                                log_debug(f"removing {sub} from possible_region")
                                possible_region.remove(sub)

                for r in possible_region:
                    log_debug(f"Adding {r} to {bb.start}'s region")
                    nodes.append(r)
                    if r.block in bb_queue:
                        bb_queue.remove(r.block)

                if current_node.type == 'switch':
                    nodes.append(current_node)
                    current_node = MediumLevelILAstSeqNode(self, nodes)

                current_node._nodes = sorted(nodes)

                if current_node.type == 'seq':
                    current_node.flatten_sequence()

                new_region = current_node
            else:
                # Section C.1 in whitepaper: Initial Loop Nodes and Successors
                latching_nodes = {
                    e.source
                    for e in bb.incoming_edges
                    if e.back_edge
                }

                loop_slice = {
                    n
                    for l in latching_nodes
                    if bb != l
                    for s in self.reaching_conditions[(bb, l)]
                    for n in s
                }
                loop_nodes = set()
                loop_nodes.add(bb)
                for e in loop_slice:
                    loop_nodes.add(e.target)
                    loop_nodes.add(e.source)

                successor_nodes = {
                    e.target
                    for n in loop_nodes
                    for e in n.outgoing_edges
                    if e.target not in loop_nodes
                }

                log_debug(f"original successor_nodes: {successor_nodes}")

                # Section C.2 in whitepaper: Successor Refinement and Loop Membership
                # TODO: modify this to ensure there is a final successor if one exists,
                # specifically, we want any return statement to be a successor....maybe?
                while len(successor_nodes) > 1:
                    new = set()
                    old = set()
                    for successor in sorted(list(successor_nodes), key=lambda i: i.start):
                        # add a successor to the loop if both hold true:
                        # a) the successor is dominated by the start of the loop
                        # b) the successor's immediate predecessors are all in
                        #    the loop.
                        if (
                            bb in successor.dominators
                            and all(
                                incoming.source in loop_nodes
                                for incoming in successor.incoming_edges
                            )
                        ):
                            loop_nodes.add(successor)
                            old.add(successor)
                            new = new & {e.target for e in successor.outgoing_edges}

                    if old:
                        successor_nodes = successor_nodes - old

                    if new:
                        successor_nodes = set(*successor_nodes, *new)
                    else:
                        break

                log_debug(f"final successor_nodes: {successor_nodes}")

                # remove any regions that are in the loop nodes
                nodes = set()
                for r in loop_nodes:
                    if r in regions:
                        sub_region = regions[r]

                        reaching_constraint = self._reaching_constraints.get((bb, r))

                        if is_true(reaching_constraint):
                            reaching_constraint = None

                        if reaching_constraint is not None:
                            new_node = MediumLevelILAstCondNode(
                                self,
                                reaching_constraint,
                                r[0],
                                MediumLevelILAstSeqNode(
                                    self,
                                    [MediumLevelILAstBasicBlockNode(self, r)]
                                )
                            )
                        else:
                            new_node = sub_region

                        del regions[r]
                    else:
                        if bb == r:
                            continue

                        reaching_constraint = self._reaching_constraints.get((bb, r))
                        if is_true(reaching_constraint):
                            reaching_constraint = None

                        if reaching_constraint is not None:
                            new_node = MediumLevelILAstCondNode(
                                self,
                                reaching_constraint,
                                bb[-1],
                                MediumLevelILAstSeqNode(
                                    self, 
                                    [MediumLevelILAstBasicBlockNode(self, r)]
                                )
                            )
                        else:
                            new_node = MediumLevelILAstSeqNode(
                                self, 
                                [MediumLevelILAstBasicBlockNode(self, r)]
                            )

                    nodes.add(new_node)

                successor_cond = None
                successor_node = None
                for successor in successor_nodes:
                    reaching_constraint = self._reaching_constraints.get(
                        (bb, successor)
                    )
                    break_node = MediumLevelILAstCondNode(
                        self,
                        reaching_constraint,
                        successor[0],
                        MediumLevelILAstSeqNode(
                            self,
                            [MediumLevelILAstBreakNode(
                                self,
                                successor.start,
                                successor.source_block.start
                            )]
                        )
                    )
                    nodes.add(break_node)

                    if successor in self._regions:
                        successor_node = self._regions[successor]
                        del self._regions[successor]
                    else:
                        successor_node = MediumLevelILAstSeqNode(
                            self, [MediumLevelILAstBasicBlockNode(self, successor)]
                        )

                    # convert the successor nodes to a chain of
                    # condition nodes for each successor
                    if len(successor_nodes) > 1:
                        successor_cond = MediumLevelILAstCondNode(
                            self,
                            self.reaching_constraints.get((bb, successor)),
                            successor.source_block[0],
                            successor_node,
                            successor_cond
                        )

                if successor_cond is not None:
                    successor_node = successor_cond

                body = MediumLevelILAstSeqNode(
                    self,
                    sorted(list(nodes))
                )

                loop_node = MediumLevelILAstLoopNode(
                    self,
                    body
                )

                if successor_node is not None:
                    region_nodes = [
                        loop_node,
                        successor_node
                    ]
                    new_region = MediumLevelILAstSeqNode(
                        self,
                        region_nodes
                    )
                else:
                    new_region = loop_node

            log_debug(f"adding {new_region} to regions")
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
        result = None
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
                RegisterValueType.InSetOfValues,
            ):
                continue

            if pv.type != RegisterValueType.InSetOfValues:
                if not check_ranges(pv.ranges, cases):
                    continue
                else:
                    result = current_operand
                    break

            # If it's InSetOfValues, check to make sure
            # all of the values are in pv.values
            if all(v in cases for v in pv.values) and len(cases) == len(pv.values):
                result = current_operand
                break
            else:
                continue

        return ConditionVisitor().simplify(result)

    def _merge_if_else(self):
        nodes_to_remove = True

        while nodes_to_remove:
            root = self.regions[0][1]
            nodes_to_remove = self.find_if_else_for_node(root, root.nodes)

            for n in nodes_to_remove:
                root._nodes.remove(n) if n in root._nodes else None

        nodes_to_check = root.nodes
        nodes_to_remove = []

        while nodes_to_check:
            if not nodes_to_remove:
                node = nodes_to_check.pop()

            if node is None:
                continue

            nodes_to_remove = []

            if node.type == 'seq':
                nodes_to_remove = self.find_if_else_for_node(node, node.nodes)
                _nodes = node._nodes

            elif node.type == 'loop':
                nodes_to_remove = self.find_if_else_for_node(node.body, node.body.nodes)
                _nodes = node.body._nodes

            for n in nodes_to_remove:
                _nodes.remove(n) if n in _nodes else None

            if node.type == 'seq':
                nodes_to_check += node.nodes
            elif node.type == 'loop':
                nodes_to_check += node.body.nodes
            elif node.type == 'cond':
                nodes_to_check.append(node[True]) if node[True] else None
                nodes_to_check.append(node[False]) if node[False] else None

    def find_if_else_for_node(self, parent: MediumLevelILAstNode, nodes: list):
        log_debug(f"find_if_else_for_node")
        nodes_to_check = list(nodes)

        nodes_to_remove = []

        while nodes_to_check:
            ni = nodes_to_check.pop()

            if ni.type != 'cond':
                continue

            log_debug(f"checking {ni}")

            for nj in nodes_to_check:
                if nj.type != 'cond':
                    continue

                if ni == nj:
                    continue

                log_debug(f"checking against {nj}")

                if self.try_make_simple_if_else(
                        ni, nj, nodes_to_check, nodes_to_remove):
                    break

                if self.try_make_complex_if_else(
                        parent, ni, nj, nodes_to_check, nodes_to_remove):
                    break

        return nodes_to_remove

    def try_make_simple_if_else(
            self, node1, node2, nodes_to_check, nodes_to_remove):
        cond1 = node1.condition
        cond2 = node2.condition

        if is_true(simplify(cond1 == Not(cond2))):
            log_debug(f"found a simple if/else match")
            if cond1.decl().name() == "not":
                node2[False] = node1[True]
                nodes_to_check.remove(node2)
                nodes_to_remove.append(node1)
            else:
                node1[False] = node2[True]
                nodes_to_remove.append(node2)
            
            return True

        return False

    def try_make_complex_if_else(
            self, parent, node1, node2, nodes_to_check, nodes_to_remove):
        log_debug("try_make_complex_if_else")
        cond1 = node1.condition
        cond2 = node2.condition

        log_debug(f"{cond1} vs {cond2}")

        to_visit = [(cond1, BoolVal(True))]

        while to_visit:
            current_cond, right_side = to_visit.pop()
            log_debug(f"current: {current_cond} right: {right_side}")

            # If the top level operation is not an And, we don't need
            # to go any further.
            if current_cond.decl().name() != 'and':
                log_debug(f"current_cond is {current_cond}")
                return False

            # try 0 and R first
            c = current_cond.arg(0)
            R = simplify(And(current_cond.arg(1), right_side))
            log_debug(f"c: {c} R: {R} cond2: {cond2}")
            if not Tactic('ctx-solver-simplify')(And(Not(c), R) == cond2)[0]:
                log_debug(f"Found complex if/else (0-1)! {R} and {c} | {cond2}")
                break

            # try again, but the other way
            c = current_cond.arg(1)
            R = simplify(And(current_cond.arg(0), right_side))
            log_debug(f"c: {c} R: {R} cond2: {cond2}")
            if not Tactic('ctx-solver-simplify')(And(Not(c), R) == cond2)[0]:
                log_debug(f"Found complex if/else (1-0)! {R} and {c} | {cond2}")
                break

            to_visit = [
                (current_cond.arg(0), current_cond.arg(1)),
                (current_cond.arg(1), current_cond.arg(0))
            ]

        # if we get here, we have a complex if/else
        new_if_else_node = MediumLevelILAstCondNode(
            self,
            c,
            node1._condition_il,
            node1[True],
            node2[True]
        )

        log_debug(f"R is currently {R}")

        new_cond_node = MediumLevelILAstCondNode(
            self,
            simplify(R),
            node1._condition_il,
            MediumLevelILAstSeqNode(
                self,
                [new_if_else_node]
            )
        )

        log_debug(f"{new_cond_node}")

        node1_idx = parent.nodes.index(node1)

        parent._nodes[node1_idx] = new_cond_node
        nodes_to_remove.append(node2)
        nodes_to_check.remove(node2)

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
                            simplify(Not(visitor.simplify(edge.source[-1].condition)))
                        )

                if and_exprs:
                    or_exprs.append(reduce(And, and_exprs))

            if or_exprs:
                self._reaching_constraints[(start, end)] = simplify(
                    reduce(Or, or_exprs)
                )

    def _refine_loops(self):
        to_visit = [r for r in self._regions.values()]

        visited = set()

        while to_visit:
            node = to_visit.pop()

            if node.type == 'block':
                continue

            if node in visited:
                log_debug(f"wtf, why have I visited {node} already")
                break

            if node.type == 'seq':
                to_visit += [n for n in node.nodes if n is not None]
            elif node.type == 'cond':
                to_visit += node[True].nodes if node[True] else []
                to_visit += node[False].nodes if node[False] else []

            if node.type == 'loop':
                log_debug(f"{node}")

                while_condition = self._check_while(node)
                if while_condition is not None:
                    log_debug(f"{node} is a while loop")
                    node.loop_type = "while"
                    node.condition = reduce(
                        And,
                        Tactic('ctx-solver-simplify')(Not(while_condition))[0]
                    )
                    
                    break_cond = node.body.nodes[0]

                    if break_cond[False] is not None:
                        node.body._nodes[0] = break_cond[False]

                    # Flatten condition nodes that have the same condition
                    # as the loop condition
                    for idx, child in enumerate(node.body.nodes):
                        if (
                            isinstance(child, MediumLevelILAstCondNode)
                            and is_true(simplify(child.condition == node.condition))
                            and child[False] is None
                        ):
                            node.body._nodes[idx] = child[True]
                    continue

                dowhile_condition = self._check_do_while(node)
                if dowhile_condition is not None:
                    log_debug(f"{node} is a do while loop")
                    node.loop_type = "dowhile"
                    node.condition = reduce(
                        And,
                        Tactic('ctx-solver-simplify')(Not(dowhile_condition))[0]
                    )
                    
                    break_cond = node.body.nodes[-1]

                    if break_cond[False] is not None:
                        node.body._nodes[-1] = break_cond[False]
                    else:
                        node.body._nodes.pop()

                    # Flatten condition nodes that have the same condition
                    # as the loop condition
                    for idx, child in enumerate(node.body.nodes):
                        if (
                            isinstance(child, MediumLevelILAstCondNode)
                            and is_true(simplify(child.condition == node.condition))
                            and child[False] is None
                        ):
                            node.body._nodes[idx] = child[True]

    def _check_while(self, loop_node: MediumLevelILAstLoopNode):
        log_debug("_check_while")
        if loop_node.loop_type != "endless":
            log_debug(loop_node.loop_type)
            return None

        if loop_node.body.nodes[0].type != 'cond':
            log_debug(f"{loop_node.body.nodes[0].type}")
            return None

        log_debug(f"{loop_node.body.nodes[0][True].nodes}")

        if loop_node.body.nodes[0][True].nodes[0].type == "break":
            log_debug(f"The loop body is {loop_node.body.nodes}")
            return loop_node.body.nodes[0].condition

        log_debug(f"{loop_node.body.nodes[0][True].nodes}")

        return None

    def _check_do_while(self, loop_node: MediumLevelILAstLoopNode) -> bool:
        log_debug("_check_do_while")
        log_debug(f"{loop_node.body.nodes}")
        if loop_node.loop_type != "endless":
            log_debug(loop_node.loop_type)
            return None

        if loop_node.body.nodes[-1].type != 'cond':
            log_debug(f"{loop_node.body.nodes[-1].type}")
            return None

        log_debug(f"{loop_node.body.nodes[-1][True].nodes}")

        if loop_node.body.nodes[-1][True].nodes[0].type == "break":
            return loop_node.body.nodes[-1].condition

        log_debug(f"{loop_node.body.nodes[-1][True].nodes}")

        return None

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
                to_visit += zip(
                    reversed(sorted(node.cases.items(), key=lambda i: i[0])),
                    repeat(indent + 4),
                )

            elif isinstance(node, tuple):
                output += f'{" "*indent}case {node[0]}:\n'
                to_visit += [(node[1], indent + 4)]

            prev_indent = indent

        return output
