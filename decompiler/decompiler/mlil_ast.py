from __future__ import annotations

from functools import cmp_to_key, reduce
from itertools import product, repeat
from typing import List

from z3 import And, BoolVal, Not, Or, Tactic, is_true, simplify, is_false

from binaryninja import (
    BranchType,
    InstructionTextTokenType,
    MediumLevelILBasicBlock,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    PossibleValueSet,
    RegisterValueType,
    log_debug,
    log_info,
    ReportCollection,
    show_report_collection
)

from .condition_visitor import ConditionVisitor
from .nodes import (
    MediumLevelILAstBasicBlockNode,
    MediumLevelILAstBreakNode,
    MediumLevelILAstCaseNode,
    MediumLevelILAstCondNode,
    MediumLevelILAstElseNode,
    MediumLevelILAstLoopNode,
    MediumLevelILAstNode,
    MediumLevelILAstSeqNode,
    MediumLevelILAstSwitchNode,
)
from .debug import generate_graph


def region_sort(nodes):
    log_debug("region_sort")
    log_debug(f"initial: {nodes}")
    sorted_region = {}
    sorted_region_reverse = {}
    for i in range(len(nodes)):
        for j in range(i, len(nodes)):
            if i == j:
                sorted_region[i] = sorted_region.get(i, list())
                sorted_region_reverse[i] = sorted_region_reverse.get(i, list())
                continue
            if nodes[i] < nodes[j]:
                if nodes[j] > nodes[i]:
                    sorted_region[i] = sorted_region.get(i, list())
                    sorted_region[i].append(j)
                    sorted_region_reverse[j] = sorted_region_reverse.get(j, list())
                    sorted_region_reverse[j].append(i)
            else:
                if nodes[i] > nodes[j]:
                    sorted_region[j] = sorted_region.get(j, list())
                    sorted_region[j].append(i)
                    sorted_region_reverse[i] = sorted_region_reverse.get(i, list())
                    sorted_region_reverse[i].append(j)

    log_debug(f"sorted_region: {sorted_region}")
    log_debug(f"sorted_region_reverse: {sorted_region_reverse}")

    new_order = []
    added = set()
    sentinel = 0
    # { 0: [4], 1: [0, 2, 3, 4], 2: [0, 4], 3: [0, 2, 4], 4: [] }
    while any(j not in added for j in range(len(nodes))):
        for i in range(len(nodes)):
            if i in added:
                continue
            if (not sorted_region_reverse[i] or
                    all(x in added for x in sorted_region_reverse[i])):
                added.add(i)
                new_order.append(nodes[i])
            log_debug(f"current: {new_order}")
        log_debug(f'{any(j not in added for j in range(len(nodes)))}')
        sentinel += 1
        if sentinel > 20:
            break

    log_debug(f"new_order: {new_order}")

    return new_order


class MediumLevelILAst(object):
    def __init__(self, function: MediumLevelILFunction):
        self._function = function
        self.view = function.source_function.view
        self._nodes = {}
        self._root = MediumLevelILAstBasicBlockNode(
            self, function.basic_blocks[0]
        )
        self._regions = {}
        self._reaching_conditions = {}
        self._reaching_constraints = {}

        self.report_collection = None

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
                "new_root must be a MediumLevelILAstNode, got "
                f"{type(new_root)}"
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

    def case_sort(self, cases: List[MediumLevelILAstCaseNode]):
        log_debug('case_sort')
        log_debug(f'initial: {cases}\n\n')

        fallsthrough = {}
        sorted_cases = sorted(cases)
        log_debug(f'sorted_cases: {sorted_cases}\n\n')
        for i in range(len(sorted_cases)):
            for j in range(i, len(sorted_cases)):
                if self.reaching_conditions.get(
                    (sorted_cases[i].block, sorted_cases[j].block)
                ):
                    log_debug(f'i->j {self.reaching_conditions[(sorted_cases[i].block,sorted_cases[j].block)]}')
                    fallsthrough[i] = fallsthrough.get(i, list())
                    fallsthrough[i].append(j)
                elif self.reaching_conditions.get(
                    (sorted_cases[j].block, sorted_cases[i].block)
                ):
                    log_debug(f'j->i {self.reaching_conditions[(sorted_cases[j].block,sorted_cases[i].block)]}')
                    fallsthrough[j] = fallsthrough.get(j, list())
                    fallsthrough[j].append(i)

        new_sorted = []
        for case in sorted_cases:
            if case is None:
                continue

            if case in fallsthrough:
                others = fallsthrough[case]
                log_debug(f'fallsthrough[{case}]: {others}')
                # Collect cases and replace them with None
                # Don't collect if it's already None, because
                # that means we already got it.
                sub_list = (
                    (
                        [sorted_cases[case]]
                        if sorted_cases[case] is not None
                        else []
                    ) +
                    [sorted_cases[o] for o in others if o is not None]
                )
                map(lambda i: sorted_cases.insert(i, None), [case]+[others])
                new_sorted += sub_list
            else:
                new_sorted.append(case)

        log_debug(f'{new_sorted}')

        return new_sorted

    def any_node_dominated(
        self,
        sub_region: MediumLevelILAstNode,
        block: MediumLevelILBasicBlock,
        bb: MediumLevelILBasicBlock
    ):
        log_debug(f'any_node_dominated: {bb} {block} {sub_region}')

        to_visit = []

        def add_to_visit(_node: MediumLevelILAstNode):
            nonlocal to_visit
            if _node.type in ('seq', 'case'):
                to_visit += _node.nodes
            elif _node.type == 'switch':
                to_visit += _node.cases
            else:
                log_debug(f'add {node.type} to add_to_visit')

        add_to_visit(sub_region)

        while to_visit:
            node = to_visit.pop()
            add_to_visit(node)

            if node.type != 'case':
                continue

            log_debug(f'checking {node.block}')

            reaching_conditions = self.reaching_conditions.get(
                (bb, node.block)
            )

            if reaching_conditions is None:
                continue

            for rc in reaching_conditions:
                targets = [e.target for e in rc]
                if block not in targets:
                    return True

        return False

    def order_basic_blocks(self):
        log_debug('order_basic_blocks')
        visited = set()
        ordering = []

        def order(bb: MediumLevelILBasicBlock):
            visited.add(bb)

            for o in bb.outgoing_edges:
                if not o.back_edge and o.target not in visited:
                    order(o.target)
            ordering.append(bb)

        order(self._function.basic_blocks[0])

        log_debug(f'ordering: {ordering}')
        return ordering

    def calculate_reaching_conditions(self):
        # TODO: add temporary node such that no_return nodes
        # think that they drop into the next region
        reaching_conditions = {}

        visited_nodes = set()

        # recursive method to create an iterator of the edges in
        # the CFG as a DFS
        def dfs_next_edge(bb, target):
            log_debug(f'--dfs_next_edge({bb})--')

            for o in bb.outgoing_edges:
                log_debug(f'yielding {o}')
                yield o
                if not o.back_edge:
                    if o.target == target:
                        continue
                    for t in dfs_next_edge(o.target, target):
                        yield t

        for ns, ne in product(self.order_basic_blocks(), repeat=2):
            if ns == ne:
                continue

            log_debug(f"({ns}, {ne})")

            dfs_stack = []
            visited_edges = set()
            visited_nodes = set()

            for e in dfs_next_edge(ns, ne):
                log_debug(f"    {e.type!r} {e.source} -> {e.target}")

                nt = e.target

                if e.back_edge:
                    visited_edges.add(e)

                if e in visited_edges:
                    log_debug(f"    edge in visited_edges")

                elif e not in visited_edges and nt not in visited_nodes:
                    log_debug(f"    adding edge to edges")
                    visited_edges.add(e)
                    visited_nodes.add(nt)
                    dfs_stack = dfs_stack + [e]

                    if nt == ne and dfs_stack:
                        log_debug(f'{nt} == {ne}')
                        log_debug("    adding finished slice")
                        reaching_conditions[
                            (ns, ne)
                        ] = reaching_conditions.get((ns, ne), list())
                        reaching_conditions[(ns, ne)].append(dfs_stack)

                elif (nt, ne) in reaching_conditions and e not in dfs_stack:
                    log_debug("    hit simple path, adding finished slice")
                    reaching_conditions[(ns, ne)] = reaching_conditions.get(
                        (ns, ne), list()
                    )

                    reaching_conditions[(ns, ne)].append(dfs_stack)
                    visited_edges.add(e)

                if dfs_stack:
                    log_debug(f'    {dfs_stack}')
                while len(dfs_stack) and all(
                    descendant.target in visited_nodes or descendant.source == ne or descendant.back_edge
                    for descendant in dfs_stack[-1].target.outgoing_edges
                ):
                    log_debug(f"    popping {dfs_stack[-1]}")
                    dfs_stack = dfs_stack[:-1]

                visited_nodes.remove(ne) if ne in visited_nodes else None

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
        self.report_collection = ReportCollection()

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
        generate_graph(self.view, self.regions[0][1], self.report_collection, 'Step 3')

        # step 6: merge if/else statements
        self._merge_if_else()
        generate_graph(self.view, self.regions[0][1], self.report_collection, 'Step 6')

        # # step 7: refine loops
        self._refine_loops()
        generate_graph(self.view, self.regions[0][1], self.report_collection, 'Step 7')

        show_report_collection('AST Generation', self.report_collection)

        log_debug("finished with AST")

    def _find_regions(self):
        basic_blocks = self._function.basic_blocks

        regions = self._regions

        bb_queue = region_sort(
            list(MediumLevelILAstBasicBlockNode(self, b) for b in basic_blocks)
        )

        log_debug(f"{bb_queue}")

        while bb_queue:
            bb = bb_queue.pop().block

            if bb not in self._cycles:
                new_region = self._create_acyclic_region(bb, regions, bb_queue)
            else:
                new_region = self._create_cyclic_region(bb, regions, bb_queue)

            if new_region is None:
                continue

            if self.report_collection is not None:
                generate_graph(
                    self.view,
                    new_region,
                    self.report_collection
                )

            log_debug(f"adding {new_region} to regions")
            regions[bb] = new_region

        return regions

    def _create_acyclic_region(self, bb: MediumLevelILBasicBlock, regions: dict, bb_queue: list):
        if next((e for e in bb.outgoing_edges if e.back_edge), None):
            # a back edge node isn't going to be the root of a region
            return

        current_node = None
        cases = {}

        log_debug(f"{'='*40}\ncreating acyclic region for {bb.start}\n{'='*40}")

        if bb[-1].operation == MediumLevelILOperation.MLIL_JUMP_TO:
            switch = bb[-1].dest.possible_values.mapping

            for case, block in switch.items():
                log_debug(f"case {case}: {block:x}")
                il_block = next(
                    b
                    for b in self._function.basic_blocks
                    if b.source_block.start == block
                )
                cases[il_block] = cases.get(il_block, list())

                cases[il_block].append(case)

            # TODO: figure out fall through cases
            switch_condition = self._find_switch_condition(
                bb[-1].dest, switch.keys()
            )
            current_node = MediumLevelILAstSwitchNode(
                self, switch_condition, bb[-1]
            )
        else:
            current_node = MediumLevelILAstSeqNode(self)

        # bb must be the head of an acyclic region (for the moment)
        possible_region = {
            MediumLevelILAstBasicBlockNode(self, pr)
            for pr in self._function.basic_blocks
            if (bb, pr) in self.reaching_conditions
        }

        nodes = [MediumLevelILAstBasicBlockNode(self, bb)]

        regions_in_this_region = {
            r for r in possible_region if r.block in self._regions
        }

        log_debug(f"regions_in_this_region: {regions_in_this_region}")

        possible_region = possible_region - regions_in_this_region

        log_debug(f"possible_region: {possible_region}")

        for r in regions_in_this_region:
            r_has_multiple_incoming = len(r.block.incoming_edges) > 1

            log_debug(
                f"{r} r_has_multiple_constraints: "
                f"{r_has_multiple_incoming}"
            )
            log_debug(
                f"{r} {bb} in r.block.dominators: "
                f"{bb in r.block.dominators}"
            )

            sub_region = regions[r.block]

            if (
                r.block in cases or not r_has_multiple_incoming
            ) or bb in r.block.dominators:
                if self.create_new_node_from_region(
                    bb, r.block, sub_region, current_node, cases, nodes
                ):
                    del regions[r.block]

            self.remove_sub_region_nodes(sub_region, possible_region)

        for r in possible_region:
            log_debug(f"Adding {r} to {bb.start}'s region")
            nodes.append(r)
            if r.block in bb_queue:
                bb_queue.remove(r.block)

        if current_node.type == "switch":
            current_node._cases = self.case_sort(current_node._cases)

            for case in current_node._cases:
                # if there are no reaching conditions, then
                # this doesn't fall through. Insert a break node.
                if all(
                    self.reaching_conditions.get(
                        (case.block, other.block)
                    )
                    is None
                    for other in current_node._cases
                ):
                    case.append(
                        MediumLevelILAstBreakNode(
                            self,
                            case.nodes[-1].start,
                            case.nodes[-1].address,
                        )
                    )

            nodes.append(current_node)
            current_node = MediumLevelILAstSeqNode(self, nodes)

        current_node._nodes = sorted(nodes)

        if current_node.type == "seq":
            current_node.flatten_sequence()

        new_region = current_node

        log_debug(f"Returning {new_region}")

        return new_region

    # TODO: Figure out why this breaks on bomb.bndb Phase 2
    def _create_cyclic_region(
        self,
        bb: MediumLevelILBasicBlock,
        regions: dict,
        bb_queue: list
    ) -> MediumLevelILAstNode:
        log_debug(f'_create_cyclic_region({bb}, regions, bb_queue)')

        log_debug(f"{'='*40}\ncreating cyclic region for {bb.start}\n{'='*40}")
        # Section C.1 in whitepaper: Initial Loop Nodes and Successors
        latching_nodes = {
            e.source for e in bb.incoming_edges if e.back_edge
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

        # Section C.2 in whitepaper: Successor Refinement and Loop
        # Membership
        while len(successor_nodes) > 1:
            new = set()
            old = set()
            for successor in sorted(
                list(successor_nodes), key=lambda i: i.start
            ):
                # add a successor to the loop if both hold true:
                # a) the successor is dominated by the start of the
                #    loop
                # b) the successor's immediate predecessors are all in
                #    the loop.
                if bb in successor.dominators and all(
                    incoming.source in loop_nodes
                    for incoming in successor.incoming_edges
                ):
                    loop_nodes.add(successor)
                    old.add(successor)
                    new = new & {
                        e.target for e in successor.outgoing_edges
                    }

            if old:
                successor_nodes = successor_nodes - old

            if new:
                successor_nodes = set(*successor_nodes, *new)
            else:
                break

        log_debug(f"final successor_nodes: {successor_nodes}")

        log_debug(f"loop_nodes: {loop_nodes}")

        loop_node = MediumLevelILAstLoopNode(
            self,
            MediumLevelILAstSeqNode(
                self,
                [MediumLevelILAstBasicBlockNode(self, bb)]
                )
        )

        loop_nodes = [
            MediumLevelILAstBasicBlockNode(self, block)
            for block in loop_nodes
        ]

        sorted_loop_nodes = region_sort(loop_nodes)
        loop_nodes = list(sorted_loop_nodes)
        log_debug(f"Sorted loop_nodes: {loop_nodes}")

        # remove any regions that are in the loop nodes
        nodes = []
        while sorted_loop_nodes:
            r = sorted_loop_nodes.pop(0)

            log_debug(f'Iterating on {r.block}')
            if r.block in regions:
                log_debug(f'Found {r.block} in regions')
                sub_region = regions[r.block]
            else:
                log_debug(f'{r.block} not in regions, creating Seq Node')
                sub_region = MediumLevelILAstSeqNode(
                        self,
                        [MediumLevelILAstBasicBlockNode(self, r.block)],
                    )

            log_debug(f"Creating node for {r.block}")
            if self.create_new_node_from_region(
                bb, r.block, sub_region, loop_node, None, nodes
            ):
                if r.block in regions:
                    log_debug(f"Removing region for {r.block}")
                    del regions[r.block]

            log_debug(f"Removing {sub_region} from loop_nodes")
            self.remove_sub_region_nodes(sub_region, sorted_loop_nodes)

            for n in loop_nodes:
                log_debug(f"Removing {n} from bb_queue")
                if n.block in bb_queue:
                    bb_queue.remove(n.block)

        log_debug('Adding break nodes for successors')

        successor_cond = None
        successor_node = None
        for successor in successor_nodes:
            log_debug(f'successor: {successor}')
            reaching_constraint = self._reaching_constraints.get(
                (bb, successor)
            )
            break_node = MediumLevelILAstCondNode(
                self,
                reaching_constraint,
                successor[0],
                MediumLevelILAstSeqNode(
                    self,
                    [
                        MediumLevelILAstBreakNode(
                            self,
                            successor.start,
                            successor.source_block.start,
                        )
                    ],
                ),
            )
            nodes.append(break_node)

            if successor in self._regions:
                successor_node = self._regions[successor]
                del self._regions[successor]
            else:
                successor_node = MediumLevelILAstSeqNode(
                    self,
                    [MediumLevelILAstBasicBlockNode(self, successor)],
                )

            # convert the successor nodes to a chain of
            # condition nodes for each successor
            if len(successor_nodes) > 1:
                successor_cond = MediumLevelILAstCondNode(
                    self,
                    self.reaching_constraints.get((bb, successor)),
                    successor.source_block[0],
                    successor_node,
                    successor_cond,
                )

        if successor_cond is not None:
            successor_node = successor_cond

        body = MediumLevelILAstSeqNode(self, nodes)
        loop_node._body = body

        if successor_node is not None:
            region_nodes = [loop_node, successor_node]
            new_region = MediumLevelILAstSeqNode(self, region_nodes)
        else:
            new_region = loop_node

        return new_region

    def create_new_node_from_region(
        self,
        bb: MediumLevelILBasicBlock,
        block: MediumLevelILBasicBlock,
        sub_region: MediumLevelILAstNode,
        current_node: MediumLevelILAstNode,
        cases: dict,
        nodes: list,
    ):
        log_debug(f'create_new_node_from_region({bb}, {block}, {sub_region}, {current_node})')
        reaching_constraint = self._reaching_constraints.get((bb, block))

        if is_true(reaching_constraint):
            reaching_constraint = None

        if reaching_constraint is not None and self.any_node_dominated(
                sub_region, block, bb):
            reaching_constraint = None

        if sub_region.type != "loop" and reaching_constraint is not None:
            # This is now a condition node if a reaching constraint exists
            log_debug(f'    Creating new CondNode with {sub_region} {reaching_constraint}\n\n')
            new_node = MediumLevelILAstCondNode(
                self,
                reaching_constraint,
                block.incoming_edges[0].source[-1],
                sub_region,
            )

        else:
            new_node = sub_region

        if new_node is not None:
            if current_node.type != "switch":
                nodes.append(new_node)
            else:
                if block in cases:
                    if current_node.block not in new_node.block.dominators:
                        case = ["default"]
                    else:
                        case = cases[block]

                    current_node.append(
                        MediumLevelILAstCaseNode(self, case, [new_node])
                    )
                else:
                    return False

        return True

    def remove_sub_region_nodes(self, sub_region, possible_region):
        if sub_region.type == "seq":
            to_remove = sub_region.nodes
        elif sub_region.type == "loop":
            to_remove = sub_region.body.nodes
        else:
            raise TypeError(
                "I don't know why I got a "
                f"{type(sub_region)} for a sub_region"
            )

        while to_remove:
            sub = to_remove.pop()

            if sub.type in ("seq", "case"):
                to_remove += sub.nodes

            elif sub.type == "loop":
                to_remove += sub.body.nodes

            elif sub.type == "cond":
                to_remove.append(sub[True])

            elif sub.type == "block":
                if sub in possible_region:
                    log_debug(f"removing {sub} from possible_region")
                    possible_region.remove(sub)

            elif sub.type == "switch":
                to_remove += sub.cases

            else:
                log_debug(f"got {sub} while iterating over to_remove")

    def _find_switch_condition(self, dest, cases):
        def check_ranges(ranges, cases):
            for r in ranges:
                for i in range(r.start, r.end, r.step):
                    if i not in cases:
                        return False

            return True

        if dest.operation == MediumLevelILOperation.MLIL_VAR:
            dest = self._function.get_ssa_var_definition(dest.ssa_form.src).src

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

            if pv.type == RegisterValueType.LookupTableValue:
                if (
                    current_operand.operation
                    == MediumLevelILOperation.MLIL_VAR
                ):
                    to_visit.append(
                        self._function.get_ssa_var_definition(
                            current_operand.ssa_form.src
                        )
                    )
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
            if all(v in cases for v in pv.values) and len(cases) == len(
                pv.values
            ):
                result = current_operand
                break
            else:
                continue

        return ConditionVisitor(self.view).simplify(result)

    def _merge_if_else(self):
        log_debug("_merge_if_else")

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

            if node.type == "seq":
                nodes_to_remove = self.find_if_else_for_node(node, node.nodes)
                _nodes = node._nodes

            elif node.type == "loop":
                nodes_to_remove = self.find_if_else_for_node(
                    node.body, node.body.nodes
                )
                _nodes = node.body._nodes

            for n in nodes_to_remove:
                _nodes.remove(n) if n in _nodes else None

            if node.type == "seq":
                nodes_to_check += node.nodes
            elif node.type == "loop":
                nodes_to_check += node.body.nodes
            elif node.type == "cond":
                nodes_to_check.append(node[True]) if node[True] else None
                nodes_to_check.append(node[False]) if node[False] else None

    def find_if_else_for_node(self, parent: MediumLevelILAstNode, nodes: list):
        log_debug(f"find_if_else_for_node")

        nodes_to_check = list(nodes)

        nodes_to_remove = []

        while nodes_to_check:
            ni = nodes_to_check.pop()

            if ni.type != "cond":
                continue

            log_debug(f"checking {ni}")

            for nj in nodes_to_check:
                if nj.type != "cond":
                    continue

                if ni == nj:
                    continue

                log_debug(f"checking against {nj}")

                if self.try_make_simple_if_else(
                    ni, nj, nodes_to_check, nodes_to_remove
                ):
                    break

                if self.try_make_complex_if_else(
                    parent, ni, nj, nodes_to_check, nodes_to_remove
                ):
                    break

        return nodes_to_remove

    def try_make_simple_if_else(
        self, node1, node2, nodes_to_check, nodes_to_remove
    ):

        log_debug("try_make_simple_if_else")

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
        self, parent, node1, node2, nodes_to_check, nodes_to_remove
    ):
        log_debug("try_make_complex_if_else")
        is_complex_if_else = self.find_c_and_R(node1.condition, node2.condition)

        if not is_complex_if_else:
            return False
        else:
            c, R = is_complex_if_else

        # if we get here, we have a complex if/else
        new_if_else_node = MediumLevelILAstCondNode(
            self, c, node1._condition_il, node1[True], node2[True]
        )

        log_debug(f"R is currently {R}")

        new_cond_node = MediumLevelILAstCondNode(
            self,
            R,
            node1._condition_il,
            MediumLevelILAstSeqNode(self, [new_if_else_node]),
        )

        log_debug(f"{new_cond_node}")

        if node1 in parent.nodes:
            node1_idx = parent.nodes.index(node1)

            parent._nodes[node1_idx] = new_cond_node
            nodes_to_remove.append(node2)
            nodes_to_check.remove(node2)
        else:
            log_debug(f'{node1} not in parent.nodes')

    def find_c_and_R(self, cond1, cond2):
        log_info(f"{cond1} vs {cond2}")

        if cond1.decl().name() != "and":
            cond1 = And(cond1, BoolVal(True))
        if cond2.decl().name() != "and":
            cond2 = And(cond2, BoolVal(True))

        to_visit = [(cond1, BoolVal(True))]

        while to_visit:
            current_cond, right_side = to_visit.pop()
            log_info(f"current: {current_cond} right: {right_side}")

            # If the top level operation is not an And, we don't need
            # to go any further.
            if current_cond.decl().name() != "and":
                log_info(f"current_cond is {current_cond}")
                return False

            if current_cond.num_args() < 2:
                log_info(f"current_cond is {current_cond}")
                return False

            # try 0 and R first
            c = current_cond.arg(0)
            R = And(
                *Tactic("ctx-solver-simplify")(
                    And(current_cond.arg(1), right_side)
                )[0]
            )
            if R.num_args() == 0:
                R = BoolVal(True)

            log_info(f"c: {c} R: {R} cond2: {cond2}")
            if not Tactic("ctx-solver-simplify")(And(Not(c), R) == cond2)[0]:
                log_info(
                    f"Found complex if/else (0-1)! {R} and {c} | {cond2}"
                )
                return c, R

            # try again, but the other way
            c = current_cond.arg(1)
            R = And(
                *Tactic("ctx-solver-simplify")(
                    And(current_cond.arg(0), right_side)
                )[0]
            )
            if R.num_args() == 0:
                R = BoolVal(True)
            log_info(f"c: {c} R: {R} cond2: {cond2}")
            if not Tactic("ctx-solver-simplify")(And(Not(c), R) == cond2)[0]:
                log_info(
                    f"Found complex if/else (1-0)! {R} and {c} | {cond2}"
                )
                return c, R

            to_visit = [
                (current_cond.arg(0), current_cond.arg(1)),
                (current_cond.arg(1), current_cond.arg(0)),
            ]

        return False

    def generate_reaching_constraints(self):
        visitor = ConditionVisitor(self.view)

        for (
            (start, end),
            reaching_condition,
        ) in self.reaching_conditions.items():
            or_exprs = []

            for condition in reaching_condition:
                and_exprs = []

                for edge in condition:
                    if edge.type == BranchType.UnconditionalBranch:
                        continue

                    if edge.type == BranchType.TrueBranch:
                        condition = edge.source[-1].condition
                        if (
                            condition.operation
                            == MediumLevelILOperation.MLIL_VAR
                        ):
                            condition = self.function.get_ssa_var_definition(
                                edge.source[-1].ssa_form.condition.src
                            ).src
                        and_exprs.append(visitor.simplify(condition))

                    elif edge.type == BranchType.FalseBranch:
                        condition = edge.source[-1].condition
                        if (
                            condition.operation
                            == MediumLevelILOperation.MLIL_VAR
                        ):
                            condition = self.function.get_ssa_var_definition(
                                edge.source[-1].ssa_form.condition.src
                            ).src
                        and_exprs += Tactic("ctx-solver-simplify")(
                            Not(visitor.simplify(condition))
                        )[0]

                if and_exprs != []:
                    or_exprs.append(And(*and_exprs))

            if or_exprs:
                or_exprs = Tactic("ctx-solver-simplify")(Or(*or_exprs))[0]
                reaching_constraint = (
                    And(*or_exprs)
                    if len(or_exprs) > 1
                    else or_exprs[0]
                    if len(or_exprs)
                    else BoolVal(True)
                )
                self._reaching_constraints[(start, end)] = reaching_constraint

    def _refine_loops(self):
        log_info("_refine_loops")

        to_visit = [r for r in self._regions.values()]

        visited = set()

        while to_visit:
            node = to_visit.pop()

            if node.type == "block":
                continue

            if node in visited:
                log_info(f"wtf, why have I visited {node} already")
                break

            if node.type == "seq":
                to_visit += [n for n in node.nodes if n is not None]
            elif node.type == "cond":
                to_visit += node[True].nodes if node[True] else []
                to_visit += node[False].nodes if node[False] else []

            if node.type == "loop":
                log_info(f"{node}")

                generate_graph(
                    self.view,
                    node,
                    self.report_collection,
                    f'    {node.start} before refining'
                )

                while_condition = self._check_while(node)
                if while_condition is not None:
                    log_info(f"{node} is a while loop")
                    node.loop_type = "while"
                    node.condition = reduce(
                        And,
                        Tactic("ctx-solver-simplify")(Not(while_condition))[0],
                    )

                    break_cond = node.body.nodes[0]

                    if break_cond[False] is not None:
                        node.body._nodes[0] = break_cond[False]

                    # Flatten condition nodes that have the same condition
                    # as the loop condition
                    for idx, child in enumerate(node.body.nodes):
                        if (
                            isinstance(child, MediumLevelILAstCondNode)
                            and is_true(
                                simplify(child.condition == node.condition)
                            )
                            and child[False] is None
                        ):
                            node.body._nodes[idx] = child[True]
                    continue

                dowhile_condition = self._check_do_while(node)
                if dowhile_condition is not None:
                    log_info(f"{node} is a do while loop")
                    node.loop_type = "dowhile"
                    node.condition = reduce(
                        And,
                        Tactic("ctx-solver-simplify")(Not(dowhile_condition))[
                            0
                        ],
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
                            and is_true(
                                simplify(child.condition == node.condition)
                            )
                            and child[False] is None
                        ):
                            node.body._nodes[idx] = child[True]

                        log_info(f"Checking {child} for break condition")
                        if (
                            isinstance(child, MediumLevelILAstCondNode)
                            and is_false(
                                simplify(And(child.condition, node.condition))
                            )
                        ):
                            is_complex_if = self.find_c_and_R(Not(child.condition), node.condition)

                            if is_complex_if:
                                c, R = is_complex_if
                                log_info(f'Found c: {c} R: {R}')
                                child[True]._nodes.append(
                                    MediumLevelILAstBreakNode(
                                        self,
                                        child[True].nodes[-1].block[-1].instr_index,
                                        child[True].nodes[-1].block[-1].address
                                    )
                                )
                            else:
                                child[True]._nodes.append(
                                    MediumLevelILAstBreakNode(
                                        self,
                                        child[True].nodes[-1].block[-1].instr_index,
                                        child[True].nodes[-1].block[-1].address
                                    )
                                )

                generate_graph(
                    self.view,
                    node,
                    self.report_collection,
                    f'    {node.start} after refining'
                )

    def _check_while(self, loop_node: MediumLevelILAstLoopNode):
        log_info("_check_while")
        if loop_node.loop_type != "endless":
            log_info(loop_node.loop_type)
            return None

        if loop_node.body.nodes[0].type != "cond":
            log_info(f"{loop_node.body.nodes[0].type}")
            return None

        log_info(f"{loop_node.body.nodes[0][True].nodes}")

        if loop_node.body.nodes[0][True].nodes[0].type == "break":
            log_info(f"The loop body is {loop_node.body.nodes}")
            return loop_node.body.nodes[0].condition

        log_info(f"{loop_node.body.nodes[0][True].nodes}")

        return None

    def _check_do_while(self, loop_node: MediumLevelILAstLoopNode) -> bool:
        log_info("_check_do_while")
        log_info(f"{loop_node.body.nodes}")
        if loop_node.loop_type != "endless":
            log_info(loop_node.loop_type)
            return None

        if loop_node.body.nodes[-1].type != "cond":
            log_info(f"final node is: {loop_node.body.nodes[-1].type}")
            return None

        log_info(f"final cond true node: {loop_node.body.nodes[-1][True].nodes}")

        if loop_node.body.nodes[-1][True].nodes[0].type == "break":
            return loop_node.body.nodes[-1].condition

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
                    if (
                        il.instr_index == node.header.end - 1
                    ) and il.operation not in (
                        MediumLevelILOperation.MLIL_RET,
                        MediumLevelILOperation.MLIL_RET_HINT,
                    ):
                        continue
                    tokens = ""
                    for t in il.tokens:
                        if (
                            t.type
                            != InstructionTextTokenType.PossibleAddressToken
                        ):
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
