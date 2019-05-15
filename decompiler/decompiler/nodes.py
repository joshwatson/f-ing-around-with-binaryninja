from __future__ import annotations

from functools import reduce

from z3 import And, Bool, Tactic, simplify

from binaryninja import (
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    log_debug,
)

from . import mlil_ast

_true_condition = simplify(Bool("a") == Bool("a"))


class MediumLevelILAstNode(object):
    def __init__(self, ast: mlil_ast.MediumLevelILAst):
        self._type = None
        self._ast = ast

    @property
    def type(self):
        return self._type

    @property
    def ast(self):
        return self._ast

    @property
    def start(self):
        return None

    @property
    def block(self):
        return None

    def __lt__(self, other):
        log_debug("MediumLevelILAstNode.__lt__")
        result = (
            True
            if self._ast.reaching_conditions.get((self.block, other.block))
            is not None
            else True
            if self.start < other.start
            else False
        )
        log_debug(f"{self} < {other} == {result}")
        return result

    def __le__(self, other):
        log_debug("__le__")
        return (
            True
            if self._ast.reaching_conditions.get((self, other)) is not None
            else False
        )

    def __gt__(self, other):
        log_debug("__gt__")
        return (
            True
            if self._ast.reaching_conditions.get((other, self)) is not None
            else False
        )

    def __ge__(self, other):
        log_debug("__ge__")
        return (
            True
            if self._ast.reaching_conditions.get((other, self)) is not None
            else False
        )

    def __eq__(self, other):
        log_debug("__eq__")
        if not isinstance(other, type(self)):
            return False

        return (
            True
            if self._type == other._type and self.start == other.start
            else False
        )

    def __ne__(self, other):
        return not isinstance(other, type(self)) or self.start != other.start


class MediumLevelILAstSeqNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, nodes: list = None):
        super().__init__(ast)
        self._type = "seq"
        self._nodes: list = nodes if nodes is not None else []

        self.flatten_sequence()

    def flatten_sequence(self):
        log_debug("flatten_sequence")

        if not len(self._nodes):
            return

        flattened_nodes = []
        for node in self.nodes:
            if node.type == "seq":
                flattened_nodes += node.nodes
            else:
                flattened_nodes.append(node)
        self._nodes = flattened_nodes

    @property
    def start(self):
        if self._nodes:
            return self._nodes[0].start
        else:
            return 0

    @property
    def address(self):
        if self._nodes:
            return self._nodes[0].address
        return None

    @property
    def block(self):
        if self._nodes:
            return self._nodes[0].block
        return None

    @property
    def nodes(self):
        return list(self._nodes)

    def append(self, value):
        self._nodes.append(value)

    def pop(self, idx=-1):
        self._nodes.pop(idx)

    def __str__(self):
        return f"<seq: start={self.start} {[n for n in self._nodes]}>"

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False

        return self.start == other.start

    def __hash__(self):
        return hash(self.start)


class MediumLevelILAstCondNode(MediumLevelILAstNode):
    def __init__(
        self,
        ast: mlil_ast.MediumLevelILAst,
        condition: Bool,
        condition_il: MediumLevelILInstruction,
        true: MediumLevelILAstNode,
        false: MediumLevelILAstNode = None,
    ):
        if condition is None:
            raise NotImplementedError("condition should not be None")
        self._condition = condition
        super().__init__(ast)
        self._type = "cond"
        self._condition_il = condition_il
        self._true = true
        self._false = false

        self._flatten_conditions()

    def _flatten_conditions(self):
        log_debug(f"_flatten_conditions {self.condition}")
        if self[True] is None:
            return

        nodes = [
            n
            for n in self[True].nodes
            if n.type != "block"
            or n.block[0].operation
            not in (
                MediumLevelILOperation.MLIL_IF,
                MediumLevelILOperation.MLIL_GOTO,
            )
        ]

        if any(n.type != "cond" for n in nodes):
            for node in nodes:
                log_debug(f"- {node}")
            return

        new_conditions = []

        for node in nodes:
            if node[False] is not None:
                return
            log_debug(f"+ {node._condition}")
            node._condition = reduce(
                And,
                Tactic("ctx-solver-simplify")(
                    And(self._condition, node._condition)
                )[0],
            )
            log_debug(f"flattened condition: {node._condition}")
            new_conditions.append(node)

        self.__class__ = MediumLevelILAstSeqNode
        self._type = "seq"
        self._nodes = sorted(new_conditions)

    @property
    def start(self) -> int:
        return self._condition_il.instr_index

    @property
    def address(self) -> int:
        return self._condition_il.address

    @property
    def block(self) -> MediumLevelILBasicBlock:
        return self._condition_il.il_basic_block

    @property
    def condition(self) -> Bool:
        return self._condition

    def __eq__(self, other):
        if not isinstance(other, MediumLevelILAstCondNode):
            return False

        return self[True] == other[True]

    def __repr__(self):
        return (
            f"<cond: start={self.start} {self.condition} -> "
            f"({self._true} | {self._false})>"
        )

    def __hash__(self):
        return hash(self.start)

    def __getitem__(self, key):
        if key:
            return self._true
        else:
            return self._false

    def __setitem__(self, key, value):
        if key:
            self._true = value
        else:
            self._false = value


class MediumLevelILAstElseNode(MediumLevelILAstNode):
    def __init__(self, ast, address):
        super().__init__(ast)
        self._type = "else"
        self._address = address

    @property
    def address(self):
        return self._address


class MediumLevelILAstBreakNode(MediumLevelILAstNode):
    def __init__(self, ast, start, address):
        super().__init__(ast)
        self._address = address
        self._start = start
        self._type = "break"

    @property
    def address(self):
        return self._address

    @property
    def start(self):
        return self._start

    def __repr__(self):
        return f"<break: start={self.start} address={self.address:x}>"

    def __iter__(self):
        return iter([])


class MediumLevelILAstLoopNode(MediumLevelILAstNode):
    def __init__(
        self,
        ast: mlil_ast.MediumLevelILAst,
        body: MediumLevelILAstSeqNode,
        condition=_true_condition,
        loop_type: str = "endless",
    ):
        super().__init__(ast)
        self._body = body
        self._condition = condition
        self._type = "loop"
        self._loop_type = loop_type

    @property
    def start(self):
        return self._body.start

    @property
    def block(self):
        return self._body.block

    @property
    def body(self):
        return self._body

    @property
    def address(self):
        return self.body.address

    @property
    def condition(self):
        return self._condition

    @condition.setter
    def condition(self, value):
        self._condition = value

    @property
    def loop_type(self):
        return self._loop_type

    @loop_type.setter
    def loop_type(self, value: str):
        if value in ("endless", "while", "dowhile", "for"):
            self._loop_type = value
        else:
            raise ValueError(
                "Type should be 'endless', 'while', 'for', or 'dowhile'."
            )

    def __hash__(self):
        return hash(self.start)

    def __repr__(self):
        return f"<loop: condition={self.condition} start={self.start}>"


class MediumLevelILAstSwitchNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, switch, start, address):
        self._switch = switch
        self._cases = {}
        super().__init__(ast)
        self._type = "switch"
        self._start = start
        self._address = address

    @property
    def children(self):
        return list(self._cases.values())

    @property
    def cases(self):
        return dict(self._cases)

    @property
    def switch(self):
        return self._switch

    @property
    def start(self):
        return self._start

    def address(self):
        return self._address

    def __setitem__(self, case, node):
        self._cases[case] = node

    def __getitem__(self, case):
        return self._cases[case]

    def __repr__(self):
        return f"<switch: start={self.start} {len(self._cases)} cases>"

    def __hash__(self):
        return hash(self.start)


class MediumLevelILAstBasicBlockNode(MediumLevelILAstNode):
    def __init__(
        self, ast: mlil_ast.MediumLevelILAst, bb: MediumLevelILBasicBlock
    ):
        super().__init__(ast)
        self._bb = bb
        self._type = "block"

    @property
    def block(self) -> MediumLevelILBasicBlock:
        return self._bb

    @property
    def start(self) -> int:
        return self._bb.start

    @property
    def address(self) -> int:
        return self._bb[0].address

    def __lt__(self, other):
        log_debug("__lt__")
        result = (
            True
            if self._ast.reaching_conditions.get((self.block, other.block))
            is not None
            else False
        )

        log_debug(f"{self} < {other} == {result}")
        return result or (self.start == other.start and other.type == "cond")

    def __eq__(self, other):
        if isinstance(other, MediumLevelILBasicBlock):
            return self.block == other

        if not isinstance(other, type(self)):
            return False

        return self.block == other.block

    def __hash__(self):
        return hash(self.block)

    def __repr__(self):
        return f"<bb start={self.start}>"
