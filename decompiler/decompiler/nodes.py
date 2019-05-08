from __future__ import annotations

from collections import deque

from binaryninja import MediumLevelILBasicBlock, MediumLevelILInstruction

from . import mlil_ast
from z3 import Bool

class MediumLevelILAstNode(object):
    def __init__(self, ast: mlil_ast.MediumLevelILAst):
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
    def ast(self) -> mlil_ast.MediumLevelILAst:
        return self._ast


class MediumLevelILAstSeqNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, header):
        super().__init__(ast)
        self._header = header

    @property
    def start(self):
        return self._header.start

    @property
    def header(self):
        return self._header

    def __str__(self):
        return f"<seq: header={self._header}, {[c for c in self._children]}>"

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False

        return self.header == other.header

    def __hash__(self):
        return hash(self.header)


class MediumLevelILAstCondNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, condition: Bool, if_address: int):
        if condition is None:
            raise NotImplementedError('condition should not be None')
        self._condition = condition
        super().__init__(ast)
        self._children = deque([None, None], 2)
        self._address = if_address

    @property
    def start(self) -> int:
        return self[True].start

    @property
    def address(self) -> int:
        return self._address

    @property
    def condition(self) -> Bool:
        return self._condition

    def __repr__(self):
        return f"<cond: start={self.start} {self.condition} -> ({self[True]} | {self[False]})>"

    def __getitem__(self, key):
        if key:
            return self._children[0]
        else:
            return self._children[1] if len(self._children) > 1 else None

    def __setitem__(self, key, value):
        if key:
            self._children[0] = value
        else:
            self._children[1] = value

class MediumLevelILAstElseNode(MediumLevelILAstSeqNode):
    def __init__(self, ast, condition: Bool, seq: MediumLevelILAstSeqNode, address: int):
        super().__init__(ast, seq.header)
        self._children = seq._children
        self._condition = condition
        self._address = address

    @property
    def condition(self) -> Bool:
        return self._condition

class MediumLevelILAstBreakNode(MediumLevelILAstNode):
    def __init__(self, ast, block: MediumLevelILBasicBlock):
        super().__init__(ast)
        self._block = block

    @property
    def address(self):
        return self._block[0].address

    @property
    def start(self):
        return self._block.start

    def __repr__(self):
        return f'<break: start={self.start} address={self.address:x}>'

    def __iter__(self):
        return iter([])

class MediumLevelILAstLoopNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, loop: MediumLevelILBasicBlock, condition, type_: str='endless'):
        super().__init__(ast)
        self._loop = loop
        self._condition = condition
        self._type = type_
        self._entries = []
        self._exits = []

    @property
    def start(self):
        return self._loop.start

    @property
    def loop(self):
        return self._loop

    @property
    def condition(self):
        return self._condition

    @condition.setter
    def condition(self, value):
        self._condition = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value: str):
        if value in ('endless', 'while', 'dowhile'):
            self._type = value
        else:
            raise ValueError("Type should be 'endless', 'while', or 'dowhile'.")

    @property
    def entries(self):
        return list(self._entries)

    @property
    def exits(self):
        return list(self._exits)

    def add_entry(self, entry):
        self._entries.append(entry)

    def add_exit(self, exit_):
        self._exits.append(exit_)

    def __repr__(self):
        return f"<loop: condition={self.condition} start={self.start}>"

class MediumLevelILAstSwitchNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, switch: MediumLevelILInstruction):
        self._switch = switch
        self._cases = {}
        super().__init__(ast)

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
        return self._switch.instr_index

    def __setitem__(self, case, node):
        self._cases[case] = node

    def __getitem__(self, case):
        return self._cases[case]

    def __repr__(self):
        return f"<switch: start={self.start} {len(self._cases)} cases>"


class MediumLevelILAstBasicBlockNode(MediumLevelILAstNode):
    def __init__(self, ast: mlil_ast.MediumLevelILAst, bb: MediumLevelILBasicBlock):
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
        return f"<bb block={self.block}>"
