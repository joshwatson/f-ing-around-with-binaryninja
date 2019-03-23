from __future__ import annotations

from binaryninja import MediumLevelILBasicBlock

from . import mlil_ast
from .nodes import MediumLevelILAstBasicBlockNode, MediumLevelILAstNode


class Region(object):
    def __init__(
        self,
        ast: mlil_ast.MediumLevelILAst,
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
            raise TypeError(f"node should be a MediumLevelILAstNode, got {type(node)}")

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
        return f"<Region header={self._header} {len(self.nodes)} nodes>"
