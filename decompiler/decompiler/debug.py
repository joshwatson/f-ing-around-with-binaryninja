from __future__ import annotations
from typing import Dict, List

from binaryninja import (BinaryView, BranchType, FlowGraph, FlowGraphNode,
                         FlowGraphReport, ReportCollection, show_graph_report)

from . import mlil_ast
from .nodes import MediumLevelILAstNode


def generate_graph(
    view: BinaryView,
    region: MediumLevelILAstNode,
    collection: ReportCollection = None,
    title: str = ''
):

    graph = FlowGraph()

    def add_children(node: MediumLevelILAstNode) -> FlowGraphNode:
        node_node = FlowGraphNode(graph)
        graph.append(node_node)

        node_line = node.type

        if node.type == 'block':
            node_line += f': {node.block}'
        if node.type == 'break':
            pass
        elif node.type in ('seq', 'case'):
            node_line += f': {node.start}'
            for child in node.nodes:
                child_node = add_children(child)
                node_node.add_outgoing_edge(
                    BranchType.UnconditionalBranch,
                    child_node
                )
        elif node.type == 'cond':
            node_line += f': {node.condition}'
            child = add_children(node[True])
            node_node.add_outgoing_edge(
                BranchType.TrueBranch,
                child
            )
            if node[False] is not None:
                child = add_children(node[False])
                node_node.add_outgoing_edge(
                    BranchType.FalseBranch,
                    child
                )
        elif node.type == 'switch':
            for child in node.cases:
                child_node = add_children(child)
                node_node.add_outgoing_edge(
                    BranchType.UnconditionalBranch,
                    child_node
                )
        elif node.type == 'loop':
            node_line += f': {node.loop_type} {node.condition}'
            child_node = add_children(node.body)
            node_node.add_outgoing_edge(
                BranchType.UnconditionalBranch,
                child_node
            )

        node_node.lines = [node_line]

        return node_node

    # iterate over regions and create nodes for them
    # in the AST
    add_children(region)

    if collection is not None:
        if not title:
            title = f'    {region.type}: {region.start}'
        report = FlowGraphReport(title, graph, view)
        collection.append(report)
    else:
        show_graph_report('Current AST', graph)
