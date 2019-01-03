from binaryninja import *
import ctypes

class CallgraphTask(BackgroundTaskThread):
    def __init__(self, view):
        super(CallgraphTask, self).__init__('Generating callgraph...')
        self.view = view

    def run(self):
        collect_calls(self.view)

def get_or_set_call_node(callgraph, function_nodes, function):
    # create a new node if one doesn't exist already
    if function not in function_nodes:
        node = FlowGraphNode(callgraph)

        function_nodes[function] = node

        if function.symbol.type == SymbolType.ImportedFunctionSymbol:
            token_type = InstructionTextTokenType.ImportToken
        else:
            token_type = InstructionTextTokenType.CodeSymbolToken

        # Set the node's text to be the name of the function
        node.lines = [
            DisassemblyTextLine(
                [
                    InstructionTextToken(
                        token_type,
                        function.name,
                        function.start
                    )
                ]
            )
        ]

        callgraph.append(node)
    else:
        node = function_nodes[function]

    return node

def collect_calls(view):
    log_info("collect_calls")

    # dict containing callee -> set(callers)    
    calls = {}

    for function in view.functions:
        for ref in view.get_code_refs(function.start):
            caller = ref.function
            calls[function] = calls.get(function, set())

            call_il = caller.get_low_level_il_at(ref.address)
            if (call_il.operation in (
                        LowLevelILOperation.LLIL_CALL,
                        LowLevelILOperation.LLIL_TAILCALL,
                        LowLevelILOperation.LLIL_CALL_STACK_ADJUST
                    ) and call_il.dest.operation == LowLevelILOperation.LLIL_CONST_PTR):
                calls[function].add(caller)

    callgraph = FlowGraph()
    callgraph.function = view.get_function_at(view.entry_point)
    root_node = FlowGraphNode(callgraph)
    root_node.lines = ['ROOT']
    callgraph.append(root_node)
    function_nodes = {}
    
    call_queue = view.functions

    while call_queue:
        # get the next called function
        callee = call_queue.pop()

        # create a new node if one doesn't exist already
        callee_node = get_or_set_call_node(callgraph, function_nodes, callee)

        # create nodes for the callers, and add edges
        callers = calls.get(callee, set())

        if not callers:
            root_node.add_outgoing_edge(
                BranchType.FalseBranch, callee_node
            )

        for caller in callers:
            caller_node = get_or_set_call_node(callgraph, function_nodes, caller)

            # Add the edge between the caller and the callee
            if ctypes.addressof(callee_node.handle.contents) not in [
                ctypes.addressof(edge.target.handle.contents)
                for edge in caller_node.outgoing_edges]:
                    caller_node.add_outgoing_edge(
                        BranchType.TrueBranch,
                        callee_node
                    )

    callgraph.layout_and_wait()
    callgraph.show('Callgraph')

def generate_callgraph(view):
    log_info("generate_callgraph")
    callgraph_task = CallgraphTask(view)
    callgraph_task.start()

PluginCommand.register(
    'Generate Callgraph',
    'Generate a callgraph of the binary',
    generate_callgraph
)