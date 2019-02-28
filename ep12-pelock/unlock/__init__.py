# This script requires python 3
__all__ = ["UnlockVisitor", "SEHState"]

from binaryninja import (
    PluginCommand,
    BinaryView,
    Function,
    FlowGraph,
    FlowGraphNode,
    DisassemblyTextLine,
    BranchType,
)
from binaryninja import core_ui_enabled
from .unlockvisitor import UnlockVisitor
from .state import SEHState


def run_unlock(view: BinaryView, function: Function):
    u = UnlockVisitor(function, function.start)
    u.start()
    if not core_ui_enabled():
        import time
        from datetime import timedelta

        dot_count = 0
        start = time.time()
        while not u.finished:
            time.sleep(1)
            print(
                f'[{timedelta(seconds=(time.time() - start))}] Running{"."*dot_count:<4s}\r',
                end="",
            )
            dot_count = (dot_count + 1) % 4
        u.join()
        print(f"{view.functions}")


PluginCommand.register_for_function(
    r"Unlock\Run unlock",
    "Run unlock",
    run_unlock,
    is_valid=lambda v, f: "obfuscated" in v.file.filename,
)


def generate_graphs(view: BinaryView):
    for func in view.functions:
        bbs = {}
        g = FlowGraph()
        g.function = func
        n = FlowGraphNode(g)
        for bb in func.basic_blocks:
            if bb.start not in bbs:
                print(f"bbs[{bb.start:x}] = n")
                bbs[bb.start] = n
            else:
                print("g.append(n)")
                g.append(n)
                print(f"n = bbs[{bb.start:x}]")
                n = bbs[bb.start]
            current_addr = bb.start
            for instr in bb:
                if instr[0][0].text not in ("nop", "jmp") or (
                    instr[0][0].text == "jmp" and not bb.outgoing_edges
                ):
                    print(instr[0])
                    n.lines += [DisassemblyTextLine(instr[0], address=current_addr)]

                current_addr += instr[1]
                if (
                    instr[0][0].text == "jmp"
                    and bb.outgoing_edges
                    and bb.outgoing_edges[0].target.start in bbs
                    and bb.outgoing_edges[0].target in bb.dominators
                ):
                    n.add_outgoing_edge(
                        BranchType.UnconditionalBranch,
                        bbs[bb.outgoing_edges[0].target.start],
                    )
                else:
                    # Keep using the same FlowGraphNode
                    pass
        g.append(n)
        g.layout_and_wait()
        g.show(func.name)


PluginCommand.register(
    r"Unlock\Generate Graphs",
    "Generate Deobfuscated Graphs",
    generate_graphs,
    lambda v: "obfuscated" in v.file.filename,
)
