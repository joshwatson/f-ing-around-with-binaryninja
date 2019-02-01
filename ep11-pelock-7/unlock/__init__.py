# This script requires python 3
__all__ = ["logging", "bnilvisitor", "UnlockVisitor"]
from binaryninja import (
    AnalysisCompletionEvent,
    Architecture,
    BasicBlock,
    BinaryDataNotification,
    BinaryView,
    Function,
    ILBranchDependence,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    RegisterValueType,
    Variable,
    VariableSourceType,
    BackgroundTaskThread,
    log_debug,
    log_warn,
    worker_enqueue,
    PluginCommand,
    BinaryReader,
    LowLevelILOperation,
    SectionSemantics,
    SSAVariable,
)
from queue import Queue
from threading import Event
from functools import partial
import operator as op

from .analysis.analyze_return import analyze_return
from .analysis.analyze_unconditional_jump import analyze_unconditional_jump
from .analysis.analyze_opaque_predicate import analyze_opaque_predicate
from .analysis.analyze_indirect_jump import analyze_indirect_jump
from .analysis.analyze_exception_handler import (
    analyze_exception_handler_store,
    analyze_exception_handler_set_var,
)
from .analysis.analyze_unwind import analyze_unwind
from .analysis.analyze_folding import analyze_goto_folding
from .bnilvisitor import BNILVisitor
from .logging import log_debug


class TargetQueue(Queue):
    def put(self, item, block=True, timeout=None):
        log_debug(f"putting {item:x} in target queue")
        super(TargetQueue, self).put(item, block, timeout)


def run_unlock(view: BinaryView, function):
    u = UnlockVisitor(function, function.start)
    u.start()


PluginCommand.register_for_function(
    "Run unlock",
    "Run unlock",
    run_unlock,
    is_valid=lambda v, f: "obfuscated" in v.file.filename,
)


class UnlockVisitor(BNILVisitor, BackgroundTaskThread):
    def __init__(self, function: Function, start: int):
        BNILVisitor.__init__(self)
        BackgroundTaskThread.__init__(self, f"Deobfuscating {start:x}", True)
        self._start: int = start
        self.function: Function = function
        self.view: BinaryView = function.view
        self.address_size = self.view.arch.address_size
        self.target_queue = TargetQueue()
        self.push_seh = None
        self.in_exception = False
        self.unwinding = False
        self.seh = []
        self.seen = {}
        self.analysis_complete = Event()
        self.target_queue.put(start)

    def run(self):
        while not self.target_queue.empty():
            self.addr = None
            while not self.target_queue.empty():
                self.addr = self.target_queue.get()
                if self.addr is not None:
                    # Attempt to navigate to the location; if we
                    # can't, then it's not a valid instruction
                    # currently
                    # valid = self.view.navigate(self.view.file.view, self.addr)
                    valid = self.view.get_functions_containing(self.addr) is not None
                    if not valid:
                        self.addr = None
                        continue
                    else:
                        break
            else:
                log_debug("target queue has been exhausted")
                return

            log_debug(f"run for {self.addr:x} started")

            self.progress = f"Deobfuscating {self.addr:x}"

            UnlockCompletionEvent(self)

            # Get a new copy of our Function object, since reanalyzing might
            # make dataflow stale
            log_debug(f"Getting new function for {self.addr:x}")
            self.function = next(
                f for f in self.view.get_functions_containing(self.addr)
            )

            self.fs = Variable(
                self.function,
                VariableSourceType.RegisterVariableSourceType,
                0,
                self.function.arch.get_reg_index("fs"),
                "fs",
            )

            il = self.function.get_low_level_il_at(self.addr).mapped_medium_level_il

            mmlil = il.function

            while True:
                log_debug(f"analyzing {il.instr_index}: {il}")

                self.view.begin_undo_actions()
                self.seen[il.address] = self.seen.get(il.address, 0) + 1
                process_result = self.visit(il)
                self.view.commit_undo_actions()

                # If it's True or False, then we've finished
                # processing this path and want to continue
                # processing other paths. If it's an integer,
                # then that's the next IL instruction index we
                # should analyze. If it's None, then just continue
                # on to the next instruction.
                if isinstance(process_result, bool):
                    break
                elif isinstance(process_result, int):
                    next_il = process_result
                else:
                    next_il = il.instr_index + 1

                try:
                    il = mmlil[next_il]
                except:
                    return

            log_debug(f"analysis for {il.address:x} finished")
            if not process_result:
                self.function.reanalyze()

            log_debug("waiting for analysis to finish")
            self.analysis_complete.wait()
            self.analysis_complete.clear()
            log_debug("analysis complete")

        log_debug("target queue is empty")

    visit_MLIL_RET = analyze_return
    visit_MLIL_RET_HINT = analyze_return

    visit_MLIL_JUMP = analyze_indirect_jump
    visit_MLIL_GOTO = analyze_goto_folding

    visit_MLIL_STORE = analyze_exception_handler_store
    visit_MLIL_SET_VAR = analyze_exception_handler_set_var

    def visit_MLIL_IF(self, expr):
        log_debug("visit_MLIL_IF")

        # is this a stosb or something similar? If so,
        # find the largest exit index and start there.
        exits = self.function.get_low_level_il_exits_at(expr.address)
        if len(exits) > 1:
            return max(exits) + 1

        return self.analyze_unconditional_jump(expr)

    def visit_MLIL_UNDEF(self, expr):
        log_debug("visit_MLIL_UNDEF")
        # Nothing to do down this path; just get something
        # else from the target queue.
        return False

    def visit_MLIL_XOR(self, expr):
        log_debug("visit_MLIL_XOR")
        
        # If it's something like `ecx ^ const` and ecx isn't a known
        # value, then just erase it. It's not needed at all. 
        if expr.left.value.type in (
            RegisterValueType.UndeterminedValue,
            RegisterValueType.EntryValue,
        ):
            self.view.convert_to_nop(expr.address)
            self.target_queue.put(expr.function[expr.instr_index + 1].address)
            return True

    def visit_MLIL_TAIL_CALL(self, expr):
        log_debug("visit_MLIL_TAIL_CALL")
        # TODO: implement something to recover control flow
        # for tail calls

        return False

    analyze_opaque_predicate = analyze_opaque_predicate
    analyze_unconditional_jump = analyze_unconditional_jump
    analyze_unwind = analyze_unwind
    analyze_goto_folding = analyze_goto_folding


class UnlockCompletionEvent(AnalysisCompletionEvent):
    def __init__(self, unlock: UnlockVisitor):
        self.unlock = unlock
        super(UnlockCompletionEvent, self).__init__(
            unlock.view, UnlockCompletionEvent.run_next
        )

    def run_next(self):
        log_debug("Setting analysis_complete")
        self.unlock.analysis_complete.set()
