# This script requires python 3
__all__ = ["logging", "bnilvisitor", "UnlockVisitor", "SEHState"]
import operator as op
import time
from functools import partial
from queue import Queue
from threading import Event

from binaryninja import (
    AnalysisCompletionEvent,
    Architecture,
    ArchitectureHook,
    BackgroundTaskThread,
    BasicBlock,
    BinaryDataNotification,
    BinaryReader,
    BinaryView,
    BranchType,
    Function,
    FunctionAnalysisSkipOverride,
    ILBranchDependence,
    InstructionBranch,
    InstructionInfo,
    LowLevelILBasicBlock,
    LowLevelILExpr,
    LowLevelILFunction,
    LowLevelILOperation,
    LowLevelILInstruction,
    MediumLevelILBasicBlock,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    PluginCommand,
    RegisterValueType,
    SectionSemantics,
    SSAVariable,
    Variable,
    VariableSourceType,
    enum
)
from binaryninja import _binaryninjacore as core
from binaryninja import log_debug, log_info, log_warn, worker_enqueue

from .analysis.analyze_exception_handler import (
    analyze_exception_handler_set_var,
    analyze_exception_handler_store,
)
from .analysis.analyze_folding import analyze_constant_folding, analyze_goto_folding
from .analysis.analyze_indirect_jump import analyze_indirect_jump, analyze_possible_call, NewFunctionNotification
from .analysis.analyze_return import analyze_return
from .analysis.analyze_unconditional_jump import analyze_unconditional_jump
from .analysis.analyze_unwind import analyze_unwind
from .bnilvisitor import BNILVisitor
from .logging import log_debug
from .state import SEHState


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
        self.seh_state = SEHState.NoException
        self.seh = []
        self.enter_location = None
        self.seen = {}
        self.analysis_complete = Event()
        self.prev_phase = 1
        self.num_phases = 1
        self.phase = 1

        self.target_queue.put(start)

        self.view.register_notification(NewFunctionNotification())

    def run(self):
        self.run_time = time.time()
        while self.phase:
            self.start_time = time.time()
            while not self.target_queue.empty():
                self.addr = None
                while not self.target_queue.empty():
                    self.addr = self.target_queue.get()
                    if self.addr is not None:
                        # Attempt to navigate to the location; if we
                        # can't, then it's not a valid instruction
                        # currently
                        # valid = self.view.navigate(self.view.file.view, self.addr)
                        log_debug(f"checking validity of {self.addr:x}")
                        valid = (
                            self.view.get_functions_containing(self.addr) is not None
                        )
                        if not valid:
                            log_debug(f"{self.addr:x} is not valid")
                            self.addr = None
                            continue
                        else:
                            break
                else:
                    log_debug("target queue has been exhausted")
                    break

                log_debug(f"run for {self.addr:x} started")

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

                self.progress = f"[Phase {self.phase}] {self.addr:x} in function {self.function.start:x} ({il.instr_index}/{len(list(mmlil.instructions))})"

                while True:
                    log_debug(f"analyzing {il.instr_index}[{il.address:08x}]: {il}")

                    # self.function.analysis_skipped = True
                    self.view.begin_undo_actions()
                    self.seen[il.address] = self.seen.get(il.address, 0) + 1
                    process_result = self.visit(il)
                    self.view.commit_undo_actions()
                    # self.function.analysis_skipped = False

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
                        break

                log_debug(f"analysis for {il.address:x} finished")

                # If process_result is True or False, then something
                # was modified and we should update.
                if process_result is not None:
                    log_debug("waiting for analysis to finish")
                    self.view.update_analysis_and_wait()
                    log_debug("analysis complete")

                # If an analysis forces a phase change, note it
                if self.phase != self.prev_phase:
                    self.end_time = time.time()
                    log_info(
                        f"Phase changed from {self.prev_phase} to {self.phase}; Time elapsed: {self.end_time - self.start_time}"
                    )
                    self.prev_phase = self.phase
                    self.start_time = time.time()

            log_debug("target queue is empty")
            self.end_time = time.time()

            log_info(
                f"Phase {self.phase} complete; Time elapsed: {self.end_time - self.start_time}"
            )

            # Iterate the phase. If it hits 0, it will stop
            self.prev_phase = self.phase
            self.phase = (self.phase + 1) % (self.num_phases + 1)

            for func in self.view.functions:
                self.target_queue.put(func.start)

        log_info(f"Analysis complete; Time elapsed: {time.time() - self.run_time}")

    visit_MLIL_RET = analyze_return
    visit_MLIL_RET_HINT = analyze_return

    def visit_MLIL_JUMP(self, expr):
        result = self.visit(expr.dest.llil)

        if result is True:
            return result

        return self.analyze_indirect_jump(expr)

    def visit_MLIL_JUMP_TO(self, expr):
        if self.analyze_possible_call(expr):
            return True

        return self.visit(expr.dest.llil)

    visit_MLIL_GOTO = analyze_goto_folding

    visit_MLIL_STORE = analyze_exception_handler_store

    def visit_MLIL_SET_VAR(self, expr):
        if self.phase == 1:
            return self.analyze_exception_handler_set_var(expr)

        elif self.phase > 1:
            llil_instr = expr.llil
            if llil_instr.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
                if not expr.function.llil.get_ssa_reg_uses(llil_instr.dest):
                    self.convert_to_nop(expr.address)
                    return self.queue_prev_block(expr)

        return self.visit(expr.src)

    def visit_LLIL_REG_SSA(self, expr):
        log_debug("visit_LLIL_REG_SSA")

        if expr.value.type in (
            RegisterValueType.ConstantPointerValue,
            RegisterValueType.ConstantValue,
        ):
            return self.analyze_constant_folding(expr)

    def visit_MLIL_SET_VAR_FIELD(self, expr):
        return self.visit(expr.src)

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

    def visit_LLIL_LOAD_SSA(self, expr):
        return self.visit(expr.src)

    def visit_LLIL_ADD(self, expr):
        log_debug("visit_LLIL_ADD")
        add_value = expr.value
        if add_value.type in (
            RegisterValueType.ConstantPointerValue,
            RegisterValueType.ConstantValue,
        ):
            log_debug(f"add value is {add_value.value:x}")
            return self.analyze_constant_folding(expr.left)
        else:
            log_debug(f"add value is not constant ptr")

        return

    def visit_LLIL_SUB(self, expr):
        log_debug("visit_LLIL_SUB")
        sub_value = expr.value
        if sub_value.type in (
            RegisterValueType.ConstantPointerValue,
            RegisterValueType.ConstantValue,
        ):
            log_debug(f"sub value is {sub_value.value:x}")
            return self.analyze_constant_folding(expr.left)
        else:
            log_debug(f"sub value is not constant ptr")

        return

    def visit_MLIL_SUB(self, expr):
        log_debug("visit_MLIL_SUB")

        # This is a top level MLIL_SUB, which means it's probably a cmp instruction
        if expr.function[expr.instr_index].operation == MediumLevelILOperation.MLIL_SUB:
            return

        if expr.left.value.type in (
            RegisterValueType.UndeterminedValue,
            RegisterValueType.EntryValue,
        ):
            # Make sure we're not accidentally NOPing a push/pop
            # due to the stack being in a bad state due to a weird
            # loop
            if (expr.left.operation != MediumLevelILOperation.MLIL_VAR and 
                    expr.left.src.index != self.view.arch.get_reg_index('esp')):
                self.convert_to_nop(expr.address)
                return self.queue_prev_block(expr)

        # The rest is only for phase 2+
        # if self.phase == 1:
        #     return

        sub_value = expr.value
        if sub_value.type in (
            RegisterValueType.ConstantPointerValue,
            RegisterValueType.ConstantValue,
        ):
            log_debug(f"sub value is {sub_value.value:x}")
            return self.analyze_constant_folding(expr.left)
        else:
            log_debug("sub value is not a constant ptr")

        return

    def visit_MLIL_ADD(self, expr):
        log_debug("visit_MLIL_ADD")

        if expr.left.value.type in (
            RegisterValueType.UndeterminedValue,
            RegisterValueType.EntryValue,
        ):
            self.convert_to_nop(expr.address)

            return self.queue_prev_block(expr)

        add_value = expr.value
        if add_value.type in (
            RegisterValueType.ConstantPointerValue,
            RegisterValueType.ConstantValue,
        ):
            log_debug(f"add value is {add_value.value:x}")
            return self.analyze_constant_folding(expr.left)
        else:
            log_debug("add value is not a constant ptr")

        return

    def visit_MLIL_CONST(self, expr):
        log_debug("visit_MLIL_CONST")

        # if self.phase == 1:
        #     return

        if expr.llil.operation != LowLevelILOperation.LLIL_CONST:
            return self.visit(expr.llil)

    def visit_MLIL_XOR(self, expr):
        log_debug("visit_MLIL_XOR")

        # If it's something like `ecx ^ const` and ecx isn't a known
        # value, then just erase it. It's not needed at all.
        if expr.left.value.type in (
            RegisterValueType.UndeterminedValue,
            RegisterValueType.EntryValue,
        ):
            self.convert_to_nop(expr.address)

            return self.queue_prev_block(expr)

    visit_MLIL_AND = visit_MLIL_XOR

    def visit_MLIL_TAILCALL(self, expr):
        log_debug("visit_MLIL_TAIL_CALL")
        # TODO: implement something to recover control flow
        # for tail calls
        return self.visit(expr.dest.llil)

    visit_MLIL_TAILCALL_UNTYPED = visit_MLIL_TAILCALL

    analyze_unconditional_jump = analyze_unconditional_jump
    analyze_indirect_jump = analyze_indirect_jump
    analyze_unwind = analyze_unwind
    analyze_goto_folding = analyze_goto_folding
    analyze_constant_folding = analyze_constant_folding
    analyze_possible_call = analyze_possible_call
    analyze_exception_handler_set_var = analyze_exception_handler_set_var

    def convert_to_nop(self, address):
        log_debug(f"Nopping {address:x}")
        self.view.convert_to_nop(address)

    def queue_prev_block(self, expr):
        log_debug("queue_prev_block")
        if isinstance(expr, MediumLevelILInstruction):
            ILBasicBlock = MediumLevelILBasicBlock

        elif isinstance(expr, LowLevelILInstruction):
            ILBasicBlock = LowLevelILBasicBlock

        current_bb: ILBasicBlock = next(
            bb
            for bb in expr.function.basic_blocks
            if bb.start <= expr.instr_index < bb.end
        )

        log_debug(f"current_bb has {len(current_bb.incoming_edges)} incoming edges")

        if len(current_bb.incoming_edges) != 1:
            log_debug("Incoming Edges was not 1, just continuing")
            self.target_queue.put(expr.address)
            return True

        prev_bb = current_bb.incoming_edges[0].source

        while prev_bb[0].operation in (LowLevelILOperation.LLIL_JUMP_TO, MediumLevelILOperation.MLIL_JUMP_TO, MediumLevelILOperation.MLIL_GOTO, LowLevelILOperation.LLIL_GOTO):
            if len(prev_bb.incoming_edges) != 1:
                log_debug("Incoming edges was not 1, stopping here")
                break
            
            log_debug(f"{prev_bb.incoming_edges}")
            if prev_bb not in prev_bb.incoming_edges[0].source.dominators:
                prev_bb = prev_bb.incoming_edges[0].source
            else:
                break

        self.target_queue.put(prev_bb.il_function[prev_bb.start].address)
        return True