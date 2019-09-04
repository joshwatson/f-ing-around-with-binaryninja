from binaryninja import (BinaryView, LowLevelILFunction, PluginCommand,
                         SegmentFlag)
from emulator import Executor


def setup_stack(view: BinaryView, function: LowLevelILFunction) -> None:
    emulator = view.session_data['emulator']
    memory_view = view.session_data['emulator.memory.view']

    map_start = 0x1000
    map_len = 0x10000

    while True:
        while memory_view.get_segment_at(map_start) is not None:
            map_start += 0x1000

        if any(
            s.start > map_start and
            s.start < map_start + map_len
            for s in memory_view.segments
        ):
            map_start += 0x1000
            continue

        emulator.map_memory(
            map_start,
            map_len,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
        )
        break

    sp = map_start + map_len - view.address_size
    emulator.write_register(view.arch.stack_pointer, sp)


PluginCommand.register_for_low_level_il_function(
    'Emulator\\Setup stack',
    'Setup Emulator Stack',
    setup_stack,
    lambda v, f: v.session_data.get('emulator') is not None
)
