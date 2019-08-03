from dataclasses import dataclass
from typing import Dict, Tuple

from binaryninja import BinaryView


@dataclass
class State:
    view: BinaryView
    regs: Dict[str, int]
    memory: Dict[Tuple[int, int], bytes]
