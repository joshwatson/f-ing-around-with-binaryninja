from binaryninja import enum

class SEHState(enum.IntEnum):
    NoException = 0
    PushSeh = 1
    Seh = 2
    InException = 3
    Unwinding = 4
    LookingForPop = 5