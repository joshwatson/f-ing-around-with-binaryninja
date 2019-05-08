from binaryninja import log_debug

old_log_debug = log_debug


def new_log_debug(msg):
    old_log_debug(f"[UNLOCK] {msg}")


log_debug = new_log_debug