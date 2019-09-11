from binaryninjaui import UIContext
from binaryninja import ChoiceField, get_form_input, HighlightStandardColor


def add_hook(emulator, instruction):
    ctx = UIContext.activeContext()
    handler = ctx.globalActions()
    hook_options = [
        a
        for a in handler.getAllValidActions()
        if "Snippets\\" in a and "emulator" in a.lower()
    ]
    snippets = ChoiceField("Snippets:", hook_options)

    get_form_input([snippets], "Add Hook")

    choice = hook_options[snippets.result]

    emulator.add_hook(instruction, choice)

    instruction.function.source_function.set_auto_instr_highlight(
        instruction.address, HighlightStandardColor.BlackHighlightColor
    )


def add_function_hook(emulator, function):
    ctx = UIContext.activeContext()
    handler = ctx.globalActions()
    hook_options = [
        a
        for a in handler.getAllValidActions()
        if "Snippets\\" in a and "emulator" in a.lower()
    ]
    snippets = ChoiceField("Snippets:", hook_options)

    get_form_input([snippets], "Add Function Hook")

    choice = hook_options[snippets.result]

    # TODO


def remove_hook(emulator, instruction):
    emulator.remove_hook(instruction)
    instruction.function.source_function.set_auto_instr_highlight(
        instruction.address, HighlightStandardColor.NoHighlightColor
    )


def remove_function_hook(emulator, function):
    # TODO
    pass
