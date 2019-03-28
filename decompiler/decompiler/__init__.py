__all__ = ['linear_mlil']

from . import mlil_ast

try:
    from binaryninjaui import ViewType

    from .mlil_linear import MlilLinearViewType
    from .linear_mlil import LinearMLILViewType

    # ViewType.registerViewType(MlilLinearViewType())
    # Register the view type so that it can be chosen by the user
    ViewType.registerViewType(LinearMLILViewType())
except ImportError as e:
    print(f"Import Error {e}")