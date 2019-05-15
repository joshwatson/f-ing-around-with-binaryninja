__all__ = ["linear_mlil"]

try:
    from binaryninjaui import ViewType

    from .linear_mlil import LinearMLILViewType

    # ViewType.registerViewType(MlilLinearViewType())
    # Register the view type so that it can be chosen by the user
    ViewType.registerViewType(LinearMLILViewType())
except ImportError as e:
    print(f"Import Error {e}")
