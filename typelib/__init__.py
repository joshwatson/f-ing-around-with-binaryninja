from binaryninja import (
    Architecture,
    FunctionParameter,
    Platform,
    QualifiedName,
    Type,
    TypeLibrary,
    Structure
)

advapi32_x86 = TypeLibrary.new(Architecture["x86"], "advapi32.dll")

advapi32_x86.add_platform(Platform["windows-x86"])

BOOL = Type.int(4, altname="BOOL")
HCRYPTPROV_type = Type.structure_type(Structure())
HCRYPTPROV = Type.named_type_from_type(
    "HCRYPTPROV", HCRYPTPROV_type
)

LPCSTR_type = Type.pointer(Architecture["x86"], Type.char())
LPCSTR = Type.named_type_from_type('LPCSTR', LPCSTR_type)

DWORD = Type.int(4, sign=False, altname="DWORD")

advapi32_x86.add_named_type("HCRYPTPROV", HCRYPTPROV_type)

CryptAcquireContextA = Type.function(
    BOOL,
    [
        FunctionParameter(
            Type.pointer(Architecture["x86"], HCRYPTPROV), "phProv"
        ),
        FunctionParameter(LPCSTR, "szContainer"),
        FunctionParameter(LPCSTR, "szProvider"),
        FunctionParameter(DWORD, "dwProvType"),
        FunctionParameter(DWORD, "dwFlags"),
    ],
    calling_convention=Platform['windows-x86'].stdcall_calling_convention
)

CryptReleaseContext = Type.function(
    BOOL,
    [
        FunctionParameter(
            HCRYPTPROV, 'hProv'
        ),
        FunctionParameter(
            DWORD, 'dwFlags'
        )
    ],
    calling_convention=Platform['windows-x86'].stdcall_calling_convention
)

advapi32_x86.add_named_object(
    QualifiedName(["CryptAcquireContextA"]), CryptAcquireContextA
)
advapi32_x86.add_named_object(
    QualifiedName(["CryptReleaseContext"]), CryptReleaseContext
)

advapi32_x86.finalize()
