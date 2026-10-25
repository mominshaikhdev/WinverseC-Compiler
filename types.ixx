// types.ixx - Core type definitions for Winverse Compiler
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
// Zero dependencies — every other module imports this
module;

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <variant>
#include <optional>
#include <set>
#include <unordered_map>
#include <span>
#include <atomic>

export module winversec.types;

export namespace wv {

// ECMA-335 Element Types
enum class ET : uint8_t {
    Void=0x01, Bool=0x02, Char=0x03,
    I1=0x04, U1=0x05, I2=0x06, U2=0x07,
    I4=0x08, U4=0x09, I8=0x0A, U8=0x0B,
    R4=0x0C, R8=0x0D, String=0x0E,
    Ptr=0x0F, ByRef=0x10, ValType=0x11, Class=0x12,
    Var=0x13, Array=0x14, GenInst=0x15,
    FnPtr=0x1B, SzArray=0x1D, MVar=0x1E,
    CModReqd=0x1F, CModOpt=0x20, End=0x00,
};

// Type Kinds
enum class Kind : uint8_t {
    Iface, Class, Enum, Struct, Union, Delegate,
    Attr, FnPtr, Const, Func,
};

// Calling Conventions
enum class CC : uint8_t {
    Def=0, Cdecl=1, Std=2, This=3, Fast=4, Vararg=5,
    Gen=0x10, HasThis=0x20, ExplThis=0x40,
};

// Type Attributes (ECMA-335 II.23.1.16)
enum class TA : uint32_t {
    NotPub=0, Pub=1, NestPub=2, NestPriv=3,
    NestFam=4, NestAsm=5,
    Cls=0, Abstract=0x80, Sealed=0x100,
    SpecName=0x400, WinRT=0x200,
    BefInit=0x100000, RTSpec=0x800,
};

// Method Attributes (ECMA-335 II.23.1.10)
enum class MA : uint16_t {
    Priv=1, Asm=3, Fam=4, Pub=6,
    Static=0x10, Final=0x20, Virtual=0x40,
    Hide=0x80, NewSlot=0x100, Abstract=0x400,
    SpecName=0x800, PInvoke=0x1000, RTSpec=0x4000,
};

// Field Attributes (ECMA-335 II.23.1.5)
enum class FA : uint16_t {
    Priv=1, Asm=3, Fam=4, Pub=6,
    Static=0x10, InitOnly=0x20, Literal=0x40,
    SpecName=0x200, PInvoke=0x2000,
    HasRVA=0x100, HasDef=0x8000, HasMarshal=0x1000,
};

// Parameter Attributes (ECMA-335 II.23.1.13)
enum class PA : uint16_t {
    In=1, Out=2, Opt=0x10, HasDef=0x1000,
};

// Architecture Flags (bitmask — Winverse extension, not in ECMA-335)
enum class Ar : uint32_t {
    None=0, X86=1, X64=2, Arm=4, Arm64=8, All=15,
};
constexpr Ar operator|(Ar a, Ar b) { return Ar(uint32_t(a) | uint32_t(b)); }
constexpr Ar operator&(Ar a, Ar b) { return Ar(uint32_t(a) & uint32_t(b)); }
constexpr bool has(Ar v, Ar f) { return (uint32_t(v) & uint32_t(f)) != 0; }

constexpr FA operator|(FA a, FA b) { return FA(uint16_t(a) | uint16_t(b)); }
constexpr TA operator|(TA a, TA b) { return TA(uint32_t(a) | uint32_t(b)); }
constexpr MA operator|(MA a, MA b) { return MA(uint16_t(a) | uint16_t(b)); }

// Constant Value
struct CVal {
    ET type = ET::Void;
    std::variant<std::monostate, bool, uint8_t, int8_t, uint16_t, int16_t,
        uint32_t, int32_t, uint64_t, int64_t, float, double, std::u16string> v;
    bool empty() const { return std::holds_alternative<std::monostate>(v); }
};

// Type Reference
struct TRef {
    std::string ns, name;
    std::vector<TRef> gen{};
    bool arr = false, byref = false, fnptr = false;
    uint32_t ptr = 0;
    // Element type when the reference is a fundamental (i2/u4/r4...).
    // Void/Ptr/Class mean "not a fundamental" — the consumer falls back to
    // the named-type encoding. Carried so method-parameter signatures keep
    // their real primitive type instead of collapsing to System.Object.
    ET elem = ET::Void;
    // C `const` qualifier on the pointee (`const wchar_t*`, `LPCWSTR` via
    // `typedef const wchar_t*`). Encoded as a Const CModReqd modifier on the
    // pointee so downstream projections can emit `wchar_t const*`.
    bool pt_const = false;
};

// Parameter-level SAL flags beyond buffer semantics (bits)
enum SALF : uint32_t {
    SF_CHECK_RETURN = 1u << 0,  // _Check_return_ / _Must_inspect_result_
    SF_NULL_TERM    = 1u << 1,  // _Null_terminated_
    SF_NOT_NULL     = 1u << 2,  // _Notnull_
    SF_MAYBE_NULL   = 1u << 3,  // _Nullable_ / _Ret_maybenull_
    SF_SUCCESS      = 1u << 4,  // _Success_(expr)
};

// Function-level declaration flags (TDef::fn_flags bits)
enum FNF : uint32_t {
    FNF_INLINE       = 1u << 0, // inline / __inline / FORCEINLINE
    FNF_FORCEINLINE  = 1u << 1, // __forceinline
    FNF_DEPRECATED   = 1u << 2, // __declspec(deprecated) / DEPRECATED
    FNF_RET_MAYBENULL= 1u << 3, // _Ret_maybenull_ on the return value
    FNF_MUST_CHECK   = 1u << 4, // _Must_inspect_result_ / _Check_return_ on the return
};

// Parameter Definition
struct PDef {
    std::string name;
    uint16_t seq = 0;
    PA attr{};
    CVal def{};
    uint32_t sal_buffer_info = 0;
    std::string sal_count_param;
    std::string sal_count_expression;
    uint32_t sal_flags = 0; // SALF bits
};

// Method Signature
struct MSig {
    CC cc = CC::Def;
    bool has_this = false;
    uint32_t gen_n = 0;
    ET ret = ET::Void;
    TRef ret_r{};
    // Method name — set for interface methods (COM vtable order);
    // unnamed for plain C function items whose name lives on the TDef.
    std::string name;
    std::vector<TRef> pt{};
    std::vector<PDef> params{};
};

// Field Definition
struct FDef {
    std::string name;
    FA attr{};
    ET type = ET::Void;
    TRef ref{};
    uint32_t sz = 0, off = 0;
    // Fixed array element count for `T name[N];` fields (0 = scalar).
    // Captured at parse; encoded as ELEMENT_TYPE_ARRAY + ArrayShape in the
    // FieldSig so downstream projections can emit `T name[N];` verbatim.
    uint32_t arr_n = 0;
    CVal def{};
};

// Interface Implementation
struct II { std::string ns, name; };

// Architecture-specific sizes
struct ArchSizes {
    uint32_t x86 = 0, x64 = 0, arm64 = 0;
};

// Custom Attribute Value
struct AttrVal {
    enum class Kind { Bool, Int, UInt, String, TypeRef, Enum, Blob };
    Kind kind = Kind::Bool;
    bool bool_val = false;
    int64_t int_val = 0;
    uint64_t uint_val = 0;
    std::string str_val;
    TRef type_val;
    std::vector<uint8_t> blob_val;

    AttrVal() = default;
    AttrVal(Kind k, bool v) : kind(k), bool_val(v) {}
    AttrVal(Kind k, int64_t v) : kind(k), int_val(v) {}
    AttrVal(Kind k, uint64_t v) : kind(k), uint_val(v) {}
    AttrVal(Kind k, const std::string& v) : kind(k), str_val(v) {}
    AttrVal(Kind k, const char* v) : kind(k), str_val(v) {}
};

// Named argument for custom attributes
struct AttrArg {
    std::string name;
    AttrVal value;
    AttrArg() = default;
    AttrArg(const std::string& n, const AttrVal& v) : name(n), value(v) {}
};

// Custom Attribute
struct Attribute {
    std::string ns;
    std::string name;
    std::vector<AttrArg> args{};
    std::vector<AttrVal> positional{};
};

// Type Definition — the central data structure
struct TDef {
    Kind kind = Kind::Class;
    std::string ns, name;
    TA attr{};
    std::string ext_ns, ext_name;
    std::vector<II> ifaces{};
    std::vector<FDef> fields{};
    std::vector<MSig> meths{};
    uint32_t cls_sz = 0;
    uint16_t pack = 0;
    bool winrt = false, is_apis = false;
    std::string source_header;
    std::vector<Attribute> attributes{};
    ArchSizes arch_sizes{};
    bool is_union = false;
    bool is_callback = false;
    bool is_com_interface = false;
    bool is_enum_flags = false;
    std::string com_iid;
    std::string import_library;
    std::string entry_point;
    // Underlying type for simple typedefs (typedef short SQLSMALLINT,
    // typedef void* PSID, typedef GUID CLSID, typedef JET_UINT32 JET_COLTYP).
    // ET::Void + empty ref means "not a simple alias". The emit layer
    // resolves chains transitively and substitutes the fully-resolved shape
    // into every signature referencing the alias, keeping the winmd
    // self-describing for any downstream language projection without the
    // original headers (same approach as Windows.Win32.winmd).
    ET alias_elem = ET::Void;
    TRef alias_ref{};
    // Declaration-specifier flags captured by the parser (FNF bits):
    // inline/forceinline, __declspec(deprecated), _Ret_maybenull_.
    uint32_t fn_flags = 0;
    // Semantic class from _Function_class_(X) on a callback typedef
    // (DRIVER_DISPATCH, DRIVER_INITIALIZE, ...). The SDK's only dispatch
    // metadata — IRP slot codes are #defines, names carry no hint.
    std::string fn_class;
    // Deprecation message from DEPRECATED("reason") / __declspec(deprecated("reason")).
    std::string deprecation_msg;
};

// Pipeline Item
struct Item {
    TDef def;
    Ar arch = Ar::All;
    std::string hdr;
};

// Parse Error
struct ParseError {
    std::string file;
    uint32_t line = 0;
    std::string msg;
    enum class Severity { Warning, Error, Fatal };
    Severity sev = Severity::Error;
};

// Global Pipeline State
// An IOCTL constant from `#define IOCTL_X CTL_CODE(a,b,c,d)` — the C
// preprocessor never materializes function-like macro values as enum
// members, so the parser records evaluated CTL_CODE defines here and the
// enricher turns them into metadata rows (IoctlCode/IoctlBuffering attrs).
struct IoctlConst {
    std::string name;
    uint32_t value = 0;
};

// A general numeric `#define` constant (GENERIC_READ, KEY_READ, WM_DESTROY,
// WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, the predefined HKEY_* roots, ...) —
// evaluated by the parser and attributed to its defining header's
// namespace. The C preprocessor never materializes object-like macros as
// enum members, so without this capture every flag/constant family in the
// SDK is absent from the winmd and projection consumers must hardcode hex
// literals.
struct IntConst {
    std::string name;
    uint32_t value = 0;
    std::string ns;
    std::string header;
    // Raw #define value text. Evaluation is DEFERRED to enrichment: each
    // parsed header works on a copy of the seed preprocessor, so value
    // chains that cross headers ((KEY_READ | ... ) -> READ_CONTROL from
    // winnt.h) cannot resolve during the parse. The enricher evaluates
    // every entry against the merged define table instead.
    std::string value_text;
};

// Function-like #define (`#define NAME(a, b) body`). Recorded globally
// because the merged evaluation table is rebuilt in the enricher from
// st.int_consts alone: without this the macro name exists only in the
// per-file preprocessor copy that saw it, so any constant built through
// one (every E_* HRESULT goes via _HRESULT_TYPEDEF_) evaluated to nothing
// and was silently dropped from the winmd.
struct FuncMacro {
    std::string name;
    std::vector<std::string> params;
    std::string value_text;
};

struct State {
    std::vector<Item> items;
    std::vector<IoctlConst> ioctl_consts;
    // IRP major-function codes from `#define IRP_MJ_CREATE 0x00` — like
    // IOCTLs they never become enum members; the enricher materializes
    // them into enum rows carrying IrpMajorFunction attributes.
    std::vector<IoctlConst> irp_mj_consts;
    // General numeric #define constants — see IntConst above.
    std::vector<IntConst> int_consts;
    // Function-like #define macros — see FuncMacro above.
    std::vector<FuncMacro> func_macros;
    std::set<std::string> nss;
    std::string asm_name = "Windows.Win32";
    std::string asm_ver = "26100.0.0";
    std::string sdk_root;
    std::string sdk_version_dir; // e.g. "10.0.26100.0" or "11.0.100.0"
    // Extra include dirs (-include_dir, repeatable): scanned recursively for
    // headers the SDK does not already provide (e.g. the Windows App SDK
    // NuGet package's MddBootstrap.h). A header whose stem was already
    // collected from the SDK is skipped here, so an SDK >= 22000 that ships
    // its own dynamic-dependency headers never collides with the NuGet copy.
    std::vector<std::filesystem::path> extra_include_dirs;
    bool include_drivers = false;
    bool drivers_only = false;
    bool verbose = false;
    std::set<std::string> parsed_files;
    // Latest-version KMDF/UMDF header dirs (Include\wdf\{kmdf,umdf}\<ver>)
    // that parse_sdk actually scanned — recorded so the coverage report
    // counts them instead of silently omitting the WDF framework.
    std::vector<std::filesystem::path> wdf_dirs;
    std::unordered_map<std::string, std::vector<std::string>> includes;
    std::unordered_map<std::string, std::string> include_map;
    // -ns <header=Namespace> overrides: lowercased header stem -> explicit
    // namespace. Generic escape hatch so any C/C++ header (SDK, NuGet,
    // third-party, your own) can be bucketed into any namespace the caller
    // wants; consulted before the built-in stem table in map_ns().
    std::unordered_map<std::string, std::string> ns_overrides;
    // Scanned from NuGet import libs: exported function name -> "<dll>.dll".
    std::unordered_map<std::string, std::string> dll_imports;
    // Windows SDK import-lib scans (symbol -> lib FILE name, e.g.
    // "kernel32.lib"), populated at RUN time in main() from the SDK's own
    // lib trees. The curated dll_map_ table necessarily lags every new
    // Windows release; these maps are the data-driven fallback that gives
    // BRAND-NEW future SDK/WDK APIs a correct linkable attribution with no
    // winversec table edit or rebuild — mirroring the namespace fallback's
    // "new headers just work" behavior. sdk_lib_imports = um + ucrt (user
    // mode, consulted by the Win32 enricher); km_lib_imports = km (kernel
    // mode, consulted by the driver enricher after its curated name rules).
    std::unordered_map<std::string, std::string> sdk_lib_imports;
    std::unordered_map<std::string, std::string> km_lib_imports;
    // include dir -> namespace root for its flat-C headers (map_ns appends
    // the header stem; e.g. WASDK MRM.h -> Windows.Win32.AppSDK.MRM).
    std::unordered_map<std::string, std::string> extra_include_ns;
    std::vector<ParseError> errors;
    std::atomic<size_t> files_parsed_atomic{0};
    std::atomic<size_t> types_found_atomic{0};
    std::atomic<size_t> funcs_found_atomic{0};
};

} // namespace wv
