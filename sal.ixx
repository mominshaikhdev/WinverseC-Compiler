// sal.ixx - SAL (Source-code Annotation Language) parser
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
// Extracts _In_, _Out_, _Inout_, _In_opt_, _Out_writes_(n), etc.
module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

export module winversec.sal;
import winversec.types;

export namespace wv {

// SAL annotation kinds
enum class SalKind : uint8_t {
    None,
    In,             // _In_
    Out,            // _Out_
    InOut,          // _Inout_
    InOpt,          // _In_opt_
    OutOpt,         // _Out_opt_
    InOutOpt,       // _Inout_opt_
    InReads,        // _In_reads_(n)
    OutWrites,      // _Out_writes_(n)
    InOutUpdates,   // _Inout_updates_(n)
    InReadsZ,       // _In_reads_z_(n)
    OutWritesZ,     // _Out_writes_z_(n)
    InOutUpdatesZ,  // _Inout_updates_z_(n)
    OutWritesTo,    // _Out_writes_to_(n, r)
    OutWritesBytes, // _Out_writes_bytes_(n)
    InReadsBytes,   // _In_reads_bytes_(n)
    InOutUpdatesBytes, // _Inout_updates_bytes_(n)
    RetMaybenull,   // _Ret_maybenull_
    Success,        // _Success_(expr)
    PostWritableByteSize, // _Post_writable_byte_size_(n)
    CheckReturn,    // _Check_return_
    MustInspect,    // _Must_inspect_result_
    Federated,      // _Federated_
    Field,          // _Field_range_(a, b)
    FieldSize,      // _Field_size_(n)
    FieldSizeConst, // _Field_size_const_(n)
    TypeDot,        // _Type_dot_(...)
    At,             // _At_(spec)
    When,           // _When_(expr, ann)
    OnFailure,      // _On_failure_(ann)
    Carve,          // _Carve_bytes_(n)
    Notnull,        // _Notnull_
    NullTerminated, // _Null_terminated_
    Nullable,       // _Nullable_
    NotNull,        // _Notnull_ (non-nullable)
    FunctionClass,  // _Function_class_(X) — semantic class of a callback
    DriverAnno,     // __drv_* (WDK driver-model annotation: __drv_allocatesMem,
                    //   __drv_holdsMut, __drv_maxIRQL, ...). Unclassified these
                    //   derailed `typedef ... __drv_allocatesMem(Mem) PVOID
                    //   NAME(...)`: the peek strips ONE underscore, so the
                    //   scanned name is `_drv_allocatesMem`; classify returned
                    //   None, parse_all stopped, and read_type ate the token
                    //   as the return type — the statement was dropped and
                    //   every consumer of NAME* failed C2039 (Ntddk
                    //   RTL_AVL_ALLOCATE_ROUTINE, ...).
    Irql,           // _IRQL_requires_/_IRQL_requires_max_/_IRQL_requires_same_
                    //   WDK IRQL contract. Unclassified these derailed
                    //   `typedef _Function_class_(X) _IRQL_requires_*(LVL) RET
                    //   NAME(...)`: parse_all stopped at the IRQL token and
                    //   read_type ate it as the return type, so the callback
                    //   fell to the function parser instead of the delegate
                    //   branch (EVT_*/PRM_* emitted as extern "C" fn, then
                    //   C2039 in every struct field typed `NAME*`).
};

// Semantic class of a function-pointer typedef, from _Function_class_(X).
// The SDK uses it to label WDK dispatch routines: the real IRP major-function
// code lives in the annotation argument (e.g. _Function_class_(IRP_MJ_CREATE)),
// never in an enum member — which is why name heuristics saw only the handful
// of dispatch routines with "Dispatch" in the name.
struct FunctionClassInfo {
    std::string raw;      // full argument text, e.g. "IRP_MJ_DEVICE_CONTROL"
    std::string category; // leading identifier, e.g. "IRP_MJ"
    uint32_t code = 0;    // parsed numeric code when the argument is numeric
    bool has_code = false;
};

// Parsed SAL annotation
struct SalAnnotation {
    SalKind kind = SalKind::None;
    std::string param_name;     // Which parameter this applies to
    std::string count_expr;     // Size expression (e.g. "nSize", "*pcbResult")
    std::string condition;      // For _Success_(expr)
    bool is_byte_count = false; // For _writes_bytes_ variants
    bool is_wide = true;        // Unicode vs ANSI
};

// Buffer semantics extracted from SAL
struct BufferSemantics {
    uint32_t param_index = 0;
    enum class Kind {
        None, Input, Output, InOut, InputString, OutputString, InOutString,
        FixedLength, VariableLength, Optional,
    } kind = Kind::None;
    std::string count_param;
    std::string count_expression;
    uint32_t constant_count = 0;
    bool is_byte_count = false;
    bool is_wide_string = true;
};

class SalParser {
public:
    // Parse a SAL annotation at the current position
    // Returns the annotation and advances pos past it
    SalAnnotation parse(std::string_view src, size_t& pos) {
        SalAnnotation ann;
        skip_ws(src, pos);

        if (pos >= src.size() || src[pos] != '_')
            return ann;

        // Read the annotation name
        auto start = pos;
        ++pos; // skip leading _
        while (pos < src.size() && (std::isalnum(src[pos]) || src[pos] == '_'))
            ++pos;
        auto name = src.substr(start + 1, pos - start - 1);

        // Skip whitespace
        skip_ws(src, pos);

        // Determine kind from name
        ann.kind = classify(name);

        // Parse parenthesized arguments if present
        if (pos < src.size() && src[pos] == '(') {
            ++pos;
            auto args = read_balanced(src, pos);
            assign_args(ann, args);
        }

        return ann;
    }

    // Parse all SAL annotations before a parameter declaration
    std::vector<SalAnnotation> parse_all(std::string_view src, size_t& pos) {
        std::vector<SalAnnotation> result;
        while (pos < src.size()) {
            skip_ws(src, pos);
            if (pos >= src.size() || src[pos] != '_')
                break;
            // Check if it's a SAL annotation
            auto peek = pos;
            ++peek;
            while (peek < src.size() && (std::isalnum(src[peek]) || src[peek] == '_'))
                ++peek;
            auto name = src.substr(pos + 1, peek - pos - 1);
            if (classify(name) == SalKind::None)
                break;
            result.push_back(parse(src, pos));
        }
        return result;
    }

    // Extract BufferSemantics from a set of SAL annotations
    BufferSemantics extract_buffer_semantics(const std::vector<SalAnnotation>& annotations, uint32_t param_index) {
        BufferSemantics bs;
        bs.param_index = param_index;

        for (auto& ann : annotations) {
            switch (ann.kind) {
                case SalKind::In:
                    bs.kind = BufferSemantics::Kind::Input;
                    break;
                case SalKind::Out:
                    bs.kind = BufferSemantics::Kind::Output;
                    bs.count_expression = ann.count_expr;
                    break;
                case SalKind::InOut:
                    bs.kind = BufferSemantics::Kind::InOut;
                    bs.count_expression = ann.count_expr;
                    break;
                case SalKind::InOpt:
                    bs.kind = BufferSemantics::Kind::Optional;
                    break;
                case SalKind::OutOpt:
                    bs.kind = BufferSemantics::Kind::Optional;
                    bs.count_expression = ann.count_expr;
                    break;
                case SalKind::InReads:
                case SalKind::InReadsBytes:
                    bs.kind = BufferSemantics::Kind::Input;
                    bs.count_expression = ann.count_expr;
                    bs.is_byte_count = ann.is_byte_count;
                    break;
                case SalKind::OutWrites:
                case SalKind::OutWritesBytes:
                    bs.kind = BufferSemantics::Kind::Output;
                    bs.count_expression = ann.count_expr;
                    bs.is_byte_count = ann.is_byte_count;
                    break;
                case SalKind::InOutUpdates:
                case SalKind::InOutUpdatesBytes:
                    bs.kind = BufferSemantics::Kind::InOut;
                    bs.count_expression = ann.count_expr;
                    bs.is_byte_count = ann.is_byte_count;
                    break;
                case SalKind::InReadsZ:
                    bs.kind = BufferSemantics::Kind::InputString;
                    bs.count_expression = ann.count_expr;
                    bs.is_wide_string = ann.is_wide;
                    break;
                case SalKind::OutWritesZ:
                    bs.kind = BufferSemantics::Kind::OutputString;
                    bs.count_expression = ann.count_expr;
                    bs.is_wide_string = ann.is_wide;
                    break;
                case SalKind::InOutUpdatesZ:
                    bs.kind = BufferSemantics::Kind::InOutString;
                    bs.count_expression = ann.count_expr;
                    bs.is_wide_string = ann.is_wide;
                    break;
                default:
                    break;
            }
        }
        return bs;
    }

public:
    // True when the identifier (without its leading underscore) is a SAL
    // annotation the parser understands. Used by the declaration-specifier
    // skipper to leave SAL tokens in place for parse_all.
    static bool is_sal_annotation(std::string_view name) {
        return classify(name) != SalKind::None;
    }

private:
    static SalKind classify(std::string_view name) {
        // SDK spellings carry a trailing underscore (_In_, _Out_opt_,
        // _Check_return_): the scanned ident is "In_", "Out_opt_", ...
        // Normalize once so every exact-match below sees the bare stem.
        if (!name.empty() && name.back() == '_') name.remove_suffix(1);
        if (name == "In")                    return SalKind::In;
        if (name == "Out")                   return SalKind::Out;
        if (name == "Inout")                 return SalKind::InOut;
        if (name == "In_opt")                return SalKind::InOpt;
        if (name == "Out_opt")               return SalKind::OutOpt;
        if (name == "Inout_opt")             return SalKind::InOutOpt;
        if (name == "In_reads" || name == "In_reads_" || name.starts_with("In_reads_"))
            return SalKind::InReads;
        if (name == "Out_writes" || name == "Out_writes_" || name.starts_with("Out_writes_"))
            return SalKind::OutWrites;
        if (name == "Inout_updates" || name.starts_with("Inout_updates_"))
            return SalKind::InOutUpdates;
        if (name == "In_reads_z" || name.starts_with("In_reads_z"))
            return SalKind::InReadsZ;
        if (name == "Out_writes_z" || name.starts_with("Out_writes_z"))
            return SalKind::OutWritesZ;
        if (name == "Inout_updates_z" || name.starts_with("Inout_updates_z"))
            return SalKind::InOutUpdatesZ;
        if (name.starts_with("Out_writes_to"))
            return SalKind::OutWritesTo;
        if (name.starts_with("Out_writes_bytes"))
            return SalKind::OutWritesBytes;
        if (name.starts_with("In_reads_bytes"))
            return SalKind::InReadsBytes;
        if (name.starts_with("Inout_updates_bytes"))
            return SalKind::InOutUpdatesBytes;
        if (name == "Ret_maybenull")         return SalKind::RetMaybenull;
        if (name == "Success")               return SalKind::Success;
        if (name.starts_with("Post_writable_byte_size"))
            return SalKind::PostWritableByteSize;
        if (name == "Check_return")          return SalKind::CheckReturn;
        if (name == "Must_inspect_result")   return SalKind::MustInspect;
        if (name == "Null_terminated")       return SalKind::NullTerminated;
        if (name == "Nullable")              return SalKind::Nullable;
        if (name == "Notnull")               return SalKind::NotNull;
        if (name.starts_with("Field_size"))  return SalKind::FieldSize;
        if (name.starts_with("Field_range")) return SalKind::Field;
        if (name.starts_with("On_failure"))  return SalKind::OnFailure;
        if (name.starts_with("When"))        return SalKind::When;
        if (name.starts_with("Function_class")) return SalKind::FunctionClass;
        // WDK driver-model annotations: the scanned name keeps one leading
        // underscore (`__drv_allocatesMem` -> `_drv_allocatesMem`).
        if (name.starts_with("_drv") || name.starts_with("drv_")) return SalKind::DriverAnno;
        // Legacy (pre-SAL2) annotations keep one leading underscore too
        // (`__in_opt` -> `_in_opt`). Without these, parse_all stops at the
        // annotation and read_type eats it as the parameter type - the
        // signature then derails and the row absorbs garbage params
        // (newdev.h DiShowUpdateDriver).
        if (name.starts_with("_deref_"))                return SalKind::InOut;
        if (name.starts_with("_inout"))                 return SalKind::InOut;
        if (name == "_in" || name.starts_with("_in_"))  return SalKind::In;
        if (name == "_out" || name.starts_with("_out_")) return SalKind::Out;
        // SAL2 side annotations _Post_* / _Pre_* (handleapi.h declares
        // `CloseHandle(_In_ _Post_ptr_invalid_ HANDLE hObject)`): the peek
        // strips one leading underscore, so classify sees `Post_ptr_invalid`.
        // Unclassified, the parse derailed exactly like legacy SAL: read_type
        // ate the token as the parameter type and the signature gained a
        // phantom second param (CloseHandle emitted with 2 args -> C2660 in
        // winrt_base). Federated is an inert marker kind: skipped like any
        // other annotation, no buffer semantics attached.
        if (name.starts_with("Post_") || name.starts_with("Pre_"))
            return SalKind::Federated;
        // _Return_type_success_(expr) / _Return_type_failure_(expr): winnt.h
        // declares `typedef _Return_type_success_(return >= 0) long HRESULT;`
        // — the annotation sits BETWEEN `typedef` and the type. Unclassified,
        // parse_all stopped, read_type read _Return_type_success_ as the TYPE
        // name, `long` hit the C++ keyword guard, and the entire typedef was
        // DROPPED — no HRESULT alias row, no AliasTarget, so every projection
        // emitted `using HRESULT = void*;` instead of std::int32_t. Federated
        // (inert marker) is correct: no buffer semantics, just skipped.
        if (name.starts_with("Return_type_success") || name.starts_with("Return_type_failure"))
            return SalKind::Federated;
        if (name.starts_with("IRQL_"))         return SalKind::Irql;
        return SalKind::None;
    }

    void assign_args(SalAnnotation& ann, std::string_view args) {
        if (ann.kind == SalKind::Success) {
            ann.condition = std::string(args);
            return;
        }
        // For _In_reads_(n), _Out_writes_(n), etc. — first arg is count
        ann.count_expr = std::string(args);
        // Check for _bytes_ suffix in count expression
        if (ann.kind == SalKind::OutWritesBytes || ann.kind == SalKind::InReadsBytes ||
            ann.kind == SalKind::InOutUpdatesBytes) {
            ann.is_byte_count = true;
        }
    }

    std::string_view read_balanced(std::string_view src, size_t& pos) {
        size_t start = pos;
        int depth = 1;
        while (pos < src.size() && depth > 0) {
            if (src[pos] == '(') ++depth;
            else if (src[pos] == ')') --depth;
            if (depth > 0) ++pos;
        }
        auto result = src.substr(start, pos - start);
        if (pos < src.size()) ++pos; // skip closing )
        return result;
    }

    // Whitespace AND comments: annotations are newline-separated and the
    // SDK freely interleaves trailing explanations —
    //     _IRQL_requires_(HIGH_LEVEL) // HIGH_LEVEL is best approximation of DIRQL
    //     _IRQL_requires_same_
    // A bare whitespace skip stopped at the `/`, parse_all bailed with the
    // remaining annotations (and the return type) unparsed, and the whole
    // typedef was dropped (wdm.h KSERVICE_ROUTINE missing from the winmd ->
    // every consumer failed C2039).
    void skip_ws(std::string_view src, size_t& pos) {
        while (pos < src.size()) {
            char c = src[pos];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos;
            }
            else if (c == '/' && pos + 1 < src.size() && src[pos + 1] == '/') {
                while (pos < src.size() && src[pos] != '\n') ++pos;
            }
            else if (c == '/' && pos + 1 < src.size() && src[pos + 1] == '*') {
                pos += 2;
                while (pos + 1 < src.size() && !(src[pos] == '*' && src[pos + 1] == '/')) ++pos;
                pos = (pos + 1 < src.size()) ? pos + 2 : src.size();
            }
            else {
                break;
            }
        }
    }
};

} // namespace wv
