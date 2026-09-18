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

private:
    SalKind classify(std::string_view name) {
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

    void skip_ws(std::string_view src, size_t& pos) {
        while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r' || src[pos] == '\n'))
            ++pos;
    }
};

} // namespace wv
