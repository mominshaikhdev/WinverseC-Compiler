// emit.ixx - ECMA-335 .winmd PE writer
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
// Fixes: string-keyed blob dedup, cached sig offsets, valid #~ table stream, streaming file output
module;

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <variant>
#include <filesystem>
#include <chrono>
#include <iostream>

export module winversec.emit;
import winversec.types;

export namespace wv {

// ECMA-335 coded index tables (II.24.2.6)
inline const uint32_t k_hca_tables[] = {0x06,0x04,0x01,0x02,0x08,0x09,0x0A,0x00,0x0E,0x17,0x14,0x11,0x1A,0x1B,0x20,0x23,0x26,0x27,0x28,0x2A,0x2C,0x2B};
inline constexpr uint32_t k_hca_tag_bits = 5, k_hca_count = 22;

inline const uint32_t k_hc_tables[] = {0x04, 0x08, 0x17};
inline constexpr uint32_t k_hc_tag_bits = 2, k_hc_count = 3;

inline const uint32_t k_cat_tables[] = {0, 0, 0x06, 0x0A, 0};
inline constexpr uint32_t k_cat_tag_bits = 3, k_cat_count = 5;

inline const uint32_t k_mf_tables[] = {0x04, 0x06};
inline constexpr uint32_t k_mf_tag_bits = 1, k_mf_count = 2;

inline const uint32_t k_tdr_tables[] = {0x02, 0x01, 0x1B};
inline constexpr uint32_t k_tdr_tag_bits = 2, k_tdr_count = 3;

inline const uint32_t k_rs_tables[] = {0x00, 0x1A, 0x23, 0x01};
inline constexpr uint32_t k_rs_tag_bits = 2, k_rs_count = 4;

inline const uint32_t k_mrp_tables[] = {0x02, 0x01, 0x1A, 0x06, 0x1B};
inline constexpr uint32_t k_mrp_tag_bits = 3, k_mrp_count = 5;

class WinmdEmitter {
public:
    State& st;
    bool verbose = false;
    explicit WinmdEmitter(State& s, bool v = false) : st(s), verbose(v) {}

    struct EmitStats {
        size_t types_emitted = 0;
        size_t methods_emitted = 0;
        size_t fields_emitted = 0;
        size_t attrs_emitted = 0;
        size_t params_emitted = 0;
        size_t constants_emitted = 0;
        size_t implmap_emitted = 0;
        size_t typeref_emitted = 0;
    };
    EmitStats emit_stats;

    bool emit(const std::string& output_path) {
        auto t0 = std::chrono::steady_clock::now();

        build_name_ns();
        build_string_heap();
        auto t1 = std::chrono::steady_clock::now();
        if (verbose) std::cerr << "    string heap: " << string_heap_.size() << " bytes, "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count() << "ms\n";

        build_blob_heap();
        auto t2 = std::chrono::steady_clock::now();
        if (verbose) std::cerr << "    blob heap: " << blob_heap_.size() << " bytes, "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count() << "ms\n";

        build_guid_heap();

        build_type_table();
        build_method_and_field_tables();
        build_assembly_ref_table();
        build_custom_attribute_table();
        build_constant_table();
        build_impl_map_table();
        build_type_ref_table();
        auto t3 = std::chrono::steady_clock::now();
        if (verbose) std::cerr << "    tables: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3-t2).count() << "ms\n";

        build_pe_streaming(output_path);
        auto t4 = std::chrono::steady_clock::now();
        if (verbose) std::cerr << "    PE write: " << std::chrono::duration_cast<std::chrono::milliseconds>(t4-t3).count() << "ms\n";

        if (verbose) std::cerr << "  Types: " << emit_stats.types_emitted
                  << " Methods: " << emit_stats.methods_emitted
                  << " Fields: " << emit_stats.fields_emitted
                  << " Params: " << emit_stats.params_emitted
                  << " Attrs: " << emit_stats.attrs_emitted << "\n";
        return true;
    }

private:
    std::vector<uint8_t> string_heap_;
    std::unordered_map<std::string, uint32_t> string_map_;

    std::vector<uint8_t> blob_heap_;
    std::unordered_map<std::string, uint32_t> blob_map_;

    std::vector<uint8_t> guid_heap_;

    struct TypeDefRow { uint32_t flags; uint32_t name; uint32_t ns; uint32_t extends_tag; uint32_t extends_row; uint32_t field_list; uint32_t method_list; };
    struct MethodDefRow { uint32_t rva; uint16_t impl_flags; uint16_t flags; uint32_t name; uint32_t sig; uint32_t param_list; };
    struct FieldRow { uint16_t flags; uint32_t name; uint32_t sig; };
    struct ParamRow { uint16_t flags; uint16_t seq; uint32_t name; };
    struct TypeRefRow { uint32_t scope_tag; uint32_t scope_row; uint32_t name; uint32_t ns; };
    struct MemberRefRow { uint32_t class_tag; uint32_t class_row; uint32_t name; uint32_t sig; };
    struct CustomAttributeRow { uint32_t parent_tag; uint32_t parent_row; uint32_t type_tag; uint32_t type_row; uint32_t value; };
    struct ConstantRow { uint8_t type; uint32_t parent_tag; uint32_t parent_row; uint32_t value; };
    struct ImplMapRow { uint16_t flags; uint32_t member_tag; uint32_t member_row; uint32_t name; uint32_t scope; };
    struct AssemblyRefRow { uint16_t major; uint16_t minor; uint16_t build_num; uint16_t rev; uint32_t flags; uint32_t public_key; uint32_t name; uint32_t culture; uint32_t hash; uint32_t docs; };
    struct ModuleRefRow { uint32_t name; };

    std::vector<TypeDefRow> type_def_table_;
    std::vector<MethodDefRow> method_def_table_;
    std::vector<FieldRow> field_table_;
    std::vector<ParamRow> param_table_;
    std::vector<TypeRefRow> type_ref_table_;
    std::vector<MemberRefRow> member_ref_table_;
    std::vector<CustomAttributeRow> custom_attribute_table_;
    std::vector<ConstantRow> constant_table_;
    std::vector<ImplMapRow> impl_map_table_;
    std::vector<AssemblyRefRow> assembly_ref_table_;
    std::vector<ModuleRefRow> module_ref_table_;
    std::unordered_map<std::string, uint32_t> attr_type_map_;
    std::unordered_map<std::string, uint32_t> typeref_map_;
    std::unordered_map<std::string, uint32_t> module_ref_map_;
    // Local typedef name -> real namespace. The parser stores bare names
    // (ref.ns empty) for by-value fields referencing same-header types
    // (PACKAGE_VERSION inside PACKAGE_ID, hoisted DUMMYUNIONNAME members);
    // signature blobs must carry the real namespace or consumers cannot
    // resolve the TypeRef back to its TypeDef.
    std::unordered_map<std::string, std::string> name_ns_;
    // Full type names ("ns.name") that actually exist as TypeDefs. Bare-name
    // references must resolve owner-namespace-first against this set: the
    // global name_ns_ map is first-wins across parallel-parsed headers, so
    // a bare `GUID` field in winnls.h could bind to nspapi.h's own
    // #ifndef GUID_DEFINED copy (Windows.Win32.NSPAPI::GUID) and every
    // consumer then imports a namespace that merely hosts a duplicate.
    std::unordered_set<std::string> full_names_;
    // Bare name -> every namespace that defines it. Resolution must be
    // deterministic: first-wins over parallel-parsed headers binds the same
    // bare name to different namespaces on different runs (GUID -> NSPAPI
    // one run, GUIDDEF the next), flipping consumer imports run to run.
    std::unordered_map<std::string, std::set<std::string>> name_all_ns_;
    // alias name -> raw underlying TRef (PSID -> void* with ptr=1,
    // CLSID -> GUID as a named ValType, JET_COLTYP -> JET_UINT32 as an
    // alias-of-alias). Resolved transitively before substitution.
    std::unordered_map<std::string, TRef> alias_ref_;

    uint32_t add_string(const std::string& s) {
        if (s.empty()) return 0;
        if (auto it = string_map_.find(s); it != string_map_.end()) return it->second;
        uint32_t offset = (uint32_t)string_heap_.size();
        string_map_[s] = offset;
        string_heap_.insert(string_heap_.end(), s.begin(), s.end());
        string_heap_.push_back(0);
        return offset;
    }

    uint32_t add_blob(const std::vector<uint8_t>& b) {
        if (b.empty()) return 0;
        std::string key(reinterpret_cast<const char*>(b.data()), b.size());
        if (auto it = blob_map_.find(key); it != blob_map_.end()) return it->second;
        uint32_t offset = (uint32_t)blob_heap_.size();
        blob_map_[key] = offset;
        write_compressed(blob_heap_, b.size());
        blob_heap_.insert(blob_heap_.end(), b.begin(), b.end());
        return offset;
    }

    uint32_t ensure_typeref(const std::string& ns, const std::string& name) {
        auto key = ns + "." + name;
        if (auto it = typeref_map_.find(key); it != typeref_map_.end()) return it->second;
        auto tname = add_string(name);
        auto tns = add_string(ns);
        uint32_t row = (uint32_t)type_ref_table_.size();
        // ResolutionScope: tag 2 = AssemblyRef, row 1 (ECMA-335 II.24.2.6:
        // k_rs_tables = {Module, ModuleRef, AssemblyRef, TypeReference}).
        type_ref_table_.push_back({0x02, 0x01, tname, tns});
        typeref_map_[key] = row + 1;  // coded indexes carry 1-based rows
        return row + 1;
    }

    uint32_t ensure_module_ref(const std::string& dll) {
        if (auto it = module_ref_map_.find(dll); it != module_ref_map_.end()) return it->second;
        uint32_t row = (uint32_t)module_ref_table_.size();
        module_ref_table_.push_back({add_string(dll)});
        module_ref_map_[dll] = row;
        return row;
    }

    void write_be16(std::vector<uint8_t>& out, uint16_t v) {
        out.push_back((v >> 8) & 0xFF);
        out.push_back(v & 0xFF);
    }
    void write_be32(std::vector<uint8_t>& out, uint32_t v) {
        out.push_back((v >> 24) & 0xFF);
        out.push_back((v >> 16) & 0xFF);
        out.push_back((v >> 8) & 0xFF);
        out.push_back(v & 0xFF);
    }
    void write_le16(std::vector<uint8_t>& out, uint16_t v) {
        out.push_back(v & 0xFF);
        out.push_back((v >> 8) & 0xFF);
    }
    void write_le32(std::vector<uint8_t>& out, uint32_t v) {
        out.push_back(v & 0xFF);
        out.push_back((v >> 8) & 0xFF);
        out.push_back((v >> 16) & 0xFF);
        out.push_back((v >> 24) & 0xFF);
    }
    void write_compressed(std::vector<uint8_t>& out, size_t value) {
        if (value < 0x80) {
            out.push_back((uint8_t)value);
        } else if (value < 0x4000) {
            out.push_back((uint8_t)(0x80 | (value >> 8)));
            out.push_back((uint8_t)(value & 0xFF));
        } else {
            out.push_back((uint8_t)(0xC0 | (value >> 24)));
            out.push_back((uint8_t)((value >> 16) & 0xFF));
            out.push_back((uint8_t)((value >> 8) & 0xFF));
            out.push_back((uint8_t)(value & 0xFF));
        }
    }

    void write_to_file(std::ofstream& out, const std::vector<uint8_t>& data) {
        if (!data.empty())
            out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    void write_be16_file(std::ofstream& out, uint16_t v) {
        uint8_t b[2] = { (uint8_t)((v >> 8) & 0xFF), (uint8_t)(v & 0xFF) };
        out.write(reinterpret_cast<const char*>(b), 2);
    }
    void write_be32_file(std::ofstream& out, uint32_t v) {
        uint8_t b[4] = { (uint8_t)((v >> 24) & 0xFF), (uint8_t)((v >> 16) & 0xFF),
                         (uint8_t)((v >> 8) & 0xFF), (uint8_t)(v & 0xFF) };
        out.write(reinterpret_cast<const char*>(b), 4);
    }
    void write_le16_file(std::ofstream& out, uint16_t v) {
        uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF) };
        out.write(reinterpret_cast<const char*>(b), 2);
    }
    void write_le32_file(std::ofstream& out, uint32_t v) {
        uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
                         (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
        out.write(reinterpret_cast<const char*>(b), 4);
    }
    void write_le64_file(std::ofstream& out, uint64_t v) {
        uint8_t b[8];
        for (int i = 0; i < 8; ++i) b[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
        out.write(reinterpret_cast<const char*>(b), 8);
    }
    void write_compressed_file(std::ofstream& out, size_t value) {
        if (value < 0x80) {
            uint8_t b = (uint8_t)value;
            out.write(reinterpret_cast<const char*>(&b), 1);
        } else if (value < 0x4000) {
            uint8_t b[2] = { (uint8_t)(0x80 | (value >> 8)), (uint8_t)(value & 0xFF) };
            out.write(reinterpret_cast<const char*>(b), 2);
        } else {
            uint8_t b[4] = { (uint8_t)(0xC0 | (value >> 24)), (uint8_t)((value >> 16) & 0xFF),
                             (uint8_t)((value >> 8) & 0xFF), (uint8_t)(value & 0xFF) };
            out.write(reinterpret_cast<const char*>(b), 4);
        }
    }

    // build string and blob heaps

    void build_name_ns() {
        for (auto& item : st.items) {
            if (!item.def.name.empty())
            {
                name_ns_.emplace(item.def.name, item.def.ns);  // first wins
                full_names_.insert(item.def.ns + "." + item.def.name);
                name_all_ns_[item.def.name].insert(item.def.ns);
            }
            if (item.def.alias_elem != ET::Void || !item.def.alias_ref.name.empty() ||
                item.def.alias_ref.ptr > 0 || item.def.alias_ref.fnptr)
            {
                // Headers are parsed standalone and in parallel, so the same
                // typedef name is discovered many times (winnt.h warts,
                // duplicated declarations). First-wins emplace lets a
                // targetless/broken alias parsed from one header shadow the
                // real `} FOO, *PFOO;` definition from another — signatures
                // referencing PFOO then collapse to void. A definition that
                // names a real target always beats a targetless one.
                auto it = alias_ref_.find(item.def.name);
                if (it == alias_ref_.end())
                {
                    alias_ref_.emplace(item.def.name, item.def.alias_ref);
                }
                else
                {
                    bool new_has_target = !item.def.alias_ref.name.empty() || item.def.alias_ref.fnptr;
                    bool old_has_target = !it->second.name.empty() || it->second.fnptr;
                    if (new_has_target && !old_has_target)
                        it->second = item.def.alias_ref;
                }
            }
        }
    }

    // Resolve a possibly namespace-less reference to (ns, name). Returns
    // false only when the name is unknown entirely. `owner` is the namespace
    // of the type/function whose signature is being encoded: bare names are
    // tried there FIRST (scoped lookup, mirrors how C headers resolve), so
    // a hoisted `_AnonymousUnion` in one namespace never binds to another
    // namespace's same-named hoist via the global first-wins map.
    bool resolve_ref_ns(TRef const& ref, std::string& ns_out, std::string const& owner = {}) {
        if (!ref.ns.empty()) { ns_out = ref.ns; return true; }
        if (ref.name.empty()) return false;
        if (!owner.empty() && full_names_.count(owner + "." + ref.name))
        {
            ns_out = owner;
            return true;
        }
        // Canonical homes for types the SDK re-declares under #ifndef guards
        // in many headers (guiddef.h is the primary definition; nspapi.h,
        // winddi.h ... carry guarded copies). Pin the TypeRef to the primary
        // so every consumer imports one consistent module.
        static const std::unordered_map<std::string_view, std::string_view> canonical_homes = {
            { "GUID", "Windows.Win32.GUIDDEF" },
            { "IID", "Windows.Win32.GUIDDEF" },
            { "CLSID", "Windows.Win32.GUIDDEF" },
            { "FMTID", "Windows.Win32.GUIDDEF" },
        };
        if (auto ch = canonical_homes.find(ref.name); ch != canonical_homes.end()
            && full_names_.count(std::string(ch->second) + "." + ref.name))
        {
            ns_out = std::string(ch->second);
            return true;
        }
        // Deterministic pick among ALL namespaces that define the name:
        // lexicographically smallest real home (full_names_ guarantees a
        // TypeDef exists there, so the consumer import always resolves).
        if (auto nit = name_all_ns_.find(ref.name); nit != name_all_ns_.end() && !nit->second.empty())
        {
            ns_out = *nit->second.begin();
            return true;
        }
        if (auto oit = name_ns_.find(ref.name); oit != name_ns_.end()) {
            ns_out = oit->second;
            return true;
        }
        return false;
    }

    void build_string_heap() {
        string_heap_.push_back(0x00); // null byte at offset 0 (ECMA-335 requirement)
        add_string("Winverse"); // Module table name
        add_string(st.asm_name); // AssemblyRef resolution scope
        for (auto& item : st.items) {
            add_string(item.def.ns);
            add_string(item.def.name);
            if (!item.def.ext_name.empty()) add_string(item.def.ext_name);
            if (item.def.kind == Kind::Func) {
                if (!item.def.entry_point.empty()) add_string(item.def.entry_point);
                if (!item.def.import_library.empty()) add_string(item.def.import_library);
            }
            for (auto& f : item.def.fields) add_string(f.name);
            for (auto& m : item.def.meths) {
                for (auto& p : m.params) add_string(p.name);
            }
            for (auto& a : item.def.attributes) {
                add_string(a.ns);
                add_string(a.name);
                for (auto& [k, v] : a.args) add_string(k);
            }
        }
        while (string_heap_.size() % 4) string_heap_.push_back(0);
    }

    void build_blob_heap() {
        blob_heap_.push_back(0x00); // null blob at offset 0
        for (auto& item : st.items) {
            for (auto& meth : item.def.meths) {
                add_blob(encode_method_sig(meth, item.def.ns));
            }
            for (auto& f : item.def.fields) {
                add_blob(encode_field_sig(f, item.def.ns));
            }
            for (auto& a : item.def.attributes) {
                add_blob(encode_custom_attr_blob(a));
            }
            for (auto& f : item.def.fields) {
                if (!f.def.empty()) {
                    add_blob(encode_const_blob(f.def));
                }
            }
        }
        while (blob_heap_.size() % 4) blob_heap_.push_back(0);
    }

    void build_guid_heap() {
        // Single null GUID (16 zero bytes) at index 0
        for (int i = 0; i < 16; ++i) guid_heap_.push_back(0);
        while (guid_heap_.size() % 4) guid_heap_.push_back(0);
    }

    // encode method and field signatures

    std::vector<uint8_t> encode_method_sig(const MSig& m, std::string const& owner = {}) {
        std::vector<uint8_t> sig;
        uint8_t flags = 0;
        if (m.has_this) flags |= 0x20;
        if (m.cc == CC::Vararg) flags |= 0x05;
        else if (m.cc == CC::Cdecl) flags |= 0x01;
        else if (m.cc == CC::Fast) flags |= 0x04;
        sig.push_back(flags);
        write_compressed(sig, m.pt.size());
        encode_element_type(sig, m.ret, m.ret_r, owner);
        for (auto& pt : m.pt) {
            ET param_et = pt.fnptr ? ET::FnPtr :
                          pt.arr  ? ET::SzArray :
                          // Primitive alias params carry their underlying
                          // element type (TRef.elem); everything else falls
                          // through to the named-type encoding. Previously
                          // every param collapsed to ET::Class/System.Object,
                          // which was both ABI-wrong and unreadable by
                          // downstream projections.
                          pt.elem != ET::Void ? pt.elem :
                          ET::Class;
            encode_element_type(sig, param_et, pt, owner);
        }
        return sig;
    }

    std::vector<uint8_t> encode_field_sig(const FDef& f, std::string const& owner = {}) {
        std::vector<uint8_t> sig;
        sig.push_back(0x06);
        if (f.arr_n > 0) {
            // Fixed-size array field: ELEMENT_TYPE_ARRAY (0x14) + element
            // type + ArrayShape { Rank=1, NumSizes=1, Size=N } per
            // ECMA-335 II.23.2.14 — the only way FieldSig can carry a
            // fixed bound (SZARRAY has none).
            sig.push_back(0x14);
            encode_element_type(sig, f.type, f.ref, owner);
            write_compressed(sig, (uint32_t)1);   // Rank
            write_compressed(sig, (uint32_t)1);   // NumSizes
            write_compressed(sig, f.arr_n);       // Size[0]
        } else {
            encode_element_type(sig, f.type, f.ref, owner);
        }
        return sig;
    }

    // Resolve a typedef-alias chain to its fully substituted shape.
    // Returns true when the reference should be rewritten (to a primitive
    // element type or to a different named type). Loops are bounded.
    bool resolve_alias_chain(const TRef& ref, ET& out_et, TRef& out_ref) const {
        if (ref.name.empty()) return false;
        TRef cur = ref;
        bool hopped = false;
        for (int hop = 0; hop < 16; ++hop) {
            auto it = alias_ref_.find(cur.name);
            if (it == alias_ref_.end()) break;          // terminal: real named type
            if (it->second.name == cur.name && it->second.ptr == cur.ptr)
                break;                                   // self-referential alias guard
            ET next_et = it->second.elem;
            TRef next = it->second;
            // const-ness travels with the chain: `const HWND` resolves
            // HWND -> HANDLE -> void* and the pointee must stay const.
            next.pt_const = next.pt_const || cur.pt_const;
            // pointer depth is carried in alias_ref (PSID: name empty,
            // elem Void, ptr 1). A pointer target terminates the chain.
            if (next.ptr > 0 || next.fnptr) {
                out_et = next.fnptr ? ET::FnPtr : (next_et != ET::Void ? next_et : ET::Void);
                out_ref = next;
                out_ref.ptr += cur.ptr; // outer pointer depth stacks on the alias's own
                return true;
            }
            if (next_et == ET::Void && next.name.empty()) break;
            cur = next;
            hopped = true;
            if (next.name.empty()) { // primitive terminal (SQLSMALLINT -> I2)
                out_et = next_et;
                out_ref = next;
                return true;
            }
        }
        // Named terminal after at least one hop (CLSID -> GUID): rewrite the
        // reference to the terminal named type so no signature ever mentions
        // an alias-only typedef. Encoded as a ValueType TypeRef - every C
        // struct/enum terminal projects as a value type in the winmd.
        if (hopped && cur.name != ref.name) {
            out_et = ET::ValType;
            out_ref = cur;
            out_ref.pt_const = out_ref.pt_const || ref.pt_const;
            return true;
        }
        return false;
    }

    void encode_element_type(std::vector<uint8_t>& sig, ET et, const TRef& ref, std::string const& owner = {}) {
        if (ref.ptr > 0 && !ref.byref) {
            sig.push_back(0x0F);
            TRef inner = ref;
            inner.ptr--;
            // Pointee carries the resolved element type when fundamental
            // (ULONG* -> u4 pointee); named pointees keep the Class/ValType
            // encoding. Unnamed pointees fall through to Void below.
            ET pe = (inner.elem != ET::Void && inner.elem != ET::Class &&
                     inner.elem != ET::ValType && inner.elem != ET::Ptr &&
                     inner.elem != ET::FnPtr && inner.elem != ET::SzArray)
                        ? inner.elem : ET::Class;
            // C `const` pointee (LPCWSTR, const GUID*): encode as a CModReqd
            // modifier on the pointee referencing a synthetic Const TypeRef
            // so any downstream projection can recover const-ness. Stripping
            // it made every const pointer param mutable (void*) and broke
            // string-literal arguments in generated consumers (C2664).
            if (inner.pt_const) {
                sig.push_back(0x1F); // CModReqd
                uint32_t crow = ensure_typeref("Windows.Win32.Foundation", "Const");
                write_compressed(sig, (crow << 2) | 0x01);
                inner.pt_const = false; // modifier consumed; do not recurse
            }
            encode_element_type(sig, pe, inner, owner);
            return;
        }
        if (ref.byref) {
            sig.push_back(0x10);
            TRef inner = ref;
            inner.byref = false;
            encode_element_type(sig, ET::Class, inner, owner);
            return;
        }
        if (ref.fnptr) {
            sig.push_back(0x1B); // FnPtr
            return;
        }
        if (ref.arr) {
            sig.push_back(0x1D); // SzArray
            TRef inner = ref;
            inner.arr = false;
            ET ae = (inner.elem != ET::Void && inner.elem != ET::Class &&
                     inner.elem != ET::ValType && inner.elem != ET::Ptr &&
                     inner.elem != ET::FnPtr && inner.elem != ET::SzArray)
                        ? inner.elem : ET::Class;
            encode_element_type(sig, ae, inner, owner);
            return;
        }
        if (!ref.gen.empty()) {
            sig.push_back(0x15); // GenericInst
            std::string ns;
            if (resolve_ref_ns(ref, ns, owner)) {
                uint32_t row = ensure_typeref(ns, ref.name);
                write_compressed(sig, (row << 2) | 0x01); // 1-based TypeRef, tag 1
            } else {
                uint32_t row = ensure_typeref("System", "Object");
                write_compressed(sig, (row << 2) | 0x01); // 1-based TypeRef, tag 1
            }
            write_compressed(sig, (uint32_t)ref.gen.size());
            for (auto& g : ref.gen) {
                encode_element_type(sig, g.fnptr ? ET::FnPtr : ET::Class, g, owner);
            }
            return;
        }
        if (et == ET::Class || et == ET::ValType) {
            ET out_et = et; TRef out_ref = ref;
            // Primitive-alias substitution: resolve the alias chain
            // transitively (SQLSMALLINT -> i2, PSID -> void*, CLSID ->
            // GUID, JET_COLTYP -> u4) and re-encode the fully resolved
            // shape so the metadata is self-describing for any projection.
            if (resolve_alias_chain(ref, out_et, out_ref)) {
                encode_element_type(sig, out_et, out_ref, owner);
                return;
            }
        }
        sig.push_back((uint8_t)et);
        if (et == ET::Class || et == ET::ValType) {
            std::string ns;
            if (resolve_ref_ns(ref, ns, owner)) {
                uint32_t row = ensure_typeref(ns, ref.name);
                write_compressed(sig, (row << 2) | 0x01); // 1-based TypeRef, tag 1
            } else if (ref.name.empty()) {
                // Unnamed reference = void (pointee of void*).
                sig.back() = (uint8_t)ET::Void;
            } else {
                // Fallback: use System.Object as opaque type
                uint32_t row = ensure_typeref("System", "Object");
                write_compressed(sig, (row << 2) | 0x01); // 1-based TypeRef, tag 1
            }
        }
    }

    std::vector<uint8_t> encode_custom_attr_blob(const Attribute& a) {
        std::vector<uint8_t> blob;
        blob.push_back(0x01);
        blob.push_back(0x00);
        // ECMA-335 II.23.3: the blob is Prolog (0x0001) followed directly by
        // the fixed args — the arg count is NOT in the blob (readers derive it
        // from the ctor signature). No positional count here.
        for (auto& v : a.positional) encode_attr_value(blob, v);
        write_compressed(blob, a.args.size());
        for (auto& [k, v] : a.args) {
            blob.push_back(0x53);
            encode_attr_value_type(blob, v);
            auto name_bytes = std::vector<uint8_t>(k.begin(), k.end());
            write_compressed(blob, name_bytes.size());
            blob.insert(blob.end(), name_bytes.begin(), name_bytes.end());
            encode_attr_value(blob, v);
        }
        return blob;
    }

    void encode_attr_value(std::vector<uint8_t>& blob, const AttrVal& v) {
        switch (v.kind) {
            case AttrVal::Kind::Bool: blob.push_back(v.bool_val ? 1 : 0); break;
            case AttrVal::Kind::Int: {
                auto val = (int32_t)v.int_val;
                blob.push_back(val & 0xFF);
                blob.push_back((val >> 8) & 0xFF);
                blob.push_back((val >> 16) & 0xFF);
                blob.push_back((val >> 24) & 0xFF);
                break;
            }
            case AttrVal::Kind::UInt: {
                auto val = (uint32_t)v.uint_val;
                blob.push_back(val & 0xFF);
                blob.push_back((val >> 8) & 0xFF);
                blob.push_back((val >> 16) & 0xFF);
                blob.push_back((val >> 24) & 0xFF);
                break;
            }
            case AttrVal::Kind::String: {
                // SerString = compressed byte-length + UTF-8 bytes, NO NUL
                // terminator inside the counted length (ECMA-335 II.23.3).
                auto bytes = std::vector<uint8_t>(v.str_val.begin(), v.str_val.end());
                write_compressed(blob, bytes.size());
                blob.insert(blob.end(), bytes.begin(), bytes.end());
                break;
            }
            default: break;
        }
    }

    void encode_attr_value_type(std::vector<uint8_t>& blob, const AttrVal& v) {
        switch (v.kind) {
            case AttrVal::Kind::Bool:  blob.push_back(0x02); break;
            case AttrVal::Kind::Int:   blob.push_back(0x08); break;
            case AttrVal::Kind::UInt:  blob.push_back(0x09); break;
            case AttrVal::Kind::String: blob.push_back(0x0E); break;
            default: blob.push_back(0x00); break;
        }
    }

    std::vector<uint8_t> encode_const_blob(const CVal& v) {
        std::vector<uint8_t> blob;
        switch (v.type) {
            case ET::I4: {
                auto val = std::get<int32_t>(v.v);
                blob.push_back(val & 0xFF);
                blob.push_back((val >> 8) & 0xFF);
                blob.push_back((val >> 16) & 0xFF);
                blob.push_back((val >> 24) & 0xFF);
                break;
            }
            case ET::U4: {
                auto val = std::get<uint32_t>(v.v);
                blob.push_back(val & 0xFF);
                blob.push_back((val >> 8) & 0xFF);
                blob.push_back((val >> 16) & 0xFF);
                blob.push_back((val >> 24) & 0xFF);
                break;
            }
            case ET::I8: {
                auto val = std::get<int64_t>(v.v);
                for (int i = 0; i < 8; ++i) blob.push_back((val >> (i * 8)) & 0xFF);
                break;
            }
            case ET::U8: {
                // 64-bit constants (WINDOWSAPPSDK_RUNTIME_VERSION_UINT64 /
                // PACKAGE_VERSION) need all 8 bytes LE; without this case
                // the Constant-table blob came out EMPTY and the value was
                // silently lost.
                auto val = std::get<uint64_t>(v.v);
                for (int i = 0; i < 8; ++i) blob.push_back((val >> (i * 8)) & 0xFF);
                break;
            }
            case ET::Bool: blob.push_back(std::get<bool>(v.v) ? 1 : 0); break;
            default: break;
        }
        return blob;
    }

    // build metadata tables

    void build_type_table() {
        uint32_t field_idx = 1;
        uint32_t method_idx = 1;
        for (auto& item : st.items) {
            // Extends must reference REAL TypeRef rows for the runtime base:
            // Enum -> System.Enum, Struct/Union -> System.ValueType,
            // Delegate -> System.MulticastDelegate, else System.Object.
            uint32_t extends_tag = 0, extends_row = 0;
            if (item.def.kind == Kind::Enum) { extends_tag = 0x01; extends_row = ensure_typeref("System", "Enum"); }
            else if (item.def.kind == Kind::Struct || item.def.kind == Kind::Union) { extends_tag = 0x01; extends_row = ensure_typeref("System", "ValueType"); }
            else if (item.def.kind == Kind::Delegate) { extends_tag = 0x01; extends_row = ensure_typeref("System", "MulticastDelegate"); }
            else if (item.def.kind == Kind::Iface) { extends_tag = 0x01; extends_row = ensure_typeref("System", "Object"); }
            else if (item.def.kind == Kind::Class) { extends_tag = 0x01; extends_row = ensure_typeref("System", "Object"); }
            else { extends_tag = 0x01; extends_row = 0x00; }

            // COM interfaces carry the Interface flag (0x20) so standard
            // metadata readers classify them as interfaces.
            uint32_t td_attr = (uint32_t)item.def.attr;
            if (item.def.kind == Kind::Iface) td_attr |= 0x00000020;

            type_def_table_.push_back({
                td_attr,
                add_string(item.def.name),
                add_string(item.def.ns),
                extends_tag, extends_row,
                field_idx,
                method_idx,
            });
            field_idx += (uint32_t)item.def.fields.size();
            method_idx += (uint32_t)item.def.meths.size();
            emit_stats.types_emitted++;
        }
    }

    void build_method_and_field_tables() {
        uint32_t param_idx = 1;
        for (auto& item : st.items) {
            for (auto& meth : item.def.meths) {
                uint16_t flags = (uint16_t)MA::Pub;
                if (item.def.kind == Kind::Func) flags |= (uint16_t)MA::PInvoke;

                // Delegates: the standard ECMA-335 shape is one method named
                // "Invoke" (any language projection looks for it by name).
                // Interface methods: their REAL name (MSig.name — set by the
                // parser in vtable order; naming every method after the type
                // made consumers read them as constructors: C2533).
                // Plain C function items: the name lives on the TDef (the
                // type IS the function) — fall back when MSig.name is empty.
                std::string meth_name;
                if (item.def.kind == Kind::Delegate)
                    meth_name = "Invoke";
                else if (!meth.name.empty())
                    meth_name = meth.name;
                else
                    meth_name = item.def.name;

                method_def_table_.push_back({
                    0,
                    0,
                    flags,
                    add_string(meth_name),
                    add_blob(encode_method_sig(meth, item.def.ns)),
                    param_idx,
                });
                emit_stats.methods_emitted++;
                for (auto& p : meth.params) {
                    param_table_.push_back({(uint16_t)p.attr, p.seq, add_string(p.name)});
                    param_idx++;
                    emit_stats.params_emitted++;
                }
            }
            for (auto& f : item.def.fields) {
                field_table_.push_back({
                    (uint16_t)f.attr,
                    add_string(f.name),
                    add_blob(encode_field_sig(f, item.def.ns)),
                });
                emit_stats.fields_emitted++;
            }
        }
    }

    uint32_t resolve_attr_type_ref(const Attribute& a) {
        auto key = a.ns + "." + a.name;
        if (auto it = attr_type_map_.find(key); it != attr_type_map_.end())
            return it->second;
        auto scope = add_string(st.asm_name);
        auto tname = add_string(a.name);
        auto tns = add_string(a.ns);
        uint32_t idx = (uint32_t)type_ref_table_.size();
        type_ref_table_.push_back({0x00, 0x01, tname, tns}); // ResolutionScope: tag 0 = Module
        emit_stats.typeref_emitted++;

        // Create MemberRef pointing to this TypeRef (CustomAttributeType requires MethodDef/MemberRef)
        uint32_t mr_idx = (uint32_t)member_ref_table_.size();
        // Method signature: HASTHIS, paramCount, ret=void, then one element
        // type per positional ctor arg — matching encode_attr_value exactly
        // (Int->I4, UInt->U4, Bool->BOOL, String->String), so consumers can
        // decode the custom attribute blob against this constructor.
        std::vector<uint8_t> ctor_sig;
        ctor_sig.push_back(0x20);            // HASTHIS
        write_compressed(ctor_sig, (uint32_t)a.positional.size());
        ctor_sig.push_back(0x01);            // ret = void
        for (auto& v : a.positional) {
            switch (v.kind) {
                case AttrVal::Kind::String: ctor_sig.push_back(0x0E); break;
                case AttrVal::Kind::Bool:   ctor_sig.push_back(0x02); break;
                case AttrVal::Kind::UInt:   ctor_sig.push_back(0x09); break; // U4
                case AttrVal::Kind::Int:
                default:                    ctor_sig.push_back(0x08); break; // I4
            }
        }
        member_ref_table_.push_back({
            0x01, idx + 1,  // class: tag 1 = TypeRef, 1-based row
            tname,
            add_blob(ctor_sig),
        });

        attr_type_map_[key] = mr_idx;
        return mr_idx;
    }

    void build_custom_attribute_table() {
        for (size_t i = 0; i < st.items.size(); ++i) {
            {
                // Scalar typedef alias target: record the resolved primitive
                // element type on the field-less alias row (DWORD -> U4,
                // RPC_STATUS -> I4, BOOL -> I4) so the C++ projection can
                // emit `using DWORD = std::uint32_t;` instead of guessing
                // void* from a row that carries no fields. Ptr/Class targets
                // (HANDLE, HKEY, GUID chains) stay targetless — opaque
                // handles flatten to void* by projection design.
                auto& _ad = st.items[i].def;
                if (_ad.kind == Kind::Class && _ad.fields.empty() && _ad.meths.empty() &&
                    !_ad.name.empty()) {
                    ET _at = _ad.alias_elem;
                    bool _prim = _at == ET::Bool || _at == ET::Char ||
                        _at == ET::I1 || _at == ET::U1 || _at == ET::I2 || _at == ET::U2 ||
                        _at == ET::I4 || _at == ET::U4 || _at == ET::I8 || _at == ET::U8 ||
                        _at == ET::R4 || _at == ET::R8;
                    if (_prim) {
                        // "<code>|<ptr-depth>" — LPWSTR (WCHAR*) must keep its
                        // pointer level or the projection spells it without '*'.
                        Attribute _aa; _aa.ns = "Winverse.Attributes"; _aa.name = "AliasTarget";
                        _aa.positional.push_back(AttrVal(AttrVal::Kind::String,
                            std::to_string(static_cast<uint8_t>(_at)) + "|" +
                            std::to_string(_ad.alias_ref.ptr)));
                        _ad.attributes.push_back(std::move(_aa));
                    }
                }
            }
            for (auto& a : st.items[i].def.attributes) {
                uint32_t mr_idx = resolve_attr_type_ref(a);
            custom_attribute_table_.push_back({
                0x03, (uint32_t)(i + 1),  // parent: tag 3 = TypeDef (HasCustomAttribute coded index: 2=TypeRef, 3=TypeDef), 1-based row
                0x03, mr_idx + 1,   // type: tag 3 = MemberRef, 1-based row
                    add_blob(encode_custom_attr_blob(a)),
                });
                emit_stats.attrs_emitted++;
            }
        }
    }

    void build_constant_table() {
        uint32_t field_row = 1;
        for (size_t i = 0; i < st.items.size(); ++i) {
            for (auto& f : st.items[i].def.fields) {
                if (!f.def.empty()) {
                    constant_table_.push_back({
                        (uint8_t)f.def.type,
                        0x00, field_row,  // parent: tag 0 = Field, 1-based row
                        add_blob(encode_const_blob(f.def)),
                    });
                    emit_stats.constants_emitted++;
                }
                field_row++;
            }
        }
    }

    void build_assembly_ref_table() {
        assembly_ref_table_.push_back({
            1, 0, 0, 0,   // MajorVersion, MinorVersion, BuildNumber, RevisionNumber
            0,             // Flags
            0,             // PublicKeyOrToken (none)
            add_string(st.asm_name), // Name
            0,             // Culture (none)
            0, 0,          // Hash, Docs
        });
    }

    void build_impl_map_table() {
        uint32_t method_row = 1;
        for (size_t i = 0; i < st.items.size(); ++i) {
            bool has_import = (st.items[i].def.kind == Kind::Func && !st.items[i].def.import_library.empty());
            if (has_import) {
                uint32_t mod_ref = ensure_module_ref(st.items[i].def.import_library);
                impl_map_table_.push_back({
                    0x0001,
                    0x00, method_row,  // member: tag 0 = MethodDef, 1-based row
                    add_string(st.items[i].def.entry_point.empty() ? st.items[i].def.name : st.items[i].def.entry_point),
                    mod_ref + 1,
                });
                emit_stats.implmap_emitted++;
            }
            method_row += (uint32_t)st.items[i].def.meths.size();
        }
    }

    void build_type_ref_table() {}

    // compute column widths for coded indexes

    uint32_t col_width_strings() const { return (string_heap_.size() > 0xFFFF) ? 4 : 2; }
    uint32_t col_width_blob() const { return (blob_heap_.size() > 0xFFFF) ? 4 : 2; }
    uint32_t col_width_guid() const { return (guid_heap_.size() > 0xFFFF) ? 4 : 2; }

    uint32_t col_width_simple(uint32_t target_table) const {
        uint32_t rows = get_table_row_count(target_table);
        return (rows > 0xFFFF) ? 4 : 2;
    }

    uint32_t col_width_coded(uint32_t tag_bits, const uint32_t* tag_tables, uint32_t tag_count) const {
        uint32_t max_rows = 0;
        for (uint32_t i = 0; i < tag_count; ++i)
            max_rows = (std::max)(max_rows, get_table_row_count(tag_tables[i]));
        return (max_rows >= (1u << (16 - tag_bits))) ? 4 : 2;
    }

    // write PE file

    void build_pe_streaming(const std::string& output_path) {
        // Pre-compute heap sizes so column widths are known
        uint32_t strings_idx_width = col_width_strings();
        uint32_t blob_idx_width = col_width_blob();
        uint32_t guid_idx_width = col_width_guid();
        uint8_t heap_sizes = 0;
        if (strings_idx_width == 4) heap_sizes |= 0x01;
        if (guid_idx_width == 4) heap_sizes |= 0x02;
        if (blob_idx_width == 4) heap_sizes |= 0x04;

        // Compute #~ stream size
        uint32_t tables_stream_size = compute_tables_stream_size();

        // Layout: .text at VA 0x1000, raw 0x200
        //   CLI Header (72 bytes) at start of .text
        //   Metadata root (BSJB) follows CLI Header
        const uint32_t file_align    = 0x200;
        const uint32_t section_align = 0x1000;
        const uint32_t text_raw      = 0x200;
        const uint32_t text_rva      = 0x1000;
        const uint32_t cli_size      = 72;
        const uint32_t cli_rva       = text_rva;
        const uint32_t meta_rva      = text_rva + cli_size;

        // Build metadata root in memory to compute total size
        std::vector<uint8_t> meta_root;
        auto write_le16 = [&](uint16_t v) {
            meta_root.push_back(v & 0xFF);
            meta_root.push_back((v >> 8) & 0xFF);
        };
        auto write_le32 = [&](uint32_t v) {
            meta_root.push_back(v & 0xFF);
            meta_root.push_back((v >> 8) & 0xFF);
            meta_root.push_back((v >> 16) & 0xFF);
            meta_root.push_back((v >> 24) & 0xFF);
        };
        auto write_be32 = [&](uint32_t v) {
            meta_root.push_back((v >> 24) & 0xFF);
            meta_root.push_back((v >> 16) & 0xFF);
            meta_root.push_back((v >> 8) & 0xFF);
            meta_root.push_back(v & 0xFF);
        };

        // Metadata root signature
        write_le32(0x424A5342); // "BSJB" in LE produces bytes 42 53 4A 42
        write_le16(1);          // MajorVersion
        write_le16(1);          // MinorVersion
        write_le32(0);          // Reserved

        // Version string
        const char* version_str = "v4.0.30319";
        uint32_t raw_len = (uint32_t)std::strlen(version_str) + 1;
        uint32_t ver_len = (raw_len + 3) & ~3u; // pad to multiple of 4
        write_le32(ver_len);
        meta_root.insert(meta_root.end(), version_str, version_str + raw_len);
        while (meta_root.size() % 4) meta_root.push_back(0);

        write_le16(0); // Flags

        uint32_t tables_padded = (tables_stream_size + 3) & ~3u;
        uint32_t strings_padded = ((uint32_t)string_heap_.size() + 3) & ~3u;
        uint32_t guids_padded = ((uint32_t)guid_heap_.size() + 3) & ~3u;

        // NumberOfStreams (2 bytes, no padding needed here)
        write_le16(4);

        // #~ stream header — write placeholder offset, fix up later
        uint32_t hdr_tables_off = (uint32_t)meta_root.size();
        write_le32(0); // placeholder
        write_le32(tables_stream_size);
        meta_root.insert(meta_root.end(), {'#','~',0,0});

        // #Strings stream header
        uint32_t hdr_strings_off = (uint32_t)meta_root.size();
        write_le32(0); // placeholder
        write_le32((uint32_t)string_heap_.size());
        meta_root.insert(meta_root.end(), {'#','S','t','r','i','n','g','s',0});
        while (meta_root.size() % 4) meta_root.push_back(0);

        // #GUID stream header
        uint32_t hdr_guids_off = (uint32_t)meta_root.size();
        write_le32(0); // placeholder
        write_le32((uint32_t)guid_heap_.size());
        meta_root.insert(meta_root.end(), {'#','G','U','I','D',0,0,0});

        // #Blob stream header
        uint32_t hdr_blob_off = (uint32_t)meta_root.size();
        write_le32(0); // placeholder
        write_le32((uint32_t)blob_heap_.size());
        meta_root.insert(meta_root.end(), {'#','B','l','o','b',0,0,0});

        // Pad to 4
        while (meta_root.size() % 4) meta_root.push_back(0);

        // Now we know where stream data starts — fix up offsets (relative to BSJB)
        uint32_t stream_data_start = (uint32_t)meta_root.size();
        uint32_t offset_tables = stream_data_start;
        uint32_t offset_strings = stream_data_start + tables_padded;
        uint32_t offset_guids = stream_data_start + tables_padded + strings_padded;
        uint32_t offset_blob = stream_data_start + tables_padded + strings_padded + guids_padded;

        // Patch the placeholder offsets in the stream headers
        meta_root[hdr_tables_off + 0] = offset_tables & 0xFF;
        meta_root[hdr_tables_off + 1] = (offset_tables >> 8) & 0xFF;
        meta_root[hdr_tables_off + 2] = (offset_tables >> 16) & 0xFF;
        meta_root[hdr_tables_off + 3] = (offset_tables >> 24) & 0xFF;

        meta_root[hdr_strings_off + 0] = offset_strings & 0xFF;
        meta_root[hdr_strings_off + 1] = (offset_strings >> 8) & 0xFF;
        meta_root[hdr_strings_off + 2] = (offset_strings >> 16) & 0xFF;
        meta_root[hdr_strings_off + 3] = (offset_strings >> 24) & 0xFF;

        meta_root[hdr_guids_off + 0] = offset_guids & 0xFF;
        meta_root[hdr_guids_off + 1] = (offset_guids >> 8) & 0xFF;
        meta_root[hdr_guids_off + 2] = (offset_guids >> 16) & 0xFF;
        meta_root[hdr_guids_off + 3] = (offset_guids >> 24) & 0xFF;

        meta_root[hdr_blob_off + 0] = offset_blob & 0xFF;
        meta_root[hdr_blob_off + 1] = (offset_blob >> 8) & 0xFF;
        meta_root[hdr_blob_off + 2] = (offset_blob >> 16) & 0xFF;
        meta_root[hdr_blob_off + 3] = (offset_blob >> 24) & 0xFF;

        // #~ stream data
        write_tables_to_vec(meta_root, heap_sizes);

        // Pad to 4
        while (meta_root.size() % 4) meta_root.push_back(0);

        // #Strings
        meta_root.insert(meta_root.end(), string_heap_.begin(), string_heap_.end());
        while (meta_root.size() % 4) meta_root.push_back(0);

        // #GUID
        meta_root.insert(meta_root.end(), guid_heap_.begin(), guid_heap_.end());
        while (meta_root.size() % 4) meta_root.push_back(0);

        // #Blob
        meta_root.insert(meta_root.end(), blob_heap_.begin(), blob_heap_.end());
        while (meta_root.size() % 4) meta_root.push_back(0);

        // Compute sizes
        uint32_t text_size = cli_size + (uint32_t)meta_root.size();
        uint32_t text_vsize = (text_size + section_align - 1) & ~(section_align - 1);
        uint32_t text_rsize = (text_size + file_align - 1) & ~(file_align - 1);
        uint32_t size_of_image = (text_rva + text_vsize + section_align - 1) & ~(section_align - 1);

        auto ws = std::filesystem::path(output_path).wstring();
#ifdef _WIN32
        if (ws.size() >= 260 && ws.substr(0, 4) != L"\\\\?\\")
            ws = L"\\\\?\\" + ws;
#endif
        std::ofstream out(ws, std::ios::binary);
        if (!out.is_open()) { std::cerr << "Cannot open output: " << output_path << "\n"; return; }

        // DOS Header (128 bytes, e_lfanew = 0x80)
        uint8_t dos[128] = {};
        dos[0] = 'M'; dos[1] = 'Z';
        dos[0x3C] = 0x80;
        out.write(reinterpret_cast<const char*>(dos), 128);

        const uint32_t pe_sig_offset = 0x80;

        // PE Signature at 0x80
        write_le32_file(out, 0x00004550); // "PE\0\0"

        // IMAGE_FILE_HEADER at 0x84
        write_le16_file(out, 0x014C); // Machine: i386
        write_le16_file(out, 1);      // NumberOfSections
        write_le32_file(out, 0);      // TimeDateStamp
        write_le32_file(out, 0);      // PointerToSymbolTable
        write_le32_file(out, 0);      // NumberOfSymbols
        write_le16_file(out, 0xE0);   // SizeOfOptionalHeader (PE32 = 224)
        write_le16_file(out, 0x2102); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE | LARGE_ADDRESS_AWARE

        // IMAGE_OPTIONAL_HEADER (PE32) at 0x98
        write_le16_file(out, 0x010B); // Magic: PE32
        write_le16_file(out, 0);      // MajorLinkerVersion, MinorLinkerVersion
        write_le32_file(out, 0);      // SizeOfCode
        write_le32_file(out, 0);      // SizeOfInitializedData
        write_le32_file(out, 0);      // SizeOfUninitializedData
        write_le32_file(out, 0);      // AddressOfEntryPoint (none for metadata)
        write_le32_file(out, 0);      // BaseOfCode
        write_le32_file(out, 0);      // BaseOfData (PE32 only)
        write_le32_file(out, 0x00400000); // ImageBase
        write_le32_file(out, 0x1000); // SectionAlignment
        write_le32_file(out, 0x200);  // FileAlignment
        write_le32_file(out, 0);      // MajorOperatingSystemVersion + Minor
        write_le32_file(out, 0);      // MajorImageVersion + Minor
        write_le32_file(out, 0);      // MajorSubsystemVersion + Minor
        write_le32_file(out, 0);      // Win32VersionValue
        write_le32_file(out, size_of_image);   // SizeOfImage
        write_le32_file(out, 0x200);  // SizeOfHeaders
        write_le32_file(out, 0);      // CheckSum
        write_le16_file(out, 3);      // Subsystem: CONSOLE
        write_le16_file(out, 0);      // DllCharacteristics
        write_le32_file(out, 0);      // SizeOfStackReserve
        write_le32_file(out, 0);      // SizeOfStackCommit
        write_le32_file(out, 0);      // SizeOfHeapReserve
        write_le32_file(out, 0);      // SizeOfHeapCommit
        write_le32_file(out, 0);      // LoaderFlags
        write_le32_file(out, 16);     // NumberOfRvaAndSizes

        // 16 Data Directories (all zero except [14])
        for (int i = 0; i < 16; ++i) {
            write_le32_file(out, 0);
            write_le32_file(out, 0);
        }

        // DataDirectory[14] = COM Descriptor (CLI Header)
        // Optional header starts at PE+24. Fixed part = 96 bytes. DataDir starts at PE+24+96 = PE+120.
        // DataDir[14] at PE+120 + 14*8
        {
            uint32_t dd14_pos = pe_sig_offset + 24 + 96 + 14 * 8;
            std::streampos cur = out.tellp();
            out.seekp(dd14_pos);
            write_le32_file(out, cli_rva);  // RVA of CLI Header
            write_le32_file(out, cli_size); // Size of CLI Header
            out.seekp(cur);
        }

        // Section Header .text at PE+24+224 = PE+248
        // PE sig is at 0x80, so section header at 0x80+248 = 0x178
        {
            uint8_t sh[40] = {};
            std::memcpy(sh, ".text\0\0\0", 8);
            // VirtualSize
            sh[8] = text_vsize & 0xFF; sh[9] = (text_vsize >> 8) & 0xFF;
            sh[10] = (text_vsize >> 16) & 0xFF; sh[11] = (text_vsize >> 24) & 0xFF;
            // VirtualAddress
            sh[12] = text_rva & 0xFF; sh[13] = (text_rva >> 8) & 0xFF;
            sh[14] = (text_rva >> 16) & 0xFF; sh[15] = (text_rva >> 24) & 0xFF;
            // SizeOfRawData
            sh[16] = text_rsize & 0xFF; sh[17] = (text_rsize >> 8) & 0xFF;
            sh[18] = (text_rsize >> 16) & 0xFF; sh[19] = (text_rsize >> 24) & 0xFF;
            // PointerToRawData
            sh[20] = text_raw & 0xFF; sh[21] = (text_raw >> 8) & 0xFF;
            sh[22] = (text_raw >> 16) & 0xFF; sh[23] = (text_raw >> 24) & 0xFF;
            // Characteristics: CODE | EXECUTE | READ
            uint32_t chars = 0x60000020;
            sh[36] = chars & 0xFF; sh[37] = (chars >> 8) & 0xFF;
            sh[38] = (chars >> 16) & 0xFF; sh[39] = (chars >> 24) & 0xFF;
            out.write(reinterpret_cast<const char*>(sh), 40);
        }

        // Pad to file_align (headers end at 0x200)
        char zero = 0;
        while (out.tellp() % file_align) out.write(&zero, 1);

        // IMAGE_COR20_HEADER (72 bytes) at start of .text
        // Fields: cb(4) + MajorVer(2) + MinorVer(2) + MetaData(8) + Flags(4) + EntryPointToken(4)
        //         + Resources(8) + StrongNameSig(8) + CodeManagerTable(8) + VTableFixups(8)
        //         + ExportAddressTableJumps(8) + ManagedNativeHeader(8) = 72
        write_le32_file(out, cli_size);          // cb (size of header)
        write_le16_file(out, 2);                 // MajorRuntimeVersion
        write_le16_file(out, 5);                 // MinorRuntimeVersion
        write_le32_file(out, meta_rva);          // MetaData RVA
        write_le32_file(out, (uint32_t)meta_root.size()); // MetaData Size
        write_le32_file(out, 0x00000001);        // Flags: IL_ONLY
        write_le32_file(out, 0);                 // EntryPointToken
        write_le32_file(out, 0); write_le32_file(out, 0); // Resources (8 bytes)
        write_le32_file(out, 0); write_le32_file(out, 0); // StrongNameSignature (8 bytes)
        write_le32_file(out, 0); write_le32_file(out, 0); // CodeManagerTable (8 bytes)
        write_le32_file(out, 0); write_le32_file(out, 0); // VTableFixups (8 bytes)
        write_le32_file(out, 0); write_le32_file(out, 0); // ExportAddressTableJumps (8 bytes)
        write_le32_file(out, 0); write_le32_file(out, 0); // ManagedNativeHeader (8 bytes)

        // Write metadata root
        out.write(reinterpret_cast<const char*>(meta_root.data()), meta_root.size());

        // Pad to section alignment
        while (out.tellp() % section_align) out.write(&zero, 1);

        out.close();
    }

    // coded index helpers per ECMA-335 II.24.2.6

    uint32_t coded_index_width(uint32_t tag_bits, const uint32_t* tables, uint32_t count) const {
        uint32_t max_rows = 0;
        for (uint32_t i = 0; i < count; ++i)
            if (tables[i] != 0)
                max_rows = (std::max)(max_rows, get_table_row_count(tables[i]));
        return (max_rows >= (1u << (16 - tag_bits))) ? 4 : 2;
    }

    void write_coded(std::vector<uint8_t>& out, uint32_t tag_bits, uint32_t tag, uint32_t row, uint32_t width) {
        // ECMA-335 II.24.2.6: the TAG occupies the low bits and the ROW is
        // shifted above it. Row numbers are 1-based; row 0 with any tag is
        // the null reference.
        uint32_t encoded = (row << tag_bits) | tag;
        if (width == 4) {
            out.push_back(encoded & 0xFF);
            out.push_back((encoded >> 8) & 0xFF);
            out.push_back((encoded >> 16) & 0xFF);
            out.push_back((encoded >> 24) & 0xFF);
        } else {
            out.push_back(encoded & 0xFF);
            out.push_back((encoded >> 8) & 0xFF);
        }
    }

    void write_idx(std::vector<uint8_t>& out, uint32_t value, uint32_t width) {
        if (width == 4) {
            out.push_back(value & 0xFF);
            out.push_back((value >> 8) & 0xFF);
            out.push_back((value >> 16) & 0xFF);
            out.push_back((value >> 24) & 0xFF);
        } else {
            out.push_back(value & 0xFF);
            out.push_back((value >> 8) & 0xFF);
        }
    }

    // compute total #~ stream size

    uint32_t compute_tables_stream_size() {
        uint32_t sw = col_width_strings();
        uint32_t bw = col_width_blob();
        uint32_t gw = col_width_guid();
        uint32_t fw = col_width_simple(0x04);
        uint32_t mw = col_width_simple(0x06);
        uint32_t pmw = col_width_simple(0x08);
        uint32_t modw = col_width_simple(0x00);
        uint32_t mrw = col_width_simple(0x1A);

        uint32_t size = 24;
        uint64_t valid = get_valid_mask();
        for (int i = 0; i < 64; ++i)
            if (valid & (1ULL << i)) size += 4;

        size += 1 * (2 + sw + gw + gw + gw); // Module (always 1 row)
        size += (uint32_t)type_ref_table_.size() * (coded_index_width(k_rs_tag_bits, k_rs_tables, k_rs_count) + sw + sw);
        size += (uint32_t)type_def_table_.size() * (4 + sw + sw + coded_index_width(k_tdr_tag_bits, k_tdr_tables, k_tdr_count) + fw + mw);
        size += (uint32_t)field_table_.size() * (2 + sw + bw);
        size += (uint32_t)method_def_table_.size() * (4 + 2 + 2 + sw + bw + pmw);
        size += (uint32_t)param_table_.size() * (2 + 2 + sw);
        size += (uint32_t)member_ref_table_.size() * (coded_index_width(k_mrp_tag_bits, k_mrp_tables, k_mrp_count) + sw + bw);
        size += (uint32_t)custom_attribute_table_.size() * (
            coded_index_width(k_hca_tag_bits, k_hca_tables, k_hca_count) +
            coded_index_width(k_cat_tag_bits, k_cat_tables, k_cat_count) + bw);
        size += (uint32_t)constant_table_.size() * (2 + coded_index_width(k_hc_tag_bits, k_hc_tables, k_hc_count) + bw);
        size += (uint32_t)impl_map_table_.size() * (2 + coded_index_width(k_mf_tag_bits, k_mf_tables, k_mf_count) + sw + mrw);
        size += (uint32_t)module_ref_table_.size() * sw; // ModuleRef: Name (string)
        size += (uint32_t)assembly_ref_table_.size() * (2 + 2 + 2 + 2 + 4 + bw + sw + sw + bw + bw); // AssemblyRef: Maj+Min+Build+Rev+Flags+PK(blob)+Name(str)+Culture(str)+Hash(blob)+Docs(blob)
        return size;
    }

    uint64_t get_valid_mask() {
        uint64_t mask = 0;
        mask |= (1ULL << 0x00); // Module (always)
        if (!type_ref_table_.empty())         mask |= (1ULL << 0x01);
        if (!type_def_table_.empty())         mask |= (1ULL << 0x02);
        if (!field_table_.empty())            mask |= (1ULL << 0x04);
        if (!method_def_table_.empty())       mask |= (1ULL << 0x06);
        if (!param_table_.empty())            mask |= (1ULL << 0x08);
        if (!member_ref_table_.empty())       mask |= (1ULL << 0x0A);
        if (!constant_table_.empty())         mask |= (1ULL << 0x0B);
        if (!custom_attribute_table_.empty()) mask |= (1ULL << 0x0C);
        if (!module_ref_table_.empty())       mask |= (1ULL << 0x1A);
        if (!impl_map_table_.empty())         mask |= (1ULL << 0x1C);
        if (!assembly_ref_table_.empty())     mask |= (1ULL << 0x27);
        return mask;
    }

    uint32_t get_table_row_count(uint32_t t) const {
        switch (t) {
            case 0x00: return 1;
            case 0x01: return (uint32_t)type_ref_table_.size();
            case 0x02: return (uint32_t)type_def_table_.size();
            case 0x04: return (uint32_t)field_table_.size();
            case 0x06: return (uint32_t)method_def_table_.size();
            case 0x08: return (uint32_t)param_table_.size();
            case 0x0A: return (uint32_t)member_ref_table_.size();
            case 0x0B: return (uint32_t)constant_table_.size();
            case 0x0C: return (uint32_t)custom_attribute_table_.size();
            case 0x1A: return (uint32_t)module_ref_table_.size();
            case 0x1C: return (uint32_t)impl_map_table_.size();
            case 0x27: return (uint32_t)assembly_ref_table_.size();
            default: return 0;
        }
    }

    // write all tables to output

    void write_tables_to_vec(std::vector<uint8_t>& out, uint8_t heap_sizes) {
        auto le16 = [&](uint16_t v) { out.push_back(v & 0xFF); out.push_back((v >> 8) & 0xFF); };
        auto le32 = [&](uint32_t v) {
            out.push_back(v & 0xFF); out.push_back((v >> 8) & 0xFF);
            out.push_back((v >> 16) & 0xFF); out.push_back((v >> 24) & 0xFF);
        };
        auto str = [&](uint32_t idx) { write_idx(out, idx, col_width_strings()); };
        auto blob = [&](uint32_t idx) { write_idx(out, idx, col_width_blob()); };
        auto simple = [&](uint32_t t, uint32_t idx) { write_idx(out, idx, col_width_simple(t)); };

        uint32_t sw = col_width_strings();
        uint32_t bw = col_width_blob();
        uint32_t fw = col_width_simple(0x04);
        uint32_t mw = col_width_simple(0x06);
        uint32_t pmw = col_width_simple(0x08);
        uint32_t mrw = col_width_simple(0x1A);
        uint32_t hca_w = coded_index_width(k_hca_tag_bits, k_hca_tables, k_hca_count);
        uint32_t hc_w = coded_index_width(k_hc_tag_bits, k_hc_tables, k_hc_count);
        uint32_t cat_w = coded_index_width(k_cat_tag_bits, k_cat_tables, k_cat_count);
        uint32_t mf_w = coded_index_width(k_mf_tag_bits, k_mf_tables, k_mf_count);
        uint32_t tdr_w = coded_index_width(k_tdr_tag_bits, k_tdr_tables, k_tdr_count);
        uint32_t rs_w = coded_index_width(k_rs_tag_bits, k_rs_tables, k_rs_count);
        uint32_t mrp_w = coded_index_width(k_mrp_tag_bits, k_mrp_tables, k_mrp_count);

        // Header
        le32(0);       // Reserved
        out.push_back(2); // MajorVersion
        out.push_back(0); // MinorVersion
        out.push_back(heap_sizes);
        out.push_back(0); // Reserved

        uint64_t valid = get_valid_mask();
        for (int i = 0; i < 8; ++i) out.push_back((uint8_t)((valid >> (i * 8)) & 0xFF));
        uint64_t sorted = (1ULL << 0x02) | (1ULL << 0x1C) | (1ULL << 0x27);
        for (int i = 0; i < 8; ++i) out.push_back((uint8_t)((sorted >> (i * 8)) & 0xFF));

        for (int i = 0; i < 64; ++i)
            if (valid & (1ULL << i)) le32(get_table_row_count(i));

        // Table 0x00: Module (1 row, required)
        {
            le16(0); // Generation
            str(add_string("Winverse")); // Name — must match the one added in build_string_heap()
            auto guid = [&](uint32_t idx) { write_idx(out, idx, col_width_guid()); };
            guid(0); // MVID
            guid(0); // EncId
            guid(0); // EncBaseId
        }

        // Table 0x01: TypeRef
        for (auto& r : type_ref_table_) {
            write_coded(out, k_rs_tag_bits, r.scope_tag, r.scope_row, rs_w);
            str(r.name);
            str(r.ns);
        }

        // Table 0x02: TypeDef
        for (auto& r : type_def_table_) {
            le32(r.flags);
            str(r.name);
            str(r.ns);
            write_coded(out, k_tdr_tag_bits, r.extends_tag, r.extends_row, tdr_w);
            simple(0x04, r.field_list);
            simple(0x06, r.method_list);
        }

        // Table 0x04: Field
        for (auto& r : field_table_) {
            le16(r.flags);
            str(r.name);
            blob(r.sig);
        }

        // Table 0x06: MethodDef
        for (auto& r : method_def_table_) {
            le32(r.rva);
            le16(r.impl_flags);
            le16(r.flags);
            str(r.name);
            blob(r.sig);
            simple(0x08, r.param_list);
        }

        // Table 0x08: Param
        for (auto& r : param_table_) {
            le16(r.flags);
            le16(r.seq);
            str(r.name);
        }

        // Table 0x0A: MemberRef
        for (auto& r : member_ref_table_) {
            write_coded(out, k_mrp_tag_bits, r.class_tag, r.class_row, mrp_w);
            str(r.name);
            blob(r.sig);
        }

        // Table 0x0B: Constant
        for (auto& r : constant_table_) {
            le16(r.type);
            write_coded(out, k_hc_tag_bits, r.parent_tag, r.parent_row, hc_w);
            blob(r.value);
        }

        // Table 0x0C: CustomAttribute
        for (auto& r : custom_attribute_table_) {
            write_coded(out, k_hca_tag_bits, r.parent_tag, r.parent_row, hca_w);
            write_coded(out, k_cat_tag_bits, r.type_tag, r.type_row, cat_w);
            blob(r.value);
        }

        // Table 0x1A: ModuleRef (must come before ImplMap per ECMA-335 table ordering)
        for (auto& r : module_ref_table_) {
            str(r.name);
        }

        // Table 0x1C: ImplMap
        for (auto& r : impl_map_table_) {
            le16(r.flags);
            write_coded(out, k_mf_tag_bits, r.member_tag, r.member_row, mf_w);
            str(r.name);
            simple(0x1A, r.scope);
        }

        // Table 0x27: AssemblyRef
        for (auto& r : assembly_ref_table_) {
            le16(r.major);
            le16(r.minor);
            le16(r.build_num);
            le16(r.rev);
            le32(r.flags);
            blob(r.public_key);
            str(r.name);
            str(r.culture);
            blob(r.hash);
            blob(r.docs);
        }
    }
};

} // namespace wv
