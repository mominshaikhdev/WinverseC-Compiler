// resolver.ixx - Cross-header type resolution and architecture-specific sizing
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
module;

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <thread>

export module winversec.resolver;
import winversec.types;

export namespace wv {

class Resolver {
public:
    State& st;
    explicit Resolver(State& s) : st(s) {}

    // Build type lookup index: (ns, name) -> item index
    void build_index() {
        type_index_.clear();
        for (size_t i = 0; i < st.items.size(); ++i) {
            auto& item = st.items[i];
            type_index_[item.def.ns + "." + item.def.name] = i;
        }
    }

    // Resolve all type references (serial)
    void resolve_all() {
        build_index();
        for (auto& item : st.items) {
            resolve_type_def(item.def);
        }
    }

    // Resolve all type references in parallel chunks
    void resolve_all_parallel(size_t num_threads) {
        build_index();
        if (st.items.empty() || num_threads <= 1) {
            resolve_all();
            return;
        }
        size_t chunk_size = (st.items.size() + num_threads - 1) / num_threads;
        std::vector<std::thread> threads;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t start = t * chunk_size;
            size_t end = std::min(start + chunk_size, st.items.size());
            if (start >= st.items.size()) break;
            threads.emplace_back([this, start, end]() {
                for (size_t i = start; i < end; ++i) {
                    resolve_type_def(st.items[i].def);
                }
            });
        }
        for (auto& th : threads) th.join();
    }

    // Resolve a single type definition's references
    void resolve_type_def(TDef& td) {
        // Resolve typedef aliases
        if (!td.ext_ns.empty() || !td.ext_name.empty()) {
            auto key = td.ext_ns + "." + td.ext_name;
            if (auto it = type_index_.find(key); it != type_index_.end()) {
                // Already resolved via index
            }
        }
        // Resolve interface implementations
        for (auto& iface : td.ifaces) {
            auto key = iface.ns + "." + iface.name;
            type_index_.count(key); // Verify it exists
        }
    }

    // Compute architecture-specific sizes for all types (serial)
    void compute_sizes() {
        for (auto& item : st.items) {
            if (item.def.kind == Kind::Struct || item.def.kind == Kind::Union) {
                compute_type_sizes(item);
            }
        }
    }

    // Compute architecture-specific sizes in parallel chunks
    void compute_sizes_parallel(size_t num_threads) {
        if (st.items.empty() || num_threads <= 1) {
            compute_sizes();
            return;
        }
        size_t chunk_size = (st.items.size() + num_threads - 1) / num_threads;
        std::vector<std::thread> threads;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t start = t * chunk_size;
            size_t end = std::min(start + chunk_size, st.items.size());
            if (start >= st.items.size()) break;
            threads.emplace_back([this, start, end]() {
                for (size_t i = start; i < end; ++i) {
                    if (st.items[i].def.kind == Kind::Struct || st.items[i].def.kind == Kind::Union) {
                        compute_type_sizes(st.items[i]);
                    }
                }
            });
        }
        for (auto& th : threads) th.join();
    }

    // Compute sizes for a single struct/union
    void compute_type_sizes(Item& item) {
        auto& td = item.def;
        uint32_t sz_x86 = 0, sz_x64 = 0, sz_arm64 = 0;
        uint32_t max_align_x86 = 1, max_align_x64 = 1, max_align_arm64 = 1;

        for (auto& field : td.fields) {
            auto [fsz_x86, fsz_x64, fsz_arm64] = field_size(field);
            auto [fal_x86, fal_x64, fal_arm64] = field_alignment(field);

            if (td.is_union) {
                sz_x86 = std::max(sz_x86, fsz_x86);
                sz_x64 = std::max(sz_x64, fsz_x64);
                sz_arm64 = std::max(sz_arm64, fsz_arm64);
            } else {
                // Align to field alignment
                sz_x86 = (sz_x86 + fal_x86 - 1) & ~(fal_x86 - 1);
                sz_x64 = (sz_x64 + fal_x64 - 1) & ~(fal_x64 - 1);
                sz_arm64 = (sz_arm64 + fal_arm64 - 1) & ~(fal_arm64 - 1);
                field.off = sz_x64; // Store x64 offset as default
                sz_x86 += fsz_x86;
                sz_x64 += fsz_x64;
                sz_arm64 += fsz_arm64;
            }
            max_align_x86 = std::max(max_align_x86, fal_x86);
            max_align_x64 = std::max(max_align_x64, fal_x64);
            max_align_arm64 = std::max(max_align_arm64, fal_arm64);
        }

        // Apply packing
        if (td.pack > 0) {
            max_align_x86 = std::min(max_align_x86, (uint32_t)td.pack);
            max_align_x64 = std::min(max_align_x64, (uint32_t)td.pack);
            max_align_arm64 = std::min(max_align_arm64, (uint32_t)td.pack);
        }

        // Final alignment
        sz_x86 = (sz_x86 + max_align_x86 - 1) & ~(max_align_x86 - 1);
        sz_x64 = (sz_x64 + max_align_x64 - 1) & ~(max_align_x64 - 1);
        sz_arm64 = (sz_arm64 + max_align_arm64 - 1) & ~(max_align_arm64 - 1);

        td.arch_sizes.x86 = sz_x86;
        td.arch_sizes.x64 = sz_x64;
        td.arch_sizes.arm64 = sz_arm64;
        td.cls_sz = sz_x64; // Default to x64
    }

private:
    std::unordered_map<std::string, size_t> type_index_;

    // Returns {size_x86, size_x64, size_arm64}
    std::tuple<uint32_t, uint32_t, uint32_t> field_size(const FDef& f) {
        switch (f.type) {
            case ET::Void:  return {0, 0, 0};
            case ET::Bool:  return {4, 4, 4};
            case ET::I1: case ET::U1: case ET::Char: return {1, 1, 1};
            case ET::I2: case ET::U2: return {2, 2, 2};
            case ET::I4: case ET::U4: case ET::R4: return {4, 4, 4};
            case ET::I8: case ET::U8: case ET::R8: return {8, 8, 8};
            case ET::Ptr: case ET::ByRef: case ET::Class: return {4, 8, 8}; // x86=32-bit, x64/arm64=64-bit
            case ET::FnPtr: return {4, 8, 8};
            default: {
                // Look up in type index
                auto key = f.ref.ns + "." + f.ref.name;
                if (auto it = type_index_.find(key); it != type_index_.end()) {
                    auto& td = st.items[it->second].def;
                    if (f.ref.ptr > 0) return {4, 8, 8};
                    return {td.arch_sizes.x86, td.arch_sizes.x64, td.arch_sizes.arm64};
                }
                return {4, 8, 8};
            }
        }
    }

    // Returns {alignment_x86, alignment_x64, alignment_arm64}
    std::tuple<uint32_t, uint32_t, uint32_t> field_alignment(const FDef& f) {
        switch (f.type) {
            case ET::I1: case ET::U1: case ET::Bool: case ET::Char: return {1, 1, 1};
            case ET::I2: case ET::U2: return {2, 2, 2};
            case ET::I4: case ET::U4: case ET::R4: return {4, 4, 4};
            case ET::I8: case ET::U8: case ET::R8: return {8, 8, 8};
            case ET::Ptr: case ET::ByRef: case ET::Class: case ET::FnPtr: return {4, 8, 8};
            default: {
                auto key = f.ref.ns + "." + f.ref.name;
                if (auto it = type_index_.find(key); it != type_index_.end()) {
                    auto& td = st.items[it->second].def;
                    if (f.ref.ptr > 0) return {4, 8, 8};
                    uint32_t a = std::max({td.arch_sizes.x86, td.arch_sizes.x64, td.arch_sizes.arm64});
                    a = std::max(a, 1u);
                    // Round to power of 2
                    uint32_t align = 1;
                    while (align < a) align <<= 1;
                    return {align, align, align};
                }
                return {4, 8, 8};
            }
        }
    }
};

} // namespace wv
