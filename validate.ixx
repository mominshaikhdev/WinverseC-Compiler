// validate.ixx - SDK coverage tracking and validation
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
module;

#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <variant>
#include <filesystem>
#include <fstream>
#include <iostream>

export module winversec.validate;
import winversec.types;

export namespace wv {

class Validator {
public:
    State& st;
    explicit Validator(State& s) : st(s) {}

    struct Report {
        size_t total_headers=0, parsed_headers=0;
        size_t total_types=0, resolved_types=0;
        size_t total_funcs=0, resolved_funcs=0;
        size_t total_consts=0, resolved_consts=0;
        size_t unresolved_refs=0;
        std::vector<std::string> missing;
    };

    Report run(const std::filesystem::path& sdk_root, const std::string& version_dir) {
        Report r;
        auto base = sdk_root / "Include" / version_dir;
        for (auto& d : {"um","km","shared"}) {
            auto p = base / d;
            if (!std::filesystem::exists(p)) continue;
            for (auto& e : std::filesystem::recursive_directory_iterator(p)) {
                if (e.is_regular_file()) {
                    auto ext = e.path().extension().string();
                    // Case-insensitive extension check
                    bool is_hdr = false;
                    if (ext.size() >= 2) {
                        char c1 = (char)tolower((unsigned char)ext[0]);
                        if (c1 == '.') {
                            if (ext.size() == 2) is_hdr = (tolower((unsigned char)ext[1]) == 'h');
                            else if (ext.size() == 4) {
                                char a = tolower((unsigned char)ext[1]);
                                char b = tolower((unsigned char)ext[2]);
                                char c = tolower((unsigned char)ext[3]);
                                is_hdr = (a=='h' && b=='p' && c=='p') || (a=='h' && b=='x' && c=='x');
                            }
                        }
                    }
                    if (is_hdr) {
                        ++r.total_headers;
                        if (st.parsed_files.count(e.path().string())) ++r.parsed_headers;
                        else r.missing.push_back(e.path().string());
                    }
                }
            }
        }
        std::unordered_set<std::string> res;
        for (auto& it : st.items) {
            ++r.total_types;
            if (!it.def.name.empty()) res.insert(it.def.ns+"."+it.def.name);
            ++r.resolved_types;
            for (auto& m : it.def.meths) { ++r.total_funcs; ++r.resolved_funcs; }
            for (auto& f : it.def.fields) { if (!f.def.empty()) { ++r.total_consts; ++r.resolved_consts; } }
        }
        for (auto& it : st.items)
            for (auto& i : it.def.ifaces)
                if (res.count(i.ns+"."+i.name)==0) ++r.unresolved_refs;
        return r;
    }

    void print(const Report& r) {
        auto pct = [](size_t a, size_t b) -> int { return b>0 ? int(double(a)/double(b)*100.0) : 0; };
        std::cout << "\n  WINVERSE COVERAGE\n"
                  << "Headers: " << r.parsed_headers << "/" << r.total_headers
                  << " (" << pct(r.parsed_headers,r.total_headers) << "%)\n"
                  << "Types:   " << r.resolved_types << "/" << r.total_types
                  << " (" << pct(r.resolved_types,r.total_types) << "%)\n"
                  << "Funcs:   " << r.resolved_funcs << "/" << r.total_funcs
                  << " (" << pct(r.resolved_funcs,r.total_funcs) << "%)\n"
                  << "Consts:  " << r.resolved_consts << "/" << r.total_consts
                  << " (" << pct(r.resolved_consts,r.total_consts) << "%)\n"
                  << "Unresolved: " << r.unresolved_refs << "\n";
    }

    bool write_html(const Report& r, const std::string& path) {
        auto ws = std::filesystem::path(path).wstring();
#ifdef _WIN32
        if (ws.size() >= 260 && ws.substr(0, 4) != L"\\\\?\\")
            ws = L"\\\\?\\" + ws;
#endif
        std::ofstream f(ws);
        if (!f) return false;
        auto pct = [](size_t a, size_t b) -> int { return b>0 ? int(double(a)/double(b)*100.0) : 0; };
        auto esc = [](std::string s) {
            std::string o; o.reserve(s.size());
            for (char c : s) {
                switch (c) { case '&': o += "&amp;"; break; case '<': o += "&lt;"; break; case '>': o += "&gt;"; break; default: o += c; }
            }
            return o;
        };
        f << "<!DOCTYPE html><html><head><title>Winverse Coverage</title>"
          << "<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}"
          << ".bar{height:24px;background:#16213e;border-radius:4px;overflow:hidden;margin:8px 0}"
          << ".fill{height:100%;background:#0f3460;display:flex;align-items:center;padding:0 10px;font-size:13px}"
          << "h1{color:#e94560}h2{color:#aaa;margin-top:20px}"
          << "table{border-collapse:collapse;margin:8px 0;width:100%}"
          << "th,td{border:1px solid #333;padding:3px 8px;text-align:left;font-size:12px}"
          << "th{background:#16213e;color:#e94560}"
          << "details{margin:6px 0;padding:4px 10px;background:#16213e;border-radius:6px}"
          << "summary{cursor:pointer;color:#7fdbca;font-size:14px}"
          << ".win32{color:#e94560}.wdk{color:#ffa500}.wasdk{color:#7fdbca}"
          << "input{background:#0f3460;color:#e0e0e0;border:1px solid #333;padding:6px 10px;width:340px;font-family:monospace}"
          << "</style></head><body>"
          << "<h1>Winverse Coverage Report</h1>";
        auto bar = [&](const char* l, size_t d, size_t t) {
            f << "<h2>" << l << "</h2><div class='bar'><div class='fill' style='width:"
              << pct(d,t) << "%'>" << d << " / " << t << " (" << pct(d,t) << "%)</div></div>";
        };
        bar("Headers", r.parsed_headers, r.total_headers);
        bar("Types", r.resolved_types, r.total_types);
        bar("Functions", r.resolved_funcs, r.total_funcs);
        bar("Constants", r.resolved_consts, r.total_consts);
        f << "<h2>Unresolved References: " << r.unresolved_refs << "</h2>";

        // Per-namespace API detail: every Win32 / WDK / WASDK namespace
        // with its functions (signature + dll), types (kind + members),
        // constants (name + value) and contributing headers.
        struct ns_stat {
            size_t funcs = 0, types = 0, consts = 0, aliases = 0;
            std::vector<std::pair<std::string, std::string>> fn_rows;  // name+sig, dll
            std::vector<std::pair<std::string, std::string>> ty_rows;  // kind, name(+members)
            std::vector<std::pair<std::string, std::string>> const_rows; // name, value
            std::set<std::string> headers;
            bool wasdk = false, wdk = false;
        };
        std::map<std::string, ns_stat> ns_stats;
        auto extra_root_hit = [&](const std::string& file) {
            for (auto const& d : st.extra_include_dirs) {
                auto ds = d.string();
                if (ds.empty()) continue;
                // Windows paths are case-insensitive: a plain prefix compare
                // misses e.g. extra dir '.../include' vs file '.../Include/..'.
                if (file.size() < ds.size()) continue;
                bool pre = true;
                for (size_t i = 0; i < ds.size(); ++i) {
                    if (tolower((unsigned char)file[i]) !=
                        tolower((unsigned char)ds[i])) { pre = false; break; }
                }
                if (pre) return true;
            }
            return false;
        };
        auto et_name = [](const TRef& ref) -> std::string {
            std::string s;
            if (!ref.name.empty()) {
                s = ref.ns.empty() ? ref.name : ref.ns + "." + ref.name;
            } else {
                switch (ref.elem) {
                    case ET::Void: s = "void"; break;
                    case ET::Bool: s = "bool"; break;
                    case ET::Char: s = "wchar_t"; break;
                    case ET::I1: s = "i1"; break;
                    case ET::U1: s = "u1"; break;
                    case ET::I2: s = "i2"; break;
                    case ET::U2: s = "u2"; break;
                    case ET::I4: s = "i4"; break;
                    case ET::U4: s = "u4"; break;
                    case ET::I8: s = "i8"; break;
                    case ET::U8: s = "u8"; break;
                    case ET::R4: s = "r4"; break;
                    case ET::R8: s = "r8"; break;
                    case ET::String: s = "string"; break;
                    default: s = "?"; break;
                }
            }
            if (ref.fnptr) s = "fnptr<" + s + ">";
            s.append(ref.ptr, '*');
            return s;
        };
        auto cval_str = [&](const CVal& c) -> std::string {
            if (c.empty()) return {};
            if (auto* p = std::get_if<bool>(&c.v)) return *p ? "true" : "false";
            if (auto* p = std::get_if<uint8_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<int8_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<uint16_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<int16_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<uint32_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<int32_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<uint64_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<int64_t>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<float>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<double>(&c.v)) return std::to_string(*p);
            if (auto* p = std::get_if<std::u16string>(&c.v)) {
                std::string o = "\"";
                for (char16_t ch : *p) if (ch >= 0x20 && ch < 0x7F) o += (char)ch;
                return o + "\"";
            }
            return {};
        };
        auto kind_name = [](Kind k) -> const char* {
            switch (k) {
                case Kind::Iface: return "interface";
                case Kind::Enum: return "enum";
                case Kind::Struct: return "struct";
                case Kind::Union: return "union";
                case Kind::Delegate: return "delegate";
                case Kind::FnPtr: return "fnptr";
                case Kind::Const: return "consts";
                case Kind::Func: return "function";
                case Kind::Attr: return "attr";
                case Kind::Class: return "class";
            }
            return "type";
        };
        for (auto& it : st.items) {
            const std::string& ns = it.def.ns.empty() ? std::string("(global)") : it.def.ns;
            ns_stat& S = ns_stats[ns];
            if (!it.hdr.empty()) S.headers.insert(it.hdr);
            if (extra_root_hit(it.hdr)) S.wasdk = true;
            else if (ns.rfind("Windows.Wdk.", 0) == 0 || it.hdr.find("\\km\\") != std::string::npos || it.hdr.find("/km/") != std::string::npos) S.wdk = true;
            if (it.def.kind == Kind::Func) {
                ++S.funcs;
                if (!it.def.meths.empty()) {
                    const MSig& m = it.def.meths[0];
                    std::string sig = et_name(m.ret_r) + " " + it.def.name + "(";
                    for (size_t i = 0; i < m.params.size(); ++i) {
                        if (i) sig += ", ";
                        sig += et_name(m.pt[i]) + " " + m.params[i].name;
                    }
                    sig += ")";
                    S.fn_rows.push_back({ std::move(sig), it.def.import_library });
                }
            } else if (it.def.kind == Kind::Const) {
                for (auto& fld : it.def.fields) {
                    if (!fld.def.empty()) {
                        ++S.consts;
                        S.const_rows.push_back({ fld.name, cval_str(fld.def) });
                    } else {
                        // enum member without a stored value: still list it
                        ++S.consts;
                        S.const_rows.push_back({ fld.name, {} });
                    }
                }
                // A Const bucket item itself is not a "type"
                if (it.def.fields.empty()) { /* nothing */ }
            } else {
                ++S.types;
                bool alias = it.def.alias_elem != ET::Void || !it.def.alias_ref.name.empty() || it.def.alias_ref.ptr > 0;
                if (alias) ++S.aliases;
                std::string members;
                if (!it.def.fields.empty()) members = std::to_string(it.def.fields.size()) + " fields";
                if (!it.def.meths.empty()) {
                    if (!members.empty()) members += ", ";
                    members += std::to_string(it.def.meths.size()) + " methods";
                }
                if (alias) {
                    if (!members.empty()) members += ", ";
                    members += "alias = " + et_name(it.def.alias_ref);
                }
                S.ty_rows.push_back({ kind_name(it.def.kind), it.def.name + (members.empty() ? "" : "  (" + members + ")") });
            }
        }

        // Platform summary
        struct plat { size_t nss = 0, funcs = 0, types = 0, consts = 0; };
        std::map<std::string, plat> plats;
        for (auto& [ns, S] : ns_stats) {
            const char* p = S.wasdk ? "WASDK" : S.wdk ? "WDK" : "Win32";
            plats[p].nss++;
            plats[p].funcs += S.funcs;
            plats[p].types += S.types;
            plats[p].consts += S.consts;
        }
        f << "<h2>Platform summary</h2><table><tr><th>Platform</th><th>Namespaces</th><th>Functions</th><th>Types</th><th>Constants</th></tr>";
        for (auto& [p, s] : plats) {
            f << "<tr><td class='" << (p == "WDK" ? "wdk" : p == "WASDK" ? "wasdk" : "win32") << "'>" << p
              << "</td><td>" << s.nss << "</td><td>" << s.funcs << "</td><td>" << s.types << "</td><td>" << s.consts << "</td></tr>";
        }
        f << "</table>\n";

        // Filter box + per-namespace details (grouped by platform)
        f << "<h2>Namespace detail</h2>"
          << "<input id='nsfilter' type='text' placeholder='filter namespaces...' onkeyup=\"var v=this.value.toLowerCase();document.querySelectorAll('details[data-ns]').forEach(function(d){d.style.display=d.getAttribute('data-ns').includes(v)?'':'none';})\">";
        const char* plat_order[] = { "Win32", "WDK", "WASDK" };
        for (const char* plat : plat_order) {
            f << "<h2 class='" << (std::string(plat) == "WDK" ? "wdk" : std::string(plat) == "WASDK" ? "wasdk" : "win32") << "'>" << plat << "</h2>";
            for (auto& [ns, S] : ns_stats) {
                bool is_wd = S.wasdk, is_k = S.wdk;
                if (std::string(plat) == "WASDK" && !is_wd) continue;
                if (std::string(plat) == "WDK" && !is_k) continue;
                if (std::string(plat) == "Win32" && (is_wd || is_k)) continue;
                f << "<details data-ns='" << esc(ns) << "'><summary>" << esc(ns)
                  << " — " << S.funcs << " funcs, " << S.types << " types, " << S.consts << " consts, "
                  << S.aliases << " aliases</summary>";
                if (!S.headers.empty()) {
                    f << "<p style='color:#666;font-size:11px'>headers: ";
                    bool first = true;
                    for (auto const& h : S.headers) { if (!first) f << ", "; f << esc(std::filesystem::path(h).filename().string()); first = false; }
                    f << "</p>";
                }
                if (!S.fn_rows.empty()) {
                    f << "<table><tr><th>Function</th><th>Import library</th></tr>";
                    for (auto& [sig, dll] : S.fn_rows)
                        f << "<tr><td>" << esc(sig) << "</td><td>" << esc(dll) << "</td></tr>";
                    f << "</table>";
                }
                if (!S.ty_rows.empty()) {
                    f << "<table><tr><th>Kind</th><th>Type</th></tr>";
                    for (auto& [k, n] : S.ty_rows)
                        f << "<tr><td>" << k << "</td><td>" << esc(n) << "</td></tr>";
                    f << "</table>";
                }
                if (!S.const_rows.empty()) {
                    f << "<table><tr><th>Constant</th><th>Value</th></tr>";
                    for (auto& [n, v] : S.const_rows)
                        f << "<tr><td>" << esc(n) << "</td><td>" << esc(v) << "</td></tr>";
                    f << "</table>";
                }
                f << "</details>\n";
            }
        }
        f << "</body></html>";
        return true;
    }
};

} // namespace wv
