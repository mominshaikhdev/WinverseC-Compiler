// parser.ixx - Bulletproof C/C++ header parser for Winverse Compiler
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
// Every loop has iteration limits. Handles ALL SDK constructs.
// Long-path aware via \\?\ prefix.
module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <set>
#include <eh.h>
#include <cstdio>
#define NOMINMAX
#include <windows.h>

export module winversec.parser;
import winversec.types;
import winversec.preprocessor;
import winversec.sal;

static thread_local std::string g_last_ident;

// Declaration-specifier capture sink: skip_decl_specifiers records
// inline/__forceinline/__declspec(deprecated) hits here; the declaration
// parsers consume them into TDef::fn_flags. Thread-local because header
// parsing runs on multiple threads.
static thread_local uint32_t g_decl_flags_sink = 0;
static thread_local std::string g_decl_msg_sink;

// Workers record evaluated #define constants (CTL_CODE IOCTLs, IRP_MJ_
// codes) into shared State vectors concurrently — plain push_back from
// several threads corrupts the vector.
static std::mutex g_define_record_mtx;

static constexpr size_t FILE_ITER_LIMIT = 10000000;
static constexpr size_t BODY_ITER_LIMIT = 500000;
static constexpr size_t PARAM_ITER_LIMIT = 50000;

struct SehException : std::exception {
    DWORD code;
    SehException(DWORD c) : code(c), std::exception("SEH exception") {}
};

extern "C" static void __cdecl seh_translator(unsigned int code, _EXCEPTION_POINTERS*) {
    throw SehException(code);
}

static std::wstring long_path_w(const std::filesystem::path& p) {
    auto s = p.lexically_normal().wstring();
#ifdef _WIN32
    if (s.size() < 260) return s;
    if (s.substr(0, 4) == L"\\\\?\\") return s;
    return L"\\\\?\\" + s;
#else
    return s;
#endif
}

static std::string long_path(const std::filesystem::path& p) {
    return std::filesystem::path(long_path_w(p)).string();
}

static std::ifstream open_file_long(const std::filesystem::path& p) {
    auto ws = long_path_w(p);
    std::ifstream f(ws, std::ios::binary);
    if (!f.is_open()) {
        f = std::ifstream(p, std::ios::binary);
    }
    return f;
}

export namespace wv::parse {

class Parser {
public:
    State& st;
    Preprocessor& sal_init_pp;

    explicit Parser(State& s, Preprocessor& p) : st(s), sal_init_pp(p) {}

    bool parse_sdk(const std::filesystem::path& sdk_root, const std::string& version_dir) {
        auto base = sdk_root / "Include" / version_dir;
        auto um = base / "um";
        auto km = base / "km";
        auto shared = base / "shared";
        auto winrt = base / "winrt";   // C API headers (roapi.h, winstring.h, hstring.h) live here

        sal_init_pp.add_include_path(um);
        sal_init_pp.add_include_path(km);
        sal_init_pp.add_include_path(shared);
        sal_init_pp.add_include_path(winrt);
        sal_init_pp.init_standard_defines();
        sal_init_pp.init_sdk_defines(version_dir);

        std::vector<std::filesystem::path> files;
        if (!st.drivers_only && std::filesystem::exists(um)) collect_files(um, files);
        if (st.include_drivers && std::filesystem::exists(km)) collect_files(km, files);
        if (std::filesystem::exists(shared)) collect_files(shared, files);
        if (!st.drivers_only && std::filesystem::exists(winrt)) collect_files(winrt, files);

        // KMDF/UMDF framework headers do NOT live under Include/<ver>/{um,
        // km, shared} — the WDK ships them at Include/wdf/kmdf/<ver>/ and
        // Include/wdf/umdf/<ver>/, outside the versioned tree, so the walks
        // above never saw them and the entire WDF framework (WdfDeviceCreate
        // & co.) was absent from the winmd. Scan the newest installed
        // version of each flavor and register it as an include path so the
        // headers' <wdf*.h> includes resolve.
        if (st.include_drivers)
        {
            auto latest_version_dir = [](const std::filesystem::path& root) -> std::filesystem::path {
                std::error_code ec;
                if (!std::filesystem::is_directory(root, ec)) return {};
                std::filesystem::path best;
                std::vector<int> best_v;
                for (auto& e : std::filesystem::directory_iterator(root, ec)) {
                    if (!e.is_directory()) continue;
                    auto name = e.path().filename().string();
                    if (name.empty() || !std::isdigit((unsigned char)name[0])) continue;
                    std::vector<int> v;
                    int cur = 0;
                    bool in_num = false;
                    for (char c : name) {
                        if (std::isdigit((unsigned char)c)) { cur = cur * 10 + (c - '0'); in_num = true; }
                        else if (c == '.' && in_num) { v.push_back(cur); cur = 0; in_num = false; }
                        else break;
                    }
                    if (in_num) v.push_back(cur);
                    if (v.empty()) continue;
                    // numeric vector compare: [1,9] < [1,15] (string sort would get this wrong)
                    if (best.empty() || v > best_v) { best = e.path(); best_v = std::move(v); }
                }
                return best;
            };
            for (const char* flavor : { "kmdf", "umdf" }) {
                auto d = latest_version_dir(sdk_root / "Include" / "wdf" / flavor);
                if (d.empty()) continue;
                sal_init_pp.add_include_path(d);
                collect_files(d, files);
                st.wdf_dirs.push_back(d);
            }
        }

        // Extra include dirs (-include_dir, repeatable): scanned recursively
        // for headers the SDK does not already provide (e.g. the Windows App
        // SDK NuGet package's MddBootstrap.h). Dedup is SDK-first by file
        // stem, case-insensitive: an SDK for Windows 11 22H2 (build 22621)
        // or later ships its own dynamic-dependency headers, wins, and the
        // NuGet copy is skipped, so symbols are never declared twice.
        if (!st.extra_include_dirs.empty())
        {
            auto lower = [](std::string s) { for (auto& c : s) c = (char)std::tolower((unsigned char)c); return s; };
            std::set<std::string> sdk_stems;
            for (auto const& f : files) sdk_stems.insert(lower(f.stem().string()));
            for (auto const& extra_dir : st.extra_include_dirs)
            {
                if (extra_dir.empty() || !std::filesystem::exists(extra_dir))
                {
                    if (st.verbose) std::fprintf(stderr, "  Skipping missing extra include dir: %s\n", extra_dir.string().c_str());
                    continue;
                }
                std::vector<std::filesystem::path> extra_files;
                collect_files(extra_dir, extra_files);
                std::size_t added = 0;
                for (auto const& ef : extra_files)
                {
                    auto ext = ef.extension().string();
                    if (ext != ".h" && ext != ".hpp") continue;
                    auto stem = lower(ef.stem().string());
                    if (sdk_stems.count(stem)) continue;  // SDK already provides it
                    sdk_stems.insert(stem);
                    sal_init_pp.add_include_path(ef.parent_path());
                    files.push_back(ef);
                    ++added;
                }
                if (st.verbose) std::fprintf(stderr, "  Extra include dir %s: %zu new headers\n", extra_dir.string().c_str(), added);
            }
        }

        if (st.verbose) std::fprintf(stderr, "  Found %zu headers to parse\n", files.size());

        unsigned nthreads = std::max(1u, std::thread::hardware_concurrency());
        std::atomic<size_t> idx{0};
        std::atomic<size_t> done{0};
        std::atomic<size_t> total_types{0};
        std::atomic<size_t> total_funcs{0};
        std::mutex collect_mtx;

        auto worker = [&]() {
            _set_se_translator(seh_translator);

            while (true) {
                size_t i = idx.fetch_add(1);
                if (i >= files.size()) break;

                try {
                    // Fresh preprocessor state PER FILE. Carrying defines
                    // across files (the old layout) made active-gating
                    // order-dependent: a worker that parsed ntddk.h first
                    // (defines _NTDDK_) saw wdm.h's whole body — DRIVER_OBJECT,
                    // IRP, every dispatch typedef — under `#ifndef _NTDDK_`
                    // and skipped the file. Which worker got which files is
                    // a race, so km coverage varied run to run.
                    Preprocessor pp = sal_init_pp;
                    SalParser sal;
                    auto fname = files[i].string();
                    std::error_code fec;
                    auto fsize = std::filesystem::file_size(files[i], fec);
                    if (!fec && fsize > 20 * 1024 * 1024) {
                        size_t d = done.fetch_add(1) + 1;
                        st.files_parsed_atomic = d;
                        continue;
                    }
                    auto f = open_file_long(files[i]);
                    if (!f.is_open()) continue;
                    std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

                    std::vector<bool> ifdef_stack;
                    bool active = true;
                    std::vector<Item> local_items;
                    std::set<std::string> local_nss;
                    size_t lt = 0, lf = 0;

                    parse_file(src, fname, pp, sal,
                               ifdef_stack, active, local_items, local_nss, lt, lf);

                    {
                        std::lock_guard<std::mutex> lk(collect_mtx);
                        for (auto& it : local_items) st.items.push_back(std::move(it));
                        for (auto& ns : local_nss) st.nss.insert(ns);
                        st.parsed_files.insert(fname);
                        total_types += lt;
                        total_funcs += lf;
                    }
                } catch (const SehException& e) {
                    fprintf(stderr, "  SEH (0x%08lX) on %s\n", e.code, files[i].filename().string().c_str());
                } catch (const std::exception& e) {
                    fprintf(stderr, "  C++ Exception on %s: %s\n", files[i].filename().string().c_str(), e.what());
                } catch (...) {
                    fprintf(stderr, "  Exception in worker on file %zu: %s\n", i, files[i].filename().string().c_str());
                }

                size_t d = done.fetch_add(1) + 1;
                st.files_parsed_atomic = d;
                st.types_found_atomic = total_types.load();
                st.funcs_found_atomic = total_funcs.load();
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(nthreads);
        for (unsigned i = 0; i < nthreads; ++i)
            pool.emplace_back(worker);

        for (auto& t : pool) t.join();
        return true;
    }

private:
    static bool is_header_ext(const std::string& ext) {
        if (ext.size() < 2) return false;
        return (ext[0] == '.' || ext[0] == '.') &&
               ((ext[1] == 'h' || ext[1] == 'H') ||
                (ext.size() == 4 && ((ext[1]=='h'||ext[1]=='H') && (ext[2]=='p'||ext[2]=='P') && (ext[3]=='p'||ext[3]=='P'))) ||
                (ext.size() == 4 && ((ext[1]=='h'||ext[1]=='H') && (ext[2]=='x'||ext[2]=='X') && (ext[3]=='x'||ext[3]=='X'))));
    }

    void collect_files(const std::filesystem::path& dir, std::vector<std::filesystem::path>& out) {
        std::error_code ec;
        for (auto& e : std::filesystem::recursive_directory_iterator(dir, ec))
            if (e.is_regular_file()) {
                auto ext = e.path().extension().string();
                auto dirpart = e.path().parent_path().string();
                auto fname = e.path().filename().string();
                // Skip C++/WinRT projection headers (winrt/ subdirs) and
                // Windows.Foundation internal ABI headers (already in Windows.winmd)
                bool skip = false;
                auto dp = dirpart;
                std::transform(dp.begin(), dp.end(), dp.begin(), [](unsigned char c){ return (char)std::tolower(c); });
                bool in_winrt_dir = dp.find("\\winrt\\") != std::string::npos || dp.find("/winrt/") != std::string::npos;
                if (in_winrt_dir) {
                    // Keep the C API headers that live here (roapi.h, winstring.h, hstring.h,
                    // roerrorapi.h, ...); skip the C++/WinRT projection headers (windows.*.h, wrl/).
                    static const std::set<std::string> winrt_c_api_headers = {
                        "roapi.h", "winstring.h", "hstring.h", "roerrorapi.h",
                        "roparameterizediid.h", "roregistrationapi.h",
                        "rometadataresolution.h", "rometadataapi.h", "rometadata.h",
                    };
                    std::string fname_lower = fname;
                    std::transform(fname_lower.begin(), fname_lower.end(), fname_lower.begin(),
                                   [](unsigned char c) { return (char)std::tolower(c); });
                    skip = winrt_c_api_headers.count(fname_lower) == 0;
                }
                if (dp.find("windowsapp\\") != std::string::npos || dp.find("windowsapp/") != std::string::npos) skip = true;
                if (ext.size() >= 4 && (ext.substr(1) == "inl" || ext.substr(1) == "idl" ||
                    ext.substr(1) == "def" || ext.substr(1) == "rc")) skip = true;
                if (is_header_ext(ext) && !skip)
                    out.push_back(e.path());
            }
    }

    // main parse loop

    void parse_file(std::string_view src, const std::string& filename,
                    Preprocessor& pp, SalParser& sal,
                    std::vector<bool>& ifdef_stack, bool& active,
                    std::vector<Item>& items, std::set<std::string>& nss,
                    size_t& types_out, size_t& funcs_out) {
        size_t pos = 0;
        const size_t total = src.size();
        size_t iter = 0;

        // WV_DUMP=<substring>: dump the preprocessed text around every
        // occurrence of <substring> in each file's parse buffer, once, so
        // parse gaps can be traced to what the preprocessor actually hands
        // the parser (e.g. WV_DUMP=GetLastError).
        static const char* dump_needle = getenv("WV_DUMP");
        static std::mutex dump_mu;
        static std::unordered_set<std::string> dumped_files;
        if (dump_needle && *dump_needle) {
            size_t npos = src.find(dump_needle);
            if (npos != std::string_view::npos) {
                std::lock_guard<std::mutex> lk(dump_mu);
                if (dumped_files.insert(filename).second) {
                    size_t b = npos > 400 ? npos - 400 : 0;
                    std::fprintf(stderr, "\n===== WV_DUMP '%s' in %s =====\n%.*s\n===== END =====\n",
                        dump_needle, filename.c_str(),
                        (int)(npos + 300 - b), src.substr(b).data());
                }
            }
        }

        while (pos < total) {
            if (++iter > FILE_ITER_LIMIT) break;
            size_t start = pos;

            skip_ws(src, pos);
            if (pos >= total) break;

            char c = src[pos];

            if (c == '\n') { ++pos; continue; }

            // When inactive (#ifdef false / #else of active block), skip everything until matching #endif
            if (!active) {
                if (c == '#') {
                    auto line_start = pos + 1;
                    auto line_end = src.find('\n', line_start);
                    if (line_end == std::string_view::npos) line_end = src.size();
                    handle_pp(src.substr(line_start, line_end - line_start), pp, ifdef_stack, active);
                    skip_to_eol(src, pos);
                    continue;
                }
                skip_to_eol(src, pos);
                continue;
            }

            if (c == '/' && pos + 1 < total) {
                if (src[pos + 1] == '/') {
                    pos += 2;
                    while (pos < total && src[pos] != '\n') ++pos;
                    continue;
                }
                if (src[pos + 1] == '*') {
                    pos += 2;
                    skip_block_comment(src, pos);
                    continue;
                }
            }

            if (c == '#') {
                auto line_start = pos + 1;
                size_t dir_end = line_start;
                auto directive = join_continued(src, line_start, dir_end);
                handle_pp(directive, pp, ifdef_stack, active);
                pos = dir_end;
                continue;
            }

            if (c == ';' || c == '}' || c == '{') { ++pos; continue; }

            // C++ attributes: [[nodiscard]], [[deprecated]], [[maybe_unused]], [[...]]
            if (c == '[' && pos + 1 < src.size() && src[pos + 1] == '[') {
                skip_balanced(src, pos, '[', ']');
                continue;
            }

            // `extern "C" {` spelled through macros: WDF_EXTERN_C_START
            // (netpacketqueue.h, udecx*.h - immediately before the first
            // EVT_ callback typedef) and the ICU U_CDECL_BEGIN/END pair.
            // The parser reads raw text (macros are never rewritten), so
            // these land as bare identifiers: the following typedef gets
            // swallowed by skip_to_next_statement and the callback type
            // vanishes (C2039 EVT_PACKET_QUEUE_START / C2061
            // URegexMatchCallback in every consumer). Skip the token.
            if (active && (match_w(src, pos, "WDF_EXTERN_C_START") ||
                           match_w(src, pos, "WDF_EXTERN_C_END") ||
                           match_w(src, pos, "EXTERN_C_START") ||
                           match_w(src, pos, "EXTERN_C_END") ||
                           match_w(src, pos, "U_CDECL_BEGIN") ||
                           match_w(src, pos, "U_CDECL_END") ||
                           match_w(src, pos, "__BEGIN_DECLS") ||
                           match_w(src, pos, "__END_DECLS"))) {
                while (pos < src.size() && src[pos] != '_' &&
                       !std::isalnum((unsigned char)src[pos])) ++pos;
                while (pos < src.size() &&
                       (std::isalnum((unsigned char)src[pos]) || src[pos] == '_')) ++pos;
                continue;
            }
            if (match_w(src, pos, "extern")) {
                // extern "C" { ... } is just C linkage - parse the block normally
                // extern "SomeDLL" { ... } is DLL import vars - skip it
                size_t epos = pos + 6;
                skip_ws(src, epos);
                bool is_c_linkage = false;
                if (epos < src.size() && src[epos] == '"') {
                    auto s = epos + 1;
                    while (s < src.size() && src[s] != '"') ++s;
                    auto lang = src.substr(epos + 1, s - epos - 1);
                    is_c_linkage = (lang == "C" || lang == "C++");
                    epos = s + 1;
                }
                if (is_c_linkage) {
                    skip_ws(src, epos);
                    if (epos < src.size() && src[epos] == '{') { ++epos; }
                    pos = epos;
                } else {
                    skip_extern_block(src, pos);
                }
                continue;
            }
            // SAL annotations can sit BEFORE the `typedef` keyword (oprghdlr.h):
            //     _Function_class_(ACPI_OP_REGION_CALLBACK)
            //     _IRQL_requires_same_
            //     typedef PVOID EXPORT ACPI_OP_REGION_CALLBACK(...);
            // Leading annotations drop the statement into try_parse_func,
            // which records a bogus extern "C" function instead of the
            // callback delegate - every consumer typed with
            // `ACPI_OP_REGION_CALLBACK*` then fails C2061. Peek past a
            // leading run of `_`-prefixed annotations; if `typedef`
            // follows, route the statement to the typedef parser.
            {
                size_t peek = pos;
                int ann_count = 0;
                while (peek < src.size() && src[peek] == '_' && ann_count < 16) {
                    size_t before = peek;
                    auto id = read_ident(src, peek);
                    if (id.empty() || peek == before) break;
                    skip_ws(src, peek);
                    if (peek < src.size() && src[peek] == '(') skip_balanced(src, peek, '(', ')');
                    skip_ws_comments(src, peek);
                    ++ann_count;
                }
                if (ann_count > 0 && match_w(src, peek, "typedef")) {
                    pos = peek;
                }
            }
            if (match_w(src, pos, "typedef")) {
                parse_typedef(src, pos, filename, pp, sal, active, items, nss, types_out);
                continue;
            }
            if (match_w(src, pos, "struct")) {
                parse_struct_or_union(src, pos, filename, pp, active, items, nss, types_out, false);
                continue;
            }
            if (match_w(src, pos, "union")) {
                parse_struct_or_union(src, pos, filename, pp, active, items, nss, types_out, true);
                continue;
            }
            if (match_w(src, pos, "enum")) {
                parse_enum(src, pos, filename, pp, active, items, nss, types_out);
                continue;
            }
            if (match_w(src, pos, "DECLARE_INTERFACE") || match_w(src, pos, "MIDL_INTERFACE")) {
                parse_com_interface(src, pos, filename, pp, active, items, nss, types_out);
                continue;
            }

            // C11/C17/C23 keywords — skip gracefully
            if (active && match_w(src, pos, "static_assert")) {
                pos += 13; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == ';') ++pos;
                continue;
            }
            if (active && match_w(src, pos, "_Static_assert")) {
                pos += 14; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == ';') ++pos;
                continue;
            }

            // C++11/14/17/20/23 keywords — skip gracefully
            if (active && match_w(src, pos, "constexpr")) { pos += 9; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "consteval")) { pos += 9; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "constinit")) { pos += 9; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "noexcept")) { pos += 8; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "override")) { pos += 8; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "final")) { pos += 5; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "volatile")) { pos += 8; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "mutable")) { pos += 7; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "explicit")) { pos += 8; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "virtual")) { pos += 7; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "friend")) { pos += 6; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "register")) { pos += 8; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "thread_local")) { pos += 12; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "alignas")) {
                pos += 7; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                continue;
            }
            if (active && match_w(src, pos, "alignof")) {
                pos += 7; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                continue;
            }
            if (active && match_w(src, pos, "decltype")) {
                pos += 8; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                continue;
            }
            if (active && match_w(src, pos, "typeid")) { pos += 6; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "throw")) {
                pos += 5; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                continue;
            }
            if (active && match_w(src, pos, "try")) {
                pos += 3; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '{') skip_balanced(src, pos, '{', '}');
                continue;
            }
            if (active && match_w(src, pos, "catch")) {
                pos += 5; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '{') skip_balanced(src, pos, '{', '}');
                continue;
            }
            if (active && match_w(src, pos, "new")) {
                pos += 3; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                continue;
            }
            if (active && match_w(src, pos, "delete")) {
                pos += 6; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '[') skip_balanced(src, pos, '[', ']');
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                continue;
            }
            if (active && match_w(src, pos, "operator")) {
                pos += 8; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                else if (pos < src.size() && src[pos] == '[') skip_balanced(src, pos, '[', ']');
                else if (pos < src.size() && src[pos] == '"') { skip_string_literal(src, pos); skip_ws(src, pos); if (pos < src.size() && src[pos] == '"') skip_string_literal(src, pos); }
                else { while (pos < src.size() && !std::isspace((unsigned char)src[pos])) ++pos; skip_ws(src, pos); if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')'); }
                continue;
            }

            // C++ statement keywords that leak out of template/class member
            // bodies the parser does not model (DXTMPL.h's CDXArray<...>::GetAt
            // bodies). Without this, `return GetAt(nIndex);` parses as a
            // function named GetAt whose return TYPE is the keyword 'return'
            // — emitting `Windows::Win32::DXTMPL::return __stdcall GetAt(...)`.
            if (active && (match_w(src, pos, "return") || match_w(src, pos, "break") ||
                           match_w(src, pos, "continue") || match_w(src, pos, "goto") ||
                           match_w(src, pos, "case") || match_w(src, pos, "default:") ||
                           match_w(src, pos, "if") || match_w(src, pos, "else") ||
                           match_w(src, pos, "while") || match_w(src, pos, "for") ||
                           match_w(src, pos, "do") || match_w(src, pos, "switch"))) {
                skip_to_next_statement(src, pos);
                continue;
            }

            // C++ templates: template<...> — skip the entire template parameter list
            if (active && match_w(src, pos, "template")) {
                pos += 8; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '<') {
                    skip_balanced(src, pos, '<', '>');
                    skip_ws(src, pos);
                    // After template<...> there may be another keyword like "class", "struct", "typename", "constexpr", "friend", "typename...", "auto", "void"
                    // Just continue — the next iteration will handle the declaration
                } else if (pos < src.size() && src[pos] == '(') {
                    // template<auto> or similar
                    skip_balanced(src, pos, '(', ')');
                }
                continue;
            }

            // C++20 concepts and requires
            if (active && match_w(src, pos, "concept")) {
                pos += 7; skip_ws(src, pos);
                // Skip: concept Name = constraint-expression;
                skip_to_next_statement(src, pos);
                continue;
            }
            if (active && match_w(src, pos, "requires")) {
                pos += 8; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '{') skip_balanced(src, pos, '{', '}');
                continue;
            }

            // C++20 coroutines
            if (active && match_w(src, pos, "co_await")) { pos += 8; skip_ws(src, pos); continue; }
            if (active && match_w(src, pos, "co_return")) {
                pos += 9; skip_ws(src, pos);
                skip_to_next_statement(src, pos);
                continue;
            }
            if (active && match_w(src, pos, "co_yield")) {
                pos += 8; skip_ws(src, pos);
                skip_to_next_statement(src, pos);
                continue;
            }

            // C++20 modules
            if (active && match_w(src, pos, "module")) {
                pos += 6; skip_ws(src, pos);
                skip_to_next_statement(src, pos);
                continue;
            }
            if (active && match_w(src, pos, "import")) {
                pos += 6; skip_ws(src, pos);
                skip_to_next_statement(src, pos);
                continue;
            }
            if (active && match_w(src, pos, "export")) {
                pos += 6; skip_ws(src, pos);
                skip_to_next_statement(src, pos);
                continue;
            }

            // using enum (C++20)
            if (active && match_w(src, pos, "using")) {
                pos += 5; skip_ws(src, pos);
                // using namespace X; or using X::Y; or using enum X;
                skip_to_next_statement(src, pos);
                continue;
            }

            // C++ namespaces: namespace X { ... }
            if (active && match_w(src, pos, "namespace")) {
                pos += 9; skip_ws(src, pos);
                skip_ws(src, pos);
                // Skip name (may be nested a::b::c)
                while (pos < src.size() && (std::isalnum((unsigned char)src[pos]) || src[pos] == '_' || src[pos] == ':')) ++pos;
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '{') skip_balanced(src, pos, '{', '}');
                continue;
            }

            // class / struct / union forward declarations or definitions (non-Win32 C++ types)
            if (active && match_w(src, pos, "class")) {
                size_t saved_pos = pos;
                pos += 5; skip_ws(src, pos);
                // Check if this is a WinRT namespace like Windows::Foundation::IVector
                auto peek = src.substr(pos, std::min<size_t>(64, src.size() - pos));
                if (peek.find("Windows::") != std::string_view::npos ||
                    peek.find("winrt::") != std::string_view::npos ||
                    peek.find("Microsoft::") != std::string_view::npos) {
                    skip_to_next_statement(src, pos);
                    continue;
                }
                pos = saved_pos;
                // COM coclass declarations carry their CLSID here:
                //     class DECLSPEC_UUID("78a51822-...") ProcessDebugManager;
                // A bodyless class whose only declspec is a UUID is the
                // C++ spelling of an MIDL `coclass` — the SDK's authoritative
                // CLSID source (mirrors the uuid(...) on coclass blocks in the
                // .idl, which the scanner skips). Capture it as a Kind::Class
                // carrying com_iid so enrich emits ComCoClass + Guid (the
                // emission path already keys on kind==Class && !com_iid.empty()).
                {
                    size_t cp = pos + 5;
                    std::string_view cp_uuid;
                    // Scan declspecs + the class name; bail on any body/inheritance.
                    for (int g = 0; g < 8; ++g) {
                        skip_ws_comments(src, cp);
                        if (match_w(src, cp, "DECLSPEC_UUID")) {
                            cp += 13; skip_ws(src, cp);
                            if (cp < src.size() && src[cp] == '(') {
                                ++cp; skip_ws(src, cp);
                                if (cp < src.size() && src[cp] == '"') {
                                    ++cp;
                                    size_t qs = cp;
                                    while (cp < src.size() && src[cp] != '"') ++cp;
                                    cp_uuid = src.substr(qs, cp - qs);
                                    if (cp < src.size()) ++cp;
                                }
                                skip_ws(src, cp);
                                if (cp < src.size() && src[cp] == ')') ++cp;
                            }
                            continue;
                        }
                        // Any other __declspec / attribute before the name
                        // is tolerated; a bare identifier NOT followed by '('
                        // is the class name — rewind so the read_ident below
                        // captures it (the name sits on the next line after
                        // the DECLSPEC_UUID macro).
                        if (src[cp] == '_' || std::isalpha((unsigned char)src[cp])) {
                            size_t before = cp;
                            read_ident(src, cp);
                            skip_ws_comments(src, cp);
                            if (cp < src.size() && src[cp] == '(') {
                                skip_balanced(src, cp, '(', ')');
                                continue;
                            }
                            cp = before;
                        }
                        break;
                    }
                    skip_ws_comments(src, cp);
                    auto cname = read_ident(src, cp);
                    skip_ws_comments(src, cp);
                    // Bodyless, no inheritance, carries a UUID -> coclass.
                    bool bodyless = cp < src.size() && src[cp] == ';';
                    if (!cname.empty() && !cp_uuid.empty() && bodyless) {
                        std::string ns = map_ns(filename);
                        TDef td; td.kind = Kind::Class; td.ns = ns; td.name = std::string(cname);
                        td.attr = TA::Pub; td.source_header = filename;
                        td.is_com_interface = true;
                        td.com_iid = std::string(cp_uuid);
                        items.push_back({std::move(td), pp.current_arch(), filename});
                        nss.insert(ns);
                        ++types_out;
                        ++cp; // consume ';'
                        pos = cp;
                        continue;
                    }
                }
                // C++ class definitions (GDI+ SizeF/PointF, ...) carry
                // constructors, member functions and inheritance - pure C++
                // artifacts with no C ABI. Emit them neither as structs nor
                // as functions: skip the whole definition so nothing leaks
                // into the language-agnostic metadata (the old fall-through
                // let try_parse_func parse constructors as free extern "C"
                // functions that collided with same-named structs).
                {
                    size_t p = pos + 5;
                    // Decoration MACROS can sit between `class` and the
                    // name (ChString.h: `class POLARITY CHString`). The
                    // macro name is not followed by another identifier -
                    // skip tokens that are, so the real name is found and
                    // the body is actually skipped (otherwise the parser
                    // resumes mid-declaration and every member leaks as a
                    // free extern "C" function: CHSTRING's GetData/Init/
                    // AllocCopy... plus a missing CHString type = C2039).
                    for (int g = 0; g < 8; ++g) {
                        skip_ws(src, p);
                        size_t look = p;
                        auto tok = read_ident(src, look);
                        if (tok.empty()) break;
                        skip_ws(src, look);
                        // another identifier follows -> `tok` was a macro
                        if (look < src.size() &&                            (std::isalpha((unsigned char)src[look]) || src[look] == '_')) {
                            p = look;
                            continue;
                        }
                        break;
                    }
                    skip_ws(src, p);
                    auto real_name = read_ident(src, p);
                    skip_ws(src, p);
                    if (p < src.size() && src[p] == '<') skip_balanced(src, p, '<', '>');
                    skip_ws(src, p);
                    if (p < src.size() && src[p] == ':') { while (p < src.size() && src[p] != '{' && src[p] != ';') ++p; }
                    bool has_body = p < src.size() && src[p] == '{';
                    if (has_body) skip_balanced(src, p, '{', '}');
                    skip_ws(src, p);
                    if (p < src.size() && src[p] == ';') ++p;
                    pos = p;
                    // Record the class as an opaque struct so consumers
                    // typed with it (CHSTRARR holds CHString** fields,
                    // PROVIDER signatures) still resolve; the body stays
                    // unmodeled.
                    if (has_body && !real_name.empty()) {
                        std::string ns = map_ns(filename);
                        TDef td; td.kind = Kind::Struct; td.ns = ns;
                        td.name = std::string(real_name); td.attr = TA::Pub;
                        td.source_header = filename;
                        items.push_back({std::move(td), pp.current_arch(), filename});
                        nss.insert(ns);
                        ++types_out;
                    }
                }
                continue;
            }

            if (active && match_w(src, pos, "DECLARE_HANDLE")) {
                pos += 14; skip_ws(src, pos);
                // The handle name is the MACRO ARGUMENT. Reading it from
                // the stale g_last_ident (leftover from the last read_type
                // call — often a ULONG64 field right before the
                // DECLARE_HANDLE) emitted bogus `class ULONG64` items in
                // WinSock/USBIOCTL and silently dropped every real handle
                // type (HIFTIMESTAMPCHANGE, USB_CHANGE_REGISTRATION_HANDLE).
                std::string hname;
                if (pos < src.size() && src[pos] == '(') {
                    size_t save = pos;
                    ++pos; skip_ws(src, pos);
                    auto id = read_ident(src, pos);
                    hname = std::string(id);
                    skip_ws(src, pos);
                    if (pos < src.size() && src[pos] == ')') ++pos;
                    else { pos = save; skip_balanced(src, pos, '(', ')'); }
                }
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == ';') ++pos;
                std::string ns = map_ns(filename);
                if (!hname.empty()) {
                    TDef td; td.kind = Kind::Class; td.ns = ns; td.name = hname;
                    td.attr = TA::Pub; td.source_header = filename;
                    items.push_back({std::move(td), pp.current_arch(), filename});
                    nss.insert(ns);
                    ++types_out;
                }
                continue;
            }

            if (active && match_w(src, pos, "DEFINE_GUID")) {
                pos += 11; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') { skip_balanced(src, pos, '(', ')'); }
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == ';') ++pos;
                continue;
            }

            if (active && match_w(src, pos, "DEFINE_DEVOPGUID")) {
                pos += 17; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') { skip_balanced(src, pos, '(', ')'); }
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == ';') ++pos;
                continue;
            }

            if (try_parse_func(src, pos, filename, pp, sal, active, items, nss, funcs_out)) {
                continue;
            }

            skip_to_next_statement(src, pos);
            if (pos == start) { ++pos; }
        }
    }

    // preprocessor handling

    void handle_pp(std::string_view directive, Preprocessor& pp,
                   std::vector<bool>& ifdef_stack, bool& active) {
        auto t = tr(directive);
        if (t.starts_with("include")) return;
        if (t.starts_with("pragma")) return;
        if (t.starts_with("error")) return;
        if (t.starts_with("warning")) return;
        if (t.starts_with("line")) return;
        if (t.starts_with("define")) {
            // Inactive-branch defines must NOT take effect: SDK headers use
            // version-selection ladders (#define _WIN32_WINNT 0x0400 ...)
            // inside inactive regions, and recording them clobbers the
            // initialized 0x0A00 target - silently hiding every API gated
            // by a higher version check (threadpoolapiset's `#if (_WIN32_WINNT >= 0x0600)`).
            if (!active) return;
            auto after = tr(t.substr(6));
            auto sp = after.find(' ');
            if (sp != std::string_view::npos) {
                auto nm = tr(after.substr(0, sp));
                auto val = tr(after.substr(sp + 1));
                if (!nm.empty() && nm.front() != '(') {
                    pp.set_define(std::string(nm), std::string(val));
                    // IOCTL/FSCTL codes are #define'd through the CTL_CODE
                    // function-like macro, which never becomes an enum
                    // member — evaluate and record them for the enricher.
                    if ((nm.starts_with("IOCTL_") || nm.starts_with("FSCTL_")) &&
                        val.find("CTL_CODE(") != std::string_view::npos) {
                        uint32_t code = 0;
                        if (pp.eval_ctl_code(val, code)) {
                            std::lock_guard<std::mutex> lk(g_define_record_mtx);
                            pp.st.ioctl_consts.push_back({ std::string(nm), code });
                        }
                    }
                    // IRP major-function codes: `#define IRP_MJ_CREATE 0x00`
                    // in wdm.h — never enum members, so record them for the
                    // enricher to materialize (IrpMajorFunction attr).
                    if (nm.rfind("IRP_MJ_", 0) == 0 && nm != "IRP_MJ_MAXIMUM_FUNCTION") {
                        uint32_t code = 0;
                        if (pp.eval_macro_int(val, code)) {
                            std::lock_guard<std::mutex> lk(g_define_record_mtx);
                            pp.st.irp_mj_consts.push_back({ std::string(nm), code });
                        }
                    }
                }
            } else if (!after.empty()) {
                auto nm = tr(after);
                if (!nm.empty() && nm.front() != '(') {
                    pp.set_define(std::string(nm));
                }
            }
        } else if (t.starts_with("undef")) {
            if (active) {
                pp.undefine(tr(t.substr(5)));
            }
        } else if (t.starts_with("ifdef")) {
            ifdef_stack.push_back(active);
            active = active && pp.eval_ifdef(tr(t.substr(5)));
        } else if (t.starts_with("ifndef")) {
            ifdef_stack.push_back(active);
            active = active && !pp.eval_ifdef(tr(t.substr(6)));
        } else if (t.starts_with("if ")) {
            ifdef_stack.push_back(active);
            active = active && pp.eval_if(tr(t.substr(3)));
        } else if (t.starts_with("if\t")) {
            ifdef_stack.push_back(active);
            active = active && pp.eval_if(tr(t.substr(3)));
        } else if (t.starts_with("if(")) {
            ifdef_stack.push_back(active);
            active = active && pp.eval_if(tr(t.substr(2)));
        } else if (t.starts_with("elif")) {
            if (!ifdef_stack.empty()) {
                auto prev = ifdef_stack.back();
                active = prev && !active && pp.eval_if(tr(t.substr(4)));
            }
        } else if (t.starts_with("else")) {
            if (!ifdef_stack.empty()) {
                auto prev = ifdef_stack.back();
                active = prev && !active;
            }
        } else if (t.starts_with("endif")) {
            if (!ifdef_stack.empty()) {
                active = ifdef_stack.back();
                ifdef_stack.pop_back();
            }
        }
    }

    // construct parsers

    void parse_typedef(std::string_view src, size_t& pos, const std::string& file,
                       Preprocessor& pp, SalParser& sal, bool active,
                       std::vector<Item>& items, std::set<std::string>& nss, size_t& types_out) {
        if (!active) { skip_to_next_statement(src, pos); return; }
        skip_ws(src, pos);

        // Consume the 'typedef' keyword itself. The dispatcher above matches
        // "typedef" with match_w() but does not advance past it; without this
        // consumption every subsequent match_w() here probed AT the typedef
        // token (always false), so read_type() swallowed 'typedef' as the
        // type name and the real declaration was mangled - typedef struct
        // bodies never reached parse_struct_or_union (this is why
        // PACKAGE_VERSION / PACKAGE_ID were missing from Windows.Win32.winmd
        // while sibling anon-union types landed).
        if (match_w(src, pos, "typedef")) { pos += 7; skip_ws(src, pos); }

        if (match_w(src, pos, "struct")) {
            parse_struct_or_union(src, pos, file, pp, active, items, nss, types_out, false);
            return;
        }
        if (match_w(src, pos, "union")) {
            parse_struct_or_union(src, pos, file, pp, active, items, nss, types_out, true);
            return;
        }
        if (match_w(src, pos, "enum")) {
            parse_enum(src, pos, file, pp, active, items, nss, types_out);
            return;
        }

        if (lookahead_fnptr(src, pos)) {
            parse_fnptr(src, pos, file, pp, active, items, nss);
            return;
        }

        // SAL annotations sit between 'typedef' and the return type:
        //     typedef _Function_class_(RTL_UMS_SCHEDULER_ENTRY_POINT) VOID
        //             NTAPI RTL_UMS_SCHEDULER_ENTRY_POINT(...);
        // read_type has no SAL handling: it recorded _Function_class_ as a
        // named class, the real return type became the alias name, and the
        // declaration degraded into a bogus function row (C2039 in every
        // consumer that typed a struct field with the true name). Skip
        // decl-specifiers and SAL annotations first so read_type sees the
        // actual return type.
        g_decl_flags_sink = 0;
        g_decl_msg_sink.clear();
        skip_decl_specifiers(src, pos, true);
        // The no-pointer-star callback form (`typedef _Function_class_(X)
        // RET NAME(...)`) reaches the delegate branch below; the semantic
        // class annotation is consumed here by parse_all, so capture it.
        std::string typedef_fn_class;
        for (auto const& ann : sal.parse_all(src, pos)) {
            if (ann.kind == SalKind::FunctionClass) typedef_fn_class = ann.count_expr;
        }
        auto type = read_type(src, pos);
        skip_ws(src, pos);
        // Decoration macros interleave with pointer stars between the
        // target type and the alias name (`typedef SOCKADDR_IN6_LH FAR
        // *LPSOCKADDR_IN6;`, `typedef PNEVCONTEXT FAR *LPFNEVCONTEXT;`).
        // read_type only skips these on the fundamental path; on the named
        // path the macro landed as the alias name -> bogus `class FAR`
        // debris in every far-pointer typedef.
        uint32_t tail_ptr = 0;
        for (int guard = 0; guard < 8; ++guard) {
            skip_ws(src, pos);
            bool progressed = false;
            for (auto const& dm : { "FAR", "NEAR", "__RPC_FAR", "far", "near" }) {
                if (match_w(src, pos, dm)) { pos += std::strlen(dm); skip_ws(src, pos); progressed = true; break; }
            }
            if (!progressed && pos < src.size() && src[pos] == '*') { ++tail_ptr; ++pos; skip_ws(src, pos); progressed = true; }
            if (!progressed) break;
        }
        // Function-type typedefs put the calling convention between the
        // return type and the alias name:
        //     typedef VOID NTAPI RTL_UMS_SCHEDULER_ENTRY_POINT(...);
        // Without skipping it, NTAPI became the alias name, the real name
        // fell to the function parser as a bogus extern "C" row, and every
        // field typed with the true name resolved to nothing (C2039).
        skip_calling_convention(src, pos);
        auto name = read_ident(src, pos);
        if (name.empty()) { skip_to_next_statement(src, pos); return; }
        // Macro-heavy headers leave parse debris whose "name" is a C++
        // keyword or fundamental type name (typedef ... char;). Recording
        // those aliases poisons every downstream C++ projection: consumers
        // emit `std::uint32_t char;` members and illegal type names. Skip.
        {
            static const std::set<std::string_view> cxx_kw = {
                "void","char","short","int","long","float","double","signed","unsigned",
                "bool","struct","class","union","enum","const","volatile","typedef",
                "default","auto","register","template","typename","operator","new","delete",
                "this","using","namespace","static","extern","goto","sizeof","alignas"
            };
            if (cxx_kw.count(name)) { skip_to_next_statement(src, pos); return; }
        }
        skip_ws(src, pos);
        // Function-type typedef WITHOUT the pointer star:
        //     typedef VOID NTAPI RTL_UMS_SCHEDULER_ENTRY_POINT(...);
        //     typedef NTSTATUS DRIVER_INITIALIZE(...);
        // read_type consumed the return type and the alias name is the
        // function-type identifier; the following '(' opens the parameter
        // list. Left to the function parser this became a bogus C function
        // row (RTL_UMS_SCHEDULER_ENTRY_POINT emitted as an extern "C" fn)
        // while struct fields typed with it resolved to nothing (C2039).
        // Record a callback delegate exactly like the pointer form
        // (parse_fnptr).
        if (pos < src.size() && src[pos] == '(' && pos + 1 < src.size() && src[pos + 1] != '*') {
            ++pos; // consume '('
            std::vector<PDef> params;
            parse_param_list(src, pos, params);
            if (pos < src.size() && src[pos] == ')') ++pos;
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == ';') ++pos;
            std::string fns = map_ns(file);
            TDef ftd; ftd.kind = Kind::Delegate; ftd.ns = fns; ftd.name = std::string(name);
            ftd.attr = TA::Pub; ftd.is_callback = true;
            ftd.source_header = file;
            ftd.fn_class = std::move(typedef_fn_class);
            MSig fsig; fsig.ret = type.elem; fsig.ret_r = type.ref;
            fsig.cc = CC::Std; fsig.params = std::move(params);
            ftd.meths.push_back(std::move(fsig));
            items.push_back({std::move(ftd), pp.current_arch(), file});
            nss.insert(fns);
            ++types_out;
            return;
        }
        if (pos < src.size() && src[pos] == ';') ++pos;

        std::string ns = map_ns(file);
        // Comma-separated declarator list sharing one base type:
        //     typedef _Null_terminated_ CONST WCHAR *LPCWCH, *PCWCH;
        // The old code bailed at the comma and dropped every declarator
        // after the first, so LPCWCH/PCWCH/LPCCH... never became aliases,
        // resolve_alias_chain failed, and every param typed with them        // degraded to an opaque System.Object signature (void* in C++,        // const lost). Record each declarator with its own pointer depth.
        static const std::set<std::string_view> cxx_kw2 = {
            "void","char","short","int","long","float","double","signed","unsigned",
            "bool","struct","class","union","enum","const","volatile","typedef",
            "default","auto","register","template","typename","operator","new","delete"
        };
        for (int decl = 0; ; ++decl)
        {
            std::string dname;
            uint32_t dptr = 0;
            if (decl == 0)
            {
                dname = std::string(name);
                dptr = tail_ptr;
            }
            else
            {
                // stars / decoration macros between ',' and the declarator name
                for (int guard = 0; guard < 8; ++guard)
                {
                    skip_ws(src, pos);
                    bool progressed = false;
                    for (auto const& dm : { "FAR", "NEAR", "__RPC_FAR", "far", "near" }) {
                        if (match_w(src, pos, dm)) { pos += std::strlen(dm); progressed = true; break; }
                    }
                    if (progressed) continue;
                    if (pos < src.size() && src[pos] == '*') { ++dptr; ++pos; progressed = true; }
                    if (!progressed) break;
                }
                skip_ws(src, pos);
                dname = std::string(read_ident(src, pos));
            }
            if (dname.empty() || cxx_kw2.count(dname))
            {
                while (pos < src.size() && src[pos] != ',' && src[pos] != ';') ++pos;
            }
            else if (pos < src.size() && src[pos] == '(')
            {
                // function-typed declarator inside a list: skip its params
                skip_balanced(src, pos, '(', ')');
            }
            else
            {
                TDef td; td.kind = Kind::Class; td.ns = ns; td.name = dname;
                td.attr = TA::Pub; td.ext_ns = type.ref.ns; td.ext_name = type.ref.name;
                // Underlying type for simple typedefs: record the raw target
                // TRef and let the emit layer resolve chains transitively
                // (alias of alias, PSID -> void*, PHCOMDB -> void**, CLSID ->
                // GUID) and substitute the fully resolved shape into every
                // signature, keeping the metadata language-agnostic.
                // Pointer/fnptr targets are recorded too (alias_ref carries
                // the pointer level). ET::Void + empty ref = "not a simple alias".
                td.alias_elem = type.elem;
                td.alias_ref = type.ref;
                td.alias_ref.elem = type.elem;
                // read_type's type_map synthesizes pointer rows for
                // well-known pointer typedefs (PDWORD -> {Ptr,"DWORD",1},
                // HANDLE -> {Ptr,"HANDLE",1}). Recording that row verbatim
                // inflated the alias's pointer depth: `typedef HANDLE
                // HLOCAL` became "pointer to HANDLE" (HANDLE**), and
                // param signatures typed with HLOCAL/LocalFree accumulated
                // one extra '*' per encode-time re-resolution (void****).
                // A Ptr element with a named pointer-depth-1 target is
                // always synthetic: record the alias as a plain alias of
                // the named target so the chain resolves naturally.
                if (type.elem == ET::Ptr && !type.ref.name.empty() && type.ref.ptr == 1)
                {
                    td.alias_elem = ET::Class;
                    td.alias_ref.elem = ET::Class;
                    td.alias_ref.ptr = 0;
                }
                // Pointer-depth model for declarator lists: each
                // declarator inherits the base type's pointer depth (from
                // type.ref.ptr) and adds its own stars.  The old code
                // overwrote with just the declarator's stars for decl>0
                // (`= dptr`), which lost the base pointer depth when the
                // base type was itself a pointer (HANDLE -> void*):
                // `typedef HANDLE RTM_DEST_HANDLE` got ptr=0 instead of 1,
                // encoding a bare 0x0F with no pointee byte — cppwinc then
                // consumed the NEXT param's type as the pointee, producing
                // PTR(BOOL) and truncating the blob.
                // Declarator-list pointer depth: base depth (from
                // type.ref.ptr) plus each declarator's own stars. Two
                // corrections here:
                //  - decl-0 stars: read_type already consumed the leading
                //    `*` from the source into stars_from_source, so those
                //    count as decl-0's own stars (tail_ptr misses them).
                //  - decl>0 stars: the source `*` belongs to the
                //    declarator, so subtract stars_from_source from the
                //    base depth before adding dptr, otherwise it
                //    double-counts (`typedef WCHAR *LPWCH, *LPWSTR` ->
                //    LPWSTR at depth 2 instead of 1).
                uint32_t underlying_ptr = 0;
                if (type.ref.ptr >= type.stars_from_source)
                    underlying_ptr = type.ref.ptr - type.stars_from_source;
                uint32_t dptr_eff = (decl == 0) ? (dptr + type.stars_from_source) : dptr;
                td.alias_ref.ptr = underlying_ptr + dptr_eff;
                if (td.alias_ref.name == dname && td.alias_ref.ptr == 0)
                    { td.alias_elem = ET::Void; td.alias_ref = TRef{}; }
                td.source_header = file;
                td.fn_flags = g_decl_flags_sink;
                td.deprecation_msg = g_decl_msg_sink;
                items.push_back({std::move(td), pp.current_arch(), file});
                nss.insert(ns);
                ++types_out;
            }
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == ',') { ++pos; continue; }
            if (pos < src.size() && src[pos] == ';') ++pos;
            break;
        }
    }

    void parse_struct_or_union(std::string_view src, size_t& pos, const std::string& file,
                               Preprocessor& pp, bool active,
                               std::vector<Item>& items, std::set<std::string>& nss,
                               size_t& types_out, bool is_union) {
        if (!active) { skip_to_next_statement(src, pos); return; }
        skip_ws(src, pos);

        size_t kw_start = pos;
        if (match_w(src, pos, "struct")) { pos += 6; }
        else if (match_w(src, pos, "union")) { pos += 6; }
        skip_ws(src, pos);

        skip_decl_specifiers(src, pos);
        skip_ws(src, pos);

        // Decoration macros can sit between 'struct' and the tag:
        // `typedef struct FARSTRUCT tagCY {...}` (WabDefs.h; FARSTRUCT
        // expands to FAR/empty in combaseapi.h). Skipping only known
        // declaration specifiers leaves the macro name as the tag and
        // seeds a bogus `struct FAR` type. Drop empty/annotation macros
        // here the same way read_type does in type position.
        {
            static const std::unordered_set<std::string_view> deco_macros = {
                "FAR", "NEAR", "far", "near", "IN", "OUT", "OPTIONAL",
                "FARSTRUCT", "HUGE", "APIENTRY", "WINAPI", "CALLBACK",
                "PASCAL", "CDECL", "EXTERN_C", "__RPC_FAR",
            };
            for (int guard = 0; guard < 8; ++guard) {
                skip_ws(src, pos);
                bool skipped = false;
                for (auto const& dm : deco_macros) {
                    if (match_w(src, pos, dm)) { pos += dm.size(); skip_ws(src, pos); skipped = true; break; }
                }
                if (!skipped) break;
            }
        }

        auto name = read_ident(src, pos);
        skip_ws(src, pos);

        if (pos < src.size() && src[pos] == ':') {
            ++pos;
            skip_to_next_statement(src, pos);
            return;
        }

        if (pos < src.size() && src[pos] == '{') {
            ++pos;
            std::string ns = map_ns(file);
            TDef td; td.kind = is_union ? Kind::Union : Kind::Struct;
            td.ns = ns; td.name = name; td.attr = TA::Pub; td.is_union = is_union;
            td.source_header = file;
            parse_struct_body(src, pos, td, std::string(name), pp, items, nss, file);
            items.push_back({std::move(td), pp.current_arch(), file});
            nss.insert(ns);
            ++types_out;
        } else {
            // Forward declaration and/or typedef alias list:
            //     struct _TP_POOL;                                (plain fwd decl)
            //     typedef struct _TP_POOL TP_POOL, *PPTP_POOL;   (aliases: first
            //         directly after the tag, subsequent after commas, each
            //         optionally pointer-typed)
            // The tag is emitted as an opaque struct; every alias becomes an
            // alias typedef (parse_typedef precedent) so signatures typed
            // PTP_POOL/PPTP_POOL resolve to the real shape instead of
            // collapsing to void.
            skip_ws(src, pos);
            std::vector<std::pair<std::string, bool>> aliases;
            if (pos < src.size() && src[pos] != ';' && src[pos] != ',') {
                // First alias can be pointer-typed with the '*' BEFORE the
                // name: typedef struct tagServerInformation *PServerInformation;
                bool first_ptr = false;
                size_t save = pos;
                skip_ws(src, pos);
                // Decoration macros interleave with '*' here too
                // (`FAR * LPNS_INFOA`, `* FAR LPWSAMSG`).
                for (int guard = 0; guard < 8; ++guard) {
                    skip_ws(src, pos);
                    bool progressed = false;
                    for (auto const& dm : { "FAR", "NEAR", "__RPC_FAR", "far", "near" }) {
                        if (match_w(src, pos, dm)) { pos += std::strlen(dm); skip_ws(src, pos); progressed = true; break; }
                    }
                    if (!progressed && pos < src.size() && src[pos] == '*') { first_ptr = true; ++pos; skip_ws(src, pos); progressed = true; }
                    if (!progressed) break;
                }
                auto a1 = read_ident(src, pos);
                if (!a1.empty()) aliases.push_back({ std::string(a1), first_ptr });
                else pos = save;
            }
            for (;;) {
                skip_ws(src, pos);
                if (pos >= src.size() || src[pos] != ',') break;
                ++pos; skip_ws(src, pos);
                bool ptr_alias = false;
                // Decoration macros interleave with '*' (see above).
                for (int guard = 0; guard < 8; ++guard) {
                    skip_ws(src, pos);
                    bool progressed = false;
                    for (auto const& dm : { "FAR", "NEAR", "__RPC_FAR", "far", "near" }) {
                        if (match_w(src, pos, dm)) { pos += std::strlen(dm); skip_ws(src, pos); progressed = true; break; }
                    }
                    if (!progressed && pos < src.size() && src[pos] == '*') { ptr_alias = true; ++pos; skip_ws(src, pos); progressed = true; }
                    if (!progressed) break;
                }
                auto a = read_ident(src, pos);
                if (a.empty()) { skip_to_next_statement(src, pos); return; }
                aliases.push_back({ std::string(a), ptr_alias });
            }
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == ';') ++pos;
            if (!name.empty()) {
                std::string ns = map_ns(file);
                // `typedef struct TAG *TAG;` (same tag+alias name, pointer
                // level) declares TAG as an opaque handle: a pointer to an
                // incomplete struct. Emit the type as a class so downstream
                // projections produce `using TAG = void*;` instead of a
                // field-less struct (RO_REGISTRATION_COOKIE,
                // CO_MTA_USAGE_COOKIE, PACKAGEDEPENDENCY_CONTEXT class of
                // bugs). A non-pointer same-name alias is a no-op C++ style
                // typedef and keeps the struct kind.
                bool opaque_handle = false;
                for (auto const& [an, pa] : aliases) {
                    if (pa && an == name) { opaque_handle = true; break; }
                }
                TDef td; td.kind = opaque_handle ? Kind::Class
                                                 : (is_union ? Kind::Union : Kind::Struct);
                td.ns = ns; td.name = name; td.attr = TA::Pub; td.is_union = is_union && !opaque_handle;
                td.source_header = file;
                td.fn_flags = g_decl_flags_sink;
                td.deprecation_msg = g_decl_msg_sink;
                items.push_back({std::move(td), pp.current_arch(), file});
                nss.insert(ns);
                ++types_out;
                for (auto& [an, pa] : aliases) {
                    if (an == name) continue;
                    TDef ad; ad.kind = Kind::Class; ad.ns = ns; ad.name = an;
                    ad.attr = TA::Pub; ad.source_header = file;
                    ad.alias_elem = ET::Class;
                    ad.alias_ref.name = name;
                    ad.alias_ref.elem = ET::Class;
                    ad.alias_ref.ptr = pa ? 1u : 0u;
                    items.push_back({std::move(ad), pp.current_arch(), file});
                    ++types_out;
                }
            }
        }
    }

    void parse_struct_body(std::string_view src, size_t& pos, TDef& td,
                           const std::string& struct_name, Preprocessor& pp,
                           std::vector<Item>& items, std::set<std::string>& nss,
                           const std::string& file) {
        size_t limit = src.size();
        size_t iter = 0;

        // Unique hoisted-name helper for nested anonymous members.
        // Uniqueness must be GLOBAL across all namespaces: ESENT and MMC
        // both live inside the aggregate Windows.Win32 module, and two
        // identically-named hoisted types (JET_..._AnonymousUnion_3 vs
        // MMC_..._AnonymousUnion_3 patterns aside, base collisions do
        // occur) would emit two conflicting members in one namespace.
        auto unique_nested_name = [&](std::string const& base) {
            std::string candidate = base;
            int suffix = 2;
            for (;;)
            {
                bool clash = false;
                for (auto const& it : items)
                {
                    if (it.def.name == candidate) { clash = true; break; }
                }
                if (!clash) return candidate;
                candidate = base + "_" + std::to_string(suffix++);
            }
        };

        while (pos < limit && src[pos] != '}') {
            if (++iter > BODY_ITER_LIMIT) { skip_to_char(src, pos, '}'); break; }
            skip_ws(src, pos);
            if (pos >= limit || src[pos] == '}') break;

            if (src[pos] == '#') { skip_to_eol(src, pos); continue; }
            if (src[pos] == '/' && pos + 1 < limit) {
                if (src[pos + 1] == '/') { pos += 2; while (pos < limit && src[pos] != '\n') ++pos; continue; }
                if (src[pos + 1] == '*') { pos += 2; skip_block_comment(src, pos); continue; }
            }
            if (src[pos] == ';' || src[pos] == '\n') { ++pos; continue; }

            // Nested struct/union member — the canonical Windows
            // DUMMYSTRUCTNAME / DUMMYUNIONNAME pattern:
            //     typedef struct PACKAGE_VERSION {
            //         union { UINT64 Version; struct {...} DUMMYSTRUCTNAME; } DUMMYUNIONNAME;
            //     } PACKAGE_VERSION;
            // The old code let read_type swallow the 'union'/'struct' keyword,
            // found no field name and silently dropped the whole member (so
            // PACKAGE_VERSION ended up fieldless / missing from the winmd).
            // Hoist the nested type to a uniquely named sibling type instead
            // (the same trick win32metadata uses with <Outer>_<member> helper
            // types) so by-value fields can reference it.
            {
                size_t backtrack = pos;
                bool nested_union = match_w(src, pos, "union");
                bool nested_struct = !nested_union && match_w(src, pos, "struct");
                if (nested_union || nested_struct)
                {
                    pos += nested_union ? 5 : 6;
                    skip_ws(src, pos);
                    auto nested_tag = read_ident(src, pos);
                    skip_ws(src, pos);
                    if (pos < limit && src[pos] == '{')
                    {
                        ++pos; // consume '{' — recursive call parses through the matching '}'
                        std::string outer = td.name.empty() ? struct_name : td.name;
                        std::string member = nested_tag.empty()
                            ? std::string(nested_union ? "AnonymousUnion" : "AnonymousStruct")
                            : std::string(nested_tag);
                        TDef nested;
                        nested.kind = nested_union ? Kind::Union : Kind::Struct;
                        nested.ns = td.ns;
                        nested.attr = TA::Pub;
                        nested.is_union = nested_union;
                        nested.source_header = file;
                        nested.name = unique_nested_name(outer + "_" + member);
                        parse_struct_body(src, pos, nested, nested.name, pp, items, nss, file);
                        std::string hoisted_name = nested.name; // captured before the move below
                        items.push_back({std::move(nested), pp.current_arch(), file});
                        nss.insert(td.ns);
                        // Member alias after the closing brace: "} DUMMYUNIONNAME;"
                        skip_ws(src, pos);
                        size_t alias_probe = pos;
                        auto member_alias = read_ident(src, pos);
                        // parse_struct_body's tail-alias scan has ALREADY
                        // consumed any real alias AND the declaration's
                        // terminating ';' ("};") before returning — so a
                        // non-empty ident here is the NEXT member's leading
                        // token, not an alias. wdm.h's
                        // OB_PRE_OPERATION_INFORMATION:
                        //     union { ... };
                        //     _In_ PVOID Object;
                        // made the SAL annotation the hoisted field's name;
                        // _In_ expands to nothing at C++ compile (C2208 on
                        // the anonymous union in every consumer). A real
                        // alias declarator is followed by ';' (or an array
                        // /'='/',' suffix) — anything else is not an alias:
                        // rewind so the outer field loop parses it.
                        if (!member_alias.empty())
                        {
                            size_t vp = pos;
                            skip_ws(src, vp);
                            bool declarator = vp < limit &&
                                (src[vp] == ';' || src[vp] == '[' ||
                                 src[vp] == '=' || src[vp] == ',');
                            if (!declarator) { pos = alias_probe; member_alias = {}; }
                        }
                        skip_ws(src, pos);
                        if (pos < limit && src[pos] == ';') ++pos;
                        // Record the by-value member so the outer struct keeps
                        // its field layout (minVer.Major / ULARGE_INTEGER
                        // DUMMYSTRUCTNAME accessors in the projection): the
                        // field references the hoisted type exactly like any
                        // other named struct field (ET::Class + ref.name).
                        FDef mfd; mfd.attr = FA::Pub;
                        mfd.name = member_alias.empty()
                            ? std::string(nested_union ? "AnonymousUnion" : "AnonymousStruct")
                            : std::move(member_alias);
                        mfd.type = ET::Class;
                        mfd.ref.name = hoisted_name;
                        td.fields.push_back(std::move(mfd));
                        continue;
                    }
                    // Not a nested definition (e.g. "struct POINT pt;") — rewind
                    // and let the normal field parser handle it.
                    pos = backtrack;
                }
            }

            skip_decl_specifiers(src, pos);
            skip_ws(src, pos);

            size_t field_start = pos;
            auto ftype = read_type(src, pos);
            skip_ws(src, pos);
            // Member functions inside struct bodies (WindowsNumerics.impl.h
            // `_WINDOWS_NUMERICS_CONSTEXPR_ static float2 zero();`) are not
            // data members: recording them as fields emits a by-value
            // member of the enclosing type still being defined (C2460 on
            // float2::zero). Skip the parameter list + optional body and
            // record nothing.
            {
                size_t probe = pos;
                auto mname = read_ident(src, probe);
                skip_ws(src, probe);
                if (!mname.empty() && probe < limit && src[probe] == '(') {
                    skip_balanced(src, probe, '(', ')');
                    skip_ws(src, probe);
                    if (probe < limit && src[probe] == '{') skip_balanced(src, probe, '{', '}');
                    skip_ws(src, probe);
                    if (probe < limit && src[probe] == ';') ++probe;
                    pos = probe;
                    continue;
                }
                pos = field_start + (pos - field_start); // no-op; probe only
            }
            // Decoration macros interleave between the type and the field
            // name (`struct wavehdr_tag FAR *lpNext;` in mmsystem.h's
            // wavehdr_tag): without this the macro becomes the FIELD NAME
            // (`wavehdr_tag FAR;`) and the real name is dropped - C2460
            // 'wavehdr_tag::FAR' in every consumer. Skip deco macros and
            // stars the same way parse_param_list does.
            uint32_t decl_stars = 0;
            for (int guard = 0; guard < 8; ++guard) {
                skip_ws(src, pos);
                bool progressed = false;
                for (auto const& dm : { "FAR", "NEAR", "far", "near", "__far", "__near", "_FAR", "_NEAR", "__unaligned", "UNALIGNED" }) {
                    if (match_w(src, pos, dm)) { pos += std::strlen(dm); skip_ws(src, pos); progressed = true; break; }
                }
                if (!progressed && pos < limit && src[pos] == '*') { ++decl_stars; ++pos; skip_ws(src, pos); progressed = true; }
                if (!progressed) break;
            }
            auto fname = read_ident(src, pos);

            if (fname.empty()) {
                // Macro-expansion debris with no ';' (wdm.h's
                // GENERAL_LOOKASIDE_LAYOUT expands to the real members,
                // so the raw body shows a bare macro name right before
                // the closing brace). Stop at the struct's '}' as well
                // as the next ';' — plain skip_to_char ran past the
                // brace and re-parsed the rest of the file as fields of
                // this struct (391KB of wdm.h lost, including every
                // IRP_MJ_ define below it).
                skip_to_char3(src, pos, ';', '}', ';');
                if (pos < limit && src[pos] == ';') ++pos;
                if (pos == field_start) { if (pos < limit && src[pos] != '}') ++pos; }
                continue;
            }

            skip_ws(src, pos);
            uint32_t field_arr = 0;
            if (pos < limit && src[pos] == '[')
            {
                if (pos + 1 < limit && src[pos + 1] == '[')
                {
                    // C++ attribute [[...]] — skip as before.
                    skip_balanced(src, pos, '[', ']');
                }
                else
                {
                    // Fixed array bound `T name[N];` — keep a PURELY numeric
                    // N (macro bounds like [ANYSIZE_ARRAY] / [countof(x)] /
                    // [sizeof x] are not constant-folded here and stay 0,
                    // preserving the old scalar behavior).
                    size_t br = pos + 1;
                    std::string num;
                    while (br < limit && src[br] != ']' && src[br] != '[' && src[br] != ';')
                    {
                        if (std::isdigit((unsigned char)src[br])) num.push_back(src[br]);
                        else if (src[br] != ' ') { num.clear(); break; }
                        ++br;
                    }
                    if (br < limit && src[br] == ']' && !num.empty() && num.size() <= 9)
                        field_arr = (uint32_t)std::strtoul(num.c_str(), nullptr, 10);
                    skip_balanced(src, pos, '[', ']');
                }
            }
            skip_ws(src, pos);
            if (pos < limit && src[pos] == ':') {
                skip_balanced(src, pos, ':', ';');
            }
            skip_ws(src, pos);
            if (pos < limit && src[pos] == '=') {
                ++pos;
                // Initializer running to the closing brace without a
                // ';' — same pass-over hazard as the debris branch.
                skip_to_char3(src, pos, ';', '}', ';');
            }
            skip_ws(src, pos);
            if (pos < limit && src[pos] == ';') ++pos;

            FDef fd; fd.name = fname; fd.attr = FA::Pub;
            fd.type = ftype.elem; fd.ref = std::move(ftype.ref);
            fd.ref.ptr += decl_stars;
            fd.arr_n = field_arr;
            // Macro-heavy headers leave parse debris: `void const*` splits
            // into a void-typed field named 'const_' (RPCDCEP's
            // RPC_CLIENT_INTERFACE), which no projection can emit (C2182
            // 'this use of void is not valid'). A bare void field is always
            // debris — drop it here at the parse level.
            if (fd.type == ET::Void && fd.ref.name.empty() && fd.ref.ptr == 0) {
                skip_to_char3(src, pos, ';', '}', ';');
                continue;
            }
            // Paired #ifdef/#else branches both active after flattening
            // declare the same union field twice (HSTRING_HEADER's
            // Reserved2); the duplicate later emits as a hard C2086
            // redefinition in every C++ projection. Keep the first.
            {
                bool dup = false;
                for (auto const& ex : td.fields)
                    if (ex.name == fd.name) { dup = true; break; }
                if (!dup) td.fields.push_back(std::move(fd));
            }
        }
        if (pos < limit && src[pos] == '}') ++pos;
        // Typedef alias list after the closing brace:
        //     typedef struct { ... } FOO, *PFOO;
        //     typedef struct tagX { ... } X, *PX;      (tagged: first alias
        //         sits DIRECTLY after '}', space-separated — same shape as
        //         the forward-decl branch. Only scanning from the first ','
        //         misses the first alias and, with it, every pointer alias
        //         after it: `} ServerInformation, *PServerInformation;`
        //         left PServerInformation targetless.)
        // Each name becomes an alias typedef (parse_typedef precedent) so
        // PFOO-typed signatures resolve to FOO* instead of void. The first
        // alias also names an anonymous tag.
        auto emit_tail_alias = [&](std::string_view alias, bool ptr_alias) {
            if (alias.empty()) return;
            if (td.name.empty()) td.name = std::string(alias);
            if (std::string(alias) != td.name) {
                TDef ad; ad.kind = Kind::Class; ad.ns = td.ns; ad.name = std::string(alias);
                ad.attr = TA::Pub; ad.source_header = file;
                ad.alias_elem = ET::Class;
                ad.alias_ref.name = td.name;
                ad.alias_ref.elem = ET::Class;
                ad.alias_ref.ptr = ptr_alias ? 1u : 0u;
                items.push_back({std::move(ad), pp.current_arch(), file});
                nss.insert(td.ns);
            }
        };
        // First alias: directly after '}', optionally '*'-prefixed.
        {
            size_t save = pos;
            skip_ws(src, pos);
            // Decoration macros interleave with '*' in tail alias lists
            // (`} NS_INFOA, FAR * LPNS_INFOA;`, `} WSAMSG, * FAR LPWSAMSG;`)
            // — without skipping, the macro lands as a bogus `class FAR`
            // alias. Skip deco/star pairs until only the name remains.
            bool first_ptr = false;
            for (int guard = 0; guard < 8; ++guard) {
                skip_ws(src, pos);
                bool progressed = false;
                for (auto const& dm : { "FAR", "NEAR", "__RPC_FAR", "far", "near" }) {
                    if (match_w(src, pos, dm)) { pos += std::strlen(dm); skip_ws(src, pos); progressed = true; break; }
                }
                if (!progressed && pos < limit && src[pos] == '*') { first_ptr = true; ++pos; skip_ws(src, pos); progressed = true; }
                if (!progressed) break;
            }
            auto a1 = read_ident(src, pos);
            if (!a1.empty()) emit_tail_alias(a1, first_ptr);
            else pos = save;
        }
        // Subsequent aliases: comma-separated, each optionally pointer-typed.
        for (;;) {
            skip_ws(src, pos);
            if (pos >= limit || src[pos] != ',') break;
            ++pos; skip_ws(src, pos);
            // Decoration macros interleave with '*' (see first-alias note).
            bool ptr_alias = false;
            for (int guard = 0; guard < 8; ++guard) {
                skip_ws(src, pos);
                bool progressed = false;
                for (auto const& dm : { "FAR", "NEAR", "__RPC_FAR", "far", "near" }) {
                    if (match_w(src, pos, dm)) { pos += std::strlen(dm); skip_ws(src, pos); progressed = true; break; }
                }
                if (!progressed && pos < limit && src[pos] == '*') { ptr_alias = true; ++pos; skip_ws(src, pos); progressed = true; }
                if (!progressed) break;
            }
            auto alias = read_ident(src, pos);
            if (alias.empty()) { skip_to_next_statement(src, pos); return; }
            emit_tail_alias(alias, ptr_alias);
        }
        skip_ws(src, pos);
        if (pos < limit && src[pos] == ';') ++pos;
    }

    void parse_enum(std::string_view src, size_t& pos, const std::string& file,
                    Preprocessor& pp, bool active,
                    std::vector<Item>& items, std::set<std::string>& nss, size_t& types_out) {
        if (!active) { skip_to_next_statement(src, pos); return; }
        skip_ws(src, pos);
        if (match_w(src, pos, "enum")) { pos += 4; }
        skip_ws(src, pos);
        // Handle enum class / enum struct (C++11 scoped enums)
        bool is_scoped = false;
        if (match_w(src, pos, "class")) { is_scoped = true; pos += 5; skip_ws(src, pos); }
        else if (match_w(src, pos, "struct")) { is_scoped = true; pos += 6; skip_ws(src, pos); }
        skip_decl_specifiers(src, pos);
        skip_ws(src, pos);
        auto name = read_ident(src, pos);
        skip_ws(src, pos);

        if (pos < src.size() && src[pos] == ':') {
            ++pos;
            skip_to_char(src, pos, '{');
        }

        if (pos < src.size() && src[pos] == '{') {
            ++pos;
            std::string ns = map_ns(file);
            TDef td; td.kind = Kind::Enum; td.ns = ns; td.name = name; td.attr = TA::Pub;
            td.source_header = file;
            int64_t val = 0;
            size_t iter = 0;
            while (pos < src.size() && src[pos] != '}') {
                if (++iter > BODY_ITER_LIMIT) break;
                skip_ws(src, pos);
                if (pos >= src.size() || src[pos] == '}') break;
                if (src[pos] == '#') { skip_to_eol(src, pos); continue; }
                // Doc comments (/// or //) before enum members: without
                // skipping them read_ident() returns empty and
                // skip_to_char3() swallows the COMMENT PLUS THE FOLLOWING
                // MEMBER — an enum whose every member carries a doc comment
                // (the WASDK MddBootstrapInitializeOptions style) landed
                // with zero members in the winmd.
                if (src[pos] == '/' && pos + 1 < src.size()) {
                    if (src[pos + 1] == '/') { pos += 2; while (pos < src.size() && src[pos] != '\n') ++pos; continue; }
                    if (src[pos + 1] == '*') { pos += 2; skip_block_comment(src, pos); continue; }
                }

                auto mname = read_ident(src, pos);
                if (mname.empty()) { skip_to_char3(src, pos, ',', '}', ';'); continue; }
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '=') {
                    ++pos; skip_ws(src, pos);
                    val = read_const_expr(src, pos);
                }
                // Trailing member comments holding commas: d3d12umddi.h ends
                // its last enumerator with no comma and a comment,
                //     D3D12DDI_STATIC_BORDER_COLOR_OPAQUE_WHITE_UINT  // 1u,1u,1u,1u
                // and the bare skip_to_char3 below stopped at the comma
                // INSIDE that comment, re-parsing "1u" as a member named
                // "1u" (C2143/C2059 'constant' in D3D12UMDDI). Comments
                // cannot carry a real terminator, so skip them first.
                for (;;) {
                    skip_ws(src, pos);
                    if (pos + 1 < src.size() && src[pos] == '/' && src[pos + 1] == '/') {
                        pos += 2; while (pos < src.size() && src[pos] != '\n') ++pos; continue;
                    }
                    if (pos + 1 < src.size() && src[pos] == '/' && src[pos + 1] == '*') {
                        pos += 2; skip_block_comment(src, pos); continue;
                    }
                    break;
                }
                skip_to_char3(src, pos, ',', '}', ';');
                if (pos < src.size() && src[pos] == ',') ++pos;

                FDef fd; fd.name = mname; fd.attr = FA::Pub | FA::Static | FA::Literal;
                fd.type = ET::I4; fd.def.type = ET::I4; fd.def.v = (int32_t)val;
                td.fields.push_back(std::move(fd));
                ++val;
            }
            if (pos < src.size() && src[pos] == '}') ++pos;
            if (pos < src.size() && src[pos] == ';') ++pos;
            items.push_back({std::move(td), pp.current_arch(), file});
            nss.insert(ns);
            ++types_out;
        } else {
            skip_to_next_statement(src, pos);
        }
    }

    void parse_fnptr(std::string_view src, size_t& pos, const std::string& file,
                     Preprocessor& pp, bool active,
                     std::vector<Item>& items, std::set<std::string>& nss) {
        if (!active) { skip_to_next_statement(src, pos); return; }
        skip_ws(src, pos);
        // _Function_class_(X) labels the callback's semantic class
        // (DRIVER_DISPATCH, DRIVER_INITIALIZE, ...). The SDK carries no other
        // dispatch metadata: IRP slot codes are #defines and the typedef
        // name is often a bare alias. Capture it for the enricher.
        std::string fn_class;
        {
            for (int guard = 0; guard < 8; ++guard) {
                skip_ws(src, pos);
                if (pos >= src.size() || src[pos] != '_') break;
                size_t s2 = pos;
                ++pos;
                while (pos < src.size() && (std::isalnum((unsigned char)src[pos]) || src[pos] == '_')) ++pos;
                bool is_fc = src.substr(s2 + 1, pos - s2 - 1).starts_with("Function_class");
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') {
                    ++pos;
                    size_t a0 = pos;
                    int depth = 1;
                    while (pos < src.size() && depth > 0) {
                        if (src[pos] == '(') ++depth;
                        else if (src[pos] == ')') --depth;
                        if (depth > 0) ++pos;
                    }
                    if (is_fc) {
                        auto args = src.substr(a0, pos - a0);
                        while (!args.empty() && (unsigned char)args.front() <= ' ') args.remove_prefix(1);
                        while (!args.empty() && (unsigned char)args.back() <= ' ') args.remove_suffix(1);
                        fn_class.assign(args);
                    }
                    if (pos < src.size()) ++pos; // ')'
                }
            }
        }
        auto ret = read_type(src, pos);
        skip_ws(src, pos);
        if (pos < src.size() && src[pos] == '(') ++pos;
        skip_ws(src, pos);
        skip_calling_convention(src, pos);
        while (pos < src.size() && (src[pos] == '*' || src[pos] == ')')) ++pos;
        auto name = read_ident(src, pos);
        skip_ws(src, pos);
        if (pos < src.size() && src[pos] == ')') ++pos;
        skip_ws(src, pos);

        std::vector<PDef> params;
        if (pos < src.size() && src[pos] == '(') {
            ++pos;
            parse_param_list(src, pos, params);
        }
        if (pos < src.size() && src[pos] == ';') ++pos;

        std::string ns = map_ns(file);
        TDef td; td.kind = Kind::Delegate; td.ns = ns; td.name = name;
        td.attr = TA::Pub; td.is_callback = true;
        td.source_header = file;
        td.fn_class = std::move(fn_class);
        MSig sig; sig.ret = ret.elem; sig.ret_r = std::move(ret.ref);
        sig.cc = CC::Def; sig.params = std::move(params);
        td.meths.push_back(std::move(sig));
        items.push_back({std::move(td), pp.current_arch(), file});
        nss.insert(ns);
    }

    // Join backslash-continued directive lines into one logical line:
    // `#define X a \` + `b` must reach handle_pp as `#define X a b`.
    // Previously only the first physical line was handled — continuation
    // lines fell through to the type parsers as fake code (a macro body's
    // `union {` opened a real parse that swallowed 394KB of wdm.h), losing
    // every #define below it: IRP_MJ_* codes and most IOCTL/FSCTL constants,
    // whose CTL_CODE calls span lines, never reached the recorder.
    // Returns the joined text; end_out = offset of the final newline (or
    // src.size()) — advance pos there so no continuation line leaks.
    static std::string join_continued(std::string_view src, size_t line_start, size_t& end_out) {
        std::string dir;
        size_t seg = line_start;
        size_t nl = std::string_view::npos;
        while (true) {
            nl = src.find('\n', seg);
            size_t seg_end = (nl == std::string_view::npos) ? src.size() : nl;
            size_t e = seg_end;
            while (e > seg && src[e - 1] == '\r') --e;
            bool cont = (e > seg && src[e - 1] == '\\');
            dir.append(src, seg, (cont ? e - 1 : e) - seg);
            if (!cont || nl == std::string_view::npos) break;
            dir.push_back(' ');
            seg = nl + 1;
        }
        end_out = (nl == std::string_view::npos) ? src.size() : nl;
        return dir;
    }

    // Skip # preprocessor lines, properly evaluating #ifdef/#ifndef/#if/#else/#endif nesting
    void skip_pp_lines(std::string_view src, size_t& pos, Preprocessor& pp) {
        // Track nested ifdef blocks — fresh state per call, not shared across calls
        std::vector<bool> local_ifdef_stack;
        bool local_active = true;
        for (int guard = 0; guard < 20; ++guard) {
            skip_ws(src, pos);
            if (pos >= src.size() || src[pos] != '#') return;

            auto line_start = pos + 1;
            size_t dir_end = line_start;
            auto directive = join_continued(src, line_start, dir_end);
            auto t = tr(directive);

            if (t.starts_with("ifdef")) {
                local_ifdef_stack.push_back(local_active);
                local_active = local_active && pp.eval_ifdef(tr(t.substr(5)));
                pos = dir_end;
                continue;
            } else if (t.starts_with("ifndef")) {
                local_ifdef_stack.push_back(local_active);
                local_active = local_active && !pp.eval_ifdef(tr(t.substr(6)));
                pos = dir_end;
                continue;
            } else if (t.starts_with("if ")) {
                local_ifdef_stack.push_back(local_active);
                local_active = local_active && pp.eval_if(tr(t.substr(3)));
                pos = dir_end;
                continue;
            } else if (t.starts_with("elif")) {
                if (!local_ifdef_stack.empty()) {
                    auto prev = local_ifdef_stack.back();
                    local_active = prev && !local_active && pp.eval_if(tr(t.substr(4)));
                }
                pos = dir_end;
                continue;
            } else if (t.starts_with("else")) {
                if (!local_ifdef_stack.empty()) {
                    auto prev = local_ifdef_stack.back();
                    local_active = prev && !local_active;
                }
                pos = dir_end;
                continue;
            } else if (t.starts_with("endif")) {
                if (!local_ifdef_stack.empty()) {
                    local_active = local_ifdef_stack.back();
                    local_ifdef_stack.pop_back();
                }
                pos = dir_end;
                continue;
            } else if (t.starts_with("pragma") || t.starts_with("error") || t.starts_with("warning") || t.starts_with("line") || t.starts_with("define") || t.starts_with("undef") || t.starts_with("include")) {
                pos = dir_end;
                continue;
            }

            // Unknown # directive — skip (honouring continuations)
            pos = dir_end;
        }
    }

    bool try_parse_func(std::string_view src, size_t& pos, const std::string& file,
                        Preprocessor& pp, SalParser& sal, bool active,
                        std::vector<Item>& items, std::set<std::string>& nss, size_t& funcs_out) {
        if (!active) return false;
        size_t saved = pos;
        if (try_parse_func_core(src, pos, file, pp, sal, items, nss, funcs_out))
            return true;
        // Generic recovery for decl shapes the first pass cannot read: a
        // leading SAL annotation or return-type macro the specifiers set
        // does not know (e.g. `_Post_equals_last_error_ DWORD WINAPI
        // GetLastError(VOID)`, `NTSYSAPI PVOID NTAPI
        // AddVectoredExceptionHandler(...)`, `WINOLEAPI_(LPVOID)
        // CoTaskMemAlloc(...)`). Skip one identifier token - consuming any
        // function-like macro argument list, whose inner text becomes the
        // return type - and retry. Bounded hops keep this O(1) and false-
        // positive free: a function still requires `name(` somewhere.
        size_t p = saved;
        for (int hop = 0; hop < 4; ++hop) {
            skip_ws(src, p);
            skip_pp_lines(src, p, pp);
            skip_ws(src, p);
            if (p >= src.size()) break;
            if (src[p] != '_' && !std::isalpha((unsigned char)src[p])) break;
            size_t tok = p;
            read_ident(src, p);
            skip_ws(src, p);
            if (p == tok) break;
            if (p < src.size() && src[p] == '(') {
                size_t inner_start = p + 1;
                skip_balanced(src, p, '(', ')');
                // inner_end excludes the closing paren (and any trailing ws
                // inside the macro body is fine - read_type skips it).
                size_t inner_end = p - 1;
                skip_ws(src, p);
                size_t q = p;
                if (try_parse_func_core(src, q, file, pp, sal, items, nss, funcs_out,
                                        inner_start, inner_end)) {
                    pos = q;
                    return true;
                }
            } else {
                size_t q = p;
                if (try_parse_func_core(src, q, file, pp, sal, items, nss, funcs_out)) {
                    pos = q;
                    return true;
                }
            }
        }
        pos = saved;
        return false;
    }

    bool try_parse_func_core(std::string_view src, size_t& pos, const std::string& file,
                             Preprocessor& pp, SalParser& sal,
                             std::vector<Item>& items, std::set<std::string>& nss, size_t& funcs_out,
                             size_t ret_start = std::string_view::npos,
                             size_t ret_end = std::string_view::npos) {
        size_t saved = pos;

        skip_decl_specifiers(src, pos);
        skip_pp_lines(src, pos, pp);
        skip_ws(src, pos);

        size_t type_start = pos;
        TRef ret;
        if (ret_start != std::string_view::npos && ret_end != std::string_view::npos && ret_end > ret_start) {
            // Return type supplied by the recovery pass from a function-like
            // return macro's argument list, e.g. LPVOID inside
            // `WINOLEAPI_(LPVOID) CoTaskMemAlloc(...)`. The return type is
            // already known, so the next identifier is the function name:
            // no read_type here.
            auto sub = src.substr(ret_start, ret_end - ret_start);
            size_t sp = 0;
            // Function-like return macros often carry SAL annotations in
            // their argument list: WINOLEAPI_(_Ret_opt_ ... LPVOID).
            // SAL annotations are reserved identifiers (leading underscore)
            // with an optional parenthesized argument; the real return type
            // never starts with '_' (LPVOID, SIZE_T, void, ...). Strip only
            // the _-prefixed tokens.
            for (int guard = 0; guard < 24; ++guard) {
                skip_ws(sub, sp);
                if (sp >= sub.size() || sub[sp] != '_') break;
                read_ident(sub, sp);
                skip_ws(sub, sp);
                if (sp < sub.size() && sub[sp] == '(') skip_balanced(sub, sp, '(', ')');
            }
            auto ret_r = read_type(sub, sp);
            ret = std::move(ret_r.ref);
            if (sp == 0 || ret.elem == ET::Void && ret.ns.empty() && ret.name.empty()) {
                pos = saved; return false;
            }
            skip_decl_specifiers(src, pos);
            skip_ws(src, pos);
            skip_calling_convention(src, pos);
            skip_ws(src, pos);
        } else {
            auto ret_r = read_type(src, pos);
            ret = std::move(ret_r.ref);
            if (pos == type_start) {
                pos = saved; return false;
            }
        }

        skip_ws(src, pos);
        skip_calling_convention(src, pos);
        skip_ws(src, pos);

        // Handle #else/#endif blocks between calling convention and function name
        // e.g. #ifndef _MAC\nLRESULT\nWINAPI\n#else\nLRESULT\nCALLBACK\n#endif\nDefWindowProcW
        skip_pp_lines(src, pos, pp);
        skip_ws(src, pos);

        auto name = read_ident(src, pos);
        if (name.empty()) {
            pos = saved; return false;
        }
        skip_ws(src, pos);

        if (pos >= src.size() || src[pos] != '(') {
            pos = saved; return false;
        }
        // Unexpanded function-like macro debris: D2D1EffectHelpers.h's
        // D2D1_*_BINDING macro bodies leave CONCAT(...) / D2D_ENTRY(...)
        // in the flattened text and they parse as bogus functions
        // (C2039/C2065 in every consumer). Real APIs are never ALL-CAPS:
        // skip the invocation whole (DEFINE_DEVOPGUID precedent above).
        {
            bool has_lower = false, has_upper = false;
            for (char c : name) {
                if (c >= 'a' && c <= 'z') { has_lower = true; break; }
                if (c >= 'A' && c <= 'Z') has_upper = true;
            }
            if (has_upper && !has_lower) {
                skip_to_next_statement(src, pos);
                return true;
            }
        }
        ++pos;

        MSig sig; sig.ret = ret.elem; sig.ret_r = std::move(ret); sig.cc = CC::Std;
        parse_param_list_with_sal(src, pos, sig, sal);

        if (pos < src.size() && src[pos] == ')') ++pos;
        skip_ws(src, pos);

        // Skip noexcept, throw(), override, final, const, volatile, __attribute__ after params
        for (int g = 0; g < 10; ++g) {
            if (pos >= src.size()) break;
            if (match_w(src, pos, "noexcept")) { pos += 8; skip_ws(src, pos); continue; }
            if (match_w(src, pos, "override")) { pos += 8; skip_ws(src, pos); continue; }
            if (match_w(src, pos, "final")) { pos += 5; skip_ws(src, pos); continue; }
            if (match_w(src, pos, "const")) { pos += 5; skip_ws(src, pos); continue; }
            if (match_w(src, pos, "volatile")) { pos += 8; skip_ws(src, pos); continue; }
            if (match_w(src, pos, "__attribute__")) {
                pos += 12; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                skip_ws(src, pos); continue;
            }
            if (match_w(src, pos, "__declspec")) {
                pos += 10; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                skip_ws(src, pos); continue;
            }
            // [[...]] attributes
            if (pos < src.size() && src[pos] == '[' && pos + 1 < src.size() && src[pos + 1] == '[') {
                skip_balanced(src, pos, '[', ']');
                skip_ws(src, pos); continue;
            }
            break;
        }

        // Skip = default / = delete
        if (pos < src.size() && src[pos] == '=') {
            size_t eq_pos = pos;
            ++pos; skip_ws(src, pos);
            if (pos < src.size() && (src[pos] == 'd' || src[pos] == '0')) {
                auto rest = src.substr(pos, std::min<size_t>(10, src.size() - pos));
                if (rest.starts_with("default") || rest.starts_with("delete")) {
                    while (pos < src.size() && src[pos] != ';' && src[pos] != '{') ++pos;
                    if (pos < src.size() && src[pos] == ';') ++pos;
                    std::string ns = map_ns(file);
                    TDef td; td.kind = Kind::Func; td.ns = ns; td.name = name;
                    td.attr = TA::Pub; td.source_header = file;
                    td.meths.push_back(std::move(sig));
                    td.fn_flags = g_decl_flags_sink;
                    td.deprecation_msg = g_decl_msg_sink;
                    items.push_back({std::move(td), pp.current_arch(), file});
                    nss.insert(ns);
                    ++funcs_out;
                    return true;
                }
            }
            pos = eq_pos;
        }

        if (pos < src.size() && src[pos] == ',') { pos = saved; return false; }
        if (pos < src.size() && src[pos] == '=') { pos = saved; return false; }
        if (pos < src.size() && src[pos] == '{') { skip_balanced(src, pos, '{', '}'); }
        if (pos < src.size() && src[pos] == ';') ++pos;

        std::string ns = map_ns(file);
        TDef td; td.kind = Kind::Func; td.ns = ns; td.name = name;
        td.attr = TA::Pub; td.source_header = file;
        td.meths.push_back(std::move(sig));
        td.fn_flags = g_decl_flags_sink;
        td.deprecation_msg = g_decl_msg_sink;
        items.push_back({std::move(td), pp.current_arch(), file});
        nss.insert(ns);
        ++funcs_out;
        return true;
    }

    void parse_com_interface(std::string_view src, size_t& pos, const std::string& file,
                             Preprocessor& pp, bool active,
                             std::vector<Item>& items, std::set<std::string>& nss, size_t& types_out) {
        if (!active) { skip_to_next_statement(src, pos); return; }

        size_t saved = pos;
        if (match_w(src, pos, "DECLARE_INTERFACE")) { pos += 17; }
        else if (match_w(src, pos, "DECLARE_INTERFACE_")) { pos += 18; }
        else         if (match_w(src, pos, "MIDL_INTERFACE")) { pos += 14; }
        // MIDL_INTERFACE_ / DECLARE_INTERFACE_ carry the trailing underscore
        // as part of the token; match_w already matched the longer spelling
        // above, but a bare `MIDL_INTERFACE` followed by `_` is a different
        // macro (e.g. MIDL_INTERFACE_ID) — consume the underscore so the
        // paren scan below starts at the IID.
        if (pos < src.size() && src[pos] == '_') ++pos;
        skip_ws(src, pos);
        std::string com_iid;
        std::string base_iface;
        if (pos < src.size() && src[pos] == '(') {
            ++pos;
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == '"') {
                ++pos;
                size_t start = pos;
                while (pos < src.size() && src[pos] != '"') ++pos;
                com_iid = std::string(src.substr(start, pos - start));
                if (pos < src.size()) ++pos;
            } else {
                // DECLARE_INTERFACE_(Name, Base) — unquoted paren carries
                // the interface name and (optionally) its COM base.
                auto id1 = read_ident(src, pos);
                skip_ws(src, pos);
                if (!id1.empty() && pos < src.size() && src[pos] == ',') {
                    ++pos;
                    skip_ws(src, pos);
                    base_iface = std::string(read_ident(src, pos));
                    skip_ws(src, pos);
                }
                (void)id1;
            }
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == ')') ++pos;
        }
        skip_ws(src, pos);

        // The interface name (and often an inheritance clause) sits BETWEEN
        // the IID paren and the body brace:
        //     MIDL_INTERFACE("AB310581-...") IShellItemArray : public IUnknown
        //     { ... };
        // The old code required '{' immediately after the IID, so every
        // real COM interface fell into the no-body branch and was dropped.
        std::string iface_name;
        {
            auto scan = pos;
            bool after_colon = false;
            while (scan < src.size() && src[scan] != '{' && src[scan] != ';') {
                if (std::isspace((unsigned char)src[scan])) { ++scan; continue; }
                if (src[scan] == ':') { after_colon = true; ++scan; continue; }
                if (src[scan] == '(') { skip_balanced(src, scan, '(', ')'); continue; }
                auto id = read_ident(src, scan);
                if (id.empty()) { ++scan; continue; }
                // access specifier after ':' — the real base follows
                if (id == "public" || id == "private" || id == "protected" || id == "struct")
                    continue;
                if (after_colon) {
                    if (base_iface.empty()) base_iface = std::string(id);
                } else if (iface_name.empty()) {
                    iface_name = std::string(id);
                }
            }
            pos = scan;
        }

        if (pos < src.size() && src[pos] == '{') {
            if (iface_name.empty()) {
                // Fallback: last identifier before the body brace.
                auto head = src.substr(saved, pos - saved);
                size_t p = head.size();
                while (p > 0 && !(std::isalnum((unsigned char)head[p - 1]) || head[p - 1] == '_')) --p;
                size_t e = p;
                while (e > 0 && (std::isalnum((unsigned char)head[e - 1]) || head[e - 1] == '_')) --e;
                iface_name = std::string(head.substr(e, p - e));
            }
            auto name = iface_name;
            ++pos;
            std::string ns = map_ns(file);
            TDef td; td.kind = Kind::Iface; td.ns = ns; td.name = name;
            td.attr = TA::Pub;
            td.is_com_interface = !com_iid.empty() || !base_iface.empty();
            td.source_header = file;
            td.com_iid = std::move(com_iid);
            if (!base_iface.empty()) td.ifaces.push_back({ "", std::move(base_iface) });

            // Parse the body: methods become meths entries in vtable order
            // (ComMethod attributes carry the index; property/event pairing
            // uses the names). STDMETHOD(X)(params) PURE and
            // `virtual ret cc X(params) = 0;` are the two SDK spellings.
            SalParser sal;
            size_t iter = 0;
            while (pos < src.size() && src[pos] != '}') {
                if (++iter > BODY_ITER_LIMIT) { skip_to_char(src, pos, '}'); break; }
                skip_ws_comments(src, pos);
                if (pos >= src.size() || src[pos] == '}') break;
                if (src[pos] == '#') { skip_to_eol(src, pos); continue; }
                // C++ access labels head MIDL interface bodies
                // (`{ public: virtual HRESULT ... }`). Unhandled, the label
                // poisoned the first method's name parse and the rollback
                // skipped it wholesale — single-method interfaces ended up
                // with methods=0.
                {
                    size_t lbl_save = pos;
                    auto lbl = read_ident(src, pos);
                    if (lbl == "public" || lbl == "private" || lbl == "protected") {
                        skip_ws(src, pos);
                        if (pos < src.size() && src[pos] == ':') ++pos;
                        continue;
                    }
                    pos = lbl_save;
                }
                if (match_w(src, pos, "STDMETHOD")) {
                    pos += 9; skip_ws(src, pos);
                    std::string mname;
                    if (pos < src.size() && src[pos] == '(') {
                        ++pos; skip_ws(src, pos);
                        mname = std::string(read_ident(src, pos));
                        skip_ws(src, pos);
                        if (pos < src.size() && src[pos] == ')') ++pos;
                    }
                    skip_ws(src, pos);
                    MSig sig; sig.has_this = true; sig.cc = CC::Std;
                    sig.ret = ET::I4; sig.ret_r.name = "HRESULT";
                    if (pos < src.size() && src[pos] == '(') {
                        ++pos;
                        parse_param_list_with_sal(src, pos, sig, sal);
                    }
                    sig.name = std::move(mname);
                    td.meths.push_back(std::move(sig));
                    skip_to_char(src, pos, ';');
                    if (pos < src.size() && src[pos] == ';') ++pos;
                    continue;
                }
                size_t mstart = pos;
                skip_calling_convention(src, pos);
                skip_decl_specifiers(src, pos, true);
                sal.parse_all(src, pos);
                auto ret_r = read_type(src, pos);
                skip_ws(src, pos);
                skip_calling_convention(src, pos);
                skip_ws(src, pos);
                auto mname = read_ident(src, pos);
                skip_ws(src, pos);
                if (mname.empty() || pos >= src.size() || src[pos] != '(') {
                    pos = mstart;
                    skip_to_char(src, pos, ';');
                    if (pos < src.size() && src[pos] == ';') ++pos;
                    continue;
                }
                MSig sig; sig.has_this = true; sig.cc = CC::Std;
                sig.ret = ret_r.elem; sig.ret_r = std::move(ret_r.ref);
                ++pos; // '('
                parse_param_list_with_sal(src, pos, sig, sal);
                sig.name = std::string(mname);
                td.meths.push_back(std::move(sig));
                skip_ws(src, pos);
                skip_to_char(src, pos, ';');
                if (pos < src.size() && src[pos] == ';') ++pos;
            }
            if (pos < src.size() && src[pos] == '}') ++pos;
            if (pos < src.size() && src[pos] == ';') ++pos;
            items.push_back({std::move(td), pp.current_arch(), file});
            nss.insert(ns);
            ++types_out;
        } else {
            skip_to_next_statement(src, pos);
        }
    }

    // parameter parsing

    void parse_param_list(std::string_view src, size_t& pos, std::vector<PDef>& params) {
        size_t iter = 0;
        while (pos < src.size() && src[pos] != ')') {
            if (++iter > PARAM_ITER_LIMIT) { skip_to_char(src, pos, ')'); break; }
            skip_ws(src, pos);
            if (pos >= src.size() || src[pos] == ')') break;
            size_t pstart = pos;
            skip_decl_specifiers(src, pos);
            auto pt = read_type(src, pos);
            // Fold declarator stars separated by no-op macros:
            // `_Outptr_ LPVOID FAR * ppv` -> one void** param named ppv.
            for (int fold = 0; fold < 16; ++fold) {
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '*') { ++pos; ++pt.ref.ptr; continue; }
                size_t save = pos;
                auto skip_id = read_ident(src, pos);
                if (!skip_id.empty() && (skip_id == "FAR" || skip_id == "NEAR" || skip_id == "far" ||
                    skip_id == "near" || skip_id == "__far" || skip_id == "__near" || skip_id == "_FAR" || skip_id == "_NEAR"))
                    continue;
                pos = save;
                break;
            }
            skip_ws(src, pos);
            auto pn = read_ident(src, pos);
            // `(VOID)` / `(void)` empty-parameter marker: an unnamed void
            // param is the C empty list, not one void-typed parameter.
            if (pn.empty() && pt.ref.ptr == 0 &&
                (pt.ref.elem == ET::Void || pt.ref.name == "VOID" || pt.ref.name == "void"))
            {
                skip_to_char(src, pos, ')');
                break;
            }
            PDef pd; pd.name = std::string(pn);
            pd.seq = uint16_t(params.size() + 1);
            params.push_back(std::move(pd));
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == '[') skip_balanced(src, pos, '[', ']');
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == ',') ++pos;
            if (pos <= pstart) { skip_to_char(src, pos, ')'); break; }
        }
    }

    void parse_param_list_with_sal(std::string_view src, size_t& pos, MSig& sig, SalParser& sal) {
        size_t iter = 0;
        while (pos < src.size() && src[pos] != ')') {
            if (++iter > PARAM_ITER_LIMIT) { skip_to_char(src, pos, ')'); break; }
            skip_ws(src, pos);
            if (pos >= src.size() || src[pos] == ')') break;
            size_t pstart = pos;
            skip_decl_specifiers(src, pos, true);
            auto sal_anns = sal.parse_all(src, pos);
            skip_ws(src, pos);
            auto pt = read_type(src, pos);
            // Fold declarator stars separated by no-op macros:
            // `_Outptr_ LPVOID FAR * ppv` -> one void** param named ppv.
            for (int fold = 0; fold < 16; ++fold) {
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '*') { ++pos; ++pt.ref.ptr; continue; }
                size_t save = pos;
                auto skip_id = read_ident(src, pos);
                if (!skip_id.empty() && (skip_id == "FAR" || skip_id == "NEAR" || skip_id == "far" ||
                    skip_id == "near" || skip_id == "__far" || skip_id == "__near" || skip_id == "_FAR" || skip_id == "_NEAR"))
                    continue;
                pos = save;
                break;
            }
            skip_ws(src, pos);
            auto pn = read_ident(src, pos);
            // `(VOID)` / `(void)` empty-parameter marker (see parse_param_list).
            if (pn.empty() && pt.ref.ptr == 0 &&
                (pt.ref.elem == ET::Void || pt.ref.name == "VOID" || pt.ref.name == "void"))
            {
                skip_to_char(src, pos, ')');
                break;
            }
            PDef pd; pd.name = std::string(pn);
            pd.seq = uint16_t(sig.params.size() + 1);
            if (!sal_anns.empty()) {
                auto bs = sal.extract_buffer_semantics(sal_anns, pd.seq);
                pd.sal_buffer_info = (uint32_t)bs.kind | ((uint32_t)bs.is_byte_count << 8);
                pd.sal_count_param = bs.count_param;
                pd.sal_count_expression = bs.count_expression;
                for (auto const& ann : sal_anns) {
                    switch (ann.kind) {
                        case SalKind::InOpt:
                        case SalKind::OutOpt:
                        case SalKind::InOutOpt:
                            // Optional parameter. This mapping did not exist
                            // at all — the CallbackOptional gate (callback
                            // type + PA::Opt) could never open.
                            pd.attr = (PA)((uint16_t)pd.attr | (uint16_t)PA::Opt);
                            break;
                        case SalKind::CheckReturn:
                        case SalKind::MustInspect: pd.sal_flags |= SF_CHECK_RETURN; break;
                        case SalKind::NullTerminated: pd.sal_flags |= SF_NULL_TERM; break;
                        case SalKind::NotNull: pd.sal_flags |= SF_NOT_NULL; break;
                        case SalKind::Nullable:
                        case SalKind::RetMaybenull: pd.sal_flags |= SF_MAYBE_NULL; break;
                        case SalKind::Success: pd.sal_flags |= SF_SUCCESS; break;
                        default: break;
                    }
                }
            }

            sig.pt.push_back(std::move(pt.ref));
            sig.params.push_back(std::move(pd));
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == '[') skip_balanced(src, pos, '[', ']');
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == '=') {
                ++pos;
                skip_to_char3(src, pos, ',', ')', ';');
            }
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == ',') ++pos;
            if (pos <= pstart) { skip_to_char(src, pos, ')'); break; }
        }
    }

    // type reader

    // stars_from_source: '*' characters actually consumed from the source
    // text. Needed by the typedef declarator-list path to split the base
    // pointer depth into "underlying type" vs "declarator" stars.
    struct TypeResult { ET elem = ET::Void; TRef ref{}; uint32_t stars_from_source = 0; };
    TypeResult read_type(std::string_view src, size_t& pos) {
        skip_ws(src, pos);
        TypeResult r;

        // Calling-convention/decoration macros that sit IN TYPE POSITION.
        // The parser reads raw text - Preprocessor defines only drive #if
        // evaluation, they never rewrite declaration bodies - so macros
        // like `#define __RPC_USER __stdcall` (rpc.h) must be skipped
        // lexically or read_type records them as bogus named classes that
        // poison every signature mentioning them (the empty `class
        // __RPC_USER` in the winmd).
        static const std::unordered_set<std::string_view> conv_macros = {
            "__RPC_USER", "__RPC_API", "__RPC_STUB", "RPC_ENTRY",
            "RPCRTAPI", "RPCNDLP", "RPC_IF_CALLBACK",
            "PASCAL", "CDECL", "CLIBAPI", "DACEL",
            "APICALL", "APIPRIVATE", "EXTERN_C",
            // winnt.h empty segment/annotation macros that appear in type
            // position in raw text (`void Foo(IN DWORD a)` params, `typedef
            // struct FAR *LPX`). Never real type names.
            "IN", "OUT", "FAR", "NEAR", "OPTIONAL", "OPTIONAL_",
            "CALLBACK", "WINAPI", "WINAPIV", "APIENTRY", "NTAPI",
            "STDMETHODCALLTYPE", "__RPC_FAR", "__RPC_DW",
        };
        for (int guard = 0; guard < 8; ++guard) {
            skip_ws(src, pos);
            bool skipped = false;
            for (auto const& cm : conv_macros) {
                if (match_w(src, pos, cm)) { pos += cm.size(); skip_ws(src, pos); skipped = true; break; }
            }
            if (!skipped) break;
        }

        bool saw_const = false;
        if (match_w(src, pos, "const")) { pos += 5; skip_ws(src, pos); saw_const = true; }
        // SDK spelled-uppercase const: winnt.h '#define CONST const'. Left
        // alone, read_type records it as a named class that eats the whole
        // parameter slot (`CONST ULONG_PTR* lpArguments` -> param CONST
        // named ULONG_PTR, lpArguments lost) and cascades into wrong
        // signatures in every consumer module.
        while (match_w(src, pos, "CONST")) { pos += 5; skip_ws(src, pos); saw_const = true; }
        if (match_w(src, pos, "volatile")) { pos += 8; skip_ws(src, pos); }
        if (match_w(src, pos, "__declspec")) {
            pos += 10; skip_ws(src, pos);
            if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            skip_ws(src, pos);
        }

        // Skip struct/class/union/enum prefix (e.g. struct Foo* as a type)
        if (match_w(src, pos, "struct") || match_w(src, pos, "class") ||
            match_w(src, pos, "union") || match_w(src, pos, "enum")) {
            if (match_w(src, pos, "struct")) pos += 6;
            else if (match_w(src, pos, "class")) pos += 5;
            else if (match_w(src, pos, "union")) pos += 5;
            else if (match_w(src, pos, "enum")) pos += 4;
            skip_ws(src, pos);
        }

        // Fundamental-type keywords. Multi-keyword sequences (unsigned long,
        // long long, unsigned short int, ...) must compose: each keyword
        // refines the running element type. Without composition 'unsigned
        // long' parsed as 'unsigned' and the trailing 'long' leaked out as a
        // garbage identifier, corrupting every signature that used it.
        {
            bool matched_fund = true;
            if      (match_w(src, pos, "void"))      { r.elem = ET::Void;  pos += 4; }
            else if (match_w(src, pos, "VOID"))      { r.elem = ET::Void;  pos += 4; }
            else if (match_w(src, pos, "BOOL"))      { r.elem = ET::Bool;  pos += 4; }
            else if (match_w(src, pos, "BOOLEAN"))   { r.elem = ET::Bool;  pos += 7; }
            else if (match_w(src, pos, "char"))      { r.elem = ET::I1;    pos += 4; }
            else if (match_w(src, pos, "int"))       { r.elem = ET::I4;    pos += 3; }
            else if (match_w(src, pos, "bool"))      { r.elem = ET::Bool;  pos += 4; }
            else if (match_w(src, pos, "float"))     { r.elem = ET::R4;    pos += 5; }
            else if (match_w(src, pos, "double"))    { r.elem = ET::R8;    pos += 6; }
            else if (match_w(src, pos, "wchar_t"))   { r.elem = ET::Char;  pos += 7; }
            else if (match_w(src, pos, "char16_t"))  { r.elem = ET::Char;  pos += 8; }
            else if (match_w(src, pos, "char32_t"))  { r.elem = ET::U4;    pos += 8; }
            else if (match_w(src, pos, "char8_t"))   { r.elem = ET::U1;    pos += 7; }
            else if (match_w(src, pos, "auto"))      { r.elem = ET::I4;    pos += 4; }
            else if (match_w(src, pos, "_BitInt"))   { r.elem = ET::I8;    pos += 7; skip_ws(src, pos); if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')'); }
            else if (match_w(src, pos, "nullptr_t")) { r.elem = ET::Ptr;   pos += 9; r.ref.name = "PVOID"; r.ref.ptr = 1; }
            else if (match_w(src, pos, "unsigned") || match_w(src, pos, "signed") ||
                     match_w(src, pos, "long")     || match_w(src, pos, "short")) {
                // signedness + width composition loop
                bool is_unsigned = false; bool have_sign = false;
                int width = 0;              // 0 = unspecified (int), 1 = short, 2 = long, 3 = long long
                bool explicit_width = false; // __intN sets width directly
                bool char_width = false;     // final 'char' in [un]signed char
                for (;;) {
                    skip_ws(src, pos);
                    if (!have_sign && match_w(src, pos, "unsigned")) { is_unsigned = true; have_sign = true; pos += 8; continue; }
                    if (!have_sign && match_w(src, pos, "signed"))   { have_sign = true; pos += 6; continue; }
                    // __intN inside the composition sequence: 'unsigned
                    // __int64 ULONG64' (basetsd.h/intsafe.h). Without this,
                    // 'unsigned' composes to U4, read_type stops before
                    // '__int64', and ULONG64 is recorded as a bogus class.
                    if (match_w(src, pos, "__int64")) { pos += 7; width = 3; explicit_width = true; continue; }
                    if (match_w(src, pos, "__int32")) { pos += 7; width = 2; explicit_width = true; continue; }
                    if (match_w(src, pos, "__int16")) { pos += 7; width = 1; explicit_width = true; continue; }
                    if (match_w(src, pos, "__int128")) { pos += 8; width = 5; explicit_width = true; continue; }
                    if (match_w(src, pos, "__int8"))  { pos += 6; width = 4; explicit_width = true; continue; } // byte-sized
                    if (match_w(src, pos, "long")) {
                        pos += 4;
                        // 'long long'
                        size_t save = pos; skip_ws(src, pos);
                        if (match_w(src, pos, "long")) { pos += 4; }
                        else pos = save;
                        width = width == 2 ? 3 : 2;
                        continue;
                    }
                    if (match_w(src, pos, "short"))  { pos += 5; width = 1; continue; }
                    if (match_w(src, pos, "int"))    { pos += 3; continue; } // 'int' adds nothing
                    // 'unsigned char' / 'signed char' — nothing valid follows,
                    // so this is the sequence's last word. Without it the loop
                    // breaks at 'unsigned' and 'char' leaks out as the FIELD
                    // NAME (GUID's `unsigned char Data4[8]` became a uint32
                    // field named 'char_').
                    if (match_w(src, pos, "char"))   { pos += 4; char_width = true; continue; }
                    break;
                }
                if (char_width) {
                    // [un]signed char: 8-bit, signedness from the prefix.
                    r.elem = is_unsigned ? ET::U1 : ET::I1;
                }
                else if (explicit_width) {
                    // __intN: exact width regardless of LLP64 'long' rules.
                    switch (width) {
                        case 1:  r.elem = is_unsigned ? ET::U2 : ET::I2; break;
                        case 2:  r.elem = is_unsigned ? ET::U4 : ET::I4; break;
                        case 3:  r.elem = is_unsigned ? ET::U8 : ET::I8; break;
                        case 5:  r.elem = is_unsigned ? ET::U8 : ET::I8; break; // __int128 → clamp to 64-bit (ECMA-335 has no I128)
                        default: r.elem = is_unsigned ? ET::U1 : ET::I1; break; // __int8
                    }
                }
                else if (width == 3) r.elem = is_unsigned ? ET::U8 : ET::I8; // long long
                else if (width == 2) r.elem = is_unsigned ? ET::U4 : ET::I4; // long (LLP64: 32-bit on Windows)
                else if (width == 1) r.elem = is_unsigned ? ET::U2 : ET::I2; // short
                else                 r.elem = is_unsigned ? ET::U4 : ET::I4; // bare int
            }
            else matched_fund = false;
            if (matched_fund) {
                // Consume pointer/array decorations before returning - the
                // early return must not skip the '*' suffix that the
                // fall-through tail normally handles (void*/int*/...).
                skip_ws(src, pos);
                while (pos < src.size() && src[pos] == '*') { ++r.ref.ptr; ++r.stars_from_source; ++pos; skip_ws(src, pos); }
                if (pos < src.size() && src[pos] == '&') { r.ref.byref = true; ++pos; }
                // Convention macros can trail the '*' too: `void * __RPC_USER
                // MIDL_user_allocate(...)` — __RPC_USER expands to __stdcall
                // (rpc.h) or empty, never a type. Skip them so the function
                // name, not the macro, becomes the declaration name.
                for (int cguard = 0; cguard < 8; ++cguard) {
                    skip_ws(src, pos);
                    bool skipped = false;
                    for (auto const& cm : conv_macros) {
                        if (match_w(src, pos, cm)) { pos += cm.size(); skip_ws(src, pos); skipped = true; break; }
                    }
                    if (!skipped) break;
                }
                while (pos < src.size() && src[pos] == '*') { ++r.ref.ptr; ++r.stars_from_source; ++pos; skip_ws(src, pos); }
                if (pos < src.size() && src[pos] == '&') { r.ref.byref = true; ++pos; }
                r.ref.elem = r.elem;
                return r;
            }
        }
        {
            auto id = read_ident(src, pos);
            if (id.empty()) { g_last_ident.clear(); return r; }

            // Skip WinRT / C++ standard library types — map to void*
            if (id.starts_with("std::") || id.starts_with("winrt::") ||
                id.starts_with("Windows::") || id.starts_with("Microsoft::") ||
                id.starts_with("ABI::") || id.starts_with("wil::")) {
                r.elem = ET::Ptr; r.ref.name = "PVOID"; r.ref.ptr = 1;
                // Skip rest of qualified name
                while (pos < src.size() && src[pos] == ':') { ++pos; skip_ws(src, pos); auto x = read_ident(src, pos); }
                skip_ws(src, pos);
                while (pos < src.size() && src[pos] == ':') { ++pos; skip_ws(src, pos); auto x = read_ident(src, pos); }
                return r;
            }

            struct TypeEntry { ET elem; const char* ref_name; uint32_t ptr; };
            static const std::unordered_map<std::string, TypeEntry> type_map = {
                {"CHAR",{ET::I1,"",0}},{"UCHAR",{ET::U1,"",0}},{"WCHAR",{ET::Char,"",0}},
                {"wchar_t",{ET::Char,"",0}},{"char16_t",{ET::Char,"",0}},
                {"char32_t",{ET::U4,"",0}},{"char8_t",{ET::U1,"",0}},
                {"SHORT",{ET::I2,"",0}},{"USHORT",{ET::U2,"",0}},
                {"LONG",{ET::I4,"",0}},{"ULONG",{ET::U4,"",0}},
                {"LONGLONG",{ET::I8,"",0}},{"ULONGLONG",{ET::U8,"",0}},
                {"INT",{ET::I4,"",0}},{"UINT",{ET::U4,"",0}},
                {"DWORD",{ET::U4,"",0}},{"DWORD64",{ET::U8,"",0}},
                {"WORD",{ET::U2,"",0}},{"BYTE",{ET::U1,"",0}},
                {"FLOAT",{ET::R4,"",0}},{"DOUBLE",{ET::R8,"",0}},
                {"INT8",{ET::I1,"",0}},{"UINT8",{ET::U1,"",0}},
                {"INT16",{ET::I2,"",0}},{"UINT16",{ET::U2,"",0}},
                {"INT32",{ET::I4,"",0}},{"UINT32",{ET::U4,"",0}},
                {"INT64",{ET::I8,"",0}},{"UINT64",{ET::U8,"",0}},
                // basetsd.h/intsafe.h 64-bit spellings: without these,
                // read_type's named path records 'typedef ULONG64 X' as a
                // targetless class (and ULONG64 itself as a bogus type).
                {"ULONG64",{ET::U8,"",0}},{"LONG64",{ET::I8,"",0}},
                {"DWORDLONG",{ET::U8,"",0}},{"DWORD64",{ET::U8,"",0}},
                {"__int8",{ET::I1,"",0}},{"__int16",{ET::I2,"",0}},
                {"__int32",{ET::I4,"",0}},{"__int64",{ET::I8,"",0}},
                {"__int128",{ET::I8,"",0}},{"__uint128",{ET::U8,"",0}},
                {"INT_PTR",{ET::I8,"",0}},{"UINT_PTR",{ET::U8,"",0}},
                {"LONG_PTR",{ET::I8,"",0}},{"ULONG_PTR",{ET::U8,"",0}},
                {"DWORD_PTR",{ET::U8,"",0}},
                {"SIZE_T",{ET::U8,"",0}},{"SSIZE_T",{ET::I8,"",0}},
                {"size_t",{ET::U8,"",0}},{"ssize_t",{ET::I8,"",0}},
                {"intptr_t",{ET::I8,"",0}},{"uintptr_t",{ET::U8,"",0}},
                {"ptrdiff_t",{ET::I8,"",0}},{"off_t",{ET::I8,"",0}},
                {"HRESULT",{ET::I4,"HRESULT",0}},{"NTSTATUS",{ET::I4,"NTSTATUS",0}},
                {"LRESULT",{ET::I8,"LRESULT",0}},{"LSTATUS",{ET::I4,"LSTATUS",0}},
                {"LPARAM",{ET::I8,"LPARAM",0}},{"WPARAM",{ET::U8,"WPARAM",0}},
                {"REGSAM",{ET::U4,"REGSAM",0}},{"ACCESS_MASK",{ET::U4,"ACCESS_MASK",0}},
                {"SECURITY_INFORMATION",{ET::U4,"SECURITY_INFORMATION",0}},
                {"NET_API_STATUS",{ET::U4,"NET_API_STATUS",0}},
                {"BOOLAPI",{ET::Bool,"",0}},{"WINAPI_FAMILY",{ET::U4,"",0}},
                {"WINOLEAPI",{ET::I4,"HRESULT",0}},{"WINOLEAUTAPI",{ET::I4,"HRESULT",0}},
                {"WINPRIVAPI",{ET::I4,"HRESULT",0}},
                {"STDAPI",{ET::I4,"HRESULT",0}},{"STDAPI_",{ET::I4,"HRESULT",0}},
                {"STDMETHODIMP",{ET::I4,"HRESULT",0}},{"STDMETHODIMP_",{ET::I4,"HRESULT",0}},
                // DECLARE_HANDLE-style handles (HANDLE, HWND, ...): the SDK
                // never has a plain typedef for these (the macro expands to
                // `struct x__*`), so the pointee is an unnamed void. Encoding
                // a named self-pointing target here made every alias of a
                // handle (typedef HANDLE HLOCAL) resolve to "pointer to
                // pointer to named handle" and gained one '*' per encode
                // (LocalFree -> void**). An empty ref_name encodes PTR(void),
                // the real ABI shape, while the enrich layer still knows the
                // handle kind from the typedef name.
                {"HANDLE",{ET::Ptr,"",1}},{"HWND",{ET::Ptr,"",1}},
                {"HINSTANCE",{ET::Ptr,"",1}},{"HMODULE",{ET::Ptr,"",1}},
                {"HKEY",{ET::Ptr,"",1}},{"HDC",{ET::Ptr,"",1}},
                {"HBITMAP",{ET::Ptr,"",1}},{"HMENU",{ET::Ptr,"",1}},
                {"HBRUSH",{ET::Ptr,"",1}},{"HFONT",{ET::Ptr,"",1}},
                {"HPEN",{ET::Ptr,"",1}},{"HICON",{ET::Ptr,"",1}},
                {"HCURSOR",{ET::Ptr,"",1}},{"HMONITOR",{ET::Ptr,"",1}},
                {"HGDIOBJ",{ET::Ptr,"",1}},{"HRSRC",{ET::Ptr,"",1}},
                {"HGLOBAL",{ET::Ptr,"",1}},
                {"SC_HANDLE",{ET::Ptr,"",1}},
                {"SERVICE_STATUS_HANDLE",{ET::Ptr,"",1}},
                {"SOCKET",{ET::Ptr,"",1}},
                {"GUID",{ET::ValType,"GUID",0}},{"IID",{ET::ValType,"IID",0}},
                {"CLSID",{ET::ValType,"CLSID",0}},
                {"BSTR",{ET::Ptr,"",1}},
                {"FARPROC",{ET::Ptr,"",1}},{"PROC",{ET::Ptr,"",1}},
                // Synthetic pointer-alias entries for LPVOID/LPWSTR/PSTR/...
                // removed: they were self-referential (PSTR -> Ptr(PSTR))
                // and shadowed the REAL typedefs from winnt.h, so every
                // param typed with them resolved to "pointer to another
                // pointer alias" and accumulated one extra '*' per
                // encode-time re-resolution (LocalFree -> void**, PSTR ->
                // PSTR**). The real typedefs record Ptr(Char/Char) with the
                // correct const flags; resolve_alias_chain substitutes them
                // fully (LPCWSTR -> Ptr(const Char) etc.).
                {"PDWORD",{ET::Ptr,"DWORD",1}},{"PULONG",{ET::Ptr,"ULONG",1}},
                {"PBOOL",{ET::Ptr,"BOOL",1}},{"PUCHAR",{ET::Ptr,"UCHAR",1}},
                {"PBYTE",{ET::Ptr,"BYTE",1}},{"PHANDLE",{ET::Ptr,"HANDLE",1}},
                {"LPDWORD",{ET::Ptr,"DWORD",1}},{"LPBOOL",{ET::Ptr,"BOOL",1}},
                {"LPLONG",{ET::Ptr,"LONG",1}},{"LPULONG",{ET::Ptr,"ULONG",1}},
                {"LPBYTE",{ET::Ptr,"BYTE",1}},{"LPWORD",{ET::Ptr,"WORD",1}},
                {"LPINT",{ET::Ptr,"INT",1}},{"LPUINT",{ET::Ptr,"UINT",1}},
                // Additional handles - all real `typedef void* X;` shapes,
                // encoded as unnamed void* pointees. Self-referential rows
                // (HLOCAL -> Ptr(HLOCAL)) stacked one '*' per re-resolution.
                {"HDEVINFO",{ET::Ptr,"",1}},{"HSPHANDLE",{ET::Ptr,"",1}},
                {"HCMNOTIFIER",{ET::Ptr,"",1}},
                {"HCERTSTORE",{ET::Ptr,"",1}},{"HCRYPTPROV",{ET::Ptr,"",1}},
                {"HCRYPTKEY",{ET::Ptr,"",1}},{"HCRYPTHASH",{ET::Ptr,"",1}},
                {"HINTERNET",{ET::Ptr,"",1}},
                {"HGLRC",{ET::Ptr,"",1}},{"HDESK",{ET::Ptr,"",1}},
                {"HWINSTA",{ET::Ptr,"",1}},{"HACCEL",{ET::Ptr,"",1}},
                {"HPALETTE",{ET::Ptr,"",1}},{"HMETAFILE",{ET::Ptr,"",1}},
                {"HENHMETAFILE",{ET::Ptr,"",1}},{"HRGN",{ET::Ptr,"",1}},
                {"HLOCAL",{ET::Ptr,"",1}},
                {"FILETIME",{ET::ValType,"FILETIME",0}},
                {"SYSTEMTIME",{ET::ValType,"SYSTEMTIME",0}},
                {"SECURITY_ATTRIBUTES",{ET::ValType,"SECURITY_ATTRIBUTES",0}},
                {"OVERLAPPED",{ET::ValType,"OVERLAPPED",0}},{"POINT",{ET::ValType,"POINT",0}},
                {"SIZE",{ET::ValType,"SIZE",0}},{"RECT",{ET::ValType,"RECT",0}},
                {"WNDCLASSW",{ET::ValType,"WNDCLASSW",0}},{"WNDCLASSA",{ET::ValType,"WNDCLASSA",0}},
                {"MSG",{ET::ValType,"MSG",0}},
                {"BY_HANDLE_FILE_INFORMATION",{ET::ValType,"BY_HANDLE_FILE_INFORMATION",0}},
                {"WIN32_FIND_DATAW",{ET::ValType,"WIN32_FIND_DATAW",0}},
                {"WIN32_FIND_DATAA",{ET::ValType,"WIN32_FIND_DATAA",0}},
                {"MEMORYSTATUS",{ET::ValType,"MEMORYSTATUS",0}},
                {"SYSTEM_INFO",{ET::ValType,"SYSTEM_INFO",0}},
                {"OSVERSIONINFOEXW",{ET::ValType,"OSVERSIONINFOEXW",0}},
                {"OSVERSIONINFOEXA",{ET::ValType,"OSVERSIONINFOEXA",0}},
                {"STARTUPINFOW",{ET::ValType,"STARTUPINFOW",0}},
                {"STARTUPINFOA",{ET::ValType,"STARTUPINFOA",0}},
                {"PROCESS_INFORMATION",{ET::ValType,"PROCESS_INFORMATION",0}},
                {"SECURITY_DESCRIPTOR",{ET::ValType,"SECURITY_DESCRIPTOR",0}},
                {"ACL",{ET::ValType,"ACL",0}},
                {"LARGE_INTEGER",{ET::ValType,"LARGE_INTEGER",0}},
                {"ULARGE_INTEGER",{ET::ValType,"ULARGE_INTEGER",0}},
                {"LIST_ENTRY",{ET::ValType,"LIST_ENTRY",0}},
                {"SINGLE_LIST_ENTRY",{ET::ValType,"SINGLE_LIST_ENTRY",0}},
                {"OBJECT_ATTRIBUTES",{ET::ValType,"OBJECT_ATTRIBUTES",0}},
                {"IO_STATUS_BLOCK",{ET::ValType,"IO_STATUS_BLOCK",0}},
                {"UNICODE_STRING",{ET::ValType,"UNICODE_STRING",0}},
                {"ANSI_STRING",{ET::ValType,"ANSI_STRING",0}},
                {"CLIENT_ID",{ET::ValType,"CLIENT_ID",0}},
                {"STRING",{ET::ValType,"STRING",0}},
                {"FLOAT128",{ET::ValType,"FLOAT128",0}},
                {"FLOATING_SAVE_AREA",{ET::ValType,"FLOATING_SAVE_AREA",0}},
                {"CONTEXT",{ET::ValType,"CONTEXT",0}},
                {"EXCEPTION_RECORD",{ET::ValType,"EXCEPTION_RECORD",0}},
                {"EXCEPTION_POINTERS",{ET::ValType,"EXCEPTION_POINTERS",0}},
                {"CRYPTOAPI_BLOB",{ET::ValType,"CRYPTOAPI_BLOB",0}},
                {"LUID",{ET::ValType,"LUID",0}},
                {"LUID_AND_ATTRIBUTES",{ET::ValType,"LUID_AND_ATTRIBUTES",0}},
                {"TOKEN_PRIVILEGES",{ET::ValType,"TOKEN_PRIVILEGES",0}},
                {"SOCKADDR",{ET::ValType,"SOCKADDR",0}},
                {"SOCKADDR_IN",{ET::ValType,"SOCKADDR_IN",0}},
                {"IN_ADDR",{ET::ValType,"IN_ADDR",0}},
                {"WSADATA",{ET::ValType,"WSADATA",0}},
                {"ADDRINFOA",{ET::ValType,"ADDRINFOA",0}},
                {"ADDRINFOW",{ET::ValType,"ADDRINFOW",0}},
                {"hostent",{ET::ValType,"hostent",0}},
                {"timeval",{ET::ValType,"timeval",0}},
                {"fd_set",{ET::ValType,"fd_set",0}},
                {"GUID_DEFINED",{ET::ValType,"GUID_DEFINED",0}},
                {"__MIDL___MIDL_itf_guid_0000_0000",{ET::ValType,"GUID",0}},
                {"SC_ACTION",{ET::ValType,"SC_ACTION",0}},
                {"SERVICE_DESCRIPTIONW",{ET::ValType,"SERVICE_DESCRIPTIONW",0}},
                {"SERVICE_DESCRIPTIONA",{ET::ValType,"SERVICE_DESCRIPTIONA",0}},
                {"QUERY_SERVICE_CONFIGW",{ET::ValType,"QUERY_SERVICE_CONFIGW",0}},
                {"QUERY_SERVICE_CONFIGA",{ET::ValType,"QUERY_SERVICE_CONFIGA",0}},
                {"SERVICE_STATUS",{ET::ValType,"SERVICE_STATUS",0}},
                {"ENUM_SERVICE_STATUSW",{ET::ValType,"ENUM_SERVICE_STATUSW",0}},
                {"ENUM_SERVICE_STATUSA",{ET::ValType,"ENUM_SERVICE_STATUSA",0}},
                {"CRYPT_BIT_BLOB",{ET::ValType,"CRYPT_BIT_BLOB",0}},
                {"CRYPT_ALGORITHM_IDENTIFIER",{ET::ValType,"CRYPT_ALGORITHM_IDENTIFIER",0}},
                {"CERT_INFO",{ET::ValType,"CERT_INFO",0}},
                {"CERT_CONTEXT",{ET::ValType,"CERT_CONTEXT",0}},
                {"CERT_REVOCATION_CRL_INFO",{ET::ValType,"CERT_REVOCATION_CRL_INFO",0}},
                {"CERT_TRUST_STATUS",{ET::ValType,"CERT_TRUST_STATUS",0}},
                {"CRYPT_DATA_BLOB",{ET::ValType,"CRYPT_DATA_BLOB",0}},
                {"CERT_CHAIN_CONTEXT",{ET::ValType,"CERT_CHAIN_CONTEXT",0}},
                {"CRYPT_INTEGER_BLOB",{ET::ValType,"CRYPT_INTEGER_BLOB",0}},
                {"BCRYPT_ALGORITHM_IDENTIFIER",{ET::ValType,"BCRYPT_ALGORITHM_IDENTIFIER",0}},
                {"BCRYPT_KEY_HANDLE",{ET::Ptr,"BCRYPT_KEY_HANDLE",1}},
                {"BCRYPT_HASH_HANDLE",{ET::Ptr,"BCRYPT_HASH_HANDLE",1}},
                {"BCRYPT_SECRET_HANDLE",{ET::Ptr,"BCRYPT_SECRET_HANDLE",1}},
                {"NCryptProviderHandle",{ET::Ptr,"NCryptProviderHandle",1}},
                {"NCryptKeyHandle",{ET::Ptr,"NCryptKeyHandle",1}},
                {"NCryptSecretHandle",{ET::Ptr,"NCryptSecretHandle",1}},
            };

            auto it = type_map.find(std::string(id));
            if (it != type_map.end()) {
                r.elem = it->second.elem;
                r.ref.name = it->second.ref_name;
                r.ref.ptr = it->second.ptr;
                r.ref.elem = r.elem; // keep TRef.elem in sync: signature
                                     // encoders take MSig.ret from TRef.elem;
                                     // leaving it unset made every named-type
                                     // return (PTP_POOL, ...) encode as VOID.
                if (r.elem != ET::Class && r.elem != ET::ValType && r.elem != ET::Ptr)
                    r.ref.elem = r.elem; // fundamental alias (INT/UINT/DWORD/...)
                g_last_ident = std::string(id);
            }
            else {
                // Never treat C++ statement/decl keywords as type names:
                // they leak from unmodeled template member bodies and would
                // encode as bogus classes (`DXTMPL::return`). The caller's
                // recovery path skips the token instead.
                static const std::unordered_set<std::string_view> not_types = {
                    "return", "break", "continue", "goto", "case", "default",
                    "if", "else", "while", "for", "do", "switch",
                    "typedef", "extern", "static", "register", "inline",
                };
                if (not_types.count(id)) { g_last_ident.clear(); return r; }
                r.elem = ET::Class;
                r.ref.name = std::string(id);
                r.ref.elem = r.elem; // named type: TRef.elem must mirror,
                                     // otherwise the return encodes as VOID
                g_last_ident = std::string(id);
            }
        }
        skip_ws(src, pos);

        // Parameterized return-type macros: WINOLEAPI_(void), STDAPI_(type),
        // where the declared name would sit. Expand: treat inner as the real
        // return type, then continue with the actual function name.
        {
            static const std::unordered_set<std::string> param_return_macros = {
                "WINOLEAPI_", "STDAPI_", "EXTERN_C", "PSSTDAPI_", "STDMETHODIMP_",
                "WINOLESTATICCTYPE_", "PAPI_", "IFACEMETHOD_",
            };
            auto pm_it = param_return_macros.find(std::string(g_last_ident));
            if (pm_it != param_return_macros.end() && pos < src.size() && src[pos] == '(') {
                ++pos; // consume '('
                // Inner text can carry SAL annotations:
                // WINOLEAPI_(_Ret_opt_ ... _Check_return_ LPVOID). Strip
                // reserved (_-prefixed) tokens with their argument lists so
                // read_type sees the real return type.
                for (int guard = 0; guard < 24; ++guard) {
                    skip_ws(src, pos);
                    if (pos >= src.size() || src[pos] != '_') break;
                    read_ident(src, pos);
                    skip_ws(src, pos);
                    if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
                }
                // Re-read the inner tokens as the actual return type.
                r = TypeResult{};
                auto inner = read_type(src, pos);
                if (pos < src.size() && src[pos] == ')') ++pos; // consume ')'
                skip_ws(src, pos);
                // read_type may have consumed '*' — keep inner ref/ptr info
                r = inner;
                skip_ws(src, pos);
                while (pos < src.size() && src[pos] == '*') { ++r.ref.ptr; ++r.stars_from_source; ++pos; skip_ws(src, pos); }
            }
        }
        skip_ws(src, pos);
        while (pos < src.size() && src[pos] == '*') { ++r.ref.ptr; ++r.stars_from_source; ++pos; skip_ws(src, pos); }
        // Trailing pointee-const (`int* const`) and const-after-* styles are
        // rare; `const T*` is recorded above, pointer-to-const pointee is the
        // common C shape and reads back the same either way for projection.
        if (saw_const) r.ref.pt_const = true;
        return r;
    }

    // expression reader

    int64_t read_const_expr(std::string_view src, size_t& pos) {
        skip_ws(src, pos);
        if (pos >= src.size()) return 0;

        if (src[pos] == '(') {
            skip_balanced(src, pos, '(', ')');
            return 0;
        }
        if (src[pos] == '"') {
            skip_string_literal(src, pos);
            return 0;
        }
        if (src[pos] == '\'') {
            skip_char_literal(src, pos);
            return 0;
        }
        if (src[pos] == '-' || src[pos] == '+') {
            bool negate = (src[pos] == '-');
            ++pos;
            skip_ws(src, pos);
            int64_t v = read_const_expr(src, pos);
            return negate ? -v : v;
        }
        if (match_w(src, pos, "sizeof")) {
            pos += 6;
            skip_ws(src, pos);
            if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            return 0;
        }
        if (match_w(src, pos, "TRUE")) { pos += 4; return 1; }
        if (match_w(src, pos, "FALSE")) { pos += 5; return 0; }
        if (match_w(src, pos, "NULL")) { pos += 4; return 0; }
        if (match_w(src, pos, "0x") || match_w(src, pos, "0X")) {
            pos += 2;
            size_t start = pos;
            while (pos < src.size() && std::isxdigit((unsigned char)src[pos])) ++pos;
            auto hex = src.substr(start, pos - start);
            try { return std::stoll(std::string(hex), nullptr, 16); } catch (...) { return 0; }
        }
        if (src[pos] == '0' && pos + 1 < src.size() && (src[pos + 1] == 'x' || src[pos + 1] == 'X')) {
            pos += 2;
            size_t start = pos;
            while (pos < src.size() && std::isxdigit((unsigned char)src[pos])) ++pos;
            auto hex = src.substr(start, pos - start);
            try { return std::stoll(std::string(hex), nullptr, 16); } catch (...) { return 0; }
        }
        size_t start = pos;
        if (pos < src.size() && src[pos] == '-') ++pos;
        while (pos < src.size() && std::isdigit((unsigned char)src[pos])) ++pos;
        auto dec = src.substr(start, pos - start);
        if (dec.empty() || dec == "-") {
            auto id = read_ident(src, pos);
            return 0;
        }
        try { return std::stoll(std::string(dec)); } catch (...) { return 0; }
    }

    // skippers

    void skip_ws(std::string_view src, size_t& pos) {
        while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r' || src[pos] == '\n')) ++pos;
    }

    void skip_to_eol(std::string_view src, size_t& pos) {
        while (pos < src.size() && src[pos] != '\n') ++pos;
    }

    void skip_to_next_statement(std::string_view src, size_t& pos) {
        int depth = 0;
        while (pos < src.size()) {
            char c = src[pos];
            if (depth == 0 && (c == ';' || c == '\n')) { ++pos; return; }
            if (c == '(' || c == '{' || c == '[') ++depth;
            else if (c == ')' || c == '}' || c == ']') { if (depth > 0) --depth; else { ++pos; return; } }
            else if (c == '\'' && depth == 0) { skip_char_literal(src, pos); continue; }
            else if (c == '"' && depth == 0) { skip_string_literal(src, pos); continue; }
            ++pos;
        }
    }

    void skip_to_char(std::string_view src, size_t& pos, char target) {
        int depth = 0;
        while (pos < src.size()) {
            char c = src[pos];
            if (depth == 0 && c == target) return;
            if (c == '(' || c == '{' || c == '[') ++depth;
            else if (c == ')' || c == '}' || c == ']') { if (depth > 0) --depth; }
            else if (c == '\'') { skip_char_literal(src, pos); continue; }
            else if (c == '"') { skip_string_literal(src, pos); continue; }
            ++pos;
        }
    }

    void skip_to_char3(std::string_view src, size_t& pos, char a, char b, char c) {
        int depth = 0;
        while (pos < src.size()) {
            char ch = src[pos];
            if (depth == 0 && (ch == a || ch == b || ch == c)) return;
            if (ch == '(' || ch == '{' || ch == '[') ++depth;
            else if (ch == ')' || ch == '}' || ch == ']') { if (depth > 0) --depth; }
            else if (ch == '\'') { skip_char_literal(src, pos); continue; }
            else if (ch == '"') { skip_string_literal(src, pos); continue; }
            ++pos;
        }
    }

    void skip_block_comment(std::string_view src, size_t& pos) {
        while (pos + 1 < src.size()) {
            if (src[pos] == '*' && src[pos + 1] == '/') { pos += 2; return; }
            ++pos;
        }
        pos = src.size();
    }

    void skip_balanced(std::string_view src, size_t& pos, char open, char close) {
        if (pos >= src.size() || src[pos] != open) return;
        int depth = 0;
        size_t iter = 0;
        while (pos < src.size()) {
            if (++iter > BODY_ITER_LIMIT) return;
            char c = src[pos];
            if (c == open) ++depth;
            else if (c == close) { --depth; if (depth == 0) { ++pos; return; } }
            else if (c == '\'') { skip_char_literal(src, pos); continue; }
            else if (c == '"') { skip_string_literal(src, pos); continue; }
            ++pos;
        }
    }

    void skip_char_literal(std::string_view src, size_t& pos) {
        if (pos >= src.size() || src[pos] != '\'') return;
        ++pos;
        if (pos < src.size() && src[pos] == '\\') { pos += 2; }
        else if (pos < src.size()) { ++pos; }
        if (pos < src.size() && src[pos] == '\'') ++pos;
    }

    void skip_string_literal(std::string_view src, size_t& pos) {
        if (pos >= src.size() || src[pos] != '"') return;
        ++pos;
        while (pos < src.size() && src[pos] != '"') {
            if (src[pos] == '\\') ++pos;
            ++pos;
        }
        if (pos < src.size()) ++pos;
    }

    void skip_extern_block(std::string_view src, size_t& pos) {
        pos += 6;
        skip_ws(src, pos);
        if (pos < src.size() && src[pos] == '"') {
            ++pos;
            while (pos < src.size() && src[pos] != '"') ++pos;
            if (pos < src.size()) ++pos;
        }
        skip_ws(src, pos);
        if (pos < src.size() && src[pos] == '{') {
            skip_balanced(src, pos, '{', '}');
        }
    }

    // stop_at_sal: callers that follow with sal.parse_all need SAL tokens
    // left in place — _In_ & friends are decl-specifiers to every other
    // caller (skip them), but the SAL parser must see them or the whole
    // buffer-semantics family stays dead.
    // Whitespace + comment skipper. MIDL-generated COM headers annotate
    // nearly every token (`virtual /* [propget] */ HRESULT STDMETHODCALLTYPE
    // Foo( /* [in] */ DWORD flags)`), and the decl-specifier/param readers
    // stopped dead at '/', silently dropping the whole declaration.
    void skip_ws_comments(std::string_view src, size_t& pos) {
        for (;;) {
            skip_ws(src, pos);
            if (pos + 1 >= src.size() || src[pos] != '/') break;
            if (src[pos + 1] == '*') { pos += 2; skip_block_comment(src, pos); }
            else if (src[pos + 1] == '/') { while (pos < src.size() && src[pos] != '\n') ++pos; }
            else break;
        }
    }

    void skip_decl_specifiers(std::string_view src, size_t& pos, bool stop_at_sal = false) {
        skip_ws_comments(src, pos);
        for (int guard = 0; guard < 50; ++guard) {
            if (pos >= src.size()) return;
            // Annotations are newline-separated: after consuming one
            // _When_(...) the cursor sits on whitespace, and without a
            // resync the generic-identifier path below reads the NEXT
            // annotation name as a bare specifier - consuming `_When_`
            // but NOT its parenthesized arguments, which then poison the
            // following parameter slots (FormatMessageA/W lpBuffer/nSize/
            // Arguments all mangled into voids).
            skip_ws_comments(src, pos);
            if (pos >= src.size()) return;

            if (src[pos] == '_' && pos + 1 < src.size() && std::isalpha((unsigned char)src[pos + 1])) {
                size_t id_start = pos;
                ++pos;
                while (pos < src.size() && (std::isalnum((unsigned char)src[pos]) || src[pos] == '_')) ++pos;
                std::string_view id = src.substr(id_start, pos - id_start);
                if (stop_at_sal && SalParser::is_sal_annotation(id.substr(1))) {
                    pos = id_start; // rewind: leave the token for parse_all
                    return;
                }
                // Return-value annotations: recorded so the enricher can emit
                // MustCheck / NullableResult. Without this the skipper ate
                // them silently and MustCheck never fired for any API.
                {
                    auto stem = id.substr(1);
                    if (!stem.empty() && stem.back() == '_') stem.remove_suffix(1);
                    if (stem == "Must_inspect_result" || stem == "Check_return")
                        g_decl_flags_sink |= FNF_MUST_CHECK;
                    else if (stem == "Ret_maybenull" || stem == "Ret_opt")
                        g_decl_flags_sink |= FNF_RET_MAYBENULL;
                }
                skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') {
                    skip_balanced(src, pos, '(', ')');
                }
                continue;
            }

            if (match_w(src, pos, "__attribute__")) {
                pos += 12; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else if (match_w(src, pos, "__declspec")) {
                pos += 10; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') {
                    // __declspec(deprecated("reason")) — capture for the Obsolete attribute
                    size_t dstart = pos + 1;
                    skip_balanced(src, pos, '(', ')');
                    size_t dend = (pos > dstart) ? pos - 1 : dstart;
                    auto slice = src.substr(dstart, dend - dstart);
                    auto dq = slice.find("deprecated");
                    if (dq != std::string_view::npos) {
                        g_decl_flags_sink |= FNF_DEPRECATED;
                        auto ob = slice.find('(', dq);
                        if (ob != std::string_view::npos) {
                            auto cb = slice.find(')', ob);
                            if (cb != std::string_view::npos && cb > ob + 1) {
                                auto msg = slice.substr(ob + 1, cb - ob - 1);
                                while (!msg.empty() && (msg.front() == ' ' || msg.front() == '"')) msg.remove_prefix(1);
                                while (!msg.empty() && (msg.back() == ' ' || msg.back() == '"')) msg.remove_suffix(1);
                                g_decl_msg_sink.assign(msg);
                            }
                        }
                    }
                }
            } else if (match_w(src, pos, "__annotation")) {
                pos += 11; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else if (match_w(src, pos, "__pragma")) {
                pos += 8; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else if (match_w(src, pos, "__attribute")) {
                pos += 10; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else if (match_w(src, pos, "__extension__")) {
                pos += 13;
            } else if (match_w(src, pos, "__asm__")) {
                pos += 7; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else if (match_w(src, pos, "asm")) {
                pos += 3; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else if (match_w(src, pos, "__asm")) {
                pos += 5; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')');
            } else {
                size_t id_start = pos;
                auto id = read_ident(src, pos);
                if (id.empty()) return;
                // Record inline/deprecation specifiers for the enricher.
                if (id == "__forceinline") g_decl_flags_sink |= FNF_FORCEINLINE;
                else if (id == "__inline" || id == "__inline__" || id == "FORCEINLINE" ||
                         id == "WINFORCEINLINE" || id == "NTAPI_INLINE" || id == "__CRT_INLINE")
                    g_decl_flags_sink |= FNF_INLINE;
                else if (id == "DECLSPEC_DEPRECATED" || id == "DEPRECATED")
                    g_decl_flags_sink |= FNF_DEPRECATED;
                static const std::unordered_set<std::string> specifiers = {
                    "__forceinline","__inline","FORCEINLINE","WINFORCEINLINE","NTAPI_INLINE",
                    "DECLSPEC_NORETURN","DECLSPEC_ALIGN","DECLSPEC_ALLOCATOR","NTAPI",
                    "APIENTRY","CALLBACK","WINAPI","API","STDMETHODCALLTYPE","WINAPIV",
                    "__w64","__int128","__ptr64","__ptr32","__sptr","__uptr",
                    "static","extern","__restrict","__volatile","__const","const","volatile",
                    "WINUSERAPI","WINBASEAPI","WINGDIAPI","WINMMAPI","WINADVAPI",
                    "WINHTTPAPI","WININETAPI","WINSOCK_API_LINKAGE","WINSOCK2_API",
                    "SHSTDAPI","SHDOCAPI","COMMCTRLAPI","SCARDAPI","WINSCARDAPI",
                    "OLEDBAPI","WINOLEAUTAPI","WINPRIVAPI","OBJECTAPI","ROAPI",
                    "HRESULT STDMETHODCALLTYPE","DECLARE_STDMETHOD_METHODS",
                    "WINSCARDAPI","SOCKADDR",
                    "_Noreturn","_Thread_local","_Atomic","_Generic","_Static_assert",
                    "_Alignas","_Alignof","__thread","__declspec","__attribute__",
                    "__extension__","__asm__","asm","__asm","__inline__",
                    "DECLSPEC_DEPRECATED","DEPRECATED","RESTRICT","__cdecl",
                    // 16-bit-era distance macros that are EMPTY in modern SDKs
                    // (`#define FAR`): `LPVOID FAR * ppv` must project as one
                    // `void**` param, not name+FAR-star garbage.
                    "FAR","NEAR","far","near","__far","__near","_FAR","_NEAR",
                    "DECLSPEC_IMPORT","DECLSPEC_EXPORT","ROAPI","ROAPI_",
                    "UNALIGNED","__unaligned","DECLSPEC_UUID","DECLSPEC_NOVTABLE",
                    "DECLSPEC_SELECTANY","MIDL_INTERFACE",
                    "DECLARE_HANDLE","DECLARE_GUID",
                    "NTAPI_INLINE","__CRTDECL","__CRT_INLINE","__CRT_USED","__CRT_GUARD",
                    // C++ keywords
                    "constexpr","consteval","constinit","noexcept","override","final",
                    "mutable","explicit","virtual","friend","register","thread_local",
                    "alignas","alignof","decltype","typeid","operator","explicit",
                    "class","struct","union","enum","namespace","concept","requires",
                    "co_await","co_return","co_yield","module","import","export",
                    "using","template","static_assert","throw","try","catch","new","delete",
                    // MSVC SAL annotations
                    "_In_","_Out_","_Inout_","_In_opt_","_Out_opt_","_Inout_opt_",
                    "_In_reads_","_Out_writes_","_In_reads_bytes_","_Out_writes_bytes_",
                    "_In_reads_z_","_Out_writes_z_","_Inout_updates_","_Inout_updates_bytes_",
                    "_In_reads_opt_","_Out_writes_opt_","_Inout_updates_opt_",
                    "_Field_size_","_Field_size_opt_","_Field_size_bytes_",
                    "_Return_type_success_","_Return_type_failure_","_Success_","_Failure_",
                    "_Pre_satisfies_","_Post_satisfies_","_Must_inspect_result_",
                    "_When_","_At_","_Group_","_Releases_lock_","_Releases_exclusive_lock_",
                    "_Acquires_lock_","_Acquires_exclusive_lock_",
                    "_Requires_lock_held_","_Analysis_assume_lock_held_",
                    "_Guarded_by_","_Write_guarded_by_",
                    "_Interlocked_operand_","_Printf_format_string_",
                    "_Structurally_equal_","_Maybe_raises_SEH",
                    "_Post_z_","_Post_maybez_","_Pre_valid_","_Post_valid_",
                    "_Pre_notnull_","_Pre_maybenull_","_Pre_valid_",
                    "_On_failure_","_On_success_",
                    "__drv_allocatesMem","__drv_freesMem","__drv_allocatesMem",
                    "__nullterminated","__nullnullterminated","__maybenull","__mustbenull",
                    "__post","__pre","__field_ecs","__field_range","__field_size",
                    "__orderby","__genonymous",
                    "__drv_linedriver","__drv_functionType","__drv_printer",
                    "__drv_dispatchType","__drv_callback",
                    // Additional SAL
                    "_Readable_bytes_","_Readable_bytes_result_",
                    "_Writable_bytes_","_Writable_bytes_result_",
                    "_Struct_size_","_Bytecount_","_Unchanged_",
                    "_Analysis_assume_","_Benign_race_begin_","_Benign_race_end_",
                    "_No_competing_thread_begin_","_No_competing_thread_end_",
                    "_Acquires_exclusive_lock_","_Releases_exclusive_lock_",
                    "_Acquires_shared_lock_","_Releases_shared_lock_",
                    "_Discards_result_","_Maybe_discard_result_",
                    "__drv_allocatesMem","__drv_freesMem","__drv_allocatesMem",
                    "_Raises_SEH_exception_","_Maybe_raises_SEH_exception_",
                    // C++ memory/model
                    "_Atomic","_Noreturn","_Thread_local","__thread",
                    // Additional specifiers found in SDK headers
                    "__CRTDECL","__CRT_INLINE","__CRT_USED","__CRT_GUARD",
                    "CALLBACK","APIENTRY","WINAPI","NTAPI","STDMETHODCALLTYPE",
                    "STDMETHODVCALLTYPE","__cdecl","__stdcall","__fastcall","__thiscall",
                    "WINBASEAPI","WINUSERAPI","WINGDIAPI","WINMMAPI","WINADVAPI",
                    "WINHTTPAPI","WININETAPI","WINSOCK_API_LINKAGE","WINSOCK2_API",
                    "SHSTDAPI","SHDOCAPI","COMMCTRLAPI","SCARDAPI","WINSCARDAPI",
                    "OLEDBAPI","WINOLEAUTAPI","WINPRIVAPI","OBJECTAPI","ROAPI",
                };
                if (specifiers.count(std::string(id))) {
                    skip_ws(src, pos);
                    continue;
                }
                pos = id_start;
                return;
            }
            skip_ws_comments(src, pos);
        }
    }

    void skip_calling_convention(std::string_view src, size_t& pos) {
        skip_ws(src, pos);
        for (int guard = 0; guard < 10; ++guard) {
            if (pos >= src.size()) return;
            if      (match_w(src, pos, "WINAPI"))           { pos += 6; }
            else if (match_w(src, pos, "APIENTRY"))         { pos += 8; }
            else if (match_w(src, pos, "NTAPI"))            { pos += 5; }
            else if (match_w(src, pos, "CALLBACK"))         { pos += 8; }
            else if (match_w(src, pos, "U_CALLCONV"))       { pos += 11; }
            else if (match_w(src, pos, "U_EXPORT2"))        { pos += 9; }
            else if (match_w(src, pos, "U_CDECL"))          { pos += 7; }
            // oprghdlr.h: `#define EXPORT __cdecl` sits between the
            // return type and the callback name (`typedef VOID EXPORT
            // ACPI_OP_REGION_CALLBACK(...)`); without this the macro
            // becomes the alias name and the real callback is swallowed.
            else if (match_w(src, pos, "EXPORT"))           { pos += 6; }
            else if (match_w(src, pos, "STDMETHODCALLTYPE")){ pos += 18; }
            else if (match_w(src, pos, "__stdcall"))        { pos += 9; }
            else if (match_w(src, pos, "__cdecl"))          { pos += 7; }
            else if (match_w(src, pos, "__fastcall"))       { pos += 10; }
            else if (match_w(src, pos, "__thiscall"))       { pos += 10; }
            else if (match_w(src, pos, "noexcept"))         { pos += 8; }
            else if (match_w(src, pos, "constexpr"))        { pos += 9; }
            else if (match_w(src, pos, "consteval"))        { pos += 9; }
            else if (match_w(src, pos, "override"))         { pos += 8; }
            else if (match_w(src, pos, "final"))            { pos += 5; }
            else if (match_w(src, pos, "const"))            { pos += 5; }
            else if (match_w(src, pos, "volatile"))         { pos += 8; }
            else if (match_w(src, pos, "mutable"))          { pos += 7; }
            else if (match_w(src, pos, "explicit"))         { pos += 8; }
            else if (match_w(src, pos, "virtual"))          { pos += 7; }
            else if (match_w(src, pos, "__forceinline"))    { pos += 13; }
            else if (match_w(src, pos, "__inline"))         { pos += 8; }
            else if (match_w(src, pos, "WS2TCPIP_INLINE"))  { pos += 15; }
            else if (match_w(src, pos, "WSK_INLINE"))       { pos += 10; }
            else if (match_w(src, pos, "NDIS_INLINE"))      { pos += 11; }
            else if (match_w(src, pos, "static"))           { pos += 6; }
            else if (match_w(src, pos, "extern"))           { pos += 6; }
            else if (match_w(src, pos, "inline"))           { pos += 6; }
            else if (match_w(src, pos, "DEPRECATED"))       { pos += 10; }
            else if (match_w(src, pos, "__RPC_USER"))       { pos += 10; }
            else if (match_w(src, pos, "__RPC_API"))        { pos += 10; }
            else if (match_w(src, pos, "__RPC_STUB"))       { pos += 10; }
            else if (match_w(src, pos, "RPC_ENTRY"))        { pos += 9; }
            else if (match_w(src, pos, "RPCRTAPI"))         { pos += 8; }
            else if (match_w(src, pos, "RPCNDLP"))          { pos += 7; }
            else if (match_w(src, pos, "IN"))               { pos += 2; }
            else if (match_w(src, pos, "OUT"))              { pos += 3; }
            else if (match_w(src, pos, "OPTIONAL"))         { pos += 8; }
            else if (match_w(src, pos, "PASCAL"))           { pos += 6; }
            else if (match_w(src, pos, "__declspec"))       { pos += 10; skip_ws(src, pos);
                if (pos < src.size() && src[pos] == '(') skip_balanced(src, pos, '(', ')'); }
            else if (pos < src.size() && src[pos] == '[' && pos + 1 < src.size() && src[pos+1] == '[') {
                skip_balanced(src, pos, '[', ']');
            }
            else break;
            skip_ws(src, pos);
        }
    }

    // helpers

    std::string_view read_ident(std::string_view src, size_t& pos) {
        skip_ws(src, pos);
        size_t start = pos;
        while (pos < src.size() && (std::isalnum((unsigned char)src[pos]) || src[pos] == '_')) ++pos;
        return src.substr(start, pos - start);
    }

    std::string read_ident_at_last(size_t last_start, std::string_view src) {
        size_t p = last_start;
        skip_ws(src, p);
        while (p < src.size() && (std::isalnum((unsigned char)src[p]) || src[p] == '_')) ++p;
        size_t end = p;
        while (end > last_start && (std::isalnum((unsigned char)src[end - 1]) || src[end - 1] == '_')) --end;
        return std::string(src.substr(end, p - end));
    }

    bool match_w(std::string_view src, size_t pos, std::string_view w) {
        if (pos + w.size() > src.size()) return false;
        if (pos > 0 && (std::isalnum((unsigned char)src[pos - 1]) || src[pos - 1] == '_')) return false;
        auto after = pos + w.size();
        if (after < src.size() && (std::isalnum((unsigned char)src[after]) || src[after] == '_')) return false;
        return src.substr(pos, w.size()) == w;
    }

    bool lookahead_fnptr(std::string_view src, size_t pos) {
        skip_ws(src, pos);
        while (pos < src.size() && std::isalpha((unsigned char)src[pos])) ++pos;
        skip_ws(src, pos);
        if (pos < src.size() && src[pos] == '(') {
            ++pos; skip_ws(src, pos);
            return (pos < src.size() && src[pos] == '*') ||
                   match_w(src, pos, "WINAPI") || match_w(src, pos, "CALLBACK") ||
                   match_w(src, pos, "APIENTRY") || match_w(src, pos, "NTAPI");
        }
        return false;
    }

    std::string_view tr(std::string_view s) {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
        return s;
    }

    std::string map_ns(const std::string& filepath) {
        auto stem = std::filesystem::path(filepath).stem().string();
        // Normalize to lowercase for case-insensitive ns_map lookup
        std::string stem_lower;
        stem_lower.reserve(stem.size());
        for (char c : stem) stem_lower += (char)std::tolower((unsigned char)c);
        static const std::unordered_map<std::string, std::string> ns_map = {
            // Win32 headers
            {"winbase","Windows.Win32.System.SystemServices"},
            {"winnt","Windows.Win32.System.SystemServices"},
            {"winuser","Windows.Win32.UI.WindowsAndMessaging"},
            {"wingdi","Windows.Win32.Graphics.Gdi"},
            {"winreg","Windows.Win32.System.Registry"},
            {"winsvc","Windows.Win32.System.Services"},
            {"winsock","Windows.Win32.Networking.WinSock"},
            {"winsock2","Windows.Win32.Networking.WinSock"},
            {"ws2tcpip","Windows.Win32.Networking.WinSock"},
            {"mmsystem","Windows.Win32.Media.Multimedia"},
            {"shellapi","Windows.Win32.UI.Shell"},
            {"shlobj","Windows.Win32.UI.Shell"},
            {"commdlg","Windows.Win32.UI.Dialogs"},
            {"commctrl","Windows.Win32.UI.Controls"},
            {"aclapi","Windows.Win32.Security"},
            {"wincrypt","Windows.Win32.Security.Cryptography"},
            {"bcrypt","Windows.Win32.Security.Cryptography"},
            {"ncrypt","Windows.Win32.Security.Cryptography"},
            {"winhttp","Windows.Win32.Networking.Http"},
            {"wininet","Windows.Win32.Networking.Internet"},
            {"setupapi","Windows.Win32.System.Setup"},
            {"cfgmgr32","Windows.Win32.System.ConfigurationManager"},
            {"fileapi","Windows.Win32.Storage.FileSystem"},
            {"handleapi","Windows.Win32.Foundation"},
            {"processthreadsapi","Windows.Win32.System.Threading"},
            {"synchapi","Windows.Win32.System.Threading"},
            {"libloaderapi","Windows.Win32.LibraryLoader"},
            {"debugapi","Windows.Win32.Diagnostics.Debug"},
            {"dbghelp","Windows.Win32.Diagnostics.DebugHelp"},
            {"ioapiset","Windows.Win32.System.IO"},
            {"memoryapi","Windows.Win32.Memory"},
            {"heapapi","Windows.Win32.Memory"},
            {"ole2","Windows.Win32.Com"},
            {"oleauto","Windows.Win32.Com.StructuredStorage"},
            {"objbase","Windows.Win32.Com"},
            {"combaseapi","Windows.Win32.Com"},
            {"d3d9","Windows.Win32.Graphics.Direct3D9"},
            {"d3d11","Windows.Win32.Graphics.Direct3D11"},
            {"d3d12","Windows.Win32.Graphics.Direct3D12"},
            {"dxgi","Windows.Win32.Graphics.Dxgi"},
            {"dsound","Windows.Win32.Graphics.DirectSound"},
            {"mfapi","Windows.Win32.Media.MediaFoundation"},
            {"mfidl","Windows.Win32.Media.MediaFoundation"},
            {"mfreadwrite","Windows.Win32.Media.MediaFoundation"},
            {"winspool","Windows.Win32.Printing"},
            {"wlanapi","Windows.Win32.Networking.WiFi"},
            {"netapi32","Windows.Win32.NetworkManagement.NetManagement"},
            {"iphlpapi","Windows.Win32.Networking.WinSock"},
            {"userenv","Windows.Win32.Security.Environment"},
            {"wincred","Windows.Win32.Security.Credentials"},
            {"shlwapi","Windows.Win32.System.String"},
            {"wtsapi32","Windows.Win32.System.RemoteDesktop"},
            {"tlhelp32","Windows.Win32.ToolHelp"},
            {"pdh","Windows.Win32.System.Performance"},
            {"psapi","Windows.Win32.System.ProcessStatus"},
            {"msxml6","Windows.Win32.Data.Xml.Xml"},
            {"werapi","Windows.Win32.Diagnostics.Wer"},
            {"kernelbase","Windows.Win32.Foundation"},
            // AppModel / dynamic dependency: PACKAGE_VERSION + package
            // queries live in the SDK's appmodel.h (um/); MddBootstrap* ship
            // with the Windows App SDK (NuGet include) and in the SDK itself
            // from Windows 11 22H2 (build 22621) on, which also declares the
            // OS dynamic dependency API (TryCreatePackageDependency & co)
            // directly in appmodel.h. Both map to the official win32metadata
            // homes so the bootstrap code can import them as normal modules.
            {"appmodel","Windows.Win32.System.AppModel"},
            {"mddbootstrap","Windows.Win32.System.DynamicDependency"},
            // Canonical GUID home: guiddef.h defines _GUID and every other
            // header only guards it with #ifndef GUID_DEFINED. Without a pin,
            // the directory-fallback gave nspapi.h's guarded copy its own
            // Windows.Win32.NSPAPI namespace, and bare-name resolution bound
            // every unqualified `GUID` field to that duplicate instead of the
            // canonical struct - breaking every consumer module that imports
            // the real one.
            {"guiddef","Windows.Win32.GUIDDEF"},
            // WDK headers
            {"ntddk","Windows.Wdk.Ntddk"},
            {"wdm","Windows.Wdk.Wdm"},
            {"wdm.h","Windows.Wdk.Wdm"},
            {"fltKernel","Windows.Wdk.FltKernel"},
            {"ndis","Windows.Wdk.Ndis"},
            {"storport","Windows.Wdk.Storport"},
            {"wdf","Windows.Wdk.Wdf"},
            // KMDF framework headers (Include\wdf\kmdf\<ver>) — shipped
            // outside km/, so these stems were never exercised until the
            // WDF trees became scannable.
            {"wdfassert","Windows.Wdk.WdfAssert"},
            {"wdfbugcodes","Windows.Wdk.WdfBugCodes"},
            {"wdfcommonbuffer","Windows.Wdk.WdfCommonBuffer"},
            {"wdfcompaniontarget","Windows.Wdk.WdfCompanionTarget"},
            {"wdfcontrol","Windows.Wdk.WdfControl"},
            {"wdfcore","Windows.Wdk.WdfCore"},
            {"wdfdmaenabler","Windows.Wdk.WdfDmaEnabler"},
            {"wdfdmatransaction","Windows.Wdk.WdfDmaTransaction"},
            {"wdfdpc","Windows.Wdk.WdfDpc"},
            {"wdffdo","Windows.Wdk.WdfFdo"},
            {"wdffuncenum","Windows.Wdk.WdfFuncEnum"},
            {"wdfglobals","Windows.Wdk.WdfGlobals"},
            {"wdfhwaccess","Windows.Wdk.WdfHwAccess"},
            {"wdfinstaller","Windows.Wdk.WdfInstaller"},
            {"wdfiotarget","Windows.Wdk.WdfIoTarget"},
            {"wdfmemory","Windows.Wdk.WdfMemory"},
            {"wdfminiport","Windows.Wdk.WdfMiniport"},
            {"wdfpdo","Windows.Wdk.WdfPdo"},
            {"wdfpool","Windows.Wdk.WdfPool"},
            {"wdfqueryinterface","Windows.Wdk.WdfQueryInterface"},
            {"wdfresource","Windows.Wdk.WdfResource"},
            {"wdfroletypes","Windows.Wdk.WdfRoleTypes"},
            {"wdfstatus","Windows.Wdk.WdfStatus"},
            {"wdftraceenums","Windows.Wdk.WdfTraceEnums"},
            {"wdftypes","Windows.Wdk.WdfTypes"},
            {"wdfusb","Windows.Wdk.WdfUsb"},
            {"wdfverifier","Windows.Wdk.WdfVerifier"},
            {"wdfwmi","Windows.Wdk.WdfWmi"},
            // UMDF-only headers (no KMDF counterpart) — same Windows.Wdk.Wdf*
            // family as the rest of the framework.
            {"wdfcompanion","Windows.Wdk.WdfCompanion"},
            {"wdftriage","Windows.Wdk.WdfTriage"},
            {"wudfwdm","Windows.Wdk.WudfWdm"},
            {"wdfdmadefault","Windows.Wdk.WdfDmaDefault"},
            {"wdfminorfunctions","Windows.Wdk.WdfMinorFunctions"},
            {"umdf","Windows.Wdk.Umdf"},
            {"wdfdevice","Windows.Wdk.WdfDevice"},
            {"wdfdriver","Windows.Wdk.WdfDriver"},
            {"wdfio","Windows.Wdk.WdfIo"},
            {"wdfrequest","Windows.Wdk.WdfRequest"},
            {"wdfinterrupt","Windows.Wdk.WdfInterrupt"},
            {"wdfobject","Windows.Wdk.WdfObject"},
            {"wdfsync","Windows.Wdk.WdfSync"},
            {"wdfcx","Windows.Wdk.WdfCx"},
            {"wdfsm","Windows.Wdk.WdfSm"},
            {"wdfsfio","Windows.Wdk.WdfSfIo"},
            {"wdftimer","Windows.Wdk.WdfTimer"},
            {"wdfworkitem","Windows.Wdk.WdfWorkItem"},
            {"wdfcollection","Windows.Wdk.WdfCollection"},
            {"wdfstring","Windows.Wdk.WdfString"},
            {"wdfregistry","Windows.Wdk.WdfRegistry"},
            {"wdfchildlist","Windows.Wdk.WdfChildList"},
            {"wdffwdenumeration","Windows.Wdk.WdfFwdEnumeration"},
            {"wdfcmreslist","Windows.Wdk.WdfCmResList"},
            {"wdfhwprofile","Windows.Wdk.WdfHwProfile"},
            {"wdffileobject","Windows.Wdk.WdfFileObject"},
            {"wdfcustomsystemfactoryeventhandler","Windows.Wdk.WdfCustomSystemFactoryEventHandler"},
            {"KMDF","Windows.Wdk.Kmdf"},
            {"UMDF","Windows.Wdk.Umdf"},
        };
        auto it = ns_map.find(stem_lower);
        if (it != ns_map.end()) return it->second;
        // Generic -ns override wins over both the table and the fallback:
        // any header on earth can be pinned to any namespace by the caller.
        if (auto ov = st.ns_overrides.find(stem_lower); ov != st.ns_overrides.end())
            return ov->second;
        // NuGet/extra include dirs: header stem becomes the leaf segment
        // under the dir's registered namespace root (no table entry needed).
        if (!st.extra_include_ns.empty())
        {
            namespace efs = std::filesystem;
            efs::path p = efs::path(filepath).lexically_normal();
            std::string fp = p.generic_string();
            for (auto const& [dir, root] : st.extra_include_ns)
            {
                std::string d = efs::path(dir).lexically_normal().generic_string();
                if (fp.size() > d.size() && fp.compare(0, d.size(), d) == 0 &&
                    (fp[d.size()] == '/' ))
                {
                    // WASDK headers are named after the API they expose
                    // (Microsoft.UI.Dispatching.Interop.h, Microsoft.Windows
                    // .AppLifecycle.h). Stacking that stem verbatim under the
                    // Windows.Win32.AppSDK root produced duplicated heads
                    // (...AppSDK.MICROSOFT.UI.DISPATCHING.INTEROP,
                    // ...AppSDK.WINDOWS.APPLIFECYCLE). Strip any leading
                    // Microsoft/Windows segments that merely restate the
                    // header's own product prefix, then UPPERCASE each
                    // remaining segment so the same header yields the same
                    // namespace on every machine (Microsoft.UI.Dispatching
                    // .Interop -> Windows.Win32.AppSDK.UI.DISPATCHING.INTEROP).
                    std::vector<std::string> segs;
                    {
                        std::string cur;
                        for (char c : stem)
                        {
                            if (c == '.') { segs.push_back(std::move(cur)); cur.clear(); }
                            else cur += c;
                        }
                        segs.push_back(std::move(cur));
                    }
                    auto is_redundant_head = [](std::string s)
                    {
                        for (char& c : s) c = char(std::tolower((unsigned char)c));
                        // "microsoft"/"windows" restate either the AppSDK root
                        // (Windows.Win32.AppSDK) or the header's own product
                        // prefix; "appsdk" would restate the root's last segment.
                        return s == "microsoft" || s == "windows" || s == "appsdk";
                    };
                    // Drop leading segments that only restate the root; never
                    // drop the whole stem (an all-Microsoft stem falls back to
                    // its final segment so the namespace stays non-empty).
                    std::size_t drop = 0;
                    while (drop + 1 < segs.size() && is_redundant_head(segs[drop])) ++drop;
                    std::string leaf;
                    for (std::size_t i = drop; i < segs.size(); ++i)
                    {
                        std::string seg = segs[i];
                        // Normalize each segment to UPPERCASE and mangle any
                        // non-identifier char to '_'. Deterministic naming: the
                        // same header must yield the same namespace no matter
                        // what casing the NuGet package used on disk
                        // (Microsoft.UI.Dispatching.Interop.h vs decimal.h), and
                        // UPPERCASE matches the unmapped-header fallbacks below
                        // (Windows.Win32.ERRHANDLINGAPI, Windows.Wdk.NTDDK).
                        std::string fixed;
                        for (char c : seg)
                            fixed += (std::isalnum((unsigned char)c) || c == '_')
                                ? char(std::toupper((unsigned char)c)) : '_';
                        if (fixed.empty()) fixed = "_";
                        else if ((fixed[0] >= '0') && (fixed[0] <= '9')) fixed.insert(fixed.begin(), '_');
                        if (!leaf.empty()) leaf += ".";
                        leaf += fixed;
                    }
                    if (leaf.empty())
                    {
                        // Every segment was a redundant head (stem ==
                        // "Microsoft"/"Windows"/"AppSDK"): fall back to the
                        // uppercased stem so the namespace is never empty.
                        for (char c : stem) leaf += char(std::toupper((unsigned char)c));
                    }
                    return root + "." + leaf;
                }
            }
        }
        // Unmapped headers follow the DIRECTORY they came from: km/ and
        // the WDK's wdf/ framework trees are kernel-side (Windows.Wdk.*),
        // everything else (um/, shared/, winrt/, extra -include_dir) is
        // user-mode (Windows.Win32.*). The old rule keyed off
        // st.include_drivers, which misbucketed hundreds of unmapped um/
        // headers (appmodel.h -> Windows.Wdk.APPMODEL) as soon as driver
        // parsing was enabled.
        bool is_kernel_header = st.drivers_only
            || filepath.find("\\km\\") != std::string::npos
            || filepath.find("/km/") != std::string::npos
            || filepath.find("\\wdf\\") != std::string::npos
            || filepath.find("/wdf/") != std::string::npos;
        if (is_kernel_header) {
            std::string result = "Windows.Wdk.";
            for (char c : stem) {
                if (c == '_') result += '.';
                else result += char(std::toupper((unsigned char)c));
            }
            while (result.find("..") != std::string::npos)
                result.erase(result.find("..") + 1, 1);
            return result;
        }
        std::string result = "Windows.Win32.";
        for (char c : stem) {
            if (c == '_') result += '.';
            else result += char(std::toupper((unsigned char)c));
        }
        // Sanitize: remove consecutive dots (e.g. "Windows.Win32..DBDAO")
        while (result.find("..") != std::string::npos)
            result.erase(result.find("..") + 1, 1);
        return result;
    }
};

} // namespace wv::parse
