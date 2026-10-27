// main.cpp - Winverse Compiler CLI entry point
// Copyright (c) 2026 Momin Shaikh. All rights reserved.

#define ENABLE_WIN32_LONG_PATHS 1
#include <iostream>
#include <string>
#include <string_view>
#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <algorithm>
#include <execution>
#include <unordered_set>
#include <unordered_map>
#include <fstream>
#include <cstdlib>
#include <windows.h>

import winversec.types;
import winversec.attributes;
import winversec.sal;
import winversec.preprocessor;
import winversec.parser;
import winversec.resolver;
import winversec.enrich;
import winversec.emit;
import winversec.validate;
import winversec.driver;

struct SdkVersion {
    std::string dir_name;
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t build = 0;
    uint32_t revision = 0;
    bool operator<(const SdkVersion& o) const {
        if (major != o.major) return major < o.major;
        if (minor != o.minor) return minor < o.minor;
        if (build != o.build) return build < o.build;
        return revision < o.revision;
    }
};

static SdkVersion parse_version_dir(const std::string& dir_name) {
    SdkVersion v;
    v.dir_name = dir_name;
    // Parse "10.0.26100.0" format
    std::vector<uint32_t> parts;
    std::string current;
    for (char c : dir_name) {
        if (c == '.') {
            if (!current.empty()) {
                try { parts.push_back(std::stoul(current)); } catch (...) {}
                current.clear();
            }
        } else if (std::isdigit((unsigned char)c)) {
            current += c;
        }
    }
    if (!current.empty()) {
        try { parts.push_back(std::stoul(current)); } catch (...) {}
    }
    if (parts.size() >= 1) v.major = parts[0];
    if (parts.size() >= 2) v.minor = parts[1];
    if (parts.size() >= 3) v.build = parts[2];
    if (parts.size() >= 4) v.revision = parts[3];
    return v;
}

static std::string auto_detect_sdk_root() {
    namespace fs = std::filesystem;
    std::vector<char> drives;
    for (char d = 'A'; d <= 'Z'; ++d) {
        std::string prefix = std::string(1, d) + ":\\";
        DWORD attrs = GetFileAttributesA(prefix.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
            drives.push_back(d);
    }
    for (char d : drives) {
        std::string base = std::string(1, d) + ":\\";
        for (auto& sub : {"Program Files (x86)", "Program Files"}) {
            std::string kits = base + sub + "\\Windows Kits";
            if (!fs::exists(kits) || !fs::is_directory(kits)) continue;
            for (auto& entry : fs::directory_iterator(kits)) {
                if (!entry.is_directory()) continue;
                auto name = entry.path().filename().string();
                bool all_digits = true;
                for (char c : name) if (!std::isdigit((unsigned char)c)) { all_digits = false; break; }
                if (!all_digits || name.empty()) continue;
                auto include_dir = entry.path() / "Include";
                if (fs::exists(include_dir) && fs::is_directory(include_dir)) {
                    for (auto& ie : fs::directory_iterator(include_dir)) {
                        if (ie.is_directory()) return entry.path().string();
                    }
                }
            }
        }
    }
    return {};
}

static std::string auto_detect_sdk_version(const std::string& sdk_root) {
    namespace fs = std::filesystem;
    fs::path include_dir = fs::path(sdk_root) / "Include";
    if (!fs::exists(include_dir) || !fs::is_directory(include_dir)) return {};
    std::vector<SdkVersion> versions;
    for (auto& entry : fs::directory_iterator(include_dir)) {
        if (!entry.is_directory()) continue;
        auto name = entry.path().filename().string();
        auto v = parse_version_dir(name);
        if (v.major > 0) versions.push_back(v);
    }
    if (versions.empty()) return {};
    std::sort(versions.begin(), versions.end());
    
    // Enforce minimum version 10.0.26100.0
    SdkVersion min_ver;
    min_ver.major = 10; min_ver.minor = 0; min_ver.build = 26100; min_ver.revision = 0;
    auto latest = versions.back();
    if (latest < min_ver) {
        std::cerr << "WARNING: Latest SDK version " << latest.dir_name
                  << " is below minimum 10.0.26100.0\n";
    }
    return versions.back().dir_name;
}

static void usage() {
    std::cout << "Winverse Compiler v1.0.0.0 - Win32 & WDK API metadata compiler\n"
              << "Usage: winversec.exe [options]\n\n"
              << "Options:\n"
              << "  -sdk <path>         Windows SDK root. Default: auto-detect.\n"
              << "  -version <ver>      SDK version directory (e.g. 10.0.26100.0).\n"
              << "                      Default: latest installed.\n"
              << "  -output <path>      Output directory, file, or base name.\n"
              << "                      Default: Windows.Win32+Wdk.winmd\n"
              << "  -include_drivers    Include WDK kernel-mode APIs. Default: on.\n"
              << "  -no_drivers         Exclude WDK APIs (Win32 only).\n"
              << "  -drivers_only       Emit Windows.Wdk.winmd only (no Win32).\n"
              << "  -include_dir <dir>  Add a header directory the SDK lacks (e.g. a\n"
              << "                      Windows App SDK NuGet include folder). Repeatable;\n"
              << "                      SDK-provided headers win on name clash.\n"
              << "  -include_wasdk [exp]\n"
              << "                      Ingest Windows App SDK (WASDK) Flat-C APIs\n"
              << "                      from the NuGet cache (highest version wins).\n"
              << "                      'exp': experimental packages only\n"
              << "                      (-experimental*) for experimental Flat-C APIs.\n"
              << "                      SDK-provided headers win on name clash.\n"
              << "  -ns <h=Namespace>   Pin a header stem to a namespace. Repeatable.\n"
              << "  -coverage <file>    Write an HTML coverage report.\n"
              << "  -verbose            Verbose output.\n"
              << "  -help               Show this help.\n";
}

// Read an import library (.lib) and record exported symbol -> dll name.
// Short import entries store null-terminated strings in file order
// (symbols before the dll name), so symbols accumulate until a
// "<name>.dll" string appears, then bind to it; __IMPORT_DESCRIPTOR_<X>
// supplies the fallback. Handles multi-dll umbrella libs.
// When fixed_value is non-empty it is recorded instead of the descriptor's
// dll name — the SDK scan passes the LIB FILE name ("kernel32.lib") because
// that is what the downstream linker consumes; descriptor DLLs are often
// api-set shims (api-ms-win-*.dll) whose .lib does not exist on disk.
static void scan_import_lib(const std::filesystem::path& lib,
                            std::unordered_map<std::string, std::string>& out,
                            std::string const& fixed_value = {})
{
    std::error_code ec;
    auto sz = std::filesystem::file_size(lib, ec);
    // Skip implibs/empty/corrupt/absurd files (import libs are KBs-MBs).
    if (ec || sz < 8 || sz > (64ull << 20)) return;
    std::vector<char> buf((size_t)sz);
    {
        std::ifstream f(lib, std::ios::binary);
        if (!f.read(buf.data(), (std::streamsize)sz)) return;
    }
    std::vector<std::string> pend;
    std::string cur_dll;
    std::string fallback_dll;
    // Import evidence: at least one "<name>.dll" string or
    // __IMPORT_DESCRIPTOR_<mod> member must have been seen in this file
    // before any symbol is attributed to it. Static archives (libucrt.lib,
    // libcmt.lib, muiload.lib, wiautil.lib, htmlhelp.lib) contain none of
    // either yet are full of identifier strings they merely *reference*
    // (CRT names, strsafe inlines compiled into a helper object, ...);
    // without this gate the final flush below bound every such identifier
    // to the lib FILE name and static libs out-competed the real import
    // libs (libucrt.lib stole CRT rows from ucrt.lib, muiload.lib/wiautil.lib
    // became "providers" of StringCch*). First-wins then made it stick.
    bool saw_import = false;
    auto flush = [&](std::string const& dll) {
        std::string const& value = !fixed_value.empty() ? fixed_value : dll;
        if (value.empty()) return;
        for (auto& s : pend)
            if (!out.contains(s)) out.emplace(s, value);
        pend.clear();
    };
    auto is_ident = [](std::string const& s) {
        if (s.empty() || s.size() > 512) return false;
        if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '_'))
            return false;
        for (char c : s)
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                return false;
        return true;
    };
    // A DLL module basename, as it appears before the ".dll" suffix. Unlike
    // is_ident this MUST accept '.' and '-': real DLL names are frequently
    // multi-segment ("Microsoft.WindowsAppRuntime.Bootstrap.dll", the WASDK
    // bootstrap) or api-set shims ("api-ms-win-core-com-l1-1-0.dll"). Using
    // is_ident here meant neither cur_dll nor fallback_dll was ever set for
    // them, so the final flush("") attributed ZERO symbols: the winmd lost
    // the ImportLibrary attribution and the downstream projection emitted an
    // empty inline stub instead of a real extern — MddBootstrapInitialize2
    // compiled to `return {};`, the bootstrap never ran, and every
    // unpackaged WinUI app died with REGDB_E_CLASSNOTREG (0x80040154).
    auto is_dll_basename = [](std::string const& s) {
        if (s.empty() || s.size() > 240) return false;
        if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') ||
              (s[0] >= '0' && s[0] <= '9')))
            return false;
        for (char c : s)
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
                return false;
        return true;
    };
    size_t i = 0;
    while (i < buf.size())
    {
        while (i < buf.size() && (unsigned char)buf[i] < 32) ++i;
        size_t start = i;
        while (i < buf.size() && (unsigned char)buf[i] >= 32 && (unsigned char)buf[i] < 127) ++i;
        // Bytes >= 0x7F are neither gap nor printable: must advance or the
        // outer loop spins on the same index forever.
        if (i == start) { ++i; continue; }
        std::string s(buf.begin() + start, buf.begin() + i);
        if (s.size() > 4 && s.size() < 300)
        {
            std::string low = s;
            for (auto& ch : low) ch = (char)std::tolower((unsigned char)ch);
            if (low.rfind(".dll", low.size() - 4) == low.size() - 4 && is_dll_basename(low.substr(0, low.size() - 4)))
            {
                saw_import = true;
                if (cur_dll != s) { flush(s); cur_dll = s; }
                continue;
            }
            static const std::string desc = "__IMPORT_DESCRIPTOR_";
            if (s.rfind(desc, 0) == 0)
            {
                // Evidence even when the module name is an api-set
                // ("api-ms-win-crt-stdio-l1-1-0" carries hyphens and
                // fails is_ident below, but the descriptor proves an
                // import object: ucrt.lib is exactly this shape).
                saw_import = true;
                std::string mod = s.substr(desc.size());
                if (is_dll_basename(mod) && fallback_dll.empty()) fallback_dll = mod + ".dll";
                continue;
            }
        }
        if (is_ident(s)) pend.push_back(std::move(s));
    }
    if (saw_import)
        flush(cur_dll.empty() ? fallback_dll : cur_dll);
}

int main(int argc, char* argv[]) {
    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ep) -> LONG {
        fprintf(stderr, "FATAL: Unhandled exception 0x%08lX at %p\n",
                ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
        return EXCEPTION_EXECUTE_HANDLER;
    });
    std::string sdk;
    std::string version_dir;
    std::string output;
    bool drivers = true;
    bool drivers_only = false;
    bool verbose = false;
    std::string coverage;
    std::vector<std::string> extra_dirs;
    std::vector<std::string> ns_overrides;
    // -include_wasdk / -include_wasdk exp: single mode variable, no second flag.
    // "" = off, "std" = -include_wasdk, "exp" = -include_wasdk exp.
    std::string include_wasdk;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-sdk" && i+1 < argc) { sdk = argv[++i]; }
        else if (a == "-version" && i+1 < argc) { version_dir = argv[++i]; }
        else if (a == "-output" && i+1 < argc) { output = argv[++i]; }
        else if (a == "-include_dir" && i+1 < argc) { extra_dirs.push_back(argv[++i]); }
        else if (a == "-ns" && i+1 < argc) { ns_overrides.push_back(argv[++i]); }
        else if (a == "-include_wasdk") {
            // `-include_wasdk` (newest installed) or `-include_wasdk exp`
            // (experimental channel only). Only that exact token is consumed,
            // so a following switch like `-verbose` is never swallowed.
            include_wasdk = "std";
            if (i + 1 < argc) {
                std::string nxt = argv[i + 1];
                for (auto& ch : nxt) ch = (char)std::tolower((unsigned char)ch);
                if (nxt == "exp") {
                    include_wasdk = "exp";
                    ++i;
                }
            }
        }
        else if (a == "-include_drivers") drivers = true;
        else if (a == "-no_drivers") drivers = false;
        else if (a == "-drivers_only") { drivers_only = true; drivers = true; }
        else if (a == "-coverage" && i+1 < argc) coverage = argv[++i];
        else if (a == "-verbose") verbose = true;
        else if (a == "-help") { usage(); return 0; }
        else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 1; }
    }

    // Resolve relative switch paths ("..\\out", "foo.winmd") against the
    // current directory so generation works from any launch directory.
    auto norm_path = [](std::string const& value) -> std::string {
        if (value.size() < 2) return value;
        if (value[1] == ':') return value;                      // drive-absolute
        if (value[0] == '/' || value[0] == '\\') return value;  // rooted
        std::error_code ec;
        auto abs = std::filesystem::absolute(value, ec);
        if (ec) return value;
        auto canon = std::filesystem::weakly_canonical(abs, ec);
        if (ec) return abs.string();
        return canon.string();
    };
    if (!sdk.empty()) sdk = norm_path(sdk);
    if (!output.empty()) output = norm_path(output);
    if (!coverage.empty()) coverage = norm_path(coverage);
    for (auto& d : extra_dirs) d = norm_path(d);

    // Invoked with no arguments: print help and exit (do not auto-run a full
    // SDK generation pass — an explicit option is required to compile).
    if (argc <= 1) {
        usage();
        return 0;
    }

        if (sdk.empty()) {
            sdk = auto_detect_sdk_root();
            if (sdk.empty()) {
                std::cerr << "ERROR: Could not find Windows SDK on any drive.\n"
                          << "Use -sdk <path> to specify manually.\n";
                return 1;
            }
            if (verbose) std::cout << "Auto-detected SDK: " << sdk << "\n";
        }

        if (version_dir.empty()) {
            version_dir = auto_detect_sdk_version(sdk);
            if (version_dir.empty()) {
                std::cerr << "ERROR: Could not find any SDK version under " << sdk << "\n";
                std::cerr << "Use -version <dir> to specify manually (e.g. -version 10.0.26100.0).\n";
                return 1;
            }
            if (verbose) std::cout << "Auto-detected version: " << version_dir << "\n";
        }

    auto hw = std::thread::hardware_concurrency();
    if (verbose) {
        std::cout << "Winverse Compiler v1.0.0.0\n"
                  << "SDK:  " << sdk << "\n"
                  << "Ver:  " << version_dir << "\n"
                  << "Drv:  " << (drivers_only ? "only" : drivers ? "yes" : "no") << "\n"
                  << "Core: " << hw << "\n\n";
    }

    wv::State state;
    state.include_drivers = drivers;
    state.drivers_only = drivers_only;
    state.verbose = verbose;
    // -include_wasdk: auto-locate Windows App SDK NuGet include dirs under the
    // machine's NuGet cache (NUGET_PACKAGES, then the default ~/.nuget),
    // matching any microsoft.windowsappsdk* package id, highest version
    // first. The include dir of each package is queued as an extra include
    // dir; parse_sdk's SDK-stem-first dedup guarantees that an SDK which
    // already provides the same header (builtin dynamic dependency on
    // Windows 11 22H2 / 22621+) wins and the NuGet copy is skipped, so
    // MddBootstrap.h etc. are never declared twice.
    if (!include_wasdk.empty())
    {
        namespace fs = std::filesystem;
        std::vector<fs::path> roots;
        if (const char* np = std::getenv("NUGET_PACKAGES"); np && *np) roots.emplace_back(np);
        else if (const char* hp = std::getenv("USERPROFILE"); hp && *hp) roots.emplace_back(fs::path(hp) / ".nuget" / "packages");
        else if (const char* hh = std::getenv("HOME"); hh && *hh) roots.emplace_back(fs::path(hh) / ".nuget" / "packages");
        // Enumerate candidate packages first (cheap ordered directory walk),
        // then evaluate every package on ALL CORES. Each slot records that
        // package's include-dir pick; the merge replays picks in enumeration
        // order, so include-dir order - and with it the first-wins header
        // dedup - is identical to a serial scan (byte-reproducible winmd).
        std::vector<fs::path> pkg_dirs;
        for (auto const& root : roots)
        {
            std::error_code ec;
            if (!fs::is_directory(root, ec)) continue;
            for (auto const& pkg : fs::directory_iterator(root, ec))
            {
                auto id = pkg.path().filename().string();
                for (auto& c : id) c = (char)std::tolower((unsigned char)c);
                if (id.rfind("microsoft.windowsappsdk", 0) == 0)
                    pkg_dirs.push_back(pkg.path());
            }
        }
        // Numeric-aware version order: plain lexicographic ranks "2.3.5"
        // above "2.3.12", which would pick an OLD package once a component
        // crosses a two-digit minor/patch. Hoisted so the parallel pass
        // shares one definition.
        auto ver_rank = [](const std::string& v) {
            std::vector<int> nums;
            std::string tail;
            size_t i = 0;
            while (i < v.size())
            {
                if (v[i] >= '0' && v[i] <= '9')
                {
                    int n = 0;
                    while (i < v.size() && v[i] >= '0' && v[i] <= '9')
                    {
                        n = n * 10 + (v[i] - '0');
                        ++i;
                    }
                    nums.push_back(n);
                }
                else { tail += v[i]; ++i; }  // separators + prerelease suffix
            }
            return std::make_pair(std::move(nums), std::move(tail));
        };
        std::vector<fs::path> picks(pkg_dirs.size());   // empty = no include dir
        std::vector<size_t> work(pkg_dirs.size());
        for (size_t i = 0; i < work.size(); ++i) work[i] = i;
        auto t_wasdk = std::chrono::steady_clock::now();
        std::for_each(std::execution::par, work.begin(), work.end(), [&](size_t pi) {
            std::error_code vec;
            std::vector<fs::path> vers;
            for (auto const& v : fs::directory_iterator(pkg_dirs[pi], vec))
                if (v.is_directory()) vers.push_back(v.path());
            // `-include_wasdk exp`: experimental channel only. Keep version
            // dirs tagged "-experimental" (2.5.4-experimental,
            // 2.0.250912002-experimental, ...) and skip stable releases, so
            // the newest installed EXPERIMENTAL package - the one carrying
            // experimental Flat-C APIs - is what gets ingested.
            if (include_wasdk == "exp")
            {
                std::vector<fs::path> exp_vers;
                for (auto const& v : vers)
                {
                    auto nm = v.filename().string();
                    for (auto& c : nm) c = (char)std::tolower((unsigned char)c);
                    if (nm.find("-experimental") != std::string::npos)
                        exp_vers.push_back(v);
                }
                vers = std::move(exp_vers);
            }
            std::sort(vers.begin(), vers.end(), [&](auto const& a, auto const& b) {
                return ver_rank(a.filename().string()) > ver_rank(b.filename().string());
            });
            for (auto const& v : vers)
            {
                fs::path inc = v / "include";
                if (fs::is_directory(inc))
                {
                    picks[pi] = inc;
                    break;  // highest version with an include dir wins
                }
            }
        });
        bool found_any = false;
        for (size_t pi = 0; pi < pkg_dirs.size(); ++pi)
        {
            if (picks[pi].empty()) continue;
            fs::path const& inc = picks[pi];
            state.extra_include_dirs.push_back(inc);
            // WASDK package Flat-C headers -> Windows.Win32.AppSDK
            // (nested under Windows.Win32 so the Flat-C AppSDK APIs
            // sit alongside the rest of the Win32 projection rather
            // than under a Microsoft.* root of their own)
            state.extra_include_ns[inc.lexically_normal().generic_string()] =
                "Windows.Win32.AppSDK";
            found_any = true;
            if (verbose) std::cout << "WASDK include" << (include_wasdk == "exp" ? " (exp)" : "")
                                  << ": " << inc.string() << "\n";
        }
        if (verbose)
            std::cout << "WASDK search: "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t_wasdk).count()
                      << " ms (all-core, " << pkg_dirs.size() << " packages)\n";
        if (!found_any)
            std::cerr << "WARNING: "
                      << (include_wasdk == "exp"
                              ? "-include_wasdk exp: no experimental Windows App SDK NuGet "
                                "package found (looked in the NuGet cache; restore a "
                                "WASDK-based project first).\n"
                              : "-include_wasdk: no Windows App SDK NuGet include dir found "
                                "(looked in the NuGet cache; restore a WASDK-based project "
                                "first).\n");
    }
    for (auto const& d : extra_dirs) state.extra_include_dirs.emplace_back(d);
    // Automatic Flat-C dll discovery: scan each extra include dir's sibling
    // NuGet lib dir (<pkg>/lib/native/<arch>) and record symbol -> dll from
    // the import libraries; arch precedence x64 > x86 > arm64 > arm64ec.
    {
        namespace fs2 = std::filesystem;
        static const char* arches[] = { "x64", "x86", "arm64", "arm64ec" };
        auto t_libs = std::chrono::steady_clock::now();
        size_t nlibs = 0;
        for (auto const& incd : state.extra_include_dirs)
        {
            std::error_code ec;
            fs2::path pkg = incd.parent_path();   // <pkg>/include -> <pkg>
            for (auto const* arch : arches)
            {
                fs2::path libdir = pkg / "lib" / "native" / arch;
                if (!fs2::is_directory(libdir, ec)) continue;
                // Collect this directory's .lib files (iteration order kept),
                // scan them on ALL CORES into per-file maps, then merge in the
                // collected order - identical first-wins results to a serial
                // scan, so the winmd stays byte-reproducible.
                std::vector<fs2::path> libs;
                for (auto const& e : fs2::directory_iterator(libdir, ec))
                {
                    if (!e.is_regular_file(ec)) continue;
                    auto ext = e.path().extension().string();
                    for (auto& c : ext) c = (char)std::tolower((unsigned char)c);
                    if (ext != ".lib") continue;
                    libs.push_back(e.path());
                }
                std::vector<std::unordered_map<std::string, std::string>> per_file(libs.size());
                std::vector<size_t> work(libs.size());
                for (size_t i = 0; i < work.size(); ++i) work[i] = i;
                std::for_each(std::execution::par, work.begin(), work.end(),
                    [&](size_t i) { scan_import_lib(libs[i], per_file[i]); });
                for (size_t i = 0; i < libs.size(); ++i)
                {
                    for (auto& [sym, dll] : per_file[i])
                        if (!state.dll_imports.contains(sym))
                            state.dll_imports.emplace(sym, dll);
                    if (verbose) std::cout << "scanned import lib: " << libs[i].string()
                                           << " (" << state.dll_imports.size() << " symbols so far)\n";
                }
                nlibs += libs.size();
                break;  // first (highest-precedence) arch present wins
            }
        }
        if (verbose)
            std::cout << "import-lib discovery: "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t_libs).count()
                      << " ms (all-core, " << nlibs << " libs, "
                      << state.dll_imports.size() << " symbols)\n";
    }
    // Automatic Windows SDK import-lib discovery: scan the SDK's own import
    // libraries (um + ucrt for user mode, km for kernel mode) and record
    // symbol -> "<lib file>.lib". The curated dll_map_ table necessarily
    // lags every new Windows release; this scan is the data-driven fallback
    // that makes FUTURE SDK/WDK APIs resolve to a linkable library with no
    // winversec table edit or rebuild — the DLL-mapping counterpart of the
    // directory-fallback namespace rule (new surface just works). Sorted
    // scan order keeps first-wins resolution deterministic across machines.
    {
        namespace fs3 = std::filesystem;
        auto scan_dir = [&](fs3::path const& dir, auto& map, char const* tag)
        {
            std::error_code ec;
            if (!fs3::is_directory(dir, ec)) return;
            std::vector<fs3::path> libs;
            for (auto const& e : fs3::directory_iterator(dir, ec))
            {
                if (!e.is_regular_file(ec)) continue;
                // Case-insensitive: the SDK ships both spellings
                // (rpcrt4.lib AND RpcRT4.Lib) and a case-sensitive
                // comparison silently skipped the CamelCase ones — taking
                // their symbols' attribution away entirely.
                std::string ext = e.path().extension().string();
                for (auto& c : ext) c = (char)std::tolower((unsigned char)c);
                if (ext == ".lib") libs.push_back(e.path());
            }
            std::sort(libs.begin(), libs.end());
            for (auto const& p : libs)
                scan_import_lib(p, map, p.filename().string());
            if (verbose)
                std::cout << "scanned SDK " << tag << " libs: " << libs.size()
                          << " files, " << map.size() << " symbols\n";
        };
        fs3::path lib_root = fs3::path(sdk) / "Lib" / version_dir;
        if (!drivers_only)
        {
            scan_dir(lib_root / "um" / "x64", state.sdk_lib_imports, "um");
            scan_dir(lib_root / "ucrt" / "x64", state.sdk_lib_imports, "ucrt");
        }
        if (drivers)
            scan_dir(lib_root / "km" / "x64", state.km_lib_imports, "km");
    }
    // -ns <header=Namespace>: pin any header's items to any namespace.
    // Header stem is lowercased for matching; namespace is taken verbatim
    // (dots allowed). Later flags win on duplicate stems.
    for (auto const& ov : ns_overrides)
    {
        auto eq = ov.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == ov.size())
        {
            std::cerr << "WARNING: -ns expects <header=Namespace>, got: " << ov << "\n";
            continue;
        }
        std::string stem = ov.substr(0, eq);
        for (auto& c : stem) c = (char)std::tolower((unsigned char)c);
        state.ns_overrides[stem] = ov.substr(eq + 1);
    }

    // Resolve output path
    namespace fs = std::filesystem;
    if (output.empty()) {
        output = drivers_only ? "Windows.Wdk.winmd" : drivers ? "Windows.Win32+Wdk.winmd" : "Windows.Win32.winmd";
    } else {
        if (output.size() >= 6 && output.substr(output.size() - 6) == ".winmd") {
            // exact file path provided
        } else if (fs::is_directory(fs::path(output))) {
            auto fname = drivers_only ? "Windows.Wdk.winmd" : drivers ? "Windows.Win32+Wdk.winmd" : "Windows.Win32.winmd";
            output = (fs::path(output) / fname).string();
        } else {
            output += ".winmd";
        }
    }
    if (drivers_only) state.asm_name = "Windows.Wdk";
    else if (drivers) state.asm_name = "Windows.Win32+Wdk";
    else state.asm_name = "Windows.Win32";
    std::cout << "Out:  " << output << "\n\n";
    auto total_start = std::chrono::steady_clock::now();

    std::cout << "[1/5] Parsing headers...\n" << std::flush;
    wv::Preprocessor pp(state);
    wv::parse::Parser parser(state, pp);

    std::atomic<bool> parsing_done{false};
    std::thread progress_thread([&]() {
        size_t last = 0;
        while (!parsing_done.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto f = state.files_parsed_atomic.load();
            auto t = state.types_found_atomic.load();
            auto fn = state.funcs_found_atomic.load();
            if (f > last) {
                last = f;
                if (verbose) std::cerr << "\r    " << f << " files, " << t << " types, " << fn << " funcs   " << std::flush;
            }
        }
    });

    bool parsed = parser.parse_sdk(std::filesystem::path(sdk), version_dir);
    parsing_done.store(true);
    progress_thread.join();
    auto t1 = std::chrono::steady_clock::now();
    if (verbose) std::cerr << "\n    Parsed " << state.items.size() << " types in "
              << std::chrono::duration_cast<std::chrono::seconds>(t1 - total_start).count() << "s\n";

    // Deduplicate types by namespace+name. Headers are parsed standalone
    // and in parallel, so the same typedef/struct name is discovered many
    // times — and a broken duplicate (targetless alias, opaque fwd-decl) can
    // finish before the real definition and poison it under keep-first
    // semantics. Definition beats declaration regardless of parse order:
    //   - an alias carrying a real target (named ref / fnptr) beats a
    //     targetless one;
    //   - a struct/union with fields/methods beats an empty one;
    //   - otherwise first wins.
    {
        auto alias_has_target = [](wv::TDef const& d) {
            return !d.alias_ref.name.empty() || d.alias_ref.fnptr;
        };
        // A PRIMITIVE-alias duplicate (elem set, no named ref: 'typedef
        // unsigned __int64 ULONG64' -> u8) must beat a named-alias duplicate
        // ('typedef ULONG64 X' leaves a Class with alias_ref=Class ULONG64
        // whose own item may have lost to a targetless dup) — otherwise
        // consumers of the primitive shape encode garbage classes (the
        // WinSock/USBIOCTL ULONG64). Rank primitive-alias highest for
        // Class-kind items with no members.
        auto is_primitive_alias = [](wv::TDef const& d) {
            return d.kind == wv::Kind::Class && d.alias_elem != wv::ET::Void
                && d.alias_elem != wv::ET::Class && d.alias_ref.name.empty()
                && d.fields.empty() && d.meths.empty();
        };
        auto item_score = [&](wv::Item const& it) {
            int s = 0;
            if (is_primitive_alias(it.def)) s += 4;
            if (it.def.kind == wv::Kind::Class && alias_has_target(it.def)) s += 2;
            if (!it.def.fields.empty() || !it.def.meths.empty()) s += 1;
            // A COM interface (Kind::Iface) carries its vtable methods and
            // IID; the C forward declaration `typedef interface IFoo IFoo;`
            // is a memberless Kind::Class alias whose +2 alias-target bonus
            // would otherwise beat the real interface, dropping every
            // ComMethod/vtable row for that interface.
            if (it.def.kind == wv::Kind::Iface) s += 3;
            return s;
        };
        // KMDF vs UMDF flavor tie-break: both WDF trees declare the same
        // Wdf* names into the same namespace, so equal-score duplicates
        // would otherwise let the parallel arrival order decide which
        // flavor survives (run-to-run nondeterminism). The kernel flavor
        // (Include\wdf\kmdf\) wins every tie.
        auto is_kmdf_flavor = [](wv::Item const& it) {
            auto const& h = it.def.source_header;
            return h.find("\\wdf\\kmdf\\") != std::string::npos ||
                   h.find("/wdf/kmdf/") != std::string::npos;
        };
        std::unordered_map<std::string, size_t> seen_idx;
        seen_idx.reserve(state.items.size());
        std::vector<wv::Item> unique;
        unique.reserve(state.items.size());
        for (auto& item : state.items) {
            auto key = item.def.ns + "." + item.def.name;
            auto [it, inserted] = seen_idx.emplace(key, unique.size());
            if (inserted) {
                unique.push_back(std::move(item));
            }
            else {
                // A COM coclass duplicate carries an irreplaceable CLSID
                // (class DECLSPEC_UUID("...")). Whichever duplicate wins
                // the dedup, graft the UUID onto the survivor — dropping
                // it left 1850 of 1858 coclasses without ComCoClass (a
                // targetless empty Class alias of the same name typically
                // finishes first and wins the tie).
                auto& w = unique[it->second].def;
                auto& d = item.def;
                if (d.kind == wv::Kind::Class && !d.com_iid.empty()
                    && w.kind == wv::Kind::Class && w.com_iid.empty()) {
                    w.com_iid = d.com_iid;
                    w.is_com_interface = true;
                }
                else if (w.kind == wv::Kind::Class && !w.com_iid.empty()
                         && d.kind == wv::Kind::Class && d.com_iid.empty()) {
                    d.com_iid = w.com_iid;
                    d.is_com_interface = true;
                }
                if (item_score(item) > item_score(unique[it->second]) ||
                    (item_score(item) == item_score(unique[it->second]) &&
                     is_kmdf_flavor(item) && !is_kmdf_flavor(unique[it->second]))) {
                    unique[it->second] = std::move(item); // definition beats declaration; kernel flavor beats user-mode
                }
            }
        }
        state.items = std::move(unique);
        if (verbose) std::cerr << "  Deduped: " << state.items.size() << " unique types\n";
    }

    // Field-less struct/union after dedup = opaque handle. In C an empty
    // struct cannot exist and every `typedef struct TAG {} *TAG;` /
    // pointer-to-incomplete shape is an opaque handle
    // (RO_REGISTRATION_COOKIE, CO_MTA_USAGE_COOKIE, PACKAGEDEPENDENCY_CONTEXT).
    // Leaving them Kind::Struct makes downstream projections skip the empty
    // body while signatures still reference the type -> C2039/C2230
    // cascades. Promote to Class so consumers emit `using X = void*;` and
    // the metadata stays language-agnostic (any projection handles an
    // opaque handle; nobody can handle a valueless struct).
    {
        size_t promoted = 0;
        for (auto& item : state.items) {
            if ((item.def.kind == wv::Kind::Struct || item.def.kind == wv::Kind::Union)
                && item.def.fields.empty() && item.def.meths.empty()) {
                item.def.kind = wv::Kind::Class;
                item.def.is_union = false;
                ++promoted;
            }
        }
        if (verbose) std::cerr << "  Promoted " << promoted << " field-less structs/unions to opaque classes\n";
    }

    // Filter out items with empty names — metadata artifacts
    {
        size_t before = state.items.size();
        state.items.erase(
            std::remove_if(state.items.begin(), state.items.end(),
                [](const wv::Item& it) {
                    if (it.def.name.empty()) return true;
                    if (it.def.ns.empty()) return true;
                    // Skip metadata artifact types (empty name after last dot in ns)
                    auto& n = it.def.name;
                    if (n.size() == 1 && n[0] == '.') return true;
                    return false;
                }),
            state.items.end());
        size_t filtered = before - state.items.size();
        if (filtered > 0 && verbose) std::cerr << "  Filtered: " << filtered << " empty-name types\n";
    }

    std::cout << "[2/5] Resolving types...\n";
    {
        wv::Resolver resolver(state);
        resolver.resolve_all_parallel(hw);
        resolver.compute_sizes_parallel(hw);
    }
    auto t2 = std::chrono::steady_clock::now();
    if (verbose) std::cout << "  Resolved " << state.items.size() << " types ("
              << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << "ms)\n";

    std::cout << "[3/5] Enriching metadata...\n";
    {
        wv::Enricher enricher(state);
        enricher.set_sdk_version(version_dir);
        enricher.run_parallel(hw);
        if (drivers) {
            if (verbose) std::cout << "  Including driver APIs...\n";
            wv::DriverEnricher denricher(state);
            denricher.run();
        }
    }
    auto t3 = std::chrono::steady_clock::now();
    if (verbose) std::cout << "  Enriched (" << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count() << "ms)\n";

    std::cout << "[4/5] Emitting .winmd...\n";
    {
        wv::WinmdEmitter emitter(state, verbose);
        bool ok = emitter.emit(output);
        if (!ok) { std::cerr << "Emit failed!\n"; return 1; }
    }
    auto t4 = std::chrono::steady_clock::now();
    if (verbose) std::cout << "  Written: " << output << " ("
              << std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count() << "ms)\n";

    std::cout << "[5/5] Validating coverage...\n";
    {
        wv::Validator validator(state);
        auto report = validator.run(std::filesystem::path(sdk), version_dir);
        validator.print(report);
        if (!coverage.empty()) {
            if (validator.write_html(report, coverage))
                std::cout << "Coverage report: " << coverage << "\n";
            else
                std::cerr << "Failed to write coverage report\n";
        }
    }

    auto total_end = std::chrono::steady_clock::now();
    std::cout << "\nTotal time: "
              << std::chrono::duration_cast<std::chrono::seconds>(total_end - total_start).count()
              << "s\n";

    return 0;
}
