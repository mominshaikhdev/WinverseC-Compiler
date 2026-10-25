// preprocessor.ixx - C/C++ preprocessor: #include, #ifdef, #define evaluation
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>

export module winversec.preprocessor;
import winversec.types;

export namespace wv {

// Preprocessor-defined constant
struct Define {
    std::string name;
    std::string value;          // Raw text
    bool is_function_macro = false;
    std::vector<std::string> params;  // For function-like macros
};

class Preprocessor {
public:
    State& st;

    explicit Preprocessor(State& s) : st(s) {}

    // Resolve #include path against SDK include directories
    std::string resolve_include(std::string_view path, const std::string& current_file) {
        // Strip quotes/angle brackets
        std::string clean(path);
        if (!clean.empty() && (clean.front() == '"' || clean.front() == '<'))
            clean = clean.substr(1);
        if (!clean.empty() && (clean.back() == '"' || clean.back() == '>'))
            clean.pop_back();

        // Try relative to current file's directory
        if (!current_file.empty()) {
            auto dir = std::filesystem::path(current_file).parent_path();
            auto candidate = dir / clean;
            if (std::filesystem::exists(candidate))
                return candidate.string();
        }

        // Try each SDK include path. The same <header> names repeat
        // thousands of times across files, and include_paths_ is frozen
        // before the worker threads start, so cache the path-search result
        // (hits AND misses) per thread - each fs::exists is a syscall, and
        // without this every failed lookup walks every WASDK/NuGet dir too.
        static thread_local std::unordered_map<std::string, std::string> res_cache;
        if (auto ci = res_cache.find(std::string(clean)); ci != res_cache.end())
            return ci->second;
        std::string resolved;
        for (auto& inc : include_paths_) {
            auto candidate = inc / clean;
            if (std::filesystem::exists(candidate)) {
                resolved = candidate.string();
                break;
            }
        }
        res_cache.emplace(std::string(clean), resolved);
        return resolved;
    }

    // Add an include search path (dedup: the collect phase queues one entry
    // per extra header, so the same NuGet include dir arrives many times)
    void add_include_path(const std::filesystem::path& p) {
        for (auto const& e : include_paths_) if (e == p) return;
        include_paths_.push_back(p);
    }

    // Check if a define is set
    bool is_defined(std::string_view name) const {
        return defines_.count(std::string(name)) > 0;
    }

    // Get define value
    std::string get_define(std::string_view name) const {
        auto it = defines_.find(std::string(name));
        return it != defines_.end() ? it->second.value : "";
    }

    // Set a define
    void set_define(const std::string& name, const std::string& value = "1") {
        defines_[name] = {name, value};
    }

    // Set a function-like macro, keeping its parameter names so the integer
    // evaluator can expand invocations. The SDK builds whole constant
    // families through these: every E_* HRESULT is
    // `#define E_FAIL _HRESULT_TYPEDEF_(0x80004005L)` where
    // `_HRESULT_TYPEDEF_(_sc) ((HRESULT)_sc)`. Recording the name alone
    // (with its parameter list still glued to it) left the invocation
    // unresolvable, so the constant was dropped from the winmd.
    void set_function_macro(const std::string& name,
                            std::vector<std::string> params,
                            const std::string& value) {
        Define d;
        d.name = name;
        d.value = value;
        d.is_function_macro = true;
        d.params = std::move(params);
        defines_[name] = std::move(d);
    }

    // Evaluate an integer expression fragment: a numeric literal (0x... /
    // decimal) or the name of a previously defined object macro. Resolves
    // one level of macro indirection recursively (FILE_DEVICE_DISK ->
    // 0x00000007).
    // Evaluate an integer #define value: literals (hex/dec with suffixes),
    // referenced defines, redundant parentheses, type casts (with optional
    // inner spaces), unary +/~/-, and the top-level binary operators |, ^,
    // &, << and >> — SDK headers spell constant families as
    // (WS_OVERLAPPED|WS_CAPTION|...), registry access masks as
    // (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_NOTIFY), the predefined
    // HKEY_* roots as (( HKEY ) ( ((ULONG_PTR)((LONG)0x80000000)) )) and
    // INVALID_HANDLE_VALUE as ((HANDLE)(LONG_PTR)-1). A literal-or-
    // identifier-only evaluator dropped every one of them.
    static void eval_trim(std::string_view& s) {
        while (!s.empty() && (unsigned char)s.front() <= ' ') s.remove_prefix(1);
        while (!s.empty() && (unsigned char)s.back() <= ' ') s.remove_suffix(1);
    }
    static void eval_trim(std::string& s) {
        while (!s.empty() && (unsigned char)s.front() <= ' ') s.erase(0, 1);
        while (!s.empty() && (unsigned char)s.back() <= ' ') s.pop_back();
    }
    // Whole-word replacement of a macro parameter inside a macro body.
    // `_sc` must not corrupt a longer identifier that merely starts with it
    // (`_sc2`, `m_scx`), so both flanking characters are checked.
    static std::string replace_word(std::string body, std::string const& word,
                                    std::string const& repl) {
        if (word.empty()) return body;
        size_t pos = 0;
        while ((pos = body.find(word, pos)) != std::string::npos) {
            bool left_ok  = (pos == 0) ||
                !(std::isalnum((unsigned char)body[pos - 1]) || body[pos - 1] == '_');
            size_t end = pos + word.size();
            bool right_ok = (end >= body.size()) ||
                !(std::isalnum((unsigned char)body[end]) || body[end] == '_');
            if (left_ok && right_ok) {
                body.replace(pos, word.size(), repl);
                pos += repl.size();
            } else {
                pos += word.size();
            }
        }
        return body;
    }
    // Split at the LAST top-level occurrence of a single-char operator
    // (rightmost split => left-associative evaluation through recursion).
    static bool eval_split1(std::string_view s, char op,
                            std::string_view& lhs, std::string_view& rhs) {
        int depth = 0;
        for (size_t i = s.size(); i-- > 0;) {
            char c = s[i];
            if (c == ')') ++depth;
            else if (c == '(') { if (--depth < 0) return false; }
            else if (c == op && depth == 0) {
                lhs = s.substr(0, i);
                rhs = s.substr(i + 1);
                eval_trim(lhs);
                eval_trim(rhs);
                return !lhs.empty() && !rhs.empty();
            }
        }
        return false;
    }
    // Same for a two-char operator (<<, >>).
    static bool eval_split2(std::string_view s, char a, char b,
                            std::string_view& lhs, std::string_view& rhs) {
        int depth = 0;
        for (size_t i = s.size(); i-- > 0;) {
            char c = s[i];
            if (c == ')') ++depth;
            else if (c == '(') { if (--depth < 0) return false; }
            else if (c == b && i > 0 && s[i - 1] == a && depth == 0) {
                lhs = s.substr(0, i - 1);
                rhs = s.substr(i + 1);
                eval_trim(lhs);
                eval_trim(rhs);
                return !lhs.empty() && !rhs.empty();
            }
        }
        return false;
    }
    bool eval_or(std::string_view s, uint32_t& out) const {
        std::string_view lhs, rhs;
        if (eval_split1(s, '|', lhs, rhs)) {
            uint32_t a = 0, b = 0;
            return eval_or(lhs, a) && eval_or(rhs, b) && ((out = a | b), true);
        }
        return eval_xor(s, out);
    }
    bool eval_xor(std::string_view s, uint32_t& out) const {
        std::string_view lhs, rhs;
        if (eval_split1(s, '^', lhs, rhs)) {
            uint32_t a = 0, b = 0;
            return eval_xor(lhs, a) && eval_xor(rhs, b) && ((out = a ^ b), true);
        }
        return eval_and(s, out);
    }
    bool eval_and(std::string_view s, uint32_t& out) const {
        std::string_view lhs, rhs;
        if (eval_split1(s, '&', lhs, rhs)) {
            uint32_t a = 0, b = 0;
            return eval_and(lhs, a) && eval_and(rhs, b) && ((out = a & b), true);
        }
        return eval_shift(s, out);
    }
    bool eval_shift(std::string_view s, uint32_t& out) const {
        std::string_view lhs, rhs;
        if (eval_split2(s, '<', '<', lhs, rhs)) {
            uint32_t a = 0, b = 0;
            return eval_shift(lhs, a) && eval_primary(rhs, b) && ((out = a << b), true);
        }
        if (eval_split2(s, '>', '>', lhs, rhs)) {
            uint32_t a = 0, b = 0;
            return eval_shift(lhs, a) && eval_primary(rhs, b) && ((out = a >> b), true);
        }
        return eval_addsub(s, out);
    }
    // Binary +/- binds tighter than << >> and looser than unary — C
    // precedence: ED_BASE+439L, FILE_DEVICE_NETWORK+N, 0x10-1. Without
    // this level every additive constant failed eval and was silently
    // dropped by materialize_int_consts (the | ^ & << >> chains resolved
    // fine, so the gap only showed on expression-valued defines).
    // Split at the LAST top-level +/- (left-associative via recursion);
    // reject a split whose lhs ENDS with an operator ('1+-2', 'A<<-1')
    // so the sign stays unary and the digit path sees the whole atom.
    bool eval_addsub(std::string_view s, uint32_t& out) const {
        int depth = 0;
        for (size_t i = s.size(); i-- > 0;) {
            char c = s[i];
            if (c == ')') { ++depth; continue; }
            if (c == '(') { if (--depth < 0) return false; continue; }
            if ((c == '+' || c == '-') && depth == 0 && i > 0) {
                // previous non-space char on the lhs: an operator or open
                // paren means this is a sign, not a subtraction
                size_t j = i;
                while (j > 0 && (unsigned char)s[j - 1] <= ' ') --j;
                if (j == 0) continue;
                char p = s[j - 1];
                if (p == '+' || p == '-' || p == '*' || p == '/' || p == '%' ||
                    p == '&' || p == '|' || p == '^' || p == '<' || p == '>' ||
                    p == '(' || p == '~' || p == '!')
                    continue;
                auto lhs = s.substr(0, i);
                auto rhs = s.substr(i + 1);
                eval_trim(lhs);
                eval_trim(rhs);
                if (lhs.empty() || rhs.empty()) continue;
                uint32_t a = 0, b = 0;
                if (eval_addsub(lhs, a) && eval_primary(rhs, b)) {
                    out = (c == '+') ? a + b : a - b;
                    return true;
                }
                // a failed split here is not decisive (e.g. an earlier
                // textual '-' inside an identifier is impossible, but a
                // nested cast may split differently) — keep scanning
            }
        }
        return eval_primary(s, out);
    }
    bool eval_primary(std::string_view s, uint32_t& out) const {
        eval_trim(s);
        if (s.empty()) return false;
        // Unwrap redundant parentheses: "(0x10)" -> "0x10",
        // "(WS_OVERLAPPED|WS_CAPTION|...)" -> "WS_OVERLAPPED|WS_CAPTION|...".
        bool unwrapped = false;
        while (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
            int depth = 0;
            bool whole = true;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '(') ++depth;
                else if (s[i] == ')') {
                    --depth;
                    if (depth == 0 && i + 1 < s.size()) { whole = false; break; }
                }
            }
            if (!whole) break;
            s = s.substr(1, s.size() - 2);
            eval_trim(s);
            unwrapped = true;
        }
        // A fully parenthesized VALUE like (A|B|C) unwraps to an expression,
        // not an atom — re-dispatch so its top-level operators split. (A
        // non-unwrapping cast chain like ( HKEY ) (0x1) never sets the flag,
        // so the cast-strip below still runs for it.)
        if (unwrapped) return eval_or(s, out);
        // Strip a leading type cast — "(HKEY)" / "( HKEY )" / "(ULONG_PTR)"
        // — when a value follows: evaluate that inner value instead.
        if (s.size() > 2 && s.front() == '(') {
            size_t i = 1;
            while (i < s.size() && (unsigned char)s[i] <= ' ') ++i;
            size_t id_start = i;
            while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) ++i;
            if (i > id_start) {
                while (i < s.size() && (unsigned char)s[i] <= ' ') ++i;
                if (i < s.size() && s[i] == ')') {
                    auto rest = s.substr(i + 1);
                    eval_trim(rest);
                    if (!rest.empty() && (rest.front() == '(' || rest.front() == '-' ||
                                          rest.front() == '+' || rest.front() == '~' ||
                                          std::isalnum((unsigned char)rest.front()) ||
                                          rest.front() == '_'))
                        return eval_or(rest, out);
                }
            }
        }
        // Unary minus / plus / complement.
        if (s.front() == '-' || s.front() == '+' || s.front() == '~') {
            char op = s.front();
            uint32_t v = 0;
            if (!eval_primary(s.substr(1), v)) return false;
            out = (op == '-') ? (uint32_t)(0u - v) : (op == '~') ? (uint32_t)~v : v;
            return true;
        }
        if (std::isdigit((unsigned char)s.front())) {
            out = (uint32_t)std::strtoul(std::string(s).c_str(), nullptr, 0);
            return true;
        }
        // Function-like macro invocation: `NAME(arg, ...)`. The SDK builds
        // constant families this way - every E_* HRESULT is
        // `_HRESULT_TYPEDEF_(0x80004005L)`, and CTL_CODE packs IOCTLs. The
        // identifier is glued to '(', so the object-like lookup below can
        // never match it; substitute the arguments into the body and
        // evaluate that instead. Argument substitution is whole-word so a
        // parameter named `_sc` cannot corrupt a longer identifier.
        {
            size_t i = 0;
            while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) ++i;
            if (i > 0 && i < s.size() && s[i] == '(') {
                auto it = defines_.find(std::string(s.substr(0, i)));
                if (it != defines_.end() && it->second.is_function_macro) {
                    // Split the argument list on top-level commas.
                    std::vector<std::string_view> args;
                    int depth = 0;
                    size_t start = i + 1;
                    for (size_t k = i + 1; k < s.size(); ++k) {
                        char c = s[k];
                        if (c == '(') ++depth;
                        else if (c == ')') {
                            if (depth == 0) {
                                args.push_back(s.substr(start, k - start));
                                break;
                            }
                            --depth;
                        }
                        else if (c == ',' && depth == 0) {
                            args.push_back(s.substr(start, k - start));
                            start = k + 1;
                        }
                    }
                    if (args.size() == it->second.params.size()) {
                        std::string body = it->second.value;
                        for (size_t p = 0; p < args.size(); ++p) {
                            std::string arg(args[p]);
                            eval_trim(arg);
                            body = replace_word(std::move(body), it->second.params[p], arg);
                        }
                        return eval_or(body, out);
                    }
                }
            }
        }
        auto it = defines_.find(std::string(s));
        if (it != defines_.end() && it->second.value != s)
            return eval_macro_int(it->second.value, out); // capped entry
        return false;
    }
    bool eval_macro_int(std::string_view s, uint32_t& out) const {
        // Recursion cap: the merged post-parse define table contains
        // mutual references; 64 frames is far beyond any real constant
        // chain (the longest observed WS_*/DSBCAPS_* nests use <10).
        thread_local int eval_depth = 0;
        if (eval_depth > 64) return false;
        struct depth_guard { int& d; ~depth_guard() { --d; } } g{ eval_depth };
        ++eval_depth;
        return eval_or(s, out);
    }

    // Evaluate CTL_CODE(DeviceType, Function, Method, Access) into its
    // packed IOCTL code: (DeviceType << 16) | (Access << 14) |
    // (Function << 2) | Method. Args are literals or defined macro names
    // (FILE_DEVICE_*, METHOD_*, FILE_*_ACCESS).
    bool eval_ctl_code(std::string_view val, uint32_t& out) const {
        auto cp = val.find("CTL_CODE(");
        if (cp == std::string_view::npos) return false;
        auto open = val.find('(', cp);
        // Split the four top-level arguments on commas.
        std::vector<std::string> parts;
        std::string acc;
        int depth = 0;
        bool closed = false;
        for (size_t r = open + 1; r < val.size() && !closed; ++r) {
            char c = val[r];
            if (c == '(') { ++depth; acc += c; continue; }
            if (c == ')') {
                if (depth == 0) { parts.push_back(acc); closed = true; break; }
                --depth; acc += c; continue;
            }
            if (c == ',' && depth == 0) { parts.push_back(acc); acc.clear(); continue; }
            acc += c;
        }
        if (!closed || parts.size() != 4) return false;
        uint32_t v[4];
        for (int i = 0; i < 4; ++i)
            if (!eval_macro_int(parts[i], v[i])) return false;
        out = (v[0] << 16) | (v[3] << 14) | (v[1] << 2) | v[2];
        return true;
    }

    // Undefine
    void undefine(std::string_view name) {
        defines_.erase(std::string(name));
    }

    // Evaluate architecture from defines
    Ar current_arch() const {
        if (is_defined("_M_IX86"))   return Ar::X86;
        if (is_defined("_M_X64"))    return Ar::X64;
        if (is_defined("_M_ARM"))    return Ar::Arm;
        if (is_defined("_M_ARM64"))  return Ar::Arm64;
        return Ar::All;
    }

    // Evaluate #ifdef condition
    bool eval_ifdef(std::string_view condition) const {
        auto name = trim(condition);
        return is_defined(name);
    }

    // Evaluate #if defined(...) or defined X
    bool eval_if_defined(std::string_view expr) const {
        auto trimmed = trim(expr);
        // Handle: defined(X) or defined X
        if (trimmed.starts_with("defined(")) {
            auto inner = trimmed.substr(8);
            if (!inner.empty() && inner.back() == ')')
                inner.remove_suffix(1);
            return is_defined(trim(inner));
        }
        if (trimmed.starts_with("defined ")) {
            return is_defined(trim(trimmed.substr(8)));
        }
        // Fallback: treat as nonzero if define exists
        return is_defined(trimmed);
    }

    // Full C preprocessor #if expression evaluator
    // Handles: ||, &&, |, &, ^, ~, !, ==, !=, <, >, <=, >=, <<, >>, +, -, *, /, %,
    //          defined(), parenthesized, hex/octal/decimal literals, ternary ?:
    bool eval_if(std::string_view expr) const {
        size_t p = 0;
        auto result = eval_ternary(expr, p);
        return result != 0;
    }

private:
    // Skip whitespace
    static void eval_skip_ws(std::string_view s, size_t& p) {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r')) ++p;
    }

    // Skip balanced parens after function-like macro call
    static void skip_parens(std::string_view s, size_t& p) {
        if (p < s.size() && s[p] == '(') {
            ++p;
            int depth = 1;
            while (p < s.size() && depth > 0) {
                if (s[p] == '(') ++depth;
                else if (s[p] == ')') --depth;
                ++p;
            }
        }
    }

    // Read an integer literal (hex 0x, octal 0, decimal)
    static int64_t eval_read_int(std::string_view s, size_t& p) {
        eval_skip_ws(s, p);
        if (p >= s.size()) return 0;
        bool neg = false;
        if (s[p] == '-') { neg = true; ++p; }
        else if (s[p] == '+') { ++p; }
        eval_skip_ws(s, p);
        int64_t val = 0;
        if (p < s.size() && s[p] == '0' && p + 1 < s.size() && (s[p+1] == 'x' || s[p+1] == 'X')) {
            p += 2;
            while (p < s.size() && std::isxdigit((unsigned char)s[p])) {
                val = val * 16 + (s[p] >= '0' && s[p] <= '9' ? s[p] - '0' : (s[p] | 32) - 'a' + 10);
                ++p;
            }
        } else if (p < s.size() && s[p] == '0' && p + 1 < s.size() && std::isdigit((unsigned char)s[p+1])) {
            ++p;
            while (p < s.size() && s[p] >= '0' && s[p] <= '7') {
                val = val * 8 + (s[p] - '0');
                ++p;
            }
        } else {
            while (p < s.size() && std::isdigit((unsigned char)s[p])) {
                val = val * 10 + (s[p] - '0');
                ++p;
            }
        }
        if (p < s.size() && s[p] == 'U') ++p;
        if (p < s.size() && s[p] == 'L') ++p;
        return neg ? -val : val;
    }

    // Read an identifier or function-like macro
    static std::string eval_read_ident(std::string_view s, size_t& p) {
        eval_skip_ws(s, p);
        size_t start = p;
        while (p < s.size() && (std::isalnum((unsigned char)s[p]) || s[p] == '_' || s[p] == '$')) ++p;
        return std::string(s.substr(start, p - start));
    }

    // Evaluate primary expression (number, ident, parenthesized, unary)
    int64_t eval_primary(std::string_view s, size_t& p) const {
        eval_skip_ws(s, p);
        if (p >= s.size()) return 0;

        // Parenthesized expression
        if (s[p] == '(') {
            ++p;
            auto val = eval_ternary(s, p);
            eval_skip_ws(s, p);
            if (p < s.size() && s[p] == ')') ++p;
            return val;
        }

        // Unary operators
        if (s[p] == '!') { ++p; return eval_primary(s, p) == 0 ? 1 : 0; }
        if (s[p] == '~') { ++p; return ~eval_primary(s, p); }
        if (s[p] == '-') { ++p; return -eval_primary(s, p); }
        if (s[p] == '+') { ++p; return eval_primary(s, p); }

        // String literal — treat as 0
        if (s[p] == '"') {
            while (p < s.size() && s[p] != '"') { if (s[p] == '\\') ++p; ++p; }
            if (p < s.size()) ++p;
            return 0;
        }
        // Char literal
        if (s[p] == '\'') {
            ++p;
            int64_t ch = 0;
            if (p < s.size() && s[p] == '\\') { ++p; if (p < s.size()) { ch = s[p]; ++p; } }
            else if (p < s.size()) { ch = s[p]; ++p; }
            if (p < s.size() && s[p] == '\'') ++p;
            return ch;
        }

        // Numeric literal
        if (std::isdigit((unsigned char)s[p]) || s[p] == '-') {
            return eval_read_int(s, p);
        }

        // Identifier or macro
        auto id = eval_read_ident(s, p);
        if (id.empty()) return 0;

        eval_skip_ws(s, p);

        // defined(X) or defined X
        if (id == "defined") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                auto inner = eval_read_ident(s, p);
                eval_skip_ws(s, p);
                if (p < s.size() && s[p] == ')') ++p;
                return is_defined(inner) ? 1 : 0;
            }
            auto inner = eval_read_ident(s, p);
            return is_defined(inner) ? 1 : 0;
        }

        // __has_include(...)
        if (id == "__has_include") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 1; // Assume all includes are available in SDK
        }

        // __has_cpp_attribute(...)
        if (id == "__has_cpp_attribute") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_warning(...)
        if (id == "__has_warning") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_extension(...)
        if (id == "__has_extension") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // sizeof — approximate: return size for common types (x64)
        if (id == "sizeof") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                auto inner = eval_read_ident(s, p);
                eval_skip_ws(s, p);
                if (p < s.size() && s[p] == ')') ++p;
                // 1-byte types
                if (inner == "char" || inner == "CHAR" || inner == "UCHAR" || inner == "BYTE" ||
                    inner == "bool" || inner == "BOOLEAN" || inner == "INT8" || inner == "UINT8" ||
                    inner == "CCHAR" || inner == "FLAGGED_BYTE" || inner == "KIRQL") return 1;
                // 2-byte types
                if (inner == "WCHAR" || inner == "wchar_t" || inner == "SHORT" || inner == "USHORT" ||
                    inner == "WORD" || inner == "INT16" || inner == "UINT16" || inner == "USHORT" ||
                    inner == "CHAR16" || inner == "char16_t") return 2;
                // 4-byte types
                if (inner == "void" || inner == "BOOL" || inner == "int" || inner == "long" ||
                    inner == "DWORD" || inner == "ULONG" || inner == "UINT" || inner == "INT" ||
                    inner == "INT32" || inner == "UINT32" || inner == "LONG" || inner == "HRESULT" ||
                    inner == "NTSTATUS" || inner == "LSTATUS" || inner == "FLOAT" ||
                    inner == "int32_t" || inner == "uint32_t" || inner == "FLONG" ||
                    inner == "COLORREF" || inner == "FourCC") return 4;
                // 8-byte types (pointers on x64, long long, etc.)
                if (inner == "long long" || inner == "LONGLONG" || inner == "ULONGLONG" ||
                    inner == "__int64" || inner == "INT64" || inner == "UINT64" ||
                    inner == "INT_PTR" || inner == "UINT_PTR" || inner == "LONG_PTR" ||
                    inner == "ULONG_PTR" || inner == "DWORD_PTR" || inner == "SIZE_T" ||
                    inner == "SSIZE_T" || inner == "size_t" || inner == "ssize_t" ||
                    inner == "intptr_t" || inner == "uintptr_t" ||
                    inner == "LPVOID" || inner == "PVOID" || inner == "HANDLE" ||
                    inner == "LPCWSTR" || inner == "LPCSTR" || inner == "LPWSTR" ||
                    inner == "LPSTR" || inner == "PCWSTR" || inner == "PCSTR" ||
                    inner == "PWSTR" || inner == "PSTR" || inner == "LRESULT" ||
                    inner == "LPARAM" || inner == "WPARAM" || inner == "INT_PTR" ||
                    inner == "DOUBLE" || inner == "int64_t" || inner == "uint64_t" ||
                    inner == "POINTER_64" || inner == "POINTER_32" ||
                    inner == "DWORD64" || inner == "KSPIN_LOCK" ||
                    inner == "ULONGLONG" || inner == "LARGE_INTEGER" ||
                    inner == "ULARGE_INTEGER" || inner == "FILETIME") return 8;
                if (inner == "float") return 4;
                if (inner == "double") return 8;
                if (inner == "GUID" || inner == "IID" || inner == "CLSID" ||
                    inner == "uuid_t" || inner == "__m128" || inner == "__m128i" ||
                    inner == "__m128d") return 16;
                if (inner == "__m256" || inner == "__m256i" || inner == "__m256d") return 32;
                if (inner == "__m512" || inner == "__m512i" || inner == "__m512d") return 64;
                return 4; // Default
            }
            return 4;
        }

        // __builtin_offsetof(TYPE, MEMBER) or offsetof(TYPE, MEMBER)
        if (id == "__builtin_offsetof" || id == "offsetof") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0; // Offset unknown at preprocessor time
        }

        // __builtin_types_compatible_p(...)
        if (id == "__builtin_types_compatible_p") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __builtin_choose_expr(...)
        if (id == "__builtin_choose_expr") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __builtin_constant_p(...)
        if (id == "__builtin_constant_p") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_feature(...)
        if (id == "__has_feature") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_builtin(...)
        if (id == "__has_builtin") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_attribute(...)
        if (id == "__has_attribute") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_declspec(...)
        if (id == "__has_declspec") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
            }
            return 0;
        }

        // __has_unique_object_representations(...)
        if (id == "__has_unique_object_representations") {
            skip_parens(s, p);
            return 0;
        }

        // __has_trivial_relocate(...)
        if (id == "__has_trivial_relocate") {
            skip_parens(s, p);
            return 0;
        }

        // __is_aggregate(...)
        if (id == "__is_aggregate") {
            skip_parens(s, p);
            return 0;
        }

        // __is_assignable(...)
        if (id == "__is_assignable") {
            skip_parens(s, p);
            return 0;
        }

        // __is_constructible(...)
        if (id == "__is_constructible") {
            skip_parens(s, p);
            return 1;
        }

        // __is_convertible(...)
        if (id == "__is_convertible") {
            skip_parens(s, p);
            return 0;
        }

        // __is_destructible(...)
        if (id == "__is_destructible") {
            skip_parens(s, p);
            return 1;
        }

        // __is_empty(...)
        if (id == "__is_empty") {
            skip_parens(s, p);
            return 0;
        }

        // __is_enum(...)
        if (id == "__is_enum") {
            skip_parens(s, p);
            return 0;
        }

        // __is_final(...)
        if (id == "__is_final") {
            skip_parens(s, p);
            return 0;
        }

        // __is_integral(...)
        if (id == "__is_integral") {
            skip_parens(s, p);
            return 0;
        }

        // __is_layout_compatible(...)
        if (id == "__is_layout_compatible") {
            skip_parens(s, p);
            return 0;
        }

        // __is_literal(...)
        if (id == "__is_literal") {
            skip_parens(s, p);
            return 0;
        }

        // __is_nothrow_constructible(...)
        if (id == "__is_nothrow_constructible") {
            skip_parens(s, p);
            return 0;
        }

        // __is_nothrow_destructible(...)
        if (id == "__is_nothrow_destructible") {
            skip_parens(s, p);
            return 1;
        }

        // __is_same(...)
        if (id == "__is_same") {
            skip_parens(s, p);
            return 0;
        }

        // __is_same_as(...)
        if (id == "__is_same_as") {
            skip_parens(s, p);
            return 0;
        }

        // __is_signed(...)
        if (id == "__is_signed") {
            skip_parens(s, p);
            return 0;
        }

        // __is_struct(...)
        if (id == "__is_struct") {
            skip_parens(s, p);
            return 0;
        }

        // __is_trivial(...)
        if (id == "__is_trivial") {
            skip_parens(s, p);
            return 0;
        }

        // __is_trivially_assignable(...)
        if (id == "__is_trivially_assignable") {
            skip_parens(s, p);
            return 0;
        }

        // __is_trivially_constructible(...)
        if (id == "__is_trivially_constructible") {
            skip_parens(s, p);
            return 0;
        }

        // __is_trivially_copyable(...)
        if (id == "__is_trivially_copyable") {
            skip_parens(s, p);
            return 0;
        }

        // __is_trivially_destructible(...)
        if (id == "__is_trivially_destructible") {
            skip_parens(s, p);
            return 1;
        }

        // __is_union(...)
        if (id == "__is_union") {
            skip_parens(s, p);
            return 0;
        }

        // __is_reference(...)
        if (id == "__is_reference") {
            skip_parens(s, p);
            return 0;
        }

        // __is_pointer(...)
        if (id == "__is_pointer") {
            skip_parens(s, p);
            return 0;
        }

        // __is_const(...)
        if (id == "__is_const") {
            skip_parens(s, p);
            return 0;
        }

        // __is_volatile(...)
        if (id == "__is_volatile") {
            skip_parens(s, p);
            return 0;
        }

        // __is_void(...)
        if (id == "__is_void") {
            skip_parens(s, p);
            return 0;
        }

        // __is_function(...)
        if (id == "__is_function") {
            skip_parens(s, p);
            return 0;
        }

        // __is_floating_point(...)
        if (id == "__is_floating_point") {
            skip_parens(s, p);
            return 0;
        }

        // __is_arithmetic(...)
        if (id == "__is_arithmetic") {
            skip_parens(s, p);
            return 0;
        }

        // __is_scalar(...)
        if (id == "__is_scalar") {
            skip_parens(s, p);
            return 0;
        }

        // __is_object(...)
        if (id == "__is_object") {
            skip_parens(s, p);
            return 0;
        }

        // __is_compound(...)
        if (id == "__is_compound") {
            skip_parens(s, p);
            return 0;
        }

        // __is_fundamental(...)
        if (id == "__is_fundamental") {
            skip_parens(s, p);
            return 0;
        }

        // __is_abstract(...)
        if (id == "__is_abstract") {
            skip_parens(s, p);
            return 0;
        }

        // __is_base_of(...)
        if (id == "__is_base_of") {
            skip_parens(s, p);
            return 0;
        }

        // __is_class(...)
        if (id == "__is_class") {
            skip_parens(s, p);
            return 0;
        }

        // __is_complete_type(...)
        if (id == "__is_complete_type") {
            skip_parens(s, p);
            return 0;
        }

        // __is_compiled(...)
        if (id == "__is_compiled") {
            skip_parens(s, p);
            return 1;
        }

        // __is_constant_evaluated(...)
        if (id == "__is_constant_evaluated") {
            skip_parens(s, p);
            return 0;
        }

        // __cpp_*, __GNUC__, __GNUC_MINOR__, __clang_major__, etc.
        if (id.size() >= 4 && id.substr(0, 4) == "cpp_") {
            skip_parens(s, p);
            return 0;
        }

        // __COUNTER__, __TIMESTAMP__, __DATE__, __TIME__ — treat as 0
        if (id == "__COUNTER__" || id == "__TIMESTAMP__" || id == "__DATE__" || id == "__TIME__") {
            return 0;
        }

        // __FILE__, __LINE__, __func__, __FUNCTION__, __PRETTY_FUNCTION__
        if (id == "__FILE__" || id == "__LINE__" || id == "__func__" ||
            id == "__FUNCTION__" || id == "__PRETTY_FUNCTION__") {
            return 0;
        }

        // __VA_ARGS__ — just return 0
        if (id == "__VA_ARGS__" || id == "__VA_OPT__") {
            return 0;
        }

        // _Pragma(...) — skip
        if (id == "_Pragma") {
            skip_parens(s, p);
            return 0;
        }

        // _BitCast, _Countof — MSVC internal
        if (id == "_BitCast" || id == "_Countof" || id == "_offsetof") {
            skip_parens(s, p);
            return 0;
        }

        // __assume, __noop — MSVC
        if (id == "__assume" || id == "__noop") {
            skip_parens(s, p);
            return 0;
        }

        // __uuidof(...) — MSVC GUID
        if (id == "__uuidof") {
            skip_parens(s, p);
            return 0;
        }

        // __FUNCSIG__, __FUNCSIG_CPP__ — MSVC
        if (id == "__FUNCSIG__" || id == "__FUNCSIG_CPP__") {
            return 0;
        }

        // __alignof, _alignof — MSVC/GCC
        if (id == "__alignof" || id == "_alignof") {
            skip_parens(s, p);
            return 4;
        }

        // __intsizeof — MSVC
        if (id == "__intsizeof") {
            skip_parens(s, p);
            return 4;
        }

        // __dbk_countof — MSVC debug
        if (id == "__dbk_countof") {
            skip_parens(s, p);
            return 0;
        }

        // __analysis_assume — SAL
        if (id == "__analysis_assume") {
            skip_parens(s, p);
            return 0;
        }

        // __drv_allocatesMem, __drv_freesMem — SAL driver
        if (id.substr(0, 5) == "__drv_") {
            skip_parens(s, p);
            return 0;
        }

        // __nullterminated, __nullnullterminated — SAL
        if (id == "__nullterminated" || id == "__nullnullterminated" ||
            id == "__maybenull" || id == "__mustbenull" ||
            id == "__post" || id == "__pre" || id == "__field_ecs" ||
            id == "__field_range" || id == "__field_size" ||
            id == "__orderby" || id == "__genonymous") {
            return 0;
        }

        // C++20 requires/requires expression
        if (id == "requires") {
            skip_parens(s, p);
            return 1;
        }

        // consteval, constinit — C++20
        if (id == "consteval" || id == "constinit") {
            return 0;
        }

        // constexpr — C++11
        if (id == "constexpr") {
            return 0;
        }

        // noexcept — C++11
        if (id == "noexcept") {
            return 1;
        }

        // override, final — C++11
        if (id == "override" || id == "final") {
            return 0;
        }

        // concept, namedRequire
        if (id == "concept") {
            return 0;
        }

        // co_await, co_return, co_yield — C++20 coroutines
        if (id == "co_await" || id == "co_return" || id == "co_yield") {
            return 0;
        }

        // decltype
        if (id == "decltype") {
            skip_parens(s, p);
            return 0;
        }

        // nullptr_t
        if (id == "nullptr_t") {
            return 0;
        }

        // __int128
        if (id == "__int128" || id == "__uint128") {
            return 0;
        }

        // __float128
        if (id == "__float128") {
            return 0;
        }

        // __wchar_t
        if (id == "__wchar_t") {
            return 0;
        }

        // __restrict__, __restrict
        if (id == "__restrict__" || id == "__restrict") {
            return 0;
        }

        // __volatile__, __volatile
        if (id == "__volatile__" || id == "__volatile") {
            return 0;
        }

        // __const__, __const
        if (id == "__const__" || id == "__const") {
            return 0;
        }

        // __signed__, __signed
        if (id == "__signed__" || id == "__signed") {
            return 0;
        }

        // __inline__, __inline
        if (id == "__inline__" || id == "__inline") {
            return 0;
        }

        // __asm__ is already handled above but just in case
        if (id == "__asm__" || id == "__asm") {
            return 0;
        }

        // __typeof__, typeof
        if (id == "__typeof__" || id == "typeof" || id == "__typeof") {
            skip_parens(s, p);
            return 0;
        }

        // __attribute__ already handled above

        // __builtin_shuffle, __builtin_shufflevector
        if (id == "__builtin_shuffle" || id == "__builtin_shufflevector") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_convertvector
        if (id == "__builtin_convertvector") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_matrix
        if (id == "__builtin_matrix") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_forward, __builtin_move
        if (id == "__builtin_forward" || id == "__builtin_move") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_launder
        if (id == "__builtin_launder") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_bit_cast
        if (id == "__builtin_bit_cast") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_is_constant_evaluated
        if (id == "__builtin_is_constant_evaluated") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_assume_aligned
        if (id == "__builtin_assume_aligned") {
            skip_parens(s, p);
            return 0;
        }

        // __builtin_trap
        if (id == "__builtin_trap") {
            return 0;
        }

        // __builtin_debugtrap
        if (id == "__builtin_debugtrap") {
            return 0;
        }

        // __builtin_line, __builtin_file, __builtin_column
        if (id == "__builtin_line" || id == "__builtin_file" || id == "__builtin_column") {
            return 0;
        }

        // __builtin_available
        if (id == "__builtin_available") {
            skip_parens(s, p);
            return 1;
        }

        // __builtin_FILE, __builtin_LINE, __builtin_FUNCTION
        if (id == "__builtin_FILE" || id == "__builtin_LINE" || id == "__builtin_FUNCTION") {
            return 0;
        }

        // __PRETTY_FUNCTION__ already handled

        // WINAPI_FAMILY_PARTITION(...)
        if (id == "WINAPI_FAMILY_PARTITION") {
            if (p < s.size() && s[p] == '(') {
                ++p;
                auto inner_p = p;
                int depth = 1;
                while (p < s.size() && depth > 0) {
                    if (s[p] == '(') ++depth;
                    else if (s[p] == ')') --depth;
                    ++p;
                }
                auto inner = s.substr(inner_p, p - inner_p - 1);
                if (inner.find("WINAPI_PARTITION_DESKTOP") != std::string_view::npos) return 1;
                if (inner.find("WINAPI_PARTITION_APP") != std::string_view::npos) return 1;
                if (inner.find("WINAPI_PARTITION_SYSTEM") != std::string_view::npos) return 1;
                if (inner.find("WINAPI_PARTITION_GAMES") != std::string_view::npos) return 1;
                return 1; // Unknown partition, assume valid
            }
        }

        // __CUDA_ARCH__ or other unknown function-like macros — skip args
        if (p < s.size() && s[p] == '(') {
            ++p;
            int depth = 1;
            while (p < s.size() && depth > 0) {
                if (s[p] == '(') ++depth;
                else if (s[p] == ')') --depth;
                ++p;
            }
            return 0;
        }

        // Known keyword constants
        if (id == "TRUE") return 1;
        if (id == "FALSE" || id == "false") return 0;
        if (id == "NULL" || id == "nullptr" || id == "__null") return 0;
        if (id == "__cplusplus") return is_defined(id) ? 1 : 0;

        // Look up define — if it has a numeric value, use it
        if (is_defined(id)) {
            auto val_str = get_define(id);
            if (!val_str.empty()) {
                // Try to parse as number
                if (val_str.size() > 2 && val_str[0] == '0' && (val_str[1] == 'x' || val_str[1] == 'X')) {
                    try { return std::stoll(val_str, nullptr, 16); } catch (...) {}
                }
                try { return std::stoll(val_str); } catch (...) {}
                // If it's a string define, check if non-empty = 1
                return 1;
            }
            return 1; // Defined but no value = truthy
        }

        return 0; // Undefined identifier = 0
    }

    // Evaluate multiplicative: *, /, %
    int64_t eval_mul(std::string_view s, size_t& p) const {
        auto left = eval_primary(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p >= s.size()) return left;
            if (s[p] == '*' && p + 1 < s.size() && s[p+1] == '/') { p += 2; continue; } // end of block comment
            if (s[p] == '*') { ++p; left *= eval_primary(s, p); }
            else if (s[p] == '/') { ++p; auto d = eval_primary(s, p); left = d != 0 ? left / d : 0; }
            else if (s[p] == '%') { ++p; auto d = eval_primary(s, p); left = d != 0 ? left % d : 0; }
            else break;
        }
        return left;
    }

    // Evaluate additive: +, -
    int64_t eval_add(std::string_view s, size_t& p) const {
        auto left = eval_mul(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p >= s.size()) return left;
            if (s[p] == '+') { ++p; left += eval_mul(s, p); }
            else if (s[p] == '-') { ++p; left -= eval_mul(s, p); }
            else break;
        }
        return left;
    }

    // Evaluate shift: <<, >>
    int64_t eval_shift(std::string_view s, size_t& p) const {
        auto left = eval_add(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p + 1 < s.size() && s[p] == '<' && s[p+1] == '<') { p += 2; left <<= eval_add(s, p); }
            else if (p + 1 < s.size() && s[p] == '>' && s[p+1] == '>') { p += 2; left >>= eval_add(s, p); }
            else break;
        }
        return left;
    }

    // Evaluate relational: <, >, <=, >=
    int64_t eval_relational(std::string_view s, size_t& p) const {
        auto left = eval_shift(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p + 1 < s.size() && s[p] == '<' && s[p+1] == '=') { p += 2; left = (left <= eval_shift(s, p)) ? 1 : 0; }
            else if (p + 1 < s.size() && s[p] == '>' && s[p+1] == '=') { p += 2; left = (left >= eval_shift(s, p)) ? 1 : 0; }
            else if (p < s.size() && s[p] == '<' && p + 1 < s.size() && s[p+1] != '<') { ++p; left = (left < eval_shift(s, p)) ? 1 : 0; }
            else if (p < s.size() && s[p] == '>' && p + 1 < s.size() && s[p+1] != '>') { ++p; left = (left > eval_shift(s, p)) ? 1 : 0; }
            else break;
        }
        return left;
    }

    // Evaluate equality: ==, !=
    int64_t eval_equality(std::string_view s, size_t& p) const {
        auto left = eval_relational(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p + 1 < s.size() && s[p] == '=' && s[p+1] == '=') { p += 2; left = (left == eval_relational(s, p)) ? 1 : 0; }
            else if (p + 1 < s.size() && s[p] == '!' && s[p+1] == '=') { p += 2; left = (left != eval_relational(s, p)) ? 1 : 0; }
            else break;
        }
        return left;
    }

    // Evaluate bitwise AND: &
    int64_t eval_bitand(std::string_view s, size_t& p) const {
        auto left = eval_equality(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p < s.size() && s[p] == '&' && p + 1 < s.size() && s[p+1] != '&') { ++p; left &= eval_equality(s, p); }
            else break;
        }
        return left;
    }

    // Evaluate bitwise XOR: ^
    int64_t eval_bitxor(std::string_view s, size_t& p) const {
        auto left = eval_bitand(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p < s.size() && s[p] == '^') { ++p; left ^= eval_bitand(s, p); }
            else break;
        }
        return left;
    }

    // Evaluate bitwise OR: |
    int64_t eval_bitor(std::string_view s, size_t& p) const {
        auto left = eval_bitxor(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p < s.size() && s[p] == '|' && p + 1 < s.size() && s[p+1] != '|') { ++p; left |= eval_bitxor(s, p); }
            else break;
        }
        return left;
    }

    // Evaluate logical AND: &&
    int64_t eval_logand(std::string_view s, size_t& p) const {
        auto left = eval_bitor(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p + 1 < s.size() && s[p] == '&' && s[p+1] == '&') { p += 2; left = (left && eval_bitor(s, p)) ? 1 : 0; }
            else break;
        }
        return left;
    }

    // Evaluate logical OR: ||
    int64_t eval_logor(std::string_view s, size_t& p) const {
        auto left = eval_logand(s, p);
        while (true) {
            eval_skip_ws(s, p);
            if (p + 1 < s.size() && s[p] == '|' && s[p+1] == '|') { p += 2; left = (left || eval_logand(s, p)) ? 1 : 0; }
            else break;
        }
        return left;
    }

    // Evaluate ternary: ? :
    int64_t eval_ternary(std::string_view s, size_t& p) const {
        auto cond = eval_logor(s, p);
        eval_skip_ws(s, p);
        if (p < s.size() && s[p] == '?') {
            ++p;
            auto if_true = eval_ternary(s, p);
            eval_skip_ws(s, p);
            if (p < s.size() && s[p] == ':') ++p;
            auto if_false = eval_ternary(s, p);
            return cond ? if_true : if_false;
        }
        return cond;
    }

public:

    // Initialize standard Win32 defines
    void init_standard_defines() {
        // Target architecture (default to x64)
        set_define("_M_X64");
        set_define("_WIN64");
        set_define("_M_AMD64");

        // Windows version — set high to enable ALL APIs
        set_define("WINVER", "0x0A00");
        set_define("_WIN32_WINNT", "0x0A00");
        set_define("NTDDI_VERSION", "0x0A000000");
        set_define("_WIN32_IE", "0x0A00");
        set_define("NTDDI_WS10", "1");
        set_define("NTDDI_WIN10", "1");
        set_define("NTDDI_WIN10_RS1", "1");
        set_define("NTDDI_WIN10_RS2", "1");
        set_define("NTDDI_WIN10_RS3", "1");
        set_define("NTDDI_WIN10_RS4", "1");
        set_define("NTDDI_WIN10_RS5", "1");
        set_define("NTDDI_WIN10_19H1", "1");
        set_define("NTDDI_WIN10_VB", "1");
        set_define("NTDDI_WIN10_MN", "1");
        set_define("NTDDI_WIN10_FE", "1");
        set_define("NTDDI_WIN10_CO", "1");
        set_define("NTDDI_WIN10_NI", "1");
        set_define("NTDDI_WIN10_AI", "1");

        // WINAPI family — enable ALL partitions
        set_define("WINAPI_FAMILY", "1");
        set_define("WINAPI_FAMILY_DESKTOP_APP", "1");
        set_define("WINAPI_PARTITION_DESKTOP", "1");
        set_define("WINAPI_PARTITION_APP", "1");
        set_define("WINAPI_PARTITION_SYSTEM", "1");
        set_define("WINAPI_PARTITION_GAMES", "1");
        set_define("WINAPI_PARTITION_TV_TITLE", "1");

        // Standard types
        set_define("UCHAR_TYPE", "unsigned char");
        set_define("WCHAR_TYPE", "wchar_t");

        // C/C++ standard
        set_define("__cplusplus", "202302L");
        set_define("_CPPRTTI");
        set_define("_CPPUNWIND");
        set_define("_MSC_VER", "1900");
        set_define("_WIN32");
        // rpc.h defines this unconditionally in real builds. Per-header parse
        // isolation means rpcdce.h never sees that #define, so it fell into
        // its #else branch: the phantom unsuffixed TCHAR-generic decls
        // (RpcBindingFromStringBinding) that RpcRT4.Lib does NOT export
        // (only ...A/...W) — names that could never get an import-lib
        // attribution or link. With this defined, the A/W decls are parsed
        // and match the actual exports exactly.
        set_define("RPC_UNICODE_SUPPORTED");
        set_define("_INTEGRAL_MAX_BITS", "64");
        set_define("__STDC__", "1");
        set_define("__STDC_VERSION__", "202311L");
        set_define("__STDC_HOSTED__", "1");
        set_define("__STDC_MB_MIGHT_NEQ_WC__", "1");
        set_define("__STDC_UTF_16__", "1");
        set_define("__STDC_UTF_32__", "1");
        set_define("__STDC_ANALYZABLE__", "1");
        set_define("__STDC_LIB_EXT1__", "201112L");
        set_define("__STDC_NO_ATOMICS__", "1");
        set_define("__STDC_NO_THREADS__", "1");
        set_define("__STDC_NO_VLA__", "1");
        set_define("__STDC_NO_COMPLEX__", "1");
        // C++ standard versions
        set_define("_MSVC_LANG", "202302L");
        set_define("__cpp_exceptions", "199711L");
        set_define("__cpp_rtti", "199711L");
        set_define("__cpp_aggregate_nsdmi", "201304L");
        set_define("__cpp_aggregate_paren_init", "201902L");
        set_define("__cpp_alias_templates", "200704L");
        set_define("__cpp_aligned_new", "201606L");
        set_define("__cpp_char8_t", "201907L");
        set_define("__cpp_concepts", "202002L");
        set_define("__cpp_constexpr", "201907L");
        set_define("__cpp_constexpr_dynamic_alloc", "201907L");
        set_define("__cpp_constexpr_in_decltype", "201703L");
        set_define("__cpp_consteval", "202002L");
        set_define("__cpp_constinit", "201907L");
        set_define("__cpp_decltype", "200707L");
        set_define("__cpp_decltype_auto", "201304L");
        set_define("__cpp_deduction_guides", "201703L");
        set_define("__cpp_designated_initializers", "201709L");
        set_define("__cpp_enumerator_attributes", "201606L");
        set_define("__cpp_explicit_conversion_operators", "201511L");
        set_define("__cpp_fold_expressions", "201603L");
        set_define("__cpp_generic_lambdas", "201304L");
        set_define("__cpp_hex_float", "201603L");
        set_define("__cpp_if_constexpr", "201606L");
        set_define("__cpp_impl_coroutine", "201902L");
        set_define("__cpp_impl_destroying_delete", "201806L");
        set_define("__cpp_impl_three_way_comparison", "201907L");
        set_define("__cpp_inheriting_constructors", "201511L");
        set_define("__cpp_init_captures", "201304L");
        set_define("__cpp_lib_is_aggregate", "201703L");
        set_define("__cpp_lib_three_way_comparison", "201907L");
        set_define("__cpp_lambdas", "200907L");
        set_define("__cpp_lib_constexpr_algorithms", "201806L");
        set_define("__cpp_lib_constexpr_complex", "201711L");
        set_define("__cpp_lib_constexpr_dynamic_alloc", "201907L");
        set_define("__cpp_lib_constexpr_functional", "201907L");
        set_define("__cpp_lib_constexpr_iterators", "201811L");
        set_define("__cpp_lib_constexpr_memory", "201811L");
        set_define("__cpp_lib_constexpr_numeric", "201911L");
        set_define("__cpp_lib_constexpr_string", "201907L");
        set_define("__cpp_lib_constexpr_string_view", "201811L");
        set_define("__cpp_lib_constexpr_tuple", "201811L");
        set_define("__cpp_lib_constexpr_utility", "201811L");
        set_define("__cpp_lib_constexpr_variant", "201911L");
        set_define("__cpp_lib_parallel_algorithm", "201703L");
        set_define("__cpp_lib_ranges", "201906L");
        set_define("__cpp_lib_starts_ends_with", "201711L");
        set_define("__cpp_lib_to_array", "201907L");
        set_define("__cpp_lib_type_identity", "201806L");
        set_define("__cpp_lib_unreachable", "202202L");
        set_define("__cpp_lib_structured_bindings", "201606L");
        set_define("__cpp_lib_invoke", "201411L");
        set_define("__cpp_lib_integer_sequence", "201304L");
        set_define("__cpp_lib_make_from_tuple", "201603L");
        set_define("__cpp_lib_apply", "201603L");
        set_define("__cpp_lib_decay", "201304L");
        set_define("__cpp_lib_result_of", "201304L");
        set_define("__cpp_lib_is_null_pointer", "201304L");
        set_define("__cpp_lib_is_invocable", "201703L");
        set_define("__cpp_lib_is_swappable", "201606L");
        set_define("__cpp_lib_barrier", "201907L");
        set_define("__cpp_lib_atomic_ref", "201806L");
        set_define("__cpp_lib_atomic_wait", "201907L");
        set_define("__cpp_lib_atomic_is_always_lock_free", "201603L");
        set_define("__cpp_lib_bit_cast", "201806L");
        set_define("__cpp_lib_bitops", "201907L");
        set_define("__cpp_lib_endian", "201907L");
        set_define("__cpp_lib_has_unique_object_representations", "201606L");
        set_define("__cpp_lib_saturation_arithmetic", "201907L");
        set_define("__cpp_lib_source_location", "201907L");
        set_define("__cpp_lib_void_t", "201411L");
        set_define("__cpp_lib_detector_idiom", "201505L");
        set_define("__cpp_lib_node_handle", "201907L");
        set_define("__cpp_lib_map_try_emplace", "201704L");
        set_define("__cpp_lib_set_contains", "202106L");
        set_define("__cpp_lib_containers_ranges", "202202L");
        set_define("__cpp_lib_generator", "202207L");
        set_define("__cpp_lib_expected", "202211L");
        set_define("__cpp_lib_optional", "202110L");
        set_define("__cpp_lib_variant", "202106L");
        set_define("__cpp_lib_format", "202110L");
        set_define("__cpp_lib_format_ranges", "202207L");
        set_define("__cpp_lib_print", "202207L");
        set_define("__cpp_lib_stacktrace", "202106L");
        set_define("__cpp_lib_coroutine", "201902L");
        set_define("__cpp_lib_jthread", "201911L");
        set_define("__cpp_lib_latch", "201907L");
        set_define("__cpp_lib_semaphore", "201907L");
        set_define("__cpp_lib_atomic_fetch_add", "201907L");
        // MSVC feature test macros
        set_define("__has_char8_t", "1");
        set_define("__cpp_unicode_characters", "201510L");
        set_define("__cpp_unicode_literals", "201510L");
        set_define("__cpp_raw_string_literals", "200809L");
        set_define("__cpp_user_defined_literals", "200809L");
        set_define("__cpp_range_based_for", "201603L");
        set_define("__cpp_static_assert", "200410L");
        set_define("__cpp_threadsafe_static_init", "200806L");
        set_define("__cpp_variadic_templates", "200410L");
        set_define("__cpp_variadic_macros", "200510L");
        set_define("__cpp_return_type_deduction", "201304L");
        set_define("__cpp_nsdmi", "200809L");
        set_define("__cpp_variable_templates", "201304L");
        set_define("__cpp_lib_clamp", "201603L");
        set_define("__cpp_lib_gcd_lcm", "201606L");
        set_define("__cpp_lib_hypot", "201603L");
        set_define("__cpp_lib_is_aligned", "201606L");
        set_define("__cpp_lib_is_constant_evaluated", "201907L");
        set_define("__cpp_lib_assume_aligned", "201811L");
        set_define("__cpp_lib_atomic_shared_ptr", "201711L");
        set_define("__cpp_lib_bad_optional_access", "201606L");
        set_define("__cpp_lib_boyer_moore_searcher", "201603L");
        set_define("__cpp_lib_exchange_function", "201304L");
        set_define("__cpp_lib_hardware_interference_size", "201703L");
        set_define("__cpp_lib_invoke_r", "202106L");
        set_define("__cpp_lib_is_final", "201402L");
        set_define("__cpp_lib_is_nothrow_invocable", "201703L");
        set_define("__cpp_lib_joinable_type_traits", "201606L");
        set_define("__cpp_lib_make_reverse_iterator", "201711L");
        set_define("__cpp_lib_not_fn", "201611L");
        set_define("__cpp_lib_result_of_sfinae", "201210L");
        set_define("__cpp_lib_robust_nonmodular_adl_misuse_detection", "201711L");
        set_define("__cpp_lib_shared_mutex", "201505L");
        set_define("__cpp_lib_shared_timed_mutex", "201402L");
        set_define("__cpp_lib_transformation_trait_aliases", "201304L");
        set_define("__cpp_lib_transparent_operators", "201510L");
        set_define("__cpp_lib_type_trait_variable_templates", "201606L");

        // MSVC extensions
        set_define("_MSC_EXTENSIONS");
        set_define("_MSC_FULL_VER", "190000000");
        set_define("_MSC_BUILD", "1");
        set_define("_MSVC", "1");
        set_define("_M_CEE", "0");
        // NOTE: _M_CEE_PURE must stay UNDEFINED. Real MSVC only defines it
        // under /clr:pure (never for native builds), and SDK headers gate
        // native-only APIs with `#ifndef _M_CEE_PURE` (e.g. GetLastError in
        // errhandlingapi.h). `#ifndef` tests definedness, not value, so a
        // "0" define hides those declarations.
        set_define("_M_CEE_safe", "0");
        set_define("_M_ARX", "0");
        set_define("_M_PPC", "0");
        set_define("_M_IA64", "0");
        set_define("_M_MIPS", "0");
        set_define("_M_SH4", "0");
        set_define("_M_ALPHA", "0");
        set_define("_M_IX86_FP", "2");

        set_define("_CHAR_UNSIGNED");
        set_define("__unaligned", "");
        set_define("__pragma(x)", "");
        set_define("__annotation(x)", "");
        set_define("_Analysis_assume_(x)", "");
        set_define("_GNFFor_(x,y)", "");
        set_define("__in_profile_cs_zone", "");

        // C11/C17 keywords (treated as no-ops in preprocessor context)
        set_define("_Static_assert(x)", "");
        set_define("_Static_assert(x,y)", "");
        set_define("_Alignof(x)", "4");
        set_define("_Alignas(x)", "");
        set_define("_Atomic", "");
        set_define("_Noreturn", "");
        set_define("_Thread_local", "__declspec(thread)");
        set_define("__thread", "__declspec(thread)");
        set_define("_Generic(x,...)", "0");
        set_define("_BitInt(x)", "int");

        // C23 keywords
        set_define("nullptr", "0");
        set_define("constexpr", "");
        set_define("consteval", "");
        set_define("constinit", "");
        set_define("char8_t", "char");
        set_define("char16_t", "unsigned short");
        set_define("char32_t", "unsigned int");

        // GCC/Clang builtins (no-ops for preprocessor)
        set_define("__builtin_offsetof(T,m)", "0");
        set_define("__builtin_types_compatible_p(x,y)", "0");
        set_define("__builtin_choose_expr(c,t,f)", "0");
        set_define("__builtin_constant_p(x)", "0");
        set_define("__builtin_expect(x,y)", "y");
        set_define("__builtin_unreachable()", "");
        set_define("__builtin_assume(x)", "");
        set_define("__attribute__(x)", "");
        set_define("__attribute__(x,y)", "");
        set_define("__has_attribute(x)", "0");
        set_define("__has_builtin(x)", "0");
        set_define("__has_feature(x)", "0");
        set_define("__has_extension(x)", "0");
        set_define("__has_warning(x)", "0");
        set_define("__has_cpp_attribute(x)", "0");
        set_define("__has_include(x)", "1");
        set_define("__has_declspec(x)", "0");

        // Standard types
        set_define("__int8", "char");
        set_define("__int16", "short");
        set_define("__int32", "int");
        set_define("__int64", "long long");
        set_define("__float128", "long double");
        set_define("__clang_cuda_math_forward_declares", "1");

        // Calling conventions
        set_define("APIENTRY", "__stdcall");
        set_define("WINAPI", "__stdcall");
        set_define("WINAPIV", "__cdecl");
        set_define("CALLBACK", "__stdcall");
        set_define("NTAPI", "__stdcall");
        // RPC headers (rpc.h) define these as calling conventions, not types:
        //   #define __RPC_API __stdcall / #define __RPC_USER __stdcall /
        //   #define __RPC_STUB __stdcall / #define RPC_ENTRY __stdcall
        // Without them, 'void * __RPC_USER MIDL_user_allocate(...)' parses
        // __RPC_USER as the return TYPE, seeding a bogus alias class that
        // poisons every projected signature with an unresolvable name.
        set_define("__RPC_API", "__stdcall");
        set_define("__RPC_USER", "__stdcall");
        set_define("__RPC_STUB", "__stdcall");
        set_define("RPC_ENTRY", "__stdcall");
        set_define("__RPC_FAR", "");
        // Obsolete segment/parameter macros the SDK still scatters through
        // declarations (minwindef.h: #define FAR / #define NEAR / #define IN /
        // #define OUT / #define OPTIONAL, all empty). Unexpanded, they leak
        // into signatures as bogus parameter names (`LPMALLOC FAR, void`).
        set_define("FAR", "");
        set_define("NEAR", "");
        set_define("far", "");
        set_define("near", "");
        set_define("IN", "");
        set_define("OUT", "");
        set_define("OPTIONAL", "");
        set_define("PASCAL", "__stdcall");
        set_define("FASTCALL", "__fastcall");
        set_define("FORCEINLINE", "__forceinline");
        set_define("WINFORCEINLINE", "__forceinline");
        set_define("NTAPI_INLINE", "__forceinline __stdcall");
        set_define("STDMETHODCALLTYPE", "__stdcall");
        set_define("STDMETHODVCALLTYPE", "__cdecl");
        set_define("STDAPI", "HRESULT __stdcall");
        set_define("STDAPI_", "HRESULT __stdcall");
        set_define("STDMETHODIMP", "HRESULT __stdcall");
        set_define("STDMETHODIMP_", "HRESULT __stdcall");

        // Declaration macros
        set_define("WINBASEAPI", "__declspec(dllimport)");
        set_define("WINUSERAPI", "__declspec(dllimport)");
        set_define("WINGDIAPI", "__declspec(dllimport)");
        set_define("WINMMAPI", "__declspec(dllimport)");
        set_define("WINADVAPI", "__declspec(dllimport)");
        set_define("WINSOCK_API_LINKAGE", "");
        set_define("WINHTTPAPI", "__declspec(dllimport)");
        set_define("WININETAPI", "__declspec(dllimport)");
        set_define("WINOLEAPI", "__declspec(dllimport)");
        set_define("WINOLEAUTAPI", "__declspec(dllimport)");
        set_define("WINPRIVAPI", "__declspec(dllimport)");
        set_define("OBJECTAPI", "__declspec(dllimport)");
        set_define("SCARDAPI", "__declspec(dllimport)");
        set_define("WINSCARDAPI", "__declspec(dllimport)");
        set_define("SHSTDAPI", "__declspec(dllimport)");
        set_define("SHDOCAPI", "__declspec(dllimport)");
        set_define("COMMCTRLAPI", "__declspec(dllimport)");
        set_define("OLEDBAPI", "__declspec(dllimport)");
        set_define("MIDL_INTERFACE(x)", "struct");

        // SDK subsystem defines
        set_define("APISetsPresent", "1");
        set_define("API_SET_LIMITER", "1");
        set_define("API_SET_NAME", "api-ms-win");
        set_define("_APISET_LIB_VERSION", "0x0201");
        set_define("PC_URLZONESCHEME", "1");
        set_define("_INC_MAC", "1");
        set_define("__cplusplus_cli", "200406L");
        set_define("__crt_initialized", "1");
        set_define("_VCRT_BUILD", "1");
        set_define("_CORECRT_BUILD", "1");
        set_define("VBOX_WITH_PUBLIC_EHAPI", "1");
        set_define("__vboxdebug__", "1");
        set_define("VBOX_WITH_ELF", "1");
        set_define("VBOX_WITH_GDB_SYMS", "1");
        set_define("UNICODE", "1");
        set_define("_UNICODE", "1");
    }

    // Add SDK-specific defines based on version
    void init_sdk_defines(const std::string& version_dir) {
        set_define("WINDOWS_SDK_VERSION", version_dir);
        // Parse major.minor from version_dir like "10.0.26100.0" or "11.0.100.0"
        uint32_t major = 0, minor = 0;
        {
            auto dot1 = version_dir.find('.');
            if (dot1 != std::string::npos) {
                major = static_cast<uint32_t>(std::stoul(version_dir.substr(0, dot1)));
                auto rest = version_dir.substr(dot1 + 1);
                auto dot2 = rest.find('.');
                minor = static_cast<uint32_t>(std::stoul(dot2 != std::string::npos ? rest.substr(0, dot2) : rest));
            }
        }
        (void)major;
    }

private:
    std::vector<std::filesystem::path> include_paths_;
    std::unordered_map<std::string, Define> defines_;

    static std::string_view trim(std::string_view s) {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' || s.front() == '\r'))
            s.remove_prefix(1);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
            s.remove_suffix(1);
        return s;
    }

};

} // namespace wv
