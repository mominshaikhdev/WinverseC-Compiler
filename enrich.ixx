// enrich.ixx - Semantic enrichment: handles, buffers, COM, IOCTL, callbacks, enums
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
module;

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <variant>
#include <thread>

export module winversec.enrich;

import winversec.types;
import winversec.attributes;

export namespace wv {

// Env-gated per-attribute emission trace (WINVERSE_ATTRTRACE=1).
struct AttrTrace {
    std::mutex m;
    std::map<std::string, uint64_t> counts;
};
inline AttrTrace& attr_trace() { static AttrTrace t; return t; }
inline bool attr_trace_enabled()
{
    static const bool on = std::getenv("WINVERSE_ATTRTRACE") != nullptr;
    return on;
}

class Enricher {
public:
    State& st;
    explicit Enricher(State& s) : st(s) {}
    void run();
    void run_parallel(size_t num_threads);
    // Target SDK version (e.g. "10.0.26100") — stamped onto every API as
    // PlatformSupported so projections know the minimum platform build.
    void set_sdk_version(std::string v) { sdk_version_ = std::move(v); }

private:
    std::unordered_map<std::string, attr::HandleKind> handle_map_;
    std::unordered_map<std::string, std::string> dll_map_;
    std::string sdk_version_ = "10.0.26100";

    void init_handle_map();
    void init_dll_map();
    void materialize_ioctl_consts();
    void materialize_irp_mj_consts();
    void init_callback_names();
    std::set<std::string, std::less<>> callback_names_;
    void enrich_type(Item& item);
    // Wires every remaining attribute the pipeline historically left
    // defined-only (architecture, pack, pointer size, close functions,
    // must-check, inline, obsolete, buffer length/type, com method/property/
    // event, guid, type forward, primitive type, constant, partition,
    // platform, contract, feature, variant, driver attributes, ...).
    void enrich_extra(Item& item);
    void detect_enum_flags(TDef& td);
    void detect_ioctl_constants(TDef& td);
    attr::FuncCategory categorize_by_header(const std::string& header);
    void resolve_aw_suffixes();

    size_t aw_stripped_ = 0;
};

// Materialize evaluated CTL_CODE defines into single-member enum items so
// the normal enum path (detect_ioctl_constants) emits IoctlCode /
// IoctlBuffering for them.
inline void Enricher::materialize_ioctl_consts()
{
    std::set<std::string, std::less<>> seen;
    for (auto const& ic : st.ioctl_consts)
    {
        if (!seen.insert(ic.name).second) continue;
        TDef td;
        td.kind = Kind::Enum;
        td.ns = "Windows.Win32.System.IO";
        td.name = ic.name;
        td.attr = TA::Pub;
        td.source_header = "shared/ioctl.h";
        FDef f;
        f.name = ic.name;
        f.attr = FA::Pub | FA::Literal | FA::InitOnly;
        f.type = ET::U4;
        f.def.type = ET::U4;
        f.def.v = ic.value;
        td.fields.push_back(std::move(f));
        st.items.push_back({ std::move(td), Ar::All, "shared/ioctl.h" });
        st.nss.insert("Windows.Win32.System.IO");
    }
}

// IRP major-function codes are `#define IRP_MJ_CREATE 0x00` in wdm.h —
// never enum members — so materialize them as single-member enums; the
// existing IRP_MJ_ enum scan then emits IrpMajorFunction rows carrying
// the real code value.
inline void Enricher::materialize_irp_mj_consts()
{
    std::set<std::string, std::less<>> seen;
    for (auto const& ic : st.irp_mj_consts)
    {
        if (!seen.insert(ic.name).second) continue;
        TDef td;
        td.kind = Kind::Enum;
        td.ns = "Windows.Wdk.Wdm";
        td.name = ic.name;
        td.attr = TA::Pub;
        td.source_header = "km/wdm.h";
        FDef f;
        f.name = ic.name;
        f.attr = FA::Pub | FA::Literal | FA::InitOnly;
        f.type = ET::U4;
        f.def.type = ET::U4;
        f.def.v = ic.value;
        td.fields.push_back(std::move(f));
        st.items.push_back({ std::move(td), Ar::All, "km/wdm.h" });
        st.nss.insert("Windows.Wdk.Wdm");
    }
}

// Callback typedef names (Kind::Delegate / is_callback). A param typed
// with one of these plus an _Opt_ SAL marker is an optional callback —
// the CallbackOptional attribute, which previously required an inline
// fnptr syntax the SDK never uses on parameters.
inline void Enricher::init_callback_names()
{
    for (auto const& item : st.items)
        if (item.def.kind == Kind::Delegate || item.def.is_callback)
            callback_names_.insert(item.def.name);
}

inline void Enricher::run()
{
    init_handle_map();
    init_dll_map();
    init_callback_names();
    materialize_ioctl_consts();
    materialize_irp_mj_consts();
    for (auto& item : st.items)
    {
        enrich_type(item);
    }
    resolve_aw_suffixes();
}

inline void Enricher::run_parallel(size_t num_threads)
{
    init_handle_map();
    init_dll_map();
    init_callback_names();
    materialize_ioctl_consts();
    materialize_irp_mj_consts();
    if (st.items.empty() || num_threads <= 1)
    {
        run();
        return;
    }
    size_t chunk_size = (st.items.size() + num_threads - 1) / num_threads;
    std::vector<std::thread> threads;
    for (size_t t = 0; t < num_threads; ++t)
    {
        size_t start = t * chunk_size;
        size_t end = std::min(start + chunk_size, st.items.size());
        if (start >= st.items.size()) break;
        threads.emplace_back([this, start, end]() {
            for (size_t i = start; i < end; ++i)
            {
                enrich_type(st.items[i]);
            }
        });
    }
    for (auto& th : threads) th.join();
    resolve_aw_suffixes();
    if (attr_trace_enabled())
    {
        auto& tr = attr_trace();
        std::lock_guard<std::mutex> lock(tr.m);
        std::fprintf(stderr, "[attr-trace] per-kind emission counts:\n");
        for (auto const& [name, n] : tr.counts)
            std::fprintf(stderr, "[attr-trace] %-24s %llu\n", name.c_str(), (unsigned long long)n);
    }
}

inline void Enricher::init_handle_map()
{
        handle_map_["HANDLE"] = attr::HandleKind::File;
        handle_map_["HWND"] = attr::HandleKind::Window;
        handle_map_["HKEY"] = attr::HandleKind::Registry;
        handle_map_["HMODULE"] = attr::HandleKind::Memory;
        handle_map_["HINSTANCE"] = attr::HandleKind::Memory;
        handle_map_["HDC"] = attr::HandleKind::DC;
        handle_map_["HBRUSH"] = attr::HandleKind::Brush;
        handle_map_["HFONT"] = attr::HandleKind::Font;
        handle_map_["HPEN"] = attr::HandleKind::Pen;
        handle_map_["HRGN"] = attr::HandleKind::Region;
        handle_map_["HBITMAP"] = attr::HandleKind::Bitmap;
        handle_map_["HICON"] = attr::HandleKind::Icon;
        handle_map_["HCURSOR"] = attr::HandleKind::Cursor;
        handle_map_["HGDIOBJ"] = attr::HandleKind::Memory;
        handle_map_["HMONITOR"] = attr::HandleKind::Monitor;
        handle_map_["HMENU"] = attr::HandleKind::Menu;
        handle_map_["HACCEL"] = attr::HandleKind::AcceleratorTable;
        handle_map_["HPALETTE"] = attr::HandleKind::Palette;
        handle_map_["HMETAFILE"] = attr::HandleKind::MetaFile;
        handle_map_["HENHMETAFILE"] = attr::HandleKind::EnhancedMetaFile;
        handle_map_["HGLRC"] = attr::HandleKind::GLRC;
        handle_map_["HRSRC"] = attr::HandleKind::Find;
        handle_map_["HGLOBAL"] = attr::HandleKind::Memory;
        handle_map_["HLOCAL"] = attr::HandleKind::Memory;
        handle_map_["HDROP"] = attr::HandleKind::File;
        handle_map_["HDEVNOTIFY"] = attr::HandleKind::Memory;
        handle_map_["HPOWERNOTIFY"] = attr::HandleKind::Memory;
        handle_map_["HRAWINPUT"] = attr::HandleKind::Memory;
        handle_map_["HKL"] = attr::HandleKind::Memory;
        handle_map_["HWINSTA"] = attr::HandleKind::WindowStation;
        handle_map_["HDESK"] = attr::HandleKind::Desktop;
        handle_map_["SC_HANDLE"] = attr::HandleKind::Service;
        handle_map_["SERVICE_STATUS_HANDLE"] = attr::HandleKind::Service;
        handle_map_["SOCKET"] = attr::HandleKind::Socket;
        handle_map_["HCRYPTPROV"] = attr::HandleKind::Memory;
        handle_map_["HCRYPTKEY"] = attr::HandleKind::Memory;
        handle_map_["HCRYPTHASH"] = attr::HandleKind::Memory;
        handle_map_["HCERTSTORE"] = attr::HandleKind::Memory;
        handle_map_["HCRYPTMSG"] = attr::HandleKind::Memory;
        handle_map_["BCRYPT_ALG_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["BCRYPT_KEY_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["BCRYPT_HASH_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["BCRYPT_SECRET_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["NCRYPT_KEY_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["NCRYPT_PROV_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["SECURITY_HANDLE"] = attr::HandleKind::Memory;
        handle_map_["CtxtHandle"] = attr::HandleKind::Memory;
        handle_map_["CredHandle"] = attr::HandleKind::Memory;
        handle_map_["HINTERNET"] = attr::HandleKind::Socket;
        handle_map_["HDEVINFO"] = attr::HandleKind::Memory;
        handle_map_["HMMDEVICE"] = attr::HandleKind::Memory;
        handle_map_["HWAVEOUT"] = attr::HandleKind::Memory;
        handle_map_["HWAVEIN"] = attr::HandleKind::Memory;
    }

inline void Enricher::init_dll_map()
    {
        dll_map_["CreateFileW"] = "kernel32.dll";
        dll_map_["CreateFileA"] = "kernel32.dll";
        dll_map_["ReadFile"] = "kernel32.dll";
        dll_map_["WriteFile"] = "kernel32.dll";
        dll_map_["CloseHandle"] = "kernel32.dll";
        dll_map_["GetLastError"] = "kernel32.dll";
        dll_map_["SetLastError"] = "kernel32.dll";
        dll_map_["LoadLibraryW"] = "kernel32.dll";
        dll_map_["LoadLibraryA"] = "kernel32.dll";
        dll_map_["GetProcAddress"] = "kernel32.dll";
        dll_map_["FreeLibrary"] = "kernel32.dll";
        dll_map_["CreateThread"] = "kernel32.dll";
        dll_map_["ExitThread"] = "kernel32.dll";
        dll_map_["WaitForSingleObject"] = "kernel32.dll";
        dll_map_["WaitForMultipleObjects"] = "kernel32.dll";
        dll_map_["CreateEventW"] = "kernel32.dll";
        dll_map_["CreateMutexW"] = "kernel32.dll";
        dll_map_["ReleaseMutex"] = "kernel32.dll";
        dll_map_["VirtualAlloc"] = "kernel32.dll";
        dll_map_["VirtualFree"] = "kernel32.dll";
        dll_map_["VirtualProtect"] = "kernel32.dll";
        dll_map_["GetModuleHandleW"] = "kernel32.dll";
        dll_map_["GetModuleHandleA"] = "kernel32.dll";
        dll_map_["GetModuleFileNameW"] = "kernel32.dll";
        dll_map_["GetModuleFileNameA"] = "kernel32.dll";
        dll_map_["CreateProcessW"] = "kernel32.dll";
        dll_map_["CreateProcessA"] = "kernel32.dll";
        dll_map_["TerminateProcess"] = "kernel32.dll";
        dll_map_["OpenProcess"] = "kernel32.dll";
        dll_map_["GetCurrentProcess"] = "kernel32.dll";
        dll_map_["GetCurrentThreadId"] = "kernel32.dll";
        dll_map_["GetCurrentProcessId"] = "kernel32.dll";
        dll_map_["Sleep"] = "kernel32.dll";
        dll_map_["GetSystemInfo"] = "kernel32.dll";
        dll_map_["GetTickCount64"] = "kernel32.dll";
        dll_map_["QueryPerformanceCounter"] = "kernel32.dll";
        dll_map_["QueryPerformanceFrequency"] = "kernel32.dll";
        dll_map_["GetComputerNameW"] = "kernel32.dll";
        dll_map_["GetComputerNameA"] = "kernel32.dll";
        dll_map_["GetUserNameW"] = "advapi32.dll";
        dll_map_["GetUserNameA"] = "advapi32.dll";
        dll_map_["SuspendThread"] = "kernel32.dll";
        dll_map_["ResumeThread"] = "kernel32.dll";
        dll_map_["TerminateThread"] = "kernel32.dll";
        dll_map_["GetTickCount"] = "kernel32.dll";
        dll_map_["SetEvent"] = "kernel32.dll";
        dll_map_["ResetEvent"] = "kernel32.dll";
        dll_map_["CreateEventA"] = "kernel32.dll";
        dll_map_["CreateFileMappingW"] = "kernel32.dll";
        dll_map_["CreateFileMappingA"] = "kernel32.dll";
        dll_map_["MapViewOfFile"] = "kernel32.dll";
        dll_map_["MapViewOfFileEx"] = "kernel32.dll";
        dll_map_["UnmapViewOfFile"] = "kernel32.dll";
        dll_map_["FlushViewOfFile"] = "kernel32.dll";
        dll_map_["GetFileSize"] = "kernel32.dll";
        dll_map_["GetFileSizeEx"] = "kernel32.dll";
        dll_map_["SetFilePointer"] = "kernel32.dll";
        dll_map_["SetFilePointerEx"] = "kernel32.dll";
        dll_map_["FindFirstFileW"] = "kernel32.dll";
        dll_map_["FindFirstFileA"] = "kernel32.dll";
        dll_map_["FindFirstFileExW"] = "kernel32.dll";
        dll_map_["FindNextFileW"] = "kernel32.dll";
        dll_map_["FindNextFileA"] = "kernel32.dll";
        dll_map_["FindClose"] = "kernel32.dll";
        dll_map_["GetFileAttributesW"] = "kernel32.dll";
        dll_map_["GetFileAttributesA"] = "kernel32.dll";
        dll_map_["SetFileAttributesW"] = "kernel32.dll";
        dll_map_["SetFileAttributesA"] = "kernel32.dll";
        dll_map_["CopyFileW"] = "kernel32.dll";
        dll_map_["CopyFileA"] = "kernel32.dll";
        dll_map_["CopyFileExW"] = "kernel32.dll";
        dll_map_["MoveFileW"] = "kernel32.dll";
        dll_map_["MoveFileA"] = "kernel32.dll";
        dll_map_["MoveFileExW"] = "kernel32.dll";
        dll_map_["DeleteFileW"] = "kernel32.dll";
        dll_map_["DeleteFileA"] = "kernel32.dll";
        dll_map_["CreateDirectoryW"] = "kernel32.dll";
        dll_map_["CreateDirectoryA"] = "kernel32.dll";
        dll_map_["RemoveDirectoryW"] = "kernel32.dll";
        dll_map_["RemoveDirectoryA"] = "kernel32.dll";
        dll_map_["GetCurrentDirectoryW"] = "kernel32.dll";
        dll_map_["SetCurrentDirectoryW"] = "kernel32.dll";
        dll_map_["GetTempPathW"] = "kernel32.dll";
        dll_map_["GetTempPathA"] = "kernel32.dll";
        dll_map_["GetTempFileNameW"] = "kernel32.dll";
        dll_map_["GetTempFileNameA"] = "kernel32.dll";
        dll_map_["GetFullPathNameW"] = "kernel32.dll";
        dll_map_["GetFullPathNameA"] = "kernel32.dll";
        dll_map_["CreatePipe"] = "kernel32.dll";
        dll_map_["GetStdHandle"] = "kernel32.dll";
        dll_map_["SetStdHandle"] = "kernel32.dll";
        dll_map_["ExitProcess"] = "kernel32.dll";
        dll_map_["SetThreadPriority"] = "kernel32.dll";
        dll_map_["GetThreadPriority"] = "kernel32.dll";
        dll_map_["SetThreadAffinityMask"] = "kernel32.dll";
        dll_map_["CreateFiber"] = "kernel32.dll";
        dll_map_["CreateFiberEx"] = "kernel32.dll";
        dll_map_["ConvertThreadToFiber"] = "kernel32.dll";
        dll_map_["ConvertThreadToFiberEx"] = "kernel32.dll";
        dll_map_["ConvertFiberToThread"] = "kernel32.dll";
        dll_map_["SwitchToFiber"] = "kernel32.dll";
        dll_map_["DeleteFiber"] = "kernel32.dll";
        dll_map_["FlsAlloc"] = "kernel32.dll";
        dll_map_["FlsFree"] = "kernel32.dll";
        dll_map_["FlsGetValue"] = "kernel32.dll";
        dll_map_["FlsSetValue"] = "kernel32.dll";
        dll_map_["CreateTimerQueue"] = "kernel32.dll";
        dll_map_["DeleteTimerQueue"] = "kernel32.dll";
        dll_map_["CreateTimerQueueTimer"] = "kernel32.dll";
        dll_map_["DeleteTimerQueueTimer"] = "kernel32.dll";
        dll_map_["ChangeTimerQueueTimer"] = "kernel32.dll";
        dll_map_["CancelIo"] = "kernel32.dll";
        dll_map_["CancelIoEx"] = "kernel32.dll";
        dll_map_["CancelSynchronousIo"] = "kernel32.dll";
        dll_map_["CreateIoCompletionPort"] = "kernel32.dll";
        dll_map_["GetQueuedCompletionStatus"] = "kernel32.dll";
        dll_map_["PostQueuedCompletionStatus"] = "kernel32.dll";
        dll_map_["GetOverlappedResult"] = "kernel32.dll";
        dll_map_["GetOverlappedResultEx"] = "kernel32.dll";
        dll_map_["EncodePointer"] = "kernel32.dll";
        dll_map_["DecodePointer"] = "kernel32.dll";
        dll_map_["GetFinalPathNameByHandleW"] = "kernel32.dll";
        dll_map_["GetFinalPathNameByHandleA"] = "kernel32.dll";
        dll_map_["GetFileInformationByHandle"] = "kernel32.dll";
        dll_map_["SetEndOfFile"] = "kernel32.dll";
        dll_map_["FlushFileBuffers"] = "kernel32.dll";
        dll_map_["LockFile"] = "kernel32.dll";
        dll_map_["UnlockFile"] = "kernel32.dll";
        dll_map_["LockFileEx"] = "kernel32.dll";
        dll_map_["UnlockFileEx"] = "kernel32.dll";
        dll_map_["GetCurrentDirectoryA"] = "kernel32.dll";
        dll_map_["SetCurrentDirectoryA"] = "kernel32.dll";
        dll_map_["GetFileType"] = "kernel32.dll";
        dll_map_["PeekNamedPipe"] = "kernel32.dll";
        dll_map_["GetNamedPipeInfo"] = "kernel32.dll";
        dll_map_["SetNamedPipeHandleState"] = "kernel32.dll";
        dll_map_["ConnectNamedPipe"] = "kernel32.dll";
        dll_map_["DisconnectNamedPipe"] = "kernel32.dll";
        dll_map_["TransactNamedPipe"] = "kernel32.dll";
        dll_map_["CreateNamedPipeW"] = "kernel32.dll";
        dll_map_["CreateNamedPipeA"] = "kernel32.dll";
        dll_map_["ImpersonateNamedPipeClient"] = "kernel32.dll";
        dll_map_["InitializeCriticalSection"] = "kernel32.dll";
        dll_map_["InitializeCriticalSectionAndSpinCount"] = "kernel32.dll";
        dll_map_["EnterCriticalSection"] = "kernel32.dll";
        dll_map_["LeaveCriticalSection"] = "kernel32.dll";
        dll_map_["TryEnterCriticalSection"] = "kernel32.dll";
        dll_map_["DeleteCriticalSection"] = "kernel32.dll";
        dll_map_["InterlockedIncrement"] = "kernel32.dll";
        dll_map_["InterlockedDecrement"] = "kernel32.dll";
        dll_map_["InterlockedExchange"] = "kernel32.dll";
        dll_map_["InterlockedCompareExchange"] = "kernel32.dll";
        dll_map_["HeapCreate"] = "kernel32.dll";
        dll_map_["HeapDestroy"] = "kernel32.dll";
        dll_map_["HeapAlloc"] = "kernel32.dll";
        dll_map_["HeapReAlloc"] = "kernel32.dll";
        dll_map_["HeapFree"] = "kernel32.dll";
        dll_map_["HeapSize"] = "kernel32.dll";
        dll_map_["GetProcessHeap"] = "kernel32.dll";
        dll_map_["GetProcessHeaps"] = "kernel32.dll";
        dll_map_["HeapValidate"] = "kernel32.dll";
        dll_map_["HeapCompact"] = "kernel32.dll";
        dll_map_["HeapLock"] = "kernel32.dll";
        dll_map_["HeapUnlock"] = "kernel32.dll";
        dll_map_["GetStartupInfoW"] = "kernel32.dll";
        dll_map_["GetStartupInfoA"] = "kernel32.dll";
        dll_map_["GetCommandLineW"] = "kernel32.dll";
        dll_map_["GetCommandLineA"] = "kernel32.dll";
        dll_map_["SetDllDirectoryW"] = "kernel32.dll";
        dll_map_["SetDllDirectoryA"] = "kernel32.dll";
        dll_map_["GetDllDirectoryW"] = "kernel32.dll";
        dll_map_["GetDllDirectoryA"] = "kernel32.dll";
        dll_map_["SetEnvironmentVariableW"] = "kernel32.dll";
        dll_map_["SetEnvironmentVariableA"] = "kernel32.dll";
        dll_map_["GetEnvironmentVariableW"] = "kernel32.dll";
        dll_map_["GetEnvironmentVariableA"] = "kernel32.dll";
        dll_map_["ExpandEnvironmentStringsW"] = "kernel32.dll";
        dll_map_["ExpandEnvironmentStringsA"] = "kernel32.dll";
        dll_map_["AllocConsole"] = "kernel32.dll";
        dll_map_["FreeConsole"] = "kernel32.dll";
        dll_map_["AttachConsole"] = "kernel32.dll";
        dll_map_["GetConsoleMode"] = "kernel32.dll";
        dll_map_["SetConsoleMode"] = "kernel32.dll";
        dll_map_["GetConsoleTitleW"] = "kernel32.dll";
        dll_map_["SetConsoleTitleW"] = "kernel32.dll";
        dll_map_["ReadConsoleW"] = "kernel32.dll";
        dll_map_["WriteConsoleW"] = "kernel32.dll";
        dll_map_["ReadConsoleA"] = "kernel32.dll";
        dll_map_["WriteConsoleA"] = "kernel32.dll";
        dll_map_["RegisterClassW"] = "user32.dll";
        dll_map_["RegisterClassA"] = "user32.dll";
        dll_map_["CreateWindowExW"] = "user32.dll";
        dll_map_["CreateWindowExA"] = "user32.dll";
        dll_map_["DestroyWindow"] = "user32.dll";
        dll_map_["DefWindowProcW"] = "user32.dll";
        dll_map_["DefWindowProcA"] = "user32.dll";
        dll_map_["GetMessageW"] = "user32.dll";
        dll_map_["GetMessageA"] = "user32.dll";
        dll_map_["TranslateMessage"] = "user32.dll";
        dll_map_["DispatchMessageW"] = "user32.dll";
        dll_map_["DispatchMessageA"] = "user32.dll";
        dll_map_["PostQuitMessage"] = "user32.dll";
        dll_map_["MessageBoxW"] = "user32.dll";
        dll_map_["MessageBoxA"] = "user32.dll";
        dll_map_["ShowWindow"] = "user32.dll";
        dll_map_["UpdateWindow"] = "user32.dll";
        dll_map_["GetDC"] = "user32.dll";
        dll_map_["ReleaseDC"] = "user32.dll";
        dll_map_["GetWindowDC"] = "user32.dll";
        dll_map_["BeginPaint"] = "user32.dll";
        dll_map_["EndPaint"] = "user32.dll";
        dll_map_["GetClientRect"] = "user32.dll";
        dll_map_["GetWindowRect"] = "user32.dll";
        dll_map_["SetWindowPos"] = "user32.dll";
        dll_map_["SetWindowTextW"] = "user32.dll";
        dll_map_["GetWindowTextW"] = "user32.dll";
        dll_map_["SetTimer"] = "user32.dll";
        dll_map_["KillTimer"] = "user32.dll";
        dll_map_["PostMessageW"] = "user32.dll";
        dll_map_["SendMessageW"] = "user32.dll";
        dll_map_["CallWindowProcW"] = "user32.dll";
        dll_map_["LoadImageW"] = "user32.dll";
        dll_map_["LoadIconW"] = "user32.dll";
        dll_map_["LoadCursorW"] = "user32.dll";
        dll_map_["DestroyIcon"] = "user32.dll";
        dll_map_["DestroyCursor"] = "user32.dll";
        dll_map_["GetSystemMetrics"] = "user32.dll";
        dll_map_["EnumDisplayMonitors"] = "user32.dll";
        dll_map_["GetMonitorInfoW"] = "user32.dll";
        dll_map_["MonitorFromPoint"] = "user32.dll";
        dll_map_["MonitorFromWindow"] = "user32.dll";
        dll_map_["OpenClipboard"] = "user32.dll";
        dll_map_["CloseClipboard"] = "user32.dll";
        dll_map_["GetClipboardData"] = "user32.dll";
        dll_map_["SetClipboardData"] = "user32.dll";
        dll_map_["EmptyClipboard"] = "user32.dll";
        dll_map_["GetClipboardSequenceNumber"] = "user32.dll";
        dll_map_["SetWindowLongW"] = "user32.dll";
        dll_map_["GetWindowLongW"] = "user32.dll";
        dll_map_["SetWindowLongPtrW"] = "user32.dll";
        dll_map_["GetWindowLongPtrW"] = "user32.dll";
        dll_map_["IsWindow"] = "user32.dll";
        dll_map_["IsWindowVisible"] = "user32.dll";
        dll_map_["IsWindowEnabled"] = "user32.dll";
        dll_map_["EnableWindow"] = "user32.dll";
        dll_map_["ShowWindowAsync"] = "user32.dll";
        dll_map_["SetForegroundWindow"] = "user32.dll";
        dll_map_["GetForegroundWindow"] = "user32.dll";
        dll_map_["SetFocus"] = "user32.dll";
        dll_map_["GetFocus"] = "user32.dll";
        dll_map_["GetActiveWindow"] = "user32.dll";
        dll_map_["SetActiveWindow"] = "user32.dll";
        dll_map_["GetKeyState"] = "user32.dll";
        dll_map_["GetAsyncKeyState"] = "user32.dll";
        dll_map_["MapVirtualKeyW"] = "user32.dll";
        dll_map_["ToAscii"] = "user32.dll";
        dll_map_["ToUnicode"] = "user32.dll";
        dll_map_["MessageBeep"] = "user32.dll";
        dll_map_["FlashWindow"] = "user32.dll";
        dll_map_["FlashWindowEx"] = "user32.dll";
        dll_map_["InvalidateRect"] = "user32.dll";
        dll_map_["ValidateRect"] = "user32.dll";
        dll_map_["GetClassLongW"] = "user32.dll";
        dll_map_["SetClassLongW"] = "user32.dll";
        dll_map_["RegisterWindowMessageW"] = "user32.dll";
        dll_map_["GetSystemMenu"] = "user32.dll";
        dll_map_["DrawMenuBar"] = "user32.dll";
        dll_map_["GetMenu"] = "user32.dll";
        dll_map_["SetMenu"] = "user32.dll";
        dll_map_["TrackPopupMenu"] = "user32.dll";
        dll_map_["CheckMenuItem"] = "user32.dll";
        dll_map_["EnableMenuItem"] = "user32.dll";
        dll_map_["AppendMenuW"] = "user32.dll";
        dll_map_["RemoveMenu"] = "user32.dll";
        dll_map_["GetMenuItemInfoW"] = "user32.dll";
        dll_map_["SetMenuItemInfoW"] = "user32.dll";
        dll_map_["CreateMenu"] = "user32.dll";
        dll_map_["CreatePopupMenu"] = "user32.dll";
        dll_map_["DestroyMenu"] = "user32.dll";
        dll_map_["DialogBoxParamW"] = "user32.dll";
        dll_map_["DialogBoxIndirectParamW"] = "user32.dll";
        dll_map_["EndDialog"] = "user32.dll";
        dll_map_["GetDlgItem"] = "user32.dll";
        dll_map_["SetDlgItemTextW"] = "user32.dll";
        dll_map_["GetDlgItemTextW"] = "user32.dll";
        dll_map_["SendDlgItemMessageW"] = "user32.dll";
        dll_map_["CheckDlgButton"] = "user32.dll";
        dll_map_["IsDlgButtonChecked"] = "user32.dll";
        dll_map_["MapDialogRect"] = "user32.dll";
        dll_map_["GetDialogBaseUnits"] = "user32.dll";
        dll_map_["ChildWindowFromPoint"] = "user32.dll";
        dll_map_["RealChildWindowFromPoint"] = "user32.dll";
        dll_map_["FindWindowW"] = "user32.dll";
        dll_map_["FindWindowExW"] = "user32.dll";
        dll_map_["EnumWindows"] = "user32.dll";
        dll_map_["EnumChildWindows"] = "user32.dll";
        dll_map_["GetParent"] = "user32.dll";
        dll_map_["SetParent"] = "user32.dll";
        dll_map_["GetTopWindow"] = "user32.dll";
        dll_map_["GetNextWindow"] = "user32.dll";
        dll_map_["GetWindow"] = "user32.dll";
        dll_map_["GetWindowThreadProcessId"] = "user32.dll";
        dll_map_["IsWindowUnicode"] = "user32.dll";
        dll_map_["IsChild"] = "user32.dll";
        dll_map_["IsIconic"] = "user32.dll";
        dll_map_["IsZoomed"] = "user32.dll";
        dll_map_["ShowOwnedPopups"] = "user32.dll";
        dll_map_["GetLastActivePopup"] = "user32.dll";
        dll_map_["GetWindowPlacement"] = "user32.dll";
        dll_map_["SetWindowPlacement"] = "user32.dll";
        dll_map_["GetWindowDisplayAffinity"] = "user32.dll";
        dll_map_["SetWindowDisplayAffinity"] = "user32.dll";
        dll_map_["AnimateWindow"] = "user32.dll";
        dll_map_["GetLayeredWindowAttributes"] = "user32.dll";
        dll_map_["SetLayeredWindowAttributes"] = "user32.dll";
        dll_map_["UpdateLayeredWindow"] = "user32.dll";
        dll_map_["PrintWindow"] = "user32.dll";
        dll_map_["SetCapture"] = "user32.dll";
        dll_map_["ReleaseCapture"] = "user32.dll";
        dll_map_["GetCapture"] = "user32.dll";
        dll_map_["SetMirrorRgn"] = "user32.dll";
        dll_map_["ClipCursor"] = "user32.dll";
        dll_map_["GetClipCursor"] = "user32.dll";
        dll_map_["GetCursorPos"] = "user32.dll";
        dll_map_["SetCursorPos"] = "user32.dll";
        dll_map_["ClientToScreen"] = "user32.dll";
        dll_map_["ScreenToClient"] = "user32.dll";
        dll_map_["MapWindowPoints"] = "user32.dll";
        dll_map_["WindowFromDC"] = "user32.dll";
        dll_map_["WindowFromPoint"] = "user32.dll";
        dll_map_["ChildWindowFromPointEx"] = "user32.dll";
        dll_map_["GetDCEx"] = "user32.dll";
        dll_map_["LockWindowUpdate"] = "user32.dll";
        dll_map_["RedrawWindow"] = "user32.dll";
        dll_map_["SetBrushOrgEx"] = "user32.dll";
        dll_map_["GetBrushOrgEx"] = "user32.dll";
        dll_map_["FillRect"] = "user32.dll";
        dll_map_["FrameRect"] = "user32.dll";
        dll_map_["InvertRect"] = "user32.dll";
        dll_map_["DrawIcon"] = "user32.dll";
        dll_map_["DrawIconEx"] = "user32.dll";
        dll_map_["DrawTextW"] = "user32.dll";
        dll_map_["DrawTextExW"] = "user32.dll";
        dll_map_["TabbedTextOutW"] = "user32.dll";
        dll_map_["GrayStringW"] = "user32.dll";
        dll_map_["DrawFocusRect"] = "user32.dll";
        dll_map_["ScrollWindow"] = "user32.dll";
        dll_map_["ScrollWindowEx"] = "user32.dll";
        dll_map_["ScrollDC"] = "user32.dll";
        dll_map_["LineScroll"] = "user32.dll";
        dll_map_["GetScrollInfo"] = "user32.dll";
        dll_map_["SetScrollInfo"] = "user32.dll";
        dll_map_["EnableScrollBar"] = "user32.dll";
        dll_map_["ShowScrollBar"] = "user32.dll";
        dll_map_["GetScrollBarRange"] = "user32.dll";
        dll_map_["SetScrollBarRange"] = "user32.dll";
        dll_map_["SystemParametersInfoW"] = "user32.dll";
        dll_map_["SystemParametersInfoForDpi"] = "user32.dll";
        dll_map_["GetDpiForWindow"] = "user32.dll";
        dll_map_["GetDpiForSystem"] = "user32.dll";
        dll_map_["GetSystemDpiForProcess"] = "user32.dll";
        dll_map_["SetProcessDpiAwareness"] = "shcore.dll";
        dll_map_["SetProcessDPIAware"] = "user32.dll";
        dll_map_["IsProcessDpiAware"] = "user32.dll";
        dll_map_["GetWindowDpiAwarenessContext"] = "user32.dll";
        dll_map_["SetProcessDpiAwarenessContext"] = "user32.dll";
        dll_map_["GetAwarenessFromDpiAwarenessContext"] = "user32.dll";
        dll_map_["AreDpiAwarenessContextsEqual"] = "user32.dll";
        dll_map_["GetThreadDpiAwarenessContext"] = "user32.dll";
        dll_map_["SetThreadDpiAwarenessContext"] = "user32.dll";
        dll_map_["GetDialogDpiChangeBehavior"] = "user32.dll";
        dll_map_["SetDialogDpiChangeBehavior"] = "user32.dll";
        dll_map_["GetChildDpiChangeBehavior"] = "user32.dll";
        dll_map_["SetChildDpiChangeBehavior"] = "user32.dll";
        dll_map_["CreateSolidBrush"] = "gdi32.dll";
        dll_map_["CreatePen"] = "gdi32.dll";
        dll_map_["CreateFontIndirectW"] = "gdi32.dll";
        dll_map_["CreateBitmap"] = "gdi32.dll";
        dll_map_["CreateCompatibleDC"] = "gdi32.dll";
        dll_map_["CreateCompatibleBitmap"] = "gdi32.dll";
        dll_map_["DeleteObject"] = "gdi32.dll";
        dll_map_["DeleteDC"] = "gdi32.dll";
        dll_map_["SelectObject"] = "gdi32.dll";
        dll_map_["BitBlt"] = "gdi32.dll";
        dll_map_["StretchBlt"] = "gdi32.dll";
        dll_map_["GetDeviceCaps"] = "gdi32.dll";
        dll_map_["GetTextMetricsW"] = "gdi32.dll";
        dll_map_["GetTextExtentPoint32W"] = "gdi32.dll";
        dll_map_["TextOutW"] = "gdi32.dll";
        dll_map_["Rectangle"] = "gdi32.dll";
        dll_map_["Ellipse"] = "gdi32.dll";
        dll_map_["MoveToEx"] = "gdi32.dll";
        dll_map_["LineTo"] = "gdi32.dll";
        dll_map_["Polyline"] = "gdi32.dll";
        dll_map_["Polygon"] = "gdi32.dll";
        dll_map_["PolyBezier"] = "gdi32.dll";
        dll_map_["CreateBrushIndirect"] = "gdi32.dll";
        dll_map_["CreatePatternBrush"] = "gdi32.dll";
        dll_map_["CreateHatchBrush"] = "gdi32.dll";
        dll_map_["CreateBitmapIndirect"] = "gdi32.dll";
        dll_map_["CreateDIBSection"] = "gdi32.dll";
        dll_map_["CreateDIBitmap"] = "gdi32.dll";
        dll_map_["CreateDiscardableBitmap"] = "gdi32.dll";
        dll_map_["GetStockObject"] = "gdi32.dll";
        dll_map_["CreateFontW"] = "gdi32.dll";
        dll_map_["CreateFontIndirectExW"] = "gdi32.dll";
        dll_map_["GetTextFaceW"] = "gdi32.dll";
        dll_map_["GetTextCharsetInfo"] = "gdi32.dll";
        dll_map_["EnumFontFamiliesExW"] = "gdi32.dll";
        dll_map_["EnumFontFamiliesW"] = "gdi32.dll";
        dll_map_["EnumFontsW"] = "gdi32.dll";
        dll_map_["GetGlyphOutlineW"] = "gdi32.dll";
        dll_map_["GetKerningPairsW"] = "gdi32.dll";
        dll_map_["CreateRectRgn"] = "gdi32.dll";
        dll_map_["CreateRoundRectRgn"] = "gdi32.dll";
        dll_map_["CreateEllipticRgn"] = "gdi32.dll";
        dll_map_["CreatePolygonRgn"] = "gdi32.dll";
        dll_map_["CreatePolyPolygonRgn"] = "gdi32.dll";
        dll_map_["CombineRgn"] = "gdi32.dll";
        dll_map_["EqualRgn"] = "gdi32.dll";
        dll_map_["OffsetRgn"] = "gdi32.dll";
        dll_map_["PtInRegion"] = "gdi32.dll";
        dll_map_["RectInRegion"] = "gdi32.dll";
        dll_map_["GetRgnBox"] = "gdi32.dll";
        dll_map_["FillRgn"] = "gdi32.dll";
        dll_map_["FrameRgn"] = "gdi32.dll";
        dll_map_["InvertRgn"] = "gdi32.dll";
        dll_map_["PaintRgn"] = "gdi32.dll";
        dll_map_["SetViewportOrgEx"] = "gdi32.dll";
        dll_map_["SetWindowOrgEx"] = "gdi32.dll";
        dll_map_["OffsetViewportOrgEx"] = "gdi32.dll";
        dll_map_["OffsetWindowOrgEx"] = "gdi32.dll";
        dll_map_["ScaleViewportExtEx"] = "gdi32.dll";
        dll_map_["ScaleWindowExtEx"] = "gdi32.dll";
        dll_map_["SetViewportExtEx"] = "gdi32.dll";
        dll_map_["SetWindowExtEx"] = "gdi32.dll";
        dll_map_["GetViewportExtEx"] = "gdi32.dll";
        dll_map_["GetWindowExtEx"] = "gdi32.dll";
        dll_map_["GetViewportOrgEx"] = "gdi32.dll";
        dll_map_["GetWindowOrgEx"] = "gdi32.dll";
        dll_map_["SetMapMode"] = "gdi32.dll";
        dll_map_["GetMapMode"] = "gdi32.dll";
        dll_map_["DPtoLP"] = "gdi32.dll";
        dll_map_["LPtoDP"] = "gdi32.dll";
        dll_map_["SaveDC"] = "gdi32.dll";
        dll_map_["RestoreDC"] = "gdi32.dll";
        dll_map_["SetBkColor"] = "gdi32.dll";
        dll_map_["SetTextColor"] = "gdi32.dll";
        dll_map_["GetBkColor"] = "gdi32.dll";
        dll_map_["GetTextColor"] = "gdi32.dll";
        dll_map_["SetBkMode"] = "gdi32.dll";
        dll_map_["GetBkMode"] = "gdi32.dll";
        dll_map_["SetTextAlign"] = "gdi32.dll";
        dll_map_["GetTextAlign"] = "gdi32.dll";
        dll_map_["SetTextCharacterExtra"] = "gdi32.dll";
        dll_map_["GetTextCharacterExtra"] = "gdi32.dll";
        dll_map_["ExtTextOutW"] = "gdi32.dll";
        dll_map_["CreateDCW"] = "gdi32.dll";
        dll_map_["CreateICW"] = "gdi32.dll";
        dll_map_["GetBitmapBits"] = "gdi32.dll";
        dll_map_["SetBitmapBits"] = "gdi32.dll";
        dll_map_["GetBitmapDimensionEx"] = "gdi32.dll";
        dll_map_["SetBitmapDimensionEx"] = "gdi32.dll";
        dll_map_["GetObjectW"] = "gdi32.dll";
        dll_map_["GetObjectType"] = "gdi32.dll";
        dll_map_["GetDIBits"] = "gdi32.dll";
        dll_map_["SetDIBits"] = "gdi32.dll";
        dll_map_["SetDIBitsToDevice"] = "gdi32.dll";
        dll_map_["StretchDIBits"] = "gdi32.dll";
        dll_map_["GetPixel"] = "gdi32.dll";
        dll_map_["SetPixel"] = "gdi32.dll";
        dll_map_["SetPixelV"] = "gdi32.dll";
        dll_map_["FloodFillSymmetric"] = "gdi32.dll";
        dll_map_["ExtFloodFill"] = "gdi32.dll";
        dll_map_["GetRegionData"] = "gdi32.dll";
        dll_map_["ExtCreateRegion"] = "gdi32.dll";
        dll_map_["NtCreateFile"] = "ntdll.dll";
        dll_map_["NtOpenFile"] = "ntdll.dll";
        dll_map_["NtReadFile"] = "ntdll.dll";
        dll_map_["NtWriteFile"] = "ntdll.dll";
        dll_map_["NtClose"] = "ntdll.dll";
        dll_map_["NtQueryInformationFile"] = "ntdll.dll";
        dll_map_["NtSetInformationFile"] = "ntdll.dll";
        dll_map_["NtCreateSection"] = "ntdll.dll";
        dll_map_["NtMapViewOfSection"] = "ntdll.dll";
        dll_map_["NtUnmapViewOfSection"] = "ntdll.dll";
        dll_map_["RtlInitUnicodeString"] = "ntdll.dll";
        dll_map_["RtlInitAnsiString"] = "ntdll.dll";
        dll_map_["RtlFreeUnicodeString"] = "ntdll.dll";
        dll_map_["RtlFreeAnsiString"] = "ntdll.dll";
        dll_map_["RegOpenKeyExW"] = "advapi32.dll";
        dll_map_["RegOpenKeyExA"] = "advapi32.dll";
        dll_map_["RegCloseKey"] = "advapi32.dll";
        dll_map_["RegQueryValueExW"] = "advapi32.dll";
        dll_map_["RegQueryValueExA"] = "advapi32.dll";
        dll_map_["RegSetValueExW"] = "advapi32.dll";
        dll_map_["RegSetValueExA"] = "advapi32.dll";
        dll_map_["RegCreateKeyExW"] = "advapi32.dll";
        dll_map_["RegDeleteKeyW"] = "advapi32.dll";
        dll_map_["RegEnumKeyExW"] = "advapi32.dll";
        dll_map_["RegEnumValueW"] = "advapi32.dll";
        dll_map_["RegDeleteValueW"] = "advapi32.dll";
        dll_map_["RegQueryInfoKeyW"] = "advapi32.dll";
        dll_map_["RegNotifyChangeKeyValue"] = "advapi32.dll";
        dll_map_["OpenSCManagerW"] = "advapi32.dll";
        dll_map_["OpenSCManagerA"] = "advapi32.dll";
        dll_map_["CloseServiceHandle"] = "advapi32.dll";
        dll_map_["OpenServiceW"] = "advapi32.dll";
        dll_map_["OpenServiceA"] = "advapi32.dll";
        dll_map_["CreateServiceW"] = "advapi32.dll";
        dll_map_["CreateServiceA"] = "advapi32.dll";
        dll_map_["DeleteService"] = "advapi32.dll";
        dll_map_["StartServiceW"] = "advapi32.dll";
        dll_map_["StartServiceA"] = "advapi32.dll";
        dll_map_["ControlService"] = "advapi32.dll";
        dll_map_["QueryServiceStatus"] = "advapi32.dll";
        dll_map_["QueryServiceConfigW"] = "advapi32.dll";
        dll_map_["EnumServicesStatusExW"] = "advapi32.dll";
        dll_map_["GetTokenInformation"] = "advapi32.dll";
        dll_map_["OpenProcessToken"] = "advapi32.dll";
        dll_map_["OpenThreadToken"] = "advapi32.dll";
        dll_map_["LookupAccountSidW"] = "advapi32.dll";
        dll_map_["LookupAccountNameW"] = "advapi32.dll";
        dll_map_["ConvertSidToStringSidW"] = "advapi32.dll";
        dll_map_["ConvertStringSidToSidW"] = "advapi32.dll";
        dll_map_["GetLengthSid"] = "advapi32.dll";
        dll_map_["IsValidSid"] = "advapi32.dll";
        dll_map_["EqualSid"] = "advapi32.dll";
        dll_map_["InitializeAcl"] = "advapi32.dll";
        dll_map_["GetAce"] = "advapi32.dll";
        dll_map_["AddAce"] = "advapi32.dll";
        dll_map_["DeleteAce"] = "advapi32.dll";
        dll_map_["AddAccessAllowedAce"] = "advapi32.dll";
        dll_map_["AddAccessDeniedAce"] = "advapi32.dll";
        dll_map_["InitializeSecurityDescriptorW"] = "advapi32.dll";
        dll_map_["SetSecurityDescriptorDacl"] = "advapi32.dll";
        dll_map_["GetSecurityDescriptorDacl"] = "advapi32.dll";
        dll_map_["SetFileSecurityW"] = "advapi32.dll";
        dll_map_["GetFileSecurityW"] = "advapi32.dll";
        dll_map_["AdjustTokenPrivileges"] = "advapi32.dll";
        dll_map_["LookupPrivilegeValueW"] = "advapi32.dll";
        dll_map_["LookupPrivilegeNameW"] = "advapi32.dll";
        dll_map_["ImpersonateSelf"] = "advapi32.dll";
        dll_map_["RevertToSelf"] = "advapi32.dll";
        dll_map_["ShellExecuteW"] = "shell32.dll";
        dll_map_["ShellExecuteA"] = "shell32.dll";
        dll_map_["SHGetFolderPathW"] = "shell32.dll";
        dll_map_["SHGetSpecialFolderPathW"] = "shell32.dll";
        dll_map_["SHGetKnownFolderPath"] = "shell32.dll";
        dll_map_["SHFileOperationW"] = "shell32.dll";
        dll_map_["SHGetFileInfoW"] = "shell32.dll";
        dll_map_["SHGetDesktopFolder"] = "shell32.dll";
        dll_map_["SHGetMalloc"] = "shell32.dll";
        dll_map_["SHCreateItemFromParsingName"] = "shell32.dll";
        dll_map_["SHCreateShellItemArrayFromDataObject"] = "shell32.dll";
        dll_map_["SHCreateMemStream"] = "shell32.dll";
        dll_map_["SHCreateStreamOnFileEx"] = "shell32.dll";
        dll_map_["SHCreateShellItem"] = "shell32.dll";
        dll_map_["WSAStartup"] = "ws2_32.dll";
        dll_map_["WSACleanup"] = "ws2_32.dll";
        dll_map_["socket"] = "ws2_32.dll";
        dll_map_["closesocket"] = "ws2_32.dll";
        dll_map_["bind"] = "ws2_32.dll";
        dll_map_["listen"] = "ws2_32.dll";
        dll_map_["accept"] = "ws2_32.dll";
        dll_map_["connect"] = "ws2_32.dll";
        dll_map_["send"] = "ws2_32.dll";
        dll_map_["recv"] = "ws2_32.dll";
        dll_map_["sendto"] = "ws2_32.dll";
        dll_map_["recvfrom"] = "ws2_32.dll";
        dll_map_["shutdown"] = "ws2_32.dll";
        dll_map_["getpeername"] = "ws2_32.dll";
        dll_map_["getsockname"] = "ws2_32.dll";
        dll_map_["getsockopt"] = "ws2_32.dll";
        dll_map_["setsockopt"] = "ws2_32.dll";
        dll_map_["ioctlsocket"] = "ws2_32.dll";
        dll_map_["WSAGetLastError"] = "ws2_32.dll";
        dll_map_["WSASetLastError"] = "ws2_32.dll";
        dll_map_["select"] = "ws2_32.dll";
        dll_map_["WSASend"] = "ws2_32.dll";
        dll_map_["WSARecv"] = "ws2_32.dll";
        dll_map_["WSASendTo"] = "ws2_32.dll";
        dll_map_["WSARecvFrom"] = "ws2_32.dll";
        dll_map_["WSASocketW"] = "ws2_32.dll";
        dll_map_["WSASocketA"] = "ws2_32.dll";
        dll_map_["WSADuplicateSocketW"] = "ws2_32.dll";
        dll_map_["WSAEventSelect"] = "ws2_32.dll";
        dll_map_["WSACreateEvent"] = "ws2_32.dll";
        dll_map_["WSAResetEvent"] = "ws2_32.dll";
        dll_map_["WSACloseEvent"] = "ws2_32.dll";
        dll_map_["WSAWaitForMultipleEvents"] = "ws2_32.dll";
        dll_map_["WSAEnumNetworkEvents"] = "ws2_32.dll";
        dll_map_["getaddrinfo"] = "ws2_32.dll";
        dll_map_["freeaddrinfo"] = "ws2_32.dll";
        dll_map_["getnameinfo"] = "ws2_32.dll";
        dll_map_["gethostbyname"] = "ws2_32.dll";
        dll_map_["inet_addr"] = "ws2_32.dll";
        dll_map_["inet_ntoa"] = "ws2_32.dll";
        dll_map_["inet_ntop"] = "ws2_32.dll";
        dll_map_["inet_pton"] = "ws2_32.dll";
        dll_map_["htons"] = "ws2_32.dll";
        dll_map_["htonl"] = "ws2_32.dll";
        dll_map_["ntohs"] = "ws2_32.dll";
        dll_map_["ntohl"] = "ws2_32.dll";
        dll_map_["WinHttpOpen"] = "winhttp.dll";
        dll_map_["WinHttpConnect"] = "winhttp.dll";
        dll_map_["WinHttpOpenRequest"] = "winhttp.dll";
        dll_map_["WinHttpSendRequest"] = "winhttp.dll";
        dll_map_["WinHttpReceiveResponse"] = "winhttp.dll";
        dll_map_["WinHttpReadData"] = "winhttp.dll";
        dll_map_["WinHttpCloseHandle"] = "winhttp.dll";
        dll_map_["WinHttpCrackUrl"] = "winhttp.dll";
        dll_map_["WinHttpCreateUrl"] = "winhttp.dll";
        dll_map_["WinHttpSetOption"] = "winhttp.dll";
        dll_map_["WinHttpQueryOption"] = "winhttp.dll";
        dll_map_["WinHttpGetProxyForUrl"] = "winhttp.dll";
        dll_map_["WinHttpSetCredentials"] = "winhttp.dll";
        dll_map_["WinHttpAddRequestHeaders"] = "winhttp.dll";
        dll_map_["WinHttpQueryHeaders"] = "winhttp.dll";
        dll_map_["InternetOpenA"] = "wininet.dll";
        dll_map_["InternetOpenW"] = "wininet.dll";
        dll_map_["InternetConnectA"] = "wininet.dll";
        dll_map_["InternetConnectW"] = "wininet.dll";
        dll_map_["HttpOpenRequestA"] = "wininet.dll";
        dll_map_["HttpOpenRequestW"] = "wininet.dll";
        dll_map_["HttpSendRequestA"] = "wininet.dll";
        dll_map_["HttpSendRequestW"] = "wininet.dll";
        dll_map_["InternetReadFile"] = "wininet.dll";
        dll_map_["InternetCloseHandle"] = "wininet.dll";
        dll_map_["InternetCrackUrlA"] = "wininet.dll";
        dll_map_["InternetCrackUrlW"] = "wininet.dll";
        dll_map_["InternetCreateUrlA"] = "wininet.dll";
        dll_map_["InternetCreateUrlW"] = "wininet.dll";
        dll_map_["InternetQueryOptionA"] = "wininet.dll";
        dll_map_["InternetSetOptionA"] = "wininet.dll";
        dll_map_["InternetQueryOptionW"] = "wininet.dll";
        dll_map_["InternetSetOptionW"] = "wininet.dll";
        dll_map_["HttpAddRequestHeadersA"] = "wininet.dll";
        dll_map_["HttpAddRequestHeadersW"] = "wininet.dll";
        dll_map_["HttpQueryInfoA"] = "wininet.dll";
        dll_map_["HttpQueryInfoW"] = "wininet.dll";
        dll_map_["InternetGetConnectedState"] = "wininet.dll";
        dll_map_["CertOpenStore"] = "crypt32.dll";
        dll_map_["CertFindCertificateInStore"] = "crypt32.dll";
        dll_map_["CertGetCertificateChain"] = "crypt32.dll";
        dll_map_["CertFreeCertificateChain"] = "crypt32.dll";
        dll_map_["CertCloseStore"] = "crypt32.dll";
        dll_map_["CertCreateCertificateContext"] = "crypt32.dll";
        dll_map_["CertGetCertificateContextProperty"] = "crypt32.dll";
        dll_map_["CertSetCertificateContextProperty"] = "crypt32.dll";
        dll_map_["CertDeleteCertificateFromStore"] = "crypt32.dll";
        dll_map_["CertEnumCertificatesInStore"] = "crypt32.dll";
        dll_map_["CertDuplicateCertificateContext"] = "crypt32.dll";
        dll_map_["PFXImportCertStore"] = "crypt32.dll";
        dll_map_["PFXIsPFXBlob"] = "crypt32.dll";
        dll_map_["PFXVerifyPassword"] = "crypt32.dll";
        dll_map_["CryptDecodeObjectEx"] = "crypt32.dll";
        dll_map_["CryptEncodeObjectEx"] = "crypt32.dll";
        dll_map_["CryptMsgOpenToDecode"] = "crypt32.dll";
        dll_map_["CryptMsgUpdate"] = "crypt32.dll";
        dll_map_["CryptMsgGetParam"] = "crypt32.dll";
        dll_map_["CryptMsgClose"] = "crypt32.dll";
        dll_map_["CryptBinaryToStringA"] = "crypt32.dll";
        dll_map_["CryptBinaryToStringW"] = "crypt32.dll";
        dll_map_["CryptStringToBinaryA"] = "crypt32.dll";
        dll_map_["CryptStringToBinaryW"] = "crypt32.dll";
        dll_map_["BCryptOpenAlgorithmProvider"] = "bcrypt.dll";
        dll_map_["BCryptCloseAlgorithmProvider"] = "bcrypt.dll";
        dll_map_["BCryptGenRandom"] = "bcrypt.dll";
        dll_map_["BCryptCreateHash"] = "bcrypt.dll";
        dll_map_["BCryptHashData"] = "bcrypt.dll";
        dll_map_["BCryptFinishHash"] = "bcrypt.dll";
        dll_map_["BCryptDestroyHash"] = "bcrypt.dll";
        dll_map_["BCryptEncrypt"] = "bcrypt.dll";
        dll_map_["BCryptDecrypt"] = "bcrypt.dll";
        dll_map_["BCryptGenerateSymmetricKey"] = "bcrypt.dll";
        dll_map_["BCryptDestroyKey"] = "bcrypt.dll";
        dll_map_["BCryptDeriveKeyPBKDF2"] = "bcrypt.dll";
        dll_map_["BCryptGenerateKeyPair"] = "bcrypt.dll";
        dll_map_["BCryptFinalizeKeyPair"] = "bcrypt.dll";
        dll_map_["BCryptExportKey"] = "bcrypt.dll";
        dll_map_["BCryptImportKey"] = "bcrypt.dll";
        dll_map_["BCryptSignHash"] = "bcrypt.dll";
        dll_map_["BCryptVerifySignature"] = "bcrypt.dll";
        dll_map_["BCryptSecretAgreement"] = "bcrypt.dll";
        dll_map_["BCryptDeriveKey"] = "bcrypt.dll";
        dll_map_["BCryptDestroySecret"] = "bcrypt.dll";
        dll_map_["BCryptHash"] = "bcrypt.dll";
        dll_map_["BCryptImportKeyPair"] = "bcrypt.dll";
        dll_map_["BCryptDestroyKeyPair"] = "bcrypt.dll";
        dll_map_["NCryptOpenStorageProvider"] = "ncrypt.dll";
        dll_map_["NCryptCreatePersistedKey"] = "ncrypt.dll";
        dll_map_["NCryptFinalizeKey"] = "ncrypt.dll";
        dll_map_["NCryptEncrypt"] = "ncrypt.dll";
        dll_map_["NCryptDecrypt"] = "ncrypt.dll";
        dll_map_["NCryptExportKey"] = "ncrypt.dll";
        dll_map_["NCryptImportKey"] = "ncrypt.dll";
        dll_map_["NCryptDeleteKey"] = "ncrypt.dll";
        dll_map_["NCryptFreeObject"] = "ncrypt.dll";
        dll_map_["NCryptEnumAlgorithms"] = "ncrypt.dll";
        dll_map_["NCryptEnumKeys"] = "ncrypt.dll";
        dll_map_["NCryptOpenKey"] = "ncrypt.dll";
        dll_map_["NCryptCopyKey"] = "ncrypt.dll";
        dll_map_["NCryptIsKeyHandle"] = "ncrypt.dll";
        dll_map_["NCryptTranslateHandle"] = "ncrypt.dll";
        dll_map_["NCryptNotifyChangeKey"] = "ncrypt.dll";
        dll_map_["NCryptSignHash"] = "ncrypt.dll";
        dll_map_["NCryptVerifySignature"] = "ncrypt.dll";
        dll_map_["NCryptSecretAgreement"] = "ncrypt.dll";
        dll_map_["NCryptDeriveKey"] = "ncrypt.dll";
        dll_map_["NCryptFreeSecret"] = "ncrypt.dll";
        dll_map_["SetupDiGetClassDevsA"] = "setupapi.dll";
        dll_map_["SetupDiGetClassDevsW"] = "setupapi.dll";
        dll_map_["SetupDiEnumDeviceInfo"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceRegistryPropertyA"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceRegistryPropertyW"] = "setupapi.dll";
        dll_map_["SetupDiCreateDeviceInterfaceA"] = "setupapi.dll";
        dll_map_["SetupDiCreateDeviceInterfaceW"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceInterfaceDetailA"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceInterfaceDetailW"] = "setupapi.dll";
        dll_map_["SetupDiDestroyDeviceInfoList"] = "setupapi.dll";
        dll_map_["GetAdaptersAddresses"] = "iphlpapi.dll";
        dll_map_["GetAdaptersInfo"] = "iphlpapi.dll";
        dll_map_["GetIfEntry"] = "iphlpapi.dll";
        dll_map_["GetIpAddrTable"] = "iphlpapi.dll";
        dll_map_["GetIpNetTable"] = "iphlpapi.dll";
        dll_map_["GetTcpTable"] = "iphlpapi.dll";
        dll_map_["GetUdpTable"] = "iphlpapi.dll";
        dll_map_["NotifyIpInterfaceChange"] = "iphlpapi.dll";
        dll_map_["CancelMibChangeNotifyAddress"] = "iphlpapi.dll";
        dll_map_["DnsQuery_A"] = "dnsapi.dll";
        dll_map_["DnsQuery_W"] = "dnsapi.dll";
        dll_map_["DnsFree"] = "dnsapi.dll";
        dll_map_["GetFileVersionInfoA"] = "version.dll";
        dll_map_["GetFileVersionInfoW"] = "version.dll";
        dll_map_["GetFileVersionInfoSizeA"] = "version.dll";
        dll_map_["GetFileVersionInfoSizeW"] = "version.dll";
        dll_map_["VerQueryValueA"] = "version.dll";
        dll_map_["VerQueryValueW"] = "version.dll";
        dll_map_["StackWalk64"] = "dbghelp.dll";
        dll_map_["SymGetSymFromAddr64"] = "dbghelp.dll";
        dll_map_["SymGetLineFromAddr64"] = "dbghelp.dll";
        dll_map_["SymInitialize"] = "dbghelp.dll";
        dll_map_["SymCleanup"] = "dbghelp.dll";
        dll_map_["MiniDumpWriteDump"] = "dbghelp.dll";
        dll_map_["CoInitialize"] = "ole32.dll";
        dll_map_["CoInitializeEx"] = "ole32.dll";
        dll_map_["CoUninitialize"] = "ole32.dll";
        dll_map_["CoCreateInstance"] = "ole32.dll";
        dll_map_["CoGetClassObject"] = "ole32.dll";
        dll_map_["CoRegisterClassObject"] = "ole32.dll";
        dll_map_["CoRevokeClassObject"] = "ole32.dll";
        dll_map_["CoTaskMemAlloc"] = "ole32.dll";
        dll_map_["CoTaskMemFree"] = "ole32.dll";
        dll_map_["CoTaskMemRealloc"] = "ole32.dll";
        dll_map_["StringFromGUID2"] = "ole32.dll";
        dll_map_["CLSIDFromString"] = "ole32.dll";
        dll_map_["IIDFromString"] = "ole32.dll";
        dll_map_["ProgIDFromCLSID"] = "ole32.dll";
        dll_map_["CLSIDFromProgID"] = "ole32.dll";
        dll_map_["SysAllocString"] = "oleaut32.dll";
        dll_map_["SysFreeString"] = "oleaut32.dll";
        dll_map_["SysStringLen"] = "oleaut32.dll";
        dll_map_["VariantInit"] = "oleaut32.dll";
        dll_map_["VariantClear"] = "oleaut32.dll";
        dll_map_["SafeArrayCreate"] = "oleaut32.dll";
        dll_map_["SafeArrayDestroy"] = "oleaut32.dll";
        dll_map_["SafeArrayGetLBound"] = "oleaut32.dll";
        dll_map_["SafeArrayGetUBound"] = "oleaut32.dll";
        dll_map_["WlanOpenHandle"] = "wlanapi.dll";
        dll_map_["WlanCloseHandle"] = "wlanapi.dll";
        dll_map_["WlanEnumInterfaces"] = "wlanapi.dll";
        dll_map_["WlanQueryInterface"] = "wlanapi.dll";
        dll_map_["WlanSetInterface"] = "wlanapi.dll";
        dll_map_["WlanGetAvailableNetworkList"] = "wlanapi.dll";
        dll_map_["WlanConnect"] = "wlanapi.dll";
        dll_map_["WlanDisconnect"] = "wlanapi.dll";
        dll_map_["WlanScan"] = "wlanapi.dll";
        dll_map_["WlanGetProfile"] = "wlanapi.dll";
        dll_map_["WlanSetProfile"] = "wlanapi.dll";
        dll_map_["wglCreateContext"] = "opengl32.dll";
        dll_map_["wglDeleteContext"] = "opengl32.dll";
        dll_map_["wglMakeCurrent"] = "opengl32.dll";
        dll_map_["wglGetProcAddress"] = "opengl32.dll";
        dll_map_["GetFileAttributesExW"] = "kernel32.dll";
        dll_map_["GetFileAttributesExA"] = "kernel32.dll";
        dll_map_["CopyFileExA"] = "kernel32.dll";
        dll_map_["MoveFileExA"] = "kernel32.dll";
        dll_map_["SearchPathW"] = "kernel32.dll";
        dll_map_["SearchPathA"] = "kernel32.dll";
        dll_map_["GetLongPathNameW"] = "kernel32.dll";
        dll_map_["GetLongPathNameA"] = "kernel32.dll";
        dll_map_["GetShortPathNameW"] = "kernel32.dll";
        dll_map_["GetShortPathNameA"] = "kernel32.dll";
        dll_map_["SetVolumeLabelW"] = "kernel32.dll";
        dll_map_["SetVolumeLabelA"] = "kernel32.dll";
        dll_map_["GetVolumeInformationW"] = "kernel32.dll";
        dll_map_["GetVolumeInformationA"] = "kernel32.dll";
        dll_map_["GetDiskFreeSpaceW"] = "kernel32.dll";
        dll_map_["GetDiskFreeSpaceA"] = "kernel32.dll";
        dll_map_["GetDiskFreeSpaceExW"] = "kernel32.dll";
        dll_map_["GetDiskFreeSpaceExA"] = "kernel32.dll";
        dll_map_["HeapWalk"] = "kernel32.dll";
        dll_map_["EncodeRemotePointer"] = "kernel32.dll";
        dll_map_["DecodeRemotePointer"] = "kernel32.dll";
        dll_map_["SetFileIoOverlappedRange"] = "kernel32.dll";
        dll_map_["RegisterWaitForSingleObject"] = "kernel32.dll";
        dll_map_["UnregisterWait"] = "kernel32.dll";
        dll_map_["QueueUserWorkItem"] = "kernel32.dll";
        dll_map_["CreateSemaphoreW"] = "kernel32.dll";
        dll_map_["CreateSemaphoreA"] = "kernel32.dll";
        dll_map_["ReleaseSemaphore"] = "kernel32.dll";
        dll_map_["CreateWaitableTimerW"] = "kernel32.dll";
        dll_map_["CreateWaitableTimerA"] = "kernel32.dll";
        dll_map_["SetWaitableTimer"] = "kernel32.dll";
        dll_map_["CancelWaitableTimer"] = "kernel32.dll";
        dll_map_["OpenEventW"] = "kernel32.dll";
        dll_map_["OpenEventA"] = "kernel32.dll";
        dll_map_["OpenMutexW"] = "kernel32.dll";
        dll_map_["OpenMutexA"] = "kernel32.dll";
        dll_map_["OpenSemaphoreW"] = "kernel32.dll";
        dll_map_["OpenSemaphoreA"] = "kernel32.dll";
        dll_map_["OpenFileMappingW"] = "kernel32.dll";
        dll_map_["OpenFileMappingA"] = "kernel32.dll";
        dll_map_["IsDebuggerPresent"] = "kernel32.dll";
        dll_map_["OutputDebugStringA"] = "kernel32.dll";
        dll_map_["OutputDebugStringW"] = "kernel32.dll";
        dll_map_["DebugBreak"] = "kernel32.dll";
        dll_map_["RaiseException"] = "kernel32.dll";
        dll_map_["SetUnhandledExceptionFilter"] = "kernel32.dll";
        dll_map_["AddVectoredExceptionHandler"] = "kernel32.dll";
        dll_map_["RemoveVectoredExceptionHandler"] = "kernel32.dll";
        dll_map_["RegCreateKeyExA"] = "advapi32.dll";
        dll_map_["RegDeleteKeyA"] = "advapi32.dll";
        dll_map_["RegDeleteValueA"] = "advapi32.dll";
        dll_map_["RegEnumKeyExA"] = "advapi32.dll";
        dll_map_["RegEnumValueA"] = "advapi32.dll";
        dll_map_["RegFlushKey"] = "advapi32.dll";
        dll_map_["RegGetKeySecurity"] = "advapi32.dll";
        dll_map_["RegSetKeySecurity"] = "advapi32.dll";
        dll_map_["RegLoadKeyW"] = "advapi32.dll";
        dll_map_["RegLoadKeyA"] = "advapi32.dll";
        dll_map_["RegUnLoadKeyW"] = "advapi32.dll";
        dll_map_["RegUnLoadKeyA"] = "advapi32.dll";
        dll_map_["InitiateSystemShutdownExW"] = "advapi32.dll";
        dll_map_["InitiateSystemShutdownExA"] = "advapi32.dll";
        dll_map_["AbortSystemShutdownW"] = "advapi32.dll";
        dll_map_["AbortSystemShutdownA"] = "advapi32.dll";
        dll_map_["LookupAccountSidA"] = "advapi32.dll";
        dll_map_["LookupAccountNameA"] = "advapi32.dll";
        dll_map_["SetTokenInformation"] = "advapi32.dll";
        dll_map_["LookupPrivilegeValueA"] = "advapi32.dll";
        dll_map_["LookupPrivilegeNameA"] = "advapi32.dll";
        dll_map_["AllocateAndInitializeSid"] = "advapi32.dll";
        dll_map_["FreeSid"] = "advapi32.dll";
        dll_map_["CopySid"] = "advapi32.dll";
        dll_map_["SetEntriesInAclA"] = "advapi32.dll";
        dll_map_["SetEntriesInAclW"] = "advapi32.dll";
        dll_map_["GetExplicitEntriesFromAclA"] = "advapi32.dll";
        dll_map_["GetExplicitEntriesFromAclW"] = "advapi32.dll";
        dll_map_["SetSecurityInfo"] = "advapi32.dll";
        dll_map_["GetSecurityInfo"] = "advapi32.dll";
        dll_map_["SetNamedSecurityInfoA"] = "advapi32.dll";
        dll_map_["SetNamedSecurityInfoW"] = "advapi32.dll";
        dll_map_["GetNamedSecurityInfoA"] = "advapi32.dll";
        dll_map_["GetNamedSecurityInfoW"] = "advapi32.dll";
        dll_map_["ConvertStringSecurityDescriptorToSecurityDescriptorA"] = "advapi32.dll";
        dll_map_["ConvertStringSecurityDescriptorToSecurityDescriptorW"] = "advapi32.dll";
        dll_map_["CryptAcquireContextA"] = "advapi32.dll";
        dll_map_["CryptAcquireContextW"] = "advapi32.dll";
        dll_map_["CryptReleaseContext"] = "advapi32.dll";
        dll_map_["CryptGenKey"] = "advapi32.dll";
        dll_map_["CryptDestroyKey"] = "advapi32.dll";
        dll_map_["CryptExportKey"] = "advapi32.dll";
        dll_map_["CryptImportKey"] = "advapi32.dll";
        dll_map_["CryptEncrypt"] = "advapi32.dll";
        dll_map_["CryptDecrypt"] = "advapi32.dll";
        dll_map_["CryptCreateHash"] = "advapi32.dll";
        dll_map_["CryptDestroyHash"] = "advapi32.dll";
        dll_map_["CryptHashData"] = "advapi32.dll";
        dll_map_["CryptGetHashParam"] = "advapi32.dll";
        dll_map_["CryptSetHashParam"] = "advapi32.dll";
        dll_map_["CryptSignHashA"] = "advapi32.dll";
        dll_map_["CryptSignHashW"] = "advapi32.dll";
        dll_map_["OpenEventLogW"] = "advapi32.dll";
        dll_map_["OpenEventLogA"] = "advapi32.dll";
        dll_map_["ReadEventLogW"] = "advapi32.dll";
        dll_map_["ReadEventLogA"] = "advapi32.dll";
        dll_map_["CloseEventLog"] = "advapi32.dll";
        dll_map_["RegisterEventSourceA"] = "advapi32.dll";
        dll_map_["RegisterEventSourceW"] = "advapi32.dll";
        dll_map_["DeregisterEventSource"] = "advapi32.dll";
        dll_map_["ReportEventA"] = "advapi32.dll";
        dll_map_["ReportEventW"] = "advapi32.dll";
        dll_map_["D3D11CreateDevice"] = "d3d11.dll";
        dll_map_["D3D11CreateDeviceAndSwapChain"] = "d3d11.dll";
        dll_map_["D3D12GetDebugInterface"] = "d3d12.dll";
        dll_map_["D3D12EnableExperimentalFeatures"] = "d3d12.dll";
        dll_map_["D3D12CreateDevice"] = "d3d12.dll";
        dll_map_["D3D12GetRemainingStaticCoefficientsPrecision"] = "d3d12.dll";
        dll_map_["CreateDXGIFactory"] = "dxgi.dll";
        dll_map_["CreateDXGIFactory1"] = "dxgi.dll";
        dll_map_["CreateDXGIFactory2"] = "dxgi.dll";
        dll_map_["DXGIGetDebugInterface1"] = "dxgi.dll";
        dll_map_["DXGIDeclareAdapterRemovalSupport"] = "dxgi.dll";
        dll_map_["D2D1CreateFactory"] = "d2d1.dll";
        dll_map_["D2D1CreateDevice"] = "d2d1.dll";
        dll_map_["D2D1MakeRotateTransform"] = "d2d1.dll";
        dll_map_["D2D1MakeSkewTransform"] = "d2d1.dll";
        dll_map_["D2D1MakeMatrixTransform"] = "d2d1.dll";
        dll_map_["D2D1ConvertColorSpace"] = "d2d1.dll";
        dll_map_["DWriteCreateFactory"] = "dwrite.dll";
        dll_map_["DWriteCreateRenderParams"] = "dwrite.dll";
        dll_map_["MFStartup"] = "mfplat.dll";
        dll_map_["MFShutdown"] = "mfplat.dll";
        dll_map_["MFCreateMediaType"] = "mfplat.dll";
        dll_map_["MFCreateMemoryBuffer"] = "mfplat.dll";
        dll_map_["MFCreateSample"] = "mfplat.dll";
        dll_map_["MFCreateEventQueue"] = "mfplat.dll";
        dll_map_["MFTEnumEx"] = "mfplat.dll";
        dll_map_["MFCreateTransformActivatorClassFactory"] = "mfplat.dll";
        dll_map_["InitCommonControlsEx"] = "comctl32.dll";
        dll_map_["InitCommonControls"] = "comctl32.dll";
        dll_map_["ImageList_Create"] = "comctl32.dll";
        dll_map_["ImageList_Destroy"] = "comctl32.dll";
        dll_map_["ImageList_Add"] = "comctl32.dll";
        dll_map_["ImageList_Remove"] = "comctl32.dll";
        dll_map_["ImageList_GetImageCount"] = "comctl32.dll";
        dll_map_["ImageList_Draw"] = "comctl32.dll";
        dll_map_["ImageList_ReplaceIcon"] = "comctl32.dll";
        dll_map_["CreateToolbarEx"] = "comctl32.dll";
        dll_map_["CreateStatusWindowW"] = "comctl32.dll";
        dll_map_["CreateStatusWindowA"] = "comctl32.dll";
        dll_map_["CreateUpDownControl"] = "comctl32.dll";
        dll_map_["GetOpenFileNameA"] = "comdlg32.dll";
        dll_map_["GetOpenFileNameW"] = "comdlg32.dll";
        dll_map_["GetSaveFileNameA"] = "comdlg32.dll";
        dll_map_["GetSaveFileNameW"] = "comdlg32.dll";
        dll_map_["ChooseColorA"] = "comdlg32.dll";
        dll_map_["ChooseColorW"] = "comdlg32.dll";
        dll_map_["ChooseFontA"] = "comdlg32.dll";
        dll_map_["ChooseFontW"] = "comdlg32.dll";
        dll_map_["FindTextA"] = "comdlg32.dll";
        dll_map_["FindTextW"] = "comdlg32.dll";
        dll_map_["ReplaceTextA"] = "comdlg32.dll";
        dll_map_["ReplaceTextW"] = "comdlg32.dll";
        dll_map_["PrintDlgA"] = "comdlg32.dll";
        dll_map_["PrintDlgW"] = "comdlg32.dll";
        dll_map_["PageSetupDlgA"] = "comdlg32.dll";
        dll_map_["PageSetupDlgW"] = "comdlg32.dll";
        dll_map_["PrintDlgExA"] = "comdlg32.dll";
        dll_map_["PrintDlgExW"] = "comdlg32.dll";
        dll_map_["PathAppendW"] = "shlwapi.dll";
        dll_map_["PathAppendA"] = "shlwapi.dll";
        dll_map_["PathCombineW"] = "shlwapi.dll";
        dll_map_["PathCombineA"] = "shlwapi.dll";
        dll_map_["PathFindFileNameW"] = "shlwapi.dll";
        dll_map_["PathFindFileNameA"] = "shlwapi.dll";
        dll_map_["PathRemoveFileSpecW"] = "shlwapi.dll";
        dll_map_["PathRemoveFileSpecA"] = "shlwapi.dll";
        dll_map_["PathFileExistsW"] = "shlwapi.dll";
        dll_map_["PathFileExistsA"] = "shlwapi.dll";
        dll_map_["PathIsDirectoryW"] = "shlwapi.dll";
        dll_map_["PathIsDirectoryA"] = "shlwapi.dll";
        dll_map_["PathCanonicalizeW"] = "shlwapi.dll";
        dll_map_["PathCanonicalizeA"] = "shlwapi.dll";
        dll_map_["PathRelativePathToW"] = "shlwapi.dll";
        dll_map_["PathRelativePathToA"] = "shlwapi.dll";
        dll_map_["PathStripPathW"] = "shlwapi.dll";
        dll_map_["PathStripPathA"] = "shlwapi.dll";
        dll_map_["PathRemoveBlanksW"] = "shlwapi.dll";
        dll_map_["PathRemoveBlanksA"] = "shlwapi.dll";
        dll_map_["PathSkipRootW"] = "shlwapi.dll";
        dll_map_["PathSkipRootA"] = "shlwapi.dll";
        dll_map_["StrCmpW"] = "shlwapi.dll";
        dll_map_["StrCmpA"] = "shlwapi.dll";
        dll_map_["StrCmpIW"] = "shlwapi.dll";
        dll_map_["StrCmpIA"] = "shlwapi.dll";
        dll_map_["StrCmpNW"] = "shlwapi.dll";
        dll_map_["StrCmpNA"] = "shlwapi.dll";
        dll_map_["StrCmpNIW"] = "shlwapi.dll";
        dll_map_["StrCmpNIA"] = "shlwapi.dll";
        dll_map_["StrStrW"] = "shlwapi.dll";
        dll_map_["StrStrA"] = "shlwapi.dll";
        dll_map_["StrStrIW"] = "shlwapi.dll";
        dll_map_["StrStrIA"] = "shlwapi.dll";
        dll_map_["StrStrNW"] = "shlwapi.dll";
        dll_map_["StrStrNA"] = "shlwapi.dll";
        dll_map_["StrStrNIW"] = "shlwapi.dll";
        dll_map_["StrStrNIA"] = "shlwapi.dll";
        dll_map_["StrCchW"] = "shlwapi.dll";
        dll_map_["StrCchA"] = "shlwapi.dll";
        dll_map_["StrCatW"] = "shlwapi.dll";
        dll_map_["StrCatA"] = "shlwapi.dll";
        dll_map_["UrlCombineW"] = "shlwapi.dll";
        dll_map_["UrlCombineA"] = "shlwapi.dll";
        dll_map_["UrlCanonicalizeW"] = "shlwapi.dll";
        dll_map_["UrlCanonicalizeA"] = "shlwapi.dll";
        dll_map_["UrlIsW"] = "shlwapi.dll";
        dll_map_["UrlIsA"] = "shlwapi.dll";
        dll_map_["PropVariantClear"] = "propsys.dll";
        dll_map_["PSPropertyBag_ReadStr"] = "propsys.dll";
        dll_map_["PSPropertyBag_WriteStr"] = "propsys.dll";
        dll_map_["SHCreatePropertyBagOnMemory"] = "propsys.dll";
        dll_map_["PSFormatForDisplay"] = "propsys.dll";
        dll_map_["RpcStringBindingComposeA"] = "rpcrt4.dll";
        dll_map_["RpcStringBindingComposeW"] = "rpcrt4.dll";
        dll_map_["RpcStringBindingParseA"] = "rpcrt4.dll";
        dll_map_["RpcStringBindingParseW"] = "rpcrt4.dll";
        dll_map_["RpcStringFreeA"] = "rpcrt4.dll";
        dll_map_["RpcStringFreeW"] = "rpcrt4.dll";
        dll_map_["RpcBindingFree"] = "rpcrt4.dll";
        dll_map_["RpcBindingFromStringBindingA"] = "rpcrt4.dll";
        dll_map_["RpcBindingFromStringBindingW"] = "rpcrt4.dll";
        dll_map_["RpcEpResolveBinding"] = "rpcrt4.dll";
        dll_map_["RpcMgmtInqServerSocketA"] = "rpcrt4.dll";
        dll_map_["UuidCreate"] = "rpcrt4.dll";
        dll_map_["UuidCreateSequential"] = "rpcrt4.dll";
        dll_map_["UuidToStringA"] = "rpcrt4.dll";
        dll_map_["UuidToStringW"] = "rpcrt4.dll";
        dll_map_["UuidFromStringA"] = "rpcrt4.dll";
        dll_map_["UuidFromStringW"] = "rpcrt4.dll";
        dll_map_["UuidCompare"] = "rpcrt4.dll";
        dll_map_["UuidCreateNil"] = "rpcrt4.dll";
        dll_map_["UuidIsNil"] = "rpcrt4.dll";
        dll_map_["GetUserNameExA"] = "secur32.dll";
        dll_map_["GetUserNameExW"] = "secur32.dll";
        dll_map_["LookupAccountSidLocalA"] = "secur32.dll";
        dll_map_["LookupAccountSidLocalW"] = "secur32.dll";
        dll_map_["GetComputerObjectNameA"] = "secur32.dll";
        dll_map_["GetComputerObjectNameW"] = "secur32.dll";
        dll_map_["CreateEnvironmentBlock"] = "userenv.dll";
        dll_map_["DestroyEnvironmentBlock"] = "userenv.dll";
        dll_map_["ExpandEnvironmentStringsForUserA"] = "userenv.dll";
        dll_map_["ExpandEnvironmentStringsForUserW"] = "userenv.dll";
        dll_map_["GetProfileDirectoryA"] = "userenv.dll";
        dll_map_["GetProfileDirectoryW"] = "userenv.dll";
        dll_map_["GetUserProfileDirectoryA"] = "userenv.dll";
        dll_map_["GetUserProfileDirectoryW"] = "userenv.dll";
        dll_map_["WNetOpenEnumW"] = "mpr.dll";
        dll_map_["WNetOpenEnumA"] = "mpr.dll";
        dll_map_["WNetCloseEnum"] = "mpr.dll";
        dll_map_["WNetEnumResourceW"] = "mpr.dll";
        dll_map_["WNetEnumResourceA"] = "mpr.dll";
        dll_map_["WNetGetConnectionW"] = "mpr.dll";
        dll_map_["WNetGetConnectionA"] = "mpr.dll";
        dll_map_["WNetGetUniversalNameW"] = "mpr.dll";
        dll_map_["WNetGetUniversalNameA"] = "mpr.dll";
        dll_map_["timeGetTime"] = "winmm.dll";
        dll_map_["timeGetSystemTime"] = "winmm.dll";
        dll_map_["timeGetDevCaps"] = "winmm.dll";
        dll_map_["timeBeginPeriod"] = "winmm.dll";
        dll_map_["timeEndPeriod"] = "winmm.dll";
        dll_map_["PlaySoundA"] = "winmm.dll";
        dll_map_["PlaySoundW"] = "winmm.dll";
        dll_map_["mciSendCommandA"] = "winmm.dll";
        dll_map_["mciSendCommandW"] = "winmm.dll";
        dll_map_["mciSendStringA"] = "winmm.dll";
        dll_map_["mciSendStringW"] = "winmm.dll";
        dll_map_["waveOutGetNumDevs"] = "winmm.dll";
        dll_map_["waveInGetNumDevs"] = "winmm.dll";
        dll_map_["joyGetPosEx"] = "winmm.dll";
        dll_map_["joyGetNumDevs"] = "winmm.dll";
        dll_map_["CreateFile2"] = "kernelbase.dll";
        dll_map_["CreateFileFromAppW"] = "kernelbase.dll";
        dll_map_["CreateFileFromAppA"] = "kernelbase.dll";
        dll_map_["CreateEventExW"] = "kernelbase.dll";
        dll_map_["CreateEventExA"] = "kernelbase.dll";
        dll_map_["CreateFileMappingFromApp"] = "kernelbase.dll";
        dll_map_["GetFileInformationByHandleEx"] = "kernel32.dll";
        dll_map_["SetFileInformationByHandle"] = "kernel32.dll";
        dll_map_["DeviceIoControl"] = "kernel32.dll";
        dll_map_["WinVerifyTrustEx"] = "wintrust.dll";
        dll_map_["WinVerifyTrust"] = "wintrust.dll";
        dll_map_["CryptQueryObject"] = "wintrust.dll";
        dll_map_["CM_Get_Device_ID_ListW"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_ID_ListA"] = "cfgmgr32.dll";
        dll_map_["CM_Locate_DevNodeW"] = "cfgmgr32.dll";
        dll_map_["CM_Locate_DevNodeA"] = "cfgmgr32.dll";
        dll_map_["CM_Get_DevNode_Status"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Child"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Sibling"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Parent"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_IDW"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_IDA"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_ID_Size"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Class_PropertyW"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_Interface_ListW"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_Interface_ListA"] = "cfgmgr32.dll";
        dll_map_["CM_Register_Notification"] = "cfgmgr32.dll";
        dll_map_["DnsQueryEx"] = "dnsapi.dll";
        dll_map_["DnsAcquireContextHandle"] = "dnsapi.dll";
        dll_map_["DnsReleaseContextHandle"] = "dnsapi.dll";
        dll_map_["GetIpNetTable2"] = "iphlpapi.dll";
        dll_map_["GetTcpTable2"] = "iphlpapi.dll";
        dll_map_["GetUdp6Table"] = "iphlpapi.dll";
        dll_map_["GetTcp6Table"] = "iphlpapi.dll";
        dll_map_["GetBestRoute"] = "iphlpapi.dll";
        dll_map_["GetBestInterface"] = "iphlpapi.dll";
        dll_map_["GetIfTable"] = "iphlpapi.dll";
        dll_map_["GetIpForwardTable"] = "iphlpapi.dll";
        dll_map_["GetIpForwardTable2"] = "iphlpapi.dll";
        dll_map_["GetUnicastIpAddressEntry"] = "iphlpapi.dll";
        dll_map_["GetUnicastIpAddressTable"] = "iphlpapi.dll";
        dll_map_["GetMulticastIpAddressEntry"] = "iphlpapi.dll";
        dll_map_["GetMulticastIpAddressTable"] = "iphlpapi.dll";
        dll_map_["NotifyRouteChange2"] = "iphlpapi.dll";
        dll_map_["CM_Get_DevNode_Registry_PropertyW"] = "cfgmgr32.dll";
        dll_map_["CM_Get_DevNode_Registry_PropertyA"] = "cfgmgr32.dll";
        dll_map_["CM_Set_DevNode_Registry_PropertyW"] = "cfgmgr32.dll";
        dll_map_["CM_Set_DevNode_Registry_PropertyA"] = "cfgmgr32.dll";
        dll_map_["CM_Disable_DevNode"] = "cfgmgr32.dll";
        dll_map_["CM_Enable_DevNode"] = "cfgmgr32.dll";
        dll_map_["CM_Scan_DevNode_Tree"] = "cfgmgr32.dll";
        dll_map_["Direct3DCreate9"] = "d3d9.dll";
        dll_map_["Direct3DCreate9Ex"] = "d3d9.dll";
        dll_map_["AVEncLibInit"] = "msvproc.dll";
        dll_map_["MFCreateVideoRenderer"] = "mf.dll";
        dll_map_["MFCreateVideoPresenter"] = "mf.dll";
        dll_map_["MFCreateMediaSession"] = "mf.dll";
        dll_map_["MFCreatePMPMediaSession"] = "mf.dll";
        dll_map_["GetDesktopWindow"] = "user32.dll";
        dll_map_["MoveWindow"] = "user32.dll";
        dll_map_["InvalidateRgn"] = "user32.dll";
        dll_map_["ValidateRgn"] = "user32.dll";
        dll_map_["GetUpdateRect"] = "user32.dll";
        dll_map_["GetUpdateRgn"] = "user32.dll";
        dll_map_["PeekMessageA"] = "user32.dll";
        dll_map_["PeekMessageW"] = "user32.dll";
        dll_map_["PostMessageA"] = "user32.dll";
        dll_map_["SendMessageA"] = "user32.dll";
        dll_map_["SendMessageCallbackA"] = "user32.dll";
        dll_map_["SendMessageCallbackW"] = "user32.dll";
        dll_map_["SendDlgItemMessageA"] = "user32.dll";
        dll_map_["DefMDIChildProcA"] = "user32.dll";
        dll_map_["DefMDIChildProcW"] = "user32.dll";
        dll_map_["DefFrameProcA"] = "user32.dll";
        dll_map_["DefFrameProcW"] = "user32.dll";
        dll_map_["TranslateAcceleratorA"] = "user32.dll";
        dll_map_["TranslateAcceleratorW"] = "user32.dll";
        dll_map_["LoadAcceleratorsA"] = "user32.dll";
        dll_map_["LoadAcceleratorsW"] = "user32.dll";
        dll_map_["MapVirtualKeyA"] = "user32.dll";
        dll_map_["GetKeyNameTextA"] = "user32.dll";
        dll_map_["GetKeyNameTextW"] = "user32.dll";
        dll_map_["GetKeyboardState"] = "user32.dll";
        dll_map_["SetKeyboardState"] = "user32.dll";
        dll_map_["GetKeyboardType"] = "user32.dll";
        dll_map_["GetKeyboardLayout"] = "user32.dll";
        dll_map_["LoadKeyboardLayoutA"] = "user32.dll";
        dll_map_["LoadKeyboardLayoutW"] = "user32.dll";
        dll_map_["UnloadKeyboardLayout"] = "user32.dll";
        dll_map_["SetWindowsHookExA"] = "user32.dll";
        dll_map_["SetWindowsHookExW"] = "user32.dll";
        dll_map_["UnhookWindowsHookEx"] = "user32.dll";
        dll_map_["CallNextHookEx"] = "user32.dll";
        dll_map_["MessageBoxExA"] = "user32.dll";
        dll_map_["MessageBoxExW"] = "user32.dll";
        dll_map_["DialogBoxParamA"] = "user32.dll";
        dll_map_["DialogBoxIndirectParamA"] = "user32.dll";
        dll_map_["SetDlgItemTextA"] = "user32.dll";
        dll_map_["GetDlgItemTextA"] = "user32.dll";
        dll_map_["CheckRadioButton"] = "user32.dll";
        dll_map_["GetDlgCtrlID"] = "user32.dll";
        dll_map_["GetNextDlgTabItem"] = "user32.dll";
        dll_map_["GetNextDlgGroupItem"] = "user32.dll";
        dll_map_["GetSysColor"] = "user32.dll";
        dll_map_["SetSysColors"] = "user32.dll";
        dll_map_["SystemParametersInfoA"] = "user32.dll";
        dll_map_["MonitorFromRect"] = "user32.dll";
        dll_map_["GetMonitorInfoA"] = "user32.dll";
        dll_map_["GetWindowLongA"] = "user32.dll";
        dll_map_["SetWindowLongA"] = "user32.dll";
        dll_map_["GetClassLongA"] = "user32.dll";
        dll_map_["SetClassLongA"] = "user32.dll";
        dll_map_["GetClassInfoA"] = "user32.dll";
        dll_map_["GetClassInfoW"] = "user32.dll";
        dll_map_["GetClassInfoExA"] = "user32.dll";
        dll_map_["GetClassInfoExW"] = "user32.dll";
        dll_map_["RegisterClassExA"] = "user32.dll";
        dll_map_["RegisterClassExW"] = "user32.dll";
        dll_map_["UnregisterClassA"] = "user32.dll";
        dll_map_["UnregisterClassW"] = "user32.dll";
        dll_map_["FindAtomA"] = "kernel32.dll";
        dll_map_["FindAtomW"] = "kernel32.dll";
        dll_map_["AddAtomA"] = "kernel32.dll";
        dll_map_["AddAtomW"] = "kernel32.dll";
        dll_map_["DeleteAtom"] = "kernel32.dll";
        dll_map_["GetAtomNameA"] = "kernel32.dll";
        dll_map_["GetAtomNameW"] = "kernel32.dll";
        dll_map_["GlobalAddAtomA"] = "kernel32.dll";
        dll_map_["GlobalAddAtomW"] = "kernel32.dll";
        dll_map_["GlobalDeleteAtom"] = "kernel32.dll";
        dll_map_["GlobalFindAtomA"] = "kernel32.dll";
        dll_map_["GlobalFindAtomW"] = "kernel32.dll";
        dll_map_["GlobalGetAtomNameA"] = "kernel32.dll";
        dll_map_["GlobalGetAtomNameW"] = "kernel32.dll";
        dll_map_["GlobalLock"] = "kernel32.dll";
        dll_map_["GlobalUnlock"] = "kernel32.dll";
        dll_map_["GlobalSize"] = "kernel32.dll";
        dll_map_["GlobalAlloc"] = "kernel32.dll";
        dll_map_["GlobalFree"] = "kernel32.dll";
        dll_map_["GlobalReAlloc"] = "kernel32.dll";
        dll_map_["GlobalWire"] = "kernel32.dll";
        dll_map_["GlobalUnWire"] = "kernel32.dll";
        dll_map_["LocalLock"] = "kernel32.dll";
        dll_map_["LocalUnlock"] = "kernel32.dll";
        dll_map_["LocalSize"] = "kernel32.dll";
        dll_map_["LocalAlloc"] = "kernel32.dll";
        dll_map_["LocalFree"] = "kernel32.dll";
        dll_map_["LocalReAlloc"] = "kernel32.dll";
        dll_map_["TransparentBlt"] = "msimg32.dll";
        dll_map_["AlphaBlend"] = "msimg32.dll";
        dll_map_["MaskBlt"] = "gdi32.dll";
        dll_map_["PlgBlt"] = "gdi32.dll";
        dll_map_["PatBlt"] = "gdi32.dll";
        dll_map_["GetCurrentPositionEx"] = "gdi32.dll";
        dll_map_["RoundRect"] = "gdi32.dll";
        dll_map_["PolyPolygon"] = "gdi32.dll";
        dll_map_["PolyPolyline"] = "gdi32.dll";
        dll_map_["Arc"] = "gdi32.dll";
        dll_map_["ArcTo"] = "gdi32.dll";
        dll_map_["Chord"] = "gdi32.dll";
        dll_map_["Pie"] = "gdi32.dll";
        dll_map_["GetCurrentObject"] = "gdi32.dll";
        dll_map_["CreatePenIndirect"] = "gdi32.dll";
        dll_map_["CreateFontA"] = "gdi32.dll";
        dll_map_["CreateFontIndirectA"] = "gdi32.dll";
        dll_map_["CreateFontIndirectExA"] = "gdi32.dll";
        dll_map_["CreateDCA"] = "gdi32.dll";
        dll_map_["GetTextMetricsA"] = "gdi32.dll";
        dll_map_["GetTextExtentPoint32A"] = "gdi32.dll";
        dll_map_["GetTextExtentExPointA"] = "gdi32.dll";
        dll_map_["GetTextExtentExPointW"] = "gdi32.dll";
        dll_map_["TextOutA"] = "gdi32.dll";
        dll_map_["ExtTextOutA"] = "gdi32.dll";
        dll_map_["TabbedTextOutA"] = "gdi32.dll";
        dll_map_["DrawTextA"] = "user32.dll";
        dll_map_["DrawTextExA"] = "user32.dll";
        dll_map_["DrawEdge"] = "user32.dll";
        dll_map_["DrawFrameControl"] = "user32.dll";
        dll_map_["DrawCaption"] = "user32.dll";
        dll_map_["GetClipBox"] = "gdi32.dll";
        dll_map_["GetClipRgn"] = "gdi32.dll";
        dll_map_["SelectClipRgn"] = "gdi32.dll";
        dll_map_["ExtSelectClipRgn"] = "gdi32.dll";
        dll_map_["OffsetClipRgn"] = "gdi32.dll";
        dll_map_["IntersectClipRect"] = "gdi32.dll";
        dll_map_["ExcludeClipRect"] = "gdi32.dll";
        dll_map_["CreateRectRgnIndirect"] = "gdi32.dll";
        dll_map_["SetROP2"] = "gdi32.dll";
        dll_map_["GetROP2"] = "gdi32.dll";
        dll_map_["SetStretchBltMode"] = "gdi32.dll";
        dll_map_["GetStretchBltMode"] = "gdi32.dll";
        dll_map_["SetPolyFillMode"] = "gdi32.dll";
        dll_map_["GetPolyFillMode"] = "gdi32.dll";
        dll_map_["SetWorldTransform"] = "gdi32.dll";
        dll_map_["GetWorldTransform"] = "gdi32.dll";
        dll_map_["ModifyWorldTransform"] = "gdi32.dll";
        dll_map_["CombineTransform"] = "gdi32.dll";
        dll_map_["GetCharWidthA"] = "gdi32.dll";
        dll_map_["GetCharWidthW"] = "gdi32.dll";
        dll_map_["GetCharWidth32A"] = "gdi32.dll";
        dll_map_["GetCharWidth32W"] = "gdi32.dll";
        dll_map_["GetCharABCWidthsA"] = "gdi32.dll";
        dll_map_["GetCharABCWidthsW"] = "gdi32.dll";
        dll_map_["GetGlyphOutlineA"] = "gdi32.dll";
        dll_map_["CreateFontPackage"] = "fontsub.dll";
        dll_map_["MergeFontFile"] = "fontsub.dll";
        dll_map_["RtlCopyUnicodeString"] = "ntdll.dll";
        dll_map_["RtlCompareUnicodeString"] = "ntdll.dll";
        dll_map_["RtlEqualUnicodeString"] = "ntdll.dll";
        dll_map_["RtlUpcaseUnicodeString"] = "ntdll.dll";
        dll_map_["RtlUnicodeStringToAnsiString"] = "ntdll.dll";
        dll_map_["RtlAnsiStringToUnicodeString"] = "ntdll.dll";
        dll_map_["NtQuerySystemInformation"] = "ntdll.dll";
        dll_map_["NtQueryVirtualMemory"] = "ntdll.dll";
        dll_map_["RtlGetVersion"] = "ntdll.dll";
        dll_map_["RtlVerifyVersionInfo"] = "ntdll.dll";
        dll_map_["RtlGetCallersAddress"] = "ntdll.dll";
        dll_map_["RtlCaptureContext"] = "kernel32.dll";
        dll_map_["RtlLookupFunctionEntry"] = "kernel32.dll";
        dll_map_["RtlVirtualUnwind"] = "kernel32.dll";
        dll_map_["LdrLoadDll"] = "ntdll.dll";
        dll_map_["LdrGetProcedureAddress"] = "ntdll.dll";
        dll_map_["NtAllocateVirtualMemory"] = "ntdll.dll";
        dll_map_["NtFreeVirtualMemory"] = "ntdll.dll";
        dll_map_["NtProtectVirtualMemory"] = "ntdll.dll";
        dll_map_["NtQueryInformationProcess"] = "ntdll.dll";
        dll_map_["NtSetInformationProcess"] = "ntdll.dll";
        dll_map_["NtCreateThread"] = "ntdll.dll";
        dll_map_["NtOpenThread"] = "ntdll.dll";
        dll_map_["NtTerminateThread"] = "ntdll.dll";
        dll_map_["NtSuspendThread"] = "ntdll.dll";
        dll_map_["NtResumeThread"] = "ntdll.dll";
        dll_map_["NtQueryInformationThread"] = "ntdll.dll";
        dll_map_["NtSetInformationThread"] = "ntdll.dll";
        dll_map_["NtOpenSection"] = "ntdll.dll";
        dll_map_["NtOpenMutant"] = "ntdll.dll";
        dll_map_["NtCreateMutant"] = "ntdll.dll";
        dll_map_["NtReleaseMutant"] = "ntdll.dll";
        dll_map_["NtCreateEvent"] = "ntdll.dll";
        dll_map_["NtOpenEvent"] = "ntdll.dll";
        dll_map_["NtSetEvent"] = "ntdll.dll";
        dll_map_["NtClearEvent"] = "ntdll.dll";
        dll_map_["NtWaitForSingleObject"] = "ntdll.dll";
        dll_map_["NtWaitForMultipleObjects"] = "ntdll.dll";
        dll_map_["NtCreateSemaphore"] = "ntdll.dll";
        dll_map_["NtOpenSemaphore"] = "ntdll.dll";
        dll_map_["NtReleaseSemaphore"] = "ntdll.dll";
        dll_map_["NtCreateTimer"] = "ntdll.dll";
        dll_map_["NtOpenTimer"] = "ntdll.dll";
        dll_map_["NtSetTimer"] = "ntdll.dll";
        dll_map_["NtDelayExecution"] = "ntdll.dll";
        dll_map_["NtCreateKey"] = "ntdll.dll";
        dll_map_["NtOpenKey"] = "ntdll.dll";
        dll_map_["NtOpenKeyEx"] = "ntdll.dll";
        dll_map_["NtQueryKey"] = "ntdll.dll";
        dll_map_["NtEnumerateKey"] = "ntdll.dll";
        dll_map_["NtDeleteKey"] = "ntdll.dll";
        dll_map_["NtSetValueKey"] = "ntdll.dll";
        dll_map_["NtQueryValueKey"] = "ntdll.dll";
        dll_map_["NtEnumerateValueKey"] = "ntdll.dll";
        dll_map_["NtDeleteValueKey"] = "ntdll.dll";
        dll_map_["NtFlushKey"] = "ntdll.dll";
        dll_map_["SHGetSpecialFolderPathA"] = "shell32.dll";
        dll_map_["SHGetFolderPathA"] = "shell32.dll";
        dll_map_["SHFree"] = "shell32.dll";
        dll_map_["ShellExecuteExA"] = "shell32.dll";
        dll_map_["ShellExecuteExW"] = "shell32.dll";
        dll_map_["SHFileOperationA"] = "shell32.dll";
        dll_map_["SHBrowseForFolderA"] = "shell32.dll";
        dll_map_["SHBrowseForFolderW"] = "shell32.dll";
        dll_map_["SHGetPathFromIDListA"] = "shell32.dll";
        dll_map_["SHGetPathFromIDListW"] = "shell32.dll";
        dll_map_["Shell_NotifyIconA"] = "shell32.dll";
        dll_map_["Shell_NotifyIconW"] = "shell32.dll";
        dll_map_["DragQueryFileA"] = "shell32.dll";
        dll_map_["DragQueryFileW"] = "shell32.dll";
        dll_map_["DragQueryPoint"] = "shell32.dll";
        dll_map_["DragFinish"] = "shell32.dll";
        dll_map_["DragAcceptFiles"] = "shell32.dll";
        dll_map_["ExtractAssociatedIconA"] = "shell32.dll";
        dll_map_["ExtractAssociatedIconW"] = "shell32.dll";
        dll_map_["ExtractIconA"] = "shell32.dll";
        dll_map_["ExtractIconW"] = "shell32.dll";
        dll_map_["ExtractIconExA"] = "shell32.dll";
        dll_map_["ExtractIconExW"] = "shell32.dll";
        dll_map_["SHGetFileInfoA"] = "shell32.dll";
        dll_map_["SHGetStockIconInfo"] = "shell32.dll";
        dll_map_["SHQueryRecycleBinA"] = "shell32.dll";
        dll_map_["SHQueryRecycleBinW"] = "shell32.dll";
        dll_map_["SHEmptyRecycleBinA"] = "shell32.dll";
        dll_map_["SHEmptyRecycleBinW"] = "shell32.dll";
        dll_map_["SHChangeNotify"] = "shell32.dll";
        dll_map_["PathIsRelativeA"] = "shlwapi.dll";
        dll_map_["PathIsRelativeW"] = "shlwapi.dll";
        dll_map_["PathCompactPathA"] = "shlwapi.dll";
        dll_map_["PathCompactPathW"] = "shlwapi.dll";
        dll_map_["PathQuoteSpacesA"] = "shlwapi.dll";
        dll_map_["PathQuoteSpacesW"] = "shlwapi.dll";
        dll_map_["PathUnquoteSpacesA"] = "shlwapi.dll";
        dll_map_["PathUnquoteSpacesW"] = "shlwapi.dll";
        dll_map_["StrRetToBufA"] = "shlwapi.dll";
        dll_map_["StrRetToBufW"] = "shlwapi.dll";
        dll_map_["StrRetToStrA"] = "shlwapi.dll";
        dll_map_["StrRetToStrW"] = "shlwapi.dll";
        dll_map_["StrChrA"] = "shlwapi.dll";
        dll_map_["StrChrW"] = "shlwapi.dll";
        dll_map_["StrRChrA"] = "shlwapi.dll";
        dll_map_["StrRChrW"] = "shlwapi.dll";
        dll_map_["StrLen"] = "shlwapi.dll";
        dll_map_["StrCpyA"] = "shlwapi.dll";
        dll_map_["StrCpyW"] = "shlwapi.dll";
        dll_map_["StrCatNA"] = "shlwapi.dll";
        dll_map_["StrCatNW"] = "shlwapi.dll";
        dll_map_["PathFindExtensionA"] = "shlwapi.dll";
        dll_map_["PathFindExtensionW"] = "shlwapi.dll";
        dll_map_["PathFindSiblingA"] = "shlwapi.dll";
        dll_map_["PathFindSiblingW"] = "shlwapi.dll";
        dll_map_["PathIsSameRootA"] = "shlwapi.dll";
        dll_map_["PathIsSameRootW"] = "shlwapi.dll";
        dll_map_["PathIsUNCServerA"] = "shlwapi.dll";
        dll_map_["PathIsUNCServerW"] = "shlwapi.dll";
        dll_map_["PathIsUNCServerShareA"] = "shlwapi.dll";
        dll_map_["PathIsUNCServerShareW"] = "shlwapi.dll";
        dll_map_["StackWalk"] = "dbghelp.dll";
        dll_map_["SymGetModuleBase64"] = "dbghelp.dll";
        dll_map_["SymGetSearchPath"] = "dbghelp.dll";
        dll_map_["SymSetSearchPath"] = "dbghelp.dll";
        dll_map_["GetIpStatistics"] = "iphlpapi.dll";
        dll_map_["GetIcmpStatistics"] = "iphlpapi.dll";
        dll_map_["GetNetworkParams"] = "iphlpapi.dll";
        dll_map_["GetDhcpServerAddress"] = "iphlpapi.dll";
        dll_map_["GetIpNetEntry"] = "iphlpapi.dll";
        dll_map_["SetIpNetEntry"] = "iphlpapi.dll";
        dll_map_["DeleteIpNetEntry"] = "iphlpapi.dll";
        dll_map_["FlushIpNetTable"] = "iphlpapi.dll";
        dll_map_["GetTcpEntry"] = "iphlpapi.dll";
        dll_map_["GetUdpEntry"] = "iphlpapi.dll";
        dll_map_["OpenPrinterA"] = "winspool.drv";
        dll_map_["OpenPrinterW"] = "winspool.drv";
        dll_map_["ClosePrinter"] = "winspool.drv";
        dll_map_["DocumentPropertiesA"] = "winspool.drv";
        dll_map_["DocumentPropertiesW"] = "winspool.drv";
        dll_map_["EnumPrintersA"] = "winspool.drv";
        dll_map_["EnumPrintersW"] = "winspool.drv";
        dll_map_["GetPrinterA"] = "winspool.drv";
        dll_map_["GetPrinterW"] = "winspool.drv";
        dll_map_["StartDocPrinterA"] = "winspool.drv";
        dll_map_["StartDocPrinterW"] = "winspool.drv";
        dll_map_["StartPagePrinter"] = "winspool.drv";
        dll_map_["WritePrinter"] = "winspool.drv";
        dll_map_["EndPagePrinter"] = "winspool.drv";
        dll_map_["EndDocPrinter"] = "winspool.drv";
        dll_map_["printf"] = "ucrtbase.dll";
        dll_map_["fprintf"] = "ucrtbase.dll";
        dll_map_["sprintf"] = "ucrtbase.dll";
        dll_map_["sscanf"] = "ucrtbase.dll";
        dll_map_["fopen"] = "ucrtbase.dll";
        dll_map_["fclose"] = "ucrtbase.dll";
        dll_map_["fread"] = "ucrtbase.dll";
        dll_map_["fwrite"] = "ucrtbase.dll";
        dll_map_["fseek"] = "ucrtbase.dll";
        dll_map_["ftell"] = "ucrtbase.dll";
        dll_map_["rewind"] = "ucrtbase.dll";
        dll_map_["fflush"] = "ucrtbase.dll";
        dll_map_["ferror"] = "ucrtbase.dll";
        dll_map_["feof"] = "ucrtbase.dll";
        dll_map_["clearerr"] = "ucrtbase.dll";
        dll_map_["fgetpos"] = "ucrtbase.dll";
        dll_map_["fsetpos"] = "ucrtbase.dll";
        dll_map_["tmpfile"] = "ucrtbase.dll";
        dll_map_["tmpnam"] = "ucrtbase.dll";
        dll_map_["setvbuf"] = "ucrtbase.dll";
        dll_map_["setbuf"] = "ucrtbase.dll";
        dll_map_["ungetc"] = "ucrtbase.dll";
        dll_map_["fgetc"] = "ucrtbase.dll";
        dll_map_["fgets"] = "ucrtbase.dll";
        dll_map_["fputc"] = "ucrtbase.dll";
        dll_map_["fputs"] = "ucrtbase.dll";
        dll_map_["puts"] = "ucrtbase.dll";
        dll_map_["putchar"] = "ucrtbase.dll";
        dll_map_["getchar"] = "ucrtbase.dll";
        dll_map_["gets_s"] = "ucrtbase.dll";
        dll_map_["scanf"] = "ucrtbase.dll";
        dll_map_["fscanf"] = "ucrtbase.dll";
        dll_map_["malloc"] = "ucrtbase.dll";
        dll_map_["calloc"] = "ucrtbase.dll";
        dll_map_["realloc"] = "ucrtbase.dll";
        dll_map_["free"] = "ucrtbase.dll";
        dll_map_["abort"] = "ucrtbase.dll";
        dll_map_["exit"] = "ucrtbase.dll";
        dll_map_["_exit"] = "ucrtbase.dll";
        dll_map_["atexit"] = "ucrtbase.dll";
        dll_map_["at_quick_exit"] = "ucrtbase.dll";
        dll_map_["system"] = "ucrtbase.dll";
        dll_map_["getenv"] = "ucrtbase.dll";
        dll_map_["_dupenv_s"] = "ucrtbase.dll";
        dll_map_["strncpy"] = "ucrtbase.dll";
        dll_map_["strcpy"] = "ucrtbase.dll";
        dll_map_["strcat"] = "ucrtbase.dll";
        dll_map_["strncat"] = "ucrtbase.dll";
        dll_map_["strcmp"] = "ucrtbase.dll";
        dll_map_["strncmp"] = "ucrtbase.dll";
        dll_map_["memcmp"] = "ucrtbase.dll";
        dll_map_["memcpy"] = "ucrtbase.dll";
        dll_map_["memmove"] = "ucrtbase.dll";
        dll_map_["memset"] = "ucrtbase.dll";
        dll_map_["strstr"] = "ucrtbase.dll";
        dll_map_["strchr"] = "ucrtbase.dll";
        dll_map_["strrchr"] = "ucrtbase.dll";
        dll_map_["strtok"] = "ucrtbase.dll";
        dll_map_["strtol"] = "ucrtbase.dll";
        dll_map_["strtoul"] = "ucrtbase.dll";
        dll_map_["strtoll"] = "ucrtbase.dll";
        dll_map_["strtoull"] = "ucrtbase.dll";
        dll_map_["strtod"] = "ucrtbase.dll";
        dll_map_["strtof"] = "ucrtbase.dll";
        dll_map_["abs"] = "ucrtbase.dll";
        dll_map_["labs"] = "ucrtbase.dll";
        dll_map_["llabs"] = "ucrtbase.dll";
        dll_map_["div"] = "ucrtbase.dll";
        dll_map_["ldiv"] = "ucrtbase.dll";
        dll_map_["lldiv"] = "ucrtbase.dll";
        dll_map_["qsort"] = "ucrtbase.dll";
        dll_map_["bsearch"] = "ucrtbase.dll";
        dll_map_["rand"] = "ucrtbase.dll";
        dll_map_["srand"] = "ucrtbase.dll";
        dll_map_["time"] = "ucrtbase.dll";
        dll_map_["localtime"] = "ucrtbase.dll";
        dll_map_["gmtime"] = "ucrtbase.dll";
        dll_map_["mktime"] = "ucrtbase.dll";
        dll_map_["difftime"] = "ucrtbase.dll";
        dll_map_["strftime"] = "ucrtbase.dll";
        dll_map_["_wtoi"] = "ucrtbase.dll";
        dll_map_["_wtol"] = "ucrtbase.dll";
        dll_map_["_wtoll"] = "ucrtbase.dll";
        dll_map_["_wtoi64"] = "ucrtbase.dll";
        dll_map_["isalpha"] = "ucrtbase.dll";
        dll_map_["isalnum"] = "ucrtbase.dll";
        dll_map_["isdigit"] = "ucrtbase.dll";
        dll_map_["isxdigit"] = "ucrtbase.dll";
        dll_map_["isspace"] = "ucrtbase.dll";
        dll_map_["isupper"] = "ucrtbase.dll";
        dll_map_["islower"] = "ucrtbase.dll";
        dll_map_["ispunct"] = "ucrtbase.dll";
        dll_map_["iscntrl"] = "ucrtbase.dll";
        dll_map_["isprint"] = "ucrtbase.dll";
        dll_map_["isgraph"] = "ucrtbase.dll";
        dll_map_["toupper"] = "ucrtbase.dll";
        dll_map_["tolower"] = "ucrtbase.dll";
        dll_map_["SetupDiSetDeviceRegistryPropertyA"] = "setupapi.dll";
        dll_map_["SetupDiSetDeviceRegistryPropertyW"] = "setupapi.dll";
        dll_map_["SetupDiOpenDevRegKey"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceInstanceIdA"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceInstanceIdW"] = "setupapi.dll";
        dll_map_["SetupDiInstallClassA"] = "setupapi.dll";
        dll_map_["SetupDiInstallClassW"] = "setupapi.dll";
        dll_map_["SetupDiCreateDeviceInfoList"] = "setupapi.dll";
        dll_map_["SetupDiCreateDeviceInfoA"] = "setupapi.dll";
        dll_map_["SetupDiCreateDeviceInfoW"] = "setupapi.dll";
        dll_map_["CM_Get_Hardware_Profile_Info_ExA"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Hardware_Profile_Info_ExW"] = "cfgmgr32.dll";
        dll_map_["MFCreateAttributes"] = "mfplat.dll";
        dll_map_["MFCreateMediaSource"] = "mf.dll";
        dll_map_["MFCreateSourceResolver"] = "mf.dll";
        dll_map_["WSAIoctl"] = "ws2_32.dll";
        dll_map_["WSADuplicateSocketA"] = "ws2_32.dll";
        dll_map_["WSAEnumProtocolsA"] = "ws2_32.dll";
        dll_map_["WSAEnumProtocolsW"] = "ws2_32.dll";
        dll_map_["WSAGetQosByName"] = "ws2_32.dll";
        dll_map_["WSAGetOverlappedResult"] = "ws2_32.dll";
        dll_map_["WSACancelBlockingCall"] = "ws2_32.dll";
        dll_map_["WSAIsBlocking"] = "ws2_32.dll";
        dll_map_["WSAUnhookBlockingHook"] = "ws2_32.dll";
        dll_map_["WSASetBlockingHook"] = "ws2_32.dll";
        dll_map_["WSACancelAsyncRequest"] = "ws2_32.dll";
        dll_map_["WSAAsyncSelect"] = "ws2_32.dll";
        dll_map_["WSAAsyncGetHostByName"] = "ws2_32.dll";
        dll_map_["WSAAsyncGetHostByAddr"] = "ws2_32.dll";
        dll_map_["WSAAsyncGetProtoByName"] = "ws2_32.dll";
        dll_map_["WSAAsyncGetProtoByNumber"] = "ws2_32.dll";
        dll_map_["WSAAsyncGetServByName"] = "ws2_32.dll";
        dll_map_["WSAAsyncGetServByPort"] = "ws2_32.dll";
        dll_map_["CertFreeCertificateContext"] = "crypt32.dll";
        dll_map_["CertSelectCertificateChains"] = "crypt32.dll";
        dll_map_["CertVerifyCertificateChainPolicy"] = "crypt32.dll";
        dll_map_["PFXExportCertStoreEx"] = "crypt32.dll";
        dll_map_["NCryptGenerateSymmetricKey"] = "ncrypt.dll";
        dll_map_["NCryptDestroyKey"] = "ncrypt.dll";
        dll_map_["WinHttpSetTimeouts"] = "winhttp.dll";
        dll_map_["WinHttpWriteData"] = "winhttp.dll";
        dll_map_["InternetOpenUrlA"] = "wininet.dll";
        dll_map_["InternetOpenUrlW"] = "wininet.dll";
        dll_map_["InternetWriteFile"] = "wininet.dll";
        dll_map_["InternetAttemptConnect"] = "wininet.dll";
        dll_map_["InternetCheckConnectionA"] = "wininet.dll";
        dll_map_["InternetCheckConnectionW"] = "wininet.dll";
        dll_map_["TranslateNameA"] = "secur32.dll";
        dll_map_["TranslateNameW"] = "secur32.dll";

        // WinRT C API (roapi.h, winstring.h) — combase.dll
        dll_map_["RoInitialize"] = "combase.dll";
        dll_map_["RoUninitialize"] = "combase.dll";
        dll_map_["RoActivateInstance"] = "combase.dll";
        dll_map_["RoGetActivationFactory"] = "combase.dll";
        dll_map_["RoRegisterActivationFactories"] = "combase.dll";
        dll_map_["RoGetActivationFactoryStatic"] = "combase.dll";
        dll_map_["RoGetClassObject"] = "combase.dll";
        dll_map_["RoGetExecutablePath"] = "combase.dll";
        dll_map_["RoResolveServer"] = "combase.dll";
        dll_map_["WindowsCreateString"] = "combase.dll";
        dll_map_["WindowsDeleteString"] = "combase.dll";
        dll_map_["WindowsDuplicateString"] = "combase.dll";
        dll_map_["WindowsGetStringRawBuffer"] = "combase.dll";
        dll_map_["WindowsPreallocateStringBuffer"] = "combase.dll";
        dll_map_["WindowsPromoteStringBuffer"] = "combase.dll";
        dll_map_["WindowsCreateStringReference"] = "combase.dll";
        dll_map_["WindowsIsStringEmpty"] = "combase.dll";
        dll_map_["WindowsCompareStringOrdinal"] = "combase.dll";
        dll_map_["WindowsConcatenateStrings"] = "combase.dll";
        dll_map_["WindowsSubstring"] = "combase.dll";
        dll_map_["WindowsSubstringWithLength"] = "combase.dll";
        dll_map_["WindowsReplaceString"] = "combase.dll";
        dll_map_["WindowsTrimStringStart"] = "combase.dll";
        dll_map_["WindowsTrimStringEnd"] = "combase.dll";
        dll_map_["WindowsAllocateString"] = "combase.dll";
        dll_map_["RoGetMetaDataFile"] = "combase.dll";
        dll_map_["RoParseTypeName"] = "combase.dll";
        dll_map_["RoLookupMetaData"] = "combase.dll";
        dll_map_["RoGetParameterizedTypeInstanceIID"] = "combase.dll";
        dll_map_["RoIsApiContractPresent"] = "combase.dll";
        dll_map_["RoIsActivationFactory"] = "combase.dll";
        dll_map_["DeriveSkillActivationFactoryInterface"] = "combase.dll";
        dll_map_["RoFailFastWithErrorContext"] = "combase.dll";

        // WinRT Foundation
        dll_map_["RoOriginateError"] = "combase.dll";
        dll_map_["RoOriginateErrorW"] = "combase.dll";
        dll_map_["RoClearError"] = "combase.dll";
        dll_map_["RoGetErrorReportBlob"] = "combase.dll";
        dll_map_["RoTransformError"] = "combase.dll";
        dll_map_["RoCaptureErrorContext"] = "combase.dll";
        dll_map_["RoFailFastWithErrorContext"] = "combase.dll";
        dll_map_["RoGetMatchingErrorInfo"] = "combase.dll";
        dll_map_["RoServiceCloseCompletionSourceSharedProcess"] = "combase.dll";

        // Common Win32 DLL APIs not yet mapped
        dll_map_["RegOpenKeyExA"] = "advapi32.dll";
        dll_map_["RegOpenKeyExW"] = "advapi32.dll";
        dll_map_["RegCloseKey"] = "advapi32.dll";
        dll_map_["RegQueryValueExA"] = "advapi32.dll";
        dll_map_["RegQueryValueExW"] = "advapi32.dll";
        dll_map_["RegSetValueExA"] = "advapi32.dll";
        dll_map_["RegSetValueExW"] = "advapi32.dll";
        dll_map_["RegCreateKeyExA"] = "advapi32.dll";
        dll_map_["RegCreateKeyExW"] = "advapi32.dll";
        dll_map_["RegDeleteKeyA"] = "advapi32.dll";
        dll_map_["RegDeleteKeyW"] = "advapi32.dll";
        dll_map_["RegDeleteValueA"] = "advapi32.dll";
        dll_map_["RegDeleteValueW"] = "advapi32.dll";
        dll_map_["RegEnumKeyExA"] = "advapi32.dll";
        dll_map_["RegEnumKeyExW"] = "advapi32.dll";
        dll_map_["RegEnumValueA"] = "advapi32.dll";
        dll_map_["RegEnumValueW"] = "advapi32.dll";
        dll_map_["OpenSCManagerA"] = "advapi32.dll";
        dll_map_["OpenSCManagerW"] = "advapi32.dll";
        dll_map_["OpenServiceA"] = "advapi32.dll";
        dll_map_["OpenServiceW"] = "advapi32.dll";
        dll_map_["CloseServiceHandle"] = "advapi32.dll";
        dll_map_["StartServiceA"] = "advapi32.dll";
        dll_map_["StartServiceW"] = "advapi32.dll";
        dll_map_["ControlService"] = "advapi32.dll";
        dll_map_["QueryServiceStatus"] = "advapi32.dll";
        dll_map_["CreateServiceA"] = "advapi32.dll";
        dll_map_["CreateServiceW"] = "advapi32.dll";
        dll_map_["DeleteService"] = "advapi32.dll";
        dll_map_["GetFileSecurityA"] = "advapi32.dll";
        dll_map_["GetFileSecurityW"] = "advapi32.dll";
        dll_map_["SetFileSecurityA"] = "advapi32.dll";
        dll_map_["SetFileSecurityW"] = "advapi32.dll";
        dll_map_["LookupAccountNameA"] = "advapi32.dll";
        dll_map_["LookupAccountNameW"] = "advapi32.dll";
        dll_map_["LookupAccountSidA"] = "advapi32.dll";
        dll_map_["LookupAccountSidW"] = "advapi32.dll";
        dll_map_["GetTokenInformation"] = "advapi32.dll";
        dll_map_["OpenProcessToken"] = "advapi32.dll";
        dll_map_["AdjustTokenPrivileges"] = "advapi32.dll";
        dll_map_["LookupPrivilegeValueA"] = "advapi32.dll";
        dll_map_["LookupPrivilegeValueW"] = "advapi32.dll";
        dll_map_["InitializeSecurityDescriptor"] = "advapi32.dll";
        dll_map_["SetSecurityDescriptorDacl"] = "advapi32.dll";
        dll_map_["SetSecurityDescriptorOwner"] = "advapi32.dll";
        dll_map_["SetSecurityDescriptorGroup"] = "advapi32.dll";
        dll_map_["ConvertSidToStringSidA"] = "advapi32.dll";
        dll_map_["ConvertSidToStringSidW"] = "advapi32.dll";
        dll_map_["ConvertStringSidToSidA"] = "advapi32.dll";
        dll_map_["ConvertStringSidToSidW"] = "advapi32.dll";
        dll_map_["InitiateSystemShutdownExA"] = "advapi32.dll";
        dll_map_["InitiateSystemShutdownExW"] = "advapi32.dll";
        dll_map_["AbortSystemShutdownA"] = "advapi32.dll";
        dll_map_["AbortSystemShutdownW"] = "advapi32.dll";
        dll_map_["CreatePrivateObjectSecurity"] = "advapi32.dll";
        dll_map_["AccessCheck"] = "advapi32.dll";
        dll_map_["ImpersonateLoggedOnUser"] = "advapi32.dll";
        dll_map_["RevertToSelf"] = "advapi32.dll";
        dll_map_["GetUserNameA"] = "advapi32.dll";
        dll_map_["GetUserNameW"] = "advapi32.dll";

        // setupapi, cfgmgr32, devobj
        dll_map_["SetupDiGetClassDevsA"] = "setupapi.dll";
        dll_map_["SetupDiGetClassDevsW"] = "setupapi.dll";
        dll_map_["SetupDiEnumDeviceInterfaces"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceInterfaceDetailA"] = "setupapi.dll";
        dll_map_["SetupDiGetDeviceInterfaceDetailW"] = "setupapi.dll";
        dll_map_["SetupDiDestroyDeviceInfoList"] = "setupapi.dll";
        dll_map_["SetupDiGetDevicePropertyW"] = "setupapi.dll";
        dll_map_["SetupDiGetDevicePropertyA"] = "setupapi.dll";
        dll_map_["CM_Get_Device_IDW"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_IDA"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Parent"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Child"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Sibling"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_ID_ListW"] = "cfgmgr32.dll";
        dll_map_["CM_Locate_DevNodeW"] = "cfgmgr32.dll";
        dll_map_["CM_Locate_DevNodeA"] = "cfgmgr32.dll";
        dll_map_["CM_Get_DevNode_Status"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Device_Node_Status"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Child_Ex"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Sibling_Ex"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Parent_Ex"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Depth"] = "cfgmgr32.dll";
        dll_map_["CM_Get_Depth_Ex"] = "cfgmgr32.dll";

        // shell32, shlwapi
        dll_map_["SHGetFolderPathA"] = "shell32.dll";
        dll_map_["SHGetFolderPathW"] = "shell32.dll";
        dll_map_["SHGetKnownFolderPath"] = "shell32.dll";
        dll_map_["SHFileOperationA"] = "shell32.dll";
        dll_map_["SHFileOperationW"] = "shell32.dll";
        dll_map_["ShellExecuteA"] = "shell32.dll";
        dll_map_["ShellExecuteW"] = "shell32.dll";
        dll_map_["ShellExecuteExA"] = "shell32.dll";
        dll_map_["ShellExecuteExW"] = "shell32.dll";
        dll_map_["SHGetSpecialFolderPathA"] = "shell32.dll";
        dll_map_["SHGetSpecialFolderPathW"] = "shell32.dll";
        dll_map_["PathAppendA"] = "shlwapi.dll";
        dll_map_["PathAppendW"] = "shlwapi.dll";
        dll_map_["PathCombineA"] = "shlwapi.dll";
        dll_map_["PathCombineW"] = "shlwapi.dll";
        dll_map_["PathFileExistsA"] = "shlwapi.dll";
        dll_map_["PathFileExistsW"] = "shlwapi.dll";
        dll_map_["PathFindFileNameA"] = "shlwapi.dll";
        dll_map_["PathFindFileNameW"] = "shlwapi.dll";
        dll_map_["PathRemoveFileSpecA"] = "shlwapi.dll";
        dll_map_["PathRemoveFileSpecW"] = "shlwapi.dll";
        dll_map_["PathStripPathA"] = "shlwapi.dll";
        dll_map_["PathStripPathW"] = "shlwapi.dll";
        dll_map_["PathCanonicalizeA"] = "shlwapi.dll";
        dll_map_["PathCanonicalizeW"] = "shlwapi.dll";
        dll_map_["PathIsRelativeA"] = "shlwapi.dll";
        dll_map_["PathIsRelativeW"] = "shlwapi.dll";
        dll_map_["StrCmpNA"] = "shlwapi.dll";
        dll_map_["StrCmpNW"] = "shlwapi.dll";
        dll_map_["StrCmpICA"] = "shlwapi.dll";
        dll_map_["StrCmpICW"] = "shlwapi.dll";
        dll_map_["StrStrA"] = "shlwapi.dll";
        dll_map_["StrStrW"] = "shlwapi.dll";
        dll_map_["StrStrIA"] = "shlwapi.dll";
        dll_map_["StrStrIW"] = "shlwapi.dll";

        // iphlpapi
        dll_map_["GetAdaptersAddresses"] = "iphlpapi.dll";
        dll_map_["GetAdaptersInfo"] = "iphlpapi.dll";
        dll_map_["GetBestRoute"] = "iphlpapi.dll";
        dll_map_["GetBestInterface"] = "iphlpapi.dll";
        dll_map_["GetIfTable"] = "iphlpapi.dll";
        dll_map_["GetIpAddrTable"] = "iphlpapi.dll";
        dll_map_["GetIpForwardTable"] = "iphlpapi.dll";
        dll_map_["GetTcpTable"] = "iphlpapi.dll";
        dll_map_["GetUdpTable"] = "iphlpapi.dll";
        dll_map_["GetTcp6Table"] = "iphlpapi.dll";
        dll_map_["GetUdp6Table"] = "iphlpapi.dll";
        dll_map_["NotifyIpInterfaceChange"] = "iphlpapi.dll";
        dll_map_["NotifyRouteChange"] = "iphlpapi.dll";

        // msi
        dll_map_["MsiOpenPackageW"] = "msi.dll";
        dll_map_["MsiOpenPackageA"] = "msi.dll";
        dll_map_["MsiCloseHandle"] = "msi.dll";
        dll_map_["MsiInstallProductW"] = "msi.dll";
        dll_map_["MsiInstallProductA"] = "msi.dll";

        // File I/O
        dll_map_["CreateFile2"] = "kernel32.dll";
        dll_map_["ReadFileEx"] = "kernel32.dll";
        dll_map_["WriteFileEx"] = "kernel32.dll";
        dll_map_["LockFile"] = "kernel32.dll";
        dll_map_["LockFileEx"] = "kernel32.dll";
        dll_map_["UnlockFile"] = "kernel32.dll";
        dll_map_["UnlockFileEx"] = "kernel32.dll";
        dll_map_["GetFileInformationByHandle"] = "kernel32.dll";
        dll_map_["SetEndOfFile"] = "kernel32.dll";
        dll_map_["CancelIo"] = "kernel32.dll";
        dll_map_["CancelIoEx"] = "kernel32.dll";
        dll_map_["CancelSynchronousIo"] = "kernel32.dll";
        dll_map_["GetOverlappedResult"] = "kernel32.dll";
        dll_map_["GetOverlappedResultEx"] = "kernel32.dll";
        dll_map_["CreateIoCompletionPort"] = "kernel32.dll";
        dll_map_["GetQueuedCompletionStatus"] = "kernel32.dll";
        dll_map_["PostQueuedCompletionStatus"] = "kernel32.dll";
        dll_map_["SetFileValidData"] = "kernel32.dll";
        dll_map_["SetFileIoOverlappedRange"] = "kernel32.dll";
        dll_map_["GetFileTime"] = "kernel32.dll";
        dll_map_["SetFileTime"] = "kernel32.dll";
        dll_map_["GetFileType"] = "kernel32.dll";
        dll_map_["DeviceIoControl"] = "kernel32.dll";

        // Thread
        dll_map_["CreateRemoteThread"] = "kernel32.dll";
        dll_map_["CreateRemoteThreadEx"] = "kernel32.dll";
        dll_map_["OpenThread"] = "kernel32.dll";
        dll_map_["GetThreadContext"] = "kernel32.dll";
        dll_map_["SetThreadContext"] = "kernel32.dll";
        dll_map_["GetExitCodeThread"] = "kernel32.dll";
        dll_map_["GetExitCodeProcess"] = "kernel32.dll";
        dll_map_["Thread32First"] = "kernel32.dll";
        dll_map_["Thread32Next"] = "kernel32.dll";
        dll_map_["Process32First"] = "kernel32.dll";
        dll_map_["Process32Next"] = "kernel32.dll";
        dll_map_["CreateToolhelp32Snapshot"] = "kernel32.dll";
        dll_map_["SwitchToThread"] = "kernel32.dll";
        dll_map_["TlsAlloc"] = "kernel32.dll";
        dll_map_["TlsFree"] = "kernel32.dll";
        dll_map_["TlsGetValue"] = "kernel32.dll";
        dll_map_["TlsSetValue"] = "kernel32.dll";
        dll_map_["FlsAlloc"] = "kernel32.dll";
        dll_map_["FlsFree"] = "kernel32.dll";
        dll_map_["FlsGetValue"] = "kernel32.dll";
        dll_map_["FlsSetValue"] = "kernel32.dll";
        dll_map_["InitializeCriticalSectionEx"] = "kernel32.dll";
        dll_map_["InitializeCriticalSectionAndSpinCount"] = "kernel32.dll";
        dll_map_["EnterCriticalSection"] = "kernel32.dll";
        dll_map_["LeaveCriticalSection"] = "kernel32.dll";
        dll_map_["TryEnterCriticalSection"] = "kernel32.dll";
        dll_map_["InitializeSRWLock"] = "kernel32.dll";
        dll_map_["AcquireSRWLockExclusive"] = "kernel32.dll";
        dll_map_["AcquireSRWLockShared"] = "kernel32.dll";
        dll_map_["ReleaseSRWLockExclusive"] = "kernel32.dll";
        dll_map_["ReleaseSRWLockShared"] = "kernel32.dll";
        dll_map_["SleepConditionVariableCS"] = "kernel32.dll";
        dll_map_["SleepConditionVariableSRW"] = "kernel32.dll";
        dll_map_["WakeConditionVariable"] = "kernel32.dll";
        dll_map_["WakeAllConditionVariable"] = "kernel32.dll";
        dll_map_["InitOnceExecuteOnce"] = "kernel32.dll";
        dll_map_["InitOnceBeginInitialize"] = "kernel32.dll";
        dll_map_["InitOnceComplete"] = "kernel32.dll";
        dll_map_["CreateThreadpool"] = "kernel32.dll";
        dll_map_["CreateThreadpoolWork"] = "kernel32.dll";
        dll_map_["SubmitThreadpoolWork"] = "kernel32.dll";
        dll_map_["WaitForThreadpoolWorkCallbacks"] = "kernel32.dll";
        dll_map_["CloseThreadpoolWork"] = "kernel32.dll";
        dll_map_["CreateThreadpoolIo"] = "kernel32.dll";
        dll_map_["StartThreadpoolIo"] = "kernel32.dll";
        dll_map_["CancelThreadpoolIo"] = "kernel32.dll";
        dll_map_["CloseThreadpoolIo"] = "kernel32.dll";
        dll_map_["CreateThreadpoolTimer"] = "kernel32.dll";
        dll_map_["SetThreadpoolTimer"] = "kernel32.dll";
        dll_map_["WaitForThreadpoolTimerCallbacks"] = "kernel32.dll";
        dll_map_["CloseThreadpoolTimer"] = "kernel32.dll";
        dll_map_["CreateThreadpoolWait"] = "kernel32.dll";
        dll_map_["SetThreadpoolWait"] = "kernel32.dll";
        dll_map_["WaitForThreadpoolWaitCallbacks"] = "kernel32.dll";
        dll_map_["CloseThreadpoolWait"] = "kernel32.dll";
        dll_map_["SetThreadpoolCallbackLibrary"] = "kernel32.dll";
        dll_map_["SetThreadpoolCallbackPersistent"] = "kernel32.dll";
        dll_map_["TrySubmitThreadpoolCallback"] = "kernel32.dll";

        // Memory
        dll_map_["VirtualAllocEx"] = "kernel32.dll";
        dll_map_["VirtualFreeEx"] = "kernel32.dll";
        dll_map_["VirtualProtectEx"] = "kernel32.dll";
        dll_map_["ReadProcessMemory"] = "kernel32.dll";
        dll_map_["WriteProcessMemory"] = "kernel32.dll";
        dll_map_["VirtualQuery"] = "kernel32.dll";
        dll_map_["VirtualQueryEx"] = "kernel32.dll";
        dll_map_["HeapAlloc"] = "kernel32.dll";
        dll_map_["HeapFree"] = "kernel32.dll";
        dll_map_["HeapReAlloc"] = "kernel32.dll";
        dll_map_["HeapSize"] = "kernel32.dll";
        dll_map_["HeapCompact"] = "kernel32.dll";
        dll_map_["HeapValidate"] = "kernel32.dll";
        dll_map_["HeapWalk"] = "kernel32.dll";
        dll_map_["Heap32ListFirst"] = "kernel32.dll";
        dll_map_["Heap32ListNext"] = "kernel32.dll";
        dll_map_["Heap32First"] = "kernel32.dll";
        dll_map_["Heap32Next"] = "kernel32.dll";

        // Process
        dll_map_["CreateProcessInternalW"] = "kernel32.dll";
        dll_map_["OpenProcessToken"] = "advapi32.dll";
        dll_map_["DuplicateHandle"] = "kernel32.dll";
        dll_map_["IsProcessInJob"] = "kernel32.dll";
        dll_map_["CreateJobObjectW"] = "kernel32.dll";
        dll_map_["AssignProcessToJobObject"] = "kernel32.dll";
        dll_map_["SetInformationJobObject"] = "kernel32.dll";
        dll_map_["QueryInformationJobObject"] = "kernel32.dll";
        dll_map_["TerminateJobObject"] = "kernel32.dll";

        // Synchronization
        dll_map_["WaitForSingleObjectEx"] = "kernel32.dll";
        dll_map_["WaitForMultipleObjectsEx"] = "kernel32.dll";
        dll_map_["SignalObjectAndWait"] = "kernel32.dll";
        dll_map_["CreateEventExW"] = "kernel32.dll";
        dll_map_["CreateEventExA"] = "kernel32.dll";
        dll_map_["CreateMutexExW"] = "kernel32.dll";
        dll_map_["CreateMutexExA"] = "kernel32.dll";
        dll_map_["CreateSemaphoreExW"] = "kernel32.dll";
        dll_map_["CreateSemaphoreExA"] = "kernel32.dll";
        dll_map_["OpenEventW"] = "kernel32.dll";
        dll_map_["OpenEventA"] = "kernel32.dll";
        dll_map_["OpenMutexW"] = "kernel32.dll";
        dll_map_["OpenMutexA"] = "kernel32.dll";
        dll_map_["OpenSemaphoreW"] = "kernel32.dll";
        dll_map_["OpenSemaphoreA"] = "kernel32.dll";

        // Pipe/Mailslot
        dll_map_["CreateNamedPipeW"] = "kernel32.dll";
        dll_map_["CreateNamedPipeA"] = "kernel32.dll";
        dll_map_["ConnectNamedPipe"] = "kernel32.dll";
        dll_map_["DisconnectNamedPipe"] = "kernel32.dll";
        dll_map_["PeekNamedPipe"] = "kernel32.dll";
        dll_map_["TransactNamedPipe"] = "kernel32.dll";
        dll_map_["GetNamedPipeHandleState"] = "kernel32.dll";
        dll_map_["SetNamedPipeHandleState"] = "kernel32.dll";
        dll_map_["GetNamedPipeInfo"] = "kernel32.dll";
        dll_map_["GetNamedPipeClientProcessId"] = "kernel32.dll";
        dll_map_["GetNamedPipeServerProcessId"] = "kernel32.dll";
        dll_map_["CreateMailslotW"] = "kernel32.dll";
        dll_map_["CreateMailslotA"] = "kernel32.dll";
        dll_map_["GetMailslotInfo"] = "kernel32.dll";
        dll_map_["SetMailslotInfo"] = "kernel32.dll";

        // Environment
        dll_map_["GetEnvironmentStrings"] = "kernel32.dll";
        dll_map_["FreeEnvironmentStrings"] = "kernel32.dll";
        dll_map_["GetEnvironmentVariableW"] = "kernel32.dll";
        dll_map_["GetEnvironmentVariableA"] = "kernel32.dll";
        dll_map_["SetEnvironmentVariableW"] = "kernel32.dll";
        dll_map_["SetEnvironmentVariableA"] = "kernel32.dll";
        dll_map_["ExpandEnvironmentStringsW"] = "kernel32.dll";
        dll_map_["ExpandEnvironmentStringsA"] = "kernel32.dll";

        // Module/Library
        dll_map_["GetModuleHandleExW"] = "kernel32.dll";
        dll_map_["GetModuleHandleExA"] = "kernel32.dll";
        dll_map_["GetModuleFileNameExA"] = "kernel32.dll";
        dll_map_["GetModuleFileNameExW"] = "kernel32.dll";
        dll_map_["LoadLibraryExW"] = "kernel32.dll";
        dll_map_["LoadLibraryExA"] = "kernel32.dll";
        dll_map_["LoadPackagedLibrary"] = "kernel32.dll";
        dll_map_["GetProcAddress"] = "kernel32.dll";
        dll_map_["FreeLibraryAndExitThread"] = "kernel32.dll";
        dll_map_["DisableThreadLibraryCalls"] = "kernel32.dll";

        // Debug
        dll_map_["OutputDebugStringA"] = "kernel32.dll";
        dll_map_["OutputDebugStringW"] = "kernel32.dll";
        dll_map_["OutputDebugStringExA"] = "kernel32.dll";
        dll_map_["OutputDebugStringExW"] = "kernel32.dll";
        dll_map_["IsDebuggerPresent"] = "kernel32.dll";
        dll_map_["CheckRemoteDebuggerPresent"] = "kernel32.dll";
        dll_map_["WaitForDebugEvent"] = "kernel32.dll";
        dll_map_["ContinueDebugEvent"] = "kernel32.dll";
        dll_map_["DebugActiveProcess"] = "kernel32.dll";
        dll_map_["DebugActiveProcessStop"] = "kernel32.dll";
        dll_map_["DebugBreak"] = "kernel32.dll";
        dll_map_["DebugBreakProcess"] = "kernel32.dll";
        dll_map_["SetDebugErrorLevel"] = "kernel32.dll";

        // Error handling
        dll_map_["FormatMessageA"] = "kernel32.dll";
        dll_map_["FormatMessageW"] = "kernel32.dll";
        dll_map_["GetThreadLocale"] = "kernel32.dll";
        dll_map_["SetThreadLocale"] = "kernel32.dll";
        dll_map_["GetUserDefaultLCID"] = "kernel32.dll";
        dll_map_["GetSystemDefaultLCID"] = "kernel32.dll";
        dll_map_["IsValidLocale"] = "kernel32.dll";
        dll_map_["CompareStringA"] = "kernel32.dll";
        dll_map_["CompareStringW"] = "kernel32.dll";
        dll_map_["CompareStringOrdinal"] = "kernel32.dll";
        dll_map_["LCMapStringA"] = "kernel32.dll";
        dll_map_["LCMapStringW"] = "kernel32.dll";
        dll_map_["GetLocaleInfoA"] = "kernel32.dll";
        dll_map_["GetLocaleInfoW"] = "kernel32.dll";
        dll_map_["SetLocaleInfoA"] = "kernel32.dll";
        dll_map_["SetLocaleInfoW"] = "kernel32.dll";

        // Cryptography
        dll_map_["CryptAcquireContextA"] = "advapi32.dll";
        dll_map_["CryptAcquireContextW"] = "advapi32.dll";
        dll_map_["CryptReleaseContext"] = "advapi32.dll";
        dll_map_["CryptGenRandom"] = "advapi32.dll";
        dll_map_["CryptImportKey"] = "advapi32.dll";
        dll_map_["CryptExportKey"] = "advapi32.dll";
        dll_map_["CryptEncrypt"] = "advapi32.dll";
        dll_map_["CryptDecrypt"] = "advapi32.dll";
        dll_map_["CryptDestroyKey"] = "advapi32.dll";
        dll_map_["CryptCreateHash"] = "advapi32.dll";
        dll_map_["CryptHashData"] = "advapi32.dll";
        dll_map_["CryptGetHashParam"] = "advapi32.dll";
        dll_map_["CryptDestroyHash"] = "advapi32.dll";
        dll_map_["CryptDeriveKey"] = "advapi32.dll";
        dll_map_["CryptSetKeyParam"] = "advapi32.dll";
        dll_map_["CryptGetKeyParam"] = "advapi32.dll";
        dll_map_["CryptGenKey"] = "advapi32.dll";

        // Timer
        dll_map_["QueryPerformanceCounter"] = "kernel32.dll";
        dll_map_["QueryPerformanceFrequency"] = "kernel32.dll";
        dll_map_["GetSystemTime"] = "kernel32.dll";
        dll_map_["GetLocalTime"] = "kernel32.dll";
        dll_map_["SetSystemTime"] = "kernel32.dll";
        dll_map_["SetLocalTime"] = "kernel32.dll";
        dll_map_["GetSystemTimeAsFileTime"] = "kernel32.dll";
        dll_map_["GetSystemTimePreciseAsFileTime"] = "kernel32.dll";
        dll_map_["FileTimeToSystemTime"] = "kernel32.dll";
        dll_map_["SystemTimeToFileTime"] = "kernel32.dll";
        dll_map_["FileTimeToLocalFileTime"] = "kernel32.dll";
        dll_map_["LocalFileTimeToFileTime"] = "kernel32.dll";
        dll_map_["CompareFileTime"] = "kernel32.dll";
        dll_map_["DosDateTimeToFileTime"] = "kernel32.dll";
        dll_map_["FileTimeToDosDateTime"] = "kernel32.dll";
        dll_map_["GetSystemTimeAdjustment"] = "kernel32.dll";

        // Misc
        dll_map_["GetComputerNameExA"] = "kernel32.dll";
        dll_map_["GetComputerNameExW"] = "kernel32.dll";
        dll_map_["SetComputerNameA"] = "kernel32.dll";
        dll_map_["SetComputerNameW"] = "kernel32.dll";
        dll_map_["SetComputerNameExA"] = "kernel32.dll";
        dll_map_["SetComputerNameExW"] = "kernel32.dll";
        dll_map_["GetSystemDirectoryA"] = "kernel32.dll";
        dll_map_["GetSystemDirectoryW"] = "kernel32.dll";
        dll_map_["GetWindowsDirectoryA"] = "kernel32.dll";
        dll_map_["GetWindowsDirectoryW"] = "kernel32.dll";
        dll_map_["GetSystemWindowsDirectoryA"] = "kernel32.dll";
        dll_map_["GetSystemWindowsDirectoryW"] = "kernel32.dll";
        dll_map_["GetTempPathA"] = "kernel32.dll";
        dll_map_["GetTempPathW"] = "kernel32.dll";
        dll_map_["GetSystemInfo"] = "kernel32.dll";
        dll_map_["GetNativeSystemInfo"] = "kernel32.dll";
        dll_map_["IsProcessorFeaturePresent"] = "kernel32.dll";
        dll_map_["GetProductInfo"] = "kernel32.dll";
        dll_map_["VerifyVersionInfoA"] = "kernel32.dll";
        dll_map_["VerifyVersionInfoW"] = "kernel32.dll";
        dll_map_["VerSetConditionMask"] = "kernel32.dll";

        // String
        dll_map_["CharLowerA"] = "user32.dll";
        dll_map_["CharLowerW"] = "user32.dll";
        dll_map_["CharUpperA"] = "user32.dll";
        dll_map_["CharUpperW"] = "user32.dll";
        dll_map_["CharNextA"] = "user32.dll";
        dll_map_["CharNextW"] = "user32.dll";
        dll_map_["CharPrevA"] = "user32.dll";
        dll_map_["CharPrevW"] = "user32.dll";
        dll_map_["CharLowerBuffA"] = "user32.dll";
        dll_map_["CharLowerBuffW"] = "user32.dll";
        dll_map_["CharUpperBuffA"] = "user32.dll";
        dll_map_["CharUpperBuffW"] = "user32.dll";
        dll_map_["IsCharAlphaA"] = "user32.dll";
        dll_map_["IsCharAlphaW"] = "user32.dll";
        dll_map_["IsCharAlphaNumericA"] = "user32.dll";
        dll_map_["IsCharAlphaNumericW"] = "user32.dll";
        dll_map_["IsCharLowerA"] = "user32.dll";
        dll_map_["IsCharLowerW"] = "user32.dll";
        dll_map_["IsCharUpperA"] = "user32.dll";
        dll_map_["IsCharUpperW"] = "user32.dll";

        // Clipboard
        dll_map_["OpenClipboard"] = "user32.dll";
        dll_map_["CloseClipboard"] = "user32.dll";
        dll_map_["EmptyClipboard"] = "user32.dll";
        dll_map_["GetClipboardData"] = "user32.dll";
        dll_map_["SetClipboardData"] = "user32.dll";
        dll_map_["CountClipboardFormats"] = "user32.dll";
        dll_map_["EnumClipboardFormats"] = "user32.dll";
        dll_map_["GetClipboardFormatNameA"] = "user32.dll";
        dll_map_["GetClipboardFormatNameW"] = "user32.dll";
        dll_map_["RegisterClipboardFormatA"] = "user32.dll";
        dll_map_["RegisterClipboardFormatW"] = "user32.dll";
        dll_map_["GetClipboardOwner"] = "user32.dll";
        dll_map_["GetClipboardViewer"] = "user32.dll";
        dll_map_["SetClipboardViewer"] = "user32.dll";
        dll_map_["AddClipboardFormatListener"] = "user32.dll";
        dll_map_["RemoveClipboardFormatListener"] = "user32.dll";

        // DDE
        dll_map_["DdeCreateStringHandleA"] = "user32.dll";
        dll_map_["DdeCreateStringHandleW"] = "user32.dll";
        dll_map_["DdeInitializeA"] = "user32.dll";
        dll_map_["DdeInitializeW"] = "user32.dll";
        dll_map_["DdeUninitialize"] = "user32.dll";
        dll_map_["DdeConnect"] = "user32.dll";
        dll_map_["DdeConnectList"] = "user32.dll";
        dll_map_["DdeDisconnect"] = "user32.dll";
        dll_map_["DdeDisconnectList"] = "user32.dll";
        dll_map_["DdeCreateDataHandle"] = "user32.dll";
        dll_map_["DdeCreateDataPointer"] = "user32.dll";
        dll_map_["DdeFreeDataHandle"] = "user32.dll";
        dll_map_["DdeGetData"] = "user32.dll";
        dll_map_["DdeAccessData"] = "user32.dll";
        dll_map_["DdeUnaccessData"] = "user32.dll";
        dll_map_["DdeClientTransaction"] = "user32.dll";
        dll_map_["DdeNameService"] = "user32.dll";
        dll_map_["DdePostAdvise"] = "user32.dll";
        dll_map_["DdeImpersonateClient"] = "user32.dll";
        dll_map_["DdeQueryStringA"] = "user32.dll";
        dll_map_["DdeQueryStringW"] = "user32.dll";
        dll_map_["DdeAbandonTransaction"] = "user32.dll";
        dll_map_["DdeKeepStringHandle"] = "user32.dll";
        dll_map_["DdeEnableCallback"] = "user32.dll";
        dll_map_["DdeQueryConvInfo"] = "user32.dll";
        dll_map_["DdeSetUserHandle"] = "user32.dll";
        dll_map_["DdeGetDataHandle"] = "user32.dll";
        dll_map_["DdeQueryHotKey"] = "user32.dll";

        // Communication
        dll_map_["BuildCommDCBAndTimeoutsA"] = "kernel32.dll";
        dll_map_["BuildCommDCBAndTimeoutsW"] = "kernel32.dll";
        dll_map_["BuildCommDCBA"] = "kernel32.dll";
        dll_map_["BuildCommDCBW"] = "kernel32.dll";
        dll_map_["GetCommState"] = "kernel32.dll";
        dll_map_["SetCommState"] = "kernel32.dll";
        dll_map_["GetCommTimeouts"] = "kernel32.dll";
        dll_map_["SetCommTimeouts"] = "kernel32.dll";
        dll_map_["GetCommMask"] = "kernel32.dll";
        dll_map_["SetCommMask"] = "kernel32.dll";
        dll_map_["GetCommModemStatus"] = "kernel32.dll";
        dll_map_["ClearCommError"] = "kernel32.dll";
        dll_map_["PurgeComm"] = "kernel32.dll";
        dll_map_["EscapeCommFunction"] = "kernel32.dll";
        dll_map_["GetCommProperties"] = "kernel32.dll";
        dll_map_["SetCommBreak"] = "kernel32.dll";
        dll_map_["ClearCommBreak"] = "kernel32.dll";
        dll_map_["TransmitCommChar"] = "kernel32.dll";
        dll_map_["SetCommConfig"] = "kernel32.dll";
        dll_map_["GetCommConfig"] = "kernel32.dll";
        dll_map_["SetCommPort"] = "kernel32.dll";
        dll_map_["GetCommPorts"] = "kernel32.dll";
        dll_map_["SetCommBreakEx"] = "kernel32.dll";
        dll_map_["ClearCommBreakEx"] = "kernel32.dll";

        // Console
        dll_map_["AllocConsole"] = "kernel32.dll";
        dll_map_["FreeConsole"] = "kernel32.dll";
        dll_map_["GetConsoleWindow"] = "kernel32.dll";
        dll_map_["GetConsoleMode"] = "kernel32.dll";
        dll_map_["SetConsoleMode"] = "kernel32.dll";
        dll_map_["GetConsoleCP"] = "kernel32.dll";
        dll_map_["SetConsoleCP"] = "kernel32.dll";
        dll_map_["GetConsoleOutputCP"] = "kernel32.dll";
        dll_map_["SetConsoleOutputCP"] = "kernel32.dll";
        dll_map_["ReadConsoleA"] = "kernel32.dll";
        dll_map_["ReadConsoleW"] = "kernel32.dll";
        dll_map_["WriteConsoleA"] = "kernel32.dll";
        dll_map_["WriteConsoleW"] = "kernel32.dll";
        dll_map_["WriteConsoleOutputA"] = "kernel32.dll";
        dll_map_["WriteConsoleOutputW"] = "kernel32.dll";
        dll_map_["ReadConsoleOutputA"] = "kernel32.dll";
        dll_map_["ReadConsoleOutputW"] = "kernel32.dll";
        dll_map_["GetConsoleTitleA"] = "kernel32.dll";
        dll_map_["GetConsoleTitleW"] = "kernel32.dll";
        dll_map_["SetConsoleTitleA"] = "kernel32.dll";
        dll_map_["SetConsoleTitleW"] = "kernel32.dll";
        dll_map_["FillConsoleOutputCharacterA"] = "kernel32.dll";
        dll_map_["FillConsoleOutputCharacterW"] = "kernel32.dll";
        dll_map_["FillConsoleOutputAttribute"] = "kernel32.dll";
        dll_map_["GetConsoleScreenBufferInfo"] = "kernel32.dll";
        dll_map_["SetConsoleCursorPosition"] = "kernel32.dll";
        dll_map_["SetConsoleTextAttribute"] = "kernel32.dll";
        dll_map_["GetConsoleCursorInfo"] = "kernel32.dll";
        dll_map_["SetConsoleCursorInfo"] = "kernel32.dll";
        dll_map_["ScrollConsoleScreenBufferA"] = "kernel32.dll";
        dll_map_["ScrollConsoleScreenBufferW"] = "kernel32.dll";
        dll_map_["SetConsoleActiveScreenBuffer"] = "kernel32.dll";
        dll_map_["FlushConsoleInputBuffer"] = "kernel32.dll";
        dll_map_["GetNumberOfConsoleInputEvents"] = "kernel32.dll";
        dll_map_["ReadConsoleInputA"] = "kernel32.dll";
        dll_map_["ReadConsoleInputW"] = "kernel32.dll";
        dll_map_["PeekConsoleInputA"] = "kernel32.dll";
        dll_map_["PeekConsoleInputW"] = "kernel32.dll";
        dll_map_["WriteConsoleInputA"] = "kernel32.dll";
        dll_map_["WriteConsoleInputW"] = "kernel32.dll";
        dll_map_["GetConsoleDisplayMode"] = "kernel32.dll";
        dll_map_["SetConsoleDisplayMode"] = "kernel32.dll";
        dll_map_["GetConsoleOriginalTitleA"] = "kernel32.dll";
        dll_map_["GetConsoleOriginalTitleW"] = "kernel32.dll";
        dll_map_["SetConsoleIcon"] = "kernel32.dll";
        dll_map_["GetConsoleIcon"] = "kernel32.dll";

        // CRT
        dll_map_["_set_invalid_parameter_handler"] = "kernel32.dll";
        dll_map_["_set_purecall_handler"] = "kernel32.dll";
        dll_map_["_set_abort_behavior"] = "kernel32.dll";
        dll_map_["_configure_narrow_argv"] = "kernel32.dll";
        dll_map_["_configure_wide_argv"] = "kernel32.dll";
        dll_map_["_initialize_narrow_environment"] = "kernel32.dll";
        dll_map_["_initialize_wide_environment"] = "kernel32.dll";
        dll_map_["_decode_pointer"] = "kernel32.dll";
        dll_map_["_encode_pointer"] = "kernel32.dll";
    }

inline void Enricher::enrich_type(Item& item)
    {
        auto& td = item.def;

        if (!td.source_header.empty())
        {
            auto pos = td.source_header.find_last_of("/\\");
            auto filename = (pos != std::string::npos) ? td.source_header.substr(pos + 1) : td.source_header;
            td.attributes.push_back(attr::make_header(filename));
        }

        if (!td.ns.empty())
        {
            td.attributes.push_back(attr::make_namespace(td.ns));
        }

        switch (td.kind)
        {
            case Kind::Class: td.attributes.push_back(attr::make_type_kind(attr::TypeKindVal::Struct)); break;
            case Kind::Enum: td.attributes.push_back(attr::make_type_kind(attr::TypeKindVal::Enum)); break;
            case Kind::Struct: td.attributes.push_back(attr::make_type_kind(attr::TypeKindVal::Struct)); break;
            case Kind::Union: td.attributes.push_back(attr::make_type_kind(attr::TypeKindVal::Union)); break;
            case Kind::Iface: td.attributes.push_back(attr::make_type_kind(attr::TypeKindVal::Interface)); break;
            case Kind::Delegate: td.attributes.push_back(attr::make_type_kind(attr::TypeKindVal::Delegate)); break;
            default: break;
        }

        if (td.kind == Kind::Struct || td.kind == Kind::Union)
        {
            if (td.is_union)
            {
                td.attributes.push_back(attr::make_union());
            }
            td.attributes.push_back(attr::make_struct_layout(
                td.is_union ? attr::StructLayoutKind::Explicit : attr::StructLayoutKind::Sequential,
                td.pack));
            if (td.cls_sz > 0)
            {
                td.attributes.push_back(attr::make_struct_size(std::to_string(td.cls_sz)));
            }
        }

        if (td.kind == Kind::Iface)
        {
            bool derives_iunknown = false;
            for (auto& iface : td.ifaces)
            {
                if (iface.name == "IUnknown" || iface.name == "IDispatch")
                {
                    derives_iunknown = true;
                    break;
                }
            }
            // MIDL_INTERFACE("...") declares a COM interface even when the
            // inheritance clause is not spelled out — a GUID is conclusive.
            if (derives_iunknown || !td.com_iid.empty())
            {
                td.is_com_interface = true;
                td.attributes.push_back(attr::make_com_interface({
                    .iid = td.com_iid,
                    .base_interface = td.ifaces.empty() ? "IUnknown" : td.ifaces[0].name,
                }));
            }
        }

        if (td.kind == Kind::Delegate)
        {
            td.is_callback = true;
            CC conv = CC::Std;
            if (!td.meths.empty()) conv = td.meths[0].cc;
            td.attributes.push_back(attr::make_callback_delegate(conv));
            td.attributes.push_back(attr::make_callback_convention(conv));
        }

        if (td.kind == Kind::Func)
        {
            for (auto& meth : td.meths)
            {
                auto it = dll_map_.find(td.name);
                if (it != dll_map_.end())
                {
                    td.import_library = it->second;
                    td.entry_point = td.name;
                    td.attributes.push_back(attr::make_import_library({
                        .dll = it->second,
                        .entry_point = td.name,
                    }));
                    td.attributes.push_back(attr::make_dll_import(it->second));
                    td.attributes.push_back(attr::make_export_function(td.name));
                }
                else if (!td.import_library.empty())
                {
                    // Resolved by an earlier pass; keep it.
                    if (td.entry_point.empty()) td.entry_point = td.name;
                }
                else if (auto nit = st.dll_imports.find(td.name); nit != st.dll_imports.end())
                {
                    // Flat-C export discovered from a NuGet import lib
                    // (scanned by the CLI); dll name read from the import
                    // descriptor, consulted after the built-in table.
                    td.import_library = nit->second;
                    td.entry_point = td.name;
                    td.attributes.push_back(attr::make_import_library({
                        .dll = nit->second,
                        .entry_point = td.name,
                    }));
                    td.attributes.push_back(attr::make_dll_import(nit->second));
                    td.attributes.push_back(attr::make_export_function(td.name));
                }

                auto cc = CC::Def;
                if (!td.import_library.empty() &&
                    (td.import_library == "ucrtbase.dll" || td.import_library == "msvcrt.dll" ||
                     td.import_library == "msvcp140.dll" || td.import_library == "vcruntime140.dll"))
                    cc = CC::Cdecl;
                else
                {
                    for (auto& n :
                    {"printf","fprintf","sprintf","snprintf","swprintf",
                                    "scanf","fscanf","sscanf","wscanf","wsprintf",
                                    "wprintf","_snprintf","_snwprintf","_vsnprintf",
                                    "vprintf","vfprintf","vsprintf","vswprintf",
                                    "DbgPrint","DbgPrintEx"})
                        if (td.name == n) { cc = CC::Cdecl; break; }
                }
                td.attributes.push_back(attr::make_calling_convention(cc));

                if (meth.ret == ET::Bool || meth.ret == ET::I4 || meth.ret == ET::U4 ||
                    meth.ret == ET::Ptr || meth.ret == ET::I8 || meth.ret == ET::U8)
                {
                    bool is_winsock = false;
                    if (td.import_library == "ws2_32.dll" || td.import_library == "wsock32.dll" ||
                        td.import_library == "mswsock.dll")
                        is_winsock = true;
                    auto& n = td.name;
                    if (n.starts_with("WSA"))
                        is_winsock = true;
                    if (!is_winsock)
                    {
                        if (n.starts_with("Get") || n.starts_with("Create") ||
                            n.starts_with("Open") || n.starts_with("Set") ||
                            n.starts_with("Reg") || n.starts_with("Find") ||
                            n.starts_with("Load") || n.starts_with("DeviceIoControl") ||
                            n.starts_with("Read") || n.starts_with("Write") ||
                            n.starts_with("Delete") || n.starts_with("Copy") ||
                            n.starts_with("Move") || n.starts_with("Format") ||
                            n.starts_with("Close") || n.starts_with("Lock") ||
                            n.starts_with("Unlock") || n.starts_with("Disconnect") ||
                            n.starts_with("MapView") ||
                            n.starts_with("UnmapView") || n.starts_with("Virtual") ||
                            n.starts_with("Heap") || n.starts_with("Local") ||
                            n.starts_with("Global") || n.starts_with("Process") ||
                            n.starts_with("Thread") || n.starts_with("Wait") ||
                            n.starts_with("Signal") || n.starts_with("Pulse") ||
                            n.starts_with("Initialize") || n.starts_with("Enter") ||
                            n.starts_with("Leave") || n.starts_with("Try") ||
                            n.starts_with("Crypt") || n.starts_with("Cert") ||
                            n.starts_with("BCrypt") || n.starts_with("NCrypt") ||
                            n.starts_with("CreateFile") || n.starts_with("ReadFile") ||
                            n.starts_with("WriteFile") || n.starts_with("GetFile") ||
                            n.starts_with("SetFile") || n.starts_with("FindFirst") ||
                            n.starts_with("FindNext") || n.starts_with("Query") ||
                            n.starts_with("Enum") || n.starts_with("Lookup") ||
                            n.starts_with("Adjust") || n.starts_with("Allocate") ||
                            n.starts_with("Free") || n.starts_with("Compare") ||
                            n.starts_with("Sizeof") || n.starts_with("IsValid") ||
                            n.starts_with("Convert") || n.starts_with("Translate") ||
                            n.starts_with("PostMessage") ||
                            n.starts_with("SendMessage") || n.starts_with("Realloc"))
                        {
                            td.attributes.push_back(attr::make_last_error());
                        }
                    }
                }

                if (meth.ret == ET::I4 && !meth.ret_r.name.empty() && meth.ret_r.name == "HRESULT")
                {
                    td.attributes.push_back(attr::make_hresult());
                }

                if (meth.ret == ET::I4 && !meth.ret_r.name.empty() && meth.ret_r.name == "NTSTATUS")
                {
                    td.attributes.push_back(attr::make_nt_status());
                }

                for (size_t pi = 0; pi < meth.params.size() && pi < meth.pt.size(); ++pi)
                {
                    auto& nm = meth.params[pi].name;
                    auto& tn = meth.pt[pi].name;
                    if (nm.find("lpwsz") != std::string::npos || nm.find("pszW") != std::string::npos ||
                        nm.find("lpszW") != std::string::npos || nm.find("pwsz") != std::string::npos ||
                        nm.find("lpWSTR") != std::string::npos || nm.find("wstr") != std::string::npos ||
                        tn.find("WCHAR") != std::string::npos || tn.find("LPWSTR") != std::string::npos ||
                        tn.find("PCWSTR") != std::string::npos || tn.find("LPCWSTR") != std::string::npos ||
                        tn.find("PWSTR") != std::string::npos || tn.find("BSTR") != std::string::npos)
                    {
                        td.attributes.push_back(attr::make_string_encoding(attr::StringEncoding::Unicode));
                        break;
                    }
                    if (nm.find("lpszA") != std::string::npos || nm.find("pszA") != std::string::npos ||
                        nm.find("lpstr") != std::string::npos || nm.find("lpasz") != std::string::npos ||
                        tn.find("LPSTR") != std::string::npos || tn.find("PCSTR") != std::string::npos ||
                        tn.find("LPCSTR") != std::string::npos || tn.find("PSTR") != std::string::npos)
                    {
                        td.attributes.push_back(attr::make_string_encoding(attr::StringEncoding::Ansi));
                        break;
                    }
                }
            }
        }

        if (td.kind == Kind::Class || td.kind == Kind::Struct)
        {
            auto ht = handle_map_.find(td.name);
            if (ht != handle_map_.end())
            {
                td.attributes.push_back(attr::make_handle_kind(ht->second));
                td.attributes.push_back(attr::make_handle_ownership(attr::HandleOwnership::Owned));
            }
        }

        if (td.kind == Kind::Func)
        {
            for (auto& meth : td.meths)
            {
                for (size_t pi = 0; pi < meth.params.size() && pi < meth.pt.size(); ++pi)
                {
                    auto& pd = meth.params[pi];
                    auto& pt = meth.pt[pi];
                    if (pd.sal_buffer_info != 0)
                    {
                        attr::BufferSemanticsInfo bsi;
                        bsi.param_index = pd.seq;
                        bsi.kind = (attr::BufferKind)(pd.sal_buffer_info & 0xFF);
                        bsi.is_byte_count = (pd.sal_buffer_info >> 8) & 1;
                        bsi.is_wide = true;
                        bsi.count_param = pd.sal_count_param;
                        bsi.count_expression = pd.sal_count_expression;
                        td.attributes.push_back(attr::make_buffer_semantics(bsi));
                    }
                    if (pt.ptr > 0 && pt.elem != ET::Void)
                    {
                        bool is_char_type = (pt.elem == ET::Char) ||
                            pt.name.find("WCHAR") != std::string::npos ||
                            pt.name.find("wchar_t") != std::string::npos ||
                            pt.name.find("CHAR") != std::string::npos ||
                            pt.name.find("char") != std::string::npos;
                        bool is_null_term = false;
                        if (is_char_type)
                        {
                            for (auto& n : meth.params[pi].name)
                            {
                                if (n == 'z' || n == 'Z') { is_null_term = true; break; }
                            }
                        }
                        if (is_null_term)
                        {
                            td.attributes.push_back(attr::make_string_null(0));
                        }
                    }
                }
            }
        }

        if (td.kind == Kind::Struct || td.kind == Kind::Union)
        {
            for (auto& f : td.fields)
            {
                if (f.ref.fnptr)
                {
                    td.attributes.push_back(attr::make_callback_delegate(CC::Def));
                    break;
                }
            }
        }

        if (td.kind == Kind::Enum)
        {
            detect_enum_flags(td);
        }

        detect_ioctl_constants(td);

        auto cat = categorize_by_header(td.source_header);
        if (cat != attr::FuncCategory::Unknown)
        {
            td.attributes.push_back(attr::make_function_category(cat));
        }

        enrich_extra(item);

        // WINVERSE_ATTRTRACE=1: count every emitted attribute per kind for
        // coverage diagnostics (printed after the enrich pass).
        if (attr_trace_enabled())
        {
            auto& tr = attr_trace();
            std::lock_guard<std::mutex> lock(tr.m);
            for (auto& a : td.attributes) ++tr.counts[a.name];
        }
    }

inline void Enricher::detect_enum_flags(TDef& td)
    {
        bool has_zero = false;
        int single_bit_count = 0;
        int multi_bit_count = 0;
        for (auto& f : td.fields)
        {
            uint64_t val = 0;
            if (f.def.type == ET::I4)
            {
                val = static_cast<uint64_t>(std::get<int32_t>(f.def.v));
            }
            else if (f.def.type == ET::U4)
            {
                val = std::get<uint32_t>(f.def.v);
            }
            else if (f.def.type == ET::I8)
            {
                val = static_cast<uint64_t>(std::get<int64_t>(f.def.v));
            }
            else if (f.def.type == ET::U8)
            {
                val = std::get<uint64_t>(f.def.v);
            }
            else if (f.def.type == ET::I1)
            {
                val = static_cast<uint64_t>(std::get<int8_t>(f.def.v));
            }
            else if (f.def.type == ET::U1)
            {
                val = std::get<uint8_t>(f.def.v);
            }
            else if (f.def.type == ET::I2)
            {
                val = static_cast<uint64_t>(std::get<int16_t>(f.def.v));
            }
            else if (f.def.type == ET::U2)
            {
                val = std::get<uint16_t>(f.def.v);
            }
            else
            {
                continue;
            }
            if (val == 0)
            {
                has_zero = true;
            }
            else if ((val & (val - 1)) == 0)
            {
                single_bit_count++;
            }
            else
            {
                multi_bit_count++;
            }
        }
        bool is_flags = has_zero && single_bit_count >= 2 && multi_bit_count >= 1;
        if (is_flags)
        {
            td.is_enum_flags = true;
            td.attributes.push_back(attr::make_flags());
        }

        // Shape classification runs independent of the [Flags] gate above:
        // a pure bitmask (>= 2 single-bit members, none combined) is
        // EnumPowerOf2 even without a 0 member. The old entry gate required
        // a combined member (multi_bit_count >= 1) while the power-of-2 test
        // required multi_bit_count == 0 — mutually exclusive, so
        // EnumPowerOf2 could never fire for any enum in the SDK.
        if (single_bit_count >= 2)
        {
            // Classify member shapes for the companion attributes:
            //  - power-of-2: every non-zero member is a single bit
            //  - combination: at least one multi-bit member whose bits all
            //    decompose into declared single-bit members
            auto field_val = [](FDef const& f, uint64_t& out) -> bool {
                switch (f.def.type)
                {
                    case ET::I4: out = (uint64_t)(int64_t)std::get<int32_t>(f.def.v); return true;
                    case ET::U4: out = std::get<uint32_t>(f.def.v); return true;
                    case ET::I8: out = (uint64_t)std::get<int64_t>(f.def.v); return true;
                    case ET::U8: out = std::get<uint64_t>(f.def.v); return true;
                    case ET::I1: out = (uint64_t)(int64_t)std::get<int8_t>(f.def.v); return true;
                    case ET::U1: out = std::get<uint8_t>(f.def.v); return true;
                    case ET::I2: out = (uint64_t)(int64_t)std::get<int16_t>(f.def.v); return true;
                    case ET::U2: out = std::get<uint16_t>(f.def.v); return true;
                    default: return false;
                }
            };
            uint64_t bit_mask = 0;
            int single = 0, combos = 0, bad_combos = 0;
            for (auto& f : td.fields)
            {
                uint64_t v = 0;
                if (!field_val(f, v) || v == 0) continue;
                if ((v & (v - 1)) == 0) { bit_mask |= v; ++single; }
            }
            for (auto& f : td.fields)
            {
                uint64_t v = 0;
                if (!field_val(f, v) || v == 0) continue;
                if ((v & (v - 1)) != 0)
                {
                    if ((v & ~bit_mask) == 0) ++combos; else ++bad_combos;
                }
            }
            // power-of-2: the enum is a pure bitmask (no combined members)
            if (single_bit_count >= 2 && multi_bit_count == 0)
                td.attributes.push_back(attr::make_enum_power_of2());
            if (combos > 0)
                td.attributes.push_back(attr::make_enum_combination());
        }
    }

inline void Enricher::detect_ioctl_constants(TDef& td)
    {
        if (td.kind != Kind::Enum && td.kind != Kind::Struct) return;
        if (td.kind == Kind::Enum)
        {
            for (auto& f : td.fields)
            {
                // NB: "IOCTL_" is 6 chars — an earlier version compared
                // substr(0, 7) against it, which can never match, so this
                // detector emitted nothing for the entire SDK.
                if (!(f.name.rfind("IOCTL_", 0) == 0 || f.name.rfind("FSCTL_", 0) == 0)) continue;
                uint64_t val = 0;
                bool got_val = false;
                if (f.def.type == ET::U4) { val = std::get<uint32_t>(f.def.v); got_val = true; }
                else if (f.def.type == ET::I4) { val = static_cast<uint64_t>(std::get<int32_t>(f.def.v)); got_val = true; }
                else if (f.def.type == ET::U8) { val = std::get<uint64_t>(f.def.v); got_val = true; }
                else if (f.def.type == ET::I8) { val = static_cast<uint64_t>(std::get<int64_t>(f.def.v)); got_val = true; }
                if (!got_val || val == 0) continue;

                attr::IoctlCodeInfo ici;
                ici.raw_code = (uint32_t)val;
                ici.device_type = (uint32_t)((val >> 16) & 0xFFFF);
                ici.function_code = (uint32_t)((val >> 2) & 0xFFF);
                ici.method = (attr::IoctlMethod)((val >> 14) & 0x3);
                ici.access = (attr::IoctlAccess)(val & 0x3);
                td.attributes.push_back(attr::make_ioctl_code(ici));
                td.attributes.push_back(attr::make_ioctl_buffering((uint32_t)ici.method));
            }
        }
    }

inline attr::FuncCategory Enricher::categorize_by_header(const std::string& header)
    {
        if (header.empty()) return attr::FuncCategory::Unknown;
        auto pos = header.find_last_of("/\\");
        auto filename = (pos != std::string::npos) ? header.substr(pos + 1) : header;

        if (filename == "winuser.h") return attr::FuncCategory::WindowManagement;
        if (filename == "wingdi.h") return attr::FuncCategory::Gdi;
        if (filename == "fileapi.h" || filename == "handleapi.h") return attr::FuncCategory::FileSystem;
        if (filename == "winreg.h") return attr::FuncCategory::Registry;
        if (filename == "winsock.h" || filename == "winsock2.h" || filename.starts_with("ws2"))
            return attr::FuncCategory::WinSock;
        if (filename.starts_with("d3d")) return attr::FuncCategory::Direct3D;
        if (filename.starts_with("dxgi")) return attr::FuncCategory::DirectX;
        if (filename.starts_with("mf")) return attr::FuncCategory::MediaFoundation;
        if (filename == "processthreadsapi.h" || filename == "synchapi.h")
            return attr::FuncCategory::Threading;
        if (filename == "memoryapi.h" || filename == "heapapi.h")
            return attr::FuncCategory::Memory;
        if (filename == "ioapiset.h") return attr::FuncCategory::IO;
        if (filename.starts_with("acl") || filename.starts_with("wincred") ||
            filename.starts_with("sspi") || filename.starts_with("wincrypt") ||
            filename.starts_with("bcrypt") || filename.starts_with("ncrypt"))
            return attr::FuncCategory::Security;
        if (filename == "shellapi.h" || filename == "shlobj.h" || filename == "shellscalingapi.h" ||
            filename == "shlwapi.h" || filename == "shobjidl_core.h" || filename == "shobjidl.h")
            return attr::FuncCategory::Shell;
        if (filename == "winhttp.h") return attr::FuncCategory::Network;
        if (filename == "wininet.h") return attr::FuncCategory::Network;
        if (filename.starts_with("dshow") || filename.starts_with("mmdevice") ||
            filename.starts_with("audioclient"))
            return attr::FuncCategory::Audio;
        if (filename.starts_with("winspool") || filename.starts_with("spoolss"))
            return attr::FuncCategory::Printing;
        if (filename == "commctrl.h") return attr::FuncCategory::Controls;
        if (filename == "commdlg.h") return attr::FuncCategory::Dialogs;
        if (filename == "oledlg.h") return attr::FuncCategory::Dialogs;
        if (filename.starts_with("ole") || filename.starts_with("com") ||
            filename.starts_with("unknwn") || filename.starts_with("objidl"))
            return attr::FuncCategory::COM;
        if (filename == "setupapi.h") return attr::FuncCategory::Setup;
        if (filename == "cfgmgr32.h") return attr::FuncCategory::DeviceManager;
        if (filename == "wlanapi.h" || filename.starts_with("windot11"))
            return attr::FuncCategory::WiFi;
        if (filename.starts_with("fwpm") || filename.starts_with("fwp"))
            return attr::FuncCategory::FilteringPlatform;
        if (filename == "dbghelp.h" || filename.starts_with("minidump"))
            return attr::FuncCategory::Diagnostics;
        if (filename == "debugapi.h") return attr::FuncCategory::Debug;

        return attr::FuncCategory::Unknown;
    }

inline void Enricher::resolve_aw_suffixes()
    {
        // Disabled: stripping the A/W suffix produces names that no DLL
        // exports (LoadLibraryExW -> LoadLibraryEx exists only as a header
        // #define, not as an export), so downstream code cannot link.
        // Language-agnostic metadata must reflect the real export names;
        // A/W pair selection is the consumer projection's job.
        (void)aw_stripped_;
        return;
        std::unordered_set<std::string> all_names;
        for (auto& item : st.items)
            all_names.insert(item.def.ns + "." + item.def.name);

        for (auto& item : st.items)
        {
            auto& name = item.def.name;
            if (name.size() <= 1) continue;
            char last = name.back();
            if (last != 'A' && last != 'W') continue;
            auto base = name.substr(0, name.size() - 1);
            if (base.size() <= 2) continue;
            auto base_key = item.def.ns + "." + base;
            if (all_names.count(base_key) == 0)
            {
                name = base;
                ++aw_stripped_;
            }
            else
            {
                // A surviving suffix means the opposite-suffix sibling
                // exists: a genuine Unicode/Ansi variant pair.
                item.def.attributes.push_back(attr::make_variant(
                    last == 'W' ? "Unicode" : "Ansi"));
            }
        }
    }

    //
    // enrich_extra — the remaining attribute surface. Every attribute the
    // factory layer defines gets an emission here, driven by data the
    // parser/enricher already has (SAL, decl specifiers, header paths,
    // architecture, handle/dll maps, enum analysis, naming conventions).
    //
    inline void Enricher::enrich_extra(Item& item)
    {
        auto& td = item.def;

        // SDK partition + kernel/UMDK detection. The WDF framework trees
        // (Include\wdf\kmdf|umdf\<ver>) sit outside km/ and um/, so classify
        // them by flavor too — otherwise every Wdf* API lands in "shared"
        // and misses the km-only DriverType/WdfObject/NoThrow extras below.
        bool is_wdf_km = td.source_header.find("/wdf/kmdf/") != std::string::npos ||
                         td.source_header.find("\\wdf\\kmdf\\") != std::string::npos;
        bool is_wdf_um = td.source_header.find("/wdf/umdf/") != std::string::npos ||
                         td.source_header.find("\\wdf\\umdf\\") != std::string::npos;
        bool is_km = td.source_header.find("/km/") != std::string::npos ||
                     td.source_header.find("\\km\\") != std::string::npos || is_wdf_km;
        bool is_um = td.source_header.find("/um/") != std::string::npos ||
                     td.source_header.find("\\um\\") != std::string::npos || is_wdf_um;
        bool is_wasdk = td.source_header.find("windowsappsdk") != std::string::npos ||
                        td.source_header.find("WindowsAppSDK") != std::string::npos;
        td.attributes.push_back(attr::make_partition(is_km ? "km" : (is_um ? "um" : "shared")));

        // Platform checks + availability on the target SDK build.
        td.attributes.push_back(attr::make_platform(0)); // 0 = Windows (universal)
        if (!sdk_version_.empty())
            td.attributes.push_back(attr::make_platform_supported(sdk_version_));

        // WindowsAppSDK-derived headers carry the App-SDK contract/feature.
        if (is_wasdk)
        {
            td.attributes.push_back(attr::make_contract("WindowsAppSdk", 0));
            td.attributes.push_back(attr::make_feature("WindowsAppSdk"));
        }

        // Architecture / struct layout extras
        if (item.arch != Ar::All && item.arch != Ar::None)
            td.attributes.push_back(attr::make_architecture(item.arch));

        bool is_record = td.kind == Kind::Struct || td.kind == Kind::Union;
        if (is_record && td.pack != 0)
            td.attributes.push_back(attr::make_pack(td.pack));

        if (is_record)
        {
            bool has_ptr = false, anon = false;
            for (auto& f : td.fields)
            {
                if (f.ref.ptr > 0 || f.ref.fnptr || f.ref.elem == ET::Ptr) has_ptr = true;
                // An anonymous nested record projects as a field with no name.
                if (f.name.empty()) anon = true;
            }
            if (anon) td.attributes.push_back(attr::make_anonymous_struct());
            if (has_ptr)
            {
                uint32_t psize = (item.arch == Ar::X86) ? 4u : 8u;
                td.attributes.push_back(attr::make_pointer_size(psize));
            }
        }

        // Handles: close function + access
        if (td.kind == Kind::Class || td.kind == Kind::Struct)
        {
            auto ht = handle_map_.find(td.name);
            if (ht != handle_map_.end())
            {
                const char* close_fn = "CloseHandle";
                switch (ht->second)
                {
                    case attr::HandleKind::Registry: close_fn = "RegCloseKey"; break;
                    case attr::HandleKind::Service:
                    case attr::HandleKind::SCManager: close_fn = "CloseServiceHandle"; break;
                    case attr::HandleKind::Find: close_fn = "FindClose"; break;
                    case attr::HandleKind::ChangeNotification: close_fn = "FindCloseChangeNotification"; break;
                    case attr::HandleKind::Memory:
                    case attr::HandleKind::FileMapping: close_fn = "UnmapViewOfFile"; break;
                    case attr::HandleKind::Socket: close_fn = "closesocket"; break;
                    case attr::HandleKind::DC: close_fn = "DeleteDC"; break;
                    case attr::HandleKind::Bitmap:
                    case attr::HandleKind::Brush:
                    case attr::HandleKind::Font:
                    case attr::HandleKind::Pen:
                    case attr::HandleKind::Region: close_fn = "DeleteObject"; break;
                    case attr::HandleKind::Icon: close_fn = "DestroyIcon"; break;
                    case attr::HandleKind::Cursor: close_fn = "DestroyCursor"; break;
                    case attr::HandleKind::Menu: close_fn = "DestroyMenu"; break;
                    case attr::HandleKind::Window: close_fn = "DestroyWindow"; break;
                    case attr::HandleKind::Clipboard: close_fn = "CloseClipboard"; break;
                    case attr::HandleKind::Desktop: close_fn = "CloseDesktop"; break;
                    case attr::HandleKind::WindowStation: close_fn = "CloseWindowStation"; break;
                    case attr::HandleKind::Monitor: close_fn = "DestroyMonitor"; break;
                    default: break;
                }
                td.attributes.push_back(attr::make_close_function(close_fn));
                td.attributes.push_back(attr::make_handle_access(3)); // Read|Write -> All
            }
        }

        // Simple typedefs: type_forward / primitive_type
        if ((td.kind == Kind::Class || td.kind == Kind::Struct) &&
            (td.alias_elem != ET::Void || !td.alias_ref.name.empty()))
        {
            // Primitive aliases carry a fundamental element type; named
            // targets (typedef HANDLE HLOCAL, typedef GUID CLSID) forward
            // to the named type instead.
            bool named_target = !td.alias_ref.name.empty();
            bool primitive = td.alias_elem != ET::Void &&
                             td.alias_elem != ET::Class &&
                             td.alias_elem != ET::Ptr &&
                             td.alias_elem != ET::FnPtr;
            if (primitive)
            {
                using PV = attr::PrimitiveTypeVal;
                PV pv;
                switch (td.alias_elem)
                {
                    case ET::Bool: pv = PV::Bool; break;
                    case ET::I1: pv = PV::I1; break;
                    case ET::U1: pv = PV::U1; break;
                    case ET::I2: pv = PV::I2; break;
                    case ET::U2: pv = PV::U2; break;
                    case ET::I4: pv = PV::I4; break;
                    case ET::U4: pv = PV::U4; break;
                    case ET::I8: pv = PV::I8; break;
                    case ET::U8: pv = PV::U8; break;
                    case ET::R4: pv = PV::R4; break;
                    case ET::R8: pv = PV::R8; break;
                    case ET::Char: pv = PV::Char; break;
                    case ET::String: pv = PV::String; break;
                    default: pv = PV::Void; break;
                }
                td.attributes.push_back(attr::make_primitive_type(pv));
            }
            else if (named_target)
            {
                td.attributes.push_back(attr::make_type_forward(
                    td.alias_ref.ns.empty() ? td.alias_ref.name
                                            : td.alias_ref.ns + "." + td.alias_ref.name));
            }
        }

        // Enums with literal members ARE the constant source
        if (td.kind == Kind::Enum)
        {
            for (auto& f : td.fields)
            {
                if ((uint16_t)f.attr & (uint16_t)FA::Literal)
                {
                    td.attributes.push_back(attr::make_constant());
                    break; // one marker per enum item is enough
                }
            }
            // IRP major function codes
            for (auto& f : td.fields)
            {
                if (f.name.starts_with("IRP_MJ_"))
                {
                    uint64_t v = 0;
                    if (f.def.type == ET::U4) v = std::get<uint32_t>(f.def.v);
                    else if (f.def.type == ET::I4) v = (uint64_t)(int64_t)std::get<int32_t>(f.def.v);
                    td.attributes.push_back(attr::make_irp_mj((uint32_t)v));
                }
            }
        }

        // COM interfaces: guid + per-method vtable rows + property/event
        // Every Kind::Iface is a COM interface by construction (the parser
        // only produces it from MIDL_INTERFACE/DECLARE_INTERFACE), so do not
        // require the is_com_interface flag here: an interface that derives
        // from a named base (not literally IUnknown/IDispatch) and carries no
        // IID would otherwise get no vtable rows at all.
        if (td.kind == Kind::Iface)
        {
            if (!td.com_iid.empty())
                td.attributes.push_back(attr::make_guid(td.com_iid));
            for (size_t mi = 0; mi < td.meths.size(); ++mi)
            {
                td.attributes.push_back(attr::make_com_method((uint32_t)mi));
                auto const& nm = td.meths[mi].name;
                // get_X at slot i paired with put_X/set_X at slot i+1
                if (nm.starts_with("get_") && mi + 1 < td.meths.size())
                {
                    auto const& nx = td.meths[mi + 1].name;
                    if (nx == "put_" + nm.substr(4) || nx == "set_" + nm.substr(4))
                        td.attributes.push_back(
                            attr::make_com_property((uint32_t)mi, (uint32_t)(mi + 1)));
                }
                // add_X at slot i paired with remove_X at slot i+1 = event
                if (nm.starts_with("add_") && mi + 1 < td.meths.size() &&
                    td.meths[mi + 1].name == "remove_" + nm.substr(4))
                    td.attributes.push_back(attr::make_com_event(td.com_iid));
            }
        }
        if (td.kind == Kind::Class && !td.com_iid.empty())
        {
            td.attributes.push_back(attr::make_com_coclass({ td.com_iid, "" }));
            td.attributes.push_back(attr::make_guid(td.com_iid));
        }
        else if (!td.com_iid.empty() && td.kind != Kind::Iface)
        {
            td.attributes.push_back(attr::make_guid(td.com_iid));
        }

        // Kernel driver attributes
        if (is_km)
        {
            bool is_wdf = td.name.starts_with("Wdf") || td.name.starts_with("WDF");
            td.attributes.push_back(attr::make_driver_type(
                is_wdf ? attr::DriverTypeVal::KMDF : attr::DriverTypeVal::WDM));
            if (is_wdf)
                td.attributes.push_back(attr::make_wdf_object((uint32_t)attr::DriverTypeVal::KMDF));
            if (td.kind == Kind::Func && td.name.find("Dispatch") != std::string::npos)
                td.attributes.push_back(attr::make_driver_dispatch(0, 0));
            // Dispatch-class callback typedefs — the SDK labels them with
            // _Function_class_(DRIVER_DISPATCH); the typedef name alone
            // often carries no hint.
            if (td.kind == Kind::Delegate && td.fn_class.starts_with("DRIVER_DISPATCH"))
                td.attributes.push_back(attr::make_driver_dispatch(0, 0));
        }
        // UMDF flavor of the same framework (Include\wdf\umdf): same Wdf*
        // surface, user-mode side — tagged UMDF so projections never fold
        // it into the kernel flavor.
        else if (is_wdf_um && (td.name.starts_with("Wdf") || td.name.starts_with("WDF")))
        {
            td.attributes.push_back(attr::make_driver_type(attr::DriverTypeVal::UMDF));
            td.attributes.push_back(attr::make_wdf_object((uint32_t)attr::DriverTypeVal::UMDF));
        }
        if (td.name.find("POWER_STATE") != std::string::npos)
            td.attributes.push_back(attr::make_power_state(0));
        if (td.name.find("PNP") != std::string::npos || td.name.find("PnP") != std::string::npos)
            td.attributes.push_back(attr::make_pnp_state(0));

        // Functions: inline / obsolete / must-check / win32-error /
        // nothrow / nullable-result + per-param buffer/string extras
        if (td.kind == Kind::Func)
        {
            if (td.fn_flags & FNF_FORCEINLINE)
                td.attributes.push_back(attr::make_inline_function(attr::InlineKind::ForceInline));
            else if (td.fn_flags & FNF_INLINE)
                td.attributes.push_back(attr::make_inline_function(attr::InlineKind::Normal));

            if (td.fn_flags & FNF_DEPRECATED)
                td.attributes.push_back(attr::make_obsolete(td.deprecation_msg));

            bool must_check = (td.fn_flags & FNF_RET_MAYBENULL) != 0 ||
                               (td.fn_flags & FNF_MUST_CHECK) != 0;
            bool ret_is_ptr = false;
            for (auto& m : td.meths)
            {
                if (m.ret == ET::Ptr || m.ret == ET::FnPtr) ret_is_ptr = true;
                if (handle_map_.count(m.ret_r.name)) ret_is_ptr = true;
                if (m.ret == ET::I4 && m.ret_r.name == "WIN32_ERROR")
                    td.attributes.push_back(attr::make_win32_error());
            }
            for (auto& m : td.meths)
            {
                for (size_t pi = 0; pi < m.params.size() && pi < m.pt.size(); ++pi)
                {
                    auto& pd = m.params[pi];
                    auto& pt = m.pt[pi];
                    if (pd.sal_flags & SF_CHECK_RETURN) must_check = true;

                    if (pd.sal_buffer_info != 0)
                    {
                        if (!pd.sal_count_param.empty())
                            td.attributes.push_back(attr::make_buffer_length(pd.sal_count_param));
                        else if (!pd.sal_count_expression.empty())
                            td.attributes.push_back(attr::make_buffer_length(pd.sal_count_expression));
                        uint32_t bk = pd.sal_buffer_info & 0xFF;
                        if (bk >= 4) // string-typed buffer kinds
                            td.attributes.push_back(attr::make_buffer_null(1));
                        else if (pd.sal_flags & SF_NULL_TERM)
                            td.attributes.push_back(attr::make_buffer_null(1));
                        if (!pt.name.empty())
                            td.attributes.push_back(attr::make_buffer_type(pt.name));
                    }
                    // char-typed buffers with a SAL count expression carry
                    // the static upper bound for marshaling.
                    bool is_char_param = (pt.elem == ET::Char) ||
                        pt.name.find("CHAR") != std::string::npos ||
                        pt.name.find("char") != std::string::npos;
                    if (pt.ptr > 0 && is_char_param && !pd.sal_count_expression.empty())
                        td.attributes.push_back(attr::make_string_max_length(pd.sal_count_expression));
                    // Optional callback parameters: an inline fnptr or a
                    // param typed with a callback typedef, plus _Opt_ SAL.
                    if ((pt.fnptr || callback_names_.count(pt.name)) &&
                        ((uint16_t)pd.attr & (uint16_t)PA::Opt))
                        td.attributes.push_back(attr::make_callback_optional());
                }
            }
            if (must_check) td.attributes.push_back(attr::make_must_check());
            // Kernel-mode functions never throw across the ABI boundary.
            if (is_km) td.attributes.push_back(attr::make_no_throw());
            if (ret_is_ptr) td.attributes.push_back(attr::make_nullable_result());
        }
    }

} // namespace wv
