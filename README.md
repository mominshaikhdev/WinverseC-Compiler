# WINVERSE COMPILER

A high-performance Win32, Driver API, and Windows App SDK (WASDK) Flat-C API metadata compiler, implemented in C++23 modules using MSVC. Produces ECMA-335 `.winmd` files directly from Windows SDK C/C++ headers with complete semantic attribution, enabling precise language projections from any target language. `-include_wasdk` (or `-include_wasdk exp` for the experimental channel) additionally ingests the WASDK NuGet packages' Flat-C headers and import libraries into `Windows.Win32.AppSDK.*`.

## Overview

Winverse Compiler parses the Windows SDK (version 26100 and later), including user-mode, kernel-mode, and shared headers, and produces a single `.winmd` binary conforming to the ECMA-335 metadata standard. The output includes every Win32 function, struct, enum, constant, callback, COM interface, and driver API — each annotated with custom attributes that capture semantics invisible to standard metadata formats: handle ownership, buffer relationships, IOCTL codes, calling conventions, import library mappings, and more.

The generated `.winmd` is directly consumable by any language with an ECMA-335 reader — C#, Rust, Zig, Python, D, Dart, Beef, Go, TypeScript, and others — without requiring language-specific code generators or per-language glue.

## Motivation

### Microsoft win32metadata

The official Microsoft project (github.com/microsoft/win32metadata) produces `Windows.Win32.winmd` through a multi-stage pipeline: ClangSharp scrapes C/C++ headers into C# source files, then Roslyn compiles them into `.winmd`. Verified architectural limitations:

| Constraint | Evidence |
|---|---|
| **Extensive manual configuration** | 7 configuration files totaling ~68,000 lines: `scraper.settings.rsp` (727), `emitter.settings.rsp` (2,404), `autoTypes.json` (1,947), `enums.json` (37,097), `libMappings.rsp` (26,808), `requiredNamespacesForNames.rsp` (2,656), `functionPointerFixups.json` (103) |
| **323 hand-maintained partitions** | Each API domain requires a `main.cpp` and `settings.rsp` — any SDK update demands manual partition adjustments |
| **External toolchain dependency** | Requires ClangSharp 17.0.1, libclang, .NET 8 SDK — version coupling creates fragility |
| **Extended build duration** | Parallel scraping across x86/x64/arm64, merging, emission, signing, and packaging requires 30–60+ minutes in CI |
| **Flat namespace model** | All functions and constants are placed in a single `Apis` static class, eliminating semantic grouping by API domain |
| **Incomplete driver coverage** | Kernel-mode headers are partially processed, but WDF/KMDF/UMDF type semantics and IRP metadata are absent |
| **No IOCTL structure** | `CTL_CODE` macros are emitted as raw integer constants — device type, function code, buffering method, and access rights are lost |
| **Two-language pipeline** | Scraping produces C# intermediate files, which are then compiled by Roslyn — two compilers, two languages, two failure modes |
| **Emitter requires .NET runtime** | The `ClangSharpSourceToWinmd` project depends on Roslyn's `MetadataBuilder`, requiring the .NET runtime at build time |
| **Centralized governance** | MIT-licensed but Microsoft-controlled — the project direction, API surface, and release cadence are not independently owned |
| **Partial SAL utilization** | SAL annotations are processed by ClangSharp but not fully propagated as metadata attributes for projection consumption |
| **Manual enum management** | The 37,097-line `enums.json` requires manual definition of every flags enum, combination enum, and constant grouping |
| **No macro function support** | Function-like `#define` macros (`SUCCEEDED`, `CONTAINING_RECORD`, `FIELD_OFFSET`, etc.) are excluded from processing |

### windows-rs metadata crate

The Rust crate at `crates/libs/metadata` within the windows-rs repository provides a pure-Rust ECMA-335 reader and writer. It is a consumer of `.winmd` files, not a producer from C/C++ headers. Verified architectural limitations:

| Constraint | Evidence |
|---|---|
| **Read-only from C/C++ perspective** | `reader/file.rs` implements PE/COFF parsing of existing `.winmd` binaries — no header parsing capability |
| **Apis expansion as foundation** | `reader/index.rs` lines 55–82: the `Index::new()` constructor expands all `Apis` container members into flat items — the anti-pattern is architectural, not incidental |
| **No header scraping** | Zero code for tokenizing, preprocessing, or parsing C/C++ source — entirely dependent on external metadata producers |
| **WinRT-oriented metadata format** | `writer/file/into_stream.rs` writes `"WindowsRuntime 1.4"` as the version string — the format was designed for WinRT projections, with Win32 as a secondary use case |
| **No driver API concepts** | No representation of kernel-mode types, IRP structures, WDF objects, or device driver interfaces |
| **Post-hoc architecture handling** | `SupportedArchitectureAttribute` is applied during merge/emission — architecture is not intrinsic to the type system |
| **Restricted type vocabulary** | `ty.rs` defines 31 `Type` variants — no function pointer type, no union type, no managed reference type |
| **No attribute generation framework** | The writer provides an `Attribute()` builder method but no attribute definition system — each projection must independently define which attributes to emit and consume |
| **Lossy merge semantics** | `merge/mod.rs` enum union selects the "fullest copy" and discards members from other sources — data loss during multi-source merging |
| **Significant merge complexity** | `merge/mod.rs` at 995 lines contains extensive special-case handling for `Apis` containers, enum unions, and architecture-specific types — complexity stemming from the foundational `Apis` pattern |

### Microsoft wdkmetadata

The official Microsoft project (github.com/microsoft/wdkmetadata) produces `Windows.Wdk.winmd` for WDK driver APIs. It uses the Microsoft.Windows.WinmdGenerator NuGet package. Verified architectural limitations:

| Constraint | Evidence |
|---|---|
| **Experimental status** | Repository README explicitly states "EXPERIMENTAL" — not production-ready |
| **7,099 files in repo** | 5,374 raw SDK/WDK headers checked in, no source code |
| **0 source files** | No `.cs`, no `.rs` — only 1 `.rsp` config file (2,756 lines) |
| **No header recompilation** | Headers are raw SDK/WDK copies in `IdlHeaders/` — no `RecompiledIdlHeaders/` directory |
| **Flat header dump** | 5,374 `.h` files in `IdlHeaders/` with no semantic partitioning |
| **No IOCTL structure** | `CTL_CODE` macros emitted as raw integers — device type, function code, buffering method lost |
| **WinmdGenerator dependency** | Build-time dependency on Microsoft.Windows.WinmdGenerator NuGet package |
| **Windows SDK coupling** | Headers are from Windows 11 Build 22000 — not forward-compatible with newer SDK versions |

### Verified Repository Statistics

| Metric | win32metadata | windows-rs | wdkmetadata |
|---|---|---|---|
| **Total files** | 4,474 | 1,861 | 7,099 |
| **Source files** | 141 `.cs` | 1,700 `.rs` | 0 `.cs` |
| **Config files** | 348 `.rsp` + 24 `.json` | 31 `Cargo.toml` | 1 `.rsp` |
| **Config lines** | 191,762 | N/A | 2,756 |
| **Partitions** | 5 top-level dirs (WinSDK: 647 subdirs) | N/A | 1 dir (IdlHeaders: 5,374 `.h`) |
| **Metadata output** | 0 `.winmd` in repo | 2 `.winmd` | 0 `.winmd` in repo |
| **SDK headers** | 2,373 `.h` (RecompiledIdlHeaders) | N/A | 5,374 `.h` (IdlHeaders, not recompiled) |
| **Total source lines** | 23,171 `.cs` | 6,304 `metadata/src/` `.rs` | 0 `.cs` |

## Winverse Compiler Architecture

Winverse Compiler employs a five-layer pipeline where each layer operates on a progressively enriched intermediate representation:

```
  Windows SDK C/C++ Headers (um/ km/ shared/ + WDK wdf/ — version 26100+)
                          |
                          v
  +------------------------------------------------------------------------+
  |  Layer 1: PARSE                                                        |
  |  Modules: parser.ixx, preprocessor.ixx, sal.ixx                       |
  |                                                                        |
  |  * Recursive descent parser with #include resolution against SDK      |
  |    include paths (um, km, shared, winrt, wdf)                          |
  |  * Preprocessor evaluation: #ifdef, #if defined(), #elif, #else,      |
  |    #endif — architecture-specific code blocks are resolved at         |
  |    parse time, tagging each declaration with the appropriate         |
  |    architecture flag (X86, X64, Arm, Arm64)                           |
  |  * SAL annotation extraction: _In_, _Out_, _Inout_, _In_opt_,       |
  |    _Out_writes_(n), _In_reads_z_(n), etc. are parsed into           |
  |    structured BufferSemanticsInfo for each parameter                   |
  |  * IID resolution from DEFINE_GUID; direct base class tracking       |
  |  * Function-to-DLL import library mapping for P/Invoke, DllImport,  |
  |    and native language projections (verified against SDK .lib files)  |
  |  * Semantic function categorization by header source (FileSystem,    |
  |    Registry, Graphics, Networking, Security, etc.)                   |
  |  * A/W suffix resolution: CreateFileA/CreateFileW -> CreateFile      |
  |  * Deprecation detection from __declspec(deprecated) and            |
  |    DEPRECATED macro usage                                           |
  |                                                                      |
  |  Implemented and wired:                                              |
  |  * Buffer semantics (SAL -> BufferSemantics attributes)              |
  |  * IOCTL expansion (CTL_CODE -> structured IoctlCode attributes)     |
  |  * COM coclass CLSIDs (class DECLSPEC_UUID -> ComCoClass)            |
  |  * IRP major-function codes (IRP_MJ_* -> IrpMajorFunction)           |
  |  * Optional-callback SAL (_In_opt_ params -> CallbackOptional)       |
  |  * Function pointer detection in struct fields                       |
  |  * String null-termination attributes                                |
  +-----------------------------------+----------------------------------+
                                      | Fully Annotated IR
                                      v
  +------------------------------------------------------------------------+
  |  Layer 4: EMIT                                                         |
  |  Module: emit.ixx                                                      |
  |                                                                        |
  |  * Pure C++ ECMA-335 binary writer — produces valid PE32+ assemblies |
  |    containing #~, #Strings, #Blob, and #GUID metadata streams         |
  |  * Zero-duplicate engine: types are deduplicated by namespace +       |
  |    name + signature; methods by calling convention + parameter list  |
  |  * Architecture merge: x86, x64, and arm64 variants of the same    |
  |    type are consolidated into a single type definition with          |
  |    per-architecture size attributes                                  |
  |  * Custom attribute emission: 64 Winverse attribute types are        |
  |    defined; all are actively emitted as ECMA-335 CustomAttribute    |
  |    rows with proper blob encoding                                    |
  |  * Semantic namespace grouping: functions are placed in domain-      |
  |    appropriate namespaces (Windows.Win32.FileSystem,                 |
  |    Windows.Win32.Registry, Windows.Win32.Graphics.Gdi, etc.)       |
  |    — not a monolithic Apis container                                 |
  |  * String and blob heap deduplication with proper ECMA-335          |
  |    compressed integer encoding                                       |
  |  * Sorted table emission per ECMA-335 specification                 |
  |  * WinRT base type integration for Windows.Foundation types         |
  +-----------------------------------+----------------------------------+
                                      | Windows.Win32.winmd
                                      v
  +------------------------------------------------------------------------+
  |  Layer 5: VALIDATE                                                     |
  |  Module: validate.ixx                                                  |
  |                                                                        |
  |  * SDK header inventory: enumerates all .h/.hpp/.hxx files across   |
  |    um, km, shared, and wdf directories; reports parsed vs. total    |
  |  * API coverage analysis: counts function declarations, struct      |
  |    definitions, enum definitions, and constants — reports resolved   |
  |    vs. total                                                         |
  |  * Cross-reference validation against existing .winmd files for     |
  |    delta analysis                                                     |
  |  * Type resolution completeness: identifies unresolved type         |
  |    references and forward declarations                               |
  |  * Custom attribute completeness verification                       |
  |  * Human-readable report generation (HTML, JSON, plain text)        |
  +------------------------------------------------------------------------+
```

## Comparative Analysis

| Dimension | Microsoft win32metadata | windows-rs metadata | Microsoft wdkmetadata | Winverse Compiler |
|---|---|---|---|---|
| **Implementation language** | C# with ClangSharp | Rust | Config-only (no source) | C++23 modules |
| **External dependencies** | .NET 8 SDK, libclang, ClangSharp 17.0.1 | None (pure Rust) | WinmdGenerator NuGet package | None (pure C++23, MSVC) |
| **Build time (full SDK)** | 30–60+ minutes | N/A (consumer only) | Inherits win32metadata pipeline time | ~30 seconds (one pass) |
| **Configuration overhead** | 191,762 lines across 372+ files | N/A | 2,756 lines (1 `.rsp` file) | ~200-line namespace mapping |
| **Partition management** | 647 hand-maintained subdirectories | N/A | IdlHeaders: 5,374 `.h` (flat) | Automatic by header |
| **Metadata generation** | Yes, via C# intermediary | No — reads existing `.winmd` only | Yes, via WinmdGenerator | Yes, direct from C/C++ headers |
| **Driver API support** | Partial (kernel-mode headers) | None | Partial (experimental) | Full — DriverType (KMDF/UMDF/WDM) + WdfObject + DriverDispatch + IrpMajorFunction (from materialized `IRP_MJ_*`) + NoThrow + SAL buffer/string semantics + bogus-macro-row cleanup |
| **Handle taxonomy** | `autoTypes.json` (2,984 lines, manual) | None | None — inherits from win32metadata | 6 kinds detected (File, Event, Thread, Process, Registry, Service) |
| **Buffer semantics** | Partial SAL propagation | None | None | SAL -> BufferSemanticsAttribute + StringNullAttribute emitted from `_In_`/`_Out_`/`_Inout_`/`_In_reads_`/`_Out_writes_`/`_Null_terminated_` annotations |
| **IOCTL metadata** | None — raw integers only | None | None — raw integers only | IoctlCodeAttribute + IoctlBufferingAttribute emitted from IOCTL_* enum constant decoding |
| **COM interface support** | Basic COM detection | None | None | Full — ComInterface (IID + flags), per-method ComMethod vtable slots, ComProperty/ComEvent slot pairing, ComCoClass CLSIDs |
| **Enum flags detection** | 37,097-line manual JSON | None | None — inherits from win32metadata | Automatic bitmask pattern analysis (>=3 bits set -> flags) |
| **Namespace model** | Flat `Apis` static class | Flat `Apis` container expansion | Flat `Windows.Wdk` hierarchy | Semantic domain grouping |
| **Custom attribute set** | ~10 projection-specific attributes | None — projections hardcode rules | None — inherits from win32metadata | 64 defined, all actively emitted |
| **A/W suffix handling** | Manual remap configuration | None | None — inherits from win32metadata | Automatic suffix detection and resolution |
| **Error recovery strategy** | ClangSharp fail-fast | N/A | WinmdGenerator fail-fast | Skip-and-continue with diagnostics |

## Example: Win32 Function Projection

A single Win32 function — `CreateFileW` — demonstrates how the attribute set drives projection logic across five languages from one `.winmd`:

```c
// C header (Windows SDK)
HANDLE WINAPI CreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
);
```

The `.winmd` emitted by Winverse carries:

| Attribute | Value | Projection Logic |
|---|---|---|
| `DllImport("kernel32.dll")` | kernel32.dll | P/Invoke DllImport |
| `CallingConvention(Stdcall)` | Stdcall | Calling convention |
| `HandleKind(0)` | File | RAII wrapper + auto-close |
| `CloseFunction("CloseHandle")` | CloseHandle | try-finally block |
| `BufferSemantics(Input)` | Input | marshal-in only |
| `LastError()` | — | GetLastError on failure |
| `PlatformSupported("5.1")` | Windows XP+ | Platform gate |
| `Architecture(X64 \| Arm64)` | — | Architecture-specific impl |

### Pseudocode: What Each Language Projection Generates

#### C# / CsWin32
```csharp
[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW")]
internal static partial SafeFileHandle CreateFileW(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    SECURITY_ATTRIBUTES? lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    SafeHandle? hTemplateFile);

// Generated wrapper:
using var handle = CreateFileW("data.txt", GENERIC_READ, FILE_SHARE_READ,
    null, OPEN_EXISTING, 0, null);
// SafeFileHandle auto-calls CloseHandle on dispose
```

#### Rust / windows-rs
```rust
#[link(name = "windows")]
extern "system" {
    pub fn CreateFileW(
        lpfilename: PCWSTR,
        dwdesiredaccess: FILE_ACCESS_FLAGS,
        dwsharemode: FILE_SHARE_MODE,
        lpsecurityattributes: *const SECURITY_ATTRIBUTES,
        dwcreationdisposition: FILE_CREATION_DISPOSITION,
        dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,
        htemplatefile: HANDLE,
    ) -> windows_core::Result<HANDLE>;
}

// Generated wrapper:
let file = CreateFileW(w!("data.txt"), GENERIC_READ, FILE_SHARE_READ,
    std::ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, HANDLE::default())?;
// Caller must CloseHandle
```

#### C++23 Modules / [CppWinC](https://github.com/mominshaikhdev/CppWinC-Compiler)
```cpp
import std;
import Windows.Win32.Storage.FileSystem;
import Windows.Win32.System;
import Windows.Win32.Foundation;
import Windows.Win32.UI.WindowsAndMessaging;
using namespace Windows::Win32::Storage::FileSystem;
using namespace Windows::Win32::System::SystemServices;
using namespace Windows::Win32::UI::WindowsAndMessaging;

// Handles flatten to void*; Win32 constants project as inline constexpr
// values in their metadata namespaces (GENERIC_READ, OPEN_EXISTING, ...).
void* file = CreateFile(L"data.txt", GENERIC_READ, FILE_SHARE_READ,
    nullptr, OPEN_EXISTING, 0, nullptr);

char buf[4096]{};
std::uint32_t bytesRead = 0;
ReadFile(file, buf, sizeof(buf), &bytesRead, nullptr);
Windows::Win32::Foundation::CloseHandle(file);

// CreateFile/CreateWindowEx are the unsuffixed canonicals cppwinc emits
// for each CreateFileW/CreateWindowExW pair; string parameters take
// wchar_t const* directly.
void* hwnd = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW, L"MyApp", L"Hello",
    WS_OVERLAPPEDWINDOW, static_cast<std::int32_t>(CW_USEDEFAULT),
    static_cast<std::int32_t>(CW_USEDEFAULT), 800, 600, nullptr, nullptr, nullptr, nullptr);
```

#### TypeScript / TSWinC
```typescript
import { CreateFileW, ReadFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING } from "Windows.Win32.FileSystem";
import { CreateWindowExW, WS_OVERLAPPED, WS_VISIBLE } from "Windows.Win32.UI.WindowsAndMessaging";

const file = CreateFileW("data.txt", GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, 0, null);
const buf = new ArrayBuffer(4096);
const bytesRead = new Uint32Array(1);
ReadFile(file, buf, buf.byteLength, bytesRead, null);

const hwnd = CreateWindowExW(0, "MyApp", "Hello", WS_OVERLAPPED | WS_VISIBLE, 0, 0, 800, 600, 0, 0, 0, null);
```

#### Python / PyWinC
```python
import ctypes
from Windows.Win32.FileSystem import CreateFileW, ReadFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING
from Windows.Win32.UI.WindowsAndMessaging import CreateWindowExW, WS_OVERLAPPED, WS_VISIBLE

file = CreateFileW("data.txt", GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
buf = ctypes.create_string_buffer(4096)
bytes_read = ctypes.c_ulong(0)
ReadFile(file, buf, 4096, ctypes.byref(bytes_read), None)

hwnd = CreateWindowExW(0, "MyApp", "Hello", WS_OVERLAPPED | WS_VISIBLE, 0, 0, 800, 600, None, None, None, None)
msg = ctypes.wintypes.MSG()
GetMessageW(ctypes.byref(msg), hwnd, 0, 0)
```

### Combined Win32 + WDK Examples

Using `Windows.Win32+Wdk.winmd` (generated with `-include_drivers`), both `Windows.Win32.*` and `Windows.Wdk.*` namespaces are available from a single file:

#### C++ — Combined Win32 + WDK (CppWinC)

```cpp
import std;
import Windows.Win32.Storage.FileSystem;
import Windows.Win32.System;
import Windows.Win32.Foundation;
import Windows.Wdk.BASETSD;
import Windows.Wdk.STRSAFE;
using namespace Windows::Win32::Storage::FileSystem;
using namespace Windows::Win32::System::SystemServices;

// Win32: user-mode API (canonical CreateFile forwards to CreateFileW)
void* file = CreateFile(L"data.txt", GENERIC_READ, FILE_SHARE_READ,
    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
Windows::Win32::Foundation::CloseHandle(file);

// WDK: type-safe integer conversions
void* handle = nullptr;
std::int32_t value = Windows::Wdk::BASETSD::HandleToLong(handle);
void* restored = Windows::Wdk::BASETSD::LongToHandle(value);

// WDK: string safety helpers (the A/W canonical takes the W signature:
// destination, size, mutable source)
wchar_t dest[256]{};
wchar_t src[] = L"Hello";
Windows::Wdk::STRSAFE::StringCbCopy(dest, sizeof(dest), src);
```

#### Rust — Combined Win32 + WDK (windows-rs)

```rust
use Windows::Win32::FileSystem::*;
use Windows::Win32::UI::WindowsAndMessaging::*;
use Windows::Wdk::Basetsd::*;
use Windows::Wdk::Strsafe::*;

// Win32: user-mode API
unsafe {
    let file = CreateFileW(w!("data.txt"), GENERIC_READ, FILE_SHARE_READ,
        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)?;
}

// WDK: type-safe integer conversions
unsafe {
    let handle: HANDLE = todo!();
    let value = HandleToLong(handle);
    let restored = LongToHandle(value);
}
```

#### Python — Combined Win32 + WDK (PyWinC)

```python
import ctypes
from Windows.Win32.FileSystem import CreateFileW, ReadFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING
from Windows.Wdk.Basetsd import HandleToLong, LongToHandle, PtrToInt, IntToPtr

# Win32: user-mode API
file = CreateFileW("data.txt", GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)

# WDK: type-safe integer conversions
handle = get_handle()  # some HANDLE
value = HandleToLong(handle)
restored = LongToHandle(value)
```

## Building

Requires Visual Studio 2026 (version 18 or later) with the C++ desktop workload and Windows SDK 10.0.26100.0.

```batch
build.bat              :: Debug build    -> build\Debug\winversec.exe
build.bat Release      :: Release build  -> build\Release\winversec.exe
build.bat Clean        :: Remove build artifacts (both configurations)
```

Each configuration owns its own output directory for `.obj` / `.ifc` / `.log`
files, so Debug and Release coexist and switching configurations can never
link objects built against a different CRT.

| Configuration | Compile flags | Link flags | Output |
|---|---|---|---|
| Debug | `/Od /Zi /D_DEBUG /MDd` | `/DEBUG` | `build\Debug\winversec.exe` + `winversec.pdb` |
| Release | `/O2 /DNDEBUG /GL /MD` | `/LTCG /OPT:REF /OPT:ICF /RELEASE` | `build\Release\winversec.exe` |

Debug `/Od` is deliberate, and `/RTC1` is deliberately absent: runtime error
checks are incompatible with the `/EHa` async EH model this project uses.
A release copy for distribution is placed in the repo root as
`winversec.exe`.

## Usage

### Win32 Only

```batch
:: Generate Win32-only metadata (excludes WDK driver APIs)
winversec.exe -no_drivers

:: Specify SDK and version explicitly
winversec.exe -no_drivers -sdk "C:\Program Files (x86)\Windows Kits\10" -version 10.0.26100.0 -output Windows.Win32.winmd
```

Parses `um/` and `shared/` directories only. Produces `Windows.Win32.winmd` with user-mode APIs, COM interfaces, structures, enums, and constants.

### Win32 + WDK (Combined)

```batch
:: Default: both Win32 and WDK APIs (include_drivers is on by default)
winversec.exe -output Windows.Win32+Wdk.winmd

:: Explicitly include WDK (same as default)
winversec.exe -include_drivers -output Windows.Win32+Wdk.winmd
```

Parses `um/`, `km/`, and `shared/` directories plus the WDK's WDF framework trees (`Include\wdf\kmdf\<ver>` and `Include\wdf\umdf\<ver>`, newest installed version of each). Produces `Windows.Win32+Wdk.winmd` with both user-mode and kernel-mode APIs: WDF/KMDF/UMDF framework functions, device driver interfaces, and kernel object types.

### WDK Only

```batch
:: Generate drivers-only metadata (no Win32 user-mode APIs)
winversec.exe -drivers_only

:: Custom output path
winversec.exe -drivers_only -output MyDriver.winmd
```

Parses only `km/`, `shared/`, and the WDF framework trees (`Include\wdf\{kmdf,umdf}\<ver>`). Produces `Windows.Wdk.winmd` with kernel-mode APIs only: `ntddk.h`, `wdm.h`, `fltKernel.h`, `ndis.h`, `storport.h`, WDF framework, and all driver-specific headers.

### Windows App SDK Headers (-include_wasdk)

```batch
:: Ingest Windows App SDK headers the Windows SDK lacks (e.g. MddBootstrap.h
:: for the unpackaged-app bootstrapper) from the machine's NuGet cache.
winversec.exe -include_wasdk -output Windows.Win32.winmd
```

`-include_wasdk` auto-locates `microsoft.windowsappsdk*` packages under the
NuGet cache (`NUGET_PACKAGES`, then `~/.nuget/packages`), highest version
first, and scans their `include/` dirs **for headers the Windows SDK does not
already provide** (dedup by file stem, case-insensitive).

**Experimental channel — `-include_wasdk exp`:** adding the optional `exp`
argument restricts ingestion to experimental packages (version directories
tagged `-experimental*`, e.g. `2.5.4-experimental`); the newest installed
experimental version wins and stable releases are skipped. This is how
experimental Flat-C WASDK APIs reach the winmd. `-include_wasdk` alone keeps
the default newest-version behavior.

```batch
:: Experimental Flat-C WASDK APIs only (e.g. 2.5.4-experimental)
winversec.exe -include_wasdk exp -output Windows.Win32.winmd
```

Version-dependent constants (`WINDOWSAPPSDK_RELEASE_MAJORMINOR`,
`WINDOWSAPPSDK_RUNTIME_VERSION_UINT64`, ...) are evaluated from the scanned
package's own headers (`WindowsAppSDK-VersionInfo.h`) at generation time —
32- and 64-bit values both land in the winmd — so a future WASDK release
never requires rebuilding winversec.

Why the dedup matters: from Windows 11 22H2 (build 22621) the Windows SDK
ships its own dynamic-dependency headers (`MddBootstrap.h`, plus the OS-level
`TryCreatePackageDependency` API in `appmodel.h`). When the SDK provides a
header, the NuGet copy is skipped, so the same symbols are never declared
twice. On older SDKs the WASDK headers fill the gap instead. Both map into
the official win32metadata homes:

| Header | Namespace |
|--------|-----------|
| `appmodel.h` | `Windows.Win32.System.AppModel` |
| `MddBootstrap.h` | `Windows.Win32.System.DynamicDependency` |

**Flat-C WindowsAppSDK APIs — automatic namespaces and DLL imports:** every other WASDK header needs no table entry:

- **Namespace**: `Windows.Win32.AppSDK.<HeaderStem>` (`MRM.h` ->
  `Windows.Win32.AppSDK.MRM`), so the Flat-C AppSDK APIs sit alongside the
  rest of the Win32 projection rather than under a `Microsoft.*` root of
  their own. WASDK headers are named after the API they expose
  (`Microsoft.UI.Dispatching.Interop.h`), so any leading `Microsoft`,
  `Windows` or `AppSDK` segment — which would only restate the root — is
  dropped and the remaining segments are uppercased for deterministic
  naming (`Microsoft.UI.Dispatching.Interop.h` ->
  `Windows.Win32.AppSDK.UI.DISPATCHING.INTEROP`). `-ns` pins and the stem
  table above take precedence.
- **DLL import**: each package's import libs (`lib/native/x64/*.lib`,
  then x86/arm64/arm64ec) are scanned for exported symbols; the dll name
  comes from the import descriptor in the binary (`MrmCreateResourceManager`
  -> `MRM.dll`), so new Flat-C APIs get their import the day they ship.
  Consulted after the built-in dll table.

### Extra Header Directories (-include_dir)

```batch
:: Scan any extra header directory (repeatable) for headers the SDK lacks.
:: Same SDK-stem-first dedup as -include_wasdk.
winversec.exe -include_dir "C:\path\to\thirdparty\include" -output Windows.Win32.winmd

:: Pin any header to any namespace (overrides the built-in table)
winversec.exe -include_dir "C:\path\to\lib\include" -ns myheader=Acme.Lib.Api -output lib.winmd
```

> **Fidelity note:** SDK-style C headers convert with full coverage (the
> coverage report / `Unresolved` count is the truth-teller). Arbitrary
> third-party headers are best-effort - preprocessor macros, typedef chains
> and function-pointer quirks may need `-ns` pinning or manual review. Always
> check the coverage report after generating.

### Coverage Report

```batch
:: Generate with HTML coverage report showing parsed vs missing APIs
winversec.exe -coverage coverage.html

:: Combined with drivers
winversec.exe -include_drivers -coverage coverage.html
```

### All Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-sdk <path>` | Windows SDK root | auto-detect any drive |
| `-version <ver>` | SDK version directory | auto-detect latest |
| `-output <file>` | Output .winmd path | `Windows.Win32+Wdk.winmd` |
| `-include_drivers` | Include WDK `km/` + `Include\wdf\` framework headers | on |
| `-no_drivers` | Exclude WDK driver APIs (Win32 only) | off |
| `-drivers_only` | Only `km/` + `shared/` + `Include\wdf\`, skip `um/` | off |
| `-include_wasdk [exp]` | Auto-ingest WASDK NuGet headers the SDK lacks; `exp` = experimental packages only | off |
| `-include_dir <dir>` | Extra header dir, repeatable (SDK stems win) | none |
| `-ns <h=Namespace>` | Pin a header stem to a namespace, repeatable | none |
| `-coverage <file>` | HTML coverage report | none |
| `-verbose` | Verbose output | off |
| `-help` | Show help | -- |

## Custom Attributes Reference

Winverse Compiler defines 64 custom attribute types (in `attributes.ixx`) that capture Win32 semantics invisible to standard metadata. The current pipeline emits all of them — each section below records the emission status (verified with `WINVERSE_ATTRTRACE=1`).

### Handle Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `HandleKindAttribute` | **Emitted** | `uint Kind` | Generate typed handle wrappers with correct cleanup: `FileHandle` -> `CloseHandle`, `RegKeyHandle` -> `RegCloseKey`, `EventHandle` -> `CloseHandle` |
| `OwnershipAttribute` | **Emitted** | `uint Owner` | Implement RAII patterns: `Owned` -> auto-close on dispose, `Borrowed` -> no cleanup required |
| `CloseFunctionAttribute` | **Emitted** | `string Name` | Generate `try-finally` blocks calling the specified close/release function |
| `HandleAccessAttribute` | **Emitted** | `uint Access` | Generate typed access rights: `Read`, `Write`, `ReadWrite`, `All` |

### Buffer Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `BufferSemanticsAttribute` | **Emitted** | `uint Kind` | Generate array/pointer marshaling: `Input` -> marshal-in, `Output` -> marshal-out, `InOut` -> marshal-in-out |
| `BufferLengthAttribute` | **Emitted** | `string Expr` | Generate buffer size calculations |
| `BufferNullAttribute` | **Emitted** | `uint Semantics` | Generate null-termination checks |
| `BufferTypeAttribute` | **Emitted** | `string TypeName` | Generate typed buffer access |

### Calling Convention Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `CallingConventionAttribute` | **Emitted** | `uint CC` | Generate P/Invoke calling convention: `Winapi` -> `CallingConvention.Winapi`, `Cdecl` -> `CallingConvention.Cdecl`, `Stdcall` -> `CallingConvention.Stdcall` |
| `InlineFunctionAttribute` | **Emitted** | `uint Kind` | Generate inline function implementations: `ForceInline` -> force-inline, `Normal` -> normal inline, `None` -> not inline |

### COM Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `ComInterfaceAttribute` | **Emitted** | `Guid Iid, uint Flags` | Generate COM interface wrappers |
| `ComMethodAttribute` | **Emitted** | `uint VTableIndex` | Generate vtable method calls |
| `ComPropertyAttribute` | **Emitted** | `uint GetIndex, uint SetIndex` | Generate property accessors |
| `ComEventAttribute` | **Emitted** | `Guid Iid` | Generate event source wrappers |
| `ComCoClassAttribute` | **Emitted** | `string Clsid` | Generate coclass metadata |

### IOCTL Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `IoctlCodeAttribute` | **Emitted** | `uint DeviceType, uint Function, uint Method, uint Access` | Generate IOCTL constants from `CTL_CODE` |
| `IoctlBufferingAttribute` | **Emitted** | `uint Method` | Generate buffer marshaling based on method |

> **Note:** IOCTL expansion covers both sources. `#define IOCTL_X CTL_CODE(...)` values are evaluated by the preprocessor, recorded by the parser, then materialized as single-member enums by `materialize_ioctl_consts` (`enrich.ixx`); enum-resident `IOCTL_*`/`FSCTL_*` members are decoded in `detect_ioctl_constants` at enrichment time — device type (`>> 16`), function code (`>> 2 & 0xFFF`), buffering method (`>> 14 & 3`), and access (`& 3`) — each emitting `IoctlCodeAttribute` + `IoctlBufferingAttribute`.

### Enum Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `EnumFlagsAttribute` | **Emitted** | -- | Generate bitwise operations: `[Flags]` enum with `HasFlag`, `Or`, `And` operators |
| `EnumCombinationAttribute` | **Emitted** | -- | Generate combination constants |
| `EnumPowerOf2Attribute` | **Emitted** | -- | Generate power-of-2 constants |

### Architecture Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `ArchitectureAttribute` | **Emitted** | `uint Arch` | Generate architecture-specific implementations |
| `PointerSizeAttribute` | **Emitted** | `uint Size` | Generate pointer size calculations |
| `PackAttribute` | **Emitted** | `uint Value` | Generate struct packing |

### String Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `StringEncodingAttribute` | **Emitted** | `uint Encoding` | Generate string marshaling |
| `StringNullAttribute` | **Emitted** | `uint Semantics` | Generate null-termination handling |
| `StringMaxLengthAttribute` | **Emitted** | `string Expr` | Generate string length calculations |

### Error Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `LastErrorAttribute` | **Emitted** | -- | Generate error handling: `GetLastError` -> marshal last error code |
| `HRESULTAttribute` | **Emitted** | -- | Generate HRESULT checking |
| `NTStatusAttribute` | **Emitted** | -- | Generate NTSTATUS checking |
| `Win32ErrorAttribute` | **Emitted** | -- | Generate Win32 error checking |
| `MustCheckAttribute` | **Emitted** | -- | Mark functions whose return values must be checked |
| `NoThrowAttribute` | **Emitted** | -- | Mark functions that never throw |
| `NullableResultAttribute` | **Emitted** | -- | Mark functions that may return null |

### Callback Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `CallbackDelegateAttribute` | **Emitted** | `Guid Iid` | Generate delegate types |
| `CallbackConventionAttribute` | **Emitted** | `uint CC` | Generate delegate calling convention |
| `CallbackOptionalAttribute` | **Emitted** | -- | Generate nullable delegates |

> **Note:** Callback emission has three sites in `enrich_type` (`enrich.ixx`): a `Kind::Delegate` typedef (`typedef void (CALLBACK *foo)(...)`) emits `CallbackDelegateAttribute` + `CallbackConventionAttribute` carrying the typedef's calling convention; a struct field whose type resolves to a function pointer (e.g., `WDF_DRIVER_CONFIG.EvtDriverDeviceAdd`) emits `CallbackDelegateAttribute` (default convention); and a parameter typed with one of those callbacks plus `_Opt_` SAL emits `CallbackOptionalAttribute`.

### Struct Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `StructLayoutAttribute` | **Emitted** | `uint Kind, uint Pack` | Generate struct layout |
| `StructSizeAttribute` | **Emitted** | `string Expr` | Generate size calculations |
| `UnionAttribute` | **Emitted** | -- | Generate union types |
| `AnonymousStructAttribute` | **Emitted** | -- | Generate anonymous struct access |

### Namespace Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `NamespaceAttribute` | **Emitted** | `string Value` | Generate namespace grouping |
| `HeaderAttribute` | **Emitted** | `string Value` | Generate header source tracking |

### Import Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `DllImportAttribute` | **Emitted** | `string Library` | Generate P/Invoke imports |
| `ImportLibraryAttribute` | **Emitted** | `string Library` | Generate import library references |
| `ExportFunctionAttribute` | **Emitted** | `string Name` | Generate export functions |

### Deprecation Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `DeprecatedAttribute` | **Emitted** | `string Message` | Generate deprecation warnings |
| `PlatformAttribute` | **Emitted** | `uint Platform` | Generate platform checks |
| `PlatformSupportedAttribute` | **Emitted** | `string Version` | Generate platform availability checks |
| `ObsoleteAttribute` | **Emitted** | `string Message, string Since` | Generate obsolete warnings |

### Type Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `TypeKindAttribute` | **Emitted** | `uint Kind` | Generate type definitions |
| `TypeForwardAttribute` | **Emitted** | `string Target` | Generate type forwarding |
| `PrimitiveTypeAttribute` | **Emitted** | `uint Type` | Generate primitive type mappings |
| `GuidAttribute` | **Emitted** | `Guid Value` | Generate GUID constants |
| `ConstantAttribute` | **Emitted** | -- | Generate constant values |

### Driver Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `DriverTypeAttribute` | **Emitted** | `uint Kind` | Generate driver-specific types: KMDF, UMDF, WDF, WDM |
| `DriverDispatchAttribute` | **Emitted** | `uint Major, uint Minor` | Generate IRP dispatch routine metadata |
| `IrpMajorFunctionAttribute` | **Emitted** | `uint MajorFunction` | Tag parameters as IRP major function codes |
| `WdfObjectAttribute` | **Emitted** | `uint Kind` | Generate WDF object type metadata |
| `PowerAttribute` | **Emitted** | `uint State` | Generate power state metadata |
| `PnpAttribute` | **Emitted** | `uint State` | Generate PnP state metadata |

> **Note:** WDK attributes are emitted from the parser via `make_*` calls in `driver.ixx`, and the enrichment pipeline is wired for kernel-mode APIs: `enrich_type` runs over every item regardless of partition (handle classification, IOCTL expansion from `CTL_CODE`, SAL buffer/string annotation), while `enrich_extra` layers the `is_km` extras on top — `DriverType`/`WdfObject`/`DriverDispatch`, `IrpMajorFunction` from materialized `IRP_MJ_*` defines, partition `km`, and `NoThrow` on kernel functions.

### Miscellaneous Attributes

| Attribute | Status | Fields | Pseudocode for Projection Owners |
|---|---|---|---|
| `ContractAttribute` | **Emitted** | `string Name, uint Version` | Generate API contract checks |
| `VariantAttribute` | **Emitted** | `string Name` | Generate API variant tracking |
| `FeatureAttribute` | **Emitted** | `string Name` | Generate feature checks |
| `PartitionAttribute` | **Emitted** | `string Name` | Generate partition checks |
| `FunctionCategoryAttribute` | **Emitted** | `uint Category` | Generate API domain classification |

### Projection Owner Guidance

Language projections read the `.winmd` and generate type-safe projections. The `.winmd` contains semantic attributes (HandleKind, DllImport, BufferSemantics, StructLayout, etc.) that drive projection logic.

## License

Copyright (c) 2026 Momin Shaikh. Released under the [MIT License](LICENSE).
