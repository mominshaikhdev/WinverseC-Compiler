// attributes.ixx - Custom attribute definitions for Win32 semantics
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
module;

#include <cstdint>
#include <string>
#include <vector>

export module winversec.attributes;
import winversec.types;

export namespace wv::attr {

enum class HandleKind : uint32_t {
    File=0, FileMapping=1,
    Event=10, Mutex=11, Semaphore=12, Timer=13,
    Thread=20, Process=21, Job=22,
    Registry=30, Service=31, SCManager=32,
    Find=40, ChangeNotification=41,
    Memory=50,
    Bitmap=60, Brush=61, Font=62, Pen=63, Region=64,
    DC=70, Window=80, Icon=81, Cursor=82,
    Mailslot=90, Pipe=91, Socket=92, AC=93,
    DeviceIoControl=100,
    Clipboard=110, Desktop=111, WindowStation=112,
    Monitor=120, Menu=121, AcceleratorTable=122,
    Palette=130, MetaFile=131, EnhancedMetaFile=132, GLRC=140,
};

enum class HandleOwnership : uint32_t { Owned=0, Borrowed=1 };

inline Attribute make_handle_kind(HandleKind k) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="HandleKind";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)k));
    return a;
}

inline Attribute make_handle_ownership(HandleOwnership o) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="HandleOwnership";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)o));
    return a;
}

inline Attribute make_close_function(const std::string& fn) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="CloseFunction";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, fn));
    return a;
}

inline Attribute make_handle_access(uint32_t access) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="HandleAccess";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)access));
    return a;
}

enum class BufferKind : uint32_t {
    None=0, Input=1, Output=2, InOut=3,
    InputString=4, OutputString=5, InOutString=6,
    FixedLength=7, VariableLength=8, Optional=9,
};

struct BufferSemanticsInfo {
    uint32_t param_index = 0;
    BufferKind kind = BufferKind::Input;
    std::string count_param;
    std::string count_expression;
    uint32_t constant_count = 0;
    bool is_byte_count = false;
    bool is_wide = true;
};

inline Attribute make_buffer_semantics(const BufferSemanticsInfo& i) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="BufferSemantics";
    a.positional.push_back(AttrVal(AttrVal::Kind::Int, (int64_t)i.param_index));
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)i.kind));
    if(!i.count_param.empty()) a.args.push_back(AttrArg("CountParam", AttrVal(AttrVal::Kind::String, i.count_param)));
    if(!i.count_expression.empty()) a.args.push_back(AttrArg("CountExpression", AttrVal(AttrVal::Kind::String, i.count_expression)));
    if(i.constant_count>0) a.args.push_back(AttrArg("Constant", AttrVal(AttrVal::Kind::UInt, (uint64_t)i.constant_count)));
    a.args.push_back(AttrArg("IsByteCount", AttrVal(AttrVal::Kind::Bool, i.is_byte_count)));
    a.args.push_back(AttrArg("IsWideString", AttrVal(AttrVal::Kind::Bool, i.is_wide)));
    return a;
}

inline Attribute make_buffer_length(const std::string& expr) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="BufferLength";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, expr));
    return a;
}

inline Attribute make_buffer_null(uint32_t sem) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="BufferNull";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)sem));
    return a;
}

inline Attribute make_buffer_type(const std::string& type_name) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="BufferType";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, type_name));
    return a;
}

inline Attribute make_calling_convention(CC conv) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="CallingConvention";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)conv));
    return a;
}

enum class InlineKind : uint32_t { None=0, Normal=1, ForceInline=2 };

inline Attribute make_inline_function(InlineKind k) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="InlineFunction";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)k));
    return a;
}

inline Attribute make_callback_delegate(CC conv = CC::Std) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="CallbackDelegate";
    a.args.push_back(AttrArg("Convention", AttrVal(AttrVal::Kind::UInt, (uint64_t)conv)));
    return a;
}

inline Attribute make_callback_convention(CC conv) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="CallbackConvention";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)conv));
    return a;
}

inline Attribute make_callback_optional() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="CallbackOptional";
    return a;
}

enum class IoctlMethod : uint32_t { Buffered=0, InDirect=1, OutDirect=2, Neither=3 };
enum class IoctlAccess : uint32_t { Any=0, Read=1, Write=2, ReadWrite=3 };

struct IoctlCodeInfo {
    uint32_t raw_code=0, device_type=0, function_code=0;
    IoctlMethod method=IoctlMethod::Buffered;
    IoctlAccess access=IoctlAccess::Any;
};

inline Attribute make_ioctl_code(const IoctlCodeInfo& i) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="IoctlCode";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)i.raw_code));
    a.args.push_back(AttrArg("DeviceType", AttrVal(AttrVal::Kind::UInt, (uint64_t)i.device_type)));
    a.args.push_back(AttrArg("FunctionCode", AttrVal(AttrVal::Kind::UInt, (uint64_t)i.function_code)));
    a.args.push_back(AttrArg("Method", AttrVal(AttrVal::Kind::UInt, (uint64_t)i.method)));
    a.args.push_back(AttrArg("Access", AttrVal(AttrVal::Kind::UInt, (uint64_t)i.access)));
    return a;
}

inline Attribute make_ioctl_buffering(uint32_t method) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="IoctlBuffering";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)method));
    return a;
}

struct ComInterfaceInfo {
    std::string iid, base_interface;
    bool dual=false, non_extensible=false, oleautomation=false;
};

inline Attribute make_com_interface(const ComInterfaceInfo& i) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ComInterface";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, i.iid));
    a.args.push_back(AttrArg("BaseInterface", AttrVal(AttrVal::Kind::String, i.base_interface)));
    a.args.push_back(AttrArg("Dual", AttrVal(AttrVal::Kind::Bool, i.dual)));
    a.args.push_back(AttrArg("NonExtensible", AttrVal(AttrVal::Kind::Bool, i.non_extensible)));
    a.args.push_back(AttrArg("OleAutomation", AttrVal(AttrVal::Kind::Bool, i.oleautomation)));
    return a;
}

inline Attribute make_com_method(uint32_t vtable_index) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ComMethod";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)vtable_index));
    return a;
}

inline Attribute make_com_property(uint32_t get_idx, uint32_t set_idx) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ComProperty";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)get_idx));
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)set_idx));
    return a;
}

inline Attribute make_com_event(const std::string& iid) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ComEvent";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, iid));
    return a;
}

struct ComCoClassInfo { std::string clsid, prog_id; };

inline Attribute make_com_coclass(const ComCoClassInfo& i) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ComCoClass";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, i.clsid));
    if(!i.prog_id.empty()) a.args.push_back(AttrArg("ProgId", AttrVal(AttrVal::Kind::String, i.prog_id)));
    return a;
}

inline Attribute make_architecture(Ar arch) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Architecture";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)(uint32_t)arch));
    return a;
}

inline Attribute make_pointer_size(uint32_t sz) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="PointerSize";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)sz));
    return a;
}

inline Attribute make_pack(uint32_t v) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Pack";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)v));
    return a;
}

struct ImportLibraryInfo { std::string dll, entry_point; uint16_t ordinal=0; };

inline Attribute make_import_library(const ImportLibraryInfo& i) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ImportLibrary";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, i.dll));
    if(!i.entry_point.empty()) a.args.push_back(AttrArg("EntryPoint", AttrVal(AttrVal::Kind::String, i.entry_point)));
    if(i.ordinal>0) a.args.push_back(AttrArg("Ordinal", AttrVal(AttrVal::Kind::UInt, (uint64_t)i.ordinal)));
    return a;
}

inline Attribute make_dll_import(const std::string& dll) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="DllImport";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, dll));
    return a;
}

inline Attribute make_export_function(const std::string& name) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="ExportFunction";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, name));
    return a;
}

inline Attribute make_flags() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="EnumFlags";
    return a;
}

inline Attribute make_enum_combination() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="EnumCombination";
    return a;
}

inline Attribute make_enum_power_of2() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="EnumPowerOf2";
    return a;
}

enum class StringEncoding : uint32_t { Ansi=0, Unicode=1, Auto=2 };

inline Attribute make_string_encoding(StringEncoding enc) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="StringEncoding";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)enc));
    return a;
}

inline Attribute make_string_null(uint32_t sem) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="StringNull";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)sem));
    return a;
}

inline Attribute make_string_max_length(const std::string& expr) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="StringMaxLength";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, expr));
    return a;
}

inline Attribute make_last_error() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="LastError"; return a;
}

inline Attribute make_hresult() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="HRESULT";
    return a;
}

inline Attribute make_nt_status() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="NTStatus";
    return a;
}

inline Attribute make_win32_error() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Win32Error";
    return a;
}

inline Attribute make_must_check() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="MustCheck"; return a;
}
inline Attribute make_no_throw() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="NoThrow"; return a;
}
inline Attribute make_nullable_result() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="NullableResult"; return a;
}

inline Attribute make_platform_supported(const std::string& v) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="PlatformSupported";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, v));
    return a;
}

inline Attribute make_platform(uint32_t p) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Platform";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)p));
    return a;
}

inline Attribute make_obsolete(const std::string& msg, const std::string& since="") {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Obsolete";
    a.args.push_back(AttrArg("Message", AttrVal(AttrVal::Kind::String, msg)));
    if(!since.empty()) a.args.push_back(AttrArg("Since", AttrVal(AttrVal::Kind::String, since)));
    return a;
}

enum class TypeKindVal : uint32_t { Struct=0, Enum=1, Union=2, Class=3, Interface=4, Delegate=5 };

inline Attribute make_type_kind(TypeKindVal k) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="TypeKind";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)k));
    return a;
}

inline Attribute make_type_forward(const std::string& target) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="TypeForward";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, target));
    return a;
}

enum class PrimitiveTypeVal : uint32_t {
    Void=0, Bool=1, I1=2, U1=3, I2=4, U2=5, I4=6, U4=7,
    I8=8, U8=9, R4=10, R8=11, Char=12, String=13,
};

inline Attribute make_primitive_type(PrimitiveTypeVal t) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="PrimitiveType";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)t));
    return a;
}

inline Attribute make_guid(const std::string& guid) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Guid";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, guid));
    return a;
}

inline Attribute make_constant() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Constant";
    return a;
}

inline Attribute make_namespace(const std::string& ns_val) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Namespace";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, ns_val));
    return a;
}

inline Attribute make_header(const std::string& hdr) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Header";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, hdr));
    return a;
}

enum class StructLayoutKind : uint32_t { Sequential=0, Explicit=1 };

inline Attribute make_struct_layout(StructLayoutKind k, uint32_t pack_val=0) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="StructLayout";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)k));
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)pack_val));
    return a;
}

inline Attribute make_struct_size(const std::string& expr) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="StructSize";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, expr));
    return a;
}

inline Attribute make_union() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Union";
    return a;
}

inline Attribute make_anonymous_struct() {
    Attribute a; a.ns="Winverse.Attributes"; a.name="AnonymousStruct";
    return a;
}

enum class DriverTypeVal : uint32_t { KMDF=0, UMDF=1, WDF=2, WDM=3 };

inline Attribute make_driver_type(DriverTypeVal k) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="DriverType";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)k));
    return a;
}

inline Attribute make_driver_dispatch(uint32_t major, uint32_t minor=0) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="DriverDispatch";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)major));
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)minor));
    return a;
}

inline Attribute make_irp_mj(uint32_t mj) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="IrpMajorFunction";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)mj));
    return a;
}

inline Attribute make_wdf_object(uint32_t kind) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="WdfObject";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)kind));
    return a;
}

inline Attribute make_power_state(uint32_t state) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Power";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)state));
    return a;
}

inline Attribute make_pnp_state(uint32_t state) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Pnp";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)state));
    return a;
}

inline Attribute make_contract(const std::string& name, uint32_t ver) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Contract";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, name));
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)ver));
    return a;
}

inline Attribute make_variant(const std::string& name) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Variant";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, name));
    return a;
}

inline Attribute make_feature(const std::string& name) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Feature";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, name));
    return a;
}

inline Attribute make_partition(const std::string& name) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="Partition";
    a.positional.push_back(AttrVal(AttrVal::Kind::String, name));
    return a;
}

enum class FuncCategory : uint32_t {
    Unknown=0, WindowManagement, FileSystem, Registry, Security, Cryptography,
    Network, WinSock, Graphics, Gdi, Direct3D, DirectX,
    Audio, Multimedia, MediaFoundation, Printing,
    COM, COM_StructuredStorage,
    Threading, IO, Memory, Process, JobObjects, Pipes,
    Services, DeviceManager, Configuration,
    Diagnostics, Debug, RemoteDesktop, GroupPolicy,
    Setup, Clipboard, Shell, HiDpi, Controls, Dialogs,
    Notifications, WiFi, NetworkManagement, FilteringPlatform,
    Smartcard, Credentials, Environment, String, Globalization,
    Performance, ToolHelp, ActiveX, Xml,
    Drivers, WDF, KMDF, UMDF, IRP, PnP, PowerManagement, WMI,
};

inline Attribute make_function_category(FuncCategory c) {
    Attribute a; a.ns="Winverse.Attributes"; a.name="FunctionCategory";
    a.positional.push_back(AttrVal(AttrVal::Kind::UInt, (uint64_t)c));
    return a;
}

} // namespace wv::attr
