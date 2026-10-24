// driver.ixx - KMDF/UMDF/WDF driver API support and IRP metadata
// Copyright (c) 2026 Momin Shaikh. All rights reserved.
module;

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>

export module winversec.driver;
import winversec.types;
import winversec.attributes;

export namespace wv {

struct DriverApiInfo {
    std::string fn_name;
    std::string dll;         // ntoskrnl.exe, wdfldr.dll, etc.
    bool is_wdf = false;     // WDF framework function
    bool is_kmdf = false;
};

class DriverEnricher {
public:
    State& st;
    explicit DriverEnricher(State& s) : st(s) {}

    // KMDF/UMDF framework function DLL mappings
    static inline const std::unordered_map<std::string, std::string> KMDF_DLLS = {
        // Device
        {"WdfDeviceCreate","wdfldr.dll"},{"WdfDeviceWdmGetDeviceObject","wdfldr.dll"},
        {"WdfDeviceGetDeviceIoTarget","wdfldr.dll"},
        {"WdfDeviceInitSetIoInCallerContextCallback","wdfldr.dll"},
        {"WdfDeviceInitSetPnpDispatchCallback","wdfldr.dll"},
        {"WdfDeviceInitSetPowerDispatchCallback","wdfldr.dll"},
        {"WdfDeviceInitSetFxDriverCallback","wdfldr.dll"},
        {"WdfDeviceSetRequestDispatchCallback","wdfldr.dll"},
        {"WdfDeviceWdmGetAttachedDeviceObject","wdfldr.dll"},
        {"WdfDeviceWdmGetDeviceObject","wdfldr.dll"},
        {"WdfDeviceSetFailed","wdfldr.dll"},
        {"WdfDeviceWdmGetPhysicalDevice","wdfldr.dll"},
        {"WdfDeviceAssignS0IdleSettings","wdfldr.dll"},
        {"WdfDeviceAssignS0WakeSettings","wdfldr.dll"},
        {"WdfDeviceSetFailed","wdfldr.dll"},
        {"WdfDeviceStopIdle","wdfldr.dll"},{"WdfDeviceStart","wdfldr.dll"},
        {"WdfDeviceFinishInitializing","wdfldr.dll"},
        {"WdfDeviceSetDeviceCapabilities","wdfldr.dll"},
        {"WdfDeviceSetDeviceCapabilities","wdfldr.dll"},
        {"WdfDeviceGetDeviceCapabilities","wdfldr.dll"},
        {"WdfDeviceGetDriver","wdfldr.dll"},
        {"WdfDeviceSetPnpCapabilities","wdfldr.dll"},
        {"WdfDeviceSetPowerCapabilities","wdfldr.dll"},

        // Driver
        {"WdfDriverCreate","wdfldr.dll"},{"WdfDriverGetRegistryPath","wdfldr.dll"},
        {"WdfDriverWdmGetDriverObject","wdfldr.dll"},{"WdfDriverOpenParametersRegistryKey","wdfldr.dll"},
        {"WdfDriverGetWdfDriverHandle","wdfldr.dll"},
        {"WdfDriverRetrieveVersionFromFileDescription","wdfldr.dll"},
        {"WdfDriverRetrieveVersionInformation","wdfldr.dll"},

        // I/O Queue
        {"WdfIoQueueCreate","wdfldr.dll"},{"WdfIoQueueGetState","wdfldr.dll"},
        {"WdfIoQueueFindRequest","wdfldr.dll"},{"WdfIoQueueRetrieveFoundRequest","wdfldr.dll"},
        {"WdfIoQueueRetrieveRequest","wdfldr.dll"},{"WdfIoQueueRetrieveNextRequest","wdfldr.dll"},
        {"WdfIoQueueStart","wdfldr.dll"},{"WdfIoQueueStop","wdfldr.dll"},
        {"WdfIoQueueDrain","wdfldr.dll"},{"WdfIoQueueDrainSynchronously","wdfldr.dll"},
        {"WdfIoQueuePurge","wdfldr.dll"},{"WdfIoQueuePurgeSynchronously","wdfldr.dll"},
        {"WdfIoQueueReadyNotify","wdfldr.dll"},
        {"WdfIoQueueGetDevice","wdfldr.dll"},{"WdfIoQueueGetFileObject","wdfldr.dll"},
        {"WdfIoQueueStopSynchronously","wdfldr.dll"},
        {"WdfIoQueueStartSynchronously","wdfldr.dll"},
        {"WdfIoQueuePurgeStop","wdfldr.dll"},{"WdfIoQueuePurgeStopSynchronously","wdfldr.dll"},
        {"WdfIoQueuePurgeStart","wdfldr.dll"},{"WdfIoQueuePurgeStartSynchronously","wdfldr.dll"},
        {"WdfIoQueueGetState","wdfldr.dll"},
        {"WdfIoQueueFindRequest","wdfldr.dll"},{"WdfIoQueueRetrieveFoundRequest","wdfldr.dll"},
        {"WdfIoQueueIsCxWdfIoQueue","wdfldr.dll"},
        {"WdfIoQueueGetDispatchType","wdfldr.dll"},
        {"WdfIoQueueGetRequestCount","wdfldr.dll"},
        {"WdfIoQueueWdmGetIoQueue","wdfldr.dll"},

        // Request
        {"WdfRequestComplete","wdfldr.dll"},{"WdfRequestCompleteWithPriorityBoost","wdfldr.dll"},
        {"WdfRequestCompleteWithInformation","wdfldr.dll"},{"WdfRequestCompleteWithInformation2","wdfldr.dll"},
        {"WdfRequestRetrieveInputBuffer","wdfldr.dll"},{"WdfRequestRetrieveOutputBuffer","wdfldr.dll"},
        {"WdfRequestRetrieveUnsafeUserInputBuffer","wdfldr.dll"},
        {"WdfRequestRetrieveUnsafeUserOutputBuffer","wdfldr.dll"},
        {"WdfRequestMarkCancelable","wdfldr.dll"},{"WdfRequestUnmarkCancelable","wdfldr.dll"},
        {"WdfRequestIsCanceled","wdfldr.dll"},{"WdfRequestGetStatus","wdfldr.dll"},
        {"WdfRequestGetIoQueue","wdfldr.dll"},{"WdfRequestSend","wdfldr.dll"},
        {"WdfRequestForwardToIoQueue","wdfldr.dll"},
        {"WdfRequestForwardToParentIoQueue","wdfldr.dll"},
        {"WdfRequestGetFileObject","wdfldr.dll"},{"WdfRequestGetRequestMode","wdfldr.dll"},
        {"WdfRequestFormatRequestUsingCurrentType","wdfldr.dll"},
        {"WdfRequestFormatRequestUsingType","wdfldr.dll"},
        {"WdfRequestFormatRequestUsingTypeAndFlags","wdfldr.dll"},
        {"WdfRequestWdmGetIrp","wdfldr.dll"},
        {"WdfRequestIsForwarded","wdfldr.dll"},
        {"WdfRequestGetInformation","wdfldr.dll"},{"WdfRequestSetInformation","wdfldr.dll"},
        {"WdfRequestGetParameters","wdfldr.dll"},
        {"WdfRequestGetIoStatus","wdfldr.dll"},
        {"WdfRequestChangeTargetQueue","wdfldr.dll"},
        {"WdfRequestChangeTargetIoQueue","wdfldr.dll"},
        {"WdfRequestChangeTargetIoQueue","wdfldr.dll"},
        {"WdfRequestGetDriver","wdfldr.dll"},{"WdfRequestGetDevice","wdfldr.dll"},
        {"WdfRequestGetFileObject","wdfldr.dll"},
        {"WdfRequestComplete","wdfldr.dll"},{"WdfRequestCompleteWithPriorityBoost","wdfldr.dll"},
        {"WdfRequestCompleteWithInformation","wdfldr.dll"},
        {"WdfRequestMarkCancelableEx","wdfldr.dll"},
        {"WdfRequestUnmarkCancelableEx","wdfldr.dll"},
        {"WdfRequestStopAcknowledge","wdfldr.dll"},
        {"WdfRequestForwardToIoQueue","wdfldr.dll"},
        {"WdfRequestForwardToParentIoQueue","wdfldr.dll"},
        {"WdfRequestGetRequestMode","wdfldr.dll"},
        {"WdfRequestRetrieveInputWdmMdl","wdfldr.dll"},
        {"WdfRequestRetrieveOutputWdmMdl","wdfldr.dll"},
        {"WdfRequestRetrieveUnsafeUserInputBuffer","wdfldr.dll"},
        {"WdfRequestRetrieveUnsafeUserOutputBuffer","wdfldr.dll"},

        // Object
        {"WdfObjectCreate","wdfldr.dll"},{"WdfObjectDelete","wdfldr.dll"},
        {"WdfObjectReference","wdfldr.dll"},{"WdfObjectDereference","wdfldr.dll"},
        {"WdfObjectReferenceActual","wdfldr.dll"},{"WdfObjectDereferenceActual","wdfldr.dll"},
        {"WdfObjectAcquireLock","wdfldr.dll"},{"WdfObjectReleaseLock","wdfldr.dll"},
        {"WdfObjectGet","wdfldr.dll"},{"WdfObjectGetImplType","wdfldr.dll"},
        {"WdfObjectGetParent","wdfldr.dll"},{"WdfObjectSetParent","wdfldr.dll"},
        {"WdfObjectGetDesktopObject","wdfldr.dll"},
        {"WdfObjectGetWdmWaitHandle","wdfldr.dll"},
        {"WdfObjectGetWdmSignalObject","wdfldr.dll"},
        {"WdfObjectGetWdmObjectId","wdfldr.dll"},

        // Timer
        {"WdfTimerCreate","wdfldr.dll"},{"WdfTimerStart","wdfldr.dll"},
        {"WdfTimerStop","wdfldr.dll"},{"WdfTimerGetDueTime","wdfldr.dll"},
        {"WdfTimerGetDevice","wdfldr.dll"},{"WdfTimerGetActiveCount","wdfldr.dll"},
        {"WdfTimerConfigure","wdfldr.dll"},
        {"WdfTimerPurge","wdfldr.dll"},{"WdfTimerPurgeSynchronously","wdfldr.dll"},

        // Work Item
        {"WdfWorkItemCreate","wdfldr.dll"},{"WdfWorkItemEnqueue","wdfldr.dll"},
        {"WdfWorkItemDequeue","wdfldr.dll"},{"WdfWorkItemFlush","wdfldr.dll"},
        {"WdfWorkItemGetDevice","wdfldr.dll"},
        {"WdfWorkItemIsQueued","wdfldr.dll"},

        // Interrupt
        {"WdfInterruptCreate","wdfldr.dll"},{"WdfInterruptGetInfo","wdfldr.dll"},
        {"WdfInterruptAcquireLock","wdfldr.dll"},{"WdfInterruptReleaseLock","wdfldr.dll"},
        {"WdfInterruptEnable","wdfldr.dll"},{"WdfInterruptDisable","wdfldr.dll"},
        {"WdfInterruptQueueDpcForIsr","wdfldr.dll"},
        {"WdfInterruptQueueWorkItemForIsr","wdfldr.dll"},
        {"WdfInterruptSynchronize","wdfldr.dll"},

        // DMA
        {"WdfDmaEnablerCreate","wdfldr.dll"},
        {"WdfDmaTransactionInitialize","wdfldr.dll"},
        {"WdfDmaTransactionExecute","wdfldr.dll"},
        {"WdfDmaTransactionRelease","wdfldr.dll"},
        {"WdfDmaTransactionAllocateResources","wdfldr.dll"},
        {"WdfDmaTransactionFreeResources","wdfldr.dll"},
        {"WdfDmaTransactionCancel","wdfldr.dll"},
        {"WdfDmaTransactionGetDeviceControlBuffer","wdfldr.dll"},
        {"WdfDmaTransactionGetCurrentScatterGather","wdfldr.dll"},
        {"WdfDmaTransactionGetLength","wdfldr.dll"},
        {"WdfDmaEnablerGetMaximumLength","wdfldr.dll"},
        {"WdfDmaEnablerGetMaximumScatterGatherElements","wdfldr.dll"},
        {"WdfCommonBufferGetAlignedVirtualAddress","wdfldr.dll"},
        {"WdfCommonBufferGetAlignedLogicalAddress","wdfldr.dll"},
        {"WdfCommonBufferGetLength","wdfldr.dll"},

        // String
        {"WdfStringCreate","wdfldr.dll"},{"WdfStringGetUnicodeString","wdfldr.dll"},
        {"WdfObjectGetUnicodeString","wdfldr.dll"},

        // Collection
        {"WdfCollectionCreate","wdfldr.dll"},{"WdfCollectionGetCount","wdfldr.dll"},
        {"WdfCollectionGetItem","wdfldr.dll"},{"WdfCollectionGetItemPointer","wdfldr.dll"},
        {"WdfCollectionAdd","wdfldr.dll"},{"WdfCollectionRemove","wdfldr.dll"},
        {"WdfCollectionRemoveItem","wdfldr.dll"},{"WdfCollectionClear","wdfldr.dll"},
        {"WdfCollectionFindItem","wdfldr.dll"},

        // CmResourceList
        {"WdfCmResourceListAppendDescriptor","wdfldr.dll"},
        {"WdfCmResourceListGetCount","wdfldr.dll"},
        {"WdfCmResourceListGetDescriptor","wdfldr.dll"},
        {"WdfCmResourceListGetDescriptorByType","wdfldr.dll"},
        {"WdfCmResourceListRemove","wdfldr.dll"},
        {"WdfCmResourceListGetDevice","wdfldr.dll"},

        // Registry
        {"WdfRegistryQueryValue","wdfldr.dll"},{"WdfRegistryQueryString","wdfldr.dll"},
        {"WdfRegistryQueryMultiString","wdfldr.dll"},
        {"WdfRegistryAssignValue","wdfldr.dll"},{"WdfRegistryAssignString","wdfldr.dll"},
        {"WdfRegistryAssignMultiString","wdfldr.dll"},
        {"WdfRegistryOpenKey","wdfldr.dll"},{"WdfRegistryOpenSubKey","wdfldr.dll"},
        {"WdfRegistryClose","wdfldr.dll"},{"WdfRegistryDeleteValue","wdfldr.dll"},

        // Child List
        {"WdfChildListCreate","wdfldr.dll"},{"WdfChildListGetDevice","wdfldr.dll"},
        {"WdfChildListInsert","wdfldr.dll"},{"WdfChildListRemove","wdfldr.dll"},
        {"WdfChildListUpdate","wdfldr.dll"},{"WdfChildListRetrieveDescriptor","wdfldr.dll"},

        // File Object
        {"WdfFileObjectGetFileName","wdfldr.dll"},{"WdfFileObjectGetFlags","wdfldr.dll"},
        {"WdfFileObjectGetDevice","wdfldr.dll"},{"WdfFileObjectWdmGetFileObject","wdfldr.dll"},

        // Verifier
        {"WdfVerifierDbgBreakPoint","wdfldr.dll"},{"WdfVerifierKeBugCheckEx","wdfldr.dll"},
        {"WdfGetTriageInfo","wdfldr.dll"},
        {"WdfVerifierPrintMemoryLeak","wdfldr.dll"},
        {"WdfVerifierCheckActiveVerifiers","wdfldr.dll"},
        {"WdfVerifierDbgBreakPoint","wdfldr.dll"},
    };

    // Kernel-mode only functions (ntoskrnl.exe)
    static inline const std::unordered_map<std::string, std::string> NTOSKRNL_DLLS = {
        // I/O manager
        {"IoCreateDevice","ntoskrnl.exe"},{"IoDeleteDevice","ntoskrnl.exe"},
        {"IoCreateSymbolicLink","ntoskrnl.exe"},{"IoDeleteSymbolicLink","ntoskrnl.exe"},
        {"IoCallDriver","ntoskrnl.exe"},{"IofCallDriver","ntoskrnl.exe"},
        {"IoCompleteRequest","ntoskrnl.exe"},{"IoAllocateIrp","ntoskrnl.exe"},
        {"IoFreeIrp","ntoskrnl.exe"},{"IoAllocateMdl","ntoskrnl.exe"},
        {"IoFreeMdl","ntoskrnl.exe"},{"IoBuildSynchronousFsdRequest","ntoskrnl.exe"},
        {"IoBuildDeviceIoControlRequest","ntoskrnl.exe"},
        {"IoRegisterDriverReinitialization","ntoskrnl.exe"},
        {"IoRegisterPlugPlayNotification","ntoskrnl.exe"},
        {"IoUnregisterPlugPlayNotification","ntoskrnl.exe"},
        {"IoSetDeviceInterfaceState","ntoskrnl.exe"},
        {"IoGetDeviceInterfaces","ntoskrnl.exe"},
        {"IoOpenDeviceRegistryKey","ntoskrnl.exe"},
        {"IoGetDeviceProperty","ntoskrnl.exe"},
        {"IoReportTargetDeviceChange","ntoskrnl.exe"},
        {"IoReportDetectedDevice","ntoskrnl.exe"},
        {"IoInvalidateDeviceRelations","ntoskrnl.exe"},
        {"IoRequestDeviceEject","ntoskrnl.exe"},
        {"IoGetCurrentProcess","ntoskrnl.exe"},
        {"IoGetCurrentThread","ntoskrnl.exe"},
        {"IoGetStackLimits","ntoskrnl.exe"},
        {"IoGetDeviceObjectPointer","ntoskrnl.exe"},
        {"IoReferenceDeviceObject","ntoskrnl.exe"},
        {"IoDereferenceDeviceObject","ntoskrnl.exe"},
        {"IoGetRelatedDeviceObject","ntoskrnl.exe"},
        {"IoGetDeviceToVerify","ntoskrnl.exe"},
        {"IoSetDeviceToVerify","ntoskrnl.exe"},
        {"IoVerifyPartitionTable","ntoskrnl.exe"},
        {"IoReadPartitionTable","ntoskrnl.exe"},
        {"IoWritePartitionTable","ntoskrnl.exe"},
        {"IoCreateNotificationEvent","ntoskrnl.exe"},
        {"IoCreateSynchronizationEvent","ntoskrnl.exe"},
        {"IoCheckEaBufferValidity","ntoskrnl.exe"},
        {"IoVolumeDeviceToDosName","ntoskrnl.exe"},
        {"IoQueryDeviceDosName","ntoskrnl.exe"},
        {"IoCopyCurrentStackLocationToNext","ntoskrnl.exe"},
        {"IoSkipCurrentIrpStackLocation","ntoskrnl.exe"},
        {"IoAllocateDriverObjectExtension","ntoskrnl.exe"},
        {"IoGetDriverObjectExtension","ntoskrnl.exe"},
        {"IoRegisterFsRegistrationChange","ntoskrnl.exe"},
        {"IoUnregisterFsRegistrationChange","ntoskrnl.exe"},
        {"IoRegisterFsRegistrationChangeEx","ntoskrnl.exe"},
        {"IoCreateFile","ntoskrnl.exe"},{"IoCreateFileEx","ntoskrnl.exe"},
        {"IoOpenDeviceInterfaceRegistryKey","ntoskrnl.exe"},
        {"IoOpenDeviceRegistryKey","ntoskrnl.exe"},
        {"IoGetDevicePropertyData","ntoskrnl.exe"},
        {"IoSetDevicePropertyData","ntoskrnl.exe"},
        {"IoRegisterDeviceInterface","ntoskrnl.exe"},
        {"IoSetDeviceInterfaceState","ntoskrnl.exe"},
        {"IoGetDeviceNumaNode","ntoskrnl.exe"},
        {"IoReplacePartitionUnit","ntoskrnl.exe"},

        // Kernel primitives
        {"KeInitializeEvent","ntoskrnl.exe"},{"KeSetEvent","ntoskrnl.exe"},
        {"KeWaitForSingleObject","ntoskrnl.exe"},{"KeWaitForMultipleObjects","ntoskrnl.exe"},
        {"KeResetEvent","ntoskrnl.exe"},{"KeClearEvent","ntoskrnl.exe"},
        {"KeAcquireSpinLockRaiseToDpc","ntoskrnl.exe"},{"KeReleaseSpinLock","ntoskrnl.exe"},
        {"KeAcquireInStackQueuedSpinLock","ntoskrnl.exe"},
        {"KeReleaseInStackQueuedSpinLock","ntoskrnl.exe"},
        {"KeInitializeSpinLock","ntoskrnl.exe"},
        {"KeGetCurrentIrql","ntoskrnl.exe"},
        {"KeRaiseIrql","ntoskrnl.exe"},{"KeLowerIrql","ntoskrnl.exe"},
        {"KeInitializeDpc","ntoskrnl.exe"},{"KeInsertQueueDpc","ntoskrnl.exe"},
        {"KeRemoveQueueDpc","ntoskrnl.exe"},
        {"KeInitializeTimer","ntoskrnl.exe"},{"KeInitializeTimerEx","ntoskrnl.exe"},
        {"KeSetTimer","ntoskrnl.exe"},{"KeSetTimerEx","ntoskrnl.exe"},
        {"KeCancelTimer","ntoskrnl.exe"},{"KeReadStateTimer","ntoskrnl.exe"},
        {"KeInitializeQueue","ntoskrnl.exe"},{"KeInsertQueue","ntoskrnl.exe"},
        {"KeRemoveQueue","ntoskrnl.exe"},{"KeRundownQueue","ntoskrnl.exe"},
        {"KeInitializeApc","ntoskrnl.exe"},{"KeInsertQueueApc","ntoskrnl.exe"},
        {"KeFlushQueuedApcs","ntoskrnl.exe"},
        {"KeAcquireGuardedMutex","ntoskrnl.exe"},{"KeReleaseGuardedMutex","ntoskrnl.exe"},
        {"KeInitializeGuardedMutex","ntoskrnl.exe"},
        {"KeEnterCriticalRegion","ntoskrnl.exe"},{"KeLeaveCriticalRegion","ntoskrnl.exe"},
        {"KeGetCurrentThread","ntoskrnl.exe"},{"KeGetCurrentProcessorNumber","ntoskrnl.exe"},
        {"KeQuerySystemTime","ntoskrnl.exe"},{"KeQueryTickCount","ntoskrnl.exe"},
        {"KeQueryPerformanceCounter","ntoskrnl.exe"},
        {"KeStallExecutionProcessor","ntoskrnl.exe"},
        {"KeBugCheckEx","ntoskrnl.exe"},{"KeBugCheck","ntoskrnl.exe"},
        {"KeInitializeMutant","ntoskrnl.exe"},{"KeReleaseMutant","ntoskrnl.exe"},
        {"KeInitializeSemaphore","ntoskrnl.exe"},{"KeReleaseSemaphore","ntoskrnl.exe"},
        {"KeReadStateSemaphore","ntoskrnl.exe"},{"KeReadStateMutant","ntoskrnl.exe"},
        {"KeTryToAcquireGuardedMutex","ntoskrnl.exe"},
        {"KeAcquireSpinLock","ntoskrnl.exe"},{"KeReleaseSpinLock","ntoskrnl.exe"},
        {"KeAcquireSpinLockAtDpcLevel","ntoskrnl.exe"},{"KeReleaseSpinLockFromDpcLevel","ntoskrnl.exe"},
        {"KeAcquireSpinLockRaiseToSynch","ntoskrnl.exe"},
        {"KeRaiseIrqlToDpcLevel","ntoskrnl.exe"},{"KeLowerIrql","ntoskrnl.exe"},
        {"KeInitializeEvent","ntoskrnl.exe"},{"KeSetEvent","ntoskrnl.exe"},
        {"KeResetEvent","ntoskrnl.exe"},{"KeClearEvent","ntoskrnl.exe"},
        {"KeWaitForSingleObject","ntoskrnl.exe"},{"KeWaitForMultipleObjects","ntoskrnl.exe"},
        {"KeInitializeSpinLock","ntoskrnl.exe"},{"KeAcquireSpinLockRaiseToDpc","ntoskrnl.exe"},
        {"KeReleaseSpinLock","ntoskrnl.exe"},
        {"KeAcquireInStackQueuedSpinLockAtDpcLevel","ntoskrnl.exe"},
        {"KeReleaseInStackQueuedSpinLockFromDpcLevel","ntoskrnl.exe"},
        {"KeGetCurrentIrql","ntoskrnl.exe"},{"KeRaiseIrql","ntoskrnl.exe"},{"KeLowerIrql","ntoskrnl.exe"},
        {"KeInitializeDpc","ntoskrnl.exe"},{"KeInsertQueueDpc","ntoskrnl.exe"},{"KeRemoveQueueDpc","ntoskrnl.exe"},
        {"KeSetDpcRoutine","ntoskrnl.exe"},{"KeSetDpcRoutineAndArgument","ntoskrnl.exe"},
        {"KeInitializeTimer","ntoskrnl.exe"},{"KeInitializeTimerEx","ntoskrnl.exe"},
        {"KeSetTimer","ntoskrnl.exe"},{"KeSetTimerEx","ntoskrnl.exe"},{"KeCancelTimer","ntoskrnl.exe"},{"KeReadStateTimer","ntoskrnl.exe"},
        {"KeInitializeQueue","ntoskrnl.exe"},{"KeInsertQueue","ntoskrnl.exe"},{"KeRemoveQueue","ntoskrnl.exe"},{"KeRundownQueue","ntoskrnl.exe"},
        {"KeInitializeApc","ntoskrnl.exe"},{"KeInsertQueueApc","ntoskrnl.exe"},{"KeFlushQueuedApcs","ntoskrnl.exe"},
        {"KeAcquireGuardedMutex","ntoskrnl.exe"},{"KeReleaseGuardedMutex","ntoskrnl.exe"},{"KeInitializeGuardedMutex","ntoskrnl.exe"},{"KeTryToAcquireGuardedMutex","ntoskrnl.exe"},
        {"KeEnterCriticalRegion","ntoskrnl.exe"},{"KeLeaveCriticalRegion","ntoskrnl.exe"},
        {"KeGetCurrentThread","ntoskrnl.exe"},{"KeGetCurrentProcessorNumber","ntoskrnl.exe"},
        {"KeQuerySystemTime","ntoskrnl.exe"},{"KeQueryTickCount","ntoskrnl.exe"},{"KeQueryPerformanceCounter","ntoskrnl.exe"},
        {"KeStallExecutionProcessor","ntoskrnl.exe"},
        {"KeBugCheckEx","ntoskrnl.exe"},{"KeBugCheck","ntoskrnl.exe"},
        {"KeInitializeMutant","ntoskrnl.exe"},{"KeReleaseMutant","ntoskrnl.exe"},
        {"KeInitializeSemaphore","ntoskrnl.exe"},{"KeReleaseSemaphore","ntoskrnl.exe"},
        {"KeReadStateSemaphore","ntoskrnl.exe"},{"KeReadStateMutant","ntoskrnl.exe"},

        // Executive
        {"ExAllocatePool","ntoskrnl.exe"},{"ExAllocatePoolWithTag","ntoskrnl.exe"},
        {"ExAllocatePool2","ntoskrnl.exe"},{"ExAllocatePoolWithQuota","ntoskrnl.exe"},
        {"ExFreePool","ntoskrnl.exe"},{"ExFreePoolWithTag","ntoskrnl.exe"},
        {"ExInitializeFastMutex","ntoskrnl.exe"},
        {"ExAcquireFastMutex","ntoskrnl.exe"},{"ExReleaseFastMutex","ntoskrnl.exe"},
        {"ExAcquireFastMutexUnsafe","ntoskrnl.exe"},{"ExReleaseFastMutexUnsafe","ntoskrnl.exe"},
        {"ExInitializeResourceLite","ntoskrnl.exe"},{"ExAcquireResourceExclusiveLite","ntoskrnl.exe"},
        {"ExAcquireSharedStarveExclusive","ntoskrnl.exe"},{"ExAcquireSharedWaitForExclusive","ntoskrnl.exe"},
        {"ExReleaseResourceLite","ntoskrnl.exe"},{"ExDeleteResourceLite","ntoskrnl.exe"},
        {"ExInitializePushLock","ntoskrnl.exe"},{"ExAcquirePushLockExclusive","ntoskrnl.exe"},
        {"ExReleasePushLockExclusive","ntoskrnl.exe"},{"ExAcquirePushLockShared","ntoskrnl.exe"},
        {"ExReleasePushLockShared","ntoskrnl.exe"},{"ExAcquirePushLockSharedEx","ntoskrnl.exe"},
        {"ExReleasePushLockSharedEx","ntoskrnl.exe"},{"ExAcquirePushLockExclusiveEx","ntoskrnl.exe"},
        {"ExReleasePushLockExclusiveEx","ntoskrnl.exe"},{"ExfAcquirePushLockExclusive","ntoskrnl.exe"},
        {"ExfReleasePushLockExclusive","ntoskrnl.exe"},{"ExfAcquirePushLockShared","ntoskrnl.exe"},
        {"ExfReleasePushLockShared","ntoskrnl.exe"},
        {"ExInitializePagedLookasideList","ntoskrnl.exe"},{"ExDeletePagedLookasideList","ntoskrnl.exe"},
        {"ExAllocateFromPagedLookasideList","ntoskrnl.exe"},{"ExFreeToPagedLookasideList","ntoskrnl.exe"},
        {"ExInitializeNPagedLookasideList","ntoskrnl.exe"},{"ExDeleteNPagedLookasideList","ntoskrnl.exe"},
        {"ExAllocateFromNPagedLookasideList","ntoskrnl.exe"},{"ExFreeToNPagedLookasideList","ntoskrnl.exe"},
        {"ExInterlockedInsertTailList","ntoskrnl.exe"},{"ExInterlockedInsertHeadList","ntoskrnl.exe"},
        {"ExInterlockedRemoveHeadList","ntoskrnl.exe"},{"ExInterlockedFlushSList","ntoskrnl.exe"},
        {"ExInitializeSListHead","ntoskrnl.exe"},{"ExInterlockedPopEntrySList","ntoskrnl.exe"},
        {"ExInterlockedPushEntrySList","ntoskrnl.exe"},{"ExQueryDepthSList","ntoskrnl.exe"},
        {"ExGetCurrentProcessorCpuUsage","ntoskrnl.exe"},{"ExGetCurrentProcessorCounts","ntoskrnl.exe"},
        {"ExSetTimerResolution","ntoskrnl.exe"},{"ExQueryTimerResolution","ntoskrnl.exe"},
        {"ExInitializeWorkItem","ntoskrnl.exe"},{"ExQueueWorkItem","ntoskrnl.exe"},
        {"ExVerifySuite","ntoskrnl.exe"},{"ExGetSuiteData","ntoskrnl.exe"},
        {"ExUuidCreate","ntoskrnl.exe"},{"ExAllocateGenericTableEntry","ntoskrnl.exe"},
        {"ExFreeGenericTableEntry","ntoskrnl.exe"},{"ExDeleteGenericTable","ntoskrnl.exe"},
        {"ExInitializeGenericTable","ntoskrnl.exe"},{"ExInsertElementGenericTable","ntoskrnl.exe"},
        {"ExDeleteAtomTable","ntoskrnl.exe"},{"ExCreateAtomTable","ntoskrnl.exe"},
        {"ExLookupAtomInAtomTable","ntoskrnl.exe"},{"ExAddAtomToAtomTable","ntoskrnl.exe"},
        {"ExDeleteHandleTable","ntoskrnl.exe"},{"ExCreateHandleTable","ntoskrnl.exe"},
        {"ExMapHandleToPointer","ntoskrnl.exe"},{"ExDestroyHandle","ntoskrnl.exe"},
        {"ExCreateCallback","ntoskrnl.exe"},{"ExRegisterCallback","ntoskrnl.exe"},
        {"ExUnregisterCallback","ntoskrnl.exe"},{"ExNotifyCallback","ntoskrnl.exe"},
        {"ExInitializeHashTable","ntoskrnl.exe"},{"ExInsertHashTable","ntoskrnl.exe"},
        {"ExRemoveHashTable","ntoskrnl.exe"},{"ExLookupHashTable","ntoskrnl.exe"},
        {"ExDeleteHashTable","ntoskrnl.exe"},{"ExAllocateHashTable","ntoskrnl.exe"},
        {"ExQuerySystemMemoryInformation","ntoskrnl.exe"},

        // Memory manager
        {"MmGetSystemAddressForMdl","ntoskrnl.exe"},
        {"MmMapLockedPagesSpecifyCache","ntoskrnl.exe"},
        {"MmBuildMdlForNonPagedPool","ntoskrnl.exe"},
        {"MmProbeAndLockPages","ntoskrnl.exe"},{"MmUnlockPages","ntoskrnl.exe"},
        {"MmMapIoSpace","ntoskrnl.exe"},{"MmUnmapIoSpace","ntoskrnl.exe"},
        {"MmMapLockedPages","ntoskrnl.exe"},{"MmUnmapLockedPages","ntoskrnl.exe"},
        {"MmAllocateContiguousMemory","ntoskrnl.exe"},{"MmFreeContiguousMemory","ntoskrnl.exe"},
        {"MmAllocateNonCachedMemory","ntoskrnl.exe"},{"MmFreeNonCachedMemory","ntoskrnl.exe"},
        {"MmAllocatePagesForMdl","ntoskrnl.exe"},{"MmFreePagesFromMdl","ntoskrnl.exe"},
        {"MmMapPages","ntoskrnl.exe"},{"MmUnmapPages","ntoskrnl.exe"},
        {"MmGetPhysicalAddress","ntoskrnl.exe"},{"MmGetVirtualForPhysical","ntoskrnl.exe"},
        {"MmAllocateAddressSpace","ntoskrnl.exe"},{"MmFreeAddressSpace","ntoskrnl.exe"},
        {"MmAllocateMdlForIoSpace","ntoskrnl.exe"},{"MmBuildMdlForIoSpace","ntoskrnl.exe"},
        {"MmAllocateContiguousMemorySpecifyCache","ntoskrnl.exe"},
        {"MmAllocatePagesForMdlEx","ntoskrnl.exe"},
        {"MmMapVideoDisplay","ntoskrnl.exe"},{"MmUnmapVideoDisplay","ntoskrnl.exe"},
        {"MmIsDriverAddress","ntoskrnl.exe"},{"MmIsAddressValid","ntoskrnl.exe"},
        {"MmGetPhysicalMemoryRanges","ntoskrnl.exe"},{"MmGetPhysicalMemoryUsage","ntoskrnl.exe"},
        {"MmGetSystemRoutineAddress","ntoskrnl.exe"},{"MmGetDllDirectory","ntoskrnl.exe"},
        {"MmSetDllDirectory","ntoskrnl.exe"},

        // Object manager
        {"ObReferenceObjectByHandle","ntoskrnl.exe"},{"ObDereferenceObject","ntoskrnl.exe"},
        {"ObReferenceObject","ntoskrnl.exe"},{"ObDereferenceObjectEx","ntoskrnl.exe"},
        {"ObReferenceObjectByPointer","ntoskrnl.exe"},
        {"ObOpenObjectByPointer","ntoskrnl.exe"},{"ObOpenObjectByName","ntoskrnl.exe"},
        {"ObOpenObjectByHandle","ntoskrnl.exe"},{"ObCloseHandle","ntoskrnl.exe"},
        {"ObRegisterCallbacks","ntoskrnl.exe"},{"ObUnRegisterCallbacks","ntoskrnl.exe"},
        {"ObGetObjectType","ntoskrnl.exe"},{"ObQueryNameString","ntoskrnl.exe"},
        {"ObInsertObject","ntoskrnl.exe"},{"ObMakeTemporaryObject","ntoskrnl.exe"},
        {"ObCreateObject","ntoskrnl.exe"},{"ObCreateObjectEx","ntoskrnl.exe"},
        {"ObfReferenceObject","ntoskrnl.exe"},{"ObfDereferenceObject","ntoskrnl.exe"},
        {"ObfReferenceObjectEx","ntoskrnl.exe"},{"ObfDereferenceObjectEx","ntoskrnl.exe"},
        {"ObGetObjectSecurity","ntoskrnl.exe"},{"ObReleaseObjectSecurity","ntoskrnl.exe"},
        {"ObSetSecurityObjectInfo","ntoskrnl.exe"},{"ObQuerySecurityObject","ntoskrnl.exe"},

        // Process/Thread
        {"PsGetCurrentThread","ntoskrnl.exe"},{"PsGetCurrentProcess","ntoskrnl.exe"},
        {"PsGetThreadProcess","ntoskrnl.exe"},{"PsGetProcessId","ntoskrnl.exe"},
        {"PsGetThreadId","ntoskrnl.exe"},{"PsGetThreadProcessId","ntoskrnl.exe"},
        {"PsTerminateProcess","ntoskrnl.exe"},{"PsLookupProcessByProcessId","ntoskrnl.exe"},
        {"PsLookupThreadByThreadId","ntoskrnl.exe"},
        {"PsReferenceProcessByPointer","ntoskrnl.exe"},{"PsDereferenceProcess","ntoskrnl.exe"},
        {"PsReferenceThreadByPointer","ntoskrnl.exe"},{"PsDereferenceThread","ntoskrnl.exe"},
        {"PsGetProcessImageFileName","ntoskrnl.exe"},{"PsGetProcessExitStatus","ntoskrnl.exe"},
        {"PsGetProcessSectionBaseAddress","ntoskrnl.exe"},
        {"PsSetCreateProcessNotifyRoutine","ntoskrnl.exe"},
        {"PsSetCreateThreadNotifyRoutine","ntoskrnl.exe"},
        {"PsSetLoadImageNotifyRoutine","ntoskrnl.exe"},
        {"PsCreateSystemThread","ntoskrnl.exe"},{"PsTerminateSystemThread","ntoskrnl.exe"},
        {"PsGetCurrentThreadId","ntoskrnl.exe"},{"PsGetCurrentProcessId","ntoskrnl.exe"},
        {"PsGetProcessWow64Process","ntoskrnl.exe"},
        {"PsGetProcessPeb","ntoskrnl.exe"},{"PsGetProcessWow64Peb","ntoskrnl.exe"},
        {"PsGetVersion","ntoskrnl.exe"},{"PsGetKernelVersion","ntoskrnl.exe"},
        {"PsGetProductType","ntoskrnl.exe"},{"PsGetNtVersionNumber","ntoskrnl.exe"},

        // RTL
        {"RtlInitUnicodeString","ntoskrnl.exe"},{"RtlInitAnsiString","ntoskrnl.exe"},
        {"RtlCopyUnicodeString","ntoskrnl.exe"},{"RtlEqualUnicodeString","ntoskrnl.exe"},
        {"RtlCompareUnicodeString","ntoskrnl.exe"},{"RtlAnsiStringToUnicodeString","ntoskrnl.exe"},
        {"RtlUnicodeStringToAnsiString","ntoskrnl.exe"},
        {"RtlFreeUnicodeString","ntoskrnl.exe"},{"RtlFreeAnsiString","ntoskrnl.exe"},
        {"RtlUpcaseUnicodeChar","ntoskrnl.exe"},{"RtlUpcaseUnicodeString","ntoskrnl.exe"},
        {"RtlAppendUnicodeString","ntoskrnl.exe"},{"RtlAppendUnicodeToString","ntoskrnl.exe"},
        {"RtlCopyMemory","ntoskrnl.exe"},{"RtlMoveMemory","ntoskrnl.exe"},
        {"RtlZeroMemory","ntoskrnl.exe"},{"RtlFillMemory","ntoskrnl.exe"},
        {"RtlCompareMemory","ntoskrnl.exe"},{"RtlCompareMemoryUlong","ntoskrnl.exe"},
        {"RtlCaptureStackBackTrace","ntoskrnl.exe"},{"RtlWalkFrameChain","ntoskrnl.exe"},
        {"RtlUnwind","ntoskrnl.exe"},{"RtlLookupFunctionEntry","ntoskrnl.exe"},
        {"RtlVirtualUnwind","ntoskrnl.exe"},{"RtlCaptureContext","ntoskrnl.exe"},
        {"RtlpGetStackAddress","ntoskrnl.exe"},
        {"RtlDecompressBuffer","ntoskrnl.exe"},{"RtlDecompressBufferEx","ntoskrnl.exe"},
        {"RtlDecompress","ntoskrnl.exe"},{"RtlCompressBuffer","ntoskrnl.exe"},
        {"RtlGetCompressionWorkSpaceSize","ntoskrnl.exe"},
        {"RtlRandom","ntoskrnl.exe"},{"RtlRandomEx","ntoskrnl.exe"},
        {"RtlCheckRegistryKey","ntoskrnl.exe"},{"RtlOpenRegistryKey","ntoskrnl.exe"},
        {"RtlQueryRegistryValues","ntoskrnl.exe"},{"RtlWriteRegistryValue","ntoskrnl.exe"},
        {"RtlDeleteRegistryValue","ntoskrnl.exe"},{"RtlCreateRegistryKey","ntoskrnl.exe"},
        {"RtlCheckRegistryKey","ntoskrnl.exe"},
        {"RtlCreateSecurityDescriptor","ntoskrnl.exe"},{"RtlSetDaclSecurityDescriptor","ntoskrnl.exe"},
        {"RtlGetDaclSecurityDescriptor","ntoskrnl.exe"},
        {"RtlCreateAcl","ntoskrnl.exe"},{"RtlAddAccessAllowedAce","ntoskrnl.exe"},
        {"RtlAddAccessDeniedAce","ntoskrnl.exe"},{"RtlAddAuditAccessAce","ntoskrnl.exe"},
        {"RtlAddAce","ntoskrnl.exe"},{"RtlDeleteAce","ntoskrnl.exe"},
        {"RtlGetAce","ntoskrnl.exe"},{"RtlCreateSid","ntoskrnl.exe"},
        {"RtlCopySid","ntoskrnl.exe"},{"RtlEqualSid","ntoskrnl.exe"},
        {"RtlLengthSid","ntoskrnl.exe"},{"RtlFreeSid","ntoskrnl.exe"},
        {"RtlIdentifierAuthoritySid","ntoskrnl.exe"},{"RtlSubAuthoritySid","ntoskrnl.exe"},
        {"RtlSubAuthorityCountSid","ntoskrnl.exe"},
        {"RtlConvertSidToUnicodeString","ntoskrnl.exe"},
        {"RtlDeriveCapabilitySidsFromName","ntoskrnl.exe"},
        {"RtlCreateSystemVolumeInformationFolder","ntoskrnl.exe"},

        // Zw/Nt system calls
        {"ZwCreateFile","ntoskrnl.exe"},{"ZwReadFile","ntoskrnl.exe"},{"ZwWriteFile","ntoskrnl.exe"},
        {"ZwClose","ntoskrnl.exe"},{"ZwCreateKey","ntoskrnl.exe"},{"ZwOpenKey","ntoskrnl.exe"},
        {"ZwQueryValueKey","ntoskrnl.exe"},{"ZwSetValueKey","ntoskrnl.exe"},
        {"ZwDeleteKey","ntoskrnl.exe"},{"ZwEnumerateKey","ntoskrnl.exe"},
        {"ZwQuerySystemInformation","ntoskrnl.exe"},{"ZwSetSystemInformation","ntoskrnl.exe"},
        {"ZwQueryInformationProcess","ntoskrnl.exe"},{"ZwSetInformationProcess","ntoskrnl.exe"},
        {"ZwQueryInformationThread","ntoskrnl.exe"},{"ZwSetInformationThread","ntoskrnl.exe"},
        {"ZwOpenProcess","ntoskrnl.exe"},{"ZwOpenThread","ntoskrnl.exe"},
        {"ZwCreateSection","ntoskrnl.exe"},{"ZwOpenSection","ntoskrnl.exe"},
        {"ZwMapViewOfSection","ntoskrnl.exe"},{"ZwUnmapViewOfSection","ntoskrnl.exe"},
        {"ZwQuerySection","ntoskrnl.exe"},{"ZwExtendSection","ntoskrnl.exe"},
        {"ZwCreateEvent","ntoskrnl.exe"},{"ZwSetEvent","ntoskrnl.exe"},
        {"ZwClearEvent","ntoskrnl.exe"},{"ZwResetEvent","ntoskrnl.exe"},
        {"ZwWaitForSingleObject","ntoskrnl.exe"},{"ZwWaitForMultipleObjects","ntoskrnl.exe"},
        {"ZwCreateMutant","ntoskrnl.exe"},{"ZwOpenMutant","ntoskrnl.exe"},
        {"ZwReleaseMutant","ntoskrnl.exe"},
        {"ZwCreateSemaphore","ntoskrnl.exe"},{"ZwOpenSemaphore","ntoskrnl.exe"},
        {"ZwReleaseSemaphore","ntoskrnl.exe"},
        {"ZwCreateTimer","ntoskrnl.exe"},{"ZwOpenTimer","ntoskrnl.exe"},
        {"ZwSetTimer","ntoskrnl.exe"},{"ZwCancelTimer","ntoskrnl.exe"},
        {"ZwQuerySystemTime","ntoskrnl.exe"},{"ZwSetSystemTime","ntoskrnl.exe"},
        {"ZwCreateIoCompletion","ntoskrnl.exe"},{"ZwOpenIoCompletion","ntoskrnl.exe"},
        {"ZwSetIoCompletion","ntoskrnl.exe"},{"ZwRemoveIoCompletion","ntoskrnl.exe"},
        {"ZwCreatePort","ntoskrnl.exe"},{"ZwConnectPort","ntoskrnl.exe"},
        {"ZwListenPort","ntoskrnl.exe"},{"ZwAcceptConnectPort","ntoskrnl.exe"},
        {"ZwRequestPort","ntoskrnl.exe"},{"ZwRequestWaitReplyPort","ntoskrnl.exe"},
        {"ZwReplyWaitReceivePort","ntoskrnl.exe"},{"ZwReplyWaitReceivePortEx","ntoskrnl.exe"},
        {"ZwImpersonateAnonymousToken","ntoskrnl.exe"},{"ZwRevertToSelf","ntoskrnl.exe"},
        {"ZwOpenThreadToken","ntoskrnl.exe"},{"ZwOpenThreadTokenEx","ntoskrnl.exe"},
        {"ZwOpenProcessToken","ntoskrnl.exe"},{"ZwOpenProcessTokenEx","ntoskrnl.exe"},
        {"ZwSetInformationThread","ntoskrnl.exe"},{"ZwQueryInformationThread","ntoskrnl.exe"},
        {"ZwQueryInformationToken","ntoskrnl.exe"},{"ZwSetInformationToken","ntoskrnl.exe"},
        {"ZwCreateProfile","ntoskrnl.exe"},{"ZwStartProfile","ntoskrnl.exe"},
        {"ZwStopProfile","ntoskrnl.exe"},{"ZwQueryProfile","ntoskrnl.exe"},
        {"ZwCreateUserProcess","ntoskrnl.exe"},
        {"ZwAllocateVirtualMemory","ntoskrnl.exe"},{"ZwFreeVirtualMemory","ntoskrnl.exe"},
        {"ZwReadVirtualMemory","ntoskrnl.exe"},{"ZwWriteVirtualMemory","ntoskrnl.exe"},
        {"ZwQueryVirtualMemory","ntoskrnl.exe"},{"ZwProtectVirtualMemory","ntoskrnl.exe"},
        {"ZwFlushVirtualMemory","ntoskrnl.exe"},{"ZwLockVirtualMemory","ntoskrnl.exe"},
        {"ZwUnlockVirtualMemory","ntoskrnl.exe"},
        {"ZwCreateNamedPipeFile","ntoskrnl.exe"},{"ZwCreateMailslotFile","ntoskrnl.exe"},
        {"ZwFsControlFile","ntoskrnl.exe"},{"ZwDeviceIoControlFile","ntoskrnl.exe"},
        {"ZwNotifyChangeKey","ntoskrnl.exe"},{"ZwNotifyChangeSession","ntoskrnl.exe"},
        {"ZwLoadDriver","ntoskrnl.exe"},{"ZwUnloadDriver","ntoskrnl.exe"},
        {"ZwSetDefaultHardErrorPort","ntoskrnl.exe"},
        {"ZwRaiseHardError","ntoskrnl.exe"},
        {"ZwAddAtom","ntoskrnl.exe"},{"ZwDeleteAtom","ntoskrnl.exe"},{"ZwFindAtom","ntoskrnl.exe"},
        {"ZwQueryInformationAtom","ntoskrnl.exe"},
        {"ZwDisplayString","ntoskrnl.exe"},{"ZwInitiatePowerAction","ntoskrnl.exe"},
        {"ZwRequestPowerIrp","ntoskrnl.exe"},{"ZwPowerInformation","ntoskrnl.exe"},

        // HAL
        {"HalGetInterruptVector","ntoskrnl.exe"},{"HalTranslateBusAddress","ntoskrnl.exe"},
        {"READ_REGISTER_BUFFER_UCHAR","ntoskrnl.exe"},
        {"WRITE_REGISTER_BUFFER_UCHAR","ntoskrnl.exe"},
        {"READ_PORT_UCHAR","ntoskrnl.exe"},{"WRITE_PORT_UCHAR","ntoskrnl.exe"},
        {"READ_REGISTER_UCHAR","ntoskrnl.exe"},{"WRITE_REGISTER_UCHAR","ntoskrnl.exe"},
        {"READ_PORT_BUFFER_UCHAR","ntoskrnl.exe"},{"WRITE_PORT_BUFFER_UCHAR","ntoskrnl.exe"},
        {"READ_REGISTER_BUFFER_USHORT","ntoskrnl.exe"},{"WRITE_REGISTER_BUFFER_USHORT","ntoskrnl.exe"},
        {"READ_REGISTER_BUFFER_ULONG","ntoskrnl.exe"},{"WRITE_REGISTER_BUFFER_ULONG","ntoskrnl.exe"},
        {"READ_PORT_USHORT","ntoskrnl.exe"},{"WRITE_PORT_USHORT","ntoskrnl.exe"},
        {"READ_PORT_ULONG","ntoskrnl.exe"},{"WRITE_PORT_ULONG","ntoskrnl.exe"},
        {"READ_PORT_BUFFER_USHORT","ntoskrnl.exe"},{"WRITE_PORT_BUFFER_USHORT","ntoskrnl.exe"},
        {"READ_PORT_BUFFER_ULONG","ntoskrnl.exe"},{"WRITE_PORT_BUFFER_ULONG","ntoskrnl.exe"},
        {"HalAllocateCommonBuffer","ntoskrnl.exe"},{"HalFreeCommonBuffer","ntoskrnl.exe"},
        {"HalAllocateCrashRundownBlock","ntoskrnl.exe"},
        {"HalAllocateContiguousMemory","ntoskrnl.exe"},{"HalFreeContiguousMemory","ntoskrnl.exe"},
        {"HalGetBusData","ntoskrnl.exe"},{"HalSetBusData","ntoskrnl.exe"},
        {"HalGetBusDataByOffset","ntoskrnl.exe"},{"HalSetBusDataByOffset","ntoskrnl.exe"},
        {"HalAssignSlotResources","ntoskrnl.exe"},{"HalGetInterruptVector","ntoskrnl.exe"},
        {"HalGetVectorInput","ntoskrnl.exe"},
        {"HalRequestSoftwareInterrupt","ntoskrnl.exe"},
        {"HalRequestDeviceInterrupt","ntoskrnl.exe"},
        {"HalDisableSystemInterrupt","ntoskrnl.exe"},{"HalEnableSystemInterrupt","ntoskrnl.exe"},
        {"HalQuerySystemInterrupt","ntoskrnl.exe"},
        {"HalLocateArrayOfPhysicalAddresses","ntoskrnl.exe"},
        {"HalGetDmaAdapter","ntoskrnl.exe"},
        {"HalMapIoSpace","ntoskrnl.exe"},{"HalUnmapIoSpace","ntoskrnl.exe"},
        {"HalReadDmaCounter","ntoskrnl.exe"},
        {"HalQueryAdapterInformation","ntoskrnl.exe"},

        // Security
        {"SeCaptureSubjectContext","ntoskrnl.exe"},{"SeReleaseSubjectContext","ntoskrnl.exe"},
        {"SeLockSubjectContext","ntoskrnl.exe"},{"SeUnlockSubjectContext","ntoskrnl.exe"},
        {"SeAuditingFileOrGlobalEvents","ntoskrnl.exe"},
        {"SeSinglePrivilegeCheck","ntoskrnl.exe"},{"SePrivilegeCheck","ntoskrnl.exe"},
        {"SeImpersonateClient","ntoskrnl.exe"},{"SeRevertToSelf","ntoskrnl.exe"},
        {"SeQuerySubjectContextToken","ntoskrnl.exe"},
        {"SeAccessCheck","ntoskrnl.exe"},{"SeAccessCheckEx","ntoskrnl.exe"},
        {"SeCreateAccessState","ntoskrnl.exe"},{"SeDeleteAccessState","ntoskrnl.exe"},
        {"SeAppendPrivileges","ntoskrnl.exe"},{"SeFreePrivileges","ntoskrnl.exe"},
        {"SeOpenObjectForWrite","ntoskrnl.exe"},
        {"SeCheckPrivileges","ntoskrnl.exe"},{"SeMarkQueryPolicyType","ntoskrnl.exe"},
        {"SeQueryInformationToken","ntoskrnl.exe"},
        {"SeValidSecurityDescriptor","ntoskrnl.exe"},
        {"SeSecurityDescriptorPresent","ntoskrnl.exe"},
        {"SeCopyClientToken","ntoskrnl.exe"},

        // Registry
        {"CmRegisterCallbackEx","ntoskrnl.exe"},{"CmUnRegisterCallback","ntoskrnl.exe"},
        {"CmRegisterCallback","ntoskrnl.exe"},
        {"CmGetCallbackVersion","ntoskrnl.exe"},
        {"CmOpenKey","ntoskrnl.exe"},{"CmCreateKey","ntoskrnl.exe"},{"CmCloseKey","ntoskrnl.exe"},
        {"CmDeleteKey","ntoskrnl.exe"},{"CmFlushKey","ntoskrnl.exe"},
        {"CmEnumerateKey","ntoskrnl.exe"},{"CmEnumerateValueKey","ntoskrnl.exe"},
        {"CmQueryKey","ntoskrnl.exe"},{"CmQueryValueKey","ntoskrnl.exe"},
        {"CmSetValueKey","ntoskrnl.exe"},{"CmDeleteValueKey","ntoskrnl.exe"},
        {"CmRenameKey","ntoskrnl.exe"},{"CmRenameValueKey","ntoskrnl.exe"},
        {"CmCopyKey","ntoskrnl.exe"},{"CmSaveKey","ntoskrnl.exe"},
        {"CmLoadKey","ntoskrnl.exe"},{"CmUnloadKey","ntoskrnl.exe"},
        {"CmSetKeyUserFlags","ntoskrnl.exe"},{"CmGetKeyUserFlags","ntoskrnl.exe"},
        {"CmCallBack","ntoskrnl.exe"},
        {"CmRegisterLastChanceShutdownNotification","ntoskrnl.exe"},

        // Power
        {"PoCallDriver","ntoskrnl.exe"},{"PoStartNextPowerIrp","ntoskrnl.exe"},
        {"PoRequestPowerIrp","ntoskrnl.exe"},{"PoSetPowerState","ntoskrnl.exe"},
        {"PoQueryPowerSequence","ntoskrnl.exe"},
        {"PoRegisterDeviceNotify","ntoskrnl.exe"},{"PoUnregisterDeviceNotify","ntoskrnl.exe"},
        {"PoSetDeviceBusy","ntoskrnl.exe"},{"PoSetDeviceBusyEx","ntoskrnl.exe"},
        {"PoSetPowerStateEx","ntoskrnl.exe"},{"PoRequestDisconnectPower","ntoskrnl.exe"},
        {"PoQueueReleaseWorkItem","ntoskrnl.exe"},
        {"PoQueueShutdownWorkItem","ntoskrnl.exe"},
        {"PoNotifyVSyncChange","ntoskrnl.exe"},
        {"PoQueryWatchdogTime","ntoskrnl.exe"},
        {"PoLogIdleDetectionEvent","ntoskrnl.exe"},

        // WMI
        {"WmiQueryTraceInformation","ntoskrnl.exe"},{"WmiTraceMessage","ntoskrnl.exe"},
        {"WmiGetClock","ntoskrnl.exe"},{"WmiGetRankAssoc","ntoskrnl.exe"},
        {"WmiAllocBuffer","ntoskrnl.exe"},{"WmiFreeBuffer","ntoskrnl.exe"},
        {"IoWMIRegistrationControl","ntoskrnl.exe"},
        {"IoWMIOpenBlock","ntoskrnl.exe"},{"IoWMICloseBlock","ntoskrnl.exe"},
        {"IoWMIQueryAllData","ntoskrnl.exe"},{"IoWMIQueryAllDataMultiple","ntoskrnl.exe"},
        {"IoWMIQuerySingleInstance","ntoskrnl.exe"},{"IoWMISetSingleInstance","ntoskrnl.exe"},
        {"IoWMISetSingleItem","ntoskrnl.exe"},{"IoWMIHandleToInstanceNumber","ntoskrnl.exe"},
        {"IoWMIDeviceInstanceToGUID","ntoskrnl.exe"},
        {"IoWMIDeviceInstanceToInstanceNumber","ntoskrnl.exe"},

        // Misc
        {"KeExpandKernelStackAndCallout","ntoskrnl.exe"},
        {"KeExpandKernelStackAndCalloutEx","ntoskrnl.exe"},
        {"ExInitializeDriverRuntime","ntoskrnl.exe"},
        {"PoSetSystemState","ntoskrnl.exe"},{"PoSetSystemWake","ntoskrnl.exe"},
        {"KeQueryActiveProcessors","ntoskrnl.exe"},
        {"KeSetSystemAffinityThread","ntoskrnl.exe"},{"KeRevertToUserAffinityThread","ntoskrnl.exe"},
        {"KeSetIdealProcessorThread","ntoskrnl.exe"},{"KeSetSystemGroupAffinityThread","ntoskrnl.exe"},
        {"KeRevertToUserGroupAffinityThread","ntoskrnl.exe"},
        {"KeQueryGroupAffinity","ntoskrnl.exe"},
        {"KeGetCurrentProcessorNumberEx","ntoskrnl.exe"},
        {"KeGetProcessorIndexFromNumber","ntoskrnl.exe"},
        {"KeGetProcessorNumberFromIndex","ntoskrnl.exe"},
        {"KeSetTargetProcessorDpc","ntoskrnl.exe"},{"KeSetTargetProcessorDpcEx","ntoskrnl.exe"},
        {"IoAllocateWorkItem","ntoskrnl.exe"},{"IoQueueWorkItem","ntoskrnl.exe"},
        {"IoFreeWorkItem","ntoskrnl.exe"},{"IoQueueWorkItemEx","ntoskrnl.exe"},
        {"KeQueryTickCount","ntoskrnl.exe"},{"KeQueryInterruptTime","ntoskrnl.exe"},
        {"KeQueryUnbiasedInterruptTime","ntoskrnl.exe"},
        {"ExQueryTimerResolution","ntoskrnl.exe"},{"ExSetTimerResolution","ntoskrnl.exe"},
    };

    // IRP major function codes
    static inline const std::unordered_map<uint32_t, std::string> IRP_MJ = {
        {0x00,"IRP_MJ_CREATE"},{0x01,"IRP_MJ_CREATE_NAMED_PIPE"},
        {0x02,"IRP_MJ_CLOSE"},{0x03,"IRP_MJ_READ"},{0x04,"IRP_MJ_WRITE"},
        {0x05,"IRP_MJ_QUERY_INFORMATION"},{0x06,"IRP_MJ_SET_INFORMATION"},
        {0x07,"IRP_MJ_QUERY_EA"},{0x08,"IRP_MJ_SET_EA"},
        {0x09,"IRP_MJ_FLUSH_BUFFERS"},{0x0A,"IRP_MJ_QUERY_VOLUME_INFORMATION"},
        {0x0B,"IRP_MJ_SET_VOLUME_INFORMATION"},{0x0C,"IRP_MJ_DIRECTORY_CONTROL"},
        {0x0D,"IRP_MJ_FILE_SYSTEM_CONTROL"},{0x0E,"IRP_MJ_DEVICE_CONTROL"},
        {0x0F,"IRP_MJ_INTERNAL_DEVICE_CONTROL"},{0x10,"IRP_MJ_SHUTDOWN"},
        {0x11,"IRP_MJ_LOCK_CONTROL"},{0x12,"IRP_MJ_CLEANUP"},
        {0x13,"IRP_MJ_CREATE_MAILSLOT"},{0x14,"IRP_MJ_QUERY_SECURITY"},
        {0x15,"IRP_MJ_SET_SECURITY"},{0x16,"IRP_MJ_POWER"},
        {0x17,"IRP_MJ_SYSTEM_CONTROL"},{0x18,"IRP_MJ_DEVICE_CHANGE"},
        {0x19,"IRP_MJ_QUERY_QUOTA"},{0x1A,"IRP_MJ_SET_QUOTA"},
        {0x1B,"IRP_MJ_PNP"},
    };

    // Check if function name is a WDK prefix (common WDK function families)
    static bool is_wdk_function(const std::string& name) {
        static const std::vector<std::string> prefixes = {
            "Io", "Ke", "Ex", "Mm", "Ob", "Ps", "Zw", "Nt", "Rtl", "Po", "Hal",
            "Se", "Cm", "Bp", "Bug", "Wdf", "Ndis", "StorPort", "Flt", "Wmi",
            "FsRtl", "Fs", "Cc", "Ldr", "Kf", "Ki", "Ke", "Hal", "IoCall",
            " READ_", " WRITE_", "RM", "NtQuery", "NtSet", "NtCreate", "NtOpen",
            "NtClose", "NtRead", "NtWrite", "NtAllocate", "NtFree", "NtDevice",
            "NtQuerySystem", "NtQueryInformation", "NtSetInformation",
            "IoGetCurrentProcess", "IoGetCurrentThread",
        };
        for (auto& p : prefixes) {
            if (name.size() >= p.size() && name.compare(0, p.size(), p) == 0)
                return true;
        }
        return false;
    }

    void run() {
        for (auto& it : st.items) {
            if (it.def.kind != Kind::Func) continue;

            // Already has a DLL mapping from dll_map_ (Win32 enricher)
            if (!it.def.import_library.empty()) continue;

            bool mapped = false;

            // Check KMDF/WDF functions
            if (KMDF_DLLS.count(it.def.name)) {
                it.def.import_library = "wdfldr.dll";
                it.def.attributes.push_back(make_driver_attr("WdfFunction"));
                mapped = true;
            }
            // Check ntoskrnl.exe functions
            else if (NTOSKRNL_DLLS.count(it.def.name)) {
                it.def.import_library = "ntoskrnl.exe";
                mapped = true;
            }
            // Check WDK function families not yet in NTOSKRNL_DLLS
            else {
                std::string dll = resolve_wdk_dll(it.def.name);
                if (!dll.empty()) {
                    it.def.import_library = dll;
                    mapped = true;
                }
            }

            // Data-driven fallback: the SDK km import-lib scan (symbol ->
            // "<lib>.lib", populated at startup in main). A FUTURE kernel API
            // from a brand-new driver library with no prefix rule yet resolves
            // to the library that actually exports it instead of the blanket
            // guess below — pure RUN-time data, so a WDK growth spurt never
            // needs a winversec table edit or rebuild.
            if (!mapped) {
                auto kit = st.km_lib_imports.find(it.def.name);
                if (kit != st.km_lib_imports.end()) {
                    it.def.import_library = kit->second;
                    mapped = true;
                }
            }

            // Fallback: kernel-namespace functions still unmapped default to
            // ntoskrnl.exe. Windows.Win32.Kernel.* is kernel-mode surface too
            // — the same rule cppwinc uses to pick the projection model.
            if (!mapped && (it.def.ns.starts_with("Windows.Wdk.") ||
                            it.def.ns.starts_with("Windows.Win32.Kernel"))) {
                it.def.import_library = "ntoskrnl.exe";
                mapped = true;
            }

            // Publish whatever THIS pass mapped. The Winverse
            // ImportLibrary/DllImport/ExportFunction attributes are the only
            // channel cppwinc reads (its winmd reader has no ModuleRef
            // fallback), so a mapping that skips them is invisible downstream
            // and the consumer link dies LNK2019. Until now every mapping
            // made here was silently dropped for exactly that reason.
            if (mapped) {
                if (it.def.entry_point.empty()) it.def.entry_point = it.def.name;
                it.def.attributes.push_back(attr::make_import_library({
                    .dll = it.def.import_library,
                    .entry_point = it.def.name,
                }));
                it.def.attributes.push_back(attr::make_dll_import(it.def.import_library));
                it.def.attributes.push_back(attr::make_export_function(it.def.name));
            }
        }
    }

    // Resolve WDK function to its DLL based on name patterns
    std::string resolve_wdk_dll(const std::string& name) {
        // NDIS functions → ndis.sys (user-mode: ndis.dll)
        if (name.starts_with("Ndis")) return "ndis.dll";
        // Storage port → storport.sys (user-mode: storport.dll)
        if (name.starts_with("Stor")) return "storport.dll";
        // Filter manager → fltMgr.sys (user-mode: fltmgr.dll)
        if (name.starts_with("Flt")) return "fltmgr.dll";
        // WDF functions not in KMDF_DLLS → wdfldr.dll
        if (name.starts_with("Wdf")) return "wdfldr.dll";
        // Common WDF user-mode
        if (name.starts_with("Wudf")) return "wudfhost.exe";
        // KMDF WDF callbacks
        if (name.starts_with("Wdf")) return "wdfldr.dll";

        // Kernel debug
        if (name.starts_with("Kd") || name.starts_with("Dbg")) return "ntoskrnl.exe";
        // HAL
        if (name.starts_with("Hal")) return "ntoskrnl.exe";
        // Kernel primitives
        if (name.starts_with("Ke")) return "ntoskrnl.exe";
        // Executive
        if (name.starts_with("Ex")) return "ntoskrnl.exe";
        // Memory manager
        if (name.starts_with("Mm")) return "ntoskrnl.exe";
        // Object manager
        if (name.starts_with("Ob")) return "ntoskrnl.exe";
        // Process/Thread
        if (name.starts_with("Ps")) return "ntoskrnl.exe";
        // I/O manager
        if (name.starts_with("Io")) return "ntoskrnl.exe";
        // Registry
        if (name.starts_with("Cm")) return "ntoskrnl.exe";
        // Power
        if (name.starts_with("Po")) return "ntoskrnl.exe";
        // Security
        if (name.starts_with("Se")) return "ntoskrnl.exe";
        // RTL
        if (name.starts_with("Rtl")) return "ntoskrnl.exe";
        // Zw/Nt system calls
        if (name.starts_with("Zw") || name.starts_with("Nt")) return "ntoskrnl.exe";
        // Bugcheck
        if (name.starts_with("Bug")) return "ntoskrnl.exe";
        // READ/WRITE register macros
        if (name.starts_with("READ_") || name.starts_with("WRITE_")) return "ntoskrnl.exe";
        // Resource/lock primitives
        if (name.starts_with("Ke") || name.starts_with("Kf")) return "ntoskrnl.exe";

        return {};
    }

private:
    Attribute make_driver_attr(const std::string& kind) {
        Attribute a;
        a.ns = "Winverse";
        a.name = kind;
        return a;
    }
};

} // namespace wv
