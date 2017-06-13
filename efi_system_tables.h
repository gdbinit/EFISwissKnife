/*
 * ______________________.___
 * \_   _____/\_   _____/|   |
 *  |    __)_  |    __)  |   |
 *  |        \ |     \   |   |
 * /_______  / \___  /   |___|
 *         \/      \/
 *   _________       .__                 ____  __.      .__  _____
 *  /   _____/_  _  _|__| ______ _____  |    |/ _| ____ |__|/ ____\____
 *  \_____  \\ \/ \/ /  |/  ___//  ___/ |      <  /    \|  \   __\/ __ \
 *  /        \\     /|  |\___ \ \___ \  |    |  \|   |  \  ||  | \  ___/
 * /_______  / \/\_/ |__/____  >____  > |____|__ \___|  /__||__|  \___  >
 *         \/                \/     \/          \/    \/              \/
 *
 * EFI Swiss Knife
 * An IDA plugin to improve (U)EFI reversing
 *
 * Copyright (C) 2016, 2017  Pedro Vilaça (fG!) - reverser@put.as - https://reverse.put.as
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * efi_system_tables.h
 *
 */

#ifndef efi_swiss_knife_efi_system_tables_h
#define efi_swiss_knife_efi_system_tables_h

#include <stdint.h>

struct services_entry
{
    char parameters[2048];
    char description[1024];
    char prototype[512];
    char name[256];
    char rcx_param[256];
    char rdx_param[256];
    char r8_param[256];
    char r9_param[256];
    char stack1_param[256];
    char stack2_param[256];
    char stack3_param[256];
    char stack4_param[256];
    uint32_t offset;
    uint32_t nr_args;
    uint32_t count;
};

#pragma mark -
#pragma mark Boot Services Table
#pragma mark -

struct services_entry boot_services_table[] = {
    {
        .name = "FAILED BOOT SERVICE",
        .offset = 0x0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .parameters = "",
        .rcx_param = "",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "RaiseTPL",
        .offset = 0x18,
        .description = "Raises a task's priority level and returns its previous level.",
        .nr_args = 1,
        .prototype = "EFI_TPL(EFIAPI * EFI_RAISE_TPL) (IN EFI_TPL NewTpl)",
        .parameters = "NewTpl   The new task priority level.",
        .rcx_param = "IN EFI_TPL NewTpl",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "RestoreTPL",
        .offset = 0x20,
        .description = "Restores a task's priority level to its previous value.",
        .nr_args = 1,
        .prototype = "VOID(EFIAPI * EFI_RESTORE_TPL) (IN EFI_TPL OldTpl)",
        .parameters = "OldTpl   The previous task priority level to restore.",
        .rcx_param = "IN EFI_TPL OldTpl",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "AllocatePages",
        .offset = 0x28,
        .description = "Allocates memory pages from the system.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_ALLOCATE_PAGES) (IN EFI_ALLOCATE_TYPE Type, IN EFI_MEMORY_TYPE MemoryType, IN UINTN Pages, IN OUT EFI_PHYSICAL_ADDRESS *Memory)",
        .parameters = "Type        The type of allocation to perform.\n\
MemoryType  The type of memory to allocate.\n\
Pages       The number of contiguous 4 KB pages to allocate.\n\
Memory      The pointer to a physical address. On input, the way in which the address is used depends on the value of Type.",
        .rcx_param = "IN EFI_ALLOCATE_TYPE Type",
        .rdx_param = "IN EFI_MEMORY_TYPE MemoryType",
        .r8_param = "IN UINTN Pages",
        .r9_param = "IN OUT EFI_PHYSICAL_ADDRESS *Memory",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "FreePages",
        .offset = 0x30,
        .description = "Frees memory pages.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_FREE_PAGES) (IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages)",
        .parameters = "Memory	The base physical address of the pages to be freed.\n\
Pages	The number of contiguous 4 KB pages to free.",
        .rcx_param = "IN EFI_PHYSICAL_ADDRESS Memory",
        .rdx_param = "IN UINTN Pages",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetMemoryMap",
        .offset = 0x38,
        .description = "Returns the current memory map.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_MEMORY_MAP) (IN OUT UINTN *MemoryMapSize, IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap, OUT UINTN *MapKey, OUT UINTN *DescriptorSize, OUT UINT32 *DescriptorVersion)",
        .parameters = "MemoryMapSize       A pointer to the size, in bytes, of the MemoryMap buffer. On input, this is the size of the buffer allocated by the caller.\n\
                    On output, it is the size of the buffer returned by the firmware if the buffer was large enough, or the size of the buffer\n\
                    needed to contain the map if the buffer was too small.\n\
MemoryMap           A pointer to the buffer in which firmware places the current memory map.\n\
MapKey              A pointer to the location in which firmware returns the key for the current memory map.\n\
DescriptorSize      A pointer to the location in which firmware returns the size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.\n\
DescriptorVersion	A pointer to the location in which firmware returns the version number associated with the EFI_MEMORY_DESCRIPTOR.",
        .rcx_param = "IN OUT UINTN *MemoryMapSize",
        .rdx_param = "IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap",
        .r8_param = "OUT UINTN *MapKey",
        .r9_param = "OUT UINTN *DescriptorSize",
        .stack1_param = "OUT UINT32 *DescriptorVersion",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "AllocatePool",
        .offset = 0x40,
        .description = "Allocates pool memory.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_ALLOCATE_POOL) (IN EFI_MEMORY_TYPE PoolType, IN UINTN Size, OUT VOID **Buffer)",
        .parameters = "PoolType	The type of pool to allocate.\n\
Size        The number of bytes to allocate from the pool.\n\
Buffer      A pointer to a pointer to the allocated buffer if the call succeeds; undefined otherwise.",
        .rcx_param = "IN EFI_MEMORY_TYPE PoolType",
        .rdx_param = "IN UINTN Size",
        .r8_param = "OUT VOID **Buffer",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "FreePool",
        .offset = 0x48,
        .description = "Returns pool memory to the system.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_FREE_POOL) (IN VOID *Buffer)",
        .parameters = "Buffer	The pointer to the buffer to free.",
        .rcx_param = "IN VOID *Buffer",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CreateEvent",
        .offset = 0x50,
        .description = "Creates an event.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CREATE_EVENT) (IN UINT32 Type, IN EFI_TPL NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction, IN VOID *NotifyContext, OUT EFI_EVENT *Event)",
        .parameters = "Type            The type of event to create and its mode and attributes.\n\
NotifyTpl       The task priority level of event notifications, if needed.\n\
NotifyFunction	The pointer to the event's notification function, if any.\n\
NotifyContext	The pointer to the notification function's context; corresponds to parameter Context in the notification function.\n\
Event           The pointer to the newly created event if the call succeeds; undefined otherwise.",
        .rcx_param = "IN UINT32 Type",
        .rdx_param = "IN EFI_TPL NotifyTpl",
        .r8_param = "IN EFI_EVENT_NOTIFY NotifyFunction",
        .r9_param = "IN VOID *NotifyContext",
        .stack1_param = "OUT EFI_EVENT *Event",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetTimer",
        .offset = 0x58,
        .description = "Sets the type of timer and the trigger time for a timer event.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SET_TIMER) (IN EFI_EVENT Event, IN EFI_TIMER_DELAY Type, IN UINT64 TriggerTime)",
        .parameters = "Event       The timer event that is to be signaled at the specified time.\n\
Type        The type of time that is specified in TriggerTime.\n\
TriggerTime	The number of 100ns units until the timer expires. A TriggerTime of 0 is legal. If Type is TimerRelative and TriggerTime is 0, then the timer event will be signaled on the next timer tick. If Type is TimerPeriodic and TriggerTime is 0, then the timer event will be signaled on every timer tick.",
        .rcx_param = "IN EFI_EVENT Event",
        .rdx_param = "IN EFI_TIMER_DELAY Type",
        .r8_param = "IN UINT64 TriggerTime",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "WaitForEvent",
        .offset = 0x60,
        .description = "Stops execution until an event is signaled.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_WAIT_FOR_EVENT) (IN UINTN NumberOfEvents, IN EFI_EVENT *Event, OUT UINTN *Index)",
        .parameters = "NumberOfEvents	The number of events in the Event array.\n\
Event           An array of EFI_EVENT.\n\
Index           The pointer to the index of the event which satisfied the wait condition.",
        .rcx_param = "IN UINTN NumberOfEvents",
        .rdx_param = "IN EFI_EVENT *Event",
        .r8_param = "OUT UINTN *Index",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SignalEvent",
        .offset = 0x68,
        .description = "Signals an event.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SIGNAL_EVENT) (IN EFI_EVENT Event)",
        .parameters = "Event	The event to signal.",
        .rcx_param = "IN EFI_EVENT Event",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CloseEvent",
        .offset = 0x70,
        .description = "Closes an event.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CLOSE_EVENT) (IN EFI_EVENT Event)",
        .parameters = "Event	The event to close.",
        .rcx_param = "IN EFI_EVENT Event",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CheckEvent",
        .offset = 0x78,
        .description = "Checks whether an event is in the signaled state.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CHECK_EVENT) (IN EFI_EVENT Event)",
        .parameters = "Event	The event to check.",
        .rcx_param = "IN EFI_EVENT Event",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "InstallProtocolInterface",
        .offset = 0x80,
        .description = "Installs a protocol interface on a device handle. If the handle does not exist, it is created and added to the list of handles in the system. InstallMultipleProtocolInterfaces() performs more error checking than InstallProtocolInterface(), so it is recommended that InstallMultipleProtocolInterfaces() be used in place of InstallProtocolInterface()",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_INSTALL_PROTOCOL_INTERFACE) (IN OUT EFI_HANDLE *Handle, IN EFI_GUID *Protocol, IN EFI_INTERFACE_TYPE InterfaceType, IN VOID *Interface)",
        .parameters = "Handle          A pointer to the EFI_HANDLE on which the interface is to be installed.\n\
Protocol        The numeric ID of the protocol interface.\n\
InterfaceType	Indicates whether Interface is supplied in native form.\n\
Interface       A pointer to the protocol interface.",
        .rcx_param = "IN OUT EFI_HANDLE *Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "IN EFI_INTERFACE_TYPE InterfaceType",
        .r9_param = "IN VOID *Interface",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "ReinstallProtocolInterface",
        .offset = 0x88,
        .description = "Reinstalls a protocol interface on a device handle.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_REINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN VOID *OldInterface, IN VOID *NewInterface)",
        .parameters = "Handle          Handle on which the interface is to be reinstalled.\n\
Protocol        The numeric ID of the interface.\n\
OldInterface	A pointer to the old interface. NULL can be used if a structure is not associated with Protocol.\n\
NewInterface	A pointer to the new interface.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "IN VOID *OldInterface",
        .r9_param = "IN VOID *NewInterface",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "UninstallProtocolInterface",
        .offset = 0x90,
        .description = "Removes a protocol interface from a device handle. It is recommended that UninstallMultipleProtocolInterfaces() be used in place of UninstallProtocolInterface().",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_UNINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN VOID *Interface)",
        .parameters = "Handle      The handle on which the interface was installed.\n\
Protocol	The numeric ID of the interface.\n\
Interface	A pointer to the interface.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "IN VOID *Interface",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "HandleProtocol",
        .offset = 0x98,
        .description = "Queries a handle to determine if it supports a specified protocol.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface)",
        .parameters = "Handle      The handle being queried.\n\
Protocol	The published unique identifier of the protocol.\n\
Interface	Supplies the address where a pointer to the corresponding Protocol Interface is returned.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "OUT VOID **Interface",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "Reserved",
        .offset = 0xA0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .parameters = "",
        .rcx_param = "",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "RegisterProtocolNotify",
        .offset = 0xA8,
        .description = "Creates an event that is to be signaled whenever an interface is installed for a specified protocol.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_REGISTER_PROTOCOL_NOTIFY) (IN EFI_GUID *Protocol, IN EFI_EVENT Event, OUT VOID **Registration)",
        .parameters = "Protocol        The numeric ID of the protocol for which the event is to be registered.\n\
Event           Event that is to be signaled whenever a protocol interface is registered for Protocol.\n\
Registration	A pointer to a memory location to receive the registration value.",
        .rcx_param = "IN EFI_GUID *Protocol",
        .rdx_param = "IN EFI_EVENT Event",
        .r8_param = "OUT VOID **Registration",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "LocateHandle",
        .offset = 0xB0,
        .description = "Returns an array of handles that support a specified protocol.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_LOCATE_HANDLE) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol, OPTIONAL IN VOID *SearchKey, OPTIONAL IN OUT UINTN *BufferSize, OUT EFI_HANDLE *Buffer)",
        .parameters = "SearchType	Specifies which handle(s) are to be returned.\n\
Protocol	Specifies the protocol to search by.\n\
SearchKey	Specifies the search key.\n\
BufferSize	On input, the size in bytes of Buffer. On output, the size in bytes of the array returned in Buffer (if the buffer was large enough) or the size, in bytes, of the buffer needed to obtain the array (if the buffer was not large enough).\n\
Buffer      The buffer in which the array is returned.",
        .rcx_param = "IN EFI_LOCATE_SEARCH_TYPE SearchType",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "OPTIONAL IN VOID *SearchKey",
        .r9_param = "OPTIONAL IN OUT UINTN *BufferSize",
        .stack1_param = "OUT EFI_HANDLE *Buffer",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "LocateDevicePath",
        .offset = 0xB8,
        .description = "Locates the handle to a device on the device path that supports the specified protocol.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_LOCATE_DEVICE_PATH) (IN EFI_GUID *Protocol, IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath, OUT EFI_HANDLE *Device)",
        .parameters = "Protocol	Specifies the protocol to search for.\n\
DevicePath	On input, a pointer to a pointer to the device path. On output, the device path pointer is modified to point to the remaining part of the device path.\n\
Device      A pointer to the returned device handle.",
        .rcx_param = "IN EFI_GUID *Protocol",
        .rdx_param = "IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath",
        .r8_param = "OUT EFI_HANDLE *Device",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "InstallConfigurationTable",
        .offset = 0xC0,
        .description = "Adds, updates, or removes a configuration table entry from the EFI System Table.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_INSTALL_CONFIGURATION_TABLE) (IN EFI_GUID *Guid, IN VOID *Table)",
        .parameters = "Guid	A pointer to the GUID for the entry to add, update, or remove.\n\
Table	A pointer to the configuration table for the entry to add, update, or remove. May be NULL.",
        .rcx_param = "IN EFI_GUID *Guid",
        .rdx_param = "IN VOID *Table",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "LoadImage",
        .offset = 0xC8,
        .description = "Loads an EFI image into memory.",
        .nr_args = 6,
        .prototype = "EFI_STATUS(EFIAPI * EFI_IMAGE_LOAD) (IN BOOLEAN BootPolicy, IN EFI_HANDLE ParentImageHandle, IN EFI_DEVICE_PATH_PROTOCOL *DevicePath, IN VOID *SourceBuffer OPTIONAL, IN UINTN SourceSize, OUT EFI_HANDLE *ImageHandle)",
        .parameters = "BootPolicy      If TRUE, indicates that the request originates from the boot manager, and that the boot manager is attempting to load FilePath as a boot selection. Ignored if SourceBuffer is not NULL.\n\
ParentImageHandle	The caller's image handle.\n\
DevicePath      The DeviceHandle specific file path from which the image is loaded.\n\
SourceBuffer	If not NULL, a pointer to the memory location containing a copy of the image to be loaded.\n\
SourceSize      The size in bytes of SourceBuffer. Ignored if SourceBuffer is NULL.\n\
ImageHandle     The pointer to the returned image handle that is created when the image is successfully loaded.",
        .rcx_param = "IN BOOLEAN BootPolicy",
        .rdx_param = "IN EFI_HANDLE ParentImageHandle",
        .r8_param = "IN EFI_DEVICE_PATH_PROTOCOL *DevicePath",
        .r9_param = "IN VOID *SourceBuffer OPTIONAL",
        .stack1_param = "IN UINTN SourceSize",
        .stack2_param = "OUT EFI_HANDLE *ImageHandle",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "StartImage",
        .offset = 0xD0,
        .description = "Transfers control to a loaded image's entry point.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_IMAGE_START) (IN EFI_HANDLE ImageHandle, OUT UINTN *ExitDataSize, OUT CHAR16 **ExitData OPTIONAL)",
        .parameters = "ImageHandle     Handle of image to be started.\n\
ExitDataSize	The pointer to the size, in bytes, of ExitData.\n\
ExitData        The pointer to a pointer to a data buffer that includes a Null-terminated string, optionally followed by additional binary data.",
        .rcx_param = "IN EFI_HANDLE ImageHandle",
        .rdx_param = "OUT UINTN *ExitDataSize",
        .r8_param = "OUT CHAR16 **ExitData OPTIONAL",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "Exit",
        .offset = 0xD8,
        .description = "Terminates a loaded EFI image and returns control to boot services.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_EXIT) (IN EFI_HANDLE ImageHandle, IN EFI_STATUS ExitStatus, IN UINTN ExitDataSize, IN CHAR16 *ExitData OPTIONAL)",
        .parameters = "ImageHandle     Handle that identifies the image. This parameter is passed to the image on entry.\n\
ExitStatus      The image's exit code.\n\
ExitDataSize	The size, in bytes, of ExitData. Ignored if ExitStatus is EFI_SUCCESS.\n\
ExitData        The pointer to a data buffer that includes a Null-terminated string, optionally followed by additional binary data. The string is a description that the caller may use to further indicate the reason for the image's exit. ExitData is only valid if ExitStatus is something other than EFI_SUCCESS. The ExitData buffer must be allocated by calling AllocatePool().",
        .rcx_param = "IN EFI_HANDLE ImageHandle",
        .rdx_param = "IN EFI_STATUS ExitStatus",
        .r8_param = "IN UINTN ExitDataSize",
        .r9_param = "IN CHAR16 *ExitData OPTIONAL",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "UnloadImage",
        .offset = 0xE0,
        .description = "Unloads an image.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_IMAGE_UNLOAD) (IN EFI_HANDLE ImageHandle)",
        .parameters = "ImageHandle	Handle that identifies the image to be unloaded.",
        .rcx_param = "IN EFI_HANDLE ImageHandle",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "ExitBootServices",
        .offset = 0xE8,
        .description = "Terminates all boot services.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_EXIT_BOOT_SERVICES) (IN EFI_HANDLE ImageHandle, IN UINTN MapKey)",
        .parameters = "ImageHandle	Handle that identifies the exiting image.\n\
MapKey      Key to the latest memory map.",
        .rcx_param = "IN EFI_HANDLE ImageHandle",
        .rdx_param = "IN UINTN MapKey",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetNextMonotonicCount",
        .offset = 0xF0,
        .description = "Returns a monotonically increasing count for the platform.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_NEXT_MONOTONIC_COUNT) (OUT UINT64 *Count)",
        .parameters = "Count	The pointer to returned value.",
        .rcx_param = "OUT UINT64 *Count",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "Stall",
        .offset = 0xF8,
        .description = "Induces a fine-grained stall.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_STALL) (IN UINTN Microseconds)",
        .parameters = "Microseconds	The number of microseconds to stall execution.",
        .rcx_param = "IN UINTN Microseconds",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetWatchdogTimer",
        .offset = 0x100,
        .description = "Sets the system's watchdog timer.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SET_WATCHDOG_TIMER) (IN UINTN Timeout, IN UINT64 WatchdogCode, IN UINTN DataSize, IN CHAR16 *WatchdogData OPTIONAL)",
        .parameters = "Timeout         The number of seconds to set the watchdog timer to.\n\
WatchdogCode    The numeric code to log on a watchdog timer timeout event.\n\
DataSize        The size, in bytes, of WatchdogData.\n\
WatchdogData    A data buffer that includes a Null-terminated string, optionally followed by additional binary data.",
        .rcx_param = "IN UINTN Timeout",
        .rdx_param = "IN UINT64 WatchdogCode",
        .r8_param = "IN UINTN DataSize",
        .r9_param = "IN CHAR16 *WatchdogData OPTIONAL",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "ConnectController",
        .offset = 0x108,
        .description = "Connects one or more drivers to a controller.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CONNECT_CONTROLLER) (IN EFI_HANDLE ControllerHandle, IN EFI_HANDLE *DriverImageHandle, OPTIONAL IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath, OPTIONAL IN BOOLEAN Recursive)",
        .parameters = "ControllerHandle	The handle of the controller to which driver(s) are to be connected.\n\
DriverImageHandle	A pointer to an ordered list handles that support the EFI_DRIVER_BINDING_PROTOCOL.\n\
RemainingDevicePath	A pointer to the device path that specifies a child of the controller specified by ControllerHandle.\n\
Recursive           If TRUE, then ConnectController() is called recursively until the entire tree of controllers below the controller specified by ControllerHandle have been created. If FALSE, then the tree of controllers is only expanded one level.",
        .rcx_param = "IN EFI_HANDLE ControllerHandle",
        .rdx_param = "IN EFI_HANDLE *DriverImageHandle",
        .r8_param = "OPTIONAL IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath",
        .r9_param = "OPTIONAL IN BOOLEAN Recursive",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "DisconnectController",
        .offset = 0x110,
        .description = "Disconnects one or more drivers from a controller.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_DISCONNECT_CONTROLLER) (IN EFI_HANDLE ControllerHandle, IN EFI_HANDLE DriverImageHandle, OPTIONAL IN EFI_HANDLE ChildHandle OPTIONAL)",
        .parameters = "ControllerHandle	The handle of the controller from which driver(s) are to be disconnected.\n\
DriverImageHandle	The driver to disconnect from ControllerHandle. If DriverImageHandle is NULL, then all the drivers currently managing ControllerHandle are disconnected from ControllerHandle.\n\
ChildHandle         The handle of the child to destroy. If ChildHandle is NULL, then all the children of ControllerHandle are destroyed before the drivers are disconnected from ControllerHandle.",
        .rcx_param = "IN EFI_HANDLE ControllerHandle",
        .rdx_param = "IN EFI_HANDLE DriverImageHandle",
        .r8_param = "OPTIONAL IN EFI_HANDLE ChildHandle OPTIONAL",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "OpenProtocol",
        .offset = 0x118,
        .description = "Queries a handle to determine if it supports a specified protocol. If the protocol is supported by the handle, it opens the protocol on behalf of the calling agent.",
        .nr_args = 6,
        .prototype = "EFI_STATUS(EFIAPI * EFI_OPEN_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface, OPTIONAL IN EFI_HANDLE AgentHandle, IN EFI_HANDLE ControllerHandle, IN UINT32 Attributes)",
        .parameters = "Handle              The handle for the protocol interface that is being opened.\n\
Protocol            The published unique identifier of the protocol.\n\
Interface           Supplies the address where a pointer to the corresponding Protocol Interface is returned.\n\
AgentHandle         The handle of the agent that is opening the protocol interface specified by Protocol and Interface.\n\
ControllerHandle	If the agent that is opening a protocol is a driver that follows the UEFI Driver Model, then this parameter is the controller handle that requires the protocol interface. If the agent does not follow the UEFI Driver Model, then this parameter is optional and may be NULL.\n\
Attributes          The open mode of the protocol interface specified by Handle and Protocol.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "OUT VOID **Interface",
        .r9_param = "OPTIONAL IN EFI_HANDLE AgentHandle",
        .stack1_param = "IN EFI_HANDLE ControllerHandle",
        .stack2_param = "IN UINT32 Attributes",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CloseProtocol",
        .offset = 0x120,
        .description = "Closes a protocol on a handle that was opened using OpenProtocol().",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CLOSE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN EFI_HANDLE AgentHandle, IN EFI_HANDLE ControllerHandle)",
        .parameters = "Handle              The handle for the protocol interface that was previously opened with OpenProtocol(), and is now being closed.\n\
Protocol          	The published unique identifier of the protocol.\n\
AgentHandle         The handle of the agent that is closing the protocol interface.\n\
ControllerHandle	If the agent that opened a protocol is a driver that follows the UEFI Driver Model, then this parameter is the controller handle that required the protocol interface.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "IN EFI_HANDLE AgentHandle",
        .r9_param = "IN EFI_HANDLE ControllerHandle",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "OpenProtocolInformation",
        .offset = 0x128,
        .description = "Retrieves the list of agents that currently have a protocol interface opened.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_OPEN_PROTOCOL_INFORMATION) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer, OUT UINTN *EntryCount)",
        .parameters = "Handle      The handle for the protocol interface that is being queried.\n\
Protocol	The published unique identifier of the protocol.\n\
EntryBuffer	A pointer to a buffer of open protocol information in the form of EFI_OPEN_PROTOCOL_INFORMATION_ENTRY structures.\n\
EntryCount	A pointer to the number of entries in EntryBuffer.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer",
        .r9_param = "OUT UINTN *EntryCount",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "ProtocolsPerHandle",
        .offset = 0x130,
        .description = "Retrieves the list of protocol interface GUIDs that are installed on a handle in a buffer allocated from pool.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PROTOCOLS_PER_HANDLE) (IN EFI_HANDLE Handle, OUT EFI_GUID ***ProtocolBuffer, OUT UINTN *ProtocolBufferCount)",
        .parameters = "Handle              The handle from which to retrieve the list of protocol interface GUIDs.\n\
ProtocolBuffer      A pointer to the list of protocol interface GUID pointers that are installed on Handle.\n\
ProtocolBufferCount	A pointer to the number of GUID pointers present in ProtocolBuffer.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "OUT EFI_GUID ***ProtocolBuffer",
        .r8_param = "OUT UINTN *ProtocolBufferCount",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "LocateHandleBuffer",
        .offset = 0x138,
        .description = "Returns an array of handles that support the requested protocol in a buffer allocated from pool.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_LOCATE_HANDLE_BUFFER) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol, OPTIONAL IN VOID *SearchKey, OPTIONAL IN OUT UINTN *NoHandles, OUT EFI_HANDLE **Buffer)",
        .parameters = "SearchType	Specifies which handle(s) are to be returned.\n\
Protocol	Provides the protocol to search by. This parameter is only valid for a SearchType of ByProtocol.\n\
SearchKey	Supplies the search key depending on the SearchType.\n\
NoHandles	The number of handles returned in Buffer.\n\
Buffer	A pointer to the buffer to return the requested array of handles that support Protocol.",
        .rcx_param = "IN EFI_LOCATE_SEARCH_TYPE SearchType",
        .rdx_param = "IN EFI_GUID *Protocol",
        .r8_param = "OPTIONAL IN VOID *SearchKey",
        .r9_param = "OPTIONAL IN OUT UINTN *NoHandles",
        .stack1_param = "OUT EFI_HANDLE **Buffer",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "LocateProtocol",
        .offset = 0x140,
        .description = "Returns the first protocol instance that matches the given protocol.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_LOCATE_PROTOCOL) (IN EFI_GUID *Protocol, IN VOID *Registration, OPTIONAL OUT VOID **Interface)",
        .parameters = "Protocol        Provides the protocol to search for.\n\
Registration    Optional registration key returned from RegisterProtocolNotify().\n\
Interface       On return, a pointer to the first interface that matches Protocol and Registration.",
        .rcx_param = "IN EFI_GUID *Protocol",
        .rdx_param = "IN VOID *Registration",
        .r8_param = "OPTIONAL OUT VOID **Interface",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "InstallMultipleProtocolInterfaces",
        .offset = 0x148,
        .description = "Installs one or more protocol interfaces into the boot services environment.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN OUT EFI_HANDLE *Handle,...)",
        .parameters = "Handle	The pointer to a handle to install the new protocol interfaces on, or a pointer to NULL if a new handle is to be allocated.\n\
...     A variable argument list containing pairs of protocol GUIDs and protocol interfaces.",
        .rcx_param = "IN OUT EFI_HANDLE *Handle",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "UninstallMultipleProtocolInterfaces",
        .offset = 0x150,
        .description = "Removes one or more protocol interfaces into the boot services environment.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN EFI_HANDLE Handle,...)",
        .parameters = "Handle	The handle to remove the protocol interfaces from.\n\
...     A variable argument list containing pairs of protocol GUIDs and protocol interfaces.",
        .rcx_param = "IN EFI_HANDLE Handle",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CalculateCrc32",
        .offset = 0x158,
        .description = "Computes and returns a 32-bit CRC for a data buffer.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CALCULATE_CRC32) (IN VOID *Data, IN UINTN DataSize, OUT UINT32 *Crc32)",
        .parameters = "Data        A pointer to the buffer on which the 32-bit CRC is to be computed.\n\
DataSize	The number of bytes in the buffer Data.\n\
Crc32       The 32-bit CRC that was computed for the data buffer specified by Data and DataSize.",
        .rcx_param = "IN VOID *Data",
        .rdx_param = "IN UINTN DataSize",
        .r8_param = "OUT UINT32 *Crc32",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CopyMem",
        .offset = 0x160,
        .description = "Copies the contents of one buffer to another buffer.",
        .nr_args = 3,
        .prototype = "VOID(EFIAPI * EFI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, IN UINTN Length)",
        .parameters = "Destination	The pointer to the destination buffer of the memory copy.\n\
Source      The pointer to the source buffer of the memory copy.\n\
Length      Number of bytes to copy from Source to Destination.",
        .rcx_param = "IN VOID *Destination",
        .rdx_param = "IN VOID *Source",
        .r8_param = "IN UINTN Length",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetMem",
        .offset = 0x168,
        .description = "The SetMem() function fills a buffer with a specified value.",
        .nr_args = 3,
        .prototype = "VOID(EFIAPI * EFI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)",
        .parameters = "Buffer	The pointer to the buffer to fill.\n\
Size	Number of bytes in Buffer to fill.\n\
Value	Value to fill Buffer with.",
        .rcx_param = "IN VOID *Buffer",
        .rdx_param = "IN UINTN Size",
        .r8_param = "IN UINT8 Value",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "CreateEventEx",
        .offset = 0x170,
        .description = "Creates an event in a group.",
        .nr_args = 6,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CREATE_EVENT_EX) (IN UINT32 Type, IN EFI_TPL NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction OPTIONAL, IN CONST VOID *NotifyContext OPTIONAL, IN CONST EFI_GUID *EventGroup OPTIONAL, OUT EFI_EVENT *Event)",
        .parameters = "Type            The type of event to create and its mode and attributes.\n\
NotifyTpl       The task priority level of event notifications,if needed.\n\
NotifyFunction	The pointer to the event's notification function, if any.\n\
NotifyContext	The pointer to the notification function's context; corresponds to parameter Context in the notification function.\n\
EventGroup      The pointer to the unique identifier of the group to which this event belongs. If this is NULL, then the function behaves as if the parameters were passed to CreateEvent.\n\
Event           The pointer to the newly created event if the call succeeds; undefined otherwise.",
        .rcx_param = "IN UINT32 Type",
        .rdx_param = "IN EFI_TPL NotifyTpl",
        .r8_param = "IN EFI_EVENT_NOTIFY NotifyFunction OPTIONAL",
        .r9_param = "IN CONST VOID *NotifyContext OPTIONAL",
        .stack1_param = "IN CONST EFI_GUID *EventGroup OPTIONAL",
        .stack2_param = "OUT EFI_EVENT *Event",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "EMPTY SERVICE",
        .offset = 0x0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .parameters = "",
        .rcx_param = "",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    }
};

#pragma mark -
#pragma mark RunTime Services Table
#pragma mark -

struct services_entry runtime_services_table[] = {
    {
        .name = "FAILED RUNTIME SERVICE",
        .offset = 0x0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .parameters = "",
        .rcx_param = "",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetTime",
        .offset = 0x18,
        .description = "Returns the current time and date information, and the time-keeping capabilities of the hardware platform.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_TIME) (OUT EFI_TIME *Time, OUT EFI_TIME_CAPABILITIES *Capabilities OPTIONAL)",
        .parameters = "Time            A pointer to storage to receive a snapshot of the current time.\n\
Capabilities	An optional pointer to a buffer to receive the real time clock device's capabilities.",
        .rcx_param = "OUT EFI_TIME *Time",
        .rdx_param = "OUT EFI_TIME_CAPABILITIES *Capabilities OPTIONAL",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetTime",
        .offset = 0x20,
        .description = "Sets the current local time and date information.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SET_TIME) (IN EFI_TIME *Time)",
        .parameters = "Time	A pointer to the current time.",
        .rcx_param = "IN EFI_TIME *Time",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetWakeupTime",
        .offset = 0x28,
        .description = "Returns the current wakeup alarm clock setting.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_WAKEUP_TIME) (OUT BOOLEAN *Enabled, OUT BOOLEAN *Pending, OUT EFI_TIME *Time)",
        .parameters = "Enabled	Indicates if the alarm is currently enabled or disabled.\n\
Pending	Indicates if the alarm signal is pending and requires acknowledgement.\n\
Time	The current alarm setting.",
        .rcx_param = "OUT BOOLEAN *Enabled",
        .rdx_param = "OUT BOOLEAN *Pending",
        .r8_param = "OUT EFI_TIME *Time",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetWakeupTime",
        .offset = 0x30,
        .description = "Sets the system wakeup alarm clock time.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SET_WAKEUP_TIME) (IN BOOLEAN Enable, IN EFI_TIME *Time OPTIONAL)",
        .parameters = "Enabled	Enable or disable the wakeup alarm.\n\
Time	If Enable is TRUE, the time to set the wakeup alarm for. If Enable is FALSE, then this parameter is optional, and may be NULL.",
        .rcx_param = "IN BOOLEAN Enable",
        .rdx_param = "IN EFI_TIME *Time OPTIONAL",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetVirtualAddressMap",
        .offset = 0x38,
        .description = "Changes the runtime addressing mode of EFI firmware from physical to virtual.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SET_VIRTUAL_ADDRESS_MAP) (IN UINTN MemoryMapSize, IN UINTN DescriptorSize, IN UINT32 DescriptorVersion, IN EFI_MEMORY_DESCRIPTOR *VirtualMap)",
        .parameters = "MemoryMapSize       The size in bytes of VirtualMap.\n\
DescriptorSize      The size in bytes of an entry in the VirtualMap.\n\
DescriptorVersion	The version of the structure entries in VirtualMap.\n\
VirtualMap          An array of memory descriptors which contain new virtual address mapping information for all runtime ranges.",
        .rcx_param = "IN UINTN MemoryMapSize",
        .rdx_param = "IN UINTN DescriptorSize",
        .r8_param = "IN UINT32 DescriptorVersion",
        .r9_param = "IN EFI_MEMORY_DESCRIPTOR *VirtualMap",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "ConvertPointer",
        .offset = 0x40,
        .description = "Determines the new virtual address that is to be used on subsequent memory accesses.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_CONVERT_POINTER) (IN UINTN DebugDisposition, IN OUT VOID **Address)",
        .parameters = "DebugDisposition	Supplies type information for the pointer being converted.\n\
Address             A pointer to a pointer that is to be fixed to be the value needed for the new virtual address mappings being applied.",
        .rcx_param = "IN UINTN DebugDisposition",
        .rdx_param = "IN OUT VOID **Address",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetVariable",
        .offset = 0x48,
        .description = "Returns the value of a variable.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_VARIABLE) (IN CHAR16 *VariableName, IN EFI_GUID *VendorGuid, OUT UINT32 *Attributes, OPTIONAL IN OUT UINTN *DataSize, OUT VOID *Data)",
        .parameters = "VariableName    A Null-terminated string that is the name of the vendor's variable.\n\
VendorGuid      A unique identifier for the vendor.\n\
Attributes      If not NULL, a pointer to the memory location to return the attributes bitmask for the variable.\n\
DataSize        On input, the size in bytes of the return Data buffer. On output the size of data returned in Data.\n\
Data            The buffer to return the contents of the variable.",
        .rcx_param = "IN CHAR16 *VariableName",
        .rdx_param = "IN EFI_GUID *VendorGuid",
        .r8_param = "OUT UINT32 *Attributes",
        .r9_param = "OPTIONAL IN OUT UINTN *DataSize",
        .stack1_param = "OUT VOID *Data",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetNextVariableName",
        .offset = 0x50,
        .description = "Enumerates the current variable names.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_NEXT_VARIABLE_NAME) (IN OUT UINTN *VariableNameSize, IN OUT CHAR16 *VariableName, IN OUT EFI_GUID *VendorGuid)",
        .parameters = "VariableNameSize         The size of the VariableName buffer.\n\
VariableName        On input, supplies the last VariableName that was returned by GetNextVariableName(). On output, returns the Nullterminated string of the current variable.\n\
VendorGuid          On input, supplies the last VendorGuid that was returned by GetNextVariableName(). On output, returns the VendorGuid of the current variable.",
        .rcx_param = "IN OUT UINTN *VariableNameSize",
        .rdx_param = "IN OUT CHAR16 *VariableName",
        .r8_param = "IN OUT EFI_GUID *VendorGuid",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "SetVariable",
        .offset = 0x58,
        .description = "Sets the value of a variable.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_SET_VARIABLE) (IN CHAR16 *VariableName, IN EFI_GUID *VendorGuid, IN UINT32 Attributes, IN UINTN DataSize, IN VOID *Data)",
        .parameters = "VariableName	A Null-terminated string that is the name of the vendor's variable. Each VariableName is unique for each VendorGuid. VariableName must contain 1 or more characters. If VariableName is an empty string, then EFI_INVALID_PARAMETER is returned.\n\
VendorGuid      A unique identifier for the vendor.\n\
Attributes      Attributes bitmask to set for the variable.\n\
DataSize        The size in bytes of the Data buffer. Unless the EFI_VARIABLE_APPEND_WRITE, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, or EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute is set, a size of zero causes the variable to be deleted. When the EFI_VARIABLE_APPEND_WRITE attribute is set, \nthen a SetVariable() call with a DataSize of zero will not cause any change to the variable value (the timestamp associated with the variable may be updated however even if no new data value is provided,\n see the description of the EFI_VARIABLE_AUTHENTICATION_2 descriptor below. In this case the DataSize will not be zero since the EFI_VARIABLE_AUTHENTICATION_2 descriptor will be populated).\n\
Data            The contents for the variable.",
        .rcx_param = "IN CHAR16 *VariableName",
        .rdx_param = "IN EFI_GUID *VendorGuid",
        .r8_param = "IN UINT32 Attributes",
        .r9_param = "IN UINTN DataSize",
        .stack1_param = "IN VOID *Data",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "GetNextHighMonotonicCount",
        .offset = 0x60,
        .description = "Returns the next high 32 bits of the platform's monotonic counter.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_GET_NEXT_HIGH_MONO_COUNT) (OUT UINT32 *HighCount)",
        .parameters = "HighCount	The pointer to returned value.",
        .rcx_param = "OUT UINT32 *HighCount",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "ResetSystem",
        .offset = 0x68,
        .description = "Resets the entire platform.",
        .nr_args = 4,
        .prototype = "VOID(EFIAPI * EFI_RESET_SYSTEM) (IN EFI_RESET_TYPE ResetType, IN EFI_STATUS ResetStatus, IN UINTN DataSize, IN VOID *ResetData OPTIONAL)",
        .parameters = "ResetType	The type of reset to perform.\n\
ResetStatus	The status code for the reset.\n\
DataSize	The size, in bytes, of WatchdogData.\n\
ResetData	For a ResetType of EfiResetCold, EfiResetWarm, or EfiResetShutdown the data buffer starts with a Null-terminated string, optionally followed by additional binary data.",
        .rcx_param = "IN EFI_RESET_TYPE ResetType",
        .rdx_param = "IN EFI_STATUS ResetStatus",
        .r8_param = "IN UINTN DataSize",
        .r9_param = "IN VOID *ResetData OPTIONAL",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "UpdateCapsule",
        .offset = 0x70,
        .description = "Passes capsules to the firmware with both virtual and physical mapping. Depending on the intended consumption, the firmware may process the capsule immediately. If the payload should persist across a system reset, the reset value returned from EFI_QueryCapsuleCapabilities must be passed into ResetSystem() and will cause the capsule to be processed by the firmware as part of the reset process.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_UPDATE_CAPSULE) (IN EFI_CAPSULE_HEADER **CapsuleHeaderArray, IN UINTN CapsuleCount, IN EFI_PHYSICAL_ADDRESS ScatterGatherList OPTIONAL)",
        .parameters = "CapsuleHeaderArray	Virtual pointer to an array of virtual pointers to the capsules being passed into update capsule.\n\
CapsuleCount        Number of pointers to EFI_CAPSULE_HEADER in CaspuleHeaderArray.\n\
ScatterGatherList	Physical pointer to a set of EFI_CAPSULE_BLOCK_DESCRIPTOR that describes the location in physical memory of a set of capsules.",
        .rcx_param = "IN EFI_CAPSULE_HEADER **CapsuleHeaderArray",
        .rdx_param = "IN UINTN CapsuleCount",
        .r8_param = "IN EFI_PHYSICAL_ADDRESS ScatterGatherList OPTIONAL",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "QueryCapsuleCapabilities",
        .offset = 0x78,
        .description = "Returns if the capsule can be supported via UpdateCapsule().",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_QUERY_CAPSULE_CAPABILITIES) (IN EFI_CAPSULE_HEADER **CapsuleHeaderArray, IN UINTN CapsuleCount, OUT UINT64 *MaximumCapsuleSize, OUT EFI_RESET_TYPE *ResetType)",
        .parameters = "CapsuleHeaderArray	Virtual pointer to an array of virtual pointers to the capsules being passed into update capsule.\n\
CapsuleCount        Number of pointers to EFI_CAPSULE_HEADER in CaspuleHeaderArray.\n\
MaxiumCapsuleSize	On output the maximum size that UpdateCapsule() can support as an argument to UpdateCapsule() via CapsuleHeaderArray and ScatterGatherList.\n\
ResetType           Returns the type of reset required for the capsule update.",
        .rcx_param = "IN EFI_CAPSULE_HEADER **CapsuleHeaderArray",
        .rdx_param = "IN UINTN CapsuleCount",
        .r8_param = "OUT UINT64 *MaximumCapsuleSize",
        .r9_param = "OUT EFI_RESET_TYPE *ResetType",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "QueryVariableInfo",
        .offset = 0x80,
        .description = "Returns information about the EFI variables.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_QUERY_VARIABLE_INFO) (IN UINT32 Attributes, OUT UINT64 *MaximumVariableStorageSize, OUT UINT64 *RemainingVariableStorageSize, OUT UINT64 *MaximumVariableSize)",
        .parameters = "Attributes                      Attributes bitmask to specify the type of variables on which to return information.\n\
MaximumVariableStorageSize      On output the maximum size of the storage space available for the EFI variables associated with the attributes specified.\n\
RemainingVariableStorageSize	Returns the remaining size of the storage space available for the EFI variables associated with the attributes specified.\n\
MaximumVariableSize             Returns the maximum size of the individual EFI variables associated with the attributes specified.",
        .rcx_param = "IN UINT32 Attributes",
        .rdx_param = "OUT UINT64 *MaximumVariableStorageSize",
        .r8_param = "OUT UINT64 *RemainingVariableStorageSize",
        .r9_param = "OUT UINT64 *MaximumVariableSize",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    },
    {
        .name = "EMPTY SERVICE",
        .offset = 0x0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .parameters = "",
        .rcx_param = "",
        .rdx_param = "",
        .r8_param = "",
        .r9_param = "",
        .stack1_param = "",
        .stack2_param = "",
        .stack3_param = "",
        .stack4_param = "",
        .count = 0
    }
};

#endif /* efi_system_tables_h */
