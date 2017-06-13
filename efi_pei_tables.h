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
 * efi_pei_tables.h
 *
 */

#ifndef efi_swiss_knife_efi_pei_tables_h
#define efi_swiss_knife_efi_pei_tables_h

#include <stdint.h>

struct pei_services_entry
{
    char description[1024];
    char prototype[512];
    char name[256];
    uint32_t offset;
    uint32_t nr_args;
    uint32_t count;
};

struct pei_services_entry
{
    {
        .name = "FAILED PEI PPI",
        .offset = 0x0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .count = 0
    },
    {
        .name = "InstallPpi",
        .offset = 0x18,
        .description = "This service is the first one provided by the PEI Foundation. This function installs an interface in the PEI PPI database by GUID. The purpose of the service is to publish an interface that other parties can use to call additional PEIMs.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_INSTALL_PPI) (IN CONST EFI_PEI_SERVICES **PeiServices, IN CONST EFI_PEI_PPI_DESCRIPTOR *PpiList)",
        .count = 0
    },
    {
        .name = "ReInstallPpi",
        .offset = 0x1C,
        .description = "This function reinstalls an interface in the PEI PPI database by GUID. The purpose of the service is to publish an interface that other parties can use to replace a same-named interface in the protocol database with a different interface.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_REINSTALL_PPI) (IN CONST EFI_PEI_SERVICES **PeiServices, IN CONST EFI_PEI_PPI_DESCRIPTOR *OldPpi, IN CONST EFI_PEI_PPI_DESCRIPTOR *NewPpi)",
        .count = 0
    },
    {
        .name = "LocatePpi",
        .offset = 0x20,
        .description = "This function locates an interface in the PEI PPI database by GUID.",
        .nr_args = 5,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_LOCATE_PPI) (IN CONST EFI_PEI_SERVICES **PeiServices, IN CONST EFI_GUID *Guid, IN UINTN Instance, IN OUT EFI_PEI_PPI_DESCRIPTOR **PpiDescriptor OPTIONAL, IN OUT VOID **Ppi)",
        .count = 0
    },
    {
        .name = "NotifyPpi",
        .offset = 0x24,
        .description = "This function installs a notification service to be called back when a given interface is installed or reinstalled. The purpose of the service is to publish an interface that other parties can use to call additional PPIs that may materialize later.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_NOTIFY_PPI) (IN CONST EFI_PEI_SERVICES **PeiServices, IN CONST EFI_PEI_NOTIFY_DESCRIPTOR *NotifyList)",
        .count = 0
    },
    {
        .name = "GetBootMode",
        .offset = 0x28,
        .description = "This function returns the present value of the boot mode.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_GET_BOOT_MODE) (IN CONST EFI_PEI_SERVICES **PeiServices, OUT EFI_BOOT_MODE *BootMode)",
        .count = 0
    },
    {
        .name = "SetBootMode",
        .offset = 0x2C,
        .description = "This function sets the value of the boot mode.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_SET_BOOT_MODE) (IN CONST EFI_PEI_SERVICES **PeiServices, IN EFI_BOOT_MODE BootMode)",
        .count = 0
    },
    {
        .name = "GetHobList",
        .offset = 0x30,
        .description = "This function returns the pointer to the list of Hand-Off Blocks (HOBs) in memory.",
        .nr_args = 2,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_GET_HOB_LIST) (IN CONST EFI_PEI_SERVICES **PeiServices, OUT VOID **HobList)",
        .count = 0
    },
    {
        .name = "CreateHob",
        .offset = 0x34,
        .description = "This service, published by the PEI Foundation, abstracts the creation of a Hand-Off Block's (HOB's) headers.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_CREATE_HOB) (IN CONST EFI_PEI_SERVICES **PeiServices, IN UINT16 Type, IN UINT16 Length, IN OUT VOID **Hob)",
        .count = 0
    },
    {
        .name = "FfsFindNextVolume",
        .offset = 0x38,
        .description = "The purpose of the service is to abstract the capability of the PEI Foundation to discover instances of firmware volumes in the system. Given the input file pointer, this service searches for the next matching file in the Firmware File System (FFS) volume.",
        .nr_args = 3,
        .prototype = "EFI_STATUS (EFIAPI *EFI_PEI_FFS_FIND_NEXT_VOLUME) (IN struct _EFI_PEI_SERVICES **PeiServices, IN UINTN Instance, IN OUT EFI_FIRMWARE_VOLUME_HEADER **FwVolHeader)",
        .count = 0
    },
    {
        .name = "FfsFindNextFile",
        .offset = 0x3C,
        .description = "The purpose of the service is to abstract the capability of the PEI Foundation to discover instances of firmware files in the system. Given the input file pointer, this service searches for the next matching file in the Firmware File System (FFS) volume.",
        .nr_args = 4,
        .prototype = "EFI_STATUS (EFIAPI *EFI_PEI_FFS_FIND_NEXT_FILE) (IN struct _EFI_PEI_SERVICES **PeiServices, IN EFI_FV_FILETYPE SearchType, IN EFI_FIRMWARE_VOLUME_HEADER *FwVolHeader, IN OUT EFI_FFS_FILE_HEADER **FileHeader);",
        .count = 0
    },
    {
        .name = "FfsFindSectionData",
        .offset = 0x40,
        .description = "Given the input file pointer, this service searches for the next matching file in the Firmware File System (FFS) volume.",
        .nr_args = 4,
        .prototype = "EFI_STATUS (EFIAPI *EFI_PEI_FFS_FIND_SECTION_DATA) (IN struct _EFI_PEI_SERVICES **PeiServices, IN EFI_SECTION_TYPE SectionType, IN EFI_FFS_FILE_HEADER *FfsFileHeader, IN OUT VOID **SectionData);",
        .count = 0
    },
    {
        .name = "InstallPeiMemory",
        .offset = 0x44,
        .description = "This function registers the found memory configuration with the PEI Foundation.",
        .nr_args = 3,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_INSTALL_PEI_MEMORY) (IN CONST EFI_PEI_SERVICES **PeiServices, IN EFI_PHYSICAL_ADDRESS MemoryBegin, IN UINT64 MemoryLength)",
        .count = 0
    },
    {
        .name = "AllocatePages",
        .offset = 0x48,
        .description = "The purpose of the service is to publish an interface that allows PEIMs to allocate memory ranges that are managed by the PEI Foundation.",
        .nr_args = 4,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_ALLOCATE_PAGES) (IN CONST EFI_PEI_SERVICES **PeiServices, IN EFI_MEMORY_TYPE MemoryType, IN UINTN Pages, OUT EFI_PHYSICAL_ADDRESS *Memory)",
        .count = 0
    },
    {
        .name = "AllocatePool",
        .offset = 0x4C,
        .description = "The purpose of this service is to publish an interface that allows PEIMs to allocate memory ranges that are managed by the PEI Foundation.",
        .nr_args = 3,
        .prototype = " EFI_STATUS(EFIAPI * EFI_PEI_ALLOCATE_POOL) (IN CONST EFI_PEI_SERVICES **PeiServices, IN UINTN Size, OUT VOID **Buffer)",
        .count = 0
    },
    {
        .name = "CopyMem",
        .offset = 0x50,
        .description = "This service copies the contents of one buffer to another buffer.",
        .nr_args = 3,
        .prototype = "VOID(EFIAPI * EFI_PEI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, IN UINTN Length)",
        .count = 0
    },
    {
        .name = "SetMem",
        .offset = 0x54,
        .description = "The service fills a buffer with a specified value.",
        .nr_args = 3,
        .prototype = "VOID(EFIAPI * EFI_PEI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)",
        .count = 0
    },
    {
        .name = "ReportStatusCode",
        .offset = 0x58,
        .description = "This service publishes an interface that allows PEIMs to report status codes. \
        ReportStatusCode() is called by PEIMs that wish to report status information on their progress. The principal use model is for a PEIM to emit one of the standard 32-bit error codes. This will allow a platform owner to ascertain the state of the system, especially under conditions where the full consoles might not have been installed.",
        .nr_args = 6,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_REPORT_STATUS_CODE) (IN CONST EFI_PEI_SERVICES **PeiServices, IN EFI_STATUS_CODE_TYPE Type, IN EFI_STATUS_CODE_VALUE Value, IN UINT32 Instance, IN CONST EFI_GUID *CallerId OPTIONAL, IN CONST EFI_STATUS_CODE_DATA *Data OPTIONAL)",
        .count = 0
    },
    {
        .name = "ResetSystem",
        .offset = 0x5C,
        .description = "Resets the entire platform. \
        This service resets the entire platform, including all processors and devices, and reboots the system. This service will never return EFI_SUCCESS.",
        .nr_args = 1,
        .prototype = "EFI_STATUS(EFIAPI * EFI_PEI_RESET_SYSTEM) (IN CONST EFI_PEI_SERVICES **PeiServices)",
        .count = 0
    },
    {
        .name = "CpuIo",
        .offset = 0x60,
        .description = "Provides an interface that a PEIM can call to execute an I/O transaction. This service is installed by an architectural PEI driver by copying the interface pointer into this table.",
        .nr_args = 1,
        .prototype = "",
        .count = 0
    },
    {
        .name = "PciCfg",
        .offset = 0x64,
        .description = "Provides an interface that a PEIM can call to execute PCI Configuration transactions. This service is installed by an architectural PEI driver by copying the interface pointer into this table.",
        .nr_args = 1,
        .prototype = "",
        .count = 0
    },
    {
        .name = "EMPTY PPI",
        .offset = 0x0,
        .description = "",
        .nr_args = 1,
        .prototype = "",
        .count = 0
    }
    
};

#endif /* efi_pei_tables_h */
