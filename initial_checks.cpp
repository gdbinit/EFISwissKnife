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
 * initial_checks.cpp
 *
 */

#include "initial_checks.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <allins.hpp>
#include <segment.hpp>
#include <limits.h>
#include <auto.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <struct.hpp>
#include <funcs.hpp>

#include <libgen.h>
#include <sqlite3.h>

#include "config.h"
#include "utlist.h"
#include "efi_guids.h"
#include "efi_system_tables.h"
#include "logging.h"
#include "database.h"

enum IDA_REGISTERS_X64
{
    REG_RAX = 0x0,
    REG_RCX = 0x1,
    REG_RDX = 0x2,
    REG_RBX = 0x3,
    REG_RSP = 0x4,
    REG_RBP = 0x5,
    REG_RSI = 0x6,
    REG_RDI = 0x7,
    REG_R8  = 0x8,
    REG_R9  = 0x9,
    REG_R10 = 0xA,
    REG_R11 = 0xB,
    REG_R12 = 0xC,
    REG_R13 = 0xD,
    REG_R14 = 0xE
};

enum IDA_REGISTERS_X86
{
    REG_EAX = 0x0,
    REG_ECX = 0x1,
    REG_EDX = 0x2,
    REG_EBX = 0x3,
    REG_ESP = 0x4,
    REG_EBP = 0x5,
    REG_ESI = 0x6,
    REG_EDI = 0x7,
    REG_AL  = 0x10,
    REG_DL  = 0x12
};

enum FILE_TYPE
{
    kPE = 0,
    kTE
};

enum ref_type
{
    kInvalid = -1,
    kLoad,
    kStore
};

struct address_list
{
    struct address_list *next;
    ea_t address;
};

enum system_services
{
    kInstallProcotol = 0,
    kReinstallProtocol,
    kHandleProtocol,
    kRegisterProtocol,
    kOpenProtocol,
    kLocateProtocol,
    kInstallMultiProtocol,
    kInvalidBoot,
    /* run time services */
    kGetVariable,
    kSetVariable,
    kInvalidRunTime
};

struct analysis_entry
{
    ea_t address;
    struct analysis_entry *next;
    enum system_services type;
};

struct guid_stats
{
    EFI_GUID guid;
    struct guid_stats *next;
    int count;
    enum system_services type;
};

struct boot_services_analysis
{
    struct analysis_entry *analysis_head;
    struct guid_stats *guid_stats_head;
    int installed_protocols;
};

struct boot_services_analysis g_boot_services_stats;

struct runtime_services_analysis
{
    struct analysis_entry *analysis_head;
    struct guid_stats *guid_stats_head;
};

struct runtime_services_analysis g_runtime_services_stats;

/* a linked list to hold boot and runtime services references for further processing */
struct service_refs
{
    ea_t offset;
    ea_t ref_addr;
    struct service_refs *next;
};

/* a separate list for boot and runtime tables */
struct service_refs *g_boot_refs_head;
struct service_refs *g_runtime_refs_head;

static int find_system_tables(void);
static const struct services_entry lookup_boot_table(ea_t offset);
static const struct services_entry lookup_runtime_table(ea_t offset);
static int find_data_seg_guids(void);
static void make_bootservice_cmts(void);
static void make_runtimeservice_cmts(void);
static char * string_guid(EFI_GUID *guid);
static void add_guid_stats_entry(enum system_services type, EFI_GUID *guid);
static void print_boot_services_usage(void);
static void print_runtime_services_usage(void);
static void analyse_interesting_boot_services(void);
static void print_protocols_usage(void);
static void log_boot_services_usage(FILE *output_file);
static void log_runtime_services_usage(FILE *output_file);
static void log_protocols_usage(FILE *output_file);
static void sql_protocols_usage(void);
static void sql_file_entry(void);
static void sql_boot_services_usage(void);
static void sql_runtime_services_usage(void);
static int locate_boot_services_refs(void);
static int locate_runtime_services_refs(void);
static void analyse_boot_refs(void);
static void analyse_runtime_refs(void);
static void make_guid_cmt(EFI_GUID *guid, ea_t target_addr);
static void print_guid(EFI_GUID *guid);
static void analyse_interesting_runtime_services(void);

ea_t bootservices_ptr = 0;
ea_t runtimeservices_ptr = 0;

extern sqlite3 *g_db_connection;
char *g_target_guid;

void
do_initial_checks(int arg)
{
    /* get target name */
    char *base_name = basename(command_line_file);
    if (strcmp(base_name, "body.bin") == 0)
    {
        char *temp = basename(dirname(command_line_file));
        size_t temp_len = strlen(temp);
        g_target_guid = (char*)malloc(temp_len+1);
        if (g_target_guid != NULL)
        {
            strlcpy(g_target_guid, temp, temp_len+1);
        }
    }
    else
    {
        size_t temp_len = strlen(base_name);
        g_target_guid = (char*)malloc(temp_len+1);
        if (g_target_guid != NULL)
        {
            strlcpy(g_target_guid, base_name, temp_len+1);
        }
    }

    find_data_seg_guids();
    if (find_system_tables() != 0)
    {
        ERROR_MSG("Failed to find required system tables.");
        return;
    }
    locate_boot_services_refs();
    locate_runtime_services_refs();
    make_bootservice_cmts();
    make_runtimeservice_cmts();
    
    if (g_config.generate_stats == 1)
    {
        analyse_boot_refs();
        analyse_runtime_refs();
        analyse_interesting_boot_services();
        analyse_interesting_runtime_services();
        print_protocols_usage();
        print_boot_services_usage();
        print_runtime_services_usage();
        
        if (g_config.output_log == 1)
        {
            char output_name[QMAXPATH] = {0};
            qsnprintf(output_name, sizeof(output_name), "%s/log", dirname(command_line_file));
            
            FILE *output_file = qfopen(output_name, "w+");
            if (output_file == NULL)
            {
                ERROR_MSG("Can't open log file: %s %s.", output_name, dirname(command_line_file) );
                return;
            }
            
            log_boot_services_usage(output_file);
            log_runtime_services_usage(output_file);
            log_protocols_usage(output_file);
            qfclose(output_file);
        }
    }
    if (g_config.output_sql)
    {
        open_db();
        sql_file_entry();
        sql_protocols_usage();
        sql_boot_services_usage();
        sql_runtime_services_usage();
        close_db();
    }
}

#pragma mark -
#pragma mark Functions to locate system tables
#pragma mark -

/*
 * auxiliary function to locate the Boot Services table
 * via the offsets
 */
static int
locate_bootservices_table(ea_t start_addr, ea_t end_addr, ea_t *out_addr)
{
    uint16_t boot_register = 0;
    int found_boot = 0;
    ea_t current_addr = start_addr;
    /* locate the boot services table */
    do
    {
        decode_insn(current_addr);
        /* we are looking for a mov instruction that involves the RDX register and Boot Services offset in System table */
        if (cmd.itype == NN_mov && cmd.Operands[1].type == o_displ && cmd.Operands[1].phrase == 0x2)
        {
            if (cmd.Operands[0].type == o_reg && cmd.Operands[1].addr == 0x60)
            {
                boot_register = cmd.Operands[0].reg;
                found_boot = 1;
            }
        }
        /* we found the correct offset so verify if it's the right instruction and label it */
        if (found_boot)
        {
            if (cmd.itype == NN_mov && cmd.Operands[1].type == o_reg && cmd.Operands[1].reg == boot_register && cmd.Operands[0].type == o_mem)
            {
                DEBUG_MSG("Found boot storage at 0x%llx Type: %x Address: 0x%llx", current_addr, cmd.Operands[0].type, cmd.Operands[0].addr);
                set_name(cmd.Operands[0].addr, "BootServices_table", SN_CHECK);
                *out_addr = cmd.Operands[0].addr;
                break;
            }
        }
    } while ((current_addr = find_code(current_addr, SEARCH_DOWN)) != BADADDR && current_addr <= end_addr);
    
    /* failure */
    if (found_boot == 0)
    {
        return 1;
    }
    /* success */
    return 0;
}

/*
 * auxiliary function to locate the RunTime Services table
 * via the offsets
 */
static int
locate_runtimeservices_table(ea_t start_addr, ea_t end_addr, ea_t *out_addr)
{
    uint16_t runtime_register = 0;
    int found_runtime = 0;
    ea_t current_addr = start_addr;

    do
    {
        decode_insn(current_addr);
        if (cmd.itype == NN_mov && cmd.Operands[1].type == o_displ && cmd.Operands[1].phrase == 0x2)
        {
            if (cmd.Operands[0].type == o_reg && cmd.Operands[1].addr == 0x58)
            {
                runtime_register = cmd.Operands[0].reg;
                found_runtime = 1;
            }
        }
        if (found_runtime)
        {
            if (cmd.itype == NN_mov && cmd.Operands[1].type == o_reg && cmd.Operands[1].reg == runtime_register && cmd.Operands[0].type == o_mem)
            {
                DEBUG_MSG("Found runtime storage at 0x%llx", current_addr);
                set_name(cmd.Operands[0].addr, "RunTimeServices_table", SN_CHECK);
                *out_addr = cmd.Operands[0].addr;
                break;
            }
        }
    } while ((current_addr = find_code(current_addr, SEARCH_DOWN)) != BADADDR && current_addr <= end_addr);
    
    if (found_runtime == 0)
    {
        return 1;
    }
    /* success */
    return 0;
}

/*
 * entry function that scans for Boot and RunTime service tables
 * labels interesting places and extracts information out of it
 *
 */
static int
find_system_tables(void)
{
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info == NULL)
    {
        ERROR_MSG("Can't find a valid code segment!");
        return 1;
    }
    
    /* locate start() */
    func_t *f = NULL;
    int found = 0;
    for (int idx = 0; idx < get_func_qty(); idx++)
    {
        char fname[1024] = {0};
        f = getn_func(idx);
        get_func_name(f->startEA, fname, sizeof(fname));
        if (strcmp(fname, "start") == 0 || strcmp(fname, "_ModuleEntryPoint") == 0)
        {
            DEBUG_MSG("Found function %s at %llx", fname, f->startEA);
            found = 1;
            break;
        }
    }
    
    if (found == 0)
    {
        ERROR_MSG("Can't find start(). Giving up...");
        return 1;
    }
    
    /* we found start() so start looking for the tables */
    
    int ret = 0;
    ret = locate_bootservices_table(f->startEA, f->endEA, &bootservices_ptr);
    /* try alternative method - there might be a call processing it */
    if (ret != 0)
    {
        DEBUG_MSG("Trying to locate boot services inside functions");
        ea_t current_addr = f->startEA;
        while ((current_addr = find_code(current_addr, SEARCH_DOWN)) != BADADDR && current_addr <= f->endEA)
        {
            decode_insn(current_addr);
            if (cmd.itype == NN_call) // XXX: call types? near? far?
            {
                func_t *call_f = NULL;
                call_f = get_func(cmd.Operands[0].addr);
                if (call_f == NULL)
                {
                    continue;
                }
                /* try to locate the boot table inside, stop if successful */
                if (locate_bootservices_table(call_f->startEA, call_f->endEA, &bootservices_ptr) == 0)
                {
                    break;
                }
            }
        }
    }
    
    if (bootservices_ptr == 0)
    {
        ERROR_MSG("Can't locate boot services table pointer.");
        return 1;
    }
    
    ret = locate_runtimeservices_table(f->startEA, f->endEA, &runtimeservices_ptr);
    if (ret != 0)
    {
        DEBUG_MSG("Trying to locate runtime services inside functions");
        ea_t current_addr = f->startEA;
        while ((current_addr = find_code(current_addr, SEARCH_DOWN)) != BADADDR && current_addr <= f->endEA)
        {
            decode_insn(current_addr);
            if (cmd.itype == NN_call) // XXX: call types? near? far?
            {
                func_t *call_f = NULL;
                call_f = get_func(cmd.Operands[0].addr);
                if (call_f == NULL)
                {
                    continue;
                }
                /* try to locate the runtime table inside, stop if successful */
                if (locate_runtimeservices_table(call_f->startEA, call_f->endEA, &runtimeservices_ptr) == 0)
                {
                    break;
                }
            }
        }
    }
    
    if (runtimeservices_ptr == 0)
    {
        ERROR_MSG("Can't locate runtime services table pointer.");
        return 1;
    }
    
    /* success */
    return 0;
}

/*
 * function to lookup the Boot Services table via offset
 */
static const struct services_entry
lookup_boot_table(ea_t offset)
{
    size_t array_size = sizeof(boot_services_table) / sizeof(*boot_services_table);
    for (int i = 0; i < array_size; i++)
    {
        if (boot_services_table[i].offset == offset)
        {
            return boot_services_table[i];
        }
    }
    /* failure */
    return boot_services_table[0];
}

/*
 * function to lookup the RunTime Services table via offset
 *
 */
static const struct services_entry
lookup_runtime_table(ea_t offset)
{
    size_t array_size = sizeof(runtime_services_table) / sizeof(*runtime_services_table);
    for (int i = 0; i < array_size; i++)
    {
        if (runtime_services_table[i].offset == offset)
        {
            return runtime_services_table[i];
        }
    }
    /* failure */
    return runtime_services_table[0];
}

static void
add_guid_stats_entry(enum system_services type, EFI_GUID *guid)
{
    struct guid_stats *stats_entry = NULL;
    int found_stats = 0;
    LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
    {
        if (stats_entry->type == type && memcmp((void*)&stats_entry->guid, (void*)guid, sizeof(EFI_GUID)) == 0)
        {
            stats_entry->count++;
            found_stats = 1;
        }
    }
    if (found_stats == 0)
    {
        struct guid_stats *stats_new_entry = (struct guid_stats*)malloc(sizeof(struct guid_stats));
        if (stats_new_entry != NULL)
        {
            memcpy((void*)&stats_new_entry->guid, (void*)guid, sizeof(EFI_GUID));
            stats_new_entry->count = 1;
            stats_new_entry->type = type;
            LL_APPEND(g_boot_services_stats.guid_stats_head, stats_new_entry);
        }
    }
}

/*
 * function to process the calls to interesting boot services we want to gather stats on
 */
static void
analyse_interesting_boot_services(void)
{
    struct analysis_entry *entry = NULL;
    /* process LocateProtocol() Boot service */
        
    /* first thing is to find out which GUIDs are used in LocateProtocol() */
    LL_FOREACH(g_boot_services_stats.analysis_head, entry)
    {
        DEBUG_MSG("Locate protocol entry at 0x%llx", entry->address);
        /* find and track the GUID */
        ea_t current_addr = entry->address;
        /* max number of instructions backwards we want to search */
        int max_nr_insts = 32;
        
        EFI_GUID current_guid = {0};
        while ((current_addr = find_code(current_addr, SEARCH_UP)) != BADADDR && max_nr_insts > 0)
        {
            decode_insn(current_addr);
            /* LocateProtocol() */
            if (entry->type == kLocateProtocol)
            {
                /* GUID pointer is loaded into RCX, the first argument to LocateProtocol() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RCX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kLocateProtocol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    break;
                }
            }
            /* HandleProtocol() */
            else if (entry->type == kHandleProtocol)
            {
                /* GUID pointer is loaded into RDX, the second argument to HandleProtocol() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RDX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kHandleProtocol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    break;
                }
            }
            /* RegisterProtocolNotify() */
            else if (entry->type == kRegisterProtocol)
            {
                /* GUID pointer is loaded into RCX, the first argument to RegisterProtocolNotify() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RCX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kRegisterProtocol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    break;
                }
            }
            /* InstallProtocolInterface () */
            else if (entry->type == kInstallProcotol)
            {
                /* GUID pointer is loaded into RDX, the second argument to InstallProtocolInterface() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RDX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kInstallProcotol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    g_boot_services_stats.installed_protocols++;
                    break;
                }
            }
            /* ReinstallProtocolInterface() */
            else if (entry->type == kReinstallProtocol)
            {
                /* GUID pointer is loaded into RDX, the second argument to ReinstallProtocolInterface() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RDX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kReinstallProtocol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    break;
                }
            }
            /* OpenProtocol() */
            else if (entry->type == kOpenProtocol)
            {
                /* GUID pointer is loaded into RDX, the second argument to OpenProtocol() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RDX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kOpenProtocol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    break;
                }
            }
            /* XXX: kInstallMultiProtocol */
            /* let's assume only one protocol is installed because this version
             * is recommended due to more error checking that InstallProtocol
             */
            else if (entry->type == kInstallMultiProtocol)
            {
                /* GUID pointer is loaded into RDX, the second argument to OpenProtocol() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RDX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    add_guid_stats_entry(kInstallMultiProtocol, &current_guid);
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    g_boot_services_stats.installed_protocols++;
                    break;
                }
            }
            max_nr_insts--;
        }
    }
}

/*
 * function to go over all detected boot services references and comment it
 * based on configuration settings
 */
static void
make_bootservice_cmts(void)
{
    struct service_refs *ref_entry = NULL;
    LL_FOREACH(g_boot_refs_head, ref_entry)
    {
        char address_string[4096] = {0};
        struct services_entry table_entry = lookup_boot_table(ref_entry->offset);
        if (g_config.comment_description == 1 && g_config.comment_prototype == 0)
        {
            qsnprintf(address_string, sizeof(address_string), "BootServices->%s()\n\n%s", table_entry.name, table_entry.description);
        }
        else if (g_config.comment_description == 0 && g_config.comment_prototype == 1)
        {
            qsnprintf(address_string, sizeof(address_string), "BootServices->%s()\n\n%s\n\n%s", table_entry.name, table_entry.prototype, table_entry.parameters);
        }
        else if (g_config.comment_description == 1 && g_config.comment_prototype == 1)
        {
            qsnprintf(address_string, sizeof(address_string), "BootServices->%s()\n\n%s\n\n%s\n\n%s", table_entry.name, table_entry.prototype, table_entry.description, table_entry.parameters);
        }
        else
        {
            qsnprintf(address_string, sizeof(address_string), "BootServices->%s()", table_entry.name);
        }
        
        set_cmt(ref_entry->ref_addr, address_string, 0);
    }
}

/*
 * auxiliary function to comment a RunTime Service call
 * based on configuration settings
 */
static void
make_runtimeservice_cmts(void)
{
    struct service_refs *ref_entry = NULL;
    LL_FOREACH(g_runtime_refs_head, ref_entry)
    {
        char address_string[4096] = {0};
        struct services_entry table_entry = lookup_runtime_table(ref_entry->offset);
        if (g_config.comment_description == 1 && g_config.comment_prototype == 0)
        {
            qsnprintf(address_string, sizeof(address_string), "RunTimeServices->%s()\n\n%s", table_entry.name, table_entry.description);
        }
        else if (g_config.comment_description == 0 && g_config.comment_prototype == 1)
        {
            qsnprintf(address_string, sizeof(address_string), "RunTimeServices->%s()\n\n%s\n\n%s", table_entry.name, table_entry.prototype, table_entry.parameters);
        }
        else if (g_config.comment_description == 1 && g_config.comment_prototype == 1)
        {
            qsnprintf(address_string, sizeof(address_string), "RunTimeServices->%s()\n\n%s\n\n%s\n\n%s", table_entry.name, table_entry.prototype, table_entry.description, table_entry.parameters);
        }
        else
        {
            qsnprintf(address_string, sizeof(address_string), "RunTimeServices->%s()", table_entry.name);
        }
        
        set_cmt(ref_entry->ref_addr, address_string, 0);
    }
}

/*
 * locate call references to the boot services table
 * this is what we use to find out where are all the calls to boot services
 */
static int
locate_boot_services_refs(void)
{
    func_t *f = NULL;

    if (bootservices_ptr != 0)
    {
        DEBUG_MSG("Looking up Boot Services references...");
        xrefblk_t xb;
        for ( bool ok=xb.first_to(bootservices_ptr, XREF_ALL); ok; ok=xb.next_to() )
        {
            ea_t ref_to_table = xb.from;
            /* disassemble and process each reference */
            f = get_func(ref_to_table);
            ea_t current_addr = ref_to_table;
            
            enum ref_type type;
            uint16_t boot_src_reg = 0;
            uint16_t boot_dst_reg = 0;
            
            decode_insn(ref_to_table);
            /* find the type of reference */
            if (cmd.itype == NN_mov)
            {
                /* loading the boot table pointer into a register */
                if (cmd.Operands[1].type == o_mem && cmd.Operands[1].addr == bootservices_ptr)
                {
                    type = kLoad;
                    boot_dst_reg = cmd.Operands[0].reg;
                }
                /* storing the boot table pointer */
                else if (cmd.Operands[0].type == o_mem && cmd.Operands[0].addr == bootservices_ptr)
                {
                    type = kStore;
                    boot_src_reg = cmd.Operands[1].reg;
                }
            }
            if (type == kInvalid)
            {
                continue;
            }
            
            ea_t function_end = 0;
            if (f == NULL)
            {
                function_end = current_addr + 64;
            }
            else
            {
                function_end = f->endEA;
            }
            while ((current_addr = find_code(current_addr, SEARCH_DOWN)) != BADADDR && current_addr <= function_end)
            {
                decode_insn(current_addr);
                /* verify if register was modified before the call so we give up in that case */
                if (type == kStore && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == boot_src_reg)
                {
                    break;
                }
                if ((cmd.itype == NN_callni  || cmd.itype == NN_jmpni) && cmd.Operands[0].type == o_displ)
                {
                    if ((type == kStore && cmd.Operands[0].phrase == boot_src_reg) ||
                        (type == kLoad && cmd.Operands[0].phrase == boot_dst_reg))
                    {
                        struct service_refs *new_ref_entry = (struct service_refs*)malloc(sizeof(struct service_refs));
                        if (new_ref_entry != NULL)
                        {
                            new_ref_entry->offset = cmd.Operands[0].addr;
                            new_ref_entry->ref_addr = current_addr;
                            LL_APPEND(g_boot_refs_head, new_ref_entry);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /* success */
    return 0;
}

/*
 * locate call references to the runtime services table
 * this is what we use to find out where are all the calls to runtime services
 */
static int
locate_runtime_services_refs(void)
{
    func_t *f = NULL;

    if (runtimeservices_ptr != 0)
    {
        DEBUG_MSG("Looking up RunTime Services references...");
        xrefblk_t xb;
        for ( bool ok=xb.first_to(runtimeservices_ptr, XREF_ALL); ok; ok=xb.next_to() )
        {
            ea_t ref_to_table = xb.from;
            /* disassemble and process each reference */
            f = get_func(ref_to_table);
            ea_t current_addr = ref_to_table;
            
            enum ref_type type = kInvalid;
            uint16_t runtime_src_reg = 0;
            uint16_t runtime_dst_reg = 0;
            
            decode_insn(ref_to_table);
            /* find the type of reference */
            if (cmd.itype == NN_mov)
            {
                /* loading the boot table pointer into a register */
                if (cmd.Operands[1].type == o_mem && cmd.Operands[1].addr == runtimeservices_ptr)
                {
                    type = kLoad;
                    runtime_dst_reg = cmd.Operands[0].reg;
                }
                /* storing the boot table pointer */
                else if (cmd.Operands[0].type == o_mem && cmd.Operands[0].addr == runtimeservices_ptr)
                {
                    type = kStore;
                    runtime_src_reg = cmd.Operands[1].reg;
                }
            }
            if (type == kInvalid)
            {
                continue;
            }
            ea_t function_end = 0;
            if (f == NULL)
            {
                function_end = current_addr + 64;
            }
            else
            {
                function_end = f->endEA;
            }

            while ((current_addr = find_code(current_addr, SEARCH_DOWN)) != BADADDR && current_addr <= function_end)
            {
                decode_insn(current_addr);
                /* verify if register was modified before the call so we give up in that case */
                if (type == kStore && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == runtime_src_reg)
                {
                    break;
                }
                if ((cmd.itype == NN_callni || cmd.itype == NN_jmpni) && cmd.Operands[0].type == o_displ)
                {
                    if ((type == kStore && cmd.Operands[0].phrase == runtime_src_reg) ||
                        (type == kLoad && cmd.Operands[0].phrase == runtime_dst_reg))
                    {
                        struct service_refs *new_ref_entry = (struct service_refs*)malloc(sizeof(struct service_refs));
                        if (new_ref_entry != NULL)
                        {
                            new_ref_entry->offset = cmd.Operands[0].addr;
                            new_ref_entry->ref_addr = current_addr;
                            LL_APPEND(g_runtime_refs_head, new_ref_entry);
                            break;
                        }
                    }
                }
            }
        }
    }

    /* success */
    return 0;
}

/*
 * helper function to add to analysis linked list
 * the interesting services we want to extract more data later on
 */
static void
add_boot_analysis_entry(ea_t address, enum system_services type)
{
    struct analysis_entry *new_entry = (struct analysis_entry*)malloc(sizeof(struct analysis_entry));
    if (new_entry != NULL)
    {
        new_entry->address = address;
        new_entry->type = type;
        LL_APPEND(g_boot_services_stats.analysis_head, new_entry);
    }
}

/*
 * iterate over all detected locations with references to boot services table
 * and generate usage stats
 * and also another data set of installed/used protocol GUIDs
 */
static void
analyse_boot_refs(void)
{
    struct service_refs *ref_entry = NULL;
    LL_FOREACH(g_boot_refs_head, ref_entry)
    {
        /* increase the count for this service so we can have stats about each used service */
        size_t array_size = sizeof(boot_services_table) / sizeof(*boot_services_table);
        for (int i = 0; i < array_size; i++)
        {
            if (boot_services_table[i].offset == ref_entry->offset)
            {
                boot_services_table[i].count++;
                break;
            }
        }
        
        /* add the interesting entries to another table for further analysis
         * we are essentially interested in services that install or use protocol GUIDs 
         * from other EFI binaries
         */
        switch (ref_entry->offset)
        {
            /* InstallProtocolInterface */
        case 0x80:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kInstallProcotol);
                break;
            }
            /* ReinstallProtocolInterface */
        case 0x88:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kReinstallProtocol);
                break;
            }
            /* HandleProtocol */
        case 0x98:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kHandleProtocol);
                break;
            }
            /* RegisterProtocolNotify */
        case 0xA8:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kRegisterProtocol);
                break;
            }
            /* OpenProtocol */
        case 0x118:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kOpenProtocol);
                break;
            }
            /* LocateProtocol */
        case 0x140:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kLocateProtocol);
                break;
            }
            /* InstallMultipleProtocolInterfaces */
        case 0x148:
            {
                add_boot_analysis_entry(ref_entry->ref_addr, kInstallMultiProtocol);
                break;
            }
        default:
            break;
        }
    }
}

/*
 * helper function to add to analysis linked list
 * the interesting services we want to extract more data later on
 */
static void
add_runtime_analysis_entry(ea_t address, enum system_services type)
{
    struct analysis_entry *new_entry = (struct analysis_entry*)malloc(sizeof(struct analysis_entry));
    if (new_entry != NULL)
    {
        new_entry->address = address;
        new_entry->type = type;
        LL_APPEND(g_runtime_services_stats.analysis_head, new_entry);
    }
}

/*
 * iterate over all detected locations with references to runtime services table
 * and generate usage stats
 * and also another data set of interesting services for further analysis
 */
static void
analyse_runtime_refs(void)
{
    struct service_refs *ref_entry = NULL;
    LL_FOREACH(g_runtime_refs_head, ref_entry)
    {
        size_t array_size = sizeof(runtime_services_table) / sizeof(*runtime_services_table);
        for (int i = 0; i < array_size; i++)
        {
            if (runtime_services_table[i].offset == ref_entry->offset)
            {
                runtime_services_table[i].count++;
                break;
            }
        }
        /* add the interesting entries to another table for further analysis
         * we are essentially interested in services that deal with EFI variables
         */
        switch (ref_entry->offset)
        {
            /* GetVariable */
            case 0x48:
                add_runtime_analysis_entry(ref_entry->ref_addr, kGetVariable);
                break;
            /* SetVariable */
            case 0x58:
                add_runtime_analysis_entry(ref_entry->ref_addr, kSetVariable);
                break;
            default:
                break;
        }
    }
}

/*
 * it's harder to keep track of Get/SetVariable because many times the GUID is an argument
 * to a function
 */
static void
analyse_interesting_runtime_services(void)
{
    struct analysis_entry *entry = NULL;
    
    /* first thing is to find out which GUIDs are used in LocateProtocol() */
    LL_FOREACH(g_runtime_services_stats.analysis_head, entry)
    {
        /* find and track the GUID */
        ea_t current_addr = entry->address;
        /* max number of instructions backwards we want to search */
        int max_nr_insts = 32;
        
        EFI_GUID current_guid = {0};
        while ((current_addr = find_code(current_addr, SEARCH_UP)) != BADADDR && max_nr_insts > 0)
        {
            decode_insn(current_addr);
            /* GetVariable() */
            if (entry->type == kGetVariable)
            {
                DEBUG_MSG("Locate GetVariable() runtime service entry at 0x%llx", entry->address);
                /* GUID pointer is loaded into RDX, the second argument to GetVariable() */
                if (cmd.itype == NN_lea && cmd.Operands[0].type == o_reg && cmd.Operands[0].reg == REG_RDX)
                {
                    ea_t target_guid_addr = cmd.Operands[1].addr;
                    /* retrieve the GUID being used and store in the structure field */
                    get_many_bytes(target_guid_addr, (void*)&current_guid, sizeof(EFI_GUID));
                    if (current_guid.Data1 == 0x0 ||  current_guid.Data1 == 0xFFFFFFFF)
                    {
                        ERROR_MSG("Invalid data retrieved, failed to identify GUID? Address: 0x%llx", current_addr);
                        break;
                    }
                    /* make a comment with the GUID where it's loaded */
                    if (g_config.comment_guid == 1)
                    {
                        make_guid_cmt(&current_guid, current_addr);
                    }
                    break;
                }
            }
            /* SetVariable() */
            else if (entry->type == kSetVariable)
            {
//                DEBUG_MSG("Locate SetVariable() runtime service entry at 0x%llx", entry->address);
            }
            /* continue to preceeding instruction */
            max_nr_insts--;
        }
    }

}

/*
 * go over the data segment and try to locate valid GUIDs
 *
 */
static int
find_data_seg_guids(void)
{
    segment_t *seg_info = get_segm_by_name(".data");
    if (seg_info == NULL)
    {
        ERROR_MSG("Can't find a valid code segment!");
        return 1;
    }
    ea_t current_addr = seg_info->startEA;
    
    while (current_addr != BADADDR && current_addr <= seg_info->endEA)
    {
        EFI_GUID guid = {0};
        
        get_many_bytes(current_addr, (void*)&guid, sizeof(EFI_GUID));

        /* ignore invalid/empty GUIDs */
        if (guid.Data1 == 0x0 || guid.Data1 == 0xFFFFFFFF)
        {
            current_addr += 8;
            continue;
        }

        for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
        {
            if (memcmp((void*)&guid_table[i].guid, (void*)&guid, sizeof(EFI_GUID)) == 0)
            {
                DEBUG_MSG("Found GUID at 0x%llx - %s", current_addr, guid_table[i].name);
                make_guid_cmt(&guid_table[i].guid, current_addr);
                set_name(current_addr, guid_table[i].name, SN_CHECK);
            }
        }
        current_addr += 8;
    }
    
    return 0;
}

#pragma mark -
#pragma mark Output to screen functions
#pragma mark -

/*
 * go over the tables and display each service usage count
 */
static void
print_boot_services_usage(void)
{
    OUTPUT_MSG(".---------------------------------------------.");
    OUTPUT_MSG("|         Boot services global usage          |");
    OUTPUT_MSG(".---------------------------------------------.");
    size_t array_size = sizeof(boot_services_table) / sizeof(*boot_services_table);
    for (int i = 0; i < array_size; i++)
    {
        if (boot_services_table[i].count > 0)
        {
            OUTPUT_MSG("| %-36s | %4d |", boot_services_table[i].name, boot_services_table[i].count);
        }
    }
    OUTPUT_MSG("`---------------------------------------------´");
}

static void
print_runtime_services_usage(void)
{
    OUTPUT_MSG(".----------------------------------.");
    OUTPUT_MSG("|   RunTime services global usage  |");
    OUTPUT_MSG(".----------------------------------.");
    size_t array_size = sizeof(runtime_services_table) / sizeof(*runtime_services_table);
    for (int i = 0; i < array_size; i++)
    {
        if (runtime_services_table[i].count > 0)
        {
            OUTPUT_MSG("| %-25s | %4d |", runtime_services_table[i].name, runtime_services_table[i].count);
        }
    }
    OUTPUT_MSG("`----------------------------------´");
}

static void
print_protocols_usage(void)
{
    /* InstallProtocolInterface */
    
    OUTPUT_MSG(".-------------------------------------------------------------------------------------------------.");
    OUTPUT_MSG("|                                  Global Protocols Usage                                         |");
    OUTPUT_MSG(".-------.--------------------------------------.--------------------------------------------------.");
    OUTPUT_MSG("| Count |                GUID                  |                    Description                   |");
    OUTPUT_MSG(".-------'--------------------------------------'--------------------------------------------------.");
    struct guid_stats *stats_entry = NULL;
    LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
    {
        /* try to see if it's a known GUID */
        int found = 0;
        int index = 0;
        for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
        {
            if (memcmp((void*)&guid_table[i].guid, (void*)&stats_entry->guid, sizeof(EFI_GUID)) == 0)
            {
                found = 1;
                index = i;
                break;
            }
        }
        if (found)
        {
            OUTPUT_MSG("| %5d | %-36s | %-48s |", stats_entry->count, string_guid(&stats_entry->guid), guid_table[index].name);
        }
        else
        {
            OUTPUT_MSG("| %5d | %-36s | N/A                                              |", stats_entry->count, string_guid(&stats_entry->guid));
        }
    }
    OUTPUT_MSG("`-------------------------------------------------------------------------------------------------´");
    
    /* output information about installed protocols, if any exist */
    if (g_boot_services_stats.installed_protocols > 0)
    {
        OUTPUT_MSG(".-----------------------------------------------------------------------------------------.");
        OUTPUT_MSG("|                               Installed Protocols                                       |");
        OUTPUT_MSG(".--------------------------------------.--------------------------------------------------.");
        OUTPUT_MSG("|                GUID                  |                    Description                   |");
        OUTPUT_MSG(".--------------------------------------'--------------------------------------------------.");
        
        LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
        {
            if (stats_entry->type == kInstallProcotol || stats_entry->type == kInstallMultiProtocol)
            {
                /* try to see if it's a known GUID */
                int found = 0;
                int index = 0;
                for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
                {
                    if (memcmp((void*)&guid_table[i].guid, (void*)&stats_entry->guid, sizeof(EFI_GUID)) == 0)
                    {
                        found = 1;
                        index = i;
                        break;
                    }
                }
                if (found)
                {
                    OUTPUT_MSG("| %-36s | %-48s |", string_guid(&stats_entry->guid), guid_table[index].name);
                }
                else
                {
                    OUTPUT_MSG("| %-36s | N/A                                              |", string_guid(&stats_entry->guid));
                }
            }
        }
        OUTPUT_MSG("`-----------------------------------------------------------------------------------------´");
    }
    
#if 0
    LL_FOREACH(boot_services_stats.locate_protocol_head, entry)
    {
        int found = 0;
        for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
        {
            if (memcmp((void*)&guid_table[i].guid, (void*)&entry->guid, sizeof(EFI_GUID)) == 0)
            {
                DEBUG_MSG("Found known GUID at 0x%llx - %s", entry->address, guid_table[i].name);
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            DEBUG_MSG("Unknown GUID:");
            print_guid(&entry->guid);
        }
    }
#endif
}

#pragma mark -
#pragma mark Output to file functions
#pragma mark -

/*
 * go over the tables and display each service usage count
 */
static void
log_boot_services_usage(FILE *output_file)
{
    if (output_file == NULL)
    {
        ERROR_MSG("Invalid file handle.");
        return;
    }
    
    qfprintf(output_file, ".---------------------------------------------.\n");
    qfprintf(output_file, "|         Boot services global usage          |\n");
    qfprintf(output_file, ".---------------------------------------------.\n");
    size_t array_size = sizeof(boot_services_table) / sizeof(*boot_services_table);
    for (int i = 0; i < array_size; i++)
    {
        if (boot_services_table[i].count > 0)
        {
            qfprintf(output_file, "| %-36s | %4d |\n", boot_services_table[i].name, boot_services_table[i].count);
        }
    }
    qfprintf(output_file, "`---------------------------------------------´\n");
}

static void
log_runtime_services_usage(FILE *output_file)
{
    if (output_file == NULL)
    {
        ERROR_MSG("Invalid file handle.");
        return;
    }

    qfprintf(output_file, ".----------------------------------.\n");
    qfprintf(output_file, "|   RunTime services global usage  |\n");
    qfprintf(output_file, ".----------------------------------.\n");
    size_t array_size = sizeof(runtime_services_table) / sizeof(*runtime_services_table);
    for (int i = 0; i < array_size; i++)
    {
        if (runtime_services_table[i].count > 0)
        {
            qfprintf(output_file, "| %-25s | %4d |\n", runtime_services_table[i].name, runtime_services_table[i].count);
        }
    }
    qfprintf(output_file, "`----------------------------------´\n");
}

static void
log_protocols_usage(FILE *output_file)
{
    if (output_file == NULL)
    {
        ERROR_MSG("Invalid file handle.");
        return;
    }
    
    qfprintf(output_file, ".--------------------------------------------------------------------------------------------------.\n");
    qfprintf(output_file, "|                                  Global Protocols Usage                                          |\n");
    qfprintf(output_file, ".-------.--------------------------------------.---------------------------------------------------.\n");
    qfprintf(output_file, "| Count |                GUID                  |                    Description                    |\n");
    qfprintf(output_file, ".-------'--------------------------------------'---------------------------------------------------.\n");
    struct guid_stats *stats_entry = NULL;
    LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
    {
        /* try to see if it's a known GUID */
        int found = 0;
        int index = 0;
        for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
        {
            if (memcmp((void*)&guid_table[i].guid, (void*)&stats_entry->guid, sizeof(EFI_GUID)) == 0)
            {
                found = 1;
                index = i;
                break;
            }
        }
        if (found)
        {
            qfprintf(output_file, "| %5d | %-36s | %-49s |\n", stats_entry->count, string_guid(&stats_entry->guid), guid_table[index].name);
        }
        else
        {
            qfprintf(output_file, "| %5d | %-36s | N/A                                               |\n", stats_entry->count, string_guid(&stats_entry->guid));
        }
    }
    qfprintf(output_file, "`--------------------------------------------------------------------------------------------------´\n");
    
    /* output information about installed protocols, if any exist */
    if (g_boot_services_stats.installed_protocols > 0)
    {
        qfprintf(output_file, ".------------------------------------------------------------------------------------------.\n");
        qfprintf(output_file, "|                               Installed Protocols                                        |\n");
        qfprintf(output_file, ".--------------------------------------.---------------------------------------------------.\n");
        qfprintf(output_file, "|                GUID                  |                    Description                    |\n");
        qfprintf(output_file, ".--------------------------------------'----------------------------------.----------------.\n");
        
        LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
        {
            if (stats_entry->type == kInstallProcotol || stats_entry->type == kInstallMultiProtocol)
            {
                /* try to see if it's a known GUID */
                int found = 0;
                int index = 0;
                for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
                {
                    if (memcmp((void*)&guid_table[i].guid, (void*)&stats_entry->guid, sizeof(EFI_GUID)) == 0)
                    {
                        found = 1;
                        index = i;
                        break;
                    }
                }
                if (found)
                {
                    qfprintf(output_file, "| %-36s | %-49s |\n", string_guid(&stats_entry->guid), guid_table[index].name);
                }
                else
                {
                    qfprintf(output_file, "| %-36s | N/A                                               |\n", string_guid(&stats_entry->guid));
                }
            }
        }
        qfprintf(output_file, "`------------------------------------------------------------------------------------------´\n");
    }
}

#pragma mark -
#pragma mark Output to database functions
#pragma mark -

static void
sql_file_entry(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Invalid database handle.");
        return;
    }
    
    sqlite3_stmt *sqlStatement = NULL;
    int ret = 0;
    
    ret = sqlite3_prepare_v2(g_db_connection, "INSERT INTO main VALUES (?,?,?,?)", -1, &sqlStatement, NULL);
    if (ret != SQLITE_OK)
    {
        ERROR_MSG("Failed prepare statement.");
        return;
    }
    sqlite3_bind_text(sqlStatement, 1, g_target_guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(sqlStatement, 2, command_line_file, -1, SQLITE_STATIC);
    /* XXX: fix type */
    sqlite3_bind_int(sqlStatement, 3, 0);
    /* XXX: fix error */
    sqlite3_bind_int(sqlStatement, 4, 0);
    
    while ((ret = sqlite3_step(sqlStatement)) == SQLITE_ROW)
    {
        
    }
    if (ret != SQLITE_DONE)
    {
        ERROR_MSG("Error inserting db record.");
        return;
    }
    sqlite3_reset(sqlStatement);
    DEBUG_MSG("Ret value %d", ret);
    sqlite3_finalize(sqlStatement);
}

/*
 * go over the tables and display each service usage count
 */
static void
sql_protocols_usage(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Invalid database handle.");
        return;
    }
    
    DEBUG_MSG("Preparing to insert protocols usage data...");
    sqlite3_stmt *sqlStatement = NULL;
    int ret = 0;
    
    ret = sqlite3_prepare_v2(g_db_connection, "INSERT INTO protocols_usage VALUES (?,?,?,?)", -1, &sqlStatement, NULL);
    if (ret != SQLITE_OK)
    {
        ERROR_MSG("Failed prepare statement.");
        return;
    }
    sqlite3_bind_text(sqlStatement, 1, g_target_guid, -1, SQLITE_STATIC);

    struct guid_stats *stats_entry = NULL;
    LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
    {
        /* try to see if it's a known GUID */
        int found = 0;
        int index = 0;
        for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
        {
            if (memcmp((void*)&guid_table[i].guid, (void*)&stats_entry->guid, sizeof(EFI_GUID)) == 0)
            {
                found = 1;
                index = i;
                break;
            }
        }
        sqlite3_bind_text(sqlStatement, 2, string_guid(&stats_entry->guid), -1, SQLITE_STATIC);

        if (found)
        {
            sqlite3_bind_text(sqlStatement, 3, guid_table[index].name, -1, SQLITE_STATIC);

        }
        else
        {
            sqlite3_bind_text(sqlStatement, 3, "N/A", -1, SQLITE_STATIC);
        }
        sqlite3_bind_int(sqlStatement, 4, stats_entry->type);
        
        DEBUG_MSG("Executing statement...");
        while ((ret = sqlite3_step(sqlStatement)) == SQLITE_ROW)
        {
            
        }
        if (ret != SQLITE_DONE)
        {
            ERROR_MSG("Error inserting db record.");
            return;
        }
        sqlite3_reset(sqlStatement);
        DEBUG_MSG("Ret value %d", ret);
    }
    sqlite3_finalize(sqlStatement);
    
    if (g_boot_services_stats.installed_protocols > 0)
    {
        DEBUG_MSG("Preparing to insert installed protocols data...");
        ret = sqlite3_prepare_v2(g_db_connection, "INSERT INTO installed_protocols VALUES (?,?,?)", -1, &sqlStatement, NULL);
        if (ret != SQLITE_OK)
        {
            ERROR_MSG("Failed to prepare installed protocols statement: %d", ret);
            return;
        }

        sqlite3_bind_text(sqlStatement, 1, g_target_guid, -1, SQLITE_STATIC);

        LL_FOREACH(g_boot_services_stats.guid_stats_head, stats_entry)
        {
            if (stats_entry->type == kInstallProcotol || stats_entry->type == kInstallMultiProtocol)
            {
                /* try to see if it's a known GUID */
                int found = 0;
                int index = 0;
                for (int i = 0; i < sizeof(guid_table) / sizeof(*guid_table) - 1; i++)
                {
                    if (memcmp((void*)&guid_table[i].guid, (void*)&stats_entry->guid, sizeof(EFI_GUID)) == 0)
                    {
                        found = 1;
                        index = i;
                        break;
                    }
                }
                sqlite3_bind_text(sqlStatement, 2, string_guid(&stats_entry->guid), -1, SQLITE_STATIC);
                sqlite3_bind_int(sqlStatement, 3, stats_entry->type);
                
                DEBUG_MSG("Executing statement...");
                while ((ret = sqlite3_step(sqlStatement)) == SQLITE_ROW)
                {
                    
                }
                if (ret != SQLITE_DONE)
                {
                    ERROR_MSG("Error inserting db record.");
                    return;
                }
                sqlite3_reset(sqlStatement);
                DEBUG_MSG("Ret value %d", ret);
            }
        }
    }
}

static void
sql_boot_services_usage(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Invalid database handle.");
        return;
    }
    
    DEBUG_MSG("Preparing to insert boot services usage data...");

    sqlite3_stmt *sqlStatement = NULL;
    int ret = 0;
    
    ret = sqlite3_prepare_v2(g_db_connection, "INSERT INTO boot_service_stats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &sqlStatement, NULL);
    if (ret != SQLITE_OK)
    {
        ERROR_MSG("Failed prepare statement: %d.", ret);
        return;
    }
    sqlite3_bind_text(sqlStatement, 1, g_target_guid, -1, SQLITE_STATIC);

    size_t array_size = sizeof(boot_services_table) / sizeof(*boot_services_table);
    for (int i = 1; i < array_size-1; i++)
    {
        sqlite3_bind_int(sqlStatement, i+1, boot_services_table[i].count);
    }
    DEBUG_MSG("Executing statement...");
    while ((ret = sqlite3_step(sqlStatement)) == SQLITE_ROW)
    {
        
    }
    if (ret != SQLITE_DONE)
    {
        ERROR_MSG("Error inserting db record.");
        return;
    }
    sqlite3_reset(sqlStatement);
    DEBUG_MSG("Ret value %d", ret);
}

static void
sql_runtime_services_usage(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Invalid database handle.");
        return;
    }
    
    DEBUG_MSG("Preparing to insert runtime services usage data...");
    
    sqlite3_stmt *sqlStatement = NULL;
    int ret = 0;
    
    ret = sqlite3_prepare_v2(g_db_connection, "INSERT INTO runtime_service_stats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &sqlStatement, NULL);
    if (ret != SQLITE_OK)
    {
        ERROR_MSG("Failed prepare statement: %d.", ret);
        return;
    }
    sqlite3_bind_text(sqlStatement, 1, g_target_guid, -1, SQLITE_STATIC);
    
    size_t array_size = sizeof(runtime_services_table) / sizeof(*runtime_services_table);
    for (int i = 1; i < array_size-1; i++)
    {
        sqlite3_bind_int(sqlStatement, i+1, runtime_services_table[i].count);
    }

    DEBUG_MSG("Executing statement...");
    while ((ret = sqlite3_step(sqlStatement)) == SQLITE_ROW)
    {
        
    }
    if (ret != SQLITE_DONE)
    {
        ERROR_MSG("Error inserting db record.");
        return;
    }
    sqlite3_reset(sqlStatement);
    DEBUG_MSG("Ret value %d", ret);
}

#pragma mark -
#pragma mark GUID printing related functions
#pragma mark -

static char *
string_guid(EFI_GUID *guid)
{
    static char guid_string[256] = {0};
    qsnprintf(guid_string, sizeof(guid_string), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              guid->Data1, guid->Data2, guid->Data3,
              guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
              guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    
    return guid_string;
}

/* helper to just print the GUID */
static void
print_guid(EFI_GUID *guid)
{
    OUTPUT_MSG("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
               guid->Data1, guid->Data2, guid->Data3,
               guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
               guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

static void
make_guid_cmt(EFI_GUID *guid, ea_t target_addr)
{
    if (guid->Data1 == 0x00000000)
    {
        return;
    }
    char cmt_string[1024] = {0};
    qsnprintf(cmt_string, sizeof(cmt_string), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              guid->Data1, guid->Data2, guid->Data3,
              guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
              guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    set_cmt(target_addr, cmt_string, 0);
}
