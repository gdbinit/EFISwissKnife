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
 * main.cpp
 *
 */

//// IDA SDK includes
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <allins.hpp>
#include <segment.hpp>

#include "initial_checks.h"
#include "config.h"
#include "logging.h"

#define VERSION "1.0"

#define EFI_IMAGE_DOS_SIGNATURE     0x5A4D     // MZ
#define EFI_IMAGE_PE_SIGNATURE      0x00004550 // PE
#define EFI_IMAGE_TE_SIGNATURE      0x5A56     // VZ

/* default options set */
struct config g_config = { .comment_prototype = 1, .comment_description = 0, .comment_guid = 1, .generate_stats = 1, .generate_log = 0, .output_log = 0, .output_sql = 0, .debug_msgs = 0};

int IDAP_init(void)
{
    
    msg(" _____ _____ _____    _____       _         _____     _ ___\n");
    msg("|   __|   __|     |  |   __|_ _ _|_|___ ___|  |  |___|_|  _|___\n");
    msg("|   __|   __|-   -|  |__   | | | | |_ -|_ -|    -|   | |  _| -_|\n");
    msg("|_____|__|  |_____|  |_____|_____|_|___|___|__|__|_|_|_|_| |___|\n");
    msg("----------------------------------------------------------------\n");
    msg("                 EFI Swiss Knife, v%s\n", VERSION);
    msg("              (c) fG!, 2016, 2017 - reverser@put.as\n");
    msg("----------------------------------------------------------------\n");
    return PLUGIN_OK;
}

void IDAP_term(void)
{
    if (g_config.generate_log == 1)
    {
        close_log_file();
    }
    return;
}

/*
 * where all the fun starts!
 *
 * arguments:
 * 0 - default configuration mode
 * 1 - display configuration options
 * 2 - batch mode
 *
 */
void IDAP_run(int arg)
{
    // this is useful for testing - plugin will be unloaded after execution
    // so we can copy a new version and call it again using IDC: RunPlugin("EFISwissKnife", -1);
    // this gave (gives?) problems in Windows version
    extern plugin_t PLUGIN;
	PLUGIN.flags |= PLUGIN_UNL;
    
    /* XXX: TE binaries not supported at the moment */
    segment_t *seg_info = get_segm_by_name("HEADER");
    if (seg_info == NULL)
    {
        ERROR_MSG("Can't find a valid code segment!");
        return;
    }
    ea_t current_addr = seg_info->startEA;
    uint16_t header_bytes = 0;
    get_many_bytes(current_addr, &header_bytes, sizeof(header_bytes));
    if (header_bytes == EFI_IMAGE_TE_SIGNATURE)
    {
        ERROR_MSG("TE Binaries not supported at the moment.");
        return;
    }
    
    if (int(arg) == 1)
    {
        /*
         * bit 0: add function prototype comment
         * bit 1: add function description comment
         * bit 2: generate stats
         * bit 3: comment GUID in service calls
         * bit 4: generate output file
         * bit 5: generate log file
         * bit 6: write to database
         * bit 7: write debugging messages
         */
        /* set some default configuration values */
        ushort checkbox = 1 << 0 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 7;
        char form[]="Configuration Options\n<Add function ~p~rototype comment:C>\n<Add function ~d~escription comment:C><Generate ~s~tats:C><~C~omment GUID in service calls:C><Generate output file:C><Generate log file:C><Database output:C><Debug messages:C>>";
        /* check if user cancelled the form */
        if (AskUsingForm_c(form, &checkbox) == 0)
        {
            return;
        }
        if (checkbox & 1 << 0)
        {
            g_config.comment_prototype = 1;
        }
        if (checkbox & 1 << 1)
        {
            g_config.comment_description = 1;
        }
        if (checkbox & 1 << 2)
        {
            g_config.generate_stats = 1;
        }
        if (checkbox & 1 << 3)
        {
            g_config.comment_guid = 1;
        }
        if (checkbox & 1 << 4)
        {
            g_config.output_log = 1;
        }
        if (checkbox & 1 << 5)
        {
            g_config.generate_log = 1;
        }
        if (checkbox & 1 << 6)
        {
            g_config.output_sql = 1;
        }
        if (checkbox & 1 << 7)
        {
            g_config.debug_msgs = 1;
        }
    }
    /* batch mode defaults */
    else if (int(arg) == 2)
    {
        g_config.generate_stats = 1;
        g_config.generate_log = 1;
        g_config.debug_msgs = 1;
        g_config.output_sql = 1;
    }
    
    /* open log file */
    if (g_config.generate_log == 1)
    {
        open_log_file();
    }
    
    do_initial_checks((int)arg);
    
    msg("EFI Swiss Knife - All done!\n");
	return;
}

char IDAP_comment[]	= "Plugin to improve EFI reversing";
char IDAP_help[]	= "EFI Swiss Knife";
char IDAP_name[]	= "EFI Swiss Knife";
char IDAP_hotkey[]	= "";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	IDAP_init,
	IDAP_term,
	IDAP_run,
	IDAP_comment,
	IDAP_help,
	IDAP_name,
	IDAP_hotkey
};
