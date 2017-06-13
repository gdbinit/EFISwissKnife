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
 * logging.c
 *
 */

#include "logging.h"

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

#include <time.h>

#include "config.h"

static FILE *g_log_file;

int
open_log_file(void)
{
    g_log_file = qfopen(LOG_FILE, "a+");
    if (g_log_file == NULL)
    {
        ERROR_MSG("Can't open log file: %s %s.", LOG_FILE);
        return 1;
    }
    /* time stamp start of log */
    time_t start_time = time(NULL);

    char logtime_string[32];

    /* write date */
    if (start_time != (time_t)-1)
    {
        char *c = ctime(&start_time);
        if (c != NULL)
        {
            strlcpy(logtime_string, c, sizeof(logtime_string));
            logtime_string[strlen(logtime_string)-1] = '\0'; // string from ctime includes return
        }
    }
    qfprintf(g_log_file, "---[ Start @ %s ]---\n", logtime_string);
    qfprintf(g_log_file, "---[ Target: %s ]---\n", command_line_file);
    return 0;
}

int
close_log_file(void)
{
    if (g_log_file != NULL)
    {
        time_t start_time = time(NULL);
        
        char logtime_string[32];
        
        /* write date */
        if (start_time != (time_t)-1)
        {
            char *c = ctime(&start_time);
            if (c != NULL)
            {
                strlcpy(logtime_string, c, sizeof(logtime_string));
                logtime_string[strlen(logtime_string)-1] = '\0'; // string from ctime includes return
            }
        }
        qfprintf(g_log_file, "---[ End @ %s ]---\n", logtime_string);
        qfprintf(g_log_file, "---[ Target: %s ]---\n\n", command_line_file);
        qfclose(g_log_file);
    }
    return 0;
}

void
log_error_msg(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (g_config.generate_log == 1)
    {
        qvfprintf(g_log_file, format, args);
    }
    else
    {
        vmsg(format, args);
    }

    va_end(args);
}

void
log_debug_msg(const char *format, ...)
{
    if (g_config.debug_msgs == 1)
    {
        va_list args;
        va_start(args, format);
        if (g_config.generate_log == 1)
        {
            qvfprintf(g_log_file, format, args);
        }
        else
        {
            vmsg(format, args);
        }
        
        va_end(args);
    }
}
