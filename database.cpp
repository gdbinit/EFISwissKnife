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
 * database.c
 *
 */

#include "database.h"

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

#include <sqlite3.h>
#include <libgen.h>

#include "config.h"
#include "logging.h"

sqlite3 *g_db_connection;

static int set_db_options(void);
static int init_db(void);

int
open_db(void)
{
    /* if db already exists just open it and set options */
    if ( access(DB_FILE, F_OK) != -1 )
    {
        if (sqlite3_open(DB_FILE, &g_db_connection) != SQLITE_OK)
        {
            ERROR_MSG("Unable to open database! (line %d)", __LINE__);
            sqlite3_close(g_db_connection);
            g_db_connection = NULL;
            return 1;
        }
        set_db_options();
    }
    /* else we need to create and init it */
    else
    {
        if (sqlite3_open(DB_FILE, &g_db_connection) == SQLITE_OK)
        {
            set_db_options();
            init_db();
        }
        else
        {
            ERROR_MSG("Unable to create database! (line %d)", __LINE__);
            sqlite3_close(g_db_connection);
            g_db_connection = NULL;
            return 1;
        }
    }
    
    return 0;
}

int
close_db(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Database handle is invalid.");
        return 1;
    }
    sqlite3_close(g_db_connection);
    g_db_connection = NULL;
    return 0;
}

/* we probably want options more safe than this to not risk any fuzzing data? */
static int
set_db_options(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Database handle is invalid.");
        return 1;
    }

    char *err_msg = NULL;
    if (sqlite3_exec(g_db_connection, "PRAGMA journal_mode = MEMORY", NULL, NULL, &err_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to set pragma: %s", err_msg);
        sqlite3_free(err_msg);
        return 1;
    }
    sqlite3_free(err_msg);
    if (sqlite3_exec(g_db_connection, "PRAGMA synchronous = ON", NULL, NULL, &err_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to set pragma: %s", err_msg);
        sqlite3_free(err_msg);
        return 1;
    }
    sqlite3_free(err_msg);
    
    return 0;
}

static int
init_db(void)
{
    if (g_db_connection == NULL)
    {
        ERROR_MSG("Database handle is invalid.");
        return 1;
    }
    
    char main_table_sql[] = "CREATE TABLE main ( \
    file_guid TEXT NOT NULL, \
    path TEXT NOT NULL, \
    type INTEGER NOT NULL, \
    error INTEGER NOT NULL)";
    
    char *error_msg = NULL;
    if (sqlite3_exec(g_db_connection, main_table_sql, NULL, NULL, &error_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to create main table: %s.", error_msg);
        return 1;
    }
    
    char boot_service_stats_table_sql[] = "CREATE TABLE boot_service_stats ( \
    file_guid TEXT NOT NULL, \
    raisetpl INTEGER NOT NULL, \
    restoretpl INTEGER NOT NULL, \
    allocatepages INTEGER NOT NULL, \
    freepages INTEGER NOT NULL, \
    getmemorymap INTEGER NOT NULL, \
    allocatepool INTEGER NOT NULL, \
    freepool INTEGER NOT NULL, \
    createevent INTEGER NOT NULL, \
    settimer INTEGER NOT NULL, \
    waitforevent INTEGER NOT NULL, \
    signalevent INTEGER NOT NULL, \
    closeevent INTEGER NOT NULL, \
    checkevent INTEGER NOT NULL, \
    installprotocolinterface INTEGER NOT NULL, \
    reinstallprotocolinterface INTEGER NOT NULL, \
    uninstallprotocolinterface INTEGER NOT NULL, \
    handleprotocol INTEGER NOT NULL, \
    reserved INTEGER NOT NULL, \
    registerprotocolnotify INTEGER NOT NULL, \
    locatehandle INTEGER NOT NULL, \
    locatedevicepath INTEGER NOT NULL, \
    installconfigurationtable INTEGER NOT NULL, \
    loadimage INTEGER NOT NULL, \
    startimage INTEGER NOT NULL, \
    exit INTEGER NOT NULL, \
    unloadimage INTEGER NOT NULL, \
    exitbootservices INTEGER NOT NULL, \
    getnextmonotoniccount INTEGER NOT NULL, \
    stall INTEGER NOT NULL, \
    setwatchdogtimer INTEGER NOT NULL, \
    connectcontroller INTEGER NOT NULL, \
    disconnectcontroller INTEGER NOT NULL, \
    openprotocol INTEGER NOT NULL, \
    closeprotocol INTEGER NOT NULL, \
    openprotocolinformation INTEGER NOT NULL, \
    protocolsperhandle INTEGER NOT NULL, \
    locatehandlebuffer INTEGER NOT NULL, \
    locateprotocol INTEGER NOT NULL, \
    installmultipleprotocolinterfaces INTEGER NOT NULL, \
    uninstallmultipleprotocolinterfaces INTEGER NOT NULL, \
    calculatecrc32 INTEGER NOT NULL, \
    copymem INTEGER NOT NULL, \
    setmem INTEGER NOT NULL, \
    createeventex INTEGER NOT NULL)";
    
    if (sqlite3_exec(g_db_connection, boot_service_stats_table_sql, NULL, NULL, &error_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to create boot services stats table: %s.", error_msg);
        return 1;
    }

    char runtime_service_stats_table_sql[] = "CREATE TABLE runtime_service_stats ( \
    file_guid TEXT NOT NULL, \
    gettime INTEGER NOT NULL, \
    settime INTEGER NOT NULL, \
    getwakeuptime INTEGER NOT NULL, \
    setwakeuptime INTEGER NOT NULL, \
    setvirtualaddressmap INTEGER NOT NULL, \
    convertpointer INTEGER NOT NULL, \
    getvariable INTEGER NOT NULL, \
    getnextvariablename INTEGER NOT NULL, \
    setvariable INTEGER NOT NULL, \
    getnexthighmonotoniccount INTEGER NOT NULL, \
    resetsystem INTEGER NOT NULL, \
    updatecapsule INTEGER NOT NULL, \
    querycapsulecapabilities INTEGER NOT NULL, \
    queryvariableinfo INTEGER NOT NULL)";
    
    if (sqlite3_exec(g_db_connection, runtime_service_stats_table_sql, NULL, NULL, &error_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to create runtime services stats table: %s.", error_msg);
        return 1;
    }

    char protocols_usage_table_sql[] = "CREATE TABLE protocols_usage ( \
    file_guid TEXT NOT NULL, \
    protocol TEXT NOT NULL , \
    description TEXT NOT NULL, \
    type INTEGER NOT NULL)";
    
    if (sqlite3_exec(g_db_connection, protocols_usage_table_sql, NULL, NULL, &error_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to create protocols usage table: %s.", error_msg);
        return 1;
    }

    char installed_protocols_table_sql[] = "CREATE TABLE installed_protocols ( \
    file_guid TEXT NOT NULL, \
    installed TEXT NOT NULL, \
    type INTEGER NOT NULL)";
    
    if (sqlite3_exec(g_db_connection, installed_protocols_table_sql, NULL, NULL, &error_msg) != SQLITE_OK)
    {
        ERROR_MSG("Unable to create installed protocols table: %s.", error_msg);
        return 1;
    }

    return 0;
}
