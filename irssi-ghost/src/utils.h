/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2012 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef IRSSI_OTR_UTILS_H
#define IRSSI_OTR_UTILS_H

void utils_free_args(char ***argv, int argc);
void utils_extract_command(const char *data, char **_cmd);
void utils_explode_args(const char *_data, char ***_argv, int *_argc);
int utils_io_extract_smp(const char *data, char **question, char **secret);
void utils_string_to_upper(char *string);
int utils_auth_extract_secret(const char *_data, char **secret);
void utils_hash_parts_to_readable_hash(const char **parts, char *dst);
char *utils_trim_string(char *s);

#define UOFF_T_LONG_LONG 1

#define zmalloc(x) calloc(1, x)

#include <src/common.h>
#include <src/core/commands.h>
#include <src/core/modules.h>
#include <src/core/servers.h>
#include <src/core/signals.h>
#include <src/core/levels.h>
#include <src/core/queries.h>
#include <src/fe-common/core/printtext.h>
#include <src/fe-common/core/fe-windows.h>
#include <src/core/modules.h>
#include <src/core/settings.h>
#include <src/irc/core/irc.h>
#include <src/irc/core/irc-commands.h>
#include <src/irc/core/irc-queries.h>
#include <src/irc/core/irc-servers.h>
#include <src/fe-text/statusbar-item.h>

/*
 * Irssi macros for printing text to console.
 */
#define OTR_IRSSI_MSG_PREFIX ""

#define IRSSI_MSG(fmt, ...)                                                 \
        do {                                                                    \
                printtext(NULL, NULL, MSGLEVEL_MSGS, OTR_IRSSI_MSG_PREFIX fmt,      \
                                                ## __VA_ARGS__);                                    \
        } while (0)

#define IRSSI_INFO(irssi, username, fmt, ...)                               \
        do {                                                                    \
                printtext(irssi, username, MSGLEVEL_CRAP, OTR_IRSSI_MSG_PREFIX fmt, \
                                                ## __VA_ARGS__);                                    \
        } while (0)
#define IRSSI_NOTICE(irssi, username, fmt, ...)                             \
        do {                                                                    \
                printtext(irssi, username, MSGLEVEL_MSGS, OTR_IRSSI_MSG_PREFIX fmt, \
                                                ## __VA_ARGS__);                                    \
        } while (0)
#define IRSSI_DEBUG(fmt, ...) \
        do {                                                                    \
                if (debug) {                                                        \
                        printtext(NULL, NULL, MSGLEVEL_MSGS, OTR_IRSSI_MSG_PREFIX fmt,  \
                                                ## __VA_ARGS__);                                    \
                }                                                                   \
        } while (0)


#endif /* IRSSI_OTR_UTILS_H */
