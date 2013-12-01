/*
 * Based on Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2008 - Uli Meis <a.sporto+bee@gmail.com>
 *               2012 - David Goulet <dgoulet@ev0ke.net>
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

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>

#include "cmd.h"

extern int debug;

/*
 * /ghost debug
 */
static void _cmd_debug(void *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	debug = !debug;
	if (debug) {
		IRSSI_INFO(NULL, NULL, "Debug on");
	} else {
		IRSSI_INFO(NULL, NULL, "Debug off");
	}
}

/*
 * /ghost version 
 */
static void _cmd_version(void *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	IRSSI_INFO(NULL, NULL, "OTR module version: " VERSION);
}

/*
 * /ghost help 
 */
static void _cmd_help(void *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	int ret;
	char *cmd_line;

	ret = asprintf(&cmd_line, "%sHELP ghost", settings_get_str("cmdchars"));
	if (ret < 0) {
		return;
	}

	/* Call /help otr instread of duplicating the text output. */
	signal_emit("send command", 3, cmd_line, irssi, NULL);

	free(cmd_line);
}

static struct irssi_commands cmds[] = {
	{ "version", _cmd_version },
	{ "debug", _cmd_debug },
	{ "help", _cmd_help },
	{ NULL, NULL },
	{ NULL, NULL }
};

/*
 * Entry point for all other commands.
 *
 * Return TRUE if command exist and is executed else FALSE.
 */
void cmd_generic(void *ustate, SERVER_REC *irssi,
		const char *target, char *cmd, const void *data)
{
	struct irssi_commands *commands = cmds;

	assert(cmd);

	do {
		if (strcmp(commands->name, cmd) == 0) {
			commands->func(ustate, irssi, target, data);
			goto end;
		}
	} while ((++commands)->name);

	IRSSI_NOTICE(irssi, target, "Unknown command %9%s%n", cmd);

end:
	return;
}
