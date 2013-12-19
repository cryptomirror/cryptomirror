/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
 *
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
 *               2012  David Goulet <dgoulet@ev0ke.net>
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
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <pthread.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"
#include "pythonbridge.h"

#define MODULE_NAME		"ghost"

FORMAT_REC theme_formats[] = {
        { MODULE_NAME, "ghost", 0 },

        /* Status bar format. */
        { NULL, "Statusbar", 0 } ,

        /* Last element. */
        { NULL, NULL, 0 }
};

int debug = FALSE;

void irssi_send_message(SERVER_REC *irssi, const char *recipient,
		const char *msg);
		

#ifdef NEED_PERL_H
static const char *signal_args_ghost_event[] = {
	"iobject", "string", "string", NULL
};
#endif

/*
 * Need this to decode arguments in perl signal handlers. Maybe irssi should
 * install perl/perl-signals.h which is where this definition comes from?
 */
#ifdef NEED_PERL_H
void perl_signal_register(const char *signal, const char **args);
#endif

/*
 * Global state for the user. Init when the module loads.
 */
void *user_state_global;

/*
 * Pipes all outgoing private messages through py bridge
 */
static void sig_server_sendmsg(void *server, const char *target,
		const char *msg, void *target_type_p)
{
	int ret;
	char *new_msg = NULL;

	IRSSI_INFO(NULL, NULL, "module got send message: %s\n", msg);

	if (GPOINTER_TO_INT(target_type_p) == SEND_TARGET_NICK)
	{
		//
		// Connect python bridge to pm send
		//
		ret = PyBridge_send_private(server, msg, target, &new_msg);		
	}
	else
	{
		//
		// Connect python bridge to non pm send
		//
		ret = PyBridge_send_public(server, msg, target, &new_msg);		
	}

	/* Critical section. On error, message MUST NOT be sent */
	if (ret)
	{
		IRSSI_INFO(NULL, NULL, "send message failed with ret: %d\n", ret);
		signal_stop();
		goto end;
	}

	if (!new_msg) {
		/* Send original message */
		signal_continue(4, server, target, msg, target_type_p);
	} else {
		/* Send encrypted message */
		signal_continue(4, server, target, new_msg, target_type_p);
	}

end:
	if (new_msg) {
		free(new_msg);
	}
	return;
}

/*
 * Pipes all incoming private messages through  py bridge
 */
void sig_message_private(void *server, const char *msg,
		const char *nick, const char *address)
{
	int ret;
	char *new_msg = NULL;

	IRSSI_INFO(NULL, NULL, "module got private message: %s\n", msg);

	ret = PyBridge_receive_private(server, msg, nick, address, &new_msg);
	if (ret) {
		IRSSI_INFO(NULL, NULL, "message private failed with ret: %d\n", ret);
		signal_stop();
		goto end;
	}

	if (!new_msg) {
		signal_continue(4, server, msg, nick, address);
	} else {
		signal_continue(4, server, new_msg, nick, address);
	}

end:
	if (new_msg) {
		free(new_msg);
	}

	return;
}

/*
 * Pipes all incoming public messages through ghost
 */
void sig_message_public(void *server, const char *msg,
		const char *nick, const char *address, const char *channel)
{
	int ret;
	char *new_msg = NULL;

	IRSSI_INFO(NULL, NULL, "module got public message: %s target=%s\n", msg, channel);

	ret = PyBridge_receive_public(server, msg, nick, channel, &new_msg);
	if (ret) {
		IRSSI_INFO(NULL, NULL, "message public failed with ret: %d\n", ret);
		signal_stop();
		goto end;
	}

	if (!new_msg) {
		signal_continue(5, server, msg, nick, address, channel);
	} else {
		signal_continue(5, server, new_msg, nick, address, channel);
	}

end:
	if (new_msg) {
		free(new_msg);
	}
	return;
}
/*
 * Finish a conversation when its query is closed.
 */
static void sig_query_destroyed(QUERY_REC *query)
{
	if (query && query->server && query->server->connrec) {
		PyBridge_close_private(query->server->connrec->address,
							   query->server->connrec->nick,
							   query->name);		
	}
}

/*
 * Handle /me IRC command.
 */
static void cmd_me(const char *data, SERVER_REC *server,
		WI_ITEM_REC *item)
{
	int ret;
	const char *target;
	char *msg, *otrmsg = NULL;
	QUERY_REC *query;

	msg = NULL;

	query = QUERY(item);

	if (!query || !query->server) {
		goto end;
	}

	CMD_IRC_SERVER(server);
	if (!IS_IRC_QUERY(query)) {
		goto end;
	}

	if (!server || !server->connected) {
		cmd_return_error(CMDERR_NOT_CONNECTED);
	}

	target = window_item_get_target(item);

	ret = -1;
//	ret = asprintf(&msg, OTR_IRC_MARKER_ME "%s", data);
	if (ret < 0) {
		goto end;
	}

	/* Critical section. On error, message MUST NOT be sent */
//	ret = otr_send(query->server, msg, target, &otrmsg);
	free(msg);

	if (!otrmsg) {
		goto end;
	}

	signal_stop();

	if (otrmsg) {
		/* Send encrypted message */
		irssi_send_message(SERVER(server), target, otrmsg);
//		otrl_message_free(otrmsg);
	}

	signal_emit("message irc own_action", 3, server, data, item->visible_name);

end:
	return;
}

/*
 * Handle the "/ghost" command.
 */
static void cmd_ghost(const char *data, void *server, WI_ITEM_REC *item)
{
	char *response = NULL;
	QUERY_REC *query;
	int ret;
	
	query = QUERY(item);

	if (*data == '\0') {
		IRSSI_INFO(NULL, NULL, "Alive!");
		goto end;
	}
	
	if (query && query->server && query->server->connrec)
	{
		ret = PyBridge_ghost_query_command(query->server, data, query->name, &response);
		if (response)
		{
			IRSSI_INFO(NULL, NULL, "GHOST QUERY CMD RESPONSE (%d): %s\n", ret, response);			
			free(response);
		}
	}
	else if (server)
	{
		ret = PyBridge_ghost_command(server, data, &response);
		if (response)
		{
			IRSSI_INFO(NULL, NULL, "GHOST CMD RESPONSE (%d): %s\n", ret, response);			
			free(response);
		}
	}

	statusbar_items_redraw("ghost");
end:
	return;
}

/*
 * Optionally finish conversations on /quit. We're already doing this on unload
 * but the quit handler terminates irc connections before unloading.
 */
static void cmd_quit(const char *data, void *server, WI_ITEM_REC *item)
{
//	otr_finishall(user_state_global);
}

/*
 * Handle otr statusbar of irssi.
 */
static void ghost_statusbar(struct SBAR_ITEM_REC *item, int get_size_only)
{
	WI_ITEM_REC *wi = active_win->active;
	QUERY_REC *query = QUERY(wi);
//	int formatnum = 0;

	if (query && query->server && query->server->connrec) {
//		formatnum = otr_get_status_format(query->server, query->name);
	}

//	statusbar_item_default_handler(item, get_size_only,
//			formatnum ? theme_formats[formatnum].def : "", " ", FALSE);
}

/*
 * Create otr module directory if none exists.
 */
static int create_module_dir(void)
{
	int ret;
	char *dir_path = strdup("/no/where/whatever");

	/* Create ~/.irssi/otr directory. */
//	ret = asprintf(&dir_path, "%s%s", get_client_config_dir(), OTR_DIR);
	ret = -1;
	if (ret < 0) {
		IRSSI_MSG("Unable to allocate home dir path.");
		goto error_alloc;
	}

	ret = access(dir_path, F_OK);
	if (ret < 0) {
		ret = mkdir(dir_path, S_IRWXU);
		if (ret < 0) {
			IRSSI_MSG("Unable to create %s directory.", dir_path);
			goto error;
		}
	}

error:
	free(dir_path);
error_alloc:
	return ret;
}

void irssi_send_message(SERVER_REC *irssi, const char *recipient,
		const char *msg)
{
	assert(irssi);

	irssi->send_message(irssi, recipient, msg,
			GPOINTER_TO_INT(SEND_TARGET_NICK));
}

/*
 * irssi init()
 */
void ghost_init(void)
{
	int ret;
	char *module;
	
	module = "ghost";

	//
	// TODO; this needs to come from a configuration
	//
	ret = PyBridge_init("/code/cryptomirror/irssi-ghost/src/python/", module);
	if (ret != 0)
	{
		IRSSI_NOTICE(NULL, NULL, "Could not initialize python bridge with module: %s (%d)\n", module, ret);
		return;
	}

	module_register(MODULE_NAME, "core");

	theme_register(theme_formats);

	ret = create_module_dir();

	signal_add_first("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add_first("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);

	command_bind("ghost", NULL, (SIGNAL_FUNC) cmd_ghost);
	command_bind_first("quit", NULL, (SIGNAL_FUNC) cmd_quit);
	command_bind_irc_first("me", NULL, (SIGNAL_FUNC) cmd_me);

	statusbar_item_register("ghost", NULL, ghost_statusbar);
	statusbar_items_redraw("window");

#ifdef NEED_PERL_H
	perl_signal_register("ghost event", signal_args_ghost_event);
#endif
}

/*
 * irssi deinit()
 */
void ghost_deinit(void)
{
	signal_remove("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);

	command_unbind("ghost", (SIGNAL_FUNC) cmd_ghost);
	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);

	statusbar_item_unregister("ghost");

	theme_unregister();
	PyBridge_deinit();
}
