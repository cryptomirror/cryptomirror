#ifndef _PYTHON_BRIDGE_H
#define _PYTHON_BRIDGE_H

int PyBridge_init(const char *scriptDirectoryName, const char *module);
void PyBridge_deinit();

int PyBridge_close_private(const char *address, const char *nick, const char *name);
int PyBridge_send_private(void *server, const char *msg, const char *target, char **ghostmsg);
int PyBridge_send_public(void *server, const char *msg, const char *target, char **ghostmsg);
int PyBridge_receive_private(void *server, const char *msg, const char *nick, const char *address, char **ghostmsg);
int PyBridge_receive_public(void *server, const char *msg, const char *nick, const char *channel, char **ghostmsg);

int
PyBridge_ghost_query_command(void *server, const char *data, const char *nick, char **response);
int
PyBridge_ghost_command(void *server, const char *data, char **response);
#endif