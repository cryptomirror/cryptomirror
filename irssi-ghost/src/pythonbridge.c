#include <Python.h>
#include "pythonbridge.h"
#include "utils.h"

PyObject *gModule;
PyObject *gFunc_send_private;
PyObject *gFunc_send_public;
PyObject *gFunc_receive_private;
PyObject *gFunc_receive_public;
PyObject *gFunc_close_private;
PyObject *gFunc_get_pending_messages;
PyObject *gFunc_get_pending_debug_messages;
PyObject *gFunc_ghost_command;
PyObject *gFunc_ghost_query_command;

static void
PyBridge_check_pending(PyObject *func, int action, SERVER_REC *server, const char *recipient)
{
	PyObject *pArgs, *pValue, *pString;
	char *msg;
	int i;
	
	if (!func)
		return;

    pArgs = PyTuple_New(1);
	if (!pArgs)
	{
		IRSSI_INFO(NULL, NULL, "mem error in check pending");
		return;		
	}
	
	if (action != 0)
	{
		recipient = "None";
	}
	
    pString = PyString_FromString(recipient);
	if (!pString)
	{
		IRSSI_INFO(NULL, NULL, "No recipient");
		Py_DECREF(pArgs);
		return;
	}

    PyTuple_SetItem(pArgs, 0, pString);

    pValue = PyObject_CallObject(func, pArgs);

	Py_DECREF(pArgs);
	
	if (!pValue)
	{
		IRSSI_INFO(NULL, NULL, "No return value");
		return;
	}	
	//
	// This routine returns a tuple of messages to send
	//

	for (i = 0; i < PyTuple_Size(pValue); i++)
	{
		pString = PyTuple_GetItem(pValue, i);
		if (pString == NULL) continue;

		msg = PyString_AsString(pString);
		if (msg)
		{
			if (action == 0)
			{
				server->send_message(server, recipient, msg,
						GPOINTER_TO_INT(SEND_TARGET_NICK));				
			}
			else
			{
				IRSSI_INFO(NULL, NULL, "GHOST DEBUG: %s\n", msg);
			}
		}
	}
	
	Py_DECREF(pValue);
}

int
PyBridge_generic_call(PyObject *pFunc, SERVER_REC *server, 
						const char *msg, const char *target, const char *channel, char **ghostmsg)
{
    PyObject *pArgs, *pValue;	
	PyObject *retCode, *retString;
	int ret;
	char *address = server->connrec->address;
	char *nick = server->connrec->nick;
	char *retCharPtr;
	int i;
	int tupleCount;

	ret = 0;
	tupleCount = 3;
	retString = NULL;
	retCode = NULL;
	retCharPtr = NULL;
	
	if (target)
		tupleCount++;
	if (channel)
		tupleCount++;
		
	i = 0;

    pArgs = PyTuple_New(tupleCount);
	if (!pArgs)
		return 5;

    pValue = PyString_FromString(address);
	if (!pValue) {
		ret = 5;
		goto End;
	}
    PyTuple_SetItem(pArgs, i++, pValue);

    pValue = PyString_FromString(nick);
	if (!pValue) {
		ret = 5;
		goto End;
	}
    PyTuple_SetItem(pArgs, i++, pValue);

	if (channel) {
	    pValue = PyString_FromString(channel);
		if (!pValue) {
			ret = 5;
			goto End;
		}
	    PyTuple_SetItem(pArgs, i++, pValue);
	}

	if (target)	{
	    pValue = PyString_FromString(target);
		if (!pValue) {
			ret = 5;
			goto End;
		}
	    PyTuple_SetItem(pArgs, i++, pValue);
	}

    pValue = PyString_FromString(msg);
	if (!pValue) {
		ret = 5;
		goto End;
	}
    PyTuple_SetItem(pArgs, i++, pValue);

    pValue = PyObject_CallObject(pFunc, pArgs);

    if (pValue != NULL) {
		retCode = PyTuple_GetItem(pValue, 0);
		if (retCode == NULL) {
			//
			// No tuple was returned so assume only error code came
			// in
			//
			ret = PyInt_AsLong(pValue);
		}
		else {
			ret = PyInt_AsLong(retCode);

			if (PyTuple_Size(pValue) == 2) {
				retString = PyTuple_GetItem(pValue, 1);
				if (retString == NULL) {
					ret = 7;
				}
				else {
					retCharPtr = strdup(PyString_AsString(retString));
				}
				*ghostmsg = retCharPtr;
			}
		}
//		IRSSI_INFO(NULL, NULL, "Result of call: %d string? %p\n", ret, retCharPtr);
        Py_DECREF(pValue);
	}
	else
	{
		//
		// Should always be getting a return value...
		//
		ret = 6;
	}

End:
	if (pArgs)
		Py_DECREF(pArgs);


	if (ret == 0)
	{
		if (target)
		{
			PyBridge_check_pending(gFunc_get_pending_messages, 0, server, target);			
		}
	}
	
	PyBridge_check_pending(gFunc_get_pending_debug_messages, 1, server, NULL);			
	return ret;
}

int
PyBridge_send_private(void *server, const char *msg, const char *target, char **ghostmsg)
{
	*ghostmsg = NULL;
	return PyBridge_generic_call(gFunc_send_private, server, msg, target, NULL, ghostmsg);
}

int
PyBridge_send_public(void *server, const char *msg, const char *target, char **ghostmsg)
{
	*ghostmsg = NULL;
	return PyBridge_generic_call(gFunc_send_public, server, msg, target, NULL, ghostmsg);
}

int
PyBridge_receive_private(void *server, const char *msg, const char *nick, const char *address, char **ghostmsg)
{
	*ghostmsg = NULL;
	return PyBridge_generic_call(gFunc_receive_private, server, msg, nick, NULL, ghostmsg);
}

int
PyBridge_receive_public(void *server, const char *msg, const char *nick, const char *channel, char **ghostmsg)
{
	*ghostmsg = NULL;
	return PyBridge_generic_call(gFunc_receive_public, server, msg, nick, channel, ghostmsg);
}

int
PyBridge_close_private(const char *address, const char *nick, const char *name)
{
	return 0;
}

int
PyBridge_ghost_query_command(void *server, const char *data, const char *nick, char **response)
{
	*response = NULL;
	return PyBridge_generic_call(gFunc_ghost_query_command, server, data, nick, NULL, response);	
}

int
PyBridge_ghost_command(void *server, const char *data, char **response)
{
	*response = NULL;
	return PyBridge_generic_call(gFunc_ghost_command, server, data, NULL, NULL, response);		
}

int
GetFunction(PyObject *module, char *name, PyObject **func)
{
	PyObject *f;
	
	f = PyObject_GetAttrString(module, name);
	if (f == NULL)
		return 3;
	
	if (!PyCallable_Check(f))
	{
        Py_XDECREF(f);
		return 4;
	}
	
	*func = f;
	return 0;
}

int
PyBridge_init(const char *scriptDirectoryName, const char *module)
{
	PyObject *sysPath, *path;
	int ret;

    Py_Initialize();
	
    sysPath = PySys_GetObject("path");
	if (sysPath == NULL)
		return 1;
    path = PyString_FromString(scriptDirectoryName);
	if (path == NULL)
		return 1;
	
    ret = PyList_Insert(sysPath, 0, path);
	if (ret != 0)
		return 1;
	
    gModule = PyImport_ImportModule(module);
    if (PyErr_Occurred())
        PyErr_Print();
	
	if (gModule == NULL)
	{
		return 2;
	}
	
	//
	// Look up and grab the bridge functions
	//
	ret = GetFunction(gModule, "send_private", &gFunc_send_private);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "send_public", &gFunc_send_public);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "receive_private", &gFunc_receive_private);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "receive_public", &gFunc_receive_public);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "close_private", &gFunc_close_private);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "pending_messages", &gFunc_get_pending_messages);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "pending_debug_messages", &gFunc_get_pending_debug_messages);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "ghost_command", &gFunc_ghost_command);
	if (ret != 0) return ret;
	ret = GetFunction(gModule, "ghost_query_command", &gFunc_ghost_query_command);
	if (ret != 0) return ret;
	
	return 0;
}

void
PyBridge_deinit()
{	
	if (gFunc_send_private)
        Py_XDECREF(gFunc_send_private);		
	if (gFunc_send_public)
        Py_XDECREF(gFunc_send_public);		
	if (gFunc_receive_private)
        Py_XDECREF(gFunc_receive_private);		
	if (gFunc_receive_public)
        Py_XDECREF(gFunc_receive_public);		
	if (gFunc_receive_public)
        Py_XDECREF(gFunc_close_private);		
	if (gFunc_get_pending_messages)
		Py_XDECREF(gFunc_get_pending_messages);
	if (gFunc_get_pending_debug_messages)
		Py_XDECREF(gFunc_get_pending_debug_messages);
	if (gFunc_ghost_command)
		Py_XDECREF(gFunc_ghost_command);
	if (gFunc_ghost_query_command)
		Py_XDECREF(gFunc_ghost_query_command);

	if (gModule != NULL)
		Py_DECREF(gModule);

	gModule = NULL;
	gFunc_send_private = NULL;
	gFunc_send_public = NULL;
	gFunc_receive_private = NULL;
	gFunc_receive_public = NULL;
	gFunc_close_private = NULL;
	gFunc_get_pending_messages = NULL;
	gFunc_ghost_command = NULL;
	gFunc_ghost_query_command = NULL;

    Py_Finalize();
}