AM_CFLAGS = $(PACKAGE_FLAGS)

IRSSI_DIST=/usr/include/irssi

IRSSI_INCLUDE = -I$(IRSSI_DIST) \
				-I$(IRSSI_DIST)/src \
				-I$(IRSSI_DIST)/src/fe-common/core \
				-I$(IRSSI_DIST)/src/core \
				-I$(IRSSI_DIST)/src/fe-text \
				-I$(IRSSI_DIST)/src/irc \
				-I$(IRSSI_DIST)/src/irc/core \
				-I$(IRSSI_DIST)/src/irc/dcc \
				-I$(IRSSI_DIST)/src/irc/notifylist

PYTHON_INCLUDE = `python2.7-config --cflags`		

INCLUDES = -I$(top_srcdir)/src $(IRSSI_INCLUDE) $(PYTHON_INCLUDE)

plugindir = $(IRSSI_MODULE_DIR)
plugin_LTLIBRARIES = libghost.la

libghost_la_SOURCES = cmd.c cmd.h utils.h utils.c module.c module.h pythonbridge.c pythonbridge.h

libghost_la_LDFLAGS = -avoid-version -module -lpython2.7
libghost_la_LDFLAGS += $(LIBOTR_LIBS) $(LIBGCRYPT_LIBS) -lpthread

install-data-hook:
	chmod 644 $(DESTDIR)/$(plugindir)/irssi_ghostlib.so
	rm $(DESTDIR)/$(plugindir)/irssi_ghostlib.la

uninstall-hook:
	rm $(DESTDIR)/$(plugindir)/irssi_ghostlib.so
