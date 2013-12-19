## IRSSI-GHOST ##

This is an irssi module which provides python hooks for transforming communications
in a manner suitable for privacy operations. 



Requirements
---------
* irssi-dev >= 0.8.15 - [Download Link](http://www.irssi.org/download)

* glib2.0 Development package

* automake, autoconf, libtool

* Python-dev

* NaCl

Installation
---------

Run the following commands to compile and install.

`$ ./bootstrap`

`$ ./configure --prefix="/usr"`

`$ make && make install`

Testing that your module loads
---------

1. `/load emptylib` in the Irssi main window.

...

Good luck! 