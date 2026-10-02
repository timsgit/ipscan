#
#    (C) Copyright 2011-2026 Tim Chappell.
#
#    This file is part of IPscan.
#
#    IPscan is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with IPscan.  If not, see <http://www.gnu.org/licenses/>.

# Makefile version
# 0.01 - initial version
# 0.02 - added MySQL support
# 0.03 - addition of ping functionality (suid bit set)
# 0.04 - default to MySQL
# 0.05 - remove sqlite support
# 0.06 - move $(LIBS) to the end of each link line
# 0.07 - minor corrections to support FreeBSD gmake builds
# 0.08 - add extra compiler checks
# 0.09 - add 'running as root' check for install step
# 0.10 - strip symbols from the final objects
# 0.11 - add additional object security-related options
# 0.12 - tidy up
# 0.13 - add support for servers where SETUID is missing/unavailable
# 0.14 - add support for servers where UDP is missing/available
# 0.15 - update copyright year
# 0.16 - force warnings to be errors
# 0.17 - update copyright year
# 0.18 - update copyright year
# 0.19 - add debug build capability, update copyright year
# 0.20 - update copyright year
# 0.21 - update copyright year
# 0.22 - update copyright year
# 0.23 - update copyright year
# 0.24 - further compiler warnings added
# 0.25 - update copyright year to 2026
# 0.26 - add the new header files
# 0.27 - move to support Linux capabilities as well as root/suid approach
# 0.28 - various fixes, typos and other improvements

# -------------------------------------------------------------------------
# Support builds without UDP port scans
# Set this variable to 0 if you don't want UDP port scans to be included
UDP_AVAILABLE=1
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Support builds without PING scans
# Set this variable to 0 if you don't want PING scans to be included
PING_AVAILABLE=1
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# IMPORTANT NOTE: All types of port scan (ICMPv6 ECHO_REQUEST, UDPv6, and TCPv6) require raw sockets
#
# If you are using Linux with CAP_NET_RAW support then include
# METHOD=caps in the make command, e.g. make METHOD=caps && make install METHOD=caps
#	this will build a binary owned by the Apache user and including CAP_NET_RAW support
#
# If you are NOT using Linux, or a version of Linux without CAP_NET_RAW support, then include
# METHOD=suid in the make command, e.g. make METHOD=suid && make install METHOD=suid
#	this will build a binary owned by root and the suid bit set
#
# Note: the BUILD_METHOD_FILE ensures that the build and installation are performed with the same METHOD= statement
# if you wish to change METHOD then run a 'make clean' between different METHOD= builds.
#
METHOD ?= caps
BUILD_METHOD_FILE := .build-method
# Determine which mode to use to enable raw sockets, defaulting to Linux capabilities
ifeq ($(METHOD),caps)
CAPNETRAW0_ROOTSUID1 := 0
$(info Running in Linux capabilities mode)
else ifeq ($(METHOD),suid)
CAPNETRAW0_ROOTSUID1 := 1
$(info Running in root/suid mode)
else
$(error Unexpected, METHOD=$(METHOD) statement in the make command-line. Expected METHOD=caps or METHOD=suid)
CAPNETRAW0_ROOTSUID1 := 0
endif
# -------------------------------------------------------------------------


# -------------------------------------------------------------------------
# Use install for binary installation
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755
INSTALL_DIR ?= $(INSTALL) -d
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# strip the binaries
STRIP ?= strip
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# set the binary capabilities to include cap_net_raw
#
SETCAP ?= setcap
SETCAP_CAPS ?= cap_net_raw+ep
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Set the installation location for the CGI files
#
TARGETDIR ?= /var/www/cgi-bin6
DESTDIR ?=
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# HTTP URI PATH by which external hosts will access the CGI files.
# This may well be unrelated to the installation path if Apache is configured
# to provide CGI access via an alias. 
# NB : the path should begin with a / but must NOT end with one ....
URIPATH=/cgi-bin6
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# General build variables
SHELL=/bin/sh
LIBPATHS=-L/usr/lib
INCLUDES=-I/usr/include
LIBS=
CC=gcc
CFLAGS=-Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wwrite-strings -Wformat=2 -Wformat-security -O2 -D_FORTIFY_SOURCE=2
CFLAGS+= -fstack-protector-all -fstack-clash-protection -Wstack-protector --param ssp-buffer-size=4
CFLAGS+= -Wconversion -Wsign-conversion -Wimplicit-fallthrough -Wl,-z,noexecstack -Wsign-compare -Wformat-signedness
CFLAGS+= -ftrapv -fPIE -Wl,-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,separate-code -Werror=implicit-function-declaration 
# control flow protection only works on x86
ifeq ($(shell $(CC) -dumpmachine | grep -Eq 'x86_64|i.86' && echo yes),yes)
CFLAGS+= -fcf-protection=full
endif
CFLAGS+= -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Text-version target executable name
TXTTARGET=ipscantxt.cgi
FASTTXTTARGET=ipscanfasttxt.cgi
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Javascript-version target executable name
JSTARGET=ipscanjs.cgi
FASTJSTARGET=ipscanfastjs.cgi
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# 
# Hopefully nothing below this point will need changing ....
# 
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Default target
.DEFAULT_GOAL := all
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Determine the appropriate database related include/library paths
# as well as any necessary libraries
LIBS+=$(shell mysql_config --libs)
CFLAGS+=$(shell mysql_config --cflags)
INCLUDES+=$(shell mysql_config --include)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# No debug by default
DEBUG=
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Concatenate the necessary parameters for each type of target
CMNPARAMS= $(DEBUG) -DEXEDIR=\"$(TARGETDIR)\" -DEXETXTNAME=\"$(TXTTARGET)\" -DEXEJSNAME=\"$(JSTARGET)\"
CMNPARAMS+= -DEXEFASTTXTNAME=\"$(FASTTXTTARGET)\" -DEXEFASTJSNAME=\"$(FASTJSTARGET)\" 
CMNPARAMS+= -DURIPATH=\"$(URIPATH)\" -DPING_AVAILABLE=$(PING_AVAILABLE) -DUDP_AVAILABLE=$(UDP_AVAILABLE) 
CMNPARAMS+= -DCAPNETRAW0_ROOTSUID1=$(CAPNETRAW0_ROOTSUID1) 
TXTPARAMS=$(CFLAGS) -DTEXTMODE=1 -DFAST=0 $(CMNPARAMS)
JSPARAMS =$(CFLAGS) -DTEXTMODE=0 -DFAST=0 $(CMNPARAMS)
FASTTXTPARAMS=$(CFLAGS) -DTEXTMODE=1 -DFAST=1 $(CMNPARAMS)
FASTJSPARAMS =$(CFLAGS) -DTEXTMODE=0 -DFAST=1 $(CMNPARAMS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Common header files which are always a dependancy
HEADERFILES=ipscan.h ipscan_db.h ipscan_portlist.h ipscan_general.h ipscan_web.h ipscan_tcp.h ipscan_udp.h ipscan_icmpv6.h
# Any other files on which we depend
DEPENDFILE=Makefile
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Generate the list of text-version and javascript-version objects from the source files
TXTOBJS=$(patsubst %.c,%-txt.o,$(wildcard *.c))
JSOBJS=$(patsubst %.c,%-js.o,$(wildcard *.c))
FASTTXTOBJS=$(patsubst %.c,%-fast-txt.o,$(wildcard *.c))
FASTJSOBJS=$(patsubst %.c,%-fast-js.o,$(wildcard *.c))
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Record the METHOD used to build the binaries and then check it is installed with the same
.PHONY: check-method
check-method:
	@if [ -f "$(BUILD_METHOD_FILE)" ]; then \
		built_method=$$(cat "$(BUILD_METHOD_FILE)"); \
		if [ "$$built_method" != "$(METHOD)" ]; then \
			echo "ERROR: binaries were built with METHOD=$$built_method"; \
			echo "       but METHOD=$(METHOD) was requested."; \
			echo "       Run 'make clean' before changing METHOD."; \
			exit 1; \
		fi; \
	else \
		echo "$(METHOD)" > "$(BUILD_METHOD_FILE)"; \
	fi
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# default target builds everything
.PHONY: all
all : check-method $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# debug target builds objects with debug, defined in ipscan.h, enabled
# Not intended for production use
.PHONY: debug
debug : $(HEADERFILES) $(DEPENDFILE)
	$(MAKE) clean
	$(MAKE) DEBUG="-DDEBUG=1" $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual text-version object and the overall text-version target
%-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(TXTPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(TXTTARGET) : $(TXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(TXTPARAMS) -o $(TXTTARGET) $(INCLUDES) $(LIBPATHS) $(TXTOBJS) $(LIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual fast text-version object and the overall text-version target
%-fast-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTTXTPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(FASTTXTTARGET) : $(FASTTXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTTXTPARAMS) -o $(FASTTXTTARGET) $(INCLUDES) $(LIBPATHS) $(FASTTXTOBJS) $(LIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual javascript-version object and the overall jscript-version target
%-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(JSPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(JSTARGET) : $(JSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(JSPARAMS) -o $(JSTARGET) $(INCLUDES) $(LIBPATHS) $(JSOBJS) $(LIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual faqst javascript-version object and the overall jscript-version target
%-fast-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTJSPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(FASTJSTARGET) : $(FASTJSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTJSPARAMS) -o $(FASTJSTARGET) $(INCLUDES) $(LIBPATHS) $(FASTJSOBJS) $(LIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Strip un-needed symbols from the binaries
.PHONY: strip
strip: $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
	@echo "Stripping the binaries to remove un-needed symbols"
	$(STRIP) --strip-unneeded $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to copy the built objects to the target installation directory
# then change the owner and either capability bits or suid
.PHONY: install
install : check-method $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET) strip
	@echo "Installing IPscan CGI executables"
	$(INSTALL_DIR) -o root -g root -m 0755 $(DESTDIR)$(TARGETDIR)
	$(INSTALL_PROGRAM) -o root -g root $(TXTTARGET) $(DESTDIR)$(TARGETDIR)/$(TXTTARGET)
	$(INSTALL_PROGRAM) -o root -g root $(FASTTXTTARGET) $(DESTDIR)$(TARGETDIR)/$(FASTTXTTARGET)
	$(INSTALL_PROGRAM) -o root -g root $(JSTARGET) $(DESTDIR)$(TARGETDIR)/$(JSTARGET)
	$(INSTALL_PROGRAM) -o root -g root $(FASTJSTARGET) $(DESTDIR)$(TARGETDIR)/$(FASTJSTARGET)
ifeq ($(CAPNETRAW0_ROOTSUID1),0)
	@command -v $(SETCAP) >/dev/null || { echo "\n\nERROR: setcap is required for METHOD=caps, but not found.\n"; exit 1; }
	@echo "Setting the installation binaries capability bits"
	$(SETCAP) $(SETCAP_CAPS) $(DESTDIR)$(TARGETDIR)/$(TXTTARGET)
	$(SETCAP) $(SETCAP_CAPS) $(DESTDIR)$(TARGETDIR)/$(FASTTXTTARGET)
	$(SETCAP) $(SETCAP_CAPS) $(DESTDIR)$(TARGETDIR)/$(JSTARGET)
	$(SETCAP) $(SETCAP_CAPS) $(DESTDIR)$(TARGETDIR)/$(FASTJSTARGET)
else
	@echo "Setting the installation binaries suid bits"
	chmod u+s $(DESTDIR)$(TARGETDIR)/$(TXTTARGET)
	chmod u+s $(DESTDIR)$(TARGETDIR)/$(FASTTXTTARGET)
	chmod u+s $(DESTDIR)$(TARGETDIR)/$(JSTARGET)
	chmod u+s $(DESTDIR)$(TARGETDIR)/$(FASTJSTARGET)
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rule to clean the source directory	
.PHONY: clean
clean :
	rm -f $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
	rm -f $(TXTOBJS) $(JSOBJS) $(FASTTXTOBJS) $(FASTJSOBJS)
	rm -f $(BUILD_METHOD_FILE)
# -------------------------------------------------------------------------
