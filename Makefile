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
# 0.29 - add support for server resource limit checks/report 
# 0.30 - add improved Linux capabilities support
# 0.31 - significant changes to separate various compiler and linker parameters
# 0.32 - verification of Linux capabilities settings applied to executables
# 0.33 - fix typo and separate objects based on METHOD to prevent incorrect installation

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
# IMPORTANT NOTE: All types of scan (ICMPv6 ECHO_REQUEST, UDPv6, and TCPv6) require raw sockets
#
# If you are using Linux with CAP_NET_RAW support then include
# METHOD=caps in the make command, e.g. make METHOD=caps && make install METHOD=caps
#	this will build a binary owned by the root user and including CAP_NET_RAW support
#
# If you are NOT using Linux, or a version of Linux without CAP_NET_RAW support, then include
# METHOD=suid in the make command, e.g. make METHOD=suid && make install METHOD=suid
#	this will build a binary owned by root and set the suid bit
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
$(info Running in root/suid mode - DEPRECATED)
else
$(error Unexpected, METHOD=$(METHOD) statement in the make command-line. Expected METHOD=caps or METHOD=suid)
CAPNETRAW0_ROOTSUID1 := 0
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Find the Apache control binary (name varies by distro)
# -------------------------------------------------------------------------
APACHECTL ?= $(shell for c in apache2ctl apachectl httpd; do command -v $$c && break; done)
# Use APACHECTL to determine the WEBUSER unless the caller supplied one (make WEBUSER=foo)
ifeq ($(origin WEBUSER),undefined)
WEBUSER := $(shell $(APACHECTL) -S 2>/dev/null | sed -n 's/^User: name="\([^"]*\)".*/\1/p' | head -n1)
endif
# Use APACHECTL to determine the WEBGROUP unless the caller supplied one (make WEBGROUP=foo)
ifeq ($(origin WEBGROUP),undefined)
WEBGROUP := $(shell $(APACHECTL) -S 2>/dev/null | sed -n 's/^Group: name="\([^"]*\)".*/\1/p' | head -n1)
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Define the directory that will hold IPscan lock files
# -------------------------------------------------------------------------
IPSCAN_SLOT_DIR ?= /var/lib/ipscan
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Define the maximum number of simultaneous IPscans that can be executed
# on the server. Defaults to 0, which is equivalent to unlimited.
# -------------------------------------------------------------------------
ifeq ($(origin IPSCAN_MAX_SCANS),undefined)
IPSCAN_MAX_SCANS := 0
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
# -------------------------------------------------------------------------
SETCAP ?= setcap
GETCAP ?= getcap
# Note: SETCAP_CAPS should assign/set (=) a flag rather than add (+) one
# otherwise the simplistic binary capabilities verification approach will
# fail. CAP_NET_RAW should be permitted (p) but NOT effective (e) at
# process startup.
SETCAP_CAPS ?= cap_net_raw=p
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Set the installation location for the CGI files
# -------------------------------------------------------------------------
TARGETDIR ?= /var/www/cgi-bin6
DESTDIR ?=
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# HTTP URI PATH by which external hosts will access the CGI files.
# This may well be unrelated to the installation path if Apache is configured
# to provide CGI access via an alias. 
# NB : the path should begin with a / but must NOT end with one ....
# -------------------------------------------------------------------------
URIPATH=/cgi-bin6
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# General build variables
# -------------------------------------------------------------------------
SHELL=/bin/sh
MYSQL_CONFIG ?= mysql_config
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# default to gcc if in the path, otherwise cc.
# command-line make CC= will take precedence
# -------------------------------------------------------------------------
ifeq ($(shell command -v gcc 2>/dev/null),)
CC = cc
else
CC = gcc
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Text-version target executable names
# -------------------------------------------------------------------------
TXTTARGET=ipscantxt.cgi
FASTTXTTARGET=ipscanfasttxt.cgi
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Javascript-version target executable names
# -------------------------------------------------------------------------
JSTARGET=ipscanjs.cgi
FASTJSTARGET=ipscanfastjs.cgi
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# 
# Hopefully nothing below this point will need changing ....
# 
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Default target - build all by default
.DEFAULT_GOAL := all
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Determine the appropriate database related include/library paths
# as well as any necessary libraries
# -------------------------------------------------------------------------
MYSQL_CPPFLAGS := $(shell $(MYSQL_CONFIG) --include 2>/dev/null)
MYSQL_LDLIBS := $(shell $(MYSQL_CONFIG) --libs 2>/dev/null) 
MYSQL_CFLAGS := $(shell $(MYSQL_CONFIG) --cflags 2>/dev/null)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# IPscan-specific compiler flags
# -------------------------------------------------------------------------
IPSCAN_CPPFLAGS =-D_FORTIFY_SOURCE=2 -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64
# add in the ones required by MySQL/MariaDB
IPSCAN_CPPFLAGS += $(MYSQL_CPPFLAGS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Define the parameters that are common to all types of target executables
# -------------------------------------------------------------------------
CMNPARAMS  = $(DEBUG)
CMNPARAMS += -DEXEDIR=\"$(TARGETDIR)\"
CMNPARAMS += -DEXETXTNAME=\"$(TXTTARGET)\"
CMNPARAMS += -DEXEJSNAME=\"$(JSTARGET)\"
CMNPARAMS += -DEXEFASTTXTNAME=\"$(FASTTXTTARGET)\"
CMNPARAMS += -DEXEFASTJSNAME=\"$(FASTJSTARGET)\"
CMNPARAMS += -DURIPATH=\"$(URIPATH)\"
CMNPARAMS += -DPING_AVAILABLE=$(PING_AVAILABLE)
CMNPARAMS += -DUDP_AVAILABLE=$(UDP_AVAILABLE)
CMNPARAMS += -DCAPNETRAW0_ROOTSUID1=$(CAPNETRAW0_ROOTSUID1)
CMNPARAMS += -DIPSCAN_SLOT_DIR=\"$(IPSCAN_SLOT_DIR)\"
CMNPARAMS += -DIPSCAN_MAX_SCANS=$(IPSCAN_MAX_SCANS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Try to include as many runtime security options as possible and make the
# compiler as fussy as possible about the code it compiles
# -------------------------------------------------------------------------
IPSCAN_CFLAGS  = -Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wwrite-strings
IPSCAN_CFLAGS += -Wformat=2 -Wformat-security -Wconversion -Wsign-conversion
IPSCAN_CFLAGS += -Wimplicit-fallthrough -Wsign-compare -Wformat-signedness
IPSCAN_CFLAGS += -Werror=implicit-function-declaration -O2 -fstack-protector-all
IPSCAN_CFLAGS += -fstack-clash-protection -Wstack-protector --param ssp-buffer-size=4
IPSCAN_CFLAGS += -ftrapv -fPIE
IPSCAN_CFLAGS += $(MYSQL_CFLAGS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Control flow protection only works on x86 CPU
# -------------------------------------------------------------------------
ifeq ($(shell $(CC) -dumpmachine | grep -Eq 'x86_64|i.86' && echo yes),yes)
IPSCAN_CFLAGS += -fcf-protection=full
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Linker options - again prioritise secure deployment
# -------------------------------------------------------------------------
IPSCAN_LDFLAGS  = -pie -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now
IPSCAN_LDFLAGS += -Wl,-z,separate-code

# -------------------------------------------------------------------------
# Define the linker libraries
# -------------------------------------------------------------------------
IPSCAN_LDLIBS =
IPSCAN_LDLIBS += $(MYSQL_LDLIBS)
# Linux capability support is only required for METHOD=caps.
ifeq ($(METHOD),caps)
IPSCAN_LDLIBS += -lcap
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# No debug by default
# -------------------------------------------------------------------------
DEBUG=
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Determine the parameters necessary for each type of target
# -------------------------------------------------------------------------
TXTPARAMS=$(CFLAGS) -DTEXTMODE=1 -DFAST=0 $(CMNPARAMS)
JSPARAMS =$(CFLAGS) -DTEXTMODE=0 -DFAST=0 $(CMNPARAMS)
FASTTXTPARAMS=$(CFLAGS) -DTEXTMODE=1 -DFAST=1 $(CMNPARAMS)
FASTJSPARAMS =$(CFLAGS) -DTEXTMODE=0 -DFAST=1 $(CMNPARAMS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Define the common header files which are always a dependency
# -------------------------------------------------------------------------
HEADERFILES=ipscan.h ipscan_db.h ipscan_portlist.h ipscan_general.h ipscan_web.h ipscan_tcp.h 
HEADERFILES+= ipscan_udp.h ipscan_icmpv6.h
# Any other files on which we depend
DEPENDFILE=Makefile
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Determine where to put the object files
# -------------------------------------------------------------------------
OBJPREFIX := obj
OBJDIR := $(OBJPREFIX)/$(METHOD)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Generate the list of object files for each type of target
# -------------------------------------------------------------------------
TXTOBJS=$(addprefix $(OBJDIR)/,$(patsubst %.c,%-txt.o,$(wildcard *.c)))
JSOBJS=$(addprefix $(OBJDIR)/,$(patsubst %.c,%-js.o,$(wildcard *.c)))
FASTTXTOBJS=$(addprefix $(OBJDIR)/,$(patsubst %.c,%-fast-txt.o,$(wildcard *.c)))
FASTJSOBJS=$(addprefix $(OBJDIR)/,$(patsubst %.c,%-fast-js.o,$(wildcard *.c)))
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Record the build METHOD for later checking
# -------------------------------------------------------------------------
.PHONY: record-method
record-method:
	@echo "$(METHOD)" > "$(BUILD_METHOD_FILE)"
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Check the build and install METHOD are the same
# -------------------------------------------------------------------------
.PHONY: check-method
check-method:
	@if [ -f "$(BUILD_METHOD_FILE)" ]; then \
		built_method=$$(cat "$(BUILD_METHOD_FILE)"); \
		if [ "$$built_method" != "$(METHOD)" ]; then \
			echo "ERROR: binaries were built with METHOD=$$built_method"; \
			echo "       installation requested with METHOD=$(METHOD)."; \
			echo "       make clean and then make METHOD=$(METHOD) && make install METHOD=$(METHOD)."; \
			exit 1; \
		fi; \
	else \
		echo "ERROR: build method marker missing."; \
		echo "       Run make METHOD=$(METHOD) first"; \
		exit 1; \
	fi
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# default target records build METHOD and builds everything
# -------------------------------------------------------------------------
.PHONY: all
all : $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET) record-method
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Debug display the build/install variable
# -------------------------------------------------------------------------
.PHONY: show-build-config
show-build-config:
	@echo "Build method: $(METHOD)"
	@echo "Compiler: $(CC)"
	@echo "CPPFLAGS: $(CPPFLAGS) $(IPSCAN_CPPFLAGS)"
	@echo "CFLAGS: $(CFLAGS) $(IPSCAN_CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS) $(IPSCAN_LDFLAGS)"
	@echo "LDLIBS: $(LDLIBS) $(IPSCAN_LDLIBS)"
	@echo "MYSQL_LDLIBS := $(MYSQL_LDLIBS)"
	@echo "MYSQL_CFLAGS := $(MYSQL_CFLAGS)"
	@echo "MYSQL_CPPFLAGS := $(MYSQL_CPPFLAGS)"
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# The debug target builds objects with debug, as defined in ipscan.h
# Not intended for production use
# -------------------------------------------------------------------------
.PHONY: debug
debug : $(HEADERFILES) $(DEPENDFILE)
	$(MAKE) clean
	$(MAKE) DEBUG="-DDEBUG=1" $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET) record-method
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual text-version object and the overall text-version target
# -------------------------------------------------------------------------
$(OBJDIR)/%-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(IPSCAN_CPPFLAGS) $(TXTPARAMS) $(IPSCAN_CFLAGS) -c -o $@ $<
$(TXTTARGET) : record-method $(TXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(LDFLAGS) $(IPSCAN_LDFLAGS) -o $@ $(TXTOBJS) $(LDLIBS) $(IPSCAN_LDLIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual fast text-version object and the overall fast text-version target
# -------------------------------------------------------------------------
$(OBJDIR)/%-fast-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(IPSCAN_CPPFLAGS) $(FASTTXTPARAMS) $(IPSCAN_CFLAGS) -c -o $@ $<
$(FASTTXTTARGET) : record-method $(FASTTXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(LDFLAGS) $(IPSCAN_LDFLAGS) -o $@ $(FASTTXTOBJS) $(LDLIBS) $(IPSCAN_LDLIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual javascript-version object and the overall javascript-version target
# -------------------------------------------------------------------------
$(OBJDIR)/%-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(IPSCAN_CPPFLAGS) $(JSPARAMS) $(IPSCAN_CFLAGS) -c -o $@ $<
$(JSTARGET) : record-method $(JSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(LDFLAGS) $(IPSCAN_LDFLAGS) -o $@ $(JSOBJS) $(LDLIBS) $(IPSCAN_LDLIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to build an individual fast javascript-version object and the overall fast javascript-version target
# -------------------------------------------------------------------------
$(OBJDIR)/%-fast-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(IPSCAN_CPPFLAGS) $(FASTJSPARAMS) $(IPSCAN_CFLAGS) -c -o $@ $<
$(FASTJSTARGET) : record-method $(FASTJSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(LDFLAGS) $(IPSCAN_LDFLAGS) -o $@ $(FASTJSOBJS) $(LDLIBS) $(IPSCAN_LDLIBS)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Strip un-needed symbols from the binaries - called as part of the installation
# -------------------------------------------------------------------------
.PHONY: strip
strip: $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
	@echo "Stripping the binaries to remove un-needed symbols"
	$(STRIP) --strip-unneeded $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rules to copy the built objects to the target installation directory
# then change the owner and either capability bits or suid
# -------------------------------------------------------------------------
.PHONY: install
install : check-method $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET) strip
	@echo "Installing IPscan CGI executables"
	$(INSTALL_DIR) -o root -g root -m 0755 $(DESTDIR)$(TARGETDIR)
	@echo "Creating the IPscan SLOTS directory"
	$(INSTALL_DIR) -o $(WEBUSER) -g $(WEBGROUP) -m 0700 $(IPSCAN_SLOT_DIR)
	$(INSTALL_PROGRAM) -o root -g root $(TXTTARGET) $(DESTDIR)$(TARGETDIR)/$(TXTTARGET)
	$(INSTALL_PROGRAM) -o root -g root $(FASTTXTTARGET) $(DESTDIR)$(TARGETDIR)/$(FASTTXTTARGET)
	$(INSTALL_PROGRAM) -o root -g root $(JSTARGET) $(DESTDIR)$(TARGETDIR)/$(JSTARGET)
	$(INSTALL_PROGRAM) -o root -g root $(FASTJSTARGET) $(DESTDIR)$(TARGETDIR)/$(FASTJSTARGET)
ifeq ($(METHOD),caps)
	@echo "Installing CAP_NET_RAW file capabilities"
	@command -v $(SETCAP) >/dev/null || { echo "\n\nERROR: setcap is required for METHOD=caps, but not found.\n"; exit 1; }
	@command -v $(GETCAP) >/dev/null || { echo "\n\nERROR: getcap is required for METHOD=caps, but not found.\n"; exit 1; }
	@echo "Setting and verifying the installation binaries capability bits"
	@set -eu; \
	for binary in \
		"$(DESTDIR)$(TARGETDIR)/$(TXTTARGET)" \
		"$(DESTDIR)$(TARGETDIR)/$(FASTTXTTARGET)" \
		"$(DESTDIR)$(TARGETDIR)/$(JSTARGET)" \
		"$(DESTDIR)$(TARGETDIR)/$(FASTJSTARGET)"; \
	do \
		$(SETCAP) $(SETCAP_CAPS) $$binary; \
		expected="$$binary $(SETCAP_CAPS)"; \
		actual=$$($(GETCAP) "$$binary"); \
		if [ "$$actual" != "$$expected" ]; then \
			echo "ERROR: incorrect capabilities on $$binary"; \
			echo "       Expected: $$expected"; \
			echo "       Actual:   $${actual:-<none>}"; \
			exit 1; \
		fi; \
		echo "OK: $$binary: $(SETCAP_CAPS)"; \
	done
else ifeq ($(METHOD),suid)
	@echo "Setting the installation binaries SUID bits"
	@set -eu; \
	for binary in \
		"$(DESTDIR)$(TARGETDIR)/$(TXTTARGET)" \
		"$(DESTDIR)$(TARGETDIR)/$(FASTTXTTARGET)" \
		"$(DESTDIR)$(TARGETDIR)/$(JSTARGET)" \
		"$(DESTDIR)$(TARGETDIR)/$(FASTJSTARGET)"; \
	do \
		chmod u-s $$binary; \
		chmod u+s $$binary; \
	done
else
	$(error Invalid METHOD=$(METHOD))
endif
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Rule to clean the source directory	
# -------------------------------------------------------------------------
.PHONY: clean
clean :
	rm -rf $(OBJPREFIX)
	rm -f  $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
	rm -f  $(BUILD_METHOD_FILE)
# -------------------------------------------------------------------------
