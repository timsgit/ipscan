#    IPscan - an http-initiated IPv6 port scanner.
#
#    (C) Copyright 2011-2019 Tim Chappell.
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
# 0.19 - remove dashes from binary names

# Support servers where SETUID is not available
# Set this variable to 0 if you don't have permissions to call SETUID
SETUID_AVAILABLE=1

# Support servers where UDP port access is disabled
# Set this variable to 0 if you don't have permissions to access UDP ports
UDP_AVAILABLE=1

# General build variables
SHELL=/bin/sh
LIBPATHS=-L/usr/lib
INCLUDES=-I/usr/include
LIBS=
CC=gcc
CFLAGS=-Wall -Wextra -Werror -Wpointer-arith -Wwrite-strings -Wformat -Wformat-security -O1 -D_FORTIFY_SOURCE=2
CFLAGS+= -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 
CFLAGS+= -ftrapv -fPIE -pie -Wl,-z,relro,-z,now 
# CFLAGS+= -ftrapv -fPIE -pie -Wl,-z,relro,-z,now -Wconversion -Wsign-conversion

# Install location for the CGI files
TARGETDIR=/var/www/cgi-bin6

# HTTP URI PATH by which external hosts will access the CGI files.
# This may well be unrelated to the installation path if Apache is configured
# to provide CGI access via an alias. 
# NB : the path should begin with a / but must NOT end with one ....
URIPATH=/cgi-bin6

# Text-version target executable name
TXTTARGET=ipscantxt.cgi
FASTTXTTARGET=ipscanfasttxt.cgi

# Javascript-version target executable name
JSTARGET=ipscanjs.cgi
FASTJSTARGET=ipscanfastjs.cgi

##############################################################################
# 
# Hopefully nothing below this point will need changing ....
# 
##############################################################################

# Determine the appropriate database related include/library paths
# as well as any necessary libraries
LIBS+=$(shell mysql_config --libs)
CFLAGS+=$(shell mysql_config --cflags)
INCLUDES+=$(shell mysql_config --include)

# Determine effective user-id - likely to work in all shells
MYEUID=$(shell id -u)

# Concatenate the necessary parameters for the two targets
CMNPARAMS= -DEXEDIR=\"$(TARGETDIR)\" -DEXETXTNAME=\"$(TXTTARGET)\" -DEXEJSNAME=\"$(JSTARGET)\"
CMNPARAMS+= -DEXEFASTTXTNAME=\"$(FASTTXTTARGET)\" -DEXEFASTJSNAME=\"$(FASTJSTARGET)\" 
CMNPARAMS+= -DURIPATH=\"$(URIPATH)\" -DSETUID_AVAILABLE=$(SETUID_AVAILABLE)
CMNPARAMS+= -DUDP_AVAILABLE=$(UDP_AVAILABLE) 
TXTPARAMS=$(CFLAGS) -DTEXTMODE=1 -DFAST=0 $(CMNPARAMS)
JSPARAMS =$(CFLAGS) -DTEXTMODE=0 -DFAST=0 $(CMNPARAMS)
FASTTXTPARAMS=$(CFLAGS) -DTEXTMODE=1 -DFAST=1 $(CMNPARAMS)
FASTJSPARAMS =$(CFLAGS) -DTEXTMODE=0 -DFAST=1 $(CMNPARAMS)

# Common header files which are always a dependancy
HEADERFILES=ipscan.h ipscan_portlist.h
# Any other files on which we depend
DEPENDFILE=Makefile

# Generate the list of text-version and javascript-version objects from the source files
TXTOBJS=$(patsubst %.c,%-txt.o,$(wildcard *.c))
JSOBJS=$(patsubst %.c,%-js.o,$(wildcard *.c))
FASTTXTOBJS=$(patsubst %.c,%-fast-txt.o,$(wildcard *.c))
FASTJSOBJS=$(patsubst %.c,%-fast-js.o,$(wildcard *.c))

# default target builds everything
.PHONY: all
all : $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)

# Rules to build an individual text-version object and the overall text-version target
%-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(TXTPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(TXTTARGET) : $(TXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(TXTPARAMS) -o $(TXTTARGET) $(INCLUDES) $(LIBPATHS) $(TXTOBJS) $(LIBS)

# Rules to build an individual text-version object and the overall text-version target
%-fast-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTTXTPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(FASTTXTTARGET) : $(FASTTXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTTXTPARAMS) -o $(FASTTXTTARGET) $(INCLUDES) $(LIBPATHS) $(FASTTXTOBJS) $(LIBS)

# Rules to build an individual jscript-version object and the overall jscript-version target
%-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(JSPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(JSTARGET) : $(JSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(JSPARAMS) -o $(JSTARGET) $(INCLUDES) $(LIBPATHS) $(JSOBJS) $(LIBS)

# Rules to build an individual jscript-version object and the overall jscript-version target
%-fast-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTJSPARAMS) -c $(INCLUDES) $(LIBPATHS) -o $@ $<
$(FASTJSTARGET) : $(FASTJSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(FASTJSPARAMS) -o $(FASTJSTARGET) $(INCLUDES) $(LIBPATHS) $(FASTJSOBJS) $(LIBS)

# Rules to copy the built objects to the target installation directory
# optionally set setuid bit on targets if required
.PHONY: install
install : $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
ifeq ($(UDP_AVAILABLE),1)
	@echo 
	@echo Running with UDP_AVAILABLE in the Makefile set to 1
	@echo If you do NOT have root permissions or UDP sockets are NOT available then
	@echo please set UDP_AVAILABLE to 0 and re-make.
	@echo 
else
	@echo 
	@echo Running with UDP_AVAILABLE in the Makefile set to 0
	@echo If you do have permissions to create UDP sockets then
	@echo please set SETUID_AVAILABLE to 1 and re-make.
	@echo
endif
# Strip un-needed symbols from the binaries and copy them to their
# target location
	strip --strip-unneeded $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
	cp $(TXTTARGET) $(FASTTXTTARGET) $(TARGETDIR)
	cp $(JSTARGET) $(FASTJSTARGET) $(TARGETDIR)
ifeq ($(SETUID_AVAILABLE),1)
	@echo 
	@echo Running with SETUID_AVAILABLE in the Makefile set to 1
	@echo If you do NOT have root permissions or chmod/setuid is NOT available then
	@echo please set SETUID_AVAILABLE to 0 and re-make.
	@echo 
ifeq ($(MYEUID),0)
	chmod 4555 $(TARGETDIR)/$(TXTTARGET)
	chmod 4555 $(TARGETDIR)/$(JSTARGET)
	chmod 4555 $(TARGETDIR)/$(FASTTXTTARGET)
	chmod 4555 $(TARGETDIR)/$(FASTJSTARGET)
else
	@echo 
	@echo ERROR: install must be run as root in order to setuid.
	@echo ERROR: user-id is currently $(MYEUID)
	@echo 
endif
else
	@echo 
	@echo Running with SETUID_AVAILABLE in the Makefile set to 0
	@echo If you do have root permissions AND chmod/setuid is available then
	@echo please set SETUID_AVAILABLE to 1 and re-make.
	@echo
endif
	
# Rule to clean the source directory	
.PHONY: clean
clean :
	rm -f $(TXTTARGET) $(JSTARGET) $(FASTTXTTARGET) $(FASTJSTARGET)
	rm -f $(TXTOBJS) $(JSOBJS) $(FASTTXTOBJS) $(FASTJSOBJS)
