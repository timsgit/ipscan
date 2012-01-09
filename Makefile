#    ipscan - an http-initiated IPv6 port scanner.
#
#    (C) Copyright 2011 Tim Chappell.
#
#    This file is part of ipscan.
#
#    ipscan is free software: you can redistribute it and/or modify
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
#    along with ipscan.  If not, see <http://www.gnu.org/licenses/>.

# Makefile version
# 0.01 - initial version
# 0.02 - added MySQL support
# 0.03 - addition of ping functionality (suid bit set)
# 0.04 - default to MySQL
# 0.05 - remove sqlite support

# General build variables
SHELL=/bin/sh
LIBPATHS=-L/usr/lib
INCLUDES=-I/usr/include
LIBS=
CC=gcc
CFLAGS=-Wall

# Install location for the CGI files
TARGETDIR=/srv/www/cgi-bin6

# HTTP URL PATH by which external hosts will access the CGI files.
# This may well be unrelated to the installation path if Apache is configured
# to provide CGI access via an alias. 
# NB : the path should begin with a / but must NOT end with one ....
URLPATH=/cgi-bin6

# Text-version target executable name
TXTTARGET=ipscan-txt.cgi

# Javascript-version target executable name
JSTARGET=ipscan-js.cgi

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

# Concatenate the necessary parameters for the two targets
CMNPARAMS=-DEXEDIR=\"$(TARGETDIR)\" -DEXETXTNAME=\"$(TXTTARGET)\" -DEXEJSNAME=\"$(JSTARGET)\" 
CMNPARAMS+= -DDIRPATH=\"$(URLPATH)\"
TXTPARAMS=$(CFLAGS) -DTEXTMODE=1 $(CMNPARAMS)
JSPARAMS =$(CFLAGS) -DTEXTMODE=0 $(CMNPARAMS)

# Common header files which are always a dependancy
HEADERFILES=ipscan.h ipscan_portlist.h
# Any other files on which we depend
DEPENDFILE=Makefile

# Generate the list of text-version and javascript-version objects from the source files
TXTOBJS=$(patsubst %.c,%-txt.o,$(wildcard *.c))
JSOBJS=$(patsubst %.c,%-js.o,$(wildcard *.c))

# default target builds everything
.PHONY: all
all : $(TXTTARGET) $(JSTARGET)

# Rules to build an individual text-version object and the overall text-version target
%-txt.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(TXTPARAMS) -c $(INCLUDES) $(LIBPATHS) $(LIBS) -o $@ $<
$(TXTTARGET) : $(TXTOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(TXTPARAMS) -o $(TXTTARGET) $(INCLUDES) $(LIBPATHS) $(LIBS) $(TXTOBJS)

# Rules to build an individual jscript-version object and the overall jscript-version target
%-js.o: %.c $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(JSPARAMS) -c $(INCLUDES) $(LIBPATHS) $(LIBS) -o $@ $<
$(JSTARGET) : $(JSOBJS) $(HEADERFILES) $(DEPENDFILE)
	$(CC) $(JSPARAMS) -o $(JSTARGET) $(INCLUDES) $(LIBPATHS) $(LIBS) $(JSOBJS)

# Rules to copy the built objects to the target installation directory
# optionally set setuid bit on targets if required
.PHONY: install
install : $(TXTTARGET) $(JSTARGET)
	cp $(TXTTARGET) $(TARGETDIR)
	cp $(JSTARGET) $(TARGETDIR)
	chmod 4555 $(TARGETDIR)/$(TXTTARGET)
	chmod 4555 $(TARGETDIR)/$(JSTARGET)
	
# Rule to clean the source directory	
.PHONY: clean
clean :
	rm -f $(TXTTARGET) $(JSTARGET) 
	rm -f $(TXTOBJS) $(JSOBJS)
