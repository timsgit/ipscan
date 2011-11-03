//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011 Tim Chappell.
//
//    This file is part of ipscan.
//
//    ipscan is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with ipscan.  If not, see <http://www.gnu.org/licenses/>.



#ifndef IPSCAN_H
	#define IPSCAN_H 1
	//
	// TEXTMODE == 1 => Text Browser compatible
	// TEXTMODE == 0 => Browser supports Javascript
	//
	#ifndef TEXTMODE
		#define TEXTMODE 0
	#endif

	// DEBUG build options - enabling these will result in copious amounts of information
	// #define DEBUG 1
	// #define DBDEBUG 1

	// Version
	#define VERSION "0.79"
	//
	// 0.5  first combined text/javascript version
	// 0.61 separate closed/timeout [CLOSED] from closed/rejected [FILTER]
	// 0.63 further response states
	// 0.64 Open, Closed or detailed response names
	// 0.65 Added results key
	// 0.66 Added Prohibited failure case (ICMPv6 administratively prohibited
	// 0.67 Add ability to create database directory path assuming only 1 additional directory is required to be created
	// 0.68 Added unreachable icmpv6 type 1 code 0
	// 0.69 Add unreachable stats
	// 0.70 Add further potential connect errors
	// 0.71 Clean logging output and web reporting
	// 0.72 Updated txt browser output and offer email feedback link.
	// 0.73 add hostname, time into feedback email body
	// 0.74 tidy up noscript link to text-only version, move to structure driven results classification
	// 0.75 improved scan summary logging for structure driven approach
	// 0.76 improved query string error checking, handling and reporting
	// 0.77 added link to source code on github to results page.
	// 0.78 added support for HEAD method
	// 0.79 Minor tweaks to ipscan_web.c and ipscan.c remove set but unused variables

	// Email address
	#define EMAILADDRESS "webmaster@chappell-family.com"

	// Database results directory
	#define DBDIR "/var/lib/ipscan"

	// Enable the generation of a summary of scans page (1) or not (0)
	// This is a potential security risk, so use cautiously and definitely choose
	// a new value for MAGICSUMMARY before enabling it!
	#define SUMMARYENABLE 0

	// *** PLEASE CHANGE THIS MAGICSUMMARY VALUE BEFORE ENABLING ***
	// Magic number requesting a scan summary
	#define MAGICSUMMARY -999123

	// Magic number requesting the start of a scan
	#define MAGICBEGIN 123456

	// Maximum number of ports to be tested - this should exceed the sum of the default port list
	// and the allowed user-defined ports
	#define MAXPORTS 64

	// Define the min/max valid port ranges. This could be used to restrict testing (e.g. >= 1024)
	// as long as the default port list is updated as well
	#define MINVALIDPORT 0
	#define MAXVALIDPORT 65535

	// Number of columns for HTML output:
	#define MAXCOLS 4
	#define COLUMNPCT (100/MAXCOLS)

	// Number of columns for text-only browser output case
	#define TXTMAXCOLS 3

	// Number of columns in log outputs
	#define LOGMAXCOLS 4
	// Maximum size for buffer used to assemble log entries, 20 characters per "column" should be plenty
	#define LOGENTRYLEN (20* LOGMAXCOLS)

	// Maximum number of supported query parameters
	// Must ensure MAXQUERIES exceeds NUMUSERDEFPORTS by sufficient amount!
	#define MAXQUERIES 16
	#define MAXQUERYSTRLEN 255
	#define MAXQUERYNAMELEN 32
	#define MAXQUERYVALLEN 64

	// Determine the executable CGI script filenames
	// These SHOULD be defined in the makefile, but provide some defaults in case
	#ifndef EXETXTNAME
		#define EXETXTNAME "ipscan-txt.cgi"
	#endif
	#ifndef EXEJSNAME
		#define EXEJSNAME "ipscan-js.cgi"
	#endif

	// Determine database filenames
	#define DBTXTNAME "results-txt.db"
	#define DBJSNAME "results-js.db"

	// Determine the executables' and database results' file names
	#if (TEXTMODE == 1)
		#define EXENAME EXETXTNAME
		#define DATABASEFILE DBTXTNAME
	#else
		#define EXENAME EXEJSNAME
		#define DATABASEFILE DBJSNAME
	#endif

	// Create a reference pointing to the results' database file
	#define DBFILE DBDIR "/" DATABASEFILE

	// Served HTTP URL directory path - needs leading /, but not a trailing one ...
	// This SHOULD be defined in the makefile, but provide a default here just in case
	#ifndef DIRPATH
		#define DIRPATH "/cgi-bin6"
	#endif

	// Maximum number of user-defined TCP ports
	// Must ensure MAXQUERIES exceeds NUMUSERDEFPORTS by sufficient amount!
	#define NUMUSERDEFPORTS 4

	// Logging prefix (goes into apache error_log)
	#define LOGPREFIX EXENAME" : Version "VERSION" : "

	// returncode which the cgi program returns on an unhandled error - check the apache error log in this case
	#define CHECKTHELOGRC 999

	//
	// Database related
	//

	// Set an assumed location for the SQLITE3 binary in case the Makefile doesn't have one
	#ifndef SQLITE3BIN
		#define SQLITE3BIN "/usr/bin/sqlite3"
	#endif

	#define MAXDBQUERYSIZE 255
	#define DBACCESS_ATTEMPTS 5
	#define BUSYHANDLERMAXCALLS 20

	// Timeout for port response
	#define TIMEOUTSECS 1

	// JSON fetch period (seconds) - tradeoff between update rate and webserver load
	#define JSONFETCHEVERY 4

	// Mapping for connection attempt results
	// To add a new entry first insert a new internal state in the PORTSTATE enumeration and then add a
	// matching entry in the results structure in ipscan.c
	// Both should be inserted before the unexpected/unknown, etc. entries

	enum PORTSTATE
	{
		PORTOPEN = 0,
		PORTABORT,
		PORTREFUSED,
		PORTCRESET,
		PORTNRESET,
		PORTINPROGRESS,
		PORTPROHIBITED,
		PORTUNREACHABLE,
		PORTNOROUTE,
		PORTPKTTOOBIG,
		PORTPARAMPROB,
		/* Unexpected and Unknown error response cases, do NOT change */
		PORTUNEXPECTED,
		PORTUNKNOWN,
		PORTINTERROR,
		/* End of list marker, do NOT change */
		PORTEOL
	};

	// Determine the number of entries
	#define NUMRESULTTYPES PORTEOL

	// Results structure
	struct rslt_struc
	{
		int returnval;
		int connrc;
		int connerrno;
		char *label;
		char *colour;
		char *description;
	};


	// End of defines
#endif
