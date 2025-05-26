//    IPscan - an HTTP-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2025 Tim Chappell.
//
//    This file is part of IPscan.
//
//    IPscan is free software: you can redistribute it and/or modify
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
//    along with IPscan.  If not, see <http://www.gnu.org/licenses/>.

#include <stdlib.h>
#include <inttypes.h>

#ifndef IPSCAN_H
	#define IPSCAN_H 1

	// Handle DEBUG flag
	#ifndef DEBUG
		#define DEBUG 0
	#endif

	// Build-mode for executable
	// Note this is controlled by the makefile, but a default is defined here for safety
	//
	// TEXTMODE == 1 => Text Browser compatible (e.g. lynx or w3m)
	// TEXTMODE == 0 => Browser supports Javascript
	//
	#ifndef TEXTMODE
		#define TEXTMODE 0
	#endif

	// Parallel scan-mode for executable
	// Note this is controlled by the makefile, but a default is defined here for safety
	#ifndef FAST
		#define FAST 0
	#endif

	// Determine which logging target to use stderr (0) or syslog(1)
	#define LOGMODE 1

	// Create the appropriate logging macro
	#if (LOGMODE == 0)
		#define IPSCAN_LOG(...) fprintf(stderr, __VA_ARGS__ )
	#else
		#define IPSCAN_LOG(...) syslog(LOG_NOTICE, __VA_ARGS__ )
	#endif

	//
	// VERSION HISTORY
	//
	// 0.5  first combined text/javascript version
	// 0.61 separate closed/timeout [CLOSED] from closed/rejected [FILTER]
	// 0.63 further response states
	// 0.64 Open, Closed or detailed response names
	// 0.65 Added results key
	// 0.66 Added Prohibited failure case (ICMPv6 administratively prohibited)
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
	// 0.79 Minor tweaks to ipscan_web.c and ipscan.c to remove set but unused variables
	// 0.80 include optional MySQL support which touches Makefile, ipscan.h and ipscan_db.c
	// 0.81 added Microsoft RDP protocol, port 3389, to list of default ports
	// 0.82 added/modified some Apple related ports
	// 0.83 added support for syslog logging
	// 0.84 renumbered default ports so they are monotonic
	// 0.85 tidied up HTML to make Opera happy
	// 0.86 added ICMPv6 ping
	// 0.87 tidied ipscan_checks
	// 0.88 ping logging improvements
	// 0.89 further logging improvements for ICMPv6 responses
	// 0.90 INNER ICMPv6 packet logging, checking and reporting
	// 0.91 further default logging improvements
	// 0.92 removal of empty HTML paragraph
	// 0.93 default to MySQL, potential query string overflow caught
	// 0.94 improve buffer overflow protection, remove SQLITE support
	// 0.95 tidy up HTML error reporting for buffer overflow cases.
	// 0.96 fix some printf casts
	// 0.97 slight improvement to logging for ICMPv6 cases
	// 0.98 tweaks for FreeBSD9 support (build under gmake)
	// 0.99 first build supporting parallel port scanning
	// 1.00 further code improvements, add HTTP-EQUIV to force IE7 mimicry
	// 1.01 Minor tweak to add further windows related ports
	// 1.02 Minor tweak to non-javascript browser message
	// 1.03 Minor tweak to add further parameter checking for customports
	// 1.04 Include port descriptive text
	// 1.05 Compress kickoff form
	// 1.06 Tidy up requestmethod declaration
	// 1.07 Introduction of UDP port scans
	// 1.08 Estimated run time improvement
	// 1.09 UDP responses renamed for improved consistency, ipscan_checks.c split
	// 1.10 Parallel UDP processing support added
	// 1.11 Separate TCP/UDP logging, all disabled by default
	// 1.12 Runtime estimate improvement - separate calc per protocol type
	// 1.13 Logging improvement
	// 1.14 Add support for scan automation help when offered a bad query string
	// 1.15 Incorporate further UDP support
	// 1.16 support optional ping for deployment on servers where setuid not possible
	// 1.17 support optional UDP for deployment on controlled servers
	// 1.18 move to use memset()
	// 1.19 support for special test cases
	// 1.20 support for TCP/32764 (Router backdoor) and special case debug logging improvements
	// 1.21 add minimum per-port timings to ensure Linux 1s ratelimit is not hit
	// 1.22 add completion indication to support quicker results deletion
	// 1.23 enable automatic results deletion
	// 1.24 further javascript improvements and fix for custom ports
	// 1.25 fix tidy-up reporting
	// 1.26 javascript lint check
	// 1.27 move final (javascript) fetch earlier
	// 1.28 further javascript improvements
	// 1.29 additional debug support to aid javascript optimisation
	// 1.30 additional javascript optimisation
	// 1.31 removed unused javascript functions
	// 1.32 auto-generate normal and fast versions
	// 1.33 improved error reporting
	// 1.34 added SNMPv2c and SNMPv3 support
	// 1.35 move to random(ish) sessions rather than pid()
	// 1.36 tidy up for push to github
	// 1.37 move to single XML HTTP Request object
	// 1.38 Variety of minor tweaks (CGI environment variable parsing)
	// 1.39 Add 'navigate away' detection to javascript version
	// 1.40 Correct some Coverity reported issues
	// 1.41 Add fork() issue reporting to aid debug
	// 1.42 Add automatic deletion of all results
	// 1.43 Add support for automatic deletion of orphaned results
	// 1.44 Add support for RIPng and IKEv2 SA_INIT
	// 1.45 Reintroduce MPLS LSP Ping
	// 1.46 Further DNS test error handling
	// 1.47 SNMP error handling improvement
	// 1.48 Different community strings for SNMPv1 and SNMPv2c
	// 1.49 Add DHCPv6 support
	// 1.50 Use memory engine table by default
	// 1.51 Change TCP getaddrinfo call to request AF_INET6
	// 1.52 Reduce the debug logging to make testing easier
	// 1.53 Add some Microsft Message Queuing ports which appear
	//      to be open in some Windows 10 installations
	// 1.54 Add Intel AMT ports
	// 1.55 Remove exit() calls to simplify fuzzing
	// 1.56 Add basic HTML5/CSS support for javascript binaries
	// 1.57 Add termsaccepted value and further HTML tag tweaks
	// 1.58 Add memcache to list of default TCP ports
	// 1.59 Add memcache to list of default UDP ports
	// 1.60 Reduced logging option by default
	// 1.61 Additional JS version debugging
	// 1.62 Fixed logging typos
	// 1.63 Further client debug logging improvements
	// 1.64 Yet more client debug logging improvements
	// 1.65 signed/unsigned conflicts corrected
	// 1.66 extern redefined
	// 1.67 Debug-only build for client debug improvements
	// 1.68 Debug-only build for client debug improvements
	// 1.69 URL corrections
	// 1.70 Fixes for servers without UDP or SUID support
	// 1.71 Fixes for warnings raised by Semmle (re-entrant time functions)
	// 1.72 Minor HTML fixes - robots and optional icon support
	//      plus javascript changes to remove eval()
	// 1.73 improved tidy_up_db() logging
	// 1.74 add missing logs for failed time_r conversions
	// 1.75 change text for initiations missing termsaccepted query
	// 1.76 add a separate debug build target, 
	//      improved client debug and copyright dates update
	// 1.77 Removed summarise_db() functionality - no longer used or desirable
	// 1.78 Add update_db to correctly handle test state logging
	// 1.79 Changes to use client determined starttime
	// 1.80 Additional debug for end-of-test checking
	// 1.81 Javascript improvements
	// 1.82 Add comments to disregard LGTM SQL injection false positives
	// 1.83 Further Javascript improvements
	// 1.84 Delete unused code, further Javascript improvements and remove LGTM pragmas
	// 1.85 define database delete wait-period separately
	// 1.86 Add some LGTM pragmas to hide cross-site scripting false positives
	// 1.87 Add some missing inet_ntop return-value checks, 
	//	further database debug and remove LGTM CGI cross-site scripting pragmas
	// 1.88 remove LGTM pragmas
	// 1.89 further User Agent validation
	// 1.90 Adjustments to help text and addition of TCP/20005 (KCodes NetUSB)
	//      CVE-2021-45608
	// 1.91 Fix portlist size calculation and user-defined port value masking
	// 1.92 Move to consistent unsigned masks approach (for C, not generated Javscript)
	// 1.93 Update copyright year
	// 1.94 User-agent reporting improvements - only at scan initialisation, plus support
	//	for Chrome UA strings 
	// 1.95 Added count_rows_db() function to improve checking/reporting
	// 1.96 increase FETCHEVERY to 6s

	// ipscan Version Number
	#define IPSCAN_VERNUM "1.96"

	// ipscan type
	#if (TEXTMODE == 0)
		#define IPSCAN_VERTYPE "JS-"
	#else
		#define IPSCAN_VERTYPE "TXT-"
	#endif

	// Determine reported version string 
	// and include a hint if parallel scanning (FAST) is enabled
	//
	#if (FAST == 1)
		#define IPSCAN_VERFAST "-FAST"
		#define IPSCAN_VER IPSCAN_VERTYPE IPSCAN_VERNUM IPSCAN_VERFAST 
	#else
		#define IPSCAN_VER IPSCAN_VERTYPE IPSCAN_VERNUM
	#endif
	//

	//
	#define IPSCAN_H_VER IPSCAN_VERNUM
	//

	// Email address
	#define EMAILADDRESS "webmaster@chappell-family.com"

	// Determine whether to include terms of use link (0 = don't include; 1 = include)
	#define INCLUDETERMSOFUSE 1
	// Link for terms of use - please update to reference a page from your website
	#define TERMSOFUSEURL "https://wiki.chappell-family.com/wiki/index.php?title=Timswiki:About"

	// Determine whether to offer help for bad/incomplete/unrecognised URLs
	// 0=offer no help, 1=offer help - need to define URL
	#define IPSCAN_BAD_URL_HELP 1
	// The link that might provide some help ...
	#define IPSCAN_BAD_URL_LINK "https://wiki.chappell-family.com/wiki/index.php?title=ScanAutomation"
	
	// Determine whether to offer link for restart page if terms and conditions not accepted
	// 0=no offer, 1=offer - need to define URL too
	#define IPSCAN_TC_MISSING_LINK 1
	#define IPSCAN_TC_MISSING_LINK_URL "https://ipv6.chappell-family.com/ipv6tcptest/"

	// URL providing description special protocol tests
	#define IPSCAN_SPECIALTESTS_URL "https://wiki.chappell-family.com/wiki/index.php?title=IPv6_SpecialTests"

	// Interface name on which the test server listens
	// Note this is only used to determine the IPv6 address inserted in MPLS LSP Ping packets
	// and the Link-local address sent in DHCPv6 requests.
	#define IPSCAN_INTERFACE_NAME "eth0"

	// MySQL database-related globals
	#define MYSQL_HOST "localhost"
	#define MYSQL_USER "ipscan-user"
	#define MYSQL_PASSWD "ipscan-passwd"
	#define MYSQL_DBNAME "ipscan"
	#define MYSQL_TBLNAME "results"

	// MySQL - maximum number of rows expected per unique client session (IP/session/starttime)
	// expected maximum is TCP+UDP+ICMP+state
	// MUST be less than INT_MAX (so can add one futher) to return successfully from count_rows_db()
	#define IPSCAN_DB_MAX_EXPECTED_ROWS (999)

	// MySQL - use the InnoDB engine type by default
	// You can verify the engine type using:
	// mysql --user="ipscan-user" --password="ipscan-passwd" --host=localhost ipscan
	// SHOW TABLE STATUS WHERE Name = 'results';
	//
	// Steps for creating the MySQL database - this MUST be done before tests are performed!
	// -------------------------------------------------------------------------------------
	//
	// NB: adjust the user name, password and database name to match the globals you've edited above:
	//
	// mysql> create database ipscan;
	// Query OK, 1 row affected (0.00 sec)
	//
	// mysql> create user 'ipscan-user'@'localhost' identified by 'ipscan-passwd';
	// Query OK, 0 rows affected (0.01 sec)
	//
	// mysql> grant all privileges on ipscan.* to 'ipscan-user'@'localhost' identified by 'ipscan-passwd';
	// Query OK, 0 rows affected (0.01 sec)
	//
	// mysql> exit
	// Bye
	//
	// -------------------------------------------------------------------------------------

	// *************************************************************************************
	// *                                                                                   *
	// *                    Nothing below this line should need changing                   *
	// *                                                                                   *
	// *************************************************************************************

	// DEBUG build options - uncommenting these #defines will result in copious amounts of information
	// IMPORTANT NOTE: None of these debug options should be uncommented on internet-facing servers.
	//
	#if (DEBUG == 1)
		// Common options for testing - do NOT use in production 
		#define IPSCAN_LOGVERBOSITY 3
		#define DBDEBUG 1
		#define CLIENTDEBUG 1
		// #define DBPSRDEBUG 1
		#define TUDBPSRDEBUG 1
		// #define IPSCAN_NO_TIDY_UP_DB 1
	#endif
	//
	// database (NOT port scan results)  related debug:
	// #define DBDEBUG 1
	//
	// database (port scan results) related debug:
	// #define DBPSRDEBUG 1
	//
	// ICMPv6 ping related debug:
	// #define PINGDEBUG 1
	//
	// Parallel processing related debug:
	// #define PARLLDEBUG 1
	//
	// UDP checks related debug:
	// #define UDPDEBUG 1
	//
	// UDP Parallel processing related debug:
	// #define UDPPARLLDEBUG 1
	//
	// Query string debug:
	// #define QUERYDEBUG 1
	//
	// Results debug:
	// #define RESULTSDEBUG 1
	//
	// Client (remote) debug - signalling, etc.
	// Primarily for troublesome Javascript clients.
	// #define CLIENTDEBUG 1

	// Decide whether to include ping support (requires setuid which some servers don't allow)
	// Do not modify this statement - adjust SETUID_AVAILABLE in the Makefile instead
	#ifndef SETUID_AVAILABLE
	#define IPSCAN_INCLUDE_PING 0
	#else
	#define IPSCAN_INCLUDE_PING SETUID_AVAILABLE
	#endif

	// Decide whether to include UDP support (access can be restricted on some servers)
	// Do not modify this statement - adjust UDP_AVAILABLE in the Makefile instead
	#ifndef UDP_AVAILABLE
	#define IPSCAN_INCLUDE_UDP 0
	#else
	#define IPSCAN_INCLUDE_UDP UDP_AVAILABLE
	#endif

	// Logging verbosity:
	//
	// (0) Quiet   - program/unexpected response errors only
	// (1) Verbose - port scan summary of states is logged (ie number of ports of type OPEN, STLTH, RFSD, etc.)
	//
	// Do NOT change this value as your server's syslog may then contain personal information
	// which you need to obtain permission to capture in order to satisfy your GDPR obligations
	//
	// #define IPSCAN_LOGVERBOSITY 0

	// Magic number requesting the start of a scan
	#define MAGICBEGIN 123456

	// Maximum number of ports to be tested - this should exceed the sum of the default port list
	// and the allowed user-defined ports
	#define MAXPORTS ( DEFNUMPORTS + NUMUDPPORTS + NUMUSERDEFPORTS + 1 )

	// Define the min/max valid port ranges. This could be used to restrict testing (e.g. >= 1024)
	// as long as the default port list is updated as well
	#define MINVALIDPORT 0
	#define MAXVALIDPORT 65535
	#define VALIDPORTMASK ((unsigned)(65535))

	// Enable HTML5 for Javscript
	#define IPSCAN_HTML5_ENABLED 1
	// Maximum HTML5 body div width (pixels)
	#define IPSCAN_BODYDIV_WIDTH 800

	// Ensure IPSCAN_HTML5_ENABLED is defined
	#ifndef IPSCAN_HTML5_ENABLED
                #define IPSCAN_HTML5_ENABLED 0
        #endif

	// Call different HTML headers
	#if (IPSCAN_HTML5_ENABLED == 0)
		// Default to HTML 4.01
		#define HTML_HEADER() create_html_common_header()
	#else
		// Use HTML 5 everywhere
		#define HTML_HEADER() create_html5_common_header()
	#endif

	// Enable(1) or disable(0)  favicon support
	#define IPSCAN_ICON_ENABLED 1
	// Icon type - common values include image/x-icon (.ico) and image/png (.png)
	#define IPSCAN_ICON_TYPE "image/x-icon"
	// Where to find your site icon
	#define IPSCAN_ICON_HREF "/favicon.ico"

	// Number of columns for HTML output:
	#define MAXCOLS 5
	#define COLUMNPCT (100/MAXCOLS)

	// Number of columns for UDP HTML output:
	#define MAXUDPCOLS 4
	#define COLUMNUDPPCT (100/MAXCOLS)

	// Number of columns for text-only browser output case
	// was #define TXTMAXCOLS 4
	#define TXTMAXCOLS 5

	// Number of columns per line in log outputs
	#define LOGMAXCOLS 4

	// Maximum size for buffer used to assemble log entries, 20 characters per "column" should be plenty
	#define LOGENTRYLEN (20* LOGMAXCOLS)

	// Number of octets per line in log outputs
	#define LOGMAXOCTETS 16

	// Maximum size for buffer used to assemble UDP packet debug entries
	#define LOGENTRYSIZE (64 + (4 * LOGMAXOCTETS))

	// Maximum number of octets of any UDP packet that can be logged when
	// in UDPDEBUG mode and IPSCAN_LOGVERBOSITY = 1
	#define UDPMAXLOGOCTETS 128

	// Maximum number of supported query parameters
	// Must ensure MAXQUERIES exceeds NUMUSERDEFPORTS by sufficient amount!
	#define MAXQUERIES 16
	#define MAXQUERYSTRLEN 255
	#define MAXQUERYNAMELEN 32
	#define MAXQUERYVALLEN 64

	// Maximum length of request-method string
	// should be one of GET, HEADER, POST, OPTIONS, etc. so 16 sufficient
	#define MAXREQMETHODLEN 16

	// Maximum length of HTTP_USER_AGENT string
	#define MAXUSERAGENTLEN 1024

	// Magic to convert from #defined integers to strings (used to protect sscanf)
	#define TOSTR1(i) #i
	#define TO_STR(i) TOSTR1(i)

	// Determine the executable CGI script filenames
	// These SHOULD be defined in the makefile, but provide some defaults in case
	#ifndef EXETXTNAME
		#define EXETXTNAME "ipscan-txt.cgi"
	#endif
	#ifndef EXEJSNAME
		#define EXEJSNAME "ipscan-js.cgi"
	#endif
	#ifndef EXEFASTTXTNAME
		#define EXETXTNAME "ipscan-fast-txt.cgi"
	#endif
	#ifndef EXEFASTJSNAME
		#define EXEJSNAME "ipscan-fast-js.cgi"
	#endif


	// Determine the executable file name
	#if (TEXTMODE == 1)
		#if (FAST == 1)
			#define EXENAME EXEFASTTXTNAME
		#else
			#define EXENAME EXETXTNAME
		#endif
	#else
		#if (FAST == 1)
			#define EXENAME EXEFASTJSNAME
		#else
			#define EXENAME EXEJSNAME
		#endif
	#endif

	// Served HTTP URI directory path - needs a leading /, but not a trailing one ...
	// This SHOULD be defined in the makefile, but provide a default here just in case
	#ifndef URIPATH
		#define URIPATH "/cgi-bin6"
	#endif

	// Maximum number of user-defined TCP ports
	// Must ensure MAXQUERIES exceeds NUMUSERDEFPORTS by sufficient amount!
	#define NUMUSERDEFPORTS 4

	// Logging prefix (goes into apache error_log or syslog)
	// #define LOGPREFIX EXENAME" : Version "IPSCAN_VER" : "
	#define LOGPREFIX 

   	//
	// Parallel port scanning related
	//

	// Determine the maximum number of children and therefore the maximum number of
	// port scans that can be running in parallel
	// Determine the maximum number of port scans that can be allocated to each child
	#if (FAST == 1)
		#define MAXCHILDREN 7
		#define MAXPORTSPERCHILD 9
	#else
		#define MAXCHILDREN 1
		#define MAXPORTSPERCHILD 9
	#endif

	// Determine the maximum number of children and therefore the maximum number of
	// UDP port scans that can be running in parallel
	// Determine the maximum number of UDP port scans that can be allocated to each child
	#if (FAST == 1)
		#define MAXUDPCHILDREN 3
		#define MAXUDPPORTSPERCHILD 3
	#else
		#define MAXUDPCHILDREN 1
		#define MAXUDPPORTSPERCHILD 9
	#endif


	//
	// Database related
	//

	// Determine the maximum length of the query-string which is used to insert and select
	// results into/out of the database. Currently queries are slightly in excess of 250 characters.
	#define MAXDBQUERYSIZE 512

	// Timeout for port response (in seconds)
	#define TIMEOUTSECS 1
	#define TIMEOUTMICROSECS 20000

	// Minimum time between ports (s)
	#define IPSCAN_MINTIME_PER_PORT 1

	// JSON fetch period (seconds) - tradeoff between update rate and webserver load
	#define JSONFETCHEVERY 6

	// ICMPv6 ECHO REQUEST packet size - suggest larger than 64 byte minimum is sensible, but as a minimum
	// needs to support magic string insertion anyway
	#define ICMPV6_PACKET_SIZE 128

	// Size to be allocated for transmit/receive buffer
	#define ICMPV6_PACKET_BUFFER_SIZE 2048

	// Magic constants intended to uniquify our packets;
	// process id and session start time are also included
	#define ICMPV6_MAGIC_SEQ 12478
	#define ICMPV6_MAGIC_VALUE1 1289
	#define ICMPV6_MAGIC_VALUE2 12569

	// UDP buffer size
	#define UDP_BUFFER_SIZE 512

	// UDP timeout (seconds) - needs to exceed UPnP/SSDP response request time (MX field) which is 1
	#define UDPTIMEOUTSECS 2
	#define UDPTIMEOUTMICROSECS 20000

	// An estimate of the time to perform the test - assumes num ports is always
	// smaller than (MAXPORTSPERCHILD * MAX_CHILDREN) for each protocol
	#define UDPSTATICTIME 2
	#define TCPSTATICTIME 2
	#define ICMP6STATICTIME 2

	#if (IPSCAN_INCLUDE_UDP == 1)
	#define UDPRUNTIME ((MAXUDPCHILDREN == 1) ? (numudpports * UDPTIMEOUTSECS + UDPSTATICTIME) :  ( (numudpports > MAXUDPPORTSPERCHILD) ? (MAXUDPPORTSPERCHILD * UDPTIMEOUTSECS + UDPSTATICTIME) : ( numudpports * UDPTIMEOUTSECS + UDPSTATICTIME) ) )
	#else
	#define UDPRUNTIME 0
	#endif

	#define TCPRUNTIME ( (MAXCHILDREN == 1) ? (numports * TIMEOUTSECS + TCPSTATICTIME) : ( (numports > MAXPORTSPERCHILD) ? (MAXPORTSPERCHILD * TIMEOUTSECS + TCPSTATICTIME) : ( numports * TIMEOUTSECS + TCPSTATICTIME) ) )
	#define ICMP6RUNTIME (ICMP6STATICTIME + TIMEOUTSECS)
	#define ESTIMATEDTIMETORUN ( UDPRUNTIME + TCPRUNTIME + ICMP6RUNTIME )

	// NTP constants - setup as client (mode 3), unsynchronised, poll interval 8, precision 1 second
	#define NTP_LI 0
	#define NTP_VN 4
	#define NTP_MODE 3
	#define NTP_STRATUM 16
	#define NTP_POLL 8
	#define NTP_PRECISION 2

	// Protocol mappings (stored in database)
	// Port number (0-65535) stored in lowest 16 bits, 15-0
	// Special case tests indicated by value in bits 17-16
	// This allows multiple tests to be targetted at the same port
	#define IPSCAN_PORT_WIDTH (16U)
	#define IPSCAN_SPECIAL_WIDTH (2U)
	#define IPSCAN_PROTO_WIDTH (4U)

	#define IPSCAN_PORT_MASK ((unsigned)((1<<IPSCAN_PORT_WIDTH)-1))
	#define IPSCAN_SPECIAL_MASK ((unsigned)((1<<IPSCAN_SPECIAL_WIDTH)-1))
	#define IPSCAN_PROTO_MASK ((unsigned)((1<<IPSCAN_PROTO_WIDTH)-1))

	#define IPSCAN_PORT_SHIFT (0U)
	#define IPSCAN_SPECIAL_SHIFT ((unsigned)(IPSCAN_PORT_SHIFT + IPSCAN_PORT_WIDTH))
	#define IPSCAN_PROTO_SHIFT ((unsigned)(IPSCAN_PORT_SHIFT + IPSCAN_PORT_WIDTH + IPSCAN_SPECIAL_WIDTH))

	#define IPSCAN_PROTO_TCP (0)
	#define IPSCAN_PROTO_ICMPV6 (1)
	#define IPSCAN_PROTO_UDP (2)
	#define IPSCAN_PROTO_TESTSTATE (3)

	// Maximum length of string holding protocol name
	#define IPSCAN_PROTO_STRING_MAX (16)

	// Maximum length of string holding fetchnum result name
	#define IPSCAN_FETCHNUM_STRING_MAX (20)

	// Maximum length of string holding result name
	#define IPSCAN_RESULT_STRING_MAX (32)

	// Maximum time we allow the javascript client to complete the test
	#define IPSCAN_CLIENT_MAX_TIME_SECS 240

	// Timeout before results are deleted ...
	// Should significantly exceed maximum test duration
	#define IPSCAN_DELETE_TIMEOUT (300)

	// Sleep time between polls when waiting to delete results
	#define IPSCAN_TESTSTATE_COMPLETE_SLEEP (30)

	// Time to wait before deleting database entries
	// Should exceed time for multiple JSON fetches and sleep period
	#define IPSCAN_DELETE_WAIT_PERIOD (IPSCAN_TESTSTATE_COMPLETE_SLEEP + 2 * JSONFETCHEVERY)

	// Offset from NOW in seconds. Results older than (NOW-this) are deleted
	// Should hardly ever be used, but ensures tests which were in-progress when
	// the server was shutdown/rebooted, etc. are deleted
	// All results, apart from the running state, older than the following will be deleted
	#define IPSCAN_DELETE_BEFORE_TIME_OFFSET (600)
	// Everything (results and running state) older than the following will be deleted
	#define IPSCAN_DELETE_BEFORE_LONGTIME_OFFSET (3600)
	//
	// Delete minimum time - only delete from database if > this value
	//
	#define IPSCAN_DELETE_MINIMUM_TIME (1746449000)

	// TIDY UP - either delete everything in the database or 'just' results
	#define IPSCAN_DELETE_EVERYTHING (1)
	#define IPSCAN_DELETE_RESULTS_ONLY (0)


	// Flag indicating that the response was indirect rather than from the host under test
	// This may be the case if the host under test is behind a firewall or router
	#define IPSCAN_INDIRECT_RESPONSE 256
	// Mask to extract the response code - used in created Javascript
	#define IPSCAN_INDIRECT_MASK 255

	// Completion indicators (passed in fetch querystring)
	//
	// IPSCAN_SUCCESSFUL_COMPLETION is used as a marker such that any query string fetch which
	// exceeds this value will be assumed to be indicating feedback from the javascript client
	//
	// IPSCAN_UNEXPECTED_CHANGE MUST be the last entry in the enumerated list
	//
	enum COMPLETIONSTATE
	{
		IPSCAN_SUCCESSFUL_COMPLETION = 990,
		IPSCAN_HTTPTIMEOUT_COMPLETION,
		IPSCAN_EVAL_ERROR,
		IPSCAN_OTHER_ERROR,
		IPSCAN_UNSUCCESSFUL_COMPLETION,
		IPSCAN_NAVIGATE_AWAY,
		IPSCAN_BAD_JSON_ERROR,
		IPSCAN_DB_ERROR,
		IPSCAN_UNEXPECTED_CHANGE,
	};

	//
	// TESTSTATE browser-signalled values - helps to debug javascript failures
	// Mapped to high values so they are all out of range of PORTSTATE
	//
	// Size of buffer holding the flag descriptions
	// Typically each flag is 11 characturs including trailing comma and space
	//
	#define IPSCAN_FLAGSBUFFER_SIZE (128)
	//
	#define IPSCAN_TESTSTATE_IDLE (0)
	#define IPSCAN_TESTSTATE_RUNNING_BIT (32)
	#define IPSCAN_TESTSTATE_COMPLETE_BIT (64)
	#define IPSCAN_TESTSTATE_HTTPTIMEOUT_BIT (128)
	#define IPSCAN_TESTSTATE_EVALERROR_BIT (256)
	#define IPSCAN_TESTSTATE_OTHERERROR_BIT (512)
	#define IPSCAN_TESTSTATE_NAVAWAY_BIT (1024)
	#define IPSCAN_TESTSTATE_UNEXPCHANGE_BIT (2048)
	#define IPSCAN_TESTSTATE_BADCOMPLETE_BIT (4096)
	#define IPSCAN_TESTSTATE_DATABASE_ERROR_BIT (8192)

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
		ECHONOREPLY,
		ECHOREPLY,
		/* Addition for UDP port respond/doesn't */
		UDPOPEN,
		UDPSTEALTH,
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
		char label[32];
		char colour[32];
		char description[384];
	};

	// Single definition of external : resultsstruct
	extern struct rslt_struc resultsstruct[];

	// Default ports structure
	//
	// This constant defines the maximum port description size. Bear in mind, irrespective of the
	// description used in ipscan_portlist.h it also needs to support the text inserted for
	// user specified ports "User-specified: %d" (21 characters plus trailing \0), and so should not be
	// reduced below 22.
	#define PORTDESCSIZE 48
	//
	// the structure - consists of a port number, a "special case" indicator and a text description
	//
	struct portlist_struc
	{
		uint16_t port_num;
		uint8_t special;
		char port_desc[PORTDESCSIZE];
	};

	// End of defines
#endif
