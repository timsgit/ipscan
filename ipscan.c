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

// ipscan.c version
// 0.01 - first released version
// 0.02 - additional DEBUG added for MySQL investigation
// 0.03 - added syslog support
// 0.04 - improved HTML (transition to styles, general compliance)
// 0.05 - addition of ICMPv6 ECHO-REQUEST functionality
// 0.06 - removal of empty HTML paragraph
// 0.07 - further buffer overflow prevention measures
// 0.08 - correct printf cast
// 0.09 - tidy up exit calls and verbosity support
// 0.10 - minor include correction for FreeBSD support
// 0.11 - add parallel port scan function
// 0.12 - remove unused parameters
// 0.13 - specifically count number of customport parameters
// 0.14 - add service names to results table (modification to portlist, now structure)
// 0.15 - fix length of requestmethod to prevent potential overflow
// 0.16 - add UDP port scan support
// 0.17 - add parallel UDP port scan support
// 0.18 - separate UDP and TCP debug logging
// 0.19 - added missing log prefix
// 0.20 - add scan automation help when offered a bad query string
// 0.21 - add support for removal of ping
// 0.22 - add support for removal of UDP
// 0.23 - add support for special test cases
// 0.24 - improve special test case debug logging
// 0.25 - add support for test completion reporting
// 0.25 - fix special case handling for custom ports
// 0.26 - correct fetch tidy-up reporting
// 0.27 - update to support further completion report types
// 0.28 - improved error logging
// 0.29 - use random(ish) sessions rather than getpid
// 0.30 - move to use strnlen() in getenv lookups
// 0.31 - improved querystring parsing, truncated session id
// 0.32 - add Navigate away detection
// 0.33 - add reporting for fork() issues
// 0.34 - add automated results deletion for javascript clients
// 0.35 - add support for deletion of orphaned results
// 0.36 - add time() response checks
// 0.37	- simplify reported syslog name
// 0.38 - remove exit() calls to simplify fuzzing
// 0.39 - transition to HTML5 support
// 0.40 - further HTML tag adjustments
// 0.41 - add TCP memcache port check
// 0.42 - logging in spirit of RFC6302 (default logging records IPv6 addresses as /48)
// 0.43 - exit from scan if terms were not accepted
// 0.44 - limited IPv6 address logging and further client debug
// 0.45 - further client debug improvements
// 0.46 - yet more client debug improvements
// 0.47 - yet more client debug improvements
// 0.48 - fix compilation on platforms which don't support UDP or SUID
// 0.49 - semmle re-entrant time function changes
// 0.50 - add page reload for case where terms and conditions not accepted
// 0.51 - further client debug improvements and copyright update
// 0.52 - remove summarise_db() functionality
// 0.53 - incorporate update_db() for test state
// 0.54 - insert delay before db_delete
// 0.55 - update logging for cases where database lookup returns UNKNOWN
// 0.56 - minor debug update to identify end-of-test client
// 0.57 - update copyright year and move to client session/starttime generation
// 0.58 - minor tweaks to delays before database record deletion at end of javascript test
// 0.59 - added LGTM pragmas to ignore cross-site scripting false positives
// 0.60 - validation added for both check_icmpv6_echoresponse() calls which overwrite indirecthost 
// 0.61 - remove LGTM pragmas which ignored cross-site scripting false positives
// 0.62 - further User Agent string validation
// 0.63 - change to response descriptions to make it clear that responses may come
//        from the host under test or a.n.other device in the path (e.g. a firewall)
// 0.64 - allow NAVAWAY as a reason for client_finished
// 0.65 - correct masking of user-defined ports - thanks to Brian Gregory for spotting the issue
// 0.66 - update copyright year
// 0.67 - change scope of multiple variables
// 0.68 - change querysession and querystarttime to unsigned with separate flags
// 0.69 - default colour to blue
// 0.70 - improve client host address reporting
// 0.71 - improve client user agent and alternatives reporting
// 0.72 - changes to report running state to client
// 0.73 - delete_from_db() gets another parameter - delete everything or delete results only
//        relies on tidy_up_db to get rid of final test state later on (not sensitive)
// 0.74 - make up to two delete_from_db() attempts in case of database deadlock
// 0.75 - delete some redundant code/comments
// 0.76 - portlist structs are consts
// 0.77 - rewrite running state if a normal fetch completes successfully
// 0.78 - CodeQL improvements
// 0.79 - incorporate new tidy_up_db() using server defined timestamp
// 0.80 - various code quality improvements (scope reductions)
// 0.81 - querystring parsing improvements

//
#define IPSCAN_MAIN_VER "0.81"
//

#include "ipscan.h"
#include "ipscan_portlist.h"
//
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <stdint.h>
// toupper/tolower routines
#include <ctype.h>

// Others that FreeBSD highlighted
#include <netinet/in.h>

// IPv6 address conversion
#include <arpa/inet.h>

// String comparison
#include <string.h>

// errors
#include <errno.h>

// Logging with syslog requires additional include
#if (1 == LOGMODE)
#include <syslog.h>
#endif

// Parallel processing related
#include <sys/wait.h>

//
// Prototype declarations
//
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, const char *indirecthost);
int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session);
int read_db_result(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port);
int delete_from_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, int8_t deleteall);
int tidy_up_db(int8_t deleteall);
int update_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, const char *indirecthost);
int count_rows_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session);
int check_udp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, const struct portlist_struc *udpportlist);
int check_tcp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, const struct portlist_struc *portlist);
void create_json_header(void);
void create_html_header(uint16_t numports, uint16_t numudpports, char * reconquery);
// starttime is of type time_t in create_html_body() calls:
void create_html_body(char * hostname, time_t timestamp, uint16_t numports, uint16_t numudpports, const struct portlist_struc *portlist, const struct portlist_struc *udpportlist);
void report_useragent_strings(char *uavar, char *secchuavar, char *secchuaarchvar, char *secchuaarchplatvar);
void report_ipscan_versions(const char *mainver, const char *generalver, const char *tcpver, const char *udpver, const char *icmpv6ver, const char *dbver,\
         const char *webver, const char *hver, const char *plver);
int querystring_is_alphanum(char check);
int querystring_is_valid(char check);
int querystring_is_number(char check);
const char* ipscan_general_ver(void);
const char* ipscan_tcp_ver(void);
const char* ipscan_udp_ver(void);
const char* ipscan_icmpv6_ver(void);
const char* ipscan_db_ver(void);
const char* ipscan_web_ver(void);
#ifdef IPSCAN_HTML5_ENABLED
void create_html5_common_header(void);
void create_html5_form(uint16_t numports, uint16_t numudpports, const struct portlist_struc *portlist, const struct portlist_struc *udpportlist);
#else
void create_html_form(uint16_t numports, uint16_t numudpports, const struct portlist_struc *portlist, const struct portlist_struc *udpportlist);
#endif
void create_html_common_header(void);
void create_html_body_end(void);
#if (1 == TEXTMODE)
uint64_t get_session(void);
#endif
void proto_to_string(int proto, char * retstring);
void fetch_to_string(int fetchnum, char * retstring);
char * state_to_string(int statenum, char * retstringptr, int retstringfree);
// create_results_key_table is only referenced if creating the text-only version of the scanner
#if (1 == TEXTMODE)
void create_results_key_table(char * hostname, time_t timestamp);
#endif
// Only include reference to ping-test function if compiled in
#if (1 == IPSCAN_INCLUDE_PING)
int check_icmpv6_echoresponse(char * hostname, uint64_t starttime, uint64_t session, char * router);
#endif

//
// End of prototypes declarations
//

// structure holding the potential results table - entries MUST be in montonically increasing enumerated returnval order
const struct rslt_struc resultsstruct[] =
{
		/* returnval,		connrc,	conn_errno		TEXT lbl			TEXT col	Description/User feedback	*/
		{ PORTOPEN, 		0, 		0,	 			"OPEN", 			"red",		"An IPv6 TCP connection was successfully established to this port. You should check that this is the expected outcome since an attacker may be able to compromise your machine by accessing this IPv6 address/port combination."},
		{ PORTABORT, 		-1, 	ECONNABORTED, 	"ABRT", 			"yellow",	"An abort indication was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTREFUSED, 		-1, 	ECONNREFUSED, 	"RFSD", 			"yellow",	"A refused indication (TCP RST/ACK or ICMPv6 type 1 code 4) was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTCRESET, 		-1, 	ECONNRESET, 	"CRST", 			"yellow",	"A connection reset request was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTNRESET, 		-1, 	ENETRESET, 		"NRST", 			"yellow",	"A network reset request was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTINPROGRESS, 	-1, 	EINPROGRESS, 	"STLTH", 			"green",	"No response was received in the allocated time period. This is the ideal response since no-one can ascertain your machines' presence at this IPv6 address/port combination."},
		{ PORTPROHIBITED, 	-1, 	EACCES, 		"PHBTD", 			"yellow",	"An administratively prohibited response (ICMPv6 type 1 code 1) was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTUNREACHABLE, 	-1, 	ENETUNREACH, 	"NUNRCH", 			"yellow",	"An unreachable response (ICMPv6 type 1 code 0) was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTNOROUTE, 		-1, 	EHOSTUNREACH, 	"HUNRCH", 			"yellow",	"A No route to host response (ICMPv6 type 1 code 3 or ICMPv6 type 3) was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTPKTTOOBIG, 	-1, 	EMSGSIZE, 		"TOOBIG", 			"yellow",	"A Packet too big response (ICMPv6 type 2) was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ PORTPARAMPROB, 	-1, 	EPROTO, 		"PRMPRB", 			"yellow",	"A Parameter problem response (ICMPv6 type 4) was received when attempting to open this port. Someone can ascertain that your machine, or another device in the path, is responding on this IPv6 address/port combination, but cannot establish a direct connection."},
		{ ECHONOREPLY, 		-96, 	-96,	 		"ECHO NO REPLY",	"green",	"No ICMPv6 ECHO_REPLY packet was received in response to the ICMPv6 ECHO_REQUEST which was sent. This is the ideal response since no-one can ascertain your machines' presence at this IPv6 address."},
		{ ECHOREPLY, 		-97, 	-97,	 		"ECHO REPLY", 		"yellow",	"An ICMPv6 ECHO_REPLY packet was received in response to the ICMPv6 ECHO_REQUEST which was sent. Someone can ascertain that your machine is present on this IPv6 address."},
		{ UDPOPEN,			-95,	-95,			"UDPOPEN",			"red",		"A valid response was received from this UDP port. You should check that this is the expected outcome since an attacker may be able to compromise your machine by accessing this IPv6 address/port combination."},
		{ UDPSTEALTH,		-1,		EAGAIN,			"UDPSTEALTH",		"green",	"No UDP response was received from your machine in the allocated time period. This is the ideal response since no-one can ascertain your machines' presence at this IPv6 address/port combination."},
		/* Unexpected and unknown error response cases, do NOT change */
		{ PORTUNEXPECTED,	-98,	-98,			"UNXPCT",			"white",	"An unexpected response was received to the connect attempt."},
		{ PORTUNKNOWN, 		-99,	-99, 			"UNKWN", 			"white",	"An unknown error response was received, or the port is yet to be tested."},
		{ PORTINTERROR,		-100,	-100,			"INTERR",			"white",	"An internal error occurred."},
		/* End of list marker, do NOT change */
		{ PORTEOL,			-101,	-101,			"EOL",				"black",	"End of list marker."}
};

//
// ----------------------------------
//
const char* ipscan_main_ver(void)
{
    return IPSCAN_MAIN_VER;
}

const char* ipscan_h_ver(void)
{
    return IPSCAN_H_VER;
}

const char* ipscan_portlist_ver(void)
{
    return IPSCAN_PORTLIST_VER;
}
//
// ----------------------------------
//

int main(void)
{

	#if (1 == TEXTMODE)
	// last is only used in text-only mode
	int last = 0;
	#else
	// fetchnum is only used in javascript-only mode
	int fetchnum = 0;
	#endif

	// List of ports to be tested and their results
	struct portlist_struc portlist[MAXPORTS];

	// Default for unused database entries

	// Only necessary if we're including ping support
	#if (1 == IPSCAN_INCLUDE_PING)
	// Storage for indirecthost address, in case required
	// Note that indirecthost value validation is performed twice below
	// It may need changing if the declaration of this variable is adjusted
	char indirecthost[INET6_ADDRSTRLEN+1];
	#endif

	char remoteaddrstring[INET6_ADDRSTRLEN+1];
	char *remoteaddrvar;

	// the session starttime, used as an unique index for the database
	time_t starttime;

	// Parallel scanning related
	int childstatus;

	// Ports to be tested
	#if (1 == IPSCAN_INCLUDE_UDP)
	uint16_t numudpports = NUMUDPPORTS;
	#endif

	// "general purpose" variables, used as required
	int rc;
	unsigned int i = 0;
	unsigned int shift;

	// stats
	unsigned int portsstats[ NUMRESULTTYPES ];

	// Determine request method and query-string
	char requestmethod[ (MAXREQMETHODLEN + 1) ];
	char thischar;
	char *reqmethodvar;
	char *querystringvar;
	char querystring[ (MAXQUERYSTRLEN + 1) ];

	// buffer for reconstituted querystring
	char reconquery[ (MAXQUERYSTRLEN + 1) ];
	char *reconptr = &reconquery[0];

	// buffer for logging entries
	size_t logbuffersize = LOGENTRYLEN;
	char logbuffer[ (LOGENTRYLEN + 1) ];
	char *logbufferptr = &logbuffer[0];

	// Structure to hold querystring variable names, their values and a validity indication
	typedef struct {
		char varname[(MAXQUERYNAMELEN+2)];
		int64_t varval; // Signed since some values will be negative
		int valid;
	} queries;

	queries query[MAXQUERIES];
	unsigned int numqueries = 0;
	int64_t varval = 0; // temporary storage for query string parameters
	// value string - add two chars to cope with trailing \0
	char valstring[ (MAXQUERYVALLEN + 2) ];

	// IPv6 address related
	unsigned char remotehost[sizeof(struct in6_addr)];

	uint64_t value;
	uint64_t remotehost_msb = 0ULL;
	uint64_t remotehost_lsb = 0ULL;

	// If syslog is in use then open the log
	#if (1 == LOGMODE)
	openlog(EXENAME, LOG_PID, LOG_LOCAL0);
	#endif

	// Initialise the port list
	for (i = 0; i < DEFNUMPORTS; i++)
	{
		portlist[i] = defportlist[i];
	}

	// Clear out the port result type statistics
	for (i = 0 ; i < NUMRESULTTYPES ; i++)
	{
		portsstats[i] = 0;
	}

	// Log the current time and "session" with which to initiate scan and fetch results
	// These should ensure that each test is globally unique when client IP address is also used.
	starttime = time(NULL);
	if (starttime < 0)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time() returned bad value for starttime %d (%s)\n", errno, strerror(errno));
		return(EXIT_SUCCESS);
	}

	#if (1 == TEXTMODE)
	uint64_t session = get_session();
	// This should never occur, but just in case ...
	if (session == 0)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: get_session() returned 0 value for session.\n");
		return(EXIT_SUCCESS);
	}
	#endif

	#ifdef CLIENTDEBUG
	#if (1 <= IPSCAN_LOGVERBOSITY)
	// Capture USER AGENT string as well as the SEC_CH_UA strings (Chrome)
	// Note web server requires additional header statements for UA strings to be requested
	//
	// <IfModule mod_headers.c>
       	// 	Header set Accept-CH "Sec-CH-UA-Platform-version,UA-Platform-Version,Sec-CH-UA-Arch"
	// </IfModule>
	//
        char *useragentvar;
        char *secchuavar;
        char *secchuaarchvar;
        char *secchuaplatvar;
        useragentvar = getenv("HTTP_USER_AGENT");
        secchuavar = getenv("HTTP_SEC_CH_UA");
        secchuaarchvar = getenv("HTTP_SEC_CH_UA_ARCH");
        secchuaplatvar = getenv("HTTP_SEC_CH_UA_PLATFORM");
	#endif
	#endif

	// QUERY_STRING / REQUEST_METHOD
	// URL is of the form: ipv6.cgi?name1=value1&name2=value2
	// REQUEST_METHOD = GET
	// QUERY_STRING = name1=value1&name2=value2
	reqmethodvar = getenv("REQUEST_METHOD");
	querystringvar = getenv("QUERY_STRING");

	// ensure length OK
	if (NULL == reqmethodvar)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : REQUEST_METHOD variable lookup returned NULL.\n");
	}
	else if ( strnlen(reqmethodvar, (MAXREQMETHODLEN+1)) > MAXREQMETHODLEN )
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ATTACK?: REQUEST_METHOD variable string is longer than allocated buffer (%d > %d)\n", (int)strnlen(reqmethodvar, (MAXREQMETHODLEN+1)), MAXREQMETHODLEN);
		// Create the header
		HTML_HEADER();
		// Now finish the header
		printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
		printf("</head>\n");
		printf("<body>\n");
		printf("<p>I was called with REQUEST_METHOD longer than my allocated buffer. That is very disappointing.</p>\n");
		// Finish the HTML
		create_html_body_end();
		return(EXIT_SUCCESS);
	}
	else if ( sscanf(reqmethodvar,"%"TO_STR(MAXREQMETHODLEN)"s",requestmethod) != 1 )
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: Invalid request-method scan.\n");
	}
	else
	{
		#ifdef QUERYDEBUG
		IPSCAN_LOG( LOGPREFIX "ipscan: Request method is : %s\n", requestmethod);
		#endif

		// Force Uppercase to ease comparison
		for (i = 0; i < (unsigned int)strnlen(requestmethod, (MAXREQMETHODLEN+1)); i++)
		{
			thischar=requestmethod[i];
			requestmethod[i]=(char)(toupper(thischar) & 0xFF);
		}

		if (0 == strncmp("GET", requestmethod, 3))
		{
			if (NULL == querystringvar)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: QUERY_STRING variable lookup returned NULL.\n");
			}
			else if ( strnlen(querystringvar, MAXQUERYSTRLEN+1) > MAXQUERYSTRLEN)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ATTACK?: QUERY_STRING environment string is longer than allocated buffer (%d > %d)\n", (int)strnlen(querystringvar, MAXQUERYSTRLEN+1), MAXQUERYSTRLEN);
				// Create the header
				HTML_HEADER();
				// Now finish the header
				printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
				printf("</head>\n");
				printf("<body>\n");
				printf("<p>I was called with a QUERY_STRING longer than my allocated buffer. That is very disappointing.</p>\n");
				// Finish the HTML
				create_html_body_end();
				return(EXIT_SUCCESS);
			}
			else if ( sscanf(querystringvar,"%"TO_STR(MAXQUERYSTRLEN)"s",querystring) != 1 )
			{
				#ifdef QUERYDEBUG
				// No query string will get reported here ....
				IPSCAN_LOG( LOGPREFIX "ipscan: Invalid query-string sscanf.\n");
				#endif
			}
			else
			{
				#ifdef QUERYDEBUG
				IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: Query-string : %s\n", querystring);
				#endif

				// Force lowercase to ease later comparison
				for (i = 0; i < (unsigned int)strnlen(querystring,(MAXQUERYSTRLEN)); i++)
				{
					thischar=querystring[i];
					querystring[i]=(char)(tolower(thischar) & 0xFF);
				}

				//
				// Split the query string into variable names and values
				//
				// URL is of the form: ipscanjs.cgi?name1=value1&name2=value2
				unsigned int queryindex = 0;
				int finished = 0;

				// Loop around while we haven't exceeded MAXQUERYSTRLEN, the next character is valid, and we haven't found too many query strings
				while (MAXQUERYSTRLEN > queryindex && 0 != querystring_is_alphanum(querystring[queryindex]) && 0 == finished && MAXQUERIES > numqueries)
				{
					int varnameindex = 0;
					query[numqueries].valid = 0;

					// Determine the querystring variable name
					// Loop around while the character is an alphanumeric and we haven't reached the allowed querystring or variable name length
					while ( 0 != querystring_is_alphanum(querystring[queryindex])\
							&& MAXQUERYSTRLEN > queryindex && MAXQUERYNAMELEN > varnameindex && 0 == finished)
					{
						query[numqueries].varname[varnameindex] = querystring[queryindex];
						varnameindex ++;
						queryindex ++;
					}
					if (MAXQUERYNAMELEN <= varnameindex)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: query parameter name string is too long : %s\n", querystring);
						varnameindex = MAXQUERYNAMELEN; // Truncate
					}
					query[numqueries].varname[varnameindex]=0; // Add termination

					// Finished if the querystring contains an invalid character (including end-of-string) or we've exceeded the maximum length
					finished = (0 == querystring_is_valid(querystring[queryindex]) ||  MAXQUERYSTRLEN <= queryindex) ? 1 : 0;

					// Jump over '=' characters - don't really need a loop, but it gives slightly more flexibility
					if (0 == finished && '=' == querystring[queryindex])
					{
						// Jump over '='
						while (MAXQUERYSTRLEN > queryindex && '=' == querystring[queryindex])
						{
							queryindex++;
						}
						int valueindex = 0;

						// Copy the value string into a separate variable. 
						// Allow numbers and signs whilst we remain under both the value and querystring length
						while ( MAXQUERYVALLEN > valueindex && MAXQUERYSTRLEN > queryindex && 0 != querystring_is_number(querystring[queryindex]) )
						{
							valstring[valueindex] = querystring[queryindex];
							queryindex++;
							valueindex++;
						}
						// Truncate and terminate, if required
						if (MAXQUERYVALLEN <= valueindex)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: query parameter value string is too long : %s\n", querystring);
							valueindex = MAXQUERYVALLEN; // Truncate
						}
						valstring[valueindex]=0; // Add termination

						// Parse the value string as a signed 64-bit integer
						rc = sscanf(valstring,"%20"SCNd64, &varval ); // added max width specifier
						if (1 == rc)
						{
							// Valid, so record the value, mark the entry as valid, and increment the number of queries found
							query[numqueries].varval = varval;
							query[numqueries].valid = 1;
							#ifdef QUERYDEBUG
							IPSCAN_LOG( LOGPREFIX "ipscan: Added a new query name: %s with a value of : %"PRId64"\n", query[numqueries].varname, query[numqueries].varval);
							#endif
							numqueries++;
						}
						else
						{
							// Invalid, so clear the value, mark the entry as invalid, and increment the number of queries found
							#ifdef QUERYDEBUG
							IPSCAN_LOG( LOGPREFIX "ipscan: Bad value assignment for %s, setting invalid.\n", query[numqueries].varname);
							#endif
							query[numqueries].varval = 0;
							query[numqueries].valid = 0;
							numqueries++;
						}
					}

					// Move past the '&' sign(s)
					while (MAXQUERYSTRLEN > queryindex && 0 == finished && '&' == querystring[queryindex])
					{
						queryindex++;
					}
					// Finished if the querystring contains an invalid character (including end-of-string) or we've exceeded the maximum length
					finished = (0 == querystring_is_valid(querystring[queryindex]) ||  MAXQUERYSTRLEN <= queryindex) ? 1 : 0;
				}
				#ifdef QUERYDEBUG
				IPSCAN_LOG( LOGPREFIX "ipscan: Number of query pairs found is : %d\n", numqueries);
				#endif
			}
		}
		else if (0 == strncmp("HEAD", requestmethod, 4))
		{
			// Create the header
			HTML_HEADER();
			// Now finish the header
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("</html>\n");
			IPSCAN_LOG( LOGPREFIX "ipscan: HEAD request method, sending headers only\n");
			return(EXIT_SUCCESS);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: called with an unsupported request method: %s.\n", requestmethod);
			// Create the header
			HTML_HEADER();
			// Now finish the header
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<p>I was called with an unsupported request-method. That is very disappointing.</p>\n");
			// Finish the HTML
			create_html_body_end();
			return(EXIT_SUCCESS);
		}
	}

	// Determine the clients' address
	remoteaddrvar = getenv("REMOTE_ADDR");
	if (NULL == remoteaddrvar)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: REMOTE_ADDR variable lookup returned NULL.\n");
	}
	else if (strnlen(remoteaddrvar,(INET6_ADDRSTRLEN+1)) > INET6_ADDRSTRLEN)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: REMOTE_ADDR variable length exceeds allocated buffer size (%d > %d)\n", (int)strnlen(remoteaddrvar, (INET6_ADDRSTRLEN+1)), INET6_ADDRSTRLEN);
		// Create the header
		HTML_HEADER();
		// Now finish the header
		printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
		printf("</head>\n");
		printf("<body>\n");
		printf("<p>I was called with a REMOTE_ADDR variable that exceeds the supported size. That is very disappointing.</p>\n");
		// Finish the HTML
		create_html_body_end();
		return(EXIT_SUCCESS);
	}
	else if ( sscanf(remoteaddrvar,"%"TO_STR(INET6_ADDRSTRLEN)"s",remoteaddrstring) != 1 )
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: Invalid REMOTE_ADDR variable data.\n");
	}
	else
	{
		// Determine the remote host address
		rc = inet_pton(AF_INET6, remoteaddrstring, remotehost);
		if (rc <= 0)
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: Unparseable IPv6 host address : %s\n", remoteaddrstring);
			// Create the header
			HTML_HEADER();
			// Now finish the header
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<p>I was called with an unparseable IPv6 host address. That is very disappointing.</p>\n");
			// Finish the HTML
			create_html_body_end();
			return(EXIT_SUCCESS);
		}
		else
		{
			remotehost_msb = 0ULL;
			remotehost_lsb = 0ULL;

			// Split address into two 64 bit values stored within database
			for (i=0 ; i<8 ; i++)
			{
				shift = 8 * (7-i);
				value = (remotehost[i]);
				while (shift > 0)
				{
					value = (value << 8);
					shift -= 8;
				}
				remotehost_msb |= value;
				shift = 8 * (7-i);
				value = (remotehost[8+i]);
				while (shift > 0)
				{
					value = (value << 8);
					shift -= 8;
				}
				remotehost_lsb |= value;
			}
		}
	}


	// If query string is empty then we generate the introductory HTML/form for the client

	if (0 == numqueries)
	{
		#ifdef CLIENTDEBUG
		#if (1 < IPSCAN_LOGVERBOSITY)
		IPSCAN_LOG( LOGPREFIX "ipscan: Remote host protected client address (/48): %x:%x:%x:: 0 queries\n",\
				(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
				(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
		#endif
		#endif

		// Create the HTML header
		HTML_HEADER();

		#ifdef IPSCAN_HTML5_ENABLED
		// Create the main HTML5 body
		create_html5_form(DEFNUMPORTS, NUMUDPPORTS, portlist, udpportlist);
		#else
		// Create the main HTML body
		create_html_form(DEFNUMPORTS, NUMUDPPORTS, portlist, udpportlist);
		#endif

		// Finish the HTML
		create_html_body_end();
	}

	// Following is a query, so determine the passed parameters and decide whether we
	// need to initiate a scan, return the current result set or a summary of scans

	else
	{
		int includeexisting = 0;
		#ifdef CLIENTDEBUG
		#if (1 < IPSCAN_LOGVERBOSITY)
		IPSCAN_LOG( LOGPREFIX "ipscan: Remote host protected client address (/48): %x:%x:%x:: %d queries\n",\
				(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
				(unsigned int)((remotehost_msb>>16) & 0xFFFF), numqueries );
		#endif
		#endif

		// includeexisting should only be passed the values -1 or 1, set to 0 if not present
		// or an unsuitable value is passed.
		i = 0;
		while (i < numqueries && 0 != strncmp("includeexisting",query[i].varname,15)) i++;
		if (i < numqueries && 1 == query[i].valid)
		{
			if ( 1 == abs((int)query[i].varval) )
			{
				includeexisting = (int)query[i].varval;
			}
			else
			{
				includeexisting = 0 ;
			}
		}
		else
		{
			includeexisting = 0;
		}

		// determine state of termsaccepted, if not present default to 0
		int termsaccepted = 0;
		i = 0;
		while (i < numqueries && 0 != strncmp("termsaccepted",query[i].varname,13)) i++;
		if (i < numqueries && 1 == query[i].valid)
		{
			if ( 1 == abs((int)query[i].varval))
			{
				termsaccepted = 1;
			}
			else
			{
				termsaccepted = 0;
			}
		}
		else
		{
			termsaccepted = 0;
		}

		// Begin the reconstitution of the query string
		int reconquerysize = MAXQUERYSTRLEN;
		rc = snprintf(reconptr, (size_t)reconquerysize, "includeexisting=%d", (int)includeexisting);
		if (16 < rc && 19 > rc)
		{
			reconptr += rc;
			reconquerysize -= (size_t)rc;
			if (0 >= reconquerysize)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: run out of room to reconstitute query, please increase MAXQUERYSTRLEN (%d) and recompile.\n", MAXQUERYSTRLEN);
				// Create the header
				HTML_HEADER();
				// Now finish the header
				printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
				printf("</head>\n");
				printf("<body>\n");
				printf("<p>I have run out of room to reconstitute the query. That is very disappointing.</p>\n");
				// Finish the HTML
				create_html_body_end();
				return(EXIT_SUCCESS);
			}
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: attempt to reconstitute query returned an unexpected length (%d, expecting 17 or 18)\n", rc);
			// Create the header
			HTML_HEADER(); 
			// Now finish the header
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<p>I was called with an unexpected query length. That is very disappointing.</p>\n");
			// Finish the HTML
			create_html_body_end();
			return(EXIT_SUCCESS);
		}

		// Continue the reconstitution of the query string
		rc = snprintf(reconptr, (size_t)reconquerysize, "&termsaccepted=%d", (int)termsaccepted);
		if (16 == rc)
		{
			reconptr += rc;
			reconquerysize -= (size_t)rc;
			if (reconquerysize <= 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: run out of room to continue reconstituting query, please increase MAXQUERYSTRLEN (%d) and recompile.\n", MAXQUERYSTRLEN);
				// Create the header
				HTML_HEADER();
				// Now finish the header
				printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
				printf("</head>\n");
				printf("<body>\n");
				printf("<p>I have run out of room to continue reconstituting the query. That is very disappointing.</p>\n");
				// Finish the HTML
				create_html_body_end();
				return(EXIT_SUCCESS);
			}
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: attempt to reconstitute query returned an unexpected length (%d, expecting 16)\n", rc);
			// Create the header
			HTML_HEADER();
			// Now finish the header
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<p>I was called with an unexpected query length. That is very disappointing.</p>\n");
			// Finish the HTML
			create_html_body_end();
			return(EXIT_SUCCESS);
		}

		// Determine whether existing ports are to be included in the tested list or not:
		uint16_t numports;
		if (1 == includeexisting)
		{
			// custom ports will be appended to the default ports list
			numports = DEFNUMPORTS;
		}
		else
		{
			// default ports will be overwritten by any custom ports
			numports = 0;
		}

		#ifdef QUERYDEBUG
		IPSCAN_LOG( LOGPREFIX "ipscan: numports is initially found to be %d\n", numports);
		#endif

		//
		// Add in the custom ports if they're valid and NOT already present in the portlist ...
		//

		int customport = 0;
		char cpnum[17];

		// Counter holding the number of received customportN statements
		unsigned int numcustomports = 0;

		while (NUMUSERDEFPORTS > customport)
		{
			size_t cplen = (size_t)snprintf(cpnum, 16, "customport%d", customport);
			i = 0;
			while (i < numqueries && 0 != strncmp(cpnum,query[i].varname,cplen)) i++;

			// If customportN parameter exists then increment the counter, irrespective of whether
			// the parameter was valid or not
			if (i < numqueries) numcustomports++;

			// If the parameter is valid then perform further checks
			if (i < numqueries && 1 == query[i].valid)
			{
				// Check the port number is in the valid range
				if (query[i].varval >= MINVALIDPORT && query[i].varval <= MAXVALIDPORT)
				{
					unsigned int j = 0;
					while (j < numports && portlist[j].port_num != query[i].varval) j++;
					// if this customport is not one of the ports already destined for checking then
					// add it to the port list
					if (j == numports)
					{
						portlist[numports].port_num = (uint16_t)(query[i].varval & VALIDPORTMASK);
						portlist[numports].special = 0;
						rc = snprintf(&portlist[numports].port_desc[0], PORTDESCSIZE, "User-specified: %d",(int)query[i].varval);
						if (rc < 0 || rc >= PORTDESCSIZE)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: INFO: failed to write user-specified port description, does PORTDESCSIZE (%d) need increasing?\n", PORTDESCSIZE);
						}
						numports ++;
						rc = snprintf(reconptr, (size_t)reconquerysize, "&customport%d=%d", customport, (int)query[i].varval);
						// &customport (11); cpnum (1-5) ; = (1) ; portnum (1-5)
						if (rc >= 14 && rc <= 22)
						{
							reconptr += rc;
							reconquerysize -= (size_t)rc;
							if (reconquerysize <= 0)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: run out of room to reconstitute query, please increase MAXQUERYSTRLEN (%d) and recompile.\n", MAXQUERYSTRLEN);
								// Create the header
								HTML_HEADER();
								// Now finish the header
								printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
								printf("</head>\n");
								printf("<body>\n");
								printf("<p>I have run out of room to reconstitute the query. That is very disappointing.</p>\n");
								// Finish the HTML
								create_html_body_end();
								return(EXIT_SUCCESS);
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: customport%d reconstitution failed, due to unexpected size.\n", customport);
							// Create the header
							HTML_HEADER();
							// Now finish the header
							printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
							printf("</head>\n");
							printf("<body>\n");
							printf("<p>I have run out of room to reconstitute the query. That is very disappointing.</p>\n");
							// Finish the HTML
							create_html_body_end();
							return(EXIT_SUCCESS);
						}
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: custom port %s port is out of range %d =< %"PRId64" <= %d\n", cpnum, MINVALIDPORT, query[i].varval, MAXVALIDPORT );
				}
			}
			customport++;
		}

		// Look for the starttime query string, set qstf to -1 if not present or invalid
		i = 0;
		uint64_t querystarttime = 9912;
		#if (TEXTMODE != 1)
		// qstf only used in javascript mode
		int8_t qstf = -1;
		#endif
		while (i < numqueries && strncmp("starttime",query[i].varname,9)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			if (query[i].varval >= 0)
			{
				querystarttime = (uint64_t)query[i].varval;
				#if (TEXTMODE != 1)
				// qstf only used in javascript mode
				qstf = 1; // valid querystarttime
				#endif
			}
		}

		// Look for the session query string, set qsf to -1 if not present or invalid
		// Session is process id related - this version is extracted from the querystring
		i = 0;
		uint64_t querysession = 9912;
		#if (TEXTMODE != 1)
		// qsf only used in javascript mode
		int8_t qsf = -1;
		#endif
		while (i < numqueries && strncmp("session",query[i].varname,7)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			if (query[i].varval >= 0)
			{
				querysession = (uint64_t)query[i].varval;
				#if (TEXTMODE != 1)
				// qsf only used in javascript mode
				qsf = 1; // valid querysession
				#endif
			}
		}

		// Look for the beginscan query string, return 0 if not present or incorrect value
		i = 0;
		int beginscan = 0;
		while (i < numqueries && strncmp("beginscan",query[i].varname,9)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			beginscan = (query[i].varval == MAGICBEGIN ) ? 1 : 0;
		}

		// Look for the fetch query string
		i = 0;
		int fetch = 0;
		while (i < numqueries && strncmp("fetch",query[i].varname,5)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			fetch = (query[i].varval >0) ? 1 : 0;
			#if (TEXTMODE != 1)
			if (1 == fetch && (int)(query[i].varval < 4096)) fetchnum = (int)query[i].varval;
			#endif
		}

		// Dump the variables resulting from the query-string parsing
		// Calculate and report time-difference
                time_t nowtimeref = time(NULL);
		if (nowtimeref < 0)
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: nowtimeref out of range before timedifference calculation, time(NULL) returned %d(%s)\n", errno, strerror(errno) );
		}

		#if (TEXTMODE != 1)
		// javascript mode only
                int64_t timedifference = ( (int64_t)(querystarttime & INT64_MAX) - (int64_t)(nowtimeref & INT64_MAX) );
		#endif

		#ifdef QUERYDEBUG
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: numqueries = %d\n", numqueries);
		#if (TEXTMODE != 1)
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: includeexisting = %d beginscan = %d fetch = %d fetchnum = %d\n", includeexisting, beginscan, fetch, fetchnum);
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: querysession = %"PRIu64" querystarttime = %"PRIu64" diff = %"PRId64"\n", querysession, querystarttime, timedifference );
		if (1 != qsf || 1 != qstf)
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: qsf = %d qstf = %d\n", qsf, qstf );
		}
		#else
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: includeexisting = %d beginscan = %d fetch = %d\n", includeexisting, beginscan, fetch);
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: session = %"PRIu64" starttime = %"PRIu64" and numports = %d\n", \
				(uint64_t)session, (uint64_t)starttime, numports);
		#endif
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: numcustomports = %d NUMUSERDEFPORTS = %d\n", numcustomports, NUMUSERDEFPORTS );
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: reconstituted query string = %s\n", reconquery );
		IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: portlist contents, numports = %d:\n", numports);
		for ( unsigned int j = 0 ; j < numports ; j++ )
		{
			IPSCAN_LOG (LOGPREFIX "ipscan: DEBUG INFO: port_num = %d, special = %d\n", portlist[j].port_num, portlist[j].special);
		}
		#endif

		//
		//
		//
		// NOW DETERMINE WHAT TO DO ......
		//
		//
		//

		#if (TEXTMODE == 1)

		char stimeresult[32]; // function calls for at least 26 characters
		char * stptr = NULL;

		// ----------------------------------------------------------------------
		//
		// Start of text-mode only cases
		//
		// ----------------------------------------------------------------------

		// *IF* we have everything we need to initiate the scan/results page then we
		// should have been passed (2+NUMUSERDEFPORTS) queries
		// i.e. includeexisting (either +1 or -1), termsaccepted and customports 0 thru n params

		if ( numqueries >= (NUMUSERDEFPORTS + 2) && (numcustomports == NUMUSERDEFPORTS) && (0 != includeexisting) && (1 == termsaccepted) )
		{
			// Take a note of the time we started running
			#if (1 <= IPSCAN_LOGVERBOSITY)
			time_t scanstart = starttime;
			#endif

			#ifdef CLIENTDEBUG
			#if (1 <= IPSCAN_LOGVERBOSITY)
        		report_useragent_strings(useragentvar, secchuavar, secchuaarchvar, secchuaplatvar);
			report_ipscan_versions(ipscan_main_ver(), ipscan_general_ver(), ipscan_tcp_ver(), ipscan_udp_ver(), ipscan_icmpv6_ver(), ipscan_db_ver(),\
				 ipscan_web_ver(), ipscan_h_ver(), ipscan_portlist_ver());
        		#endif
			IPSCAN_LOG( LOGPREFIX "ipscan: Remote host protected client address (/48): %x:%x:%x:: text-mode, initiate scan\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			//
			// Record TESTSTATE as RUNNING even though not necessary for text-mode
			//
                        const char unusedfield[] = "unused";
                        // Generate database entry for test state - indicate test running
                        rc = write_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session,\
                                         (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), IPSCAN_TESTSTATE_RUNNING_BIT, unusedfield);
                        if (rc != 0)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: write_db for IPSCAN_PROTO_TESTSTATE RUNNING text-mode returned non-zero: %d\n", rc);
                        }
			// Check we know about this client
                        int num_rows = count_rows_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() text-mode (after init) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                        }
                        else
                        {  
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() text-mode (after init) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                                #endif
                                #endif
                        }


			// Create the header
			HTML_HEADER();
			// Create main output
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<h3 style=\"color:blue\">IPv6 Port Scanner Version %s, results for host %s</h3>\n", IPSCAN_VER, remoteaddrstring);
			stptr = ctime_r(&starttime,stimeresult);
			if (NULL == stptr)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR - text-mode ctime_r() failed\n");
			}
			else
			{
				printf("<p>Scan beginning at: %s, expected to take up to %d seconds ...</p>\n", \
						stimeresult, (int)ESTIMATEDTIMETORUN );
			}

			// Log termsaccepted
			IPSCAN_LOG( LOGPREFIX "ipscan: protected client address (/48): %x:%x:%x:: beginning text-mode scan with termsaccepted = %d\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), termsaccepted );
			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: at time %"PRIu64", session %"PRIu64"\n", (uint64_t)starttime, (uint64_t)session);
			#endif

			// Only included if ping is compiled in ...
			#if (1 == IPSCAN_INCLUDE_PING)
			// Ping the remote host and store the result ...
			int pingresult = check_icmpv6_echoresponse(remoteaddrstring, (uint64_t)starttime, (uint64_t)session, &indirecthost[0] );

			// Ensure the indirecthost returned is valid
			// NOTE: this validation may require adjustment if the declaration of indirecthost changes
			int ih_adjusted = 0;
			indirecthost[INET6_ADDRSTRLEN] = 0;
			char indirecthost2[INET6_ADDRSTRLEN+1];
			for ( i = 0 ; i < INET6_ADDRSTRLEN ; i++ ) indirecthost2[i] = indirecthost[i] ;
			for ( i = 0 ; i < INET6_ADDRSTRLEN && indirecthost[i] > 0 ; i++ )
			{
				// Ensure only valid ASCII characters are included, but terminating '0' is retained
				// 0..9 are 48-57, : is 58, A-F are 65-70, a-f are 97-102
				if ( (indirecthost[i] > 0 && indirecthost[i] < 48) || (indirecthost[i] > 58 && indirecthost[i] < 65) \
					|| (indirecthost[i] > 70 && indirecthost[i] < 97) ||  indirecthost[i] > 102 )
				{
					indirecthost[i] = 32;
					ih_adjusted = 1;
				}
			}
			if (0 != ih_adjusted)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ICMPv6 indirecthost was updated, exiting with i = %d and \"%s\"\n", i, indirecthost);
				IPSCAN_LOG( LOGPREFIX "ipscan: indirecthost[0:7] %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", indirecthost2[0], indirecthost2[1], indirecthost2[2], indirecthost2[3], indirecthost2[4], indirecthost2[5], indirecthost2[6], indirecthost2[7] );
				IPSCAN_LOG( LOGPREFIX "ipscan: indirecthost[8:15] %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", indirecthost2[8], indirecthost2[9], indirecthost2[10], indirecthost2[11], indirecthost2[12], indirecthost2[13], indirecthost2[14], indirecthost2[15] );

			}

			int result = (pingresult >= IPSCAN_INDIRECT_RESPONSE) ? (pingresult - IPSCAN_INDIRECT_RESPONSE) : pingresult ;

			#if (0 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: ICMPv6 ping of client %s returned %d (%s), from host %s\n",remoteaddrstring, pingresult, resultsstruct[result].label, indirecthost);
			#else
			IPSCAN_LOG( LOGPREFIX "ipscan: ICMPv6 ping of protected client address (/48): %x:%x:%x::\n",\
				(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
				(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			portsstats[result]++ ;

			rc = write_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session,\
					(uint32_t)(0 + (IPSCAN_PROTO_ICMPV6 << IPSCAN_PROTO_SHIFT)), pingresult, indirecthost);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : write_db for ping result returned : %d\n", rc);
			}

			// Check we know about this client
                        num_rows = count_rows_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() text-mode (after ping) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                        }
                        else
                        {  
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() text-mode (after ping) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                                #endif
                                #endif
                        }
			printf("<p>ICMPv6 ECHO-Request:</p>\n");
			printf("<table>\n");
			printf("<tr style=\"text-align:left\">\n");
			if (pingresult >= IPSCAN_INDIRECT_RESPONSE)
			{
				printf("<td title=\"IPv6 ping\">ICMPv6 ECHO REQUEST returned : </td><td style=\"background-color:%s\">INDIRECT-%s (from %s)</td>\n",resultsstruct[result].colour,resultsstruct[result].label, indirecthost);
			}
			else
			{
				printf("<td title=\"IPv6 ping\">ICMPv6 ECHO REQUEST returned : </td><td style=\"background-color:%s\">%s</td>\n",resultsstruct[result].colour,resultsstruct[result].label);
			}
			printf("</tr>\n");
			printf("</table>\n");
			#endif

			#if (1 == IPSCAN_INCLUDE_UDP)
			// Log UDP start of scan
			#if (2 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d UDP ports on client : %s\n", numudpports, remoteaddrstring);
			#else
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d UDP ports on protected client address (/48): %x:%x:%x::\n",\
					numudpports, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			// Scan the UDP ports in parallel
			int remaining = numudpports;
			unsigned int porti = 0;
			int numchildren = 0;
			rc = 0;
			while (remaining > 0 || numchildren > 0)
			{
				while (remaining > 0)
				{
					if (numchildren < MAXUDPCHILDREN && remaining > 0)
					{
						unsigned int todo = (remaining > MAXUDPPORTSPERCHILD) ? MAXUDPPORTSPERCHILD : (unsigned int)remaining;
						#ifdef UDPPARLLDEBUG
						IPSCAN_LOG( LOGPREFIX "ipscan: check_udp_ports_parll(%s,%d,%d,host_msb,host_lsb,starttime,session,portlist)\n",remoteaddrstring,porti,todo);
						#endif
						rc |= check_udp_ports_parll(remoteaddrstring, porti, todo, remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session, &udpportlist[0]);
						porti += todo;
						numchildren ++;
						remaining = (int)(numudpports - porti);
					}
					if (numchildren == MAXUDPCHILDREN && remaining > 0)
					{
						int pid = wait(&childstatus);
						numchildren--;
						if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: UDP ongoing phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
					}
				}
				while (numchildren > 0)
				{
					int pid = wait(&childstatus);
					numchildren--;
					if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: UDP shutdown phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
				}
			}

			// Check we know about this client
                        num_rows = count_rows_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() text-mode (after UDP) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                        }
                        else
                        {  
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() text-mode (after UDP) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                                #endif
                                #endif
                        }

			printf("<p>Individual UDP port scan results:</p>\n");
			// Start of UDP port scan results table
			unsigned int position = 0;
			printf("<table border=\"1\">\n");
			for (uint16_t portindex= 0; portindex < NUMUDPPORTS ; portindex++)
			{
				uint16_t port = udpportlist[portindex].port_num;
				uint8_t special = udpportlist[portindex].special;
				last = (portindex == (NUMUDPPORTS-1)) ? 1 : 0 ;
				result = read_db_result(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session, (uint32_t)(port + ((special & (unsigned)IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_UDP << IPSCAN_PROTO_SHIFT) ));
				if ( PORTUNKNOWN == result )
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: text-mode read_db_result() returned UNKNOWN: UDP port scan results table\n" );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: for protected client address (/48): %x:%x:%x::\n",\
							(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
							(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: at starttime %"PRIu64", session %"PRIu64"\n", (uint64_t)starttime, (uint64_t)session);
				}

				#ifdef UDPDEBUG
				if (0 != special)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: UDP port %d:%d returned %d(%s)\n", port, special, result, resultsstruct[result].label);
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: UDP port %d returned %d(%s)\n", port, result, resultsstruct[result].label);
				}
				#endif

				#ifdef UDPDEBUGOPEN
				if (0 != special && UDPOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: UDP port %d:%d returned : UDPOPEN\n", port, special);
				}
				else if (0 == special && UDPOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: UDP port %d returned : UDPOPEN\n", port);
				}
				#endif

				// Start of a new row, so insert the appropriate tag if required
				if (position == 0) printf("<tr>");

				// Find a matching returnval, or else flag it as unknown
				i = 0 ;
				while (i < NUMRESULTTYPES && resultsstruct[i].returnval != result) i++;
				if (result == resultsstruct[i].returnval)
				{
					portsstats[result]++ ;
					if (0 != special)
					{
						printf("<td title=\"%s\" style=\"background-color:%s\">Port %d[%d] = %s</td>", udpportlist[portindex].port_desc, resultsstruct[i].colour, port, special, resultsstruct[i].label);
					}
					else
					{
						printf("<td title=\"%s\" style=\"background-color:%s\">Port %d = %s</td>", udpportlist[portindex].port_desc, resultsstruct[i].colour, port, resultsstruct[i].label);
					}
				}
				else
				{
					if (0 != special)
					{
						printf("<td title=\"%s\" style=\"background-color:white\">Port %d[%d] = BAD</td>", udpportlist[portindex].port_desc, port, special);
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: Unknown result for UDP port %d:%d is %d\n", port, special, result);
					}
					else
					{
						printf("<td title=\"%s\" style=\"background-color:white\">Port %d = BAD</td>", udpportlist[portindex].port_desc, port);
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: Unknown result for UDP port %d is %d\n", port, result);
					}
					portsstats[ PORTUNKNOWN ]++ ;
				}

				// Get ready for the next cell, add the end of row tag if required
				position++;
				if (position >= TXTMAXCOLS || last == 1) { printf("</tr>\n"); position=0; };

			}
			printf("</table>\n");
			#endif

			//
			// TCP scan is always included
			//
			#if (2 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d TCP ports on client : %s\n", numports, remoteaddrstring);
			#else
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d TCP ports on protected client address (/48): %x:%x:%x::\n",\
					numports, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif
			printf("<p>Individual TCP port scan results:</p>\n");

			// Scan the TCP ports in parallel
			remaining = (int)numports;
			porti = 0;
			numchildren = 0;
			rc = 0;
			while (remaining > 0 || numchildren > 0)
			{
				while (remaining > 0)
				{
					if (numchildren < MAXCHILDREN && remaining > 0)
					{
						unsigned int todo = (remaining > MAXPORTSPERCHILD) ? MAXPORTSPERCHILD : (unsigned int)remaining;
						#ifdef PARLLDEBUG
						IPSCAN_LOG( LOGPREFIX "ipscan: check_tcp_ports_parll(%s,%d,%d,host_msb,host_lsb,starttime,session,portlist)\n",remoteaddrstring,porti,todo);
						#endif
						rc |= check_tcp_ports_parll(remoteaddrstring, porti, todo, remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session, &portlist[0]);
						porti += todo;
						numchildren ++;
						remaining = (int)(numports - porti);
					}
					if (numchildren == MAXCHILDREN && remaining > 0)
					{
						int pid = wait(&childstatus);
						numchildren--;
						if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: ongoing phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
					}
				}
				while (numchildren > 0)
				{
					int pid = wait(&childstatus);
					numchildren--;
					if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: shutdown phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
				}
			}

			// Update test state to reflect complete, even though we don't use it for text-mode case
			result = IPSCAN_TESTSTATE_COMPLETE_BIT;
                        // Write the new value back to the database
                        rc = update_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session,\
                                 (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), result, unusedfield);
                        if (0 != rc)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: update_db for text-mode IPSCAN_TESTSTATE UPDATE returned non-zero: %d\n", rc);
                        }

			// Check we know about this client
                        num_rows = count_rows_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() text-mode (after TCP) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                        }
                        else
                        {  
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() text-mode (after TCP) returned rows: %d, %x:%x:%x:: starttime %"PRIu64", session %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), (uint64_t)starttime, (uint64_t)session );
                                #endif
                                #endif
                        }

			// Start of TCP port scan results table
 			printf("<table border=\"1\">\n");
			position = 0;
			for (uint16_t portindex= 0; portindex < numports ; portindex++)
			{
				uint16_t port = portlist[portindex].port_num;
				uint8_t special = portlist[portindex].special;
				last = (portindex == (numports-1)) ? 1 : 0 ;
				result = read_db_result(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session, (uint32_t)(port + ((special & (unsigned)IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT)+ (IPSCAN_PROTO_TCP << IPSCAN_PROTO_SHIFT)) );
				if ( PORTUNKNOWN == result )
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: text-mode read_db_result() returned UNKNOWN: TCP port scan results table\n" );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: for protected client address (/48): %x:%x:%x::\n",\
							(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
							(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: at starttime %"PRIu64", session %"PRIu64"\n",\
							(uint64_t)starttime, (uint64_t)session);
				}

				#ifdef RESULTSDEBUG
				if (0 != special)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: TCP port %d:%d returned %d(%s)\n", port, special, result, resultsstruct[result].label);
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: TCP port %d returned %d(%s)\n", port, result, resultsstruct[result].label);
				}
				#endif

				#ifdef TCPDEBUGOPEN
				if (0 != special && PORTOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: TCP port %d:%d returned : PORTOPEN\n", port, special);
				}
				else if (0 == special && PORTOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: TCP port %d returned : PORTOPEN\n", port);
				}
				#endif

				// Start of a new row, so insert the appropriate tag if required
				if (position == 0) printf("<tr>");

				// Find a matching returnval, or else flag it as unknown
				i = 0 ;
				while (i < NUMRESULTTYPES && resultsstruct[i].returnval != result) i++;
				if (result == resultsstruct[i].returnval)
				{
					portsstats[result]++ ;
					if (0 != special)
					{
						// False positive with LGTM - port_desc is predefined text with integer
						// port and special are restricted-range integers
						printf("<td title=\"%s\" style=\"background-color:%s\">Port %d[%d] = %s</td>", portlist[portindex].port_desc, resultsstruct[i].colour, port, special, resultsstruct[i].label);
					}
					else
					{
						// False positive with LGTM - port_desc is predefined text with integer
						// port is a restricted-range integer
						printf("<td title=\"%s\" style=\"background-color:%s\">Port %d = %s</td>", portlist[portindex].port_desc, resultsstruct[i].colour, port, resultsstruct[i].label);
					}

				}
				else
				{
					if (0 != special)
					{
						// False positive with LGTM - port_desc is predefined text with integer
						// port and special are restricted-range integers
						printf("<td title=\"%s\" style=\"background-color:white\">Port %d[%d] = BAD</td>", portlist[portindex].port_desc, port, special);
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: Unknown result for TCP port %d:%d is %d\n", port, special, result);
					}
					else
					{
						// False positive with LGTM - port_desc is predefined text with integer
						// port is a restricted-range integer
						printf("<td title=\"%s\" style=\"background-color:white\">Port %d = BAD</td>", portlist[portindex].port_desc, port);
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: Unknown result for TCP port %d is %d\n",port,result);
					}
					portsstats[ PORTUNKNOWN ]++ ;
				}

				// Get ready for the next cell, add the end of row tag if required
				position++;
				if (position >= TXTMAXCOLS || last == 1) { printf("</tr>\n"); position=0; };

			}
			printf("</table>\n");

			char fintimeresult[32]; // ctime requires 26 bytes
			char * ftptr = NULL;
			time_t nowtime = time(NULL);
			if (nowtime < 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time(NULL) returned bad value for nowtime %d (%s)\n", errno, strerror(errno));
			}
			else
			{
				ftptr = ctime_r(&nowtime, fintimeresult);
				if (NULL == ftptr)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: finish time ctime_r() returned NULL\n");
				}
				else
				{
					printf("<p>Scan of %d ports complete at: %s.</p>\n", numports, fintimeresult);
				}
			}

			// Create results key table
			create_results_key_table(remoteaddrstring, starttime);
			// Finish the output
			create_html_body_end();

			#if (1 <= IPSCAN_LOGVERBOSITY)
			time_t scancomplete = time(NULL);
			if (scancomplete < 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time(NULL) returned bad value for scancomplete %d (%s)\n", errno, strerror(errno));
			}
			IPSCAN_LOG( LOGPREFIX "ipscan: port scan and HTML document generation took %d seconds\n", (int)(scancomplete - scanstart));
			#endif

			// Log the summary of results internally
			i = 0;
			position = 0;
			while (i < NUMRESULTTYPES)
			{
				if (position == 0)
				{
					rc = snprintf(logbufferptr, logbuffersize, "Found %d %s",portsstats[i], resultsstruct[i].label );
				}
				else
				{
					rc = snprintf(logbufferptr, logbuffersize, ", %d %s", portsstats[i], resultsstruct[i].label);
				}

				if (rc < 0 || rc >= (int)logbuffersize)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: logbuffer write truncated, increase LOGENTRYLEN (currently %d) and recompile.\n", LOGENTRYLEN);
					break;
				}

				logbufferptr += rc ;
				logbuffersize -= (size_t)rc;
				position ++ ;
				if ( position >= LOGMAXCOLS || i == (NUMRESULTTYPES -1) )
				{
					#if (1 <= IPSCAN_LOGVERBOSITY)
					IPSCAN_LOG( LOGPREFIX "ipscan: %s\n", logbuffer);
					#endif
					logbufferptr = &logbuffer[0];
					logbuffersize = LOGENTRYLEN;
					position = 0;
				}
				i++ ;
			}

			// Delete our results now that we're done
			// have up to two attempts in case of deadlock
			rc = -1;
			for (i = 0 ; i<2 && rc != 0; i++)
			{
				rc = delete_from_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session, IPSCAN_DELETE_RESULTS_ONLY);
				if (0 != rc)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: text-only delete_from_db attempt %d return code was %d (expected 0)\n", (i+1), rc);
					// Wait to improve chances of missing a database deadlock
                                	sleep( IPSCAN_DELETE_WAIT_PERIOD );
				}
			}
                        if (0 != rc)
                        {
                        	IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: text-only delete_from_db loop exited after two attempts with non-zero rc: %d\n", rc);
                        }
			// Mark test as completed successfully
			result = IPSCAN_TESTSTATE_COMPLETE_BIT;
			rc = update_db(remotehost_msb, remotehost_lsb, (uint64_t)starttime, (uint64_t)session,\
                                (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), result, unusedfield);
                        if (0 != rc)
                        {
                        	IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: update_db for IPSCAN_TESTSTATE UPDATE returned non-zero: %d\n", rc);
                        }
			return(EXIT_SUCCESS);
		}

		// ----------------------------------------------------------------------
		//
		// End of text-mode only cases
		//
		// ----------------------------------------------------------------------

		#else

		// ----------------------------------------------------------------------
		//
		// Start of javascript-mode only cases
		//
		// ----------------------------------------------------------------------

		// *IF* we have everything we need to query the database ...
		// (1)querysession, (2)querystarttime, (3)fetch, (4)includeexisting and (5)termsaccepted. 
		// Could also have one or more customports. 
		// This statement handles cases where fetch indicates completion/failure.

		if ( numqueries >= 5 && qsf > 0 && qstf > 0 && beginscan == 0 && fetch == 1 \
				&& termsaccepted == 1 && includeexisting != 0 && IPSCAN_SUCCESSFUL_COMPLETION <= fetchnum)
		{
			#ifdef CLIENTDEBUG
			char fetchstring[IPSCAN_FETCHNUM_STRING_MAX+1];
			fetch_to_string(fetchnum, &fetchstring[0]);
			IPSCAN_LOG( LOGPREFIX "ipscan: Fetch indicated %s completion for (/48): %x:%x:%x:: at querystarttime %"PRIu64", querysession %"PRIu64"\n",\
				 fetchstring, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF), (unsigned int)((remotehost_msb>>16) & 0xFFFF),\
				 querystarttime, querysession );
			if (1 != qsf || 1 != qstf)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: DEBUG INFO: qsf = %d qstf = %d\n", qsf, qstf );
			}
			#endif

			// Calculate and report time-difference
                        nowtimeref = time(NULL);
                        timedifference = ( (int64_t)(querystarttime & INT64_MAX) - (int64_t)(nowtimeref & INT64_MAX) );

                        if (IPSCAN_DELETE_RESULTS_SHORT_OFFSET <= timedifference || timedifference <= (int64_t)(-1 * IPSCAN_DELETE_RESULTS_SHORT_OFFSET))
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: WARNING: host (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, fetchnum = %d, diff = %"PRId64"\n",\
                                        (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, fetchnum, timedifference );
                        }  
                        else
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: host (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, fetchnum = %d, diff = %"PRId64"\n",\
                                        (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, fetchnum, timedifference );
                        }

			// Check we know about this client
			int num_rows = count_rows_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
			if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() javascript (done/error) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
				// report error but allow execution to continue - return(EXIT_SUCCESS);
			}
			else
			{
				#ifdef CLIENTDEBUG
				#if (1 <= IPSCAN_LOGVERBOSITY)
				IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() javascript (done/error) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
				#endif
				#endif
			}
		
			// Fetch running state result from database so it can be updated
			int result = read_db_result(remotehost_msb, remotehost_lsb, querystarttime, querysession, (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT) ) );
			if ( PORTUNKNOWN == result )
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: read_db_result() javascript returned UNKNOWN: fetching running state\n" );
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: for protected client address (/48): %x:%x:%x::\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: at querystarttime %"PRIu64", querysession %"PRIu64"\n", querystarttime, querysession);
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
				}
				// Set state to running but flag that database returned something unexpected
				result = ( IPSCAN_TESTSTATE_RUNNING_BIT | IPSCAN_TESTSTATE_DATABASE_ERROR_BIT );
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: running state changed to indicate DATABASE error\n" );
				// Default for unused database entries
				const char unusedfield[] = "unused";
				rc = write_db(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
					 (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), result, unusedfield);
				if (rc != 0)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: write_db for IPSCAN_PROTO_TESTSTATE rewrite returned non-zero: %d\n", rc);
				}
			}

			if (IPSCAN_SUCCESSFUL_COMPLETION == fetchnum)
			{
				// Overwrite any other bits in this ONE case
				result = IPSCAN_TESTSTATE_COMPLETE_BIT;
			}
			else if (IPSCAN_HTTPTIMEOUT_COMPLETION == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_HTTPTIMEOUT_BIT; 
			}
			else if (IPSCAN_EVAL_ERROR == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_EVALERROR_BIT;
			}
			else if (IPSCAN_OTHER_ERROR == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_OTHERERROR_BIT; 
			}
			else if (IPSCAN_UNSUCCESSFUL_COMPLETION == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_BADCOMPLETE_BIT;
			}
			else if (IPSCAN_NAVIGATE_AWAY == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_NAVAWAY_BIT; 
			}
			else if (IPSCAN_BAD_JSON_ERROR == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_EVALERROR_BIT;
			}
			else if (IPSCAN_UNEXPECTED_CHANGE == fetchnum)
			{
				result |= IPSCAN_TESTSTATE_UNEXPCHANGE_BIT; 
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: INFO: fetch included unexpected value %d for protected client address (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
						fetchnum, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
						(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
				result |= IPSCAN_TESTSTATE_OTHERERROR_BIT; 
				IPSCAN_LOG( LOGPREFIX "ipscan: INFO: state changed to indicate OTHER error\n" );
			}
			// Default for unused database entries
			const char unusedfield[] = "unused";
			// Write the new value back to the database
			rc = update_db(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
				 (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), result, unusedfield);
			if (0 != rc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: update_db for IPSCAN_TESTSTATE UPDATE returned non-zero: %d\n", rc);
			}
			// Replacement for dummy output
			// Simplified header in which to wrap array of results
                        create_json_header();
                        // Dump the current port results for this client, querystarttime and querysession
                        rc = dump_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
                        if (rc != 0)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: dump_db return code was %d (expected 0)\n", rc);
                                return(EXIT_SUCCESS);
                        }
			// Replacement for dummy output
		}

		// *IF* we have everything we need to query the database ...
		// (1)querysession, (2)querystarttime, (3)fetch, (4)includeexisting and (5)termsaccepted. 
		// Could also have one or more customports.
		// Check that fetch number is less than a value which indicates completion/failure

		else if ( numqueries >= 5 && qsf > 0 && qstf > 0 && beginscan == 0 && fetch == 1 \
				&& termsaccepted == 1 && includeexisting != 0  && IPSCAN_SUCCESSFUL_COMPLETION > fetchnum)
		{
			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: Remote protected client address (/48):  %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, query database fetch\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
			if (1 != qsf || 1 != qstf)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: qsf = %d qstf = %d\n", qsf, qstf );
			}
			// Calculate and report time-difference
                        nowtimeref = time(NULL);
                        timedifference = ( (int64_t)(querystarttime & INT64_MAX) - (int64_t)(nowtimeref & INT64_MAX) );
                        if (IPSCAN_DELETE_RESULTS_SHORT_OFFSET <= timedifference || timedifference <= (int64_t)(-1 * IPSCAN_DELETE_RESULTS_SHORT_OFFSET))
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: WARNING: host (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, fetchnum = %d, diff = %"PRId64"\n",\
                                        (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, fetchnum, timedifference );
                        }  
                        else
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: host (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, fetchnum = %d, diff = %"PRId64"\n",\
                                        (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, fetchnum, timedifference );
                        }
			#endif

			// Check we know about this client
                        int num_rows = count_rows_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() javascript (query) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					 num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                // still return results return(EXIT_SUCCESS);
                        }
                        else
                        {
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() javascript (query) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                #endif
                                #endif
                        }
			// Simplified header in which to wrap array of results
			create_json_header();
			// Dump the current port results for this client, querystarttime and querysession
			rc = dump_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: dump_db return code was %d (expected 0)\n", rc);
				return(EXIT_SUCCESS);
			}
			// Check the current running state and if it's NOT running then update it to running
			// effectively clear timeout bit, etc. if we've had a successful fetch
			int result = read_db_result(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
                                        (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)) );
			if (IPSCAN_TESTSTATE_RUNNING_BIT != result)
			{
				#ifdef CLIENTDEBUG
				IPSCAN_LOG( LOGPREFIX "ipscan: javascript fetch attempting to rewrite result from %d to %d\n", result, IPSCAN_TESTSTATE_RUNNING_BIT );
				#endif
				result = IPSCAN_TESTSTATE_RUNNING_BIT;
                        	// Write the new value back to the database
				const char unusedfield[] = "unused";
                        	rc = update_db(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
                                 	(uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), result, unusedfield);
                        	if (0 != rc)
                        	{
                               		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: update_db for javascript-mode fetch IPSCAN_TESTSTATE UPDATE returned non-zero: %d\n", rc);
                        	}
			}
		}

		// *IF* we have everything we need to initiate the scan
		// (1)querysession, (2)querystarttime, (3)beginscan, (4)termsaccepted, (5)includeexisting
		// Could also have one or more customports.
		// Check that there is no fetch query.

		else if ( numqueries >= 5 && qsf > 0 && qstf > 0 && beginscan == 1 \
				&& termsaccepted == 1 && includeexisting != 0 && fetch == 0)
		{
			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: Remote protected client address (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, initiate scan\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
			if (1 != qsf || 1 != qstf)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: qsf = %d qstf = %d\n", qsf, qstf );
			}
			#if (1 <= IPSCAN_LOGVERBOSITY)
		        // Handle reporting of USER AGENT string
        		report_useragent_strings(useragentvar, secchuavar, secchuaarchvar, secchuaplatvar);
			report_ipscan_versions(ipscan_main_ver(), ipscan_general_ver(), ipscan_tcp_ver(), ipscan_udp_ver(), ipscan_icmpv6_ver(), ipscan_db_ver(),\
				 ipscan_web_ver(), ipscan_h_ver(), ipscan_portlist_ver());
        		#endif
			// Calculate and report time-difference
			nowtimeref = time(NULL);
			timedifference = ( (int64_t)(querystarttime & INT64_MAX) - (int64_t)(nowtimeref & INT64_MAX) );
			if (IPSCAN_DELETE_RESULTS_SHORT_OFFSET <= timedifference || timedifference <= (int64_t)(-1 * IPSCAN_DELETE_RESULTS_SHORT_OFFSET))
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: WARNING: host (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, time difference = %"PRId64"\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, timedifference );
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: INFO: host (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", javascript-mode, time difference = %"PRId64"\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, timedifference );
			}
			#endif

			// Default for unused database entries
			const char unusedfield[] = "unused";
			// Generate database entry for test state - indicate test running
			rc = write_db(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
					 (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), IPSCAN_TESTSTATE_RUNNING_BIT, unusedfield);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: write_db for IPSCAN_PROTO_TESTSTATE RUNNING returned non-zero: %d\n", rc);
			}

			time_t scanstart = time(NULL);
			if (scanstart < 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time(NULL) returned bad value for scanstart %d (%s)\n", errno, strerror(errno));
				return(EXIT_SUCCESS); // new
			}

			// Check we know about this client
                        int num_rows = count_rows_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() javascript (init) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                // don't stop execution - return(EXIT_SUCCESS);
                        }
                        else
                        {
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() javascript (init) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                #endif
                                #endif
                        }

			// Put out a dummy page to keep the webserver happy
			// Creating this page will take the entire duration of the scan ...
			HTML_HEADER();
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<p>Initiate scan.</p>\n");
			// Finish the output
			create_html_body_end();

			#ifdef CLIENTDEBUG
			#if (1 <= IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: write_db to set IPSCAN_PROTO_TESTSTATE RUNNING for protected client address (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
			if (1 != qsf || 1 != qstf)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: qsf = %d qstf = %d\n", qsf, qstf );
			}
			#endif
			#endif

			// Log terms accepted
			IPSCAN_LOG( LOGPREFIX "ipscan: protected client address (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", beginning with termsaccepted = %d\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, termsaccepted );
			#ifdef CLIENTDEBUG
			if (1 != qsf || 1 != qstf)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: qsf = %d qstf = %d\n", qsf, qstf );
			}
			#endif

			// Only include this section if ping is compiled in ...
			#if (IPSCAN_INCLUDE_PING == 1)
			int pingresult = check_icmpv6_echoresponse(remoteaddrstring, querystarttime, querysession, &indirecthost[0] );
			// Ensure the indirecthost returned is valid
                        // NOTE: this validation may require adjustment if the declaration of indirecthost changes
			int ih_adjusted = 0;
                        indirecthost[INET6_ADDRSTRLEN] = 0;
			char indirecthost2[INET6_ADDRSTRLEN+1];
			for ( i = 0 ; i < INET6_ADDRSTRLEN ; i++ ) indirecthost2[i] = indirecthost[i] ;
                        for ( i = 0 ; i < INET6_ADDRSTRLEN && indirecthost[i] > 0 ; i++ )
                        {
                                // Ensure only valid ASCII characters are included, but terminating '0' is retained
                                // 0..9 are 48-57, : is 58, A-F are 65-70, a-f are 97-102
                                if ( (indirecthost[i] > 0 && indirecthost[i] < 48) || (indirecthost[i] > 58 && indirecthost[i] < 65) \
                                        || (indirecthost[i] > 70 && indirecthost[i] < 97) ||  indirecthost[i] > 102 )
                                {
                                        indirecthost[i] = 32;
                                        ih_adjusted = 1;
                                }
                        }
                        if (0 != ih_adjusted)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ICMPv6 indirecthost was updated, exiting with i = %d and \"%s\"\n", i, indirecthost);
                                IPSCAN_LOG( LOGPREFIX "ipscan: indirecthost[0:7] %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", indirecthost2[0], indirecthost2[1], indirecthost2[2], indirecthost2[3], indirecthost2[4], indirecthost2[5], indirecthost2[6], indirecthost2[7] );
                                IPSCAN_LOG( LOGPREFIX "ipscan: indirecthost[8:15] %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", indirecthost2[8], indirecthost2[9], indirecthost2[10], indirecthost2[11], indirecthost2[12], indirecthost2[13], indirecthost2[14], indirecthost2[15] );

                        }

			int result = (pingresult >= IPSCAN_INDIRECT_RESPONSE) ? (pingresult - IPSCAN_INDIRECT_RESPONSE) : pingresult ;
			#if (0 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: ICMPv6 ping of client %s returned %d (%s), from host %s\n",remoteaddrstring,\
					pingresult, resultsstruct[result].label, indirecthost);
			#else
			IPSCAN_LOG( LOGPREFIX "ipscan: ICMPv6 ping of protected client address (/48): %x:%x:%x::\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif
			portsstats[result]++ ;
			rc = write_db(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
					(uint32_t)(0 + (IPSCAN_PROTO_ICMPV6 << IPSCAN_PROTO_SHIFT)), pingresult, indirecthost);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: write_db for ping result returned non-zero: %d\n", rc);
				create_html_body_end();
				return(EXIT_SUCCESS);
			}
			#endif

			// Check we know about this client
                        num_rows = count_rows_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() javascript (after ping) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                // return(EXIT_SUCCESS);
                        }
                        else
                        {
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() javascript (after ping) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                #endif
                                #endif
                        }
			// Only included if UDP is compiled in ...
			#if (IPSCAN_INCLUDE_UDP == 1)

			#if (2 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d UDP ports on client : %s\n", numudpports, remoteaddrstring);
			#else
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d UDP ports on protected client address (/48): %x:%x:%x::\n",\
					numudpports, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			// Scan the UDP ports in parallel
			int remaining = (int)numudpports;
			unsigned int porti = 0;
			int numchildren = 0;
			while (remaining > 0 || numchildren > 0)
			{
				while (remaining > 0)
				{
					if (numchildren < MAXUDPCHILDREN)
					{
						unsigned int todo = (remaining > MAXUDPPORTSPERCHILD) ? MAXUDPPORTSPERCHILD : (unsigned int)remaining;
						#ifdef UDPPARLLDEBUG
						IPSCAN_LOG( LOGPREFIX "ipscan: check_udp_ports_parll(%s,%d,%d,host_msb,host_lsb,querystarttime,querysession,portlist)\n",\
							remoteaddrstring,porti,todo);
						#endif
						rc = check_udp_ports_parll(remoteaddrstring, porti, todo, remotehost_msb, remotehost_lsb, querystarttime,\
							querysession, &udpportlist[0]);
						porti += todo;
						numchildren ++;
						remaining = (int)(numudpports - porti);
					}
					if (numchildren == MAXUDPCHILDREN)
					{
						int pid = wait(&childstatus);
						numchildren--;
						if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: UDP ongoing phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
					}
				}
				while (numchildren > 0)
				{
					int pid = wait(&childstatus);
					numchildren--;
					if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: UDP shutdown phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
				}
			}
			#endif

			// Check we know about this client
                        num_rows = count_rows_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() javascript (after UDP) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                // return(EXIT_SUCCESS);
                        }
                        else
                        {
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() javascript (after UDP) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                #endif
                                #endif
                        }

			#if (2 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d TCP ports on client : %s\n", numports, remoteaddrstring);
			#else
			IPSCAN_LOG( LOGPREFIX "ipscan: Beginning scan of %d TCP ports on protected client address (/48): %x:%x:%x::\n",\
					numports, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			// Scan the TCP ports in parallel
			remaining = (int)numports;
			porti = 0;
			numchildren = 0;
			while (remaining > 0 || numchildren > 0)
			{
				while (remaining > 0)
				{
					if (numchildren < MAXCHILDREN)
					{
						unsigned int todo = (remaining > MAXPORTSPERCHILD) ? MAXPORTSPERCHILD : (unsigned int)remaining;
						#ifdef PARLLDEBUG
						IPSCAN_LOG( LOGPREFIX "ipscan: check_tcp_ports_parll(%s,%d,%d,host_msb,host_lsb,querystarttime,querysession,portlist)\n",remoteaddrstring,porti,todo);
						#endif
						rc = check_tcp_ports_parll(remoteaddrstring, porti, todo, remotehost_msb, remotehost_lsb,\
								 querystarttime, querysession, &portlist[0]);
						porti += todo;
						numchildren ++;
						remaining = (int)(numports - porti);
					}
					if (numchildren == MAXCHILDREN)
					{
						int pid = wait(&childstatus);
						numchildren--;
						if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: ongoing phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
					}
				}
				while (numchildren > 0)
				{
					int pid = wait(&childstatus);
					numchildren--;
					if (childstatus != 0) IPSCAN_LOG( LOGPREFIX "ipscan: INFO: shutdown phase : PID=%d retired with status=%d, numchildren is now %d\n", pid, childstatus, numchildren );
				}
			}

			// Check we know about this client
                        num_rows = count_rows_db(remotehost_msb, remotehost_lsb, querystarttime, querysession);
                        if (num_rows <= 0 || num_rows > IPSCAN_DB_MAX_EXPECTED_ROWS)
                        {
                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: count_rows_db() javascript (after TCP) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                // return(EXIT_SUCCESS);
                        }
                        else
                        {
				#ifdef CLIENTDEBUG
                                #if (1 <= IPSCAN_LOGVERBOSITY)
                                IPSCAN_LOG( LOGPREFIX "ipscan: INFO: count_rows_db() javascript (after TCP) returned rows: %d, %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64"\n",\
					num_rows, (unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
                                        (unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession );
				if (1 != qsf || 1 != qstf)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: INFO: qsf = %d qstf = %d\n", qsf, qstf );
				}
                                #endif
                                #endif
                        }

			// Only included if UDP is compiled in ...
			#if (IPSCAN_INCLUDE_UDP == 1)
			// Generate the stats
			for (uint16_t portindex= 0; portindex < NUMUDPPORTS ; portindex++)
			{
				uint16_t port = udpportlist[portindex].port_num;
				uint8_t special = udpportlist[portindex].special;
				result = read_db_result(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
					(uint32_t)(port + ((special & (unsigned)IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_UDP << IPSCAN_PROTO_SHIFT) ) );
				if ( PORTUNKNOWN == result )
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: javascript read_db_result() returned UNKNOWN: UDP creating stats\n" );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: for protected client address (/48): %x:%x:%x::\n",\
						(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
						(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: at querystarttime %"PRIu64", querysession %"PRIu64"\n", querystarttime, querysession);
					if (1 != qsf || 1 != qstf)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
					}
				}

				// Find a matching returnval, or else flag it as unknown
				i = 0 ;
				while (i < NUMRESULTTYPES && resultsstruct[i].returnval != result) i++;
				if (result == resultsstruct[i].returnval)
				{
					portsstats[result]++ ;
				}
				else
				{
					if (0 != special)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: scan of UDP port %d:%d returned : %d\n", port, special, result);
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: scan of UDP port %d returned : %d\n", port, result);
					}
					portsstats[PORTUNKNOWN]++;
				}

				#ifdef UDPDEBUGOPEN
				if (0 != special && UDPOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: scan of UDP port %d:%d returned : UDPOPEN\n", port, special);
				}
				else if (0 == special && UDPOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: scan of UDP port %d returned : UDPOPEN\n", port);
				}
				#endif
			}
			#endif

			for (uint16_t portindex= 0; portindex < numports ; portindex++)
			{
				uint16_t port = portlist[portindex].port_num;
				uint8_t special = portlist[portindex].special;
				result = read_db_result(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
				 (uint32_t)(port + ((special & (unsigned)IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_TCP << IPSCAN_PROTO_SHIFT) ));
				if ( PORTUNKNOWN == result )
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: read_db_result() javascript returned UNKNOWN: TCP creating stats\n" );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: for protected client address (/48): %x:%x:%x::\n",\
							(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
							(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: at querystarttime %"PRIu64", querysession %"PRIu64"\n", querystarttime, querysession);
					if (1 != qsf || 1 != qstf)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
					}
				}

				// Find a matching returnval, or else flag it as unknown
				i = 0 ;
				while (i < NUMRESULTTYPES && resultsstruct[i].returnval != result) i++;
				if (result == resultsstruct[i].returnval)
				{
					portsstats[result]++ ;
				}
				else
				{
					if (0 != special)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: scan of TCP port %d:%d returned : %d\n", port, special, result);
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: INFO: scan of TCP port %d returned : %d\n", port, result);
					}
					portsstats[PORTUNKNOWN]++;
				}

				#ifdef TCPDEBUGOPEN
				if (0 != special && PORTOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: scan of TCP port %d:%d returned : PORTOPEN\n", port, special);
				}
				else if (0 == special && PORTOPEN == result)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: scan of TCP port %d returned : PORTOPEN\n", port);
				}
				#endif
			}

			#if (1 < IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: rmthost protected client address (/48): %x:%x:%x::\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			IPSCAN_LOG( LOGPREFIX "ipscan: querystarttime %"PRIu64" querysession %"PRIu64" numcustomports %d\n",\
					 querystarttime, querysession, numcustomports);
			#endif


			#if (1 <= IPSCAN_LOGVERBOSITY)
			time_t scancomplete = time(NULL);
			if (scancomplete < 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time(NULL) returned bad value for scancomplete %d (%s)\n", errno, strerror(errno));
			}
			IPSCAN_LOG( LOGPREFIX "ipscan: port scan and HTML document generation took %d seconds\n", (int)(scancomplete - scanstart));
			#endif

			// Log the summary of results internally
			i = 0;
			unsigned int position = 0;
			while (i < NUMRESULTTYPES)
			{
				if (position == 0)
				{
					rc = snprintf(logbufferptr, logbuffersize, "Found %u %s",portsstats[i], resultsstruct[i].label );
				}
				else
				{
					rc = snprintf(logbufferptr, logbuffersize, ", %u %s", portsstats[i], resultsstruct[i].label);
				}

				if (rc < 0 || rc >= (int)logbuffersize)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: logbuffer write truncated, increase LOGENTRYLEN (currently %d) and recompile.\n", LOGENTRYLEN);
					break;
				}

				logbufferptr += rc ;
				logbuffersize -= (size_t)rc;
				position ++ ;
				if ( position >= LOGMAXCOLS || i == (NUMRESULTTYPES -1) )
				{
					#if (1 <= IPSCAN_LOGVERBOSITY)
					IPSCAN_LOG( LOGPREFIX "ipscan: %s\n", logbuffer);
					#endif
					logbufferptr = &logbuffer[0];
					logbuffersize = LOGENTRYLEN;
					position = 0;
				}
				i++ ;
			}

			// Wait until the javascript client has flagged the test as complete or we've run out of time ...
			#ifdef CLIENTDEBUG
			char flags[IPSCAN_FLAGSBUFFER_SIZE+1];
			char * flagsrc = NULL;
			memset(flags, 0, sizeof(flags));
			#endif

			unsigned int client_finished = 0;
			time_t timeouttime = (scanstart + IPSCAN_DELETE_TIMEOUT);
			time_t deletenowtime = time(NULL);
			if (deletenowtime < 0)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time(NULL) returned bad value for first deletenowtime %d (%s)\n", errno, strerror(errno));
				deletenowtime = timeouttime;
			}

			//
			// wait for client to signal test complete or timeout
			//
			while (deletenowtime < timeouttime && client_finished == 0)
			{
				result = read_db_result(remotehost_msb, remotehost_lsb, querystarttime, querysession,\
						 (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT) ) );
				if ( PORTUNKNOWN == result )
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: read_db_result() javascript returned UNKNOWN: waiting for test end\n" );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: for protected client address (/48): %x:%x:%x::\n",\
							(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
							(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: at querystarttime %"PRIu64", querysession %"PRIu64"\n", querystarttime, querysession);
					if (1 != qsf || 1 != qstf)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: qsf = %d qstf = %d\n", qsf, qstf );
					}
					result = ( IPSCAN_TESTSTATE_RUNNING_BIT | IPSCAN_TESTSTATE_DATABASE_ERROR_BIT );
				}

				#ifdef CLIENTDEBUG
				flagsrc = state_to_string(result, &flags[0], (int)IPSCAN_FLAGSBUFFER_SIZE);

				#if (1 <= IPSCAN_LOGVERBOSITY)
				IPSCAN_LOG( LOGPREFIX "ipscan: waiting for IPSCAN_TESTSTATE_COMPLETE, IPSCAN_TESTSTATE value is currently: %d\n", result);
				#endif

				if (NULL != flagsrc)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: IPSCAN_TESTSTATE for protected client address (/48): %x:%x:%x:: querystarttime %"PRIu64", querysession %"PRIu64", '%s'\n",\
							(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
							(unsigned int)((remotehost_msb>>16) & 0xFFFF), querystarttime, querysession, flagsrc );
					if (1 != qsf || 1 != qstf)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: qsf = %d qstf = %d\n", qsf, qstf );
					}
				}
				#endif

				// Check whether the client has signalled the test is complete - various reasons
				if (IPSCAN_TESTSTATE_COMPLETE_BIT == (result & IPSCAN_TESTSTATE_COMPLETE_BIT))
				{
					client_finished = 1;
				}
				else
				{
					// Otherwise sleep before checking again
					sleep(IPSCAN_TESTSTATE_COMPLETE_SLEEP);
				}

				deletenowtime = time(NULL);
				if (deletenowtime < 0)
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: time(NULL) returned bad value for deletenowtime %d (%s)\n", errno, strerror(errno));
					deletenowtime = timeouttime;
				}
			} // end of wait for client to signal test complete or timeout

			#ifdef CLIENTDEBUG
			char cdstartres[32]; // ctime_r requires 26 chars
			char cdtimeoutres[32]; // ctime_r requires 26 chars
			char * cds_ptr = NULL;
			char * cdt_ptr = NULL;
			cds_ptr = ctime_r(&scanstart, cdstartres);
			cdt_ptr = ctime_r(&timeouttime, cdtimeoutres);

			if (1 == client_finished)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: Exited test-complete loop because client signalled.\n");

			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: Exited test-complete loop with no client response.\n");
				if (NULL != cds_ptr) IPSCAN_LOG( LOGPREFIX "ipscan: starttime   was : %d (%s)\n", (int)scanstart, cdstartres );
				if (NULL != cdt_ptr) IPSCAN_LOG( LOGPREFIX "ipscan: timeouttime was : %d (%s)\n", (int)timeouttime, cdtimeoutres);
			}
			#endif

			// If the client finished successfully then delete the results now, otherwise cleanup will delete them later
			if (1 == client_finished)
			{
				// Have two attempts in case of database deadlock
				rc = -1;
                        	for (i = 0 ; i<2 && rc != 0; i++)
                        	{
					// Wait so that errant/delayed XHR fetches are likely to subside and deadlocks less likely
					sleep( IPSCAN_DELETE_WAIT_PERIOD );

					// Delete the results
					//
					rc = delete_from_db(remotehost_msb, remotehost_lsb, querystarttime, querysession, IPSCAN_DELETE_RESULTS_ONLY);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: javascript delete_from_db attempt %d return code was %d (expected 0)\n", (i+1),  rc);
					}
				}
			}
		}

		// *IF* we have everything we need to create the standard HTML page
		// we should have been passed (2+NUMUSERDEFPORTS) queries
		// i.e. (+1)includeexisting (either +1 or -1) and (+2)termsaccepted and NUMUSERDEFPORTS

		else if (numqueries >= (NUMUSERDEFPORTS + 2) && numcustomports == NUMUSERDEFPORTS && includeexisting != 0 && beginscan == 0 \
				&& termsaccepted == 1 && fetch == 0)
		{
			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: Remote host protected client address (/48): %x:%x:%x:: javascript-mode, create start page\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			#if (1 <= IPSCAN_LOGVERBOSITY)
			IPSCAN_LOG( LOGPREFIX "ipscan: Creating the standard web results page start point\n");

			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: for protected client address (/48): %x:%x:%x::\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif
			#endif

			// Create the header and body
			#if (IPSCAN_INCLUDE_UDP == 1)
			// starttime is of type time_t in create_html_body() calls:
			create_html_header(numports, numudpports, reconquery);
			create_html_body(remoteaddrstring, starttime, numports, numudpports, portlist, udpportlist);
			#else
			// starttime is of type time_t in create_html_body() calls:
			create_html_header(numports, 0, reconquery);
			create_html_body(remoteaddrstring, starttime, numports, 0, portlist, udpportlist);
			#endif
			// Create the main html body
			create_html_body_end();
		}

		// ----------------------------------------------------------------------
		//
		// End of java-script only cases
		//
		// ----------------------------------------------------------------------

		#endif

		// ----------------------------------------------------------------------
		//
		// Cases common to both modes of operation
		//
		// ----------------------------------------------------------------------

		else if (termsaccepted == 0)
		{
			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: Remote host protected client address (/48): %x:%x:%x:: common-mode, terms not accepted\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			// Tell the user that they haven't accepted the terms and conditions
			HTML_HEADER();

			printf("<title>IPv6 Port Scanner - Terms and Conditions MUST be accepted BEFORE use</title>\n");
			printf("</head>\n");

			printf("<body>\n");
			printf("<h3 style=\"color:blue\">IPv6 Port Scanner Terms and Conditions MUST be accepted BEFORE use</h3>\n");
			printf("<p>IPscan testing cannot continue until the terms and conditions of use have been accepted. ");
			printf("You seem to have presented an incomplete or unexpected query string to IPscan.</p>\n");
			#if (IPSCAN_BAD_URL_HELP != 0)
			printf("<p>If you are trying to automate IPscan operation then please see the following ");
			printf("<a href=\"%s\">Scan Automation link</a> for commonly used examples. ", IPSCAN_BAD_URL_LINK);
			printf("Assuming that you accept the terms and conditions of use, then you might just be missing an \
			 \"&amp;termsaccepted=1\" term from the provided query-string.</p>\n");
			#endif
			#if (IPSCAN_TC_MISSING_LINK != 0)
			printf("<p style=\"font-weight:bold\">Please <a href=\"%s\">click here</a> to start again.</p>\n", IPSCAN_TC_MISSING_LINK_URL);
			#endif
			// Finish the output
			create_html_body_end();
			IPSCAN_LOG( LOGPREFIX "ipscan: Something untoward happened, numqueries = %d\n", numqueries);
			IPSCAN_LOG( LOGPREFIX "ipscan: includeexisting = %d, beginscan = %d, fetch = %d,\n", includeexisting, beginscan, fetch);
			IPSCAN_LOG( LOGPREFIX "ipscan: querysession = %"PRIu64" querystarttime = %"PRIu64" numports = %d and numcustomports = %d.\n", \
					querysession, querystarttime, numports, numcustomports);
			IPSCAN_LOG( LOGPREFIX "ipscan: protected client address (/48): %x:%x:%x:: beginning with termsaccepted = %d\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), termsaccepted );
		}

		else
		{
			#ifdef CLIENTDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: Remote host protected client address (/48): %x:%x:%x:: common-mode, final else - hack?\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF) );
			#endif

			// Dummy report - most likely to be triggered via a hackers attempt to pass unusual query parameters
			HTML_HEADER();
			printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
			printf("</head>\n");
			printf("<body>\n");
			printf("<p>Nothing useful to report.</p>\n");
			#if (IPSCAN_BAD_URL_HELP != 0)
			printf("<p>You seem to have presented an incomplete or unexpected query string to IPscan. ");
			printf("If you are trying to automate IPscan operation then please see the following ");
			printf("<a href=\"%s\">Scan Automation link.</a></p>\n", IPSCAN_BAD_URL_LINK);
			#endif
			// Finish the output
			create_html_body_end();
			// Log information relevant to the event
			IPSCAN_LOG( LOGPREFIX "ipscan: Something untoward happened, numqueries = %d\n", numqueries);
			IPSCAN_LOG( LOGPREFIX "ipscan: includeexisting = %d, beginscan = %d, fetch = %d,\n", includeexisting, beginscan, fetch);
			IPSCAN_LOG( LOGPREFIX "ipscan: querysession = %"PRIu64" querystarttime = %"PRIu64" numports = %d and numcustomports = %d.\n", \
					querysession, querystarttime, numports, numcustomports);
			IPSCAN_LOG( LOGPREFIX "ipscan: protected client address (/48): %x:%x:%x:: beginning with termsaccepted = %d\n",\
					(unsigned int)((remotehost_msb>>48) & 0xFFFF), (unsigned int)((remotehost_msb>>32) & 0xFFFF),\
					(unsigned int)((remotehost_msb>>16) & 0xFFFF), termsaccepted );
		}
	}

	#ifdef IPSCAN_NO_TIDY_UP_DB
	IPSCAN_LOG( LOGPREFIX "ipscan: WARNING: tidy_up_db() calls disabled\n");
	#else
	// Call tidy_up_db() to purge any expired results 
	rc = tidy_up_db(IPSCAN_DELETE_RESULTS_ONLY);
	if (0 != rc) IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: tidy_up_db(IPSCAN_DELETE_RESULTS_ONLY) returned %d\n", rc);
	rc = tidy_up_db(IPSCAN_DELETE_EVERYTHING);
	if (0 != rc) IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: tidy_up_db(IPSCAN_DELETE_EVERYTHING  ) returned %d\n", rc);
	#endif

	return(EXIT_SUCCESS);
}
