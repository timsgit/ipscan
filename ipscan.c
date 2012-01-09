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

// ipscan.c version
// 0.01 - first released version
// 0.02 - additional DEBUG added for MySQL investigation
// 0.03 - added syslog support
// 0.04 - improved HTML (transition to styles, general compliance)
// 0.05 - addition of ICMPv6 ECHO-REQUEST functionality
// 0.06 - removal of empty HTML paragraph
// 0.07 - further buffer overflow prevention measures

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
// toupper/tolower routines
#include <ctype.h>

// IPv6 address conversion
#include <arpa/inet.h>

// String comparison
#include <string.h>

// errors
#include <errno.h>

// Logging with syslog requires additional include
#if (LOGMODE == 1)
	#include <syslog.h>
#endif

//
// Prototype declarations
//

int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result , char *indirecthost);
int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session);

int check_tcp_port(char * hostname, uint16_t port);
int check_icmpv6_echoresponse(char * hostname, uint64_t starttime, uint64_t session, char * router);
void create_html_common_header(void);
void create_json_header(void);
void create_html_header(char * servername, uint64_t session, time_t timestamp, uint16_t numports, uint16_t *portlist, char * reconquery);
void create_html_body(char * hostname, uint64_t session, time_t timestamp, uint16_t numports, uint16_t *portlist);
void create_html_body_end(void);
void create_html_form(uint16_t numports, uint16_t *portlist);

// create_results_key_table is only referenced if creating the text-only version
#if (TEXTMODE == 1)
void create_results_key_table(char * hostname, time_t timestamp);
#endif

// summarise_db is only referenced if summary is enabled
#if (SUMMARYENABLE == 1)
int summarise_db(void);
#endif

//
// End of prototypes declarations
//

// structure holding the potential results table - entries MUST be in montonically increasing enumerated returnval order
struct rslt_struc resultsstruct[] =
{
	/* returnval,		connrc,	conn_errno		TEXT lbl			TEXT col	Description/User feedback	*/
	{ PORTOPEN, 		0, 		0,	 			"OPEN", 			"red",		"An IPv6 TCP connection was successfully established to this port. You should check that this is the expected outcome since an attacker may be able to compromise your machine by accessing this IPv6 address/port combination."},
	{ PORTABORT, 		-1, 	ECONNABORTED, 	"ABRT", 			"yellow",	"An abort indication was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTREFUSED, 		-1, 	ECONNREFUSED, 	"RFSD", 			"yellow",	"A refused indication (TCP RST/ACK or ICMPv6 type 1 code 4) was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTCRESET, 		-1, 	ECONNRESET, 	"CRST", 			"yellow",	"A connection reset request was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTNRESET, 		-1, 	ENETRESET, 		"NRST", 			"yellow",	"A network reset request was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTINPROGRESS, 	-1, 	EINPROGRESS, 	"STLTH", 			"green",	"No response was received from your machine in the allocated time period. This is the ideal response since no-one can ascertain your machines' presence at this IPv6 address/port combination."},
	{ PORTPROHIBITED, 	-1, 	EACCES, 		"PHBTD", 			"yellow",	"An administratively prohibited response (ICMPv6 type 1 code 1) was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTUNREACHABLE, 	-1, 	ENETUNREACH, 	"NUNRCH", 			"yellow",	"An unreachable response (ICMPv6 type 1 code 0) was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTNOROUTE, 		-1, 	EHOSTUNREACH, 	"HUNRCH", 			"yellow",	"A No route to host response (ICMPv6 type 1 code 3 or ICMPv6 type 3) was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTPKTTOOBIG, 	-1, 	EMSGSIZE, 		"TOOBIG", 			"yellow",	"A Packet too big response (ICMPv6 type 2) was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ PORTPARAMPROB, 	-1, 	EPROTO, 		"PRMPRB", 			"yellow",	"A Parameter problem response (ICMPv6 type 4) was received when attempting to open this port. Someone can ascertain that your machine is responding on this IPv6 address/port combination, but cannot establish a TCP connection."},
	{ ECHONOREPLY, 		-96, 	-96,	 		"ECHO NO REPLY",	"green",	"No ICMPv6 ECHO_REPLY packet was received in response to the ICMPv6 ECHO_REQUEST which was sent. This is the ideal response since no-one can ascertain your machines' presence at this IPv6 address."},
	{ ECHOREPLY, 		-97, 	-97,	 		"ECHO REPLY", 		"yellow",	"An ICMPv6 ECHO_REPLY packet was received in response to the ICMPv6 ECHO_REQUEST which was sent. Someone can ascertain that your machine is present on this IPv6 address."},
	/* Unexpected and unknown error response cases, do NOT change */
	{ PORTUNEXPECTED,	-98,	-98,			"UNXPCT",			"white",	"An unexpected response was received to the connect attempt."},
	{ PORTUNKNOWN, 		-99,	-99, 			"UNKWN", 			"white",	"An unknown error response was received, or the port is yet to be tested."},
	{ PORTINTERROR,		-100,	-100,			"INTERR",			"white",	"An internal error occurred."},
	/* End of list marker, do NOT change */
	{ PORTEOL,			-101,	-101,			"EOL",				"black",	"End of list marker."}
};

int main(void)
{

	#if (TEXTMODE != 1)
	// Currently unused, but referenced in javascript mode
	char serveraddrstring[INET6_ADDRSTRLEN] = "unknown";
	#else
	// last is only used in text-only mode
	int last = 0;
	#endif

	int result, pingresult;
	char remoteaddrstring[INET6_ADDRSTRLEN];
	char *remoteaddrvar;

	// Storage for indirecthost address, in case required
	char indirecthost[INET6_ADDRSTRLEN];

	unsigned int position = 0;

	// Default to testing
	int beginscan = 0;
	int fetch = 0;

	// the session starttime, used as an unique index for the database
	time_t   starttime;
	int64_t  querystarttime;

	uint16_t port;
	uint16_t portindex;

	// List of ports to be tested
	uint16_t portlist[MAXPORTS];

	// Ports to be tested
	uint16_t numports = 0;

	// "general purpose" variables, used as required
	int rc = 0;
	unsigned int i = 0;
	unsigned int shift = 0;
	unsigned int j = 0;

	// stats
	unsigned int portsstats[ NUMRESULTTYPES ];

	// Determine request method and query-string
	char requestmethod[MAXREQMETHODLEN];
	char thischar;
	char *reqmethodvar;
	char *querystringvar;
	char querystring[ (MAXQUERYSTRLEN + 1) ];

	// buffer for reconstituted querystring
	int reconquerysize = MAXQUERYSTRLEN;
	char reconquery[ (MAXQUERYSTRLEN + 1) ];
	char *reconptr = &reconquery[0];

	// buffer for logging entries
	int logbuffersize = LOGENTRYLEN;
	char logbuffer[ (LOGENTRYLEN + 1) ];
	char *logbufferptr = &logbuffer[0];

	// Structure to hold querystring variable names, their values and a validity indication
	typedef struct {
		char varname[MAXQUERYNAMELEN];
		int64_t varval;
		int valid;
	} queries;

	queries query[MAXQUERIES];
	unsigned int numqueries = 0;
	int64_t varval = 0;
	// value string - add two chars to cope with trailing \0
	char valstring[ (MAXQUERYVALLEN + 2) ];
	
	int64_t magic = 0;
	int includeexisting = 0;

	// IPv6 address related
	unsigned char remotehost[sizeof(struct in6_addr)];

	uint64_t value;
	uint64_t remotehost_msb = 0;
	uint64_t remotehost_lsb = 0;

	// If syslog is in use then open the log
	#if (LOGMODE == 1)
		openlog("ipscan", LOG_PID, LOG_LOCAL0);
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

	// Process id related - this version is extracted from the querystring
	int64_t querysession = 0;

	// Log the current time and "session" with which to initiate scan and fetch results
	starttime = time(0);
	uint64_t session = (uint64_t) getpid();

		// QUERY_STRING / REQUEST_METHOD
	// URL  of the form: ipv6.cgi?name1=value1&name2=value2
	// REQUEST_METHOD = GET
	// QUERY_STRING = name1=value1&name2=value2 
	reqmethodvar = getenv("REQUEST_METHOD");
	querystringvar = getenv("QUERY_STRING");

	// ensure length OK
	if (NULL == reqmethodvar)
	{
		#ifdef DEBUG
		IPSCAN_LOG( LOGPREFIX "Error in passing request-method from form to script.");
		#endif
	}
	else if ( strlen(reqmethodvar) > MAXREQMETHODLEN )
	{
		//IPSCAN_LOG( LOGPREFIX "Request-method environment string is longer than allocated buffer\n");
		//exit(CHECKTHELOGRC);
	}
	else if( sscanf(reqmethodvar,"%"TO_STR(MAXREQMETHODLEN)"s",requestmethod) != 1 )
	{
		#ifdef DEBUG
		IPSCAN_LOG( LOGPREFIX "Invalid request-method scan.");
		#endif
	}
	else
	{
		#ifdef DEBUG
		IPSCAN_LOG( LOGPREFIX "Request method is : %s\n", requestmethod);
		#endif

		// Force Uppercase to ease comparison
		for (i = 0; i < strlen(requestmethod); i++)
		{
			thischar=requestmethod[i];
			requestmethod[i]=toupper(thischar);
		}

		if (strncmp("GET", requestmethod, 3) == 0)
		{
			if(NULL == querystringvar)
			{
				IPSCAN_LOG( LOGPREFIX "Error in passing null query-string from form to script.\n");
			}
			else if ( strlen(querystringvar) > MAXQUERYSTRLEN)
			{
				IPSCAN_LOG( LOGPREFIX "Query-string environment string is longer than allocated buffer (%d)\n", MAXQUERYSTRLEN);
				exit(CHECKTHELOGRC);
			}
			else if( sscanf(querystringvar,"%"TO_STR(MAXQUERYSTRLEN)"s",querystring) != 1 )
			{
				#ifdef DEBUG
				// No query string will get reported here ....
				IPSCAN_LOG( LOGPREFIX "Invalid query-string sscanf.\n");
				#endif
			}
			else
			{
				#ifdef DEBUG
				IPSCAN_LOG( LOGPREFIX "Query-string name  : %s\n", querystring);
				#endif


				// Force lowercase to ease later comparison
				for (i = 0; i < strlen(querystring); i++)
				{
					thischar=querystring[i];
					querystring[i]=tolower(thischar);
				}

				// Split the query string into variable names and values
				int byte = 0;
				int finished = 0;
				while (byte < MAXQUERYSTRLEN && querystring[byte] >= 32 && finished == 0 && numqueries < MAXQUERIES)
				{
					int varnamenum = 0;
					query[numqueries].valid = 0;
					while ( querystring[byte] >= 32 && querystring[byte] != '='
						&& querystring[byte] != '&' && varnamenum<MAXQUERYNAMELEN && finished == 0)
					{
						query[numqueries].varname[varnamenum] = querystring[byte];
						varnamenum ++;
						byte ++;	
					}
					if (varnamenum >= MAXQUERYNAMELEN)
					{
						IPSCAN_LOG( LOGPREFIX "query parameter name string is too long : %s\n", querystring);
					}
					query[numqueries].varname[varnamenum]=0;
					finished = (querystring[byte] < 32 || byte >= MAXQUERYSTRLEN) ? 1 : 0;
					if (querystring[byte] == '=' && finished == 0)
					{
						byte++;
						int valbyte = 0;
						while ( querystring[byte] >= 32 && querystring[byte] != '='
                                && querystring[byte] != '&' && valbyte< MAXQUERYVALLEN && byte < MAXQUERYSTRLEN)
						{
							valstring[valbyte] = querystring[byte];
							byte++;
							valbyte++;
						}
						valstring[valbyte]=0;
						if (valbyte >= MAXQUERYVALLEN)
						{
							IPSCAN_LOG( LOGPREFIX "query parameter value string is too long for %s : %s\n", \
									query[numqueries].varname, querystring);
						}
						rc = sscanf(valstring,"%"SCNd64, &varval );
						if (rc == 1)
						{
							// Mark the entry as valid, increment the number of queries found
							query[numqueries].varval = varval;
							query[numqueries].valid = 1;
							#ifdef DEBUG
							IPSCAN_LOG( LOGPREFIX "Added a new query name: %s\n", query[numqueries].varname);
							IPSCAN_LOG( LOGPREFIX "with a value of       : %"PRId64"\n", query[numqueries].varval);
							#endif
							numqueries++;
						}
						else
						{
							#ifdef DEBUG
							IPSCAN_LOG( LOGPREFIX "Bad value assignment for %s, setting invalid.\n", query[numqueries].varname);
							#endif
							query[numqueries].valid = 0;
							numqueries++;
						}
					}
					// Move past the '&' sign
					while (querystring[byte] == '&' && querystring[byte] >= 32 && byte < MAXQUERYSTRLEN && finished == 0)
					{
						byte++;
					}
					finished = (querystring[byte] < 32 || byte >= MAXQUERYSTRLEN) ? 1 : 0;
				}
				#ifdef DEBUG
				IPSCAN_LOG( LOGPREFIX "Number of query pairs found is : %d\n", numqueries);
				#endif
			}
		}
		else if (strncmp("HEAD", requestmethod, 4) == 0)
		{
			// Create the header
			create_html_common_header();
			// Now finish the header
        		printf("<TITLE>IPv6 Universal TCP Port Scanner Version %s</TITLE>\n", IPSCAN_VER);
        		printf("</HEAD>\n");
		        printf("</HTML>\n");
			IPSCAN_LOG( LOGPREFIX "HEAD request method, sending headers only\n");
			exit(0);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "Unsupported request method: %s.\n", requestmethod);
			exit(CHECKTHELOGRC);
		}
	}

	// Determine the clients' address
	remoteaddrvar = getenv("REMOTE_ADDR");
	if(NULL == remoteaddrvar)
	{
		IPSCAN_LOG( LOGPREFIX "Error in passing remoteaddr data from form to script.\n");
	}
	else if (strlen(remoteaddrvar) > INET6_ADDRSTRLEN)
	{
		IPSCAN_LOG( LOGPREFIX "Host address length exceeds allocated buffer size (%d > %d)\n", strlen(remoteaddrvar), INET6_ADDRSTRLEN);
		exit(CHECKTHELOGRC);
	}
	else if( sscanf(remoteaddrvar,"%"TO_STR(INET6_ADDRSTRLEN)"s",remoteaddrstring) != 1 )
	{
		IPSCAN_LOG( LOGPREFIX "Invalid remoteaddr data.\n");
	}
	else
	{	
		// Determine the remote host address
		rc = inet_pton(AF_INET6, remoteaddrstring, remotehost);
		if (rc <= 0)
		{
			IPSCAN_LOG( LOGPREFIX "Unparseable IPv6 host address : %s\n", remoteaddrstring);
			exit(CHECKTHELOGRC);
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

			#ifdef DEBUG
			IPSCAN_LOG( LOGPREFIX "Remote host address MSB %"PRIx64" and LSB %"PRIx64"\n", remotehost_msb, remotehost_lsb);
			IPSCAN_LOG( LOGPREFIX "Remote host address MSB %"PRIu64" and LSB %"PRIu64"\n", remotehost_msb, remotehost_lsb);
			#endif

		}
	}


	// If query string is empty then we generate the introductory html/form for the client

	if (numqueries == 0)
	{
		// Create the header
		create_html_common_header();
		// Create the main html body
		create_html_form( DEFNUMPORTS , &portlist[0]);
		// Finish the html
		create_html_body_end();
	}

	// Following is a query, so determine the passed parameters and decide whether we
	// need to initiate a scan, return the current result set or a summary of scans

	else
	{

		// includeexisting should only be passed the values -1 or 1, set to 0 if not present
		// or an unsuitable value is passed.

		i = 0;
		while (i < numqueries && strncmp("includeexisting",query[i].varname,15)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			if ( abs((int) query[i].varval) == 1 )
			{
				includeexisting = query[i].varval;
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

		// Begin the reconstitution of the query string
		rc = snprintf(reconptr, reconquerysize, "includeexisting=%d", (int)includeexisting);
		if (rc > 16 && rc < 19)
		{
			reconptr += rc;
			reconquerysize -= rc;
			if (reconquerysize <= 0)
			{
				IPSCAN_LOG( LOGPREFIX "run out of room to reconstitute query, please increase MAXQUERYSTRLEN (%d) and recompile.\n", MAXQUERYSTRLEN);
				exit(CHECKTHELOGRC);
			}
		}
		else
		{
			#ifdef DEBUG
			IPSCAN_LOG( LOGPREFIX "attempt to reconstitute query returned an unexpected length (%d, expecting 17 or 18)\n", rc);
			#endif
			exit(CHECKTHELOGRC);
		}

		// Determine whether existing ports are to be included in the tested list or not:
		if (includeexisting == 1)
		{
			// custom ports will be appended to the default ports list
			numports = DEFNUMPORTS;
		}
		else
		{
			// default ports will be overwritten by any custom ports
			numports = 0;
		}

		#ifdef DEBUG
		IPSCAN_LOG( LOGPREFIX "numports is initially found to be %d\n", numports);
		#endif

		// Add in the custom ports if they're valid and NOT already present in the portlist ...

		int customport = 0;
		char cpnum[16];
		int cplen;

		while (customport < NUMUSERDEFPORTS)
		{
			cplen = snprintf(cpnum, 16, "customport%d", customport);
			i = 0;
			while (i < numqueries && strncmp(cpnum,query[i].varname,cplen)!= 0) i++;
			if (i < numqueries && query[i].valid == 1)
			{
				if (query[i].varval >=MINVALIDPORT && query[i].varval <= MAXVALIDPORT)
				{
					j = 0;
					while (j < numports && portlist[j] != query[i].varval) j++;
					if (j == numports)
					{
						portlist[numports] = query[i].varval;
						numports ++;
						rc = snprintf(reconptr, reconquerysize, "&customport%d=%d", customport, (int)query[i].varval);
						// &customport (11); cpnum (1-5) ; = (1) ; portnum (1-5)
						if (rc >= 14 && rc <= 22)
						{
							reconptr += rc;
							reconquerysize -= rc;
							if (reconquerysize <= 0)
							{
								IPSCAN_LOG( LOGPREFIX "run out of room to reconstitute query, please increase MAXQUERYSTRLEN (%d) and recompile.\n", MAXQUERYSTRLEN);
								exit(CHECKTHELOGRC);
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "customport%d reconstitution failed, due to unexpected size.\n", customport);
							exit(CHECKTHELOGRC);
						}
					}
				}
			}
			customport++;
		}

		// Look for Tims magic query string
		// Could be desirable to make things more secure by comparing remote hosts IPv6 address too ...
		i = 0;
		magic = -1;
		while (i < numqueries && strncmp("magic",query[i].varname,5)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			magic = query[i].varval;
		}

		// Look for the starttime query string, set it to -1 if not present or invalid
		i = 0;
		querystarttime = -1;
		while (i < numqueries && strncmp("starttime",query[i].varname,9)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			if (query[i].varval >= 0)
			{
				querystarttime = query[i].varval;
			}
		}

		// Look for the session query string, set it to -1 if not present or invalid
		i = 0;
		querysession = -1;
		while (i < numqueries && strncmp("session",query[i].varname,7)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			if (query[i].varval >= 0)
			{
				querysession = query[i].varval;
			}
		}

		// Look for the beginscan query string, return 0 if not present or incorrect value
		i = 0;
		beginscan = 0;
		while (i < numqueries && strncmp("beginscan",query[i].varname,9)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			beginscan = (query[i].varval == MAGICBEGIN ) ? 1 : 0;
		}

		// Look for the fetch query string
		i = 0;
		fetch = 0;
		while (i < numqueries && strncmp("fetch",query[i].varname,5)!= 0) i++;
		if (i < numqueries && query[i].valid == 1)
		{
			fetch = (query[i].varval >0) ? 1 : 0;
		}


		#ifdef DEBUG
			IPSCAN_LOG( LOGPREFIX "DEBUG info: numqueries = %d,\n", numqueries);
			IPSCAN_LOG( LOGPREFIX "DEBUG info: includeexisting = %d, beginscan = %d, fetch = %d,\n", includeexisting, beginscan, fetch);
			IPSCAN_LOG( LOGPREFIX "DEBUG info: session = %"PRIu64" starttime = %"PRIu64" and numports = %d.\n", \
					session, (uint64_t)starttime, numports);
		#endif

		//
		//
		//
		// NOW DETERMINE WHAT TO DO ......
		//
		//
		//


		//
		// NON-Javascript mode of operation (text browser compatible)
		//
		#if (TEXTMODE == 1)
		// *IF* we have everything we need to initiate the scan/results page then we
		// should have been passed (1+NUMUSERDEFPORTS) queries
		// i.e. includeexisting (either +1 or -1) and customports 0 thru n params

		if ( numqueries >= (NUMUSERDEFPORTS + 1) && includeexisting != 0 )
		{

			// Take current time/PID for database logging purposes
			starttime = time(0);
			session = (uint64_t) getpid();

			// Create the header
			create_html_common_header();
			// Create main output
			printf("<TITLE>IPv6 Universal TCP Port Scanner Version %s</TITLE>\n", IPSCAN_VER);
			printf("</HEAD>\n");
			printf("<BODY>\n");
			printf("<H3 style=\"color:red\">IPv6 Universal TCP Port Scanner by Tim Chappell</H3>\n");
			printf("<P>Results for host : %s</P>\n\n", remoteaddrstring);
			IPSCAN_LOG( LOGPREFIX "Beginning scan of %d TCP ports on client : %s\n", numports, remoteaddrstring);
			printf("<P>Scan beginning at: %s, expected to take up to %d seconds ...</P>\n", \
					asctime(localtime(&starttime)), (numports * TIMEOUTSECS));

			// Ping the remote host and store the result ...
			pingresult = check_icmpv6_echoresponse(remoteaddrstring, starttime, session, indirecthost);
			result = (pingresult >= IPSCAN_INDIRECT_RESPONSE) ? (pingresult - IPSCAN_INDIRECT_RESPONSE) : pingresult ;

			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "INFO: ICMPv6 ping of %s returned %d, indirect host %s\n",remoteaddrstring, pingresult, indirecthost);
			#endif

			portsstats[result]++ ;

			rc = write_db(remotehost_msb, remotehost_lsb, (uint64_t)querystarttime, (uint64_t)querysession, (0 + IPSCAN_PROTO_ICMPV6), pingresult, indirecthost);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "WARNING : write_db for ping result returned : %d\n", rc);
			}

			printf("<TABLE border=\"1\">\n");
			printf("<TR style=\"text-align:left\">\n");
			if (pingresult >= IPSCAN_INDIRECT_RESPONSE)
			{
				printf("<TD>ICMPv6 ECHO REQUEST returned : </TD><TD style=\"background-color:%s\">INDIRECT-%s (from %s)</TD>\n",resultsstruct[result].colour,resultsstruct[result].label, indirecthost);
			}
			else
			{
				printf("<TD>ICMPv6 ECHO REQUEST returned : </TD><TD style=\"background-color:%s\">%s</TD>\n",resultsstruct[result].colour,resultsstruct[result].label);
			}
			printf("</TR>\n");
			printf("</TABLE>\n");
			printf("<P>Individual TCP port scan results:</P>\n");

			// Start of table
			printf("<TABLE border=\"1\">\n");
			for (portindex= 0; portindex < numports ; portindex++)
			{
				port = portlist[portindex];
				last = (portindex == (numports-1)) ? 1 : 0 ;
				result = check_tcp_port(remoteaddrstring, port);

				#ifdef DEBUG
				IPSCAN_LOG( LOGPREFIX "INFO: port %d returned %d(%s)\n",port,result,resultsstruct[result].label);
				#endif

				rc = write_db(remotehost_msb, remotehost_lsb, starttime, session, (port + IPSCAN_PROTO_TCP), result, "unused" );
				if (rc != 0)
				{
					IPSCAN_LOG( LOGPREFIX "WARNING : write_db returned %d\n", rc);
				}

				// Start of a new row, so insert the appropriate tag if required
				if (position ==0) printf("<TR>");

				// Find a matching returnval, or else flag it as unknown
				i = 0 ;
				while (i < NUMRESULTTYPES && resultsstruct[i].returnval != result) i++;
				if (result == resultsstruct[i].returnval)
				{
					portsstats[result]++ ;
					printf("<TD style=\"background-color:%s\">Port %d = %s</TD>", resultsstruct[i].colour, port, resultsstruct[i].label);
				}
				else
				{
					printf("<TD style=\"background-color:white\">Port %d = BAD</TD>",port);
					IPSCAN_LOG( LOGPREFIX "WARNING: Unknown result for port %d is %d\n",port,result);
					portsstats[ PORTUNKNOWN ]++ ;
				}

				// Get ready for the next cell, add the end of row tag if required
				position++;
				if (position >= TXTMAXCOLS || last == 1) { printf("</TR>\n"); position=0; };

			}
			printf("</TABLE>\n");

			starttime = time(0);
			printf("<P>Scan of %d ports complete at: %s.</P>\n", numports, asctime(localtime(&starttime)));

			// Create results key table
			create_results_key_table(remoteaddrstring, starttime);
			// Finish the output
			create_html_body_end();

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

				if (rc < 0 || rc >= logbuffersize)
				{
					IPSCAN_LOG( LOGPREFIX "logbuffer write truncated, increase LOGENTRYLEN (currently %d) and recompile.\n", LOGENTRYLEN);
					exit(CHECKTHELOGRC);
				}

				logbufferptr += rc ;
				logbuffersize -= rc;
				position ++ ;
				if ( position >= LOGMAXCOLS || i == (NUMRESULTTYPES -1) )
				{
					IPSCAN_LOG( LOGPREFIX "%s\n", logbuffer);
					logbufferptr = &logbuffer[0];
					logbuffersize = LOGENTRYLEN;
					position = 0;
				}
				i++ ;
			}

		}
		#else

		// *IF* we have everything we need to query the database ...
		// session, starttime, fetch and includeexisting
		// was numqueries >= 4, without includeexisting check - but javascript updateurl always minimally includes includeexisting

		if ( numqueries >= 4 && querysession >= 0 && querystarttime >= 0 && beginscan == 0 && fetch == 1 && includeexisting != 0)
		{
			// Simplified header in which to wrap array of results
			create_json_header();
			// Dump the current port results for this client, starttime and session
			rc = dump_db(remotehost_msb, remotehost_lsb, (uint64_t)querystarttime, (uint64_t)querysession);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "dump_db rc was %d\n", rc);
				exit(CHECKTHELOGRC);
			}
		}


		// *IF* we have everything we need to initiate the scan
		// session, starttime, beginscan, includeexisting and userdefined ports [NOTE: no fetch]

		else if ( numqueries >= 4 && querysession >= 0 && querystarttime >= 0 && beginscan == 1 && fetch == 0)
		{

			IPSCAN_LOG( LOGPREFIX "Beginning scan of %d TCP ports on client : %s\n", numports, remoteaddrstring);
			// Put out a dummy page to keep the webserver happy
			// Creating this page will take the entire duration of the scan ...
			create_html_common_header();
			printf("<TITLE>IPv6 Universal TCP Port Scanner Version %s</TITLE>\n", IPSCAN_VER);
			printf("</HEAD>\n");
			printf("<BODY>\n");

			pingresult = check_icmpv6_echoresponse(remoteaddrstring, querystarttime, querysession, indirecthost);
			result = (pingresult >= IPSCAN_INDIRECT_RESPONSE) ? (pingresult - IPSCAN_INDIRECT_RESPONSE) : pingresult ;
			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "INFO: ICMPv6 ping of %s returned %d, indirect host %s\n",remoteaddrstring, pingresult, indirecthost);
			#endif
			portsstats[result]++ ;
			rc = write_db(remotehost_msb, remotehost_lsb, (uint64_t)querystarttime, (uint64_t)querysession, (0 + IPSCAN_PROTO_ICMPV6), pingresult, indirecthost);
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "write_db for ping result returned : %d\n", rc);
				create_html_body_end();
				exit(CHECKTHELOGRC);
			}

			for (portindex= 0; portindex < numports ; portindex++)
			{
				port = portlist[portindex];
				result = check_tcp_port(remoteaddrstring, port);

				// Find a matching returnval, or else flag it as unknown
				i = 0 ;
				while (i < NUMRESULTTYPES && resultsstruct[i].returnval != result) i++;
				if (result == resultsstruct[i].returnval)
				{
					portsstats[result]++ ;
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "WARNING scan of port %d returned : %d\n", port, result);
					portsstats[PORTUNKNOWN]++;
				}

				//
				// Put result into database:
				//
				rc = write_db(remotehost_msb, remotehost_lsb, (uint64_t)querystarttime, (uint64_t)querysession, (port + IPSCAN_PROTO_TCP), result, "unused");
				if (rc != 0)
				{
					IPSCAN_LOG( LOGPREFIX "write_db inside scan routine returned : %d\n", rc);
					create_html_body_end();
					exit(CHECKTHELOGRC);
				}
			}

			#ifdef DEBUG
			IPSCAN_LOG( LOGPREFIX "rmthost        was : %"PRIx64":%"PRIx64"\n", remotehost_msb, remotehost_lsb);
			IPSCAN_LOG( LOGPREFIX "querystarttime was : %"PRId64"\n", querystarttime);
			IPSCAN_LOG( LOGPREFIX "querysession   was : %"PRId64"\n", querysession);
			#endif


			// Finish the output
			create_html_body_end();

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

				if (rc < 0 || rc >= logbuffersize)
				{
					IPSCAN_LOG( LOGPREFIX "logbuffer write truncated, increase LOGENTRYLEN (currently %d) and recompile.\n", LOGENTRYLEN);
					exit(CHECKTHELOGRC);
				}

				logbufferptr += rc ;
				logbuffersize -= rc;
				position ++ ;
				if ( position >= LOGMAXCOLS || i == (NUMRESULTTYPES -1) )
				{
					IPSCAN_LOG( LOGPREFIX "%s\n", logbuffer);
					logbufferptr = &logbuffer[0];
					logbuffersize = LOGENTRYLEN;
					position = 0;
				}
				i++ ;
			}
		}

		// *IF* we have everything we need to initiate create the standard results page
		// should have been passed (1+NUMUSERDEFPORTS) queries
		// i.e. includeexisting (either +1 or -1) and customports 0 thru n params

		else if (numqueries >= (NUMUSERDEFPORTS + 1) && includeexisting != 0 && beginscan == 0 && fetch == 0)
		{
			IPSCAN_LOG( LOGPREFIX "Creating the standard web results page start point\n");
			starttime = time(0);
			session = (uint64_t) getpid();
			// Create the header
			create_html_header(serveraddrstring, session, starttime, numports, &portlist[0], reconquery);
			// Create the main html body
			create_html_body(remoteaddrstring, session, starttime, numports, &portlist[0]);
			// Finish the html
			create_html_body_end();
		}

		#endif

		//
		// Cases common to both modes of operation
		//

		#if (SUMMARYENABLE == 1)
		// Generate a summary of scans - limited to IPv6 addresses and time/date
		else if (numqueries == 1 && magic == MAGICSUMMARY )
		{
			create_html_common_header();
			printf("<TITLE>IPv6 Universal TCP Port Scanner Version %s</TITLE>\n", IPSCAN_VER);
			printf("</HEAD>\n");
			printf("<BODY>\n");
			printf("<H3 style=\"color:red\">IPv6 Universal TCP Port Scanner by Tim Chappell</H3>\n");
			printf("<P>Summary of Scans:</P>\n");
			// Output the scan summary
			rc = summarise_db();
			// Finish the output
			create_html_body_end();
			IPSCAN_LOG( LOGPREFIX "summarise_db: provided the requested summary, exited with rc=%d\n", rc);
		}
		#endif

		else
		{
			// Dummy report - most likely to be triggered via a hackers attempt to pass unusual query parameters
			create_html_common_header();
			printf("<TITLE>IPv6 Universal TCP Port Scanner Version %s</TITLE>\n", IPSCAN_VER);
			printf("</HEAD>\n");
			printf("<BODY>\n");
			printf("<P>Nothing to report.</P>\n");
			// Finish the output
			create_html_body_end();
			IPSCAN_LOG( LOGPREFIX "Something untoward happened, numqueries = %d, magic = %"PRId64"\n", numqueries, magic);
			IPSCAN_LOG( LOGPREFIX "includeexisting = %d, beginscan = %d, fetch = %d,\n", includeexisting, beginscan, fetch);
			IPSCAN_LOG( LOGPREFIX "querysession = %"PRId64" querystarttime = %"PRId64" and numports = %d.\n", \
					querysession, querystarttime, numports);
		}
	}
	exit(0);
}
