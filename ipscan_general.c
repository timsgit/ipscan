//    IPscan - an HTTP-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2021 Tim Chappell.
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

// ipscan_general.c version
// 0.01 - first released version
// 0.02 - update copyright dates
// 0.03 - slight logic change
// 0.04 - update copyright dates
// 0.05 - add proto_to_string()
// 0.06 - add fetch_to_string()
// 0.07 - add state_to_string()
// 0.08 - add result_to_string()
// 0.09 - update copyright dates
// 0.10 - update copyright year

#include "ipscan.h"
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

// Others that FreeBSD highlighted
#include <netinet/in.h>

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
// -----------------------------------------------------------------------------
//
uint64_t get_session(void)
{
	uint64_t sessionnum = 0;
	uint64_t fetchedsession = 0;
	FILE *fp;
	fp = fopen("/dev/urandom", "r");

	if (NULL == fp)
	{
		sessionnum = (uint64_t)getpid();
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : Cannot open /dev/urandom, %d (%s), defaulting session to getpid() = %"PRIu64"\n", errno, strerror(errno), sessionnum);
	}
	else
	{
		size_t numitems = fread( &fetchedsession, sizeof(fetchedsession), 1, fp);
		fclose(fp);
		if (1 == numitems)
		{
			// Clear the MSB of the random session ID so that we're sure it will fit
			// into an int64_t which the QUERY_STRING parser assumes
			sessionnum = fetchedsession & ( ((uint64_t)~0) >> 1);

			#ifdef QUERYDEBUG
			IPSCAN_LOG( LOGPREFIX "ipscan: Session number modification check, before = %"PRIu64" after = %"PRIu64"\n", fetchedsession, sessionnum);
			#endif
		}
		else
		{
			sessionnum = (uint64_t)getpid();
			IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : Cannot read /dev/urandom, defaulting session to getpid() = %"PRIu64"\n", sessionnum);
		}
	}
	return (sessionnum);
}

//
// -----------------------------------------------------------------------------
//
void proto_to_string(int proto, char * retstring)
{
	int rc = 0;
	switch (proto)
	{
	case IPSCAN_PROTO_TCP:
		rc = snprintf(retstring, IPSCAN_PROTO_STRING_MAX, "%s", "TCPv6");
		break;

	case IPSCAN_PROTO_UDP:
		rc = snprintf(retstring, IPSCAN_PROTO_STRING_MAX, "%s", "UDPv6");
		break;

	case IPSCAN_PROTO_ICMPV6:
		rc = snprintf(retstring, IPSCAN_PROTO_STRING_MAX, "%s", "ICMPv6");
		break;

	case IPSCAN_PROTO_TESTSTATE:
		rc = snprintf(retstring, IPSCAN_PROTO_STRING_MAX, "%s", "TESTSTATE");
		break;

	default:
		rc = snprintf(retstring, IPSCAN_PROTO_STRING_MAX, "%s", "UNDEFINED");
		break;

	}
	// Report error - does IPSCAN_PROTO_STRING_MAX need increasing?
	if (rc < 0 || rc >= IPSCAN_PROTO_STRING_MAX)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : Cannot fit protocol string into buffer, returned %d\n", rc);
	}
	return;
}

//
// -----------------------------------------------------------------------------
//
void fetch_to_string(int fetchnum, char * retstring)
{
	int rc;
	if (IPSCAN_SUCCESSFUL_COMPLETION == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "SUCCESSFUL");
	}
	else if (IPSCAN_HTTPTIMEOUT_COMPLETION == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "HTTP-TIMEOUT");
	}
	else if (IPSCAN_UNSUCCESSFUL_COMPLETION == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "UNSUCCESSFUL");
	}
	else if (IPSCAN_EVAL_ERROR == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "EVAL ERROR");
	}
	else if (IPSCAN_OTHER_ERROR == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "OTHER ERROR");
	}
	else if (IPSCAN_NAVIGATE_AWAY == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "NAVIGATEAWAY");
	}
	else if (IPSCAN_UNEXPECTED_CHANGE == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "UNEXP CHANGE");
	}  
	else
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s:%d", "UNKNOWN", fetchnum);
	}
	// Report error - does IPSCAN_FETCHNUM_STRING_MAX need increasing?
	if (rc < 0 || rc >= IPSCAN_FETCHNUM_STRING_MAX)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : Cannot fit fetchnum string into buffer, returned %d\n", rc);
	}

	return;
}


//
// -----------------------------------------------------------------------------
//
char * state_to_string(int statenum, char * retstringptr, int retstringfree)
{
	if (0 >= retstringfree) return (char *)NULL;
	char * retstringptrstart = retstringptr;
	int rc = 0;
	rc = snprintf(retstringptr, retstringfree, "%s", "flags: ");
	if (rc < 0 || rc >= retstringfree) return (char *)NULL;
	retstringptr += rc;
	retstringfree -= rc;

	if (0 != (statenum & PORTUNKNOWN))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "UNKNOWN, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_RUNNING_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "RUNNING, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_COMPLETE_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "COMPLETE, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_HTTPTIMEOUT_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "TIMEOUT, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_EVALERROR_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "EVALERROR, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_OTHERERROR_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "OTHERERROR, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_NAVAWAY_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "NAVAWAY, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_UNEXPCHANGE_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "UNEXPECTED, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_BADCOMPLETE_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "BADCOMPLETE, ");
		if (rc < 0 || rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= rc;
	}
	rc = snprintf(retstringptr, retstringfree, "%s", "<EOL>\n\0");
	if (rc < 0 || rc >= retstringfree) return (char *)NULL;
	retstringptr += rc;
	retstringfree -= rc;
	if (0 > retstringfree) return (char *)NULL;
	return retstringptrstart;
}


//
// -----------------------------------------------------------------------------
//
void result_to_string(int result, char * retstring)
{
	int rc;

	if (PORTOPEN == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "OPEN");
	}
	else if (PORTABORT == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "ABORT");
	}
	else if (PORTREFUSED == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "REFUSED");
	}
	else if (PORTCRESET == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "CRESET");
	}
	else if (PORTNRESET == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "NRESET");
	}
	else if (PORTINPROGRESS == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "IN-PROGRESS");
	}
	else if (PORTPROHIBITED == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "PROHIBITED");
	}
	else if (PORTUNREACHABLE == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "UNREACHABLE");
	}
	else if (PORTNOROUTE == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "NO ROUTE");
	}
	else if (PORTPKTTOOBIG == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "PKT TOO BIG");
	}
	else if (PORTPARAMPROB == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "PARAM PROBLEM");
	}
	else if (ECHONOREPLY == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "ECHO NO-REPLY");
	}
	else if (ECHOREPLY == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "ECHO REPLY");
	}
	else if (UDPOPEN == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "UDP OPEN");
	}
	else if (UDPSTEALTH == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "UDP STEALTH");
	}
	else if (PORTUNEXPECTED == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "UNEXPECTED");
	}
	else if (PORTUNKNOWN == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "UNKNOWN");
	}
	else if (PORTINTERROR == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "INTERNAL ERROR");
	}
	else if (PORTEOL == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s", "<EOL>");
	}
	else
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s:%d", "<MISSING>", result);
	}
	// Report error - does IPSCAN_RESULT_STRING_MAX need increasing?
	if (rc < 0 || rc >= IPSCAN_RESULT_STRING_MAX)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : Cannot fit result string into buffer, returned %d\n", rc);
	}

	return;
}
//
// -----------------------------------------------------------------------------
//
