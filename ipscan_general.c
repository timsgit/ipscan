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
// 0.11 - reorder entries to match definitions, add database error
// 0.12 - update copyright year
// 0.13 - moved to unsigned proto
// 0.14 - update copyright year
// 0.15 - add report_useragent_strings()
// 0.16 - hide leading and trailing spaces
// 0.17 - added flag values
// 0.18 - added report_ipscan_versions()
// 0.19 - CodeQL improvements
// 0.20 - add querystring checkers
// 0.21 - tidy various format strings

//
#define IPSCAN_GENERAL_VER "0.21"
//

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
// report version
//
const char* ipscan_general_ver(void)
{
    return IPSCAN_GENERAL_VER;
}
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
void proto_to_string(uint32_t proto, char * retstring)
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
void fetch_to_string(uint32_t fetchnum, char * retstring)
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
	else if (IPSCAN_EVAL_ERROR == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "EVAL ERROR");
	}
	else if (IPSCAN_OTHER_ERROR == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "OTHER ERROR");
	}
	else if (IPSCAN_UNSUCCESSFUL_COMPLETION == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "UNSUCCESSFUL");
	}
	else if (IPSCAN_NAVIGATE_AWAY == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "NAVIGATEAWAY");
	}
	else if (IPSCAN_BAD_JSON_ERROR == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "BAD JSON ERR");
	}  
	else if (IPSCAN_DB_ERROR == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "DATABASE ERR");
	}  
	else if (IPSCAN_UNEXPECTED_CHANGE == fetchnum)
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s", "UNEXP CHANGE");
	}  
	else
	{
		rc = snprintf(retstring, IPSCAN_FETCHNUM_STRING_MAX, "%s:%u", "UNKNOWN", fetchnum);
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
// TJC - put restringfree back to signed so that calcs work correctly?
char * state_to_string(uint64_t statenum, char * retstringptr, int retstringstart)
{
	if (0 >= retstringstart) return (char *)NULL;
	char * retstringptrstart = retstringptr;
	int rc = 0;
	size_t retstringfree = (size_t)retstringstart;

	rc = snprintf(retstringptr, retstringfree, "%s", "flags: ");
	if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
	retstringptr += rc;
	retstringfree -= (size_t)rc;

	if (0 != (statenum & PORTUNKNOWN))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "UNKNOWN, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_RUNNING_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "RUNNING, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_COMPLETE_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "COMPLETE, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_HTTPTIMEOUT_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "TIMEOUT, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_EVALERROR_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "EVALERROR, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_OTHERERROR_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "OTHERERROR, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_NAVAWAY_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "NAVAWAY, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_UNEXPCHANGE_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "UNEXPECTED, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_BADCOMPLETE_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "BADCOMPLETE, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	if (0 != (statenum & IPSCAN_TESTSTATE_DATABASE_ERROR_BIT))
	{
		rc = snprintf(retstringptr, retstringfree, "%s", "DB ERROR, ");
		if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
		retstringptr += rc;
		retstringfree -= (size_t)rc;
	}
	rc = snprintf(retstringptr, retstringfree, "%s", "<EOL>\n\0");
	if (rc < 0 || (size_t)rc >= retstringfree) return (char *)NULL;
	retstringptr += rc;
	retstringfree -= (size_t)rc;
	if (0 == retstringfree) return (char *)NULL;
	return retstringptrstart;
}


//
// -----------------------------------------------------------------------------
//
void result_to_string(uint32_t result, char * retstring)
{
	int rc;
	char hosttype[16];
	if (IPSCAN_INDIRECT_RESPONSE <= result)
	{
		result -= IPSCAN_INDIRECT_RESPONSE;
		strncpy(hosttype, "indirect:", 15);
	}
	else
	{
		strncpy(hosttype, "", 15);
	}

	if (PORTOPEN == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "OPEN");
	}
	else if (PORTABORT == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "ABORT");
	}
	else if (PORTREFUSED == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "REFUSED");
	}
	else if (PORTCRESET == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "CRESET");
	}
	else if (PORTNRESET == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "NRESET");
	}
	else if (PORTINPROGRESS == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "IN-PROGRESS");
	}
	else if (PORTPROHIBITED == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "PROHIBITED");
	}
	else if (PORTUNREACHABLE == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "UNREACHABLE");
	}
	else if (PORTNOROUTE == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "NO ROUTE");
	}
	else if (PORTPKTTOOBIG == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "PKT TOO BIG");
	}
	else if (PORTPARAMPROB == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "PARAM PROBLEM");
	}
	else if (ECHONOREPLY == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "ECHO NO-REPLY");
	}
	else if (ECHOREPLY == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "ECHO REPLY");
	}
	else if (UDPOPEN == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "UDP OPEN");
	}
	else if (UDPSTEALTH == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "UDP STEALTH");
	}
	else if (PORTUNEXPECTED == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "UNEXPECTED");
	}
	else if (PORTUNKNOWN == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "UNKNOWN");
	}
	else if (PORTINTERROR == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "INTERNAL ERROR");
	}
	else if (PORTEOL == result)
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s%s", hosttype, "<EOL>");
	}
	else
	{
		rc = snprintf(retstring, IPSCAN_RESULT_STRING_MAX, "%s-%s:%u", "<MISSING>", hosttype, result);
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
void report_agent_string(char * agentstringvar, const char *varname, unsigned int error1ignore0)
{
	// Note that none of this content can be trusted - so agressively limit the character set
	char agentstring[ (MAXUSERAGENTLEN + 1) ];
	unsigned int i;
	// Pre-clear array since using sscanf with %Nc doesn't guarantee string will be 0 terminated
	memset(agentstring, 0, sizeof(agentstring));

 	if ( NULL == agentstringvar )
        {
		if (1 == error1ignore0)
		{
                	IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : %s variable lookup returned NULL.\n", varname);
		}
        }
        else if ( strnlen(agentstringvar, (MAXUSERAGENTLEN+1)) > MAXUSERAGENTLEN )
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: %s variable string is longer than allocated buffer (%d > %d)\n", varname,\
								 (int)strnlen(agentstringvar, (MAXUSERAGENTLEN+1)), MAXUSERAGENTLEN);
        }
	else if ( sscanf(agentstringvar,"%"TO_STR(MAXUSERAGENTLEN)"c",agentstring) != EOF )
	{
		if (strnlen(agentstring, MAXUSERAGENTLEN+1) > MAXUSERAGENTLEN)
		{
			agentstring[0] = 0; // truncate string
		}
		else
		{
			for ( i = 0 ; i < strnlen(agentstring, MAXUSERAGENTLEN+1) ; i++ )
			{
				// Clamp to printable ASCII range - but ensure 0 is not corrupted
				if ( (agentstring[i] > 0 && agentstring[i] < 32) || agentstring[i] > 126 ) agentstring[i] = 32;
				// and also protect against special characters which could be used for XSS
				switch (agentstring[i])
				{
					case '<':
					case '>':
					case ':':
					case ';':
					case '&':
					case '\\':
					case '\"':
					case '/':
					case '=':
					case '*':
					case ',':
					case '^':
					case '$':
					case '|':
					case '%':
					case '{':
					case '}':
					case '!':
					case '[':
					case ']':
					case '?':
						agentstring[i] = ' ';
					break;
			
					default:
						// do nothing
					break;
				}
			}
		}
		size_t left = 0;
		size_t right = strnlen(agentstring,MAXUSERAGENTLEN+1);
		if (MAXUSERAGENTLEN < right)
		{
			// no end-of-string '0' found, so insert one
			agentstring[MAXUSERAGENTLEN] = 0;
			right = strnlen(agentstring,MAXUSERAGENTLEN+1);
		}
		// skip left-leading spaces
		while (left < right && left < MAXUSERAGENTLEN && agentstring[left]==' ')
		{
			left++;
		}
		// truncate right-trailing spaces and zeroes
		while ((agentstring[right]==' ' || agentstring[right]==0) && right > left && right > 0)
		{ 
			agentstring[right] = 0;
			right--;
		}
		IPSCAN_LOG( LOGPREFIX "ipscan: INFO: %s = '%s'\n", varname, &agentstring[left]);
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: %s variable not reportable.\n", varname);
	}
}

//
// -----------------------------------------------------------------------------
//
void report_useragent_strings(char *uavar, char *secchuavar, char *secchuaarchvar, char *secchuaarchplatvar)
{
	// Note that content cannot be trusted - so agressively limit the character set
	report_agent_string(uavar, "HTTP_USER_AGENT", 1);
	report_agent_string(secchuavar, "HTTP_SEC_CH_UA", 0);
	report_agent_string(secchuaarchvar, "HTTP_SEC_CH_UA_ARCH", 0);
	report_agent_string(secchuaarchplatvar, "HTTP_SEC_CH_UA_PLATFORM", 0);
}

//
// -----------------------------------------------------------------------------
//
void report_ipscan_versions(const char *mainver, const char *generalver, const char *tcpver, const char *udpver, const char *icmpv6ver, const char *dbver,\
	 const char *webver, const char *hver, const char *plver)
{
	IPSCAN_LOG( LOGPREFIX "ipscan: INFO: IPSCAN_MAIN_VER      = %-4s, IPSCAN_GENERAL_VER = %-4s, IPSCAN_WEB_VER    = %-4s, IPSCAN_H_VER  = %-4s\n", mainver, generalver, webver, hver);
	IPSCAN_LOG( LOGPREFIX "ipscan: INFO: IPSCAN_TCP_VER       = %-4s, IPSCAN_UDP_VER     = %-4s, IPSCAN_ICMPV6_VER = %-4s, IPSCAN_DB_VER = %-4s\n", tcpver, udpver, icmpv6ver, dbver);
	IPSCAN_LOG( LOGPREFIX "ipscan: INFO: IPSCAN_PORTLIST_VER  = %-4s\n", plver);
}

//
// -----------------------------------------------------------------------------
//
int querystring_is_alphanum(char check)
{
	int retval = 0;
	// allow a-z,0-9
	if ((check >= 'a' && check <= 'z') || (check >= '0' && check <= '9'))
	{
		retval = 1;
	}
	return (retval);
}

//
// -----------------------------------------------------------------------------
//
int querystring_is_valid(char check)
{
	int retval = 0;
	// allow &,=,a-z,0-9,+,-
	if (check == '&' || check == '=' || (check >= 'a' && check <= 'z') || (check >= '0' && check <= '9') || check == '+' || check == '-')
	{
		retval = 1;
	}
	return (retval);
}

//
// -----------------------------------------------------------------------------
//
int querystring_is_number(char check)
{
	int retval = 0;
	// allow 0-9,+,-
	if ( (check >= '0' && check <= '9') || check == '+' || check == '-' )
	{
		retval = 1;
	}
	return (retval);
}

