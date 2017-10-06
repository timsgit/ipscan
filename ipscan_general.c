//    IPscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2017 Tim Chappell.
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
		// Clear the MSB of the random session ID so that we're sure it will fit into an int64_t which the QUERY_STRING parser assumes
		sessionnum = fetchedsession & ( ((uint64_t)~0) >> 1);

		#ifdef QUERYDEBUG
		IPSCAN_LOG( LOGPREFIX "ipscan: Session number modification check, before = %"PRIu64" after = %"PRIu64"\n", fetchedsession, sessionnum);
		#endif

		if (1 != numitems)
		{
			sessionnum = (uint64_t)getpid();
			IPSCAN_LOG( LOGPREFIX "ipscan: ERROR : Cannot read /dev/urandom, defaulting session to getpid() = %"PRIu64"\n", sessionnum);
		}
	}
	return (sessionnum);
}
