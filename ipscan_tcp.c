//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2014 Tim Chappell.
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

// ipscan_tcp.c 	version
// 0.01  			initial version after split from ipscan_checks.c
// 0.02				tidy up logging prefixes
// 0.03				move to memset()
// 0.04				add support for special cases
// 0.05				ensure minimum timings are met

#include "ipscan.h"
//
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>

// IPv6 address conversion
#include <arpa/inet.h>

// String comparison
#include <string.h>

// Logging with syslog requires additional include
#if (LOGMODE == 1)
	#include <syslog.h>
#endif

// Include externals : resultsstruct
extern struct rslt_struc resultsstruct[];

// Others that FreeBSD highlighted
#include <netinet/in.h>
#include <stdint.h>
#include <inttypes.h>

// Other IPv6 related
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

//Poll support
#include <poll.h>

// Parallel processing related
#include <sys/wait.h>

// Define offset into ICMPv6 packet where user-defined data resides
#define ICMP6DATAOFFSET sizeof(struct icmp6_hdr)

//
// Prototype declarations
//
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, char *indirecthost );

//
// Check an individual TCP port
//

int check_tcp_port(char * hostname, uint16_t port, uint8_t special)
{
	struct addrinfo *res, *aip;
	struct addrinfo hints;
	int sock = -1, timeo = -1, conn = -1, cl = -1;
	int error;
	int i;
	struct timeval timeout;
	char portnum[8];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;

	// set return value to a known default
	int retval = PORTUNKNOWN;

	error = snprintf(portnum, 8,"%d", port);
	if (error < 0 || error >= 8)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port: Failed to write portnum, rc was %d\n", error);
		retval = PORTINTERROR;
	}

	error = getaddrinfo(hostname, portnum, &hints, &res);
	if (error != 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port: getaddrinfo: %s for host %s port %d\n", gai_strerror(error), hostname, port);
		retval = PORTINTERROR;
	}
	else
	{

		// cycle around the results ...
		for (aip = res; (NULL != aip && PORTUNKNOWN == retval) ; aip = aip->ai_next)
		{
			// If this is not an IPv6 address then skip
			if (aip->ai_family != AF_INET6)
			{
				// IPSCAN_LOG( LOGPREFIX "Skipping, because ai_family != AF_INET6 (actually %d)\n",aip->ai_family);
				continue;
			}

			// Attempt to create a socket
			sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
			if (sock == -1)
			{
				int errsv = errno ;
				IPSCAN_LOG( LOGPREFIX "check_tcp_port: Bad socket call, returned %d (%s)\n", errsv, strerror(errsv));
				retval = PORTINTERROR;
			}

			// Assuming something bad hasn't already happened then attempt to set the receive timeout
			if (PORTUNKNOWN == retval)
			{
				// Set send timeout
				memset(&timeout, 0, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = TIMEOUTMICROSECS;
				timeo = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
				if (timeo < 0)
				{
					int errsv = errno ;
					IPSCAN_LOG( LOGPREFIX "check_tcp_port: Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}
			}

			// Assuming something bad hasn't already happened then attempt to set the receive timeout
			if (PORTUNKNOWN == retval)
			{
				// Set receive timeout
				memset(&timeout, 0, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = TIMEOUTMICROSECS;
				timeo = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
				if (timeo < 0)
				{
					int errsv = errno ;
					IPSCAN_LOG( LOGPREFIX "check_tcp_port: Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}
			}

			// Assuming something bad hasn't already happened then attempt to connect
			if (PORTUNKNOWN == retval)
			{
				// attempt to connect
				conn = connect(sock, aip->ai_addr, aip->ai_addrlen);
				int errsv = errno ;

				// cycle through the expected list of results
				for (i = 0; PORTEOL != resultsstruct[i].returnval && PORTUNKNOWN == retval ; i++)
				{

					// Find a matching connect returncode and also errno, if appropriate
					if (resultsstruct[i].connrc == conn)
					{
						// Set the returnvalue if we find a match
						if ( conn == 0 || (conn == -1 && resultsstruct[i].connerrno == errsv) )
						{
							retval = resultsstruct[i].returnval;
						}
					}
				}

				#ifdef DEBUG
				if (0 != special)
				{
					IPSCAN_LOG( LOGPREFIX "check_tcp_port: found port %d:%d returned conn = %d, errsv = %d(%s)\n", port, special, conn, errsv, strerror(errsv));
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "check_tcp_port: found port %d returned conn = %d, errsv = %d(%s)\n", port, conn, errsv, strerror(errsv));
				}
				#endif

				// If we haven't found a matching returncode/errno then log this ....
				if (PORTUNKNOWN == retval)
				{
					if (0 != special)
					{
						IPSCAN_LOG( LOGPREFIX "check_tcp_port: connect unexpected response, errno is : %d (%s) for host %s port %d:%d\n", \
							errsv, strerror(errsv), hostname, port, special);
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "check_tcp_port: connect unexpected response, errno is : %d (%s) for host %s port %d\n", \
							errsv, strerror(errsv), hostname, port);
					}
					retval = PORTUNEXPECTED;
				}

				cl = close(sock);
				if (cl == -1)
				{
					IPSCAN_LOG( LOGPREFIX "check_tcp_port: close unexpected failure : %d (%s)\n", errno, strerror(errno));
				}

			}
			else
			{
				// Something bad has happened during setsockopts, but ensure we close an open socket anyway
				if (-1 != sock)
				{
					cl = close(sock);
				}
			}

		} // end for loop
		freeaddrinfo(res);
	}

	// If we received any non-positive feedback then make sure we wait at least IPSCAN_MINTIME_PER_PORT secs
	if ((PORTOPEN != retval) && (PORTINPROGRESS != retval)) sleep(IPSCAN_MINTIME_PER_PORT);

	return(retval);
}


int check_tcp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, struct portlist_struc *portlist)
{
	int i,rc,result;
	pid_t childpid = fork();
	if (childpid > 0)
	{
		// parent
		#ifdef PARLLDEBUG
		IPSCAN_LOG( LOGPREFIX "check_tcp_ports_parll(): forked and started child PID=%d\n",childpid);
		#endif
	}
	else if (childpid == 0)
	{
		#ifdef PARLLDEBUG
		IPSCAN_LOG( LOGPREFIX "check_tcp_ports_parll(): startindex %d, todo %d\n",portindex,todo);
		#endif
		// child - actually do the work here - and then exit successfully
		char unusedfield[8] = "unused";
		for (i = 0 ; i <(int)todo ; i++)
		{
			uint16_t port = portlist[portindex+i].port_num;
			uint8_t special = portlist[portindex+i].special;
			result = check_tcp_port(hostname, port, special);
			// Put results into database
			rc = write_db(host_msb, host_lsb, timestamp, session, (port + ((special & IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_TCP << IPSCAN_PROTO_SHIFT)), result, unusedfield );
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "check_tcp_ports_parll(): check_tcp_port_parll() write_db returned %d\n", rc);
			}
		}
		// Usual practice to have children _exit() whilst the parent calls exit()
		_exit(EXIT_SUCCESS);
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_ports_parll(): fork() failed childpid=%d, errno=%d(%s)\n", childpid, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return( (int)childpid );
}
