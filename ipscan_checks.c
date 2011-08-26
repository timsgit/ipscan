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

#include "ipscan.h"
//
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

// IPv6 address conversion
#include <arpa/inet.h>

// String comparison
#include <string.h>

// Include resultsstruct
extern struct rslt_struc resultsstruct[];

int check_tcp_port(char * hostname, uint16_t port)
{
	struct addrinfo *res, *aip;
	struct addrinfo hints;
	int sock = -1, timeo = -1, conn = -1, cl = -1;
	int error;
	int i;
	struct timeval timeout;
	char portnum[8];

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;

	// set return value to a known default
	int retval = PORTUNKNOWN;

	snprintf(portnum, 8,"%d", port);
	error = getaddrinfo(hostname, portnum, &hints, &res);
	if (error != 0)
	{
		fprintf(stderr, LOGPREFIX "getaddrinfo: %s for host %s port %d\n", gai_strerror(error), hostname, port);
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
				// printf("Skipping, because family = %d\n",aip->ai_family);
				continue;
			}

			// Attempt to create a socket
			sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
			if (sock == -1)
			{
				int errsv = errno ;
				fprintf(stderr, LOGPREFIX "Bad socket call, returned %d (%s)\n", errsv, strerror(errsv));
				retval = PORTINTERROR;
			}

			// Assuming something bad hasn't already happened then attempt to set the receive timeout
			if (PORTUNKNOWN == retval)
			{
				// Set send timeout
				bzero(&timeout, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = 0;
				timeo = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
				if (timeo < 0)
				{
					int errsv = errno ;
					fprintf(stderr, LOGPREFIX "Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}
			}

			// Assuming something bad hasn't already happened then attempt to set the receive timeout
			if (PORTUNKNOWN == retval)
			{
				// Set receive timeout
				bzero(&timeout, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = 0;
				timeo = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
				if (timeo < 0)
				{
					int errsv = errno ;
					fprintf(stderr, LOGPREFIX "Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
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
				fprintf(stderr, LOGPREFIX "found port %d returned conn = %d, errsv = %d(%s)\n",port, conn, errsv, strerror(errsv));
				#endif

				// If we haven't found a matching returncode/errno then log this ....
				if (PORTUNKNOWN == retval)
				{
					fprintf(stderr, LOGPREFIX "connect unexpected response, errno is : %d (%s) for host %s port %d\n", \
							errsv, strerror(errsv), hostname, port);
					retval = PORTUNEXPECTED;
				}

				cl = close(sock);
				if (cl == -1)
				{
					fprintf(stderr, LOGPREFIX "close unexpected failure : %d (%s)\n", errno, strerror(errno));
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

	return(retval);
}
