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

// ipscan_checks.c version
// 0.01 - initial version
// 0.02 - added syslog support
// 0.03 - addition of ping functionality
// 0.04 - reordered code to match calling order

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

// Logging with syslog requires additional include
#if (LOGMODE == 1)
	#include <syslog.h>
#endif

// Include resultsstruct
extern struct rslt_struc resultsstruct[];

// Other IPv6 related
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

//Poll support
#include <poll.h>

// Define offset into ICMPv6 packet where user-defined data resides
#define ICMP6DATAOFFSET sizeof(struct icmp6_hdr)


//
// Send an ICMPv6 ECHO-REQUEST and see whether we receive an ECHO-REPLY in response
//

int check_icmpv6_echoresponse(char * hostname, uint64_t starttime, uint64_t session)
{
	struct addrinfo *res;
	struct addrinfo hints;

	struct sockaddr_in6 destination;
	struct sockaddr_in6 source;
	struct sockaddr *srcaddr;
	int srclen;

	int sock = -1;
	int errsv;
	int rc;
	int error;
	unsigned int sendsize;

	struct timeval timeout;

	struct icmp6_hdr *txicmp6hdr_ptr;
	struct icmp6_hdr *rxicmp6hdr_ptr;

	struct icmp6_filter myfilter;
	// reply tracker
	unsigned int foundit = 0;

	// send and receive message headers
	struct msghdr smsghdr;
	struct msghdr rmsghdr;
	struct iovec txiov[2], rxiov[2];
	char txpackdata[ICMPV6_PACKET_BUFFER_SIZE];
	char rxpackdata[ICMPV6_PACKET_BUFFER_SIZE];
	char *rxpacket = &rxpackdata[0];
	char rxbuf[ICMPV6_PACKET_BUFFER_SIZE];
	char tmpbuf[128];

	// set return value to a known default
	int retval = PORTUNKNOWN;

	txicmp6hdr_ptr = (struct icmp6_hdr *)txpackdata;

	struct pollfd pollfiledesc[1];

	unsigned int txid = (unsigned int)session;
	unsigned int rxid;
	unsigned int txseqno = 14872; // MAGIC number - assume no reason to start at 1?
	unsigned int rxseqno;

	unsigned int rxicmp6_type, rxicmp6_code;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;

	error = getaddrinfo(hostname, NULL, &hints, &res);
	if (error != 0)
	{
		IPSCAN_LOG( LOGPREFIX "getaddrinfo: failed1 %s for host %s\n", gai_strerror(error), hostname);
		return (PORTINTERROR);
	}

	if (!res->ai_addr)
	{
		IPSCAN_LOG( LOGPREFIX "getaddrinfo: failed2 %s for host %s\n",gai_strerror(error), hostname);
		freeaddrinfo(res);
		return (PORTINTERROR);
	}

	// Copy the resulting address into our destination
	memcpy(&destination, res->ai_addr, res->ai_addrlen);
	// Done with the address info now, so free the area
	freeaddrinfo(res);

	// Get root privileges in order to create the raw socket

	uid_t uid = getuid();
	uid_t gid = getgid();

	#ifdef PINGDEBUG
	uid_t euid = geteuid();
	uid_t egid = getegid();
	#endif

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "Entered with real UID  %d  real GID  %d  effective UID %d  effective GID %d\n", uid, gid, euid, egid);
	#endif

	rc = setuid(0);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "setuid: failed to gain root privileges - is setuid permission set?\n");
		retval = PORTINTERROR;
	}

	rc = setgid(0);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "setgid: failed to gain root privileges - is setgid permission set?\n");
		retval = PORTINTERROR;
	}

	// run with ROOT privileges, keep section to a minimum
	if (retval == PORTUNKNOWN)
	{
			sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			errsv = errno;
			if (sock < 0)
			{
				IPSCAN_LOG( LOGPREFIX "socket: Error : %s (%d) for host %s\n", strerror(errsv), errsv, hostname);
				retval = PORTINTERROR;
			}
			else
			{
				bzero(&timeout, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = 0;

				rc = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
				errsv = errno;
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}

				bzero(&timeout, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = 0;

				rc = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
				errsv = errno;
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}

				// Filter out everything except the responses we're looking for
				// taken from RFC3542
				ICMP6_FILTER_SETBLOCKALL(&myfilter);
				ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &myfilter);
				ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &myfilter);
				ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &myfilter);
				ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &myfilter);
				ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &myfilter);

				rc = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &myfilter, sizeof(myfilter));
				errsv = errno;
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "setsockopt: Error setting ICMPv6 filter: %s (%d)\n", strerror(errsv), errsv);
					retval = PORTINTERROR;
				}

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "Exiting privileged section\n");
				#endif

			} // end if (socket created successfully)
	}

	// END OF ROOT PRIVILEGES - Revert to previous privilege level
	rc = setgid(gid);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "setgid: failed to revoke root gid privileges\n");
		retval = PORTINTERROR;
	}

	rc = setuid(uid);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "setuid: failed to revoke root uid privileges\n");
		retval = PORTINTERROR;
	}

	// If something bad has happened then return now ...
	// mustn't return to caller with root privileges, hence done here ...
	if (retval != PORTUNKNOWN)
	{
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "Post-revoke real UID  %d real GID  %d effective UID %d effective GID %d\n", getuid (), getgid (), geteuid(), getegid());
	#endif

	// -----------------------------------------------
	//
	// ICMPv6 ECHO-REQUEST TRANSMIT
	//
	// -----------------------------------------------

	memset( txicmp6hdr_ptr, 0, sizeof(txicmp6hdr_ptr));
	txicmp6hdr_ptr->icmp6_cksum = 0;
	txicmp6hdr_ptr->icmp6_type = ICMP6_ECHO_REQUEST;
	txicmp6hdr_ptr->icmp6_code = 0;
	txicmp6hdr_ptr->icmp6_id = htons(txid);
	txicmp6hdr_ptr->icmp6_seq = htons(txseqno);

	// socket address
	memset(&smsghdr, 0, sizeof(smsghdr));
	smsghdr.msg_name = (caddr_t)&destination;
	smsghdr.msg_namelen = sizeof(destination);

	// Insert the unique data
	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "Sending PING unique data starttime=%"PRId64" session=%"PRId64"\n", starttime, session);
	#endif

	rc = snprintf(&txpackdata[ICMP6DATAOFFSET],(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET),"%"PRId64" %"PRId64" 010892 210695", starttime, session);
	if (rc < 0 || rc > (ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET))
	{
		IPSCAN_LOG( LOGPREFIX "snprintf returned %d, expected >=0 but <= %d\n", rc, (ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

	// Choose a packet slightly bigger than minimum size
	sendsize = ICMPV6_PACKET_SIZE;

	// scatter/gather array
	memset(&txiov, 0, sizeof(txiov));
	txiov[0].iov_base = (caddr_t)&txpackdata;
	txiov[0].iov_len = sendsize;
	smsghdr.msg_iov = txiov;
	smsghdr.msg_iovlen = 1;

	rc = sendmsg(sock, &smsghdr, 0);
	errsv = errno;

	if (rc < 0)
	{
		IPSCAN_LOG( LOGPREFIX "sendmsg %d (%s)\n", errsv, strerror(errsv));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

	if (rc != sendsize)
	{
		IPSCAN_LOG( LOGPREFIX"sendmsg sent %s %d chars but sendmsg returned %d\n", hostname, sendsize, rc);
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX"session mapped into txid was %d (0x%04x)\n", txid,txid);
	#endif

	// -----------------------------------------------
	//
	// // ICMPv6 ECHO-REPLY RECEIVE
	//
	// -----------------------------------------------

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "Setting up receiver ...\n");
	#endif

	time_t timestart = time(0);
	time_t timenow = timestart;
	unsigned int loopcount = 0;

	// Effectively a promiscuous receive of ICMPv6 packets, so need to discern which are for us
	// ... may need to go round this loop more than once ...

	while ( ((timenow - timestart) <= 1+TIMEOUTSECS) && foundit == 0)
	{
		loopcount++;
		#ifdef PINGDEBUG
		IPSCAN_LOG( LOGPREFIX "Beginning time %d through the loop.\n", loopcount);
		#endif

		pollfiledesc[0].fd = sock;
		// Want indication that there is something to read
		pollfiledesc[0].events = POLLIN;
		rc = poll(pollfiledesc, 1, 1000*TIMEOUTSECS);
		errsv = errno;
		// Capture current time for next timeout comparison
		timenow = time(0);

		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "RESTART: poll returned bad things : %d (%s)\n", errsv, strerror(errsv));
			continue;
		}
		else if (rc == 0)
		{
			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "RESTART: poll returned 0 results\n");
			#endif
			continue;
		}

		#ifdef PINGDEBUG
		IPSCAN_LOG( LOGPREFIX "returned events = %d\n", pollfiledesc[0].revents);
		#endif

		if ( (pollfiledesc[0].revents & POLLIN) != POLLIN)
		{
			IPSCAN_LOG( LOGPREFIX "RESTART: poll returned but failed to find POLLIN set: %d\n",pollfiledesc[0].revents);
			continue;
		}

		rmsghdr.msg_name = (caddr_t)&source;
		rmsghdr.msg_namelen = sizeof(source);
		memset(&rxiov, 0, sizeof(rxiov));
		rxiov[0].iov_base = (caddr_t)rxpacket;
		rxiov[0].iov_len = ICMPV6_PACKET_BUFFER_SIZE;
		rmsghdr.msg_iov = rxiov;
		rmsghdr.msg_iovlen = 1;
		rmsghdr.msg_control = (caddr_t)rxbuf;
		rmsghdr.msg_controllen = sizeof(rxbuf);
		rc = recvmsg(sock, &rmsghdr, 0);
		errsv = errno;
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "RESTART: recvmsg returned bad things : %d (%s)\n", errsv, strerror(errsv));
			continue;
		}
		else if (rc == 0)
		{
			IPSCAN_LOG( LOGPREFIX "RESTART: recvmsg returned 0 - is this a control message?\n");
			continue;
		}
		else
		{
			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "recvmsg returned indicating %d bytes received\n",rc);
			#endif

			if (rc < (int)sizeof(struct icmp6_hdr))
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "RESTART: Received packet too small - expected at least %d, got %d\n",(int)sizeof(struct icmp6_hdr),rc);
				#endif
				continue;
			}

			if (rmsghdr.msg_namelen != sizeof(struct sockaddr_in6))
			{
				IPSCAN_LOG( LOGPREFIX "RESTART: received bad peername length (namelen %d)\n",rmsghdr.msg_namelen);
				continue;
			}

			if (((struct sockaddr *)rmsghdr.msg_name)->sa_family != AF_INET6)
			{
				IPSCAN_LOG( LOGPREFIX "RESTART: received bad peername family (sa_family %d)\n",((struct sockaddr *)rmsghdr.msg_name)->sa_family);
				continue;
			}

			srcaddr = (struct sockaddr *)rmsghdr.msg_name;
			srclen = rmsghdr.msg_namelen;
			
			rc = getnameinfo(srcaddr, srclen, tmpbuf, sizeof(tmpbuf), NULL, 0, NI_NUMERICHOST);
			errsv = errno;
			if (rc == 0)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "Received source address was %s\n", tmpbuf);
				#endif
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "RESTART: getnameinfo returned bad indication %d (%s)\n",errsv, gai_strerror(errsv));
				continue;
			}

			// Extract ICMPv6 type and code for checking and reporting
			rxicmp6hdr_ptr = (struct icmp6_hdr *)rxpacket;
			rxicmp6_type = rxicmp6hdr_ptr->icmp6_type;
			rxicmp6_code = rxicmp6hdr_ptr->icmp6_code;
			// Extract sequence number and ID
			rxseqno = htons(rxicmp6hdr_ptr->icmp6_seq);
			rxid = htons(rxicmp6hdr_ptr->icmp6_id);

			// Check whether our tx destination equals our rx source
			if (IN6_ARE_ADDR_EQUAL(&source,&destination)==0)
			{
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was %d ICMP6_CODE was %d\n", rxicmp6_type, rxicmp6_code);
				IPSCAN_LOG( LOGPREFIX "RESTART: address mismatch\n");
				continue;
			}

			// Check what type of ICMPv6 packet we received and handle appropriately ...
			if (rxicmp6_type == ICMP6_ECHO_REPLY)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "Received an ICMP6_ECHO_REPLY, with code %d\n", rxicmp6_code);
				#endif
			}
			else if ( rxicmp6_type == ICMP6_DST_UNREACH )
			{
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was DST_UNREACH, with code %d\n", rxicmp6_code);
				switch ( rxicmp6_code )
				{
				case ICMP6_DST_UNREACH_NOROUTE:
					retval = PORTUNREACHABLE;
					break;
				case ICMP6_DST_UNREACH_ADMIN:
					retval = PORTPROHIBITED;
					break;
				case ICMP6_DST_UNREACH_ADDR:
					retval = PORTNOROUTE;
					break;
				case ICMP6_DST_UNREACH_NOPORT:
					retval = PORTREFUSED;
					break;
				default:
					retval = PORTUNREACHABLE;
					break;
				}
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval);
			}
			else if (rxicmp6_type == ICMP6_PARAM_PROB)
			{
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was PARAM_PROB, with code %d\n", rxicmp6_code);
				retval = PORTPARAMPROB;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval);
			}
			else if (rxicmp6_type == ICMP6_TIME_EXCEEDED)
			{
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was TIME_EXCEEDED, with code %d\n", rxicmp6_code);
				retval = PORTNOROUTE;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval);
			}
			else if (rxicmp6_type == ICMP6_PACKET_TOO_BIG)
			{
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was PACKET_TOO_BIG, with code %d\n", rxicmp6_code);
				retval = PORTPKTTOOBIG;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "RESTART: unhandled ICMP6_TYPE was %d ICMP6_CODE was %d\n", rxicmp6_type, rxicmp6_code);
				continue;
			}

			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "ICMP6_SEQ was %d (0x%04x) ICMP6_ID was %d (0x%04x)\n", rxseqno, rxseqno, rxid, rxid);
			#endif

			if (rxseqno != txseqno)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "RESTART: Sequence number mismatch - not for us\n");
				#endif
				continue;
			}
			if (rxid != txid)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "RESTART: id mismatch - not for us\n");
				#endif
				continue;
			}

			// Check for the expected received data
			// sent:
			// "%"PRId64" %"PRId64" 010892 210695", starttime, session
			uint64_t rxstarttime, rxsession;
			unsigned int rxmagic1, rxmagic2;

			rc = sscanf(&rxpackdata[ICMP6DATAOFFSET], "%"PRId64" %"PRId64" %d %d", &rxstarttime, &rxsession, &rxmagic1, &rxmagic2);
			if (rc == 4)
			{
				if (rxstarttime != starttime)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "RESTART: magic data rxstarttime (%"PRId64") != starttime (%"PRId64")\n", rxstarttime, starttime);
					#endif
					continue;
				}
				if (rxsession != session)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "RESTART: magic data rxsession (%"PRId64") != session (%"PRId64")\n", rxsession, session);
					#endif
					continue;
				}
				if (10892 != rxmagic1)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "RESTART: magic data rxmagic1 (%d) != 010892\n", rxmagic1);
					#endif
					continue;
				}
				if (210695 != rxmagic2)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "RESTART: magic data rxmagic2 (%d) != 010892\n", rxmagic2);
					#endif
					continue;
				}

				//
				// if we get to this point then everything matches ...
				//
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "Everything matches - it was our expected ICMPv6 ECHO_RESPONSE\n");
				#endif
				foundit = 1;
			}
			else
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "RESTART: magic data - number of parameters mismatched, got %d\n", rc);
				#endif
				continue;
			}

		} // end of if (received some bytes)

	} // end of while

	if (foundit == 1) retval = ECHOREPLY; else retval = ECHONOREPLY;

	// return the status
	if (-1 != sock) close(sock); // close socket if appropriate
	return(retval);
}

//
// Check an individual TCP port
//

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
		IPSCAN_LOG( LOGPREFIX "getaddrinfo: %s for host %s port %d\n", gai_strerror(error), hostname, port);
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
				IPSCAN_LOG( LOGPREFIX "Bad socket call, returned %d (%s)\n", errsv, strerror(errsv));
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
					IPSCAN_LOG( LOGPREFIX "Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
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
					IPSCAN_LOG( LOGPREFIX "Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
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
				IPSCAN_LOG( LOGPREFIX "found port %d returned conn = %d, errsv = %d(%s)\n",port, conn, errsv, strerror(errsv));
				#endif

				// If we haven't found a matching returncode/errno then log this ....
				if (PORTUNKNOWN == retval)
				{
					IPSCAN_LOG( LOGPREFIX "connect unexpected response, errno is : %d (%s) for host %s port %d\n", \
							errsv, strerror(errsv), hostname, port);
					retval = PORTUNEXPECTED;
				}

				cl = close(sock);
				if (cl == -1)
				{
					IPSCAN_LOG( LOGPREFIX "close unexpected failure : %d (%s)\n", errno, strerror(errno));
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





