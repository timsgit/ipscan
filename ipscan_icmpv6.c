//    IPscan - an HTTP-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2026 Tim Chappell.
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

// ipscan_icmpv6.c 	version
// 0.1			initial version after splitting from ipscan_checks.c
// 0.2			add prefixes to debug log output
// 0.3			move to memset()
// 0.4			ensure minimum timings are met
// 0.5			ensure txid doesn't exceed 16-bits (move to random session ID)
// 0.6			clear msghdr.msg_flags
// 0.7			add time() checks
// 0.8			update copyright year
// 0.9			update copyright year
// 0.10			update copyright year
// 0.11			extern no longer defined here
// 0.12			correct signedness of sprintf/sscanf used for packet data
// 0.13			update copyright year
// 0.14			swap comparison terms, where appropriate
// 0.15			delete old comments, update copyright year
// 0.16			add missing error checks for inet_ntop calls
// 0.17			and snprintf for router too
// 0.18			update copyright year
// 0.19			update copyright year
// 0.20			add (potentially) missing length check
// 0.21			add pragmas to hide gcc warnings
// 0.22			update copyright year
// 1.00			drop/regain privileges
// 1.01			Make drop/regain privileges a compile-time option
// 1.02			Move to new ICMPv6 mappings
// 1.03			Improve checks for direct ICMPv6 response from HUT, fix various printf formats and typos

//
#define IPSCAN_ICMPV6_VER "1.03"
//

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

// Others that FreeBSD highlighted
#include <netinet/in.h>
#include <stdint.h>
#include <inttypes.h>

// Other IPv6 related
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

// Poll support
#include <poll.h>

// Define offset into ICMPv6 packet where user-defined data resides
#define ICMP6DATAOFFSET sizeof(struct icmp6_hdr)

//
// report version
//
const char* ipscan_icmpv6_ver(void)
{
    return IPSCAN_ICMPV6_VER;
}

// Function prototypes
#include "ipscan_general.h"

//
// Send an ICMPv6 ECHO-REQUEST and see whether we receive an ECHO-REPLY in response
//

int check_icmpv6_echoresponse(char * hostname, uint64_t starttime, uint64_t session, char * router)
{
	struct addrinfo *res;
	struct addrinfo hints;

	struct sockaddr_in6 destination;
	struct sockaddr_in6 source;

	int sock = -1;
	int errsv;
	int rc;
	int error;
	unsigned int sendsize;
	const char * rccharptr;

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
	char txpackdata[ICMPV6_PACKET_BUFFER_SIZE+1];
	char rxpackdata[ICMPV6_PACKET_BUFFER_SIZE+1];
	char *rxpacket = &rxpackdata[0];
	char rxbuf[ICMPV6_PACKET_BUFFER_SIZE+1];
	char tmpbuf[128];

	// set return value to a known default
	int retval = PORTUNKNOWN;

	txicmp6hdr_ptr = (struct icmp6_hdr *)txpackdata;

	struct pollfd pollfiledesc[1];

	short unsigned int txid = (unsigned int)(session & 0xFFFF); // Maximum 16 bits
	unsigned int rxid;
	short unsigned int txseqno = ICMPV6_MAGIC_SEQ; // MAGIC number - assume no reason to start at 1?
	unsigned int rxseqno;

	unsigned int rxicmp6_type, rxicmp6_code;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;

	error = getaddrinfo(hostname, NULL, &hints, &res);
	if (error != 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: getaddrinfo: failed1 %s for host %s\n", gai_strerror(error), hostname);
		return (PORTINTERROR);
	}

	if (!res->ai_addr)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: getaddrinfo: failed2 %s for host %s\n",gai_strerror(error), hostname);
		freeaddrinfo(res);
		return (PORTINTERROR);
	}

	// Copy the resulting address into our destination if there is sufficient room
	memset(&destination, 0, sizeof(struct sockaddr_in6));
	if (res->ai_addrlen <= sizeof(struct sockaddr_in6))
	{
		memcpy(&destination, res->ai_addr, res->ai_addrlen);
	}
	// Done with the address info now, so free the area
	freeaddrinfo(res);

	// Determine the local address used to reach the HUT (hostname)
        struct in6_addr my_tx_ipaddr;
        rc = get_my_local_ipaddr(hostname, &my_tx_ipaddr);
        if (EXIT_FAILURE == rc)
        {
                IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: get_my_local_ipaddr() returned EXIT_FAILURE\n");
                retval = PORTINTERROR;
        }

	// Set default logged router address to dead::1 (valid format IPv6 address)
	rc = snprintf(router, INET6_ADDRSTRLEN, "dead::1");
	if (rc < 0 || rc >= INET6_ADDRSTRLEN)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Failed to unset logged router address, rc was %d\n", rc);
		memset(router, 0, INET6_ADDRSTRLEN);
		retval = PORTINTERROR;
	}

	// run with ROOT privileges, or setcap net, keep section to a minimum
	if (PORTUNKNOWN == retval)
	{
		sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		errsv = errno;
		if (-1 == sock)
		{
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: socket: ERROR: %s (%d) for host %s\n", strerror(errsv), errsv, hostname);
			retval = PORTINTERROR;
		}
		else
		{
			memset(&timeout, 0, sizeof(timeout));
			timeout.tv_sec = TIMEOUTSECS;
			timeout.tv_usec = TIMEOUTMICROSECS;

			rc = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
			errsv = errno;
			if (-1 == rc)
			{
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
				retval = PORTINTERROR;
			}

			if (retval == PORTUNKNOWN)
			{
				memset(&timeout, 0, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = TIMEOUTMICROSECS;

				rc = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
				errsv = errno;
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}
			}

			// Filter out everything except the responses we're looking for
			// taken from RFC3542
			ICMP6_FILTER_SETBLOCKALL(&myfilter);
			// Start-of-pragma to prevent gcc sign-conversion warnings ...
			#pragma GCC diagnostic push
			#pragma GCC diagnostic ignored "-Wsign-conversion"
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &myfilter);
			ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &myfilter);
			ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &myfilter);
			ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &myfilter);
			ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &myfilter);
			#pragma GCC diagnostic pop
			// End-of-pragma
			if (retval == PORTUNKNOWN)
			{
				rc = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &myfilter, sizeof(myfilter));
				errsv = errno;
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: setsockopt: setting ICMPv6 filter: %s (%d)\n", strerror(errsv), errsv);
					retval = PORTINTERROR;
				}
			}

			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Exiting privileged user code section\n");
			#endif

		} // end if (socket created successfully)
	}
	#if (1 == IPSCAN_PRIVILEGES)
	rc = drop_privileges();
	if (rc != EXIT_SUCCESS)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: drop_privileges() returned %d\n", rc);
		retval = PORTINTERROR;
	}
	#endif
	// END OF ROOT PRIVILEGES - Revert to previous privilege level


	// If something bad has happened then return now ...
	// mustn't return to caller with root privileges, hence done here ...
	if (PORTUNKNOWN != retval)
	{
		if (-1 != sock) close(sock); // close socket if appropriate
		//
        	// More sensitive packet processing is over, so now safe(r) to regain_privileges();
        	//
		#if (1 == IPSCAN_PRIVILEGES)
        	rc = regain_privileges();
        	if (rc != EXIT_SUCCESS)
        	{
               		 IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
        	}
		#endif
		return (retval);
	}

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Post-revoke real UID  %u real GID  %u effective UID %u effective GID %u\n", getuid(), getgid(), geteuid(), getegid());
	#endif

	// -----------------------------------------------
	//
	// ICMPv6 ECHO-REQUEST TRANSMIT
	//
	// -----------------------------------------------

	memset( txicmp6hdr_ptr, 0, sizeof(struct icmp6_hdr));
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
	IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Sending PING unique data starttime=%"PRIu64" session=%"PRIu64"\n", starttime, session);
	#endif

	// capture length of custom data
	size_t customlength = 0;

	rc = snprintf(&txpackdata[ICMP6DATAOFFSET],(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET),"%"PRIu64" %"PRIu64" %u %u", starttime, session, ICMPV6_MAGIC_VALUE1, ICMPV6_MAGIC_VALUE2);
	if (rc < (int)0 || rc >= (int)(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET))
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: txpackdata snprintf returned %d, expected >=0 but < %d\n", rc, (int)(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		//
                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                //
		#if (1 == IPSCAN_PRIVILEGES)
                rc = regain_privileges();
                if (rc != EXIT_SUCCESS)
                {
                         IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                }
		#endif
		return (retval);
	}
	else
	{
		customlength = (size_t)rc;
	}

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: PING custom data length = %lu\n", customlength);
	#endif

	// Choose a packet slightly bigger than minimum size
	sendsize = ICMPV6_PACKET_SIZE;

	rc = getnameinfo((struct sockaddr *)&destination, sizeof(destination), tmpbuf, sizeof(tmpbuf), NULL, 0, NI_NUMERICHOST);
	errsv = errno;
	if (0 == rc)
	{
		#ifdef PINGDEBUG
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Transmitted destination address was %s\n", tmpbuf);
		#endif
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: getnameinfo returned bad indication %d (%s)\n",errsv, gai_strerror(errsv));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		//
                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                //
		#if (1 == IPSCAN_PRIVILEGES)
                rc = regain_privileges();
                if (rc != EXIT_SUCCESS)
                {
                         IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                }
		#endif
		return (retval);
	}

	// scatter/gather array
	memset(&txiov, 0, sizeof(txiov));
	txiov[0].iov_base = (caddr_t)&txpackdata;
	txiov[0].iov_len = sendsize;
	smsghdr.msg_iov = txiov;
	smsghdr.msg_iovlen = 1;

	rc = (int)sendmsg(sock, &smsghdr, 0);
	errsv = errno;

	if (rc < 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: sendmsg returned error, with errno %d (%s)\n", errsv, strerror(errsv));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		//
                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                //
		#if (1 == IPSCAN_PRIVILEGES)
                rc = regain_privileges();
                if (rc != EXIT_SUCCESS)
                {
                         IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                }
		#endif
		return (retval);
	}

	if (rc != (int)sendsize)
	{
		IPSCAN_LOG( LOGPREFIX"check_icmpv6_echoresponse: requested sendmsg sent %u chars to %s but sendmsg returned %d\n", sendsize, hostname, rc);
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		//
                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                //
		#if (1 == IPSCAN_PRIVILEGES)
                rc = regain_privileges();
                if (rc != EXIT_SUCCESS)
                {
                         IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                }
		#endif
		return (retval);
	}

	// -----------------------------------------------
	//
	// // ICMPv6 ECHO-REPLY RECEIVE
	//
	// -----------------------------------------------

	// indirect determines whether a host other than the intended target has replied
	int indirect = 0;
	time_t timestart = time(0);
	if (timestart < 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: time() returned bad value for timestart %d (%s)\n", errno, strerror(errno));
	}
	time_t timenow = timestart;
	unsigned int loopcount = 0;

	// Effectively a promiscuous receive of ICMPv6 packets, so need to discern which are for us
	// ... may need to go round this loop more than once ...

	while ( ((timenow - timestart) <= 1+TIMEOUTSECS) && foundit == 0)
	{
		loopcount++;
		#ifdef PINGDEBUG
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Beginning time %u through the loop.\n", loopcount);
		#endif

		pollfiledesc[0].fd = sock;
		// Want indication that there is something to read
		pollfiledesc[0].events = POLLIN;
		rc = poll(pollfiledesc, 1, 1000*TIMEOUTSECS);
		errsv = errno;
		// Capture current time for next timeout comparison
		timenow = time(0);
		if (timenow < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: time() returned bad value for timenow %d (%s)\n", errno, strerror(errno));
		}

		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: poll returned bad things : %d (%s)\n", errsv, strerror(errsv));
			continue;
		}
		else if (rc == 0)
		{
			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: poll returned 0 results\n");
			#endif
			continue;
		}

		#ifdef PINGDEBUG
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: poll returned events = %d\n", pollfiledesc[0].revents);
		#endif

		if ( (pollfiledesc[0].revents & POLLIN) != POLLIN)
		{
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: poll returned but failed to find POLLIN set: %d\n",pollfiledesc[0].revents);
			continue;
		}

		// Clear the buffer before receive
		memset(rxpacket, 0, ICMPV6_PACKET_BUFFER_SIZE+1);

		rmsghdr.msg_name = (caddr_t)&source;
		rmsghdr.msg_namelen = sizeof(source);
		memset(&rxiov, 0, sizeof(rxiov));
		rxiov[0].iov_base = (caddr_t)rxpacket;
		rxiov[0].iov_len = ICMPV6_PACKET_BUFFER_SIZE;
		rmsghdr.msg_iov = rxiov;
		rmsghdr.msg_iovlen = 1;
		rmsghdr.msg_control = (caddr_t)rxbuf;
		rmsghdr.msg_controllen = sizeof(rxbuf);
		rmsghdr.msg_flags = 0; // filled on receive
		rc = (int)recvmsg(sock, &rmsghdr, 0);
		errsv = errno;
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: recvmsg returned bad things : %d (%s)\n", errsv, strerror(errsv));
			continue;
		}
		else if (rc == 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: recvmsg returned 0 - is this a control message?\n");
			continue;
		}
		else
		{
			int rxpacketsize = rc;
			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: recvmsg returned indicating %d bytes received\n",rc);
			#endif

			if (rxpacketsize < (int)sizeof(struct icmp6_hdr))
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: Received packet too small - expected at least %d, got %d\n",(int)sizeof(struct icmp6_hdr),rxpacketsize);
				#endif
				continue;
			}

			if (rmsghdr.msg_namelen != sizeof(struct sockaddr_in6))
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: received bad peername length (namelen %u)\n",rmsghdr.msg_namelen);
				#endif
				continue;
			}

			if (((struct sockaddr *)rmsghdr.msg_name)->sa_family != AF_INET6)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: received bad peername family (sa_family %d)\n",((struct sockaddr *)rmsghdr.msg_name)->sa_family);
				#endif
				continue;
			}

			rc = getnameinfo((struct sockaddr *)&source, sizeof(source), tmpbuf, sizeof(tmpbuf), NULL, 0, NI_NUMERICHOST);
			errsv = errno;
			if (0 == rc)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Received source address was %s\n", tmpbuf);
				#endif
			}
			else
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: getnameinfo returned bad indication %d (%s)\n",errsv, gai_strerror(errsv));
				#endif
				continue;
			}

			// Store the outer packet address in case we do have a valid response from a machine(router) other than
			// the intended target
			rccharptr = inet_ntop(AF_INET6, &(source.sin6_addr), router, INET6_ADDRSTRLEN);
			errsv = errno;
			if (NULL == rccharptr)
			{
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: inet_ntop() for router returned bad indication %d (%s)\n", errsv, strerror(errsv));
				memset(router, 0, INET6_ADDRSTRLEN);
			}

			// Extract ICMPv6 type and code for checking and reporting
			rxicmp6hdr_ptr = (struct icmp6_hdr *)rxpacket;
			rxicmp6_type = rxicmp6hdr_ptr->icmp6_type;
			rxicmp6_code = rxicmp6hdr_ptr->icmp6_code;
			// Extract sequence number and ID
			rxseqno = ntohs(rxicmp6hdr_ptr->icmp6_seq);
			rxid = ntohs(rxicmp6hdr_ptr->icmp6_id);

			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
			#endif

			// Check whether our tx destination address equals our rx source
			// RFC3542 section 2.3 macro returns non-zero if addresses equal, otherwise 0
			if ( IN6_ARE_ADDR_EQUAL( &(source.sin6_addr), &(destination.sin6_addr) ) == 0 )
			{

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER IPv6 hdr src address (%s) did not match our tx dest address\n", router);
				#endif

				// if a router replied instead of the host under test then size will be original packet plus an IPv6 header and an ICMPv6 header
				if ( rxpacketsize == (int)(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sendsize) )
				{
					char tx_dst_addr[INET6_ADDRSTRLEN], orig_src_addr[INET6_ADDRSTRLEN], orig_dst_addr[INET6_ADDRSTRLEN];
					struct ip6_hdr *rx2ip6hdr_ptr;
					struct icmp6_hdr *rx2icmp6hdr_ptr;
					rx2ip6hdr_ptr = (struct ip6_hdr *)&rxpacket[sizeof(struct icmp6_hdr)];
					// struct in6_addr ip6_src and ip6_dst
					struct in6_addr orig_dst = rx2ip6hdr_ptr->ip6_dst;
					struct in6_addr orig_src = rx2ip6hdr_ptr->ip6_src;
					unsigned int nextheader = rx2ip6hdr_ptr->ip6_nxt;

					rccharptr = inet_ntop(AF_INET6, &orig_src, orig_src_addr, INET6_ADDRSTRLEN);
					errsv = errno;
					if (NULL == rccharptr)
					{
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: inet_ntop() for orig_src_addr returned bad indication %d (%s)\n", errsv, strerror(errsv));
						memset(orig_src_addr, 0, INET6_ADDRSTRLEN);
					}
					// original source address would be our IPv6 address
					// TODO - perhaps we should be checking this for completeness ...

					rccharptr = inet_ntop(AF_INET6, &orig_dst, orig_dst_addr, INET6_ADDRSTRLEN);
					errsv = errno;
					if (NULL == rccharptr)
					{
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: inet_ntop() for orig_dst_addr returned bad indication %d (%s)\n", errsv, strerror(errsv));
						memset(orig_dst_addr, 0, INET6_ADDRSTRLEN);
					}
					// original destination should match our transmitted destination address

					rccharptr = inet_ntop(AF_INET6, &(destination.sin6_addr), tx_dst_addr, INET6_ADDRSTRLEN);
					errsv = errno;
					if (NULL == rccharptr)
					{
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: inet_ntop() for tx_dst_addr returned bad indication %d (%s)\n", errsv, strerror(errsv));
						memset(tx_dst_addr, 0, INET6_ADDRSTRLEN);
					}

					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
					#endif

					// if addresses don't match then it was returned in response to another packet,
					// so this packet is not relevant to us ...
					if ( IN6_ARE_ADDR_EQUAL( &orig_dst, &(destination.sin6_addr) ) == 0)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 hdr dst %s was != our Tx dst %s\n", orig_dst_addr, tx_dst_addr);
						#endif
						continue;
					}

					// Check that the next header is ICMPv6, otherwise not in response to our tx
					if (nextheader == IPPROTO_ICMPV6)
					{
						rx2icmp6hdr_ptr = (struct icmp6_hdr *)&rxpacket[sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)];
						unsigned int rx2icmp6_type = rx2icmp6hdr_ptr->icmp6_type;
						unsigned int rx2icmp6_code = rx2icmp6hdr_ptr->icmp6_code;
						// Extract sequence number and ID
						unsigned int rx2seqno = ntohs(rx2icmp6hdr_ptr->icmp6_seq);
						unsigned int rx2id    = ntohs(rx2icmp6hdr_ptr->icmp6_id);

						// Check inner ICMPv6 packet was an ECHO_REQUEST
						if (rx2icmp6_type != ICMP6_ECHO_REQUEST)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_TYPE was not ECHO_REQUEST : %u\n", rx2icmp6_type);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check inner ICMPv6 code was 0
						if (rx2icmp6_code != 0)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_CODE was not 0\n");
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check sequence number matches what we transmitted
						if (rx2seqno != txseqno)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_SEQN was not %d\n", txseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check ID matches what we transmitted
						if (rx2id != txid)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_ID was not %d\n", txid);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check for the expected received data
						// sent:
						// "%"PRIu64" %"PRIu64" %u %u", starttime, session, ICMPV6_MAGIC_VALUE1, ICMPV6_MAGIC_VALUE2
						uint64_t rx2starttime, rx2session;
						unsigned int rx2magic1, rx2magic2;
						// add a zero termination, just in case
						rxpackdata[sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)+sendsize] = 0;	
						rc = sscanf(&rxpackdata[sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)+ICMP6DATAOFFSET], "%"PRIu64" %"PRIu64" %u %u", &rx2starttime, &rx2session, &rx2magic1, &rx2magic2);
						if (rc == 4)
						{
							if (rx2starttime != starttime)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2starttime (%"PRIu64") != starttime (%"PRIu64")\n", rx2starttime, starttime);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}
							if (rx2session != session)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2session (%"PRIu64") != session (%"PRIu64")\n", rx2session, session);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}
							if (ICMPV6_MAGIC_VALUE1 != rx2magic1)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2magic1 (%u) != expected %u\n", rx2magic1, ICMPV6_MAGIC_VALUE1);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}
							if (ICMPV6_MAGIC_VALUE2 != rx2magic2)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2magic2 (%u) != expected %u\n", rx2magic2, ICMPV6_MAGIC_VALUE2);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}

							//
							// If we get to this point then the returned packet was in response to the packet we originally
							// transmitted
							//
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Packet from %s contained our tx ECHO-REQUEST, so flagging INDIRECT response\n", router);
							#endif
							indirect = IPSCAN_INDIRECT_RESPONSE;
						}
						else
						{
							// wrong number of parameters
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 packet returned number of magic parameters (%d) != 4\n", rc);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %u; code %u; seq %u; id %u\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 next header didn't indicate an ICMPv6 packet inside\n");
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: INNER packet details: src %s ; dst %s; nextheader %u\n", orig_src_addr, orig_dst_addr, nextheader);
						#endif
						continue;
					}
				}
				else
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: OUTER address mismatch with INNER unexpected size : %d\n", rxpacketsize);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}

			}
			else
			{
				//
				// response came directly from HUT
				//
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: INFO: OUTER address is HUT match\n");
				#endif
				if ((rxicmp6_type == ICMP6_ECHO_REQUEST) || ((rxicmp6_type >4) && (rxicmp6_type <ICMP6_ECHO_REQUEST)) || (rxicmp6_type == 0))
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: OUTER address is HUT match but type %u is NOT expected\n", rxicmp6_type);
					#endif
					continue;
				}
				else
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: rxicmp6_type is %u\n", rxicmp6_type);
					#endif
				}

				if (rxicmp6_type > 0 && rxicmp6_type < 5) // ERROR responses, so will include different headers
				{
					// for an error response to our ICMPv6 ECHO REQUEST then we expect the outer IPv6 header, the ICMPv6 error plus our original payload
					if ((unsigned int)rxpacketsize < (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sendsize))
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: RECEIVED size (%d) too small to contain IPv6+ICMPv6 wrapper (%lu) and our tx payload %u\n",\
							rxpacketsize, (sizeof(struct ip6_hdr)+sizeof(struct icmp6_hdr)), sendsize);
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: RECEIVED size (%d) is sufficient (>= %lu)\n",\
							rxpacketsize, (sizeof(struct ip6_hdr)+sizeof(struct icmp6_hdr)+sendsize));
						#endif
					}

					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE (for now) : NOT ECHO REPLY\n");
					#endif
					// Next in the stack is the IPv6 header from our original packet (src=us,dst=HUT)
					// inner-ip6hdr
					struct ip6_hdr* rxiip6hdr_ptr = (struct ip6_hdr *)&rxpacket[sizeof(struct icmp6_hdr)];
					uint16_t rxiip6hdr_payloadlen = ntohs(rxiip6hdr_ptr->ip6_plen); //be16
					if (rxiip6hdr_payloadlen != sendsize)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 Header payloadlen MISMATCH, expected %u, got %u\n", rxiip6hdr_payloadlen, sendsize);
						#endif
						continue;
					}
					uint8_t rxiip6hdr_nexthdr = rxiip6hdr_ptr->ip6_nxt;// next proto should be ICMPv6
					if (rxiip6hdr_nexthdr != IPPROTO_ICMPV6)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 Header next payload MISMATCH, expected %d, got %u\n", IPPROTO_ICMPV6, rxiip6hdr_nexthdr);
						#endif
						continue;
					}
					struct in6_addr rxiip6hdr_saddr = rxiip6hdr_ptr->ip6_src; // struct in6_addr
					if ( IN6_ARE_ADDR_EQUAL( &my_tx_ipaddr, &rxiip6hdr_saddr ) == 0 )
					{
						#ifdef PINGDEBUG
						char expected[INET6_ADDRSTRLEN+1], received[INET6_ADDRSTRLEN+1];
						const char * exp = inet_ntop(AF_INET6, &my_tx_ipaddr, expected, INET6_ADDRSTRLEN);
						const char * got = inet_ntop(AF_INET6, &rxiip6hdr_saddr, received, INET6_ADDRSTRLEN);
						if (exp != NULL && got != NULL)
						{
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 Header source address MISMATCH, expected %s, got %s\n", expected, received);
						}
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER IPv6 Header source address MATCH\n");
						#endif
					}
					struct in6_addr rxiip6hdr_daddr = rxiip6hdr_ptr->ip6_dst; // struct in6_addr
					if ( IN6_ARE_ADDR_EQUAL( &(destination.sin6_addr), &rxiip6hdr_daddr ) == 0 )
					{
						#ifdef PINGDEBUG
						char expected[INET6_ADDRSTRLEN+1], received[INET6_ADDRSTRLEN+1];
						const char * exp = inet_ntop(AF_INET6, &(destination.sin6_addr), expected, INET6_ADDRSTRLEN);
						const char * got = inet_ntop(AF_INET6, &rxiip6hdr_daddr, received, INET6_ADDRSTRLEN);
						if (exp != NULL && got != NULL)
						{
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 Header destination address MISMATCH, expected %s, got %s\n", expected, received);
						}
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER IPv6 Header destination address MATCH\n");
						#endif
					}

					// Next in the stack is the ICMPv6 packet we sent
					// inner-icmp6hdr
					struct icmp6_hdr *rxiicmp6hdr_ptr = (struct icmp6_hdr *)&rxpacket[sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)];
					uint8_t rxiicmp6_type = rxiicmp6hdr_ptr->icmp6_type;
					if (rxiicmp6_type != ICMP6_ECHO_REQUEST)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 Header type MISMATCH, expected %d, got %u\n", ICMP6_ECHO_REQUEST, rxicmp6_type);
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER ICMPv6 Header type was ECHO REQ\n");
						#endif
					}
       		                 	uint8_t rxiicmp6_code = rxiicmp6hdr_ptr->icmp6_code;
					if (rxiicmp6_code != 0)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 Header code MISMATCH, expected %d, got %u\n", 0, rxicmp6_code);
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER ICMPv6 Header code was 0\n");
						#endif
					}
       		                 	uint16_t rxiicmp6_seqno = ntohs(rxiicmp6hdr_ptr->icmp6_seq);
					if (rxiicmp6_seqno != txseqno)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 Header seqno MISMATCH, expected %u, got %u\n", txseqno, rxiicmp6_seqno);
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER ICMPv6 TXSEQNO was %u\n", txseqno);
						#endif
					}
       		                 	uint16_t rxiicmp6_id = ntohs(rxiicmp6hdr_ptr->icmp6_id);
					if (rxiicmp6_id != txid)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 Header id MISMATCH, expected %u, got %u\n", txid, rxiicmp6_id);
						#endif
						continue;
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER ICMPv6 id was %u\n", txid);
						#endif
					}
					// Finally in the stack is the custom data
					// &txpackdata[ICMP6DATAOFFSET] customlength bytes
					if (memcmp(&txpackdata[ICMP6DATAOFFSET], &rxpacket[sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)], customlength) != 0)
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: custom payload MISMATCH\n");
						for (uint8_t o = 0; o<16 ; o++)
						{
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: tx[%u] = %02x, rx[%u] = %02x\n", o, txpackdata[ICMP6DATAOFFSET+o], o,\
								rxpacket[sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + o]);
						}
						#endif
						continue;
					}	
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE: INNER ICMPv6 custom data payload MATCHES\n");
						#endif
					}

				}
				else if (rxicmp6_type == ICMP6_ECHO_REQUEST)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: OUTER ICMPv6 type was %u\n", rxicmp6_type);
					#endif
					continue;
				}
				else // ECHO-REPLY
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE (for now) : straight ECHO REPLY\n");
					#endif
				}
			}

			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: CONTINUE completed non-ECHO REPLY checks - now entering return section with outer type = %u, code = %u\n", rxicmp6_type, rxicmp6_code);
			#endif
			//
			// Check what type of ICMPv6 packet we received and set return value appropriately ...
			//
			if (rxicmp6_type == ICMP6_ECHO_REPLY)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was ICMP6_ECHO_REPLY, with code %u\n", rxicmp6_code);
				#endif
			}
			else if ( rxicmp6_type == ICMP6_DST_UNREACH ) // type 1
			{
				switch ( rxicmp6_code )
				{
				case ICMP6_DST_UNREACH_NOROUTE: // code 0
					retval = PORTNOROUTE_T1C0;
					break;
				case ICMP6_DST_UNREACH_ADMIN: // code 1
					retval = PORTADMPRHBTD_T1C1;
					break;
				case ICMP6_DST_UNREACH_ADDR: // code 3
					retval = PORTADDRUNREACHABLE_T1C3;
					break;
				case ICMP6_DST_UNREACH_NOPORT: // code 4
					retval = PORTUNREACHABLE_T1C4;
					break;
				case ICMP6_DST_UNREACH_BEYONDSCOPE: // code 2
					retval = PORTBEYONDSCOPE_T1C2; 
					break;
				case 5: // code 5
					retval = PORTFAILEDPOLICY_T1C5;
					break;
				case 6: // code 6
					retval = PORTREJECTROUTE_T1C6;
					break;
				default:// other codes
					retval = PORTICMPV6_T1;
					break;
				}

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was DST_UNREACH, with code %u (%s)\n", rxicmp6_code, resultsstruct[retval].label);
				#endif

				if (-1 != sock) close(sock); // close socket if appropriate
				//
                		// More sensitive packet processing is over, so now safe(r) to regain_privileges();
                		//
				#if (1 == IPSCAN_PRIVILEGES)
                		rc = regain_privileges();
                		if (rc != EXIT_SUCCESS)
                		{
                         		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                		}
				#endif
				return (retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_PARAM_PROB) // type 4
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was PARAM_PROB, with code %u\n", rxicmp6_code);
				#endif

				retval = PORTPARAMPROB_T4;
				if (-1 != sock) close(sock); // close socket if appropriate
				//
                                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                                //
				#if (1 == IPSCAN_PRIVILEGES)
                                rc = regain_privileges();
                                if (rc != EXIT_SUCCESS)
                                {
                                        IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                                }
				#endif
				return (retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_TIME_EXCEEDED) // type 3
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was TIME_EXCEEDED, with code %u\n", rxicmp6_code);
				#endif

				retval = PORTTIMEEXCEEDED_T3;
				if (-1 != sock) close(sock); // close socket if appropriate
				//
                                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                                //
				#if (1 == IPSCAN_PRIVILEGES)
                                rc = regain_privileges();
                                if (rc != EXIT_SUCCESS)
                                {
                                        IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                                }
				#endif
				return (retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_PACKET_TOO_BIG) // type 2
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was PACKET_TOO_BIG, with code %u\n", rxicmp6_code);
				#endif

				retval = PORTPKTTOOBIG_T2;
				if (-1 != sock) close(sock); // close socket if appropriate
				//
                                // More sensitive packet processing is over, so now safe(r) to regain_privileges();
                                //
				#if (1 == IPSCAN_PRIVILEGES)
                                rc = regain_privileges();
                                if (rc != EXIT_SUCCESS)
                                {
                                        IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
                                }
				#endif
				return (retval+indirect);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: unhandled ICMPv6 packet TYPE %u CODE %u\n", rxicmp6_type, rxicmp6_code);
				continue;
			}

			//
			// If we get this far then packet is a direct ECHO-REPLY, so we can check the contents
			//

			if (rxseqno != txseqno)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: Sequence number mismatch - expected %d\n", txseqno);
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				#endif
				continue;
			}

			if (rxid != txid)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: ICMP6 id mismatch - expected %d\n", txid);
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				#endif
				continue;
			}

			// Check for the expected received data
			// sent:
			// "%"PRIu64" %"PRIu64" %u %u", starttime, session, ICMPV6_MAGIC_VALUE1, ICMPV6_MAGIC_VALUE2
			uint64_t rxstarttime, rxsession;
			unsigned int rxmagic1, rxmagic2;

			// add a zero termination, just in case
			rxpackdata[sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)+customlength] = 0;	
			//
			rc = sscanf(&rxpackdata[ICMP6DATAOFFSET], "%"PRIu64" %"PRIu64" %u %u", &rxstarttime, &rxsession, &rxmagic1, &rxmagic2);
			if (rc == 4)
			{
				if (rxstarttime != starttime)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: magic data rxstarttime (%"PRIu64") != starttime (%"PRIu64")\n", rxstarttime, starttime);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}
				if (rxsession != session)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: magic data rxsession (%"PRIu64") != session (%"PRIu64")\n", rxsession, session);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}
				if (ICMPV6_MAGIC_VALUE1 != rxmagic1)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: RX magic data 1 (%u) != expected %u\n", rxmagic1, ICMPV6_MAGIC_VALUE1);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}
				if (ICMPV6_MAGIC_VALUE2 != rxmagic2)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: RX magic data 2 (%u) != expected %u\n", rxmagic2, ICMPV6_MAGIC_VALUE2);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}

				//
				// if we get to this point then everything matches ...
				//
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Everything matches - it was our expected ICMPv6 ECHO_RESPONSE\n");
				#endif
				foundit = 1;
			}
			else
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: number of magic parameters mismatched, got %d, expected 4\n", rc);
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %u; code %u; id %u; seqno %u\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				#endif
				continue;
			}

		} // end of if (received some bytes)

	} // end of while

	if (foundit == 1) retval = PORTECHOREPLY; else retval = PORTECHONOREPLY;

	//
	// More sensitive packet processing is over, so now safe(r) to regain_privileges();
	//
	#if (1 == IPSCAN_PRIVILEGES)
	rc = regain_privileges();
	if (rc != EXIT_SUCCESS)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ERROR: regain_privileges() returned %d\n", rc);
		retval = PORTINTERROR;
	}
	#endif

	// return the status
	if (-1 != sock) close(sock); // close socket if appropriate


	// Make sure we wait long enough in all cases
	sleep(IPSCAN_MINTIME_PER_PORT);

	return (retval);
}

