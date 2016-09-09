//    IPscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2016 Tim Chappell.
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
// 0.1				initial version after splitting from ipscan_checks.c
// 0.2				add prefixes to debug log output
// 0.3				move to memset()
// 0.4				ensure minimum timings are met
// 0.5				ensure txid doesn't exceed 16-bits (move to random session ID)
// 0.6				clear msghdr.msg_flags
// 0.7				add time() checks

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

// Define offset into ICMPv6 packet where user-defined data resides
#define ICMP6DATAOFFSET sizeof(struct icmp6_hdr)

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

	unsigned int txid = (unsigned int)(session & 0xFFFF); // Maximum 16 bits
	unsigned int rxid;
	unsigned int txseqno = ICMPV6_MAGIC_SEQ; // MAGIC number - assume no reason to start at 1?
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

	// Copy the resulting address into our destination
	memcpy(&destination, res->ai_addr, res->ai_addrlen);
	// Done with the address info now, so free the area
	freeaddrinfo(res);

	// Set default logged router address to "unset"
	rc = snprintf(router, INET6_ADDRSTRLEN, "unset");
	if (rc < 0 || rc >= INET6_ADDRSTRLEN)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Failed to unset logged router address, rc was %d\n", rc);
		retval = PORTINTERROR;
	}

	// Get root privileges in order to create the raw socket

	uid_t uid = getuid();
	uid_t gid = getgid();

	#ifdef PINGDEBUG
	uid_t euid = geteuid();
	uid_t egid = getegid();
	#endif

	#ifdef PINGDEBUG
	IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Entered with real UID  %d  real GID  %d  effective UID %d  effective GID %d\n", uid, gid, euid, egid);
	#endif

	rc = setuid(0);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: setuid: failed to gain root privileges - is setuid permission set?\n");
		retval = PORTINTERROR;
	}

	rc = setgid(0);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: setgid: failed to gain root privileges - is setgid permission set?\n");
		retval = PORTINTERROR;
	}

	// run with ROOT privileges, keep section to a minimum
	if (retval == PORTUNKNOWN)
	{
			sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			errsv = errno;
			if (sock < 0)
			{
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: socket: Error : %s (%d) for host %s\n", strerror(errsv), errsv, hostname);
				retval = PORTINTERROR;
			}
			else
			{
				memset(&timeout, 0, sizeof(timeout));
				timeout.tv_sec = TIMEOUTSECS;
				timeout.tv_usec = TIMEOUTMICROSECS;

				rc = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
				errsv = errno;
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
					retval = PORTINTERROR;
				}

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
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: setsockopt: Error setting ICMPv6 filter: %s (%d)\n", strerror(errsv), errsv);
					retval = PORTINTERROR;
				}

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Exiting privileged user code section\n");
				#endif

			} // end if (socket created successfully)
	}

	// END OF ROOT PRIVILEGES - Revert to previous privilege level
	rc = setgid(gid);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: setgid: failed to revoke root gid privileges\n");
		retval = PORTINTERROR;
	}

	rc = setuid(uid);
	if (rc != 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: setuid: failed to revoke root uid privileges\n");
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
	IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Post-revoke real UID  %d real GID  %d effective UID %d effective GID %d\n", getuid (), getgid (), geteuid(), getegid());
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
	IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Sending PING unique data starttime=%"PRId64" session=%"PRId64"\n", starttime, session);
	#endif

	rc = snprintf(&txpackdata[ICMP6DATAOFFSET],(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET),"%"PRId64" %"PRId64" %d %d", starttime, session, ICMPV6_MAGIC_VALUE1, ICMPV6_MAGIC_VALUE2);
	if (rc < (int)0 || rc >= (int)(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET))
	{
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: txpackdata snprintf returned %d, expected >=0 but < %d\n", rc, (int)(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

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
		return(retval);
	}

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
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: sendmsg returned error, with errno %d (%s)\n", errsv, strerror(errsv));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

	if (rc != (int)sendsize)
	{
		IPSCAN_LOG( LOGPREFIX"check_icmpv6_echoresponse: requested sendmsg sent %d chars to %s but sendmsg returned %d\n", sendsize, hostname, rc);
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
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
		IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: Beginning time %d through the loop.\n", loopcount);
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
		rc = recvmsg(sock, &rmsghdr, 0);
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
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: received bad peername length (namelen %d)\n",rmsghdr.msg_namelen);
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
			inet_ntop(AF_INET6, &(source.sin6_addr), router, INET6_ADDRSTRLEN);

			// Extract ICMPv6 type and code for checking and reporting
			rxicmp6hdr_ptr = (struct icmp6_hdr *)rxpacket;
			rxicmp6_type = rxicmp6hdr_ptr->icmp6_type;
			rxicmp6_code = rxicmp6hdr_ptr->icmp6_code;
			// Extract sequence number and ID
			rxseqno = htons(rxicmp6hdr_ptr->icmp6_seq);
			rxid = htons(rxicmp6hdr_ptr->icmp6_id);

			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
			#endif

			// Check whether our tx destination address equals our rx source
			// RFC3542 section 2.3 macro returns non-zero if addresses equal, otherwise 0
			if ( IN6_ARE_ADDR_EQUAL( &(source.sin6_addr), &(destination.sin6_addr) ) == 0 )
			{

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER IPv6 hdr src address (%s) did not match our tx dest address\n", router);
				#endif

				// if a router replied instead of the host under test then size will be original packet plus an IPv6 header
				if ( rxpacketsize == (int)(sizeof(struct ip6_hdr) + 8 + sendsize) )
				{
					char tx_dst_addr[INET6_ADDRSTRLEN], orig_src_addr[INET6_ADDRSTRLEN], orig_dst_addr[INET6_ADDRSTRLEN];
					struct ip6_hdr *rx2ip6hdr_ptr;
					struct icmp6_hdr *rx2icmp6hdr_ptr;
					rx2ip6hdr_ptr = (struct ip6_hdr *)&rxpacket[sizeof(struct icmp6_hdr)];
					// struct in6_addr ip6_src and ip6_dst
					struct in6_addr orig_dst = rx2ip6hdr_ptr->ip6_dst;
					struct in6_addr orig_src = rx2ip6hdr_ptr->ip6_src;
					unsigned int nextheader = rx2ip6hdr_ptr->ip6_nxt;

					inet_ntop(AF_INET6, &orig_src, orig_src_addr, INET6_ADDRSTRLEN);
					// original source address would be our IPv6 address
					// TODO - perhaps we should be checking this for completeness ...

					inet_ntop(AF_INET6, &orig_dst, orig_dst_addr, INET6_ADDRSTRLEN);
					// original destination should match our transmitted destination address

					inet_ntop(AF_INET6, &(destination.sin6_addr), tx_dst_addr, INET6_ADDRSTRLEN);

					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
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
						unsigned int rx2seqno = htons(rx2icmp6hdr_ptr->icmp6_seq);
						unsigned int rx2id = htons(rx2icmp6hdr_ptr->icmp6_id);

						// Check inner ICMPv6 packet was an ECHO_REQUEST
						if (rx2icmp6_type != ICMP6_ECHO_REQUEST)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_TYPE was not ECHO_REQUEST : %d\n", rx2icmp6_type);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check inner ICMPv6 code was 0
						if (rx2icmp6_code != 0)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_CODE was not 0\n");
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check sequence number matches what we transmitted
						if (rx2seqno != txseqno)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_SEQN was not %d\n", txseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check ID matches what we transmitted
						if (rx2id != txid)
						{
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6_ID was not %d\n", txid);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}

						// Check for the expected received data
						// sent:
						// "%"PRId64" %"PRId64" ICMPV6_MAGIC_VALUE1 ICMPV6_MAGIC_VALUE2", starttime, session
						uint64_t rx2starttime, rx2session;
						unsigned int rx2magic1, rx2magic2;

						rc = sscanf(&rxpackdata[sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)+ICMP6DATAOFFSET], "%"PRId64" %"PRId64" %d %d", &rx2starttime, &rx2session, &rx2magic1, &rx2magic2);
						if (rc == 4)
						{
							if (rx2starttime != starttime)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2starttime (%"PRId64") != starttime (%"PRId64")\n", rx2starttime, starttime);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}
							if (rx2session != session)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2session (%"PRId64") != session (%"PRId64")\n", rx2session, session);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}
							if (ICMPV6_MAGIC_VALUE1 != rx2magic1)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2magic1 (%d) != expected %d\n", rx2magic1, ICMPV6_MAGIC_VALUE1);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								#endif
								continue;
							}
							if (ICMPV6_MAGIC_VALUE2 != rx2magic2)
							{
								#ifdef PINGDEBUG
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER ICMPv6 magic data rx2magic2 (%d) != expected %d\n", rx2magic2, ICMPV6_MAGIC_VALUE2);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
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
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							#endif
							continue;
						}
					}
					else
					{
						#ifdef PINGDEBUG
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: INNER IPv6 next header didn't indicate an ICMPv6 packet inside\n");
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
						IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
						#endif
						continue;
					}
				}
				else
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: OUTER address mismatch with INNER unexpected size : %d\n", rxpacketsize);

					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}

			}

            		//
			// Check what type of ICMPv6 packet we received and set return value appropriately ...
			//
			if (rxicmp6_type == ICMP6_ECHO_REPLY)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was ICMP6_ECHO_REPLY, with code %d\n", rxicmp6_code);
				#endif
			}
			else if ( rxicmp6_type == ICMP6_DST_UNREACH )
			{
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

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was DST_UNREACH, with code %d (%s)\n", rxicmp6_code, resultsstruct[retval].label);
				#endif

				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_PARAM_PROB)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was PARAM_PROB, with code %d\n", rxicmp6_code);
				#endif

				retval = PORTPARAMPROB;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_TIME_EXCEEDED)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was TIME_EXCEEDED, with code %d\n", rxicmp6_code);
				#endif

				retval = PORTNOROUTE;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_PACKET_TOO_BIG)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: ICMP6_TYPE was PACKET_TOO_BIG, with code %d\n", rxicmp6_code);
				#endif

				retval = PORTPKTTOOBIG;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: RESTART: unhandled ICMPv6 packet TYPE was %d CODE was %d\n", rxicmp6_type, rxicmp6_code);
				continue;
			}

			//
			// If we get this far then packet is a direct ECHO-REPLY, so we can check the contents
			//

			if (rxseqno != txseqno)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: Sequence number mismatch - expected %d\n", txseqno);
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				#endif
				continue;
			}

			if (rxid != txid)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: ICMP6 id mismatch - expected %d\n", txid);
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				#endif
				continue;
			}

			// Check for the expected received data
			// sent:
			// "%"PRId64" %"PRId64" ICMPV6_MAGIC_VALUE1 ICMPV6_MAGIC_VALUE2", starttime, session
			uint64_t rxstarttime, rxsession;
			unsigned int rxmagic1, rxmagic2;

			rc = sscanf(&rxpackdata[ICMP6DATAOFFSET], "%"PRId64" %"PRId64" %d %d", &rxstarttime, &rxsession, &rxmagic1, &rxmagic2);
			if (rc == 4)
			{
				if (rxstarttime != starttime)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: magic data rxstarttime (%"PRId64") != starttime (%"PRId64")\n", rxstarttime, starttime);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}
				if (rxsession != session)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: magic data rxsession (%"PRId64") != session (%"PRId64")\n", rxsession, session);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}
				if (ICMPV6_MAGIC_VALUE1 != rxmagic1)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: RX magic data 1 (%d) != expected %d\n", rxmagic1, ICMPV6_MAGIC_VALUE1);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					#endif
					continue;
				}
				if (ICMPV6_MAGIC_VALUE2 != rxmagic2)
				{
					#ifdef PINGDEBUG
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARD: RX magic data 2 (%d) != expected %d\n", rxmagic2, ICMPV6_MAGIC_VALUE2);
					IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
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
				IPSCAN_LOG( LOGPREFIX "check_icmpv6_echoresponse: DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				#endif
				continue;
			}

		} // end of if (received some bytes)

	} // end of while

	if (foundit == 1) retval = ECHOREPLY; else retval = ECHONOREPLY;

	// return the status
	if (-1 != sock) close(sock); // close socket if appropriate

	// Make sure we wait long enough in all cases
	sleep(IPSCAN_MINTIME_PER_PORT);

	return(retval);
}

