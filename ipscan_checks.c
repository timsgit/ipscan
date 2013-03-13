//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2013 Tim Chappell.
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
// 0.05 - add support for indirect ICMPv6 host responses
// 0.06 - improved default ICMPv6 packet logging
// 0.07 - further buffer overflow prevention
// 0.08 - correct printf cast
// 0.09 - yet more ICMPv6 logging improvements
// 0.10 - minor include correction for FreeBSD support
// 0.11 - add parallel port scan function
// 0.12 - fix some mis-signed comparisons, unused variables and parameters
// 0.13 - add service names to results table (modification to portlist, now structure)
// 0.14 - add UDP support

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

	unsigned int txid = (unsigned int)session;
	unsigned int rxid;
	unsigned int txseqno = ICMPV6_MAGIC_SEQ; // MAGIC number - assume no reason to start at 1?
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

	// Set default logged router address to "unset"
	rc = snprintf(router, INET6_ADDRSTRLEN, "unset");
	if (rc < 0 || rc >= INET6_ADDRSTRLEN)
	{
		IPSCAN_LOG( LOGPREFIX "Failed to unset logged router address, rc was %d\n", rc);
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
				IPSCAN_LOG( LOGPREFIX "Exiting privileged user code section\n");
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

	rc = snprintf(&txpackdata[ICMP6DATAOFFSET],(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET),"%"PRId64" %"PRId64" %d %d", starttime, session, ICMPV6_MAGIC_VALUE1, ICMPV6_MAGIC_VALUE2);
	if (rc < (int)0 || rc >= (int)(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET))
	{
		IPSCAN_LOG( LOGPREFIX "snprintf returned %d, expected >=0 but < %d\n", rc, (int)(ICMPV6_PACKET_SIZE-ICMP6DATAOFFSET));
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
		IPSCAN_LOG( LOGPREFIX "Transmitted destination address was %s\n", tmpbuf);
		#endif
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "RESTART: getnameinfo returned bad indication %d (%s)\n",errsv, gai_strerror(errsv));
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
		IPSCAN_LOG( LOGPREFIX "sendmsg returned error, with errno %d (%s)\n", errsv, strerror(errsv));
		retval = PORTINTERROR;
		if (-1 != sock) close(sock); // close socket if appropriate
		return(retval);
	}

	if (rc != (int)sendsize)
	{
		IPSCAN_LOG( LOGPREFIX"requested sendmsg sent %d chars to %s but sendmsg returned %d\n", sendsize, hostname, rc);
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
		IPSCAN_LOG( LOGPREFIX "poll returned events = %d\n", pollfiledesc[0].revents);
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
			int rxpacketsize = rc;
			#ifdef PINGDEBUG
			IPSCAN_LOG( LOGPREFIX "recvmsg returned indicating %d bytes received\n",rc);
			#endif

			if (rxpacketsize < (int)sizeof(struct icmp6_hdr))
			{
				IPSCAN_LOG( LOGPREFIX "DISCARD: Received packet too small - expected at least %d, got %d\n",(int)sizeof(struct icmp6_hdr),rxpacketsize);
				continue;
			}

			if (rmsghdr.msg_namelen != sizeof(struct sockaddr_in6))
			{
				IPSCAN_LOG( LOGPREFIX "DISCARD: received bad peername length (namelen %d)\n",rmsghdr.msg_namelen);
				continue;
			}

			if (((struct sockaddr *)rmsghdr.msg_name)->sa_family != AF_INET6)
			{
				IPSCAN_LOG( LOGPREFIX "DISCARD: received bad peername family (sa_family %d)\n",((struct sockaddr *)rmsghdr.msg_name)->sa_family);
				continue;
			}

			rc = getnameinfo((struct sockaddr *)&source, sizeof(source), tmpbuf, sizeof(tmpbuf), NULL, 0, NI_NUMERICHOST);
			errsv = errno;
			if (0 == rc)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "Received source address was %s\n", tmpbuf);
				#endif
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "DISCARD: getnameinfo returned bad indication %d (%s)\n",errsv, gai_strerror(errsv));
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
			IPSCAN_LOG( LOGPREFIX "OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
			#endif

			// Check whether our tx destination address equals our rx source
			// RFC3542 section 2.3 macro returns non-zero if addresses equal, otherwise 0
			if ( IN6_ARE_ADDR_EQUAL( &(source.sin6_addr), &(destination.sin6_addr) ) == 0 )
			{

				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "OUTER IPv6 hdr src address (%s) did not match our tx dest address\n", router);
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
					IPSCAN_LOG( LOGPREFIX "INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
					#endif

					// if addresses don't match then it was returned in response to another packet,
					// so this packet is not relevant to us ...
					if ( IN6_ARE_ADDR_EQUAL( &orig_dst, &(destination.sin6_addr) ) == 0)
					{
						IPSCAN_LOG( LOGPREFIX "DISCARD: INNER IPv6 hdr dst %s was != our Tx dst %s\n", orig_dst_addr, tx_dst_addr);
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
							IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6_TYPE was not ECHO_REQUEST : %d\n", rx2icmp6_type);
							IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							continue;
						}

						// Check inner ICMPv6 code was 0
						if (rx2icmp6_code != 0)
						{
							IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6_CODE was not 0\n");
							IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							continue;
						}

						// Check sequence number matches what we transmitted
						if (rx2seqno != txseqno)
						{
							IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6_SEQN was not %d\n", txseqno);
							IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							continue;
						}

						// Check ID matches what we transmitted
						if (rx2id != txid)
						{
							IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6_ID was not %d\n", txid);
							IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
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
								IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6 magic data rx2starttime (%"PRId64") != starttime (%"PRId64")\n", rx2starttime, starttime);
								IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								continue;
							}
							if (rx2session != session)
							{
								IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6 magic data rx2session (%"PRId64") != session (%"PRId64")\n", rx2session, session);
								IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								continue;
							}
							if (ICMPV6_MAGIC_VALUE1 != rx2magic1)
							{
								IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6 magic data rx2magic1 (%d) != expected %d\n", rx2magic1, ICMPV6_MAGIC_VALUE1);
								IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								continue;
							}
							if (ICMPV6_MAGIC_VALUE2 != rx2magic2)
							{
								IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6 magic data rx2magic2 (%d) != expected %d\n", rx2magic2, ICMPV6_MAGIC_VALUE2);
								IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
								IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
								continue;
							}

							//
							// If we get to this point then the returned packet was in response to the packet we originally
							// transmitted
							//
							#ifdef PINGDEBUG
							IPSCAN_LOG( LOGPREFIX "Packet from %s contained our tx ECHO-REQUEST, so flagging INDIRECT response\n", router);
							#endif
							indirect = IPSCAN_INDIRECT_RESPONSE;
						}
						else
						{
							// wrong number of parameters
							IPSCAN_LOG( LOGPREFIX "DISCARD: INNER ICMPv6 packet returned number of magic parameters (%d) != 4\n", rc);
							IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
							IPSCAN_LOG( LOGPREFIX "DISCARDED INNER packet icmp6 details: type %d; code %d; seq %d; id %d\n", rx2icmp6_type, rx2icmp6_code, rx2seqno, rx2id);
							continue;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "DISCARD: INNER IPv6 next header didn't indicate an ICMPv6 packet inside\n");
						IPSCAN_LOG( LOGPREFIX "OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
						IPSCAN_LOG( LOGPREFIX "INNER packet details: src %s ; dst %s; nextheader %d\n", orig_src_addr, orig_dst_addr, nextheader);
						continue;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "DISCARD: OUTER address mismatch with INNER unexpected size : %d\n", rxpacketsize);
					IPSCAN_LOG( LOGPREFIX "OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					continue;
				}

			}

            		//
			// Check what type of ICMPv6 packet we received and set return value appropriately ...
			//
			if (rxicmp6_type == ICMP6_ECHO_REPLY)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was ICMP6_ECHO_REPLY, with code %d\n", rxicmp6_code);
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
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was DST_UNREACH, with code %d (%s)\n", rxicmp6_code, resultsstruct[retval].label);
				#endif

				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_PARAM_PROB)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was PARAM_PROB, with code %d\n", rxicmp6_code);
				#endif

				retval = PORTPARAMPROB;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_TIME_EXCEEDED)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was TIME_EXCEEDED, with code %d\n", rxicmp6_code);
				#endif

				retval = PORTNOROUTE;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else if (rxicmp6_type == ICMP6_PACKET_TOO_BIG)
			{
				#ifdef PINGDEBUG
				IPSCAN_LOG( LOGPREFIX "ICMP6_TYPE was PACKET_TOO_BIG, with code %d\n", rxicmp6_code);
				#endif

				retval = PORTPKTTOOBIG;
				if (-1 != sock) close(sock); // close socket if appropriate
				return(retval+indirect);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "RESTART: unhandled ICMPv6 packet TYPE was %d CODE was %d\n", rxicmp6_type, rxicmp6_code);
				continue;
			}

			//
			// If we get this far then packet is a direct ECHO-REPLY, so we can check the contents
			//

			if (rxseqno != txseqno)
			{
				IPSCAN_LOG( LOGPREFIX "DISCARD: Sequence number mismatch - expected %d\n", txseqno);
				IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
				continue;
			}

			if (rxid != txid)
			{
				IPSCAN_LOG( LOGPREFIX "DISCARD: ICMP6 id mismatch - expected %d\n", txid);
				IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
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
					IPSCAN_LOG( LOGPREFIX "DISCARD: magic data rxstarttime (%"PRId64") != starttime (%"PRId64")\n", rxstarttime, starttime);
					IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					continue;
				}
				if (rxsession != session)
				{
					IPSCAN_LOG( LOGPREFIX "DISCARD: magic data rxsession (%"PRId64") != session (%"PRId64")\n", rxsession, session);
					IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					continue;
				}
				if (ICMPV6_MAGIC_VALUE1 != rxmagic1)
				{
					IPSCAN_LOG( LOGPREFIX "DISCARD: RX magic data 1 (%d) != expected %d\n", rxmagic1, ICMPV6_MAGIC_VALUE1);
					IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
					continue;
				}
				if (ICMPV6_MAGIC_VALUE2 != rxmagic2)
				{
					IPSCAN_LOG( LOGPREFIX "DISCARD: RX magic data 2 (%d) != expected %d\n", rxmagic2, ICMPV6_MAGIC_VALUE2);
					IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
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
				IPSCAN_LOG( LOGPREFIX "DISCARD: number of magic parameters mismatched, got %d, expected 4\n", rc);
				IPSCAN_LOG( LOGPREFIX "DISCARDED OUTER packet details: src %s; type %d; code %d; id %d; seqno %d\n", router, rxicmp6_type, rxicmp6_code, rxid, rxseqno);
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

	error = snprintf(portnum, 8,"%d", port);
	if (error < 0 || error >= 8)
	{
		IPSCAN_LOG( LOGPREFIX "Failed to write portnum, rc was %d\n", error);
		retval = PORTINTERROR;
	}

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
				// IPSCAN_LOG( LOGPREFIX "Skipping, because ai_family != AF_INET6 (actually %d)\n",aip->ai_family);
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


int check_tcp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, struct portlist_struc *portlist)
{
	int i,rc,result;
	pid_t childpid = fork();
	if (childpid > 0)
	{
		// parent
		#ifdef PARLLDEBUG
		IPSCAN_LOG( LOGPREFIX "INFO: check_tcp_ports_parll() forked and started child PID=%d\n",childpid);
		#endif
	}
	else if (childpid == 0)
	{
		#ifdef PARLLDEBUG
		IPSCAN_LOG( LOGPREFIX "INFO: startindex %d, todo %d\n",portindex,todo);
		#endif
		// child - actually do the work here - and then exit successfully
		char unusedfield[8] = "unused";
		for (i = 0 ; i <(int)todo ; i++)
		{
			uint16_t port = portlist[portindex+i].port_num;
			result = check_tcp_port(hostname, port);
			// Put results into database
			rc = write_db(host_msb, host_lsb, timestamp, session, (port + IPSCAN_PROTO_TCP), result, unusedfield );
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "WARNING : check_tcp_port_parll() write_db returned %d\n", rc);
			}
		}
		// Usual practive to have children _exit() whilst the parent calls exit()
		_exit(EXIT_SUCCESS);
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "fork() failed childpid=%d, errno=%d(%s)\n", childpid, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return( (int)childpid );
}

/***************************************************************************************************************
 * UDP
 *
 **************************************************************************************************************/
int check_udp_port(char * hostname, uint16_t port)
{
	char txmessage[UDP_BUFFER_SIZE],rxmessage[UDP_BUFFER_SIZE];
	struct sockaddr_in6 remoteaddr;
	struct timeval timeout;
	int rc = 0, i;
	int fd = -1;

	// buffer for logging entries
	#ifdef UDPDEBUG
	int udplogbuffersize = LOGENTRYSIZE;
	char udplogbuffer[ (LOGENTRYSIZE + 1) ];
	char *udplogbufferptr = &udplogbuffer[0];
	#endif

	// Holds length of transmitted UDP packet, which since they are representative packets, depends on the port being tested
	int len = 0;

	// set return value to a known default
	int retval = PORTUNKNOWN;

	rc = inet_pton(AF_INET6, hostname, &(remoteaddr.sin6_addr));
	if (rc != 1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad inet_pton() call, returned %d with errno %d (%s)\n", rc, errno, strerror(errno));
		retval = PORTINTERROR;
	}
	remoteaddr.sin6_port = htons(port);
	remoteaddr.sin6_family = AF_INET6;
	remoteaddr.sin6_flowinfo = 0;

	// Attempt to create a socket
	if (retval == PORTUNKNOWN)
	{
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd == -1)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad socket call, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
		else
		{
			bzero(&timeout, sizeof(timeout));
			timeout.tv_sec = UDPTIMEOUTSECS;
			timeout.tv_usec = 0;

			rc = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
			if (rc < 0)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errno, strerror(errno));
				retval = PORTINTERROR;
			}
		}
	}

	if (retval == PORTUNKNOWN) // continue
	{
		bzero(&timeout, sizeof(timeout));
		timeout.tv_sec = UDPTIMEOUTSECS;
		timeout.tv_usec = 0;

		rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

	if (retval == PORTUNKNOWN)
	{
		// Need to connect, since otherwise asynchronous ICMPv6 responses will not be delivered to us
		rc = connect( fd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr) );
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad connect() attempt, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}


	if (retval == PORTUNKNOWN)
	{
		// Fill the txmessage with the appropriate message (depends on service)
		switch (port)
		{

			// DNS query
			case 53:
			{
				/*
				Header - 12 bytes
				Contains fields that describe the type of message and provide important information about it.
				Also contains fields that indicate the number of entries in the other sections of the message.
				Question carries one or more “questions”, that is, queries for information being sent to a DNS name server.
				Answer carries one or more resource records that answer the question(s) indicated in the Question section above.
				Authority contains one or more resource records that point to authoritative name servers that can be used to
				continue the resolution process.
				Additional conveys one or more resource records that contain additional information related to the query that
				is not strictly necessary to answer the queries (questions) in the message.
				*/
				// ID - identifier - 16 bit field
				txmessage[0]= 21;
				txmessage[1]= 06;
				// QR - query/response flag - 0=query. 1 bit field
				// OP - opcode - 0=query,2=status. 4 bit field
				// AA - Authoritative Answer flag. 1 bit field
				// TC - truncation flag. 1 bit field
				// RD - recursion desired - 0=not desired, 1=desired. 1 bit field
				// RA - recursion available. 1 bit field
				// Z  - reserved. 3 bit field
				// Rcode - result code - 0=no error, 4=not implemented
				txmessage[2]= 16; // 16 for server status query
				txmessage[3]= 0;
				// QDCOUNT - question count - 16 bit field
				txmessage[4]= 0;
				txmessage[5]= 1;
				// ANCOUNT - answer record count - 16 bit field
				txmessage[6]= 0;
				txmessage[7]= 0;
				// NSCOUNT - authority record count (NS=name server) - 16 bit field
				txmessage[8]= 0;
				txmessage[9]= 0;
				// ARCOUNT - 16 bit field
				txmessage[10]= 0;
				txmessage[11]= 0;
				// Question section
				txmessage[12]= 4;
				// Need one extra octet for trailing 0, however this will be overwritten
				// by the length of the next part of the host name in standard DNS format
				rc = snprintf(&txmessage[13], 5, "%s", "www4");
				txmessage[17]= 4;
				rc = snprintf(&txmessage[18], 5, "%s", "ipv6");
				txmessage[22]= 15;
				rc = snprintf(&txmessage[23], 16, "%s", "chappell-family");
				txmessage[38]= 3;
				rc = snprintf(&txmessage[39], 4, "%s", "com");
				txmessage[42]= 0;
				// Question type - 1 = host address, 2=NS, 255 is request all
				txmessage[43] = 0;
				txmessage[44] = 255;
				// Qclass - 1=INternet
				txmessage[45] = 0;
				txmessage[46] = 1;
				len=47;
				break;
			}

			case 69:
			{
				/* TFTP
				TFTP supports five types of packets, all of which have been mentioned
				   above:

				          opcode  operation
				            1     Read request (RRQ)
				            2     Write request (WRQ)
				            3     Data (DATA)
				            4     Acknowledgment (ACK)
				            5     Error (ERROR)

				   The TFTP header of a packet contains the  opcode  associated  with
				   that packet.

				            2 bytes     string    1 byte     string   1 byte
				            ------------------------------------------------
				           | Opcode |  Filename  |   0  |    Mode    |   0  |
				            ------------------------------------------------

				                       Figure 5-1: RRQ/WRQ packet

				    The mode field contains the string "netascii", "octet", or "mail"
				    (or any combination of upper and lower case, such as "NETASCII",
				    NetAscii", etc.) in netascii indicating the three modes defined in
				    the protocol.                                                   */

				// Create a pseudo-random filename based on the current pid
				len = snprintf(&txmessage[0], UDP_BUFFER_SIZE, "%c%c%s%d%coctet%c",0,1,"/filename_tjc_",getpid(),0,0);
				if (len < 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for tftp, returned %d\n", len);
					len = 0;
					retval = PORTINTERROR;
				}
				break;
			}



			case 123:
			{
			/* NTP
			 * from RFC4330
								1                   2                   3
				  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9  0  1
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |LI | VN  |Mode |    Stratum    |     Poll      |   Precision    |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                          Root  Delay                           |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                       Root  Dispersion                         |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                     Reference Identifier                       |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                                                                |
				 |                    Reference Timestamp (64)                    |
				 |                                                                |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                                                                |
				 |                    Originate Timestamp (64)                    |
				 |                                                                |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                                                                |
				 |                     Receive Timestamp (64)                     |
				 |                                                                |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 |                                                                |
				 |                     Transmit Timestamp (64)                    |
				 |                                                                |
				 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  */

				txmessage[0] = ((NTP_LI << 5) + (NTP_VN << 3) + ( NTP_MODE ));
				txmessage[1] = NTP_STRATUM;
				txmessage[2] = NTP_POLL;
				txmessage[3] = NTP_PRECISION;
				// Clear out 11 32-bit words (Root Delay through transmit timestamp)
				bzero(&txmessage[4], 44);
				len = 48;
				break;
			}


			case 1900:
			{
				// UPnP
				// taken from http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
				//
				len = snprintf(&txmessage[0], UDP_BUFFER_SIZE, \
				"M-SEARCH * HTTP/1.1\r\nHost:[%s]:1900\r\nMan: \"ssdp:discover\"\r\nMX:1\r\nST: \"ssdp:all\"\r\nUSER-AGENT: linux/2.6 UPnP/1.1 TimsTester/1.0\r\n\r\n", hostname);
				if (len < 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for upnp, returned %d\n", len);
					len = 0;
					retval = PORTINTERROR;
				}

				break;
			}



			default:
			{
				// Unhandled port
				retval = PORTINTERROR;
				IPSCAN_LOG( LOGPREFIX "check_udp_port: FATAL ERROR - Request for unhandled UDP port %d\n", port);
				break;
			}
		}
	}

	if (retval == PORTUNKNOWN)
	{
		rc = write(fd,&txmessage,len);
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad write() attempt, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
		else
		{
			#ifdef UDPDEBUG
			IPSCAN_LOG( LOGPREFIX "check_udp_port: write() returned %d\n", rc);
			#endif
		}
	}

	if (retval == PORTUNKNOWN)
	{
		rc=read(fd,&rxmessage,UDP_BUFFER_SIZE);
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad read(), returned %d (%s)\n", errno, strerror(errno));

			int errsv = errno ;
			// cycle through the expected list of results
			for (i = 0; PORTEOL != resultsstruct[i].returnval && PORTUNKNOWN == retval ; i++)
			{

				// Find a matching connect returncode and also errno, if appropriate
				if (resultsstruct[i].connrc == rc)
				{
					// Set the returnvalue if we find a match
					if ( rc == -1 && resultsstruct[i].connerrno == errsv )
					{
						retval = resultsstruct[i].returnval;
					}
				}
			}

			#ifdef UDPDEBUG
			IPSCAN_LOG( LOGPREFIX "check_udp_port: found port %d returned read = %d, errsv = %d(%s)\n",port, rc, errsv, strerror(errsv));
			#endif

			// If we haven't found a matching returncode/errno then log this ....
			if (PORTUNKNOWN == retval)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: read() unexpected response, errno is : %d (%s) for host %s port %d\n", \
						errsv, strerror(errsv), hostname, port);
				retval = PORTUNEXPECTED;
			}
		}
		else
		{
			retval = UDPRESP;

			#ifdef UDPDEBUG
			IPSCAN_LOG( LOGPREFIX "check_udp_port: good read(), returned %d bytes\n", rc);
			// Log the summary of results internally - but only if LOGVERBOSITY is set to 1
			int rxlength = ( rc < UDPMAXLOGOCTETS ) ? rc : UDPMAXLOGOCTETS;
			int i = 0;
			int position = 0;
			while (i < rxlength)
			{
				if (position == 0)
				{
					rc = snprintf(udplogbufferptr, udplogbuffersize, "Found response packet for port %d: %02x", port, (rxmessage[i] & 0xff) );
				}
				else
				{
					rc = snprintf(udplogbufferptr, udplogbuffersize, " %02x", (rxmessage[i] & 0xff) );
				}

				if (rc < 0 || rc >= udplogbuffersize)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: logbuffer write truncated, increase LOGENTRYSIZE (currently %d) and recompile.\n", LOGENTRYSIZE);
					exit(EXIT_FAILURE);
				}

				udplogbufferptr += rc ;
				udplogbuffersize -= rc;
				position ++ ;
				if ( position >= LOGMAXOCTETS || i == (rxlength-1) )
				{
					#if (IPSCAN_LOGVERBOSITY == 1)
					IPSCAN_LOG( LOGPREFIX "%s\n", udplogbuffer);
					#endif
					udplogbufferptr = &udplogbuffer[0];
					udplogbuffersize = LOGENTRYSIZE;
					position = 0;
				}
				i++ ;
			}
			#endif
		}
	}

	if (-1 != fd)
	{
		rc = close(fd);
		if (rc == -1)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: close of fd %d caused unexpected failure : %d (%s)\n", fd, errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}


	return (retval);
}
