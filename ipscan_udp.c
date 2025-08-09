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

// ipscan_udp.c 	version
// 0.01 		initial version after split from ipscan_checks.c
// 0.02			add parallel scanning support
// 0.03			add SNMP support
// 0.04			improve debug logging
// 0.05			generate a dummy packet for unhandled ports
// 0.06			add the beginnings of ISAKMP and LSP Ping
// 0.07                 remove LSP Ping
// 0.08                 move to memset()
// 0.09			ensure minimum timings are met
// 0.10			improve error handling
// 0.11			SNMPv3 support
// 0.12			initialise sin6_scope_id, although unused
// 0.13			add logging for DNS query term creation
// 0.14			add null termination to unusedfield
// 0.15			add RIPng
// 0.16			add MPLS LSP Ping back
// 0.17			tweaks to DNS query
// 0.18			Improvements to MPLS LSP Ping
// 0.19			Further DNS test error handling improvements
// 0.20			SNMP test error handling improvement
// 0.21			Separate community strings for SNMPv1 and SNMPv2c
// 0.22			Add DHCPv6 support
// 0.23			Update dates
// 0.24			Update dates
// 0.25			Update dates
// 0.26			extern updated
// 0.27			fix snprintf size parameter type
// 0.28			Update copyright dates
// 0.29			swap comparison terms, where appropriate
// 0.30			delete old comments, update copyright year
// 0.31			Add memset clear for inet_ntop failure case
// 0.32			Add logging for bad gettimeofday() calls
// 0.33			Update copyright year
// 0.34			Update copyright year
// 0.35			Improvements to reduce scope of multiple variables
// 0.36			Update copyright year and DNS target
// 0.37 		Add write_db loop to account for deadlocks
// 0.38			move to nanosleep() from deprecated usleep()
// 0.39			improve various format strings

//
#define IPSCAN_UDP_VER "0.39"
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

// gettimeofday()
#include <sys/time.h>

// getifaddrs()
#include <ifaddrs.h>

// Link layer
#include <linux/if_packet.h>
#include <net/ethernet.h>

//
// Prototype declarations
//
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint64_t port, uint64_t result, const char *indirecthost );

// Others that FreeBSD highlighted
#include <netinet/in.h>
#include <stdint.h>
#include <inttypes.h>

// Other IPv6 related
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

// Poll support
#include <poll.h>

// Parallel processing related
#include <sys/wait.h>

//
// report version
//
const char* ipscan_udp_ver(void)
{
    return IPSCAN_UDP_VER;
}

//
// ----------------------------------------------------------------
//
int check_udp_port(char * hostname, uint16_t port, uint8_t special)
{
	char txmessage[UDP_BUFFER_SIZE+1],rxmessage[UDP_BUFFER_SIZE+1];
	struct sockaddr_in6 remoteaddr;
	struct timeval timeout;
	struct sockaddr_in6 localaddr;

	// Local address update indication
	int la_update = 0;

	int rc = 0;
	unsigned int i = 0;
	int fd = -1;

	// buffer for logging entries
	#ifdef UDPDEBUG
	int udplogbuffersize = LOGENTRYSIZE;
	char udplogbuffer[ (size_t)(LOGENTRYSIZE + 1) ];
	char *udplogbufferptr = &udplogbuffer[0];
	#endif

	// Holds length of transmitted UDP packet, which since they are representative packets,
	//  depends on the port being tested
	unsigned int len = 0;

	// set return value to a known default
	int retval = PORTUNKNOWN;

	// Capture time of day and convert to NTP format
	struct timeval tv;
	rc = gettimeofday(&tv, NULL);
	if (0 > rc)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad gettimeofday() call for NTP, returned %d with errno %d (%s)\n", rc, errno, strerror(errno));
	}
	const unsigned long long EPOCH = 2208988800ULL;
	const unsigned long long NTP_SCALE_FRAC = 4294967296ULL;
	long long unsigned int tv_secs  = (long long unsigned int)(tv.tv_sec) + EPOCH;
	long long unsigned int tv_usecs = ((NTP_SCALE_FRAC * (long long unsigned int)tv.tv_usec) / 1000000UL);

	// Prefill transmit message buffer with 0s
	memset(&txmessage, 0,  UDP_BUFFER_SIZE+1);

	// Local MAC address lookup and storage
	struct ifaddrs *ifaddr, *ifa;
	unsigned char localmacaddr[6];
	memset( &localmacaddr, 0, sizeof(localmacaddr));
	// Fill in a default MAC in case getifaddrs() is unsuccessful
	localmacaddr[5] = 0x01;
	// Local MAC address update indication
	int lam_update = 0;

	// Clear localaddr
	memset(&localaddr, 0, sizeof(struct sockaddr_in6));
	// Fill in a default address in case getifaddrs() is unsuccessful
	rc = inet_pton(AF_INET6, "::1", &(localaddr.sin6_addr));

	if (rc != 1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad inet_pton() call for localaddr, returned %d with errno %d (%s)\n", rc, errno, strerror(errno));
	}
	localaddr.sin6_port = htons(port);
	localaddr.sin6_family = AF_INET6;
	localaddr.sin6_flowinfo = 0;
	localaddr.sin6_scope_id = 0;

	// Determine local address and its related MAC address
	// Modify IPSCAN_INTERFACE_NAME in ipscan.h to match the server
	rc = getifaddrs( &ifaddr );
	if (rc == -1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: getifaddrs failed, returned %d (%s)\n", errno, strerror(errno));
	}
	else
	{
		for (ifa = ifaddr; (NULL != ifa); ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr == NULL) continue;

			int family = ifa->ifa_addr->sa_family;

			if ( family == AF_INET6 && strcasecmp(IPSCAN_INTERFACE_NAME, ifa->ifa_name) == 0 && la_update == 0 )
			{
				char localaddrstr[INET6_ADDRSTRLEN+1];
				const char * rccharptr = inet_ntop(AF_INET6, &((*((struct sockaddr_in6*)ifa->ifa_addr)).sin6_addr), localaddrstr, INET6_ADDRSTRLEN);
				if (NULL == rccharptr)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: inet_ntop() returned an error (%s)\n", strerror(errno));
					memset(localaddrstr, 0, INET6_ADDRSTRLEN);
				}
				else
				{
					// Copy result to localaddr for later use (MPLS LSP Ping)
					memcpy(&localaddr.sin6_addr, &((*((struct sockaddr_in6*)ifa->ifa_addr)).sin6_addr), sizeof(struct in6_addr));
					la_update = 1;
					#ifdef UDPDEBUG
					IPSCAN_LOG( LOGPREFIX "check_udp_port: found localaddr = %s\n", localaddrstr);
					#endif
				}
			}

			if ( family == AF_PACKET && strcasecmp(IPSCAN_INTERFACE_NAME, ifa->ifa_name) == 0 && lam_update == 0 )
			{
				// Copy result to localmacaddr for later use (DHCPv6)
				struct sockaddr_ll *sa_ll = (struct sockaddr_ll * )ifa->ifa_addr;
				for (i = 0; i < 6; i++) localmacaddr[i] = sa_ll->sll_addr[i];
				lam_update = 1;
				#ifdef UDPDEBUG
				IPSCAN_LOG( LOGPREFIX "check_udp_port: found MAC address %02x:%02x:%02x:%02x:%02x:%02x\n", localmacaddr[0], localmacaddr[1], localmacaddr[2], localmacaddr[3], localmacaddr[4], localmacaddr[5]);
				#endif
			}
		}
		freeifaddrs(ifaddr);
	}

	if (la_update == 0 && lam_update == 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: INFO: failed to determine the link-local or MAC address for interface %s\n", IPSCAN_INTERFACE_NAME);
		IPSCAN_LOG( LOGPREFIX "check_udp_port: INFO: check whether IPSCAN_INTERFACE_NAME defined in ipscan.h is correct.\n");
	}

	rc = inet_pton(AF_INET6, hostname, &(remoteaddr.sin6_addr));
	if (rc != 1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad inet_pton() call, returned %d with errno %d (%s)\n", rc, errno, strerror(errno));
		retval = PORTINTERROR;
	}
	remoteaddr.sin6_port = htons(port);
	remoteaddr.sin6_family = AF_INET6;
	remoteaddr.sin6_flowinfo = 0;
	remoteaddr.sin6_scope_id = 0; // unused in our case

	// Attempt to create a socket
	if (PORTUNKNOWN == retval)
	{
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd == -1)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad socket call, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
		else
		{
			memset(&timeout, 0, sizeof(timeout));
			timeout.tv_sec = UDPTIMEOUTSECS;
			timeout.tv_usec = UDPTIMEOUTMICROSECS;

			rc = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
			if (rc < 0)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errno, strerror(errno));
				retval = PORTINTERROR;
			}
		}
	}

	if (PORTUNKNOWN == retval) // continue
	{
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = UDPTIMEOUTSECS;
		timeout.tv_usec = UDPTIMEOUTMICROSECS;

		rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

	if (PORTUNKNOWN == retval)
	{
		// Need to connect, since otherwise asynchronous ICMPv6 responses will not be delivered to us
		rc = connect( fd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr) );
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad connect() attempt, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}


	if (PORTUNKNOWN == retval)
	{
		size_t rc_st = 0;
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
				Question carries one or more questions, that is, queries for information being sent to a DNS name server.
				Answer carries one or more resource records that answer the question(s) indicated in the Question section above.
				Authority contains one or more resource records that point to authoritative name servers that can be used to
				continue the resolution process.
				Additional conveys one or more resource records that contain additional information related to the query that
				is not strictly necessary to answer the queries (questions) in the message.
			 */
			len = 0;
			// ID - identifier - 16 bit field
			txmessage[len]= 21;
			len++;
			txmessage[len]= 6;
			len++;
			// QR - query/response flag - 0=query. 1 bit field
			// OP - opcode - 0=query,2=status. 4 bit field
			// AA - Authoritative Answer flag. 1 bit field
			// TC - truncation flag. 1 bit field
			// RD - recursion desired - 0=not desired, 1=desired. 1 bit field
			// RA - recursion available. 1 bit field
			// Z  - reserved. 3 bit field
			// Rcode - result code - 0=no error, 4=not implemented
			txmessage[len]= 1; // 0=Standard Query, 1=Recursion, 16 for server status query
			len++;
			txmessage[len]= 0;
			len++;
			// QDCOUNT - question count - 16 bit field
			txmessage[len]= 0;
			len++;
			txmessage[len]= 1;
			len++;
			// ANCOUNT - answer record count - 16 bit field
			txmessage[len]= 0;
			len++;
			txmessage[len]= 0;
			len++;
			// NSCOUNT - authority record count (NS=name server) - 16 bit field
			txmessage[len]= 0;
			len++;
			txmessage[len]= 0;
			len++;
			// ARCOUNT - 16 bit field
			txmessage[len]= 0;
			len++;
			txmessage[len]= 0;
			len++;
			// Question section

			const char * dnsquery1 = "www66";
			rc_st = strnlen(dnsquery1,(size_t)(UDP_BUFFER_SIZE-len));
			if (rc_st == (UDP_BUFFER_SIZE-len))
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad strnlen() for DNS query1, returned %lu\n", rc_st);
				retval = PORTINTERROR;
			}
			else
			{
				txmessage[len] = (char)(rc_st & 0xff);
				len++;
			}
			// Need one extra octet for trailing 0, however this will be overwritten
			// by the length of the next part of the host name in standard DNS format
			rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery1);
			if (rc < 0 || rc >=( UDP_BUFFER_SIZE-(int)len ))
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for DNS query, returned %d\n", rc);
				retval = PORTINTERROR;
			}
			else
			{
				len += (unsigned int)rc;
			}

			// Only add new octets if no internal error has been encountered
			//
			if (PORTUNKNOWN == retval)
			{
				const char * dnsquery2 = "chappell-family";
				rc_st = strnlen(dnsquery2,(size_t)(UDP_BUFFER_SIZE-len));
				if (rc_st == (UDP_BUFFER_SIZE-len))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad strnlen() for DNS query2, returned %lu\n", rc_st);
					retval = PORTINTERROR;
				}
				else
				{
					txmessage[len] = (char)(rc_st & 0xff);
					len++;
				}
				rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery2);
				if (rc < 0 || rc >= ( UDP_BUFFER_SIZE-(int)len ))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for DNS query, returned %d\n", rc);
					retval = PORTINTERROR;
				}
				else
				{
					len += (unsigned int)rc;
				}
			}

			// Only add new octets if no internal error has been encountered
			//
			if (PORTUNKNOWN == retval)
			{
				const char * dnsquery3 = "co";
				rc_st = strnlen(dnsquery3,(size_t)(UDP_BUFFER_SIZE-len));
				if (rc_st == (UDP_BUFFER_SIZE-len))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad strnlen() for DNS query3, returned %lu\n", rc_st);
					retval = PORTINTERROR;
				}
				else
				{
					txmessage[len] = (char)(rc_st & 0xff);
					len++;
				}
				rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery3);
				if (rc < 0 || rc >= ( UDP_BUFFER_SIZE-(int)len ))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for DNS query, returned %d\n", rc);
					retval = PORTINTERROR;
				}
				else
				{
					len += (unsigned int)rc;
				}
			}

			// Only add new octets if no internal error has been encountered
			//
			if (PORTUNKNOWN == retval)
			{
				const char * dnsquery4 = "uk";
				rc_st = strnlen(dnsquery4,(size_t)(UDP_BUFFER_SIZE-len));
				if (rc_st == (UDP_BUFFER_SIZE-len))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad strnlen() for DNS query4, returned %lu\n", rc_st);
					retval = PORTINTERROR;
				}
				else
				{
					txmessage[len] = (char)(rc_st & 0xff);
					len++;
				}
				rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery4);
				if (rc < 0 || rc >= ( UDP_BUFFER_SIZE-(int)len ))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for DNS query, returned %d\n", rc);
					retval = PORTINTERROR;
				}
				else
				{
					len += (unsigned int)rc;
				}
			}

			// Only add new octets if no internal error has been encountered
			//
			if (PORTUNKNOWN == retval)
			{
				// End of name
				txmessage[len]= 0;
				len++;

				// Question type - 1 = host address, 2=NS, 255 is request all
				txmessage[len] = 0;
				len++;
				txmessage[len] = 255;
				len++;
				// Qclass - 1=INternet
				txmessage[len] = 0;
				len++;
				txmessage[len] = 1;
				len++;
			}
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
			int length = snprintf(&txmessage[0], UDP_BUFFER_SIZE, "%c%c%s%d%coctet%c",0,1,"/filename_tjc_",getpid(),0,0);
			if (length < 0)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for tftp, returned %d\n", length);
				len = 0;
				retval = PORTINTERROR;
			}
			else
			{
				len = (unsigned int)length;
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

			if (1 == special) // NTP monlist case
			{
				txmessage[0] = 0x17; 	// NTP version 2, NTP_MODE = 7 (Private use)
				txmessage[1] = 0; 	// (Auth bit and sequence number)
				txmessage[2] = 0x03;	// Implementation is XNTPD
				txmessage[3] = 0X2a;	// MON_GETLIST_1
				len = 256;
			}
			else // Standard NTP client query
			{
				txmessage[0] = ((NTP_LI << 5) + (NTP_VN << 3) + ( NTP_MODE ));
				txmessage[1] = NTP_STRATUM;
				txmessage[2] = NTP_POLL;
				txmessage[3] = NTP_PRECISION;
				// Pad out 11 32-bit words (Root Delay through transmit timestamp)
				len = 48;
			}
			break;
		}


		case 161:
		{
			len = 0;

			if (0 == special || 1 == special)
			{
				// SNMPv1 or SNMPv2c get
				// Note this code will need amending if you modify the mib string and it includes IDs with values >=128
				const char mib[32] = {1,2,1,1,1,0}; // system.sysDescr.0 - System Description minus 1.3.6 prefix
				unsigned int miblen = 6;
				// Use different community strings for SNMPv1 (index 0) and SNMPv2c (index 1)
        			const char community[2][16] = { "public", "private" };

				// SNMP packet start
				txmessage[len] = 0x30;
				len++;
				// was txmessage[len] = (char)(29 + strlen(community[special]) + miblen);
				rc_st = strnlen(community[special],(size_t)(UDP_BUFFER_SIZE-len));
				if (rc_st == (UDP_BUFFER_SIZE-len))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad strnlen() for SNMP community, returned %lu\n", rc_st);
					retval = PORTINTERROR;
				}
				else
				{
					txmessage[len] = (char)((29 + rc_st + miblen) & 0xff);
					len++;
				}
				// SNMP version 1
				txmessage[len] = 0x02; //int
				len++;
				txmessage[len] = 0x01; //length of 1
				len++;
				txmessage[len] = (special & 0xff); // 0 = SNMPv1, 1 = SNMPv2c
				len++;
				// Community name
				txmessage[len] = 0x04; //string
				len++;
				// was txmessage[len] = (char)strlen(community[special]);
				rc_st = strnlen(community[special],(size_t)(UDP_BUFFER_SIZE-len));
				if (rc_st == (UDP_BUFFER_SIZE-len))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad strnlen() for SNMP community, returned %lu\n", rc_st);
					retval = PORTINTERROR;
				}
				else
				{
					txmessage[len] = (char)(rc_st & 0xff);
					len++;
				}
				rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", community[special]);
				if (rc < 0 || rc >= (UDP_BUFFER_SIZE-(int)len))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for SNMP, returned %d\n", rc);
					retval = PORTINTERROR;
				}
				else
				{
					len += (unsigned int)rc;
				}

				// MIB - check there's enough room before adding
				if (PORTUNKNOWN == retval && (len < (unsigned int)(UDP_BUFFER_SIZE-24-miblen)) )
				{
					txmessage[len] = 0xA0; // SNMP GET request
					len++;
					txmessage[len] = (char)(22 + miblen); //0x1c
					len++;

					txmessage[len] = 0x02; // Request ID
					len++;
					txmessage[len] = 0x04; // 4 octets length
					len++;
					txmessage[len] = 0x21; // "Random" value
					len++;
					txmessage[len] = 0x06;
					len++;
					txmessage[len] = 0x01;
					len++;
					txmessage[len] = 0x08;
					len++;

					// Error status (0=noError)
					txmessage[len] = 0x02; //int
					len++;
					txmessage[len] = 0x01; //length of 1
					len++;
					txmessage[len] = 0x00; // SNMP error status
					len++;
					// Error index (0)
					txmessage[len] = 0x02; //int
					len++;
					txmessage[len] = 0x01; //length of 1
					len++;
					txmessage[len] = 0x00; // SNMP error index
					len++;
					// Variable bindings
					txmessage[len] = 0x30; //var-bind sequence
					len++;
					txmessage[len] = (char)(8 + miblen);
					len++;

					txmessage[len] = 0x30; //var-bind
					len++;
					txmessage[len] = (char)(miblen +6 );
					len++;

					txmessage[len] = 0x06; // Object
					len++;
					txmessage[len] = (char)(miblen + 2); // MIB length
					len++;

					txmessage[len] = 0x2b;
					len++;
					txmessage[len] = 0x06;
					len++;
					// Insert the OID
					for (i = 0; i <miblen; i++)
					{
						txmessage[len] = mib[i];
						len++;
					}
					txmessage[len] = 0x05; // Null object
					len++;
					txmessage[len] = 0x00; // length of 0
					len++;
				}
				else if (PORTUNKNOWN == retval && (len >= (unsigned int)(UDP_BUFFER_SIZE-24-miblen)))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Insufficient room to add OID, len = %u\n", len);
					retval = PORTINTERROR;
				}
			}
			else if (2 == special)
			{
				// SNMPv3 engine discovery
				txmessage[len] = 0x30;
				len++;
				txmessage[len] = 0x38;
				len++;

				// SNMP version 3
				txmessage[len] = 0x02; // int
				len++;
				txmessage[len] = 0x01; // length of 1
				len++;
				txmessage[len] = 0x03; // SNMP v3
				len++;

				// msgGlobalData
				txmessage[len] = 0x30;
				len++;
				txmessage[len] = 0x0e;
				len++;

				txmessage[len] = 0x02;
				len++;
				txmessage[len] = 0x01;
				len++;
				txmessage[len] = 0x02; // msgID
				len++;

				txmessage[len] = 0x02; //
				len++;
				txmessage[len] = 0x03; //
				len++;
				txmessage[len] = 0x00; // Max message size (less than 64K)
				len++;
				txmessage[len] = 0xff; //
				len++;
				txmessage[len] = 0xe3; //
				len++;

				txmessage[len] = 0x04;
				len++;
				txmessage[len] = 0x01;
				len++;
				txmessage[len] = 0x04; // flags (reportable, not encrypted, not authenticated)
				len++;

				txmessage[len] = 0x02;
				len++;
				txmessage[len] = 0x01;
				len++;
				txmessage[len] = 0x03; // msgSecurityModel is USM (3)
				len++;

				// end of GlobalData

				txmessage[len] = 0x04;
				len++;
				txmessage[len] = 0x10; //
				len++;

				txmessage[len] = 0x30; //
				len++;
				txmessage[len] = 0x0e; // length to end of this varbind
				len++;

				txmessage[len] = 0x04; //
				len++;
				txmessage[len] = 0x00; // EngineID
				len++;

				txmessage[len] = 0x02;
				len++;
				txmessage[len] = 0x01;
				len++;
				txmessage[len] = 0x00; // EngineBoots
				len++;

				txmessage[len] = 0x02;
				len++;
				txmessage[len] = 0x01;
				len++;
				txmessage[len] = 0x00; // EngineTime
				len++;

				txmessage[len] = 0x04; // UserName
				len++;
				txmessage[len] = 0x00;
				len++;

				txmessage[len] = 0x04; // Authentication Parameters
				len++;
				txmessage[len] = 0x00;
				len++;

				txmessage[len] = 0x04; // Privacy Parameters
				len++;
				txmessage[len] = 0x00;
				len++;

				// msgData
				txmessage[len] = 0x30; //
				len++;
				txmessage[len] = 0x11; //
				len++;

				txmessage[len] = 0x04; //  Context Engine ID (missing)
				len++;
				txmessage[len] = 0x00; //
				len++;

				txmessage[len] = 0x04; //  Context Name (missing)
				len++;
				txmessage[len] = 0x00; //
				len++;

				txmessage[len] = 0xa0; //  Get Request
				len++;
				txmessage[len] = 0x0b; //
				len++;

				txmessage[len] = 0x02; // Request ID (is 0x14)
				len++;
				txmessage[len] = 0x01; //
				len++;
				txmessage[len] = 0x14; //
				len++;

				// Error status (0=noError)
				txmessage[len] = 0x02; //int
				len++;
				txmessage[len] = 0x01; //length of 1
				len++;
				txmessage[len] = 0x00; // SNMP error status
				len++;
				// Error index (0)
				txmessage[len] = 0x02; //int
				len++;
				txmessage[len] = 0x01; //length of 1
				len++;
				txmessage[len] = 0x00; // SNMP error index
				len++;
				// Variable bindings (none)
				txmessage[len] = 0x30; //var-bind sequence
				len++;
				txmessage[len] = 0x00;
				len++;

				// End of msgData
			}

			break;
		}

		// IKEv2
		case 500:
		case 4500:
		{
			// ISAKMP
			len = 0;
			// Initiator cookie (8 bytes)
			txmessage[len++] = 0xde;
			txmessage[len++] = 0xad;
			txmessage[len++] = 0xfa;
			txmessage[len++] = 0xce;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 1;
			// Responder cookie (8 bytes)
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			// Next payload 0=None, 2=proposal, 4=key exchange, 33=SA
			txmessage[len++] = 33;
			// Version Major/Minor 2.0
			txmessage[len++] = 32;
			// Exchange type 4=aggressive, 34=IKE_SA_INIT
			txmessage[len++] = 34;
			// Flags 8=initiator
			txmessage[len++] = 8;

			// Message ID (4 bytes)
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			// Length (4 bytes)
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0x01;
			txmessage[len++] = 0x2c; // includes key exchange payload

			// SA=33
			// Next payload 0=None, 2=proposal, 4=key exchange, 33=SA, 34=KeyEx
			txmessage[len++] = 34;
			txmessage[len++] = 0; // Not critical
			txmessage[len++] = 0; // Length 44
			txmessage[len++] = 44;

			txmessage[len++] = 0x00; // No next payload
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 40
			txmessage[len++] = 0x28;
			txmessage[len++] = 0x01; // Proposal 1
			txmessage[len++] = 0x01; // IKE
			txmessage[len++] = 0x00; // SPI size 0
			txmessage[len++] = 0x04; // Number of transforms
			txmessage[len++] = 0x03; // Payload type is transform
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 8
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x01; // ENCRYPTION Algorithm
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // 3=3DES
			txmessage[len++] = 0x03;
			txmessage[len++] = 0x03; // Payload type is transform
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 8
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x03; // INTEGRITY Algorithm
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // 2=AUTH_HMAC_SHA1_96
			txmessage[len++] = 0x02;
			txmessage[len++] = 0x03; // Payload type is transform
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 8
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x02; // PRF Algorithm
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // 2=PRF_HMAC_SHA1
			txmessage[len++] = 0x02;
			txmessage[len++] = 0x00; // Next Payload type is NONE
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // Length 8
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x04; // 4=Diffie-Hellman Group
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // 1024-bit MODP group
			txmessage[len++] = 0x02;

			// Key Exchange payload
			//      		   	  1                   2                   3
			//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//! Next Payload  !   RESERVED    !         Payload Length        !
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//!                                                               !
			//~                       Key Exchange Data                       ~
			//!                                                               !
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//

			txmessage[len++] = 0x28; // Next Payload type is None (40)
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 136
			txmessage[len++] = 0x88;
			txmessage[len++] = 0x00; // DH group 1024-bit MODP (2)
			txmessage[len++] = 0x02;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x2d; // Key Exchange data (128 octets)
			txmessage[len++] = 0x54;
			txmessage[len++] = 0x91;
			txmessage[len++] = 0xfa;
			txmessage[len++] = 0x0c;
			txmessage[len++] = 0xd4;
			txmessage[len++] = 0xd4;
			txmessage[len++] = 0xcc;
			txmessage[len++] = 0x77;
			txmessage[len++] = 0xf8;
			txmessage[len++] = 0xce;
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x98;
			txmessage[len++] = 0x45;
			txmessage[len++] = 0x40;
			txmessage[len++] = 0xb7;
			txmessage[len++] = 0xc6;
			txmessage[len++] = 0x8c;
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x93;
			txmessage[len++] = 0x2c;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0xf7;
			txmessage[len++] = 0xc1;
			txmessage[len++] = 0x5b;
			txmessage[len++] = 0xf1;
			txmessage[len++] = 0x04;
			txmessage[len++] = 0xb0;
			txmessage[len++] = 0x94;
			txmessage[len++] = 0x02;
			txmessage[len++] = 0x1a;
			txmessage[len++] = 0xf9;
			txmessage[len++] = 0x95;
			txmessage[len++] = 0x29;
			txmessage[len++] = 0x6c;
			txmessage[len++] = 0x4a;
			txmessage[len++] = 0x26;
			txmessage[len++] = 0x12;
			txmessage[len++] = 0x18;
			txmessage[len++] = 0x75;
			txmessage[len++] = 0x21;
			txmessage[len++] = 0x0e;
			txmessage[len++] = 0x02;
			txmessage[len++] = 0x06;
			txmessage[len++] = 0x11;
			txmessage[len++] = 0x49;
			txmessage[len++] = 0xc1;
			txmessage[len++] = 0xa0;
			txmessage[len++] = 0xc5;
			txmessage[len++] = 0x82;
			txmessage[len++] = 0xe1;
			txmessage[len++] = 0x11;
			txmessage[len++] = 0x30;
			txmessage[len++] = 0xab;
			txmessage[len++] = 0xc4;
			txmessage[len++] = 0x31;
			txmessage[len++] = 0xde;
			txmessage[len++] = 0x49;
			txmessage[len++] = 0x7d;
			txmessage[len++] = 0xd3;
			txmessage[len++] = 0xe6;
			txmessage[len++] = 0xfb;
			txmessage[len++] = 0x42;
			txmessage[len++] = 0x08;
			txmessage[len++] = 0xfd;
			txmessage[len++] = 0x72;
			txmessage[len++] = 0x74;
			txmessage[len++] = 0xbf;
			txmessage[len++] = 0x34;
			txmessage[len++] = 0x60;
			txmessage[len++] = 0xdc;
			txmessage[len++] = 0x98;
			txmessage[len++] = 0x97;
			txmessage[len++] = 0xd3;
			txmessage[len++] = 0xb5;
			txmessage[len++] = 0x5b;
			txmessage[len++] = 0x82;
			txmessage[len++] = 0xec;
			txmessage[len++] = 0x77;
			txmessage[len++] = 0x0d;
			txmessage[len++] = 0xae;
			txmessage[len++] = 0xca;
			txmessage[len++] = 0x39;
			txmessage[len++] = 0xfd;
			txmessage[len++] = 0x9a;
			txmessage[len++] = 0x08;
			txmessage[len++] = 0x8f;
			txmessage[len++] = 0x5a;
			txmessage[len++] = 0x73;
			txmessage[len++] = 0xa1;
			txmessage[len++] = 0xfd;
			txmessage[len++] = 0x60;
			txmessage[len++] = 0x98;
			txmessage[len++] = 0xa8;
			txmessage[len++] = 0xc8;
			txmessage[len++] = 0xdf;
			txmessage[len++] = 0x16;
			txmessage[len++] = 0x3d;
			txmessage[len++] = 0x55;
			txmessage[len++] = 0xff;
			txmessage[len++] = 0x6d;
			txmessage[len++] = 0xe0;
			txmessage[len++] = 0x94;
			txmessage[len++] = 0xd7;
			txmessage[len++] = 0x93;
			txmessage[len++] = 0xa6;
			txmessage[len++] = 0x82;
			txmessage[len++] = 0x1f;
			txmessage[len++] = 0xce;
			txmessage[len++] = 0x07;
			txmessage[len++] = 0x0a;
			txmessage[len++] = 0x17;
			txmessage[len++] = 0xf4;
			txmessage[len++] = 0x87;
			txmessage[len++] = 0x0b;
			txmessage[len++] = 0xc7;
			txmessage[len++] = 0x90;
			txmessage[len++] = 0xa2;
			txmessage[len++] = 0x47;
			txmessage[len++] = 0x51;
			txmessage[len++] = 0xca;
			txmessage[len++] = 0x2c;
			txmessage[len++] = 0xe8;
			txmessage[len++] = 0x33;
			txmessage[len++] = 0x3a;
			txmessage[len++] = 0x4d;
			txmessage[len++] = 0x5f;
			txmessage[len++] = 0xae;

			// Payload is Nonce
			txmessage[len++] = 0x29; // Next payload is Notify (41)
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 36
			txmessage[len++] = 0x24; // Nonce data
			txmessage[len++] = 0xfb;
			txmessage[len++] = 0xe5;
			txmessage[len++] = 0x90;
			txmessage[len++] = 0x3f;
			txmessage[len++] = 0xc9;
			txmessage[len++] = 0xdf;
			txmessage[len++] = 0x47;
			txmessage[len++] = 0x09;
			txmessage[len++] = 0xe5;
			txmessage[len++] = 0xd4;
			txmessage[len++] = 0xab;
			txmessage[len++] = 0x0a;
			txmessage[len++] = 0xa6;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0xb3;
			txmessage[len++] = 0xbe;
			txmessage[len++] = 0x36;
			txmessage[len++] = 0xeb;
			txmessage[len++] = 0x35;
			txmessage[len++] = 0xa6;
			txmessage[len++] = 0xf5;
			txmessage[len++] = 0x54;
			txmessage[len++] = 0x47;
			txmessage[len++] = 0xfe;
			txmessage[len++] = 0xda;
			txmessage[len++] = 0xb9;
			txmessage[len++] = 0x0d;
			txmessage[len++] = 0x67;
			txmessage[len++] = 0x66;
			txmessage[len++] = 0x9f;
			txmessage[len++] = 0xab;
			txmessage[len++] = 0x96;

			// Payload is Notify
			txmessage[len++] = 0x29; // Next payload is also notify
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // Length 28
			txmessage[len++] = 0x1c;
			txmessage[len++] = 0x00; // Protocol ID is RESERVED (0)
			txmessage[len++] = 0x00; // SPI size is 0
			txmessage[len++] = 0x40; // NAT_DETECTION_SOURCE_IP (16388)
			txmessage[len++] = 0x04;
			// data is SHA1(SPIs, source IP address, source port)
			// however, we're just looking for a response, not a valid
			// packet
			txmessage[len++] = 0xc6; // Notification data
			txmessage[len++] = 0x93;
			txmessage[len++] = 0x14;
			txmessage[len++] = 0x61;
			txmessage[len++] = 0x31;
			txmessage[len++] = 0xa7;
			txmessage[len++] = 0x7f;
			txmessage[len++] = 0xe9;
			txmessage[len++] = 0x93;
			txmessage[len++] = 0x47;
			txmessage[len++] = 0x26;
			txmessage[len++] = 0xe5;
			txmessage[len++] = 0x23;
			txmessage[len++] = 0x17;
			txmessage[len++] = 0xd4;
			txmessage[len++] = 0xec;
			txmessage[len++] = 0x5f;
			txmessage[len++] = 0x64;
			txmessage[len++] = 0x45;
			txmessage[len++] = 0xf1;

			// Payload is Notify
			txmessage[len++] = 0x00; // Next payload is NONE
			txmessage[len++] = 0x00; // Not critical
			txmessage[len++] = 0x00; // :ength 28
			txmessage[len++] = 0x1c;
			txmessage[len++] = 0x00; // Protocol ID is RESERVED(0)
			txmessage[len++] = 0x00; // SPI size = 0
			txmessage[len++] = 0x40; // NAT_DETECTION_DESTIANTION_IP (16389)
			txmessage[len++] = 0x05;
			// data is SHA1(SPIs, source IP address, source port)
			// however, we're just looking for a response, not a valid
			// packet
			txmessage[len++] = 0xf9; // Notification data
			txmessage[len++] = 0x33;
			txmessage[len++] = 0xa1;
			txmessage[len++] = 0x9a;
			txmessage[len++] = 0x65;
			txmessage[len++] = 0x1a;
			txmessage[len++] = 0xc3;
			txmessage[len++] = 0x73;
			txmessage[len++] = 0x8b;
			txmessage[len++] = 0xb7;
			txmessage[len++] = 0xf6;
			txmessage[len++] = 0x04;
			txmessage[len++] = 0x43;
			txmessage[len++] = 0x6f;
			txmessage[len++] = 0x80;
			txmessage[len++] = 0x12;
			txmessage[len++] = 0x69;
			txmessage[len++] = 0x3e;
			txmessage[len++] = 0x6a;
			txmessage[len++] = 0x2a;

			break;
		}

		// RIPng
		case 521:
		{
			len = 0;
			txmessage[len++] = 0x01; // Command is REQUEST
			txmessage[len++] = 0x01; // Version 1
			txmessage[len++] = 0x00; // Reserved
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // ::
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // Route Tag
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00; // Prefix length
			txmessage[len++] = 0x10; // Metric
			break;
		}

		case 547:
		{
			// DHCPv6 defined in https://tools.ietf.org/html/rfc3315
			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |    msg-type   |               transaction-id                  |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                                                               |
			//      .                            options                            .
			//      .                           (variable)                          .
			//      |                                                               |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			len = 0;
			txmessage[len++] = 0x01; // msg-type = 0x01 (Solicit)
			txmessage[len++] = 0xde; // transaction-id
			txmessage[len++] = 0xad;
			txmessage[len++] = 0xfa;

			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |        OPTION_CLIENTID        |          option-len           |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      .                                                               .
			//      .                              DUID                             .
			//      .                        (variable length)                      .
			//      .                                                               .
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			txmessage[len++] = 0x00; // Option 1 is Client Identifier
			txmessage[len++] = 0x01;

			txmessage[len++] = 0x00; // Length field
			txmessage[len++] = 0x0e;


			// The following diagram illustrates the format of a DUID-LLT:
			//
			//     0                   1                   2                   3
			//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |               1               |    hardware type (16 bits)    |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |                        time (32 bits)                         |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    .                                                               .
			//    .             link-layer address (variable length)              .
			//    .                                                               .
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//

			txmessage[len++] = 0x00; // DUID-LLT
			txmessage[len++] = 0x01;

			txmessage[len++] = 0x00; // Hardware type: Ethernet
			txmessage[len++] = 0x01;

			txmessage[len++] = 0x00; // Time
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x01;

			// Copy in the local MAC address as the Link-layer address
			for (i = 0; i < 6 ; i++) txmessage[len++] = localmacaddr[i];

			//  0                   1                   2                   3
			//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |     OPTION_RECONF_ACCEPT      |               0               |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//      option-code   OPTION_RECONF_ACCEPT (20).
			//
			//      option-len    0.
			//

			txmessage[len++] = 0x00; // Reconfigure Accept option
			txmessage[len++] = 0x14;

			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			// The format of the IA_NA option is:
			//
			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |          OPTION_IA_NA         |          option-len           |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                        IAID (4 octets)                        |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                              T1                               |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                              T2                               |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                                                               |
			//      .                         IA_NA-options                         .
			//      .                                                               .
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//      option-code          OPTION_IA_NA (3).
			//
			//      option-len           12 + length of IA_NA-options field.
			//
			//      IAID                 The unique identifier for this IA_NA; the
			//                           IAID must be unique among the identifiers for
			//                           all of this client's IA_NAs.  The number
			//                           space for IA_NA IAIDs is separate from the
			//                           number space for IA_TA IAIDs.
			//
			//      T1                   The time at which the client contacts the
			//                           server from which the addresses in the IA_NA
			//                           were obtained to extend the lifetimes of the
			//                           addresses assigned to the IA_NA; T1 is a
			//                           time duration relative to the current time
			//                           expressed in units of seconds.
			//
			//      T2                   The time at which the client contacts any
			//                           available server to extend the lifetimes of
			//                           the addresses assigned to the IA_NA; T2 is a
			//                           time duration relative to the current time
			//                           expressed in units of seconds.
			//
			//      IA_NA-options        Options associated with this IA_NA.

			txmessage[len++] = 0x00; // Identity Association for Non-temporary Address (IA_NA) option
			txmessage[len++] = 0x03;

			txmessage[len++] = 0x00; // Length (options length = 0)
			txmessage[len++] = 0x0c;

			txmessage[len++] = 0x00; // IAID
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			txmessage[len++] = 0x00; // T1
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			txmessage[len++] = 0x00; // T2
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |      OPTION_ELAPSED_TIME      |           option-len          |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |          elapsed-time         |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//      option-code   OPTION_ELAPSED_TIME (8).
			//
			//      option-len    2.
			//
			//      elapsed-time  The amount of time since the client began its
			//                    current DHCP transaction.  This time is expressed in
			//                    hundredths of a second (10^-2 seconds).


			txmessage[len++] = 0x00; // Elapsed Time Option
			txmessage[len++] = 0x08;

			txmessage[len++] = 0x00; // Length
			txmessage[len++] = 0x02;

			txmessage[len++] = 0x00; // We just started ..
			txmessage[len++] = 0x00;

			//   The Option Request option is used to identify a list of options in a
			//   message between a client and a server.  The format of the Option
			//   Request option is:
			//
			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |           OPTION_ORO          |           option-len          |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |    requested-option-code-1    |    requested-option-code-2    |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                              ...                              |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//      option-code   OPTION_ORO (6).
			//
			//      option-len    2 * number of requested options.
			//
			//      requested-option-code-n The option code for an option requested by
			//      the client.

			txmessage[len++] = 0x00; // Option Request Option Option
			txmessage[len++] = 0x06;

			txmessage[len++] = 0x00; // Option length
			txmessage[len++] = 0x04;

			txmessage[len++] = 0x00; // Recursive DNS server
			txmessage[len++] = 0x17;

			txmessage[len++] = 0x00; // Domain Search List
			txmessage[len++] = 0x18;

			// From RFC 3633
			// The IA_PD option is used to carry a prefix delegation identity
			//   association, the parameters associated with the IA_PD and the
			//   prefixes associated with it.
			//
			//   The format of the IA_PD option is:
			//
			//     0                   1                   2                   3
			//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |         OPTION_IA_PD          |         option-length         |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |                         IAID (4 octets)                       |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |                              T1                               |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |                              T2                               |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    .                                                               .
			//    .                          IA_PD-options                        .
			//    .                                                               .
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//   option-code:      OPTION_IA_PD (25)
			//
			//   option-length:    12 + length of IA_PD-options field.
			//
			//   IAID:             The unique identifier for this IA_PD; the IAID must
			//                     be unique among the identifiers for all of this
			//                     requesting router's IA_PDs.
			//
			//   T1:               The time at which the requesting router should
			//                     contact the delegating router from which the
			//                     prefixes in the IA_PD were obtained to extend the
			//                     lifetimes of the prefixes delegated to the IA_PD;
			//                     T1 is a time duration relative to the current time
			//                     expressed in units of seconds.
			//
			//   T2:               The time at which the requesting router should
			//                     contact any available delegating router to extend
			//                     the lifetimes of the prefixes assigned to the
			//                     IA_PD; T2 is a time duration relative to the
			//                     current time expressed in units of seconds.
			//
			//   IA_PD-options:    Options associated with this IA_PD.

			txmessage[len++] = 0x00; // IA_PD Option
			txmessage[len++] = 0x19;

			txmessage[len++] = 0x00; // Length
			txmessage[len++] = 0x29;

			txmessage[len++] = 0x00; // IAID
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			txmessage[len++] = 0x00; // T1
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			txmessage[len++] = 0x00; // T2
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;

			//   The IA_PD Prefix option is used to specify IPv6 address prefixes
			//   associated with an IA_PD.  The IA_PD Prefix option must be
			//   encapsulated in the IA_PD-options field of an IA_PD option.
			//
			//   The format of the IA_PD Prefix option is:
			//
			//     0                   1                   2                   3
			//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |        OPTION_IAPREFIX        |         option-length         |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |                      preferred-lifetime                       |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |                        valid-lifetime                         |
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    | prefix-length |                                               |
			//    +-+-+-+-+-+-+-+-+          IPv6 prefix                          |
			//    |                           (16 octets)                         |
			//    |                                                               |
			//    |                                                               |
			//    |                                                               |
			//    |               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//    |               |                                               .
			//    +-+-+-+-+-+-+-+-+                                               .
			//    .                       IAprefix-options                        .
			//    .                                                               .
			//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//   option-code:      OPTION_IAPREFIX (26)
			//
			//   option-length:    25 + length of IAprefix-options field
			//
			//   preferred-lifetime: The recommended preferred lifetime for the IPv6
			//                     prefix in the option, expressed in units of
			//                     seconds.  A value of 0xFFFFFFFF represents
			//                     infinity.
			//
			//   valid-lifetime:   The valid lifetime for the IPv6 prefix in the
			//                     option, expressed in units of seconds.  A value of
			//                     0xFFFFFFFF represents infinity.
			//
			//   prefix-length:    Length for this prefix in bits
			//
			//   IPv6-prefix:      An IPv6 prefix
			//
			//   IAprefix-options: Options associated with this prefix

			txmessage[len++] = 0x00; // IA Prefix option
			txmessage[len++] = 0x1a;

			txmessage[len++] = 0x00; // Length (no additional options)
			txmessage[len++] = 0x19;

			txmessage[len++] = 0x00; // Preferred lifetime - 21600 seconds (6 hours)
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x54;
			txmessage[len++] = 0x60;

			txmessage[len++] = 0x00; // Valid lifetime - 86400 seconds (24 hours)
			txmessage[len++] = 0x01;
			txmessage[len++] = 0x51;
			txmessage[len++] = 0x80;

			txmessage[len++] = 0x40; // 64-bit prefix length

			txmessage[len++] = 0x00; // Prefix ::
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			txmessage[len++] = 0x00;
			break;
		}


		case 1900:
		{
			// UPnP
			// taken from http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
			//
			int length = snprintf(&txmessage[0], UDP_BUFFER_SIZE, \
					"M-SEARCH * HTTP/1.1\r\nHost:[%s]:1900\r\nMan: \"ssdp:discover\"\r\nMX:1\r\nST: \"ssdp:all\"\r\nUSER-AGENT: linux/2.6 UPnP/1.1 TimsTester/1.0\r\n\r\n", hostname);
			if (length < 0 || length >= UDP_BUFFER_SIZE)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for UPnP, returned %d\n", length);
				len = 0;
				retval = PORTINTERROR;
			}
			else
			{
				len = (unsigned int)length;
			}

			break;
		}

		// LSP Ping
		case 3503:
		{
			// Taken from RFC4379
			//
			//             0                   1                   2                   3
			//		       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |         Version Number        |         Global Flags          |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |  Message Type |   Reply mode  |  Return Code  | Return Subcode|
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                        Sender's Handle                        |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                        Sequence Number                        |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                    TimeStamp Sent (seconds)                   |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                  TimeStamp Sent (microseconds)                |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                  TimeStamp Received (seconds)                 |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                TimeStamp Received (microseconds)              |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//		      |                            TLVs ...                           |
			//		      .                                                               .
			//		      .                                                               .
			//		      .                                                               .
			//		      |                                                               |
			//		      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// Version
			txmessage[len++] = 0;
			txmessage[len++] = 1; // Version 1
			// Global flags
			txmessage[len++] = 0;
			txmessage[len++] = 1; // Global Flags 1=Validate FEC Stack
			// Message type
			txmessage[len++] = 1; // Message type 1=echo request
			// Reply mode
			txmessage[len++] = 2; // Reply Mode (1=don't;2=ip udp;3=ip udp + router alert; 4 = app level control channel)
			// Return code
			txmessage[len++] = 0; // Filled in by responder
			// Return subcode
			txmessage[len++] = 0; // Filled in by responder
			// Sender's Handle
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			// Sequence Number
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 1;
			// Timestamp sent (seconds)
			txmessage[len++] = (tv_secs >> 24) & 0xff;
			txmessage[len++] = (tv_secs >> 16) & 0xff;
			txmessage[len++] = (tv_secs >>  8) & 0xff;
			txmessage[len++] = tv_secs         & 0xff;
			// Timestamp sent (microseconds)
			txmessage[len++] = (tv_usecs >> 24) & 0xff;
			txmessage[len++] = (tv_usecs >> 16) & 0xff;
			txmessage[len++] = (tv_usecs >>  8) & 0xff;
			txmessage[len++] = tv_usecs         & 0xff;
			// Timestamp received (seconds)
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			// Timestamp received (microseconds)
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			txmessage[len++] = 0;
			//
			// TLVs
			//
			//			TLVs (Type-Length-Value tuples) have the following format:
			//
			//			       0                   1                   2                   3
			//			       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//			      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//			      |             Type              |            Length             |
			//			      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//			      |                             Value                             |
			//			      .                                                               .
			//			      .                                                               .
			//			      .                                                               .
			//			      |                                                               |
			//			      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//			   Types are defined below; Length is the length of the Value field in
			//			   octets.  The Value field depends on the Type; it is zero padded to
			//			   align to a 4-octet boundary.  TLVs may be nested within other TLVs,
			//			   in which case the nested TLVs are called sub-TLVs.  Sub-TLVs have
			//			   independent types and MUST also be 4-octet aligned.
			//
			//			   A description of the Types and Values of the top-level TLVs for LSP
			//			   ping are given below:
			//
			//			          Type #                  Value Field
			//			          ------                  -----------
			//			               1                  Target FEC Stack
			//			               2                  Downstream Mapping
			//			               3                  Pad
			//			               4                  Not Assigned
			//			               5                  Vendor Enterprise Number
			//			               6                  Not Assigned
			//			               7                  Interface and Label Stack
			//			               8                  Not Assigned
			//			               9                  Errored TLVs
			//			              10                  Reply TOS Byte
			//
			// Always include a FEC TLV
			txmessage[len++] = 0;
			txmessage[len++] = 1; // Target FEC Stack (from types listed above)
			txmessage[len++] = 0;
			txmessage[len++] = 24; // length of LDP IPv6 prefix that follows
			//
			// A Target FEC Stack is a list of sub-TLVs.  The number of elements is
			//   determined by looking at the sub-TLV length fields.
			//
			//    Sub-Type       Length            Value Field
			//    --------       ------            -----------
			//           1            5            LDP IPv4 prefix
			//           2           17            LDP IPv6 prefix
			//           3           20            RSVP IPv4 LSP
			//           4           56            RSVP IPv6 LSP
			//           5                         Not Assigned
			//           6           13            VPN IPv4 prefix
			//           7           25            VPN IPv6 prefix
			//           8           14            L2 VPN endpoint
			//           9           10            "FEC 128" Pseudowire (deprecated)
			//          10           14            "FEC 128" Pseudowire
			//          11          16+            "FEC 129" Pseudowire
			//          12            5            BGP labeled IPv4 prefix
			//
			txmessage[len++] = 0;
			txmessage[len++] = 2; // Sub-type LDP IPv6 prefix
			txmessage[len++] = 0;
			txmessage[len++] = 17; // LDP IPv6 prefix TLV length as listed above
			//
			//			The Label Distribution Protocol (LDP) IPv6 FEC
			//			sub-TLV has the following format:
			//
			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                          IPv6 prefix                          |
			//      |                          (16 octets)                          |
			//      |                                                               |
			//      |                                                               |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      | Prefix Length |         Must Be Zero                          |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//
			//
			// copy the server's local address into the FEC entry
			for (i = 0; i < 16; i++)
			{
				txmessage[len++] = localaddr.sin6_addr.s6_addr[i] & 0xff;
			}
			txmessage[len++] = 128; // single host is /128
			txmessage[len++] = 0;   // 0-padding
			txmessage[len++] = 0;
			txmessage[len++] = 0;

			break;
		}

		case 11211: // memcache
		{
			len = 0;
			if (0 == special)
			{
				// ASCII mode
				// The frame header is 8 bytes long, as follows (all values are 16-bit integers
				// in network byte order, high byte first):
				//
				// 0-1 Request ID
				// 2-3 Sequence number
				// 4-5 Total number of datagrams in this message
				// 6-7 Reserved for future use; must be 0
				// <cmd>\r\n

				txmessage[len++] = 0x00; // Request ID
				txmessage[len++] = 0x01;
				txmessage[len++] = 0x00; // Sequence ID
				txmessage[len++] = 0x00;
				txmessage[len++] = 0x00; // Number of datagrams
				txmessage[len++] = 0x01;
				txmessage[len++] = 0x00; // Reserved for future use
				txmessage[len++] = 0x00;

				const char mccmd[] = "version";

				rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s\r\n", mccmd);
				if (rc < 0 || rc >= ( UDP_BUFFER_SIZE-(int)len ))
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for memcache command, returned %d\n", rc);
					retval = PORTINTERROR;
				}
				else
				{
					len += (unsigned int)rc;
				}
			}
			else
			{
				txmessage[len++] = 0x00; // Request ID
				txmessage[len++] = 0x01;
				txmessage[len++] = 0x00; // Sequence ID
				txmessage[len++] = 0x00;
				txmessage[len++] = 0x00; // Number of datagrams
				txmessage[len++] = 0x01;
				txmessage[len++] = 0x00; // Reserved for future use
				txmessage[len++] = 0x00;
				// Binary mode
				// https://github.com/couchbase/memcached/blob/master/docs/BinaryProtocol.md#0x0b-version
				//
				//  Byte/     0       |       1       |       2       |       3       |
				//     /              |               |               |               |
				//    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
				//    +---------------+---------------+---------------+---------------+
				//   0| 0x80          | 0x0b          | 0x00          | 0x00          |
				//    +---------------+---------------+---------------+---------------+
				//   4| 0x00          | 0x00          | 0x00          | 0x00          |
				//    +---------------+---------------+---------------+---------------+
				//   8| 0x00          | 0x00          | 0x00          | 0x00          |
				//    +---------------+---------------+---------------+---------------+
				//  12| 0x00          | 0x00          | 0x00          | 0x00          |
				//    +---------------+---------------+---------------+---------------+
				//  16| 0x00          | 0x00          | 0x00          | 0x00          |
				//    +---------------+---------------+---------------+---------------+
				//  20| 0x00          | 0x00          | 0x00          | 0x00          |
				//    +---------------+---------------+---------------+---------------+
				//
				txmessage[len++] = 0x80; //	request
				txmessage[len++] = 0x0b; //	opcode - Version
				txmessage[len++] = 0; //	keylength
				txmessage[len++] = 0; //	keylength
				txmessage[len++] = 0; //	extras length -must be 0, else "multipart not supported"
				txmessage[len++] = 1; //	data type    - must be 1, else "multipart not supported"
				txmessage[len++] = 0; //	reserved
				txmessage[len++] = 0; //	reserved
				txmessage[len++] = 0; //	total body length
				txmessage[len++] = 0; //	total body length
				txmessage[len++] = 0; //	total body length
				txmessage[len++] = 0; //	total body length
				txmessage[len++] = 0x21; //	opaque
				txmessage[len++] = 0x03; //	opaque
				txmessage[len++] = 0x14; //	opaque
				txmessage[len++] = 0x08; //	opaque
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
				txmessage[len++] = 0; //	cas
			}
			break;
		}

		default:
		{
			// Unhandled port
			IPSCAN_LOG( LOGPREFIX "check_udp_port: generating an unspecified message for UDP port %d\n", port);
			len = 0;
			// Generate an unspecified message
			txmessage[len++] = 0x0A;
			txmessage[len++] = 0x0A;
			txmessage[len++] = 0x0D;
			txmessage[len++] = 0x0;
			rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "IPscan (c) 2011-2025 Tim Chappell. See https://ipv6.chappell-family.com/ipv6tcptest/ This message is destined for UDP port %d\n", port);
			if (rc < 0 || rc >= (UDP_BUFFER_SIZE-(int)len))
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for unhandled port, returned %d\n", rc);
				retval = PORTINTERROR;
			}
			else
			{
				len += (unsigned int)rc;
			}
			break;
		}
		}
	}

	if (PORTUNKNOWN == retval)
	{
		rc = (int)write(fd,&txmessage,(size_t)len);
		if (rc < 0)
		{
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad write(port %d:%d) attempt, returned %d (%s)\n", port, special, errno, strerror(errno));
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad write(port %d) attempt, returned %d (%s)\n", port, errno, strerror(errno));
			}
			retval = PORTINTERROR;
		}
		else
		{
			#ifdef UDPDEBUG
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: write(port %d:%d) returned %d\n", port, special, rc);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: write(port %d) returned %d\n", port, rc);
			}
			#endif
		}
	}

	if (PORTUNKNOWN == retval)
	{
		rc = (int)read(fd,&rxmessage,UDP_BUFFER_SIZE);
		int errsv = errno ;
		if (rc < 0)
		{
			#ifdef UDPDEBUG
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad read(port %d:%d), returned %d (%s)\n", port, special, errno, strerror(errno));
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad read(port %d), returned %d (%s)\n", port, errno, strerror(errno));
			}
			#endif
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

			#ifdef RESULTSDEBUG
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: found port %d:%d returned read = %d, errsv = %d(%s)\n",port, special, rc, errsv, strerror(errsv));
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: found port %d returned read = %d, errsv = %d(%s)\n",port, rc, errsv, strerror(errsv));
			}
			#endif

			// If we haven't found a matching returncode/errno then log this ....
			if (PORTUNKNOWN == retval)
			{
				if (0 != special)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: read(port %d:%d) unexpected response, errno is : %d (%s) for host %s port %d\n", port, special,\
							errsv, strerror(errsv), hostname, port);
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: read(port %d) unexpected response, errno is : %d (%s) for host %s port %d\n", port, \
							errsv, strerror(errsv), hostname, port);
				}
				retval = PORTUNEXPECTED;
			}
		}
		else
		{
			retval = UDPOPEN;

			#ifdef UDPDEBUG
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: good read() of UDP port %d:%d, returned %d bytes\n", port, special, rc);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port: good read() of UDP port %d, returned %d bytes\n", port, rc);
			}

			// Log the summary of results internally - but only if LOGVERBOSITY is set to 1
			unsigned int rxlength = ( rc < UDPMAXLOGOCTETS ) ? rc : UDPMAXLOGOCTETS;
			i = 0;
			int position = 0;
			while (i < rxlength)
			{
				if (position == 0)
				{
					if (0 != special)
					{
						rc = snprintf(udplogbufferptr, udplogbuffersize, "check_udp_port: Found response packet for port %d:%d: %02x", port, special, (rxmessage[i] & 0xff) );
					}
					else
					{
						rc = snprintf(udplogbufferptr, udplogbuffersize, "check_udp_port: Found response packet for port %d: %02x", port, (rxmessage[i] & 0xff) );
					}
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

	// If we received any non-positive feedback then make sure we wait at least IPSCAN_MINTIME_PER_PORT secs
	if ((UDPOPEN != retval) && (UDPSTEALTH != retval)) sleep(IPSCAN_MINTIME_PER_PORT);

	return (retval);
}

int check_udp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, struct portlist_struc *udpportlist)
{
	pid_t childpid = fork();
	if (childpid > 0)
	{
		// parent
		#ifdef UDPPARLLDEBUG
		IPSCAN_LOG( LOGPREFIX "check_udp_ports_parll(): forked and started child PID=%d\n",childpid);
		#endif
	}
	else if (childpid == 0)
	{
		#ifdef UDPPARLLDEBUG
		IPSCAN_LOG( LOGPREFIX "check_udp_ports_parll(): startindex %d and todo %d\n",portindex,todo);
		#endif
		// child - actually do the work here - and then exit successfully
		const char unusedfield[8] = "unused\0";
		for (unsigned int i = 0 ; i <todo ; i++)
		{
			uint16_t port = udpportlist[(unsigned int)(portindex+i)].port_num;
			uint8_t special = udpportlist[(unsigned int)(portindex+i)].special;
			int result = check_udp_port(hostname, port, special);
			uint64_t write_result = 0;
                        if (result >= 0) write_result = (uint64_t)result;
			// Put results into database
			// make up to IPSCAN_DB_ACCESS_ATTEMPTS attempts in case of deadlock
			int rc = -1;
			for (unsigned int z = 0 ; z < IPSCAN_DB_ACCESS_ATTEMPTS && rc != 0; z++)
			{
				rc = write_db(host_msb, host_lsb, timestamp, session, (uint64_t)(port + ((special & IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_UDP << IPSCAN_PROTO_SHIFT)), write_result, unusedfield );
				if (rc != 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port_parll(): ERROR: write_db attempt %u returned %d\n", (z+1), rc);
					// Wait to improve chances of missing a database deadlock
					struct timespec rem;
                                        const struct timespec req = { IPSCAN_DB_DEADLOCK_WAIT_PERIOD_S, IPSCAN_DB_DEADLOCK_WAIT_PERIOD_NS };
                                        int rc2 = nanosleep( &req, &rem);
                                        if (0 != rc2)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: check_udp_port_parll() write_db nanosleep() returned %d(%s)\n", rc2, strerror(errno) );
                                        }
				}
			}
			if (0 != rc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: check_udp_port_parll(): ERROR: write_db loop exited after %d attempts with non-zero rc: %d\n", IPSCAN_DB_ACCESS_ATTEMPTS, rc);
			}
		}
		// Usual practice to have children _exit() whilst the parent calls exit()
		_exit(EXIT_SUCCESS);
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port_parll(): fork() failed childpid=%d, errno=%d(%s)\n", childpid, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return( (int)childpid );
}

