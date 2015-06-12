//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2015 Tim Chappell.
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
// 0.11			snmpv3 support

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

// Include externals : resultsstruct
extern struct rslt_struc resultsstruct[];

//
// Prototype declarations
//
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, char *indirecthost );

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

int check_udp_port(char * hostname, uint16_t port, uint8_t special)
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

	// Capture time of day and convert to NTP format
	struct timeval tv;
	gettimeofday(&tv, NULL);

	// Prefill transmit message buffer with 0s
	memset(&txmessage, 0,  UDP_BUFFER_SIZE);

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

	if (retval == PORTUNKNOWN) // continue
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

				if (1 == special) // NTP monlist case
				{
					txmessage[0] = 0x17; 	// NTP version 2, NTP_MODE = 7 (Private use)
					txmessage[1] = 0; 		// (Auth bit and sequence number)
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

				if (0 == special || 1 == special)
				{
					// SNMPv1 or SNMPv2c get
					// Note this code will need amending if you modify the mib string and it includes IDs with values >=128
					char community[16] = "public";
					char mib[32] = {1,2,1,1,1,0}; // system.sysDescr.0 - System Description minus 1.3.6 prefix
					int miblen = 6;
					len = 0;
					// SNMP packet start
					txmessage[len++] = 0x30;
					txmessage[len++] = (29 + strlen(community) + miblen);
					// SNMP version 1
					txmessage[len++] = 0x02; //int
					txmessage[len++] = 0x01; //length of 1
					txmessage[len++] = (special & 0xff); // 0 = SNMPv1, 1 = SNMPv2c
					// Community name
					txmessage[len++] = 0x04; //string
					txmessage[len++] = strlen(community);
					rc = sprintf(&txmessage[len], "%s", community);
					if (rc < 0)
					{
						IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for snmp, returned %d\n", rc);
						retval = PORTINTERROR;
					}
					else
					{
						len += rc;
					}
					// MIB
					txmessage[len++] = 0xA0; // SNMP GET request
					txmessage[len++] = (22 + miblen); //0x1c

					txmessage[len++] = 0x02; // Request ID
					txmessage[len++] = 0x04; // 4 octets length
					txmessage[len++] = 0x21; // "Random" value
					txmessage[len++] = 0x06;
					txmessage[len++] = 0x01;
					txmessage[len++] = 0x08;

					// Error status (0=noError)
					txmessage[len++] = 0x02; //int
					txmessage[len++] = 0x01; //length of 1
					txmessage[len++] = 0x00; // SNMP error status
					// Error index (0)
					txmessage[len++] = 0x02; //int
					txmessage[len++] = 0x01; //length of 1
					txmessage[len++] = 0x00; // SNMP error index
					// Variable bindings
					txmessage[len++] = 0x30; //var-bind sequence
					txmessage[len++] = (8 + miblen);

					txmessage[len++] = 0x30; //var-bind
					txmessage[len++] = (miblen +6 );

					txmessage[len++] = 0x06; // Object
					txmessage[len++] = (miblen + 2); // MIB length

					txmessage[len++] = 0x2b;
					txmessage[len++] = 0x06;
					// Insert the OID
					for (i = 0; i <miblen; i++)
					{
						txmessage[len++] = mib[i];
					}
					txmessage[len++] = 0x05; // Null object
					txmessage[len++] = 0x00; // length of 0
				}
				else if (2 == special)
				{
					// SNMPv3 engine discovery
					txmessage[len++] = 0x30;
					txmessage[len++] = 0x38; //(29 + strlen(community) + miblen);

					// SNMP version 3
					txmessage[len++] = 0x02; // int
					txmessage[len++] = 0x01; // length of 1
					txmessage[len++] = 0x03; // SNMP v3

					// msgGlobalData
					txmessage[len++] = 0x30;
					txmessage[len++] = 0x0e;

					txmessage[len++] = 0x02;
					txmessage[len++] = 0x01;
					txmessage[len++] = 0x02; // msgID

					txmessage[len++] = 0x02; //
					txmessage[len++] = 0x03; //
					txmessage[len++] = 0x00; // Max message size (less than 64K)
					txmessage[len++] = 0xff; //
					txmessage[len++] = 0xe3; //

					txmessage[len++] = 0x04;
					txmessage[len++] = 0x01;
					txmessage[len++] = 0x04; // flags (reportable, not encrypted, not authenticated)

					txmessage[len++] = 0x02;
					txmessage[len++] = 0x01;
					txmessage[len++] = 0x03; // msgSecurityModel is USM (3)

					// end of GlobalData

					txmessage[len++] = 0x04;
					txmessage[len++] = 0x10; //

					txmessage[len++] = 0x30; //
					txmessage[len++] = 0x0e; // length to end of this varbind

					txmessage[len++] = 0x04; //
					txmessage[len++] = 0x00; // EngineID

					txmessage[len++] = 0x02;
					txmessage[len++] = 0x01;
					txmessage[len++] = 0x00; // EngineBoots

					txmessage[len++] = 0x02;
					txmessage[len++] = 0x01;
					txmessage[len++] = 0x00; // EngineTime

					txmessage[len++] = 0x04; // UserName
					txmessage[len++] = 0x00;

					txmessage[len++] = 0x04; // Authentication Parameters
					txmessage[len++] = 0x00;

					txmessage[len++] = 0x04; // Privacy Parameters
					txmessage[len++] = 0x00;

					// msgData
					txmessage[len++] = 0x30; //
					txmessage[len++] = 0x11; //

					txmessage[len++] = 0x04; //  Context Engine ID (missing)
					txmessage[len++] = 0x00; //

					txmessage[len++] = 0x04; //  Context Name (missing)
					txmessage[len++] = 0x00; //

					txmessage[len++] = 0xa0; //  Get Request
					txmessage[len++] = 0x0b; //

					txmessage[len++] = 0x02; // Request ID (is 0x14)
					txmessage[len++] = 0x01; //
					txmessage[len++] = 0x14; //

					// Error status (0=noError)
					txmessage[len++] = 0x02; //int
					txmessage[len++] = 0x01; //length of 1
					txmessage[len++] = 0x00; // SNMP error status
					// Error index (0)
					txmessage[len++] = 0x02; //int
					txmessage[len++] = 0x01; //length of 1
					txmessage[len++] = 0x00; // SNMP error index
					// Variable bindings (none)
					txmessage[len++] = 0x30; //var-bind sequence
					txmessage[len++] = 0x00;

					// End of msgData
				}

				break;
			}

			case 500:
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
				// Next payload 0=None, 2=proposal, 4=key exchange
				txmessage[len++] = 4;
				// Version Major/Minor 1.0
				txmessage[len++] = 16;
				// Exchange type 4=aggressive
				txmessage[len++] = 4;
				// Flags
				txmessage[len++] = 0;

				// Message ID (4 bytes)
				txmessage[len++] = 128;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				// Length (4 bytes)
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = (28+12); // includes key exchange payload

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
				// next payload 0=none
				txmessage[len++] = 0;
				// reserved
				txmessage[len++] = 0;
				// length
				txmessage[len++] = 0;
				txmessage[len++] = 12;
				// Key exchange data
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
				txmessage[len++] = 0;
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
				IPSCAN_LOG( LOGPREFIX "check_udp_port: generating an unspecified message for UDP port %d\n", port);
				len = 0;
				// Generate an unspecified message
				txmessage[len++] = 0x0A;
				txmessage[len++] = 0x0A;
				txmessage[len++] = 0x0D;
				txmessage[len++] = 0x0;
				rc = sprintf(&txmessage[len], "ipscan (c) 2014 Tim Chappell. This message is destined for UDP port %d\n", port);
				if (rc < 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_udp_port: Bad snprintf() for unhandled port, returned %d\n", rc);
					retval = PORTINTERROR;
				}
				else
				{
					len += rc;
				}
				break;
			}
		}
	}

	if (retval == PORTUNKNOWN)
	{
		rc = write(fd,&txmessage,len);
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

	if (retval == PORTUNKNOWN)
	{
		rc=read(fd,&rxmessage,UDP_BUFFER_SIZE);
		if (rc < 0)
		{
			int errsv = errno ;
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
			int rxlength = ( rc < UDPMAXLOGOCTETS ) ? rc : UDPMAXLOGOCTETS;
			int i = 0;
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
	int i,rc,result;
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
		char unusedfield[8] = "unused";
		for (i = 0 ; i <(int)todo ; i++)
		{
			uint16_t port = udpportlist[portindex+i].port_num;
			uint8_t special = udpportlist[portindex+i].special;
			result = check_udp_port(hostname, port, special);
			// Put results into database
			rc = write_db(host_msb, host_lsb, timestamp, session, (port + ((special & IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_UDP << IPSCAN_PROTO_SHIFT)), result, unusedfield );
			if (rc != 0)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port_parll(): ERROR: write_db returned %d\n", rc);
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

