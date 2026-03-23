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
// 0.40 		update copyright year
// 0.41			add function to get local IPv6 address
// 1.00			add raw sockets functionality
// 1.01			update while() loop with continues
// 1.02			add raw socket BPF filter to reduce userland processing

//
#define IPSCAN_UDP_VER "1.02"
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

// Interface name length
#include <net/if.h>

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

// Define offset into ICMPv6 packet where user-defined data resides
#define ICMP6DATAOFFSET sizeof(struct icmp6_hdr)

// Other IPv6 related
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/ipv6.h>
// RAW
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/select.h>

// BPF support
#include <linux/if_ether.h>
#include <linux/filter.h>

//
// Prototype declarations
//
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint64_t port, uint64_t result, const char *indirecthost );
unsigned short checksum(unsigned short *ptr, int nbytes) ; // RAW
int get_my_local_ipaddr(const char *dest_ip, struct in6_addr *local_ip);
void print_ids(const char * place);
int drop_privileges();
int regain_privileges();
void result_to_string(uint32_t result, char * retstring);
uint32_t get_random32(void);
uint16_t get_ephemeral(void);
//
#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
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
/* FUNCTIONALITY OUTLINE

	0. retval = PORTUNKNOWN, create sockets, select ports, configure sockets, apply filter
	0b. create/send packet to elicit response
	1. while (retval == PORTUNKNOWN && sockets valid)
	{
	2. poll()
	2b. if error then log, set retval and continue;
	2c. else if (poll timeout) then retval = STEALTH/break; // we timed out and no response
	3.  if (PROTO events && POLLIN && retval == PORTUNKNOWN) // UDP/TCP packet received
		while (retval == PORTUNKNOWN)
		{
			recvfrom (NONBLOCKING)
			if error (EAGAIN or EWOULDBLOCK) then break; // this recvfrom is done - we've looked at all packets
			check size exceeds minimum
			check source address == DUT, report if not and continue;
			check swapped src/dest ports match our transmission, report if not and continue;
			[TCP] check ack sequence matches our (transmission+1), report if not and continue;
			if all matches && TCP then check flags
				ACK => OPEN
				RST => REFUSED
			if (all matches && UDP) then UDPOPEN
		}
	4. if (ICMPv6 event && POLLIN && retval == PORTUNKNOWN) // only look at ICMPv6 if we haven't had something valid in TCP/UDP socket
		while (retval == PORTUNKNOWN)
		{
			indirect = 0; // direct
			recvfrom (NONBLOCKING)
			if error (EAGAIN or EWOULDBLOCK) then break; // this recvfrom is done - we've looked at all packets
			check size exceeds minimum
			check ICMPv6 header source address == DUT && inner packet matches
				if (sa == DUT) then indirect = 0
				else if (sa != DUT && sa != localhost && sa != localip) then log and set indirect = IPSCAN_INDIRECT_RESPONSE;
				else not for us, so continue
			check inner IPv6 source & destination addresses and NEXTHDR match our transmission, report if not and continue;
			check inner TCP/UDP src/dest ports match our transmission, report if not and continue;
			[TCP] check inner TCP sequence matches our transmission+1, report if not and continue;
			set retval based on ICMPv6 type/code
		}
	}
	close sockets
	return (retval + indirect)
		
END OF FUNCTIONALITY OUTLINE: */
//
// ----------------------------------------------------------------
//
int check_udp_port_raw(char * hostname, uint16_t port, uint8_t special, char * indhost_ptr)
{
	char txmessage[UDP_BUFFER_SIZE+1];
	struct sockaddr_in6 remoteaddr;
	struct timeval timeout;
	struct sockaddr_in6 localaddr;
	int rc = 0;
	// set return value to a known default
	int retval = PORTUNKNOWN;

	#ifdef IPSCAN_PRIV_DEBUG
	print_ids("start of udp_raw");
	#endif

 	struct in6_addr my_tx_ipaddr, dest_ip;
	struct sockaddr_in6 local_sockaddr;

	// lodge/create UDP header parameters
        uint16_t my_tx_src_port = get_ephemeral();
        uint16_t my_tx_dst_port = port;


	// Convert the HUT's hostname to a struct in6_addr
        if (inet_pton(AF_INET6, hostname, &dest_ip) == 1)
        {
		#ifdef UDPDEBUG
                IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: entering with host %s, dstport %u and special %u, selecting srcport = %u\n",\
                        hostname, my_tx_dst_port, special, my_tx_src_port);
		#endif
        }  
        else
        {
                IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: inet_pton() for HUT: %s\n", hostname);
                retval = PORTINTERROR;
        }

	// determine local address (my_tx_ipaddr) which is used to send to hostname
    	rc = get_my_local_ipaddr(hostname, &my_tx_ipaddr);
	if (EXIT_FAILURE == rc)
	{
                IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: get_my_local_ipaddr() returned with an error\n");
		retval = PORTINTERROR;
	}

	memset(&local_sockaddr, 0, sizeof(struct sockaddr_in6));
	local_sockaddr.sin6_family = AF_INET6;
	local_sockaddr.sin6_addr = my_tx_ipaddr;
	local_sockaddr.sin6_port = 0; // Must be 0 for raw sockets to avoid EINVAL

	// Set to IPSCAN_INDIRECT_RESPONSE if another host responds on the DUT's behalf (e.g. a mid-point router or firewall)
        int indirect = 0; // default - report as direct response. 

	// struct for an ICMPv6 filter, so only wanted types are received
        struct icmp6_filter myfilter;

	// Local address update indication
	int found_la_name = 0;

	rc = 0;
	unsigned int i = 0;

	// Holds length of transmitted UDP packet, which since they are representative packets,
	//  depends on the port being tested
	unsigned int len = 0;

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

	// Create localaddr sockaddr_in6 structure - for use in address comparison
	memset(&localaddr, 0, sizeof(struct sockaddr_in6));
	// Fill in a default address in case getifaddrs() is unsuccessful
	rc = inet_pton(AF_INET6, "::1", &(localaddr.sin6_addr));
	if (rc != 1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: ERROR: Bad inet_pton() call for localaddr, returned %d with errno %d (%s)\n", rc, errno, strerror(errno));
		retval = PORTINTERROR;
	}
	localaddr.sin6_port = htons(port);
	localaddr.sin6_family = AF_INET6;
	localaddr.sin6_flowinfo = 0;
	localaddr.sin6_scope_id = 0;

	// Determine transmit interface name and then MAC address
	rc = getifaddrs( &ifaddr );
	if (rc == -1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: ERROR: getifaddrs() failed, returned %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}
	else
	{
		// find the interface name based on the address that we've already determined
		char my_tx_intname[IFNAMSIZ+1];
		memset(my_tx_intname, 0, sizeof(my_tx_intname));
		for (ifa = ifaddr; (NULL != ifa); ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr == NULL) continue; // skip
			int family = ifa->ifa_addr->sa_family;

			if ( family == AF_INET6 && IN6_ARE_ADDR_EQUAL(&(local_sockaddr.sin6_addr), &((*((struct sockaddr_in6*)ifa->ifa_addr)).sin6_addr)) == 1)
			{
				memcpy(my_tx_intname, ifa->ifa_name, strnlen(ifa->ifa_name,IFNAMSIZ) ); // store the interface name
				found_la_name = 1;
				#ifdef UDPDEBUG
				IPSCAN_LOG( LOGPREFIX "check_udp_port: INFO: found device name for transmit interface: %s\n", my_tx_intname);
				#endif
			} 
		}
		// if we found the interface name then attempt to find the link-local (MAC) address
		if (found_la_name == 1)
		{
			for (ifa = ifaddr; (NULL != ifa); ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr == NULL) continue;
				int family = ifa->ifa_addr->sa_family;

				if ( family == AF_PACKET && strcasecmp(ifa->ifa_name,my_tx_intname) == 0 && lam_update == 0 )
				{
					// Copy result to localmacaddr for later use (DHCPv6)
					struct sockaddr_ll *sa_ll = (struct sockaddr_ll * )ifa->ifa_addr;
					for (i = 0; i < 6; i++) localmacaddr[i] = sa_ll->sll_addr[i];
					lam_update = 1;
					#ifdef UDPDEBUG
					IPSCAN_LOG( LOGPREFIX "check_udp_port: INFO: found MAC address for transmit interface: %02x:%02x:%02x:%02x:%02x:%02x\n",\
						localmacaddr[0], localmacaddr[1], localmacaddr[2], localmacaddr[3], localmacaddr[4], localmacaddr[5]);
					#endif
				}
			}
		}
		freeifaddrs(ifaddr);
	}

	if (found_la_name == 0 || lam_update == 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: ERROR: failed to determine the transmit interface device name or MAC address\n");
		retval = PORTINTERROR;
	}

	// Populate remoteaddr as HUT (hostname)
	rc = inet_pton(AF_INET6, hostname, &(remoteaddr.sin6_addr));
	if (rc != 1)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port: ERROR Bad inet_pton() call for hostname, returned %d with errno %d (%s)\n", rc, errno, strerror(errno));
		retval = PORTINTERROR;
	}
	remoteaddr.sin6_port = htons(port);
	remoteaddr.sin6_family = AF_INET6;
	remoteaddr.sin6_flowinfo = 0;
	remoteaddr.sin6_scope_id = 0; // unused in our case

	// Attempt to create a socket
	int udp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	if (udp_sock < 0)
        {
        	IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: UDPv6 socket. Need root privileges? Unexpected failure : %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
        }

    	int icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmp_sock < 0)
        {
        	IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: ICMPv6 socket. Need root privileges? Unexpected failure : %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
        }

	// Set socket timeouts tx/rx for both UDP and ICMPv6 raw sockets
	if (PORTUNKNOWN == retval)
	{
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = UDPTIMEOUTSECS;
		timeout.tv_usec = UDPTIMEOUTMICROSECS;

		rc = setsockopt(udp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad UDPv6 setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

	if (PORTUNKNOWN == retval)
	{
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = UDPTIMEOUTSECS;
		timeout.tv_usec = UDPTIMEOUTMICROSECS;

		rc = setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad UDPv6 setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

      	// Assuming something bad hasn't already happened then attempt to set the ICMPv6 timeouts
	if (PORTUNKNOWN == retval)
	{
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = UDPTIMEOUTSECS;
		timeout.tv_usec = UDPTIMEOUTMICROSECS;

		rc = setsockopt(icmp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad ICMPv6 setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}
        else
        {
                IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 setsockopt SO_SNDTIMEO not attempted\n");
        }

        if (PORTUNKNOWN == retval)
        {
                // Set receive timeout
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = UDPTIMEOUTSECS;
                timeout.tv_usec = UDPTIMEOUTMICROSECS;
                int timeo = setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                if (timeo < 0)
                {
                        int errsv = errno ;
                        IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad ICMPv6 setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
                        retval = PORTINTERROR;
                }
        }
        else
        {
                IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 setsockopt SO_RCVTIMEO not attempted\n");
        }

	if (retval == PORTUNKNOWN)
	{
        	// Filter out all the ICMPv6 responses except the ones we're looking for
        	// taken from RFC3542
        	ICMP6_FILTER_SETBLOCKALL(&myfilter);
        	// Start-of-pragma to prevent gcc sign-conversion warnings ...
        	#pragma GCC diagnostic push
        	#pragma GCC diagnostic ignored "-Wsign-conversion"
        	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &myfilter);
        	ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &myfilter);
        	ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &myfilter);
        	ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &myfilter);
        	#pragma GCC diagnostic pop
        	// End-of-pragma
        	rc = setsockopt(icmp_sock, IPPROTO_ICMPV6, ICMP6_FILTER, &myfilter, sizeof(myfilter));
        	if (rc < 0)
        	{
               		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: setsockopt: setting ICMPv6 filter: %s (%d)\n", strerror(errno), errno);
               		retval = PORTINTERROR;
        	}
	}

	if (retval == PORTUNKNOWN)
	{
		// Bind both sockets to our local address
		rc = bind(udp_sock, (const struct sockaddr *)&local_sockaddr, sizeof(struct sockaddr_in6));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: failed to bind udp_sock = %d(%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

	if (retval == PORTUNKNOWN)
	{
		rc = bind(icmp_sock, (const struct sockaddr *)&local_sockaddr, sizeof(struct sockaddr_in6));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: failed to bind icmp_sock = %d(%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

        if (PORTUNKNOWN == retval)
        {
		// Create a BPF socket filter that checks source/destination ports
		struct sock_fprog Filter;
    
		// NOTE: IPv6 raw socket returns No MAC header and No IP header - so data (&offsets) start at UDP layer
		struct sock_filter BPF_code[] = {
			// 0. Check Source Port (Offset 0, 2 bytes)  
			{ BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x00000000 },         // LDH [0]
			{ BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x0123 },            // JEQ #0x0123, else skip 3
			// 2. Check Destination Port (Offset 2, 2 bytes)
			{ BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x00000002 },         // LDH [2]
			{ BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x4567 },            // JEQ #0x4567, else skip 1
			// 4. Responses
			{ BPF_RET | BPF_K, 0, 0, 0x00040000 },			// Pass (Return max length)
			{ BPF_RET | BPF_K, 0, 0, 0x00000000 }			// Drop
        	};

		// adjust the dummy port numbers above to match the ones we actually transmitted/expect
		BPF_code[1].k = my_tx_dst_port; //the source port we're comparing was the destination port of our transmission
		BPF_code[3].k = my_tx_src_port; //the destination port we're comparing was the source port of our transmission

		Filter.len = sizeof(BPF_code) / sizeof(struct sock_filter);
		Filter.filter = BPF_code;

    		// Attach the filter
    		rc = setsockopt(udp_sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter));
		if (rc < 0 )
		{
                	IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: setsockopt: attaching BPF filter: %s (%d)\n", strerror(errno), errno);
                	retval = PORTINTERROR;
    		}
	}

	// Socket is created/configured so drop privileges
	rc = drop_privileges();
	if (rc != EXIT_SUCCESS)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: drop_privileges() returned %d\n", rc);
                retval = PORTINTERROR;
	}

        // If something bad has happened then return now ...
        // mustn't return to caller with root privileges, hence done here ...
        if (PORTUNKNOWN != retval)
        {
                if (-1 != udp_sock) close(udp_sock); // close socket if appropriate
                if (-1 != icmp_sock) close(icmp_sock); // close socket if appropriate
		rc = regain_privileges();
		if (rc != EXIT_SUCCESS)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: regain_privileges() returned %d\n", rc);
		}
                return (retval);
        }

	//
	// Write the selected UDP packet content into txmessage, based on the selected port
	//
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
			rc = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "IPscan (c) 2011-2026 Tim Chappell. See https://ipv6.chappell-family.com/ipv6udptest/ This message is destined for UDP port %d\n", port);
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

	// define and clear the send and receive buffers
        unsigned char send_buf[IP_MAXPACKET], rcv_buf[IP_MAXPACKET];
	memset(send_buf, 0, IP_MAXPACKET);
	memset(rcv_buf, 0, IP_MAXPACKET);

	// udphdr will be the start of the packet we send (so begins at send_buf (offset 0)
	// all the udphdr fields are 16-bit 
	struct udphdr *udp = (struct udphdr *)send_buf;
	uint16_t udp_len = (uint16_t)(sizeof(struct udphdr) + len); // header size plus message length (len)
        udp->source = htons(my_tx_src_port);
        udp->dest = htons(my_tx_dst_port);
    	udp->len = htons(udp_len);

	// Create the pseudo-header so we can determine the checksum
    	struct pseudo_hdr ph = { .src = my_tx_ipaddr, .dst = dest_ip, .len = htonl(udp_len), .next_hdr = IPPROTO_UDP };
    	unsigned char check_buf[IP_MAXPACKET]; // to hold the pseudo-header plus real packet for checksum calculation only
	// fill the checksum buffer - pseudo-header + udp header + udp body
    	memcpy(check_buf, &ph, sizeof(ph));
	memcpy(check_buf+sizeof(ph), udp, sizeof(struct udphdr));
    	memcpy(check_buf + sizeof(ph)+ sizeof(struct udphdr), txmessage, len);

	// calculate the udp checksum from check_buf data - total length is pseudo-header + UDP header + message body
	// put the result into udp->check
    	udp->check = checksum((unsigned short*)check_buf, sizeof(ph) + udp_len);

	// add the txmessage octets to the end of the send_buf (the buffer we'll actually transmit)
	// it alread has the udp header (inc checksum) at the start, so offset appropriately
    	memcpy(send_buf + sizeof(struct udphdr), txmessage, len);

	// Send the packet
	if (PORTUNKNOWN == retval)
	{
		// Send the message - UDP header + message body (txmessage, len octets)
    		struct sockaddr_in6 d_addr = { .sin6_family = AF_INET6, .sin6_addr = dest_ip };
    		ssize_t bytes_sent = sendto(udp_sock, send_buf, udp_len, 0, (struct sockaddr *)&d_addr, sizeof(d_addr));

		if (bytes_sent < 0) // error condition
		{
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad sendto(port %d:%d) attempt, returned %d (%s)\n", port, special, errno, strerror(errno));
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad sendto(port %d) attempt, returned %d (%s)\n", port, errno, strerror(errno));
			}
			retval = PORTINTERROR;
		}
		else // successful sendto()
		{
			#ifdef UDPDEBUG
			if (0 != special)
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: sendto(port %d:%d) sent %ld octets\n", port, special, bytes_sent);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: sendto(port %d) sent %ld octets\n", port, bytes_sent);
			}
			#endif
		}
	}

	// Calculate/create localhost sockaddr_in6 structure - for later address comparison
	struct sockaddr_in6 localhost_addr;
	memset(&localhost_addr, 0, sizeof(localhost_addr));
	localhost_addr.sin6_family = AF_INET6;
	localhost_addr.sin6_port = 0; // Must be 0 for raw sockets to avoid EINVAL
	// Convert IPv6 localhost
	rc = inet_pton(AF_INET6, "::1", &localhost_addr.sin6_addr);
	if (rc < 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Bad inet_pton for localhost, returned %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}

	time_t timestart = time(0);
	if (timestart < 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: time() returned bad value for timestart %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}
	time_t timenow = timestart;
	unsigned int loopcount = 0;

	//
	// Start of the main receive loop which is based on the functionality outline described above
	//
	while (((timenow-timestart) <= (UDPTIMEOUTSECS+2)) && (retval == PORTUNKNOWN))
	{ // OUTER LOOP
	        loopcount++;
		#ifdef UDPDEBUG
		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: OUTER loopcount = %u for HUT %s dst port %u special %u\n", loopcount, hostname, my_tx_dst_port, special);
		#endif
		// file descriptors for UDP and ICMPv6
		struct pollfd fds[2];
		fds[0].fd = udp_sock;
		fds[0].events = POLLIN;
		fds[1].fd = icmp_sock;
		fds[1].events = POLLIN;

		// Poll for a response on either socket
		int pollrc = poll(fds, 2, (UDPTIMEOUTSECS*1000+100)); // timeout is in ms
		if (pollrc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: OUTERLOOP poll error for HUT %s dst port %u special %u, %d(%s)\n",\
				hostname, my_tx_dst_port, special, errno, strerror(errno));
			retval = PORTINTERROR;
			continue;
		}
		else if (pollrc == 0)
		{
			// timeout
			#ifdef UDPDEBUG
       		 	IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: OUTERLOOP poll timeout for HUT %s dstport %u special %u\n", hostname, my_tx_dst_port, special);
			#endif
			retval = UDPSTEALTH;
			continue;
		}
		else
		{
			if ((fds[0].revents & POLLIN) && (retval == PORTUNKNOWN)) // UDP socket has some data
			{
				unsigned int udp_loopcount = 0;
				while (retval == PORTUNKNOWN)
				{
					udp_loopcount++;
					// NON-BLOCKING - if there's nothing there then move on
					struct sockaddr_storage rx_src_addr;
					socklen_t rx_src_addr_len = sizeof(rx_src_addr);
					char rx_ip6addr_str[INET6_ADDRSTRLEN+1];
					ssize_t bytes_received = recvfrom(udp_sock, rcv_buf, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&rx_src_addr, &rx_src_addr_len);
					if (bytes_received < 0) // error condition
					{
						if (errno == EAGAIN || errno == EWOULDBLOCK) // nothing to receive - we're done with this socket
						{
							#ifdef UDPDEBUG
       		 					IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: HUT %s dstport %u special %u UDP recvfrom() UDP loopcount %u returned indicating nothing received %d(%s)\n",\
								hostname, my_tx_dst_port, special, udp_loopcount, errno, strerror(errno));
							#endif
						}
						else // an actual error
						{
       		 					IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: HUT %s dstport %u special %u UDP recvfrom() UDP loopcount %u returned error %d(%s)\n", \
								hostname, my_tx_dst_port, special, udp_loopcount, errno, strerror(errno));
						}
						// nothing useful we can do - break from this loop and try ICMPv6
						break;
					}
					else if (bytes_received >= (ssize_t)(sizeof(struct udphdr)) )
					{
						#ifdef IPSCAN_BPF_DEBUG
						// dump header bytes to allow for BPF filter debug
                                                if (bytes_received >= 16)
                                                {
                                                        IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: INFO rcv_buf 00-07: %02x %02x %02x %02x %02x %02x %02x %02x\n", \
                                                                rcv_buf[0], rcv_buf[1], rcv_buf[2], rcv_buf[3], rcv_buf[4], rcv_buf[5], rcv_buf[6], rcv_buf[7]);
                                                        IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: INFO rcv_buf 08-15: %02x %02x %02x %02x %02x %02x %02x %02x\n", \
                                                                rcv_buf[8], rcv_buf[9], rcv_buf[10], rcv_buf[11], rcv_buf[12], rcv_buf[13], rcv_buf[14], rcv_buf[15]);
                                                }
						#endif

						#ifdef UDPDEBUG
       		 				IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: HUT %s dstport %u special %u UDP recvfrom() UDP loopcount %u returned %ld octets\n", \
							hostname, my_tx_dst_port, special, udp_loopcount, bytes_received);
						#endif
						// compare the received packet with what we're expecting
						struct sockaddr_in6 *rx_sockaddr_in6 = (struct sockaddr_in6 *)&rx_src_addr;
						struct udphdr *udphdr_ptr = (struct udphdr *)rcv_buf;
						if (rx_src_addr.ss_family == AF_INET6)
						{
							// Convert receive address (binary) to string and report size
							if (inet_ntop(AF_INET6, &(rx_sockaddr_in6->sin6_addr), rx_ip6addr_str, sizeof(rx_ip6addr_str)) != NULL)
							{
								#ifdef UDPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 recvfrom() size %ld from host %s\n",\
									 bytes_received, rx_ip6addr_str);
								#endif
							}
							else // address conversion failed, so check for another packet
							{
								#ifdef UDPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 inet_ntop() returned %d(%s), so SKIP\n", errno, strerror(errno));
								#endif
								continue;
							}
							// Check if received packet is from HUT
							if ( IN6_ARE_ADDR_EQUAL( &dest_ip, &(rx_sockaddr_in6->sin6_addr)) == 1)
							{
								#ifdef UDPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 response received from HUT\n");
								#endif
								// Now we know response is from HUT then start checking the detail - reversed src/dst ports. UDP has no sequence
								if ((ntohs(udphdr_ptr->source) == my_tx_dst_port) && (ntohs(udphdr_ptr->dest) == my_tx_src_port))
								{
									#ifdef UDPDEBUG
									IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 response packet for HUT %s dstport %u special %u UDP loopcount %u\n",\
										hostname, my_tx_dst_port, special, udp_loopcount );
									#endif
									retval = UDPOPEN;
									continue; // retval setting should complete the loop
								}
								else
								{
									#ifdef UDPDEBUG
									IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 response packet mismatch for HUT %s dstport %u spec %u UDP loopcount %u, received srcport %u, dstport %u, so SKIP\n",\
										hostname, my_tx_dst_port, special, udp_loopcount,ntohs(udphdr_ptr->source), ntohs(udphdr_ptr->dest));
									#endif
									continue;
								}
							}
							else
							{
								#ifdef UDPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 srcaddress mismatch, for HUT %s dstport %u special %u UDP loopcount %u, actually from: %s, so SKIP\n",\
									 hostname, my_tx_dst_port, special, udp_loopcount, rx_ip6addr_str);
								#endif
								continue;
							}
						}
						else
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: UDPv6 response packet for HUT %s dstport %u special %u UDP loopcount %u was not IPv6, so SKIP\n",\
								hostname, my_tx_dst_port, special, udp_loopcount);
							#endif
							continue;
						}
					}
					else // too few bytes received - check for another packet
					{
						#ifdef UDPDEBUG
       		 				IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: HUT %s dstport %u special %u UDP recvfrom() UDP loopcount %u returned too few octets: %ld, so SKIP\n", \
							hostname, my_tx_dst_port, special, udp_loopcount, bytes_received);
						#endif
						continue;	
					}
				} // end of UDP socket while loop
			} // end of UDP socket if

			// Check ICMPv6 if nothing found for UDP socket
			if ((fds[1].revents & POLLIN) && (retval == PORTUNKNOWN)) // ICMPv6 socket has some data
			{
				unsigned int icmp_loopcount = 0;
				while (retval == PORTUNKNOWN)
				{
					icmp_loopcount++;
					struct sockaddr_storage rx_src_addr;
					socklen_t rx_src_addr_len = sizeof(rx_src_addr);
					// NON-BLOCKING - if there's nothing there then move on
					ssize_t bytes_received = recvfrom(icmp_sock, rcv_buf, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&rx_src_addr, &rx_src_addr_len);
					if (bytes_received < 0) // error condition
					{
						if (errno == EAGAIN || errno == EWOULDBLOCK) // nothing to receive - we're done with this socket
						{
							#ifdef UDPDEBUG
       		 					IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: HUT %s dstport %u special %u ICMPv6 recvfrom() ICMPv6 loopcount %u returned indicating nothing received %d(%s)\n",\
								hostname, my_tx_dst_port, special, icmp_loopcount, errno, strerror(errno));
							#endif
						}
						else // an actual error
						{
							#ifdef UDPDEBUG
       		 					IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: HUT %s dstport %u special %u UDP recvfrom() ICMPv6 loopcount %u returned error %d(%s)\n", \
								hostname, my_tx_dst_port, special, icmp_loopcount, errno, strerror(errno));
							#endif
						}
						// nothing useful we can do - break from this loop
						break;
					}
					else if (bytes_received >= ((ssize_t)(sizeof(struct icmp6_hdr)+sizeof(struct ipv6hdr)+sizeof(struct udphdr))))
					{
						struct sockaddr_in6 *rx_sockaddr_in6 = (struct sockaddr_in6 *)&rx_src_addr;
						struct icmp6_hdr *rx_icmphdr_ptr = (struct icmp6_hdr *)rcv_buf;
						struct ipv6hdr *rx_ipv6hdr_ptr = (struct ipv6hdr *)(rcv_buf + sizeof(struct icmp6_hdr));
						struct udphdr *rx_udphdr_ptr = (struct udphdr *)(rcv_buf + sizeof(struct icmp6_hdr) + sizeof(struct ipv6hdr));
						char rx_ip6addr_str[INET6_ADDRSTRLEN];
						if (rx_src_addr.ss_family == AF_INET6)
       		                                {
                                                	// Convert binary to string
                                                	if (inet_ntop(AF_INET6, &(rx_sockaddr_in6->sin6_addr), rx_ip6addr_str, sizeof(rx_ip6addr_str)) != NULL)
                                                	{
								#ifdef UDPDEBUG
                                                       		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 recvfrom() size %ld from host %s\n",\
                                                        		bytes_received, rx_ip6addr_str);
								#endif
                                                	}
                                                	else // check for another packet
                                                	{
								#ifdef UDPDEBUG
                                                       		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 inet_ntop() returned %d(%s), so SKIP\n", errno, strerror(errno));
								#endif
                                                       		continue;
                                                	}
						}
						else
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 response was not from an IPv6 source, so SKIP\n");
							#endif
							continue;
						}
						if ( IN6_ARE_ADDR_EQUAL( &dest_ip, &(rx_sockaddr_in6->sin6_addr)) == 1 \
							&& (rx_ipv6hdr_ptr->nexthdr == IPPROTO_UDP && IN6_ARE_ADDR_EQUAL( &rx_ipv6hdr_ptr->daddr, &dest_ip ) == 1 \
                               		                && IN6_ARE_ADDR_EQUAL(&local_sockaddr.sin6_addr, &rx_ipv6hdr_ptr->saddr) == 1 )\
                               		                && (ntohs(rx_udphdr_ptr->source) == my_tx_src_port) && (ntohs(rx_udphdr_ptr->dest) == my_tx_dst_port))
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: Matching ICMPv6 response received from HUT\n");
							#endif
							indirect = 0; // from expected host
						}
						else if (  (IN6_ARE_ADDR_EQUAL( &dest_ip, &(rx_sockaddr_in6->sin6_addr)) == 0) \
							&& (IN6_ARE_ADDR_EQUAL( &localhost_addr.sin6_addr, &(rx_sockaddr_in6->sin6_addr)) == 0)\
							&& (IN6_ARE_ADDR_EQUAL( &local_sockaddr.sin6_addr, &(rx_sockaddr_in6->sin6_addr)) == 0)\
							&& (rx_ipv6hdr_ptr->nexthdr == IPPROTO_UDP && IN6_ARE_ADDR_EQUAL( &rx_ipv6hdr_ptr->daddr, &dest_ip ) == 1 \
                                       		        && IN6_ARE_ADDR_EQUAL(&local_sockaddr.sin6_addr, &rx_ipv6hdr_ptr->saddr) == 1 )\
                                       		        && (ntohs(rx_udphdr_ptr->source) == my_tx_src_port) && (ntohs(rx_udphdr_ptr->dest) == my_tx_dst_port) )
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: INDIRECT: Matching ICMPv6 response is NOT from HUT, potentially from another mid-point device: %s\n", rx_ip6addr_str);
							#endif
							indirect = IPSCAN_INDIRECT_RESPONSE; // not expected source address (HUT) but also NOT (localhost or our source address)
							// copy string address
							memset(indhost_ptr, 0, INET6_ADDRSTRLEN); //Blank it first
							memcpy(indhost_ptr, rx_ip6addr_str, INET6_ADDRSTRLEN); // copy the source address string over it
						}
						else
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 response is NOT from HUT, or from suitable mid-point device address : %s, or else mismatches, so SKIP\n", rx_ip6addr_str);
							#endif	
							continue; // a packet we're not expecting - could be from a 3rd party, ourselves, or localhost
						}
						// Inner ICMPv6 should already match if we get to here - so could be simplified
						if ((rx_ipv6hdr_ptr->nexthdr == IPPROTO_UDP && IN6_ARE_ADDR_EQUAL( &rx_ipv6hdr_ptr->daddr, &dest_ip ) == 1 \
							&& IN6_ARE_ADDR_EQUAL(&local_sockaddr.sin6_addr, &rx_ipv6hdr_ptr->saddr) == 1 )\
						 	&& (ntohs(rx_udphdr_ptr->source) == my_tx_src_port) && (ntohs(rx_udphdr_ptr->dest) == my_tx_dst_port))
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 response received with inner IP packet UDP next header and UDP src/dst port matches\n");
							#endif
							if (rx_icmphdr_ptr->icmp6_type < 128)
							{ // Error messages only - ignore neighbour discovery, etc. ICMPv6 filter should stop non-error cases being delivered
								#ifdef UDPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 error received for %s port %u, Type %d Code %d\n",\
									hostname, port, rx_icmphdr_ptr->icmp6_type, rx_icmphdr_ptr->icmp6_code);
								#endif
								if (rx_icmphdr_ptr->icmp6_type == 1)
								{
									#ifdef UDPDEBUG
									const char *codes[] = {"No route", "Admin prohibited", "Beyond scope", "Addr unreachable", "Port unreachable"};
									IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 : %s\n", (rx_icmphdr_ptr->icmp6_code <= 4) ? codes[rx_icmphdr_ptr->icmp6_code] : "Unknown unreachable");
									#endif
									if (rx_icmphdr_ptr->icmp6_code == 0)
									{
										retval = PORTUNREACHABLE; // checked - No route to destination - add new response?
									}
									else if (rx_icmphdr_ptr->icmp6_code == 1)
									{	
										retval = PORTPROHIBITED; // checked - Administratively prohibited
									}
									else if (rx_icmphdr_ptr->icmp6_code == 2)
									{	
										retval = PORTBEYONDSCOPE; // checked - Beyond scope of source address
									}
									else if (rx_icmphdr_ptr->icmp6_code == 3)
									{	
										retval = PORTNOROUTE; // check - address unreachable from wireshark
									}
									else if (rx_icmphdr_ptr->icmp6_code == 4)
									{
										retval = PORTUNREACHABLE; // checked
									}
									else if (rx_icmphdr_ptr->icmp6_code == 5)
									{
										retval = PORTFAILEDPOLICY; // checked - good
									}
									else if (rx_icmphdr_ptr->icmp6_code == 6)
									{
										retval = PORTREJECTROUTE; // checked - good
									}
									else // catchall - for other unhandled values
									{
										#ifdef UDPDEBUG
										IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Unhandled ICMPv6 type 1, code = %d for host %s port %u\n", rx_icmphdr_ptr->icmp6_code, hostname, port);
										#endif
										retval = PORTINTERROR;
									}
								}
								else if (rx_icmphdr_ptr->icmp6_type == 2)
								{
									retval = PORTPKTTOOBIG; // checked
								}
								else if (rx_icmphdr_ptr->icmp6_type == 3)
								{
									retval = PORTTIMEEXCEEDED; // checked
								}
								else if (rx_icmphdr_ptr->icmp6_type == 4)
								{
									retval = PORTPARAMPROB; // checked
								}
								else
								{
									#ifdef UDPDEBUG
									IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: Unhandled ICMPv6 type: %d\n", rx_icmphdr_ptr->icmp6_type);
									#endif
									continue;
								}
							}
							else
							{
								#ifdef UDPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 non-error response, type: %d, so SKIP\n", rx_icmphdr_ptr->icmp6_type);
								#endif
								continue;
							}
						}
						else
						{
							#ifdef UDPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ICMPv6 inner packet mismatch, so SKIP\n");
							#endif
							continue;
						}
					}
					else
					{
						// too few bytes
						#ifdef UDPDEBUG
        					IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: HUT %s dstport %u special %u UDP recvfrom() ICMPv6 loopcount %u returned too few bytes: %ld, so SKIP\n", \
							hostname, my_tx_dst_port, special, icmp_loopcount, bytes_received);
						#endif
						continue;
					}
				} // end of ICMPv6 socket while loop
			} // end of ICMPv6 IF
		} // END of OUTERLOOP main IF
	} // END of OUTERLOOP

	// No other valid response has been received then set as if in-progress
	if (retval == PORTUNKNOWN) retval = UDPSTEALTH;

	if (UDPSTEALTH == retval)
	{
		#ifdef UDPDEBUG
		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: No UDP or ICMPv6 response received for %s port %u\n", hostname, port);
		#endif
	}

	close(udp_sock); 
	close(icmp_sock);

	// Packet tx/rx is complete, so attempt to regain privileges
	rc = regain_privileges();
	if (rc != EXIT_SUCCESS)
	{
		IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: ERROR: regain_privileges() returned %d\n", rc);
		retval = PORTINTERROR;
	}

	// return
	#ifdef UDPDEBUG
	char retstring[32] = "undefined";
	result_to_string((uint32_t)retval, retstring);
	IPSCAN_LOG( LOGPREFIX "check_udp_port_raw: returning for host %s port %u with retval = %d (%s), indirect = %d, indhost =%s\n", hostname, port, retval, retstring, indirect, indhost_ptr);
	#endif
	return (retval+indirect);
}
// ----------------------
//
//
//
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
		for (unsigned int i = 0 ; i <todo ; i++)
		{
			uint16_t port = udpportlist[(unsigned int)(portindex+i)].port_num;
			uint8_t special = udpportlist[(unsigned int)(portindex+i)].special;
			char indirecthost[INET6_ADDRSTRLEN+1] = "::1\0";
			int result = check_udp_port_raw(hostname, port, special, &indirecthost[0]);
			uint64_t write_result = 0;
                        if (result >= 0) write_result = (uint64_t)result;
			// Put results into database
			// make up to IPSCAN_DB_ACCESS_ATTEMPTS attempts in case of deadlock
			int rc = -1;
			for (unsigned int z = 0 ; z < IPSCAN_DB_ACCESS_ATTEMPTS && rc != 0; z++)
			{
				rc = write_db(host_msb, host_lsb, timestamp, session, (uint64_t)(port + ((special & IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_UDP << IPSCAN_PROTO_SHIFT)), write_result, indirecthost );
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
//
// ----------------------------------------------------------------
//
