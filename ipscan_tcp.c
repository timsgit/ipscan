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

// ipscan_tcp.c 	version
// 0.01			initial version after split from ipscan_checks.c
// 0.02			tidy up logging prefixes
// 0.03			move to memset()
// 0.04			add support for special cases
// 0.05			ensure minimum timings are met
// 0.06			improve error reporting
// 0.07			ensure fd closure is handled cleanly
// 0.08			add null termination to unusedfield
// 0.09			enforce use of AF_INET6
// 0.10			update copyright date
// 0.11			update copyright date
// 0.12			update copyright date
// 0.13			extern updated
// 0.14			update copyright date
// 0.15			update copyright year
// 0.16			update copyright year
// 0.17			update copyright year
// 0.18			reduce scope of multiple variables
// 0.19			add write_db loop to account for deadlocks
// 0.20			move to nanosleep() from deprecated usleep()
// 0.21			improve various format strings
// 0.22			update copyright year
// 1.00			add raw socket approach to reveal more response detail
// 1.01			update while() loop with continues
// 1.02			raw socket filter addition
// 1.03			handle more TCP flags for HUT and mid-point devices
// 1.04			Add further address checks for TCP flags from non-HUT case
// 1.05			Minor midpoint logging differences to aid debug

//
#define IPSCAN_TCP_VER "1.05"
//
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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
#include <linux/ipv6.h>
// RAW
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>

// Poll support
#include <poll.h>

// Parallel processing related
#include <sys/wait.h>

// Define offset into ICMPv6 packet where user-defined data resides
#define ICMP6DATAOFFSET sizeof(struct icmp6_hdr)

// BPF support
#include <linux/if_ether.h>
#include <linux/filter.h>
//
// Prototype declarations
//
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint64_t port, uint64_t result, const char *indirecthost );
unsigned short checksum(unsigned short *ptr, int nbytes) ; // RAW
int get_my_local_ipaddr(const char *dest_ip, struct in6_addr *local_ip);
uint32_t get_random32(void);
uint16_t get_ephemeral(void);
void print_ids(const char * place);
int drop_privileges();
int regain_privileges();
void result_to_string(uint32_t result, char * retstring);

//
// report version
//
const char* ipscan_tcp_ver(void)
{
    return IPSCAN_TCP_VER;
}

//
// ----------------------------------------------------------------
//
/* FUNCTIONALITY OUTLINE

	0. retval = PORTUNKNOWN, create sockets, configure, apply filters
	0b. select ports, create/send packet to elicit response
	1. while (retval == PORTUNKNOWN && sockets valid)
	{
	2. poll()
	2b. if error then log, set retval and continue;
	2c. else if (poll timeout) then retval = STEALTH/break; // we timed out and no reponse
	3.  if (PROTO events && POLLIN && retval == PORTUNKNOWN) // TCP packet received
		while (retval == PORTUNKNOWN)
		{
			recvfrom (NONBLOCKING)
			if error (EAGAIN or EWOULDBLOCK) then break; // this recvfrom is done - we've looked at all packets
			check size exceeds minimum
			if source address == HUT
			{
				check swapped src/dest ports and ack sequence match our transmission, report if not and continue;
				if all matches && TCP then check flags
					SYN+ACK => OPEN
					RST => REFUSED
					FIN+ACK => SOFTCLOSE
					ACK => ALREADYOPEN
			}
			else
			{ // This could only be a mid-point/firewall device - so only handle a limited set of flags
				check swapped src/dest ports and ack sequence match our transmission, report if not and continue;
				if all matches && TCP then check flags
					RST => REFUSED
					FIN+ACK => SOFTCLOSE
					if one of these cases then
						set indirect = IPSCAN_INDIRECT_RESPONSE, record response source address 
			}
		}
	4. if (ICMPv6 event && POLLIN && retval == PORTUNKNOWN) // only look at ICMPv6 if we haven't had something valid in TCP socket
		while (retval == PORTUNKNOWN)
		{
			indirect = 0; // direct
			recvfrom (NONBLOCKING)
			if error (EAGAIN or EWOULDBLOCK) then break; // this recvfrom is done - we've looked at all packets
			check size exceeds minimum
			check ICMPv6 header source address == HUT
				if (sa == HUT && inner packet matches) then indirect = 0
				else if (sa != HUT && sa != localhost && sa != localip && inner packet matches) then log and set indirect = IPSCAN_INDIRECT_RESPONSE, record source address;
			check inner IPv6 source & destination addresses and NEXTHDR match our transmission, report if not and continue;
			check inner TCP src/dest ports match our transmission, report if not and continue;
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
int check_tcp_port_raw(char * hostname, uint16_t port, uint8_t special, char * indhost_ptr)
{

	// set return value to a known default
	int retval = PORTUNKNOWN;
	int indirect = 0; // default - direct response
	struct in6_addr destaddr;
	struct icmp6_filter myfilter;
	int rc = -1;
	// lodge/create TCP header parameters
	uint16_t my_tx_src_port = get_ephemeral(); 
	uint16_t my_tx_dst_port = port;
	uint32_t my_tx_seq = get_random32();

	// Convert the HUT's hostname to a struct in6_addr
	if (inet_pton(AF_INET6, hostname, &destaddr) == 1)
	{
		#ifdef TCPDEBUG
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: entering with host %s, dstport %u and special %u, selecting srcport = %u, seq = %08x\n",\
			hostname, my_tx_dst_port, special, my_tx_src_port, my_tx_seq);
		#endif
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: inet_pton() for host %s, dstport %u and special %u returned %d (%s)\n",\
			hostname, my_tx_dst_port, special, errno, strerror(errno));
		retval = PORTINTERROR;	
	}
	struct timeval timeout;

	// Determine the local address used to reach the HUT (hostname)
	struct in6_addr my_tx_ipaddr;
	rc = get_my_local_ipaddr(hostname, &my_tx_ipaddr);
	if (EXIT_FAILURE == rc)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: get_my_local_ipaddr() returned EXIT_FAILURE\n");
		retval = PORTINTERROR;
	}

	// Create the local sockaddr_in6
	struct sockaddr_in6 local_sockaddr;
        memset(&local_sockaddr, 0, sizeof(struct sockaddr_in6));
        local_sockaddr.sin6_family = AF_INET6;
        local_sockaddr.sin6_addr = my_tx_ipaddr;

	#ifdef IPSCAN_PRIV_DEBUG
	print_ids("start of tcp_raw");
	#endif

	// Open the two raw sockets
	int tcp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
	if (tcp_sock < 0)
	{ 
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: TCPv6 socket. Need root privileges? Unexpected failure : %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}

	int icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmp_sock < 0)
	{ 
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: ICMPv6 Need root privileges? Unexpected failure : %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}

	// Assuming something bad hasn't already happened then attempt to set the TCP receive timeout
	if (PORTUNKNOWN == retval)
	{
		// Set send timeout
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = TIMEOUTSECS;
                timeout.tv_usec = TIMEOUTMICROSECS;
                int timeo = setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                if (timeo < 0)
                {
                	int errsv = errno ;
                	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Bad TCP setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
                	retval = PORTINTERROR;
                }
        }
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: TCP setsockopt SO_SNDTIMEO not attempted\n");
	}

        // Assuming something bad hasn't already happened then attempt to set the TCP receive timeout
       	if (PORTUNKNOWN == retval)
        {
                // Set receive timeout
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = TIMEOUTSECS;
                timeout.tv_usec = TIMEOUTMICROSECS;
                int timeo = setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                if (timeo < 0)
                {
                	int errsv = errno ;
                	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Bad TCP setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
                	retval = PORTINTERROR;
                }
       	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: TCP setsockopt SO_RCVTIMEO not attempted\n");
	}

	// Assuming something bad hasn't already happened then attempt to set the ICMPv6 transmit timeout
	if (PORTUNKNOWN == retval)
	{
		// Set send timeout
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = TIMEOUTSECS;
                timeout.tv_usec = TIMEOUTMICROSECS;
                int timeo = setsockopt(icmp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                if (timeo < 0)
                {
                	int errsv = errno ;
                	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Bad ICMPv6 setsockopt SO_SNDTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
                	retval = PORTINTERROR;
                }
        }
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: ICMPv6 setsockopt SO_SNDTIMEO not attempted\n");
	}

        // Assuming something bad hasn't already happened then attempt to set the ICMPv6 receive timeout
       	if (PORTUNKNOWN == retval)
        {
                // Set receive timeout
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = TIMEOUTSECS;
                timeout.tv_usec = TIMEOUTMICROSECS;
                int timeo = setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                if (timeo < 0)
                {
                	int errsv = errno ;
                	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Bad ICMPv6 setsockopt SO_RCVTIMEO set, returned %d (%s)\n", errsv, strerror(errsv));
                	retval = PORTINTERROR;
                }
       	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: ICMPv6 setsockopt SO_RCVTIMEO not attempted\n");
	}

	if (retval == PORTUNKNOWN)
	{
		// Filter out everything except the ICMPv6 responses we're looking for
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

		// Apply the ICMPv6 filter
        	rc = setsockopt(icmp_sock, IPPROTO_ICMPV6, ICMP6_FILTER, &myfilter, sizeof(myfilter));
        	if (rc < 0)
        	{
        		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: setsockopt: setting ICMPv6 filter: %s (%d)\n", strerror(errno), errno);
        		retval = PORTINTERROR;
       		}
	}

	if (retval == PORTUNKNOWN)
	{
		// Bind the TCP socket to our local address
		rc = bind(tcp_sock, (const struct sockaddr *)&local_sockaddr, sizeof(struct sockaddr_in6));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: failed to bind tcp_sock = %d(%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

	if (retval == PORTUNKNOWN)
	{
		// Bind the ICMPv6 socket to our local address
		rc = bind(icmp_sock, (const struct sockaddr *)&local_sockaddr, sizeof(struct sockaddr_in6));
		if (rc < 0)
		{
			IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: failed to bind icmp_sock = %d(%s)\n", errno, strerror(errno));
			retval = PORTINTERROR;
		}
	}

	// Define a BPF filter that accepts wanted source/destination ports and ACK sequence
	// NOTE: No MAC header and No IP header returned - so starts at TCP layer

	struct sock_filter BPF_code[] = {
    		// 0. Check Source Port (Offset 0, 2 bytes)
		{ BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x00000000 }, 	// LDH [0]
		{ BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0x0123 },    	// JEQ #0x0123, else skip 5
		// 2. Check Destination Port (Offset 2, 2 bytes)
		{ BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x00000002 },		// LDH [2]
		{ BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x4567 },		// JEQ #0x4567, else skip 3
		// 4. Check TCP ACK Number (Offset 8, 4 bytes)
		{ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0x00000008 }, 	// LDW [8]
		{ BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x87654321 },	// JEQ #0x87654321, else skip 1
		// 6. Verdicts
		{ BPF_RET | BPF_K, 0, 0, 0x00040000 },			// Pass (Return max length)
		{ BPF_RET | BPF_K, 0, 0, 0x00000000 }			// Drop
	};

	// adjust the dummy port numbers and ACK sequence number above to match the ones we actually transmitted/expect
	BPF_code[1].k = my_tx_dst_port; //the source port we're comparing was the destination port of our transmission
	BPF_code[3].k = my_tx_src_port; //the destination port we're comparing was the source port of our transmission
	BPF_code[5].k = (my_tx_seq+1);  // response sequence number is (our transmission + 1)

	struct sock_fprog Filter;
	Filter.len = sizeof(BPF_code) / sizeof(struct sock_filter);
	Filter.filter = BPF_code;

	// Attach the BPF filter
        if (PORTUNKNOWN == retval)
        {
                // Attach the filter
                rc = setsockopt(tcp_sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter));
                if (rc < 0 )
                {
                        IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: setsockopt: attaching BPF filter: %s (%d)\n", strerror(errno), errno);
                        retval = PORTINTERROR;
                }
        }

	//
	// END OF ROOT PRIVILEGES - Revert to previous privilege level
	//
	rc = drop_privileges();
	if (rc != EXIT_SUCCESS)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: drop_privileges() unsuccessful, returned %d\n", rc);
		retval = PORTINTERROR;
	}

	// If something bad has happened then return now ...
        if (PORTUNKNOWN != retval)
        {
                if (-1 != tcp_sock) close(tcp_sock); // close socket if appropriate
                if (-1 != icmp_sock) close(icmp_sock); // close socket if appropriate

		// regain the privileges now we've finished processing the packets
		rc = regain_privileges();
		if (rc != EXIT_SUCCESS)
		{
			IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: regain_privileges() unsuccessful, returned %d\n", rc);
		}
                return (retval);
        }

	// Buffers for sending and receiving packets
    	char send_buf[IP_MAXPACKET], rcv_buf[IP_MAXPACKET];

	// Build TCP SYN packet
	struct tcphdr *tcp = (struct tcphdr *)send_buf;
	memset(send_buf, 0, sizeof(struct tcphdr));
	tcp->source = htons(my_tx_src_port);
	tcp->dest = htons(my_tx_dst_port);
	tcp->seq = htonl(my_tx_seq);
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->window = htons(65535);

	// Create the pseudo-header so we can calculate the checksum
	struct pseudo_hdr ph = { .src = my_tx_ipaddr, .dst = destaddr, .len = htonl(sizeof(struct tcphdr)), .next_hdr = IPPROTO_TCP };
	char check_buf[sizeof(ph) + sizeof(struct tcphdr)];
	memcpy(check_buf, &ph, sizeof(ph));
	memcpy(check_buf + sizeof(ph), tcp, sizeof(struct tcphdr));
	tcp->check = checksum((unsigned short*)check_buf, sizeof(check_buf));

	// Send the TCP SYN packet - no body necessary for TCP
	struct sockaddr_in6 d_addr = { .sin6_family = AF_INET6, .sin6_addr = destaddr };
	ssize_t bytes_sent = sendto(tcp_sock, send_buf, sizeof(struct tcphdr), 0, (struct sockaddr *)&d_addr, sizeof(d_addr));
	if (-1 == bytes_sent)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: sendto() returned %d(%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}

	#ifdef TCPDEBUG
	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Request of %ld octets sent to %s port %u\n", bytes_sent, hostname, port);
	#endif

	// Create a localhost structure for ::1 (IPv6 localhost) 
	struct sockaddr_in6 localhost_addr;
	memset(&localhost_addr, 0, sizeof(localhost_addr));
	localhost_addr.sin6_family = AF_INET6;
	localhost_addr.sin6_port = 0; // Must be 0 for raw sockets to avoid EINVAL
	rc = inet_pton(AF_INET6, "::1", &localhost_addr.sin6_addr);
	if (rc < 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: Bad inet_pton for localhost, returned %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}

	time_t timestart = time(0);
	if (timestart < 0)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: time() returned bad value for timestart %d (%s)\n", errno, strerror(errno));
		retval = PORTINTERROR;
	}
	time_t timenow = timestart;
	unsigned int loopcount = 0;

	// OUTER loop - exit when we've run out of time or retval is no longer PORTUNKNOWN
	while (((timenow-timestart) <= (TIMEOUTSECS+2)) && (retval == PORTUNKNOWN))
	{ // OUTER LOOP
		loopcount++;
		#ifdef TCPDEBUG
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: OUTER loopcount = %u for HUT %s dst port %u special %u\n", loopcount, hostname, my_tx_dst_port, special);
		#endif
		// file descriptors for TCP and ICMPv6
		struct pollfd fds[2];
		fds[0].fd = tcp_sock;
		fds[0].events = POLLIN;
		fds[1].fd = icmp_sock;
		fds[1].events = POLLIN;

		// Poll for a response on either socket
		int pollrc = poll(fds, 2, (TIMEOUTSECS*1000+100)); // timeout is in ms
		if (pollrc < 0)
		{
       		 	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: OUTERLOOP poll error for HUT %s dst port %u special %u, %d(%s)\n",\
				hostname, my_tx_dst_port, special, errno, strerror(errno));
			retval = PORTINTERROR;
			continue;
		}
		else if (pollrc == 0)
		{
			// timeout
			#ifdef TCPDEBUG
       		 	IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: OUTERLOOP poll timeout for HUT %s dstport %u special %u\n", hostname, my_tx_dst_port, special);
			#endif
			retval = PORTINPROGRESS;
			continue;
		}
		else
		{
			if ((fds[0].revents & POLLIN) && (retval == PORTUNKNOWN)) // TCP socket has some data
			{
				unsigned int tcp_loopcount = 0;
				while (retval == PORTUNKNOWN)
				{ // TCP WHILE
					tcp_loopcount++;
					// NON-BLOCKING (set DONTWAIT) - if there's nothing to receive then move on
					struct sockaddr_storage rx_src_addr;
					socklen_t rx_src_addr_len = sizeof(rx_src_addr);
					char rx_ip6addr_str[INET6_ADDRSTRLEN+1];
					ssize_t bytes_received = recvfrom(tcp_sock, rcv_buf, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&rx_src_addr, &rx_src_addr_len);
					if (bytes_received < 0) // error condition
					{
						if (errno == EAGAIN || errno == EWOULDBLOCK) // nothing to receive - we're done with this socket
						{
							#ifdef TCPDEBUG
       		 					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: HUT %s dstport %u special %u TCP recvfrom() TCP loopcount %u returned indicating nothing received %d(%s)\n",\
								hostname, my_tx_dst_port, special, tcp_loopcount, errno, strerror(errno));
							#endif
						}
						else // an actual error
						{
       		 					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: HUT %s dstport %u special %u TCP recvfrom() TCP loopcount %u returned error %d(%s)\n", \
								hostname, my_tx_dst_port, special, tcp_loopcount, errno, strerror(errno));
						}
						// nothing useful we can do - break from this loop and try ICMPv6
						break;
					}
					else if (bytes_received >= (ssize_t)(sizeof(struct tcphdr)) )
					{
						#ifdef TCPDEBUG
       		 				IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: HUT %s dstport %u special %u TCP recvfrom() TCP loopcount %u returned %ld octets\n", \
							hostname, my_tx_dst_port, special, tcp_loopcount, bytes_received);
						#endif

						#ifdef IPSCAN_BPF_DEBUG
						// dump header bytes to allow for BPF filter debug
						if (bytes_received >= 16)
						{
       		 					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO rcv_buf 00-07: %02x %02x %02x %02x %02x %02x %02x %02x\n", \
								rcv_buf[0], rcv_buf[1], rcv_buf[2], rcv_buf[3], rcv_buf[4], rcv_buf[5], rcv_buf[6], rcv_buf[7]);
       		 					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO rcv_buf 08-15: %02x %02x %02x %02x %02x %02x %02x %02x\n", \
								rcv_buf[8], rcv_buf[9], rcv_buf[10], rcv_buf[11], rcv_buf[12], rcv_buf[13], rcv_buf[14], rcv_buf[15]);
						}
						#endif
						
						// compare the received packet with what we're expecting
						struct sockaddr_in6 *rx_sockaddr_in6 = (struct sockaddr_in6 *)&rx_src_addr;
						struct tcphdr *tcphdr_ptr = (struct tcphdr *)rcv_buf;
						if (rx_src_addr.ss_family == AF_INET6)
						{
							// Convert received address from binary to string
							if (inet_ntop(AF_INET6, &(rx_sockaddr_in6->sin6_addr), rx_ip6addr_str, sizeof(rx_ip6addr_str)) != NULL)
							{
								#ifdef TCPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 recvfrom() size %ld from host %s\n",\
									 bytes_received, rx_ip6addr_str);
								#endif
							}
							else // check for another packet
							{
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 inet_ntop() returned %d(%s), so SKIP\n", errno, strerror(errno));
								continue;
							}
							// Check if received packet is from HUT
							if ( IN6_ARE_ADDR_EQUAL( &destaddr, &(rx_sockaddr_in6->sin6_addr)) == 1)
							{
								#ifdef TCPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 response is from HUT\n");
								#endif
								// Now we know response is from HUT then start checking the detail - reversed src/dst ports and TCP sequence
								if ((ntohs(tcphdr_ptr->source) == my_tx_dst_port) && (ntohs(tcphdr_ptr->dest) == my_tx_src_port)\
									 && (ntohl(tcphdr_ptr->ack_seq) == (my_tx_seq+1) ))
								{
									#ifdef TCPDEBUG
									IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 response packet match for HUT %s dstport %u special %u TCP loopcount %u, flags: %s%s%s\n",\
										hostname, my_tx_dst_port, special, tcp_loopcount,\
										tcphdr_ptr->syn ? "SYN " : "", tcphdr_ptr->ack ? "ACK " : "", tcphdr_ptr->rst ? "RST " : "");
									#endif
									if (1 == tcphdr_ptr->rst)
									{
										#ifdef TCPDEBUG
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Connection refused by HUT (RST) in response to SYN to host %s port %u special %u\n",\
											 hostname, my_tx_dst_port, special);
										#endif
										retval = PORTREFUSED; // checked - matches description
									}
									else if ((0 == tcphdr_ptr->rst) && (1 == tcphdr_ptr->ack) && (1 == tcphdr_ptr->syn) && (0 == tcphdr_ptr->fin))
									{
										#ifdef TCPDEBUG
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Connection accepted by HUT (SYN+ACK) in response to SYN to host %s port %u special %u\n",\
											 hostname, my_tx_dst_port, special);
										#endif
										retval = PORTOPEN;
									}
									else if ((0 == tcphdr_ptr->rst) && (1 == tcphdr_ptr->ack) && (0 == tcphdr_ptr->syn) && (0 == tcphdr_ptr->fin))
									{
										#ifdef TCPDEBUG
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Connection already open from HUT (ACK) in response to SYN to host %s port %u special %u\n",\
											 hostname, my_tx_dst_port, special);
										#endif
										retval = PORTALREADYOPN;
									}
									else if ((0 == tcphdr_ptr->rst) && (1 == tcphdr_ptr->ack) && (0 == tcphdr_ptr->syn) && (1 == tcphdr_ptr->fin))
									{
										#ifdef TCPDEBUG
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Connection soft close from HUT (FIN+ACK) in response to SYN to host %s port %u special %u\n",\
											 hostname, my_tx_dst_port, special);
										#endif
										retval = PORTSOFTCLOSE;
									}
									// SYN only - do nothing - expect a later SYN+ACK packet
									continue; // retval setting should complete the loop
								}
								else
								{
									#ifdef TCPDEBUG
									IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 response inner-packet mismatch for HUT %s dstport %u special %u TCP loopcount %u, received srcport %u, dstport %u ACK sequence %08x, so SKIP\n",\
										hostname, my_tx_dst_port, special, tcp_loopcount,ntohs(tcphdr_ptr->source), ntohs(tcphdr_ptr->dest), ntohl(tcphdr_ptr->ack_seq));
									#endif
									continue;
								}
							}
							// if there's a HUT-address mismatch BUT its not from localhost or our external address then it might be from a valid midpoint device
							else if ( (IN6_ARE_ADDR_EQUAL( &destaddr, &(rx_sockaddr_in6->sin6_addr)) == 0) \
                                                        && (IN6_ARE_ADDR_EQUAL( &localhost_addr.sin6_addr, &(rx_sockaddr_in6->sin6_addr)) == 0)\
                                                        && (IN6_ARE_ADDR_EQUAL( &local_sockaddr.sin6_addr, &(rx_sockaddr_in6->sin6_addr)) == 0))
							{
								#ifdef MIDPOINTDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 response is NOT from HUT\n");
								#endif
								// Now we know response is NOT from HUT then start checking the detail - reversed src/dst ports and TCP sequence
								if ((ntohs(tcphdr_ptr->source) == my_tx_dst_port) && (ntohs(tcphdr_ptr->dest) == my_tx_src_port)\
									 && (ntohl(tcphdr_ptr->ack_seq) == (my_tx_seq+1) ))
								{
									#ifdef MIDPOINTDEBUG
									IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 srcaddress check fail BUT ports/seq match, HUT %s dstport %u special %u TCP loopcount %u, actually from: %s\n",\
										 hostname, my_tx_dst_port, special, tcp_loopcount, rx_ip6addr_str);
									#endif
									if (1 == tcphdr_ptr->rst)
									{
										#ifdef MIDPOINTDEBUG
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: Connection refused by someone else (%s) (RST) in response to SYN to host %s port %u special %u\n",\
											rx_ip6addr_str, hostname, my_tx_dst_port, special);
										#endif
                                                                                retval = PORTREFUSED; // checked - matches description
										indirect = IPSCAN_INDIRECT_RESPONSE; // not expected source address (HUT) but also NOT (localhost or our source address)
										// copy string address
										memset(indhost_ptr, 0, INET6_ADDRSTRLEN); //Blank it first
										memcpy(indhost_ptr, rx_ip6addr_str, INET6_ADDRSTRLEN); // copy the source address string over it
                                                                        }
									else if ((0 == tcphdr_ptr->rst) && (1 == tcphdr_ptr->ack) && (0 == tcphdr_ptr->syn) && (1 == tcphdr_ptr->fin))
									{
										#ifdef MIDPOINTDEBUG
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: Connection soft close by someone else (%s) (FIN+ACK) in response to SYN to host %s port %u special %u\n",\
											 rx_ip6addr_str, hostname, my_tx_dst_port, special);
										#endif
										retval = PORTSOFTCLOSE;
										indirect = IPSCAN_INDIRECT_RESPONSE; // not expected source address (HUT) but also NOT (localhost or our source address)
										// copy string address
										memset(indhost_ptr, 0, INET6_ADDRSTRLEN); //Blank it first
										memcpy(indhost_ptr, rx_ip6addr_str, INET6_ADDRSTRLEN); // copy the source address string over it
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: response with valid ports/sequence received from %s but unexpected flag state: SAFR = %d%d%d%d\n",\
											rx_ip6addr_str, tcphdr_ptr->syn, tcphdr_ptr->ack, tcphdr_ptr->fin, tcphdr_ptr->rst);
									}
								}
								// continue whether this was a recognised packet/address/ports/flags, or NOT
								// if it was recognised then retval has been set appropriately
								continue;
								
							}
							else
							{
								#ifdef MIDPOINTDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: TCPv6 response is NOT from HUT, or a valid midpoint addresss. Address : %s, so SKIP\n",\
									rx_ip6addr_str);
								#endif
								continue;
							}
						}
						else
						{
							#ifdef TCPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: TCPv6 response packet for HUT %s dstport %u special %u TCP loopcount %u was not IPv6, so SKIP\n",\
								hostname, my_tx_dst_port, special, tcp_loopcount);
							#endif
							continue;
						}
					}
					else // too few bytes received - check for another packet
					{
						#ifdef TCPDEBUG
       		 				IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: HUT %s dstport %u special %u TCP recvfrom() TCP loopcount %u returned too few octets: %ld, so SKIP\n", \
							hostname, my_tx_dst_port, special, tcp_loopcount, bytes_received);
						#endif
						continue;	
					}
				} // end of TCP socket while loop
			} // end of TCP socket if

			// Check ICMPv6 if nothing definitive found for TCP socket. If something definitive (e.g. OPEN) was received then retval would be modified
			if ((fds[1].revents & POLLIN) && (retval == PORTUNKNOWN)) // ICMPv6 socket has some data
			{
				unsigned int icmp_loopcount = 0;
				while (retval == PORTUNKNOWN)
				{ // ICMPv6 WHILE
					icmp_loopcount++;
					struct sockaddr_storage rx_src_addr;
					socklen_t rx_src_addr_len = sizeof(rx_src_addr);
					// NON-BLOCKING - if there's nothing there then move on
					ssize_t bytes_received = recvfrom(icmp_sock, rcv_buf, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&rx_src_addr, &rx_src_addr_len);
					if (bytes_received < 0) // error condition
					{
						if (errno == EAGAIN || errno == EWOULDBLOCK) // nothing to receive - we're done with this socket
						{
							#ifdef TCPDEBUG
       		 					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: HUT %s dstport %u special %u ICMPv6 recvfrom() ICMPv6 loopcount %u returned indicating nothing received %d(%s)\n",\
								hostname, my_tx_dst_port, special, icmp_loopcount, errno, strerror(errno));
							#endif
						}
						else // an actual error
						{
       		 					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: HUT %s dstport %u special %u TCP recvfrom() ICMPv6 loopcount %u returned error %d(%s)\n", \
								hostname, my_tx_dst_port, special, icmp_loopcount, errno, strerror(errno));
						}
						// nothing useful we can do in either case, so break from this loop
						break;
					}
					else if (bytes_received >= ((ssize_t)(sizeof(struct icmp6_hdr)+sizeof(struct ipv6hdr)+sizeof(struct tcphdr)))) 
					{
						struct sockaddr_in6 *rx_sockaddr_in6 = (struct sockaddr_in6 *)&rx_src_addr;
						struct icmp6_hdr *rx_icmphdr_ptr = (struct icmp6_hdr *)rcv_buf;
						// Inner packet should be IPv6 then TCP
						struct ipv6hdr *rx_ipv6hdr_ptr = (struct ipv6hdr *)(rcv_buf + sizeof(struct icmp6_hdr));
						struct tcphdr *rx_tcphdr_ptr = (struct tcphdr *)(rcv_buf + sizeof(struct icmp6_hdr) + sizeof(struct ipv6hdr));
						char rx_ip6addr_str[INET6_ADDRSTRLEN];
						if (rx_src_addr.ss_family == AF_INET6)
                               		        {
                               		        	// Convert binary to string
                               		                if (inet_ntop(AF_INET6, &(rx_sockaddr_in6->sin6_addr), rx_ip6addr_str, sizeof(rx_ip6addr_str)) != NULL)
                               		                {
								#ifdef TCPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 recvfrom() size %ld from host %s\n",\
									bytes_received, rx_ip6addr_str);
								#endif
                               		                }
                               		                else // check for another packet
                               		                {
								#ifdef TCPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 inet_ntop() returned %d(%s), so SKIP\n", errno, strerror(errno));
								#endif
								continue;
							}
						}
						else
						{
							#ifdef TCPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 response not from IPv6 address, so SKIP\n");
							#endif
							continue;
						}

						// if we received the packet from HUT (our destaddr), next header is TCP, 
						// INNER IPv6 header dest addr is HUT, source address is our local address
						// INNER TCP header source/dest ports and SEQuences match then ICMPv6 is valid and from expected host
						if ( IN6_ARE_ADDR_EQUAL( &destaddr, &(rx_sockaddr_in6->sin6_addr)) == 1 \
							&& (rx_ipv6hdr_ptr->nexthdr == IPPROTO_TCP && IN6_ARE_ADDR_EQUAL( &rx_ipv6hdr_ptr->daddr, &destaddr ) == 1 \
                               		                && IN6_ARE_ADDR_EQUAL(&local_sockaddr.sin6_addr, &rx_ipv6hdr_ptr->saddr) == 1 )\
                               		                && (ntohs(rx_tcphdr_ptr->source) == my_tx_src_port) && (ntohs(rx_tcphdr_ptr->dest) == my_tx_dst_port)\
							&& (ntohl(rx_tcphdr_ptr->seq) == my_tx_seq))
						{
							#ifdef TCPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: Matching ICMPv6 response received from HUT\n");
							#endif
							indirect = 0; // from expected host
						}
						// else if packet was not sent from HUT BUT its also NOT from localhost OR our own address
						// BUT the INNER IPv6 header was sent from us (src) to HUT (dest) and the next header is TCP
						// and the INNER TCP header matches our transmitted src/dest ports and TCP sequence then its an INDIRECT response
						else if ( (IN6_ARE_ADDR_EQUAL( &destaddr, &(rx_sockaddr_in6->sin6_addr)) == 0) \
							&& (IN6_ARE_ADDR_EQUAL( &localhost_addr.sin6_addr, &(rx_sockaddr_in6->sin6_addr)) == 0)\
							&& (IN6_ARE_ADDR_EQUAL( &local_sockaddr.sin6_addr, &(rx_sockaddr_in6->sin6_addr)) == 0)\
							&& (rx_ipv6hdr_ptr->nexthdr == IPPROTO_TCP && IN6_ARE_ADDR_EQUAL( &rx_ipv6hdr_ptr->daddr, &destaddr ) == 1 \
                               		                && IN6_ARE_ADDR_EQUAL(&local_sockaddr.sin6_addr, &rx_ipv6hdr_ptr->saddr) == 1 )\
                               		                && (ntohs(rx_tcphdr_ptr->source) == my_tx_src_port) && (ntohs(rx_tcphdr_ptr->dest) == my_tx_dst_port)\
							&& (ntohl(rx_tcphdr_ptr->seq) == my_tx_seq) )
						{
							#ifdef MIDPOINTDEBUG
							IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: INFO: Matching ICMPv6 response is NOT from HUT, potentially from another mid-point device: %s\n", rx_ip6addr_str);
							#endif
							indirect = IPSCAN_INDIRECT_RESPONSE; // not expected source address (HUT) but also NOT (localhost or our source address)
							// copy string address
							memset(indhost_ptr, 0, INET6_ADDRSTRLEN); //Blank it first
							memcpy(indhost_ptr, rx_ip6addr_str, INET6_ADDRSTRLEN); // copy the source address string over it
						}
						else // not our expected packet
						{
							#ifdef TCPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 response is NOT from HUT, or from suitable mid-point device address : %s, or inner mismatch, so SKIP\n", rx_ip6addr_str);
							#endif
							continue; // a packet we're not expecting - could be from ourselves, or localhost, or inner ICMPv6 does not match
						}
						// Check the inner headers match and then set retval based on ICMPv6 type/code
						if ((rx_ipv6hdr_ptr->nexthdr == IPPROTO_TCP && IN6_ARE_ADDR_EQUAL( &rx_ipv6hdr_ptr->daddr, &destaddr ) == 1 \
							&& IN6_ARE_ADDR_EQUAL(&local_sockaddr.sin6_addr, &rx_ipv6hdr_ptr->saddr) == 1 )\
						 	&& (ntohs(rx_tcphdr_ptr->source) == my_tx_src_port) && (ntohs(rx_tcphdr_ptr->dest) == my_tx_dst_port) && (ntohl(rx_tcphdr_ptr->seq) == my_tx_seq))
						{
							#ifdef TCPDEBUG
							IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 response received with inner IP packet TCP next header and TCP src/dst port and seq match\n");
							#endif
							if (rx_icmphdr_ptr->icmp6_type < 128)
							{ // Error messages only - ignore neighbour discovery, etc.
								#ifdef TCPDEBUG
								IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 error received for %s port %u, Type %d Code %d\n", hostname, port, rx_icmphdr_ptr->icmp6_type, rx_icmphdr_ptr->icmp6_code);
								#endif
								if (rx_icmphdr_ptr->icmp6_type == 1)
								{
									#ifdef TCPDEBUG
									const char *codes[] = {"No route", "Admin prohibited", "Beyond scope", "Addr unreachable", "Port unreachable"};
									IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ICMPv6 : %s\n", (rx_icmphdr_ptr->icmp6_code <= 4) ? codes[rx_icmphdr_ptr->icmp6_code] : "Unknown unreachable");
									#endif
									if (rx_icmphdr_ptr->icmp6_code == 0)
									{
										retval = PORTUNREACHABLE; // checked - No route to destination
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
										IPSCAN_LOG( LOGPREFIX " check_tcp_port_raw: ERROR: Unhandled ICMPv6 type 1, code = %d for host %s port %u\n", rx_icmphdr_ptr->icmp6_code, hostname, port);
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
									IPSCAN_LOG( LOGPREFIX " check_tcp_port_raw: ERROR: Unhandled ICMPv6 type: %d\n", rx_icmphdr_ptr->icmp6_type);
									continue;
								}
							}
							else
							{
								#ifdef TCPDEBUG
								IPSCAN_LOG( LOGPREFIX " check_tcp_port_raw: ICMPv6 non-error response, type: %d, so SKIP\n", rx_icmphdr_ptr->icmp6_type);
								#endif
								continue;
							}
						}
						else
						{
							#ifdef TCPDEBUG
							IPSCAN_LOG( LOGPREFIX " check_tcp_port_raw: ICMPv6 inner packet mismatch, so SKIP\n");
							#endif
							continue;
						}
					}
					else
					{
						// too few bytes
						#ifdef TCPDEBUG
        					IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: HUT %s dstport %u special %u TCP recvfrom() ICMPv6 loopcount %u returned too few bytes: %ld, so SKIP\n", \
							hostname, my_tx_dst_port, special, icmp_loopcount, bytes_received);
						#endif
						continue;
					}
				} // end of ICMPv6 socket while loop
			} // end of ICMPv6 IF
		} // END of OUTERLOOP main IF
	} // END of OUTERLOOP

	// No other response has been received so set return value as if in-progress
	if (retval == PORTUNKNOWN) retval = PORTINPROGRESS;
	// Log that No TCPv6 or ICMPv6 response was received
	#ifdef TCPDEBUG
	if (PORTINPROGRESS == retval)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: No TCP or ICMPv6 response received for %s port %u\n", hostname, port);
	}
	#endif

	// Close the TCP and ICMPv6 sockets
	close(tcp_sock); 
	close(icmp_sock);

	// regain the privileges now we've finished processing the packets
	rc = regain_privileges();
	if (rc != EXIT_SUCCESS)
	{
		IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: ERROR: regain_privileges() unsuccessful, returned %d\n", rc);
		retval = PORTINTERROR;
	}

	// return - determine the return value text equivalent in retstring
	#ifdef MIDPOINTDEBUG
	if (0 != indirect)
	{
		char retstring[32] = "undefined";
		result_to_string((uint32_t)retval, retstring);
		if (0 == special)
		{
			IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: returning for host %s port %u with retval = %d (%s), indirect = %d, indhost : %s\n", hostname, port, retval, retstring, indirect, indhost_ptr);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "check_tcp_port_raw: returning for host %s port %u:%u with retval = %d (%s), indirect = %d, indhost : %s\n", hostname, port, special, retval, retstring, indirect, indhost_ptr);
		}
	}
	#endif
	return (retval+indirect);
}
//
// ---------------------------------------------------------
//
int check_tcp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, struct portlist_struc *portlist)
{
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
		for (unsigned int i = 0 ; i < todo ; i++)
		{
			uint16_t port = portlist[portindex+i].port_num;
			uint8_t special = portlist[portindex+i].special;
			char indirecthost[INET6_ADDRSTRLEN+1] = "::1\0"; 
			#ifdef PARLLDEBUG
			IPSCAN_LOG( LOGPREFIX "check_tcp_ports_parll(): DEBUG: portindex = %u, i = %u, port_num = %d, special = %d\n", portindex, i, portlist[portindex+i].port_num, portlist[portindex+i].special);
			IPSCAN_LOG ( LOGPREFIX "check_tcp_ports_parll(): DEBUG: hostname = %s, port = %u, special = %u\n", hostname, port, special);
			#endif
			int result = check_tcp_port_raw(hostname, port, special, &indirecthost[0]);
			uint64_t write_result = 0;
			if (result >= 0) { write_result = (uint64_t)result; }

			// Put results into database
			// make up to IPSCAN_DB_ACCESS_ATTEMPTS attempts in case of deadlock
			int rc = -1;
			for (unsigned int z = 0 ; z < IPSCAN_DB_ACCESS_ATTEMPTS && rc != 0; z++)
			{
				rc = write_db(host_msb, host_lsb, timestamp, session, (uint64_t)(port + ((special & IPSCAN_SPECIAL_MASK) << IPSCAN_SPECIAL_SHIFT) + (IPSCAN_PROTO_TCP << IPSCAN_PROTO_SHIFT)), write_result, indirecthost );
				if (rc != 0)
				{
					IPSCAN_LOG( LOGPREFIX "check_tcp_ports_parll(): ERROR: check_tcp_port_parll() write_db attempt %u returned %d\n", (z+1), rc);
					// Wait to improve chances of missing a database deadlock
					struct timespec rem;
                                        const struct timespec req = { IPSCAN_DB_DEADLOCK_WAIT_PERIOD_S, IPSCAN_DB_DEADLOCK_WAIT_PERIOD_NS };
                                        int rc2 = nanosleep( &req, &rem);
                                        if (0 != rc2)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: check_tcp_port_parll() write_db nanosleep() returned %d(%s)\n", rc2, strerror(errno) );
                                        }
				}
			}
			if (0 != rc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: check_tcp_ports_parll(): ERROR: write_db loop exited after %d attempts with non-zero rc: %d\n", IPSCAN_DB_ACCESS_ATTEMPTS, rc);
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
	return ( (int)childpid );
}
