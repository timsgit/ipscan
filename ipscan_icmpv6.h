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
//
//
//
// ipscan_icmpv6.h
//
// VERSION HISTORY
//
// 0.1  first version - to ensure ICMPv6 function APIs are consistent

#include "ipscan.h"
#include <stdint.h>
//
#ifndef IPSCAN_ICMP6_H
#define IPSCAN_ICMP6_H 1
//
// all the ICMPv6 functions
//
const char* ipscan_icmpv6_ver(void);
// Only include reference to ping-test function if compiled in
#if (1 == IPSCAN_INCLUDE_PING)
int check_icmpv6_echoresponse(char * hostname, uint64_t starttime, uint64_t session, char * router);
#endif
//
//
//
#endif // IPSCAN_ICMP6_H
