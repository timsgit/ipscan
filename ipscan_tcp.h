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
// ipscan_tcp.h
//
// VERSION HISTORY
//
// 0.1  first version - to ensure TCP function APIs are consistent

#include "ipscan.h"
#include <stdint.h>
//
#ifndef IPSCAN_TCP_H
#define IPSCAN_TCP_H 1
//
// all the TCP functions
//
const char* ipscan_tcp_ver(void);
// hostname for check_tcp_ports_parll must be the FULL 128-bit host address - NOT the safe version
int check_tcp_ports_parll(char * hostname, unsigned int portindex, unsigned int todo, uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, const struct portlist_struc *portlist);
//
//
//
#endif // IPSCAN_TCP_H
