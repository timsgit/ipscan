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
// ipscan_web.h
//
// VERSION HISTORY
//
// 0.1  first version - to ensure web function APIs are consistent

#include "ipscan.h"
#include <stdint.h>
//
#ifndef IPSCAN_WEB_H
#define IPSCAN_WEB_H 1
//
// all the web functions
//
const char* ipscan_web_ver(void);
void create_json_header(void);
void create_html_header(uint16_t numports, uint16_t numudpports, char * reconquery);
// starttime is of type time_t in create_html_body() calls:
void create_html_body(char * hostname, time_t timestamp, uint16_t numports, uint16_t numudpports, const struct portlist_struc *portlist, const struct portlist_struc *udpportlist);
#ifdef IPSCAN_HTML5_ENABLED
void create_html5_common_header(void);
void create_html5_form(uint16_t numports, uint16_t numudpports, const struct portlist_struc *portlist, const struct portlist_struc *udpportlist);
#else
void create_html_form(uint16_t numports, uint16_t numudpports, const struct portlist_struc *portlist, const struct portlist_struc *udpportlist);
#endif
void create_html_common_header(void);
void create_html_body_end(void);
// create_results_key_table is only referenced if creating the text-only version of the scanner
#if (1 == TEXTMODE)
void create_results_key_table(char * hostname, time_t timestamp);
#endif
//
//
//
#endif // IPSCAN_WEB_H
