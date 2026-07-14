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
// ipscan_general.h
//
// VERSION HISTORY
//
// 0.1  first version - to ensure general function APIs are consistent

#include "ipscan.h"
#include <stdint.h>
//
#ifndef IPSCAN_GENERAL_H
#define IPSCAN_GENERAL_H 1
//
// all the general functions
//
void report_ipscan_versions(const char *mainver, const char *generalver, const char *tcpver, const char *udpver, const char *icmpv6ver, const char *dbver,\
         const char *webver, const char *hver, const char *plver);
const char* ipscan_general_ver(void);
uint64_t get_session(void);
unsigned int fork_safe_seedval(void);
uint32_t backoff_in_microseconds(unsigned int * seedval, unsigned int attempt);
void proto_to_string(uint32_t proto, char * retstring);
void fetch_to_string(uint32_t fetchnum, char * retstring);
char * state_to_string(uint64_t statenum, char * retstringptr, int retstringstart);
void result_to_string(uint32_t result, char * retstring);
void report_agent_string(char * agentstringvar, const char *varname, unsigned int error1ignore0);
void report_useragent_strings(char *uavar, char *secchuavar, char *secchuaarchvar, char *secchuaarchplatvar);
int querystring_is_alphanum(char check);
int querystring_is_valid(char check);
int querystring_is_number(char check);
bool ipv6_address_to_string( uint64_t msb, uint64_t lsb, char * buffer, unsigned char bufflen, bool slash48 );
uint32_t get_random32(void);
uint16_t get_ephemeral(void);
void print_ids(const char * place);
int drop_privileges(void);
int regain_privileges(void);
//
//
//
#endif // IPSCAN_GENERAL_H
