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
// ipscan_db.h
//
// VERSION HISTORY
//
// 0.1  first version - to ensure database function APIs are consistent

#include "ipscan.h"
#include <stdint.h>
//
#ifndef IPSCAN_DB_H
#define IPSCAN_DB_H 1
//
// all the database functions
//
const char* ipscan_db_ver(void);
int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint64_t port, uint64_t result, const char *indirecthost);
int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session);
int read_db_result(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint64_t port, char *indhost);
int delete_from_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, int8_t deleteall);
int tidy_up_db(int8_t deleteall);
int update_result_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint64_t port, uint64_t result);
int count_rows_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session);

#if (CLIENTDEBUG > 1)
int count_teststate_rows_db(uint64_t timestamp, uint64_t session);
#endif
#endif // IPSCAN_DB_H
