//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011 Tim Chappell.
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

#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>

#ifndef IPSCAN_PORTLIST_H
	#define IPSCAN_PORTLIST_H 1

	// Determine the default list of ports to be tested
	uint16_t defportlist[] =
	{
		7, 21, 22, 23, 25, 37, 53, 79, 80, 88, 110, 111, 113, 119, 123, \
		135, 137, 138, 139, 143, 311, 389, 427, 443, 445, 514, 548,\
		543, 544, 631, 749, 873, 993, 1025, 1026, 1029, 1030, 1080, 1720,\
		1812, 3128, 3306, 3389, 3689, 5000, 5100, 5900, 8080, 9090
	};

	// Calculate and record the number of default ports to be tested
	#define DEFNUMPORTS ( sizeof(defportlist) / sizeof(uint16_t) )

#endif /* IPSCAN_PORTLIST_H_ */
