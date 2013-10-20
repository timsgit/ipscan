//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2013 Tim Chappell.
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
//
// Version	Change
// 0.01		Original
// 0.02		Added additional Windows related ports
//			2869 - SSDP event notification
//			5357 - WSDAPI HTTP
//			10243 - WMP HTTP
// 0.03 - add service names to results table (modification to portlist, now structure)
// 0.04 - add UDP ports and service names
// 0.05 - add SNMP (UDP port 161) support

#include "ipscan.h"

#ifndef IPSCAN_PORTLIST_H
	#define IPSCAN_PORTLIST_H 1

	// Determine the default list of ports to be tested
	// Note: each entry includes its port number followed by
	// a text description (up to PORTDESCSIZE-1 characters long)
	//
	struct portlist_struc defportlist[] =
	{
		{    7, "Echo"},\
		{   21, "FTP" },\
		{   22, "SSH" },\
		{   23, "Telnet" },\
		{   25, "SMTP" },\
		{   37, "Time" },\
		{   53, "DNS" },\
		{   79, "Finger" },\
		{   80, "HTTP" },\
		{   88, "Kerberos" },\
		{  110, "POP3" },\
		{  111, "SUN-RPC" },\
		{  113, "Ident, Auth" },\
		{  119, "NNTP" },\
		{  123, "NTP" },\
		{  135, "Microsoft-EPMAP" },\
		{  137, "NetBIOS Naming" },\
		{  138, "NetBIOS Datagram" },\
		{  139, "NetBIOS Session" },\
		{  143, "IMAP" },\
		{  311, "Apple-WebAdmin" },\
		{  389, "LDAP" },\
		{  427, "SLP" },\
		{  443, "HTTPS" },\
		{  445, "Microsoft-DS" },\
		{  514, "Shell" },\
		{  543, "Kerberos Login" },\
		{  544, "Kerberos RSH" },\
		{  548, "Apple-File" },\
		{  631, "IPP" },\
		{  749, "Kerberos Admin" },\
		{  873, "Rsync" },\
		{  993, "IMAPS" },\
		{ 1025, "Blackjack, NFS, IIS or RFS" },\
		{ 1026, "CAP, Microsoft DCOM" },\
		{ 1029, "Microsoft DCOM" },\
		{ 1030, "BBN IAD" },\
		{ 1080, "Socks" },\
		{ 1720, "H323, Microsoft Netmeeting" },\
		{ 1812, "RADIUS" },\
		{ 2869, "SSDP Event Notification" },\
		{ 3128, "Active API, or Squid Proxy" },\
		{ 3306, "MySQL" },\
		{ 3389, "Microsoft RDP" },\
		{ 3689, "DAAP, iTunes" },\
		{ 5000, "UPNP" },\
		{ 5060, "SIP" },\
		{ 5100, "Service Mux, Yahoo Messenger" },\
		{ 5357, "WSDAPI HTTP" },\
		{ 5900, "VNC" },\
		{ 8080, "HTTP alternate" },\
		{ 9090, "WebSM" },\
		{10243, "Microsoft WMP HTTP"}\
	};


	// Calculate and record the number of default ports to be tested
	#define DEFNUMPORTS ( sizeof(defportlist) / sizeof(struct portlist_struc) )

	struct portlist_struc udpportlist[] =
		{
			{   53, "DNS" },\
			{   69, "TFTP" },\
			{  123, "NTP" },\
			{  161, "SNMP" },\
			{ 1900, "UPnP SSDP" },\
		};
#if (IPSCAN_INCLUDE_UDP == 1)
	#define NUMUDPPORTS ( sizeof(udpportlist) / sizeof(struct portlist_struc) )
#else
	#define NUMUDPPORTS 0
#endif

#endif /* IPSCAN_PORTLIST_H */
