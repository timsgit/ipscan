//    IPscan - an HTTP-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2023 Tim Chappell.
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
// Version	Change
// 0.01		Original
// 0.02		Added additional Windows related ports
//			2869 - SSDP event notification
//			5357 - WSDAPI HTTP
//			10243 - WMP HTTP
// 0.03 - add service names to results table (modification to portlist, now structure)
// 0.04 - add UDP ports and service names
// 0.05 - add SNMP (UDP port 161) support
// 0.06 - add NTP special case
// 0.07 - add TCP/32764 router backdoor port (may be IPv4 only)
// 0.08 - add SNMPv2c and SNMPv3
// 0.09 - slight tweaks to a few Microsoft ports
//        as per https://msdn.microsoft.com/en-us/library/cc875824.aspx
// 0.10 - added Intel AMT ports
// 0.11 - update copyright dates
// 0.12 - add memcached check (TCP only, UDP not supported for IPv6)
// 0.13 - add memcached UDP check
// 0.14 - update copyright dates
// 0.15 - update copyright dates
// 0.16 - update copyright year
// 0.17 - add whois, TCP/43
// 0.18 - update copyright year
// 0.19 - add TCP/20005 (for KCodes NetUSB - see CVE-2021-45608)
// 0.20 - update copyright year

#include "ipscan.h"

#ifndef IPSCAN_PORTLIST_H
#define IPSCAN_PORTLIST_H 1

// Determine the default list of ports to be tested
// Note: each entry includes its port number followed by
// a text description (up to PORTDESCSIZE-1 characters long)
//
struct portlist_struc defportlist[] =
{
		{    7, 0, "Echo"},\
		{   21, 0, "FTP" },\
		{   22, 0, "SSH" },\
		{   23, 0, "Telnet" },\
		{   25, 0, "SMTP" },\
		{   37, 0, "Time" },\
		{   43, 0, "WHOIS" },\
		{   53, 0, "DNS" },\
		{   79, 0, "Finger" },\
		{   80, 0, "HTTP" },\
		{  110, 0, "POP3" },\
		{  111, 0, "SUN-RPC" },\
		{  113, 0, "Ident, Auth" },\
		{  119, 0, "NNTP" },\
		{  135, 0, "Microsoft-EPMAP" },\
		{  139, 0, "NetBIOS Session" },\
		{  143, 0, "IMAP" },\
		{  179, 0, "BGP" },\
		{  311, 0, "Apple-WebAdmin" },\
		{  389, 0, "LDAP" },\
		{  427, 0, "SLP" },\
		{  443, 0, "HTTPS" },\
		{  445, 0, "Microsoft-DS" },\
		{  515, 0, "LPD" },\
		{  543, 0, "Kerberos Login" },\
		{  544, 0, "Kerberos RSH" },\
		{  548, 0, "Apple-File" },\
		{  587, 0, "ESMTP" },\
		{  631, 0, "IPP" },\
		{  749, 0, "Kerberos Admin" },\
		{  873, 0, "Rsync" },\
		{  993, 0, "IMAPS" },\
		{  995, 0, "POP3S" },\
		{ 1025, 0, "Blackjack, NFS, IIS or RFS" },\
		{ 1026, 0, "CAP, Microsoft DCOM" },\
		{ 1029, 0, "Microsoft DCOM" },\
		{ 1030, 0, "BBN IAD" },\
		{ 1080, 0, "Socks" },\
		{ 1720, 0, "H323, Microsoft Netmeeting" },\
		{ 1723, 0, "PPTP" },\
		{ 1801, 0, "MSMQ" },\
		{ 2103, 0, "MSMQ-RPC" },\
		{ 2105, 0, "MSMQ-RPC" },\
		{ 2107, 0, "MSMQ-Mgmt" },\
		{ 2869, 0, "SSDP Event Notification" },\
		{ 3128, 0, "Active API, or Squid Proxy" },\
		{ 3306, 0, "MySQL" },\
		{ 3389, 0, "Microsoft RDP" },\
		{ 3689, 0, "DAAP, iTunes" },\
		{ 5000, 0, "UPNP" },\
		{ 5060, 0, "SIP" },\
		{ 5100, 0, "Service Mux, Yahoo Messenger" },\
		{ 5357, 0, "WSDAPI HTTP" },\
		{ 5900, 0, "VNC" },\
		{ 8080, 0, "HTTP alternate" },\
		{ 9090, 0, "WebSM" },\
		{10243, 0, "Microsoft WMP HTTP"},\
		{11211, 0, "memcache" },\
		{16992, 0, "Intel AMT SOAP/HTTP"},\
		{16993, 0, "Intel AMT SOAP/HTTPS"},\
		{16994, 0, "Intel AMT Redir/TCP"},\
		{16995, 0, "Intel AMT Redir/TLS"},\
		{20005, 0, "Router KCodes NetUSB port, see CVE-2021-45608"},\
		{32764, 0, "Router Backdoor"}\
};


// Calculate and record the number of default ports to be tested
#define DEFNUMPORTS ( sizeof(defportlist) / sizeof(struct portlist_struc) )

struct portlist_struc udpportlist[] =
{
		{   53, 0, "DNS" },\
		{   69, 0, "TFTP" },\
		{  123, 0, "NTP" },\
		{  123, 1, "NTP MONLIST" },\
		{  161, 0, "SNMPv1" },\
		{  161, 1, "SNMPv2c" },\
		{  161, 2, "SNMPv3" },\
		{  500, 0, "IKEv2 SA_INIT" },\
		{  521, 0, "RIPng" },\
		{  547, 0, "DHCPv6" },\
		{ 1900, 0, "UPnP SSDP" },\
		{ 3503, 0, "MPLS LSP Ping" },\
		{ 4500, 0, "IKEv2 NAT-T SA_INIT" },\
		{11211, 0, "memcache ASCII" },\
		{11211, 1, "memcache binary" },\
};

#if (IPSCAN_INCLUDE_UDP == 1)
#define NUMUDPPORTS ( sizeof(udpportlist) / sizeof(struct portlist_struc) )
#else
#define NUMUDPPORTS 0
#endif

#endif /* IPSCAN_PORTLIST_H */
