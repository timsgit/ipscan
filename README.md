# IPscan
### An HTTP-initiated IPv6 port scanner, offering text-only and javascript browser compatible versions.

Copyright (C) 2011-2019 Tim Chappell.

This file is part of IPscan.

IPscan is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with IPscan. If not, see <http://www.gnu.org/licenses/>.

---

IPscan requires access to a MySQL database and the associated client development libraries 
(libmysqlclient-dev or similar) to be installed on the server which will act as your scanner. 
IPscan is known to build on: openSUSE versions 11.1/11.4/12.1/13.1, Centos 7, Fedora 16, 
Ubuntu 12.04, Mint 12, FreeBSD 9, Arch Linux ARM (Raspberry Pi) and Raspbian and run alongside 
Apache versions 2.2 and 2.4. Please let me know of any other build successes/failures on 
unlisted platforms.

NOTE: IPscan logging has been updated to aid operators needing to comply with regulatory
requirements for the protection of end-users, e.g. GDPR. Where applicable, the logging-related
recommendations outlined in: https://tools.ietf.org/id/draft-andersdotter-intarea-update-to-rfc6302-00.html#RFC6302
have been implemented, for unmodified ipscan.h configurations. 

Installation Steps:
===================
IMPORTANT: when UPGRADING from versions before 0.90: a database change has occurred and consequently 
it is necessary that you remove your existing database prior to building and installing 
versions 0.90 and later. See step 4 below for details.

    1. edit the Makefile and adjust the following entries as required:
        a. TARGETDIR - this should be set to the desired location for the cgi files (e.g. `/srv/www/cgi-bin6`)
                   Ensure that the selected target directory exists, with appropriate permissions, before 
                   attempting to install the final executables.
        b. URIPATH - this is the request URI by which the cgi files will be accessed from your webserver
                   e.g. https://www64.chappell-family.co.uk/cgi-bin6/ipscan-js.cgi then set URIPATH=/cgi-bin6
        c. TXTTARGET and JSTARGET - these define the names of the two cgi objects that will be created
        d. SETUID_AVAILABLE and UDP_AVAILABLE - if you're running the service on a machine where you, or
                   the web server, don't have permissions to call setuid() or create UDP sockets then these features
                   need to be disabled.

    2. edit ipscan.h and adjust *at least* the following entries:
        a. EMAILADDRESS - suggest you use a non-personal email address if the webserver will be world-accessible
        b. INCLUDETERMSOFUSE and TERMSOFUSEURL if you wish to reference a terms of use page on your website.
        c. IPSCAN_INTERFACE_NAME - modify this to match the server's interface to which clients will browse.  
        d. MYSQL_XXXX   - Adjust the following constants to match the settings of your database server: 
                          MYSQL_HOST - the hostname or IP address of the machine hosting the MySQL database
                          MYSQL_USER - the username used to access the IPscan database.
                          MYSQL_PASSWD - the password used to identify the MySQL user.
                          MYSQL_DBNAME - the name of the IPscan database.
                          MYSQL_TBLNAME - the name of the table in which IPscan results will reside.

    3. edit ipscan_portlist.h and change the list of ports to be tested, if required. Note that if you add 
       new UDP ports then you must also add a matching packet generator function to ipscan_udp.c
    
    4. Create the database and user and allocate appropriate user privileges, using the following commands within the mysql shell:

       NB: adjust the host, user name, password and database name to match the globals you've edited in step 2 above:
        
       mysql> create database ipscan;
       Query OK, 1 row affected (0.00 sec)

       Note: it is unnecessary to re-create the user if upgrading from a previous version.
       
       mysql> create user 'ipscan-user'@'localhost' identified by 'ipscan-passwd';
       Query OK, 0 rows affected (0.01 sec)

       mysql> grant all privileges on ipscan.* to 'ipscan-user'@'localhost' identified by 'ipscan-passwd';
       Query OK, 0 rows affected (0.01 sec)

       mysql> exit
       Bye
       
       If performing an upgrade from an earlier version of IPscan then either drop the table within a mysql shell, e.g. :
        
       mysql> use ipscan;
       mysql> drop table if exists results;
       
       or use the BASH upgrade script within the IPscan source directory:
       
       $ ./upgrade.bsh
        
       
    5. make && make install
       
       Given that the suid bit is set on the installed executables, in order to support raw sockets for ICMPv6 testing, 
       it is necessary to perform the 'make install' stage as root user. 
       
       Note: when updating an existing installation to version 1.10 and beyond it may be necessary to manually 
       remove the ipscan_checks.c file, if it remains in your install directory, prior to building. 
       The functionality within ipscan_checks.c has been redistributed to separate files which 
       handle tcp, udp and icmpv6 testing.
       
       Note: please use gmake under FreeBSD.
    
    6. make sure that the URI path directory (which may well be accessed via an Apache alias) is enabled to execute cgi:
        
       ScriptAlias /cgi-bin6/ "/srv/www/cgi-bin6/"
       <Directory "/srv/www/cgi-bin6">
          AllowOverride None
          Options +ExecCGI -Includes
          Order allow,deny
          Allow from 2000::/3
       </Directory>
        
       Also disable client caching, having enabled the loading of mod_headers:
       
       <IfModule mod_headers.c>
          Header set Cache-Control "private, no-cache, no-store, must-revalidate"
          Header set Pragma "no-cache"
          Header set Expires "0"
       </IfModule>
       
       Don't forget to restart your web server after making the appropriate modifications.
    
    7. If you are using an SELinux-enabled distribution (e.g. Fedora) then it may be necessary to perform additional 
       steps similar to those outlined below:
       a. Ensure that your Apache server is enabled to support cgi, as root type:
          # setsebool -P httpd_enable_cgi on
       b. Enable the correct execution permissions to the cgi scripts, as root type:
          # cd /srv/www/cgi-bin6/ (use your selected installation path)
          # chcon -t httpd_unconfined_script_exec_t *.cgi
          
       IMPORTANT NOTE: the steps listed in step 7 above are only indicative of what may be required, and 
       depend upon your existing installation. Please consult the SELinux documentation for further details. 
          
    8. Browse from a machine that you want testing towards your servers' IPv6 address, e.g. 
       w3m https://www64.chappell-family.co.uk/cgi-bin6/ipscan-fast-txt.cgi 
       or: 
       lynx https://[2001:470:971f:6::4]/cgi-bin6/ipscan-txt.cgi

    9. Check the web server access/error logs or syslog for messages. IPscan will place summary messages in the 
       web server error log or syslog if enabled to do so (this is NOT the default option - change 
       IPSCAN_LOGVERBOSITY to 1 to enable this). It is possible to enable copious amounts of debug by 
       uncommenting the debug #define statements in ipscan.h.
    
    10. If you're providing public access to IPscan then please ensure that you disable verbose reporting,
        the summary option and ALL debug facilities.

        Note: versions v1.42 and later of IPscan automatically delete the scan results, for both javascript
        and text-only clients, after reporting them to the user. Earlier versions relied on a cron job
        to achieve the same end, but this is no longer required for current versions.

    11. For those considering providing IPscan access on the public internet then consider adding a 
        landing page which will check for host IP address suitability prior to allowing access to the 
        cgi script(s) - most (apart from google) search engine spiders/robots currently only use IPv4. 
        It may be advisable to only offer direct links to the cgi scripts if the address checks 
        were successful. See https://ipv6.chappell-family.com/ipv6tcptest/ as an example. 

    12. Notes on IPscan binaries: IPscan is provided in two basic versions, one supporting 
        javascript-enabled browsers and the other for text-based browsers. Additionally, the standard 
        build provides fast and standard versions of both of these tests. The fast version tests 
        multiple TCP or UDP ports in parallel, whereas the standard version tests only 1 port at a time,
        at a default rate of 1 port per second. Please be aware that some OS and firewalls apply 
        rate-limiting to their generation, or passing, of ICMPv6 responses on the basis that this 
        behaviour is indicative of a port scan being performed. Consequently such rate-limiting might 
        cause a port which would normally generate an ICMPv6 response (e.g. PHBTD) to send no response 
        at all, which IPscan would report as STEALTHed. If you are testing a host or firewall (whether 
        on the client under test or elsewhere in the path between your client and test server) which 
        implements such rate-limiting then you are advised to use the standard, slower versions of IPscan 
        which should not trigger the rate-limiting behaviour. If you're unsure which version is appropriate 
        for your device, then try both and compare the results. Some Linux distributions and some ISP firewalls
        are known to implement such rate-limiting.


Getting further help:
=====================
A demonstration Raspberry Pi IPv6 firewall checker is available to IPv6 enabled clients at: <https://ipv6.chappell-family.com/ipv6tcptest/>. If you need further help then please email me at: <webmaster@chappell-family.com> or visit my IPscan wiki at: <https://wiki.chappell-family.com/wiki/index.php?title=IPv6>

[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/timsgit/ipscan.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/timsgit/ipscan/context:cpp)
---
