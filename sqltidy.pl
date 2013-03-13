#!/usr/bin/perl -wT
#
# ipscan - an http-initiated IPv6 port scanner, offering text-only and javascript browser compatible versions.
# 
# Copyright (C) 2011-2013 Tim Chappell.
# 
# This file is part of ipscan.
# 
# ipscan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with ipscan. If not, see <http://www.gnu.org/licenses/>.
#
# Version 	Description
# 0.1		Initial version
# 
use strict;
use DBI;
####################################################################
# Adjust these variables to match your database configuration:
#
my $MYSQL_DBNAME='ipscan';
my $MYSQL_HOST='localhost';
my $MYSQL_USER='ipscan-user';
my $MYSQL_PASSWD='ipscan-passwd';
my $MYSQL_TBLNAME='results';
#
####################################################################
#
####################################################################
# To run every 5 minutes a typical cron job would look like this:
#
# */5 * * * * /path/to/sqltidy.pl 2>&1
#
####################################################################
#
####################################################################
# Nothing below this line should require user servicing!
####################################################################
#
# Set to 1 to enable debug - dumps number of deleted records
my $DB_DEBUG = 0;
#
####################################################################
# This script should be scheduled to run every 5 minutes. Calculate 
# the times which bound the entries that we're going to delete:
# $earliest is 10m00s ago
# $latest is   05m01s ago
####################################################################
#
# It is not recommended that you change runperiod but if you do
# then it MUST divide exactly into 1 hour (3600 seconds). The script
# is intended to delete records which are no longer required and since
# no scan is intended to take more than 1 minute then a 5 minute
# runperiod is a reasonable compromise. It also ties in well with
# the Munin-node update period if you want to log the number of scans
# which have been run. runperiod is measured in seconds. 
#
my $runperiod = 5*60;
#
# Determine current time, then split into runperiod chunks:
#
my $now = time();
my $nowXminutes = int($now / $runperiod);
#
# Subtract two runperiod chunks and then convert back to seconds:
#
my $earliest = ($nowXminutes - 2) * $runperiod;
#
# latest is 1 run period chunk later than earliest, minus 1 second:
#
my $latest = ($earliest + $runperiod - 1);
#
# Now open the database using the parameters defined above
#
my $dbh = DBI->connect("DBI:mysql:database=$MYSQL_DBNAME;host=$MYSQL_HOST","$MYSQL_USER","$MYSQL_PASSWD") or die "Cannot connect: " . $DBI::errstr;
#
# Select and delete the entries bound by the times we calculated above
#
my $sql = qq"DELETE FROM $MYSQL_TBLNAME WHERE createdate >= $earliest AND createdate <= $latest";
my $sth = $dbh->prepare($sql) or die "Cannot prepare: " . $dbh->errstr();
$sth->execute() or die "Cannot execute: " . $sth->errstr();
#
# If debug is enabled and some rows were deleted then report this to stdout
#
if ($DB_DEBUG == 1 && $sth->rows > 0)
{
	print "Runperiod = ".$runperiod." seconds\n";
	print "Now       = ".localtime($now)."\n";
	print "Earliest  = ".localtime($earliest)."\n";
	print "Latest    = ".localtime($latest)."\n";
	print "Rows deleted : ".$sth->rows."\n";
}
$sth->finish();
