#!/usr/bin/perl -wT
use strict;
use DBI;
#
# Adjust these variables to match your database configuration:
#
my $DB_NAME='ipscan';
my $DB_HOST='localhost';
my $DB_USER='ipscan-user';
my $DB_PASSWORD='ipscan-passwd';
my $DB_TABLE='results';
#
# Nothing below this line should require user servicing!
#
# Enable debug (1) - dumps number of deleted records
my $DB_DEBUG = 0;
# This should be scheduled to run every 5 minutes so calculate time 
# 10m00s to 14m59s ago and then select and delete those rows
#
# Typical cron job:
#
# */5     *       *       *       *       /path/to/sqltidy.pl 2>&1
#
my $now = time();
my $now5minutes = int($now / 300);
my $earliest = ($now5minutes - 2) * 300;
my $latest = ($earliest + 299);
my $dbh = DBI->connect("DBI:mysql:database=$DB_NAME;host=$DB_HOST","$DB_USER","$DB_PASSWORD") or die "Cannot connect: " . $DBI::errstr;
my $sql = qq"DELETE FROM $DB_TABLE WHERE createdate >= $earliest AND createdate <= $latest";
my $sth = $dbh->prepare($sql) or die "Cannot prepare: " . $dbh->errstr();
$sth->execute() or die "Cannot execute: " . $sth->errstr();
if ($DB_DEBUG == 1 && $sth->rows > 0)
{
	print "Now      = ".localtime($now)."\n";
	print "Earliest = ".localtime($earliest)."\n";
	print "Latest   = ".localtime($latest)."\n";
	print "Rows deleted : ".$sth->rows."\n";
}
$sth->finish();
