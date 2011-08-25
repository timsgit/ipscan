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

#include "ipscan.h"
//
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>

// Database
#include <sqlite3.h>
// String comparison
#include <string.h>
// Directory creation
#include <sys/stat.h>
// Error number handling
#include <errno.h>

// Include resultsstruct
extern struct rslt_struc resultsstruct[];

int writebusyhandler(void *pArg1, int previouscalls)
{
	// Arg1 is currently unused

	// sleep if we've not exceeded our number of calls
	if (previouscalls < BUSYHANDLERMAXCALLS)
	{
		// wait a random amount of time
		usleep((rand() % 50000) + 100000);
		return 1;
	}

	// otherwise blocked call will now return with error
	fprintf(stderr, LOGPREFIX "write_db: busyHandler was called %d times, now exiting\n", previouscalls);
	return 0;
}


static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
	int i;
	for(i=0; i<argc; i++)
	{
		fprintf(stderr, LOGPREFIX "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	fprintf(stderr, LOGPREFIX "\n");
	return 0;
}

int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result )
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char query[MAXDBQUERYSIZE];
	int *unused = 0;
	int mkrc, errsv;

	uint16_t attempt = 0;
	uint32_t sleeptime;
	rc = SQLITE_ERROR;

	// ROWID HOSTADDRESS DATE TIME SESSIONID PORT RESULT

	// ROWID INT8
	// HOSTADDRESS MSB INT8
	//	       LSB INT8
	// DATE-TIME INT8
	// SESSIONID ??
	//
	// PORT INT8 
	//		16-bits Port number (0-65535)
	//		16-bits Protocol (TCP only at present)
	//		32-bits Reserved
	// RESULT INT8

	// INSERT INTO t1 VALUES(NULL,123);
	// is logically equivalent to saying:

	// INSERT INTO t1 VALUES((SELECT max(a) FROM t1)+1,123);

	// There is a function named sqlite3_last_insert_rowid() which will return 
	// the integer key for the most recent insert operation.

	// SELECT x FROM t1 WHERE a = b ORDER BY x;
	// --result 1 2 3
	
	FILE *fstream;
	
	if ( (fstream = fopen(DBFILE, "r")) == NULL )
	{
		fprintf(stderr, LOGPREFIX  "write_db: Database file %s is non-existent, or unwriteable, creating ...\n", DBFILE);
		// Make directory with full (rwx) OWNER and partial (r-x) GRP/OTH privileges
		mkrc = mkdir( DBDIR, (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) );
		errsv = errno ;
		if (-1 == mkrc)
		{
			fprintf(stderr, LOGPREFIX  "write_db: Failed to mkdir %s reason %d (%s)\n", DBDIR, errsv, strerror(errsv) );
		}
		// At this point we can assume that the directory exists, if it doesn't then there's little we can do ...
		system( SQLITE3BIN" "DBFILE" .quit" );
	}
	else
	{
		fclose(fstream);
	}

	// Attempt to open the database
	uint16_t pid = ((uint16_t)getpid() & 0xFFFF);
	while (attempt < DBACCESS_ATTEMPTS && rc != SQLITE_OK)
	{
		rc = sqlite3_open( DBFILE, &db);
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, LOGPREFIX "write_db: Failed to open database at attempt %"PRIu16", reason : %s\n", attempt, sqlite3_errmsg(db));
			sqlite3_close(db);
		}
		// Include PID in order that all processes don't use the same wait time
		sleeptime = 20000 + pid + (10000 * attempt);
		attempt++;
		if (attempt < DBACCESS_ATTEMPTS && rc != SQLITE_OK)
		{
			usleep(sleeptime);
		}
	}

	if( rc != SQLITE_OK )
	{
		fprintf(stderr,  LOGPREFIX "write_db: Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return (1);
	}
	else
	{
		// insert the busy handler
		sqlite3_busy_handler(db, writebusyhandler, unused);

		rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS r1 (r1key INTEGER PRIMARY KEY,\
				hostmsb INT8, hostlsb INT8,\
				createdate DATETIME,\
				session INT8,\
				portnum INT8, portresult INT8);", callback, 0, &zErrMsg);
		if( rc!=SQLITE_OK )
		{
			fprintf(stderr, LOGPREFIX "write_db: SQL table create error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
			sqlite3_close(db);
			return (3);
		}
		else
		{
			// write the data
			// int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int result )
			#ifdef DBDEBUG
			rc = fprintf(stderr, LOGPREFIX "write_db: INSERT INTO r1 (hostmsb, hostlsb, createdate, session, portnum, portresult) \
									     VALUES ( '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%u', '%d'   )\n",\
								host_msb, host_lsb, timestamp, session, port, result);
			#endif

			rc = sprintf(query, "INSERT INTO r1 (hostmsb, hostlsb, createdate, session, portnum, portresult) \
						     VALUES ( '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%u', '%d'   )\n",\
					host_msb, host_lsb, timestamp, session, port, result);

			if (rc > 0)
			{
				rc = sqlite3_exec(db, query, 0, 0, &zErrMsg);
				if( rc!=SQLITE_OK )
				{
					fprintf(stderr, LOGPREFIX "write_db: SQL insert entry error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
					sqlite3_close(db);
					return (5);
				}
				else
				{
				#ifdef DBDEBUG
					fprintf(stderr, LOGPREFIX "write_db: SQL insert returned successfully\n");
				#endif
				}
			}
			else
			{
					fprintf(stderr, LOGPREFIX "write_db: Failed to create SQL query for insert\n");
					sqlite3_close(db);
					return (4);
			}
						 
		}
	}

	//commit ; 
	sqlite3_close(db);
	return (0);
}

int dumpbusyhandler(void *pArg1, int previouscalls)
{
	// Arg1 is currently unused

	// sleep if we've not exceeded our number of calls
	if (previouscalls < BUSYHANDLERMAXCALLS)
	{
		// wait a random amount of time
		usleep((rand() % 70000) + 100000);
		return 1;
	}

	// otherwise blocked call will now return with error
	fprintf(stderr, LOGPREFIX "dump_db: busyHandler was called %d times, now exiting\n", previouscalls);
	return 0;
}

// CALLED for each row returned:
// The 2nd argument to the sqlite3_exec() callback function is the number of columns in the result.
// The 3rd argument to the sqlite3_exec() callback is an array of pointers to strings obtained as if
// from sqlite3_column_text(), one for each column. If an element of a result row is NULL then the
// corresponding string pointer for the sqlite3_exec() callback is a NULL pointer.
// The 4th argument to the sqlite3_exec() callback is an array of pointers to strings where each
// entry represents the name of corresponding result column as obtained from sqlite3_column_name().

int callbackdumper(void *pArg, int argc, char **argv, char **columnNames)
{
	int i;
	for (i=0; i<argc; i++)
	{
		printf("%-10s %-8s %s\n", columnNames[i], columnNames[i+argc], argv[i]);
	}
	return(0);
}

int callbackresultsdumper(void *pArg, int argc, char **argv, char **columnNames)
{
	printf("%s, ", argv[6]);
	return(0);
}


int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char query[MAXDBQUERYSIZE];
	int *unused = 0;

	uint16_t attempt = 0;
	uint32_t sleeptime;
	rc = SQLITE_ERROR;

	// Attempt to open the database
	uint16_t pid = ((uint16_t)getpid() & 0xFFFF);
	while (attempt < DBACCESS_ATTEMPTS && rc != SQLITE_OK)
	{
		rc = sqlite3_open( DBFILE, &db);
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, LOGPREFIX "dump_db: Failed to open database at attempt %"PRIu16 ", reason : %s\n", attempt, sqlite3_errmsg(db));
			sqlite3_close(db);
		}
		// Include PID in order that all processes don't use the same wait time
		sleeptime = 30000 + pid + (10000 * attempt);
		attempt++;
		if (attempt < DBACCESS_ATTEMPTS && rc != SQLITE_OK)
		{
			usleep(sleeptime);
		}
	}

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, LOGPREFIX "dump_db: Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return (1);
	}
	else
	{
			// insert the busy handler
			sqlite3_busy_handler(db, dumpbusyhandler, unused);

			// int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session )
			// SELECT x FROM t1 WHERE a = b ORDER BY x;
			rc = sprintf(query, "SELECT * FROM r1 WHERE (\
						hostmsb = '%"PRIu64"' AND \
					    hostlsb = '%"PRIu64"' AND \
						createdate = '%"PRIu64"' AND \
						session = '%"PRIu64"') ORDER BY ROWID;",\
						host_msb, host_lsb, timestamp, session);

			if (rc > 0)
			{
				#ifdef DBDEBUG
				fprintf(stderr, LOGPREFIX "SQL Query is : %s\n", query);
				#endif
				rc = sqlite3_exec(db, "PRAGMA SHOW_DATATYPES=ON", 0, 0, &zErrMsg);
				if( rc!=SQLITE_OK )
				{
					fprintf(stderr, LOGPREFIX "dump_db: SQL pragma setting error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
					sqlite3_close(db);
					return (8);
				}
				else
				{
					printf("[ ");
					rc = sqlite3_exec(db, query, callbackresultsdumper, 0, &zErrMsg);
					if( rc!=SQLITE_OK )
					{
						fprintf(stderr, LOGPREFIX "dump_db: SQL query db error: %s\n", zErrMsg);
						sqlite3_free(zErrMsg);
						sqlite3_close(db);
						return (7);
					}
					else
					{
						printf(" -9999 ]\n");
						#ifdef DBDEBUG
						fprintf(stderr, LOGPREFIX "dump_db: SQL dump returned successfully\n");
						#endif
					}

				}
			}
			else
			{
					fprintf(stderr, LOGPREFIX "dump_db: Failed to create SQL query for dump\n");
					sqlite3_close(db);
					return (6);
			}
	}
	sqlite3_close(db);
	return (0);
}


int summarybusyhandler(void *pArg1, int previouscalls)
{
	// Arg1 is currently unused

	// sleep if we've not exceeded our number of calls
	if (previouscalls < BUSYHANDLERMAXCALLS)
	{
		// wait a random amount of time
		usleep((rand() % 90000) + 110000);
		return 1;
	}

	// otherwise blocked call will now return with error
	fprintf(stderr, LOGPREFIX "summarise_db: busyHandler was called %d times, now exiting\n", previouscalls);
	return 0;
}

int callbacksummarydumper(void *pArg, int argc, char **argv, char **columnNames)
{
	int rc, i;
	uint64_t value, hostmsb, hostlsb ;
	time_t createdate;
	unsigned char remotehost[sizeof(struct in6_addr)];
	char hostname[INET6_ADDRSTRLEN];

	rc=sscanf(argv[0],"%"SCNu64, &value);
	if (rc == 1) hostmsb = value; else hostmsb = 0;
	rc=sscanf(argv[1],"%"SCNu64, &value);
	if (rc == 1) hostlsb = value; else hostlsb = 0;
	rc=sscanf(argv[2],"%"SCNu64, &value);
	if (rc == 1) createdate = (time_t)value; else createdate = 0;

	value = hostmsb;
	for (i=0 ; i<8 ; i++)
	{
		remotehost[7-i] = value & 0xFF;
		value = (value >> 8);
	}
	value = hostlsb;
	for (i=0 ; i<8 ; i++)
	{
		remotehost[15-i] = value & 0xFF;
		value = (value >> 8);
	}

	if (inet_ntop(AF_INET6, &remotehost, hostname, INET6_ADDRSTRLEN) != NULL)
	{
		printf("<tr align=\"center\">\n");
		printf("<td width=\"50%%\">%s</td>\n", hostname);
		printf("<td width=\"50%%\">%s</td>\n", asctime(localtime(&createdate)));
		printf("</tr>\n");
	}

	return(0);
}


int summarise_db(void)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char query[MAXDBQUERYSIZE];
	int *unused = 0;

	uint16_t attempt = 0;
	uint32_t sleeptime;
	rc = SQLITE_ERROR;

	// Attempt to open the database
	uint16_t pid = ((uint16_t)getpid() & 0xFFFF);
	while (attempt < DBACCESS_ATTEMPTS && rc != SQLITE_OK)
	{
		rc = sqlite3_open( DBFILE, &db);
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, LOGPREFIX "summarise_db: Failed to open database at attempt %"PRIu16 ", reason : %s\n", attempt, sqlite3_errmsg(db));
			sqlite3_close(db);
		}
		// Include PID in order that all processes don't use the same wait time
		sleeptime = 70000 + pid + (70000 * attempt);
		attempt++;
		if (attempt < DBACCESS_ATTEMPTS && rc != SQLITE_OK)
		{
			usleep(sleeptime);
		}
	}

	if( rc != SQLITE_OK)
	{
		fprintf(stderr, LOGPREFIX "summarise_db: Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return (1);
	}
	else
	{
			// insert the busy handler
			sqlite3_busy_handler(db, summarybusyhandler, unused);

			// int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session )
			// SELECT x FROM t1 WHERE a = b ORDER BY x;
			rc = sprintf(query, "SELECT hostmsb, hostlsb, createdate FROM r1 GROUP BY createdate ORDER BY createdate;\n" );
			if (rc > 0)
			{
				#ifdef DBDEBUG
				fprintf(stderr, LOGPREFIX "SQL Query is : %s\n", query);
				#endif
				rc = sqlite3_exec(db, "PRAGMA SHOW_DATATYPES=ON", 0, 0, &zErrMsg);
				if( rc!=SQLITE_OK )
				{
					fprintf(stderr, LOGPREFIX "summarise_db: SQL pragma setting error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
					sqlite3_close(db);
					return (8);
				}
				else
				{
					printf("<p><table border=\"4\" bordercolor=\"black\">\n");
					printf("<tr align=\"center\"><td width=\"50%%\">Host scanned:</td><td width=\"50%%\">Scan begin time:</td></tr>\n");
					rc = sqlite3_exec(db, query, callbacksummarydumper, 0, &zErrMsg);
					if( rc!=SQLITE_OK )
					{
						fprintf(stderr, LOGPREFIX "summarise_db: SQL query db error: %s\n", zErrMsg);
						sqlite3_free(zErrMsg);
						sqlite3_close(db);
						return (7);
					}
					else
					{
						printf("</table></p>\n");
						#ifdef DBDEBUG
						fprintf(stderr, LOGPREFIX "summarise_db: SQL dump returned successfully\n");
						#endif
					}

				}
			}
			else
			{
					fprintf(stderr, LOGPREFIX "summarise_db: Failed to create SQL query for dump\n");
					sqlite3_close(db);
					return (6);
			}
	}
	sqlite3_close(db);
	return (0);
}
