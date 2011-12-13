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

// ipscan_db.c version
// 0.01 - initial version
// 0.02 - added MySQL support
// 0.03 - added syslog support
// 0.04 - improved HTML (transition to styles, general compliance)

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

#if (DBTYPE == 0)
	// sqlite3 Database includes
	#include <sqlite3.h>
#else
	// MySQL Database includes
	#include <my_global.h>
	#include <mysql.h>
#endif

// Logging with syslog requires additional include
#if (LOGMODE == 1)
	#include <syslog.h>
#endif

// String comparison
#include <string.h>
// Directory creation
#include <sys/stat.h>
// Error number handling
#include <errno.h>

// Include resultsstruct
extern struct rslt_struc resultsstruct[];

	// ----------------------------------------------------------------------------------------
	//
	// Functions to write to the database, creating it first, if required
	//
	// ----------------------------------------------------------------------------------------

#if (DBTYPE == 0)

	// SQLITE3 version

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
		IPSCAN_LOG( LOGPREFIX "write_db: busyHandler was called %d times, now exiting\n", previouscalls);
		return 0;
	}
	
	
	static int callback(void *NotUsed, int argc, char **argv, char **azColName)
	{
		int i;
		for(i=0; i<argc; i++)
		{
			IPSCAN_LOG( LOGPREFIX "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
		}
		IPSCAN_LOG( LOGPREFIX "\n");
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
			IPSCAN_LOG( LOGPREFIX  "write_db: Database file %s is non-existent, or unwriteable, creating ...\n", DBFILE);
			// Make directory with full (rwx) OWNER and partial (r-x) GRP/OTH privileges
			mkrc = mkdir( DBDIR, (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) );
			errsv = errno ;
			if (-1 == mkrc)
			{
				IPSCAN_LOG( LOGPREFIX  "write_db: Failed to mkdir %s reason %d (%s)\n", DBDIR, errsv, strerror(errsv) );
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
				IPSCAN_LOG( LOGPREFIX "write_db: Failed to open database at attempt %"PRIu16", reason : %s\n", attempt, sqlite3_errmsg(db));
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
			IPSCAN_LOG(  LOGPREFIX "write_db: Can't open database: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			return (1);
		}
		else
		{
			// insert the busy handler
			sqlite3_busy_handler(db, writebusyhandler, unused);

			rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS r1 (r1key INTEGER PRIMARY KEY, hostmsb INT8, hostlsb INT8, createdate INT8, session INT8, portnum INT8, portresult INT8);", callback, 0, &zErrMsg);
			if( rc!=SQLITE_OK )
			{
				IPSCAN_LOG( LOGPREFIX "write_db: SQL table create error: %s\n", zErrMsg);
				sqlite3_free(zErrMsg);
				sqlite3_close(db);
				return (3);
			}
			else
			{
				// write the data
				rc = sprintf(query, "INSERT INTO r1 (hostmsb, hostlsb, createdate, session, portnum, portresult) VALUES ( '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%u', '%d' )\n", host_msb, host_lsb, timestamp, session, port, result);
				if (rc > 0)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "write_db: Query insert string is : %s", query);
					#endif

					rc = sqlite3_exec(db, query, 0, 0, &zErrMsg);
					if( rc!=SQLITE_OK )
					{
						IPSCAN_LOG( LOGPREFIX "write_db: SQL insert entry error: %s\n", zErrMsg);
						sqlite3_free(zErrMsg);
						sqlite3_close(db);
						return (5);
					}
					else
					{
					#ifdef DBDEBUG
						IPSCAN_LOG( LOGPREFIX "write_db: SQL insert returned successfully\n");
					#endif
					}
				}
				else
				{
						IPSCAN_LOG( LOGPREFIX "write_db: Failed to create SQL query for insert\n");
						sqlite3_close(db);
						return (4);
				}

			}
		}

		//commit ;
		sqlite3_close(db);
		return (0);
	}

#else

	// MYSQL version

	int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result )
	{
		// ID HOSTADDRESS DATE TIME SESSIONID PORT RESULT

		// ID              INT8
		// HOSTADDRESS MSB INT8
		//	           LSB INT8
		// DATE-TIME       INT8
		// SESSIONID       INT8
		// PORT INT8
		//				16-bits Port number (0-65535)
		//				16-bits Protocol (TCP only at present)
		//				32-bits Reserved
		// RESULT INT8

		int rc;
		unsigned int qrylen;
		int retval = 0;
		char query[MAXDBQUERYSIZE];
		MYSQL *connection;
		MYSQL *mysqlrc;

		connection = mysql_init(NULL);
		if (NULL == connection)
		{
			IPSCAN_LOG( LOGPREFIX "write_db: Failed to initialise MySQL\n");
			retval = 1;
		}
		else
		{
			// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
			// in the my.cnf file which ensures that your program works, even if someone has set
			// up MySQL in some nonstandard way.
			rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
			if (0 == rc)
			{

				mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
				if (NULL == mysqlrc)
				{
					IPSCAN_LOG( LOGPREFIX "write_db: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection));
					IPSCAN_LOG( LOGPREFIX "write_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
					retval = 3;
				}
				else
				{
					qrylen = sprintf(query, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, hostmsb BIGINT UNSIGNED , hostlsb BIGINT UNSIGNED, createdate BIGINT UNSIGNED, session BIGINT UNSIGNED, portnum BIGINT UNSIGNED, portresult BIGINT UNSIGNED, PRIMARY KEY (id) )",MYSQL_TBLNAME );
					if (qrylen > 0)
					{
						#ifdef DBDEBUG
						IPSCAN_LOG( LOGPREFIX "write_db: MySQL Query is : %s\n", query);
						#endif
						rc = mysql_real_query(connection, query, qrylen);
						if (rc == 0)
						{
							qrylen = sprintf(query, "INSERT INTO `%s` (hostmsb, hostlsb, createdate, session, portnum, portresult) VALUES ( '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%u', '%d' )", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port, result);
							if (qrylen > 0)
							{
								#ifdef DBDEBUG
								IPSCAN_LOG( LOGPREFIX "write_db: MySQL Query is : %s\n", query);
								#endif
								rc = mysql_real_query(connection, query, qrylen);
								if (rc == 0)
								{
									retval = 0;
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "write_db: Failed to execute insert query %d (%s)\n",\
											mysql_errno(connection), mysql_error(connection) );
									retval = 7;
								}
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "write_db: Failed to create insert query\n");
								retval = 8;
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "write_db: Failed to execute create_table query %d (%s)\n",\
									mysql_errno(connection), mysql_error(connection) );
							retval = 6;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "write_db: Failed to create create_table query\n");
						retval = 5;
					}
				}
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "write_db: mysql_options() failed - check your my.cnf file\n");
				retval = 2;
			}
			// Tidy up
			mysql_commit(connection);
			mysql_close(connection);
		}
	return (retval);
	}

#endif

	// ----------------------------------------------------------------------------------------
	//
	// Functions to dump the database
	//
	// ----------------------------------------------------------------------------------------

#if (DBTYPE == 0)

	// SQLITE3 version

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
		IPSCAN_LOG( LOGPREFIX "dump_db: busyHandler was called %d times, now exiting\n", previouscalls);
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
				IPSCAN_LOG( LOGPREFIX "dump_db: Failed to open database at attempt %"PRIu16 ", reason : %s\n", attempt, sqlite3_errmsg(db));
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
			IPSCAN_LOG( LOGPREFIX "dump_db: Can't open database: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			return (1);
		}
		else
		{
				// insert the busy handler
				sqlite3_busy_handler(db, dumpbusyhandler, unused);

				// int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session )
				// SELECT x FROM t1 WHERE a = b ORDER BY x;
				rc = sprintf(query, "SELECT * FROM r1 WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"') ORDER BY ROWID;", host_msb, host_lsb, timestamp, session);

				if (rc > 0)
				{
					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "SQL Query is : %s\n", query);
					#endif
					rc = sqlite3_exec(db, "PRAGMA SHOW_DATATYPES=ON", 0, 0, &zErrMsg);
					if( rc!=SQLITE_OK )
					{
						IPSCAN_LOG( LOGPREFIX "dump_db: SQL pragma setting error: %s\n", zErrMsg);
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
							IPSCAN_LOG( LOGPREFIX "dump_db: SQL query db error: %s\n", zErrMsg);
							sqlite3_free(zErrMsg);
							sqlite3_close(db);
							return (7);
						}
						else
						{
							printf(" -9999 ]\n");
							#ifdef DBDEBUG
							IPSCAN_LOG( LOGPREFIX "dump_db: SQL dump returned successfully\n");
							#endif
						}

					}
				}
				else
				{
						IPSCAN_LOG( LOGPREFIX "dump_db: Failed to create SQL query for dump\n");
						sqlite3_close(db);
						return (6);
				}
		}
		sqlite3_close(db);
		return (0);
	}

#else

	// MYSQL version

	int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
	{

		int rc;
		int retval = 0;
		unsigned int num_fields;
		unsigned int qrylen;
		char query[MAXDBQUERYSIZE];
		MYSQL *connection;
		MYSQL *mysqlrc;
		MYSQL_RES *result;
		MYSQL_ROW row;

		connection = mysql_init(NULL);
		if (NULL == connection)
		{
			IPSCAN_LOG( LOGPREFIX "dump_db: Failed to initialise MySQL\n");
			retval = 1;
		}
		else
		{
			// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
			// in the my.cnf file which ensures that your program works, even if someone has set
			// up MySQL in some nonstandard way.
			rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
			if (0 == rc)
			{

				mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
				if (NULL == mysqlrc)
				{
					IPSCAN_LOG( LOGPREFIX "dump_db: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
					IPSCAN_LOG( LOGPREFIX "dump_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
					retval = 3;
				}
				else
				{
					// int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session )
					// SELECT x FROM t1 WHERE a = b ORDER BY x;
					qrylen = sprintf(query, "SELECT * FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"') ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
					if (qrylen > 0)
					{

						#ifdef DBDEBUG
						IPSCAN_LOG( LOGPREFIX "dump_db: MySQL Query is : %s\n", query);
						#endif
						rc = mysql_real_query(connection, query, qrylen);
						if (0 == rc)
						{
							result = mysql_store_result(connection);
							if (result)
							{
								num_fields = mysql_num_fields(result);
								#ifdef DBDEBUG
								IPSCAN_LOG( LOGPREFIX "dump_db: MySQL returned num_fields : %d\n", num_fields);
								#endif
								printf("[ ");

								while ((row = mysql_fetch_row(result)))
								{
									printf("%s, ", row[num_fields-1]);
								}
								printf(" -9999 ]\n");
								mysql_free_result(result);
							}
							else
							{
								// Didn't get any results, so check if we should have got some
								if (mysql_field_count(connection) == 0)
								{
									IPSCAN_LOG( LOGPREFIX "dump_db: suprisingly mysql_store_result() expected to return 0 fields\n");
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "dump_db: mysql_store_result() error : %s\n", mysql_error(connection));
									retval = 10;
								}
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "dump_db: Failed to execute select query\n");
							retval = 5;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "dump_db: Failed to create select query\n");
						retval = 4;
					}
				}
				mysql_commit(connection);
				mysql_close(connection);
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "dump_db: mysql_options() failed - check your my.cnf file\n");
				retval = 9;
			}
		}
	return (retval);
	}

#endif

	// ----------------------------------------------------------------------------------------
	//
	// Functions to summarise the database
	//
	// ----------------------------------------------------------------------------------------

#if (DBTYPE == 0)

	// SQLITE3 version

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
		IPSCAN_LOG( LOGPREFIX "summarise_db: busyHandler was called %d times, now exiting\n", previouscalls);
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
			printf("<TR style=\"text-align:center\">\n");
			printf("<TD width=\"50%%\">%s</TD>", hostname);
			printf("<TD width=\"50%%\">%s</TD>\n", asctime(localtime(&createdate)));
			printf("</TR>\n");
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
				IPSCAN_LOG( LOGPREFIX "summarise_db: Failed to open database at attempt %"PRIu16 ", reason : %s\n", attempt, sqlite3_errmsg(db));
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
			IPSCAN_LOG( LOGPREFIX "summarise_db: Can't open database: %s\n", sqlite3_errmsg(db));
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
					IPSCAN_LOG( LOGPREFIX "SQL Query is : %s\n", query);
					#endif
					rc = sqlite3_exec(db, "PRAGMA SHOW_DATATYPES=ON", 0, 0, &zErrMsg);
					if( rc!=SQLITE_OK )
					{
						IPSCAN_LOG( LOGPREFIX "summarise_db: SQL pragma setting error: %s\n", zErrMsg);
						sqlite3_free(zErrMsg);
						sqlite3_close(db);
						return (8);
					}
					else
					{
						printf("<TABLE border=\"1\">\n");
						printf("<TR style=\"text-align:center\"><TD width=\"50%%\">Host scanned:</TD><TD width=\"50%%\">Scan begin time:</TD></TR>\n");
						rc = sqlite3_exec(db, query, callbacksummarydumper, 0, &zErrMsg);
						if( rc!=SQLITE_OK )
						{
							IPSCAN_LOG( LOGPREFIX "summarise_db: SQL query db error: %s\n", zErrMsg);
							sqlite3_free(zErrMsg);
							sqlite3_close(db);
							return (7);
						}
						else
						{
							printf("</TABLE>\n");
							#ifdef DBDEBUG
							IPSCAN_LOG( LOGPREFIX "summarise_db: SQL dump returned successfully\n");
							#endif
						}

					}
				}
				else
				{
						IPSCAN_LOG( LOGPREFIX "summarise_db: Failed to create SQL query for dump\n");
						sqlite3_close(db);
						return (6);
				}
		}
		sqlite3_close(db);
		return (0);
	}

#else

	// MYSQL version

	int summarise_db(void)
	{


		int i,rc;
		unsigned int qrylen;
		int retval = 0;
		char query[MAXDBQUERYSIZE];
		MYSQL *connection;
		MYSQL *mysqlrc;
		MYSQL_RES *result;
		MYSQL_ROW row;

		uint64_t value, hostmsb, hostlsb ;
		time_t createdate;
		unsigned char remotehost[sizeof(struct in6_addr)];
		char hostname[INET6_ADDRSTRLEN];

		connection = mysql_init(NULL);
		if (NULL == connection)
		{
			IPSCAN_LOG( LOGPREFIX "summarise_db: Failed to initialise MySQL\n");
			retval = 1;
		}
		else
		{
			// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
			// in the my.cnf file which ensures that your program works, even if someone has set
			// up MySQL in some nonstandard way.
			rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
			if (0 == rc)
			{

				mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
				if (NULL == mysqlrc)
				{
					IPSCAN_LOG( LOGPREFIX "summarise_db: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
					IPSCAN_LOG( LOGPREFIX "summarise_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
					retval = 3;
				}
				else
				{

					qrylen = sprintf(query, "SELECT hostmsb, hostlsb, createdate FROM `%s` GROUP BY createdate ORDER BY createdate", MYSQL_TBLNAME);
					if (qrylen > 0)
					{
						#ifdef DBDEBUG
						IPSCAN_LOG( LOGPREFIX "summarise_db: MySQL Query is : %s\n", query);
						#endif
						rc = mysql_real_query(connection, query, qrylen);
						if (0 == rc)
						{
							result = mysql_store_result(connection);
							if (result)
							{

								printf("<TABLE border=\"1\">\n");
								printf("<TR style=\"text-align:center\"><TD width=\"50%%\">Host scanned:</TD><TD width=\"50%%\">Scan begin time:</TD></TR>\n");

								while ((row = mysql_fetch_row(result)))
								{
									rc=sscanf(row[0],"%"SCNu64, &value);
									if (rc == 1) hostmsb = value; else hostmsb = 0;
									rc=sscanf(row[1],"%"SCNu64, &value);
									if (rc == 1) hostlsb = value; else hostlsb = 0;
									rc=sscanf(row[2],"%"SCNu64, &value);
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
										printf("<TR style=\"text-align:center\">\n");
										printf("<TD width=\"50%%\">%s</TD>", hostname);
										printf("<TD width=\"50%%\">%s</TD>\n", asctime(localtime(&createdate)));
										printf("</TR>\n");
									}
								}

								printf("</TABLE>\n");

								mysql_free_result(result);
							}
							else
							{
								// Didn't get any results, so check if we should have got some
								if (mysql_field_count(connection) == 0)
								{
									IPSCAN_LOG( LOGPREFIX "summarise_db: surprisingly mysql_store_result() expected to return 0 fields\n");
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "summarise_db: mysql_store_result() error : %s\n", mysql_error(connection));
									retval = 10;
								}
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "summarise_db: Failed to execute select query\n");
							retval = 5;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "summarise_db: Failed to create select query\n");
						retval = 4;
					}

					mysql_commit(connection);
					mysql_close(connection);
				}
			}
			else
			{
				IPSCAN_LOG( LOGPREFIX "summarise_db: mysql_options() failed - check your my.cnf file\n");
				retval = 9;
			}
		}

	return (retval);
	}

#endif

