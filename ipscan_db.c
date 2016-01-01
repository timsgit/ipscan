//    IPscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2016 Tim Chappell.
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

// ipscan_db.c version
// 0.01 - initial version
// 0.02 - added MySQL support
// 0.03 - added syslog support
// 0.04 - improved HTML (transition to styles, general compliance)
// 0.05 - addition of ping functionality (doc tidyup only)
// 0.06 - addition of storage for indirect host responses
// 0.07 - fix potential db query-string buffer overflow
// 0.08 - fix potential sscanf buffer overflow
// 0.09 - remove sqlite3 support
// 0.10 - tidy up comparisons and correct debug logging
// 0.11 - minor include correction for FreeBSD support
// 0.12 - add read_db_result() function
// 0.13 - change dump_db() to extend json results to report port, result and "address"
//      - necessary for UDP support
// 0.14 - improve debug logging
// 0.15 - change comments related to port field
// 0.16 - add delete support
// 0.17 - include debug reporting of number of rows sent to client
// 0.18 - further debug log improvements
// 0.19 - handle addition of test-state field which shouldn't be reported to client
// 0.20 - add support for database tidy up (deletion of orphaned results)
// 0.21 - use memory engine table type by default

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

// Others that FreeBSD highlighted
#include <netinet/in.h>

// MySQL Database includes
#include <my_global.h>
#include <mysql.h>

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

// ----------------------------------------------------------------------------------------
//
// Functions to write to the database, creating it first, if required
//
// ----------------------------------------------------------------------------------------

int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, char *indirecthost )
{
	// ID HOSTADDRESS DATE TIME SESSIONID PORT RESULT

	// ID                 BIGINT UNSIGNED
	//
	// HOSTADDRESS MSB    BIGINT UNSIGNED
	//	           LSB    BIGINT UNSIGNED
	//
	// DATE-TIME          BIGINT UNSIGNED
	//
	// SESSIONID          BIGINT UNSIGNED
	//
	// PORT               BIGINT UNSIGNED
	//				      Multiple fields are mapped to this single entry by the calling routines.
	//					  This includes the port, a special case indicator and the protocol.
	//					  See ipscan.h for the field masks and shifts
	//
	// RESULT             BIGINT UNSIGNED
	//
	// INDHOST            VARCHAR(INET6_ADDRSTRLEN+1)

	int rc;
	unsigned int qrylen;
	int retval = -1; // do not change this
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
		rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP, "ipscan");
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
				#if (IPSCAN_MYSQL_MEMORY_ENGINE_ENABLE == 1)
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SET max_heap_table_size = %d", MYSQL_MAX_HEAP_SIZE);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "write_db: MySQL Query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, qrylen);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "write_db: Failed to execute set max_heap_table_size %d (%s)\n",\
						mysql_errno(connection), mysql_error(connection) );
						retval = 32;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "write_db: Failed to create set max_heap_table_size command.\n");
					retval = 64;
				}
				#endif
				// retval defaults to -1, and is set to other values if an error condition occurs
				if (retval < 0)
				{
					#if (IPSCAN_MYSQL_MEMORY_ENGINE_ENABLE == 1)
					// Use memory engine - ensures sensitive data does not persist if MySQL is stopped/restarted
					qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, hostmsb BIGINT UNSIGNED , hostlsb BIGINT UNSIGNED, createdate BIGINT UNSIGNED, session BIGINT UNSIGNED, portnum BIGINT UNSIGNED, portresult BIGINT UNSIGNED, indhost VARCHAR(%d), PRIMARY KEY (id) ) ENGINE = MEMORY",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
					#else
					// Use the default engine - sensitive data may persist until next tidy_up_db() call
					qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, hostmsb BIGINT UNSIGNED , hostlsb BIGINT UNSIGNED, createdate BIGINT UNSIGNED, session BIGINT UNSIGNED, portnum BIGINT UNSIGNED, portresult BIGINT UNSIGNED, indhost VARCHAR(%d), PRIMARY KEY (id) )",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
					#endif
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						#ifdef DBDEBUG
						IPSCAN_LOG( LOGPREFIX "write_db: MySQL Query is : %s\n", query);
						#endif
						rc = mysql_real_query(connection, query, qrylen);
						if (0 == rc)
						{
							qrylen = snprintf(query, MAXDBQUERYSIZE, "INSERT INTO `%s` (hostmsb, hostlsb, createdate, session, portnum, portresult, indhost) VALUES ( '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%"PRIu64"', '%u', '%d', '%s' )", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port, result, indirecthost);
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								#ifdef DBDEBUG
								IPSCAN_LOG( LOGPREFIX "write_db: MySQL Query is : %s\n", query);
								#endif
								rc = mysql_real_query(connection, query, qrylen);
								if (0 == rc)
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
								IPSCAN_LOG( LOGPREFIX "write_db: Failed to create insert query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
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
						IPSCAN_LOG( LOGPREFIX "write_db: Failed to create create_table query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
						retval = 5;
					}
				} // matches with retval < 0
			} // Matches with main else
		} // MySQL options
		else
		{
			IPSCAN_LOG( LOGPREFIX "write_db: mysql_options() failed - check your my.cnf file\n");
			retval = 2;
		}
		// Tidy up
		mysql_commit(connection);
		mysql_close(connection);
	}

	#ifdef DBDEBUG
	IPSCAN_LOG( LOGPREFIX "write_db: returning with retval = %d\n",retval);
	#endif
	return (retval);
}


// ----------------------------------------------------------------------------------------
//
// Function to dump the database
//
// ----------------------------------------------------------------------------------------

int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
{

	int rc;
	int rcport, rcres, rchost;
	int retval = 0;
	unsigned int num_fields;
	unsigned int qrylen;
	int port, res;
	char hostind[INET6_ADDRSTRLEN+1];
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
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"') ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
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
							#if (IPSCAN_LOGVERBOSITY == 1)
							unsigned int nump = 0;
							#endif

							printf("[ ");

							while ((row = mysql_fetch_row(result)))
							{
								if (num_fields == 8) // database includes indirect host field
								{
									rcport = sscanf(row[5], "%d", &port);
									rcres = sscanf(row[6], "%d", &res);
									rchost = sscanf(row[7], "%"TO_STR(INET6_ADDRSTRLEN)"s", &hostind[0]);

									if ( rcres == 1 && rchost == 1 && rcport == 1 )
									{
										int proto = (port >> IPSCAN_PROTO_SHIFT) & IPSCAN_PROTO_MASK;
										// Report everything to the client apart from the test-state
										if (IPSCAN_PROTO_TESTSTATE != proto)
										{
											printf("%d, %d, \"%s\", ", port, res, hostind);
											#if (IPSCAN_LOGVERBOSITY == 1)
											nump += 1;
											#endif
										}
										else
										{
											#ifdef DBDEBUG
											IPSCAN_LOG( LOGPREFIX "dump_db: found port 0x%08x with proto %d, result %d\n", port, proto, res);
											#endif
										}
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "dump_db: Unexpected row scan results - rcport = %d, rcres = %d, rchost = %d, port = %d\n", rcport, rcres, rchost, port);
									}
								}
								else // original approach
								{
									printf("%s, ", row[num_fields-1]);
									IPSCAN_LOG( LOGPREFIX "dump_db: ERROR - you NEED to update to the new database format - please see the README for details!\n");
									#if (IPSCAN_LOGVERBOSITY == 1)
									nump += 1;
									#endif
								}
							}
							printf(" -9999, -9999, \"::1\" ]\n");
							mysql_free_result(result);
							#if (IPSCAN_LOGVERBOSITY == 1)
							IPSCAN_LOG( LOGPREFIX "dump_db: reported %d actual results to the client.\n", nump);
							#endif
						}
						else
						{
							// Didn't get any results, so check if we should have got some
							if (mysql_field_count(connection) == 0)
							{
								IPSCAN_LOG( LOGPREFIX "dump_db: surprisingly mysql_field_count() expected to return 0 fields\n");
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
// ----------------------------------------------------------------------------------------
//
// Functions to delete selected result from the database
//
// ----------------------------------------------------------------------------------------
int delete_from_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
{
	int rc;
	int retval = 0;
	unsigned int qrylen;
	char query[MAXDBQUERYSIZE];
	MYSQL *connection;
	MYSQL *mysqlrc;

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "delete_from_db: Failed to initialise MySQL\n");
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
				IPSCAN_LOG( LOGPREFIX "delete_from_db: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "delete_from_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// DELETE FROM t1 WHERE a = b ;
				qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"')", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "delete_from_db: MySQL Query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, qrylen);
					if (0 == rc)
					{
						my_ulonglong affected_rows = mysql_affected_rows(connection);
						if ( ((my_ulonglong)-1) == affected_rows)
						{
							IPSCAN_LOG( LOGPREFIX "delete_from_db: surprisingly delete returned successfully, but mysql_affected_rows() did not.\n");
							retval = 11;
						}
						else
						{
							#if (IPSCAN_LOGVERBOSITY == 1)
							IPSCAN_LOG( LOGPREFIX "delete_from_db: Deleted %ld entries from %s database.\n", (long)affected_rows, MYSQL_TBLNAME);
							#endif
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "delete_from_db: Delete failed, returned %d (%s).\n", rc, mysql_error(connection) );
						retval = 10;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "delete_from_db: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "delete_from_db: mysql_options() failed - check your my.cnf file\n");
			retval = 9;
		}
	}
return (retval);
}


// ----------------------------------------------------------------------------------------
//
// Functions to summarise the database
//
// ----------------------------------------------------------------------------------------


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

				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT hostmsb, hostlsb, createdate FROM `%s` GROUP BY createdate ORDER BY createdate", MYSQL_TBLNAME);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
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


//
// Fetch a single result
//

int read_db_result(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port)
{

	int rc;
	int rcres, dbres;
	int retres = PORTUNKNOWN;
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
		IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Failed to initialise MySQL\n");
		retres = PORTINTERROR;
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
				IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "read_db_result: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retres = PORTINTERROR;
			}
			else
			{
				// int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session )
				// SELECT x FROM t1 WHERE a = b ORDER BY x;
				// uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"' AND portnum = '%d') ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "read_db_result: MySQL Query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, qrylen);
					if (0 == rc)
					{
						result = mysql_store_result(connection);
						if (result)
						{
							num_fields = mysql_num_fields(result);
							#ifdef DBDEBUG
							IPSCAN_LOG( LOGPREFIX "read_db_result: MySQL returned num_fields : %d\n", num_fields);
							#endif
							while ((row = mysql_fetch_row(result)))
							{
								if (num_fields == 8) // database includes indirect host field
								{
									rcres = sscanf(row[6], "%d", &dbres);
									if ( rcres == 1)
									{
										// Set the return result
										retres = dbres;
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Unexpected row scan results - rcres = %d\n", rcres);
									}
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Unexpected row scan results - num_fields = %d\n", num_fields);
								}
							}
							mysql_free_result(result);
						}
						else
						{
							// Didn't get any results, so check if we should have got some
							if (mysql_field_count(connection) == 0)
							{
								IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: surprisingly mysql_field_count() expected to return 0 fields\n");
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: mysql_store_result() error : %s\n", mysql_error(connection));
								retres = PORTINTERROR;
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Failed to execute select query\n");
						retres = PORTINTERROR;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Failed to create select query\n");
					retres = PORTINTERROR;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "read_db_result: mysql_options() failed - check your my.cnf file\n");
			retres = PORTINTERROR;
		}
	}

if (PORTUNKNOWN == retres)
{
	IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: about to exit with PORTUNKNOWN return code\n");
}

return (retres);
}

// ----------------------------------------------------------------------------------------
//
// Function to tidy up old results from the database
//
// ----------------------------------------------------------------------------------------
int tidy_up_db(uint64_t time_now)
{
	int rc;
	int retval = 0;
	unsigned int qrylen;
	char query[MAXDBQUERYSIZE];
	MYSQL *connection;
	MYSQL *mysqlrc;
	if (time_now <= IPSCAN_DELETE_TIME_OFFSET)
	{
		IPSCAN_LOG( LOGPREFIX "tidy_up_db: Called with invalid time_now - %"PRIu64"\n", time_now);
		return (1);
	}
	// Calculate ( now - IPSCAN_DELETE_TIME_OFFSET ).
	// We'll delete everything older than this.
	uint64_t delete_before_time = (time_now - IPSCAN_DELETE_TIME_OFFSET);

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "tidy_up_db: Failed to initialise MySQL\n");
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
				IPSCAN_LOG( LOGPREFIX "tidy_up_db: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "tidy_up_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// DELETE FROM t1 WHERE a = b ;
				qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( createdate <= '%"PRIu64"' )", MYSQL_TBLNAME, delete_before_time);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "tidy_up_db: MySQL Query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, qrylen);
					if (0 == rc)
					{
						my_ulonglong affected_rows = mysql_affected_rows(connection);
						if ( ((my_ulonglong)-1) == affected_rows)
						{
							IPSCAN_LOG( LOGPREFIX "tidy_up_db: surprisingly delete returned successfully, but mysql_affected_rows() did not.\n");
							retval = 11;
						}
						else
						{
							#if (IPSCAN_LOGVERBOSITY == 1)
							if (affected_rows > 0 ) IPSCAN_LOG( LOGPREFIX "tidy_up_db: Deleted %ld entries from %s database.\n", (long)affected_rows, MYSQL_TBLNAME);
							#endif
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "tidy_up_db: Delete failed, returned %d (%s).\n", rc, mysql_error(connection) );
						retval = 10;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "tidy_up_db: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "tidy_up_db: mysql_options() failed - check your my.cnf file\n");
			retval = 9;
		}
	}
return (retval);
}
