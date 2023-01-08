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
// 0.22 - modify debug/test logging
// 0.23 - update copyright dates
// 0.24 - further HTML tag adjustments
// 0.25 - update copyright dates
// 0.26 - remove memory engine resizing
// 0.27 - updated logging for client debug (number of deleted rows)
// 0.28 - update copyright dates
// 0.29 - added timestamp and session to client debug options
// 0.30 - only log number of deleted rows during tidy_up_db if >0
// 0.31 - semmle re-entrant time functions added
// 0.32 - add debug dump of rows about to be tidied
// 0.33 - fix typo in summarise_db()
// 0.34 - improved tidy_up_db debug logging, copyright update
// 0.35 - removed summarise_db() functionality
// 0.36 - add update_db() for use in place of write_db() for IPSCAN_TESTSTATE monitoring
// 0.37 - additional debug for write_db() and update_db()
// 0.38 - move primary key statements, update copyright year
// 0.39 - add LGTM pragmas to prevent False Positive (FP) reporting of SQL injection vuln
// 0.40 - remove LGTM pragmas since FP diagnosis accepted and alerts should go away soon
// 0.41 - additional read_db_result() and dump_db() debug
// 0.42 - update copyright dates
// 0.43 - reduce scope of multiple variables
// 0.44 - fix unsigned sscanf() mistake

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
// Functions from ipscan_general.c
//
void proto_to_string(int proto, char * retstring);
char * state_to_string(int statenum, char * retstringptr, int retstringfree);
void result_to_string(int result, char * retstring);
// ----------------------------------------------------------------------------------------

// ----------------------------------------------------------------------------------------
//
// Functions to write to the database, creating it first, if required
//
// ----------------------------------------------------------------------------------------

int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, const char *indirecthost )
{

	// ID                 BIGINT UNSIGNED
	//
	// HOSTADDRESS MSB    BIGINT UNSIGNED
	//	       LSB    BIGINT UNSIGNED
	//
	// DATE-TIME          BIGINT UNSIGNED
	//
	// SESSIONID          BIGINT UNSIGNED
	//
	// PORT               BIGINT UNSIGNED
	//				  Multiple fields are mapped to this single entry by the calling routines.
	//				  This includes the port, a special case indicator and the protocol.
	//				  See ipscan.h for the field masks and shifts
	//
	// RESULT             BIGINT UNSIGNED
	//
	// INDHOST            VARCHAR(INET6_ADDRSTRLEN+1)

	int retval = -1; // do not change this
	MYSQL *connection;

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "write_db: ERROR: Failed to initialise MySQL\n");
		retval = 1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		int rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP, "ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "write_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection));
				IPSCAN_LOG( LOGPREFIX "write_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// retval defaults to -1, and is set to other values if an error condition occurs
				if (retval < 0)
				{
					char query[MAXDBQUERYSIZE];
					#if (IPSCAN_MYSQL_MEMORY_ENGINE_ENABLE == 1)
					// Use memory engine - ensures sensitive data does not persist if MySQL is stopped/restarted
					int qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, hostmsb BIGINT UNSIGNED DEFAULT 0, hostlsb BIGINT UNSIGNED DEFAULT 0, createdate BIGINT UNSIGNED DEFAULT 0, session BIGINT UNSIGNED DEFAULT 0, portnum BIGINT UNSIGNED DEFAULT 0, portresult BIGINT UNSIGNED DEFAULT 0, indhost VARCHAR(%d) DEFAULT '' ) ENGINE = MEMORY",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
					#else
					// Use the default engine - sensitive data may persist until next tidy_up_db() call
					int qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, hostmsb BIGINT UNSIGNED DEFAULT 0, hostlsb BIGINT UNSIGNED DEFAULT 0, createdate BIGINT UNSIGNED DEFAULT 0, session BIGINT UNSIGNED DEFAULT 0, portnum BIGINT UNSIGNED DEFAULT 0, portresult BIGINT UNSIGNED DEFAULT 0, indhost VARCHAR(%d) DEFAULT '' )",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
					#endif
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						rc = mysql_real_query(connection, query, (unsigned long)qrylen);
						if (0 == rc)
						{
							qrylen = snprintf(query, MAXDBQUERYSIZE, "INSERT INTO `%s` (hostmsb, hostlsb, createdate, session, portnum, portresult, indhost) VALUES ( %"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64", %u, %d, '%s' )", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port, result, indirecthost);
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								#ifdef DBDEBUG
								IPSCAN_LOG( LOGPREFIX "write_db: MySQL Query is : %s\n", query);
								#endif
								rc = mysql_real_query(connection, query, (unsigned long)qrylen);
								if (0 == rc)
								{
									retval = 0;
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "write_db: ERROR: Failed to execute insert query \"%s\" %d (%s)\n",\
											query, mysql_errno(connection), mysql_error(connection) );
									retval = 7;
								}
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "write_db: ERROR: Failed to create insert query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
								retval = 8;
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "write_db: ERROR: Failed to execute create_table query \"%s\" %d (%s)\n",\
									query, mysql_errno(connection), mysql_error(connection) );
							retval = 6;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "write_db: ERROR: Failed to create create_table query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
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

	if (0 != retval) IPSCAN_LOG( LOGPREFIX "write_db: WARNING - returning with retval = %d\n",retval);
	return (retval);
}


// ----------------------------------------------------------------------------------------
//
// Function to dump the database
//
// ----------------------------------------------------------------------------------------

int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
{

	int retval = 0;
	uint32_t port, res;
	MYSQL *connection;
	MYSQL_ROW row;

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "dump_db: ERROR: Failed to initialise MySQL\n");
		retval = 1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		int rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "dump_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "dump_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session
				// SELECT x FROM t1 WHERE a = b ORDER BY x;
				char query[MAXDBQUERYSIZE];
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"') ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "dump_db: MySQL Query is : \"%s\"\n", query);
					#endif
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						MYSQL_RES * result = mysql_store_result(connection);
						if (result)
						{
							unsigned int num_fields = mysql_num_fields(result);
							#if (IPSCAN_LOGVERBOSITY == 1)
							unsigned int nump = 0;
							#endif

							uint64_t num_rows = mysql_num_rows(result);
							if (0 == num_rows)
							{
								IPSCAN_LOG( LOGPREFIX "dump_db: WARNING: 0 rows returned, num_fields = %d, query = \"%s\"\n", num_fields, query);
							}

							printf("[ ");

							while ((row = mysql_fetch_row(result)))
							{
								if (8 == num_fields) // database includes indirect host field
								{
									char hostind[INET6_ADDRSTRLEN+1];
									int rcport = sscanf(row[5], "%u", &port); // was %d 2023
									int rcres = sscanf(row[6], "%u", &res); // was %d 2023
									int rchost = sscanf(row[7], "%"TO_STR(INET6_ADDRSTRLEN)"s", &hostind[0]);
									if ( 1 == rcres && 1 == rchost && 1 == rcport )
									{
										uint32_t proto = (port >> IPSCAN_PROTO_SHIFT) & IPSCAN_PROTO_MASK;
										// Report everything to the client apart from the test-state
										if (IPSCAN_PROTO_TESTSTATE != proto)
										{
											printf("%d, %d, \"%s\", ", port, res, hostind);
											#ifdef DBDEBUG
											IPSCAN_LOG( LOGPREFIX "dump_db: raw results: proto %d, port %d, result %d, host \"%s\"\n", proto, port, res, hostind);
											#endif
											#if (IPSCAN_LOGVERBOSITY == 1)
											nump += 1;
											#endif
										}
										else
										{
											#ifdef DBDEBUG
											IPSCAN_LOG( LOGPREFIX "dump_db: raw results: TESTSTATE, port %d, result %d\n", port, res);
											#endif
										}
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "dump_db: Unexpected row scan results - rcport = %d, rcres = %d, rchost = %d\n", rcport, rcres, rchost);
									}
								}
								else // original approach
								{
									printf("%s, ", row[num_fields-1]);
									IPSCAN_LOG( LOGPREFIX "dump_db: MySQL returned num_fields : %d\n", num_fields);
									IPSCAN_LOG( LOGPREFIX "dump_db: ERROR - you NEED to update to the new database format - please see the README for details!\n");
									#if (IPSCAN_LOGVERBOSITY == 1)
									nump += 1;
									#endif
								}
							}
							printf(" -9999, -9999, \"::1\" ]\n");
							mysql_free_result(result);
							#ifdef RESULTSDEBUG
							#if (IPSCAN_LOGVERBOSITY == 1)
							IPSCAN_LOG( LOGPREFIX "dump_db: reported %d actual results to the client.\n", nump);
							#endif
							#endif
						}
						else
						{
							// Didn't get any results, so check if we should have got some
							if (0 == mysql_field_count(connection))
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
						IPSCAN_LOG( LOGPREFIX "dump_db: ERROR: Failed to execute select query \"%s\" %d (%s)\n",\
                                                                                        query, mysql_errno(connection), mysql_error(connection) );
						retval = 5;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "dump_db: ERROR: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "dump_db: ERROR: mysql_options() failed - check your my.cnf file\n");
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
	int retval = 0;
	MYSQL *connection;

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "delete_from_db: ERROR: Failed to initialise MySQL\n");
		retval = 1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		int rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "delete_from_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "delete_from_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// DELETE FROM t1 WHERE a = b ;
				char query[MAXDBQUERYSIZE];
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"')", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "delete_from_db: MySQL Query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						my_ulonglong affected_rows = mysql_affected_rows(connection);
						if ( ((my_ulonglong)-1) == affected_rows)
						{
							IPSCAN_LOG( LOGPREFIX "delete_from_db: ERROR: surprisingly delete returned successfully, but mysql_affected_rows() did not.\n");
							retval = 11;
						}
						else
						{
							#ifdef CLIENTDEBUG
							IPSCAN_LOG( LOGPREFIX "delete_from_db: Deleted %ld rows for %x:%x:%x:: from %s database.\n",\
									(long)affected_rows, (unsigned int)((host_msb>>48)&0xFFFF),\
									(unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF), MYSQL_TBLNAME);
							IPSCAN_LOG( LOGPREFIX "delete_from_db: Timestamp %"PRIu64", session %"PRIu64"\n", timestamp, session);
							#endif
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "delete_from_db: ERROR: Delete failed, returned %d (%s).\n", rc, mysql_error(connection) );
						retval = 10;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "delete_from_db: ERROR: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "delete_from_db: ERROR: mysql_options() failed - check your my.cnf file\n");
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

	int dbres;
	int retres = PORTUNKNOWN;
	MYSQL *connection;
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
		int rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "read_db_result: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retres = PORTINTERROR;
			}
			else
			{
				// was SELECT x FROM t1 WHERE a = b ORDER BY x;
				// SELECT x FROM t1 WHERE ( a = b ) ORDER BY x DESC;
				// uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port
				char query[MAXDBQUERYSIZE];
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = '%"PRIu64"' AND hostlsb = '%"PRIu64"' AND createdate = '%"PRIu64"' AND session = '%"PRIu64"' AND portnum = '%d') ORDER BY id DESC", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						MYSQL_RES * result = mysql_store_result(connection);
						if (NULL != result)
						{
							unsigned int num_fields = mysql_num_fields(result);
							uint64_t num_rows = mysql_num_rows(result);
							if (0 == num_rows)
							{
								IPSCAN_LOG( LOGPREFIX "read_db_result: WARNING: 0 rows returned, num_fields = %d, query = \"%s\"\n", num_fields, query);
							}
							while ((row = mysql_fetch_row(result)))
							{
								if (8 == num_fields) // database includes indirect host field
								{
									int rcres = sscanf(row[6], "%d", &dbres);
									if (1 == rcres)
									{
										// Set the return result
										retres = dbres;
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Unexpected row scan results - sscanf() = %d\n", rcres);
									}
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Unexpected row scan results - num_fields() = %d\n", num_fields);
								}
							}
							mysql_free_result(result);
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: surprisingly mysql_store_result() returned NULL\n");
							// Didn't get any results, so check if we should have got some
							if (0 == mysql_field_count(connection))
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
						IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: Failed to execute select query \"%s\" %d (%s)\n",\
                                                                                        query, mysql_errno(connection), mysql_error(connection) );
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
			IPSCAN_LOG( LOGPREFIX "read_db_result: ERROR: mysql_options() failed - check your my.cnf file\n");
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
	int retval = 0;
	MYSQL *connection;

	//
	// Only need these variables if we're going to report the records
	// to be deleted during tidy_up_db()
	//
	#if (DBDEBUG == 1)
	MYSQL_ROW row;
	int port, res;
	#endif

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
		IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: Failed to initialise MySQL\n");
		retval = 1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		int rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL *mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "tidy_up_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
				#if (DBDEBUG == 1)
				//
				// Select and report old (expired) results - SELECT * FROM t1 WHERE ( createdate <= delete_before_time );
				//
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( createdate <= '%"PRIu64"' )", MYSQL_TBLNAME, delete_before_time);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					IPSCAN_LOG( LOGPREFIX "tidy_up_db: MySQL SELECT query is : %s\n", query);
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						MYSQL_RES * result = mysql_store_result(connection);
						if (0 != result)
						{
							unsigned int num_fields = mysql_num_fields(result);
							uint64_t num_rows = mysql_num_rows(result);
							IPSCAN_LOG( LOGPREFIX "tidy_up_db: about to dump %"PRIu64" rows WHERE ( createdate <= '%"PRIu64"' )", num_rows, delete_before_time);

							int i, rcmsb, rclsb, rcdate, rcsess;
							const char * rchostname;
							uint64_t value, hostmsb, hostlsb, session ;
							time_t createdate;
							char createdateresult[32]; // 26 chars for ctime_r()
							memset(&createdateresult[0],0,32);
							char * cdptr = NULL;
							unsigned char remotehost[sizeof(struct in6_addr)];
							char hostname[INET6_ADDRSTRLEN+1];

							while ((row = mysql_fetch_row(result)))
							{
								if (8 == num_fields) // database includes indirect host field
								{
									// row[0] - id
									rcmsb=sscanf(row[1],"%"SCNu64, &value);
									if (1 == rcmsb) hostmsb = value; else hostmsb = 0ULL;
									rclsb=sscanf(row[2],"%"SCNu64, &value);
									if (1 == rclsb) hostlsb = value; else hostlsb = 0ULL;
									rcdate=sscanf(row[3],"%"SCNu64, &value);
									if (1 == rcdate) createdate = (time_t)value; else createdate = 0;
									cdptr = ctime_r(&createdate, createdateresult);
									if (NULL == cdptr) createdateresult[0]=0;
									rcsess=sscanf(row[4],"%"SCNu64, &value);
									if (1 == rcsess) session = value; else session = 0ULL;

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

									rchostname = inet_ntop(AF_INET6, &remotehost, hostname, INET6_ADDRSTRLEN);
									int rcport = sscanf(row[5], "%d", &port);
									int rcres = sscanf(row[6], "%d", &res);
									char hostind[INET6_ADDRSTRLEN+1];
									int rcindhost = sscanf(row[7], "%"TO_STR(INET6_ADDRSTRLEN)"s", &hostind[0]);

									if ( 1 == rcres && 1 == rcindhost && 1 == rcport && 1 == rcsess && NULL != rchostname)
									{
										int portnum = (port >> IPSCAN_PORT_SHIFT) & IPSCAN_PORT_MASK;
										int proto = (port >> IPSCAN_PROTO_SHIFT) & IPSCAN_PROTO_MASK;
										int special = (port >> IPSCAN_SPECIAL_SHIFT) & IPSCAN_SPECIAL_MASK;
										char protostring[IPSCAN_PROTO_STRING_MAX+1]; 
										char resstring[IPSCAN_RESULT_STRING_MAX+1];
										proto_to_string(proto, &protostring[0]);
										result_to_string(res,&resstring[0]);
										if (IPSCAN_PROTO_TESTSTATE != proto)
										{
											IPSCAN_LOG( LOGPREFIX "tidy_up_db: raw results: host %s, date %"PRIu64" (%s), session %"PRIu64", proto %d (%s), special %d, port %d, result %d (%s), indhost %s\n", hostname, (uint64_t)createdate, createdateresult, session, proto, protostring, special, portnum, res, resstring, hostind);
										}
										else
										{
											char statestring[IPSCAN_FLAGSBUFFER_SIZE+1];
											char * staterc;
											staterc = state_to_string(res, &statestring[0], (int)IPSCAN_FLAGSBUFFER_SIZE );
											if (NULL != staterc)
											{
												IPSCAN_LOG( LOGPREFIX "tidy_up_db: host \"%s\", date \"%s\", TESTSTATE (%s), port %d, result %d\n", hostname, createdateresult, staterc, port, res);
											}
											else
											{
												IPSCAN_LOG( LOGPREFIX "tidy_up_db: host \"%s\", date \"%s\", TESTSTATE, port %d, result %d\n", hostname, createdateresult, port, res);
											}
										}
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "tidy_up_db: Unexpected row scan results - rchost = %d, rcport = %d, rcres = %d, rchost = %d, port = %d\n", rchost, rcport, rcres, rchost, port);
									}
								}
								else // original database approach
								{
									IPSCAN_LOG( LOGPREFIX "tidy_up_db: MySQL returned num_fields : %d\n", num_fields);
									IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR - you NEED to update to the new database format - please see the README for details!\n");
									retval = 5;
								}
							}
							IPSCAN_LOG( LOGPREFIX "tidy_up_db:   end of dump rows WHERE ( createdate <= '%"PRIu64"' )", delete_before_time);
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "tidy_up_db: select ERROR - no result\n");
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: select failed, returned %d (%s).\n", rc, mysql_error(connection) );
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: select query creation returned: %d.\n", qrylen );
				}
				#endif

				//
				// Delete old (expired) results - DELETE FROM t1 WHERE ( createdate <= delete_before_time )
				//
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( createdate <= '%"PRIu64"' )", MYSQL_TBLNAME, delete_before_time);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "tidy_up_db: MySQL DELETE query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
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
							if (0 < affected_rows)
							{
								IPSCAN_LOG( LOGPREFIX "tidy_up_db: Deleted %ld entries from %s database.\n", (long)affected_rows, MYSQL_TBLNAME);
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: Delete failed, \"%s\" returned %d (%s).\n", query, rc, mysql_error(connection) );
						retval = 10;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "tidy_up_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 9;
		}
	}
	return (retval);
}


// ----------------------------------------------------------------------------------------
//
// Function to update the database, creating it first, if required
//
// ----------------------------------------------------------------------------------------

int update_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, int32_t result, const char *indirecthost )
{

	// ID                 BIGINT UNSIGNED
	//
	// HOSTADDRESS MSB    BIGINT UNSIGNED
	//	       LSB    BIGINT UNSIGNED
	//
	// DATE-TIME          BIGINT UNSIGNED
	//
	// SESSIONID          BIGINT UNSIGNED
	//
	// PORT               BIGINT UNSIGNED
	//				  Multiple fields are mapped to this single entry by the calling routines.
	//				  This includes the port, a special case indicator and the protocol.
	//				  See ipscan.h for the field masks and shifts
	//
	// RESULT             BIGINT UNSIGNED
	//
	// INDHOST            VARCHAR(INET6_ADDRSTRLEN+1)

	int retval = -1; // do not change this
	MYSQL *connection;

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "update_db: ERROR: Failed to initialise MySQL\n");
		retval = 1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		int rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP, "ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "update_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection));
				IPSCAN_LOG( LOGPREFIX "update_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// retval defaults to -1, and is set to other values if an error condition occurs
				if (retval < 0)
				{
					char query[MAXDBQUERYSIZE];
					#if (IPSCAN_MYSQL_MEMORY_ENGINE_ENABLE == 1)
					// Use memory engine - ensures sensitive data does not persist if MySQL is stopped/restarted
					int qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, hostmsb BIGINT UNSIGNED DEFAULT 0, hostlsb BIGINT UNSIGNED DEFAULT 0, createdate BIGINT UNSIGNED DEFAULT 0, session BIGINT UNSIGNED DEFAULT 0, portnum BIGINT UNSIGNED DEFAULT 0, portresult BIGINT UNSIGNED DEFAULT 0, indhost VARCHAR(%d) DEFAULT '' ) ENGINE = MEMORY",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
					#else
					// Use the default engine - sensitive data may persist until next tidy_up_db() call
					int qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS %s(id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, hostmsb BIGINT UNSIGNED DEFAULT 0, hostlsb BIGINT UNSIGNED DEFAULT 0, createdate BIGINT UNSIGNED DEFAULT 0, session BIGINT UNSIGNED DEFAULT 0, portnum BIGINT UNSIGNED DEFAULT 0, portresult BIGINT UNSIGNED DEFAULT 0, indhost VARCHAR(%d) DEFAULT '' )",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
					#endif
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						rc = mysql_real_query(connection, query, (unsigned long)qrylen);
						if (0 == rc)
						{
							qrylen = snprintf(query, MAXDBQUERYSIZE, "UPDATE `%s` set `portresult` = %d WHERE ( `hostmsb` = %"PRIu64" AND `hostlsb` = %"PRIu64" AND `createdate` = %"PRIu64" AND `session` = %"PRIu64" AND `portnum` = %u AND `indhost` = '%s' )" , MYSQL_TBLNAME, result, host_msb, host_lsb, timestamp, session, port, indirecthost);
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								#ifdef DBDEBUG
								IPSCAN_LOG( LOGPREFIX "update_db: MySQL Query is : %s\n", query);
								#endif
								rc = mysql_real_query(connection, query, (unsigned long)qrylen);
								if (0 == rc)
								{
									retval = 0;
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "update_db: ERROR: Failed to execute update query \"%s\" %d (%s)\n",\
											query, mysql_errno(connection), mysql_error(connection) );
									retval = 7;
								}
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "update_db: ERROR: Failed to create update query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
								retval = 8;
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "update_db: ERROR: Failed to execute create_table query \"%s\" %d (%s)\n",\
									query, mysql_errno(connection), mysql_error(connection) );
							retval = 6;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "update_db: ERROR: Failed to create create_table query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
						retval = 5;
					}
				} // matches with retval < 0
			} // Matches with main else
		} // MySQL options
		else
		{
			IPSCAN_LOG( LOGPREFIX "update_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 2;
		}
		// Tidy up
		mysql_commit(connection);
		mysql_close(connection);
	}

	if (0 != retval) IPSCAN_LOG( LOGPREFIX "update_db: WARNING - returning with retval = %d\n",retval);
	return (retval);
}
