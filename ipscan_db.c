//    IPscan - an HTTP-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2025 Tim Chappell.
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
// 0.45 - remove unnecessary if statements
// 0.46 - prepend logging to identify ipscan and function
// 0.47 - added count_rows_db()
// 0.48 - additional debug for read_db_result() and dump_db()
// 0.49 - DBDEBUG - report host address directly instead of integer equivalents
// 0.50 - add separate DBPSRDEBUG cases so that port scan results are not reported by default
// 0.51 - support reporting of running state in dump_db()
// 0.52 - tidy_up_db now uses constants to define mode, plus separate TUDBPSRDEBUG
// 0.53 - add session transaction level setting to all functions
// 0.54 - add delete EVERYTHING or RESULTS-ONLY parameter to delete_from_db()
// 0.55 - further database call improvements
// 0.56 - correct indhost column typos
// 0.57 - yet more database call improvements
// 0.58 - CodeQL improvements
// 0.59 - add missing table name quotea for consistency
// 0.60 - add timestamp to database (for reliable tidy_up_db deletions)
// 0.61 - update to simplify tidy_up_db() and delete based on server timestamp entries
// 0.62 - various code quality improvements (scope reductions)
// 0.63 - added missing return codes for update_db and count_rows_db
// 0.64 - added missing return codes for dump_db
// 0.65 - documented return values
// 0.66 - add unique key
// 0.67 - add count_teststate_rows_db()
// 0.68 - introduce 'LOCK TABLES' for INSERTS/DELETES

//
#define IPSCAN_DB_VER "0.68"
//

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
// Limits for integers
#include <limits.h>

// ----------------------------------------------------------------------------------------
//
// Prototype functions from ipscan_general.c
//
void proto_to_string(uint32_t proto, char * retstring);
char * state_to_string(uint32_t statenum, char * retstringptr, int retstringfree);
void result_to_string(uint32_t result, char * retstring);
// ----------------------------------------------------------------------------------------

//
// report version
//
const char* ipscan_db_ver(void)
{
    return IPSCAN_DB_VER;
}

//
// MySQL quoting - where necessary quote table and column names with `` and varchar (strings) with ''
//

// ----------------------------------------------------------------------------------------
//
// Functions to write to the database, creating it first, if required
//
// ----------------------------------------------------------------------------------------

int write_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, uint32_t result, const char *indirecthost )
{

	// 0	ID                 	BIGINT UNSIGNED
	//
	// 1	HOSTMSB    		BIGINT UNSIGNED
	// 2    HOSTLSB    		BIGINT UNSIGNED
	//
	// 3	CREATETIME         	BIGINT UNSIGNED
	//				Client's time - used only as a unique field 
	//
	// 4	SESSION          	BIGINT UNSIGNED
	//
	// 5	PORTNUM            	BIGINT UNSIGNED
	//			  	Multiple fields are mapped to this single entry by the calling routines.
	//			  	This includes the port, a special case indicator and the protocol.
	//			  	See ipscan.h for the field masks and shifts
	//
	// 6	PORTRESULT		BIGINT UNSIGNED
	//
	// 7	INDIRECTHOST		VARCHAR(INET6_ADDRSTRLEN+1)
	//
	// 8	TS		      	TIMESTAMP(6)
	//				Server's time to microsecond resolution
	//				 - automatically added as rows are inserted. Used solely for later auto-deletion.
	//
	// RETURNS 0 - write completed successfully, otherwise non-0
	//

	int retval = -1; // do not change this
	MYSQL *connection;

	int rc = mysql_library_init(0, NULL, NULL);
	if (0 != rc)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to initialise MySQL library\n");
		mysql_library_end();
		return (98);
	}

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to initialise MySQL\n");
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
			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection));
				IPSCAN_LOG( LOGPREFIX "ipscan: write_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// retval defaults to -1, and is set to other values if an error condition occurs
				char query[MAXDBQUERYSIZE];
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
						retval = 101;
					}
				}
				else
				{
					retval = 100;
				}
				// Use the default engine - sensitive data may persist until next tidy_up_db() call
				qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS `%s` (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, hostmsb BIGINT UNSIGNED DEFAULT 0, hostlsb BIGINT UNSIGNED DEFAULT 0, createdate BIGINT UNSIGNED DEFAULT 0, session BIGINT UNSIGNED DEFAULT 0, portnum BIGINT UNSIGNED DEFAULT 0, portresult BIGINT UNSIGNED DEFAULT 0, indirecthost VARCHAR(%d) DEFAULT '', ts TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY `mykey` (hostmsb,hostlsb,createdate,session,portnum) ) ENGINE = Innodb",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						qrylen = snprintf(query, MAXDBQUERYSIZE, "SET AUTOCOMMIT=0");
						if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
						{
							rc = mysql_real_query(connection, query, (unsigned long)qrylen);
							if (0 != rc)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: SET AUTOCOMMIT=0 failed, returned %d\n", rc);
								retval = 191;
							}
						}
						qrylen = snprintf(query, MAXDBQUERYSIZE, "LOCK TABLES `%s` WRITE", MYSQL_TBLNAME);
						if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
						{
							rc = mysql_real_query(connection, query, (unsigned long)qrylen);
							if (0 != rc)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: LOCK TABLES failed, returned %d\n", rc);
								retval = 192;
							}
						}
						// SET AUTOCOMMIT=0;LOCK TABLES `%s` WRITE; INSERT .... ; COMMIT; UNLOCK TABLES
						qrylen = snprintf(query, MAXDBQUERYSIZE, "INSERT INTO `%s` (hostmsb, hostlsb, createdate, session, portnum, portresult, indirecthost) VALUES ( %"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64", %u, %u, '%s' )", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port, result, indirecthost);
						if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
						{
							#ifdef DBDEBUG
							uint32_t proto = (port >> IPSCAN_PROTO_SHIFT) & IPSCAN_PROTO_MASK;
                                                        if (IPSCAN_PROTO_TESTSTATE == proto)
							{
								char statestring[IPSCAN_FLAGSBUFFER_SIZE+1];
								char * staterc;
								staterc = state_to_string(result, &statestring[0], (int)IPSCAN_FLAGSBUFFER_SIZE);
								if (NULL != staterc)
								{

									IPSCAN_LOG( LOGPREFIX "ipscan: write_db: INSERT INTO `%s` (host = %x:%x:%x:%x:%x:%x:%x:%x, createdate = %"PRIu64", session = %"PRIu64", portnum = %u, TESTSTATE = %u (%s), indirecthost = '%s')\n",\
										MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF),\
										 (unsigned int)(host_msb & 0xFFFF), (unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF),\
										 (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session, port, result, staterc, indirecthost); 
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: write_db: INSERT INTO `%s` (host = %x:%x:%x:%x:%x:%x:%x:%x, createdate = %"PRIu64", session = %"PRIu64", portnum = %u, TESTSTATE = %u, indirecthost = '%s')\n",\
									 	MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF),\
										 (unsigned int)(host_msb & 0xFFFF), (unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF),\
										 (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session, port, result, indirecthost); 
								}
							}
							else
							{
								#if (DBPSRDEBUG == 1)
								uint32_t realport = (port >> IPSCAN_PORT_SHIFT) & IPSCAN_PORT_MASK;
								uint32_t special = (port >> IPSCAN_SPECIAL_SHIFT) & IPSCAN_SPECIAL_MASK;
								char protostring[IPSCAN_PROTO_STRING_MAX+1];
								proto_to_string(proto, protostring);
								char resultstring[IPSCAN_RESULT_STRING_MAX+1];
								result_to_string(result, resultstring);
								if (0 != special)
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: write_db: INSERT INTO `%s` (host = %x:%x:%x:%x:%x:%x:%x:%x, createdate = %"PRIu64", session = %"PRIu64" proto = %u(%s), port = %u:%u, result = %u(%s), indirecthost = \"%s\")\n",\
									 MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF),\
									 (unsigned int)(host_msb & 0xFFFF), (unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF), (unsigned int)((host_lsb>>16)&0xFFFF),\
									 (unsigned int)(host_lsb & 0xFFFF), timestamp, session, proto, protostring, realport, special, result, resultstring, indirecthost); 
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: write_db: INSERT INTO `%s` (host = %x:%x:%x:%x:%x:%x:%x:%x, createdate = %"PRIu64", session = %"PRIu64" proto = %d(%s), port = %d, result = %d(%s), indirecthost = \"%s\")\n",\
									 MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF),\
									 (unsigned int)(host_msb & 0xFFFF), (unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF),\
									 (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF),\
									 timestamp, session, proto, protostring, realport, result, resultstring, indirecthost);
								}
								#endif
							}
							#endif
							rc = mysql_real_query(connection, query, (unsigned long)qrylen);
							if (0 == rc)
							{
								retval = 0;
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to execute insert query \"%s\" %d (%s)\n",\
										query, mysql_errno(connection), mysql_error(connection) );
								retval = 7;
							}
							qrylen = snprintf(query, MAXDBQUERYSIZE, "COMMIT");
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								rc = mysql_real_query(connection, query, (unsigned long)qrylen);
								if (0 != rc)
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: COMMIT failed, returned %d\n", rc);
									retval = 193;
								}
							}
							qrylen = snprintf(query, MAXDBQUERYSIZE, "UNLOCK TABLES");
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								rc = mysql_real_query(connection, query, (unsigned long)qrylen);
								if (0 != rc)
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: UNLOCK TABLES failed, returned %d\n", rc);
									retval = 194;
								}
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to create insert query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
							retval = 8;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to execute create_table query \"%s\" %d (%s)\n",\
								query, mysql_errno(connection), mysql_error(connection) );
						retval = 6;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: Failed to create create_table query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
					retval = 5;
				}
			} // Matches with main else
		} // MySQL options
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 2;
		}
		// Tidy up
		mysql_commit(connection);
		mysql_close(connection);
	}
	// finalise the MySQL library - frees resources
	mysql_library_end();

	if (0 != retval) IPSCAN_LOG( LOGPREFIX "ipscan: write_db: ERROR: returning with non-zero retval = %d\n",retval);
	return (retval);
}


// ----------------------------------------------------------------------------------------
//
// Function to dump the database
//
// ----------------------------------------------------------------------------------------

int dump_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
{
	//
	// RETURNS 0 - dump completed successfully, otherwise non-0
	//

	int retval = 0;
	uint32_t port, res;
	MYSQL *connection;
	MYSQL_ROW row;

	int rc = mysql_library_init(0, NULL, NULL);
        if (0 != rc)
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (99);
        }

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: Failed to initialise MySQL\n");
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

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
                                int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
						retval = 98;
                                        }
                                }
				// uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session
				// SELECT x FROM t1 WHERE a = b ORDER BY x;
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = %"PRIu64" AND hostlsb = %"PRIu64" AND createdate = %"PRIu64" AND session = %"PRIu64") ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
                                	IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: SELECT * FROM `%s` WHERE ( host = %x:%x:%x:%x:%x:%x:%x:%x AND createdate = %"PRIu64" AND session = %"PRIu64") ORDER BY id\n",\
						 MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF), (unsigned int)(host_msb & 0xFFFF),\
                                                (unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF), (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session);
                                	#endif

					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						MYSQL_RES * result = mysql_store_result(connection);
						if (result)
						{
							unsigned int num_fields = mysql_num_fields(result);
							#ifdef RESULTSDEBUG
							#if (IPSCAN_LOGVERBOSITY >= 1)
							unsigned int nump = 0;
							#endif
							#endif

							uint64_t num_rows = mysql_num_rows(result);
							if (0 == num_rows)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: INFO: 0 rows returned, num_fields = %d, query = \"%s\"\n", num_fields, query);
							}

							
							// Start of json array
							int dumped_running_state = 0;
							printf("[ ");

							while ((row = mysql_fetch_row(result)))
							{
								if (9 == num_fields) // database includes indirect host and timestamp fields
								{
									char hostind[INET6_ADDRSTRLEN+1];
									int rcport = sscanf(row[5], "%u", &port);
									int rcres = sscanf(row[6], "%u", &res);
									int rchost = sscanf(row[7], "%"TO_STR(INET6_ADDRSTRLEN)"s", &hostind[0]);
									if ( 1 == rcres && 1 == rchost && 1 == rcport )
									{
										uint32_t proto = (port >> IPSCAN_PROTO_SHIFT) & IPSCAN_PROTO_MASK;
										// Report everything to the client apart from the test-state
										if (IPSCAN_PROTO_TESTSTATE != proto)
										{
											// results returned to browser ...
											printf("%u, %u, \"%s\", ", port, res, hostind);
											// results returned to log ...
											#if (DBPSRDEBUG == 1)
											uint32_t realport = (port >> IPSCAN_PORT_SHIFT) & IPSCAN_PORT_MASK;
											uint32_t special = (port >> IPSCAN_SPECIAL_SHIFT) & IPSCAN_SPECIAL_MASK;
											char protostring[IPSCAN_PROTO_STRING_MAX+1];
											proto_to_string(proto, protostring);
											char resstring[IPSCAN_RESULT_STRING_MAX+1];
											result_to_string(res, resstring);
											if (0 != special)
											{
												IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: raw results: proto %d(%s), port %d:%d, result %d (%s), host \"%s\"\n", proto, protostring, realport, special, res, resstring, hostind);
											}
											else
											{
												IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: raw results: proto %d(%s), port %d, result %d (%s), host \"%s\"\n", proto, protostring, realport, res, resstring, hostind);
											}
											#endif
											#ifdef RESULTSDEBUG
											#if (IPSCAN_LOGVERBOSITY >= 1)
											nump += 1;
											#endif
											#endif
										}
										else
										{
											// results returned to browser ...
											printf("%u, %u, \"%s\", ", port, res, hostind);
											dumped_running_state = 1;
											// results returned to log ...
											#if (DBPSRDEBUG == 1)
											char statestring[IPSCAN_FLAGSBUFFER_SIZE+1];
                                                                                        char * staterc;
                                                                                        staterc = state_to_string(res, &statestring[0], (int)IPSCAN_FLAGSBUFFER_SIZE);
											if (NULL != staterc)
                                                                                        {
												IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: raw results: TESTSTATE, port %d, result %d (%s)\n", port, res, staterc);
											}
											else
											{
												IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: raw results: TESTSTATE, port %d, result %d\n", port, res);
											}
											#endif
										}
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "ipscan: ERROR: dump_db: Unexpected row scan results - rcport = %d, rcres = %d, rchost = %d\n", rcport, rcres, rchost);
										retval = 97;
									}
								}
								else // original approach
								{
									printf("%s, ", row[num_fields-1]);
									IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: MySQL returned num_fields : %d expecting 9\n", num_fields);
									IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR - you NEED to update to the new database format - please see the README for details!\n");
									#ifdef RESULTSDEBUG
									#if (IPSCAN_LOGVERBOSITY >= 1)
									nump += 1;
									#endif
									#endif
								}
							}

							if (0 == dumped_running_state)
							{
								// default  - in case TESTSTATE was missing from database
								port = (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT));
								res =  (uint32_t)(IPSCAN_TESTSTATE_DATABASE_ERROR_BIT);
								printf("%u, %u, \"%s\", ", port, res, "::1");
								IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: TESTSTATE missing, so reported IPSCAN_TESTSTATE_DATABASE_ERROR_BIT to client.\n");
								dumped_running_state = 1;
								retval = 96;
							}
							// End of json array
							printf(" -9999, -9999, \"::1\" ]\n");

							mysql_free_result(result);
							#ifdef RESULTSDEBUG
							#if (IPSCAN_LOGVERBOSITY >= 1)
							IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: reported %d actual results to the client.\n", nump);
							#endif
							#endif
						}
						else
						{
							// Didn't get any results, so check if we should have got some
							if (0 == mysql_field_count(connection))
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: surprisingly mysql_field_count() expected to return 0 fields\n");
								retval = 95;
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: mysql_store_result() error : %s\n", mysql_error(connection));
								retval = 10;
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: Failed to execute select query \"%s\" %d (%s)\n",\
                                                                                        query, mysql_errno(connection), mysql_error(connection) );
						retval = 5;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 9;
		}
	}
	mysql_library_end();
	if (0 != retval) IPSCAN_LOG( LOGPREFIX "ipscan: dump_db: INFO: returning with retval = %d\n",retval);
	return (retval);
}
// ----------------------------------------------------------------------------------------
//
// Functions to delete selected result from the database
//
// ----------------------------------------------------------------------------------------
int delete_from_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, int8_t deleteall)
{
	//
	// RETURNS 0 - delete_from_db() completed successfully, otherwise non-0
	//

	if ( IPSCAN_DELETE_MINIMUM_TIME >= timestamp)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: timestamp (%"PRIu64") <= IPSCAN_DELETE_MINIMUM_TIME (%d)\n", timestamp, IPSCAN_DELETE_MINIMUM_TIME);
		return (99);
	}

	int rc = mysql_library_init(0, NULL, NULL);
        if (0 != rc)
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (98);
        }
	int retval = 0;
	MYSQL *connection;

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: Failed to initialise MySQL\n");
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

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET AUTOCOMMIT=0");
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: SET AUTOCOMMIT=0 failed, returned %d\n", rc);
						retval = 391;
					}
				}
				qrylen = snprintf(query, MAXDBQUERYSIZE, "LOCK TABLES `%s` WRITE", MYSQL_TBLNAME);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: LOCK TABLES failed, returned %d\n", rc);
						retval = 392;
					}
				}
				// SET AUTOCOMMIT=0;LOCK TABLES `%s` WRITE; INSERT .... ; COMMIT; UNLOCK TABLES
                                qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
                                        }
                                }
				// DELETE FROM t1 WHERE ( a = b ) ORDER BY id;
				if (IPSCAN_DELETE_EVERYTHING == deleteall)
				{
					// delete everything for this test
					qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( hostmsb = %"PRIu64" AND hostlsb = %"PRIu64" AND createdate = %"PRIu64" AND session = %"PRIu64") ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);
				}
				else
				{
					// delete everything for this test except the test state
					qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( hostmsb = %"PRIu64" AND hostlsb = %"PRIu64" AND createdate = %"PRIu64" AND session = %"PRIu64" AND portnum <> %u) ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)) );
				}
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					if (IPSCAN_DELETE_EVERYTHING == deleteall)
					{
					IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: DELETE FROM `%s` WHERE ( host = %x:%x:%x:%x:%x:%x:%x:%x AND createdate = %"PRIu64" AND session = %"PRIu64") ORDER BY id\n",\
						 MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF), (unsigned int)(host_msb & 0xFFFF),\
						(unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF), (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session);
					}
					else
					{
					IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: DELETE FROM `%s` WHERE ( host = %x:%x:%x:%x:%x:%x:%x:%x AND createdate = %"PRIu64" AND session = %"PRIu64" AND portnum <> %d) ORDER BY id\n",\
						 MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF), (unsigned int)(host_msb & 0xFFFF),\
						(unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF), (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session, (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)) );
					}
					#endif
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						my_ulonglong affected_rows = mysql_affected_rows(connection);
						if ( ((my_ulonglong)-1) == affected_rows)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: surprisingly delete returned successfully, but mysql_affected_rows() did not.\n");
							retval = 11;
						}
						else
						{
							#ifdef CLIENTDEBUG
							IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: Deleted %ld rows for protected client address (/48): %x:%x:%x:: createdate %"PRIu64", session %"PRIu64" from %s.\n",\
									(long)affected_rows, (unsigned int)((host_msb>>48)&0xFFFF),\
									(unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF), timestamp, session, MYSQL_TBLNAME);
							#endif
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: Delete failed, returned %d (%s).\n", rc, mysql_error(connection) );
						retval = 10;
					}
					qrylen = snprintf(query, MAXDBQUERYSIZE, "COMMIT");
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						rc = mysql_real_query(connection, query, (unsigned long)qrylen);
						if (0 != rc)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: COMMIT failed, returned %d\n", rc);
							retval = 393;
						}
					}
					qrylen = snprintf(query, MAXDBQUERYSIZE, "UNLOCK TABLES");
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						rc = mysql_real_query(connection, query, (unsigned long)qrylen);
						if (0 != rc)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: UNLOCK TABLES failed, returned %d\n", rc);
							retval = 394;
						}
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 9;
		}
	}
	mysql_library_end();
	if (0 != retval) IPSCAN_LOG( LOGPREFIX "ipscan: delete_from_db: INFO: returning with retval = %d\n",retval);
	return (retval);
}


//
// Fetch a single result
//

int read_db_result(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port)
{

	//
	// RETURNS <0 			- error condition
	//         0 =< x <= INT_MAX 	- portresult value from database
	//

	uint64_t dbres;
	int retres = -1;
	MYSQL *connection;
	MYSQL_ROW row;

	int rc = mysql_library_init(0, NULL, NULL);
	if (0 != rc) 
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (-98);
        }

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Failed to initialise MySQL\n");
		retres = -2;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retres = -3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
                                int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
                                        }
                                }
				// SELECT x FROM t1 WHERE ( a = b ) ORDER BY x DESC;
				// uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = %"PRIu64" AND hostlsb = %"PRIu64" AND createdate = %"PRIu64" AND session = %"PRIu64" AND portnum = %u) ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session, port);
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
								IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: 0 rows returned, num_fields = %d, query = \"%s\"\n", num_fields, query);
								IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: protected client address (/48): %x:%x:%x:: session = %"PRIu64" timestamp = %"PRIu64" port = %d\n",\
                                      					(unsigned int)((host_msb>>48) & 0xFFFF), (unsigned int)((host_msb>>32) & 0xFFFF),\
                                    					(unsigned int)((host_msb>>16) & 0xFFFF), session, timestamp, port);
							}
							while ((row = mysql_fetch_row(result)))
							{
								if (9 == num_fields) // database includes indirect host and timestamp fields
								{
									// 6	PORTRESULT	BIGINT UNSIGNED
									int rcres = sscanf(row[6], "%"SCNu64, &dbres);
									if (1 == rcres)
									{
										// Set the return result
										if ( INT_MAX >= dbres )
										{
											retres = (int)dbres;
										}
										else
										{
											IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: database returned portresult out of range: %"PRIu64"\n", dbres);
											retres = -4;
										}
										#ifdef DBDEBUG
										uint32_t proto = (port >> IPSCAN_PROTO_SHIFT) & IPSCAN_PROTO_MASK;
                                                                                // report result as TESTSTATE
                                                                                if (IPSCAN_PROTO_TESTSTATE == proto && 0 <= retres)
										{
											char statestring[IPSCAN_FLAGSBUFFER_SIZE+1];
                                                                                        char * staterc;
                                                                                        staterc = state_to_string(retres, &statestring[0], (int)IPSCAN_FLAGSBUFFER_SIZE);
                                                                                        if (NULL != staterc)
                                                                                        {
												IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: INFO: protected client address (/48): %x:%x:%x:: timestamp %"PRIu64" session %"PRIu64" TESTSTATE returned %d (%s)\n",\
                                      						  			(unsigned int)((host_msb>>48) & 0xFFFF), (unsigned int)((host_msb>>32) & 0xFFFF),\
                                    						  			(unsigned int)((host_msb>>16) & 0xFFFF), timestamp, session, retres, staterc);
                                                                                        }
                                                                                        else
                                                                                        {
												IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: INFO: protected client address (/48): %x:%x:%x:: timestamp %"PRIu64" session %"PRIu64" TESTSTATE returned %d\n",\
                                      						  			(unsigned int)((host_msb>>48) & 0xFFFF), (unsigned int)((host_msb>>32) & 0xFFFF),\
                                    						  			(unsigned int)((host_msb>>16) & 0xFFFF), timestamp, session, retres);
                                                                                        }
										}
										else if (IPSCAN_PROTO_TESTSTATE != proto && 0 <= retres)
										{
											#if (DBPSRDEBUG == 1)
											uint32_t realport = (port >> IPSCAN_PORT_SHIFT) & IPSCAN_PORT_MASK;
											uint32_t special = (port >> IPSCAN_SPECIAL_SHIFT) & IPSCAN_SPECIAL_MASK;
                                                                                	// report result as port scan result
											char protostring[IPSCAN_PROTO_STRING_MAX+1];
											proto_to_string(proto, protostring);
											char resstring[IPSCAN_RESULT_STRING_MAX+1];
											result_to_string(retres, resstring);
											if (0 != special)
											{
												IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: INFO: protected client address (/48): %x:%x:%x:: timestamp %"PRIu64" session %"PRIu64" proto %d(%s), port %d:%d returned %d(%s)\n",\
                                      						  			(unsigned int)((host_msb>>48) & 0xFFFF), (unsigned int)((host_msb>>32) & 0xFFFF),\
                                    						  			(unsigned int)((host_msb>>16) & 0xFFFF), timestamp, session, proto, protostring, realport, special, retres, resstring);
											}
											else
											{
												IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: INFO: protected client address (/48): %x:%x:%x:: timestamp %"PRIu64" session %"PRIu64" proto %d(%s), port %d returned %d(%s)\n",\
                                      						  			(unsigned int)((host_msb>>48) & 0xFFFF), (unsigned int)((host_msb>>32) & 0xFFFF),\
                                    						  			(unsigned int)((host_msb>>16) & 0xFFFF), timestamp, session, proto, protostring, realport, retres, resstring);
											}
											#endif
										}
										else
										{
												IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: retres less than 0: %d\n", retres);
										}
										#endif
									}
									else
									{
										IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Unexpected row scan results - sscanf() = %d\n", rcres);
										retres = -20;
									}
								}
								else
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Unexpected num_fields results - num_fields() = %d, not 9\n", num_fields);
									retres = -21;
								}
							}
							mysql_free_result(result);
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: surprisingly mysql_store_result() returned NULL\n");
							// Didn't get any results, so check if we should have got some
							if (0 == mysql_field_count(connection))
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: surprisingly mysql_field_count() expected to return 0 fields\n");
								retres = -5;
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: mysql_store_result() error : %s\n", mysql_error(connection));
								retres = -6;
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Failed to execute select query \"%s\" %d (%s)\n",\
                                                                                        query, mysql_errno(connection), mysql_error(connection) );
						retres = -7;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: Failed to create select query\n");
					retres = -8;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: ERROR: mysql_options() failed - check your my.cnf file\n");
			retres = -9;
		}
	}
	mysql_library_end();
	if (0 > retres) IPSCAN_LOG( LOGPREFIX "ipscan: read_db_result: INFO: returning with retres = %d\n",retres);
	return (retres);
}

// ----------------------------------------------------------------------------------------
//
// Function to tidy up old results from the database
//
// ----------------------------------------------------------------------------------------
int tidy_up_db(int8_t deleteall)
{
	//
	// RETURNS <>0		- error condition
	//           0		- tidy_up_db() completed successfully
	//

	int retval = 0;
	MYSQL *connection;

	int rc = mysql_library_init(0, NULL, NULL);
        if (0 != rc)
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (98);
        }

	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: Failed to initialise MySQL\n");
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

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
				int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET AUTOCOMMIT=0");
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: SET AUTOCOMMIT=0 failed, returned %d\n", rc);
						retval = 491;
					}
				}
				qrylen = snprintf(query, MAXDBQUERYSIZE, "LOCK TABLES `%s` WRITE", MYSQL_TBLNAME);
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 != rc)
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: LOCK TABLES failed, returned %d\n", rc);
						retval = 492;
					}
				}
				// SET AUTOCOMMIT=0;LOCK TABLES `%s` WRITE; INSERT .... ; COMMIT; UNLOCK TABLES
                                qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
                                        }
                                }

				//
				// Delete old (expired) results - DELETE FROM t1 WHERE ( ts <= NOW() - INTERVAL xx ) ORDER BY id
				//
				if (IPSCAN_DELETE_EVERYTHING == deleteall)
				{
					// delete based on time only
					qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( ts <= NOW() - INTERVAL %u SECOND ) ORDER BY id",\
						 MYSQL_TBLNAME, (uint32_t)IPSCAN_DELETE_EVERYTHING_LONG_OFFSET );
				}
				else
				{
					// delete based on time and row is not test state
					qrylen = snprintf(query, MAXDBQUERYSIZE, "DELETE FROM `%s` WHERE ( portnum <> %u AND ts <= NOW() - INTERVAL %u SECOND ) ORDER BY id",\
						 MYSQL_TBLNAME, (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)), (uint32_t)IPSCAN_DELETE_RESULTS_SHORT_OFFSET );
				}
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#if (DBDEBUG > 1)
					IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: MySQL DELETE query is : %s\n", query);
					#endif
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						my_ulonglong affected_rows = mysql_affected_rows(connection);
						if ( ((my_ulonglong)-1) == affected_rows)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: surprisingly delete returned successfully, but mysql_affected_rows() did not.\n");
							retval = 11;
						}
						else
						{
							if (0 < affected_rows)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: Deleted %ld entries from %s database.\n", (long)affected_rows, MYSQL_TBLNAME);
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: Delete failed, \"%s\" returned %d (%s).\n", query, rc, mysql_error(connection) );
						retval = 10;
					}
					qrylen = snprintf(query, MAXDBQUERYSIZE, "COMMIT");
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						rc = mysql_real_query(connection, query, (unsigned long)qrylen);
						if (0 != rc)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: COMMIT failed, returned %d\n", rc);
							retval = 493;
						}
					}
					qrylen = snprintf(query, MAXDBQUERYSIZE, "UNLOCK TABLES");
					if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
					{
						rc = mysql_real_query(connection, query, (unsigned long)qrylen);
						if (0 != rc)
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: UNLOCK TABLES failed, returned %d\n", rc);
							retval = 494;
						}
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: Failed to create select query\n");
					retval = 4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 9;
		}
	}
	mysql_library_end();
	if (0 != retval) IPSCAN_LOG( LOGPREFIX "ipscan: tidy_up_db: INFO: returning with retval = %d\n",retval);
	return (retval);
}


// ----------------------------------------------------------------------------------------
//
// Function to update the database, creating it first, if required
//
// ----------------------------------------------------------------------------------------

int update_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session, uint32_t port, uint32_t result, const char *indirecthost )
{

	// ID                 BIGINT UNSIGNED
	//
	// HOSTADDRESS MSB    BIGINT UNSIGNED
	//	       LSB    BIGINT UNSIGNED
	//
	// DATE-TIME          BIGINT UNSIGNED
	//			Client's idea of time - can't rely on this - just use as an uniqifier
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
	//
	// TS		      TIMESTAMP
	//			Server's idea of time - can rely on this	
	//

	//
	// RETURNS   0		- update_db() completed successfully
	//         <>0		- update_db() completed unsuccessfully
	//

	int retval = -1; // do not change this
	MYSQL *connection;

	int rc = mysql_library_init(0, NULL, NULL);
        if (0 != rc)
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (98);
        }
	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to initialise MySQL\n");
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
			// allow multiple statements so we can use START TRANSACTION ; ...; COMMIT
			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection));
				IPSCAN_LOG( LOGPREFIX "ipscan: update_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = 3;
			}
			else
			{
				// retval defaults to -1, and is set to other values if an error condition occurs
				char query[MAXDBQUERYSIZE];
                                int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
                                        }
                                }
				// Use the default engine - sensitive data may persist until next tidy_up_db() call
				qrylen = snprintf(query, MAXDBQUERYSIZE, "CREATE TABLE IF NOT EXISTS `%s` (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, hostmsb BIGINT UNSIGNED DEFAULT 0, hostlsb BIGINT UNSIGNED DEFAULT 0, createdate BIGINT UNSIGNED DEFAULT 0, session BIGINT UNSIGNED DEFAULT 0, portnum BIGINT UNSIGNED DEFAULT 0, portresult BIGINT UNSIGNED DEFAULT 0, indirecthost VARCHAR(%d) DEFAULT '', ts TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY `mykey` (hostmsb,hostlsb,createdate,session,portnum) ) ENGINE = Innodb",MYSQL_TBLNAME, (INET6_ADDRSTRLEN+1) );
				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						qrylen = snprintf(query, MAXDBQUERYSIZE, "SET AUTOCOMMIT=0");
						if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
						{
							rc = mysql_real_query(connection, query, (unsigned long)qrylen);
							if (0 != rc)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: SET AUTOCOMMIT=0 failed, returned %d\n", rc);
								retval = 201;
							}
						}
						qrylen = snprintf(query, MAXDBQUERYSIZE, "LOCK TABLES `%s` WRITE", MYSQL_TBLNAME);
						if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
						{
							rc = mysql_real_query(connection, query, (unsigned long)qrylen);
							if (0 != rc)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: LOCK TABLES failed, returned %d\n", rc);
								retval = 202;
							}
						}
						// SET AUTOCOMMIT=0;LOCK TABLES `%s` WRITE; INSERT .... ; COMMIT; UNLOCK TABLES
						qrylen = snprintf(query, MAXDBQUERYSIZE, "START TRANSACTION READ WRITE;UPDATE `%s` SET portresult = %u WHERE (hostmsb = %"PRIu64" AND hostlsb = %"PRIu64" AND createdate = %"PRIu64" AND session = %"PRIu64" AND portnum = %u AND indirecthost = '%s');COMMIT" , MYSQL_TBLNAME, result, host_msb, host_lsb, timestamp, session, port, indirecthost);
						if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
						{
							#ifdef DBDEBUG
							IPSCAN_LOG( LOGPREFIX "ipscan: update_db: START TRANSACTION READ WRITE ; UPDATE `%s` SET portresult = %u WHERE ( host = %x:%x:%x:%x:%x:%x:%x:%x AND createdate = %"PRIu64" AND session = %"PRIu64" AND portnum = %u AND indirecthost = '%s'); COMMIT\n",\
								MYSQL_TBLNAME, result, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF),\
								(unsigned int)(host_msb & 0xFFFF), (unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF),\
								(unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session, port, indirecthost);
							#endif
							rc = mysql_real_query(connection, query, (unsigned long)qrylen);
							if (0 == rc)
							{
								// process each result separately
								do 
								{
									// fetch result set
									MYSQL_RES * dbresult = mysql_store_result(connection);
									if (dbresult)
									{
										#if (DBDEBUG > 1)
										//Count the rows and report
										uint64_t num_rows = mysql_num_rows(dbresult);
										IPSCAN_LOG( LOGPREFIX "ipscan: update_db: Found %"PRIu64" rows in the result set\n", num_rows );
										unsigned int num_fields = mysql_num_fields(dbresult);
										MYSQL_ROW dbrow;
										while ((dbrow = mysql_fetch_row(dbresult)))
										{
											unsigned long *lengths;
											lengths = mysql_fetch_lengths(dbresult);
											for (unsigned int i = 0; i < num_fields; i++)
											{
												IPSCAN_LOG( LOGPREFIX "ipscan: update_db: row [%.*s]\n", (int)lengths[i], dbrow[i] ? dbrow[i] : "NULL" );
											}
										}
										#endif
								  		mysql_free_result(dbresult);
								  	}
								  	else
								  	{
										// no result set, or an error occurred
								 		if (mysql_field_count(connection) == 0)
								 		{
											#if (DBDEBUG > 1)
											IPSCAN_LOG( LOGPREFIX "ipscan: update_db: Found %lld rows affected\n", mysql_affected_rows(connection));
											#endif
										}
										else
										{
											IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR retrieving result\n");
											retval = 999;
											break;
										}
									}
									// more results to process?
									// >0 error, -1 = no, 0 = yes (another loop)
									if ((rc = mysql_next_result(connection)) > 0)
									{
										IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR could not execute statement in multi-statement update\n");
									}
								} while (rc == 0);
								retval = 0;
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to execute update query \"%s\" %d (%s)\n",\
										query, mysql_errno(connection), mysql_error(connection) );
								retval = 7;
							}
							qrylen = snprintf(query, MAXDBQUERYSIZE, "COMMIT");
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								rc = mysql_real_query(connection, query, (unsigned long)qrylen);
								if (0 != rc)
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: COMMIT failed, returned %d\n", rc);
									retval = 203;
								}
							}
							qrylen = snprintf(query, MAXDBQUERYSIZE, "UNLOCK TABLES");
							if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
							{
								rc = mysql_real_query(connection, query, (unsigned long)qrylen);
								if (0 != rc)
								{
									IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: UNLOCK TABLES failed, returned %d\n", rc);
									retval = 204;
								}
							}
						}
						else
						{
							IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to create update query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
							retval = 8;
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to execute create_table query \"%s\" %d (%s)\n",\
								query, mysql_errno(connection), mysql_error(connection) );
						retval = 6;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: Failed to create create_table query, length returned was %d, max was %d\n", qrylen, MAXDBQUERYSIZE);
					retval = 5;
				}
			} // Matches with main else
		} // MySQL options
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: update_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = 2;
		}
		// Tidy up
		mysql_commit(connection);
		mysql_close(connection);
	}
	mysql_library_end();

	if (0 != retval) IPSCAN_LOG( LOGPREFIX "ipscan: update_db: INFO: returning with retval = %d\n",retval);
	return (retval);
}

// ----------------------------------------------------------------------------------------
//
// Function to count the number of valid rows for given test set
//
// ----------------------------------------------------------------------------------------

int count_rows_db(uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session)
{
	//
	// RETURNS < 0  - count_rows_db() completed unsuccessfully
	//         >=0 - number of rows present in database
	//

	int retval = 0;
	MYSQL *connection;

	int rc = mysql_library_init(0, NULL, NULL);
        if (0 != rc)
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (-98);
        }
	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: Failed to initialise MySQL\n");
		retval = -1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = -3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
                                int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
                                        }
                                }
				// uint64_t host_msb, uint64_t host_lsb, uint64_t timestamp, uint64_t session
				// SELECT x FROM t1 WHERE a = b ORDER BY x;
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE ( hostmsb = %"PRIu64" AND hostlsb = %"PRIu64" AND createdate = %"PRIu64" AND session = %"PRIu64") ORDER BY id", MYSQL_TBLNAME, host_msb, host_lsb, timestamp, session);

				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					#ifdef DBDEBUG
					IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: SELECT * FROM `%s` WHERE ( host = %x:%x:%x:%x:%x:%x:%x:%x AND createdate = %"PRIu64" AND session = %"PRIu64") ORDER BY id\n",\
						 MYSQL_TBLNAME, (unsigned int)((host_msb>>48)&0xFFFF), (unsigned int)((host_msb>>32)&0xFFFF), (unsigned int)((host_msb>>16)&0xFFFF), (unsigned int)(host_msb & 0xFFFF),\
						(unsigned int)((host_lsb>>48)&0xFFFF), (unsigned int)((host_lsb>>32)&0xFFFF), (unsigned int)((host_lsb>>16)&0xFFFF), (unsigned int)(host_lsb & 0xFFFF), timestamp, session);
					#endif
					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						MYSQL_RES * result = mysql_store_result(connection);
						if (result)
						{
							uint64_t num_rows = mysql_num_rows(result);
							if (IPSCAN_DB_MAX_EXPECTED_ROWS < num_rows)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: more than expected (%d) number of rows returned: %"PRIu64".\n", \
									IPSCAN_DB_MAX_EXPECTED_ROWS, num_rows);
								retval = -11;
							}
							else
							{
								retval = (int)num_rows;
							}
							mysql_free_result(result);
						}
						else
						{
							// Didn't get any results, so check if we should have got some
							if (0 == mysql_field_count(connection))
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: surprisingly mysql_field_count() expected to return 0 fields\n");
								retval = -12;
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: mysql_store_result() error : %s\n", mysql_error(connection));
								retval = -10;
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: Failed to execute select query \"%s\" %d (%s)\n",\
                                                                                        query, mysql_errno(connection), mysql_error(connection) );
						retval = -5;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: Failed to create select query\n");
					retval = -4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = -9;
		}
	}
	mysql_library_end();
	if (0 > retval) IPSCAN_LOG( LOGPREFIX "ipscan: count_rows_db: INFO: returning with retval = %d\n",retval);
	return (retval);
}

// ----------------------------------------------------------------------------------------
//
// Function to count the number of teststate rows for a given timestamp and session
//
// ----------------------------------------------------------------------------------------

int count_teststate_rows_db(uint64_t timestamp, uint64_t session)
{
	//
	// RETURNS < 0  - count_teststate_rows_db() completed unsuccessfully
	//         >=0 - number of rows present in database
	//

	int retval = 0;
	MYSQL *connection;

	int rc = mysql_library_init(0, NULL, NULL);
        if (0 != rc)
        {
                IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: Failed to initialise MySQL library\n");
                mysql_library_end();
                return (-98);
        }
	connection = mysql_init(NULL);
	if (NULL == connection)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: Failed to initialise MySQL\n");
		retval = -1;
	}
	else
	{
		// By using mysql_options() the MySQL library reads the [client] and [ipscan] sections
		// in the my.cnf file which ensures that your program works, even if someone has set
		// up MySQL in some nonstandard way.
		rc = mysql_options(connection, MYSQL_READ_DEFAULT_GROUP,"ipscan");
		if (0 == rc)
		{

			MYSQL * mysqlrc = mysql_real_connect(connection, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, MYSQL_DBNAME, 0, NULL, 0);
			if (NULL == mysqlrc)
			{
				IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: Failed to connect to MySQL database (%s) : %s\n", MYSQL_DBNAME, mysql_error(connection) );
				IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: HOST %s, USER %s, PASSWD %s\n", MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD);
				retval = -3;
			}
			else
			{
				char query[MAXDBQUERYSIZE];
                                int qrylen = snprintf(query, MAXDBQUERYSIZE, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                                if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
                                {
                                        rc = mysql_real_query(connection, query, (unsigned long)qrylen);
                                        if (0 != rc)
                                        {
                                                IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: SET SESSION TRANSACTION ISOLATION LEVEL failed, returned %d\n", rc);
                                        }
                                }
				// uint64_t timestamp, uint64_t session
				// SELECT x FROM t1 WHERE a = b ORDER BY x;
				qrylen = snprintf(query, MAXDBQUERYSIZE, "SELECT * FROM `%s` WHERE (createdate = %"PRIu64" AND session = %"PRIu64" AND portnum = %u) ORDER BY id", MYSQL_TBLNAME, timestamp, session, (uint32_t)(0 + (IPSCAN_PROTO_TESTSTATE << IPSCAN_PROTO_SHIFT)) );

				if (qrylen > 0 && qrylen < MAXDBQUERYSIZE)
				{

					rc = mysql_real_query(connection, query, (unsigned long)qrylen);
					if (0 == rc)
					{
						MYSQL_RES * result = mysql_store_result(connection);
						if (result)
						{
							uint64_t num_rows = mysql_num_rows(result);
							if (INT_MAX < num_rows)
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: more than expected (%d) number of rows returned: %"PRIu64".\n", \
									INT_MAX, num_rows);
								retval = -11;
							}
							else
							{
								retval = (int)num_rows;
							}
							mysql_free_result(result);
						}
						else
						{
							// Didn't get any results, so check if we should have got some
							if (0 == mysql_field_count(connection))
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: surprisingly mysql_field_count() expected to return 0 fields\n");
								retval = -12;
							}
							else
							{
								IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: mysql_store_result() error : %s\n", mysql_error(connection));
								retval = -10;
							}
						}
					}
					else
					{
						IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: Failed to execute select query \"%s\" %d (%s)\n",\
                                                                                        query, mysql_errno(connection), mysql_error(connection) );
						retval = -5;
					}
				}
				else
				{
					IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: Failed to create select query\n");
					retval = -4;
				}
			}
			mysql_commit(connection);
			mysql_close(connection);
		}
		else
		{
			IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: ERROR: mysql_options() failed - check your my.cnf file\n");
			retval = -9;
		}
	}
	mysql_library_end();
	if (0 > retval) IPSCAN_LOG( LOGPREFIX "ipscan: count_teststate_rows_db: INFO: returning with retval = %d\n",retval);
	return (retval);
}
// ----------------------------------------------------------------------------------------
//
// end of ipscan_db.c
//
// ----------------------------------------------------------------------------------------
