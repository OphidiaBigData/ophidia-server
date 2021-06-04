/*
    Ophidia Server
    Copyright (C) 2012-2021 CMCC Foundation

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "oph_odb_job.h"

#include "oph_auth.h"

extern int last_idjob;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

typedef struct {
	int *id;
	int number_of_rows;
	int number_of_cols;
} oph_sqlite_id;

int _oph_odb_get_id_callback(void *res, int argc, char **argv, char **azColName)
{
	UNUSED(azColName);

	if (!res)
		return OPH_ODB_NULL_PARAM;

	((oph_sqlite_id *) res)->number_of_cols = argc;

	if (!argc)
		return OPH_ODB_NO_ROW_FOUND;

	if (argv && argv[0]) {
		if (!((oph_sqlite_id *) res)->number_of_rows)
			*((oph_sqlite_id *) res)->id = strtol(argv[0], NULL, 10);
		((oph_sqlite_id *) res)->number_of_rows++;
	}

	return OPH_ODB_SUCCESS;
}

int _oph_odb_retrieve_user_id(ophidiadb * oDB, char *username, int *id_user, pthread_mutex_t * flag)
{
	if (!oDB || !username || !id_user) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_user = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_RETRIEVE_USER_ID, username);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, query)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) < 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "No row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (mysql_num_rows(res) > 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) != NULL)
		*id_user = (int) strtol(row[0], NULL, 10);

	mysql_free_result(res);

#else

	oph_sqlite_id res;
	res.id = id_user;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, query, _oph_odb_get_id_callback, &res, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", query);
		return OPH_ODB_MYSQL_ERROR;
	}

	if (res.number_of_rows < 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "No row found by query\n");
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (res.number_of_rows > 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (res.number_of_cols != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_user_id(ophidiadb * oDB, char *username, int *id_user)
{
	return _oph_odb_retrieve_user_id(oDB, username, id_user, &global_flag);
}

int oph_odb_retrieve_user_id_unsafe(ophidiadb * oDB, char *username, int *id_user)
{
	return _oph_odb_retrieve_user_id(oDB, username, id_user, NULL);
}

int _oph_odb_retrieve_session_id(ophidiadb * oDB, const char *sessionid, int *id_session, pthread_mutex_t * flag)
{
	if (!oDB || !sessionid || !id_session) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_session = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_RETRIEVE_SESSION_ID, sessionid);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, query)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) < 1) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (mysql_num_rows(res) > 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) != NULL)
		*id_session = (int) strtol(row[0], NULL, 10);

	mysql_free_result(res);

#else

	oph_sqlite_id res;
	res.id = id_session;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, query, _oph_odb_get_id_callback, &res, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", query);
		return OPH_ODB_MYSQL_ERROR;
	}

	if (res.number_of_rows < 1) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (res.number_of_rows > 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (res.number_of_cols != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_session_id(ophidiadb * oDB, const char *sessionid, int *id_session)
{
	return _oph_odb_retrieve_session_id(oDB, sessionid, id_session, &global_flag);
}

int oph_odb_retrieve_session_id_unsafe(ophidiadb * oDB, const char *sessionid, int *id_session)
{
	return _oph_odb_retrieve_session_id(oDB, sessionid, id_session, NULL);
}

int _oph_odb_retrieve_job_id(ophidiadb * oDB, char *sessionid, char *markerid, int *id_job, pthread_mutex_t * flag)
{
	if (!oDB || !sessionid || !markerid || !id_job) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_job = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_RETRIEVE_JOB_ID, sessionid, markerid);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Find job with markerid '%s'\n", markerid);

#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, query)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) < 1) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (mysql_num_rows(res) > 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) && row[0])
		*id_job = (int) strtol(row[0], NULL, 10);

	mysql_free_result(res);

#else

	oph_sqlite_id res;
	res.id = id_job;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, query, _oph_odb_get_id_callback, &res, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", query);
		return OPH_ODB_MYSQL_ERROR;
	}

	if (res.number_of_rows < 1) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (res.number_of_rows > 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (res.number_of_cols != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_job_id(ophidiadb * oDB, char *sessionid, char *markerid, int *id_job)
{
	return _oph_odb_retrieve_job_id(oDB, sessionid, markerid, id_job, &global_flag);
}

int oph_odb_retrieve_job_id_unsafe(ophidiadb * oDB, char *sessionid, char *markerid, int *id_job)
{
	return _oph_odb_retrieve_job_id(oDB, sessionid, markerid, id_job, NULL);
}

int _oph_odb_update_folder_table(ophidiadb * oDB, char *folder_name, int *id_folder, pthread_mutex_t * flag)
{
#ifndef OPH_DB_SUPPORT
	*id_folder = 0;		// Needs to be updated to anew value by the framework
	pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Unable to create a new folder in Ophidia DB\n");
	return OPH_ODB_SUCCESS;
#endif

	if (!oDB || !folder_name || !id_folder) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_FOLDER, folder_name);

	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}

	if (mysql_query(oDB->conn, insertQuery)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (!(*id_folder = mysql_insert_id(oDB->conn))) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to find last inserted folder id\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_update_folder_table(ophidiadb * oDB, char *folder_name, int *id_folder)
{
	return _oph_odb_update_folder_table(oDB, folder_name, id_folder, &global_flag);
}

int oph_odb_update_folder_table_unsafe(ophidiadb * oDB, char *folder_name, int *id_folder)
{
	return _oph_odb_update_folder_table(oDB, folder_name, id_folder, NULL);
}

int _oph_odb_update_session_table(ophidiadb * oDB, char *sessionid, int id_user, int *id_session, pthread_mutex_t * flag)
{
	if (!oDB || !sessionid || !id_session) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char session_code[OPH_MAX_STRING_SIZE];
	if (oph_get_session_code(sessionid, session_code)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to extract session code.\n");
		return OPH_ODB_MYSQL_ERROR;
	}
	int id_folder;
	if (_oph_odb_update_folder_table(oDB, session_code, &id_folder, flag)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to create folder.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION, id_user, sessionid, id_folder);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT

	if (mysql_set_server_option(oDB->conn, MYSQL_OPTION_MULTI_STATEMENTS_ON)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (mysql_query(oDB->conn, insertQuery)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (!(*id_session = mysql_insert_id(oDB->conn))) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to find last inserted session id\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}

	return OPH_ODB_SUCCESS;

#else

	int result = OPH_ODB_SUCCESS;

	if (flag)
		pthread_mutex_lock(flag);

	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", insertQuery);
		result = OPH_ODB_MYSQL_ERROR;
	}

	if (!result && !(*id_session = sqlite3_last_insert_rowid(oDB->db))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to find last inserted session id\n");
		result = OPH_ODB_TOO_MANY_ROWS;
	}

	if (flag)
		pthread_mutex_unlock(flag);

	return result;

#endif
}

int oph_odb_update_session_table(ophidiadb * oDB, char *sessionid, int id_user, int *id_session)
{
	return _oph_odb_update_session_table(oDB, sessionid, id_user, id_session, &global_flag);
}

int oph_odb_update_session_table_unsafe(ophidiadb * oDB, char *sessionid, int id_user, int *id_session)
{
	return _oph_odb_update_session_table(oDB, sessionid, id_user, id_session, NULL);
}

int _oph_odb_update_job_table(ophidiadb * oDB, char *markerid, char *task_string, char *status, int id_user, int id_session, int nchildren, int *id_job, char *parentid, char *workflowid,
			      pthread_mutex_t * flag)
{
	if (!oDB || !markerid || !task_string || !status || !id_job) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_job = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char insertQuery[MYSQL_BUFLEN];
	int n, i, j;

	char new_query[4 + OPERATION_QUERY_SIZE];
	j = 0;
	for (i = 0; task_string[i]; i++) {
		if (task_string[i] == '\'')
#ifdef OPH_DB_SUPPORT
			new_query[j++] = '\\';
#else
			new_query[j++] = '\'';
#endif
		new_query[j++] = task_string[i];
		if (j >= OPERATION_QUERY_SIZE) {
			strcpy(new_query + j, "...");
			j += 3;
			break;
		}
	}
	new_query[j] = 0;

	if (flag)
		pthread_mutex_lock(flag);
	*id_job = ++last_idjob;
	if (flag)
		pthread_mutex_unlock(flag);

	if (parentid)
		n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_CHILD, *id_job, id_user, id_session, markerid, status, new_query, parentid, workflowid);
	else if (nchildren >= 0)
		n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_PARENT, *id_job, id_user, id_session, markerid, status, new_query, nchildren, workflowid);
	else
		n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB, *id_job, id_user, id_session, markerid, status, new_query);
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Execute query: %s\n", insertQuery);

	if (n >= MYSQL_BUFLEN) {
		if (flag)
			pthread_mutex_lock(flag);
		--last_idjob;
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		if (flag)
			pthread_mutex_unlock(flag);
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT
	if (mysql_query(oDB->conn, insertQuery)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}
#else
	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", insertQuery);
		return OPH_ODB_MYSQL_ERROR;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_update_job_table(ophidiadb * oDB, char *markerid, char *task_string, char *status, int id_user, int id_session, int nchildren, int *id_job, char *parentid, char *workflowid)
{
	return _oph_odb_update_job_table(oDB, markerid, task_string, status, id_user, id_session, nchildren, id_job, parentid, workflowid, &global_flag);
}

int oph_odb_update_job_table_unsafe(ophidiadb * oDB, char *markerid, char *task_string, char *status, int id_user, int id_session, int nchildren, int *id_job, char *parentid, char *workflowid)
{
	return _oph_odb_update_job_table(oDB, markerid, task_string, status, id_user, id_session, nchildren, id_job, parentid, workflowid, NULL);
}

int _oph_odb_create_job(ophidiadb * oDB, char *task_string, HASHTBL * task_tbl, int nchildren, int *id_job, pthread_mutex_t * flag)
{
	if (!task_tbl) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter task table\n");
		return OPH_ODB_NULL_PARAM;
	}

	char *username = hashtbl_get(task_tbl, OPH_ARG_USERNAME);
	if (!username) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Missing input parameter '%s'\n", OPH_ARG_USERNAME);
		return OPH_ODB_NULL_PARAM;
	}

	char *sessionid = hashtbl_get(task_tbl, OPH_ARG_SESSIONID);
	if (!sessionid) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Missing input parameter '%s'\n", OPH_ARG_SESSIONID);
		return OPH_ODB_NULL_PARAM;
	}

	char *markerid = hashtbl_get(task_tbl, OPH_ARG_MARKERID);
	if (!markerid) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Missing input parameter '%s'\n", OPH_ARG_MARKERID);
		return OPH_ODB_NULL_PARAM;
	}

	int res, id_user;
	if ((res = _oph_odb_retrieve_user_id(oDB, username, &id_user, flag))) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve user id.\n");
		return res;
	}

	int id_session = 0;
	if ((res = _oph_odb_retrieve_session_id(oDB, sessionid, &id_session, flag))) {
		if (res != OPH_ODB_NO_ROW_FOUND) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve session id\n");
			return res;
		}
		if ((res = _oph_odb_update_session_table(oDB, sessionid, id_user, &id_session, flag))) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to create a new entry in table 'session'\n");
			return res;
		}
	}

	if ((res = _oph_odb_retrieve_job_id(oDB, sessionid, markerid, id_job, flag))) {
		if (res != OPH_ODB_NO_ROW_FOUND) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve job id\n");
			return res;
		}
		if ((res =
		     _oph_odb_update_job_table(oDB, markerid, task_string, OPH_ODB_STATUS_PENDING_STR, id_user, id_session, nchildren, id_job, hashtbl_get(task_tbl, OPH_ARG_PARENTID),
					       hashtbl_get(task_tbl, OPH_ARG_WORKFLOWID), flag))) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to create a new entry in table 'job'\n");
			return res;
		}
	} else {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Found a job with the same identifier '%s'\n", markerid);
		return res;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_create_job(ophidiadb * oDB, char *task_string, HASHTBL * task_tbl, int nchildren, int *id_job)
{
	return _oph_odb_create_job(oDB, task_string, task_tbl, nchildren, id_job, &global_flag);
}

int oph_odb_create_job_unsafe(ophidiadb * oDB, char *task_string, HASHTBL * task_tbl, int nchildren, int *id_job)
{
	return _oph_odb_create_job(oDB, task_string, task_tbl, nchildren, id_job, NULL);
}

const char *oph_odb_convert_status_to_str(enum oph__oph_odb_job_status status)
{
	switch (status) {
		case OPH_ODB_STATUS_PENDING:
			return OPH_ODB_STATUS_PENDING_STR;
		case OPH_ODB_STATUS_WAIT:
			return OPH_ODB_STATUS_WAITING_STR;
		case OPH_ODB_STATUS_RUNNING:
			return OPH_ODB_STATUS_RUNNING_STR;
		case OPH_ODB_STATUS_START:
			return OPH_ODB_STATUS_START_STR;
		case OPH_ODB_STATUS_SET_ENV:
			return OPH_ODB_STATUS_SET_ENV_STR;
		case OPH_ODB_STATUS_INIT:
			return OPH_ODB_STATUS_INIT_STR;
		case OPH_ODB_STATUS_DISTRIBUTE:
			return OPH_ODB_STATUS_DISTRIBUTE_STR;
		case OPH_ODB_STATUS_EXECUTE:
			return OPH_ODB_STATUS_EXECUTE_STR;
		case OPH_ODB_STATUS_REDUCE:
			return OPH_ODB_STATUS_REDUCE_STR;
		case OPH_ODB_STATUS_DESTROY:
			return OPH_ODB_STATUS_DESTROY_STR;
		case OPH_ODB_STATUS_UNSET_ENV:
			return OPH_ODB_STATUS_UNSET_ENV_STR;
		case OPH_ODB_STATUS_COMPLETED:
			return OPH_ODB_STATUS_COMPLETED_STR;
		case OPH_ODB_STATUS_ERROR:
			return OPH_ODB_STATUS_ERROR_STR;
		case OPH_ODB_STATUS_PENDING_ERROR:
			return OPH_ODB_STATUS_PENDING_ERROR_STR;
		case OPH_ODB_STATUS_RUNNING_ERROR:
			return OPH_ODB_STATUS_RUNNING_ERROR_STR;
		case OPH_ODB_STATUS_START_ERROR:
			return OPH_ODB_STATUS_START_ERROR_STR;
		case OPH_ODB_STATUS_SET_ENV_ERROR:
			return OPH_ODB_STATUS_SET_ENV_ERROR_STR;
		case OPH_ODB_STATUS_INIT_ERROR:
			return OPH_ODB_STATUS_INIT_ERROR_STR;
		case OPH_ODB_STATUS_DISTRIBUTE_ERROR:
			return OPH_ODB_STATUS_DISTRIBUTE_ERROR_STR;
		case OPH_ODB_STATUS_EXECUTE_ERROR:
			return OPH_ODB_STATUS_EXECUTE_ERROR_STR;
		case OPH_ODB_STATUS_REDUCE_ERROR:
			return OPH_ODB_STATUS_REDUCE_ERROR_STR;
		case OPH_ODB_STATUS_DESTROY_ERROR:
			return OPH_ODB_STATUS_DESTROY_ERROR_STR;
		case OPH_ODB_STATUS_UNSET_ENV_ERROR:
			return OPH_ODB_STATUS_UNSET_ENV_ERROR_STR;
		case OPH_ODB_STATUS_SKIPPED:
			return OPH_ODB_STATUS_SKIPPED_STR;
		case OPH_ODB_STATUS_ABORTED:
			return OPH_ODB_STATUS_ABORTED_STR;
		case OPH_ODB_STATUS_UNSELECTED:
			return OPH_ODB_STATUS_UNSELECTED_STR;
		case OPH_ODB_STATUS_EXPIRED:
			return OPH_ODB_STATUS_EXPIRED_STR;
		default:
			return OPH_ODB_STATUS_UNKNOWN_STR;
	}
	return OPH_ODB_STATUS_UNKNOWN_STR;
}

int oph_odb_set_job_status(int id_job, enum oph__oph_odb_job_status status, ophidiadb * oDB)
{
	return oph_odb_set_job_status_and_nchildrencompleted(id_job, status, -1, 0, oDB);
}

int oph_odb_set_job_status_and_nchildrencompleted(int id_job, enum oph__oph_odb_job_status status, int nchildren, int force_nchildren_saving, ophidiadb * oDB)
{
	if (!oDB) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char insertQuery[MYSQL_BUFLEN];
	int n;

	switch (status) {
		case OPH_ODB_STATUS_UNKNOWN:
			if (nchildren >= 0) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Status is not changed\n");
				return OPH_ODB_SUCCESS;
			}
			n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_DELETE_OPHIDIADB_JOB, id_job);
			break;
		case OPH_ODB_STATUS_PENDING:
		case OPH_ODB_STATUS_WAIT:
		case OPH_ODB_STATUS_START:
		case OPH_ODB_STATUS_SET_ENV:
		case OPH_ODB_STATUS_INIT:
		case OPH_ODB_STATUS_DISTRIBUTE:
		case OPH_ODB_STATUS_EXECUTE:
		case OPH_ODB_STATUS_REDUCE:
		case OPH_ODB_STATUS_DESTROY:
		case OPH_ODB_STATUS_UNSET_ENV:
			if (nchildren < 0)
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_1, oph_odb_convert_status_to_str(status), id_job);
			else
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_1, oph_odb_convert_status_to_str(status), nchildren, id_job);
			break;
		case OPH_ODB_STATUS_RUNNING:
			if (nchildren < 0)
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_2, oph_odb_convert_status_to_str(status), id_job);
			else if (force_nchildren_saving)
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_1, oph_odb_convert_status_to_str(status), nchildren, id_job);
			else
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_2, oph_odb_convert_status_to_str(status), nchildren, id_job);
			break;
		case OPH_ODB_STATUS_COMPLETED:
		case OPH_ODB_STATUS_ERROR:
		case OPH_ODB_STATUS_START_ERROR:	// Exception due to errors in operator arguments
		case OPH_ODB_STATUS_ABORTED:
		case OPH_ODB_STATUS_EXPIRED:
			if (nchildren < 0)
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_3, oph_odb_convert_status_to_str(status), id_job);
			else
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_3, oph_odb_convert_status_to_str(status), nchildren, id_job);
			break;
		default:
			if (nchildren < 0)
#ifdef OPH_DB_SUPPORT
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_4, id_job);	// In this case the framework has already set current status
#else
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_3, oph_odb_convert_status_to_str(status), id_job);
#endif
			else
				n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_4, nchildren, id_job);
	}
	if (n >= MYSQL_BUFLEN) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT

	if ((nchildren >= 0) && mysql_set_server_option(oDB->conn, MYSQL_OPTION_MULTI_STATEMENTS_ON)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (mysql_query(oDB->conn, insertQuery)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}
#else

	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", insertQuery);
		return OPH_ODB_MYSQL_ERROR;
	}
#endif

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Job status changed into '%s' using: %s\n", oph_odb_convert_status_to_str(status), insertQuery);

	return OPH_ODB_SUCCESS;
}

int oph_odb_change_job_status(int idjob, enum oph__oph_odb_job_status status)
{
	int res;
	ophidiadb oDB;

	oph_odb_initialize_ophidiadb(&oDB);
	if ((res = oph_odb_read_config_ophidiadb(&oDB))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return res;
	}
	if ((res = oph_odb_connect_to_ophidiadb(&oDB))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return res;
	}

	oph_odb_set_job_status(idjob, status, &oDB);

	oph_odb_disconnect_from_ophidiadb(&oDB);

	return OPH_ODB_SUCCESS;
}

int oph_odb_enque_job(int idjob)
{
	return oph_odb_change_job_status(idjob, OPH_ODB_STATUS_PENDING);
}

int oph_odb_start_job(int idjob)
{
	return oph_odb_change_job_status(idjob, OPH_ODB_STATUS_RUNNING);
}

int oph_odb_stop_job(int idjob)
{
	return oph_odb_change_job_status(idjob, OPH_ODB_STATUS_COMPLETED);
}

int oph_odb_abort_job(int idjob)
{
	return oph_odb_change_job_status(idjob, OPH_ODB_STATUS_ERROR);
}

int oph_odb_remove_job(int idjob)
{
	return oph_odb_change_job_status(idjob, OPH_ODB_STATUS_UNKNOWN);
}

int oph_odb_enque_job_fast(int idjob, ophidiadb * oDB)
{
	return oph_odb_set_job_status(idjob, OPH_ODB_STATUS_PENDING, oDB);
}

int oph_odb_start_job_fast(int idjob, ophidiadb * oDB)
{
	return oph_odb_set_job_status(idjob, OPH_ODB_STATUS_RUNNING, oDB);
}

int oph_odb_stop_job_fast(int idjob, ophidiadb * oDB)
{
	return oph_odb_set_job_status(idjob, OPH_ODB_STATUS_COMPLETED, oDB);
}

int oph_odb_abort_job_fast(int idjob, ophidiadb * oDB)
{
	return oph_odb_set_job_status(idjob, OPH_ODB_STATUS_ERROR, oDB);
}

int oph_odb_remove_job_fast(int idjob, ophidiadb * oDB)
{
	return oph_odb_set_job_status(idjob, OPH_ODB_STATUS_UNKNOWN, oDB);
}

int oph_odb_get_parent_job_id(int idjob, int *parent_idjob, ophidiadb * oDB)
{
	if (!oDB || !parent_idjob) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*parent_idjob = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_RETRIEVE_PARENT_JOB_ID, idjob);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}

	if (mysql_query(oDB->conn, query)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) < 1) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (mysql_num_rows(res) > 1) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) != NULL) {
		if (!row[0]) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "No parent job found\n");
			mysql_free_result(res);
			return OPH_ODB_ERROR;
		}
		*parent_idjob = (int) strtol(row[0], NULL, 10);
	}

	mysql_free_result(res);

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_uncompleted_job_number(int parent_idjob, int *number, ophidiadb * oDB)
{
	if (!oDB || !number) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*number = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_RETRIEVE_UNCOMPLETED_JOB_NUMBER, parent_idjob);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Extract number of pending children using: %s.\n", query);
	if (mysql_query(oDB->conn, query)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) < 1) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (mysql_num_rows(res) > 1) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "More than one row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) != NULL) {
		if (!row[0]) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "No parent job found\n");
			mysql_free_result(res);
			return OPH_ODB_ERROR;
		}
		*number = (int) strtol(row[0], NULL, 10);
	}

	mysql_free_result(res);

	return OPH_ODB_SUCCESS;
}

int _oph_odb_update_session_label(ophidiadb * oDB, const char *sessionid, char *label, pthread_mutex_t * flag)
{
	if (!oDB || !sessionid) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	int id_session;
	if (_oph_odb_retrieve_session_id(oDB, sessionid, &id_session, flag)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve session id\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_LABEL, label ? label : "", id_session);

	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT
	if (mysql_set_server_option(oDB->conn, MYSQL_OPTION_MULTI_STATEMENTS_ON)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (mysql_query(oDB->conn, insertQuery)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}
#else

	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", insertQuery);
		return OPH_ODB_MYSQL_ERROR;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_update_session_label(ophidiadb * oDB, const char *sessionid, char *label)
{
	return _oph_odb_update_session_label(oDB, sessionid, label, &global_flag);
}

int oph_odb_update_session_label_unsafe(ophidiadb * oDB, const char *sessionid, char *label)
{
	return _oph_odb_update_session_label(oDB, sessionid, label, NULL);
}

int _oph_odb_get_last_id(ophidiadb * oDB, int *idjob, pthread_mutex_t * flag)
{
	if (!oDB || !idjob)
		return OPH_ODB_NULL_PARAM;

	*idjob = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char selectQuery[MYSQL_BUFLEN];
	int n = snprintf(selectQuery, MYSQL_BUFLEN, MYSQL_QUERY_RETRIEVE_LAST_ID);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, selectQuery)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if ((mysql_field_count(oDB->conn) != 1) || (mysql_num_rows(res) != 1)) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) && row[0])
		*idjob = strtol(row[0], NULL, 10);

	mysql_free_result(res);

#else

	oph_sqlite_id res;
	res.id = idjob;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, selectQuery, _oph_odb_get_id_callback, &res, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", selectQuery);
		return OPH_ODB_MYSQL_ERROR;
	}

	if ((res.number_of_rows != 1) || (res.number_of_cols != 1))
		return OPH_ODB_TOO_MANY_ROWS;

#endif

	// Clean main table
	if (*idjob > 0) {
		n = snprintf(selectQuery, MYSQL_BUFLEN, MYSQL_QUERY_CLEAN_JOB_TABLE, *idjob);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, selectQuery)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
			return OPH_ODB_MYSQL_ERROR;
		}
#else
		if (sqlite3_exec(oDB->db, selectQuery, NULL, NULL, NULL)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", selectQuery);
			return OPH_ODB_MYSQL_ERROR;
		}
#endif
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_last_id(ophidiadb * oDB, int *idjob)
{
	return _oph_odb_get_last_id(oDB, idjob, &global_flag);
}

int oph_odb_get_last_id_unsafe(ophidiadb * oDB, int *idjob)
{
	return _oph_odb_get_last_id(oDB, idjob, NULL);
}

int _oph_odb_copy_job(ophidiadb * oDB, int idjob, int idparent, pthread_mutex_t * flag)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	int n;
	char copyQuery[MYSQL_BUFLEN];
	if (idjob) {
		if (idparent)
			n = snprintf(copyQuery, MYSQL_BUFLEN, MYSQL_QUERY_COPY_JOB_PARENT, idjob, idparent);
		else
			n = snprintf(copyQuery, MYSQL_BUFLEN, MYSQL_QUERY_COPY_JOB, idjob);
	} else if (idparent)
		n = snprintf(copyQuery, MYSQL_BUFLEN, MYSQL_QUERY_COPY_JOB_CHILD, idparent);
	else
		return OPH_ODB_NULL_PARAM;

	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT
	if (mysql_query(oDB->conn, copyQuery)) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}
#else
	if (sqlite3_exec(oDB->db, copyQuery, NULL, NULL, NULL)) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", copyQuery);
		return OPH_ODB_MYSQL_ERROR;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_copy_job(ophidiadb * oDB, int idjob, int idparent)
{
	return _oph_odb_copy_job(oDB, idjob, idparent, &global_flag);
}

int oph_odb_copy_job_unsafe(ophidiadb * oDB, int idjob, int idparent)
{
	return _oph_odb_copy_job(oDB, idjob, idparent, NULL);
}

int _oph_odb_drop_job(ophidiadb * oDB, int idjob, int idparent, pthread_mutex_t * flag)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	int n;
	char deleteQuery[MYSQL_BUFLEN];
	if (idjob) {
		if (idparent)
			n = snprintf(deleteQuery, MYSQL_BUFLEN, MYSQL_QUERY_DROP_JOB_PARENT, idjob, idparent);
		else
			n = snprintf(deleteQuery, MYSQL_BUFLEN, MYSQL_QUERY_DROP_JOB, idjob);
	} else if (idparent)
		n = snprintf(deleteQuery, MYSQL_BUFLEN, MYSQL_QUERY_DROP_JOB_CHILD, idparent);
	else
		return OPH_ODB_NULL_PARAM;
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT
	if (mysql_set_server_option(oDB->conn, MYSQL_OPTION_MULTI_STATEMENTS_ON)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (mysql_query(oDB->conn, deleteQuery)) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}
#else
	if (sqlite3_exec(oDB->db, deleteQuery, NULL, NULL, NULL)) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", deleteQuery);
		return OPH_ODB_MYSQL_ERROR;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_drop_job(ophidiadb * oDB, int idjob, int idparent)
{
	return _oph_odb_drop_job(oDB, idjob, idparent, &global_flag);
}

int oph_odb_drop_job_unsafe(ophidiadb * oDB, int idjob, int idparent)
{
	return _oph_odb_drop_job(oDB, idjob, idparent, NULL);
}
