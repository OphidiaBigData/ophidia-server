/*
    Ophidia Server
    Copyright (C) 2012-2022 CMCC Foundation

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

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int _oph_odb_retrieve_user_id(ophidiadb * oDB, char *username, int *id_user, pthread_mutex_t * flag)
{
	if (!oDB || !username || !id_user) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_user = 1;

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
	*id_session = 1;

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
	*id_job = 1;

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
	if (!oDB || !folder_name || !id_folder) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_folder = 1;

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
	UNUSED(id_user);

	if (!oDB || !sessionid || !id_session) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_session = 1;

	return OPH_ODB_SUCCESS;
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
	UNUSED(id_user);
	UNUSED(id_session);
	UNUSED(nchildren);
	UNUSED(parentid);
	UNUSED(workflowid);

	if (!oDB || !markerid || !task_string || !status || !id_job) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*id_job = 1;

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

	int id_session;
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
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Found a job with the same identifier %s\n", task_string);
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
	UNUSED(id_job);
	UNUSED(status);
	UNUSED(nchildren);
	UNUSED(force_nchildren_saving);

	if (!oDB) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

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
	UNUSED(idjob);

	if (!oDB || !parent_idjob) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*parent_idjob = 1;

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_uncompleted_job_number(int parent_idjob, int *number, ophidiadb * oDB)
{
	UNUSED(parent_idjob);

	if (!oDB || !number) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*number = 0;

	return OPH_ODB_SUCCESS;
}

int _oph_odb_update_session_label(ophidiadb * oDB, const char *sessionid, char *label, pthread_mutex_t * flag)
{
	UNUSED(label);

	if (!oDB || !sessionid) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

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
	if (mysql_query(oDB->conn, copyQuery))
		return OPH_ODB_MYSQL_ERROR;
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
		pmesg(LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	if (mysql_query(oDB->conn, deleteQuery))
		return OPH_ODB_MYSQL_ERROR;
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

int oph_odb_start_wf_fast(int idjob, ophidiadb * oDB)
{
	UNUSED(idjob);

	if (!oDB) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}

	return OPH_ODB_SUCCESS;
}
