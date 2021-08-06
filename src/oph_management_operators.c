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

#include "oph_management_operators.h"

#include "oph_auth.h"
#include "oph_ophidiadb.h"
#include "oph_json_library.h"
#include "oph_task_parser_library.h"
#include "oph_workflow_engine.h"
#include "oph_rmanager.h"
#include "oph_utils.h"

#include <sys/stat.h>
#include <dirent.h>

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif
extern char *oph_web_server;
extern char *oph_log_file_name;
extern char *oph_auth_location;
extern unsigned int oph_default_max_sessions;
extern unsigned int oph_default_session_timeout;
extern oph_rmanager *orm;
extern char oph_cluster_deployment;
extern char *oph_txt_location;
extern char *oph_subm_user;
extern ophidiadb *ophDB;

extern int oph_finalize_known_operator(int idjob, oph_json * oper_json, const char *operator_name, char *error_message, int success, char **response, ophidiadb * oDB,
				       enum oph__oph_odb_job_status *exit_code);

int oph_serve_management_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id, int *light_task_id,
				  int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, const char *os_username, const char *project,
				  const char *operator_name)
{
	UNUSED(ncores);
	UNUSED(odb_wf_id);
	UNUSED(task_id);
	UNUSED(light_task_id);
	UNUSED(odb_jobid);
	UNUSED(exit_output);

	int error = OPH_SERVER_UNKNOWN;

	if (!strncasecmp(operator_name, OPH_OPERATOR_CANCEL, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Task parser error\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		char username[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE], oph_jobid[OPH_MAX_STRING_SIZE], type[OPH_MAX_STRING_SIZE];
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, oph_jobid)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int) strtol(oph_jobid, NULL, 10);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, username)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_USERNAME);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_WORKFLOWID, workflowid)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_WORKFLOWID);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		*type = 0;
		oph_tp_find_param_in_task_string(request, OPH_OPERATOR_PARAMETER_TYPE, type);

		int wid, success = 0, success2 = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE], btype = 'k';

		while (!success) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s'!", OPH_ARG_ID);
			char *str_id = hashtbl_get(task_tbl, OPH_ARG_ID);
			if (!str_id)
				break;

			wid = (int) strtol(str_id, NULL, 10);
			if (wid <= 0)
				break;

			snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s'!", OPH_OPERATOR_PARAMETER_TYPE);
			if (!strcasecmp(type, OPH_OPERATOR_CANCEL_PARAMETER_TYPE_ABORT))
				btype = 'a';
			else if (!strcasecmp(type, OPH_OPERATOR_CANCEL_PARAMETER_TYPE_STOP))
				btype = 's';
			else if (*type && strcasecmp(type, OPH_OPERATOR_CANCEL_PARAMETER_TYPE_KILL))
				break;

			success = 1;
		}

		if (success) {
			int jobid = 0;
			char error_notification[OPH_MAX_STRING_SIZE];
			*error_notification = 0;

			snprintf(error_message, OPH_MAX_STRING_SIZE, "Workflow '%d' not found!", wid);
			oph_job_info *item = NULL;

			pthread_mutex_lock(&global_flag);

			if (!(item = oph_find_workflow_in_job_list(state->job_info, sessionid, wid)))
				success = 0;
			else if (!item->wf->is_closed && (item->wf->status < (int) OPH_ODB_STATUS_ABORTED)) {
				item->wf->status = OPH_ODB_STATUS_ABORTED;
				item->wf->cancel_type = btype;
				snprintf(error_notification, OPH_MAX_STRING_SIZE, OPH_WORKFLOW_BASE_NOTIFICATION, item->wf->idjob, 0, -1, item->wf->idjob, OPH_ODB_STATUS_ABORTED, item->wf->sessionid,
					 item->wf->markerid, item->wf->save ? OPH_COMMON_YES : OPH_COMMON_NO);
				jobid = ++*state->jobid;
			}

			pthread_mutex_unlock(&global_flag);

			if (strlen(error_notification)) {
				int response = 0;
				oph_workflow_notify(state, 'N', jobid, error_notification, NULL, &response);
				if (response)
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N%d: error %d in notify\n", jobid, response);
			}
		}

		while (!success2) {
			if (oph_json_alloc(&oper_json)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success2 = 1;
		}
		if (success)
			success = success2;

		if (task_tbl)
			hashtbl_destroy(task_tbl);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success)
			*error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_MANAGE_SESSION, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		char *action, *key, *value, username[OPH_MAX_STRING_SIZE], *new_sessionid = NULL, oph_jobid[OPH_MAX_STRING_SIZE];
		const char *session;
		int result, save_user = 0, save_session = 0, num_sessions = -1;

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, oph_jobid)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int) strtol(oph_jobid, NULL, 10);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_odb_start_job_fast(idjob, &oDB);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERID, username)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_USERID);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		int id_user = (int) strtol(username, NULL, 10);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, username)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_USERNAME);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		// Convert dn to user
		char _username[OPH_MAX_STRING_SIZE];
		snprintf(_username, OPH_MAX_STRING_SIZE, "%s", username);
		int i, j = strlen(_username);
		for (i = 0; i < j; ++i)
			if ((_username[i] == '/') || (_username[i] == ' ') || (_username[i] == '='))
				_username[i] = '_';

		// Load user information
		int save_in_odb = 0;
		oph_argument *user_args = NULL;
		oph_init_args(&user_args);
		pthread_mutex_lock(&global_flag);
		result = oph_load_user(_username, &user_args, &save_in_odb);
		pthread_mutex_unlock(&global_flag);
		if (result) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error in opening user data\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (save_in_odb)	// Save the entry in OphDB
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Saving reference to '%s' in system catalog\n", username);
			if (oph_odb_insert_user(&oDB, username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error in saving reference to '%s' in system catalog\n", username);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_cleanup_args(&user_args);
				return OPH_SERVER_IO_ERROR;
			}
		}

		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Task parser error\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		char **objkeys = NULL;
		int objkeys_num = 0;
		value = hashtbl_get(task_tbl, OPH_ARG_OBJKEY_FILTER);
		if (!value) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Argument '%s' is not set\n", OPH_ARG_OBJKEY_FILTER);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (oph_tp_parse_multiple_value_param(value, &objkeys, &objkeys_num)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Operator string not valid\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		action = hashtbl_get(task_tbl, OPH_ARG_ACTION);
		session = hashtbl_get(task_tbl, OPH_ARG_SESSION);
		key = hashtbl_get(task_tbl, OPH_ARG_KEY);
		value = hashtbl_get(task_tbl, OPH_ARG_VALUE);

		if (session) {
			if (!strncasecmp(session, OPH_COMMON_PARAMETER_WORKING_SESSION, OPH_MAX_STRING_SIZE))
				session = sessionid;
			else if (strncmp(session, oph_web_server, strlen(oph_web_server))) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Received wrong sessionid '%s'\n", session);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_WRONG_PARAMETER_ERROR;
			}
		} else
			session = sessionid;

		char default_key[OPH_SHORT_STRING_SIZE] = OPH_ARG_KEY_VALUE_USER;
		if (!key)
			key = default_key;

		char owner[OPH_MAX_STRING_SIZE];
		oph_auth_user_role role = OPH_ROLE_NONE;
		char session_code[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE];

		char last_session[OPH_MAX_STRING_SIZE];
		if (oph_get_arg(user_args, OPH_USER_LAST_SESSION_ID, last_session))
			*last_session = 0;

		if (oph_get_session_code(sessionid, session_code)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_WORKFLOWID, workflowid)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_WORKFLOWID);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);

		oph_argument *args = NULL;
		if (session) {
			oph_init_args(&args);
			pthread_mutex_lock(&global_flag);
			if (oph_auth_session(_username, session, oph_web_server, &args, NULL, &role)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "received wrong sessionid '%s'\n", session);
				pthread_mutex_unlock(&global_flag);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_cleanup_args(&args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_AUTH_ERROR;
			}
			char *str_role;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "role of the user '%s' is '%s'\n", username, str_role = oph_role_to_string(role));
			if (str_role)
				free(str_role);
			pthread_mutex_unlock(&global_flag);
			if (oph_get_session_code(session, session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "unable to get session code\n");
				oph_cleanup_args(&args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			if (oph_get_arg(args, OPH_SESSION_OWNER, owner)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "unable to get session owner\n");
				oph_cleanup_args(&args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "session owner is '%s'\n", owner);
		} else
			*session_code = 0;

		int success = 0;
		oph_json *oper_json = NULL;

		char error_message[OPH_MAX_STRING_SIZE], tmp[OPH_MAX_STRING_SIZE], filename[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		int num_fields, iii, jjj = 0;

		char **jsonkeys = NULL;
		char **fieldtypes = NULL;
		char **jsonvalues = NULL;

		// JSON Response creation
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			if (session) {
				if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					break;
				}
				if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					break;
				}
				if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					break;
				}
				if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					break;
				}
			}
			if (oph_json_add_consumer(oper_json, username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}
			success = 1;
		}
		if (!success)
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");

		char _action[OPH_SHORT_STRING_SIZE] = OPH_ARG_ACTION_VALUE_LIST;
		if (!action)
			action = _action;

		// Commands for any user
		if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_LIST, OPH_MAX_STRING_SIZE)) {
			num_fields = 8;
			if (success) {
				// Header
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
					success = 0;
				else
					success = 1;
				while (!success) {
					jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonkeys) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj = 0;
					jsonkeys[jjj] = strdup(OPH_SESSION_ID);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_LABEL);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_OWNER);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_CREATION_TIME);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_LAST_ACCESS_TIME);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_LAST_WORKFLOW);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_LAST_MARKER);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup(OPH_SESSION_ACTIVE);
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj = 0;
					fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
					if (!fieldtypes) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_INT);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_INT);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, "Session List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < num_fields; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					for (iii = 0; iii < num_fields; iii++)
						if (fieldtypes[iii])
							free(fieldtypes[iii]);
					if (fieldtypes)
						free(fieldtypes);

					success = 1;
				}
			}

			int last_access_time = 0, exist, check_num_sessions = 0;
			struct dirent *entry, save_entry;
			char directory[OPH_MAX_STRING_SIZE];
			snprintf(directory, OPH_MAX_STRING_SIZE, OPH_SESSION_DIR, oph_auth_location, _username);

			num_sessions = oph_get_arg(user_args, OPH_USER_OPENED_SESSIONS, tmp);
			if (num_sessions)
				num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
			else
				num_sessions = strtol(tmp, NULL, 10);

			int timeout_value = oph_get_arg(user_args, OPH_USER_TIMEOUT_SESSION, tmp);
			if (timeout_value)
				timeout_value = oph_default_session_timeout;
			else
				timeout_value = strtol(tmp, NULL, 10);

			pthread_mutex_lock(&global_flag);

			struct timeval tv;
			gettimeofday(&tv, 0);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "scanning %s\n", directory);
			DIR *dirp = opendir(directory);
			if (!dirp) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error in opening session directory '%s'\n", directory);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_json_free(oper_json);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			oph_arguments *session_args_list = NULL, *session_args_item;
			oph_init_args_list(&session_args_list);

			oph_argument *session_args = NULL;
			struct stat file_stat;

			while (success && !readdir_r(dirp, &save_entry, &entry) && entry) {
				snprintf(filename, OPH_MAX_STRING_SIZE, "%s/%s", directory, entry->d_name);
				lstat(filename, &file_stat);
				if (S_ISLNK(file_stat.st_mode)) {
					oph_init_args(&session_args);
					if (!oph_load_file(filename, &session_args)) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "check for %s\n", OPH_SESSION_LAST_ACCESS_TIME);
						if (!oph_get_arg(session_args, OPH_SESSION_LAST_ACCESS_TIME, tmp)) {
							last_access_time = strtol(tmp, NULL, 10);
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "check for %s\n", OPH_SESSION_AUTOREMOVE);
							if (timeout_value && !oph_get_arg(session_args, OPH_SESSION_AUTOREMOVE, tmp) && !strcasecmp(tmp, OPH_DEFAULT_YES)) {
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "found a removable session '%s', last access on %d\n", filename, last_access_time);
								if (tv.tv_sec > last_access_time + timeout_value * OPH_DEFAULT_DAY_TO_SEC)	// Timeout
								{
									pmesg(LOG_INFO, __FILE__, __LINE__, "session '%s' has expired... removing it\n", filename);
									remove(filename);
									oph_cleanup_args(&session_args);
									if (num_sessions > 0)
										num_sessions--;
									else
										pmesg(LOG_WARNING, __FILE__, __LINE__, "error in handling session number\n");
									save_user = 1;
									continue;
								}
							}
						}

					} else {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "found a broken file '%s'... removing it\n", filename);
						remove(filename);
						oph_cleanup_args(&session_args);
						if (num_sessions > 0)
							num_sessions--;
						else
							pmesg(LOG_WARNING, __FILE__, __LINE__, "error in handling session number\n");
						save_user = 1;
						continue;
					}

					if (oph_append_args_list(&session_args_list, session_args, last_access_time)) {
						closedir(dirp);
						pmesg(LOG_ERROR, __FILE__, __LINE__, "error in handling session list\n");
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl)
							hashtbl_destroy(task_tbl);
						oph_cleanup_args_list(&session_args_list);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
						return OPH_SERVER_SYSTEM_ERROR;
					}

					check_num_sessions++;
				}
			}
			closedir(dirp);

			pthread_mutex_unlock(&global_flag);

			if (num_sessions != check_num_sessions) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unexpected number of sessions '%d': forcing new value '%d'\n", num_sessions, check_num_sessions);
				num_sessions = check_num_sessions;
			}

			int max_sessions = oph_get_arg(user_args, OPH_USER_MAX_SESSIONS, tmp);
			if (max_sessions)
				max_sessions = oph_default_max_sessions;
			else
				max_sessions = strtol(tmp, NULL, 10);
			if (max_sessions && (num_sessions > max_sessions)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Number of sessions '%d' is higher than the maximum number '%d'!", num_sessions, max_sessions);
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "the number of sessions '%d' is higher than the maximum number '%d'\n", num_sessions, max_sessions);
			}
			// Order by last_access_time
			if (oph_order_args_list(&session_args_list)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "error in ordering session list\n");
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_cleanup_args_list(&session_args_list);
				oph_json_free(oper_json);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			time_t nowtime, nowtime2;
			struct tm nowtm, nowtm2;
			// Data
			if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
				success = 0;
			else
				success = 1;
			while (!success) {
				for (session_args_item = session_args_list; session_args_item; session_args_item = session_args_item->next) {
					session_args = session_args_item->item;
					nowtime = (time_t) (session_args_item->id);
					if (!localtime_r(&nowtime, &nowtm)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error getting system time\n");
						break;
					}
					strftime(filename, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm);

					jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj = 0;
					exist = !oph_get_arg(session_args, OPH_SESSION_ID, tmp);
					jsonvalues[jjj] = strdup(exist ? tmp : "-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args, OPH_SESSION_LABEL, tmp);
					jsonvalues[jjj] = strdup(exist ? tmp : "-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args, OPH_SESSION_OWNER, tmp);
					jsonvalues[jjj] = strdup(exist ? tmp : "-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args, OPH_SESSION_CREATION_TIME, tmp);
					if (exist) {
						nowtime2 = (time_t) strtol(tmp, NULL, 10);
						if (!localtime_r(&nowtime2, &nowtm2)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error getting system time\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						strftime(tmp, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm2);
					}
					jsonvalues[jjj] = strdup(exist ? tmp : "-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(filename);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args, OPH_SESSION_LAST_WORKFLOW, tmp);
					jsonvalues[jjj] = strdup(exist ? tmp : "0");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args, OPH_SESSION_LAST_MARKER, tmp);
					jsonvalues[jjj] = strdup(exist ? tmp : "0");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args, OPH_SESSION_ACTIVE, tmp);
					jsonvalues[jjj] = strdup(exist ? tmp : "-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					for (iii = 0; iii < num_fields; iii++)
						if (jsonvalues[iii])
							free(jsonvalues[iii]);
					if (jsonvalues)
						free(jsonvalues);

				}

				if (session_args_item)
					break;
				else
					success = 1;
			}
			oph_cleanup_args_list(&session_args_list);

			if (success) {
				if (!num_sessions)
					snprintf(tmp, OPH_MAX_STRING_SIZE, "No session found");
				else if (num_sessions == 1)
					snprintf(tmp, OPH_MAX_STRING_SIZE, "Found 1 session");
				else
					snprintf(tmp, OPH_MAX_STRING_SIZE, "Found %d sessions", num_sessions);
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_SUMMARY)
				    && oph_json_add_text(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_SUMMARY, "Summary", tmp)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD TEXT error\n");
					success = 0;
				}
			}
		} else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_NEW, OPH_MAX_STRING_SIZE)) {
			num_sessions = oph_get_arg(user_args, OPH_USER_OPENED_SESSIONS, tmp);
			if (num_sessions)
				num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
			else
				num_sessions = strtol(tmp, NULL, 10);

			int max_sessions = oph_get_arg(user_args, OPH_USER_MAX_SESSIONS, tmp);
			if (max_sessions)
				max_sessions = oph_default_max_sessions;
			else
				max_sessions = strtol(tmp, NULL, 10);

			int timeout_value = oph_get_arg(user_args, OPH_USER_TIMEOUT_SESSION, tmp);
			if (timeout_value)
				timeout_value = oph_default_session_timeout;
			else
				timeout_value = strtol(tmp, NULL, 10);

			oph_workflow *wf = (oph_workflow *) calloc(1, sizeof(oph_workflow));
			wf->username = strdup(username);
			wf->os_username = strdup(os_username);
			wf->project = project ? strdup(project) : NULL;
			wf->command = strdup("");

			pthread_mutex_lock(&global_flag);
			if (oph_generate_oph_jobid(state, 'R', 0, wf, &num_sessions, max_sessions, timeout_value, NULL, NULL, NULL, NULL, oph_jobid, 0))
				success = 0;
			else {
				int id_session;
				if ((result = oph_odb_retrieve_session_id_unsafe(&oDB, wf->sessionid, &id_session))) {
					if (result != OPH_ODB_NO_ROW_FOUND) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve session id\n");
						success = 0;
					} else if ((result = oph_odb_update_session_table_unsafe(&oDB, wf->sessionid, id_user, &id_session))) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to create a new entry in table 'session'\n");
						success = 0;
					}
				}
			}
			pthread_mutex_unlock(&global_flag);

			new_sessionid = wf->sessionid ? strdup(wf->sessionid) : NULL;
			if (!wf->sessionid)
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");

			oph_workflow_free(wf);

			save_user = 3;
		} else if (!session) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Expected parameter '%s'!", OPH_ARG_SESSION);
			success = 0;
		}
		// Commands for readers
		else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_ENV, OPH_MAX_STRING_SIZE)) {
			if (!(role & OPH_ROLE_READ)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			}
			num_fields = 2;
			if (success) {
				// Header
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
					success = 0;
				else
					success = 1;
				while (!success) {
					jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonkeys) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj = 0;
					jsonkeys[jjj] = strdup("PARAMETER");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("VALUE");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj = 0;
					fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
					if (!fieldtypes) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, "Session List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < num_fields; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					for (iii = 0; iii < num_fields; iii++)
						if (fieldtypes[iii])
							free(fieldtypes[iii]);
					if (fieldtypes)
						free(fieldtypes);

					success = 1;
				}
			}

			if (success) {
				oph_argument *tmp2, *us_args = NULL;
				time_t nowtime;
				struct tm nowtm;
				// Data
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
					success = 0;
				else
					success = 1;
				while (!success) {
					for (tmp2 = args; tmp2; tmp2 = tmp2->next) {
						if (!strcasecmp(tmp2->key, OPH_SESSION_USERS))
							continue;	// Use listusers instead
						if (tmp2->value) {
							if (!strcasecmp(tmp2->key, OPH_SESSION_CREATION_TIME) || !strcasecmp(tmp2->key, OPH_SESSION_LAST_ACCESS_TIME)) {
								nowtime = (time_t) strtol(tmp2->value, NULL, 10);
								if (!localtime_r(&nowtime, &nowtm)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error getting system time\n");
									break;
								}
								strftime(tmp, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm);
							} else
								strncpy(tmp, tmp2->value, OPH_MAX_STRING_SIZE);
						}
						jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							break;
						}
						jjj = 0;
						jsonvalues[jjj] = strdup(tmp2->key);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(tmp2->value ? tmp : "-");
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							for (iii = 0; iii < num_fields; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						for (iii = 0; iii < num_fields; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);

					}
					if (!tmp2)
						success = 1;
					else
						break;

					oph_init_args(&us_args);
					snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, _username, session_code);
					pthread_mutex_lock(&global_flag);
					if (oph_load_file(filename, &us_args))	// DT_REG
					{
						pmesg(LOG_ERROR, __FILE__, __LINE__, "unable to load user-specific session data of '%s'\n", sessionid);
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&us_args);
						break;
					}
					pthread_mutex_unlock(&global_flag);
					for (tmp2 = us_args; tmp2; tmp2 = tmp2->next) {
						jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							break;
						}
						jjj = 0;
						jsonvalues[jjj] = strdup(tmp2->key);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(tmp2->value ? tmp2->value : "-");
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							for (iii = 0; iii < num_fields; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						for (iii = 0; iii < num_fields; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);

					}
					oph_cleanup_args(&us_args);
					if (!tmp2)
						success = 1;
					else
						break;
				}
			}
		} else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_LISTUSERS, OPH_MAX_STRING_SIZE)) {
			if (!(role & OPH_ROLE_READ)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			}
			num_fields = 2;
			if (success) {
				// Header
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
					success = 0;
				else
					success = 1;
				while (!success) {
					jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonkeys) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj = 0;
					jsonkeys[jjj] = strdup("USER");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("ROLE");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj = 0;
					fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
					if (!fieldtypes) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, "Session List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < num_fields; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					for (iii = 0; iii < num_fields; iii++)
						if (fieldtypes[iii])
							free(fieldtypes[iii]);
					if (fieldtypes)
						free(fieldtypes);

					success = 1;
				}
			}

			if (success) {
				// Data
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
					success = 0;
				else
					success = 1;
				while (!success) {
					jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj = 0;
					jsonvalues[jjj] = strdup(owner);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(OPH_ROLE_OWNER_STR);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					for (iii = 0; iii < num_fields; iii++)
						if (jsonvalues[iii])
							free(jsonvalues[iii]);
					if (jsonvalues)
						free(jsonvalues);

					success = 1;
				}
			}
			if (success && !oph_get_arg(args, OPH_SESSION_USERS, tmp)) {
				char *save_pointer = NULL, *pch1, *pch2;
				// Data
				if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST))
					success = 0;
				else
					success = 1;
				while (!success) {
					pch1 = strtok_r(tmp, OPH_SEPARATOR_USER, &save_pointer);
					while (pch1) {
						pch2 = strchr(pch1, OPH_SEPARATOR_ROLE);
						if (!pch2) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
							break;
						}

						jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							break;
						}
						jjj = 0;
						jsonvalues[jjj] = strndup(pch1, pch2 - pch1);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = oph_expand_role_string(1 + pch2);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_MANAGE_SESSION_LIST, jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							for (iii = 0; iii < num_fields; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						for (iii = 0; iii < num_fields; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);

						pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
					}
					if (!pch1)
						success = 1;
					else
						break;
				}
			}
		}
		// Commands for writers
		else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_SETENV, OPH_MAX_STRING_SIZE)) {
			if (!(role & OPH_ROLE_WRITE)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			}
			if (success) {
				if (!key) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Expected parameter '%s'!", OPH_ARG_KEY);
					success = 0;
				} else if (!strncasecmp(key, OPH_ARG_KEY_VALUE_LABEL, OPH_MAX_STRING_SIZE) || !strncasecmp(key, OPH_SESSION_LABEL, OPH_MAX_STRING_SIZE)) {
					char label[OPH_MAX_STRING_SIZE];
					if (!value)
						*label = 0;
					else
						snprintf(label, OPH_MAX_STRING_SIZE, "%s", value);
					if (oph_set_arg(&args, OPH_SESSION_LABEL, label)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_LABEL);
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl)
							hashtbl_destroy(task_tbl);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
						return OPH_SERVER_SYSTEM_ERROR;
					}

					if (oph_odb_update_session_label(&oDB, session, label)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "unable to connect to OphidiaDB. Check access parameters\n");
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl)
							hashtbl_destroy(task_tbl);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
						return OPH_SERVER_IO_ERROR;
					}

					save_session = 1;
				} else if (strncmp(username, owner, OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER))	// Parameters for owners
				{
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
					success = 0;
				} else if (!strncasecmp(key, OPH_ARG_KEY_VALUE_ACTIVE, OPH_MAX_STRING_SIZE) || !strncasecmp(key, OPH_SESSION_ACTIVE, OPH_MAX_STRING_SIZE)) {
					if (!value) {
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Expected parameter '%s'!", OPH_ARG_VALUE);
						success = 0;
					} else if (!strncasecmp(value, OPH_COMMON_YES, OPH_MAX_STRING_SIZE) || !strncasecmp(value, OPH_COMMON_NO, OPH_MAX_STRING_SIZE)) {
						if (oph_set_arg(&args, OPH_SESSION_ACTIVE, value)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_ACTIVE);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl)
								hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						if (!strncasecmp(value, OPH_COMMON_NO, OPH_MAX_STRING_SIZE) && !strncmp(last_session, session, OPH_MAX_STRING_SIZE))
							save_user = 2;
						save_session = 1;
					} else {
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s=%s'!", OPH_ARG_VALUE, value);
						success = 0;
					}
				} else if (!strncasecmp(key, OPH_ARG_KEY_VALUE_AUTOREMOVE, OPH_MAX_STRING_SIZE) || !strncasecmp(key, OPH_SESSION_AUTOREMOVE, OPH_MAX_STRING_SIZE)) {
					if (!value) {
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Expected parameter '%s'!", OPH_ARG_VALUE);
						success = 0;
					} else if (!strncasecmp(value, OPH_COMMON_YES, OPH_MAX_STRING_SIZE) || !strncasecmp(value, OPH_COMMON_NO, OPH_MAX_STRING_SIZE)) {
						if (oph_set_arg(&args, OPH_SESSION_AUTOREMOVE, value)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_AUTOREMOVE);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl)
								hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						save_session = 1;
					} else {
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s=%s'!", OPH_ARG_VALUE, value);
						success = 0;
					}
				} else {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s=%s'!", OPH_ARG_KEY, key);
					success = 0;
				}
			}
		}
		// Commands for administrators
		else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_GRANT, OPH_MAX_STRING_SIZE)) {
			if (!(role & OPH_ROLE_ADMIN)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			}
			if (success) {
				if (!key) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Expected parameter '%s'!", OPH_ARG_KEY);
					success = 0;
				} else if (!strncasecmp(key, OPH_ARG_KEY_VALUE_USER, OPH_MAX_STRING_SIZE)) {
					oph_argument *users, *tmp2;
					oph_auth_user_role nrole;
					char *save_pointer = NULL, *pch1, *pch2, session_username[OPH_MAX_STRING_SIZE];

					oph_init_args(&users);
					snprintf(tmp, OPH_MAX_STRING_SIZE, "%s", value);
					pch1 = strtok_r(tmp, OPH_SEPARATOR_USER, &save_pointer);
					while (pch1) {
						pch2 = strchr(pch1, OPH_SEPARATOR_ROLE);
						if (pch2) {
							strncpy(session_username, pch1, pch2 - pch1);
							session_username[pch2 - pch1] = 0;
						} else
							snprintf(session_username, OPH_MAX_STRING_SIZE, "%s", pch1);
						if (strcasecmp(session_username, owner)) {
							tmp2 = (oph_argument *) malloc(sizeof(oph_argument));
							if (!tmp2) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "memory allocation error\n");
								oph_cleanup_args(&users);
								oph_cleanup_args(&args);
								oph_cleanup_args(&user_args);
								if (task_tbl)
									hashtbl_destroy(task_tbl);
								oph_json_free(oper_json);
								oph_odb_disconnect_from_ophidiadb(&oDB);
								oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
								return OPH_SERVER_SYSTEM_ERROR;
							}
							tmp2->key = strndup(session_username, OPH_MAX_STRING_SIZE);
							if (!tmp2->key) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "memory allocation error\n");
								oph_cleanup_args(&users);
								oph_cleanup_args(&args);
								oph_cleanup_args(&user_args);
								if (task_tbl)
									hashtbl_destroy(task_tbl);
								oph_json_free(oper_json);
								oph_odb_disconnect_from_ophidiadb(&oDB);
								oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
								return OPH_SERVER_SYSTEM_ERROR;
							}
							if (pch2)
								tmp2->value = oph_code_role_string(1 + pch2);
							else
								tmp2->value = oph_role_to_string(OPH_DEFAULT_SESSION_ROLE);
							if (!tmp2->value) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Permissions of user '%s' are wrong!", tmp2->key);
								free(tmp2->key);
								free(tmp2);
								pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
								continue;
							}
							nrole = oph_string_to_role(tmp2->value);
							if (nrole == OPH_ROLE_NONE) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Permissions of user '%s' will be not changed!", tmp2->key);
								free(tmp2->key);
								free(tmp2->value);
								free(tmp2);
								pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
								continue;
							}
							if (nrole >= OPH_ROLE_OWNER) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Session ownership cannot be changed!");
								free(tmp2->key);
								free(tmp2->value);
								free(tmp2);
								pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
								continue;
							}
							tmp2->next = users;
							users = tmp2;

							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "found user '%s' with role '%s'\n", tmp2->key, tmp2->value);
						} else
							snprintf(error_message, OPH_MAX_STRING_SIZE, "Permissions of the owner cannot be changed!");
						pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
					}
					char new_user_string[OPH_MAX_STRING_SIZE];
					if (!oph_get_arg(args, OPH_SESSION_USERS, tmp)) {
						int first = 1, pointer;
						char linkname[OPH_MAX_STRING_SIZE], newrole[OPH_MAX_STRING_SIZE];
						*new_user_string = 0;
						success = 0;
						while (!success) {
							pch1 = strtok_r(tmp, OPH_SEPARATOR_USER, &save_pointer);
							while (pch1) {
								pch2 = strchr(pch1, OPH_SEPARATOR_ROLE);
								if (!pch2) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
									break;
								}
								strncpy(session_username, pch1, pch2 - pch1);	// Username
								session_username[pch2 - pch1] = 0;
								snprintf(newrole, OPH_MAX_STRING_SIZE, "%s", 1 + pch2);	// Role
								for (tmp2 = users; tmp2; tmp2 = tmp2->next)
									if (tmp2->key && !strncmp(session_username, tmp2->key, OPH_MAX_STRING_SIZE)) {
										snprintf(newrole, OPH_MAX_STRING_SIZE, "%s", tmp2->value);
										free(tmp2->key);
										tmp2->key = 0;
										break;
									}
								if (!first)
									strncat(new_user_string, OPH_SEPARATOR_USER, OPH_MAX_STRING_SIZE - strlen(new_user_string));
								else
									first = 0;

								strncat(new_user_string, session_username, OPH_MAX_STRING_SIZE - strlen(new_user_string) - 1);
								pointer = strlen(new_user_string);
								new_user_string[pointer] = OPH_SEPARATOR_ROLE;
								new_user_string[++pointer] = 0;
								strncat(new_user_string, newrole, OPH_MAX_STRING_SIZE - strlen(new_user_string));

								pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
							}
							if (!pch1)
								success = 1;
							else
								break;
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "user list will be updated to '%s'\n", new_user_string);
						// Add the new users
						if (success) {
							int first_link = 1;
							oph_argument *us_args = NULL;	// User-specific session data
							for (tmp2 = users; tmp2; tmp2 = tmp2->next)
								if (tmp2->key) {
									if (first_link) {
										snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, _username, session_code);
										pthread_mutex_lock(&global_flag);
										int nchars = readlink(linkname, newrole, OPH_MAX_STRING_SIZE);
										pthread_mutex_unlock(&global_flag);
										if (nchars < 0) {
											pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "unable to solve symbolic link '%s'\n", linkname);
											oph_cleanup_args(&users);
											oph_cleanup_args(&args);
											oph_cleanup_args(&user_args);
											if (task_tbl)
												hashtbl_destroy(task_tbl);
											oph_json_free(oper_json);
											oph_odb_disconnect_from_ophidiadb(&oDB);
											oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
											return OPH_SERVER_SYSTEM_ERROR;
										} else if (nchars >= OPH_MAX_STRING_SIZE) {
											pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "real file name of '%s' is too long\n", linkname);
											oph_cleanup_args(&users);
											oph_cleanup_args(&args);
											oph_cleanup_args(&user_args);
											if (task_tbl)
												hashtbl_destroy(task_tbl);
											oph_json_free(oper_json);
											oph_odb_disconnect_from_ophidiadb(&oDB);
											oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
											return OPH_SERVER_SYSTEM_ERROR;
										}
										newrole[nchars] = 0;
										first_link = 0;
									}
									// Add user separator in case this user is not the first one
									if (!first)
										strncat(new_user_string, OPH_SEPARATOR_USER, OPH_MAX_STRING_SIZE - strlen(new_user_string));
									else
										first = 0;

									strncat(new_user_string, tmp2->key, OPH_MAX_STRING_SIZE - strlen(new_user_string) - 1);
									pointer = strlen(new_user_string);
									new_user_string[pointer] = OPH_SEPARATOR_ROLE;
									new_user_string[++pointer] = 0;
									strncat(new_user_string, tmp2->value, OPH_MAX_STRING_SIZE - strlen(new_user_string));

									// Create the symbolic link
									strcpy(session_username, tmp2->key);
									jjj = strlen(session_username);
									for (iii = 0; iii < jjj; iii++)
										if ((session_username[iii] == '/') || (session_username[iii] == ' ') || (session_username[iii] == '='))
											session_username[iii] = '_';
									snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, session_username, session_code);

									oph_init_args(&us_args);
									if (oph_set_arg(&us_args, OPH_SESSION_CWD, OPH_WORKFLOW_ROOT_FOLDER)) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "error in saving %s\n", OPH_SESSION_CWD);
										pthread_mutex_unlock(&global_flag);
										oph_cleanup_args(&us_args);
										oph_cleanup_args(&users);
										oph_cleanup_args(&args);
										oph_cleanup_args(&user_args);
										if (task_tbl)
											hashtbl_destroy(task_tbl);
										oph_json_free(oper_json);
										oph_odb_disconnect_from_ophidiadb(&oDB);
										oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
										return OPH_SERVER_SYSTEM_ERROR;
									}

									pthread_mutex_lock(&global_flag);
									if (symlink(newrole, linkname)) {
										if (errno == EEXIST)
											pmesg(LOG_WARNING, __FILE__, __LINE__, "symbolic link '%s' already exists\n", linkname);
										else {
											pmesg(LOG_WARNING, __FILE__, __LINE__, "unable to create symbolic link '%s'\n", linkname);
											pthread_mutex_unlock(&global_flag);
											oph_cleanup_args(&us_args);
											oph_cleanup_args(&users);
											oph_cleanup_args(&args);
											oph_cleanup_args(&user_args);
											if (task_tbl)
												hashtbl_destroy(task_tbl);
											oph_json_free(oper_json);
											oph_odb_disconnect_from_ophidiadb(&oDB);
											oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
											return OPH_SERVER_SYSTEM_ERROR;
										}
									}
									if (oph_save_user_session(session_username, sessionid, us_args)) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "error in saving user-specific session data\n");
										pthread_mutex_unlock(&global_flag);
										oph_cleanup_args(&us_args);
										oph_cleanup_args(&users);
										oph_cleanup_args(&args);
										oph_cleanup_args(&user_args);
										if (task_tbl)
											hashtbl_destroy(task_tbl);
										oph_json_free(oper_json);
										oph_odb_disconnect_from_ophidiadb(&oDB);
										oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
										return OPH_SERVER_SYSTEM_ERROR;
									}
									pthread_mutex_unlock(&global_flag);

									oph_cleanup_args(&us_args);

									free(tmp2->key);
									tmp2->key = 0;
								}
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "new user list is '%s'\n", new_user_string);
					}
					if (success) {
						if (oph_set_arg(&args, OPH_SESSION_USERS, new_user_string)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_USERS);
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl)
								hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						save_session = 1;
					}
					oph_cleanup_args(&users);
				} else {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s=%s'!", OPH_ARG_KEY, key);
					success = 0;
				}
			}
		} else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_REVOKE, OPH_MAX_STRING_SIZE)) {
			if (!(role & OPH_ROLE_ADMIN)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			}
			if (success) {
				if (!key) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Expected parameter '%s'!", OPH_ARG_KEY);
					success = 0;
				} else if (!strncasecmp(key, OPH_ARG_KEY_VALUE_USER, OPH_MAX_STRING_SIZE)) {
					oph_argument *users, *tmp2;
					char *save_pointer = NULL, *pch1, session_username[OPH_MAX_STRING_SIZE], *pch2;

					oph_init_args(&users);
					strncpy(tmp, value, OPH_MAX_STRING_SIZE);
					pch1 = strtok_r(tmp, OPH_SEPARATOR_USER, &save_pointer);
					while (pch1) {
						pch2 = strchr(pch1, OPH_SEPARATOR_ROLE);
						if (pch2) {
							strncpy(session_username, pch1, pch2 - pch1);
							session_username[pch2 - pch1] = 0;
						} else
							snprintf(session_username, OPH_MAX_STRING_SIZE, "%s", pch1);
						tmp2 = (oph_argument *) malloc(sizeof(oph_argument));
						if (!tmp2) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "memory allocation error\n");
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl)
								hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						tmp2->key = strndup(session_username, OPH_MAX_STRING_SIZE);
						if (!tmp2->key) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "memory allocation error\n");
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl)
								hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						tmp2->value = NULL;
						tmp2->next = users;
						users = tmp2;
						pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
					}
					char new_user_string[OPH_MAX_STRING_SIZE];
					if (!oph_get_arg(args, OPH_SESSION_USERS, tmp)) {
						int first = 1;
						char linkname[OPH_MAX_STRING_SIZE];
						*new_user_string = 0;
						success = 0;
						while (!success) {
							pch1 = strtok_r(tmp, OPH_SEPARATOR_USER, &save_pointer);
							while (pch1) {
								pch2 = strchr(pch1, OPH_SEPARATOR_ROLE);
								if (!pch2) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
									break;
								}
								strncpy(session_username, pch1, pch2 - pch1);
								session_username[pch2 - pch1] = 0;
								for (tmp2 = users; tmp2; tmp2 = tmp2->next)
									if (tmp2->key && !strncmp(session_username, tmp2->key, OPH_MAX_STRING_SIZE)) {
										jjj = strlen(session_username);
										for (iii = 0; iii < jjj; iii++)
											if ((session_username[iii] == '/') || (session_username[iii] == ' ') || (session_username[iii] == '='))
												session_username[iii] = '_';
										snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, session_username, session_code);
										pthread_mutex_lock(&global_flag);
										remove(linkname);
										snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, session_username, session_code);
										remove(linkname);
										pthread_mutex_unlock(&global_flag);
										break;
									}
								if (!tmp2) {
									if (!first)
										strncat(new_user_string, OPH_SEPARATOR_USER, OPH_MAX_STRING_SIZE - strlen(new_user_string));
									else
										first = 0;
									strncat(new_user_string, pch1, OPH_MAX_STRING_SIZE - strlen(new_user_string));
								}
								pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
							}
							if (!pch1)
								success = 1;
							else
								break;
						}
					}
					if (success) {
						if (oph_set_arg(&args, OPH_SESSION_USERS, new_user_string)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_USERS);
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl)
								hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						save_session = 1;
					}
					oph_cleanup_args(&users);
				} else {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s=%s'!", OPH_ARG_KEY, key);
					success = 0;
				}
			}
		}
		// Commands for owners
		else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_DISABLE, OPH_MAX_STRING_SIZE)) {
			if (strncmp(username, owner, OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			} else {
				if (oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_COMMON_NO)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_ACTIVE);
					oph_cleanup_args(&args);
					oph_cleanup_args(&user_args);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (!strncmp(last_session, session, OPH_MAX_STRING_SIZE))
					save_user = 2;
				save_session = 1;
			}
		} else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_ENABLE, OPH_MAX_STRING_SIZE)) {
			if (strncmp(username, owner, OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			} else {
				if (oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_COMMON_YES)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_SESSION_ACTIVE);
					oph_cleanup_args(&args);
					oph_cleanup_args(&user_args);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				save_session = 1;
			}
		} else if (!strncasecmp(action, OPH_ARG_ACTION_VALUE_REMOVE, OPH_MAX_STRING_SIZE)) {
			if (strncmp(username, owner, OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Permission denied!");
				success = 0;
			} else {
				char linkname[OPH_MAX_STRING_SIZE];
				if (!oph_get_arg(args, OPH_SESSION_USERS, tmp)) {
					char *save_pointer = NULL, *pch1, *pch2;
					char session_username[OPH_MAX_STRING_SIZE];
					success = 0;
					while (!success) {
						pch1 = strtok_r(tmp, OPH_SEPARATOR_USER, &save_pointer);
						while (pch1) {
							pch2 = strchr(pch1, OPH_SEPARATOR_ROLE);
							if (!pch2) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
								break;
							}
							strncpy(session_username, pch1, pch2 - pch1);
							session_username[pch2 - pch1] = 0;
							jjj = strlen(session_username);
							for (iii = 0; iii < jjj; iii++)
								if ((session_username[iii] == '/') || (session_username[iii] == ' ') || (session_username[iii] == '='))
									session_username[iii] = '_';
							snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, session_username, session_code);
							pthread_mutex_lock(&global_flag);
							remove(linkname);
							snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, session_username, session_code);
							remove(linkname);
							pthread_mutex_unlock(&global_flag);
							pch1 = strtok_r(NULL, OPH_SEPARATOR_USER, &save_pointer);
						}
						if (!pch1)
							success = 1;
						else
							break;
					}
				}
				if (success) {
					if (oph_set_arg(&args, OPH_SESSION_USERS, "") || oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_COMMON_NO)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "unable to set session data\n");
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl)
							hashtbl_destroy(task_tbl);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
						return OPH_SERVER_SYSTEM_ERROR;
					}
					if (!strncmp(last_session, session, OPH_MAX_STRING_SIZE))
						save_user = 2;
					save_session = 2;	// Means that file will be removed
				}
			}
		} else {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s=%s'!", OPH_ARG_ACTION, action);
			success = 0;
		}

		if (success && save_session) {
			pthread_mutex_lock(&global_flag);
			if (oph_save_session(_username, session, args, DT_LNK)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "unable to save session data of '%s'\n", session);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_json_free(oper_json);
				if (new_sessionid)
					free(new_sessionid);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			if (save_session > 1)	// Remove the intended session
			{
				char linkname[OPH_MAX_STRING_SIZE];
				snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, _username, session_code);
				remove(linkname);
				snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, _username, session_code);
				remove(linkname);
				if (num_sessions < 0) {
					num_sessions = oph_get_arg(user_args, OPH_USER_OPENED_SESSIONS, tmp);
					if (num_sessions)
						num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
					else
						num_sessions = strtol(tmp, NULL, 10);
				}
				if (num_sessions > 0)
					num_sessions--;
				else {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error in handling session number\n");
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&args);
					oph_cleanup_args(&user_args);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					if (new_sessionid)
						free(new_sessionid);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (!save_user)
					save_user = 1;
			}
			pthread_mutex_unlock(&global_flag);
		}
		oph_cleanup_args(&args);

		// Update user data
		if (success && save_user) {
			if (save_user > 1)	// Reset OPH_USER_LAST_SESSION_ID or set to sessionid
			{
				char *new_jobid = strdup(save_user > 2 ? (new_sessionid ? new_sessionid : "") : "");
				if (oph_set_arg(&user_args, OPH_USER_LAST_SESSION_ID, new_jobid)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_USER_LAST_SESSION_ID);
					oph_cleanup_args(&user_args);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					if (new_sessionid)
						free(new_sessionid);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (jobid_response) {
					if (*jobid_response)
						free(*jobid_response);
					*jobid_response = new_jobid;
				} else
					free(new_jobid);
			}
			if (num_sessions >= 0) {
				snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", num_sessions);
				if (oph_set_arg(&user_args, OPH_USER_OPENED_SESSIONS, tmp)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "unable to set '%s'\n", OPH_USER_LAST_SESSION_ID);
					oph_cleanup_args(&user_args);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					if (new_sessionid)
						free(new_sessionid);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
			pthread_mutex_lock(&global_flag);
			if (oph_save_user(_username, user_args)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "unable to save user data of '%s'\n", username);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&user_args);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				oph_json_free(oper_json);
				if (new_sessionid)
					free(new_sessionid);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			pthread_mutex_unlock(&global_flag);
		}
		oph_cleanup_args(&user_args);
		if (new_sessionid)
			free(new_sessionid);

		if (task_tbl)
			hashtbl_destroy(task_tbl);

		oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_LOG_INFO, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		error = OPH_SERVER_SYSTEM_ERROR;

		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s task parser error\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		char **objkeys = NULL;
		int objkeys_num, success = 0, nlines;
		oph_json *oper_json = NULL;
		char *value, username[OPH_MAX_STRING_SIZE], session_code[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE], oph_jobid[OPH_MAX_STRING_SIZE], error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		value = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_LOG_TYPE);
		if (!value || strncasecmp(value, OPH_OPERATOR_LOG_INFO_PARAMETER_SERVER, OPH_MAX_STRING_SIZE)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_OPERATOR_PARAMETER_LOG_TYPE);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_UNKNOWN;
		}

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, oph_jobid)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int) strtol(oph_jobid, NULL, 10);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_odb_start_job_fast(idjob, &oDB);

		while (1) {
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}
			if (oph_tp_find_param_in_task_string(request, OPH_ARG_WORKFLOWID, workflowid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_WORKFLOWID);
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);

			if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_USERNAME);
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}

			value = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_LINES_NUMBER);
			if (!value) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_WORKFLOWID);
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}
			nlines = strtol(value, NULL, 10);

			if (oph_json_alloc(&oper_json)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			if (oph_log_file_name) {
				value = hashtbl_get(task_tbl, OPH_ARG_OBJKEY_FILTER);
				if (!value) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Argument '%s' is not set\n", OPH_ARG_OBJKEY_FILTER);
					error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				}
				if (oph_tp_parse_multiple_value_param(value, &objkeys, &objkeys_num)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Operator string not valid\n");
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				}

				int is_objkey_printable = oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_LOG_INFO);
				if (is_objkey_printable) {
					int num_fields = 3, iii, jjj = 0;

					// Header
					char **jsonkeys = NULL;
					char **fieldtypes = NULL;
					jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonkeys) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jsonkeys[jjj] = strdup("TIMESTAMP");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("TYPE");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("MESSAGE");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj = 0;
					fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
					if (!fieldtypes) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					jjj++;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < jjj; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_LOG_INFO, "Log Data", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						for (iii = 0; iii < num_fields; iii++)
							if (fieldtypes[iii])
								free(fieldtypes[iii]);
						if (fieldtypes)
							free(fieldtypes);
						break;
					}
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					for (iii = 0; iii < num_fields; iii++)
						if (fieldtypes[iii])
							free(fieldtypes[iii]);
					if (fieldtypes)
						free(fieldtypes);
				}

				char *lines;
				if (nlines > 0) {
					lines = (char *) malloc(nlines * OPH_MAX_STRING_SIZE + 1);
					if (!lines) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
				} else {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Invalid lines_number value\n");
					break;
				}

				FILE *file;
				file = fopen(oph_log_file_name, "r");
				if (file == NULL) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "File %s cannot be opened\n", oph_log_file_name);
					free(lines);
					break;
				}

				fseek(file, 0, SEEK_END);
				if (!ftell(file)) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Server log is empty");
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "File %s is empty\n", oph_log_file_name);
					fclose(file);
					free(lines);
					success = 1;
					break;
				}

				memset(lines, 0, nlines * OPH_MAX_STRING_SIZE + 1);

				fseek(file, -1, SEEK_END);
				char c;
				int i = nlines * OPH_MAX_STRING_SIZE - 1;
				int count = 0;
				int flag = 0;
				do {
					c = getc(file);
					if (c == '\n' && i != (nlines * OPH_MAX_STRING_SIZE - 1)) {
						count++;
						if (count == nlines) {
							flag = 1;
							break;
						}
					}
					lines[i] = c;
					i--;
				} while ((fseek(file, -2, SEEK_CUR)) == 0);
				fclose(file);

				if (flag == 0)
					count++;

				char *ptr = 0;
				for (i = 0; i < nlines * OPH_MAX_STRING_SIZE + 1; i++) {
					if (lines[i] != '\0') {
						ptr = lines + i;
						break;
					}
				}
				snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", ptr ? ptr : "");

				if (ptr && is_objkey_printable) {
					int num_fields = 3, iii, jjj = 0, kkk = 0, print_data, k;
					char *jsontmp[num_fields];
					char **jsonvalues = NULL;
					char *my_ptr = ptr;

					while (my_ptr) {
						for (k = 0; k < num_fields; ++k)
							jsontmp[k] = 0;
						k = 0;
						while (my_ptr && (*my_ptr != '\n') && (*my_ptr != '\0')) {
							if (*my_ptr == '[') {
								if (k < num_fields)
									jsontmp[k++] = my_ptr + 1;
							} else if (*my_ptr == ']') {
								if (!jsontmp[1] || !jsontmp[2])
									*my_ptr = '\0';
								else if (*(jsontmp[2]) != '\t')
									jsontmp[2] = my_ptr + 1;
							}
							my_ptr++;
						}

						if (!my_ptr || (*my_ptr == '\0'))
							break;

						*my_ptr = '\0';
						my_ptr++;

						if (jsontmp[2] && (*(jsontmp[2]) == '\t'))
							(jsontmp[2])++;

						print_data = 1;
						for (k = 0; k < num_fields; ++k)
							if (!jsontmp[k]) {
								print_data = 0;
								break;
							}
						if (print_data) {
							jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonvalues) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
								break;
							}
							for (jjj = 0; jjj < num_fields; jjj++) {
								jsonvalues[jjj] = strdup(jsontmp[jjj]);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
							}
							if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_LOG_INFO, jsonvalues)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
								for (iii = 0; iii < num_fields; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							for (iii = 0; iii < num_fields; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
						}
						kkk++;
					}
				}

				free(lines);
				success = 1;
			} else
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Server log not found!");
			break;
		}

		if (task_tbl)
			hashtbl_destroy(task_tbl);

		oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);

		if (!oper_json) {
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return error;
		}

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;

	} else if (!strncasecmp(operator_name, OPH_OPERATOR_CLUSTER, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int max_hosts = item->wf->max_hosts;	// Its value should be used only for the deploy, refer to ophDB otherwise
		char em = item->wf->exec_mode && !strncasecmp(item->wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE);
		int wid = item->wf->workflowid;

		pthread_mutex_unlock(&global_flag);

		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Task parser error\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		char username[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE], oph_jobid[OPH_MAX_STRING_SIZE], *type = NULL, *value = NULL;
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, oph_jobid)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int) strtol(oph_jobid, NULL, 10);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERID, username)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_USERID);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		int id_user = (int) strtol(username, NULL, 10);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, username)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_USERNAME);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		snprintf(workflowid, OPH_MAX_STRING_SIZE, "%d", wid);

		int success = 0, success2 = 0, nhosts = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE], *host_partition = NULL, host_type = 0, *user_filter = NULL, btype = 0;	// Get information about user-defined partitions
		char **objkeys = NULL;
		int objkeys_num = 0;
		char random_name[OPH_SHORT_STRING_SIZE];

		while (!success) {

			if (!oph_cluster_deployment) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Dynamic cluster deployment is disabled!");
				break;
			}

			type = hashtbl_get(task_tbl, OPH_ARG_ACTION);
			if (!type) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Argument '%s' is not set\n", OPH_ARG_ACTION);
				break;
			}
			if (!strcasecmp(type, OPH_OPERATOR_CLUSTER_PARAMETER_INFO_CLUSTER))
				btype = 1;	// Get all information about deployed clusters
			else if (!strcasecmp(type, OPH_OPERATOR_CLUSTER_PARAMETER_DEPLOY))
				btype = 2;	// Allocate
			else if (!strcasecmp(type, OPH_OPERATOR_CLUSTER_PARAMETER_UNDEPLOY))
				btype = 3;	// Deallocate
			else if (strcasecmp(type, OPH_OPERATOR_CLUSTER_PARAMETER_INFO)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s'!", OPH_ARG_ACTION);
				break;
			}

			value = hashtbl_get(task_tbl, OPH_ARG_NHOSTS);
			if (!value) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Argument '%s' is not set\n", OPH_ARG_NHOSTS);
				break;
			}
			nhosts = (int) strtol(value, NULL, 10);
			if (nhosts < 0) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s'!", OPH_ARG_NHOSTS);
				break;
			}

			host_partition = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_HOST_PARTITION);
			if (!host_partition) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s'!", OPH_OPERATOR_PARAMETER_HOST_PARTITION);
				break;
			}
			size_t length = strlen(host_partition);
			if (!length || (length > OPH_ODB_PARTITION_NAME_SIZE)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s': its size exceeds limit!", OPH_OPERATOR_PARAMETER_HOST_PARTITION);
				break;
			}
			if (!strcasecmp(host_partition, OPH_OPERATOR_CLUSTER_PARAMETER_AUTO)) {
				if (btype < 2)
					host_partition = NULL;
				else if (btype == 2) {
					snprintf(random_name, OPH_SHORT_STRING_SIZE, "_%d", idjob);
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Host partition name will be set to '%s'!", random_name);
					host_partition = random_name;
				} else {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Parameter '%s' needs to be set to a value different from '%s' to perform action '%s'!",
						 OPH_OPERATOR_PARAMETER_HOST_PARTITION, OPH_OPERATOR_CLUSTER_PARAMETER_AUTO, type);
					break;
				}
			}
			if (host_partition && !strcasecmp(host_partition, OPH_OPERATOR_CLUSTER_PARAMETER_ALL)) {
				host_partition = NULL;
				if (btype > 1) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Parameter '%s' needs to be set to a value different from '%s' to perform action '%s'!",
						 OPH_OPERATOR_PARAMETER_HOST_PARTITION, OPH_OPERATOR_CLUSTER_PARAMETER_ALL, type);
					break;
				}
			}

			value = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_HOST_TYPE);
			if (!value) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong parameter '%s'!", OPH_OPERATOR_PARAMETER_HOST_TYPE);
				break;
			}
			if (!strcasecmp(value, OPH_OPERATOR_CLUSTER_PARAMETER_COMPUTE))
				host_type = 1;
			else if (strcasecmp(value, OPH_OPERATOR_CLUSTER_PARAMETER_IO)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Value of argument '%s' is not valid\n", OPH_OPERATOR_PARAMETER_HOST_TYPE);
				break;
			}

			user_filter = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_USER_FILTER);
			if (!user_filter) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Argument '%s' is not set\n", OPH_OPERATOR_PARAMETER_USER_FILTER);
				break;
			}
			if (!strcasecmp(user_filter, OPH_OPERATOR_CLUSTER_PARAMETER_ALL))
				user_filter = NULL;

			value = hashtbl_get(task_tbl, OPH_ARG_OBJKEY_FILTER);
			if (!value) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Argument '%s' is not set\n", OPH_ARG_OBJKEY_FILTER);
				break;
			}
			if (oph_tp_parse_multiple_value_param(value, &objkeys, &objkeys_num)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Operator string not valid\n");
				break;
			}

			success = 1;
		}

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_odb_start_job_fast(idjob, &oDB);

		if (success && oph_json_alloc(&oper_json)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
			success = 0;
		}

		ophidiadb_list list;
		oph_odb_initialize_ophidiadb_list(&list);
		ophidiadb_list user_list;
		oph_odb_initialize_ophidiadb_list(&user_list);

		if (success) {

			success = 0;
			while (!success) {

				if (!orm) {
					orm = (oph_rmanager *) malloc(sizeof(oph_rmanager));
					if (initialize_rmanager(orm)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on initialization OphidiaDB\n");
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Internal error!");
						break;
					}
					if (oph_read_rmanager_conf(orm)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on read resource manager parameters\n");
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Internal error!\n");
						break;
					}
				}

				int num_fields, iii, jjj = 0, idp;
				int total_hosts = 0, reserved_hosts = 0, available_hosts = 0;
				char **jsonkeys = NULL;
				char **fieldtypes = NULL;
				char **jsonvalues = NULL;
				char tmp[OPH_MAX_STRING_SIZE];

				switch (btype) {

					case 0:{

							if (oph_odb_get_total_hosts(&oDB, &total_hosts)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of total hosts cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of total hosts!");
								break;
							}
							if (oph_odb_get_reserved_hosts(&oDB, id_user, &reserved_hosts)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of reserved hosts of '%s' cannot be retrieved\n", username);
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of reserved hosts!");
								break;
							}
							if (oph_get_available_host_number(&available_hosts, idjob)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of available hosts cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of available hosts!");
								break;
							}
							// Update max_hosts to actual value
							snprintf(tmp, OPH_MAX_STRING_SIZE, OPHIDIADB_RETRIEVE_USER, id_user);
							if (oph_odb_retrieve_list(&oDB, tmp, &user_list)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "User data cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve user data!");
								break;
							}
							if (user_list.size && user_list.id)
								max_hosts = user_list.id[0];
							if (max_hosts && (available_hosts > max_hosts - reserved_hosts))
								available_hosts = max_hosts - reserved_hosts;
							if (available_hosts < 0)
								available_hosts = 0;
							snprintf(tmp, OPH_MAX_STRING_SIZE, OPHIDIADB_RETRIEVE_RESERVED_PARTITIONS, id_user, host_partition ? host_partition : "%");
							success = oph_odb_retrieve_list2(&oDB, tmp, &list);
							if (success && (success != OPH_ODB_NO_ROW_FOUND)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Partition list cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve partition list!");
								break;
							}

							num_fields = 4;

							// Header
							success = oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_SUMMARY) ? 0 : 1;
							while (!success) {
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								jsonkeys[jjj] = strdup("TOTAL CLUSTER SIZE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("QUOTA");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("RESERVED HOSTS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("AVAILABLE HOSTS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}

								jjj = 0;
								fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
								if (!fieldtypes) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}

								if (oph_json_add_grid
								    (oper_json, OPH_JSON_OBJKEY_CLUSTER_SUMMARY, "Cluster summary", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < num_fields; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								for (iii = 0; iii < num_fields; iii++)
									if (fieldtypes[iii])
										free(fieldtypes[iii]);
								if (fieldtypes)
									free(fieldtypes);

								success = 2;
							}

							// Data
							if (success == 2)
								success = 0;
							while (!success) {
								jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonvalues) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", total_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", max_hosts ? max_hosts : total_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", reserved_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", available_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_CLUSTER_SUMMARY, jsonvalues)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);

								success = 2;
							}

							num_fields = 5;

							// Header
							if ((success == 2) && oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_LIST))
								success = 0;
							else
								success = 1;	// No output
							while (!success) {
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								jsonkeys[jjj] = strdup("HOST PARTITION");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("TYPE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("SIZE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("STATUS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("CREATION DATE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}

								jjj = 0;
								fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
								if (!fieldtypes) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}

								if (oph_json_add_grid
								    (oper_json, OPH_JSON_OBJKEY_CLUSTER_LIST, "Reserved partitions", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < num_fields; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								for (iii = 0; iii < num_fields; iii++)
									if (fieldtypes[iii])
										free(fieldtypes[iii]);
								if (fieldtypes)
									free(fieldtypes);

								success = 2;
							}

							// Data
							if (success == 2)
								success = 0;
							while (!success) {
								for (idp = 0; idp < list.size; ++idp) {
									jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
									if (!jsonvalues) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										break;
									}
									jjj = 0;
									jsonvalues[jjj] = strdup(list.ctime && list.ctime[idp] ? list.ctime[idp] : OPH_UNKNOWN);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%s", list.pid
										 && list.pid[idp] ? OPH_OPERATOR_CLUSTER_VALUE_COMPUTE : OPH_OPERATOR_CLUSTER_VALUE_IO);
									jsonvalues[jjj] = strdup(tmp);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", list.id ? list.id[idp] : 0);
									jsonvalues[jjj] = strdup(tmp);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									jsonvalues[jjj] = strdup(list.wid[idp] ? OPH_ODB_STATUS_PENDING_STR : OPH_ODB_STATUS_RUNNING_STR);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									jsonvalues[jjj] = strdup(list.max_status && list.max_status[idp] ? list.max_status[idp] : OPH_UNKNOWN);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_CLUSTER_LIST, jsonvalues)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
										for (iii = 0; iii < num_fields; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									for (iii = 0; iii < num_fields; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
								}
								if (idp >= list.size)
									success = 2;
								else
									break;
							}

							if (success == 2) {
								if (!list.size)
									snprintf(tmp, OPH_MAX_STRING_SIZE, "No partition found");
								else
									snprintf(tmp, OPH_MAX_STRING_SIZE, "Found %d partition%s", list.size, list.size == 1 ? "" : "s");
								if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_LIST_SUMMARY)
								    && oph_json_add_text(oper_json, OPH_JSON_OBJKEY_CLUSTER_LIST_SUMMARY, "Summary", tmp)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD TEXT error\n");
									success = 0;
								} else
									success = 1;
							}

							break;
						}

					case 1:{

#ifdef OPH_DB_SUPPORT
							if (oph_odb_get_total_hosts(&oDB, &total_hosts)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of total hosts cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of total hosts!");
								break;
							}
							if (oph_odb_get_reserved_hosts(&oDB, 0, &reserved_hosts)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of reserved hosts of '%s' cannot be retrieved\n", username);
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of reserved hosts!");
								break;
							}
							if (oph_get_available_host_number(&available_hosts, idjob)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of available hosts cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of available hosts!");
								break;
							}
							snprintf(tmp, OPH_MAX_STRING_SIZE, OPHIDIADB_RETRIEVE_USERS, user_filter ? user_filter : "%");
							if (oph_odb_retrieve_list(&oDB, tmp, &user_list)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "User list cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve user list!");
								break;
							}
							snprintf(tmp, OPH_MAX_STRING_SIZE, OPHIDIADB_RETRIEVE_TOTAL_RESERVED_PARTITIONS, user_filter ? user_filter : "%",
								 host_partition ? host_partition : "%");
							success = oph_odb_retrieve_list2(&oDB, tmp, &list);
							if (success && (success != OPH_ODB_NO_ROW_FOUND)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Partition list cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve partition list!");
								break;
							}

							num_fields = 4;

							// Header
							success = oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_SUMMARY) ? 0 : 1;
							while (!success) {
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								jsonkeys[jjj] = strdup("TOTAL CLUSTER SIZE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("UNUSABLE HOSTS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("RESERVED HOSTS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("AVAILABLE HOSTS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}

								jjj = 0;
								fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
								if (!fieldtypes) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}

								if (oph_json_add_grid
								    (oper_json, OPH_JSON_OBJKEY_CLUSTER_SUMMARY, "Cluster summary", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < num_fields; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								for (iii = 0; iii < num_fields; iii++)
									if (fieldtypes[iii])
										free(fieldtypes[iii]);
								if (fieldtypes)
									free(fieldtypes);

								success = 2;
							}

							// Data
							if (success == 2)
								success = 0;
							while (!success) {
								jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonvalues) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", total_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", total_hosts - reserved_hosts - available_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", reserved_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", available_hosts);
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_CLUSTER_SUMMARY, jsonvalues)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);

								success = 2;
							}

							num_fields = 3;

							// Header
							if (success && oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_USER))
								success = 0;
							else
								success = 1;	// No output
							while (!success) {
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								jsonkeys[jjj] = strdup("USER");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("QUOTA");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("RESERVED HOSTS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}

								jjj = 0;
								fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
								if (!fieldtypes) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}

								if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_CLUSTER_USER, "Users", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < num_fields; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								for (iii = 0; iii < num_fields; iii++)
									if (fieldtypes[iii])
										free(fieldtypes[iii]);
								if (fieldtypes)
									free(fieldtypes);

								success = 2;
							}

							// Data
							if (success == 2)
								success = 0;
							while (!success) {
								for (idp = 0; idp < user_list.size; ++idp) {
									jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
									if (!jsonvalues) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										break;
									}
									jjj = 0;
									jsonvalues[jjj] = strdup(user_list.name && user_list.name[idp] ? user_list.name[idp] : OPH_UNKNOWN);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", user_list.wid && user_list.wid[idp] ? user_list.wid[idp] : total_hosts);
									jsonvalues[jjj] = strdup(tmp);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", user_list.id ? user_list.id[idp] : 0);
									jsonvalues[jjj] = strdup(tmp);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_CLUSTER_USER, jsonvalues)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
										for (iii = 0; iii < num_fields; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									for (iii = 0; iii < num_fields; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
								}
								if (idp >= user_list.size)
									success = 2;
								else
									break;
							}

							if (success == 2) {
								if (!user_list.size)
									snprintf(tmp, OPH_MAX_STRING_SIZE, "No user found");
								else
									snprintf(tmp, OPH_MAX_STRING_SIZE, "Found %d user%s", user_list.size, user_list.size == 1 ? "" : "s");
								if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_USER_SUMMARY)
								    && oph_json_add_text(oper_json, OPH_JSON_OBJKEY_CLUSTER_USER_SUMMARY, "Summary", tmp)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD TEXT error\n");
									success = 0;
								} else
									success = 1;
							}

							num_fields = 6;

							// Header
							if (success && oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_LIST))
								success = 0;
							else
								success = 1;	// No output
							while (!success) {
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									break;
								}
								jjj = 0;
								jsonkeys[jjj] = strdup("USER");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("HOST PARTITION");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("TYPE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("SIZE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("STATUS");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("CREATION DATE");
								if (!jsonkeys[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}

								jjj = 0;
								fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
								if (!fieldtypes) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								jjj++;
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < jjj; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}

								if (oph_json_add_grid
								    (oper_json, OPH_JSON_OBJKEY_CLUSTER_LIST, "Reserved partitions", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									for (iii = 0; iii < num_fields; iii++)
										if (fieldtypes[iii])
											free(fieldtypes[iii]);
									if (fieldtypes)
										free(fieldtypes);
									break;
								}
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								for (iii = 0; iii < num_fields; iii++)
									if (fieldtypes[iii])
										free(fieldtypes[iii]);
								if (fieldtypes)
									free(fieldtypes);

								success = 2;
							}

							// Data
							if (success == 2)
								success = 0;
							while (!success) {
								for (idp = 0; idp < list.size; ++idp) {
									jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
									if (!jsonvalues) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										break;
									}
									jjj = 0;
									jsonvalues[jjj] = strdup(list.name && list.name[idp] ? list.name[idp] : OPH_UNKNOWN);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									jsonvalues[jjj] = strdup(list.ctime && list.ctime[idp] ? list.ctime[idp] : OPH_UNKNOWN);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%s", list.pid
										 && list.pid[idp] ? OPH_OPERATOR_CLUSTER_VALUE_COMPUTE : OPH_OPERATOR_CLUSTER_VALUE_IO);
									jsonvalues[jjj] = strdup(tmp);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%d", list.id ? list.id[idp] : 0);
									jsonvalues[jjj] = strdup(tmp);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									jsonvalues[jjj] = strdup(list.wid[idp] ? OPH_ODB_STATUS_PENDING_STR : OPH_ODB_STATUS_RUNNING_STR);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									jsonvalues[jjj] = strdup(list.max_status && list.max_status[idp] ? list.max_status[idp] : OPH_UNKNOWN);
									if (!jsonvalues[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_CLUSTER_LIST, jsonvalues)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
										for (iii = 0; iii < num_fields; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									for (iii = 0; iii < num_fields; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
								}
								if (idp >= list.size)
									success = 2;
								else
									break;
							}

							if (success == 2) {
								if (!list.size)
									snprintf(tmp, OPH_MAX_STRING_SIZE, "No partition found");
								else
									snprintf(tmp, OPH_MAX_STRING_SIZE, "Found %d partition%s", list.size, list.size == 1 ? "" : "s");
								if (oph_json_is_objkey_printable(objkeys, objkeys_num, OPH_JSON_OBJKEY_CLUSTER_LIST_SUMMARY)
								    && oph_json_add_text(oper_json, OPH_JSON_OBJKEY_CLUSTER_LIST_SUMMARY, "Summary", tmp)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD TEXT error\n");
									success = 0;
								} else
									success = 1;
							}
#else
							snprintf(error_message, OPH_MAX_STRING_SIZE, "This option is disabled in this implementation!");
#endif

							break;
						}

					case 2:{

							if (!host_partition) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "'%s' is a reserved word!", OPH_OPERATOR_CLUSTER_PARAMETER_ALL);
								break;
							}

							if (oph_get_available_host_number(&available_hosts, idjob)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of available hosts cannot be retrieved\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of available hosts!");
								break;
							}
							if (!available_hosts) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "No host available");
								break;
							}
							if (max_hosts) {
								int rhosts = 0;
								if (oph_odb_get_reserved_hosts(&oDB, id_user, &rhosts)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Number of reserved hosts of '%s' cannot be retrieved\n", username);
									snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to retrieve number of reserved hosts!");
									break;
								}
								if (!nhosts) {
									nhosts = max_hosts - rhosts;
									if (nhosts <= 0) {
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Reached the maximum number of reserved hosts: no host available");
										break;
									}
								}
								if (rhosts + nhosts > max_hosts) {
									nhosts = max_hosts - rhosts;
									if (nhosts <= 0) {
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Reached the maximum number of reserved hosts: no host available");
										break;
									}
									if (nhosts > available_hosts)
										nhosts = available_hosts;
									snprintf(error_message, OPH_MAX_STRING_SIZE, "Reached the maximum number of reserved hosts: only %d host%s available", nhosts,
										 nhosts == 1 ? " is" : "s are");
									break;
								}
							} else if (!nhosts)
								nhosts = available_hosts;
							if (nhosts > available_hosts) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Eccessive host number: only %d host%s available", available_hosts,
									 available_hosts == 1 ? " is" : "s are");
								break;
							}

							int id_hostpartition = 0;
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Reserving host partition '%s'\n", host_partition);
							if (oph_odb_reserve_hp(&oDB, host_partition, id_user, idjob, nhosts, host_type, &id_hostpartition)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Host partition '%s' cannot be reserved\n", host_partition);
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to create host partition '%s', maybe it already exists!", host_partition);
								break;
							}
							if (!id_hostpartition) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to create host partition '%s', maybe it already exists!", host_partition);
								break;
							}

							char command[OPH_MAX_STRING_SIZE];
							snprintf(command, OPH_MAX_STRING_SIZE, "%d", id_hostpartition);

							char outfile[OPH_MAX_STRING_SIZE];
							snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_NULL_FILENAME);
							if (get_debug_level() == LOG_DEBUG) {
								char code[OPH_MAX_STRING_SIZE];
								if (!oph_get_session_code(sessionid, code)) {
									if (oph_subm_user && strcasecmp(os_username, oph_subm_user)) {
										snprintf(outfile, OPH_MAX_STRING_SIZE, "%s/%s", oph_txt_location, os_username);
										oph_mkdir(outfile);
										snprintf(outfile, OPH_MAX_STRING_SIZE, "%s/" OPH_TXT_FILENAME, oph_txt_location, os_username, code, markerid);
									} else
										snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_TXT_FILENAME, oph_txt_location, code, markerid);
								}
							}

							char *cmd = NULL;
							if (oph_form_subm_string(command, nhosts, outfile, 0, orm, idjob, os_username, project, wid, &cmd, 1 + host_type)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on forming submission string\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to set submission string!");
								if (cmd) {
									free(cmd);
									cmd = NULL;
								}
								break;
							}
							if (!cmd) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on forming submission string\n");
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to set submission string!");
								break;
							}
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Submitting command: %s\n", cmd);

							snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_INFO, OPH_SEPARATOR_KV, "Cluster has been stopped", OPH_SEPARATOR_PARAM);
							success = !oph_system(cmd, tmp, state, 0, em, &oph_odb_release_hp2, id_hostpartition);
							free(cmd);

							if (!success) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Error during remote submission!");
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s\n", error_message);
								break;
							}

							if (!em)
								oph_detach_task(idjob);

							snprintf(error_message, OPH_MAX_STRING_SIZE, "Host partition '%s' correctly reserved", host_partition);
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
							break;
						}

					case 3:{

							if (!host_partition) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "'%s' is a reserved word!", OPH_OPERATOR_CLUSTER_PARAMETER_ALL);
								break;
							}

							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Retrieving host partition '%s'\n", host_partition);
							int id_hostpartition = 0, id_job = 0;
							if (oph_odb_retrieve_hp(&oDB, host_partition, id_user, &id_hostpartition, &id_job, &host_type)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Host partition '%s' not found\n", host_partition);
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to find host partition '%s'!", host_partition);
								break;
							}
							if (!id_hostpartition) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to find host partition '%s'!", host_partition);
								break;
							}

							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Undeploying cluster associated with host partition '%s' (%d)\n", host_partition,
								   id_hostpartition);
							if ((!host_type && oph_stop_request(id_job, os_username)) || (host_type && oph_umount_request(id_job, os_username)))
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to stop host partition '%s'", host_partition);
							else
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Host partition '%s' correctly released", host_partition);
							oph_remove_detached_task(id_job);

							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Releasing host partition '%s' (%d)\n", host_partition, id_hostpartition);
							if (oph_odb_release_hp(&oDB, id_hostpartition)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Host partition '%s' cannot be released\n", host_partition);
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to delete host partition '%s'!", host_partition);
								break;
							}

							success = 1;
							break;
						}

					default:;
				}

				break;
			}
		}

		oph_odb_free_ophidiadb_list(&list);
		oph_odb_free_ophidiadb_list(&user_list);

		while (!success2) {
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success2 = 1;
		}
		if (success)
			success = success2;

		if (task_tbl)
			hashtbl_destroy(task_tbl);
		oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);

		if (success)
			*error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}

	return error;
}
