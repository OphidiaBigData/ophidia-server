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

#include "oph_known_operators.h"

#include "oph_flow_control_operators.h"
#include "oph_management_operators.h"

#include "oph_ophidiadb.h"
#include "oph_json_library.h"
#include "oph_task_parser_library.h"
#include "oph_workflow_engine.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_finalize_known_operator(int idjob, oph_json * oper_json, const char *operator_name, char *error_message, int success, char **response, ophidiadb * oDB, enum oph__oph_odb_job_status *exit_code)
{
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Finalize known operator: %s (%s)\n", success ? "success" : "failure", error_message ? error_message : "-");

	char *jstring = NULL;
	if (oper_json) {
		int return_code = 0;

		if (!success) {
			if (!strlen(error_message)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Operator '%s' failed!", operator_name);
				if (exit_code)
					*exit_code = OPH_ODB_STATUS_ERROR;
			}
			if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "ADD TEXT error\n");
				return_code = -1;
			} else if (oph_write_and_get_json(oper_json, &jstring)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "JSON file creation error\n");
				return_code = -1;
			}
		} else {
			if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", strlen(error_message) ? error_message : NULL)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "ADD TEXT error\n");
				return_code = -1;
			} else if (oph_write_and_get_json(oper_json, &jstring)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "JSON file creation error\n");
				return_code = -1;
			} else if (exit_code && (*exit_code != OPH_ODB_STATUS_WAIT))
				*exit_code = OPH_ODB_STATUS_COMPLETED;
		}
		oph_json_free(oper_json);

		if (return_code && exit_code)
			*exit_code = OPH_ODB_STATUS_ERROR;

	} else if (exit_code)
		*exit_code = OPH_ODB_STATUS_ERROR;

	if (!jstring) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Unable to convert JSON Response into a string\n");
		if (exit_code)
			*exit_code = OPH_ODB_STATUS_ERROR;
		oph_odb_disconnect_from_ophidiadb(oDB);
		return OPH_SERVER_SYSTEM_ERROR;
	}
	if (response)
		*response = jstring;
	else
		free(jstring);

	// Set ODB_STATUS to COMPLETED
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Finalize OphDB status\n");
	if (exit_code && (*exit_code == OPH_ODB_STATUS_WAIT))
		oph_odb_set_job_status(idjob, OPH_ODB_STATUS_WAIT, oDB);
	else
		oph_odb_stop_job_fast(idjob, oDB);
	oph_odb_disconnect_from_ophidiadb(oDB);

	return OPH_SERVER_OK;
}

int oph_serve_known_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id, int *light_task_id,
			     int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, char *username, char *project)
{
	int error = OPH_SERVER_UNKNOWN;
	if (exit_code)
		*exit_code = OPH_ODB_STATUS_ERROR;
	if (exit_output)
		*exit_output = 1;

	if (!request) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Submission string not found\n");
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (!sessionid) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s not found\n", OPH_ARG_SESSIONID);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (!markerid) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s not found\n", OPH_ARG_MARKERID);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}

	char operator_name[OPH_MAX_STRING_SIZE];
	if (oph_tp_find_param_in_task_string(request, OPH_ARG_OPERATOR, operator_name)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s not found\n", OPH_ARG_OPERATOR);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}

	if ((error =
	     oph_serve_flow_control_operator(state, request, ncores, sessionid, markerid, odb_wf_id, task_id, light_task_id, odb_jobid, response, jobid_response, exit_code, exit_output, username,
					     operator_name)) != OPH_SERVER_UNKNOWN)
		return error;

	if ((error =
	     oph_serve_management_operator(state, request, ncores, sessionid, markerid, odb_wf_id, task_id, light_task_id, odb_jobid, response, jobid_response, exit_code, exit_output, username,
					   project, operator_name)) != OPH_SERVER_UNKNOWN)
		return error;

	return error;
}
