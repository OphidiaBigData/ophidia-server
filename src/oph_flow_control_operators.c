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

#define _GNU_SOURCE

#include "oph_flow_control_operators.h"

#include "oph_ophidiadb.h"
#include "oph_json_library.h"
#include "oph_workflow_engine.h"
#include "oph_subset_library.h"
#include "oph_service_info.h"

#include <math.h>
#include <time.h>
#include <curl/curl.h>

#ifdef MATHEVAL_SUPPORT
#include <matheval.h>
#define OPH_FLOW_EVAL "EVAL("
#endif

#define OPH_FS_COMMAND "operator=oph_fs;command=ls;file=%s;sessionid=%s;workflowid=%d;markerid=%d;taskindex=%d;lighttaskindex=-1;username=%s;userid=%d;userrole=%d;parentid=%d;"
#define OPH_FS_GRID_CLASS "grid"
#define OPH_FS_GRID_NAME "fs"
#define OPH_FS_GRID_TYPE "T"
#define OPH_FS_GRID_OBJECT "OBJECT"
#define OPH_FS_TYPE_FILE "f"
#define OPH_FS_MEASURE "measure=%s;"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_mutex_t curl_flag;
extern pthread_cond_t waiting_flag;
#endif
extern char *oph_base_src_path;
extern char *oph_web_server_location;
extern oph_service_info *service_info;

extern int oph_finalize_known_operator(int idjob, oph_json * oper_json, const char *operator_name, char *error_message, int success, char **response, ophidiadb * oDB,
				       enum oph__oph_odb_job_status *exit_code);

int _oph_wait_stat(oph_workflow * wf, int task_index, char *command, char *markerid, struct oph_plugin_data *state)
{
	int success = 1;

	int response = 0, _odb_wf_id = wf->idjob, _task_id = task_index, saved_idjob = wf->tasks[task_index].idjob;
	wf->tasks[task_index].idjob = 0;	// Set for internel operations

	response = oph_serve_request(command, 1, wf->sessionid, markerid, "", state, &_odb_wf_id, &_task_id, NULL, NULL, 0, NULL, NULL, NULL, NULL, wf->os_username, wf->project, wf->workflowid);

	if (response) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to scan file system: error %s. Aborting...\n", response);
		return -1;
	}

	pthread_mutex_lock(&global_flag);
	while (!wf->tasks[task_index].response) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Waiting for scanning report\n");
		pthread_cond_wait(&waiting_flag, &global_flag);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "A file scanning report is arrived\n");
	}
	pthread_mutex_unlock(&global_flag);

	wf->tasks[task_index].idjob = saved_idjob;

	if (wf->tasks[task_index].response && !strlen(wf->tasks[task_index].response)) {
		free(wf->tasks[task_index].response);
		wf->tasks[task_index].response = NULL;
	}

	if (wf->tasks[task_index].status > OPH_ODB_STATUS_COMPLETED) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Scanning result is %s. Aborting...\n", oph_odb_convert_status_to_str(wf->tasks[task_index].status));
		return -2;
	}

	unsigned int i, j;
	oph_json *oper_json = NULL;
	oph_json_obj_grid *grid_json = NULL;
	while (success && wf->tasks[task_index].response) {
		if (oph_json_from_json_string(&oper_json, wf->tasks[task_index].response)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in parsing JSON Response\n");
			break;
		}
		for (i = 0; i < oper_json->responseKeyset_num; ++i)
			if (!strcmp(oper_json->responseKeyset[i], OPH_FS_GRID_NAME))
				break;
		if ((i >= oper_json->responseKeyset_num) || (i >= oper_json->response_num) || strcmp(oper_json->response[i].objclass, OPH_FS_GRID_CLASS)
		    || strcmp(oper_json->response[i].objkey, OPH_FS_GRID_NAME)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Grid '%s' not found in JSON Response\n", OPH_FS_GRID_NAME);
			break;
		}
		grid_json = (oph_json_obj_grid *) oper_json->response[i].objcontent;
		if ((grid_json->keys_num != 2) || (grid_json->values_num2 != 2) || strcmp(grid_json->keys[0], OPH_FS_GRID_TYPE) || strcmp(grid_json->keys[1], OPH_FS_GRID_OBJECT)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Grid '%s' is not correct in JSON Response\n", OPH_FS_GRID_NAME);
			break;
		}
		for (j = 0; j < grid_json->values_num1; ++j)
			if (!strcmp(grid_json->values[j][0], OPH_FS_TYPE_FILE) && grid_json->values[j][1]) {
				success = 0;	// The file already exists
				break;
			}
		break;
	}
	if (oper_json)
		oph_json_free(oper_json);

	// Remove the intermediate response to set real response of OPH_WAIT
	if (wf->tasks[task_index].response) {
		free(wf->tasks[task_index].response);
		wf->tasks[task_index].response = NULL;
	}

	return success;
}

void *_oph_wait(oph_notify_data * data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
#endif

	if (!data || !data->data) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading input data\n");
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#ifdef OPH_DB_SUPPORT
		mysql_thread_end();
#endif
#endif
		return NULL;
	}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_incr(service_info);
#endif

	oph_workflow *wf = data->wf;
	int task_index = data->task_index, idjob = 0, pidjob = 0, status, success = 1;
	struct oph_plugin_data *state = data->state;
	char *json_output = data->json_output;
	oph_wait_data *wd = (oph_wait_data *) data->data;
	char _filename[OPH_MAX_STRING_SIZE], tmp[OPH_MAX_STRING_SIZE], fast_exit = 0;
	CURL *curl = NULL;
	char *pointer = wd->filename, *is_http = NULL;
	char *sessionid = strdup(wf->sessionid);
	char save_flag = wf->tasks[task_index].save;
	int markerid = wf->tasks[task_index].markerid;

	// Init
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Initialize waiting procedure\n");
	switch (wd->type) {
		case 'f':
			while (pointer && (*pointer == ' '))
				pointer++;
			if (!pointer) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Empty parameter '%s'\n", OPH_OPERATOR_PARAMETER_FILENAME);
				success = 0;
				break;
			}
			if ((is_http = strstr(pointer, "http"))) {
				curl = curl_easy_init();
				if (!curl) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to check remote objects\n");
					success = 0;
					break;
				}
				curl_easy_setopt(curl, CURLOPT_URL, pointer);
				curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
				curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "CURL options set\n");
				strcpy(_filename, pointer);
			} else if (oph_base_src_path && strlen(oph_base_src_path))
				snprintf(_filename, OPH_MAX_STRING_SIZE, "%s%s%s", oph_base_src_path, *pointer == '/' ? "" : "/", pointer);
			else if (!oph_get_session_code(wf->sessionid, tmp))
				snprintf(_filename, OPH_MAX_STRING_SIZE, OPH_SESSION_MISCELLANEA_FOLDER_TEMPLATE "%s%s", oph_web_server_location, tmp, *pointer == '/' ? "" : "/", pointer);
			else {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error in extracting session code from '%s'\n", wf->sessionid);
				success = 0;
			}
		case 'c':
		case 'i':
			break;
		default:
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error in parsing input data\n");
			success = 0;
	}

	char command[OPH_MAX_STRING_SIZE];
	char str_markerid[OPH_SHORT_STRING_SIZE];
	snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].markerid);
	if (success && !is_http && (wd->type == 'f')) {
		char measure[OPH_MAX_STRING_SIZE];
		if (wd->measure)
			snprintf(measure, OPH_MAX_STRING_SIZE, OPH_FS_MEASURE, wd->measure);
		snprintf(command, OPH_MAX_STRING_SIZE, OPH_FS_COMMAND "%s%s" OPH_SERVER_REQUEST_FLAG, pointer, sessionid, wf->workflowid, markerid, task_index, wf->username, wf->iduser, wf->userrole,
			 wf->idjob, wd->measure ? measure : "", wd->subset_params ? wd->subset_params : "");
	} else
		*command = 0;

	// Process
	if (success) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Process waiting procedure\n");

		int counter;
		CURLcode res;

		pthread_mutex_lock(&global_flag);
		status = wf->tasks[task_index].status;
		pthread_mutex_unlock(&global_flag);

		do {
			if ((wd->type == 'f') && (status == (int) OPH_ODB_STATUS_WAIT)) {
				if (curl) {
					pthread_mutex_lock(&curl_flag);
					if (curl_easy_perform(curl) == CURLE_OK)
						success = 0;
					pthread_mutex_unlock(&curl_flag);
				} else {
					success = _oph_wait_stat(wf, task_index, command, str_markerid, state);
					if (success < 0) {
						pthread_mutex_lock(&global_flag);
						status = wf->tasks[task_index].status = OPH_ODB_STATUS_ERROR;
						pthread_mutex_unlock(&global_flag);
						break;
					}
				}
				if (!success) {
					success = 1;
					pthread_mutex_lock(&global_flag);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "File '%s' already exists\n", _filename);
					status = wf->tasks[task_index].status = OPH_ODB_STATUS_COMPLETED;
					pthread_mutex_unlock(&global_flag);
					break;
				}
			}

			counter = 0;
			while ((status == (int) OPH_ODB_STATUS_WAIT) && ((wd->timeout < 0) || (counter < wd->timeout))) {

				pthread_mutex_lock(&global_flag);
				if (wf->waiting_tasks_num >= 0)
					wf->waiting_tasks_num++;
				else
					wf->waiting_tasks_num--;
				pthread_mutex_unlock(&global_flag);

				sleep(1);
				counter++;

				pthread_mutex_lock(&global_flag);
				if (wf->status < (int) OPH_ODB_STATUS_COMPLETED)
					status = wf->tasks[task_index].status;
				else
					status = wf->tasks[task_index].status = OPH_ODB_STATUS_ERROR;
				if (wf->waiting_tasks_num > 0)
					wf->waiting_tasks_num--;
				else {
					wf->waiting_tasks_num++;
					if (!wf->waiting_tasks_num) {
						status = OPH_ODB_STATUS_ABORTED;
						fast_exit = 1;
					}
				}
				pthread_mutex_unlock(&global_flag);
			}

			if (status == (int) OPH_ODB_STATUS_WAIT) {
				switch (wd->type) {
					case 'f':
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Check if the object '%s' exists\n", _filename);
						if (curl) {
							pthread_mutex_lock(&curl_flag);
							res = curl_easy_perform(curl);
							pthread_mutex_unlock(&curl_flag);
							if (res != CURLE_OK) {
								pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Object '%s' is not reachable: %s\n", _filename, curl_easy_strerror(res));
								break;
							}
						} else if ((success = _oph_wait_stat(wf, task_index, command, str_markerid, state))) {
							if (success < 0) {
								pthread_mutex_lock(&global_flag);
								status = wf->tasks[task_index].status = OPH_ODB_STATUS_ERROR;
								pthread_mutex_unlock(&global_flag);
							} else
								pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "File '%s' does not exist\n", _filename);
							break;
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "File '%s' exists\n", _filename);
					case 'c':
					case 'i':
					default:
						pthread_mutex_lock(&global_flag);
						status = wf->tasks[task_index].status = OPH_ODB_STATUS_COMPLETED;
						pthread_mutex_unlock(&global_flag);
				}
			}

		} while (status == (int) OPH_ODB_STATUS_WAIT);

		pthread_mutex_lock(&global_flag);

		idjob = wf->tasks[task_index].idjob;
		pidjob = wf->idjob;
		if (status < (int) OPH_ODB_STATUS_COMPLETED)
			status = wf->tasks[task_index].status = success < 0 ? OPH_ODB_STATUS_ERROR : OPH_ODB_STATUS_COMPLETED;

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Task '%s' of workflow '%s' stops to wait (current status is %s).\n", wf->tasks[task_index].name, wf->name, oph_odb_convert_status_to_str(status));

		pthread_mutex_unlock(&global_flag);
	}
	// Finalize
	int jobid = 0;
	ophidiadb oDB;
	while (success && idjob && pidjob) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Finalize waiting procedure\n");

		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			break;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			break;
		}
		success = status == OPH_ODB_STATUS_COMPLETED;
		if (success)
			oph_odb_stop_job_fast(idjob, &oDB);
		else
			oph_odb_abort_job_fast(idjob, &oDB);

		oph_odb_disconnect_from_ophidiadb(&oDB);

		if (state && state->jobid && !fast_exit) {

			pthread_mutex_lock(&global_flag);
			jobid = ++*state->jobid;
			pthread_mutex_unlock(&global_flag);

			wf->tasks[task_index].status = OPH_ODB_STATUS_RUNNING;	// Force notification process

			if (!success) {
				oph_json *oper_json = NULL;
				while (json_output) {
					if (oph_json_from_json_string(&oper_json, json_output)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in parsing JSON Response\n");
						break;
					}
					int i, j;
					for (i = 0; i < oper_json->responseKeyset_num; ++i)
						if (!strcmp(oper_json->responseKeyset[i], OPH_JSON_OBJKEY_STATUS))
							break;
					if ((i >= oper_json->responseKeyset_num) || (i >= oper_json->response_num) || strcmp(oper_json->response[i].objclass, OPH_JSON_TEXT)
					    || strcmp(oper_json->response[i].objkey, OPH_JSON_OBJKEY_STATUS)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Text not found in JSON Response\n");
						break;
					}
					oph_json_obj_text *obj = NULL;
					for (j = 0; j < oper_json->response[i].objcontent_num; ++j)
						if (oper_json->response[i].objcontent) {
							obj = (oph_json_obj_text *) (oper_json->response[i].objcontent) + j;
							if (obj) {
								if (obj->title)
									free(obj->title);
								obj->title = strdup("ERROR");
								if (obj->message)
									free(obj->message);
								obj->message = strdup("Operation cannot be executed: check input arguments");
								break;
							}
						}
					free(json_output);
					json_output = NULL;
					if (oph_write_and_get_json(oper_json, &json_output))
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in writing JSON Response\n");
					break;
				}
				if (oper_json)
					oph_json_free(oper_json);
			}

			int response = 0;
			char success_notification[OPH_MAX_STRING_SIZE];
			snprintf(success_notification, OPH_MAX_STRING_SIZE, "%s=%d;%s=%d;%s=%d;%s=%d;%s=%d;%s=%s;%s=%s;%s=%s;%s", OPH_ARG_STATUS, status, OPH_ARG_JOBID, idjob, OPH_ARG_PARENTID,
				 pidjob, OPH_ARG_TASKINDEX, task_index, OPH_ARG_LIGHTTASKINDEX, -1, OPH_ARG_SESSIONID, sessionid, OPH_ARG_MARKERID, str_markerid, OPH_ARG_SAVE,
				 save_flag ? OPH_COMMON_YES : OPH_COMMON_NO, data->add_to_notify ? data->add_to_notify : "");
			oph_workflow_notify(state, 'W', jobid, success_notification, json_output, &response);
			if (response && (response != OPH_SERVER_WRONG_PARAMETER_ERROR))
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "W%d: error %d in notify\n", jobid, response);
		}

		break;
	}

	// Free
	if (curl)
		curl_easy_cleanup(curl);
	if (json_output)
		free(json_output);
	if (state) {
		if (state->serverid)
			free(state->serverid);
		free(state);
	}
	if (data->add_to_notify)
		free(data->add_to_notify);
	if (wd) {
		if (wd->filename)
			free(wd->filename);
		if (wd->measure)
			free(wd->measure);
		if (wd->subset_params)
			free(wd->subset_params);
		free(wd);
	}
	free(data);
	if (fast_exit)
		oph_workflow_free(wf);
	if (sessionid)
		free(sessionid);

	if (jobid)
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "W%d: exit from waiting procedure\n", jobid);
	else
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Exit from waiting procedure\n");

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif

	return NULL;
}

// Thread unsafe
int oph_set_status_of_selection_block(oph_workflow * wf, int task_index, enum oph__oph_odb_job_status status, int parent, int nk, char skip_the_next, int *exit_output)
{
	if (wf->tasks[task_index].dependents_indexes_num) {
		if (!wf->tasks[task_index].dependents_indexes) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		int i, j, k, res, gparent, found;
		for (k = 0; k < wf->tasks[task_index].dependents_indexes_num; ++k) {
			if (nk < 0)
				nk = k;
			i = wf->tasks[task_index].dependents_indexes[k];
			if (wf->tasks[i].parent == parent) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found '%s' child of task '%s' of workflow '%s' with %d branches\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name,
				      wf->tasks[i].branch_num);
				if (strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE))
					wf->tasks[i].is_skipped = skip_the_next;
				else if (wf->tasks[i].branch_num > 1) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Drop dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
					wf->tasks[parent].dependents_indexes[nk] = parent;
					found = 0;
					for (j = 0; j < wf->tasks[i].deps_num; ++j)
						if (wf->tasks[i].deps[j].task_index == task_index) {
							wf->tasks[i].deps[j].task_index = i;
							found = 1;
						}
					if (found)
						wf->tasks[i].residual_deps_num--;
				} else {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Set dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
					wf->tasks[parent].dependents_indexes[nk] = i;
					for (j = 0; j < wf->tasks[i].deps_num; ++j)
						if (wf->tasks[i].deps[j].task_index == task_index)
							wf->tasks[i].deps[j].task_index = parent;
					if (exit_output && !strncasecmp(wf->tasks[parent].operator, OPH_OPERATOR_IF, OPH_MAX_STRING_SIZE) && !wf->tasks[parent].forward)
						*exit_output = 0;
				}
				continue;
			}
			gparent = oph_gparent_of(wf, parent);
			if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE) && (wf->tasks[i].parent == gparent)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Drop dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
				wf->tasks[parent].dependents_indexes[nk] = i;
				wf->tasks[gparent].dependents_indexes[nk] = i;
				found = 0;
				for (j = 0; j < wf->tasks[i].deps_num; ++j)
					if (wf->tasks[i].deps[j].task_index == task_index) {
						wf->tasks[i].deps[j].task_index = gparent;
						found = 1;
					}
				if (found)
					wf->tasks[i].residual_deps_num--;
			} else {
				if (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED) {
					if (!wf->residual_tasks_num) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "Number of residual tasks of '%s' cannot be reduced\n", wf->tasks[i].name);
						return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
					}
					wf->residual_tasks_num--;
				}
				wf->tasks[i].status = status;
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Status of '%s' is set to '%s'\n", wf->tasks[i].name, oph_odb_convert_status_to_str(status));
				if ((res = oph_set_status_of_selection_block(wf, i, status, parent, nk, skip_the_next, exit_output)))
					return res;
			}
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_if_impl(oph_workflow * wf, int i, char *error_message, int *exit_output)
{
	*error_message = 0;

	int j;
	char check = 0;
	if (!wf->tasks[i].is_skipped) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract arguments of task '%s'.\n", wf->tasks[i].name);

		char *arg_value, *condition = NULL, *error_msg = NULL;

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j = 0; j < wf->tasks[i].arguments_num; ++j)
			if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_CONDITION)) {
				arg_value = strdup(wf->tasks[i].arguments_values[j]);
				if (!arg_value)
					break;
				if (oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, OPH_OPERATOR_PARAMETER_CONDITION)) {
					free(arg_value);
					break;
				}
				condition = arg_value;
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_FORWARD)) {
				char *forward_value = strdup(wf->tasks[i].arguments_values[j]);
				if (oph_workflow_var_substitute(wf, i, -1, &forward_value, &error_msg, OPH_OPERATOR_PARAMETER_FORWARD)) {
					free(forward_value);
					break;
				}
				if (!strcasecmp(forward_value, OPH_COMMON_YES))
					wf->tasks[i].forward = 1;
				else if (strcasecmp(forward_value, OPH_COMMON_NO)) {
					error_msg = strdup("Wrong parameter 'forward'!");
					free(forward_value);
					break;
				}
				free(forward_value);
			}
		if (error_msg) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", error_msg);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			free(error_msg);
			if (condition)
				free(condition);
			return OPH_SERVER_ERROR;
		}
#ifdef MATHEVAL_SUPPORT
		if (condition && strlen(condition)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Evaluate expression '%s'.\n", condition);

			// Evaluate expression
			int count;
			char **names;
			void *me = evaluator_create(condition);
			if (!me) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong expression '%s'!", condition);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				free(condition);
				return OPH_SERVER_ERROR;
			}
			evaluator_get_variables(me, &names, &count);
			if (count > 0) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Too variables in the expression '%s'!", condition);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				evaluator_destroy(me);
				free(condition);
				return OPH_SERVER_ERROR;
			}
			double return_value = evaluator_evaluate(me, count, names, NULL);
			evaluator_destroy(me);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Expression '%s' = %f.\n", condition, return_value);
			if (isnan(return_value) || isinf(return_value)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong condition '%s'!", condition);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				free(condition);
				return OPH_SERVER_ERROR;
			}
			// In case condition is not satisfied...
			if (!return_value)
				wf->tasks[i].is_skipped = 1;
		}
#endif
		check = 1;
		if (condition)
			free(condition);
	}
	if (wf->tasks[i].is_skipped) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Skip the selection block associated with task '%s'.\n", wf->tasks[i].name);

		// Skip this sub-block
		if (oph_set_status_of_selection_block(wf, i, OPH_ODB_STATUS_UNSELECTED, i, -1, !check, exit_output)) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Error in updating the status of dependents of '%s'.", wf->tasks[i].name);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s\n", error_message);
		}
		if (check)
			wf->tasks[i].is_skipped = 0;
	} else			// Condition is satisfied
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Execute the selection block associated with task '%s'.\n", wf->tasks[i].name);

		for (j = 0; j < wf->tasks_num; ++j)
			if ((wf->tasks[j].parent == i) && strncasecmp(wf->tasks[j].operator, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE)) {
				wf->tasks[j].is_skipped = 1;
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Task '%s' and related branch of workflow '%s' will be skipped.\n", wf->tasks[j].name, wf->name);
			}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_else_impl(oph_workflow * wf, int i, char *error_message, int *exit_output)
{
	*error_message = 0;

	if (wf->tasks[i].is_skipped) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Skip the selection block associated with task '%s'.\n", wf->tasks[i].name);

		// Skip this sub-block
		if (oph_set_status_of_selection_block(wf, i, OPH_ODB_STATUS_UNSELECTED, i, -1, 0, exit_output)) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Error in updating the status of dependents of '%s'.", wf->tasks[i].name);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s\n", error_message);
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_extract_from_json(char **key, const char *json_string)
{
	if (!key || !(*key) || !json_string)
		return OPH_SERVER_ERROR;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parsing '%s'\n", *key);
	char tmp[1 + strlen(*key)], *pch = NULL, *save_pointer = NULL, *target = NULL, *objkey = NULL, *title = NULL, *colkey = NULL, *row = NULL, *col = NULL;
	strcpy(tmp, *key);

	int step = 0;
	while ((pch = strtok_r(pch ? NULL : tmp, OPH_WORKFLOW_OBJECT, &save_pointer))) {
		switch (step) {
			case 0:
				objkey = pch;
				break;
			case 1:
				title = pch;
				break;
			case 2:
				colkey = pch;
				break;
			default:
				return OPH_SERVER_ERROR;
		}
		target = pch;
		step++;
	}
	if (!step)
		return OPH_SERVER_ERROR;

	while (1) {
		pch = strchr(target, OPH_WORKFLOW_BRACKET_BEGIN[0]);
		step = 0;

		if (!pch)
			break;
		*pch = 0;
		row = pch + 1;
		step = 1;	// Bracket open

		pch = strchr(row, OPH_WORKFLOW_SEPARATORS[3]);
		if (!pch) {
			pch = strchr(row, OPH_WORKFLOW_BRACKET_END[0]);
			if (!pch)
				break;
			if (!title && !colkey)
				break;
			*pch = 0;
			step = 2;	// Bracket closed, row by index, col by name
			break;
		}
		*pch = 0;
		col = pch + 1;
		step = 3;	// Bracket open, row and col by index

		pch = strchr(col, OPH_WORKFLOW_BRACKET_END[0]);
		if (!pch)
			break;
		*pch = 0;
		step = 4;	// Bracket closed, row and col by index

		break;
	}
	if (!pch && step) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: syntax error at step %d\n", step);
		return OPH_SERVER_ERROR;
	}

	oph_json *json = NULL;
	if (oph_json_from_json_string_unsafe(&json, json_string)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: json lookup failed\n");
		oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	unsigned int i, j = 0, k = json->response_num;
	for (i = 0; i < json->response_num; ++i)
		if (json->response && json->response[i].objkey && !strcmp(json->response[i].objkey, objkey))
			break;
	if (i >= json->response_num) {
		if (colkey) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objkey not found\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		// Let us assume the form title[.colname]
		colkey = title;
		title = objkey;
		for (i = 0; i < json->response_num; ++i)
			if (json->response && json->response[i].objkey && json->response[i].objclass) {
				if (!strcmp(json->response[i].objclass, OPH_JSON_TEXT)) {
					oph_json_obj_text *obj = NULL;
					for (j = 0; j < json->response[i].objcontent_num; ++j)
						if (json->response[i].objcontent) {
							obj = (oph_json_obj_text *) (json->response[i].objcontent) + j;
							if (obj && obj->title && !strcmp(obj->title, title)) {
								if (k < json->response_num)
									break;
								else
									k = i;
							}
						}
				} else if (!strcmp(json->response[i].objclass, OPH_JSON_GRID)) {
					oph_json_obj_grid *obj = NULL;
					for (j = 0; j < json->response[i].objcontent_num; ++j)
						if (json->response[i].objcontent) {
							obj = (oph_json_obj_grid *) (json->response[i].objcontent) + j;
							if (obj && obj->title && !strcmp(obj->title, title)) {
								if (k < json->response_num)
									break;
								else
									k = i;
							}
						}
				}
				if (j < json->response[i].objcontent_num)
					break;
			}

		if (i < json->response_num) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: more than one objcontent found\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		} else if (k >= json->response_num) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		i = k;
		objkey = json->response[i].objkey;
	}

	if (!json->response[i].objclass) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objclass not found\n");
		oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	unsigned int objcontent_num = 0;
	k = json->response[i].objcontent_num;
	if (!strcmp(json->response[i].objclass, OPH_JSON_TEXT)) {
		oph_json_obj_text *obj = NULL;
		for (j = 0; j < json->response[i].objcontent_num; ++j)
			if (json->response[i].objcontent) {
				obj = (oph_json_obj_text *) (json->response[i].objcontent) + j;
				if (obj) {
					objcontent_num++;
					if (title) {
						if (obj->title && !strcmp(obj->title, title))
							break;
					} else
						k = j;
				}
			}
		if ((j >= json->response[i].objcontent_num) && (title || (objcontent_num != 1))) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		if (!title) {
			obj = (oph_json_obj_text *) (json->response[i].objcontent) + k;
			title = obj->title;
			if (!title) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
				oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		free(*key);
		*key = strdup(obj->message);
		if (!(*key)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Key updated to '%s'\n", *key);
	} else if (!strcmp(json->response[i].objclass, OPH_JSON_GRID)) {
		oph_json_obj_grid *obj = NULL;
		for (j = 0; j < json->response[i].objcontent_num; ++j)
			if (json->response[i].objcontent) {
				obj = (oph_json_obj_grid *) (json->response[i].objcontent) + j;
				if (obj) {
					objcontent_num++;
					if (title) {
						if (obj->title && !strcmp(obj->title, title))
							break;
					} else
						k = j;
				}
			}
		if ((j >= json->response[i].objcontent_num) && (title || (objcontent_num != 1))) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		if (!title) {
			obj = (oph_json_obj_grid *) (json->response[i].objcontent) + k;
			title = obj->title;
			if (!title) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
				oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		unsigned int irow = 0, icol = 0;
		char all_values = 0;
		if (colkey) {
			if (obj->keys)
				for (; icol < obj->keys_num; ++icol)
					if (!strcmp(obj->keys[icol], colkey))
						break;
			if (!obj->keys || (icol >= obj->keys_num)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: rowkey not found\n");
				oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found key '%s' at column %d\n", colkey, icol);
		} else {
			if (col && !strcmp(col, OPH_WORKFLOW_GENERIC_VALUE))
				all_values = 2;
			else if (col && !strcmp(col, OPH_WORKFLOW_END_VALUE))
				icol = obj->values_num2 - 1;	// Non 'C'-like indexing
			else {
				icol = col ? (unsigned int) strtol(col, NULL, 10) : 0;
				if (icol)
					icol--;	// Non 'C'-like indexing
			}
		}
		if (row && !strcmp(row, OPH_WORKFLOW_GENERIC_VALUE)) {
			if (all_values) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: only scalars and vectors can be extracted\n");
				oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
			all_values = 1;
		} else if (row && !strcmp(row, OPH_WORKFLOW_END_VALUE))
			irow = obj->values_num1 - 1;	// Non 'C'-like indexing
		else {
			irow = row ? (unsigned int) strtol(row, NULL, 10) : 0;
			if (irow)
				irow--;	// Non 'C'-like indexing
		}

		if ((irow >= obj->values_num1) || (icol >= obj->values_num2)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: index out of boundaries\n");
			oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		free(*key);
		*key = NULL;

		char *tmp_key = NULL;
		switch (all_values) {
			case 1:	// All the rows
				if (obj->values_num1)
					*key = strdup(obj->values[0][icol]);
				for (irow = 1; irow < obj->values_num1; irow++) {
					tmp_key = *key;
					*key = (char *) malloc(strlen(tmp_key) + 2 + strlen(obj->values[irow][icol]));
					if (!(*key)) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
						if (tmp_key)
							free(tmp_key);
						oph_json_free(json);
						return OPH_SERVER_ERROR;
					}
					sprintf(*key, "%s%s%s", tmp_key, OPH_SEPARATOR_SUBPARAM_STR, obj->values[irow][icol]);
					if (tmp_key)
						free(tmp_key);
					tmp_key = NULL;
				}
				break;
			case 2:	// All the columns
				if (obj->values_num2)
					*key = strdup(obj->values[irow][0]);
				for (icol = 1; icol < obj->values_num2; icol++) {
					tmp_key = *key;
					*key = (char *) malloc(strlen(tmp_key) + 2 + strlen(obj->values[irow][icol]));
					if (!(*key)) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
						if (tmp_key)
							free(tmp_key);
						oph_json_free(json);
						return OPH_SERVER_ERROR;
					}
					sprintf(*key, "%s%s%s", tmp_key, OPH_SEPARATOR_SUBPARAM_STR, obj->values[irow][icol]);
					if (tmp_key)
						free(tmp_key);
					tmp_key = NULL;
				}
				break;
			default:
				*key = strdup(obj->values[irow][icol]);
				if (!(*key)) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
					oph_json_free(json);
					return OPH_SERVER_ERROR;
				}
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Key '%s' updated to '%s'\n", title, *key);

	} else {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objclass not supported\n");
		oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	oph_json_free(json);
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_check_input_response(oph_workflow * wf, int i, char ***svalues, int *svalues_num, char *arg_value)
{
	if (!wf || !svalues || !svalues_num || !arg_value)
		return OPH_SERVER_NULL_POINTER;
	*svalues = NULL;
	*svalues_num = 0;

	int h, hh, kk = 0;
	char *tmp = strdup(arg_value), expansion, *pch, *pch1, *save_pointer = NULL;
	if (!tmp)
		return OPH_SERVER_NULL_POINTER;
	if (!strlen(tmp)) {
		free(tmp);
		return OPH_SERVER_OK;
	}
	do {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Values parsing: %s\n", tmp);
		expansion = *svalues_num = 0;
		pch = strchr(tmp, OPH_SEPARATOR_SUBPARAM);
		for (++*svalues_num; pch; ++*svalues_num) {
			pch1 = pch + 1;
			if (!pch1 || !*pch1)
				break;
			pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %d values\n", *svalues_num);
		*svalues = (char **) calloc(*svalues_num, sizeof(char *));
		if (!*svalues)
			break;
		pch = strtok_r(tmp, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
		for (kk = 0; pch && (kk < *svalues_num); ++kk) {
			(*svalues)[kk] = strndup(pch, OPH_WORKFLOW_MAX_STRING);
			if (!(*svalues)[kk])
				break;
			for (h = 0; h < wf->tasks_num; ++h)
				if (wf->tasks[h].response) {
					for (hh = 0; hh < wf->tasks[h].dependents_indexes_num; ++hh)
						if (wf->tasks[h].dependents_indexes[hh] == i) {
							if (!oph_extract_from_json(*svalues + kk, wf->tasks[h].response))	// Found a correspondence
							{
								if (strchr((*svalues)[kk], OPH_SEPARATOR_SUBPARAM)) {
									hh = 0;
									char expanded_value[1 + strlen(arg_value) + strlen((*svalues)[kk])];
									for (h = 0; h < kk; ++h)
										hh = sprintf(expanded_value + hh, "%s%c", (*svalues)[h], OPH_SEPARATOR_SUBPARAM);
									hh = sprintf(expanded_value + hh, "%s", (*svalues)[kk]);
									pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
									if (pch)
										sprintf(expanded_value + hh, "%c%s", OPH_SEPARATOR_SUBPARAM, pch);
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "Values expansion: %s\n", expanded_value);
									free(tmp);
									tmp = strdup(expanded_value);
									for (h = 0; h <= kk; ++h)
										free((*svalues)[h]);
									free(*svalues);
									expansion = 1;
								}
								break;
							}
						}
					if (expansion || (hh < wf->tasks[h].dependents_indexes_num))
						break;
				}
			if (!expansion)
				pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
		}
	}
	while (expansion);
	free(tmp);

	if (kk < *svalues_num)
		return OPH_SERVER_ERROR;

#ifdef MATHEVAL_SUPPORT
	int count = 0;
	unsigned int bracket, n, nchar;
	char **names = NULL, *start, *stop, *base, flag;
	void *me = NULL;
	double return_value;
	for (kk = 0; kk < *svalues_num; ++kk) {

		tmp = (*svalues)[kk];
		if (tmp && strlen(tmp)) {

			char tmp2[OPH_MAX_STRING_SIZE];
			*tmp2 = 0;
			base = tmp;
			flag = n = 0;

			while (base && ((start = strstr(base, OPH_FLOW_EVAL)))) {

				if (start > base) {
					nchar = start - base;
					if (nchar >= OPH_MAX_STRING_SIZE - strlen(tmp2))
						break;
					snprintf(tmp2 + n, 1 + nchar, "%s", base);
					n += nchar;
				}

				stop = start += strlen(OPH_FLOW_EVAL);
				bracket = 1;
				while (stop && *stop && bracket) {
					if (*stop == OPH_WORKFLOW_BRACKET_BEGIN[0])
						bracket++;
					else if (*stop == OPH_WORKFLOW_BRACKET_END[0]) {
						bracket--;
						if (!bracket)
							break;
					}
					stop++;
				}
				if (!stop || !*stop || bracket)
					break;

				if (stop > start) {

					char expr[1 + stop - start];
					strncpy(expr, start, stop - start);
					expr[stop - start] = 0;

					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Try to evaluate expression '%s'.\n", expr);
					me = evaluator_create(expr);
					if (!me)
						break;
					evaluator_get_variables(me, &names, &count);
					if (count > 0) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Variables are not admitted in expression '%s'.\n", expr);
						evaluator_destroy(me);
						break;
					}
					return_value = evaluator_evaluate(me, count, names, NULL);
					evaluator_destroy(me);

					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Expression '%s' = %f.\n", expr, return_value);
					if (isnan(return_value) || isinf(return_value))
						break;

					n += snprintf(tmp2 + n, OPH_MAX_STRING_SIZE - strlen(tmp2), "%f", return_value);
				}

				base = stop + (*stop ? 1 : 0);
				flag = 1;
			}

			if (!flag)
				continue;

			n += snprintf(tmp2 + n, OPH_MAX_STRING_SIZE - strlen(tmp2), "%s", base);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Value[%d] = %s.\n", kk, tmp2);
			free((*svalues)[kk]);
			(*svalues)[kk] = strdup(tmp2);
		}
	}
#endif

	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_set_impl(oph_workflow * wf, int i, char *error_message, struct oph_plugin_data *state, char has_action)
{
	*error_message = 0;

	char *name = NULL, **names = NULL, **svalues = NULL;
	int j, kk = 0, names_num = 0, svalues_num = 0, num, wid = 0, tt = -1, ttt;
	unsigned int kkk, lll = strlen(OPH_WORKFLOW_SEPARATORS);
	char *arg_value, *error_msg = NULL, *taskname = NULL, first = 1, repeat = 0, compress_value = 0;
	oph_workflow *twf = wf;
	enum oph__oph_odb_job_status caction = OPH_ODB_STATUS_RUNNING;
	double offset = 1;

	int success = 0, ret = OPH_SERVER_OK;
	while (!success) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract arguments of task '%s'.\n", wf->tasks[i].name);

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			arg_value = strdup(wf->tasks[i].arguments_values[j]);
			if (!arg_value) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Memory error!");
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) {
					free(error_msg);
					error_msg = NULL;
				}
				break;
			}

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", wf->tasks[i].arguments_keys[j], wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, wf->tasks[i].arguments_keys[j])) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) {
					free(error_msg);
					error_msg = NULL;
				}
				free(arg_value);
				break;
			}

			if (!name && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_KEY))
				name = wf->tasks[i].arguments_values[j];	// it should not be 'arg_value'!
			else if (!svalues && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_VALUE) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				if (oph_check_input_response(wf, i, &svalues, &svalues_num, arg_value)) {
					free(arg_value);
					break;
				}
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_SUBSET_FILTER)) {
				if (!strcasecmp(arg_value, OPH_COMMON_YES))
					compress_value = 1;
				else if (!strcasecmp(arg_value, OPH_COMMON_REAL))
					compress_value = 2;
				else if (strcasecmp(arg_value, OPH_COMMON_NO)) {
					snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong value for parameter '%s'!", OPH_ARG_SUBSET_FILTER);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
					free(arg_value);
					break;
				}
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_OFFSET)) {
				offset = strtod(arg_value, NULL);
				if (offset < 0) {
					snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong value for parameter '%s'!", OPH_ARG_OFFSET);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
					free(arg_value);
					break;
				}
			} else if (!wid && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_ID)) {
				wid = strtol(arg_value, NULL, 10);
				if (!wid)
					wid = wf->workflowid;
				else if (wid != wf->workflowid) {
					oph_job_info *item = NULL;
					if ((wid <= 0) || !(item = oph_find_workflow_in_job_list(state->job_info, wf->sessionid, wid))) {
						snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong workflow identifier '%d'!", wid);
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
						free(arg_value);
						break;
					}
					twf = item->wf;
				}
			} else if (has_action) {
				if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_ACTION)) {
					if (!strcmp(arg_value, OPH_OPERATOR_INPUT_PARAMETER_ACTION_ABORT))
						caction = OPH_ODB_STATUS_ERROR;
					else if (!strcmp(arg_value, OPH_OPERATOR_INPUT_PARAMETER_ACTION_WAIT))
						caction = OPH_ODB_STATUS_WAIT;
					else if (strcmp(arg_value, OPH_OPERATOR_INPUT_PARAMETER_ACTION_CONTINUE)) {
						snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong action '%s'!", arg_value);
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
						free(arg_value);
						break;
					}
				} else if (!taskname && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_TASKNAME))
					taskname = strdup(arg_value);
			}
			free(arg_value);
		}
		if ((j < wf->tasks[i].arguments_num) || error_msg) {
			if (!strlen(error_message)) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, error_msg ? error_msg : "Generic error in parsing arguments of task '%s'.", wf->tasks[i].name);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			}
			if (error_msg) {
				free(error_msg);
				error_msg = NULL;
			}
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (name) {
			arg_value = strdup(name);
			if (!arg_value)
				break;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", OPH_ARG_KEY, wf->tasks[i].name);
			oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, OPH_ARG_KEY);

			char *tmp = arg_value, *pch, *pch1, *save_pointer = NULL;
			pch = strchr(tmp, OPH_SEPARATOR_SUBPARAM);
			for (names_num++; pch; names_num++) {
				pch1 = pch + 1;
				if (!pch1 || !*pch1)
					break;
				pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
			}
			names = (char **) malloc(names_num * sizeof(char *));
			if (!names)
				break;
			pch = strtok_r(tmp, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
			for (kk = 0; kk < names_num; ++kk) {
				names[kk] = strndup(pch, OPH_WORKFLOW_MAX_STRING);
				if (!names[kk])
					break;
				pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
			}
			free(tmp);
			if (kk < names_num)
				break;

			for (j = 0; j < names_num; ++j) {

				name = names[j];
				if (name)
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check compliance of variable name '%s' of task '%s' with IEEE Std 1003.1-2001 conventions.\n", name, wf->tasks[i].name);
				for (kk = 0; name && (kk < (int) strlen(name)); ++kk)	// check compliance with IEEE Std 1003.1-2001 conventions
				{
					if ((name[kk] == '_') || ((name[kk] >= 'A') && (name[kk] <= 'Z')) || ((name[kk] >= 'a') && (name[kk] <= 'z'))
					    || (kk && (name[kk] >= '0') && (name[kk] <= '9')))
						continue;
					for (kkk = 0; kkk < lll; ++kkk)
						if (name[kk] == OPH_WORKFLOW_SEPARATORS[kkk]) {
							name = NULL;
							break;
						}
					if (name)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Change variable name '%s'.", name);
					break;
				}
				if (!name)
					break;
			}
			if (!name) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad argument '%s'.", OPH_ARG_KEY);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
		}
		if (!name && !has_action) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad argument '%s'.", OPH_ARG_KEY);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (!svalues_num)
			svalues_num = names_num;

		if (svalues_num < names_num) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad number of keys in parameter '%s'.", OPH_ARG_VALUE);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (has_action) {
			if (!taskname)
				taskname = strdup("Task 0");
			int implicit_target = -1;
			for (tt = 0; tt < twf->tasks_num; ++tt)
				if (!strcmp(twf->tasks[tt].operator, OPH_OPERATOR_WAIT)) {
					if (!strcmp(twf->tasks[tt].name, taskname))
						break;
					if (implicit_target < 0)
						implicit_target = tt;
					else
						implicit_target = twf->tasks_num;
				}
			if ((tt >= twf->tasks_num) && (implicit_target >= 0))
				tt = implicit_target;
			if (tt >= twf->tasks_num) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Invalid task name, task not found or ambiguous!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
		}

		num = svalues_num > names_num ? svalues_num : names_num;
		for (j = 0; j < num; repeat ? repeat = 0 : ++j) {

			if (j < names_num) {
				if (first && !j) {
					repeat = 1;
					first = 0;
					ttt = asprintf(&name, "%s_1", names[0]);
					if (ttt < 0) {
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
						ret = OPH_SERVER_ERROR;
						break;
					}
				} else {
					name = names[j];
					ttt = -1;
				}
			} else {
				ttt = asprintf(&name, "%s_%d", names[0], j - names_num + 2);
				if (ttt < 0) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
					ret = OPH_SERVER_ERROR;
					break;
				}
			}

			// Drop the previous value
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Drop variable '%s'\n", name);
			hashtbl_remove(twf->vars, name);

			oph_workflow_var var;
			void *var_buffer;
			size_t var_size = sizeof(oph_workflow_var), svalue_size;
			var.caller = wid != wf->workflowid ? -1 : i;
			var.ivalue = 1 + j;	// Non C-like indexing
			if (svalues) {
				if (repeat || j)
					var.svalue = strdup(svalues[j]);
				else {	// Consider the whole array
					int jj, tttt;
					char *array_value = NULL, *previous_value = NULL;
					for (jj = 0; jj < svalues_num; ++jj, previous_value = array_value) {
						tttt = asprintf(&array_value, "%s%s%s", previous_value ? previous_value : "", jj ? OPH_SEPARATOR_SUBPARAM_STR : "", svalues[jj]);
						if (previous_value)
							free(previous_value);
						if (tttt < 0)
							break;
					}
					if (jj < svalues_num)	// In case of errors
						array_value = NULL;
					var.svalue = array_value ? array_value : strdup(svalues[j]);
				}
			} else {
				var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
				if (var.svalue)
					snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", var.ivalue);
			}
			if (!var.svalue) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				if (ttt >= 0)
					free(name);
				ret = OPH_SERVER_ERROR;
				break;
			}
			// Check for compression
			if (compress_value == 1) {
				long long l_offset = (long long) offset;
				if (l_offset > 0) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Try to compress variable '%s' in environment of workflow '%s'\n", name, twf->name);
					char flag = 0, first = 0;
					long long current, start, end;
					char *base_string = strdup(var.svalue);
					char *final_string = strdup(var.svalue);
					char *pch = NULL, *save_pointer = NULL;
					unsigned int n = 0;
					*final_string = 0;
					while ((pch = strtok_r(pch ? NULL : base_string, OPH_SUBSET_LIB_SUBSET_SEPARATOR, &save_pointer))) {
						current = strtoll(pch, NULL, 10);
						if (flag) {
							if (current == end + l_offset) {
								end = current;
								flag = 2;
							} else {
								if (flag > 1)
									n += sprintf(final_string + n, "%s%lld%s%lld", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start,
										     OPH_SUBSET_LIB_PARAM_SEPARATOR, end);
								else
									n += sprintf(final_string + n, "%s%lld", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start);
								first = 1;
								start = end = current;
								flag = 1;
							}
						} else {
							start = end = current;
							flag = 1;
						}
					}
					if (flag) {
						if (flag > 1)
							n += sprintf(final_string + n, "%s%lld%s%lld", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start, OPH_SUBSET_LIB_PARAM_SEPARATOR, end);
						else
							n += sprintf(final_string + n, "%s%lld", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start);
						free(var.svalue);
						var.svalue = final_string;
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Variable '%s' in environment of workflow '%s' has been compressed\n", name, twf->name);
					} else
						free(final_string);
					free(base_string);
				}
			} else if (offset && (compress_value == 2)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Try to compress variable '%s' in environment of workflow '%s'\n", name, twf->name);
				char flag = 0, first = 0;
				double current, start, end, half_offset = offset / 2.0;
				char *base_string = strdup(var.svalue);
				char *final_string = strdup(var.svalue);
				char *pch = NULL, *save_pointer = NULL;
				unsigned int n = 0;
				*final_string = 0;
				while ((pch = strtok_r(pch ? NULL : base_string, OPH_SUBSET_LIB_SUBSET_SEPARATOR, &save_pointer))) {
					current = strtod(pch, NULL);
					if (flag) {
						if (fabs(current - (end + offset)) < half_offset) {
							end = current;
							flag = 2;
						} else {
							if (flag > 1)
								n += sprintf(final_string + n, "%s%g%s%g", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start - half_offset,
									     OPH_SUBSET_LIB_PARAM_SEPARATOR, end + half_offset);
							else
								n += sprintf(final_string + n, "%s%g", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start);
							first = 1;
							start = end = current;
							flag = 1;
						}
					} else {
						start = end = current;
						flag = 1;
					}
				}
				if (flag) {
					if (flag > 1)
						n += sprintf(final_string + n, "%s%g%s%g", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start - half_offset, OPH_SUBSET_LIB_PARAM_SEPARATOR,
							     end + half_offset);
					else
						n += sprintf(final_string + n, "%s%g", first ? OPH_SUBSET_LIB_SUBSET_SEPARATOR : "", start);
					free(var.svalue);
					var.svalue = final_string;
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Variable '%s' in environment of workflow '%s' has been compressed\n", name, twf->name);
				} else
					free(final_string);
				free(base_string);
			}

			svalue_size = strlen(var.svalue) + 1;
			var_buffer = malloc(var_size + svalue_size);
			if (!var_buffer) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				if (ttt >= 0)
					free(name);
				free(var.svalue);
				break;
			}
			memcpy(var_buffer, (void *) &var, var_size);
			memcpy(var_buffer + var_size, var.svalue, svalue_size);
			if (hashtbl_insert_with_size(twf->vars, name, var_buffer, var_size + svalue_size)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to store variable '%s' in environment of workflow '%s'. Maybe it already exists.", name, twf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				if (ttt >= 0)
					free(name);
				free(var.svalue);
				free(var_buffer);
				break;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s' in environment of workflow '%s'.\n", name, twf->name);

			if (ttt >= 0)
				free(name);
			free(var.svalue);
			free(var_buffer);
		}

		if (has_action && (twf->tasks[tt].status < (int) caction)) {
			twf->tasks[tt].status = caction;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Change status of task '%s' of workflow '%s' to %s.\n", twf->tasks[tt].name, twf->name,
			      oph_odb_convert_status_to_str(twf->tasks[tt].status));
		}

		success = 1;
	}

	if (names) {
		for (kk = 0; kk < names_num; ++kk)
			if (names[kk])
				free(names[kk]);
		free(names);
	}
	if (svalues) {
		for (kk = 0; kk < svalues_num; ++kk)
			if (svalues[kk])
				free(svalues[kk]);
		free(svalues);
	}
	if (taskname)
		free(taskname);

	return ret;
}

// Thread unsafe
int oph_for_impl(oph_workflow * wf, int i, char *error_message)
{
	*error_message = 0;

	char *name = NULL, **svalues = NULL, mode = 0;
	int *ivalues = NULL;	// If not allocated then it is equal to [1:values_num]
	int j, kk = 0, svalues_num = 0, ivalues_num = 0;
	unsigned int kkk, lll = strlen(OPH_WORKFLOW_SEPARATORS);
	long value;
	char *arg_value, *error_msg = NULL;

	int success = 0, ret = OPH_SERVER_OK;
	while (!success) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract arguments of task '%s'.\n", wf->tasks[i].name);

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			arg_value = strdup(wf->tasks[i].arguments_values[j]);
			if (!arg_value) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Memory error!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) {
					free(error_msg);
					error_msg = NULL;
				}
				break;
			}

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", wf->tasks[i].arguments_keys[j], wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, wf->tasks[i].arguments_keys[j])) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) {
					free(error_msg);
					error_msg = NULL;
				}
				free(arg_value);
				break;
			}

			if (!name && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_KEY))
				name = wf->tasks[i].arguments_values[j];	// it should not be 'arg_value'!
			else if (!svalues && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_VALUES) && strlen(arg_value) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				if (oph_check_input_response(wf, i, &svalues, &svalues_num, arg_value)) {
					free(arg_value);
					break;
				}
			} else if (!mode && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_PARALLEL)) {
				if (!strcasecmp(arg_value, OPH_COMMON_YES))
					mode = 1;
				else if (strcasecmp(arg_value, OPH_COMMON_NO)) {
					free(arg_value);
					break;
				}
			}
			free(arg_value);
		}
		if ((j < wf->tasks[i].arguments_num) || error_msg) {
			if (!strlen(error_message)) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, error_msg ? error_msg : "Generic error in parsing arguments of task '%s'.", wf->tasks[i].name);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			}
			if (error_msg) {
				free(error_msg);
				error_msg = NULL;
			}
			ret = OPH_SERVER_ERROR;
			break;
		}
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			arg_value = strdup(wf->tasks[i].arguments_values[j]);
			if (!arg_value)
				break;
			oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, wf->tasks[i].arguments_keys[j]);

			if (!ivalues && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_COUNTER) && strlen(arg_value) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				oph_subset *subset_struct = NULL;
				if (oph_subset_init(&subset_struct)) {
					oph_subset_free(subset_struct);
					free(arg_value);
					break;
				}
				if (oph_subset_parse(arg_value, strlen(arg_value), subset_struct, svalues_num)) {
					oph_subset_free(subset_struct);
					free(arg_value);
					break;
				}
				ivalues_num = subset_struct->total;
				ivalues = (int *) malloc(ivalues_num * sizeof(int));
				if (!ivalues) {
					oph_subset_free(subset_struct);
					free(arg_value);
					break;
				}
				for (kk = kkk = 0; (kk < ivalues_num) && (kkk < subset_struct->number); ++kkk) {
					value = subset_struct->start[kkk];
					do {
						ivalues[kk++] = (int) value;
						value += subset_struct->stride[kkk];
					}
					while ((kk < ivalues_num) && (value <= subset_struct->end[kkk]));
				}
				oph_subset_free(subset_struct);
			}
			free(arg_value);
		}
		if ((j < wf->tasks[i].arguments_num) || error_msg) {
			if (!strlen(error_message)) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, error_msg ? error_msg : "Generic error in parsing arguments of task '%s'.", wf->tasks[i].name);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			}
			if (error_msg) {
				free(error_msg);
				error_msg = NULL;
			}
			ret = OPH_SERVER_ERROR;
			break;
		}

		arg_value = NULL;
		if (name) {
			arg_value = strdup(name);
			if (arg_value) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", OPH_ARG_KEY, wf->tasks[i].name);
				oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, OPH_ARG_KEY);
				name = arg_value;
			}
		}

		if (name)
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check compliance of variable name '%s' of task '%s' with IEEE Std 1003.1-2001 conventions.\n", name, wf->tasks[i].name);
		for (kk = 0; name && (kk < (int) strlen(name)); ++kk)	// check compliance with IEEE Std 1003.1-2001 conventions
		{
			if ((name[kk] == '_') || ((name[kk] >= 'A') && (name[kk] <= 'Z')) || ((name[kk] >= 'a') && (name[kk] <= 'z')) || (kk && (name[kk] >= '0') && (name[kk] <= '9')))
				continue;
			for (kkk = 0; kkk < lll; ++kkk)
				if (name[kk] == OPH_WORKFLOW_SEPARATORS[kkk]) {
					name = NULL;
					break;
				}
			if (name)
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Change variable name '%s'.", name);
			break;
		}
		if (!name) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad argument '%s'.", OPH_ARG_KEY);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			if (arg_value)
				free(arg_value);
			break;
		}

		if (mode) {
			if (ivalues) {
				free(ivalues);
				ivalues = NULL;
			}
			if (svalues) {
				for (kk = 0; kk < svalues_num; ++kk)
					if (svalues[kk])
						free(svalues[kk]);
				free(svalues);
				svalues = NULL;
			}
			svalues_num = 1;	// Parallel for involves only one loop
		} else if (svalues_num) {
			if (ivalues_num && (ivalues_num != svalues_num)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Arguments '%s' and '%s' have different sizes.", OPH_ARG_VALUES, OPH_OPERATOR_PARAMETER_COUNTER);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				if (arg_value)
					free(arg_value);
				break;
			}
		} else
			svalues_num = ivalues_num ? ivalues_num : 1;	// One loop is executed by default

		if (!mode && (svalues_num > 0)) {
			oph_workflow_var var;
			void *var_buffer;
			size_t var_size = sizeof(oph_workflow_var), svalue_size;
			var.caller = i;
			if (ivalues)
				var.ivalue = ivalues[0];
			else
				var.ivalue = 1;	// Non C-like indexing
			if (svalues)
				var.svalue = strdup(svalues[0]);
			else {
				var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
				if (var.svalue)
					snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", var.ivalue);
			}
			if (!var.svalue) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				if (arg_value)
					free(arg_value);
				break;
			}
			svalue_size = strlen(var.svalue) + 1;
			var_buffer = malloc(var_size + svalue_size);
			if (!var_buffer) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				free(var.svalue);
				if (arg_value)
					free(arg_value);
				break;
			}
			memcpy(var_buffer, (void *) &var, var_size);
			memcpy(var_buffer + var_size, var.svalue, svalue_size);
			if (hashtbl_insert_with_size(wf->vars, name, var_buffer, var_size + svalue_size)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to store variable '%s' in environment of workflow '%s'. Maybe it already exists.", name, wf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				free(var.svalue);
				free(var_buffer);
				if (arg_value)
					free(arg_value);
				break;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s' in environment of workflow '%s'.\n", name, wf->name);
			free(var.svalue);
			free(var_buffer);

			// Push them into the stack, even in case only one loop has to be performed
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Push for-data into the stack of workflow '%s'.\n", wf->name);
			if (oph_workflow_push(wf, i, name, svalues, ivalues, svalues_num)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to push for-data into the stack of workflow '%s'.", wf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_SYSTEM_ERROR;
				if (arg_value)
					free(arg_value);
				break;
			}
		}

		if (arg_value)
			free(arg_value);

		success = 1;
	}

	if (!success) {
		if (ivalues)
			free(ivalues);
		if (svalues) {
			for (kk = 0; kk < svalues_num; ++kk)
				if (svalues[kk])
					free(svalues[kk]);
			free(svalues);
		}
	}

	return ret;
}

// Thread unsafe
int oph_endfor_impl(oph_workflow * wf, int i, char *error_message, oph_trash * trash, int *task_id, int *odb_jobid)
{
	*error_message = 0;

	// Find the data inserted by the parent within the stack
	oph_workflow_stack *tmp = wf->stack, *tmpp = NULL;
	while (tmp && (tmp->caller != wf->tasks[i].parent)) {
		tmpp = tmp;
		tmp = tmp->next;
	}
	if (tmp) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update index '%s' set by task '%s' in environment of workflow '%s'.\n", tmp->name, wf->tasks[tmp->caller].name, wf->name);

		tmp->index++;
		if (hashtbl_remove(wf->vars, tmp->name))	// Skip this in the last step to extend the scope of the variable to any descendent
		{
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to remove variable '%s' from environment of workflow '%s'.", tmp->name, wf->name);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (tmp->index < tmp->values_num) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Create variable '%s' to be stored in environment of workflow '%s'.\n", tmp->name, wf->name);
			oph_workflow_var var;
			void *var_buffer;
			size_t var_size = sizeof(oph_workflow_var), svalue_size;
			var.caller = tmp->caller;
			if (tmp->ivalues)
				var.ivalue = tmp->ivalues[tmp->index];
			else
				var.ivalue = 1 + tmp->index;	// Non C-like indexing
			if (tmp->svalues)
				var.svalue = strdup(tmp->svalues[tmp->index]);
			else {
				var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
				if (var.svalue)
					snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", var.ivalue);
			}
			if (!var.svalue) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			svalue_size = strlen(var.svalue) + 1;
			var_buffer = malloc(var_size + svalue_size);
			if (!var_buffer) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				free(var.svalue);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			memcpy(var_buffer, (void *) &var, var_size);
			memcpy(var_buffer + var_size, var.svalue, svalue_size);
			if (hashtbl_insert_with_size(wf->vars, tmp->name, var_buffer, var_size + svalue_size)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to update variable '%s' in environment of workflow '%s'.", tmp->name, wf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				free(var.svalue);
				free(var_buffer);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			if (tmp->svalues)
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update variable '%s=%s' in environment of workflow '%s'.\n", tmp->name, var.svalue, wf->name);
			else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update variable '%s=%d' in environment of workflow '%s'.\n", tmp->name, var.ivalue, wf->name);
			free(var.svalue);
			free(var_buffer);

			if (odb_jobid)	// Reset status
			{
				int p = wf->tasks[i].parent, tasks_num = 0;

				*odb_jobid = wf->tasks[p].idjob;	// Used to change 'jobid' in notification message to oph_for
				*task_id = p;	// Used to change 'taskindex' in notification message to oph_for

				oph_odb_remove_job(wf->tasks[i].idjob);	// Drop line of oph_endfor from OphDB

				if (oph_trash_append(trash, wf->sessionid, wf->tasks[i].markerid))
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Unable to release markerid.\n");
				else
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Release markerid '%d'.\n", wf->tasks[i].markerid);

				if (oph_workflow_reset_task(wf, wf->tasks[p].dependents_indexes, wf->tasks[p].dependents_indexes_num, i, tmp, &tasks_num)) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to reset task data from '%s'.", wf->tasks[p].name);
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				} else
					wf->residual_tasks_num += tasks_num;

				if (oph_workflow_disable_deps(wf, wf->tasks[p].dependents_indexes, wf->tasks[p].dependents_indexes_num, p, i)) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to disable dependencies task data from '%s'.", wf->tasks[p].name);
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				}

				if (wf->tasks[p].outputs_num) {
					oph_output_data_free(wf->tasks[p].outputs_keys, wf->tasks[p].outputs_num);
					oph_output_data_free(wf->tasks[p].outputs_values, wf->tasks[p].outputs_num);
					wf->tasks[p].outputs_num = 0;
					wf->tasks[p].outputs_keys = wf->tasks[p].outputs_values = NULL;
				}

				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Reset task '%s' of '%s' and start a new loop.\n", wf->tasks[i].name, wf->name);

				return OPH_SERVER_NO_RESPONSE;
			}
		} else
			wf->tasks[i].parallel_mode = 1;	// used to trasform the end-for in a massive operator

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Pop for-data from the stack of workflow '%s'.\n", wf->name);
		if (oph_workflow_pop(wf, tmpp)) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to pop for-data from the stack of workflow '%s'.", wf->name);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
			return OPH_SERVER_SYSTEM_ERROR;
		}
	} else {
		snprintf(error_message, OPH_MAX_STRING_SIZE, "No index found in environment of workflow '%s'.", wf->name);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
	}

	return OPH_SERVER_OK;
}

int oph_wait_impl(oph_workflow * wf, int i, char *error_message, char **message, oph_notify_data * data)
{
	*error_message = 0;

	char *name = NULL, **names = NULL, **svalues = NULL;
	int j, kk = 0, names_num = 0, svalues_num = 0;
	unsigned int kkk, lll = strlen(OPH_WORKFLOW_SEPARATORS);
	char *arg_value, *error_msg = NULL, *timeout = NULL, ttype = 'i', *input = NULL;
	char add_to_notify[OPH_MAX_STRING_SIZE], tmp[OPH_MAX_STRING_SIZE], subset_params[OPH_MAX_STRING_SIZE];
	*add_to_notify = *subset_params = 0;

	oph_wait_data *wd = (oph_wait_data *) malloc(sizeof(oph_wait_data));
	wd->type = 'c';
	wd->timeout = -1;
	wd->filename = NULL;
	wd->measure = NULL;
	wd->subset_params = NULL;
	data->data = (void *) wd;
	if (message)
		*message = NULL;

	int success = 0, ret = OPH_SERVER_OK;
	while (!success) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract arguments of task '%s'.\n", wf->tasks[i].name);

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			arg_value = strdup(wf->tasks[i].arguments_values[j]);
			if (!arg_value) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) {
					free(error_msg);
					error_msg = NULL;
				}
				break;
			}

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", wf->tasks[i].arguments_keys[j], wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, wf->tasks[i].arguments_keys[j])) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) {
					free(error_msg);
					error_msg = NULL;
				}
				free(arg_value);
				break;
			}

			if (!name && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_KEY) && strcasecmp(arg_value, OPH_COMMON_NULL))
				name = wf->tasks[i].arguments_values[j];	// it should not be 'arg_value'!
			else if (!svalues && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_VALUE) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				if (oph_check_input_response(wf, i, &svalues, &svalues_num, arg_value)) {
					free(arg_value);
					break;
				}
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_TYPE)) {
				if (!strcmp(arg_value, OPH_OPERATOR_WAIT_PARAMETER_TYPE_INPUT))
					wd->type = 'i';
				else if (!strcmp(arg_value, OPH_OPERATOR_WAIT_PARAMETER_TYPE_FILE))
					wd->type = 'f';
				else if (strcmp(arg_value, OPH_OPERATOR_WAIT_PARAMETER_TYPE_CLOCK)) {
					snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong type '%s'!", arg_value);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
					free(arg_value);
					break;
				}
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_TIMEOUT_TYPE)) {
				if (!strcmp(arg_value, OPH_OPERATOR_WAIT_PARAMETER_TTYPE_DEADLINE))
					ttype = 'd';
				else if (strcmp(arg_value, OPH_OPERATOR_WAIT_PARAMETER_TTYPE_DURATION)) {
					snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong timeout type '%s'!", arg_value);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
					free(arg_value);
					break;
				}
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_TIMEOUT)) {
				timeout = strdup(arg_value);
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_FILENAME) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				if (!wd->filename)
					wd->filename = strdup(arg_value);
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_INPUT) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				input = strdup(arg_value);
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_OUTPUT) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				if (wd->filename)
					free(wd->filename);
				wd->filename = strdup(arg_value);
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_MEASURE) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				if (!wd->measure)
					wd->measure = strdup(arg_value);
			} else if (message && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_MESSAGE) && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				*message = strdup(arg_value);
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_RUN)) {
				if (!strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_NO))
					data->run = 0;
				else if (strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_YES)) {
					snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Wrong value '%s' for parameter '%s'!", arg_value, OPH_OPERATOR_PARAMETER_RUN);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
					free(arg_value);
					break;
				}
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_CUBE)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_CUBE, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(add_to_notify, tmp, OPH_MAX_STRING_SIZE - strlen(add_to_notify));
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_CWD)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_CWD, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(add_to_notify, tmp, OPH_MAX_STRING_SIZE - strlen(add_to_notify));
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_OFFSET)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_OFFSET, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(subset_params, tmp, OPH_MAX_STRING_SIZE - strlen(subset_params));
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_TIME_FILTER)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_TIME_FILTER, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(subset_params, tmp, OPH_MAX_STRING_SIZE - strlen(subset_params));
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_SUBSET_DIMS)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_SUBSET_DIMS, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(subset_params, tmp, OPH_MAX_STRING_SIZE - strlen(subset_params));
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_SUBSET_TYPE)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_SUBSET_TYPE, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(subset_params, tmp, OPH_MAX_STRING_SIZE - strlen(subset_params));
			} else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_SUBSET_FILTER)) {
				snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_SUBSET_FILTER, OPH_SEPARATOR_KV, arg_value, OPH_SEPARATOR_PARAM);
				strncat(subset_params, tmp, OPH_MAX_STRING_SIZE - strlen(subset_params));
			}
			free(arg_value);
		}
		if ((j < wf->tasks[i].arguments_num) || error_msg) {
			if (!strlen(error_message)) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, error_msg ? error_msg : "Generic error in parsing arguments of task '%s'.", wf->tasks[i].name);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			}
			if (error_msg) {
				free(error_msg);
				error_msg = NULL;
			}
			if (input)
				free(input);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (wd->filename) {
			snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_ARG_FILE, OPH_SEPARATOR_KV, wd->filename, OPH_SEPARATOR_PARAM);
			strncat(add_to_notify, tmp, OPH_MAX_STRING_SIZE - strlen(add_to_notify));
		} else if (input) {
			snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s%s", OPH_OPERATOR_PARAMETER_OUTPUT, OPH_SEPARATOR_KV, input, OPH_SEPARATOR_PARAM);
			strncat(add_to_notify, tmp, OPH_MAX_STRING_SIZE - strlen(add_to_notify));
		}
		if (input)
			free(input);
		if (strlen(subset_params))
			wd->subset_params = strdup(subset_params);
		if (timeout) {
			if (ttype == 'd') {
				struct tm tm;
				time_t epoch;
				if (strptime(timeout, "%Y-%m-%d %H:%M:%S", &tm) != NULL) {
					tm.tm_isdst = -1;
					epoch = mktime(&tm);
				} else {
					snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Date conversion error in parsing the value '%s' for task '%s'!", timeout, wf->tasks[i].name);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
					ret = OPH_SERVER_ERROR;
					break;
				}
				time_t now;
				time(&now);
				wd->timeout = epoch - now;	// Ceiling
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Date %s has been converted into %d steps (until epoch %d since now %d)\n", timeout, wd->timeout, epoch, now);
			} else
				wd->timeout = (int) strtol(timeout, NULL, 10);
		}
		if (wd->timeout < 0) {
			if (wd->type != 'i') {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Timeout can be infinity only for type 'input'. Use a non-negative value!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
			snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Warning: setting infinite waiting time");
		}
		if ((wd->type == 'f') && (!wd->filename)) {
			snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "Empty parameter '%s'\n", OPH_OPERATOR_PARAMETER_FILENAME);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (name) {
			arg_value = strdup(name);
			if (!arg_value)
				break;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", OPH_ARG_KEY, wf->tasks[i].name);
			oph_workflow_var_substitute(wf, i, -1, &arg_value, &error_msg, OPH_ARG_KEY);

			char *tmp = arg_value, *pch, *pch1, *save_pointer = NULL;
			pch = strchr(tmp, OPH_SEPARATOR_SUBPARAM);
			for (names_num++; pch; names_num++) {
				pch1 = pch + 1;
				if (!pch1 || !*pch1)
					break;
				pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
			}
			names = (char **) malloc(names_num * sizeof(char *));
			if (!names)
				break;
			pch = strtok_r(tmp, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
			for (kk = 0; kk < names_num; ++kk) {
				names[kk] = strndup(pch, OPH_WORKFLOW_MAX_STRING);
				if (!names[kk])
					break;
				pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
			}
			free(tmp);
			if (kk < names_num)
				break;

			for (j = 0; j < names_num; ++j) {

				name = names[j];
				if (name)
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check compliance of variable name '%s' of task '%s' with IEEE Std 1003.1-2001 conventions.\n", name, wf->tasks[i].name);
				for (kk = 0; name && (kk < (int) strlen(name)); ++kk)	// check compliance with IEEE Std 1003.1-2001 conventions
				{
					if ((name[kk] == '_') || ((name[kk] >= 'A') && (name[kk] <= 'Z')) || ((name[kk] >= 'a') && (name[kk] <= 'z'))
					    || (kk && (name[kk] >= '0') && (name[kk] <= '9')))
						continue;
					for (kkk = 0; kkk < lll; ++kkk)
						if (name[kk] == OPH_WORKFLOW_SEPARATORS[kkk]) {
							name = NULL;
							break;
						}
					if (name)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Change variable name '%s'.", name);
					break;
				}
				if (!name)
					break;
			}
			if (!name) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad argument '%s'.", OPH_ARG_KEY);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
		}
		if (!svalues_num)
			svalues_num = names_num;

		if (svalues_num > names_num)
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Only the first %d value%s of the list will be considered\n", names_num, names_num == 1 ? "" : "s");
		if (svalues_num < names_num) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad number of keys in parameter '%s'.", OPH_ARG_VALUE);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			break;
		}

		oph_workflow_var var;
		void *var_buffer;
		size_t var_size = sizeof(oph_workflow_var), svalue_size;
		for (j = 0; j < names_num; ++j) {

			// Add the variable only in case it does not exist
			// otherwise do not drop the previous value;
			// this enables non-blocking input
			if (!hashtbl_get(wf->vars, names[j])) {

				var.caller = i;
				var.ivalue = 1 + j;	// Non C-like indexing
				if (svalues)
					var.svalue = strdup(svalues[j]);
				else {
					var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
					if (var.svalue)
						snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", var.ivalue);
				}
				if (!var.svalue) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
					ret = OPH_SERVER_ERROR;
					break;
				}
				svalue_size = strlen(var.svalue) + 1;
				var_buffer = malloc(var_size + svalue_size);
				if (!var_buffer) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Memory error.");
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
					ret = OPH_SERVER_ERROR;
					free(var.svalue);
					break;
				}
				memcpy(var_buffer, (void *) &var, var_size);
				memcpy(var_buffer + var_size, var.svalue, svalue_size);
				if (hashtbl_insert_with_size(wf->vars, names[j], var_buffer, var_size + svalue_size)) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to store variable '%s' in environment of workflow '%s'. Maybe it already exists.", name, wf->name);
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
					ret = OPH_SERVER_ERROR;
					free(var.svalue);
					free(var_buffer);
					break;
				}
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s' in environment of workflow '%s'.\n", names[j], wf->name);
				free(var.svalue);
				free(var_buffer);
			}
		}

		if (strlen(add_to_notify))
			data->add_to_notify = strdup(add_to_notify);

		wf->tasks[i].status = OPH_ODB_STATUS_WAIT;
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Change status of task '%s' of workflow '%s' to %s.\n", wf->tasks[i].name, wf->name, oph_odb_convert_status_to_str(wf->tasks[i].status));
		if (wf->status < (int) OPH_ODB_STATUS_RUNNING) {
			wf->status = OPH_ODB_STATUS_RUNNING;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Change status of workflow '%s' to %s.\n", wf->name, oph_odb_convert_status_to_str(wf->status));
		}
		if (wd->timeout >= 0)
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Task '%s' of workflow '%s' starts to wait %sfor %d second%s.\n", wf->tasks[i].name, wf->name, wd->timeout ? "" : "virtually ",
			      wd->timeout, wd->timeout == 1 ? "" : "s");
		else
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Task '%s' of workflow '%s' starts to wait indefinitely.\n", wf->tasks[i].name, wf->name);

		success = 1;
	}

	if (names) {
		for (kk = 0; kk < names_num; ++kk)
			if (names[kk])
				free(names[kk]);
		free(names);
	}
	if (svalues) {
		for (kk = 0; kk < svalues_num; ++kk)
			if (svalues[kk])
				free(svalues[kk]);
		free(svalues);
	}
	if (timeout)
		free(timeout);

	return ret;
}

int _oph_serve_flow_control_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id,
				     int *light_task_id, int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, const char *os_username,
				     const char *operator_name, pthread_t * tid)
{
	UNUSED(ncores);
	UNUSED(request);
	UNUSED(jobid_response);
	UNUSED(exit_output);
	UNUSED(os_username);

	int error = OPH_SERVER_UNKNOWN;

	if (!state) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Workflow list cannot be given\n");
		return error;
	}

	if (!strncasecmp(operator_name, OPH_OPERATOR_SET, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;

		int i = *task_id, idjob = wf->tasks[i].idjob;
		wf->tasks[i].is_known = 1;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

		if (success) {
			int ret = oph_set_impl(wf, i, error_message, state, 0);
			if (ret) {
				success = 0;
				if (ret == OPH_SERVER_SYSTEM_ERROR) {
					pthread_mutex_unlock(&global_flag);
					oph_json_free(oper_json);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
		}

		pthread_mutex_unlock(&global_flag);

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

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_FOR, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;

		int i = *task_id, idjob = wf->tasks[i].idjob;
		wf->tasks[i].is_known = 1;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

		if (success) {
			int ret = oph_for_impl(wf, i, error_message);
			if (ret) {
				success = 0;
				if (ret == OPH_SERVER_SYSTEM_ERROR) {
					pthread_mutex_unlock(&global_flag);
					oph_json_free(oper_json);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
		}

		pthread_mutex_unlock(&global_flag);

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

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_ENDFOR, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, ret;
		wf->tasks[i].is_known = 1;

		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in executing oph_endfor!");

		ret = oph_endfor_impl(wf, i, error_message, state->trash, task_id, odb_jobid);
		if (ret) {
			if (exit_code)
				*exit_code = OPH_ODB_STATUS_COMPLETED;
			pthread_mutex_unlock(&global_flag);
			return ret;
		}
		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

		pthread_mutex_unlock(&global_flag);

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

		if (oph_finalize_known_operator(wf->tasks[i].idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_IF, OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name, OPH_OPERATOR_ELSEIF, OPH_MAX_STRING_SIZE))	// oph_if, oph_elseif
	{
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;
		wf->tasks[i].is_known = 1;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

#ifdef MATHEVAL_SUPPORT
		if (success) {
			if (oph_if_impl(wf, i, error_message, exit_output))
				success = 0;
		}
#else
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Math expression parser is not enabled!");
		success = 0;
#endif

		pthread_mutex_unlock(&global_flag);

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

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_ELSE, OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE))	// oph_else, oph_endif
	{
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;
		wf->tasks[i].is_known = 1;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

		if (success && !strncasecmp(operator_name, OPH_OPERATOR_ELSE, OPH_MAX_STRING_SIZE)) {
			if (oph_else_impl(wf, i, error_message, exit_output))
				success = 0;
		}

		pthread_mutex_unlock(&global_flag);

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

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_WAIT, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;

		int i = *task_id, idjob = wf->tasks[i].idjob, first = wf->status < (int) OPH_ODB_STATUS_RUNNING;
		wf->tasks[i].is_known = 1;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

		oph_notify_data *data = NULL;
		if (success) {
			char *message = NULL;
			data = (oph_notify_data *) malloc(sizeof(oph_notify_data));
			if (!data) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Memory error.\n");
				pthread_mutex_unlock(&global_flag);
				oph_json_free(oper_json);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			data->wf = wf;
			data->task_index = i;
			data->json_output = NULL;
			data->add_to_notify = NULL;
			data->data = NULL;
			data->run = 1;
			data->detach = !tid;

			data->state = (struct oph_plugin_data *) malloc(sizeof(struct oph_plugin_data));
			if (!data->state) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Memory error.\n");
				pthread_mutex_unlock(&global_flag);
				oph_json_free(oper_json);
				free(data);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			memcpy(data->state, (struct oph_plugin_data *) state, sizeof(struct oph_plugin_data));
			if (state->serverid)
				data->state->serverid = strndup(state->serverid, OPH_MAX_STRING_SIZE);
			else
				data->state->serverid = NULL;
			data->state->is_copy = 1;
			data->state->job_info = state->job_info;

			int ret = oph_wait_impl(wf, i, error_message, &message, data);
			if (ret) {
				success = 0;
				if (ret == OPH_SERVER_SYSTEM_ERROR) {
					pthread_mutex_unlock(&global_flag);
					oph_json_free(oper_json);
					if (data->state) {
						if (data->state->serverid)
							free(data->state->serverid);
						free(data->state);
					}
					if (data->add_to_notify)
						free(data->add_to_notify);
					oph_wait_data *wd = (oph_wait_data *) data->data;
					if (wd) {
						if (wd->filename)
							free(wd->filename);
						if (wd->measure)
							free(wd->measure);
						if (wd->subset_params)
							free(wd->subset_params);
						free(wd);
					}
					free(data);
					if (message)
						free(message);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
			if (message) {
				oph_json_add_text(oper_json, OPH_JSON_OBJKEY_SUMMARY, "Interactive task", message);
				free(message);
			}
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (data) {
				if (data->state) {
					if (data->state->serverid)
						free(data->state->serverid);
					free(data->state);
				}
				if (data->add_to_notify)
					free(data->add_to_notify);
				oph_wait_data *wd = (oph_wait_data *) data->data;
				if (wd) {
					if (wd->filename)
						free(wd->filename);
					if (wd->measure)
						free(wd->measure);
					if (wd->subset_params)
						free(wd->subset_params);
					free(wd);
				}
				free(data);
			}
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (data) {
				if (data->state) {
					if (data->state->serverid)
						free(data->state->serverid);
					free(data->state);
				}
				if (data->add_to_notify)
					free(data->add_to_notify);
				oph_wait_data *wd = (oph_wait_data *) data->data;
				if (wd) {
					if (wd->filename)
						free(wd->filename);
					if (wd->measure)
						free(wd->measure);
					if (wd->subset_params)
						free(wd->subset_params);
					free(wd);
				}
				free(data);
			}
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success && first)
			oph_odb_start_job_fast(wf->idjob, &oDB);

		if (success && exit_code)
			*exit_code = OPH_ODB_STATUS_WAIT;
		if (success && !exit_code) {
			enum oph__oph_odb_job_status _exit_code = OPH_ODB_STATUS_WAIT;
			if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, &_exit_code))
				return OPH_SERVER_SYSTEM_ERROR;
		} else if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		if (data) {
			char run = data->run;
			if (success) {
				if (*response)
					data->json_output = strdup(*response);
				if (data->run) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Starting waiting procedure\n");
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
					pthread_t _tid;
					pthread_create(&_tid, NULL, (void *(*)(void *)) &_oph_wait, data);
					if (tid)
						*tid = _tid;
#else
					_oph_wait(data);
#endif
				}
			}
			if (!success || !run) {
				if (data->state) {
					if (data->state->serverid)
						free(data->state->serverid);
					free(data->state);
				}
				if (data->add_to_notify)
					free(data->add_to_notify);
				oph_wait_data *wd = (oph_wait_data *) data->data;
				if (wd) {
					if (wd->filename)
						free(wd->filename);
					if (wd->measure)
						free(wd->measure);
					if (wd->subset_params)
						free(wd->subset_params);
					free(wd);
				}
				free(data);
			}
		}

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_INPUT, OPH_MAX_STRING_SIZE)) {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute known operator '%s'\n", operator_name);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;
		wf->tasks[i].is_known = 1;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
			*error_message = 0;
		}

		if (success) {
			int ret = oph_set_impl(wf, i, error_message, state, 1);
			if (ret) {
				success = 0;
				if (ret == OPH_SERVER_SYSTEM_ERROR) {
					pthread_mutex_unlock(&global_flag);
					oph_json_free(oper_json);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
		}

		pthread_mutex_unlock(&global_flag);

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

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}

	return error;
}

int oph_serve_flow_control_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id,
				    int *light_task_id, int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, const char *os_username,
				    const char *operator_name)
{
	return _oph_serve_flow_control_operator(state, request, ncores, sessionid, markerid, odb_wf_id, task_id, light_task_id, odb_jobid, response, jobid_response, exit_code, exit_output,
						os_username, operator_name, NULL);
}
