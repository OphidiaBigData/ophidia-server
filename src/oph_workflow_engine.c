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

#define _GNU_SOURCE

#include "oph_workflow_engine.h"
#include "oph_parser.h"
#include "oph_utils.h"
#include "oph_memory_job.h"
#include "oph_json_library.h"
#include "oph_rmanager.h"
#include "oph_massive_operations.h"
#include "oph_session_report.h"
#include "oph_subset_library.h"
#include "oph_filters.h"
#include "oph_service_info.h"

#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <curl/curl.h>

extern char *oph_auth_location;
extern char *oph_user_admin;
extern char *oph_web_server;
extern char *oph_web_server_location;
extern char *oph_json_location;
extern unsigned int oph_server_task_limit;
extern unsigned int oph_server_core_limit;
extern unsigned int oph_server_task_running;
extern unsigned int oph_server_core_running;
extern unsigned int oph_auto_retry;
extern unsigned int oph_server_poll_time;
extern char oph_server_is_running;
extern char *oph_subm_user;
extern char *oph_txt_location;
extern FILE *wf_logfile;
extern FILE *task_logfile;
extern oph_service_info *service_info;
extern char *oph_status_log_file_name;
extern char oph_cancel_all_enabled;
extern ophidiadb *ophDB;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_mutex_t curl_flag;
extern pthread_mutex_t service_flag;
extern pthread_mutex_t savefile_flag;
extern pthread_cond_t termination_flag;
extern pthread_cond_t waiting_flag;
extern pthread_cond_t limit_flag;
#endif

typedef struct _oph_request_data {
	char serve_request;
	int jobid;
	char *submission_string;
	char *markerid;
	int ncores;
	int *status;
	char *error_notification;
	char *output_json;
	int task_id;
	int light_task_id;
	char *error;
	char run;
	int delay;
	char *taskname;
} oph_request_data;

typedef struct _oph_monitor_data {
	unsigned int poll_time;
	struct oph_plugin_data *state;
} oph_monitor_data;

int oph_request_data_init(oph_request_data * item)
{
	if (item) {
		item->submission_string = NULL;
		item->markerid = NULL;
		item->error_notification = NULL;
		item->output_json = NULL;
		item->error = NULL;
		item->taskname = NULL;
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_request_data_free(oph_request_data * item)
{
	if (item) {
		if (item->submission_string)
			free(item->submission_string);
		if (item->markerid)
			free(item->markerid);
		if (item->error_notification)
			free(item->error_notification);
		if (item->output_json)
			free(item->output_json);
		if (item->error)
			free(item->error);
		if (item->taskname)
			free(item->taskname);
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_request_data_vector_init(oph_request_data * item, int num)
{
	int i;
	if (item)
		for (i = 0; i < num; i++)
			oph_request_data_init(&(item[i]));
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_request_data_vector_free(oph_request_data * item, int num)
{
	int i;
	if (item) {
		for (i = 0; i < num; i++)
			oph_request_data_free(&(item[i]));
		free(item);
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

char *oph_remake_notification(const char *error_notification, int task_index, int light_task_index, int odb_jobid, enum oph__oph_odb_job_status new_status, char *submit_string, char *sessionid)
{
	if (!error_notification)
		return NULL;
	size_t len, maxlen = OPH_MAX_STRING_SIZE + (submit_string ? strlen(submit_string) : 0);
	char *tmp0 = strdup(error_notification);
	if (!tmp0)
		return NULL;
	char *tmp1 = (char *) malloc(maxlen * sizeof(char));
	if (!tmp1) {
		free(tmp0);
		return NULL;
	}
	*tmp1 = 0;
	char tmp2[OPH_MAX_STRING_SIZE], *pch, *save_pointer = NULL, *cube = NULL, *cwd = NULL, *output = NULL, *pointer, close;
	pch = strtok_r(tmp0, OPH_SEPARATOR_PARAM, &save_pointer);
	while (pch) {
		if (!strncasecmp(pch, OPH_ARG_JOBID, strlen(OPH_ARG_JOBID))) {
			snprintf(tmp2, OPH_MAX_STRING_SIZE, "%s%s%d", OPH_ARG_JOBID, OPH_SEPARATOR_KV, odb_jobid);
			strcat(tmp1, tmp2);
		} else if (!strncasecmp(pch, OPH_ARG_TASKINDEX, strlen(OPH_ARG_TASKINDEX))) {
			snprintf(tmp2, OPH_MAX_STRING_SIZE, "%s%s%d", OPH_ARG_TASKINDEX, OPH_SEPARATOR_KV, task_index);
			strcat(tmp1, tmp2);
		} else if (!strncasecmp(pch, OPH_ARG_LIGHTTASKINDEX, strlen(OPH_ARG_LIGHTTASKINDEX))) {
			snprintf(tmp2, OPH_MAX_STRING_SIZE, "%s%s%d", OPH_ARG_LIGHTTASKINDEX, OPH_SEPARATOR_KV, light_task_index);
			strcat(tmp1, tmp2);
		} else if (!strncasecmp(pch, OPH_ARG_STATUS, strlen(OPH_ARG_STATUS))) {
			snprintf(tmp2, OPH_MAX_STRING_SIZE, "%s%s%d", OPH_ARG_STATUS, OPH_SEPARATOR_KV, new_status);
			strcat(tmp1, tmp2);
		} else {
			strcat(tmp1, pch);
			if (!strncasecmp(pch, OPH_ARG_CWD, strlen(OPH_ARG_CWD)))
				cwd = pch;
			else if (!strncasecmp(pch, OPH_ARG_CUBE, strlen(OPH_ARG_CUBE)))
				cube = pch;
			else if (!strncasecmp(pch, OPH_OPERATOR_PARAMETER_OUTPUT, strlen(OPH_OPERATOR_PARAMETER_OUTPUT)))
				output = pch;
		}
		strcat(tmp1, OPH_SEPARATOR_PARAM);
		pch = strtok_r(NULL, OPH_SEPARATOR_PARAM, &save_pointer);
	}
	free(tmp0);
	// Transfer "cube" and "cwd" to notification string
	if (submit_string) {
		tmp0 = strdup(submit_string);
		pch = strtok_r(tmp0, OPH_SEPARATOR_PARAM, &save_pointer);
		while (pch) {
			if (!cwd && !strncasecmp(pch, OPH_ARG_CWD, strlen(OPH_ARG_CWD))) {
				close = 0;
				len = 1 + strlen(OPH_ARG_CWD);
				if (pch[len] != OPH_WORKFLOW_ROOT_FOLDER[0]) {
					strcat(tmp1, pch);
					close = 1;
				} else if (!oph_get_session_code(sessionid, tmp2)) {
					pointer = strstr(pch + len, tmp2);
					if (pointer && (pointer == pch + len + 1)) {
						strcat(tmp1, OPH_ARG_CWD);
						strcat(tmp1, OPH_SEPARATOR_KV);
						pointer = strchr(pointer, OPH_WORKFLOW_ROOT_FOLDER[0]);
						strcat(tmp1, pointer && (strlen(pointer) > 1) ? pointer : OPH_WORKFLOW_ROOT_FOLDER);
						close = 1;
					}
				}
				if (close)
					strcat(tmp1, OPH_SEPARATOR_PARAM);
			} else if (!cube && !strncasecmp(pch, OPH_ARG_CUBE, strlen(OPH_ARG_CUBE))) {
				strcat(tmp1, pch);
				strcat(tmp1, OPH_SEPARATOR_PARAM);
			} else if (!output && !strncasecmp(pch, OPH_OPERATOR_PARAMETER_INPUT, strlen(OPH_OPERATOR_PARAMETER_INPUT))) {
				strcat(tmp1, OPH_ARG_FILE);
				strcat(tmp1, pch + strlen(OPH_OPERATOR_PARAMETER_INPUT));
				strcat(tmp1, OPH_SEPARATOR_PARAM);
			}
			pch = strtok_r(NULL, OPH_SEPARATOR_PARAM, &save_pointer);
		}
		free(tmp0);
	}
	return tmp1;
}

int oph_build_hash(char *str, unsigned int len)
{
	char *result = str;
	unsigned int b = 378551;
	unsigned int a = 63689;
	unsigned int hash1 = 0;
	unsigned int hash2 = 1315423911;
	unsigned int i = 0;

	for (i = 0; i < len; str++, i++) {
		hash1 = hash1 * a + (*str);
		a = a * b;
		hash2 ^= ((hash2 << 5) + (*str) + (hash2 >> 2));
	}

	sprintf(result, "%u%u", hash1, hash2);

	return OPH_SERVER_OK;
}

int oph_workflow_save(oph_workflow * wf, const char *session_code, const char *checkpoint)
{
	if (!wf || !checkpoint)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	char *jstring = NULL;
	pthread_mutex_lock(&global_flag);
	if (oph_workflow_store(wf, &jstring, checkpoint)) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Unable to create the JSON Request with checkpoint '%s'\n", checkpoint);
		pthread_mutex_unlock(&global_flag);
		if (jstring)
			free(jstring);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	pthread_mutex_unlock(&global_flag);

	char linkname[OPH_SHORT_STRING_SIZE], filename[OPH_MAX_STRING_SIZE];

	pthread_mutex_lock(&savefile_flag);	// This lock is required as more checkpoint with the same name could be saved with the same name, the last is the best
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_CHECKPOINT, oph_web_server_location, session_code, wf->workflowid, checkpoint);
	FILE *fil = fopen(filename, "w");
	if (fil) {
		fprintf(fil, "%s", jstring);
		fclose(fil);
	} else
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Unable to save the JSON Request with checkpoint '%s'\n", checkpoint);
	snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_CHECKPOINT, oph_web_server_location, session_code, wf->workflowid,
		 OPH_OPERATOR_RESUME_PARAMETER_LAST);
	unlink(linkname);
	if (symlink(filename, linkname))
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Unable to link the JSON Request with checkpoint '%s'\n", OPH_OPERATOR_RESUME_PARAMETER_LAST);
	pthread_mutex_unlock(&savefile_flag);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "JSON Request with checkpoint '%s' saved\n", checkpoint);
	if (jstring)
		free(jstring);

	snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_CHECKPOINT, wf->workflowid, checkpoint);
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_CHECKPOINT, oph_web_server, session_code, wf->workflowid, checkpoint);
	oph_session_report_append_link(session_code, wf->workflowid, NULL, linkname, filename, 'R');

	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_workflow_set_status(char ttype, int jobid, oph_workflow * wf, int *dependents_indexes, int dependents_indexes_num, enum oph__oph_odb_job_status status)
{
	if (dependents_indexes_num) {
		if (!dependents_indexes) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: null pointer\n", ttype, jobid);
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		int i, k, res;
		for (k = 0; k < dependents_indexes_num; ++k) {
			i = dependents_indexes[k];
			if (wf->tasks[i].status && (wf->tasks[i].status < (int) status)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: found a depending task '%s' with a status already set to '%s'\n", ttype, jobid, wf->tasks[i].name,
				      oph_odb_convert_status_to_str(status));
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
			if (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED) {
				if (!wf->residual_tasks_num) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: number of residual tasks of '%s' cannot be reduced\n", ttype, jobid, wf->tasks[i].name);
					return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
				}
				wf->residual_tasks_num--;
			}
			wf->tasks[i].status = status;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: status of '%s' is set to '%s'\n", ttype, jobid, wf->tasks[i].name, oph_odb_convert_status_to_str(status));
			if ((res = oph_workflow_set_status(ttype, jobid, wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, status)))
				return res;
		}
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_reset_task(oph_workflow * wf, int *dependents_indexes, int dependents_indexes_num, int last_task, oph_workflow_stack * stack, int *tasks_num)
{
	if (dependents_indexes_num) {
		if (!dependents_indexes) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}

		int i, j, k, res;
		for (k = 0; k < dependents_indexes_num; ++k) {
			i = dependents_indexes[k];
			if (!wf->tasks[i].status)
				continue;

			wf->tasks[i].idjob = 0;
			wf->tasks[i].markerid = 0;
			wf->tasks[i].status = OPH_ODB_STATUS_UNKNOWN;
			wf->tasks[i].is_skipped = 0;
			wf->tasks[i].residual_retry_num = wf->tasks[i].retry_num;
			wf->tasks[i].residual_auto_retry_num = 0;
			wf->tasks[i].is_marked_for_auto_retry = 0;
			wf->tasks[i].is_marked_to_be_aborted = 0;
			wf->tasks[i].forward = 0;
			if (wf->tasks[i].arguments_keys) {
				for (j = 0; j < wf->tasks[i].arguments_num; ++j)
					if (wf->tasks[i].arguments_keys[j]) {
						free(wf->tasks[i].arguments_keys[j]);
						wf->tasks[i].arguments_keys[j] = NULL;
					}
				free(wf->tasks[i].arguments_keys);
				wf->tasks[i].arguments_keys = NULL;
			}
			if (wf->tasks[i].arguments_values) {
				for (j = 0; j < wf->tasks[i].arguments_num; ++j)
					if (wf->tasks[i].arguments_values[j]) {
						free(wf->tasks[i].arguments_values[j]);
						wf->tasks[i].arguments_values[j] = NULL;
					}
				free(wf->tasks[i].arguments_values);
				wf->tasks[i].arguments_values = NULL;
			}
			if (wf->tasks[i].arguments_lists) {
				for (j = 0; j < wf->tasks[i].arguments_num; ++j)
					if (wf->tasks[i].arguments_lists[j]) {
						free(wf->tasks[i].arguments_lists[j]);
						wf->tasks[i].arguments_lists[j] = NULL;
					}
				free(wf->tasks[i].arguments_lists);
				wf->tasks[i].arguments_lists = NULL;
			}
			wf->tasks[i].arguments_num = stack->tasks[i].arguments_num;
			if (wf->tasks[i].arguments_num) {
				wf->tasks[i].arguments_keys = (char **) malloc(wf->tasks[i].arguments_num * sizeof(char *));
				if (!wf->tasks[i].arguments_keys) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Memory error\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				wf->tasks[i].arguments_values = (char **) malloc(wf->tasks[i].arguments_num * sizeof(char *));
				if (!wf->tasks[i].arguments_values) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Memory error\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				wf->tasks[i].arguments_lists = (oph_workflow_ordered_list **) malloc(wf->tasks[i].arguments_num * sizeof(oph_workflow_ordered_list *));
				if (!wf->tasks[i].arguments_lists) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Memory error\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				for (j = 0; j < stack->tasks[i].arguments_num; ++j) {
					wf->tasks[i].arguments_keys[j] = strdup(stack->tasks[i].arguments_keys[j]);
					wf->tasks[i].arguments_values[j] = stack->tasks[i].arguments_values[j] ? strdup(stack->tasks[i].arguments_values[j]) : NULL;
					wf->tasks[i].arguments_lists[j] = oph_workflow_copy_list(stack->tasks[i].arguments_lists[j]);
				}
			}
			for (j = 0; j < wf->tasks[i].deps_num; ++j)
				wf->tasks[i].deps[j].task_index = stack->tasks[i].deps_task_index[j];
			wf->tasks[i].residual_deps_num = stack->tasks[i].residual_deps_num;
			for (j = 0; j < wf->tasks[i].dependents_indexes_num; ++j)
				wf->tasks[i].dependents_indexes[j] = stack->tasks[i].dependents_indexes[j];
			oph_output_data_free(wf->tasks[i].outputs_keys, wf->tasks[i].outputs_num);
			oph_output_data_free(wf->tasks[i].outputs_values, wf->tasks[i].outputs_num);
			wf->tasks[i].outputs_keys = NULL;
			wf->tasks[i].outputs_values = NULL;
			wf->tasks[i].outputs_num = 0;
			if (wf->tasks[i].light_tasks) {
				for (j = 0; j < wf->tasks[i].light_tasks_num; ++j)
					oph_workflow_light_task_free(&(wf->tasks[i].light_tasks[j]));
				free(wf->tasks[i].light_tasks);
			}
			wf->tasks[i].light_tasks_num = wf->tasks[i].residual_light_tasks_num = 0;
			if (wf->tasks[i].response) {
				free(wf->tasks[i].response);
				wf->tasks[i].response = NULL;
			}

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Status of '%s' has been reset\n", wf->tasks[i].name);
			if (tasks_num)
				(*tasks_num)++;

			if ((i != last_task) && (res = oph_workflow_reset_task(wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, last_task, stack, tasks_num)))
				return res;
		}
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_disable_deps(oph_workflow * wf, int *dependents_indexes, int dependents_indexes_num, int first_task, int last_task)
{
	if (dependents_indexes_num) {
		if (!dependents_indexes) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		int i, j, k, h, res;
		for (k = 0; k < dependents_indexes_num; ++k) {
			i = dependents_indexes[k];
			if (wf->tasks[i].status)
				continue;

			for (j = 0; j < wf->tasks[i].deps_num; ++j) {
				h = wf->tasks[i].deps[j].task_index;
				if ((h >= 0) && (h != first_task) && (wf->tasks[h].status >= (int) OPH_ODB_STATUS_COMPLETED)) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Dependency of '%s' from '%s' of workflow '%s' will be considered as 'satisfied'.\n", wf->tasks[i].name, wf->tasks[h].name,
					      wf->name);
					wf->tasks[i].residual_deps_num--;
				}
			}

			if ((i != last_task) && (res = oph_workflow_disable_deps(wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, first_task, last_task)))
				return res;
		}
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_load_aggregate_response(oph_workflow * wf, int level)
{
	if (!wf)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if ((level < 0) || (level > 3))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	if (level == 1)
		return OPH_WORKFLOW_EXIT_SUCCESS;

	char *buffer = NULL, *pbuffer;

	int j;
	oph_workflow_task_out *tmp = wf->output;
	while (tmp) {
		if (tmp->response) {
			if (buffer) {
				pbuffer = buffer;
				if (asprintf(&buffer, "%s%s", pbuffer, tmp->response) <= 0)
					break;
				free(pbuffer);
			} else
				buffer = strdup(tmp->response);
		}
		if (level >= 3) {
			for (j = 0; j < tmp->light_tasks_num; ++j) {
				if (tmp->light_task_outs[j].response) {
					if (buffer) {
						pbuffer = buffer;
						if (asprintf(&buffer, "%s%s", pbuffer, tmp->light_task_outs[j].response) <= 0)
							break;
						free(pbuffer);
					} else
						buffer = strdup(tmp->light_task_outs[j].response);
				}
			}
			if (j < tmp->light_tasks_num)
				break;
		}
		tmp = tmp->next;
	}
	if (tmp) {
		if (buffer)
			free(buffer);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	if (wf->response)
		free(wf->response);
	wf->response = buffer;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Thread unsafe
int oph_generate_oph_jobid(struct oph_plugin_data *state, char ttype, int jobid, oph_workflow * wf, int *num_sessions, int max_sessions, int timeout_value, int *markerid, char *str_markerid,
			   int *workflowid, char *str_workflowid, char *oph_jobid, int prev_markerid)
{
	if (!wf || !oph_jobid)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	char tmp[OPH_MAX_STRING_SIZE];
	oph_argument *args = NULL;

	struct timeval tv;
	gettimeofday(&tv, 0);

	// Convert dn to user
	char _username[OPH_MAX_STRING_SIZE];
	snprintf(_username, OPH_MAX_STRING_SIZE, "%s", wf->username);
	int i, j = strlen(_username), update_last_marker = 1;
	for (i = 0; i < j; ++i)
		if ((_username[i] == '/') || (_username[i] == ' ') || (_username[i] == '='))
			_username[i] = '_';

	if (!wf->sessionid)	// Create a new session
	{
		if (state->authorization < OPH_AUTH_WRITE) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: user cannot create new sessions\n", ttype, jobid);
			return OPH_WORKFLOW_EXIT_AUTH_ERROR;
		}
		if (num_sessions) {
			if (max_sessions) {
				if (timeout_value && (*num_sessions >= max_sessions))	// Try to close old sessions
				{
					char filename[OPH_MAX_STRING_SIZE];
					int last_access_time;

					*num_sessions = 0;
					// Check for maximum number of opened sessions
					struct dirent *entry, save_entry;

					char directory[OPH_MAX_STRING_SIZE];
					snprintf(directory, OPH_MAX_STRING_SIZE, OPH_SESSION_DIR, oph_auth_location, _username);

					DIR *dirp = opendir(directory);	// There should be error handling after this
					if (!dirp) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in opening session directory '%s'\n", ttype, jobid, directory);
						return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
					}
					struct stat file_stat;

					while (!readdir_r(dirp, &save_entry, &entry) && entry) {
						snprintf(filename, OPH_MAX_STRING_SIZE, "%s/%s", directory, entry->d_name);
						lstat(filename, &file_stat);
						if (S_ISLNK(file_stat.st_mode)) {
							oph_init_args(&args);
							if (!oph_load_file(filename, &args))	// entry->d_type
							{
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: check for %s\n", ttype, jobid, OPH_SESSION_AUTOREMOVE);
								if (!oph_get_arg(args, OPH_SESSION_AUTOREMOVE, tmp) && !strcmp(tmp, OPH_DEFAULT_YES)) {
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: check for %s\n", ttype, jobid, OPH_SESSION_LAST_ACCESS_TIME);
									if (!oph_get_arg(args, OPH_SESSION_LAST_ACCESS_TIME, tmp)) {
										last_access_time = strtol(tmp, NULL, 10);
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: found a removable session '%s', last access on %d\n", ttype, jobid,
										      filename, last_access_time);
										if (tv.tv_sec > last_access_time + timeout_value * OPH_DEFAULT_DAY_TO_SEC)	// Timeout
										{
											pmesg(LOG_INFO, __FILE__, __LINE__, "%c%d: session '%s' has expired... removing it\n", ttype, jobid, filename);
											remove(filename);
											oph_cleanup_args(&args);
											continue;
										}
									}
								}
							}
							oph_cleanup_args(&args);
							(*num_sessions)++;
						}
					}
					closedir(dirp);
				}

				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: the number of opened sessions from user '%s' is %d. Maximum is %d\n", ttype, jobid, wf->username, *num_sessions,
				      max_sessions);
				if (*num_sessions >= max_sessions) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: attempt to open too many sessions. Maximum is %d\n", ttype, jobid, max_sessions);
					return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
				}
			}

			(*num_sessions)++;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: the number of opened sessions from user '%s' has been updated to %d\n", ttype, jobid, wf->username, *num_sessions);
		}
		// Create a new sessionid
		char hash[OPH_MAX_STRING_SIZE];
		snprintf(hash, OPH_MAX_STRING_SIZE, "%d%d%s%d", (int) tv.tv_sec, (int) tv.tv_usec, wf->username, (int) jobid);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: string to be coded: %s (len %d)\n", ttype, jobid, hash, strlen(hash));
		if (oph_build_hash(hash, strlen(hash))) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in building hash\n", ttype, jobid);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		snprintf(tmp, OPH_MAX_STRING_SIZE, "%d%d", (int) tv.tv_sec, (int) tv.tv_usec);	// For unicity
		strncat(hash, tmp, OPH_MAX_STRING_SIZE - strlen(hash));
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: coded string: %s\n", ttype, jobid, hash);

		char sessionid[OPH_MAX_STRING_SIZE];
		snprintf(sessionid, OPH_MAX_STRING_SIZE, OPH_SESSIONID_TEMPLATE, oph_web_server, hash);

		wf->sessionid = strdup(sessionid);
		if (markerid)
			*markerid = 0;
		if (workflowid)
			*workflowid = 0;

		wf->userrole = OPH_ROLE_ALL;

		// Create basic folders in oph_web_server_location
		char name[OPH_MAX_STRING_SIZE];
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_BASE_TEMPLATE, oph_web_server_location);
		if (oph_mkdir(name)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_FOLDER_TEMPLATE, oph_web_server_location, hash);
		if (oph_mkdir(name)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_FOLDER_TEMPLATE, oph_web_server_location, hash);
		if (oph_mkdir(name)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE, oph_web_server_location, hash);
		if (oph_mkdir(name)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		char mk_user_dir = oph_subm_user && strcmp(wf->os_username, oph_subm_user);
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE, oph_web_server_location, hash);
		if (oph_mkdir2(name, mk_user_dir ? 0775 : 0755)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_EXPORT_FOLDER_TEMPLATE, oph_web_server_location, hash);
		if (oph_mkdir2(name, mk_user_dir ? 0775 : 0755)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSION_CUBE_FOLDER_TEMPLATE, oph_web_server_location);
		if (oph_mkdir2(name, mk_user_dir ? 0775 : 0755)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: error in creating session folder '%s'\n", jobid, name);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}

		if (!oph_session_report_init(hash))
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: session index created\n", jobid);
	} else			// Open an existing session
	{
		int active = 0;
		oph_auth_user_role userrole = OPH_ROLE_NONE;

		// Check session access
		oph_init_args(&args);
		if (oph_auth_session(_username, wf->sessionid, oph_web_server, &args, &active, &userrole) || !active) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: received wrong sessionid: %s\n", ttype, jobid, wf->sessionid);
			return OPH_WORKFLOW_EXIT_AUTH_ERROR;
		}
		if (userrole == OPH_ROLE_NONE) {
			oph_cleanup_args(&args);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: user '%s' is not authorized to access this session\n", ttype, jobid, wf->username);
			return OPH_WORKFLOW_EXIT_AUTH_ERROR;
		}
		// Check each command
		int i;
		for (i = 0; i < wf->tasks_num; ++i)
			if (oph_auth_check_role(wf->tasks[i].role, userrole))
				break;
		if (i < wf->tasks_num) {
			oph_cleanup_args(&args);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: user '%s' is not authorized to execute '%s' within this session\n", ttype, jobid, wf->username, wf->tasks[i].operator);
			return OPH_WORKFLOW_EXIT_AUTH_ERROR;
		}

		wf->userrole = (int) userrole;

		if (markerid && !oph_trash_extract(state->trash, wf->sessionid, markerid)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reuse of markerid '%d'\n", ttype, jobid, *markerid);
			update_last_marker = 0;
		} else if (markerid && !oph_get_arg(args, OPH_SESSION_LAST_MARKER, tmp))
			*markerid = strtol(tmp, NULL, 10);
		else if (str_markerid && !oph_get_arg(args, OPH_SESSION_LAST_MARKER, tmp))
			sprintf(str_markerid, "%s", tmp);
		if (workflowid && !oph_get_arg(args, OPH_SESSION_LAST_WORKFLOW, tmp))
			*workflowid = strtol(tmp, NULL, 10);
	}
	int new_session = !args, set_workflow = new_session;

	if (markerid) {
		if (update_last_marker)
			(*markerid)++;
		if (str_markerid)
			sprintf(str_markerid, "%d", *markerid);
	}

	if (workflowid)
		(*workflowid)++;	// Main response
	else if (markerid && str_markerid && update_last_marker)	// Tasks and sub-tasks
	{
		char session_code[OPH_MAX_STRING_SIZE];
		if (oph_get_session_code(wf->sessionid, session_code))
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);
		else {
			char linkname[OPH_SHORT_STRING_SIZE];
			snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_TASK, *markerid);
			snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_MAIN, oph_web_server, session_code, *markerid);
			oph_session_report_append_link(session_code, wf->workflowid, str_markerid, linkname, tmp, 'W');
		}
	}
	if (!update_last_marker && str_markerid && !oph_get_arg(args, OPH_SESSION_LAST_MARKER, tmp))
		sprintf(str_markerid, "%s", tmp);

	if (workflowid && str_workflowid) {
		sprintf(str_workflowid, "%d", *workflowid);
		set_workflow = 1;
	}

	char str_time[OPH_SHORT_STRING_SIZE];
	snprintf(str_time, OPH_SHORT_STRING_SIZE, "%d", (int) tv.tv_sec);

	if (new_session) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: saving session data\n", ttype, jobid);
		if (oph_init_args(&args)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving session data\n", ttype, jobid);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_ID, wf->sessionid)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_ID);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_OWNER, wf->username)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_OWNER);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_CREATION_TIME, str_time)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_CREATION_TIME);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_DEFAULT_SESSION_ACTIVE)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_ACTIVE);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_AUTOREMOVE, OPH_DEFAULT_SESSION_AUTOREMOVE)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_AUTOREMOVE);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_USERS, "")) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_USERS);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		struct tm nowtm;
		if (!localtime_r(&tv.tv_sec, &nowtm)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in getting system time\n", ttype, jobid);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		strftime(tmp, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm);
		if (oph_set_arg(&args, OPH_SESSION_LABEL, tmp)) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_LABEL);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_set_arg(&args, OPH_SESSION_CUBE, "")) {
			oph_cleanup_args(&args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_CUBE);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}

		oph_argument *us_args = NULL;	// User-specific session data
		oph_init_args(&us_args);
		if (oph_set_arg(&us_args, OPH_SESSION_CWD, OPH_WORKFLOW_ROOT_FOLDER)) {
			oph_cleanup_args(&args);
			oph_cleanup_args(&us_args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_CWD);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		if (oph_save_user_session(_username, wf->sessionid, us_args)) {
			oph_cleanup_args(&args);
			oph_cleanup_args(&us_args);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving session data\n", ttype, jobid);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		oph_cleanup_args(&us_args);
	}
	if (oph_set_arg(&args, OPH_SESSION_LAST_MARKER, str_markerid ? str_markerid : "0")) {
		oph_cleanup_args(&args);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_LAST_MARKER);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	if (set_workflow && oph_set_arg(&args, OPH_SESSION_LAST_WORKFLOW, str_workflowid ? str_workflowid : "0")) {
		oph_cleanup_args(&args);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_LAST_WORKFLOW);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	if (oph_set_arg(&args, OPH_SESSION_LAST_ACCESS_TIME, str_time)) {
		oph_cleanup_args(&args);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_LAST_ACCESS_TIME);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	if (oph_set_arg(&args, OPH_SESSION_LAST_COMMAND, wf->command && (strlen(wf->command) < OPH_LONG_STRING_SIZE) ? wf->command : wf->name)) {
		oph_cleanup_args(&args);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving %s\n", ttype, jobid, OPH_SESSION_LAST_COMMAND);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	if (oph_save_session(_username, wf->sessionid, args, new_session ? DT_REG : DT_LNK)) {
		oph_cleanup_args(&args);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in saving session data\n", ttype, jobid);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	oph_cleanup_args(&args);

	if (!markerid && str_markerid)
		sprintf(str_markerid, "%d", prev_markerid);
	if (str_markerid && str_workflowid)
		snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid, OPH_SESSION_MARKER_DELIMITER, str_markerid);
	else
		snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s", wf->sessionid);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Thread unsafe
int oph_check_for_massive_operation(struct oph_plugin_data *state, char ttype, int jobid, oph_workflow * wf, int task_index, ophidiadb * oDB, char ***output_list, int *output_list_dim, char **query,
				    char *remake_submission_string)
{
	if (!wf) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: null parameter\n", ttype, jobid);
		return OPH_SERVER_NULL_POINTER;
	}
	if ((task_index < 0) || (task_index > wf->tasks_num)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: index %d out of boundaries\n", ttype, jobid, task_index);
		return OPH_SERVER_SYSTEM_ERROR;
	}
	if (remake_submission_string)
		*remake_submission_string = 0;

	int i, j = -1;
	oph_workflow_task *task = &(wf->tasks[task_index]);

	char auto_retry = oph_auto_retry && task->residual_auto_retry_num && (task->retry_num == 1);
	char manual_retry = task->residual_retry_num && (task->retry_num > 1);
	if (auto_retry || manual_retry) {
		for (i = 0; i < task->light_tasks_num; ++i)
			if ((auto_retry && (task->light_tasks[i].status == (int) OPH_ODB_STATUS_START_ERROR)) || (manual_retry && (task->light_tasks[i].status > (int) OPH_ODB_STATUS_COMPLETED))) {
				if (oph_trash_append(state->trash, wf->sessionid, task->light_tasks[i].markerid))
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to release markerid '%d'\n", ttype, jobid, task->light_tasks[i].markerid);
				else
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: release markerid '%d'\n", ttype, jobid, task->light_tasks[i].markerid);
				task->light_tasks[i].markerid = 0;
				task->light_tasks[i].status = OPH_ODB_STATUS_UNKNOWN;
				if (oDB && oph_odb_set_job_status(task->light_tasks[i].idjob, task->light_tasks[i].status, oDB))
					pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to update job status\n", ttype, jobid);
				task->light_tasks[i].idjob = 0;
			}
		task->residual_light_tasks_num = task->light_tasks_num;
		return OPH_SERVER_OK;
	}

	if (task->light_tasks_num) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: found %d massive operation children already set\n", ttype, jobid, task->light_tasks_num);
		return OPH_SERVER_NO_RESPONSE;
	}
	if (task->light_tasks) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: task struct of '%s' is wrong\n", ttype, jobid, task->name);
		return OPH_SERVER_SYSTEM_ERROR;
	}

	int res = OPH_SERVER_OK;
	char *src_path = 0, *datacube_input = 0, *measure = 0, *cwd_value = 0, *cdd_value = 0, *src_path_key = 0, *datacube_input_key = 0, *measure_key = 0, ncubes = 0;
	for (i = 0; i < task->arguments_num; ++i) {
		if (!strcmp(task->arguments_keys[i], OPH_ARG_INPUT)) {	// More priority than OPH_ARG_SRC_PATH
			src_path_key = task->arguments_keys[i];
			src_path = task->arguments_values[i];
			j = i;
		} else if (!strcmp(task->arguments_keys[i], OPH_ARG_SRC_PATH)) {
			if (!src_path_key) {
				src_path_key = task->arguments_keys[i];
				src_path = task->arguments_values[i];
				j = i;
			}
		} else if (!strcmp(task->arguments_keys[i], OPH_ARG_CUBE)) {
			if (!ncubes) {
				datacube_input_key = task->arguments_keys[i];
				datacube_input = task->arguments_values[i];
				ncubes = 1;
			}
		} else if (!strcmp(task->arguments_keys[i], OPH_ARG_CUBES)) {
			datacube_input_key = task->arguments_keys[i];
			datacube_input = task->arguments_values[i];
			ncubes = 2;
		} else if (!strcmp(task->arguments_keys[i], OPH_ARG_MEASURE)) {
			measure_key = task->arguments_keys[i];
			measure = task->arguments_values[i];
		} else if (!strcmp(task->arguments_keys[i], OPH_ARG_CWD))
			cwd_value = task->arguments_values[i];
		else if (!strcmp(task->arguments_keys[i], OPH_ARG_CDD))
			cdd_value = task->arguments_values[i];
	}

	char *target_base = NULL;
	if (src_path) {
		datacube_input = 0;
		target_base = strdup(src_path);
		src_path = target_base;
	} else if (datacube_input) {
		target_base = strdup(datacube_input);
		datacube_input = target_base;
	}

	if (datacube_input || src_path) {
		if (!target_base) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: memory error\n", ttype, jobid);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: variable substitution for task '%s'\n", ttype, jobid, task->name);
		if (oph_workflow_var_substitute(wf, task_index, -1, &target_base, NULL, src_path ? OPH_ARG_SRC_PATH : (ncubes > 1 ? OPH_ARG_CUBES : OPH_ARG_CUBE))) {
			free(target_base);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in variable substitution for task '%s'\n", ttype, jobid, task->name);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		char **datacube_inputs = NULL, **measure_name = NULL;
		int running = 0;
		unsigned int number = 0;

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: parsing task '%s' for massive operations\n", ttype, jobid, task->name);
		if ((res =
		     oph_mf_parse_query_unsafe(state, wf, task_index, &datacube_inputs, &measure_name, &number, target_base, cwd_value, cdd_value, wf->sessionid, &running, src_path ? 1 : 0, oDB,
					       query))) {
			free(target_base);
			return res;
		}
		free(target_base);

		// Do not consider operations with parameter 'cubes' as massive 
		if (datacube_input && !src_path && (ncubes > 1)) {
			for (i = 0; i < (int) number; ++i)
				if (datacube_inputs[i])
					free(datacube_inputs[i]);
			free(datacube_inputs);
			datacube_inputs = NULL;
		}
		// Do not consider input for OPH_IMPORTNCS as massive, but expand the value of the parameter
		if (datacube_inputs && src_path && number && (!strcasecmp(task->operator, OPH_OPERATOR_IMPORTNCS) || !strcasecmp(task->operator, OPH_OPERATOR_FOR)) && (j >= 0)) {
			size_t max_dim = number * OPH_LONG_STRING_SIZE;
			char *tmp = (char *) malloc(max_dim);
			if (!tmp) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: memory error\n", ttype, jobid);
				for (i = 0; i < (int) number; ++i)
					if (datacube_inputs[i])
						free(datacube_inputs[i]);
				free(datacube_inputs);
				datacube_inputs = NULL;
				if (measure_name) {
					for (i = 0; i < (int) number; ++i)
						if (measure_name[i])
							free(measure_name[i]);
					free(measure_name);
					measure_name = 0;
				}
				return OPH_SERVER_SYSTEM_ERROR;
			}
			*tmp = 0;
			char next = 0;
			for (i = 0; i < (int) number; ++i)
				if (datacube_inputs[i]) {
					if (next)
						strncat(tmp, OPH_SEPARATOR_SUBPARAM_STR, max_dim - strlen(tmp));
					strncat(tmp, datacube_inputs[i], max_dim - strlen(tmp));
					free(datacube_inputs[i]);
					next = 1;
				}
			free(datacube_inputs);
			datacube_inputs = NULL;
			free(task->arguments_values[j]);
			task->arguments_values[j] = tmp;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: argument '%s' of task '%s' has been updated to '%s'\n", ttype, jobid, task->arguments_keys[j], task->name, tmp);
			if (remake_submission_string)
				*remake_submission_string = 1;
		}

		if (datacube_inputs) {

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: found %d light tasks\n", ttype, jobid, number);

			int j;
			if (running) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: serving task '%s' as massive operation\n", ttype, jobid, task->name);

				task->light_tasks_num = task->residual_light_tasks_num = number;
				task->light_tasks = (oph_workflow_light_task *) malloc(number * sizeof(oph_workflow_light_task));

				int add_measure = src_path && !measure_key && measure_name, arguments_num;
				for (i = 0; i < (int) number; ++i) {
					arguments_num = task->arguments_num + (add_measure && measure_name[i] ? 1 : 0);
					task->light_tasks[i].idjob = 0;
					task->light_tasks[i].markerid = 0;
					task->light_tasks[i].status = OPH_ODB_STATUS_UNKNOWN;
					task->light_tasks[i].ncores = task->ncores;	// Basic policy for ncores
					task->light_tasks[i].arguments_keys = (char **) malloc(arguments_num * sizeof(char *));
					task->light_tasks[i].arguments_values = (char **) malloc(arguments_num * sizeof(char *));
					task->light_tasks[i].arguments_num = arguments_num;
					task->light_tasks[i].response = NULL;
					for (j = 0; j < task->arguments_num; ++j) {
						if (!task->arguments_keys[j]) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to set arguments of light tasks from task '%s'\n", ttype, jobid, task->name);
							continue;
						}
						task->light_tasks[i].arguments_keys[j] = strdup(task->arguments_keys[j]);
						if ((src_path && (task->arguments_keys[j] == src_path_key)) || (!src_path && (task->arguments_keys[j] == datacube_input_key)))
							task->light_tasks[i].arguments_values[j] = strdup(datacube_inputs[i]);
						else if (task->arguments_keys[j] == measure_key) {
							if (measure_name && measure_name[i])
								task->light_tasks[i].arguments_values[j] = strdup(measure_name[i]);
							else
								task->light_tasks[i].arguments_values[j] = strdup(measure);
						} else
							task->light_tasks[i].arguments_values[j] = task->arguments_values[j] ? strdup(task->arguments_values[j]) : NULL;
					}
					if (add_measure && measure_name[i]) {
						task->light_tasks[i].arguments_keys[j] = strdup(OPH_ARG_MEASURE);
						task->light_tasks[i].arguments_values[j] = strdup(measure_name[i]);
					}
				}

				for (i = 0; i < (int) number; ++i)
					if (datacube_inputs[i])
						free(datacube_inputs[i]);
				free(datacube_inputs);
				datacube_inputs = NULL;
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: light tasks loaded from task '%s'\n", ttype, jobid, task->name);
			} else {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: serving task '%s' as massive operation without effective execution\n", ttype, jobid, task->name);
				res = OPH_SERVER_NO_RESPONSE;
				if (output_list)
					*output_list = datacube_inputs;
				if (output_list_dim)
					*output_list_dim = number;
			}
		} else
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: no light tasks found\n", ttype, jobid);

		if (measure_name) {
			for (i = 0; i < (int) number; ++i)
				if (measure_name[i])
					free(measure_name[i]);
			free(measure_name);
			measure_name = 0;
		}
	}

	return res;
}

// Thread unsafe
int oph_save_basic_json(char ttype, int jobid, oph_workflow * wf, int task_index, int light_task_index, const char *message_type, const char *message, char **output_json)
{
	if (!wf || !message_type) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: null parameter\n", ttype, jobid);
		return OPH_SERVER_NULL_POINTER;
	}
	if ((task_index < 0) || (task_index >= wf->tasks_num)) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: wrong task index %d\n", ttype, jobid, task_index);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (light_task_index >= wf->tasks[task_index].light_tasks_num) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: wrong light task index %d\n", ttype, jobid, light_task_index);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (output_json)
		*output_json = NULL;

	oph_json *oper_json = NULL;

	char str_jobid[OPH_MAX_STRING_SIZE];
	char session_code[OPH_MAX_STRING_SIZE];
	char str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];

	int success = 0, markerid = light_task_index >= 0 ? wf->tasks[task_index].light_tasks[light_task_index].markerid : wf->tasks[task_index].markerid;

	snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
	snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
	snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", markerid);

	if (oph_get_session_code(wf->sessionid, session_code)) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);
		return OPH_SERVER_SYSTEM_ERROR;
	}

	char error_type[OPH_MAX_STRING_SIZE];
	char error_message[OPH_MAX_STRING_SIZE];

	while (!success) {
		if (oph_json_alloc_unsafe(&oper_json)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
			break;
		}
		if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "Session Code", session_code)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "Workflow", str_workflowid)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "Marker", str_markerid)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "JobID", str_jobid)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_consumer_unsafe(oper_json, wf->username)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
			break;
		}
		success = 1;
	}

	if (success) {
		snprintf(error_type, OPH_MAX_STRING_SIZE, "%s", message_type);
		snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", message);
	} else {
		snprintf(error_type, OPH_MAX_STRING_SIZE, "ERROR");
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
	}

	char *my_output_json = NULL;

	if (oper_json) {
		int return_code = 0;
		if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, error_type, error_message)) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
			return_code = -1;
		} else if (oph_write_and_get_json_unsafe(oper_json, &my_output_json))
			return_code = -1;
		if (!return_code)
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
	}
	oph_json_free_unsafe(oper_json);

	if (my_output_json) {
		if (output_json)
			*output_json = my_output_json;
		else
			free(my_output_json);
	}

	return OPH_SERVER_OK;
}

int oph_workflow_mark_children_of(oph_workflow * wf, int k, int p)
{
	if (!wf || !wf->tasks || (k < 0) || (k >= wf->tasks_num) || (p < 0) || (p >= wf->tasks_num)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	int i, j;
	for (i = 0; i < wf->tasks[k].dependents_indexes_num; ++i) {
		j = wf->tasks[k].dependents_indexes[i];
		if (j == wf->tasks[p].child)
			continue;	// Don't mark the final task
		else if (oph_workflow_is_child_of(wf, j, wf->tasks[p].child))	// Check if a descendent of task j is the end task
		{
			wf->tasks[j].is_marked = 1;
			if (oph_workflow_mark_children_of(wf, j, p))
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Thread safe
int oph_workflow_parallel_fco(oph_workflow * wf, int nesting_level, struct oph_plugin_data *state)
{
	if (!wf || !wf->tasks) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	char *pch, *save_pointer = NULL, *name = NULL, **svalues = NULL;
	int *ivalues = NULL;	// If not allocated then it is equal to [1:values_num]
	int i, j, jj, k, kk, svalues_num = 0, ivalues_num = 0, new_branch_num, replied_num, old_tasks_num, new_index[wf->tasks_num];
	int old_dependents_indexes_num, *old_dependents_indexes = NULL, old_deps_num;
	unsigned int kkk, kkkk, lll = strlen(OPH_WORKFLOW_SEPARATORS);
	long value;
	oph_workflow_dep *old_deps = NULL;
	oph_workflow_var var;
	void *var_buffer;
	size_t var_size = sizeof(oph_workflow_var), svalue_size;
	int jobid;

	char reset = 0, exploded = 0, found = 0;	// Found a FOR with higher nesting_level
	for (i = 0; i < wf->tasks_num; ++i) {
		if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_FOR, OPH_WORKFLOW_MAX_STRING)) {
			if (wf->tasks[i].parallel_mode)
				continue;	// The current task is a parallel-for already exploded

			// Pre-parsing for possible file list
			if (!wf->tasks[i].massive_expansion) {
				jj = -1;
				for (j = 0; j < wf->tasks[i].arguments_num; ++j)
					if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_INPUT) && strlen(wf->tasks[i].arguments_values[j])
					    && strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_NULL)) {
						jj = j;
						break;
					}
				if (jj < 0) {
					for (j = 0; j < wf->tasks[i].arguments_num; ++j)
						if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_SRC_PATH) && strlen(wf->tasks[i].arguments_values[j])
						    && strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_NULL)) {
							jj = j;
							break;
						}
				}

				pthread_mutex_lock(&global_flag);
				jobid = *state->jobid;
				if (wf->workflowid < 0) {
					jobid = ++*state->jobid;
					wf->workflowid = -jobid;
					oph_get_new_jobid_from_job_list(state->job_info, &wf->idjob);	// Get a valid odb_jobid that is unique in job list
					reset = 1;
				}
				pthread_mutex_unlock(&global_flag);

				oph_wf_list_append(state->job_info, wf);

				pthread_mutex_lock(&global_flag);
				oph_check_for_massive_operation(state, 'F', jobid, wf, i, ophDB, NULL, NULL, NULL, NULL);
				pthread_mutex_unlock(&global_flag);

				if (reset) {
					oph_wf_list_drop2(state->job_info, wf->idjob, 0);
					wf->workflowid = -1;
				}

				if (jj >= 0) {
					for (j = 0; j < wf->tasks[i].arguments_num; ++j)
						if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_VALUES)) {
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Override value of parameter '%s' of task '%s' with '%s'\n", OPH_ARG_VALUES,
								   wf->tasks[i].name, wf->tasks[i].arguments_values[jj]);
							free(wf->tasks[i].arguments_values[j]);
							wf->tasks[i].arguments_values[j] = strdup(wf->tasks[i].arguments_values[jj]);
							break;
						}
					if (j >= wf->tasks[i].arguments_num) {
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Override key of parameter '%s' of task '%s' with '%s'\n", wf->tasks[i].arguments_keys[jj],
							   wf->tasks[i].name, OPH_ARG_VALUES);
						free(wf->tasks[i].arguments_keys[jj]);
						wf->tasks[i].arguments_keys[jj] = strdup(OPH_ARG_VALUES);
					}
					wf->tasks[i].massive_expansion = 1;
				}
			}

			for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
				if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_PARALLEL) && !wf->tasks[i].parallel_mode) {
					if (!strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_YES))
						wf->parallel_mode = wf->tasks[i].parallel_mode = 1;
					else if (strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_NO))
						break;
				}
			}
			if (j < wf->tasks[i].arguments_num) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Bad argument '%s' of task '%s'.\n", OPH_OPERATOR_PARAMETER_PARALLEL, wf->tasks[i].name);
				break;
			}
			if (!wf->tasks[i].parallel_mode)
				continue;

			if (wf->tasks[i].nesting_level > nesting_level) {
				wf->tasks[i].parallel_mode = 0;	// Skip this parallel-for now 
				found = 1;
				continue;
			}

			name = NULL;
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
			svalues_num = ivalues_num = 0;

			// Extract the other arguments
			for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
				if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_KEY) && !name)
					name = wf->tasks[i].arguments_values[j];
				else if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_VALUES) && !svalues && strlen(wf->tasks[i].arguments_values[j])
					 && strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_NULL)) {
					char *pch1;
					pch = strchr(wf->tasks[i].arguments_values[j], OPH_SEPARATOR_SUBPARAM);
					for (svalues_num++; pch; svalues_num++) {
						pch1 = pch + 1;
						if (!pch1 || !*pch1)
							break;
						pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
					}
					svalues = (char **) malloc(svalues_num * sizeof(char *));
					if (!svalues)
						break;
					char *tmp = strdup(wf->tasks[i].arguments_values[j]);
					if (!tmp)
						break;
					pch = strtok_r(tmp, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
					for (kk = 0; kk < svalues_num; ++kk) {
						svalues[kk] = strndup(pch, OPH_WORKFLOW_MAX_STRING);
						if (!svalues[kk])
							break;
						pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
					}
					free(tmp);
					if (kk < svalues_num)
						break;
				}
			}
			if (j < wf->tasks[i].arguments_num) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Generic error in parsing arguments of task '%s'.\n", wf->tasks[i].name);
				break;
			}
			for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
				if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_COUNTER) && !ivalues && strlen(wf->tasks[i].arguments_values[j])
				    && strcasecmp(wf->tasks[i].arguments_values[j], OPH_COMMON_NULL)) {
					oph_subset *subset_struct = NULL;
					if (oph_subset_init(&subset_struct)) {
						oph_subset_free(subset_struct);
						break;
					}
					if (oph_subset_parse(wf->tasks[i].arguments_values[j], strlen(wf->tasks[i].arguments_values[j]), subset_struct, svalues_num)) {
						oph_subset_free(subset_struct);
						break;
					}
					ivalues_num = subset_struct->total;
					ivalues = (int *) malloc(ivalues_num * sizeof(int));
					if (!ivalues) {
						oph_subset_free(subset_struct);
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
			}
			if (j < wf->tasks[i].arguments_num) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Generic error in parsing arguments of task '%s'.\n", wf->tasks[i].name);
				break;
			}
			for (kk = 0; name && (kk < (int) strlen(name)); ++kk)	// check compliance with IEEE Std 1003.1-2001 conventions
			{
				if ((name[kk] == '_') || ((name[kk] >= 'A') && (name[kk] <= 'Z')) || ((name[kk] >= 'a') && (name[kk] <= 'z')) || (kk && (name[kk] >= '0') && (name[kk] <= '9')))
					continue;
				for (kkk = 0; kkk < lll; ++kkk)
					if (name[kk] == OPH_WORKFLOW_SEPARATORS[kkk]) {
						name = NULL;
						break;
					}
				break;
			}
			if (!name) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Bad argument '%s' of task '%s'.\n", OPH_ARG_KEY, wf->tasks[i].name);
				break;
			}
			if (svalues_num) {
				if (ivalues_num && (ivalues_num != svalues_num)) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Arguments '%s' and '%s' have different sizes.\n", OPH_ARG_VALUES,
						   OPH_OPERATOR_PARAMETER_COUNTER, wf->tasks[i].name);
					break;
				}
			} else
				svalues_num = ivalues_num ? ivalues_num : 1;	// One loop is executed by default
			new_branch_num = svalues_num - 1;	// Number of new branches

			// Mark inner tasks
			replied_num = 0;
			for (j = 0; j < wf->tasks_num; ++j)
				wf->tasks[j].is_marked = 0;
			if (oph_workflow_mark_children_of(wf, i, i)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in processing task '%s'.\n", wf->tasks[i].name);
				break;
			}
			// Count inner tasks
			for (j = 0; j < wf->tasks_num; ++j)
				if (wf->tasks[j].is_marked)
					replied_num++;
			if (!replied_num)
				continue;

			// Add the number of branches to workflow environment
			size_t name_size = 2 + strlen(name) + strlen(OPH_WORKFLOW_COUNTER_SIZE);
			char number_of_loops[name_size];
			snprintf(number_of_loops, var_size, "%s_" OPH_WORKFLOW_COUNTER_SIZE, name);
			if (!hashtbl_get(wf->vars, number_of_loops)) {
				var.caller = -1;	// Global scope
				var.ivalue = 1;	// Non used
				var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
				if (var.svalue)
					snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", svalues_num);
				if (!var.svalue) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
					break;
				}
				svalue_size = strlen(var.svalue) + 1;
				var_buffer = malloc(var_size + svalue_size);
				if (!var_buffer) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
					free(var.svalue);
					break;
				}
				memcpy(var_buffer, (void *) &var, var_size);
				memcpy(var_buffer + var_size, var.svalue, svalue_size);
				if (hashtbl_insert_with_size(wf->vars, number_of_loops, var_buffer, var_size + svalue_size)) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to store variable '%s' in environment of task '%s'. Maybe it already exists.\n",
						   number_of_loops, wf->tasks[j].name);
					free(var.svalue);
					free(var_buffer);
					break;
				}
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%s' in environment of task '%s'.\n", number_of_loops, var.svalue, wf->tasks[j].name);
				free(var.svalue);
				free(var_buffer);
			}
			// In case no additional branch has to be created, simply add for-variable as task local variable to marked tasks
			if (!new_branch_num) {
				for (j = 0; j < wf->tasks_num; ++j)
					if (wf->tasks[j].is_marked) {
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
							break;
						}
						svalue_size = strlen(var.svalue) + 1;
						var_buffer = malloc(var_size + svalue_size);
						if (!var_buffer) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
							free(var.svalue);
							break;
						}
						memcpy(var_buffer, (void *) &var, var_size);
						memcpy(var_buffer + var_size, var.svalue, svalue_size);
						if (hashtbl_insert_with_size(wf->tasks[j].vars, name, var_buffer, var_size + svalue_size)) {
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to store variable '%s' in environment of task '%s'. Maybe it already exists.\n",
								   name, wf->tasks[j].name);
							free(var.svalue);
							free(var_buffer);
							break;
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%s' in environment of task '%s'.\n", name, var.svalue, wf->tasks[j].name);
						free(var.svalue);
						free(var_buffer);
					}
				continue;
			}

			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%d task%s will be replied %d time%s.\n", replied_num, replied_num == 1 ? "" : "s", new_branch_num,
				   new_branch_num == 1 ? "" : "s");

			// Expand tasks
			old_tasks_num = wf->tasks_num;
			if (oph_workflow_expand(wf, old_tasks_num + replied_num * new_branch_num)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in processing task '%s'.\n", wf->tasks[i].name);
				break;
			}
			// Fill new tasks
			for (j = 0; j < new_branch_num; ++j) {
				for (kk = kkk = 0; kk < replied_num; kkk++) {
					if (wf->tasks[kkk].is_marked) {
						kkkk = old_tasks_num + j * replied_num + kk;
						if (oph_workflow_copy_task(wf->tasks + kkk, wf->tasks + kkkk, 2 + j)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in copy task '%s'.\n", wf->tasks[kkk].name);
							break;
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Task '%s' (index %d) has been copied with index %d.\n", wf->tasks[kkk].name, kkk, kkkk);
						if (!j)
							new_index[kkk] = kk;
						kk++;
					}
				}
				if (kk < replied_num)
					break;
			}
			for (j = 0; j < old_tasks_num; ++j)
				if (wf->tasks[j].is_marked) {
					size_t length = strlen(wf->tasks[j].name) - 1;
					char tmp[length + OPH_WORKFLOW_MIN_STRING];
					if (wf->tasks[j].name[length] == OPH_WORKFLOW_NAME_EXPANSION_END) {
						wf->tasks[j].name[length] = 0;
						sprintf(tmp, OPH_WORKFLOW_NAME_EXPANSION2, wf->tasks[j].name, 1);
					} else
						sprintf(tmp, OPH_WORKFLOW_NAME_EXPANSION1, wf->tasks[j].name, 1);
					free(wf->tasks[j].name);
					wf->tasks[j].name = strdup(tmp);
				}
			for (j = 0; j < new_branch_num; ++j)
				for (kk = 0; kk < replied_num; kk++) {
					kkkk = old_tasks_num + j * replied_num + kk;
					for (k = 0; k < wf->tasks[kkkk].dependents_indexes_num; k++)
						if (wf->tasks[wf->tasks[kkkk].dependents_indexes[k]].is_marked)
							wf->tasks[kkkk].dependents_indexes[k] = old_tasks_num + j * replied_num + new_index[wf->tasks[kkkk].dependents_indexes[k]];
					for (k = 0; k < wf->tasks[kkkk].deps_num; k++) {
						if (wf->tasks[wf->tasks[kkkk].deps[k].task_index].is_marked)
							wf->tasks[kkkk].deps[k].task_index = old_tasks_num + j * replied_num + new_index[wf->tasks[kkkk].deps[k].task_index];
						if (wf->tasks[kkkk].deps[k].task_name)
							free(wf->tasks[kkkk].deps[k].task_name);
						wf->tasks[kkkk].deps[k].task_name = strdup(wf->tasks[wf->tasks[kkkk].deps[k].task_index].name);
					}
				}

			// Update dependence data
			for (j = 0; j < old_tasks_num; ++j) {
				if (!wf->tasks[j].is_marked) {
					kkk = 0;
					int tmp_array[new_branch_num * replied_num];
					for (k = 0; k < wf->tasks[j].dependents_indexes_num; k++)
						if (wf->tasks[wf->tasks[j].dependents_indexes[k]].is_marked)
							for (kk = 0; kk < new_branch_num; ++kk)
								tmp_array[kkk++] = old_tasks_num + kk * replied_num + new_index[wf->tasks[j].dependents_indexes[k]];
					if (kkk) {
						old_dependents_indexes_num = wf->tasks[j].dependents_indexes_num;
						old_dependents_indexes = wf->tasks[j].dependents_indexes;
						wf->tasks[j].dependents_indexes_num += kkk;
						wf->tasks[j].dependents_indexes = (int *) malloc(wf->tasks[j].dependents_indexes_num * sizeof(int));
						memcpy(wf->tasks[j].dependents_indexes, old_dependents_indexes, old_dependents_indexes_num * sizeof(int));
						memcpy(wf->tasks[j].dependents_indexes + old_dependents_indexes_num, tmp_array, kkk * sizeof(int));
						free(old_dependents_indexes);
					}

					kkk = 0;
					oph_workflow_dep tmp_array_dep[new_branch_num * replied_num];
					for (k = 0; k < wf->tasks[j].deps_num; k++)
						if (wf->tasks[wf->tasks[j].deps[k].task_index].is_marked)
							for (kk = 0; kk < new_branch_num; ++kk) {
								memcpy(tmp_array_dep + kkk, wf->tasks[j].deps + k, sizeof(oph_workflow_dep));
								if (wf->tasks[j].deps[k].argument && !((tmp_array_dep[kkk].argument = strdup(wf->tasks[j].deps[k].argument))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								if (wf->tasks[j].deps[k].order && !((tmp_array_dep[kkk].order = strdup(wf->tasks[j].deps[k].order))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								if (wf->tasks[j].deps[k].type && !((tmp_array_dep[kkk].type = strdup(wf->tasks[j].deps[k].type))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								if (wf->tasks[j].deps[k].filter && !((tmp_array_dep[kkk].filter = strdup(wf->tasks[j].deps[k].filter))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								if (wf->tasks[j].deps[k].output_argument && !((tmp_array_dep[kkk].output_argument = strdup(wf->tasks[j].deps[k].output_argument))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								if (wf->tasks[j].deps[k].output_order && !((tmp_array_dep[kkk].output_order = strdup(wf->tasks[j].deps[k].output_order))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								tmp_array_dep[kkk].task_index = old_tasks_num + kk * replied_num + new_index[wf->tasks[j].deps[k].task_index];
								if (!((tmp_array_dep[kkk].task_name = strdup(wf->tasks[tmp_array_dep[kkk].task_index].name))))
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								kkk++;
							}
					if (kkk) {
						old_deps_num = wf->tasks[j].deps_num;
						old_deps = wf->tasks[j].deps;
						wf->tasks[j].deps_num += kkk;
						wf->tasks[j].residual_deps_num += kkk;
						wf->tasks[j].deps = (oph_workflow_dep *) malloc(wf->tasks[j].deps_num * sizeof(oph_workflow_dep));
						memcpy(wf->tasks[j].deps, old_deps, old_deps_num * sizeof(oph_workflow_dep));
						memcpy(wf->tasks[j].deps + old_deps_num, tmp_array_dep, kkk * sizeof(oph_workflow_dep));
						free(old_deps);
					}
				} else
					for (k = 0; k < wf->tasks[j].deps_num; k++) {
						if (wf->tasks[j].deps[k].task_name)
							free(wf->tasks[j].deps[k].task_name);
						wf->tasks[j].deps[k].task_name = strdup(wf->tasks[wf->tasks[j].deps[k].task_index].name);
					}
			}
			for (j = 0; j < old_tasks_num; ++j)
				for (k = 0; k < wf->tasks[j].deps_num; ++k) {
					kk = wf->tasks[j].deps[k].task_index;
					if (wf->tasks[kk].is_marked && (kk < old_tasks_num)) {
						if (wf->tasks[j].deps[k].task_name)
							free(wf->tasks[j].deps[k].task_name);
						wf->tasks[j].deps[k].task_name = strdup(wf->tasks[kk].name);
					}
				}

			// Add for-variable as task local variable
			for (j = 0; j < wf->tasks_num; ++j)
				if (wf->tasks[j].is_marked) {
					if (j < old_tasks_num)
						k = 0;
					else
						k = 1 + (j - old_tasks_num) / replied_num;
					var.caller = i;
					if (ivalues)
						var.ivalue = ivalues[k];
					else
						var.ivalue = 1 + k;	// Non C-like indexing
					if (svalues)
						var.svalue = strdup(svalues[k]);
					else {
						var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
						if (var.svalue)
							snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", var.ivalue);
					}
					if (!var.svalue) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
						break;
					}
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					if (!var_buffer) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
						free(var.svalue);
						break;
					}
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->tasks[j].vars, name, var_buffer, var_size + svalue_size)) {
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to store variable '%s' in environment of task '%s'. Maybe it already exists.\n", name,
							   wf->tasks[j].name);
						free(var.svalue);
						free(var_buffer);
						break;
					}
					if (svalues)
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%s' in environment of task '%s'.\n", name, var.svalue, wf->tasks[j].name);
					else
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%d' in environment of task '%s'.\n", name, var.ivalue, wf->tasks[j].name);
					free(var.svalue);
					free(var_buffer);
				}

			exploded = 1;
			break;
		}
	}
	if (ivalues)
		free(ivalues);
	if (svalues) {
		for (kk = 0; kk < svalues_num; ++kk)
			if (svalues[kk])
				free(svalues[kk]);
		free(svalues);
	}
	if (i < wf->tasks_num) {
		if (exploded)
			return oph_workflow_parallel_fco(wf, nesting_level, state);
		else
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	if (found)
		return oph_workflow_parallel_fco(wf, nesting_level + 1, state);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Thread safe
int oph_workflow_execute(struct oph_plugin_data *state, char ttype, int jobid, oph_workflow * wf, int *tasks_indexes, int tasks_indexes_num, ophidiadb * oDB, char **jobid_response)
{
	if (!state || !wf || !oDB) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: wrong parameters\n", ttype, jobid);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	if (!tasks_indexes_num) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: no tasks have to be executed\n", ttype, jobid);
		return OPH_WORKFLOW_EXIT_SUCCESS;
	}

	if (!tasks_indexes) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: wrong parameters\n", ttype, jobid);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	int i, j, k, odb_jobid, first = 1, res, nn = 0, nnn;
	char *submission_string, *sss, *errore, str_markerid[OPH_SHORT_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], oph_jobid[OPH_MAX_STRING_SIZE], *submission_string_ext =
	    NULL, *output_json = NULL;

	oph_request_data *request_data[tasks_indexes_num];
	int request_data_dim[tasks_indexes_num];
	for (k = 0; k < tasks_indexes_num; ++k) {
		request_data[k] = NULL;
		request_data_dim[k] = 0;
	}

	pthread_mutex_lock(&global_flag);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: check for executing new jobs\n", ttype, jobid);

	// Init the hashtable
	HASHTBL *task_tbl = hashtbl_create(5, NULL);
	if (!task_tbl) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to create hash table.\n", ttype, jobid);
		pthread_mutex_unlock(&global_flag);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	hashtbl_insert(task_tbl, OPH_ARG_SESSIONID, wf->sessionid);
	hashtbl_insert(task_tbl, OPH_ARG_USERNAME, wf->username);
	snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->idjob);
	hashtbl_insert(task_tbl, OPH_ARG_PARENTID, str_markerid);	// Old workflow id
	snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
	hashtbl_insert(task_tbl, OPH_ARG_WORKFLOWID, str_workflowid);
	*str_markerid = 0;

	if ((wf->status < (int) OPH_ODB_STATUS_COMPLETED) || (tasks_indexes[0] == wf->tasks_num))
		for (k = 0; k < tasks_indexes_num; ++k) {
			if (output_json) {
				free(output_json);
				output_json = NULL;
			}

			i = tasks_indexes[k];

			// Check the indexes
			if ((i < 0) || (i > wf->tasks_num) || ((i == wf->tasks_num) && strcmp(wf->tasks[i].name, OPH_WORKFLOW_FINAL_TASK))) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: index out of boundary\n", ttype, jobid);
				continue;
			}

			if (wf->tasks[i].residual_deps_num || wf->tasks[i].status)
				continue;

			for (j = 0; j < wf->tasks[i].arguments_num; ++j)
				if (wf->tasks[i].arguments_lists[j]) {
					if (oph_workflow_print_list(wf->tasks[i].arguments_lists[j], wf->tasks[i].arguments_values + j)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error while filling the argument '%s' of task '%s'\n", ttype, jobid, wf->tasks[i].arguments_keys[j],
						      wf->tasks[i].name);
						pthread_mutex_unlock(&global_flag);
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					oph_workflow_free_list(wf->tasks[i].arguments_lists[j]);
					wf->tasks[i].arguments_lists[j] = NULL;
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: use '%s=%s' for task '%s'\n", ttype, jobid, wf->tasks[i].arguments_keys[j], wf->tasks[i].arguments_values[j],
					      wf->tasks[i].name);
				}

			if (!wf->tasks[i].idjob)	// Normal task
			{
				// Create the new markerid
				if (oph_generate_oph_jobid
				    (state, ttype, jobid, wf, NULL, 0, 0, wf->tasks[i].markerid ? NULL : &(wf->tasks[i].markerid), str_markerid, NULL, NULL, oph_jobid, wf->tasks[i].markerid)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: anew markerid cannot be created... aborting\n", ttype, jobid);
					wf->tasks[i].status = OPH_ODB_STATUS_ERROR;
					if (oph_workflow_set_status(ttype, jobid, wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, OPH_ODB_STATUS_ABORTED))
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in updating the status of dependents of '%s'\n", ttype, jobid, wf->tasks[i].name);

					nnn =
					    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid,
							 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
					submission_string_ext = (char *) malloc(nnn * sizeof(char));
					snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid,
						 wf->tasks[i].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

					request_data_dim[k] = 1;
					request_data[k] = (oph_request_data *) malloc(sizeof(oph_request_data));
					oph_request_data_init(request_data[k]);

					request_data[k]->serve_request = 0;
					request_data[k]->error_notification = submission_string_ext;
					request_data[k]->taskname = strdup(wf->tasks[i].name);

					continue;
				}
			} else	// Normal task: a re-execution has been invokated
			{
				snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[i].markerid);
				snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER,
					 wf->tasks[i].markerid);
			}
			if (!first)
				hashtbl_remove(task_tbl, OPH_ARG_MARKERID);
			else
				first = 0;
			hashtbl_insert(task_tbl, OPH_ARG_MARKERID, str_markerid);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: build the submission string of task '%s' of '%s'.\n", ttype, jobid, wf->tasks[i].name, wf->name);
			submission_string = sss = errore = NULL;
			if (oph_workflow_get_submission_string(wf, i, -1, &submission_string, &sss, &errore)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: submission string cannot be loaded\n", ttype, jobid);
				wf->tasks[i].status = OPH_ODB_STATUS_ERROR;
				if (oph_workflow_set_status(ttype, jobid, wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, OPH_ODB_STATUS_ABORTED))
					pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in updating the status of dependents of '%s'\n", ttype, jobid, wf->tasks[i].name);

				nnn =
				    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid,
						 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
				submission_string_ext = (char *) malloc(nnn * sizeof(char));
				snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid,
					 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

				if (!oph_odb_create_job_unsafe(oDB, sss ? sss : "-", task_tbl, wf->tasks[i].light_tasks_num ? wf->tasks[i].light_tasks_num : -1, &odb_jobid))
					oph_odb_abort_job_fast(odb_jobid, oDB);

				if (submission_string)
					free(submission_string);
				if (sss)
					free(sss);

				request_data_dim[k] = 1;
				request_data[k] = (oph_request_data *) malloc(sizeof(oph_request_data));
				oph_request_data_init(request_data[k]);

				request_data[k]->serve_request = 0;
				request_data[k]->error_notification = submission_string_ext;
				request_data[k]->taskname = strdup(wf->tasks[i].name);
				request_data[k]->markerid = strdup(str_markerid);
				request_data[k]->error = errore;

				continue;
			}

			char **output_list = NULL, remake_submission_string = 0;
			int output_list_dim = 0;
			if ((wf->tasks[i].parent < 0) && ((res = oph_check_for_massive_operation(state, ttype, jobid, wf, i, oDB, &output_list, &output_list_dim, NULL, &remake_submission_string)))) {
				odb_jobid = 0;
				// Create the child job in OphidiaDB
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: create the entry for '%s' in OphidiaDB.\n", ttype, jobid, wf->tasks[i].name);
				if (oph_odb_create_job_unsafe(oDB, sss, task_tbl, 0, &odb_jobid))
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to save job parameters into OphidiaDB. Check access parameters.\n", ttype, jobid);
				else
					wf->tasks[i].idjob = odb_jobid;

				// Save JSON related to parent job
				int success = 0;
				oph_json *oper_json = NULL;

				char str_jobid[OPH_MAX_STRING_SIZE];
				char session_code[OPH_MAX_STRING_SIZE];

				snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER,
					 wf->tasks[i].markerid);
				snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
				snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[i].markerid);

				char error_message[OPH_MAX_STRING_SIZE];
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Parent task data processing failed!");

				while (!success) {
					if (oph_json_alloc_unsafe(&oper_json)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
						break;
					}
					if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
						break;
					}
					if (oph_get_session_code(wf->sessionid, session_code)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "Session Code", session_code)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "Workflow", str_workflowid)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "Marker", str_markerid)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "JobID", str_jobid)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_consumer_unsafe(oper_json, wf->username)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
						break;
					}
					success = 1;
				}

				if (res == OPH_SERVER_NO_RESPONSE) {
					wf->tasks[i].status = OPH_ODB_STATUS_COMPLETED;

					if (!success)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
					else if (output_list_dim) {
						int num_fields = 1, iii, jjj = 0;
						char **jsonkeys = NULL;
						char **fieldtypes = NULL;
						char **jsonvalues = NULL;

						success = 0;
						while (!success) {
							if (oph_json_add_text
							    (oper_json, OPH_JSON_OBJKEY_MASSIVE_STATUS, "Massive Operation Status", oph_odb_convert_status_to_str(wf->tasks[i].status))) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
								break;
							}
							// Header
							jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonkeys) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								break;
							}
							jsonkeys[jjj] = strdup("OBJECT");
							if (!jsonkeys[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							fieldtypes[jjj] = strdup(OPH_JSON_STRING);
							if (!fieldtypes[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							if (oph_json_add_grid_unsafe
							    (oper_json, OPH_JSON_OBJKEY_MASSIVE_LIST, "Massive Operation Target List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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

							for (j = 0; j < output_list_dim; ++j) {
								jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonvalues) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									break;
								}
								jjj = 0;
								jsonvalues[jjj] = strdup(output_list[j]);
								if (!jsonvalues[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								if (oph_json_add_grid_row_unsafe(oper_json, OPH_JSON_OBJKEY_MASSIVE_LIST, jsonvalues)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID ROW error\n", ttype, jobid);
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

							if (j < output_list_dim)
								break;
							else
								success = 1;
						}
					} else {
						int num_fields = wf->output_format ? 2 : 6, iii, jjj = 0;
						char **jsonkeys = NULL;
						char **fieldtypes = NULL;

						success = 0;
						while (!success) {
							if (oph_json_add_text
							    (oper_json, OPH_JSON_OBJKEY_MASSIVE_STATUS, "Massive Operation Status", oph_odb_convert_status_to_str(wf->tasks[i].status))) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
								break;
							}
							// Header
							if (wf->output_format) {

								int num_fields = 3;
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									break;
								}
								jsonkeys[jjj] = strdup("OPH JOB ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("WORKFLOW ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("PARENT MARKER ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
								if (oph_json_add_grid_unsafe
								    (oper_json, OPH_JSON_OBJKEY_MASSIVE_INFO, "Massive Operation Information", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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

							jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonkeys) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								break;
							}
							jjj = 0;
							if (!wf->output_format) {
								jsonkeys[jjj] = strdup("OPH JOB ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("SESSION CODE");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("WORKFLOW ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
							}
							jsonkeys[jjj] = strdup("MARKER ID");
							if (!jsonkeys[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							jjj++;
							if (!wf->output_format) {
								jsonkeys[jjj] = strdup("PARENT MARKER ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
							}
							jsonkeys[jjj] = strdup("EXIT STATUS");
							if (!jsonkeys[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
							if (!fieldtypes) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							jjj = 0;
							if (!wf->output_format) {
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							}
							fieldtypes[jjj] = strdup(OPH_JSON_INT);
							if (!fieldtypes[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							if (!wf->output_format) {
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							}
							fieldtypes[jjj] = strdup(OPH_JSON_STRING);
							if (!fieldtypes[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							if (oph_json_add_grid_unsafe
							    (oper_json, OPH_JSON_OBJKEY_MASSIVE_LIST, "Massive Operation Task List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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
				} else {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in parsing the request\n", ttype, jobid);
					wf->tasks[i].status = OPH_ODB_STATUS_ERROR;

					if (!success)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
					else {
						success = 0;
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Error in parsing the request!");
					}
				}

				if (oper_json) {
					int return_code = 0;
					if (!success) {
						if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
							return_code = -1;
						} else if (oph_write_and_get_json_unsafe(oper_json, &output_json))
							return_code = -1;
					} else {
						char tmp[OPH_MAX_STRING_SIZE];
						if (output_list_dim)
							snprintf(tmp, OPH_MAX_STRING_SIZE, "Found %d object%s", output_list_dim, output_list_dim == 1 ? "" : "s");
						else
							snprintf(tmp, OPH_MAX_STRING_SIZE, "No object found!");
						if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_MASSIVE_SUMMARY, output_list_dim ? "SUMMARY" : "WARNING", tmp)) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
							return_code = -1;
						}
						if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
							return_code = -1;
						} else if (oph_write_and_get_json_unsafe(oper_json, &output_json))
							return_code = -1;
					}
					if (!return_code)
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
				}
				oph_json_free_unsafe(oper_json);

				for (j = 0; j < output_list_dim; ++j)
					if (output_list[j])
						free(output_list[j]);
				if (output_list)
					free(output_list);
				output_list = NULL;

				// Save the status
				if (odb_jobid && oph_odb_set_job_status_and_nchildrencompleted(wf->tasks[i].idjob, wf->tasks[i].status, -1, 0, oDB))
					pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to update job status\n", ttype, jobid);

				nnn = 1 + snprintf(NULL, 0, "%s%s=%d;", submission_string, OPH_ARG_JOBID, odb_jobid);
				submission_string_ext = (char *) malloc(nnn * sizeof(char));
				snprintf(submission_string_ext, nnn, "%s%s=%d;", submission_string, OPH_ARG_JOBID, odb_jobid);

				if (submission_string)
					free(submission_string);
				if (sss)
					free(sss);

				request_data_dim[k] = 1;
				request_data[k] = (oph_request_data *) malloc(sizeof(oph_request_data));
				oph_request_data_init(request_data[k]);

				request_data[k]->serve_request = 0;
				request_data[k]->jobid = odb_jobid;
				request_data[k]->submission_string = submission_string_ext;
				request_data[k]->markerid = strdup(str_markerid);
				request_data[k]->task_id = i;
				request_data[k]->light_task_id = -1;
				if (output_json)
					request_data[k]->output_json = strdup(output_json);

				nnn =
				    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, request_data[k]->task_id, request_data[k]->light_task_id, odb_jobid, wf->tasks[i].status,
						 wf->sessionid, wf->tasks[i].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
				submission_string_ext = (char *) malloc(nnn * sizeof(char));
				snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, request_data[k]->task_id, request_data[k]->light_task_id, odb_jobid,
					 wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

				request_data[k]->error_notification = submission_string_ext;
				request_data[k]->taskname = strdup(wf->tasks[i].name);

				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: massive operation '%s' is finished\n", ttype, jobid, wf->tasks[i].name);

				continue;
			}
			// Create the child job in OphidiaDB
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: create the entry for '%s' in OphidiaDB.\n", ttype, jobid, wf->tasks[i].name);
			if (oph_odb_create_job_unsafe(oDB, sss, task_tbl, wf->tasks[i].light_tasks_num ? wf->tasks[i].light_tasks_num : -1, &odb_jobid)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to save job parameters into OphidiaDB. Check access parameters.\n", ttype, jobid);
				wf->tasks[i].status = OPH_ODB_STATUS_ERROR;
				if (oph_workflow_set_status(ttype, jobid, wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, OPH_ODB_STATUS_ABORTED))
					pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in updating the status of dependents of '%s'\n", ttype, jobid, wf->tasks[i].name);

				nnn =
				    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid,
						 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
				submission_string_ext = (char *) malloc(nnn * sizeof(char));
				snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid,
					 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

				if (submission_string)
					free(submission_string);
				if (sss)
					free(sss);

				request_data_dim[k] = 1;
				request_data[k] = (oph_request_data *) malloc(sizeof(oph_request_data));
				oph_request_data_init(request_data[k]);

				request_data[k]->serve_request = 0;
				request_data[k]->error_notification = submission_string_ext;
				request_data[k]->taskname = strdup(wf->tasks[i].name);

				continue;
			}
			wf->tasks[i].idjob = odb_jobid;

			if (remake_submission_string)	// OPH_IMPORTNCS
			{
				if (submission_string)
					free(submission_string);
				if (sss)
					free(sss);

				submission_string = sss = errore = NULL;
				if (oph_workflow_get_submission_string(wf, i, -1, &submission_string, &sss, &errore)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: submission string cannot be loaded\n", ttype, jobid);
					wf->tasks[i].status = OPH_ODB_STATUS_ERROR;
					if (oph_workflow_set_status(ttype, jobid, wf, wf->tasks[i].dependents_indexes, wf->tasks[i].dependents_indexes_num, OPH_ODB_STATUS_ABORTED))
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in updating the status of dependents of '%s'\n", ttype, jobid, wf->tasks[i].name);

					nnn =
					    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid, wf->tasks[i].markerid,
							 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
					submission_string_ext = (char *) malloc(nnn * sizeof(char));
					snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, -1, wf->tasks[i].idjob, wf->tasks[i].status, wf->sessionid,
						 wf->tasks[i].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

					if (!oph_odb_create_job_unsafe(oDB, sss ? sss : "-", task_tbl, wf->tasks[i].light_tasks_num ? wf->tasks[i].light_tasks_num : -1, &odb_jobid))
						oph_odb_abort_job_fast(odb_jobid, oDB);

					if (submission_string)
						free(submission_string);
					if (sss)
						free(sss);

					request_data_dim[k] = 1;
					request_data[k] = (oph_request_data *) malloc(sizeof(oph_request_data));
					oph_request_data_init(request_data[k]);

					request_data[k]->serve_request = 0;
					request_data[k]->error_notification = submission_string_ext;
					request_data[k]->taskname = strdup(wf->tasks[i].name);
					request_data[k]->markerid = strdup(str_markerid);
					request_data[k]->error = errore;

					continue;
				}
			}

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: initialize variables to be sent to resource manager.\n", ttype, jobid);
			if (wf->tasks[i].light_tasks_num)	// Massive operation
			{
				if (submission_string)
					free(submission_string);
				if (sss)
					free(sss);

				request_data_dim[k] = wf->tasks[i].light_tasks_num;
				request_data[k] = (oph_request_data *) malloc(request_data_dim[k] * sizeof(oph_request_data));
				oph_request_data_vector_init(request_data[k], request_data_dim[k]);

				char str_parent[OPH_SHORT_STRING_SIZE];
				snprintf(str_parent, OPH_SHORT_STRING_SIZE, "%d", odb_jobid);
				hashtbl_remove(task_tbl, OPH_ARG_PARENTID);
				hashtbl_insert(task_tbl, OPH_ARG_PARENTID, str_parent);

				char retry = (oph_auto_retry && wf->tasks[i].residual_auto_retry_num && (wf->tasks[i].retry_num == 1)) || (wf->tasks[i].residual_retry_num
																	   && (wf->tasks[i].retry_num > 1));
				for (j = 0; j < wf->tasks[i].light_tasks_num; ++j) {
					if (wf->tasks[i].light_tasks[j].status) {
						if (!retry) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unexpected task with an active state '%s'\n", ttype, jobid,
							      oph_odb_convert_status_to_str(wf->tasks[i].light_tasks[j].status));
							wf->tasks[i].light_tasks[j].status = OPH_ODB_STATUS_ERROR;
						}

						nnn =
						    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob, wf->tasks[i].light_tasks[j].status,
								 wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
						submission_string_ext = (char *) malloc(nnn * sizeof(char));
						snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob,
							 wf->tasks[i].light_tasks[j].status, wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

						request_data[k][j].serve_request = 0;
						request_data[k][j].error_notification = submission_string_ext;
						request_data[k][j].taskname = strdup(wf->tasks[i].name);

						continue;
					}
					// Create the new markerid
					if (oph_generate_oph_jobid
					    (state, ttype, jobid, wf, NULL, 0, 0, &(wf->tasks[i].light_tasks[j].markerid), str_markerid, NULL, NULL, oph_jobid, wf->tasks[i].light_tasks[j].markerid)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: anew markerid cannot be created... aborting\n", ttype, jobid);
						wf->tasks[i].light_tasks[j].status = OPH_ODB_STATUS_ERROR;

						nnn =
						    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob, wf->tasks[i].light_tasks[j].status,
								 wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
						submission_string_ext = (char *) malloc(nnn * sizeof(char));
						snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob,
							 wf->tasks[i].light_tasks[j].status, wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

						request_data[k][j].serve_request = 0;
						request_data[k][j].error_notification = submission_string_ext;

						continue;
					}
					if (retry)
						sprintf(str_markerid, "%d", wf->tasks[i].light_tasks[j].markerid);
					hashtbl_remove(task_tbl, OPH_ARG_MARKERID);
					hashtbl_insert(task_tbl, OPH_ARG_MARKERID, str_markerid);

					// Build the preliminary submission string (without jobid)
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: build preliminary submission string of task '%s' of '%s'.\n", ttype, jobid, wf->tasks[i].name, wf->name);
					submission_string = sss = errore = NULL;
					if (oph_workflow_get_submission_string(wf, i, j, &submission_string, &sss, &errore)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: submission string cannot be loaded\n", ttype, jobid);
						wf->tasks[i].light_tasks[j].status = OPH_ODB_STATUS_ERROR;

						nnn =
						    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob, wf->tasks[i].light_tasks[j].status,
								 wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
						submission_string_ext = (char *) malloc(nnn * sizeof(char));
						snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob,
							 wf->tasks[i].light_tasks[j].status, wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

						if (!oph_odb_create_job_unsafe(oDB, sss ? sss : "-", task_tbl, -1, &odb_jobid))
							oph_odb_abort_job_fast(odb_jobid, oDB);

						if (submission_string)
							free(submission_string);
						if (sss)
							free(sss);

						request_data[k][j].serve_request = 0;
						request_data[k][j].error_notification = submission_string_ext;
						request_data[k][j].taskname = strdup(wf->tasks[i].name);
						request_data[k][j].markerid = strdup(str_markerid);
						request_data[k][j].error = errore;

						continue;
					}
					// Create the child job in OphidiaDB
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: create the entry for the light task %d of '%s' in OphidiaDB using markerid '%s'.\n", ttype, jobid, j,
					      wf->tasks[i].name, str_markerid);
					if (oph_odb_create_job_unsafe(oDB, sss, task_tbl, -1, &odb_jobid)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to save job parameters into OphidiaDB. Check access parameters.\n", ttype, jobid);
						wf->tasks[i].light_tasks[j].status = OPH_ODB_STATUS_ERROR;

						nnn =
						    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob, wf->tasks[i].light_tasks[j].status,
								 wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
						submission_string_ext = (char *) malloc(nnn * sizeof(char));
						snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, i, j, wf->tasks[i].light_tasks[j].idjob,
							 wf->tasks[i].light_tasks[j].status, wf->sessionid, wf->tasks[i].light_tasks[j].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);

						if (submission_string)
							free(submission_string);
						if (sss)
							free(sss);

						request_data[k][j].serve_request = 0;
						request_data[k][j].error_notification = submission_string_ext;
						request_data[k][j].taskname = strdup(wf->tasks[i].name);
						request_data[k][j].markerid = strdup(str_markerid);

						continue;
					}
					wf->tasks[i].light_tasks[j].idjob = odb_jobid;

					nnn = 1 + snprintf(NULL, 0, "%s%s=%d;", submission_string, OPH_ARG_JOBID, odb_jobid);
					submission_string_ext = (char *) malloc(nnn * sizeof(char));
					snprintf(submission_string_ext, nnn, "%s%s=%d;", submission_string, OPH_ARG_JOBID, odb_jobid);

					if (submission_string)
						free(submission_string);
					if (sss)
						free(sss);

					request_data[k][j].serve_request = 1;
					request_data[k][j].jobid = odb_jobid;
					request_data[k][j].submission_string = submission_string_ext;
					request_data[k][j].markerid = strdup(str_markerid);
					request_data[k][j].ncores = wf->tasks[i].light_tasks[j].ncores;
					request_data[k][j].status = &(wf->tasks[i].light_tasks[j].status);
					request_data[k][j].task_id = i;
					request_data[k][j].light_task_id = j;
					request_data[k][j].run = wf->tasks[i].run;
					request_data[k][j].delay = 0;

					nnn =
					    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, request_data[k][j].task_id, request_data[k][j].light_task_id,
							 wf->tasks[i].light_tasks[j].idjob, OPH_ODB_STATUS_START_ERROR, wf->sessionid, wf->tasks[i].light_tasks[j].markerid,
							 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
					submission_string_ext = (char *) malloc(nnn * sizeof(char));
					snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, request_data[k][j].task_id, request_data[k][j].light_task_id,
						 wf->tasks[i].light_tasks[j].idjob, OPH_ODB_STATUS_START_ERROR, wf->sessionid, wf->tasks[i].light_tasks[j].markerid,
						 wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
					request_data[k][j].error_notification = submission_string_ext;
					request_data[k][j].taskname = strdup(wf->tasks[i].name);

					wf->tasks[i].light_tasks[j].status = OPH_ODB_STATUS_PENDING;
				}

				if (!retry) {
					struct timeval tv;
					gettimeofday(&tv, 0);
					wf->tasks[i].timestamp = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);
					wf->tasks[i].status = OPH_ODB_STATUS_PENDING;
				} else
					wf->tasks[i].status = OPH_ODB_STATUS_RUNNING;

			} else	// Single operation
			{
				nnn = 1 + snprintf(NULL, 0, "%s%s=%d;", submission_string, OPH_ARG_JOBID, odb_jobid);
				submission_string_ext = (char *) malloc(nnn * sizeof(char));
				snprintf(submission_string_ext, nnn, "%s%s=%d;", submission_string, OPH_ARG_JOBID, odb_jobid);

				if (submission_string)
					free(submission_string);
				if (sss)
					free(sss);

				request_data_dim[k] = 1;
				request_data[k] = (oph_request_data *) malloc(sizeof(oph_request_data));
				oph_request_data_init(request_data[k]);

				request_data[k]->serve_request = 1;
				request_data[k]->jobid = wf->tasks[i].idjob;
				request_data[k]->submission_string = submission_string_ext;
				request_data[k]->markerid = strdup(str_markerid);
				request_data[k]->ncores = wf->tasks[i].ncores;
				request_data[k]->status = &(wf->tasks[i].status);
				request_data[k]->task_id = i;
				request_data[k]->light_task_id = -1;
				request_data[k]->run = wf->tasks[i].run;
				request_data[k]->delay = 0;

				if (wf->tasks[i].backoff_time > 0) {
					int retry_num = 0;
					if (wf->tasks[i].retry_num)
						retry_num = wf->tasks[i].retry_num - wf->tasks[i].residual_retry_num;
					if (oph_auto_retry && wf->tasks[i].residual_auto_retry_num) {
						int retry_num2 = 1 + oph_auto_retry - wf->tasks[i].residual_auto_retry_num;
						if (retry_num < retry_num2)
							retry_num = retry_num2;
					}
					if (retry_num > 0) {
						int backoff = wf->tasks[i].backoff_time;
						switch (wf->tasks[i].backoff_type) {
							case 'e':
								while (--retry_num)
									backoff <<= 1;
							case 'r':
								request_data[k]->delay = rand() % backoff;
								break;
							default:
								request_data[k]->delay = backoff;
								break;
						}
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: backoff size %d; chosen %d second%s\n", ttype, jobid, backoff, request_data[k]->delay,
						      request_data[k]->delay == 1 ? "" : "s");
					}
				}

				nnn =
				    1 + snprintf(NULL, 0, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, request_data[k]->task_id, request_data[k]->light_task_id, wf->tasks[i].idjob,
						 OPH_ODB_STATUS_START_ERROR, wf->sessionid, wf->tasks[i].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
				submission_string_ext = (char *) malloc(nnn * sizeof(char));
				snprintf(submission_string_ext, nnn, OPH_WORKFLOW_BASE_NOTIFICATION, wf->idjob, request_data[k]->task_id, request_data[k]->light_task_id, wf->tasks[i].idjob,
					 OPH_ODB_STATUS_START_ERROR, wf->sessionid, wf->tasks[i].markerid, wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
				request_data[k]->error_notification = submission_string_ext;
				request_data[k]->taskname = strdup(wf->tasks[i].name);

				struct timeval tv;
				gettimeofday(&tv, 0);
				wf->tasks[i].timestamp = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);

				wf->tasks[i].status = OPH_ODB_STATUS_PENDING;
			}
			nn++;
		}
	if (task_tbl) {
		hashtbl_destroy(task_tbl);
		task_tbl = NULL;
	}
	if (output_json) {
		free(output_json);
		output_json = NULL;
	}

	char *sessionid = strdup(wf->sessionid);
	char *username = strdup(wf->username);
	char *os_username = strdup(wf->os_username);
	char *project = wf->project ? strdup(wf->project) : NULL;
	int wid = wf->workflowid;
	odb_jobid = wf->idjob;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: %d task%s prepared for submission\n", ttype, jobid, nn, nn == 1 ? "" : "s");

	pthread_mutex_unlock(&global_flag);

	// Submit the commands
	int response, nnnn = 0, exit_output;
	char *json_response = NULL;
	enum oph__oph_odb_job_status exit_code = OPH_ODB_STATUS_PENDING;
	nn = nnn = 0;
	for (k = 0; k < tasks_indexes_num; ++k) {
		if (!request_data[k])
			continue;
		for (j = 0; j < request_data_dim[k]; ++j) {
			if (request_data[k][j].serve_request) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: call resource manager\n", ttype, jobid);
				if (!request_data[k][j].run) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: simulate task execution\n", ttype, jobid);
					char *success_notification =
					    oph_remake_notification(request_data[k][j].error_notification, request_data[k][j].task_id, request_data[k][j].light_task_id, request_data[k][j].jobid,
								    OPH_ODB_STATUS_COMPLETED, request_data[k][j].submission_string, sessionid);
					response = 0;
					oph_workflow_notify(state, ttype, jobid, success_notification ? success_notification : request_data[k][j].output_json, json_response, &response);
					if (response)
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: error %d in notify\n", ttype, jobid, response);
					if (success_notification)
						free(success_notification);
					nnn++;
				} else
				    if ((response =
					 oph_serve_request(request_data[k][j].submission_string, request_data[k][j].ncores, sessionid, request_data[k][j].markerid,
							   request_data[k][j].error_notification, state, &odb_jobid, &request_data[k][j].task_id, &request_data[k][j].light_task_id,
							   &request_data[k][j].jobid, request_data[k][j].delay, &json_response, jobid_response, &exit_code, &exit_output,
							   os_username, project, request_data[k][j].taskname, wid)) != OPH_SERVER_OK) {
					if (response == OPH_SERVER_NO_RESPONSE) {
						if (exit_code != OPH_ODB_STATUS_WAIT) {
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: notification auto-sending with code %s\n", ttype, jobid,
								   oph_odb_convert_status_to_str(exit_code));
							char *success_notification =
							    oph_remake_notification(request_data[k][j].error_notification, request_data[k][j].task_id, request_data[k][j].light_task_id,
										    request_data[k][j].jobid, exit_code, exit_output ? request_data[k][j].submission_string : NULL, sessionid);
							response = 0;
							oph_workflow_notify(state, ttype, jobid, success_notification ? success_notification : request_data[k][j].output_json, json_response,
									    &response);
							if (response)
								pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: error %d in notify\n", ttype, jobid, response);
							if (success_notification)
								free(success_notification);
						}
					} else {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: error in serving the request; reporting the notification '%s'\n", ttype, jobid,
							   request_data[k][j].error_notification);
						if (request_data[k][j].jobid) {
							if (!request_data[k][j].output_json) {
								int success = 0;
								oph_json *oper_json = NULL;

								char str_jobid[OPH_MAX_STRING_SIZE];
								char session_code[OPH_MAX_STRING_SIZE];

								snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid,
									 OPH_SESSION_MARKER_DELIMITER, request_data[k][j].markerid);
								if ((res = oph_get_session_code(sessionid, session_code)))
									pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);

								char error_message[OPH_MAX_STRING_SIZE];
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Error in sending the request!");

								while (!success) {
									if (oph_json_alloc(&oper_json)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
										break;
									}
									if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
										break;
									}
									if (res)
										break;
									if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
										break;
									}
									if (oph_json_add_source_detail(oper_json, "Workflow", str_workflowid)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
										break;
									}
									if (oph_json_add_source_detail(oper_json, "Marker", request_data[k][j].markerid)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
										break;
									}
									if (oph_json_add_source_detail(oper_json, "JobID", str_jobid)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
										break;
									}
									if (oph_json_add_consumer(oper_json, username)) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
										break;
									}
									success = 1;
								}
								if (oper_json) {
									int return_code = 0;
									if (!success)
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
									if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
										pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
										return_code = -1;
									} else if (oph_write_and_get_json(oper_json, &(request_data[k][j].output_json)))
										return_code = -1;
									if (!return_code)
										pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
								}
								oph_json_free(oper_json);
							}

							response = 0;
							oph_workflow_notify(state, ttype, jobid, request_data[k][j].error_notification, request_data[k][j].output_json, &response);
							if (response)
								pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: error %d in notify\n", ttype, jobid, response);
						}
					}
					nn++;
				}
				if (json_response) {
					free(json_response);
					json_response = NULL;
				}
			} else {
				if (request_data[k][j].error)	// Basic JSON Response to report error in generate submission string
				{
					int success = 0;
					oph_json *oper_json = NULL;

					char str_jobid[OPH_MAX_STRING_SIZE];
					char session_code[OPH_MAX_STRING_SIZE];

					snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid, OPH_SESSION_MARKER_DELIMITER,
						 request_data[k][j].markerid);
					if ((res = oph_get_session_code(sessionid, session_code)))
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);

					char error_message[OPH_MAX_STRING_SIZE];
					snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", request_data[k][j].error);

					while (!success) {
						if (oph_json_alloc(&oper_json)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
							break;
						}
						if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
							break;
						}
						if (res)
							break;
						if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail(oper_json, "Workflow", str_workflowid)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail(oper_json, "Marker", request_data[k][j].markerid)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail(oper_json, "JobID", str_jobid)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_consumer(oper_json, username)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
							break;
						}
						success = 1;
					}
					if (oper_json) {
						int return_code = 0;
						if (!success)
							snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
						if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
							return_code = -1;
						} else if (oph_write_and_get_json(oper_json, &(request_data[k][j].output_json)))
							return_code = -1;
						if (!return_code)
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
					}
					oph_json_free(oper_json);
				}
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: special task is finished; reporting the notification '%s'\n", ttype, jobid,
					   request_data[k][j].error_notification);
				response = 0;
				oph_workflow_notify(state, ttype, jobid, request_data[k][j].error_notification, request_data[k][j].output_json, &response);
				if (response)
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: error %d in notify\n", ttype, jobid, response);
				nnnn++;
			}
		}
		oph_request_data_vector_free(request_data[k], request_data_dim[k]);
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: %d task%s submitted\n", ttype, jobid, nn, nn == 1 ? "" : "s");
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: %d task%s submitted virtually\n", ttype, jobid, nnn, nnn == 1 ? "" : "s");
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: %d special task%s\n", ttype, jobid, nnnn, nnnn == 1 ? "" : "s");

	if (sessionid)
		free(sessionid);
	if (username)
		free(username);
	if (os_username)
		free(os_username);
	if (project)
		free(project);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

size_t function_pt(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t total_size = size * nmemb;
	if (!ptr || stream)
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "N0: loading a file of %d bytes\n", total_size);
/*
    char tmp[total_size];
    strncpy(tmp,(char*)ptr,total_size);
    pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "N0: reply to the notification:\n%s\n", tmp);
*/
	return total_size;
}

int oph_workflow_abort_task(char ttype, int jobid, oph_workflow * wf, int task_index, int light_task_index, char massive_task)
{
	if (!wf || (task_index < 0) || (task_index > wf->tasks_num) || (light_task_index >= wf->tasks[task_index].light_tasks_num))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	char light_task = light_task_index >= 0;

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: aborting task (%d, %d) of workflow '%s'\n", ttype, jobid, task_index, light_task_index, wf->name);

	if (light_task)
		wf->tasks[task_index].light_tasks[light_task_index].status = OPH_ODB_STATUS_ABORTED;
	else
		wf->tasks[task_index].status = OPH_ODB_STATUS_ABORTED;

	int success = 0;
	oph_json *oper_json = NULL;

	char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE], session_code[OPH_MAX_STRING_SIZE], *my_output_json = NULL;
	snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
	snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", light_task ? wf->tasks[task_index].light_tasks[light_task_index].markerid : wf->tasks[task_index].markerid);
	snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid, OPH_SESSION_MARKER_DELIMITER, str_markerid);

	char error_message[OPH_MAX_STRING_SIZE];
	snprintf(error_message, OPH_MAX_STRING_SIZE, "Task aborted!");

	pthread_mutex_lock(&global_flag);

	while (!success) {
		if (oph_json_alloc_unsafe(&oper_json)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
			break;
		}
		if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
			break;
		}
		if (oph_get_session_code(wf->sessionid, session_code)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "Session Code", session_code)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "Workflow", str_workflowid)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "Marker", str_markerid)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_source_detail_unsafe(oper_json, "JobID", str_jobid)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
			break;
		}
		if (oph_json_add_consumer_unsafe(oper_json, wf->username)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
			break;
		}
		success = 1;
	}
	if (oper_json) {
		int return_code = 0;
		if (!success)
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
			return_code = -1;
		} else if (oph_write_and_get_json_unsafe(oper_json, &my_output_json))
			return_code = -1;
		if (!return_code)
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
	}

	pthread_mutex_unlock(&global_flag);

	oph_json_free_unsafe(oper_json);

	if (my_output_json) {

		if (!light_task) {
			if (wf->tasks[task_index].response)
				free(wf->tasks[task_index].response);
			wf->tasks[task_index].response = my_output_json;
		} else {
#ifdef LEVEL3
			if (wf->tasks[task_index].light_tasks[light_task_index].response)
				free(wf->tasks[task_index].light_tasks[light_task_index].response);
			wf->tasks[task_index].light_tasks[light_task_index].response = my_output_json;
#else
			free(my_output_json);
#endif
		}
	}

	if (!massive_task && !oph_cancel_all_enabled)
		oph_cancel_request(light_task ? wf->tasks[task_index].light_tasks[light_task_index].idjob : wf->tasks[task_index].idjob, wf->os_username);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_notify(struct oph_plugin_data *state, char ttype, int jobid, char *data, char *output_json, int *response)
{
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: %s\n", ttype, jobid, data ? data : "");
	*response = OPH_SERVER_OK;

	if (!state) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: state not specified. Skipping the notification\n", ttype, jobid);
		*response = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
	}

	oph_argument *args = NULL, *aitem;
	unsigned int ii, counter;

	if (oph_parse_query(&args, &counter, data))	// Parse notification string
	{
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: error in parsing '%s'\n", ttype, jobid, data);
		*response = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}

	char *ctmp, *sessionid = NULL, *query = NULL;
	int i, j, odb_jobid = -1, odb_status = -1, odb_parentid = -1, task_index = -1, light_task_index = -1, light_task_index_orig = -1, marker_id = -1, outputs_num = 0;
#ifdef OPH_OPENID_SUPPORT
	char *access_token = NULL, *refresh_token = NULL, *userinfo = NULL;
#endif
	char **outputs_keys = NULL;
	char **outputs_values = NULL;
	short outputs_index[counter];

	for (ii = 0, aitem = args; ii < counter; ++ii, aitem = aitem->next) {
		if (!aitem) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: error in parsing '%s'\n", ttype, jobid, data);
			*response = OPH_SERVER_SYSTEM_ERROR;
			if (query)
				free(query);
			oph_cleanup_args(&args);
			return SOAP_OK;
		}
		ctmp = aitem->value;
		outputs_index[ii] = 0;
		if (!strncmp(aitem->key, OPH_ARG_JOBID, OPH_MAX_STRING_SIZE))
			odb_jobid = strtol(ctmp, NULL, 10);
		else if (!strncmp(aitem->key, OPH_ARG_STATUS, OPH_MAX_STRING_SIZE))
			odb_status = strtol(ctmp, NULL, 10);
		else if (!strncmp(aitem->key, OPH_ARG_PARENTID, OPH_MAX_STRING_SIZE))
			odb_parentid = strtol(ctmp, NULL, 10);
		else if (!strncmp(aitem->key, OPH_ARG_TASKINDEX, OPH_MAX_STRING_SIZE))
			task_index = strtol(ctmp, NULL, 10);
		else if (!strncmp(aitem->key, OPH_ARG_LIGHTTASKINDEX, OPH_MAX_STRING_SIZE))
			light_task_index = light_task_index_orig = strtol(ctmp, NULL, 10);
		else if (!strncmp(aitem->key, OPH_ARG_SESSIONID, OPH_MAX_STRING_SIZE))
			sessionid = strdup(ctmp);
		else if (!strncmp(aitem->key, OPH_ARG_MARKERID, OPH_MAX_STRING_SIZE))
			marker_id = strtol(ctmp, NULL, 10);
		else if (!strncmp(aitem->key, OPH_ARG_INFO, OPH_MAX_STRING_SIZE)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: %s\n", ttype, jobid, ctmp);
			if (sessionid)
				free(sessionid);
			if (query)
				free(query);
			oph_cleanup_args(&args);
			return SOAP_OK;
		} else if (!strncmp(aitem->key, OPH_ARG_QUERY, OPH_MAX_STRING_SIZE))
			query = strdup(ctmp);
#ifdef OPH_OPENID_SUPPORT
		else if (!strncmp(aitem->key, OPH_ARG_ACCESS_TOKEN, OPH_MAX_STRING_SIZE))
			access_token = ctmp;
		else if (!strncmp(aitem->key, OPH_ARG_REFRESH_TOKEN, OPH_MAX_STRING_SIZE))
			refresh_token = ctmp;
		else if (!strncmp(aitem->key, OPH_ARG_USERINFO, OPH_MAX_STRING_SIZE))
			userinfo = ctmp;
#endif
		else {
			outputs_num++;
			outputs_index[ii] = 1;
		}
	}

#ifdef OPH_OPENID_SUPPORT
	if (access_token) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: found tokens to be saved\n", ttype, jobid);
		oph_auth_save_token(access_token, refresh_token, userinfo);
		if (sessionid)
			free(sessionid);
		if (query)
			free(query);
		oph_cleanup_args(&args);
		return SOAP_OK;
	}
#endif

	if ((odb_jobid < 0) || (odb_status < 0) || (odb_parentid < 0) || (task_index < 0) || (marker_id < 0) || !sessionid) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: missing mandatory parameters in '%s'\n", ttype, jobid, data);
		*response = OPH_SERVER_WRONG_PARAMETER_ERROR;
		if (sessionid)
			free(sessionid);
		if (query)
			free(query);
		oph_cleanup_args(&args);
		return SOAP_OK;
	}

	if (outputs_num) {
		int j = 0;
		outputs_keys = (char **) malloc(outputs_num * sizeof(char *));
		if (!outputs_keys) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: error in alloc memory for output keys\n", ttype, jobid);
			*response = OPH_SERVER_SYSTEM_ERROR;
			if (sessionid)
				free(sessionid);
			if (query)
				free(query);
			oph_cleanup_args(&args);
			return SOAP_OK;
		}
		outputs_values = (char **) malloc(outputs_num * sizeof(char *));
		if (!outputs_keys) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: error in alloc memory for output values\n", ttype, jobid);
			*response = OPH_SERVER_SYSTEM_ERROR;
			if (sessionid)
				free(sessionid);
			if (query)
				free(query);
			oph_cleanup_args(&args);
			if (outputs_keys)
				free(outputs_keys);
			return SOAP_OK;
		}
		for (ii = 0, aitem = args; ii < counter; ++ii, aitem = aitem->next)
			if (outputs_index[ii]) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: found output '%s=%s'\n", ttype, jobid, aitem->key, aitem->value);
				outputs_keys[j] = strdup(aitem->key);
				outputs_values[j] = strdup(aitem->value);
				j++;
			}
	}

	oph_cleanup_args(&args);
	// End parsing

	// New status for workflow
	enum oph__oph_odb_job_status status = odb_status;
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: status of job %d has been updated to %s\n", ttype, jobid, odb_jobid, oph_odb_convert_status_to_str(status));
	switch (status) {
		case OPH_ODB_STATUS_PENDING:
		case OPH_ODB_STATUS_RUNNING:
		case OPH_ODB_STATUS_COMPLETED:
		case OPH_ODB_STATUS_ERROR:
			break;
		case OPH_ODB_STATUS_START:
		case OPH_ODB_STATUS_SET_ENV:
		case OPH_ODB_STATUS_INIT:
		case OPH_ODB_STATUS_DISTRIBUTE:
		case OPH_ODB_STATUS_EXECUTE:
		case OPH_ODB_STATUS_REDUCE:
		case OPH_ODB_STATUS_DESTROY:
		case OPH_ODB_STATUS_UNSET_ENV:
		case OPH_ODB_STATUS_WAIT:
			status = OPH_ODB_STATUS_RUNNING;
			break;
		case OPH_ODB_STATUS_UNSELECTED:
			status = OPH_ODB_STATUS_COMPLETED;
			break;
		case OPH_ODB_STATUS_PENDING_ERROR:
		case OPH_ODB_STATUS_RUNNING_ERROR:
		case OPH_ODB_STATUS_START_ERROR:
		case OPH_ODB_STATUS_SET_ENV_ERROR:
		case OPH_ODB_STATUS_INIT_ERROR:
		case OPH_ODB_STATUS_DISTRIBUTE_ERROR:
		case OPH_ODB_STATUS_EXECUTE_ERROR:
		case OPH_ODB_STATUS_REDUCE_ERROR:
		case OPH_ODB_STATUS_DESTROY_ERROR:
		case OPH_ODB_STATUS_UNSET_ENV_ERROR:
		case OPH_ODB_STATUS_SKIPPED:
		case OPH_ODB_STATUS_ABORTED:
		case OPH_ODB_STATUS_EXPIRED:
			status = OPH_ODB_STATUS_ERROR;
			break;
		default:
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: wrong status code\n", ttype, jobid);
			*response = OPH_SERVER_WRONG_PARAMETER_ERROR;
			oph_output_data_free(outputs_keys, outputs_num);
			oph_output_data_free(outputs_values, outputs_num);
			if (sessionid)
				free(sessionid);
			if (query)
				free(query);
			return SOAP_OK;
	}

	if ((get_debug_level() == LOG_DEBUG) && (status == OPH_ODB_STATUS_ERROR)) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: arrived an error notification:\n%s\n", ttype, jobid, output_json ? output_json : "No JSON Response");
		char outfile[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE], buffer[OPH_MAX_STRING_SIZE];
		if (sessionid && !oph_get_session_code(sessionid, code)) {
			snprintf(buffer, OPH_MAX_STRING_SIZE, "%d", marker_id);
			snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_TXT_FILENAME, oph_txt_location, code, buffer);	// multi user approach is not supported
			FILE *log = fopen(outfile, "r");
			if (log) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: log file '%s':\n", ttype, jobid, outfile);
				while (fgets(buffer, OPH_MAX_STRING_SIZE, log))
					pmesg_safe(&global_flag, LOG_RAW, __FILE__, __LINE__, "%s", buffer);
				fclose(log);
			} else
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: log file '%s' not found; do not care!\n", ttype, jobid, outfile);
		}
	}

	char session_code[OPH_MAX_STRING_SIZE], tmp[OPH_MAX_STRING_SIZE], *my_output_json = NULL, *failed_task = NULL;
	int res, update_wf_data = 0, update_task_data = 0, update_light_task_data = 0, task_completed = 0, final = 0, retry_task_execution = 0, check_for_constraint = 0, connection_up = 0;
	oph_job_info *item = NULL, *prev = NULL;
	ophidiadb oDB;
	oph_workflow *wf = NULL;

	pthread_mutex_lock(&global_flag);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: search the workflow identified by id %d\n", ttype, jobid, odb_parentid);
	if (!(item = oph_find_job_in_job_list(state->job_info, odb_parentid, &prev))) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: workflow %d not found. Skipping the notification\n", ttype, jobid, odb_parentid);
		pthread_mutex_unlock(&global_flag);
		*response = OPH_SERVER_WRONG_PARAMETER_ERROR;
		oph_output_data_free(outputs_keys, outputs_num);
		oph_output_data_free(outputs_values, outputs_num);
		if (sessionid)
			free(sessionid);
		if (query)
			free(query);
		return SOAP_OK;
	}
	wf = item->wf;
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: found workflow '%s'\n", ttype, jobid, wf->name);
	if (strcmp(wf->sessionid, sessionid))
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: sessionid in memory is different from sessionid in notification\n", ttype, jobid);
	if (sessionid)
		free(sessionid);

	// Update limits: known operators do not use resources
	if ((status >= OPH_ODB_STATUS_COMPLETED) && !oph_is_known_operator(wf->tasks[task_index].operator)) {
		char broadcast = 0;
		if (oph_server_task_limit && (oph_server_task_running > 0)) {
			oph_server_task_running--;
			broadcast = 1;
		}
		if (oph_server_core_limit && (oph_server_core_running >= wf->tasks[task_index].ncores)) {
			oph_server_core_running -= wf->tasks[task_index].ncores;
			broadcast = 1;
		}
		if (broadcast)
			pthread_cond_broadcast(&limit_flag);
	}

	if (!odb_jobid && !wf->tasks[task_index].idjob && (wf->tasks[task_index].status < (int) OPH_ODB_STATUS_ERROR)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: an internal operation '%s' is waiting for a response: received a notification with status %s\n", ttype, jobid, wf->tasks[task_index].name,
		      oph_odb_convert_status_to_str(status));
		if (wf->tasks[task_index].response)
			free(wf->tasks[task_index].response);
		wf->tasks[task_index].response = NULL;
		if (status == OPH_ODB_STATUS_COMPLETED) {
			wf->tasks[task_index].response = strdup(output_json);
			if (query)
				wf->tasks[task_index].query = strdup(query);
			pthread_cond_broadcast(&waiting_flag);
		} else {
			if (status == OPH_ODB_STATUS_ERROR) {
				wf->tasks[task_index].response = strdup("");
				pthread_cond_broadcast(&waiting_flag);
			}
		}
		pthread_mutex_unlock(&global_flag);
		oph_output_data_free(outputs_keys, outputs_num);
		oph_output_data_free(outputs_values, outputs_num);
		if (query)
			free(query);
		return SOAP_OK;
	}

	if (query)
		free(query);

	if ((res = oph_get_session_code(wf->sessionid, session_code)))
		pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to get session code\n", ttype, jobid);

	char process_notification = 1;

	if (wf->is_closed || (wf->status >= (int) OPH_ODB_STATUS_ABORTED)) {

		oph_output_data_free(outputs_keys, outputs_num);
		oph_output_data_free(outputs_values, outputs_num);

		if (odb_jobid != odb_parentid) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: wrong jobid: %d instead of %d\n", ttype, jobid, odb_jobid, odb_parentid);
			pthread_mutex_unlock(&global_flag);
			*response = OPH_SERVER_WRONG_PARAMETER_ERROR;
			return SOAP_OK;
		}

		oph_drop_from_job_list(state->job_info, item, prev);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: workflow '%s' dropped from the list\n", ttype, jobid, wf->name);
		free(item);

		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to read OphidiaDB configuration\n", ttype, jobid);
			*response = OPH_SERVER_SYSTEM_ERROR;
			oph_odb_disconnect_from_ophidiadb(&oDB);
		} else if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to connect to OphidiaDB. Check access parameters.\n", ttype, jobid);
			*response = OPH_SERVER_IO_ERROR;
			oph_odb_disconnect_from_ophidiadb(&oDB);
		} else {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: CONNECTED to OphidiaDB\n", ttype, jobid);
			connection_up = 1;
			if (oph_odb_set_job_status_and_nchildrencompleted(odb_parentid, wf->status, wf->tasks_num - wf->residual_tasks_num, 1, &oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to update parent job status\n", ttype, jobid);
				*response = OPH_SERVER_IO_ERROR;
			} else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: update status of job %d to %s\n", ttype, jobid, odb_parentid, oph_odb_convert_status_to_str(status));
		}

		pthread_mutex_unlock(&global_flag);

		// Kill queued tasks
		if (wf->cancel_type != 's') {

			if (oph_cancel_all_enabled || (wf->cancel_type != 'a')) {	// Using option "CANCEL_ALL" all tasks are always killed
				for (i = 0; i < wf->tasks_num; ++i)
					if ((wf->tasks[i].status > (int) OPH_ODB_STATUS_UNKNOWN) && (wf->tasks[i].status < (int) OPH_ODB_STATUS_COMPLETED)) {
						if (wf->tasks[i].light_tasks_num) {
							for (j = 0; j < wf->tasks[i].light_tasks_num; ++j)
								if ((wf->tasks[i].light_tasks[j].status > (int) OPH_ODB_STATUS_UNKNOWN)
								    && (wf->tasks[i].light_tasks[j].status < (int) OPH_ODB_STATUS_COMPLETED))
									oph_workflow_abort_task(ttype, jobid, wf, i, j, 0);
						}
						oph_workflow_abort_task(ttype, jobid, wf, i, -1, wf->tasks[i].light_tasks_num);
					}
				if (oph_cancel_all_enabled)
					oph_cancel_all_request(wf->workflowid, wf->os_username);
			} else {
				for (i = 0; i < wf->tasks_num; ++i) {
					if (wf->tasks[i].light_tasks_num) {
						if ((wf->tasks[i].status > (int) OPH_ODB_STATUS_UNKNOWN) && (wf->tasks[i].status < (int) OPH_ODB_STATUS_COMPLETED)) {
							for (j = 0; j < wf->tasks[i].light_tasks_num; ++j)
								if (wf->tasks[i].light_tasks[j].status == (int) OPH_ODB_STATUS_PENDING)
									oph_workflow_abort_task(ttype, jobid, wf, i, j, 0);
						}
					}
					if (wf->tasks[i].status == (int) OPH_ODB_STATUS_PENDING)
						oph_workflow_abort_task(ttype, jobid, wf, i, -1, wf->tasks[i].light_tasks_num);
				}
			}
		}

		process_notification = 0;

	} else if (status == OPH_ODB_STATUS_ERROR) {

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: check if the notification has to be neglected\n", ttype, jobid);
		if (light_task_index >= 0) {
			if (!wf->tasks[task_index].light_tasks[light_task_index].status || (wf->tasks[task_index].light_tasks[light_task_index].status >= OPH_ODB_STATUS_COMPLETED)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: status of child %d of task '%s' has been already updated to %s in memory; skip the notification for status %s\n", ttype,
				      jobid, light_task_index, wf->tasks[task_index].name, oph_odb_convert_status_to_str(wf->tasks[task_index].light_tasks[light_task_index].status),
				      oph_odb_convert_status_to_str(odb_status));
				pthread_mutex_unlock(&global_flag);
				process_notification = 0;
			}
		} else {
			if (!wf->tasks[task_index].status || (wf->tasks[task_index].status >= OPH_ODB_STATUS_COMPLETED)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: status of task '%s' has been already updated to %s in memory; skip the notification for status %s\n", ttype, jobid,
				      wf->tasks[task_index].name, oph_odb_convert_status_to_str(wf->tasks[task_index].status), oph_odb_convert_status_to_str(odb_status));
				pthread_mutex_unlock(&global_flag);
				process_notification = 0;
			}
		}
		if (!process_notification) {
			oph_output_data_free(outputs_keys, outputs_num);
			oph_output_data_free(outputs_values, outputs_num);
		}
	}

	if (process_notification) {

		char massive_completed = 0;
		if (light_task_index >= 0)	// Massive operation
		{
			if (wf->tasks[task_index].light_tasks[light_task_index].status < odb_status)
				update_light_task_data = 1;
			wf->tasks[task_index].light_tasks[light_task_index].status = odb_status;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: status of child %d of task '%s' has been updated to %s in memory\n", ttype, jobid, light_task_index, wf->tasks[task_index].name,
			      oph_odb_convert_status_to_str(wf->tasks[task_index].light_tasks[light_task_index].status));
			if (odb_status == OPH_ODB_STATUS_START_ERROR) {
				if (oph_auto_retry && (wf->tasks[task_index].retry_num == 1) && (wf->tasks[task_index].residual_auto_retry_num != 1)) {
					wf->tasks[task_index].is_marked_for_auto_retry = 1;
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' is marked for auto-retry\n", ttype, jobid, wf->tasks[task_index].name);
				}
				if (wf->tasks[task_index].status < (int) OPH_ODB_STATUS_RUNNING) {
					wf->tasks[task_index].status = OPH_ODB_STATUS_RUNNING;
					update_task_data = 1;
				}
				if (wf->status < (int) OPH_ODB_STATUS_RUNNING) {
					wf->status = OPH_ODB_STATUS_RUNNING;
					update_wf_data = 1;
				}
				if (task_index < wf->tasks_num) {
					struct stat s;
					char filename[OPH_MAX_STRING_SIZE], str_markerid[OPH_MAX_STRING_SIZE];
					snprintf(str_markerid, OPH_MAX_STRING_SIZE, "%d", wf->tasks[task_index].light_tasks[light_task_index].markerid);
					snprintf(filename, OPH_MAX_STRING_SIZE, OPH_JSON_RESPONSE_FILENAME, oph_json_location, session_code, str_markerid);
					if (stat(filename, &s) && (errno == ENOENT)) {
						char error_message[OPH_MAX_STRING_SIZE];
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in executing a child of task '%s'!", wf->tasks[task_index].name);
						update_light_task_data = 1;
						if (oph_save_basic_json(ttype, jobid, wf, task_index, light_task_index, "ERROR", error_message, NULL)) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to save JSON Response for task '%s' of '%s'\n", ttype, jobid, wf->tasks[task_index].name,
							      wf->name);
							pthread_mutex_unlock(&global_flag);
							*response = OPH_SERVER_SYSTEM_ERROR;
							oph_output_data_free(outputs_keys, outputs_num);
							oph_output_data_free(outputs_values, outputs_num);
							return SOAP_OK;
						}
					}
				}
			}
			if ((status == OPH_ODB_STATUS_COMPLETED) || (status == OPH_ODB_STATUS_ERROR)) {
				update_task_data = 1;
				if (!wf->tasks[task_index].residual_light_tasks_num) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: massive operation '%s' of workflow '%s' has no children but a child is ended\n", ttype, jobid,
					      wf->tasks[task_index].name, wf->name);
					pthread_mutex_unlock(&global_flag);
					*response = OPH_SERVER_SYSTEM_ERROR;
					oph_output_data_free(outputs_keys, outputs_num);
					oph_output_data_free(outputs_values, outputs_num);
					return SOAP_OK;
				}
				wf->tasks[task_index].residual_light_tasks_num--;

				// Log into TASK_LOGFILE
				if (task_logfile) {
					time_t nowtime;
					struct tm nowtm;
					struct timeval tv;
					char buffer[OPH_SHORT_STRING_SIZE];
					*buffer = 0;
					pthread_mutex_lock(&curl_flag);
					gettimeofday(&tv, 0);
					time(&nowtime);
					if (localtime_r(&nowtime, &nowtm))
						strftime(buffer, OPH_SHORT_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm);
					fprintf(task_logfile, "%s\t%d\t%d\t%s\t%d\t%d\t%f\n", buffer, wf->tasks[task_index].light_tasks[light_task_index].idjob, wf->idjob,
						wf->tasks[task_index].operator, wf->tasks[task_index].light_tasks[light_task_index].ncores, status == OPH_ODB_STATUS_COMPLETED,
						(double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->tasks[task_index].timestamp);
					pthread_mutex_unlock(&curl_flag);
				}
#ifdef LEVEL3
				if (wf->exec_mode && !strncasecmp(wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
					if (wf->tasks[task_index].light_tasks[light_task_index].response)
						free(wf->tasks[task_index].light_tasks[light_task_index].response);
					wf->tasks[task_index].light_tasks[light_task_index].response = strdup(output_json ? output_json : "");
				}
#endif
				if (status == OPH_ODB_STATUS_COMPLETED) {
					// Save the output
					if (outputs_keys) {
						// Save well-known parameters and publish them on web
						char linkname[OPH_SHORT_STRING_SIZE];
						for (i = 0; i < outputs_num; ++i) {
							if (!strncmp(outputs_keys[i], OPH_ARG_CUBE, OPH_MAX_STRING_SIZE)) {
								if (wf->cube)
									free(wf->cube);
								wf->cube = strndup(outputs_values[i], OPH_MAX_STRING_SIZE);
								snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_CUBE, wf->tasks[task_index].light_tasks[light_task_index].markerid);
								oph_session_report_append_link(session_code, wf->workflowid, NULL, linkname, outputs_values[i], 'C');
							} else if (!strncmp(outputs_keys[i], OPH_ARG_CDD, OPH_MAX_STRING_SIZE)) {
								if (wf->cdd)
									free(wf->cdd);
								wf->cdd = strndup(outputs_values[i], OPH_MAX_STRING_SIZE);
							} else if (!strncmp(outputs_keys[i], OPH_ARG_CWD, OPH_MAX_STRING_SIZE)) {
								if (wf->cwd)
									free(wf->cwd);
								wf->cwd = strndup(outputs_values[i], OPH_MAX_STRING_SIZE);
							} else if (!strncmp(outputs_keys[i], OPH_ARG_LINK, OPH_MAX_STRING_SIZE)) {
								snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_LINK, wf->tasks[task_index].light_tasks[light_task_index].markerid);
								oph_session_report_append_link(session_code, wf->workflowid, NULL, linkname, outputs_values[i], 'L');
							}
						}

						int outputs_file = -1;
						for (i = 0; i < outputs_num; ++i) {
							if (!strncmp(outputs_keys[i], OPH_ARG_FILE, OPH_MAX_STRING_SIZE)) {
								for (j = 0; j < outputs_num; ++j) {
									if ((i != j) && !strncmp(outputs_keys[j], OPH_ARG_CUBE, OPH_MAX_STRING_SIZE)) {
										free(outputs_values[j]);
										outputs_values[j] = strdup(outputs_values[i]);	// Option 'file' has the priority, value of 'cube' is overwritten
										outputs_file = j;
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: value of '%s' is overwritten with value of '%s'\n", ttype, jobid,
										      OPH_ARG_CUBE, OPH_ARG_FILE);
										break;
									}
								}
								if (j == outputs_num) {	// parameter 'cube' not found
									char **outputs_keys_new = (char **) realloc(outputs_keys, (1 + outputs_num) * sizeof(char *));
									if (outputs_keys_new) {
										outputs_keys = outputs_keys_new;
										outputs_keys[outputs_num] = strdup(OPH_ARG_CUBE);
									} else
										pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in adding parameter '%s'\n", ttype, jobid, OPH_ARG_CUBE);
									char **outputs_values_new = (char **) realloc(outputs_values, (1 + outputs_num) * sizeof(char *));
									if (outputs_values_new) {
										outputs_values = outputs_values_new;
										outputs_values[outputs_num] = strdup(outputs_values[i]);
									} else
										pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in adding parameter '%s'\n", ttype, jobid, OPH_ARG_CUBE);
									outputs_file = outputs_num;
									outputs_num++;
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: add '%s=%s' to notification\n", ttype, jobid, OPH_ARG_CUBE, outputs_values[i]);
								}
								break;
							}
						}

						if (wf->tasks[task_index].outputs_keys) {
							if (wf->tasks[task_index].outputs_num != outputs_num)
								pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: dimension of output list does not match with that of the output list of task '%s'\n",
								      ttype, jobid, wf->tasks[task_index].name);
							else
								for (i = 0; i < outputs_num; ++i) {
									if (!strncmp(outputs_keys[i], wf->tasks[task_index].outputs_keys[i], OPH_MAX_STRING_SIZE))	// It is assumed the perfect correspondence between the outputs
									{
										snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s", wf->tasks[task_index].outputs_values[i], OPH_SEPARATOR_SUBPARAM_STR,
											 outputs_values[i]);
										free(wf->tasks[task_index].outputs_values[i]);
										wf->tasks[task_index].outputs_values[i] = strdup(tmp);
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: updated output '%s=%s' of task '%s'\n", ttype, jobid,
										      wf->tasks[task_index].outputs_keys[i], wf->tasks[task_index].outputs_values[i], wf->tasks[task_index].name);
									} else
										pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: output argument '%s' does not match with the output list of task '%s'\n",
										      ttype, jobid, outputs_keys[i], wf->tasks[task_index].name);
								}
							oph_output_data_free(outputs_keys, outputs_num);
							oph_output_data_free(outputs_values, outputs_num);
						} else {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: save the output list of child %d as output of task '%s'\n", ttype, jobid, light_task_index,
							      wf->tasks[task_index].name);
							wf->tasks[task_index].outputs_keys = outputs_keys;
							wf->tasks[task_index].outputs_values = outputs_values;
							wf->tasks[task_index].outputs_file = outputs_file;
							wf->tasks[task_index].outputs_num = outputs_num;
						}

						outputs_keys = outputs_values = NULL;
						outputs_num = 0;
					}
				}

				if (!wf->tasks[task_index].residual_light_tasks_num)	// Massive operation is ended
				{
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: massive operation '%s' of workflow '%s' is ended\n", ttype, jobid, wf->tasks[task_index].name, wf->name);
					for (i = 0; i < wf->tasks[task_index].light_tasks_num; ++i)
						if (wf->tasks[task_index].light_tasks[i].status > OPH_ODB_STATUS_COMPLETED)
							break;
					if (i == wf->tasks[task_index].light_tasks_num)
						wf->tasks[task_index].status = OPH_ODB_STATUS_COMPLETED;
					else
						wf->tasks[task_index].status = OPH_ODB_STATUS_ERROR;
					status = wf->tasks[task_index].status;
					massive_completed = 1;

					// Save JSON related to parent job
					int success = 0;
					oph_json *oper_json = NULL;

					char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];

					snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER,
						 wf->tasks[task_index].markerid);
					snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
					snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].markerid);

					char error_message[OPH_MAX_STRING_SIZE];
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Parent task data processing failed!");

					while (!success) {
						if (oph_json_alloc_unsafe(&oper_json)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
							break;
						}
						if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
							break;
						}
						if (res)
							break;
						if (oph_json_add_source_detail_unsafe(oper_json, "Session Code", session_code)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail_unsafe(oper_json, "Workflow", str_workflowid)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail_unsafe(oper_json, "Marker", str_markerid)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail_unsafe(oper_json, "JobID", str_jobid)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_consumer_unsafe(oper_json, wf->username)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
							break;
						}
						success = 1;
					}

					unsigned int number_of_jobs = 0;
					if (!success)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
					else {
						int num_fields = wf->output_format ? 2 : 6, iii, jjj = 0;

						char **jsonkeys = NULL;
						char **fieldtypes = NULL;
						char **jsonvalues = NULL;
						char jsontmp[OPH_MAX_STRING_SIZE];

						success = 0;
						while (!success) {
							if (oph_json_add_text
							    (oper_json, OPH_JSON_OBJKEY_MASSIVE_STATUS, "Massive Operation Status", oph_odb_convert_status_to_str(wf->tasks[task_index].status))) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
								break;
							}

							if (wf->output_format) {

								int num_fields = 3;
								// Header
								jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonkeys) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									break;
								}
								jsonkeys[jjj] = strdup("OPH JOB ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("WORKFLOW ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("PARENT MARKER ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < num_fields; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
								if (oph_json_add_grid_unsafe
								    (oper_json, OPH_JSON_OBJKEY_MASSIVE_INFO, "Massive Operation Information", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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

								jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonvalues) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									break;
								}
								jjj = 0;
								snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid,
									 OPH_SESSION_MARKER_DELIMITER, wf->tasks[task_index].markerid);
								jsonvalues[jjj] = strdup(jsontmp);
								if (!jsonvalues[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
								jsonvalues[jjj] = strdup(jsontmp);
								if (!jsonvalues[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].markerid);
								jsonvalues[jjj] = strdup(jsontmp);
								if (!jsonvalues[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								if (oph_json_add_grid_row_unsafe(oper_json, OPH_JSON_OBJKEY_MASSIVE_INFO, jsonvalues)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID ROW error\n", ttype, jobid);
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
							// Header
							jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonkeys) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								break;
							}
							jjj = 0;
							if (!wf->output_format) {
								jsonkeys[jjj] = strdup("OPH JOB ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("SESSION CODE");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
								jsonkeys[jjj] = strdup("WORKFLOW ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
							}
							jsonkeys[jjj] = strdup("MARKER ID");
							if (!jsonkeys[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							jjj++;
							if (!wf->output_format) {
								jsonkeys[jjj] = strdup("PARENT MARKER ID");
								if (!jsonkeys[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonkeys[iii])
											free(jsonkeys[iii]);
									if (jsonkeys)
										free(jsonkeys);
									break;
								}
								jjj++;
							}
							jsonkeys[jjj] = strdup("EXIT STATUS");
							if (!jsonkeys[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
							if (!fieldtypes) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < num_fields; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
							jjj = 0;
							if (!wf->output_format) {
								fieldtypes[jjj] = strdup(OPH_JSON_STRING);
								if (!fieldtypes[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							}
							fieldtypes[jjj] = strdup(OPH_JSON_INT);
							if (!fieldtypes[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							if (!wf->output_format) {
								fieldtypes[jjj] = strdup(OPH_JSON_INT);
								if (!fieldtypes[jjj]) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							}
							fieldtypes[jjj] = strdup(OPH_JSON_STRING);
							if (!fieldtypes[jjj]) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
							if (oph_json_add_grid_unsafe
							    (oper_json, OPH_JSON_OBJKEY_MASSIVE_LIST, "Massive Operation Task List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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

							// Data
							for (i = 0; i < wf->tasks[task_index].light_tasks_num; ++i) {
								if (wf->tasks[task_index].light_tasks[i].status && (wf->tasks[task_index].light_tasks[i].status < OPH_ODB_STATUS_ABORTED))	// Discard uninitialized or aborted jobs
								{
									jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
									if (!jsonvalues) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
										break;
									}
									jjj = 0;
									if (!wf->output_format) {
										snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid,
											 OPH_SESSION_MARKER_DELIMITER, wf->tasks[task_index].light_tasks[i].markerid);
										jsonvalues[jjj] = strdup(jsontmp);
										if (!jsonvalues[jjj]) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
											for (iii = 0; iii < jjj; iii++)
												if (jsonvalues[iii])
													free(jsonvalues[iii]);
											if (jsonvalues)
												free(jsonvalues);
											break;
										}
										jjj++;
										jsonvalues[jjj] = strdup(session_code);
										if (!jsonvalues[jjj]) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
											for (iii = 0; iii < jjj; iii++)
												if (jsonvalues[iii])
													free(jsonvalues[iii]);
											if (jsonvalues)
												free(jsonvalues);
											break;
										}
										jjj++;
										snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
										jsonvalues[jjj] = strdup(jsontmp);
										if (!jsonvalues[jjj]) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
											for (iii = 0; iii < jjj; iii++)
												if (jsonvalues[iii])
													free(jsonvalues[iii]);
											if (jsonvalues)
												free(jsonvalues);
											break;
										}
										jjj++;
									}
									snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].light_tasks[i].markerid);
									jsonvalues[jjj] = strdup(jsontmp);
									if (!jsonvalues[jjj]) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									jjj++;
									if (!wf->output_format) {
										snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].markerid);
										jsonvalues[jjj] = strdup(jsontmp);
										if (!jsonvalues[jjj]) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
											for (iii = 0; iii < jjj; iii++)
												if (jsonvalues[iii])
													free(jsonvalues[iii]);
											if (jsonvalues)
												free(jsonvalues);
											break;
										}
										jjj++;
									}
									jsonvalues[jjj] = strdup(oph_odb_convert_status_to_str(wf->tasks[task_index].light_tasks[i].status));
									if (!jsonvalues[jjj]) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
										for (iii = 0; iii < jjj; iii++)
											if (jsonvalues[iii])
												free(jsonvalues[iii]);
										if (jsonvalues)
											free(jsonvalues);
										break;
									}
									if (oph_json_add_grid_row_unsafe(oper_json, OPH_JSON_OBJKEY_MASSIVE_LIST, jsonvalues)) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: ADD GRID ROW error\n", jobid);
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

									number_of_jobs++;
								}
							}

							if (i < wf->tasks[task_index].light_tasks_num)
								break;
							else
								success = 1;
						}
					}

					if (oper_json) {
						int return_code = 0;
						if (!success) {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: notify an error\n", ttype, jobid);
							if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
								pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
								return_code = -1;
							} else if (oph_write_and_get_json_unsafe(oper_json, &my_output_json))
								return_code = -1;
						} else {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: notify a warning\n", ttype, jobid);
							if (!number_of_jobs && oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_WORKFLOW_SUMMARY, "WARNING", "No job found!")) {
								pmesg(LOG_WARNING, __FILE__, __LINE__, "N%d: ADD TEXT error\n", ttype, jobid);
								return_code = -1;
							}
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: notify a success\n", ttype, jobid);
							if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
								pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
								return_code = -1;
							} else if (oph_write_and_get_json_unsafe(oper_json, &my_output_json))
								return_code = -1;
						}
						if (!return_code)
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
					}
					oph_json_free_unsafe(oper_json);

				} else if (wf->tasks[task_index].status == OPH_ODB_STATUS_RUNNING)
					update_task_data = 2;
			} else if (status == OPH_ODB_STATUS_RUNNING) {
				if (wf->tasks[task_index].status < (int) status) {
					wf->tasks[task_index].status = status;
					update_task_data = 1;
				}
				if (wf->status < (int) status) {
					wf->status = status;
					update_wf_data = 1;
				}
			}

			output_json = NULL;	// Skip output JSON in case of massive operation --> refer to my_output_json instead
		} else {
			char set_update_task_data = 0;
			if ((wf->tasks[task_index].status <= (int) OPH_ODB_STATUS_PENDING) || (wf->tasks[task_index].status < odb_status))	// It needs to be tested
				set_update_task_data = 1;
			wf->tasks[task_index].status = odb_status;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: status of task '%s' has been updated to %s in memory\n", ttype, jobid, wf->tasks[task_index].name,
			      oph_odb_convert_status_to_str(wf->tasks[task_index].status));
			if (wf->tasks[task_index].is_marked_for_auto_retry || (odb_status == OPH_ODB_STATUS_START_ERROR)) {
				if (wf->tasks[task_index].is_marked_for_auto_retry)
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' has been marked for auto-retry\n", ttype, jobid, wf->tasks[task_index].name);

				char save = 0;
				if (oph_auto_retry && (wf->tasks[task_index].retry_num == 1))	// Setting for auto-retry
				{
					if (!wf->tasks[task_index].residual_auto_retry_num) {
						wf->tasks[task_index].residual_auto_retry_num = 1 + oph_auto_retry;
						wf->tasks[task_index].is_marked_for_auto_retry = 1;
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' is marked for auto-retry\n", ttype, jobid, wf->tasks[task_index].name);
					} else if (wf->tasks[task_index].residual_auto_retry_num > 1)
						wf->tasks[task_index].residual_auto_retry_num--;
					else
						save = 1;
				} else
					save = 1;
				if (save) {
					if (task_index < wf->tasks_num) {
						struct stat s;
						char filename[OPH_MAX_STRING_SIZE], str_markerid[OPH_MAX_STRING_SIZE];
						snprintf(str_markerid, OPH_MAX_STRING_SIZE, "%d", wf->tasks[task_index].markerid);
						snprintf(filename, OPH_MAX_STRING_SIZE, OPH_JSON_RESPONSE_FILENAME, oph_json_location, session_code, str_markerid);
						if (stat(filename, &s) && (errno == ENOENT)) {
							char error_message[OPH_MAX_STRING_SIZE];
							snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in executing task '%s'!", wf->tasks[task_index].name);
							update_task_data = 1;
							if (oph_save_basic_json(ttype, jobid, wf, task_index, -1, "ERROR", error_message, &my_output_json)) {
								pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to save JSON Response for task '%s' of '%s'\n", ttype, jobid,
								      wf->tasks[task_index].name, wf->name);
								pthread_mutex_unlock(&global_flag);
								*response = OPH_SERVER_IO_ERROR;
								oph_output_data_free(outputs_keys, outputs_num);
								oph_output_data_free(outputs_values, outputs_num);
								return SOAP_OK;
							}
						}
					}
					if (set_update_task_data)
						update_task_data = 1;
				}
			} else {
				wf->tasks[task_index].residual_auto_retry_num = 0;
				if (set_update_task_data)
					update_task_data = 1;
			}
		}

		int check_status = 0;
		if (massive_completed || (light_task_index < 0)) {

			check_status = (status == OPH_ODB_STATUS_COMPLETED) || (status == OPH_ODB_STATUS_ERROR);
			if (check_status) {
				if (wf->tasks[wf->tasks_num].name)
					update_wf_data = final = 1;

				// Log into TASK_LOGFILE
				if (task_logfile) {
					time_t nowtime;
					struct tm nowtm;
					struct timeval tv;
					char buffer[OPH_SHORT_STRING_SIZE];
					*buffer = 0;
					pthread_mutex_lock(&curl_flag);
					gettimeofday(&tv, 0);
					time(&nowtime);
					if (localtime_r(&nowtime, &nowtm))
						strftime(buffer, OPH_SHORT_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm);
					fprintf(task_logfile, "%s\t%d\t%d\t%s\t%d\t%d\t%f\n", buffer, wf->tasks[task_index].idjob, wf->idjob, wf->tasks[task_index].operator,
						wf->tasks[task_index].light_tasks_num ? 0 : wf->tasks[task_index].ncores, status == OPH_ODB_STATUS_COMPLETED,
						(double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->tasks[task_index].timestamp);
					pthread_mutex_unlock(&curl_flag);
				}

				if (service_info)	// This increment is not covered by service_flag only for simplicity, otherwise a lock could result in a deadlock
					service_info->closed_tasks++;
			}
			if (check_status && !final) {
				int hh = 0;
				char *next_task;
				update_wf_data = 1;

				if (!wf->residual_tasks_num) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: workflow '%s' has no children but a child is ended\n", ttype, jobid, wf->name);
					pthread_mutex_unlock(&global_flag);
					*response = OPH_SERVER_SYSTEM_ERROR;
					oph_output_data_free(outputs_keys, outputs_num);
					oph_output_data_free(outputs_values, outputs_num);
					return SOAP_OK;
				}
#if defined(LEVEL1) || defined(LEVEL2) || defined(LEVEL3) || defined(COMMAND_TO_JSON)
				// Store the JSON Response of the task if not received: maybe execution simulation was activated or some errors occured!
				if (!my_output_json && !output_json) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: Missed receipt of JSON Response from framework: %s\n", ttype, jobid, data);

					int success = 0;
					oph_json *oper_json = NULL;

					char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];
					snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
					snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d",
						 light_task_index_orig >= 0 ? wf->tasks[task_index].light_tasks[light_task_index_orig].markerid : wf->tasks[task_index].markerid);
					snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid, OPH_SESSION_MARKER_DELIMITER,
						 str_markerid);

					char error_message[OPH_MAX_STRING_SIZE];
					if (wf->tasks[task_index].run)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Internal server error: no response has been received from analytics framework!");
					else
						snprintf(error_message, OPH_MAX_STRING_SIZE, "This task was not performed really!");

					while (!success) {
						if (oph_json_alloc_unsafe(&oper_json)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
							break;
						}
						if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
							break;
						}
						if (res)
							break;
						if (oph_json_add_source_detail_unsafe(oper_json, "Session Code", session_code)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail_unsafe(oper_json, "Workflow", str_workflowid)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail_unsafe(oper_json, "Marker", str_markerid)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_source_detail_unsafe(oper_json, "JobID", str_jobid)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
							break;
						}
						if (oph_json_add_consumer_unsafe(oper_json, wf->username)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
							break;
						}
						success = 1;
					}
					if (oper_json) {
						int return_code = 0;
						if (!success)
							snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
						if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, wf->tasks[task_index].run ? "ERROR" : "SUCCESS", error_message)) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
							return_code = -1;
						} else if (oph_write_and_get_json_unsafe(oper_json, &my_output_json))
							return_code = -1;
						if (!return_code)
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
					}
					oph_json_free_unsafe(oper_json);

#if defined(LEVEL2) || defined(LEVEL3)
					if (wf->tasks[task_index].response)
						free(wf->tasks[task_index].response);
					wf->tasks[task_index].response = strdup(my_output_json);
					hh = 1;
#endif
				}
#endif

#ifdef LEVEL2
				// Save the JSON Response (Level2 output is admitted)
				if (!hh && wf->exec_mode && !strncasecmp(wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
					if (wf->tasks[task_index].response)
						free(wf->tasks[task_index].response);
					wf->tasks[task_index].response = strdup(my_output_json ? my_output_json : (output_json ? output_json : ""));
				} else
#endif
				if (!hh)
					for (; hh < wf->tasks[task_index].dependents_indexes_num; ++hh) {
						next_task = wf->tasks[wf->tasks[task_index].dependents_indexes[hh]].operator;
						if (!strncasecmp(next_task, OPH_OPERATOR_FOR, OPH_MAX_STRING_SIZE) || !strncasecmp(next_task, OPH_OPERATOR_SET, OPH_MAX_STRING_SIZE)) {
							if (wf->tasks[task_index].response)
								free(wf->tasks[task_index].response);
							wf->tasks[task_index].response = strdup(my_output_json ? my_output_json : (output_json ? output_json : ""));
						}
					}

				if (wf->tasks[task_index].retry_num < 0) {
					status = OPH_ODB_STATUS_COMPLETED;	// Skip possible errors
					if ((wf->tasks[task_index].status > (int) OPH_ODB_STATUS_COMPLETED) && (wf->tasks[task_index].status < (int) OPH_ODB_STATUS_SKIPPED))
						wf->tasks[task_index].status = OPH_ODB_STATUS_SKIPPED;
				}

				if (status == OPH_ODB_STATUS_COMPLETED) {
					if (wf->tasks[task_index].is_skipped && (wf->tasks[task_index].status <= (int) OPH_ODB_STATUS_COMPLETED))
						wf->tasks[task_index].status = OPH_ODB_STATUS_UNSELECTED;

					wf->residual_tasks_num--;

					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' of workflow '%s' is ended (%d tasks to go)\n", ttype, jobid, wf->tasks[task_index].name, wf->name,
					      wf->residual_tasks_num);

					task_completed = 1;

					// Save well-known parameters and publish it on web
					char linkname[OPH_SHORT_STRING_SIZE];
					for (i = 0; i < outputs_num; ++i) {
						if (!strncmp(outputs_keys[i], OPH_ARG_CUBE, OPH_MAX_STRING_SIZE)) {
							if (wf->cube)
								free(wf->cube);
							wf->cube = strndup(outputs_values[i], OPH_MAX_STRING_SIZE);
							snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_CUBE, wf->tasks[task_index].markerid);
							oph_session_report_append_link(session_code, wf->workflowid, NULL, linkname, outputs_values[i], 'C');
						} else if (!strncmp(outputs_keys[i], OPH_ARG_CDD, OPH_MAX_STRING_SIZE)) {
							if (wf->cdd)
								free(wf->cdd);
							wf->cdd = strndup(outputs_values[i], OPH_MAX_STRING_SIZE);
						} else if (!strncmp(outputs_keys[i], OPH_ARG_CWD, OPH_MAX_STRING_SIZE)) {
							if (wf->cwd)
								free(wf->cwd);
							wf->cwd = strndup(outputs_values[i], OPH_MAX_STRING_SIZE);
						} else if (!strncmp(outputs_keys[i], OPH_ARG_LINK, OPH_MAX_STRING_SIZE)) {
							snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_LINK, wf->tasks[task_index].markerid);
							oph_session_report_append_link(session_code, wf->workflowid, NULL, linkname, outputs_values[i], 'L');
						}
					}

					int outputs_file = -1;
					for (i = 0; i < outputs_num; ++i) {
						if (!strncmp(outputs_keys[i], OPH_ARG_FILE, OPH_MAX_STRING_SIZE)) {
							for (j = 0; j < outputs_num; ++j) {
								if ((i != j) && !strncmp(outputs_keys[j], OPH_ARG_CUBE, OPH_MAX_STRING_SIZE)) {
									free(outputs_values[j]);
									outputs_values[j] = strdup(outputs_values[i]);	// Option 'file' has the priority, value of 'cube' is overwritten
									outputs_file = j;
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: value of '%s' is overwritten with value of '%s'\n", ttype, jobid, OPH_ARG_CUBE,
									      OPH_ARG_FILE);
									break;
								}
							}
							if (j == outputs_num) {	// parameter 'cube' not found
								char **outputs_keys_new = (char **) realloc(outputs_keys, (1 + outputs_num) * sizeof(char *));
								if (outputs_keys_new) {
									outputs_keys = outputs_keys_new;
									outputs_keys[outputs_num] = strdup(OPH_ARG_CUBE);
								} else
									pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in adding parameter '%s'\n", ttype, jobid, OPH_ARG_CUBE);
								char **outputs_values_new = (char **) realloc(outputs_values, (1 + outputs_num) * sizeof(char *));
								if (outputs_values_new) {
									outputs_values = outputs_values_new;
									outputs_values[outputs_num] = strdup(outputs_values[i]);
								} else
									pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in adding parameter '%s'\n", ttype, jobid, OPH_ARG_CUBE);
								outputs_file = outputs_num;
								outputs_num++;
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: add '%s=%s' to notification\n", ttype, jobid, OPH_ARG_CUBE, outputs_values[i]);
							}
							break;
						}
					}

					if (wf->tasks[task_index].outputs_keys) {
						if (!wf->tasks[task_index].parallel_mode && (!wf->tasks[task_index].light_tasks_num || wf->tasks[task_index].residual_light_tasks_num)) {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: workflow '%s' has already an output list but it is not massive\n", ttype, jobid, wf->name);
							pthread_mutex_unlock(&global_flag);
							*response = OPH_SERVER_SYSTEM_ERROR;
							oph_output_data_free(outputs_keys, outputs_num);
							oph_output_data_free(outputs_values, outputs_num);
							return SOAP_OK;
						}
					} else {
						wf->tasks[task_index].outputs_keys = outputs_keys;
						wf->tasks[task_index].outputs_values = outputs_values;
						wf->tasks[task_index].outputs_file = outputs_file;
						wf->tasks[task_index].outputs_num = outputs_num;
					}

					outputs_keys = outputs_values = NULL;
					outputs_num = 0;

					// Dependences
					int k, kk, dep_task_index;
					for (i = 0; i < wf->tasks[task_index].dependents_indexes_num; ++i) {
						dep_task_index = wf->tasks[task_index].dependents_indexes[i];
						if ((dep_task_index < 0) || (dep_task_index >= wf->tasks_num))
							continue;
						for (j = 0; j < wf->tasks[dep_task_index].deps_num; ++j) {
							if (wf->tasks[dep_task_index].deps[j].task_index == task_index) {
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: found a dependence '%s' with respect to task '%s'\n", ttype, jobid,
								      wf->tasks[dep_task_index].deps[j].type, wf->tasks[dep_task_index].name);
								if (strncasecmp(wf->tasks[dep_task_index].deps[j].type, OPH_WORKFLOW_TYPE_EMBEDDED, OPH_MAX_STRING_SIZE)) {
									for (k = 0; k < wf->tasks[task_index].outputs_num; ++k)
										if (!strncmp
										    (wf->tasks[task_index].outputs_keys[k], wf->tasks[dep_task_index].deps[j].output_argument, OPH_MAX_STRING_SIZE)) {
											if ((wf->tasks[task_index].light_tasks_num > 1)
											    && !strncasecmp(wf->tasks[dep_task_index].deps[j].type, OPH_WORKFLOW_TYPE_SINGLE, OPH_MAX_STRING_SIZE)) {
												if (wf->tasks[dep_task_index].retry_num < 0)
													pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: skipping dependence check for task '%s'\n", ttype,
													      jobid, wf->tasks[dep_task_index].name);
												else {
													pmesg(LOG_WARNING, __FILE__, __LINE__,
													      "%c%d: dependence type with task '%s' is '%s', but the task '%s' has more outputs called '%s'\n",
													      ttype, jobid, wf->tasks[dep_task_index].name, OPH_WORKFLOW_TYPE_SINGLE,
													      wf->tasks[task_index].name, wf->tasks[task_index].outputs_keys[k]);
													// Set the depending tasks as ABORTED
													wf->tasks[dep_task_index].status = OPH_ODB_STATUS_ABORTED;
													if (oph_workflow_set_status
													    (ttype, jobid, wf, wf->tasks[dep_task_index].dependents_indexes,
													     wf->tasks[dep_task_index].dependents_indexes_num, OPH_ODB_STATUS_ABORTED)) {
														pmesg(LOG_ERROR, __FILE__, __LINE__,
														      "%c%d: error in updating the status of dependents of '%s'\n", ttype, jobid,
														      wf->tasks[task_index].name);
														pthread_mutex_unlock(&global_flag);
														*response = OPH_SERVER_SYSTEM_ERROR;
														return SOAP_OK;
													}
													wf->status = OPH_ODB_STATUS_ERROR;
													check_for_constraint = 1;
													failed_task = wf->tasks[dep_task_index].name;
													break;
												}
											}
											for (kk = 0; kk < wf->tasks[dep_task_index].arguments_num; ++kk)
												if (!strcmp(wf->tasks[dep_task_index].arguments_keys[kk], wf->tasks[dep_task_index].deps[j].argument))
													break;
											if (kk >= wf->tasks[dep_task_index].arguments_num) {
												kk = wf->tasks[dep_task_index].arguments_num;
												int kkk = kk;
												if (oph_realloc_vector(&(wf->tasks[dep_task_index].arguments_keys), &kk, 1)
												    || (kk != 1 + wf->tasks[dep_task_index].arguments_num)) {
													pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
													pthread_mutex_unlock(&global_flag);
													*response = OPH_SERVER_SYSTEM_ERROR;
													return SOAP_OK;
												}
												if (oph_realloc_vector(&(wf->tasks[dep_task_index].arguments_values), &kkk, 1) || (kk != kkk)) {
													pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
													pthread_mutex_unlock(&global_flag);
													*response = OPH_SERVER_SYSTEM_ERROR;
													return SOAP_OK;
												}
												if (oph_realloc_vector2
												    (&(wf->tasks[dep_task_index].arguments_lists), &(wf->tasks[dep_task_index].arguments_num), 1)
												    || (kk != wf->tasks[dep_task_index].arguments_num)) {
													pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
													pthread_mutex_unlock(&global_flag);
													*response = OPH_SERVER_SYSTEM_ERROR;
													return SOAP_OK;
												}
												kk--;
												wf->tasks[dep_task_index].arguments_keys[kk] = strdup(wf->tasks[dep_task_index].deps[j].argument);
											}

											if (oph_workflow_add_to_list
											    (wf->tasks[dep_task_index].deps[j].order, wf->tasks[task_index].outputs_values[k],
											     wf->tasks[dep_task_index].arguments_lists + kk)) {
												pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in setting ordered list\n", ttype, jobid);
												pthread_mutex_unlock(&global_flag);
												*response = OPH_SERVER_SYSTEM_ERROR;
												return SOAP_OK;
											}
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: add KV pair '%s=%s' to list of task '%s'\n", ttype, jobid,
											      wf->tasks[dep_task_index].arguments_keys[kk], wf->tasks[task_index].outputs_values[k],
											      wf->tasks[dep_task_index].name);

											break;
										}
									if (check_for_constraint)
										break;
									if (k == wf->tasks[task_index].outputs_num)
										pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: output argument '%s' not found\n", ttype, jobid,
										      wf->tasks[dep_task_index].deps[j].output_argument);
								}
								if (!wf->tasks[dep_task_index].residual_deps_num) {
									pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: too dependencies were coded for task '%s' of '%s'\n", ttype, jobid,
									      wf->tasks[dep_task_index].name, wf->name);
									pthread_mutex_unlock(&global_flag);
									*response = OPH_SERVER_SYSTEM_ERROR;
									return SOAP_OK;
								} else
									(wf->tasks[dep_task_index].residual_deps_num)--;
								wf->tasks[dep_task_index].deps[j].task_index = -1;
							}
						}
					}

					// Exit operation
					while (wf->tasks[task_index].exit_action) {
						char target[OPH_MAX_STRING_SIZE];
						switch (wf->tasks[task_index].exit_action) {
							case OPH_WORKFLOW_EXIT_ACTION_DELETE:
								strcpy(target, OPH_ARG_CUBE);
								break;
							case OPH_WORKFLOW_EXIT_ACTION_DELETECONTAINER:
								strcpy(target, OPH_ARG_CONTAINER_PID);
								break;
							default:
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: unknown code for 'exit action'\n", ttype, jobid);
								*target = 0;
						}
						if (!strlen(target))
							break;
						char *pch, *pch2 = NULL, *save_pointer = NULL, *output_objects = NULL, tmp2[OPH_MAX_STRING_SIZE];
						for (k = 0; k < wf->tasks[task_index].outputs_num; ++k)
							if (!strncmp(wf->tasks[task_index].outputs_keys[k], target, OPH_MAX_STRING_SIZE)) {
								// Check input cubes in order to avoid to apply the exit action to read-only cubes
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: process '%s' to filter input cubes/containers for final operation\n", ttype, jobid,
								      wf->tasks[task_index].outputs_values[k]);
								if (k == wf->tasks[task_index].outputs_file) {
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: '%s' will be not considered for final operation\n", ttype, jobid,
									      wf->tasks[task_index].outputs_values[k]);
									break;
								}
								snprintf(tmp2, OPH_MAX_STRING_SIZE, "%s", wf->tasks[task_index].outputs_values[k]);
								pch = strtok_r(tmp2, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
								while (pch) {
									for (i = 0; i < wf->tasks[task_index].arguments_num; ++i)
										if (!strncmp(wf->tasks[task_index].arguments_keys[i], target, OPH_MAX_STRING_SIZE)) {
											if (wf->tasks[task_index].light_tasks_num) {
												for (j = 0; j < wf->tasks[task_index].light_tasks_num; ++j) {
													if (!strcmp(pch, pch2 = wf->tasks[task_index].light_tasks[j].arguments_values[i]))
														break;
												}
												if (j >= wf->tasks[task_index].light_tasks_num)
													pch2 = NULL;
											} else
												pch2 = wf->tasks[task_index].arguments_values[i];
											while (pch2 && ((pch2 = strstr(pch2, pch)))) {
												pch2 += strlen(pch);
												if (!(*pch2) || (*pch2 == OPH_SEPARATOR_SUBPARAM_STR[0]))
													break;
											}
											break;
										}
									if (!pch2) {
										if (output_objects) {
											snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%s", output_objects, OPH_SEPARATOR_SUBPARAM_STR, pch);
											free(output_objects);
											output_objects = strdup(tmp);
										} else
											output_objects = strdup(pch);
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: add '%s' to candidate list for final operation\n", ttype, jobid, pch);
									} else
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: '%s' will be not considered for final operation\n", ttype, jobid, pch);
									pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
								}
								if (output_objects) {
									char *objectid = NULL;
									switch (wf->tasks[task_index].exit_action) {
										case OPH_WORKFLOW_EXIT_ACTION_DELETE:{
												pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: process '%s' to select cubes for final operation\n", ttype,
												      jobid, output_objects);
												do {
													objectid = strrchr(output_objects, OPH_SEPARATOR_FOLDER[0]);
													if (!objectid)
														break;
													objectid++;
													if (!wf->exit_cubes && oph_trash_create(&wf->exit_cubes)) {
														pmesg(LOG_WARNING, __FILE__, __LINE__,
														      "%c%d: error in allocating the list of exit cubes\n", ttype, jobid);
														free(output_objects);
														pthread_mutex_unlock(&global_flag);
														*response = OPH_SERVER_SYSTEM_ERROR;
														return SOAP_OK;
													}
													oph_trash_append(wf->exit_cubes, NULL, strtol(objectid, NULL, 10));
													pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: add '%s' to KV pair for final operation\n", ttype,
													      jobid, objectid);
													objectid = strrchr(output_objects, OPH_SEPARATOR_SUBPARAM_STR[0]);
													if (objectid)
														*objectid = 0;
												}
												while (objectid);
												break;
											}
										case OPH_WORKFLOW_EXIT_ACTION_DELETECONTAINER:{
												pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: process '%s' to select containers for final operation\n",
												      ttype, jobid, output_objects);
												do {
													objectid = strrchr(output_objects, OPH_SEPARATOR_FOLDER[0]);
													if (!objectid)
														break;
													objectid++;
													if (!wf->exit_containers && oph_trash_create(&wf->exit_containers)) {
														pmesg(LOG_WARNING, __FILE__, __LINE__,
														      "%c%d: error in allocating the list of exit containers\n", ttype, jobid);
														free(output_objects);
														pthread_mutex_unlock(&global_flag);
														*response = OPH_SERVER_SYSTEM_ERROR;
														return SOAP_OK;
													}
													oph_trash_append(wf->exit_containers, NULL, strtol(objectid, NULL, 10));
													pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: add '%s' to KV pair for final operation\n", ttype,
													      jobid, objectid);
													objectid = strrchr(output_objects, OPH_SEPARATOR_SUBPARAM_STR[0]);
													if (objectid)
														*objectid = 0;
												}
												while (objectid);
												break;
											}
									}
									free(output_objects);
									output_objects = NULL;
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: updated KV pair for final operation\n", ttype, jobid);
								}
								break;
							}
						break;
					}

					if (wf->status == OPH_ODB_STATUS_ERROR)	// Due to a previous failed task
					{
						if (!wf->residual_tasks_num) {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: completed the last task of '%s', current state %s\n", ttype, jobid, wf->name,
							      oph_odb_convert_status_to_str(wf->status));
							final = 1;
						} else {
							for (i = 0; i < wf->tasks_num; ++i)
								if ((wf->tasks[i].status > OPH_ODB_STATUS_UNKNOWN) && (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED))
									break;
							if (i == wf->tasks_num) {
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: completed the last task of '%s', current state %s\n", ttype, jobid, wf->name,
								      oph_odb_convert_status_to_str(wf->status));
								final = 1;
							}
						}
					} else if (!wf->residual_tasks_num) {
						if (wf->status < (int) status)
							wf->status = status;	// OPH_ODB_STATUS_COMPLETED
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: completed the last task of '%s', current state %s\n", ttype, jobid, wf->name,
						      oph_odb_convert_status_to_str(wf->status));
						final = 1;
					} else
						update_wf_data = 2;
				} else {
					if (!wf->tasks[task_index].retry_num) {
						wf->residual_tasks_num--;
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' of '%s' has been skipped\n", ttype, jobid, wf->tasks[task_index].name, wf->name);
						// Set the depending tasks as ABORTED
						if (oph_workflow_set_status
						    (ttype, jobid, wf, wf->tasks[task_index].dependents_indexes, wf->tasks[task_index].dependents_indexes_num, OPH_ODB_STATUS_ABORTED)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in updating the status of dependents of '%s'\n", ttype, jobid, wf->tasks[task_index].name);
							pthread_mutex_unlock(&global_flag);
							*response = OPH_SERVER_SYSTEM_ERROR;
							return SOAP_OK;
						}
						if (!wf->residual_tasks_num)	// Check for workflow termination
						{
							status = OPH_ODB_STATUS_COMPLETED;
							if (wf->status < (int) status)
								wf->status = status;
							final = 1;
						} else if (wf->status == OPH_ODB_STATUS_ERROR) {
							for (i = 0; i < wf->tasks_num; ++i)
								if ((wf->tasks[i].status > OPH_ODB_STATUS_UNKNOWN) && (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED))
									break;
							if (i == wf->tasks_num) {
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: completed the last task of '%s', current state %s\n", ttype, jobid, wf->name,
								      oph_odb_convert_status_to_str(wf->status));
								final = 1;
							}
						}
					} else if (!wf->tasks[task_index].residual_retry_num)	// Critical error
					{
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: error in handling the retry attempts for task '%s'\n", ttype, jobid, wf->tasks[task_index].name);
						pthread_mutex_unlock(&global_flag);
						*response = OPH_SERVER_SYSTEM_ERROR;
						return SOAP_OK;
					} else {
						char reduce_residual_retry_num = 1;
						if (oph_auto_retry && wf->tasks[task_index].is_marked_for_auto_retry && (wf->tasks[task_index].retry_num == 1)) {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' has been marked for auto-retry\n", ttype, jobid, wf->tasks[task_index].name);
							char save = 0;
							if (!wf->tasks[task_index].residual_auto_retry_num)
								wf->tasks[task_index].residual_auto_retry_num = 1 + oph_auto_retry;
							else if (wf->tasks[task_index].residual_auto_retry_num > 1)
								wf->tasks[task_index].residual_auto_retry_num--;
							else
								save = 1;
							if (!save) {
								update_wf_data = 0;
								status = OPH_ODB_STATUS_RUNNING;
								wf->tasks[task_index].status = OPH_ODB_STATUS_UNKNOWN;
								retry_task_execution = 1;
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' of '%s' will be re-executed\n", ttype, jobid, wf->tasks[task_index].name,
								      wf->name);
								reduce_residual_retry_num = 0;
							}
						}
						if (reduce_residual_retry_num) {
							wf->tasks[task_index].residual_retry_num--;
							if (wf->tasks[task_index].residual_retry_num)	// Try to restart the task
							{
								update_wf_data = 0;
								status = OPH_ODB_STATUS_RUNNING;
								wf->tasks[task_index].status = OPH_ODB_STATUS_UNKNOWN;
								retry_task_execution = 1;
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' of '%s' will be re-executed\n", ttype, jobid, wf->tasks[task_index].name,
								      wf->name);
							} else	// Task is definitely considered as "failed"
							{
								wf->residual_tasks_num--;
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: task '%s' of '%s' will be considered as 'failed'\n", ttype, jobid,
								      wf->tasks[task_index].name, wf->name);
								wf->status = status;
								for (i = 0; i < wf->tasks_num; ++i)
									if ((wf->tasks[i].status > OPH_ODB_STATUS_UNKNOWN) && (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED))
										break;
								if (i == wf->tasks_num) {
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: completed the last task of '%s', current state %s\n", ttype, jobid, wf->name,
									      oph_odb_convert_status_to_str(wf->status));
									final = 1;
								}
							}
						}
					}
				}

				// Trace the output
				if ((status == OPH_ODB_STATUS_COMPLETED) || (status == OPH_ODB_STATUS_ERROR)) {
					oph_workflow_task_out *wtmp = wf->output, *wtmp2 = NULL, *prev = NULL;
					while (wtmp && (wtmp->markerid < wf->tasks[task_index].markerid)) {
						prev = wtmp;
						wtmp = wtmp->next;
					}
					if (wtmp && (wtmp->markerid == wf->tasks[task_index].markerid))
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: output of task '%s' of '%s' has been already traced\n", ttype, jobid, wf->tasks[task_index].name,
						      wf->name);
					else if (oph_workflow_save_task_output(&(wf->tasks[task_index]), &wtmp2))
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: output of task '%s' of '%s' cannot be traced\n", ttype, jobid, wf->tasks[task_index].name, wf->name);
					else if (prev)
						prev->next = wtmp2;
					else
						wf->output = wtmp2;
					if (wtmp2)
						wtmp2->next = wtmp;
				}
			} else if (status == OPH_ODB_STATUS_RUNNING) {
				if (wf->status < (int) status) {
					wf->status = status;
					update_wf_data = 1;
				}
			}
		}

		oph_output_data_free(outputs_keys, outputs_num);
		oph_output_data_free(outputs_values, outputs_num);

		int error = 0;

		if (update_wf_data || update_task_data || update_light_task_data || retry_task_execution) {
			oph_odb_initialize_ophidiadb(&oDB);
			if (oph_odb_read_config_ophidiadb(&oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to read OphidiaDB configuration\n", ttype, jobid);
				*response = OPH_SERVER_SYSTEM_ERROR;
				oph_odb_disconnect_from_ophidiadb(&oDB);
				error = 1;
			} else if (oph_odb_connect_to_ophidiadb(&oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to connect to OphidiaDB. Check access parameters.\n", ttype, jobid);
				*response = OPH_SERVER_IO_ERROR;
				oph_odb_disconnect_from_ophidiadb(&oDB);
				error = 1;
			} else {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: CONNECTED to OphidiaDB\n", ttype, jobid);
				connection_up = 1;
			}
		}

		if (!error && update_light_task_data) {
			if (oph_odb_set_job_status(wf->tasks[task_index].light_tasks[light_task_index_orig].idjob, wf->tasks[task_index].light_tasks[light_task_index_orig].status, &oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to update job status\n", ttype, jobid);
				*response = OPH_SERVER_IO_ERROR;
				error = 1;
			} else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: update status of job %d to %s\n", ttype, jobid, wf->tasks[task_index].light_tasks[light_task_index_orig].idjob,
				      oph_odb_convert_status_to_str(wf->tasks[task_index].light_tasks[light_task_index_orig].status));
		}
		if (massive_completed)
			light_task_index = -1;	// It needs to be tested

		if (!error && update_task_data) {
			if (oph_odb_set_job_status_and_nchildrencompleted
			    (wf->tasks[task_index].idjob, wf->tasks[task_index].status,
			     wf->tasks[task_index].light_tasks_num ? wf->tasks[task_index].light_tasks_num - wf->tasks[task_index].residual_light_tasks_num : -1, update_task_data == 2, &oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to update job status\n", ttype, jobid);
				*response = OPH_SERVER_IO_ERROR;
				error = 1;
			} else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: update status of job %d to %s\n", ttype, jobid, wf->tasks[task_index].idjob,
				      oph_odb_convert_status_to_str(wf->tasks[task_index].status));
		}

		if (!error && update_wf_data && !wf->tasks[wf->tasks_num].name) {
			if (oph_odb_set_job_status_and_nchildrencompleted(odb_parentid, wf->status, wf->tasks_num - wf->residual_tasks_num, update_wf_data == 2, &oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to update parent job status\n", ttype, jobid);
				*response = OPH_SERVER_IO_ERROR;
				error = 1;
			} else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: update status of job %d to %s\n", ttype, jobid, odb_parentid, oph_odb_convert_status_to_str(status));
		}

		int final_task = 0;
		if (final) {
			if (wf->exit_cubes) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: building '%s'\n", ttype, jobid, OPH_WORKFLOW_FINAL_TASK);
				wf->tasks[wf->tasks_num].name = strdup(OPH_WORKFLOW_FINAL_TASK);
				wf->tasks[wf->tasks_num].operator = strdup(OPH_WORKFLOW_DELETE);
				wf->tasks[wf->tasks_num].ncores = 1;	// Only 1-core is used for each job of final task

				int kk = wf->tasks[wf->tasks_num].arguments_num, kkk = kk;;
				if (oph_realloc_vector(&(wf->tasks[wf->tasks_num].arguments_keys), &kk, 1) || (kk != 1 + wf->tasks[wf->tasks_num].arguments_num)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
					*response = OPH_SERVER_SYSTEM_ERROR;
					error = 1;
				} else if (oph_realloc_vector(&(wf->tasks[wf->tasks_num].arguments_values), &kkk, 1) || (kk != kkk)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
					*response = OPH_SERVER_SYSTEM_ERROR;
					error = 1;
				} else if (oph_realloc_vector2(&(wf->tasks[wf->tasks_num].arguments_lists), &(wf->tasks[wf->tasks_num].arguments_num), 1)
					   || (kk != wf->tasks[wf->tasks_num].arguments_num)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
					*response = OPH_SERVER_SYSTEM_ERROR;
					error = 1;
				} else {
					kk--;
					// Order the exit values
					int cubeid, write, append;
					char exit_cubes[OPH_MAX_STRING_SIZE], *last_block, *last_index;
					*exit_cubes = 0;
					oph_trash_order(wf->exit_cubes, NULL);
					while (!oph_trash_extract(wf->exit_cubes, NULL, &cubeid)) {
						if (strlen(exit_cubes)) {
							write = append = 1;
							last_block = strrchr(exit_cubes, OPH_SUBSET_LIB_SUBSET_SEPARATOR[0]);
							if (!last_block)
								last_block = exit_cubes;
							else
								last_block++;
							last_index = strchr(last_block, OPH_SUBSET_LIB_PARAM_SEPARATOR[0]);
							if (last_index) {
								last_index++;
								if (strtol(last_index, NULL, 10) == cubeid - 1) {
									snprintf(last_index, OPH_MAX_STRING_SIZE - strlen(last_index), "%d", cubeid);
									write = append = 0;
								}
							} else {
								if (strtol(last_block, NULL, 10) == cubeid - 1) {
									snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%d", OPH_SUBSET_LIB_PARAM_SEPARATOR, cubeid);
									write = 0;
								}
							}
							if (write)
								snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%d", OPH_SUBSET_LIB_SUBSET_SEPARATOR, cubeid);
							if (append)
								strncat(exit_cubes, tmp, OPH_MAX_STRING_SIZE - strlen(exit_cubes) - 1);
						} else
							snprintf(exit_cubes, OPH_MAX_STRING_SIZE, "%d", cubeid);
					}
					snprintf(tmp, OPH_MAX_STRING_SIZE, "%c%s%s%s%s%s%s%s%s%s%s%s%c", OPH_SEPARATOR_SUBPARAM_OPEN, OPH_MF_ARG_DATACUBE_FILTER, OPH_SEPARATOR_KV, exit_cubes,
						 OPH_SEPARATOR_PARAM, OPH_MF_ARG_PATH, OPH_SEPARATOR_KV, OPH_MF_ROOT_FOLDER, OPH_SEPARATOR_PARAM, OPH_MF_ARG_RECURSIVE, OPH_SEPARATOR_KV,
						 OPH_MF_ARG_VALUE_YES, OPH_SEPARATOR_SUBPARAM_CLOSE);

					wf->tasks[wf->tasks_num].arguments_keys[kk] = strdup(OPH_ARG_CUBE);
					wf->tasks[wf->tasks_num].arguments_values[kk] = strdup(tmp);
					wf->tasks[wf->tasks_num].arguments_lists[kk] = NULL;

					final_task = 1;
					final = 0;
				}
				oph_trash_destroy(wf->exit_cubes);
				wf->exit_cubes = NULL;
			} else if (wf->exit_containers) {

				// Warning:only one container can be deleted
				unsigned int size = 0;
				oph_trash_size(wf->exit_containers, NULL, &size);
				if (size) {

					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: building '%s'\n", ttype, jobid, OPH_WORKFLOW_FINAL_TASK);
					if (size > 1)
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: only the first container will be considered even if %d containers was created\n", ttype, jobid, size);

					wf->tasks[wf->tasks_num].name = strdup(OPH_WORKFLOW_FINAL_TASK);
					wf->tasks[wf->tasks_num].operator = strdup(OPH_WORKFLOW_DELETECONTAINER);
					wf->tasks[wf->tasks_num].ncores = 1;	// Only 1-core is used for each job of final task

					int kk = wf->tasks[wf->tasks_num].arguments_num, kkk = kk, incr = 3;	// Specific arguments for this final operation (see below)
					if (oph_realloc_vector(&(wf->tasks[wf->tasks_num].arguments_keys), &kk, incr) || (kk != incr + wf->tasks[wf->tasks_num].arguments_num)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
						*response = OPH_SERVER_SYSTEM_ERROR;
						error = 1;
					} else if (oph_realloc_vector(&(wf->tasks[wf->tasks_num].arguments_values), &kkk, incr) || (kk != kkk)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
						*response = OPH_SERVER_SYSTEM_ERROR;
						error = 1;
					} else if (oph_realloc_vector2(&(wf->tasks[wf->tasks_num].arguments_lists), &(wf->tasks[wf->tasks_num].arguments_num), incr)
						   || (kk != wf->tasks[wf->tasks_num].arguments_num)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in reallocating vector\n", ttype, jobid);
						*response = OPH_SERVER_SYSTEM_ERROR;
						error = 1;
					} else {
						kk -= incr;
						int containerid = 0;
						oph_trash_extract(wf->exit_containers, NULL, &containerid);
						if (containerid) {
							snprintf(tmp, OPH_MAX_STRING_SIZE, "%s/%d", oph_web_server, containerid);
							wf->tasks[wf->tasks_num].arguments_keys[kk] = strdup(OPH_ARG_CONTAINER_PID);
							wf->tasks[wf->tasks_num].arguments_values[kk] = strdup(tmp);
							wf->tasks[wf->tasks_num].arguments_lists[kk++] = NULL;
							wf->tasks[wf->tasks_num].arguments_keys[kk] = strdup(OPH_ARG_CONTAINER);
							wf->tasks[wf->tasks_num].arguments_values[kk] = strdup(OPH_COMMON_NULL);
							wf->tasks[wf->tasks_num].arguments_lists[kk++] = NULL;
							wf->tasks[wf->tasks_num].arguments_keys[kk] = strdup(OPH_WORKFLOW_DELETECONTAINER_FORCE);
							wf->tasks[wf->tasks_num].arguments_values[kk] = strdup(OPH_COMMON_YES);
							wf->tasks[wf->tasks_num].arguments_lists[kk++] = NULL;
							final_task = 1;
							final = 0;
						} else {
							pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: error in extracting the pid of container\n", ttype, jobid);
							*response = OPH_SERVER_SYSTEM_ERROR;
							error = 1;
						}
					}
				} else
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: no container has been created during the execution of workflow '%s'", ttype, jobid, wf->name);

				oph_trash_destroy(wf->exit_containers);
				wf->exit_containers = NULL;
			} else {
				oph_drop_from_job_list(state->job_info, item, prev);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: workflow '%s' dropped from the list\n", ttype, jobid, wf->name);
				free(item);
			}
		}

		pthread_mutex_unlock(&global_flag);

		if (!error) {
			if (final_task) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: execute '%s'\n", ttype, jobid, OPH_WORKFLOW_FINAL_TASK);
				if (oph_workflow_execute(state, 'N', jobid, wf, &wf->tasks_num, 1, &oDB, NULL)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to start '%s'\n", ttype, jobid, OPH_WORKFLOW_FINAL_TASK);
					*response = OPH_SERVER_SYSTEM_ERROR;
					error = 1;
				}
			} else if (retry_task_execution) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: re-execute task '%s'\n", ttype, jobid, wf->tasks[task_index].name);
				if (oph_workflow_execute(state, 'N', jobid, wf, &task_index, 1, &oDB, NULL))	// Data can be out of lock as they should change
				{
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to restart task '%s'\n", ttype, jobid, wf->tasks[task_index].name);
					*response = OPH_SERVER_SYSTEM_ERROR;
					error = 1;
				}
			} else if (update_wf_data && task_completed && !final) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: execute the tasks depending on '%s'\n", ttype, jobid, wf->tasks[task_index].name);
				if (oph_workflow_execute(state, 'N', jobid, wf, wf->tasks[task_index].dependents_indexes, wf->tasks[task_index].dependents_indexes_num, &oDB, NULL))	// Data can be out of lock as they should change
				{
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to start new jobs\n", ttype, jobid);
					*response = OPH_SERVER_SYSTEM_ERROR;
					error = 1;
				}
			}
		}
		// Checkpoint: reference to wf could not be consistent
		char save = final;
		if (!save) {
			pthread_mutex_lock(&global_flag);
			if (oph_find_job_in_job_list(state->job_info, odb_parentid, NULL))
				save = 1;
			else
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to save checkpoint since the workflow has been deleted\n", ttype, jobid);
			pthread_mutex_unlock(&global_flag);
		}
		if (save && wf->tasks[task_index].checkpoint && (status > OPH_ODB_STATUS_RUNNING) && (wf->tasks[task_index].status == OPH_ODB_STATUS_COMPLETED))
			oph_workflow_save(wf, session_code, wf->tasks[task_index].checkpoint);
	}

	if (final) {
		char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];

		snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER, wf->markerid);
		snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
		snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->markerid);

		char error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		// Save JSON related to parent job
		oph_json *oper_json = NULL;
		int success = 0, ii, jj;

		struct timeval tv;
		gettimeofday(&tv, 0);
		char exec_time[OPH_SHORT_STRING_SIZE];
		snprintf(exec_time, OPH_SHORT_STRING_SIZE, "%.2f", (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->timestamp);

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: initialization of the main JSON Response\n", ttype, jobid);
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
				break;
			}
			if (res)
				break;
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Workflow", str_workflowid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", str_markerid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
				break;
			}
			if (oph_json_add_source_detail(oper_json, "JobID", str_jobid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
				break;
			}
			if (oph_json_add_extra_detail(oper_json, OPH_EXEC_TIME, exec_time)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD EXTRA DETAIL error\n", ttype, jobid);
				break;
			}
			if (wf->cdd && oph_json_add_extra_detail(oper_json, OPH_ARG_CDD, wf->cdd)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD EXTRA DETAIL error\n", ttype, jobid);
				break;
			}
			if (wf->cube && oph_json_add_extra_detail(oper_json, OPH_ARG_CUBE, wf->cube)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD EXTRA DETAIL error\n", ttype, jobid);
				break;
			}
			if (wf->cwd && oph_json_add_extra_detail(oper_json, OPH_ARG_CWD, wf->cwd)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD EXTRA DETAIL error\n", ttype, jobid);
				break;
			}
			if (wf->new_token && oph_json_add_extra_detail(oper_json, OPH_AUTH_TOKEN_JSON, wf->new_token)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD EXTRA DETAIL error\n", ttype, jobid);
				break;
			}
			success = 1;
		}

		if (!success)
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		else if (odb_status == OPH_ODB_STATUS_START_ERROR)
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in starting the execution of a task!");

		int check_for_aborted = 0, wf_status = wf->status > (int) OPH_ODB_STATUS_ERROR ? OPH_ODB_STATUS_ERROR : wf->status;
		if (success && item) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: starting to format JSON file\n", ttype, jobid);

			int num_fields = 8, iii, jjj = 0, skipped_num;

			char **jsonkeys = NULL;
			char **fieldtypes = NULL;
			char **jsonvalues = NULL;
			char jsontmp[OPH_MAX_STRING_SIZE];

			success = 0;
			while (!success) {
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_WORKFLOW_STATUS, "Workflow Status", oph_odb_convert_status_to_str(wf_status))) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
					break;
				}

				num_fields = 3;
				jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
				if (!jsonkeys) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					break;
				}
				jsonkeys[jjj] = strdup("NUMBER OF COMPLETED TASKS");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("NUMBER OF SKIPPED TASKS");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("TOTAL NUMBER OF TASKS");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				fieldtypes[jjj] = strdup(OPH_JSON_INT);
				if (!fieldtypes[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
				if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_WORKFLOW_PROGRESS, "Workflow Progress", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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
				jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
				if (!jsonvalues) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					break;
				}

				for (iii = skipped_num = 0; iii < wf->tasks_num; iii++)
					if ((wf->tasks[iii].status == (int) OPH_ODB_STATUS_SKIPPED) || (wf->tasks[iii].status == (int) OPH_ODB_STATUS_UNSELECTED))
						skipped_num++;

				jjj = 0;
				snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%d", wf->tasks_num - wf->residual_tasks_num - skipped_num);
				jsonvalues[jjj] = strdup(jsontmp);
				if (!jsonvalues[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonvalues[iii])
							free(jsonvalues[iii]);
					if (jsonvalues)
						free(jsonvalues);
					break;
				}
				jjj++;
				snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%d", skipped_num);
				jsonvalues[jjj] = strdup(jsontmp);
				if (!jsonvalues[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonvalues[iii])
							free(jsonvalues[iii]);
					if (jsonvalues)
						free(jsonvalues);
					break;
				}
				jjj++;
				snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%d", wf->tasks_num);
				jsonvalues[jjj] = strdup(jsontmp);
				if (!jsonvalues[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonvalues[iii])
							free(jsonvalues[iii]);
					if (jsonvalues)
						free(jsonvalues);
					break;
				}
				if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_WORKFLOW_PROGRESS, jsonvalues)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID ROW error\n", ttype, jobid);
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

				// Header
				if (wf->output_format) {

					num_fields = 3;
					jjj = 0;
					jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonkeys) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						break;
					}
					jsonkeys[jjj] = strdup("OPH JOB ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("WORKFLOW ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("PARENT MARKER ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_WORKFLOW_INFO, "Workflow Basic Information", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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

					jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						break;
					}
					jjj = 0;
					snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER, wf->markerid);
					jsonvalues[jjj] = strdup(jsontmp);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
					jsonvalues[jjj] = strdup(jsontmp);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->markerid);
					jsonvalues[jjj] = strdup(jsontmp);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;

					if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_WORKFLOW_INFO, jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID ROW error\n", ttype, jobid);
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

				num_fields = wf->output_format ? 4 : 8;
				jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
				if (!jsonkeys) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					break;
				}
				jjj = 0;
				if (!wf->output_format) {
					jsonkeys[jjj] = strdup("OPH JOB ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("SESSION CODE");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("WORKFLOW ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
				}
				jsonkeys[jjj] = strdup("MARKER ID");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				if (!wf->output_format) {
					jsonkeys[jjj] = strdup("PARENT MARKER ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
				}
				jsonkeys[jjj] = strdup("TASK NAME");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("EXIT STATUS");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
				if (!fieldtypes) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj = 0;
				if (!wf->output_format) {
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
				}
				fieldtypes[jjj] = strdup(OPH_JSON_INT);
				if (!fieldtypes[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
				if (!wf->output_format) {
					fieldtypes[jjj] = strdup(OPH_JSON_INT);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
				}
				fieldtypes[jjj] = strdup(OPH_JSON_STRING);
				if (!fieldtypes[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
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
				if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_WORKFLOW_LIST, "Workflow Task List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID error\n", ttype, jobid);
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

				// Data
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: inserting data into JSON file\n", ttype, jobid);
				oph_workflow_task_out *wtmp = wf->output;	// It should be already ordered by markerid
				while (wtmp) {
					if (wtmp->status && (wtmp->status < OPH_ODB_STATUS_ABORTED))	// Discard uninitialized or aborted jobs
					{
						jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
							break;
						}
						jjj = 0;
						if (!wf->output_format) {
							snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid,
								 OPH_SESSION_MARKER_DELIMITER, wtmp->markerid);
							jsonvalues[jjj] = strdup(jsontmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup(session_code);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
							jsonvalues[jjj] = strdup(jsontmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
						}
						snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wtmp->markerid);
						jsonvalues[jjj] = strdup(jsontmp);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						if (!wf->output_format) {
							snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->markerid);
							jsonvalues[jjj] = strdup(jsontmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
						}
						jsonvalues[jjj] = strdup(wtmp->name);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(wtmp->light_tasks_num ? "MASSIVE" : "SIMPLE");
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(oph_odb_convert_status_to_str(wtmp->status));
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_WORKFLOW_LIST, jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD GRID ROW error\n", ttype, jobid);
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
					} else if (wtmp->status == OPH_ODB_STATUS_ABORTED)
						check_for_aborted++;

					wtmp = wtmp->next;
				}

				if (wtmp)
					break;
				else
					success = 1;
			}
		}

		if (success) {
			if (wf->status > OPH_ODB_STATUS_ERROR)
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Workflow aborted!");
			else if (wf->status == OPH_ODB_STATUS_ERROR) {
				if (check_for_constraint)
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Workflow constraint violated on task '%s'!", failed_task ? failed_task : "unknown");
				else {
					int num_errors;
					for (ii = num_errors = 0; ii < wf->tasks_num; ++ii)
						if ((wf->tasks[ii].status >= (int) OPH_ODB_STATUS_ERROR) && (wf->tasks[ii].status < (int) OPH_ODB_STATUS_ABORTED))
							num_errors++;
					snprintf(error_message, OPH_MAX_STRING_SIZE, "%d task%s failed!", num_errors, num_errors == 1 ? "" : "s");
				}
			} else if (check_for_aborted)
				snprintf(error_message, OPH_MAX_STRING_SIZE, "%d task%s %s aborted!", check_for_aborted, check_for_aborted == 1 ? "" : "s", check_for_aborted == 1 ? "was" : "were");
		}

		if (oper_json) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: finalizing JSON file\n", ttype, jobid);

			int return_code = 0;
			if (!success) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting error into JSON file\n", ttype, jobid);
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
					return_code = -1;
				} else if (oph_write_and_get_json(oper_json, &(wf->response)))
					return_code = -1;
			} else {
				if (strlen(error_message)) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting warning into JSON file\n", ttype, jobid);
					if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_WORKFLOW_SUMMARY, "WARNING", error_message)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
						return_code = -1;
					}
				}
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting success into JSON file\n", ttype, jobid);
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
					return_code = -1;
				} else if (oph_write_and_get_json(oper_json, &(wf->response)))
					return_code = -1;
			}
			if (!return_code)
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output for workflow '%s' has been written\n", ttype, jobid, wf->name);
		}
		oph_json_free(oper_json);

		// Move job data for job table to accounting table
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: Transfer workflow metadata to accounting table\n", ttype, jobid);
		success = oph_odb_copy_job(&oDB, wf->idjob, 0);
		if (!success) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: Transfer task metadata to accounting table\n", ttype, jobid);
			success = oph_odb_copy_job(&oDB, 0, wf->idjob);
		}
		for (ii = 0; !success && (ii <= wf->tasks_num); ii++)
			if (wf->tasks[ii].name && wf->tasks[ii].light_tasks_num) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: Transfer light task metadata to accounting table\n", ttype, jobid);
				success = oph_odb_copy_job(&oDB, 0, wf->tasks[ii].idjob);
			}
		if (success)
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: Transfer to accounting table cannot possible: skipping...\n", ttype, jobid);
		oph_odb_drop_job(&oDB, wf->idjob, 0);

		// Log into WF_LOGFILE
		if (wf_logfile) {
			int tasks_num = 0, success_tasks_num = 0;
			for (ii = 0; ii <= wf->tasks_num; ii++)
				if (wf->tasks[ii].name) {
					if (!wf->tasks[ii].light_tasks_num) {
						tasks_num++;
						if ((wf->tasks[ii].status == (int) OPH_ODB_STATUS_COMPLETED) || (wf->tasks[ii].status == (int) OPH_ODB_STATUS_UNSELECTED)
						    || (wf->tasks[ii].status == (int) OPH_ODB_STATUS_SKIPPED))
							success_tasks_num++;
					}
					for (jj = 0; jj < wf->tasks[ii].light_tasks_num; jj++) {
						tasks_num++;
						if ((wf->tasks[ii].light_tasks[jj].status == (int) OPH_ODB_STATUS_COMPLETED)
						    || (wf->tasks[ii].light_tasks[jj].status == (int) OPH_ODB_STATUS_UNSELECTED)
						    || (wf->tasks[ii].light_tasks[jj].status == (int) OPH_ODB_STATUS_SKIPPED))
							success_tasks_num++;
					}
				}
			time_t nowtime;
			struct tm nowtm;
			struct timeval tv;
			char buffer[OPH_SHORT_STRING_SIZE];
			*buffer = 0;
			pthread_mutex_lock(&curl_flag);
			gettimeofday(&tv, 0);
			time(&nowtime);
			if (localtime_r(&nowtime, &nowtm))
				strftime(buffer, OPH_SHORT_STRING_SIZE, "%Y-%m-%d %H:%M:%S", &nowtm);
			char sha_username[2 * SHA_DIGEST_LENGTH + 2];
			oph_sha(sha_username, wf->username);
			fprintf(wf_logfile, "%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%f\n", buffer, wf->idjob, wf->name, sha_username, wf->ip_address ? wf->ip_address : "unknown",
				wf->client_address ? wf->client_address : "unknown", tasks_num, success_tasks_num, (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->timestamp);
			fflush(wf_logfile);
			if (task_logfile)
				fflush(task_logfile);
			pthread_mutex_unlock(&curl_flag);
		}

		if (wf->callback_url) {
			// Build request
			if (!res) {
				CURL *curl = curl_easy_init();
				if (!curl)
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to send notification\n", ttype, jobid);
				else {
					char real_callback_url[OPH_MAX_STRING_SIZE];
#if defined(LEVEL1) || defined(LEVEL2) || defined(LEVEL3) || defined(COMMAND_TO_JSON)
#if defined(LEVEL1) || defined(LEVEL2)
					if (wf->tasks_num == 1)
#elif defined(LEVEL3)
					if (wf->tasks_num == 1)
#else
					if (!wf->author)
#endif
					{
						snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d",
							 light_task_index_orig >= 0 ? wf->tasks[task_index].light_tasks[light_task_index_orig].markerid : wf->tasks[task_index].markerid);
						snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%s", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, wf->workflowid, OPH_SESSION_MARKER_DELIMITER,
							 str_markerid);
					}
#endif
					snprintf(real_callback_url, OPH_MAX_STRING_SIZE, "%s&resulturi=" OPH_JSON_RESPONSE_FILENAME "&jobid=%s", wf->callback_url, oph_web_server, session_code,
						 str_markerid, str_jobid);
					pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "%c%d: send notification to %s\n", ttype, jobid, real_callback_url);

					// Curl options
					curl_easy_setopt(curl, CURLOPT_URL, real_callback_url);
					curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
					curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
					curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, function_pt);
					curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: CURL options set.\n", ttype, jobid);

					// Send notification
					pthread_mutex_lock(&curl_flag);
					res = curl_easy_perform(curl);
					pthread_mutex_unlock(&curl_flag);

					// Cleanup
					curl_easy_cleanup(curl);

					// Check for output
					if (res != CURLE_OK)
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: unable to send notification to %s: %s\n", ttype, jobid, real_callback_url,
							   curl_easy_strerror(res));
				}
			}
		}

		oph_workflow_destroy_hp(wf, &oDB);

		if (wf->exec_mode && !strncasecmp(wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
			pthread_mutex_lock(&global_flag);
			wf->is_closed = 1;	// Effective termination
#if defined(LEVEL1) || defined(LEVEL2) || defined(LEVEL3) || defined(COMMAND_TO_JSON)
			if (!my_output_json && !output_json) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: Missed receipt of JSON Response from framework: %s\n", ttype, jobid, data);

				success = 0;
				oper_json = NULL;
				snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
				snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d",
					 light_task_index_orig >= 0 ? wf->tasks[task_index].light_tasks[light_task_index_orig].markerid : wf->tasks[task_index].markerid);
				snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid, OPH_SESSION_MARKER_DELIMITER, str_markerid);
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Internal server error: no response has been received from analytics framework!");

				while (!success) {
					if (oph_json_alloc_unsafe(&oper_json)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
						break;
					}
					if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
						break;
					}
					if (res)
						break;
					if (oph_json_add_source_detail_unsafe(oper_json, "Session Code", session_code)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "Workflow", str_workflowid)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "Marker", str_markerid)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_source_detail_unsafe(oper_json, "JobID", str_jobid)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD SOURCE DETAIL error\n", ttype, jobid);
						break;
					}
					if (oph_json_add_consumer_unsafe(oper_json, wf->username)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
						break;
					}
					success = 1;
				}
				if (oper_json) {
					int return_code = 0;
					if (!success)
						snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
					if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
						return_code = -1;
					} else if (oph_write_and_get_json_unsafe(oper_json, &my_output_json))
						return_code = -1;
					if (!return_code)
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
				}
				oph_json_free_unsafe(oper_json);

#if defined(LEVEL2) || defined(LEVEL3)
				if (light_task_index < 0) {
					if (wf->tasks[task_index].response)
						free(wf->tasks[task_index].response);
					wf->tasks[task_index].response = strdup(my_output_json);
				}
#ifdef LEVEL3
				else {
					if (wf->tasks[task_index].light_tasks[light_task_index].response)
						free(wf->tasks[task_index].light_tasks[light_task_index].response);
					wf->tasks[task_index].light_tasks[light_task_index].response = strdup(my_output_json);
				}
#endif
#else
				if (light_task_index < 0) {
					int hh;
					char *next_task;
					for (hh = 0; hh < wf->tasks[task_index].dependents_indexes_num; ++hh) {
						next_task = wf->tasks[wf->tasks[task_index].dependents_indexes[hh]].operator;
						if (!strncasecmp(next_task, OPH_OPERATOR_FOR, OPH_MAX_STRING_SIZE) || !strncasecmp(next_task, OPH_OPERATOR_SET, OPH_MAX_STRING_SIZE)) {
							if (wf->tasks[task_index].response)
								free(wf->tasks[task_index].response);
							wf->tasks[task_index].response = strdup(my_output_json);
						}
					}
				}
#endif
			}
			if (wf->direct_output) {
#if defined(LEVEL1)
				if (wf->response && (wf->tasks_num == 1)) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reply with the JSON Response related to single task\n", ttype, jobid);
					free(wf->response);	// Clear level-1 JSON Response
					if (my_output_json)
						wf->response = strdup(my_output_json);
					else if (output_json)
						wf->response = strdup(output_json);
				}
#elif defined(LEVEL2)
				if (wf->response) {
					oph_workflow_load_aggregate_response(wf, 2);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reply with a level-2 JSON Response:\n%s\n", ttype, jobid, wf->response);
				}
#elif defined(LEVEL3)
				if (wf->response) {
					oph_workflow_load_aggregate_response(wf, 3);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reply with a level-3 JSON Response:\n%s\n", ttype, jobid, wf->response);
				}
#else
				if (wf->response && !wf->author) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reply with the JSON Response related to single task\n", ttype, jobid);
					free(wf->response);	// Clear level-1 JSON Response
					if (my_output_json)
						wf->response = strdup(my_output_json);
					else if (output_json)
						wf->response = strdup(output_json);
				}
#endif
			}
#endif
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: sending termination signal for workflow '%s'\n", ttype, jobid, wf->name);
			pthread_cond_broadcast(&termination_flag);
			pthread_mutex_unlock(&global_flag);
		} else {
			if (oph_status_log_file_name) {
				oph_job_info *item = (oph_job_info *) malloc(sizeof(oph_job_info));
				item->wf = wf;
				pthread_mutex_lock(&global_flag);
				oph_save_job_in_job_list(state->job_info, item);
				pthread_mutex_unlock(&global_flag);
			} else
				oph_workflow_free(wf);
		}

		if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
			pthread_mutex_lock(&service_flag);
#endif
			service_info->closed_workflows++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
			pthread_mutex_unlock(&service_flag);
#endif
		}
	}

	if (my_output_json)
		free(my_output_json);

	while (1)		// Find a new workflow to be executed in workflow queue
	{
		pthread_mutex_lock(&global_flag);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: look for a queued workflow\n", ttype, jobid);
		oph_job_info *next_item = oph_find_unstarted_in_job_list(state->job_info);
		if (next_item)
			next_item->wf->status = OPH_ODB_STATUS_PENDING;	// Change the status before releasing the lock
		pthread_mutex_unlock(&global_flag);
		if (next_item)	// else the workflow has been queued
		{
			wf = next_item->wf;
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: found '%s' in queue: starting its execution\n", ttype, jobid, wf->name);

			if (!connection_up) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: a re-connection to OphidiaDB is needed!\n", ttype, jobid);
				oph_odb_initialize_ophidiadb(&oDB);
				if (oph_odb_read_config_ophidiadb(&oDB)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to read OphidiaDB configuration\n", ttype, jobid);
					oph_wf_list_drop(state->job_info, wf->idjob);
					continue;
				}
				if (oph_odb_connect_to_ophidiadb(&oDB)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to connect to OphidiaDB. Check access parameters.\n", ttype, jobid);
					oph_wf_list_drop(state->job_info, wf->idjob);
					continue;
				}
				connection_up = 1;
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: CONNECTED to OphidiaDB\n", ttype, jobid);
			}
			// Initialize the workflow
			int *initial_tasks_indexes = NULL, initial_tasks_indexes_num = 0;
			if (oph_workflow_init(wf->tasks, wf->tasks_num, &initial_tasks_indexes, &initial_tasks_indexes_num)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: initial tasks of workflow '%s' cannot be initialized\n", ttype, jobid, wf->name);
				oph_wf_list_drop(state->job_info, wf->idjob);
				free(initial_tasks_indexes);
				continue;
			}
			// Execute the workflow
			char *jobid_response = NULL;
			if (oph_workflow_execute(state, ttype, jobid, wf, initial_tasks_indexes, initial_tasks_indexes_num, &oDB, &jobid_response)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "%c%d: workflow '%s' cannot be executed\n", ttype, jobid, wf->name);
				oph_wf_list_drop(state->job_info, wf->idjob);
				free(initial_tasks_indexes);
				continue;
			}
			free(initial_tasks_indexes);
			if (jobid_response)
				free(jobid_response);
		} else
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: no queued workflow found\n", ttype, jobid);
		break;
	}
	if (connection_up) {
		oph_odb_disconnect_from_ophidiadb(&oDB);
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d: DISCONNECTED from OphidiaDB\n", ttype, jobid);
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c%d has been processed\n", ttype, jobid);
	return SOAP_OK;
}

#define BASIC_JSON_STRING "\
{\
  \"name\":\"%s\",\
  \"author\":\"Ophidia Server\",\
  \"abstract\":\"This workflow is automatically generated by Ophidia Server.\",\
  %s\
  \"tasks\":[\
           {\
               \"name\":\"%s\",\
               \"operator\":\"%s\"\
               %s\
           }\
          ]\
}"

// Thread safe
int oph_workflow_command_to_json(const char *command, char **json)
{
	if (!command || !json) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	*json = NULL;

	int s;
	unsigned int i, counter = 0;
	oph_argument *args = NULL, *item;

	if (oph_parse_query(&args, &counter, command)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error in parsing the command '%s'\n", command);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	char tmp[OPH_MAX_STRING_SIZE], header[OPH_MAX_PROGRAM_SIZE], arguments[OPH_MAX_PROGRAM_SIZE];
	*header = *arguments = 0;
	char *operator = NULL;

	for (i = 0, item = args; i < counter; ++i, item = item->next) {
		if (!item) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error in parsing the command\n");
			oph_cleanup_args(&args);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}

		if (!strncmp(item->key, OPH_ARG_OPERATOR, OPH_MAX_STRING_SIZE))
			operator = item->value;
		else if (!strncmp(item->key, OPH_ARG_NCORES, OPH_MAX_STRING_SIZE)) {
			snprintf(tmp, OPH_MAX_STRING_SIZE, "\"%s\":\"%s\",", OPH_ARG_NCORES, item->value);
			if ((s = OPH_MAX_PROGRAM_SIZE - strlen(header)) > 1)
				strncat(header, tmp, s);
		} else if (!strncmp(item->key, OPH_ARG_MODE, OPH_MAX_STRING_SIZE)) {
			snprintf(tmp, OPH_MAX_STRING_SIZE, "\"%s\":\"%s\",", OPH_ARG_MODE, item->value);
			if ((s = OPH_MAX_PROGRAM_SIZE - strlen(header)) > 1)
				strncat(header, tmp, s);
		} else if (!strncmp(item->key, OPH_ARG_SESSIONID, OPH_MAX_STRING_SIZE)) {
			snprintf(tmp, OPH_MAX_STRING_SIZE, "\"%s\":\"%s\",", OPH_ARG_SESSIONID, item->value);
			if ((s = OPH_MAX_PROGRAM_SIZE - strlen(header)) > 1)
				strncat(header, tmp, s);
		} else if (!strncmp(item->key, OPH_ARG_CALLBACK_URL, OPH_MAX_STRING_SIZE)) {
			snprintf(tmp, OPH_MAX_STRING_SIZE, "\"%s\":\"%s\",", OPH_ARG_CALLBACK_URL, item->value);
			if ((s = OPH_MAX_PROGRAM_SIZE - strlen(header)) > 1)
				strncat(header, tmp, s);
		} else {
			if (!(*arguments))
				snprintf(arguments, OPH_MAX_PROGRAM_SIZE, ",\"arguments\":[\"%s=%s\"", item->key, item->value);
			else {
				snprintf(tmp, OPH_MAX_STRING_SIZE, ",\"%s=%s\"", item->key, item->value);
				if ((s = OPH_MAX_PROGRAM_SIZE - strlen(arguments)) > 1)
					strncat(arguments, tmp, s);
			}
		}
	}
	if (!operator) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Unable to detect the operator name\n");
		oph_cleanup_args(&args);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	if (*arguments && ((s = OPH_MAX_PROGRAM_SIZE - strlen(arguments)) > 1))
		strncat(arguments, "]", s);

	char _json[OPH_MAX_PROGRAM_SIZE];
	snprintf(_json, OPH_MAX_PROGRAM_SIZE, BASIC_JSON_STRING, operator, header, operator, operator, arguments);
	oph_cleanup_args(&args);

	*json = strdup(_json);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

void *_oph_workflow_check_job_queue(oph_monitor_data * data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif

	if (data) {
		int i, j, jobid, *list = NULL, response;
		unsigned int k, n, nn = 0;
		oph_job_list *job_list = data->state->job_info;
		oph_job_info *temp;
		char submission_string_ext[OPH_MAX_STRING_SIZE], *error_notification[OPH_SERVER_POLL_ITEMS], **username = NULL;

		for (k = 0; k < OPH_SERVER_POLL_ITEMS; ++k)
			error_notification[k] = NULL;

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Start polling time for aborted or starved tasks (%d seconds)\n", data->poll_time);

		while (oph_server_is_running) {
			if (list) {
				free(list);
				list = NULL;
			}
			for (k = 0; k < nn; ++k)
				if (error_notification[k]) {
					free(error_notification[k]);
					error_notification[k] = NULL;
				}
			n = nn = 0;

			// Wait for next check
			for (k = 0; k < data->poll_time; ++k) {
				sleep(1);
				if (!oph_server_is_running)
					break;
			}
			if (!oph_server_is_running)
				break;

			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Check for aborted or starved tasks\n");

			// Load task list in resource manager queue
			if (oph_read_job_queue(&list, &username, &n))
				continue;

			pthread_mutex_lock(&global_flag);

			// Flush expired tasks
			if (oph_find_marker_in_job_list(job_list, NULL, -1, NULL, NULL))
				pmesg(LOG_WARNING, __FILE__, __LINE__, "Found a task with markerid set to -1!\n");

			// Look for tasks aborted without sending error notification
			for (temp = job_list->head; temp; temp = temp->next)
				if (temp->wf) {
					for (i = 0; i <= temp->wf->tasks_num; ++i)
						if (temp->wf->tasks[i].name && (temp->wf->tasks[i].status > (int) OPH_ODB_STATUS_PENDING)
						    && (temp->wf->tasks[i].status < (int) OPH_ODB_STATUS_COMPLETED) && !temp->wf->tasks[i].is_known) {
							if (temp->wf->tasks[i].light_tasks_num) {
								for (j = 0; j < temp->wf->tasks[i].light_tasks_num; ++j)
									if ((temp->wf->tasks[i].light_tasks[j].status > (int) OPH_ODB_STATUS_PENDING)
									    && (temp->wf->tasks[i].light_tasks[j].status < (int) OPH_ODB_STATUS_COMPLETED)) {
										for (k = 0; k < n; ++k)
											if (temp->wf->tasks[i].light_tasks[j].idjob == list[k]) {
												list[k] = 0;
												break;
											}
										if (k >= n) {
											if (temp->wf->tasks[i].light_tasks[j].is_marked_to_be_aborted) {
												snprintf(submission_string_ext, OPH_MAX_STRING_SIZE, OPH_WORKFLOW_BASE_NOTIFICATION, temp->wf->idjob, i,
													 j, temp->wf->tasks[i].light_tasks[j].idjob, OPH_ODB_STATUS_ABORTED, temp->wf->sessionid,
													 temp->wf->tasks[i].light_tasks[j].markerid,
													 temp->wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
												error_notification[nn++] = strdup(submission_string_ext);
												if (nn >= OPH_SERVER_POLL_ITEMS)
													break;
											} else
												temp->wf->tasks[i].light_tasks[j].is_marked_to_be_aborted = 1;
										}
									}
								if (nn >= OPH_SERVER_POLL_ITEMS)
									break;
							} else {
								for (k = 0; k < n; ++k)
									if (temp->wf->tasks[i].idjob == list[k]) {
										list[k] = 0;
										break;
									}
								if (k >= n) {
									if (temp->wf->tasks[i].is_marked_to_be_aborted) {
										snprintf(submission_string_ext, OPH_MAX_STRING_SIZE, OPH_WORKFLOW_BASE_NOTIFICATION, temp->wf->idjob, i, -1,
											 temp->wf->tasks[i].idjob, OPH_ODB_STATUS_ABORTED, temp->wf->sessionid, temp->wf->tasks[i].markerid,
											 temp->wf->tasks[i].save ? OPH_COMMON_YES : OPH_COMMON_NO);
										error_notification[nn++] = strdup(submission_string_ext);
										if (nn >= OPH_SERVER_POLL_ITEMS)
											break;
									} else
										temp->wf->tasks[i].is_marked_to_be_aborted = 1;
								}
							}
						}
					if (nn >= OPH_SERVER_POLL_ITEMS)
						break;
				}

			if (nn >= OPH_SERVER_POLL_ITEMS)
				nn = OPH_SERVER_POLL_ITEMS;

			// Look for starved tasks
			for (temp = job_list->head; temp; temp = temp->next)
				if (temp->wf) {
					for (i = 0; i <= temp->wf->tasks_num; ++i)
						if (temp->wf->tasks[i].name && (temp->wf->tasks[i].status >= (int) OPH_ODB_STATUS_COMPLETED)) {
							if (temp->wf->tasks[i].light_tasks_num) {
								for (j = 0; j < temp->wf->tasks[i].light_tasks_num; ++j)
									if (temp->wf->tasks[i].light_tasks[j].status >= (int) OPH_ODB_STATUS_COMPLETED) {
										for (k = 0; k < n; ++k)
											if (temp->wf->tasks[i].light_tasks[j].idjob == list[k]) {
												list[k] = -list[k];
												break;
											}
									}
							} else {
								for (k = 0; k < n; ++k)
									if (temp->wf->tasks[i].idjob == list[k]) {
										list[k] = -list[k];
										break;
									}
							}
						}
				}
			for (k = 0; k < n; ++k)
				if (list[k] > 0) {
					for (temp = job_list->head; temp; temp = temp->next)
						if (temp->wf) {
							for (i = 0; i <= temp->wf->tasks_num; ++i)
								if (temp->wf->tasks[i].name) {
									if (temp->wf->tasks[i].light_tasks_num) {
										for (j = 0; j < temp->wf->tasks[i].light_tasks_num; ++j)
											if (temp->wf->tasks[i].light_tasks[j].idjob == list[k])
												break;
										if (j < temp->wf->tasks[i].light_tasks_num)
											break;
									} else if (temp->wf->tasks[i].idjob == list[k])
										break;
								}
							if (i <= temp->wf->tasks_num)
								break;
						}
					if (!temp)
						list[k] = -list[k];
				}

			pthread_mutex_unlock(&global_flag);

			for (k = 0; k < nn; ++k)
				if (error_notification[k]) {
					pthread_mutex_lock(&global_flag);
					jobid = ++*data->state->jobid;
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "M%d: a task has been aborted before sending error notification\n", jobid);
					pthread_mutex_unlock(&global_flag);

					response = 0;
					oph_workflow_notify(data->state, 'M', jobid, error_notification[k], NULL, &response);
					if (response)
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "M%d: error %d in notify\n", jobid, response);
					free(error_notification[k]);
					error_notification[k] = NULL;
				}
			// Kill starved tasks
			for (k = 0; k < n; ++k)
				if ((list[k] < 0) && !oph_is_detached_task(-list[k]))
					oph_cancel_request(-list[k], username[k] ? username[k] : NULL);
		}

		if (list)
			free(list);
		if (username) {
			for (k = 0; k < n; ++k)
				if (username[k])
					free(username[k]);
			free(username);
		}
		for (k = 0; k < nn; ++k)
			if (error_notification[k])
				free(error_notification[k]);
		if (data->state)
			free(data->state);
		free(data);
	}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif
	return (void *) NULL;
}

int oph_workflow_check_job_queue(struct oph_plugin_data *state)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	int poll_time = 0;

	pthread_mutex_lock(&global_flag);
	poll_time = oph_server_poll_time;
	oph_server_poll_time = 0;
	pthread_mutex_unlock(&global_flag);

	if (!poll_time)
		return OPH_WORKFLOW_EXIT_SUCCESS;

	if (!state)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	oph_monitor_data *data = (oph_monitor_data *) malloc(sizeof(oph_monitor_data));
	if (!data)
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	data->state = (struct oph_plugin_data *) malloc(sizeof(struct oph_plugin_data));
	if (!data->state) {
		free(data);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	memcpy(data->state, (struct oph_plugin_data *) state, sizeof(struct oph_plugin_data));
	data->state->serverid = NULL;
	data->state->is_copy = 1;
	data->state->job_info = state->job_info;

	data->poll_time = poll_time;

	pthread_t tid;
	pthread_create(&tid, NULL, (void *(*)(void *)) &_oph_workflow_check_job_queue, data);
#endif
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_create_hp(oph_workflow * wf, ophidiadb * oDB)
{
	if (!wf || !oDB)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	if (!wf->host_partition || !strlen(wf->host_partition))
		return OPH_WORKFLOW_EXIT_SUCCESS;

	int id_user = 0;
	if (oph_odb_retrieve_user_id(oDB, wf->username, &id_user))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	char pname[OPH_SHORT_STRING_SIZE];
	snprintf(pname, OPH_SHORT_STRING_SIZE, "_%d", wf->idjob);

	if (oph_odb_create_hp(oDB, pname, wf->host_partition, id_user))
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;

	if (wf->host_partition_orig)
		free(wf->host_partition_orig);
	wf->host_partition_orig = wf->host_partition;
	wf->host_partition = strdup(pname);
	if (!wf->host_partition)
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_destroy_hp(oph_workflow * wf, ophidiadb * oDB)
{
	if (!wf || !oDB)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	if (!wf->host_partition || !strlen(wf->host_partition))
		return OPH_WORKFLOW_EXIT_SUCCESS;

	if (oph_odb_destroy_hp(oDB, wf->host_partition))
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_get_progress_ratio_of(oph_workflow * wf, double *wpr, char **cdate)
{
	if (!wf || !wpr) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	*wpr = 0.0;
	if (cdate)
		*cdate = NULL;

	char query[OPH_MAX_STRING_SIZE];
	snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_PROGRESS_RATIO_OF_WORKFLOW, wf->sessionid, wf->workflowid, wf->sessionid, wf->workflowid);

	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (oph_odb_read_config_ophidiadb(&oDB)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration.\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	if (oph_odb_connect_to_ophidiadb(&oDB)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}

	ophidiadb_list list;
	oph_odb_initialize_ophidiadb_list(&list);

	if (oph_odb_retrieve_list(&oDB, query, &list)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract job information using '%s'.\n", query);
		oph_odb_free_ophidiadb_list(&list);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
#ifndef OPH_DB_SUPPORT
	oph_load_datacube_status(list.id, list.wid, list.pid, list.size, wf->idjob);
#endif

	int i, j, k, n = 0, try_in_list = list.size, nfound;
	for (i = 0; i <= wf->tasks_num; ++i)
		if (wf->tasks[i].name) {
			n++;
			if (wf->tasks[i].light_tasks_num) {
				for (j = 0; j < wf->tasks[i].light_tasks_num; ++j) {
					nfound = 1;
					if (try_in_list) {
						for (k = 0; k < list.size; ++k)
							if (list.id[k] && (list.id[k] == wf->tasks[i].light_tasks[j].idjob)) {
								if (list.wid[k])
									*wpr += (double) list.pid[k] / (double) (list.wid[k] * wf->tasks[i].light_tasks_num);	// Lesser weight for light tasks
								list.id[k] = nfound = 0;
								try_in_list--;
								break;
							}
					}
					if (nfound && (wf->tasks[i].light_tasks[j].status >= (int) OPH_ODB_STATUS_COMPLETED))
						*wpr += 1.0 / wf->tasks[i].light_tasks_num;	// Lesser weight for light tasks
				}
			} else {
				nfound = 1;
				if (try_in_list) {
					for (k = 0; k < list.size; ++k)
						if (list.id[k] && (list.id[k] == wf->tasks[i].idjob)) {
							if (list.wid[k])
								*wpr += (double) list.pid[k] / (double) list.wid[k];
							list.id[k] = nfound = 0;
							try_in_list--;
							break;
						}
				}
				if (nfound && (wf->tasks[i].status >= (int) OPH_ODB_STATUS_COMPLETED))
					++ * wpr;
			}
		}
	*wpr /= n;
	oph_odb_free_ophidiadb_list(&list);
	if (cdate) {

		snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_CREATION_DATE_OF_WORKFLOW, wf->sessionid, wf->workflowid, wf->sessionid, wf->workflowid);

		oph_odb_initialize_ophidiadb_list(&list);

		if (oph_odb_retrieve_list(&oDB, query, &list)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract job information using '%s'.\n", query);
			oph_odb_free_ophidiadb_list(&list);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}

		if (!list.size || (list.size > 1)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract creation date of workflow '%s'.\n", wf->name);
			oph_odb_free_ophidiadb_list(&list);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}

		*cdate = strdup(list.ctime[0]);
		if (!*cdate) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to allocate memory for creation date of workflow '%s'.\n", wf->name);
			oph_odb_free_ophidiadb_list(&list);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}

		oph_odb_free_ophidiadb_list(&list);
	}

	oph_odb_disconnect_from_ophidiadb(&oDB);
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_get_info_of(char *sessionid, int workflowid, char **status, char **cdate)
{
	if (!sessionid || !workflowid || !status || !cdate) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	*status = 0;
	*cdate = NULL;

	char query[OPH_MAX_STRING_SIZE];
	snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_CREATION_DATE_OF_WORKFLOW, sessionid, workflowid, sessionid, workflowid);

	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (oph_odb_read_config_ophidiadb(&oDB)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration.\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	if (oph_odb_connect_to_ophidiadb(&oDB)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}

	ophidiadb_list list;
	oph_odb_initialize_ophidiadb_list(&list);

	if (oph_odb_retrieve_list(&oDB, query, &list)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract job information using '%s'.\n", query);
		oph_odb_free_ophidiadb_list(&list);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}

	if (!list.size || (list.size > 1)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract creation date of workflow '%s#%d'.\n", sessionid, workflowid);
		oph_odb_free_ophidiadb_list(&list);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}

	*status = strdup(list.name[0]);
	if (!*status) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to allocate memory for creation date of workflow '%s#%d'.\n", sessionid, workflowid);
		oph_odb_free_ophidiadb_list(&list);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	*cdate = strdup(list.ctime[0]);
	if (!*cdate) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to allocate memory for creation date of workflow '%s#%d'.\n", sessionid, workflowid);
		oph_odb_free_ophidiadb_list(&list);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	oph_odb_free_ophidiadb_list(&list);
	oph_odb_disconnect_from_ophidiadb(&oDB);
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_add_to_list(char *key, char *object, oph_workflow_ordered_list ** list)
{
	if (!key || !object || !list)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	oph_workflow_ordered_list *t, *c = *list, *p = NULL;

	t = (oph_workflow_ordered_list *) malloc(sizeof(oph_workflow_ordered_list));
	t->key = strdup(key);
	t->object = strdup(object);

	while (c) {
		if (!c->key || (strcmp(c->key, key) > 0))
			break;
		p = c;
		c = c->next;
	}

	t->next = c;
	if (p)
		p->next = t;
	else
		*list = t;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_print_list(oph_workflow_ordered_list * list, char **string)
{
	if (!list || !string)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	int r = 0;
	char *tmp;
	while (list) {
		if (*string) {
			tmp = NULL;
			r = asprintf(&tmp, "%s%s%s", *string, OPH_SEPARATOR_SUBPARAM_STR, list->object);
			free(*string);
		} else if (!(tmp = strdup(list->object)))
			r = -1;
		*string = tmp;
		if (r < 0)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		list = list->next;
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}
