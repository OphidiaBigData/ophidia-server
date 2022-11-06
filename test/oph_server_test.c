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

#include "oph.nsmap"

#include "oph_flow_control_operators.h"
#include "oph_workflow_engine.h"
#include "oph_rmanager.h"
#include "oph_task_parser_library.h"
#include "oph_plugin.h"
#include "oph_memory_job.h"
#include "oph_filters.h"
#include "oph_service_info.h"

#include <unistd.h>
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <threads.h>
#include <pthread.h>
#endif
#include <signal.h>

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_mutex_t global_flag;
pthread_mutex_t libssh2_flag;
pthread_mutex_t curl_flag;
pthread_mutex_t service_flag;
pthread_mutex_t savefile_flag;
pthread_cond_t termination_flag;
pthread_cond_t waiting_flag;
#ifdef OPH_OPENID_SUPPORT
pthread_t token_tid_openid = 0;
#endif
#ifdef OPH_AAA_SUPPORT
pthread_t token_tid_aaa = 0;
#endif
#endif

char *oph_server_location = 0;
HASHTBL *oph_server_params = 0;
char *oph_server_protocol = 0;
char *oph_server_host = 0;
char *oph_server_port = 0;
int oph_server_timeout = OPH_SERVER_TIMEOUT;
int oph_server_workflow_timeout = OPH_SERVER_WORKFLOW_TIMEOUT;
FILE *wf_logfile = 0;
FILE *task_logfile = 0;
char *oph_log_file_name = 0;
char *oph_status_log_file_name = 0;
char *oph_rmanager_conf_file = 0;
char *oph_json_location = 0;
char *oph_auth_location = 0;
char *oph_web_server = 0;
char *oph_web_server_location = 0;
char *oph_txt_location = 0;
char *oph_operator_client = 0;
char *oph_ip_target_host = 0;
char oph_subm_ssh = 0;
char *oph_subm_user = 0;
char *oph_subm_user_publk = 0;
char *oph_subm_user_privk = 0;
char *oph_xml_operator_dir = 0;
unsigned int oph_server_farm_size = 0;
unsigned int oph_server_queue_size = 0;
unsigned int oph_auto_retry = 0;
unsigned int oph_server_poll_time = OPH_SERVER_POLL_TIME;
oph_rmanager *orm = 0;
ophidiadb *ophDB = 0;
char oph_server_is_running = 1;
char *oph_base_src_path = 0;
unsigned int oph_base_backoff = 0;
oph_service_info *service_info = NULL;
unsigned int oph_default_max_sessions = OPH_DEFAULT_USER_MAX_SESSIONS;
unsigned int oph_default_max_cores = OPH_DEFAULT_USER_MAX_CORES;
unsigned int oph_default_max_hosts = OPH_DEFAULT_USER_MAX_HOSTS;
unsigned int oph_default_session_timeout = OPH_DEFAULT_SESSION_TIMEOUT;
char oph_cluster_deployment;
char oph_cancel_all_enabled = 0;
#ifdef OPH_DIRECT_OUTPUT
char oph_direct_output = 1;
#else
char oph_direct_output = 0;
#endif
#ifdef OPH_OPENID_SUPPORT
char *oph_openid_endpoint = 0;
char *oph_openid_client_id = 0;
char *oph_openid_client_secret = 0;
unsigned int oph_openid_token_timeout = OPH_SERVER_TIMEOUT;
unsigned int oph_openid_token_check_time = 0;
char *oph_openid_user_name = 0;
char oph_openid_allow_local_user = 0;
#endif
#ifdef OPH_AAA_SUPPORT
char *oph_aaa_endpoint = 0;
char *oph_aaa_category = 0;
char *oph_aaa_name = 0;
unsigned int oph_aaa_token_check_time = 0;
#endif

void set_global_values(const char *configuration_file)
{
	if (!configuration_file)
		return;
	pmesg(LOG_INFO, __FILE__, __LINE__, "Loading configuration from '%s'\n", configuration_file);

	oph_server_params = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
	if (!oph_server_params)
		return;

	char tmp[OPH_MAX_STRING_SIZE];
	char *value;
	FILE *file = fopen(configuration_file, "r");
	if (file) {
		char key[OPH_MAX_STRING_SIZE];
		while (fgets(tmp, OPH_MAX_STRING_SIZE, file)) {
			if (strlen(tmp)) {
				tmp[strlen(tmp) - 1] = '\0';
				value = strchr(tmp, OPH_SEPARATOR_KV[0]);
				if (value) {
					value++;
					snprintf(key, value - tmp, "%s", tmp);
					if (value[0])
						hashtbl_insert(oph_server_params, key, value);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Read %s=%s\n", key, value);
				}
			}
		}
		fclose(file);
	}
	oph_auth_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR);
	oph_web_server = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER);
	oph_web_server_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER_LOCATION);
	oph_xml_operator_dir = hashtbl_get(oph_server_params, OPH_SERVER_CONF_XML_DIR);

	oph_json_location = oph_web_server_location;	// Position of JSON Response will be the same of web server
}

void cleanup()
{
	if (oph_server_params)
		hashtbl_destroy(oph_server_params);
#ifdef OPH_SERVER_LOCATION
	if (oph_server_location)
		free(oph_server_location);
#endif
	if (oph_base_src_path)
		free(oph_base_src_path);
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_destroy(&global_flag);
	pthread_mutex_destroy(&libssh2_flag);
	pthread_mutex_destroy(&curl_flag);
	pthread_mutex_destroy(&service_flag);
	pthread_mutex_destroy(&savefile_flag);
	pthread_cond_destroy(&termination_flag);
	pthread_cond_destroy(&waiting_flag);
#endif
	oph_tp_end_xml_parser();
}

int _check_oph_server(const char *function, int option)
{
	char sessionid[OPH_MAX_STRING_SIZE];
	snprintf(sessionid, OPH_MAX_STRING_SIZE, "%s/sessions/123/experiment", oph_web_server);

	void *var_buffer;
	size_t var_size = sizeof(oph_workflow_var), svalue_size;

	// Workflow
	oph_workflow *wf = (oph_workflow *) calloc(1, sizeof(oph_workflow));
	if (!wf)
		return 1;

	// HEADER
	wf->idjob = 1;
	wf->workflowid = 1;
	wf->markerid = 1;
	wf->status = OPH_ODB_STATUS_RUNNING;
	wf->username = strdup("oph-test");
	wf->os_username = strdup("oph-test");
	wf->userrole = 31;
	wf->name = strdup("test");
	wf->author = strdup("test");
	wf->abstract = strdup("-");
	wf->sessionid = strdup(sessionid);
	wf->exec_mode = strdup("sync");
	wf->ncores = 1;
	wf->cwd = strdup("/");
	wf->run = 1;
	wf->parallel_mode = 0;

	if (!strcmp(function, "oph_if_impl")) {
		char condition[OPH_MAX_STRING_SIZE];
		sprintf(condition, "1");

		switch (option) {
			case 0:
				{
					*condition = 0;
				}
				break;

			case 2:
			case 11:
				{
					sprintf(condition, "0");
				}
				break;

			case 5:
				{
					sprintf(condition, "0/0");
				}
				break;

			case 6:
				{
					sprintf(condition, "1/0");
				}
				break;

			case 9:
				{
					sprintf(condition, "x");
				}
				break;

			case 10:
				{
					sprintf(condition, "---");
				}
				break;

			default:;
		}

		// Tasks
		wf->tasks_num = 5;
		wf->residual_tasks_num = 5;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// IF
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("IF");
		wf->tasks[0].operator = strdup("oph_if");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 1;
		wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_keys[0] = strdup("condition");
		wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_values[0] = strdup(condition);
		wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 2;
		wf->tasks[0].dependents_indexes = (int *) calloc(wf->tasks[0].dependents_indexes_num, sizeof(int));
		wf->tasks[0].dependents_indexes[0] = 1;
		wf->tasks[0].dependents_indexes[1] = 2;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		// Operator for true
		wf->tasks[1].idjob = wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[1].name = strdup("Operator for true");
		wf->tasks[1].operator = strdup("oph_operator");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 0;
		wf->tasks[1].arguments_keys = NULL;
		wf->tasks[1].arguments_values = NULL;
		wf->tasks[1].arguments_lists = NULL;
		wf->tasks[1].deps_num = 1;
		wf->tasks[1].deps = (oph_workflow_dep *) calloc(wf->tasks[1].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[1].deps[0].task_name = strdup("IF");
		wf->tasks[1].deps[0].task_index = 0;
		wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int *) calloc(wf->tasks[1].dependents_indexes_num, sizeof(int));
		wf->tasks[1].dependents_indexes[0] = 4;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// ELSE
		wf->tasks[2].idjob = wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[2].name = strdup("ELSE");
		wf->tasks[2].operator = strdup("oph_else");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].arguments_lists = NULL;
		wf->tasks[2].deps_num = 1;
		wf->tasks[2].deps = (oph_workflow_dep *) calloc(wf->tasks[2].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[2].deps[0].task_name = strdup("IF");
		wf->tasks[2].deps[0].task_index = 0;
		wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 1;
		wf->tasks[2].dependents_indexes = (int *) calloc(wf->tasks[2].dependents_indexes_num, sizeof(int));
		wf->tasks[2].dependents_indexes[0] = 3;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = 0;

		// Operator for false
		wf->tasks[3].idjob = wf->tasks[3].markerid = 5;
		wf->tasks[3].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[3].name = strdup("Operator for false");
		wf->tasks[3].operator = strdup("oph_operator");
		wf->tasks[3].role = oph_code_role("read");
		wf->tasks[3].ncores = wf->ncores;
		wf->tasks[3].arguments_num = 0;
		wf->tasks[3].arguments_keys = NULL;
		wf->tasks[3].arguments_values = NULL;
		wf->tasks[3].arguments_lists = NULL;
		wf->tasks[3].deps_num = 1;
		wf->tasks[3].deps = (oph_workflow_dep *) calloc(wf->tasks[3].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[3].deps[0].task_name = strdup("ELSE");
		wf->tasks[3].deps[0].task_index = 2;
		wf->tasks[3].deps[0].type = strdup("embedded");
		wf->tasks[3].dependents_indexes_num = 1;
		wf->tasks[3].dependents_indexes = (int *) calloc(wf->tasks[3].dependents_indexes_num, sizeof(int));
		wf->tasks[3].dependents_indexes[0] = 4;
		wf->tasks[3].run = 1;
		wf->tasks[3].parent = -1;

		// ENDIF
		wf->tasks[4].idjob = wf->tasks[4].markerid = 6;
		wf->tasks[4].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[4].name = strdup("ENDIF");
		wf->tasks[4].operator = strdup("oph_endif");
		wf->tasks[4].role = oph_code_role("read");
		wf->tasks[4].ncores = wf->ncores;
		wf->tasks[4].arguments_num = 0;
		wf->tasks[4].arguments_keys = NULL;
		wf->tasks[4].arguments_values = NULL;
		wf->tasks[4].arguments_lists = NULL;
		wf->tasks[4].deps_num = 2;
		wf->tasks[4].deps = (oph_workflow_dep *) calloc(wf->tasks[4].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[4].deps[0].task_name = strdup("Operator for true");
		wf->tasks[4].deps[0].task_index = 1;
		wf->tasks[4].deps[0].type = strdup("embedded");
		wf->tasks[4].deps[1].task_name = strdup("Operator for false");
		wf->tasks[4].deps[1].task_index = 3;
		wf->tasks[4].deps[1].type = strdup("embedded");
		wf->tasks[4].dependents_indexes_num = 0;
		wf->tasks[4].dependents_indexes = NULL;
		wf->tasks[4].run = 1;
		wf->tasks[4].parent = 0;
		wf->tasks[4].branch_num = 2;

		char error_message[OPH_MAX_STRING_SIZE];
		int exit_output;
		*error_message = 0;

		switch (option) {
			case 3:
				{
					wf->tasks[0].is_skipped = 1;	// in case of oph_elseif
				}
				break;

			case 4:
				{
					free(wf->tasks[0].arguments_keys[0]);
					free(wf->tasks[0].arguments_keys);
					free(wf->tasks[0].arguments_values[0]);
					free(wf->tasks[0].arguments_values);
					free(wf->tasks[0].arguments_lists);
					wf->tasks[0].arguments_num = 0;
					wf->tasks[0].arguments_keys = NULL;
					wf->tasks[0].arguments_values = NULL;
					wf->tasks[0].arguments_lists = NULL;
				}
				break;

			case 7:
				{
					oph_workflow_var var;
					var.caller = -1;
					var.ivalue = 1;
					var.svalue = strdup("234-234");
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, "condition", var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("@condition");
				}
				break;

			case 8:
				{
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("@condition");
				}
				break;

			case 11:
				{
					// ELSE
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					if (wf->tasks[2].deps) {
						if (wf->tasks[2].deps[0].task_name)
							free(wf->tasks[2].deps[0].task_name);
						if (wf->tasks[2].deps[0].type)
							free(wf->tasks[2].deps[0].type);
						free(wf->tasks[2].deps);
					}
					wf->tasks[2].deps_num = 0;
					wf->tasks[2].deps = NULL;

					// Operator for false
					wf->tasks[3].status = OPH_ODB_STATUS_COMPLETED;
					if (wf->tasks[3].dependents_indexes);
					free(wf->tasks[3].dependents_indexes);
					wf->tasks[3].dependents_indexes_num = 1;
					wf->tasks[3].dependents_indexes = NULL;

					// ENDIF
					if (wf->tasks[4].deps) {
						if (wf->tasks[4].deps[0].task_name);
						free(wf->tasks[4].deps[0].task_name);
						if (wf->tasks[4].deps[0].type)
							free(wf->tasks[4].deps[0].type);
						if (wf->tasks[4].deps[1].task_name);
						free(wf->tasks[4].deps[1].task_name);
						if (wf->tasks[4].deps[1].type)
							free(wf->tasks[4].deps[1].type);
						free(wf->tasks[4].deps);
					}
					wf->tasks[4].deps_num = 1;
					wf->tasks[4].deps = (oph_workflow_dep *) calloc(wf->tasks[4].deps_num, sizeof(oph_workflow_dep));
					wf->tasks[4].deps[0].task_name = strdup("Operator for true");
					wf->tasks[4].deps[0].task_index = 1;
					wf->tasks[4].deps[0].type = strdup("embedded");
					wf->tasks[4].branch_num = 1;
				}
				break;

			default:;
		}

		int res = oph_if_impl(wf, 0, error_message, &exit_output);

		switch (option) {
#ifdef MATHEVAL_SUPPORT
			case 5:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong condition '0/0'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 6:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong condition '1/0'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 9:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Too variables in the expression 'x'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
#endif
			case 8:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Too variables in the expression '@condition'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 10:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong expression '---'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			default:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
		}

		switch (option) {

#ifndef MATHEVAL_SUPPORT
			case 2:
			case 7:
#endif
			case 0:
			case 1:
				{
					if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
				}
				break;

#ifdef MATHEVAL_SUPPORT
			case 2:
			case 7:
				{
					if (wf->tasks[1].status != OPH_ODB_STATUS_UNSELECTED) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Task status is wrong: %s\n", oph_odb_convert_status_to_str(wf->tasks[1].status));
						goto _EXIT_3;
					}
					if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
					if ((wf->tasks[4].deps[0].task_index != 4) || (wf->tasks[4].deps[1].task_index != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Dependence data are wrong\n");
						goto _EXIT_3;
					}
				}
				break;

			case 3:
				{
					if (wf->tasks[1].status != OPH_ODB_STATUS_UNSELECTED) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Status flags are wrong\n");
						goto _EXIT_3;
					}
					if (!wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
					if ((wf->tasks[4].deps[0].task_index != 4) || (wf->tasks[4].deps[1].task_index != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Dependence data are wrong\n");
						goto _EXIT_3;
					}
				}
				break;
#else
			case 3:
				{
					if (!wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
				}
				break;
#endif

			case 4:
				{
					if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
				}
				break;

			default:;
		}
	} else if (!strcmp(function, "oph_else_impl")) {
		// Tasks
		wf->tasks_num = 5;
		wf->residual_tasks_num = 3;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// IF
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
		wf->tasks[0].name = strdup("IF");
		wf->tasks[0].operator = strdup("oph_if");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 1;
		wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_keys[0] = strdup("condition");
		wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_values[0] = strdup("0");
		wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 2;
		wf->tasks[0].dependents_indexes = (int *) calloc(wf->tasks[0].dependents_indexes_num, sizeof(int));
		wf->tasks[0].dependents_indexes[0] = 4;
		wf->tasks[0].dependents_indexes[1] = 2;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		// Operator for true
		wf->tasks[1].idjob = wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_UNSELECTED;
		wf->tasks[1].name = strdup("Operator for true");
		wf->tasks[1].operator = strdup("oph_operator");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 0;
		wf->tasks[1].arguments_keys = NULL;
		wf->tasks[1].arguments_values = NULL;
		wf->tasks[1].arguments_lists = NULL;
		wf->tasks[1].deps_num = 1;
		wf->tasks[1].deps = (oph_workflow_dep *) calloc(wf->tasks[1].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[1].deps[0].task_name = strdup("IF");
		wf->tasks[1].deps[0].task_index = 0;
		wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int *) calloc(wf->tasks[1].dependents_indexes_num, sizeof(int));
		wf->tasks[1].dependents_indexes[0] = 4;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// ELSE
		wf->tasks[2].idjob = wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[2].name = strdup("ELSE");
		wf->tasks[2].operator = strdup("oph_else");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].arguments_lists = NULL;
		wf->tasks[2].deps_num = 1;
		wf->tasks[2].deps = (oph_workflow_dep *) calloc(wf->tasks[2].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[2].deps[0].task_name = strdup("IF");
		wf->tasks[2].deps[0].task_index = 0;
		wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 1;
		wf->tasks[2].dependents_indexes = (int *) calloc(wf->tasks[2].dependents_indexes_num, sizeof(int));
		wf->tasks[2].dependents_indexes[0] = 3;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = 0;

		// Operator for false
		wf->tasks[3].idjob = wf->tasks[3].markerid = 5;
		wf->tasks[3].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[3].name = strdup("Operator for false");
		wf->tasks[3].operator = strdup("oph_operator");
		wf->tasks[3].role = oph_code_role("read");
		wf->tasks[3].ncores = wf->ncores;
		wf->tasks[3].arguments_num = 0;
		wf->tasks[3].arguments_keys = NULL;
		wf->tasks[3].arguments_values = NULL;
		wf->tasks[3].arguments_lists = NULL;
		wf->tasks[3].deps_num = 1;
		wf->tasks[3].deps = (oph_workflow_dep *) calloc(wf->tasks[3].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[3].deps[0].task_name = strdup("ELSE");
		wf->tasks[3].deps[0].task_index = 2;
		wf->tasks[3].deps[0].type = strdup("embedded");
		wf->tasks[3].dependents_indexes_num = 1;
		wf->tasks[3].dependents_indexes = (int *) calloc(wf->tasks[3].dependents_indexes_num, sizeof(int));
		wf->tasks[3].dependents_indexes[0] = 4;
		wf->tasks[3].run = 1;
		wf->tasks[3].parent = -1;

		// ENDIF
		wf->tasks[4].idjob = wf->tasks[4].markerid = 6;
		wf->tasks[4].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[4].name = strdup("ENDIF");
		wf->tasks[4].operator = strdup("oph_endif");
		wf->tasks[4].role = oph_code_role("read");
		wf->tasks[4].ncores = wf->ncores;
		wf->tasks[4].arguments_num = 0;
		wf->tasks[4].arguments_keys = NULL;
		wf->tasks[4].arguments_values = NULL;
		wf->tasks[4].arguments_lists = NULL;
		wf->tasks[4].deps_num = 2;
		wf->tasks[4].deps = (oph_workflow_dep *) calloc(wf->tasks[4].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[4].deps[0].task_name = strdup("Operator for true");
		wf->tasks[4].deps[0].task_index = 0;
		wf->tasks[4].deps[0].type = strdup("embedded");
		wf->tasks[4].deps[1].task_name = strdup("Operator for false");
		wf->tasks[4].deps[1].task_index = 3;
		wf->tasks[4].deps[1].type = strdup("embedded");
		wf->tasks[4].dependents_indexes_num = 0;
		wf->tasks[4].dependents_indexes = NULL;
		wf->tasks[4].run = 1;
		wf->tasks[4].parent = 0;
		wf->tasks[4].branch_num = 2;

		char error_message[OPH_MAX_STRING_SIZE];
		int exit_output;
		*error_message = 0;

		switch (option) {
			case 1:
				{
					wf->tasks[0].dependents_indexes[0] = 1;
					wf->tasks[0].dependents_indexes[1] = 4;
					wf->tasks[1].status = OPH_ODB_STATUS_PENDING;
					wf->tasks[2].is_skipped = 1;
					wf->tasks[4].deps[0].task_index = 1;
					wf->tasks[4].deps[1].task_index = 0;
				}
				break;

			default:;
		}

		int res = oph_else_impl(wf, 2, error_message, &exit_output);

		switch (option) {
			default:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
		}

		switch (option) {
			case 0:
				{
					if (wf->tasks[1].status != OPH_ODB_STATUS_UNSELECTED) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Status flags are wrong\n");
						goto _EXIT_3;
					}
					if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
					if ((wf->tasks[4].deps[0].task_index != 0) || (wf->tasks[4].deps[1].task_index != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Dependence data are wrong\n");
						goto _EXIT_3;
					}
				}
				break;

			case 1:
				{
					if ((wf->tasks[1].status == OPH_ODB_STATUS_UNSELECTED) || (wf->tasks[3].status != OPH_ODB_STATUS_UNSELECTED)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Status flags are wrong\n");
						goto _EXIT_3;
					}
					if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Skipping flags are wrong\n");
						goto _EXIT_3;
					}
					if ((wf->tasks[4].deps[0].task_index != 1) || (wf->tasks[4].deps[1].task_index != 0)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Dependence data are wrong\n");
						goto _EXIT_3;
					}
				}
				break;

			default:;
		}
	} else if (!strcmp(function, "oph_for_impl")) {
		// Tasks
		wf->tasks_num = 4;
		wf->residual_tasks_num = 3;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// Operator
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
		wf->tasks[0].name = strdup("Operator1");
		wf->tasks[0].operator = strdup("oph_operator");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 0;
		wf->tasks[0].arguments_keys = NULL;
		wf->tasks[0].arguments_values = NULL;
		wf->tasks[0].arguments_lists = NULL;
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 1;
		wf->tasks[0].dependents_indexes = (int *) calloc(wf->tasks[0].dependents_indexes_num, sizeof(int));
		wf->tasks[0].dependents_indexes[0] = 1;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;
		wf->tasks[0].response = strdup("{ \
    \"response\": [ \
        { \
            \"objclass\": \"grid\", \
            \"objkey\": \"data\", \
            \"objcontent\": [ \
                { \
                    \"rowvalues\": [ \
                        [ \
                            \"1st\", \
                            \"2nd\", \
                            \"3rd\" \
                        ] \
                    ], \
                    \"rowfieldtypes\": [ \
                        \"string\", \
                        \"string\", \
                        \"string\" \
                    ], \
                    \"title\": \"table1\", \
                    \"rowkeys\": [ \
                        \"column1\", \
                        \"column2\", \
                        \"column3\" \
                    ] \
                }, \
                { \
                    \"rowvalues\": [ \
                        [ \
                            \"1st\" \
                        ], \
                        [ \
                            \"2nd\" \
                        ], \
                        [ \
                            \"3rd\" \
                        ] \
                    ], \
                    \"rowfieldtypes\": [ \
                        \"string\" \
                    ], \
                    \"title\": \"table2\", \
                    \"rowkeys\": [ \
                        \"column\" \
                    ] \
                } \
            ] \
        }, \
        { \
            \"objclass\": \"grid\", \
            \"objkey\": \"data2\", \
            \"objcontent\": [ \
                { \
                    \"rowvalues\": [ \
                        [ \
                            \"1st\", \
                            \"2nd\", \
                            \"3rd\" \
                        ] \
                    ], \
                    \"rowfieldtypes\": [ \
                        \"string\", \
                        \"string\", \
                        \"string\" \
                    ], \
                    \"title\": \"table1\", \
                    \"rowkeys\": [ \
                        \"column1\", \
                        \"column2\", \
                        \"column3\" \
                    ] \
                } \
            ] \
        }, \
        { \
            \"objclass\": \"text\", \
            \"objkey\": \"summary\", \
            \"objcontent\": [ \
                { \
                    \"title\": \"text\", \
                    \"message\": \"1st\" \
                } \
            ] \
        }, \
        { \
            \"objclass\": \"text\", \
            \"objkey\": \"summary2\", \
            \"objcontent\": [ \
                { \
                    \"title\": \"text\", \
                    \"message\": \"2nd\" \
                }, \
				{ \
                    \"title\": \"text2\", \
                    \"message\": \"3rd\" \
                } \
            ] \
        }, \
        { \
            \"objclass\": \"text\", \
            \"objkey\": \"status\", \
            \"objcontent\": [ \
                { \
                    \"title\": \"SUCCESS\" \
                } \
            ] \
        } \
	], \
	\"responseKeyset\": [ \
        \"data\", \
        \"data2\", \
        \"summary\", \
        \"summary2\", \
        \"status\" \
    ], \
    \"source\": { \
        \"srckey\": \"oph\", \
        \"srcname\": \"Ophidia\", \
        \"producer\": \"oph-test\", \
        \"keys\": [ \
            \"Session Code\", \
            \"Workflow\", \
            \"Marker\", \
            \"JobID\" \
        ], \
        \"description\": \"Ophidia Data Source\", \
        \"values\": [ \
            \"123\", \
            \"1\", \
            \"1\", \
            \"http://localhost/sessions/123/experiment?1#1\" \
        ] \
    }, \
    \"consumers\": [ \
        \"oph-test\" \
    ] \
}");

		// FOR
		wf->tasks[1].idjob = wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[1].name = strdup("FOR");
		wf->tasks[1].operator = strdup("oph_for");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 4;
		wf->tasks[1].arguments_keys = (char **) calloc(wf->tasks[1].arguments_num, sizeof(char *));
		wf->tasks[1].arguments_keys[0] = strdup("key");
		wf->tasks[1].arguments_keys[1] = strdup("values");
		wf->tasks[1].arguments_keys[2] = strdup("counter");
		wf->tasks[1].arguments_keys[3] = strdup("parallel");
		wf->tasks[1].arguments_values = (char **) calloc(wf->tasks[1].arguments_num, sizeof(char *));
		wf->tasks[1].arguments_values[0] = strdup("index");
		wf->tasks[1].arguments_values[1] = strdup("first|second|third");
		wf->tasks[1].arguments_values[2] = strdup("1:3");
		wf->tasks[1].arguments_values[3] = strdup("no");
		wf->tasks[1].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[1].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[1].deps_num = 1;
		wf->tasks[1].deps = (oph_workflow_dep *) calloc(wf->tasks[1].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[1].deps[0].task_name = strdup("Operator1");
		wf->tasks[1].deps[0].task_index = 0;
		wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int *) calloc(wf->tasks[1].dependents_indexes_num, sizeof(int));
		wf->tasks[1].dependents_indexes[0] = 1;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;
		int for_index = 1;

		// Operator
		wf->tasks[2].idjob = wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[2].name = strdup("Operator2");
		wf->tasks[2].operator = strdup("oph_operator");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].arguments_lists = NULL;
		wf->tasks[2].deps_num = 1;
		wf->tasks[2].deps = (oph_workflow_dep *) calloc(wf->tasks[2].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[2].deps[0].task_name = strdup("FOR");
		wf->tasks[2].deps[0].task_index = 0;
		wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 1;
		wf->tasks[2].dependents_indexes = (int *) calloc(wf->tasks[2].dependents_indexes_num, sizeof(int));
		wf->tasks[2].dependents_indexes[0] = 2;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = -1;

		// ENDFOR
		wf->tasks[3].idjob = wf->tasks[3].markerid = 5;
		wf->tasks[3].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[3].name = strdup("ENDFOR");
		wf->tasks[3].operator = strdup("oph_endfor");
		wf->tasks[3].role = oph_code_role("read");
		wf->tasks[3].ncores = wf->ncores;
		wf->tasks[3].arguments_num = 0;
		wf->tasks[3].arguments_keys = NULL;
		wf->tasks[3].arguments_values = NULL;
		wf->tasks[3].arguments_lists = NULL;
		wf->tasks[3].deps_num = 1;
		wf->tasks[3].deps = (oph_workflow_dep *) calloc(wf->tasks[3].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[3].deps[0].task_name = strdup("Operator2");
		wf->tasks[3].deps[0].task_index = 1;
		wf->tasks[3].deps[0].type = strdup("embedded");
		wf->tasks[3].dependents_indexes_num = 0;
		wf->tasks[3].dependents_indexes = NULL;
		wf->tasks[3].run = 1;
		wf->tasks[3].parent = 0;

		char error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		switch (option) {
			case 1:
				{
					oph_workflow_var var;
					var.caller = -1;
					var.ivalue = 1;
					var.svalue = strdup("first|second|third");
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, "values", var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("@values");
				}
				break;

			case 2:
				{
					free(wf->tasks[1].arguments_keys[0]);
					wf->tasks[1].arguments_keys[0] = strdup("no-key");
				}
				break;

			case 3:
				{
					free(wf->tasks[1].arguments_keys[1]);
					wf->tasks[1].arguments_keys[1] = strdup("no-values");
				}
				break;

			case 4:
				{
					free(wf->tasks[1].arguments_keys[2]);
					wf->tasks[1].arguments_keys[2] = strdup("no-counter");
				}
				break;

			case 5:
				{
					free(wf->tasks[1].arguments_keys[3]);
					wf->tasks[1].arguments_keys[3] = strdup("no-parallel");
				}
				break;

			case 6:
				{
					free(wf->tasks[1].arguments_keys[1]);
					wf->tasks[1].arguments_keys[1] = strdup("no-values");
					free(wf->tasks[1].arguments_keys[2]);
					wf->tasks[1].arguments_keys[2] = strdup("no-counter");
				}
				break;

			case 7:
				{
					free(wf->tasks[1].arguments_values[3]);
					wf->tasks[1].arguments_values[3] = strdup("yes");
				}
				break;

			case 8:
				{
					free(wf->tasks[1].arguments_values[0]);
					wf->tasks[1].arguments_values[0] = strdup("1ndex");
				}
				break;

			case 9:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table1(1,*)");
				}
				break;

			case 10:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table2(*,1)");
				}
				break;

			case 11:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table2.column(*)");
				}
				break;

			case 12:
				{
					free(wf->tasks[1].arguments_values[0]);
					wf->tasks[1].arguments_values[0] = strdup("@badvariable");
				}
				break;

			case 13:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("@badvariable");
				}
				break;

			case 14:
				{
					free(wf->tasks[1].arguments_values[2]);
					wf->tasks[1].arguments_values[2] = strdup("@badvariable");
				}
				break;

			case 15:
				{
					free(wf->tasks[1].arguments_values[3]);
					wf->tasks[1].arguments_values[3] = strdup("@badvariable");
				}
				break;

			case 16:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table2.column(1)|data.table2.column(2)|data.table2.column(3)");
				}
				break;

			case 17:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table2.column(1)|data.table2.column(4)|data.table2.column(3)");
				}
				break;

			case 18:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("summary.text|2nd|data.table2.column(3)");
				}
				break;

			case 19:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("wrong(0.0)|wrong.wrong(0,0)|wrong.wrong.wrong(0)");
				}
				break;

			case 20:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("text(0)|text.text|text.text(0)");
				}
				break;

			case 21:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("table2.column(1)|table2.column(2)|table2.column(3)");
				}
				break;

			case 22:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("table1.column1|table2.column(2)|table2.column(3)");
				}
				break;

			case 23:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("summary|summary|summary");
				}
				break;

			case 24:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("summary2|summary2|summary2");
				}
				break;

			case 25:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data(1,1)|data(1,1)|data(1,1)");
				}
				break;

			case 26:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data2|data2|data2");
				}
				break;

			case 27:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table2.column1(10)|data.table2.column2(20)|data.table2.column3(30)");
				}
				break;

			case 28:
				{
					free(wf->tasks[1].arguments_values[1]);
					wf->tasks[1].arguments_values[1] = strdup("data.table2.(*,*)|data.table2(*.*)|data.table2.(*,*)");
				}
				break;

			case 29:
				{
					free(wf->tasks[1].arguments_values[2]);
					wf->tasks[1].arguments_values[2] = strdup("3:1");
				}
				break;

			case 30:
				{
					free(wf->tasks[1].arguments_values[2]);
					wf->tasks[1].arguments_values[2] = strdup("1:2");
				}
				break;

			case 31:
				{
					free(wf->tasks[1].arguments_values[0]);
					wf->tasks[1].arguments_values[0] = strdup("special:");
				}
				break;

			default:;
		}

		int res = oph_for_impl(wf, for_index, error_message);

		switch (option) {
			case 2:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad argument 'key'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 7:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
				if (wf->stack) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Non-empty stack\n");
					goto _EXIT_3;
				}
				break;

			case 8:
				if (res || !strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nEmpty error message\n", res);
					goto _EXIT_3;
				}
				if (strcmp(error_message, "Change variable name '1ndex'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong error message: %s\n", error_message);
					goto _EXIT_3;
				}
				if (!wf->stack) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Empty stack\n");
					goto _EXIT_3;
				}
				if (wf->stack->caller != for_index) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Flag 'caller' is wrong\n");
					goto _EXIT_3;
				}
				if (wf->stack->index) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Index is wrong\n");
					goto _EXIT_3;
				}
				if (!wf->stack->name) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
					goto _EXIT_3;
				}
				break;

			case 12:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad argument 'key'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 13:
			case 14:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Arguments 'values' and 'counter' have different sizes.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 15:
			case 29:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Generic error in parsing arguments of task 'FOR'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 30:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Arguments 'values' and 'counter' have different sizes.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 31:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad argument 'key'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nEmpty error message\n", res);
					goto _EXIT_3;
				}
				break;

			default:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
				if (!wf->stack) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Empty stack\n");
					goto _EXIT_3;
				}
				if (wf->stack->caller != for_index) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Flag 'caller' is wrong\n");
					goto _EXIT_3;
				}
				if (wf->stack->index) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Index is wrong\n");
					goto _EXIT_3;
				}
				if (!wf->stack->name) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
					goto _EXIT_3;
				}
		}

		switch (option) {
			case 0:
			case 1:
			case 4:
			case 5:
				{
					if (!wf->stack->svalues || (wf->stack->values_num != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
					if (strcmp(wf->stack->svalues[0], "first") || strcmp(wf->stack->svalues[1], "second") || strcmp(wf->stack->svalues[2], "third")) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack: %s|%s|%s\n", wf->stack->svalues[0], wf->stack->svalues[1],
						      wf->stack->svalues[2]);
						goto _EXIT_3;
					}
				}
				break;

			case 9:
			case 10:
			case 11:
			case 16:
			case 18:
				{
					if (!wf->stack->svalues || (wf->stack->values_num != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
					if (strcmp(wf->stack->svalues[0], "1st") || strcmp(wf->stack->svalues[1], "2nd") || strcmp(wf->stack->svalues[2], "3rd")) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack: %s|%s|%s\n", wf->stack->svalues[0], wf->stack->svalues[1],
						      wf->stack->svalues[2]);
						goto _EXIT_3;
					}
				}
				break;

			case 17:
				{
					if (!wf->stack->svalues || (wf->stack->values_num != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
					if (strcmp(wf->stack->svalues[0], "1st") || strcmp(wf->stack->svalues[1], "data.table2.column(4)") || strcmp(wf->stack->svalues[2], "3rd")) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack: %s|%s|%s\n", wf->stack->svalues[0], wf->stack->svalues[1],
						      wf->stack->svalues[2]);
						goto _EXIT_3;
					}
				}
				break;
		}

		switch (option) {
			case 0:
			case 1:
			case 3:
			case 5:
			case 9:
				{
					if (!wf->stack->ivalues || (wf->stack->values_num != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
					if ((wf->stack->ivalues[0] != 1) || (wf->stack->ivalues[1] != 2) || (wf->stack->ivalues[2] != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack: %d|%d|%d\n", wf->stack->ivalues[0], wf->stack->ivalues[1],
						      wf->stack->ivalues[2]);
						goto _EXIT_3;
					}
				}
				break;
		}

		switch (option) {
			case 6:
				{
					if ((wf->stack->values_num != 1) || wf->stack->ivalues || wf->stack->svalues) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
				}
				break;
		}

	} else if (!strcmp(function, "oph_endfor_impl")) {
		// Tasks
		wf->tasks_num = 3;
		wf->residual_tasks_num = 1;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// FOR
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
		wf->tasks[0].name = strdup("FOR");
		wf->tasks[0].operator = strdup("oph_for");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 4;
		wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_keys[0] = strdup("key");
		wf->tasks[0].arguments_keys[1] = strdup("values");
		wf->tasks[0].arguments_keys[2] = strdup("counter");
		wf->tasks[0].arguments_keys[3] = strdup("parallel");
		wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_values[0] = strdup("index");
		wf->tasks[0].arguments_values[1] = strdup("first|second|third");
		wf->tasks[0].arguments_values[2] = strdup("1:3");
		wf->tasks[0].arguments_values[3] = strdup("no");
		wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 1;
		wf->tasks[0].dependents_indexes = (int *) calloc(wf->tasks[0].dependents_indexes_num, sizeof(int));
		wf->tasks[0].dependents_indexes[0] = 1;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;
		wf->tasks[0].outputs_num = 1;
		wf->tasks[0].outputs_keys = (char **) calloc(wf->tasks[0].outputs_num, sizeof(char *));
		wf->tasks[0].outputs_keys[0] = strdup("output_key");
		wf->tasks[0].outputs_values = (char **) calloc(wf->tasks[0].outputs_num, sizeof(char *));
		wf->tasks[0].outputs_values[0] = strdup("output_value");

		// Operator
		wf->tasks[1].idjob = wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
		wf->tasks[1].name = strdup("Operator");
		wf->tasks[1].operator = strdup("oph_operator");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 0;
		wf->tasks[1].arguments_keys = NULL;
		wf->tasks[1].arguments_values = NULL;
		wf->tasks[1].arguments_lists = NULL;
		wf->tasks[1].deps_num = 1;
		wf->tasks[1].deps = (oph_workflow_dep *) calloc(wf->tasks[1].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[1].deps[0].task_name = strdup("FOR");
		wf->tasks[1].deps[0].task_index = 0;
		wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int *) calloc(wf->tasks[1].dependents_indexes_num, sizeof(int));
		wf->tasks[1].dependents_indexes[0] = 2;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// ENDFOR
		wf->tasks[2].idjob = wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[2].name = strdup("ENDFOR");
		wf->tasks[2].operator = strdup("oph_endfor");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].arguments_lists = NULL;
		wf->tasks[2].deps_num = 1;
		wf->tasks[2].deps = (oph_workflow_dep *) calloc(wf->tasks[2].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[2].deps[0].task_name = strdup("Operator");
		wf->tasks[2].deps[0].task_index = 1;
		wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 0;
		wf->tasks[2].dependents_indexes = NULL;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = 0;

		char error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		int task_id = 2;
		int odb_jobid = wf->tasks[2].idjob;

		oph_trash *trash;
		if (oph_trash_create(&trash)) {
			goto _EXIT_3;
		}

		switch (option) {
			case 3:
				{

				}
				break;

			case 4:
				{
					int svalues_num = 3;
					char **svalues = (char **) calloc(svalues_num, sizeof(char *));
					svalues[0] = strdup("first");
					svalues[1] = strdup("second");
					svalues[2] = strdup("third");
					int *ivalues = (int *) calloc(svalues_num, sizeof(int));
					ivalues[0] = 1;
					ivalues[1] = 2;
					ivalues[2] = 3;
					if (oph_workflow_push(wf, 0, wf->tasks[0].arguments_values[0], svalues, ivalues, svalues_num)) {
						oph_trash_destroy(trash);
						while (--svalues_num)
							free(svalues[svalues_num]);
						free(svalues);
						free(ivalues);
						goto _EXIT_3;
					}
				}
				break;

			case 5:
				{
					int svalues_num = 3;
					char **svalues = (char **) calloc(svalues_num, sizeof(char *));
					svalues[0] = strdup("first");
					svalues[1] = strdup("second");
					svalues[2] = strdup("third");
					int *ivalues = (int *) calloc(svalues_num, sizeof(int));
					ivalues[0] = 1;
					ivalues[1] = 2;
					ivalues[2] = 3;
					if (oph_workflow_push(wf, 0, wf->tasks[0].arguments_values[0], svalues, ivalues, svalues_num) || !wf->stack) {
						oph_trash_destroy(trash);
						while (--svalues_num)
							free(svalues[svalues_num]);
						free(svalues);
						free(ivalues);
						goto _EXIT_3;
					}

					wf->stack->index = 2;

					oph_workflow_var var;
					var.caller = 0;
					var.ivalue = ivalues[wf->stack->index];
					char svalue[OPH_WORKFLOW_MAX_STRING];
					snprintf(svalue, OPH_WORKFLOW_MAX_STRING, "%s", svalues[wf->stack->index]);
					var.svalue = strdup(svalue);
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, wf->tasks[0].arguments_values[0], var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						oph_trash_destroy(trash);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);
				}
				break;

			default:
				{
					int svalues_num = 3;
					char **svalues = (char **) calloc(svalues_num, sizeof(char *));
					svalues[0] = strdup("first");
					svalues[1] = strdup("second");
					svalues[2] = strdup("third");
					int *ivalues = (int *) calloc(svalues_num, sizeof(int));
					ivalues[0] = 1;
					ivalues[1] = 2;
					ivalues[2] = 3;
					if (oph_workflow_push(wf, 0, wf->tasks[0].arguments_values[0], svalues, ivalues, svalues_num) || !wf->stack) {
						oph_trash_destroy(trash);
						while (--svalues_num)
							free(svalues[svalues_num]);
						free(svalues);
						free(ivalues);
						goto _EXIT_3;
					}

					oph_workflow_var var;
					var.caller = 0;
					var.ivalue = ivalues[wf->stack->index];
					char svalue[OPH_WORKFLOW_MAX_STRING];
					snprintf(svalue, OPH_WORKFLOW_MAX_STRING, "%s", svalues[wf->stack->index]);
					var.svalue = strdup(svalue);
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, wf->tasks[0].arguments_values[0], var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						oph_trash_destroy(trash);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);
				}
		}

		switch (option) {
			case 1:
				{
					free(wf->tasks[0].arguments_keys[1]);
					wf->tasks[0].arguments_keys[1] = strdup("no-values");
				}
				break;

			case 2:
				{
					free(wf->tasks[0].arguments_keys[2]);
					wf->tasks[0].arguments_keys[2] = strdup("no-counter");
				}
				break;

			default:;
		}

		int res = oph_endfor_impl(wf, 2, error_message, trash, &task_id, &odb_jobid);

		switch (option) {
			case 3:
			case 4:
			case 5:
				if (trash && trash->trash) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Non empty trash\n");
					oph_trash_destroy(trash);
					goto _EXIT_3;
				}
				break;

			default:
				if (!trash || !trash->trash || !trash->trash->key || !trash->trash->head || !trash->trash->head->item) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Empty trash\n");
					oph_trash_destroy(trash);
					goto _EXIT_3;
				}
				if (strcmp(trash->trash->key, wf->sessionid) || (trash->trash->head->item != 4)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Untrashed marker id\n");
					oph_trash_destroy(trash);
					goto _EXIT_3;
				}
		}

		oph_trash_destroy(trash);

		switch (option) {
			case 3:
				{
					if (res || !strlen(error_message)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
						goto _EXIT_3;
					}
					if (strcmp(error_message, "No index found in environment of workflow 'test'.")) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong error message: %s\n", error_message);
						goto _EXIT_3;
					}
				}
				break;

			case 4:
				{
					if ((res != OPH_SERVER_SYSTEM_ERROR) || !strlen(error_message)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
						goto _EXIT_3;
					}
					if (strcmp(error_message, "Unable to remove variable 'index' from environment of workflow 'test'.")) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong error message: %s\n", error_message);
						goto _EXIT_3;
					}
				}
				break;

			case 5:
				{
					if (res || strlen(error_message)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
						goto _EXIT_3;
					}
				}
				break;

			default:
				if ((res != OPH_SERVER_NO_RESPONSE) || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
				if (!wf->stack) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Empty stack\n");
					goto _EXIT_3;
				}
				if (wf->stack->caller) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Flag 'caller' is wrong\n");
					goto _EXIT_3;
				}
				if (wf->stack->index != 1) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Index is wrong\n");
					goto _EXIT_3;
				}
				if (!wf->stack->name) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
					goto _EXIT_3;
				}
				if (wf->tasks[0].outputs_num || wf->tasks[0].outputs_keys || wf->tasks[0].outputs_values) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Task status not reset\n");
					goto _EXIT_3;
				}
		}

		switch (option) {
			case 0:
			case 2:
				{
					if (!wf->stack->svalues || (wf->stack->values_num != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
					if (strcmp(wf->stack->svalues[0], "first") || strcmp(wf->stack->svalues[1], "second") || strcmp(wf->stack->svalues[2], "third")) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack: %s|%s|%s\n", wf->stack->svalues[0], wf->stack->svalues[1],
						      wf->stack->svalues[2]);
						goto _EXIT_3;
					}
				}
				break;
		}

		switch (option) {
			case 0:
			case 1:
				{
					if (!wf->stack->ivalues || (wf->stack->values_num != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack\n");
						goto _EXIT_3;
					}
					if ((wf->stack->ivalues[0] != 1) || (wf->stack->ivalues[1] != 2) || (wf->stack->ivalues[2] != 3)) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Parameters are not correctly pushed into the stack: %d|%d|%d\n", wf->stack->ivalues[0], wf->stack->ivalues[1],
						      wf->stack->ivalues[2]);
						goto _EXIT_3;
					}
				}
				break;
		}
	} else if (!strcmp(function, "oph_serve_flow_control_operator")) {

		struct oph_plugin_data *state = (struct oph_plugin_data *) calloc(1, sizeof(struct oph_plugin_data));
		if (!state) {
			goto _EXIT_3;
		}

		oph_job_list *job_info;
		if (oph_create_job_list(&job_info)) {
			free(state);
			goto _EXIT_3;
		}
		state->job_info = job_info;

		if (oph_wf_list_append(job_info, wf)) {
			oph_destroy_job_list(job_info);
			free(state);
			goto _EXIT_3;
		}

		oph_trash *trash;
		if (oph_trash_create(&trash)) {
			oph_destroy_job_list(job_info);
			free(state);
			return 1;
		}
		state->trash = trash;
		state->serverid = strdup(oph_web_server);

		char markerid[OPH_SHORT_STRING_SIZE];
		int odb_wf_id = 1;
		int task_id = 0;
		int light_task_id = -1;
		int odb_jobid = 0;
		char *response = NULL;
		enum oph__oph_odb_job_status exit_code = OPH_ODB_STATUS_COMPLETED;
		int exit_output = 0;
		char operator_name[OPH_SHORT_STRING_SIZE];
		char os_username[OPH_SHORT_STRING_SIZE];
		snprintf(os_username, OPH_SHORT_STRING_SIZE, "%s", wf->os_username);

		// Tasks
		wf->tasks_num = wf->residual_tasks_num = 10;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// FOR
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("FOR");
		wf->tasks[0].operator = strdup("oph_for");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 4;
		wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_keys[0] = strdup("key");
		wf->tasks[0].arguments_keys[1] = strdup("values");
		wf->tasks[0].arguments_keys[2] = strdup("counter");
		wf->tasks[0].arguments_keys[3] = strdup("parallel");
		wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_values[0] = strdup("index");
		wf->tasks[0].arguments_values[1] = strdup("first|second|third");
		wf->tasks[0].arguments_values[2] = strdup("1:3");
		wf->tasks[0].arguments_values[3] = strdup("no");
		wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 1;
		wf->tasks[0].dependents_indexes = (int *) calloc(wf->tasks[0].dependents_indexes_num, sizeof(int));
		wf->tasks[0].dependents_indexes[0] = 1;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;
		wf->tasks[0].outputs_num = 1;
		wf->tasks[0].outputs_keys = (char **) calloc(wf->tasks[0].outputs_num, sizeof(char *));
		wf->tasks[0].outputs_keys[0] = strdup("output_key");
		wf->tasks[0].outputs_values = (char **) calloc(wf->tasks[0].outputs_num, sizeof(char *));
		wf->tasks[0].outputs_values[0] = strdup("output_value");

		// IF
		wf->tasks[1].idjob = wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[1].name = strdup("IF");
		wf->tasks[1].operator = strdup("oph_if");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 1;
		wf->tasks[1].arguments_keys = (char **) calloc(wf->tasks[1].arguments_num, sizeof(char *));
		wf->tasks[1].arguments_keys[0] = strdup("condition");
		wf->tasks[1].arguments_values = (char **) calloc(wf->tasks[1].arguments_num, sizeof(char *));
		wf->tasks[1].arguments_values[0] = strdup("1");
		wf->tasks[1].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[1].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[1].deps_num = 1;
		wf->tasks[1].deps = (oph_workflow_dep *) calloc(wf->tasks[1].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[1].deps[0].task_name = strdup("FOR");
		wf->tasks[1].deps[0].task_index = 0;
		wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 2;
		wf->tasks[1].dependents_indexes = (int *) calloc(wf->tasks[1].dependents_indexes_num, sizeof(int));
		wf->tasks[1].dependents_indexes[0] = 2;
		wf->tasks[1].dependents_indexes[1] = 3;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// Operator for true
		wf->tasks[2].idjob = wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[2].name = strdup("Operator for true");
		wf->tasks[2].operator = strdup("oph_operator");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].arguments_lists = NULL;
		wf->tasks[2].deps_num = 1;
		wf->tasks[2].deps = (oph_workflow_dep *) calloc(wf->tasks[2].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[2].deps[0].task_name = strdup("IF");
		wf->tasks[2].deps[0].task_index = 1;
		wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 1;
		wf->tasks[2].dependents_indexes = (int *) calloc(wf->tasks[2].dependents_indexes_num, sizeof(int));
		wf->tasks[2].dependents_indexes[0] = 5;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = -1;

		// ELSE
		wf->tasks[3].idjob = wf->tasks[3].markerid = 5;
		wf->tasks[3].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[3].name = strdup("ELSE");
		wf->tasks[3].operator = strdup("oph_else");
		wf->tasks[3].role = oph_code_role("read");
		wf->tasks[3].ncores = wf->ncores;
		wf->tasks[3].arguments_num = 0;
		wf->tasks[3].arguments_keys = NULL;
		wf->tasks[3].arguments_values = NULL;
		wf->tasks[3].arguments_lists = NULL;
		wf->tasks[3].deps_num = 1;
		wf->tasks[3].deps = (oph_workflow_dep *) calloc(wf->tasks[3].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[3].deps[0].task_name = strdup("IF");
		wf->tasks[3].deps[0].task_index = 1;
		wf->tasks[3].deps[0].type = strdup("embedded");
		wf->tasks[3].dependents_indexes_num = 1;
		wf->tasks[3].dependents_indexes = (int *) calloc(wf->tasks[3].dependents_indexes_num, sizeof(int));
		wf->tasks[3].dependents_indexes[0] = 4;
		wf->tasks[3].run = 1;
		wf->tasks[3].parent = 0;

		// Operator for false
		wf->tasks[4].idjob = wf->tasks[4].markerid = 6;
		wf->tasks[4].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[4].name = strdup("Operator for false");
		wf->tasks[4].operator = strdup("oph_operator");
		wf->tasks[4].role = oph_code_role("read");
		wf->tasks[4].ncores = wf->ncores;
		wf->tasks[4].arguments_num = 0;
		wf->tasks[4].arguments_keys = NULL;
		wf->tasks[4].arguments_values = NULL;
		wf->tasks[4].arguments_lists = NULL;
		wf->tasks[4].deps_num = 1;
		wf->tasks[4].deps = (oph_workflow_dep *) calloc(wf->tasks[4].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[4].deps[0].task_name = strdup("ELSE");
		wf->tasks[4].deps[0].task_index = 3;
		wf->tasks[4].deps[0].type = strdup("embedded");
		wf->tasks[4].dependents_indexes_num = 1;
		wf->tasks[4].dependents_indexes = (int *) calloc(wf->tasks[4].dependents_indexes_num, sizeof(int));
		wf->tasks[4].dependents_indexes[0] = 5;
		wf->tasks[4].run = 1;
		wf->tasks[4].parent = -1;

		// ENDIF
		wf->tasks[5].idjob = wf->tasks[5].markerid = 7;
		wf->tasks[5].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[5].name = strdup("ENDIF");
		wf->tasks[5].operator = strdup("oph_endif");
		wf->tasks[5].role = oph_code_role("read");
		wf->tasks[5].ncores = wf->ncores;
		wf->tasks[5].arguments_num = 0;
		wf->tasks[5].arguments_keys = NULL;
		wf->tasks[5].arguments_values = NULL;
		wf->tasks[5].arguments_lists = NULL;
		wf->tasks[5].deps_num = 2;
		wf->tasks[5].deps = (oph_workflow_dep *) calloc(wf->tasks[5].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[5].deps[0].task_name = strdup("Operator for true");
		wf->tasks[5].deps[0].task_index = 2;
		wf->tasks[5].deps[0].type = strdup("embedded");
		wf->tasks[5].deps[1].task_name = strdup("Operator for false");
		wf->tasks[5].deps[1].task_index = 4;
		wf->tasks[5].deps[1].type = strdup("embedded");
		wf->tasks[5].dependents_indexes_num = 1;
		wf->tasks[5].dependents_indexes = (int *) calloc(wf->tasks[5].dependents_indexes_num, sizeof(int));
		wf->tasks[5].dependents_indexes[0] = 6;
		wf->tasks[5].run = 1;
		wf->tasks[5].parent = 0;
		wf->tasks[5].branch_num = 2;

		// ENDFOR
		wf->tasks[6].idjob = wf->tasks[6].markerid = 8;
		wf->tasks[6].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[6].name = strdup("ENDFOR");
		wf->tasks[6].operator = strdup("oph_endfor");
		wf->tasks[6].role = oph_code_role("read");
		wf->tasks[6].ncores = wf->ncores;
		wf->tasks[6].arguments_num = 0;
		wf->tasks[6].arguments_keys = NULL;
		wf->tasks[6].arguments_values = NULL;
		wf->tasks[6].arguments_lists = NULL;
		wf->tasks[6].deps_num = 1;
		wf->tasks[6].deps = (oph_workflow_dep *) calloc(wf->tasks[6].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[6].deps[0].task_name = strdup("ENDIF");
		wf->tasks[6].deps[0].task_index = 5;
		wf->tasks[6].deps[0].type = strdup("embedded");
		wf->tasks[6].dependents_indexes_num = 0;
		wf->tasks[6].dependents_indexes = NULL;
		wf->tasks[6].run = 1;
		wf->tasks[6].parent = 0;

		// WAIT
		wf->tasks[7].idjob = wf->tasks[7].markerid = 9;
		wf->tasks[7].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[7].name = strdup("WAIT");
		wf->tasks[7].operator = strdup("oph_wait");
		wf->tasks[7].role = oph_code_role("read");
		wf->tasks[7].ncores = wf->ncores;
		wf->tasks[7].arguments_num = 1;
		wf->tasks[7].arguments_keys = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
		wf->tasks[7].arguments_keys[0] = strdup("timeout");
		wf->tasks[7].arguments_values = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
		wf->tasks[7].arguments_values[0] = strdup("2");
		wf->tasks[7].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[7].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[7].deps_num = 1;
		wf->tasks[7].deps = (oph_workflow_dep *) calloc(wf->tasks[7].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[7].deps[0].task_name = strdup("ENDFOR");
		wf->tasks[7].deps[0].task_index = 6;
		wf->tasks[7].deps[0].type = strdup("embedded");
		wf->tasks[7].dependents_indexes_num = 0;
		wf->tasks[7].dependents_indexes = NULL;
		wf->tasks[7].run = 1;
		wf->tasks[7].parent = -1;

		// SET
		wf->tasks[8].idjob = wf->tasks[8].markerid = 10;
		wf->tasks[8].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[8].name = strdup("SET");
		wf->tasks[8].operator = strdup("oph_set");
		wf->tasks[8].role = oph_code_role("read");
		wf->tasks[8].ncores = wf->ncores;
		wf->tasks[8].arguments_num = 1;
		wf->tasks[8].arguments_keys = (char **) calloc(wf->tasks[8].arguments_num, sizeof(char *));
		wf->tasks[8].arguments_keys[0] = strdup("timeout");
		wf->tasks[8].arguments_values = (char **) calloc(wf->tasks[8].arguments_num, sizeof(char *));
		wf->tasks[8].arguments_values[0] = strdup("2");
		wf->tasks[8].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[8].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[8].deps_num = 1;
		wf->tasks[8].deps = (oph_workflow_dep *) calloc(wf->tasks[8].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[8].deps[0].task_name = strdup("ENDFOR");
		wf->tasks[8].deps[0].task_index = 6;
		wf->tasks[8].deps[0].type = strdup("embedded");
		wf->tasks[8].dependents_indexes_num = 0;
		wf->tasks[8].dependents_indexes = NULL;
		wf->tasks[8].run = 1;
		wf->tasks[8].parent = -1;

		// INPUT
		wf->tasks[9].idjob = wf->tasks[9].markerid = 11;
		wf->tasks[9].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[9].name = strdup("INPUT");
		wf->tasks[9].operator = strdup("oph_input");
		wf->tasks[9].role = oph_code_role("read");
		wf->tasks[9].ncores = wf->ncores;
		wf->tasks[9].arguments_num = 1;
		wf->tasks[9].arguments_keys = (char **) calloc(wf->tasks[9].arguments_num, sizeof(char *));
		wf->tasks[9].arguments_keys[0] = strdup("timeout");
		wf->tasks[9].arguments_values = (char **) calloc(wf->tasks[9].arguments_num, sizeof(char *));
		wf->tasks[9].arguments_values[0] = strdup("2");
		wf->tasks[9].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[9].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[9].deps_num = 1;
		wf->tasks[9].deps = (oph_workflow_dep *) calloc(wf->tasks[9].deps_num, sizeof(oph_workflow_dep));
		wf->tasks[9].deps[0].task_name = strdup("ENDFOR");
		wf->tasks[9].deps[0].task_index = 6;
		wf->tasks[9].deps[0].type = strdup("embedded");
		wf->tasks[9].dependents_indexes_num = 0;
		wf->tasks[9].dependents_indexes = NULL;
		wf->tasks[9].run = 1;
		wf->tasks[9].parent = -1;

		switch (option) {
			case 0:
				{
					task_id = 0;
					odb_jobid = 2;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_for");
					wf->residual_tasks_num = 10;
				}
				break;

			case 1:
				{
					task_id = 6;
					odb_jobid = 8;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_endfor");
					wf->residual_tasks_num = 4;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
				}
				break;

			case 2:
				{
					task_id = 1;
					odb_jobid = 3;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_if");
					wf->residual_tasks_num = 9;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
				}
				break;

			case 3:
				{
					task_id = 3;
					odb_jobid = 5;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_else");
					wf->residual_tasks_num = 7;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_UNSELECTED;
					free(wf->tasks[1].arguments_values[0]);
					wf->tasks[1].arguments_values[0] = strdup("0");
				}
				break;

			case 4:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;
				}
				break;

			case 5:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;

					free(wf->tasks[7].arguments_keys[0]);
					free(wf->tasks[7].arguments_keys);
					free(wf->tasks[7].arguments_values[0]);
					free(wf->tasks[7].arguments_values);
					wf->tasks[7].arguments_num = 3;
					wf->tasks[7].arguments_keys = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_keys[0] = strdup("timeout");
					wf->tasks[7].arguments_keys[1] = strdup("type");
					wf->tasks[7].arguments_keys[2] = strdup("filename");
					wf->tasks[7].arguments_values = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_values[0] = strdup("2");
					wf->tasks[7].arguments_values[1] = strdup("file");
					wf->tasks[7].arguments_values[2] = strdup("testdata/a_12.test");
				}
				break;

			case 6:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;

					free(wf->tasks[7].arguments_keys[0]);
					free(wf->tasks[7].arguments_keys);
					free(wf->tasks[7].arguments_values[0]);
					free(wf->tasks[7].arguments_values);
					wf->tasks[7].arguments_num = 3;
					wf->tasks[7].arguments_keys = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_keys[0] = strdup("timeout");
					wf->tasks[7].arguments_keys[1] = strdup("type");
					wf->tasks[7].arguments_keys[2] = strdup("filename");
					wf->tasks[7].arguments_values = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_values[0] = strdup("2");
					wf->tasks[7].arguments_values[1] = strdup("file");
					wf->tasks[7].arguments_values[2] = strdup("testdata/a_12.test");

					if (wf->sessionid)
						free(wf->sessionid);
					wf->sessionid = strdup("");

					if (oph_base_src_path)
						free(oph_base_src_path);
					oph_base_src_path = NULL;
				}
				break;

			case 7:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;

					free(wf->tasks[7].arguments_keys[0]);
					free(wf->tasks[7].arguments_keys);
					free(wf->tasks[7].arguments_values[0]);
					free(wf->tasks[7].arguments_values);
					wf->tasks[7].arguments_num = 3;
					wf->tasks[7].arguments_keys = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_keys[0] = strdup("timeout");
					wf->tasks[7].arguments_keys[1] = strdup("type");
					wf->tasks[7].arguments_keys[2] = strdup("filename");
					wf->tasks[7].arguments_values = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_values[0] = strdup("2");
					wf->tasks[7].arguments_values[1] = strdup("file");
					wf->tasks[7].arguments_values[2] = strdup(oph_web_server);
				}
				break;

			case 8:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;

					free(wf->tasks[7].arguments_keys[0]);
					free(wf->tasks[7].arguments_keys);
					free(wf->tasks[7].arguments_values[0]);
					free(wf->tasks[7].arguments_values);
					wf->tasks[7].arguments_num = 2;
					wf->tasks[7].arguments_keys = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_keys[0] = strdup("timeout");
					wf->tasks[7].arguments_keys[1] = strdup("type");
					wf->tasks[7].arguments_values = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_values[0] = strdup("2");
					wf->tasks[7].arguments_values[1] = strdup("input");
				}
				break;

			case 9:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;
					wf->status = OPH_ODB_STATUS_COMPLETED;	// Wrong value
				}
				break;

			case 10:
				{
					task_id = 7;
					odb_jobid = 9;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_wait");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;

					free(wf->tasks[7].arguments_keys[0]);
					free(wf->tasks[7].arguments_keys);
					free(wf->tasks[7].arguments_values[0]);
					free(wf->tasks[7].arguments_values);
					wf->tasks[7].arguments_num = 3;
					wf->tasks[7].arguments_keys = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_keys[0] = strdup("timeout");
					wf->tasks[7].arguments_keys[1] = strdup("type");
					wf->tasks[7].arguments_keys[2] = strdup("filename");
					wf->tasks[7].arguments_values = (char **) calloc(wf->tasks[7].arguments_num, sizeof(char *));
					wf->tasks[7].arguments_values[0] = strdup("2");
					wf->tasks[7].arguments_values[1] = strdup("file");
					wf->tasks[7].arguments_values[2] = strdup("testdata/test.test");
				}
				break;

			case 11:
				{
					task_id = 8;
					odb_jobid = 10;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_set");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;
				}
				break;

			case 12:
				{
					task_id = 9;
					odb_jobid = 11;
					snprintf(operator_name, OPH_MAX_STRING_SIZE, "oph_input");
					wf->residual_tasks_num = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[1].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[2].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[3].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[4].status = OPH_ODB_STATUS_UNSELECTED;
					wf->tasks[5].status = OPH_ODB_STATUS_COMPLETED;
					wf->tasks[6].status = OPH_ODB_STATUS_COMPLETED;
				}
				break;

			default:;
		}
		snprintf(markerid, OPH_SHORT_STRING_SIZE, "%d", odb_jobid);

		int res;
		pthread_t tid;
		if ((option >= 4) && (option <= 10))
			res =
			    _oph_serve_flow_control_operator(state, NULL, 0, sessionid, markerid, &odb_wf_id, &task_id, &light_task_id, &odb_jobid, &response, NULL, &exit_code, &exit_output,
							     os_username, operator_name, &tid);
		else
			res =
			    oph_serve_flow_control_operator(state, NULL, 0, sessionid, markerid, &odb_wf_id, &task_id, &light_task_id, &odb_jobid, &response, NULL, &exit_code, &exit_output,
							    os_username, operator_name);

		if (response)
			free(response);

		if ((option >= 4) && (option <= 10)) {
			sleep(3);
			if (option == 10) {
				FILE *file = fopen("testdata/test.test", "w");
				if (file)
					fclose(file);
				sleep(3);
				unlink("testdata/test.test");
			}
			pthread_mutex_lock(&global_flag);
			pthread_cancel(tid);
			pthread_mutex_unlock(&global_flag);
		}

		if (!oph_base_src_path)
			oph_base_src_path = strdup(".");

		wf = NULL;
		oph_destroy_job_list(job_info);
		oph_trash_destroy(trash);
		if (state->serverid)
			free(state->serverid);
		free(state);

		if (res != OPH_SERVER_NO_RESPONSE) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
			return 1;
		}

	} else if (!strcmp(function, "oph_check_for_massive_operation")) {

		int test_on_data_num = 32, return_value = 1;

		if (option < test_on_data_num) {

#ifdef OPH_DB_SUPPORT

			int filter_num = 23;
			char *filter[] = {
				"[*]",
				"[run=no]",
				"[measure=measure]",
				"[container=containername]",
				"[cube_filter=2]",
				"[cube_filter=2:4]",
				"[cube_filter=2:3:10]",
				"[cube_filter=2,3,10]",
				"[metadata_key=key1|key2]",
				"[metadata_value=value1|value2]",
				"[metadata_key=key;metadata_value=value]",
				"[metadata_key=key1|key2;metadata_value=value1|value2]",
				"[level=2|3]",
				"[path=/path/to/container]",
				"[path=/path/to/container;recursive=yes]",
				"[container=containername;metadata_key=key;metadata_value=value;level=2;path=/path/to/container;recursive=yes]",
				"1|3|5",
				"[level=1,3]|[measure=measure]|5",
				"[10]",
				"[container_pid=http://localhost/5]",
				"[parent_cube=http://localhost/3/4]",
				"[all]",
				"[]"
			};
			char *equery[] = {
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND datacube.measure='measure' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND container.containername='containername' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (mysql.oph_is_in_subset(datacube.iddatacube,2,1,2)) AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (mysql.oph_is_in_subset(datacube.iddatacube,2,1,4)) AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (mysql.oph_is_in_subset(datacube.iddatacube,2,3,10)) AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (mysql.oph_is_in_subset(datacube.iddatacube,2,1,2) OR mysql.oph_is_in_subset(datacube.iddatacube,3,1,3) OR mysql.oph_is_in_subset(datacube.iddatacube,10,1,10)) AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container,metadatainstance AS metadatainstance0,metadatainstance AS metadatainstance1 WHERE datacube.idcontainer=container.idcontainer AND metadatainstance0.iddatacube=datacube.iddatacube AND metadatainstance0.label='key1' AND metadatainstance1.iddatacube=datacube.iddatacube AND metadatainstance1.label='key2' AND (container.idfolder='1')",
				"No query expected",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container,metadatainstance AS metadatainstance0k0 WHERE datacube.idcontainer=container.idcontainer AND metadatainstance0k0.iddatacube=datacube.iddatacube AND metadatainstance0k0.label='key' AND CONVERT(metadatainstance0k0.value USING latin1) LIKE '%value%' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container,metadatainstance AS metadatainstance0k0,metadatainstance AS metadatainstance0k1 WHERE datacube.idcontainer=container.idcontainer AND metadatainstance0k0.iddatacube=datacube.iddatacube AND metadatainstance0k0.label='key1' AND CONVERT(metadatainstance0k0.value USING latin1) LIKE '%value1%' AND metadatainstance0k1.iddatacube=datacube.iddatacube AND metadatainstance0k1.label='key2' AND CONVERT(metadatainstance0k1.value USING latin1) LIKE '%value2%' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (datacube.level='2' OR datacube.level='3') AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (container.idfolder='1' OR container.idfolder='2')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container,metadatainstance AS metadatainstance0k0 WHERE datacube.idcontainer=container.idcontainer AND (datacube.level='2') AND container.containername='containername' AND metadatainstance0k0.iddatacube=datacube.iddatacube AND metadatainstance0k0.label='key' AND CONVERT(metadatainstance0k0.value USING latin1) LIKE '%value%' AND (container.idfolder='1' OR container.idfolder='2')",
				"No query expected",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (datacube.level='1') AND (container.idfolder='1')|SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND datacube.measure='measure' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (mysql.oph_is_in_subset(datacube.iddatacube,10,1,10)) AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND datacube.idcontainer='5' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container,task AS taskp,hasinput AS hasinputp,datacube AS datacubep WHERE datacube.idcontainer=container.idcontainer AND datacube.iddatacube=taskp.idoutputcube AND taskp.idtask=hasinputp.idtask AND hasinputp.iddatacube=datacubep.iddatacube AND datacubep.iddatacube='4' AND datacubep.idcontainer='3' AND (container.idfolder='1')",
				"SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (container.idfolder='1')",
				"No query expected"
			};

			// Tasks
			wf->tasks_num = 1;
			wf->residual_tasks_num = 1;
			wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));

			// MASSIVE
			wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
			wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
			wf->tasks[0].name = strdup("MASSIVE");
			wf->tasks[0].operator = strdup("oph_massive");
			wf->tasks[0].role = oph_code_role("read");
			wf->tasks[0].ncores = wf->ncores;
			wf->tasks[0].arguments_num = 3;
			wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
			wf->tasks[0].arguments_keys[0] = strdup("cube");
			wf->tasks[0].arguments_keys[1] = strdup("cwd");
			wf->tasks[0].arguments_keys[2] = strdup("measure");
			wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
			wf->tasks[0].arguments_values[0] = strdup(filter[option < filter_num ? option : 0]);
			wf->tasks[0].arguments_values[1] = strdup(wf->cwd);
			wf->tasks[0].arguments_values[2] = strdup("measure");
			wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
			wf->tasks[0].run = 1;

			ophidiadb oDB;
			oph_odb_initialize_ophidiadb(&oDB);

			char **output_list = NULL, *query = NULL;
			int res, j, output_list_dim = 0;

			pthread_mutex_lock(&global_flag);

			switch (option - filter_num) {
				case 0:
					res = oph_check_for_massive_operation(NULL, 'T', 0, NULL, 0, &oDB, &output_list, &output_list_dim, &query, NULL);
					break;

				case 1:
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, NULL, &output_list, &output_list_dim, &query, NULL);
					break;

				case 2:
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, &oDB, NULL, &output_list_dim, &query, NULL);
					break;

				case 3:
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, &oDB, &output_list, NULL, &query, NULL);
					break;

				case 4:
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 2, &oDB, &output_list, &output_list_dim, &query, NULL);
					break;

				case 5:
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, -1, &oDB, &output_list, &output_list_dim, &query, NULL);
					break;

				case 6:
					wf->tasks[0].light_tasks_num = 1;
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, &oDB, &output_list, &output_list_dim, &query, NULL);
					break;

				case 7:
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("[filter=@badvariable]");
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, &oDB, &output_list, &output_list_dim, &query, NULL);
					break;

				case 8:
					free(wf->tasks[0].arguments_keys[0]);
					wf->tasks[0].arguments_keys[0] = strdup("cube2");
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, &oDB, &output_list, &output_list_dim, &query, NULL);
					break;

				default:
					res = oph_check_for_massive_operation(NULL, 'T', 0, wf, 0, &oDB, &output_list, &output_list_dim, &query, NULL);
			}

			pthread_mutex_unlock(&global_flag);

			switch (option) {
				case 1:
				case 18:
					if (res != OPH_SERVER_NO_RESPONSE) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (!query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Expected return query\n");
						goto _EXIT_1;
					}
					if (strcmp(query, equery[option < filter_num ? option : 0])) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong return query: %s\n", query);
						goto _EXIT_1;
					}
					break;

				case 9:
					if (res != OPH_SERVER_SYSTEM_ERROR) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				case 16:
					if (res) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				case 22:
					if (res != OPH_SERVER_ERROR) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				case 23:
				case 24:
				case 25:
				case 26:
					if (res != OPH_SERVER_NULL_POINTER) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				case 27:
				case 28:
					if (res != OPH_SERVER_SYSTEM_ERROR) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				case 29:
					if (res != OPH_SERVER_NO_RESPONSE) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				case 31:
					if (res) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "No query expected\n");
						goto _EXIT_1;
					}
					break;

				default:
					if (res) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_1;
					}
					if (!query) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Expected return query\n");
						goto _EXIT_1;
					}
					if (strcmp(query, equery[option < filter_num ? option : 0])) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong return query: %s\n", query);
						goto _EXIT_1;
					}
			}

			char object_name[OPH_MAX_STRING_SIZE];
			if (option < filter_num)
				switch (option) {
					case 1:
						if (output_list_dim != 3) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", output_list_dim);
							goto _EXIT_1;
						}
						if (!output_list) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_1;
						}
						for (j = 0; j < output_list_dim; ++j) {
							snprintf(object_name, OPH_MAX_STRING_SIZE, "%s/1/%d", oph_web_server, j + 1);
							if (strcmp(output_list[j], object_name)) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object '%s' returned from the function\n", output_list[j]);
								goto _EXIT_1;
							}
						}
						break;

					case 9:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_1;
						}
						break;

					case 16:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_1;
						}
						if (wf->tasks[0].light_tasks_num != 3) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", output_list_dim);
							goto _EXIT_1;
						}
						if (!wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_1;
						}
						for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
							if (!wf->tasks[0].light_tasks[j].arguments_keys || !wf->tasks[0].light_tasks[j].arguments_values) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad arguments in object %d returned from the function\n", j);
								goto _EXIT_1;
							}
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_keys[0], "cube")) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object 'cube' returned from the function\n");
								goto _EXIT_1;
							}
							snprintf(object_name, OPH_MAX_STRING_SIZE, "%d", 2 * j + 1);
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_values[0], object_name)) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object '%s' returned from the function\n", wf->tasks[0].light_tasks[j].arguments_values[0]);
								goto _EXIT_1;
							}
						}
						break;

					case 17:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_1;
						}
						if (wf->tasks[0].light_tasks_num != 7) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", wf->tasks[0].light_tasks_num);
							goto _EXIT_1;
						}
						if (!wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_1;
						}
						for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
							if (wf->tasks[0].light_tasks[j].arguments_num != 3) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of arguments of object %d returned from the function: %d\n", j,
								      wf->tasks[0].light_tasks[j].arguments_num);
								goto _EXIT_1;
							}
							if (!wf->tasks[0].light_tasks[j].arguments_keys || !wf->tasks[0].light_tasks[j].arguments_values) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad arguments in object %d returned from the function\n", j);
								goto _EXIT_1;
							}
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_keys[0], "cube")) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object 'cube' returned from the function\n");
								goto _EXIT_1;
							}
						}
						break;

					case 18:
					case 22:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_1;
						}
						if (wf->tasks[0].light_tasks_num) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", output_list_dim);
							goto _EXIT_1;
						}
						if (wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_1;
						}
						break;

					default:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_1;
						}
						if (wf->tasks[0].light_tasks_num != 3) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", wf->tasks[0].light_tasks_num);
							goto _EXIT_1;
						}
						if (!wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_1;
						}
						for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
							if (wf->tasks[0].light_tasks[j].arguments_num != 3) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of arguments of object %d returned from the function: %d\n", j,
								      wf->tasks[0].light_tasks[j].arguments_num);
								goto _EXIT_1;
							}
							if (!wf->tasks[0].light_tasks[j].arguments_keys || !wf->tasks[0].light_tasks[j].arguments_values) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad arguments in object %d returned from the function\n", j);
								goto _EXIT_1;
							}
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_keys[0], "cube")) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object 'cube' returned from the function\n");
								goto _EXIT_1;
							}
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Argument value for %d: %s\n", j, wf->tasks[0].light_tasks[j].arguments_values[0]);
							snprintf(object_name, OPH_MAX_STRING_SIZE, "%s/1/%d", oph_web_server, j + 1);
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_values[0], object_name)) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object '%s' returned from the function\n", wf->tasks[0].light_tasks[j].arguments_values[0]);
								goto _EXIT_1;
							}
						}
				}

			return_value = 0;

		      _EXIT_1:
			for (j = 0; j < output_list_dim; ++j)
				if (output_list[j])
					free(output_list[j]);
			if (output_list)
				free(output_list);
			output_list = NULL;
			if (query)
				free(query);
			query = NULL;

			if (return_value)
				goto _EXIT_3;

#else
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Test skipped with this configuration\n");
#endif

		} else {
			option -= test_on_data_num;

			int filter_num = 25;
			char *filter[] = {
				"[testdata/*]",
				"[testdata/*.test]",
				"[testdata/testdata2/*]",
				"[testdata/testdata2/*.tst]",
				"[path= testdata;recursive=no]",
				"[path=testdata;recursive=yes;]",
				"[path=testdata/testdata2;recursive=no]",
				"[path=testdata/testdata2;recursive=yes]",
				"[path=testdata;file=*1*]",
				"[path=testdata;file=*1*;recursive=yes]",
				"[path=testdata;file=*12*;recursive=yes]",
				"[path=testdata/testdata2;file=*2*te*;recursive=yes]",
				"[path=testdata;file=nofile]",
				"[path=testdata;file={nofile}]",
				"[path=testdata;convention=cmip5]|[path=testdata/a;convention=cmip5]",
				"[path=testdata;convention=cmip5;recursive=yes]",
				"[file={nofile}]",
				"[wrong",
				"[path=testdata;run=no;measure=measure]",
				"[path=*;recursive=yes]",
				"[path=testdata/wrong*]",
				"[..]",
				"[path=testdata]",
				"[path=testdata]",
				"[path=testdata2]"
			};

			// Tasks
			wf->tasks_num = 1;
			wf->residual_tasks_num = 1;
			wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));

			// MASSIVE
			wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
			wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
			wf->tasks[0].name = strdup("MASSIVE");
			wf->tasks[0].operator = strdup("oph_massive");
			wf->tasks[0].role = oph_code_role("read");
			wf->tasks[0].ncores = wf->ncores;
			wf->tasks[0].arguments_num = 4;
			wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
			wf->tasks[0].arguments_keys[0] = strdup("src_path");
			wf->tasks[0].arguments_keys[1] = strdup("cwd");
			wf->tasks[0].arguments_keys[2] = strdup("measure");
			wf->tasks[0].arguments_keys[3] = strdup("cdd");
			wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
			wf->tasks[0].arguments_values[0] = strdup(filter[option < filter_num ? option : 0]);
			wf->tasks[0].arguments_values[1] = strdup(wf->cwd);
			wf->tasks[0].arguments_values[2] = strdup("x");
			wf->tasks[0].arguments_values[3] = strdup("/");
			wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
			wf->tasks[0].run = 1;

			switch (option) {

				case 22:
					free(wf->tasks[0].arguments_values[3]);
					wf->tasks[0].arguments_values[3] = strdup("wrong");
					break;

				case 23:
					free(wf->tasks[0].arguments_values[3]);
					wf->tasks[0].arguments_values[3] = strdup("/wrong/../wrong");
					break;

				case 24:
					free(wf->tasks[0].arguments_values[3]);
					wf->tasks[0].arguments_values[3] = strdup("/testdata");
					break;

				default:;
			}

			ophidiadb oDB;
			oph_odb_initialize_ophidiadb(&oDB);

			char **output_list = NULL;
			int res, j, output_list_dim = 0;

			struct oph_plugin_data *state = (struct oph_plugin_data *) calloc(1, sizeof(struct oph_plugin_data));
			if (!state) {
				goto _EXIT_3;
			}

			oph_job_list *job_info;
			if (oph_create_job_list(&job_info)) {
				free(state);
				goto _EXIT_3;
			}
			state->job_info = job_info;

			if (oph_wf_list_append(job_info, wf)) {
				oph_destroy_job_list(job_info);
				free(state);
				goto _EXIT_3;
			}

			oph_trash *trash;
			if (oph_trash_create(&trash)) {
				oph_destroy_job_list(job_info);
				free(state);
				return 1;
			}
			state->trash = trash;
			state->serverid = strdup(oph_web_server);

			pthread_mutex_lock(&global_flag);
			res = oph_check_for_massive_operation(state, 'T', 0, wf, 0, &oDB, &output_list, &output_list_dim, NULL, NULL);
			pthread_mutex_unlock(&global_flag);

			switch (option) {

				case 17:
				case 21:
				case 22:
				case 23:
					if (res != OPH_SERVER_ERROR) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_2;
					}
					break;

				case 18:
					if (res != OPH_SERVER_NO_RESPONSE) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_2;
					}
					break;

				default:
					if (res != OPH_SERVER_OK) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
						goto _EXIT_2;
					}
			}

			if (option < filter_num)
				switch (option) {

					case 17:
					case 21:
					case 22:
					case 23:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_2;
						}
						if (wf->tasks[0].light_tasks_num) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", wf->tasks[0].light_tasks_num);
							goto _EXIT_2;
						}
						if (wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_2;
						}
						break;

					case 14:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_2;
						}
						if (wf->tasks[0].light_tasks_num != 2) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", wf->tasks[0].light_tasks_num);
							goto _EXIT_2;
						}
						if (!wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_2;
						}
						for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
							if (wf->tasks[0].light_tasks[j].arguments_num != 4) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of arguments of object %d returned from the function: %d\n", j,
								      wf->tasks[0].light_tasks[j].arguments_num);
								goto _EXIT_2;
							}
							if (!wf->tasks[0].light_tasks[j].arguments_keys || !wf->tasks[0].light_tasks[j].arguments_values) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad arguments in object %d returned from the function\n", j);
								goto _EXIT_2;
							}
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_keys[0], "src_path")) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object 'cube' returned from the function\n");
								goto _EXIT_2;
							}
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Argument value for %d: %s\n", j, wf->tasks[0].light_tasks[j].arguments_values[0]);
						}
						break;

					case 18:
						if (!output_list || !output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is empty\n");
							goto _EXIT_2;
						}
						if (wf->tasks[0].light_tasks_num) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", wf->tasks[0].light_tasks_num);
							goto _EXIT_2;
						}
						if (wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_2;
						}
						for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
							if (wf->tasks[0].light_tasks[j].arguments_num != 4) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of arguments of object %d returned from the function: %d\n", j,
								      wf->tasks[0].light_tasks[j].arguments_num);
								goto _EXIT_2;
							}
							if (!wf->tasks[0].light_tasks[j].arguments_keys || !wf->tasks[0].light_tasks[j].arguments_values) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad arguments in object %d returned from the function\n", j);
								goto _EXIT_2;
							}
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_keys[0], "src_path")) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object 'cube' returned from the function\n");
								goto _EXIT_2;
							}
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Argument value for %d: %s\n", j, wf->tasks[0].light_tasks[j].arguments_values[0]);
						}
						break;

					default:
						if (output_list || output_list_dim) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Object list is not empty: it contains %d objects\n", output_list_dim);
							goto _EXIT_2;
						}
						if (wf->tasks[0].light_tasks_num != 1) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of objects returned from the function: %d\n", wf->tasks[0].light_tasks_num);
							goto _EXIT_2;
						}
						if (!wf->tasks[0].light_tasks) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object list returned from the function\n");
							goto _EXIT_2;
						}
						for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
							if (wf->tasks[0].light_tasks[j].arguments_num != 4) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad number of arguments of object %d returned from the function: %d\n", j,
								      wf->tasks[0].light_tasks[j].arguments_num);
								goto _EXIT_2;
							}
							if (!wf->tasks[0].light_tasks[j].arguments_keys || !wf->tasks[0].light_tasks[j].arguments_values) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad arguments in object %d returned from the function\n", j);
								goto _EXIT_2;
							}
							if (strcmp(wf->tasks[0].light_tasks[j].arguments_keys[0], "src_path")) {
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object 'cube' returned from the function\n");
								goto _EXIT_2;
							}
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Argument value for %d: %s\n", j, wf->tasks[0].light_tasks[j].arguments_values[0]);
						}
				}

			switch (option) {

				default:
					for (j = 0; j < wf->tasks[0].light_tasks_num; ++j) {
						if (strcmp(wf->tasks[0].light_tasks[j].arguments_values[0], "/test.test")) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad object '%s' returned from the function\n", wf->tasks[0].light_tasks[j].arguments_values[0]);
							goto _EXIT_2;
						}
					}

			}

			return_value = 0;

		      _EXIT_2:
			for (j = 0; j < output_list_dim; ++j)
				if (output_list[j])
					free(output_list[j]);
			if (output_list)
				free(output_list);
			output_list = NULL;

			wf = NULL;
			oph_destroy_job_list(job_info);
			oph_trash_destroy(trash);
			if (state->serverid)
				free(state->serverid);
			free(state);

			if (return_value)
				goto _EXIT_3;
		}

	} else if (!strcmp(function, "oph_set_impl")) {

		// Tasks
		wf->tasks_num = 1;
		wf->residual_tasks_num = 1;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// SET
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("SET");
		wf->tasks[0].operator = strdup("oph_set");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 2;
		wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_keys[0] = strdup("key");
		wf->tasks[0].arguments_keys[1] = strdup("value");
		wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_values[0] = strdup("variable");
		wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 0;
		wf->tasks[0].dependents_indexes = NULL;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		char error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		switch (option) {

			case 0:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
				}
				break;

			case 1:
				{
					oph_workflow_var var;
					var.caller = -1;
					var.ivalue = 1;
					var.svalue = strdup("value");
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, "goodvariable", var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);
					wf->tasks[0].arguments_values[1] = strdup("@goodvariable");
				}
				break;

			case 2:
				{
					wf->tasks[0].arguments_values[1] = strdup("@badvariable");
				}
				break;

			default:;
		}

		int res = oph_set_impl(wf, 0, error_message, NULL, 0);

		switch (option) {

			default:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
		}

	} else if (!strcmp(function, "oph_input_impl")) {

		// Tasks
		wf->tasks_num = 3;
		wf->residual_tasks_num = 3;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		if ((option < 6) || (option > 11))
			wf->tasks[0].arguments_num = 3;
		else
			wf->tasks[0].arguments_num = 4;

		// INPUT
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("INPUT");
		wf->tasks[0].operator = strdup("oph_input");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_keys[0] = strdup("key");
		wf->tasks[0].arguments_keys[1] = strdup("value");
		wf->tasks[0].arguments_keys[2] = strdup("taskname");
		wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
		wf->tasks[0].arguments_values[0] = strdup("variable");
		wf->tasks[0].arguments_values[2] = strdup("WAIT");
		wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 0;
		wf->tasks[0].dependents_indexes = NULL;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		// WAIT
		wf->tasks[1].idjob = wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_RUNNING;
		wf->tasks[1].name = strdup("WAIT");
		wf->tasks[1].operator = strdup("oph_wait");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 1;
		wf->tasks[1].arguments_keys = (char **) calloc(wf->tasks[1].arguments_num, sizeof(char *));
		wf->tasks[1].arguments_keys[0] = strdup("timeout");
		wf->tasks[1].arguments_values = (char **) calloc(wf->tasks[1].arguments_num, sizeof(char *));
		wf->tasks[1].arguments_values[0] = strdup("10");
		wf->tasks[1].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[1].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[1].deps_num = 0;
		wf->tasks[1].deps = NULL;
		wf->tasks[1].dependents_indexes_num = 0;
		wf->tasks[1].dependents_indexes = NULL;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// WAIT
		wf->tasks[2].idjob = wf->tasks[1].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_RUNNING;
		wf->tasks[2].name = strdup("WAIT2");
		wf->tasks[2].operator = strdup("oph_wait");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 1;
		wf->tasks[2].arguments_keys = (char **) calloc(wf->tasks[2].arguments_num, sizeof(char *));
		wf->tasks[2].arguments_keys[0] = strdup("timeout");
		wf->tasks[2].arguments_values = (char **) calloc(wf->tasks[2].arguments_num, sizeof(char *));
		wf->tasks[2].arguments_values[0] = strdup("20");
		wf->tasks[2].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[2].arguments_num, sizeof(oph_workflow_ordered_list *));
		wf->tasks[2].deps_num = 0;
		wf->tasks[2].deps = NULL;
		wf->tasks[2].dependents_indexes_num = 0;
		wf->tasks[2].dependents_indexes = NULL;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = -1;

		char error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		switch (option) {

			case 0:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
				}
				break;

			case 1:
				{
					oph_workflow_var var;
					var.caller = -1;
					var.ivalue = 1;
					var.svalue = strdup("value");
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, "goodvariable", var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);
					wf->tasks[0].arguments_values[1] = strdup("@goodvariable");
				}
				break;

			case 2:
				{
					wf->tasks[0].arguments_values[1] = strdup("@badvariable");
				}
				break;

			case 3:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					free(wf->tasks[0].arguments_values[2]);
					wf->tasks[0].arguments_values[2] = strdup("wrong");
				}
				break;

			case 4:
				{
					wf->tasks[0].arguments_values[1] = strdup("value|discarded");
				}
				break;

			case 5:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("variable|wrong");
				}
				break;

			case 6:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					wf->tasks[0].arguments_keys[3] = strdup("id");
					wf->tasks[0].arguments_values[3] = strdup("1");
				}
				break;

			case 7:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					wf->tasks[0].arguments_keys[3] = strdup("id");
					wf->tasks[0].arguments_values[3] = strdup("-1");
				}
				break;

			case 8:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					wf->tasks[0].arguments_keys[3] = strdup("action");
					wf->tasks[0].arguments_values[3] = strdup("continue");
				}
				break;

			case 9:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					wf->tasks[0].arguments_keys[3] = strdup("action");
					wf->tasks[0].arguments_values[3] = strdup("wait");
				}
				break;

			case 10:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					wf->tasks[0].arguments_keys[3] = strdup("action");
					wf->tasks[0].arguments_values[3] = strdup("abort");
				}
				break;

			case 11:
				{
					wf->tasks[0].arguments_values[1] = strdup("value");
					wf->tasks[0].arguments_keys[3] = strdup("action");
					wf->tasks[0].arguments_values[3] = strdup("wrong");
				}
				break;

			case 12:
				{
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("@badvariable");
					wf->tasks[0].arguments_values[1] = strdup("value");
				}
				break;

			case 13:
				{
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("special:");
					wf->tasks[0].arguments_values[1] = strdup("value");
				}
				break;

			case 14:
				{
					free(wf->tasks[0].arguments_values[0]);
					wf->tasks[0].arguments_values[0] = strdup("1ndex");
					wf->tasks[0].arguments_values[1] = strdup("value");
				}
				break;

			default:;
		}

		int res = oph_set_impl(wf, 0, error_message, NULL, 1);

		switch (option) {

			case 3:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Invalid task name, task not found or ambiguous!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 5:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad number of keys in parameter 'value'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 7:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong workflow identifier '-1'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 11:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong action 'wrong'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 12:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad argument 'key'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 13:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad argument 'key'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			case 14:
				if (res || strcmp(error_message, "Change variable name '1ndex'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			default:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
		}

	} else if (!strcmp(function, "oph_wait_impl")) {

		// Tasks
		wf->tasks_num = 1;
		wf->residual_tasks_num = 1;
		wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// WAIT
		wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("WAIT");
		wf->tasks[0].operator = strdup("oph_wait");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 0;
		wf->tasks[0].dependents_indexes = NULL;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		char error_message[OPH_MAX_STRING_SIZE], *message = NULL;
		*error_message = 0;

		switch (option) {
			case 0:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("timeout_type");
					wf->tasks[0].arguments_keys[3] = strdup("cube");
					wf->tasks[0].arguments_keys[4] = strdup("cwd");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("2030-01-01 00:00:00");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("deadline");
					wf->tasks[0].arguments_values[3] = strdup("http://localhost/1");
					wf->tasks[0].arguments_values[4] = strdup(wf->cwd);
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 1:
				{
					wf->tasks[0].arguments_num = 3;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("timeout_type");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("2010-01-01 00:00:00");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("deadline");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 2:
				{
					wf->tasks[0].arguments_num = 3;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("timeout_type");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("wrong");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 3:
				{
					wf->tasks[0].arguments_num = 3;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("wrong");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 4:
				{
					wf->tasks[0].arguments_num = 4;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("filename");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("file");
					wf->tasks[0].arguments_values[3] = strdup("filename");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 5:
				{
					wf->tasks[0].arguments_num = 3;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("message");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("message");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 6:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("variable");
					wf->tasks[0].arguments_values[4] = strdup("value");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 7:
				{
					wf->tasks[0].arguments_num = 3;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("wrong");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 8:
				{
					oph_workflow_var var;
					var.caller = -1;
					var.ivalue = 1;
					var.svalue = strdup("value");
					svalue_size = strlen(var.svalue) + 1;
					var_buffer = malloc(var_size + svalue_size);
					memcpy(var_buffer, (void *) &var, var_size);
					memcpy(var_buffer + var_size, var.svalue, svalue_size);
					if (hashtbl_insert_with_size(wf->vars, "goodvariable", var_buffer, var_size + svalue_size)) {
						free(var.svalue);
						free(var_buffer);
						goto _EXIT_3;
					}
					free(var.svalue);
					free(var_buffer);

					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("variable");
					wf->tasks[0].arguments_values[4] = strdup("@goodvariable");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 9:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("variable");
					wf->tasks[0].arguments_values[4] = strdup("@badvariable");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 10:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("1ndex");
					wf->tasks[0].arguments_values[4] = strdup("value");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 11:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("special:");
					wf->tasks[0].arguments_values[4] = strdup("value");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 12:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("variable");
					wf->tasks[0].arguments_values[4] = strdup("value|value2");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			case 13:
				{
					wf->tasks[0].arguments_num = 5;
					wf->tasks[0].arguments_keys = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_keys[0] = strdup("timeout");
					wf->tasks[0].arguments_keys[1] = strdup("run");
					wf->tasks[0].arguments_keys[2] = strdup("type");
					wf->tasks[0].arguments_keys[3] = strdup("key");
					wf->tasks[0].arguments_keys[4] = strdup("value");
					wf->tasks[0].arguments_values = (char **) calloc(wf->tasks[0].arguments_num, sizeof(char *));
					wf->tasks[0].arguments_values[0] = strdup("10");
					wf->tasks[0].arguments_values[1] = strdup("no");
					wf->tasks[0].arguments_values[2] = strdup("input");
					wf->tasks[0].arguments_values[3] = strdup("variable|variable2");
					wf->tasks[0].arguments_values[4] = strdup("value");
					wf->tasks[0].arguments_lists = (oph_workflow_ordered_list **) calloc(wf->tasks[0].arguments_num, sizeof(oph_workflow_ordered_list *));
				}
				break;

			default:;
		}

		oph_notify_data *data = (oph_notify_data *) malloc(sizeof(oph_notify_data));
		if (!data) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			goto _EXIT_3;
		}
		data->wf = wf;
		data->task_index = 0;
		data->json_output = NULL;
		data->data = NULL;
		data->run = data->detach = 1;
		data->state = NULL;
		data->add_to_notify = NULL;

		int res = oph_wait_impl(wf, 0, error_message, &message, data);

		if (message)
			free(message);

		if (data->add_to_notify)
			free(data->add_to_notify);
		oph_wait_data *wd = (oph_wait_data *) data->data;
		if (wd) {
			if (wd->filename)
				free(wd->filename);
			free(wd);
		}
		free(data);

		switch (option) {

			case 1:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Timeout can be infinity only for type 'input'. Use a non-negative value!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 2:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong timeout type 'wrong'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 3:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong value 'wrong' for parameter 'run'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 7:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Wrong type 'wrong'!")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 10:
				if (res || strcmp(error_message, "Change variable name '1ndex'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 11:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad argument 'key'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;
			case 13:
				if ((res != OPH_SERVER_ERROR) || strcmp(error_message, "Bad number of keys in parameter 'value'.")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error message: %s\n", error_message);
					goto _EXIT_3;
				}
				break;

			default:
				if (res || strlen(error_message)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\nError message: %s\n", res, error_message);
					goto _EXIT_3;
				}
		}
	} else if (!strcmp(function, "oph_filters")) {

		int res, i, j;
		char tables[OPH_MAX_STRING_SIZE], where_clause[OPH_MAX_STRING_SIZE], query[OPH_MAX_STRING_SIZE];
		*tables = *where_clause = 0;

		switch (option) {

			case 0:
				res = oph_filter_level(NULL, tables, where_clause, NULL, 0);
				break;

			case 1:
				res = oph_filter_level("", tables, where_clause, NULL, 0);
				break;

			case 2:
				res = oph_filter_level("level=", tables, where_clause, NULL, 0);
				break;

			case 3:
				res = oph_filter_level("1", tables, where_clause, NULL, 0);
				break;

			case 4:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					*tables = where_clause[i] = 0;
					res = oph_filter_level("1", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 5:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					*tables = where_clause[i] = 0;
					res = oph_filter_level("1|2|3", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 6:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					*tables = where_clause[i] = 0;
					res = oph_filter_measure("measure", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 7:
				res = oph_filter_parent("wrong", tables, where_clause, NULL, 0);
				break;

			case 8:
				res = oph_filter_parent("http://localhostwrong", tables, where_clause, NULL, 0);
				break;

			case 9:
				res = oph_filter_parent("http://localhost/", tables, where_clause, NULL, 0);
				break;

			case 10:
				res = oph_filter_parent("http://localhost/wrong", tables, where_clause, NULL, 0);
				break;

			case 11:
				for (j = 0; j < 300; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					*tables = where_clause[i] = 0;
					res = oph_filter_parent("http://localhost/1/1", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 12:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						tables[i] = ' ';
					*where_clause = tables[i] = 0;
					res = oph_filter_parent("http://localhost/1/1", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 13:
				res = oph_filter_using_subset("1:1:1:1", tables, where_clause, NULL, 0);
				break;

			case 14:
				for (j = 0; j < 200; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					where_clause[i] = 0;
					res = oph_filter_using_subset("1:2,3", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 15:
				res = oph_filter_container("", tables, where_clause, NULL, 0);
				break;

			case 16:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					where_clause[i] = 0;
					res = oph_filter_container("container", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 17:
				res = oph_filter_container_pid("", tables, where_clause, NULL, 0);
				break;

			case 18:
				res = oph_filter_container_pid("wrong", tables, where_clause, NULL, 0);
				break;

			case 19:
				res = oph_filter_container_pid("http://localhostwrong", tables, where_clause, NULL, 0);
				break;

			case 20:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					where_clause[i] = 0;
					res = oph_filter_container_pid("http://localhost/1", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 21:
				res = oph_filter_metadata_key("", tables, where_clause, NULL, 0);
				break;

			case 22:
				res = oph_filter_metadata_key("key=", tables, where_clause, NULL, 0);
				break;

			case 23:
				for (j = 0; j < 300; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					*tables = where_clause[i] = 0;
					res = oph_filter_metadata_key("key1|key2", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 24:
				for (j = 0; j < 300; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						tables[i] = ' ';
					*where_clause = tables[i] = 0;
					res = oph_filter_metadata_key("key1|key2", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 25:
				res = oph_filter_metadata_value("", "", tables, where_clause, NULL, 0);
				break;

			case 26:
				res = oph_filter_metadata_value("", "value=", tables, where_clause, NULL, 0);
				break;

			case 27:
				res = oph_filter_metadata_value("key1|key2", "value=", tables, where_clause, NULL, 0);
				break;

			case 28:
				res = oph_filter_metadata_value("key1|key2", "value", tables, where_clause, NULL, 0);
				break;

			case 29:
				res = oph_filter_metadata_value("key=", "value", tables, where_clause, NULL, 0);
				break;

			case 30:
				for (j = 0; j < 600; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					*tables = where_clause[i] = 0;
					res = oph_filter_metadata_value("key1|key2", "value1|value2", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 31:
				for (j = 0; j < 600; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						tables[i] = ' ';
					*where_clause = tables[i] = 0;
					res = oph_filter_metadata_value("key1|key2", "value1|value2", tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 32:
				res = oph_filter_path("", "yes", "2", sessionid, NULL, tables, where_clause, NULL, 0);
				break;

			case 33:
				res = oph_filter_path("/", "yes", "2", sessionid, NULL, tables, where_clause, NULL, 0);
				break;

			case 34:
				res = oph_filter_path("/123/", "yes", "2", NULL, NULL, tables, where_clause, NULL, 0);
				break;

			case 35:
				res = oph_filter_path("/123/", "yes", "2", sessionid, NULL, tables, where_clause, NULL, 0);
				break;

			case 36:
				for (j = 0; j < 100; ++j) {
					for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
						where_clause[i] = ' ';
					where_clause[i] = 0;
					res = oph_filter_path("/123/path/to/container", "yes", "2", sessionid, NULL, tables, where_clause, NULL, 0);
					if (!res)
						break;
				}
				break;

			case 37:
				{
					res = OPH_MF_ERROR;
					HASHTBL *task_tbl = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
					if (!task_tbl)
						break;
					hashtbl_insert(task_tbl, "key1", "value1");
					hashtbl_insert(task_tbl, "key2", "value2");
					for (j = 0; j < 600; ++j) {
						for (i = 0; i < OPH_MAX_STRING_SIZE - j - 2; ++i)
							where_clause[i] = ' ';
						*tables = where_clause[i] = 0;
						res = oph_filter_free_kvp(task_tbl, tables, where_clause, NULL, 0);
						if (!res)
							break;
					}
					hashtbl_destroy(task_tbl);
				}
				break;

			case 38:
				res = _oph_filter(NULL, NULL, NULL, NULL, NULL, NULL);
				break;

			case 39:
				res = _oph_filter(NULL, "", NULL, "", NULL, NULL);
				break;

			case 40:
				res = _oph_filter(NULL, query, " path ", sessionid, NULL, NULL);
				break;

			case 41:
				{
					res = OPH_MF_ERROR;
					HASHTBL *task_tbl = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
					if (!task_tbl)
						break;
					hashtbl_insert(task_tbl, OPH_MF_ARG_LEVEL, "=");
					res = _oph_filter(task_tbl, query, "/123/", sessionid, NULL, NULL);
					hashtbl_destroy(task_tbl);
				}
				break;

			case 42:
				{
					res = OPH_MF_ERROR;
					HASHTBL *task_tbl = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
					if (!task_tbl)
						break;
					hashtbl_insert(task_tbl, OPH_MF_ARG_PARENT, "////");
					res = _oph_filter(task_tbl, query, "/123/", sessionid, NULL, NULL);
					hashtbl_destroy(task_tbl);
				}
				break;

			case 43:
				{
					res = OPH_MF_ERROR;
					HASHTBL *task_tbl = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
					if (!task_tbl)
						break;
					hashtbl_insert(task_tbl, OPH_MF_ARG_DATACUBE_FILTER, "1:2:3:4:5");
					res = _oph_filter(task_tbl, query, "/123/", sessionid, NULL, NULL);
					hashtbl_destroy(task_tbl);
				}
				break;

			case 44:
				{
					res = OPH_MF_ERROR;
					HASHTBL *task_tbl = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
					if (!task_tbl)
						break;
					hashtbl_insert(task_tbl, OPH_MF_ARG_CONTAINER_PID, "////");
					res = _oph_filter(task_tbl, query, "/123/", sessionid, NULL, NULL);
					hashtbl_destroy(task_tbl);
				}
				break;

			case 45:
				{
					for (i = 0; i < OPH_MAX_STRING_SIZE - 2; ++i)
						where_clause[i] = ' ';
					where_clause[i] = 0;
					res = OPH_MF_ERROR;
					HASHTBL *task_tbl = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
					if (!task_tbl)
						break;
					hashtbl_insert(task_tbl, OPH_MF_ARG_METADATA_KEY, "key");
					hashtbl_insert(task_tbl, OPH_MF_ARG_METADATA_VALUE, "value|value");
					res = _oph_filter(task_tbl, query, "/123/", sessionid, NULL, NULL);
					hashtbl_destroy(task_tbl);
				}
				break;

		}

		switch (option) {

			case 0:
			case 1:
			case 3:
			case 4:
			case 5:
			case 6:
			case 11:
			case 12:
			case 14:
			case 15:
			case 16:
			case 17:
			case 20:
			case 21:
			case 23:
			case 24:
			case 25:
			case 30:
			case 31:
			case 32:
			case 35:
			case 36:
			case 37:
			case 40:
				if (res) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
					goto _EXIT_3;
				}
				break;

			default:
				if (res != OPH_MF_ERROR) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
					goto _EXIT_3;
				}
		}

	} else if (!strcmp(function, "misc")) {

		int res = 1;
		unsigned int c = 0;
		char *buffer = NULL;

		switch (option) {

			case 0:
				{
					char **block = (char **) malloc(2 * sizeof(char *));
					if (!block)
						break;
					block[0] = strdup("");
					if (!block[0]) {
						free(block);
						break;
					}
					block[1] = strdup("");
					if (!block[1]) {
						free(block[0]);
						free(block);
						break;
					}
					freeBlock(&block, 2);
					res = 0;
				}
				break;

			case 1:
				res = _oph_mf_parse_KV(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL);
				break;

			case 2:
				res = _oph_mf_parse_query(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL);
				break;

			case 3:
				_oph_wait(NULL);
				break;

			case 4:
				{
					oph_notify_data *data = (oph_notify_data *) malloc(sizeof(oph_notify_data));
					if (!data)
						break;
					data->wf = wf;
					data->task_index = 0;
					data->json_output = NULL;
					data->data = NULL;
					data->run = data->detach = 1;
					data->state = NULL;
					data->add_to_notify = strdup("");

					oph_wait_data *wd = (oph_wait_data *) malloc(sizeof(oph_wait_data));
					if (!wd)
						break;
					wd->type = 'w';	// Wrong type
					wd->timeout = -1;
					wd->filename = NULL;
					wd->measure = NULL;
					data->data = (void *) wd;

					// Tasks
					wf->tasks_num = wf->residual_tasks_num = 1;
					wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));

					_oph_wait(data);

					res = 0;
				}
				break;

			case 5:
				{
					oph_notify_data *data = (oph_notify_data *) malloc(sizeof(oph_notify_data));
					if (!data)
						break;
					data->wf = wf;
					data->task_index = 0;
					data->json_output = NULL;
					data->data = NULL;
					data->run = data->detach = 1;
					data->state = NULL;
					data->add_to_notify = strdup("");

					oph_wait_data *wd = (oph_wait_data *) malloc(sizeof(oph_wait_data));
					if (!wd)
						break;
					wd->type = 'f';
					wd->timeout = -1;
					wd->filename = strdup("testdata/a_12.test");
					wd->measure = NULL;
					data->data = (void *) wd;

					// Tasks
					wf->tasks_num = wf->residual_tasks_num = 1;
					wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
					wf->vars = hashtbl_create(wf->tasks_num, NULL);

					// WAIT
					wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
					wf->tasks[0].name = strdup("WAIT");
					wf->tasks[0].operator = strdup("oph_wait");
					wf->tasks[0].arguments_num = 0;
					wf->tasks[0].arguments_keys = NULL;
					wf->tasks[0].arguments_values = NULL;
					wf->tasks[0].arguments_lists = NULL;
					wf->tasks[0].deps_num = 0;
					wf->tasks[0].deps = NULL;
					wf->tasks[0].dependents_indexes_num = 0;
					wf->tasks[0].dependents_indexes = NULL;

					_oph_wait(data);

					res = 0;
				}
				break;

			case 6:
				{
					// Tasks
					wf->tasks_num = wf->residual_tasks_num = 1;
					wf->tasks = (oph_workflow_task *) calloc(1 + wf->tasks_num, sizeof(oph_workflow_task));
					wf->vars = hashtbl_create(wf->tasks_num, NULL);

					// WAIT
					wf->tasks[0].idjob = wf->tasks[0].markerid = 2;
					wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
					wf->tasks[0].name = strdup("WAIT");
					wf->tasks[0].operator = strdup("oph_wait");
					wf->tasks[0].arguments_num = 0;
					wf->tasks[0].arguments_keys = NULL;
					wf->tasks[0].arguments_values = NULL;
					wf->tasks[0].arguments_lists = NULL;
					wf->tasks[0].deps_num = 0;
					wf->tasks[0].deps = NULL;
					wf->tasks[0].dependents_indexes_num = 1;	// Wrong
					wf->tasks[0].dependents_indexes = NULL;
					res = oph_set_status_of_selection_block(wf, 0, OPH_ODB_STATUS_UNSELECTED, -1, 0, 1, NULL);

					wf->tasks[0].dependents_indexes_num = 0;
				}
				break;

			case 7:
				res = oph_extract_from_json(NULL, "");
				break;

			case 8:
				{
					char *key = strdup("");
					res = oph_extract_from_json(&key, "");
					if (key)
						free(key);
				}
				break;

			case 9:
				{
					char *key = strdup("a.b.c.d");
					res = oph_extract_from_json(&key, "");
					if (key)
						free(key);
				}
				break;

			case 10:
				{
					char *key = strdup("a.b.c(d");
					res = oph_extract_from_json(&key, "");
					if (key)
						free(key);
				}
				break;

			case 11:
				{
					char *key = strdup("a(b,c");
					res = oph_extract_from_json(&key, "");
					if (key)
						free(key);
				}
				break;

			case 12:
				{
					char *key = strdup("a(b,c)");
					res = oph_extract_from_json(&key, "");
					if (key)
						free(key);
				}
				break;

			default:;
		}

		switch (option) {

			case 0:
			case 4:
			case 5:
				if (res) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
					goto _EXIT_3;
				}
				break;

			default:
				if (!res) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Return code: %d\n", res);
					goto _EXIT_3;
				}
		}
	}

	oph_workflow_free(wf);
	return 0;

      _EXIT_3:
	oph_workflow_free(wf);
	return 1;
}

int check_oph_server(int *i, int *f, int n, const char *function, int option, int abort_on_first_error, FILE * file)
{
	(*i)++;
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "TEST %d/%d: function '%s' input %d\n", *i, n, function, 1 + option);
	fprintf(file, "TEST %d/%d: function '%s' input %d ... ", *i, n, function, 1 + option);
	if (_check_oph_server(function, option)) {
		(*f)++;
		fprintf(file, "FAILED\n");
		if (abort_on_first_error)
			return 1;
	} else
		fprintf(file, "OK\n");
	return 0;
}

int main(int argc, char *argv[])
{
	UNUSED(argc);
	UNUSED(argv);
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_init(&global_flag, NULL);
	pthread_mutex_init(&libssh2_flag, NULL);
	pthread_mutex_init(&curl_flag, NULL);
	pthread_mutex_init(&service_flag, NULL);
	pthread_mutex_init(&savefile_flag, NULL);
	pthread_cond_init(&termination_flag, NULL);
	pthread_cond_init(&waiting_flag, NULL);
#endif

	int ch, msglevel = LOG_DEBUG, abort_on_first_error = 1;
	static char *USAGE = "\nUSAGE:\noph_server_test [-a] [-d] [-o output_file] [-v] [-w]\n";
	char *filename = "test_output.trs";

	fprintf(stdout, "%s", OPH_VERSION);
	fprintf(stdout, "%s", OPH_DISCLAIMER);

	set_debug_level(msglevel + 10);

	while ((ch = getopt(argc, argv, "ado:vw")) != -1) {
		switch (ch) {
			case 'a':
				abort_on_first_error = 1;
				break;
			case 'd':
				msglevel = LOG_DEBUG;
				break;
			case 'o':
				filename = optarg;
				break;
			case 'v':
				return 0;
				break;
			case 'w':
				if (msglevel < LOG_WARNING)
					msglevel = LOG_WARNING;
				break;
			default:
				fprintf(stdout, "%s", USAGE);
				return 0;
		}
	}

	set_debug_level(msglevel + 10);
	pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log level %d\n", msglevel);

	oph_server_location = strdup("..");
	oph_base_src_path = strdup(".");

	char configuration_file[OPH_MAX_STRING_SIZE];
	snprintf(configuration_file, OPH_MAX_STRING_SIZE, OPH_CONFIGURATION_FILE, getenv("PWD"));
	set_global_values(configuration_file);

	FILE *file = fopen(filename, "w");
	if (!file) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Output file cannot be created!\n");
		return 1;
	}

	int test_mode_num = 11;
	int test_num[] = { 12, 2, 32, 6, 13, 57, 3, 15, 14, 46, 13 };
	char *test_name[] = { "oph_if_impl", "oph_else_impl", "oph_for_impl", "oph_endfor_impl", "oph_serve_flow_control_operator", "oph_check_for_massive_operation", "oph_set_impl", "oph_input_impl",
		"oph_wait_impl", "oph_filters", "misc"
	};
	int i = 0, j, k, f = 0, n = 0;
	for (j = 0; j < test_mode_num; ++j)
		n += test_num[j];

	for (k = 0; k < test_mode_num; ++k)
		for (j = 0; j < test_num[k]; ++j)
			if (check_oph_server(&i, &f, n, test_name[k], j, abort_on_first_error, file)) {
				fclose(file);
				return 1;
			}

	if (f)
		fprintf(file, "WARNING: %d TASK%s FAILED out of %d\nSUCCESS RATE %.1f %%\n", f, f == 1 ? "" : "S", n, (n - f) * 100.0 / ((float) n));
	else
		fprintf(file, "SUCCESS: %d TASK%s PASSED out of %d\nSUCCESS RATE 100.0 %%\n", n, n == 1 ? "" : "S", n);

	fclose(file);

	cleanup();

	pmesg(LOG_INFO, __FILE__, __LINE__, "Exit with code %d\n", f);

	return f;
}
