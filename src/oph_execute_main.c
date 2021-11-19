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

#include "oph_auth.h"
#include "oph_plugin.h"
#include "oph_rmanager.h"
#include "oph_massive_operations.h"
#include "oph_odb_job.h"
#include "oph_memory_job.h"
#include "oph_json_library.h"
#include "oph_workflow_engine.h"
#include "oph_task_parser_library.h"
#include "oph_session_report.h"
#include "oph_service_info.h"
#include "hashtbl.h"

#ifdef INTERFACE_TYPE_IS_GSI
#include "gsi.h"
#endif

#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>

#define OPH_EXTRA "    \"extra\": {\n\
        \"keys\": [\n\
            %s\n\
        ],\n\
        \"values\": [\n\
            %s\n\
        ]\n\
    }\n"

extern int oph_service_status;
extern char oph_auth_enabled;
extern char *oph_auth_location;
extern char *oph_log_file_name;
extern char *oph_xml_operators;
extern char *oph_web_server;
extern char *oph_web_server_location;
extern char *oph_base_src_path;
extern FILE *wf_logfile;
extern oph_service_info *service_info;
extern char *oph_status_log_file_name;
extern unsigned int oph_default_max_sessions;
extern unsigned int oph_default_max_cores;
extern unsigned int oph_default_max_hosts;
extern unsigned int oph_default_session_timeout;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_cond_t termination_flag;
extern pthread_cond_t waiting_flag;
extern pthread_mutex_t curl_flag;
extern pthread_mutex_t service_flag;
#endif

#ifdef OPH_OPENID_SUPPORT
extern char oph_openid_allow_local_user;
#endif

void free_string_vector(char **ctime, int n)
{
	if (ctime) {
		int i;
		for (i = 0; i < n; ++i)
			if (ctime[i])
				free(ctime[i]);
		free(ctime);
	}
}

int oph_check_operator(const char *operator, int *ncores, int *nhosts, int *role)
{
	if (!ncores || !nhosts) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Null pointer\n");
		return OPH_SERVER_ERROR;
	}

	int previous = *ncores;
	char task_string[OPH_MAX_STRING_SIZE], value[OPH_MAX_STRING_SIZE], op_role[OPH_MAX_STRING_SIZE];
	*value = *op_role = 0;

	snprintf(task_string, OPH_MAX_STRING_SIZE, "%s=%d;", OPH_ARG_NCORES, *ncores);
	int result = oph_tp_task_param_checker_and_role(operator, task_string, OPH_ARG_NCORES, value, op_role);
	if (result == OPH_TP_TASK_SYSTEM_ERROR)
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	if (strlen(value))
		*ncores = (int) strtol(value, NULL, 10);
	else
		*ncores = OPH_DEFAULT_CORES;
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Input value for '%s' is %d, but effective value is '%d'\n", OPH_ARG_NCORES, previous, *ncores);

	*value = 0;
	snprintf(task_string, OPH_MAX_STRING_SIZE, "%s=%d;", OPH_ARG_NHOSTS, *nhosts);
	result = oph_tp_task_param_checker_and_role(operator, task_string, OPH_ARG_NHOSTS, value, op_role);
	if (result == OPH_TP_TASK_SYSTEM_ERROR)
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	if (strlen(value))
		*nhosts = (int) strtol(value, NULL, 10);
	else
		*nhosts = OPH_DEFAULT_HOSTS;

	*role = oph_code_role(op_role);
	if (!(*role))
		*role = OPH_ROLE_READ;
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Permission to submit the command is '%s' (%d)\n", *op_role ? op_role : OPH_ROLE_READ_STR, *role);

	return OPH_SERVER_OK;
}

int oph_check_status_mask(enum oph__oph_odb_job_status status, char *smask)
{
	int i;
	if (!smask)
		return 0;
	switch (status) {
		case OPH_ODB_STATUS_PENDING:
			i = 0;
			break;
		case OPH_ODB_STATUS_WAIT:
			i = 1;
			break;
		case OPH_ODB_STATUS_RUNNING:
		case OPH_ODB_STATUS_START:
		case OPH_ODB_STATUS_SET_ENV:
		case OPH_ODB_STATUS_INIT:
		case OPH_ODB_STATUS_DISTRIBUTE:
		case OPH_ODB_STATUS_EXECUTE:
		case OPH_ODB_STATUS_REDUCE:
		case OPH_ODB_STATUS_DESTROY:
		case OPH_ODB_STATUS_UNSET_ENV:
			i = 2;
			break;
		case OPH_ODB_STATUS_COMPLETED:
			i = 3;
			break;
		case OPH_ODB_STATUS_ERROR:
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
			i = 4;
			break;
		case OPH_ODB_STATUS_SKIPPED:
			i = 5;
			break;
		case OPH_ODB_STATUS_ABORTED:
			i = 6;
			break;
		case OPH_ODB_STATUS_UNSELECTED:
			i = 7;
			break;
		default:
			return 0;
	}
	return smask[i] == OPH_OPERATOR_RESUME_PARAMETER_MASK_UP;
}

int oph_add_extra(char **jstring, char **keys, char **values, unsigned int n)
{
	if (!jstring)
		return OPH_SERVER_ERROR;

	if (!n || !keys || !values)
		return OPH_SERVER_OK;

	char *_response = (char *) calloc(OPH_MAX_STRING_SIZE + strlen(*jstring), sizeof(char));
	if (!_response)
		return OPH_SERVER_ERROR;

	strcpy(_response, *jstring);

	char *last_bracket = strrchr(_response, OPH_SEPARATOR_BRACKET_CLOSE);
	if (last_bracket) {

		unsigned int i, k = 0, v = 0;
		char _keys[OPH_MAX_STRING_SIZE], _values[OPH_MAX_STRING_SIZE];
		*_keys = *_values = 0;
		for (i = 0; i < n; i++) {
			k += snprintf(_keys + k, OPH_MAX_STRING_SIZE - k, "%s\"%s\"", i ? ", " : "", keys[i]);
			v += snprintf(_values + v, OPH_MAX_STRING_SIZE - v, "%s\"%s\"", i ? ", " : "", values[i]);
		}

		snprintf(last_bracket, OPH_MAX_STRING_SIZE, ",\n" OPH_EXTRA "%c", _keys, _values, OPH_SEPARATOR_BRACKET_CLOSE);

		free(*jstring);
		*jstring = _response;

	} else
		free(_response);

	return OPH_SERVER_OK;
}

typedef struct __ophExecuteMain_data {
	struct soap *soap;
	xsd__string request;
} _ophExecuteMain_data;

void *_ophExecuteMain(_ophExecuteMain_data * data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif

	struct oph__ophResponse new_response;

	oph__ophExecuteMain(data->soap, data->request, &new_response);

	if (data->soap->userid)
		free((char *) data->soap->userid);
	if (data->soap->passwd)
		free((char *) data->soap->passwd);

	soap_destroy(data->soap);	/* for C++ */
	soap_end(data->soap);
	soap_free(data->soap);

	free(data->request);
	free(data);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
	mysql_thread_end();
#endif

	return (void *) NULL;;
}

int oph__ophExecuteMain(struct soap *soap, xsd__string request, struct oph__ophResponse *response)
{
	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->incoming_requests++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}

	char _host[OPH_SHORT_STRING_SIZE];
	if (!soap->host || !strlen(soap->host)) {
		if (soap->ip)
			snprintf(_host, OPH_SHORT_STRING_SIZE, "%d.%d.%d.%d", (int) (soap->ip >> 24) & 0xFF, (int) (soap->ip >> 16) & 0xFF, (int) (soap->ip >> 8) & 0xFF, (int) soap->ip & 0xFF);
		else
			strcpy(_host, "NONE");
	} else
		snprintf(_host, OPH_SHORT_STRING_SIZE, "%s", soap->host);

	char *userid = (char *) soap->userid;
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R0: received a request from %s:%d sent by user '%s'\n", _host, soap->port, userid ? userid : "NONE");

	if (!request || !response) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R0: null pointer\n");
		if (response)
			response->error = OPH_SERVER_NULL_POINTER;
		return SOAP_OK;
	}

	response->jobid = response->response = NULL;
	response->error = OPH_SERVER_OK;

	struct oph_plugin_data *state = NULL;
	if (!(state = (struct oph_plugin_data *) soap_lookup_plugin((struct soap *) soap, OPH_PLUGIN_ID))) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R0: error on oph lookup plugin struct\n");
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}

	int jobid, result, i, j;
	pthread_mutex_lock(&global_flag);
	jobid = ++*state->jobid;
	pthread_mutex_unlock(&global_flag);

	oph_argument *args = NULL;

	if (get_debug_level() != LOG_DEBUG)
		pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "R%d: received a request from %s:%d sent by user '%s'\n", jobid, _host, soap->port, userid ? userid : "NONE");
	else
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: assigned label R%d to workflow:\n%s\n", jobid, jobid, request);

	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->accepted_requests++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}
#ifdef INTERFACE_TYPE_IS_GSI
	struct gsi_plugin_data *data = (struct gsi_plugin_data *) soap_lookup_plugin(soap, GSI_PLUGIN_ID);
	if (!data) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: error on lookup gsi plugin struct\n", jobid);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	userid = data->client_identity;
#endif

#ifdef INTERFACE_TYPE_IS_SSL
	int free_userid = 0, free_actual_userid = 0;
	char __userid[OPH_MAX_STRING_SIZE], *new_token = NULL, _new_token[OPH_MAX_STRING_SIZE], *actual_userid = NULL, userid_exist = 0;
	*_new_token = 0;
	state->authorization = OPH_AUTH_WRITE;

	if (oph_auth_enabled) {

		pthread_mutex_lock(&global_flag);

		if (!userid || !strcmp(userid, OPH_AUTH_TOKEN)) {
			short token_type = 0;
			if (!(result = oph_auth_token(soap->passwd, _host, &userid, &new_token, &token_type))) {
				// Token is valid: check local authorization
				if (oph_auth_user_enabling(userid, &result, &actual_userid)) {	// New user
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: token submitted by user '%s' is valid\n", jobid, userid);
					if (oph_auth_is_user_black_listed(userid)) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: user '%s' is black listed\n", jobid, userid);
						result = OPH_SERVER_AUTH_ERROR;
					} else if ((result = oph_auth_user(userid, NULL, _host, &actual_userid, &userid_exist))) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: user '%s' is not authorized locally\n", jobid, userid);
						switch (token_type) {
							case 1:
								{
									oph_argument *token_args = NULL;
									if (!(result = oph_auth_read_token(soap->passwd, userid, &token_args)))
										result = oph_auth_vo(token_args, &actual_userid);	// Return the userid associated with VO in configuration file
									oph_cleanup_args(&token_args);
									break;
								}
							case 2:
								{
									result = oph_auth_check(soap->passwd, userid);
									break;
								}
							default:
								result = OPH_SERVER_SYSTEM_ERROR;
						}
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: user '%s' is %sauthorized globally\n", jobid, userid, result ? "not " : "");
					} else
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: user '%s' is authorized locally\n", jobid, userid);
#ifdef OPH_OPENID_SUPPORT
					if (actual_userid && userid_exist && oph_openid_allow_local_user) {
						free(actual_userid);
						actual_userid = NULL;
					}
#endif
					if (actual_userid) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: cache user '%s' as '%s'\n", jobid, userid, actual_userid);
						if (userid_exist)
							pmesg(strcmp(userid, actual_userid) ? LOG_WARNING : LOG_DEBUG, __FILE__, __LINE__, "R%d: found user '%s' in local authorization list\n", jobid,
							      userid);
					}
					oph_auth_enable_user(userid, result, actual_userid);
					if (actual_userid)
						free_actual_userid = 1;
				} else
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: user '%s' is %sauthorized (cached authorization)\n", jobid, userid, result ? "not " : "");
			}
			if (new_token) {
				snprintf(_new_token, OPH_MAX_STRING_SIZE, "%s", new_token);
				free(new_token);
				new_token = NULL;
			}
			free_userid = 1;
		} else if (soap->passwd)
			result = oph_auth_user(userid, soap->passwd, _host, NULL, NULL);
		else
			result = OPH_SERVER_AUTH_ERROR;

		pthread_mutex_unlock(&global_flag);

	} else {
		result = OPH_SERVER_OK;
		userid = strdup(OPH_SUBM_USER);
		free_userid = 1;
	}

	if (!result && actual_userid) {
		if (userid)
			free(userid);
		userid = strdup(actual_userid);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: the username will be '%s'\n", jobid, userid);
	}
	if (free_userid && userid) {
		snprintf(__userid, OPH_MAX_STRING_SIZE, "%s", userid);
		free(userid);
		userid = __userid;
	}
	if (free_actual_userid)
		free(actual_userid);
	if (result) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong credentials: %s %s (errno %d)\n", jobid, userid ? userid : OPH_AUTH_TOKEN,
			   soap->passwd ? soap->passwd : "NONE", result);
		response->error = OPH_SERVER_AUTH_ERROR;
		return SOAP_OK;
	}
#endif

	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->authorized_requests++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}
	// Convert dn to user
	char _userid[OPH_MAX_STRING_SIZE];
	snprintf(_userid, OPH_MAX_STRING_SIZE, "%s", userid);
	j = strlen(_userid);
	for (i = 0; i < j; ++i)
		if ((_userid[i] == '/') || (_userid[i] == ' ') || (_userid[i] == '='))
			_userid[i] = '_';

	// Load workflow
	oph_workflow *wf = NULL;
	if (oph_workflow_load(request, userid, _host, &wf)) {
#ifdef COMMAND_TO_JSON
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for JSON conversion\n", jobid);
		char *json = NULL;
		if (oph_workflow_command_to_json(request, &json)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong data\n", jobid);
			response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
			return SOAP_OK;
		}
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: generated the following JSON request:\n%s\n", jobid, json);
		if (oph_workflow_load(json, userid, _host, &wf)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong data\n", jobid);
			if (json)
				free(json);
			response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
			return SOAP_OK;
		}
		if (json)
			free(json);
		if (wf->author) {
			free(wf->author);
			wf->author = NULL;
		}
#else
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong data\n", jobid);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
#endif
	}
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: workflow loaded correctly\n", jobid);

	// Remember the password
	if (soap->passwd)
		wf->password = strdup(soap->passwd);

	// Save the token
	if (strlen(_new_token))
		wf->new_token = strdup(_new_token);

	// Flush useless variables
	if (wf->cdd) {
		free(wf->cdd);
		wf->cdd = NULL;
	}
	if (wf->cwd) {
		free(wf->cwd);
		wf->cwd = NULL;
	}
	if (wf->cube) {
		free(wf->cube);
		wf->cube = NULL;
	}

	if (wf->client_address) {	// Useless in this version
		free(wf->client_address);
		wf->client_address = NULL;
	}
	if (soap->proxy_from)
		wf->client_address = strdup(soap->proxy_from);
	else
		wf->client_address = strdup(_host);

	if (!wf->tasks_num) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: no task found in workflow '%s'\n", jobid, wf->name);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
	}
	// Indexing
	if (oph_workflow_indexing(wf->tasks, i = wf->tasks_num)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to indexing tasks of workflow '%s'\n", jobid, wf->name);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		oph_workflow_free(wf);
		return SOAP_OK;
	}
	// Validate the workflow
	if (oph_workflow_validate(wf) || oph_workflow_validate_fco(wf) || oph_workflow_parallel_fco(wf, 0) || ((i < wf->tasks_num) && oph_workflow_validate_fco(wf))) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: workflow '%s' is not valid\n", jobid, wf->name);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		oph_workflow_free(wf);
		return SOAP_OK;
	}
	// Control on workflow parameters
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s and %s\n", jobid, OPH_ARG_NCORES, OPH_ARG_NHOSTS);
	int ncores = wf->ncores, nhosts = wf->nhosts;
	for (i = 0; i < wf->tasks_num; ++i) {
		if (oph_check_operator(wf->tasks[i].operator, &(wf->tasks[i].ncores), &(wf->tasks[i].nhosts), &(wf->tasks[i].role))) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: error in check operator '%s'\n", jobid, wf->tasks[i].operator);
			response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
			oph_workflow_free(wf);
			return SOAP_OK;
		}
		if (ncores < wf->tasks[i].ncores)
			ncores = wf->tasks[i].ncores;
		if (nhosts < wf->tasks[i].nhosts)
			nhosts = wf->tasks[i].nhosts;
	}
	if (!ncores) {
		wf->ncores = ncores = OPH_DEFAULT_CORES;
		for (i = 0; i < wf->tasks_num; ++i)
			wf->tasks[i].ncores = ncores;
	} else
		wf->ncores = ncores;
	if (!nhosts) {
		wf->nhosts = nhosts = OPH_DEFAULT_HOSTS;
		for (i = 0; i < wf->tasks_num; ++i)
			wf->tasks[i].nhosts = nhosts;
	} else
		wf->nhosts = nhosts;

	char load_previous_session = 0;

	pthread_mutex_lock(&global_flag);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_ARG_SESSIONID);
	if (wf->sessionid && !strncasecmp(wf->sessionid, OPH_NULL_VALUE, strlen(OPH_NULL_VALUE))) {
		free(wf->sessionid);
		wf->sessionid = NULL;
		load_previous_session = 1;
	} else if (wf->sessionid && strncmp(wf->sessionid, state->serverid, strlen(state->serverid))) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong sessionid '%s'\n", jobid, wf->sessionid);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	pthread_mutex_unlock(&global_flag);

	// Load user information
	int save_in_odb = 0;
	oph_argument *user_args = NULL;
	oph_init_args(&user_args);
	pthread_mutex_lock(&global_flag);
	result = oph_load_user(_userid, &user_args, &save_in_odb);
	pthread_mutex_unlock(&global_flag);
	if (result) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: error in opening user data\n", jobid);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	if (save_in_odb)	// Save the entry in OphDB
	{
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: saving reference to '%s' in system catalog\n", jobid, userid);
		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to read OphidiaDB configuration\n", jobid);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_cleanup_args(&user_args);
			oph_workflow_free(wf);
			response->error = OPH_SERVER_IO_ERROR;
			return SOAP_OK;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to connect to OphidiaDB. Check access parameters\n", jobid);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_cleanup_args(&user_args);
			oph_workflow_free(wf);
			response->error = OPH_SERVER_IO_ERROR;
			return SOAP_OK;
		}
		if (oph_odb_insert_user(&oDB, userid)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: error in saving reference to '%s' in system catalog\n", jobid, userid);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_cleanup_args(&user_args);
			oph_workflow_free(wf);
			response->error = OPH_SERVER_IO_ERROR;
			return SOAP_OK;
		}
		oph_odb_disconnect_from_ophidiadb(&oDB);
	}

	char tmp[OPH_MAX_STRING_SIZE];	// Generic multi-purpose string

	int nstandardcommands = 0, is_admin = !oph_get_arg(user_args, OPH_USER_IS_ADMIN, tmp) && !strncasecmp(tmp, OPH_COMMON_YES, OPH_MAX_STRING_SIZE);
	oph_known_operators oph_known_operator = OPH_NO_OPERATOR;
	for (i = 0; i < wf->tasks_num; ++i) {
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			if (wf->tasks[i].arguments_keys[j]) {
				if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_OPERATOR, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong operator '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_SESSIONID, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong sessionid '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_WORKFLOWID, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong workflowid '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_MARKERID, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong marker '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_JOBID, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong jobid '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_USERNAME, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong username '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_USERROLE, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong userrole '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_PARENTID, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parentid '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_TASKINDEX, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong taskindex '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				} else if (!strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_LIGHTTASKINDEX, OPH_MAX_STRING_SIZE)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong lighttaskindex '%s'\n", jobid, wf->tasks[i].arguments_values[j]);
					response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				}
			}
		}
		if (response->error)
			break;
		if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_LOG_INFO, OPH_MAX_STRING_SIZE)) {
			if (!is_admin) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: the user is not authorized to submit the command '%s'\n", jobid, wf->tasks[i].operator);
				response->error = OPH_SERVER_AUTH_ERROR;
				break;
			}
			oph_known_operator = OPH_LOG_INFO_OPERATOR;
			wf->tasks[i].is_known = 1;
		} else if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_SERVICE, OPH_MAX_STRING_SIZE)) {
			if (!is_admin) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: the user is not authorized to submit the command '%s'\n", jobid, wf->tasks[i].operator);
				response->error = OPH_SERVER_AUTH_ERROR;
				break;
			}
			oph_known_operator = OPH_SERVICE_OPERATOR;
			wf->tasks[i].is_known = 1;
		} else if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_GET_CONFIG, OPH_MAX_STRING_SIZE)) {
			oph_known_operator = OPH_GET_CONFIG_OPERATOR;
			wf->tasks[i].is_known = 1;
		} else if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_RESUME, OPH_MAX_STRING_SIZE)) {
			oph_known_operator = OPH_RESUME_OPERATOR;
			wf->tasks[i].is_known = 1;
		} else if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_MANAGE_SESSION, OPH_MAX_STRING_SIZE)) {
			oph_known_operator = OPH_MANAGE_SESSION_OPERATOR;
			wf->tasks[i].is_known = 1;
		} else if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_CANCEL, OPH_MAX_STRING_SIZE)) {
			oph_known_operator = OPH_CANCEL_OPERATOR;
			wf->tasks[i].is_known = 1;
		} else if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_CLUSTER, OPH_MAX_STRING_SIZE)) {
			oph_known_operator = OPH_CLUSTER_OPERATOR;
			if (!is_admin) {
				for (j = 0; j < wf->tasks[i].arguments_num; ++j)
					if (wf->tasks[i].arguments_keys[j] && wf->tasks[i].arguments_values[j] && !strncasecmp(wf->tasks[i].arguments_keys[j], OPH_ARG_ACTION, OPH_MAX_STRING_SIZE)
					    && !strncasecmp(wf->tasks[i].arguments_values[j], OPH_OPERATOR_CLUSTER_PARAMETER_INFO_CLUSTER, OPH_MAX_STRING_SIZE)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: the user is not authorized to submit the command '%s'\n", jobid, wf->tasks[i].operator);
						response->error = OPH_SERVER_AUTH_ERROR;
						break;
					}
			}
			wf->tasks[i].is_known = 1;
		} else
			nstandardcommands++;
	}
	if ((nstandardcommands || (wf->tasks_num > 1)) && (nstandardcommands < wf->tasks_num)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: there are commands which cannot be called in this context. Use them as single commands\n", jobid);
		response->error = OPH_SERVER_ERROR;
	}
	if (response->error) {
		oph_workflow_free(wf);
		oph_cleanup_args(&user_args);
		return SOAP_OK;
	}
	// Handle SERVICE_OPERATOR
	if (oph_known_operator == OPH_SERVICE_OPERATOR) {
		oph_cleanup_args(&user_args);

		int level = 1;
		char *value = NULL, *value_copy, *pch, *pch1, *save_pointer = NULL, **user_to_be_enabled = NULL, **user_to_be_disabled = NULL;
		unsigned int nn, nnee = 0, nndd = 0;
		for (i = 0; i < wf->tasks[0].arguments_num; ++i) {
			if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_STATUS, OPH_MAX_STRING_SIZE)) {
				value = wf->tasks[0].arguments_values[i];
				if (value && strlen(value)) {
					pthread_mutex_lock(&global_flag);
					if (!strncasecmp(value, OPH_OPERATOR_SERVICE_PARAMETER_STATUS_UP, OPH_MAX_STRING_SIZE))
						oph_service_status = 1;
					else if (!strncasecmp(value, OPH_OPERATOR_SERVICE_PARAMETER_STATUS_DOWN, OPH_MAX_STRING_SIZE))
						oph_service_status = 0;
					else {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong status '%s'\n", jobid, value);
						pthread_mutex_unlock(&global_flag);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						return SOAP_OK;
					}
					pthread_mutex_unlock(&global_flag);
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_LEVEL, OPH_MAX_STRING_SIZE)) {
				value = wf->tasks[0].arguments_values[i];
				if (value && strlen(value)) {
					level = (int) strtol(value, NULL, 10);
					if ((level < 1) || (level > 2)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong level '%s'\n", jobid, value);
						pthread_mutex_unlock(&global_flag);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_OPERATOR_PARAMETER_ENABLE, OPH_MAX_STRING_SIZE)) {
				value = wf->tasks[0].arguments_values[i];
				if (value && strlen(value) && !nnee) {
					value_copy = strdup(value);
					pch = strchr(value_copy, OPH_SEPARATOR_SUBPARAM);
					for (++nnee; pch; ++nnee) {
						pch1 = pch + 1;
						if (!pch1 || !*pch1)
							break;
						pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
					}
					if (!nnee) {
						free(value_copy);
						continue;
					}
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: found %d user%s in clause %s\n", jobid, nnee, nnee == 1 ? "" : "s", OPH_OPERATOR_PARAMETER_ENABLE);
					user_to_be_enabled = (char **) calloc(nnee, sizeof(char *));
					if (!user_to_be_enabled) {
						free(value_copy);
						nnee = 0;
						continue;
					}
					for (nn = 0, pch = strtok_r(value_copy, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer); pch && (nn < nnee);
					     nn++, pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer))
						user_to_be_enabled[nn] = strdup(pch);
					free(value_copy);
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_OPERATOR_PARAMETER_DISABLE, OPH_MAX_STRING_SIZE)) {
				value = wf->tasks[0].arguments_values[i];
				if (value && strlen(value) && !nndd) {
					value_copy = strdup(value);
					pch = strchr(value_copy, OPH_SEPARATOR_SUBPARAM);
					for (++nndd; pch; ++nndd) {
						pch1 = pch + 1;
						if (!pch1 || !*pch1)
							break;
						pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
					}
					if (!nndd) {
						free(value_copy);
						continue;
					}
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: found %d user%s in clause %s\n", jobid, nndd, nndd == 1 ? "" : "s", OPH_OPERATOR_PARAMETER_DISABLE);
					user_to_be_disabled = (char **) calloc(nndd, sizeof(char *));
					if (!user_to_be_disabled) {
						free(value_copy);
						nndd = 0;
						continue;
					}
					for (nn = 0, pch = strtok_r(value_copy, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer); pch && (nn < nndd);
					     nn++, pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer))
						user_to_be_disabled[nn] = strdup(pch);
					free(value_copy);
				}
			}
		}

		if (user_to_be_enabled) {

			if ((nnee == 1) && !strcmp(user_to_be_enabled[0], OPH_OPERATOR_SERVICE_PARAMETER_ALL)) {	// Enable all users
				pthread_mutex_lock(&global_flag);
				result = oph_enable_all_users(1);
				pthread_mutex_unlock(&global_flag);
				if (result)
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s' for all users\n", jobid, OPH_USER_ENABLED);
			}

			while (nnee)
				if (user_to_be_enabled[--nnee]) {
					if (strcmp(user_to_be_enabled[nnee], OPH_OPERATOR_SERVICE_PARAMETER_ALL) && strcmp(user_to_be_enabled[nnee], OPH_OPERATOR_SERVICE_PARAMETER_NONE)) {
						user_args = NULL;
						oph_init_args(&user_args);
						pthread_mutex_lock(&global_flag);
						result = oph_load_user(user_to_be_enabled[nnee], &user_args, &save_in_odb);
						pthread_mutex_unlock(&global_flag);
						if (result) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: error in opening user data\n", jobid);
							oph_cleanup_args(&user_args);
							free(user_to_be_enabled[nnee]);
							continue;
						}
						result = oph_set_arg(&user_args, OPH_USER_ENABLED, OPH_COMMON_YES);
						if (result) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_ENABLED);
							oph_cleanup_args(&user_args);
							free(user_to_be_enabled[nnee]);
							continue;
						}
						pthread_mutex_lock(&global_flag);
						result = oph_save_user(user_to_be_enabled[nnee], user_args);
						pthread_mutex_unlock(&global_flag);
						if (result) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user data of '%s'\n", jobid, userid);
							oph_cleanup_args(&user_args);
							free(user_to_be_enabled[nnee]);
							continue;
						}
						oph_cleanup_args(&user_args);
					} else
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: discard value '%s' in clause %s\n", jobid, user_to_be_enabled[nnee], OPH_OPERATOR_PARAMETER_ENABLE);
					free(user_to_be_enabled[nnee]);
				}
			free(user_to_be_enabled);
		}

		if (user_to_be_disabled) {

			if ((nndd == 1) && !strcmp(user_to_be_disabled[0], OPH_OPERATOR_SERVICE_PARAMETER_ALL)) {	// Disable all users
				pthread_mutex_lock(&global_flag);
				result = oph_enable_all_users(0);
				pthread_mutex_unlock(&global_flag);
				if (result)
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s' for all users\n", jobid, OPH_USER_ENABLED);
			}

			while (nndd)
				if (user_to_be_disabled[--nndd]) {
					if (strcmp(user_to_be_disabled[nndd], OPH_OPERATOR_SERVICE_PARAMETER_ALL) && strcmp(user_to_be_disabled[nnee], OPH_OPERATOR_SERVICE_PARAMETER_NONE)) {
						user_args = NULL;
						oph_init_args(&user_args);
						pthread_mutex_lock(&global_flag);
						result = oph_load_user(user_to_be_disabled[nndd], &user_args, &save_in_odb);
						pthread_mutex_unlock(&global_flag);
						if (result) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: error in opening user data\n", jobid);
							oph_cleanup_args(&user_args);
							free(user_to_be_disabled[nndd]);
							continue;
						}
						result = oph_set_arg(&user_args, OPH_USER_ENABLED, OPH_COMMON_NO);
						if (result) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_ENABLED);
							oph_cleanup_args(&user_args);
							free(user_to_be_disabled[nndd]);
							continue;
						}
						pthread_mutex_lock(&global_flag);
						result = oph_save_user(user_to_be_disabled[nndd], user_args);
						pthread_mutex_unlock(&global_flag);
						if (result) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user data of '%s'\n", jobid, userid);
							oph_cleanup_args(&user_args);
							free(user_to_be_disabled[nndd]);
							continue;
						}
						oph_cleanup_args(&user_args);
					} else
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: discard value '%s' in clause %s\n", jobid, user_to_be_disabled[nnee], OPH_OPERATOR_PARAMETER_DISABLE);
					free(user_to_be_disabled[nndd]);
				}
			free(user_to_be_disabled);
		}

		int _oph_service_status;
		*tmp = 0;

		pthread_mutex_lock(&global_flag);
		_oph_service_status = oph_service_status;
		pthread_mutex_unlock(&global_flag);

		int success = 0;
		oph_json *oper_json = NULL;

		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");

		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: JSON alloc error\n", jobid);
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", userid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: SET SOURCE error\n", jobid);
				break;
			}
			if (oph_json_add_consumer(oper_json, userid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD CONSUMER error\n", jobid);
				break;
			}
			success = 1;
			*error_message = 0;
		}

		if (success && (level > 1)) {

			success = 0;
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in setting JSON data!");

			int num_fields = 8, ii, jj, iii, jjj = 0;

			char **jsonkeys = NULL;
			char **fieldtypes = NULL;
			char **jsonvalues = NULL;
			char jsontmp[OPH_MAX_STRING_SIZE];

			while (!success) {
				// Header
				jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
				if (!jsonkeys) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					break;
				}
				jsonkeys[jjj] = strdup("USER");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("SESSION ID");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("MARKER ID");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("TASK NAME");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					for (iii = 0; iii < jjj; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				jjj++;
				jsonkeys[jjj] = strdup("TASK STATUS");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				fieldtypes[jjj] = strdup(OPH_JSON_STRING);
				if (!fieldtypes[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
				if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_SERVICE_TASKS, "Task List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID error\n", jobid);
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

				oph_job_list *job_info = state->job_info;
				oph_job_info *temp;
				oph_workflow *wf;	// Overwrite previous definition
				for (temp = job_info->head; temp; temp = temp->next) {	// Loop on workflows
					if (!(wf = temp->wf))
						break;

					jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						break;
					}
					jjj = 0;
					jsonvalues[jjj] = strdup(wf->username);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(wf->sessionid);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup("");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(wf->name);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup("WORKFLOW");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(oph_odb_convert_status_to_str(wf->status));
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_SERVICE_TASKS, jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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

					for (ii = 0; ii < wf->tasks_num; ii++) {	// Loop on tasks

						jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							break;
						}
						jjj = 0;
						jsonvalues[jjj] = strdup(wf->username);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(wf->sessionid);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[ii].markerid);
						jsonvalues[jjj] = strdup(jsontmp);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(wf->tasks[ii].name);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(wf->tasks[ii].light_tasks_num ? "MASSIVE" : "SIMPLE");
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(oph_odb_convert_status_to_str(wf->tasks[ii].status));
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_SERVICE_TASKS, jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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

						for (jj = 0; jj < wf->tasks[ii].light_tasks_num; jj++) {	// Loop on light tasks

							jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonvalues) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								break;
							}
							jjj = 0;
							jsonvalues[jjj] = strdup(wf->username);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup(wf->sessionid);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[ii].light_tasks[jj].markerid);
							jsonvalues[jjj] = strdup(jsontmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[ii].markerid);
							jsonvalues[jjj] = strdup(jsontmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup(wf->tasks[ii].name);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup("SIMPLE");
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup(oph_odb_convert_status_to_str(wf->tasks[ii].light_tasks[jj].status));
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_SERVICE_TASKS, jsonvalues)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
						if (jj < wf->tasks[ii].light_tasks_num)
							break;
					}
					if (ii < wf->tasks_num)
						break;
				}
				if (!temp) {
					success = 1;
					*error_message = 0;
				}
			}
		}

		if (success) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", _oph_service_status ? OPH_ODB_STATUS_ACTIVE_STR : OPH_ODB_STATUS_INACTIVE_STR);
			if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_SERVICE_STATUS, "Service status", error_message)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
				success = 0;
			}
		}

		if (oper_json) {
			char *jstring = NULL;
			int return_code = 0;
			if (!success) {
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
					return_code = -1;
				} else if (oph_json_to_json_string(oper_json, &jstring))
					return_code = -1;
			} else {
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
					return_code = -1;
				} else if (oph_json_to_json_string(oper_json, &jstring))
					return_code = -1;
			}
			if (!return_code)
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: JSON output created\n", jobid);
			if (jstring) {
				if (strlen(_new_token)) {
					char **keys = (char **) malloc(sizeof(char *)), **values = (char **) malloc(sizeof(char *));
					if (keys && values) {
						keys[0] = strdup(OPH_AUTH_TOKEN_JSON);
						values[0] = strdup(_new_token);
						if (keys[0] && values[0]) {
							if (oph_add_extra(&jstring, keys, values, 1))
								response->response = soap_strdup(soap, jstring);
						}
					}
					free_string_vector(keys, 1);
					free_string_vector(values, 1);
				}
				if (!response->response)
					response->response = soap_strdup(soap, jstring);
				free(jstring);
			}
		}
		oph_json_free(oper_json);

		// Log into WF_LOGFILE
		if (wf_logfile) {
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
			fprintf(wf_logfile, "%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%f\n", buffer, 0, wf->name, sha_username, wf->ip_address ? wf->ip_address : OPH_UNKNOWN,
				wf->client_address ? wf->client_address : OPH_UNKNOWN, 1, 1, (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->timestamp);
			fflush(wf_logfile);
			pthread_mutex_unlock(&curl_flag);
		}
		oph_workflow_free(wf);

		pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "R%d has been processed\n", jobid);
		return SOAP_OK;
	}
	// Handle GET_CONFIG_OPERATOR
	if (oph_known_operator == OPH_GET_CONFIG_OPERATOR) {
		char *key = 0;
		*tmp = 0;

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_ARG_KEY);
		for (i = 0; i < wf->tasks[0].arguments_num; ++i)
			if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_KEY, OPH_MAX_STRING_SIZE))
				break;
		if (i < wf->tasks[0].arguments_num)
			key = wf->tasks[0].arguments_values[i];

		int success = 0;
		oph_json *oper_json = NULL;

		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");

		int num_fields = 2, iii, jjj = 0;

		char **jsonkeys = NULL;
		char **fieldtypes = NULL;
		char **jsonvalues = NULL;

		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: JSON alloc error\n", jobid);
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", userid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: SET SOURCE error\n", jobid);
				break;
			}
			if (oph_json_add_consumer(oper_json, userid)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD CONSUMER error\n", jobid);
				break;
			}
			success = 1;
			*error_message = 0;
		}

		if (success) {
			success = 0;
			while (!success) {
				// Header
				jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
				if (!jsonkeys) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					break;
				}
				jsonkeys[jjj] = strdup("PARAMETER");
				if (!jsonkeys[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
					for (iii = 0; iii < num_fields; iii++)
						if (jsonkeys[iii])
							free(jsonkeys[iii]);
					if (jsonkeys)
						free(jsonkeys);
					break;
				}
				fieldtypes[jjj] = strdup(OPH_JSON_STRING);
				if (!fieldtypes[jjj]) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
				if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_GET_CONFIG, "Configuration Parameters", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID error\n", jobid);
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
			success = 0;
			while (!success) {
				// OPH_SERVER_CONF_XML_URL
				if (!key || !strncasecmp(key, OPH_OPERATOR_GET_CONFIG_PARAMETER_ALL, OPH_MAX_STRING_SIZE) || !strncasecmp(key, OPH_SERVER_CONF_XML_URL, OPH_MAX_STRING_SIZE)) {
					jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						break;
					}
					jjj = 0;
					jsonvalues[jjj] = strdup(OPH_SERVER_CONF_XML_URL);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(oph_xml_operators);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					//jjj++;
					if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_GET_CONFIG, jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
				// OPH_SERVER_CONF_BASE_SRC_PATH
				if (!key || !strncasecmp(key, OPH_OPERATOR_GET_CONFIG_PARAMETER_ALL, OPH_MAX_STRING_SIZE)
				    || !strncasecmp(key, "OPH_" OPH_SERVER_CONF_BASE_SRC_PATH, OPH_MAX_STRING_SIZE)) {
					jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						break;
					}
					jjj = 0;
					jsonvalues[jjj] = strdup("OPH_" OPH_SERVER_CONF_BASE_SRC_PATH);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(oph_base_src_path);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonvalues[iii])
								free(jsonvalues[iii]);
						if (jsonvalues)
							free(jsonvalues);
						break;
					}
					//jjj++;
					if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_GET_CONFIG, jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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

				char *last_session_id = NULL;

				char *parameters[OPH_USER_LAST_STATUS_SIZE] = OPH_USER_LAST_STATUS;
				for (i = 0; i < OPH_USER_LAST_STATUS_SIZE; ++i) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, parameters[i]);
					if (!oph_get_arg(user_args, parameters[i], tmp)) {
						if (!key || !strncasecmp(key, OPH_OPERATOR_GET_CONFIG_PARAMETER_ALL, OPH_MAX_STRING_SIZE) || !strncasecmp(key, parameters[i], OPH_MAX_STRING_SIZE)) {
							jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonvalues) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								break;
							}
							jjj = 0;
							jsonvalues[jjj] = strdup(parameters[i]);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup(tmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_GET_CONFIG, jsonvalues)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
						if (!last_session_id && !strcmp(parameters[i], OPH_USER_LAST_SESSION_ID) && (strlen(tmp) > 0))
							last_session_id = strdup(tmp);
					}
				}
				if (i < OPH_USER_LAST_STATUS_SIZE) {
					if (last_session_id)
						free(last_session_id);
					break;
				}

				if (last_session_id) {
					char filename[OPH_MAX_STRING_SIZE], session_code[OPH_MAX_STRING_SIZE];
					if (oph_get_session_code(last_session_id, session_code)) {
						free(last_session_id);
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to get session code\n", jobid);
						break;
					}
					free(last_session_id);
					oph_argument *session_args = NULL;

					snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, _userid, session_code);
					oph_init_args(&session_args);

					pthread_mutex_lock(&global_flag);
					result = oph_load_file(filename, &session_args);	// DT_LNK
					pthread_mutex_unlock(&global_flag);
					if (result) {
						oph_cleanup_args(&session_args);
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: error in opening session data\n", jobid);
						break;
					}

					char *sparameters[OPH_SESSION_LAST_STATUS_SIZE] = OPH_SESSION_LAST_STATUS;
					for (i = 0; i < OPH_SESSION_LAST_STATUS_SIZE; ++i) {
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, sparameters[i]);
						if (!oph_get_arg(session_args, sparameters[i], tmp)) {
							if (!key || !strncasecmp(key, OPH_OPERATOR_GET_CONFIG_PARAMETER_ALL, OPH_MAX_STRING_SIZE)
							    || !strncasecmp(key, sparameters[i], OPH_MAX_STRING_SIZE)) {
								jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonvalues) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									break;
								}
								jjj = 0;
								jsonvalues[jjj] = strdup(sparameters[i]);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_GET_CONFIG, jsonvalues)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
						}
					}
					oph_cleanup_args(&session_args);

					if (i < OPH_SESSION_LAST_STATUS_SIZE)
						break;

					// .user
					snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, _userid, session_code);
					oph_init_args(&session_args);

					pthread_mutex_lock(&global_flag);
					result = oph_load_file(filename, &session_args);	// DT_REG
					pthread_mutex_unlock(&global_flag);
					if (result) {
						oph_cleanup_args(&session_args);
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: error in opening user-specific session data\n", jobid);
						break;
					}

					char *usparameters[OPH_USER_SESSION_LAST_STATUS_SIZE] = OPH_USER_SESSION_LAST_STATUS;
					for (i = 0; i < OPH_USER_SESSION_LAST_STATUS_SIZE; ++i) {
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, usparameters[i]);
						if (!oph_get_arg(session_args, usparameters[i], tmp)) {
							if (!key || !strncasecmp(key, OPH_OPERATOR_GET_CONFIG_PARAMETER_ALL, OPH_MAX_STRING_SIZE)
							    || !strncasecmp(key, usparameters[i], OPH_MAX_STRING_SIZE)) {
								jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
								if (!jsonvalues) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									break;
								}
								jjj = 0;
								jsonvalues[jjj] = strdup(usparameters[i]);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								jjj++;
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_GET_CONFIG, jsonvalues)) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
						}
					}
					oph_cleanup_args(&session_args);

					if (i < OPH_USER_SESSION_LAST_STATUS_SIZE)
						break;
				}

				success = 1;
			}
		}

		if (oper_json) {
			char *jstring = NULL;
			int return_code = 0;
			if (!success) {
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
					return_code = -1;
				} else if (oph_json_to_json_string(oper_json, &jstring))
					return_code = -1;
			} else {
				if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
					return_code = -1;
				} else if (oph_json_to_json_string(oper_json, &jstring))
					return_code = -1;
			}
			if (!return_code)
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: JSON output created\n", jobid);
			if (jstring) {
				if (strlen(_new_token)) {
					char **keys = (char **) malloc(sizeof(char *)), **values = (char **) malloc(sizeof(char *));
					if (keys && values) {
						keys[0] = strdup(OPH_AUTH_TOKEN_JSON);
						values[0] = strdup(_new_token);
						if (keys[0] && values[0]) {
							if (oph_add_extra(&jstring, keys, values, 1))
								response->response = soap_strdup(soap, jstring);
						}
					}
					free_string_vector(keys, 1);
					free_string_vector(values, 1);
				}
				if (!response->response)
					response->response = soap_strdup(soap, jstring);
				free(jstring);
			}
		}
		oph_json_free(oper_json);

		// Log into WF_LOGFILE
		if (wf_logfile) {
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
			fprintf(wf_logfile, "%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%f\n", buffer, 0, wf->name, sha_username, wf->ip_address ? wf->ip_address : OPH_UNKNOWN,
				wf->client_address ? wf->client_address : OPH_UNKNOWN, 1, 1, (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->timestamp);
			fflush(wf_logfile);
			pthread_mutex_unlock(&curl_flag);
		}

		oph_workflow_free(wf);
		oph_cleanup_args(&user_args);

		pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "R%d has been processed\n", jobid);
		return SOAP_OK;
	}

	int current_service_status;
	pthread_mutex_lock(&global_flag);
	current_service_status = oph_service_status;
	pthread_mutex_unlock(&global_flag);

	if (current_service_status) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_ENABLED);
		if (!oph_get_arg(user_args, OPH_USER_ENABLED, tmp) && !strcasecmp(tmp, OPH_COMMON_NO))
			current_service_status = 0;
	}

	if (!current_service_status) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: service is not available\n", jobid);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_NO_RESPONSE;
		return SOAP_OK;
	}

	char oph_jobid[OPH_MAX_STRING_SIZE], filename[OPH_MAX_STRING_SIZE];

	// Handle RESUME_OPERATOR
	if (oph_known_operator == OPH_RESUME_OPERATOR) {
		char *session = NULL, *user = NULL, *mask = NULL, *checkpoint = NULL;
		int id = -1, id_type = -1, document_type = -1, level = -1, save = -1, wid = 0, execute = -1;

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s and %s\n", jobid, OPH_ARG_SESSION, OPH_ARG_MARKER);
		for (i = 0; i < wf->tasks[0].arguments_num; ++i) {
			if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_SESSION, OPH_MAX_STRING_SIZE)) {
				if (!session) {
					if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_COMMON_PARAMETER_WORKING_SESSION, OPH_MAX_STRING_SIZE))
						session = wf->sessionid;
					else
						session = wf->tasks[0].arguments_values[i];
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_ID, OPH_MAX_STRING_SIZE)) {
				if (id < 0) {
					id = strtol(wf->tasks[0].arguments_values[i], NULL, 10);
					if (id < 0) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_ARG_ID);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_IDTYPE, OPH_MAX_STRING_SIZE)) {
				if (id_type < 0) {
					if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_OPERATOR_RESUME_PARAMETER_MARKER, OPH_MAX_STRING_SIZE))
						id_type = 1;
					else if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_OPERATOR_RESUME_PARAMETER_WORKFLOW, OPH_MAX_STRING_SIZE))
						id_type = 0;
					else {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_ARG_IDTYPE);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_DOCUMENTTYPE, OPH_MAX_STRING_SIZE)) {
				if (document_type < 0) {
					if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_OPERATOR_RESUME_PARAMETER_REQUEST, OPH_MAX_STRING_SIZE))
						document_type = 1;
					else if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_OPERATOR_RESUME_PARAMETER_RESPONSE, OPH_MAX_STRING_SIZE))
						document_type = 0;
					else {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_ARG_DOCUMENTTYPE);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_LEVEL, OPH_MAX_STRING_SIZE)) {
				if (level < 0) {
					level = strtol(wf->tasks[0].arguments_values[i], NULL, 10);
					if ((level < 0) || (level > 5)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_ARG_LEVEL);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_SAVE, OPH_MAX_STRING_SIZE)) {
				if (save < 0) {
					if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_COMMON_YES, OPH_MAX_STRING_SIZE))
						save = 1;
					else if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_COMMON_NO, OPH_MAX_STRING_SIZE))
						save = 0;
					else {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_ARG_SAVE);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_ARG_USER, OPH_MAX_STRING_SIZE)) {
				if (!user)
					user = wf->tasks[0].arguments_values[i];
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_OPERATOR_PARAMETER_STATUS_FILTER, OPH_MAX_STRING_SIZE)) {
				if (!mask)
					mask = wf->tasks[0].arguments_values[i];
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_OPERATOR_PARAMETER_EXECUTE, OPH_MAX_STRING_SIZE)) {
				if (execute < 0) {
					if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_COMMON_YES, OPH_MAX_STRING_SIZE))
						execute = 1;
					else if (!strncasecmp(wf->tasks[0].arguments_values[i], OPH_COMMON_NO, OPH_MAX_STRING_SIZE))
						execute = 0;
					else {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_OPERATOR_PARAMETER_EXECUTE);
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
				}
			} else if (wf->tasks[0].arguments_keys[i] && !strncasecmp(wf->tasks[0].arguments_keys[i], OPH_OPERATOR_PARAMETER_CHECKPOINT, OPH_MAX_STRING_SIZE)) {
				if (!checkpoint)
					checkpoint = wf->tasks[0].arguments_values[i];
			}
		}

		char smask[OPH_OPERATOR_RESUME_PARAMETER_MASK_SIZE];
		if (mask) {
			int mask_size = strlen(mask);
			for (i = 0; (i < OPH_OPERATOR_RESUME_PARAMETER_MASK_SIZE) && (i < mask_size); ++i)
				smask[i] = mask[i] == OPH_OPERATOR_RESUME_PARAMETER_MASK_UP ? OPH_OPERATOR_RESUME_PARAMETER_MASK_UP : OPH_OPERATOR_RESUME_PARAMETER_MASK_DOWN;
			for (; i < OPH_OPERATOR_RESUME_PARAMETER_MASK_SIZE; ++i)
				smask[i] = OPH_OPERATOR_RESUME_PARAMETER_MASK_DOWN;
		} else
			snprintf(smask, OPH_OPERATOR_RESUME_PARAMETER_MASK_SIZE, OPH_OPERATOR_RESUME_PARAMETER_MASK);

		if (id < 0)
			id = 0;
		if (id_type < 0)
			id_type = 0;
		if (document_type < 0)
			document_type = 0;
		if (level < 0)
			level = 1;
		if (save < 0)
			save = 0;
		if (execute < 0)
			execute = 0;

		if (!level && document_type)	// Options level == 0 and level == 1 are equivalent in case of JSON Requests
			level = 1;

		if (level > 4)
			document_type = 2;
		if (level > 3) {
			level = 3;	// Or less

			if (id_type)	// A workflow filter is wanted
			{
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong parameter '%s'\n", jobid, OPH_ARG_LEVEL);
				response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				oph_workflow_free(wf);
				oph_cleanup_args(&user_args);
				return SOAP_OK;
			}
			id_type = 1;	// Recycle the code for marker filtering

			if (id)
				wid = id;	// Remember only the workflow id (wid)
			id = 0;

			if (!document_type)
				document_type = 1;	// Level 4 is associated only "requests for a specific workflow". Currently, this parameter is useless
		}

		if (session) {
			pthread_mutex_lock(&global_flag);
			if (strncmp(session, state->serverid, strlen(state->serverid))) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong sessionid '%s'\n", jobid, session);
				pthread_mutex_unlock(&global_flag);
				response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				oph_workflow_free(wf);
				oph_cleanup_args(&user_args);
				return SOAP_OK;
			}
			pthread_mutex_unlock(&global_flag);
		} else
			session = wf->sessionid;

		if (!session) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: missing parameter '%s'\n", jobid, OPH_ARG_SESSION);
			response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
			oph_workflow_free(wf);
			oph_cleanup_args(&user_args);
			return SOAP_OK;
		}

		if (!document_type)
			checkpoint = NULL;

		oph_init_args(&args);

		int active = 0;
		pthread_mutex_lock(&global_flag);
		if (oph_auth_session(_userid, session, state->serverid, &args, &active, NULL) || !active) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong sessionid '%s'\n", jobid, session);
			pthread_mutex_unlock(&global_flag);
			response->error = OPH_SERVER_AUTH_ERROR;
			oph_cleanup_args(&args);
			oph_workflow_free(wf);
			oph_cleanup_args(&user_args);
			return SOAP_OK;
		}
		pthread_mutex_unlock(&global_flag);

		int last_markerid = 0, last_workflowid = 0;
		if (!oph_get_arg(args, OPH_SESSION_LAST_MARKER, tmp))
			last_markerid = strtol(tmp, NULL, 10);
		if (!oph_get_arg(args, OPH_SESSION_LAST_WORKFLOW, tmp))
			last_workflowid = strtol(tmp, NULL, 10);
		oph_cleanup_args(&args);

		char *jstring = NULL;
		char session_code[OPH_MAX_STRING_SIZE];
		if (oph_get_session_code(session, session_code)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to get session code\n", jobid);
			response->error = OPH_SERVER_SYSTEM_ERROR;
			oph_workflow_free(wf);
			oph_cleanup_args(&user_args);
			return SOAP_OK;
		}
		// Open JSON Response
		int success = 0;
		oph_json *oper_json = NULL;

		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");

		int num_fields = !wid && (document_type || !id_type) ? 6 : 7, iii, jjj;

		char **jsonkeys = NULL;
		char **fieldtypes = NULL;
		char **jsonvalues = NULL;

		double wpr;

		if (!id)	// Return a JSON Response with the list of oph_jobid submitted within the target session
		{
			while (!success) {
				if (oph_json_alloc(&oper_json)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: JSON alloc error\n", jobid);
					break;
				}
				if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", userid)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: SET SOURCE error\n", jobid);
					break;
				}
				if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
					break;
				}
				if (oph_json_add_source_detail(oper_json, "Workflow", "0")) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
					break;
				}
				if (oph_json_add_source_detail(oper_json, "Marker", "0")) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
					break;
				}
				if (oph_json_add_source_detail(oper_json, "JobID", session)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
					break;
				}
				if (oph_json_add_consumer(oper_json, userid)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD CONSUMER error\n", jobid);
					break;
				}
				success = 1;
				*error_message = 0;
			}

			if (success) {
				success = 0;
				while (!success) {
					// Header
					jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
					if (!jsonkeys) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						break;
					}
					jjj = 0;
					jsonkeys[jjj] = strdup("OPH JOB ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj++;
					jsonkeys[jjj] = strdup("MARKER ID");
					if (!jsonkeys[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < jjj; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					if (wid) {
						jjj++;
						jsonkeys[jjj] = strdup("PARENT MARKER ID");
						if (!jsonkeys[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
					}
					if (document_type) {
						jjj++;
						jsonkeys[jjj] = strdup("COMMAND");
						if (!jsonkeys[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
					} else {
						if (id_type) {
							jjj++;
							jsonkeys[jjj] = strdup("PARENT MARKER ID");
							if (!jsonkeys[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonkeys[iii])
										free(jsonkeys[iii]);
								if (jsonkeys)
									free(jsonkeys);
								break;
							}
						}
						jjj++;
						if (level)
							jsonkeys[jjj] = strdup("EXIT STATUS");
						else
							jsonkeys[jjj] = strdup("PROGRESS RATIO");
						if (!jsonkeys[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
						/*
						   jjj++;
						   jsonkeys[jjj] = strdup("LINK");
						   if (!jsonkeys[jjj]) {
						   pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						   for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						   if (jsonkeys) free(jsonkeys);
						   break;
						   }
						 */
					}
					fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
					if (!fieldtypes) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						for (iii = 0; iii < num_fields; iii++)
							if (jsonkeys[iii])
								free(jsonkeys[iii]);
						if (jsonkeys)
							free(jsonkeys);
						break;
					}
					jjj = 0;
					fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					if (!fieldtypes[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					if (wid) {
						jjj++;
						fieldtypes[jjj] = strdup(OPH_JSON_INT);
						if (!fieldtypes[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					}
					if (document_type) {
						jjj++;
						fieldtypes[jjj] = strdup(OPH_JSON_STRING);
						if (!fieldtypes[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
					} else {
						if (id_type) {
							jjj++;
							fieldtypes[jjj] = strdup(OPH_JSON_INT);
							if (!fieldtypes[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						}
						jjj++;
						if (level)
							fieldtypes[jjj] = strdup(OPH_JSON_STRING);
						else
							fieldtypes[jjj] = strdup(OPH_JSON_DOUBLE);
						if (!fieldtypes[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						/*
						   jjj++;
						   fieldtypes[jjj] = strdup(OPH_JSON_STRING);
						   if (!fieldtypes[jjj]) {
						   pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
						   for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						   if (jsonkeys) free(jsonkeys);
						   for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						   if (fieldtypes) free(fieldtypes);
						   break;
						   }
						 */
					}
					if (oph_json_add_grid
					    (oper_json, OPH_JSON_OBJKEY_RESUME, document_type ? (id_type ? "Command List" : "Request List") : (id_type ? "Response List" : "Workflow List"), NULL,
					     jsonkeys, num_fields, fieldtypes, num_fields)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID error\n", jobid);
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
				// Open the OphidiaDB
				ophidiadb oDB;
				oph_odb_initialize_ophidiadb(&oDB);

				if (oph_odb_read_config_ophidiadb(&oDB)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to read OphidiaDB configuration\n", jobid);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
				if (oph_odb_connect_to_ophidiadb(&oDB)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to connect to OphidiaDB. Check access parameters\n", jobid);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: CONNECTED to OphidiaDB\n", jobid);

				// Load data
				ophidiadb_list list;
				oph_odb_initialize_ophidiadb_list(&list);

				char query[OPH_MAX_STRING_SIZE];
				if (user && !id_type)
					snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_WORKFLOWS_OF_USER_SESSION, session, user, session, user);
				else if (document_type && id_type) {
					if (wid)
						snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_SUBMISSION_STRINGS_OF_WORKFLOW, session, wid, session, wid);
					else
						snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_SUBMISSION_STRINGS_OF_SESSION, session, session);
				} else if (id_type)
					snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_JOBS_OF_SESSION, session, session);
				else
					snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_WORKFLOWS_OF_SESSION, session, session, session, session);
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: execute query '%s'\n", jobid, query);
				if (oph_odb_retrieve_list(&oDB, query, &list)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to execute '%s'\n", jobid, query);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_odb_free_ophidiadb_list(&list);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}

				success = 0;
				while (!success) {
					oph_workflow *old_wf = NULL;
					char *buffer, *submission_string = NULL;
					struct stat s;
					char orig_request;

					for (i = 0; i < list.size; ++i) {
						if (document_type) {
							if (submission_string)
								free(submission_string);
							buffer = submission_string = NULL;
							if (id_type)
								submission_string = strdup(list.name[i] ? list.name[i] : "-");
							else {
								orig_request = document_type > 1;
								if (!orig_request) {
									snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_EXT,
										 oph_web_server_location, session_code, list.wid[i]);
									pthread_mutex_lock(&global_flag);	// setting of 'errno' could be thread-unsafe
									orig_request = stat(filename, &s) && (errno == ENOENT);
									pthread_mutex_unlock(&global_flag);
								}
								if (orig_request)
									snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_MAIN,
										 oph_web_server_location, session_code, list.wid[i]);
								if (oph_get_result_from_file(filename, &buffer) || !buffer) {
									pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to load JSON Request '%s'\n", jobid, filename);
									if (buffer)
										free(buffer);
									oph_json_free(oper_json);
									oph_odb_disconnect_from_ophidiadb(&oDB);
									oph_workflow_free(wf);
									oph_odb_free_ophidiadb_list(&list);
									oph_cleanup_args(&user_args);
									response->error = OPH_SERVER_IO_ERROR;
									return SOAP_OK;
								}
								if (level < 3) {
									if (!oph_workflow_load(buffer, userid, _host, &old_wf)) {
										if (level == 1) {
											if (old_wf->command)
												submission_string = strdup(old_wf->command);
											else if (old_wf->tasks_num == 1) {
												if (oph_workflow_get_submitted_string(old_wf, 0, -1, 1, &submission_string))
													submission_string = NULL;
											} else
												submission_string = strdup(old_wf->name);
										} else {
											if (old_wf->tasks_num == 1) {
												if (oph_workflow_get_submitted_string(old_wf, 0, -1, 1, &submission_string))
													submission_string = NULL;
											} else if (old_wf->command)
												submission_string = strdup(old_wf->command);
											else
												submission_string = strdup(old_wf->name);
										}
										oph_workflow_free(old_wf);
									}
								} else
									submission_string = strdup(buffer);
								free(buffer);
							}
						}

						jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							break;
						}
						jjj = 0;
						snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", session, OPH_SESSION_WORKFLOW_DELIMITER, list.wid[i], OPH_SESSION_MARKER_DELIMITER, list.id[i]);
						jsonvalues[jjj] = strdup(tmp);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						if (list.wid[i])
							snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", list.wid[i]);
						else
							snprintf(tmp, OPH_SHORT_STRING_SIZE, "-");
						jsonvalues[jjj] = strdup(tmp);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", list.id[i]);
						jsonvalues[jjj] = strdup(tmp);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(list.ctime[i]);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonvalues[iii])
									free(jsonvalues[iii]);
							if (jsonvalues)
								free(jsonvalues);
							break;
						}
						if (wid) {
							jjj++;
							if (list.pid[i])
								snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", list.pid[i]);
							else
								snprintf(tmp, OPH_SHORT_STRING_SIZE, "-");
							jsonvalues[jjj] = strdup(tmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
						}
						if (document_type) {
							jjj++;
							jsonvalues[jjj] = strdup(submission_string ? submission_string : "-");
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
						} else {
							if (id_type) {
								jjj++;
								if (list.pid[i])
									snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", list.pid[i]);
								else
									snprintf(tmp, OPH_SHORT_STRING_SIZE, "-");
								jsonvalues[jjj] = strdup(tmp);
								if (!jsonvalues[jjj]) {
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
							}
							jjj++;
							if (level) {
								if (list.max_status[i] && !strcmp(list.name[i], OPH_ODB_STATUS_RUNNING_STR) && !strcmp(list.max_status[i], OPH_ODB_STATUS_WAITING_STR))
									jsonvalues[jjj] = strdup(list.max_status[i]);
								else if (list.max_status[i] && !strcmp(list.name[i], OPH_ODB_STATUS_ERROR_STR)
									 && strcmp(list.max_status[i], OPH_ODB_STATUS_COMPLETED_STR)
									 && !strstr(list.max_status[i], "ERROR"))
									jsonvalues[jjj] = strdup(OPH_ODB_STATUS_RUNNING_ERROR_STR);
								else
									jsonvalues[jjj] = strdup(list.name[i]);
							} else {
								wpr = 1.0;
								oph_job_info *item = NULL;
								pthread_mutex_lock(&global_flag);
								item =
								    id_type ? oph_find_marker_in_job_list(state->job_info, session, list.id[i], NULL,
													  NULL) : oph_find_workflow_in_job_list(state->job_info, session, list.wid[i]);
								if (item && oph_get_progress_ratio_of(item->wf, &wpr, NULL)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
									pthread_mutex_unlock(&global_flag);
									for (iii = 0; iii < jjj; iii++)
										if (jsonvalues[iii])
											free(jsonvalues[iii]);
									if (jsonvalues)
										free(jsonvalues);
									break;
								}
								pthread_mutex_unlock(&global_flag);
								snprintf(tmp, OPH_SHORT_STRING_SIZE, "%f", wpr);
								jsonvalues[jjj] = strdup(tmp);
							}
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							/*
							   jjj++;
							   snprintf(tmp,OPH_SHORT_STRING_SIZE,"%d",list.id[i]);
							   snprintf(tmp,OPH_MAX_STRING_SIZE,OPH_JSON_RESPONSE_FILENAME,oph_web_server,session_code,tmp);
							   jsonvalues[jjj] = strdup(tmp);
							   if (!jsonvalues[jjj]) {
							   pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							   for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							   if (jsonvalues) free(jsonvalues);
							   break;
							   }
							 */
						}
						if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_RESUME, jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
					if (submission_string)
						free(submission_string);

					if (i < list.size)
						break;
					else
						success = 1;
				}

				// Close the OphidiaDB
				oph_odb_disconnect_from_ophidiadb(&oDB);
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: DISCONNECTED from OphidiaDB\n", jobid);

				oph_odb_free_ophidiadb_list(&list);
			}

			if (success && save)
				response->jobid = soap_strdup(soap, session);

			if (oper_json) {
				int return_code = 0;
				if (!success) {
					if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
						return_code = -1;
					} else if (oph_json_to_json_string(oper_json, &jstring))
						return_code = -1;
				} else {
					if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
						return_code = -1;
					} else if (oph_json_to_json_string(oper_json, &jstring))
						return_code = -1;
				}
				if (!return_code)
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: JSON output created\n", jobid);
			}
			oph_json_free(oper_json);
		} else		// Return the intended JSON Response
		{
			int workflow = 0, marker = 0;
			if (id_type)
				marker = id;
			else
				workflow = id;

			// Pre-check
			if ((workflow < 0) || (workflow > last_workflowid)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong workflowid '%d'\n", jobid, workflow);
				response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				oph_workflow_free(wf);
				oph_cleanup_args(&user_args);
				return SOAP_OK;
			}
			if ((marker < 0) || (marker > last_markerid)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong markerid '%d'\n", jobid, marker);
				response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				oph_workflow_free(wf);
				oph_cleanup_args(&user_args);
				return SOAP_OK;
			}
			// Open the OphidiaDB
			ophidiadb oDB;
			oph_odb_initialize_ophidiadb(&oDB);
			if (oph_odb_read_config_ophidiadb(&oDB)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to read OphidiaDB configuration\n", jobid);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_workflow_free(wf);
				oph_cleanup_args(&user_args);
				response->error = OPH_SERVER_IO_ERROR;
				return SOAP_OK;
			}
			if (oph_odb_connect_to_ophidiadb(&oDB)) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to connect to OphidiaDB. Check access parameters\n", jobid);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_workflow_free(wf);
				oph_cleanup_args(&user_args);
				response->error = OPH_SERVER_IO_ERROR;
				return SOAP_OK;
			}
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: CONNECTED to OphidiaDB\n", jobid);

			int n = 0, *markers = NULL;
			char **ctime = NULL;
			char query[OPH_MAX_STRING_SIZE], *submission_string = NULL, *creation_date = NULL;
			if (!document_type && !id_type && ((level == 1) || (level == 3)))	// JSON Response for workflow: extract specific outputs
			{
				snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_MARKERS_OF_WORKFLOW_TASKS, session, workflow, session, workflow);
				if (oph_odb_retrieve_ids(&oDB, query, &markers, &ctime, &n)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to retrieve marker id\n", jobid);
					if (markers) {
						free(markers);
						markers = NULL;
					}
					if (ctime) {
						free_string_vector(ctime, n);
						ctime = NULL;
					}
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
			} else if (document_type && id_type)	// Request for specific submission strings
			{
				ophidiadb_list list;
				oph_odb_initialize_ophidiadb_list(&list);

				snprintf(query, OPH_MAX_STRING_SIZE, MYSQL_RETRIEVE_SUBMISSION_STRING_OF_JOB, session, marker, session, marker);
				if (oph_odb_retrieve_list(&oDB, query, &list)) {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to load submission string of %s?%d#%d\n", jobid, session, workflow, marker);
					oph_odb_free_ophidiadb_list(&list);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
				n = list.size;
				if (n != 1) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unexpected number of rows '%d'\n", jobid, n);
					oph_odb_free_ophidiadb_list(&list);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
				markers = (int *) malloc(sizeof(int));
				if (!markers) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: memory allocation error\n", jobid);
					oph_odb_free_ophidiadb_list(&list);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				markers[0] = list.wid[0];
				submission_string = strdup(list.name[0] ? list.name[0] : "-");
				if (!submission_string) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: memory allocation error\n", jobid);
					if (markers) {
						free(markers);
						markers = NULL;
					}
					oph_odb_free_ophidiadb_list(&list);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				creation_date = strdup(list.ctime[0] ? list.ctime[0] : "-");
				if (!creation_date) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: memory allocation error\n", jobid);
					if (markers) {
						free(markers);
						markers = NULL;
					}
					if (creation_date)
						free(creation_date);
					oph_odb_free_ophidiadb_list(&list);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}

				oph_odb_free_ophidiadb_list(&list);
			} else	// Normal case
			{
				// Set the markerid by accessing OphidiaDB
				snprintf(query, OPH_MAX_STRING_SIZE, id_type ? MYSQL_RETRIEVE_WORKFLOW_BY_MARKER : MYSQL_RETRIEVE_MARKER_BY_WORKFLOW, session, id_type ? marker : workflow, session,
					 id_type ? marker : workflow);
				if (oph_odb_retrieve_ids(&oDB, query, &markers, &ctime, &n)) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to retrieve marker/workflow id\n", jobid);
					if (markers) {
						free(markers);
						markers = NULL;
					}
					if (ctime) {
						free_string_vector(ctime, n);
						ctime = NULL;
					}
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
				if (n != 1) {
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unexpected number of rows '%d'\n", jobid, n);
					if (markers) {
						free(markers);
						markers = NULL;
					}
					if (ctime) {
						free_string_vector(ctime, n);
						ctime = NULL;
					}
					oph_odb_disconnect_from_ophidiadb(&oDB);
					oph_workflow_free(wf);
					oph_cleanup_args(&user_args);
					response->error = OPH_SERVER_IO_ERROR;
					return SOAP_OK;
				}
			}

			// Close the OphidiaDB
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: DISCONNECTED from OphidiaDB\n", jobid);

			if (document_type) {
				// Open JSON Response
				while (!success) {
					if (oph_json_alloc(&oper_json)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: JSON alloc error\n", jobid);
						break;
					}
					if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", userid)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: SET SOURCE error\n", jobid);
						break;
					}
					if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
						break;
					}
					snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", workflow);
					if (oph_json_add_source_detail(oper_json, "Workflow", tmp)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
						break;
					}
					snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", marker);
					if (oph_json_add_source_detail(oper_json, "Marker", tmp)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
						break;
					}
					if (oph_json_add_source_detail(oper_json, "JobID", session)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD SOURCE DETAIL error\n", jobid);
						break;
					}
					if (oph_json_add_consumer(oper_json, userid)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD CONSUMER error\n", jobid);
						break;
					}
					success = 1;
				}

				if (success) {
					success = 0;
					while (!success) {
						// Header
						jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
						if (!jsonkeys) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							break;
						}
						jjj = 0;
						jsonkeys[jjj] = strdup("OPH JOB ID");
						if (!jsonkeys[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
						jjj++;
						jsonkeys[jjj] = strdup("MARKER ID");
						if (!jsonkeys[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
						jjj++;
						jsonkeys[jjj] = strdup("COMMAND");
						if (!jsonkeys[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < jjj; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
						fieldtypes = (char **) malloc(sizeof(char *) * num_fields);
						if (!fieldtypes) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
							for (iii = 0; iii < num_fields; iii++)
								if (jsonkeys[iii])
									free(jsonkeys[iii]);
							if (jsonkeys)
								free(jsonkeys);
							break;
						}
						jjj = 0;
						fieldtypes[jjj] = strdup(OPH_JSON_STRING);
						if (!fieldtypes[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
						if (oph_json_add_grid(oper_json, OPH_JSON_OBJKEY_RESUME, "Request List", NULL, jsonkeys, num_fields, fieldtypes, num_fields)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID error\n", jobid);
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
			} else
				success = 1;

			if (success) {
				char *buffer = NULL;
				int iterate = 1;
				for (i = 0; iterate && (i < n); ++i) {
					if (id_type)
						workflow = markers[i];
					else
						marker = markers[i];
					if (!marker || !workflow) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to extract markerid or workflowid\n", jobid);
						if (markers) {
							free(markers);
							markers = NULL;
						}
						if (ctime) {
							free_string_vector(ctime, n);
							ctime = NULL;
						}
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						response->error = OPH_SERVER_IO_ERROR;
						return SOAP_OK;
					}
					// Post-check
					if ((workflow < 0) || (workflow > last_workflowid)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong workflowid '%d'\n", jobid, workflow);
						if (markers) {
							free(markers);
							markers = NULL;
						}
						if (ctime) {
							free_string_vector(ctime, n);
							ctime = NULL;
						}
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}
					if ((marker < 0) || (marker > last_markerid)) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong markerid '%d'\n", jobid, marker);
						if (markers) {
							free(markers);
							markers = NULL;
						}
						if (ctime) {
							free_string_vector(ctime, n);
							ctime = NULL;
						}
						response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
						oph_workflow_free(wf);
						oph_cleanup_args(&user_args);
						return SOAP_OK;
					}

					if (!i) {
						if (save) {
							snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", session, OPH_SESSION_WORKFLOW_DELIMITER, workflow, OPH_SESSION_MARKER_DELIMITER, marker);
							response->jobid = soap_strdup(soap, oph_jobid);
						}
						if (n > 1)
							continue;	// In case of more than one rows then the first is related to the parent and the others are related to children
					}
#ifdef LEVEL1
#ifdef OPH_DIRECT_OUTPUT
					if (!document_type && !id_type && (level == 1) && (n > 2))	// Found a multi-task workflow --> show the task list
#else
					if (!document_type && !id_type && (level == 1))	// Show the task list
#endif
					{
						marker = markers[0];	// In case of more than one rows then the first is related to the parent and the others are related to children
						iterate = 0;
					}
#endif
					if (!document_type || !id_type) {
						oph_job_info *item = NULL;
						int task_index = -1, light_task_index = -1;

						pthread_mutex_lock(&global_flag);

						if (!document_type)
							item =
							    id_type ? oph_find_marker_in_job_list(state->job_info, session, marker, &task_index,
												  &light_task_index) : oph_find_workflow_in_job_list(state->job_info, session, workflow);

						if (!level) {	// Get the progress ratio

							char error_message[OPH_MAX_STRING_SIZE];
							*error_message = 0;

							char *sessionid = session, *username = wf->username, *name = NULL, *cstatus = NULL, *cdate = NULL;
							int workflowid = workflow, markerid = marker, status = -1;
							char ttype = 'R', success = 1;

							if (item) {
								sessionid = item->wf->sessionid;
								workflowid = item->wf->workflowid;
								markerid = item->wf->markerid;
								username = item->wf->username;
								name = item->wf->name;
								status = item->wf->status;
							} else {
								// Get workflow status and creation date
								if (oph_get_info_of(sessionid, workflowid, &cstatus, &cdate)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: unable to get workflow info\n", ttype, jobid);
									snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining workflow info!");
									success = 0;
								}
							}

							char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];
							snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER,
								 markerid);
							snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", workflowid);
							snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", markerid);

							// Save JSON related to parent job
							oph_json *oper_json = NULL;
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON initialization\n", ttype, jobid);

							char _success = 0;
							while (!_success) {
								if (oph_json_alloc_unsafe(&oper_json)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
									break;
								}
								if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", username)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
									break;
								}
								if (oph_get_session_code(sessionid, session_code)) {
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
								if (oph_json_add_consumer_unsafe(oper_json, username)) {
									pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
									break;
								}
								_success = 1;
							}
							if (!_success) {
								snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
								success = 0;
							}

							if (success) {
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: starting to format JSON file\n", ttype, jobid);

								int num_fields, iii, jjj = 0;

								char **jsonkeys = NULL;
								char **fieldtypes = NULL;
								char **jsonvalues = NULL;
								char jsontmp[OPH_MAX_STRING_SIZE];

								success = 0;
								while (!success) {
									if (oph_json_add_text_unsafe
									    (oper_json, OPH_JSON_OBJKEY_WORKFLOW_STATUS, "Workflow Status",
									     cstatus ? cstatus : oph_odb_convert_status_to_str(status))) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
										break;
									}
									// Progress
									num_fields = 2;
									jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
									if (!jsonkeys) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
										break;
									}
									jsonkeys[jjj] = strdup("CREATION DATE");
									if (!jsonkeys[jjj]) {
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
										for (iii = 0; iii < jjj; iii++)
											if (jsonkeys[iii])
												free(jsonkeys[iii]);
										if (jsonkeys)
											free(jsonkeys);
										break;
									}
									jjj++;
									jsonkeys[jjj] = strdup("PROGRESS RATIO");
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
									fieldtypes[jjj] = strdup(OPH_JSON_DOUBLE);
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
									if (oph_json_add_grid
									    (oper_json, OPH_JSON_OBJKEY_WORKFLOW_PROGRESS, "Workflow Progress Ratio", NULL, jsonkeys, num_fields, fieldtypes,
									     num_fields)) {
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

									wpr = 1.0;
									if (item && oph_get_progress_ratio_of(item->wf, &wpr, &cdate)) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error evaluationg progress ratio\n", ttype, jobid);
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining progress ratio!");
										break;
									}

									jjj = 0;
									jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
									if (!jsonvalues) {
										pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
										break;
									}

									jsonvalues[jjj] = cdate ? cdate : strdup("-");
									cdate = NULL;
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
									snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%f", wpr);
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

									if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_WORKFLOW_PROGRESS, jsonvalues)) {
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

									success = 1;
								}
							}

							if (cdate)
								free(cdate);
							if (cstatus)
								free(cstatus);

							if (success) {
								if (item && (item->wf->status == OPH_ODB_STATUS_ERROR)) {
									int ii, num_errors;
									for (ii = num_errors = 0; ii < item->wf->tasks_num; ++ii)
										if ((item->wf->tasks[ii].status >= (int) OPH_ODB_STATUS_ERROR)
										    && (item->wf->tasks[ii].status < (int) OPH_ODB_STATUS_ABORTED))
											num_errors++;
									snprintf(error_message, OPH_MAX_STRING_SIZE, "%d task%s failed!", num_errors, num_errors == 1 ? "" : "s");
								}
							}

							if (oper_json) {
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: finalizing JSON file\n", ttype, jobid);

								int return_code = 0;
								if (!success) {
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting error into JSON file\n", ttype, jobid);
									if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
										pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
										return_code = -1;
									} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
										return_code = -1;
								} else {
									if (strlen(error_message)) {
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting warning into JSON file\n", ttype, jobid);
										if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_WORKFLOW_SUMMARY, "WARNING", error_message)) {
											pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
											return_code = -1;
										}
									}
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting success into JSON file\n", ttype, jobid);
									if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
										pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
										return_code = -1;
									} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
										return_code = -1;
								}
								if (!return_code)
									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output for workflow '%s' has been written\n", ttype, jobid,
									      name ? name : "No-name");
							}
							oph_json_free(oper_json);
						} else if (item)	// Found a workflow in memory
						{
#ifdef LEVEL1
							if ((level == 1) && (item->wf->tasks_num > 1))	// Found a multi-task workflow --> show the task list
							{
								marker = markers[0];	// In case of more than one rows then the first is related to the parent and the others are related to children
								iterate = 0;
							}
#endif
							snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_MAIN, oph_web_server_location,
								 session_code, marker);
							if (oph_get_result_from_file_unsafe(filename, &jstring) || !jstring) {

								pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: no JSON Response found: build the virtual response\n", jobid, marker);

								// Build the virtual JSON Response
								char ttype = 'R', session_code[OPH_MAX_STRING_SIZE];
								int make_swap, swap, max_swap = 1;

								if (task_index < 0) {
									char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];

									snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER,
										 item->wf->workflowid, OPH_SESSION_MARKER_DELIMITER, item->wf->markerid);
									snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
									snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", item->wf->markerid);

									char error_message[OPH_MAX_STRING_SIZE];
									*error_message = 0;

									// Save JSON related to parent job
									oph_json *oper_json = NULL;
									int success = 0;

									pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON initialization\n", ttype, jobid);

									while (!success) {
										if (oph_json_alloc_unsafe(&oper_json)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
											break;
										}
										if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", item->wf->username)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
											break;
										}
										if (oph_get_session_code(item->wf->sessionid, session_code)) {
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
										if (oph_json_add_consumer_unsafe(oper_json, item->wf->username)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
											break;
										}
										success = 1;
									}

									if (!success)
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");

									int check_for_aborted = 0;
									if (success && item)	// Warning... "item" was in the shared memory, but now it is unbound from the list, so that it can be read after releasing the lock!!!
									{
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: starting to format JSON file\n", ttype, jobid);

										int num_fields, iii, jjj = 0, skipped_num;

										char **jsonkeys = NULL;
										char **fieldtypes = NULL;
										char **jsonvalues = NULL;
										char jsontmp[OPH_MAX_STRING_SIZE];

										success = 0;
										while (!success) {
											if (oph_json_add_text_unsafe
											    (oper_json, OPH_JSON_OBJKEY_WORKFLOW_STATUS, "Workflow Status",
											     oph_odb_convert_status_to_str(item->wf->status))) {
												pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												break;
											}
											// Progress
											num_fields = 3;
											jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
											if (!jsonkeys) {
												pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
												break;
											}
											jsonkeys[jjj] = strdup("NUMBER OF COMPLETED TASKS");
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
											jsonkeys[jjj] = strdup("NUMBER OF SKIPPED TASKS");
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
											jsonkeys[jjj] = strdup("TOTAL NUMBER OF TASKS");
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
											if (oph_json_add_grid
											    (oper_json, OPH_JSON_OBJKEY_WORKFLOW_PROGRESS, "Workflow Progress", NULL, jsonkeys, num_fields, fieldtypes,
											     num_fields)) {
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

											for (iii = skipped_num = 0; iii < wf->tasks_num; iii++)
												if (wf->tasks[iii].status >= (int) OPH_ODB_STATUS_ABORTED)
													skipped_num++;

											jjj = 0;
											snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%d", item->wf->tasks_num - item->wf->residual_tasks_num - skipped_num);
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
											snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%d", skipped_num);
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
											snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%d", item->wf->tasks_num);
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
											if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_WORKFLOW_PROGRESS, jsonvalues)) {
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

											// Header
											if (item->wf->output_format) {

												num_fields = 3;
												jjj = 0;
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
												if (oph_json_add_grid
												    (oper_json, OPH_JSON_OBJKEY_WORKFLOW_INFO, "Workflow Basic Information", NULL, jsonkeys, num_fields,
												     fieldtypes, num_fields)) {
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
												snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid,
													 OPH_SESSION_WORKFLOW_DELIMITER, item->wf->workflowid, OPH_SESSION_MARKER_DELIMITER,
													 item->wf->markerid);
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
												snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
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
												snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->markerid);
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

												if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_WORKFLOW_INFO, jsonvalues)) {
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

											num_fields = item->wf->output_format ? 4 : 8;
											jjj = 0;
											jsonkeys = (char **) malloc(sizeof(char *) * num_fields);
											if (!jsonkeys) {
												pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
												break;
											}
											if (!item->wf->output_format) {
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
											if (!item->wf->output_format) {
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
											jsonkeys[jjj] = strdup("TASK NAME");
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
											jsonkeys[jjj] = strdup("TYPE");
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
											if (!item->wf->output_format) {
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
											if (!item->wf->output_format) {
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
											    (oper_json, OPH_JSON_OBJKEY_WORKFLOW_LIST, "Workflow Task List", NULL, jsonkeys, num_fields, fieldtypes,
											     num_fields)) {
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
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: inserting data into JSON file\n", ttype, jobid);
											int ppp[item->wf->tasks_num];
											for (i = 0; i < item->wf->tasks_num; ++i)
												ppp[i] = i;
											do	// Order by markerid
											{
												make_swap = 0;
												for (i = 0; i < item->wf->tasks_num - max_swap; ++i)
													if (item->wf->tasks[ppp[i]].markerid > item->wf->tasks[ppp[i + 1]].markerid) {
														swap = ppp[i];
														ppp[i] = ppp[i + 1];
														ppp[i + 1] = swap;
														make_swap = 1;
														max_swap++;
													}
											}
											while (make_swap);

											for (i = 0; i < item->wf->tasks_num; ++i) {
												if (item->wf->tasks[i].status && oph_check_status_mask(item->wf->tasks[i].status, smask))	// Discard uninitialized or aborted jobs
												{
													jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
													if (!jsonvalues) {
														pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
														break;
													}
													jjj = 0;
													if (!item->wf->output_format) {
														snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid,
															 OPH_SESSION_WORKFLOW_DELIMITER, item->wf->workflowid,
															 OPH_SESSION_MARKER_DELIMITER, item->wf->tasks[i].markerid);
														jsonvalues[jjj] = strdup(jsontmp);
														if (!jsonvalues[jjj]) {
															pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype,
															      jobid);
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
															pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype,
															      jobid);
															for (iii = 0; iii < jjj; iii++)
																if (jsonvalues[iii])
																	free(jsonvalues[iii]);
															if (jsonvalues)
																free(jsonvalues);
															break;
														}
														jjj++;
														snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
														jsonvalues[jjj] = strdup(jsontmp);
														if (!jsonvalues[jjj]) {
															pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype,
															      jobid);
															for (iii = 0; iii < jjj; iii++)
																if (jsonvalues[iii])
																	free(jsonvalues[iii]);
															if (jsonvalues)
																free(jsonvalues);
															break;
														}
														jjj++;
													}
													snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->tasks[i].markerid);
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
													if (!item->wf->output_format) {
														snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->markerid);
														jsonvalues[jjj] = strdup(jsontmp);
														if (!jsonvalues[jjj]) {
															pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype,
															      jobid);
															for (iii = 0; iii < jjj; iii++)
																if (jsonvalues[iii])
																	free(jsonvalues[iii]);
															if (jsonvalues)
																free(jsonvalues);
															break;
														}
														jjj++;
													}
													jsonvalues[jjj] = strdup(item->wf->tasks[i].name);
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
													jsonvalues[jjj] = strdup(item->wf->tasks[i].light_tasks_num ? "MASSIVE" : "SIMPLE");
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
													jsonvalues[jjj] = strdup(oph_odb_convert_status_to_str(item->wf->tasks[i].status));
													if (!jsonvalues[jjj]) {
														pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: Error allocating memory\n", ttype, jobid);
														for (iii = 0; iii < jjj; iii++)
															if (jsonvalues[iii])
																free(jsonvalues[iii]);
														if (jsonvalues)
															free(jsonvalues);
														break;
													}
													if (oph_json_add_grid_row_unsafe(oper_json, OPH_JSON_OBJKEY_WORKFLOW_LIST, jsonvalues)) {
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
												if (item->wf->tasks[i].status == OPH_ODB_STATUS_ABORTED)
													check_for_aborted++;
											}

											if (i < item->wf->tasks_num)
												break;
											else
												success = 1;
										}
									}

									if (success) {
										if (item->wf->status == OPH_ODB_STATUS_ERROR) {
											int ii, num_errors;
											for (ii = num_errors = 0; ii < item->wf->tasks_num; ++ii)
												if ((item->wf->tasks[ii].status >= (int) OPH_ODB_STATUS_ERROR)
												    && (item->wf->tasks[ii].status < (int) OPH_ODB_STATUS_ABORTED))
													num_errors++;
											snprintf(error_message, OPH_MAX_STRING_SIZE, "%d task%s failed!", num_errors, num_errors == 1 ? "" : "s");
										} else if (check_for_aborted)
											snprintf(error_message, OPH_MAX_STRING_SIZE, "%d task%s %s aborted!", check_for_aborted,
												 check_for_aborted == 1 ? "" : "s", check_for_aborted == 1 ? "was" : "were");
									}

									if (oper_json) {
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: finalizing JSON file\n", ttype, jobid);

										int return_code = 0;
										if (!success) {
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting error into JSON file\n", ttype, jobid);
											if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
												pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												return_code = -1;
											} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
												return_code = -1;
										} else {
											if (strlen(error_message)) {
												pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting warning into JSON file\n", ttype, jobid);
												if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_WORKFLOW_SUMMARY, "WARNING", error_message)) {
													pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
													return_code = -1;
												}
											}
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: reporting success into JSON file\n", ttype, jobid);
											if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
												pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												return_code = -1;
											} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
												return_code = -1;
										}
										if (!return_code)
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output for workflow '%s' has been written\n", ttype, jobid,
											      item->wf->name);
									}
									oph_json_free(oper_json);
								} else if ((light_task_index < 0) && (item->wf->tasks[task_index].light_tasks_num))	// Massive operation
								{
									int success = 0;
									oph_json *oper_json = NULL;

									char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];

									snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER,
										 item->wf->workflowid, OPH_SESSION_MARKER_DELIMITER, item->wf->tasks[task_index].markerid);
									snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
									snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", item->wf->tasks[task_index].markerid);

									char error_message[OPH_MAX_STRING_SIZE];
									snprintf(error_message, OPH_MAX_STRING_SIZE, "Parent task data processing failed!");

									while (!success) {
										if (oph_json_alloc_unsafe(&oper_json)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
											break;
										}
										if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", item->wf->username)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
											break;
										}
										if (oph_get_session_code(item->wf->sessionid, session_code)) {
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
										if (oph_json_add_consumer_unsafe(oper_json, item->wf->username)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
											break;
										}
										success = 1;
									}

									unsigned int number_of_jobs = 0;
									if (!success)
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
									else {
										int num_fields = item->wf->output_format ? 2 : 6, iii, jjj = 0;

										char **jsonkeys = NULL;
										char **fieldtypes = NULL;
										char **jsonvalues = NULL;
										char jsontmp[OPH_MAX_STRING_SIZE];

										success = 0;
										while (!success) {
											if (oph_json_add_text
											    (oper_json, OPH_JSON_OBJKEY_MASSIVE_STATUS, "Massive Operation Status",
											     oph_odb_convert_status_to_str(item->wf->tasks[task_index].status))) {
												pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												break;
											}

											if (item->wf->output_format) {

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
												    (oper_json, OPH_JSON_OBJKEY_MASSIVE_INFO, "Massive Operation Information", NULL, jsonkeys,
												     num_fields, fieldtypes, num_fields)) {
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
												snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid,
													 OPH_SESSION_WORKFLOW_DELIMITER, item->wf->workflowid, OPH_SESSION_MARKER_DELIMITER,
													 item->wf->tasks[task_index].markerid);
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
												snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
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
												snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->tasks[task_index].markerid);
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
											if (!item->wf->output_format) {
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
											if (!item->wf->output_format) {
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
											if (!item->wf->output_format) {
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
											if (!item->wf->output_format) {
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
											    (oper_json, OPH_JSON_OBJKEY_MASSIVE_LIST, "Massive Operation Task List", NULL, jsonkeys, num_fields,
											     fieldtypes, num_fields)) {
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
											int ppp[item->wf->tasks[task_index].light_tasks_num];
											for (i = 0; i < item->wf->tasks_num; ++i)
												ppp[i] = i;
											do	// Order by markerid
											{
												make_swap = 0;
												for (i = 0; i < item->wf->tasks_num - max_swap; ++i)
													if (item->wf->tasks[task_index].light_tasks[ppp[i]].markerid >
													    item->wf->tasks[task_index].light_tasks[ppp[i + 1]].markerid) {
														swap = ppp[i];
														ppp[i] = ppp[i + 1];
														ppp[i + 1] = swap;
														make_swap = 1;
														max_swap++;
													}
											}
											while (make_swap);

											for (i = 0; i < item->wf->tasks[task_index].light_tasks_num; ++i) {
												if (item->wf->tasks[task_index].light_tasks[i].status && oph_check_status_mask(item->wf->tasks[task_index].light_tasks[i].status, smask))	// Discard uninitialized or aborted jobs
												{
													jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
													if (!jsonvalues) {
														pmesg(LOG_ERROR, __FILE__, __LINE__, "N%d: Error allocating memory\n", jobid);
														break;
													}
													jjj = 0;
													if (!item->wf->output_format) {
														snprintf(jsontmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid,
															 OPH_SESSION_WORKFLOW_DELIMITER, item->wf->workflowid,
															 OPH_SESSION_MARKER_DELIMITER,
															 item->wf->tasks[task_index].light_tasks[i].markerid);
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
														snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
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
													snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d",
														 item->wf->tasks[task_index].light_tasks[i].markerid);
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
													if (!item->wf->output_format) {
														snprintf(jsontmp, OPH_SHORT_STRING_SIZE, "%d", item->wf->tasks[task_index].markerid);
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
													jsonvalues[jjj] =
													    strdup(oph_odb_convert_status_to_str(item->wf->tasks[task_index].light_tasks[i].status));
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

											if (i < item->wf->tasks[task_index].light_tasks_num)
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
											} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
												return_code = -1;
										} else {
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: notify a warning\n", ttype, jobid);
											if (!number_of_jobs
											    && oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_MASSIVE_SUMMARY, "WARNING", "No job found!")) {
												pmesg(LOG_WARNING, __FILE__, __LINE__, "N%d: ADD TEXT error\n", ttype, jobid);
												return_code = -1;
											}
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: notify a success\n", ttype, jobid);
											if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
												pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												return_code = -1;
											} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
												return_code = -1;
										}
										if (!return_code)
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
									}
									oph_json_free_unsafe(oper_json);
								} else	// Single task (possible light task)
								{
									int success = 0;
									oph_json *oper_json = NULL;

									char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE];

									snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", item->wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER,
										 item->wf->workflowid, OPH_SESSION_MARKER_DELIMITER, marker);
									snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", item->wf->workflowid);
									snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", marker);

									char error_message[OPH_MAX_STRING_SIZE];
									*error_message = 0;

									while (!success) {
										if (oph_json_alloc_unsafe(&oper_json)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: JSON alloc error\n", ttype, jobid);
											break;
										}
										if (oph_json_set_source_unsafe(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", item->wf->username)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: SET SOURCE error\n", ttype, jobid);
											break;
										}
										if (oph_get_session_code(item->wf->sessionid, session_code)) {
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
										if (oph_json_add_consumer_unsafe(oper_json, item->wf->username)) {
											pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD CONSUMER error\n", ttype, jobid);
											break;
										}
										success = 1;
									}

									if (!success)
										snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
									else {
										success = 0;
										while (!success) {
											int tstatus = 0;
											if (light_task_index >= 0)
												tstatus = item->wf->tasks[task_index].light_tasks[light_task_index].status;
											else
												tstatus = item->wf->tasks[task_index].status;
											if (oph_json_add_text
											    (oper_json, OPH_JSON_OBJKEY_RESUME_STATUS, "Job Status", oph_odb_convert_status_to_str(tstatus))) {
												pmesg(LOG_ERROR, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												break;
											}
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
											} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
												return_code = -1;
										} else {
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: notify a success\n", ttype, jobid);
											if (oph_json_add_text_unsafe(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
												pmesg(LOG_WARNING, __FILE__, __LINE__, "%c%d: ADD TEXT error\n", ttype, jobid);
												return_code = -1;
											} else if (oph_json_to_json_string_unsafe(oper_json, &jstring))
												return_code = -1;
										}
										if (!return_code)
											pmesg(LOG_DEBUG, __FILE__, __LINE__, "%c%d: JSON output written\n", ttype, jobid);
									}
									oph_json_free_unsafe(oper_json);
								}
							} else
								pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: JSON Response found\n", jobid, marker);
						}

						pthread_mutex_unlock(&global_flag);

						if (level && !item)	// Check for the file
						{
							if (document_type) {
								struct stat s;
								// select the original workflow (or its extension in case of parallel for)
								if (!checkpoint || !strlen(checkpoint) || !strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_ALL)) {
									char orig_request = document_type > 1;
									if (!orig_request) {
										snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_EXT,
											 oph_web_server_location, session_code, workflow);
										pthread_mutex_lock(&global_flag);	// setting of 'errno' could be thread-unsafe
										orig_request = stat(filename, &s) && (errno == ENOENT);
										pthread_mutex_unlock(&global_flag);
									}
									if (orig_request)
										snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_MAIN,
											 oph_web_server_location, session_code, workflow);
								} else {	// otherwise select a sub-workflow from a checkpoint
									char checkpoint_not_found = 0;
									snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_CHECKPOINT,
										 oph_web_server_location, session_code, workflow, checkpoint);
									pthread_mutex_lock(&global_flag);	// setting of 'errno' could be thread-unsafe
									checkpoint_not_found = stat(filename, &s) && (errno == ENOENT);
									pthread_mutex_unlock(&global_flag);
									if (checkpoint_not_found) {
										pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: checkpoint '%s' not found\n", jobid, checkpoint);
										if (markers) {
											free(markers);
											markers = NULL;
										}
										if (ctime) {
											free_string_vector(ctime, n);
											ctime = NULL;
										}
										response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
										oph_workflow_free(wf);
										oph_cleanup_args(&user_args);
										if (jstring)
											free(jstring);
										oph_json_free(oper_json);
										return SOAP_OK;
									}
								}
							} else
								snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_MAIN, oph_web_server_location,
									 session_code, marker);
							if (oph_get_result_from_file(filename, &jstring) || !jstring) {
								pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to load JSON %s '%s'\n", jobid,
									   document_type ? "Request" : "Response", filename);
								if (markers) {
									free(markers);
									markers = NULL;
								}
								if (ctime) {
									free_string_vector(ctime, n);
									ctime = NULL;
								}
								response->error = OPH_SERVER_NO_RESPONSE;
								oph_workflow_free(wf);
								oph_cleanup_args(&user_args);
								if (jstring)
									free(jstring);
								oph_json_free(oper_json);
								return SOAP_OK;
							}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
							// Run the workflow as a new request
							if (execute) {
								struct soap *tsoap = soap_copy(soap);
								if (tsoap) {
									if (!tsoap->userid && soap->userid)
										tsoap->userid = strdup(soap->userid);
									if (!tsoap->passwd && soap->passwd)
										tsoap->passwd = strdup(soap->passwd);
									_ophExecuteMain_data *data = (_ophExecuteMain_data *) malloc(sizeof(_ophExecuteMain_data));
									data->soap = tsoap;
									data->request = strdup(jstring);
									pthread_t tid;
									pthread_create(&tid, NULL, (void *(*)(void *)) &_ophExecuteMain, data);
								}
							}
#endif
						}
					}

					if (document_type) {
						if (id_type)
							jstring = submission_string;
						else if (level < 3)	// JSON Request: extract synthetic command
						{
							oph_workflow *old_wf = NULL;
							submission_string = NULL;
							if (!oph_workflow_load(jstring, userid, _host, &old_wf)) {
								if (level == 1) {
									if (old_wf->command)
										submission_string = strdup(old_wf->command);
									else if (old_wf->tasks_num == 1) {
										if (oph_workflow_get_submitted_string(old_wf, 0, -1, 1, &submission_string))
											submission_string = NULL;
									} else
										submission_string = strdup(old_wf->name);
								} else	// if (level==2)
								{
									if (old_wf->tasks_num == 1) {
										if (oph_workflow_get_submitted_string(old_wf, 0, -1, 1, &submission_string))
											submission_string = NULL;
									} else if (old_wf->command)
										submission_string = strdup(old_wf->command);
									else
										submission_string = strdup(old_wf->name);
								}
								oph_workflow_free(old_wf);
							}
							if (submission_string) {
								free(jstring);
								jstring = submission_string;
							}
						}

						success = 0;
						while (!success) {
							jsonvalues = (char **) malloc(sizeof(char *) * num_fields);
							if (!jsonvalues) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								break;
							}
							jjj = 0;
							snprintf(tmp, OPH_MAX_STRING_SIZE, "%s%s%d%s%d", session, OPH_SESSION_WORKFLOW_DELIMITER, workflow, OPH_SESSION_MARKER_DELIMITER, marker);
							jsonvalues[jjj] = strdup(tmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
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
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", workflow);
							jsonvalues[jjj] = strdup(tmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", marker);
							jsonvalues[jjj] = strdup(tmp);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = creation_date ? creation_date : strdup(ctime[i]);
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							jjj++;
							jsonvalues[jjj] = strdup(jstring ? jstring : "-");
							if (!jsonvalues[jjj]) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: Error allocating memory\n", jobid);
								for (iii = 0; iii < jjj; iii++)
									if (jsonvalues[iii])
										free(jsonvalues[iii]);
								if (jsonvalues)
									free(jsonvalues);
								break;
							}
							if (oph_json_add_grid_row(oper_json, OPH_JSON_OBJKEY_RESUME, jsonvalues)) {
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: ADD GRID ROW error\n", jobid);
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
						if (jstring)
							free(jstring);
					} else if (buffer) {
						char *pbuffer = buffer;
						buffer = NULL;
						if (asprintf(&buffer, "%s%s", pbuffer, jstring) > 0)
							free(pbuffer);
						else {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: Error allocating buffer for response... skipping\n", jobid);
							if (buffer)
								free(buffer);
							buffer = pbuffer;
						}
						if (jstring)
							free(jstring);
					} else
						buffer = jstring;
				}
				if (!document_type)
					jstring = buffer;
				else
					free(buffer);
			}

			if (markers) {
				free(markers);
				markers = NULL;
			}
			if (ctime) {
				free_string_vector(ctime, n);
				ctime = NULL;
			}

			if (document_type) {
				// Close JSON
				if (oper_json) {
					int return_code = 0;
					if (!success) {
						if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "ERROR", error_message)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
							return_code = -1;
						} else if (oph_json_to_json_string(oper_json, &jstring))
							return_code = -1;
					} else {
						if (oph_json_add_text(oper_json, OPH_JSON_OBJKEY_STATUS, "SUCCESS", NULL)) {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: ADD TEXT error\n", jobid);
							return_code = -1;
						} else if (oph_json_to_json_string(oper_json, &jstring))
							return_code = -1;
					}
					if (!return_code)
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: JSON output created\n", jobid);
				}
				oph_json_free(oper_json);
			}
		}

		// Update user data
		if (save) {
			// Change last_session and save user data
			if (oph_set_arg(&user_args, OPH_USER_LAST_SESSION_ID, session)) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_LAST_SESSION_ID);
				oph_cleanup_args(&user_args);
				oph_workflow_free(wf);
				if (jstring)
					free(jstring);
				response->error = OPH_SERVER_SYSTEM_ERROR;
				return SOAP_OK;
			}
			pthread_mutex_lock(&global_flag);
			if (oph_save_user(_userid, user_args)) {
				pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user data of '%s'\n", jobid, userid);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&user_args);
				oph_workflow_free(wf);
				if (jstring)
					free(jstring);
				response->error = OPH_SERVER_SYSTEM_ERROR;
				return SOAP_OK;
			}
			pthread_mutex_unlock(&global_flag);
		}
		// Log into WF_LOGFILE
		if (wf_logfile) {
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
			fprintf(wf_logfile, "%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%f\n", buffer, 0, wf->name, sha_username, wf->ip_address ? wf->ip_address : OPH_UNKNOWN,
				wf->client_address ? wf->client_address : OPH_UNKNOWN, 1, 1, (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->timestamp);
			fflush(wf_logfile);
			pthread_mutex_unlock(&curl_flag);
		}
		oph_workflow_free(wf);
		oph_cleanup_args(&user_args);

		if (!jstring) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to convert JSON Response into a string\n", jobid);
			response->error = OPH_SERVER_SYSTEM_ERROR;
			return SOAP_OK;
		}

		if (strlen(_new_token)) {
			char **keys = (char **) malloc(sizeof(char *)), **values = (char **) malloc(sizeof(char *));
			if (keys && values) {
				keys[0] = strdup(OPH_AUTH_TOKEN_JSON);
				values[0] = strdup(_new_token);
				if (keys[0] && values[0]) {
					if (oph_add_extra(&jstring, keys, values, 1))
						response->response = soap_strdup(soap, jstring);
				}
			}
			free_string_vector(keys, 1);
			free_string_vector(values, 1);
		}
		if (!response->response)
			response->response = soap_strdup(soap, jstring);
		free(jstring);

		pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "R%d has been processed\n", jobid);
		return SOAP_OK;
	}

	oph_mode_type mode_type;
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for mode type\n", jobid);
	if (!wf->exec_mode) {
		mode_type = OPH_MODE_DEFAULT;
		wf->exec_mode = strdup(OPH_ARG_MODE_DEFAULT);
	} else if (!strncasecmp(wf->exec_mode, OPH_ARG_MODE_ASYNC, OPH_MAX_STRING_SIZE)) {
		mode_type = OPH_MODE_ASYNC;
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: execution mode is ASYNC\n", jobid);
	} else if (!strncasecmp(wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
		mode_type = OPH_MODE_SYNC;
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: execution mode is SYNC\n", jobid);
	} else {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong mode '%s'\n", jobid, wf->exec_mode);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		oph_workflow_free(wf);
		oph_cleanup_args(&user_args);
		return SOAP_OK;
	}

	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->incoming_workflows++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}
	// Load previous session (if any)
	if (load_previous_session && !wf->sessionid && !oph_get_arg(user_args, OPH_USER_LAST_SESSION_ID, tmp))
		wf->sessionid = strdup(tmp);

	// Test user data
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_OPENED_SESSIONS);
	int num_sessions = oph_get_arg(user_args, OPH_USER_OPENED_SESSIONS, tmp);
	if (num_sessions)
		num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
	else
		num_sessions = strtol(tmp, NULL, 10);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_MAX_CORES);
	int max_cores = oph_get_arg(user_args, OPH_USER_MAX_CORES, tmp);
	if (max_cores)
		max_cores = oph_default_max_cores;
	else
		max_cores = strtol(tmp, NULL, 10);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_MAX_HOSTS);
	int max_hosts = oph_get_arg(user_args, OPH_USER_MAX_HOSTS, tmp);
	if (max_hosts)
		max_hosts = oph_default_max_hosts;
	else
		max_hosts = strtol(tmp, NULL, 10);
	wf->max_hosts = max_hosts;

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_MAX_SESSIONS);
	int max_sessions = oph_get_arg(user_args, OPH_USER_MAX_SESSIONS, tmp);
	if (max_sessions)
		max_sessions = oph_default_max_sessions;
	else
		max_sessions = strtol(tmp, NULL, 10);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_TIMEOUT_SESSION);
	int timeout_value = oph_get_arg(user_args, OPH_USER_TIMEOUT_SESSION, tmp);
	if (timeout_value)
		timeout_value = oph_default_session_timeout;
	else
		timeout_value = strtol(tmp, NULL, 10);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: check for %s\n", jobid, OPH_USER_OS_USERNAME);
	wf->os_username = strdup(oph_get_arg(user_args, OPH_USER_OS_USERNAME, tmp) || !strlen(tmp) ? wf->username : tmp);

	// Check for number of cores
	if (ncores < OPH_DEFAULT_CORES) {
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong '%s': %d. Minimum is %d\n", jobid, OPH_ARG_NCORES, ncores, OPH_DEFAULT_CORES);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
	}
	if (max_cores && (ncores > max_cores)) {
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong '%s': %d. Maximum is %d\n", jobid, OPH_ARG_NCORES, ncores, max_cores);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
	}
	// Check for number of hosts
	if (nhosts < OPH_DEFAULT_HOSTS) {
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong '%s': %d. Minimum is %d\n", jobid, OPH_ARG_NHOSTS, nhosts, OPH_DEFAULT_HOSTS);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
	}
	if (max_hosts && (nhosts > max_hosts)) {
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: received wrong '%s': %d. Maximum is %d\n", jobid, OPH_ARG_NHOSTS, nhosts, max_hosts);
		response->error = OPH_SERVER_WRONG_PARAMETER_ERROR;
		return SOAP_OK;
	}

	char str_markerid[OPH_SHORT_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE];

	pthread_mutex_lock(&global_flag);
	if ((result =
	     oph_generate_oph_jobid(state, 'R', jobid, wf, &num_sessions, max_sessions, timeout_value, &(wf->markerid), str_markerid, &(wf->workflowid), str_workflowid, oph_jobid, wf->markerid))) {
		pthread_mutex_unlock(&global_flag);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = result == OPH_WORKFLOW_EXIT_AUTH_ERROR ? OPH_SERVER_AUTH_ERROR : OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	pthread_mutex_unlock(&global_flag);

	// Change and save user specific data
	snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", num_sessions);
	if (oph_set_arg(&user_args, OPH_USER_OPENED_SESSIONS, tmp)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_OPENED_SESSIONS);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	if (oph_set_arg(&user_args, OPH_USER_LAST_SESSION_ID, wf->sessionid)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_LAST_SESSION_ID);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	if (oph_set_arg(&user_args, OPH_USER_LAST_EXEC_MODE, wf->exec_mode)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_LAST_EXEC_MODE);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	snprintf(tmp, OPH_SHORT_STRING_SIZE, "%d", ncores);
	if (oph_set_arg(&user_args, OPH_USER_LAST_NCORES, tmp)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to set '%s'\n", jobid, OPH_USER_LAST_NCORES);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	pthread_mutex_lock(&global_flag);
	if (oph_save_user(_userid, user_args)) {
		pthread_mutex_unlock(&global_flag);
		oph_cleanup_args(&user_args);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	pthread_mutex_unlock(&global_flag);

	oph_cleanup_args(&user_args);

	char session_code[OPH_MAX_STRING_SIZE];
	if (oph_get_session_code(wf->sessionid, session_code)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to get session code\n", jobid);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		oph_workflow_free(wf);
		return SOAP_OK;
	}
	// Save the request
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_JSON_REQUEST_FILENAME, oph_web_server_location, session_code, str_workflowid);
	FILE *fil = fopen(filename, "w");
	if (fil) {
		fprintf(fil, "%s", request);
		fclose(fil);
	} else
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save the request\n", jobid);

	char *submission_string = NULL;
	if (wf->command)
		submission_string = strdup(wf->command);
	else if (wf->tasks_num == 1) {
		if (oph_workflow_get_submitted_string(wf, 0, -1, 0, &submission_string))
			submission_string = NULL;
	} else
		submission_string = strdup(wf->name);
	if (!oph_session_report_append_command(session_code, wf->workflowid, wf->markerid, wf->username, submission_string ? submission_string : request))
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: command added to session report\n", jobid);
	if (submission_string)
		free(submission_string);

	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->accepted_workflows++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}

	if (wf->parallel_mode) {
		// Save the extended JSON request
		char *jstring = NULL;
		pthread_mutex_lock(&global_flag);
		if (oph_workflow_store(wf, &jstring, NULL)) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to create the extended JSON Request\n", jobid);
			pthread_mutex_unlock(&global_flag);
			if (jstring)
				free(jstring);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		pthread_mutex_unlock(&global_flag);

		char linkname[OPH_SHORT_STRING_SIZE], filename[OPH_MAX_STRING_SIZE];
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_EXT, oph_web_server_location, session_code, wf->workflowid);
		FILE *fil = fopen(filename, "w");
		if (fil) {
			fprintf(fil, "%s", jstring);
			fclose(fil);
		} else
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save the extended JSON Request\n", jobid);

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: extended JSON Request saved\n", jobid);
		if (jstring)
			free(jstring);

		snprintf(linkname, OPH_SHORT_STRING_SIZE, OPH_SESSION_OUTPUT_EXT, wf->workflowid);
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE "/" OPH_SESSION_OUTPUT_EXT, oph_web_server, session_code, wf->workflowid);
		oph_session_report_append_link(session_code, wf->workflowid, NULL, linkname, filename, 'R');
	}
	// Open the OphidiaDB
	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (oph_odb_read_config_ophidiadb(&oDB)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to read OphidiaDB configuration\n", jobid);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_IO_ERROR;
		return SOAP_OK;
	}
	if (oph_odb_connect_to_ophidiadb(&oDB)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to connect to OphidiaDB. Check access parameters.\n", jobid);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_IO_ERROR;
		return SOAP_OK;
	}
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: CONNECTED to OphidiaDB\n", jobid);

	if (oph_odb_retrieve_user_id(&oDB, wf->username, &wf->iduser)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to retrieve user id.\n", jobid);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_IO_ERROR;
		return SOAP_OK;
	}

	int odb_jobid = 0;

	// Save the job in OphidiaDB
	HASHTBL *task_tbl = hashtbl_create(5, NULL);
	if (!task_tbl) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to create hash table.\n", jobid);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	hashtbl_insert(task_tbl, OPH_ARG_SESSIONID, wf->sessionid);
	hashtbl_insert(task_tbl, OPH_ARG_MARKERID, str_markerid);
	hashtbl_insert(task_tbl, OPH_ARG_USERNAME, wf->username);
	hashtbl_insert(task_tbl, OPH_ARG_WORKFLOWID, str_workflowid);
	if (oph_odb_create_job(&oDB, wf->command ? wf->command : wf->name, task_tbl, wf->tasks_num, &odb_jobid)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: unable to save job parameters into OphidiaDB. Check access parameters.\n", jobid);
		oph_odb_disconnect_from_ophidiadb(&oDB);
		hashtbl_destroy(task_tbl);
		oph_workflow_free(wf);
		response->error = OPH_SERVER_IO_ERROR;
		return SOAP_OK;
	}
	if (task_tbl) {
		hashtbl_destroy(task_tbl);
		task_tbl = NULL;
	}
	wf->idjob = odb_jobid;
	wf->status = OPH_ODB_STATUS_PENDING;

	// Save the job in memory
	if ((result = oph_wf_list_append(state->job_info, wf))) {
		if (result != OPH_SERVER_NO_RESPONSE)	// Workflow queued
		{
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_workflow_free(wf);
			response->error = OPH_SERVER_IO_ERROR;
			return SOAP_OK;
		} else
			wf->status = OPH_ODB_STATUS_UNKNOWN;	// Used only for queue management, real status is OPH_ODB_STATUS_PENDING
	}

	if (wf->status)		// else the workflow has been queued
	{
		// Initialize the workflow
		int *initial_tasks_indexes = NULL, initial_tasks_indexes_num = 0;
		if (oph_workflow_init(wf->tasks, wf->tasks_num, &initial_tasks_indexes, &initial_tasks_indexes_num)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: initial tasks of workflow '%s' cannot be initialized\n", jobid, wf->name);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_wf_list_drop(state->job_info, wf->idjob);
			free(initial_tasks_indexes);
			response->error = OPH_SERVER_SYSTEM_ERROR;
			return SOAP_OK;
		}
		// Set basic variables
		if (oph_workflow_set_basic_var(wf)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: basic variables of workflow '%s' cannot be set\n", jobid, wf->name);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_wf_list_drop(state->job_info, wf->idjob);
			free(initial_tasks_indexes);
			response->error = OPH_SERVER_SYSTEM_ERROR;
			return SOAP_OK;
		}
		// Create temporary host partition (if any)
		if (oph_workflow_create_hp(wf, &oDB)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: host partition cannot be set for workflow '%s'\n", jobid, wf->name);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_wf_list_drop(state->job_info, wf->idjob);
			free(initial_tasks_indexes);
			response->error = OPH_SERVER_SYSTEM_ERROR;
			return SOAP_OK;
		}
		// Execute the workflow
		char *jobid_response = NULL;
		if (oph_workflow_execute(state, 'R', jobid, wf, initial_tasks_indexes, initial_tasks_indexes_num, &oDB, &jobid_response)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "R%d: workflow '%s' cannot be executed\n", jobid, wf->name);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_wf_list_drop(state->job_info, wf->idjob);
			free(initial_tasks_indexes);
			response->error = OPH_SERVER_SYSTEM_ERROR;
			return SOAP_OK;
		}
		free(initial_tasks_indexes);
		if (jobid_response)	// Update oph_jobid according to specific command. Used only for oph_manage_session
		{
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s", jobid_response);
			free(jobid_response);
		}
		oph_workflow_check_job_queue(state);
	}
	// Close the OphidiaDB
	oph_odb_disconnect_from_ophidiadb(&oDB);
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: DISCONNECTED from OphidiaDB\n", jobid);


	// Set oph_jobid
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: output string is '%s'\n", jobid, oph_jobid);
	response->jobid = soap_strdup(soap, oph_jobid);


	// Outputing
	if (mode_type == OPH_MODE_SYNC) {
		// Block the master thread until workflow is completed
		pthread_mutex_lock(&global_flag);
		while (!wf->is_closed && (wf->status < (int) OPH_ODB_STATUS_ABORTED)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: waiting for workflow end\n", jobid);
			pthread_cond_wait(&termination_flag, &global_flag);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: a workflow is finished; status of '%s' is %s\n", jobid, wf->name, oph_odb_convert_status_to_str(wf->status));
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "R%d: the workflow '%s' is completed\n", jobid, wf->name);
		pthread_mutex_unlock(&global_flag);

		if (wf->response && wf->is_closed) {

			unsigned int nextra = 1;

			// Save user data in user.dat
			if (wf->cdd) {
				oph_init_args(&user_args);
				snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_FILE, oph_auth_location, _userid);
				pthread_mutex_lock(&global_flag);
				if (oph_load_file(filename, &user_args))	// DT_REG
				{
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to load user data of '%s'\n", jobid, _userid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&user_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				if (oph_set_arg(&user_args, OPH_USER_LAST_CDD, wf->cdd)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user data of '%s'\n", jobid, _userid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&user_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				if (oph_save_user(_userid, user_args)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user data of '%s'\n", jobid, _userid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&user_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&user_args);
				nextra++;
			}

			int skip = 0;
			oph_argument *session_args = NULL;

			// Save session data in <session_code>.session
			if (wf->cube) {
				oph_init_args(&session_args);
				snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, _userid, session_code);
				pthread_mutex_lock(&global_flag);
				if (oph_load_file(filename, &session_args))	// DT_LNK
				{
					if (oph_known_operator == OPH_MANAGE_SESSION_OPERATOR)
						skip = 1;
					else {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to load session data of '%s'\n", jobid, wf->sessionid);
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&session_args);
						oph_workflow_free(wf);
						response->error = OPH_SERVER_SYSTEM_ERROR;
						return SOAP_OK;
					}
				}
				if (!skip && oph_set_arg(&session_args, OPH_SESSION_CUBE, wf->cube)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save session data of '%s'\n", jobid, wf->sessionid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&session_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				if (!skip && oph_save_session(_userid, wf->sessionid, session_args, DT_LNK)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save session data of '%s'\n", jobid, wf->sessionid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&session_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&session_args);
				nextra++;
			}
			// Save user-specific session data in <session_code>.user
			if (!skip && wf->cwd) {
				oph_init_args(&session_args);
				snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, _userid, session_code);
				pthread_mutex_lock(&global_flag);
				if (oph_load_file(filename, &session_args))	// DT_REG
				{
					if (oph_known_operator == OPH_MANAGE_SESSION_OPERATOR)
						skip = 1;
					else {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to load user-specific session data of '%s'\n", jobid, wf->sessionid);
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&session_args);
						oph_workflow_free(wf);
						response->error = OPH_SERVER_SYSTEM_ERROR;
						return SOAP_OK;
					}
				}
				if (!skip && oph_set_arg(&session_args, OPH_SESSION_CWD, wf->cwd)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user-specific session data of '%s'\n", jobid, wf->sessionid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&session_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				if (!skip && oph_save_user_session(_userid, wf->sessionid, session_args)) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "R%d: unable to save user-specific session data of '%s'\n", jobid, wf->sessionid);
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&session_args);
					oph_workflow_free(wf);
					response->error = OPH_SERVER_SYSTEM_ERROR;
					return SOAP_OK;
				}
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&session_args);
				nextra++;
			}
#ifdef OPH_DIRECT_OUTPUT
#if defined(LEVEL1)
			if (wf->response && (wf->tasks_num == 1)) {	// Add volatile extra data only in case of the output of single commands

				unsigned int iextra = 0;
				if (strlen(_new_token))
					nextra++;

				struct timeval tv;
				gettimeofday(&tv, 0);
				char exec_time[OPH_SHORT_STRING_SIZE];
				snprintf(exec_time, OPH_SHORT_STRING_SIZE, "%.2f", (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0) - wf->timestamp);
				char **keys = (char **) calloc(nextra, sizeof(char *)), **values = (char **) calloc(nextra, sizeof(char *));
				while (keys && values) {

					keys[iextra] = strdup(OPH_EXEC_TIME);
					values[iextra] = strdup(exec_time);
					if (!keys[iextra] || !values[iextra])
						break;
					iextra++;
					if (wf->cdd) {
						keys[iextra] = strdup(OPH_ARG_CDD);
						values[iextra] = strdup(wf->cdd);
						if (!keys[iextra] || !values[iextra])
							break;
						iextra++;
					}
					if (wf->cube) {
						keys[iextra] = strdup(OPH_ARG_CUBE);
						values[iextra] = strdup(wf->cube);
						if (!keys[iextra] || !values[iextra])
							break;
						iextra++;
					}
					if (wf->cwd) {
						keys[iextra] = strdup(OPH_ARG_CWD);
						values[iextra] = strdup(wf->cwd);
						if (!keys[iextra] || !values[iextra])
							break;
						iextra++;
					}
					if (strlen(_new_token)) {
						keys[iextra] = strdup(OPH_AUTH_TOKEN_JSON);
						values[iextra] = strdup(_new_token);
						if (!keys[iextra] || !values[iextra])
							break;
						iextra++;
					}

					break;
				}

				if (oph_add_extra(&wf->response, keys, values, iextra))	// iextra is correct
					response->response = soap_strdup(soap, wf->response);
				free_string_vector(keys, nextra);
				free_string_vector(values, nextra);
			}
#endif
#endif

			if (!response->response)
				response->response = soap_strdup(soap, wf->response);

			if (oph_status_log_file_name) {
				oph_job_info *item = (oph_job_info *) malloc(sizeof(oph_job_info));
				item->wf = wf;
				pthread_mutex_lock(&global_flag);
				oph_save_job_in_job_list(state->job_info, item);
				pthread_mutex_unlock(&global_flag);
			} else
				oph_workflow_free(wf);

			if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
				pthread_mutex_lock(&service_flag);
#endif
				service_info->outcoming_responses++;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
				pthread_mutex_unlock(&service_flag);
#endif
			}

		} else {

			char is_aborted = wf->status == (int) OPH_ODB_STATUS_ABORTED;

			if (is_aborted) {

				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "R%d: workflow '%s' has been aborted\n", jobid, wf->name);

				int success = 0;
				oph_json *oper_json = NULL;

				char str_jobid[OPH_MAX_STRING_SIZE], str_workflowid[OPH_SHORT_STRING_SIZE], str_markerid[OPH_SHORT_STRING_SIZE], session_code[OPH_MAX_STRING_SIZE], *my_output_json =
				    NULL;
				snprintf(str_workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
				snprintf(str_markerid, OPH_SHORT_STRING_SIZE, "%d", wf->markerid);
				snprintf(str_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", wf->sessionid, OPH_SESSION_WORKFLOW_DELIMITER, str_workflowid, OPH_SESSION_MARKER_DELIMITER, str_markerid);

				char error_message[OPH_MAX_STRING_SIZE], ttype = 'R';
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Workflow aborted!");

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
				// In case of waiting tasks are still active
				oph_job_info *item = NULL, *prev = NULL;
				if ((item = oph_find_job_in_job_list(state->job_info, wf->idjob, &prev))) {
					oph_drop_from_job_list(state->job_info, item, prev);
					free(item);
				}
				pthread_cond_broadcast(&waiting_flag);

				pthread_mutex_unlock(&global_flag);

				oph_json_free_unsafe(oper_json);

				if (!response->response)
					response->response = soap_strdup(soap, my_output_json);
				free(my_output_json);

			} else
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "R%d: error in serving the request\n", jobid);

			if (oph_status_log_file_name) {
				oph_job_info *item = (oph_job_info *) malloc(sizeof(oph_job_info));
				item->wf = wf;
				pthread_mutex_lock(&global_flag);
				oph_save_job_in_job_list(state->job_info, item);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "R%d: append the workflow '%s' in job list\n", jobid, wf->name);
				pthread_mutex_unlock(&global_flag);
			} else
				oph_workflow_free(wf);

			if (!response->error && !is_aborted)
				response->error = OPH_SERVER_SYSTEM_ERROR;

			return SOAP_OK;
		}
	}

	pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "R%d has been satified\n", jobid);
	return SOAP_OK;
}
