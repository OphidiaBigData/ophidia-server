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

#include "oph.nsmap"

#include "oph_utils.h"
#include "hashtbl.h"
#include "oph_rmanager.h"
#include "oph_ophidiadb.h"
#include "oph_task_parser_library.h"
#include "oph_workflow_engine.h"
#include "oph_service_info.h"

#include <unistd.h>
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <threads.h>
#include <pthread.h>
#endif
#include <signal.h>
#ifdef OPH_DB_SUPPORT
#include <mysql.h>
#endif

#define OPH_STATUS_LOG_PERIOD 1
#define OPH_STATUS_LOG_HYSTERESIS_PERIOD 2
#define OPH_STATUS_LOG_ALPHA 0.5
#define OPH_STATUS_LOG_AVG_PERIOD 60

/******************************************************************************\
 *
 *	Forward decls
 *
\******************************************************************************/

void *process_request(struct soap *);
void *status_logger(struct soap *);
int CRYPTO_thread_setup();
void CRYPTO_thread_cleanup();
int oph_handle_signals();
void oph_signal_handler(int sig);
void oph_child_signal_handler(int sig);

/******************************************************************************\
 *
 *	Global variables
 *
\******************************************************************************/

struct soap *psoap;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_mutex_t global_flag;
pthread_mutex_t libssh2_flag;
pthread_mutex_t curl_flag;
pthread_mutex_t service_flag;
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
int oph_server_inactivity_timeout = OPH_SERVER_INACTIVITY_TIMEOUT;
int oph_server_workflow_timeout = OPH_SERVER_WORKFLOW_TIMEOUT;
FILE *logfile = 0;
FILE *wf_logfile = 0;
FILE *task_logfile = 0;
FILE *statuslogfile = 0;
char *oph_log_file_name = 0;
char *oph_status_log_file_name = 0;
char *oph_wf_csv_log_file_name = 0;
char *oph_task_csv_log_file_name = 0;
char *oph_server_cert = 0;
char *oph_server_ca = 0;
char *oph_server_password = 0;
char *oph_rmanager_conf_file = 0;
char *oph_auth_location = 0;
char *oph_json_location = 0;
char *oph_txt_location = 0;
char *oph_web_server = 0;
char *oph_web_server_location = 0;
char *oph_operator_client = 0;
char *oph_ip_target_host = 0;
char oph_subm_ssh = 0;
char *oph_subm_user = 0;
char *oph_subm_user_publk = 0;
char *oph_subm_user_privk = 0;
char *oph_xml_operators = 0;
char *oph_xml_operator_dir = 0;
char *oph_user_notifier = 0;
unsigned int oph_server_farm_size = 0;
unsigned int oph_server_queue_size = 0;
unsigned int oph_auto_retry = 0;
unsigned int oph_server_poll_time = OPH_SERVER_POLL_TIME;
oph_rmanager *orm = 0;
int oph_service_status = 1;
ophidiadb *ophDB = 0;
int last_idjob = 0;
char oph_server_is_running = 1;
char *oph_base_src_path = 0;
unsigned int oph_base_backoff = 0;
oph_service_info *service_info = NULL;
unsigned int oph_default_max_sessions = OPH_DEFAULT_USER_MAX_SESSIONS;
unsigned int oph_default_max_cores = OPH_DEFAULT_USER_MAX_CORES;
unsigned int oph_default_max_hosts = OPH_DEFAULT_USER_MAX_HOSTS;
unsigned int oph_default_session_timeout = OPH_DEFAULT_SESSION_TIMEOUT;
char oph_cluster_deployment = 0;
char oph_auth_enabled = 1;
char oph_cancel_all_enabled = 0;
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

int oph_status_code(enum oph__oph_odb_job_status code)
{
	switch (code) {
		case OPH_ODB_STATUS_ERROR:
		case OPH_ODB_STATUS_START_ERROR:
			return 1;
		case OPH_ODB_STATUS_ABORTED:
			return 2;
		case OPH_ODB_STATUS_EXPIRED:
			return 3;
		case OPH_ODB_STATUS_PENDING:
			return 4;
		case OPH_ODB_STATUS_WAIT:
			return 5;
		case OPH_ODB_STATUS_RUNNING:
			return 6;
		case OPH_ODB_STATUS_COMPLETED:
			return 7;
		default:
			return 0;
	}
	return 0;
}

int set_global_values(const char *configuration_file)
{
	if (!freopen(OPH_SERVER_DEV_NULL, "r", stdin)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in redirect stdin\n");
		return OPH_SERVER_IO_ERROR;
	}

	if (!configuration_file)
		return OPH_SERVER_NULL_POINTER;
	pmesg(LOG_INFO, __FILE__, __LINE__, "Loading configuration from '%s'\n", configuration_file);

	oph_server_params = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
	if (!oph_server_params) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
		return OPH_SERVER_SYSTEM_ERROR;
	}

	char tmp[OPH_MAX_STRING_SIZE];
	char *value;
	FILE *file = fopen(configuration_file, "r");
	if (file) {
		char key[OPH_MAX_STRING_SIZE], value2[OPH_MAX_STRING_SIZE];
		while (fgets(tmp, OPH_MAX_STRING_SIZE, file)) {
			if (strlen(tmp)) {
				tmp[strlen(tmp) - 1] = '\0';
				if (tmp[0] == OPH_COMMENT_MARK)
					continue;	// Skip possible commented lines
				value = strchr(tmp, OPH_SEPARATOR_KV[0]);
				if (value) {
					value++;
					snprintf(key, value - tmp, "%s", tmp);
					if (value[0]) {
						if (value[0] == OPH_SUBSTITUTION_MARK && !strncasecmp(value + 1, OPH_SERVER_LOCATION_STR, strlen(OPH_SERVER_LOCATION_STR))) {
							snprintf(value2, OPH_MAX_STRING_SIZE, "%s%s", oph_server_location, value + strlen(OPH_SERVER_LOCATION_STR) + 1);
							value = value2;
						}
						hashtbl_insert(oph_server_params, key, value);
					} else
						hashtbl_insert(oph_server_params, key, "");
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Read %s=%s\n", key, value);
				}
			}
		}
		fclose(file);
	}
	// Pre-process
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_TIMEOUT)))
		oph_server_timeout = strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_INACTIVITY_TIMEOUT)))
		oph_server_inactivity_timeout = strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WORKFLOW_TIMEOUT)))
		oph_server_workflow_timeout = strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SERVER_FARM_SIZE)))
		oph_server_farm_size = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_QUEUE_SIZE)))
		oph_server_queue_size = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AUTO_RETRY)))
		oph_auto_retry = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_POLL_TIME)))
		oph_server_poll_time = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_BASE_BACKOFF)))
		oph_base_backoff = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_DEFAULT_MAX_SESSIONS)))
		oph_default_max_sessions = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_DEFAULT_MAX_CORES)))
		oph_default_max_cores = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_DEFAULT_MAX_HOSTS)))
		oph_default_max_hosts = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_DEFAULT_TIMEOUT_SESSION)))
		oph_default_session_timeout = (unsigned int) strtol(value, NULL, 10);
	if (!logfile && (value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_LOGFILE))) {
		if ((logfile = fopen(value, "a"))) {
			pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log file '%s'\n", value);
			set_log_file(logfile);
		}
		// Redirect stdout and stderr to logfile
		if (!freopen(value, "a", stdout))
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in redirect stdout to logfile\n");
		if (!freopen(value, "a", stderr))
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in redirect stderr to logfile\n");
	}
	if (!wf_logfile && (value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WF_LOGFILE))) {
		if ((wf_logfile = fopen(value, "a")))
			pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log file '%s'\n", value);
	}
	if (!task_logfile && (value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_TASK_LOGFILE))) {
		if ((task_logfile = fopen(value, "a")))
			pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log file '%s'\n", value);
	}
	// Default values
	if (!oph_server_protocol && !(oph_server_protocol = hashtbl_get(oph_server_params, OPH_SERVER_CONF_PROTOCOL))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_PROTOCOL, OPH_DEFAULT_PROTOCOL);
		oph_server_protocol = hashtbl_get(oph_server_params, OPH_SERVER_CONF_PROTOCOL);
	}
	if (!oph_server_host && !(oph_server_host = hashtbl_get(oph_server_params, OPH_SERVER_CONF_HOST))) {
		if (!gethostname(tmp, OPH_MAX_STRING_SIZE))
			hashtbl_insert(oph_server_params, OPH_SERVER_CONF_HOST, tmp);
		else
			hashtbl_insert(oph_server_params, OPH_SERVER_CONF_HOST, OPH_DEFAULT_HOST);
		oph_server_host = hashtbl_get(oph_server_params, OPH_SERVER_CONF_HOST);
	}
	if (!oph_server_port && !(oph_server_port = hashtbl_get(oph_server_params, OPH_SERVER_CONF_PORT))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_PORT, OPH_DEFAULT_PORT);
		oph_server_port = hashtbl_get(oph_server_params, OPH_SERVER_CONF_PORT);
	}
	if (!(oph_server_cert = hashtbl_get(oph_server_params, OPH_SERVER_CONF_CERT))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SERVER_CERT, oph_server_location);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_CERT, tmp);
		oph_server_cert = hashtbl_get(oph_server_params, OPH_SERVER_CONF_CERT);
	}
	if (!(oph_server_ca = hashtbl_get(oph_server_params, OPH_SERVER_CONF_CA))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SERVER_CA, oph_server_location);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_CA, tmp);
		oph_server_ca = hashtbl_get(oph_server_params, OPH_SERVER_CONF_CA);
	}
	if (!(oph_server_password = hashtbl_get(oph_server_params, OPH_SERVER_CONF_CERT_PASSWORD))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_CERT_PASSWORD, OPH_SERVER_PASSWORD);
		oph_server_password = hashtbl_get(oph_server_params, OPH_SERVER_CONF_CERT_PASSWORD);
	}
	if (!(oph_rmanager_conf_file = hashtbl_get(oph_server_params, OPH_SERVER_CONF_RMANAGER_CONF_FILE))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_RMANAGER_CONF_FILE, oph_server_location);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_RMANAGER_CONF_FILE, tmp);
		oph_rmanager_conf_file = hashtbl_get(oph_server_params, OPH_SERVER_CONF_RMANAGER_CONF_FILE);
	}
	if (!(oph_auth_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SERVER_AUTHZ, oph_server_location);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR, tmp);
		oph_auth_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR);
	}
	if (!(oph_txt_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_TXT_DIR))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_TXT_LOCATION, oph_server_location);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_TXT_DIR, tmp);
		oph_txt_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_TXT_DIR);
	}
	if (!(oph_web_server = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_WEB_SERVER);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_WEB_SERVER, tmp);
		oph_web_server = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER);
	}
	if (strlen(oph_web_server) > OPH_LONG_STRING_SIZE) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Length of parameter '%s' is too high\n", OPH_LONG_STRING_SIZE);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (!(oph_web_server_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER_LOCATION))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_WEB_SERVER_LOCATION);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_WEB_SERVER_LOCATION, tmp);
		oph_web_server_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER_LOCATION);
	}
	if (!(oph_operator_client = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPERATOR_CLIENT))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_OPERATOR_CLIENT);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_OPERATOR_CLIENT, tmp);
		oph_operator_client = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPERATOR_CLIENT);
	}
	if (!(oph_ip_target_host = hashtbl_get(oph_server_params, OPH_SERVER_CONF_IP_TARGET_HOST))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_IP_TARGET_HOST);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_IP_TARGET_HOST, tmp);
		oph_ip_target_host = hashtbl_get(oph_server_params, OPH_SERVER_CONF_IP_TARGET_HOST);
	}
	if (!(oph_subm_user = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SUBM_USER))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SUBM_USER);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_SUBM_USER, tmp);
		oph_subm_user = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SUBM_USER);
	}
	if (!(oph_subm_user_publk = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SUBM_USER_PUBLK))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SUBM_USER_PUBLK);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_SUBM_USER_PUBLK, tmp);
		oph_subm_user_publk = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SUBM_USER_PUBLK);
	}
	if (!(oph_subm_user_privk = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SUBM_USER_PRIVK))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SUBM_USER_PRIVK);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_SUBM_USER_PRIVK, tmp);
		oph_subm_user_privk = hashtbl_get(oph_server_params, OPH_SERVER_CONF_SUBM_USER_PRIVK);
	}
	if (!(oph_xml_operators = hashtbl_get(oph_server_params, OPH_SERVER_CONF_XML_URL))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_CLIENT_XML_URL);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_XML_URL, tmp);
		oph_xml_operators = hashtbl_get(oph_server_params, OPH_SERVER_CONF_XML_URL);
	}
	if (!(oph_xml_operator_dir = hashtbl_get(oph_server_params, OPH_SERVER_CONF_XML_DIR))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_SERVER_XML_EXT_PATH);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_XML_DIR, tmp);
		oph_xml_operator_dir = hashtbl_get(oph_server_params, OPH_SERVER_CONF_XML_DIR);
	}
	if (!(oph_user_notifier = hashtbl_get(oph_server_params, OPH_SERVER_CONF_NOTIFIER))) {
		snprintf(tmp, OPH_MAX_STRING_SIZE, OPH_USER_NOTIFIER);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_NOTIFIER, tmp);
		oph_user_notifier = hashtbl_get(oph_server_params, OPH_SERVER_CONF_NOTIFIER);
	}
	if (!(oph_base_src_path = hashtbl_get(oph_server_params, OPH_SERVER_CONF_BASE_SRC_PATH))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_BASE_SRC_PATH, OPH_BASE_SRC_PATH);
		oph_base_src_path = hashtbl_get(oph_server_params, OPH_SERVER_CONF_BASE_SRC_PATH);
	}
	value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_ENABLE_CLUSTER_DEPLOYMENT);
	if (value && !strcasecmp(value, OPH_DEFAULT_YES))
		oph_cluster_deployment = 1;
	value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_ENABLE_AUTHORIZATION);
	if (value && !strcasecmp(value, OPH_DEFAULT_NO))
		oph_auth_enabled = 0;
	value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_ENABLE_CANCEL_ALL);
	if (value && !strcasecmp(value, OPH_DEFAULT_YES))
		oph_cancel_all_enabled = 1;
	value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WORKING_DIR);
	if (value && chdir(value))
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Unable to change working directory to '%s'\n", value);
#ifdef OPH_OPENID_SUPPORT
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_TOKEN_TIMEOUT)))
		oph_openid_token_timeout = (unsigned int) strtol(value, NULL, 10);
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_TOKEN_CHECK_TIME)))
		oph_openid_token_check_time = (unsigned int) strtol(value, NULL, 10);
	oph_openid_endpoint = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_ENDPOINT);
	oph_openid_client_id = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_CLIENT_ID);
	oph_openid_client_secret = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_CLIENT_SECRET);
	oph_openid_user_name = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_USER_NAME);
	if (oph_openid_user_name) {
		if (!strcmp(oph_openid_user_name, OPH_SERVER_CONF_OPENID_USER_NAME_SUB)) {
		} else if (!strcmp(oph_openid_user_name, OPH_SERVER_CONF_OPENID_USER_NAME_PREFERRED)) {
		} else if (!strcmp(oph_openid_user_name, OPH_SERVER_CONF_OPENID_USER_NAME_NAME)) {
		} else if (!strcmp(oph_openid_user_name, OPH_SERVER_CONF_OPENID_USER_NAME_EMAIL)) {
		} else {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "OPENID: wrong '%s': it will set to '%s'\n", OPH_SERVER_CONF_OPENID_USER_NAME, OPH_SERVER_CONF_OPENID_USER_NAME_SUB);
			oph_openid_user_name = NULL;
		}
	}
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_ALLOW_LOCAL_USER))) {
		if (!strcmp(value, OPH_COMMON_YES))
			oph_openid_allow_local_user = 1;
		else if (strcmp(value, OPH_COMMON_NO))
			pmesg(LOG_WARNING, __FILE__, __LINE__, "OPENID: wrong '%s': it will set to '%s'\n", OPH_SERVER_CONF_OPENID_ALLOW_LOCAL_USER, OPH_COMMON_NO);
	}
#endif
#ifdef OPH_AAA_SUPPORT
	if ((value = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AAA_TOKEN_CHECK_TIME)))
		oph_aaa_token_check_time = (unsigned int) strtol(value, NULL, 10);
	oph_aaa_endpoint = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AAA_ENDPOINT);
	if (!(oph_aaa_category = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AAA_CATEGORY))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_AAA_CATEGORY, OPH_AAA_CATEGORY);
		oph_aaa_category = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AAA_CATEGORY);
	}
	if (!(oph_aaa_name = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AAA_NAME))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_AAA_NAME, OPH_AAA_NAME);
		oph_aaa_name = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AAA_NAME);
	}
#endif

	oph_json_location = oph_web_server_location;	// Position of JSON Response will be the same of web server

	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (!oph_odb_read_config_ophidiadb(&oDB) && !oph_odb_connect_to_ophidiadb(&oDB) && !oph_odb_get_last_id(&oDB, &last_idjob))
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Starting from idjob %d\n", last_idjob);
	else
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Last idjob is not available: starting with 0\n");
	oph_odb_disconnect_from_ophidiadb(&oDB);

	return OPH_SERVER_OK;
}

/******************************************************************************\
 *
 *	Clean up
 *
\******************************************************************************/

void cleanup()
{
	pmesg(LOG_INFO, __FILE__, __LINE__, "Server shutdown\n");
	oph_server_is_running = 0;
	if (oph_status_log_file_name)
		oph_status_log_file_name = NULL;
#ifdef OPH_OPENID_SUPPORT
	oph_openid_token_check_time = 0;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	if (token_tid_openid)
		pthread_cancel(token_tid_openid);
#endif
#endif
#ifdef OPH_AAA_SUPPORT
	oph_aaa_token_check_time = 0;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	if (token_tid_aaa)
		pthread_cancel(token_tid_aaa);
#endif
#endif

	sleep(OPH_STATUS_LOG_PERIOD);

	if (statuslogfile) {
		fclose(statuslogfile);
		statuslogfile = NULL;
	}
	if (wf_logfile) {
		fclose(wf_logfile);
		wf_logfile = NULL;
	}
	if (task_logfile) {
		fclose(task_logfile);
		task_logfile = NULL;
	}
#ifdef OPH_DB_SUPPORT
	mysql_library_end();
#endif
	soap_destroy(psoap);
	soap_end(psoap);
	soap_done(psoap);
	CRYPTO_thread_cleanup();
	if (service_info)
		free(service_info);
	if (logfile) {
		fclose(logfile);
		fclose(stdout);
		fclose(stderr);
	}
	if (oph_server_params)
		hashtbl_destroy(oph_server_params);
#ifdef OPH_SERVER_LOCATION
	if (oph_server_location)
		free(oph_server_location);
#endif
	if (orm)
		free_oph_rmanager(orm);
	if (ophDB)
		oph_odb_free_ophidiadb(ophDB);
	oph_auth_free();
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_destroy(&global_flag);
	pthread_mutex_destroy(&libssh2_flag);
	pthread_mutex_destroy(&curl_flag);
	pthread_mutex_destroy(&service_flag);
	pthread_cond_destroy(&termination_flag);
	pthread_cond_destroy(&waiting_flag);
#endif
	oph_tp_end_xml_parser();
}

/******************************************************************************\
 *
 *	Main
 *
\******************************************************************************/

int main(int argc, char *argv[])
{
	SOAP_SOCKET m;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_t tid;
	pthread_mutex_init(&global_flag, NULL);
	pthread_mutex_init(&libssh2_flag, NULL);
	pthread_mutex_init(&curl_flag, NULL);
	pthread_mutex_init(&service_flag, NULL);
	pthread_cond_init(&termination_flag, NULL);
	pthread_cond_init(&waiting_flag, NULL);
#endif
	struct soap soap, *tsoap = NULL;
	psoap = &soap;

	int ch, msglevel = LOG_INFO;
	static char *USAGE = "\nUSAGE:\noph_server [-d] [-l <log_file>] [-p <port>] [-v] [-w]\n";

	fprintf(stdout, "%s", OPH_VERSION);
	fprintf(stdout, "%s", OPH_DISCLAIMER);

	set_debug_level(msglevel + 10);

	while ((ch = getopt(argc, argv, "ac:dhl:mp:s:t:vwxz")) != -1) {
		switch (ch) {
			case 'a':
				oph_auth_enabled = 0;
				break;
			case 'c':
				oph_wf_csv_log_file_name = optarg;
				break;
			case 'd':
				msglevel = LOG_DEBUG;
				break;
			case 'h':
				fprintf(stdout, "%s", USAGE);
				return 0;
			case 'l':
				oph_log_file_name = optarg;
				break;
			case 'm':
				oph_subm_ssh = 1;
				break;
			case 'p':
				oph_server_port = optarg;
				break;
			case 's':
				oph_status_log_file_name = optarg;
				break;
			case 't':
				oph_task_csv_log_file_name = optarg;
				break;
			case 'v':
				return 0;
				break;
			case 'w':
				if (msglevel < LOG_WARNING)
					msglevel = LOG_WARNING;
				break;
			case 'x':
				fprintf(stdout, "%s", OPH_WARRANTY);
				return 0;
			case 'z':
				fprintf(stdout, "%s", OPH_CONDITIONS);
				return 0;
			default:
				fprintf(stdout, "%s", USAGE);
				return 0;
		}
	}

	set_debug_level(msglevel + 10);
	pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log level %d\n", msglevel);

#ifdef OPH_SERVER_LOCATION
	oph_server_location = strdup(OPH_SERVER_LOCATION);
#else
	oph_server_location = getenv(OPH_SERVER_LOCATION_STR);
	if (!oph_server_location) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPH_SERVER_LOCATION has to be set\n");
		return 1;
	}
#endif
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Server location '%s'\n", oph_server_location);

	char configuration_file[OPH_MAX_STRING_SIZE];
	snprintf(configuration_file, OPH_MAX_STRING_SIZE, OPH_CONFIGURATION_FILE, oph_server_location);
	if (set_global_values(configuration_file)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in loading server configuration\n");
		return 1;
	}

	if (oph_auth_check_location())
		oph_auth_enabled = 0;
	if (!oph_auth_enabled)
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Authorization procedure disabled\n");

	service_info = (oph_service_info *) calloc(1, sizeof(oph_service_info));

	if (oph_log_file_name) {
		if (logfile)
			fclose(logfile);
		if (!(logfile = fopen(oph_log_file_name, "a"))) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong log file name '%s'\n", oph_log_file_name);
			return 1;
		}
		pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log file '%s'\n", oph_log_file_name);
		if (logfile)
			set_log_file(logfile);
	} else
		oph_log_file_name = hashtbl_get(oph_server_params, OPH_SERVER_CONF_LOGFILE);

	if (oph_status_log_file_name)
		pmesg(LOG_INFO, __FILE__, __LINE__, "Selected status log file '%s'\n", oph_status_log_file_name);
	if (oph_wf_csv_log_file_name) {
		if (wf_logfile)
			fclose(wf_logfile);
		if (!(wf_logfile = fopen(oph_wf_csv_log_file_name, "a"))) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong log file name '%s'\n", oph_wf_csv_log_file_name);
			return 1;
		}
		pmesg(LOG_INFO, __FILE__, __LINE__, "Selected workflow log file '%s'\n", oph_wf_csv_log_file_name);
	}
	if (oph_task_csv_log_file_name) {
		if (task_logfile)
			fclose(task_logfile);
		if (!(task_logfile = fopen(oph_task_csv_log_file_name, "a"))) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong log file name '%s'\n", oph_task_csv_log_file_name);
			return 1;
		}
		pmesg(LOG_INFO, __FILE__, __LINE__, "Selected task log file '%s'\n", oph_task_csv_log_file_name);
	}
	if (wf_logfile && !ftell(wf_logfile))
		fprintf(wf_logfile, "timestamp\tidworkflow\tname\tusername\tip_address\tclient_address\t#tasks\t#success_tasks\tduration\n");
	if (task_logfile && !ftell(task_logfile))
		fprintf(task_logfile, "timestamp\tidtask\tidworkflow\toperator\t#cores\tsuccess_flag\tduration\n");

	int int_port = strtol(oph_server_port, NULL, 10);

	if (oph_handle_signals()) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "A problem occurred while setting up signal dispositions\n");
		exit(1);
	}
#ifdef OPH_DB_SUPPORT
	if (mysql_library_init(0, 0, 0)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot setup MySQL\n");
		exit(1);
	}
#endif

	oph_tp_start_xml_parser();
	if (CRYPTO_thread_setup()) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot setup thread mutex for OpenSSL\n");
		exit(1);
	}
	soap_init(&soap);
	soap.fget = oph_http_get;
	if (soap_register_plugin(&soap, oph_plugin)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot register %s plugin\n", OPH_PLUGIN_ID);
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(-1);
	}
	// Register serverid
	struct oph_plugin_data *state = NULL;
	if (!(state = (struct oph_plugin_data *) soap_lookup_plugin(&soap, OPH_PLUGIN_ID))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error on lookup plugin struct\n");
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(-1);
	}
	state->serverid = strdup(oph_web_server);

#ifdef WITH_OPENSSL
	/* init gsoap context and SSL */
	if (soap_ssl_server_context(&soap, SOAP_TLSv1_2, oph_server_cert, oph_server_password, oph_server_ca, NULL, NULL, NULL, NULL)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "SSL Server Context Error\n");
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(1);
	}
#endif

	soap.accept_timeout = oph_server_inactivity_timeout;
	soap.send_timeout = soap.recv_timeout = oph_server_timeout;
	soap.bind_flags |= SO_REUSEADDR;
	m = soap_bind(&soap, NULL, int_port, 100);
	if (!soap_valid_socket(m)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Soap invalid socket\n");
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(1);
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Bind successful: socket = %d\n", m);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	if (oph_status_log_file_name) {
		tsoap = soap_copy(&soap);
		if (tsoap)
			pthread_create(&tid, NULL, (void *(*)(void *)) &status_logger, tsoap);
	}
#endif

	oph_auth_autocheck_tokens();

	for (;;) {
		SOAP_SOCKET s = soap_accept(&soap);
		if (!soap_valid_socket(s)) {
			if (soap.errnum) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Soap invalid socket\n");
				soap_print_fault(&soap, stderr);
			} else
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Server timed out (timeout set to %d seconds)\n", soap.accept_timeout);
			break;
		}
		tsoap = soap_copy(&soap);
		if (!tsoap) {
			soap_closesock(&soap);
			continue;
		}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_create(&tid, NULL, (void *(*)(void *)) &process_request, tsoap);
#else
		process_request(tsoap);
#endif
	}
	cleanup();
	return 0;
}

void *process_request(struct soap *soap)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif

#ifdef WITH_OPENSSL
	if (soap_ssl_accept(soap) != SOAP_OK) {
		/* when soap_ssl_accept() fails, socket is closed and SSL data reset */
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SSL request failed, continue with next call...\n");
		soap_print_fault(soap, stderr);
	} else
#endif
		soap_serve(soap);

	soap_destroy(soap);	/* for C++ */
	soap_end(soap);
	soap_free(soap);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif

	return (void *) NULL;
}

#define OPH_SERVER_MAX_WF_LOG_PARAM 10

typedef struct _oph_status_object {
	char *key;
	char *tag[OPH_SERVER_MAX_WF_LOG_PARAM];
	unsigned long value[OPH_SERVER_MAX_WF_LOG_PARAM];
	struct _oph_status_object *next;
} oph_status_object;

int oph_status_add(oph_status_object ** list, const char *key, unsigned long *old_value, char **tag, size_t number_of_tags, unsigned long *new_value, size_t number_of_new_values)
{
	if (!list || !key || (number_of_tags > OPH_SERVER_MAX_WF_LOG_PARAM) || (number_of_new_values > OPH_SERVER_MAX_WF_LOG_PARAM))
		return 1;

	size_t i, j, key_size = strlen(key);
	char _key[1 + 2 * key_size];
	for (i = j = 0; i <= key_size; ++i, ++j) {
		if (key[i] == ' ')
			_key[j++] = '\\';
		_key[j] = key[i];
	}

	oph_status_object *tmp;
	if (!new_value) {
		for (tmp = *list; tmp; tmp = tmp->next)
			if (tmp->key && !strcmp(tmp->key, _key)) {
				tmp->value[0]++;
				return 0;
			}
	}

	tmp = (oph_status_object *) malloc(sizeof(oph_status_object));
	if (!tmp)
		return 2;
	tmp->key = strdup(_key);
	if (!tmp->key)
		return 3;
	i = 0;
	if (tag)
		for (; i < number_of_tags; ++i)
			tmp->tag[i] = tag[i];
	for (; i < OPH_SERVER_MAX_WF_LOG_PARAM; ++i)
		tmp->tag[i] = NULL;
	if (new_value)
		for (i = 0; i < number_of_new_values; ++i)
			tmp->value[i] = new_value[i];

	tmp->next = *list;
	*list = tmp;

	if (old_value)
		++ * old_value;

	return 0;
}

int oph_status_destroy(oph_status_object ** list)
{
	if (!list)
		return 1;

	int i;
	oph_status_object *tmp, *next;
	for (tmp = *list; tmp; tmp = next) {
		next = tmp->next;
		if (tmp->key)
			free(tmp->key);
		for (i = 0; i < OPH_SERVER_MAX_WF_LOG_PARAM; i++)
			if (tmp->tag[i])
				free(tmp->tag[i]);
		free(tmp);
	}
	*list = NULL;

	return 0;
}

void reset_load_average(unsigned long *load_average)
{
	unsigned int i;
	for (i = 0; i < OPH_STATUS_LOG_AVG_PERIOD; i++)
		load_average[i] = 0;
}

unsigned int eval_load_average(unsigned long *load_average)
{
	unsigned int result = 0, i;
	for (i = 0; i < OPH_STATUS_LOG_AVG_PERIOD; i++)
		result += load_average[i];
	return result;
}

void *status_logger(struct soap *soap)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif

	struct oph_plugin_data *state = NULL;
	if (!(state = (struct oph_plugin_data *) soap_lookup_plugin((struct soap *) soap, OPH_PLUGIN_ID))) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on oph lookup plugin struct\n");
		return (void *) NULL;
	}

	unsigned long aw;	// Number of active workflows
	unsigned long pw;	// Number of pending workflows
	unsigned long ww;	// Number of waiting workflows
	unsigned long rw;	// Number of running workflows
	unsigned long iw;	// Number of incoming workflows from last snapshoot
	unsigned long dw;	// Number of outcoming workflows from last snapshoot
	unsigned long at;	// Number of active tasks
	unsigned long pt;	// Number of pending tasks
	unsigned long wt;	// Number of waiting tasks
	unsigned long rt;	// Number of running tasks
	unsigned long mt;	// Number of massive tasks
	unsigned long it;	// Number of incoming tasks from last snapshoot
	unsigned long st;	// Number of submmitted tasks from last snapshoot
	unsigned long dt;	// Number of completed tasks from last snapshoot
	unsigned long lt;	// Number of active light tasks
	unsigned long plt;	// Number of pending light tasks
	unsigned long rlt;	// Number of running light tasks
	unsigned long ct;	// Number of completed tasks
	unsigned long ft;	// Number of failed tasks
	unsigned long un;	// Number of users
	unsigned long cn;	// Number of active cores
	unsigned long in;	// Number of notifications from last snapshoot
	unsigned long ctn;	// Number of active threads (current)
	unsigned long ptn;	// Number of active threads (peak)
	double wpr;		// Progress ratio of a workflow
	// Number of workflow tasks
	// Progress ratio of a massive task
	// Number of light tasks of a massive task
	unsigned long miw;	// Mean number of incoming workflows in average period

	oph_job_list *job_info;
	oph_job_info *temp;
	oph_workflow *wf;
	struct timeval tv, tv2;
	int i, j;
	oph_status_object *users, *workflows, *massives, *tmp;
	unsigned long prev, _value[OPH_SERVER_MAX_WF_LOG_PARAM];
	long tau = 0, eps = 0, _eps;
	char name[OPH_MAX_STRING_SIZE], saved, *_tag[OPH_SERVER_MAX_WF_LOG_PARAM];

	unsigned long last_iw = 0, last_it = 0, last_st = 0, last_dw = 0, last_dt = 0, last_in = 0;	// Initialization
	unsigned long load_average[OPH_STATUS_LOG_AVG_PERIOD], current_load = 0;
	reset_load_average(load_average);

	while (oph_status_log_file_name) {

		if (!(statuslogfile = fopen(oph_status_log_file_name, "w"))) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Wrong status log file name '%s'\n", oph_status_log_file_name);
			break;
		}

		if (tau)
			prev = tv.tv_sec + (tv.tv_usec > 500000);
		gettimeofday(&tv, NULL);
		if (tau) {
			_eps = tv.tv_usec + (tv.tv_sec - OPH_STATUS_LOG_PERIOD - prev) * 1000000;
			eps = eps ? (long) (OPH_STATUS_LOG_ALPHA * eps + (1.0 - OPH_STATUS_LOG_ALPHA) * _eps) : _eps;
		}

		aw = pw = ww = rw = at = pt = wt = rt = mt = st = lt = plt = rlt = ct = ft = un = cn = 0;	// Initialization
		wpr = 0.0;
		users = workflows = massives = NULL;
		for (i = 0; i < OPH_SERVER_MAX_WF_LOG_PARAM; i++)
			_tag[i] = NULL;

		if (service_info) {

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
			pthread_mutex_lock(&service_flag);
#endif

			// Save current stats
			iw = service_info->incoming_workflows - last_iw;
			it = service_info->incoming_tasks - last_it;
			st = service_info->submitted_tasks - last_st;
			dw = service_info->closed_workflows - last_dw;
			dt = service_info->closed_tasks - last_dt;
			in = service_info->incoming_notifications - last_in;

			ctn = service_info->current_thread_number;
			ptn = service_info->peak_thread_number;

			// Update internals for next snapshot
			last_iw = service_info->incoming_workflows;
			last_it = service_info->incoming_tasks;
			last_st = service_info->submitted_tasks;
			last_dw = service_info->closed_workflows;
			last_dt = service_info->closed_tasks;
			last_in = service_info->incoming_notifications;

			if (service_info->peak_thread_number_timestamp + OPH_STATUS_LOG_HYSTERESIS_PERIOD < tv.tv_sec)
				service_info->peak_thread_number = service_info->current_thread_number;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
			pthread_mutex_unlock(&service_flag);
#endif
		}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&global_flag);
#endif

		load_average[current_load++] = iw;
		current_load %= OPH_STATUS_LOG_AVG_PERIOD;
		miw = eval_load_average(load_average);

		job_info = state->job_info;
		saved = job_info->head ? 1 : 0;
		for (temp = saved ? job_info->head : job_info->saved; temp;) {	// Loop on workflows
			if (!(wf = temp->wf))
				continue;
			aw++;
			_tag[0] = strdup(wf->username ? wf->username : OPH_UNKNOWN);
			_tag[1] = strdup(oph_odb_convert_status_to_str(wf->status));
			_value[1] = wf->tasks_num - wf->residual_tasks_num;	// Completed/failed tasks
			_value[2] = wf->tasks_num;	// Total number of tasks
			_value[3] = oph_status_code(wf->status);
			if (oph_get_progress_ratio_of(wf, &wpr, NULL))
				_value[0] = (unsigned long) (_value[1] * 100.0 / _value[2]);	// Workflow progress ratio
			else
				_value[0] = (unsigned long) (wpr * 100.0);
			snprintf(name, OPH_MAX_STRING_SIZE, "%s #%d", wf->name, wf->workflowid);
			oph_status_add(&workflows, name, NULL, _tag, 2, _value, 4);
			oph_status_add(&users, wf->username ? wf->username : OPH_UNKNOWN, &un, NULL, 0, NULL, 0);
			if (wf->status == (int) OPH_ODB_STATUS_PENDING)
				pw++;
			else if (wf->status == (int) OPH_ODB_STATUS_WAIT)
				ww++;
			else if ((wf->status > (int) OPH_ODB_STATUS_WAIT) && (wf->status < (int) OPH_ODB_STATUS_COMPLETED))
				rw++;
			if ((wf->status > (int) OPH_ODB_STATUS_PENDING) && (wf->status < (int) OPH_ODB_STATUS_COMPLETED)) {	// Loop on tasks
				at += wf->tasks_num;
				if (wf->tasks[wf->tasks_num].name)	// Final task
					at++;
				for (i = 0; i <= wf->tasks_num; ++i) {
					if (!wf->tasks[i].name)
						continue;
					if (wf->tasks[i].light_tasks_num) {
						mt++;
						lt += wf->tasks[i].light_tasks_num;
						for (j = 0; j < wf->tasks[i].light_tasks_num; ++j) {
							if (wf->tasks[i].light_tasks[j].status == (int) OPH_ODB_STATUS_PENDING)
								plt++;
							else if (wf->tasks[i].light_tasks[j].status < (int) OPH_ODB_STATUS_COMPLETED)
								rlt++;
						}
						_value[1] = wf->tasks[i].light_tasks_num - wf->tasks[i].residual_light_tasks_num;	// Completed/failed light tasks
						_value[2] = wf->tasks[i].light_tasks_num;	// Total number of light tasks
						_value[0] = (unsigned long) (_value[1] * 100.0 / wf->tasks[i].light_tasks_num);	// Task progress ratio
						snprintf(name, OPH_MAX_STRING_SIZE, "%s.%s #%d?%d", wf->name, wf->tasks[i].name, wf->workflowid, wf->tasks[i].markerid);
						oph_status_add(&massives, name, NULL, NULL, 0, _value, 3);
					}
					if (wf->tasks[i].status == (int) OPH_ODB_STATUS_PENDING)
						pt++;
					else if (wf->tasks[i].status == (int) OPH_ODB_STATUS_WAIT)
						wt++;
					else if ((wf->tasks[i].status > (int) OPH_ODB_STATUS_WAIT) && (wf->tasks[i].status < (int) OPH_ODB_STATUS_COMPLETED)) {
						rt++;
						if (wf->tasks[i].light_tasks_num)
							for (j = 0; j < wf->tasks[i].light_tasks_num; ++j) {
								if ((wf->tasks[i].light_tasks[j].status > (int) OPH_ODB_STATUS_WAIT)
								    && (wf->tasks[i].light_tasks[j].status < (int) OPH_ODB_STATUS_COMPLETED))
									cn += wf->tasks[i].light_tasks[j].ncores;
						} else
							cn += wf->tasks[i].ncores;
					} else if (wf->tasks[i].status == (int) OPH_ODB_STATUS_COMPLETED)
						ct++;
					else if ((wf->tasks[i].status > (int) OPH_ODB_STATUS_COMPLETED) && (wf->tasks[i].status < (int) OPH_ODB_STATUS_UNSELECTED))
						ft++;
				}
			}

			temp = temp->next;
			if (!temp && saved) {
				temp = job_info->saved;
				saved = 0;
			}
		}

		oph_delete_saved_jobs_from_job_list(job_info, OPH_STATUS_LOG_HYSTERESIS_PERIOD);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&global_flag);
#endif

		if (statuslogfile) {
			fprintf(statuslogfile, "workflow,status=active value=%ld %d000000000\n", aw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=pending value=%ld %d000000000\n", pw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=waiting value=%ld %d000000000\n", ww, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=running value=%ld %d000000000\n", rw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=incoming value=%ld %d000000000\n", iw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=closed value=%ld %d000000000\n", dw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=load value=%ld %d000000000\n", miw, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=active value=%ld %d000000000\n", at, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=pending value=%ld %d000000000\n", pt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=waiting value=%ld %d000000000\n", wt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=running value=%ld %d000000000\n", rt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=massive value=%ld %d000000000\n", mt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=incoming value=%ld %d000000000\n", it, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=submitted value=%ld %d000000000\n", st, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=closed value=%ld %d000000000\n", dt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=completed value=%ld %d000000000\n", ct, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=failed value=%ld %d000000000\n", ft, (int) tv.tv_sec);
			fprintf(statuslogfile, "light\\ task,status=active value=%ld %d000000000\n", lt, (int) tv.tv_sec);
			fprintf(statuslogfile, "light\\ task,status=pending value=%ld %d000000000\n", plt, (int) tv.tv_sec);
			fprintf(statuslogfile, "light\\ task,status=running value=%ld %d000000000\n", rlt, (int) tv.tv_sec);
			fprintf(statuslogfile, "user,status=active value=%ld %d000000000\n", un, (int) tv.tv_sec);
			fprintf(statuslogfile, "core,status=active value=%ld %d000000000\n", cn, (int) tv.tv_sec);
			for (tmp = workflows; tmp; tmp = tmp->next)
				fprintf(statuslogfile, "workflow\\ status,name=%s,user=%s,status=%s progress\\ ratio=%ld,task=%ld,total\\ task=%ld,status\\ value=%ld %d000000000\n", tmp->key,
					tmp->tag[0], tmp->tag[1], tmp->value[0], tmp->value[1], tmp->value[2], tmp->value[3], (int) tv.tv_sec);
			for (tmp = massives; tmp; tmp = tmp->next)
				fprintf(statuslogfile, "massive\\ status,name=%s progress\\ ratio=%ld,task=%ld,total\\ task=%ld %d000000000\n", tmp->key, tmp->value[0], tmp->value[1], tmp->value[2],
					(int) tv.tv_sec);
			fprintf(statuslogfile, "notification,status=received value=%ld %d000000000\n", in, (int) tv.tv_sec);
			fprintf(statuslogfile, "thread,status=active value=%ld %d000000000\n", ctn, (int) tv.tv_sec);
			fprintf(statuslogfile, "thread,status=peak value=%ld %d000000000\n", ptn, (int) tv.tv_sec);
			fclose(statuslogfile);
			statuslogfile = NULL;
		}

		oph_status_destroy(&users);
		oph_status_destroy(&workflows);
		oph_status_destroy(&massives);

		gettimeofday(&tv2, NULL);
		tau = (OPH_STATUS_LOG_PERIOD - (tv2.tv_sec - tv.tv_sec)) * 1000000 - tv2.tv_usec + tv.tv_usec - eps;
		while (tau < 0)
			tau += OPH_STATUS_LOG_PERIOD;
		usleep(tau);
	}

	soap_destroy(soap);	/* for C++ */
	soap_end(soap);
	soap_free(soap);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif

	return (void *) NULL;
}


/******************************************************************************\
 *
 *	OpenSSL
 *
\******************************************************************************/

#ifdef WITH_OPENSSL

struct CRYPTO_dynlock_value {
	MUTEX_TYPE mutex;
};

static MUTEX_TYPE *mutex_buf;

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{
	if (!file || !line)
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "");
	struct CRYPTO_dynlock_value *value;
	value = (struct CRYPTO_dynlock_value *) malloc(sizeof(struct CRYPTO_dynlock_value));
	if (value)
		MUTEX_SETUP(value->mutex);
	return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if (!file || !line)
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "");
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(l->mutex);
	else
		MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if (!file || !line)
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "");
	MUTEX_CLEANUP(l->mutex);
	free(l);
}

void locking_function(int mode, int n, const char *file, int line)
{
	if (!file || !line)
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "");
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

unsigned long id_function()
{
	return (unsigned long) THREAD_ID;
}

int CRYPTO_thread_setup()
{
	int i;
	mutex_buf = (MUTEX_TYPE *) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return SOAP_EOM;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
	return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{
	int i;
	if (!mutex_buf)
		return;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
}

#else

/* OpenSSL not used, e.g. GNUTLS is used */

int CRYPTO_thread_setup()
{
	return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{
}

#endif

/******************************************************************************\
 *
 *	SIGNAL HANDLING
 *
\******************************************************************************/

int oph_handle_signals(void)
{
	int rc;
	struct sigaction act;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "CALLED oph_handle_signals\n");

	/* initialize the struct sigaction act */
	memset(&act, 0, sizeof(act));
	rc = sigfillset(&act.sa_mask);
	if (rc != 0) {
		return -1;
	}
#ifdef  SA_RESTART
	act.sa_flags |= SA_RESTART;
#endif

	act.sa_handler = SIG_IGN;

	rc = sigaction(SIGHUP, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGQUIT, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGPIPE, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGTSTP, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGTTIN, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGTTOU, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	act.sa_handler = oph_signal_handler;

	rc = sigaction(SIGINT, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGTERM, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGBUS, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGFPE, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGILL, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGSEGV, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGSYS, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGXCPU, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	rc = sigaction(SIGXFSZ, &act, NULL);
	if (rc != 0) {
		return -1;
	}
#ifdef  SA_NOCLDSTOP
	act.sa_flags |= SA_NOCLDSTOP;
#endif

	act.sa_handler = oph_child_signal_handler;

	rc = sigaction(SIGCHLD, &act, NULL);
	if (rc != 0) {
		return -1;
	}

	return 0;
}

void oph_signal_handler(int sig)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "CALLED oph_signal_handler; catched signal nr %d (%s)\n", sig, sys_siglist[sig] ? sys_siglist[sig] : "");
	cleanup();
	exit(1);
}

void oph_child_signal_handler(int sig)
{
	UNUSED(sig);
}
