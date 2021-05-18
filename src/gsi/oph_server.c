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

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "config.h"
#include "gsi.h"

#include "oph_plugin.h"
#include "oph_utils.h"
#include "hashtbl.h"
#include "oph_rmanager.h"
#include "oph_ophidiadb.h"
#include "oph_auth.h"
#include "oph_task_parser_library.h"
#include "oph_service_info.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <threads.h>
#include <pthread.h>
#endif

#define OPH_STATUS_LOG_PERIOD 1

#define OPH_VOMS_AUTH_READ "pdas_read"
#define OPH_VOMS_AUTH_WRITE "pdas_write"

struct soap *psoap;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_t token_tid = 0;
pthread_mutex_t global_flag;
pthread_mutex_t libssh2_flag;
pthread_mutex_t curl_flag;
pthread_mutex_t service_flag;
pthread_cond_t termination_flag;
pthread_cond_t waiting_flag;
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
char *oph_log_file_name = 0;
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
		pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log file '%s'\n", value);
		logfile = fopen(value, "a");
		if (logfile)
			set_log_file(logfile);
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

void cleanup()
{
	pmesg(LOG_INFO, __FILE__, __LINE__, "Server shutdown\n");
	oph_server_is_running = 0;
	sleep(OPH_STATUS_LOG_PERIOD);

	if (wf_logfile) {
		fclose(wf_logfile);
		wf_logfile = NULL;
	}
	if (task_logfile) {
		fclose(task_logfile);
		task_logfile = NULL;
	}

	mysql_library_end();
	soap_destroy(psoap);
	soap_end(psoap);
	soap_done(psoap);	/* MUST call before CRYPTO_thread_cleanup */
	globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
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

typedef void Sigfunc(int);

Sigfunc *set_signal_handler(int signo, Sigfunc * func);
int gsi_authorization_callback(struct soap *soap, char *distinguished_name);

void oph_signal_handler(int signal)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Received signal %d\n", signal);
	cleanup();
	pid_t pid = getpid();
	kill(pid, SIGTERM);
	while (wait(NULL) > 0);	// now wait
	if (errno != ECHILD)
		pmesg(LOG_ERROR, __FILE__, __LINE__, "An error occurred on shutdown\n");
	exit(0);
}

void oph_child_signal_handler(int sig)
{
	UNUSED(sig);
}

void *process_request(void *arg)
{
	int rc;
	struct gsi_plugin_data *data = NULL;
	struct soap *soap = NULL;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif

	soap = (struct soap *) arg;
	if (!soap)
		return (void *) NULL;

	data = (struct gsi_plugin_data *) soap_lookup_plugin(soap, GSI_PLUGIN_ID);
	if (!data)
		return (void *) NULL;

	/* Timeout after 2 minutes stall on send/recv */
	gsi_set_recv_timeout(soap, 120);
	gsi_set_send_timeout(soap, 120);

	rc = gsi_accept_security_context(soap);
	if (!rc) {		/* success */
#ifdef GLITE_VOMS
		if (data->fqans) {
			int i;
			for (i = 0; data->fqans[i]; i++)
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "FQAN[%d]: %s\n", i, data->fqans[i]);
		}
#endif
		rc = data->gsi_authorization_callback(soap, data->client_identity);
		if (!rc) {	/* success */
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "User '%s' is authorized\n", data->client_identity);
			soap_serve(soap);
		} else {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "User '%s' is not authorized\n", data->client_identity);
			soap_receiver_fault(soap, "Authorization error", NULL);
			soap_send_fault(soap);
		}
	} else {
		soap_receiver_fault(soap, "Failed to establish security context", NULL);
		soap_send_fault(soap);
	}

	soap_destroy(soap);
	soap_end(soap);
	soap_free(soap);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
	mysql_thread_end();
#endif

	return (void *) NULL;
}

int oph_utils_tokenize_string_r(const char *s, const char *delimiters, char ***tokenp)
{
	char *t = NULL;
	const char *snew;
	int numtokens;
	int i;
	char *saveptr = NULL;
	char *ptr;

	if (!tokenp)
		return -1;
	*tokenp = NULL;

	/* snew is real start of string after skipping leading delimiters */
	snew = s + strspn(s, delimiters);
	/* create space for a copy of snew in t */
	if (!(t = (char *) calloc(strlen(snew) + 1, sizeof(char))))
		numtokens = -1;
	else {			/* count the number of tokens in snew */

		strcpy(t, snew);
		if (!(ptr = strtok_r(t, delimiters, &saveptr)))
			numtokens = 0;
		else {
			for (numtokens = 1; (ptr = strtok_r(NULL, delimiters, &saveptr)) != NULL; numtokens++);
			if (!(*tokenp = (char **) calloc(numtokens + 1, sizeof(char *))))
				numtokens = -1;
			else {	/* insert pointers to tokens into the array */

				if (numtokens > 0) {
					strcpy(t, snew);
					**tokenp = strdup(strtok_r(t, delimiters, &saveptr));
					for (i = 1; i < numtokens + 1; i++) {
						ptr = strtok_r(NULL, delimiters, &saveptr);
						*((*tokenp) + i) = ptr ? strdup(ptr) : NULL;
					}
				} else
					*tokenp = NULL;
			}
		}
	}
	if (t)
		free(t);
	return numtokens;
}

#ifdef GLITE_VOMS
int load_voms_system_privileges(struct oph_plugin_data *data, char **fqans)
{
	if (!data || !data->serverid) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
		return -1;
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Parsing FQANS...\n");
	int i = 0;
	int j = 0;
	int numtoken = 0;
	char **token = NULL;
	char *hostname, *vo, *server_name, *role, *current_vo = NULL;

	if (((numtoken = oph_utils_tokenize_string_r(data->serverid, "/", &token)) < 2) || !token || !token[1]) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error while extracting hostname from '%s'\n", data->serverid);
		if (token) {
			for (j = 0; token[j]; j++)
				if (token[j])
					free(token[j]);
			free(token);
		}
		return -2;
	}
	hostname = strdup(token[1]);
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "HOSTNAME: %s\n", hostname);
	if (token) {
		for (j = 0; token[j]; j++)
			if (token[j])
				free(token[j]);
		free(token);
	}

	if (fqans) {
		FILE *fd = NULL;
		char buf[OPH_MAX_STRING_SIZE];
		for (i = 0; fqans[i] && (data->authorization < OPH_AUTH_WRITE); i++) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Parsing FQAN[%d]: %s\n", i, fqans[i]);

			vo = server_name = role = NULL;

			numtoken = oph_utils_tokenize_string_r(fqans[i], "/", &token);
			if (!token || (numtoken < 4) || (numtoken > 6)) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "FQAN[%d] is not valid\n", i);
				if (token) {
					for (j = 0; token[j]; j++)
						if (token[j])
							free(token[j]);
					free(token);
				}
				continue;
			}
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "FQAN[%d] is valid and contains the following %d tokens\n", i, numtoken);
			for (j = 0; token[j]; j++)
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Token %d: %s\n", j, token[j]);

			if (!token[1] || !token[2] || strcasecmp(token[1], "oph") || strcasecmp(token[2], "pdas")) {
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Voms attributes '%s' or '%s' not recognized\n", token[1], token[2]);
				if (token) {
					for (j = 0; token[j]; j++)
						if (token[j])
							free(token[j]);
					free(token);
				}
				continue;
			}

			for (j = 3; token[j]; j++) {
				if (!strncasecmp(token[j], "Role=", 5)) {
					if (!(role = strdup(token[j] + 5))) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory allocation error\n");
						if (token) {
							for (j = 0; token[j]; j++)
								if (token[j])
									free(token[j]);
							free(token);
						}
						if (vo)
							free(vo);
						if (server_name)
							free(server_name);
						if (role)
							free(role);
						if (fd)
							fclose(fd);
						if (hostname)
							free(hostname);
						return -3;
					}
				} else if (!strncasecmp(token[j], "Capability=", 11))
					continue;
				else if (j == 3)
					server_name = strdup(token[3]);
				else {
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Wrong VOMS attribute format\n");
					if (token) {
						for (j = 0; token[j]; j++)
							if (token[j])
								free(token[j]);
						free(token);
					}
					if (vo)
						free(vo);
					if (server_name)
						free(server_name);
					if (role)
						free(role);
					continue;
				}
			}
			vo = strdup(token[0]);

			if (token) {
				for (j = 0; token[j]; j++)
					if (token[j])
						free(token[j]);
				free(token);
			}

			if (!fd) {
				char *auth_vo = globus_libc_getenv("AUTHORIZED_VO_FILE");
				char *auth_vo_file = strdup(auth_vo ? auth_vo : AUTHORIZED_VO_FILE);
				fd = fopen(auth_vo_file, "r");
				if (!fd)
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Can not read file '%s'\n", auth_vo_file);
				if (auth_vo)
					free(auth_vo);
				if (auth_vo_file)
					free(auth_vo_file);
			}
			if (fd && (!current_vo || strcasecmp(current_vo, vo))) {
				rewind(fd);
				while (fgets(buf, OPH_MAX_STRING_SIZE, fd)) {
					if (strlen(buf))
						buf[strlen(buf) - 1] = '\0';
					if (strlen(buf) && !strcasecmp(vo, buf)) {
						if (current_vo)
							free(current_vo);
						current_vo = strdup(vo);
						break;
					}
				}
			}
			if (!current_vo) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "No VO '%s' found in authorized VO list\n", vo);
				if (vo)
					free(vo);
				if (server_name)
					free(server_name);
				if (role)
					free(role);
				continue;
			}
			if (role && !strcasecmp(role, OPH_NULL_VALUE)) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "No role associated with VO '%s'\n", vo);
				if (vo)
					free(vo);
				if (server_name)
					free(server_name);
				free(role);
				continue;
			}
			if (server_name && strcasecmp(hostname, server_name)) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Server name mismatch: token '%s' in not equal to hostname '%s'\n", server_name, hostname);
				if (vo)
					free(vo);
				free(server_name);
				if (role)
					free(role);
				continue;
			}

			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "VO: %s, SERVER: %s, ROLE: %s\n", vo ? vo : "", server_name ? server_name : "", role ? role : "");

			// Update the privileges
			if (!strcasecmp(role, OPH_VOMS_AUTH_READ) && data->authorization < OPH_AUTH_READ)
				data->authorization = OPH_AUTH_READ;
			else if (!strcasecmp(role, OPH_VOMS_AUTH_WRITE) && data->authorization < OPH_AUTH_WRITE)
				data->authorization = OPH_AUTH_WRITE;

			if (vo)
				free(vo);
			if (server_name)
				free(server_name);
			if (role)
				free(role);
		}
		if (fd)
			fclose(fd);
		if (current_vo)
			free(current_vo);
	} else
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "No FQANS found!\n");
	if (hostname)
		free(hostname);

	return 0;
}
#endif

int main(int argc, char **argv)
{
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
	unsigned short int port;
	int ch, rc, m, s, msglevel = LOG_INFO;

	static char *USAGE = "\nUSAGE:\noph_server [-d] [-l <log_file>] [-p <port>] [-v] [-w]\n";
	port = PLUGIN_DEFAULT_PORT;

	fprintf(stdout, "%s", OPH_VERSION);
	fprintf(stdout, "%s", OPH_DISCLAIMER);

	set_debug_level(msglevel + 10);

	while ((ch = getopt(argc, argv, "adhl:mp:vwxz")) != -1) {
		switch (ch) {
			case 'a':
				oph_auth_enabled = 0;
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
				port = (unsigned short int) atoi(optarg);
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
	// Pre check of ENVIRONMENTAL VARIABLES
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

	if (wf_logfile && !ftell(wf_logfile))
		fprintf(wf_logfile, "timestamp\tidworkflow\tname\tusername\tip_address\tclient_address\t#tasks\t#success_tasks\tduration\n");
	if (task_logfile && !ftell(task_logfile))
		fprintf(task_logfile, "timestamp\tidtask\tidworkflow\toperator\t#cores\tsuccess_flag\tduration\n");

	if (mysql_library_init(0, 0, 0)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot setup MySQL\n");
		exit(1);
	}
	oph_tp_start_xml_parser();
	soap_init(&soap);

	if (soap_register_plugin(&soap, oph_plugin)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot register %s plugin\n", OPH_PLUGIN_ID);
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(-1);
	}
	// Register serverid
	struct oph_plugin_data *state = (struct oph_plugin_data *) soap_lookup_plugin(&soap, OPH_PLUGIN_ID);
	if (!state) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error on lookup plugin struct\n");
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(-1);
	}
	state->serverid = strdup(oph_web_server);

	globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

	/* we register the GSI plugin */

	if (soap_register_plugin(&soap, globus_gsi)) {
		soap_print_fault(&soap, stderr);
		cleanup();
		exit(EXIT_FAILURE);
	}

	/* we begin acquiring our credential */
	rc = gsi_acquire_credential(&soap);
	if (rc < 0) {
		cleanup();
		exit(EXIT_FAILURE);
	}

	/* setup of authorization callback */
	gsi_authorization_callback_register(&soap, gsi_authorization_callback);

	/* listen for incoming connections */
	soap.bind_flags |= SO_REUSEADDR;
	m = gsi_listen(&soap, NULL, port, 512);
	if (m == -1) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Failing in gsi_listen, now exiting\n");
		cleanup();
		exit(EXIT_FAILURE);
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Bind successful: socket = %d\n", m);

	set_signal_handler(SIGHUP, SIG_IGN);
	set_signal_handler(SIGQUIT, SIG_IGN);
	set_signal_handler(SIGPIPE, SIG_IGN);
	set_signal_handler(SIGINT, oph_signal_handler);
	set_signal_handler(SIGCHLD, oph_child_signal_handler);

	for (;;) {
		/* accepting incoming connections */
		s = soap_accept(&soap);
		if (s == -1) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Failing in soap_accept, now exiting\n");
			break;
		}

		/* spawning a new thread to serve the client's request */
		tsoap = soap_copy(&soap);
		if (!tsoap)
			break;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_create(&tid, NULL, &process_request, (void *) tsoap);
#else
		process_request((void *) tsoap);
#endif
	}

	cleanup();
	exit(EXIT_FAILURE);
}

int gsi_authorization_callback(struct soap *soap, char *distinguished_name)
{
	struct oph_plugin_data *data = (struct oph_plugin_data *) soap_lookup_plugin(soap, OPH_PLUGIN_ID);
	if (!data) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on lookup plugin struct\n");
		soap_print_fault(soap, stderr);
		return 2;
	}
	data->authorization = OPH_AUTH_UNKNOWN;

	char buf[OPH_MAX_STRING_SIZE];
	FILE *fd;

	// Black list
	if (!data->authorization) {
		char *black_list = globus_libc_getenv("BLACK_LIST_FILE");
		char *black_list_file = strdup(black_list ? black_list : BLACK_LIST_FILE);
		fd = fopen(black_list_file, "r");
		if (fd) {
			while (fgets(buf, OPH_MAX_STRING_SIZE, fd)) {
				if (strlen(buf))
					buf[strlen(buf) - 1] = '\0';
				if (strlen(buf)) {
					if (!strcmp(distinguished_name, buf)) {
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "User '%s' is black-listed\n", distinguished_name);
						data->authorization = OPH_AUTH_DENIED;
					}
				}
			}
			fclose(fd);
		} else
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Can not read file '%s'\n", black_list_file);
		if (black_list)
			free(black_list);
		if (black_list_file)
			free(black_list_file);
	}
	// Local authentication
	if (!data->authorization) {
		char *auth = globus_libc_getenv("AUTHORIZATION_FILE");
		char *auth_file = strdup(auth ? auth : AUTHORIZATION_FILE);
		char *role;
		fd = fopen(auth_file, "r");
		if (fd) {
			while (fgets(buf, OPH_MAX_STRING_SIZE, fd)) {
				if (strlen(buf))
					buf[strlen(buf) - 1] = '\0';
				if (strlen(buf)) {
					role = strrchr(buf, OPH_SEPARATOR_BASIC[0]);
					if (!role) {
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Format of line '%s' in file '%s' is not correct\n", buf, auth_file);
						continue;
					}
					if (!strncmp(distinguished_name, buf, role - buf)) {
						role++;
						if (!strcasecmp(role, OPH_ROLE_READ_STR)) {
							data->authorization = OPH_AUTH_READ;
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Local authorization is '%s'\n", OPH_ROLE_READ_STR);
						} else if (!strcasecmp(role, OPH_ROLE_READ_FORCE_STR)) {
							data->authorization = OPH_AUTH_READ_FORCE;
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Local authorization is '%s'\n", OPH_ROLE_READ_FORCE_STR);
						} else if (!strcasecmp(role, OPH_ROLE_WRITE_STR)) {
							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Local authorization is '%s'\n", OPH_ROLE_WRITE_STR);
							data->authorization = OPH_AUTH_WRITE;
						} else {
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Role in line '%s' in file '%s' is not correct\n", buf, auth_file);
							continue;
						}
						break;
					}
				}
			}
			fclose(fd);
		} else
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Can not read file '%s'\n", auth_file);
		if (auth)
			free(auth);
		if (auth_file)
			free(auth_file);

		if (!data->authorization)
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Local authorization is denied\n");
	}
#ifdef GLITE_VOMS
	// Global authentication
	if (!data->authorization || (data->authorization == OPH_AUTH_READ)) {
		struct gsi_plugin_data *gsi_data = (struct gsi_plugin_data *) soap_lookup_plugin(soap, GSI_PLUGIN_ID);
		if (!gsi_data) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on lookup plugin struct\n");
			soap_print_fault(soap, stderr);
			return 2;
		}
		char **fqans = gsi_data->fqans;
		if (!load_voms_system_privileges(data, fqans)) {
			switch (data->authorization) {
				case OPH_AUTH_READ:
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Global authorization is '%s'\n", OPH_ROLE_READ_STR);
					break;
				case OPH_AUTH_WRITE:
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Global authorization is '%s'\n", OPH_ROLE_WRITE_STR);
					break;
				default:
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Global authorization is denied\n");
			}
		}
	}
#endif

	switch (data->authorization) {
		case OPH_AUTH_READ:
		case OPH_AUTH_READ_FORCE:
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "User '%s' is allowed to access the server in '%s' mode\n", distinguished_name, OPH_ROLE_READ_STR);
			break;
		case OPH_AUTH_WRITE:
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "User '%s' is allowed to access the server in '%s' mode\n", distinguished_name, OPH_ROLE_WRITE_STR);
			break;
		default:
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "User '%s' is not allowed to access the server\n", distinguished_name);
			return 1;
	}

	return 0;
}

/******************************************************************************\
 *
 *	SIGNAL HANDLING
 *
\******************************************************************************/

Sigfunc *set_signal_handler(int signo, Sigfunc * func)
{
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef  SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;	// SunOS 4.x 
#endif
	} else {
#ifdef  SA_RESTART
		act.sa_flags |= SA_RESTART;	// SVR4, 44BSD
#endif
	}
	if (sigaction(signo, &act, &oact) < 0)
		return (SIG_ERR);
	return (oact.sa_handler);
}
