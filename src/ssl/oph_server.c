/*
    Ophidia Server
    Copyright (C) 2012-2016 CMCC Foundation

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

#include <unistd.h>
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <threads.h>
#include <pthread.h>
#endif
#include <signal.h>
#include <mysql.h>

#define OPH_STATUS_LOG_PERIOD 1
#define OPH_STATUS_LOG_ALPHA 0.5

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
 *	Global variable;
 *
\******************************************************************************/

struct soap *psoap;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_mutex_t global_flag;
pthread_mutex_t libssh2_flag;
pthread_cond_t termination_flag;
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
char *oph_log_file_name = 0;
FILE *statuslogfile = 0;
char *oph_status_log_file_name = 0;
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
char oph_server_is_running = 1;
char *oph_base_src_path = 0;
unsigned int oph_base_backoff = 0;
#ifdef OPH_OPENID_ENDPOINT
char *oph_openid_endpoint = 0;
char *oph_openid_client_id = 0;
char *oph_openid_client_secret = 0;
#endif

void set_global_values(const char *configuration_file)
{
	if (!freopen(OPH_SERVER_DEV_NULL, "r", stdin))
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in redirect stdin\n");

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
#ifdef OPH_OPENID_ENDPOINT
	if (!(oph_openid_endpoint = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_ENDPOINT))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_OPENID_ENDPOINT, OPH_OPENID_ENDPOINT);
		oph_openid_endpoint = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_ENDPOINT);
	}
	if (!(oph_openid_client_id = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_CLIENT_ID))) {
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_OPENID_CLIENT_ID, OPH_OPENID_CLIENT_ID);
		oph_openid_client_id = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_CLIENT_ID);
	}
	oph_openid_client_secret = hashtbl_get(oph_server_params, OPH_SERVER_CONF_OPENID_CLIENT_SECRET);
#endif

	oph_json_location = oph_web_server_location;	// Position of JSON Response will be the same of web server
}

/******************************************************************************\
 *
 *	Main
 *
\******************************************************************************/

void cleanup()
{
	pmesg(LOG_INFO, __FILE__, __LINE__, "Server shutdown\n");
	oph_server_is_running = 0;
	if (statuslogfile) {
		fclose(statuslogfile);
		statuslogfile = 0;
	}
	sleep(1);
	mysql_library_end();
	soap_destroy(psoap);
	soap_end(psoap);
	soap_done(psoap);
	CRYPTO_thread_cleanup();
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
	pthread_cond_destroy(&termination_flag);
#endif
	oph_tp_end_xml_parser();
}

int main(int argc, char *argv[])
{
	SOAP_SOCKET m;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_t tid;
	pthread_mutex_init(&global_flag, NULL);
	pthread_mutex_init(&libssh2_flag, NULL);
	pthread_cond_init(&termination_flag, NULL);
#endif
	struct soap soap, *tsoap = NULL;
	psoap = &soap;

	int ch, msglevel = LOG_INFO;
	static char *USAGE = "\nUSAGE:\noph_server [-d] [-l <log_file>] [-p <port>] [-v] [-w]\n";

	fprintf(stdout, "%s", OPH_VERSION);
	fprintf(stdout, "%s", OPH_DISCLAIMER);

	set_debug_level(msglevel + 10);

	while ((ch = getopt(argc, argv, "dhl:p:s:vwxz")) != -1) {
		switch (ch) {
			case 'd':
				msglevel = LOG_DEBUG;
				break;
			case 'h':
				fprintf(stdout, "%s", USAGE);
				return 0;
			case 'l':
				oph_log_file_name = optarg;
				break;
			case 'p':
				oph_server_port = optarg;
				break;
			case 's':
				oph_status_log_file_name = optarg;
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
		fprintf(stderr, "OPH_SERVER_LOCATION has to be set\n");
		return 1;
	}
#endif
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Server location '%s'\n", oph_server_location);

	char configuration_file[OPH_MAX_STRING_SIZE];
	snprintf(configuration_file, OPH_MAX_STRING_SIZE, OPH_CONFIGURATION_FILE, oph_server_location);
	set_global_values(configuration_file);

	if (oph_log_file_name) {
		if (logfile)
			fclose(logfile);
		if (!(logfile = fopen(oph_log_file_name, "a"))) {
			fprintf(stderr, "Wrong log file name '%s'\n", oph_log_file_name);
			return 1;
		}
		pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log file '%s'\n", oph_log_file_name);
		if (logfile)
			set_log_file(logfile);
	} else
		oph_log_file_name = hashtbl_get(oph_server_params, OPH_SERVER_CONF_LOGFILE);

	if (oph_status_log_file_name) {
		if (statuslogfile)
			fclose(statuslogfile);
		if (!(statuslogfile = fopen(oph_status_log_file_name, "w"))) {
			fprintf(stderr, "Wrong status log file name '%s'\n", oph_status_log_file_name);
			return 1;
		}
	}

	int int_port = strtol(oph_server_port, NULL, 10);

	if (oph_handle_signals()) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "A problem occurred while setting up signal dispositions\n");
		exit(1);
	}

	if (mysql_library_init(0, 0, 0)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot setup MySQL\n");
		exit(1);
	}

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
	if (statuslogfile) {
		tsoap = soap_copy(&soap);
		if (tsoap)
			pthread_create(&tid, NULL, (void *(*)(void *)) &status_logger, tsoap);
	}
#endif

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

	mysql_thread_end();

	return NULL;
}

#define OPH_SERVER_MAX_WF_LOG_PARAM 10

typedef struct _oph_status_object {
	char *key;
	unsigned long value[OPH_SERVER_MAX_WF_LOG_PARAM];
	struct _oph_status_object *next;
} oph_status_object;

int oph_status_add(oph_status_object ** list, const char *key, unsigned long *old_value, unsigned long *new_value, size_t number_of_new_values)
{
	if (!list || !key || (number_of_new_values > OPH_SERVER_MAX_WF_LOG_PARAM))
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

	oph_status_object *tmp, *next;
	for (tmp = *list; tmp; tmp = next) {
		next = tmp->next;
		if (tmp->key)
			free(tmp->key);
		free(tmp);
	}
	*list = NULL;

	return 0;
}

void *status_logger(struct soap *soap)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
#endif

	struct oph_plugin_data *state = NULL;
	if (!(state = (struct oph_plugin_data *) soap_lookup_plugin((struct soap *) soap, OPH_PLUGIN_ID))) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on oph lookup plugin struct\n");
		return NULL;
	}

	unsigned long aw;	// Number of active workflows
	unsigned long pw;	// Number of pending workflows
	unsigned long ww;	// Number of waiting workflows
	unsigned long rw;	// Number of running workflows
	unsigned long at;	// Number of active tasks
	unsigned long pt;	// Number of pending tasks
	unsigned long wt;	// Number of waiting tasks
	unsigned long rt;	// Number of running tasks
	unsigned long mt;	// Number of massive tasks
	unsigned long lt;	// Number of active light tasks
	unsigned long plt;	// Number of pending light tasks
	unsigned long rlt;	// Number of running light tasks
	unsigned long ct;	// Number of completed tasks
	unsigned long ft;	// Number of failed tasks
	unsigned long un;	// Number of users
	unsigned long cn;	// Number of active cores
	double wpr;		// Progress ratio of a workflow
	// Number of workflow tasks
	// Progress ratio of a massive task
	// Number of light tasks of a massive task

	oph_job_list *job_info;
	oph_job_info *temp;
	oph_workflow *wf;
	struct timeval tv, tv2;
	int i, j;
	oph_status_object *users, *workflows, *massives, *tmp;
	unsigned long prev, _value[10];
	long tau = 0, eps = 0, _eps;
	char name[OPH_MAX_STRING_SIZE];

	int nofile = fileno(statuslogfile);

	if (statuslogfile) {
		gettimeofday(&tv, NULL);
		fprintf(statuslogfile, "service,status=up value=0 %d000000000\n", (int) tv.tv_sec);
		fflush(statuslogfile);
	}

	while (statuslogfile) {

		if (tau)
			prev = tv.tv_sec + (tv.tv_usec > 500000);
		gettimeofday(&tv, NULL);
		if (tau) {
			_eps = tv.tv_usec + (tv.tv_sec - OPH_STATUS_LOG_PERIOD - prev) * 1000000;
			eps = eps ? (long) (OPH_STATUS_LOG_ALPHA * eps + (1.0 - OPH_STATUS_LOG_ALPHA) * _eps) : _eps;
		}

		aw = pw = ww = rw = at = pt = wt = rt = mt = lt = plt = rlt = ct = ft = un = cn = 0;	// Initialization
		wpr = 0.0;
		users = workflows = massives = NULL;

		pthread_mutex_lock(&global_flag);

		job_info = state->job_info;
		for (temp = job_info->head; temp; temp = temp->next) {	// Loop on workflows
			if (!(wf = temp->wf))
				continue;
			aw++;
			_value[1] = wf->tasks_num - wf->residual_tasks_num;	// Completed/failed tasks
			if (oph_get_progress_ratio_of(wf, &wpr, NULL))
				_value[0] = (unsigned long) (_value[1] * 100.0 / wf->tasks_num);	// Workflow progress ratio
			else
				_value[0] = (unsigned long) (wpr * 100.0);
			snprintf(name, OPH_MAX_STRING_SIZE, "%s #%d", wf->name, wf->workflowid);
			oph_status_add(&workflows, name, NULL, _value, 2);
			if (wf->username)
				oph_status_add(&users, wf->username, &un, NULL, 0);
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
						_value[0] = (unsigned long) (_value[1] * 100.0 / wf->tasks[i].light_tasks_num);	// Task progress ratio
						snprintf(name, OPH_MAX_STRING_SIZE, "%s.%s #%d?%d", wf->name, wf->tasks[i].name, wf->workflowid, wf->tasks[i].markerid);
						oph_status_add(&massives, name, NULL, _value, 2);
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
		}

		pthread_mutex_unlock(&global_flag);

		if (statuslogfile) {
			fprintf(statuslogfile, "workflow,status=active value=%ld %d000000000\n", aw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=pending value=%ld %d000000000\n", pw, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=waiting value=%ld %d000000000\n", ww, (int) tv.tv_sec);
			fprintf(statuslogfile, "workflow,status=running value=%ld %d000000000\n", rw, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=active value=%ld %d000000000\n", at, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=pending value=%ld %d000000000\n", pt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=waiting value=%ld %d000000000\n", wt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=running value=%ld %d000000000\n", rt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=massive value=%ld %d000000000\n", mt, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=completed value=%ld %d000000000\n", ct, (int) tv.tv_sec);
			fprintf(statuslogfile, "task,status=failed value=%ld %d000000000\n", ft, (int) tv.tv_sec);
			fprintf(statuslogfile, "light\\ task,status=active value=%ld %d000000000\n", lt, (int) tv.tv_sec);
			fprintf(statuslogfile, "light\\ task,status=pending value=%ld %d000000000\n", plt, (int) tv.tv_sec);
			fprintf(statuslogfile, "light\\ task,status=running value=%ld %d000000000\n", rlt, (int) tv.tv_sec);
			fprintf(statuslogfile, "user,status=active value=%ld %d000000000\n", un, (int) tv.tv_sec);
			fprintf(statuslogfile, "core,status=active value=%ld %d000000000\n", cn, (int) tv.tv_sec);
			for (tmp = workflows; tmp; tmp = tmp->next)
				if (tmp->key) {
					fprintf(statuslogfile, "progress\\ ratio,name=%s value=%ld %d000000000\n", tmp->key, tmp->value[0], (int) tv.tv_sec);
					fprintf(statuslogfile, "workflow\\ task,name=%s value=%ld %d000000000\n", tmp->key, tmp->value[1], (int) tv.tv_sec);
				}
			for (tmp = massives; tmp; tmp = tmp->next)
				if (tmp->key) {
					fprintf(statuslogfile, "massive\\ progress\\ ratio,name=%s value=%ld %d000000000\n", tmp->key, tmp->value[0], (int) tv.tv_sec);
					fprintf(statuslogfile, "massive\\ task,name=%s value=%ld %d000000000\n", tmp->key, tmp->value[1], (int) tv.tv_sec);
				}
			fflush(statuslogfile);
		}

		oph_status_destroy(&users);
		oph_status_destroy(&workflows);
		oph_status_destroy(&massives);

		gettimeofday(&tv2, NULL);
		tau = (OPH_STATUS_LOG_PERIOD - (tv2.tv_sec - tv.tv_sec)) * 1000000 - tv2.tv_usec + tv.tv_usec - eps;
		while (tau < 0)
			tau += OPH_STATUS_LOG_PERIOD;
		usleep(tau);

		ftruncate(nofile, 0);
	}

	if (statuslogfile) {
		gettimeofday(&tv, NULL);
		fprintf(statuslogfile, "service,status=down value=0 %d000000000\n", (int) tv.tv_sec);
		fflush(statuslogfile);
	}

	soap_destroy(soap);	/* for C++ */
	soap_end(soap);
	soap_free(soap);

	mysql_thread_end();

	return NULL;
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
