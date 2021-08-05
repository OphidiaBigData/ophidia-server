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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "hashtbl.h"
#include "oph_ophidiadb.h"
#include "oph_auth.h"
#include "oph_utils.h"
#include "oph_service_info.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ftw.h>

#ifdef INTERFACE_TYPE_IS_GSI
#include "globus_common.h"
#endif

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_mutex_t global_flag;
pthread_mutex_t curl_flag;
pthread_mutex_t service_flag;
#ifdef OPH_OPENID_SUPPORT
pthread_t token_tid_openid;
#endif
#ifdef OPH_AAA_SUPPORT
pthread_t token_tid_aaa;
#endif
#endif

#define OPH_PASSWD_SIZE		16
#define OPH_COMMAND_SUDO	"sudo -u %s %s %s %s"

char *oph_server_location = 0;
HASHTBL *oph_server_params = 0;
char *oph_server_host = 0;
char *oph_server_port = 0;
int oph_server_timeout = OPH_SERVER_TIMEOUT;
char *oph_auth_location = 0;
char *oph_txt_location = 0;
char *oph_web_server = 0;
oph_auth_user_bl *bl_head = 0;
ophidiadb *ophDB = 0;
oph_argument *args = 0;
oph_service_info *service_info = NULL;
char *oph_add_user = 0;
char *oph_update_user = 0;
unsigned int oph_default_max_sessions = OPH_DEFAULT_USER_MAX_SESSIONS;
unsigned int oph_default_max_cores = OPH_DEFAULT_USER_MAX_CORES;
unsigned int oph_default_max_hosts = OPH_DEFAULT_USER_MAX_HOSTS;
unsigned int oph_default_session_timeout = OPH_DEFAULT_SESSION_TIMEOUT;
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

void cleanup()
{
	oph_cleanup_args(&args);
#ifdef OPH_DB_SUPPORT
	mysql_library_end();
#endif
	if (oph_server_params)
		hashtbl_destroy(oph_server_params);
#ifdef OPH_SERVER_LOCATION
	if (oph_server_location)
		free(oph_server_location);
#endif
	if (ophDB)
		oph_odb_free_ophidiadb(ophDB);
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_destroy(&global_flag);
	pthread_mutex_destroy(&curl_flag);
#endif
}

int oph_mkdir(const char *name)
{
	return oph_mkdir2(name, 0755);
}

int oph_mkdir2(const char *name, mode_t mode)
{
	struct stat st;
	int res = stat(name, &st);
	if (!res)
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Directory '%s' already exist\n", name);
	else if (res == -1) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Directory creation: '%s'\n", name);
		if (mkdir(name, mode)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Directory '%s' cannot be created\n", name);
			return OPH_SERVER_IO_ERROR;
		}
	} else {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Directory '%s' cannot be created\n", name);
		return OPH_SERVER_IO_ERROR;
	}

	return OPH_SERVER_OK;
}

int _delete_files(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
	UNUSED(st);
	UNUSED(flag);
	UNUSED(ftw);
	return remove(path);
}

int set_global_values(const char *configuration_file)
{
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
				}
			}
		}
		fclose(file);
	}
	// Pre-process
	if (!oph_server_host && !(oph_server_host = hashtbl_get(oph_server_params, OPH_SERVER_CONF_HOST))) {
		if (!gethostname(tmp, OPH_MAX_STRING_SIZE))
			hashtbl_insert(oph_server_params, OPH_SERVER_CONF_HOST, tmp);
		else
			hashtbl_insert(oph_server_params, OPH_SERVER_CONF_HOST, OPH_DEFAULT_HOST);
		oph_server_host = hashtbl_get(oph_server_params, OPH_SERVER_CONF_HOST);
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
	oph_add_user = hashtbl_get(oph_server_params, OPH_SERVER_CONF_ADD_USER);
	oph_update_user = hashtbl_get(oph_server_params, OPH_SERVER_CONF_UPDATE_USER);

	return OPH_SERVER_OK;
}

int main(int argc, char *argv[])
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_init(&global_flag, NULL);
	pthread_mutex_init(&curl_flag, NULL);
#endif
	int ch, msglevel = LOG_ERROR;
	char *action = NULL, *username = NULL, *password = NULL, *name = NULL, *surname = NULL, *email = NULL, *country = NULL, *is_admin = "no", log = 0, *cdd = NULL, *os_username = NULL;
	unsigned int max_sessions = 100, timeout_session = 1, max_cores = 8, max_hosts = 1, black_listed = 0, update = 0, random_password = 0;
	char _random_password[1 + OPH_PASSWD_SIZE];
	while ((ch = getopt(argc, argv, "a:bc:d:e:f:hi:lm:n:o:p:qr:s:t:u:vw")) != -1) {
		switch (ch) {
			case 'a':
				action = optarg;
				break;
			case 'c':
				max_cores = (unsigned int) strtol(optarg, NULL, 10);
				update += 1;
				break;
			case 'd':
				cdd = optarg;
				if (!cdd || (*cdd != '/')) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad data directory '%d': it needs to start with '/'!\n");
					cleanup();
					return 1;
				}
				update += 32;
				break;
			case 'e':
				email = optarg;
				break;
			case 'f':
				country = optarg;
				break;
			case 'i':
				max_hosts = (unsigned int) strtol(optarg, NULL, 10);
				update += 16;
				break;
			case 'l':
				log = 1;
				break;
			case 'm':
				max_sessions = (unsigned int) strtol(optarg, NULL, 10);
				update += 2;
				break;
			case 'n':
				name = optarg;
				break;
			case 'o':
				os_username = optarg;
				update += 64;
				break;
			case 'p':
				password = optarg;	// For GSI it means 'role': read, write...
				break;
			case 'q':
				random_password = 1;
				break;
			case 'r':
				is_admin = optarg;
				if (strcasecmp(is_admin, "yes") && strcasecmp(is_admin, "no")) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad input parameter. Use '-r yes' or '-r no'!\n");
					cleanup();
					return 1;
				}
				update += 4;
				break;
			case 's':
				surname = optarg;
				break;
			case 't':
				timeout_session = (unsigned int) strtol(optarg, NULL, 10);
				update += 8;
				break;
			case 'u':
				username = optarg;
				break;
			case 'v':
				msglevel = LOG_DEBUG;
				break;
			case 'w':
				if (msglevel < LOG_WARNING)
					msglevel = LOG_WARNING;
				break;
			case 'b':
#ifdef INTERFACE_TYPE_IS_GSI
				black_listed = 1;
				break;
#endif
			case 'h':
			default:
				fprintf(stdout, "Usage:\noph_manage_user -a add|del|list|update [-u <username>] [other params] [-v] [-w]\n");
#ifdef INTERFACE_TYPE_IS_GSI
				fprintf(stdout, "-b to black-list the user\n");
#endif
				fprintf(stdout, "-c <maximum number of cores per task> (default %d)\n", max_cores);
				fprintf(stdout, "-d <home data directory> (default '/')\n");
				fprintf(stdout, "-e <email>\n");
				fprintf(stdout, "-f <country>\n");
				fprintf(stdout, "-i <maximum number of hosts> (default %d)\n", max_hosts);
				fprintf(stdout, "-l is used in case a specific folder for user log data has to be created (valid only for type 'add')\n");
				fprintf(stdout, "-m <maximum number of opened sessions> (default %d)\n", max_sessions);
				fprintf(stdout, "-n <name>\n");
				fprintf(stdout, "-o <username used to submit requests to cluster>\n");
#ifdef INTERFACE_TYPE_IS_GSI
				fprintf(stdout, "-p <role>\n");
#else
				fprintf(stdout, "-p <password>\n");
				fprintf(stdout, "-q is used to generate a random password\n");
#endif
				fprintf(stdout, "-r <yes|no> to enable|disable administration privileges (default '%s')\n", is_admin);
				fprintf(stdout, "-s <surname>\n");
				fprintf(stdout, "-t <session timeout> in days (default %d)\n", timeout_session);
				return 0;
		}
	}

	set_debug_level(msglevel + 10);
	pmesg(LOG_INFO, __FILE__, __LINE__, "Selected log level %d\n", msglevel);

	if (!action) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Set an action with the option -a: add|del|list|update\n");
		cleanup();
		return 1;
	}
#ifdef OPH_SERVER_LOCATION
	oph_server_location = strdup(OPH_SERVER_LOCATION);
#else
	oph_server_location = getenv(OPH_SERVER_LOCATION_STR);
	if (!oph_server_location) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPH_SERVER_LOCATION has to be set\n");
		cleanup();
		return 1;
	}
#endif
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Server location '%s'\n", oph_server_location);

	char filename[OPH_MAX_STRING_SIZE];
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_CONFIGURATION_FILE, oph_server_location);
	if (set_global_values(filename)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in loading server configuration\n");
		return 1;
	}

	FILE *file;
	oph_argument *tmp;
#ifdef INTERFACE_TYPE_IS_GSI
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_AUTH_DN_FILE, oph_auth_location);
#else
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_AUTH_FILE, oph_auth_location);
#endif
	oph_init_args(&args);
	if (oph_load_file2(filename, &args)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in opening '%s'\n", filename);
		cleanup();
		return 1;
	}
#ifdef OPH_DB_SUPPORT
	if (mysql_library_init(0, 0, 0)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot setup MySQL\n");
		exit(1);
	}
#endif

	size_t iiii, jjjj = strlen(username ? username : "");
	char user_string[1 + jjjj];
	if (username) {
		strcpy(user_string, username);
		for (iiii = 0; iiii < jjjj; ++iiii)
			if ((user_string[iiii] == '/') || (user_string[iiii] == ' ') || (user_string[iiii] == '=') || (user_string[iiii] == ':'))
				user_string[iiii] = '_';
	}

	if (random_password) {
		const char allowedchars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#_+-*/.[]";
		srand(time(NULL));	// randomize seed
		for (iiii = 0; iiii < OPH_PASSWD_SIZE; iiii++)
			_random_password[iiii] = allowedchars[rand() % 72];
		_random_password[iiii] = '\0';
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Password: %s\n", _random_password);
		password = _random_password;
	}

	if (!strcasecmp(action, "add") || !strcasecmp(action, "append") || !strcasecmp(action, "create")) {
		if (!username || !password) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad input parameters. Username and password are mandatory!\n");
			cleanup();
			return 1;
		}
		for (tmp = args; tmp; tmp = tmp->next)
			if (!strcmp(username, tmp->key)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "User already exists!\n");
				cleanup();
				return 1;
			}
		const char allowedchars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@_.-/:= ";
		for (iiii = 0; iiii < jjjj; ++iiii)
			if (!strchr(allowedchars, username[iiii]))
				break;
		if (iiii < jjjj) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Char '%c' is not allowed!\n", username[iiii]);
			return 1;
		}
		if (strchr(username, '@'))
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Char '@' is not recommended!\n");

		char *_password = password;
#ifdef INTERFACE_TYPE_IS_SSL
		char sha_password[2 * SHA_DIGEST_LENGTH + 2];
		_password = oph_sha(sha_password, password);
		if (!_password) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "SHA digest cannot be created!\n");
			cleanup();
			return 1;
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Use SHA digest: %s\n", _password);
#endif

		// users.dat
		file = fopen(filename, "a");
		if (!file) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File cannot be opened!\n");
			cleanup();
			return 1;
		}
		fprintf(file, "%s%s%s\n", username, OPH_SEPARATOR_BASIC, _password);
		fclose(file);

		// folders
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_DIR, oph_auth_location, user_string);
		if (oph_mkdir(filename)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Directory cannot be opened!\n");
			cleanup();
			return 1;
		}
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_DIR, oph_auth_location, user_string);
		if (oph_mkdir(filename)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Directory cannot be opened!\n");
			cleanup();
			return 1;
		}
		// user.dat
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_FILE, oph_auth_location, user_string);
		file = fopen(filename, "w");
		if (!file) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File cannot be opened!\n");
			cleanup();
			return 1;
		}
		fprintf(file, "%s%s%d\n", OPH_USER_OPENED_SESSIONS, OPH_SEPARATOR_KV, 0);
		fprintf(file, "%s%s%d\n", OPH_USER_MAX_SESSIONS, OPH_SEPARATOR_KV, max_sessions);
		fprintf(file, "%s%s%d\n", OPH_USER_TIMEOUT_SESSION, OPH_SEPARATOR_KV, timeout_session);
		fprintf(file, "%s%s%d\n", OPH_USER_MAX_CORES, OPH_SEPARATOR_KV, max_cores);
		fprintf(file, "%s%s%d\n", OPH_USER_MAX_HOSTS, OPH_SEPARATOR_KV, max_hosts);
		fprintf(file, "%s%s%s\n", OPH_USER_IS_ADMIN, OPH_SEPARATOR_KV, is_admin);
		fprintf(file, "%s%s%s\n", OPH_USER_LAST_SESSION_ID, OPH_SEPARATOR_KV, "");
		fprintf(file, "%s%s%s\n", OPH_USER_LAST_CDD, OPH_SEPARATOR_KV, cdd ? cdd : "/");
		fprintf(file, "%s%s%s\n", OPH_USER_OS_USERNAME, OPH_SEPARATOR_KV, os_username ? os_username : "");
		fclose(file);

		// ophDB
		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
			cleanup();
			return 1;
		} else if (oph_odb_connect_to_ophidiadb(&oDB)) {
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
			cleanup();
			return 1;
		} else if (oph_odb_insert_user2(&oDB, username, password, name, surname, email, country, max_hosts)) {
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to insert new user data in OphidiaDB.\n");
			cleanup();
			return 1;
		} else
			oph_odb_disconnect_from_ophidiadb(&oDB);

		// log data
		if (log) {
			snprintf(filename, OPH_MAX_STRING_SIZE, "%s/%s", oph_txt_location, user_string);
			if (oph_mkdir2(filename, 0775)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Directory cannot be opened!\n");
				cleanup();
				return 1;
			}
		}
		// environmental variables
		if (oph_add_user) {
			char command[OPH_MAX_STRING_SIZE];
			snprintf(command, OPH_MAX_STRING_SIZE, OPH_COMMAND_SUDO, username, oph_add_user, password, oph_server_host);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Command: %s\n", command);
			if (system(command))
				pmesg(LOG_WARNING, __FILE__, __LINE__, "Environmental variables cannot be set!\n");
		}

	} else if (!strcasecmp(action, "del") || !strcasecmp(action, "delete") || !strcasecmp(action, "rm") || !strcasecmp(action, "remove")) {
		if (!username) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad input parameters. Username is mandatory!\n");
			cleanup();
			return 1;
		}
		for (tmp = args; tmp; tmp = tmp->next)
			if (!strcmp(username, tmp->key))
				break;
		if (!tmp) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "User not found!\n");
			cleanup();
			return 1;
		}
		// users.dat
		file = fopen(filename, "w");
		if (!file) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' cannot be opened!\n", filename);
			cleanup();
			return 1;
		}
		for (tmp = args; tmp; tmp = tmp->next)
			if (strcmp(username, tmp->key))
				fprintf(file, "%s%s%s\n", tmp->key, OPH_SEPARATOR_BASIC, tmp->value);
		fclose(file);

		// folder
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_DIR, oph_auth_location, user_string);
		if (nftw(filename, _delete_files, 2, FTW_DEPTH | FTW_PHYS)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Directory '%s' cannot be removed!\n", filename);
			cleanup();
			return 1;
		}
		// ophDB
		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
			cleanup();
			return 1;
		} else if (oph_odb_connect_to_ophidiadb(&oDB)) {
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
			cleanup();
			return 1;
		} else if (oph_odb_delete_user(&oDB, username)) {
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to insert new user data in OphidiaDB.\n");
			cleanup();
			return 1;
		} else
			oph_odb_disconnect_from_ophidiadb(&oDB);
	} else if (!strcasecmp(action, "update")) {
		if (!username) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad input parameters. Username is mandatory!\n");
			cleanup();
			return 1;
		}
		for (tmp = args; tmp; tmp = tmp->next)
			if (!strcmp(username, tmp->key))
				break;
		if (!tmp) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "User not found!\n");
			cleanup();
			return 1;
		}
		// users.dat
		if (password) {
			char *_password = password;
#ifdef INTERFACE_TYPE_IS_SSL
			char sha_password[2 * SHA_DIGEST_LENGTH + 2];
			_password = oph_sha(sha_password, password);
			if (!_password) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SHA digest cannot be created!\n");
				cleanup();
				return 1;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Use SHA digest: %s\n", _password);
#endif
			file = fopen(filename, "w");
			if (!file) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' cannot be opened!\n", filename);
				cleanup();
				return 1;
			}
			for (tmp = args; tmp; tmp = tmp->next)
				if (strcmp(username, tmp->key))
					fprintf(file, "%s%s%s\n", tmp->key, OPH_SEPARATOR_BASIC, tmp->value);
				else
					fprintf(file, "%s%s%s\n", username, OPH_SEPARATOR_BASIC, _password);
			fclose(file);
		}
		// user.dat
		if (update) {
			oph_cleanup_args(&args);

			snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_FILE, oph_auth_location, user_string);
			if (oph_load_file(filename, &args)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' cannot be opened!\n", filename);
				cleanup();
				return 1;
			}
			file = fopen(filename, "w");
			if (!file) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' cannot be opened!\n", filename);
				cleanup();
				return 1;
			}
			if (update & 2)
				for (tmp = args; tmp; tmp = tmp->next) {
					unsigned int opened_sessions = (unsigned int) strtol(tmp->value, NULL, 10);
					if (!strcmp(tmp->key, OPH_USER_OPENED_SESSIONS) && (max_sessions < opened_sessions)) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "Current number of opened sessions (%d) is higher than %d!\n", opened_sessions, max_sessions);
						max_sessions = opened_sessions;
					}
				}
			for (tmp = args; tmp; tmp = tmp->next) {
				if ((update & 1) && (!strcmp(tmp->key, OPH_USER_MAX_CORES)))
					fprintf(file, "%s%s%d\n", OPH_USER_MAX_CORES, OPH_SEPARATOR_KV, max_cores);
				else if ((update & 2) && (!strcmp(tmp->key, OPH_USER_MAX_SESSIONS)))
					fprintf(file, "%s%s%d\n", OPH_USER_MAX_SESSIONS, OPH_SEPARATOR_KV, max_sessions);
				else if ((update & 4) && (!strcmp(tmp->key, OPH_USER_IS_ADMIN)))
					fprintf(file, "%s%s%s\n", OPH_USER_IS_ADMIN, OPH_SEPARATOR_KV, is_admin);
				else if ((update & 8) && (!strcmp(tmp->key, OPH_USER_TIMEOUT_SESSION)))
					fprintf(file, "%s%s%d\n", OPH_USER_TIMEOUT_SESSION, OPH_SEPARATOR_KV, timeout_session);
				else if ((update & 16) && (!strcmp(tmp->key, OPH_USER_MAX_HOSTS)))
					fprintf(file, "%s%s%d\n", OPH_USER_MAX_HOSTS, OPH_SEPARATOR_KV, max_hosts);
				else if ((update & 32) && (!strcmp(tmp->key, OPH_USER_LAST_CDD)))
					fprintf(file, "%s%s%s\n", OPH_USER_LAST_CDD, OPH_SEPARATOR_KV, cdd ? cdd : "/");
				else if ((update & 64) && (!strcmp(tmp->key, OPH_USER_OS_USERNAME)))
					fprintf(file, "%s%s%s\n", OPH_USER_OS_USERNAME, OPH_SEPARATOR_KV, os_username ? os_username : "");
				else
					fprintf(file, "%s%s%s\n", tmp->key, OPH_SEPARATOR_KV, tmp->value);
			}
			fclose(file);
		}
		// ophDB
		if (password || name || surname || email || country || (update & 16)) {
			ophidiadb oDB;
			oph_odb_initialize_ophidiadb(&oDB);
			if (oph_odb_read_config_ophidiadb(&oDB)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
				cleanup();
				return 1;
			} else if (oph_odb_connect_to_ophidiadb(&oDB)) {
				oph_odb_disconnect_from_ophidiadb(&oDB);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
				cleanup();
				return 1;
			} else if (oph_odb_update_user(&oDB, username, password, name, surname, email, country, max_hosts)) {
				oph_odb_disconnect_from_ophidiadb(&oDB);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to insert new user data in OphidiaDB.\n");
				cleanup();
				return 1;
			} else
				oph_odb_disconnect_from_ophidiadb(&oDB);
		}
#ifdef INTERFACE_TYPE_IS_GSI
		if (black_listed) {
			char *black_list = globus_libc_getenv("BLACK_LIST_FILE");
			char *black_list_file = strdup(black_list ? black_list : BLACK_LIST_FILE);
			snprintf(filename, OPH_MAX_STRING_SIZE, black_list_file);
			file = fopen(filename, "a");
			if (!file) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' cannot be opened!\n", filename);
				cleanup();
				return 1;
			}
			fprintf(file, "%s\n", username);
			fclose(file);
		}
#else
		UNUSED(black_listed);
#endif

		// environmental variables
		if (oph_update_user) {
			char command[OPH_MAX_STRING_SIZE];
			snprintf(command, OPH_MAX_STRING_SIZE, OPH_COMMAND_SUDO, username, oph_update_user, password, oph_server_host);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Command: %s\n", command);
			if (system(command))
				pmesg(LOG_WARNING, __FILE__, __LINE__, "Environmental variables cannot be updated!\n");
		}

	} else if (!strcasecmp(action, "list"))
		for (tmp = args; tmp; tmp = tmp->next)
			printf("%s\n", tmp->key);
	else
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad command '%s'\n", action);

	cleanup();

	pmesg(LOG_INFO, __FILE__, __LINE__, "Success\n");
	return 0;
}
