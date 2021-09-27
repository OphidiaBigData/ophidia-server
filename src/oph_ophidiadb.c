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

#include "oph_ophidiadb.h"
#include "oph_gather.h"

#include <ctype.h>
#include <unistd.h>

extern char *oph_server_location;
extern ophidiadb *ophDB;

extern char *oph_sha(char *to, const char *passwd);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

#ifndef OPH_DB_SUPPORT
extern char *oph_server_port;
extern char *oph_txt_location;
unsigned int oph_odb_sequence = 0;
#endif

#define OPH_ODB_TEMPORARY_FILE "%s/%s%s%d.out"
#define OPH_ODB_TAB "\t"

typedef struct {
	int *id;
	int number_of_rows;
	int number_of_cols;
} oph_sqlite_id;

int _oph_odb_get_id_callback(void *res, int argc, char **argv, char **azColName)
{
	UNUSED(azColName);

	if (!res)
		return OPH_ODB_NULL_PARAM;

	((oph_sqlite_id *) res)->number_of_cols = argc;

	if (!argc)
		return OPH_ODB_NO_ROW_FOUND;

	if (argv && argv[0]) {
		if (!((oph_sqlite_id *) res)->number_of_rows)
			*((oph_sqlite_id *) res)->id = strtol(argv[0], NULL, 10);
		((oph_sqlite_id *) res)->number_of_rows++;
	}

	return OPH_ODB_SUCCESS;
}

typedef struct {
	char **user;
	int number_of_rows;
	int number_of_cols;
} oph_sqlite_user;

int _oph_odb_get_user_callback(void *res, int argc, char **argv, char **azColName)
{
	UNUSED(azColName);

	if (!res)
		return OPH_ODB_NULL_PARAM;

	((oph_sqlite_user *) res)->number_of_cols = argc;

	if (!argc)
		return OPH_ODB_NO_ROW_FOUND;

	if (argv && argv[0]) {
		if (!((oph_sqlite_user *) res)->number_of_rows)
			*((oph_sqlite_user *) res)->user = strdup(argv[0]);
		((oph_sqlite_user *) res)->number_of_rows++;
	}

	return OPH_ODB_SUCCESS;
}

typedef struct _oph_sqlite_item {
	int id;
	char *ctime;
	char *name;
	int wid;
	int pid;
	char *max_status;
	struct _oph_sqlite_item *next;
} oph_sqlite_item;

int _oph_sqlite_alloc_list(oph_sqlite_item ** head)
{
	if (!head)
		return OPH_ODB_NULL_PARAM;

	*head = (oph_sqlite_item *) malloc(sizeof(oph_sqlite_item));
	if (!*head)
		return OPH_ODB_MEMORY_ERROR;

	(*head)->id = 0;
	(*head)->ctime = NULL;
	(*head)->name = NULL;
	(*head)->wid = 0;
	(*head)->pid = 0;
	(*head)->max_status = NULL;

	return OPH_ODB_SUCCESS;
}

int _oph_sqlite_free_list(oph_sqlite_item * head)
{
	if (!head)
		return OPH_ODB_NULL_PARAM;

	oph_sqlite_item *next = NULL;
	for (; head; head = next) {
		next = head->next;
		if (head->ctime)
			free(head->ctime);
		if (head->name)
			free(head->name);
		if (head->max_status)
			free(head->max_status);
		free(head);
	}

	return OPH_ODB_SUCCESS;
}

typedef struct {
	oph_sqlite_item *head;
	oph_sqlite_item *tail;
	int number_of_rows;
	int number_of_cols;
} oph_sqlite_list;

int _oph_odb_get_list_callback(void *res, int argc, char **argv, char **azColName)
{
	UNUSED(azColName);

	if (!res)
		return OPH_ODB_NULL_PARAM;

	((oph_sqlite_list *) res)->number_of_cols = argc;

	if (!argc)
		return OPH_ODB_NO_ROW_FOUND;

	if (argv) {

		oph_sqlite_item *tmp = NULL;
		if (_oph_sqlite_alloc_list(&tmp))
			return OPH_ODB_MEMORY_ERROR;

		if (argv[0])
			tmp->id = strtol(argv[0], NULL, 10);
		if ((argc > 1) && argv[1])
			tmp->ctime = strdup(argv[1]);
		if ((argc > 2) && argv[2])
			tmp->name = strdup(argv[2]);
		if ((argc > 3) && argv[3])
			tmp->wid = strtol(argv[3], NULL, 10);
		if ((argc > 4) && argv[4])
			tmp->pid = strtol(argv[4], NULL, 10);
		if ((argc > 5) && argv[5])
			tmp->max_status = strdup(argv[5]);
		tmp->next = NULL;

		if (((oph_sqlite_list *) res)->head)
			((oph_sqlite_list *) res)->tail->next = tmp;
		else
			((oph_sqlite_list *) res)->head = tmp;
		((oph_sqlite_list *) res)->tail = tmp;

		((oph_sqlite_list *) res)->number_of_rows++;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_read_config_ophidiadb(ophidiadb * oDB)
{
	if (!ophDB) {
		ophDB = (ophidiadb *) malloc(sizeof(ophidiadb));
		if (!ophDB)
			return OPH_ODB_MEMORY_ERROR;

		char config[OPH_MAX_STRING_SIZE];
		snprintf(config, sizeof(config), OPH_DBMS_CONF_FILE, oph_server_location);

		FILE *file = fopen(config, "r");
		if (file == NULL)
			return OPH_ODB_ERROR;

		unsigned int i;
		char *argument = NULL;
		char *argument_value = NULL;
		int argument_length = 0;
		char *result = NULL;
		char line[OPH_MAX_STRING_SIZE] = { '\0' };
		while (!feof(file)) {
			result = fgets(line, OPH_MAX_STRING_SIZE, file);
			if (!result) {
				if (ferror(file)) {
					fclose(file);
					return OPH_ODB_ERROR;
				}
				break;
			}

			if (!strlen(line))
				continue;

			/* Remove trailing newline */
			if (line[strlen(line) - 1] == '\n')
				line[strlen(line) - 1] = '\0';

			/* Skip comment lines */
			if ((line[0] == '#') || (line[0] == '\n'))
				continue;

			/* Check if line contains only spaces */
			for (i = 0; (i < strlen(line)) && (i < OPH_MAX_STRING_SIZE); i++) {
				if (!isspace((unsigned char) line[i]))
					break;
			}
			if (i == strlen(line) || i == OPH_MAX_STRING_SIZE) {
				continue;
			}

			/* Split argument and value on '=' character */
			for (i = 0; (i < strlen(line)) && (i < OPH_MAX_STRING_SIZE); i++) {
				if (line[i] == '=')
					break;
			}
			if ((i == strlen(line)) || (i == OPH_MAX_STRING_SIZE)) {
				continue;
			}

			argument_length = strlen(line) - i - 1;

			argument = (char *) strndup(line, sizeof(char) * i);
			if (!argument) {
				fclose(file);
				return OPH_ODB_ERROR;
			}

			argument_value = (char *) strndup(line + i + 1, sizeof(char) * argument_length);
			if (!argument_value) {
				fclose(file);
				free(argument);
				return OPH_ODB_ERROR;
			}

			if (!strncasecmp(argument, OPH_CONF_OPHDB_NAME, strlen(OPH_CONF_OPHDB_NAME))) {
				ophDB->name = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_HOST, strlen(OPH_CONF_OPHDB_HOST))) {
				ophDB->hostname = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_PORT, strlen(OPH_CONF_OPHDB_PORT))) {
				ophDB->server_port = (int) strtol(argument_value, NULL, 10);
				free(argument_value);
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_LOGIN, strlen(OPH_CONF_OPHDB_LOGIN))) {
				ophDB->username = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_PWD, strlen(OPH_CONF_OPHDB_PWD))) {
				ophDB->pwd = argument_value;
#ifndef OPH_DB_SUPPORT
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_GRH, strlen(OPH_CONF_OPHDB_GRH))) {
				ophDB->grh = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_GTH, strlen(OPH_CONF_OPHDB_GTH))) {
				ophDB->gth = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_CHP, strlen(OPH_CONF_OPHDB_CHP))) {
				ophDB->chp = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_DHP, strlen(OPH_CONF_OPHDB_DHP))) {
				ophDB->dhp = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_RLHP, strlen(OPH_CONF_OPHDB_RLHP))) {
				ophDB->rlhp = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_RSHP, strlen(OPH_CONF_OPHDB_RSHP))) {
				ophDB->rshp = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_RTHP, strlen(OPH_CONF_OPHDB_RTHP))) {
				ophDB->rthp = argument_value;
			} else if (!strncasecmp(argument, OPH_CONF_OPHDB_RLIST, strlen(OPH_CONF_OPHDB_RLIST))) {
				ophDB->rlist = argument_value;
#endif
			} else {
				free(argument_value);
			}

			free(argument);
		}

		fclose(file);

#ifdef OPH_DB_SUPPORT
		ophDB->conn = NULL;
#else
		ophDB->db = NULL;
#endif
	}

	if (oDB) {
		oDB->name = ophDB->name;
		oDB->hostname = ophDB->hostname;
		oDB->server_port = ophDB->server_port;
		oDB->username = ophDB->username;
		oDB->pwd = ophDB->pwd;
#ifndef OPH_DB_SUPPORT
		oDB->grh = ophDB->grh;
		oDB->gth = ophDB->gth;
		oDB->chp = ophDB->chp;
		oDB->dhp = ophDB->dhp;
		oDB->rlhp = ophDB->rlhp;
		oDB->rshp = ophDB->rshp;
		oDB->rthp = ophDB->rthp;
		oDB->rlist = ophDB->rlist;
#endif
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_initialize_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	oDB->name = NULL;
	oDB->hostname = NULL;
	oDB->username = NULL;
	oDB->pwd = NULL;
#ifdef OPH_DB_SUPPORT
	oDB->conn = NULL;
#else
	oDB->db = NULL;
	oDB->grh = NULL;
	oDB->gth = NULL;
	oDB->chp = NULL;
	oDB->dhp = NULL;
	oDB->rlhp = NULL;
	oDB->rshp = NULL;
	oDB->rthp = NULL;
	oDB->rlist = NULL;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_free_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	if (oDB->name) {
		free(oDB->name);
		oDB->name = NULL;
	}
	if (oDB->hostname) {
		free(oDB->hostname);
		oDB->hostname = NULL;
	}
	if (oDB->username) {
		free(oDB->username);
		oDB->username = NULL;
	}
	if (oDB->pwd) {
		free(oDB->pwd);
		oDB->pwd = NULL;
	}
#ifdef OPH_DB_SUPPORT
	if (oDB->conn) {
		oph_odb_disconnect_from_ophidiadb(oDB);
		oDB->conn = NULL;
	}
#else
	if (oDB->db) {
		oph_odb_disconnect_from_ophidiadb(oDB);
		oDB->db = NULL;
	}
	if (oDB->grh) {
		free(oDB->grh);
		oDB->grh = NULL;
	}
	if (oDB->gth) {
		free(oDB->gth);
		oDB->gth = NULL;
	}
	if (oDB->chp) {
		free(oDB->chp);
		oDB->chp = NULL;
	}
	if (oDB->dhp) {
		free(oDB->dhp);
		oDB->dhp = NULL;
	}
	if (oDB->rlhp) {
		free(oDB->rlhp);
		oDB->rlhp = NULL;
	}
	if (oDB->rshp) {
		free(oDB->rshp);
		oDB->rshp = NULL;
	}
	if (oDB->rthp) {
		free(oDB->rthp);
		oDB->rthp = NULL;
	}
	if (oDB->rlist) {
		free(oDB->rlist);
		oDB->rlist = NULL;
	}
#endif

	free(oDB);

	return OPH_ODB_SUCCESS;
}

int oph_odb_connect_to_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

#ifndef OPH_DB_SUPPORT
	if (!oDB->name) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get system catalog name\n");
		return OPH_ODB_ERROR;
	}

	oDB->db = NULL;

	char sqlite_db[OPH_MAX_STRING_SIZE];
	snprintf(sqlite_db, OPH_MAX_STRING_SIZE, OPH_DB_FILE, oph_server_location, oDB->name);

	int result = 0;
	if ((result = sqlite3_open(sqlite_db, &oDB->db))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to open '%s': %d\n", sqlite_db, result);
		oph_odb_disconnect_from_ophidiadb(oDB);
		return OPH_ODB_MYSQL_ERROR;
	}
	if (sqlite3_exec(oDB->db, SQLITE_SWITCH_ON_FOREIGN_KEYS, NULL, NULL, NULL))
		return OPH_ODB_MYSQL_ERROR;
#else
	oDB->conn = NULL;
	if (!(oDB->conn = mysql_init(NULL))) {
		oph_odb_disconnect_from_ophidiadb(oDB);
		return OPH_ODB_MYSQL_ERROR;
	}

	/* Connect to database */
	if (!mysql_real_connect(oDB->conn, oDB->hostname, oDB->username, oDB->pwd, oDB->name, oDB->server_port, NULL, 0)) {
		oph_odb_disconnect_from_ophidiadb(oDB);
		return OPH_ODB_MYSQL_ERROR;
	}
#endif
	return OPH_ODB_SUCCESS;
}

int oph_odb_check_connection_to_ophidiadb(ophidiadb * oDB)
{
#ifdef OPH_DB_SUPPORT

	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	if (!(oDB->conn))
		return OPH_ODB_MYSQL_ERROR;

	if (mysql_ping(oDB->conn)) {
		mysql_close(oDB->conn);
		/* Connect to database */
		if (oph_odb_connect_to_ophidiadb(oDB)) {
			oph_odb_disconnect_from_ophidiadb(oDB);
			return OPH_ODB_MYSQL_ERROR;
		}
	}
#endif
	return OPH_ODB_SUCCESS;
}

int oph_odb_disconnect_from_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

#ifndef OPH_DB_SUPPORT
	if (oDB->db) {
		sqlite3_close(oDB->db);
		oDB->db = NULL;
	}
	return OPH_ODB_SUCCESS;
#else
	if (oDB->conn) {
		mysql_close(oDB->conn);
		oDB->conn = NULL;
	}

	return OPH_ODB_SUCCESS;
#endif
}

int oph_odb_retrieve_ids(ophidiadb * oDB, const char *command, int **id, char ***ctime, int *nn)
{
	if (!oDB || !command || !id || !nn) {
		return OPH_ODB_NULL_PARAM;
	}
	*nn = 0;
	*id = NULL;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, "%s", command);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT

	if (mysql_select_db(oDB->conn, oDB->name))
		return OPH_ODB_MYSQL_ERROR;

	if (mysql_query(oDB->conn, query))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_field_count(oDB->conn) != 2) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	*nn = mysql_num_rows(res);
	if (!(*nn)) {
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	*id = (int *) malloc((*nn) * sizeof(int));
	if (ctime)
		*ctime = (char **) malloc((*nn) * sizeof(char *));

	int j = 0;
	while ((row = mysql_fetch_row(res)) != NULL) {
		(*id)[j] = (int) strtol(row[0], NULL, 10);
		if (ctime)
			(*ctime)[j] = row[1] ? strdup(row[1]) : NULL;
		j++;
	}
	mysql_free_result(res);

#else

	oph_sqlite_list res;
	res.head = NULL;
	res.tail = NULL;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, query, _oph_odb_get_list_callback, &res, NULL))
		return OPH_ODB_MYSQL_ERROR;

	if (res.number_of_cols != 2)
		return OPH_ODB_TOO_MANY_ROWS;

	*nn = res.number_of_rows;
	if (!(*nn))
		return OPH_ODB_NO_ROW_FOUND;

	*id = (int *) malloc((*nn) * sizeof(int));
	if (ctime)
		*ctime = (char **) malloc((*nn) * sizeof(char *));

	int j;
	oph_sqlite_item *tmp = res.head;
	for (j = 0; j < *nn; j++, tmp = tmp->next) {
		(*id)[j] = tmp->id;
		if (ctime)
			(*ctime)[j] = tmp->ctime ? strdup(tmp->ctime) : NULL;
	}
	_oph_sqlite_free_list(res.head);

#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_list(ophidiadb * oDB, const char *command, ophidiadb_list * list)
{
	if (!oDB || !command || !list)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, "%s", command);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT

	if (mysql_select_db(oDB->conn, oDB->name))
		return OPH_ODB_MYSQL_ERROR;

	if (mysql_query(oDB->conn, query))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if ((mysql_field_count(oDB->conn) < 3) || (mysql_field_count(oDB->conn) > 6)) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	list->size = mysql_num_rows(res);
	if (!list->size) {
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	list->name = (char **) malloc(list->size * sizeof(char *));
	list->id = (int *) malloc(list->size * sizeof(int));
	list->pid = (int *) malloc(list->size * sizeof(int));
	list->wid = (int *) malloc(list->size * sizeof(int));
	list->ctime = (char **) malloc(list->size * sizeof(char *));
	list->max_status = (char **) malloc(list->size * sizeof(char *));

	if (!list->name || !list->id || !list->wid || !list->pid || !list->ctime || !list->max_status) {
		mysql_free_result(res);
		return OPH_ODB_MEMORY_ERROR;
	}

	int j = 0;
	while ((row = mysql_fetch_row(res)) != NULL) {
		list->id[j] = row[0] ? (int) strtol(row[0], NULL, 10) : 0;
		list->ctime[j] = row[1] ? strdup(row[1]) : NULL;
		list->name[j] = row[2] ? strdup(row[2]) : NULL;
		if ((mysql_field_count(oDB->conn) > 3) && row[3])
			list->wid[j] = (int) strtol(row[3], NULL, 10);
		else
			list->wid[j] = 0;
		if ((mysql_field_count(oDB->conn) > 4) && row[4])
			list->pid[j] = (int) strtol(row[4], NULL, 10);
		else
			list->pid[j] = 0;
		if ((mysql_field_count(oDB->conn) > 5) && row[5])
			list->max_status[j] = strdup(row[5]);
		else
			list->max_status[j] = NULL;
		j++;
	}
	mysql_free_result(res);

#else

	oph_sqlite_list res;
	res.head = NULL;
	res.tail = NULL;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, query, _oph_odb_get_list_callback, &res, NULL))
		return OPH_ODB_MYSQL_ERROR;

	if ((res.number_of_cols < 3) || (res.number_of_cols > 6))
		return OPH_ODB_TOO_MANY_ROWS;

	list->size = res.number_of_rows;
	if (!list->size)
		return OPH_ODB_NO_ROW_FOUND;

	list->name = (char **) malloc(list->size * sizeof(char *));
	list->id = (int *) malloc(list->size * sizeof(int));
	list->pid = (int *) malloc(list->size * sizeof(int));
	list->wid = (int *) malloc(list->size * sizeof(int));
	list->ctime = (char **) malloc(list->size * sizeof(char *));
	list->max_status = (char **) malloc(list->size * sizeof(char *));

	if (!list->name || !list->id || !list->wid || !list->pid || !list->ctime || !list->max_status)
		return OPH_ODB_MEMORY_ERROR;

	int j;
	oph_sqlite_item *tmp = res.head;
	for (j = 0; j < list->size; j++, tmp = tmp->next) {
		list->id[j] = tmp->id;
		list->ctime[j] = tmp->ctime ? strdup(tmp->ctime) : NULL;
		list->name[j] = tmp->name ? strdup(tmp->name) : NULL;
		if ((res.number_of_cols > 3) && tmp->wid)
			list->wid[j] = tmp->wid;
		else
			list->wid[j] = 0;
		if ((res.number_of_cols > 4) && tmp->pid)
			list->pid[j] = tmp->pid;
		else
			list->pid[j] = 0;
		if ((res.number_of_cols > 5) && tmp->max_status)
			list->max_status[j] = strdup(tmp->max_status);
		else
			list->max_status[j] = NULL;
	}
	_oph_sqlite_free_list(res.head);

#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_list2(ophidiadb * oDB, const char *command, ophidiadb_list * list)
{
#ifdef OPH_DB_SUPPORT

	return oph_odb_retrieve_list(oDB, command, list);

#else

	if (!oDB->rlist)
		return OPH_ODB_NULL_PARAM;

	unsigned int sequence = 0;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_lock(&global_flag);
	sequence = oph_odb_sequence++;
	pthread_mutex_unlock(&global_flag);
#endif

	char _command[MYSQL_BUFLEN], outfile[MYSQL_BUFLEN];
	snprintf(outfile, MYSQL_BUFLEN, OPH_ODB_TEMPORARY_FILE, oph_txt_location, oph_server_port, OPH_SERVER_PREFIX, sequence);
	snprintf(_command, MYSQL_BUFLEN, "%s \"%s\" %s", oDB->rlist, command, outfile);

	if (system(_command)) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}

	char tmp[MYSQL_BUFLEN];
	FILE *file = fopen(outfile, "r");
	if (!file) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}

	list->size = -1;
	while (fgets(tmp, MYSQL_BUFLEN, file))
		list->size++;

	if (list->size <= 0) {
		list->size = 0;
		fclose(file);
		unlink(outfile);
		return OPH_ODB_NO_ROW_FOUND;
	}

	list->name = (char **) malloc(list->size * sizeof(char *));
	list->id = (int *) malloc(list->size * sizeof(int));
	list->pid = (int *) malloc(list->size * sizeof(int));
	list->wid = (int *) malloc(list->size * sizeof(int));
	list->ctime = (char **) malloc(list->size * sizeof(char *));
	list->max_status = (char **) malloc(list->size * sizeof(char *));

	if (!list->name || !list->id || !list->wid || !list->pid || !list->ctime || !list->max_status) {
		fclose(file);
		unlink(outfile);
		return OPH_ODB_MEMORY_ERROR;
	}

	rewind(file);

	int j = -1;
	char first = 1, *pch, *save_pointer = NULL;
	while (fgets(tmp, MYSQL_BUFLEN, file)) {

		if (first) {
			first = 0;
			continue;
		}
		j++;

		pch = strtok_r(tmp, OPH_ODB_TAB, &save_pointer);
		list->id[j] = pch ? (int) strtol(pch, NULL, 10) : 0;
		if (!pch)
			continue;

		pch = strtok_r(NULL, OPH_ODB_TAB, &save_pointer);
		list->ctime[j] = pch ? strdup(pch) : NULL;
		if (!pch)
			continue;

		pch = strtok_r(NULL, OPH_ODB_TAB, &save_pointer);
		list->name[j] = pch && strcmp(pch, OPH_NULL_VALUE) ? strdup(pch) : NULL;
		if (!pch)
			continue;

		pch = strtok_r(NULL, "\t", &save_pointer);
		if (pch)
			list->wid[j] = (int) strtol(pch, NULL, 10);
		else {
			list->wid[j] = 0;
			continue;
		}

		pch = strtok_r(NULL, OPH_ODB_TAB, &save_pointer);
		if (pch)
			list->pid[j] = (int) strtol(pch, NULL, 10);
		else {
			list->pid[j] = 0;
			continue;
		}

		pch = strtok_r(NULL, OPH_ODB_TAB, &save_pointer);
		if (pch && strcmp(pch, OPH_NULL_VALUE))
			list->max_status[j] = strdup(pch);
		else {
			list->max_status[j] = NULL;
			continue;
		}
	}

	fclose(file);
	unlink(outfile);

	return OPH_ODB_SUCCESS;
#endif
}

int oph_odb_initialize_ophidiadb_list(ophidiadb_list * list)
{
	if (!list)
		return OPH_ODB_NULL_PARAM;

	list->name = NULL;
	list->id = NULL;
	list->pid = NULL;
	list->wid = NULL;
	list->ctime = NULL;
	list->max_status = NULL;

	list->size = 0;
	return OPH_ODB_SUCCESS;
}

int oph_odb_free_ophidiadb_list(ophidiadb_list * list)
{
	int j;
	if (!list)
		return OPH_ODB_NULL_PARAM;

	if (list->name) {
		for (j = 0; j < list->size; ++j)
			if (list->name[j]) {
				free(list->name[j]);
				list->name[j] = NULL;
			}
		free(list->name);
		list->name = NULL;
	}
	if (list->id) {
		free(list->id);
		list->id = NULL;
	}
	if (list->pid) {
		free(list->pid);
		list->pid = NULL;
	}
	if (list->wid) {
		free(list->wid);
		list->wid = NULL;
	}
	if (list->ctime) {
		for (j = 0; j < list->size; ++j)
			if (list->ctime[j]) {
				free(list->ctime[j]);
				list->ctime[j] = NULL;
			}
		free(list->ctime);
		list->ctime = NULL;
	}
	if (list->max_status) {
		for (j = 0; j < list->size; ++j)
			if (list->max_status[j]) {
				free(list->max_status[j]);
				list->max_status[j] = NULL;
			}
		free(list->max_status);
		list->max_status = NULL;
	}

	list->size = 0;
	return OPH_ODB_SUCCESS;
}

int oph_odb_extract_datacube_ids(ophidiadb * oDB, char *query, cube ** datacube, int *counter)
{
#ifdef OPH_DB_SUPPORT
	if (!oDB || !query || !datacube || !counter)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	if (mysql_query(oDB->conn, query))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_field_count(oDB->conn) != 2) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	*counter = mysql_num_rows(res);
	if (!(*counter)) {
		mysql_free_result(res);
		return OPH_ODB_SUCCESS;
	}

	if (!(*datacube = (cube *) malloc(*counter * sizeof(cube)))) {
		mysql_free_result(res);
		return OPH_ODB_MEMORY_ERROR;
	}

	int i = 0;
	while ((row = mysql_fetch_row(res)) != NULL) {
		(*datacube)[i].id_datacube = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
		(*datacube)[i].id_container = (row[1] ? (int) strtol(row[1], NULL, 10) : 0);
		i++;
	}
	mysql_free_result(res);
#endif
	return OPH_ODB_SUCCESS;
}

int oph_odb_insert_user(ophidiadb * oDB, const char *username)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_INSERT_USER, username);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;
#else

	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL))
		return OPH_ODB_MYSQL_ERROR;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_insert_user2(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN], tmp[MYSQL_BUFLEN];
	int n;
	if (country) {
		int idcountry = 0;

		n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_SELECT_COUNTRY, country);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, insertQuery))
			return OPH_ODB_MYSQL_ERROR;

		MYSQL_RES *res;
		MYSQL_ROW row;
		res = mysql_store_result(oDB->conn);

		if ((mysql_field_count(oDB->conn) != 1) || (mysql_num_rows(res) != 1)) {
			mysql_free_result(res);
			return OPH_ODB_TOO_MANY_ROWS;
		}

		while ((row = mysql_fetch_row(res)) != NULL)
			idcountry = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
		mysql_free_result(res);
#else
		oph_sqlite_id res;
		res.id = &idcountry;
		res.number_of_rows = 0;
		res.number_of_cols = 0;
		if (sqlite3_exec(oDB->db, insertQuery, _oph_odb_get_id_callback, &res, NULL))
			return OPH_ODB_MYSQL_ERROR;

		if ((res.number_of_rows != 1) || (res.number_of_cols != 1))
			return OPH_ODB_NO_ROW_FOUND;
#endif

		snprintf(tmp, MYSQL_BUFLEN, "%d", idcountry);
	} else
		snprintf(tmp, MYSQL_BUFLEN, OPH_NULL_VALUE);

#ifdef INTERFACE_TYPE_IS_SSL
	char sha_passwd[2 * SHA_DIGEST_LENGTH + 2];
	if (password) {
		oph_sha(sha_passwd, password);
		password = sha_passwd;
	}
#endif

	n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_INSERT_USER2, username, password, name ? "'" : "", name ? name : OPH_NULL_VALUE, name ? "'" : "", surname ? "'" : "",
		     surname ? surname : OPH_NULL_VALUE, surname ? "'" : "", email ? "'" : "", email ? email : OPH_NULL_VALUE, email ? "'" : "", tmp, max_hosts > 0 ? max_hosts : 0);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;
#else

	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL))
		return OPH_ODB_MYSQL_ERROR;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_delete_user(ophidiadb * oDB, const char *username)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_DELETE_USER, username);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;
#else

	if (sqlite3_exec(oDB->db, insertQuery, NULL, NULL, NULL))
		return OPH_ODB_MYSQL_ERROR;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_update_user(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char updateQuery[MYSQL_BUFLEN];
	int n;

	if (password) {

#ifdef INTERFACE_TYPE_IS_SSL
		char sha_passwd[2 * SHA_DIGEST_LENGTH + 2];
		oph_sha(sha_passwd, password);
		password = sha_passwd;
#endif
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER2, "password", password, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
#else
		if (sqlite3_exec(oDB->db, updateQuery, NULL, NULL, NULL))
			return OPH_ODB_MYSQL_ERROR;
#endif
	}
	if (name) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "name", name, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
#else
		if (sqlite3_exec(oDB->db, updateQuery, NULL, NULL, NULL))
			return OPH_ODB_MYSQL_ERROR;
#endif
	}
	if (surname) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "surname", surname, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
#else
		if (sqlite3_exec(oDB->db, updateQuery, NULL, NULL, NULL))
			return OPH_ODB_MYSQL_ERROR;
#endif
	}
	if (email) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "mail", email, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
#else
		if (sqlite3_exec(oDB->db, updateQuery, NULL, NULL, NULL))
			return OPH_ODB_MYSQL_ERROR;
#endif
	}
	if (country) {
		int idcountry = 0;

		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_SELECT_COUNTRY, country);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;

		MYSQL_RES *res;
		MYSQL_ROW row;
		res = mysql_store_result(oDB->conn);

		if ((mysql_field_count(oDB->conn) != 1) || (mysql_num_rows(res) != 1)) {
			mysql_free_result(res);
			return OPH_ODB_TOO_MANY_ROWS;
		}

		while ((row = mysql_fetch_row(res)) != NULL)
			idcountry = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
		mysql_free_result(res);
#else
		oph_sqlite_id res;
		res.id = &idcountry;
		res.number_of_rows = 0;
		res.number_of_cols = 0;
		if (sqlite3_exec(oDB->db, updateQuery, _oph_odb_get_id_callback, &res, NULL))
			return OPH_ODB_MYSQL_ERROR;

		if ((res.number_of_rows != 1) || (res.number_of_cols != 1))
			return OPH_ODB_NO_ROW_FOUND;
#endif

		char tmp[MYSQL_BUFLEN];
		snprintf(tmp, MYSQL_BUFLEN, "%d", idcountry);
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "idcountry", tmp, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
#else
		if (sqlite3_exec(oDB->db, updateQuery, NULL, NULL, NULL))
			return OPH_ODB_MYSQL_ERROR;
#endif
	}
	if (max_hosts >= 0) {
		char tmp[MYSQL_BUFLEN];
		snprintf(tmp, MYSQL_BUFLEN, "%d", max_hosts);

		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "maxhosts", tmp, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;
#ifdef OPH_DB_SUPPORT
		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
#else
		if (sqlite3_exec(oDB->db, updateQuery, NULL, NULL, NULL))
			return OPH_ODB_MYSQL_ERROR;
#endif
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_create_hp(ophidiadb * oDB, const char *name, const char *parent, int id_user)
{
	if (!oDB || !name || !parent || !id_user)
		return OPH_ODB_NULL_PARAM;

#ifndef OPH_DB_SUPPORT

	if (!oDB->chp)
		return OPH_ODB_NULL_PARAM;

	char command[MYSQL_BUFLEN];
	snprintf(command, MYSQL_BUFLEN, "%s %s %d %s", oDB->chp, name, id_user, parent);

	if (system(command))
		return OPH_ODB_MYSQL_ERROR;

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN], select_by_name = strcmp(parent, OPH_COMMON_AUTO);

	int n;
	if (select_by_name)
		n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RETRIEVE_PARTITION "AND partitionname = '%s'", id_user, parent);
	else
		n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RETRIEVE_PARTITION, id_user);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if ((mysql_field_count(oDB->conn) != 1) || (select_by_name && (mysql_num_rows(res) != 1) || (!select_by_name && !mysql_num_rows(res)))) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	int idhostpartition = 0;
	if ((row = mysql_fetch_row(res)))
		idhostpartition = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
	mysql_free_result(res);

	if (!idhostpartition)
		return OPH_ODB_MYSQL_ERROR;

	n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_CREATE_PARTITION, name);	// Hidden partition name needs to be unique
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_FILL_PARTITION, idhostpartition);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_destroy_hp(ophidiadb * oDB, const char *name)
{
	if (!oDB || !name)
		return OPH_ODB_NULL_PARAM;

#ifndef OPH_DB_SUPPORT

	if (!oDB->dhp)
		return OPH_ODB_NULL_PARAM;

	char command[MYSQL_BUFLEN];
	snprintf(command, MYSQL_BUFLEN, "%s %s", oDB->dhp, name);

	if (system(command))
		return OPH_ODB_MYSQL_ERROR;

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char updateQuery[MYSQL_BUFLEN];

	int n = snprintf(updateQuery, MYSQL_BUFLEN, OPHIDIADB_DESTROY_PARTITION, name);	// Hidden partition name needs to be unique
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, updateQuery))
		return OPH_ODB_MYSQL_ERROR;

#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_reserve_hp(ophidiadb * oDB, const char *name, int id_user, int id_job, int hosts, char type, int *id_hostpartition)
{
	if (!oDB || !name || !id_user || !id_job || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;
	*id_hostpartition = 0;

#ifndef OPH_DB_SUPPORT

	if (!oDB->rshp)
		return OPH_ODB_NULL_PARAM;

	char command[MYSQL_BUFLEN];
	snprintf(command, MYSQL_BUFLEN, "%s %s %d %d %d %d", oDB->rshp, name, id_user, id_job, hosts, type);

	if (system(command))
		return OPH_ODB_MYSQL_ERROR;

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RESERVE_PARTITION, name, id_user, id_job, hosts, type);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	*id_hostpartition = (int) mysql_insert_id(oDB->conn);

#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_release_hp(ophidiadb * oDB, int id_hostpartition)
{
	if (!oDB || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;

#ifndef OPH_DB_SUPPORT

	if (!oDB->rlhp)
		return OPH_ODB_NULL_PARAM;

	char command[MYSQL_BUFLEN];
	snprintf(command, MYSQL_BUFLEN, "%s %d", oDB->rlhp, id_hostpartition);

	if (system(command))
		return OPH_ODB_MYSQL_ERROR;

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RELEASE_HOSTS, id_hostpartition);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RELEASE_PARTITION, id_hostpartition);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_release_hp2(int id_hostpartition)
{
#ifndef OPH_DB_SUPPORT
	return oph_odb_release_hp(NULL, id_hostpartition);
#else
	int result = OPH_ODB_MYSQL_ERROR;
	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (!oph_odb_read_config_ophidiadb(&oDB) && !oph_odb_connect_to_ophidiadb(&oDB))
		result = oph_odb_release_hp(&oDB, id_hostpartition);
	oph_odb_disconnect_from_ophidiadb(&oDB);
	return result;
#endif
}

int oph_odb_retrieve_hp(ophidiadb * oDB, const char *name, int id_user, int *id_hostpartition, int *id_job, char *host_type)
{
	if (!oDB || !name || !id_user || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;
	*id_hostpartition = 0;
	if (id_job)
		*id_job = 0;
	if (*host_type)
		*host_type = 0;

#ifndef OPH_DB_SUPPORT

	if (!oDB->rthp)
		return OPH_ODB_NULL_PARAM;

	unsigned int sequence = 0;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_lock(&global_flag);
	sequence = oph_odb_sequence++;
	pthread_mutex_unlock(&global_flag);
#endif

	char command[MYSQL_BUFLEN], outfile[MYSQL_BUFLEN];
	snprintf(outfile, MYSQL_BUFLEN, OPH_ODB_TEMPORARY_FILE, oph_txt_location, oph_server_port, OPH_SERVER_PREFIX, sequence);
	snprintf(command, MYSQL_BUFLEN, "%s %s %d %s", oDB->rthp, name, id_user, outfile);

	if (system(command)) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}

	char tmp[MYSQL_BUFLEN];
	FILE *file = fopen(outfile, "r");
	if (!file) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}
	*tmp = 0;
	fscanf(file, "%s", tmp);
	if (strcmp(tmp, OPH_NULL_VALUE))
		*id_hostpartition = (int) strtol(tmp, NULL, 10);
	*tmp = 0;
	fscanf(file, "%s", tmp);
	if (id_job && strcmp(tmp, OPH_NULL_VALUE))
		*id_job = (int) strtol(tmp, NULL, 10);
	*tmp = 0;
	fscanf(file, "%s", tmp);
	if (host_type && strcmp(tmp, OPH_NULL_VALUE))
		*host_type = (int) strtol(tmp, NULL, 10);
	fclose(file);
	unlink(outfile);

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RETRIEVE_RESERVED_PARTITION, name, id_user);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if ((mysql_field_count(oDB->conn) != 3) || (mysql_num_rows(res) != 1)) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	while ((row = mysql_fetch_row(res)) != NULL) {
		*id_hostpartition = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
		if (id_job && row[1])
			*id_job = (int) strtol(row[1], NULL, 10);
		if (host_type && row[2])
			*host_type = (int) strtol(row[2], NULL, 10);
	}
	mysql_free_result(res);
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_total_hosts(ophidiadb * oDB, int *thosts)
{
	if (!oDB || !thosts)
		return OPH_ODB_NULL_PARAM;
	*thosts = 0;

#ifndef OPH_DB_SUPPORT

	if (!oDB->gth)
		return OPH_ODB_NULL_PARAM;

	unsigned int sequence = 0;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_lock(&global_flag);
	sequence = oph_odb_sequence++;
	pthread_mutex_unlock(&global_flag);
#endif

	char command[MYSQL_BUFLEN], outfile[MYSQL_BUFLEN];
	snprintf(outfile, MYSQL_BUFLEN, OPH_ODB_TEMPORARY_FILE, oph_txt_location, oph_server_port, OPH_SERVER_PREFIX, sequence);
	snprintf(command, MYSQL_BUFLEN, "%s %s", oDB->gth, outfile);

	if (system(command)) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}

	FILE *file = fopen(outfile, "r");
	if (!file) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}
	fscanf(file, "%d", thosts);

	fclose(file);
	unlink(outfile);

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RETRIEVE_TOTAL_HOSTS);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if ((mysql_field_count(oDB->conn) != 1) || (mysql_num_rows(res) != 1)) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	while ((row = mysql_fetch_row(res)) != NULL) {
		*thosts = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
	}
	mysql_free_result(res);
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_reserved_hosts(ophidiadb * oDB, int id_user, int *rhosts)
{
	if (!oDB || !rhosts)
		return OPH_ODB_NULL_PARAM;
	*rhosts = 0;

#ifndef OPH_DB_SUPPORT

	if (!oDB->grh)
		return OPH_ODB_NULL_PARAM;

	unsigned int sequence = 0;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_lock(&global_flag);
	sequence = oph_odb_sequence++;
	pthread_mutex_unlock(&global_flag);
#endif

	char command[MYSQL_BUFLEN], outfile[MYSQL_BUFLEN];
	snprintf(outfile, MYSQL_BUFLEN, OPH_ODB_TEMPORARY_FILE, oph_txt_location, oph_server_port, OPH_SERVER_PREFIX, sequence);
	snprintf(command, MYSQL_BUFLEN, "%s %d %s", oDB->grh, id_user, outfile);

	if (system(command)) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}

	FILE *file = fopen(outfile, "r");
	if (!file) {
		unlink(outfile);
		return OPH_ODB_MYSQL_ERROR;
	}
	fscanf(file, "%d", rhosts);

	fclose(file);
	unlink(outfile);

#else

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n;
	if (id_user)
		n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RETRIEVE_RESERVED_HOSTS, id_user);
	else
		n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RETRIEVE_TOTAL_RESERVED_HOSTS);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if ((mysql_field_count(oDB->conn) != 1) || (mysql_num_rows(res) != 1)) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	while ((row = mysql_fetch_row(res)) != NULL) {
		*rhosts = (row[0] ? (int) strtol(row[0], NULL, 10) : 0);
	}
	mysql_free_result(res);

#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_user_from_mail(ophidiadb * oDB, const char *mail, char **username, pthread_mutex_t * flag)
{
	if (!oDB || !mail || !username) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_ODB_NULL_PARAM;
	}
	*username = NULL;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to reconnect to OphidiaDB.\n");
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_SELECT_USER_FROM_MAIL, mail);
	if (n >= MYSQL_BUFLEN) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Size of query exceed query limit.\n");
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
#ifdef OPH_DB_SUPPORT
	if (mysql_query(oDB->conn, query)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "MySQL query error: %s\n", mysql_error(oDB->conn));
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) < 1) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		mysql_free_result(res);
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (mysql_num_rows(res) > 1)
		pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "More than one row found by query\n");

	if (mysql_field_count(oDB->conn) != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) != NULL)
		*username = strdup(row[0]);

	mysql_free_result(res);
#else
	oph_sqlite_user res;
	res.user = username;
	res.number_of_rows = 0;
	res.number_of_cols = 0;
	if (sqlite3_exec(oDB->db, query, _oph_odb_get_user_callback, &res, NULL)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "SQLite error while executing query '%s'\n", query);
		return OPH_ODB_MYSQL_ERROR;
	}

	if (res.number_of_rows < 1) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "No row found by query\n");
		return OPH_ODB_NO_ROW_FOUND;
	}

	if (res.number_of_rows > 1)
		pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "More than one row found by query\n");

	if (res.number_of_cols != 1) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Not enough fields found by query\n");
		return OPH_ODB_TOO_MANY_ROWS;
	}
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_user_from_mail2(const char *mail, char **username, pthread_mutex_t * flag)
{
	int result = OPH_ODB_MYSQL_ERROR;
	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (!oph_odb_read_config_ophidiadb(&oDB) && !oph_odb_connect_to_ophidiadb(&oDB))
		result = oph_odb_retrieve_user_from_mail(&oDB, mail, username, flag);
	oph_odb_disconnect_from_ophidiadb(&oDB);
	return result;
}
