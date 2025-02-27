/*
    Ophidia Server
    Copyright (C) 2012-2024 CMCC Foundation

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

extern char *oph_server_location;
extern ophidiadb *ophDB;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_odb_read_config_ophidiadb(ophidiadb *oDB)
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
				} else {
					break;
				}
			}

			/* Remove trailing newline */
			if (line[strlen(line) - 1] == '\n')
				line[strlen(line) - 1] = '\0';

			/* Skip comment lines */
			if (line[0] == '#') {
				continue;
			}

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
			} else {
				free(argument_value);
			}

			free(argument);
		}

		fclose(file);

		ophDB->conn = 0;
	}

	if (oDB) {
		oDB->name = ophDB->name;
		oDB->hostname = ophDB->hostname;
		oDB->server_port = ophDB->server_port;
		oDB->username = ophDB->username;
		oDB->pwd = ophDB->pwd;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_initialize_ophidiadb(ophidiadb *oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	oDB->name = NULL;
	oDB->hostname = NULL;
	oDB->username = NULL;
	oDB->pwd = NULL;
	oDB->conn = NULL;

	return OPH_ODB_SUCCESS;
}

int oph_odb_free_ophidiadb(ophidiadb *oDB)
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
	if (oDB->conn) {
		oph_odb_disconnect_from_ophidiadb(oDB);
		oDB->conn = NULL;
	}

	free(oDB);

	return OPH_ODB_SUCCESS;
}

int oph_odb_connect_to_ophidiadb(ophidiadb *oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

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

	return OPH_ODB_SUCCESS;
}

int oph_odb_check_connection_to_ophidiadb(ophidiadb *oDB)
{
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
	return OPH_ODB_SUCCESS;
}

int oph_odb_disconnect_from_ophidiadb(ophidiadb *oDB)
{
	if (!oDB) {
		return OPH_ODB_NULL_PARAM;
	}

	if (oDB->conn) {
		mysql_close(oDB->conn);
		oDB->conn = NULL;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_ids(ophidiadb *oDB, const char *command, int **id, char ***ctime, int *nn)
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

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_list(ophidiadb *oDB, const char *command, ophidiadb_list *list)
{
	if (!oDB || !command || !list)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, "%s", command);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

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
		list->name = list->ctime = list->max_status = NULL;
		list->id = list->pid = list->wid = NULL;
		mysql_free_result(res);
		return OPH_ODB_SUCCESS;
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
		list->ctime[j] = row[1] ? strndup(row[1], OPH_MAX_STRING_SIZE) : NULL;
		list->name[j] = row[2] ? strndup(row[2], OPH_MAX_STRING_SIZE) : NULL;
		if ((mysql_field_count(oDB->conn) > 3) && row[3])
			list->wid[j] = (int) strtol(row[3], NULL, 10);
		else
			list->wid[j] = 0;
		if ((mysql_field_count(oDB->conn) > 4) && row[4])
			list->pid[j] = (int) strtol(row[4], NULL, 10);
		else
			list->pid[j] = 0;
		if ((mysql_field_count(oDB->conn) > 5) && row[5])
			list->max_status[j] = strndup(row[5], OPH_MAX_STRING_SIZE);
		else
			list->max_status[j] = NULL;
		j++;
	}
	mysql_free_result(res);

	return OPH_ODB_SUCCESS;
}

int oph_odb_initialize_ophidiadb_list(ophidiadb_list *list)
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

int oph_odb_free_ophidiadb_list(ophidiadb_list *list)
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

int oph_odb_extract_datacube_ids(ophidiadb *oDB, char *query, cube **datacube, int *counter)
{
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
	return OPH_ODB_SUCCESS;
}

int oph_odb_insert_user(ophidiadb *oDB, const char *username)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_INSERT_USER, username);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	return OPH_ODB_SUCCESS;
}

int oph_odb_insert_user2(ophidiadb *oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts)
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

		snprintf(tmp, MYSQL_BUFLEN, "%d", idcountry);
	} else
		snprintf(tmp, MYSQL_BUFLEN, OPH_NULL_VALUE);

	n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_INSERT_USER2, username, password, name ? "'" : "", name ? name : OPH_NULL_VALUE, name ? "'" : "", surname ? "'" : "",
		     surname ? surname : OPH_NULL_VALUE, surname ? "'" : "", email ? "'" : "", email ? email : OPH_NULL_VALUE, email ? "'" : "", tmp, max_hosts > 0 ? max_hosts : 0);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	return OPH_ODB_SUCCESS;
}

int oph_odb_delete_user(ophidiadb *oDB, const char *username)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, MYSQL_QUERY_DELETE_USER, username);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	return OPH_ODB_SUCCESS;
}

int oph_odb_update_user(ophidiadb *oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char updateQuery[MYSQL_BUFLEN];
	int n;

	if (password) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER2, "password", password, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
	}
	if (name) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "name", name, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
	}
	if (surname) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "surname", surname, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
	}
	if (email) {
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "mail", email, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
	}
	if (country) {
		int idcountry = 0;

		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_SELECT_COUNTRY, country);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

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

		char tmp[MYSQL_BUFLEN];
		snprintf(tmp, MYSQL_BUFLEN, "%d", idcountry);
		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "idcountry", tmp, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
	}
	if (max_hosts >= 0) {
		char tmp[MYSQL_BUFLEN];
		snprintf(tmp, MYSQL_BUFLEN, "%d", max_hosts);

		n = snprintf(updateQuery, MYSQL_BUFLEN, MYSQL_QUERY_UPDATE_USER, "maxhosts", tmp, username);
		if (n >= MYSQL_BUFLEN)
			return OPH_ODB_STR_BUFF_OVERFLOW;

		if (mysql_query(oDB->conn, updateQuery))
			return OPH_ODB_MYSQL_ERROR;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_create_hp(ophidiadb *oDB, const char *name, const char *parent, int id_user)
{
	if (!oDB || !name || !parent || !id_user)
		return OPH_ODB_NULL_PARAM;

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

	return OPH_ODB_SUCCESS;
}

int oph_odb_destroy_hp(ophidiadb *oDB, const char *name)
{
	if (!oDB || !name)
		return OPH_ODB_NULL_PARAM;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char updateQuery[MYSQL_BUFLEN];

	int n = snprintf(updateQuery, MYSQL_BUFLEN, OPHIDIADB_DESTROY_PARTITION, name);	// Hidden partition name needs to be unique
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, updateQuery))
		return OPH_ODB_MYSQL_ERROR;

	return OPH_ODB_SUCCESS;
}

int oph_odb_reserve_hp(ophidiadb *oDB, const char *name, int id_user, int id_job, int hosts, char type, int *id_hostpartition)
{
	if (!oDB || !name || !id_user || !id_job || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;
	*id_hostpartition = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB))
		return OPH_ODB_MYSQL_ERROR;

	char insertQuery[MYSQL_BUFLEN];
	int n = snprintf(insertQuery, MYSQL_BUFLEN, OPHIDIADB_RESERVE_PARTITION, name, id_user, id_job, hosts, type);
	if (n >= MYSQL_BUFLEN)
		return OPH_ODB_STR_BUFF_OVERFLOW;

	if (mysql_query(oDB->conn, insertQuery))
		return OPH_ODB_MYSQL_ERROR;

	*id_hostpartition = (int) mysql_insert_id(oDB->conn);

	return OPH_ODB_SUCCESS;
}

int oph_odb_release_hp(ophidiadb *oDB, int id_hostpartition)
{
	if (!oDB || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;

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

	return OPH_ODB_SUCCESS;
}

int oph_odb_release_hp2(int id_hostpartition)
{
	int result = OPH_ODB_MYSQL_ERROR;
	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (!oph_odb_read_config_ophidiadb(&oDB) && !oph_odb_connect_to_ophidiadb(&oDB))
		result = oph_odb_release_hp(&oDB, id_hostpartition);
	oph_odb_disconnect_from_ophidiadb(&oDB);
	return result;
}

int oph_odb_retrieve_hp(ophidiadb *oDB, const char *name, int id_user, int *id_hostpartition, int *id_job, char *host_type)
{
	if (!oDB || !name || !id_user || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;
	*id_hostpartition = 0;
	if (id_job)
		*id_job = 0;
	if (*host_type)
		*host_type = 0;

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

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_total_hosts(ophidiadb *oDB, int *thosts)
{
	if (!oDB || !thosts)
		return OPH_ODB_NULL_PARAM;
	*thosts = 0;

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

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_reserved_hosts(ophidiadb *oDB, int id_user, int *rhosts)
{
	if (!oDB || !rhosts)
		return OPH_ODB_NULL_PARAM;
	*rhosts = 0;

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

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_user_from_mail(ophidiadb *oDB, const char *mail, char **username, pthread_mutex_t *flag)
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

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_user_from_mail2(const char *mail, char **username, pthread_mutex_t *flag)
{
	int result = OPH_ODB_MYSQL_ERROR;
	ophidiadb oDB;
	oph_odb_initialize_ophidiadb(&oDB);
	if (!oph_odb_read_config_ophidiadb(&oDB) && !oph_odb_connect_to_ophidiadb(&oDB))
		result = oph_odb_retrieve_user_from_mail(&oDB, mail, username, flag);
	oph_odb_disconnect_from_ophidiadb(&oDB);
	return result;
}
