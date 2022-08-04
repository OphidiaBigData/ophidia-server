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

#include "oph_ophidiadb_fs_library.h"
#define _GNU_SOURCE

/* Standard C99 headers */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_odb_fs_path_parsing(char *inpath, char *cwd, int *folder_id, char **output_path, ophidiadb * oDB)
{

	if (!oDB || !inpath || !cwd || !folder_id) {
		return OPH_ODB_NULL_PARAM;
	}
	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	if (cwd[0] != '/') {
		return OPH_ODB_ERROR;
	}

	char buffer[MYSQL_BUFLEN];
	char buffer2[MYSQL_BUFLEN];
	int list_size = 0;
	int i, j;


	if (inpath[0] == '/') {
		snprintf(buffer, MYSQL_BUFLEN, "%s", inpath);
		snprintf(buffer2, MYSQL_BUFLEN, "%s", inpath);
	} else {
		snprintf(buffer, MYSQL_BUFLEN, "%s/%s", cwd, inpath);
		snprintf(buffer2, MYSQL_BUFLEN, "%s/%s", cwd, inpath);
	}
	if (!strcmp(buffer, "//")) {
		return OPH_ODB_ERROR;
	}

	char *savepointer = NULL, *ptr2 = strtok_r(buffer2, "/", &savepointer);
	if (ptr2) {
		list_size++;
	} else {
		return OPH_ODB_ERROR;
	}

	while ((ptr2 = strtok_r(NULL, "/", &savepointer)) != NULL)
		list_size++;

	char **list = (char **) malloc(sizeof(char *) * list_size);
	if (!list) {
		return OPH_ODB_MEMORY_ERROR;
	}
	for (i = 0; i < list_size; i++) {
		list[i] = (char *) malloc(MYSQL_BUFLEN);
		if (!list[i]) {
			for (j = 0; j < i; j++) {
				free(list[j]);
			}
			free(list);
			return OPH_ODB_MEMORY_ERROR;
		}
	}

	i = 0;
	char *ptr = strtok_r(buffer, "/", &savepointer);
	if (ptr) {
		if (!strcmp(ptr, ".")) {
			if (!output_path) {
				free(list);
				return OPH_ODB_ERROR;
			}
		} else if (!strcmp(ptr, "..")) {
			if (!output_path) {
				free(list);
				return OPH_ODB_ERROR;
			}
			i--;
			if (i < 0) {
				for (j = 0; j < list_size; j++) {
					free(list[j]);
				}
				free(list);
				return OPH_ODB_ERROR;
			}
		} else {
			snprintf(list[i], MYSQL_BUFLEN, "%s", ptr);
			i++;
		}
	} else {
		for (j = 0; j < list_size; j++) {
			free(list[j]);
		}
		free(list);
		return OPH_ODB_ERROR;
	}

	while ((ptr = strtok_r(NULL, "/", &savepointer)) != NULL) {
		if (!strcmp(ptr, ".")) {
			if (!output_path) {
				free(list);
				return OPH_ODB_ERROR;
			}
		} else if (!strcmp(ptr, "..")) {
			if (!output_path) {
				free(list);
				return OPH_ODB_ERROR;
			}
			i--;
			if (i < 0) {
				for (j = 0; j < list_size; j++) {
					free(list[j]);
				}
				free(list);
				return OPH_ODB_ERROR;
			}
		} else {
			snprintf(list[i], MYSQL_BUFLEN, "%s", ptr);
			i++;
		}
	}

	int n = 0;
	if (output_path) {
		*output_path = (char *) malloc(MYSQL_BUFLEN);
		if (!*output_path) {
			for (j = 0; j < list_size; j++) {
				free(list[j]);
			}
			free(list);
			return OPH_ODB_MEMORY_ERROR;
		}

		n += snprintf((*output_path) + n, MYSQL_BUFLEN, "/");
		for (j = 0; j < i; j++) {
			n += snprintf((*output_path) + n, MYSQL_BUFLEN, "%s/", list[j]);
		}
	}
	char query[MYSQL_BUFLEN];
	MYSQL_RES *res;
	MYSQL_ROW row;
	int num_rows;

	// retrieve root id
	snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_OPH_FS_RETRIEVE_ROOT_ID);
	if (mysql_query(oDB->conn, query)) {
		for (j = 0; j < list_size; j++) {
			free(list[j]);
		}
		free(list);
		if (output_path)
			free(*output_path);
		return OPH_ODB_MYSQL_ERROR;
	}
	res = mysql_store_result(oDB->conn);
	num_rows = mysql_num_rows(res);
	if (num_rows != 1) {
		mysql_free_result(res);
		for (j = 0; j < list_size; j++) {
			free(list[j]);
		}
		free(list);
		if (output_path)
			free(*output_path);
		return OPH_ODB_ERROR;
	}
	row = mysql_fetch_row(res);
	*folder_id = (int) strtol(row[0], NULL, 10);
	mysql_free_result(res);

	// retrieve folder id
	int k;
	for (k = 0; k < i; k++) {
		snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_OPH_FS_PATH_PARSING_ID, *folder_id, list[k]);
		if (mysql_query(oDB->conn, query)) {
			for (j = 0; j < list_size; j++) {
				free(list[j]);
			}
			free(list);
			if (output_path)
				free(*output_path);
			return OPH_ODB_MYSQL_ERROR;
		}
		res = mysql_store_result(oDB->conn);
		num_rows = mysql_num_rows(res);
		if (num_rows != 1) {
			mysql_free_result(res);
			for (j = 0; j < list_size; j++) {
				free(list[j]);
			}
			free(list);
			if (output_path)
				free(*output_path);
			return OPH_ODB_ERROR;
		}
		row = mysql_fetch_row(res);
		*folder_id = (int) strtol(row[0], NULL, 10);
		mysql_free_result(res);
	}

	// cleanup
	for (j = 0; j < list_size; j++) {
		free(list[j]);
	}
	free(list);

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_check_folder_session(int folder_id, char *sessionid, ophidiadb * oDB, int *status)
{
	if (!oDB || !folder_id || !sessionid || !status) {
		return OPH_ODB_NULL_PARAM;
	}

	*status = 0;

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	int session_folder_id;

	//Retrive session home folder id
	if (oph_odb_fs_get_session_home_id(sessionid, oDB, &session_folder_id)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	//If session home is the folder specified than end
	if (session_folder_id == folder_id) {
		*status = 1;
		return OPH_ODB_SUCCESS;
	}
	//Retrive all input parent of this folder
	char query[MYSQL_BUFLEN];
	int n;
	MYSQL_RES *res;
	MYSQL_ROW row;

	int root_flag = 0;
	int internal_folder_id = folder_id;
	int tmp_folder_id = 0;
	while (!root_flag) {
		n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_RETRIEVE_PARENT_FOLDER_ID, internal_folder_id);
		if (n >= MYSQL_BUFLEN) {
			return OPH_ODB_STR_BUFF_OVERFLOW;
		}

		if (mysql_query(oDB->conn, query)) {
			return OPH_ODB_MYSQL_ERROR;
		}

		res = mysql_store_result(oDB->conn);

		if (mysql_num_rows(res) != 1) {
			mysql_free_result(res);
			return OPH_ODB_TOO_MANY_ROWS;
		}

		if (mysql_field_count(oDB->conn) != 1) {
			mysql_free_result(res);
			return OPH_ODB_TOO_MANY_ROWS;
		}

		if ((row = mysql_fetch_row(res)) != NULL) {
			if (row[0]) {
				tmp_folder_id = (int) strtol(row[0], NULL, 10);
				if (tmp_folder_id == session_folder_id) {
					*status = 1;
					mysql_free_result(res);
					break;
				}
				internal_folder_id = tmp_folder_id;
			} else {
				root_flag = 1;
			}
		}
		mysql_free_result(res);
	}

	return OPH_ODB_SUCCESS;
}


int oph_odb_fs_get_session_home_id(char *sessionid, ophidiadb * oDB, int *folder_id)
{
	if (!oDB || !folder_id || !sessionid) {
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	//Retrive session home folder id
	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_RETRIEVE_SESSION_FOLDER_ID, sessionid);
	if (n >= MYSQL_BUFLEN) {
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}

	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) != 1) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if ((row = mysql_fetch_row(res)) != NULL)
		*folder_id = (int) strtol(row[0], NULL, 10);
	mysql_free_result(res);

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_build_path(int folder_id, ophidiadb * oDB, char (*out_path)[MYSQL_BUFLEN])
{
	if (!oDB || !folder_id || !out_path) {
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	int n;
	char query[MYSQL_BUFLEN];

	MYSQL_RES *res;
	MYSQL_ROW row;

	//Retrive all input parent of this folder
	int root_flag = 0;
	int internal_folder_id = folder_id;
	int tmp_folder_id = 0;
	(*out_path)[0] = 0;
	char tmp_out_path[MYSQL_BUFLEN];
	tmp_out_path[0] = 0;
	while (!root_flag) {
		n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_RETRIEVE_PARENT_FOLDER, internal_folder_id);
		if (n >= MYSQL_BUFLEN) {
			return OPH_ODB_STR_BUFF_OVERFLOW;
		}

		if (mysql_query(oDB->conn, query)) {
			return OPH_ODB_MYSQL_ERROR;
		}

		res = mysql_store_result(oDB->conn);

		if (mysql_num_rows(res) != 1) {
			mysql_free_result(res);
			return OPH_ODB_TOO_MANY_ROWS;
		}

		if (mysql_field_count(oDB->conn) != 2) {
			mysql_free_result(res);
			return OPH_ODB_TOO_MANY_ROWS;
		}

		if ((row = mysql_fetch_row(res)) != NULL) {
			if (row[0]) {
				snprintf(*out_path, MYSQL_BUFLEN, "%s/%s", row[1], tmp_out_path);
				snprintf(tmp_out_path, MYSQL_BUFLEN, "%s", *out_path);
				tmp_folder_id = (int) strtol(row[0], NULL, 10);
				internal_folder_id = tmp_folder_id;
			} else {
				root_flag = 1;
			}
		}
		mysql_free_result(res);
	}
	snprintf(*out_path, MYSQL_BUFLEN, OPH_ODB_FS_ROOT "%s", tmp_out_path);

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_retrive_container_folder_id(ophidiadb * oDB, int container_id, int *folder_id)
{
	if (!oDB || !folder_id || !container_id) {
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];
	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_RETRIEVE_CONTAINER_FOLDER_ID, container_id);
	if (n >= MYSQL_BUFLEN) {
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}

	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (mysql_num_rows(res) != 1) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	row = mysql_fetch_row(res);
	*folder_id = (int) strtol(row[0], NULL, 10);

	mysql_free_result(res);
	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_str_last_token(const char *input, char **first_part, char **last_token)
{
	if (!first_part || !input || !last_token)
		return OPH_ODB_NULL_PARAM;

	*first_part = (char *) malloc(MYSQL_BUFLEN);
	if (!*first_part) {
		return OPH_ODB_MEMORY_ERROR;
	}
	*last_token = (char *) malloc(MYSQL_BUFLEN);
	if (!*last_token) {
		free(*first_part);
		return OPH_ODB_MEMORY_ERROR;
	}

	char buffer[MYSQL_BUFLEN];
	char buffer2[MYSQL_BUFLEN];
	snprintf(buffer, MYSQL_BUFLEN, "%s", input);
	snprintf(buffer2, MYSQL_BUFLEN, "%s", input);

	int token_num = 0;
	char *savepointer = NULL, *ptr2 = strtok_r(buffer2, "/", &savepointer);
	if (ptr2) {
		token_num++;
	} else {
		free(*first_part);
		free(*last_token);
		return OPH_ODB_ERROR;
	}

	while ((ptr2 = strtok_r(NULL, "/", &savepointer)) != NULL)
		token_num++;

	char *ptr = strtok_r(buffer, "/", &savepointer);

	if (token_num == 1) {
		if (input[0] == '/') {
			snprintf(*first_part, MYSQL_BUFLEN, "%s", "/");
		} else {
			snprintf(*first_part, MYSQL_BUFLEN, "%s", "");
		}
		snprintf(*last_token, MYSQL_BUFLEN, "%s", ptr);
		return OPH_ODB_SUCCESS;
	}
	int i;
	int n = 0;
	if (input[0] == '/') {
		n += snprintf((*first_part) + n, MYSQL_BUFLEN, "%s", "/");
	}
	for (i = 0; i < token_num; i++) {
		if (i != (token_num - 1)) {
			n += snprintf((*first_part) + n, MYSQL_BUFLEN, "%s/", ptr);
			ptr = strtok_r(NULL, "/", &savepointer);
		} else {
			snprintf(*last_token, MYSQL_BUFLEN, "%s", ptr);
		}
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_is_visible_container(int folder_id, char *name, ophidiadb * oDB, int *answer)
{
	if (!oDB || !name || !folder_id || !answer) {
		return OPH_ODB_NULL_PARAM;
	}
	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];
	MYSQL_RES *res;
	int num_rows;

	snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_OPH_FS_IS_VISIBLE_CONTAINER, folder_id, name);
	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	res = mysql_store_result(oDB->conn);
	num_rows = mysql_num_rows(res);
	if (num_rows == 0) {
		*answer = 0;
		mysql_free_result(res);
	} else if (num_rows == 1) {
		*answer = 1;
		mysql_free_result(res);
	} else {
		mysql_free_result(res);
		return OPH_ODB_ERROR;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_is_unique(int folder_id, char *name, ophidiadb * oDB, int *answer)
{
	if (!oDB || !name || !folder_id || !answer) {
		return OPH_ODB_NULL_PARAM;
	}
	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];
	MYSQL_RES *res;
	int num_rows;

	snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_OPH_FS_UNIQUENESS, folder_id, name, folder_id, name);
	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	res = mysql_store_result(oDB->conn);
	num_rows = mysql_num_rows(res);
	if (num_rows == 0) {
		*answer = 1;
		mysql_free_result(res);
	} else {
		*answer = 0;
		mysql_free_result(res);
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_is_empty_folder(int folder_id, ophidiadb * oDB, int *answer)
{
	if (!oDB || !folder_id || !answer) {
		return OPH_ODB_NULL_PARAM;
	}
	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];
	MYSQL_RES *res;
	int num_rows;

	snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_OPH_FS_EMPTINESS, folder_id, folder_id);
	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	res = mysql_store_result(oDB->conn);
	num_rows = mysql_num_rows(res);
	if (num_rows == 0) {
		*answer = 1;
		mysql_free_result(res);
	} else {
		*answer = 0;
		mysql_free_result(res);
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_update_container_path_name(ophidiadb * oDB, int in_container_id, int out_folder_id, char *out_container_name)
{
	if (!oDB || !in_container_id || !out_folder_id || !out_container_name) {
		return OPH_ODB_NULL_PARAM;
	}
	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	char query[MYSQL_BUFLEN];
	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_MV, out_folder_id, out_container_name, in_container_id);
	if (n >= MYSQL_BUFLEN) {
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_find_fs_objects(ophidiadb * oDB, int level, int id_folder, char *container_name, MYSQL_RES ** information_list)
{
	(*information_list) = NULL;

	if (!oDB || !id_folder) {
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	if (level > 3) {
		return OPH_ODB_NULL_PARAM;
	}

	char query[MYSQL_BUFLEN];
	int n;
	char where_clause[MYSQL_BUFLEN];

	if (level < 1)
		container_name = NULL;

	if (container_name)
		snprintf(where_clause, MYSQL_BUFLEN, "AND containername = '%s'", container_name);
	else
		where_clause[0] = 0;

	switch (level) {
		case 0:
			n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_LIST_0, id_folder);
			break;
		case 1:
			if (container_name)
				n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_LIST_1_WC, id_folder, container_name);
			else
				n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_LIST_1, id_folder, id_folder);
			break;
		case 2:
			if (container_name)
				n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_LIST_2_WC, id_folder, container_name);
			else
				n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_LIST_2, id_folder, id_folder);
			break;
		default:
			return OPH_ODB_NULL_PARAM;
	}
	if (n >= MYSQL_BUFLEN) {
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}
	//Execute query
	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	// Init res 
	*information_list = mysql_store_result(oDB->conn);

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_get_subfolders(int folder_id, int **subfolder_id, int *num_subfolders, ophidiadb * oDB)
{
	if (!oDB || !folder_id || !subfolder_id || !num_subfolders) {
		return OPH_ODB_NULL_PARAM;
	}

	if (oph_odb_check_connection_to_ophidiadb(oDB)) {
		return OPH_ODB_MYSQL_ERROR;
	}
	//Retrive user home folder id
	char query[MYSQL_BUFLEN];

	int n = snprintf(query, MYSQL_BUFLEN, MYSQL_QUERY_FS_RETRIEVE_SUB_FOLDER_ID, folder_id);
	if (n >= MYSQL_BUFLEN) {
		return OPH_ODB_STR_BUFF_OVERFLOW;
	}

	if (mysql_query(oDB->conn, query)) {
		return OPH_ODB_MYSQL_ERROR;
	}

	MYSQL_RES *res;
	MYSQL_ROW row;
	res = mysql_store_result(oDB->conn);

	if (!(*num_subfolders = mysql_num_rows(res))) {
		mysql_free_result(res);
		return OPH_ODB_SUCCESS;
	}

	if (mysql_field_count(oDB->conn) != 1) {
		mysql_free_result(res);
		return OPH_ODB_TOO_MANY_ROWS;
	}

	*subfolder_id = (int *) malloc((*num_subfolders) * sizeof(int));
	if (!(*subfolder_id)) {
		mysql_free_result(res);
		return OPH_ODB_MEMORY_ERROR;
	}

	n = 0;
	while ((row = mysql_fetch_row(res)) != NULL)
		(*subfolder_id)[n++] = (int) strtol(row[0], NULL, 10);

	mysql_free_result(res);

	return OPH_ODB_SUCCESS;
}
