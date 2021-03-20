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

#include "oph_ophidiadb_fs_library.h"
#define _GNU_SOURCE

/* Standard C99 headers */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "oph_gather.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_odb_fs_path_parsing(char *inpath, char *cwd, int *folder_id, char **output_path, ophidiadb * oDB)
{

	if (!inpath || !cwd || !folder_id) {
		return OPH_ODB_NULL_PARAM;
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

	*folder_id = 1;

	// cleanup
	for (j = 0; j < list_size; j++) {
		free(list[j]);
	}
	free(list);

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_check_folder_session(int folder_id, char *sessionid, ophidiadb * oDB, int *status)
{
	if (!folder_id || !sessionid || !status) {
		return OPH_ODB_NULL_PARAM;
	}
	*status = 1;

	return OPH_ODB_SUCCESS;
}


int oph_odb_fs_get_session_home_id(char *sessionid, ophidiadb * oDB, int *folder_id)
{
	if (!folder_id || !sessionid) {
		return OPH_ODB_NULL_PARAM;
	}
	*folder_id = 1;

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_build_path(int folder_id, ophidiadb * oDB, char (*out_path)[MYSQL_BUFLEN])
{
	if (!folder_id || !out_path) {
		return OPH_ODB_NULL_PARAM;
	}

	snprintf(*out_path, MYSQL_BUFLEN, OPH_ODB_FS_ROOT "1");

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_retrive_container_folder_id(ophidiadb * oDB, int container_id, int *folder_id)
{
	if (!folder_id || !container_id) {
		return OPH_ODB_NULL_PARAM;
	}
	*folder_id = 1;

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
	if (!name || !folder_id || !answer) {
		return OPH_ODB_NULL_PARAM;
	}
	*answer = 1;

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_is_unique(int folder_id, char *name, ophidiadb * oDB, int *answer)
{
	if (!name || !folder_id || !answer) {
		return OPH_ODB_NULL_PARAM;
	}
	*answer = 1;

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_is_empty_folder(int folder_id, ophidiadb * oDB, int *answer)
{
	if (!folder_id || !answer) {
		return OPH_ODB_NULL_PARAM;
	}
	*answer = 1;

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_update_container_path_name(ophidiadb * oDB, int in_container_id, int out_folder_id, char *out_container_name)
{
	if (!in_container_id || !out_folder_id || !out_container_name) {
		return OPH_ODB_NULL_PARAM;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_find_fs_objects(ophidiadb * oDB, int level, int id_folder, char *container_name, MYSQL_RES ** information_list)
{
	UNUSED(container_name);

	(*information_list) = NULL;

	if (!id_folder) {
		return OPH_ODB_NULL_PARAM;
	}
	if (level > 3) {
		return OPH_ODB_NULL_PARAM;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_fs_get_subfolders(int folder_id, int **subfolder_id, int *num_subfolders, ophidiadb * oDB)
{
	if (!folder_id || !subfolder_id || !num_subfolders) {
		return OPH_ODB_NULL_PARAM;
	}

	if (folder_id == 1) {
		*num_subfolders = 1;
		*subfolder_id = (int *) malloc(*num_subfolders * sizeof(int));
		int i;
		for (i = 0; i < *num_subfolders; ++i)
			(*subfolder_id)[i] = i + 2;
	} else {
		*num_subfolders = 0;
		*subfolder_id = NULL;
	}

	return OPH_ODB_SUCCESS;
}
