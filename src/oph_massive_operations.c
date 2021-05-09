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

#include "oph_massive_operations.h"

#include "oph_ophidiadb.h"
#include "oph_parser.h"
#include "oph_task_parser_library.h"
#include "oph_filters.h"
#include "oph_odb_job.h"
#include "oph_rmanager.h"
#include "oph_json_library.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>

#define OPH_MF_LS_COMMAND "operator=oph_list;level=9;%scwd=%s;sessionid=%s;workflowid=%d;markerid=%d;taskindex=%d;lighttaskindex=-1;username=%s;userid=%d;userrole=%d;parentid=%d;"
#define OPH_MF_LS_GRID_CLASS "grid"
#define OPH_MF_LS_GRID_NAME "list"
#define OPH_MF_LS_GRID_OBJECT "DATACUBE PID"

#define OPH_MF_FS_COMMAND "operator=oph_fs;command=ls;realpath=yes;%s%s%s%scdd=%s;sessionid=%s;workflowid=%d;markerid=%d;taskindex=%d;lighttaskindex=-1;username=%s;userid=%d;userrole=%d;parentid=%d;"
#define OPH_MF_FS_GRID_CLASS "grid"
#define OPH_MF_FS_GRID_NAME "fs"
#define OPH_MF_FS_GRID_TYPE "T"
#define OPH_MF_FS_GRID_OBJECT "OBJECT"
#define OPH_MF_TYPE_FILE "f"

extern char *oph_web_server;
extern char *oph_base_src_path;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_cond_t waiting_flag;
#endif

void freeBlock(char ***block, unsigned int count)
{
	if (block && *block) {
		unsigned int i;
		for (i = 0; i < count; ++i)
			if ((*block)[i])
				free((*block)[i]);
		free(*block);
		*block = NULL;
	}
}

int _oph_mf_parse_KV(struct oph_plugin_data *state, oph_workflow * wf, int task_index, char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *task_string, char *cwd, char *cdd,
		     char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **_query, pthread_mutex_t * flag)
{
	if (!task_string || !datacube_inputs || !measure_name || !counter || !sessionid || !running || !oDB)
		return OPH_SERVER_NULL_POINTER;
	*datacube_inputs = *measure_name = NULL;
	*counter = 0;
	*running = 1;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "%s=%c%s%c\n", is_src_path ? OPH_ARG_SRC_PATH : OPH_ARG_CUBE, OPH_SEPARATOR_SUBPARAM_OPEN, task_string, OPH_SEPARATOR_SUBPARAM_CLOSE);

	HASHTBL *task_tbl = NULL;
	unsigned int task_string_size = strlen(task_string) + OPH_SHORT_STRING_SIZE;	// Additional size is provided to consider OPH_MF_ARG_PATH or OPH_MF_ARG_DATACUBE_FILTER
	char tmp[task_string_size + 1], filter = 1;

	// No filter set
	if (!strchr(task_string, OPH_SEPARATOR_KV[0])) {
		char stop = 1;
		unsigned int i, j;
		for (i = j = 0; stop && (i < task_string_size) && (j < task_string_size); j++) {
			if (task_string[j] == OPH_SEPARATOR_PARAM[0])
				stop = 0;
			else if (task_string[j] != OPH_SEPARATOR_NULL)
				tmp[i++] = task_string[j];
		}
		tmp[i] = 0;
		if (!stop)	// Skip beyond OPH_SEPARATOR_PARAM[0]
			task_string[j] = 0;
		if (!is_src_path) {	// In case of datacube filter, check for '*' and 'all'
			switch (strlen(tmp)) {
				case 0:
					break;
				case 1:
					if (tmp[0] == '*')
						filter = 0;
					break;
				case 3:
					if (!strcasecmp(tmp, "all"))
						filter = 0;
					break;
				default:
					pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Consider '%s' as a path or subset string of cube ids.\n", task_string);
			}
		}
		if (filter)	// By default all the task string is a path in case of src_path or a list of identifiers in case of datacube
		{
			char tmp2[strlen(tmp) + 1];
			int not_clause = tmp[0] == OPH_MF_SYMBOL_NOT[0] ? 1 : 0;
			if (not_clause) {
				strcpy(tmp2, tmp);
				task_string = tmp2;
			}
			snprintf(tmp, task_string_size, "%s%s=%s", is_src_path ? OPH_MF_ARG_PATH : OPH_MF_ARG_DATACUBE_FILTER, not_clause ? OPH_MF_SYMBOL_NOT : "", task_string + not_clause);
			task_string = tmp;
			pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Add option '%s' to task string\n", tmp);
		}
	}

	if (oph_tp_task_params_parser(OPH_MASSIVE_OPERATOR, filter ? task_string : NULL, &task_tbl)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to process input parameters\n");
		if (task_tbl)
			hashtbl_destroy(task_tbl);
		return OPH_SERVER_ERROR;
	}
	// Filtering
#ifdef OPH_DB_SUPPORT
	char query[OPH_MAX_STRING_SIZE];
	if (!is_src_path) {
		if (oph_filter_unsafe(task_tbl, query, cwd ? cwd : OPH_MF_ROOT_FOLDER, sessionid, oDB)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to create filtering query.\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Filtering query: %s\n", query);
	}
#else
	char *query = NULL;
#endif

	char *running_value = task_tbl ? hashtbl_get(task_tbl, OPH_MF_ARG_RUN) : NULL;
	if (running_value && !strncasecmp(running_value, OPH_MF_ARG_VALUE_NO, OPH_MAX_STRING_SIZE))
		*running = 0;

	unsigned int i;
	cube *datacube = NULL;
	char **filenames = NULL;
	if (is_src_path)	// In case of src_path only the parameter OPH_MF_ARG_PATH is considered
	{
		char _path[PATH_MAX], _path2[PATH_MAX];
		char *path = hashtbl_get(task_tbl, OPH_MF_ARG_PATH);
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Raw path to files for massive operation: %s\n", path ? path : "(null)");
		while (path && (*path == ' '))
			path++;
		if (!path) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to parse '%s'.\n", task_string);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_ERROR;
		}
		if (strstr(path, "..")) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "The use of '..' in '%s' is forbidden.\n", path);
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_ERROR;
		}
		if (cdd && (*path != OPH_MF_ROOT_FOLDER[0])) {
			if (*cdd != OPH_MF_ROOT_FOLDER[0]) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Parameter '%s' must begin with '/'.\n", OPH_ARG_CDD);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				return OPH_SERVER_ERROR;
			}
			if (strlen(cdd) > 1) {
				if (strstr(cdd, "..")) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "The use of '..' in '%s' is forbidden.\n", OPH_ARG_CDD);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					return OPH_SERVER_ERROR;
				}
				snprintf(_path2, PATH_MAX, "%s/%s", cdd + 1, path);
				path = _path2;
			}
		}
		if (oph_base_src_path && strlen(oph_base_src_path)) {
			snprintf(_path, PATH_MAX, "%s%s%s", oph_base_src_path, *path != OPH_MF_ROOT_FOLDER[0] ? OPH_MF_ROOT_FOLDER : "", path);
			path = _path;
		}

		char dpath[OPH_MAX_STRING_SIZE];
		*dpath = 0;
		if (hashtbl_get(task_tbl, OPH_MF_ARG_PATH) && strlen(hashtbl_get(task_tbl, OPH_MF_ARG_PATH)))
			snprintf(dpath, OPH_MAX_STRING_SIZE, "dpath=%s;", (char *) hashtbl_get(task_tbl, OPH_MF_ARG_PATH));
		char file[OPH_MAX_STRING_SIZE];
		*file = 0;
		if (hashtbl_get(task_tbl, OPH_MF_ARG_FILE) && strlen(hashtbl_get(task_tbl, OPH_MF_ARG_FILE)))
			snprintf(file, OPH_MAX_STRING_SIZE, "file=%s;", (char *) hashtbl_get(task_tbl, OPH_MF_ARG_FILE));
		char recursive[OPH_MAX_STRING_SIZE];
		*recursive = 0;
		if (hashtbl_get(task_tbl, OPH_MF_ARG_RECURSIVE))
			snprintf(recursive, OPH_MAX_STRING_SIZE, "recursive=%s;", (char *) hashtbl_get(task_tbl, OPH_MF_ARG_RECURSIVE));
		char depth[OPH_MAX_STRING_SIZE];
		*depth = 0;
		if (hashtbl_get(task_tbl, OPH_MF_ARG_DEPTH))
			snprintf(depth, OPH_MAX_STRING_SIZE, "depth=%s;", (char *) hashtbl_get(task_tbl, OPH_MF_ARG_DEPTH));
		char command[OPH_MAX_STRING_SIZE];
		snprintf(command, OPH_MAX_STRING_SIZE, OPH_MF_FS_COMMAND "" OPH_SERVER_REQUEST_FLAG, dpath, file, recursive, depth, cdd, sessionid, wf->workflowid, wf->tasks[task_index].markerid,
			 task_index, wf->username, wf->iduser, wf->userrole, wf->idjob);
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Command to scan file system: %s\n", command);

		char markerid[OPH_SHORT_STRING_SIZE];
		snprintf(markerid, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].markerid);

		char *sessionid = strdup(wf->sessionid);
		char *os_username = strdup(wf->os_username);
		char *project = wf->project ? strdup(wf->project) : NULL;

		int response = 0, _odb_wf_id = wf->idjob, _task_id = task_index, wid = wf->workflowid;

		if (!flag)
			pthread_mutex_unlock(&global_flag);
		response = oph_serve_request(command, 1, sessionid, markerid, "", state, &_odb_wf_id, &_task_id, NULL, NULL, 0, NULL, NULL, NULL, NULL, os_username, project, wid);
		if (!flag)
			pthread_mutex_lock(&global_flag);

		if (sessionid)
			free(sessionid);
		if (os_username)
			free(os_username);
		if (project)
			free(project);

		if (response) {
			pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to scan file system\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_ERROR;
		}

		while (!flag && !wf->tasks[task_index].response) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Waiting for scanning report\n");
			pthread_cond_wait(&waiting_flag, &global_flag);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "A file scanning report is arrived\n");
		}

		if (wf->tasks[task_index].response && !strlen(wf->tasks[task_index].response)) {
			free(wf->tasks[task_index].response);
			wf->tasks[task_index].response = NULL;
		}

		unsigned int j;
		oph_json *oper_json = NULL;
		oph_json_obj_grid *grid_json = NULL;
		while (wf->tasks[task_index].response) {
			if (oph_json_from_json_string(&oper_json, wf->tasks[task_index].response)) {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Error in parsing JSON Response\n");
				break;
			}
			for (i = 0; i < oper_json->responseKeyset_num; ++i)
				if (!strcmp(oper_json->responseKeyset[i], OPH_MF_FS_GRID_NAME))
					break;
			if ((i >= oper_json->responseKeyset_num) || (i >= oper_json->response_num) || strcmp(oper_json->response[i].objclass, OPH_MF_FS_GRID_CLASS)
			    || strcmp(oper_json->response[i].objkey, OPH_MF_FS_GRID_NAME)) {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Grid '%s' not found in JSON Response\n", OPH_MF_FS_GRID_NAME);
				break;
			}
			grid_json = (oph_json_obj_grid *) oper_json->response[i].objcontent;
			if ((grid_json->keys_num != 2) || (grid_json->values_num2 != 2) || strcmp(grid_json->keys[0], OPH_MF_FS_GRID_TYPE) || strcmp(grid_json->keys[1], OPH_MF_FS_GRID_OBJECT)) {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Grid '%s' is not correct in JSON Response\n", OPH_MF_FS_GRID_NAME);
				break;
			}
			for (j = 0; j < grid_json->values_num1; ++j)
				if (!strcmp(grid_json->values[j][0], OPH_MF_TYPE_FILE) && grid_json->values[j][1])
					++ * counter;
			if (*counter) {
				filenames = (char **) calloc(*counter, sizeof(char *));
				for (i = j = 0; j < grid_json->values_num1; ++j)
					if (!strcmp(grid_json->values[j][0], OPH_MF_TYPE_FILE) && grid_json->values[j][1])
						filenames[i++] = strdup(grid_json->values[j][1]);
			}
			break;
		}
		oph_json_free(oper_json);

	} else {

#ifdef OPH_DB_SUPPORT
		if (oph_odb_extract_datacube_ids(oDB, query, &datacube, (int *) counter)) {
			pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Unable to extract datacube PIDs.\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			if (datacube)
				free(datacube);
			return OPH_SERVER_NO_RESPONSE;
		}
#else
		size_t len = strlen(task_string);
		if (len && (task_string[len - 1] == OPH_SEPARATOR_PARAM[0]))
			task_string[len - 1] = 0;

		char cube_filter[OPH_MAX_STRING_SIZE];
		snprintf(cube_filter, OPH_MAX_STRING_SIZE, "%s=%c%s%c;", OPH_MF_ARG_DATACUBE_FILTER, OPH_SEPARATOR_SUBPARAM_OPEN, task_string, OPH_SEPARATOR_SUBPARAM_CLOSE);

		char command[OPH_MAX_STRING_SIZE];
		snprintf(command, OPH_MAX_STRING_SIZE, OPH_MF_LS_COMMAND "" OPH_SERVER_REQUEST_FLAG, cube_filter, cwd ? cwd : OPH_MF_ROOT_FOLDER, sessionid, wf->workflowid,
			 wf->tasks[task_index].markerid, task_index, wf->username, wf->iduser, wf->userrole, wf->idjob);
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Command to scan virtual file system: %s\n", command);

		char markerid[OPH_SHORT_STRING_SIZE];
		snprintf(markerid, OPH_SHORT_STRING_SIZE, "%d", wf->tasks[task_index].markerid);

		char *sessionid = strdup(wf->sessionid);
		char *os_username = strdup(wf->os_username);
		char *project = wf->project ? strdup(wf->project) : NULL;

		int response = 0, _odb_wf_id = wf->idjob, _task_id = task_index, wid = wf->workflowid;

		if (!flag)
			pthread_mutex_unlock(&global_flag);
		response = oph_serve_request(command, 1, sessionid, markerid, "", state, &_odb_wf_id, &_task_id, NULL, NULL, 0, NULL, NULL, NULL, NULL, os_username, project, wid);
		if (!flag)
			pthread_mutex_lock(&global_flag);

		if (sessionid)
			free(sessionid);
		if (os_username)
			free(os_username);
		if (project)
			free(project);

		if (response) {
			pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to scan virtual file system\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_ERROR;
		}

		while (!flag && !wf->tasks[task_index].response) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Waiting for scanning report\n");
			pthread_cond_wait(&waiting_flag, &global_flag);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "A file scanning report is arrived\n");
		}

		if (wf->tasks[task_index].response && !strlen(wf->tasks[task_index].response)) {
			free(wf->tasks[task_index].response);
			wf->tasks[task_index].response = NULL;
		}

		unsigned int j;
		oph_json *oper_json = NULL;
		oph_json_obj_grid *grid_json = NULL;
		while (wf->tasks[task_index].response) {
			if (oph_json_from_json_string(&oper_json, wf->tasks[task_index].response)) {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Error in parsing JSON Response\n");
				break;
			}
			for (i = 0; i < oper_json->responseKeyset_num; ++i)
				if (!strcmp(oper_json->responseKeyset[i], OPH_MF_LS_GRID_NAME))
					break;
			if ((i >= oper_json->responseKeyset_num) || (i >= oper_json->response_num) || strcmp(oper_json->response[i].objclass, OPH_MF_LS_GRID_CLASS)
			    || strcmp(oper_json->response[i].objkey, OPH_MF_LS_GRID_NAME)) {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Grid '%s' not found in JSON Response\n", OPH_MF_LS_GRID_NAME);
				break;
			}
			grid_json = (oph_json_obj_grid *) oper_json->response[i].objcontent;
			if ((grid_json->keys_num != 1) || (grid_json->values_num2 != 1) || strcmp(grid_json->keys[0], OPH_MF_LS_GRID_OBJECT)) {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Grid '%s' is not correct in JSON Response\n", OPH_MF_LS_GRID_NAME);
				break;
			}
			*counter = grid_json->values_num1;
			if (*counter) {
				filenames = (char **) calloc(*counter, sizeof(char *));	// Datacube PIDs
				for (i = 0; i < grid_json->values_num1; ++i)
					filenames[i] = strdup(grid_json->values[i][0]);
			}
			query = wf->tasks[task_index].query;
			break;
		}
		oph_json_free(oper_json);
#endif
		if (_query && query) {
			if (*_query) {
				char tquery[2 + strlen(*_query) + strlen(query)];
				sprintf(tquery, "%s|%s", *_query, query);
				free(*_query);
				*_query = strdup(tquery);
			} else
				*_query = strdup(query);
		}
	}

	char convention[OPH_MAX_STRING_SIZE];
	convention[0] = 0;
	if ((running_value = task_tbl ? hashtbl_get(task_tbl, OPH_MF_ARG_CONVENTION) : NULL))
		strncat(convention, running_value, OPH_MAX_STRING_SIZE - 1);

	if (task_tbl)
		hashtbl_destroy(task_tbl);

	// Outputing
	if (!(*counter)) {
		pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "No object found.\n");
		if (datacube)
			free(datacube);
		return OPH_SERVER_NO_RESPONSE;
	}
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Found %d implicit objects which the massive operation will be applied on\n", *counter);

	char *base_name, *measure;
	*datacube_inputs = (char **) malloc((*counter) * sizeof(char *));
	if (is_src_path) {
		if (strncasecmp(convention, OPH_MF_ARG_VALUE_NO, OPH_MAX_STRING_SIZE)) {
			*measure_name = (char **) malloc((*counter) * sizeof(char *));
			memset(*measure_name, 0, (*counter) * sizeof(char *));
		}
	}
	for (i = 0; i < *counter; ++i) {

#ifdef OPH_DB_SUPPORT
		if (!is_src_path)
			snprintf(query, OPH_MAX_STRING_SIZE, "%s/%d/%d", oph_web_server, datacube[i].id_container, datacube[i].id_datacube);
		else
			snprintf(query, OPH_MAX_STRING_SIZE, "%s", filenames[i]);
#else
		query = filenames[i];
#endif
		(*datacube_inputs)[i] = strdup(query);
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Object name: %s\n", (*datacube_inputs)[i]);

		if (is_src_path)	// Check for file convention
		{
			if (!strncasecmp(convention, OPH_MF_ARG_VALUE_CMIP5, OPH_MAX_STRING_SIZE))	// CMIP5 convention
			{
				base_name = basename(query);
				if (base_name) {
					measure = strchr(base_name, '_');
					if (measure)
						*measure = 0;	// Truncate file name to variable name only, which is the first word until the first occurrence of '_'
					(*measure_name)[i] = strdup(base_name);
				} else
					(*measure_name)[i] = 0;
				pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Measure name: %s\n", (*measure_name)[i]);
			}
			//else other conventions
		}
	}

	if (datacube)
		free(datacube);
	if (filenames) {
		for (i = 0; i < *counter; ++i)
			if (filenames[i])
				free(filenames[i]);
		free(filenames);
	}

	return OPH_SERVER_OK;
}

int _oph_mf_parse_query(struct oph_plugin_data *state, oph_workflow * workflow, int task_index, char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input, char *cwd,
			char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query, pthread_mutex_t * flag)
{
	if (!datacube_input || !datacube_inputs || !measure_name || !counter || !sessionid || !running || !oDB)
		return OPH_SERVER_NULL_POINTER;
	*datacube_inputs = *measure_name = NULL;
	*counter = 0;
	*running = -1;

	char **datacube_inputs_ = NULL, **measure_name_ = NULL;
	char **tmp1, **tmp2;

	int result, running_;
	unsigned int i, j, counter_, datacube_input_size = (unsigned int) strlen(datacube_input);
	char *task_string, *end_task, *last_char, tmp[1 + datacube_input_size], *_datacube_input, _task_string[1 + datacube_input_size];

	// Copy while skipping spaces in parameter name
	result = 0;
	for (i = j = 0; i <= datacube_input_size; ++i) {
		if (datacube_input[i] == OPH_SEPARATOR_BASIC[0])
			result = 0;
		else if (datacube_input[i] == OPH_SEPARATOR_KV[0])
			result = 1;
		if (result || (datacube_input[i] != OPH_SEPARATOR_NULL))
			tmp[j++] = datacube_input[i];
	}

	result = OPH_SERVER_OK;
	_datacube_input = tmp;
	while (_datacube_input && ((task_string = strchr(_datacube_input, OPH_SEPARATOR_SUBPARAM_OPEN)))) {
		task_string++;
		if (!(end_task = strchr(task_string, OPH_SEPARATOR_SUBPARAM_CLOSE))) {
			freeBlock(datacube_inputs, *counter);
			freeBlock(measure_name, *counter);
			freeBlock(&datacube_inputs_, counter_);
			freeBlock(&measure_name_, counter_);
			*counter = 0;
			return OPH_SERVER_ERROR;
		}
		_datacube_input = end_task + 1;
		*end_task = OPH_SEPARATOR_PARAM[0];
		while (task_string != end_task) {
			last_char = end_task - 1;
			if (*last_char == OPH_SEPARATOR_PARAM[0]) {
				*end_task = 0;
				end_task = last_char;
			} else
				break;
		}
		snprintf(_task_string, end_task - task_string + 2, "%s", task_string);
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Extract '%s'\n", _task_string);
		if ((result = _oph_mf_parse_KV(state, workflow, task_index, &datacube_inputs_, &measure_name_, &counter_, _task_string, cwd, cdd, sessionid, &running_, is_src_path, oDB, query, flag))) {
			if (result != OPH_SERVER_NO_RESPONSE) {
				freeBlock(datacube_inputs, *counter);
				freeBlock(measure_name, *counter);
				freeBlock(&datacube_inputs_, counter_);
				freeBlock(&measure_name_, counter_);
				*counter = 0;
				return result;
			}
			counter_ = 0;
		}
		if (counter_ > 0) {
			if (*counter) {
				if (*running != running_) {
					pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Error in using parameter 'running'\n");
					freeBlock(datacube_inputs, *counter);
					freeBlock(measure_name, *counter);
					freeBlock(&datacube_inputs_, counter_);
					freeBlock(&measure_name_, counter_);
					*counter = 0;
					return OPH_SERVER_ERROR;
				}

				tmp1 = *datacube_inputs;
				tmp2 = *measure_name;
				*datacube_inputs = (char **) malloc((*counter + counter_) * sizeof(char *));
				if (tmp2)
					*measure_name = (char **) malloc((*counter + counter_) * sizeof(char *));
				for (i = 0; i < *counter; ++i) {
					(*datacube_inputs)[i] = tmp1[i];
					if (tmp2)
						(*measure_name)[i] = tmp2[i];
				}
				for (j = 0; j < counter_; ++j, ++i) {
					(*datacube_inputs)[i] = datacube_inputs_[j];
					if (tmp2 && measure_name_)
						(*measure_name)[i] = measure_name_[j];
				}

				free(tmp1);
				if (tmp2)
					free(tmp2);
				free(datacube_inputs_);
				datacube_inputs_ = NULL;
				if (measure_name_) {
					free(measure_name_);
					measure_name_ = NULL;
				}
			} else {
				*datacube_inputs = datacube_inputs_;
				*measure_name = measure_name_;
				*running = running_;
			}
			*counter += counter_;
		}
	}

	// Check for pipes
	char bracket = 0;
	for (i = 0; i < datacube_input_size; ++i)
		if (!bracket) {
			if (datacube_input[i] == OPH_SEPARATOR_SUBPARAM)
				break;
			else if (datacube_input[i] == OPH_SEPARATOR_SUBPARAM_OPEN)
				bracket = 1;
		} else if (datacube_input[i] == OPH_SEPARATOR_SUBPARAM_CLOSE)
			bracket = 0;
	if (i == datacube_input_size)
		return result;

	// Copy while skipping spaces in parameter name
	result = 0;
	for (i = j = 0; i <= datacube_input_size; ++i) {
		if (datacube_input[i] == OPH_SEPARATOR_BASIC[0])
			result = 0;
		else if (datacube_input[i] == OPH_SEPARATOR_KV[0])
			result = 1;
		if (result || (datacube_input[i] != OPH_SEPARATOR_NULL))
			tmp[j++] = datacube_input[i];
	}

	_datacube_input = tmp;
	end_task = strchr(tmp, OPH_SEPARATOR_SUBPARAM_OPEN);
	if (end_task && !strchr(end_task, OPH_SEPARATOR_SUBPARAM_CLOSE)) {
		freeBlock(datacube_inputs, *counter);
		freeBlock(measure_name, *counter);
		*counter = 0;
		return OPH_SERVER_ERROR;
	}
	while (end_task) {
		if (*end_task == OPH_SEPARATOR_SUBPARAM)
			*end_task = OPH_SEPARATOR_NULL;
		if (*end_task == OPH_SEPARATOR_SUBPARAM_CLOSE)
			end_task = strchr(end_task, OPH_SEPARATOR_SUBPARAM_OPEN);
		else
			end_task++;
	}

	counter_ = i = 0;
	task_string = strchr(_datacube_input, OPH_SEPARATOR_SUBPARAM);
	end_task = strchr(_datacube_input, OPH_SEPARATOR_SUBPARAM_OPEN);
	if (!end_task || (task_string && (end_task > task_string)))
		counter_++;
	while (task_string) {
		end_task = strchr(task_string, OPH_SEPARATOR_SUBPARAM_OPEN);
		task_string = strchr(task_string + 1, OPH_SEPARATOR_SUBPARAM);
		if (!end_task || (task_string && (end_task > task_string)))
			counter_++;
	}
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Found %d explicit objects which the massive operation will be applied on\n", counter_);

	if (*counter) {
		tmp1 = *datacube_inputs;
		tmp2 = *measure_name;
		*datacube_inputs = (char **) malloc((*counter + counter_) * sizeof(char *));
		if (tmp2)
			*measure_name = (char **) malloc((*counter + counter_) * sizeof(char *));
		for (i = 0; i < *counter; ++i) {
			(*datacube_inputs)[i] = tmp1[i];
			if (tmp2)
				(*measure_name)[i] = tmp2[i];
		}
		free(tmp1);
		if (tmp2)
			free(tmp2);
	} else
		*datacube_inputs = (char **) malloc(counter_ * sizeof(char *));
	*counter += counter_;

	char *next_cube = strchr(task_string = _datacube_input, OPH_SEPARATOR_SUBPARAM);
	for (j = 0; j < counter_; ++j, ++i) {
		while (1) {
			end_task = strchr(task_string, OPH_SEPARATOR_SUBPARAM_OPEN);
			if (end_task && (!next_cube || (end_task < next_cube))) {
				if (next_cube) {
					task_string = ++next_cube;
					next_cube = strchr(next_cube, OPH_SEPARATOR_SUBPARAM);
				} else {
					pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Error in counting.\n", *counter);
					freeBlock(datacube_inputs, *counter);
					freeBlock(measure_name, *counter);
					*counter = 0;
					return OPH_SERVER_ERROR;
				}
				continue;
			}
			break;
		}
		(*datacube_inputs)[i] = strndup(task_string, strlen(task_string) - (next_cube ? strlen(next_cube) : 0));
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Object name: %s\n", (*datacube_inputs)[i]);
		if (next_cube) {
			task_string = ++next_cube;
			next_cube = strchr(next_cube, OPH_SEPARATOR_SUBPARAM);
		}
	}

	return OPH_SERVER_OK;
}

int oph_mf_parse_query(struct oph_plugin_data *state, oph_workflow * workflow, int task_index, char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input, char *cwd,
		       char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query)
{
	return _oph_mf_parse_query(state, workflow, task_index, datacube_inputs, measure_name, counter, datacube_input, cwd, cdd, sessionid, running, is_src_path, oDB, query, &global_flag);
}

int oph_mf_parse_query_unsafe(struct oph_plugin_data *state, oph_workflow * workflow, int task_index, char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input,
			      char *cwd, char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query)
{
	return _oph_mf_parse_query(state, workflow, task_index, datacube_inputs, measure_name, counter, datacube_input, cwd, cdd, sessionid, running, is_src_path, oDB, query, NULL);
}
