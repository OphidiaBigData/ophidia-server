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

#define _GNU_SOURCE

#include "oph_massive_operations.h"

#include "oph_ophidiadb.h"
#include "oph_parser.h"
#include "oph_task_parser_library.h"
#include "oph_filters.h"
#include "oph_odb_job.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <glob.h>
#include <libgen.h>

extern char *oph_web_server;
extern char *oph_base_src_path;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
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

int openDir(const char *path, int recursive, unsigned int *counter, char **buffer, char *file, pthread_mutex_t * flag)
{
	if (!path || !counter || !buffer)
		return OPH_SERVER_NULL_POINTER;

	DIR *dirp = opendir(path);
	if (!dirp)
		return OPH_SERVER_WRONG_PARAMETER_ERROR;

	struct dirent *entry = NULL, save_entry;
	char *sub;
	int s;

	if (recursive < 0)
		recursive++;

	if (file) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Search in directory '%s' using pattern '%s'\n", path, file);
		glob_t globbuf;
		char *path_and_file = NULL;
		s = asprintf(&path_and_file, "%s/%s", path, file);
		if (!path_and_file) {
			closedir(dirp);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if ((s = glob(path_and_file, GLOB_MARK | GLOB_NOSORT, NULL, &globbuf))) {
			if (s != GLOB_NOMATCH) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to parse '%s'\n", path_and_file);
				free(path_and_file);
				closedir(dirp);
				return OPH_SERVER_SYSTEM_ERROR;
			} else {
				pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "No object found.\n");
				if (!recursive) {
					free(path_and_file);
					closedir(dirp);
					return OPH_SERVER_OK;
				}
			}
		}
		free(path_and_file);
		*counter += globbuf.gl_pathc;
		unsigned int i;
		for (i = 0; i < globbuf.gl_pathc; ++i) {
			if (globbuf.gl_pathv[i][strlen(globbuf.gl_pathv[i]) - 1] == '/')	// Skip the subfolder
			{
				(*counter)--;
				continue;
			}
			if (*buffer) {
				sub = *buffer;
				s = asprintf(buffer, "%s%s%s", sub, globbuf.gl_pathv[i], OPH_SEPARATOR_PARAM);
				free(sub);
			} else
				s = asprintf(buffer, "%s%s", globbuf.gl_pathv[i], OPH_SEPARATOR_PARAM);
		}
		globfree(&globbuf);
	} else
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Search in directory '%s'\n", path);

	char full_filename[OPH_MAX_STRING_SIZE];
	struct stat file_stat;

	int result;
	while (!readdir_r(dirp, &save_entry, &entry) && entry) {
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
			snprintf(full_filename, OPH_MAX_STRING_SIZE, "%s/%s", path, entry->d_name);
			lstat(full_filename, &file_stat);
			if (!file && S_ISREG(file_stat.st_mode)) {
				pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Found file '%s'\n", entry->d_name);
				(*counter)++;
				if (*buffer) {
					sub = *buffer;
					s = asprintf(buffer, "%s%s/%s%s", sub, path, entry->d_name, OPH_SEPARATOR_PARAM);
					free(sub);
				} else
					s = asprintf(buffer, "%s/%s%s", path, entry->d_name, OPH_SEPARATOR_PARAM);
			} else if (recursive && S_ISDIR(file_stat.st_mode)) {
				sub = NULL;
				s = asprintf(&sub, "%s/%s", path, entry->d_name);
				if (!sub)
					result = OPH_SERVER_SYSTEM_ERROR;
				else {
					result = openDir(sub, recursive, counter, buffer, file, flag);
					free(sub);
				}
				if (result) {
					closedir(dirp);
					return result;
				}
			}
		}
	}
	closedir(dirp);

	return OPH_SERVER_OK;
}

int _oph_mf_parse_KV(char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *task_string, char *cwd, char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **_query, pthread_mutex_t * flag)
{
	if (!task_string || !datacube_inputs || !measure_name || !counter || !sessionid || !running || !oDB)
		return OPH_SERVER_NULL_POINTER;
	*datacube_inputs = *measure_name = NULL;
	*counter = 0;
	*running = 1;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "%s=%c%s%c\n", is_src_path ? OPH_ARG_SRC_PATH : OPH_ARG_CUBE, OPH_SEPARATOR_SUBPARAM_OPEN, task_string, OPH_SEPARATOR_SUBPARAM_CLOSE);

	// Check XML
	HASHTBL *task_tbl = NULL;
	char tmp[OPH_MAX_STRING_SIZE], filter = 1;
	if (!strchr(task_string, OPH_SEPARATOR_KV[0])) {
		// Check for 'all'
		if (!is_src_path) {
			unsigned int i, j;
			for (i = j = 0; (i < OPH_MAX_STRING_SIZE) && (j < strlen(task_string)); j++)
				if ((task_string[j] != OPH_SEPARATOR_NULL) && (task_string[j] != OPH_SEPARATOR_PARAM[0]))
					tmp[i++] = task_string[j];
			tmp[i] = 0;
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
			snprintf(tmp, OPH_MAX_STRING_SIZE, "%s=%s", is_src_path ? OPH_MF_ARG_PATH : OPH_MF_ARG_DATACUBE_FILTER, task_string);
			task_string = tmp;
			pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Add option '%s' to task string\n", tmp);
		}
	}

	if (oph_tp_task_params_parser(OPH_MASSIVE_OPERATOR, filter ? task_string : "", &task_tbl)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to process input parameters\n");
		if (task_tbl)
			hashtbl_destroy(task_tbl);
		return OPH_SERVER_ERROR;
	}
	// Filtering
	char query[OPH_MAX_STRING_SIZE];
	if (!is_src_path) {
		if (oph_filter_unsafe(task_tbl, query, cwd, sessionid, oDB)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to create filtering query.\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Filtering query: %s\n", query);
		if (_query) {
			if (*_query) {
				char tquery[2 + strlen(*_query) + strlen(query)];
				sprintf(tquery, "%s|%s", *_query, query);
				free(*_query);
				*_query = strdup(tquery);
			} else
				*_query = strdup(query);
		}
	}

	char *running_value = task_tbl ? hashtbl_get(task_tbl, OPH_MF_ARG_RUN) : NULL;
	if (running_value && !strncasecmp(running_value, OPH_MF_ARG_VALUE_NO, OPH_MAX_STRING_SIZE))
		*running = 0;

	char *tbuffer = NULL, *pbuffer;

	unsigned int i;
	cube *datacube = NULL;
	if (is_src_path)	// In case of src_path only the parameter OPH_MF_ARG_PATH is considered
	{
		char _path[PATH_MAX], _path2[PATH_MAX];
		char *path = hashtbl_get(task_tbl, OPH_MF_ARG_PATH);
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
		if (*path != OPH_MF_ROOT_FOLDER[0]) {
			if (!cdd) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Missing input parameter '%s'.\n", OPH_ARG_CDD);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				return OPH_SERVER_ERROR;
			}
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
					return OPH_SERVER_ERROR;;
				}
				snprintf(_path2, PATH_MAX, "%s/%s", cdd + 1, path);
				path = _path2;
			}
		}
		if (oph_base_src_path && strlen(oph_base_src_path)) {
			snprintf(_path, PATH_MAX, "%s%s%s", oph_base_src_path, *path != OPH_MF_ROOT_FOLDER[0] ? OPH_MF_ROOT_FOLDER : "", path);
			path = _path;
		}
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Path to files for massive operation: %s.\n", path);

		int recursive = 0;
		running_value = hashtbl_get(task_tbl, OPH_MF_ARG_RECURSIVE);
		if (running_value && strncasecmp(running_value, OPH_MF_ARG_VALUE_NO, OPH_MAX_STRING_SIZE)) {
			recursive = 1;
			if ((running_value = hashtbl_get(task_tbl, OPH_MF_ARG_DEPTH))) {
				int rdepth = (int) strtol(running_value, NULL, 10);
				if (rdepth > 0)
					recursive = -rdepth;
			}
		}

		char real_path[PATH_MAX];
		if (strchr(path, '*') || strchr(path, '~') || strchr(path, '{') || strchr(path, '}'))	// Use glob
		{
			pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Use glob to parse expression '%s'\n", path);
			if (recursive) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Recursive option cannot be selected for '%s'\n", path);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			int s;
			glob_t globbuf;
			if ((s = glob(path, GLOB_MARK | GLOB_NOSORT | GLOB_TILDE_CHECK | GLOB_BRACE, NULL, &globbuf))) {
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				if (s != GLOB_NOMATCH) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to parse '%s'\n", path);
					return OPH_SERVER_SYSTEM_ERROR;
				} else {
					pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "No object found.\n");
					return OPH_SERVER_NO_RESPONSE;
				}
			}
			*counter = globbuf.gl_pathc;
			for (i = 0; i < globbuf.gl_pathc; ++i) {
				if (globbuf.gl_pathv[i][strlen(globbuf.gl_pathv[i]) - 1] == '/')	// Skip the subfolder
				{
					(*counter)--;
					continue;
				}
				if (!realpath(globbuf.gl_pathv[i], real_path)) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong path name '%s'\n", globbuf.gl_pathv[i]);
					if (task_tbl)
						hashtbl_destroy(task_tbl);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (tbuffer) {
					pbuffer = tbuffer;
					s = asprintf(&tbuffer, "%s%s%s", pbuffer, real_path, OPH_SEPARATOR_PARAM);
					free(pbuffer);
				} else
					s = asprintf(&tbuffer, "%s%s", real_path, OPH_SEPARATOR_PARAM);
			}
			globfree(&globbuf);
		} else {
			if (!realpath(path, real_path)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong path name '%s'\n", path);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				return OPH_SERVER_ERROR;
			}

			char *arg_file = hashtbl_get(task_tbl, OPH_MF_ARG_FILE);
			if (openDir(real_path, recursive, counter, &tbuffer, arg_file && strlen(arg_file) ? arg_file : 0, flag)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to open '%s'.\n", path);
				if (task_tbl)
					hashtbl_destroy(task_tbl);
				return OPH_SERVER_SYSTEM_ERROR;
			}
		}
	} else {
		if (oph_odb_extract_datacube_ids(oDB, query, &datacube, (int *) counter)) {
			pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Unable to extract datacube PIDs.\n");
			if (task_tbl)
				hashtbl_destroy(task_tbl);
			if (datacube)
				free(datacube);
			return OPH_SERVER_NO_RESPONSE;
		}
	}

	char convention[OPH_MAX_STRING_SIZE];
	convention[0] = 0;
	if ((running_value = task_tbl ? hashtbl_get(task_tbl, OPH_MF_ARG_CONVENTION) : NULL))
		strncat(convention, running_value, OPH_MAX_STRING_SIZE - 1);

	if (task_tbl)
		hashtbl_destroy(task_tbl);

	int lbuffer = 0;
	if (tbuffer)
		lbuffer = strlen(tbuffer);
	char buffer[1 + lbuffer];
	if (tbuffer) {
		strcpy(buffer, tbuffer);
		free(tbuffer);
	} else
		*buffer = 0;

	// Outputing
	if (!(*counter)) {
		pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "No object found.\n");
		if (datacube)
			free(datacube);
		return OPH_SERVER_NO_RESPONSE;
	}
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Found %d implicit objects which the massive operation will be applied on\n", *counter);

	size_t base_src_size = 0;
	if (is_src_path && oph_base_src_path)
		base_src_size = strlen(oph_base_src_path);

	char *base_name, *measure, *savepointer = NULL;
	*datacube_inputs = (char **) malloc((*counter) * sizeof(char *));
	if (is_src_path) {
		if (strncasecmp(convention, OPH_MF_ARG_VALUE_NO, OPH_MAX_STRING_SIZE)) {
			*measure_name = (char **) malloc((*counter) * sizeof(char *));
			memset(*measure_name, 0, (*counter) * sizeof(char *));
		}
		running_value = strtok_r(buffer, OPH_SEPARATOR_PARAM, &savepointer);
	}
	for (i = 0; i < *counter; ++i) {
		if (is_src_path) {
			snprintf(query, OPH_MAX_STRING_SIZE, "%s", running_value + base_src_size);
			running_value = strtok_r(NULL, OPH_SEPARATOR_PARAM, &savepointer);
		} else
			snprintf(query, OPH_MAX_STRING_SIZE, "%s/%d/%d", oph_web_server, datacube[i].id_container, datacube[i].id_datacube);
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

	return OPH_SERVER_OK;
}

int _oph_mf_parse_query(char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input, char *cwd, char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query, pthread_mutex_t * flag)
{
	if (!datacube_input || !datacube_inputs || !measure_name || !counter || !sessionid || !running || !oDB)
		return OPH_SERVER_NULL_POINTER;
	*datacube_inputs = *measure_name = NULL;
	*counter = 0;
	*running = -1;

	char **datacube_inputs_ = NULL, **measure_name_ = NULL;
	char **tmp1, **tmp2;

	int result, running_;
	unsigned int i, j, counter_;
	char *task_string, *end_task, *last_char, tmp[1 + strlen(datacube_input)], *_datacube_input, _task_string[1 + strlen(datacube_input)];

	// Copy while skipping spaces in parameter name
	result = 0;
	for (i = j = 0; i <= strlen(datacube_input); ++i) {
		if (datacube_input[i] == OPH_SEPARATOR_BASIC[0])
			result = 0;
		if (datacube_input[i] == OPH_SEPARATOR_KV[0])
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
		if ((result = _oph_mf_parse_KV(&datacube_inputs_, &measure_name_, &counter_, _task_string, cwd ? cwd : OPH_MF_ROOT_FOLDER, cdd ? cdd : OPH_MF_ROOT_FOLDER, sessionid, &running_, is_src_path, oDB, query, flag))) {
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
	if (!strchr(datacube_input, OPH_SEPARATOR_SUBPARAM))
		return result;

	// Copy while skipping spaces in parameter name
	result = 0;
	for (i = j = 0; i <= strlen(datacube_input); ++i) {
		if (datacube_input[i] == OPH_SEPARATOR_BASIC[0])
			result = 0;
		if (datacube_input[i] == OPH_SEPARATOR_KV[0])
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

int oph_mf_parse_query(char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input, char *cwd, char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query)
{
	return _oph_mf_parse_query(datacube_inputs, measure_name, counter, datacube_input, cwd, cdd, sessionid, running, is_src_path, oDB, query, &global_flag);
}

int oph_mf_parse_query_unsafe(char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input, char *cwd, char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query)
{
	return _oph_mf_parse_query(datacube_inputs, measure_name, counter, datacube_input, cwd, cdd, sessionid, running, is_src_path, oDB, query, NULL);
}
