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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/time.h>

/* Jansson header to manipulate JSONs */
#include <jansson.h>

#include "oph_workflow_functions.h"
#include "oph_workflow_define.h"
#include "oph_parser.h"

#define OPH_GLOBAL_VARS "Global variables"

extern unsigned int oph_base_backoff;
extern char oph_direct_output;

/* Alloc oph_workflow struct */
int _oph_workflow_alloc(oph_workflow ** workflow);
/* Add key and value to list of arguments for each task not yet comprising that key */
int _oph_workflow_substitute_var(char *key, char *value, oph_workflow_task * tasks, int tasks_num);
/* Add cube to list of arguments for each task with no explicit cube argument and with none or embedded-only deps */
int _oph_workflow_substitute_cube(char *pid, oph_workflow_task * tasks, int tasks_num);
int _oph_workflow_add_to_json(json_t * oph_json, const char *name, const char *value);
/* Skip comments from input JSON file */
int _oph_workflow_skip_comments(const char *json_string, char **clean_json_string);

int oph_workflow_load(char *json_string, const char *username, const char *ip_address, oph_workflow ** workflow)
{
	if (!json_string || !username || !workflow) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	*workflow = NULL;

	//alloc and init
	if (_oph_workflow_alloc(workflow)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "_oph_workflow_alloc error\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	//add username
	(*workflow)->username = (char *) strdup((const char *) username);
	if (!((*workflow)->username)) {
		oph_workflow_free(*workflow);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating username\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (ip_address) {
		//add ip_address
		(*workflow)->ip_address = (char *) strdup((const char *) ip_address);
	}
	// Skip comments
	char *clean_json_string = NULL;
	if (_oph_workflow_skip_comments(json_string, &clean_json_string) || !clean_json_string) {
		oph_workflow_free(*workflow);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "comments are not set correctly\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	//load json_t from json_string
	json_t *jansson = json_loads((const char *) clean_json_string, 0, NULL);
	if (!jansson) {
		free(clean_json_string);
		oph_workflow_free(*workflow);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "json_loads error\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	free(clean_json_string);

	//unpack global vars
	char *name = NULL, *author = NULL, *abstract = NULL, *sessionid = NULL, *exec_mode = NULL, *ncores = NULL, *cwd = NULL, *cdd = NULL, *cube = NULL, *callback_url = NULL, *on_error =
	    NULL, *command = NULL, *on_exit = NULL, *run = NULL, *output_format = NULL, *host_partition = NULL, *url = NULL, *nhosts = NULL, *nthreads = NULL, *project = NULL, *save =
	    NULL, *checkpoint = NULL, *direct_output = NULL;
	json_unpack(jansson, "{s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s}", "name", &name, "author", &author, "abstract", &abstract, "sessionid",
		    &sessionid, "exec_mode", &exec_mode, "ncores", &ncores, "cwd", &cwd, "cdd", &cdd, "cube", &cube, "callback_url", &callback_url, "on_error", &on_error, "command", &command,
		    "on_exit", &on_exit, "run", &run, "output_format", &output_format, "host_partition", &host_partition, "url", &url, "nhost", &nhosts, "nthreads", &nthreads, "project", &project,
		    "save", &save, "checkpoint", &checkpoint, "direct_output", &direct_output);

	//add global vars
	if (!name) {
		oph_workflow_free(*workflow);
		if (jansson)
			json_decref(jansson);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "invalid json\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	(*workflow)->name = (char *) strdup((const char *) name);
	if (!((*workflow)->name)) {
		oph_workflow_free(*workflow);
		if (jansson)
			json_decref(jansson);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating name\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (author && strlen(author)) {
		(*workflow)->author = (char *) strdup((const char *) author);
		if (!((*workflow)->author)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating author\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (abstract && strlen(abstract)) {
		(*workflow)->abstract = (char *) strdup((const char *) abstract);
		if (!((*workflow)->abstract)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating abstract\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (url && strlen(url)) {
		(*workflow)->url = (char *) strdup((const char *) url);
		if (!((*workflow)->url)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating sessionid\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (sessionid && strlen(sessionid)) {
		(*workflow)->sessionid = (char *) strdup((const char *) sessionid);
		if (!((*workflow)->sessionid)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating sessionid\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (exec_mode && strlen(exec_mode)) {
		(*workflow)->exec_mode = (char *) strdup((const char *) exec_mode);
		if (!((*workflow)->exec_mode)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating exec_mode\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (ncores)
		(*workflow)->ncores = (int) strtol((const char *) ncores, NULL, 10);
	if (nhosts)
		(*workflow)->nhosts = (int) strtol((const char *) nhosts, NULL, 10);
	if (nthreads)
		(*workflow)->nthreads = (int) strtol((const char *) nthreads, NULL, 10);
	if (project && strlen(project)) {
		(*workflow)->project = (char *) strdup((const char *) project);
		if (!((*workflow)->project)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating project\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (cwd && strlen(cwd)) {
		(*workflow)->cwd = (char *) strdup((const char *) cwd);
		if (!((*workflow)->cwd)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating cwd\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (cdd && strlen(cdd)) {
		(*workflow)->cdd = (char *) strdup((const char *) cdd);
		if (!((*workflow)->cdd)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating cdd\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (cube && strlen(cube)) {
		(*workflow)->cube = (char *) strdup((const char *) cube);
		if (!((*workflow)->cube)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating cube\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (callback_url && strlen(callback_url)) {
		(*workflow)->callback_url = (char *) strdup((const char *) callback_url);
		if (!((*workflow)->callback_url)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating callback_url\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (command && strlen(command)) {
		(*workflow)->command = (char *) strdup((const char *) command);
		if (!((*workflow)->command)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating command\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (on_error && strlen(on_error)) {
		(*workflow)->on_error = (char *) strdup((const char *) on_error);
		if (!((*workflow)->on_error)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating on_error\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (on_exit && strlen(on_exit)) {
		(*workflow)->on_exit = (char *) strdup((const char *) on_exit);
		if (!((*workflow)->on_exit)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating on_exit\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (checkpoint && strlen(checkpoint)) {
		if (!strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_NO) || !strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_ALL) || !strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_LAST)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'checkpoint': value '%s' is not allowed\n", checkpoint);
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		(*workflow)->checkpoint = (char *) strdup((const char *) checkpoint);
		if (!((*workflow)->checkpoint)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating checkpoint\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	(*workflow)->run = 1;	// Default value (yes)
	if (run && strlen(run)) {
		if (!strcmp(run, OPH_WORKFLOW_NO))
			(*workflow)->run = 0;
		else if (strcmp(run, OPH_WORKFLOW_YES)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'run'\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}
	(*workflow)->save = 1;	// Default value (yes)
	if (save && strlen(save)) {
		if (!strcmp(save, OPH_WORKFLOW_NO))
			(*workflow)->save = 0;
		else if (strcmp(save, OPH_WORKFLOW_YES)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'save'\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}
	(*workflow)->output_format = 0;
	if (output_format && strlen(output_format)) {
		if (!strcmp(output_format, OPH_WORKFLOW_COMPACT))
			(*workflow)->output_format = 1;
		else if (strcmp(output_format, OPH_WORKFLOW_CLASSIC)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'output_format'\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}
	(*workflow)->direct_output = oph_direct_output;
	if (direct_output && strlen(direct_output)) {
		if (!strcmp(direct_output, OPH_WORKFLOW_NO))
			(*workflow)->direct_output = 0;
		else if (!strcmp(direct_output, OPH_WORKFLOW_YES))
			(*workflow)->direct_output = 1;
		else {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'direct_output'\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	if (host_partition && strlen(host_partition)) {
		(*workflow)->host_partition = (char *) strdup((const char *) host_partition);
		if (!((*workflow)->host_partition)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating host_partition\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	//unpack tasks
	json_t *tasks = NULL;
	json_unpack(jansson, "{s?o}", "tasks", &tasks);
	if (!tasks) {
		oph_workflow_free(*workflow);
		if (jansson)
			json_decref(jansson);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error extracting tasks\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	//add tasks
	(*workflow)->tasks_num = (int) json_array_size(tasks);
	(*workflow)->residual_tasks_num = (*workflow)->tasks_num;
	if ((*workflow)->tasks_num < 1) {
		oph_workflow_free(*workflow);
		if (jansson)
			json_decref(jansson);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "tasks_num must be >= 1\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	(*workflow)->tasks = (oph_workflow_task *) calloc((*workflow)->tasks_num + 1, sizeof(oph_workflow_task));	// '1+' stand for the "final task"
	if (!((*workflow)->tasks)) {
		(*workflow)->tasks_num = 0;
		(*workflow)->residual_tasks_num = (*workflow)->tasks_num;
		oph_workflow_free(*workflow);
		if (jansson)
			json_decref(jansson);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating tasks\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	// Create hash-table for run-time environment
	(*workflow)->vars = hashtbl_create((*workflow)->tasks_num, NULL);
	json_t *task = NULL;
	int i, j;
	for (i = 0; i < (*workflow)->tasks_num; i++) {
		task = json_array_get(tasks, i);
		if (!task) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error extracting task\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
		//unpack name and operator
		char *name = NULL, *operator= NULL, *on_error_task = NULL, *on_exit_task = NULL, *run_task = NULL, *save_task = NULL, *type = NULL, *checkpoint = NULL;
		json_unpack(task, "{s?s,s?s,s?s,s?s,s?s,s?s,s?s,s?s}", "name", &name, "operator", &operator, "on_error", &on_error_task, "on_exit", &on_exit_task, "run", &run_task, "save", &save_task,
			    "type", &type, "checkpoint", &checkpoint);

		//add name and operator
		if (!name || !operator) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "null task name and/or operator\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		(*workflow)->tasks[i].name = (char *) strdup((const char *) name);
		if (!((*workflow)->tasks[i].name)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task name\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		(*workflow)->tasks[i].operator =(char *) strdup((const char *) operator);
		if (!((*workflow)->tasks[i].operator)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task operator\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		if (type) {
			if (strcmp(type, OPH_TYPE_OPHIDIA) && strcmp(type, OPH_TYPE_CDO) && strcmp(type, OPH_TYPE_GENERIC) && strcmp(type, OPH_TYPE_CONTROL)) {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error setting task: type not allowed\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
			(*workflow)->tasks[i].type = (char *) strdup((const char *) type);
			if (!strcmp(type, OPH_TYPE_CONTROL)) {
				char tmp[5 + strlen((*workflow)->tasks[i].operator)];
				sprintf(tmp, "oph_%s", (*workflow)->tasks[i].operator);
				if (strcmp(tmp, OPH_OPERATOR_FOR) && strcmp(tmp, OPH_OPERATOR_ENDFOR) && strcmp(tmp, OPH_OPERATOR_IF) && strcmp(tmp, OPH_OPERATOR_ELSEIF)
				    && strcmp(tmp, OPH_OPERATOR_ELSE) && strcmp(tmp, OPH_OPERATOR_ENDIF) && strcmp(tmp, OPH_OPERATOR_WAIT) && strcmp(tmp, OPH_OPERATOR_SET)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error setting task: operation '%s' not allowed\n", (*workflow)->tasks[i].operator);
					oph_workflow_free(*workflow);
					if (jansson)
						json_decref(jansson);
					return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
				}
			}
		} else
			(*workflow)->tasks[i].type = (char *) strdup(OPH_TYPE_OPHIDIA);
		if (!((*workflow)->tasks[i].type)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task operator\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		//unpack arguments
		json_t *arguments = NULL;
		json_unpack(task, "{s?o}", "arguments", &arguments);
		if (arguments) {
			(*workflow)->tasks[i].arguments_num = (int) json_array_size(arguments);
			if ((*workflow)->tasks[i].arguments_num >= 1) {
				(*workflow)->tasks[i].arguments_keys = (char **) calloc((*workflow)->tasks[i].arguments_num, sizeof(char *));
				if (!((*workflow)->tasks[i].arguments_keys)) {
					(*workflow)->tasks[i].arguments_num = 0;
					oph_workflow_free(*workflow);
					if (jansson)
						json_decref(jansson);
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task arg keys\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				(*workflow)->tasks[i].arguments_values = (char **) calloc((*workflow)->tasks[i].arguments_num, sizeof(char *));
				if (!((*workflow)->tasks[i].arguments_values)) {
					(*workflow)->tasks[i].arguments_num = 0;
					free((*workflow)->tasks[i].arguments_keys);
					(*workflow)->tasks[i].arguments_keys = NULL;
					oph_workflow_free(*workflow);
					if (jansson)
						json_decref(jansson);
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task arg values\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				(*workflow)->tasks[i].arguments_lists = (oph_workflow_ordered_list **) calloc((*workflow)->tasks[i].arguments_num, sizeof(oph_workflow_ordered_list *));
				if (!((*workflow)->tasks[i].arguments_lists)) {
					(*workflow)->tasks[i].arguments_num = 0;
					free((*workflow)->tasks[i].arguments_keys);
					(*workflow)->tasks[i].arguments_keys = NULL;
					free((*workflow)->tasks[i].arguments_values);
					(*workflow)->tasks[i].arguments_values = NULL;
					oph_workflow_free(*workflow);
					if (jansson)
						json_decref(jansson);
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task arg values\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				for (j = 0; j < (*workflow)->tasks[i].arguments_num; j++) {
					(*workflow)->tasks[i].arguments_lists[j] = NULL;
					char *argument = NULL;
					json_unpack(json_array_get(arguments, j), "s", &argument);
					if (argument) {
						unsigned int k;
						int ok = 0;
						for (k = 0; k < strlen(argument); k++) {
							if (argument[k] == '=') {
								(*workflow)->tasks[i].arguments_keys[j] = (char *) strndup(argument, k);
								if (!((*workflow)->tasks[i].arguments_keys[j])) {
									oph_workflow_free(*workflow);
									if (jansson)
										json_decref(jansson);
									pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task arg key\n");
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								}
								(*workflow)->tasks[i].arguments_values[j] = (char *) strdup(argument + k + 1);
								if (!((*workflow)->tasks[i].arguments_values[j])) {
									oph_workflow_free(*workflow);
									if (jansson)
										json_decref(jansson);
									pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating task arg value\n");
									return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
								}
								ok = 1;
								break;
							}
						}
						if (!ok) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "invalid format for task argument\n");
							return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
						}
					}
				}
			}
		}
		//unpack dependencies
		json_t *dependencies = NULL;
		json_unpack(task, "{s?o}", "dependencies", &dependencies);
		if (dependencies) {
			(*workflow)->tasks[i].deps_num = (int) json_array_size(dependencies);
			(*workflow)->tasks[i].residual_deps_num = (*workflow)->tasks[i].deps_num;
			if ((*workflow)->tasks[i].deps_num >= 1) {
				(*workflow)->tasks[i].deps = (oph_workflow_dep *) calloc((*workflow)->tasks[i].deps_num, sizeof(oph_workflow_dep));
				if (!((*workflow)->tasks[i].deps)) {
					(*workflow)->tasks[i].deps_num = 0;
					(*workflow)->tasks[i].residual_deps_num = (*workflow)->tasks[i].deps_num;
					oph_workflow_free(*workflow);
					if (jansson)
						json_decref(jansson);
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating deps\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				unsigned int auto_order = 0;
				char auto_order_s[OPH_WORKFLOW_MIN_STRING];
				for (j = 0; j < (*workflow)->tasks[i].deps_num; j++) {
					json_t *dependency = NULL;
					dependency = json_array_get(dependencies, j);
					if (dependency) {
						char *argument = NULL, *order = NULL, *task_name = NULL, *type = NULL, *filter = NULL, *output_argument = NULL, *output_order = NULL;
						json_unpack(dependency, "{s?s,s?s,s?s,s?s,s?s,s?s,s?s}", "argument", &argument, "order", &order, "task", &task_name, "type", &type, "filter", &filter,
							    "output_argument", &output_argument, "output_order", &output_order);

						//add task_name
						if (!task_name) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "null task name in dependency\n");
							return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
						}
						(*workflow)->tasks[i].deps[j].task_name = (char *) strdup((const char *) task_name);
						if (!((*workflow)->tasks[i].deps[j].task_name)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep task name\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						//add argument
						if (argument) {
							(*workflow)->tasks[i].deps[j].argument = (char *) strdup((const char *) argument);
						} else {
							(*workflow)->tasks[i].deps[j].argument = (char *) strdup((const char *) "cube");
						}
						if (!((*workflow)->tasks[i].deps[j].argument)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep argument\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						//add order
						if (order) {
							(*workflow)->tasks[i].deps[j].order = (char *) strdup((const char *) order);
						} else {
							snprintf(auto_order_s, OPH_WORKFLOW_MIN_STRING, "%d", auto_order++);
							(*workflow)->tasks[i].deps[j].order = (char *) strdup(auto_order_s);
						}
						if (!((*workflow)->tasks[i].deps[j].order)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep order\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						//add type
						if (type) {
							if (strcmp(type, "all") && strcmp(type, "single") && strcmp(type, "embedded")) {
								oph_workflow_free(*workflow);
								if (jansson)
									json_decref(jansson);
								pmesg(LOG_ERROR, __FILE__, __LINE__, "invalid dep type\n");
								return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
							}
							(*workflow)->tasks[i].deps[j].type = (char *) strdup((const char *) type);
						} else if (argument)
							(*workflow)->tasks[i].deps[j].type = (char *) strdup((const char *) "all");
						else
							(*workflow)->tasks[i].deps[j].type = (char *) strdup((const char *) "embedded");
						if (!((*workflow)->tasks[i].deps[j].type)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep type\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						//add filter
						if (filter) {
							(*workflow)->tasks[i].deps[j].filter = (char *) strdup((const char *) filter);
						} else {
							(*workflow)->tasks[i].deps[j].filter = (char *) strdup((const char *) "all");
						}
						if (!((*workflow)->tasks[i].deps[j].filter)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep filter\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						//add output_argument
						if (output_argument) {
							(*workflow)->tasks[i].deps[j].output_argument = (char *) strdup((const char *) output_argument);
						} else {
							(*workflow)->tasks[i].deps[j].output_argument = (char *) strdup((const char *) "cube");
						}
						if (!((*workflow)->tasks[i].deps[j].output_argument)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep output_argument\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						//add output_order
						if (output_order) {
							(*workflow)->tasks[i].deps[j].output_order = (char *) strdup((const char *) output_order);
						} else {
							(*workflow)->tasks[i].deps[j].output_order = (char *) strdup((const char *) "0");
						}
						if (!((*workflow)->tasks[i].deps[j].output_order)) {
							oph_workflow_free(*workflow);
							if (jansson)
								json_decref(jansson);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating dep output_order\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
					}
				}
			}
		}
		// Create hash-table for task-specific run-time environment
		(*workflow)->tasks[i].vars = hashtbl_create((*workflow)->tasks_num, NULL);
		//unpack variables
		json_t *variables = NULL;
		json_unpack(task, "{s?o}", "variables", &variables);
		if (variables) {
			oph_workflow_var var;
			void *var_buffer;
			size_t var_size = sizeof(oph_workflow_var), svalue_size;
			for (j = 0; j < (int) json_array_size(variables); j++) {
				json_t *variable = NULL;
				variable = json_array_get(variables, j);
				if (variable) {
					char *key = NULL, *svalue = NULL, *ivalue = NULL;
					json_unpack(variable, "{s?s,s?s,s?s}", "key", &key, "svalue", &svalue, "ivalue", &ivalue);
					if (key) {
						var.caller = i;
						if (ivalue)
							var.ivalue = (int) strtol(ivalue, NULL, 10);
						else
							var.ivalue = 1;	// Non C-like indexing
						if (svalue)
							var.svalue = strdup(svalue);
						else {
							var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
							if (var.svalue)
								snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", var.ivalue);
						}
						if (!var.svalue) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
							break;
						}
						svalue_size = strlen(var.svalue) + 1;
						var_buffer = malloc(var_size + svalue_size);
						if (!var_buffer) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
							free(var.svalue);
							break;
						}
						memcpy(var_buffer, (void *) &var, var_size);
						memcpy(var_buffer + var_size, var.svalue, svalue_size);
						if (hashtbl_insert_with_size((*workflow)->tasks[i].vars, key, var_buffer, var_size + svalue_size)) {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to store variable '%s' in environment of task '%s'. Maybe it already exists.\n", key,
							      (*workflow)->tasks[i].name);
							free(var.svalue);
							free(var_buffer);
							break;
						}
						if (svalue)
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%s' in environment of task '%s'.\n", key, var.svalue, (*workflow)->tasks[i].name);
						else
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%d' in environment of task '%s'.\n", key, var.ivalue, (*workflow)->tasks[i].name);
						free(var.svalue);
						free(var_buffer);
					}
				}
			}
		}
		// Set the retry number
		(*workflow)->tasks[i].retry_num = 1;	// Default value
		(*workflow)->tasks[i].backoff_time = (int) oph_base_backoff;
		if (!on_error_task)
			on_error_task = on_error;
		else if (strlen(on_error_task)) {
			(*workflow)->tasks[i].on_error = (char *) strdup((const char *) on_error_task);
			if (!((*workflow)->tasks[i].on_error)) {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating on_error\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
		}
		if (on_error_task) {
			if (!strcmp(on_error_task, OPH_WORKFLOW_SKIP))
				(*workflow)->tasks[i].retry_num = -1;
			else if (!strcmp(on_error_task, OPH_WORKFLOW_CONTINUE))
				(*workflow)->tasks[i].retry_num = 0;
			else if (!strcmp(on_error_task, OPH_WORKFLOW_BREAK) || !strcmp(on_error_task, OPH_WORKFLOW_ABORT))
				(*workflow)->tasks[i].retry_num = 1;
			else if (!strncmp(on_error_task, OPH_WORKFLOW_REPEAT, strlen(OPH_WORKFLOW_REPEAT))) {
				on_error_task += strlen(OPH_WORKFLOW_REPEAT);
				(*workflow)->tasks[i].retry_num = 1 + (int) strtol(on_error_task, NULL, 10);
				if ((*workflow)->tasks[i].retry_num < 1) {
					oph_workflow_free(*workflow);
					if (jansson)
						json_decref(jansson);
					pmesg(LOG_ERROR, __FILE__, __LINE__, "error in setting the number of execution retries\n");
					return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
				}
				while (*on_error_task == ' ')
					on_error_task++;
				char *space = strstr(on_error_task, " ");
				if (space) {	// Backoff time
					while (*space == ' ')
						space++;
					(*workflow)->tasks[i].backoff_time = (int) strtol(space, NULL, 10);
					space = strstr(space, " ");
					if (space) {	// Back off type
						while (*space == ' ')
							space++;
						(*workflow)->tasks[i].backoff_type = *space;
					}
				}
			} else {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'on_error'\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
		}
		(*workflow)->tasks[i].residual_retry_num = (*workflow)->tasks[i].retry_num;

		// Set the exit code
		(*workflow)->tasks[i].exit_action = OPH_WORKFLOW_EXIT_ACTION_NOP;	// Default value (no operation)
		if (!on_exit_task)
			on_exit_task = on_exit;
		else if (strlen(on_exit_task)) {
			(*workflow)->tasks[i].on_exit = (char *) strdup((const char *) on_exit_task);
			if (!((*workflow)->tasks[i].on_exit)) {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error allocating on_exit\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
		}
		if (on_exit_task) {
			if (!strlen(on_exit_task) || !strcmp(on_exit_task, OPH_WORKFLOW_NOP))
				(*workflow)->tasks[i].exit_action = OPH_WORKFLOW_EXIT_ACTION_NOP;
			else if (!strcmp(on_exit_task, OPH_WORKFLOW_DELETE))
				(*workflow)->tasks[i].exit_action = OPH_WORKFLOW_EXIT_ACTION_DELETE;
			else if (!strcmp(on_exit_task, OPH_WORKFLOW_DELETECONTAINER))
				(*workflow)->tasks[i].exit_action = OPH_WORKFLOW_EXIT_ACTION_DELETECONTAINER;
			else {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'on_exit'\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
		}

		(*workflow)->tasks[i].run = 1;	// Default value (yes)
		if (!run_task)
			run_task = run;
		if (run_task && strlen(run_task)) {
			if (!strcmp(run_task, OPH_WORKFLOW_NO))
				(*workflow)->tasks[i].run = 0;
			else if (strcmp(run_task, OPH_WORKFLOW_YES)) {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'run'\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
		}

		(*workflow)->tasks[i].save = 1;	// Default value (yes)
		if (!save_task)
			save_task = save;
		if (save_task && strlen(save_task)) {
			if (!strcmp(save_task, OPH_WORKFLOW_NO))
				(*workflow)->tasks[i].save = 0;
			else if (strcmp(save_task, OPH_WORKFLOW_YES)) {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'save'\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
		}

		(*workflow)->tasks[i].parent = (*workflow)->tasks[i].child = -1;
		(*workflow)->tasks[i].nesting_level = (*workflow)->tasks[i].parallel_mode = 0;

		if (checkpoint && strlen(checkpoint)) {
			if (!strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_NO) || !strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_ALL) || !strcmp(checkpoint, OPH_OPERATOR_RESUME_PARAMETER_LAST)) {
				oph_workflow_free(*workflow);
				if (jansson)
					json_decref(jansson);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'checkpoint': value '%s' is not allowed\n", checkpoint);
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
			(*workflow)->tasks[i].checkpoint = strdup(checkpoint);
		} else if ((*workflow)->checkpoint)
			(*workflow)->tasks[i].checkpoint = strdup(checkpoint);
	}

	// Final task
	(*workflow)->tasks[(*workflow)->tasks_num].run = 1;	// Default value (yes)
	if (run && strlen(run)) {
		if (!strcmp(run, OPH_WORKFLOW_NO))
			(*workflow)->tasks[(*workflow)->tasks_num].run = 0;
		else if (strcmp(run, OPH_WORKFLOW_YES)) {
			oph_workflow_free(*workflow);
			if (jansson)
				json_decref(jansson);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error in parsing parameter 'run'\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}
	(*workflow)->tasks[(*workflow)->tasks_num].retry_num = (*workflow)->tasks[(*workflow)->tasks_num].parent = (*workflow)->tasks[(*workflow)->tasks_num].child = -1;
	(*workflow)->tasks[(*workflow)->tasks_num].exit_action = (*workflow)->tasks[(*workflow)->tasks_num].nesting_level = (*workflow)->tasks[(*workflow)->tasks_num].parallel_mode = 0;

	// Cleanup
	if (jansson)
		json_decref(jansson);

	// Global var substitution
	//ncores
	if ((*workflow)->ncores != 0) {
		char buf[OPH_WORKFLOW_MIN_STRING];
		snprintf(buf, OPH_WORKFLOW_MIN_STRING, "%d", (*workflow)->ncores);
		if (_oph_workflow_substitute_var("ncores", buf, (*workflow)->tasks, (*workflow)->tasks_num)) {
			oph_workflow_free(*workflow);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting ncores\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	// Finalize ncores
	for (i = 0; i < (*workflow)->tasks_num; i++) {
		if (!(*workflow)->tasks[i].ncores) {
			for (j = 0; j < (*workflow)->tasks[i].arguments_num; j++) {
				if (!strcmp((*workflow)->tasks[i].arguments_keys[j], "ncores")) {
					(*workflow)->tasks[i].ncores = (int) strtol((*workflow)->tasks[i].arguments_values[j], NULL, 10);
					break;
				}
			}
		}
		if ((*workflow)->tasks[i].ncores < 0) {
			oph_workflow_free(*workflow);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "ncores cannot be negative\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	//nhosts
	if ((*workflow)->nhosts != 0) {
		char buf[OPH_WORKFLOW_MIN_STRING];
		snprintf(buf, OPH_WORKFLOW_MIN_STRING, "%d", (*workflow)->nhosts);
		if (_oph_workflow_substitute_var("nhost", buf, (*workflow)->tasks, (*workflow)->tasks_num)) {
			oph_workflow_free(*workflow);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting nhosts\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	// Finalize nhosts
	for (i = 0; i < (*workflow)->tasks_num; i++) {
		if (!(*workflow)->tasks[i].nhosts) {
			for (j = 0; j < (*workflow)->tasks[i].arguments_num; j++) {
				if (!strcmp((*workflow)->tasks[i].arguments_keys[j], "nhost")) {
					(*workflow)->tasks[i].nhosts = (int) strtol((*workflow)->tasks[i].arguments_values[j], NULL, 10);
					break;
				}
			}
		}
		if ((*workflow)->tasks[i].nhosts < 0) {
			oph_workflow_free(*workflow);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "nhost cannot be negative\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	//nthreads
	if ((*workflow)->nthreads != 0) {
		char buf[OPH_WORKFLOW_MIN_STRING];
		snprintf(buf, OPH_WORKFLOW_MIN_STRING, "%d", (*workflow)->nthreads);
		if (_oph_workflow_substitute_var("nthreads", buf, (*workflow)->tasks, (*workflow)->tasks_num)) {
			oph_workflow_free(*workflow);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting nthreads\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	// Finalize nthreads
	for (i = 0; i < (*workflow)->tasks_num; i++) {
		if (!(*workflow)->tasks[i].nthreads) {
			for (j = 0; j < (*workflow)->tasks[i].arguments_num; j++) {
				if (!strcmp((*workflow)->tasks[i].arguments_keys[j], "nthreads")) {
					(*workflow)->tasks[i].nthreads = (int) strtol((*workflow)->tasks[i].arguments_values[j], NULL, 10);
					break;
				}
			}
		}
		if ((*workflow)->tasks[i].nthreads < 0) {
			oph_workflow_free(*workflow);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "nthreads cannot be negative\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	//project
	if ((*workflow)->project && _oph_workflow_substitute_var("project", (*workflow)->project, (*workflow)->tasks, (*workflow)->tasks_num)) {
		oph_workflow_free(*workflow);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting project\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	//cwd
	if (!(*workflow)->cwd)
		(*workflow)->cwd = strdup(OPH_WORKFLOW_ROOT_FOLDER);
	if (_oph_workflow_substitute_var("cwd", (*workflow)->cwd, (*workflow)->tasks, (*workflow)->tasks_num)) {
		oph_workflow_free(*workflow);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting cwd\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	//cdd
	if (!(*workflow)->cdd)
		(*workflow)->cdd = strdup(OPH_WORKFLOW_ROOT_FOLDER);
	if (_oph_workflow_substitute_var("cdd", (*workflow)->cdd, (*workflow)->tasks, (*workflow)->tasks_num)) {
		oph_workflow_free(*workflow);
		pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting cdd\n");
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}
	//cube
	if ((*workflow)->cube) {
		if (_oph_workflow_substitute_cube((*workflow)->cube, (*workflow)->tasks, (*workflow)->tasks_num)) {
			oph_workflow_free(*workflow);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "error substituting cube\n");
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}
	}
	// Support for non-Ophidia operators
	char *tmp = NULL;
	for (i = 0; i < (*workflow)->tasks_num; i++) {
		if (!strcmp((*workflow)->tasks[i].type, OPH_TYPE_CDO) || !strcmp((*workflow)->tasks[i].type, OPH_TYPE_GENERIC)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found operator: %s %s\n", (*workflow)->tasks[i].type, (*workflow)->tasks[i].operator);
			int kk = (*workflow)->tasks[i].arguments_num, kkk = kk;
			if (oph_realloc_vector(&((*workflow)->tasks[i].arguments_keys), &kk, 1) || (kk != 1 + (*workflow)->tasks[i].arguments_num)) {
				oph_workflow_free(*workflow);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to reallocate vector\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			} else if (oph_realloc_vector(&((*workflow)->tasks[i].arguments_values), &kkk, 1) || (kk != kkk)) {
				oph_workflow_free(*workflow);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to reallocate vector\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			} else if (oph_realloc_vector2(&((*workflow)->tasks[i].arguments_lists), &((*workflow)->tasks[i].arguments_num), 1) || (kk != (*workflow)->tasks[i].arguments_num)) {
				oph_workflow_free(*workflow);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to reallocate vector\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			kk--;
			(*workflow)->tasks[i].arguments_keys[kk] = strdup(OPH_ARG_COMMAND);
			(*workflow)->tasks[i].arguments_values[kk] = strdup((*workflow)->tasks[i].operator);
			(*workflow)->tasks[i].arguments_lists[kk] = NULL;

			if (asprintf(&tmp, "oph_%s", (*workflow)->tasks[i].type) <= 0) {
				oph_workflow_free(*workflow);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to allocate operator name\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			free((*workflow)->tasks[i].operator);
			(*workflow)->tasks[i].operator = tmp;

			(*workflow)->tasks[i].rtype = (*workflow)->tasks[i].type;	// Save original task type to fill extended response
			(*workflow)->tasks[i].type = strdup(OPH_TYPE_OPHIDIA);

		} else if (!strcmp((*workflow)->tasks[i].type, OPH_TYPE_CONTROL)) {

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found operator: %s %s\n", (*workflow)->tasks[i].type, (*workflow)->tasks[i].operator);
			if (asprintf(&tmp, "oph_%s", (*workflow)->tasks[i].operator) <= 0) {
				oph_workflow_free(*workflow);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to allocate operator name\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			free((*workflow)->tasks[i].operator);
			(*workflow)->tasks[i].operator = tmp;

			(*workflow)->tasks[i].rtype = (*workflow)->tasks[i].type;	// Save original task type to fill extended response
			(*workflow)->tasks[i].type = strdup(OPH_TYPE_OPHIDIA);
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Thread_unsafe
int oph_workflow_store(oph_workflow * workflow, char **jstring, const char *checkpoint)
{
	if (!workflow || !jstring) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	*jstring = NULL;

	int i, j, k;
	char jsontmp[OPH_WORKFLOW_MAX_STRING], erase_command = 0, empty = 1, skip_dependence = 0, add_global_vars = 0;
	json_t *request = json_object();
	if (!request)
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	snprintf(jsontmp, OPH_WORKFLOW_MAX_STRING, "%s%s%s", workflow->name, checkpoint ? " - from checkpoint: " : "", checkpoint ? checkpoint : "");
	if (_oph_workflow_add_to_json(request, "name", jsontmp))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "author", workflow->author))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "abstract", workflow->abstract))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "url", workflow->url))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "sessionid", workflow->sessionid))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "exec_mode", workflow->exec_mode))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	snprintf(jsontmp, OPH_WORKFLOW_MIN_STRING, "%d", workflow->ncores);
	if (_oph_workflow_add_to_json(request, "ncores", jsontmp))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	snprintf(jsontmp, OPH_WORKFLOW_MIN_STRING, "%d", workflow->nhosts);
	if (_oph_workflow_add_to_json(request, "nhost", jsontmp))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	snprintf(jsontmp, OPH_WORKFLOW_MIN_STRING, "%d", workflow->nthreads);
	if (_oph_workflow_add_to_json(request, "nthreads", jsontmp))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (workflow->project && _oph_workflow_add_to_json(request, "project", workflow->project))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "on_error", workflow->on_error))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "on_exit", workflow->on_exit))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (!workflow->run && _oph_workflow_add_to_json(request, "run", "no"))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (workflow->checkpoint && _oph_workflow_add_to_json(request, "checkpoint", workflow->checkpoint))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "cwd", workflow->cwd))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "cdd", workflow->cdd))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "cube", workflow->cube))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "callback_url", workflow->callback_url))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "command", workflow->command))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (_oph_workflow_add_to_json(request, "host_partition", workflow->host_partition_orig ? workflow->host_partition_orig : workflow->host_partition))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	json_t *tasks = json_array();
	if (!tasks) {
		if (request)
			json_decref(request);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	while (checkpoint && workflow->vars) {

		oph_workflow_var *value = NULL;
		char jsontmp2[OPH_WORKFLOW_MAX_STRING], first = 1, *key = NULL;
		snprintf(jsontmp, OPH_WORKFLOW_MAX_STRING, "%s=", OPH_ARG_KEYS);
		snprintf(jsontmp2, OPH_WORKFLOW_MAX_STRING, "%s=", OPH_ARG_VALUE);
		char *common_key[OPH_WORKFLOW_MIN_STRING] = OPH_WORKFLOW_BVAR_KEYS;

		while (!hashtbl_next(workflow->vars, &key, (void **) &value)) {
			for (i = 0; i < OPH_WORKFLOW_BVAR_KEYS_SIZE; ++i)
				if (!strcmp(key, common_key[i]))
					break;
			if (i < OPH_WORKFLOW_BVAR_KEYS_SIZE)	// Discard common keys
				continue;
			if (!first)
				strncat(jsontmp, OPH_SEPARATOR_SUBPARAM_STR, OPH_WORKFLOW_MAX_STRING - strlen(jsontmp));
			strncat(jsontmp, key, OPH_WORKFLOW_MAX_STRING - strlen(jsontmp));
			if (!first)
				strncat(jsontmp2, OPH_SEPARATOR_SUBPARAM_STR, OPH_WORKFLOW_MAX_STRING - strlen(jsontmp2));
			strncat(jsontmp2, value->svalue, OPH_WORKFLOW_MAX_STRING - strlen(jsontmp2));
			first = 0;
		}

		if (first)	// No variable found
			break;

		json_t *task = json_object();
		if (!task)
			break;
		if (_oph_workflow_add_to_json(task, "name", OPH_GLOBAL_VARS)) {
			if (task)
				json_decref(task);
			break;
		}
		if (_oph_workflow_add_to_json(task, "type", OPH_TYPE_OPHIDIA)) {
			if (task)
				json_decref(task);
			break;
		}
		if (_oph_workflow_add_to_json(task, "operator", OPH_OPERATOR_SET)) {
			if (task)
				json_decref(task);
			break;
		}

		json_t *arguments = json_array();
		if (!arguments) {
			if (task)
				json_decref(task);
			break;
		}

		if (json_array_append_new(arguments, json_string(jsontmp))) {
			if (arguments)
				json_decref(arguments);
			if (task)
				json_decref(task);
			break;
		}
		if (json_array_append_new(arguments, json_string(jsontmp2))) {
			if (arguments)
				json_decref(arguments);
			if (task)
				json_decref(task);
			break;
		}

		if (json_object_set_new(task, "arguments", arguments)) {
			if (arguments)
				json_decref(arguments);
			if (task)
				json_decref(task);
			break;
		}

		if (json_array_append_new(tasks, task)) {
			if (task)
				json_decref(task);
			break;
		}

		add_global_vars = 1;
		break;
	}

	for (i = 0; i < workflow->tasks_num; ++i) {

		if (checkpoint) {
			if (workflow->tasks[i].status >= OPH_ODB_STATUS_COMPLETED)
				continue;
			if ((workflow->tasks[i].parent >= 0) && (workflow->tasks[workflow->tasks[i].parent].status >= OPH_ODB_STATUS_COMPLETED))
				continue;
		}

		json_t *task = json_object();
		if (!task)
			break;
		erase_command = workflow->tasks[i].rtype && strcmp(workflow->tasks[i].rtype, OPH_TYPE_CONTROL);
		if (_oph_workflow_add_to_json(task, "name", workflow->tasks[i].name))
			break;
		if (_oph_workflow_add_to_json(task, "type", workflow->tasks[i].rtype ? workflow->tasks[i].rtype : workflow->tasks[i].type))
			break;
		if (!erase_command && _oph_workflow_add_to_json(task, "operator", workflow->tasks[i].operator +(workflow->tasks[i].rtype ? 4 : 0)))
			break;
		if (_oph_workflow_add_to_json(task, "on_error", workflow->tasks[i].on_error))
			break;
		if (_oph_workflow_add_to_json(task, "on_exit", workflow->tasks[i].on_exit))
			break;
		if (!workflow->tasks[i].run && _oph_workflow_add_to_json(task, "run", "no"))
			break;
		if (workflow->tasks[i].checkpoint && _oph_workflow_add_to_json(task, "checkpoint", workflow->tasks[i].checkpoint))
			break;

		json_t *arguments = json_array();
		if (!arguments) {
			if (task)
				json_decref(task);
			break;
		}
		if (!erase_command) {
			for (j = 0; j < workflow->tasks[i].arguments_num; ++j) {
				snprintf(jsontmp, OPH_WORKFLOW_MAX_STRING, "%s=%s", workflow->tasks[i].arguments_keys[j], workflow->tasks[i].arguments_values[j]);
				if (json_array_append_new(arguments, json_string(jsontmp)))
					break;
			}
		} else {
			for (j = 0; j < workflow->tasks[i].arguments_num; ++j) {
				if (strcmp(workflow->tasks[i].arguments_keys[j], OPH_ARG_COMMAND)) {
					snprintf(jsontmp, OPH_WORKFLOW_MAX_STRING, "%s=%s", workflow->tasks[i].arguments_keys[j], workflow->tasks[i].arguments_values[j]);
					if (json_array_append_new(arguments, json_string(jsontmp)))
						break;
				} else if (_oph_workflow_add_to_json(task, "operator", workflow->tasks[i].arguments_values[j]))
					break;
			}
		}
		if (j < workflow->tasks[i].arguments_num) {
			if (arguments)
				json_decref(arguments);
			if (task)
				json_decref(task);
			break;
		}
		if (json_object_set_new(task, "arguments", arguments)) {
			if (arguments)
				json_decref(arguments);
			if (task)
				json_decref(task);
			break;
		}

		if (workflow->tasks[i].deps_num) {
			json_t *dependencies = json_array();
			if (!dependencies) {
				if (task)
					json_decref(task);
				break;
			}

			while (add_global_vars) {
				json_t *dependency = json_object();
				if (!dependency)
					break;
				if (_oph_workflow_add_to_json(dependency, "task", OPH_GLOBAL_VARS))
					break;
				if (json_array_append_new(dependencies, dependency)) {
					if (dependency)
						json_decref(dependency);
					break;
				}
				break;
			}

			for (j = 0; j < workflow->tasks[i].deps_num; ++j) {

				if (checkpoint && (workflow->tasks[i].deps[j].task_index < 0))
					continue;

				// Check if the parent task exists
				for (k = 0; k < workflow->tasks_num; ++k) {
					skip_dependence = (k == i) || (checkpoint && (workflow->tasks[k].status >= OPH_ODB_STATUS_COMPLETED));
					if (!strcmp(workflow->tasks[k].name, workflow->tasks[i].deps[j].task_name))
						break;
				}
				if (skip_dependence || (k >= workflow->tasks_num))
					continue;

				json_t *dependency = json_object();
				if (!dependency)
					break;
				if (_oph_workflow_add_to_json(dependency, "argument", workflow->tasks[i].deps[j].argument))
					break;
				if (_oph_workflow_add_to_json(dependency, "order", workflow->tasks[i].deps[j].order))
					break;
				if (_oph_workflow_add_to_json(dependency, "task", workflow->tasks[i].deps[j].task_name))
					break;
				if (_oph_workflow_add_to_json(dependency, "type", workflow->tasks[i].deps[j].type))
					break;
				if (_oph_workflow_add_to_json(dependency, "filter", workflow->tasks[i].deps[j].filter))
					break;
				if (_oph_workflow_add_to_json(dependency, "output_argument", workflow->tasks[i].deps[j].output_argument))
					break;
				if (_oph_workflow_add_to_json(dependency, "output_order", workflow->tasks[i].deps[j].output_order))
					break;

				if (json_array_append_new(dependencies, dependency)) {
					if (dependency)
						json_decref(dependency);
					break;
				}
			}
			if (j < workflow->tasks[i].deps_num) {
				if (dependencies)
					json_decref(dependencies);
				if (task)
					json_decref(task);
				break;
			}
			if (json_object_set_new(task, "dependencies", dependencies)) {
				if (dependencies)
					json_decref(dependencies);
				if (task)
					json_decref(task);
				break;
			}
		}

		if (json_array_append_new(tasks, task)) {
			if (task)
				json_decref(task);
			break;
		}
		// Add task-specific variables
		if (checkpoint && workflow->tasks[i].vars) {

			json_t *variables = json_array();
			if (!variables) {
				if (task)
					json_decref(task);
				break;
			}

			oph_workflow_var *value = NULL;
			char first = 1, *key = NULL;

			while (!hashtbl_next(workflow->tasks[i].vars, &key, (void **) &value)) {

				json_t *variable = json_object();
				if (!variable)
					break;
				if (_oph_workflow_add_to_json(variable, "key", key))
					break;
				if (value->svalue && _oph_workflow_add_to_json(variable, "svalue", value->svalue))
					break;
				snprintf(jsontmp, OPH_WORKFLOW_MAX_STRING, "%d", value->ivalue);
				if (_oph_workflow_add_to_json(variable, "ivalue", jsontmp))
					break;

				if (json_array_append_new(variables, variable)) {
					if (variable)
						json_decref(variable);
					break;
				}
				first = 0;
			}

			if (first || json_object_set_new(task, "variables", variables)) {
				if (variables)
					json_decref(variables);
				break;
			}
		}

		empty = 0;
	}
	if (i < workflow->tasks_num) {
		if (request)
			json_decref(request);
		if (tasks)
			json_decref(tasks);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	if (json_object_set_new(request, "tasks", tasks)) {
		if (request)
			json_decref(request);
		if (tasks)
			json_decref(tasks);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	if (empty) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Request has no valid tasks\n");
		if (request)
			json_decref(request);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}

	*jstring = json_dumps((const json_t *) request, JSON_INDENT(4));
	if (!(*jstring)) {
		if (request)
			json_decref(request);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (request)
		json_decref(request);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Saving the following request:\n%s\n", *jstring);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// OTHER INTERNAL FUNCTIONS

int _oph_workflow_add_to_json(json_t * item, const char *name, const char *value)
{
	if (value && json_object_set_new(item, name, json_string(value))) {
		if (item)
			json_decref(item);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int _oph_workflow_alloc(oph_workflow ** workflow)
{
	if (!workflow) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	//alloc
	*workflow = (oph_workflow *) calloc(1, sizeof(oph_workflow));
	if (!(*workflow)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating workflow\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	//init
	(*workflow)->url = NULL;
	(*workflow)->abstract = NULL;
	(*workflow)->author = NULL;
	(*workflow)->callback_url = NULL;
	(*workflow)->cube = NULL;
	(*workflow)->cwd = NULL;
	(*workflow)->cdd = NULL;
	(*workflow)->exec_mode = NULL;
	(*workflow)->idjob = -1;
	(*workflow)->markerid = -1;
	(*workflow)->name = NULL;
	(*workflow)->ncores = 0;
	(*workflow)->nhosts = 0;
	(*workflow)->nthreads = 0;
	(*workflow)->residual_tasks_num = 0;
	(*workflow)->sessionid = NULL;
	(*workflow)->status = OPH_WORKFLOW_STATUS_PENDING;
	(*workflow)->tasks = NULL;
	(*workflow)->tasks_num = 0;
	(*workflow)->username = NULL;
	(*workflow)->password = NULL;
	(*workflow)->os_username = NULL;
	(*workflow)->iduser = 0;
	(*workflow)->ip_address = NULL;
	(*workflow)->response = NULL;
	(*workflow)->command = NULL;
	(*workflow)->exit_cubes = NULL;
	(*workflow)->exit_containers = NULL;
	(*workflow)->workflowid = -1;
	(*workflow)->vars = NULL;
	(*workflow)->stack = NULL;
	(*workflow)->run = 1;
	(*workflow)->parallel_mode = 0;
	(*workflow)->host_partition = NULL;
	(*workflow)->host_partition_orig = NULL;
	(*workflow)->client_address = NULL;
	(*workflow)->new_token = NULL;
	(*workflow)->project = NULL;
	(*workflow)->checkpoint = NULL;

	struct timeval tv;
	gettimeofday(&tv, 0);

	(*workflow)->timestamp = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int _oph_workflow_substitute_var(char *key, char *value, oph_workflow_task * tasks, int tasks_num)
{
	if (!key || !value || !tasks || tasks_num < 1) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	int i, j;
	for (i = 0; i <= tasks_num; i++)	// the last step is related to the "final task"
	{
		if (tasks[i].arguments_num == 0) {
			if (!strcmp(key, "ncores")) {
				tasks[i].ncores = (int) strtol(value, NULL, 10);
			} else if (!strcmp(key, "nhost")) {
				tasks[i].nthreads = (int) strtol(value, NULL, 10);
			} else if (!strcmp(key, "nthreads")) {
				tasks[i].nthreads = (int) strtol(value, NULL, 10);
			} else {
				tasks[i].arguments_keys = (char **) calloc(1, sizeof(char *));
				if (!(tasks[i].arguments_keys)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments keys\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_values = (char **) calloc(1, sizeof(char *));
				if (!(tasks[i].arguments_values)) {
					free(tasks[i].arguments_keys);
					tasks[i].arguments_keys = NULL;
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments values\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_lists = (oph_workflow_ordered_list **) calloc(1, sizeof(oph_workflow_ordered_list *));
				if (!(tasks[i].arguments_lists)) {
					free(tasks[i].arguments_keys);
					free(tasks[i].arguments_values);
					tasks[i].arguments_keys = NULL;
					tasks[i].arguments_values = NULL;
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments lists\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_num++;
				tasks[i].arguments_keys[0] = (char *) strdup((const char *) key);
				if (!(tasks[i].arguments_keys[0])) {
					free(tasks[i].arguments_keys);
					free(tasks[i].arguments_values);
					free(tasks[i].arguments_lists);
					tasks[i].arguments_keys = NULL;
					tasks[i].arguments_values = NULL;
					tasks[i].arguments_lists = NULL;
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments key\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_values[0] = (char *) strdup((const char *) value);
				if (!(tasks[i].arguments_values[0])) {
					free(tasks[i].arguments_keys);
					free(tasks[i].arguments_values);
					free(tasks[i].arguments_lists);
					tasks[i].arguments_keys = NULL;
					tasks[i].arguments_values = NULL;
					tasks[i].arguments_lists = NULL;
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments value\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_lists[0] = NULL;
			}
		} else {
			int found = 0;
			for (j = 0; j < tasks[i].arguments_num; j++) {
				if (!strcmp(tasks[i].arguments_keys[j], key)) {
					found = 1;
					if (!strcmp(key, "ncores") || !strcmp(key, "nhost") || !strcmp(key, "nthreads")) {
						if (!strcmp(key, "ncores"))
							tasks[i].ncores = (int) strtol(tasks[i].arguments_values[j], NULL, 10);
						else if (!strcmp(key, "nhost"))
							tasks[i].nhosts = (int) strtol(tasks[i].arguments_values[j], NULL, 10);
						else
							tasks[i].nthreads = (int) strtol(tasks[i].arguments_values[j], NULL, 10);
						free(tasks[i].arguments_keys[j]);
						tasks[i].arguments_keys[j] = NULL;
						free(tasks[i].arguments_values[j]);
						tasks[i].arguments_values[j] = NULL;
						oph_workflow_free_list(tasks[i].arguments_lists[j]);
						tasks[i].arguments_lists[j] = NULL;
						char **tmpkeys = (char **) calloc(tasks[i].arguments_num - 1, sizeof(char *));
						if (!tmpkeys) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating tmpkeys\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						char **tmpvalues = (char **) calloc(tasks[i].arguments_num - 1, sizeof(char *));
						if (!tmpvalues) {
							free(tmpkeys);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating tmpvalues\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						oph_workflow_ordered_list **tmplists = (oph_workflow_ordered_list **) calloc(tasks[i].arguments_num - 1, sizeof(oph_workflow_ordered_list *));
						if (!tmpvalues) {
							free(tmpkeys);
							free(tmpvalues);
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating tmplists\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						int k, q = 0;
						for (k = 0; k < tasks[i].arguments_num; k++) {
							if (tasks[i].arguments_keys[k]) {
								tmpkeys[q] = tasks[i].arguments_keys[k];
								tmpvalues[q] = tasks[i].arguments_values[k];
								tmplists[q] = tasks[i].arguments_lists[k];
								q++;
							}
						}
						free(tasks[i].arguments_keys);
						free(tasks[i].arguments_values);
						free(tasks[i].arguments_lists);
						tasks[i].arguments_keys = tmpkeys;
						tasks[i].arguments_values = tmpvalues;
						tasks[i].arguments_lists = tmplists;
						tasks[i].arguments_num--;
					}
					break;
				}
			}
			if (!found) {
				if (!strcmp(key, "ncores")) {
					tasks[i].ncores = (int) strtol(value, NULL, 10);
				} else if (!strcmp(key, "nhost")) {
					tasks[i].nhosts = (int) strtol(value, NULL, 10);
				} else if (!strcmp(key, "nthreads")) {
					tasks[i].nthreads = (int) strtol(value, NULL, 10);
				} else {
					char **tmpkeys = tasks[i].arguments_keys;
					char **tmpvalues = tasks[i].arguments_values;
					oph_workflow_ordered_list **tmplists = tasks[i].arguments_lists;
					tasks[i].arguments_keys = (char **) realloc(tasks[i].arguments_keys, sizeof(char *) * (tasks[i].arguments_num + 1));
					if (!(tasks[i].arguments_keys)) {
						tasks[i].arguments_keys = tmpkeys;
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating arguments keys\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_keys[tasks[i].arguments_num] = NULL;
					tasks[i].arguments_values = (char **) realloc(tasks[i].arguments_values, sizeof(char *) * (tasks[i].arguments_num + 1));
					if (!(tasks[i].arguments_values)) {
						tasks[i].arguments_values = tmpvalues;
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating arguments values\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_values[tasks[i].arguments_num] = NULL;
					tasks[i].arguments_lists = (oph_workflow_ordered_list **) realloc(tasks[i].arguments_lists, sizeof(oph_workflow_ordered_list *) * (tasks[i].arguments_num + 1));
					if (!(tasks[i].arguments_lists)) {
						tasks[i].arguments_lists = tmplists;
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating arguments lists\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_lists[tasks[i].arguments_num] = NULL;
					tasks[i].arguments_num++;
					tasks[i].arguments_keys[tasks[i].arguments_num - 1] = (char *) strdup((const char *) key);
					if (!(tasks[i].arguments_keys[tasks[i].arguments_num - 1])) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating new argument key\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_values[tasks[i].arguments_num - 1] = (char *) strdup((const char *) value);
					if (!(tasks[i].arguments_values[tasks[i].arguments_num - 1])) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating new argument value\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_lists[tasks[i].arguments_num - 1] = NULL;
				}
			}
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int _oph_workflow_substitute_cube(char *pid, oph_workflow_task * tasks, int tasks_num)
{
	if (!pid || !tasks || tasks_num < 1) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	int i, j;
	for (i = 0; i < tasks_num; i++) {
		if (tasks[i].arguments_num == 0) {
			int k;
			int ok = 1;
			for (k = 0; k < tasks[i].deps_num; k++) {
				if (strcmp(tasks[i].deps[k].type, "embedded")) {
					ok = 0;
					break;
				}
			}
			if (ok) {
				tasks[i].arguments_keys = (char **) calloc(1, sizeof(char *));
				if (!(tasks[i].arguments_keys)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments keys\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_values = (char **) calloc(1, sizeof(char *));
				if (!(tasks[i].arguments_values)) {
					free(tasks[i].arguments_keys);
					tasks[i].arguments_keys = NULL;
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments values\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_lists = (oph_workflow_ordered_list **) calloc(1, sizeof(oph_workflow_ordered_list *));
				if (!(tasks[i].arguments_lists)) {
					free(tasks[i].arguments_keys);
					tasks[i].arguments_keys = NULL;
					tasks[i].arguments_values = NULL;
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments values\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_num++;
				tasks[i].arguments_keys[0] = (char *) strdup((const char *) "cube");
				if (!(tasks[i].arguments_keys[0])) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments key\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_values[0] = (char *) strdup((const char *) pid);
				if (!(tasks[i].arguments_values[0])) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating arguments value\n");
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
				tasks[i].arguments_lists[0] = NULL;
			}
		} else {
			int found = 0;
			for (j = 0; j < tasks[i].arguments_num; j++) {
				if (!strcmp(tasks[i].arguments_keys[j], "cube")) {
					found = 1;
					break;
				}
			}
			if (!found) {
				int k;
				int ok = 1;
				for (k = 0; k < tasks[i].deps_num; k++) {
					if (strcmp(tasks[i].deps[k].type, "embedded")) {
						ok = 0;
						break;
					}
				}
				if (ok) {
					char **tmpkeys = tasks[i].arguments_keys;
					char **tmpvalues = tasks[i].arguments_values;
					oph_workflow_ordered_list **tmplists = tasks[i].arguments_lists;
					tasks[i].arguments_keys = (char **) realloc(tasks[i].arguments_keys, sizeof(char *) * (tasks[i].arguments_num + 1));
					if (!(tasks[i].arguments_keys)) {
						tasks[i].arguments_keys = tmpkeys;
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating arguments keys\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_keys[tasks[i].arguments_num] = NULL;
					tasks[i].arguments_values = (char **) realloc(tasks[i].arguments_values, sizeof(char *) * (tasks[i].arguments_num + 1));
					if (!(tasks[i].arguments_values)) {
						tasks[i].arguments_values = tmpvalues;
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating arguments values\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_values[tasks[i].arguments_num] = NULL;
					tasks[i].arguments_lists = (oph_workflow_ordered_list **) realloc(tasks[i].arguments_lists, sizeof(oph_workflow_ordered_list *) * (tasks[i].arguments_num + 1));
					if (!(tasks[i].arguments_lists)) {
						tasks[i].arguments_lists = tmplists;
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating arguments lists\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_lists[tasks[i].arguments_num] = NULL;
					tasks[i].arguments_num++;
					tasks[i].arguments_keys[tasks[i].arguments_num - 1] = (char *) strdup((const char *) "cube");
					if (!(tasks[i].arguments_keys[tasks[i].arguments_num - 1])) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating new argument key\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_values[tasks[i].arguments_num - 1] = (char *) strdup((const char *) pid);
					if (!(tasks[i].arguments_values[tasks[i].arguments_num - 1])) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating new argument value\n");
						return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
					}
					tasks[i].arguments_lists[tasks[i].arguments_num - 1] = NULL;
				}
			}
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int _oph_workflow_skip_comments(const char *json_string, char **clean_json_string)
{
	if (!json_string || !clean_json_string)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	*clean_json_string = NULL;

	size_t i, j, size = strlen(json_string);
	char invalue = 0, flag = 0, print, drop;
	char *result = (char *) malloc(1 + size);
	if (!result)
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	for (i = j = 0; i < size; ++i) {
		print = 1;
		drop = 0;
		if (json_string[i] == '"') {
			if (invalue)
				invalue = 0;
			else
				invalue = 1;
		}
		if (!invalue) {
			if (json_string[i] == '/') {
				if (flag == 0)	// Previous char belongs to valid code
					flag = 1;
				else if (flag == 1)	// Previous char is '/'
				{
					flag = 4;
					drop = 1;
				} else if (flag == 3)	// Previous char is '*'
				{
					flag = 0;
					print = 0;
				}
			} else if (json_string[i] == '*') {
				if (flag == 1)	// Previous char is '/'
				{
					flag = 2;	// Comment until '*/'
					drop = 1;
				} else if (flag == 2)	// Possible end of a comment
					flag = 3;
				else if (flag == 3)
					flag = 2;
			} else if (json_string[i] == '\n') {
				if (flag == 1)
					flag = 0;
				else if (flag == 2)
					result[j++] = json_string[i];
				else if (flag == 3)
					flag = 2;
				else if (flag == 4)
					flag = 0;
			} else {
				if (flag == 1)
					flag = 0;
				else if (flag == 3)
					flag = 2;
			}
		}
		if (print && (flag < 2))
			result[j++] = json_string[i];
		if (drop && (j > 0))
			j--;
	}
	result[j] = 0;

	if (flag) {
		free(result);
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	}

	*clean_json_string = result;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}
