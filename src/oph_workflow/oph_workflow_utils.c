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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>

#include "oph_workflow_library.h"
#include "debug.h"
#include "oph_auth.h"

int oph_workflow_get_argument_size(oph_workflow * workflow, int task_index, size_t * max)
{
	if (!workflow || !max)
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;

	if (*max < 1)
		*max = 1;

	size_t current;
	int i;
	for (i = 0; i < workflow->tasks[task_index].arguments_num; ++i) {
		current = 3 + strlen(workflow->tasks[task_index].arguments_keys[i]) + strlen(workflow->tasks[task_index].arguments_values[i]);
		if (*max < current)
			*max = current;
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_check_args(oph_workflow * workflow, int task_index, int light_task_index, const char *key, char **value, int *index, const char *current_arg)
{
	if (!value || !index)
		return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
	*value = NULL;
	*index = -1;

	char arg[OPH_WORKFLOW_MAX_STRING];
	int i, is_task = light_task_index < 0, arguments_num = is_task ? workflow->tasks[task_index].arguments_num : workflow->tasks[task_index].light_tasks[light_task_index].arguments_num;
	size_t j, len;

	// Check on known parameters
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check if %s=%s for workflow '%s'\n", key, OPH_WORKFLOW_BVAR_KEY_MARKERID, workflow->name);
	if (!strcmp(key, OPH_WORKFLOW_BVAR_KEY_MARKERID)) {
		if (asprintf(value, "%d", is_task ? workflow->tasks[task_index].markerid : workflow->tasks[task_index].light_tasks[light_task_index].markerid) <= 0)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		return OPH_WORKFLOW_EXIT_SUCCESS;
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check if %s=%s for workflow '%s'\n", key, OPH_WORKFLOW_BVAR_KEY_NCORES, workflow->name);
	if (!strcmp(key, OPH_WORKFLOW_BVAR_KEY_NCORES)) {
		if (asprintf(value, "%d", is_task ? workflow->tasks[task_index].ncores : workflow->tasks[task_index].light_tasks[light_task_index].ncores) <= 0)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		return OPH_WORKFLOW_EXIT_SUCCESS;
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check if %s=%s for workflow '%s'\n", key, OPH_WORKFLOW_BVAR_KEY_NHOSTS, workflow->name);
	if (!strcmp(key, OPH_WORKFLOW_BVAR_KEY_NHOSTS)) {
		if (asprintf(value, "%d", is_task ? workflow->tasks[task_index].nhosts : workflow->tasks[task_index].light_tasks[light_task_index].nhosts) <= 0)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		return OPH_WORKFLOW_EXIT_SUCCESS;
	}
	// Loop on the arguments
	for (i = 0; i < arguments_num; ++i) {
		len =
		    snprintf(arg, OPH_WORKFLOW_MAX_STRING, "%s", is_task ? workflow->tasks[task_index].arguments_keys[i] : workflow->tasks[task_index].light_tasks[light_task_index].arguments_keys[i]);
		if (current_arg && !strcmp(arg, current_arg)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Skip argument '%s' in workflow '%s'\n", arg, workflow->name);
			continue;
		}
		for (j = 0; j < len; ++j)
			arg[j] = toupper(arg[j]);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check if %s=%s for workflow '%s'\n", key, arg, workflow->name);
		if (!strcmp(key, arg)) {
			*value = strdup(is_task ? workflow->tasks[task_index].arguments_values[i] : workflow->tasks[task_index].light_tasks[light_task_index].arguments_values[i]);
			if (!*value)
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			*index = i;
			return OPH_WORKFLOW_EXIT_SUCCESS;
		}
	}

	return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
}

int oph_workflow_var_substitute(oph_workflow * workflow, int task_index, int light_task_index, char **submit_string, char **error, const char *skip_arg)
{
	if (!workflow || !submit_string || !*submit_string) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null parameter\n");
		if (error)
			*error = strdup("Null parameter");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	unsigned int i, l = strlen(OPH_WORKFLOW_SEPARATORS), offset, skip_until = 0;
	char *p, *ep, firstc, lastc, lastcc, return_error, prefix, *key, *value = NULL, parse_embedded_variable, *replaced_value = NULL, *target_value = NULL;
	oph_workflow_var *var = NULL;
	int index, new_size;

	while (((p = strchr(*submit_string + skip_until, OPH_WORKFLOW_VARIABLE_PREFIX))) || ((p = strchr(*submit_string, OPH_WORKFLOW_INDEX_PREFIX)))) {

		do {
			firstc = 1;
			lastc = lastcc = parse_embedded_variable = 0;
			for (ep = p + 1; *ep; ep++)	// assuming compliance with IEEE Std 1003.1-2001 conventions
			{
				if (firstc) {
					firstc = 0;
					if (*ep == OPH_WORKFLOW_BRACKET[0]) {
						lastc = 1;
						continue;
					}
				}
				if (lastc && (*ep == OPH_WORKFLOW_BRACKET[1])) {
					lastcc = 1;
					break;
				}
				for (i = 0; i < l; ++i)
					if (*ep == OPH_WORKFLOW_SEPARATORS[i]) {
						if ((*ep == OPH_WORKFLOW_VARIABLE_PREFIX) || (*ep == OPH_WORKFLOW_INDEX_PREFIX)) {	// Embedded variable
							p = ep;
							parse_embedded_variable = 1;
						}
						break;
					}
				if (i < l)
					break;
				if (lastc || (*ep == '_') || ((*ep >= 'A') && (*ep <= 'Z')) || ((*ep >= 'a') && (*ep <= 'z')) || ((ep - p > 1) && (*ep >= '0') && (*ep <= '9')))
					continue;
				break;
			}
		}
		while (parse_embedded_variable);

		if (ep < p) {
			char _error[OPH_WORKFLOW_MAX_STRING];
			snprintf(_error, OPH_WORKFLOW_MAX_STRING, "Parsing error");
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s while processing workflow '%s'\n", _error, workflow->name);
			if (error)
				*error = strdup(_error);
			return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
		}

		target_value = (char *) malloc((ep - p + 1) * sizeof(char));
		if (!target_value) {
			char _error[OPH_WORKFLOW_MAX_STRING];
			snprintf(_error, OPH_WORKFLOW_MAX_STRING, "Memory error");
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s while processing workflow '%s'\n", _error, workflow->name);
			if (error)
				*error = strdup(_error);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}

		strncpy(target_value, p, ep - p);
		target_value[ep - p] = 0;
		if (lastcc)
			ep++;

		key = target_value + 1 + lastc;
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found key '%s' in workflow '%s'\n", key, workflow->name);
		if (lastc != lastcc)
			return_error = 1;
		else if (!strlen(key))
			return_error = -1;
		else if (workflow->tasks[task_index].vars && ((var = hashtbl_get(workflow->tasks[task_index].vars, key))))
			return_error = 0;
		else if (workflow->vars && ((var = hashtbl_get(workflow->vars, key))) && oph_workflow_is_child_of(workflow, var->caller, task_index))
			return_error = 0;
		else {
			char *current_arg = NULL;
			if (!skip_arg) {
				char *ck = p;
				while (ck && (ck > *submit_string) && (*ck != OPH_WORKFLOW_KV_SEPARATOR[0]))
					ck--;
				if (ck) {
					if (*ck == OPH_WORKFLOW_KV_SEPARATOR[0])
						ck++;
					char *ek = strchr(ck, OPH_WORKFLOW_VALUE_SEPARATOR);
					if (ek) {
						size_t key_size = ek - ck;
						char current_key[1 + key_size];
						strncpy(current_key, ck, key_size);
						current_key[key_size] = 0;
						current_arg = strdup(current_key);
					}
				}
			}
			if (!oph_workflow_check_args(workflow, task_index, light_task_index, key, &value, &index, skip_arg ? skip_arg : current_arg))
				return_error = -1;
			else
				return_error = 1;
			if (current_arg)
				free(current_arg);
		}
		prefix = *target_value == OPH_WORKFLOW_INDEX_PREFIX;
		if (((return_error > 0) && (*p != OPH_WORKFLOW_VARIABLE_PREFIX)) || (prefix && (return_error < 0) && (index < 0))) {
			char _error[OPH_WORKFLOW_MAX_STRING];
			snprintf(_error, OPH_WORKFLOW_MAX_STRING, "Bad variable '%s' in task '%s'", target_value, workflow->tasks[task_index].name);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%s of workflow '%s'\n", _error, workflow->name);
			if (error)
				*error = strdup(_error);
			if (value)
				free(value);
			free(target_value);
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		} else if (return_error > 0) {
			offset = p - *submit_string + 1;
			if (skip_until < offset)
				skip_until = offset;
			if (value) {
				free(value);
				value = NULL;
			}
			free(target_value);
			continue;
		}
		offset = p - *submit_string;

		if (prefix)
			new_size = 1 + snprintf(NULL, 0, "%d", return_error ? index : var->ivalue) + strlen(ep);
		else
			new_size = 1 + strlen(return_error ? value : (char *) var + sizeof(oph_workflow_var)) + strlen(ep);

		replaced_value = (char *) malloc((new_size + offset) * sizeof(char));
		if (!replaced_value) {
			char _error[OPH_WORKFLOW_MAX_STRING];
			snprintf(_error, OPH_WORKFLOW_MAX_STRING, "Memory error");
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s while processing workflow '%s'\n", _error, workflow->name);
			if (error)
				*error = strdup(_error);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}

		strncpy(replaced_value, *submit_string, offset);
		replaced_value[offset] = 0;
		if (prefix)
			snprintf(replaced_value + offset, new_size, "%d%s", return_error ? index : var->ivalue, ep);
		else
			snprintf(replaced_value + offset, new_size, "%s%s", return_error ? value : (char *) var + sizeof(oph_workflow_var), ep);

		free(*submit_string);
		*submit_string = replaced_value;

		if (value) {
			free(value);
			value = NULL;
		}
		free(target_value);
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_strcat(char **base, char *extension)
{
	if (!base)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (!extension)
		return OPH_WORKFLOW_EXIT_SUCCESS;

	char *new = (char *) malloc(((*base ? strlen(*base) : 0) + strlen(extension) + 1) * sizeof(char));
	if (!new)
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	sprintf(new, "%s%s", *base ? *base : "", extension);

	free(*base);
	*base = new;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_get_submission_string(oph_workflow * workflow, int task_index, int light_task_index, char **long_submission_string, char **short_submission_string, char **error)
{
	if (error)
		*error = NULL;
	if (!workflow || !long_submission_string) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null parameter\n");
		if (error)
			*error = strdup("Null parameter");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	*long_submission_string = NULL;
	if (short_submission_string)
		*short_submission_string = NULL;
	if ((task_index < 0) || (task_index > workflow->tasks_num) || ((task_index == workflow->tasks_num) && strcmp(workflow->tasks[task_index].name, OPH_WORKFLOW_FINAL_TASK))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Index out of boundaries\n");
		if (error)
			*error = strdup("Index out of boundaries");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	int subtask = light_task_index >= 0;
	if (subtask) {
		if (light_task_index >= workflow->tasks[task_index].light_tasks_num) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Index out of boundaries\n");
			if (error)
				*error = strdup("Index out of boundaries");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	size_t max_size = OPH_WORKFLOW_MAX_STRING;
	oph_workflow_get_argument_size(workflow, task_index, &max_size);

	int i, j;
	char *long_submit_string = NULL, *short_submit_string = NULL;
	char key_value[max_size];
	char *key, *value, *value2;
	char *path_key[OPH_WORKFLOW_PATH_SET_SIZE] = OPH_WORKFLOW_PATH_SET;
	char path_value[OPH_WORKFLOW_MAX_STRING];
	char session_code[OPH_WORKFLOW_MAX_STRING];
	if (oph_get_session_code(workflow->sessionid, session_code)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
		if (error)
			*error = strdup("Unable to get session code");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	if (asprintf
	    (&long_submit_string, OPH_WORKFLOW_EXT_SUB_STRING, workflow->tasks[task_index].operator, workflow->sessionid, workflow->workflowid,
	     subtask ? workflow->tasks[task_index].light_tasks[light_task_index].markerid : workflow->tasks[task_index].markerid, workflow->username, workflow->iduser, workflow->userrole,
	     workflow->idjob, task_index, light_task_index, workflow->exec_mode) <= 0) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
		if (long_submit_string)
			free(long_submit_string);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	if (workflow->host_partition) {
		snprintf(key_value, OPH_WORKFLOW_MAX_STRING, OPH_WORKFLOW_KEY_VALUE_STRING, OPH_WORKFLOW_KEY_HOST_PARTITION, workflow->host_partition);
		if (oph_workflow_strcat(&long_submit_string, key_value)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			if (long_submit_string)
				free(long_submit_string);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (workflow->nhosts) {
		snprintf(key_value, OPH_WORKFLOW_MAX_STRING, OPH_WORKFLOW_KEY_VALUE_STRING3, OPH_WORKFLOW_KEY_NHOSTS, workflow->nhosts);
		if (oph_workflow_strcat(&long_submit_string, key_value)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			if (long_submit_string)
				free(long_submit_string);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}

	if (short_submission_string) {
		if (asprintf(&short_submit_string, "%s ", workflow->tasks[task_index].operator) <= 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			if (long_submit_string)
				free(long_submit_string);
			if (short_submit_string)
				free(short_submit_string);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}

	for (j = 0; j < (subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_num : workflow->tasks[task_index].arguments_num); ++j) {
		key = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_keys[j] : workflow->tasks[task_index].arguments_keys[j];
		value = value2 = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_values[j] : workflow->tasks[task_index].arguments_values[j];
		if (key && value && strlen(key) && strlen(value)) {
			// Path correction
			if (value[0] == OPH_WORKFLOW_ROOT_FOLDER[0]) {
				for (i = 0; i < OPH_WORKFLOW_PATH_SET_SIZE; ++i)
					if (!strcmp(key, path_key[i])) {
						snprintf(path_value, OPH_WORKFLOW_MAX_STRING, "%s%s%s", OPH_WORKFLOW_ROOT_FOLDER, session_code, strlen(value) > 1 ? value : "");
						value = path_value;
						break;
					}
			}
			snprintf(key_value, max_size, strchr(value, OPH_WORKFLOW_VALUE_SEPARATOR) ? OPH_WORKFLOW_KEY_VALUE_STRING2 : OPH_WORKFLOW_KEY_VALUE_STRING, key, value);
			if (oph_workflow_strcat(&long_submit_string, key_value)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
				if (long_submit_string)
					free(long_submit_string);
				if (short_submit_string)
					free(short_submit_string);
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			if (short_submission_string) {
				if (value != value2)
					snprintf(key_value, max_size, strchr(value2, OPH_WORKFLOW_VALUE_SEPARATOR) ? OPH_WORKFLOW_KEY_VALUE_STRING2 : OPH_WORKFLOW_KEY_VALUE_STRING, key, value2);
				if (oph_workflow_strcat(&short_submit_string, key_value)) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
					if (long_submit_string)
						free(long_submit_string);
					if (short_submit_string)
						free(short_submit_string);
					return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
				}
			}
		} else
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Argument skipped\n");
	}

	// Variable substitution
	if (oph_workflow_var_substitute(workflow, task_index, light_task_index, &long_submit_string, error, NULL)) {
		if (long_submit_string)
			free(long_submit_string);
		if (short_submit_string)
			free(short_submit_string);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Submission string of '%s' is '%s'\n", workflow->tasks[task_index].name, long_submit_string);
	*long_submission_string = long_submit_string;
	if (short_submission_string) {
		// Variable substitution
		if (oph_workflow_var_substitute(workflow, task_index, light_task_index, &short_submit_string, error, NULL)) {
			if (long_submit_string)
				free(long_submit_string);
			if (short_submit_string)
				free(short_submit_string);
			*long_submission_string = NULL;
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Short submission string of '%s' is '%s'\n", workflow->tasks[task_index].name, short_submit_string);
		*short_submission_string = short_submit_string;
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}


int oph_workflow_get_submitted_string(oph_workflow * workflow, int task_index, int light_task_index, int show_callback, char **submitted_string)
{
	if (!workflow || !submitted_string) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	if ((task_index < 0) || (task_index > workflow->tasks_num) || ((task_index == workflow->tasks_num) && strcmp(workflow->tasks[task_index].name, OPH_WORKFLOW_FINAL_TASK))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Index out of boundaries\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	int subtask = light_task_index >= 0;
	if (subtask) {
		if (light_task_index >= workflow->tasks[task_index].light_tasks_num) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Index out of boundaries\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	size_t max_size = OPH_WORKFLOW_MAX_STRING;
	oph_workflow_get_argument_size(workflow, task_index, &max_size);

	int j;
	char *submit_string = NULL;
	char key_value[max_size];
	char *key, *value;
	if (asprintf(&submit_string, "%s ", workflow->tasks[task_index].operator) <= 0) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
		if (submit_string)
			free(submit_string);
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (workflow->exec_mode && strlen(workflow->exec_mode)) {
		snprintf(key_value, OPH_WORKFLOW_MAX_STRING, strchr(workflow->exec_mode, OPH_WORKFLOW_VALUE_SEPARATOR) ? OPH_WORKFLOW_KEY_VALUE_STRING2 : OPH_WORKFLOW_KEY_VALUE_STRING, "exec_mode",
			 workflow->exec_mode);
		if (oph_workflow_strcat(&submit_string, key_value)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			if (submit_string)
				free(submit_string);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (show_callback && workflow->callback_url && strlen(workflow->callback_url)) {
		snprintf(key_value, OPH_WORKFLOW_MAX_STRING, strchr(workflow->callback_url, OPH_WORKFLOW_VALUE_SEPARATOR)
			 ? OPH_WORKFLOW_KEY_VALUE_STRING2 : OPH_WORKFLOW_KEY_VALUE_STRING, "callback_url", workflow->callback_url);
		if (oph_workflow_strcat(&submit_string, key_value)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			if (submit_string)
				free(submit_string);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	for (j = 0; j < (subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_num : workflow->tasks[task_index].arguments_num); ++j) {
		key = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_keys[j] : workflow->tasks[task_index].arguments_keys[j];
		value = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_values[j]
		    : workflow->tasks[task_index].arguments_values[j];
		if (key && value && strlen(key)
		    && strlen(value)) {
			snprintf(key_value, max_size, strchr(value, OPH_WORKFLOW_VALUE_SEPARATOR)
				 ? OPH_WORKFLOW_KEY_VALUE_STRING2 : OPH_WORKFLOW_KEY_VALUE_STRING, key, value);
			if (oph_workflow_strcat(&submit_string, key_value)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
				if (submit_string)
					free(submit_string);
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
		} else
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Argument skipped\n");
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Submission string of '%s' is '%s'\n", workflow->tasks[task_index].name, submit_string);
	*submitted_string = submit_string;
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_realloc_vector(char ***vector, int *length, int incr)
{
	if (!vector || !(*vector) || !length)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	char **tmp = *vector;
	*vector = (char **) malloc((*length + incr) * sizeof(char *));

	if (!(*vector)) {
		*vector = tmp;
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	memcpy(*vector, tmp, *length * sizeof(char *));
	free(tmp);

	memset(*vector + *length, 0, incr * sizeof(char *));
	*length += incr;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_realloc_vector2(oph_workflow_ordered_list *** vector, int *length, int incr)
{
	if (!vector || !(*vector) || !length)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	oph_workflow_ordered_list **tmp = *vector;
	*vector = (oph_workflow_ordered_list **) malloc((*length + incr) * sizeof(oph_workflow_ordered_list *));

	if (!(*vector)) {
		*vector = tmp;
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	memcpy(*vector, tmp, *length * sizeof(oph_workflow_ordered_list *));
	free(tmp);

	memset(*vector + *length, 0, incr * sizeof(oph_workflow_ordered_list *));
	*length += incr;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Other utililty functions
