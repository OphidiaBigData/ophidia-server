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

#include "oph_flow_control_operators.h"

#include "oph_ophidiadb.h"
#include "oph_json_library.h"
#include "oph_workflow_engine.h"
#include "oph_subset_library.h"

#include <math.h>

#ifdef MATHEVAL_SUPPORT
#include <matheval.h>
#endif

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

extern int oph_finalize_known_operator(int idjob, oph_json * oper_json, const char *operator_name, char *error_message, int success, char **response, ophidiadb * oDB,
				       enum oph__oph_odb_job_status *exit_code);

// Thread unsafe
int oph_set_status_of_selection_block(oph_workflow * wf, int task_index, enum oph__oph_odb_job_status status, int parent, int nk, int skip_the_next, int *exit_output)
{
	if (wf->tasks[task_index].dependents_indexes_num) {
		if (!wf->tasks[task_index].dependents_indexes) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		int i, j, k, res, gparent;
		for (k = 0; k < wf->tasks[task_index].dependents_indexes_num; ++k) {
			if (nk < 0)
				nk = k;
			i = wf->tasks[task_index].dependents_indexes[k];
			if (wf->tasks[i].parent == parent) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found '%s' child of task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
				if (strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE))
					wf->tasks[i].is_skipped = skip_the_next;
				else if (wf->tasks[i].branch_num > 1) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Drop dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
					wf->tasks[parent].dependents_indexes[nk] = parent;
					for (j = 0; j < wf->tasks[i].deps_num; ++j)
						if (wf->tasks[i].deps[j].task_index == task_index)
							wf->tasks[i].deps[j].task_index = i;
					wf->tasks[i].residual_deps_num--;
				} else {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Set dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
					wf->tasks[parent].dependents_indexes[nk] = i;
					for (j = 0; j < wf->tasks[i].deps_num; ++j)
						if (wf->tasks[i].deps[j].task_index == task_index)
							wf->tasks[i].deps[j].task_index = parent;
					if (exit_output && !strncasecmp(wf->tasks[parent].operator, OPH_OPERATOR_IF, OPH_MAX_STRING_SIZE))
						*exit_output = 0;
				}
				continue;
			}
			gparent = oph_gparent_of(wf, parent);
			if (!strncasecmp(wf->tasks[i].operator, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE) && (wf->tasks[i].parent == gparent)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Drop dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
				wf->tasks[gparent].dependents_indexes[nk] = i;
				for (j = 0; j < wf->tasks[i].deps_num; ++j)
					if (wf->tasks[i].deps[j].task_index == task_index)
						wf->tasks[i].deps[j].task_index = gparent;
				wf->tasks[i].residual_deps_num--;
			} else {
				if (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED) {
					if (!wf->residual_tasks_num) {
						pmesg(LOG_WARNING, __FILE__, __LINE__, "Number of residual tasks of '%s' cannot be reduced\n", wf->tasks[i].name);
						return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
					}
					wf->residual_tasks_num--;
				}
				wf->tasks[i].status = status;
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Status of '%s' is set to '%s'\n", wf->tasks[i].name, oph_odb_convert_status_to_str(status));
				if ((res = oph_set_status_of_selection_block(wf, i, status, parent, nk, skip_the_next, exit_output)))
					return res;
			}
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_if_impl(oph_workflow * wf, int i, char *error_message, int *exit_output)
{
	int j, check = 0;
	if (!wf->tasks[i].is_skipped) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract arguments of task '%s'.\n", wf->tasks[i].name);

		char arg_value[OPH_WORKFLOW_MAX_STRING], *condition = NULL, *error_msg = NULL;

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j = 0; j < wf->tasks[i].arguments_num; ++j)
			if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_CONDITION)) {
				snprintf(arg_value, OPH_WORKFLOW_MAX_STRING, "%s", wf->tasks[i].arguments_values[j]);
				if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg))
					break;
				condition = arg_value;
				break;
			}
		if (error_msg) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", error_msg);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			free(error_msg);
			return OPH_SERVER_ERROR;
		}
		if (condition && strlen(condition)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Evaluate expression '%s'.\n", condition);

			// Evaluate expression
			int count;
			char **names;
			void *me = evaluator_create(condition);
			evaluator_get_variables(me, &names, &count);
			if (count > 0) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Too variables in the expression '%s'!", condition);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				evaluator_destroy(me);
				return OPH_SERVER_ERROR;
			}
			double return_value = evaluator_evaluate(me, count, names, NULL);
			evaluator_destroy(me);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Expression '%s' = %f.\n", condition, return_value);
			if (isnan(return_value) || isinf(return_value)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Wrong condition '%s'!", condition);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				return OPH_SERVER_ERROR;
			}
			// In case condition is not satisfied...
			if (!return_value)
				wf->tasks[i].is_skipped = 1;
		}
		check = 1;
	}
	if (wf->tasks[i].is_skipped) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Skip the selection block associated with task '%s'.\n", wf->tasks[i].name);

		// Skip this sub-block
		if (oph_set_status_of_selection_block(wf, i, OPH_ODB_STATUS_SKIPPED, i, -1, !check, exit_output)) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Error in updating the status of dependents of '%s'.", wf->tasks[i].name);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s\n", error_message);
		}
		if (check)
			wf->tasks[i].is_skipped = 0;
	} else			// Condition is satisfied
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Execute the selection block associated with task '%s'.\n", wf->tasks[i].name);

		for (j = 0; j < wf->tasks_num; ++j)
			if ((wf->tasks[j].parent == i) && strncasecmp(wf->tasks[j].operator, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE)) {
				wf->tasks[j].is_skipped = 1;
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Task '%s' and related branch of workflow '%s' will be skipped.\n", wf->tasks[j].name, wf->name);
			}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_else_impl(oph_workflow * wf, int i, char *error_message, int *exit_output)
{
	if (wf->tasks[i].is_skipped) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Skip the selection block associated with task '%s'.\n", wf->tasks[i].name);

		// Skip this sub-block
		if (oph_set_status_of_selection_block(wf, i, OPH_ODB_STATUS_SKIPPED, i, -1, 0, exit_output)) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Error in updating the status of dependents of '%s'.", wf->tasks[i].name);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "%s\n", error_message);
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_extract_from_json(char **key, const char *json_string)
{
	if (!key || !(*key) || !json_string)
		return OPH_SERVER_ERROR;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parsing '%s'\n", *key);
	char tmp[1 + strlen(*key)], *pch = NULL, *save_pointer = NULL, *target = NULL, *objkey = NULL, *title = NULL, *colkey = NULL, *row = NULL, *col = NULL;
	strcpy(tmp, *key);

	int step = 0;
	while ((pch = strtok_r(pch ? NULL : tmp, OPH_WORKFLOW_OBJECT, &save_pointer))) {
		switch (step) {
			case 0:
				objkey = pch;
				break;
			case 1:
				title = pch;
				break;
			case 2:
				colkey = pch;
				break;
			default:
				return OPH_SERVER_ERROR;
		}
		target = pch;
		step++;
	}
	if (!step)
		return OPH_SERVER_ERROR;

	while (1) {
		pch = strchr(target, OPH_WORKFLOW_BRACKET_BEGIN[0]);
		step = 0;

		if (!pch)
			break;
		*pch = 0;
		row = pch + 1;
		step = 1;	// Bracket open

		pch = strchr(row, OPH_WORKFLOW_SEPARATORS[3]);
		if (!pch) {
			if (!colkey)
				break;
			pch = strchr(row, OPH_WORKFLOW_BRACKET_END[0]);
			if (!pch)
				break;
			*pch = 0;
			step = 2;	// Bracket closed, row by index, col by name
			break;
		}
		*pch = 0;
		col = pch + 1;
		step = 3;	// Bracket open, row and col by index

		pch = strchr(col, OPH_WORKFLOW_BRACKET_END[0]);
		if (!pch)
			break;
		*pch = 0;
		step = 4;	// Bracket closed, row and col by index

		break;
	}
	if (!pch && step) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: syntax error\n");
		return OPH_SERVER_ERROR;
	}

	oph_json *json = NULL;
	if (oph_json_from_json_string_unsafe(&json, json_string)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: json lookup failed\n");
		if (json)
			oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	unsigned int i, j = 0, k = json->response_num;
	for (i = 0; i < json->response_num; ++i)
		if (json->response && json->response[i].objkey && !strcmp(json->response[i].objkey, objkey))
			break;
	if (i >= json->response_num) {
		if (colkey) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objkey not found\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		// Let us assume the form title[.colname]
		colkey = title;
		title = objkey;
		for (i = 0; i < json->response_num; ++i)
			if (json->response && json->response[i].objkey && json->response[i].objclass) {
				if (!strcmp(json->response[i].objclass, OPH_JSON_TEXT)) {
					oph_json_obj_text *obj = NULL;
					for (j = 0; j < json->response[i].objcontent_num; ++j)
						if (json->response[i].objcontent) {
							obj = (oph_json_obj_text *) (json->response[i].objcontent) + j;
							if (obj && obj->title && !strcmp(obj->title, title)) {
								if (k < json->response_num)
									break;
								else
									k = i;
							}
						}
				} else if (!strcmp(json->response[i].objclass, OPH_JSON_GRID)) {
					oph_json_obj_grid *obj = NULL;
					for (j = 0; j < json->response[i].objcontent_num; ++j)
						if (json->response[i].objcontent) {
							obj = (oph_json_obj_grid *) (json->response[i].objcontent) + j;
							if (obj && obj->title && !strcmp(obj->title, title)) {
								if (k < json->response_num)
									break;
								else
									k = i;
							}
						}
				}
				if (j < json->response[i].objcontent_num)
					break;
			}
		if (i < json->response_num) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: more than one objcontent found\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		} else if (k >= json->response_num) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		i = k;
		objkey = json->response[i].objkey;
	}

	if (!json->response[i].objclass) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objclass not found\n");
		if (json)
			oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	unsigned int objcontent_num = 0;
	k = json->response[i].objcontent_num;
	if (!strcmp(json->response[i].objclass, OPH_JSON_TEXT)) {
		oph_json_obj_text *obj = NULL;
		for (j = 0; j < json->response[i].objcontent_num; ++j)
			if (json->response[i].objcontent) {
				obj = (oph_json_obj_text *) (json->response[i].objcontent) + j;
				if (obj) {
					objcontent_num++;
					if (title) {
						if (obj->title && !strcmp(obj->title, title))
							break;
					} else
						k = j;
				}
			}
		if ((j >= json->response[i].objcontent_num) && (title || (objcontent_num != 1))) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		if (!title) {
			obj = (oph_json_obj_text *) (json->response[i].objcontent) + k;
			title = obj->title;
			if (!title) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
				if (json)
					oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		free(*key);
		*key = strdup(obj->message);
		if (!(*key)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Key updated to '%s'\n", *key);
	} else if (!strcmp(json->response[i].objclass, OPH_JSON_GRID)) {
		oph_json_obj_grid *obj = NULL;
		for (j = 0; j < json->response[i].objcontent_num; ++j)
			if (json->response[i].objcontent) {
				obj = (oph_json_obj_grid *) (json->response[i].objcontent) + j;
				if (obj) {
					objcontent_num++;
					if (title) {
						if (obj->title && !strcmp(obj->title, title))
							break;
					} else
						k = j;
				}
			}
		if ((j >= json->response[i].objcontent_num) && (title || (objcontent_num != 1))) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		if (!title) {
			obj = (oph_json_obj_grid *) (json->response[i].objcontent) + k;
			title = obj->title;
			if (!title) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
				if (json)
					oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		unsigned int irow = 0, icol = 0;
		char all_values = 0;
		if (colkey) {
			if (obj->keys)
				for (; icol < obj->keys_num; ++icol)
					if (!strcmp(obj->keys[icol], colkey))
						break;
			if (!obj->keys || (icol >= obj->keys_num)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: rowkey not found\n");
				if (json)
					oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found key '%s' at column %d\n", colkey, icol);
		} else {
			if (col && !strcmp(col, OPH_WORKFLOW_GENERIC_VALUE))
				all_values = 2;
			else {
				icol = col ? (unsigned int) strtol(col, NULL, 10) : 0;
				if (icol)
					icol--;	// Non 'C'-like indexing
			}
		}
		if (row && !strcmp(row, OPH_WORKFLOW_GENERIC_VALUE)) {
			if (all_values) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: only scalars and vectors can be extracted\n");
				if (json)
					oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
			all_values = 1;
		} else {
			irow = row ? (unsigned int) strtol(row, NULL, 10) : 0;
			if (irow)
				irow--;	// Non 'C'-like indexing
		}

		if ((irow >= obj->values_num1) || (icol >= obj->values_num2)) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: index out of boundaries\n");
			if (json)
				oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		free(*key);
		*key = NULL;
		if (all_values) {
			char *tmp_key = NULL;
			switch (all_values) {
				case 1:	// All the rows
					if (obj->values_num1)
						*key = strdup(obj->values[0][icol]);
					for (irow = 1; irow < obj->values_num1; irow++) {
						tmp_key = *key;
						*key = (char *) malloc(strlen(tmp_key) + 2 + strlen(obj->values[irow][icol]));
						if (!(*key)) {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
							if (tmp_key)
								free(tmp_key);
							if (json)
								oph_json_free(json);
							return OPH_SERVER_ERROR;
						}
						sprintf(*key, "%s%s%s", tmp_key, OPH_SEPARATOR_SUBPARAM_STR, obj->values[irow][icol]);
						if (tmp_key)
							free(tmp_key);
						tmp_key = NULL;
					}
					break;
				case 2:	// All the columns
					if (obj->values_num2)
						*key = strdup(obj->values[irow][0]);
					for (icol = 1; icol < obj->values_num2; icol++) {
						tmp_key = *key;
						*key = (char *) malloc(strlen(tmp_key) + 2 + strlen(obj->values[irow][icol]));
						if (!(*key)) {
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
							if (tmp_key)
								free(tmp_key);
							if (json)
								oph_json_free(json);
							return OPH_SERVER_ERROR;
						}
						sprintf(*key, "%s%s%s", tmp_key, OPH_SEPARATOR_SUBPARAM_STR, obj->values[irow][icol]);
						if (tmp_key)
							free(tmp_key);
						tmp_key = NULL;
					}
					break;
				default:
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: wrong condition\n");
					if (json)
						oph_json_free(json);
					return OPH_SERVER_ERROR;
			}
		} else {
			*key = strdup(obj->values[irow][icol]);
			if (!(*key)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
				if (json)
					oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Key '%s' updated to '%s'\n", title, *key);
	} else {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objclass not supported\n");
		if (json)
			oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	if (json)
		oph_json_free(json);
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_for_impl(oph_workflow * wf, int i, char *error_message, char is_for)
{
	char *pch, *save_pointer = NULL, *name = NULL, **svalues = NULL, mode = 0;
	int *ivalues = NULL;	// If not allocated then it is equal to [1:values_num]
	int j, kk = 0, h, hh, svalues_num = 0, ivalues_num = 0;
	unsigned int kkk, lll = strlen(OPH_WORKFLOW_SEPARATORS);
	long value;
	char arg_value[OPH_WORKFLOW_MAX_STRING], *error_msg = NULL;

	int success = 0, ret = OPH_SERVER_OK;
	while (!success) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract arguments of task '%s'.\n", wf->tasks[i].name);

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			snprintf(arg_value, OPH_WORKFLOW_MAX_STRING, "%s", wf->tasks[i].arguments_values[j]);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", wf->tasks[i].arguments_keys[j], wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg)) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg)
					free(error_msg);
				ret = OPH_SERVER_ERROR;
				break;
			}

			if (!strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_NAME) && !name)
				name = wf->tasks[i].arguments_values[j];	// it should not be 'arg_value'!
			else if (((is_for && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_VALUES))
				  || (!is_for && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_VALUE))) && !svalues && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				char *tmp = strdup(arg_value), expansion, *pch1;
				if (!tmp)
					break;
				do {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Values parsing: %s\n", tmp);
					expansion = svalues_num = 0;
					pch = strchr(tmp, OPH_SEPARATOR_SUBPARAM);
					for (svalues_num++; pch; svalues_num++) {
						pch1 = pch + 1;
						if (!pch1 || !*pch1)
							break;
						pch = strchr(pch1, OPH_SEPARATOR_SUBPARAM);
					}
					svalues = (char **) malloc(svalues_num * sizeof(char *));
					if (!svalues)
						break;
					pch = strtok_r(tmp, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
					for (kk = 0; kk < svalues_num; ++kk) {
						svalues[kk] = strndup(pch, OPH_WORKFLOW_MAX_STRING);
						if (!svalues[kk])
							break;
						// Begin check in input JSON Response
						for (h = 0; h < wf->tasks_num; ++h)
							if (wf->tasks[h].response) {
								for (hh = 0; hh < wf->tasks[h].dependents_indexes_num; ++hh)
									if (wf->tasks[h].dependents_indexes[hh] == i) {
										if (!oph_extract_from_json(svalues + kk, wf->tasks[h].response))	// Found a correspondence
										{
											if (strchr(svalues[kk], OPH_SEPARATOR_SUBPARAM)) {
												hh = 0;
												char expanded_value[1 + strlen(arg_value) + strlen(svalues[kk])];
												for (h = 0; h < kk; ++h)
													hh = sprintf(expanded_value + hh, "%s%c", svalues[h], OPH_SEPARATOR_SUBPARAM);
												hh = sprintf(expanded_value + hh, "%s", svalues[kk]);
												pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
												if (pch)
													sprintf(expanded_value + hh, "%c%s", OPH_SEPARATOR_SUBPARAM, pch);
												pmesg(LOG_DEBUG, __FILE__, __LINE__, "Values expansion: %s\n", expanded_value);
												free(tmp);
												tmp = strdup(expanded_value);
												for (h = 0; h <= kk; ++h)
													free(svalues[h]);
												free(svalues);
												expansion = 1;
											}
											break;
										}
									}
								if (expansion || (hh < wf->tasks[h].dependents_indexes_num))
									break;
							}
						// End check
						if (!expansion)
							pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
					}
				}
				while (expansion);
				free(tmp);
				if (kk < svalues_num)
					break;
				if (!is_for && (svalues_num > 1))
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Only the first value of the list will be considered\n");
			} else if (is_for && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_PARALLEL) && !mode) {
				if (!strcasecmp(arg_value, OPH_COMMON_YES))
					mode = 1;
				else if (strcasecmp(arg_value, OPH_COMMON_NO))
					break;
			}
		}
		if ((j < wf->tasks[i].arguments_num) || error_msg) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Generic error in parsing arguments of task '%s'.\n", wf->tasks[i].name);
			ret = OPH_SERVER_ERROR;
			break;
		}
		for (j = 0; j < wf->tasks[i].arguments_num; ++j) {
			snprintf(arg_value, OPH_WORKFLOW_MAX_STRING, "%s", wf->tasks[i].arguments_values[j]);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg)) {
				snprintf(error_message, OPH_WORKFLOW_MAX_STRING, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg)
					free(error_msg);
				ret = OPH_SERVER_ERROR;
				break;
			}

			if (is_for && !strcasecmp(wf->tasks[i].arguments_keys[j], OPH_OPERATOR_PARAMETER_COUNTER) && !ivalues && strcasecmp(arg_value, OPH_COMMON_NULL)) {
				oph_subset *subset_struct = NULL;
				if (oph_subset_init(&subset_struct)) {
					oph_subset_free(subset_struct);
					break;
				}
				if (oph_subset_parse(arg_value, strlen(arg_value), subset_struct, svalues_num)) {
					oph_subset_free(subset_struct);
					break;
				}
				ivalues_num = subset_struct->total;
				ivalues = (int *) malloc(ivalues_num * sizeof(int));
				if (!ivalues) {
					oph_subset_free(subset_struct);
					break;
				}
				for (kk = kkk = 0; (kk < ivalues_num) && (kkk < subset_struct->number); ++kkk) {
					value = subset_struct->start[kkk];
					do {
						ivalues[kk++] = (int) value;
						value += subset_struct->stride[kkk];
					}
					while ((kk < ivalues_num) && (value <= subset_struct->end[kkk]));
				}
				oph_subset_free(subset_struct);
			}
		}
		if ((j < wf->tasks[i].arguments_num) || error_msg) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Generic error in parsing arguments of task '%s'.\n", wf->tasks[i].name);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (name) {
			snprintf(arg_value, OPH_WORKFLOW_MAX_STRING, "%s", name);

			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check for variables in argument '%s' of task '%s'.\n", OPH_OPERATOR_PARAMETER_NAME, wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "%s", error_msg ? error_msg : "Error in variable substitution!");
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg)
					free(error_msg);
				ret = OPH_SERVER_ERROR;
				break;
			}
			name = arg_value;
		}

		if (name)
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Check compliance of variable name '%s' of task '%s' with IEEE Std 1003.1-2001 conventions.\n", name, wf->tasks[i].name);
		for (kk = 0; name && (kk < (int) strlen(name)); ++kk)	// check compliance with IEEE Std 1003.1-2001 conventions
		{
			if ((name[kk] == '_') || ((name[kk] >= 'A') && (name[kk] <= 'Z')) || ((name[kk] >= 'a') && (name[kk] <= 'z')) || (kk && (name[kk] >= '0') && (name[kk] <= '9')))
				continue;
			for (kkk = 0; kkk < lll; ++kkk)
				if (name[kk] == OPH_WORKFLOW_SEPARATORS[kkk]) {
					name = NULL;
					break;
				}
			if (name)
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Change variable name '%s'.", name);
			break;
		}
		if (!name) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Bad argument '%s'.", OPH_OPERATOR_PARAMETER_NAME);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (mode) {
			if (ivalues) {
				free(ivalues);
				ivalues = NULL;
			}
			if (svalues) {
				for (kk = 0; kk < svalues_num; ++kk)
					if (svalues[kk])
						free(svalues[kk]);
				free(svalues);
				svalues = NULL;
			}
			svalues_num = 1;	// Parallel for involves only one loop
		} else if (svalues_num) {
			if (ivalues_num && (ivalues_num != svalues_num)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Arguments '%s' and '%s' have different sizes.", OPH_OPERATOR_PARAMETER_VALUES, OPH_OPERATOR_PARAMETER_COUNTER);
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
		} else
			svalues_num = ivalues_num ? ivalues_num : 1;	// One loop is executed by default

		if (!mode && (svalues_num > 0)) {
			if (!is_for)	// Drop the previous value in case of oph_set
			{
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Drop variable '%s'\n", name);
				hashtbl_remove(wf->vars, name);
			}

			oph_workflow_var var;
			var.caller = i;
			if (ivalues)
				var.ivalue = ivalues[0];
			else
				var.ivalue = 1;	// Non C-like indexing
			if (svalues)
				strcpy(var.svalue, svalues[0]);
			else
				snprintf(var.svalue, OPH_WORKFLOW_MAX_STRING, "%d", var.ivalue);

			if (svalues)
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s=%s' in environment of workflow '%s'.\n", name, var.svalue, wf->name);
			else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s=%d' in environment of workflow '%s'.\n", name, var.ivalue, wf->name);
			if (hashtbl_insert_with_size(wf->vars, name, (void *) &var, sizeof(oph_workflow_var))) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to store variable '%s' in environment of workflow '%s'. Maybe it already exists.", name, wf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
			// Push them into the stack, even in case only one loop has to be performed
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Push for-data into the stack of workflow '%s'.\n", wf->name);
			if (is_for && oph_workflow_push(wf, i, name, svalues, ivalues, svalues_num)) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to push for-data into the stack of workflow '%s'.", wf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_SYSTEM_ERROR;
				break;
			}
		}

		success = 1;
	}

	if (!success || !is_for) {
		if (ivalues)
			free(ivalues);
		if (svalues) {
			for (kk = 0; kk < svalues_num; ++kk)
				if (svalues[kk])
					free(svalues[kk]);
			free(svalues);
		}
	}

	return ret;
}

// Thread unsafe
int oph_endfor_impl(oph_workflow * wf, int i, char *error_message, oph_trash * trash, int *task_id, int *odb_jobid)
{
	// Find the data inserted by the parent within the stack
	oph_workflow_stack *tmp = wf->stack, *tmpp = NULL;
	while (tmp && (tmp->caller != wf->tasks[i].parent)) {
		tmpp = tmp;
		tmp = tmp->next;
	}
	if (tmp) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update index '%s' set by task '%s' in environment of workflow '%s'.\n", tmp->name, wf->tasks[tmp->caller].name, wf->name);

		tmp->index++;
		if (hashtbl_remove(wf->vars, tmp->name))	// Skip this in the last step to extend the scope of the variable to any descendent
		{
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to remove variable '%s' from environment of workflow '%s'.", tmp->name, wf->name);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (tmp->index < tmp->values_num) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Create variable '%s' to be stored in environment of workflow '%s'.\n", tmp->name, wf->name);
			oph_workflow_var var;
			var.caller = tmp->caller;
			if (tmp->ivalues)
				var.ivalue = tmp->ivalues[tmp->index];
			else
				var.ivalue = 1 + tmp->index;	// Non C-like indexing
			if (tmp->svalues)
				strcpy(var.svalue, tmp->svalues[tmp->index]);
			else
				snprintf(var.svalue, OPH_WORKFLOW_MAX_STRING, "%d", var.ivalue);

			if (tmp->svalues)
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update variable '%s=%s' in environment of workflow '%s'.\n", tmp->name, var.svalue, wf->name);
			else
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update variable '%s=%d' in environment of workflow '%s'.\n", tmp->name, var.ivalue, wf->name);
			if (hashtbl_insert_with_size(wf->vars, tmp->name, (void *) &var, sizeof(oph_workflow_var))) {
				snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to update variable '%s' in environment of workflow '%s'.", tmp->name, wf->name);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			if (odb_jobid)	// Reset status
			{
				int p = wf->tasks[i].parent, tasks_num = 0;

				*odb_jobid = wf->tasks[p].idjob;	// Used to change 'jobid' in notification message to oph_for
				*task_id = p;	// Used to change 'taskindex' in notification message to oph_for

				oph_odb_remove_job(wf->tasks[i].idjob);	// Drop line of oph_endfor from OphDB

				if (oph_trash_append(trash, wf->sessionid, wf->tasks[i].markerid))
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Unable to release markerid.\n");
				else
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Release markerid '%d'.\n", wf->tasks[i].markerid);

				if (oph_workflow_reset_task(wf, wf->tasks[p].dependents_indexes, wf->tasks[p].dependents_indexes_num, i, tmp, &tasks_num)) {
					snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to reset task data from '%s'.", wf->tasks[p].name);
					pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
				} else
					wf->residual_tasks_num += tasks_num;

				if (wf->tasks[p].outputs_num) {
					oph_output_data_free(wf->tasks[p].outputs_keys, wf->tasks[p].outputs_num);
					oph_output_data_free(wf->tasks[p].outputs_values, wf->tasks[p].outputs_num);
					wf->tasks[p].outputs_num = 0;
					wf->tasks[p].outputs_keys = wf->tasks[p].outputs_values = NULL;
				}

				return OPH_SERVER_NO_RESPONSE;
			}
		} else
			wf->tasks[i].parallel_mode = 1;	// used to trasform the end-for in a massive operator

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Pop for-data from the stack of workflow '%s'.\n", wf->name);
		if (oph_workflow_pop(wf, tmpp)) {
			snprintf(error_message, OPH_MAX_STRING_SIZE, "Unable to pop for-data from the stack of workflow '%s'.", wf->name);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "%s\n", error_message);
			return OPH_SERVER_SYSTEM_ERROR;
		}
	} else {
		snprintf(error_message, OPH_MAX_STRING_SIZE, "No index found in environment of workflow '%s'.", wf->name);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s\n", error_message);
	}

	return OPH_SERVER_OK;
}

int oph_serve_flow_control_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id, int *light_task_id,
				    int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, const char *operator_name)
{
	UNUSED(ncores);
	UNUSED(request);
	UNUSED(jobid_response);

	int error = OPH_SERVER_UNKNOWN;

	if (!strncasecmp(operator_name, OPH_OPERATOR_FOR, OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name, OPH_OPERATOR_SET, OPH_MAX_STRING_SIZE)) {
		char is_for = !strncasecmp(operator_name, OPH_OPERATOR_FOR, OPH_MAX_STRING_SIZE);

		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;

		int i = *task_id, idjob = wf->tasks[i].idjob;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
		}

		if (success) {
			int ret = oph_for_impl(wf, i, error_message, is_for);
			if (ret) {
				success = 0;
				if (ret == OPH_SERVER_SYSTEM_ERROR) {
					pthread_mutex_unlock(&global_flag);
					oph_json_free(oper_json);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success)
			*error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_ENDFOR, OPH_MAX_STRING_SIZE)) {
		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, ret;

		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in executing oph_endif!");

		ret = oph_endfor_impl(wf, i, error_message, state->trash, task_id, odb_jobid);
		if (ret) {
			pthread_mutex_unlock(&global_flag);
			return ret;
		}
		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success)
			*error_message = 0;
		if (oph_finalize_known_operator(wf->tasks[i].idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_IF, OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name, OPH_OPERATOR_ELSEIF, OPH_MAX_STRING_SIZE))	// oph_if, oph_elseif
	{
#ifndef MATHEVAL_SUPPORT
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to execute %s. Matheval is not available\n", operator_name);
		return OPH_SERVER_SYSTEM_ERROR;
#endif
		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
		}

		if (success) {
			if (oph_if_impl(wf, i, error_message, exit_output))
				success = 0;
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success)
			*error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	} else if (!strncasecmp(operator_name, OPH_OPERATOR_ELSE, OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name, OPH_OPERATOR_ENDIF, OPH_MAX_STRING_SIZE))	// oph_else, oph_endif
	{
#ifndef MATHEVAL_SUPPORT
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to execute %s. Matheval is not available\n", operator_name);
		return OPH_SERVER_SYSTEM_ERROR;
#endif
		if (!task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info *item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow *wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;

		// JSON Response creation
		int success = 0;
		oph_json *oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message, OPH_MAX_STRING_SIZE, "Failure in obtaining JSON data!");
		while (!success) {
			if (oph_json_alloc(&oper_json)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json, "oph", "Ophidia", NULL, "Ophidia Data Source", wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Session Code", session_code)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE, "%d", wf->workflowid);
			if (oph_json_add_source_detail(oper_json, "Workflow", workflowid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json, "Marker", markerid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid, OPH_MAX_STRING_SIZE, "%s%s%s%s%s", sessionid, OPH_SESSION_WORKFLOW_DELIMITER, workflowid, OPH_SESSION_MARKER_DELIMITER, markerid);
			if (oph_json_add_source_detail(oper_json, "JobID", oph_jobid)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				break;
			}
			if (oph_json_add_consumer(oper_json, wf->username)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				break;
			}

			success = 1;
		}

		if (success && !strncasecmp(operator_name, OPH_OPERATOR_ELSE, OPH_MAX_STRING_SIZE)) {
			if (oph_else_impl(wf, i, error_message, exit_output))
				success = 0;
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if (oph_odb_read_config_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (oph_odb_connect_to_ophidiadb(&oDB)) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success)
			*error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code))
			return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}

	return error;
}
