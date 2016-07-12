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

#include "oph_known_operators.h"

#include "oph_auth.h"
#include "oph_ophidiadb.h"
#include "oph_json_library.h"
#include "oph_task_parser_library.h"
#include "oph_workflow_engine.h"
#include "oph_subset_library.h"

#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <math.h>

#ifdef MATHEVAL_SUPPORT
#include <matheval.h>
#endif

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_cond_t termination_flag;
#endif
extern char* oph_web_server;
extern char* oph_log_file_name;
extern char* oph_auth_location;

// Thread unsafe
int oph_set_status_of_selection_block(oph_workflow *wf, int task_index, enum oph__oph_odb_job_status status, int parent, int nk, int skip_the_next, int* exit_output)
{
	if (wf->tasks[task_index].dependents_indexes_num)
	{
		if (!wf->tasks[task_index].dependents_indexes)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__, "Null pointer\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		int i,j,k,res,gparent;
		for (k=0;k<wf->tasks[task_index].dependents_indexes_num;++k)
		{
			if (nk<0) nk=k;
			i = wf->tasks[task_index].dependents_indexes[k];
			if (wf->tasks[i].parent == parent)
			{
				pmesg(LOG_DEBUG, __FILE__,__LINE__, "Found '%s' child of task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
				if (strncasecmp(wf->tasks[i].operator,OPH_OPERATOR_ENDIF,OPH_MAX_STRING_SIZE)) wf->tasks[i].is_skipped = skip_the_next;
				else if (wf->tasks[i].branch_num > 1)
				{
					pmesg(LOG_DEBUG, __FILE__,__LINE__, "Drop dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
					wf->tasks[parent].dependents_indexes[nk] = parent;
					for (j=0;j<wf->tasks[i].deps_num;++j) if (wf->tasks[i].deps[j].task_index == task_index) wf->tasks[i].deps[j].task_index = i;
					wf->tasks[i].residual_deps_num--;
				}
				else
				{
					pmesg(LOG_DEBUG, __FILE__,__LINE__, "Set dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
					wf->tasks[parent].dependents_indexes[nk] = i;
					for (j=0;j<wf->tasks[i].deps_num;++j) if (wf->tasks[i].deps[j].task_index == task_index) wf->tasks[i].deps[j].task_index = parent;
					if (exit_output && !strncasecmp(wf->tasks[parent].operator,OPH_OPERATOR_IF,OPH_MAX_STRING_SIZE)) *exit_output = 0;
				}
				continue;
			}
			gparent = oph_gparent_of(wf,parent);
			if (!strncasecmp(wf->tasks[i].operator,OPH_OPERATOR_ENDIF,OPH_MAX_STRING_SIZE) && (wf->tasks[i].parent == gparent))
			{
				pmesg(LOG_DEBUG, __FILE__,__LINE__, "Drop dependence to '%s' from task '%s' of workflow '%s'\n", wf->tasks[i].name, wf->tasks[parent].name, wf->name);
				wf->tasks[gparent].dependents_indexes[nk] = i;
				for (j=0;j<wf->tasks[i].deps_num;++j) if (wf->tasks[i].deps[j].task_index == task_index) wf->tasks[i].deps[j].task_index = gparent;
				wf->tasks[i].residual_deps_num--;
			}
			else
			{
				if (wf->tasks[i].status < OPH_ODB_STATUS_COMPLETED)
				{
					if (!wf->residual_tasks_num)
					{
						pmesg(LOG_WARNING, __FILE__,__LINE__, "Number of residual tasks of '%s' cannot be reduced\n",wf->tasks[i].name);
						return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
					}
					wf->residual_tasks_num--;
				}
				wf->tasks[i].status = status;
				pmesg(LOG_DEBUG, __FILE__,__LINE__, "Status of '%s' is set to '%s'\n",wf->tasks[i].name,oph_odb_convert_status_to_str(status));
				if ((res = oph_set_status_of_selection_block(wf, i, status, parent, nk, skip_the_next, exit_output))) return res;
			}
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_if_impl(oph_workflow* wf, int i, char* error_message, int *exit_output)
{
	int j, check = 0;
	if (!wf->tasks[i].is_skipped)
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__, "Extract arguments of task '%s'.\n",wf->tasks[i].name);

		char arg_value[OPH_WORKFLOW_MAX_STRING], *condition = NULL, *error_msg = NULL;

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j=0;j<wf->tasks[i].arguments_num;++j) if (!strcasecmp(wf->tasks[i].arguments_keys[j],OPH_OPERATOR_PARAMETER_CONDITION))
		{
			snprintf(arg_value,OPH_WORKFLOW_MAX_STRING,"%s",wf->tasks[i].arguments_values[j]);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg)) break;
			condition = arg_value;
			break;
		}
		if (error_msg)
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"%s",error_msg);
			pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
			free(error_msg);
			return OPH_SERVER_ERROR;
		}
		if (condition && strlen(condition))
		{
			pmesg(LOG_DEBUG, __FILE__,__LINE__, "Evaluate expression '%s'.\n",condition);

			// Evaluate expression
			int count;
			char** names;
			void *me = evaluator_create(condition);
			evaluator_get_variables(me, &names, &count);
			if (count>0)
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Too variables in the expression '%s'!", condition);
				pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
				evaluator_destroy(me);
				return OPH_SERVER_ERROR;
			}
			double return_value = evaluator_evaluate(me, count, names, NULL);
			evaluator_destroy(me);

			pmesg(LOG_DEBUG, __FILE__,__LINE__, "Expression '%s' = %f.\n",condition,return_value);
			if (isnan(return_value) || isinf(return_value))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong condition '%s'!", condition);
				pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
				return OPH_SERVER_ERROR;
			}

			// In case condition is not satisfied...
			if (!return_value) wf->tasks[i].is_skipped = 1;
		}
		check = 1;
	}
	if (wf->tasks[i].is_skipped)
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__, "Skip the selection block associated with task '%s'.\n",wf->tasks[i].name);

		// Skip this sub-block
		if (oph_set_status_of_selection_block(wf, i, OPH_ODB_STATUS_SKIPPED, i, -1, !check, exit_output))
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Error in updating the status of dependents of '%s'.", wf->tasks[i].name);
			pmesg(LOG_ERROR, __FILE__,__LINE__, "%s\n", error_message);
		}
		if (check) wf->tasks[i].is_skipped = 0;
	}
	else // Condition is satisfied
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__, "Execute the selection block associated with task '%s'.\n",wf->tasks[i].name);

		for (j=0;j<wf->tasks_num;++j) if ((wf->tasks[j].parent == i) && strncasecmp(wf->tasks[j].operator,OPH_OPERATOR_ENDIF,OPH_MAX_STRING_SIZE))
		{
			wf->tasks[j].is_skipped = 1;
			pmesg(LOG_DEBUG, __FILE__,__LINE__, "Task '%s' and related branch of workflow '%s' will be skipped.\n", wf->tasks[j].name, wf->name);
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_else_impl(oph_workflow* wf, int i, char* error_message, int *exit_output)
{
	if (wf->tasks[i].is_skipped)
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__, "Skip the selection block associated with task '%s'.\n",wf->tasks[i].name);

		// Skip this sub-block
		if (oph_set_status_of_selection_block(wf, i, OPH_ODB_STATUS_SKIPPED, i, -1, 0, exit_output))
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Error in updating the status of dependents of '%s'.", wf->tasks[i].name);
			pmesg(LOG_ERROR, __FILE__,__LINE__, "%s\n", error_message);
		}
	}
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_extract_from_json(char** key, const char* json_string)
{
	if (!key || !(*key) || !json_string) return OPH_SERVER_ERROR;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parsing '%s'\n",*key);
	char tmp[1+strlen(*key)], *pch = NULL, *save_pointer = NULL, *target = NULL, *objkey = NULL, *title = NULL, *colkey = NULL, *row = NULL, *col = NULL;
	strcpy(tmp,*key);

	int step=0;
	while ((pch = strtok_r(pch?NULL:tmp,OPH_WORKFLOW_OBJECT,&save_pointer)))
	{
		switch (step)
		{
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
	if (!step) return OPH_SERVER_ERROR;

	while (1)
	{
		pch = strchr(target,OPH_WORKFLOW_BRACKET_BEGIN[0]);
		step = 0;

		if (!pch) break;
		*pch = 0;
		row = pch+1;
		step = 1; // Bracket open

		pch = strchr(row,OPH_WORKFLOW_SEPARATORS[3]);
		if (!pch)
		{
			if (!colkey) break;
			pch = strchr(row,OPH_WORKFLOW_BRACKET_END[0]);
			if (!pch) break;
			*pch = 0;
			step = 2; // Bracket closed, row by index, col by name
			break;
		}
		*pch = 0;
		col = pch+1;
		step = 3; // Bracket open, row and col by index

		pch = strchr(col,OPH_WORKFLOW_BRACKET_END[0]);
		if (!pch) break;
		*pch = 0;
		step = 4; // Bracket closed, row and col by index

		break;
	}
	if (!pch && step)
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: syntax error\n");
		return OPH_SERVER_ERROR;
	}

	oph_json *json = NULL;
	if (oph_json_from_json_string_unsafe(&json,json_string))
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: json lookup failed\n");
		if (json) oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	unsigned int i,j=0,k = json->response_num;
	for (i=0; i<json->response_num; ++i) if (json->response && json->response[i].objkey && !strcmp(json->response[i].objkey,objkey)) break;
	if (i>=json->response_num)
	{
		if (colkey)
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objkey not found\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		// Let us assume the form title[.colname]
		colkey = title;
		title = objkey;
		for (i=0; i<json->response_num; ++i) if (json->response && json->response[i].objkey && json->response[i].objclass)
		{
			if (!strcmp(json->response[i].objclass,OPH_JSON_TEXT))
			{
				oph_json_obj_text* obj = NULL;
				for (j=0; j<json->response[i].objcontent_num; ++j) if (json->response[i].objcontent)
				{
					obj = (oph_json_obj_text*)(json->response[i].objcontent)+j;
					if (obj && obj->title && !strcmp(obj->title,title))
					{
						if (k < json->response_num) break;
						else k = i;
					}
				}
			}
			else if (!strcmp(json->response[i].objclass,OPH_JSON_GRID))
			{
				oph_json_obj_grid* obj = NULL;
				for (j=0; j<json->response[i].objcontent_num; ++j) if (json->response[i].objcontent)
				{
					obj = (oph_json_obj_grid*)(json->response[i].objcontent)+j;
					if (obj && obj->title && !strcmp(obj->title,title))
					{
						if (k < json->response_num) break;
						else k = i;
					}
				}
			}
			if (j<json->response[i].objcontent_num) break;
		}
		if (i<json->response_num)
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: more than one objcontent found\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		else if (k>=json->response_num)
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		i = k;
		objkey = json->response[i].objkey;
	}

	if (!json->response[i].objclass)
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objclass not found\n");
		if (json) oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	unsigned int objcontent_num = 0;
	k = json->response[i].objcontent_num;
	if (!strcmp(json->response[i].objclass,OPH_JSON_TEXT))
	{
		oph_json_obj_text* obj = NULL;
		for (j=0; j<json->response[i].objcontent_num; ++j) if (json->response[i].objcontent)
		{
			obj = (oph_json_obj_text*)(json->response[i].objcontent)+j;
			if (obj)
			{
				objcontent_num++;
				if (title)
				{
					if (obj->title && !strcmp(obj->title,title)) break;
				}
				else k=j;
			}
		}
		if ((j>=json->response[i].objcontent_num) && (title || (objcontent_num!=1)))
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		if (!title)
		{
			obj = (oph_json_obj_text*)(json->response[i].objcontent)+k;
			title = obj->title;
			if (!title)
			{
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
				if (json) oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		free(*key);
		*key = strdup(obj->message);
		if (!(*key))
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Key updated to '%s'\n",*key);
	}
	else if (!strcmp(json->response[i].objclass,OPH_JSON_GRID))
	{
		oph_json_obj_grid* obj = NULL;
		for (j=0; j<json->response[i].objcontent_num; ++j) if (json->response[i].objcontent)
		{
			obj = (oph_json_obj_grid*)(json->response[i].objcontent)+j;
			if (obj)
			{
				objcontent_num++;
				if (title)
				{
					if (obj->title && !strcmp(obj->title,title)) break;
				}
				else k=j;
			}
		}
		if ((j>=json->response[i].objcontent_num) && (title || (objcontent_num!=1)))
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}
		if (!title)
		{
			obj = (oph_json_obj_grid*)(json->response[i].objcontent)+k;
			title = obj->title;
			if (!title)
			{
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objcontent not found\n");
				if (json) oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		unsigned int irow = 0, icol = 0;
		char all_values = 0;
		if (colkey)
		{
			if (obj->keys) for (; icol<obj->keys_num; ++icol) if (!strcmp(obj->keys[icol],colkey)) break;
			if (!obj->keys || (icol>=obj->keys_num))
			{
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: rowkey not found\n");
				if (json) oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found key '%s' at column %d\n",colkey,icol);
		}
		else
		{
			if (col && !strcmp(col,OPH_WORKFLOW_GENERIC_VALUE)) all_values = 2;
			else
			{
				icol = col ? (unsigned int)strtol(col,NULL,10) : 0;
				if (icol) icol--; // Non 'C'-like indexing
			}
		}
		if (row && !strcmp(row,OPH_WORKFLOW_GENERIC_VALUE))
		{
			if (all_values)
			{
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: only scalars and vectors can be extracted\n");
				if (json) oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
			all_values = 1;
		}
		else
		{
			irow = row ? (unsigned int)strtol(row,NULL,10) : 0;
			if (irow) irow--; // Non 'C'-like indexing
		}

		if ( (irow>=obj->values_num1) || (icol>=obj->values_num2) )
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: index out of boundaries\n");
			if (json) oph_json_free(json);
			return OPH_SERVER_ERROR;
		}

		free(*key); *key=NULL;
		if (all_values)
		{
			char* tmp_key = NULL;
			switch (all_values)
			{
				case 1: // All the rows
					if (obj->values_num1) *key = strdup(obj->values[0][icol]);
					for (irow=1; irow<obj->values_num1; irow++)
					{
						tmp_key = *key;
						*key = (char*)malloc(strlen(tmp_key)+2+strlen(obj->values[irow][icol]));
						if (!(*key))
						{
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
							if (tmp_key) free(tmp_key);
							if (json) oph_json_free(json);
							return OPH_SERVER_ERROR;
						}
						sprintf(*key,"%s%s%s",tmp_key,OPH_SEPARATOR_SUBPARAM_STR,obj->values[irow][icol]);
						if (tmp_key) free(tmp_key);
						tmp_key = NULL;
					}
					break;
				case 2: // All the columns
					if (obj->values_num2) *key = strdup(obj->values[irow][0]);
					for (icol=1; icol<obj->values_num2; icol++)
					{
						tmp_key = *key;
						*key = (char*)malloc(strlen(tmp_key)+2+strlen(obj->values[irow][icol]));
						if (!(*key))
						{
							pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
							if (tmp_key) free(tmp_key);
							if (json) oph_json_free(json);
							return OPH_SERVER_ERROR;
						}
						sprintf(*key,"%s%s%s",tmp_key,OPH_SEPARATOR_SUBPARAM_STR,obj->values[irow][icol]);
						if (tmp_key) free(tmp_key);
						tmp_key = NULL;
					}
					break;
				default:
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: wrong condition\n");
					if (json) oph_json_free(json);
					return OPH_SERVER_ERROR;
			}
		}
		else
		{
			*key = strdup(obj->values[irow][icol]);
			if (!(*key))
			{
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: memory error\n");
				if (json) oph_json_free(json);
				return OPH_SERVER_ERROR;
			}
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Key '%s' updated to '%s'\n",title,*key);
	}
	else
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Parse error: objclass not supported\n");
		if (json) oph_json_free(json);
		return OPH_SERVER_ERROR;
	}

	if (json) oph_json_free(json);
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_for_impl(oph_workflow* wf, int i, char* error_message, char is_for)
{
	char *pch, *save_pointer = NULL, *name = NULL, **svalues = NULL, mode = 0;
	int *ivalues = NULL; // If not allocated then it is equal to [1:values_num]
	int j, kk = 0, h, hh, svalues_num = 0, ivalues_num = 0;
	unsigned int kkk, lll = strlen(OPH_WORKFLOW_SEPARATORS);
	long value;
	char arg_value[OPH_WORKFLOW_MAX_STRING], *error_msg = NULL;

	int success = 0, ret = OPH_SERVER_OK;
	while (!success)
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__, "Extract arguments of task '%s'.\n",wf->tasks[i].name);

		// Extract arguments. Warning: task parser is not used. Note that the access to oph_jobinfo is unavoidable!
		for (j=0;j<wf->tasks[i].arguments_num;++j)
		{
			snprintf(arg_value,OPH_WORKFLOW_MAX_STRING,"%s",wf->tasks[i].arguments_values[j]);

			pmesg(LOG_DEBUG, __FILE__,__LINE__, "Check for variables in argument '%s' of task '%s'.\n",wf->tasks[i].arguments_keys[j],wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg))
			{
				snprintf(error_message,OPH_WORKFLOW_MAX_STRING,"%s",error_msg?error_msg:"Error in variable substitution!");
				pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) free(error_msg);
				break;
			}

			if (!strcasecmp(wf->tasks[i].arguments_keys[j],OPH_OPERATOR_PARAMETER_NAME) && !name) name = wf->tasks[i].arguments_values[j]; // it should not be 'arg_value'!
			else if (((is_for && !strcasecmp(wf->tasks[i].arguments_keys[j],OPH_OPERATOR_PARAMETER_VALUES)) || (!is_for && !strcasecmp(wf->tasks[i].arguments_keys[j],OPH_OPERATOR_PARAMETER_VALUE))) && !svalues && strcasecmp(arg_value,OPH_COMMON_NULL))
			{
				char *tmp = strdup(arg_value), expansion, *pch1;
				if (!tmp) break;
				do
				{
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Values parsing: %s\n", tmp);
					expansion = svalues_num = 0;
					pch = strchr(tmp,OPH_SEPARATOR_SUBPARAM);
					for (svalues_num++; pch; svalues_num++)
					{
						pch1 = pch+1;
						if (!pch1 || !*pch1) break;
						pch = strchr(pch1,OPH_SEPARATOR_SUBPARAM);
					}
					svalues = (char**)malloc(svalues_num * sizeof(char*));
					if (!svalues) break;
					pch = strtok_r(tmp, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
					for (kk=0; kk<svalues_num; ++kk)
					{
						svalues[kk] = strndup(pch,OPH_WORKFLOW_MAX_STRING);
						if (!svalues[kk]) break;
						// Begin check in input JSON Response
						for (h=0; h<wf->tasks_num; ++h) if (wf->tasks[h].response)
						{
							for (hh=0; hh<wf->tasks[h].dependents_indexes_num; ++hh) if (wf->tasks[h].dependents_indexes[hh] == i)
							{
								if (!oph_extract_from_json(svalues+kk,wf->tasks[h].response)) // Found a correspondence
								{
									if (strchr(svalues[kk],OPH_SEPARATOR_SUBPARAM))
									{
										hh = 0;
										char expanded_value[1+strlen(arg_value)+strlen(svalues[kk])];
										for (h=0; h<kk; ++h) hh = sprintf(expanded_value+hh, "%s%c", svalues[h], OPH_SEPARATOR_SUBPARAM);
										hh = sprintf(expanded_value+hh, "%s", svalues[kk]);
										pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
										if (pch) sprintf(expanded_value+hh, "%c%s", OPH_SEPARATOR_SUBPARAM, pch);
										pmesg(LOG_DEBUG, __FILE__, __LINE__, "Values expansion: %s\n", expanded_value);
										free(tmp);
										tmp = strdup(expanded_value);
										for (h=0; h<=kk; ++h) free(svalues[h]);
										free(svalues);
										expansion = 1;
									}
									break;
								}
							}
							if (expansion || (hh<wf->tasks[h].dependents_indexes_num)) break;
						}
						// End check
						if (!expansion) pch = strtok_r(NULL, OPH_SEPARATOR_SUBPARAM_STR, &save_pointer);
					}
				}
				while (expansion);
				free(tmp);
				if (kk<svalues_num) break;
				if (!is_for && (svalues_num>1)) pmesg(LOG_WARNING, __FILE__, __LINE__, "Only the first value of the list will be considered\n");
			}
			else if (is_for && !strcasecmp(wf->tasks[i].arguments_keys[j],OPH_OPERATOR_PARAMETER_PARALLEL) && !mode)
			{
				if (!strcasecmp(arg_value,OPH_COMMON_YES)) mode = 1;
				else if (strcasecmp(arg_value,OPH_COMMON_NO)) break;
			}
		}
		if ((j<wf->tasks[i].arguments_num) || error_msg)
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Generic error in parsing arguments of task '%s'.\n",wf->tasks[i].name);
			ret = OPH_SERVER_ERROR;
			break;
		}
		for (j=0;j<wf->tasks[i].arguments_num;++j)
		{
			snprintf(arg_value,OPH_WORKFLOW_MAX_STRING,"%s",wf->tasks[i].arguments_values[j]);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg))
			{
				snprintf(error_message,OPH_WORKFLOW_MAX_STRING,"%s",error_msg?error_msg:"Error in variable substitution!");
				pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) free(error_msg);
				break;
			}

			if (is_for && !strcasecmp(wf->tasks[i].arguments_keys[j],OPH_OPERATOR_PARAMETER_COUNTER) && !ivalues && strcasecmp(arg_value,OPH_COMMON_NULL))
			{
				oph_subset* subset_struct = NULL;
				if (oph_subset_init(&subset_struct))
				{
					oph_subset_free(subset_struct);
					break;
				}
				if (oph_subset_parse(arg_value,strlen(arg_value),subset_struct,svalues_num))
				{
					oph_subset_free(subset_struct);
					break;
				}
				ivalues_num = subset_struct->total;
				ivalues = (int*)malloc(ivalues_num*sizeof(int));
				if (!ivalues)
				{
					oph_subset_free(subset_struct);
					break;
				}
				for (kk=kkk=0; (kk<ivalues_num) && (kkk<subset_struct->number); ++kkk)
				{
					value = subset_struct->start[kkk];
					do
					{
						ivalues[kk++] = (int)value;
						value += subset_struct->stride[kkk];
					}
					while ((kk<ivalues_num) && (value <= subset_struct->end[kkk]));
				}
				oph_subset_free(subset_struct);
			}
		}
		if ((j<wf->tasks[i].arguments_num) || error_msg)
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Generic error in parsing arguments of task '%s'.\n",wf->tasks[i].name);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (name)
		{
			snprintf(arg_value,OPH_WORKFLOW_MAX_STRING,"%s",name);

			pmesg(LOG_DEBUG, __FILE__,__LINE__, "Check for variables in argument '%s' of task '%s'.\n",OPH_OPERATOR_PARAMETER_NAME,wf->tasks[i].name);
			if (oph_workflow_var_substitute(wf, i, arg_value, &error_msg))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"%s",error_msg?error_msg:"Error in variable substitution!");
				pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
				if (error_msg) free(error_msg);
				ret = OPH_SERVER_ERROR;
				break;
			}
			name = arg_value;
		}

		if (name) pmesg(LOG_DEBUG, __FILE__,__LINE__, "Check compliance of variable name '%s' of task '%s' with IEEE Std 1003.1-2001 conventions.\n",name,wf->tasks[i].name);
		for (kk=0;name && (kk<(int)strlen(name));++kk) // check compliance with IEEE Std 1003.1-2001 conventions
		{
			if ((name[kk]=='_') || ((name[kk]>='A') && (name[kk]<='Z')) || ((name[kk]>='a') && (name[kk]<='z')) || (kk && (name[kk]>='0') && (name[kk]<='9'))) continue;
			for (kkk=0;kkk<lll;++kkk) if (name[kk]==OPH_WORKFLOW_SEPARATORS[kkk]) { name = NULL; break; }
			if (name) snprintf(error_message,OPH_MAX_STRING_SIZE,"Change variable name '%s'.",name);
			break;
		}
		if (!name)
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Bad argument '%s'.",OPH_OPERATOR_PARAMETER_NAME);
			pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
			ret = OPH_SERVER_ERROR;
			break;
		}
		if (mode)
		{
			if (ivalues) { free(ivalues); ivalues=NULL; }
			if (svalues)
			{
				for (kk=0; kk<svalues_num; ++kk) if (svalues[kk]) free(svalues[kk]);
				free(svalues); svalues=NULL;
			}
			svalues_num = 1; // Parallel for involves only one loop
		}
		else if (svalues_num)
		{
			if (ivalues_num && (ivalues_num != svalues_num))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Arguments '%s' and '%s' have different sizes.",OPH_OPERATOR_PARAMETER_VALUES,OPH_OPERATOR_PARAMETER_COUNTER);
				pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}
		}
		else svalues_num = ivalues_num ? ivalues_num : 1; // One loop is executed by default

		if (!mode && (svalues_num > 0))
		{
			if (!is_for) // Drop the previous value in case of oph_set
			{
				pmesg(LOG_DEBUG, __FILE__,__LINE__, "Drop variable '%s'\n",name);
				hashtbl_remove(wf->vars, name);
			}

			oph_workflow_var var;
			var.caller = i;
			if (ivalues) var.ivalue = ivalues[0]; else var.ivalue=1; // Non C-like indexing
			if (svalues) strcpy(var.svalue,svalues[0]); else snprintf(var.svalue,OPH_WORKFLOW_MAX_STRING,"%d",var.ivalue);

			if (svalues) pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s=%s' in environment of workflow '%s'.\n",name,var.svalue,wf->name);
			else pmesg(LOG_DEBUG, __FILE__, __LINE__, "Add variable '%s=%d' in environment of workflow '%s'.\n",name,var.ivalue,wf->name);
			if (hashtbl_insert_with_size(wf->vars, name, (void *)&var, sizeof(oph_workflow_var)))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE, "Unable to store variable '%s' in environment of workflow '%s'. Maybe it already exists.",name,wf->name);
				pmesg(LOG_WARNING,  __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_ERROR;
				break;
			}

			// Push them into the stack, even in case only one loop has to be performed
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Push for-data into the stack of workflow '%s'.\n",wf->name);
			if (is_for && oph_workflow_push(wf,i,name,svalues,ivalues,svalues_num))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE, "Unable to push for-data into the stack of workflow '%s'.",wf->name);
				pmesg(LOG_WARNING,  __FILE__, __LINE__, "%s\n", error_message);
				ret = OPH_SERVER_SYSTEM_ERROR;
				break;
			}
		}

		success=1;
	}

	if (!success || !is_for)
	{
		if (ivalues) free(ivalues);
		if (svalues)
		{
			for (kk=0; kk<svalues_num; ++kk) if (svalues[kk]) free(svalues[kk]);
			free(svalues);
		}
	}

	return ret;
}

// Thread unsafe
int oph_endfor_impl(oph_workflow* wf, int i, char* error_message, oph_trash* trash, int *task_id, int* odb_jobid)
{
	// Find the data inserted by the parent within the stack
	oph_workflow_stack *tmp = wf->stack, *tmpp = NULL;
	while (tmp && (tmp->caller != wf->tasks[i].parent)) { tmpp = tmp; tmp = tmp->next; }
	if (tmp)
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update index '%s' set by task '%s' in environment of workflow '%s'.\n",tmp->name,wf->tasks[tmp->caller].name,wf->name);

		tmp->index++;
		if (hashtbl_remove(wf->vars, tmp->name)) // Skip this in the last step to extend the scope of the variable to any descendent
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE, "Unable to remove variable '%s' from environment of workflow '%s'.",tmp->name,wf->name);
			pmesg(LOG_WARNING,  __FILE__, __LINE__, "%s\n", error_message);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (tmp->index < tmp->values_num)
		{
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Create variable '%s' to be stored in environment of workflow '%s'.\n",tmp->name,wf->name);
			oph_workflow_var var;
			var.caller = tmp->caller;
			if (tmp->ivalues) var.ivalue = tmp->ivalues[tmp->index]; else var.ivalue=1+tmp->index; // Non C-like indexing
			if (tmp->svalues) strcpy(var.svalue,tmp->svalues[tmp->index]); else snprintf(var.svalue,OPH_WORKFLOW_MAX_STRING,"%d",var.ivalue);

			if (tmp->svalues) pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update variable '%s=%s' in environment of workflow '%s'.\n",tmp->name,var.svalue,wf->name);
			else pmesg(LOG_DEBUG, __FILE__, __LINE__, "Update variable '%s=%d' in environment of workflow '%s'.\n",tmp->name,var.ivalue,wf->name);
			if (hashtbl_insert_with_size(wf->vars, tmp->name, (void *)&var, sizeof(oph_workflow_var)))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE, "Unable to update variable '%s' in environment of workflow '%s'.",tmp->name,wf->name);
				pmesg(LOG_WARNING,  __FILE__, __LINE__, "%s\n", error_message);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			if (odb_jobid) // Reset status
			{
				int p = wf->tasks[i].parent, tasks_num = 0;

				*odb_jobid = wf->tasks[p].idjob; // Used to change 'jobid' in notification message to oph_for
				*task_id = p; // Used to change 'taskindex' in notification message to oph_for

				oph_odb_remove_job(wf->tasks[i].idjob); // Drop line of oph_endfor from OphDB

				if (oph_trash_append(trash, wf->sessionid, wf->tasks[i].markerid)) pmesg(LOG_WARNING, __FILE__, __LINE__, "Unable to release markerid.\n");
				else pmesg(LOG_DEBUG, __FILE__,__LINE__,"Release markerid '%d'.\n", wf->tasks[i].markerid);

				if (oph_workflow_reset_task(wf, wf->tasks[p].dependents_indexes, wf->tasks[p].dependents_indexes_num, i, tmp, &tasks_num))
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE, "Unable to reset task data from '%s'.",wf->tasks[p].name);
					pmesg(LOG_WARNING,  __FILE__, __LINE__, "%s\n", error_message);
				}
				else wf->residual_tasks_num += tasks_num;

				if (wf->tasks[p].outputs_num)
				{
					oph_output_data_free(wf->tasks[p].outputs_keys,wf->tasks[p].outputs_num);
					oph_output_data_free(wf->tasks[p].outputs_values,wf->tasks[p].outputs_num);
					wf->tasks[p].outputs_num = 0;
					wf->tasks[p].outputs_keys = wf->tasks[p].outputs_values = NULL;
				}

				return OPH_SERVER_NO_RESPONSE;
			}
		}
		else wf->tasks[i].parallel_mode = 1; // used to trasform the end-for in a massive operator

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Pop for-data from the stack of workflow '%s'.\n",wf->name);
		if (oph_workflow_pop(wf,tmpp))
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE, "Unable to pop for-data from the stack of workflow '%s'.",wf->name);
			pmesg(LOG_WARNING,  __FILE__, __LINE__, "%s\n", error_message);
			return OPH_SERVER_SYSTEM_ERROR;
		}
	}
	else
	{
		snprintf(error_message,OPH_MAX_STRING_SIZE, "No index found in environment of workflow '%s'.",wf->name);
		pmesg(LOG_DEBUG,  __FILE__, __LINE__, "%s\n", error_message);
	}

	return OPH_SERVER_OK;
}

int oph_finalize_known_operator(int idjob, oph_json *oper_json, const char *operator_name, char *error_message, int success, char **response, ophidiadb *oDB, enum oph__oph_odb_job_status *exit_code)
{
	if (exit_code) *exit_code = OPH_ODB_STATUS_ERROR;

	char *jstring = NULL;
	if (oper_json)
	{
		int return_code = 0;
		if (!success)
		{
			if (!strlen(error_message)) snprintf(error_message,OPH_MAX_STRING_SIZE,"Operator '%s' failed!",operator_name);
			if (oph_json_add_text(oper_json,OPH_JSON_OBJKEY_STATUS,"ERROR",error_message))
			{
			    	pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "ADD TEXT error\n");
				return_code = -1;
			}
			else if (oph_write_and_get_json(oper_json, &jstring)) return_code = -1;
		}
		else
		{
			if (oph_json_add_text(oper_json,OPH_JSON_OBJKEY_STATUS,"SUCCESS",strlen(error_message) ? error_message : NULL))
			{
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "ADD TEXT error\n");
				return_code = -1;
			}
			else if (oph_write_and_get_json(oper_json, &jstring)) return_code = -1;
			else if (exit_code) *exit_code = OPH_ODB_STATUS_COMPLETED;
		}
		oph_json_free(oper_json);
		if (return_code) pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"error in generate JSON Response\n");
	}
	if (!jstring)
	{
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to convert JSON Response into a string\n");
		oph_odb_disconnect_from_ophidiadb(oDB);
		return OPH_SERVER_SYSTEM_ERROR;
	}
	if (response) *response = jstring;
	else free(jstring);

	// Set ODB_STATUS to COMPLETED
	oph_odb_stop_job_fast(idjob, oDB);
	oph_odb_disconnect_from_ophidiadb(oDB);

	return OPH_SERVER_OK;
}

int oph_serve_known_operator(struct oph_plugin_data *state, const char* request, const int ncores, const char* sessionid, const char* markerid, int *odb_wf_id, int *task_id, int *light_task_id, int* odb_jobid, char** response, char** jobid_response, enum oph__oph_odb_job_status *exit_code, int* exit_output)
{
	UNUSED(ncores)

	int error = OPH_SERVER_UNKNOWN;
	if (exit_code) *exit_code = OPH_ODB_STATUS_COMPLETED;
	if (exit_output) *exit_output = 1;

	if (!request)
	{
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Submission string not found\n");
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (!sessionid)
	{
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s not found\n",OPH_ARG_SESSIONID);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}
	if (!markerid)
	{
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s not found\n",OPH_ARG_MARKERID);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}

	char operator_name[OPH_MAX_STRING_SIZE];
	if (oph_tp_find_param_in_task_string(request, OPH_ARG_OPERATOR, &operator_name))
	{
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s not found\n",OPH_ARG_OPERATOR);
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}

	// Flow control tasks
	if (!strncasecmp(operator_name,OPH_OPERATOR_CANCEL,OPH_MAX_STRING_SIZE))
	{
		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Task parser error\n");
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		char username[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE], oph_jobid[OPH_MAX_STRING_SIZE];
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, &oph_jobid))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int)strtol(oph_jobid, NULL, 10);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, &username))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_USERNAME);
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_WORKFLOWID, &workflowid))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_WORKFLOWID);
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		int wid,success=0,success2=0;
		oph_json* oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];

		while(!success)
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s'!",OPH_ARG_ID);
			char* str_id = hashtbl_get(task_tbl, OPH_ARG_ID);
			if (!str_id) break;

			wid = (int)strtol(str_id,NULL,10);
			if (wid<=0) break;

			success=1;
		}

		if (success)
		{
			int jobid = 0;
			char error_notification[OPH_MAX_STRING_SIZE];
			*error_notification=0;

			pthread_mutex_lock(&global_flag);

			snprintf(error_message,OPH_MAX_STRING_SIZE,"Workflow '%d' not found!",wid);
			oph_job_info* item = NULL, *prev = NULL;
			if (!(item = oph_find_workflow_in_job_list_to_drop(state->job_info, sessionid, wid, &prev))) success=0;
			else if (item->wf->status < (int)OPH_ODB_STATUS_ABORTED)
			{
				item->wf->status = OPH_ODB_STATUS_ABORTED;
				snprintf(error_notification, OPH_MAX_STRING_SIZE, OPH_WORKFLOW_BASE_NOTIFICATION, item->wf->idjob, 0, -1, item->wf->idjob, OPH_ODB_STATUS_ABORTED);
				jobid = *(state->jobid) = *(state->jobid) + 1;
			}

			pthread_mutex_unlock(&global_flag);

			if (strlen(error_notification))
			{
				int response=0;
				oph_workflow_notify(state, 'N', jobid, error_notification, NULL, &response);
				if (response) pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__, "N%d: error %d in notify\n", jobid, response);
			}
		}

		while(!success2)
		{
			if (oph_json_alloc(&oper_json))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",username))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code))
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Marker",markerid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);
			if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_consumer(oper_json,username))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}

			success2=1;
		}
		if (success) success=success2;

		if (task_tbl) hashtbl_destroy(task_tbl);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success) *error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}
	else if (!strncasecmp(operator_name,OPH_OPERATOR_FOR,OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name,OPH_OPERATOR_SET,OPH_MAX_STRING_SIZE))
	{
		char is_for = !strncasecmp(operator_name,OPH_OPERATOR_FOR,OPH_MAX_STRING_SIZE);

		if (!task_id)
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info* item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev)))
		{
			pmesg(LOG_WARNING, __FILE__,__LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow* wf = item->wf;

		int i = *task_id, idjob = wf->tasks[i].idjob;

		// JSON Response creation
		int success=0;
		oph_json* oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message,OPH_MAX_STRING_SIZE,"Failure in obtaining JSON data!");
		while (!success)
		{
			if (oph_json_alloc(&oper_json))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",wf->username))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code))
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE,"%d",wf->workflowid);
			if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Marker",markerid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);
			if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_consumer(oper_json,wf->username))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}

			success=1;
		}

		if (success)
		{
			int ret = oph_for_impl(wf, i, error_message, is_for);
			if (ret)
			{
				success = 0;
				if (ret == OPH_SERVER_SYSTEM_ERROR)
				{
					pthread_mutex_unlock(&global_flag);
					oph_json_free(oper_json);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success) *error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}
	else if (!strncasecmp(operator_name,OPH_OPERATOR_ENDFOR,OPH_MAX_STRING_SIZE))
	{
		if (!task_id)
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info* item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev)))
		{
			pmesg(LOG_WARNING, __FILE__,__LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow* wf = item->wf;
		int i = *task_id, ret;

		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message,OPH_MAX_STRING_SIZE,"Failure in executing oph_endif!");

		ret = oph_endfor_impl(wf, i, error_message, state->trash, task_id, odb_jobid);
		if (ret)
		{
			pthread_mutex_unlock(&global_flag);
			return ret;
		}

		// JSON Response creation
		int success=0;
		oph_json* oper_json = NULL;
		snprintf(error_message,OPH_MAX_STRING_SIZE,"Failure in obtaining JSON data!");
		while (!success)
		{
			if (oph_json_alloc(&oper_json))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",wf->username))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code))
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE,"%d",wf->workflowid);
			if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Marker",markerid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);
			if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_consumer(oper_json,wf->username))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}

			success=1;
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success) *error_message = 0;
		if (oph_finalize_known_operator(wf->tasks[i].idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}
	else if (!strncasecmp(operator_name,OPH_OPERATOR_IF,OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name,OPH_OPERATOR_ELSEIF,OPH_MAX_STRING_SIZE)) // oph_if, oph_elseif
	{
#ifndef MATHEVAL_SUPPORT
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to execute %s. Matheval is not available\n", operator_name);
		return OPH_SERVER_SYSTEM_ERROR;
#endif
		if (!task_id)
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info* item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev)))
		{
			pmesg(LOG_WARNING, __FILE__,__LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow* wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;

		// JSON Response creation
		int success=0;
		oph_json* oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message,OPH_MAX_STRING_SIZE,"Failure in obtaining JSON data!");
		while (!success)
		{
			if (oph_json_alloc(&oper_json))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",wf->username))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code))
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE,"%d",wf->workflowid);
			if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Marker",markerid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);
			if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_consumer(oper_json,wf->username))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}

			success=1;
		}

		if (success)
		{
			if (oph_if_impl(wf, i, error_message, exit_output)) success = 0;
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success) *error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}
	else if (!strncasecmp(operator_name,OPH_OPERATOR_ELSE,OPH_MAX_STRING_SIZE) || !strncasecmp(operator_name,OPH_OPERATOR_ENDIF,OPH_MAX_STRING_SIZE)) // oph_else, oph_endif
	{
#ifndef MATHEVAL_SUPPORT
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to execute %s. Matheval is not available\n", operator_name);
		return OPH_SERVER_SYSTEM_ERROR;
#endif
		if (!task_id)
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' needs parameter task_id\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (light_task_id && (*light_task_id >= 0))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "Operator '%s' cannot be used within massive operations\n", operator_name);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		pthread_mutex_lock(&global_flag);

		oph_job_info* item = NULL, *prev = NULL;
		if (!odb_wf_id || !(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev)))
		{
			pmesg(LOG_WARNING, __FILE__,__LINE__, "Workflow with ODB_ID %d not found\n", *odb_wf_id);
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_workflow* wf = item->wf;
		int i = *task_id, idjob = wf->tasks[i].idjob;

		// JSON Response creation
		int success=0;
		oph_json* oper_json = NULL;
		char error_message[OPH_MAX_STRING_SIZE];
		snprintf(error_message,OPH_MAX_STRING_SIZE,"Failure in obtaining JSON data!");
		while (!success)
		{
			if (oph_json_alloc(&oper_json))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",wf->username))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			char session_code[OPH_MAX_STRING_SIZE];
			if (oph_get_session_code(sessionid, session_code))
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char workflowid[OPH_SHORT_STRING_SIZE];
			snprintf(workflowid, OPH_SHORT_STRING_SIZE,"%d",wf->workflowid);
			if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Marker",markerid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			char oph_jobid[OPH_MAX_STRING_SIZE];
			snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);
			if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_consumer(oper_json,wf->username))
			{
				  pmesg(LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}

			success=1;
		}

		if (success && !strncasecmp(operator_name,OPH_OPERATOR_ELSE,OPH_MAX_STRING_SIZE))
		{
			if (oph_else_impl(wf, i, error_message, exit_output)) success = 0;
		}

		pthread_mutex_unlock(&global_flag);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}

		if (success) *error_message = 0;
		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}

	else // Normal tasks

	if (!strncasecmp(operator_name,OPH_OPERATOR_MANAGE_SESSION,OPH_MAX_STRING_SIZE))
	{
		char *action, *key, *value, username[OPH_MAX_STRING_SIZE], *new_sessionid = NULL, oph_jobid[OPH_MAX_STRING_SIZE];
		const char *session;
		int result, save_user=0, save_session=0, num_sessions=-1;

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, &oph_jobid))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int)strtol(oph_jobid, NULL, 10);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_odb_start_job_fast(idjob, &oDB);

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, &username))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_USERNAME);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		// Convert dn to user
		char _username[OPH_MAX_STRING_SIZE];
		snprintf(_username,OPH_MAX_STRING_SIZE,"%s",username);
		int i,j=strlen(_username);
		for (i=0;i<j;++i) if ((_username[i]=='/') || (_username[i]==' ') || (_username[i]=='=')) _username[i]='_';

		// Load user information
		int save_in_odb=0;
		oph_argument* user_args = NULL;
		oph_init_args(&user_args);
		pthread_mutex_lock(&global_flag);
		result = oph_load_user(_username,&user_args,&save_in_odb);
		pthread_mutex_unlock(&global_flag);
		if (result)
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "Error in opening user data\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if (save_in_odb) // Save the entry in OphDB
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__,"Saving reference to '%s' in system catalog\n",username);
			if (oph_odb_insert_user(&oDB,username))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__,"Error in saving reference to '%s' in system catalog\n",username);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_cleanup_args(&user_args);
				return OPH_SERVER_IO_ERROR;
			}
		}

		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Task parser error\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl) hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		action = hashtbl_get(task_tbl, OPH_ARG_ACTION);
		session = hashtbl_get(task_tbl, OPH_ARG_SESSION);
		key = hashtbl_get(task_tbl, OPH_ARG_KEY);
		value = hashtbl_get(task_tbl, OPH_ARG_VALUE);
	
		if (session)
		{
			if (!strncasecmp(session,OPH_COMMON_PARAMETER_WORKING_SESSION,OPH_MAX_STRING_SIZE)) session = sessionid;
			else if (strncmp(session,oph_web_server,strlen(oph_web_server)))
			{
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"Received wrong sessionid '%s'\n",session);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				return OPH_SERVER_WRONG_PARAMETER_ERROR;
			}
		}
		else session = sessionid;

		char default_key[OPH_SHORT_STRING_SIZE] = OPH_ARG_KEY_VALUE_USER;
		if (!key) key = default_key;

		char owner[OPH_MAX_STRING_SIZE];
		oph_auth_user_role role = OPH_ROLE_NONE;
		char session_code[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE];

		char last_session[OPH_MAX_STRING_SIZE];
		if (oph_get_arg(user_args, OPH_USER_LAST_SESSION_ID, last_session)) *last_session=0;

		if (oph_get_session_code(sessionid, session_code))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl) hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		if (oph_tp_find_param_in_task_string(request, OPH_ARG_WORKFLOWID, &workflowid))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_WORKFLOWID);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			if (task_tbl) hashtbl_destroy(task_tbl);
			oph_cleanup_args(&user_args);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
		snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);

		oph_argument* args = NULL;
		if (session)
		{
			oph_init_args(&args);
			pthread_mutex_lock(&global_flag);
			if (oph_auth_session(_username, session, oph_web_server, &args, NULL, &role))
			{
				pmesg(LOG_WARNING, __FILE__,__LINE__,"received wrong sessionid '%s'\n", session);
				pthread_mutex_unlock(&global_flag);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				oph_cleanup_args(&args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				return OPH_SERVER_AUTH_ERROR;
			}
			char *str_role;
			pmesg(LOG_DEBUG, __FILE__,__LINE__, "role of the user '%s' is '%s'\n", username, str_role=oph_role_to_string(role));
			if (str_role) free(str_role);
			pthread_mutex_unlock(&global_flag);
			if (oph_get_session_code(session, session_code))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "unable to get session code\n");
				oph_cleanup_args(&args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			if (oph_get_arg(args, OPH_SESSION_OWNER, owner))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "unable to get session owner\n");
				oph_cleanup_args(&args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_cleanup_args(&user_args);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__, "session owner is '%s'\n", owner);
		}
		else *session_code=0;

		int success=0;
		oph_json* oper_json = NULL;

		char error_message[OPH_MAX_STRING_SIZE], tmp[OPH_MAX_STRING_SIZE], filename[OPH_MAX_STRING_SIZE];
		*error_message=0;

		int num_fields,iii,jjj=0;
	
		char **jsonkeys = NULL;
		char **fieldtypes = NULL;
		char **jsonvalues = NULL;

		// JSON Response creation
		while (!success)
		{
			if (oph_json_alloc(&oper_json))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",username))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			if (session)
			{
				if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
				{
					  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					  break;
				}
				if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
				{
					  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					  break;
				}
				if (oph_json_add_source_detail(oper_json,"Marker",markerid))
				{
					  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					  break;
				}
				if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
				{
					  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
					  break;
				}
			}
			if (oph_json_add_consumer(oper_json,username))
			{
				  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}
			success=1;
		}

		if (!success)
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Failure in obtaining JSON data!");
		}
		if (!action)
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_ACTION);
			success=0;
		}
		// Commands for any user
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_LIST,OPH_MAX_STRING_SIZE))
		{
			num_fields=8;
			if (success)
			{
				// Header
				success=0;
				while (!success)
				{
					  jsonkeys = (char **)malloc(sizeof(char *)*num_fields);
					  if (!jsonkeys) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  break;
					  }
					  jjj = 0;
					  jsonkeys[jjj] = strdup(OPH_SESSION_ID);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_LABEL);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_OWNER);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_CREATION_TIME);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_LAST_ACCESS_TIME);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_LAST_WORKFLOW);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_LAST_MARKER);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup(OPH_SESSION_ACTIVE);
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj = 0;
					  fieldtypes = (char **)malloc(sizeof(char *)*num_fields);
					  if (!fieldtypes) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_INT);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_INT);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  if (oph_json_add_grid(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,"Session List",NULL,jsonkeys,num_fields,fieldtypes,num_fields)) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
					  if (jsonkeys) free(jsonkeys);
					  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
					  if (fieldtypes) free(fieldtypes);

					success=1;
				}
			}

			int last_access_time = 0, exist, check_num_sessions = 0;
			struct dirent *entry, save_entry;
			char directory[OPH_MAX_STRING_SIZE];
			snprintf(directory,OPH_MAX_STRING_SIZE,OPH_SESSION_DIR,oph_auth_location,_username);

			num_sessions = oph_get_arg(user_args,OPH_USER_OPENED_SESSIONS,tmp);
			if (num_sessions) num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
			else num_sessions = strtol(tmp,NULL,10);

			int timeout_value = oph_get_arg(user_args,OPH_USER_TIMEOUT_SESSION,tmp);
			if (timeout_value) timeout_value = OPH_DEFAULT_SESSION_TIMEOUT;
			else timeout_value = strtol(tmp,NULL,10);

			pthread_mutex_lock(&global_flag);

			struct timeval tv;
			gettimeofday(&tv,0);

			pmesg(LOG_DEBUG, __FILE__,__LINE__, "scanning %s\n",directory);
			DIR* dirp = opendir(directory);
			if (!dirp)
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__, "error in opening session directory '%s'\n",directory);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_json_free(oper_json);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			oph_arguments *session_args_list = NULL, *session_args_item;
			oph_init_args_list(&session_args_list);

			oph_argument* session_args = NULL;
			struct stat file_stat;

			while (success && !readdir_r(dirp, &save_entry, &entry) && entry)
			{
				snprintf(filename,OPH_MAX_STRING_SIZE,"%s/%s",directory,entry->d_name);
				lstat(filename, &file_stat);
				if (S_ISLNK(file_stat.st_mode))
				{
					oph_init_args(&session_args);
					if (!oph_load_file(filename, &session_args))
					{
						pmesg(LOG_DEBUG, __FILE__,__LINE__, "check for %s\n",OPH_SESSION_LAST_ACCESS_TIME);
						if (!oph_get_arg(session_args,OPH_SESSION_LAST_ACCESS_TIME,tmp))
						{
							last_access_time = strtol(tmp,NULL,10);
							pmesg(LOG_DEBUG, __FILE__,__LINE__, "check for %s\n",OPH_SESSION_AUTOREMOVE);
							if (timeout_value && !oph_get_arg(session_args,OPH_SESSION_AUTOREMOVE,tmp) && !strcmp(tmp,OPH_DEFAULT_YES))
							{
								pmesg(LOG_DEBUG, __FILE__,__LINE__, "found a removable session '%s', last access on %d\n",filename,last_access_time);
								if (tv.tv_sec > last_access_time + timeout_value*OPH_DEFAULT_DAY_TO_SEC) // Timeout
								{
									pmesg(LOG_INFO, __FILE__,__LINE__, "session '%s' has expired... removing it\n",filename);
									remove(filename);
									oph_cleanup_args(&session_args);

									if (num_sessions>0) num_sessions--;
									else
									{
										closedir(dirp);
										pmesg(LOG_ERROR, __FILE__,__LINE__, "error in handling session number\n");
										pthread_mutex_unlock(&global_flag);
										oph_cleanup_args(&args);
										oph_cleanup_args(&user_args);
										if (task_tbl) hashtbl_destroy(task_tbl);
										oph_cleanup_args_list(&session_args_list);
										oph_json_free(oper_json);
										oph_odb_disconnect_from_ophidiadb(&oDB);
										return OPH_SERVER_SYSTEM_ERROR;
									}
									save_user=1;

									continue;
								}
							}
						}

					}
					else
					{
						closedir(dirp);
						pmesg(LOG_ERROR, __FILE__,__LINE__, "error in opening session file '%s'\n",filename);
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl) hashtbl_destroy(task_tbl);
						oph_cleanup_args_list(&session_args_list);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						return OPH_SERVER_SYSTEM_ERROR;
					}

					if (oph_append_args_list(&session_args_list,session_args,last_access_time))
					{
						closedir(dirp);
						pmesg(LOG_ERROR, __FILE__,__LINE__, "error in handling session list\n");
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl) hashtbl_destroy(task_tbl);
						oph_cleanup_args_list(&session_args_list);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						return OPH_SERVER_SYSTEM_ERROR;
					}

					check_num_sessions++;
				}
			}
			closedir(dirp);

			pthread_mutex_unlock(&global_flag);

			if (num_sessions != check_num_sessions)
			{
				pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__, "unexpected number of sessions '%d': forcing new value '%d'\n",num_sessions,check_num_sessions);
				num_sessions = check_num_sessions;
			}

			int max_sessions = oph_get_arg(user_args,OPH_USER_MAX_SESSIONS,tmp);
			if (max_sessions) max_sessions = OPH_DEFAULT_USER_MAX_SESSIONS;
			else max_sessions = strtol(tmp,NULL,10);
			if (max_sessions && (num_sessions > max_sessions))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "the number of sessions '%d' is higher than the maximum number '%d'\n",num_sessions,max_sessions);
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_cleanup_args_list(&session_args_list);
				oph_json_free(oper_json);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			// Order by last_access_time
			if (oph_order_args_list(&session_args_list))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "error in ordering session list\n");
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_cleanup_args_list(&session_args_list);
				oph_json_free(oper_json);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}

			time_t nowtime, nowtime2;
			struct tm *nowtm, *nowtm2;
			// Data
			success=0;
			while (!success)
			{
				for (session_args_item = session_args_list; session_args_item; session_args_item = session_args_item->next)
				{
					session_args=session_args_item->item;
					nowtime = (time_t)(session_args_item->id);
					nowtm = localtime(&nowtime);
					strftime(filename, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", nowtm);

					jsonvalues = (char **)malloc(sizeof(char *)*num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj=0;
					exist = !oph_get_arg(session_args,OPH_SESSION_ID,tmp);
					jsonvalues[jjj] = strdup(exist?tmp:"-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args,OPH_SESSION_LABEL,tmp);
					jsonvalues[jjj] = strdup(exist?tmp:"-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args,OPH_SESSION_OWNER,tmp);
					jsonvalues[jjj] = strdup(exist?tmp:"-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args,OPH_SESSION_CREATION_TIME,tmp);
					if (exist)
					{
						nowtime2 = (time_t)strtol(tmp,NULL,10);
						nowtm2 = localtime(&nowtime2);
						strftime(tmp, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", nowtm2);
					}
					jsonvalues[jjj] = strdup(exist?tmp:"-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(filename);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args,OPH_SESSION_LAST_WORKFLOW,tmp);
					jsonvalues[jjj] = strdup(exist?tmp:"0");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args,OPH_SESSION_LAST_MARKER,tmp);
					jsonvalues[jjj] = strdup(exist?tmp:"0");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					exist = !oph_get_arg(session_args,OPH_SESSION_ACTIVE,tmp);
					jsonvalues[jjj] = strdup(exist?tmp:"-");
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					if (oph_json_add_grid_row(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
						for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
					if (jsonvalues) free(jsonvalues);

				}

				if (session_args_item) break;
				else success=1;
			}
			oph_cleanup_args_list(&session_args_list);

			if (success)
			{
				if (!num_sessions) snprintf(tmp,OPH_MAX_STRING_SIZE,"No session found");
				else if (num_sessions==1) snprintf(tmp,OPH_MAX_STRING_SIZE,"Found 1 session");
				else snprintf(tmp,OPH_MAX_STRING_SIZE,"Found %d sessions",num_sessions);
				if (oph_json_add_text(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_SUMMARY,"Summary",tmp))
				{
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD TEXT error\n");
					success=0;
				}
			}
		}
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_NEW,OPH_MAX_STRING_SIZE))
		{
			num_sessions = oph_get_arg(user_args,OPH_USER_OPENED_SESSIONS,tmp);
			if (num_sessions) num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
			else num_sessions = strtol(tmp,NULL,10);

			int max_sessions = oph_get_arg(user_args,OPH_USER_MAX_SESSIONS,tmp);
			if (max_sessions) max_sessions = OPH_DEFAULT_USER_MAX_SESSIONS;
			else max_sessions = strtol(tmp,NULL,10);

			int timeout_value = oph_get_arg(user_args,OPH_USER_TIMEOUT_SESSION,tmp);
			if (timeout_value) timeout_value = OPH_DEFAULT_SESSION_TIMEOUT;
			else timeout_value = strtol(tmp,NULL,10);

			oph_workflow *wf = (oph_workflow *)calloc(1,sizeof(oph_workflow));
			wf->username = strdup(username);
			wf->command = strdup("");

			pthread_mutex_lock(&global_flag);
			if (oph_generate_oph_jobid(state, 'R', 0, wf, &num_sessions, max_sessions, timeout_value, NULL, NULL, NULL, NULL, oph_jobid, 0)) success=0;
			else
			{
				int id_user, id_session;
				if ((result = oph_odb_retrieve_user_id_unsafe(&oDB, wf->username, &id_user)))
				{
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve user id.\n");
					success=0;
				}
				else if ((result = oph_odb_retrieve_session_id_unsafe(&oDB, wf->sessionid, &id_session)))
				{
					if (result != OPH_ODB_NO_ROW_FOUND)
					{
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to retrieve session id\n");
						success=0;
					}
					else if ((result = oph_odb_update_session_table_unsafe(&oDB, wf->sessionid, id_user, &id_session)))
					{
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to create a new entry in table 'session'\n");
						success=0;
					}
				}
			}
			pthread_mutex_unlock(&global_flag);

			new_sessionid = wf->sessionid ? strdup(wf->sessionid) : NULL;
			if (!wf->sessionid) snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");

			oph_workflow_free(wf);

			save_user=3;
		}
		else if (!session)
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_SESSION);
			success=0;
		}
		// Commands for readers
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_ENV,OPH_MAX_STRING_SIZE))
		{
			if (!(role & OPH_ROLE_READ))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			num_fields=2;
			if (success)
			{
				// Header
				success=0;
				while (!success)
				{
					  jsonkeys = (char **)malloc(sizeof(char *)*num_fields);
					  if (!jsonkeys) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  break;
					  }
					  jjj = 0;
					  jsonkeys[jjj] = strdup("PARAMETER");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup("VALUE");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj = 0;
					  fieldtypes = (char **)malloc(sizeof(char *)*num_fields);
					  if (!fieldtypes) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  if (oph_json_add_grid(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,"Session List",NULL,jsonkeys,num_fields,fieldtypes,num_fields)) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
					  if (jsonkeys) free(jsonkeys);
					  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
					  if (fieldtypes) free(fieldtypes);

					success=1;
				}
			}

			if (success)
			{
				oph_argument *tmp2, *us_args=NULL;
				time_t nowtime;
				struct tm *nowtm;
				// Data
				success=0;
				while (!success)
				{
					for (tmp2=args; tmp2; tmp2=tmp2->next)
					{
						if (!strcmp(tmp2->key,OPH_SESSION_USERS)) continue; // Use listusers instead
						if (tmp2->value)
						{
							if (!strcmp(tmp2->key,OPH_SESSION_CREATION_TIME) || !strcmp(tmp2->key,OPH_SESSION_LAST_ACCESS_TIME))
							{
								nowtime = (time_t)strtol(tmp2->value,NULL,10);
								nowtm = localtime(&nowtime);
								strftime(tmp, OPH_MAX_STRING_SIZE, "%Y-%m-%d %H:%M:%S", nowtm);
							}
							else strncpy(tmp,tmp2->value,OPH_MAX_STRING_SIZE);
						}
						jsonvalues = (char **)malloc(sizeof(char *)*num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							break;
						}
						jjj=0;
						jsonvalues[jjj] = strdup(tmp2->key);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(tmp2->value?tmp:"-");
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);

					}
					if (!tmp2) success=1;
					else break;

					oph_init_args(&us_args);
					snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_SESSION_FILE,oph_auth_location,_username,session_code);
					pthread_mutex_lock(&global_flag);
					if (oph_load_file(filename, &us_args)) // DT_REG
					{
						pmesg(LOG_ERROR, __FILE__,__LINE__,"unable to load user-specific session data of '%s'\n",sessionid);
						pthread_mutex_unlock(&global_flag);
						oph_cleanup_args(&us_args);
						break;
					}
					pthread_mutex_unlock(&global_flag);
					for (tmp2=us_args; tmp2; tmp2=tmp2->next)
					{
						jsonvalues = (char **)malloc(sizeof(char *)*num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							break;
						}
						jjj=0;
						jsonvalues[jjj] = strdup(tmp2->key);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = strdup(tmp2->value?tmp2->value:"-");
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);

					}
					oph_cleanup_args(&us_args);
					if (!tmp2) success=1;
					else break;
				}
			}
		}
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_LISTUSERS,OPH_MAX_STRING_SIZE))
		{
			if (!(role & OPH_ROLE_READ))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			num_fields=2;
			if (success)
			{
				// Header
				success=0;
				while (!success)
				{
					  jsonkeys = (char **)malloc(sizeof(char *)*num_fields);
					  if (!jsonkeys) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  break;
					  }
					  jjj = 0;
					  jsonkeys[jjj] = strdup("USER");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup("ROLE");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj = 0;
					  fieldtypes = (char **)malloc(sizeof(char *)*num_fields);
					  if (!fieldtypes) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  if (oph_json_add_grid(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,"Session List",NULL,jsonkeys,num_fields,fieldtypes,num_fields)) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
					  if (jsonkeys) free(jsonkeys);
					  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
					  if (fieldtypes) free(fieldtypes);

					success=1;
				}
			}

			if (success)
			{
				// Data
				success=0;
				while (!success)
				{
					jsonvalues = (char **)malloc(sizeof(char *)*num_fields);
					if (!jsonvalues) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						break;
					}
					jjj=0;
					jsonvalues[jjj] = strdup(owner);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					jjj++;
					jsonvalues[jjj] = strdup(OPH_ROLE_OWNER_STR);
					if (!jsonvalues[jjj]) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					if (oph_json_add_grid_row(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,jsonvalues)) {
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
						for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);
						break;
					}
					for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
					if (jsonvalues) free(jsonvalues);

					success=1;
				}
			}
			if (success && !oph_get_arg(args,OPH_SESSION_USERS,tmp))
			{
				char *save_pointer=NULL, *pch1, *pch2;
				// Data
				success=0;
				while (!success)
				{
					pch1 = strtok_r(tmp,OPH_SEPARATOR_USER,&save_pointer);
					while (pch1)
					{
						pch2 = strchr(pch1,OPH_SEPARATOR_ROLE);
						if (!pch2)
						{
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
							break;
						}

						jsonvalues = (char **)malloc(sizeof(char *)*num_fields);
						if (!jsonvalues) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							break;
						}
						jjj=0;
						jsonvalues[jjj] = strndup(pch1,pch2-pch1);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						jjj++;
						jsonvalues[jjj] = oph_expand_role_string(1+pch2);
						if (!jsonvalues[jjj]) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						if (oph_json_add_grid_row(oper_json,OPH_JSON_OBJKEY_MANAGE_SESSION_LIST,jsonvalues)) {
							pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							if (jsonvalues) free(jsonvalues);
							break;
						}
						for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						if (jsonvalues) free(jsonvalues);

						pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
					}
					if (!pch1) success=1;
					else break;
				}
			}
		}
		// Commands for writers
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_SETENV,OPH_MAX_STRING_SIZE))
		{
			if (!(role & OPH_ROLE_WRITE))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			if (success)
			{
				if (!key)
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_KEY);
					success=0;
				}
				else if (!strncasecmp(key,OPH_ARG_KEY_VALUE_LABEL,OPH_MAX_STRING_SIZE) || !strncasecmp(key,OPH_SESSION_LABEL,OPH_MAX_STRING_SIZE))
				{
					char label[OPH_MAX_STRING_SIZE];
					if (!value) *label=0;
					else snprintf(label,OPH_MAX_STRING_SIZE,"%s",value);
					if (oph_set_arg(&args, OPH_SESSION_LABEL, label))
					{
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_LABEL);
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl) hashtbl_destroy(task_tbl);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						return OPH_SERVER_SYSTEM_ERROR;
					}

					if(oph_odb_update_session_label(&oDB,session,label))
					{
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "unable to connect to OphidiaDB. Check access parameters\n");
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl) hashtbl_destroy(task_tbl);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						return OPH_SERVER_IO_ERROR;
					}

					save_session=1;
				}
				else if (strncmp(username,owner,OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER)) // Parameters for owners
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
					success=0;
				}
				else if (!strncasecmp(key,OPH_ARG_KEY_VALUE_ACTIVE,OPH_MAX_STRING_SIZE) || !strncasecmp(key,OPH_SESSION_ACTIVE,OPH_MAX_STRING_SIZE))
				{
					if (!value)
					{
						snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_VALUE);
						success=0;
					}
					else if (!strncasecmp(value,OPH_COMMON_YES,OPH_MAX_STRING_SIZE) || !strncasecmp(value,OPH_COMMON_NO,OPH_MAX_STRING_SIZE))
					{
						if (oph_set_arg(&args, OPH_SESSION_ACTIVE, value))
						{
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_ACTIVE);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl) hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						if (!strncasecmp(value,OPH_COMMON_NO,OPH_MAX_STRING_SIZE) && !strncmp(last_session,session,OPH_MAX_STRING_SIZE)) save_user=2;
						save_session=1;
					}
					else
					{
						snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s=%s'!",OPH_ARG_VALUE,value);
						success=0;
					}
				}
				else if (!strncasecmp(key,OPH_ARG_KEY_VALUE_AUTOREMOVE,OPH_MAX_STRING_SIZE) || !strncasecmp(key,OPH_SESSION_AUTOREMOVE,OPH_MAX_STRING_SIZE))
				{
					if (!value)
					{
						snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_VALUE);
						success=0;
					}
					else if (!strncasecmp(value,OPH_COMMON_YES,OPH_MAX_STRING_SIZE) || !strncasecmp(value,OPH_COMMON_NO,OPH_MAX_STRING_SIZE))
					{
						if (oph_set_arg(&args, OPH_SESSION_AUTOREMOVE, value))
						{
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_AUTOREMOVE);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl) hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						save_session=1;
					}
					else
					{
						snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s=%s'!",OPH_ARG_VALUE,value);
						success=0;
					}
				}
				else
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s=%s'!",OPH_ARG_KEY,key);
					success=0;
				}
			}
		}
		// Commands for administrators
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_GRANT,OPH_MAX_STRING_SIZE))
		{
			if (!(role & OPH_ROLE_ADMIN))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			if (success)
			{
				if (!key)
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_KEY);
					success=0;
				}
				else if (!strncasecmp(key,OPH_ARG_KEY_VALUE_USER,OPH_MAX_STRING_SIZE))
				{
					oph_argument *users, *tmp2;
					oph_auth_user_role nrole;
					char *save_pointer=NULL, *pch1, *pch2, session_username[OPH_MAX_STRING_SIZE];

					oph_init_args(&users);
					snprintf(tmp,OPH_MAX_STRING_SIZE,"%s",value);
					pch1 = strtok_r(tmp,OPH_SEPARATOR_USER,&save_pointer);
					while (pch1)
					{
						pch2 = strchr(pch1,OPH_SEPARATOR_ROLE);
						if (pch2)
						{
							strncpy(session_username,pch1,pch2-pch1);
							session_username[pch2-pch1]=0;
						}
						else snprintf(session_username,OPH_MAX_STRING_SIZE,"%s",pch1);
						if (strcmp(session_username,owner))
						{
							tmp2 = (oph_argument *)malloc(sizeof(oph_argument));
							if (!tmp2)
							{
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__,"memory allocation error\n");
								oph_cleanup_args(&users);
								oph_cleanup_args(&args);
								oph_cleanup_args(&user_args);
								if (task_tbl) hashtbl_destroy(task_tbl);
								oph_json_free(oper_json);
								oph_odb_disconnect_from_ophidiadb(&oDB);
								return OPH_SERVER_SYSTEM_ERROR;
							}
							tmp2->key = strndup(session_username,OPH_MAX_STRING_SIZE);
							if (!tmp2->key)
							{
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__,"memory allocation error\n");
								oph_cleanup_args(&users);
								oph_cleanup_args(&args);
								oph_cleanup_args(&user_args);
								if (task_tbl) hashtbl_destroy(task_tbl);
								oph_json_free(oper_json);
								oph_odb_disconnect_from_ophidiadb(&oDB);
								return OPH_SERVER_SYSTEM_ERROR;
							}
							if (pch2) tmp2->value = oph_code_role_string(1+pch2);
							else tmp2->value = oph_role_to_string(OPH_DEFAULT_SESSION_ROLE);
							if (!tmp2->value)
							{
								snprintf(error_message,OPH_MAX_STRING_SIZE,"Permissions of user '%s' are wrong!",tmp2->key);
								free(tmp2->key);
								free(tmp2);
								pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
								continue;
							}
							nrole = oph_string_to_role(tmp2->value);
							if (nrole == OPH_ROLE_NONE)
							{
								snprintf(error_message,OPH_MAX_STRING_SIZE,"Permissions of user '%s' will be not changed!",tmp2->key);
								free(tmp2->key);
								free(tmp2->value);
								free(tmp2);
								pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
								continue;
							}
							if (nrole >= OPH_ROLE_OWNER)
							{
								snprintf(error_message,OPH_MAX_STRING_SIZE,"Session ownership cannot be changed!");
								free(tmp2->key);
								free(tmp2->value);
								free(tmp2);
								pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
								continue;
							}
							tmp2->next = users;
							users = tmp2;

							pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__,"found user '%s' with role '%s'\n",tmp2->key,tmp2->value);
						}
						else snprintf(error_message,OPH_MAX_STRING_SIZE,"Permissions of the owner cannot be changed!");
						pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
					}
					char new_user_string[OPH_MAX_STRING_SIZE];
					if (!oph_get_arg(args,OPH_SESSION_USERS,tmp))
					{
						int first=1,pointer;
						char linkname[OPH_MAX_STRING_SIZE],newrole[OPH_MAX_STRING_SIZE];
						*new_user_string=0;
						success=0;
						while (!success)
						{
							pch1 = strtok_r(tmp,OPH_SEPARATOR_USER,&save_pointer);
							while (pch1)
							{
								pch2 = strchr(pch1,OPH_SEPARATOR_ROLE);
								if (!pch2)
								{
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
									break;
								}
								strncpy(session_username,pch1,pch2-pch1); // Username
								session_username[pch2-pch1]=0;
								snprintf(newrole,OPH_MAX_STRING_SIZE,"%s",1+pch2); // Role
								for (tmp2=users; tmp2; tmp2=tmp2->next) if (tmp2->key && !strncmp(session_username,tmp2->key,OPH_MAX_STRING_SIZE))
								{
									snprintf(newrole,OPH_MAX_STRING_SIZE,"%s",tmp2->value);
									free(tmp2->key);
									tmp2->key=0;
									break;
								}
								if (!first) strncat(new_user_string,OPH_SEPARATOR_USER,OPH_MAX_STRING_SIZE-strlen(new_user_string));
								else first=0;

								strncat(new_user_string,session_username,OPH_MAX_STRING_SIZE-strlen(new_user_string)-1);
								pointer=strlen(new_user_string);
								new_user_string[pointer]=OPH_SEPARATOR_ROLE;
								new_user_string[++pointer]=0;
								strncat(new_user_string,newrole,OPH_MAX_STRING_SIZE-strlen(new_user_string));

								pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
							}
							if (!pch1) success=1;
							else break;
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__,"user list will be updated to '%s'\n",new_user_string);
						// Add the new users
						if (success)
						{
							int first_link=1;
							oph_argument* us_args=NULL; // User-specific session data
							for (tmp2=users; tmp2; tmp2=tmp2->next) if (tmp2->key)
							{
								if (first_link)
								{
									snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,_username,session_code);
									pthread_mutex_lock(&global_flag);
									int nchars = readlink(linkname,newrole,OPH_MAX_STRING_SIZE);
									pthread_mutex_unlock(&global_flag);
									if (nchars<0)
									{
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__,"unable to solve symbolic link '%s'\n",linkname);
										oph_cleanup_args(&users);
										oph_cleanup_args(&args);
										oph_cleanup_args(&user_args);
										if (task_tbl) hashtbl_destroy(task_tbl);
										oph_json_free(oper_json);
										oph_odb_disconnect_from_ophidiadb(&oDB);
										return OPH_SERVER_SYSTEM_ERROR;
									}
									else if (nchars>=OPH_MAX_STRING_SIZE)
									{
										pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__,"real file name of '%s' is too long\n",linkname);
										oph_cleanup_args(&users);
										oph_cleanup_args(&args);
										oph_cleanup_args(&user_args);
										if (task_tbl) hashtbl_destroy(task_tbl);
										oph_json_free(oper_json);
										oph_odb_disconnect_from_ophidiadb(&oDB);
										return OPH_SERVER_SYSTEM_ERROR;
									}
									newrole[nchars]=0;
									first_link=0;
								}

								// Add user separator in case this user is not the first one
								if (!first) strncat(new_user_string,OPH_SEPARATOR_USER,OPH_MAX_STRING_SIZE-strlen(new_user_string));
								else first=0;

								strncat(new_user_string,tmp2->key,OPH_MAX_STRING_SIZE-strlen(new_user_string)-1);
								pointer=strlen(new_user_string);
								new_user_string[pointer]=OPH_SEPARATOR_ROLE;
								new_user_string[++pointer]=0;
								strncat(new_user_string,tmp2->value,OPH_MAX_STRING_SIZE-strlen(new_user_string));

								// Create the symbolic link
								strcpy(session_username,tmp2->key);
								jjj=strlen(session_username);
								for (iii=0;iii<jjj;iii++) if ((session_username[iii]=='/') || (session_username[iii]==' ') || (session_username[iii]=='=')) session_username[iii]='_';
								snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,session_username,session_code);

								oph_init_args(&us_args);
								if (oph_set_arg(&us_args, OPH_SESSION_CWD, OPH_WORKFLOW_ROOT_FOLDER))
								{
									pmesg(LOG_ERROR, __FILE__,__LINE__, "error in saving %s\n", OPH_SESSION_CWD);
									pthread_mutex_unlock(&global_flag);
									oph_cleanup_args(&us_args);
									oph_cleanup_args(&users);
									oph_cleanup_args(&args);
									oph_cleanup_args(&user_args);
									if (task_tbl) hashtbl_destroy(task_tbl);
									oph_json_free(oper_json);
									oph_odb_disconnect_from_ophidiadb(&oDB);
									return OPH_SERVER_SYSTEM_ERROR;
								}

								pthread_mutex_lock(&global_flag);
								if (symlink(newrole,linkname))
								{
									if (errno==EEXIST) pmesg(LOG_WARNING, __FILE__,__LINE__,"symbolic link '%s' already exists\n",linkname);
									else
									{
										pmesg(LOG_WARNING, __FILE__,__LINE__,"unable to create symbolic link '%s'\n",linkname);
										pthread_mutex_unlock(&global_flag);
										oph_cleanup_args(&us_args);
										oph_cleanup_args(&users);
										oph_cleanup_args(&args);
										oph_cleanup_args(&user_args);
										if (task_tbl) hashtbl_destroy(task_tbl);
										oph_json_free(oper_json);
										oph_odb_disconnect_from_ophidiadb(&oDB);
										return OPH_SERVER_SYSTEM_ERROR;
									}
								}
								if (oph_save_user_session(session_username,sessionid,us_args))
								{
									pmesg(LOG_ERROR, __FILE__,__LINE__, "error in saving user-specific session data\n");
									pthread_mutex_unlock(&global_flag);
									oph_cleanup_args(&us_args);
									oph_cleanup_args(&users);
									oph_cleanup_args(&args);
									oph_cleanup_args(&user_args);
									if (task_tbl) hashtbl_destroy(task_tbl);
									oph_json_free(oper_json);
									oph_odb_disconnect_from_ophidiadb(&oDB);
									return OPH_SERVER_SYSTEM_ERROR;
								}
								pthread_mutex_unlock(&global_flag);

								oph_cleanup_args(&us_args);

								free(tmp2->key);
								tmp2->key=0;
							}
						}
						pmesg_safe(&global_flag, LOG_DEBUG, __FILE__,__LINE__,"new user list is '%s'\n",new_user_string);
					}
					if (success)
					{
						if (oph_set_arg(&args,OPH_SESSION_USERS,new_user_string))
						{
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_USERS);
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl) hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						save_session=1;
					}
					oph_cleanup_args(&users);
				}
				else
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s=%s'!",OPH_ARG_KEY,key);
					success=0;
				}
			}
		}
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_REVOKE,OPH_MAX_STRING_SIZE))
		{
			if (!(role & OPH_ROLE_ADMIN))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			if (success)
			{
				if (!key)
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Expected parameter '%s'!",OPH_ARG_KEY);
					success=0;
				}
				else if (!strncasecmp(key,OPH_ARG_KEY_VALUE_USER,OPH_MAX_STRING_SIZE))
				{
					oph_argument *users, *tmp2;
					char *save_pointer=NULL, *pch1, session_username[OPH_MAX_STRING_SIZE], *pch2;

					oph_init_args(&users);
					strncpy(tmp,value,OPH_MAX_STRING_SIZE);
					pch1 = strtok_r(tmp,OPH_SEPARATOR_USER,&save_pointer);
					while (pch1)
					{
						pch2 = strchr(pch1,OPH_SEPARATOR_ROLE);
						if (pch2)
						{
							strncpy(session_username,pch1,pch2-pch1);
							session_username[pch2-pch1]=0;
						}
						else snprintf(session_username,OPH_MAX_STRING_SIZE,"%s",pch1);
						tmp2 = (oph_argument *)malloc(sizeof(oph_argument));
						if (!tmp2)
						{
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"memory allocation error\n");
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl) hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						tmp2->key = strndup(session_username,OPH_MAX_STRING_SIZE);
						if (!tmp2->key)
						{
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"memory allocation error\n");
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl) hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						tmp2->value = NULL;
						tmp2->next = users;
						users = tmp2;
						pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
					}
					char new_user_string[OPH_MAX_STRING_SIZE];
					if (!oph_get_arg(args,OPH_SESSION_USERS,tmp))
					{
						int first=1;
						char linkname[OPH_MAX_STRING_SIZE];
						*new_user_string=0;
						success=0;
						while (!success)
						{
							pch1 = strtok_r(tmp,OPH_SEPARATOR_USER,&save_pointer);
							while (pch1)
							{
								pch2 = strchr(pch1,OPH_SEPARATOR_ROLE);
								if (!pch2)
								{
									pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
									break;
								}
								strncpy(session_username,pch1,pch2-pch1);
								session_username[pch2-pch1]=0;
								for (tmp2=users; tmp2; tmp2=tmp2->next) if (tmp2->key && !strncmp(session_username,tmp2->key,OPH_MAX_STRING_SIZE))
								{
									jjj=strlen(session_username);
									for (iii=0;iii<jjj;iii++) if ((session_username[iii]=='/') || (session_username[iii]==' ') || (session_username[iii]=='=')) session_username[iii]='_';
									snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,session_username,session_code);
									pthread_mutex_lock(&global_flag);
									remove(linkname);
									snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_USER_SESSION_FILE,oph_auth_location,session_username,session_code);
									remove(linkname);
									pthread_mutex_unlock(&global_flag);
									break;
								}
								if (!tmp2)
								{
									if (!first) strncat(new_user_string,OPH_SEPARATOR_USER,OPH_MAX_STRING_SIZE-strlen(new_user_string));
									else first=0;
									strncat(new_user_string,pch1,OPH_MAX_STRING_SIZE-strlen(new_user_string));
								}
								pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
							}
							if (!pch1) success=1;
							else break;
						}
					}
					if (success)
					{
						if (oph_set_arg(&args,OPH_SESSION_USERS,new_user_string))
						{
							pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_USERS);
							oph_cleanup_args(&users);
							oph_cleanup_args(&args);
							oph_cleanup_args(&user_args);
							if (task_tbl) hashtbl_destroy(task_tbl);
							oph_json_free(oper_json);
							oph_odb_disconnect_from_ophidiadb(&oDB);
							return OPH_SERVER_SYSTEM_ERROR;
						}
						save_session=1;
					}
					oph_cleanup_args(&users);
				}
				else
				{
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s=%s'!",OPH_ARG_KEY,key);
					success=0;
				}
			}
		}
		// Commands for owners
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_DISABLE,OPH_MAX_STRING_SIZE))
		{
			if (strncmp(username,owner,OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			else
			{
				if (oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_COMMON_NO))
				{
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_ACTIVE);
					oph_cleanup_args(&args);
					oph_cleanup_args(&user_args);
					if (task_tbl) hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (!strncmp(last_session,session,OPH_MAX_STRING_SIZE)) save_user=2;
				save_session=1;
			}
		}
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_ENABLE,OPH_MAX_STRING_SIZE))
		{
			if (strncmp(username,owner,OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			else
			{
				if (oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_COMMON_YES))
				{
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_SESSION_ACTIVE);
					oph_cleanup_args(&args);
					oph_cleanup_args(&user_args);
					if (task_tbl) hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				save_session=1;
			}
		}
		else if (!strncasecmp(action,OPH_ARG_ACTION_VALUE_REMOVE,OPH_MAX_STRING_SIZE))
		{
			if (strncmp(username,owner,OPH_MAX_STRING_SIZE) || !(role & OPH_ROLE_OWNER))
			{
				snprintf(error_message,OPH_MAX_STRING_SIZE,"Permission denied!");
				success=0;
			}
			else
			{
				char linkname[OPH_MAX_STRING_SIZE];
				if (!oph_get_arg(args,OPH_SESSION_USERS,tmp))
				{
					char *save_pointer=NULL, *pch1, *pch2;
					char session_username[OPH_MAX_STRING_SIZE];
					success=0;
					while (!success)
					{
						pch1 = strtok_r(tmp,OPH_SEPARATOR_USER,&save_pointer);
						while (pch1)
						{
							pch2 = strchr(pch1,OPH_SEPARATOR_ROLE);
							if (!pch2)
							{
								pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Session file is corrupted\n");
								break;
							}
							strncpy(session_username,pch1,pch2-pch1);
							session_username[pch2-pch1]=0;
							jjj=strlen(session_username);
							for (iii=0;iii<jjj;iii++) if ((session_username[iii]=='/') || (session_username[iii]==' ') || (session_username[iii]=='=')) session_username[iii]='_';
							snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,session_username,session_code);
							pthread_mutex_lock(&global_flag);
							remove(linkname);
							snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_USER_SESSION_FILE,oph_auth_location,session_username,session_code);
							remove(linkname);
							pthread_mutex_unlock(&global_flag);
							pch1 = strtok_r(NULL,OPH_SEPARATOR_USER,&save_pointer);
						}
						if (!pch1) success=1;
						else break;
					}
				}
				if (success)
				{
					if (oph_set_arg(&args,OPH_SESSION_USERS,"") || oph_set_arg(&args, OPH_SESSION_ACTIVE, OPH_COMMON_NO))
					{
						pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__,"unable to set session data\n");
						oph_cleanup_args(&args);
						oph_cleanup_args(&user_args);
						if (task_tbl) hashtbl_destroy(task_tbl);
						oph_json_free(oper_json);
						oph_odb_disconnect_from_ophidiadb(&oDB);
						return OPH_SERVER_SYSTEM_ERROR;
					}
					if (!strncmp(last_session,session,OPH_MAX_STRING_SIZE)) save_user=2;
					save_session=2; // Means that file will be removed
				}
			}
		}
		else
		{
			snprintf(error_message,OPH_MAX_STRING_SIZE,"Wrong parameter '%s=%s'!",OPH_ARG_ACTION,action);
			success=0;
		}

		if (success && save_session)
		{
			pthread_mutex_lock(&global_flag);
			if (oph_save_session(_username, session, args, DT_LNK))
			{
				pmesg(LOG_WARNING, __FILE__,__LINE__,"unable to save session data of '%s'\n",session);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&args);
				oph_cleanup_args(&user_args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_json_free(oper_json);
				if (new_sessionid) free(new_sessionid);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			if (save_session>1) // Remove the intended session
			{
				char linkname[OPH_MAX_STRING_SIZE];
				snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,_username,session_code);
				remove(linkname);
				snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_USER_SESSION_FILE,oph_auth_location,_username,session_code);
				remove(linkname);
				if (num_sessions<0)
				{
					num_sessions = oph_get_arg(user_args,OPH_USER_OPENED_SESSIONS,tmp);
					if (num_sessions) num_sessions = OPH_DEFAULT_USER_OPENED_SESSIONS;
					else num_sessions = strtol(tmp,NULL,10);
				}
				if (num_sessions>0) num_sessions--;
				else
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "error in handling session number\n");
					pthread_mutex_unlock(&global_flag);
					oph_cleanup_args(&args);
					oph_cleanup_args(&user_args);
					if (task_tbl) hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					if (new_sessionid) free(new_sessionid);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (!save_user) save_user=1;
			}
			pthread_mutex_unlock(&global_flag);
		}
		oph_cleanup_args(&args);

		// Update user data
		if (success && save_user)
		{
			if (save_user>1) // Reset OPH_USER_LAST_SESSION_ID or set to sessionid
			{
				char *new_jobid = strdup(save_user>2 ? (new_sessionid ? new_sessionid : "") : "");
				if (oph_set_arg(&user_args, OPH_USER_LAST_SESSION_ID, new_jobid))
				{
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_USER_LAST_SESSION_ID);
					oph_cleanup_args(&user_args);
					if (task_tbl) hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					if (new_sessionid) free(new_sessionid);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					return OPH_SERVER_SYSTEM_ERROR;
				}
				if (jobid_response)
				{
					if (*jobid_response) free(*jobid_response);
					*jobid_response = new_jobid;
				}
				else free(new_jobid);
			}
			if (num_sessions>=0)
			{
				snprintf(tmp,OPH_SHORT_STRING_SIZE,"%d",num_sessions);
				if (oph_set_arg(&user_args, OPH_USER_OPENED_SESSIONS, tmp))
				{
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__,"unable to set '%s'\n",OPH_USER_LAST_SESSION_ID);
					oph_cleanup_args(&user_args);
					if (task_tbl) hashtbl_destroy(task_tbl);
					oph_json_free(oper_json);
					if (new_sessionid) free(new_sessionid);
					oph_odb_disconnect_from_ophidiadb(&oDB);
					return OPH_SERVER_SYSTEM_ERROR;
				}
			}
			pthread_mutex_lock(&global_flag);
			if (oph_save_user(_username,user_args))
			{
				pmesg(LOG_WARNING, __FILE__,__LINE__,"unable to save user data of '%s'\n",username);
				pthread_mutex_unlock(&global_flag);
				oph_cleanup_args(&user_args);
				if (task_tbl) hashtbl_destroy(task_tbl);
				oph_json_free(oper_json);
				if (new_sessionid) free(new_sessionid);
				oph_odb_disconnect_from_ophidiadb(&oDB);
				return OPH_SERVER_SYSTEM_ERROR;
			}
			pthread_mutex_unlock(&global_flag);
		}
		oph_cleanup_args(&user_args);
		if (new_sessionid) free(new_sessionid);

		if (task_tbl) hashtbl_destroy(task_tbl);

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}
	else if (!strncasecmp(operator_name,OPH_OPERATOR_LOG_INFO,OPH_MAX_STRING_SIZE))
	{
		error = OPH_SERVER_SYSTEM_ERROR;

		HASHTBL *task_tbl = NULL;
		if (oph_tp_task_params_parser(operator_name, request, &task_tbl))
		{
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "%s task parser error\n");
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_WRONG_PARAMETER_ERROR;
		}

		char** objkeys = NULL;
		int objkeys_num, success=0, nlines;
		oph_json* oper_json = NULL;
		char *value, username[OPH_MAX_STRING_SIZE], session_code[OPH_MAX_STRING_SIZE], workflowid[OPH_MAX_STRING_SIZE], oph_jobid[OPH_MAX_STRING_SIZE], error_message[OPH_MAX_STRING_SIZE];
		*error_message=0;

		value = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_LOG_TYPE);
		if (!value || strncasecmp(value,OPH_OPERATOR_LOG_INFO_PARAMETER_SERVER,OPH_MAX_STRING_SIZE))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_OPERATOR_PARAMETER_LOG_TYPE);
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_UNKNOWN;
		}

		if (oph_tp_find_param_in_task_string(request, OPH_ARG_JOBID, &oph_jobid))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to get %s\n", OPH_ARG_JOBID);
			if (task_tbl) hashtbl_destroy(task_tbl);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		int idjob = (int)strtol(oph_jobid, NULL, 10);

		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Error in reading OphidiaDB params\n");
			if (task_tbl) hashtbl_destroy(task_tbl);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Unable to connect to OphidiaDB\n");
			if (task_tbl) hashtbl_destroy(task_tbl);
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		oph_odb_start_job_fast(idjob, &oDB);

		while(1)
		{
			if (oph_get_session_code(sessionid, session_code))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}
			if (oph_tp_find_param_in_task_string(request, OPH_ARG_WORKFLOWID, &workflowid))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_WORKFLOWID);
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}
			snprintf(oph_jobid,OPH_MAX_STRING_SIZE,"%s%s%s%s%s",sessionid,OPH_SESSION_WORKFLOW_DELIMITER,workflowid,OPH_SESSION_MARKER_DELIMITER,markerid);

			if (oph_tp_find_param_in_task_string(request, OPH_ARG_USERNAME, &username))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_USERNAME);
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}

			value = hashtbl_get(task_tbl, OPH_OPERATOR_PARAMETER_LINES_NUMBER);
			if (!value)
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to get %s\n",OPH_ARG_WORKFLOWID);
				error = OPH_SERVER_WRONG_PARAMETER_ERROR;
				break;
			}
			nlines = strtol(value, NULL, 10);

			if (oph_json_alloc(&oper_json))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "JSON alloc error\n");
				break;
			}
			if (oph_json_set_source(oper_json,"oph","Ophidia",NULL,"Ophidia Data Source",username))
			{
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "SET SOURCE error\n");
				break;
			}
			if (oph_json_add_source_detail(oper_json,"Session Code",session_code))
			{
				  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Workflow",workflowid))
			{
				  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"Marker",markerid))
			{
				  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_source_detail(oper_json,"JobID",oph_jobid))
			{
				  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD SOURCE DETAIL error\n");
				  break;
			}
			if (oph_json_add_consumer(oper_json,username))
			{
				  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
				  break;
			}

			if (oph_log_file_name)
			{
				value = hashtbl_get(task_tbl, OPH_ARG_OBJKEY_FILTER);
				if (!value)
				{
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD CONSUMER error\n");
					error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				}
				if(oph_tp_parse_multiple_value_param(value, &objkeys, &objkeys_num))
				{
					pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Operator string not valid\n");
					oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
					error = OPH_SERVER_WRONG_PARAMETER_ERROR;
					break;
				}

				int is_objkey_printable = oph_json_is_objkey_printable(objkeys,objkeys_num,OPH_JSON_OBJKEY_LOG_INFO);
				if (is_objkey_printable)
				{
					int num_fields = 3, iii,jjj=0;

					// Header
					  char **jsonkeys = NULL;
					  char **fieldtypes = NULL;
					  jsonkeys = (char **)malloc(sizeof(char *)*num_fields);
					  if (!jsonkeys) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  break;
					  }
					  jsonkeys[jjj] = strdup("TIMESTAMP");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup("TYPE");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj++;
					  jsonkeys[jjj] = strdup("MESSAGE");
					  if (!jsonkeys[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii=0;iii<jjj;iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  jjj = 0;
					  fieldtypes = (char **)malloc(sizeof(char *)*num_fields);
					  if (!fieldtypes) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  break;
					  }
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  jjj++;
					  fieldtypes[jjj] = strdup(OPH_JSON_STRING);
					  if (!fieldtypes[jjj]) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < jjj; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  if (oph_json_add_grid(oper_json,OPH_JSON_OBJKEY_LOG_INFO,"Log Data",NULL,jsonkeys,num_fields,fieldtypes,num_fields)) {
						  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID error\n");
						  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
						  if (jsonkeys) free(jsonkeys);
						  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
						  if (fieldtypes) free(fieldtypes);
						  break;
					  }
					  for (iii = 0; iii < num_fields; iii++) if (jsonkeys[iii]) free(jsonkeys[iii]);
					  if (jsonkeys) free(jsonkeys);
					  for (iii = 0; iii < num_fields; iii++) if (fieldtypes[iii]) free(fieldtypes[iii]);
					  if (fieldtypes) free(fieldtypes);
				  }

				  char *lines;
				  if (nlines>0) {
				      lines = (char *) malloc(nlines*OPH_MAX_STRING_SIZE + 1);
				      if (!lines) {
					  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
					  break;
				      }
				  } else {
				      pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Invalid lines_number value\n");
				      break;
				  }

				  FILE *file;
				  file = fopen(oph_log_file_name, "r");
				  if(file == NULL) {
					  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "File %s cannot be opened\n",oph_log_file_name);
					  free(lines);
					  break;
				  }

				  fseek(file, 0, SEEK_END);
				  if (!ftell(file))
				  {
					snprintf(error_message,OPH_MAX_STRING_SIZE,"Server log is empty");
					pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "File %s is empty\n",oph_log_file_name);
					fclose(file);
					free(lines);
					success=1;
					break;
				  }

				  memset(lines,0,nlines*OPH_MAX_STRING_SIZE+1);

				  fseek(file,-1,SEEK_END);
				  char c;
				  int i=nlines*OPH_MAX_STRING_SIZE -1;
				  int count=0;
				  int flag=0;
				  do {
				      c = getc(file);
				      if (c=='\n' && i!=(nlines*OPH_MAX_STRING_SIZE -1)) {
					  count++;
					  if (count==nlines) {
					      flag=1;
					      break;
					  }
				      }
				      lines[i] = c;
				      i--;
				  } while((fseek(file,-2,SEEK_CUR))==0);
				  fclose(file);

				  if (flag==0) count++;

				  char *ptr=0;
				  for (i = 0; i < nlines*OPH_MAX_STRING_SIZE +1; i++) {
				      if (lines[i]!='\0') {
					  ptr = lines + i;
					  break;
				      }
				  }
				  snprintf(error_message,OPH_MAX_STRING_SIZE,"%s",ptr?ptr:"");

				  if (ptr && is_objkey_printable)
				  {
					int num_fields = 3, iii, jjj=0, kkk=0, print_data, k;
					char *jsontmp[num_fields];
					char **jsonvalues = NULL;
					char *my_ptr = ptr;

					while (my_ptr)
					{
					  for (k=0;k<num_fields;++k) jsontmp[k]=0;
					  k=0;
					  while (my_ptr && (*my_ptr!='\n') && (*my_ptr!='\0'))
					  {
						if (*my_ptr == '[')
						{
							if (k<num_fields) jsontmp[k++]=my_ptr+1;
						}
						else if (*my_ptr == ']')
						{
							if (!jsontmp[1] || !jsontmp[2]) *my_ptr='\0';
							else if (*(jsontmp[2])!='\t') jsontmp[2]=my_ptr+1;
						}
						my_ptr++;
					  }

					  if (!my_ptr || (*my_ptr=='\0')) break;

					  *my_ptr='\0';
					  my_ptr++;

					  if (jsontmp[2] && (*(jsontmp[2])=='\t')) (jsontmp[2])++;

					  print_data=1;
					  for (k=0;k<num_fields;++k) if (!jsontmp[k]) { print_data=0; break; }
					  if (print_data)
					  {
						  jsonvalues = (char **)malloc(sizeof(char *)*num_fields);
						  if (!jsonvalues) {
							  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
							  break;
						  }
						  for (jjj = 0; jjj < num_fields; jjj++)
						  {
							  jsonvalues[jjj] = strdup(jsontmp[jjj]);
							  if (!jsonvalues[jjj]) {
								  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
								  for (iii = 0; iii < jjj; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
								  if (jsonvalues) free(jsonvalues);
								  break;
							  }
						  }
						  if (oph_json_add_grid_row(oper_json,OPH_JSON_OBJKEY_LOG_INFO,jsonvalues)) {
							  pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "ADD GRID ROW error\n");
							  for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
							  if (jsonvalues) free(jsonvalues);
							  break;
						  }
						  for (iii = 0; iii < num_fields; iii++) if (jsonvalues[iii]) free(jsonvalues[iii]);
						  if (jsonvalues) free(jsonvalues);
					  }
					  kkk++;
					}
				  }

				  free(lines);
				  success=1;
			}
			else snprintf(error_message,OPH_MAX_STRING_SIZE,"Server log not found!");
			break;
		}

		if (task_tbl) hashtbl_destroy(task_tbl);
		if(objkeys)
		{
			oph_tp_free_multiple_value_param_list(objkeys, objkeys_num);
	      		objkeys = NULL;
		}

		if (!oper_json)
		{
			oph_odb_disconnect_from_ophidiadb(&oDB);
			return error;
		}

		if (oph_finalize_known_operator(idjob, oper_json, operator_name, error_message, success, response, &oDB, exit_code)) return OPH_SERVER_SYSTEM_ERROR;

		error = OPH_SERVER_NO_RESPONSE;
	}

	return error;
}

