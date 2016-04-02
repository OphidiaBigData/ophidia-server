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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "oph_workflow_library.h"
#include "debug.h"
#include "oph_auth.h"

int oph_workflow_var_substitute(oph_workflow *workflow, int task_index, char* submit_string, char** error)
{
	unsigned int i,l=strlen(OPH_WORKFLOW_SEPARATORS),offset;
	char *p, *ep, firstc, lastc, lastcc, return_error;
	char replaced_value[OPH_WORKFLOW_MAX_STRING], target_value[OPH_WORKFLOW_MAX_STRING];
	oph_workflow_var *var;

	while (((p=strchr(submit_string,OPH_WORKFLOW_VARIABLE_PREFIX))) || ((p=strchr(submit_string,OPH_WORKFLOW_INDEX_PREFIX))))
	{
		firstc = 1;
		lastc = lastcc = 0;
		for (ep=p+1;*ep;ep++) // assuming compliance with IEEE Std 1003.1-2001 conventions
		{
			if (firstc)
			{
				firstc=0;
				if (*ep==OPH_WORKFLOW_BRACKET[0]) { lastc=1; continue; }
			}
			if (lastc && (*ep==OPH_WORKFLOW_BRACKET[1])) { lastcc=1; break; }
			for (i=0;i<l;++i) if (*ep==OPH_WORKFLOW_SEPARATORS[i]) break;
			if (i<l) break;
			if (lastc || (*ep=='_') || ((*ep>='A') && (*ep<='Z')) || ((*ep>='a') && (*ep<='z')) || ((ep-p>1) && (*ep>='0') && (*ep<='9'))) continue;
			break;
		}
		strncpy(target_value,p,ep-p);
		target_value[ep-p] = 0;
		if (lastcc) ep++;

		if (lastc != lastcc) return_error = 1;
		else if (workflow->tasks[task_index].vars && ((var = hashtbl_get(workflow->tasks[task_index].vars, target_value+1+lastc)))) return_error = 0;
		else if (workflow->vars && ((var = hashtbl_get(workflow->vars, target_value+1+lastc))) && oph_workflow_is_child_of(workflow, var->caller, task_index)) return_error = 0;
		else return_error = 1;
		if (return_error)
		{
			char _error[OPH_WORKFLOW_MAX_STRING];
			snprintf(_error,OPH_WORKFLOW_MAX_STRING,"Bad variable '%s' in task '%s'",target_value,workflow->tasks[task_index].name);
			pmesg(LOG_WARNING,__FILE__,__LINE__,"%s of workflow '%s'\n",_error,workflow->name);
			if (error) *error = strdup(_error);
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
		offset = p-submit_string;
		*replaced_value = 0;
		strncpy(replaced_value, submit_string, offset);
		replaced_value[offset] = 0;
		if (*target_value==OPH_WORKFLOW_INDEX_PREFIX) snprintf(replaced_value+offset, OPH_WORKFLOW_MAX_STRING, "%d%s", var->ivalue, ep);
		else snprintf(replaced_value+offset, OPH_WORKFLOW_MAX_STRING, "%s%s", var->svalue, ep);
		strcpy(submit_string, replaced_value);
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_get_submission_string(oph_workflow *workflow, int task_index, int light_task_index, char** long_submission_string, char** short_submission_string, char** error)
{
	if (error) *error = NULL;
	if (!workflow || !long_submission_string)
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Null parameter\n");
		if (error) *error = strdup("Null parameter");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	if ((task_index<0) || (task_index>workflow->tasks_num) || ((task_index==workflow->tasks_num) && strcmp(workflow->tasks[task_index].name,OPH_WORKFLOW_FINAL_TASK)))
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Index out of boundaries\n");
		if (error) *error = strdup("Index out of boundaries");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	int subtask = light_task_index>=0;
	if (subtask)
	{
		if (light_task_index>=workflow->tasks[task_index].light_tasks_num)
		{
			pmesg(LOG_ERROR,__FILE__,__LINE__,"Index out of boundaries\n");
			if (error) *error = strdup("Index out of boundaries");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	int i,j;
	unsigned int length;
	char long_submit_string[OPH_WORKFLOW_MAX_STRING], short_submit_string[OPH_WORKFLOW_MAX_STRING];
	char key_value[OPH_WORKFLOW_MAX_STRING];
	char* key, *value, *value2;
	char* path_key[OPH_WORKFLOW_PATH_SET_SIZE] = OPH_WORKFLOW_PATH_SET;
	char path_value[OPH_WORKFLOW_MAX_STRING];
	char session_code[OPH_WORKFLOW_MAX_STRING];
	if (oph_get_session_code(workflow->sessionid, session_code))
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Unable to get session code\n");
		if (error) *error = strdup("Unable to get session code");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	snprintf(long_submit_string,OPH_WORKFLOW_MAX_STRING,OPH_WORKFLOW_EXT_SUB_STRING,workflow->tasks[task_index].operator,workflow->sessionid,workflow->workflowid,subtask ? workflow->tasks[task_index].light_tasks[light_task_index].markerid : workflow->tasks[task_index].markerid,workflow->username,workflow->userrole,workflow->idjob,task_index,light_task_index);

	if (short_submission_string) snprintf(short_submit_string,OPH_WORKFLOW_MAX_STRING,"%s ",workflow->tasks[task_index].operator);

	for (j=0; j < (subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_num : workflow->tasks[task_index].arguments_num); ++j)
	{
		key = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_keys[j] : workflow->tasks[task_index].arguments_keys[j];
		value = value2 = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_values[j] : workflow->tasks[task_index].arguments_values[j];
		if (key && value && strlen(key) && strlen(value))
		{
			// Path correction
			if (value[0]==OPH_WORKFLOW_ROOT_FOLDER[0])
			{
				for (i=0;i<OPH_WORKFLOW_PATH_SET_SIZE;++i) if (!strcmp(key,path_key[i]))
				{
					snprintf(path_value,OPH_WORKFLOW_MAX_STRING,"%s%s%s",OPH_WORKFLOW_ROOT_FOLDER,session_code,strlen(value)>1?value:"");
					value = path_value;
					break;
				}
			}
			snprintf(key_value,OPH_WORKFLOW_MAX_STRING,strchr(value,OPH_WORKFLOW_VALUE_SEPARATOR)?OPH_WORKFLOW_KEY_VALUE_STRING2:OPH_WORKFLOW_KEY_VALUE_STRING,key,value);
			if ((length = OPH_WORKFLOW_MAX_STRING-strlen(long_submit_string)) <= strlen(key_value))
			{
				pmesg(LOG_ERROR,__FILE__,__LINE__,"Space for submission string is not enough\n");
				if (error) *error = strdup("Space for submission string is not enough");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			strncat(long_submit_string,key_value,length);
			if (short_submission_string)
			{
				if (value!=value2) snprintf(key_value,OPH_WORKFLOW_MAX_STRING,strchr(value2,OPH_WORKFLOW_VALUE_SEPARATOR)?OPH_WORKFLOW_KEY_VALUE_STRING2:OPH_WORKFLOW_KEY_VALUE_STRING,key,value2);
				strncat(short_submit_string,key_value,length);
			}
		}
		else pmesg(LOG_WARNING,__FILE__,__LINE__,"Argument skipped\n");
	}

	// Variable substitution
	if (oph_workflow_var_substitute(workflow, task_index, long_submit_string, error)) return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	pmesg(LOG_DEBUG,__FILE__,__LINE__,"Submission string of '%s' is '%s'\n",workflow->tasks[task_index].name,long_submit_string);

	*long_submission_string = strdup(long_submit_string);
	if (!(*long_submission_string))
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Unable to allocate submission string\n");
		if (error) *error = strdup("Unable to allocate submission string");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	if (short_submission_string)
	{
		// Variable substitution
		if (oph_workflow_var_substitute(workflow, task_index, short_submit_string, error)) return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		*short_submission_string = strdup(short_submit_string);
		if (!(*short_submission_string))
		{
			pmesg(LOG_ERROR,__FILE__,__LINE__,"Unable to allocate submission string\n");
			if (error) *error = strdup("Unable to allocate submission string");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}


int oph_workflow_get_submitted_string(oph_workflow *workflow, int task_index, int light_task_index, int show_callback, char** submitted_string)
{
	if (!workflow || !submitted_string)
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	if ((task_index<0) || (task_index>workflow->tasks_num) || ((task_index==workflow->tasks_num) && strcmp(workflow->tasks[task_index].name,OPH_WORKFLOW_FINAL_TASK)))
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Index out of boundaries\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	int subtask = light_task_index>=0;
	if (subtask)
	{
		if (light_task_index>=workflow->tasks[task_index].light_tasks_num)
		{
			pmesg(LOG_ERROR,__FILE__,__LINE__,"Index out of boundaries\n");
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	int j;
	unsigned int length;
	char submit_string[OPH_WORKFLOW_MAX_STRING];
	char key_value[OPH_WORKFLOW_MAX_STRING];
	char* key, *value;

	snprintf(submit_string,OPH_WORKFLOW_MAX_STRING,"%s ",workflow->tasks[task_index].operator);
	if (workflow->exec_mode && strlen(workflow->exec_mode))
	{
		snprintf(key_value,OPH_WORKFLOW_MAX_STRING,strchr(workflow->exec_mode,OPH_WORKFLOW_VALUE_SEPARATOR)?OPH_WORKFLOW_KEY_VALUE_STRING2:OPH_WORKFLOW_KEY_VALUE_STRING,"exec_mode",workflow->exec_mode);
		if ((length = OPH_WORKFLOW_MAX_STRING-strlen(submit_string)) <= strlen(key_value))
		{
			pmesg(LOG_ERROR,__FILE__,__LINE__,"Space for submission string is not enough\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		strncat(submit_string,key_value,length);
	}
	if (show_callback && workflow->callback_url && strlen(workflow->callback_url))
	{
		snprintf(key_value,OPH_WORKFLOW_MAX_STRING,strchr(workflow->callback_url,OPH_WORKFLOW_VALUE_SEPARATOR)?OPH_WORKFLOW_KEY_VALUE_STRING2:OPH_WORKFLOW_KEY_VALUE_STRING,"callback_url",workflow->callback_url);
		if ((length = OPH_WORKFLOW_MAX_STRING-strlen(submit_string)) <= strlen(key_value))
		{
			pmesg(LOG_ERROR,__FILE__,__LINE__,"Space for submission string is not enough\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		strncat(submit_string,key_value,length);
	}
	for (j=0; j < (subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_num : workflow->tasks[task_index].arguments_num); ++j)
	{
		key = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_keys[j] : workflow->tasks[task_index].arguments_keys[j];
		value = subtask ? workflow->tasks[task_index].light_tasks[light_task_index].arguments_values[j] : workflow->tasks[task_index].arguments_values[j];
		if (key && value && strlen(key) && strlen(value))
		{
			snprintf(key_value,OPH_WORKFLOW_MAX_STRING,strchr(value,OPH_WORKFLOW_VALUE_SEPARATOR)?OPH_WORKFLOW_KEY_VALUE_STRING2:OPH_WORKFLOW_KEY_VALUE_STRING,key,value);
			if ((length = OPH_WORKFLOW_MAX_STRING-strlen(submit_string)) <= strlen(key_value))
			{
				pmesg(LOG_ERROR,__FILE__,__LINE__,"Space for submission string is not enough\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			strncat(submit_string,key_value,length);
		}
		else pmesg(LOG_WARNING,__FILE__,__LINE__,"Argument skipped\n");
	}
	pmesg(LOG_DEBUG,__FILE__,__LINE__,"Submission string of '%s' is '%s'\n",workflow->tasks[task_index].name,submit_string);

	*submitted_string = strdup(submit_string);
	if (!(*submitted_string))
	{
		pmesg(LOG_ERROR,__FILE__,__LINE__,"Unable to alloc submission string\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

// Other utililty functions

