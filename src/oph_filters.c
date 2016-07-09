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

#include "oph_filters.h"
#include "oph_auth.h"
#include "oph_task_parser_library.h"
#include "oph_ophidiadb_fs_library.h"
#include "oph_subset_library.h"

extern char* oph_web_server;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_filter_level(char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	UNUSED(tables)

	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_LEVEL,value);

	int i, level, key_num, s;
	char condition[OPH_MAX_STRING_SIZE], **key_list=NULL;
	if (oph_tp_parse_multiple_value_param (value, &key_list, &key_num)) return OPH_MF_ERROR;
	if (!key_num) return OPH_MF_ERROR;

	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			return OPH_MF_ERROR;
		}
		strncat(where_clause," AND (",s);
	}
	else snprintf(where_clause,OPH_MAX_STRING_SIZE,"(");

	for (i=0;i<key_num;++i)
	{
		level = (int)strtol(key_list[i],NULL,10);
		if (i)
		{
			if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
			{
				oph_tp_free_multiple_value_param_list(key_list, key_num);
				return OPH_MF_ERROR;
			}
			strncat(where_clause, " OR ", s);
		}
		snprintf(condition,OPH_MAX_STRING_SIZE,"%s.level='%d'",OPH_MF_ARG_DATACUBE,level);
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			return OPH_MF_ERROR;
		}
		strncat(where_clause,condition,s);
	}

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
	{
		oph_tp_free_multiple_value_param_list(key_list, key_num);
		return OPH_MF_ERROR;
	}
	strncat(where_clause,")",s);

	oph_tp_free_multiple_value_param_list(key_list, key_num);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_LEVEL,value);
	return OPH_MF_OK;
}

int oph_filter_measure(const char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	UNUSED(tables)

	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_MEASURE,value);

	char condition[OPH_MAX_STRING_SIZE];
	int s;
	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," AND ",s);
	}
	snprintf(condition,OPH_MAX_STRING_SIZE,"%s.measure='%s'",OPH_MF_ARG_DATACUBE,value);
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,condition,s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_MEASURE,value);
	return OPH_MF_OK;
}

int oph_filter_parent(char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_PARENT,value);

	if (strncasecmp(value,oph_web_server,strlen(oph_web_server)))
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		return OPH_MF_ERROR;
	}

	char *pointer1 = value+strlen(oph_web_server);
	if (*pointer1 != OPH_MF_ROOT_FOLDER[0])
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		return OPH_MF_ERROR;
	}
	pointer1++;

	char condition[OPH_MAX_STRING_SIZE];
	strncpy(condition,pointer1,OPH_MAX_STRING_SIZE);
	char *savepointer = NULL, *pointer2 = strtok_r(condition,OPH_MF_ROOT_FOLDER,&savepointer);
	if (!pointer2)
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		return OPH_MF_ERROR;
	}
	pointer2 = strtok_r(NULL,OPH_MF_ROOT_FOLDER,&savepointer);
	if (!pointer2)
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		return OPH_MF_ERROR;
	}
	
	int s, idcontainer = (int)strtol(pointer1,NULL,10), idparent = (int)strtol(pointer2,NULL,10);	

	if (*tables)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0) return OPH_MF_ERROR;
		strncat(tables,",",s);
	}
	strncat(tables,"task AS taskp,hasinput AS hasinputp,datacube AS datacubep",OPH_MAX_STRING_SIZE-strlen(tables));

	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," AND ",s);
	}
	snprintf(condition,OPH_MAX_STRING_SIZE,"%s.iddatacube=taskp.idoutputcube AND taskp.idtask=hasinputp.idtask AND hasinputp.iddatacube=datacubep.iddatacube AND datacubep.iddatacube='%d' AND datacubep.idcontainer='%d'",OPH_MF_ARG_DATACUBE,idparent,idcontainer);
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,condition,s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0) return OPH_MF_ERROR;
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_PARENT,value);
	return OPH_MF_OK;
}

int oph_filter_using_subset(char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	UNUSED(tables)

	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_DATACUBE_FILTER,value);

	int s;

	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," AND (",s);
	}
	else snprintf(where_clause,OPH_MAX_STRING_SIZE,"(");

	oph_subset* subset_struct = NULL;
	if (oph_subset_init(&subset_struct))
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		oph_subset_free(subset_struct);
		return OPH_MF_ERROR;
	}
	if (oph_subset_parse(value,strlen(value),subset_struct,0))
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		oph_subset_free(subset_struct);
		return OPH_MF_ERROR;
	}

	char condition[OPH_MAX_STRING_SIZE], temp[OPH_MAX_STRING_SIZE];
	*condition = 0;

	unsigned int i;
	for (i=0; i<subset_struct->number; ++i)
	{
		if (i)
		{
			if ((s=OPH_MAX_STRING_SIZE-strlen(condition)-1)<=0)
			{
				oph_subset_free(subset_struct);
				return OPH_MF_ERROR;
			}
			strncat(condition, " OR ", s);
		}
		snprintf(temp, OPH_MAX_STRING_SIZE, OPH_SUBSET_ISINSUBSET_PLUGIN, OPH_MF_ARG_DATACUBE, "iddatacube", subset_struct->start[i], subset_struct->stride[i], subset_struct->end[i]);
		if ((s=OPH_MAX_STRING_SIZE-strlen(condition)-1)<=0)
		{
			oph_subset_free(subset_struct);
			return OPH_MF_ERROR;
		}
		strncat(condition, temp, s);
	}
	oph_subset_free(subset_struct);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,condition,s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,")",s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_DATACUBE_FILTER,value);
	return OPH_MF_OK;
}

int oph_filter_container(char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	UNUSED(tables)

	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_CONTAINER,value);

	char condition[OPH_MAX_STRING_SIZE];
	int s;

	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," AND ",s);
	}

	snprintf(condition,OPH_MAX_STRING_SIZE,"%s.containername='%s'",OPH_MF_ARG_CONTAINER,value);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,condition,s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_CONTAINER,value);
	return OPH_MF_OK;
}

int oph_filter_container_pid(char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	UNUSED(tables)

	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_CONTAINER_PID,value);

	if (strncasecmp(value,oph_web_server,strlen(oph_web_server)))
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		return OPH_MF_ERROR;
	}
	char *pointer = value+strlen(oph_web_server);
	if (*pointer != OPH_MF_ROOT_FOLDER[0])
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",value);
		return OPH_MF_ERROR;
	}
	pointer++;
	int idcontainer = (int)strtol(pointer,NULL,10);	
	char condition[OPH_MAX_STRING_SIZE];
	int s;
	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," AND ",s);
	}
	snprintf(condition,OPH_MAX_STRING_SIZE,"%s.idcontainer='%d'",OPH_MF_ARG_DATACUBE,idcontainer);
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,condition,s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_CONTAINER_PID,value);
	return OPH_MF_OK;
}

int oph_filter_metadata_key(char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_METADATA_KEY,value);

	char condition[OPH_MAX_STRING_SIZE];

	int key_num;
	char** key_list=NULL;
	if (oph_tp_parse_multiple_value_param (value, &key_list, &key_num)) return OPH_MF_ERROR;
	if (!key_num) return OPH_MF_ERROR;

	int s;
	if (*tables)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			return OPH_MF_ERROR;
		}
		strncat(tables,",",s);
	}
	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			return OPH_MF_ERROR;
		}
		strncat(where_clause," AND ",s);
	}

	int i;
	for (i=0;i<key_num;++i)
	{
		if (i)
		{	if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0)
			{
				oph_tp_free_multiple_value_param_list(key_list, key_num);
				return OPH_MF_ERROR;
			}
			strncat(tables,",",s);
		}
		snprintf(condition,OPH_MAX_STRING_SIZE,"metadatakey AS metadatakey%d,metadatainstance AS metadatainstance%d",i,i);
		if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0) return OPH_MF_ERROR;
		strncat(tables,condition,s);

		if (i)
		{	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
			{
				oph_tp_free_multiple_value_param_list(key_list, key_num);
				return OPH_MF_ERROR;
			}
			strncat(where_clause," AND ",s);
		}
		snprintf(condition,OPH_MAX_STRING_SIZE,"metadatakey%d.idkey=metadatainstance%d.idkey AND metadatainstance%d.iddatacube=%s.iddatacube AND metadatakey%d.label='%s'",i,i,i,OPH_MF_ARG_DATACUBE,i,key_list[i]);
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			return OPH_MF_ERROR;
		}
		strncat(where_clause,condition,s);
	}
	oph_tp_free_multiple_value_param_list(key_list, key_num);

	if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0) return OPH_MF_ERROR;
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_METADATA_KEY,value);
	return OPH_MF_OK;
}

int _oph_filter_metadata_value(char* key, char* value, char* tables, char* where_clause, pthread_mutex_t* flag, unsigned int prefix)
{
	if (!value || !strlen(value)) return OPH_MF_OK;
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_METADATA_KEY,key);
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s'\n",OPH_MF_ARG_METADATA_VALUE,value);

	char condition[OPH_MAX_STRING_SIZE];

	int key_num, value_num;
	char** key_list=NULL;
	char** value_list=NULL;
	if (oph_tp_parse_multiple_value_param (key, &key_list, &key_num)) return OPH_MF_ERROR;
	if (!key_num) return OPH_MF_ERROR;
	if (oph_tp_parse_multiple_value_param (value, &value_list, &value_num))
	{
		oph_tp_free_multiple_value_param_list(key_list, key_num);
		return OPH_MF_ERROR;
	}
	if (!value_num)
	{
		oph_tp_free_multiple_value_param_list(key_list, key_num);
		return OPH_MF_ERROR;
	}
	if (key_num != value_num)
	{
		oph_tp_free_multiple_value_param_list(key_list, key_num);
		oph_tp_free_multiple_value_param_list(value_list, value_num);
		return OPH_MF_ERROR;
	}

	int s;
	if (*tables)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			oph_tp_free_multiple_value_param_list(value_list, value_num);
			return OPH_MF_ERROR;
		}
		strncat(tables,",",s);
	}
	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			oph_tp_free_multiple_value_param_list(value_list, value_num);
			return OPH_MF_ERROR;
		}
		strncat(where_clause," AND ",s);
	}

	int i;
	for (i=0;i<key_num;++i)
	{
		if (i)
		{	if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0)
			{
				oph_tp_free_multiple_value_param_list(key_list, key_num);
				oph_tp_free_multiple_value_param_list(value_list, value_num);
				return OPH_MF_ERROR;
			}
			strncat(tables,",",s);
		}
		snprintf(condition,OPH_MAX_STRING_SIZE,"metadatakey AS metadatakey%dk%d,metadatainstance AS metadatainstance%dk%d",prefix,i,prefix,i);
		if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			oph_tp_free_multiple_value_param_list(value_list, value_num);
			return OPH_MF_ERROR;
		}
		strncat(tables,condition,s);

		if (i)
		{	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
			{
				oph_tp_free_multiple_value_param_list(key_list, key_num);
				oph_tp_free_multiple_value_param_list(value_list, value_num);
				return OPH_MF_ERROR;
			}
			strncat(where_clause," AND ",s);
		}
		snprintf(condition,OPH_MAX_STRING_SIZE,"metadatakey%dk%d.idkey=metadatainstance%dk%d.idkey AND metadatainstance%dk%d.iddatacube=%s.iddatacube AND metadatakey%dk%d.label='%s' AND CONVERT(metadatainstance%dk%d.value USING latin1) LIKE '%%%s%%'",prefix,i,prefix,i,prefix,i,OPH_MF_ARG_DATACUBE,prefix,i,key_list[i],prefix,i,value_list[i]);
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0)
		{
			oph_tp_free_multiple_value_param_list(key_list, key_num);
			oph_tp_free_multiple_value_param_list(value_list, value_num);
			return OPH_MF_ERROR;
		}
		strncat(where_clause,condition,s);
	}
	oph_tp_free_multiple_value_param_list(key_list, key_num);
	oph_tp_free_multiple_value_param_list(value_list, value_num);

	if ((s=OPH_MAX_STRING_SIZE-strlen(tables)-1)<=0) return OPH_MF_ERROR;
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s'\n",OPH_MF_ARG_METADATA_VALUE,value);
	return OPH_MF_OK;
}
int oph_filter_metadata_value(char* key, char* value, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	return _oph_filter_metadata_value(key, value, tables, where_clause, flag, 0);
}

int oph_add_folder(int folder_id, int* counter, char* where_clause, ophidiadb* oDB, int recursive_flag, pthread_mutex_t* flag)
{
	int s;
	char condition[OPH_MAX_STRING_SIZE];
	if (*counter)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," OR ",s);
	}
	snprintf(condition,OPH_MAX_STRING_SIZE,"%s.idfolder='%d'",OPH_MF_ARG_CONTAINER,folder_id);
	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,condition,s);
	(*counter)++;

	if (recursive_flag<0) recursive_flag++;
	if (recursive_flag)
	{
		int *subfolder_id=0, num_subfolders, i;
		if (oph_odb_fs_get_subfolders(folder_id, &subfolder_id, &num_subfolders, oDB)) return OPH_MF_ERROR;
		for (i=0; i<num_subfolders; ++i) if (oph_add_folder(subfolder_id[i], counter, where_clause, oDB, recursive_flag, flag)) break;
		if (subfolder_id) free(subfolder_id);
		if (i<num_subfolders) return OPH_MF_ERROR;
	}

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	return OPH_MF_OK;
}
int oph_filter_path(char* path, char* recursive, char* depth, char* sessionid, ophidiadb* oDB, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	UNUSED(tables)

	if (!path || !strlen(path)) return OPH_MF_OK;

	int permission=0, folder_id=0, s, counter=0, recursive_flag = recursive && !strcmp(recursive,OPH_MF_ARG_VALUE_YES);
	if (recursive_flag && depth)
	{
		int rdepth = (int)strtol(depth,NULL,10);
		if (rdepth>0) recursive_flag = -rdepth;
	}

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Process argument %s='%s' (%s=%s)\n",OPH_MF_ARG_PATH,path,OPH_MF_ARG_RECURSIVE,recursive_flag?OPH_MF_ARG_VALUE_YES:OPH_MF_ARG_VALUE_NO);

	if (oph_odb_fs_path_parsing("", path, &folder_id, NULL, oDB))
	{
		//Check if user can work on datacube
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Path '%s' doesn't exists\n", path);
		return OPH_MF_ERROR;
	}
	if (oph_odb_fs_check_folder_session(folder_id, sessionid, oDB, &permission) || !permission) // Only the permission on specified folder is checked, subfolders will be accessed in case the specified one is accessible
	{
		//Check if user can work on datacube
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Access in folder '%s' is not allowed\n", path);
		return OPH_MF_ERROR;
	}

	if (*where_clause)
	{
		if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
		strncat(where_clause," AND (",s);
	}
	else snprintf(where_clause,OPH_MAX_STRING_SIZE,"(");

	if (oph_add_folder(folder_id, &counter, where_clause, oDB, recursive_flag, flag))
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Folder '%s' cannot be explored\n", path);
		return OPH_MF_ERROR;
	}

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;
	strncat(where_clause,")",s);

	if ((s=OPH_MAX_STRING_SIZE-strlen(where_clause)-1)<=0) return OPH_MF_ERROR;

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Processed argument %s='%s' (%s=%s)\n",OPH_MF_ARG_PATH,path,OPH_MF_ARG_RECURSIVE,recursive_flag?OPH_MF_ARG_VALUE_YES:OPH_MF_ARG_VALUE_NO);
	return OPH_MF_OK;
}

int oph_filter_free_kvp(HASHTBL *task_tbl, char* tables, char* where_clause, pthread_mutex_t* flag)
{
	unsigned int i,j=0;
	struct hashnode_s *node;
	for (i=0; i<task_tbl->size; ++i) for (node=task_tbl->nodes[i]; node; node=node->next)
		if (_oph_filter_metadata_value(node->key, (char*)node->data, tables, where_clause, flag, ++j)) return OPH_MF_ERROR;
	return OPH_MF_OK;
}

int _oph_filter(HASHTBL *task_tbl, char* query, char* cwd, char* sessionid, ophidiadb* oDB, pthread_mutex_t* flag)
{
	if (!query || !sessionid)
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
		return OPH_MF_ERROR;
	}

	char tables[OPH_MAX_STRING_SIZE], where_clause[OPH_MAX_STRING_SIZE];

	char* container = task_tbl ? hashtbl_get(task_tbl, OPH_MF_ARG_CONTAINER) : NULL;
	char* path = task_tbl ? hashtbl_get(task_tbl, OPH_MF_ARG_PATH) : cwd;
	if (!path || !strlen(path)) path = OPH_MF_ROOT_FOLDER;

	// Basic tables and where_clause
	snprintf(tables,OPH_MAX_STRING_SIZE,"%s,%s",OPH_MF_ARG_DATACUBE,OPH_MF_ARG_CONTAINER);
	snprintf(where_clause,OPH_MAX_STRING_SIZE,"%s.idcontainer=%s.idcontainer",OPH_MF_ARG_DATACUBE,OPH_MF_ARG_CONTAINER);

	// Filter on current session
	char ext_path[OPH_MAX_STRING_SIZE];
	*ext_path = OPH_ODB_FS_ROOT[0];
	if (oph_get_session_code(sessionid, ext_path+1))
	{
		pmesg_safe(flag, LOG_ERROR, __FILE__,__LINE__, "Unable to get session code\n");
		return OPH_SERVER_SYSTEM_ERROR;
	}
	
	// Extend path or cwd
	if (path) strncat(ext_path,path,OPH_MAX_STRING_SIZE-strlen(ext_path));
	pmesg_safe(flag, LOG_DEBUG, __FILE__,__LINE__, "Extended path to be explored is '%s'\n",ext_path);

	if (task_tbl)
	{
		char *value = NULL, *value2 = NULL;

		// Filters
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Parse filters\n");

		if (oph_filter_level(value=hashtbl_get(task_tbl, OPH_MF_ARG_LEVEL),tables,where_clause,flag)) return OPH_MF_ERROR;
		if (oph_filter_measure(value=hashtbl_get(task_tbl, OPH_MF_ARG_MEASURE),tables,where_clause,flag)) return OPH_MF_ERROR;
		if (oph_filter_parent(value=hashtbl_get(task_tbl, OPH_MF_ARG_PARENT),tables,where_clause,flag)) return OPH_MF_ERROR;
		if (oph_filter_using_subset(value=hashtbl_get(task_tbl, OPH_MF_ARG_DATACUBE_FILTER),tables,where_clause,flag)) return OPH_MF_ERROR;
		if (container && strlen(container))
		{
			if (oph_filter_container(container,tables,where_clause,flag)) return OPH_MF_ERROR;
		}
		else
		{
			if (oph_filter_container_pid(value=hashtbl_get(task_tbl, OPH_MF_ARG_CONTAINER_PID),tables,where_clause,flag)) return OPH_MF_ERROR;
		}
		char* metadata_key = hashtbl_get(task_tbl, OPH_MF_ARG_METADATA_KEY);
		if (metadata_key && strlen(metadata_key))
		{
			char* metadata_value = hashtbl_get(task_tbl, OPH_MF_ARG_METADATA_VALUE);
			if (metadata_value && strlen(metadata_value))
			{
				if (oph_filter_metadata_value(metadata_key, metadata_value,tables,where_clause,flag))
				{
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong arguments '%s' and '%s'\n",OPH_MF_ARG_METADATA_KEY,OPH_MF_ARG_METADATA_VALUE);
					return OPH_MF_ERROR;
				}
			}
			else if (oph_filter_metadata_key(metadata_key,tables,where_clause,flag))
			{
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",OPH_MF_ARG_METADATA_KEY);
				return OPH_MF_ERROR;
			}
		}
		else
		{
			char* metadata_value = hashtbl_get(task_tbl, OPH_MF_ARG_METADATA_VALUE);
			if (metadata_value && strlen(metadata_value))
			{
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Wrong argument '%s'\n",OPH_MF_ARG_METADATA_VALUE);
				return OPH_MF_ERROR;
			}
		}
		if (oph_filter_path(ext_path,value=hashtbl_get(task_tbl, OPH_MF_ARG_RECURSIVE),value2=hashtbl_get(task_tbl, OPH_MF_ARG_DEPTH),sessionid,oDB,tables,where_clause,flag)) return OPH_MF_ERROR; // path or cwd
		if ((value=hashtbl_get(task_tbl, OPH_MF_ARG_FILE))) pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Argument '%s' will be skipped\n",OPH_MF_ARG_FILE);
		if ((value=hashtbl_get(task_tbl, OPH_MF_ARG_CONVENTION))) pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, "Argument '%s' will be skipped\n",OPH_MF_ARG_CONVENTION);
	}
	else if (oph_filter_path(ext_path,OPH_MF_ARG_VALUE_NO,NULL,sessionid,oDB,tables,where_clause,flag)) return OPH_MF_ERROR;

	if (*where_clause) snprintf(query,OPH_MAX_STRING_SIZE,OPH_MF_QUERY,tables,where_clause);
	else snprintf(query,OPH_MAX_STRING_SIZE,OPH_MF_QUERY_DUMMY,tables);

	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Query for massive operation: %s;\n",query);
	return OPH_MF_OK;
}

int oph_filter(HASHTBL *task_tbl, char* query, char* cwd, char* sessionid, ophidiadb* oDB)
{
	return _oph_filter(task_tbl, query, cwd, sessionid, oDB, &global_flag);
}

int oph_filter_unsafe(HASHTBL *task_tbl, char* query, char* cwd, char* sessionid, ophidiadb* oDB)
{
	return _oph_filter(task_tbl, query, cwd, sessionid, oDB, NULL);
}

