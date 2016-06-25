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

#ifndef OPH_PARSER_H
#define OPH_PARSER_H

#include "oph_gather.h"

// Keywords
#define OPH_ARG_SESSIONID "sessionid"
#define OPH_ARG_MARKERID "markerid"
#define OPH_ARG_WORKFLOWID "workflowid"
#define OPH_ARG_NCORES "ncores"
#define OPH_ARG_NHOSTS "nhosts"
#define OPH_ARG_MODE "exec_mode"
#define OPH_ARG_OPERATOR "operator"
#define OPH_ARG_USER "user"
#define OPH_ARG_USERNAME "username"
#define OPH_ARG_USERROLE "userrole"
#define OPH_ARG_CUBE "cube"
#define OPH_ARG_CWD "cwd"
#define OPH_ARG_SRC_PATH "src_path"
#define OPH_ARG_MEASURE "measure"
#define OPH_ARG_KEY "key"
#define OPH_ARG_VALUE "value"
#define OPH_ARG_CALLBACK_URL "callback_url"
#define OPH_ARG_OBJKEY "objkey_filter"
#define OPH_ARG_PARENTID "parentid"
#define OPH_ARG_JOBID "jobid"
#define OPH_ARG_TASKINDEX "taskindex"
#define OPH_ARG_LIGHTTASKINDEX "lighttaskindex"
#define OPH_ARG_STATUS "status"
#define OPH_ARG_SESSION "session"
#define OPH_ARG_MARKER "marker"
#define OPH_ARG_SAVE "save"
#define OPH_ARG_ACTION "action"
#define OPH_ARG_ID "id"
#define OPH_ARG_IDTYPE "id_type"
#define OPH_ARG_DOCUMENTTYPE "document_type"
#define OPH_ARG_LEVEL "level"
#define OPH_ARG_LINK "link"
#define OPH_ARG_OBJKEY_FILTER "objkey_filter"

#define OPH_ARG_MODE_SYNC "sync"
#define OPH_ARG_MODE_ASYNC "async"
#define OPH_ARG_MODE_DEFAULT OPH_ARG_MODE_ASYNC
#define OPH_MODE_DEFAULT OPH_MODE_ASYNC

#define OPH_ARG_LOG_TYPE "LOG_TYPE"

#define OPH_SEPARATOR_BASIC ":"
#define OPH_SEPARATOR_NULL ' '
#define OPH_SEPARATOR_KV "="
#define OPH_SEPARATOR_PARAM ";"
#define OPH_SEPARATOR_SUBPARAM_OPEN '['
#define OPH_SEPARATOR_SUBPARAM_CLOSE ']'
#define OPH_SEPARATOR_SUBPARAM_STR "|"
#define OPH_SEPARATOR_SUBPARAM OPH_SEPARATOR_SUBPARAM_STR[0]
#define OPH_SEPARATOR_QUERY '\n'
#define OPH_SEPARATOR_USER ","
#define OPH_SEPARATOR_ROLE OPH_SEPARATOR_BASIC[0]
#define OPH_SEPARATOR_ROLES "|"
#define OPH_SEPARATOR_FOLDER "/"
#define OPH_COMMENT_MARK '#'
#define OPH_SUBSTITUTION_MARK '$'

// Known operators
#define OPH_OPERATOR_LOG_INFO "oph_log_info"
#define OPH_OPERATOR_SCRIPT "oph_script"
#define OPH_OPERATOR_GET_CONFIG "oph_get_config"
#define OPH_OPERATOR_RESUME "oph_resume"
#define OPH_OPERATOR_SERVICE "oph_service"
#define OPH_OPERATOR_MANAGE_SESSION "oph_manage_session"
#define OPH_OPERATOR_CANCEL "oph_cancel"

// Known parameters
#define OPH_OPERATOR_PARAMETER_NAME "name"
#define OPH_OPERATOR_PARAMETER_VALUE "value"
#define OPH_OPERATOR_PARAMETER_VALUES "values"
#define OPH_OPERATOR_PARAMETER_LOG_TYPE "log_type"
#define OPH_OPERATOR_PARAMETER_LINES_NUMBER "nlines"
#define OPH_OPERATOR_PARAMETER_COUNTER "counter"
#define OPH_OPERATOR_PARAMETER_PARALLEL "parallel"
#define OPH_OPERATOR_PARAMETER_CONDITION "condition"

// Known values
#define OPH_COMMON_NULL "-"
#define OPH_COMMON_YES "yes"
#define OPH_COMMON_NO "no"
#define OPH_COMMON_PARAMETER_WORKING_SESSION "this"
#define OPH_OPERATOR_LOG_INFO_PARAMETER_SERVER "server"
#define OPH_OPERATOR_GET_CONFIG_PARAMETER_ALL "all"
#define OPH_OPERATOR_RESUME_PARAMETER_WORKFLOW "workflow"
#define OPH_OPERATOR_RESUME_PARAMETER_MARKER "marker"
#define OPH_OPERATOR_RESUME_PARAMETER_REQUEST "request"
#define OPH_OPERATOR_RESUME_PARAMETER_RESPONSE "response"
#define OPH_OPERATOR_SERVICE_PARAMETER_STATUS_UP "up"
#define OPH_OPERATOR_SERVICE_PARAMETER_STATUS_DOWN "down"

// Session management
#define OPH_ARG_ACTION_VALUE_DISABLE "disable"
#define OPH_ARG_ACTION_VALUE_ENABLE "enable"
#define OPH_ARG_ACTION_VALUE_ENV "env"
#define OPH_ARG_ACTION_VALUE_GRANT "grant"
#define OPH_ARG_ACTION_VALUE_LIST "list"
#define OPH_ARG_ACTION_VALUE_LISTUSERS "listusers"
#define OPH_ARG_ACTION_VALUE_NEW "new"
#define OPH_ARG_ACTION_VALUE_REMOVE "remove"
#define OPH_ARG_ACTION_VALUE_REVOKE "revoke"
#define OPH_ARG_ACTION_VALUE_SETENV "setenv"

#define OPH_ARG_KEY_VALUE_USER "user"
#define OPH_ARG_KEY_VALUE_ACTIVE "active"
#define OPH_ARG_KEY_VALUE_AUTOREMOVE "autoremove"
#define OPH_ARG_KEY_VALUE_LABEL "label"

typedef enum { OPH_MODE_UNKNOWN, OPH_MODE_ASYNC, OPH_MODE_SYNC } oph_mode_type;
typedef enum { OPH_NO_OPERATOR, OPH_LOG_INFO_OPERATOR, OPH_GET_CONFIG_OPERATOR, OPH_RESUME_OPERATOR, OPH_SERVICE_OPERATOR, OPH_MANAGE_SESSION_OPERATOR, OPH_CANCEL_OPERATOR } oph_known_operators;

typedef struct _oph_argument
{
	char* key;
	char* value;
	struct _oph_argument* next;
} oph_argument;

typedef struct _oph_arguments
{
	int id;
	oph_argument* item;
	struct _oph_arguments* next;
} oph_arguments;

int oph_init_args(oph_argument** args);
int oph_cleanup_args(oph_argument** args);

int oph_parse_program(oph_argument** args, unsigned int* counter, const char* program);
int oph_parse_query(oph_argument** args, unsigned int* counter, const char* query);
int oph_get_arg(oph_argument* args, const char* key, char* value);
int oph_set_arg(oph_argument** args, const char* key, const char* value);
int oph_arg_to_string(oph_argument* args, char* string, int add_datacube_input);

int oph_init_args_list(oph_arguments** list);
int oph_append_args_list(oph_arguments** list, oph_argument* item, int id);
int oph_order_args_list(oph_arguments** list);
int oph_cleanup_args_list(oph_arguments** list);

#endif /* OPH_PARSER_H */

