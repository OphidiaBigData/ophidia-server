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

#ifndef __OPH_WORKFLOW_DEFINE_H
#define __OPH_WORKFLOW_DEFINE_H

#define OPH_WORKFLOW_MAX_STRING		2048
#define OPH_WORKFLOW_MIN_STRING		24

#define OPH_WORKFLOW_TYPE_EMBEDDED	"embedded"
#define OPH_WORKFLOW_TYPE_SINGLE	"single"
#define OPH_WORKFLOW_TYPE_ALL		"all"

#define OPH_WORKFLOW_KV_SEPARATOR	";"
#define OPH_WORKFLOW_KV_SEPARATOR2	"="
#define OPH_WORKFLOW_KV_BRACKET		"[]"
#define OPH_WORKFLOW_OP_SEPARATOR	"|"
#define OPH_WORKFLOW_BRACKET_BEGIN	"("
#define OPH_WORKFLOW_BRACKET_END	")"
#define OPH_WORKFLOW_PREFIX		"@&"
#define OPH_WORKFLOW_BRACKET		"{}"
#define OPH_WORKFLOW_SEPARATORS		OPH_WORKFLOW_KV_SEPARATOR"="OPH_WORKFLOW_OP_SEPARATOR",:"OPH_WORKFLOW_PREFIX""OPH_WORKFLOW_BRACKET
#define OPH_WORKFLOW_VALUE_SEPARATOR	OPH_WORKFLOW_SEPARATORS[1]
#define OPH_WORKFLOW_VARIABLE_PREFIX	OPH_WORKFLOW_PREFIX[0]
#define OPH_WORKFLOW_INDEX_PREFIX	OPH_WORKFLOW_PREFIX[1]
#define OPH_WORKFLOW_NAME_EXPANSION1	"%s (%d)"
#define OPH_WORKFLOW_NAME_EXPANSION2	"%s,%d)"
#define OPH_WORKFLOW_NAME_EXPANSION_END	OPH_WORKFLOW_BRACKET_END[0]
#define OPH_WORKFLOW_OBJECT			"."
#define OPH_WORKFLOW_GENERIC_VALUE	"*"
#define OPH_WORKFLOW_END_VALUE		"end"

#define OPH_WORKFLOW_FIXED_VALUE	""
#define OPH_WORKFLOW_EXT_SUB_STRING	"operator=%s;sessionid=%s;workflowid=%d;markerid=%d;username="OPH_WORKFLOW_FIXED_VALUE"%s"OPH_WORKFLOW_FIXED_VALUE";userid="OPH_WORKFLOW_FIXED_VALUE"%d"OPH_WORKFLOW_FIXED_VALUE";userrole=%d;parentid=%d;taskindex=%d;lighttaskindex=%d;exec_mode=%s;"
#define OPH_WORKFLOW_KEY_VALUE_STRING	"%s=%s;"
#define OPH_WORKFLOW_KEY_VALUE_STRING2	"%s="OPH_WORKFLOW_FIXED_VALUE"%s"OPH_WORKFLOW_FIXED_VALUE";"
#define OPH_WORKFLOW_KEY_VALUE_STRING3	"%s=%d;"
#define OPH_WORKFLOW_KEY_HOST_PARTITION	"host_partition"
#define OPH_WORKFLOW_KEY_NHOSTS			"nhost"

#define OPH_WORKFLOW_BASE_NOTIFICATION	"parentid=%d;taskindex=%d;lighttaskindex=%d;jobid=%d;status=%d;sessionid=%s;markerid=%d;save=%s;"

#define OPH_WORKFLOW_ROOT_FOLDER	"/"
#define OPH_WORKFLOW_PATH_SET		{"cwd","path"}
#define OPH_WORKFLOW_PATH_SET_SIZE	2

#define OPH_WORKFLOW_YES		"yes"
#define OPH_WORKFLOW_NO			"no"
#define OPH_WORKFLOW_NOP		"nop"
#define OPH_WORKFLOW_SKIP		"skip"
#define OPH_WORKFLOW_CONTINUE	"continue"
#define OPH_WORKFLOW_BREAK		"break"
#define OPH_WORKFLOW_REPEAT		"repeat"

#define OPH_WORKFLOW_DELETE				"oph_delete"
#define OPH_WORKFLOW_DELETECONTAINER	"oph_deletecontainer"

#define OPH_WORKFLOW_DELETECONTAINER_FORCE	"force"

#define OPH_WORKFLOW_EXIT_ACTION_NOP				0
#define OPH_WORKFLOW_EXIT_ACTION_DELETE				1
#define OPH_WORKFLOW_EXIT_ACTION_DELETECONTAINER	2

#define OPH_WORKFLOW_CLASSIC		"classic"
#define OPH_WORKFLOW_COMPACT		"compact"

#define OPH_WORKFLOW_FINAL_TASK		"Final task"

#define OPH_WORKFLOW_BVAR_KEYS		{"OPH_SESSION_ID","OPH_SESSION_CODE","OPH_WORKFLOW_ID","OPH_SERVER_HOST","OPH_SERVER_PORT","OPH_USER","OPH_PASSWD","OPH_OS_USER"}
#define OPH_WORKFLOW_BVAR_KEYS_SIZE	8
#define OPH_WORKFLOW_BVAR_KEY_MARKERID	"OPH_MARKER_ID"
#define OPH_WORKFLOW_BVAR_KEY_NCORES	"NCORES"
#define OPH_WORKFLOW_BVAR_KEY_NHOSTS	"NHOST"

#define OPH_WORKFLOW_BVAR_HIDDEN_KEY	"OPH_PASSWD"
#define OPH_WORKFLOW_BVAR_HIDDEN_VALUE	"***"

// Additional known operators
#define OPH_OPERATOR_SET		"oph_set"
#define OPH_OPERATOR_FOR		"oph_for"
#define OPH_OPERATOR_ENDFOR		"oph_endfor"
#define OPH_OPERATOR_IF			"oph_if"
#define OPH_OPERATOR_ELSEIF		"oph_elseif"
#define OPH_OPERATOR_ELSE		"oph_else"
#define OPH_OPERATOR_ENDIF		"oph_endif"
#define OPH_OPERATOR_WAIT		"oph_wait"
#define OPH_OPERATOR_INPUT		"oph_input"

#define OPH_ARG_COMMAND			"command"
#define OPH_TYPE_OPHIDIA		"ophidia"
#define OPH_TYPE_CDO			"cdo"
#define OPH_TYPE_GENERIC		"generic"
#define OPH_TYPE_CONTROL		"control"

#endif				//__OPH_WORKFLOW_DEFINE_H
