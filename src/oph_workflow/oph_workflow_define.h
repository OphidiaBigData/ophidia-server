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

#ifndef __OPH_WORKFLOW_DEFINE_H
#define __OPH_WORKFLOW_DEFINE_H

#define OPH_WORKFLOW_MAX_STRING		2048
#define OPH_WORKFLOW_MIN_STRING		24

#define OPH_WORKFLOW_TYPE_EMBEDDED	"embedded"
#define OPH_WORKFLOW_TYPE_SINGLE	"single"
#define OPH_WORKFLOW_TYPE_ALL		"all"

#define OPH_WORKFLOW_BRACKET_BEGIN	"("
#define OPH_WORKFLOW_BRACKET_END	")"
#define OPH_WORKFLOW_PREFIX		"@&"
#define OPH_WORKFLOW_BRACKET		"{}"
#define OPH_WORKFLOW_SEPARATORS		";=|,:"OPH_WORKFLOW_PREFIX""OPH_WORKFLOW_BRACKET
#define OPH_WORKFLOW_VALUE_SEPARATOR	OPH_WORKFLOW_SEPARATORS[1]
#define OPH_WORKFLOW_VARIABLE_PREFIX	OPH_WORKFLOW_PREFIX[0]
#define OPH_WORKFLOW_INDEX_PREFIX	OPH_WORKFLOW_PREFIX[1]
#define OPH_WORKFLOW_NAME_EXPANSION1	"%s (%d)"
#define OPH_WORKFLOW_NAME_EXPANSION2	"%s,%d)"
#define OPH_WORKFLOW_NAME_EXPANSION_END	OPH_WORKFLOW_BRACKET_END[0]
#define OPH_WORKFLOW_OBJECT		"."
#define OPH_WORKFLOW_GENERIC_VALUE	"*"

#define OPH_WORKFLOW_FIXED_VALUE	""
#define OPH_WORKFLOW_EXT_SUB_STRING	"operator=%s;sessionid=%s;workflowid=%d;markerid=%d;username="OPH_WORKFLOW_FIXED_VALUE"%s"OPH_WORKFLOW_FIXED_VALUE";userrole=%d;parentid=%d;taskindex=%d;lighttaskindex=%d;"
#define OPH_WORKFLOW_KEY_VALUE_STRING	"%s=%s;"
#define OPH_WORKFLOW_KEY_VALUE_STRING2	"%s="OPH_WORKFLOW_FIXED_VALUE"%s"OPH_WORKFLOW_FIXED_VALUE";"

#define OPH_WORKFLOW_BASE_NOTIFICATION	"parentid=%d;taskindex=%d;lighttaskindex=%d;jobid=%d;status=%d;"

#define OPH_WORKFLOW_ROOT_FOLDER	"/"
#define OPH_WORKFLOW_PATH_SET		{"cwd","path"}
#define OPH_WORKFLOW_PATH_SET_SIZE	2

#define OPH_WORKFLOW_YES		"yes"
#define OPH_WORKFLOW_NO			"no"
#define OPH_WORKFLOW_NOP		"nop"
#define OPH_WORKFLOW_SKIP		"skip"
#define OPH_WORKFLOW_CONTINUE		"continue"
#define OPH_WORKFLOW_BREAK		"break"
#define OPH_WORKFLOW_REPEAT		"repeat"
#define OPH_WORKFLOW_DELETE		"oph_delete"

#define OPH_WORKFLOW_FINAL_TASK		"Final task"

#define OPH_OPERATOR_SET		"oph_set"
#define OPH_OPERATOR_FOR		"oph_for"
#define OPH_OPERATOR_ENDFOR		"oph_endfor"

#endif //__OPH_WORKFLOW_DEFINE_H
