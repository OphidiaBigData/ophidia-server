/*
    Ophidia Server
    Copyright (C) 2012-2024 CMCC Foundation

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

#ifndef __OPH_JSON_OBJKEYS_H__
#define __OPH_JSON_OBJKEYS_H__

/***********OPH_JSON OBJKEYS***********/
#ifdef BENCHMARK
#define OPH_JSON_OBJKEY_EXEC_TIME 					"exec_time"
#endif

// ALL OPERATORS
#define OPH_JSON_OBJKEY_STATUS 						"status"
#define OPH_JSON_OBJKEY_SUMMARY						"summary"

// OPH_LOGGINGBK
#define OPH_JSON_OBJKEY_LOGGINGBK					"loggingbk"

// OPH_LIST
#define OPH_JSON_OBJKEY_LIST 						"list"

// OPH_CUBEIO
#define OPH_JSON_OBJKEY_CUBEIO 						"cubeio"
#define OPH_JSON_OBJKEY_CUBEIO_GRAPH 				"cubeio_graph"

// OPH_CUBESIZE
#define OPH_JSON_OBJKEY_CUBESIZE	 				"cubesize"

// OPH_CUBEELEMENTS
#define OPH_JSON_OBJKEY_CUBEELEMENTS 				"cubeelements"

// OPH_CUBESCHEMA
#define OPH_JSON_OBJKEY_CUBESCHEMA_CUBEINFO 		"cubeschema_cubeinfo"
#define OPH_JSON_OBJKEY_CUBESCHEMA_MORECUBEINFO		"cubeschema_morecubeinfo"
#define OPH_JSON_OBJKEY_CUBESCHEMA_DIMINFO 			"cubeschema_diminfo"
#define OPH_JSON_OBJKEY_CUBESCHEMA_DIMVALUES		"cubeschema_dimvalues"

// OPH_HIERARCHY
#define OPH_JSON_OBJKEY_HIERARCHY_LIST 				"hierarchy_list"
#define OPH_JSON_OBJKEY_HIERARCHY_TIP 				"hierarchy_tip"
#define OPH_JSON_OBJKEY_HIERARCHY_ATTRS 			"hierarchy_attrs"
#define OPH_JSON_OBJKEY_HIERARCHY_FUNCTION 			"hierarchy_function"

// OPH_INSPECTFRAG
#define OPH_JSON_OBJKEY_INSPECTFRAG_DATA 			"inspectfrag_data"
#define OPH_JSON_OBJKEY_INSPECTFRAG_SUMMARY 		"inspectfrag_summary"

// OPH_MAN
#define OPH_JSON_OBJKEY_MAN_INFO 					"man_info"
#define OPH_JSON_OBJKEY_MAN_ARGS 					"man_args"
#define OPH_JSON_OBJKEY_MAN_MULTIARGS 				"man_multiargs"
#define OPH_JSON_OBJKEY_MAN_FUNCTION 				"man_function"

// OPH_OPERATORS_LIST
#define OPH_JSON_OBJKEY_OPERATORS_LIST_LIST			"operators_list_list"
#define OPH_JSON_OBJKEY_OPERATORS_LIST_TIP			"operators_list_tip"

// OPH_PRIMITIVES_LIST
#define OPH_JSON_OBJKEY_PRIMITIVES_LIST_LIST		"primitives_list_list"
#define OPH_JSON_OBJKEY_PRIMITIVES_LIST_TIP			"primitives_list_tip"

// OPH_DUPLICATE
#define OPH_JSON_OBJKEY_DUPLICATE 					"duplicate"

// OPH_EXPLORECUBE
#define OPH_JSON_OBJKEY_EXPLORECUBE_DATA 			"explorecube_data"
#define OPH_JSON_OBJKEY_EXPLORECUBE_SUMMARY 		"explorecube_summary"
#define OPH_JSON_OBJKEY_EXPLORECUBE_DIMVALUES		"explorecube_dimvalues"

#define OPH_JSON_OBJKEY_EXPLORENC_DATA 				"explorenc_data"
#define OPH_JSON_OBJKEY_EXPLORENC_SUMMARY 			"explorenc_summary"
#define OPH_JSON_OBJKEY_EXPLORENC_DIMVALUES			"explorenc_dimvalues"
#define OPH_JSON_OBJKEY_EXPLORENC_WAVELET_DATA		"explorenc_wavelet_data"
#define OPH_JSON_OBJKEY_EXPLORENC_WAVELET_COEFF		"explorenc_wavelet_coeff"
#define OPH_JSON_OBJKEY_EXPLORENC_STATS				"explorenc_stats"
#define OPH_JSON_OBJKEY_EXPLORENC_FIT				"explorenc_fit"

#define OPH_JSON_OBJKEY_PERMUTE						"permute"
#define OPH_JSON_OBJKEY_SUBSET						"subset"
#define OPH_JSON_OBJKEY_SUBSET2						"subset2"
#define OPH_JSON_OBJKEY_REDUCE						"reduce"
#define OPH_JSON_OBJKEY_REDUCE2						"reduce2"
#define OPH_JSON_OBJKEY_AGGREGATE					"aggregate"
#define OPH_JSON_OBJKEY_AGGREGATE2					"aggregate2"
#define OPH_JSON_OBJKEY_DRILLDOWN					"drilldown"
#define OPH_JSON_OBJKEY_ROLLUP						"rollup"
#define OPH_JSON_OBJKEY_DUPLICATE					"duplicate"
#define OPH_JSON_OBJKEY_APPLY						"apply"
#define OPH_JSON_OBJKEY_RANDCUBE					"randcube"
#define OPH_JSON_OBJKEY_DELETE						"delete"
#define OPH_JSON_OBJKEY_UNPUBLISH					"unpublish"
#define OPH_JSON_OBJKEY_DELETECONTAINER				"deletecontainer"
#define OPH_JSON_OBJKEY_SPLIT						"split"
#define OPH_JSON_OBJKEY_MERGE						"merge"
#define OPH_JSON_OBJKEY_INSTANCES					"instances"
#define OPH_JSON_OBJKEY_TASKS						"tasks"
#define OPH_JSON_OBJKEY_FIND_LIST					"find_list"
#define OPH_JSON_OBJKEY_FIND_SUMMARY				"find_summary"
#define OPH_JSON_OBJKEY_IMPORTNC					"importnc"
#define OPH_JSON_OBJKEY_IMPORTCSV					"importcsv"
#define OPH_JSON_OBJKEY_EXPORTNC					"exportnc"
#define OPH_JSON_OBJKEY_EXPORTNC2					"exportnc2"
#define OPH_JSON_OBJKEY_EXPORTCSV					"exportcsv"
#define OPH_JSON_OBJKEY_EXPLORENC					"explorenc"
#define OPH_JSON_OBJKEY_LOG_INFO					"log_info"
#define OPH_JSON_OBJKEY_PUBLISH						"publish"
#define OPH_JSON_OBJKEY_CREATECONTAINER				"createcontainer"
#define OPH_JSON_OBJKEY_SYSTEM						"system"
#define OPH_JSON_OBJKEY_FOLDER						"folder"
#define OPH_JSON_OBJKEY_SEARCH						"search"
#define OPH_JSON_OBJKEY_RESTORECONTAINER			"restorecontainer"
#define OPH_JSON_OBJKEY_MOVECONTAINER				"movecontainer"
#define OPH_JSON_OBJKEY_SHOWGRID_LIST				"showgrid_list"
#define OPH_JSON_OBJKEY_SHOWGRID_DIMINFO			"showgrid_diminfo"
#define OPH_JSON_OBJKEY_SHOWGRID_DIMVALUES			"showgrid_dimvalues"
#define OPH_JSON_OBJKEY_SHOWGRID_TIP				"showgrid_tip"
#define OPH_JSON_OBJKEY_METADATA_LIST				"metadata_list"
#define OPH_JSON_OBJKEY_METADATA_SUMMARY			"metadata_summary"
#define OPH_JSON_OBJKEY_CONCATNC					"concatnc"
#define OPH_JSON_OBJKEY_INTERCUBE					"intercube"
#define OPH_JSON_OBJKEY_MERGECUBES					"mergecubes"
#define OPH_JSON_OBJKEY_SCRIPT						"script"

// OPH_MASSIVE
#define OPH_JSON_OBJKEY_MASSIVE_LIST				"massive_list"
#define OPH_JSON_OBJKEY_MASSIVE_SUMMARY				"massive_summary"
#define OPH_JSON_OBJKEY_MASSIVE_STATUS				"massive_status"
#define OPH_JSON_OBJKEY_MASSIVE_INFO				"massive_info"

// OPH_WORKFLOW
#define OPH_JSON_OBJKEY_WORKFLOW_LIST				"workflow_list"
#define OPH_JSON_OBJKEY_WORKFLOW_SUMMARY			"workflow_summary"
#define OPH_JSON_OBJKEY_WORKFLOW_STATUS				"workflow_status"
#define OPH_JSON_OBJKEY_WORKFLOW_PROGRESS			"workflow_progress"
#define OPH_JSON_OBJKEY_WORKFLOW_INFO				"workflow_info"

// OPH_RESUME
#define OPH_JSON_OBJKEY_RESUME						"resume"
#define OPH_JSON_OBJKEY_RESUME_STATUS				"resume_status"

// OPH_GET_CONFIG
#define OPH_JSON_OBJKEY_GET_CONFIG					"get_config"

// OPH_SERVICE
#define OPH_JSON_OBJKEY_SERVICE_STATUS				"service_status"
#define OPH_JSON_OBJKEY_SERVICE_TASKS				"service_tasks"

// OPH_MANAGE_SESSION
#define OPH_JSON_OBJKEY_MANAGE_SESSION_LIST			"manage_session_list"
#define OPH_JSON_OBJKEY_MANAGE_SESSION_SUMMARY		"manage_session_summary"

// OPH_CLUSTER
#define OPH_JSON_OBJKEY_CLUSTER_SUMMARY				"cluster_summary"
#define OPH_JSON_OBJKEY_CLUSTER_LIST				"cluster_list"
#define OPH_JSON_OBJKEY_CLUSTER_LIST_SUMMARY		"cluster_list_summary"
#define OPH_JSON_OBJKEY_CLUSTER_USER				"cluster_user"
#define OPH_JSON_OBJKEY_CLUSTER_USER_SUMMARY		"cluster_user_summary"

#endif
