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

#ifndef __OPH_TASK_PARSER_H
#define __OPH_TASK_PARSER_H

#include "oph_gather.h"

#define OPH_TP_TASK_PARSER_SUCCESS 0
#define OPH_TP_TASK_PARSER_ERROR 1
#define OPH_TP_TASK_SYSTEM_ERROR 2

#define OPH_TP_TASKLEN OPH_MAX_STRING_SIZE
#define	OPH_TP_BUFLEN OPH_MAX_STRING_SIZE

#include "hashtbl.h"

#define OPH_TP_XML_PATH_LENGTH OPH_MAX_STRING_SIZE

#define OPH_TP_XML_FILE_EXTENSION "xml"

#define OPH_TP_XML_PRIMITIVE_TYPE "primitive"
#define OPH_TP_XML_OPERATOR_TYPE "operator"
#define OPH_TP_XML_HIERARCHY_TYPE "hierarchy"
#define OPH_TP_XML_PRIMITIVE_TYPE_CODE 1
#define OPH_TP_XML_OPERATOR_TYPE_CODE 2
#define OPH_TP_XML_HIERARCHY_TYPE_CODE 3

#define OPH_TP_XML_ARGS "args"
#define OPH_TP_XML_ARGUMENT "argument"
#define OPH_TP_XML_INFO "info"
#define OPH_TP_XML_PERMISSION "permission"

#define OPH_TP_XML_ATTRIBUTE_TYPE "type"
#define OPH_TP_XML_ATTRIBUTE_MANDATORY "mandatory"
#define OPH_TP_XML_ATTRIBUTE_DEFAULT "default"
#define OPH_TP_XML_ATTRIBUTE_MINVALUE "minvalue"
#define OPH_TP_XML_ATTRIBUTE_MAXVALUE "maxvalue"
#define OPH_TP_XML_ATTRIBUTE_VALUES "values"
#define OPH_TP_XML_ATTRIBUTE_ALLOWNOT "allownot"

#define OPH_TP_INT_TYPE "int"
#define OPH_TP_REAL_TYPE "double"

//Retrieve the correct xml file version for operators or primitives
int oph_tp_retrieve_function_xml_file(const char *function_name, const char *function_version, char (*xml_filename)[OPH_TP_BUFLEN], const char *folder);

//Look for value of param in task string
int oph_tp_find_param_in_task_string(const char *task_string, const char *param, char *value);

//Load the operator parameters from task_string and XML into the hash table
int oph_tp_task_params_parser(const char *operator_name, const char *task_string, HASHTBL ** hashtbl);

//Split multiple values params into a value_list of size value_num
int oph_tp_parse_multiple_value_param(char *values, char ***value_list, int *value_num);

//Free the value_list of size value_num
int oph_tp_free_multiple_value_param_list(char **value_list, int value_num);

// Check the value of a key
int oph_tp_task_param_checker(const char *operator, const char *task_string, char *key, char *value);

// Check the value of a key changed in order to extract the permission
int oph_tp_task_param_checker_and_role(const char *operator, const char *task_string, char *key, char *value, char *op_role);

//Start xml parsing
int oph_tp_start_xml_parser();

//End xml parsing
int oph_tp_end_xml_parser();

#endif				//__OPH_TASK_PARSER_H
