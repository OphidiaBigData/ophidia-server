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

#define _GNU_SOURCE

#include "oph_task_parser_library.h"
#include "oph_gather.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libxml/parser.h>
#include <libxml/valid.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

#define OPH_TP_PARAM_VALUE_SEPARATOR '='
#define OPH_TP_PARAM_PARAM_SEPARATOR ';'
#define OPH_TP_MULTI_VALUE_SEPARATOR '|'
#define OPH_TP_CONT_CUBE_SEPARATOR '.'
#define OPH_TP_SKIP_SEPARATOR '\0'

extern char *oph_server_location;
extern char *oph_xml_operator_dir;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_tp_retrieve_function_xml_file(const char *function_name, const char *function_version, char (*xml_filename)[OPH_TP_BUFLEN], const char *folder)
{
	DIR *dir;
	struct dirent *ent, save_ent;
	int found = 0;
	char full_filename[OPH_TP_BUFLEN];
	struct stat file_stat;

	if ((dir = opendir(folder)) != NULL) {
		if (function_version == NULL) {
			char format[OPH_TP_BUFLEN];
			char buffer[OPH_TP_BUFLEN];
			unsigned int maxlen = 0;
			int maxversionlen = 0;
			int versionlen = 0;
			int count = 0;
			char *ptr1, *ptr2, *ptr3;

			snprintf(*xml_filename, OPH_TP_BUFLEN, "%s_" OPH_TP_XML_OPERATOR_TYPE "_", function_name);

			while (!readdir_r(dir, &save_ent, &ent) && ent) {
				snprintf(full_filename, OPH_TP_BUFLEN, "%s/%s", folder, ent->d_name);
				lstat(full_filename, &file_stat);

				if (!S_ISLNK(file_stat.st_mode) && !S_ISREG(file_stat.st_mode))
					continue;
				if (strcasestr(ent->d_name, *xml_filename)) {
					ptr1 = strrchr(ent->d_name, '_');
					ptr2 = strrchr(ent->d_name, '.');
					if (!ptr1 || !ptr2) {
						return OPH_TP_TASK_SYSTEM_ERROR;
					}

					strncpy(buffer, ent->d_name, strlen(ent->d_name) - strlen(ptr1) + 1);
					buffer[strlen(ent->d_name) - strlen(ptr1) + 1] = 0;
					if (strcasecmp(*xml_filename, buffer))
						continue;

					versionlen = 0;
					ptr3 = strchr(ptr1 + 1, '.');

					if (strlen(ptr1) - strlen(ptr3) - 1 > maxlen) {
						maxlen = strlen(ptr1) - strlen(ptr3) - 1;
					}
					versionlen++;
					count++;

					while (ptr2 != ptr3) {
						ptr1 = strchr(ptr1 + 1, '.');
						ptr3 = strchr(ptr1 + 1, '.');
						if (!ptr1 || !ptr3) {
							return OPH_TP_TASK_SYSTEM_ERROR;
						}
						if (strlen(ptr1) - strlen(ptr3) - 1 > maxlen) {
							maxlen = strlen(ptr1) - strlen(ptr3) - 1;
						}
						versionlen++;
					}

					snprintf(format, OPH_TP_BUFLEN, "%%0%dd", maxlen);
					if (versionlen > maxversionlen) {
						maxversionlen = versionlen;
					}

					if (strncasecmp(ptr2 + 1, OPH_TP_XML_FILE_EXTENSION, strlen(OPH_TP_XML_FILE_EXTENSION)) || strncasecmp(ptr2 + 1, OPH_TP_XML_FILE_EXTENSION, strlen(ptr2 + 1)))
						continue;

					found = 1;
					break;
				}
			}
			closedir(dir);

			if (!found) {
				return OPH_TP_TASK_SYSTEM_ERROR;
			}

			char *field = (char *) malloc((maxlen + 1) * sizeof(char));
			if (!field) {
				return OPH_TP_TASK_SYSTEM_ERROR;
			}

			char **versions = (char **) malloc(count * sizeof(char *));
			if (!versions) {
				return OPH_TP_TASK_SYSTEM_ERROR;
			}
			int i;
			for (i = 0; i < count; i++) {
				versions[i] = (char *) malloc((maxlen * maxversionlen + 1) * sizeof(char));
				if (!versions[i]) {
					return OPH_TP_TASK_SYSTEM_ERROR;
				}
			}
			char **versions2 = (char **) malloc(count * sizeof(char *));
			if (!versions2) {
				return OPH_TP_TASK_SYSTEM_ERROR;
			}
			for (i = 0; i < count; i++) {
				versions2[i] = (char *) malloc(OPH_TP_BUFLEN * sizeof(char));
				if (!versions2[i]) {
					return OPH_TP_TASK_SYSTEM_ERROR;
				}
			}

			int j = 0;
			int val;
			if ((dir = opendir(folder)) != NULL) {
				while (!readdir_r(dir, &save_ent, &ent) && ent) {
					snprintf(full_filename, OPH_TP_BUFLEN, "%s/%s", folder, ent->d_name);
					lstat(full_filename, &file_stat);

					if (!S_ISLNK(file_stat.st_mode) && !S_ISREG(file_stat.st_mode))
						continue;
					if (strcasestr(ent->d_name, *xml_filename)) {
						ptr1 = strrchr(ent->d_name, '_');
						ptr2 = strrchr(ent->d_name, '.');
						if (!ptr1 || !ptr2) {
							return OPH_TP_TASK_SYSTEM_ERROR;
						}

						strncpy(buffer, ent->d_name, strlen(ent->d_name) - strlen(ptr1) + 1);
						buffer[strlen(ent->d_name) - strlen(ptr1) + 1] = 0;
						if (strcasecmp(*xml_filename, buffer))
							continue;

						j++;
						i = 0;
						ptr3 = strchr(ptr1 + 1, '.');

						//copy real filename
						strncpy(versions2[j - 1], ent->d_name, strlen(ent->d_name));
						versions2[j - 1][strlen(ent->d_name)] = 0;

						//extract a single value from version
						strncpy(field, ptr1 + 1, strlen(ptr1) - strlen(ptr3) - 1);
						field[strlen(ptr1) - strlen(ptr3) - 1] = 0;
						val = strtol(field, NULL, 10);
						snprintf(field, maxlen + 1, format, val);
						strncpy(versions[j - 1] + i * maxlen, field, maxlen);

						i++;
						while (i < maxversionlen) {
							if (ptr2 != ptr3) {
								ptr1 = strchr(ptr1 + 1, '.');
								ptr3 = strchr(ptr1 + 1, '.');
								if (!ptr1 || !ptr3)
									return OPH_TP_TASK_SYSTEM_ERROR;

								//extract a single value from version
								strncpy(field, ptr1 + 1, strlen(ptr1) - strlen(ptr3) - 1);
								field[strlen(ptr1) - strlen(ptr3) - 1] = 0;
								val = strtol(field, NULL, 10);
								snprintf(field, maxlen + 1, format, val);
								strncpy(versions[j - 1] + i * maxlen, field, maxlen);

							} else {
								//consider value=0
								val = 0;
								snprintf(field, maxlen + 1, format, val);
								strncpy(versions[j - 1] + i * maxlen, field, maxlen);

							}
							i++;
						}

						versions[j - 1][maxlen * maxversionlen] = 0;

						if (j == count)
							break;
					}
				}
				closedir(dir);
			} else {
				return OPH_TP_TASK_SYSTEM_ERROR;
			}

			//find latest version
			int latest_index = 0;
			for (j = 1; j < count; j++) {
				if (strcmp(versions[j], versions[latest_index]) > 0) {
					latest_index = j;
				}
			}

			snprintf(*xml_filename, OPH_TP_BUFLEN, "%s", versions2[latest_index]);

			free(field);
			for (i = 0; i < count; i++) {
				free(versions[i]);
			}
			free(versions);
			for (i = 0; i < count; i++) {
				free(versions2[i]);
			}
			free(versions2);

		} else {
			snprintf(*xml_filename, OPH_TP_BUFLEN, "%s_" OPH_TP_XML_OPERATOR_TYPE "_%s.xml", function_name, function_version);
			while (!readdir_r(dir, &save_ent, &ent) && ent) {
				snprintf(full_filename, OPH_TP_BUFLEN, "%s/%s", folder, ent->d_name);
				lstat(full_filename, &file_stat);

				if (!S_ISLNK(file_stat.st_mode) && !S_ISREG(file_stat.st_mode))
					continue;
				if (!strcasecmp(*xml_filename, ent->d_name)) {
					found = 1;
					snprintf(*xml_filename, OPH_TP_BUFLEN, "%s", ent->d_name);
					break;
				}
			}
			closedir(dir);
			if (!found) {
				return OPH_TP_TASK_SYSTEM_ERROR;
			}
		}
	} else {
		return OPH_TP_TASK_SYSTEM_ERROR;
	}

	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_validate_task_string(const char *task_string)
{
	if (!task_string)
		return OPH_TP_TASK_SYSTEM_ERROR;

	char last_char = OPH_TP_PARAM_PARAM_SEPARATOR;
	char previous_char = 0;
	int first_flag = 1;
	int i;

	int skip_flag = 0, skip_check = 0;
	for (i = 0; task_string[i]; i++) {
		if (skip_flag) {
			if (task_string[i] == OPH_TP_SKIP_SEPARATOR) {
				skip_flag = 0;
				skip_check = 1;
			}
			continue;
		}
		if (skip_check && task_string[i] != OPH_TP_PARAM_PARAM_SEPARATOR)
			return OPH_TP_TASK_PARSER_ERROR;
		switch (task_string[i]) {
			case OPH_TP_SKIP_SEPARATOR:{
					if (previous_char != OPH_TP_PARAM_VALUE_SEPARATOR)
						return OPH_TP_TASK_PARSER_ERROR;
					skip_flag = 1;
					break;
				}
			case OPH_TP_PARAM_VALUE_SEPARATOR:{
					if (((last_char != OPH_TP_PARAM_PARAM_SEPARATOR) && (last_char != OPH_TP_PARAM_VALUE_SEPARATOR))
					    || (previous_char == OPH_TP_PARAM_VALUE_SEPARATOR || previous_char == OPH_TP_MULTI_VALUE_SEPARATOR || previous_char == OPH_TP_PARAM_PARAM_SEPARATOR))
						return OPH_TP_TASK_PARSER_ERROR;
					else {
						last_char = OPH_TP_PARAM_VALUE_SEPARATOR;
						first_flag = 0;
					}
					break;
				}
			case OPH_TP_PARAM_PARAM_SEPARATOR:{
					if (first_flag)
						return OPH_TP_TASK_PARSER_ERROR;
					if (last_char == OPH_TP_PARAM_PARAM_SEPARATOR
					    || (previous_char == OPH_TP_PARAM_VALUE_SEPARATOR || previous_char == OPH_TP_MULTI_VALUE_SEPARATOR || previous_char == OPH_TP_PARAM_PARAM_SEPARATOR))
						return OPH_TP_TASK_PARSER_ERROR;
					else
						last_char = OPH_TP_PARAM_PARAM_SEPARATOR;
					break;
				}
			case OPH_TP_MULTI_VALUE_SEPARATOR:{
					if (first_flag)
						return OPH_TP_TASK_PARSER_ERROR;
					if (last_char == OPH_TP_PARAM_PARAM_SEPARATOR
					    || (previous_char == OPH_TP_PARAM_VALUE_SEPARATOR || previous_char == OPH_TP_MULTI_VALUE_SEPARATOR || previous_char == OPH_TP_PARAM_PARAM_SEPARATOR))
						return OPH_TP_TASK_PARSER_ERROR;
					else
						last_char = OPH_TP_MULTI_VALUE_SEPARATOR;
					break;
				}
		}
		previous_char = task_string[i];
		skip_check = 0;
	}
	if (skip_flag || skip_check)
		return OPH_TP_TASK_PARSER_ERROR;
	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_find_param_in_task_string(const char *task_string, const char *param, char *value)
{
	if (!task_string || !param || !value)
		return OPH_TP_TASK_SYSTEM_ERROR;

	const char *ptr_begin, *ptr_equal, *ptr_end, *start_char, *stop_char;

	ptr_begin = task_string;
	ptr_equal = strchr(task_string, OPH_TP_PARAM_VALUE_SEPARATOR);
	ptr_end = strchr(task_string, OPH_TP_PARAM_PARAM_SEPARATOR);
	while (ptr_end) {
		if (!ptr_begin || !ptr_equal || !ptr_end)
			return OPH_TP_TASK_SYSTEM_ERROR;

		if (!strncmp(ptr_begin, param, strlen(ptr_begin) - strlen(ptr_equal)) && !strncmp(ptr_begin, param, strlen(param))) {
			start_char = ptr_equal + 1;
			stop_char = ptr_end;
			if (*start_char == OPH_TP_SKIP_SEPARATOR) {
				start_char++;
				stop_char--;
			}
			strncpy(value, start_char, strlen(start_char) - strlen(stop_char));
			value[strlen(start_char) - strlen(stop_char)] = 0;
			return OPH_TP_TASK_PARSER_SUCCESS;
		}
		ptr_begin = ptr_end + 1;
		ptr_equal = strchr(ptr_end + 1, OPH_TP_PARAM_VALUE_SEPARATOR);
		ptr_end = strchr(ptr_end + 1, OPH_TP_PARAM_PARAM_SEPARATOR);
	}
	return OPH_TP_TASK_PARSER_ERROR;
}

int oph_tp_validate_xml_document(xmlDocPtr document)
{
	if (!document)
		return OPH_TP_TASK_SYSTEM_ERROR;

	//Create validation context
	xmlValidCtxtPtr ctxt;
	ctxt = xmlNewValidCtxt();
	if (ctxt == NULL)
		return OPH_TP_TASK_SYSTEM_ERROR;

	//Parse the DTD file
	char tmp[OPH_TP_BUFLEN];
	snprintf(tmp, OPH_TP_BUFLEN, OPH_SERVER_DTD_SCHEMA, oph_server_location);
	xmlDtdPtr dtd = xmlParseDTD(NULL, (xmlChar *) tmp);
	if (dtd == NULL) {
		xmlFreeValidCtxt(ctxt);
		return OPH_TP_TASK_SYSTEM_ERROR;
	}
	//Validate document
	if (!xmlValidateDtd(ctxt, document, dtd)) {
		xmlFreeValidCtxt(ctxt);
		xmlFreeDtd(dtd);
		return OPH_TP_TASK_SYSTEM_ERROR;
	}
	xmlFreeDtd(dtd);
	xmlFreeValidCtxt(ctxt);

	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_match_value_in_xml_value_list(const char *value, const xmlChar * values)
{
	if (!value || !values)
		return OPH_TP_TASK_SYSTEM_ERROR;

	char *ptr_begin, *ptr_end;

	ptr_begin = (char *) values;
	ptr_end = strchr(ptr_begin, OPH_TP_MULTI_VALUE_SEPARATOR);
	while (ptr_end) {
		if (!ptr_begin || !ptr_end)
			return OPH_TP_TASK_SYSTEM_ERROR;

		if (!strncmp(ptr_begin, value, strlen(ptr_begin) - strlen(ptr_end)) && !strncmp(ptr_begin, value, strlen(value)))
			return OPH_TP_TASK_PARSER_SUCCESS;

		ptr_begin = ptr_end + 1;
		ptr_end = strchr(ptr_end + 1, OPH_TP_MULTI_VALUE_SEPARATOR);
	}
	//Check last value
	if (!strncmp(ptr_begin, value, strlen(ptr_begin)) && !strncmp(ptr_begin, value, strlen(value)))
		return OPH_TP_TASK_PARSER_SUCCESS;

	return OPH_TP_TASK_PARSER_ERROR;
}

int oph_tp_validate_task_string_param(const char *task_string, xmlNodePtr xml_node, const char *param, char *value)
{
	if (!task_string || !param || !value || !xml_node)
		return OPH_TP_TASK_SYSTEM_ERROR;

	xmlChar *attribute_type, *attribute_mandatory, *attribute_minvalue, *attribute_maxvalue, *attribute_default, *attribute_values;
	char *tmp_value = strdup(task_string);
	if (!tmp_value) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
		return OPH_TP_TASK_PARSER_ERROR;
	}
	//Find param in task string
	if (oph_tp_find_param_in_task_string(task_string, param, tmp_value)) {

		//Check if the parameter is mandatory
		attribute_mandatory = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_MANDATORY);
		if (attribute_mandatory != NULL && !xmlStrcmp((const xmlChar *) "no", attribute_mandatory)) {
			xmlFree(attribute_mandatory);
			attribute_default = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_DEFAULT);
			if (attribute_default != NULL) {
				strncpy(value, (char *) attribute_default, xmlStrlen(attribute_default));
				value[xmlStrlen(attribute_default)] = 0;
				xmlFree(attribute_default);
			} else {
				free(tmp_value);
				return OPH_TP_TASK_PARSER_ERROR;
			}
		} else {
			xmlFree(attribute_mandatory);
			free(tmp_value);
			return OPH_TP_TASK_PARSER_ERROR;
		}
	} else {

		//Other checks
		attribute_type = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_TYPE);
		if (attribute_type != NULL) {

			if (!xmlStrcmp(attribute_type, (const xmlChar *) OPH_TP_INT_TYPE)) {
				int numeric_value = (int) strtol(tmp_value, NULL, 10);

				attribute_minvalue = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_MINVALUE);
				attribute_maxvalue = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_MAXVALUE);
				int min_value = 0, max_value = 0;
				if (attribute_minvalue != NULL && attribute_maxvalue != NULL) {
					min_value = (int) strtol((char *) attribute_minvalue, NULL, 10);
					max_value = (int) strtol((char *) attribute_maxvalue, NULL, 10);
					xmlFree(attribute_minvalue);
					xmlFree(attribute_maxvalue);
					if (min_value == max_value) {
						sprintf(tmp_value, "%d", min_value);
					} else {
						if (numeric_value < min_value) {
							xmlFree(attribute_type);
							free(tmp_value);
							return OPH_TP_TASK_PARSER_ERROR;
						}
						if (numeric_value > max_value) {
							xmlFree(attribute_type);
							free(tmp_value);
							return OPH_TP_TASK_PARSER_ERROR;
						}
					}
				} else if (attribute_minvalue != NULL) {
					min_value = strtol((char *) attribute_minvalue, NULL, 10);
					xmlFree(attribute_minvalue);
					if (numeric_value < min_value) {
						xmlFree(attribute_type);
						free(tmp_value);
						return OPH_TP_TASK_PARSER_ERROR;
					}
				} else if (attribute_maxvalue != NULL) {
					max_value = strtol((char *) attribute_maxvalue, NULL, 10);
					xmlFree(attribute_maxvalue);
					if (numeric_value > max_value) {
						xmlFree(attribute_type);
						free(tmp_value);
						return OPH_TP_TASK_PARSER_ERROR;
					}
				}
			} else if (!xmlStrcmp(attribute_type, (const xmlChar *) OPH_TP_REAL_TYPE)) {
				double numeric_value = (int) strtod(tmp_value, NULL);

				attribute_minvalue = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_MINVALUE);
				attribute_maxvalue = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_MAXVALUE);
				double min_value = 0, max_value = 0;
				if (attribute_minvalue != NULL && attribute_maxvalue != NULL) {
					min_value = strtod((char *) attribute_minvalue, NULL);
					max_value = strtod((char *) attribute_maxvalue, NULL);
					xmlFree(attribute_minvalue);
					xmlFree(attribute_maxvalue);
					if (min_value == max_value) {
						sprintf(tmp_value, "%f", min_value);
						pmesg(LOG_WARNING, __FILE__, __LINE__, "Param '%s' is changed to the only possible value %f\n", param, min_value);
					} else {
						if (numeric_value < min_value) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Param '%s' is lower than minvalue %f\n", param, min_value);
							xmlFree(attribute_type);
							free(tmp_value);
							return OPH_TP_TASK_PARSER_ERROR;
						}
						if (numeric_value > max_value) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Param '%s' is higher than maxvalue %f\n", param, max_value);
							xmlFree(attribute_type);
							free(tmp_value);
							return OPH_TP_TASK_PARSER_ERROR;
						}
					}
				} else if (attribute_minvalue != NULL) {
					min_value = strtod((char *) attribute_minvalue, NULL);
					xmlFree(attribute_minvalue);
					if (numeric_value < min_value) {
						xmlFree(attribute_type);
						free(tmp_value);
						return OPH_TP_TASK_PARSER_ERROR;
					}
				} else if (attribute_maxvalue != NULL) {
					max_value = strtod((char *) attribute_maxvalue, NULL);
					xmlFree(attribute_maxvalue);
					if (numeric_value > max_value) {
						xmlFree(attribute_type);
						free(tmp_value);
						return OPH_TP_TASK_PARSER_ERROR;
					}
				}
			}

			attribute_values = xmlGetProp(xml_node, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_VALUES);
			if (attribute_values != NULL) {
				//Check if the value is in the set of specified values
				if (oph_tp_match_value_in_xml_value_list(tmp_value, attribute_values)) {
					xmlFree(attribute_type);
					xmlFree(attribute_values);
					free(tmp_value);
					return OPH_TP_TASK_PARSER_ERROR;
				}
				xmlFree(attribute_values);
			}

			strncpy(value, tmp_value, strlen(tmp_value));
			value[strlen(tmp_value)] = 0;
			xmlFree(attribute_type);
		}
	}

	free(tmp_value);

	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_start_xml_parser()
{
	xmlInitParser();
	LIBXML_TEST_VERSION return 0;
}

int oph_tp_end_xml_parser()
{
	xmlCleanupParser();
	return 0;
}

int oph_tp_task_params_parser(const char *operator, const char *task_string, HASHTBL ** hashtbl)
{
	if (!operator || ! hashtbl)
		return OPH_TP_TASK_SYSTEM_ERROR;

	if (!task_string || !strlen(task_string))
		return OPH_TP_TASK_PARSER_SUCCESS;

	//Check if string has correct format
	if (oph_tp_validate_task_string(task_string))
		return OPH_TP_TASK_PARSER_ERROR;

	xmlDocPtr document;
	xmlNodePtr root, node, subnode;

	//Select the correct XML file
	char path_file[OPH_TP_XML_PATH_LENGTH] = { '\0' };
	char filename[OPH_TP_XML_PATH_LENGTH] = { '\0' };
	char operator_name[OPH_TP_TASKLEN] = { '\0' };
	strncpy(operator_name, operator, OPH_TP_TASKLEN);
	char *op = operator_name;
	while (*op != '\0') {
		*op = toupper((unsigned char) *op);
		op++;
	}

	char folder[OPH_TP_BUFLEN];
	snprintf(folder, OPH_TP_BUFLEN, OPH_SERVER_XML_PATH, oph_server_location);

	if (oph_tp_retrieve_function_xml_file((const char *) operator_name, NULL, &filename, folder))
		return OPH_TP_TASK_SYSTEM_ERROR;

	snprintf(path_file, sizeof(path_file), OPH_SERVER_XML_FILE, oph_server_location, filename);

	//Open document
	document = xmlParseFile(path_file);
	if (document == NULL)
		return OPH_TP_TASK_SYSTEM_ERROR;

	//Validate XML document
	if (oph_tp_validate_xml_document(document)) {
		xmlFreeDoc(document);
		return OPH_TP_TASK_SYSTEM_ERROR;
	}
	//Read root
	root = xmlDocGetRootElement(document);
	if (root == NULL) {
		xmlFreeDoc(document);
		return OPH_TP_TASK_SYSTEM_ERROR;
	}

	xmlChar *content, *attribute_allownot;

	//Parse till args section
	size_t len = strlen(task_string);
	long number_arguments = 0;
	char key1[OPH_TP_TASKLEN];
	char *value1 = NULL;
	node = root->children;
	while (node) {
		if (!xmlStrcmp(node->name, (const xmlChar *) OPH_TP_XML_ARGS)) {
			//Count number of elements
			number_arguments = xmlChildElementCount(node);

			if (!(*hashtbl = hashtbl_create(number_arguments + 1, NULL))) {
				xmlFreeDoc(document);
				return OPH_TP_TASK_SYSTEM_ERROR;
			}
			//For each argument read content and attributes
			subnode = node->xmlChildrenNode;
			while (subnode != NULL) {
				if ((!xmlStrcmp(subnode->name, (const xmlChar *) OPH_TP_XML_ARGUMENT))) {
					//Look for param names (xml content)
					content = xmlNodeGetContent(subnode->xmlChildrenNode);
					if (content != NULL) {
						value1 = (char *) malloc(len + 10);
						if (!value1) {
							xmlFree(content);
							xmlFreeDoc(document);
							return OPH_TP_TASK_PARSER_ERROR;
						}
						//Get and check value for parameter
						if (oph_tp_validate_task_string_param(task_string, subnode, (char *) content, value1)) {
							xmlFree(content);
							xmlFreeDoc(document);
							free(value1);
							return OPH_TP_TASK_PARSER_ERROR;
						}
						hashtbl_insert(*hashtbl, (char *) content, value1);
						attribute_allownot = xmlGetProp(subnode, (const xmlChar *) OPH_TP_XML_ATTRIBUTE_ALLOWNOT);
						if (attribute_allownot) {
							if (!xmlStrcmp((const xmlChar *) "yes", attribute_allownot)) {
								snprintf(key1, OPH_TP_TASKLEN, "%s!", (char *) content);
								if (oph_tp_validate_task_string_param(task_string, subnode, key1, value1)) {
									xmlFree(attribute_allownot);
									xmlFree(content);
									xmlFreeDoc(document);
									free(value1);
									return OPH_TP_TASK_PARSER_ERROR;
								}
								hashtbl_insert(*hashtbl, key1, value1);
							}
							xmlFree(attribute_allownot);
						}
						free(value1);
					}
					xmlFree(content);
				}
				subnode = subnode->next;
			}
			break;
		}
		node = node->next;
	}

	// free up the parser context
	xmlFreeDoc(document);

	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_task_param_checker(const char *operator, const char *task_string, char *key, char *value)
{
	return oph_tp_task_param_checker_and_role(operator, task_string, key, value, NULL);
}

int oph_tp_task_param_checker_and_role(const char *operator, const char *task_string, char *key, char *value, char *role)
{
	if (!operator || ! task_string || !key || !value)
		return OPH_TP_TASK_SYSTEM_ERROR;

	//Check if string has correct format
	if (oph_tp_validate_task_string(task_string))
		return OPH_TP_TASK_PARSER_ERROR;

	xmlDocPtr document;
	xmlNodePtr root, node, subnode;

	//Select the correct XML file
	char path_file[OPH_TP_XML_PATH_LENGTH] = { '\0' };
	char filename[OPH_TP_XML_PATH_LENGTH] = { '\0' };
	char operator_name[OPH_TP_TASKLEN] = { '\0' };
	strncpy(operator_name, operator, OPH_TP_TASKLEN);
	char *op = operator_name;
	while (*op != '\0') {
		*op = toupper((unsigned char) *op);
		op++;
	}

	if (oph_tp_retrieve_function_xml_file((const char *) operator_name, NULL, &filename, oph_xml_operator_dir))
		return OPH_TP_TASK_SYSTEM_ERROR;

	snprintf(path_file, sizeof(path_file), OPH_SERVER_XML_EXT_FILE, oph_xml_operator_dir, filename);

	//Open document
	document = xmlParseFile(path_file);
	if (document == NULL)
		return OPH_TP_TASK_SYSTEM_ERROR;

	//Validate XML document
	if (oph_tp_validate_xml_document(document)) {
		xmlFreeDoc(document);
		return OPH_TP_TASK_SYSTEM_ERROR;
	}
	//Read root
	root = xmlDocGetRootElement(document);
	if (root == NULL) {
		xmlFreeDoc(document);
		return OPH_TP_TASK_SYSTEM_ERROR;
	}

	xmlChar *content;

	//Parse till args section
	char *value1 = NULL;
	node = root->children;
	while (node) {
		if (!xmlStrcmp(node->name, (const xmlChar *) OPH_TP_XML_ARGS)) {
			//For each argument read content and attributes
			subnode = node->xmlChildrenNode;
			while (subnode) {
				if ((!xmlStrcmp(subnode->name, (const xmlChar *) OPH_TP_XML_ARGUMENT))) {
					//Look for param names (xml content)
					content = xmlNodeGetContent(subnode->xmlChildrenNode);
					if (content) {
						if (!strncmp((char *) content, key, OPH_TP_TASKLEN)) {
							value1 = strdup(task_string);
							if (!value1) {
								xmlFree(content);
								xmlFreeDoc(document);
								return OPH_TP_TASK_PARSER_ERROR;
							}
							//Get and check value for parameter
							if (oph_tp_validate_task_string_param(task_string, subnode, (char *) content, value1)) {
								xmlFree(content);
								xmlFreeDoc(document);
								free(value1);
								return OPH_TP_TASK_PARSER_ERROR;
							}
							strcpy(value, value1);
							xmlFree(content);
							free(value1);
							break;
						}
						xmlFree(content);
					}
				}
				subnode = subnode->next;
			}
			break;
		}
		node = node->next;
	}

	node = root->children;
	while (role && node) {
		if (!xmlStrcmp(node->name, (const xmlChar *) OPH_TP_XML_INFO)) {
			subnode = node->xmlChildrenNode;
			while (subnode) {
				if (!xmlStrcmp(subnode->name, (const xmlChar *) OPH_TP_XML_PERMISSION)) {
					content = xmlNodeGetContent(subnode->xmlChildrenNode);
					if (content) {
						strcpy(role, (char *) content);
						xmlFree(content);
					}
					break;
				}
				subnode = subnode->next;
			}
			break;
		}
		node = node->next;
	}

	// free up the parser context
	xmlFreeDoc(document);

	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_parse_multiple_value_param(char *values, char ***value_list, int *value_num)
{
	if (!values || !value_list || !value_num)
		return OPH_TP_TASK_SYSTEM_ERROR;

	*value_list = NULL;
	*value_num = 0;

	if (!strlen(values))
		return OPH_TP_TASK_PARSER_SUCCESS;

	int param_num = 1, i, j, msize = 0, csize = 0;

	//Check if string is correct
	for (i = 0; values[i]; i++) {
		if (values[i] == OPH_TP_PARAM_VALUE_SEPARATOR || values[i] == OPH_TP_PARAM_PARAM_SEPARATOR)
			return OPH_TP_TASK_PARSER_ERROR;
	}

	//Count number of parameters
	for (i = 0; values[i]; i++) {
		csize++;
		if (values[i] == OPH_TP_MULTI_VALUE_SEPARATOR) {
			param_num++;
			if (msize < csize)
				msize = csize;
			csize = 0;
		}
	}
	if (msize < csize)
		msize = csize;

	*value_list = (char **) malloc(param_num * sizeof(char *));
	if (!(*value_list))
		return OPH_TP_TASK_SYSTEM_ERROR;
	for (i = 0; i < param_num; i++)
		(*value_list)[i] = (char *) malloc((1 + msize) * sizeof(char));

	char *ptr_begin, *ptr_end;

	ptr_begin = values;
	ptr_end = strchr(values, OPH_TP_MULTI_VALUE_SEPARATOR);
	j = 0;
	while (ptr_begin) {
		if (ptr_end) {
			strncpy((*value_list)[j], ptr_begin, strlen(ptr_begin) - strlen(ptr_end));
			(*value_list)[j][strlen(ptr_begin) - strlen(ptr_end)] = 0;
			ptr_begin = ptr_end + 1;
			ptr_end = strchr(ptr_end + 1, OPH_TP_MULTI_VALUE_SEPARATOR);
		} else {
			strncpy((*value_list)[j], ptr_begin, strlen(ptr_begin));
			(*value_list)[j][strlen(ptr_begin)] = 0;
			ptr_begin = NULL;
		}
		j++;
	}

	*value_num = param_num;
	return OPH_TP_TASK_PARSER_SUCCESS;
}

int oph_tp_free_multiple_value_param_list(char **value_list, int value_num)
{
	int i;
	if (value_list) {
		for (i = 0; i < value_num; i++)
			if (value_list[i])
				free(value_list[i]);
		free(value_list);
	}
	return OPH_TP_TASK_PARSER_SUCCESS;
}
