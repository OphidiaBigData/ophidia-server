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

#include "oph_parser.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_init_args(oph_argument ** args)
{
	if (!args)
		return OPH_SERVER_NULL_POINTER;
	*args = NULL;
	return OPH_SERVER_OK;
}

int oph_cleanup_args(oph_argument ** args)
{
	if (!args)
		return OPH_SERVER_NULL_POINTER;

	oph_argument *tmp;
	for (tmp = *args; tmp; tmp = *args) {
		if (tmp->key) {
			free(tmp->key);
			tmp->key = 0;
		}
		if (tmp->value) {
			free(tmp->value);
			tmp->value = 0;
		}
		*args = tmp->next;
		free(tmp);
	}

	return OPH_SERVER_OK;
}

int oph_init_args_list(oph_arguments ** list)
{
	if (!list)
		return OPH_SERVER_NULL_POINTER;
	*list = NULL;
	return OPH_SERVER_OK;
}

int oph_append_args_list(oph_arguments ** list, oph_argument * item, int id)
{
	if (!list || !item)
		return OPH_SERVER_NULL_POINTER;
	oph_arguments *args_item = (oph_arguments *) malloc(sizeof(oph_arguments));
	if (!args_item)
		return OPH_SERVER_SYSTEM_ERROR;
	args_item->id = id;
	args_item->item = item;
	args_item->next = *list;
	*list = args_item;
	return OPH_SERVER_OK;
}

int oph_order_args_list(oph_arguments ** list)
{
	if (!list)
		return OPH_SERVER_NULL_POINTER;
	if (!(*list) || !((*list)->next))
		return OPH_SERVER_OK;

	oph_arguments *item, *prev;
	int count;
	do {
		count = 0;
		prev = NULL;
		for (item = *list; item->next;) {
			if (item->id > item->next->id) {
				count++;
				if (prev)
					prev->next = item->next;
				else
					*list = item->next;
				prev = prev ? prev->next : *list;
				item->next = prev->next;
				prev->next = item;
			} else {
				prev = item;
				item = item->next;
			}
		}
	}
	while (count);

	return OPH_SERVER_OK;
}

int oph_cleanup_args_list(oph_arguments ** list)
{
	if (!list)
		return OPH_SERVER_NULL_POINTER;

	oph_arguments *tmp;
	for (tmp = *list; tmp; tmp = *list) {
		oph_cleanup_args(&(tmp->item));
		*list = tmp->next;
		free(tmp);
	}

	return OPH_SERVER_OK;
}

int oph_parse_program(oph_argument ** args, unsigned int *counter, const char *task_string)
{
	if (!task_string || !counter || !args)
		return OPH_SERVER_NULL_POINTER;

	char *ptr0, *ptr1;
	oph_argument *tmp, *tmp2 = 0;
	char program[OPH_MAX_PROGRAM_SIZE], key[OPH_SHORT_STRING_SIZE];

	*args = 0;
	*counter = 0;

	snprintf(program, OPH_MAX_PROGRAM_SIZE, "%s\n", task_string);

	ptr0 = program;
	ptr1 = strchr(ptr0, OPH_SEPARATOR_QUERY);
	if (ptr1)
		ptr1++;

	while (ptr0 && strlen(ptr0) && ptr1) {
		(*counter)++;

		if (strlen(ptr0) - strlen(ptr1) > OPH_MAX_STRING_SIZE) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Query size too high\n");
			oph_cleanup_args(args);
			return OPH_SERVER_ERROR;
		}

		snprintf(key, OPH_SHORT_STRING_SIZE, "%d", *counter);

		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(key);
		tmp->value = strndup(ptr0, strlen(ptr0) - strlen(ptr1) - 1);

		if (tmp2) {
			tmp->next = tmp2->next;
			tmp2->next = tmp;
		} else {
			tmp->next = *args;
			*args = tmp;
		}

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "New query added '%s: %s'\n", tmp->key, tmp->value);

		ptr0 = ptr1;
		ptr1 = strchr(ptr0, OPH_SEPARATOR_QUERY);
		if (ptr1)
			ptr1++;

		tmp2 = tmp;
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Found %d queries\n", *counter);
	if (!(*counter))
		return OPH_SERVER_ERROR;

	return OPH_SERVER_OK;
}

int oph_parse_query(oph_argument ** args, unsigned int *counter, const char *task_string)
{
	if (!task_string || !args || !counter)
		return OPH_SERVER_NULL_POINTER;

	char *ptr0, *ptr1, *ptr2, *ptr3;
	oph_argument *tmp, *tmp2 = 0;

	*args = NULL;
	*counter = 0;

	ptr0 = (char *) task_string;
	ptr1 = strchr(ptr0, OPH_SEPARATOR_KV[0]);
	if (ptr1) {
		ptr1++;
		if (*ptr1 == OPH_SEPARATOR_SUBPARAM_OPEN) {
			ptr3 = strchr(ptr1, OPH_SEPARATOR_SUBPARAM_CLOSE);
			if (!ptr3)
				return OPH_SERVER_ERROR;
			ptr2 = strchr(ptr3, OPH_SEPARATOR_PARAM[0]);
		} else if (*ptr1 == OPH_SEPARATOR_BRACKET_OPEN) {
			ptr3 = strchr(ptr1, OPH_SEPARATOR_BRACKET_CLOSE);
			if (!ptr3)
				return OPH_SERVER_ERROR;
			ptr2 = strchr(ptr3, OPH_SEPARATOR_PARAM[0]);
		} else
			ptr2 = strchr(ptr1, OPH_SEPARATOR_PARAM[0]);
		if (ptr2)
			ptr2++;
	}
	while (ptr0 && ptr1 && ptr2) {
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strndup(ptr0, strlen(ptr0) - strlen(ptr1) - 1);
		tmp->value = strndup(ptr1, strlen(ptr1) - strlen(ptr2) - 1);

		if (tmp2) {
			tmp->next = tmp2->next;
			tmp2->next = tmp;
		} else {
			tmp->next = *args;
			*args = tmp;
		}

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "New pair added '%s=%s'\n", tmp->key, tmp->value);

		(*counter)++;

		ptr0 = ptr2;
		ptr1 = strchr(ptr0, OPH_SEPARATOR_KV[0]);
		if (ptr1) {
			ptr1++;
			if (*ptr1 == OPH_SEPARATOR_SUBPARAM_OPEN) {
				ptr3 = strchr(ptr1, OPH_SEPARATOR_SUBPARAM_CLOSE);
				if (!ptr3)
					return OPH_SERVER_ERROR;
				ptr2 = strchr(ptr3, OPH_SEPARATOR_PARAM[0]);
			} else if (*ptr1 == OPH_SEPARATOR_BRACKET_OPEN) {
				ptr3 = strchr(ptr1, OPH_SEPARATOR_BRACKET_CLOSE);
				if (!ptr3)
					return OPH_SERVER_ERROR;
				ptr2 = strchr(ptr3, OPH_SEPARATOR_PARAM[0]);
			} else
				ptr2 = strchr(ptr1, OPH_SEPARATOR_PARAM[0]);
			if (ptr2)
				ptr2++;
		}

		tmp2 = tmp;
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Found %d KV pairs\n", *counter);

	if (!(*counter))
		return OPH_SERVER_ERROR;

	return OPH_SERVER_OK;
}

int oph_get_arg(oph_argument * args, const char *key, char *value)
{
	if (!args || !key || !value)
		return OPH_SERVER_NULL_POINTER;

	oph_argument *tmp;
	for (tmp = args; tmp; tmp = tmp->next) {
		if (!strncasecmp(tmp->key, key, OPH_MAX_STRING_SIZE)) {
			strncpy(value, tmp->value, OPH_MAX_STRING_SIZE);
			return OPH_SERVER_OK;
		}
	}
	return OPH_SERVER_UNKNOWN;
}

int oph_set_arg(oph_argument ** args, const char *key, const char *value)
{
	if (!args || !key || !value)
		return OPH_SERVER_NULL_POINTER;

	oph_argument *tmp, *tmp2 = 0;
	for (tmp = *args; tmp; tmp = tmp->next) {
		if (!strncasecmp(tmp->key, key, OPH_MAX_STRING_SIZE))
			break;
		tmp2 = tmp;
	}

	if (!tmp) {
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		if (tmp2) {
			tmp->next = tmp2->next;
			tmp2->next = tmp;
		} else {
			tmp->next = *args;
			*args = tmp;
		}
	} else {
		free(tmp->key);
		free(tmp->value);
	}
	tmp->key = strndup(key, OPH_MAX_STRING_SIZE);
	tmp->value = strndup(value, OPH_MAX_STRING_SIZE);

	return OPH_SERVER_OK;
}

int oph_arg_to_string(oph_argument * args, char *string, int add_datacube_input)
{
	if (!string)
		return OPH_SERVER_NULL_POINTER;
	string[0] = '\0';

	oph_argument *tmp;
	for (tmp = args; tmp; tmp = tmp->next) {
		if (!strncasecmp(OPH_ARG_NCORES, tmp->key, OPH_MAX_STRING_SIZE))
			continue;
		if (!strncasecmp(OPH_ARG_NHOSTS, tmp->key, OPH_MAX_STRING_SIZE))
			continue;
		if (!strncasecmp(OPH_ARG_MODE, tmp->key, OPH_MAX_STRING_SIZE))
			continue;
		if (!strncasecmp(OPH_ARG_CUBE, tmp->key, OPH_MAX_STRING_SIZE) && !add_datacube_input)
			continue;
		if (!strncasecmp(OPH_ARG_SRC_PATH, tmp->key, OPH_MAX_STRING_SIZE))
			continue;
		if (!strncasecmp(OPH_ARG_MEASURE, tmp->key, OPH_MAX_STRING_SIZE))
			continue;
		if (!strncasecmp(OPH_ARG_CALLBACK_URL, tmp->key, OPH_MAX_STRING_SIZE))
			continue;
		strncat(string, tmp->key, OPH_MAX_STRING_SIZE);
		strncat(string, OPH_SEPARATOR_KV, OPH_MAX_STRING_SIZE);
		strncat(string, tmp->value, OPH_MAX_STRING_SIZE);
		strncat(string, OPH_SEPARATOR_PARAM, OPH_MAX_STRING_SIZE);
	}
	return OPH_SERVER_OK;
}
