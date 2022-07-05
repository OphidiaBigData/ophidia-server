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

#include "oph_subset_library.h"

#include <string.h>
#include <stdlib.h>

#include "debug.h"

void _oph_subset_free(oph_subset * subset)
{
	if (subset->type) {
		free(subset->type);
		subset->type = 0;
	}
	if (subset->start) {
		free(subset->start);
		subset->start = 0;
	}
	if (subset->end) {
		free(subset->end);
		subset->end = 0;
	}
	if (subset->stride) {
		free(subset->stride);
		subset->stride = 0;
	}
	if (subset->count) {
		free(subset->count);
		subset->count = 0;
	}
}

int oph_subset_init(oph_subset ** subset)
{
	if (!subset) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
		return OPH_SUBSET_LIB_NULL_POINTER_ERR;
	}
	*subset = (oph_subset *) malloc(sizeof(oph_subset));
	if (!(*subset)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in allocating oph_subset\n");
		return OPH_SUBSET_LIB_SYSTEM_ERR;
	}
	return OPH_SUBSET_LIB_OK;
}

int oph_subset_parse(const char *cond, unsigned long len, oph_subset * subset, long max)
{
	char *result, *result2, temp0[OPH_SUBSET_LIB_MAX_STRING_LENGTH], temp1[OPH_SUBSET_LIB_MAX_STRING_LENGTH], temp2[OPH_SUBSET_LIB_MAX_STRING_LENGTH], *next, *temp, *savepointer = NULL;
	unsigned int number;

	if (!subset) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
		return OPH_SUBSET_LIB_NULL_POINTER_ERR;
	}

	subset->number = 0;
	strncpy(temp0, cond, len);
	temp0[len] = '\0';

	strcpy(temp2, temp0);
	result = strtok_r(temp0, OPH_SUBSET_LIB_SUBSET_SEPARATOR, &savepointer);

	while (result) {
		subset->number++;
		result = strtok_r(NULL, OPH_SUBSET_LIB_SUBSET_SEPARATOR, &savepointer);
	}

	if (!subset->number)
		return OPH_SUBSET_LIB_DATA_ERR;

	int retval = OPH_SUBSET_LIB_OK, i = 0;

	subset->type = (oph_subset_type *) malloc(subset->number * sizeof(oph_subset_type));
	subset->start = (long *) malloc(subset->number * sizeof(long));
	subset->end = (long *) malloc(subset->number * sizeof(long));
	subset->stride = (unsigned long *) malloc(subset->number * sizeof(unsigned long));
	subset->count = (unsigned long *) malloc(subset->number * sizeof(unsigned long));
	subset->total = 0;

	next = temp2;
	result = strchr(temp2, OPH_SUBSET_LIB_SUBSET_SEPARATOR[0]);

	while (next && (retval == OPH_SUBSET_LIB_OK)) {
		if (result) {
			result[0] = '\0';
			temp = result + 1;
		} else
			temp = 0;
		result = next;
		next = temp;

		number = 0;
		strncpy(temp1, result, OPH_SUBSET_LIB_MAX_STRING_LENGTH);
		result2 = strtok_r(temp1, OPH_SUBSET_LIB_PARAM_SEPARATOR, &savepointer);
		while (result2 && (retval == OPH_SUBSET_LIB_OK)) {
			switch (number) {
				case 0:
					if (!strncasecmp(result2, OPH_SUBSET_LIB_PARAM_END, strlen(OPH_SUBSET_LIB_PARAM_END))) {
						if (max)
							subset->end[i] = max;
						else {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Clause '%s' cannot be used in this context\n", OPH_SUBSET_LIB_PARAM_END);
							retval = OPH_SUBSET_LIB_DATA_ERR;
						}
					} else
						subset->end[i] = strtol(result2, NULL, 10);
					subset->start[i] = subset->end[i];
					subset->stride[i] = 1;
					subset->type[i] = OPH_SUBSET_LIB_SINGLE;
					break;
				case 1:
					if (!strncasecmp(result2, OPH_SUBSET_LIB_PARAM_END, strlen(OPH_SUBSET_LIB_PARAM_END))) {
						if (max)
							subset->end[i] = max;
						else {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Clause '%s' cannot be used in this context\n", OPH_SUBSET_LIB_PARAM_END);
							retval = OPH_SUBSET_LIB_DATA_ERR;
						}
					} else
						subset->end[i] = strtol(result2, NULL, 10);
					subset->type[i] = OPH_SUBSET_LIB_INTERVAL;
					break;
				case 2:
					subset->stride[i] = subset->end[i];
					if (!strncasecmp(result2, OPH_SUBSET_LIB_PARAM_END, strlen(OPH_SUBSET_LIB_PARAM_END))) {
						if (max)
							subset->end[i] = max;
						else {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Clause '%s' cannot be used in this context\n", OPH_SUBSET_LIB_PARAM_END);
							retval = OPH_SUBSET_LIB_DATA_ERR;
						}
					} else
						subset->end[i] = strtol(result2, NULL, 10);
					if (subset->stride[i] > 1)
						subset->type[i] = OPH_SUBSET_LIB_STRIDE;
					break;
				default:
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong input data: too many '%s' in subset\n", OPH_SUBSET_LIB_PARAM_SEPARATOR);
					retval = OPH_SUBSET_LIB_DATA_ERR;
			}
			number++;
			result2 = strtok_r(NULL, OPH_SUBSET_LIB_PARAM_SEPARATOR, &savepointer);
		}
		if (retval != OPH_SUBSET_LIB_OK)
			break;

		if (!number) {
			subset->type[i] = OPH_SUBSET_LIB_INTERVAL;
			subset->start[i] = subset->stride[i] = 1;
			if (max)
				subset->end[i] = max;
			else
				subset->end[i] = subset->start[i];
		}

		if (!subset->stride[i] || (subset->start[i] > subset->end[i])) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong input data: 'start', 'stop' or 'step' parameters are not correctly set\n");
			retval = OPH_SUBSET_LIB_DATA_ERR;
			break;
		}
		subset->count[i] = 1 + (subset->end[i] - subset->start[i]) / subset->stride[i];
		subset->total += subset->count[i];
		++i;
		if (next)
			result = strchr(next, OPH_SUBSET_LIB_SUBSET_SEPARATOR[0]);
	}

	if (retval != OPH_SUBSET_LIB_OK)
		_oph_subset_free(subset);

	return retval;
}

int oph_subset_free(oph_subset * subset)
{
	if (subset) {
		_oph_subset_free(subset);
		free(subset);
	}
	return OPH_SUBSET_LIB_OK;
}
