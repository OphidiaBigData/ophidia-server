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

#ifndef __OPH_SUBSET_H__
#define __OPH_SUBSET_H__

#define OPH_SUBSET_LIB_MAX_STRING_LENGTH 1024
#define OPH_SUBSET_LIB_MAX_TYPE_LENGTH 64
#define OPH_SUBSET_LIB_OK 0
#define OPH_SUBSET_LIB_DATA_ERR 1
#define OPH_SUBSET_LIB_NULL_POINTER_ERR 2
#define OPH_SUBSET_LIB_SYSTEM_ERR 3

#define OPH_SUBSET_LIB_PARAM_SEPARATOR ":"
#define OPH_SUBSET_LIB_SUBSET_SEPARATOR ","
#define OPH_SUBSET_LIB_PARAM_BEGIN "begin"
#define OPH_SUBSET_LIB_PARAM_END "end"
#define OPH_SUBSET_LIB_MAX_DIM 10

#define OPH_SUBSET_ISINSUBSET_PLUGIN "mysql.oph_is_in_subset(%s.%s,%ld,%ld,%ld)"

typedef enum { OPH_SUBSET_LIB_SINGLE, OPH_SUBSET_LIB_INTERVAL, OPH_SUBSET_LIB_STRIDE } oph_subset_type;

typedef struct {
	oph_subset_type *type;
	long *start;
	long *end;
	unsigned long *stride;
	unsigned long *count;
	unsigned long total;
	unsigned int number;	// Number of intervals
} oph_subset;			// List of subsets in the form <start>:<stride>:<end>

// Initialization of struct oph_subset
int oph_subset_init(oph_subset ** subset);

// Translate non-null-terminated string into an oph_subset struct. Set 'max' to 0 to avoid truncation to 'max' elements
int oph_subset_parse(const char *cond, unsigned long len, oph_subset * subset, long max);

// Freeing the struct oph_subset
int oph_subset_free(oph_subset * subset);

#endif				/* __OPH_SUBSET_H__ */
