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

#ifndef OPH_FILTERS_H
#define OPH_FILTERS_H

#include "hashtbl.h"
#include "oph_ophidiadb.h"

#define OPH_MF_OK 0
#define OPH_MF_ERROR 1

#define OPH_MF_QUERY "SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM %s WHERE %s"
#define OPH_MF_QUERY_DUMMY "SELECT datacube.iddatacube, datacube.idcontainer FROM %s"

#define OPH_MF_ARG_DATACUBE "datacube"
#define OPH_MF_ARG_RUN "run"
#define OPH_MF_ARG_RECURSIVE "recursive"
#define OPH_MF_ARG_DEPTH "depth"
#define OPH_MF_ARG_OBJKEY_FILTER "objkey_filter"

#define OPH_MF_ARG_VALUE_YES "yes"
#define OPH_MF_ARG_VALUE_NO "no"
#define OPH_MF_ARG_VALUE_CMIP5 "cmip5"
#define OPH_MF_ROOT_FOLDER "/"

// Datacube filters
#define OPH_MF_ARG_LEVEL "level"
#define OPH_MF_ARG_MEASURE "measure"
#define OPH_MF_ARG_PARENT "parent_cube"
#define OPH_MF_ARG_DATACUBE_FILTER "cube_filter"

// Container filters
#define OPH_MF_ARG_CONTAINER "container"
#define OPH_MF_ARG_CONTAINER_PID "container_pid"
#define OPH_MF_ARG_METADATA_KEY "metadata_key"
#define OPH_MF_ARG_METADATA_VALUE "metadata_value"

// Container and file filters
#define OPH_MF_ARG_PATH "path"

// File filters
#define OPH_MF_ARG_FILE "file"
#define OPH_MF_ARG_CONVENTION "convention"

// Const
#define OPH_MF_SYMBOL_NOT "!"	// "`"

// Main interface of this library
int oph_filter(HASHTBL * task_tbl, char *query, char *cwd, char *sessionid, ophidiadb * oDB);
int oph_filter_unsafe(HASHTBL * task_tbl, char *query, char *cwd, char *sessionid, ophidiadb * oDB);

// Internal functions
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
int oph_filter_level(char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_measure(const char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_parent(char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_using_subset(char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_container(char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_container_pid(char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_metadata_key(char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_metadata_value(char *key, char *value, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_path(char *path, char *recursive, char *depth, char *sessionid, ophidiadb * oDB, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
int oph_filter_free_kvp(HASHTBL * task_tbl, char *tables, char *where_clause, pthread_mutex_t * flag, char not_clause);
#endif

#endif				/* OPH_FILTERS_H */
