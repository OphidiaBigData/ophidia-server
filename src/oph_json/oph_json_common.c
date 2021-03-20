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

#define _GNU_SOURCE

#include "oph_json_common.h"
#include "oph_json_text.h"
#include "oph_json_grid.h"
#include "oph_json_multigrid.h"
#include "oph_json_tree.h"
#include "oph_json_graph.h"

#include "oph_gather.h"

/* Standard C99 headers */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

/* Jansson header to manipulate JSONs */
#include <jansson.h>

#include "debug.h"

extern char *oph_json_location;

extern int msglevel;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int _oph_json_add_text(oph_json * json, const char *objkey, const char *title, const char *message, pthread_mutex_t * flag);
int _oph_json_add_grid(oph_json * json, const char *objkey, const char *title, const char *description, char **keys, int keys_num, char **fieldtypes, int fieldtypes_num, pthread_mutex_t * flag);
int _oph_json_add_grid_row(oph_json * json, const char *objkey, char **values, pthread_mutex_t * flag);
int _oph_json_add_multigrid(oph_json * json, const char *objkey, const char *title, const char *description, char **rowkeys, int rowkeys_num, char **rowfieldtypes, int rowfieldtypes_num,
			    char **colkeys, int colkeys_num, char **colfieldtypes, int colfieldtypes_num, char ***colvalues, int colvalues_num, const char *measurename, const char *measuretype,
			    pthread_mutex_t * flag);
int _oph_json_add_multigrid_row(oph_json * json, const char *objkey, char **rowvalues, char **measurevalues, pthread_mutex_t * flag);
int _oph_json_add_tree(oph_json * json, const char *objkey, const char *title, const char *description, char **nodekeys, int nodekeys_num, pthread_mutex_t * flag);
int _oph_json_add_tree_node(oph_json * json, const char *objkey, char **nodevalues, pthread_mutex_t * flag);
int _oph_json_set_tree_root(oph_json * json, const char *objkey, int rootnode, pthread_mutex_t * flag);
int _oph_json_add_tree_link(oph_json * json, const char *objkey, int sourcenode, int targetnode, const char *description, pthread_mutex_t * flag);
int _oph_json_add_graph(oph_json * json, const char *objkey, int is_digraph, const char *title, const char *description, char **nodekeys, int nodekeys_num, pthread_mutex_t * flag);
int _oph_json_add_graph(oph_json * json, const char *objkey, int is_digraph, const char *title, const char *description, char **nodekeys, int nodekeys_num, pthread_mutex_t * flag);
int _oph_json_add_graph_node(oph_json * json, const char *objkey, char **nodevalues, pthread_mutex_t * flag);
int _oph_json_add_graph_link(oph_json * json, const char *objkey, int node1, int node2, const char *description, pthread_mutex_t * flag);

int _oph_json_to_json_string(oph_json * json, char **jstring, pthread_mutex_t * flag)
{
	if (!json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}

	*jstring = NULL;

	/* INIT JSON OBJECT */
	json_t *oph_json = json_object();
	if (!oph_json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "oph_json");
		return OPH_JSON_MEMORY_ERROR;
	}

	/* ADD SOURCE */
	if (json->source) {
		json_t *source = json_object();
		if (!source) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "source");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		if (json_object_set_new(oph_json, "source", source)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "source");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		// SRCKEY
		if (!json->source->srckey) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "srckey");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_BAD_PARAM_ERROR;
		}
		if (json_object_set_new(source, "srckey", json_string((const char *) json->source->srckey))) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "srckey");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		// SRCNAME
		if (!json->source->srcname) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "srcname");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_BAD_PARAM_ERROR;
		}
		if (json_object_set_new(source, "srcname", json_string((const char *) json->source->srcname))) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "srcname");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		// SRCURL
		if (json->source->srcurl) {
			if (json_object_set_new(source, "srcurl", json_string((const char *) json->source->srcurl))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "srcurl");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
		}
		// DESCRIPTION
		if (json->source->description) {
			if (json_object_set_new(source, "description", json_string((const char *) json->source->description))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
		}
		// PRODUCER
		if (json->source->producer) {
			if (json_object_set_new(source, "producer", json_string((const char *) json->source->producer))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "producer");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
		}
		// KEYS & VALUES
		if (json->source->keys_num != json->source->values_num) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "keys/values num");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_BAD_PARAM_ERROR;
		}
		if (json->source->keys_num != 0) {
			unsigned int i;
			json_t *keys = json_array();
			if (!keys) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			if (json_object_set_new(source, "keys", keys)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}

			json_t *values = json_array();
			if (!values) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			if (json_object_set_new(source, "values", values)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}

			for (i = 0; i < json->source->keys_num; i++) {
				if (json_array_append_new(keys, json_string((const char *) json->source->keys[i]))) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "key");
					if (oph_json)
						json_decref(oph_json);
					return OPH_JSON_MEMORY_ERROR;
				}
				if (json_array_append_new(values, json_string((const char *) json->source->values[i]))) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "value");
					if (oph_json)
						json_decref(oph_json);
					return OPH_JSON_MEMORY_ERROR;
				}
			}
		}
	}

	/* ADD EXTRA */
	if (json->extra) {
		json_t *extra = json_object();
		if (!extra) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "extra");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		if (json_object_set_new(oph_json, "extra", extra)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "extra");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		if (json->extra->keys_num != json->extra->values_num) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "keys/values num");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_BAD_PARAM_ERROR;
		}
		if (json->extra->keys_num != 0) {
			unsigned int i;
			json_t *keys = json_array();
			if (!keys) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			if (json_object_set_new(extra, "keys", keys)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}

			json_t *values = json_array();
			if (!values) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			if (json_object_set_new(extra, "values", values)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}

			for (i = 0; i < json->extra->keys_num; i++) {
				if (json_array_append_new(keys, json_string((const char *) json->extra->keys[i]))) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "key");
					if (oph_json)
						json_decref(oph_json);
					return OPH_JSON_MEMORY_ERROR;
				}
				if (json_array_append_new(values, json_string((const char *) json->extra->values[i]))) {
					pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "value");
					if (oph_json)
						json_decref(oph_json);
					return OPH_JSON_MEMORY_ERROR;
				}
			}
		}
	}

	/* ADD CONSUMERS */
	if (json->consumers_num != 0) {
		unsigned int i;
		json_t *consumers = json_array();
		if (!consumers) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumers");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		if (json_object_set_new(oph_json, "consumers", consumers)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumers");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}

		for (i = 0; i < json->consumers_num; i++) {
			if (json_array_append_new(consumers, json_string((const char *) json->consumers[i]))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumer");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
		}
	}

	/* ADD RESPONSEKEYSET */
	if (json->responseKeyset_num != 0) {
		unsigned int i;
		json_t *responseKeyset = json_array();
		if (!responseKeyset) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKeyset");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		if (json_object_set_new(oph_json, "responseKeyset", responseKeyset)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKeyset");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}

		for (i = 0; i < json->responseKeyset_num; i++) {
			if (json_array_append_new(responseKeyset, json_string((const char *) json->responseKeyset[i]))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKey");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
		}
	}

	/* ADD RESPONSE */
	if (json->response_num != 0) {
		unsigned int i;
		json_t *response = json_array();
		if (!response) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "response");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}
		if (json_object_set_new(oph_json, "response", response)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "response");
			if (oph_json)
				json_decref(oph_json);
			return OPH_JSON_MEMORY_ERROR;
		}

		for (i = 0; i < json->response_num; i++) {
			json_t *response_i = json_object();
			if (!response_i) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "response_i");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			if (json_array_append_new(response, response_i)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "response_i");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			// OBJCLASS
			if (!json->response[i].objclass) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "objclass");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_BAD_PARAM_ERROR;
			}
			if (json_object_set_new(response_i, "objclass", json_string((const char *) json->response[i].objclass))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objclass");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			// OBJKEY
			if (!json->response[i].objkey) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "objkey");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_BAD_PARAM_ERROR;
			}
			if (json_object_set_new(response_i, "objkey", json_string((const char *) json->response[i].objkey))) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objkey");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}

			/* OBJCONTENT */
			if (json->response[i].objcontent_num == 0) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "objcontent");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_BAD_PARAM_ERROR;
			}
			json_t *objcontent = json_array();
			if (!objcontent) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}
			if (json_object_set_new(response_i, "objcontent", objcontent)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_MEMORY_ERROR;
			}

			unsigned int j;
			if (!strcmp(json->response[i].objclass, OPH_JSON_TEXT)) {
				/* ADD TEXT */
				for (j = 0; j < json->response[i].objcontent_num; j++) {
					json_t *objcontent_j = json_object();
					if (!objcontent_j) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_array_append_new(objcontent, objcontent_j)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// TITLE
					if (!((oph_json_obj_text *) json->response[i].objcontent)[j].title) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "title", json_string((const char *) ((oph_json_obj_text *) json->response[i].objcontent)[j].title))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// MESSAGE
					if (((oph_json_obj_text *) json->response[i].objcontent)[j].message) {
						if (json_object_set_new(objcontent_j, "message", json_string((const char *) ((oph_json_obj_text *) json->response[i].objcontent)[j].message))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "message");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}
				}
			} else if (!strcmp(json->response[i].objclass, OPH_JSON_GRID)) {
				/* ADD GRID */
				for (j = 0; j < json->response[i].objcontent_num; j++) {
					json_t *objcontent_j = json_object();
					if (!objcontent_j) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_array_append_new(objcontent, objcontent_j)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// TITLE
					if (!((oph_json_obj_grid *) json->response[i].objcontent)[j].title) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "title", json_string((const char *) ((oph_json_obj_grid *) json->response[i].objcontent)[j].title))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// DESCRIPTION
					if (((oph_json_obj_grid *) json->response[i].objcontent)[j].description) {
						if (json_object_set_new(objcontent_j, "description", json_string((const char *) ((oph_json_obj_grid *) json->response[i].objcontent)[j].description))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}
					// ROWKEYS & ROWFIELDTYPES
					if (((oph_json_obj_grid *) json->response[i].objcontent)[j].keys_num != ((oph_json_obj_grid *) json->response[i].objcontent)[j].fieldtypes_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "keys/fieldtypes num");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					unsigned int k;
					json_t *rowkeys = json_array();
					if (!rowkeys) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowkeys");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rowkeys", rowkeys)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowkeys");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					json_t *rowfieldtypes = json_array();
					if (!rowfieldtypes) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowfieldtypes");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rowfieldtypes", rowfieldtypes)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowfieldtypes");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_grid *) json->response[i].objcontent)[j].keys_num; k++) {
						if (json_array_append_new(rowkeys, json_string((const char *) ((oph_json_obj_grid *) json->response[i].objcontent)[j].keys[k]))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowkey");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(rowfieldtypes, json_string((const char *) ((oph_json_obj_grid *) json->response[i].objcontent)[j].fieldtypes[k]))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowfieldtype");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}

					// ROWVALUES
					if (((oph_json_obj_grid *) json->response[i].objcontent)[j].values_num2 != ((oph_json_obj_grid *) json->response[i].objcontent)[j].keys_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "values_num2");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *rowvalues = json_array();
					if (!rowvalues) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rowvalues", rowvalues)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_grid *) json->response[i].objcontent)[j].values_num1; k++) {
						json_t *rowvalues_k = json_array();
						if (!rowvalues_k) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(rowvalues, rowvalues_k)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						unsigned int q;
						for (q = 0; q < ((oph_json_obj_grid *) json->response[i].objcontent)[j].values_num2; q++) {
							if (json_array_append_new(rowvalues_k, json_string((const char *) ((oph_json_obj_grid *) json->response[i].objcontent)[j].values[k][q]))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalue_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
						}
					}
				}
			} else if (!strcmp(json->response[i].objclass, OPH_JSON_MULTIGRID)) {
				/* ADD MULTIGRID */
				for (j = 0; j < json->response[i].objcontent_num; j++) {
					json_t *objcontent_j = json_object();
					if (!objcontent_j) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_array_append_new(objcontent, objcontent_j)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// TITLE
					if (!((oph_json_obj_multigrid *) json->response[i].objcontent)[j].title) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "title", json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].title))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// DESCRIPTION
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].description) {
						if (json_object_set_new
						    (objcontent_j, "description", json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].description))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}
					// MEASURENAME
					if (!((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurename) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "measurename");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "measurename", json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurename))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measurename");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// MEASURETYPE
					if (!((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measuretype) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "measuretype");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "measuretype", json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measuretype))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measuretype");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// ROWKEYS & ROWFIELDTYPES
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowkeys_num != ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowfieldtypes_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "rowkeys/rowfieldtypes num");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					unsigned int k;
					json_t *rowkeys = json_array();
					if (!rowkeys) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowkeys");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rowkeys", rowkeys)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowkeys");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					json_t *rowfieldtypes = json_array();
					if (!rowfieldtypes) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowfieldtypes");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rowfieldtypes", rowfieldtypes)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowfieldtypes");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowkeys_num; k++) {
						if (json_array_append_new(rowkeys, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowkeys[k]))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowkey");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(rowfieldtypes, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowfieldtypes[k]))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowfieldtype");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}

					// ROWVALUES
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowvalues_num2 != ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowkeys_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "rowvalues_num2");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *rowvalues = json_array();
					if (!rowvalues) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rowvalues", rowvalues)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowvalues_num1; k++) {
						json_t *rowvalues_k = json_array();
						if (!rowvalues_k) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(rowvalues, rowvalues_k)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						unsigned int q;
						for (q = 0; q < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowvalues_num2; q++) {
							if (json_array_append_new
							    (rowvalues_k, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowvalues[k][q]))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rowvalue_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
						}
					}

					// COLKEYS & COLFIELDTYPES
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colkeys_num != ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colfieldtypes_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "colkeys/colfieldtypes num");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *colkeys = json_array();
					if (!colkeys) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colkeys");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "colkeys", colkeys)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colkeys");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					json_t *colfieldtypes = json_array();
					if (!colfieldtypes) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colfieldtypes");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "colfieldtypes", colfieldtypes)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colfieldtypes");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colkeys_num; k++) {
						if (json_array_append_new(colkeys, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colkeys[k]))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colkey");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(colfieldtypes, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colfieldtypes[k]))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colfieldtype");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}

					// COLVALUES
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colvalues_num2 != ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colkeys_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "colvalues_num2");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *colvalues = json_array();
					if (!colvalues) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colvalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "colvalues", colvalues)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colvalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colvalues_num1; k++) {
						json_t *colvalues_k = json_array();
						if (!colvalues_k) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colvalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(colvalues, colvalues_k)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colvalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						unsigned int q;
						for (q = 0; q < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colvalues_num2; q++) {
							if (json_array_append_new
							    (colvalues_k, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colvalues[k][q]))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "colvalue_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
						}
					}

					// MEASUREVALUES
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurevalues_num2 !=
					    ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].colvalues_num1) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "measurevalues_num2");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurevalues_num1 !=
					    ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].rowvalues_num1) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "measurevalues_num1");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *measurevalues = json_array();
					if (!measurevalues) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measurevalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "measurevalues", measurevalues)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measurevalues");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					for (k = 0; k < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurevalues_num1; k++) {
						json_t *measurevalues_k = json_array();
						if (!measurevalues_k) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measurevalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(measurevalues, measurevalues_k)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measurevalues_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						unsigned int q;
						for (q = 0; q < ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurevalues_num2; q++) {
							if (json_array_append_new
							    (measurevalues_k, json_string((const char *) ((oph_json_obj_multigrid *) json->response[i].objcontent)[j].measurevalues[k][q]))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "measurevalue_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
						}
					}
				}
			} else if (!strcmp(json->response[i].objclass, OPH_JSON_TREE)) {
				/* ADD TREE */
				for (j = 0; j < json->response[i].objcontent_num; j++) {
					json_t *objcontent_j = json_object();
					if (!objcontent_j) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_array_append_new(objcontent, objcontent_j)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// TITLE
					if (!((oph_json_obj_tree *) json->response[i].objcontent)[j].title) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "title", json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].title))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// DESCRIPTION
					if (((oph_json_obj_tree *) json->response[i].objcontent)[j].description) {
						if (json_object_set_new(objcontent_j, "description", json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].description))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}
					// ROOTNODE
					if (!((oph_json_obj_tree *) json->response[i].objcontent)[j].rootnode) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "rootnode");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "rootnode", json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].rootnode))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "rootnode");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// NODEKEYS
					if (((oph_json_obj_tree *) json->response[i].objcontent)[j].nodekeys_num != 0) {
						if (((oph_json_obj_tree *) json->response[i].objcontent)[j].nodevalues_num2 != ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodekeys_num) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "nodevalues_num2");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_BAD_PARAM_ERROR;
						}
						unsigned int k;
						json_t *nodekeys = json_array();
						if (!nodekeys) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodekeys");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_object_set_new(objcontent_j, "nodekeys", nodekeys)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodekeys");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						for (k = 0; k < ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodekeys_num; k++) {
							if (json_array_append_new(nodekeys, json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodekeys[k]))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodekey");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
						}

						// NODEVALUES
						json_t *nodevalues = json_array();
						if (!nodevalues) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_object_set_new(objcontent_j, "nodevalues", nodevalues)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						for (k = 0; k < ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodevalues_num1; k++) {
							json_t *nodevalues_k = json_array();
							if (!nodevalues_k) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							if (json_array_append_new(nodevalues, nodevalues_k)) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							unsigned int q;
							for (q = 0; q < ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodevalues_num2; q++) {
								if (json_array_append_new
								    (nodevalues_k, json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodevalues[k][q]))) {
									pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalue_k");
									if (oph_json)
										json_decref(oph_json);
									return OPH_JSON_MEMORY_ERROR;
								}
							}
						}
					}
					// NODELINKS
					if (((oph_json_obj_tree *) json->response[i].objcontent)[j].nodevalues_num1 != 0
					    && ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodevalues_num1 != ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "nodevalues_num1/nodelinks_num");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *nodelinks = json_array();
					if (!nodelinks) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "nodelinks", nodelinks)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					unsigned int k;
					for (k = 0; k < ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks_num; k++) {
						json_t *nodelinks_k = json_array();
						if (!nodelinks_k) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(nodelinks, nodelinks_k)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						unsigned int q;
						for (q = 0; q < ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks[k].links_num; q++) {
							json_t *nodelinks_kq = json_object();
							if (!nodelinks_kq) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_kq");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							if (json_array_append_new(nodelinks_k, nodelinks_kq)) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_kq");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							// NODE
							if (!((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks[k].links[q].node) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "node");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_BAD_PARAM_ERROR;
							}
							if (json_object_set_new
							    (nodelinks_kq, "node", json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks[k].links[q].node))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "node");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							// DESCRIPTION
							if (((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks[k].links[q].description) {
								if (json_object_set_new
								    (nodelinks_kq, "description",
								     json_string((const char *) ((oph_json_obj_tree *) json->response[i].objcontent)[j].nodelinks[k].links[q].description))) {
									pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
									if (oph_json)
										json_decref(oph_json);
									return OPH_JSON_MEMORY_ERROR;
								}
							}
						}
					}
				}
			} else if (!strcmp(json->response[i].objclass, OPH_JSON_DGRAPH) || !strcmp(json->response[i].objclass, OPH_JSON_GRAPH)) {
				/* ADD (DI)GRAPH */
				for (j = 0; j < json->response[i].objcontent_num; j++) {
					json_t *objcontent_j = json_object();
					if (!objcontent_j) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_array_append_new(objcontent, objcontent_j)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "objcontent_j");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// TITLE
					if (!((oph_json_obj_graph *) json->response[i].objcontent)[j].title) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					if (json_object_set_new(objcontent_j, "title", json_string((const char *) ((oph_json_obj_graph *) json->response[i].objcontent)[j].title))) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "title");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					// DESCRIPTION
					if (((oph_json_obj_graph *) json->response[i].objcontent)[j].description) {
						if (json_object_set_new(objcontent_j, "description", json_string((const char *) ((oph_json_obj_graph *) json->response[i].objcontent)[j].description))) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
					}
					// NODEKEYS
					if (((oph_json_obj_graph *) json->response[i].objcontent)[j].nodekeys_num != 0) {
						if (((oph_json_obj_graph *) json->response[i].objcontent)[j].nodevalues_num2 != ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodekeys_num) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "nodevalues_num2");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_BAD_PARAM_ERROR;
						}
						unsigned int k;
						json_t *nodekeys = json_array();
						if (!nodekeys) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodekeys");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_object_set_new(objcontent_j, "nodekeys", nodekeys)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodekeys");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						for (k = 0; k < ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodekeys_num; k++) {
							if (json_array_append_new(nodekeys, json_string((const char *) ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodekeys[k]))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodekey");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
						}

						// NODEVALUES
						json_t *nodevalues = json_array();
						if (!nodevalues) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_object_set_new(objcontent_j, "nodevalues", nodevalues)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						for (k = 0; k < ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodevalues_num1; k++) {
							json_t *nodevalues_k = json_array();
							if (!nodevalues_k) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							if (json_array_append_new(nodevalues, nodevalues_k)) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalues_k");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							unsigned int q;
							for (q = 0; q < ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodevalues_num2; q++) {
								if (json_array_append_new
								    (nodevalues_k, json_string((const char *) ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodevalues[k][q]))) {
									pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodevalue_k");
									if (oph_json)
										json_decref(oph_json);
									return OPH_JSON_MEMORY_ERROR;
								}
							}
						}
					}
					// NODELINKS
					if (((oph_json_obj_graph *) json->response[i].objcontent)[j].nodevalues_num1 != 0
					    && ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodevalues_num1 != ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks_num) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "nodevalues_num1/nodelinks_num");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_BAD_PARAM_ERROR;
					}
					json_t *nodelinks = json_array();
					if (!nodelinks) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					if (json_object_set_new(objcontent_j, "nodelinks", nodelinks)) {
						pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks");
						if (oph_json)
							json_decref(oph_json);
						return OPH_JSON_MEMORY_ERROR;
					}
					unsigned int k;
					for (k = 0; k < ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks_num; k++) {
						json_t *nodelinks_k = json_array();
						if (!nodelinks_k) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						if (json_array_append_new(nodelinks, nodelinks_k)) {
							pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_k");
							if (oph_json)
								json_decref(oph_json);
							return OPH_JSON_MEMORY_ERROR;
						}
						unsigned int q;
						for (q = 0; q < ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks[k].links_num; q++) {
							json_t *nodelinks_kq = json_object();
							if (!nodelinks_kq) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_kq");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							if (json_array_append_new(nodelinks_k, nodelinks_kq)) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "nodelinks_kq");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							// NODE
							if (!((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks[k].links[q].node) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "node");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_BAD_PARAM_ERROR;
							}
							if (json_object_set_new
							    (nodelinks_kq, "node", json_string((const char *) ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks[k].links[q].node))) {
								pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "node");
								if (oph_json)
									json_decref(oph_json);
								return OPH_JSON_MEMORY_ERROR;
							}
							// DESCRIPTION
							if (((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks[k].links[q].description) {
								if (json_object_set_new
								    (nodelinks_kq, "description",
								     json_string((const char *) ((oph_json_obj_graph *) json->response[i].objcontent)[j].nodelinks[k].links[q].description))) {
									pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
									if (oph_json)
										json_decref(oph_json);
									return OPH_JSON_MEMORY_ERROR;
								}
							}
						}
					}
				}
			} else {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "objclass");
				if (oph_json)
					json_decref(oph_json);
				return OPH_JSON_BAD_PARAM_ERROR;
			}
		}
	}

	*jstring = json_dumps((const json_t *) oph_json, JSON_INDENT(4));
	if (!(*jstring)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "jstring");
		if (oph_json)
			json_decref(oph_json);
		return OPH_JSON_MEMORY_ERROR;
	}

	/* CLEANUP */
	if (oph_json)
		json_decref(oph_json);

	return OPH_JSON_SUCCESS;
}

int oph_json_to_json_string(oph_json * json, char **jstring)
{
	return _oph_json_to_json_string(json, jstring, &global_flag);
}

int oph_json_to_json_string_unsafe(oph_json * json, char **jstring)
{
	return _oph_json_to_json_string(json, jstring, NULL);
}

int __oph_json_to_json_file(oph_json * json, char *filename, char **jstring, pthread_mutex_t * flag)
{
	*jstring = NULL;

	if (_oph_json_to_json_string(json, jstring, flag)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "json string");
		return OPH_JSON_MEMORY_ERROR;
	}

	if (*jstring) {
		pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Opening '%s'\n", filename);
		FILE *fp = fopen(filename, "w");
		if (!fp) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_IO_ERROR, filename);
			free(*jstring);
			*jstring = NULL;
			return OPH_JSON_IO_ERROR;
		}
		fprintf(fp, "%s\n", *jstring);
		fclose(fp);
	}

	return OPH_JSON_SUCCESS;
}

int _oph_json_to_json_file(oph_json * json, char *filename, pthread_mutex_t * flag)
{
	char *jstring = NULL;
	int res = __oph_json_to_json_file(json, filename, &jstring, flag);
	if (jstring)
		free(jstring);
	return res;
}

int oph_json_to_json_file(oph_json * json, char *filename)
{
	return _oph_json_to_json_file(json, filename, &global_flag);
}

int oph_json_to_json_file_unsafe(oph_json * json, char *filename)
{
	return _oph_json_to_json_file(json, filename, NULL);
}

int _oph_write_json(oph_json * oper_json, pthread_mutex_t * flag)
{
	if (!oper_json)
		return OPH_JSON_BAD_PARAM_ERROR;

	if (!strcmp(oper_json->source->values[2], "0")) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_WRITE_ERROR);
		return OPH_JSON_GENERIC_ERROR;
	}

	char filename[OPH_MAX_STRING_SIZE];
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_JSON_RESPONSE_FILENAME, oph_json_location, oper_json->source->values[0], oper_json->source->values[2]);

	if (_oph_json_to_json_file(oper_json, filename, flag)) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "JSON file creation failed.\n");
		return OPH_JSON_IO_ERROR;
	}

	return OPH_JSON_SUCCESS;
}

int oph_write_json(oph_json * oper_json)
{
	return _oph_write_json(oper_json, &global_flag);
}

int oph_write_json_unsafe(oph_json * oper_json)
{
	return _oph_write_json(oper_json, NULL);
}

int _oph_write_and_get_json(oph_json * oper_json, char **jstring, pthread_mutex_t * flag)
{
	if (!oper_json || !jstring)
		return OPH_JSON_BAD_PARAM_ERROR;

	if (!strcmp(oper_json->source->values[2], "0"))	// Do not save
	{
		pmesg_safe(flag, LOG_WARNING, __FILE__, __LINE__, OPH_JSON_LOG_WRITE_ERROR);
		if (_oph_json_to_json_string(oper_json, jstring, flag)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "json string");
			return OPH_JSON_MEMORY_ERROR;
		}
	} else {
		char filename[OPH_MAX_STRING_SIZE];
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_JSON_RESPONSE_FILENAME, oph_json_location, oper_json->source->values[0], oper_json->source->values[2]);

		if (__oph_json_to_json_file(oper_json, filename, jstring, flag)) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "JSON file creation failed.\n");
			return OPH_JSON_IO_ERROR;
		}
	}

	return OPH_JSON_SUCCESS;
}

int oph_write_and_get_json(oph_json * oper_json, char **jstring)
{
	return _oph_write_and_get_json(oper_json, jstring, &global_flag);
}

int oph_write_and_get_json_unsafe(oph_json * oper_json, char **jstring)
{
	return _oph_write_and_get_json(oper_json, jstring, NULL);
}

/***********OPH_JSON INTERNAL FUNCTIONS***********/

// Check if measure type does exist
int oph_json_is_measuretype_correct(const char *measuretype)
{
	int res;
	if (!strcmp(measuretype, OPH_JSON_INT))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_LONG))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_SHORT))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_BYTE))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_FLOAT))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_DOUBLE))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_STRING))
		res = 1;
	else if (!strcmp(measuretype, OPH_JSON_BLOB))
		res = 1;
	else
		res = 0;
	return res;
}

// Check if type does exist
int oph_json_is_type_correct(const char *type)
{
	int res;
	if (!strcmp(type, OPH_JSON_INT))
		res = 1;
	else if (!strcmp(type, OPH_JSON_LONG))
		res = 1;
	else if (!strcmp(type, OPH_JSON_SHORT))
		res = 1;
	else if (!strcmp(type, OPH_JSON_BYTE))
		res = 1;
	else if (!strcmp(type, OPH_JSON_FLOAT))
		res = 1;
	else if (!strcmp(type, OPH_JSON_DOUBLE))
		res = 1;
	else if (!strcmp(type, OPH_JSON_STRING))
		res = 1;
	else if (!strcmp(type, OPH_JSON_BLOB))
		res = 1;
	else
		res = 0;
	return res;
}

// Add an objkey to the responseKeyset if new
int _oph_json_add_responseKey(oph_json * json, const char *responseKey, pthread_mutex_t * flag)
{
	if (!json || !responseKey) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->responseKeyset_num == 0) {
		json->responseKeyset = (char **) malloc(sizeof(char *));
		if (!json->responseKeyset) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKeyset");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->responseKeyset[0] = (char *) strdup(responseKey);
		if (!json->responseKeyset[0]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKey");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->responseKeyset_num++;
	} else {
		unsigned int i;
		for (i = 0; i < json->responseKeyset_num; i++) {
			if (!strcmp(json->responseKeyset[i], responseKey)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "responseKey");
				return OPH_JSON_BAD_PARAM_ERROR;
			}
		}
		char **tmp = json->responseKeyset;
		json->responseKeyset = (char **) realloc(json->responseKeyset, sizeof(char *) * (json->responseKeyset_num + 1));
		if (!json->responseKeyset) {
			json->responseKeyset = tmp;
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKeyset");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->responseKeyset[json->responseKeyset_num] = (char *) strdup(responseKey);
		if (!json->responseKeyset[json->responseKeyset_num]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "responseKey");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->responseKeyset_num++;
	}
	return OPH_JSON_SUCCESS;
}

int oph_json_add_responseKey(oph_json * json, const char *responseKey)
{
	return _oph_json_add_responseKey(json, responseKey, &global_flag);
}

int oph_json_add_responseKey_unsafe(oph_json * json, const char *responseKey)
{
	return _oph_json_add_responseKey(json, responseKey, NULL);
}

// Free consumers
int _oph_json_free_consumers(oph_json * json, pthread_mutex_t * flag)
{
	if (!json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->consumers) {
		unsigned int i;
		for (i = 0; i < json->consumers_num; i++) {
			if (json->consumers[i]) {
				free(json->consumers[i]);
				json->consumers[i] = NULL;
			}
		}
		free(json->consumers);
		json->consumers = NULL;
	}
	json->consumers_num = 0;
	return OPH_JSON_SUCCESS;
}

int oph_json_free_consumers(oph_json * json)
{
	return _oph_json_free_consumers(json, &global_flag);
}

int oph_json_free_consumers_unsafe(oph_json * json)
{
	return _oph_json_free_consumers(json, NULL);
}

// Free responseKeyset
int _oph_json_free_responseKeyset(oph_json * json, pthread_mutex_t * flag)
{
	if (!json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->responseKeyset) {
		unsigned int i;
		for (i = 0; i < json->responseKeyset_num; i++) {
			if (json->responseKeyset[i]) {
				free(json->responseKeyset[i]);
				json->responseKeyset[i] = NULL;
			}
		}
		free(json->responseKeyset);
		json->responseKeyset = NULL;
	}
	json->responseKeyset_num = 0;
	return OPH_JSON_SUCCESS;
}

int oph_json_free_responseKeyset(oph_json * json)
{
	return _oph_json_free_responseKeyset(json, &global_flag);
}

int oph_json_free_responseKeyset_unsafe(oph_json * json)
{
	return _oph_json_free_responseKeyset(json, NULL);
}

// Free source
int _oph_json_free_source(oph_json * json, pthread_mutex_t * flag)
{
	if (!json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->source) {
		if (json->source->description) {
			free(json->source->description);
			json->source->description = NULL;
		}
		if (json->source->keys) {
			unsigned int i;
			for (i = 0; i < json->source->keys_num; i++) {
				if (json->source->keys[i]) {
					free(json->source->keys[i]);
					json->source->keys[i] = NULL;
				}
			}
			free(json->source->keys);
			json->source->keys = NULL;
		}
		json->source->keys_num = 0;
		if (json->source->producer) {
			free(json->source->producer);
			json->source->producer = NULL;
		}
		if (json->source->srckey) {
			free(json->source->srckey);
			json->source->srckey = NULL;
		}
		if (json->source->srcname) {
			free(json->source->srcname);
			json->source->srcname = NULL;
		}
		if (json->source->srcurl) {
			free(json->source->srcurl);
			json->source->srcurl = NULL;
		}
		if (json->source->values) {
			unsigned int i;
			for (i = 0; i < json->source->values_num; i++) {
				if (json->source->values[i]) {
					free(json->source->values[i]);
					json->source->values[i] = NULL;
				}
			}
			free(json->source->values);
			json->source->values = NULL;
		}
		json->source->values_num = 0;

		free(json->source);
		json->source = NULL;
	}
	return OPH_JSON_SUCCESS;
}

int oph_json_free_source(oph_json * json)
{
	return _oph_json_free_source(json, &global_flag);
}

int oph_json_free_source_unsafe(oph_json * json)
{
	return _oph_json_free_source(json, NULL);
}

// Free extra
int _oph_json_free_extra(oph_json * json, pthread_mutex_t * flag)
{
	if (!json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->extra) {
		if (json->extra->keys) {
			unsigned int i;
			for (i = 0; i < json->extra->keys_num; i++) {
				if (json->extra->keys[i]) {
					free(json->extra->keys[i]);
					json->extra->keys[i] = NULL;
				}
			}
			free(json->extra->keys);
			json->extra->keys = NULL;
		}
		json->extra->keys_num = 0;
		if (json->extra->values) {
			unsigned int i;
			for (i = 0; i < json->extra->values_num; i++) {
				if (json->extra->values[i]) {
					free(json->extra->values[i]);
					json->extra->values[i] = NULL;
				}
			}
			free(json->extra->values);
			json->extra->values = NULL;
		}
		json->extra->values_num = 0;

		free(json->extra);
		json->extra = NULL;
	}
	return OPH_JSON_SUCCESS;
}

int oph_json_free_extra(oph_json * json)
{
	return _oph_json_free_extra(json, &global_flag);
}

int oph_json_free_extra_unsafe(oph_json * json)
{
	return _oph_json_free_extra(json, NULL);
}

// Free response
int _oph_json_free_response(oph_json * json, pthread_mutex_t * flag)
{
	if (!json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->response) {
		unsigned int i;
		for (i = 0; i < json->response_num; i++) {
			if (json->response[i].objkey) {
				free(json->response[i].objkey);
				json->response[i].objkey = NULL;
			}
			if (json->response[i].objcontent) {
				unsigned int j;
				if (!strcmp(json->response[i].objclass, OPH_JSON_TEXT)) {
					for (j = 0; j < json->response[i].objcontent_num; j++) {
						oph_json_free_text(&((oph_json_obj_text *) json->response[i].objcontent)[j]);
					}
				} else if (!strcmp(json->response[i].objclass, OPH_JSON_GRID)) {
					for (j = 0; j < json->response[i].objcontent_num; j++) {
						oph_json_free_grid((&((oph_json_obj_grid *) json->response[i].objcontent)[j]));
					}
				} else if (!strcmp(json->response[i].objclass, OPH_JSON_MULTIGRID)) {
					for (j = 0; j < json->response[i].objcontent_num; j++) {
						oph_json_free_multigrid((&((oph_json_obj_multigrid *) json->response[i].objcontent)[j]));
					}
				} else if (!strcmp(json->response[i].objclass, OPH_JSON_TREE)) {
					for (j = 0; j < json->response[i].objcontent_num; j++) {
						oph_json_free_tree((&((oph_json_obj_tree *) json->response[i].objcontent)[j]));
					}
				} else if (!strcmp(json->response[i].objclass, OPH_JSON_DGRAPH) || !strcmp(json->response[i].objclass, OPH_JSON_GRAPH)) {
					for (j = 0; j < json->response[i].objcontent_num; j++) {
						oph_json_free_graph((&((oph_json_obj_graph *) json->response[i].objcontent)[j]));
					}
				}
				free(json->response[i].objcontent);
				json->response[i].objcontent = NULL;
			}
			json->response[i].objcontent_num = 0;
			if (json->response[i].objclass) {
				free(json->response[i].objclass);
				json->response[i].objclass = NULL;
			}
		}
		free(json->response);
		json->response = NULL;
	}
	json->response_num = 0;
	return OPH_JSON_SUCCESS;
}

int oph_json_free_response(oph_json * json)
{
	return _oph_json_free_response(json, &global_flag);
}

int oph_json_free_response_unsafe(oph_json * json)
{
	return _oph_json_free_response(json, NULL);
}

/***********OPH_JSON FUNCTIONS***********/

int _oph_json_alloc(oph_json ** json, pthread_mutex_t * flag)
{
	*json = (oph_json *) malloc(sizeof(oph_json));
	if (!*json) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "oph_json");
		return OPH_JSON_MEMORY_ERROR;
	}
	(*json)->consumers = NULL;
	(*json)->consumers_num = 0;
	(*json)->response = NULL;
	(*json)->responseKeyset = NULL;
	(*json)->responseKeyset_num = 0;
	(*json)->response_num = 0;
	(*json)->source = NULL;
	(*json)->extra = NULL;
	return OPH_JSON_SUCCESS;
}

int oph_json_alloc(oph_json ** json)
{
	return _oph_json_alloc(json, &global_flag);
}

int oph_json_alloc_unsafe(oph_json ** json)
{
	return _oph_json_alloc(json, NULL);
}

int _oph_json_free(oph_json * json, pthread_mutex_t * flag)
{
	if (json) {
		_oph_json_free_consumers(json, flag);
		_oph_json_free_response(json, flag);
		_oph_json_free_responseKeyset(json, flag);
		_oph_json_free_source(json, flag);
		_oph_json_free_extra(json, flag);
		free(json);
		json = NULL;
	}
	return OPH_JSON_SUCCESS;
}

int oph_json_free(oph_json * json)
{
	return _oph_json_free(json, &global_flag);
}

int oph_json_free_unsafe(oph_json * json)
{
	return _oph_json_free(json, NULL);
}

int _oph_json_add_consumer(oph_json * json, const char *consumer, pthread_mutex_t * flag)
{
	if (!json || !consumer) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->consumers_num == 0) {
		json->consumers = (char **) malloc(sizeof(char *));
		if (!json->consumers) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumers");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->consumers[0] = (char *) strdup(consumer);
		if (!json->consumers[0]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumer");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->consumers_num++;
	} else {
		unsigned int i;
		for (i = 0; i < json->consumers_num; i++) {
			if (!strcmp(json->consumers[i], consumer)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "consumer");
				return OPH_JSON_BAD_PARAM_ERROR;
			}
		}
		char **tmp = json->consumers;
		json->consumers = (char **) realloc(json->consumers, sizeof(char *) * (json->consumers_num + 1));
		if (!json->consumers) {
			json->consumers = tmp;
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumers");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->consumers[json->consumers_num] = (char *) strdup(consumer);
		if (!json->consumers[json->consumers_num]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "consumer");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->consumers_num++;
	}
	return OPH_JSON_SUCCESS;
}

int oph_json_add_consumer(oph_json * json, const char *consumer)
{
	return _oph_json_add_consumer(json, consumer, &global_flag);
}

int oph_json_add_consumer_unsafe(oph_json * json, const char *consumer)
{
	return _oph_json_add_consumer(json, consumer, NULL);
}

int _oph_json_set_source(oph_json * json, const char *srckey, const char *srcname, const char *srcurl, const char *description, const char *producer, pthread_mutex_t * flag)
{
	if (!json || !srckey || !srcname) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	if (json->source) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "source");
		return OPH_JSON_BAD_PARAM_ERROR;
	}
	json->source = (oph_json_source *) malloc(sizeof(oph_json_source));
	if (!json->source) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "source");
		return OPH_JSON_MEMORY_ERROR;
	}
	json->source->description = NULL;
	json->source->keys = NULL;
	json->source->keys_num = 0;
	json->source->producer = NULL;
	json->source->srckey = NULL;
	json->source->srcname = NULL;
	json->source->srcurl = NULL;
	json->source->values = NULL;
	json->source->values_num = 0;

	json->source->srckey = (char *) strdup(srckey);
	if (!json->source->srckey) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "srckey");
		return OPH_JSON_MEMORY_ERROR;
	}
	json->source->srcname = (char *) strdup(srcname);
	if (!json->source->srcname) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "srcname");
		return OPH_JSON_MEMORY_ERROR;
	}

	if (srcurl) {
		json->source->srcurl = (char *) strdup(srcurl);
		if (!json->source->srcurl) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "srcurl");
			return OPH_JSON_MEMORY_ERROR;
		}
	}
	if (description) {
		json->source->description = (char *) strdup(description);
		if (!json->source->description) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "description");
			return OPH_JSON_MEMORY_ERROR;
		}
	}
	if (producer) {
		json->source->producer = (char *) strdup(producer);
		if (!json->source->producer) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "producer");
			return OPH_JSON_MEMORY_ERROR;
		}
	}

	return OPH_JSON_SUCCESS;
}

int oph_json_set_source(oph_json * json, const char *srckey, const char *srcname, const char *srcurl, const char *description, const char *producer)
{
	return _oph_json_set_source(json, srckey, srcname, srcurl, description, producer, &global_flag);
}

int oph_json_set_source_unsafe(oph_json * json, const char *srckey, const char *srcname, const char *srcurl, const char *description, const char *producer)
{
	return _oph_json_set_source(json, srckey, srcname, srcurl, description, producer, NULL);
}

int _oph_json_add_source_detail(oph_json * json, const char *key, const char *value, pthread_mutex_t * flag)
{
	if (!json || !key || !value) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}

	if (!json->source) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "source");
		return OPH_JSON_BAD_PARAM_ERROR;
	}

	if (json->source->keys_num == 0) {
		json->source->keys = (char **) malloc(sizeof(char *));
		if (!json->source->keys) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->keys[0] = (char *) strdup(key);
		if (!json->source->keys[0]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "key");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->keys_num++;
		json->source->values = (char **) malloc(sizeof(char *));
		if (!json->source->values) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->values[0] = (char *) strdup(value);
		if (!json->source->values[0]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "value");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->values_num++;
	} else {
		unsigned int i;
		for (i = 0; i < json->source->keys_num; i++) {
			if (!strcmp(json->source->keys[i], key)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "key");
				return OPH_JSON_BAD_PARAM_ERROR;
			}
		}
		char **tmp = json->source->keys;
		json->source->keys = (char **) realloc(json->source->keys, sizeof(char *) * (json->source->keys_num + 1));
		if (!json->source->keys) {
			json->source->keys = tmp;
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->keys[json->source->keys_num] = (char *) strdup(key);
		if (!json->source->keys[json->source->keys_num]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "key");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->keys_num++;
		char **tmp2 = json->source->values;
		json->source->values = (char **) realloc(json->source->values, sizeof(char *) * (json->source->values_num + 1));
		if (!json->source->values) {
			json->source->values = tmp2;
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->values[json->source->values_num] = (char *) strdup(value);
		if (!json->source->values[json->source->values_num]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "value");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->source->values_num++;
	}

	return OPH_JSON_SUCCESS;
}

int oph_json_add_source_detail(oph_json * json, const char *key, const char *value)
{
	return _oph_json_add_source_detail(json, key, value, &global_flag);
}

int oph_json_add_source_detail_unsafe(oph_json * json, const char *key, const char *value)
{
	return _oph_json_add_source_detail(json, key, value, NULL);
}

int _oph_json_add_extra_detail(oph_json * json, const char *key, const char *value, pthread_mutex_t * flag)
{
	if (!json || !key || !value) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "(NULL parameters)");
		return OPH_JSON_BAD_PARAM_ERROR;
	}

	if (!json->extra) {
		json->extra = (oph_json_extra *) malloc(sizeof(oph_json_extra));
		if (!json->extra) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "extra");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->keys = NULL;
		json->extra->keys_num = 0;
		json->extra->values = NULL;
		json->extra->values_num = 0;
	}

	if (json->extra->keys_num == 0) {
		json->extra->keys = (char **) malloc(sizeof(char *));
		if (!json->extra->keys) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->keys[0] = (char *) strdup(key);
		if (!json->extra->keys[0]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "key");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->keys_num++;
		json->extra->values = (char **) malloc(sizeof(char *));
		if (!json->extra->values) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->values[0] = (char *) strdup(value);
		if (!json->extra->values[0]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "value");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->values_num++;
	} else {
		unsigned int i;
		for (i = 0; i < json->extra->keys_num; i++) {
			if (!strcmp(json->extra->keys[i], key)) {
				pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_BAD_PARAM_ERROR, "key");
				return OPH_JSON_BAD_PARAM_ERROR;
			}
		}
		char **tmp = json->extra->keys;
		json->extra->keys = (char **) realloc(json->extra->keys, sizeof(char *) * (json->extra->keys_num + 1));
		if (!json->extra->keys) {
			json->extra->keys = tmp;
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "keys");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->keys[json->extra->keys_num] = (char *) strdup(key);
		if (!json->extra->keys[json->extra->keys_num]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "key");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->keys_num++;
		char **tmp2 = json->extra->values;
		json->extra->values = (char **) realloc(json->extra->values, sizeof(char *) * (json->extra->values_num + 1));
		if (!json->extra->values) {
			json->extra->values = tmp2;
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "values");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->values[json->extra->values_num] = (char *) strdup(value);
		if (!json->extra->values[json->extra->values_num]) {
			pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, OPH_JSON_LOG_MEMORY_ERROR, "value");
			return OPH_JSON_MEMORY_ERROR;
		}
		json->extra->values_num++;
	}

	return OPH_JSON_SUCCESS;
}

int oph_json_add_extra_detail(oph_json * json, const char *key, const char *value)
{
	return _oph_json_add_extra_detail(json, key, value, NULL);
}

int oph_json_add_extra_detail_unsafe(oph_json * json, const char *key, const char *value)
{
	return _oph_json_add_extra_detail(json, key, value, NULL);
}

int oph_json_is_objkey_printable(char **objkeys, int objkeys_num, const char *objkey)
{
	if (objkeys_num < 1 || !objkeys || !objkey)
		return 1;
	if (!strcmp(objkeys[0], "all"))
		return 1;
	if (!strcmp(objkeys[0], "none"))
		return 0;
	int i;
	for (i = 0; i < objkeys_num; i++) {
		if (!strcmp(objkeys[i], objkey))
			return 1;
	}
	return 0;
}

int _oph_json_from_json_string(oph_json ** json, const char *jstring, pthread_mutex_t * flag)
{
	if (!jstring || !json)
		return OPH_JSON_BAD_PARAM_ERROR;
	*json = NULL;

	// ALLOC OPH_JSON
	if (_oph_json_alloc(json, flag))
		return OPH_JSON_MEMORY_ERROR;

	/* LOAD JSON_T */
	json_t *jansson = json_loads(jstring, 0, NULL);
	if (!jansson) {
		return OPH_JSON_GENERIC_ERROR;
	}

	json_t *source = NULL;
	json_t *extra = NULL;
	json_t *consumers = NULL;
	json_t *response = NULL;

	//GET SOURCE DATA FROM JSON_T
	json_unpack(jansson, "{s?o}", "source", &source);
	if (source) {
		char *srckey = NULL, *srcname = NULL, *srcurl = NULL, *description = NULL, *producer = NULL;
		json_unpack(source, "{s?s,s?s,s?s,s?s,s?s}", "srckey", &srckey, "srcname", &srcname, "srcurl", &srcurl, "description", &description, "producer", &producer);

		if (_oph_json_set_source(*json, (const char *) srckey, (const char *) srcname, (const char *) srcurl, (const char *) description, (const char *) producer, flag)) {
			if (jansson)
				json_decref(jansson);
			return OPH_JSON_GENERIC_ERROR;
		}

		json_t *keys = NULL;
		json_t *values = NULL;
		json_unpack(source, "{s?o,s?o}", "keys", &keys, "values", &values);

		if (keys && values) {
			char *key = NULL, *value = NULL;
			size_t index;
			for (index = 0; index < json_array_size(keys); index++) {
				json_unpack(json_array_get(keys, index), "s", &key);
				json_unpack(json_array_get(values, index), "s", &value);

				if (_oph_json_add_source_detail(*json, (const char *) key, (const char *) value, flag)) {
					if (jansson)
						json_decref(jansson);
					return OPH_JSON_GENERIC_ERROR;
				}
			}
		} else if ((keys && !values) || (!keys && values)) {
			if (jansson)
				json_decref(jansson);
			return OPH_JSON_GENERIC_ERROR;
		}
	}
	//GET EXTRA DATA FROM JSON_T
	json_unpack(jansson, "{s?o}", "extra", &extra);
	if (extra) {
		json_t *keys = NULL;
		json_t *values = NULL;
		json_unpack(extra, "{s?o,s?o}", "keys", &keys, "values", &values);

		if (keys && values) {
			char *key = NULL, *value = NULL;
			size_t index;
			for (index = 0; index < json_array_size(keys); index++) {
				json_unpack(json_array_get(keys, index), "s", &key);
				json_unpack(json_array_get(values, index), "s", &value);

				if (_oph_json_add_extra_detail(*json, (const char *) key, (const char *) value, flag)) {
					if (jansson)
						json_decref(jansson);
					return OPH_JSON_GENERIC_ERROR;
				}
			}
		} else if ((keys && !values) || (!keys && values)) {
			if (jansson)
				json_decref(jansson);
			return OPH_JSON_GENERIC_ERROR;
		}
	}
	//GET CONSUMERS DATA FROM JSON_T
	json_unpack(jansson, "{s?o}", "consumers", &consumers);
	if (consumers) {
		char *consumer = NULL;
		size_t index;
		for (index = 0; index < json_array_size(consumers); index++) {
			json_unpack(json_array_get(consumers, index), "s", &consumer);

			if (_oph_json_add_consumer(*json, (const char *) consumer, flag)) {
				if (jansson)
					json_decref(jansson);
				return OPH_JSON_GENERIC_ERROR;
			}
		}
	}
	//GET RESPONSE DATA FROM JSON_T
	json_unpack(jansson, "{s?o}", "response", &response);
	if (response) {
		json_t *obj = NULL;
		size_t index1;
		for (index1 = 0; index1 < json_array_size(response); index1++) {
			json_unpack(json_array_get(response, index1), "o", &obj);

			if (obj) {
				char *objkey = NULL, *objclass = NULL;
				json_t *objcontent = NULL;
				json_unpack(obj, "{s?s,s?s,s?o}", "objclass", &objclass, "objkey", &objkey, "objcontent", &objcontent);
				if (!objkey || !objclass || !objcontent) {
					if (jansson)
						json_decref(jansson);
					return OPH_JSON_GENERIC_ERROR;
				}

				if (!strcmp(objclass, OPH_JSON_TEXT)) {	//OBJCLASS TEXT
					json_t *objcontentfrag = NULL;
					size_t index2;
					for (index2 = 0; index2 < json_array_size(objcontent); index2++) {
						json_unpack(json_array_get(objcontent, index2), "o", &objcontentfrag);

						if (objcontentfrag) {
							char *title = NULL, *message = NULL;
							json_unpack(objcontentfrag, "{s?s,s?s}", "title", &title, "message", &message);

							if (_oph_json_add_text(*json, (const char *) objkey, (const char *) title, (const char *) message, flag)) {
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_GENERIC_ERROR;
							}
						}
					}
				} else if (!strcmp(objclass, OPH_JSON_GRID)) {	//OBJCLASS GRID
					json_t *objcontentfrag = NULL;
					size_t index2;
					for (index2 = 0; index2 < json_array_size(objcontent); index2++) {
						json_unpack(json_array_get(objcontent, index2), "o", &objcontentfrag);

						if (objcontentfrag) {
							char *title = NULL, *description = NULL, **keys = NULL, **fieldtypes = NULL;
							int keys_num = 0, fieldtypes_num = 0;
							json_t *rowkeys = NULL;
							json_t *rowfieldtypes = NULL;
							json_unpack(objcontentfrag, "{s?s,s?s,s?o,s?o}", "title", &title, "description", &description, "rowkeys", &rowkeys, "rowfieldtypes",
								    &rowfieldtypes);
							if (!rowkeys || !rowfieldtypes) {
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}

							keys_num = json_array_size(rowkeys);
							fieldtypes_num = json_array_size(rowfieldtypes);

							// fill keys and fieldtypes
							keys = (char **) calloc(keys_num, sizeof(char *));
							if (!keys) {
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							fieldtypes = (char **) calloc(fieldtypes_num, sizeof(char *));
							if (!fieldtypes) {
								if (keys)
									free(keys);
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							int index3;
							for (index3 = 0; index3 < keys_num; index3++) {
								json_unpack(json_array_get(rowkeys, index3), "s", &(keys[index3]));
								if (!keys[index3]) {
									if (keys)
										free(keys);
									if (fieldtypes)
										free(fieldtypes);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
							}
							for (index3 = 0; index3 < fieldtypes_num; index3++) {
								json_unpack(json_array_get(rowfieldtypes, index3), "s", &(fieldtypes[index3]));
								if (!fieldtypes[index3]) {
									if (keys)
										free(keys);
									if (fieldtypes)
										free(fieldtypes);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
							}

							// add grid
							if (_oph_json_add_grid
							    (*json, (const char *) objkey, (const char *) title, (const char *) description, keys, (int) keys_num, fieldtypes, (int) fieldtypes_num,
							     flag)) {
								if (keys)
									free(keys);
								if (fieldtypes)
									free(fieldtypes);
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_GENERIC_ERROR;
							}
							if (keys)
								free(keys);
							if (fieldtypes)
								free(fieldtypes);

							json_t *rowvalues = NULL;
							json_unpack(objcontentfrag, "{s?o}", "rowvalues", &rowvalues);
							if (rowvalues) {
								size_t index4;
								json_t *rowvalues_i = NULL;
								for (index4 = 0; index4 < json_array_size(rowvalues); index4++) {	// for each row of values
									json_unpack(json_array_get(rowvalues, index4), "o", &rowvalues_i);	// get i-th row
									if (rowvalues_i) {
										char **values = NULL;
										int values_num = 0;

										values_num = json_array_size(rowvalues_i);

										// fill row with values
										values = (char **) calloc(values_num, sizeof(char *));
										if (!values) {
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_MEMORY_ERROR;
										}
										int index5;
										for (index5 = 0; index5 < values_num; index5++) {
											json_unpack(json_array_get(rowvalues_i, index5), "s", &(values[index5]));
											if (!values[index5]) {
												if (values)
													free(values);
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
										}

										// add grid row
										if (_oph_json_add_grid_row(*json, (const char *) objkey, values, flag)) {
											if (values)
												free(values);
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_GENERIC_ERROR;
										}
										if (values)
											free(values);
									}
								}
							}
						}
					}
				} else if (!strcmp(objclass, OPH_JSON_MULTIGRID)) {	//OBJCLASS MULTIGRID
					json_t *objcontentfrag = NULL;
					size_t index2;
					for (index2 = 0; index2 < json_array_size(objcontent); index2++) {
						json_unpack(json_array_get(objcontent, index2), "o", &objcontentfrag);

						if (objcontentfrag) {
							char *title = NULL, *description = NULL, **row_keys = NULL, **row_fieldtypes = NULL, **col_keys = NULL, **col_fieldtypes = NULL, ***col_values =
							    NULL, *measurename = NULL, *measuretype = NULL;
							int row_keys_num = 0, row_fieldtypes_num = 0, col_keys_num = 0, col_fieldtypes_num = 0, col_values_num = 0;
							json_t *rowkeys = NULL;
							json_t *rowfieldtypes = NULL;
							json_t *colkeys = NULL;
							json_t *colfieldtypes = NULL;
							json_t *colvalues = NULL;
							json_unpack(objcontentfrag, "{s?s,s?s,s?o,s?o,s?o,s?o,s?o,s?s,s?s}", "title", &title, "description", &description, "rowkeys", &rowkeys,
								    "rowfieldtypes", &rowfieldtypes, "colkeys", &colkeys, "colfieldtypes", &colfieldtypes, "colvalues", &colvalues, "measurename",
								    &measurename, "measuretype", &measuretype);
							if (!rowkeys || !rowfieldtypes || !colkeys || !colfieldtypes || !colvalues) {
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}

							row_keys_num = json_array_size(rowkeys);
							row_fieldtypes_num = json_array_size(rowfieldtypes);
							col_keys_num = json_array_size(colkeys);
							col_fieldtypes_num = json_array_size(colfieldtypes);
							col_values_num = json_array_size(colvalues);

							// alloc row_keys,row_fieldtypes,col_keys and col_fieldtypes
							row_keys = (char **) calloc(row_keys_num, sizeof(char *));
							if (!row_keys) {
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							row_fieldtypes = (char **) calloc(row_fieldtypes_num, sizeof(char *));
							if (!row_fieldtypes) {
								if (row_keys)
									free(row_keys);
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							col_keys = (char **) calloc(col_keys_num, sizeof(char *));
							if (!col_keys) {
								if (row_keys)
									free(row_keys);
								if (row_fieldtypes)
									free(row_fieldtypes);
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							col_fieldtypes = (char **) calloc(col_fieldtypes_num, sizeof(char *));
							if (!col_fieldtypes) {
								if (row_keys)
									free(row_keys);
								if (row_fieldtypes)
									free(row_fieldtypes);
								if (col_keys)
									free(col_keys);
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							// fill row_keys,row_fieldtypes,col_keys and col_fieldtypes
							int index3;
							for (index3 = 0; index3 < row_keys_num; index3++) {
								json_unpack(json_array_get(rowkeys, index3), "s", &(row_keys[index3]));
								if (!row_keys[index3]) {
									if (row_keys)
										free(row_keys);
									if (row_fieldtypes)
										free(row_fieldtypes);
									if (col_keys)
										free(col_keys);
									if (col_fieldtypes)
										free(col_fieldtypes);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
							}
							for (index3 = 0; index3 < row_fieldtypes_num; index3++) {
								json_unpack(json_array_get(rowfieldtypes, index3), "s", &(row_fieldtypes[index3]));
								if (!row_fieldtypes[index3]) {
									if (row_keys)
										free(row_keys);
									if (row_fieldtypes)
										free(row_fieldtypes);
									if (col_keys)
										free(col_keys);
									if (col_fieldtypes)
										free(col_fieldtypes);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
							}
							for (index3 = 0; index3 < col_keys_num; index3++) {
								json_unpack(json_array_get(colkeys, index3), "s", &(col_keys[index3]));
								if (!col_keys[index3]) {
									if (row_keys)
										free(row_keys);
									if (row_fieldtypes)
										free(row_fieldtypes);
									if (col_keys)
										free(col_keys);
									if (col_fieldtypes)
										free(col_fieldtypes);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
							}
							for (index3 = 0; index3 < col_fieldtypes_num; index3++) {
								json_unpack(json_array_get(colfieldtypes, index3), "s", &(col_fieldtypes[index3]));
								if (!col_fieldtypes[index3]) {
									if (row_keys)
										free(row_keys);
									if (row_fieldtypes)
										free(row_fieldtypes);
									if (col_keys)
										free(col_keys);
									if (col_fieldtypes)
										free(col_fieldtypes);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
							}

							// alloc col_values
							col_values = (char ***) calloc(col_values_num, sizeof(char **));
							if (!col_values) {
								if (row_keys)
									free(row_keys);
								if (row_fieldtypes)
									free(row_fieldtypes);
								if (col_keys)
									free(col_keys);
								if (col_fieldtypes)
									free(col_fieldtypes);
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_MEMORY_ERROR;
							}
							// fill col_values
							json_t *colvalues_i = NULL;
							int q;
							for (q = 0; q < col_values_num; q++) {
								json_unpack(json_array_get(colvalues, q), "o", &colvalues_i);
								if (colvalues_i) {
									int colvalues_i_num = json_array_size(colvalues_i);
									col_values[q] = (char **) calloc(colvalues_i_num, sizeof(char *));
									if (!col_values[q]) {
										int n;
										for (n = 0; n < q; n++) {
											if (col_values[n])
												free(col_values[n]);
										}
										if (col_values)
											free(col_values);
										if (row_keys)
											free(row_keys);
										if (row_fieldtypes)
											free(row_fieldtypes);
										if (col_keys)
											free(col_keys);
										if (col_fieldtypes)
											free(col_fieldtypes);
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_MEMORY_ERROR;
									}

									int index4;
									for (index4 = 0; index4 < colvalues_i_num; index4++) {
										json_unpack(json_array_get(colvalues_i, index4), "s", &(col_values[q][index4]));
										if (!col_values[q][index4]) {
											int n;
											for (n = 0; n < q; n++) {
												if (col_values[n])
													free(col_values[n]);
											}
											if (col_values)
												free(col_values);
											if (row_keys)
												free(row_keys);
											if (row_fieldtypes)
												free(row_fieldtypes);
											if (col_keys)
												free(col_keys);
											if (col_fieldtypes)
												free(col_fieldtypes);
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_GENERIC_ERROR;
										}
									}
								}
							}

							// add multigrid
							if (_oph_json_add_multigrid
							    (*json, (const char *) objkey, (const char *) title, (const char *) description, row_keys, (int) row_keys_num, row_fieldtypes,
							     (int) row_fieldtypes_num, col_keys, (int) col_keys_num, col_fieldtypes, (int) col_fieldtypes_num, col_values, (int) col_values_num,
							     (const char *) measurename, (const char *) measuretype, flag)) {
								if (row_keys)
									free(row_keys);
								if (row_fieldtypes)
									free(row_fieldtypes);
								if (col_keys)
									free(col_keys);
								if (col_fieldtypes)
									free(col_fieldtypes);
								if (col_values) {
									int ii;
									for (ii = 0; ii < col_values_num; ii++) {
										if (col_values[ii])
											free(col_values[ii]);
									}
									free(col_values);
								}
								if (jansson)
									json_decref(jansson);
								return OPH_JSON_GENERIC_ERROR;
							}
							if (row_keys)
								free(row_keys);
							if (row_fieldtypes)
								free(row_fieldtypes);
							if (col_keys)
								free(col_keys);
							if (col_fieldtypes)
								free(col_fieldtypes);
							if (col_values) {
								int ii;
								for (ii = 0; ii < col_values_num; ii++) {
									if (col_values[ii])
										free(col_values[ii]);
								}
								free(col_values);
							}
							// manage rows of values
							json_t *rowvalues = NULL;
							json_t *measurevalues = NULL;
							json_unpack(objcontentfrag, "{s?o,s?o}", "rowvalues", &rowvalues, "measurevalues", &measurevalues);
							if (rowvalues && measurevalues) {
								size_t index4;
								json_t *rowvalues_i = NULL;
								json_t *measurevalues_i = NULL;
								for (index4 = 0; index4 < json_array_size(rowvalues); index4++) {	// for each row of values
									json_unpack(json_array_get(rowvalues, index4), "o", &rowvalues_i);
									json_unpack(json_array_get(measurevalues, index4), "o", &measurevalues_i);	// get i-th row
									if (rowvalues_i && measurevalues_i) {
										char **row_values = NULL, **measure_values = NULL;

										// alloc row
										row_values = (char **) calloc(json_array_size(rowvalues_i), sizeof(char *));
										if (!row_values) {
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_MEMORY_ERROR;
										}
										measure_values = (char **) calloc(json_array_size(measurevalues_i), sizeof(char *));
										if (!measure_values) {
											if (row_values)
												free(row_values);
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_MEMORY_ERROR;
										}
										// fill row with values
										size_t index5;
										for (index5 = 0; index5 < json_array_size(rowvalues_i); index5++) {
											json_unpack(json_array_get(rowvalues_i, index5), "s", &(row_values[index5]));
											if (!row_values[index5]) {
												if (row_values)
													free(row_values);
												if (measure_values)
													free(measure_values);
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
										}
										for (index5 = 0; index5 < json_array_size(measurevalues_i); index5++) {
											json_unpack(json_array_get(measurevalues_i, index5), "s", &(measure_values[index5]));
											if (!measure_values[index5]) {
												if (row_values)
													free(row_values);
												if (measure_values)
													free(measure_values);
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
										}

										// add multigrid row
										if (_oph_json_add_multigrid_row(*json, (const char *) objkey, row_values, measure_values, flag)) {
											if (row_values)
												free(row_values);
											if (measure_values)
												free(measure_values);
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_GENERIC_ERROR;
										}
										if (row_values)
											free(row_values);
										if (measure_values)
											free(measure_values);
									}
								}
							}
						}
					}
				} else if (!strcmp(objclass, OPH_JSON_TREE)) {	//OBJCLASS TREE
					json_t *objcontentfrag = NULL;
					size_t index2;
					for (index2 = 0; index2 < json_array_size(objcontent); index2++) {
						json_unpack(json_array_get(objcontent, index2), "o", &objcontentfrag);

						if (objcontentfrag) {
							char *title = NULL, *description = NULL, **node_keys = NULL;
							int node_keys_num = 0;
							json_t *nodekeys = NULL;
							json_unpack(objcontentfrag, "{s?s,s?s,s?o}", "title", &title, "description", &description, "nodekeys", &nodekeys);

							if (nodekeys) {
								node_keys_num = json_array_size(nodekeys);
								// alloc node_keys
								node_keys = (char **) calloc(node_keys_num, sizeof(char *));
								if (!node_keys) {
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_MEMORY_ERROR;
								}
								// fill node_keys
								int index3;
								for (index3 = 0; index3 < node_keys_num; index3++) {
									json_unpack(json_array_get(nodekeys, index3), "s", &(node_keys[index3]));
									if (!node_keys[index3]) {
										if (node_keys)
											free(node_keys);
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_GENERIC_ERROR;
									}
								}

								// add tree
								if (_oph_json_add_tree
								    (*json, (const char *) objkey, (const char *) title, (const char *) description, node_keys, (int) node_keys_num, flag)) {
									if (node_keys)
										free(node_keys);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
								if (node_keys)
									free(node_keys);

								json_t *nodevalues = NULL;
								json_unpack(objcontentfrag, "{s?o}", "nodevalues", &nodevalues);
								if (nodevalues) {
									size_t index4;
									json_t *nodevalues_i = NULL;
									for (index4 = 0; index4 < json_array_size(nodevalues); index4++) {	// for each row of values
										json_unpack(json_array_get(nodevalues, index4), "o", &nodevalues_i);	// get i-th row
										if (nodevalues_i) {
											char **node_values = NULL;

											// alloc row
											node_values = (char **) calloc(json_array_size(nodevalues_i), sizeof(char *));
											if (!node_values) {
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_MEMORY_ERROR;
											}
											// fill row with values
											size_t index5;
											for (index5 = 0; index5 < json_array_size(nodevalues_i); index5++) {
												json_unpack(json_array_get(nodevalues_i, index5), "s", &(node_values[index5]));
												if (!node_values[index5]) {
													if (node_values)
														free(node_values);
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}
											}

											// add tree node
											if (_oph_json_add_tree_node(*json, (const char *) objkey, node_values, flag)) {
												if (node_values)
													free(node_values);
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
											if (node_values)
												free(node_values);
										}
									}

									char *rootnode = NULL;
									json_t *nodelinks = NULL;
									int nodelinks_num = 0;
									json_unpack(objcontentfrag, "{s?o,s?s}", "nodelinks", &nodelinks, "rootnode", &rootnode);
									nodelinks_num = json_array_size(nodelinks);

									// set tree root
									if (_oph_json_set_tree_root(*json, (const char *) objkey, (int) strtol(rootnode, NULL, 10), flag)) {
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_GENERIC_ERROR;
									}
									// add tree links
									int sourcenode;
									json_t *nodelinks_i = NULL;
									for (sourcenode = 0; sourcenode < nodelinks_num; sourcenode++) {
										json_unpack(json_array_get(nodelinks, sourcenode), "o", &nodelinks_i);

										if (nodelinks_i) {
											size_t s;
											for (s = 0; s < json_array_size(nodelinks_i); s++) {
												char *targetnode = NULL, *linkdescription = NULL;
												json_unpack(json_array_get(nodelinks_i, s), "{s?s,s?s}", "node", &targetnode, "description",
													    &linkdescription);
												if (!targetnode) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}

												if (_oph_json_add_tree_link
												    (*json, (const char *) objkey, sourcenode, (int) strtol(targetnode, NULL, 10),
												     (const char *) linkdescription, flag)) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}
											}
										}
									}
								} else {
									char *rootnode = NULL;
									json_t *nodelinks = NULL;
									int nodelinks_num = 0;
									json_unpack(objcontentfrag, "{s?o,s?s}", "nodelinks", &nodelinks, "rootnode", &rootnode);
									nodelinks_num = json_array_size(nodelinks);

									// add empty tree nodes
									int index4;
									for (index4 = 0; index4 < nodelinks_num; index4++) {
										if (_oph_json_add_tree_node(*json, (const char *) objkey, NULL, flag)) {
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_GENERIC_ERROR;
										}
									}

									// set tree root
									if (_oph_json_set_tree_root(*json, (const char *) objkey, (int) strtol(rootnode, NULL, 10), flag)) {
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_GENERIC_ERROR;
									}
									// add tree links
									int sourcenode;
									json_t *nodelinks_i = NULL;
									for (sourcenode = 0; sourcenode < nodelinks_num; sourcenode++) {
										json_unpack(json_array_get(nodelinks, sourcenode), "o", &nodelinks_i);

										if (nodelinks_i) {
											size_t s;
											for (s = 0; s < json_array_size(nodelinks_i); s++) {
												char *targetnode = NULL, *linkdescription = NULL;
												json_unpack(json_array_get(nodelinks_i, s), "{s?s,s?s}", "node", &targetnode, "description",
													    &linkdescription);
												if (!targetnode) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}

												if (_oph_json_add_tree_link
												    (*json, (const char *) objkey, sourcenode, (int) strtol(targetnode, NULL, 10),
												     (const char *) linkdescription, flag)) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}
											}
										}
									}
								}
							} else {
								// add empty tree
								if (_oph_json_add_tree(*json, (const char *) objkey, (const char *) title, (const char *) description, NULL, 0, flag)) {
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}

								char *rootnode = NULL;
								json_t *nodelinks = NULL;
								int nodelinks_num = 0;
								json_unpack(objcontentfrag, "{s?o,s?s}", "nodelinks", &nodelinks, "rootnode", &rootnode);
								nodelinks_num = json_array_size(nodelinks);

								// add empty tree nodes
								int index3;
								for (index3 = 0; index3 < nodelinks_num; index3++) {
									if (_oph_json_add_tree_node(*json, (const char *) objkey, NULL, flag)) {
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_GENERIC_ERROR;
									}
								}

								// set tree root
								if (_oph_json_set_tree_root(*json, (const char *) objkey, (int) strtol(rootnode, NULL, 10), flag)) {
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
								// add tree links
								int sourcenode;
								json_t *nodelinks_i = NULL;
								for (sourcenode = 0; sourcenode < nodelinks_num; sourcenode++) {
									json_unpack(json_array_get(nodelinks, sourcenode), "o", &nodelinks_i);

									if (nodelinks_i) {
										size_t s;
										for (s = 0; s < json_array_size(nodelinks_i); s++) {
											char *targetnode = NULL, *linkdescription = NULL;
											json_unpack(json_array_get(nodelinks_i, s), "{s?s,s?s}", "node", &targetnode, "description", &linkdescription);
											if (!targetnode) {
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}

											if (_oph_json_add_tree_link
											    (*json, (const char *) objkey, sourcenode, (int) strtol(targetnode, NULL, 10),
											     (const char *) linkdescription, flag)) {
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
										}
									}
								}
							}
						}
					}
				} else if (!strcmp(objclass, OPH_JSON_DGRAPH) || !strcmp(objclass, OPH_JSON_GRAPH)) {	//OBJCLASS (DI)GRAPH
					int is_digraph = (!strcmp(objclass, OPH_JSON_DGRAPH)) ? 1 : 0;
					json_t *objcontentfrag = NULL;
					size_t index2;
					for (index2 = 0; index2 < json_array_size(objcontent); index2++) {
						json_unpack(json_array_get(objcontent, index2), "o", &objcontentfrag);

						if (objcontentfrag) {
							char *title = NULL, *description = NULL, **node_keys = NULL;
							int node_keys_num = 0;
							json_t *nodekeys = NULL;
							json_unpack(objcontentfrag, "{s?s,s?s,s?o}", "title", &title, "description", &description, "nodekeys", &nodekeys);

							if (nodekeys) {
								node_keys_num = json_array_size(nodekeys);
								// alloc node_keys
								node_keys = (char **) calloc(node_keys_num, sizeof(char *));
								if (!node_keys) {
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_MEMORY_ERROR;
								}
								// fill node_keys
								int index3;
								for (index3 = 0; index3 < node_keys_num; index3++) {
									json_unpack(json_array_get(nodekeys, index3), "s", &(node_keys[index3]));
									if (!node_keys[index3]) {
										if (node_keys)
											free(node_keys);
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_GENERIC_ERROR;
									}
								}

								// add graph
								if (_oph_json_add_graph
								    (*json, (const char *) objkey, is_digraph, (const char *) title, (const char *) description, node_keys, (int) node_keys_num,
								     flag)) {
									if (node_keys)
										free(node_keys);
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}
								if (node_keys)
									free(node_keys);

								json_t *nodevalues = NULL;
								json_unpack(objcontentfrag, "{s?o}", "nodevalues", &nodevalues);
								if (nodevalues) {
									size_t index4;
									json_t *nodevalues_i = NULL;
									for (index4 = 0; index4 < json_array_size(nodevalues); index4++) {	// for each row of values
										json_unpack(json_array_get(nodevalues, index4), "o", &nodevalues_i);	// get i-th row
										if (nodevalues_i) {
											char **node_values = NULL;

											// alloc row
											node_values = (char **) calloc(json_array_size(nodevalues_i), sizeof(char *));
											if (!node_values) {
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_MEMORY_ERROR;
											}
											// fill row with values
											size_t index5;
											for (index5 = 0; index5 < json_array_size(nodevalues_i); index5++) {
												json_unpack(json_array_get(nodevalues_i, index5), "s", &(node_values[index5]));
												if (!node_values[index5]) {
													if (node_values)
														free(node_values);
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}
											}

											// add graph node
											if (_oph_json_add_graph_node(*json, (const char *) objkey, node_values, flag)) {
												if (node_values)
													free(node_values);
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
											if (node_values)
												free(node_values);
										}
									}

									json_t *nodelinks = NULL;
									int nodelinks_num = 0;
									json_unpack(objcontentfrag, "{s?o}", "nodelinks", &nodelinks);
									nodelinks_num = json_array_size(nodelinks);

									// add graph links
									int sourcenode;
									json_t *nodelinks_i = NULL;
									for (sourcenode = 0; sourcenode < nodelinks_num; sourcenode++) {
										json_unpack(json_array_get(nodelinks, sourcenode), "o", &nodelinks_i);

										if (nodelinks_i) {
											size_t s;
											for (s = 0; s < json_array_size(nodelinks_i); s++) {
												char *targetnode = NULL, *linkdescription = NULL;
												json_unpack(json_array_get(nodelinks_i, s), "{s?s,s?s}", "node", &targetnode, "description",
													    &linkdescription);
												if (!targetnode) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}

												if (_oph_json_add_graph_link
												    (*json, (const char *) objkey, sourcenode, (int) strtol(targetnode, NULL, 10),
												     (const char *) linkdescription, flag)) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}
											}
										}
									}
								} else {
									json_t *nodelinks = NULL;
									int nodelinks_num = 0;
									json_unpack(objcontentfrag, "{s?o}", "nodelinks", &nodelinks);
									nodelinks_num = json_array_size(nodelinks);

									// add empty graph nodes
									int index4;
									for (index4 = 0; index4 < nodelinks_num; index4++) {
										if (_oph_json_add_graph_node(*json, (const char *) objkey, NULL, flag)) {
											if (jansson)
												json_decref(jansson);
											return OPH_JSON_GENERIC_ERROR;
										}
									}

									// add graph links
									int sourcenode;
									json_t *nodelinks_i = NULL;
									for (sourcenode = 0; sourcenode < nodelinks_num; sourcenode++) {
										json_unpack(json_array_get(nodelinks, sourcenode), "o", &nodelinks_i);

										if (nodelinks_i) {
											size_t s;
											for (s = 0; s < json_array_size(nodelinks_i); s++) {
												char *targetnode = NULL, *linkdescription = NULL;
												json_unpack(json_array_get(nodelinks_i, s), "{s?s,s?s}", "node", &targetnode, "description",
													    &linkdescription);
												if (!targetnode) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}

												if (_oph_json_add_graph_link
												    (*json, (const char *) objkey, sourcenode, (int) strtol(targetnode, NULL, 10),
												     (const char *) linkdescription, flag)) {
													if (jansson)
														json_decref(jansson);
													return OPH_JSON_GENERIC_ERROR;
												}
											}
										}
									}
								}
							} else {
								// add empty graph
								if (_oph_json_add_graph(*json, (const char *) objkey, is_digraph, (const char *) title, (const char *) description, NULL, 0, flag)) {
									if (jansson)
										json_decref(jansson);
									return OPH_JSON_GENERIC_ERROR;
								}

								json_t *nodelinks = NULL;
								int nodelinks_num = 0;
								json_unpack(objcontentfrag, "{s?o}", "nodelinks", &nodelinks);
								nodelinks_num = json_array_size(nodelinks);

								// add empty graph nodes
								int index3;
								for (index3 = 0; index3 < nodelinks_num; index3++) {
									if (_oph_json_add_graph_node(*json, (const char *) objkey, NULL, flag)) {
										if (jansson)
											json_decref(jansson);
										return OPH_JSON_GENERIC_ERROR;
									}
								}

								// add graph links
								int sourcenode;
								json_t *nodelinks_i = NULL;
								for (sourcenode = 0; sourcenode < nodelinks_num; sourcenode++) {
									json_unpack(json_array_get(nodelinks, sourcenode), "o", &nodelinks_i);

									if (nodelinks_i) {
										size_t s;
										for (s = 0; s < json_array_size(nodelinks_i); s++) {
											char *targetnode = NULL, *linkdescription = NULL;
											json_unpack(json_array_get(nodelinks_i, s), "{s?s,s?s}", "node", &targetnode, "description", &linkdescription);
											if (!targetnode) {
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}

											if (_oph_json_add_graph_link
											    (*json, (const char *) objkey, sourcenode, (int) strtol(targetnode, NULL, 10),
											     (const char *) linkdescription, flag)) {
												if (jansson)
													json_decref(jansson);
												return OPH_JSON_GENERIC_ERROR;
											}
										}
									}
								}
							}
						}
					}
				} else {
					if (jansson)
						json_decref(jansson);
					return OPH_JSON_GENERIC_ERROR;
				}
			}
		}
	}

	/* CLEANUP */
	if (jansson)
		json_decref(jansson);

	return OPH_JSON_SUCCESS;
}

int oph_json_from_json_string(oph_json ** json, const char *jstring)
{
	return _oph_json_from_json_string(json, jstring, &global_flag);
}

int oph_json_from_json_string_unsafe(oph_json ** json, const char *jstring)
{
	return _oph_json_from_json_string(json, jstring, NULL);
}
