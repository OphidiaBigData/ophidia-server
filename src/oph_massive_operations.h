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

#ifndef OPH_MASSIVE_OP_H
#define OPH_MASSIVE_OP_H

#include "oph_ophidiadb.h"
#include "oph_plugin.h"
#include "oph_workflow_library.h"

// Parameters
#define OPH_MASSIVE_OPERATOR	"OPH_MASSIVE"

int oph_mf_parse_query(struct oph_plugin_data *state, oph_workflow * workflow, int task_index, char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input, char *cwd,
		       char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query);
int oph_mf_parse_query_unsafe(struct oph_plugin_data *state, oph_workflow * workflow, int task_index, char ***datacube_inputs, char ***measure_name, unsigned int *counter, char *datacube_input,
			      char *cwd, char *cdd, char *sessionid, int *running, int is_src_path, ophidiadb * oDB, char **query);

#endif				/* OPH_MASSIVE_OP_H */
