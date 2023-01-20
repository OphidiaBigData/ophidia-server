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

#ifndef OPH_KNOWN_OPERATORS_H
#define OPH_KNOWN_OPERATORS_H

#include "oph_gather.h"
#include "oph_plugin.h"

int oph_serve_known_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id, int *light_task_id,
			     int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, char *username, char *project, char *taskname);
int oph_is_known_operator(const char *operator_name);

#endif				/* OPH_KNOWN_OPERATORS_H */
