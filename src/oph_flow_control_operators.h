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

#ifndef OPH_FLOW_OPERATORS_H
#define OPH_FLOW_OPERATORS_H

#include "oph_gather.h"
#include "oph_plugin.h"

typedef struct _oph_notify_data {
	oph_workflow *wf;
	int task_index;
	char *json_output;
	struct oph_plugin_data *state;
	char *add_to_notify;
	void *data;
	char run;
	char detach;
} oph_notify_data;

typedef struct _oph_wait_data {
	char type;
	int timeout;
	char *filename;
	char *measure;
	char *subset_params;
} oph_wait_data;

// Main interface of the library
int oph_serve_flow_control_operator(struct oph_plugin_data *state, const char *request, const int ncores, const char *sessionid, const char *markerid, int *odb_wf_id, int *task_id, int *light_task_id,
				    int *odb_jobid, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, const char *os_username, const char *taskname,
				    const char *operator_name);
int oph_is_flow_control_operator(const char *operator_name);

// Internal functions
int oph_if_impl(oph_workflow * wf, int i, char *error_message, int *exit_output);
int oph_else_impl(oph_workflow * wf, int i, char *error_message, int *exit_output);
int oph_for_impl(oph_workflow * wf, int i, char *error_message);
int oph_endfor_impl(oph_workflow * wf, int i, char *error_message, oph_trash * trash, int *task_id, int *odb_jobid);
int oph_set_impl(oph_workflow * wf, int i, char *error_message, struct oph_plugin_data *state, char has_action);
int oph_wait_impl(oph_workflow * wf, int i, char *error_message, char **message, oph_notify_data * data);

int oph_set_status_of_selection_block(oph_workflow * wf, int task_index, enum oph__oph_odb_job_status status, int parent, int nk, char skip_the_next, int *exit_output);
int oph_extract_from_json(char **key, const char *json_string);

#endif				/* OPH_FLOW_OPERATORS_H */
