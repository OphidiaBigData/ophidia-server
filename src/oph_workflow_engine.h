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

#ifndef OPH_WORKFLOW_ENGINE_H
#define OPH_WORKFLOW_ENGINE_H

#include "oph_auth.h"
#include "oph_plugin.h"
#include "oph_odb_job.h"

#include "oph_workflow_library.h"

int oph_workflow_reset_task(oph_workflow * wf, int *dependents_indexes, int dependents_indexes_num, int last_task, oph_workflow_stack * stack, int *tasks_num);
int oph_workflow_disable_deps(oph_workflow * wf, int *dependents_indexes, int dependents_indexes_num, int first_task, int last_task);

int oph_workflow_execute(struct oph_plugin_data *state, char ttype, int jobid, oph_workflow * wf, int *initial_tasks_indexes, int initial_tasks_indexes_num, ophidiadb * oDB, char **jobid_response);
int oph_workflow_notify(struct oph_plugin_data *state, char ttype, int jobid, char *data, char *json, int *response);
int oph_workflow_command_to_json(const char *command, char **json);

int oph_check_for_massive_operation(struct oph_plugin_data *state, char ttype, int jobid, oph_workflow * wf, int task_index, ophidiadb * oDB, char ***output_list, int *output_list_dim, char **query);
int oph_generate_oph_jobid(struct oph_plugin_data *state, char ttype, int jobid, oph_workflow * wf, int *num_sessions, int max_sessions, int timeout_value, int *markerid, char *str_markerid,
			   int *workflowid, char *str_workflowid, char *oph_jobid, int prev_markerid);

int oph_workflow_parallel_fco(oph_workflow * wf, int nesting_level);

int oph_workflow_check_job_queue(struct oph_plugin_data *state);

int oph_workflow_create_hp(oph_workflow * wf, ophidiadb * oDB);
int oph_workflow_destroy_hp(oph_workflow * wf, ophidiadb * oDB);

int oph_get_progress_ratio_of(oph_workflow * wf, double *wpr, char **cdate);
int oph_get_info_of(char *sessionid, int workflowid, char **status, char **cdate);

int oph_workflow_add_to_list(char *key, char *object, oph_workflow_ordered_list ** list);
int oph_workflow_print_list(oph_workflow_ordered_list * list, char **string);

#endif				/* OPH_WORKFLOW_ENGINE_H */
