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

#ifndef OPH_JOB_LIST_H
#define OPH_JOB_LIST_H

#include "oph_workflow_library.h"

#define OPH_JOB_LIST_OK 0
#define OPH_JOB_LIST_ERROR 1
#define OPH_JOB_LIST_EXISTING_JOB 2
#define OPH_JOB_LIST_FULL 3
#define OPH_JOB_LIST_FARM_FULL 4

#define OPH_JOB_LIST_MAX_STRING 256

#define OPH_JOB_NUMBER_UNLIMITED -1
#define OPH_JOB_SEPARATOR "|"

typedef struct _oph_child_job_info {
	int jobid;
	int marker_id;
	int status;

	struct _oph_child_job_info *next;
} oph_child_job_info;

typedef struct _oph_job_info {
	int timestamp;
	oph_workflow *wf;

	struct _oph_job_info *next;
} oph_job_info;

typedef struct {
	oph_job_info *head;
	oph_job_info *tail;
	oph_job_info *saved;
	unsigned int counter;
} oph_job_list;

int oph_create_job_list(oph_job_list ** list);

oph_job_info *oph_find_job_in_job_list(oph_job_list * list, int jobid, oph_job_info ** prev);
int oph_insert_into_job_list(oph_job_list * list, oph_job_info * item);
int oph_drop_from_job_list(oph_job_list * list, oph_job_info * item, oph_job_info * prev);
int oph_delete_from_job_list(oph_job_list * list, oph_job_info * item, oph_job_info * prev);
int oph_save_job_in_job_list(oph_job_list * list, oph_job_info * item);
int oph_delete_saved_jobs_from_job_list(oph_job_list * list, int hysteresis);

int oph_free_job_list(oph_job_list * list);

int oph_destroy_job_list(oph_job_list * list);

int oph_free_children_list(oph_child_job_info * child);

oph_job_info *oph_find_job_in_children_job_lists(oph_job_list * list, int jobid, oph_job_info ** prev);

oph_job_info *oph_find_workflow_in_job_list_to_drop(oph_job_list * list, const char *sessionid, int workflowid, oph_job_info ** prev);
oph_job_info *oph_find_workflow_in_job_list(oph_job_list * list, const char *sessionid, int workflowid);
oph_job_info *oph_find_marker_in_job_list(oph_job_list * list, const char *sessionid, int markerid, int *task_index, int *light_task_index);
oph_job_info *oph_find_unstarted_in_job_list(oph_job_list * list);

#endif				/* OPH_JOB_LIST_H */
