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

#include "oph_job_list.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

extern int oph_server_workflow_timeout;
extern unsigned int oph_server_farm_size;
extern unsigned int oph_server_queue_size;
extern char *oph_status_log_file_name;

#include "oph_parser.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_cond_t termination_flag;
#endif

int oph_free_children_list(oph_child_job_info * child)
{
	oph_child_job_info *temp;
	for (temp = child; temp; temp = child) {
		child = temp->next;
		free(temp);
	}
	return OPH_JOB_LIST_OK;
}

int oph_create_job_list(oph_job_list ** list)
{
	if (!list)
		return OPH_JOB_LIST_ERROR;
	*list = (oph_job_list *) malloc(sizeof(oph_job_list));
	if (!(*list))
		return OPH_JOB_LIST_ERROR;
	(*list)->head = (*list)->tail = (*list)->saved = NULL;
	(*list)->counter = 0;
	return OPH_JOB_LIST_OK;
}

oph_job_info *oph_find_job_in_job_list(oph_job_list * list, int jobid, oph_job_info ** prev)
{
	if (!list)
		return NULL;
	oph_job_info *temp, *temp_prev = 0, *next;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int remote_deadline = tv.tv_sec - oph_server_workflow_timeout;
	for (temp = list->head; temp; temp_prev = temp, temp = next) {
		next = temp->next;
		if (temp->timestamp < remote_deadline) {
			if (!list->counter)
				return NULL;
			if (list->tail == temp)
				list->tail = temp_prev;
			if (list->head == temp)
				list->head = next;
			else if (temp_prev)
				temp_prev->next = next;
			list->counter--;

			if (temp->wf->exec_mode && !strncasecmp(temp->wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Workflow '%s' is expired\n", temp->wf->name);
				temp->wf->status = OPH_ODB_STATUS_EXPIRED;
				pthread_cond_broadcast(&termination_flag);
			} else
				oph_workflow_free(temp->wf);

			free(temp);
		} else if (temp->wf->idjob == jobid) {
			if (prev)
				*prev = temp_prev;
			return temp;
		}
	}
	return NULL;
}

int oph_insert_into_job_list(oph_job_list * list, oph_job_info * item)
{
	int result = OPH_JOB_LIST_OK;
	if (!list)
		return OPH_JOB_LIST_ERROR;
	if (oph_server_farm_size && (list->counter >= oph_server_farm_size)) {
		if (oph_server_queue_size && (list->counter >= oph_server_farm_size + oph_server_queue_size))
			return OPH_JOB_LIST_FULL;
		result = OPH_JOB_LIST_FARM_FULL;
	}
	if (oph_find_job_in_job_list(list, item->wf->idjob, 0))
		return OPH_JOB_LIST_EXISTING_JOB;
	if (list->tail)
		list->tail->next = item;
	list->tail = item;
	item->next = 0;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	item->timestamp = tv.tv_sec;
	if (!list->head)
		list->head = item;
	list->counter++;
	return result;
}

int oph_drop_from_job_list(oph_job_list * list, oph_job_info * item, oph_job_info * prev)
{
	if (!list)
		return OPH_JOB_LIST_ERROR;
	list->counter--;
	if (list->tail == item)
		list->tail = prev;
	if (list->head == item)
		list->head = item->next;
	else {
		if (!prev)
			return OPH_JOB_LIST_ERROR;
		prev->next = item->next;
	}
	return OPH_JOB_LIST_OK;
}

int oph_save_job_in_job_list(oph_job_list * list, oph_job_info * item)
{
	if (!list)
		return OPH_JOB_LIST_ERROR;
	if (oph_status_log_file_name) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		item->timestamp = tv.tv_sec;
		item->next = list->saved;
		list->saved = item;
	} else {
		oph_workflow_free(item->wf);
		free(item);
	}
	return OPH_JOB_LIST_OK;
}

int oph_delete_from_job_list(oph_job_list * list, oph_job_info * item, oph_job_info * prev)
{
	if (oph_drop_from_job_list(list, item, prev))
		return OPH_JOB_LIST_ERROR;
	return oph_save_job_in_job_list(list, item);
}

int oph_delete_saved_jobs_from_job_list(oph_job_list * list, int hysteresis)
{
	if (!list)
		return OPH_JOB_LIST_ERROR;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	oph_job_info *current = list->saved, *next, *prev = NULL;
	list->saved = NULL;
	for (; current; current = next) {
		next = current->next;
		if (!hysteresis || (current->timestamp < tv.tv_sec - hysteresis)) {
			oph_workflow_free(current->wf);
			free(current);
			if (prev)
				prev->next = next;
		} else {
			prev = current;
			if (!list->saved)
				list->saved = current;
		}
	}
	return OPH_JOB_LIST_OK;
}

int oph_free_job_list(oph_job_list * list)
{
	if (!list)
		return OPH_JOB_LIST_ERROR;
	oph_job_info *temp;
	for (temp = list->head; temp;) {
		list->head = temp->next;
		oph_workflow_free(temp->wf);
		free(temp);
		temp = list->head;
	}
	list->tail = NULL;
	list->counter = 0;
	oph_delete_saved_jobs_from_job_list(list, 0);
	return OPH_JOB_LIST_OK;
}

int oph_destroy_job_list(oph_job_list * list)
{
	if (!list)
		return OPH_JOB_LIST_ERROR;
	if (oph_free_job_list(list))
		return OPH_JOB_LIST_ERROR;
	free(list);
	return OPH_JOB_LIST_OK;
}

oph_job_info *oph_find_job_in_children_job_lists(oph_job_list * list, int jobid, oph_job_info ** prev)
{
	if (!list)
		return NULL;
	oph_job_info *temp, *temp_prev = 0, *next;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int remote_deadline = tv.tv_sec - oph_server_workflow_timeout;
	for (temp = list->head; temp; temp_prev = temp, temp = next) {
		next = temp->next;
		if (temp->timestamp < remote_deadline) {
			if (!list->counter)
				return NULL;
			if (list->tail == temp)
				list->tail = temp_prev;
			if (list->head == temp)
				list->head = next;
			else if (temp_prev)
				temp_prev->next = next;
			list->counter--;

			if (temp->wf) {
				if (temp->wf->exec_mode && !strncasecmp(temp->wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Workflow '%s' is expired\n", temp->wf->name);
					temp->wf->status = OPH_ODB_STATUS_EXPIRED;
					pthread_cond_broadcast(&termination_flag);
				} else
					oph_workflow_free(temp->wf);
			}

			free(temp);
		} else if (temp->wf->tasks) {
			int i;
			for (i = 0; i < temp->wf->tasks_num; ++i) {
				if (temp->wf && (temp->wf->tasks[i].idjob == jobid)) {
					if (prev)
						*prev = temp_prev;
					return temp;
				}
			}
		}
	}
	return NULL;
}


oph_job_info *oph_find_workflow_in_job_list_to_drop(oph_job_list * list, const char *sessionid, int workflowid, oph_job_info ** prev)
{
	if (!list)
		return NULL;
	if (prev)
		*prev = NULL;
	oph_job_info *temp, *temp_prev = NULL, *next, *result = NULL;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int remote_deadline = tv.tv_sec - oph_server_workflow_timeout;
#ifdef PRINT_RAW_SHARED_MEMORY
	int i, j;
#endif
	for (temp = list->head; temp; temp_prev = temp, temp = next) {
		next = temp->next;
		if (temp->timestamp < remote_deadline) {
			if (!list->counter)
				return NULL;
			if (list->tail == temp)
				list->tail = temp_prev;
			if (list->head == temp)
				list->head = next;
			else if (temp_prev)
				temp_prev->next = next;
			list->counter--;

			if (temp->wf->exec_mode && !strncasecmp(temp->wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Workflow '%s' is expired\n", temp->wf->name);
				temp->wf->status = OPH_ODB_STATUS_EXPIRED;
				pthread_cond_broadcast(&termination_flag);
			} else
				oph_workflow_free(temp->wf);

			free(temp);
		} else if ((temp->wf->workflowid == workflowid) && (!sessionid || !strcmp(temp->wf->sessionid, sessionid)))
#ifdef PRINT_RAW_SHARED_MEMORY
			if (!result)
				result = temp;

		if (get_debug_level() == LOG_DEBUG) {
			printf("Workflow '%s': ID %d STATUS %d\n", temp->wf->name, temp->wf->workflowid, temp->wf->status);
			for (i = 0; i < temp->wf->tasks_num; ++i) {
				printf("\tTask %d '%s': ID %d#%d STATUS %d OPERATOR %s\n", i, temp->wf->tasks[i].name, temp->wf->workflowid, temp->wf->tasks[i].markerid, temp->wf->tasks[i].status,
				       temp->wf->tasks[i].operator);
				for (j = 0; j < temp->wf->tasks[i].light_tasks_num; ++j)
					printf("\t\tLight task %d: ID %d#%d STATUS %d\n", j, temp->wf->workflowid, temp->wf->tasks[i].light_tasks[j].markerid,
					       temp->wf->tasks[i].light_tasks[j].status);
			}
		}

		if (prev && !result)
			*prev = temp;
#else
			return temp;
		if (prev)
			*prev = temp;
#endif
	}
	return result;
}

oph_job_info *oph_find_workflow_in_job_list(oph_job_list * list, const char *sessionid, int workflowid)
{
	return oph_find_workflow_in_job_list_to_drop(list, sessionid, workflowid, NULL);
}

oph_job_info *oph_find_marker_in_job_list(oph_job_list * list, const char *sessionid, int markerid, int *task_index, int *light_task_index)
{
	if (!list)
		return NULL;
	if (task_index)
		*task_index = -1;
	if (light_task_index)
		*light_task_index = -1;

	oph_job_info *temp, *temp_prev = 0, *next;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int remote_deadline = tv.tv_sec - oph_server_workflow_timeout, i, j;
	for (temp = list->head; temp; temp_prev = temp, temp = next) {
		next = temp->next;
		if (temp->timestamp < remote_deadline) {
			if (!list->counter)
				return NULL;
			if (list->tail == temp)
				list->tail = temp_prev;
			if (list->head == temp)
				list->head = next;
			else if (temp_prev)
				temp_prev->next = next;
			list->counter--;

			if (temp->wf->exec_mode && !strncasecmp(temp->wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Workflow '%s' is expired\n", temp->wf->name);
				temp->wf->status = OPH_ODB_STATUS_EXPIRED;
				pthread_cond_broadcast(&termination_flag);
			} else
				oph_workflow_free(temp->wf);

			free(temp);
		} else if ((temp->wf->markerid == markerid) && (!sessionid || !strcmp(temp->wf->sessionid, sessionid)))
			return temp;
		else
			for (i = 0; i < temp->wf->tasks_num; ++i) {
				if ((temp->wf->tasks[i].markerid == markerid) && (!sessionid || !strcmp(temp->wf->sessionid, sessionid))) {
					if (task_index)
						*task_index = i;
					return temp;
				} else
					for (j = 0; j < temp->wf->tasks[i].light_tasks_num; ++j)
						if ((temp->wf->tasks[i].light_tasks[j].markerid == markerid) && (!sessionid || !strcmp(temp->wf->sessionid, sessionid))) {
							if (task_index)
								*task_index = i;
							if (light_task_index)
								*light_task_index = j;
							return temp;
						}
			}
	}
	return NULL;
}

oph_job_info *oph_find_unstarted_in_job_list(oph_job_list * list)
{
	if (!list)
		return NULL;
	oph_job_info *temp, *temp_prev = 0, *next;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int remote_deadline = tv.tv_sec - oph_server_workflow_timeout;
	unsigned int number_of_running_wf = 0;
	for (temp = list->head; temp; temp_prev = temp, temp = next) {
		next = temp->next;
		if (temp->timestamp < remote_deadline) {
			if (!list->counter)
				return NULL;
			if (list->tail == temp)
				list->tail = temp_prev;
			if (list->head == temp)
				list->head = next;
			else if (temp_prev)
				temp_prev->next = next;
			list->counter--;

			if (temp->wf->exec_mode && !strncasecmp(temp->wf->exec_mode, OPH_ARG_MODE_SYNC, OPH_MAX_STRING_SIZE)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Workflow '%s' is expired\n", temp->wf->name);
				temp->wf->status = OPH_ODB_STATUS_EXPIRED;
				pthread_cond_broadcast(&termination_flag);
			} else
				oph_workflow_free(temp->wf);

			free(temp);
		} else if (temp->wf->status)
			number_of_running_wf++;
	}
	// If at least server is now available and there is at least an element in queue
	if (oph_server_farm_size && (number_of_running_wf < oph_server_farm_size) && (list->counter > number_of_running_wf))
		for (temp = list->head; temp; temp = temp->next)	// Find a workflow in queue
			if (!temp->wf->status)
				return temp;	// not started yet
	return NULL;
}
