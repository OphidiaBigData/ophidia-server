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

#ifndef OPH_SERVICE_INFO_H
#define OPH_SERVICE_INFO_H

#include <time.h>

typedef struct _oph_service_info_task {
	char *operator;
	char status;
} oph_service_info_task;

typedef struct _oph_service_info_wf {
	char *client_address;
	char status;
	oph_service_info_task *tasks;
	unsigned int tasks_num;
	struct _oph_service_info_wf *next;
} oph_service_info_wf;

typedef struct _oph_service_info {
	unsigned long incoming_requests;
	unsigned long accepted_requests;
	unsigned long authorized_requests;
	unsigned long incoming_workflows;
	unsigned long accepted_workflows;
	unsigned long closed_workflows;
	unsigned long incoming_tasks;
	unsigned long submitted_tasks;
	unsigned long closed_tasks;
	unsigned long incoming_notifications;
	unsigned long incoming_responses;
	unsigned long outcoming_responses;
	unsigned long current_thread_number;
	unsigned long peak_thread_number;
	time_t peak_thread_number_timestamp;
	oph_service_info_wf *workflows;
} oph_service_info;

void oph_service_info_thread_incr(oph_service_info * service_info);
void oph_service_info_thread_decr(oph_service_info * service_info);

#endif				/* OPH_SERVICE_INFO_H */
