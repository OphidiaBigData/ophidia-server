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

#ifndef OPH_RMANAGER_H
#define OPH_RMANAGER_H

#include "oph_gather.h"
#include "oph_plugin.h"

#define RMANAGER_SUCCESS 0
#define RMANAGER_NULL_PARAM 1
#define RMANAGER_FILE_ERROR 2
#define RMANAGER_STR_BUFF_OVERFLOW 3
#define RMANAGER_MEMORY_ERROR 4
#define RMANAGER_ERROR 5

#define OPH_RMANAGER_PREFIX OPH_SERVER_PREFIX
#define OPH_RMANAGER_MAX_INT_SIZE 32

#define OPH_NULL_FILENAME "/dev/null"

typedef struct _oph_detached_task {
	int id;
	struct _oph_detached_task *next;
} oph_detached_task;

struct _oph_rmanager {
	char *subm_cmd_submit;
	char *subm_cmd_start;
	char *subm_cmd_mount;
	char *subm_cmd_cancel;
	char *subm_cmd_stop;
	char *subm_cmd_umount;
	char *subm_cmd_check;
	char *subm_cmd_count;
	char *subm_cmd_cancel_all;
	char subm_multiuser;
	char *subm_group;
	char *subm_queue_high;
	char *subm_queue_low;
	char *subm_prefix;
	char *subm_postfix;
	int subm_taskid;
	oph_detached_task *subm_detached_tasks;
};
typedef struct _oph_rmanager oph_rmanager;

int oph_serve_request(const char *request, const int ncores, const char *sessionid, const char *markerid, const char *error, struct oph_plugin_data *state, int *odb_wf_id, int *task_id,
		      int *light_task_id, int *odb_jobid, int delay, char **response, char **jobid, enum oph__oph_odb_job_status *exit_code, int *exit_output, char *username, char *project, int wid);
int initialize_rmanager(oph_rmanager * orm);
int oph_read_rmanager_conf(oph_rmanager * orm);
int oph_form_subm_string(const char *request, const int ncores, char *outfile, short int interactive_subm, oph_rmanager * orm, int jobid, const char *username, const char *project, int wid,
			 char **cmd, char type);
int oph_get_result_from_file(char *filename, char **response);
int oph_get_result_from_file_unsafe(char *filename, char **response);
int free_oph_rmanager(oph_rmanager * orm);
int oph_cancel_request(int jobid, const char *username);
int oph_stop_request(int jobid, const char *username);
int oph_umount_request(int jobid, const char *username);
int oph_cancel_all_request(int wid, const char *username);
int oph_read_job_queue(int **list, char ***username, unsigned int *n);
int oph_get_available_host_number(int *size, int jobid);
int oph_system(const char *command, const char *error, struct oph_plugin_data *state, int delay, char blocking, int (*postprocess) (int), int id);

int oph_detach_task(int id);
int oph_is_detached_task(int id);
int oph_remove_detached_task(int id);

#endif				/* OPH_RMANAGER_H */
