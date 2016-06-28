/*
    Ophidia Server
    Copyright (C) 2012-2016 CMCC Foundation

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

#define OPH_RMANAGER_PREFIX "oph"
#define OPH_RMANAGER_MAX_INT_SIZE 32

struct _oph_rmanager
{
	char *name;
	char *subm_cmd;
	char *subm_args;
	char *subm_ncores;
	char *interact_subm;
	char *batch_subm;
	char *subm_stdoutput;
	char *subm_stderror;
	char *subm_postfix;
	char *subm_jobname;
	char *cancel;
};
typedef struct _oph_rmanager oph_rmanager;

int oph_serve_request(const char* request, const int ncores, const char* sessionid, const char* markerid, const char* error, struct oph_plugin_data *state, int* odb_wf_id, int* task_id, int* light_task_id, int* odb_jobid, char** response, char** jobid, enum oph__oph_odb_job_status *exit_code, int* exit_output);
int initialize_rmanager(oph_rmanager *orm);
int oph_read_rmanager_conf(oph_rmanager *orm);
int oph_form_subm_string(const char *request, const int ncores, char *outfile, short int interactive_subm, oph_rmanager* orm, int jobid, char** cmd);
int oph_get_result_from_file(char* filename, char **response);
int free_oph_rmanager(oph_rmanager *orm);
int oph_cancel_request(int jobid);

#endif /* OPH_RMANAGER_H */

