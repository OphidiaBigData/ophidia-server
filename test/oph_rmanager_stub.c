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

#include "oph_rmanager.h"

#include "oph_known_operators.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_cond_t waiting_flag;
#endif

#define OPH_DEFAULT_REPLY "{\
    \"source\": {\
        \"description\": \"Ophidia Data Source\",\
        \"srckey\": \"oph\",\
        \"srcname\": \"Ophidia\",\
        \"producer\": \"oph-test\",\
        \"keys\": [\
            \"Session Code\",\
            \"Workflow\",\
            \"Marker\",\
            \"JobID\"\
        ],\
        \"values\": [\
            \"2163617111829230661500484334207798\",\
            \"124\",\
            \"261\",\
            \"http://127.0.0.1/ophidia/sessions/2163617111829230661500484334207798/experiment?124#261\"\
        ]\
    },\
    \"consumers\": [\
        \"oph-test\"\
    ],\
    \"responseKeyset\": [\
        \"fs\",\
        \"status\"\
    ],\
    \"response\": [\
        {\
            \"objkey\": \"fs\",\
            \"objclass\": \"grid\",\
            \"objcontent\": [\
                {\
                    \"title\": \"/testdata\",\
                    \"rowvalues\": [\
                        [\
                            \"f\",\
                            \"/test.test\"\
                        ]\
                    ],\
                    \"rowkeys\": [\
                        \"T\",\
                        \"OBJECT\"\
                    ],\
                    \"rowfieldtypes\": [\
                        \"string\",\
                        \"string\"\
                    ]\
                }\
            ]\
        },\
        {\
            \"objkey\": \"status\",\
            \"objclass\": \"text\",\
            \"objcontent\": [\
                {\
                    \"title\": \"SUCCESS\"\
                }\
            ]\
        }\
    ]\
}"

int oph_system(const char *command, const char *error, struct oph_plugin_data *state, int delay, char blocking, int (*postprocess)(int), int id)
{
	UNUSED(error);
	UNUSED(state);
	UNUSED(delay);
	UNUSED(blocking);
	UNUSED(id);

	if (!command) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
	}

	return RMANAGER_SUCCESS;
}

void *_oph_sleep(char **response)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
#endif

	if (!response)
		return NULL;

	sleep(1);

	pthread_mutex_lock(&global_flag);
	*response = strdup(OPH_DEFAULT_REPLY);
	if (!*response)
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
	pthread_cond_broadcast(&waiting_flag);
	pthread_mutex_unlock(&global_flag);

	return NULL;
}

int oph_serve_request(const char *request, const int ncores, const char *sessionid, const char *markerid, const char *error, struct oph_plugin_data *state, int *odb_wf_id, int *task_id,
		      int *light_task_id, int *odb_jobid, int delay, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, char *username, char *project,
		      char *taskname, int wid)
{
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Incoming request '%s' to run job '%s#%s' with %d cores\n", request, sessionid, markerid, ncores);

	if (exit_code)
		*exit_code = OPH_ODB_STATUS_COMPLETED;
	if (exit_output)
		*exit_output = 1;

	int _ncores = ncores;
	if (ncores < 1) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "The job will be executed with 1!\n");
		_ncores = 1;
	}

	int result;
	if ((result =
	     oph_serve_known_operator(state, request, ncores, sessionid, markerid, odb_wf_id, task_id, light_task_id, odb_jobid, response, jobid_response, exit_code,
				      exit_output, username, project, taskname)) != OPH_SERVER_UNKNOWN)
		return result;

	if (strstr(request, "oph_fs")) {

		if (!odb_wf_id || !task_id) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Missing parameters to identify the task!\n");
			return OPH_SERVER_ERROR;
		}

		oph_job_info *item = NULL, *prev = NULL;
		oph_workflow *wf = NULL;

		pthread_mutex_lock(&global_flag);

		if (!(item = oph_find_job_in_job_list(state->job_info, *odb_wf_id, &prev))) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to find the workflow!\n");
			pthread_mutex_unlock(&global_flag);
			return OPH_SERVER_ERROR;
		}
		wf = item->wf;
		if (wf->tasks[*task_id].response) {
			free(wf->tasks[*task_id].response);
			wf->tasks[*task_id].response = NULL;
		}

		pthread_mutex_unlock(&global_flag);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_t tid;
		pthread_create(&tid, NULL, (void *(*)(void *)) &_oph_sleep, &wf->tasks[*task_id].response);
#else
		_oph_sleep(&wf->tasks[*task_id].response);
#endif
	}

	return OPH_SERVER_OK;
}

int initialize_rmanager(oph_rmanager * orm)
{
	return OPH_SERVER_OK;
}

int oph_read_rmanager_conf(oph_rmanager * orm)
{
	return OPH_SERVER_OK;
}

int oph_form_subm_string(const char *request, const int ncores, char *outfile, short int interactive_subm, oph_rmanager * orm, int jobid, const char *username, const char *project,
			 const char *taskname, int wid, char **cmd, char type)
{
	return OPH_SERVER_OK;
}

int oph_get_result_from_file(char *filename, char **response)
{
	return OPH_SERVER_OK;
}

int oph_get_result_from_file_unsafe(char *filename, char **response)
{
	return OPH_SERVER_OK;
}

int free_oph_rmanager(oph_rmanager * orm)
{
	return OPH_SERVER_OK;
}

int oph_cancel_request(int jobid, const char *username)
{
	return OPH_SERVER_OK;
}

int oph_stop_request(int jobid, const char *username)
{
	return OPH_SERVER_OK;
}

int oph_umount_request(int jobid, const char *username)
{
	return OPH_SERVER_OK;
}

int oph_cancel_all_request(int wid, const char *username)
{
	return OPH_SERVER_OK;
}

int oph_read_job_queue(int **list, char ***username, unsigned int *n)
{
	return OPH_SERVER_OK;
}

int oph_get_available_host_number(int *size, int jobid)
{
	return OPH_SERVER_OK;
}

int oph_detach_task(int id)
{
	return OPH_SERVER_OK;
}

int oph_is_detached_task(int id)
{
	return OPH_SERVER_OK;
}

int oph_remove_detached_task(int id)
{
	return OPH_SERVER_OK;
}

int oph_load_datacube_status(int *jobs, int *tot, int *current, int size, int jobid)
{
	return OPH_SERVER_OK;
}
