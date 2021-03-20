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

#include "oph_memory_job.h"
#include "oph_gather.h"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_wf_list_append(oph_job_list * job_info, oph_workflow * wf)
{
	int k;
	oph_job_info *item = (oph_job_info *) malloc(sizeof(oph_job_info));
	if (!item) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to alloc memory for '%s'\n", wf->name);
		return OPH_SERVER_ERROR;
	}

	item->wf = wf;

	pthread_mutex_lock(&global_flag);
	k = oph_insert_into_job_list(job_info, item);
	pthread_mutex_unlock(&global_flag);

	if (k) {
		if (k == OPH_JOB_LIST_FARM_FULL) {
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "The workflow has been queued.\n");
			return OPH_SERVER_NO_RESPONSE;	// The workflow has been queued
		} else if (k == OPH_JOB_LIST_FULL)
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Reached the maximum number of pending workflows.\n");
		else
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to store data for '%s' in server memory\n", wf->name);
		free(item);
		return OPH_SERVER_ERROR;
	}

	return OPH_SERVER_OK;
}

int oph_wf_list_drop(oph_job_list * job_info, int jobid)
{
	int result;
	oph_job_info *item, *prev;
	pthread_mutex_lock(&global_flag);
	item = oph_find_job_in_job_list(job_info, jobid, &prev);
	if (!item) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Error in searching data related to job %d.\n", jobid);
		pthread_mutex_unlock(&global_flag);
		return OPH_SERVER_OK;
	}
	result = oph_delete_from_job_list(job_info, item, prev);
	pthread_mutex_unlock(&global_flag);
	if (result)
		return OPH_SERVER_ERROR;
	return OPH_SERVER_OK;
}
