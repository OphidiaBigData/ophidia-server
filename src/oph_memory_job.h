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

#ifndef OPH_MEMORY_JOB_H
#define OPH_MEMORY_JOB_H

#include "oph_job_list.h"
#include "oph_server_error.h"

int oph_wf_list_append(oph_job_list * job_info, oph_workflow * wf);
int oph_wf_list_drop(oph_job_list * job_info, int jobid);
int oph_wf_list_drop2(oph_job_list * job_info, int jobid, char remove);

#endif				/* OPH_MEMORY_JOB_H */
