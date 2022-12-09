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

#ifndef OPH_PLUGIN_H
#define OPH_PLUGIN_H

#include "stdsoap2.h"
#define OPH_PLUGIN_ID "OPH_PLUGIN-1.0"

#include "oph_job_list.h"
#include "oph_trash.h"

struct oph_plugin_data {
	int *jobid;
	int is_copy;
	char *serverid;
	oph_job_list *job_info;
	int authorization;
	oph_trash *trash;
};

int oph_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

#endif				/* OPH_PLUGIN_H */
