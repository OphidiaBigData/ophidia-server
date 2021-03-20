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

#include "oph_plugin.h"
#include "oph_gather.h"

static void oph_delete(struct soap *soap, struct soap_plugin *p);
static int oph_copy(struct soap *soap, struct soap_plugin *q, struct soap_plugin *p);

int oph_plugin(struct soap *soap, struct soap_plugin *p, void *arg)
{
	if (!soap || !p) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%s: null pointer\n", OPH_PLUGIN_ID);
		return SOAP_NULL;
	}
	if (!arg)
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "%s: no argument used\n", OPH_PLUGIN_ID);
	p->id = OPH_PLUGIN_ID;
	p->data = (void *) malloc(sizeof(struct oph_plugin_data));
	if (!p->data) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%s: not enough memory\n", OPH_PLUGIN_ID);
		return SOAP_EOM;
	}

	((struct oph_plugin_data *) p->data)->jobid = malloc(sizeof(int));
	*((int *) ((struct oph_plugin_data *) p->data)->jobid) = 0;
	((struct oph_plugin_data *) p->data)->is_copy = 0;
	((struct oph_plugin_data *) p->data)->serverid = NULL;
	if (oph_create_job_list(&(((struct oph_plugin_data *) p->data)->job_info)))
		((struct oph_plugin_data *) p->data)->job_info = NULL;
	((struct oph_plugin_data *) p->data)->authorization = 0;
	if (oph_trash_create(&(((struct oph_plugin_data *) p->data)->trash)))
		((struct oph_plugin_data *) p->data)->trash = NULL;

	p->fcopy = oph_copy;
	p->fdelete = oph_delete;
	return SOAP_OK;
}

static int oph_copy(struct soap *soap, struct soap_plugin *dst, struct soap_plugin *src)
{
	if (!soap || !dst || !src) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%s: null pointer\n", OPH_PLUGIN_ID);
		return SOAP_NULL;
	}
	dst->data = (struct oph_plugin_data *) malloc(sizeof(struct oph_plugin_data));
	if (!dst->data) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%s: not enough memory\n", OPH_PLUGIN_ID);
		return SOAP_EOM;
	}

	memcpy(dst->data, (struct oph_plugin_data *) (src->data), sizeof(struct oph_plugin_data));

	if (((struct oph_plugin_data *) src->data)->serverid)
		((struct oph_plugin_data *) dst->data)->serverid = strndup(((struct oph_plugin_data *) src->data)->serverid, OPH_MAX_STRING_SIZE);
	else
		((struct oph_plugin_data *) dst->data)->serverid = NULL;
	((struct oph_plugin_data *) dst->data)->is_copy = 1;
	((struct oph_plugin_data *) dst->data)->job_info = ((struct oph_plugin_data *) src->data)->job_info;
	((struct oph_plugin_data *) dst->data)->trash = ((struct oph_plugin_data *) src->data)->trash;

	return SOAP_OK;

}

static void oph_delete(struct soap *soap, struct soap_plugin *p)
{
	if (!soap || !p) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "%s: null pointer\n", OPH_PLUGIN_ID);
		return;
	}
	if (!((struct oph_plugin_data *) p->data)->is_copy) {
		free(((struct oph_plugin_data *) p->data)->jobid);
		((struct oph_plugin_data *) p->data)->jobid = NULL;

		oph_destroy_job_list(((struct oph_plugin_data *) p->data)->job_info);
		((struct oph_plugin_data *) p->data)->job_info = NULL;

		oph_trash_destroy(((struct oph_plugin_data *) p->data)->trash);
		((struct oph_plugin_data *) p->data)->trash = NULL;
	}
	if (((struct oph_plugin_data *) p->data)->serverid) {
		free(((struct oph_plugin_data *) p->data)->serverid);
		((struct oph_plugin_data *) p->data)->serverid = NULL;
	}
	free(p->data);
	p->data = NULL;
}
