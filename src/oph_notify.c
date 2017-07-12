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

#include "oph_auth.h"
#include "oph_plugin.h"
#include "oph_workflow_engine.h"
#include "oph_json_library.h"

#ifdef INTERFACE_TYPE_IS_GSI
#include "gsi.h"
#endif

extern char *oph_user_notifier;
extern char *oph_json_location;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph__oph_notify(struct soap *soap, xsd__string data, xsd__string output_json, xsd__int * response)
{
	char _host[OPH_SHORT_STRING_SIZE];
	if (!soap->host || !strlen(soap->host)) {
		if (soap->ip)
			snprintf(_host, OPH_SHORT_STRING_SIZE, "%d.%d.%d.%d", (int) (soap->ip >> 24) & 0xFF, (int) (soap->ip >> 16) & 0xFF, (int) (soap->ip >> 8) & 0xFF, (int) soap->ip & 0xFF);
		else
			strcpy(_host, "NONE");
	} else
		snprintf(_host, OPH_SHORT_STRING_SIZE, "%s", soap->host);

	char *userid = (char *) soap->userid;
	pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "N0: received a notification from %s:%d sent by user '%s'\n", _host, soap->port, userid ? userid : "NONE");

	if (!response) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N0: null pointer\n");
		return SOAP_OK;
	}

	*response = OPH_SERVER_OK;

#ifdef INTERFACE_TYPE_IS_GSI
	struct gsi_plugin_data *gsi_data = (struct gsi_plugin_data *) soap_lookup_plugin(soap, GSI_PLUGIN_ID);
	if (!gsi_data) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "N0: error on lookup gsi plugin struct\n");
		*response = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}
	userid = gsi_data->client_identity;
#endif

	if (!userid || strcasecmp(userid, oph_user_notifier)) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N0: the user '%s' cannot send any notification\n", userid ? userid : "");
		*response = OPH_SERVER_AUTH_ERROR;
		return SOAP_OK;
	}
#ifdef INTERFACE_TYPE_IS_SSL
	int res;
	pthread_mutex_lock(&global_flag);
	res = oph_auth_user(userid, soap->passwd, _host);
	pthread_mutex_unlock(&global_flag);
	if (res) {
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N0: received wrong credentials: %s %s\n", userid, soap->passwd ? soap->passwd : "NONE");
		*response = OPH_SERVER_AUTH_ERROR;
		return SOAP_OK;
	}
#endif

	struct oph_plugin_data *state = NULL;
	if (!(state = (struct oph_plugin_data *) soap_lookup_plugin((struct soap *) soap, OPH_PLUGIN_ID))) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "N0: error on lookup plugin struct\n");
		*response = OPH_SERVER_SYSTEM_ERROR;
		return SOAP_OK;
	}

	int jobid;
	pthread_mutex_lock(&global_flag);
	jobid = ++*state->jobid;
	pthread_mutex_unlock(&global_flag);

	oph_json *oper_json = NULL;
	while (output_json && strlen(output_json)) {

		if (oph_json_from_json_string(&oper_json, output_json)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N%d: error in parsing JSON Response\n", jobid);
			break;
		}

		char session_code[OPH_MAX_STRING_SIZE];
		*session_code = 0;
		if (oper_json->source && oper_json->source->values && oper_json->source->values[0])
			strcpy(session_code, oper_json->source->values[0]);
		else {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N%d: session code cannot be extracted\n", jobid);
			break;
		}

		char str_markerid[OPH_SHORT_STRING_SIZE];
		*str_markerid = 0;
		if (oper_json->source && oper_json->source->values && oper_json->source->values[2])
			strcpy(str_markerid, oper_json->source->values[2]);
		else {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N%d: marker id cannot be extracted\n", jobid);
			break;
		}

		char filename[OPH_MAX_STRING_SIZE];
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_JSON_RESPONSE_FILENAME, oph_json_location, session_code, str_markerid);
		if (oph_json_to_json_file(oper_json, filename)) {
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "N%d: error in saving JSON Response\n", jobid);
			break;
		}

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "N%d: JSON Response saved\n", jobid);
		break;
	}
	oph_json_free(oper_json);

	return oph_workflow_notify(state, 'N', jobid, data, output_json, (int *) response);
}
