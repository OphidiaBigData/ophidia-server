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

#include "oph_session_report.h"

#include "oph_auth.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern char *oph_web_server;
extern char *oph_web_server_location;
extern char *oph_server_location;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

#define OPH_SESSION_REPORT_ITEM "\t\t<P>\n\t\t\t[<A name=\"%d\" href=\"#%d\">%d</A>][%s]&nbsp;&gt;&gt;&nbsp;<B>%s</B><BR/>\n\t\t\t[Date]:&nbsp;%s<BR/>\n\t\t\t[Request]:&nbsp;<A href=\"%s/%d.json\">"OPH_SESSION_OUTPUT_MAIN"</A><SPAN id=\"RID%d\"></SPAN><BR/>\n\t\t\t[Response]:&nbsp;<A href=\"%s/%d.json\">"OPH_SESSION_OUTPUT_MAIN"</A><SPAN id=\"WID%d\"></SPAN><SPAN id=\"CID%d\"></SPAN><SPAN id=\"LID%d\"></SPAN></P>\n"
#define OPH_SESSION_REPORT_LINK1 "\t\t\t<SCRIPT>document.getElementById(\"%cID%d\").innerHTML+='&nbsp;<A name=\"%s\" href=\"%s\">%s</A>';</SCRIPT>\n"
#define OPH_SESSION_REPORT_LINK1_WO_ANCHOR "\t\t\t<SCRIPT>document.getElementById(\"%cID%d\").innerHTML+='&nbsp;<A href=\"%s\">%s</A>';</SCRIPT>\n"
#define OPH_SESSION_REPORT_LINK2 "\t\t\t<SCRIPT>if (document.getElementById(\"%cID%d\").innerHTML.length==0) document.getElementById(\"%cID%d\").innerHTML+='</BR>[%s]:&nbsp;'; document.getElementById(\"%cID%d\").innerHTML+='&nbsp;<A name=\"%s\" href=\"%s\">%s</A>';</SCRIPT>\n"
#define OPH_SESSION_REPORT_LINK2_WO_ANCHOR "\t\t\t<SCRIPT>if (document.getElementById(\"%cID%d\").innerHTML.length==0) document.getElementById(\"%cID%d\").innerHTML+='</BR>[%s]:&nbsp;'; document.getElementById(\"%cID%d\").innerHTML+='&nbsp;<A href=\"%s\">%s</A>';</SCRIPT>\n"

// Thread_unsafe
int oph_session_report_init(const char *session_code)
{
	if (!session_code) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_SERVER_NULL_POINTER;
	}
	// Save the file
	char name[OPH_MAX_STRING_SIZE];
	snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSIONID_TEMPLATE, oph_web_server_location, session_code);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session report creation: '%s'\n", name);
	FILE *file = fopen(name, "w");
	if (!file) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Session report cannot be created\n");
		return OPH_SERVER_IO_ERROR;
	}
	fclose(file);

	return OPH_SERVER_OK;
}

// Thread_unsafe
int oph_session_report_append_command(const char *session_code, const int workflowid, const int markerid, const char *username, const char *data)
{
	if (!session_code || !username || !data) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_SERVER_NULL_POINTER;
	}
	if (markerid <= 0) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong input parameter\n");
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	}

	time_t t1 = time(NULL);
	char *now = ctime(&t1);
	now[strlen(now) - 1] = 0;

	// Update the file
	char name[OPH_MAX_STRING_SIZE];
	snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSIONID_TEMPLATE, oph_web_server_location, session_code);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session report update: '%s'\n", name);
	FILE *file = fopen(name, "a");
	if (!file) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Session report cannot be created\n");
		return OPH_SERVER_IO_ERROR;
	}

	char request[OPH_MAX_STRING_SIZE];
	snprintf(request, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE, oph_web_server, session_code);
	char response[OPH_MAX_STRING_SIZE];
	snprintf(response, OPH_MAX_STRING_SIZE, OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE, oph_web_server, session_code);

	fprintf(file, OPH_SESSION_REPORT_ITEM, markerid, markerid, workflowid, username, data, now, request, workflowid, workflowid, workflowid, response, markerid, markerid, workflowid, workflowid,
		workflowid);

	fclose(file);

	return OPH_SERVER_OK;
}

// Thread_unsafe
int oph_session_report_append_link(const char *session_code, const int workflowid, const char *anchor, const char *linkname, const char *link, const char type)
{
	if (!session_code || !linkname || !link) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return OPH_SERVER_NULL_POINTER;
	}

	if (type == 'C')
		return OPH_SERVER_OK;	// Link to data cubes will not be shown

	// Update the file
	char name[OPH_MAX_STRING_SIZE];
	snprintf(name, OPH_MAX_STRING_SIZE, OPH_SESSIONID_TEMPLATE, oph_web_server_location, session_code);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session report update: '%s'\n", name);
	FILE *file = fopen(name, "a");
	if (!file) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Session report cannot be created\n");
		return OPH_SERVER_IO_ERROR;
	}

	if ((type == 'W') || (type == 'R')) {
		if (anchor)
			fprintf(file, OPH_SESSION_REPORT_LINK1, type, workflowid, anchor, link, linkname);
		else
			fprintf(file, OPH_SESSION_REPORT_LINK1_WO_ANCHOR, type, workflowid, link, linkname);
	} else {
		if (type == 'L')
			snprintf(name, OPH_MAX_STRING_SIZE, "Links");
		else if (type == 'C')
			snprintf(name, OPH_MAX_STRING_SIZE, "Output cubes");
		else
			snprintf(name, OPH_MAX_STRING_SIZE, "Other");
		if (anchor)
			fprintf(file, OPH_SESSION_REPORT_LINK2, type, workflowid, type, workflowid, name, type, workflowid, anchor, link, linkname);
		else
			fprintf(file, OPH_SESSION_REPORT_LINK2_WO_ANCHOR, type, workflowid, type, workflowid, name, type, workflowid, link, linkname);
	}

	fclose(file);

	return OPH_SERVER_OK;
}
