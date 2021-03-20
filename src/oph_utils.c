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

#include "oph_utils.h"
#include "oph_gather.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern char *oph_server_location;
extern char *oph_server_protocol;
extern char *oph_server_host;
extern char *oph_server_port;

#define OPH_SERVER_STD_HTTP_RESPONSE "<html>\
<head><title>\
Web Services\
</title></head>\
<body>\
<h1>Web Services</h1>\
<table width='100%%' border='1'>\
<tr>\
<td>\
Ophidia WS-I\
</td>\
</tr>\
<tr>\
<td>\
<table border='0'><tr><td>Address:</td><td>%s://%s:%s/</td></tr><tr><td>WSDL:</td><td><a href='%s://%s:%s/?wsdl'>%s://%s:%s/?wsdl</a></td></tr></table>\
</td>\
</tr>\
</table>\
</body>\
</html>"

//Thread_unsafe
int oph_mkdir(const char *name)
{
	return oph_mkdir2(name, 0755);
}

int oph_mkdir2(const char *name, mode_t mode)
{
	struct stat st;
	int res = stat(name, &st);
	if (!res)
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Session directory '%s' already exist\n", name);
	else if (res == -1) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session directory creation: '%s'\n", name);
		if (mkdir(name, mode)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Session directory cannot be created\n");
			return OPH_SERVER_IO_ERROR;
		}
	} else {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Session directory cannot be created\n");
		return OPH_SERVER_IO_ERROR;
	}

	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_http_get(struct soap *soap)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Received a HTTP GET Request\n");
	if (!oph_server_protocol || !oph_server_host || !oph_server_port) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Return SOAP Fault\n");
		return SOAP_GET_METHOD;
	}
	FILE *fd = NULL;
	char buffer[OPH_MAX_STRING_SIZE] = { '\0' }, *s = strchr(soap->path, '?');
	if (!s) {
		snprintf(buffer, OPH_MAX_STRING_SIZE, OPH_SERVER_STD_HTTP_RESPONSE, oph_server_protocol, oph_server_host, oph_server_port, oph_server_protocol, oph_server_host, oph_server_port,
			 oph_server_protocol, oph_server_host, oph_server_port);
		soap->http_content = "text/html";
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Return HTML description of web service\n");
	} else if (strcmp(s, "?wsdl")) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Return SOAP Fault\n");
		return SOAP_GET_METHOD;
	} else {
		snprintf(buffer, OPH_MAX_STRING_SIZE, OPH_SERVER_WSDL, oph_server_location);
		fd = fopen(buffer, "rb");
		if (!fd) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Return HTTP 'Not Found' error\n");
			return 404;
		}
		soap->http_content = "text/xml";
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Return WSDL description of web service\n");
	}
	soap_response(soap, SOAP_FILE);
	size_t r;
	if (fd) {
		for (;;) {
			r = fread(soap->tmpbuf, 1, sizeof(soap->tmpbuf), fd);
			if (!r)
				break;
			if (soap_send_raw(soap, soap->tmpbuf, r))
				break;
		}
		fclose(fd);
	} else {
		r = snprintf(soap->tmpbuf, sizeof(soap->tmpbuf), "%s", buffer);
		soap_send_raw(soap, soap->tmpbuf, r);
	}
	soap_end_send(soap);
	return SOAP_OK;
}
