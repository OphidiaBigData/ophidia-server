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

#ifndef OPH_SESSION_REPORT_H
#define OPH_SESSION_REPORT_H

#define OPH_SESSION_OUTPUT_MAIN "%d.json"
#define OPH_SESSION_OUTPUT_EXT "%dext.json"
#define OPH_SESSION_OUTPUT_CHECKPOINT "%d_%s.json"
#define OPH_SESSION_OUTPUT_TASK "%d.json"
#define OPH_SESSION_OUTPUT_CUBE "%d.cube"
#define OPH_SESSION_OUTPUT_LINK "%d.html"

int oph_session_report_init(const char *session_code);
int oph_session_report_append_command(const char *session_code, const int workflowid, const int markerid, const char *username, const char *data);
int oph_session_report_append_link(const char *session_code, const int workflowid, const char *anchor, const char *linkname, const char *link, const char type);

#endif				/* OPH_SESSION_REPORT_H */
