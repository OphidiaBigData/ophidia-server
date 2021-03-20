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

#ifndef OPH_UTILS_H
#define OPH_UTILS_H

#include "soapStub.h"
#include "oph_server_error.h"

int oph_mkdir(const char *name);
int oph_mkdir2(const char *name, mode_t mode);
int oph_http_get(struct soap *soap);

#endif				/* OPH_UTILS_H */
