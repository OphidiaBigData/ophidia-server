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

//gsoap oph  service method-protocol:   oph_notify SOAP
//gsoap oph  service method-style:      oph_notify document
//gsoap oph  service method-action:     oph_notify ""
//gsoap oph  service method-documentation: oph_notify Notify a job status update

int oph__oph_notify(xsd__string oph_notify_data, xsd__string oph_notify_json, xsd__int * oph_notify_response);
