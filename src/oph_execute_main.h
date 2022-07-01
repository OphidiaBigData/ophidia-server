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

//gsoap oph service name:                 oph
//gsoap oph service namespace:            urn:oph
//gsoap oph service method-protocol:      ophExecuteMain SOAP
//gsoap oph service method-style:         ophExecuteMain document
//gsoap oph service method-action:        ophExecuteMain ""
//gsoap oph service method-documentation: ophExecuteMain Execute a command using Ophidia analytics framework

struct oph__ophResponse {
	xsd__string jobid;
	xsd__string response;
	xsd__int error;
};
int oph__ophExecuteMain(xsd__string ophExecuteMainRequest, struct oph__ophResponse *ophExecuteMainResponse);
