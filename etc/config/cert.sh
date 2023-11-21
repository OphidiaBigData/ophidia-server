#
#    Ophidia Server
#    Copyright (C) 2012-2023 CMCC Foundation
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#!/bin/bash
openssl req -newkey rsa:1024 \
    -passout pass:abcd \
    -subj "/" -sha1 \
    -keyout rootkey.pem \
    -out rootreq.pem
openssl x509 -req -in rootreq.pem \
    -passin pass:abcd \
    -sha1 -extensions v3_ca \
    -signkey rootkey.pem \
    -out rootcert.pem
cat rootcert.pem rootkey.pem  > cacert.pem

openssl req -newkey rsa:1024 \
    -passout pass:abcd \
    -subj "/" -sha1 \
    -keyout serverkey.pem \
    -out serverreq.pem
openssl x509 -req \
    -in serverreq.pem \
    -passin pass:abcd \
    -sha1 -extensions usr_cert \
    -CA cacert.pem  \
    -CAkey cacert.pem \
    -CAcreateserial \
    -out servercert.pem
cat servercert.pem serverkey.pem rootcert.pem > myserver.pem
