#
#    Ophidia Server
#    Copyright (C) 2012-2018 CMCC Foundation
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

# Input parameters
hpid=$1

OPHIDIADB_SERVER_HOST=127.0.0.1
OPHIDIADB_SERVER_PORT=3306
OPHIDIADB_NAME=ophidiadb
OPHIDIADB_CLIENT_CONFIGURATION=$HOME/.my.cnf
IO_SERVER_PATH=/usr/local/ophidia/oph-cluster/oph-io-server

# Body
string=`hostname --all-fqdns`
searchstring='-ib'
temp=${string%$searchstring*}
myhost=`echo ${temp} | tail -c 5`'-ib'
myid=`echo ${temp} | tail -c 4 | bc`

echo "Updating info related to host ${myhost} in OphidiaDB"
mysql --defaults-file=${OPHIDIADB_CLIENT_CONFIGURATION} -h ${OPHIDIADB_SERVER_HOST} -P ${OPHIDIADB_SERVER_PORT} ${OPHIDIADB_NAME} -e "UPDATE host SET status='up' WHERE hostname='${myhost}'; INSERT INTO hashost(idhostpartition, idhost) VALUES (${hpid}, (SELECT idhost FROM host WHERE hostname='${myhost}'));"
echo "OphidiaDB updated"

rm -rf ${IO_SERVER_PATH}/data${myid}/*
mkdir -p ${IO_SERVER_PATH}/data${myid}/{var,log}

echo "Starting I/O server ${myid}"
${IO_SERVER_PATH}/bin/oph_io_server -i ${myid} > ${IO_SERVER_PATH}/data${myid}/log/server.log 2>&1 < /dev/null
echo "Exit from IO server ${myid}"

