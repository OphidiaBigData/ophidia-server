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

LOGIN_NODE=127.0.0.1
CONFIGURATION=/etc/.my.cnf
IO_SERVER_PATH=/usr/local/ophidia/oph-cluster/oph-io-server

# Body
string=`hostname --all-fqdns`
searchstring='-ib'
temp=${string%$searchstring*}
myhost=`echo ${temp} | tail -c 5`'-ib'
myid=`echo ${temp} | tail -c 4 | bc`

mysql --default-file=${CONFIGURATION} -P 3306 -h ${LOGIN_NODE} ophidiadb -e "UPDATE host SET status='up' WHERE hostname='${myhost}'; INSERT INTO hashost(idhostpartition, idhost) VALUES (${hpid}, (SELECT idhost FROM host WHERE hostname='${myhost}'));"

rm -rf ${IO_SERVER_PATH}/data${myid}/*
mkdir -p ${IO_SERVER_PATH}/data${myid}/{var,log}

${IO_SERVER_PATH}/bin/oph_io_server -i $myid >> ${IO_SERVER_PATH}/data${myid}/log/server.log 2>>&1 < /dev/null

