#
#    Ophidia Server
#    Copyright (C) 2012-2021 CMCC Foundation
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
hpid=${1}
odb_host=${2}

# Const
OPHDB_NAME=ophidiadb
OPHDB_PORT=33306
OPHDB_LOGIN=ophidia
OPHDB_PWD=ophidia2022
IO_SERVER_PATH=$HOME/install/oph-io-server/bin/oph_io_server
IO_SERVER_TEMPLATE=$HOME/install/oph-io-server/etc/oph_ioserver.conf.template

# Body
myhost=`hostname`
OPHDB_HOST=${odb_host}

COUNT=`$HOME/mysql-env/bin/mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -s -N -e "SELECT idhost FROM host WHERE hostname like '${myhost}%'"`
myid=$COUNT
echo $myid

echo "Add host ${myhost} to partition ${hpid}"
res=1
retry=5
echo "$HOME/mysql-env/bin/mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e START TRANSACTION; UPDATE host SET status = 'up' WHERE hostname like ${myhost}%; INSERT INTO hashost(idhostpartition, idhost) VALUES (${hpid}, (SELECT idhost FROM host WHERE hostname like ${myhost}%)); COMMIT;"
while [ $res -ne 0 ]; do
$HOME/mysql-env/bin/mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "START TRANSACTION; UPDATE host SET status = 'up' WHERE hostname like '${myhost}%'; INSERT INTO hashost(idhostpartition, idhost) VALUES (${hpid}, (SELECT idhost FROM host WHERE hostname like '${myhost}%')); COMMIT;"
res=$?
if [ $res -ne 0 ]; then
        echo "Query failed, retry in 5 seconds"
        retry="$((retry-1))"
        if [ $retry -eq 0 ]; then
                echo "Unable to run query"
                exit 1
        fi
        #exit 1
fi
sleep 5
done

echo "OphidiaDB updated"

rm -rf ${HOME}/.ophidia/data${myid}/*
mkdir -p ${HOME}/.ophidia/data${myid}/{var,log}

cp -f ${IO_SERVER_TEMPLATE} ${HOME}/.ophidia/data${myid}/oph_ioserver.conf
sed -i "s|\$HOME|${HOME}|g" ${HOME}/.ophidia/data${myid}/oph_ioserver.conf

echo "Starting I/O server ${myid}"
${IO_SERVER_PATH} -i ${myid} -c ${HOME}/.ophidia/data${myid}/oph_ioserver.conf > ${HOME}/.ophidia/data${myid}/log/server.log 2>&1 < /dev/null &


exit 0
