#
#    Ophidia Server
#    Copyright (C) 2012-2022 CMCC Foundation
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

my_dir="$(dirname "$0")"
source $my_dir/oph_odb.sh

# Input parameters
hpid=${1}

# Const
IO_SERVER_PATH=/usr/local/ophidia/oph-cluster/oph-io-server/bin/oph_io_server
IO_SERVER_TEMPLATE=/usr/local/ophidia/oph-cluster/oph-io-server/etc/oph_ioserver.conf.template

# Body
# Let us assume there is only one I/O server running on host 127.0.0.2.
# So that, preliminarly, the host has to registered in Ophidia DB as follows
# mysql > use ophidiadb;
# mysql > INSERT INTO host (hostname, cores, memory, status) VALUES ('127.0.0.2',1,1,'down');
myhost="127.0.0.2"
myid=1

echo "Add host ${myhost} to partition ${hpid}"
mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "START TRANSACTION; UPDATE host SET status = 'up' WHERE hostname = '${myhost}'; INSERT INTO hashost(idhostpartition, idhost) VALUES (${hpid}, (SELECT idhost FROM host WHERE hostname = '${myhost}')); COMMIT;"
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 1
fi
echo "OphidiaDB updated"

rm -rf ${HOME}/.ophidia/data${myid}/*
mkdir -p ${HOME}/.ophidia/data${myid}/{var,log}

cp -f ${IO_SERVER_TEMPLATE} ${HOME}/.ophidia/data${myid}/oph_ioserver.conf
sed -i "s|\$HOME|${HOME}|g" ${HOME}/.ophidia/data${myid}/oph_ioserver.conf

echo "Starting I/O server ${myid}"
${IO_SERVER_PATH} -i ${myid} -c ${HOME}/.ophidia/data${myid}/oph_ioserver.conf > ${HOME}/.ophidia/data${myid}/log/server.log 2>&1 < /dev/null
echo "Exit from IO server ${myid}"

echo "Remove host ${myhost} from partition ${hpid}"
mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "START TRANSACTION; UPDATE host SET status = 'down', importcount = 0 WHERE hostname='${myhost}'; DELETE FROM hashost WHERE idhostpartition = ${hpid} AND idhost IN (SELECT idhost FROM host WHERE hostname = '${myhost}'); COMMIT;"
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 1
fi
echo "OphidiaDB updated"

rm -rf ${HOME}/.ophidia/data${myid}/*

exit 0

