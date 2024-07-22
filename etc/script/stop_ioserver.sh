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

my_dir=$(dirname "$0")
. $my_dir/../server.conf
. $my_dir/../ophidiadb.conf

# Input parameters
hpid=${1}
myid=${2}

# Const
SCRIPT_DIR=${HOME}/.ophidia

# Body
myhost="$(cat ${SCRIPT_DIR}/host/${myid}.address)"
if [ $? -ne 0 ]; then
	echo "Address of target host cannot be retrieved"
	exit 1
fi

echo "Remove host ${myhost} from partition ${hpid} (inserted by job ${myid})"
mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "START TRANSACTION; UPDATE host SET status = 'down', importcount = 0 WHERE hostname='${myhost}'; DELETE FROM hashost WHERE idhostpartition = ${hpid} AND idhost IN (SELECT idhost FROM host WHERE hostname = '${myhost}'); COMMIT;"
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 1
fi
echo "OphidiaDB updated"

rm -rf ${SCRIPT_DIR}/data${myid}/*
rm -rf ${SCRIPT_DIR}/host/${myid}.address

exit 0

