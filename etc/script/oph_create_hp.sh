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

my_dir="$(dirname "$0")"
source $my_dir/oph_odb.sh

# Input parameters
name=${1}
id_user=${2}
parent=${3}

# Body
if [ "${name}" == "" ] || [ "${id_user}" == "" ] || [ "${id_user}" == "0" ] || [ "${parent}" == "" ]
then
	echo "Missing input arguments"
	exit 1
fi

if [ "${parent}" == "auto" ]
then
	OUTPUT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "SELECT idhostpartition FROM hostpartition WHERE (NOT reserved OR iduser = ${id_user});"`
else
	OUTPUT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "SELECT idhostpartition FROM hostpartition WHERE (NOT reserved OR iduser = ${id_user}) AND partitionname = '${parent}';"`
fi
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 2
fi

NUMBER=`echo $OUTPUT | awk '{print NF}'`
if [ "${parent}" == "auto" ]; then
	if [ "${NUMBER}" == "1" ]; then
		echo "No partition available"
		exit 3
	fi
else
	if [ "${NUMBER}" ~= "2" ]; then
		echo "Too partitions with the same name"
		exit 4
	fi
fi
idhostpartition=`echo $OUTPUT | awk '{print $2}'`

mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "START TRANSACTION; INSERT INTO hostpartition (partitionname, hidden) VALUES ('${name}', 1); INSERT INTO hashost (idhostpartition, idhost, importcount) SELECT LAST_INSERT_ID(), idhost, importcount FROM host WHERE idhost IN ( SELECT idhost FROM hashost WHERE idhostpartition = ${idhostpartition} ); COMMIT;"
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 5
fi

exit 0

