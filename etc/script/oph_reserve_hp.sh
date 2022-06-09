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
id_job=${3}
hosts=${4}
type=${5}
outfile=${6}

# Body
if [ "${name}" == "" ] || [ "${id_user}" == "" ] || [ "${id_user}" == "0" ] || [ "${id_job}" == "" ] || [ "${id_job}" == "0" ] || [ "${hosts}" == "" ] || [ "${hosts}" == "0" ] || [ "${type}" == "" ]  || [ "${outfile}" == "" ]
then
	echo "Missing input arguments"
	exit 1
fi

mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "INSERT IGNORE INTO hostpartition (partitionname, iduser, idjob, reserved, hosts, partitiontype) VALUES ('${name}', ${id_user}, ${id_job}, 1, ${hosts}, ${type});"
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 2
fi

OUTPUT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "SELECT idhostpartition FROM hostpartition WHERE partitionname = '${name}'" | sed -n '2{p;q;}'`
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 3
fi

echo $OUTPUT > $outfile
if [ $? -ne 0 ]; then
	echo "Error in saving output"
	exit 4
fi

exit 0

