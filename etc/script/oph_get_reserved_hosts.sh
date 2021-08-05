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
id_user=${1}
outfile=${2}

# Body
if [ "${outfile}" == "" ]
then
	echo "Missing input arguments"
	exit 1
fi

if [ "${id_user}" == "" ] || [ "${id_user}" == "0" ]
then
	OUTPUT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "SELECT COUNT(*) FROM hashost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition WHERE reserved;" | sed -n '2{p;q;}'`
else
	OUTPUT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "SELECT COUNT(*) FROM hashost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition WHERE reserved AND iduser = ${id_user};" | sed -n '2{p;q;}'`
fi
if [ $? -ne 0 ]; then
	echo "Query failed"
	exit 2
fi

echo $OUTPUT > $outfile
if [ $? -ne 0 ]; then
	echo "Error in saving output"
	exit 3
fi

exit 0

