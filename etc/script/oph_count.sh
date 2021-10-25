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
WORK_FILE=${1}

# Body
COUNT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -s -N -e "SELECT COUNT(*) FROM host WHERE status = 'down' AND idhost NOT IN (SELECT idhost FROM hashost);" 2> ${WORK_FILE}`
ERROR=`wc -l < ${WORK_FILE}`
if [ $ERROR -gt 1 ]; then
	echo "Query failed"
	exit -1
fi
echo $COUNT > ${WORK_FILE}
exit 0

