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

# Const
OPHDB_NAME=ophidiadb
OPHDB_HOST=127.0.0.1
OPHDB_PORT=3306
OPHDB_LOGIN=root
OPHDB_PWD=abcd

# Body
COUNT=`mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -s -N -e "SELECT COUNT(*) FROM host WHERE status = 'down';" 2> /tmp/oph_count.log`
ERROR=`wc -l < /tmp/oph_count.log`
if [ $ERROR -gt 1 ]; then
	echo "Query failed"
	exit -1
fi
echo "Found $COUNT available hosts"
exit $COUNT

