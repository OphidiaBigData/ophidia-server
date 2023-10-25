#!/bin/bash
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

# Start mysql
module load anaconda3/2020.02
source activate $HOME/mysql-env
myhost=`hostname`
OPHDB_NAME=ophidiadb
OPHDB_PORT=33306
OPHDB_LOGIN=ophidia
OPHDB_PWD=ophidia2022
OPHDB_HOST=${COMPSS_MASTER_NODE}

#Check if master node
if [ $myhost == ${COMPSS_MASTER_NODE} ]; then
        # Stop services
        pkill oph_server
        $HOME/mysql-env/bin/mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -s -N -e "DELETE FROM hashost; UPDATE host set status='down';"
        $HOME/mysql-env/bin/mysqladmin -u root shutdown -p${OPHDB_PWD}
else
        # Stop services
        pkill oph_io_server
#       rm ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh
fi

exit 0