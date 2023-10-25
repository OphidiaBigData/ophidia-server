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

# Const
OPHDB_NAME=ophidiadb
OPHDB_PORT=33306
OPHDB_LOGIN=ophidia
OPHDB_PWD=ophidia2022
SERVER_PATH=$HOME/install/ophidia/oph-server/

# Get hostname 
myhost=`hostname`
OPHDB_HOST=${myhost}

# Replace hostname in configuration files
echo "Replace host ${myhost} in configuration files"
sed -i "/OPHDB_HOST/c\OPHDB_HOST=${myhost}" $SERVER_PATH/etc/ophidiadb.conf
sed -i "/HOST/c\HOST=${myhost}" $SERVER_PATH/etc/server.conf
sed -i "/OPHDB_HOST/c\OPHDB_HOST=${myhost}" $HOME/install/oph-analytics-framework/etc/oph_configuration
sed -i "/DIMDB_HOST/c\DIMDB_HOST=${myhost}" $HOME/install/oph-analytics-framework/etc/oph_configuration
sed -i "/SOAP_HOST/c\SOAP_HOST=${myhost}" $HOME/install/oph-analytics-framework/etc/oph_soap_configuration

# Reset host list
$HOME/mysql-env/bin/mysql -u ${OPHDB_LOGIN} -p${OPHDB_PWD} -h ${OPHDB_HOST} -P ${OPHDB_PORT} ${OPHDB_NAME} -e "START TRANSACTION; UPDATE host SET status = 'down', importcount = 0 WHERE status = 'up'; DELETE FROM hashost WHERE idhostpartition = ${hpid}; COMMIT;"

#Save hostname in user file
> $HOME/.ophidia/server.run
echo "$myhost" >> $HOME/.ophidia/server.run

echo "Starting server ${myhost}"
$SERVER_PATH/bin/oph_server -d 2>&1 > /dev/null < /dev/null &

#echo "Exit from server ${myhost}"

#exit 0
