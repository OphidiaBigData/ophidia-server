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

#Fixed arguments
taskid=0
hostpartition="fixedTest"
idhostpartition=1
serverid="1"

# Const
IO_SERVER_LAUNCHER=$HOME/install/ophidia/oph-server/etc/script/start_ioserver_multi.sh
SERVER_LAUNCHER=$HOME/install/ophidia/oph-server/etc/script/start_server.sh
myhost=`hostname`
echo ${COMPSS_MASTER_NODE}
echo ${COMPSS_WORKER_NODES}

module load anaconda3/2020.02
source activate $HOME/mysql-env

#Check if master node
if [ $myhost == ${COMPSS_MASTER_NODE} ]; then
        echo "Start master node"
        #Start mysql
        echo "Start MySQL server"
        $HOME/mysql-env/bin/mysqld_safe --defaults-file=$HOME/mysql-env/etc/my.cnf &

        sleep 5
        
        # Run server
        echo "Run server on ${myhost}"
        $HOME/install/ophidia/oph-server/etc/script/start_server.sh 1
        if [ $? -ne 0 ]; then
                echo "Unable to start Ophidia server"
                rm ${HOME}/.ophidia/${serverid}${taskid}.io.sh
                $HOME/mysql-env/bin/mysqladmin -u root shutdown -pophidia2022
                exit -1
        fi
        sleep 5
else #Worker node
        echo "Start worker node"
        # Setup I/O server env
        echo "Setup I/O server script for ${myhost}"
        mkdir -p ${HOME}/.ophidia
        > ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh
        echo "#!/bin/bash" >> ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh
        echo "${IO_SERVER_LAUNCHER} ${idhostpartition} ${COMPSS_MASTER_NODE}" >> ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh
        chmod +x ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh

        # Run I/O server
        echo "Run I/O server ${myhost}"
        ssh ${myhost} ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh
        if [ $? -ne 0 ]; then
                echo "Unable to start ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh"
                #rm ${HOME}/.ophidia/${myhost}${serverid}${taskid}.io.sh
                exit -1
        fi

fi

exit 0
