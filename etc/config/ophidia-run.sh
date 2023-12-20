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

set -e

if [ $# -gt 1 ]; then
	export PREFIX=$1
else
	echo "[LOG] SET PREFIX TO $PWD/share"
	mkdir -p share
	export PREFIX=$PWD/share
fi

export MYSQLENV=mysql-env
export SLURM_CONF=$HOME/.ophidia/etc/slurm.conf

cd `spack location -i munge`
echo "[LOG] STARTING MUNGE..."
sbin/munged -S $HOME/.ophidia/var_run_munge/munge.socket.2
cd `spack location -i slurm`
echo "[LOG] STARTING SLURM..."
sbin/slurmd
sbin/slurmctld
echo "[LOG] STARTING MYSQL..."
cd $CONDA_PREFIX
bin/mysqld_safe --defaults-file=$PREFIX/$MYSQLENV/etc/my.cnf &
echo "[LOG] STARTING OPHIDIA SERVER..."
cd `spack location -i ophidia-server`
bin/oph_server -d 2>&1 > /dev/null < /dev/null &
echo "[LOG] OPHIDIA IS RUNNING (check $PWD/log/server.log)"

