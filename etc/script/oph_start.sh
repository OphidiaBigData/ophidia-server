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
taskid=${1}
ncores=${2}
log=${3}
hostpartition=${4}
queue=${5}
serverid=${6}

# Const
fixString=
SERVER_PATH=/usr/local/ophidia/oph-server
LAUNCHER=/usr/local/ophidia/extra/bin/srun

# Body
mkdir -p ${HOME}/.ophidia
> ${HOME}/.ophidia/${serverid}${taskid}.start.sh
echo "#!/bin/bash" >> ${HOME}/.ophidia/${serverid}${taskid}.start.sh
echo "${SERVER_PATH}/etc/script/start_ioserver.sh ${hostpartition}" >> ${HOME}/.ophidia/${serverid}${taskid}.start.sh
chmod +x ${HOME}/.ophidia/${serverid}${taskid}.start.sh

${LAUNCHER} --mpi=pmi2 --input=none -n ${ncores} -o ${log} -e ${log} -J ${fixString}${serverid}${taskid} ${HOME}/.ophidia/${serverid}${taskid}.start.sh
if [ $? -ne 0 ]; then
        echo "Unable to submit ${HOME}/.ophidia/${serverid}${taskid}.start.sh"
        exit 1
fi

rm ${HOME}/.ophidia/${serverid}${taskid}.start.sh

exit 0
