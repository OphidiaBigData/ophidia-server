#
#    Ophidia Server
#    Copyright (C) 2012-2022 CMCC Foundation
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
workflowid=${7}
project=${8}
taskname=${9}

# Const
fixString=
LAUNCHER=/usr/local/ophidia/extra/bin/srun
IO_SERVER_LAUNCHER=/usr/local/ophidia/oph-server/etc/script/start_ioserver.sh
JOBNAME="${taskname} ${fixString}${serverid}${taskid}"
SCRIPT_DIR=${HOME}/.ophidia
SCRIPT_FILE=${SCRIPT_DIR}/${serverid}${taskid}.start.sh

# Body
mkdir -p ${SCRIPT_DIR}
> ${SCRIPT_FILE}
echo "#!/bin/bash" >> ${SCRIPT_FILE}
echo "${IO_SERVER_LAUNCHER} ${hostpartition}" >> ${SCRIPT_FILE}
chmod +x ${SCRIPT_FILE}

${LAUNCHER} --mpi=pmi2 --input=none --exclusive --ntasks-per-node=1 -N ${ncores} -o ${log} -e ${log} -J "${JOBNAME}" ${SCRIPT_FILE}
if [ $? -ne 0 ]; then
	echo "Unable to submit ${SCRIPT_FILE}"
	rm ${SCRIPT_FILE}
	exit -1
fi

rm ${SCRIPT_FILE}

exit 0

