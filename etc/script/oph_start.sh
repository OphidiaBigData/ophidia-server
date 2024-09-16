#
#    Ophidia Server
#    Copyright (C) 2012-2024 CMCC Foundation
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

my_dir=$(dirname "$0")
. $my_dir/../server.conf

# Input parameters
taskid=${1}
nhosts=${2}
log=${3}
hostpartition=${4}
queue=${5}
serverid=${6}
workflowid=${7}
project=${8}
taskname=${9}

# Const
fixString=
LAUNCHER=${OPH_EXTRA_LOCATION}/bin/srun
BLAUNCHER=${OPH_EXTRA_LOCATION}/bin/sbatch
IO_SERVER_LAUNCHER=${OPH_SERVER_LOCATION}/etc/script/start_ioserver.sh
IO_SERVER_FLUSHER=${OPH_SERVER_LOCATION}/etc/script/stop_ioserver.sh
JOBNAME="${taskname} ${fixString}${serverid}${taskid}"
SCRIPT_DIR=${HOME}/.ophidia
START_SCRIPT_FILE=${SCRIPT_DIR}/${serverid}${taskid}.start.sh
STOP_SCRIPT_FILE=${SCRIPT_DIR}/${serverid}${taskid}.stop.sh

# Body
mkdir -p ${SCRIPT_DIR}
> ${START_SCRIPT_FILE}
echo "#!/bin/bash" >> ${START_SCRIPT_FILE}
echo "${IO_SERVER_LAUNCHER} ${hostpartition}" >> ${START_SCRIPT_FILE}
chmod +x ${START_SCRIPT_FILE}

JID="$(${BLAUNCHER} --input=none --ntasks-per-node=1 -N ${nhosts} -o ${log} -e ${log} -J "${JOBNAME}" ${START_SCRIPT_FILE})"
if [ $? -ne 0 ]; then
	echo "Unable to submit ${START_SCRIPT_FILE}"
	rm -f ${START_SCRIPT_FILE}
	exit 1
fi

> ${STOP_SCRIPT_FILE}
echo "#!/bin/bash" >> ${STOP_SCRIPT_FILE}
echo "${IO_SERVER_FLUSHER} ${hostpartition} ${JID##* }" >> ${STOP_SCRIPT_FILE}
chmod +x ${STOP_SCRIPT_FILE}

echo "Schedule the flushing procedure"
${LAUNCHER} -input=none -n 1 -o ${log} -e ${log} -J "${JOBNAME}" -d singleton ${STOP_SCRIPT_FILE}
if [ $? -ne 0 ]; then
	echo "Unable to submit ${STOP_SCRIPT_FILE}"
	rm -f ${START_SCRIPT_FILE}
	rm -f ${STOP_SCRIPT_FILE}
	exit 1
fi

rm -f ${START_SCRIPT_FILE}
rm -f ${STOP_SCRIPT_FILE}

exit 0

