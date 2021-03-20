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
taskid=${1}
ncores=${2}
log=${3}
submissionstring=${4}
queue=${5}
serverid=${6}
workflowid=${7}
project=${8}

# Const
fixString=
FRAMEWORK_PATH=/usr/local/ophidia/oph-cluster/oph-analytics-framework
LAUNCHER=/usr/local/ophidia/extra/bin/srun

# Body
mkdir -p ${HOME}/.ophidia
> ${HOME}/.ophidia/${serverid}${taskid}.submit.sh
echo "#!/bin/bash" >> ${HOME}/.ophidia/${serverid}${taskid}.submit.sh
echo "${FRAMEWORK_PATH}/bin/oph_analytics_framework \"${submissionstring}\"" >> ${HOME}/.ophidia/${serverid}${taskid}.submit.sh
chmod +x ${HOME}/.ophidia/${serverid}${taskid}.submit.sh

MPI_TYPE=--mpi=pmi2
if [ ${ncores} -eq 1 ]
then
	if [[ ${submissionstring} = *"operator=oph_script;"* || ${submissionstring} = *"operator=oph_generic;"* || ${submissionstring} = *"operator=oph_cdo;"* ]]
	then
		MPI_TYPE=--mpi=none
	fi
fi

${LAUNCHER} ${MPI_TYPE} --input=none -n ${ncores} -o ${log} -e ${log} -J ${fixString}${serverid}${taskid} ${HOME}/.ophidia/${serverid}${taskid}.submit.sh
if [ $? -ne 0 ]; then
	echo "Unable to submit ${HOME}/.ophidia/${serverid}${taskid}.submit.sh"
	exit -1
fi

rm ${HOME}/.ophidia/${serverid}${taskid}.submit.sh

exit 0

