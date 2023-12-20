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
export PREFIX=/scratch/shared/
export CNFDIR=$(realpath "$(dirname "$0")")
echo "[LOG] MUNGE AND SLURM INSTALLATION"
spack install slurm
spack load munge
spack load slurm
export MUNGE_DIR=`spack location -i munge`
export SLURM_DIR=`spack location -i slurm`
cd $HOME/.ophidia/
mkdir -p var/log/slurm
mkdir -p var/run/slurm
mkdir -p var/spool/slurm
mkdir -p var/spool/slurmd
mkdir -p var/log/slurmctld
mkdir -p etc

echo "[LOG] MUNGE CONFIGURATION"
cd $MUNGE_DIR
sbin/mungekey
mkdir -p var/run
mkdir -p var/run/munge
chmod 700 var/log/munge
chmod 700 etc/munge
chmod 755 $PREFIX
ln -s $MUNGE_DIR/var/run/munge $HOME/.ophidia/var_run_munge

echo "[LOG] SLURM CONFIGURATION"
cd $SLURM_DIR
cp $CNFDIR/slurm.conf.template $HOME/.ophidia/etc/slurm.conf
sed -i "s|\$HOME|$HOME|g" $HOME/.ophidia/etc/slurm.conf
sed -i "s|\$USER|$USER|g" $HOME/.ophidia/etc/slurm.conf
PROCS=`grep -c ^processor /proc/cpuinfo`
sed -i "s|\$PROCS|$PROCS|g" $HOME/.ophidia/etc/slurm.conf
export SLURM_CONF=$HOME/.ophidia/etc/slurm.conf
echo "[LOG] SLURM CONFIGURED"
