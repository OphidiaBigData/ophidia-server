#!/bin/bash
export SLURM_CONF=$HOME/.ophidia/etc/slurm.conf
cd `spack location -i munge`
echo "[LOG] STARTING MUNGE..."
sbin/munged -S $HOME/.ophidia/var_run_munge/munge.socket.2
#munge -n -S $HOME/.ophidia/var_run_munge/munge.socket.2
cd `spack location -i slurm`
echo "[LOG] STARTING SLURM..."
sbin/slurmd
sbin/slurmctld
cd $CONDA_PREFIX
bin/mysqld_safe --defaults-file=/scratch/shared/mysql-env/etc/my.cnf &
cd `spack location -i ophidia-server`
bin/oph_server -d 2>&1 > /dev/null < /dev/null &