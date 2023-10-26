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
myhost=`hostname`
myport=3306
myuser=ophidia
mypassword=ophidia2022
mymemory=16384
numnodes=1
export PREFIX=/scratch/shared/
export MYSQLENV=mysql-env
export CNFDIR=$(realpath "$(dirname "$0")")
export TMP=$PREFIX/tmp;
export SPACK_USER_CACHE_PATH=$PREFIX/spack/tmp;
sed -i "s|# build_jobs: 16|build_jobs: 2|g" $SPACK_ROOT/etc/spack/defaults/config.yaml
echo "[LOG] OPHIDIA COMPONENTS INSTALLATION"
spack install ophidia-primitives
spack install ophidia-io-server
spack install ophidia-analytics-framework
spack install ophidia-server
export OPHIDIA_PRIMITIVES=`spack location -i ophidia-primitives`
export OPHIDIA_IOSERVER=`spack location -i ophidia-io-server`
export OPHIDIA_FRAMEWORK=`spack location -i ophidia-analytics-framework`
export OPHIDIA_SERVER=`spack location -i ophidia-server`
echo "[LOG] CONDA ENVIRONMENT CREATION"
wget https://repo.anaconda.com/archive/Anaconda3-2022.10-Linux-x86_64.sh
bash Anaconda3-2022.10-Linux-x86_64.sh
conda create python=3.7 --prefix=$PREFIX/$MYSQLENV -y
source $CONDA_PREFIX/etc/profile.d/conda.sh
conda activate $PREFIX/$MYSQLENV

echo "[LOG] PYOPHIDIA INSTALLATION IN THE ENVIRONMENT: $MYSQLENV"
conda install -c conda-forge -y pyophidia

echo "[LOG] MYSQL INSTALLATION IN THE ENVIRONMENT: $MYSQLENV"
conda install -y mysql

echo "[LOG] MYSQL CONFIGURATION"
cd $PREFIX/$MYSQLENV
mkdir etc
mkdir -p var/lib/mysql
mkdir -p var/log/mysql/mysql
mkdir -p var/run/mysqld
mkdir -p tmp
mkdir ophidia-primitives
cd $PREFIX/$MYSQLENV/ophidia-primitives/
ln -s $OPHIDIA_PRIMITIVES/lib/ lib
cp $CNFDIR/my.cnf.template $PREFIX/$MYSQLENV/etc/my.cnf
sed -i "s|\$PORT|${myport}|g" $PREFIX/$MYSQLENV/etc/my.cnf
sed -i "s|\$USER|${myuser}|g" $PREFIX/$MYSQLENV/etc/my.cnf
sed -i "s|\$PASSWORD|${mypassword}|g" $PREFIX/$MYSQLENV/etc/my.cnf
sed -i "s|\$PREFIX|$PREFIX|g" $PREFIX/$MYSQLENV/etc/my.cnf
sed -i "s|\$MYSQLENV|$MYSQLENV|g" $PREFIX/$MYSQLENV/etc/my.cnf

echo "[LOG] STARTING MYSQL SERVER..."
cd $PREFIX/$MYSQLENV
bin/mysqld --defaults-file=$PREFIX/$MYSQLENV/etc/my.cnf --user=$USER --initialize-insecure
bin/mysqld_safe --defaults-file=$PREFIX/$MYSQLENV/etc/my.cnf &
sleep 5
cp $CNFDIR/mysql.sql.template $CNFDIR/mysql.sql
sed -i "s|\$USER|${myuser}|g" $CNFDIR/mysql.sql
sed -i "s|\$PASSWORD|${mypassword}|g" $CNFDIR/mysql.sql
bin/mysql -u root --skip-password < $CNFDIR/mysql.sql
sed -i "s|###||g" $PREFIX/$MYSQLENV/etc/my.cnf
chmod 600 $PREFIX/$MYSQLENV/etc/my.cnf

bin/mysql --defaults-file=$PREFIX/$MYSQLENV/etc/my.cnf ophidiadb < $OPHIDIA_FRAMEWORK/etc/ophidiadb.sql
spack load gsl
bin/mysql -u root -p${mypassword} mysql < $OPHIDIA_PRIMITIVES/etc/create_func.sql

echo "[LOG] CHECK SRUN INSTALLATION"
if ! command -v srun > $CNFDIR/slurm_path.txt
then
    if ! spack location -i slurm
    then
        $CNFDIR/slurm-conf.sh
    fi
    export SLURM_PATH=`spack location -i slurm`
else
    SRUN_PATH=$(cat $CNFDIR/slurm_path.txt)
    tmp=$(dirname $SRUN_PATH)
    export SLURM_PATH=${tmp%/*}
fi
echo "[LOG] SLURM INSTALLED IN $SLURM_PATH"
echo "[LOG] OPHIDIA SERVER CONFIGURATION"
sed -i "s|127.0.0.1|${myhost}|g" $OPHIDIA_SERVER/etc/ophidiadb.conf
sed -i "s|3306|${myport}|g" $OPHIDIA_SERVER/etc/ophidiadb.conf
sed -i "s|root|${myuser}|g" $OPHIDIA_SERVER/etc/ophidiadb.conf
sed -i "s|abcd|${mypassword}|g" $OPHIDIA_SERVER/etc/ophidiadb.conf
sed -i "s|127.0.0.1|${myhost}|g" $OPHIDIA_SERVER/etc/server.conf
sed -i "s|OPH_EXTRA_LOCATION=/usr/local/ophidia/extra|OPH_EXTRA_LOCATION=${SLURM_PATH}|g" $OPHIDIA_SERVER/etc/server.conf
sed -i "s|OPH_IOSERVER_LOCATION=/usr/local/ophidia/oph-cluster/oph-io-server|OPH_IOSERVER_LOCATION=${OPHIDIA_IOSERVER}|g" $OPHIDIA_SERVER/etc/server.conf
echo "ENABLE_CLUSTER_DEPLOYMENT=yes" >> $OPHIDIA_SERVER/etc/server.conf
echo "ENABLE_CLUSTER_INCREASE=yes" >> $OPHIDIA_SERVER/etc/server.conf
sed -i "s|127.0.0.1|${myhost}|g" $OPHIDIA_SERVER/etc/script/start_ioserver.sh
sed -i "s|3306|${myport}|g" $OPHIDIA_SERVER/etc/script/start_ioserver.sh
sed -i "s|root|${myuser}|g" $OPHIDIA_SERVER/etc/script/start_ioserver.sh
sed -i "s|abcd|${mypassword}|g" $OPHIDIA_SERVER/etc/script/start_ioserver.sh
sed -i "s|65001|65000|g" $OPHIDIA_SERVER/etc/script/oph_ioserver.conf.template
if [ $numnodes -eq 1 ]; then
        sed -i "s|--exclusive||g" $OPHIDIA_SERVER/etc/script/oph_start.sh
fi

cd $OPHIDIA_SERVER
mkdir -p log
mkdir -p etc/cert
cd $OPHIDIA_SERVER/etc/cert
cp $CNFDIR/cert.sh $OPHIDIA_SERVER/etc/cert/cert.sh
./cert.sh
spack stage ophidia-server
spack cd ophidia-server

cp -r authz $OPHIDIA_SERVER

echo "[LOG] OPHIDIA ANALYTICS FRAMEWORK CONFIGURATION"
sed -i "s|127.0.0.1|${myhost}|g" $OPHIDIA_FRAMEWORK/etc/oph_configuration
sed -i "s|3306|${myport}|g" $OPHIDIA_FRAMEWORK/etc/oph_configuration
sed -i "s|root|${myuser}|g" $OPHIDIA_FRAMEWORK/etc/oph_configuration
sed -i "s|abcd|${mypassword}|g" $OPHIDIA_FRAMEWORK/etc/oph_configuration
sed -i "s|1024|${mymemory}|g" $OPHIDIA_FRAMEWORK/etc/oph_configuration
sed -i "s|127.0.0.1|${myhost}|g" $OPHIDIA_FRAMEWORK/etc/oph_soap_configuration

mkdir -p $HOME/.ophidia/
chmod 700 $HOME/.ophidia/
echo "[mysql]" >> $HOME/.my.cnf
echo "user=${myuser}" >> $HOME/.my.cnf
echo "password=${mypassword}" >> $HOME/.my.cnf
cd $OPHIDIA_FRAMEWORK
mkdir -p html/sessions
mkdir -p log

echo "[LOG] MYSQL SERVER SHUTDOWN"
cd $PREFIX/$MYSQLENV
bin/mysqladmin -u root shutdown -pophidia2022
conda deactivate
