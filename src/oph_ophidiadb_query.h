/*
    Ophidia Server
    Copyright (C) 2012-2021 CMCC Foundation

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OPH_OPHIDIADB_QUERY_H
#define OPH_OPHIDIADB_QUERY_H

#include "oph_gather.h"

// User management
#ifdef OPH_DB_SUPPORT
#define MYSQL_QUERY_INSERT_USER "INSERT IGNORE INTO `user` (username) VALUES ('%s')"
#ifdef INTERFACE_TYPE_IS_SSL
#define MYSQL_QUERY_INSERT_USER2 "INSERT IGNORE INTO `user` (username,password,name,surname,mail,idcountry,accountcertified,maxhosts) VALUES ('%s','%s',%s%s%s,%s%s%s,%s%s%s,%s,1,%d)"
#else
#define MYSQL_QUERY_INSERT_USER2 "INSERT IGNORE INTO `user` (username,password,name,surname,mail,idcountry,accountcertified,maxhosts) VALUES ('%s',PASSWORD('%s'),%s%s%s,%s%s%s,%s%s%s,%s,1,%d)"
#endif
#else
#define MYSQL_QUERY_INSERT_USER "INSERT OR IGNORE INTO `user` (username) VALUES ('%s')"
#ifdef INTERFACE_TYPE_IS_SSL
#define MYSQL_QUERY_INSERT_USER2 "INSERT OR IGNORE INTO `user` (username,password,name,surname,mail,idcountry,accountcertified,maxhosts) VALUES ('%s','%s',%s%s%s,%s%s%s,%s%s%s,%s,1,%d)"
#else
#define MYSQL_QUERY_INSERT_USER2 "INSERT OR IGNORE INTO `user` (username,password,name,surname,mail,idcountry,accountcertified,maxhosts) VALUES ('%s',PASSWORD('%s'),%s%s%s,%s%s%s,%s%s%s,%s,1,%d)"
#endif
#endif
#define MYSQL_QUERY_SELECT_COUNTRY "SELECT idcountry FROM `country` WHERE name = '%s'"
#define MYSQL_QUERY_DELETE_USER "DELETE FROM `user` WHERE username = '%s'"
#define MYSQL_QUERY_UPDATE_USER "UPDATE `user` SET %s = '%s' WHERE username = '%s'"
#ifdef INTERFACE_TYPE_IS_SSL
#define MYSQL_QUERY_UPDATE_USER2 "UPDATE `user` SET %s = '%s' WHERE username = '%s'"
#else
#define MYSQL_QUERY_UPDATE_USER2 "UPDATE `user` SET %s = PASSWORD('%s') WHERE username = '%s'"
#endif
#define MYSQL_QUERY_SELECT_USER_FROM_MAIL "SELECT `username` FROM `user` WHERE mail = '%s'"

// Session and job management
#define MYSQL_RETRIEVE_USER_ID "SELECT iduser FROM `user` WHERE username = '%s';"
#define MYSQL_RETRIEVE_SESSION_ID "SELECT idsession FROM session WHERE sessionid = '%s'"
#define MYSQL_RETRIEVE_JOB_ID "SELECT idjob FROM session INNER JOIN job ON session.idsession = job.idsession WHERE sessionid = '%s' AND markerid = %s"
#define MYSQL_RETRIEVE_PARENT_JOB_ID "SELECT idparent FROM job WHERE idjob = %d"
#define MYSQL_RETRIEVE_UNCOMPLETED_JOB_NUMBER "SELECT COUNT(*) FROM job WHERE idparent = %d AND timeend IS NULL"
#define MYSQL_RETRIEVE_MARKER_ID "SELECT markerid FROM job WHERE idjob = %d"

#define MYSQL_RETRIEVE_JOBS_OF_SESSION "SELECT jobc.markerid AS jobid, jobc.creationdate, jobc.status, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' UNION SELECT ajobc.markerid AS jobid, ajobc.creationdate, ajobc.status, ajobc.workflowid, ajobp.markerid FROM (jobaccounting AS ajobc INNER JOIN session ON ajobc.idsession = session.idsession) LEFT JOIN jobaccounting AS ajobp ON ajobc.idparent = ajobp.idjob WHERE sessionid = '%s' ORDER BY jobid;"
#define MYSQL_RETRIEVE_SUBMISSION_STRING_OF_JOB "SELECT jobc.markerid AS jobid, jobc.creationdate, jobc.submissionstring, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' AND jobc.markerid = %d UNION SELECT ajobc.markerid AS jobid, ajobc.creationdate, ajobc.submissionstring, ajobc.workflowid, ajobp.markerid FROM (jobaccounting AS ajobc INNER JOIN session ON ajobc.idsession = session.idsession) LEFT JOIN jobaccounting AS ajobp ON ajobc.idparent = ajobp.idjob WHERE sessionid = '%s' AND ajobc.markerid = %d ORDER BY jobid;"
#define MYSQL_RETRIEVE_SUBMISSION_STRINGS_OF_SESSION "SELECT jobc.markerid AS jobid, jobc.creationdate, jobc.submissionstring, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' UNION SELECT ajobc.markerid AS jobid, ajobc.creationdate, ajobc.submissionstring, ajobc.workflowid, ajobp.markerid FROM (jobaccounting AS ajobc INNER JOIN session ON ajobc.idsession = session.idsession) LEFT JOIN jobaccounting AS ajobp ON ajobc.idparent = ajobp.idjob WHERE sessionid = '%s' ORDER BY jobid;"
#define MYSQL_RETRIEVE_SUBMISSION_STRINGS_OF_WORKFLOW "SELECT jobc.markerid AS jobid, jobc.creationdate, jobc.submissionstring, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' AND jobc.workflowid = %d UNION SELECT ajobc.markerid AS jobid, ajobc.creationdate, ajobc.submissionstring, ajobc.workflowid, ajobp.markerid FROM (jobaccounting AS ajobc INNER JOIN session ON ajobc.idsession = session.idsession) LEFT JOIN jobaccounting AS ajobp ON ajobc.idparent = ajobp.idjob WHERE sessionid = '%s' AND ajobc.workflowid = %d ORDER BY jobid;"
#define MYSQL_RETRIEVE_WORKFLOWS_OF_SESSION "SELECT markerid, job.creationdate, status, workflowid, NULL, max FROM job INNER JOIN session ON job.idsession = session.idsession LEFT JOIN (SELECT workflowid AS wid, MAX(status) AS max FROM job INNER JOIN session ON job.idsession = session.idsession WHERE sessionid = '%s' AND idparent IS NOT NULL AND status <> '" OPH_ODB_STATUS_PREFIX "SKIPPED' GROUP BY workflowid ORDER BY markerid) AS maxstatus ON workflowid = wid WHERE sessionid = '%s' AND idparent IS NULL UNION SELECT markerid, ajob.creationdate, status, workflowid, NULL, max FROM jobaccounting AS ajob INNER JOIN session ON ajob.idsession = session.idsession LEFT JOIN (SELECT workflowid AS wid, MAX(status) AS max FROM jobaccounting AS ajob INNER JOIN session ON ajob.idsession = session.idsession WHERE sessionid = '%s' AND ajob.idparent IS NOT NULL AND status <> '" OPH_ODB_STATUS_PREFIX "SKIPPED' GROUP BY workflowid ORDER BY markerid) AS maxstatus ON workflowid = wid WHERE sessionid = '%s' AND ajob.idparent IS NULL ORDER BY markerid;"
#define MYSQL_RETRIEVE_WORKFLOWS_OF_USER_SESSION "SELECT markerid, status, workflowid FROM (job INNER JOIN session ON job.idsession = session.idsession) INNER JOIN user ON job.iduser = user.iduser WHERE sessionid = '%s' AND idparent IS NULL AND username = '%s' UNION SELECT markerid, status, workflowid FROM (jobaccounting AS ajob INNER JOIN session ON ajob.idsession = session.idsession) INNER JOIN user ON ajob.iduser = user.iduser WHERE sessionid = '%s' AND idparent IS NULL AND username = '%s' ORDER BY markerid;"
#define MYSQL_RETRIEVE_MARKER_BY_WORKFLOW "SELECT markerid, job.creationdate FROM job INNER JOIN session ON job.idsession = session.idsession WHERE sessionid = '%s' AND workflowid = %d AND idparent IS NULL UNION SELECT markerid, ajob.creationdate FROM jobaccounting AS ajob INNER JOIN session ON ajob.idsession = session.idsession WHERE sessionid = '%s' AND workflowid = %d AND idparent IS NULL ORDER BY markerid;"
#define MYSQL_RETRIEVE_MARKERS_OF_WORKFLOW_TASKS "SELECT jobc.markerid AS jobid, jobc.creationdate FROM (job AS jobc LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob) INNER JOIN session ON jobc.idsession = session.idsession WHERE sessionid = '%s' AND jobc.workflowid = %d AND jobp.idparent IS NULL UNION SELECT ajobc.markerid AS jobid, ajobc.creationdate FROM (jobaccounting AS ajobc LEFT JOIN jobaccounting AS ajobp ON ajobc.idparent = ajobp.idjob) INNER JOIN session ON ajobc.idsession = session.idsession WHERE sessionid = '%s' AND ajobc.workflowid = %d AND ajobp.idparent IS NULL ORDER BY jobid;"
#define MYSQL_RETRIEVE_WORKFLOW_BY_MARKER "SELECT workflowid, job.creationdate FROM job INNER JOIN session ON job.idsession = session.idsession WHERE sessionid = '%s' AND markerid = %d UNION SELECT workflowid, ajob.creationdate FROM jobaccounting AS ajob INNER JOIN session ON ajob.idsession = session.idsession WHERE sessionid = '%s' AND markerid = %d;"
#define MYSQL_RETRIEVE_PROGRESS_RATIO_OF_WORKFLOW "SELECT job.idjob, job.creationdate, NULL, hostxdatacube*fragmentxdb AS fragment, COUNT(*) AS current FROM session INNER JOIN job ON session.idsession = job.idsession INNER JOIN task ON job.idjob = task.idjob INNER JOIN datacube ON idoutputcube = datacube.iddatacube INNER JOIN fragment ON datacube.iddatacube = fragment.iddatacube WHERE sessionid='%s' AND workflowid=%d GROUP BY fragment.iddatacube UNION SELECT ajob.idjob, ajob.creationdate, NULL, hostxdatacube*fragmentxdb AS fragment, COUNT(*) AS current FROM session INNER JOIN jobaccounting AS ajob ON session.idsession = ajob.idsession INNER JOIN task ON ajob.idjob = task.idjob INNER JOIN datacube ON idoutputcube = datacube.iddatacube INNER JOIN fragment ON datacube.iddatacube = fragment.iddatacube WHERE sessionid='%s' AND workflowid=%d GROUP BY fragment.iddatacube;"
#define MYSQL_RETRIEVE_CREATION_DATE_OF_WORKFLOW "SELECT idjob, job.creationdate, status, workflowid FROM session INNER JOIN job ON session.idsession = job.idsession WHERE sessionid='%s' AND workflowid=%d AND idparent IS NULL UNION SELECT idjob, ajob.creationdate, status, workflowid FROM session INNER JOIN jobaccounting AS ajob ON session.idsession = ajob.idsession WHERE sessionid='%s' AND workflowid=%d AND idparent IS NULL;"

#ifdef OPH_DB_SUPPORT
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_LABEL "LOCK TABLES session WRITE; UPDATE session SET label = '%s' WHERE idsession = %d; UNLOCK TABLES;"
#else
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_LABEL "BEGIN TRANSACTION; UPDATE session SET label = '%s' WHERE idsession = %d; COMMIT;"
#endif

// Job update
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_FOLDER "INSERT INTO `folder` (`idparent`, `foldername`) VALUES (1, '%s')"
#ifdef OPH_DB_SUPPORT
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION "INSERT INTO `session` (`iduser`, `sessionid`, `idfolder`) VALUES (%d, '%s', %d); UPDATE session SET label = creationdate WHERE idsession = LAST_INSERT_ID();"
#else
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION "INSERT INTO `session` (`iduser`, `sessionid`, `idfolder`) VALUES (%d, '%s', %d); UPDATE session SET label = creationdate WHERE idsession = last_insert_rowid();"
#endif
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB "INSERT INTO `job` (`idjob`, `iduser`, `idsession`, `markerid`, `status`, `submissionstring`) VALUES (%d, %d, %d, '%s', '%s', '%s')"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_PARENT "INSERT INTO `job` (`idjob`, `iduser`, `idsession`, `markerid`, `status`, `submissionstring`, `nchildrentotal`, `nchildrencompleted`, `workflowid`) VALUES (%d, %d, %d, '%s', '%s', '%s', %d, 0, '%s')"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_CHILD "INSERT INTO `job` (`idjob`, `iduser`, `idsession`, `markerid`, `status`, `submissionstring`, `idparent`, `workflowid`) VALUES (%d, %d, %d, '%s', '%s', '%s', '%s', '%s')"

#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_CHILDREN_NUMBER "UPDATE job SET nchildrentotal=%d WHERE idjob=%d"	// Used in case of UNLIMITED

#ifdef OPH_DB_SUPPORT
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_1 "UPDATE job SET status='%s' WHERE idjob=%d"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_2 "UPDATE job SET status='%s', timestart=NOW() WHERE idjob=%d AND timestart IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_3 "UPDATE job SET status='%s', timeend=NOW() WHERE idjob=%d AND timeend IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_4 "UPDATE job SET status=CONCAT(status,'_ERROR'), timeend=NOW() WHERE idjob=%d AND timeend IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_1 "LOCK TABLES job WRITE; UPDATE job SET status='%s', nchildrencompleted=%d WHERE idjob=%d; UNLOCK TABLES;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_2 "LOCK TABLES job WRITE; UPDATE job SET status='%s', nchildrencompleted=%d, timestart=NOW() WHERE idjob=%d AND timestart IS NULL; UNLOCK TABLES;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_3 "LOCK TABLES job WRITE; UPDATE job SET status='%s', nchildrencompleted=%d, timeend=NOW() WHERE idjob=%d AND timeend IS NULL; UNLOCK TABLES;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_4 "LOCK TABLES job WRITE; UPDATE job SET status=CONCAT(status,'_ERROR'), nchildrencompleted=%d, timeend=NOW() WHERE idjob=%d AND timeend IS NULL; UNLOCK TABLES;"
#else
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_1 "UPDATE job SET status='%s' WHERE idjob=%d"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_2 "UPDATE job SET status='%s', timestart=strftime('%%Y-%%m-%%d %%H-%%M-%%S','now') WHERE idjob=%d AND timestart IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_3 "UPDATE job SET status='%s', timeend=strftime('%%Y-%%m-%%d %%H-%%M-%%S','now') WHERE idjob=%d AND timeend IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_1 "BEGIN TRANSACTION; UPDATE job SET status='%s', nchildrencompleted=%d WHERE idjob=%d; COMMIT;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_2 "BEGIN TRANSACTION; UPDATE job SET status='%s', nchildrencompleted=%d, timestart=strftime('%%Y-%%m-%%d %%H-%%M-%%S','now') WHERE idjob=%d AND timestart IS NULL; COMMIT;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_3 "BEGIN TRANSACTION; UPDATE job SET status='%s', nchildrencompleted=%d, timeend=strftime('%%Y-%%m-%%d %%H-%%M-%%S','now') WHERE idjob=%d AND timeend IS NULL; COMMIT;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_4 "BEGIN TRANSACTION; UPDATE job SET status=status || '_ERROR', nchildrencompleted=%d, timeend=strftime('%%Y-%%m-%%d %%H-%%M-%%S','now') WHERE idjob=%d AND timeend IS NULL; COMMIT;"
#endif

#define MYSQL_QUERY_DELETE_OPHIDIADB_JOB "DELETE FROM `job` WHERE idjob=%d"

// Not used
#define OPHIDIADB_DATACUBE_LIST "SELECT iddatacube, datacubename FROM datacube"

// Host partitions
#define OPHIDIADB_RETRIEVE_PARTITION "SELECT idhostpartition FROM hostpartition WHERE (NOT reserved OR iduser = %d)"
#define OPHIDIADB_CREATE_PARTITION "INSERT INTO hostpartition (partitionname, hidden) VALUES ('%s', 1);"
#define OPHIDIADB_FILL_PARTITION "INSERT INTO hashost (idhostpartition, idhost, importcount) SELECT LAST_INSERT_ID(), idhost, importcount FROM host WHERE idhost IN ( SELECT idhost FROM hashost WHERE idhostpartition = %d );"
#define OPHIDIADB_DESTROY_PARTITION "DELETE FROM hostpartition WHERE partitionname = '%s' AND hidden = 1;"
#ifdef OPH_DB_SUPPORT
#define OPHIDIADB_RESERVE_PARTITION "INSERT IGNORE INTO hostpartition (partitionname, iduser, idjob, reserved, hosts, partitiontype) VALUES ('%s', %d, %d, 1, %d, %d);"
#else
#define OPHIDIADB_RESERVE_PARTITION "INSERT OR IGNORE INTO hostpartition (partitionname, iduser, idjob, reserved, hosts, partitiontype) VALUES ('%s', %d, %d, 1, %d, %d);"
#endif
#define OPHIDIADB_RETRIEVE_RESERVED_PARTITION "SELECT idhostpartition, idjob, partitiontype FROM hostpartition WHERE partitionname = '%s' AND iduser = %d;"
#define OPHIDIADB_RELEASE_HOSTS "UPDATE host SET status = 'down', importcount = 0 WHERE idhost IN (SELECT idhost FROM hashost WHERE idhostpartition = %d);"
#define OPHIDIADB_RELEASE_PARTITION "DELETE FROM hostpartition WHERE idhostpartition = %d;"
#define OPHIDIADB_RETRIEVE_TOTAL_HOSTS "SELECT COUNT(*) FROM host;"
#define OPHIDIADB_RETRIEVE_RESERVED_HOSTS "SELECT COUNT(*) FROM hashost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition WHERE reserved AND iduser = %d;"
#define OPHIDIADB_RETRIEVE_TOTAL_RESERVED_HOSTS "SELECT COUNT(*) AS hosts FROM hashost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition WHERE reserved;"
#define OPHIDIADB_RETRIEVE_RESERVED_PARTITIONS "SELECT COUNT(*) AS hosts, partitionname, NULL, STRCMP(MIN(status),'up') AS partitionstatus, partitiontype, creationdate FROM host INNER JOIN hashost ON host.idhost = hashost.idhost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition WHERE reserved AND iduser = %d AND partitionname LIKE '%%%s%%' GROUP BY hostpartition.idhostpartition ORDER BY partitionname;"
#define OPHIDIADB_RETRIEVE_USERS "SELECT size, NULL, username, maxhosts FROM user LEFT JOIN (SELECT iduser, COUNT(*) AS size FROM hashost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition WHERE reserved GROUP BY iduser) AS hosts ON user.iduser = hosts.iduser WHERE username LIKE '%%%s%%' ORDER BY username;"
#define OPHIDIADB_RETRIEVE_TOTAL_RESERVED_PARTITIONS "SELECT COUNT(*) AS hosts, partitionname, username, STRCMP(MIN(status),'up') AS partitionstatus, partitiontype, creationdate FROM host INNER JOIN hashost ON host.idhost = hashost.idhost INNER JOIN hostpartition ON hashost.idhostpartition = hostpartition.idhostpartition INNER JOIN user ON hostpartition.iduser = user.iduser WHERE reserved AND username LIKE '%%%s%%' AND partitionname LIKE '%%%s%%' GROUP BY hostpartition.idhostpartition ORDER BY username, partitionname;"

// Job accounting
#define MYSQL_QUERY_RETRIEVE_LAST_ID "SELECT MAX(idjob) FROM jobaccounting;"
#define MYSQL_QUERY_CLEAN_JOB_TABLE "DELETE FROM `job` WHERE idjob > %d;"
#define MYSQL_QUERY_COPY_JOB "INSERT INTO `jobaccounting` SELECT * FROM `job` WHERE idjob = %d;"
#define MYSQL_QUERY_COPY_JOB_PARENT "INSERT INTO `jobaccounting` SELECT * FROM `job` WHERE idjob = %d OR idparent = %d;"
#define MYSQL_QUERY_COPY_JOB_CHILD "INSERT INTO `jobaccounting` SELECT * FROM `job` WHERE idparent = %d;"

#ifdef OPH_DB_SUPPORT
#define MYSQL_QUERY_DROP_JOB "LOCK TABLES job WRITE; DELETE FROM `job` WHERE idjob = %d; UNLOCK TABLES;"
#define MYSQL_QUERY_DROP_JOB_PARENT "LOCK TABLES job WRITE; DELETE FROM `job` WHERE idjob = %d OR idparent = %d; UNLOCK TABLES;"
#define MYSQL_QUERY_DROP_JOB_CHILD "LOCK TABLES job WRITE; DELETE FROM `job` WHERE idparent = %d; UNLOCK TABLES;"
#else
#define MYSQL_QUERY_DROP_JOB "BEGIN TRANSACTION; DELETE FROM `job` WHERE idjob = %d; COMMIT;"
#define MYSQL_QUERY_DROP_JOB_PARENT "BEGIN TRANSACTION; DELETE FROM `job` WHERE idjob = %d OR idparent = %d; COMMIT;"
#define MYSQL_QUERY_DROP_JOB_CHILD "BEGIN TRANSACTION; DELETE FROM `job` WHERE idparent = %d; COMMIT;"
#endif

#ifndef OPH_DB_SUPPORT
#define SQLITE_SWITCH_ON_FOREIGN_KEYS "PRAGMA foreign_keys=ON;"
#endif

#endif				/* OPH_OPHIDIADB_QUERY_H */
