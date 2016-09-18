/*
    Ophidia Server
    Copyright (C) 2012-2016 CMCC Foundation

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

// User management
#define MYSQL_QUERY_INSERT_USER "INSERT IGNORE INTO `user` (username) VALUES ('%s')"
#define MYSQL_QUERY_INSERT_USER2 "INSERT IGNORE INTO `user` (username,password,name,surname,mail,idcountry,accountcertified) VALUES ('%s',PASSWORD('%s'),%s%s%s,%s%s%s,%s%s%s,%s,1)"
#define MYSQL_QUERY_SELECT_COUNTRY "SELECT idcountry FROM `country` WHERE country = '%s'"
#define MYSQL_QUERY_DELETE_USER "DELETE FROM `user` WHERE username = '%s'"
#define MYSQL_QUERY_UPDATE_USER "UPDATE `user` SET %s = '%s' WHERE username = '%s'"
#define MYSQL_QUERY_UPDATE_USER2 "UPDATE `user` SET %s = PASSWORD('%s') WHERE username = '%s'"

// Session and job management
#define MYSQL_RETRIEVE_USER_ID "SELECT iduser from `user` where username = '%s';"
#define MYSQL_RETRIEVE_SESSION_ID "SELECT idsession FROM session WHERE sessionid = '%s'"
#define MYSQL_RETRIEVE_JOB_ID "SELECT idjob FROM session INNER JOIN job ON session.idsession = job.idsession WHERE sessionid = '%s' AND markerid = %s"
#define MYSQL_RETRIEVE_PARENT_JOB_ID "SELECT idparent FROM job WHERE idjob = %d"
#define MYSQL_RETRIEVE_UNCOMPLETED_JOB_NUMBER "SELECT COUNT(*) FROM job WHERE idparent = %d AND timeend IS NULL"
#define MYSQL_RETRIEVE_MARKER_ID "SELECT markerid FROM job WHERE idjob = %d"
#define MYSQL_RETRIEVE_JOBS_OF_SESSION "SELECT jobc.markerid, jobc.creationdate, jobc.status, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' ORDER BY jobc.markerid"
#define MYSQL_RETRIEVE_SUBMISSION_STRING_OF_JOB "SELECT jobc.markerid, jobc.creationdate, jobc.submissionstring, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' AND jobc.markerid = %d"
#define MYSQL_RETRIEVE_SUBMISSION_STRINGS_OF_SESSION "SELECT jobc.markerid, jobc.creationdate, jobc.submissionstring, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' ORDER BY jobc.markerid"
#define MYSQL_RETRIEVE_SUBMISSION_STRINGS_OF_WORKFLOW "SELECT jobc.markerid, jobc.creationdate, jobc.submissionstring, jobc.workflowid, jobp.markerid FROM (job AS jobc INNER JOIN session ON jobc.idsession = session.idsession) LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob WHERE sessionid = '%s' AND jobc.workflowid = %d ORDER BY jobc.markerid"
#define MYSQL_RETRIEVE_WORKFLOWS_OF_SESSION "SELECT markerid, job.creationdate, status, workflowid, NULL, max FROM job INNER JOIN session ON job.idsession = session.idsession INNER JOIN (SELECT workflowid AS wid, MAX(status) AS max FROM job INNER JOIN session ON job.idsession = session.idsession WHERE sessionid = '%s' AND idparent IS NOT NULL GROUP BY workflowid ORDER BY markerid) AS maxstatus ON workflowid = wid WHERE sessionid = '%s' AND idparent IS NULL ORDER BY markerid"
#define MYSQL_RETRIEVE_WORKFLOWS_OF_USER_SESSION "SELECT markerid, status, workflowid FROM (job INNER JOIN session ON job.idsession = session.idsession) INNER JOIN user ON job.iduser = user.iduser WHERE sessionid = '%s' AND idparent IS NULL AND username = '%s' ORDER BY markerid"
#define MYSQL_RETRIEVE_MARKER_BY_WORKFLOW "SELECT markerid, job.creationdate FROM job INNER JOIN session ON job.idsession = session.idsession WHERE sessionid = '%s' AND workflowid = %d AND idparent IS NULL ORDER BY markerid"
#define MYSQL_RETRIEVE_MARKERS_OF_WORKFLOW_TASKS "SELECT jobc.markerid, jobc.creationdate FROM (job AS jobc LEFT JOIN job AS jobp ON jobc.idparent = jobp.idjob) INNER JOIN session ON jobc.idsession = session.idsession WHERE sessionid = '%s' AND jobc.workflowid = %d AND jobp.idparent IS NULL ORDER BY jobc.markerid"
#define MYSQL_RETRIEVE_WORKFLOW_BY_MARKER "SELECT workflowid, job.creationdate FROM job INNER JOIN session ON job.idsession = session.idsession WHERE sessionid = '%s' AND markerid = %d"

#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_LABEL "LOCK TABLES session WRITE; UPDATE session SET label = '%s' WHERE idsession = %d; UNLOCK TABLES;"

// Job update
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION_FOLDER "INSERT INTO `folder` (`idparent`, `foldername`) VALUES (1, '%s')"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_SESSION "INSERT INTO `session` (`iduser`, `sessionid`, `idfolder`) VALUES (%d, '%s', %d); UPDATE session SET label = creationdate WHERE idsession = LAST_INSERT_ID();"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB "INSERT INTO `job` (`iduser`, `idsession`, `markerid`, `status`, `submissionstring`) VALUES (%d, %d, '%s', '%s', '%s')"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_PARENT "INSERT INTO `job` (`iduser`, `idsession`, `markerid`, `status`, `submissionstring`, `nchildrentotal`, `nchildrencompleted`, `workflowid`) VALUES (%d, %d, '%s', '%s', '%s', %d, 0, '%s')"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_CHILD "INSERT INTO `job` (`iduser`, `idsession`, `markerid`, `status`, `submissionstring`, `idparent`, `workflowid`) VALUES (%d, %d, '%s', '%s', '%s', '%s', '%s')"

#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_CHILDREN_NUMBER "UPDATE job SET nchildrentotal=%d WHERE idjob=%d"	// Used in case of UNLIMITED

#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_1 "UPDATE job SET status='%s' WHERE idjob=%d"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_2 "UPDATE job SET status='%s', timestart=NOW() WHERE idjob=%d AND timestart IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_3 "UPDATE job SET status='%s', timeend=NOW() WHERE idjob=%d AND timeend IS NULL"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_4 "UPDATE job SET status=CONCAT(status,'_ERROR'), timeend=NOW() WHERE idjob=%d AND timeend IS NULL"

#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_1 "LOCK TABLES job WRITE; UPDATE job SET status='%s', nchildrencompleted=%d WHERE idjob=%d; UNLOCK TABLES;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_2 "LOCK TABLES job WRITE; UPDATE job SET status='%s', nchildrencompleted=%d, timestart=NOW() WHERE idjob=%d AND timestart IS NULL; UNLOCK TABLES;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_3 "LOCK TABLES job WRITE; UPDATE job SET status='%s', nchildrencompleted=%d, timeend=NOW() WHERE idjob=%d AND timeend IS NULL; UNLOCK TABLES;"
#define MYSQL_QUERY_UPDATE_OPHIDIADB_JOB_STATUS_PARENT_4 "LOCK TABLES job WRITE; UPDATE job SET status=CONCAT(status,'_ERROR'), nchildrencompleted=%d, timeend=NOW() WHERE idjob=%d AND timeend IS NULL; UNLOCK TABLES;"

#define MYSQL_QUERY_DELETE_OPHIDIADB_JOB "DELETE FROM `job` WHERE idjob=%d"

// Not used
#define OPHIDIADB_DATACUBE_LIST "SELECT iddatacube, datacubename FROM datacube"

#endif				/* OPH_OPHIDIADB_QUERY_H */
