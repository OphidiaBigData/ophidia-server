--
--    Ophidia Server
--    Copyright (C) 2012-2020 CMCC Foundation
--
--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

-- Use:
--
-- > sqlite ophidiadb
-- sqlite> .read ophidiadb.sql

CREATE TABLE IF NOT EXISTS session(
	idsession INTEGER PRIMARY KEY NOT NULL,
	iduser INTEGER NOT NULL,
	idfolder INTEGER DEFAULT NULL,
	sessionid VARCHAR(1024) NOT NULL,
	label VARCHAR(256) DEFAULT NULL,
	creationdate INTEGER DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS job(
	idjob INTEGER PRIMARY KEY NOT NULL,
	idparent INTEGER DEFAULT NULL,
	markerid INTEGER NOT NULL,
	workflowid INTEGER DEFAULT NULL,
	idsession INTEGER DEFAULT NULL,
	iduser INTEGER,
	creationdate INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
	status VARCHAR(64) NOT NULL,
	submissionstring VARCHAR(2048) DEFAULT NULL,
	timestart INTEGER DEFAULT NULL,
	timeend INTEGER DEFAULT NULL,
	nchildrentotal INTEGER DEFAULT NULL,
	nchildrencompleted INTEGER DEFAULT NULL,
	CONSTRAINT `idparent_j` FOREIGN KEY (`idparent`) REFERENCES `job` (`idjob`) ON DELETE CASCADE ON UPDATE CASCADE,
 	CONSTRAINT `idsession_j` FOREIGN KEY (`idsession`) REFERENCES `session` (`idsession`) ON DELETE CASCADE ON UPDATE CASCADE);
CREATE TABLE IF NOT EXISTS jobaccounting(
	idjob INTEGER PRIMARY KEY NOT NULL,
	idparent INTEGER DEFAULT NULL,
	markerid INTEGER NOT NULL,
	workflowid INTEGER DEFAULT NULL,
	idsession INTEGER DEFAULT NULL,
	iduser INTEGER DEFAULT NULL,
	creationdate INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
	status VARCHAR(64) NOT NULL,
	submissionstring VARCHAR(2048) DEFAULT NULL,
	timestart INTEGER DEFAULT NULL,
	timeend INTEGER DEFAULT NULL,
	nchildrentotal INTEGER DEFAULT NULL,
	nchildrencompleted INTEGER DEFAULT NULL,
	CONSTRAINT `idparent_ja` FOREIGN KEY (`idparent`) REFERENCES `jobaccounting` (`idjob`) ON DELETE CASCADE ON UPDATE CASCADE,
 	CONSTRAINT `idsession_ja` FOREIGN KEY (`idsession`) REFERENCES `session` (`idsession`) ON DELETE SET NULL ON UPDATE CASCADE);
PRAGMA foreign_keys=ON;

