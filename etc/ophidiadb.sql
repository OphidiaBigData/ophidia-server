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

CREATE TABLE job(idjob INT, idparent INT, markerid INT, workflowid INT, idsession INT, iduser INT, creationdate INT, status TEXT, submissionstring TEXT, timestart INT, timeend INT, nchildrentotal INT, nchildrencompleted INT);
CREATE TABLE jobaccounting(idjob INT, idparent INT, markerid INT, workflowid INT, idsession INT, iduser INT, creationdate INT, status TEXT, submissionstring TEXT, timestart INT, timeend INT, nchildrentotal INT, nchildrencompleted INT);

