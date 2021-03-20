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

#ifndef OPH_ODB_JOB_H
#define OPH_ODB_JOB_H

#include "soapStub.h"
#include "hashtbl.h"
#include "oph_ophidiadb.h"

#include "oph_gather.h"

const char *oph_odb_convert_status_to_str(enum oph__oph_odb_job_status status);

int oph_odb_update_session_label(ophidiadb * oDB, const char *sessionid, char *label);
int oph_odb_update_session_label_unsafe(ophidiadb * oDB, const char *sessionid, char *label);

int oph_odb_update_job_table(ophidiadb * oDB, char *markerid, char *task_string, char *status, int id_user, int id_session, int nchildren, int *id_job, char *parentid, char *workflowid);
int oph_odb_create_job(ophidiadb * oDB, char *task_string, HASHTBL * task_tbl, int nchildren, int *id_job);
int oph_odb_create_job_unsafe(ophidiadb * oDB, char *task_string, HASHTBL * task_tbl, int nchildren, int *id_job);

int oph_odb_change_job_status(int idjob, enum oph__oph_odb_job_status status);
int oph_odb_enque_job(int idjob);
int oph_odb_start_job(int idjob);
int oph_odb_stop_job(int idjob);
int oph_odb_abort_job(int idjob);
int oph_odb_remove_job(int idjob);

int oph_odb_set_job_status(int id_job, enum oph__oph_odb_job_status status, ophidiadb * oDB);
int oph_odb_enque_job_fast(int idjob, ophidiadb * oDB);
int oph_odb_start_job_fast(int idjob, ophidiadb * oDB);
int oph_odb_stop_job_fast(int idjob, ophidiadb * oDB);
int oph_odb_abort_job_fast(int idjob, ophidiadb * oDB);
int oph_odb_remove_job_fast(int idjob, ophidiadb * oDB);

int oph_odb_set_job_status_and_nchildrencompleted(int id_job, enum oph__oph_odb_job_status status, int nchildren, int force_nchildren_saving, ophidiadb * oDB);

int oph_odb_get_parent_job_id(int idjob, int *parent_idjob, ophidiadb * oDB);
int oph_odb_get_uncompleted_job_number(int parent_idjob, int *n, ophidiadb * oDB);

int oph_odb_retrieve_user_id(ophidiadb * oDB, char *username, int *id_user);
int oph_odb_retrieve_user_id_unsafe(ophidiadb * oDB, char *username, int *id_user);

int oph_odb_update_session_table(ophidiadb * oDB, char *sessionid, int id_user, int *id_session);
int oph_odb_update_session_table_unsafe(ophidiadb * oDB, char *sessionid, int id_user, int *id_session);

int oph_odb_retrieve_session_id(ophidiadb * oDB, const char *sessionid, int *id_session);
int oph_odb_retrieve_session_id_unsafe(ophidiadb * oDB, const char *sessionid, int *id_session);

int oph_odb_get_last_id(ophidiadb * oDB, int *idjob);
int oph_odb_get_last_id_unsafe(ophidiadb * oDB, int *idjob);

int oph_odb_copy_job(ophidiadb * oDB, int idjob, int idparent);
int oph_odb_copy_job_unsafe(ophidiadb * oDB, int idjob, int idparent);

int oph_odb_drop_job(ophidiadb * oDB, int idjob, int idparent);
int oph_odb_drop_job_unsafe(ophidiadb * oDB, int idjob, int idparent);

#endif				/* OPH_ODB_JOB_H */
