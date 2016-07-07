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

#include "oph_known_operators.h"

#include "hashtbl.h"
#include "oph_rmanager.h"
#include "oph_ophidiadb.h"
#include "oph_auth.h"

#include <unistd.h>
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <threads.h>
#include <pthread.h>
#endif
#include <signal.h>
#include <mysql.h>

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_mutex_t global_flag;
pthread_mutex_t libssh2_flag;
pthread_cond_t termination_flag;
#endif

char* oph_server_location=0;
HASHTBL *oph_server_params=0;
char* oph_server_protocol=0;
char* oph_server_host=0;
char* oph_server_port=0;
int oph_server_timeout=OPH_SERVER_TIMEOUT;
int oph_server_inactivity_timeout=OPH_SERVER_INACTIVITY_TIMEOUT;
int oph_server_workflow_timeout=OPH_SERVER_WORKFLOW_TIMEOUT;
FILE* logfile=0;
char* oph_log_file_name=0;
char* oph_server_cert=0;
char* oph_server_ca=0;
char* oph_server_password=0;
char* oph_rmanager_conf_file=0;
char* oph_auth_location=0;
char* oph_json_location=0;
char* oph_txt_location=0;
char* oph_web_server=0;
char* oph_web_server_location=0;
char* oph_operator_client=0;
char* oph_ip_target_host=0;
char* oph_subm_user=0;
char* oph_subm_user_publk=0;
char* oph_subm_user_privk=0;
char* oph_xml_operators=0;
char* oph_xml_operator_dir=0;
char* oph_user_notifier=0;
unsigned int oph_server_farm_size=0;
unsigned int oph_server_queue_size=0;
oph_rmanager* orm=0;
int oph_service_status=1;
oph_auth_user_bl* bl_head=0;
ophidiadb *ophDB=0;

int _check_oph_server(const char* operator, int option)
{
	// Workflow
	oph_workflow* wf = (oph_workflow*)calloc(1,sizeof(oph_workflow));
	if (!wf) return 1;

	// HEADER
	wf->idjob = 1;
	wf->workflowid = 1;
	wf->markerid = 1;
	wf->status = OPH_ODB_STATUS_RUNNING;
	wf->username = strdup("oph-test");
	wf->userrole = 31;
	wf->name = strdup("test");
	wf->author = strdup("test");
	wf->abstract = strdup("-");
	wf->sessionid = strdup("http://localhost/sessions/1/experiment");
	wf->exec_mode = strdup("sync");
	wf->ncores = 1;
	wf->cwd = strdup("/1");
	wf->run = 1;
	wf->parallel_mode = 0;

	if (!strcmp(operator,"oph_if"))
	{
		char condition[OPH_MAX_STRING_SIZE];
		sprintf(condition,"1");

		switch (option)
		{
			case 0:
			{
				*condition = 0;
			}
			break;

			case 2:
			{
				sprintf(condition,"0");
			}
			break;

			case 5:
			{
				sprintf(condition,"0/0");
			}
			break;

			case 6:
			{
				sprintf(condition,"1/0");
			}
			break;

			default:;
		}

		// Tasks
		wf->tasks_num = 5;
		wf->residual_tasks_num = 5;
		wf->tasks = (oph_workflow_task*)calloc(1+wf->tasks_num,sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// IF
		wf->tasks[0].idjob = 2;
		wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("IF");
		wf->tasks[0].operator = strdup("oph_if");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 1;
		wf->tasks[0].arguments_keys = (char**)calloc(wf->tasks[0].arguments_num,sizeof(char*));
			wf->tasks[0].arguments_keys[0] = strdup("condition");
		wf->tasks[0].arguments_values = (char**)calloc(wf->tasks[0].arguments_num,sizeof(char*));
			wf->tasks[0].arguments_values[0] = strdup(condition);
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 2;
		wf->tasks[0].dependents_indexes = (int*)calloc(wf->tasks[0].dependents_indexes_num,sizeof(int));
			wf->tasks[0].dependents_indexes[0] = 1;
			wf->tasks[0].dependents_indexes[1] = 2;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		// Operator for true
		wf->tasks[1].idjob = 3;
		wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[1].name = strdup("Operator for true");
		wf->tasks[1].operator = strdup("oph_operator");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 0;
		wf->tasks[1].arguments_keys = NULL;
		wf->tasks[1].arguments_values = NULL;
		wf->tasks[1].deps = (oph_workflow_dep*)calloc(wf->tasks[1].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[1].deps[0].task_name = strdup("oph_if");
			wf->tasks[1].deps[0].task_index = 0;
			wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int*)calloc(wf->tasks[1].dependents_indexes_num,sizeof(int));
			wf->tasks[1].dependents_indexes[0] = 4;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// ELSE
		wf->tasks[2].idjob = 4;
		wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[2].name = strdup("ELSE");
		wf->tasks[2].operator = strdup("oph_else");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].deps = (oph_workflow_dep*)calloc(wf->tasks[2].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[2].deps[0].task_name = strdup("oph_if");
			wf->tasks[2].deps[0].task_index = 0;
			wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 1;
		wf->tasks[2].dependents_indexes = (int*)calloc(wf->tasks[2].dependents_indexes_num,sizeof(int));
			wf->tasks[2].dependents_indexes[0] = 3;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = 0;

		// Operator for false
		wf->tasks[3].idjob = 5;
		wf->tasks[3].markerid = 5;
		wf->tasks[3].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[3].name = strdup("Operator for false");
		wf->tasks[3].operator = strdup("oph_operator");
		wf->tasks[3].role = oph_code_role("read");
		wf->tasks[3].ncores = wf->ncores;
		wf->tasks[3].arguments_num = 0;
		wf->tasks[3].arguments_keys = NULL;
		wf->tasks[3].arguments_values = NULL;
		wf->tasks[3].deps = (oph_workflow_dep*)calloc(wf->tasks[3].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[3].deps[0].task_name = strdup("oph_else");
			wf->tasks[3].deps[0].task_index = 2;
			wf->tasks[3].deps[0].type = strdup("embedded");
		wf->tasks[3].dependents_indexes_num = 1;
		wf->tasks[3].dependents_indexes = (int*)calloc(wf->tasks[3].dependents_indexes_num,sizeof(int));
			wf->tasks[3].dependents_indexes[0] = 4;
		wf->tasks[3].run = 1;
		wf->tasks[3].parent = -1;

		// ENDIF
		wf->tasks[4].idjob = 6;
		wf->tasks[4].markerid = 6;
		wf->tasks[4].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[4].name = strdup("ENDIF");
		wf->tasks[4].operator = strdup("oph_endif");
		wf->tasks[4].role = oph_code_role("read");
		wf->tasks[4].ncores = wf->ncores;
		wf->tasks[4].arguments_num = 0;
		wf->tasks[4].arguments_keys = NULL;
		wf->tasks[4].arguments_values = NULL;
		wf->tasks[4].deps_num = 2;
		wf->tasks[4].deps = (oph_workflow_dep*)calloc(wf->tasks[4].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[4].deps[0].task_name = strdup("oph_operator");
			wf->tasks[4].deps[0].task_index = 1;
			wf->tasks[4].deps[0].type = strdup("embedded");
			wf->tasks[4].deps[1].task_name = strdup("oph_operator");
			wf->tasks[4].deps[1].task_index = 3;
			wf->tasks[4].deps[1].type = strdup("embedded");
		wf->tasks[4].dependents_indexes_num = 0;
		wf->tasks[4].dependents_indexes = NULL;
		wf->tasks[4].run = 1;
		wf->tasks[4].parent = 0;

		char error_message[OPH_MAX_STRING_SIZE];
		int exit_output;
		*error_message = 0;

		switch (option)
		{
			case 3:
			{
				wf->tasks[0].is_skipped = 1; // in case of oph_elseif
			}
			break;

			case 4:
			{
				free(wf->tasks[0].arguments_keys[0]);
				free(wf->tasks[0].arguments_keys);
				free(wf->tasks[0].arguments_values[0]);
				free(wf->tasks[0].arguments_values);
				wf->tasks[0].arguments_num = 0;
				wf->tasks[0].arguments_keys = NULL;
				wf->tasks[0].arguments_values = NULL;
			}
			break;

			case 7:
			{
				oph_workflow_var var;
				var.caller = -1;
				var.ivalue = 1;
				snprintf(var.svalue,OPH_WORKFLOW_MAX_STRING,"234-234");
				if (hashtbl_insert_with_size(wf->vars, "condition", (void *)&var, sizeof(oph_workflow_var))) return 1;
				free(wf->tasks[0].arguments_values[0]);
				wf->tasks[0].arguments_values[0] = strdup("@condition");
			}
			break;

			case 8:
			{
				free(wf->tasks[0].arguments_values[0]);
				wf->tasks[0].arguments_values[0] = strdup("@condition");
			}
			break;

			default:;
		}

		int res = oph_if_impl(wf, 0, error_message, &exit_output);

		switch (option)
		{
			case 5:
				if ((res != OPH_SERVER_ERROR) || strcasecmp(error_message,"Wrong condition '0/0'!"))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Error message: %s\n",error_message);
					return 1;
				}
			break;
			case 6:
				if ((res != OPH_SERVER_ERROR) || strcasecmp(error_message,"Wrong condition '1/0'!"))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Error message: %s\n",error_message);
					return 1;
				}
			break;
			case 8:
				if ((res != OPH_SERVER_ERROR) || strcasecmp(error_message,"Bad variable '@condition' in task 'IF'"))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Error message: %s\n",error_message);
					return 1;
				}
			break;

			default:
				if (res || strlen(error_message))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Return code: %d\nError message: %s\n",res,error_message);
					return 1;
				}
		}

		switch (option)
		{
			case 0:
			case 1:
			{
				if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Skipping flags are wrong\n");
					return 1;
				}
			}
			break;

			case 2:
			case 7:
			{
				if (wf->tasks[1].status != OPH_ODB_STATUS_SKIPPED)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Status flags are wrong\n");
					return 1;
				}
				if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Skipping flags are wrong\n");
					return 1;
				}
				if ((wf->tasks[4].deps[0].task_index != 0) || (wf->tasks[4].deps[1].task_index != 3))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Dependence data are wrong\n");
					return 1;
				}
			}
			break;

			case 3:
			{
				if (wf->tasks[1].status != OPH_ODB_STATUS_SKIPPED)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Status flags are wrong\n");
					return 1;
				}
				if (!wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Skipping flags are wrong\n");
					return 1;
				}
				if ((wf->tasks[4].deps[0].task_index != 0) || (wf->tasks[4].deps[1].task_index != 3))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Dependence data are wrong\n");
					return 1;
				}
			}
			break;

			case 4:
			{
				if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Skipping flags are wrong\n");
					return 1;
				}
			}
			break;

			default:;
		}
	}
	else if (!strcmp(operator,"oph_else"))
	{
		// Tasks
		wf->tasks_num = 5;
		wf->residual_tasks_num = 3;
		wf->tasks = (oph_workflow_task*)calloc(1+wf->tasks_num,sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// IF
		wf->tasks[0].idjob = 2;
		wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_COMPLETED;
		wf->tasks[0].name = strdup("IF");
		wf->tasks[0].operator = strdup("oph_if");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 1;
		wf->tasks[0].arguments_keys = (char**)calloc(wf->tasks[0].arguments_num,sizeof(char*));
			wf->tasks[0].arguments_keys[0] = strdup("condition");
		wf->tasks[0].arguments_values = (char**)calloc(wf->tasks[0].arguments_num,sizeof(char*));
			wf->tasks[0].arguments_values[0] = strdup("0");
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 2;
		wf->tasks[0].dependents_indexes = (int*)calloc(wf->tasks[0].dependents_indexes_num,sizeof(int));
			wf->tasks[0].dependents_indexes[0] = 4;
			wf->tasks[0].dependents_indexes[1] = 2;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		// Operator for true
		wf->tasks[1].idjob = 3;
		wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_SKIPPED;
		wf->tasks[1].name = strdup("Operator for true");
		wf->tasks[1].operator = strdup("oph_operator");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 0;
		wf->tasks[1].arguments_keys = NULL;
		wf->tasks[1].arguments_values = NULL;
		wf->tasks[1].deps = (oph_workflow_dep*)calloc(wf->tasks[1].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[1].deps[0].task_name = strdup("oph_if");
			wf->tasks[1].deps[0].task_index = 0;
			wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int*)calloc(wf->tasks[1].dependents_indexes_num,sizeof(int));
			wf->tasks[1].dependents_indexes[0] = 4;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// ELSE
		wf->tasks[2].idjob = 4;
		wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[2].name = strdup("ELSE");
		wf->tasks[2].operator = strdup("oph_else");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].deps = (oph_workflow_dep*)calloc(wf->tasks[2].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[2].deps[0].task_name = strdup("oph_if");
			wf->tasks[2].deps[0].task_index = 0;
			wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 1;
		wf->tasks[2].dependents_indexes = (int*)calloc(wf->tasks[2].dependents_indexes_num,sizeof(int));
			wf->tasks[2].dependents_indexes[0] = 3;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = 0;

		// Operator for false
		wf->tasks[3].idjob = 5;
		wf->tasks[3].markerid = 5;
		wf->tasks[3].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[3].name = strdup("Operator for false");
		wf->tasks[3].operator = strdup("oph_operator");
		wf->tasks[3].role = oph_code_role("read");
		wf->tasks[3].ncores = wf->ncores;
		wf->tasks[3].arguments_num = 0;
		wf->tasks[3].arguments_keys = NULL;
		wf->tasks[3].arguments_values = NULL;
		wf->tasks[3].deps = (oph_workflow_dep*)calloc(wf->tasks[3].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[3].deps[0].task_name = strdup("oph_else");
			wf->tasks[3].deps[0].task_index = 2;
			wf->tasks[3].deps[0].type = strdup("embedded");
		wf->tasks[3].dependents_indexes_num = 1;
		wf->tasks[3].dependents_indexes = (int*)calloc(wf->tasks[3].dependents_indexes_num,sizeof(int));
			wf->tasks[3].dependents_indexes[0] = 4;
		wf->tasks[3].run = 1;
		wf->tasks[3].parent = -1;

		// ENDIF
		wf->tasks[4].idjob = 6;
		wf->tasks[4].markerid = 6;
		wf->tasks[4].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[4].name = strdup("ENDIF");
		wf->tasks[4].operator = strdup("oph_endif");
		wf->tasks[4].role = oph_code_role("read");
		wf->tasks[4].ncores = wf->ncores;
		wf->tasks[4].arguments_num = 0;
		wf->tasks[4].arguments_keys = NULL;
		wf->tasks[4].arguments_values = NULL;
		wf->tasks[4].deps_num = 2;
		wf->tasks[4].deps = (oph_workflow_dep*)calloc(wf->tasks[4].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[4].deps[0].task_name = strdup("oph_operator");
			wf->tasks[4].deps[0].task_index = 0;
			wf->tasks[4].deps[0].type = strdup("embedded");
			wf->tasks[4].deps[1].task_name = strdup("oph_operator");
			wf->tasks[4].deps[1].task_index = 3;
			wf->tasks[4].deps[1].type = strdup("embedded");
		wf->tasks[4].dependents_indexes_num = 0;
		wf->tasks[4].dependents_indexes = NULL;
		wf->tasks[4].run = 1;
		wf->tasks[4].parent = 0;

		char error_message[OPH_MAX_STRING_SIZE];
		int exit_output;
		*error_message = 0;

		switch (option)
		{
			case 1:
			{
				wf->tasks[0].dependents_indexes[0] = 1;
				wf->tasks[0].dependents_indexes[1] = 4;
				wf->tasks[1].status = OPH_ODB_STATUS_PENDING;
				wf->tasks[2].is_skipped = 1;
				wf->tasks[4].deps[0].task_index = 1;
				wf->tasks[4].deps[1].task_index = 0;
			}
			break;

			default:;
		}

		int res = oph_else_impl(wf, 2, error_message, &exit_output);

		switch (option)
		{
			default:
				if (res || strlen(error_message))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Return code: %d\nError message: %s\n",res,error_message);
					return 1;
				}
		}

		switch (option)
		{
			case 0:
			{
				if (wf->tasks[1].status != OPH_ODB_STATUS_SKIPPED)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Status flags are wrong\n");
					return 1;
				}
				if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Skipping flags are wrong\n");
					return 1;
				}
				if ((wf->tasks[4].deps[0].task_index != 0) || (wf->tasks[4].deps[1].task_index != 3))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Dependence data are wrong\n");
					return 1;
				}
			}
			break;

			case 1:
			{
				if ((wf->tasks[1].status == OPH_ODB_STATUS_SKIPPED) || (wf->tasks[3].status != OPH_ODB_STATUS_SKIPPED))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Status flags are wrong\n");
					return 1;
				}
				if (wf->tasks[0].is_skipped || wf->tasks[1].is_skipped || !wf->tasks[2].is_skipped || wf->tasks[3].is_skipped || wf->tasks[4].is_skipped)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Skipping flags are wrong\n");
					return 1;
				}
				if ((wf->tasks[4].deps[0].task_index != 1) || (wf->tasks[4].deps[1].task_index != 0))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Dependence data are wrong\n");
					return 1;
				}
			}
			break;

			default:;
		}
	}
	else if (!strcmp(operator,"oph_for"))
	{
		// Tasks
		wf->tasks_num = 3;
		wf->residual_tasks_num = 3;
		wf->tasks = (oph_workflow_task*)calloc(1+wf->tasks_num,sizeof(oph_workflow_task));
		wf->vars = hashtbl_create(wf->tasks_num, NULL);

		// FOR
		wf->tasks[0].idjob = 2;
		wf->tasks[0].markerid = 2;
		wf->tasks[0].status = OPH_ODB_STATUS_PENDING;
		wf->tasks[0].name = strdup("FOR");
		wf->tasks[0].operator = strdup("oph_for");
		wf->tasks[0].role = oph_code_role("read");
		wf->tasks[0].ncores = wf->ncores;
		wf->tasks[0].arguments_num = 4;
		wf->tasks[0].arguments_keys = (char**)calloc(wf->tasks[0].arguments_num,sizeof(char*));
			wf->tasks[0].arguments_keys[0] = strdup("name");
			wf->tasks[0].arguments_keys[1] = strdup("values");
			wf->tasks[0].arguments_keys[2] = strdup("counter");
			wf->tasks[0].arguments_keys[3] = strdup("parallel");
		wf->tasks[0].arguments_values = (char**)calloc(wf->tasks[0].arguments_num,sizeof(char*));
			wf->tasks[0].arguments_values[0] = strdup("index");
			wf->tasks[0].arguments_values[1] = strdup("first|second|third");
			wf->tasks[0].arguments_values[2] = strdup("1:3");
			wf->tasks[0].arguments_values[3] = strdup("no");
		wf->tasks[0].deps_num = 0;
		wf->tasks[0].deps = NULL;
		wf->tasks[0].dependents_indexes_num = 1;
		wf->tasks[0].dependents_indexes = (int*)calloc(wf->tasks[0].dependents_indexes_num,sizeof(int));
			wf->tasks[0].dependents_indexes[0] = 1;
		wf->tasks[0].run = 1;
		wf->tasks[0].parent = -1;

		// Operator
		wf->tasks[1].idjob = 3;
		wf->tasks[1].markerid = 3;
		wf->tasks[1].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[1].name = strdup("Operator");
		wf->tasks[1].operator = strdup("oph_operator");
		wf->tasks[1].role = oph_code_role("read");
		wf->tasks[1].ncores = wf->ncores;
		wf->tasks[1].arguments_num = 0;
		wf->tasks[1].arguments_keys = NULL;
		wf->tasks[1].arguments_values = NULL;
		wf->tasks[1].deps = (oph_workflow_dep*)calloc(wf->tasks[1].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[1].deps[0].task_name = strdup("oph_for");
			wf->tasks[1].deps[0].task_index = 0;
			wf->tasks[1].deps[0].type = strdup("embedded");
		wf->tasks[1].dependents_indexes_num = 1;
		wf->tasks[1].dependents_indexes = (int*)calloc(wf->tasks[1].dependents_indexes_num,sizeof(int));
			wf->tasks[1].dependents_indexes[0] = 2;
		wf->tasks[1].run = 1;
		wf->tasks[1].parent = -1;

		// ENDFOR
		wf->tasks[2].idjob = 4;
		wf->tasks[2].markerid = 4;
		wf->tasks[2].status = OPH_ODB_STATUS_UNKNOWN;
		wf->tasks[2].name = strdup("ENDFOR");
		wf->tasks[2].operator = strdup("oph_endfor");
		wf->tasks[2].role = oph_code_role("read");
		wf->tasks[2].ncores = wf->ncores;
		wf->tasks[2].arguments_num = 0;
		wf->tasks[2].arguments_keys = NULL;
		wf->tasks[2].arguments_values = NULL;
		wf->tasks[2].deps = (oph_workflow_dep*)calloc(wf->tasks[2].deps_num,sizeof(oph_workflow_dep));
			wf->tasks[2].deps[0].task_name = strdup("oph_operator");
			wf->tasks[2].deps[0].task_index = 1;
			wf->tasks[2].deps[0].type = strdup("embedded");
		wf->tasks[2].dependents_indexes_num = 0;
		wf->tasks[2].dependents_indexes = NULL;
		wf->tasks[2].run = 1;
		wf->tasks[2].parent = 0;

		char error_message[OPH_MAX_STRING_SIZE];
		*error_message = 0;

		switch (option)
		{
			case 1:
			{
				oph_workflow_var var;
				var.caller = -1;
				var.ivalue = 1;
				snprintf(var.svalue,OPH_WORKFLOW_MAX_STRING,"first|second|third");
				if (hashtbl_insert_with_size(wf->vars, "values", (void *)&var, sizeof(oph_workflow_var))) return 1;
				free(wf->tasks[0].arguments_values[1]);
				wf->tasks[0].arguments_values[1] = strdup("@values");
			}
			break;

			case 2:
			{
				free(wf->tasks[0].arguments_keys[0]);
				wf->tasks[0].arguments_keys[0] = strdup("no-name");
			}
			break;

			case 3:
			{
				free(wf->tasks[0].arguments_keys[1]);
				wf->tasks[0].arguments_keys[1] = strdup("no-values");
			}
			break;

			case 4:
			{
				free(wf->tasks[0].arguments_keys[2]);
				wf->tasks[0].arguments_keys[2] = strdup("no-counter");
			}
			break;

			case 5:
			{
				free(wf->tasks[0].arguments_keys[3]);
				wf->tasks[0].arguments_keys[3] = strdup("no-parallel");
			}
			break;

			case 6:
			{
				free(wf->tasks[0].arguments_keys[1]);
				wf->tasks[0].arguments_keys[1] = strdup("no-values");
				free(wf->tasks[0].arguments_keys[2]);
				wf->tasks[0].arguments_keys[2] = strdup("no-counter");
			}
			break;

			default:;
		}

		int res = oph_for_impl(wf, 0, error_message, 1, OPH_SERVER_UNKNOWN);

		switch (option)
		{
			case 2:
				if ((res != OPH_SERVER_ERROR) || strcasecmp(error_message,"Bad argument 'name'."))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Error message: %s\n",error_message);
					return 1;
				}
			break;

			default:
				if (res || strlen(error_message))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Return code: %d\nError message: %s\n",res,error_message);
					return 1;
				}
				if (!wf->stack)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Empty stack\n");
					return 1;
				}
				if (wf->stack->caller)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Flag 'caller' is wrong\n");
					return 1;
				}
				if (wf->stack->index)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Index is wrong\n");
					return 1;
				}
				if (!wf->stack->name)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Parameters are not correctly pushed into the stack\n");
					return 1;
				}
		}

		switch (option)
		{
			case 0:
			case 1:
			case 4:
			case 5:
			{
				if (!wf->stack->svalues || (wf->stack->values_num != 3))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Parameters are not correctly pushed into the stack\n");
					return 1;
				}
				if (strcasecmp(wf->stack->svalues[0],"first") || strcasecmp(wf->stack->svalues[1],"second") || strcasecmp(wf->stack->svalues[2],"third"))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Parameters are not correctly pushed into the stack\n");
					return 1;
				}
			}
			break;
		}

		switch (option)
		{
			case 0:
			case 1:
			case 3:
			case 5:
			{
				if (!wf->stack->ivalues || (wf->stack->values_num != 3))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Parameters are not correctly pushed into the stack\n");
					return 1;
				}
				if ((wf->stack->ivalues[0] != 1) || (wf->stack->ivalues[1] != 2) || (wf->stack->ivalues[2] != 3))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Parameters are not correctly pushed into the stack\n");
					return 1;
				}
			}
			break;
		}

		switch (option)
		{
			case 6:
			{
				if ((wf->stack->values_num != 1) || wf->stack->ivalues || wf->stack->svalues)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__, "Parameters are not correctly pushed into the stack\n");
					return 1;
				}
			}
			break;
		}

	}
	else if (!strcmp(operator,"oph_endfor"))
	{
	}

	//oph_workflow_free(wf);

	return 0;
}

int check_oph_server(int* i, int n, const char* operator, int option)
{
	(*i)++;
	printf("TEST %d/%d: operator '%s' option %d\n", *i, n, operator, option);
	if (_check_oph_server(operator, option)) return 1;
	printf("PASSED %d/%d\n\n",*i,n);
	return 0;
}

int main(int argc, char* argv[])
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_t tid;
	pthread_mutex_init(&global_flag, NULL);
	pthread_mutex_init(&libssh2_flag, NULL);
	pthread_cond_init(&termination_flag, NULL);
#endif

	UNUSED(argc)
	UNUSED(argv)
	UNUSED(tid)

	set_debug_level(LOG_DEBUG+10);

	int i = 0, n = 18, j;
	printf("\n");

	for (j=0; j<9; ++j) if (check_oph_server(&i,n,"oph_if", j)) return 1;
	for (j=0; j<2; ++j) if (check_oph_server(&i,n,"oph_else", j)) return 1;
	for (j=0; j<7; ++j) if (check_oph_server(&i,n,"oph_for", j)) return 1;

	return 0;
}

