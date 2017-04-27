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

#include "oph_rmanager.h"

#include "oph_auth.h"
#include "oph_known_operators.h"

#include <mysql.h>

#define OPH_NULL_FILENAME "/dev/null"

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif
extern char *oph_rmanager_conf_file;
extern char *oph_txt_location;
extern char *oph_operator_client;
extern char *oph_json_location;
extern char *oph_server_port;
extern oph_rmanager *orm;
extern char oph_subm_ssh;
extern char *oph_subm_user;

extern int oph_ssh_submit(const char *cmd);

extern int oph_workflow_notify(struct oph_plugin_data *state, char ttype, int jobid, char *data, char *json, int *response);

typedef struct _oph_command_data {
	char *command;
	char *error;
	struct oph_plugin_data *state;
	int delay;
} oph_command_data;

void *_oph_system(oph_command_data * data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
#endif
	if (data) {
		if (data->command) {
			if (data->delay > 0) {
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Back off for %d seconds\n", data->delay);
				sleep(data->delay);
			}
#ifdef LOCAL_FRAMEWORK
			if (system(data->command))
#else
			if (oph_ssh_submit(data->command))
#endif
			{
				int jobid;
				pthread_mutex_lock(&global_flag);
				jobid = ++*data->state->jobid;
				pmesg(LOG_ERROR, __FILE__, __LINE__, "C%d: critical error in task submission\n", jobid);
				pthread_mutex_unlock(&global_flag);

				if (data->error) {
					int response = 0;
					oph_workflow_notify(data->state, 'C', jobid, data->error, NULL, &response);
					if (response)
						pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "C%d: error %d in notify\n", jobid, response);
				}
			}
			free(data->command);
		}
		if (data->error)
			free(data->error);

		if (data->state) {
			if (data->state->serverid)
				free(data->state->serverid);
			free(data->state);
		}

		free(data);
	}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	mysql_thread_end();
#endif
	return NULL;
}

int oph_system(const char *command, const char *error, struct oph_plugin_data *state, int delay)
{
	if (!command) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
	}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_command_data *data = (oph_command_data *) malloc(sizeof(oph_command_data));
	if (!data)
		return RMANAGER_ERROR;

	data->command = strndup(command, OPH_MAX_STRING_SIZE);
	if (!data->command)
		return RMANAGER_ERROR;

	if (error) {
		data->error = strndup(error, OPH_MAX_STRING_SIZE);
		if (!data->error) {
			free(data->command);
			free(data);
			return RMANAGER_ERROR;
		}
	} else
		data->error = NULL;

	data->state = (struct oph_plugin_data *) malloc(sizeof(struct oph_plugin_data));
	if (!data->state) {
		free(data->command);
		if (data->error)
			free(data->error);
		free(data);
		return RMANAGER_ERROR;
	}
	memcpy(data->state, (struct oph_plugin_data *) state, sizeof(struct oph_plugin_data));
	if (state->serverid)
		data->state->serverid = strndup(state->serverid, OPH_MAX_STRING_SIZE);
	else
		data->state->serverid = NULL;
	data->state->is_copy = 1;
	data->state->job_info = state->job_info;
	data->delay = delay;

	pthread_t tid;
	pthread_create(&tid, NULL, (void *(*)(void *)) &_oph_system, data);
	return RMANAGER_SUCCESS;
#else
	return system(command);
#endif
}

int oph_read_rmanager_conf(oph_rmanager * orm)
{
	if (!orm) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
	}

	char config[OPH_MAX_STRING_SIZE];
	snprintf(config, sizeof(config), "%s", oph_rmanager_conf_file);

	FILE *file = fopen(config, "r");
	if (file == NULL) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Configuration file not found\n");
		return RMANAGER_ERROR;
	} else {
		char buffer[OPH_MAX_STRING_SIZE];
		char *position;
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Reading resource manager configuration file '%s'\n", config);

		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->name = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->name, position + 1, strlen(position + 1) + 1);
			orm->name[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_cmd = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_cmd, position + 1, strlen(position + 1) + 1);
			orm->subm_cmd[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_args = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_args, position + 1, strlen(position + 1) + 1);
			orm->subm_args[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_username = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_username, position + 1, strlen(position + 1) + 1);
			orm->subm_username[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_group = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_group, position + 1, strlen(position + 1) + 1);
			orm->subm_group[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_ncores = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_ncores, position + 1, strlen(position + 1) + 1);
			orm->subm_ncores[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_interact = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_interact, position + 1, strlen(position + 1) + 1);
			orm->subm_interact[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_batch = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_batch, position + 1, strlen(position + 1) + 1);
			orm->subm_batch[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_stdoutput = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_stdoutput, position + 1, strlen(position + 1) + 1);
			orm->subm_stdoutput[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_stderror = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_stderror, position + 1, strlen(position + 1) + 1);
			orm->subm_stderror[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_postfix = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_postfix, position + 1, strlen(position + 1) + 1);
			orm->subm_postfix[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_jobname = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_jobname, position + 1, strlen(position + 1) + 1);
			orm->subm_jobname[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_cancel = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_cancel, position + 1, strlen(position + 1) + 1);
			orm->subm_cancel[strlen(position + 1)] = '\0';
		}

		fgetc(file);
		if (fscanf(file, "%[^\n]", buffer) == EOF) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
			fclose(file);
			return RMANAGER_ERROR;
		}
		position = strchr(buffer, '=');
		if (position != NULL) {
			if (!(orm->subm_jobcheck = (char *) malloc((strlen(position + 1) + 1) * sizeof(char)))) {
				pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
				fclose(file);
				return RMANAGER_MEMORY_ERROR;
			}
			strncpy(orm->subm_jobcheck, position + 1, strlen(position + 1) + 1);
			orm->subm_jobcheck[strlen(position + 1)] = '\0';
		}
	}

	fclose(file);

	return RMANAGER_SUCCESS;

}

int initialize_rmanager(oph_rmanager * orm)
{
	if (!orm) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
	}

	orm->name = NULL;
	orm->subm_cmd = NULL;
	orm->subm_args = NULL;
	orm->subm_username = NULL;
	orm->subm_group = NULL;
	orm->subm_ncores = NULL;
	orm->subm_interact = NULL;
	orm->subm_batch = NULL;
	orm->subm_stdoutput = NULL;
	orm->subm_stderror = NULL;
	orm->subm_postfix = NULL;
	orm->subm_jobname = NULL;
	orm->subm_cancel = NULL;
	orm->subm_jobcheck = NULL;

	return RMANAGER_SUCCESS;
}

int oph_cancel_request(int jobid)
{
	if (!jobid)
		return RMANAGER_NULL_PARAM;
	if (orm && orm->subm_cancel) {
#ifdef LOCAL_FRAMEWORK
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Task %d cannot be stopped\n", jobid);
#else
		size_t len = 2 + strlen(orm->subm_cancel) + strlen(oph_server_port) + strlen(OPH_RMANAGER_PREFIX) + OPH_RMANAGER_MAX_INT_SIZE;
		char cmd[len];
		snprintf(cmd, len, "%s %s%s%d", orm->subm_cancel, oph_server_port, OPH_RMANAGER_PREFIX, jobid);
		if (oph_ssh_submit(cmd)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error during remote submission\n");
			return RMANAGER_ERROR;
		}
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Task %d has been stopped\n");
#endif
	}
	return RMANAGER_SUCCESS;
}

int oph_read_job_queue(int **list, unsigned int *n)
{
	if (!list || !n) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null parameter\n");
		return RMANAGER_NULL_PARAM;
	}
	*list = NULL;
	*n = 0;
#ifndef LOCAL_FRAMEWORK
	if (orm && orm->subm_jobcheck) {
		char outfile[OPH_MAX_STRING_SIZE];
		snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_TXT_FILENAME, oph_txt_location, "job", "queue");
		size_t len = 4 + strlen(orm->subm_jobcheck) + strlen(outfile);
		char cmd[len];
		snprintf(cmd, len, "%s > %s", orm->subm_jobcheck, outfile);
		if (oph_ssh_submit(cmd)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error during remote submission\n");
			return RMANAGER_ERROR;
		}

		char *response = NULL;
		if (oph_get_result_from_file(outfile, &response) || !response)
			return RMANAGER_SUCCESS;

		len = strlen(oph_server_port) + strlen(OPH_RMANAGER_PREFIX);
		char prefix[1 + len];
		sprintf(prefix, "%s%s", oph_server_port, OPH_RMANAGER_PREFIX);

		char *tmp = strdup(response);
		if (!tmp) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error during job queue scanning\n");
			free(response);
			return RMANAGER_ERROR;
		}
		char *pch, *save_pointer = NULL;
		for (pch = strtok_r(tmp, "\n", &save_pointer); pch; pch = strtok_r(NULL, "\n", &save_pointer))
			if (!strncmp(pch, prefix, len))
				(*n)++;
		free(tmp);

		*list = (int *) calloc(*n, sizeof(int));
		unsigned int i = 0;
		save_pointer = NULL;
		for (pch = strtok_r(response, "\n", &save_pointer); pch; pch = strtok_r(NULL, "\n", &save_pointer))
			if (!strncmp(pch, prefix, len))
				(*list)[i++] = (int) strtol(pch + len, NULL, 10);
		free(response);
	}
#endif
	return RMANAGER_SUCCESS;
}

int oph_form_subm_string(const char *request, const int ncores, char *outfile, short int interactive_subm, oph_rmanager * orm, int jobid, char *username, char **cmd)
{
	if (!orm) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
	}

	char *_outfile = outfile, *tmp = NULL;
	int len = 0;
	if (oph_subm_ssh)
		len =
		    strlen(orm->subm_cmd) + 1 + strlen(orm->subm_args) + 1 + strlen(orm->subm_ncores) + 1 + strlen(orm->subm_interact) + 1 + strlen(orm->subm_batch) + 1 + strlen(orm->subm_stdoutput) +
		    1 + strlen(outfile) + 1 + strlen(orm->subm_stderror) + 1 + strlen(outfile) + 1 + strlen(orm->subm_postfix) + 1 + strlen(orm->subm_jobname) + 1 + strlen(request);
	else {
		len =
		    strlen(orm->subm_cmd) + 1 + strlen(orm->subm_args) + 1 + 2 * strlen(orm->subm_username) + 2 + strlen(orm->subm_group) + 1 + +1 + strlen(orm->subm_ncores) + 1 +
		    strlen(orm->subm_interact) + 1 + strlen(orm->subm_batch) + 1 + strlen(orm->subm_stdoutput) + 1 + strlen(outfile) + 1 + strlen(orm->subm_stderror) + 1 + strlen(outfile) + 1 +
		    strlen(orm->subm_postfix) + 1 + strlen(orm->subm_jobname) + 1 + strlen(request);
		if (username)
			len += strlen(username);
		else if (oph_subm_user) {
			username = oph_subm_user;
			len += strlen(username);
		} else {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "No username selected\n");
			return RMANAGER_NULL_PARAM;
		}
		tmp = (char *) malloc(2 + strlen(outfile) + strlen(orm->subm_username));
		if (tmp) {
			sprintf(tmp, "%s/%s", outfile, orm->subm_username);
			_outfile = tmp;
		} else
			pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "Error allocating memory for log file '%s'\n", outfile);
	}
	len += 128;		// 128 is a very big number to include the number of cores and the name of the ophidia application client

	if (!(*cmd = (char *) malloc(len * sizeof(char)))) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
		if (tmp)
			free(tmp);
		return RMANAGER_MEMORY_ERROR;
	}

	if (!strcasecmp(orm->name, "slurm")) {
		if (oph_subm_ssh) {
			if (interactive_subm)
				sprintf(*cmd, "%s %s %s %d %s %s %s %s %s %s \"%s\" &", orm->subm_cmd, orm->subm_args, orm->subm_ncores, ncores, orm->subm_interact, orm->subm_stdoutput, _outfile,
					orm->subm_stderror, _outfile, oph_operator_client, request);
			else
				sprintf(*cmd, "%s %s %s %d %s %s %s %s %s %s %s%s%d %s \"%s\" %s &", orm->subm_cmd, orm->subm_args, orm->subm_ncores, ncores, orm->subm_batch, orm->subm_stdoutput,
					_outfile, orm->subm_stderror, _outfile, orm->subm_jobname, oph_server_port, OPH_RMANAGER_PREFIX, jobid, oph_operator_client, request, orm->subm_postfix);
		} else {
			if (interactive_subm)
				sprintf(*cmd, "%s %s %s%s %s %s %d %s %s %s %s %s %s \"%s\"", orm->subm_cmd, orm->subm_args, orm->subm_username, username, orm->subm_group, orm->subm_ncores, ncores,
					orm->subm_interact, orm->subm_stdoutput, _outfile, orm->subm_stderror, _outfile, oph_operator_client, request);
			else
				sprintf(*cmd, "%s %s %s%s %s %s %d %s %s %s %s %s %s %s%s%d %s \"%s\" %s", orm->subm_cmd, orm->subm_args, orm->subm_username, username, orm->subm_group,
					orm->subm_ncores, ncores, orm->subm_batch, orm->subm_stdoutput, _outfile, orm->subm_stderror, _outfile, orm->subm_jobname, oph_server_port, OPH_RMANAGER_PREFIX,
					jobid, oph_operator_client, request, orm->subm_postfix);
		}
	} else {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Resource manager not found\n");
		if (tmp)
			free(tmp);
		return RMANAGER_ERROR;
	}
	if (tmp)
		free(tmp);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Submission string:\n%s\n", *cmd);

	return RMANAGER_SUCCESS;
}

int free_oph_rmanager(oph_rmanager * orm)
{
	if (!orm) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
	}
	if (orm->name) {
		free(orm->name);
		orm->name = NULL;
	}
	if (orm->subm_cmd) {
		free(orm->subm_cmd);
		orm->subm_cmd = NULL;
	}
	if (orm->subm_args) {
		free(orm->subm_args);
		orm->subm_args = NULL;
	}
	if (orm->subm_username) {
		free(orm->subm_username);
		orm->subm_username = NULL;
	}
	if (orm->subm_group) {
		free(orm->subm_group);
		orm->subm_group = NULL;
	}
	if (orm->subm_ncores) {
		free(orm->subm_ncores);
		orm->subm_ncores = NULL;
	}
	if (orm->subm_interact) {
		free(orm->subm_interact);
		orm->subm_interact = NULL;
	}
	if (orm->subm_batch) {
		free(orm->subm_batch);
		orm->subm_batch = NULL;
	}
	if (orm->subm_stdoutput) {
		free(orm->subm_stdoutput);
		orm->subm_stdoutput = NULL;
	}
	if (orm->subm_stderror) {
		free(orm->subm_stderror);
		orm->subm_stderror = NULL;
	}
	if (orm->subm_postfix) {
		free(orm->subm_postfix);
		orm->subm_postfix = NULL;
	}
	if (orm->subm_jobname) {
		free(orm->subm_jobname);
		orm->subm_jobname = NULL;
	}
	if (orm->subm_cancel) {
		free(orm->subm_cancel);
		orm->subm_cancel = NULL;
	}
	if (orm->subm_jobcheck) {
		free(orm->subm_jobcheck);
		orm->subm_jobcheck = NULL;
	}
	free(orm);
	return RMANAGER_SUCCESS;

}

int _oph_get_result_from_file(char *filename, char **response, pthread_mutex_t * flag)
{
	/* declare a file pointer */
	FILE *infile;
	long numbytes;

	/* open an existing file for reading */
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "Opening file %s\n", filename);
	infile = fopen(filename, "r");

	/* quit if the file does not exist */
	if (infile == NULL) {
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to open output file: %s\n", filename);
		return RMANAGER_FILE_ERROR;
	}

	/* Get the number of bytes */
	fseek(infile, 0L, SEEK_END);
	numbytes = ftell(infile);

	/* reset the file position indicator to the beginning of the file */
	fseek(infile, 0L, SEEK_SET);

	/* grab sufficient memory for the buffer to hold the text */
	*response = (char *) malloc((1 + numbytes) * sizeof(char));

	/* memory error */
	if (*response == NULL) {
		fclose(infile);
		pmesg_safe(flag, LOG_ERROR, __FILE__, __LINE__, "Unable to alloc response\n");
		return RMANAGER_FILE_ERROR;
	}

	/* copy all the text into the buffer */
	size_t n = fread(*response, sizeof(char), numbytes, infile);
	(*response)[n] = '\0';
	fclose(infile);

	/* confirm we have read the file by outputing it to the console */
	pmesg_safe(flag, LOG_DEBUG, __FILE__, __LINE__, "The file called %s contains this text\n\n%s\n\n%d chars\n", filename, *response, n);

	return RMANAGER_SUCCESS;
}

int oph_get_result_from_file(char *filename, char **response)
{
	return _oph_get_result_from_file(filename, response, &global_flag);
}

int oph_get_result_from_file_unsafe(char *filename, char **response)
{
	return _oph_get_result_from_file(filename, response, NULL);
}

int oph_serve_request(const char *request, const int ncores, const char *sessionid, const char *markerid, const char *error, struct oph_plugin_data *state, int *odb_wf_id, int *task_id,
		      int *light_task_id, int *odb_jobid, int delay, char **response, char **jobid_response, enum oph__oph_odb_job_status *exit_code, int *exit_output, char *username)
{
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Incoming request '%s' to run job '%s#%s' with %d cores\n", request, sessionid, markerid, ncores);

	if (exit_code)
		*exit_code = OPH_ODB_STATUS_COMPLETED;
	if (exit_output)
		*exit_output = 1;

	int _ncores = ncores;
	if (ncores < 1) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "The job will be executed with 1!\n");
		_ncores = 1;
	}

	int result;
	if ((result =
	     oph_serve_known_operator(state, request, ncores, sessionid, markerid, odb_wf_id, task_id, light_task_id, odb_jobid, response, jobid_response, exit_code,
				      exit_output)) != OPH_SERVER_UNKNOWN)
		return result;

	char *cmd = NULL;

	if (!orm) {
		orm = (oph_rmanager *) malloc(sizeof(oph_rmanager));
		if (initialize_rmanager(orm)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on initialization OphidiaDB\n");
			return OPH_SERVER_ERROR;
		}
		if (oph_read_rmanager_conf(orm)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on read resource manager parameters\n");
			return OPH_SERVER_ERROR;
		}
	}

	char outfile[OPH_MAX_STRING_SIZE];
	if (get_debug_level() == LOG_DEBUG) {
		char code[OPH_MAX_STRING_SIZE];
		if (oph_get_session_code(sessionid, code)) {
			pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on read resource manager parameters\n");
			return OPH_SERVER_ERROR;
		}
		snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_TXT_FILENAME, oph_txt_location, code, markerid);
	} else
		snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_NULL_FILENAME);

#ifdef LOCAL_FRAMEWORK
	char command[OPH_MAX_STRING_SIZE];
#ifdef USE_MPI
	snprintf(command, OPH_MAX_STRING_SIZE, "rm -f %s; mpirun -np %d %s \"%s\" >> %s 2>> %s", outfile, ncores, oph_operator_client, request, outfile, outfile);
#else
	snprintf(command, OPH_MAX_STRING_SIZE, "rm -f %s; %s \"%s\" >> %s 2>> %s", outfile, oph_operator_client, request, outfile, outfile);
	if (ncores > 1)
		pmesg_safe(&global_flag, LOG_WARNING, __FILE__, __LINE__, "MPI is disabled. Only one core will be used\n");
#endif
	pmesg_safe(&global_flag, LOG_INFO, __FILE__, __LINE__, "Execute command: %s\n", command);
	if (oph_system(command, error, state, delay)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on executing the command\n");
		if (cmd) {
			free(cmd);
			cmd = NULL;
		}
		return OPH_SERVER_ERROR;
	}
#else
	if (oph_form_subm_string(request, ncores, outfile, 0, orm, odb_jobid ? *odb_jobid : 0, username, &cmd)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error on forming submission string\n");
		if (cmd) {
			free(cmd);
			cmd = NULL;
		}
		return OPH_SERVER_ERROR;
	}

	if (oph_system(cmd, error, state, delay)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error during remote submission\n");
		if (cmd) {
			free(cmd);
			cmd = NULL;
		}
		return OPH_SERVER_ERROR;
	}
#endif
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}

	return OPH_SERVER_OK;
}
