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

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif
extern char* oph_rmanager_conf_file;
extern char* oph_txt_location;
extern char* oph_operator_client;
extern char* oph_json_location;
extern oph_rmanager* orm;

extern int oph_ssh_submit(const char* cmd);

#ifdef LOCAL_FRAMEWORK
extern int oph_workflow_notify(struct oph_plugin_data *state, char ttype, int jobid, char* data, char* json, int* response);

typedef struct _oph_command_data
{
	char* command;
	char* error;
	struct oph_plugin_data *state;
} oph_command_data;

void* _oph_system(oph_command_data* data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
#endif
	if (data)
	{
		if (data->command)
		{
#ifdef LOCAL_FRAMEWORK
			if (system(data->command))
#else
			if (oph_ssh_submit(data->command))
#endif
			{
				int jobid;
				pthread_mutex_lock(&global_flag);
				jobid = *(data->state->jobid) = *(data->state->jobid) + 1;
				pthread_mutex_unlock(&global_flag);

				pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "C%d: critical error\n", jobid);
				if (data->error)
				{
					int response=0;
					oph_workflow_notify(data->state, 'C', jobid, data->error, NULL, &response);
					if (response) pmesg_safe(&global_flag, LOG_WARNING, __FILE__,__LINE__, "C%d: error %d in notify\n", jobid, response);
				}
			}
			free(data->command);
		}
		if (data->error) free(data->error);

		if (data->state)
		{
			if (data->state->serverid) free(data->state->serverid);
			free(data->state);
		}

		free(data);
	}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	mysql_thread_end();
#endif
	return NULL;
}

int oph_system(const char* command, const char* error, struct oph_plugin_data *state)
{
	if (!command)
	{
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
		return RMANAGER_NULL_PARAM;
        }

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_command_data* data = (oph_command_data*)malloc(sizeof(oph_command_data));
	if (!data) return RMANAGER_ERROR;

	data->command = strndup(command,OPH_MAX_STRING_SIZE);
	if (!data->command) return RMANAGER_ERROR;

	if (error)
	{
		data->error = strndup(error,OPH_MAX_STRING_SIZE);
		if (!data->error) return RMANAGER_ERROR;
	}
	else data->error = NULL;

	data->state = (struct oph_plugin_data *) malloc (sizeof (struct oph_plugin_data));
	if (!data->state) return RMANAGER_ERROR;
	memcpy(data->state, (struct oph_plugin_data*)state, sizeof (struct oph_plugin_data));
	if (state->serverid) data->state->serverid = strndup(state->serverid, OPH_MAX_STRING_SIZE);
	else data->state->serverid = NULL;
	data->state->is_copy = 1;
	data->state->job_info = state->job_info;

	pthread_t tid;
	pthread_create(&tid, NULL, (void*(*)(void*))&_oph_system, data);
	return RMANAGER_SUCCESS;
#else
	char fg_command[OPH_MAX_STRING_SIZE];
	snprintf(fg_command,OPH_MAX_STRING_SIZE,"%s &",command);
	return system(fg_command);
#endif
}
#endif

int oph_read_rmanager_conf(oph_rmanager *orm)
{
        if(!orm){
                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
                return RMANAGER_NULL_PARAM;
        }

        char config[OPH_MAX_STRING_SIZE];
        snprintf(config, sizeof(config), "%s", oph_rmanager_conf_file);

        FILE *file = fopen(config, "r");
        if(file == NULL)
        {
                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Configuration file not found\n");
                return RMANAGER_ERROR;
        }
        else
        {
		char buffer[OPH_MAX_STRING_SIZE];
                char *position;
		pmesg_safe(&global_flag,LOG_DEBUG, __FILE__,__LINE__, "Reading resource manager configuration file '%s'\n", config);

		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                        if(!(orm->name=(char*)malloc((strlen(position+1)+1)*sizeof(char))))
                        {
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->name, position+1, strlen(position+1)+1);
                        orm->name[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                 	pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_cmd=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_cmd, position+1, strlen(position+1)+1);
                        orm->subm_cmd[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                	pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                       	return RMANAGER_ERROR;
		}
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_args=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                        	pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_args, position+1, strlen(position+1)+1);
                        orm->subm_args[strlen(position+1)] = '\0';
                }
	
		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_ncores=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                        	pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_ncores, position+1, strlen(position+1)+1);
                        orm->subm_ncores[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->interact_subm=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->interact_subm, position+1, strlen(position+1)+1);
                        orm->interact_subm[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->batch_subm=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->batch_subm, position+1, strlen(position+1)+1);
                        orm->batch_subm[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_stdoutput=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_stdoutput, position+1, strlen(position+1)+1);
                        orm->subm_stdoutput[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_stderror=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_stderror, position+1, strlen(position+1)+1);
                        orm->subm_stderror[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_postfix=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_postfix, position+1, strlen(position+1)+1);
                        orm->subm_postfix[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->subm_jobname=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->subm_jobname, position+1, strlen(position+1)+1);
                        orm->subm_jobname[strlen(position+1)] = '\0';
                }

		fgetc(file);
		if( fscanf(file, "%[^\n]", buffer) == EOF)
                {
                        pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error retrieving data from configuration file\n");
                        fclose(file);
                        return RMANAGER_ERROR;
                }
                position = strchr(buffer, '=');
                if(position != NULL)
                {
                	if(!(orm->cancel=(char*)malloc((strlen(position+1)+1)*sizeof(char)))){
                                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                                fclose(file);
                                return RMANAGER_MEMORY_ERROR;
                        }
                        strncpy(orm->cancel, position+1, strlen(position+1)+1);
                        orm->cancel[strlen(position+1)] = '\0';
                }
	}

        fclose(file);

        return RMANAGER_SUCCESS;

}

int initialize_rmanager(oph_rmanager *orm)
{
        if(!orm){
                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
                return RMANAGER_NULL_PARAM;
        }

        orm->name=NULL;
        orm->subm_cmd = NULL;
        orm->subm_args = NULL;
        orm->subm_ncores = NULL;
        orm->interact_subm = NULL;
        orm->batch_subm = NULL;
	orm->subm_stdoutput = NULL;
	orm->subm_stderror = NULL;
        orm->subm_postfix = NULL;
        orm->subm_jobname = NULL;
        orm->cancel = NULL;

        return RMANAGER_SUCCESS;
}

int oph_cancel_request(int jobid)
{
	if (!jobid) return RMANAGER_NULL_PARAM;
	if (orm && orm->cancel)
	{
#ifdef LOCAL_FRAMEWORK
		pmesg_safe(&global_flag,LOG_WARNING, __FILE__, __LINE__, "Task %d cannot be stopped\n");
#else
		size_t len = 1+strlen(orm->cancel)+strlen(OPH_RMANAGER_PREFIX)+OPH_RMANAGER_MAX_INT_SIZE;
		char cmd[len];
		snprintf(cmd, len, "%s %s%d", orm->cancel, OPH_RMANAGER_PREFIX, jobid);
		if (oph_ssh_submit(cmd))
		{
			pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error during remote submission\n");
			return RMANAGER_ERROR;
		}
		pmesg_safe(&global_flag,LOG_DEBUG, __FILE__, __LINE__, "Task %d has been stopped\n");
#endif
	}
	return RMANAGER_SUCCESS;
}

int oph_form_subm_string(const char *request, const int ncores, char *outfile, short int interactive_subm, oph_rmanager* orm, int jobid, char** cmd)
{
        if(!orm){
                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
                return RMANAGER_NULL_PARAM;
        }

	int len = 0;
	len = strlen(orm->subm_cmd) + 1 + strlen(orm->subm_args) + 1 + strlen(orm->subm_ncores) + 1 + strlen(orm->interact_subm) + 1 + strlen(orm->batch_subm) + 1 + strlen(orm->subm_stdoutput) + 1 + strlen(outfile) + 1 + strlen(orm->subm_stderror) + 1 + strlen(outfile) + 1 + strlen(orm->subm_postfix) + 1 + strlen(orm->subm_jobname) + 1 + strlen(request) + 128; // 128 is a very big number to include the number of cores and the name of the ophidia application client
	
        if(!(*cmd=(char*)malloc(len*sizeof(char)))){
        	pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Error allocating memory\n");
                return RMANAGER_MEMORY_ERROR;
        }

	if( !strcasecmp(orm->name, "lsf")){
		if(interactive_subm)
			sprintf(*cmd, "%s %s %s %d %s mpirun.lsf \"%s %s\" > %s 2>&1", orm->subm_cmd, orm->subm_args, orm->subm_ncores, ncores, orm->interact_subm, oph_operator_client, request, outfile);
		else
			sprintf(*cmd, "%s %s %s %d %s %s %s %s %s %s %s%d mpirun.lsf \"%s %s\" %s", orm->subm_cmd, orm->subm_args, orm->subm_ncores, ncores, orm->batch_subm, orm->subm_stdoutput, outfile, orm->subm_stderror, outfile, orm->subm_jobname, OPH_RMANAGER_PREFIX, jobid, oph_operator_client, request, orm->subm_postfix);
	}
	else //Default, SLURM
	{
		if(interactive_subm)
			sprintf(*cmd, "%s %s %s %d %s %s %s %s %s %s \"%s\"", orm->subm_cmd, orm->subm_args, orm->subm_ncores, ncores, orm->interact_subm,  orm->subm_stdoutput, outfile, orm->subm_stderror, outfile, oph_operator_client, request);
		else
			sprintf(*cmd, "%s %s %s %d %s %s %s %s %s %s %s%d %s \"%s\" %s", orm->subm_cmd, orm->subm_args, orm->subm_ncores, ncores, orm->batch_subm, orm->subm_stdoutput, outfile, orm->subm_stderror, outfile, orm->subm_jobname, OPH_RMANAGER_PREFIX, jobid, oph_operator_client, request, orm->subm_postfix);
	}
	pmesg_safe(&global_flag,LOG_DEBUG, __FILE__, __LINE__, "Submission string:\n%s\n", *cmd);

	return RMANAGER_SUCCESS;
}

int free_oph_rmanager(oph_rmanager *orm)
{
        if(!orm){
                pmesg_safe(&global_flag,LOG_ERROR, __FILE__, __LINE__, "Null input parameter\n");
                return RMANAGER_NULL_PARAM;
        }
        if(orm->name){
		free(orm->name);
		orm->name=NULL;
	}
        if(orm->subm_cmd){
		free(orm->subm_cmd);
		orm->subm_cmd=NULL;
	}
        if(orm->subm_args){
		free(orm->subm_args);
		orm->subm_args=NULL;
	}
        if(orm->subm_ncores){
		free(orm->subm_ncores);
		orm->subm_ncores=NULL;
	}
        if(orm->interact_subm){
		free(orm->interact_subm);
		orm->interact_subm=NULL;
	}
        if(orm->batch_subm){
		free(orm->batch_subm);
		orm->batch_subm=NULL;
	}
	if(orm->subm_stdoutput){
		free(orm->subm_stdoutput);
		orm->subm_stdoutput=NULL;
	}
	if(orm->subm_stderror){
		free(orm->subm_stderror);
		orm->subm_stderror=NULL;
	}
        if(orm->subm_postfix){
		free(orm->subm_postfix);
		orm->subm_postfix=NULL;
	}
	if(orm->subm_jobname){
		free(orm->subm_jobname);
		orm->subm_jobname=NULL;
	}
	if(orm->cancel){
		free(orm->cancel);
		orm->cancel=NULL;
	}
	free(orm);
        return RMANAGER_SUCCESS;

}

int oph_get_result_from_file(char* filename, char **response)
{
	/* declare a file pointer */
	FILE    *infile;
	long    numbytes;

	/* open an existing file for reading */
	pmesg_safe(&global_flag,LOG_DEBUG, __FILE__, __LINE__, "Opening file %s\n", filename);
	infile = fopen(filename, "r");

	/* quit if the file does not exist */
	if(infile == NULL){
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__,"Unable to open output file: %s\n", filename);
		return RMANAGER_FILE_ERROR;
	}

	/* Get the number of bytes */
	fseek(infile, 0L, SEEK_END);
	numbytes = ftell(infile);

	/* reset the file position indicator to the beginning of the file */
	fseek(infile, 0L, SEEK_SET);

	/* grab sufficient memory for the buffer to hold the text */
	*response = (char*)malloc((1+numbytes)*sizeof(char));

	/* memory error */
	if(*response == NULL){
   		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__,"Unable to alloc response\n");
		return RMANAGER_FILE_ERROR;
	}

	/* copy all the text into the buffer */
	size_t n = fread(*response, sizeof(char), numbytes, infile);
	if (!n) {
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__,"Unable to read response\n");
		return RMANAGER_FILE_ERROR;
	}

	(*response)[numbytes] = '\0';
	fclose(infile);

	/* confirm we have read the file by outputing it to the console */
	pmesg_safe(&global_flag,LOG_DEBUG,__FILE__,__LINE__,"The file called %s contains this text\n\n%s\n\n%d chars\n", filename, *response, n);

	return RMANAGER_SUCCESS;
}

int oph_serve_request(const char* request, const int ncores, const char* sessionid, const char* markerid, const char* error, struct oph_plugin_data *state, int *odb_wf_id, int *task_id, int *light_task_id, int* odb_jobid, char** response, char** jobid_response)
{
	pmesg_safe(&global_flag,LOG_DEBUG, __FILE__,__LINE__, "Incoming request '%s' to run job '%s#%s' with %d cores\n", request, sessionid, markerid, ncores);

	int _ncores = ncores;
	if (ncores < 1) {
		pmesg_safe(&global_flag,LOG_DEBUG, __FILE__,__LINE__, "The job will be executed with 1!\n");
		_ncores = 1;
	}

	int result;
	if ((result = oph_serve_known_operator(state, request, _ncores, sessionid, markerid, odb_wf_id, task_id, light_task_id, odb_jobid, response, jobid_response)) != OPH_SERVER_UNKNOWN) return result;

	char *cmd = NULL;

	if (!orm)
	{
		orm = (oph_rmanager*)malloc(sizeof(oph_rmanager));
		if (initialize_rmanager(orm))
	  	{
			pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error on initialization OphidiaDB\n");
			return OPH_SERVER_ERROR;
	  	}
		if(oph_read_rmanager_conf(orm))
		{
			pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error on read resource manager parameters\n");
			return OPH_SERVER_ERROR;
		}
	}

	char outfile[OPH_MAX_STRING_SIZE];
	char code[OPH_MAX_STRING_SIZE];
	if (oph_get_session_code(sessionid,code))
	{
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error on read resource manager parameters\n");
		return OPH_SERVER_ERROR;
	}
	snprintf(outfile, OPH_MAX_STRING_SIZE, OPH_TXT_FILENAME, oph_txt_location, code, markerid);

#ifdef LOCAL_FRAMEWORK
	char command[OPH_MAX_STRING_SIZE];
#ifdef USE_MPI
	snprintf(command, OPH_MAX_STRING_SIZE, "rm -f %s; mpirun -np %d %s \"%s\" >> %s 2>> %s", outfile, _ncores, oph_operator_client, request, outfile, outfile);
#else
	snprintf(command, OPH_MAX_STRING_SIZE, "rm -f %s; %s \"%s\" >> %s 2>> %s", outfile, oph_operator_client, request, outfile, outfile);
	if (_ncores > 1) pmesg_safe(&global_flag,LOG_WARNING, __FILE__,__LINE__, "MPI is disabled. Only one core will be used\n");
#endif
	pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "Execute command: %s\n",command);
	if (oph_system(command,error,state))
	{
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error on executing the command\n");
		if(cmd){
			free(cmd);
			cmd = NULL;
		}
		return OPH_SERVER_ERROR;
	}
#else
	if(oph_form_subm_string(request, _ncores, outfile, 0, orm, odb_jobid ? *odb_jobid : 0, &cmd))
	{
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error on forming submission string\n");
		if(cmd){
			free(cmd);
			cmd = NULL;
		}
		return OPH_SERVER_ERROR;
	}

	if(oph_system(cmd,error,state))
	{
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error during remote submission\n");
		if(cmd){
			free(cmd);
			cmd = NULL;
		}
		return OPH_SERVER_ERROR;
	}
#endif
	if(cmd){
		free(cmd);
		cmd = NULL;
	}

	return OPH_SERVER_OK;
}

