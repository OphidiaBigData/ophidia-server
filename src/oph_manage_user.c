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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "hashtbl.h"
#include "oph_ophidiadb.h"
#include "oph_auth.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ftw.h>

#ifdef INTERFACE_TYPE_IS_GSI
#include "globus_common.h"
#endif

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
pthread_mutex_t global_flag;
#endif

char* oph_server_location=0;
HASHTBL *oph_server_params=0;
int oph_server_timeout=OPH_SERVER_TIMEOUT;
char* oph_auth_location=0;
char* oph_web_server=0;
oph_auth_user_bl* bl_head=0;
ophidiadb *ophDB=0;
oph_argument *args=0;

void cleanup(){
  oph_cleanup_args(&args);
  mysql_library_end();
  if (oph_server_params) hashtbl_destroy(oph_server_params);
#ifdef OPH_SERVER_LOCATION
  if (oph_server_location) free(oph_server_location);
#endif
  if (ophDB) oph_odb_free_ophidiadb(ophDB);
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
  pthread_mutex_destroy(&global_flag);
#endif
}

int oph_mkdir(const char* name)
{
	struct stat st;
	int res = stat(name, &st);
	if (!res) pmesg(LOG_WARNING, __FILE__, __LINE__, "Session directory '%s' already exist\n",name);
	else if (res == -1)
	{
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session directory creation: '%s'\n",name);
		if (mkdir(name, 0755))
		{
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Session directory cannot be created\n");
			return OPH_SERVER_IO_ERROR;
		}
	}
	else
	{
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Session directory cannot be created\n");
		return OPH_SERVER_IO_ERROR;
	}

	return OPH_SERVER_OK;
}

int _delete_files(const char* path, const struct stat* st, int flag, struct FTW *ftw)
{
	UNUSED(st); UNUSED(flag); UNUSED(ftw);
	return remove(path);
}

void set_global_values(const char* configuration_file)
{
	if (!configuration_file) return;
	pmesg(LOG_INFO, __FILE__,__LINE__,"Loading configuration from '%s'\n",configuration_file);

	oph_server_params = hashtbl_create(HASHTBL_KEY_NUMBER, NULL);
	if (!oph_server_params) return;

	char tmp[OPH_MAX_STRING_SIZE];
	char* value;
	FILE* file = fopen(configuration_file,"r");
	if (file)
	{
		char key[OPH_MAX_STRING_SIZE], value2[OPH_MAX_STRING_SIZE];
		while (fgets(tmp,OPH_MAX_STRING_SIZE,file))
		{
			if (strlen(tmp))
			{
				tmp[strlen(tmp)-1]='\0';
				if (tmp[0]==OPH_COMMENT_MARK) continue; // Skip possible commented lines
				value=strchr(tmp,OPH_SEPARATOR_KV[0]);
				if (value)
				{
					value++;
					snprintf(key,value-tmp,"%s",tmp);
					if (value[0])
					{
						if (value[0]==OPH_SUBSTITUTION_MARK && !strncasecmp(value+1,OPH_SERVER_LOCATION_STR,strlen(OPH_SERVER_LOCATION_STR)))
						{
							snprintf(value2,OPH_MAX_STRING_SIZE,"%s%s",oph_server_location,value+strlen(OPH_SERVER_LOCATION_STR)+1);
							value = value2;
						}
						hashtbl_insert(oph_server_params, key, value);
					}
					else hashtbl_insert(oph_server_params, key, "");
					pmesg(LOG_DEBUG, __FILE__,__LINE__,"Read %s=%s\n",key,value);
				}
			}
		}
		fclose(file);
	}

	// Pre-process
	if (!(oph_auth_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR)))
	{
		snprintf(tmp,OPH_MAX_STRING_SIZE,OPH_SERVER_AUTHZ,oph_server_location);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR, tmp);
		oph_auth_location = hashtbl_get(oph_server_params, OPH_SERVER_CONF_AUTHZ_DIR);
	}
	if (!(oph_web_server = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER)))
	{
		snprintf(tmp,OPH_MAX_STRING_SIZE,OPH_WEB_SERVER);
		hashtbl_insert(oph_server_params, OPH_SERVER_CONF_WEB_SERVER, tmp);
		oph_web_server = hashtbl_get(oph_server_params, OPH_SERVER_CONF_WEB_SERVER);
	}
}

int main(int argc, char* argv[])
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_mutex_init(&global_flag, NULL);
#endif
	int ch, msglevel = LOG_ERROR;
	char *action = NULL, *username = NULL, *password = NULL, *name = NULL, *surname = NULL, *email = NULL, *country = NULL, *is_admin = NULL;
	unsigned int max_sessions = 100, timeout_session = 1, max_cores = 8, black_listed = 0, update = 0;
	while ((ch = getopt(argc, argv, "a:bc:e:f:hm:n:p:r:s:t:u:vw"))!=-1)
	{
		switch (ch)
		{
			case 'a':
				action = optarg;
			break;
			case 'c':
				max_cores = (unsigned int)strtol(optarg,NULL,10);
				if (max_cores<=0) max_cores = 1;
				update += 1;
			break;
			case 'e':
				email = optarg;
			break;
			case 'f':
				country = optarg;
			break;
			case 'm':
				max_sessions = (unsigned int)strtol(optarg,NULL,10);
				if (max_sessions<=0) max_sessions = 1;
				update += 2;
			break;
			case 'n':
				name = optarg;
			break;
			case 'p':
				password = optarg; // For GSI it means 'role': read, write...
			break;
			case 'r':
				is_admin = optarg;
				if (strcasecmp(is_admin,"yes") && strcasecmp(is_admin,"no"))
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__,"Bad input parameter. Use '-r yes' or '-r no'!\n");
					cleanup();
					return 1;
				}
				update += 4;
			break;
			case 's':
				surname = optarg;
			break;
			case 't':
				timeout_session = (unsigned int)strtol(optarg,NULL,10);
				if (timeout_session<=0) timeout_session = 1;
				update += 8;
			break;
			case 'u':
				username = optarg;
			break;
			case 'v':
				msglevel = LOG_DEBUG;
			break;
			case 'w':
				if (msglevel<LOG_WARNING) msglevel = LOG_WARNING;
			break;
			case 'b':
#ifdef INTERFACE_TYPE_IS_GSI
				black_listed = 1;
				break;
#endif
			case 'h':
			default:
				fprintf(stdout,"Usage:\noph_manage_user -a add|del|list|update [-u <username>] [other params] [-v] [-w]\n");
#ifdef INTERFACE_TYPE_IS_GSI
				fprintf(stdout,"-b to black-list the user\n");
#endif
				fprintf(stdout,"-c <maximum number of cores per task>\n");
				fprintf(stdout,"-e <email>\n");
				fprintf(stdout,"-f <country>\n");
				fprintf(stdout,"-m <maximum number of opened sessions>\n");
				fprintf(stdout,"-n <name>\n");
#ifdef INTERFACE_TYPE_IS_GSI
				fprintf(stdout,"-p <role>\n");
#else
				fprintf(stdout,"-p <password>\n");
#endif
				fprintf(stdout,"-r <yes|no> to enable|disable administration privileges\n");
				fprintf(stdout,"-s <surname>\n");
				fprintf(stdout,"-t <session timeout> in days\n");
				return 0;
		}
	}

	set_debug_level(msglevel+10);
	pmesg(LOG_INFO, __FILE__,__LINE__,"Selected log level %d\n",msglevel);

	if (!action)
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Set an action with the option -a: add|del|list|update\n");
		cleanup();
		return 1;
	}

#ifdef OPH_SERVER_LOCATION
	oph_server_location = strdup(OPH_SERVER_LOCATION);
#else
	oph_server_location = getenv(OPH_SERVER_LOCATION_STR);
	if (!oph_server_location)
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"OPH_SERVER_LOCATION has to be set\n");
		cleanup();
		return 1;
	}
#endif
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Server location '%s'\n",oph_server_location);

	char filename[OPH_MAX_STRING_SIZE];
	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_CONFIGURATION_FILE,oph_server_location);
	set_global_values(filename);

	FILE* file;
	oph_argument *tmp;
#ifdef INTERFACE_TYPE_IS_GSI
	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_AUTH_DN_FILE,oph_auth_location);
#else
	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_AUTH_FILE,oph_auth_location);
#endif
	oph_init_args(&args);
	if (oph_load_file2(filename, &args))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in opening '%s'\n",filename);
		cleanup();
		return 1;
	}

	if (mysql_library_init(0, 0, 0))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Cannot setup MySQL\n");
		exit(1);
	}

	size_t iiii,jjjj=strlen(username?username:"");
	char user_string[1+jjjj];
	if (username)
	{
		strcpy(user_string,username);
		for (iiii=0;iiii<jjjj;++iiii) if ((user_string[iiii]=='/') || (user_string[iiii]==' ') || (user_string[iiii]=='=') || (user_string[iiii]==':')) user_string[iiii]='_';
	}

	if (!strcasecmp(action,"add") || !strcasecmp(action,"append") || !strcasecmp(action,"create"))
	{
		if (!username || !password)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Bad input parameters. Username and password are mandatory!\n");
			cleanup();
			return 1;
		}
		for (tmp=args; tmp; tmp=tmp->next) if (!strcmp(username,tmp->key))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"User already exists!\n");
			cleanup();
			return 1;
		}

		// users.dat
		file = fopen(filename,"a");
		if (!file)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"File cannot be opened!\n");
			cleanup();
			return 1;
		}
		fprintf(file,"%s%s%s\n",username,OPH_SEPARATOR_BASIC,password);
		fclose(file);

		// folders
		snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_DIR,oph_auth_location,user_string);
		if (oph_mkdir(filename))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Directory cannot be opened!\n");
			cleanup();
			return 1;
		}
		snprintf(filename,OPH_MAX_STRING_SIZE,OPH_SESSION_DIR,oph_auth_location,user_string);
		if (oph_mkdir(filename))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Directory cannot be opened!\n");
			cleanup();
			return 1;
		}

		// user.dat
		snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_FILE,oph_auth_location,user_string);
		file = fopen(filename,"w");
		if (!file)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"File cannot be opened!\n");
			cleanup();
			return 1;
		}
		fprintf(file,"%s%s%d\n",OPH_USER_OPENED_SESSIONS,OPH_SEPARATOR_KV,0);
		fprintf(file,"%s%s%d\n",OPH_USER_MAX_SESSIONS,OPH_SEPARATOR_KV,max_sessions);
		fprintf(file,"%s%s%d\n",OPH_USER_TIMEOUT_SESSION,OPH_SEPARATOR_KV,timeout_session);
		fprintf(file,"%s%s%d\n",OPH_USER_MAX_CORES,OPH_SEPARATOR_KV,max_cores);
		fprintf(file,"%s%s%d\n",OPH_USER_MAX_HOSTS,OPH_SEPARATOR_KV,1);
		fprintf(file,"%s%s%s\n",OPH_USER_IS_ADMIN,OPH_SEPARATOR_KV,is_admin);
		fprintf(file,"%s%s\n",OPH_USER_LAST_SESSION_ID,OPH_SEPARATOR_KV);
		fclose(file);

		// ophDB
		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
			cleanup();
			return 1;
		}
		else if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
			cleanup();
			return 1;
		}
		else if (oph_odb_insert_user2(&oDB, username, password, name, surname, email, country))
		{
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to insert new user data in OphidiaDB.\n");
			cleanup();
			return 1;
		}
		else oph_odb_disconnect_from_ophidiadb(&oDB);
	}
	else if (!strcasecmp(action,"del") || !strcasecmp(action,"delete") || !strcasecmp(action,"rm") || !strcasecmp(action,"remove"))
	{
		if (!username)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Bad input parameters. Username is mandatory!\n");
			cleanup();
			return 1;
		}
		for (tmp=args; tmp; tmp=tmp->next) if (!strcmp(username,tmp->key)) break;
		if (!tmp)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"User not found!\n");
			cleanup();
			return 1;
		}

		// users.dat
		file = fopen(filename,"w");
		if (!file)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' cannot be opened!\n",filename);
			cleanup();
			return 1;
		}
		for (tmp=args; tmp; tmp=tmp->next) if (strcmp(username,tmp->key)) fprintf(file,"%s%s%s\n",tmp->key,OPH_SEPARATOR_BASIC,tmp->value);
		fclose(file);

		// folder
		snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_DIR,oph_auth_location,user_string);
		if (nftw(filename, _delete_files, 2, FTW_DEPTH | FTW_PHYS))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Directory '%s' cannot be removed!\n",filename);
			cleanup();
			return 1;
		}

		// ophDB
		ophidiadb oDB;
		oph_odb_initialize_ophidiadb(&oDB);
		if(oph_odb_read_config_ophidiadb(&oDB))
		{
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
			cleanup();
			return 1;
		}
		else if(oph_odb_connect_to_ophidiadb(&oDB))
		{
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
			cleanup();
			return 1;
		}
		else if (oph_odb_delete_user(&oDB, username))
		{
			oph_odb_disconnect_from_ophidiadb(&oDB);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to insert new user data in OphidiaDB.\n");
			cleanup();
			return 1;
		}
		else oph_odb_disconnect_from_ophidiadb(&oDB);
	}
	else if (!strcasecmp(action,"update"))
	{
		if (!username)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Bad input parameters. Username is mandatory!\n");
			cleanup();
			return 1;
		}
		for (tmp=args; tmp; tmp=tmp->next) if (!strcmp(username,tmp->key)) break;
		if (!tmp)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"User not found!\n");
			cleanup();
			return 1;
		}

		// users.dat
		if (password)
		{
			file = fopen(filename,"w");
			if (!file)
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' cannot be opened!\n",filename);
				cleanup();
				return 1;
			}
			for (tmp=args; tmp; tmp=tmp->next)
				if (strcmp(username,tmp->key)) fprintf(file,"%s%s%s\n",tmp->key,OPH_SEPARATOR_BASIC,tmp->value);
				else fprintf(file,"%s%s%s\n",username,OPH_SEPARATOR_BASIC,password);
			fclose(file);
		}

		// user.dat
		if (update)
		{
			oph_cleanup_args(&args);

			snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_FILE,oph_auth_location,user_string);
			if (oph_load_file(filename, &args))
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' cannot be opened!\n",filename);
				cleanup();
				return 1;
			}
			file = fopen(filename,"w");
			if (!file)
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' cannot be opened!\n",filename);
				cleanup();
				return 1;
			}
			if (update & 2) for (tmp=args; tmp; tmp=tmp->next)
			{
				unsigned int opened_sessions = (unsigned int)strtol(tmp->value,NULL,10);
				if (!strcmp(tmp->key,OPH_USER_OPENED_SESSIONS) && (max_sessions < opened_sessions))
				{
					pmesg(LOG_WARNING, __FILE__,__LINE__,"Current number of opened sessions (%d) is higher than %d!\n",opened_sessions,max_sessions);
					max_sessions = opened_sessions;
				}
			}
			for (tmp=args; tmp; tmp=tmp->next)
			{
				if ((update & 1) && (!strcmp(tmp->key,OPH_USER_MAX_CORES))) fprintf(file,"%s%s%d\n",OPH_USER_MAX_CORES,OPH_SEPARATOR_KV,max_cores);
				else if ((update & 2) && (!strcmp(tmp->key,OPH_USER_MAX_SESSIONS))) fprintf(file,"%s%s%d\n",OPH_USER_MAX_SESSIONS,OPH_SEPARATOR_KV,max_sessions);
				else if ((update & 4) && (!strcmp(tmp->key,OPH_USER_IS_ADMIN))) fprintf(file,"%s%s%s\n",OPH_USER_IS_ADMIN,OPH_SEPARATOR_KV,is_admin);
				else if ((update & 8) && (!strcmp(tmp->key,OPH_USER_TIMEOUT_SESSION))) fprintf(file,"%s%s%d\n",OPH_USER_TIMEOUT_SESSION,OPH_SEPARATOR_KV,timeout_session);
				else fprintf(file,"%s%s%s\n",tmp->key,OPH_SEPARATOR_KV,tmp->value);
			}
			fclose(file);
		}

		// ophDB
		if (password || name || surname || email || country)
		{
			ophidiadb oDB;
			oph_odb_initialize_ophidiadb(&oDB);
			if(oph_odb_read_config_ophidiadb(&oDB))
			{
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to read OphidiaDB configuration\n");
				cleanup();
				return 1;
			}
			else if(oph_odb_connect_to_ophidiadb(&oDB))
			{
				oph_odb_disconnect_from_ophidiadb(&oDB);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to connect to OphidiaDB. Check access parameters.\n");
				cleanup();
				return 1;
			}
			else if (oph_odb_update_user(&oDB, username, password, name, surname, email, country))
			{
				oph_odb_disconnect_from_ophidiadb(&oDB);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to insert new user data in OphidiaDB.\n");
				cleanup();
				return 1;
			}
			else oph_odb_disconnect_from_ophidiadb(&oDB);
		}

#ifdef INTERFACE_TYPE_IS_GSI
		if (black_listed)
		{
			char *black_list = globus_libc_getenv("BLACK_LIST_FILE");
			char *black_list_file = strdup(black_list?black_list:BLACK_LIST_FILE);
			snprintf(filename,OPH_MAX_STRING_SIZE,black_list_file);
			file = fopen(filename,"a");
			if (!file)
			{
				pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' cannot be opened!\n",filename);
				cleanup();
				return 1;
			}
			fprintf(file,"%s\n",username);
			fclose(file);
		}
#else
		UNUSED(black_listed)
#endif
	}
	else if (!strcasecmp(action,"list")) for (tmp=args; tmp; tmp=tmp->next) printf("%s\n",tmp->key);
	else pmesg(LOG_ERROR, __FILE__,__LINE__,"Bad command '%s'\n",action);

	cleanup();

	pmesg(LOG_INFO, __FILE__,__LINE__,"Ok\n");
	return 0;
}

