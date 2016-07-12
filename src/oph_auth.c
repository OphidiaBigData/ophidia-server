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

#define _GNU_SOURCE

#include "oph_auth.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>

#ifdef INTERFACE_TYPE_IS_SSL
#include <openssl/sha.h>
#endif

#define OPH_AUTH_MAX_COUNT 5

extern char* oph_auth_location;
extern char* oph_web_server;
extern oph_auth_user_bl* bl_head;
extern int oph_server_timeout;

int oph_get_session_code(const char* sessionid, char* code)
{
	char tmp[OPH_MAX_STRING_SIZE];
	strncpy(tmp,sessionid,OPH_MAX_STRING_SIZE);

	char* tmp2 = tmp, *savepointer = NULL;
	unsigned short i,max=3;
	if (oph_web_server)
	{
		unsigned int length = strlen(oph_web_server);
		if ((length >= OPH_MAX_STRING_SIZE) || strncmp(sessionid,oph_web_server,length)) return OPH_SERVER_ERROR;
		tmp2 += length;
		max = 1;
	}

	tmp2 = strtok_r(tmp2,OPH_SEPARATOR_FOLDER,&savepointer);
	if (!tmp2) return OPH_SERVER_ERROR;
	for (i=0;i<max;++i)
	{
		tmp2 = strtok_r(NULL,OPH_SEPARATOR_FOLDER,&savepointer);
		if (!tmp2) return OPH_SERVER_ERROR;
	}
	strcpy(code,tmp2);
	
	return OPH_SERVER_OK;
}

int oph_load_file(const char* filename, oph_argument** args)
{
	if (!filename || !args) return OPH_SERVER_NULL_POINTER;

	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Open file '%s'\n",filename);

	FILE* file;
	oph_argument* tail = *args = NULL;
	int result = OPH_SERVER_OK;

	if (result == OPH_SERVER_OK)
	{
		if ((file = fopen(filename,"r")))
		{
			char buffer[OPH_MAX_STRING_SIZE], *pch;
			oph_argument* tmp;
			while(fgets(buffer,OPH_MAX_STRING_SIZE,file))
			{
				if (strlen(buffer) && (buffer[strlen(buffer)-1]=='\n')) buffer[strlen(buffer)-1]=0; // Skip the last '\n'
				if (strlen(buffer))
				{
					pch = strchr(buffer,OPH_SEPARATOR_KV[0]);
					if (!pch)
					{
						pmesg(LOG_ERROR, __FILE__,__LINE__,"File is corrupted\n");
						result = OPH_SERVER_IO_ERROR;
						break;
					}
					tmp = (oph_argument*)malloc(sizeof(oph_argument));
					if (strlen(pch)<=1) tmp->value = strdup("");
					else tmp->value = strndup(pch+1,OPH_MAX_STRING_SIZE);
					pch[0]=0;
					tmp->key = strndup(buffer,OPH_MAX_STRING_SIZE);
					tmp->next = NULL;

					if (tail) tail->next = tmp;
					else *args = tmp;
					tail = tmp;
				}
			}
			fclose(file);
		}
		else
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"File not found\n");
			result = OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
	}

	return result;
}

int oph_load_file2(const char* filename, oph_argument** args)
{
	if (!filename || !args) return OPH_SERVER_NULL_POINTER;

	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Open file '%s'\n",filename);

	FILE* file;
	oph_argument* tail = *args = NULL;
	int result = OPH_SERVER_OK;

	if (result == OPH_SERVER_OK)
	{
		if ((file = fopen(filename,"r")))
		{
			char buffer[OPH_MAX_STRING_SIZE], *pch;
			oph_argument* tmp;
			while(fgets(buffer,OPH_MAX_STRING_SIZE,file))
			{
				if (strlen(buffer) && (buffer[strlen(buffer)-1]=='\n')) buffer[strlen(buffer)-1]=0; // Skip the last '\n'
				if (strlen(buffer))
				{
					pch = strrchr(buffer,OPH_SEPARATOR_BASIC[0]);
					if (!pch)
					{
						pmesg(LOG_ERROR, __FILE__,__LINE__,"File is corrupted\n");
						result = OPH_SERVER_IO_ERROR;
						break;
					}
					tmp = (oph_argument*)malloc(sizeof(oph_argument));
					if (strlen(pch)<=1) tmp->value = strdup("");
					else tmp->value = strndup(pch+1,OPH_MAX_STRING_SIZE);
					pch[0]=0;
					tmp->key = strndup(buffer,OPH_MAX_STRING_SIZE);
					tmp->next = NULL;

					if (tail) tail->next = tmp;
					else *args = tmp;
					tail = tmp;
				}
			}
			fclose(file);
		}
		else
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"File not found\n");
			result = OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
	}

	return result;
}

int oph_add_to_bl(const char* userid, const char* host)
{
	if (!userid || !host) return OPH_SERVER_NULL_POINTER;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl* bl_item = (oph_auth_user_bl*)malloc(sizeof(oph_auth_user_bl));
	bl_item->userid = strdup(userid);
	bl_item->host = strdup(host);
	bl_item->count = 1;
	bl_item->timestamp = tv.tv_sec;
	bl_item->next = bl_head;
	bl_head = bl_item;

	return OPH_SERVER_OK;
}
short oph_is_in_bl(const char* userid, const char* host, char* deadline)
{
	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = bl_head, *bl_prev=NULL;
	while (bl_item)
	{
		deadtime = (time_t)(bl_item->timestamp + oph_server_timeout);
		if (tv.tv_sec > deadtime)
		{
			if (bl_prev) bl_prev->next = bl_item->next;
			else bl_head = bl_item->next;
			if (bl_item->userid) free(bl_item->userid);
			if (bl_item->host) free(bl_item->host);
			free(bl_item);
			bl_item = bl_prev ? bl_prev->next : bl_head;
		}
		else if (!strcmp(bl_item->userid,userid) && !strcmp(bl_item->host,host))
		{
			struct tm *nowtm = localtime(&deadtime);
			strftime(deadline, OPH_MAX_STRING_SIZE, "%H:%M:%S", nowtm);
			bl_item->count++;
			return bl_item->count;
		}
		else
		{
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return 0;
}
int oph_drop_from_bl(const char* userid, const char* host)
{
	if (!userid || !host) return OPH_SERVER_NULL_POINTER;

	int found=0;
	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = bl_head, *bl_prev=NULL;
	while (bl_item)
	{
		deadtime = (time_t)(bl_item->timestamp + oph_server_timeout);
		if ( (found = !strcmp(bl_item->userid,userid) && !strcmp(bl_item->host,host)) || (tv.tv_sec > deadtime) )
		{
			if (bl_prev) bl_prev->next = bl_item->next;
			else bl_head = bl_item->next;
			if (bl_item->userid) free(bl_item->userid);
			if (bl_item->host) free(bl_item->host);
			free(bl_item);
			if (found) return OPH_SERVER_OK;
			else bl_item = bl_prev ? bl_prev->next : bl_head;
		}
		else
		{
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return OPH_SERVER_OK;
}

#ifdef INTERFACE_TYPE_IS_SSL
char *octet2hex(char *to, const unsigned char *str, size_t len)
{
	const char hexvalue[] = "0123456789ABCDEF";
	for (; len; --len, ++str)
	{
		*to++ = hexvalue[(*str) >> 4];
		*to++ = hexvalue[(*str) & 0x0F];
	}
	*to= '\0';
	return to;
}
char* oph_sha(char* to, const char* passwd)
{
	char* result = to;
	if (passwd && to)
	{
		unsigned char hash_stage[SHA_DIGEST_LENGTH];
		SHA_CTX sha1_context;
		if (!SHA1_Init(&sha1_context)) return NULL;
		if (!SHA1_Update(&sha1_context, passwd, strlen(passwd))) return NULL;
		memset(hash_stage,0,SHA_DIGEST_LENGTH);
		if (!SHA1_Final(hash_stage, &sha1_context)) return NULL;
		if (!SHA1_Init(&sha1_context)) return NULL;
		if (!SHA1_Update(&sha1_context, hash_stage, SHA_DIGEST_LENGTH)) return NULL;
		memset(hash_stage,0,SHA_DIGEST_LENGTH);
		if (!SHA1_Final(hash_stage, &sha1_context)) return NULL;
		*to++= '*';
		octet2hex(to, hash_stage, SHA_DIGEST_LENGTH);
	}
	return result;
}
#endif

int oph_auth_user(const char* userid, const char* passwd, const char* host)
{
	int result = OPH_SERVER_ERROR;
	FILE* file;
	short count;

	if (!userid || !passwd) return OPH_SERVER_NULL_POINTER;

	char oph_auth_file[OPH_MAX_STRING_SIZE], deadline[OPH_MAX_STRING_SIZE];
	snprintf(oph_auth_file,OPH_MAX_STRING_SIZE,OPH_AUTH_FILE,oph_auth_location);

#ifdef INTERFACE_TYPE_IS_SSL
	char sha_passwd[2*SHA_DIGEST_LENGTH+2];
	oph_sha(sha_passwd, passwd);
#endif

	if ((file = fopen(oph_auth_file,"r")))
	{
		char buffer[OPH_MAX_STRING_SIZE], *username, *password, *savepointer = NULL;
		while(fgets(buffer,OPH_MAX_STRING_SIZE,file))
		{
			if (strlen(buffer) && (buffer[strlen(buffer)-1]=='\n')) buffer[strlen(buffer)-1]=0; // Skip the last '\n'
			if (strlen(buffer))
			{
				username = strtok_r(buffer,OPH_SEPARATOR_BASIC,&savepointer);
				if (!username)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' is corrupted\n",oph_auth_file);
					result = OPH_SERVER_IO_ERROR;
					break;
				}
				if (strcmp(userid, username)) continue;
				if ((count = oph_is_in_bl(userid, host, deadline)) > OPH_AUTH_MAX_COUNT)
				{
					pmesg(LOG_WARNING, __FILE__,__LINE__,"Access of user '%s' from %s has been blocked until %s since too access attemps have been received\n",userid,host,deadline);
					result = OPH_SERVER_AUTH_ERROR;
					break;
				}
				password = strtok_r(NULL,OPH_SEPARATOR_BASIC,&savepointer);
				if (!password)
				{
					pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' is corrupted\n",oph_auth_file);
					result = OPH_SERVER_IO_ERROR;
				}
				else if (!strcmp(passwd, password))
				{
					pmesg(LOG_DEBUG, __FILE__,__LINE__,"User '%s' is authorized\n",userid);
					oph_drop_from_bl(userid,host);
					result = OPH_SERVER_OK;
				}
#ifdef INTERFACE_TYPE_IS_SSL
				else if (!strcmp(sha_passwd, password))
				{
					pmesg(LOG_DEBUG, __FILE__,__LINE__,"User '%s' is authorized\n",userid);
					oph_drop_from_bl(userid,host);
					result = OPH_SERVER_OK;
				}
#endif
				else if (!count) oph_add_to_bl(userid,host);
				break;
			}
		}
		fclose(file);
	}
	else result = OPH_SERVER_IO_ERROR;
	
	return result;
}

int oph_load_user(const char* userid, oph_argument** args, int* save_in_odb)
{
	if (!userid || !args) return OPH_SERVER_NULL_POINTER;
	if (save_in_odb) *save_in_odb=0;

	// Dynamic creation of the folders
	char dirname[OPH_MAX_STRING_SIZE];
	snprintf(dirname,OPH_MAX_STRING_SIZE,OPH_SESSION_DIR,oph_auth_location,userid);

	struct stat s;
	if (stat(dirname,&s) && (errno==ENOENT))
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__,"Automatic creation of configuration directories\n");
		int i;
		for (i=0;dirname[i];++i)
		{
			if (dirname[i]=='/')
			{
				dirname[i]=0;
				mkdir(dirname, 0755);
				dirname[i]='/';
			}
		}
		mkdir(dirname, 0755);
	}

	char filename[OPH_MAX_STRING_SIZE];
	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_FILE,oph_auth_location,userid);
	if (stat(filename,&s) && (errno==ENOENT))
	{
		pmesg(LOG_DEBUG, __FILE__,__LINE__,"Automatic creation of configuration files\n");
		oph_argument *tmp, *tail = *args = NULL;

		tmp = (oph_argument*)malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_OPENED_SESSIONS);
		if (asprintf(&tmp->value,"%d",OPH_DEFAULT_USER_OPENED_SESSIONS) <= 0)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in creation of configuration files\n");
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail) tail->next = tmp; else *args = tmp;
		tail = tmp;
		tmp = (oph_argument*)malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_MAX_SESSIONS);
		if (asprintf(&tmp->value,"%d",OPH_DEFAULT_USER_MAX_SESSIONS) <= 0)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in creation of configuration files\n");
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail) tail->next = tmp; else *args = tmp;
		tail = tmp;
		tmp = (oph_argument*)malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_TIMEOUT_SESSION);
		if (asprintf(&tmp->value,"%d",OPH_DEFAULT_SESSION_TIMEOUT) <= 0)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in creation of configuration files\n");
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail) tail->next = tmp; else *args = tmp;
		tail = tmp;
		tmp = (oph_argument*)malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_MAX_CORES);
		if (asprintf(&tmp->value,"%d",OPH_DEFAULT_USER_MAX_CORES) <= 0)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in creation of configuration files\n");
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail) tail->next = tmp; else *args = tmp;
		tail = tmp;
		tmp = (oph_argument*)malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_MAX_HOSTS);
		if (asprintf(&tmp->value,"%d",OPH_DEFAULT_USER_MAX_HOSTS) <= 0)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in creation of configuration files\n");
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail) tail->next = tmp; else *args = tmp;
		tail = tmp;
		tmp = (oph_argument*)malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_IS_ADMIN);
		tmp->value = strdup(OPH_DEFAULT_NO);
		tmp->next = NULL;
		if (tail) tail->next = tmp; else *args = tmp;
		tail = tmp;

		pmesg(LOG_DEBUG, __FILE__,__LINE__,"Saving configuration data of '%s'\n",userid);
		if (*args && oph_save_user(userid, *args))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Error in saving configuration data of '%s'\n",userid);
			oph_cleanup_args(args);
			return OPH_SERVER_IO_ERROR;
		}

		if (save_in_odb) *save_in_odb=1;
	}
	else if (oph_load_file(filename, args)) return OPH_SERVER_ERROR; // DT_REG
	
	return OPH_SERVER_OK;
}

int oph_save_user(const char* userid, oph_argument* args)
{
	if (!userid || !args) return OPH_SERVER_NULL_POINTER;

	int result = OPH_SERVER_OK;
	char filename[OPH_MAX_STRING_SIZE];
	FILE* file;

	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_FILE,oph_auth_location,userid);
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"User data saving in '%s'\n",filename);
	if ((file = fopen(filename,"w")))
	{
		oph_argument* tmp;
		for (tmp=args; tmp; tmp=tmp->next) fprintf(file,"%s=%s\n",tmp->key,tmp->value);
		fclose(file);
	}
	else result = OPH_SERVER_IO_ERROR;

	return result;
}

// This function changes the argument 'user_string'
int oph_check_role_of(const char* userid, char* user_string, oph_auth_user_role* role)
{
	if (!userid || !user_string || !role) return OPH_SERVER_WRONG_PARAMETER_ERROR;
	*role = OPH_ROLE_NONE;

	char* upointer = strstr(user_string,userid);
	if (!upointer)
	{
		int iiii,jjjj=strlen(user_string);
		for (iiii=0;iiii<jjjj;++iiii) if ((user_string[iiii]=='/') || (user_string[iiii]==' ') || (user_string[iiii]=='=') || (user_string[iiii]==':')) user_string[iiii]='_';
		upointer = strstr(user_string,userid);
		if (!upointer)
		{
			pmesg(LOG_DEBUG, __FILE__,__LINE__, "User '%s' not found in session user list '%s'\n",userid,user_string);
			return OPH_SERVER_OK;
		}
	}

	char *rpointer = strchr(upointer,OPH_SEPARATOR_ROLE);
	if (!rpointer)
	{
		pmesg(LOG_WARNING, __FILE__,__LINE__, "Session data are not correct\n");
		return OPH_SERVER_SYSTEM_ERROR;
	}

	char *save_pointer = NULL, *epointer = strtok_r(rpointer,OPH_SEPARATOR_USER,&save_pointer);
	if (!epointer)
	{
		pmesg(LOG_WARNING, __FILE__,__LINE__, "Session data are not correct\n");
		return OPH_SERVER_SYSTEM_ERROR;
	}

	*rpointer=0;
	*role = oph_string_to_role(1+rpointer);
	if (*role == OPH_ROLE_NONE)
	{
		pmesg(LOG_WARNING, __FILE__,__LINE__, "Session data are not correct: role '%s' does not exist\n",1+rpointer);
		return OPH_SERVER_SYSTEM_ERROR;
	}

	return OPH_SERVER_OK;
}

int oph_auth_session(const char* userid, const char* sessionid, const char* serverid, oph_argument** args, int* active, oph_auth_user_role *role)
{
	if (!userid || !sessionid || !args) return OPH_SERVER_NULL_POINTER;
	if (role) *role = OPH_ROLE_NONE;

	char filename[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE];

	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Extract session code from '%s'\n",sessionid);
	if (oph_get_session_code(sessionid,code))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Unable to extract session code from '%s'\n",sessionid);
		return OPH_SERVER_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Session code is '%s'\n",code);

	if (serverid)
	{
		char effective_sessionid[OPH_MAX_STRING_SIZE];
		snprintf(effective_sessionid,OPH_MAX_STRING_SIZE,OPH_SESSIONID_TEMPLATE,serverid,code);
		if (strncmp(sessionid,effective_sessionid,OPH_MAX_STRING_SIZE))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Session id '%s' does not match with the template\n",sessionid);
			return OPH_SERVER_ERROR;
		}
	}

	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,userid,code);
	if (oph_load_file(filename, args)) // DT_LNK
	{
		oph_cleanup_args(args);
		return OPH_SERVER_ERROR;
	}

	char tmp[OPH_MAX_STRING_SIZE];

	// Check if session is active
	if (active)
	{
		if (oph_get_arg(*args, OPH_SESSION_ACTIVE, tmp))
		{
			oph_cleanup_args(args);
			pmesg(LOG_WARNING, __FILE__,__LINE__,"Error in loading data of session: %s\n", sessionid);
			return OPH_SERVER_ERROR;
		}
		if (strcmp(tmp,OPH_DEFAULT_YES)) *active=0;
		else *active=1;
	}

	// Check user role
	if (role)
	{
		if (oph_get_arg(*args, OPH_SESSION_OWNER, tmp))
		{
			oph_cleanup_args(args);
			pmesg(LOG_WARNING, __FILE__,__LINE__,"Error in loading data of session: %s\n", sessionid);
			return OPH_SERVER_ERROR;
		}
		pmesg(LOG_DEBUG, __FILE__,__LINE__,"Owner of this session is: %s\n", tmp);
		int i,j=strlen(tmp);
		for (i=0;i<j;++i) if ((tmp[i]=='/') || (tmp[i]==' ') || (tmp[i]=='=') || (tmp[i]==':')) tmp[i]='_';
		if (!strcmp(userid, tmp)) *role = OPH_ROLE_ALL;
		else
		{
			if (oph_get_arg(*args, OPH_SESSION_USERS, tmp))
			{
				oph_cleanup_args(args);
				pmesg(LOG_WARNING, __FILE__,__LINE__,"Error in loading data of session: %s\n", sessionid);
				return OPH_SERVER_ERROR;
			}
			if (oph_check_role_of(userid, tmp, role))
			{
				oph_cleanup_args(args);
				pmesg(LOG_WARNING, __FILE__,__LINE__,"Error in loading data of session: %s\n", sessionid);
				return OPH_SERVER_ERROR;
			}
		}
	}

	return OPH_SERVER_OK;
}

int oph_save_session(const char* userid, const char* sessionid, oph_argument* args, int type)
{
	if (!userid || !sessionid || !args) return OPH_SERVER_NULL_POINTER;

	char filename[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE];
	FILE* file;

	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Extract session code from '%s'\n",sessionid);
	if (oph_get_session_code(sessionid,code))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Unable to extract session code from '%s'\n",sessionid);
		return OPH_SERVER_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Session code is '%s'\n",code);

	if (type == DT_REG)
	{
		// Create file
		char str_time[OPH_MAX_STRING_SIZE], dirname[OPH_MAX_STRING_SIZE];
		if (oph_get_arg(args, OPH_SESSION_CREATION_TIME, str_time))
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Unable to extract creation time\n");
			return OPH_SERVER_ERROR;
		}
		time_t nowtime = (time_t)strtol(str_time,NULL,10);
		struct tm *nowtm = localtime(&nowtime);
		strftime(str_time, OPH_MAX_STRING_SIZE, "%Y", nowtm);
		snprintf(dirname,OPH_MAX_STRING_SIZE,OPH_SESSION_REAL_DIR,oph_auth_location,str_time);
		if (mkdir(dirname, 0755)) pmesg(LOG_DEBUG, __FILE__,__LINE__,"Unable to create the folder '%s', but don't care\n",dirname);
		strftime(str_time, OPH_MAX_STRING_SIZE, "/%m", nowtm);
		strncat(dirname,str_time,OPH_MAX_STRING_SIZE-strlen(dirname));
		if (mkdir(dirname, 0755)) pmesg(LOG_DEBUG, __FILE__,__LINE__,"Unable to create the folder '%s', but don't care\n",dirname);
		strftime(str_time, OPH_MAX_STRING_SIZE, "/%d", nowtm);
		strncat(dirname,str_time,OPH_MAX_STRING_SIZE-strlen(dirname));
		if (mkdir(dirname, 0755)) pmesg(LOG_DEBUG, __FILE__,__LINE__,"Unable to create the folder '%s', but don't care\n",dirname);
		snprintf(filename,OPH_MAX_STRING_SIZE,OPH_SESSION_REAL_FILE,dirname,code);
	}
	else if (type == DT_LNK)
	{
		// Find file
		char linkname[OPH_MAX_STRING_SIZE];
		snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,userid,code);
		int nchars = readlink(linkname,filename,OPH_MAX_STRING_SIZE);
		if (nchars<0)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"File '%s' does not exist\n",filename);
			return OPH_SERVER_IO_ERROR;
		}
		else if (nchars>=OPH_MAX_STRING_SIZE)
		{
			pmesg(LOG_ERROR, __FILE__,__LINE__,"Real file name '%s' is too long\n",filename);
			return OPH_SERVER_IO_ERROR;
		}
		else
		{
			filename[nchars]=0;
			pmesg(LOG_DEBUG, __FILE__,__LINE__,"Effective file name is '%s'\n",filename);
		}
	}
	else
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Wrong type '%s'\n",type);
		return OPH_SERVER_IO_ERROR;
	}

	// Write file .session
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Saving session data in '%s'\n",filename);
	if (!(file = fopen(filename,"w")))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Unable to save '%s'\n",filename);
		return OPH_SERVER_IO_ERROR;
	}
	oph_argument* tmp;
	for (tmp=args; tmp; tmp=tmp->next) fprintf(file,"%s=%s\n",tmp->key,tmp->value);
	fclose(file);

	// Create link
	if (type == DT_REG)
	{
		char linkname[OPH_MAX_STRING_SIZE];
		snprintf(linkname,OPH_MAX_STRING_SIZE,OPH_SESSION_FILE,oph_auth_location,userid,code);
		if (symlink(filename,linkname)) pmesg(LOG_DEBUG, __FILE__,__LINE__,"Unable to create the symbolic link, but don't care\n");
	}

	return OPH_SERVER_OK;
}

int oph_save_user_session(const char* userid, const char* sessionid, oph_argument* args)
{
	if (!userid || !sessionid || !args) return OPH_SERVER_NULL_POINTER;

	char filename[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE];
	FILE* file;

	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Extract session code from '%s'\n",sessionid);
	if (oph_get_session_code(sessionid,code))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Unable to extract session code from '%s'\n",sessionid);
		return OPH_SERVER_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Session code is '%s'\n",code);

	// Write file .user
	snprintf(filename,OPH_MAX_STRING_SIZE,OPH_USER_SESSION_FILE,oph_auth_location,userid,code);
	pmesg(LOG_DEBUG, __FILE__,__LINE__,"Saving user-specific session data in '%s'\n",filename);
	if (!(file = fopen(filename,"w")))
	{
		pmesg(LOG_ERROR, __FILE__,__LINE__,"Unable to save '%s'\n",filename);
		return OPH_SERVER_IO_ERROR;
	}
	oph_argument* tmp;
	for (tmp=args; tmp; tmp=tmp->next) fprintf(file,"%s=%s\n",tmp->key,tmp->value);
	fclose(file);

	return OPH_SERVER_OK;
}

oph_auth_user_role oph_string_to_role(const char* role)
{
	short owner=0, admin=0, writer=0;
	oph_auth_user_role result = OPH_ROLE_NONE;
	if (role)
	{
		if (role[4]==OPH_ROLE_OWNER_STR[0]) { result+=OPH_ROLE_OWNER; owner=1; }
		if (owner || (role[3]==OPH_ROLE_ADMIN_STR[0])) { result+=OPH_ROLE_ADMIN; admin=1; }
		if (admin || (role[2]==OPH_ROLE_EXECUTE_STR[0])) result+=OPH_ROLE_EXECUTE;
		if (admin || (role[1]==OPH_ROLE_WRITE_STR[0])) { result+=OPH_ROLE_WRITE; writer=1; }
		if (writer || (role[0]==OPH_ROLE_READ_STR[0])) result+=OPH_ROLE_READ;
	}
	return result;
}

char* oph_role_to_string(oph_auth_user_role role)
{
	short owner=0, admin=0, writer=0;
	char result[6];
	sprintf(result,OPH_ROLE_NULL_STR);
	if (role & OPH_ROLE_OWNER) { result[4]=OPH_ROLE_OWNER_STR[0]; owner=1; }
	if (owner || (role & OPH_ROLE_ADMIN)) { result[3]=OPH_ROLE_ADMIN_STR[0]; admin=1; }
	if (admin || (role & OPH_ROLE_EXECUTE)) result[2]=OPH_ROLE_EXECUTE_STR[0];
	if (admin || (role & OPH_ROLE_WRITE)) { result[1]=OPH_ROLE_WRITE_STR[0]; writer=1; }
	if (writer || (role & OPH_ROLE_READ)) result[0]=OPH_ROLE_READ_STR[0];
	return strdup(result);
}

oph_auth_user_role oph_code_role(const char* role)
{
	short owner=0, admin=0, writer=0, found;
	unsigned int i;
	oph_auth_user_role result = OPH_ROLE_NONE;
	if (!role) return result;

	char string[1+strlen(role)], *pch, *save_pointer=NULL;
	strcpy(string,role);
	pch = strtok_r(string,OPH_SEPARATOR_ROLES,&save_pointer);
	while (pch)
	{
		found=0;
		if (!strcmp(pch,OPH_ROLE_OWNER_STR)) { result+=OPH_ROLE_OWNER; owner=1; found=1; }
		if (owner || !strcmp(pch,OPH_ROLE_ADMIN_STR)) { result+=OPH_ROLE_ADMIN; admin=1; if (!owner) found=1; }
		if (admin || !strcmp(pch,OPH_ROLE_EXECUTE_STR)) { result+=OPH_ROLE_EXECUTE; if (!admin) found=1; }
		if (admin || !strcmp(pch,OPH_ROLE_WRITE_STR)) { result+=OPH_ROLE_WRITE; writer=1; if (!admin) found=1; }
		if (writer || !strcmp(pch,OPH_ROLE_READ_STR)) { result+=OPH_ROLE_READ; if (!writer) found=1; }
		if (!found) for (i=0;i<strlen(pch);++i)
		{
			owner=admin=writer=found=0;
			if (pch[i] == OPH_ROLE_OWNER_STR[0]) { result+=OPH_ROLE_OWNER; owner=1; found=1; }
			if (owner || (pch[i] == OPH_ROLE_ADMIN_STR[0])) { result+=OPH_ROLE_ADMIN; admin=1; if (!owner) found=1; }
			if (admin || (pch[i] == OPH_ROLE_EXECUTE_STR[0])) { result+=OPH_ROLE_EXECUTE; if (!admin) found=1; }
			if (admin || (pch[i] == OPH_ROLE_WRITE_STR[0])) { result+=OPH_ROLE_WRITE; writer=1; if (!admin) found=1; }
			if (writer || (pch[i] == OPH_ROLE_READ_STR[0])) { result+=OPH_ROLE_READ; if (!writer) found=1; }
			if (!found) return OPH_ROLE_NONE;
		}
		pch = strtok_r(NULL,OPH_SEPARATOR_ROLES,&save_pointer);
	}

	return result;
}

char* oph_code_role_string(const char* role)
{
	short owner=0, admin=0, writer=0, found;
	unsigned int i;
	char result[6];
	sprintf(result,OPH_ROLE_NULL_STR);
	if (!role) return strdup(result);

	char string[1+strlen(role)], *pch, *save_pointer=NULL;
	strcpy(string,role);
	pch = strtok_r(string,OPH_SEPARATOR_ROLES,&save_pointer);
	while (pch)
	{
		found=0;
		if (!strcmp(pch,OPH_ROLE_OWNER_STR)) { result[4]=OPH_ROLE_OWNER_STR[0]; owner=1; found=1; }
		if (owner || !strcmp(pch,OPH_ROLE_ADMIN_STR)) { result[3]=OPH_ROLE_ADMIN_STR[0]; admin=1; if (!owner) found=1; }
		if (admin || !strcmp(pch,OPH_ROLE_EXECUTE_STR)) { result[2]=OPH_ROLE_EXECUTE_STR[0]; if (!admin) found=1; }
		if (admin || !strcmp(pch,OPH_ROLE_WRITE_STR)) { result[1]=OPH_ROLE_WRITE_STR[0]; writer=1; if (!admin) found=1; }
		if (writer || !strcmp(pch,OPH_ROLE_READ_STR)) { result[0]=OPH_ROLE_READ_STR[0]; if (!writer) found=1; }
		if (!found) for (i=0;i<strlen(pch);++i)
		{
			owner=admin=writer=found=0;
			if (pch[i] == OPH_ROLE_OWNER_STR[0]) { result[4]=OPH_ROLE_OWNER_STR[0]; owner=1; found=1; }
			if (owner || (pch[i] == OPH_ROLE_ADMIN_STR[0])) { result[3]=OPH_ROLE_ADMIN_STR[0]; admin=1; if (!owner) found=1; }
			if (admin || (pch[i] == OPH_ROLE_EXECUTE_STR[0])) { result[2]=OPH_ROLE_EXECUTE_STR[0]; if (!admin) found=1; }
			if (admin || (pch[i] == OPH_ROLE_WRITE_STR[0])) { result[1]=OPH_ROLE_WRITE_STR[0]; writer=1; if (!admin) found=1; }
			if (writer || (pch[i] == OPH_ROLE_READ_STR[0])) { result[0]=OPH_ROLE_READ_STR[0]; if (!writer) found=1; }
			if (!found) return NULL;
		}
		pch = strtok_r(NULL,OPH_SEPARATOR_ROLES,&save_pointer);
	}

	return strdup(result);
}

char* oph_expand_role_string(const char* role)
{
	short only_exe=0;
	char string[OPH_SHORT_STRING_SIZE];
	*string=0;
	if (role)
	{
		if (role[4]==OPH_ROLE_OWNER_STR[0]) snprintf(string,OPH_SHORT_STRING_SIZE,"%s",OPH_ROLE_OWNER_STR);
		else if (role[3]==OPH_ROLE_ADMIN_STR[0]) snprintf(string,OPH_SHORT_STRING_SIZE,"%s",OPH_ROLE_ADMIN_STR);
		else
		{
			if (role[1]==OPH_ROLE_WRITE_STR[0]) snprintf(string,OPH_SHORT_STRING_SIZE,"%s%s%s",OPH_ROLE_READ_STR,OPH_SEPARATOR_ROLES,OPH_ROLE_WRITE_STR);
			else if (role[0]==OPH_ROLE_READ_STR[0]) snprintf(string,OPH_SHORT_STRING_SIZE,"%s",OPH_ROLE_READ_STR);
			else only_exe=1;
			if (role[2]==OPH_ROLE_EXECUTE_STR[0])
			{
				if (only_exe) snprintf(string,OPH_SHORT_STRING_SIZE,"%s",OPH_ROLE_EXECUTE_STR);
				else
				{
					int s;
					if ((s=OPH_SHORT_STRING_SIZE-strlen(string))>1) strncat(string,OPH_SEPARATOR_ROLES,s);
					if ((s=OPH_SHORT_STRING_SIZE-strlen(string))>1) strncat(string,OPH_ROLE_EXECUTE_STR,s);
				}
			}
		}
	}
	return strdup(string);
}

int oph_auth_check_role(oph_auth_user_role role, oph_auth_user_role permission)
{
	if ((role & OPH_ROLE_READ) && !(permission & OPH_ROLE_READ)) return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_WRITE) && !(permission & OPH_ROLE_WRITE)) return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_EXECUTE) && !(permission & OPH_ROLE_EXECUTE)) return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_ADMIN) && !(permission & OPH_ROLE_ADMIN)) return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_OWNER) && !(permission & OPH_ROLE_OWNER)) return OPH_SERVER_AUTH_ERROR;
	return OPH_SERVER_OK;
}

