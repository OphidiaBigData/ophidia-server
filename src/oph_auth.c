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

#define _GNU_SOURCE

#include "oph_auth.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>
#ifdef OPH_DB_SUPPORT
#include <mysql.h>
#endif

#ifdef INTERFACE_TYPE_IS_SSL
#include <openssl/sha.h>
#endif

#ifdef OPH_OPENID_SUPPORT

#include "hashtbl.h"
#include "oph_service_info.h"
#include "oph_ophidiadb.h"
#include <curl/curl.h>
#include <jansson.h>
#include <cjose/cjose.h>

extern oph_service_info *service_info;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_t token_tid_openid;
extern pthread_mutex_t global_flag;
extern pthread_mutex_t curl_flag;
#endif

#define AUTH_CONNECTTIMEOUT 30

typedef struct _oph_auth_clip {
	char *memory;
	size_t size;
} oph_auth_clip;

typedef struct _oph_refresh_token {
	char *access_token;
	char *refresh_token;
	char *userid;
	char *userinfo;
} oph_refresh_token;

HASHTBL *usersinfo = NULL;

typedef struct _auth_jwt_hdr {
	json_t *cnt;
	char *str;
	char *alg;
	char *kid;
	char *enc;
} auth_jwt_hdr;

typedef struct _auth_jwt_payload {
	json_t *cnt;
	char *str;
	char *iss;
	char *sub;
	char *jti;
	char *nonce;
	char *aud;
	char *kid;
	double auth_time;
	double exp;
	double iat;
} auth_jwt_payload;

extern char *oph_server_host;
extern char *oph_openid_endpoint;
extern char *oph_openid_client_id;
extern char *oph_openid_client_secret;
extern unsigned int oph_openid_token_timeout;
extern unsigned int oph_openid_token_check_time;
extern char *oph_openid_user_name;
extern char oph_openid_allow_local_user;

char *oph_openid_endpoint_public_key = NULL;

#endif



#ifdef OPH_AAA_SUPPORT

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_t token_tid_aaa;
#endif

#ifndef OPH_OPENID_SUPPORT

#include "hashtbl.h"
#include "oph_service_info.h"
#include <curl/curl.h>
#include <jansson.h>

extern oph_service_info *service_info;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
extern pthread_mutex_t curl_flag;
#endif

#define AUTH_CONNECTTIMEOUT 30

typedef struct _oph_auth_clip {
	char *memory;
	size_t size;
} oph_auth_clip;

HASHTBL *usersinfo = NULL;

#endif

extern char *oph_aaa_endpoint;
extern char *oph_aaa_category;
extern char *oph_aaa_name;
extern unsigned int oph_aaa_token_check_time;

#endif



#define OPH_AUTH_MAX_COUNT 5

extern char *oph_auth_location;
extern char *oph_web_server;
extern int oph_server_timeout;
extern unsigned int oph_default_max_sessions;
extern unsigned int oph_default_max_cores;
extern unsigned int oph_default_max_hosts;
extern unsigned int oph_default_session_timeout;

oph_auth_user_bl *bl_head = NULL;
oph_auth_user_bl *tokens_openid = NULL;
oph_auth_user_bl *tokens_aaa = NULL;
oph_auth_user_bl *auth_users = NULL;
oph_auth_user_bl *actual_users = NULL;

int oph_get_session_code(const char *sessionid, char *code)
{
	char tmp[OPH_MAX_STRING_SIZE];
	strncpy(tmp, sessionid, OPH_MAX_STRING_SIZE);

	char *tmp2 = tmp, *savepointer = NULL;
	unsigned short i, max = 3;
	if (oph_web_server) {
		unsigned int length = strlen(oph_web_server);
		if ((length >= OPH_MAX_STRING_SIZE) || strncmp(sessionid, oph_web_server, length))
			return OPH_SERVER_ERROR;
		tmp2 += length;
		max = 1;
	}

	tmp2 = strtok_r(tmp2, OPH_SEPARATOR_FOLDER, &savepointer);
	if (!tmp2)
		return OPH_SERVER_ERROR;
	for (i = 0; i < max; ++i) {
		tmp2 = strtok_r(NULL, OPH_SEPARATOR_FOLDER, &savepointer);
		if (!tmp2)
			return OPH_SERVER_ERROR;
	}
	strcpy(code, tmp2);

	return OPH_SERVER_OK;
}

int oph_load_file(const char *filename, oph_argument ** args)
{
	if (!filename || !args)
		return OPH_SERVER_NULL_POINTER;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Open file '%s'\n", filename);

	FILE *file;
	oph_argument *tail = *args = NULL;
	int result = OPH_SERVER_OK;

	if (result == OPH_SERVER_OK) {
		if ((file = fopen(filename, "r"))) {
			char buffer[OPH_MAX_STRING_SIZE], *pch;
			oph_argument *tmp;
			while (fgets(buffer, OPH_MAX_STRING_SIZE, file)) {
				if (strlen(buffer) && (buffer[strlen(buffer) - 1] == '\n'))
					buffer[strlen(buffer) - 1] = 0;	// Skip the last '\n'
				if (strlen(buffer)) {
					pch = strchr(buffer, OPH_SEPARATOR_KV[0]);
					if (!pch) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "File is corrupted\n");
						result = OPH_SERVER_IO_ERROR;
						break;
					}
					tmp = (oph_argument *) malloc(sizeof(oph_argument));
					if (strlen(pch) <= 1)
						tmp->value = strdup("");
					else
						tmp->value = strndup(pch + 1, OPH_MAX_STRING_SIZE);
					pch[0] = 0;
					tmp->key = strndup(buffer, OPH_MAX_STRING_SIZE);
					tmp->next = NULL;

					if (tail)
						tail->next = tmp;
					else
						*args = tmp;
					tail = tmp;
				}
			}
			fclose(file);
		} else {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File not found\n");
			result = OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
	}

	return result;
}

int oph_load_file2(const char *filename, oph_argument ** args)
{
	if (!filename || !args)
		return OPH_SERVER_NULL_POINTER;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Open file '%s'\n", filename);

	FILE *file;
	oph_argument *tail = *args = NULL;
	int result = OPH_SERVER_OK;

	if (result == OPH_SERVER_OK) {
		if ((file = fopen(filename, "r"))) {
			char buffer[OPH_MAX_STRING_SIZE], *pch;
			oph_argument *tmp;
			while (fgets(buffer, OPH_MAX_STRING_SIZE, file)) {
				if (strlen(buffer) && (buffer[strlen(buffer) - 1] == '\n'))
					buffer[strlen(buffer) - 1] = 0;	// Skip the last '\n'
				if (strlen(buffer)) {
					pch = strrchr(buffer, OPH_SEPARATOR_BASIC[0]);
					if (!pch) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "File is corrupted\n");
						result = OPH_SERVER_IO_ERROR;
						break;
					}
					tmp = (oph_argument *) malloc(sizeof(oph_argument));
					if (strlen(pch) <= 1)
						tmp->value = strdup("");
					else
						tmp->value = strndup(pch + 1, OPH_MAX_STRING_SIZE);
					pch[0] = 0;
					tmp->key = strndup(buffer, OPH_MAX_STRING_SIZE);
					tmp->next = NULL;

					if (tail)
						tail->next = tmp;
					else
						*args = tmp;
					tail = tmp;
				}
			}
			fclose(file);
		} else {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File not found\n");
			result = OPH_SERVER_WRONG_PARAMETER_ERROR;
		}
	}

	return result;
}

int _oph_add_to_bl(oph_auth_user_bl ** head, const char *userid, const char *host, char verified)
{
	if (!head || !userid || !host)
		return OPH_SERVER_NULL_POINTER;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = (oph_auth_user_bl *) malloc(sizeof(oph_auth_user_bl));
	bl_item->userid = strdup(userid);
	bl_item->host = strdup(host);
	bl_item->verified = verified;
	bl_item->value = NULL;
	bl_item->count = 1;
	bl_item->timestamp = bl_item->check_time = tv.tv_sec;
	bl_item->next = *head;
	*head = bl_item;

	return OPH_SERVER_OK;
}

int oph_add_to_bl(oph_auth_user_bl ** head, const char *userid, const char *host)
{
	return (_oph_add_to_bl(head, userid, host, 0));
}

void oph_delete_item_in_bl(oph_auth_user_bl * bl_item)
{
	if (bl_item->userid)
		free(bl_item->userid);
	if (bl_item->host)
		free(bl_item->host);
	if (bl_item->value)
		free(bl_item->value);
	free(bl_item);
}

short oph_is_in_bl(oph_auth_user_bl ** head, const char *userid, const char *host, char *deadline)
{
	if (!head || !userid || !host)
		return OPH_SERVER_NULL_POINTER;

	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = *head, *bl_prev = NULL;
	while (bl_item) {
		deadtime = (time_t) (bl_item->timestamp + oph_server_timeout);
		if (tv.tv_sec > deadtime) {
			if (bl_prev)
				bl_prev->next = bl_item->next;
			else
				*head = bl_item->next;
			oph_delete_item_in_bl(bl_item);
			bl_item = bl_prev ? bl_prev->next : *head;
		} else if (!strcmp(bl_item->userid, userid) && !strcmp(bl_item->host, host)) {
			if (deadline) {
				struct tm nowtm;
				if (!localtime_r(&deadtime, &nowtm))
					return -1;
				strftime(deadline, OPH_MAX_STRING_SIZE, "%H:%M:%S", &nowtm);
			}
			bl_item->count++;
			return bl_item->count;
		} else {
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return 0;
}

char *oph_get_host_by_user_in_bl(oph_auth_user_bl ** head, const char *userid, char *deadline)
{
	if (!head || !userid)
		return NULL;

	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = *head, *bl_prev = NULL;
	while (bl_item) {
		deadtime = (time_t) (bl_item->timestamp + oph_server_timeout);
		if (tv.tv_sec > deadtime) {
			if (bl_prev)
				bl_prev->next = bl_item->next;
			else
				*head = bl_item->next;
			oph_delete_item_in_bl(bl_item);
			bl_item = bl_prev ? bl_prev->next : *head;
		} else if (!strcmp(bl_item->userid, userid)) {
			if (deadline) {
				struct tm nowtm;
				if (!localtime_r(&deadtime, &nowtm))
					return NULL;
				strftime(deadline, OPH_MAX_STRING_SIZE, "%H:%M:%S", &nowtm);
			}
			return bl_item->host;
		} else {
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return NULL;
}

int oph_get_user_by_token(oph_auth_user_bl ** head, const char *token, char **userid, char **new_token, char *verified)
{
	if (!head || !token)
		return OPH_SERVER_NULL_POINTER;

	if (userid)
		*userid = NULL;
	if (new_token)
		*new_token = NULL;

	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = *head, *bl_prev = NULL;
	while (bl_item) {
		deadtime = (time_t) (bl_item->timestamp + oph_server_timeout);
		if (tv.tv_sec > deadtime) {
#ifdef OPH_OPENID_SUPPORT
			hashtbl_remove(usersinfo, bl_item->host);
#endif
			if (bl_prev)
				bl_prev->next = bl_item->next;
			else
				*head = bl_item->next;
			oph_delete_item_in_bl(bl_item);
			bl_item = bl_prev ? bl_prev->next : *head;
		} else if (!strcmp(bl_item->host, token)) {
			if (userid)
				*userid = strdup(bl_item->userid);
			bl_item->count = 0;	// Hit
			if (new_token && bl_item->value && strcmp(bl_item->value, token))
				*new_token = strdup(bl_item->value);
			if (verified)
				*verified = bl_item->verified;
			return OPH_SERVER_OK;
		} else {
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return OPH_SERVER_ERROR;
}

int oph_drop_from_bl(oph_auth_user_bl ** head, const char *userid, const char *host)
{
	if (!head || !userid || !host)
		return OPH_SERVER_NULL_POINTER;

	int found = 0;
	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = *head, *bl_prev = NULL;
	while (bl_item) {
		deadtime = (time_t) (bl_item->timestamp + oph_server_timeout);
		if ((found = !strcmp(bl_item->userid, userid) && !strcmp(bl_item->host, host)) || (tv.tv_sec > deadtime)) {
			if (bl_prev)
				bl_prev->next = bl_item->next;
			else
				*head = bl_item->next;
			oph_delete_item_in_bl(bl_item);
			if (found)
				return OPH_SERVER_OK;
			else
				bl_item = bl_prev ? bl_prev->next : *head;
		} else {
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return OPH_SERVER_OK;
}

int oph_free_bl(oph_auth_user_bl ** head)
{
	oph_auth_user_bl *bl_item = *head;
	while (bl_item) {
		*head = bl_item->next;
		oph_delete_item_in_bl(bl_item);
		bl_item = *head;
	}
	return OPH_SERVER_OK;
}

int oph_auth_free()
{
	oph_free_bl(&bl_head);
	oph_free_bl(&tokens_openid);
	oph_free_bl(&tokens_aaa);
	oph_free_bl(&auth_users);
	oph_free_bl(&actual_users);
#ifdef OPH_OPENID_SUPPORT
	if (oph_openid_endpoint_public_key)
		free(oph_openid_endpoint_public_key);
#endif
#if defined(OPH_OPENID_SUPPORT) || defined(OPH_AAA_SUPPORT)
	if (usersinfo)
		hashtbl_destroy(usersinfo);
#endif
	return OPH_SERVER_OK;
}

int oph_auth_update_values_of_user(oph_auth_user_bl ** head, const char *userid, const char *access_token)
{
	if (!head || !userid || !access_token)
		return OPH_SERVER_NULL_POINTER;

	time_t deadtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	oph_auth_user_bl *bl_item = *head, *bl_prev = NULL;
	while (bl_item) {
		deadtime = (time_t) (bl_item->timestamp + oph_server_timeout);
		if (tv.tv_sec > deadtime) {
#ifdef OPH_OPENID_SUPPORT
			hashtbl_remove(usersinfo, bl_item->host);
#endif
			if (bl_prev)
				bl_prev->next = bl_item->next;
			else
				*head = bl_item->next;
			oph_delete_item_in_bl(bl_item);
			bl_item = bl_prev ? bl_prev->next : *head;
		} else {
			if (!strcmp(bl_item->userid, userid)) {
				if (bl_item->value)
					free(bl_item->value);
				bl_item->value = strdup(access_token);
			}
			bl_prev = bl_item;
			bl_item = bl_item->next;
		}
	}

	return OPH_SERVER_OK;
}

#ifdef INTERFACE_TYPE_IS_SSL
char *oph_sha(char *to, const char *passwd)
{
	char *result = to;
	if (passwd && to) {
		unsigned char hash_stage[SHA_DIGEST_LENGTH];
		SHA_CTX sha1_context;
		if (!SHA1_Init(&sha1_context))
			return NULL;
		if (!SHA1_Update(&sha1_context, passwd, strlen(passwd)))
			return NULL;
		memset(hash_stage, 0, SHA_DIGEST_LENGTH);
		if (!SHA1_Final(hash_stage, &sha1_context))
			return NULL;
		if (!SHA1_Init(&sha1_context))
			return NULL;
		if (!SHA1_Update(&sha1_context, hash_stage, SHA_DIGEST_LENGTH))
			return NULL;
		memset(hash_stage, 0, SHA_DIGEST_LENGTH);
		if (!SHA1_Final(hash_stage, &sha1_context))
			return NULL;
		*to++ = '*';
		const char hash_byte[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		char *str = hash_stage, *str_end = hash_stage + SHA_DIGEST_LENGTH;
		for (; str != str_end; ++str) {
			*to++ = hash_byte[((unsigned char) *str) >> 4];
			*to++ = hash_byte[((unsigned char) *str) & 0x0F];
		}
		*to = '\0';
	}
	return result;
}
#endif

#if defined(OPH_OPENID_SUPPORT) || defined(OPH_AAA_SUPPORT)

size_t json_pt(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t bytec = size * nmemb;
	oph_auth_clip *mem = (oph_auth_clip *) stream;
	mem->memory = (char *) realloc(mem->memory, mem->size + bytec + 1);
	if (mem->memory == NULL)
		return 0;
	memcpy(mem->memory + mem->size, ptr, bytec);
	mem->size += bytec;
	mem->memory[mem->size] = 0;
	return bytec;
}

#endif

#ifdef OPH_OPENID_SUPPORT

char *mystrdup(const char *s, size_t len)
{
	char *new = (char *) calloc(1 + len, sizeof(char));
	if (new == NULL)
		return NULL;

	return (char *) memcpy(new, s, len);
}

void header_free(auth_jwt_hdr * header)
{
	if (header->cnt != NULL)
		json_decref(header->cnt);

	if (header->str != NULL)
		free(header->str);

	if (header->alg != NULL)
		free(header->alg);

	if (header->kid != NULL)
		free(header->kid);

	if (header->enc != NULL)
		free(header->enc);

	header->cnt = NULL;
	header->str = NULL;
	header->alg = NULL;
	header->kid = NULL;
	header->enc = NULL;
}

void payload_free(auth_jwt_payload * payload)
{
	if (payload->cnt != NULL)
		json_decref(payload->cnt);

	if (payload->str != NULL)
		free(payload->str);

	if (payload->iss != NULL)
		free(payload->iss);

	if (payload->sub != NULL)
		free(payload->sub);

	if (payload->jti != NULL)
		free(payload->jti);

	if (payload->nonce != NULL)
		free(payload->nonce);

	if (payload->aud != NULL)
		free(payload->aud);

	if (payload->kid != NULL)
		free(payload->kid);

	payload->exp = 0;
	payload->iat = 0;
	payload->auth_time = 0;
	payload->cnt = NULL;
	payload->str = NULL;
	payload->iss = NULL;
	payload->sub = NULL;
	payload->jti = NULL;
	payload->nonce = NULL;
	payload->aud = NULL;
	payload->kid = NULL;
}

int get_json_string(const json_t * json, const char *key, char **str)
{
	if (!str)
		return OPH_SERVER_NULL_POINTER;
	*str = NULL;

	json_t *obj = json_object_get(json, key);
	if (!obj)
		return OPH_SERVER_OK;

	if (!json_is_string(obj))
		return OPH_SERVER_ERROR;

	const char *tmpstr = json_string_value(obj);
	if (!tmpstr)
		return OPH_SERVER_ERROR;

	*str = strdup(tmpstr);
	if (!*str)
		return OPH_SERVER_ERROR;

	return OPH_SERVER_OK;
}

int get_json_number(const json_t * json, const char *key, double *num)
{
	if (!num)
		return OPH_SERVER_NULL_POINTER;
	*num = 0;

	json_t *obj = json_object_get(json, key);
	if (!obj)
		return OPH_SERVER_OK;

	if (!json_is_number(obj))
		return OPH_SERVER_ERROR;

	*num = json_number_value(obj);

	return OPH_SERVER_OK;
}

int get_json_boolean(const json_t * json, const char *key, bool * value)
{
	if (!value)
		return OPH_SERVER_NULL_POINTER;
	*value = 0;

	json_t *obj = json_object_get(json, key);
	if (!obj)
		return OPH_SERVER_OK;

	if (!json_is_boolean(obj))
		return OPH_SERVER_ERROR;

	*value = json_is_true(obj);

	return OPH_SERVER_OK;
}

int read_values(const json_t * json, const char **char_arg, char ***char_ptr, int n_char_arg, const char **num_arg, double **num_ptr, int n_num_arg, const char **bool_arg, bool ** bool_ptr,
		int n_bool_arg)
{
	int i, j;

	for (i = 0; i < n_num_arg; i++)
		if (get_json_number(json, num_arg[i], num_ptr[i]))
			return OPH_SERVER_ERROR;

	for (i = 0; i < n_bool_arg; i++)
		if (get_json_boolean(json, bool_arg[i], bool_ptr[i]))
			return OPH_SERVER_ERROR;

	for (i = 0; i < n_char_arg; i++)
		if (get_json_string(json, char_arg[i], char_ptr[i])) {
			for (j = 0; j < i; j++)
				free(*(char_ptr[j]));
			return OPH_SERVER_ERROR;
		}

	return OPH_SERVER_OK;
}

int extract_header(cjose_jws_t * jwt, auth_jwt_hdr * header)
{
	cjose_header_t *hdr = cjose_jws_get_protected(jwt);

	char *hdr_str = json_dumps((json_t *) hdr, 0);
	if (!hdr_str)
		return OPH_SERVER_ERROR;
	header->str = hdr_str;

	json_t *json = json_deep_copy((json_t *) hdr);
	if (!json) {
		free(header->str);
		return OPH_SERVER_ERROR;
	}
	header->cnt = json;

	const char arg_alg[4] = "alg";
	const char arg_kid[4] = "kid";
	const char arg_enc[4] = "enc";

	const char *char_arg[3] = { arg_alg, arg_kid, arg_enc };
	char **char_ptr[3] = { &(header->alg), &(header->kid), &(header->enc) };

	if (read_values(json, char_arg, char_ptr, 3, NULL, NULL, 0, NULL, NULL, 0)) {
		free(header->str);
		json_decref(json);
		return OPH_SERVER_ERROR;
	}

	return OPH_SERVER_OK;
}

int extract_payload(cjose_jws_t * jwt, auth_jwt_payload * payload)
{
	char *payload_ptr = NULL;
	size_t payload_length;
	if (!cjose_jws_get_plaintext(jwt, (uint8_t **) & payload_ptr, &payload_length, NULL))
		return OPH_SERVER_ERROR;

	payload->str = mystrdup(payload_ptr, payload_length);
	if (!payload->str)
		return OPH_SERVER_ERROR;

	json_t *json = json_loads(payload->str, 0, NULL);
	if (!json) {
		if (payload->str)
			free(payload->str);
		return OPH_SERVER_ERROR;
	} else if (!json_is_object(json)) {
		if (payload->str)
			free(payload->str);
		json_decref(json);
		return OPH_SERVER_ERROR;
	}
	payload->cnt = json;

	const char arg_iss[4] = "iss";
	const char arg_sub[4] = "sub";
	const char arg_exp[4] = "exp";
	const char arg_iat[4] = "iat";
	const char arg_jti[4] = "jti";
	const char arg_nonce[6] = "nonce";
	const char arg_aud[4] = "aud";
	const char arg_kid[4] = "kid";
	const char arg_at[10] = "auth_time";

	const char *char_arg[6] = { arg_iss, arg_sub, arg_jti, arg_nonce, arg_aud, arg_kid };
	char **char_ptr[6] = { &(payload->iss), &(payload->sub), &(payload->jti), &(payload->nonce), &(payload->aud), &(payload->kid) };
	const char *num_arg[3] = { arg_exp, arg_iat, arg_at };
	double *num_ptr[3] = { &(payload->exp), &(payload->iat), &(payload->auth_time) };

	if (read_values(json, char_arg, char_ptr, 6, num_arg, num_ptr, 3, NULL, NULL, 0)) {
		if (payload->str)
			free(payload->str);
		json_decref(json);
		return OPH_SERVER_ERROR;
	}

	return OPH_SERVER_OK;
}

int auth_jwt_import(const char *token, auth_jwt_hdr * header, auth_jwt_payload * payload)
{
	if (!token || (!header && !payload))
		return OPH_SERVER_NULL_POINTER;

	cjose_jws_t *jwt = cjose_jws_import(token, strlen(token), NULL);
	if (!jwt) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token cannot be processed\n");
		return OPH_SERVER_ERROR;
	}

	if (header && extract_header(jwt, header)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: header cannot be extracted\n");
		cjose_jws_release(jwt);
		return OPH_SERVER_ERROR;
	}

	if (payload && extract_payload(jwt, payload)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: payload cannot be extracted\n");
		cjose_jws_release(jwt);
		if (header)
			header_free(header);
		return OPH_SERVER_ERROR;
	}

	if (!oph_openid_endpoint_public_key) {

		oph_auth_clip chunk;
		chunk.memory = (char *) malloc(1);
		*chunk.memory = chunk.size = 0;
		char url[OPH_MAX_STRING_SIZE];
		snprintf(url, OPH_MAX_STRING_SIZE, "%s/jwk", oph_openid_endpoint);

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET public key: waiting...\n");

		CURL *curl = curl_easy_init();
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, AUTH_CONNECTTIMEOUT);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, json_pt);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);

		pthread_mutex_unlock(&global_flag);
		pthread_mutex_lock(&curl_flag);
		CURLcode res = curl_easy_perform(curl);
		pthread_mutex_unlock(&curl_flag);
		pthread_mutex_lock(&global_flag);

		curl_easy_cleanup(curl);

		if (res || !chunk.memory) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: unable to get public key: %s\n", curl_easy_strerror(res));
			if (chunk.memory)
				free(chunk.memory);
			return OPH_SERVER_AUTH_ERROR;
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET public key: completed\n");

		char error = 1;
		while (error) {
			char *start = chunk.memory + 1;
			while (start && *start && (*start != '{'))
				start++;
			if (!start || !*start)
				break;
			char *stop = start + 1;
			while (stop && *stop && (*stop != '}'))
				stop++;
			if (!stop || !*stop)
				break;
			stop[1] = 0;
			oph_openid_endpoint_public_key = strdup(start);
			if (!oph_openid_endpoint_public_key)
				break;
			error = 0;
		}

		free(chunk.memory);

		if (error) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: unable to get public key: %s\n", curl_easy_strerror(res));
			return OPH_SERVER_AUTH_ERROR;
		} else
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: public key: %s\n", oph_openid_endpoint_public_key);
	}

	cjose_jwk_t *jwk = cjose_jwk_import(oph_openid_endpoint_public_key, strlen(oph_openid_endpoint_public_key), NULL);
	if (!jwk) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: public key cannot be processed\n");
		cjose_jws_release(jwt);
		if (header)
			header_free(header);
		if (payload)
			payload_free(payload);
		return OPH_SERVER_ERROR;
	}

	if (!cjose_jws_verify(jwt, jwk, NULL)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: signature is not correct\n");
		//cjose_jws_release(jwt);
		cjose_jwk_release(jwk);
		if (header)
			header_free(header);
		if (payload)
			payload_free(payload);
		return OPH_SERVER_ERROR;
	}

	cjose_jws_release(jwt);
	cjose_jwk_release(jwk);

	return OPH_SERVER_OK;
}

#endif

#if defined(OPH_OPENID_SUPPORT) || defined(OPH_AAA_SUPPORT)

int oph_auth_cache_userinfo(const char *access_token, const char *userinfo)
{
	if (!access_token || !userinfo)
		return OPH_SERVER_NULL_POINTER;

	if (!usersinfo) {
		usersinfo = hashtbl_create(strlen(access_token), NULL);
		if (!usersinfo)
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Memory error\n");
	}
	if (usersinfo)
		hashtbl_insert(usersinfo, access_token, (char *) userinfo);

	return OPH_SERVER_OK;
}

#endif

#ifdef OPH_OPENID_SUPPORT

void *_oph_refresh(oph_refresh_token * refresh)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif

	if (!refresh || !refresh->access_token || !refresh->refresh_token || !refresh->userid) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: memory error\n");
		return (void *) NULL;;
	}

	oph_auth_clip chunk;
	char url[OPH_MAX_STRING_SIZE], credentials[OPH_MAX_STRING_SIZE], fields[OPH_MAX_STRING_SIZE];
	snprintf(url, OPH_MAX_STRING_SIZE, "%s/token", oph_openid_endpoint);
	snprintf(credentials, OPH_MAX_STRING_SIZE, "%s:%s", oph_openid_client_id, oph_openid_client_secret);

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "OPENID: start token refreshing procedure\n");

	while (1) {

		sleep(oph_openid_token_timeout);

		pthread_mutex_lock(&global_flag);

		chunk.memory = (char *) malloc(1);
		*chunk.memory = chunk.size = 0;
		snprintf(fields, OPH_MAX_STRING_SIZE, "grant_type=refresh_token&refresh_token=%s", refresh->refresh_token);

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET new token: waiting...\n");

		CURL *curl = curl_easy_init();
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_USERPWD, credentials);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, AUTH_CONNECTTIMEOUT);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, json_pt);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

		pthread_mutex_unlock(&global_flag);
		pthread_mutex_lock(&curl_flag);
		CURLcode res = curl_easy_perform(curl);
		pthread_mutex_unlock(&curl_flag);
		pthread_mutex_lock(&global_flag);

		curl_easy_cleanup(curl);

		if (res || !chunk.memory) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: unable to get new token: %s\n", curl_easy_strerror(res));
			pthread_mutex_unlock(&global_flag);
			if (chunk.memory)
				free(chunk.memory);
			break;
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET new token: completed\n");

		json_t *response = json_loads(chunk.memory, 0, NULL);
		if (!response) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: unable to parse JSON string\n");
			pthread_mutex_unlock(&global_flag);
			free(chunk.memory);
			break;
		}

		char *error = NULL, *refresh_token = NULL, *access_token = NULL;
		json_unpack(response, "{s?s,s?s,s?s}", "error", &error, "refresh_token", &refresh_token, "access_token", &access_token);

		if (error) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: GET returns an error code\n");
			pthread_mutex_unlock(&global_flag);
			json_decref(response);
			free(chunk.memory);
			break;
		}
		if (!refresh_token || !access_token) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: GET does not contain the required tokens\n");
			pthread_mutex_unlock(&global_flag);
			json_decref(response);
			free(chunk.memory);
			break;
		}

		if (refresh->access_token) {
			free(refresh->access_token);
			refresh->access_token = NULL;
		}
		if (refresh->refresh_token) {
			free(refresh->refresh_token);
			refresh->refresh_token = NULL;
		}

		if (!(refresh->access_token = strdup(access_token))) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: memory error\n");
			pthread_mutex_unlock(&global_flag);
			json_decref(response);
			free(chunk.memory);
			break;
		}
		if (!(refresh->refresh_token = strdup(refresh_token))) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: memory error\n");
			pthread_mutex_unlock(&global_flag);
			json_decref(response);
			free(chunk.memory);
			break;
		}

		json_decref(response);
		free(chunk.memory);

		oph_auth_update_values_of_user(&tokens_openid, refresh->userid, refresh->access_token);

		if (oph_get_user_by_token(&tokens_openid, refresh->access_token, NULL, NULL, NULL)) {
			_oph_add_to_bl(&tokens_openid, refresh->userid, refresh->access_token, 1);
			oph_auth_cache_userinfo(refresh->access_token, refresh->userinfo);
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token added to active token list\n");
		} else
			pmesg(LOG_WARNING, __FILE__, __LINE__, "OPENID: token found in active token list\n");	// Warning: the token should not be already buffered

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET new token: processed\n");

		pthread_mutex_unlock(&global_flag);
	}

	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "OPENID: exit from token refreshing procedure\n");

	if (refresh->access_token)
		free(refresh->access_token);
	if (refresh->refresh_token)
		free(refresh->refresh_token);
	if (refresh->userid)
		free(refresh->userid);
	if (refresh->userinfo)
		free(refresh->userinfo);
	free(refresh);

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif

	return (void *) NULL;
}

int oph_auth_get_user_from_userinfo_openid(const char *userinfo, char **userid)
{
	if (!userinfo || !userid)
		return OPH_SERVER_NULL_POINTER;
	*userid = NULL;

	json_t *userinfo_json = json_loads(userinfo, 0, NULL);
	if (!userinfo_json) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: unable to parse JSON string\n");
		return OPH_SERVER_ERROR;
	}

	char *error = NULL, *subject_identifier = NULL;
	json_unpack(userinfo_json, "{s?s,s?s}", "error", &error, oph_openid_user_name ? oph_openid_user_name : OPH_SERVER_CONF_OPENID_USER_NAME_SUB, &subject_identifier);

	if (error) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "OPENID: GET returns an error code\n");
		json_decref(userinfo_json);
		return OPH_SERVER_AUTH_ERROR;
	}
	if (!subject_identifier) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "OPENID: userinfo does not contain the claim '%s'\n", oph_openid_user_name ? oph_openid_user_name : OPH_SERVER_CONF_OPENID_USER_NAME_SUB);
		json_decref(userinfo_json);
		return OPH_SERVER_AUTH_ERROR;
	}
	// Check for stored emails
	char *new_subject_identifier = NULL;
	if (oph_openid_allow_local_user && !strcmp(oph_openid_user_name, OPH_SERVER_CONF_OPENID_USER_NAME_EMAIL) && !oph_odb_retrieve_user_from_mail2(subject_identifier, &new_subject_identifier, NULL)
	    && new_subject_identifier) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: found known email '%s' associated with username '%s'\n", subject_identifier, new_subject_identifier);
		*userid = new_subject_identifier;
	} else
		*userid = strdup(subject_identifier);

	if (!*userid) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: memory error\n");
		json_decref(userinfo_json);
		return OPH_SERVER_ERROR;
	}

	json_decref(userinfo_json);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: retrieve username '%s'\n", *userid);

	return OPH_SERVER_OK;
}

int oph_auth_check_token_openid(const char *token)
{
	if (!token)
		return OPH_SERVER_NULL_POINTER;

	auth_jwt_payload *payload = (auth_jwt_payload *) calloc(1, sizeof(auth_jwt_payload));
	if (auth_jwt_import(token, NULL, payload)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token cannot be verified\n");
		payload_free(payload);
		free(payload);
		return OPH_SERVER_AUTH_ERROR;
	}

	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (tv.tv_sec < payload->iat) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token is not valid\n");
		payload_free(payload);
		free(payload);
		return OPH_SERVER_AUTH_ERROR;
	}
	if (tv.tv_sec > payload->exp) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token is expired\n");
		payload_free(payload);
		free(payload);
		return OPH_SERVER_AUTH_ERROR;
	}

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token is valid\n");

	payload_free(payload);
	free(payload);

	return OPH_SERVER_OK;
}

#endif

#ifdef OPH_AAA_SUPPORT

int oph_auth_get_user_from_userinfo_aaa(const char *userinfo, char **userid)
{
	if (!userinfo || !userid)
		return OPH_SERVER_NULL_POINTER;
	*userid = NULL;

	json_t *userinfo_json = json_loads(userinfo, 0, NULL);
	if (!userinfo_json) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "AAA: unable to parse JSON string\n");
		return OPH_SERVER_ERROR;
	}

	char *response = NULL;
	json_unpack(userinfo_json, "{s?s}", "response", &response);

	if (!response) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "AAA: GET does not contain the response\n");
		json_decref(userinfo_json);
		return OPH_SERVER_AUTH_ERROR;
	}
	if (!strcmp(response, "invalid token")) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: invalid token\n");
		json_decref(userinfo_json);
		return OPH_SERVER_AUTH_ERROR;
	}

	if (!(*userid = strdup(response))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "AAA: memory error\n");
		json_decref(userinfo_json);
		return OPH_SERVER_ERROR;
	}

	json_decref(userinfo_json);

	return OPH_SERVER_OK;
}

int oph_auth_check_token_aaa(const char *token)
{
	if (!token)
		return OPH_SERVER_NULL_POINTER;

	// Add specific check to token string in order to check validity before sending any request to identity server

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: token is valid\n");

	return OPH_SERVER_OK;
}

#endif

int oph_auth_check_token(const char *token, short *type)
{
	if (!token)
		return OPH_SERVER_NULL_POINTER;
	if (type)
		*type = 0;

#ifdef OPH_OPENID_SUPPORT
	if (!oph_auth_check_token_openid(token)) {
		if (type)
			*type = 1;
		return OPH_SERVER_OK;
	}
#endif

#ifdef OPH_AAA_SUPPORT
	if (!oph_auth_check_token_aaa(token)) {
		if (type)
			*type = 2;
		return OPH_SERVER_OK;
	}
#endif

	return OPH_SERVER_AUTH_ERROR;
}

int oph_auth_get_user_from_token_openid(const char *token, char **userid, char cache)
{
	if (!token || !userid)
		return OPH_SERVER_NULL_POINTER;
	*userid = NULL;

#ifndef OPH_OPENID_SUPPORT

	UNUSED(cache);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: endpoint is not set\n");
	return OPH_SERVER_AUTH_ERROR;

#else

	if (!oph_openid_endpoint || !strlen(oph_openid_endpoint)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: endpoint is not set\n");
		return OPH_SERVER_AUTH_ERROR;
	}

	oph_auth_clip chunk;
	chunk.memory = (char *) malloc(1);
	*chunk.memory = chunk.size = 0;

	char header[OPH_MAX_STRING_SIZE], url[OPH_MAX_STRING_SIZE];
	snprintf(header, OPH_MAX_STRING_SIZE, "Authorization: Bearer %s", token);
	snprintf(url, OPH_MAX_STRING_SIZE, "%s/userinfo", oph_openid_endpoint);
	struct curl_slist *slist = curl_slist_append(NULL, header);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET userinfo: waiting...\n");

	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, AUTH_CONNECTTIMEOUT);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, json_pt);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

	pthread_mutex_unlock(&global_flag);
	pthread_mutex_lock(&curl_flag);
	CURLcode res = curl_easy_perform(curl);
	pthread_mutex_unlock(&curl_flag);
	pthread_mutex_lock(&global_flag);

	curl_slist_free_all(slist);
	curl_easy_cleanup(curl);

	if (res || !chunk.memory) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: unable to get userinfo: %s\n", curl_easy_strerror(res));
		if (chunk.memory)
			free(chunk.memory);
		return OPH_SERVER_AUTH_ERROR;
	}

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: GET userinfo: completed\n");

	int result;
	if ((result = oph_auth_get_user_from_userinfo_openid(chunk.memory, userid)) || !*userid) {
		free(chunk.memory);
		return result;
	}

	if (cache)
		oph_auth_cache_userinfo(token, chunk.memory);

	free(chunk.memory);

	return OPH_SERVER_OK;

#endif
}

int oph_auth_get_user_from_token_aaa(const char *token, char **userid, char cache)
{
	if (!token || !userid)
		return OPH_SERVER_NULL_POINTER;
	*userid = NULL;

#ifndef OPH_AAA_SUPPORT

	UNUSED(cache);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: endpoint is not set\n");
	return OPH_SERVER_AUTH_ERROR;

#else

	if (!oph_aaa_endpoint || !strlen(oph_aaa_endpoint)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: endpoint is not set\n");
		return OPH_SERVER_AUTH_ERROR;
	}

	oph_auth_clip chunk;
	chunk.memory = (char *) malloc(1);
	*chunk.memory = chunk.size = 0;

	char url[OPH_MAX_STRING_SIZE], fields[OPH_MAX_STRING_SIZE];
	snprintf(url, OPH_MAX_STRING_SIZE, "%s/engine/api/verify_token", oph_aaa_endpoint);
	snprintf(fields, OPH_MAX_STRING_SIZE, "token=%s", token);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: VERIFY token: waiting...\n");

	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, AUTH_CONNECTTIMEOUT);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, json_pt);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

	pthread_mutex_unlock(&global_flag);
	pthread_mutex_lock(&curl_flag);
	CURLcode res = curl_easy_perform(curl);
	pthread_mutex_unlock(&curl_flag);
	pthread_mutex_lock(&global_flag);

	curl_easy_cleanup(curl);

	if (res || !chunk.memory) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: unable to verify token: %s\n", curl_easy_strerror(res));
		if (chunk.memory)
			free(chunk.memory);
		return OPH_SERVER_AUTH_ERROR;
	}

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: VERIFY token: completed\n");

	int result;
	if ((result = oph_auth_get_user_from_userinfo_aaa(chunk.memory, userid)) || !*userid) {
		free(chunk.memory);
		return result;
	}

	if (cache)
		oph_auth_cache_userinfo(token, chunk.memory);

	free(chunk.memory);

	return OPH_SERVER_OK;

#endif
}

int oph_auth_get_user_from_token(const char *token, char **userid, char cache, short type)
{
	if (!token || !userid)
		return OPH_SERVER_NULL_POINTER;
	*userid = NULL;

#ifdef OPH_OPENID_SUPPORT
	if ((type == 1) && !oph_auth_get_user_from_token_openid(token, userid, cache))
		return OPH_SERVER_OK;
#endif

#ifdef OPH_AAA_SUPPORT
	if ((type == 2) && !oph_auth_get_user_from_token_aaa(token, userid, cache))
		return OPH_SERVER_OK;
#endif

	return OPH_SERVER_AUTH_ERROR;
}

#ifdef OPH_OPENID_SUPPORT

void *_oph_check_openid(void *data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif
	UNUSED(data);

	char *userid = NULL, *token, *user;
	time_t deadtime;
	struct timeval tv;
	oph_auth_user_bl *bl_item;

	while (oph_openid_token_check_time) {

		sleep(oph_openid_token_check_time);

		pthread_mutex_lock(&global_flag);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: check for revoked tokens...\n");

		do {

			gettimeofday(&tv, NULL);
			bl_item = tokens_openid;
			while (bl_item) {
				deadtime = (time_t) (bl_item->check_time + oph_openid_token_check_time);
				if (tv.tv_sec >= deadtime) {
					token = strdup(bl_item->host);
					user = strdup(bl_item->userid);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: check validity of token associated with user '%s'\n", user);
					bl_item->check_time = tv.tv_sec;
					if (oph_auth_get_user_from_token_openid(token, &userid, 0) || !userid) {	// Release the lock internally
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token '%s' has been revoked by the user '%s'\n", token, user);
						oph_drop_from_bl(&tokens_openid, user, token);
					}
					if (token)
						free(token);
					if (user)
						free(user);
					break;	// Need to restart since the lock has been released
				}
				bl_item = bl_item->next;
				if (userid) {
					free(userid);
					userid = NULL;
				}
			}

		} while (bl_item);

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: check for revoked tokens... done\n");
		pthread_mutex_unlock(&global_flag);
	}

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif

	return (void *) NULL;
}

#endif

#ifdef OPH_AAA_SUPPORT

void *_oph_check_aaa(void *data)
{
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_detach(pthread_self());
	oph_service_info_thread_incr(service_info);
#endif
	UNUSED(data);

	char *userid = NULL, *token, *user;
	time_t deadtime;
	struct timeval tv;
	oph_auth_user_bl *bl_item;

	while (oph_aaa_token_check_time) {

		sleep(oph_aaa_token_check_time);

		pthread_mutex_lock(&global_flag);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: check for revoked tokens...\n");

		do {

			gettimeofday(&tv, NULL);
			bl_item = tokens_aaa;
			while (bl_item) {
				deadtime = (time_t) (bl_item->check_time + oph_aaa_token_check_time);
				if (tv.tv_sec >= deadtime) {
					token = strdup(bl_item->host);
					user = strdup(bl_item->userid);
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: check validity of token associated with user '%s'\n", user);
					bl_item->check_time = tv.tv_sec;
					if (oph_auth_get_user_from_token_aaa(token, &userid, 0) || !userid) {	// Release the lock internally
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: token '%s' has been revoked by the user '%s'\n", token, user);
						oph_drop_from_bl(&tokens_aaa, user, token);
					}
					if (token)
						free(token);
					if (user)
						free(user);
					break;	// Need to restart since the lock has been released
				}
				bl_item = bl_item->next;
				if (userid) {
					free(userid);
					userid = NULL;
				}
			}

		} while (bl_item);

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: check for revoked tokens... done\n");
		pthread_mutex_unlock(&global_flag);
	}

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	oph_service_info_thread_decr(service_info);
#ifdef OPH_DB_SUPPORT
	mysql_thread_end();
#endif
#endif

	return (void *) NULL;
}

#endif

int oph_auth_check_forged_tokens(const char *token)
{
	if (!token)
		return OPH_SERVER_NULL_POINTER;

#ifdef OPH_OPENID_SUPPORT

	char verified = 0;
	if (!oph_get_user_by_token(&tokens_openid, token, NULL, NULL, &verified) && verified)
		return OPH_SERVER_OK;
	else
		return OPH_SERVER_AUTH_ERROR;

#else

	return OPH_SERVER_AUTH_ERROR;

#endif
}

int oph_auth_read_token(const char *token, const char *userid, oph_argument ** args)
{
	if (!token || !args)
		return OPH_SERVER_NULL_POINTER;
	*args = NULL;

#ifdef OPH_OPENID_SUPPORT

	if (!usersinfo)
		return OPH_SERVER_AUTH_ERROR;

	char *userinfo = hashtbl_get(usersinfo, token);
	if (!userinfo)
		return OPH_SERVER_AUTH_ERROR;

	json_t *info = NULL;
	char *organisation_name = NULL;

	if (oph_auth_check_forged_tokens(token)) {

		info = json_loads(userinfo, 0, NULL);
		if (!info) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: unable to parse JSON string\n");
			return OPH_SERVER_ERROR;
		}

		json_unpack(info, "{s?s}", OPH_SERVER_CONF_OPENID_ORGANISATION_NAME, &organisation_name);

	} else {

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "OPENID: token forged by the server\n");	// Considering email provider
		organisation_name = strstr(userid, "@");
		if (organisation_name)
			organisation_name++;
	}

	if (!organisation_name) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: organisation name not found\n");
		json_decref(info);
		return OPH_SERVER_AUTH_ERROR;
	}

	oph_argument *tmp, *tail = NULL;

	tmp = (oph_argument *) malloc(sizeof(oph_argument));
	tmp->key = strdup(OPH_SERVER_CONF_OPENID_ORGANISATION_NAME);
	if (!(tmp->value = strdup(organisation_name))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "OPENID: memory error\n");
		oph_cleanup_args(&tmp);
		if (info)
			json_decref(info);
		return OPH_SERVER_SYSTEM_ERROR;
	}
	tmp->next = NULL;
	if (tail)
		tail->next = tmp;
	else
		*args = tmp;
	tail = tmp;

	if (info)
		json_decref(info);

	return OPH_SERVER_OK;

#endif

	return OPH_SERVER_AUTH_ERROR;
}

int oph_auth_check(const char *token, const char *userid)
{
	if (!token || !userid)
		return OPH_SERVER_NULL_POINTER;

#ifdef OPH_AAA_SUPPORT

	if (!strlen(oph_aaa_endpoint)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: endpoint is not set\n");
		return OPH_SERVER_AUTH_ERROR;
	}

	oph_auth_clip chunk;
	chunk.memory = (char *) malloc(1);
	*chunk.memory = chunk.size = 0;

	char url[OPH_MAX_STRING_SIZE], fields[OPH_MAX_STRING_SIZE];
	snprintf(url, OPH_MAX_STRING_SIZE, "%s/engine/api/read_authorisation", oph_aaa_endpoint);
	snprintf(fields, OPH_MAX_STRING_SIZE, "username=%s&resource_category=%s&resource_name=%s&token=%s", userid, oph_aaa_category, oph_aaa_name, token);

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: GET authorization rule: waiting...\n");

	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, AUTH_CONNECTTIMEOUT);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, json_pt);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

	pthread_mutex_unlock(&global_flag);
	pthread_mutex_lock(&curl_flag);
	CURLcode res = curl_easy_perform(curl);
	pthread_mutex_unlock(&curl_flag);
	pthread_mutex_lock(&global_flag);

	curl_easy_cleanup(curl);

	if (res || !chunk.memory) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: unable to obtaine authorization rule: %s\n", curl_easy_strerror(res));
		if (chunk.memory)
			free(chunk.memory);
		return OPH_SERVER_AUTH_ERROR;
	}

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: GET authorization rule: completed\n");

	json_t *info = json_loads(chunk.memory, 0, NULL);
	if (!info) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "AAA: unable to parse JSON string\n");
		free(chunk.memory);
		return OPH_SERVER_ERROR;
	}

	char *success = NULL, *error = NULL;
	json_unpack(info, "{s?s,s?s}", "success", &success, "error", &error);

	if (error) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "AAA: %s\n", error);
		json_decref(info);
		free(chunk.memory);
		return OPH_SERVER_AUTH_ERROR;
	}
	if (!success) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "AAA: unexpected return message\n");
		json_decref(info);
		free(chunk.memory);
		return OPH_SERVER_AUTH_ERROR;
	}

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "AAA: %s\n", success);

	json_decref(info);
	free(chunk.memory);

	return OPH_SERVER_OK;

#endif

	return OPH_SERVER_AUTH_ERROR;
}

int oph_auth_is_user_black_listed(const char *userid)
{
	if (!userid)
		return OPH_SERVER_NULL_POINTER;

#ifdef BLACK_LIST_FILE

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Search '%s' in black list '%s'\n", userid, BLACK_LIST_FILE);
	int result = OPH_SERVER_OK;
	char buf[OPH_MAX_STRING_SIZE];
	FILE *fd = fopen(BLACK_LIST_FILE, "r");
	if (fd) {
		while (fgets(buf, OPH_MAX_STRING_SIZE, fd)) {
			if (strlen(buf))
				buf[strlen(buf) - 1] = '\0';
			if (strlen(buf) && !strcmp(userid, buf)) {
				result = OPH_SERVER_AUTH_ERROR;
				break;
			}
		}
		fclose(fd);
	} else
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "No black list configured as '%s'\n", BLACK_LIST_FILE);

	if (result)
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "User '%s' in the black list\n", userid);

	return result;

#else

	return OPH_SERVER_OK;

#endif
}

int oph_auth_vo(oph_argument * args, char **username)
{
	if (!args)
		return OPH_SERVER_NULL_POINTER;

	if (username)
		*username = NULL;

#ifdef AUTHORIZED_VO_FILE

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Search '%s=%s' in VO list '%s'\n", args->key, args->value, AUTHORIZED_VO_FILE);
	int result = OPH_SERVER_AUTH_ERROR;
	char buf[OPH_MAX_STRING_SIZE], *user = NULL;
	FILE *fd = fopen(AUTHORIZED_VO_FILE, "r");
	if (fd) {
		while (fgets(buf, OPH_MAX_STRING_SIZE, fd)) {
			if (strlen(buf))
				buf[strlen(buf) - 1] = '\0';
			if (strlen(buf)) {
				if (username && ((user = strstr(buf, OPH_SEPARATOR_BASIC)))) {
					*user = 0;
					user++;
				}
				if (!strcmp(args->value, buf)) {
					if (username && user)
						*username = strdup(user);
					result = OPH_SERVER_OK;
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found an authorized VO '%s' for the user\n", buf);
					break;
				}
			}
		}
		fclose(fd);
	} else
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "No VO found in '%s'\n", AUTHORIZED_VO_FILE);
	if (result)
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to find any VO in list of the authorized VO\n");
	return result;
#else

	return OPH_SERVER_AUTH_ERROR;

#endif
}

int oph_auth_token(const char *token, const char *host, char **userid, char **new_token, short *type)
{
	if (!token || !host)
		return OPH_SERVER_NULL_POINTER;
	if (userid)
		*userid = NULL;
	if (new_token)
		*new_token = NULL;
	if (type)
		*type = 0;

#if defined(OPH_OPENID_SUPPORT) || defined(OPH_AAA_SUPPORT)

	short _type = 0;
	int result = OPH_SERVER_OK;
	if (!oph_get_user_by_token(&tokens_openid, token, userid, new_token, NULL))
		_type = 1;
	else if (!oph_get_user_by_token(&tokens_aaa, token, userid, new_token, NULL))
		_type = 2;
	if (_type)
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Token found in active token list\n");
	else {
		short count;
		char deadline[OPH_MAX_STRING_SIZE];
		if ((count = oph_is_in_bl(&bl_head, OPH_AUTH_TOKEN, host, deadline)) > OPH_AUTH_MAX_COUNT) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Access with token from %s has been blocked until %s since too access attemps have been received\n", host, deadline);
			result = OPH_SERVER_AUTH_ERROR;
		} else if ((result = oph_auth_check_token(token, &_type))) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Token is not valid\n");
			if (!count)
				oph_add_to_bl(&bl_head, OPH_AUTH_TOKEN, host);
		} else if ((result = oph_auth_get_user_from_token(token, userid, 1, _type)) || !*userid) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to get username from token\n");
			if (!count)
				oph_add_to_bl(&bl_head, OPH_AUTH_TOKEN, host);
		} else {
			switch (_type) {
				case 1:
					oph_add_to_bl(&tokens_openid, *userid, token);
					break;
				case 2:
					oph_add_to_bl(&tokens_aaa, *userid, token);
					break;
				default:
					pmesg(LOG_ERROR, __FILE__, __LINE__, "Bad token type\n");
					result = OPH_SERVER_SYSTEM_ERROR;
			}
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Token added to active token list\n");
		}
	}
	if (!result) {
		if (!*userid) {
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Memory error\n");
			result = OPH_SERVER_ERROR;
		} else
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Token is associated with the user '%s'\n", *userid);
	}
	if (type)
		*type = _type;

	return result;

#else

	return OPH_SERVER_AUTH_ERROR;

#endif
}

int oph_auth_save_token(const char *access_token, const char *refresh_token, const char *userinfo)
{
	if (!access_token || !userinfo)
		return OPH_SERVER_NULL_POINTER;

#ifdef OPH_OPENID_SUPPORT

	pthread_mutex_lock(&global_flag);

	char *userid = NULL;
	if (oph_auth_get_user_from_userinfo_openid(userinfo, &userid) || !userid) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Userinfo has to be retrieved\n");
		if (oph_auth_token(access_token, oph_server_host, &userid, NULL, NULL) || !userid) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Token will be discarded\n");
			return OPH_SERVER_ERROR;
		}
	} else if (oph_get_user_by_token(&tokens_openid, access_token, NULL, NULL, NULL)) {
		_oph_add_to_bl(&tokens_openid, userid, access_token, 1);
		oph_auth_cache_userinfo(access_token, userinfo);
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Token added to active token list\n");
	} else
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Token found in active token list\n");	// Warning: the token should not be already buffered

	pthread_mutex_unlock(&global_flag);

	if (refresh_token) {
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "The token will be refreshed after %d sec\n", oph_openid_token_timeout);

		oph_refresh_token *refresh_tokens = (oph_refresh_token *) malloc(sizeof(oph_refresh_token));
		if (refresh_tokens) {
			refresh_tokens->access_token = strdup(access_token);
			refresh_tokens->refresh_token = strdup(refresh_token);
			refresh_tokens->userid = strdup(userid);
			refresh_tokens->userinfo = userinfo ? strdup(userinfo) : NULL;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
			pthread_t tid;
			pthread_create(&tid, NULL, (void *(*)(void *)) &_oph_refresh, refresh_tokens);
#endif
		} else
			pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Memory error\n");
	}

	if (userid)
		free(userid);

#endif

	UNUSED(refresh_token);
	return OPH_SERVER_OK;
}

// Thread unsafe
int oph_auth_check_location()
{
	if (!oph_auth_location)
		return OPH_SERVER_AUTH_ERROR;

	struct stat s;
	if (stat(oph_auth_location, &s) && (errno == ENOENT)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Authorization directory '%s' not found\n", oph_auth_location);
		return OPH_SERVER_AUTH_ERROR;
	}

	char filename[OPH_MAX_STRING_SIZE];
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_AUTH_FLAG, oph_auth_location);
	if (!stat(filename, &s) || (errno != ENOENT)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Authorization directory '%s' found, but it has been auto-generated\n", oph_auth_location);
		return OPH_SERVER_AUTH_ERROR;
	}

	return OPH_SERVER_OK;
}

int oph_auth_user(const char *userid, const char *passwd, const char *host, char **actual_userid, char *userid_exist)
{
	if (!userid)
		return OPH_SERVER_NULL_POINTER;
	if (actual_userid)
		*actual_userid = NULL;
	if (userid_exist)
		*userid_exist = 0;

	char oph_auth_file[OPH_MAX_STRING_SIZE], deadline[OPH_MAX_STRING_SIZE];
	snprintf(oph_auth_file, OPH_MAX_STRING_SIZE, OPH_AUTH_FILE, oph_auth_location);

#ifdef INTERFACE_TYPE_IS_SSL
	char sha_passwd[2 * SHA_DIGEST_LENGTH + 2];
	if (passwd)
		oph_sha(sha_passwd, passwd);
#endif

	int result = OPH_SERVER_ERROR;
	FILE *file;
	short count;

	if ((file = fopen(oph_auth_file, "r"))) {
		char buffer[OPH_MAX_STRING_SIZE], *username, *password, *savepointer = NULL;
		while (fgets(buffer, OPH_MAX_STRING_SIZE, file)) {
			if (strlen(buffer) && (buffer[strlen(buffer) - 1] == '\n'))
				buffer[strlen(buffer) - 1] = 0;	// Skip the last '\n'
			if (strlen(buffer)) {
				username = strtok_r(buffer, OPH_SEPARATOR_BASIC, &savepointer);
				if (!username) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' is corrupted\n", oph_auth_file);
					result = OPH_SERVER_IO_ERROR;
					break;
				}
				if (strcmp(userid, username))
					continue;
				if ((count = oph_is_in_bl(&bl_head, userid, host, deadline)) > OPH_AUTH_MAX_COUNT) {
					pmesg(LOG_WARNING, __FILE__, __LINE__, "Access of user '%s' from %s has been blocked until %s since too access attemps have been received\n", userid, host,
					      deadline);
					result = OPH_SERVER_AUTH_ERROR;
					break;
				}
				if (userid_exist)
					*userid_exist = 1;
				password = strtok_r(NULL, OPH_SEPARATOR_BASIC, &savepointer);
				if (!password) {
					pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' is corrupted\n", oph_auth_file);
					result = OPH_SERVER_IO_ERROR;
#ifndef INTERFACE_TYPE_IS_GSI
				} else if (!passwd) {	// If passwd == NULL, password check is skipped (used only in case of tokens)
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "User '%s' is authorized\n", userid);
					oph_drop_from_bl(&bl_head, userid, host);
					result = OPH_SERVER_OK;
#endif
				} else if (passwd && !strcmp(passwd, password)) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "User '%s' is authorized\n", userid);
					oph_drop_from_bl(&bl_head, userid, host);
					result = OPH_SERVER_OK;
				}
#ifdef INTERFACE_TYPE_IS_SSL
				else if (passwd && !strcmp(sha_passwd, password)) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "User '%s' is authorized\n", userid);
					oph_drop_from_bl(&bl_head, userid, host);
					result = OPH_SERVER_OK;
				}
#endif
				else if (!count)
					oph_add_to_bl(&bl_head, userid, host);
				if (!result && actual_userid)
					*actual_userid = strtok_r(NULL, OPH_SEPARATOR_BASIC, &savepointer);
				break;
			}
		}
		fclose(file);
	} else
		result = OPH_SERVER_IO_ERROR;

	return result;
}

int oph_load_user(const char *userid, oph_argument ** args, int *save_in_odb)
{
	if (!userid || !args)
		return OPH_SERVER_NULL_POINTER;
	if (save_in_odb)
		*save_in_odb = 0;

	if (!oph_auth_location)
		return OPH_SERVER_AUTH_ERROR;

	// Dynamic creation of the folders
	struct stat s;
	char dirname[OPH_MAX_STRING_SIZE], filename[OPH_MAX_STRING_SIZE];

	strcpy(dirname, oph_auth_location);
	if (stat(dirname, &s) && (errno == ENOENT)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Automatic creation of configuration directory: %s\n", dirname);
		int i;
		for (i = 0; dirname[i]; ++i) {
			if (dirname[i] == '/') {
				dirname[i] = 0;
				mkdir(dirname, 0755);
				dirname[i] = '/';
			}
		}
		mkdir(dirname, 0755);
		// Place flag
		FILE *file;
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_AUTH_FLAG, oph_auth_location);
		if ((file = fopen(filename, "w")))
			fclose(file);
	}

	snprintf(dirname, OPH_MAX_STRING_SIZE, OPH_SESSION_ROOT, oph_auth_location);
	if (stat(dirname, &s) && (errno == ENOENT)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Automatic creation of configuration directory: %s\n", dirname);
		int i;
		for (i = 0; dirname[i]; ++i) {
			if (dirname[i] == '/') {
				dirname[i] = 0;
				mkdir(dirname, 0755);
				dirname[i] = '/';
			}
		}
		mkdir(dirname, 0755);
	}

	snprintf(dirname, OPH_MAX_STRING_SIZE, OPH_SESSION_DIR, oph_auth_location, userid);
	if (stat(dirname, &s) && (errno == ENOENT)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Automatic creation of configuration directory: %s\n", dirname);
		int i;
		for (i = 0; dirname[i]; ++i) {
			if (dirname[i] == '/') {
				dirname[i] = 0;
				mkdir(dirname, 0755);
				dirname[i] = '/';
			}
		}
		mkdir(dirname, 0755);
	}

	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_FILE, oph_auth_location, userid);
	if (stat(filename, &s) && (errno == ENOENT)) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Automatic creation of configuration file: %s\n", filename);
		oph_argument *tmp, *tail = *args = NULL;

		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_OPENED_SESSIONS);
		if (asprintf(&tmp->value, "%d", OPH_DEFAULT_USER_OPENED_SESSIONS) <= 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in creation of configuration files\n");
			oph_cleanup_args(&tmp);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_MAX_SESSIONS);
		if (asprintf(&tmp->value, "%d", oph_default_max_sessions) <= 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in creation of configuration files\n");
			oph_cleanup_args(&tmp);
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_TIMEOUT_SESSION);
		if (asprintf(&tmp->value, "%d", oph_default_session_timeout) <= 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in creation of configuration files\n");
			oph_cleanup_args(&tmp);
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_MAX_CORES);
		if (asprintf(&tmp->value, "%d", oph_default_max_cores) <= 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in creation of configuration files\n");
			oph_cleanup_args(&tmp);
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_MAX_HOSTS);
		if (asprintf(&tmp->value, "%d", oph_default_max_hosts) <= 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in creation of configuration files\n");
			oph_cleanup_args(&tmp);
			oph_cleanup_args(args);
			return OPH_SERVER_SYSTEM_ERROR;
		}
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_IS_ADMIN);
		tmp->value = strdup(OPH_DEFAULT_NO);
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;
		tmp = (oph_argument *) malloc(sizeof(oph_argument));
		tmp->key = strdup(OPH_USER_ENABLED);
		tmp->value = strdup(OPH_DEFAULT_YES);
		tmp->next = NULL;
		if (tail)
			tail->next = tmp;
		else
			*args = tmp;
		tail = tmp;

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Saving configuration data of '%s'\n", userid);
		if (*args && oph_save_user(userid, *args)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error in saving configuration data of '%s'\n", userid);
			oph_cleanup_args(args);
			return OPH_SERVER_IO_ERROR;
		}

		if (save_in_odb)
			*save_in_odb = 1;
	} else if (oph_load_file(filename, args))
		return OPH_SERVER_ERROR;	// DT_REG

	return OPH_SERVER_OK;
}

int oph_save_user(const char *userid, oph_argument * args)
{
	if (!userid || !args)
		return OPH_SERVER_NULL_POINTER;

	int result = OPH_SERVER_OK;
	char filename[OPH_MAX_STRING_SIZE];
	FILE *file;

	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_FILE, oph_auth_location, userid);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "User data saving in '%s'\n", filename);
	if ((file = fopen(filename, "w"))) {
		oph_argument *tmp;
		for (tmp = args; tmp; tmp = tmp->next)
			fprintf(file, "%s=%s\n", tmp->key, tmp->value);
		fclose(file);
	} else
		result = OPH_SERVER_IO_ERROR;

	return result;
}

// This function changes the argument 'user_string'
int oph_check_role_of(const char *userid, char *user_string, oph_auth_user_role * role)
{
	if (!userid || !user_string || !role)
		return OPH_SERVER_WRONG_PARAMETER_ERROR;
	*role = OPH_ROLE_NONE;

	char *upointer = strstr(user_string, userid);
	if (!upointer) {
		int iiii, jjjj = strlen(user_string);
		for (iiii = 0; iiii < jjjj; ++iiii)
			if ((user_string[iiii] == '/') || (user_string[iiii] == ' ') || (user_string[iiii] == '=') || (user_string[iiii] == ':'))
				user_string[iiii] = '_';
		upointer = strstr(user_string, userid);
		if (!upointer) {
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "User '%s' not found in session user list '%s'\n", userid, user_string);
			return OPH_SERVER_OK;
		}
	}

	char *rpointer = strchr(upointer, OPH_SEPARATOR_ROLE);
	if (!rpointer) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Session data are not correct\n");
		return OPH_SERVER_SYSTEM_ERROR;
	}

	char *save_pointer = NULL, *epointer = strtok_r(rpointer, OPH_SEPARATOR_USER, &save_pointer);
	if (!epointer) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Session data are not correct\n");
		return OPH_SERVER_SYSTEM_ERROR;
	}

	*rpointer = 0;
	*role = oph_string_to_role(1 + rpointer);
	if (*role == OPH_ROLE_NONE) {
		pmesg(LOG_WARNING, __FILE__, __LINE__, "Session data are not correct: role '%s' does not exist\n", 1 + rpointer);
		return OPH_SERVER_SYSTEM_ERROR;
	}

	return OPH_SERVER_OK;
}

int oph_auth_session(const char *userid, const char *sessionid, const char *serverid, oph_argument ** args, int *active, oph_auth_user_role * role)
{
	if (!userid || !sessionid || !args)
		return OPH_SERVER_NULL_POINTER;
	if (role)
		*role = OPH_ROLE_NONE;

	char filename[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE];

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract session code from '%s'\n", sessionid);
	if (oph_get_session_code(sessionid, code)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract session code from '%s'\n", sessionid);
		return OPH_SERVER_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session code is '%s'\n", code);

	if (serverid) {
		char effective_sessionid[OPH_MAX_STRING_SIZE];
		snprintf(effective_sessionid, OPH_MAX_STRING_SIZE, OPH_SESSIONID_TEMPLATE, serverid, code);
		if (strncmp(sessionid, effective_sessionid, OPH_MAX_STRING_SIZE)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Session id '%s' does not match with the template\n", sessionid);
			return OPH_SERVER_ERROR;
		}
	}

	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, userid, code);
	if (oph_load_file(filename, args))	// DT_LNK
	{
		oph_cleanup_args(args);
		return OPH_SERVER_ERROR;
	}

	char tmp[OPH_MAX_STRING_SIZE];

	// Check if session is active
	if (active) {
		if (oph_get_arg(*args, OPH_SESSION_ACTIVE, tmp)) {
			oph_cleanup_args(args);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Error in loading data of session: %s\n", sessionid);
			return OPH_SERVER_ERROR;
		}
		if (strcmp(tmp, OPH_DEFAULT_YES))
			*active = 0;
		else
			*active = 1;
	}
	// Check user role
	if (role) {
		if (oph_get_arg(*args, OPH_SESSION_OWNER, tmp)) {
			oph_cleanup_args(args);
			pmesg(LOG_WARNING, __FILE__, __LINE__, "Error in loading data of session: %s\n", sessionid);
			return OPH_SERVER_ERROR;
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Owner of this session is: %s\n", tmp);
		int i, j = strlen(tmp);
		for (i = 0; i < j; ++i)
			if ((tmp[i] == '/') || (tmp[i] == ' ') || (tmp[i] == '=') || (tmp[i] == ':'))
				tmp[i] = '_';
		if (!strcmp(userid, tmp))
			*role = OPH_ROLE_ALL;
		else {
			if (oph_get_arg(*args, OPH_SESSION_USERS, tmp)) {
				oph_cleanup_args(args);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "Error in loading data of session: %s\n", sessionid);
				return OPH_SERVER_ERROR;
			}
			if (oph_check_role_of(userid, tmp, role)) {
				oph_cleanup_args(args);
				pmesg(LOG_WARNING, __FILE__, __LINE__, "Error in loading data of session: %s\n", sessionid);
				return OPH_SERVER_ERROR;
			}
		}
	}

	return OPH_SERVER_OK;
}

int oph_save_session(const char *userid, const char *sessionid, oph_argument * args, int type)
{
	if (!userid || !sessionid || !args)
		return OPH_SERVER_NULL_POINTER;

	char filename[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE];
	FILE *file;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract session code from '%s'\n", sessionid);
	if (oph_get_session_code(sessionid, code)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract session code from '%s'\n", sessionid);
		return OPH_SERVER_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session code is '%s'\n", code);

	if (type == DT_REG) {
		// Create file
		char str_time[OPH_MAX_STRING_SIZE], dirname[OPH_MAX_STRING_SIZE];
		if (oph_get_arg(args, OPH_SESSION_CREATION_TIME, str_time)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract creation time\n");
			return OPH_SERVER_ERROR;
		}
		time_t nowtime = (time_t) strtol(str_time, NULL, 10);
		struct tm nowtm;
		if (!localtime_r(&nowtime, &nowtm)) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get system time\n");
			return OPH_SERVER_SYSTEM_ERROR;
		}
		strftime(str_time, OPH_MAX_STRING_SIZE, "%Y", &nowtm);
		snprintf(dirname, OPH_MAX_STRING_SIZE, OPH_SESSION_REAL_DIR, oph_auth_location, str_time);
		if (mkdir(dirname, 0755))
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to create the folder '%s', but don't care\n", dirname);
		strftime(str_time, OPH_MAX_STRING_SIZE, "/%m", &nowtm);
		strncat(dirname, str_time, OPH_MAX_STRING_SIZE - strlen(dirname));
		if (mkdir(dirname, 0755))
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to create the folder '%s', but don't care\n", dirname);
		strftime(str_time, OPH_MAX_STRING_SIZE, "/%d", &nowtm);
		strncat(dirname, str_time, OPH_MAX_STRING_SIZE - strlen(dirname));
		if (mkdir(dirname, 0755))
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to create the folder '%s', but don't care\n", dirname);
		snprintf(filename, OPH_MAX_STRING_SIZE, OPH_SESSION_REAL_FILE, dirname, code);
	} else if (type == DT_LNK) {
		// Find file
		char linkname[OPH_MAX_STRING_SIZE];
		snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, userid, code);
		int nchars = readlink(linkname, filename, OPH_MAX_STRING_SIZE);
		if (nchars < 0) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File '%s' does not exist\n", filename);
			return OPH_SERVER_IO_ERROR;
		} else if (nchars >= OPH_MAX_STRING_SIZE) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Real file name '%s' is too long\n", filename);
			return OPH_SERVER_IO_ERROR;
		} else {
			filename[nchars] = 0;
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Effective file name is '%s'\n", filename);
		}
	} else {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong type '%s'\n", type);
		return OPH_SERVER_IO_ERROR;
	}

	// Write file .session
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Saving session data in '%s'\n", filename);
	if (!(file = fopen(filename, "w"))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to save '%s'\n", filename);
		return OPH_SERVER_IO_ERROR;
	}
	oph_argument *tmp;
	for (tmp = args; tmp; tmp = tmp->next)
		fprintf(file, "%s=%s\n", tmp->key, tmp->value);
	fclose(file);

	// Create link
	if (type == DT_REG) {
		char linkname[OPH_MAX_STRING_SIZE];
		snprintf(linkname, OPH_MAX_STRING_SIZE, OPH_SESSION_FILE, oph_auth_location, userid, code);
		if (symlink(filename, linkname))
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to create the symbolic link, but don't care\n");
	}

	return OPH_SERVER_OK;
}

int oph_save_user_session(const char *userid, const char *sessionid, oph_argument * args)
{
	if (!userid || !sessionid || !args)
		return OPH_SERVER_NULL_POINTER;

	char filename[OPH_MAX_STRING_SIZE], code[OPH_MAX_STRING_SIZE];
	FILE *file;

	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Extract session code from '%s'\n", sessionid);
	if (oph_get_session_code(sessionid, code)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to extract session code from '%s'\n", sessionid);
		return OPH_SERVER_ERROR;
	}
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Session code is '%s'\n", code);

	// Write file .user
	snprintf(filename, OPH_MAX_STRING_SIZE, OPH_USER_SESSION_FILE, oph_auth_location, userid, code);
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Saving user-specific session data in '%s'\n", filename);
	if (!(file = fopen(filename, "w"))) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to save '%s'\n", filename);
		return OPH_SERVER_IO_ERROR;
	}
	oph_argument *tmp;
	for (tmp = args; tmp; tmp = tmp->next)
		fprintf(file, "%s=%s\n", tmp->key, tmp->value);
	fclose(file);

	return OPH_SERVER_OK;
}

oph_auth_user_role oph_string_to_role(const char *role)
{
	short owner = 0, admin = 0, writer = 0;
	oph_auth_user_role result = OPH_ROLE_NONE;
	if (role) {
		if (role[4] == OPH_ROLE_OWNER_STR[0]) {
			result += OPH_ROLE_OWNER;
			owner = 1;
		}
		if (owner || (role[3] == OPH_ROLE_ADMIN_STR[0])) {
			result += OPH_ROLE_ADMIN;
			admin = 1;
		}
		if (admin || (role[2] == OPH_ROLE_EXECUTE_STR[0]))
			result += OPH_ROLE_EXECUTE;
		if (admin || (role[1] == OPH_ROLE_WRITE_STR[0])) {
			result += OPH_ROLE_WRITE;
			writer = 1;
		}
		if (writer || (role[0] == OPH_ROLE_READ_STR[0]))
			result += OPH_ROLE_READ;
	}
	return result;
}

char *oph_role_to_string(oph_auth_user_role role)
{
	short owner = 0, admin = 0, writer = 0;
	char result[6];
	sprintf(result, OPH_ROLE_NULL_STR);
	if (role & OPH_ROLE_OWNER) {
		result[4] = OPH_ROLE_OWNER_STR[0];
		owner = 1;
	}
	if (owner || (role & OPH_ROLE_ADMIN)) {
		result[3] = OPH_ROLE_ADMIN_STR[0];
		admin = 1;
	}
	if (admin || (role & OPH_ROLE_EXECUTE))
		result[2] = OPH_ROLE_EXECUTE_STR[0];
	if (admin || (role & OPH_ROLE_WRITE)) {
		result[1] = OPH_ROLE_WRITE_STR[0];
		writer = 1;
	}
	if (writer || (role & OPH_ROLE_READ))
		result[0] = OPH_ROLE_READ_STR[0];
	return strdup(result);
}

oph_auth_user_role oph_code_role(const char *role)
{
	short owner = 0, admin = 0, writer = 0, found;
	unsigned int i;
	oph_auth_user_role result = OPH_ROLE_NONE;
	if (!role)
		return result;

	char string[1 + strlen(role)], *pch, *save_pointer = NULL;
	strcpy(string, role);
	pch = strtok_r(string, OPH_SEPARATOR_ROLES, &save_pointer);
	while (pch) {
		found = 0;
		if (!strcmp(pch, OPH_ROLE_OWNER_STR)) {
			result += OPH_ROLE_OWNER;
			owner = 1;
			found = 1;
		}
		if (owner || !strcmp(pch, OPH_ROLE_ADMIN_STR)) {
			result += OPH_ROLE_ADMIN;
			admin = 1;
			if (!owner)
				found = 1;
		}
		if (admin || !strcmp(pch, OPH_ROLE_EXECUTE_STR)) {
			result += OPH_ROLE_EXECUTE;
			if (!admin)
				found = 1;
		}
		if (admin || !strcmp(pch, OPH_ROLE_WRITE_STR)) {
			result += OPH_ROLE_WRITE;
			writer = 1;
			if (!admin)
				found = 1;
		}
		if (writer || !strcmp(pch, OPH_ROLE_READ_STR)) {
			result += OPH_ROLE_READ;
			if (!writer)
				found = 1;
		}
		if (!found)
			for (i = 0; i < strlen(pch); ++i) {
				owner = admin = writer = found = 0;
				if (pch[i] == OPH_ROLE_OWNER_STR[0]) {
					result += OPH_ROLE_OWNER;
					owner = 1;
					found = 1;
				}
				if (owner || (pch[i] == OPH_ROLE_ADMIN_STR[0])) {
					result += OPH_ROLE_ADMIN;
					admin = 1;
					if (!owner)
						found = 1;
				}
				if (admin || (pch[i] == OPH_ROLE_EXECUTE_STR[0])) {
					result += OPH_ROLE_EXECUTE;
					if (!admin)
						found = 1;
				}
				if (admin || (pch[i] == OPH_ROLE_WRITE_STR[0])) {
					result += OPH_ROLE_WRITE;
					writer = 1;
					if (!admin)
						found = 1;
				}
				if (writer || (pch[i] == OPH_ROLE_READ_STR[0])) {
					result += OPH_ROLE_READ;
					if (!writer)
						found = 1;
				}
				if (!found)
					return OPH_ROLE_NONE;
			}
		pch = strtok_r(NULL, OPH_SEPARATOR_ROLES, &save_pointer);
	}

	return result;
}

char *oph_code_role_string(const char *role)
{
	short owner = 0, admin = 0, writer = 0, found;
	unsigned int i;
	char result[6];
	sprintf(result, OPH_ROLE_NULL_STR);
	if (!role)
		return strdup(result);

	char string[1 + strlen(role)], *pch, *save_pointer = NULL;
	strcpy(string, role);
	pch = strtok_r(string, OPH_SEPARATOR_ROLES, &save_pointer);
	while (pch) {
		found = 0;
		if (!strcmp(pch, OPH_ROLE_OWNER_STR)) {
			result[4] = OPH_ROLE_OWNER_STR[0];
			owner = 1;
			found = 1;
		}
		if (owner || !strcmp(pch, OPH_ROLE_ADMIN_STR)) {
			result[3] = OPH_ROLE_ADMIN_STR[0];
			admin = 1;
			if (!owner)
				found = 1;
		}
		if (admin || !strcmp(pch, OPH_ROLE_EXECUTE_STR)) {
			result[2] = OPH_ROLE_EXECUTE_STR[0];
			if (!admin)
				found = 1;
		}
		if (admin || !strcmp(pch, OPH_ROLE_WRITE_STR)) {
			result[1] = OPH_ROLE_WRITE_STR[0];
			writer = 1;
			if (!admin)
				found = 1;
		}
		if (writer || !strcmp(pch, OPH_ROLE_READ_STR)) {
			result[0] = OPH_ROLE_READ_STR[0];
			if (!writer)
				found = 1;
		}
		if (!found)
			for (i = 0; i < strlen(pch); ++i) {
				owner = admin = writer = found = 0;
				if (pch[i] == OPH_ROLE_OWNER_STR[0]) {
					result[4] = OPH_ROLE_OWNER_STR[0];
					owner = 1;
					found = 1;
				}
				if (owner || (pch[i] == OPH_ROLE_ADMIN_STR[0])) {
					result[3] = OPH_ROLE_ADMIN_STR[0];
					admin = 1;
					if (!owner)
						found = 1;
				}
				if (admin || (pch[i] == OPH_ROLE_EXECUTE_STR[0])) {
					result[2] = OPH_ROLE_EXECUTE_STR[0];
					if (!admin)
						found = 1;
				}
				if (admin || (pch[i] == OPH_ROLE_WRITE_STR[0])) {
					result[1] = OPH_ROLE_WRITE_STR[0];
					writer = 1;
					if (!admin)
						found = 1;
				}
				if (writer || (pch[i] == OPH_ROLE_READ_STR[0])) {
					result[0] = OPH_ROLE_READ_STR[0];
					if (!writer)
						found = 1;
				}
				if (!found)
					return NULL;
			}
		pch = strtok_r(NULL, OPH_SEPARATOR_ROLES, &save_pointer);
	}

	return strdup(result);
}

char *oph_expand_role_string(const char *role)
{
	short only_exe = 0;
	char string[OPH_SHORT_STRING_SIZE];
	*string = 0;
	if (role) {
		if (role[4] == OPH_ROLE_OWNER_STR[0])
			snprintf(string, OPH_SHORT_STRING_SIZE, "%s", OPH_ROLE_OWNER_STR);
		else if (role[3] == OPH_ROLE_ADMIN_STR[0])
			snprintf(string, OPH_SHORT_STRING_SIZE, "%s", OPH_ROLE_ADMIN_STR);
		else {
			if (role[1] == OPH_ROLE_WRITE_STR[0])
				snprintf(string, OPH_SHORT_STRING_SIZE, "%s%s%s", OPH_ROLE_READ_STR, OPH_SEPARATOR_ROLES, OPH_ROLE_WRITE_STR);
			else if (role[0] == OPH_ROLE_READ_STR[0])
				snprintf(string, OPH_SHORT_STRING_SIZE, "%s", OPH_ROLE_READ_STR);
			else
				only_exe = 1;
			if (role[2] == OPH_ROLE_EXECUTE_STR[0]) {
				if (only_exe)
					snprintf(string, OPH_SHORT_STRING_SIZE, "%s", OPH_ROLE_EXECUTE_STR);
				else {
					int s;
					if ((s = OPH_SHORT_STRING_SIZE - strlen(string)) > 1)
						strncat(string, OPH_SEPARATOR_ROLES, s);
					if ((s = OPH_SHORT_STRING_SIZE - strlen(string)) > 1)
						strncat(string, OPH_ROLE_EXECUTE_STR, s);
				}
			}
		}
	}
	return strdup(string);
}

int oph_auth_check_role(oph_auth_user_role role, oph_auth_user_role permission)
{
	if ((role & OPH_ROLE_READ) && !(permission & OPH_ROLE_READ))
		return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_WRITE) && !(permission & OPH_ROLE_WRITE))
		return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_EXECUTE) && !(permission & OPH_ROLE_EXECUTE))
		return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_ADMIN) && !(permission & OPH_ROLE_ADMIN))
		return OPH_SERVER_AUTH_ERROR;
	if ((role & OPH_ROLE_OWNER) && !(permission & OPH_ROLE_OWNER))
		return OPH_SERVER_AUTH_ERROR;
	return OPH_SERVER_OK;
}

int oph_auth_user_enabling(const char *userid, int *result, char **actual_userid)
{
	if (!userid || !result)
		return OPH_SERVER_NULL_POINTER;
	*result = -1;
	if (actual_userid)
		*actual_userid = NULL;

	char *res = oph_get_host_by_user_in_bl(&auth_users, userid, NULL);
	if (res) {
		*result = (int) strtol(res, NULL, 10);
		if (actual_userid)
			*actual_userid = oph_get_host_by_user_in_bl(&actual_users, userid, NULL);
		return OPH_SERVER_OK;
	}

	return OPH_SERVER_ERROR;
}

int oph_auth_enable_user(const char *userid, int result, char *actual_userid)
{
	if (!userid)
		return OPH_SERVER_NULL_POINTER;

	char res[OPH_SHORT_STRING_SIZE];
	snprintf(res, OPH_SHORT_STRING_SIZE, "%d", result);
	oph_add_to_bl(&auth_users, userid, res);
	if (actual_userid)
		oph_add_to_bl(&actual_users, userid, actual_userid);

	return OPH_SERVER_OK;
}

int oph_auth_autocheck_tokens()
{

#ifdef OPH_OPENID_SUPPORT

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_create(&token_tid_openid, NULL, (void *(*)(void *)) &_oph_check_openid, NULL);
#endif

#endif
#ifdef OPH_AAA_SUPPORT

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
	pthread_create(&token_tid_aaa, NULL, (void *(*)(void *)) &_oph_check_aaa, NULL);
#endif

#endif

	return OPH_SERVER_OK;
}

int oph_enable_all_users(char flag)
{
	int result = OPH_SERVER_OK, rresult;
	oph_argument *args = NULL;
	struct dirent *entry, save_entry;
	char dirname[OPH_MAX_STRING_SIZE], filename[OPH_MAX_STRING_SIZE], *userid = NULL;
	snprintf(dirname, OPH_MAX_STRING_SIZE, OPH_USERS_DIR, oph_auth_location);
	struct stat file_stat;

	DIR *dirp = opendir(dirname);
	if (!dirp)
		return OPH_SERVER_IO_ERROR;

	while (!readdir_r(dirp, &save_entry, &entry) && entry) {

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		snprintf(filename, OPH_MAX_STRING_SIZE, "%s/%s", dirname, entry->d_name);
		lstat(filename, &file_stat);
		if (!S_ISDIR(file_stat.st_mode))
			continue;

		userid = entry->d_name;

		oph_init_args(&args);
		rresult = oph_load_user(userid, &args, NULL);
		if (rresult) {
			oph_cleanup_args(&args);
			if (!result)
				result = rresult;
			continue;
		}
		if (!oph_get_arg(args, OPH_USER_ENABLED, filename) && !strncasecmp(filename, flag ? OPH_COMMON_YES : OPH_COMMON_NO, OPH_MAX_STRING_SIZE)) {
			oph_cleanup_args(&args);
			continue;
		}
		rresult = oph_set_arg(&args, OPH_USER_ENABLED, flag ? OPH_COMMON_YES : OPH_COMMON_NO);
		if (rresult) {
			oph_cleanup_args(&args);
			if (!result)
				result = rresult;
			continue;
		}
		rresult = oph_save_user(userid, args);
		if (rresult) {
			oph_cleanup_args(&args);
			if (!result)
				result = rresult;
			continue;
		}
		oph_cleanup_args(&args);
	}

	closedir(dirp);

	return result;
}
