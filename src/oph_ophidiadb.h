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

#ifndef OPH_OPHIDIADB_H
#define OPH_OPHIDIADB_H

/* MySQL headers */
#ifdef OPH_DB_SUPPORT
#include <mysql.h>
#endif
#ifndef OPH_DB_SUPPORT
#include <sqlite3.h>
#endif

#include "oph_ophidiadb_query.h"

#define OPH_ODB_SUCCESS 0
#define OPH_ODB_NULL_PARAM 1
#define OPH_ODB_MYSQL_ERROR 2
#define OPH_ODB_STR_BUFF_OVERFLOW 3
#define OPH_ODB_MEMORY_ERROR 4
#define OPH_ODB_TOO_MANY_ROWS 5
#define OPH_ODB_ERROR 6
#define OPH_ODB_NO_ROW_FOUND 7

#define OPH_ODB_PARTITION_NAME_SIZE 64

#define MYSQL_BUFLEN 2048
#define OPERATION_QUERY_SIZE 1536

#define OPH_CONF_OPHDB_NAME	"OPHDB_NAME"
#define OPH_CONF_OPHDB_HOST	"OPHDB_HOST"
#define OPH_CONF_OPHDB_PORT	"OPHDB_PORT"
#define OPH_CONF_OPHDB_LOGIN	"OPHDB_LOGIN"
#define OPH_CONF_OPHDB_PWD	"OPHDB_PWD"

#define OPH_NULL_VALUE "NULL"

/**
 * \brief Structure that contain OphidiaDB parameters
 * \param name name of OphidiaDB
 * \param hostname name of OphidiaDB host
 * \param server_port port of the MySQL instance that host OphidiaDB
 * \param username to connect to MySQL instance that host OphidiaDB
 * \param pwd Password to connect to MySQL instance that host OphidiaDB
 * \param conn Pointer to a MYSQL * type that is used to do a query on the db
 */
typedef struct {
	char *name;
	char *hostname;
	int server_port;
	char *username;
	char *pwd;
#ifdef OPH_DB_SUPPORT
	MYSQL *conn;
#else
	sqlite3 *db;
#endif
} ophidiadb;

typedef struct {
	int *id;
	char **name;
	int *pid;
	int *wid;
	char **ctime;
	char **max_status;
	int size;
} ophidiadb_list;

typedef struct {
	int id_datacube;
	int id_container;
} cube;

int oph_odb_initialize_ophidiadb(ophidiadb * oDB);
int oph_odb_free_ophidiadb(ophidiadb * oDB);

int oph_odb_initialize_ophidiadb_list(ophidiadb_list * list);
int oph_odb_free_ophidiadb_list(ophidiadb_list * list);

/**
 * \brief Function to read OphidiaDB info from configuration file 
 * \param ophidiadb Pointer to an allocated ophidiadb structure
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_read_config_ophidiadb(ophidiadb * oDB);

/**
 * \brief Function to connect to the OphidiaDB. WARNING: Call this function before any other function or the system will crash
 * \param structure containing OphidiaDB parameters
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_connect_to_ophidiadb(ophidiadb * oDB);

/**
 * \brief Function to check connect status to the OphidiaDB. WARNING: Do not call this function (or any other) before calling connect_to_ophidiaDB or the client will crash
 * \param structure containing OphidiaDB parameters
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_check_connection_to_ophidiadb(ophidiadb * oDB);

/**
 * \brief Function to disconnect from the OphidiaDB
 * \param structure containig OphidiaDB parameters
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_disconnect_from_ophidiadb(ophidiadb * oDB);

int oph_odb_retrieve_ids(ophidiadb * oDB, const char *query, int **id, char ***ctime, int *n);
int oph_odb_retrieve_list(ophidiadb * oDB, const char *query, ophidiadb_list * list);
int oph_odb_extract_datacube_ids(ophidiadb * oDB, char *query, cube ** datacube, int *counter);

int oph_odb_insert_user(ophidiadb * oDB, const char *username);
int oph_odb_insert_user2(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts);
int oph_odb_delete_user(ophidiadb * oDB, const char *username);
int oph_odb_update_user(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts);

int oph_odb_create_hp(ophidiadb * oDB, const char *name, const char *parent, int id_user);
int oph_odb_destroy_hp(ophidiadb * oDB, const char *name);
int oph_odb_reserve_hp(ophidiadb * oDB, const char *name, int id_user, int id_job, int hosts, char type, int *id_hostpartition);
int oph_odb_release_hp(ophidiadb * oDB, int id_hostpartition);
int oph_odb_release_hp2(int id_hostpartition);
int oph_odb_retrieve_hp(ophidiadb * oDB, const char *name, int id_user, int *id_hostpartition, int *id_job, char *host_type);
int oph_odb_get_total_hosts(ophidiadb * oDB, int *thosts);
int oph_odb_get_reserved_hosts(ophidiadb * oDB, int id_user, int *rhosts);

int oph_odb_retrieve_user_from_mail(ophidiadb * oDB, const char *mail, char **username, pthread_mutex_t * flag);
int oph_odb_retrieve_user_from_mail2(const char *mail, char **username, pthread_mutex_t * flag);
#endif				/* OPH_OPHIDIADB_H */
