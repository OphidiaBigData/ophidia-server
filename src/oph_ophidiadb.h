/*
    Ophidia Server
    Copyright (C) 2012-2019 CMCC Foundation

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
#include <mysql.h>
#ifdef OPH_ODB_MNG
#include <mongoc.h>
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
#ifdef OPH_ODB_MNG
#define OPH_ODB_MONGODB_ERROR 8
#endif

#define MYSQL_BUFLEN 2048
#define OPERATION_QUERY_SIZE 1536

#define OPH_CONF_OPHDB_NAME	"OPHDB_NAME"
#define OPH_CONF_OPHDB_HOST	"OPHDB_HOST"
#define OPH_CONF_OPHDB_PORT	"OPHDB_PORT"
#define OPH_CONF_OPHDB_LOGIN	"OPHDB_LOGIN"
#define OPH_CONF_OPHDB_PWD	"OPHDB_PWD"

#ifdef OPH_ODB_MNG
#define OPH_CONF_MNGDB_NAME	"MNGDB_NAME"
#define OPH_CONF_MNGDB_HOST	"MNGDB_HOST"
#define OPH_CONF_MNGDB_PORT	"MNGDB_PORT"
#define OPH_CONF_MNGDB_LOGIN	"MNGDB_LOGIN"
#define OPH_CONF_MNGDB_PWD	"MNGDB_PWD"
#define OPH_ODB_MNGDB_CONN	"mongodb://%s:%d/?appname=%s"
#define OPH_ODB_MNGDB_COLL_METADATAINSTANCE	"metadatainstance"
#define OPH_ODB_MNGDB_COLL_MANAGE	"manage"
#endif

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
	MYSQL *conn;
#ifdef OPH_ODB_MNG
	char *mng_name;
	char *mng_hostname;
	int mng_server_port;
	char *mng_username;
	char *mng_pwd;
	mongoc_client_t *mng_conn;
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

#ifdef OPH_ODB_MNG
/**
 * \brief Function to initilize OphidiaDB structure.
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_init_mongodb(ophidiadb * oDB);

/**
 * \brief Function to delete OphidiaDB and to free memory allocated in multi-thread environment.
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_free_mongodb(ophidiadb * oDB);

/**
 * \brief Function to connect to the OphidiaDB. WARNING: Call this function before any other function or the system will crash
 * \param structure containing OphidiaDB parameters
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_connect_to_mongodb(ophidiadb * oDB);

/**
 * \brief Function to check connect status to the OphidiaDB. WARNING: Do not call this function (or any other) before calling connect_to_ophidiaDB or the client will crash
 * \param structure containing OphidiaDB parameters
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_check_connection_to_mongodb(ophidiadb * oDB);

/**
 * \brief Function to disconnect from the OphidiaDB
 * \param structure containig OphidiaDB parameters
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_disconnect_from_mongodb(ophidiadb * oDB);
#endif

int oph_odb_retrieve_ids(ophidiadb * oDB, const char *query, int **id, char ***ctime, int *n);
int oph_odb_retrieve_list(ophidiadb * oDB, const char *query, ophidiadb_list * list);
int oph_odb_extract_datacube_ids(ophidiadb * oDB, char *query, cube ** datacube, int *counter);

int oph_odb_insert_user(ophidiadb * oDB, const char *username);
int oph_odb_insert_user2(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts);
int oph_odb_delete_user(ophidiadb * oDB, const char *username);
int oph_odb_update_user(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts);

int oph_odb_create_hp(ophidiadb * oDB, const char *name, const char *parent, int id_user);
int oph_odb_destroy_hp(ophidiadb * oDB, const char *name);
int oph_odb_reserve_hp(ophidiadb * oDB, const char *name, int id_user, int id_job, int hosts, int *id_hostpartition);
int oph_odb_release_hp(ophidiadb * oDB, int id_hostpartition);
int oph_odb_release_hp2(int id_hostpartition);
int oph_odb_retrieve_hp(ophidiadb * oDB, const char *name, int id_user, int *id_hostpartition, int *id_job);
int oph_odb_get_total_hosts(ophidiadb * oDB, int *thosts);
int oph_odb_get_reserved_hosts(ophidiadb * oDB, int id_user, int *rhosts);

#endif				/* OPH_OPHIDIADB_H */
