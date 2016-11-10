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

#ifndef OPH_OPHIDIADB_H
#define OPH_OPHIDIADB_H

/* MySQL headers */
#include <mysql.h>

#include "oph_ophidiadb_query.h"

#define OPH_ODB_SUCCESS 0
#define OPH_ODB_NULL_PARAM 1
#define OPH_ODB_MYSQL_ERROR 2
#define OPH_ODB_STR_BUFF_OVERFLOW 3
#define OPH_ODB_MEMORY_ERROR 4
#define OPH_ODB_TOO_MANY_ROWS 5
#define OPH_ODB_ERROR 6
#define OPH_ODB_NO_ROW_FOUND 7

#define MYSQL_BUFLEN 2048
#define OPERATION_QUERY_SIZE 2048

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
int oph_odb_insert_user2(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country);
int oph_odb_delete_user(ophidiadb * oDB, const char *username);
int oph_odb_update_user(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country);

int oph_odb_create_hp(ophidiadb * oDB, const char *name, const char *parent);
int oph_odb_destroy_hp(ophidiadb * oDB, const char *name);

#endif				/* OPH_OPHIDIADB_H */
