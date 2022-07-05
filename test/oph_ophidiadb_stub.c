/*
    Ophidia Server
    Copyright (C) 2012-2022 CMCC Foundation

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

#include "oph_ophidiadb.h"
#include "oph_gather.h"

extern char *oph_server_location;
extern ophidiadb *ophDB;

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t global_flag;
#endif

int oph_odb_read_config_ophidiadb(ophidiadb * oDB)
{
	return oph_odb_initialize_ophidiadb(oDB);
}

int oph_odb_initialize_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	oDB->name = NULL;
	oDB->hostname = NULL;
	oDB->username = NULL;
	oDB->pwd = NULL;
#ifdef OPH_DB_SUPPORT
	oDB->conn = NULL;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_free_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	if (oDB->name) {
		free(oDB->name);
		oDB->name = NULL;
	}
	if (oDB->hostname) {
		free(oDB->hostname);
		oDB->hostname = NULL;
	}
	if (oDB->username) {
		free(oDB->username);
		oDB->username = NULL;
	}
	if (oDB->pwd) {
		free(oDB->pwd);
		oDB->pwd = NULL;
	}
#ifdef OPH_DB_SUPPORT
	if (oDB->conn) {
		oph_odb_disconnect_from_ophidiadb(oDB);
		oDB->conn = NULL;
	}
#endif

	free(oDB);

	return OPH_ODB_SUCCESS;
}

int oph_odb_connect_to_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_check_connection_to_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_disconnect_from_ophidiadb(ophidiadb * oDB)
{
	if (!oDB)
		return OPH_ODB_NULL_PARAM;

#ifdef OPH_DB_SUPPORT
	if (oDB->conn)
		oDB->conn = NULL;
#endif

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_ids(ophidiadb * oDB, const char *command, int **id, char ***ctime, int *nn)
{
	if (!oDB || !command || !id || !nn)
		return OPH_ODB_NULL_PARAM;

	*nn = 3;

	int j;
	*id = (int *) malloc((*nn) * sizeof(int));
	for (j = 0; j < *nn; ++j)
		(*id)[j] = j + 1;

	if (ctime) {
		*ctime = (char **) malloc((*nn) * sizeof(char *));
		for (j = 0; j < *nn; j++)
			(*ctime)[j] = NULL;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_retrieve_list(ophidiadb * oDB, const char *command, ophidiadb_list * list)
{
	if (!oDB || !command || !list)
		return OPH_ODB_NULL_PARAM;

	list->size = 3;

	list->name = (char **) malloc(list->size * sizeof(char *));
	list->id = (int *) malloc(list->size * sizeof(int));
	list->pid = (int *) malloc(list->size * sizeof(int));
	list->wid = (int *) malloc(list->size * sizeof(int));
	list->ctime = (char **) malloc(list->size * sizeof(char *));
	if (!list->name || !list->id || !list->wid || !list->pid || !list->ctime)
		return OPH_ODB_MEMORY_ERROR;

	int j;
	for (j = 0; j < list->size; ++j) {
		list->id[j] = j + 1;
		list->ctime[j] = NULL;
		list->name[j] = strdup("name");
		list->wid[j] = 1;
		list->pid[j] = 0;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_initialize_ophidiadb_list(ophidiadb_list * list)
{
	if (!list)
		return OPH_ODB_NULL_PARAM;

	list->name = NULL;
	list->id = NULL;
	list->pid = NULL;
	list->wid = NULL;
	list->ctime = NULL;

	list->size = 0;
	return OPH_ODB_SUCCESS;
}

int oph_odb_free_ophidiadb_list(ophidiadb_list * list)
{
	int j;
	if (!list)
		return OPH_ODB_NULL_PARAM;

	if (list->name) {
		for (j = 0; j < list->size; ++j)
			if (list->name[j]) {
				free(list->name[j]);
				list->name[j] = NULL;
			}
		free(list->name);
		list->name = NULL;
	}
	if (list->id) {
		free(list->id);
		list->id = NULL;
	}
	if (list->pid) {
		free(list->pid);
		list->pid = NULL;
	}
	if (list->wid) {
		free(list->wid);
		list->wid = NULL;
	}
	if (list->ctime) {
		for (j = 0; j < list->size; ++j)
			if (list->ctime[j]) {
				free(list->ctime[j]);
				list->ctime[j] = NULL;
			}
		free(list->ctime);
		list->ctime = NULL;
	}

	list->size = 0;
	return OPH_ODB_SUCCESS;
}

int oph_odb_extract_datacube_ids(ophidiadb * oDB, char *query, cube ** datacube, int *counter)
{
	if (!oDB || !query || !datacube || !counter)
		return OPH_ODB_NULL_PARAM;

	if (!strcmp
	    (query,
	     "SELECT DISTINCT datacube.iddatacube, datacube.idcontainer FROM datacube,container WHERE datacube.idcontainer=container.idcontainer AND (mysql.oph_is_in_subset(datacube.iddatacube,10,1,10)) AND (container.idfolder='1')"))
		*counter = 0;
	else
		*counter = 3;

	if (!(*datacube = (cube *) malloc(*counter * sizeof(cube))))
		return OPH_ODB_MEMORY_ERROR;

	int j;
	for (j = 0; j < *counter; ++j) {
		(*datacube)[j].id_datacube = j + 1;
		(*datacube)[j].id_container = 1;
	}

	return OPH_ODB_SUCCESS;
}

int oph_odb_insert_user(ophidiadb * oDB, const char *username)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_insert_user2(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts)
{
	UNUSED(password);
	UNUSED(name);
	UNUSED(surname);
	UNUSED(email);
	UNUSED(country);
	UNUSED(max_hosts);

	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_delete_user(ophidiadb * oDB, const char *username)
{
	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_update_user(ophidiadb * oDB, const char *username, const char *password, const char *name, const char *surname, const char *email, const char *country, const int max_hosts)
{
	UNUSED(password);
	UNUSED(name);
	UNUSED(surname);
	UNUSED(email);
	UNUSED(country);
	UNUSED(max_hosts);

	if (!oDB || !username)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_create_hp(ophidiadb * oDB, const char *name, const char *parent, int id_user)
{
	if (!oDB || !name || !parent || !id_user)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_destroy_hp(ophidiadb * oDB, const char *name)
{
	if (!oDB || !name)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_reserve_hp(ophidiadb * oDB, const char *name, int id_user, int id_job, int hosts, char type, int *id_hostpartition)
{
	if (!oDB || !name || !id_user || !id_job || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_release_hp(ophidiadb * oDB, int id_hostpartition)
{
	if (!oDB || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_release_hp2(int id_hostpartition)
{
	return oph_odb_release_hp(ophDB, id_hostpartition);
}

int oph_odb_retrieve_hp(ophidiadb * oDB, const char *name, int id_user, int *id_hostpartition, int *id_job, char *host_type)
{
	if (!oDB || !name || !id_user || !id_hostpartition)
		return OPH_ODB_NULL_PARAM;
	if (id_job)
		*id_job = 0;

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_reserved_hosts(ophidiadb * oDB, int id_user, int *rhosts)
{
	if (!oDB || !id_user || !rhosts)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}

int oph_odb_get_total_hosts(ophidiadb * oDB, int *thosts)
{
	if (!oDB || !thosts)
		return OPH_ODB_NULL_PARAM;

	return OPH_ODB_SUCCESS;
}
