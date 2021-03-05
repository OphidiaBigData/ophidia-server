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

#ifndef __OPH_OPHIDIADB_FS_H__
#define __OPH_OPHIDIADB_FS_H__

/* MySQL headers */
#include <mysql.h>

/* Project headers */
#include "oph_ophidiadb.h"

#define MYSQL_QUERY_OPH_FS_RETRIEVE_ROOT_ID "SELECT idfolder FROM folder WHERE idparent IS NULL"
#define MYSQL_QUERY_OPH_FS_PATH_PARSING_ID "SELECT idfolder FROM folder WHERE idparent=%d AND foldername='%s'"
#define MYSQL_QUERY_OPH_FS_IS_VISIBLE_CONTAINER "SELECT idcontainer FROM container WHERE idfolder=%d AND containername='%s'"
#define MYSQL_QUERY_OPH_FS_UNIQUENESS "SELECT folder.foldername FROM folder WHERE folder.idparent=%d AND folder.foldername='%s' UNION SELECT container.containername FROM container WHERE container.idfolder=%d AND container.containername='%s'"
#define MYSQL_QUERY_OPH_FS_EMPTINESS "SELECT folder.foldername FROM folder WHERE folder.idparent=%d UNION SELECT container.containername FROM container WHERE container.idfolder=%d"

#define MYSQL_QUERY_FS_RETRIEVE_SESSION_FOLDER_ID "SELECT idfolder FROM session WHERE sessionid = '%s';"
#define MYSQL_QUERY_FS_RETRIEVE_CONTAINER_FOLDER_ID "SELECT idfolder FROM container WHERE idcontainer = %d;"
#define MYSQL_QUERY_FS_RETRIEVE_PARENT_FOLDER_ID "SELECT idparent FROM folder WHERE idfolder = %d;"
#define MYSQL_QUERY_FS_RETRIEVE_SUB_FOLDER_ID "SELECT idfolder FROM folder WHERE idparent = %d;"

#define MYSQL_QUERY_FS_RETRIEVE_PARENT_FOLDER "SELECT idparent, foldername FROM folder WHERE idfolder = %d;"
#define MYSQL_QUERY_FS_MV "UPDATE container SET container.idfolder=%d, container.containername='%s' WHERE container.idcontainer=%d;"
#define MYSQL_QUERY_FS_LIST_0 "SELECT foldername, idfolder FROM folder WHERE folder.idparent=%d;"
#define MYSQL_QUERY_FS_LIST_1 "SELECT foldername AS name, 1 AS type FROM folder WHERE folder.idparent=%d UNION SELECT containername AS name, 2 AS type FROM container WHERE container.idfolder=%d;"
#define MYSQL_QUERY_FS_LIST_1_WC "SELECT containername AS name, 2 AS type FROM container WHERE container.idfolder=%d AND containername = '%s';"
#define MYSQL_QUERY_FS_LIST_2  "SELECT foldername AS name, 1 AS type, NULL AS idcontainer, NULL AS iddatacube FROM folder WHERE folder.idparent=%d UNION SELECT containername AS name, 2 AS type, datacube.idcontainer, iddatacube FROM container LEFT OUTER JOIN datacube ON datacube.idcontainer=container.idcontainer WHERE container.idfolder=%d;"
#define MYSQL_QUERY_FS_LIST_2_WC  "SELECT containername AS name, 2 AS type, datacube.idcontainer, iddatacube FROM container LEFT OUTER JOIN datacube ON datacube.idcontainer=container.idcontainer WHERE container.idfolder=%d AND containername = '%s';"

#define OPH_ODB_FS_ROOT "/"

/**
 * \brief Function used to parse/control paths
 * \param inpath Absolute path or relative path with respect to cwd. It can be the string "".
 * \param cwd Absolute path representing the current working directory. It cannot be NULL and must start with "/".
 * \param folder_id Id of the folder indicated by the path "cwd/inpath" (leaf folder).
 * \param output_path Expanded absolute path of the folder indicated by the path "cwd/inpath". If NULL, the function will control the existence of the folder and return only its id.
 * \param oDB Pointer to the OphidiaDB
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_path_parsing(char *inpath, char *cwd, int *folder_id, char **output_path, ophidiadb * oDB);

/**
 * \brief Function used to retreive session home ID
 * \param sessionid SessionID of the session to be checked
 * \param oDB Pointer to the OphidiaDB
 * \param folder_id Pointer to session home ID
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_get_session_home_id(char *sessionid, ophidiadb * oDB, int *folder_id);

/**
 * \brief Function used to check if a folder is within session tree
 * \param folder_id Id of the folder to be checked
 * \param sessionid SessionID of the session to be checked
 * \param oDB Pointer to the OphidiaDB
 * \param status If the folder is within session tree it will be set to 1, otherwise it will be 0.
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_check_folder_session(int folder_id, char *sessionid, ophidiadb * oDB, int *status);

/**
 * \brief Function used to retrieve the folder id of a container
 * \param oDB Pointer to the OphidiaDB
 * \param container_id Id of the container
 * \param folder_id Id of the folder related to the container
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_retrive_container_folder_id(ophidiadb * oDB, int container_id, int *folder_id);

/**
 * \brief Function used to build backward path given the id of the leaf folder
 * \param folder_id Id of the leaf folder
 * \param oDB Pointer to the OphidiaDB
 * \param out_path Path to be built
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_build_path(int folder_id, ophidiadb * oDB, char (*out_path)[MYSQL_BUFLEN]);

/**
 * \brief Function used to split a generic path in dirname and basename (leaf folder/container)
 * \param input Input path
 * \param first_part Output dirname
 * \param last_token Output basename
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_str_last_token(const char *input, char **first_part, char **last_token);

/**
 * \brief Function used to check if name is a visible container located in the folder related to folder_id
 * \param folder_id Id of the container parent folder
 * \param name Name of the container
 * \param oDB Pointer to the OphidiaDB
 * \param answer 1 if visible, 0 otherwise
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_is_visible_container(int folder_id, char *name, ophidiadb * oDB, int *answer);

/**
 * \brief Function used to check if name is not used by any of the folders or visible containers located in the folder related to folder_id
 * \param folder_id Id of the parent folder
 * \param name Name to check
 * \param oDB Pointer to the OphidiaDB
 * \param answer 1 if unique, 0 otherwise
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_is_unique(int folderid, char *name, ophidiadb * oDB, int *answer);

/**
 * \brief Function used to check if the folder indicated by folder_id is empty (no subfolders)
 * \param folder_id Id of the folder to check
 * \param oDB Pointer to the OphidiaDB
 * \param answer 1 if empty, 0 otherwise
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_is_empty_folder(int folderid, ophidiadb * oDB, int *answer);

/**
 * \brief Function used to update name and folder of a container
 * \param container_id Id of the container to be updated
 * \param out_folder_id Id of the output folder used
 * \param out_container_name Name to be given
 * \param oDB Pointer to the OphidiaDB
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_update_container_path_name(ophidiadb * oDB, int in_container_id, int out_folder_id, char *out_container_name);

/**
 * \brief Function used to retrieve filesystem objects (folders, containers and datacubes)
 * \param level 0 - only folders, 1 - folders and containers, 2 - folders, containers and datacubes
 * \param id_folder Id of the current folder
 * \param container_name Optional filter on the name of containers. It can be NULL.
 * \param information_list Output result set
 * \param oDB Pointer to the OphidiaDB
 * \return 0 if successfull, -1 otherwise
 */
int oph_odb_fs_find_fs_objects(ophidiadb * oDB, int level, int id_folder, char *container_name, MYSQL_RES ** information_list);

int oph_odb_fs_get_subfolders(int folder_id, int **subfolder_id, int *num_subfolders, ophidiadb * oDB);

#endif				/* __OPH_OPHIDIADB_FS_H__ */
