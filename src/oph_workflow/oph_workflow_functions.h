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

#ifndef __OPH_WORKFLOW_FUNCTIONS_H
#define __OPH_WORKFLOW_FUNCTIONS_H

#include "oph_workflow_structs.h"

/* \brief Function for JSON parsing and global variables substitution (ncores,cwd and cube)
 * \param json_string Input JSON string
 * \param username Input username
 * \param ip_address Optional IP address of submitter
 * \param workflow Output OPH_WORKFLOW
 * \return 0 if successful
 */
int oph_workflow_load(char *json_string, const char *username, const char *ip_address, oph_workflow ** workflow);

/* \brief Function for JSON parsing and global variables substitution (ncores,cwd and cube)
 * \param workflow Input OPH_WORKFLOW
 * \param json_string Output JSON string
 * \param checkpoint If set completed tasks are not saved; the checkpoint is appended to workflow name
 * \return 0 if successful
 */
int oph_workflow_store(oph_workflow * workflow, char **json_string, const char *checkpoint);

/* \brief Function to index task names in deps and init dependents_indexes
 * \param tasks Array of tasks
 * \param tasks_num Number of tasks
 * \return 0 if successful
 */
int oph_workflow_indexing(oph_workflow_task * tasks, int tasks_num);

/* \brief Function for cyclic dependencies check
 * \param workflow Input OPH_WORKFLOW to be validated
 * \return 0 if successful
 */
int oph_workflow_validate(oph_workflow * workflow);

/* \brief Function for parallel for check
 * \param workflow Input OPH_WORKFLOW to be validated
 * \return 0 if successful
 */
int oph_workflow_validate_fco(oph_workflow * wf);

/* \brief Function for the setup of the initial array of independent tasks
 * \param tasks Array of tasks
 * \param tasks_num Number of tasks
 * \param initial_tasks_indexes Output array of initial tasks indexes
 * \param initial_tasks_indexes_num Number of initial tasks
 * \return 0 if successful
 */
int oph_workflow_init(oph_workflow_task * tasks, int tasks_num, int **initial_tasks_indexes, int *initial_tasks_indexes_num);

/* \brief Function for extracting the submission string
 * \param workflow Input OPH_WORKFLOW
 * \param task_index Input index of the target task
 * \param light_task_index Input index of the target light task
 * \param long_submission_string Output string to be submitted to resource manager; the string has to be freed
 * \param short_submission_string Output string in short format; the string has to be freed; it can NULL
 * \param error Output string indicating a possible error; the string has to be freed; it can NULL
 * \return 0 if successful
 */
int oph_workflow_get_submission_string(oph_workflow * workflow, int task_index, int light_task_index, char **long_submission_string, char **short_submission_string, char **error);

/* \brief Function for extracting the string submitted by the user
 * \param workflow Input OPH_WORKFLOW
 * \param task_index Input index of the target task
 * \param light_task_index Input index of the target light task
 * \param submitted_string Command string equivalent to workflow; the string has to be freed
 * \return 0 if successful
 */
int oph_workflow_get_submitted_string(oph_workflow * workflow, int task_index, int light_task_index, int show_callback, char **submitted_string);

/* \brief Function for checking dependences
 * \param workflow Input OPH_WORKFLOW
 * \param p Index of parent task
 * \param c Index of child task
 * \return 1 if the task c depends on the task p
 */
int oph_workflow_is_child_of(oph_workflow * wf, int p, int c);

/* \brief Function for variable substitution
 * \param workflow Input OPH_WORKFLOW
 * \param task_index Input index of the target task
 * \param light_task_index Possible input index of the light target task
 * \param submit_string String to be parsed
 * \param error Pointer to save a possible error message
 * \param skip_arg Argument that must not be substituted
 * \return 1 in case of errors
 */
int oph_workflow_var_substitute(oph_workflow * workflow, int task_index, int light_task_index, char **submit_string, char **error, const char *skip_arg);

/* \brief Function to set basic variables
 * \param workflow Input OPH_WORKFLOW
 * \return 1 in case of errors
 */
int oph_workflow_set_basic_var(oph_workflow * workflow);

/* \brief Function to extract the grand parent of a task
 * \param workflow Input OPH_WORKFLOW
 * \param p Index of child task
 * \return The index of grand parent of task k
 */
int oph_gparent_of(oph_workflow * wf, int k);

/* \brief Function to realloc a static vector
 * \param vector Input array
 * \param length Initial array length
 * \param incr Additional item number
 * \return 1 in case of errors
 */
int oph_realloc_vector(char ***vector, int *length, int incr);
int oph_realloc_vector2(oph_workflow_ordered_list *** vector, int *length, int incr);

#endif				//__OPH_WORKFLOW_FUNCTIONS_H
