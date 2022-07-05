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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "oph_workflow_library.h"
#include "debug.h"

extern char *oph_server_host;
extern char *oph_server_port;

// Internal structures

typedef struct _workflow_node {
	int *out_edges;
	int out_edges_num;
	int out_edges_size;
	int *in_edges;
	int in_edges_num;
	int in_edges_size;
	int index;
} workflow_node;

typedef struct _workflow_s_node {
	workflow_node *node;
	struct _workflow_s_node *next;
} workflow_s_node;

typedef struct _workflow_s_nodes {
	workflow_s_node *head;
	workflow_s_node *tail;
	int nodes_num;
} workflow_s_nodes;

int workflow_s_add(workflow_s_nodes * s, workflow_node * node);
int workflow_s_remove(workflow_s_nodes * s, workflow_node ** node);
int workflow_s_nodes_free(workflow_s_nodes * s);
int workflow_node_free(workflow_node * node);
int oph_get_session_code(char *session_id, char *session_code);

// API functions

int oph_workflow_indexing(oph_workflow_task * tasks, int tasks_num)
{
	if (!tasks || tasks_num < 1) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	int i, j, k;
	oph_workflow_task *curtask = NULL;

	for (i = 0; i < tasks_num; i++) {
		curtask = &(tasks[i]);
		for (j = 0; j < curtask->deps_num; j++) {
			if (!strcmp(curtask->deps[j].task_name, curtask->name)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Loop edges not allowed!\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
			for (k = 0; k < tasks_num; k++) {
				if (!strcmp(curtask->deps[j].task_name, tasks[k].name)) {
					curtask->deps[j].task_index = k;
					if (tasks[k].dependents_indexes_num == 0) {
						tasks[k].dependents_indexes = (int *) calloc(1, sizeof(int));
						if (!(tasks[k].dependents_indexes)) {
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating dependents indexes\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						tasks[k].dependents_indexes[0] = i;
						tasks[k].dependents_indexes_num++;
					} else {
						int *tmp = tasks[k].dependents_indexes;
						tasks[k].dependents_indexes = (int *) realloc(tasks[k].dependents_indexes, (tasks[k].dependents_indexes_num + 1) * sizeof(int));
						if (!(tasks[k].dependents_indexes)) {
							tasks[k].dependents_indexes = tmp;
							pmesg(LOG_ERROR, __FILE__, __LINE__, "Error reallocating dependents indexes\n");
							return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
						}
						tasks[k].dependents_indexes[tasks[k].dependents_indexes_num] = i;
						tasks[k].dependents_indexes_num++;
					}
					break;
				}
			}
			if (k >= tasks_num) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Dependency task name not found!\n");
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_validate(oph_workflow * workflow)
{
	if (!workflow || !(workflow->tasks)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}
	// Check for uniqueness of task name
	int i, j, k;
	for (i = 0; i < workflow->tasks_num - 1; i++)
		for (j = i + 1; j < workflow->tasks_num; j++)
			if (!strcmp(workflow->tasks[i].name, workflow->tasks[j].name)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Found two tasks with the same name '%s'\n", workflow->tasks[i].name);
				return OPH_WORKFLOW_EXIT_TASK_NAME_ERROR;
			}
	// Check for special chars in parameters
	size_t value_size, bracket_on = 0;
	for (i = 0; i < workflow->tasks_num; i++)
		for (j = 0; j < workflow->tasks[i].arguments_num; j++) {
			if (strchr(workflow->tasks[i].arguments_keys[j], OPH_WORKFLOW_KV_SEPARATOR[0])) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong key '%s': '%s' is reserved\n", workflow->tasks[i].arguments_keys[j], OPH_WORKFLOW_KV_SEPARATOR);
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
			if (strchr(workflow->tasks[i].arguments_keys[j], OPH_WORKFLOW_KV_SEPARATOR2[0])) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong key '%s': '%s' is reserved\n", workflow->tasks[i].arguments_keys[j], OPH_WORKFLOW_KV_SEPARATOR2);
				return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
			}
			value_size = strlen(workflow->tasks[i].arguments_values[j]);
			for (k = 0; k < (int) value_size; ++k) {
				if (workflow->tasks[i].arguments_values[j][k] == OPH_WORKFLOW_KV_BRACKET[0])
					bracket_on++;
				else if (bracket_on && (workflow->tasks[i].arguments_values[j][k] == OPH_WORKFLOW_KV_BRACKET[1]))
					bracket_on--;
				else if (!bracket_on) {
					if (workflow->tasks[i].arguments_values[j][k] == OPH_WORKFLOW_KV_SEPARATOR[0]) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong value '%s' for key '%s': '%s' is reserved\n", workflow->tasks[i].arguments_values[j],
						      workflow->tasks[i].arguments_keys[j], OPH_WORKFLOW_KV_SEPARATOR);
						return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
					}
					if (workflow->tasks[i].arguments_values[j][k] == OPH_WORKFLOW_KV_SEPARATOR2[0]) {
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Wrong value '%s' for key '%s': '%s' is reserved\n", workflow->tasks[i].arguments_values[j],
						      workflow->tasks[i].arguments_keys[j], OPH_WORKFLOW_KV_SEPARATOR2);
						return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
					}
				}
			}
		}

	// Create graph from tasks
	workflow_node *graph = NULL;
	graph = (workflow_node *) calloc((unsigned int) workflow->tasks_num, sizeof(workflow_node));
	if (!graph) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating graph\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	for (i = 0; i < workflow->tasks_num; i++) {
		if (workflow->tasks[i].deps_num >= 1) {
			graph[i].in_edges = (int *) calloc(workflow->tasks[i].deps_num, sizeof(int));
			if (!(graph[i].in_edges)) {
				for (k = 0; k < workflow->tasks_num; k++)
					workflow_node_free(&(graph[k]));
				free(graph);
				graph = NULL;
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating in_edges\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			graph[i].in_edges_size = workflow->tasks[i].deps_num;
			graph[i].in_edges_num = workflow->tasks[i].deps_num;
			for (j = 0; j < workflow->tasks[i].deps_num; j++)
				graph[i].in_edges[j] = workflow->tasks[i].deps[j].task_index;
		}
		if (workflow->tasks[i].dependents_indexes_num >= 1) {
			graph[i].out_edges = (int *) calloc(workflow->tasks[i].dependents_indexes_num, sizeof(int));
			if (!(graph[i].out_edges)) {
				for (k = 0; k < workflow->tasks_num; k++)
					workflow_node_free(&(graph[k]));
				free(graph);
				graph = NULL;
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating out_edges\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
			graph[i].out_edges_size = workflow->tasks[i].dependents_indexes_num;
			graph[i].out_edges_num = workflow->tasks[i].dependents_indexes_num;
			for (j = 0; j < workflow->tasks[i].dependents_indexes_num; j++)
				graph[i].out_edges[j] = workflow->tasks[i].dependents_indexes[j];
		}
		graph[i].index = i;
	}

	/*  Test for DAG through Topological Sort
	 *
	 *      S ← Set of all nodes with no incoming edges
	 *      while S is non-empty do
	 *          remove a node n from S
	 *          for each node m with an edge e from n to m do
	 *              remove edge e from the graph
	 *              if m has no other incoming edges then
	 *                  insert m into S
	 *      if graph has edges then
	 *          return error (graph has at least one cycle)
	 *      else
	 *          return success (graph has no cycles)
	 */

	//      S ← Set of all nodes with no incoming edges
	workflow_s_nodes S;
	S.head = NULL;
	S.tail = NULL;
	S.nodes_num = 0;
	for (i = 0; i < workflow->tasks_num; i++) {
		if (graph[i].in_edges_num == 0) {
			if (workflow_s_add(&S, &(graph[i]))) {
				for (k = 0; k < workflow->tasks_num; k++)
					workflow_node_free(&(graph[k]));
				free(graph);
				graph = NULL;
				workflow_s_nodes_free(&S);
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Error setting S\n");
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			}
		}
	}

	workflow_node *n = NULL;

	//      while S is non-empty do
	while (S.nodes_num != 0) {
		//          remove a node n from S
		if (workflow_s_remove(&S, &n)) {
			for (k = 0; k < workflow->tasks_num; k++)
				workflow_node_free(&(graph[k]));
			free(graph);
			graph = NULL;
			workflow_s_nodes_free(&S);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error removing node from S\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		//          for each node m with an edge e from n to m do
		for (i = 0; i < n->out_edges_size; i++) {
			if (n->out_edges[i] != -1) {
				//              remove edge e from the graph
				int index = n->out_edges[i];
				n->out_edges[i] = -1;
				n->out_edges_num--;
				for (j = 0; j < graph[index].in_edges_size; j++) {
					if (graph[index].in_edges[j] == n->index) {
						graph[index].in_edges[j] = -1;
						graph[index].in_edges_num--;
						//              if m has no other incoming edges then
						if (graph[index].in_edges_num == 0) {
							//                  insert m into S
							if (workflow_s_add(&S, &(graph[index]))) {
								for (k = 0; k < workflow->tasks_num; k++)
									workflow_node_free(&(graph[k]));
								free(graph);
								graph = NULL;
								workflow_s_nodes_free(&S);
								pmesg(LOG_ERROR, __FILE__, __LINE__, "Error adding a node to S\n");
								return OPH_WORKFLOW_EXIT_GENERIC_ERROR;
							}
						}
						break;
					}
				}
			}
		}
	}

	for (i = 0; i < workflow->tasks_num; i++) {
		//      if graph has edges then
		if (graph[i].in_edges_num != 0 || graph[i].out_edges_num != 0) {
			for (k = 0; k < workflow->tasks_num; k++)
				workflow_node_free(&(graph[k]));
			free(graph);
			graph = NULL;
			workflow_s_nodes_free(&S);
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Graph is not a DAG!\n");
			//          return error (graph has at least one cycle)
			return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
		}
	}

	for (k = 0; k < workflow->tasks_num; k++)
		workflow_node_free(&(graph[k]));
	free(graph);
	graph = NULL;
	workflow_s_nodes_free(&S);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_init(oph_workflow_task * tasks, int tasks_num, int **initial_tasks_indexes, int *initial_tasks_indexes_num)
{
	if (!tasks || tasks_num < 1 || !initial_tasks_indexes || !initial_tasks_indexes_num) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	(*initial_tasks_indexes) = NULL;
	(*initial_tasks_indexes_num) = 0;

	int i;
	for (i = 0; i < tasks_num; i++)
		if (tasks[i].deps_num < 1)
			(*initial_tasks_indexes_num)++;

	if ((*initial_tasks_indexes_num) == 0) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "There must be at least 1 independent task!\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	(*initial_tasks_indexes) = (int *) calloc((*initial_tasks_indexes_num), sizeof(int));
	if (!(*initial_tasks_indexes)) {
		(*initial_tasks_indexes_num) = 0;
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating initial tasks indexes\n");
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}

	int j = 0;
	for (i = 0; i < tasks_num; i++) {
		if (tasks[i].deps_num < 1) {
			(*initial_tasks_indexes)[j] = i;
			j++;
			if (j == (*initial_tasks_indexes_num))
				break;
		}
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_gparent_of(oph_workflow * wf, int k)
{
	if (k < 0)
		return -2;
	int p = wf->tasks[k].parent;
	if (p < 0)
		return -2;
	do {
		k = p;
		p = wf->tasks[k].parent;
	}
	while (p >= 0);
	return k;
}

// Other internal functions

int workflow_s_add(workflow_s_nodes * s, workflow_node * node)
{
	if (!s || !node) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	if (s->tail) {
		workflow_s_node *s_node = (workflow_s_node *) calloc(1, sizeof(workflow_s_node));
		if (!s_node) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating s_node\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		s_node->node = node;
		s_node->next = NULL;
		s->tail->next = s_node;
		s->tail = s_node;
		s->nodes_num++;
	} else {
		workflow_s_node *s_node = (workflow_s_node *) calloc(1, sizeof(workflow_s_node));
		if (!s_node) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Error allocating s_node\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		s_node->node = node;
		s_node->next = NULL;
		s->head = s_node;
		s->tail = s_node;
		s->nodes_num++;
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int workflow_s_remove(workflow_s_nodes * s, workflow_node ** node)
{
	if (!s || !node) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	if (s->head) {
		*node = s->head->node;
	} else {
		*node = NULL;
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Empty list!\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	workflow_s_node *tmp = s->head->next;
	free(s->head);
	s->head = tmp;
	if (tmp == NULL)
		s->tail = NULL;
	s->nodes_num--;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int workflow_s_nodes_free(workflow_s_nodes * s)
{
	if (!s)
		return OPH_WORKFLOW_EXIT_SUCCESS;
	workflow_s_node *tmp = NULL;
	workflow_s_node *ptr = s->head;
	while (ptr) {
		tmp = ptr->next;
		free(ptr);
		ptr = tmp;
	}
	s->head = NULL;
	s->tail = NULL;
	s->nodes_num = 0;
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int workflow_node_free(workflow_node * node)
{
	if (!node)
		return OPH_WORKFLOW_EXIT_SUCCESS;
	if (node->in_edges) {
		free(node->in_edges);
		node->in_edges = NULL;
		node->in_edges_num = 0;
		node->in_edges_size = 0;
	}
	if (node->out_edges) {
		free(node->out_edges);
		node->out_edges = NULL;
		node->out_edges_num = 0;
		node->out_edges_size = 0;
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_is_child_of(oph_workflow * wf, int p, int c)
{
	if (!wf || (p >= wf->tasks_num) || (c < 0) || (c >= wf->tasks_num))
		return 0;
	if ((p < 0) || (p == c))
		return 1;
	int i, j;
	for (i = 0; i < wf->tasks[p].dependents_indexes_num; ++i) {
		j = wf->tasks[p].dependents_indexes[i];
		if ((j != p) && oph_workflow_is_child_of(wf, j, c))
			return 1;
	}
	return 0;
}

unsigned int workflow_number_of(oph_workflow * wf, int k, int p, int gp, const char *op, const char *nop, char *flag, char *level, int bracket_number, int *child)
{
	if (!wf || (k < 0) || (k >= wf->tasks_num))
		return 0;
	int i, j, res = 0, bn;
	for (i = 0; i < wf->tasks[k].dependents_indexes_num; ++i) {
		j = wf->tasks[k].dependents_indexes[i];
		bn = bracket_number;
		if (level[j] < bn + level[p])
			level[j] = bn + level[p];
		if (!strncasecmp(wf->tasks[j].operator, (bracket_number > 0) && strcmp(nop, OPH_OPERATOR_FOR) ? OPH_OPERATOR_ENDIF : op, OPH_WORKFLOW_MAX_STRING))	// Found an "end-task"
		{
			if (level[j] > bn + level[p])
				bn = level[j] - level[p];
			if (bn)
				res += workflow_number_of(wf, j, p, gp, op, nop, flag, level, bn - 1, child);
			else if (flag[j]) {
				res++;
				flag[j] = 0;	// Mark this task in order to avoid to count it more times
				if ((wf->tasks[j].parent < 0) || (wf->tasks[j].parent == p)) {
					wf->tasks[j].parent = p;
					wf->tasks[p].child = j;
					if (child)
						*child = j;
				} else if ((wf->tasks[j].parent != p) && (wf->tasks[j].parent != gp))
					res++;	// Performance improvement
				wf->tasks[j].branch_num++;
			}
		} else {
			char tmp[1 + strlen(nop)], check = 0;
			strcpy(tmp, nop);
			char *save_pointer = NULL, *pch = strtok_r(tmp, OPH_WORKFLOW_OP_SEPARATOR, &save_pointer);
			while (pch) {
				if (!strncasecmp(wf->tasks[j].operator, pch, OPH_WORKFLOW_MAX_STRING)) {
					check = 1;
					break;
				}
				pch = strtok_r(NULL, OPH_WORKFLOW_OP_SEPARATOR, &save_pointer);
			}
			if (check) {
				bn++;
				if (wf->tasks[p].nesting_level < bn)
					wf->tasks[p].nesting_level = bn;
				if (level[j] < bn + level[p])
					level[j] = bn + level[p];
			}
			res += workflow_number_of(wf, j, p, gp, op, nop, flag, level, bn, child);
		}
		if (res > 1)
			break;	// Performance improvement
	}
	return res;
}

int oph_workflow_validate_fco(oph_workflow * wf)
{
	if (!wf) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null pointer!\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	int i, k, kk, child;
	char flag[wf->tasks_num];
	char level[wf->tasks_num];
	unsigned int number;

	for (k = 0; k < wf->tasks_num; k++) {
		wf->tasks[k].parent = wf->tasks[k].child = -1;
		wf->tasks[k].branch_num = wf->tasks[k].nesting_level = 0;
		level[k] = 0;
	}

	for (k = 0; k < wf->tasks_num; k++) {
		if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_FOR, OPH_WORKFLOW_MAX_STRING)) {
			for (i = 0; i < wf->tasks_num; ++i)
				flag[i] = 1;
			number = workflow_number_of(wf, k, k, k, OPH_OPERATOR_ENDFOR, OPH_OPERATOR_FOR, flag, level, 0, &child);
			if (!number || (number > 1)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDFOR,
				      wf->tasks[k].name);
				break;
			}
			for (i = 0; i < wf->tasks_num; ++i)
				if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ENDFOR, OPH_WORKFLOW_MAX_STRING) && !oph_workflow_is_child_of(wf, i, child))
					break;
			if (i < wf->tasks_num) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDFOR);
				break;
			}
		} else if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_IF, OPH_WORKFLOW_MAX_STRING)) {
			for (i = 0; i < wf->tasks_num; ++i)
				flag[i] = 1;
			child = -1;
			number = workflow_number_of(wf, k, k, k, OPH_OPERATOR_ELSEIF, OPH_OPERATOR_IF, flag, level, 0, &child);
			if (number > 1) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
				      wf->tasks[k].name);
				break;
			}
			if (child >= 0) {
				for (i = 0; i < wf->tasks_num; ++i)
					if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSEIF, OPH_WORKFLOW_MAX_STRING) && !oph_workflow_is_child_of(wf, i, child))
						break;
				if (i < wf->tasks_num) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
					break;
				}
			} else {
				for (i = 0; i < wf->tasks_num; ++i)
					flag[i] = 1;
				child = -1;
				number = workflow_number_of(wf, k, k, k, OPH_OPERATOR_ELSE, OPH_OPERATOR_IF, flag, level, 0, &child);
				if (number > 1) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
					      wf->tasks[k].name);
					break;
				}
				if (child >= 0) {
					for (i = 0; i < wf->tasks_num; ++i)
						if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSE, OPH_WORKFLOW_MAX_STRING)
						    && !oph_workflow_is_child_of(wf, i, child))
							break;
					if (i < wf->tasks_num) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
						break;
					}
				}
			}
			for (i = 0; i < wf->tasks_num; ++i)
				flag[i] = 1;
			number = workflow_number_of(wf, k, k, k, OPH_OPERATOR_ENDIF, OPH_OPERATOR_IF, flag, level, 0, &child);
			if (!number && (number > 1)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
				      wf->tasks[k].name);
				break;
			}
			for (i = 0; i < wf->tasks_num; ++i)
				if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ENDIF, OPH_WORKFLOW_MAX_STRING) && !oph_workflow_is_child_of(wf, i, child))
					break;
			if (i < wf->tasks_num) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
				break;
			}
		} else if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSEIF, OPH_WORKFLOW_MAX_STRING)) {
			kk = oph_gparent_of(wf, k);
			for (i = 0; i < wf->tasks_num; ++i)
				flag[i] = 1;
			child = -1;
			number = workflow_number_of(wf, k, k, kk, OPH_OPERATOR_ELSEIF, OPH_OPERATOR_IF, flag, level, 0, &child);
			if (number > 1) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
				      wf->tasks[k].name);
				break;
			}
			if (child >= 0) {
				for (i = 0; i < wf->tasks_num; ++i)
					if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSEIF, OPH_WORKFLOW_MAX_STRING) && !oph_workflow_is_child_of(wf, i, child))
						break;
				if (i < wf->tasks_num) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
					break;
				}
			} else {
				for (i = 0; i < wf->tasks_num; ++i)
					flag[i] = 1;
				child = -1;
				number = workflow_number_of(wf, k, k, kk, OPH_OPERATOR_ELSE, OPH_OPERATOR_IF, flag, level, 0, &child);
				if (number > 1) {
					pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
					      wf->tasks[k].name);
					break;
				}
				if (child >= 0) {
					for (i = 0; i < wf->tasks_num; ++i)
						if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSE, OPH_WORKFLOW_MAX_STRING)
						    && !oph_workflow_is_child_of(wf, i, child))
							break;
					if (i < wf->tasks_num) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
						break;
					}
				} else {
					for (i = 0; i < wf->tasks_num; ++i)
						flag[i] = 1;
					number = workflow_number_of(wf, k, k, kk, OPH_OPERATOR_ENDIF, OPH_OPERATOR_IF, flag, level, 0, &child);
					if (!number || (number > 1)) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
						      wf->tasks[k].name);
						break;
					}
					for (i = 0; i < wf->tasks_num; ++i)
						if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ENDIF, OPH_WORKFLOW_MAX_STRING)
						    && !oph_workflow_is_child_of(wf, i, child))
							break;
					if (i < wf->tasks_num) {
						pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
						break;
					}
				}
			}
		} else if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSE, OPH_WORKFLOW_MAX_STRING)) {
			kk = oph_gparent_of(wf, k);
			for (i = 0; i < wf->tasks_num; ++i)
				flag[i] = 1;
			number = workflow_number_of(wf, k, k, kk, OPH_OPERATOR_ENDIF, OPH_OPERATOR_IF, flag, level, 0, &child);
			if (!number || (number > 1)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found %s%d ways to reach '%s' corresponding to '%s'.\n", number ? "at least " : "", number, OPH_OPERATOR_ENDIF,
				      wf->tasks[k].name);
				break;
			}
			for (i = 0; i < wf->tasks_num; ++i)
				if ((wf->tasks[i].parent == k) && strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ENDIF, OPH_WORKFLOW_MAX_STRING) && !oph_workflow_is_child_of(wf, i, child))
					break;
			if (i < wf->tasks_num) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found a wrong correspondence between '%s' and '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_ENDIF);
				break;
			}
		}
	}
	if (k < wf->tasks_num) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Flow control operator '%s' is not set correctly!\n", wf->tasks[k].name);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	for (k = 0; k < wf->tasks_num; k++)
		if (wf->tasks[k].parent < 0) {
			if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ENDFOR, OPH_WORKFLOW_MAX_STRING)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found '%s' without '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_FOR);
				break;
			} else if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSEIF, OPH_WORKFLOW_MAX_STRING)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found '%s' without '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_IF);
				break;
			} else if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ELSE, OPH_WORKFLOW_MAX_STRING)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found '%s' without '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_IF);
				break;
			} else if (!strncasecmp(wf->tasks[k].operator, OPH_OPERATOR_ENDIF, OPH_WORKFLOW_MAX_STRING)) {
				pmesg(LOG_DEBUG, __FILE__, __LINE__, "Found '%s' without '%s'.\n", wf->tasks[k].name, OPH_OPERATOR_IF);
				break;
			}
		}
	if (k < wf->tasks_num) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Flow control operator '%s' is not set correctly!\n", wf->tasks[k].name);
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_set_basic_var(oph_workflow * wf)
{
	if (!wf) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Null param\n");
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	}

	oph_workflow_var var;
	var.caller = -1;	// Don't care

	int i;
	char *key[OPH_WORKFLOW_MIN_STRING] = OPH_WORKFLOW_BVAR_KEYS;
	void *var_buffer;
	size_t var_size = sizeof(oph_workflow_var), svalue_size;
	for (i = 0; i < OPH_WORKFLOW_BVAR_KEYS_SIZE; ++i) {
		var.svalue = NULL;
		switch (i) {
			case 0:
				var.svalue = strdup(wf->sessionid ? wf->sessionid : "none");
				break;
			case 1:
				if (wf->sessionid) {
					char session_code[OPH_WORKFLOW_MAX_STRING];
					if (oph_get_session_code(wf->sessionid, session_code))
						pmesg(LOG_ERROR, __FILE__, __LINE__, "Unable to get session code\n");
					else
						var.svalue = strdup(session_code);
				}
				break;
			case 2:
				if (wf->sessionid) {
					var.svalue = (char *) calloc(OPH_WORKFLOW_MIN_STRING, sizeof(char));
					if (var.svalue)
						snprintf(var.svalue, OPH_WORKFLOW_MIN_STRING, "%d", wf->workflowid);
				}
				break;
			case 3:
				var.svalue = strdup(oph_server_host ? oph_server_host : "none");
				break;
			case 4:
				var.svalue = strdup(oph_server_port ? oph_server_port : "none");
				break;
			case 5:
				var.svalue = strdup(wf->username ? wf->username : "none");
				break;
			case 6:
				var.svalue = strdup(wf->password ? wf->password : "none");
				break;
			case 7:
				var.svalue = strdup(wf->os_username ? wf->os_username : "none");
				break;
			default:
				pmesg(LOG_WARNING, __FILE__, __LINE__, "No basic key available at index %d for workflow '%s'.\n", i, wf->name);
				var.svalue = strdup("");
		}
		if (!var.svalue) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		svalue_size = strlen(var.svalue) + 1;
		var_buffer = malloc(var_size + svalue_size);
		if (!var_buffer) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory error\n");
			free(var.svalue);
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
		memcpy(var_buffer, (void *) &var, var_size);
		memcpy(var_buffer + var_size, var.svalue, svalue_size);
		if (hashtbl_insert_with_size(wf->vars, key[i], var_buffer, var_size + svalue_size))
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Unable to store variable '%s' in environment of workflow '%s'. Maybe it already exists.\n", key[i], wf->name);
		else
			pmesg(LOG_DEBUG, __FILE__, __LINE__, "Added variable '%s=%s' in environment of workflow '%s'.\n", key[i],
			      strcmp(key[i], OPH_WORKFLOW_BVAR_HIDDEN_KEY) ? var.svalue : OPH_WORKFLOW_BVAR_HIDDEN_VALUE, wf->name);
		free(var.svalue);
		free(var_buffer);
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}
