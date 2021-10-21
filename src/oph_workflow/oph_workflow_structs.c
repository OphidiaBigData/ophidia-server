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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "oph_workflow_structs.h"


int oph_output_data_free(char **output, int num)
{
	int i;
	if (output) {
		for (i = 0; i < num; i++)
			free(output[i]);
		free(output);
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_free(oph_workflow * workflow)
{
	if (!workflow)
		return OPH_WORKFLOW_EXIT_SUCCESS;
	if (workflow->waiting_tasks_num) {
		if (workflow->waiting_tasks_num > 0)
			workflow->waiting_tasks_num = -workflow->waiting_tasks_num;
		return OPH_WORKFLOW_EXIT_SUCCESS;
	}
	int i;
	if (workflow->url) {
		free(workflow->url);
		workflow->url = NULL;
	}
	if (workflow->abstract) {
		free(workflow->abstract);
		workflow->abstract = NULL;
	}
	if (workflow->author) {
		free(workflow->author);
		workflow->author = NULL;
	}
	if (workflow->callback_url) {
		free(workflow->callback_url);
		workflow->callback_url = NULL;
	}
	if (workflow->host_partition) {
		free(workflow->host_partition);
		workflow->host_partition = NULL;
	}
	if (workflow->host_partition_orig) {
		free(workflow->host_partition_orig);
		workflow->host_partition_orig = NULL;
	}
	if (workflow->client_address) {
		free(workflow->client_address);
		workflow->client_address = NULL;
	}
	if (workflow->new_token) {
		free(workflow->new_token);
		workflow->new_token = NULL;
	}
	if (workflow->project) {
		free(workflow->project);
		workflow->project = NULL;
	}
	if (workflow->cube) {
		free(workflow->cube);
		workflow->cube = NULL;
	}
	if (workflow->cwd) {
		free(workflow->cwd);
		workflow->cwd = NULL;
	}
	if (workflow->cdd) {
		free(workflow->cdd);
		workflow->cdd = NULL;
	}
	if (workflow->exec_mode) {
		free(workflow->exec_mode);
		workflow->exec_mode = NULL;
	}
	if (workflow->name) {
		free(workflow->name);
		workflow->name = NULL;
	}
	if (workflow->sessionid) {
		free(workflow->sessionid);
		workflow->sessionid = NULL;
	}
	if (workflow->username) {
		free(workflow->username);
		workflow->username = NULL;
	}
	if (workflow->password) {
		free(workflow->password);
		workflow->password = NULL;
	}
	if (workflow->os_username) {
		free(workflow->os_username);
		workflow->os_username = NULL;
	}
	if (workflow->ip_address) {
		free(workflow->ip_address);
		workflow->ip_address = NULL;
	}
	if (workflow->tasks_num) {
		for (i = 0; i <= workflow->tasks_num; i++) {
			oph_workflow_task_free(&(workflow->tasks[i]));
		}
		free(workflow->tasks);
		workflow->tasks = NULL;
	}
	if (workflow->response) {
		free(workflow->response);
		workflow->response = NULL;
	}
	if (workflow->command) {
		free(workflow->command);
		workflow->command = NULL;
	}
	if (workflow->on_error) {
		free(workflow->on_error);
		workflow->on_error = NULL;
	}
	if (workflow->on_exit) {
		free(workflow->on_exit);
		workflow->on_exit = NULL;
	}
	if (workflow->checkpoint) {
		free(workflow->checkpoint);
		workflow->checkpoint = NULL;
	}
	if (workflow->exit_cubes) {
		oph_trash_destroy(workflow->exit_cubes);
		workflow->exit_cubes = NULL;
	}
	if (workflow->exit_containers) {
		oph_trash_destroy(workflow->exit_containers);
		workflow->exit_containers = NULL;
	}
	oph_workflow_task_out *tmp = NULL;
	while (workflow->output) {
		tmp = workflow->output->next;
		if (workflow->output->name) {
			free(workflow->output->name);
			workflow->output->name = NULL;
		}
		if (workflow->output->light_task_outs) {
			for (i = 0; i < workflow->output->light_tasks_num; i++)
				if (workflow->output->light_task_outs[i].response) {
					free(workflow->output->light_task_outs[i].response);
					workflow->output->light_task_outs[i].response = NULL;
				}
			free(workflow->output->light_task_outs);
			workflow->output->light_task_outs = NULL;
		}
		if (workflow->output->response) {
			free(workflow->output->response);
			workflow->output->response = NULL;
		}
		free(workflow->output);
		workflow->output = tmp;
	}
	if (workflow->vars) {
		hashtbl_destroy(workflow->vars);
		workflow->vars = NULL;
	}
	while (workflow->stack && !oph_workflow_pop(workflow, NULL));
	free(workflow);
	workflow = NULL;
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_task_free(oph_workflow_task * task)
{
	if (!task)
		return OPH_WORKFLOW_EXIT_SUCCESS;
	int i;
	if (task->arguments_num) {
		for (i = 0; i < task->arguments_num; i++) {
			if (task->arguments_keys[i]) {
				free(task->arguments_keys[i]);
				task->arguments_keys[i] = NULL;
			}
			if (task->arguments_values[i]) {
				free(task->arguments_values[i]);
				task->arguments_values[i] = NULL;
			}
			if (task->arguments_lists[i]) {
				oph_workflow_free_list(task->arguments_lists[i]);
				task->arguments_lists[i] = NULL;
			}
		}
		free(task->arguments_keys);
		task->arguments_keys = NULL;
		free(task->arguments_values);
		task->arguments_values = NULL;
		free(task->arguments_lists);
		task->arguments_lists = NULL;
	}
	if (task->dependents_indexes_num) {
		free(task->dependents_indexes);
		task->dependents_indexes = NULL;
	}
	if (task->deps_num) {
		for (i = 0; i < task->deps_num; i++) {
			oph_workflow_dep_free(&(task->deps[i]));
		}
		free(task->deps);
		task->deps = NULL;
	}
	if (task->light_tasks_num) {
		for (i = 0; i < task->light_tasks_num; i++) {
			oph_workflow_light_task_free(&(task->light_tasks[i]));
		}
		free(task->light_tasks);
		task->light_tasks = NULL;
	}
	if (task->name) {
		free(task->name);
		task->name = NULL;
	}
	if (task->operator) {
		free(task->operator);
		task->operator= NULL;
	}
	if (task->type) {
		free(task->type);
		task->type = NULL;
	}
	if (task->rtype) {
		free(task->rtype);
		task->rtype = NULL;
	}
	if (task->outputs_num) {
		for (i = 0; i < task->outputs_num; i++) {
			if (task->outputs_keys[i]) {
				free(task->outputs_keys[i]);
				task->outputs_keys[i] = NULL;
			}
			if (task->outputs_values[i]) {
				free(task->outputs_values[i]);
				task->outputs_values[i] = NULL;
			}
		}
		free(task->outputs_keys);
		task->outputs_keys = NULL;
		free(task->outputs_values);
		task->outputs_values = NULL;
	}
	if (task->response) {
		free(task->response);
		task->response = NULL;
	}
	if (task->vars) {
		hashtbl_destroy(task->vars);
		task->vars = NULL;
	}
	if (task->on_error) {
		free(task->on_error);
		task->on_error = NULL;
	}
	if (task->on_exit) {
		free(task->on_exit);
		task->on_exit = NULL;
	}
	if (task->checkpoint) {
		free(task->checkpoint);
		task->checkpoint = NULL;
	}
	if (task->query) {
		free(task->query);
		task->query = NULL;
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_dep_free(oph_workflow_dep * dep)
{
	if (!dep)
		return OPH_WORKFLOW_EXIT_SUCCESS;
	if (dep->argument) {
		free(dep->argument);
		dep->argument = NULL;
	}
	if (dep->filter) {
		free(dep->filter);
		dep->filter = NULL;
	}
	if (dep->order) {
		free(dep->order);
		dep->order = NULL;
	}
	if (dep->output_argument) {
		free(dep->output_argument);
		dep->output_argument = NULL;
	}
	if (dep->output_order) {
		free(dep->output_order);
		dep->output_order = NULL;
	}
	if (dep->task_name) {
		free(dep->task_name);
		dep->task_name = NULL;
	}
	if (dep->type) {
		free(dep->type);
		dep->type = NULL;
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_light_task_free(oph_workflow_light_task * light_task)
{
	if (!light_task)
		return OPH_WORKFLOW_EXIT_SUCCESS;
	int i;
	if (light_task->arguments_num) {
		for (i = 0; i < light_task->arguments_num; i++) {
			if (light_task->arguments_keys[i]) {
				free(light_task->arguments_keys[i]);
				light_task->arguments_keys[i] = NULL;
			}
			if (light_task->arguments_values[i]) {
				free(light_task->arguments_values[i]);
				light_task->arguments_values[i] = NULL;
			}
		}
		free(light_task->arguments_keys);
		light_task->arguments_keys = NULL;
		free(light_task->arguments_values);
		light_task->arguments_values = NULL;
	}
	if (light_task->response) {
		free(light_task->response);
		light_task->response = NULL;
	}
	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_save_task_output(oph_workflow_task * task, oph_workflow_task_out ** task_out)
{
	if (!task || !task_out)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	*task_out = (oph_workflow_task_out *) malloc(sizeof(oph_workflow_task_out));
	if (!(*task_out))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	(*task_out)->name = strdup(task->name);
	(*task_out)->markerid = task->markerid;
	(*task_out)->status = task->status;
	(*task_out)->light_tasks_num = task->light_tasks_num;
	(*task_out)->response = task->response ? strdup(task->response) : NULL;	// The copy is used for oph_set
	(*task_out)->next = NULL;

	if (task->light_tasks_num) {
		(*task_out)->light_task_outs = (oph_workflow_light_task_out *) malloc(task->light_tasks_num * sizeof(oph_workflow_light_task_out));
		if (!((*task_out)->light_task_outs)) {
			free(*task_out);
			*task_out = NULL;
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}

		int i;
		for (i = 0; i < task->light_tasks_num; ++i) {
			(*task_out)->light_task_outs[i].markerid = task->light_tasks[i].markerid;
			(*task_out)->light_task_outs[i].status = task->light_tasks[i].status;
			(*task_out)->light_task_outs[i].response = task->light_tasks[i].response;	// No copy for oph_set!!!
			task->light_tasks[i].response = NULL;
		}
	} else
		(*task_out)->light_task_outs = NULL;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_push(oph_workflow * workflow, int caller, char *name, char **svalues, int *ivalues, int values_num)
{
	if (!workflow || !name || (values_num <= 0))
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	oph_workflow_stack *tmp = (oph_workflow_stack *) malloc(sizeof(oph_workflow_stack));
	if (!tmp)
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	tmp->tasks_num = workflow->tasks_num;
	if (workflow->tasks_num) {
		tmp->tasks = (oph_workflow_stack_task *) malloc(workflow->tasks_num * sizeof(oph_workflow_stack_task));
		if (!tmp->tasks)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

		int i, j;
		for (i = 0; i < workflow->tasks_num; ++i) {
			tmp->tasks[i].arguments_num = workflow->tasks[i].arguments_num;
			if (workflow->tasks[i].arguments_num) {
				tmp->tasks[i].arguments_keys = (char **) malloc(workflow->tasks[i].arguments_num * sizeof(char *));
				tmp->tasks[i].arguments_values = (char **) malloc(workflow->tasks[i].arguments_num * sizeof(char *));
				tmp->tasks[i].arguments_lists = (oph_workflow_ordered_list **) malloc(workflow->tasks[i].arguments_num * sizeof(oph_workflow_ordered_list *));
				for (j = 0; j < workflow->tasks[i].arguments_num; ++j) {
					tmp->tasks[i].arguments_keys[j] = strdup(workflow->tasks[i].arguments_keys[j]);
					tmp->tasks[i].arguments_values[j] = strdup(workflow->tasks[i].arguments_values[j]);
					tmp->tasks[i].arguments_lists[j] = oph_workflow_copy_list(workflow->tasks[i].arguments_lists[j]);
				}
			} else {
				tmp->tasks[i].arguments_keys = NULL;
				tmp->tasks[i].arguments_values = NULL;
				tmp->tasks[i].arguments_lists = NULL;
			}
			tmp->tasks[i].deps_num = workflow->tasks[i].deps_num;
			if (workflow->tasks[i].deps_num) {
				tmp->tasks[i].deps_task_index = (int *) malloc(workflow->tasks[i].deps_num * sizeof(int));
				for (j = 0; j < workflow->tasks[i].deps_num; ++j)
					tmp->tasks[i].deps_task_index[j] = workflow->tasks[i].deps[j].task_index;
			} else
				tmp->tasks[i].deps_task_index = NULL;
			tmp->tasks[i].residual_deps_num = workflow->tasks[i].residual_deps_num;
			tmp->tasks[i].dependents_indexes_num = workflow->tasks[i].dependents_indexes_num;
			if (workflow->tasks[i].dependents_indexes_num) {
				tmp->tasks[i].dependents_indexes = (int *) malloc(workflow->tasks[i].dependents_indexes_num * sizeof(int));
				for (j = 0; j < workflow->tasks[i].dependents_indexes_num; ++j)
					tmp->tasks[i].dependents_indexes[j] = workflow->tasks[i].dependents_indexes[j];
			} else
				tmp->tasks[i].dependents_indexes = NULL;
		}
	}

	tmp->caller = caller;
	tmp->index = 0;		// From 0 to values_num-1
	tmp->name = strdup(name);
	tmp->svalues = svalues;
	tmp->ivalues = ivalues;
	tmp->values_num = values_num;
	tmp->next = workflow->stack;
	workflow->stack = tmp;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_pop(oph_workflow * workflow, oph_workflow_stack * prev)
{
	if (!workflow)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	oph_workflow_stack *tmp = prev ? prev->next : workflow->stack;
	if (!tmp)
		return OPH_WORKFLOW_EXIT_SUCCESS;

	if (prev)
		prev->next = tmp->next;
	else
		workflow->stack = tmp->next;

	int i, j;
	if (tmp->tasks) {
		for (i = 0; i < tmp->tasks_num; ++i) {
			for (j = 0; j < tmp->tasks[i].arguments_num; ++j) {
				if (tmp->tasks[i].arguments_keys[j])
					free(tmp->tasks[i].arguments_keys[j]);
				if (tmp->tasks[i].arguments_values[j])
					free(tmp->tasks[i].arguments_values[j]);
				if (tmp->tasks[i].arguments_lists[j])
					oph_workflow_free_list(tmp->tasks[i].arguments_lists[j]);
			}
			if (tmp->tasks[i].arguments_keys)
				free(tmp->tasks[i].arguments_keys);
			if (tmp->tasks[i].arguments_values)
				free(tmp->tasks[i].arguments_values);
			if (tmp->tasks[i].arguments_lists)
				free(tmp->tasks[i].arguments_lists);
			if (tmp->tasks[i].deps_task_index)
				free(tmp->tasks[i].deps_task_index);
			if (tmp->tasks[i].dependents_indexes)
				free(tmp->tasks[i].dependents_indexes);
		}
		free(tmp->tasks);
	}
	if (tmp->name)
		free(tmp->name);
	if (tmp->svalues) {
		for (i = 0; i < tmp->values_num; ++i)
			if (tmp->svalues[i])
				free(tmp->svalues[i]);
		free(tmp->svalues);
	}
	if (tmp->ivalues)
		free(tmp->ivalues);
	free(tmp);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_expand(oph_workflow * wf, int tasks_num)
{
	if (!wf)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;
	if (tasks_num <= wf->tasks_num)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	oph_workflow_task *old_tasks = wf->tasks;
	int old_tasks_num = wf->tasks_num;

	wf->tasks = (oph_workflow_task *) calloc(tasks_num + 1, sizeof(oph_workflow_task));	// +1 is due to append an empty task at the end for a possible "Final task"
	if (!wf->tasks) {
		wf->tasks = old_tasks;
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	wf->tasks_num = wf->residual_tasks_num = tasks_num;

	memcpy(wf->tasks, old_tasks, old_tasks_num * sizeof(oph_workflow_task));
	memcpy(wf->tasks + wf->tasks_num, old_tasks + old_tasks_num, sizeof(oph_workflow_task));	// Copy the final task
	free(old_tasks);

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

int oph_workflow_copy_task(oph_workflow_task * s, oph_workflow_task * d, int suffix)
{
	if (!s || !d)
		return OPH_WORKFLOW_EXIT_BAD_PARAM_ERROR;

	int i;
	memcpy(d, s, sizeof(oph_workflow_task));
	if (s->name) {
		if (suffix >= 0) {
			size_t length = strlen(s->name) - 1;
			char tmp[length + OPH_WORKFLOW_MIN_STRING];
			if (s->name[length] == OPH_WORKFLOW_NAME_EXPANSION_END) {
				char *tmp2 = strdup(s->name);	// Don't change source task!
				tmp2[length] = 0;
				sprintf(tmp, OPH_WORKFLOW_NAME_EXPANSION2, tmp2, suffix);
				free(tmp2);
			} else
				sprintf(tmp, OPH_WORKFLOW_NAME_EXPANSION1, s->name, suffix);
			if (!((d->name = strdup(tmp))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		} else if (!((d->name = strdup(s->name))))
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (s->operator && ! ((d->operator = strdup(s->operator))))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	if (s->type && !((d->type = strdup(s->type))))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	if (s->rtype && !((d->rtype = strdup(s->rtype))))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	if (s->arguments_keys) {
		d->arguments_keys = (char **) calloc(s->arguments_num, sizeof(char *));
		if (!d->arguments_keys)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		for (i = 0; i < s->arguments_num; ++i)
			if (s->arguments_keys[i] && !((d->arguments_keys[i] = strdup(s->arguments_keys[i]))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (s->arguments_values) {
		d->arguments_values = (char **) calloc(s->arguments_num, sizeof(char *));
		if (!d->arguments_values)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		for (i = 0; i < s->arguments_num; ++i)
			if (s->arguments_values[i] && !((d->arguments_values[i] = strdup(s->arguments_values[i]))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (s->arguments_lists) {
		d->arguments_lists = (oph_workflow_ordered_list **) calloc(s->arguments_num, sizeof(oph_workflow_ordered_list *));
		if (!d->arguments_lists)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		for (i = 0; i < s->arguments_num; ++i)
			if (s->arguments_lists[i] && !((d->arguments_lists[i] = oph_workflow_copy_list(s->arguments_lists[i]))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	}
	if (s->deps) {
		d->deps = (oph_workflow_dep *) calloc(s->deps_num, sizeof(oph_workflow_dep));
		if (!d->deps)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		memcpy(d->deps, s->deps, s->deps_num * sizeof(oph_workflow_dep));
		for (i = 0; i < s->deps_num; ++i) {
			d->deps[i].task_name = NULL;
			if (s->deps[i].argument && !((d->deps[i].argument = strdup(s->deps[i].argument))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			if (s->deps[i].order && !((d->deps[i].order = strdup(s->deps[i].order))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			if (s->deps[i].type && !((d->deps[i].type = strdup(s->deps[i].type))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			if (s->deps[i].filter && !((d->deps[i].filter = strdup(s->deps[i].filter))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			if (s->deps[i].output_argument && !((d->deps[i].output_argument = strdup(s->deps[i].output_argument))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
			if (s->deps[i].output_order && !((d->deps[i].output_order = strdup(s->deps[i].output_order))))
				return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		}
	}
	if (s->dependents_indexes) {
		d->dependents_indexes = (int *) calloc(s->dependents_indexes_num, sizeof(int));
		if (!d->dependents_indexes)
			return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
		memcpy(d->dependents_indexes, s->dependents_indexes, s->dependents_indexes_num * sizeof(int));
	}
	if (s->vars && !((d->vars = hashtbl_duplicate(s->vars))))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	if (s->on_error && !((s->on_error = strdup(s->on_error))))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;
	if (s->on_exit && !((s->on_exit = strdup(s->on_exit))))
		return OPH_WORKFLOW_EXIT_MEMORY_ERROR;

	return OPH_WORKFLOW_EXIT_SUCCESS;
}

oph_workflow_ordered_list *oph_workflow_copy_list(oph_workflow_ordered_list * list)
{
	oph_workflow_ordered_list *c, *p = NULL, *result = NULL;

	while (list) {
		c = (oph_workflow_ordered_list *) malloc(sizeof(oph_workflow_ordered_list));
		c->key = list->key ? strdup(list->key) : NULL;
		c->object = list->object ? strdup(list->object) : NULL;
		c->next = NULL;
		if (!result)
			result = c;
		if (p)
			p->next = c;
		p = c;
		list = list->next;
	}

	return result;
}

int oph_workflow_free_list(oph_workflow_ordered_list * list)
{
	oph_workflow_ordered_list *c;

	while (list) {
		c = list;
		list = list->next;
		if (c->key)
			free(c->key);
		if (c->object)
			free(c->object);
		free(c);
	}

	return OPH_WORKFLOW_EXIT_SUCCESS;
}
