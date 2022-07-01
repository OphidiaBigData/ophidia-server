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

#include "oph_trash.h"

#include <stdlib.h>
#include <string.h>

int oph_trash_create(oph_trash ** trash)
{
	if (!trash)
		return OPH_TRASH_ERROR;
	*trash = (oph_trash *) malloc(sizeof(oph_trash));	// Main
	if (!(*trash))
		return OPH_TRASH_ERROR;
	(*trash)->trash = NULL;
	return OPH_TRASH_OK;
}

int oph_trash_destroy(oph_trash * trash)
{
	if (!trash)
		return OPH_TRASH_ERROR;
	oph_trash_node *tmp, *next;
	oph_trash_item *itmp, *inext;
	for (tmp = trash->trash; tmp; tmp = next) {
		next = tmp->next;
		if (tmp->key)
			free(tmp->key);	// Key
		for (itmp = tmp->head; itmp; itmp = inext) {
			inext = itmp->next;
			free(itmp);	// Item
		}
		free(tmp);	// Node
	}
	free(trash);		// Main
	return OPH_TRASH_OK;
}

int oph_trash_append(oph_trash * trash, const char *key, int item)
{
	if (!trash)
		return OPH_TRASH_ERROR;

	oph_trash_item *itmp = (oph_trash_item *) malloc(sizeof(oph_trash_item));	// Item
	if (!itmp)
		return OPH_TRASH_ERROR;
	itmp->item = item;
	itmp->next = NULL;

	oph_trash_node *tmp;
	for (tmp = trash->trash; tmp; tmp = tmp->next)
		if (!key || !strcmp(tmp->key, key))
			break;
	if (!tmp) {
		tmp = (oph_trash_node *) malloc(sizeof(oph_trash_node));	// Node
		if (!tmp)
			return OPH_TRASH_ERROR;
		if (key) {
			tmp->key = strdup(key);	// Key
			if (!tmp->key) {
				free(tmp);	// Node
				return OPH_TRASH_ERROR;
			}
		} else
			tmp->key = NULL;
		tmp->head = tmp->tail = NULL;
		tmp->next = trash->trash ? trash->trash->next : NULL;
		trash->trash = tmp;
	}

	if (tmp->tail)
		tmp->tail->next = itmp;
	else
		tmp->head = itmp;
	tmp->tail = itmp;

	return OPH_TRASH_OK;
}

int oph_trash_extract(oph_trash * trash, const char *key, int *item)
{
	if (!trash || !item)
		return OPH_TRASH_ERROR;
	*item = 0;

	oph_trash_node *tmp, *prev = NULL;
	for (tmp = trash->trash; tmp; tmp = tmp->next) {
		if (!key || !strcmp(tmp->key, key))
			break;
		prev = tmp;
	}
	if (!tmp || !tmp->head)
		return OPH_TRASH_ERROR;

	*item = tmp->head->item;
	oph_trash_item *next = tmp->head->next;

	free(tmp->head);	// Item

	if (tmp->head == tmp->tail)	// Only one item
	{
		if (tmp->key)
			free(tmp->key);	// Key
		if (prev)
			prev->next = tmp->next;
		else
			trash->trash = tmp->next;
		free(tmp);	// Node
	} else
		tmp->head = next;	// More items

	return OPH_TRASH_OK;
}

int oph_trash_order(oph_trash * trash, const char *key)
{
	if (!trash)
		return OPH_TRASH_ERROR;

	oph_trash_node *tmp;
	oph_trash_item *temp, *next;
	for (tmp = trash->trash; tmp; tmp = tmp->next)
		if (!key || !strcmp(tmp->key, key))
			break;
	if (!tmp)
		return OPH_TRASH_ERROR;

	int swap;
	do {
		swap = 0;
		for (temp = tmp->head; temp && temp->next; temp = next) {
			next = temp->next;
			if (temp->item > next->item) {
				swap = temp->item;
				temp->item = next->item;
				next->item = swap;
			}
		}
	} while (swap);

	return OPH_TRASH_OK;
}

int oph_trash_size(oph_trash * trash, const char *key, unsigned int *size)
{
	if (!trash || !size)
		return OPH_TRASH_ERROR;
	*size = 0;

	oph_trash_node *tmp;
	for (tmp = trash->trash; tmp; tmp = tmp->next)
		if (!key || !strcmp(tmp->key, key))
			break;
	if (!tmp || !tmp->head)
		return OPH_TRASH_ERROR;

	oph_trash_item *temp;
	for (temp = tmp->head; temp; temp = temp->next)
		++ * size;

	return OPH_TRASH_OK;
}
