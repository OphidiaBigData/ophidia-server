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

#ifndef OPH_TRASH_H
#define OPH_TRASH_H

#define OPH_TRASH_OK 0
#define OPH_TRASH_ERROR 1

typedef struct _oph_trash_item {
	int item;
	struct _oph_trash_item *next;
} oph_trash_item;

typedef struct _oph_trash_node {
	char *key;
	oph_trash_item *head;
	oph_trash_item *tail;
	struct _oph_trash_node *next;
} oph_trash_node;

typedef struct _oph_trash {
	oph_trash_node *trash;
} oph_trash;

int oph_trash_create(oph_trash ** trash);
int oph_trash_destroy(oph_trash * trash);
int oph_trash_append(oph_trash * trash, const char *key, int item);
int oph_trash_extract(oph_trash * trash, const char *key, int *item);
int oph_trash_order(oph_trash * trash, const char *key);
int oph_trash_size(oph_trash * trash, const char *key, unsigned int *size);

#endif				/* OPH_TRASH_H */
