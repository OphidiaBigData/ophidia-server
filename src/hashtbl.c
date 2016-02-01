/* The authors of this work have released all rights to it and placed it
in the public domain under the Creative Commons CC0 1.0 waiver
(http://creativecommons.org/publicdomain/zero/1.0/).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Retrieved from: http://en.literateprograms.org/Hash_table_(C)?oldid=19638
*/

#include "hashtbl.h"

#include <string.h>
#include <stdio.h>

static char *mystrdup(const char *s)
{
	char *b;
	if(!(b=malloc(strlen(s)+1))) return NULL;
	strcpy(b, s);
	return b;
}

static hash_size def_hashfunc(const char *key)
{
	hash_size hash=0;
	
	while(*key) hash+=(unsigned char)*key++;

	return hash;
}

HASHTBL *hashtbl_create(hash_size size, hash_size (*hashfunc)(const char *))
{
	HASHTBL *hashtbl;

	if(!(hashtbl=malloc(sizeof(HASHTBL)))) return NULL;

	if(!(hashtbl->nodes=calloc(size, sizeof(struct hashnode_s*)))) {
		free(hashtbl);
		return NULL;
	}

	hashtbl->size=size;

	if(hashfunc) hashtbl->hashfunc=hashfunc;
	else hashtbl->hashfunc=def_hashfunc;

	return hashtbl;
}

HASHTBL *hashtbl_duplicate(HASHTBL *h) // added
{
	HASHTBL *hashtbl;
	hash_size n;
	struct hashnode_s *node;

	if(!(hashtbl=malloc(sizeof(HASHTBL)))) return NULL;

	if(!(hashtbl->nodes=calloc(h->size, sizeof(struct hashnode_s*))))
	{
		free(hashtbl);
		return NULL;
	}

	hashtbl->size=h->size;
	hashtbl->hashfunc=h->hashfunc;

	// Copy data
	for(n=0; n<h->size; ++n)
	{
		for (node=h->nodes[n]; node; node=node->next) if (hashtbl_insert_with_size(hashtbl, node->key, node->data, node->size)) break;
		if (node) break;
	}
	if (n<h->size)
	{
		free(hashtbl);
		return NULL;
	}

	return hashtbl;
}

void hashtbl_destroy(HASHTBL *hashtbl)
{
	hash_size n;
	struct hashnode_s *node, *oldnode;
	
	for(n=0; n<hashtbl->size; ++n) {
		node=hashtbl->nodes[n];
		while(node) {
			free(node->key);
			free(node->data);  // added 
			oldnode=node;
			node=node->next;
			free(oldnode);
		}
	}
	free(hashtbl->nodes);
	free(hashtbl);
}

int hashtbl_insert(HASHTBL *hashtbl, const char *key, void *data)
{
	return hashtbl_insert_with_size(hashtbl, key, data, strlen((char*)data));
}

int hashtbl_insert_with_size(HASHTBL *hashtbl, const char *key, void *data, size_t size)
{
	struct hashnode_s *node;
	hash_size hash=hashtbl->hashfunc(key)%hashtbl->size;

	node=hashtbl->nodes[hash];
	while(node)
	{
		if(!strcmp(node->key, key)) return -1;
		node=node->next;
	}

	if(!(node=malloc(sizeof(struct hashnode_s)))) return -1;
	if(!(node->key=mystrdup(key))) {
		free(node);
		return -1;
	}
	//node->data=data;
       	node->data = malloc(size + 1); //added
	memcpy(node->data,data,size); // added
	*(char*)(node->data+size) = 0; // added

	node->size = size; // added

	node->next=hashtbl->nodes[hash];
	hashtbl->nodes[hash]=node;

	return 0;
}

int hashtbl_remove(HASHTBL *hashtbl, const char *key)
{
	struct hashnode_s *node, *prevnode=NULL;
	hash_size hash=hashtbl->hashfunc(key)%hashtbl->size;

	node=hashtbl->nodes[hash];
	while(node) {
		if(!strcmp(node->key, key)) {
			free(node->key);
			free(node->data); // added
			if(prevnode) prevnode->next=node->next;
			else hashtbl->nodes[hash]=node->next;
			free(node);
			return 0;
		}
		prevnode=node;
		node=node->next;
	}

	return -1;
}

void *hashtbl_get(HASHTBL *hashtbl, const char *key)
{
	struct hashnode_s *node;
	hash_size hash=hashtbl->hashfunc(key)%hashtbl->size;

	node=hashtbl->nodes[hash];
	while(node) {
		if(!strcmp(node->key, key)) return node->data;
		node=node->next;
	}

	return NULL;
}

int hashtbl_resize(HASHTBL *hashtbl, hash_size size)
{
	HASHTBL newtbl;
	hash_size n;
	struct hashnode_s *node,*next;

	newtbl.size=size;
	newtbl.hashfunc=hashtbl->hashfunc;

	if(!(newtbl.nodes=calloc(size, sizeof(struct hashnode_s*)))) return -1;

	for(n=0; n<hashtbl->size; ++n) {
		for(node=hashtbl->nodes[n]; node; node=next) {
			next = node->next;
			hashtbl_insert_with_size(&newtbl, node->key, node->data, node->size);
			hashtbl_remove(hashtbl, node->key);
			
		}
	}

	free(hashtbl->nodes);
	hashtbl->size=newtbl.size;
	hashtbl->nodes=newtbl.nodes;

	return 0;
}

int hashtbl_next(HASHTBL *hashtbl, char **key, void **data) // added
{
	if (!key || !data) return -1;

	int next_node=1;
	struct hashnode_s *node;
	hash_size hash=0;
	if (*key)
	{
		hash=hashtbl->hashfunc(*key)%hashtbl->size;
		node=hashtbl->nodes[hash];
		while(node) {
			if(!strcmp(node->key, *key)) break;
			node=node->next;
		}
		if (!node) return -1;
		node=node->next;
		next_node=0;
	}

	for (;hash<hashtbl->size;hash++)
	{
		if (next_node) node=hashtbl->nodes[hash];
		else next_node=1;
		if (node)
		{
			*key = node->key;
			*data  = node->data;
			return 0;
		}
	}

	return -1;
}

