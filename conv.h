#ifndef CONV_H
#define CONV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct conv_table;

struct conv_table *conv_table_create();
void conv_table_free(struct conv_table * /*table*/);

uint32_t conv_new(struct conv_table * /*table*/);
void conv_insert(struct conv_table * /*table*/, uint32_t /*conv*/,
		 void * /*session*/);
void conv_free(struct conv_table * /*table*/, uint32_t /*conv*/);
void *conv_find(struct conv_table * /*table*/, uint32_t /*conv*/);
size_t conv_size(struct conv_table * /*table*/);

typedef bool (*conv_iterate_cb)(struct conv_table * /*table*/,
				uint32_t /*conv*/, void * /*session*/,
				void * /*user*/, bool * /*delete*/);
void conv_iterate(struct conv_table * /*table*/, conv_iterate_cb /*f*/,
		  void * /*user*/);

#endif /* CONV_H */
