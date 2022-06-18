#ifndef QUEUE_H
#define QUEUE_H

#include "util.h"

#include <stddef.h>
#include <stdbool.h>

struct queue;

struct queue *queue_new(size_t buf_size, size_t capacity);
void queue_free(struct queue * /*q*/);

bool queue_push(struct queue * /*q*/, const char * /*data*/, size_t /*len*/,
		struct sockaddr /*to*/);
char *queue_peek(struct queue * /*q*/, size_t * /*len*/,
		 struct sockaddr * /*to*/);
bool queue_pop(struct queue * /*q*/);

bool queue_full(struct queue * /*q*/);
bool queue_empty(struct queue * /*q*/);

#endif /* QUEUE_H */
