#include "queue.h"

#include <assert.h>
#include <string.h>

#include <sys/socket.h>

struct buffer {
	char *data;
	size_t len;
};

struct node {
	struct buffer buf;
	struct sockaddr to;
	struct node *next;
};

struct queue {
	struct node *head, *tail;
	struct node *free;
	size_t buf_size;
	size_t size, capacity;
};

struct queue *queue_new(size_t buf_size, size_t capacity)
{
	struct queue *q = util_malloc(sizeof(struct queue));
	if (q == NULL) {
		return NULL;
	}
	*q = (struct queue){
		.head = NULL,
		.tail = NULL,
		.free = NULL,
		.buf_size = buf_size,
		.size = 0,
		.capacity = capacity,
	};
	return q;
}

static inline void free_list(struct node *head)
{
	struct node *p = head;
	while (p != NULL) {
		struct node *last = p;
		p = p->next;
		util_free(last);
	}
}

void queue_free(struct queue *restrict q)
{
	free_list(q->head);
	free_list(q->free);
	util_free(q);
}

static inline struct node *new_node(struct queue *restrict q)
{
	if (q->free != NULL) {
		struct node *n = q->free;
		q->free = n->next;
		return n;
	}
	if (q->size == q->capacity) {
		return NULL;
	}
	struct node *n = util_malloc(sizeof(struct node));
	if (n == NULL) {
		return NULL;
	}
	char *buf = util_malloc(q->buf_size);
	if (n == NULL) {
		util_free(n);
		return NULL;
	}
	n->buf.data = buf;
	return n;
}

bool queue_push(struct queue *restrict q, const char *data, size_t len,
		struct sockaddr to)
{
	assert(len <= q->buf_size);
	struct node *n = new_node(q);
	if (n == NULL) {
		return false;
	}
	memcpy(n->buf.data, data, len);
	n->to = to;
	n->buf.len = len;
	n->next = NULL;
	if (q->head == NULL) {
		q->head = n;
		q->tail = n;
	} else {
		q->tail->next = n;
		q->tail = n;
	}
	q->size++;
	return true;
}

char *queue_peek(struct queue *restrict q, size_t *len, struct sockaddr *to)
{
	struct node *restrict p = q->head;
	if (p == NULL) {
		return NULL;
	}
	*len = p->buf.len;
	*to = p->to;
	return p->buf.data;
}

bool queue_pop(struct queue *restrict q)
{
	struct node *restrict p = q->head;
	if (p == NULL) {
		return false;
	}
	q->head = p->next;
	p->next = q->free;
	q->free = p;
	q->size--;
	return true;
}

bool queue_full(struct queue *q)
{
	return q->size == q->capacity;
}

bool queue_empty(struct queue *q)
{
	return q->head == NULL;
}
