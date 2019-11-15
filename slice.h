#ifndef SLICE_H
#define SLICE_H

#include "util.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

typedef struct {
	size_t cap, start, end;
	char *data;
} slice_t;

static inline slice_t slice_make(size_t cap)
{
	char *data = (char *)util_malloc(cap);
	if (data == NULL) {
		return (slice_t){ 0 };
	}
	return (slice_t){
		.cap = cap,
		.start = 0,
		.end = 0,
		.data = data,
	};
}

static inline slice_t slice_free(slice_t slice)
{
	if (slice.data) {
		util_free(slice.data);
	}
	return (slice_t){ 0 };
}

static inline size_t slice_len(slice_t s)
{
	assert(s.start <= s.end && s.end <= s.cap);
	return s.end - s.start;
}

#endif /* SLICE_H */
