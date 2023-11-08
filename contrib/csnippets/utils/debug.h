/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include <stddef.h>

struct vbuffer;

struct vbuffer *
print_txt(struct vbuffer *vbuf, const char *indent, const void *data, size_t n);
struct vbuffer *
print_bin(struct vbuffer *vbuf, const char *indent, const void *data, size_t n);

#endif /* UTILS_DEBUG_H */
