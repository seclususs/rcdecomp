/* RCDecomp Header */

#ifndef RCDECOMP_H
#define RCDECOMP_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct ContextDecompiler;

struct ContextDecompiler *create_contextDecompiler(void);

void free_contextDecompiler(struct ContextDecompiler *ctx_ptr);

int load_binaryFile(struct ContextDecompiler *ctx_ptr, const char *path_ptr);

#endif  /* RCDECOMP_H */
