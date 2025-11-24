/* RCDecomp Header */

#ifndef RCDECOMP_H
#define RCDECOMP_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct ContextDecompiler;

struct ContextDecompiler *buat_konteks_decompiler(void);

void hapus_konteks_decompiler(struct ContextDecompiler *ctx_ptr);

int muat_file_biner(struct ContextDecompiler *ctx_ptr, const char *path_ptr);

#endif  /* RCDECOMP_H */
