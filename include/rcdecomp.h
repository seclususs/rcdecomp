/* Shared Library Header: rcdecomp_core - Auto Generated */

#ifndef RCDECOMP_CORE_H
#define RCDECOMP_CORE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define EFLAGS_CF_MASK 1

#define EFLAGS_PF_MASK 4

#define EFLAGS_AF_MASK 16

#define EFLAGS_ZF_MASK 64

#define EFLAGS_SF_MASK 128

#define EFLAGS_TF_MASK 256

#define EFLAGS_IF_MASK 512

#define EFLAGS_DF_MASK 1024

#define EFLAGS_OF_MASK 2048

struct ContextDecompiler;

struct ContextDecompiler *buat_konteks_decompiler(void);

void hapus_konteks_decompiler(struct ContextDecompiler *ctx_ptr);

int muat_file_biner(struct ContextDecompiler *ctx_ptr, const char *path_ptr);

#endif  /* RCDECOMP_CORE_H */
