/* Portable replacements for Clang-only alignment builtins */
#ifndef COMPAT_ALIGN_H
#define COMPAT_ALIGN_H

#include <stdint.h>

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if !__has_builtin(__builtin_is_aligned)
#define __builtin_is_aligned(x, a) (((uintptr_t)(x) & ((a) - 1)) == 0)
#endif

#if !__has_builtin(__builtin_align_down)
#define __builtin_align_down(x, a) ((typeof(x))((uintptr_t)(x) & ~((uintptr_t)(a) - 1)))
#endif

#if !__has_builtin(__builtin_align_up)
#define __builtin_align_up(x, a) ((typeof(x))(((uintptr_t)(x) + (a) - 1) & ~((uintptr_t)(a) - 1)))
#endif

#endif /* COMPAT_ALIGN_H */
