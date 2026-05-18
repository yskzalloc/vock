// Copyright 2022 Erik Rigtorp <erik@rigtorp.se>

#pragma once

#include <stdatomic.h>
#include <stdbool.h>

typedef struct {
  atomic_bool lock_;
} spinlock;

#define SPINLOCK_INIT { ATOMIC_VAR_INIT(false) }

static inline void spinlock_lock(spinlock *s) {
  for (;;) {
    if (!atomic_exchange_explicit(&s->lock_, true, memory_order_acquire))
      return;
    while (atomic_load_explicit(&s->lock_, memory_order_relaxed))
      __builtin_ia32_pause();
  }
}

static inline bool spinlock_try_lock(spinlock *s) {
  return !atomic_load_explicit(&s->lock_, memory_order_relaxed) &&
         !atomic_exchange_explicit(&s->lock_, true, memory_order_acquire);
}

static inline void spinlock_unlock(spinlock *s) {
  atomic_store_explicit(&s->lock_, false, memory_order_release);
}
