// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// CPython's pthread surface over Capsule fibers: a fiber is a thread. The
// locks are real, not OS primitives, and contention spins within the BPF work
// budget; thread identity is the fiber index; thread-specific storage is
// _Thread_local, which the compiler keeps per fiber. Creating operating-system
// threads stays unsupported.
#include <Python.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include "bpf_capsule.h"

int pthread_mutex_init(pthread_mutex_t* restrict mutex, const pthread_mutexattr_t* restrict attr) {
    (void)attr;
    mutex->locked = 0;
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t* mutex) {
    return __atomic_load_n(&mutex->locked, __ATOMIC_RELAXED) ? EBUSY : 0;
}

int pthread_mutex_trylock(pthread_mutex_t* mutex) {
    return __atomic_exchange_n(&mutex->locked, 1, __ATOMIC_ACQUIRE) ? EBUSY : 0;
}

int pthread_mutex_lock(pthread_mutex_t* mutex) {
    while (pthread_mutex_trylock(mutex)) {
        while (__atomic_load_n(&mutex->locked, __ATOMIC_RELAXED)) {
        }
    }
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t* mutex) {
    __atomic_store_n(&mutex->locked, 0, __ATOMIC_RELEASE);
    return 0;
}

int pthread_cond_init(pthread_cond_t* restrict cond, const pthread_condattr_t* restrict attr) {
    cond->sequence = 0;
    cond->clock = attr ? (clockid_t)attr->__attr : CLOCK_REALTIME;
    return 0;
}

int pthread_cond_destroy(pthread_cond_t* cond) {
    (void)cond;
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t* restrict cond, pthread_mutex_t* restrict mutex, const struct timespec* restrict deadline) {
    if (deadline && (deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000)) {
        return EINVAL;
    }
    // Read the sequence while still holding the caller's mutex, so a signal
    // between unlock and the first poll cannot be lost. Spurious wakeups are
    // permitted; callers must check their predicate after reacquiring it.
    unsigned sequence = __atomic_load_n(&cond->sequence, __ATOMIC_ACQUIRE);
    pthread_mutex_unlock(mutex);
    int result = 0;
    while (__atomic_load_n(&cond->sequence, __ATOMIC_ACQUIRE) == sequence) {
        if (deadline) {
            struct timespec now;
            if (clock_gettime(cond->clock, &now)) {
                result = errno;
                break;
            }
            if (now.tv_sec > deadline->tv_sec || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
                result = ETIMEDOUT;
                break;
            }
        }
    }
    pthread_mutex_lock(mutex);
    return result;
}

int pthread_cond_wait(pthread_cond_t* restrict cond, pthread_mutex_t* restrict mutex) {
    return pthread_cond_timedwait(cond, mutex, NULL);
}

int pthread_cond_signal(pthread_cond_t* cond) {
    __atomic_fetch_add(&cond->sequence, 1, __ATOMIC_RELEASE);
    return 0;
}

int pthread_condattr_init(pthread_condattr_t* attr) {
    attr->__attr = CLOCK_REALTIME;
    return 0;
}

int pthread_condattr_setclock(pthread_condattr_t* attr, clockid_t clock) {
    if (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) {
        return EINVAL;
    }
    attr->__attr = clock;
    return 0;
}

pthread_t pthread_self(void) {
    return (pthread_t)(capsule_fiber_index() + 1u);
}

// Keys are never reused: CPython creates a few for the runtime's lifetime.
static unsigned int keys_created;
static _Thread_local void* key_values[PTHREAD_KEYS_MAX];

int pthread_key_create(pthread_key_t* key, void (*destructor)(void*)) {
    if (!key) {
        return EINVAL;
    }
    if (destructor) {
        return ENOTSUP;
    }
    unsigned int index = __atomic_fetch_add(&keys_created, 1, __ATOMIC_RELAXED);
    if (index >= PTHREAD_KEYS_MAX) {
        return EAGAIN;
    }
    *key = index;
    return 0;
}

int pthread_key_delete(pthread_key_t key) {
    return key < PTHREAD_KEYS_MAX ? 0 : EINVAL;
}

void* pthread_getspecific(pthread_key_t key) {
    return key < PTHREAD_KEYS_MAX ? key_values[key] : NULL;
}

int pthread_setspecific(pthread_key_t key, const void* value) {
    if (key >= PTHREAD_KEYS_MAX) {
        return EINVAL;
    }
    key_values[key] = (void*)value;
    return 0;
}

int pthread_create(pthread_t* restrict thread, const pthread_attr_t* restrict attr, void* (*start)(void*), void* restrict arg) {
    (void)thread;
    (void)attr;
    (void)start;
    (void)arg;
    return EAGAIN;
}

int pthread_detach(pthread_t thread) {
    (void)thread;
    return ESRCH;
}

int pthread_join(pthread_t thread, void** value) {
    (void)thread;
    (void)value;
    return ESRCH;
}

int pthread_exit(void* value) {
    (void)value;
    abort();
}

int pthread_attr_init(pthread_attr_t* attr) {
    attr->__attr = 0;
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t* attr, size_t size) {
    (void)attr;
    (void)size;
    return ENOTSUP;
}

int pthread_attr_destroy(pthread_attr_t* attr) {
    (void)attr;
    return 0;
}
