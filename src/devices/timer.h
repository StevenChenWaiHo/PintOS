#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h>
#include "threads/synch.h"

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

struct thread_sleep
{
    int64_t sleep_until;    /* The time to wake up a thread */
    struct semaphore sema;  /* Up when thread wakes up, down to shcedule it to sleep */
    struct list_elem elem;  /* List element. */
};

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

//static bool sleep_time_cmp (const struct list_elem *p, const struct list_elem *q, void *aux);
//static void timer_wake(void);

/* Sleep and yield the CPU to other threads. */
void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

/* Busy waits. */
void timer_mdelay (int64_t milliseconds);
void timer_udelay (int64_t microseconds);
void timer_ndelay (int64_t nanoseconds);

void timer_print_stats (void);

#endif /* devices/timer.h */