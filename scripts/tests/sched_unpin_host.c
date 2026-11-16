/* SPDX-License-Identifier: GPL-2.0 */
/* Deterministic services for extracted production migration and lock wrappers.
 * Raw lock/pin state is an oracle; this is not a kernel concurrency test. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define __acquires(x)
#define __releases(x)
#define __acquire(x) ((void)0)
#define unlikely(x) (x)
#define BUG_ON(x) assert(!(x))
#define SINGLE_DEPTH_NESTING 1
#define _RET_IP_ 0
#define TASK_ON_RQ_MIGRATING 2
#define TASK_ON_RQ_QUEUED 1
#define DEQUEUE_NOCLOCK 8

struct pin_cookie { unsigned val; };
struct lock { bool held; unsigned pins, acquisitions, releases, pin_calls, unpin_calls; int dep_map; };
struct rq { struct lock lock; };
struct rq_flags { unsigned long flags; struct pin_cookie cookie; };
struct task_struct { int cpu, on_rq, wake_cpu; struct lock pi_lock; };
struct migration_arg { struct task_struct *task; int dest_cpu; };
static struct rq queues[2];
static int source_cpu, destination_cpu, contention;
static bool irq_off, migrated;
static unsigned final_source_unlocks, dequeues, enqueues, preempts, clocks, pending;

static struct rq *cpu_rq(int cpu) { assert(cpu == 0 || cpu == 1); return &queues[cpu]; }
static struct rq *this_rq(void) { return cpu_rq(source_cpu); }
static struct rq *task_rq(struct task_struct *p) { return cpu_rq(p->cpu); }
static int task_cpu(struct task_struct *p) { return p->cpu; }
static bool task_on_rq_queued(struct task_struct *p) { return p->on_rq == TASK_ON_RQ_QUEUED; }
static bool is_cpu_allowed(struct task_struct *p, int cpu) { (void)p; return cpu == destination_cpu; }
static void lockdep_assert_held(struct lock *lock) { assert(lock->held); }
static bool irqs_disabled(void) { return irq_off; }
static void local_irq_disable(void) { assert(!irq_off); irq_off = true; }
static void local_irq_enable(void) { assert(irq_off); irq_off = false; }
static void sched_ttwu_pending(void) { assert(irq_off); pending++; }

static void raw_spin_lock(struct lock *lock)
{
    assert(irq_off && !lock->held && !lock->pins);
    lock->held = true;
    lock->acquisitions++;
}
static void raw_spin_unlock(struct lock *lock)
{
    assert(irq_off && lock->held && !lock->pins);
    if (lock == &queues[source_cpu].lock && migrated)
        final_source_unlocks++;
    lock->held = false;
    lock->releases++;
}
static int raw_spin_trylock(struct lock *lock)
{
    assert(lock == &queues[destination_cpu].lock);
    if (contention)
        return 0;
    raw_spin_lock(lock);
    return 1;
}
static void raw_spin_lock_nested(struct lock *lock, int subclass)
{
    assert(subclass == SINGLE_DEPTH_NESTING);
    raw_spin_lock(lock);
}
static struct pin_cookie lockdep_pin_lock(struct lock *lock)
{
    assert(lock->held && !lock->pins);
    struct pin_cookie cookie = {lock == &queues[source_cpu].lock ? 7 : 13};
    lock->pins = cookie.val;
    lock->pin_calls++;
    return cookie;
}
static void lockdep_unpin_lock(struct lock *lock, struct pin_cookie cookie)
{
    assert(lock->held);
    /* The baseline fails here: rq_unlock tries to consume the same pin twice. */
    assert(lock->pins && lock->pins == cookie.val);
    lock->pins = 0;
    lock->unpin_calls++;
}
static void lock_set_subclass(int *map, int subclass, int ip)
{
    (void)ip;
    assert(map == &queues[source_cpu].lock.dep_map && subclass == 0);
    assert(queues[source_cpu].lock.held && !queues[source_cpu].lock.pins);
}
static void update_rq_clock(struct rq *rq) { assert(rq == this_rq() && rq->lock.held); clocks++; }
static void dequeue_task(struct rq *rq, struct task_struct *p, int flags)
{
    assert(rq == this_rq() && rq->lock.held && rq->lock.pins);
    assert(p->on_rq == TASK_ON_RQ_MIGRATING && flags == DEQUEUE_NOCLOCK);
    dequeues++;
}
static void set_task_cpu(struct task_struct *p, int cpu)
{
    assert(p->pi_lock.held && p->on_rq == TASK_ON_RQ_MIGRATING);
    assert(queues[source_cpu].lock.held && !queues[source_cpu].lock.pins);
#ifdef CONFIG_SCHED_WALT
    assert(queues[destination_cpu].lock.held);
#else
    assert(!queues[destination_cpu].lock.held);
#endif
    assert(cpu == destination_cpu);
    p->cpu = cpu;
    migrated = true;
}
static void enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
    assert(rq == cpu_rq(destination_cpu) && rq->lock.held && rq->lock.pins);
    assert(!queues[source_cpu].lock.held && final_source_unlocks == 1);
    assert(p->cpu == destination_cpu && p->on_rq == TASK_ON_RQ_MIGRATING && flags == 0);
    enqueues++;
}
static void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags)
{
    assert(rq->lock.held && rq->lock.pins && p->on_rq == TASK_ON_RQ_QUEUED && !flags);
    preempts++;
}

/* PRODUCTION */

int main(int argc, char **argv)
{
    assert(argc == 3);
    source_cpu = atoi(argv[1]);
    destination_cpu = 1 - source_cpu;
    contention = atoi(argv[2]);
    struct task_struct task = {.cpu = source_cpu, .on_rq = TASK_ON_RQ_QUEUED};
    struct migration_arg arg = {&task, destination_cpu};
    assert(!migration_cpu_stop(&arg));
    assert(!irq_off && !task.pi_lock.held && !task.pi_lock.pins);
    assert(task.pi_lock.acquisitions == 1 && task.pi_lock.releases == 1);
    assert(task.cpu == destination_cpu && task.on_rq == TASK_ON_RQ_QUEUED);
    assert(dequeues == 1 && enqueues == 1 && preempts == 1 && clocks == 1 && pending == 1);
    assert(final_source_unlocks == 1);
    struct lock *src = &queues[source_cpu].lock, *dst = &queues[destination_cpu].lock;
    unsigned src_physical = 1, dst_physical = 1;
#ifdef CONFIG_SCHED_WALT
    dst_physical = 2;
#ifdef CONFIG_PREEMPT
    src_physical = 2;
#else
    if (source_cpu == 1 && contention)
        src_physical = 2;
#endif
#endif
    assert(src->acquisitions == src_physical && src->releases == src_physical);
    assert(dst->acquisitions == dst_physical && dst->releases == dst_physical);
    assert(src->pin_calls == 1 && src->unpin_calls == 1);
    assert(dst->pin_calls == 1 && dst->unpin_calls == 1);
    assert(!src->held && !dst->held && !src->pins && !dst->pins);
    puts("PASS production migration/wrappers; deterministic lock services");
    return 0;
}
