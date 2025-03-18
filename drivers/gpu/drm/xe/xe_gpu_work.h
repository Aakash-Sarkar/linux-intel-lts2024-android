#ifndef _XE_GPU_WORK_H_
#define _XE_GPU_WORK_H_

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/list.h>

#define XE_ENGINE_WORK_STATS_COUNT (256)
#define GPU_WORK_PERIOD_EVENT_TIMEOUT_MS (10)
#define SEC_IN_NSEC (1000000000)
#define GPU_WORK_TIME_GAP_LIMIT_NS (SEC_IN_NSEC)

#define HASH_MAP(x) (x & (XE_ENGINE_WORK_STATS_COUNT - 1))
#define KEY_INVALID(key) (key < 0 || key >= XE_ENGINE_WORK_STATS_COUNT)
#define STAT_INVALID(stat) (!stat->start_time_ns || \
                            stat->start_time_ns >= stat->end_time_ns || \
                            !stat->active_duration_ns || \
                            (stat->end_time_ns - stat->start_time_ns) < \
                            stat->active_duration_ns)

struct xe_exec_queue;
struct xe_hw_engine;

struct xe_work_stats {
    u32 gpu_id;
    u32 uid;
    u64 start_time_ns;
    u64 end_time_ns;
    u64 active_duration_ns;

    /* Lock protecting this stat */
    spinlock_t lock;
    /* List of queues currently contributing to this uid */
    struct list_head queues;
    /* Number of jiffies since we last emitted event for this uid */
    unsigned long jiffies;
};

struct xe_engine_work {
    /* Indicates if gpu work period is enabled */
    bool enabled;
    /* number of entries currently in work stats */
    atomic_t num_entries;
    /* work period stats record per engine */
    struct xe_work_stats stats[XE_ENGINE_WORK_STATS_COUNT];
};

void xe_gpu_work_process_queue(struct xe_exec_queue *q,
                            struct xe_engine_work *ew);

void xe_gpu_work_stats_init(struct xe_hw_engine *engine);
void xe_gpu_work_stats_fini(struct xe_hw_engine *engine);

#endif /*_XE_GPU_WORK_H_*/