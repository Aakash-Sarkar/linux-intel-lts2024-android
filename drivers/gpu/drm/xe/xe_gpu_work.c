#include "xe_gpu_work.h"
#include <linux/pid.h>
#include <linux/errno.h>
#include <linux/jiffies.h>

#include "xe_exec_queue.h"
#include "xe_hw_engine.h"
#include "xe_lrc.h"
#include "xe_device.h"
#include "xe_gt.h"
#include "xe_gt_clock.h"

#define CREATE_TRACE_POINTS
#include "xe_power_gpu_work_period_trace.h"

static inline u32 get_stats_uid(s32 key, struct xe_work_stats *stats)
{
    struct xe_work_stats *stat = &stats[key];
    return READ_ONCE(stat->uid);
}

static int get_uid_queue(struct xe_exec_queue *q)
{
    struct xe_file *xef = NULL;
    struct pid *pid = NULL;
    struct task_struct *task = NULL;
    const struct cred *cred = NULL;
    int ret;

    if (!q->vm || !q->vm->xef)
        return -EINVAL;

    xef = xe_file_get(q->vm->xef);
    if (!xef) {
        ret = -EINVAL;
        goto out;
    }

    pid = find_get_pid(xef->pid);
    if (!pid) {
        ret = -ESRCH;
        goto put_xef;
    }

    task = get_pid_task(pid, PIDTYPE_PID);
    if (!task) {
        ret = -EINVAL;
        goto put_pid;
    }

    cred = get_task_cred(task);
    if (!cred) {
        ret = -EINVAL;
        goto put_task;
    }

    const unsigned int uid = cred->euid.val;
    ret = (int)uid;

    put_cred(cred);
put_task:
    put_task_struct(task);
put_pid:
    put_pid(pid);
put_xef:
    xe_file_put(xef);
out:
    return ret;
}

static void __emit_work_period_event(struct xe_work_stats *stat, bool discard)
{
    struct xe_exec_queue *q = NULL, *q2 = NULL;

    BUG_ON(!stat->uid);

    lockdep_assert_held(&stat->lock);

    if (STAT_INVALID(stat))
        discard = true;

    if (!discard) {
        trace_gpu_work_period(stat->gpu_id, stat->uid,
            stat->start_time_ns, stat->end_time_ns,
            stat->active_duration_ns);
    }

    /* clean up the slate */
    /* We keep the uid and the end time intact since we
       may encounter the same uid again soon */
    stat->start_time_ns = 0;
    stat->active_duration_ns = 0;
    stat->jiffies = 0;

    /* Remove all the contexts associated with this uid and drop their
     * reference
     */
    list_for_each_entry_safe(q, q2, &stat->queues, record.ws_link) {
        list_del_init(&q->record.ws_link);
        xe_exec_queue_put(q);
    }
    smp_mb();
}

static void emit_work_period_event(struct xe_work_stats *stat)
{
    lockdep_assert_held(&stat->lock);

    u64 start_time = stat->start_time_ns;
    u64 end_time = stat->end_time_ns;

    /* Google requirement restricts the interval between end time
     * and start time to be at most 1 second
     */
    bool discard = ((end_time - start_time) >
                        GPU_WORK_TIME_GAP_LIMIT_NS);

    __emit_work_period_event(stat, discard);
}

static void emit_event_and_evict_slot(struct xe_work_stats *stat)
{
    lockdep_assert_held(&stat->lock);

    u64 start_time = stat->start_time_ns;
    u64 end_time = stat->end_time_ns;

    /* Google requirement restricts the interval between end time
     * and start time to be at most 1 second
     */
    bool discard = ((end_time - start_time) >
                        GPU_WORK_TIME_GAP_LIMIT_NS);
    stat->uid = 0;
    stat->end_time_ns = 0;
    __emit_work_period_event(stat, discard);
}

static inline u32 get_cur_dt(struct xe_exec_queue* q)
{
    struct xe_lrc *lrc;

    spin_lock(&q->record.lock);
    lrc = q->lrc[0];
    u32 ts = xe_lrc_ctx_timestamp(lrc);
    s32 dt = ts - q->record.last_ts;
    q->record.last_ts = ts;
    spin_unlock(&q->record.lock);

    if (unlikely(dt < 0))
        dt = 0;
    return dt * q->width;
}

static u64 get_active_duration_ns(struct xe_exec_queue* q)
{
    struct xe_gt *gt = q->gt;
    u64 dur = get_cur_dt(q);
    return dur? xe_gt_clock_interval_to_ns(gt, dur) : dur;
}

static int handle_collision(s32 key, struct xe_engine_work *ew,
                            u32 uid)
{
    struct xe_work_stats * const stats = &ew->stats[0];
    u32 count = 0;

    BUG_ON(KEY_INVALID(key));

    while (get_stats_uid(key, stats) != uid) {
        if (unlikely(count >= XE_ENGINE_WORK_STATS_COUNT)) {
            return -ENOENT;
        }
        key++;
        if (key == XE_ENGINE_WORK_STATS_COUNT)
            key = 0;
        count++;
    }
    return key;
}

static int find_next_available_slot(int key, struct xe_engine_work *ew)
{
    return handle_collision(key, ew, 0);
}

void xe_gpu_work_process_queue(struct xe_exec_queue *q,
                        struct xe_engine_work *ew)
{
    struct xe_work_stats *stat = NULL;
    s32 key = 0, uid = 0, cur_uid = 0;

    if (!ew->enabled)
        return;

    uid = get_uid_queue(q);
    if (uid < 0)
        return;

    key = HASH_MAP(uid);
    cur_uid = get_stats_uid(key, ew->stats);

    if (unlikely(cur_uid && cur_uid != uid)) {
        /*
         * We have encountered a hash collision.
         * First check if the uid is already present in another
         * slot by doing a linear search
         */
        key = handle_collision(key, ew, uid);
        /*
         * We couldn't find the uid in the stats array
         * this means this is the first occurence of this
         * uid. So we find the next available slot
         */
        if (KEY_INVALID(key))
            key = find_next_available_slot(key, ew);

        /*
         * This can only happen if all the slots in our stats
         * array are occupied. Emit the event and evict one slot.
         */
        if (KEY_INVALID(key)) {
            u32 idx = HASH_MAP(uid);
            stat = &ew->stats[idx];
            spin_lock(&stat->lock);
            emit_event_and_evict_slot(stat);
            spin_unlock(&stat->lock);
            key = idx;
        }
    }
    stat = &ew->stats[key];
    BUG_ON(stat->uid && (stat->uid != uid));
    u64 job_start_time =
        atomic64_read(&q->record.start_time_ns);

    /*
     * If the uid at our hash index is empty (zero)
     * this implies that our ctx is processed for
     * the first time.
     *
     * So, we set the start time to the last time this
     * ctx was put into the active queue after emitting
     * its event. We also set the total active duration to
     * the current runtime of this ctx
     */
    spin_lock(&stat->lock);
    if (!stat->uid) {
        stat->uid = uid;
        stat->start_time_ns = job_start_time;
        stat->active_duration_ns =
                    get_active_duration_ns(q);
        stat->end_time_ns = ktime_get_raw_ns();

        atomic_inc(&ew->num_entries);
        goto list_add;
    }

    /* Google requirement prohibits next start time to
     * overlap with previous end time for a given uid.
     * Skip the reuqests that don't match the requirement
     * until we get the desired new start time
     */
    u64 prev_start_time = stat->start_time_ns;
    u64 prev_end_time = stat->end_time_ns;
    if (!prev_start_time && job_start_time <= prev_end_time)
        goto out;

    /*
     * We set the endtime to the current time this job
     * is being processed and accumulate the current
     * runtime to the total active duration
     */
    stat->start_time_ns = prev_start_time?: job_start_time;
    stat->end_time_ns = ktime_get_raw_ns();
    stat->active_duration_ns +=
                get_active_duration_ns(q);

    /* We limit the frequency of events to 10ms */
    unsigned long delta = jiffies - stat->jiffies;
    if (jiffies_to_msecs(delta) >=
                GPU_WORK_PERIOD_EVENT_TIMEOUT_MS)
    {
        emit_work_period_event(stat);
        stat->jiffies = jiffies;
        goto out;
    }

list_add:
    if (list_empty(&q->record.ws_link)) {
        /* This implies the queue wasn't being tracked
         * until this point. Get a reference and add this
         * to the list to mark it as being tracked.
         */
        xe_exec_queue_get(q);
        list_add(&q->record.ws_link, &stat->queues);
    }
out:
    spin_unlock(&stat->lock);
}

void xe_gpu_work_stats_init(struct xe_hw_engine *engine)
{
    struct xe_engine_work *ew = &engine->gpu_work;

    atomic_set(&ew->num_entries, 0);

    /* Initalize the slots */
    for (int i = 0; i < XE_ENGINE_WORK_STATS_COUNT; i++) {
        struct xe_work_stats *stat = &ew->stats[i];

        stat->gpu_id = engine->class;
        stat->uid = 0;
        stat->start_time_ns = 0;
        stat->end_time_ns = 0;
        stat->active_duration_ns = 0;
        stat->jiffies = 0;

        spin_lock_init(&stat->lock);
        INIT_LIST_HEAD(&stat->queues);
    }

    /* Enable gpu work period */
    ew->enabled = true;
}

void xe_gpu_work_stats_fini(struct xe_hw_engine *engine)
{
    struct xe_engine_work *ew = &engine->gpu_work;

    ew->enabled = false;
    if (!atomic_read(&ew->num_entries))
        return;

    for (int i = 0; i < XE_ENGINE_WORK_STATS_COUNT; i++) {
        struct xe_work_stats *stat = &ew->stats[i];

        if (!get_stats_uid(i, stat))
            continue;

        spin_lock(&stat->lock);
        emit_work_period_event(stat);
        spin_unlock(&stat->lock);

        if (atomic_dec_and_test(&ew->num_entries))
            break;
    }
}
