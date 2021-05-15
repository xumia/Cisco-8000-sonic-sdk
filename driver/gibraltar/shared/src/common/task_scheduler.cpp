// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#include "common/task_scheduler.h"
#include "common/gen_utils.h"
#include "common/la_status.h"
#include "common/logger.h"

namespace silicon_one
{
struct timespec
to_timespec(const std::chrono::milliseconds& rhs)
{
    struct timespec ts_rhs;
    ts_rhs.tv_nsec = rhs.count() * std::nano::den / std::milli::den;
    ts_rhs.tv_sec = 0;
    if (ts_rhs.tv_nsec > std::nano::den) {
        ts_rhs.tv_sec = ts_rhs.tv_nsec / std::nano::den;
        ts_rhs.tv_nsec = ts_rhs.tv_nsec % std::nano::den;
    }
    return ts_rhs;
}

bool
operator<(const timespec& lhs, const timespec& rhs)
{
    return std::tie(lhs.tv_sec, lhs.tv_nsec) < std::tie(rhs.tv_sec, rhs.tv_nsec);
}

timespec
sum_of_timespecs(const struct timespec& lhs, const struct timespec& rhs, const bool invert_rhs)
{
    struct timespec ts_result;

    if (invert_rhs == false) {
        ts_result.tv_nsec = lhs.tv_nsec + rhs.tv_nsec;
        ts_result.tv_sec = lhs.tv_sec + rhs.tv_sec;
    } else {
        ts_result.tv_nsec = lhs.tv_nsec - rhs.tv_nsec;
        ts_result.tv_sec = lhs.tv_sec - rhs.tv_sec;
    }

    if (ts_result.tv_nsec > std::nano::den) {
        ++ts_result.tv_sec;
        ts_result.tv_nsec = ts_result.tv_nsec % std::nano::den;
    } else if (ts_result.tv_nsec < 0) {
        --ts_result.tv_sec;
        ts_result.tv_nsec = std::nano::den + ts_result.tv_nsec;
    }

    return ts_result;
}

timespec
operator+(const struct timespec& lhs, const struct timespec& rhs)
{
    return sum_of_timespecs(lhs, rhs, false);
}

timespec
operator-(const struct timespec& lhs, const struct timespec& rhs)
{
    return sum_of_timespecs(lhs, rhs, true);
}

interruptible_sleep::interruptible_sleep()
{
    pthread_condattr_init(&m_attr);
    // Benchmarking shows that using CLOCK_MONOTONIC_COARSE gives much slower performance overall.
    // This was not debugged further.
    pthread_condattr_setclock(&m_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&m_sleep_cv, &m_attr);
}

interruptible_sleep::~interruptible_sleep()
{
}

bool
interruptible_sleep::sleep_for(const struct timespec& duration)
{
    struct timespec ts;
    bool rs = false;

    if (duration.tv_sec < 0 || (duration.tv_sec == 0 && duration.tv_nsec == 0)) {
        // Effectively provided duration has already passed. We can skip everything.
        return true;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);

    ts = ts + duration;

    pthread_mutex_lock(&m_mutex);

    int rc = 0;
    while (m_wake_up == false && (rc = pthread_cond_timedwait(&m_sleep_cv, &m_mutex, &ts)) == 0) {
    }

    if (rc == ETIMEDOUT) {
        rs = true;
    } else {
        rs = false;
    }

    m_wake_up.store(false);

    pthread_mutex_unlock(&m_mutex);
    return rs;
}

void
interruptible_sleep::wake_up()
{
    // Even if the condition variable is atomic, mutexes should be used to ensure proper data propagation.
    pthread_mutex_lock(&m_mutex);
    m_wake_up.store(true);
    pthread_mutex_unlock(&m_mutex);

    pthread_cond_broadcast(&m_sleep_cv);
}

enum {
    DEFAULT_SLEEP_TIME_MS = 100 // in ms.
};

bool
task_scheduler::task_less_operator::operator()(const task_desc& lhs, const task_desc& rhs) const
{
    return lhs.ex_point < rhs.ex_point;
}

task_scheduler::~task_scheduler()
{
    terminate();
}

task_scheduler::task_handle
task_scheduler::schedule_task(task_func task_function, std::chrono::milliseconds delay)
{
    return schedule_task_core(task_function, nullptr /*period function*/, delay);
}

task_scheduler::task_handle
task_scheduler::schedule_periodic_task(task_func task_function, repeat_period_func period_function)
{
    return schedule_task_core(task_function, period_function, std::chrono::milliseconds(0));
}

task_scheduler::task_handle
task_scheduler::schedule_task_core(task_func task_function, repeat_period_func period_function, std::chrono::milliseconds delay)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    task_desc new_task = {
        .func = task_function, .period_function = period_function, .delay = delay, .ex_point = timespec(), .handle = m_next_handle};

    auto rc = schedule_task_core(new_task);

    if (rc != INVALID_TASK_HANDLE) {
        m_next_handle++;
    }

    return rc;
}

task_scheduler::task_handle
task_scheduler::schedule_task_core(task_desc& descriptor)
{
    auto delay = descriptor.delay;

    if (descriptor.period_function != nullptr) {
        // do what is unique for repeating tasks.
        delay = descriptor.period_function();

        if (delay.count() == 0) {
            // Current implementation of repeating tasks does not make room for period 0.
            log_err(COMMON, "%s: Cannot schedule a periodic task (id=%lu) with a zero delay", __func__, descriptor.handle);
            return INVALID_TASK_HANDLE;
        }
    }

    struct timespec ts_now_point;
    clock_gettime(CLOCK_MONOTONIC, &ts_now_point);
    struct timespec ts_delay = to_timespec(delay);
    struct timespec ts_execution_point_of_new_task = ts_now_point + ts_delay;

    descriptor.ex_point = ts_execution_point_of_new_task;

    m_tasks.insert(descriptor);

    if (m_tasks.begin()->handle == descriptor.handle) {
        // The new task is due before any of the currently pending tasks, wake up a potentially sleeping worker thread.
        m_interruptible_sleep.wake_up();
    }

    return descriptor.handle;
}

void
task_scheduler::unschedule_task(task_scheduler::task_handle handle)
{
    std::lock_guard<std::recursive_mutex> lock(m_task_execution_recursive_mutex);
    std::lock_guard<std::mutex> lock2(m_mutex);

    for (task_desc_container::iterator it = m_tasks.begin(); it != m_tasks.end(); ++it) {
        if (it->handle == handle) {
            m_tasks.erase(it);
            break;
        }
    }
}

void
task_scheduler::unschedule_all_tasks()
{
    std::lock_guard<std::recursive_mutex> lock(m_task_execution_recursive_mutex);
    std::lock_guard<std::mutex> lock2(m_mutex);

    m_tasks.clear();
}

task_scheduler::task_desc_container
task_scheduler::get_tasks()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    return m_tasks;
}

size_t
task_scheduler::get_num_tasks()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    return m_tasks.size();
}

void
task_scheduler::tick()
{
    std::lock_guard<std::recursive_mutex> lock(m_task_execution_recursive_mutex);

    task_desc_list list = get_tasks_for_execution();

    for (task_desc_list::iterator it = list.begin(); it != list.end(); it++) {
        it->func();
    }
}

void
task_scheduler::wait_until_next_event()
{
    m_interruptible_sleep.sleep_for(get_time_until_next_task());
}

struct timespec
task_scheduler::get_time_until_next_task()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    struct timespec ts_now_point;

    if (m_tasks.empty()) {
        // currently we have no scheduled tasks. Return a default value.
        struct timespec ret_val = to_timespec(std::chrono::milliseconds(DEFAULT_SLEEP_TIME_MS));
        return ret_val;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_now_point);

    if (m_tasks.begin()->ex_point < ts_now_point) {
        // Dont want to worry if tv_sec ever becomes unsigned type, and - operator starts acting funny.
        struct timespec ret_val = {.tv_sec = 0, .tv_nsec = 0};
        return ret_val;
        ;
    }

    return m_tasks.begin()->ex_point - ts_now_point;
}

la_status
task_scheduler::spawn(std::function<void()> init_function)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_worker_thread != nullptr) {
        return LA_STATUS_EEXIST;
    }

    m_work = true;
    m_worker_thread = silicon_one::make_unique<std::thread>(&task_scheduler::worker_thread, this, init_function);

    return LA_STATUS_SUCCESS;
}

void
task_scheduler::terminate()
{
    m_mutex.lock();

    auto th = std::move(m_worker_thread);

    if (th != nullptr) {
        m_work = false;
        m_worker_thread = nullptr;

        m_interruptible_sleep.wake_up();
    }

    m_mutex.unlock();

    if (th && th->joinable()) {
        th->join();
    }
}

task_scheduler::task_desc_list
task_scheduler::get_tasks_for_execution()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    struct timespec ts_now_point;
    clock_gettime(CLOCK_MONOTONIC, &ts_now_point);

    task_desc_list list;

    while (m_tasks.begin() != m_tasks.end()) {

        task_desc_container::iterator it = m_tasks.begin();

        if (ts_now_point < it->ex_point) {
            // no more tasks to be executed.
            break;
        }

        task_desc tsk = *it;

        m_tasks.erase(it);
        list.push_back(tsk);

        if (tsk.period_function != nullptr) {
            schedule_task_core(tsk);
        }
    }

    return list;
}

void
task_scheduler::worker_thread(std::function<void()> init_function)
{
    init_function();

    while (m_work) {
        tick();
        wait_until_next_event();
    }
    log_debug(COMMON, "%s stopping.", __func__);
}

} // namespace silicon_one
