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

#ifndef __TASK_SCHEDULER_H__
#define __TASK_SCHEDULER_H__

#include "common/allocator_wrapper.h"
#include "common/la_status.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <pthread.h>
#include <set>
#include <thread>
#include <time.h>

namespace silicon_one
{
class interruptible_sleep
{

public:
    /// @brief constructor.
    interruptible_sleep();

    /// @brief destructor
    ~interruptible_sleep();

    /// @brief Sleep until timeout expires, or somebody calls wake_up.
    ///
    /// @return true if timeout expired, false if sleep was interrupted.
    bool sleep_for(const struct timespec& duration);

    /// @brief Wake up a thread that might be blocked sleeping.
    /// @note If no thread is asleep, then the first thread that calls sleep_for will not go to sleep.
    void wake_up();

private:
    /// @brief Used to implement interruptible sleep.
    pthread_condattr_t m_attr;
    pthread_cond_t m_sleep_cv;

    pthread_mutex_t m_mutex = PTHREAD_MUTEX_INITIALIZER;

    /// @brief Used to differentiate between spurious wake ups on the condition variable and real wake ups.
    std::atomic<bool> m_wake_up{false};
};

/// @brief Task scheduler.
class task_scheduler
{
public:
    /// @brief Constructor.
    task_scheduler() = default;

    /// @brief Destructor.
    ~task_scheduler();

    /// @brief Copy constructor.
    task_scheduler(const task_scheduler& original) = delete;

    /// @brief Assignment operator.
    task_scheduler& operator=(const task_scheduler& original) = delete;

    /// @brief Move constructor.
    task_scheduler(const task_scheduler&& original) = delete;

    /// @brief Move assignment operator.
    task_scheduler& operator=(const task_scheduler&& original) = delete;

    using task_func = std::function<void()>;
    using repeat_period_func = std::function<std::chrono::milliseconds()>;
    using task_handle = uint64_t; // handle cannot be an iterator, because periodic tasks are rescheduled.

    /// @brief Contains the relevant data for one task.
    ///
    /// @note struct timespec and clock_gettime are used for time keeping instead of the std::chrono. Because put less load on the
    /// cpu.
    struct task_desc {
        task_func func;                     ///<Task function.
        repeat_period_func period_function; ///<Time. Determines how how often should a repeating task be executed.
        std::chrono::milliseconds delay;    ///<Delay. Determines how much should a non repeating tasks be delayed.
        struct timespec ex_point;           ///<Execution time. Scheduled moment of execution.
        task_handle handle;                 ///<Handle. Unique ID used to identify the task.
    };

    /// @brief
    struct task_less_operator {
        bool operator()(const task_desc& lhs, const task_desc& rhs) const;
    };

    /// @brief Container for all of the scheduled tasks.
    using task_desc_container = multiset_alloc<task_desc, task_less_operator>;

    /// @brief Schedule a non periodic task for execution.
    ///
    /// @param[in] task_function        Function to be executed.
    /// @param[in] delay                Delay after which task should be executed.
    /// @return  a unique handle to the registered task.
    /// @return  INVALID_TASK_HANDLE    Operation was unsuccessful.
    task_handle schedule_task(task_func task_function, std::chrono::milliseconds delay);

    /// @brief Schedule a periodic task for execution.
    ///
    /// @param[in] task_function        Function to be executed.
    /// @param[in] period_function      Function that returns the period to spin the task by.
    /// @return  a unique handle to the registered task.
    /// @return  INVALID_TASK_HANDLE    Operation was unsuccessful.
    task_handle schedule_periodic_task(task_func task_function, repeat_period_func period_function);

    /// @brief Unschedule task.
    ///
    /// @param[in] handle     Unique handle of the task to be unscheduled.
    void unschedule_task(task_handle handle);

    /// @brief Unschedule all tasks.
    ///
    void unschedule_all_tasks();

    /// @brief Get a list of currently pending tasks, both periodic and regular.
    ///
    /// @return a container of task descriptors of all of the pending tasks.
    task_desc_container get_tasks();

    /// @brief Get the number of currently scheduled tasks.
    ///
    /// @return the number of currently scheduled tasks
    size_t get_num_tasks();

    /// @brief Execute tasks whose time has run out.
    ///
    /// @note Call this function only if spawn is not called, if the internal task scheduler thread is not being used.
    void tick();

    /// @brief Get time until next task execution.
    ///
    /// @return Remaining time until first task execution in ms.
    struct timespec get_time_until_next_task();

    /// @brief Block until next task is ready to be executed or somebody wakes us up.
    void wait_until_next_event();

    /// @brief If not spawned, spawn a worker thread.
    ///
    /// @ init_function       A function to be executed at the start of the worker thread.
    /// @return LA_STATUS_SUCCESS if thread is spawned successfully. Otherwise error code.
    la_status spawn(std::function<void()> init_function);

    /// @brief If running, terminate the worker thread.
    void terminate();

    static constexpr task_handle INVALID_TASK_HANDLE = 0;

private:
    /// @brief Schedule a task for execution.
    ///
    /// @param[in] task_function           Function to be executed.
    /// @param[in] period_function         Function that determines the period for repeating tasks. If not set than the task will
    /// not be repeated.
    /// @param[in] delay                   Delay of a non repeating task. This only has effect if period_function is not set.
    ///
    /// @return  a unique handle to the registered task.
    /// @return  INVALID_TASK_HANDLE    Operation was unsuccessful.
    task_handle schedule_task_core(task_func task_function, repeat_period_func period_function, std::chrono::milliseconds delay);

    /// @brief Calculate the next execution point of this task, update the descriptor, and put in the tasks internal container.
    ///
    /// @param[in] descriptor      Descriptor of the task to be rescheduled. Will be modified.
    ///
    /// @return  a unique handle to the registered task.
    /// @return  INVALID_TASK_HANDLE    Operation was unsuccessful.
    ///
    /// @note This function does error handling for the illegal return value of the delay function for this task.
    task_handle schedule_task_core(task_desc& descriptor);

    /// @brief Container for tasks that should be executed.
    using task_desc_list = std::list<task_desc>;

    /// @brief Get a list of tasks for execution "now".
    ///
    /// @note Repeatable tasks are re-added with updated execution time.
    task_desc_list get_tasks_for_execution();

    /// @brief Container for all of the scheduled tasks.
    task_desc_container m_tasks;

    /// @brief Mutex for synchronizing access to the class.
    std::mutex m_mutex;

    /// @brief Synchronizes task execution and unscheduling.
    std::recursive_mutex m_task_execution_recursive_mutex;

    /// @brief Implements interruptible sleep in milliseconds.
    interruptible_sleep m_interruptible_sleep;

    /// @brief Determines unique handle to be assigned to a newly scheduled task.
    task_handle m_next_handle = INVALID_TASK_HANDLE + 1;

    /// @brief Will hold the worker thread if spawn is called.
    std::unique_ptr<std::thread> m_worker_thread{nullptr};

    /// @brief While true worker thread should spin, when false it should terminate.
    std::atomic<bool> m_work{false};

    /// @brief Body of the worker thread that is created when spawn is called.
    void worker_thread(std::function<void()> init_function);

}; // class task_scheduler

} // namespace silicon_one

#endif
