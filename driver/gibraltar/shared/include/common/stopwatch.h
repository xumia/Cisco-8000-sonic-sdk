// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_STOPWATCH_H__
#define __LEABA_STOPWATCH_H__

#include "common/cereal_utils.h"
#include "common/logger.h"
#include <errno.h>
#include <stdint.h>
#include <time.h>

/// @file
/// @brief Stopwatch class definition.

namespace silicon_one
{

/// @brief Stopwatch.
///
/// Provides the interval time between the last start/stop calls, and accumulated time of all intervals.
class stopwatch
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    /// @brief Time units
    ///
    /// Should be in sync with convert_nsec_to_time_unit::time_unit_scale_arr
    enum class time_unit_e {
        NS,  ///< Nano-seconds
        US,  ///< Micro-seconds
        MS,  ///< Milli-seconds
        SEC, ///< Seconds

        LAST = SEC
    };

    /// @brief Stopwatch constructor
    stopwatch()
    {
        reset();
    }

    /// @brief Stopwatch destructor
    ~stopwatch()
    {
    }

    /// @brief Reset a stopwatch.
    ///
    /// Stops the stopwatch and clears its total accumulated time.
    void reset()
    {
        m_total_elapsed_time = 0;
        m_is_running = false;
    }

    /// @brief Starts the stopwatch.
    void start()
    {
        if (m_is_running) {
            log_err(COMMON, "%s: start called while stopwatch is already running", __PRETTY_FUNCTION__);
        }

        int retval = clock_gettime(CLOCK_MONOTONIC, &m_start_time);
        if (retval == 0) {
            m_is_running = true;
        } else {
            log_err(COMMON, "%s: call to clock_gettime failed with retval=%d, errno=%u", __PRETTY_FUNCTION__, retval, errno);
            m_is_running = false;
        }
    }

    /// @brief Stops the stopwatch and accumulates current interval time to the total.
    ///
    /// @see #start
    ///
    /// @return Interval time in nanoseconds from the last start() call.
    uint64_t stop()
    {
        if (!m_is_running) {
            log_err(COMMON, "%s: stop called while stopwatch is not running", __PRETTY_FUNCTION__);
            return -1;
        }

        m_is_running = false;

        int retval = clock_gettime(CLOCK_MONOTONIC, &(m_end_time));
        if (retval != 0) {
            log_err(COMMON, "%s: call to clock_gettime failed with retval=%d, errno=%u", __PRETTY_FUNCTION__, retval, errno);

            return -1;
        }

        uint64_t interval_time_nsec = get_interval_time();
        m_total_elapsed_time += interval_time_nsec;

        return interval_time_nsec;
    }

    /// @brief Returns the measured interval time in nanoseconds
    ///
    /// @return Interval time in nanoseconds between the last start and stop
    uint64_t get_interval_time() const;

    /// @brief Returns the measured interval time in requested time unit.
    ///
    /// @param[in]  time_unit    Time unit.
    ///
    /// @return Interval time in requested time unit between the last start and stop
    uint64_t get_interval_time(const time_unit_e time_unit) const;

    /// @brief Returns the total elapsed time in nanoseconds
    ///
    /// @return The total elapsed time of all invervals in nanoseconds
    uint64_t get_total_elapsed_time() const;

    /// @brief Returns the total elapsed time in in requested time unit.
    ///
    /// @param[in]  time_unit    Time unit.
    ///
    /// @return The total elapsed time of all invervals in in requested time unit
    uint64_t get_total_elapsed_time(const time_unit_e time_unit) const;

    /// @brief Get the stopwatch state.
    ///
    /// @return true if the stopwatch is running, false otherwise.
    bool is_running() const;

private:
    /// @brief Time unit scale constants
    enum {
        NANOSECONDS_IN_NANOSECOND = 1,
        NANOSECONDS_IN_MICROSECOND = 1000,
        NANOSECONDS_IN_MILLISECOND = 1000 * 1000,
        NANOSECONDS_IN_SECOND = 1000 * 1000 * 1000
    };

    /// @brief converts time in nanoseconds to another time unit.
    ///
    /// @param[in]  time_in_nsec
    /// @param[in]  result_time_unit
    ///
    /// @return Time in requested time units.
    uint64_t convert_nsec_to_time_unit(const uint64_t time_in_nsec, const time_unit_e result_time_unit) const;

    struct timespec m_start_time;  ///< Stopwatch start time
    struct timespec m_end_time;    ///< Stopwatch end time
    uint64_t m_total_elapsed_time; ///< Sum of elapsed time from all start->stop periods
    bool m_is_running;             ///< Stopwatch state
};

} // namespace silicon_one

#endif
