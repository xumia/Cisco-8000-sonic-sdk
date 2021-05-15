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

#ifndef __LA_PROFILE_H__
#define __LA_PROFILE_H__

#include <algorithm>
#include <atomic>

#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/la_profile_database.h"
#include "common/logger.h"

#define start_named_profiler(var_name, description)                                                                                \
    static la_profile_database::profile_stats* stats_##var_name                                                                    \
        = la_profile_database::get_instance().register_profiler(__PRETTY_FUNCTION__, description);                                 \
    la_profiler var_name(stats_##var_name);

#define start_scoped_profiler(description)                                                                                         \
    static la_profile_database::profile_stats* concat_tokens(__stats_, __LINE__)                                                   \
        = la_profile_database::get_instance().register_profiler(__PRETTY_FUNCTION__, description);                                 \
    la_profiler concat_tokens(__profiler_, __LINE__)(concat_tokens(__stats_, __LINE__));

#define get_profiling_type(_1, _2, NAME, ...) NAME

#ifdef __aarch64__
#define START_ASM_MEASUREMENT __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(m_start_time.higher_lower[0]));
#else
#define START_ASM_MEASUREMENT                                                                                                      \
    __asm__ __volatile__("rdtsc" : "=a"(m_start_time.higher_lower[0]), "=d"(m_start_time.higher_lower[1]));
#endif

#ifdef __aarch64__
#define END_ASM_MEASUREMENT __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(m_end_time.higher_lower[0]));
#else
#define END_ASM_MEASUREMENT __asm__ __volatile__("rdtsc" : "=a"(m_end_time.higher_lower[0]), "=d"(m_end_time.higher_lower[1]));
#endif

/// @note profiling API usage
///
/// All usage of the API will be through start_profiling(...) macro.
/// In case we want to start profiling from a certain point in code until the end of
/// current scope, we enter only one argument to the profiler, a text that will be used
/// as description of the profile, used when reporting profile statistics.
/// ex.
/// { ...
///     start_profiling("Slow code section")
///     ... //section in question
/// }
/// If we want to use the profiler to measure performance of a segement of code before
/// end of scope we enter two arguments in the macro, name of the variable to used
/// later to stop measurements, and again the description of the profiler
/// ex.
/// start_profiling(my_profiler, "testing register access speed")
/// ... //code being profiled
/// my_profiler.stop();

#define start_profiling(...) get_profiling_type(__VA_ARGS__, start_named_profiler, start_scoped_profiler)(__VA_ARGS__)

namespace silicon_one
{
/// @brief Profiler data collection helper.
///
/// Collects execution statistics for the given code scope/section.
/// Call count is one per each la_profile instantiation.
/// Time measured start on la_profiler creation, and end on a call to stop() or the la_profiler's destruction.
class la_profiler
{
public:
    /// @brief Profiler constructor.
    ///
    /// Registers a profiler with the database
    ///
    /// @param[in] stats        Pointer to position in database to which data will be written
    la_profiler(la_profile_database::profile_stats* stats) : m_stats(stats)
    {
        m_stats += silicon_one::get_device_id();
#ifdef __aarch64__
        __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(m_start_time.rdtsc_hi_lo[0]));
#else
        __asm__ __volatile__("rdtsc" : "=a"(m_start_time.rdtsc_hi_lo[0]), "=d"(m_start_time.rdtsc_hi_lo[1]));
#endif
    }

    /// @brief Profiler destructor
    ///
    /// Sends time data to the profile database.
    ~la_profiler()
    {
        if (m_is_stopped) {
            return;
        }
        stop();
    }

    /// @brief Stop measuring time and update the profiling database.
    void stop()
    {
        if (m_is_stopped) {
            return;
        }
#ifdef __aarch64__
        __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(m_end_time.rdtsc_hi_lo[0]));
#else
        __asm__ __volatile__("rdtsc" : "=a"(m_end_time.rdtsc_hi_lo[0]), "=d"(m_end_time.rdtsc_hi_lo[1]));
#endif
        la_uint64_t diff = m_end_time.cycles - m_start_time.cycles;
        m_stats->count++;
        m_stats->total_cycles += diff;
#ifndef SWIG
        m_stats->max_cycles = std::max(std::atomic_load(&m_stats->max_cycles), diff);
#else
        m_stats->max_cycles = std::max(m_stats->max_cycles, diff);
#endif

        m_is_stopped = true;
    }

private:
    union time_union {
        la_uint32_t rdtsc_hi_lo[2]; ///< Assembler call stores the timestamp split into two 32-bit integers.
        la_uint64_t cycles;         ///< Full timestamp.
    };

    la_profile_database::profile_stats* m_stats = nullptr; ///< The index of the profiler inside the database.
    time_union m_start_time;                               ///< Time when the profiling started.
    time_union m_end_time;                                 ///< Time when the profiling ended.
    bool m_is_stopped = false;                             ///< Whether profiler was manually stopped by a call to stop().
};

} // namespace silicon_one

#endif //__PROFILER_H__
