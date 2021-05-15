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

#ifndef __LA_PROFILE_DATABASE_H__
#define __LA_PROFILE_DATABASE_H__

#include "api/types/la_common_types.h"
#include "common/allocator_wrapper.h"
#include "common/defines.h"
#include "common/logger.h"
#include <atomic>
#include <utility>

namespace silicon_one
{
/// @brief Profiling database
class la_profile_database
{

public:
    /// @brief Report sorting criteria.
    enum class sort_criteria_e {
        TOTAL = 0,   ///< Total time counted for this profiler.
        INVOCATIONS, ///< Number of invocations for this profiler.
        MAX,         ///< Max instance time counted for this profiler.
        NONE,        ///< No sorting.
    };

    /// @brief A structure to hold collected data from one profile.
    struct profile_stats {
#ifndef SWIG
        std::atomic<la_uint64_t> count{0};        ///< Number of calls.
        std::atomic<la_uint64_t> total_cycles{0}; ///< Amount of CPU cycles of all executions profile.
        std::atomic<la_uint64_t> max_cycles{0};   ///< Amount of CPU cycles for a max instance execution.
#else
        la_uint64_t count{0};        ///< Number of calls.
        la_uint64_t total_cycles{0}; ///< Amount of CPU cycles of all executions profile.
        la_uint64_t max_cycles{0};   ///< Amount of CPU cycles for a max instance execution.
#endif
        la_device_id_t device_id; ///< Device Id.
    };

    struct profile_description {
        const char* containing_function; ///< Name of the fucntion that contains the profile.
        const char* text;                ///< Desciprition of the profile.
    };

    /// @brief Print basic data collected from profilers.
    void report();

    /// @brief Print basic data collected from profilers.
    ///
    /// @param[in] device_id                    Device whose measurements are being read.
    /// Use #silicon_one::logger::NUM_DEVICES to print data for all devices.
    /// @param[in] sort_criteria                Criteria according to which SDK profiler report is sorted.
    /// @param[in] name_filter                  Regular expression to filter profiles with.
    /// Passing an empty string results in no filtering.
    void report(la_device_id_t device_id, sort_criteria_e sort_criteria, const std::string& name_filter);

    /// @brief Print basic data collected from profilers.
    ///
    /// @param[in] device_id                    Device whose measurements are being read.
    /// Use #silicon_one::logger::NUM_DEVICES to print data for all devices.
    /// @param[in] sort_criteria                Criteria according to which SDK profiler report is sorted.
    /// @param[in] name_filter                  Regular expression to filter profiles with.
    /// Passing an empty string results in no filtering.
    /// @param[in] output_stream               Stream where data is being written.
    void report(la_device_id_t device_id,
                sort_criteria_e sort_criteria,
                const std::string& name_filter,
                std::ostream& output_stream);

    /// @brief Clear all stored profiling data.
    void reset();

    /// @brief Register profiler in the database.
    ///
    /// @param[in] function_name       Name of the function containing the profile.
    /// @param[in] text                Description of the profile.
    ///
    /// @return                        Pointer to array of profile_stats across all devices for the profile that just got
    /// registered.
    profile_stats* register_profiler(const char* function_name, const char* text);

    /// @brief return an instance of the profile database.
    ///
    /// @return Singleton instance of the database.
    static la_profile_database& get_instance()
    {
        return m_db_instance;
    }

private:
    using la_database_profile_index = size_t;

    using profile_index_pair = std::pair<la_database_profile_index, la_database_profile_index>;

    static constexpr la_database_profile_index NUM_PROFILES = 8192;

    /// @brief la_profile_database constuctor.
    la_profile_database();

    /// @brief Check if profile with index matches name_filter.
    ///
    /// @param[in] index            Index of the profile description.
    ///
    /// @param[in] name_filter      Regular expression to filter profile with.
    ///
    /// @return                     True in case the profile matches name_filter, otherwise false.
    bool filter_profiler(size_t index, const std::string& name_filter);

    /// @brief Acquire CPU frequency.
    void read_cpu_frequency();

    /// @brief Converts time in cycles to time in seconds + unit.
    std::string time_to_string(la_uint64_t time_in_cycles);

    /// @brief Print header in profiler report.
    void print_header();

    /// @brief Database of profiles, arranged as a two dimensional array.
    profile_stats m_database[NUM_PROFILES][silicon_one::logger::NUM_DEVICES + 1];

    /// @brief Counter that tracks amount of registered profiles.
    la_database_profile_index m_current_index;

    /// @brief Array of profile descriptions.
    profile_description m_profile_descriptions[NUM_PROFILES];

    static la_profile_database m_db_instance;

    /// @brief Frequency of the CPU, in kHz.
    size_t m_cpu_freq;
};
}; /// namespace silicon_one

#endif //__LA_PROFILE_DATABASE_H__
