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

#include <iostream>

#include "common/la_profile_database.h"
#include "common/logger.h"
#include <cmath>
#include <iomanip>
#include <numeric>
#include <regex>
#include <sstream>
#include <string.h>

#define MAX_DECIMAL_DIGITS_IN_UINT64 19

namespace silicon_one
{

la_profile_database::la_profile_database()
{
    m_current_index = 0;
    read_cpu_frequency();
}

void
la_profile_database::print_header()
{
    std::cout << "Profile database report (detected processor speed " << (m_cpu_freq / 1000) << "MHz)\n";
}

std::string
la_profile_database::time_to_string(la_uint64_t time_in_cycles)
{
    std::string unit;
    std::ostringstream result;
    double time_in_sec = time_in_cycles * 1.0 / (m_cpu_freq * 1000);

    // The value is multiplied by 10 to keep one decimal point.
    if (time_in_sec < 1e-6) { // order of magnitude: nanoseconds
        unit = "ns";
        time_in_sec *= 1e9 * 10;
    } else if (time_in_sec < 1e-3) { // order of magnitude: microseconds
        unit = "us";
        time_in_sec *= 1e6 * 10;
    } else if (time_in_sec < 1.0) { // order of magnitude: milliseconds
        unit = "ms";
        time_in_sec *= 1e3 * 10;
    } else {
        unit = "s"; // order of magnitude: seconds
        time_in_sec *= 10.0;
    }
    // Value scaled back.
    time_in_sec = std::trunc(time_in_sec) / 10.0;

    result << time_in_sec << unit;
    return result.str();
}

static bool
la_profile_sort_total(const la_profile_database::profile_stats& first_profile_stats,
                      const la_profile_database::profile_stats& second_profile_stats)
{
    return (first_profile_stats.total_cycles < second_profile_stats.total_cycles);
}

static bool
la_profile_sort_max(const la_profile_database::profile_stats& first_profile_stats,
                    const la_profile_database::profile_stats& second_profile_stats)
{
    return (first_profile_stats.max_cycles < second_profile_stats.max_cycles);
}

static bool
la_profile_sort_invocations(const la_profile_database::profile_stats& first_profile_stats,
                            const la_profile_database::profile_stats& second_profile_stats)
{
    return (first_profile_stats.count < second_profile_stats.count);
}

void
la_profile_database::report()
{
    print_header();
    report(silicon_one::logger::NUM_DEVICES, sort_criteria_e::TOTAL, "" /* name_filter */, std::cout);
}

void
la_profile_database::report(la_device_id_t device_id, sort_criteria_e sort_criteria, const std::string& name_filter)
{
    report(device_id, sort_criteria, name_filter, std::cout);
}

void
la_profile_database::report(la_device_id_t device_id,
                            sort_criteria_e sort_criteria,
                            const std::string& name_filter,
                            std::ostream& ooutput_stream)
{
    vector_alloc<profile_index_pair> profile_index_pairs;
    for (la_database_profile_index i = 0; i < m_current_index; i++) {
        if (!filter_profiler(i, name_filter)) {
            continue;
        }

        std::vector<la_database_profile_index> devices(
            device_id == silicon_one::logger::NUM_DEVICES ? silicon_one::logger::NUM_DEVICES : 1);
        std::iota(devices.begin(), devices.end(), device_id == silicon_one::logger::NUM_DEVICES ? 0 : device_id);

        for (auto& device : devices) {
            if (m_database[i][device].count != 0) {
                m_database[i][device].device_id = device;
                profile_index_pair current_pair = std::make_pair(i, device);
                profile_index_pairs.push_back(current_pair);
            }
        }
    }

    switch (sort_criteria) {
    case sort_criteria_e::TOTAL: {
        std::sort(profile_index_pairs.begin(),
                  profile_index_pairs.end(),
                  [&](profile_index_pair const& first_pair, profile_index_pair const& second_pair) {
                      la_database_profile_index const& first_index = first_pair.first;
                      la_database_profile_index const& first_device = first_pair.second;
                      la_database_profile_index const& second_index = second_pair.first;
                      la_database_profile_index const& second_device = second_pair.second;
                      return la_profile_sort_total(m_database[first_index][first_device], m_database[second_index][second_device]);
                  });
        break;
    }
    case sort_criteria_e::INVOCATIONS: {
        std::sort(profile_index_pairs.begin(),
                  profile_index_pairs.end(),
                  [&](profile_index_pair const& first_pair, profile_index_pair const& second_pair) {
                      la_database_profile_index const& first_index = first_pair.first;
                      la_database_profile_index const& first_device = first_pair.second;
                      la_database_profile_index const& second_index = second_pair.first;
                      la_database_profile_index const& second_device = second_pair.second;
                      return la_profile_sort_invocations(m_database[first_index][first_device],
                                                         m_database[second_index][second_device]);
                  });
        break;
    }
    case sort_criteria_e::MAX: {
        std::sort(profile_index_pairs.begin(),
                  profile_index_pairs.end(),
                  [&](profile_index_pair const& first_pair, profile_index_pair const& second_pair) {
                      la_database_profile_index const& first_index = first_pair.first;
                      la_database_profile_index const& first_device = first_pair.second;
                      la_database_profile_index const& second_index = second_pair.first;
                      la_database_profile_index const& second_device = second_pair.second;
                      return la_profile_sort_max(m_database[first_index][first_device], m_database[second_index][second_device]);
                  });
        break;
    }
    case sort_criteria_e::NONE: {
        break;
    }
    }

    for (auto& curr_index_pair : profile_index_pairs) {
        auto& curr_index = curr_index_pair.first;
        auto& curr_device = curr_index_pair.second;
        auto& curr_description = m_profile_descriptions[curr_index];
        auto& curr_stats = m_database[curr_index][curr_device];
        ooutput_stream << "Profile: " << curr_description.containing_function << ": " << curr_description.text << "\n";
        ooutput_stream << "\tDevice no. " << curr_stats.device_id << "\n";
        ooutput_stream << "\t\t"
                       << "Executions: " << std::setw(MAX_DECIMAL_DIGITS_IN_UINT64) << curr_stats.count;
        ooutput_stream << "\t\t"
                       << "Total: " << std::setw(MAX_DECIMAL_DIGITS_IN_UINT64) << curr_stats.total_cycles;
        ooutput_stream << "\t\tAVG: " << std::setw(MAX_DECIMAL_DIGITS_IN_UINT64) << curr_stats.total_cycles / curr_stats.count
                       << " / " << time_to_string(curr_stats.total_cycles / curr_stats.count);
        ooutput_stream << "\t\tMAX: " << std::setw(MAX_DECIMAL_DIGITS_IN_UINT64) << curr_stats.max_cycles << "\n";
    }
}

bool
la_profile_database::filter_profiler(size_t index, const std::string& name_filter)
{
    std::regex regexp(name_filter);
    std::smatch matched_sequence;

    if (name_filter == "") {
        return true;
    }

    std::string name_of_current_function = m_profile_descriptions[index].containing_function;
    std::regex_search(name_of_current_function, matched_sequence, regexp);

    return !matched_sequence.empty();
}

void
la_profile_database::read_cpu_frequency()
{
    size_t frequency;
    FILE* f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

    if (f == nullptr) {
        log_info(COMMON, "Couldn't open scaling_min_freq, setting frequency scaling to 1 ghz");
        m_cpu_freq = 1000000;
        return;
    }
    fscanf(f, "%lu", &frequency);
    fclose(f);

    m_cpu_freq = frequency;
    return;
}

void
la_profile_database::reset()
{
    size_t num_bytes = sizeof(m_database);
    memset(m_database, 0, num_bytes);
}

la_profile_database::profile_stats*
la_profile_database::register_profiler(const char* function_name, const char* text)
{
    profile_stats* ret = m_database[m_current_index];
    if (LA_UNLIKELY(m_current_index >= NUM_PROFILES)) {
        m_current_index = NUM_PROFILES - 1;
        log_err(COMMON, "Profile %s : %s would have index: %lu out of bounds", function_name, text, m_current_index);
        return nullptr;
    }
    m_profile_descriptions[m_current_index].containing_function = function_name;
    m_profile_descriptions[m_current_index].text = text;

    m_current_index++;

    return ret;
}

la_profile_database la_profile_database::m_db_instance;

} // namespace silicon_one
