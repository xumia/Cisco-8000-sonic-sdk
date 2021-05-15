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

#include "common/stopwatch.h"

using namespace std;

namespace silicon_one
{
uint64_t
stopwatch::get_interval_time() const
{
    if (m_is_running) {
        log_err(COMMON, "%s: cannot get interval time for a running stopwatch", __PRETTY_FUNCTION__);
        return -1;
    }

    return (m_end_time.tv_sec - m_start_time.tv_sec) * NANOSECONDS_IN_SECOND + (m_end_time.tv_nsec - m_start_time.tv_nsec);
}

uint64_t
stopwatch::get_interval_time(const time_unit_e time_unit) const
{
    uint64_t interval_time = get_interval_time();
    interval_time = convert_nsec_to_time_unit(interval_time, time_unit);

    return interval_time;
}

uint64_t
stopwatch::get_total_elapsed_time() const
{
    if (m_is_running) {
        log_err(COMMON, "%s: cannot get total elapsed time for a running stopwatch", __PRETTY_FUNCTION__);
        return -1;
    }

    return m_total_elapsed_time;
}

uint64_t
stopwatch::get_total_elapsed_time(const time_unit_e time_unit) const
{
    uint64_t total_elapsed_time = get_total_elapsed_time();
    total_elapsed_time = convert_nsec_to_time_unit(total_elapsed_time, time_unit);

    return total_elapsed_time;
}

bool
stopwatch::is_running() const
{
    return m_is_running;
}

uint64_t
stopwatch::convert_nsec_to_time_unit(const uint64_t time_in_nsec, const time_unit_e result_time_unit) const
{
    if (result_time_unit > time_unit_e::LAST) {
        log_err(COMMON, "Unknown time_unit=%d", (int)result_time_unit);
        return -1;
    }

    // time_unit_scale_arr should be in sync with stopwatch::time_unit_e.
    const uint64_t time_unit_scale_arr[] = {[(int)time_unit_e::NS] = NANOSECONDS_IN_NANOSECOND,
                                            [(int)time_unit_e::US] = NANOSECONDS_IN_MICROSECOND,
                                            [(int)time_unit_e::MS] = NANOSECONDS_IN_MILLISECOND,
                                            [(int)time_unit_e::SEC] = NANOSECONDS_IN_SECOND};

    return time_in_nsec / time_unit_scale_arr[(size_t)result_time_unit];
}

} // namespace silicon_one
