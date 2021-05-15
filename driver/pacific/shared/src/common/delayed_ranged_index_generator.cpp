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

#include "common/delayed_ranged_index_generator.h"
#include "common/dassert.h"

/// @file
/// @brief Delayed ranged index generator.

namespace silicon_one
{

delayed_ranged_index_generator::delayed_ranged_index_generator(uint64_t lower_bound,
                                                               uint64_t upper_bound,
                                                               std::chrono::microseconds delayed_threshold)
    : m_lower_bound(lower_bound),
      m_upper_bound(upper_bound),
      m_index_gen(lower_bound, upper_bound),
      m_delayed_release_threshold(delayed_threshold),
      m_delayed_array(upper_bound - lower_bound)
{
    dassert_crit(upper_bound > lower_bound);
}

void
delayed_ranged_index_generator::check_for_delayed_release()
{
    for (uint64_t ix = 0; ix < (m_upper_bound - m_lower_bound); ix++) {
        if (!m_delayed_array[ix].is_running()) {
            continue;
        }

        m_delayed_array[ix].stop();
        std::chrono::nanoseconds elapsed = std::chrono::nanoseconds(m_delayed_array[ix].get_total_elapsed_time());
        if (elapsed < m_delayed_release_threshold) {
            // Restart the stopwatch
            m_delayed_array[ix].start();
        } else {
            // Reset the stopwatch and release this profile. Only release one profile per call.
            m_delayed_array[ix].reset();
            m_index_gen.release(ix);
            break;
        }
    }
}

uint64_t
delayed_ranged_index_generator::allocate()
{
    // First check if we can release entries that were previously marked as delayed.
    check_for_delayed_release();

    return m_index_gen.allocate();
}

void
delayed_ranged_index_generator::release(uint64_t index)

{
    uint64_t ix;

    dassert_crit(index >= m_lower_bound && index < m_upper_bound);

    ix = index - m_lower_bound;

    // Check if we need to delay the release.
    if (m_delayed_release_threshold != std::chrono::microseconds(0)) {
        m_delayed_array[ix].start();
        return;
    }

    m_index_gen.release(index);
}

} // namespace silicon_one
