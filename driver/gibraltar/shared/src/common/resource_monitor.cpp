// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/resource_monitor.h"
#include "common/logger.h"
#include <algorithm>

namespace silicon_one
{

resource_monitor::resource_monitor(const action_cb_sptr& notify,
                                   size_t max_size,
                                   size_t current_size,
                                   size_t resource_type,
                                   size_t resource_instance_idx)
    : m_notify(notify),
      m_max_size(max_size),
      m_current_size(current_size),
      m_state(0),
      m_resource_type(resource_type),
      m_resource_instance_idx(resource_instance_idx)
{
}

bool
resource_monitor::check_change()
{
    for (size_t i = 0; i < m_thresholds_vec.size(); i++) {
        if (m_current_size > m_max_size * m_thresholds_vec[i].high_watermark && m_state < (i + 1)) {
            m_state = i + 1;
            if (m_notify != nullptr) {
                (*m_notify)(m_state, m_max_size, m_current_size);
            }
            return true;
        }

        if (m_current_size < m_max_size * m_thresholds_vec[i].low_watermark && m_state > i) {
            m_state = i;
            if (m_notify != nullptr) {
                (*m_notify)(m_state, m_max_size, m_current_size);
            }

            return true;
        }
    }

    return false;
}

la_status
resource_monitor::set_thresholds(const std::vector<resource_thresholds>& thresholds_vec)
{
    // Validate threshold configuration.
    // - Sorted in increasing order of threshold (low, high) values.
    // - For each threshold pair low < high.
    // - There are no overlaps between threhsold pairs.
    for (size_t i = 0; i < thresholds_vec.size() - 1; i++) {
        bool thresholds_valid = (/* Sorted */
                                 (thresholds_vec[i].low_watermark < thresholds_vec[i + 1].low_watermark)
                                 && (thresholds_vec[i].high_watermark < thresholds_vec[i + 1].high_watermark))
                                && (/* low < high. */
                                    (thresholds_vec[i].low_watermark < thresholds_vec[i].high_watermark)
                                    && (thresholds_vec[i + 1].low_watermark < thresholds_vec[i + 1].high_watermark))
                                && (/* no overlaps */
                                    (thresholds_vec[i].high_watermark < thresholds_vec[i + 1].low_watermark));
        if (!thresholds_valid) {
            return LA_STATUS_EINVAL;
        }
    }

    m_thresholds_vec = thresholds_vec;
    check_change();

    return LA_STATUS_SUCCESS;
}

void
resource_monitor::get_thresholds(std::vector<resource_thresholds>& out_thresholds_vec) const
{
    out_thresholds_vec = m_thresholds_vec;
}

void
resource_monitor::update_size(size_t new_size)
{
    m_current_size = new_size;
    check_change();
}

void
resource_monitor::update_max_size(size_t new_max_size)
{
    m_max_size = new_max_size;
    check_change();
}

size_t
resource_monitor::get_size() const
{
    return m_current_size;
}

size_t
resource_monitor::get_max_size() const
{
    return m_max_size;
}

size_t
resource_monitor::get_state() const
{
    return m_state;
}

size_t
resource_monitor::get_resource_type() const
{
    return m_resource_type;
}

size_t
resource_monitor::get_resource_instance_idx() const
{
    return m_resource_instance_idx;
}

void
resource_monitor::offset_size(int offset)
{
    update_size(m_current_size + offset);
}

} // namespace silicon_one
