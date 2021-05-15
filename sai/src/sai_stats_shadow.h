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

#ifndef __SAI_STATS_SHADOW_H__
#define __SAI_STATS_SHADOW_H__

#include <string>
#include <chrono>

namespace silicon_one
{
namespace sai
{

template <typename T>
class lsai_stats_shadow
{
public:
    la_status get_data(std::shared_ptr<lsai_device>& sdev, T*& data_ptr, sai_stats_mode_t mode)
    {
        if (mode != m_last_mode) {
            return LA_STATUS_EINVAL;
        }

        std::chrono::milliseconds age_out = std::chrono::milliseconds(sdev->m_counter_refresh_interval);
        auto time_since_last_update = std::chrono::steady_clock::now() - m_last_shadow_update;
        if (time_since_last_update >= age_out) {
            return LA_STATUS_EINVAL;
        }
        data_ptr = &m_data;
        return LA_STATUS_SUCCESS;
    }

    void set_data(T& data, sai_stats_mode_t mode)
    {
        m_last_shadow_update = std::chrono::steady_clock::now();
        m_data = data;
        m_last_mode = mode;
    }

private:
    sai_stats_mode_t m_last_mode;
    std::chrono::time_point<std::chrono::steady_clock> m_last_shadow_update{};
    T m_data;
};
}
}
#endif
