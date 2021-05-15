// BEGIN_LEGAL
//
// Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __INIT_PERFORMANCE_HELPER_BASE_H__
#define __INIT_PERFORMANCE_HELPER_BASE_H__

#include "api/system/la_css_memory_layout.h"
#include "api/system/la_device.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class init_performance_helper_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit init_performance_helper_base(const la_device_impl_wptr& device);
    ~init_performance_helper_base();

    la_status reset();
    la_status set_init_completed() const;
    bool is_optimization_enabled() const;

private:
    init_performance_helper_base(); // Required for Serialization

    la_device_impl_wptr m_device;

    la_status store_to_css(const bool init_completed) const;
    la_status load_from_css(bool& out_init_completed) const;

    struct LA_PACKED init_metadata {
        uint32_t boot_state;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(init_metadata)
    static_assert(sizeof(init_metadata) == 1 * sizeof(uint32_t), "");

    bool m_optimization_enabled;
};

} // namespace silicon_one

#endif // __INIT_PERFORMANCE_HELPER_BASE_H__
