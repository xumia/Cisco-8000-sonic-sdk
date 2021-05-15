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

#ifndef __LA_PROTECTION_MONITOR_IMPL_H__
#define __LA_PROTECTION_MONITOR_IMPL_H__

#include "api/npu/la_protection_monitor.h"
#include "api/types/la_ip_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "resolution_configurator.h"

namespace silicon_one
{

class la_protection_monitor_impl : public la_protection_monitor
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // la_protection_monitor_impl API-s
    explicit la_protection_monitor_impl(const la_device_impl_wptr& device);
    ~la_protection_monitor_impl() override;
    la_status initialize(la_object_id_t oid, la_protection_monitor_gid_t protection_monitor_gid);
    la_status destroy();
    la_protection_monitor_gid_t get_gid() const;

    // la_protection_monitor API-s
    la_status set_state(monitor_state_e state) override;
    la_status get_state(monitor_state_e& out_state) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API helpers
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

private:
    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};
    // Protection monitor ID
    la_protection_monitor_gid_t m_gid;

    // Address of table entry
    resolution_cfg_handle_t m_stage0_cfg_handle;
    resolution_cfg_handle_t m_stage1_cfg_handle;

    // Protection monitor State
    monitor_state_e m_state;

    // Resolution related data
    struct resolution_data {
        resolution_data();
        la_uint_t users_for_step[RESOLUTION_STEP_LAST];
    } m_resolution_data;
    CEREAL_SUPPORT_PRIVATE_CLASS(resolution_data);

    // Resolution API helpers
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;

    // Manage the resolution table configuration
    la_status configure_resolution_step(resolution_step_e cur_step);
    la_status configure_stage1_protection_table();
    la_status configure_stage2_protection_table();
    la_status teardown_resolution_step(resolution_step_e cur_step);
    la_status teardown_stage1_protection_table();
    la_status teardown_stage2_protection_table();

    la_protection_monitor_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_PROTECTION_MONITOR_IMPL_H__
