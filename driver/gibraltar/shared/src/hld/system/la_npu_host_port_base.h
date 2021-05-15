// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_NPU_HOST_PORT_BASE_H__
#define __LA_NPU_HOST_PORT_BASE_H__

#include <memory>

#include "api/system/la_mac_port.h"
#include "api/system/la_npu_host_port.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

constexpr la_mac_port::port_speed_e NPU_HOST_PORT_DEFAULT_SPEED = la_mac_port::port_speed_e::E_100G;

class la_npu_host_port_base : public la_npu_host_port
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    la_npu_host_port_base(const la_device_impl_wptr& device);
    ~la_npu_host_port_base() override;

    // Object life-cycle API-s
    virtual la_status initialize(la_object_id_t oid,
                                 la_remote_device* remote_device,
                                 la_system_port_gid_t system_port,
                                 la_voq_set* voq_set,
                                 const la_tc_profile* tc_profile)
        = 0;

    la_status initialize_resources(la_slice_id_t slice, la_ifg_id_t ifg, la_object_id_t oid);

    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_npu_host_port API-s
    la_interface_scheduler* get_scheduler() const override;

    const la_system_port* get_system_port() const override;

    la_status get_speed(la_mac_port::port_speed_e& out_speed) const;

    bool is_remote() const;

protected:
    la_npu_host_port_base() = default;
    la_status set_redirect_destination(la_slice_id_t slice, la_ifg_id_t ifg);

    virtual la_status set_slice_source_pif_entry() = 0;
    virtual la_status erase_slice_source_pif_entry() = 0;

    virtual la_status initialize_remote(la_remote_device* remote_device,
                                        la_system_port_gid_t system_port_gid,
                                        la_voq_set* voq_set,
                                        const la_tc_profile* tc_profile)
        = 0;

    la_status initialize_local(la_system_port_gid_t system_port_gid, la_voq_set* voq_set, const la_tc_profile* tc_profile);

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Scheduler
    la_interface_scheduler_impl_wptr m_scheduler;

    // System Port
    la_system_port_base_wptr m_system_port;

    // Remote port
    la_remote_port_impl_wptr m_remote_port;

    // Port speed
    la_mac_port::port_speed_e m_speed;
};

} // namespace silicon_one

#endif // __LA_NPU_HOST_PORT_BASE_H__
