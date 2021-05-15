// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_MULTICAST_PROTECTION_GROUP_BASE_H__
#define __LA_MULTICAST_PROTECTION_GROUP_BASE_H__

#include "api/npu/la_multicast_protection_group.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_multicast_protection_group_base : public la_multicast_protection_group
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_multicast_protection_group_base(const la_device_impl_wptr& device);
    ~la_multicast_protection_group_base() override;
    la_status initialize(la_object_id_t oid,
                         const la_next_hop_wptr& primary_destination,
                         const la_system_port_wptr& primary_system_port,
                         const la_next_hop_wptr& backup_destination,
                         const la_system_port_wptr& backup_system_port,
                         const la_multicast_protection_monitor_wptr& protection_monitor);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Inherited API-s
    la_status get_monitor(const la_multicast_protection_monitor*& out_protection_monitor) const override;
    la_status get_primary_destination(const la_next_hop*& out_next_hop, const la_system_port*& out_system_port) const override;
    la_status get_backup_destination(const la_next_hop*& out_next_hop, const la_system_port*& out_system_port) const override;
    la_status modify_protection_group(const la_next_hop* primary_destination,
                                      const la_system_port* primary_system_port,
                                      const la_next_hop* backup_destination,
                                      const la_system_port* backup_system_port,
                                      const la_multicast_protection_monitor* protection_monitor) override;

private:
    la_status verify_parameters(const la_next_hop_wcptr& primary_dest,
                                const la_system_port_wcptr& primary_sys_port,
                                const la_next_hop_wcptr& backup_dest,
                                const la_system_port_wcptr& backup_sys_port,
                                const la_multicast_protection_monitor_wcptr& monitor) const;
    la_status check_destination(const la_next_hop_wcptr& destination, const la_system_port_wcptr& sys_port) const;

    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Primary/Backup paths
    la_next_hop_wcptr m_primary_dest;
    la_next_hop_wcptr m_backup_dest;
    la_system_port_wcptr m_primary_sys_port;
    la_system_port_wcptr m_backup_sys_port;

    // Monitor
    la_multicast_protection_monitor_wcptr m_monitor;

    la_multicast_protection_group_base() = default; // For serialization only
};

} // namespace  silicon_one

#endif // __LA_MULTICAST_PROTECTION_GROUP_BASE_H__
