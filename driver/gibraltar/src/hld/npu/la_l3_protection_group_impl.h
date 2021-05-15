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

#ifndef __LA_L3_PROTECTION_GROUP_IMPL_H__
#define __LA_L3_PROTECTION_GROUP_IMPL_H__

#include "api/npu/la_l3_protection_group.h"
#include "api/types/la_ip_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "resolution_configurator.h"
#include <vector>

namespace silicon_one
{

class la_l3_protection_group_impl : public la_l3_protection_group, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // la_l3_protection_group_impl API-s
    explicit la_l3_protection_group_impl(const la_device_impl_wptr& device);

    ~la_l3_protection_group_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    la_status initialize(la_object_id_t oid,
                         la_l3_port_gid_t group_gid,
                         const la_l3_destination_wcptr& primary_destination,
                         const la_l3_destination_wcptr& backup_destination,
                         const la_protection_monitor_wcptr& protection_monitor);

    la_status destroy();

    // la_l3_protection_group API-s
    la_status get_monitor(const la_protection_monitor*& out_protection_monitor) const override;
    la_status set_monitor(const la_protection_monitor* protection_monitor) override;
    la_l3_port_gid_t get_gid() const override;

    la_status get_primary_destination(const la_l3_destination*& out_l3_destination) const override;
    la_status get_backup_destination(const la_l3_destination*& out_l3_destination) const override;
    la_status modify_protection_group(const la_l3_destination* primary_destination,
                                      const la_l3_destination* backup_destination,
                                      const la_protection_monitor* protection_monitor) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API helpers
    destination_id get_destination_id(resolution_step_e prev_step) const;
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);
    la_status get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const;

    static const la_l3_protection_group_gid_t LA_L3_PROTECTION_GROUP_GID_INVALID = (la_l3_protection_group_gid_t)(-1);

private:
    // Resolution helper functions
    la_status get_stage1_table_protection_member_entry(const la_l3_destination_wcptr& protection_member_dest,
                                                       npl_wide_protection_entry_t& value);

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper functions for adding/removing attribute dependency
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);
    void register_attribute_dependency(const la_l3_destination_wcptr& destination);
    void deregister_attribute_dependency(const la_l3_destination_wcptr& destination);

    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // L3 protection group GID
    la_l3_protection_group_gid_t m_gid;

    // L3 protection group primary destination
    la_l3_destination_wcptr m_primary_destination;

    // L3 protection group backup destination
    la_l3_destination_wcptr m_backup_destination;

    // L3 protection group protection monitor
    la_protection_monitor_wcptr m_protection_monitor;

    resolution_cfg_handle_t m_res_cfg_handle;

    // Resolution API helpers
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;

    // General functions
    la_status check_destination(la_l3_protection_group_gid_t group_gid,
                                const la_l3_destination_wcptr& primary_destination,
                                const la_l3_destination_wcptr& backup_destination,
                                const la_protection_monitor_wcptr& protection_monitor) const;

    // Manage the resolution table configuration
    la_status configure_resolution_step();
    la_status teardown_resolution_step();

    la_l3_protection_group_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_L3_PROTECTION_GROUP_IMPL_H__
