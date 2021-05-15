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

#ifndef __LA_PBTS_GROUP_IMPL_H__
#define __LA_PBTS_GROUP_IMPL_H__

#include <vector>

#include "api/npu/la_pbts_group.h"
#include "api/types/la_ip_types.h"
#include "common/cereal_utils.h"
#include "common/transaction.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "resolution_utils.h"

#include "nplapi/nplapi_tables.h"
#include "system/la_pbts_map_profile_impl.h"

namespace silicon_one
{

class la_pbts_group_impl : public la_pbts_group
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_pbts_group_impl() = default;
    //////////////////////////////
public:
    explicit la_pbts_group_impl(const la_device_impl_wptr& device);
    ~la_pbts_group_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op);

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_pbts_map_profile* profile);
    la_status destroy();

    // Inherited API-s
    la_status get_member(la_pbts_destination_offset offset, const la_l3_destination*& out_member) const override;
    la_status set_member(la_pbts_destination_offset offset, const la_l3_destination* member) override;
    const la_pbts_map_profile* get_profile() const override;

    // la_object API-s
    object_type_e type() const override;
    la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

private:
    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;
    resolution_table_index get_id_in_step(resolution_step_e res_step) const;

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper functions for adding/removing attribute dependency
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);
    void register_attribute_dependency(const la_l3_destination_wcptr& destination);
    void deregister_attribute_dependency(const la_l3_destination_wcptr& destination);

    // Device this PBTS group belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // PBTS MAP Profile
    la_pbts_map_profile_impl_wptr m_profile;

    // Layer-3 destinations comprising the PBTS group
    std::vector<la_l3_destination_wcptr> m_l3_destinations;

    // First Destination ID
    la_l3_destination_gid_t m_first_dest_gid;
    bool m_gid_valid = false;
    la_uint_t m_user_count = 0;
};
}

#endif
