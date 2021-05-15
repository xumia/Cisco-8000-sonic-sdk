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

#ifndef __LA_ECMP_GROUP_IMPL_H__
#define __LA_ECMP_GROUP_IMPL_H__

#include <vector>

#include "api/npu/la_ecmp_group.h"
#include "api/types/la_ip_types.h"
#include "common/transaction.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "resolution_configurator.h"
#include "resolution_utils.h"

namespace silicon_one
{

class la_ecmp_group_impl : public la_ecmp_group, public dependency_listener
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_ecmp_group_impl() = default;
    //////////////////////////////
public:
    explicit la_ecmp_group_impl(const la_device_impl_wptr& device);
    ~la_ecmp_group_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, level_e level);
    la_status destroy();

    // Inherited API-s
    la_status add_member(la_l3_destination* l3_destination) override;
    la_status remove_member(const la_l3_destination* l3_destination) override;
    la_status get_member(size_t member_idx, const la_l3_destination*& out_member) const override;
    la_status get_members(la_l3_destination_vec_t& out_members) const override;
    la_status set_members(const la_l3_destination_vec_t& members) override;
    la_status set_lb_mode(la_lb_mode_e lb_mode) override;
    la_status set_lb_fields(la_lb_fields_t lb_fields) override;
    la_status set_lb_hash(la_lb_hash_e lb_hash) override;
    la_status set_slb_mode(bool enabled) override;
    la_status get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const;

    // la_object API-s
    object_type_e type() const override;
    la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Populate the value field of the FEC table
    la_status get_fec_table_value(npl_fec_table_value_t& value);

    // Get ECMP level
    level_e get_ecmp_level() const;

    // Helper function to check if members are of type ASBR_LSP
    bool has_only_asbr_lsps_configured() const;

    // Resolution API helpers
    la_status instantiate(resolution_step_e prev_step);
    la_status instantiate(resolution_step_e prev_step, const la_object* prev_obj);
    la_status uninstantiate(resolution_step_e prev_step);
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;

private:
    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;
    resolution_table_index get_id_in_step(resolution_step_e res_step) const;
    la_status do_prefix_object_instantiate(resolution_step_e prev_step, const la_prefix_object_base_wcptr& pfx_obj);

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper functions for adding/removing attribute dependency
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);
    void register_attribute_dependency(const la_l3_destination_wcptr& destination);
    void deregister_attribute_dependency(const la_l3_destination_wcptr& destination);

    // Fully write the object to resolution, and helper functions
    la_status configure_resolution_step_new_members(resolution_step_e res_step,
                                                    const std::vector<la_l3_destination_wcptr>& old_members,
                                                    const std::vector<la_l3_destination_wcptr>& new_members);
    la_status configure_resolution_step(resolution_step_e res_step,
                                        const std::vector<la_l3_destination_wcptr>& old_configured_members,
                                        const std::vector<la_l3_destination_wcptr>& new_members);
    la_status unconfigure_resolution_step(resolution_step_e res_step);
    la_status configure_resolution_step_lb_members_list(resolution_step_e res_step,
                                                        const std::vector<la_l3_destination_wcptr>& old_configured_members,
                                                        const std::vector<la_l3_destination_wcptr>& new_members);
    la_status unconfigure_resolution_step_lb_members_list(resolution_step_e res_step,
                                                          const std::vector<la_l3_destination_wcptr>& old_members,
                                                          size_t new_members_list_size);
    la_status configure_resolution_step_lb_member_at_index(resolution_step_e res_step,
                                                           const la_l3_destination_wcptr& l3_dest,
                                                           size_t lbg_member_id);
    la_status configure_resolution_step_lb_group_size(resolution_step_e res_step, size_t lbg_group_size);
    la_status erase_resolution_step_lb_group_size(resolution_step_e res_step);
    la_status erase_resolution_step_lb_member_at_index(resolution_step_e res_step, size_t lbg_member_id);
    la_status erase_resolution_step_old_members(resolution_step_e res_step, size_t old_group_size, size_t new_members_list_size);

    // Per resolution step, helper functions that provide the entries for LB tables
    la_status populate_stage0_lb_to_nh_value(const la_next_hop_base_wcptr& next_hop,
                                             npl_resolution_stage_assoc_data_narrow_entry_t& value) const;
    la_status populate_stage0_lb_to_ecmp_group_value(const la_ecmp_group_impl_wcptr& ecmp_group,
                                                     npl_resolution_stage_assoc_data_narrow_entry_t& value) const;
    la_status populate_stage1_lb_to_nh_value(const la_l3_destination_wcptr& l3_dest,
                                             npl_resolution_stage_assoc_data_narrow_entry_t& value) const;
    la_status populate_stage1_lb_to_p_nh_common_data(const la_l3_destination_wcptr& l3_dest,
                                                     npl_em_common_data_t& em_common_data) const;
    la_status populate_stage1_lb_to_te_tunnel_nh_value(const la_te_tunnel_impl_wcptr& te_tunnel,
                                                       const la_next_hop_base_wcptr& next_hop,
                                                       npl_resolution_stage_assoc_data_narrow_entry_t& value) const;
    la_status populate_stage1_lb_to_te_tunnel_p_nh_common_data(const la_te_tunnel_impl_wcptr& te_tunnel,
                                                               const la_l3_protection_group_impl_wcptr& l3_protection_group,
                                                               npl_em_common_data_t& common_data) const;
    la_status populate_stage1_lb_to_p_nh_asb_lsp_common_data(const la_asbr_lsp_impl_wcptr& asbr_lsp,
                                                             npl_em_common_data_t& em_common_data) const;
    la_status populate_stage1_lb_to_nh_asbr_lsp(const la_asbr_lsp_impl_wcptr& asbr_lsp,
                                                npl_resolution_stage_assoc_data_narrow_entry_t& value) const;

    la_status add_member_in_resolution(const la_l3_destination_wcptr& l3_dest);
    la_status remove_member_in_resolution(size_t lbg_member_id);
    la_status set_drop_status();

    // Device this ECMP group belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // ECMP level
    level_e m_level;

    enum class member_type_e {
        UNKNOWN = 0,
        IP = 1,
        LDP = 2,
        GLOBAL_LSP = 3,
    };

    // ECMP type
    member_type_e m_type;

    // Layer-3 destinations comprising the ECMP group
    std::vector<la_l3_destination_wcptr> m_l3_destinations;

    // Resolution related data
    struct resolution_data {
        resolution_data();
        la_uint_t users_for_step[RESOLUTION_STEP_LAST] = {0};
        resolution_table_index id_in_step[RESOLUTION_STEP_LAST];
        std::map<size_t, resolution_cfg_handle_t> cfg_handles[RESOLUTION_STEP_LAST];
    } m_resolution_data;
    CEREAL_SUPPORT_PRIVATE_CLASS(resolution_data);

    bool m_is_ip_tunnel;
    bool m_is_drop;
    enum { NUM_OF_BITS_IN_LPM_DESTINATION = 20 };
    enum { DEFAULT_ROUTE_DESTINATION_BIT_MASK = 1 << (NUM_OF_BITS_IN_LPM_DESTINATION - 1) };
};
}

#endif
