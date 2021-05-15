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

#ifndef __LEABA_LA_L2_SERVICE_PORT_GIBRALTAR_H__
#define __LEABA_LA_L2_SERVICE_PORT_GIBRALTAR_H__

#include <array>
#include <map>

#include "la_l2_service_port_pacgb.h"
#include "npu/resolution_configurator.h"

namespace silicon_one
{

class la_l2_service_port_gibraltar : public la_l2_service_port_pacgb
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_l2_service_port_gibraltar() = default;
    //////////////////////////////
public:
    explicit la_l2_service_port_gibraltar(const la_device_impl_wptr& device);
    ~la_l2_service_port_gibraltar() override;

    la_status set_l3_destination(const la_l3_destination* l3_destination) override;
    la_status add_ifg(la_slice_ifg ifg) override;
    la_status remove_ifg(la_slice_ifg ifg) override;
    la_status update_l3_destination_for_l3vxlan(bool shared_overlay_nh) override;
    la_status get_fec_table_value(npl_fec_table_value_t& value) const;
    la_status set_group_policy_encap(bool enabled) override;
    la_status get_group_policy_encap(bool& out_enabled) const override;

private:
    la_status configure_common_tables() override;
    la_status teardown_tables() override;
    la_status do_update_relay_id_in_pwe_tables(uint64_t relay_id) override;
    la_status configure_resolution_step();
    la_status teardown_resolution_step();
    la_status configure_resolution_step_vxlan(uint64_t ovl_nh_id);
    la_status configure_mpls_termination_table() override;
    la_status teardown_mpls_termination_table() override;
    la_status update_lp_attributes_payload_lp(npl_mac_lp_attributes_payload_t& payload) override;
    la_status update_lp_attributes_payload_pwe_tagged(npl_mac_lp_attributes_payload_t& payload) override;

    void populate_payload_counters(npl_mac_lp_attributes_payload_t& payload, la_slice_id_t slice_idx) override;
    la_status update_vxlan_group_policy_encap(npl_vxlan_l2_dlp_table_value_t& value) override;

    // Helper function for allocating PWE SLP ID-s
    la_status allocate_pwe_slp_ids() override;
    la_status deallocate_pwe_slp_ids() override;

    // Helper function for getting local SLP ID per slice
    uint64_t get_local_slp_id(la_slice_id_t slice) const override;

    la_status map_vxlan_slp() override;
    la_status unmap_vxlan_slp() override;
    la_status map_mcast_vxlan_slp() override;
    la_status unmap_mcast_vxlan_slp() override;
    la_status configure_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair) override;
    la_status teardown_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair) override;

    la_slice_pair_id_vec_t pwe_get_slice_pairs() const;
    la_status configure_pwe_service_lp_attributes_table() override;
    la_status teardown_pwe_service_lp_attributes_table() override;

    la_status configure_pwe_encap_table() override;
    la_status teardown_pwe_encap_table() override;
    la_status configure_pwe_vpls_label_table() override;
    la_status teardown_pwe_vpls_label_table() override;
    la_status do_update_cw_fat_pwe_vpls(bool flow_label_enable, bool control_word_enable) override;
    la_status configure_pwe_to_l3_dest_table() override;
    la_status teardown_pwe_to_l3_dest_table() override;
    la_status do_set_pwe_vpls_filter_group(la_slice_pair_id_t pair_idx, uint64_t group_id) override;
    la_status pwe_sw_dest_in_use(const la_l3_destination_wcptr& l3_destination) override;
    la_status instantiate_pwe_l3_destination(const la_l3_destination_wcptr& l3_destination) override;
    la_status uninstantiate_pwe_l3_destination(const la_l3_destination_wcptr& l3_destination) override;
    la_status update_l3_destination_pwe(const la_l3_destination_wcptr& l3_destination);
    la_status get_attached_destination_id(const la_l2_destination_wcptr& destination, uint64_t& attached_dest_id) override;
    la_status service_mapping_set_destination_p2p_pwe(const la_l2_destination_wcptr& destination) override;

    la_status set_ac_profile_for_pwe(la_ac_profile* ac_profile) override;
    void clear_ac_profile_for_pwe() override;
    la_status get_ac_profile_for_pwe(la_ac_profile*& out_ac_profile) const override;
    la_status configure_pwe_port_tag_table() override;
    la_status update_vxlan_group_policy_encap(la_slice_pair_id_t pair_idx);

    la_status populate_nh_l2_payload(npl_nh_payload_t& out_nh_payload, la_slice_pair_id_t slice_pair_idx) const override;

private:
    struct slice_data {
        // PWE service mapping table entry and location
        size_t pwe_port_tag_entry_location = -1;
        npl_service_mapping_tcam_pwe_tag_table_entry_wptr_t pwe_port_tag_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);

    struct slice_pair_data {
        /// L2 DLP table entry
        npl_l2_dlp_table_entry_wptr_t l2_dlp_entry;

        // MPLS termination table entry
        npl_mpls_termination_em1_table_entry_wptr_t mpls_termination_entry;

        // LP attributes table entry
        // The LP attribute table is slice_pair, however, we hold an entry for each slice to handle a meters hardware bug.
        npl_service_lp_attributes_table_entry_wptr_t lp_attributes_entry;

        // PWE, PWE-tagged local SLP ID
        uint64_t local_slp_id = la_ac_port_common::LOCAL_SLP_ID_INVALID;

        // PWE, entry used for VPWS only
        npl_pwe_label_table_entry_wptr_t pwe_encap_entry;
        // PWE,entry of pwe_vpls_label_table for a PWE, used in VPLS encap tx
        npl_pwe_vpls_label_table_entry_wptr_t pwe_vpls_label_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data);

    /// Per-slice data
    std::vector<slice_data> m_slice_data;

    /// Per-slice-pair data
    std::vector<slice_pair_data> m_slice_pair_data;

    // Resolution table entries
    resolution_cfg_handle_t m_stage_cfg_handle;

    // PWE AC profile
    la_ac_profile_impl_wptr m_ac_profile_for_pwe;

    // PWE to L3 dest entry
    npl_pwe_to_l3_dest_table_entry_wptr_t m_pwe_l3_dest_entry;
};

/// @}
}

#endif
