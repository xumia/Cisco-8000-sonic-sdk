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

#ifndef __LA_NEXT_HOP_AKPG_H__
#define __LA_NEXT_HOP_AKPG_H__

#include "la_next_hop_base.h"
#include "npu/resolution_configurator.h"

namespace silicon_one
{

class la_next_hop_akpg : public la_next_hop_base
{
    friend class la_next_hop_impl_common;

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_next_hop_akpg(la_device_impl_wptr device);
    ~la_next_hop_akpg() override;
    la_status initialize(la_object_id_t oid,
                         la_next_hop_gid_t nh_gid,
                         la_mac_addr_t nh_mac_addr,
                         const la_l3_port_wptr& port,
                         nh_type_e nh_type) override;

    la_status destroy() override;

    // la_next_hop API-s
    la_status set_nh_type(nh_type_e nh_type) override;
    la_status get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const override;

    /// @brief Populate the value field of the FEC table
    la_status get_fec_table_value(npl_fec_table_value_t& value, npl_destination_t& rpf_fec_table_dest) const;

    // Resolution API helpers
    la_status instantiate(resolution_step_e prev_step) override;
    la_status uninstantiate(resolution_step_e prev_step) override;
    resolution_table_index get_id(resolution_step_e prev_step) const override;
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const override;
    destination_id get_destination_id(resolution_step_e prev_step) const override;
    la_status notify_change(dependency_management_op op) override;
    la_status modify_mac_move_dsp_or_dspa() override;
    la_status get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const;

protected:
    la_next_hop_akpg() = default;
    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const override;

    // Fully write the object to resolution, and helper functions
    la_status configure_resolution_step(resolution_step_e res_step) override;
    la_status configure_resolution_step_fec();
    la_status configure_resolution_step_stage2(nh_type_e nh_type);

    // Delete the object from the resolution, and helper functions
    la_status teardown_resolution_step(resolution_step_e res_step) override;
    la_status teardown_resolution_step_fec();
    la_status teardown_resolution_step_stage2();

    /// Next-hop table entry
    npl_egress_nh_and_svi_direct_table_entry_wptr_t m_nh_direct_entry[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    // Resolution related data
    struct resolution_data {
        resolution_data();
        la_uint_t users_for_step[RESOLUTION_STEP_LAST];

        // FEC wrapper object
        la_l3_fec_impl_sptr fec_impl;

        // Resolution config handle
        resolution_cfg_handle_t cfg_handle;
    } m_resolution_data;
    CEREAL_SUPPORT_PRIVATE_CLASS(resolution_data)

protected:
    // Manage the TX table
    la_status configure_global_tx_tables() override;
    la_status do_configure_global_tx_tables(la_slice_id_t slice) override;
    la_status update_global_tx_tables() override;
    la_status do_update_global_tx_tables(la_slice_id_t slice) override;
    la_status teardown_global_tx_tables() override;
    la_status do_teardown_global_tx_tables(la_slice_id_t slice) override;

    la_status populate_nh_and_svi_payload(npl_nh_and_svi_payload_t& out_nh_and_svi_payload, la_slice_id_t slice) const override;
    la_status populate_nh_payload(npl_nh_payload_t& out_nh_payload,
                                  const la_l3_port_wptr& l3_port,
                                  la_slice_id_t slice) const override;
    la_status populate_nh_payload_l2_info(npl_nh_payload_t& out_nh_payload,
                                          const la_l3_port_wptr& l3_port,
                                          la_slice_id_t slice) const override;
};

} // namesapce silicon_one

#endif // __LA_NEXT_HOP_IMPL_H__
