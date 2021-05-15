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

//
// Implementation of common parts of multicast-group configurations. Mainly managing the EM MC DB.
//

#ifndef __LA_MULTICAST_GROUP_PACIFIC_H__
#define __LA_MULTICAST_GROUP_PACIFIC_H__

#include <map>
#include <vector>

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_port.h"
#include "api/npu/la_l3_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "la_multicast_group_common_base.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_multicast_group_common_pacific : public la_multicast_group_common_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_multicast_group_common_pacific(const la_device_impl_wptr& device);
    la_multicast_group_common_pacific() = default; // needed for cereal
    ~la_multicast_group_common_pacific() override;
    la_status initialize(la_multicast_group_gid_t multicast_gid,
                         la_multicast_group_gid_t local_mcid,
                         la_replication_paradigm_e rep_paradigm,
                         bool is_scale_mode_mcid) override;
    la_status destroy() override;

    la_status configure_egress_rep_common(const group_member_desc& member,
                                          const la_system_port_wcptr& dsp,
                                          uint64_t mc_copy_id) override;
    la_status teardown_egress_rep_common(const group_member_desc& member, const la_system_port_wcptr& dsp) override;
    la_status set_member_dsp(const group_member_desc& member,
                             const la_system_port_wcptr& curr_dsp,
                             const la_system_port_wcptr& new_dsp,
                             uint64_t old_mc_copy_id,
                             uint64_t new_mc_copy_id) override;
    la_status verify_dsp(const la_ethernet_port_wcptr& eth, const la_system_port_wcptr& dsp) const override;

    la_status update_member_slice_data(const group_member_desc& old_member,
                                       const group_member_desc& new_member,
                                       la_slice_id_t slice) override;

    bool is_dsp_remote(const la_system_port_wcptr& dsp) const override;

    void set_local_mcid(la_multicast_group_gid_t local_mcid) override;

    la_status configure_ingress_rep_common(const group_member_desc& member, la_slice_id_t slice) override;
    la_status teardown_ingress_rep_common(const group_member_desc& member, la_slice_id_t slice) override;

    // Configure CUD mapping table
    la_status configure_cud_mapping(const group_member_desc& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) override;
    la_status teardown_cud_mapping(const group_member_desc& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) override;

    la_status reconfigure_mcemdb_entry(group_member_desc member, const la_system_port_base_wcptr dsp, uint64_t mc_copy_id) override;

private:
    // Helper functions for configring the MC EM DB
    la_status add_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp,
                                            const group_member_desc& member,
                                            uint64_t mc_copy_id) override;
    la_status remove_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp, const group_member_desc& tbr_member) override;
    la_status insert_entry_to_mc_em_db_tx_format_0(uint64_t entry_index,
                                                   uint64_t dest_slice,
                                                   uint64_t tc_map_profile,
                                                   uint64_t oq_group,
                                                   uint64_t mc_copy_id,
                                                   npl_mc_em_db_entry_wptr_t& out_entry) override;
    la_status remove_entry_from_mc_em_db_tx_format_0(size_t member_index, npl_mc_em_db_key_t key) override;
    la_status update_entry_in_mc_em_db_tx_format_0(npl_mc_em_db_entry_wptr_t entry,
                                                   size_t member_index_in_entry,
                                                   const npl_mc_em_db_value_t& value,
                                                   size_t member_index_in_value) override;
    la_status do_add_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp,
                                               uint64_t member_index,
                                               uint64_t mc_copy_id,
                                               npl_mc_em_db_entry_wptr_t& out_entry) override;
    la_status do_add_mc_em_db_entry_egress_rep(la_slice_ifg slice_ifg,
                                               la_uint_t base_serdes,
                                               uint64_t member_index,
                                               uint64_t mc_copy_id,
                                               npl_mc_em_db_entry_wptr_t& out_entry);

    // Ingress replication helper functions
    la_status add_mc_em_db_entry_ingress_rep(const group_member_desc& member, la_slice_id_t slice, uint64_t member_mcid) override;
    la_status do_add_mc_em_db_entry_ingress_rep(uint64_t member_index,
                                                uint64_t slice,
                                                uint64_t member_mcid,
                                                npl_mc_em_db_entry_wptr_t& out_entry) override;
    la_status insert_entry_to_mc_em_db_rx_result(uint64_t member_index,
                                                 uint64_t slice,
                                                 uint64_t tc_map_profile,
                                                 uint64_t base_voq_nr,
                                                 uint64_t member_mcid,
                                                 npl_mc_em_db_entry_wptr_t& out_entry) override;
    void populate_mc_em_db_rx_result_value(bool is_0,
                                           uint64_t tc_map_profile,
                                           uint64_t base_voq_nr,
                                           uint64_t member_mcid,
                                           npl_mc_em_db_value_t& out_value) override;
    la_status remove_mc_em_db_entry_ingress_rep(const group_member_desc& member, la_slice_id_t slice) override;
    la_status update_entry_in_mc_em_db_rx_result(la_slice_id_t slice,
                                                 size_t dst_index,
                                                 npl_mc_em_db_entry_wptr_t& dst_entry,
                                                 size_t src_index,
                                                 npl_mc_em_db_entry_wptr_t& src_entry) override;
    la_status remove_entry_from_mc_em_db_rx_result(la_slice_id_t slice,
                                                   size_t member_index,
                                                   npl_mc_em_db_entry_wptr_t& entry) override;
};

} // namespace silicon_one

#endif // __LA_MULTICAST_GROUP_PACIFIC_H__
