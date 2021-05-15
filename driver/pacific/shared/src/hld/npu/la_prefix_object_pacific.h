// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_PREFIX_OBJECT_PACIFIC_H__
#define __LA_PREFIX_OBJECT_PACIFIC_H__

#include "la_prefix_object_base.h"

namespace silicon_one
{

class la_prefix_object_pacific : public la_prefix_object_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_prefix_object_pacific(const la_device_impl_wptr& device);
    ~la_prefix_object_pacific() override;

    la_status destroy() override;
    la_status set_destination(const la_l3_destination* destination) override;
    la_status update_destination(const la_l3_destination_wcptr& destination, bool is_global, bool is_init) override;

    /// @brief Populate the value field of the native-FEC table
    la_status get_fec_table_value(npl_native_fec_table_value_t& value);

    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const override;
    destination_id get_destination_id(resolution_step_e prev_step) const override;

private:
    la_status update_dependent_attributes(dependency_management_op op) override;
    void register_attribute_dependency(const la_l3_destination_wcptr& destination) override;
    void deregister_attribute_dependency(const la_l3_destination_wcptr& destination) override;

    la_status do_clear_nh_lsp_properties(const la_next_hop_wcptr& nh) override;
    la_status do_set_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                       const la_mpls_label_vec_t& labels,
                                       const la_counter_set_wptr& counter,
                                       lsp_counter_mode_e counter_mode) override;
    la_status do_clear_vrf_properties(const la_vrf_wcptr& vrf, la_ip_version_e ip_version) override;
    la_status do_set_vrf_properties(const la_vrf_wcptr& vrf,
                                    la_ip_version_e ip_version,
                                    const la_mpls_label_vec_t& labels) override;

    // Manage the MPLS headend Small Encap table configuration
    la_status configure_small_encap_mpls_he_asbr_table(la_slice_pair_id_t pair_idx,
                                                       const la_next_hop_base_wcptr& nh,
                                                       const la_mpls_label_vec_t& labels,
                                                       const la_counter_set_wcptr& counter) override;

    // Manage the resolution table configuration
    la_status configure_native_prefix_table();
    la_status configure_native_ce_ptr_to_nh_or_protected_nh_value();
    la_status configure_native_ce_ptr_to_tenh_value();
    la_status configure_native_ce_ptr_to_ecmp_group_value();
    la_status teardown_native_prefix_table();

    la_prefix_object_pacific() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_PREFIX_OBJECT_PACIFIC_H__
