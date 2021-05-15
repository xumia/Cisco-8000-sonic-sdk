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

#ifndef __LA_DESTINATION_PE_IMPL_H__
#define __LA_DESTINATION_PE_IMPL_H__

#include "api/npu/la_destination_pe.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "npu/resolution_configurator.h"

namespace silicon_one
{

class la_device_impl;
class la_prefix_object_base;
class la_vrf_impl;

class la_destination_pe_impl : public la_destination_pe
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // la_destination_pe_impl API-s
    explicit la_destination_pe_impl(const la_device_impl_wptr& device);
    ~la_destination_pe_impl() override;

    la_status initialize(la_object_id_t oid,
                         la_l3_destination_gid_t destination_pe_gid,
                         const la_l3_destination_wcptr& destination);
    la_status destroy();
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

    // la_destination_pe API-s
    la_l3_destination_gid_t get_gid() const override;
    const la_l3_destination* get_destination() const override;
    la_status set_destination(const la_l3_destination* destination) override;
    la_status set_vrf_properties(const la_vrf* vrf, la_ip_version_e protocol, const la_mpls_label_vec_t& labels) override;
    la_status get_vrf_properties(const la_vrf* vrf, la_ip_version_e protocol, la_mpls_label_vec_t& out_labels) const override;
    la_status clear_vrf_properties(const la_vrf* vrf, la_ip_version_e protocol) override;
    la_status set_asbr_properties(const la_prefix_object* asbr, const la_mpls_label_vec_t& labels) override;
    la_status get_asbr_properties(const la_prefix_object* asbr, la_mpls_label_vec_t& out_labels) const override;
    la_status clear_asbr_properties(const la_prefix_object* asbr) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;
    la_status get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const;

private:
    static constexpr int CR_PTR_INTER_AS_OFFSET = 0;
    static constexpr int CE_PTR_VPN_OFFSET = 1;

    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // Destionation PE ID
    la_l3_destination_gid_t m_gid;

    // Associated destination
    la_l3_destination_wcptr m_destination;

    // Hold entry information
    struct vpn_info {
        la_mpls_label_vec_t ipv4_labels;
        bool ipv4_valid = false;
        la_mpls_label_vec_t ipv6_labels;
        bool ipv6_valid = false;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(vpn_info);

    // EM-key to VPN label mapping
    typedef std::map<la_vrf_impl_wcptr, vpn_info> vpn_entry_map_t;

    vpn_entry_map_t m_vpn_entry_map;

    bool m_vpn_enabled;

    resolution_cfg_handle_t m_res_cfg_handle;

    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;

    // Manage the resolution table configuration
    la_status configure_stage0_prefix_table();
    la_status configure_stage0_ce_ptr_to_ecmp_group_value();
    la_status teardown_stage0_prefix_table();

    // Hold entry information
    struct asbr_info {
        la_mpls_label_vec_t labels;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(asbr_info);

    // EM-key to ASBR label mapping
    typedef std::map<la_prefix_object_base_wcptr, asbr_info> asbr_entry_map_t;

    asbr_entry_map_t m_asbr_entry_map;

    la_status update_destination(const la_l3_destination_wcptr& destination, bool is_init);

    // Helper functions for adding/removing dependency
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);

    // Manage the VPN Encap table configuration
    la_status configure_per_pe_and_vrf_vpn_key_large_table(const la_vrf_impl_wcptr& vrf,
                                                           la_ip_version_e protocol,
                                                           vpn_info& map_entry,
                                                           const la_mpls_label_vec_t& labels);
    la_status teardown_per_pe_and_vrf_vpn_key_large_table();
    la_status teardown_per_pe_and_vrf_vpn_key_large_table_entry(const la_vrf_impl_wcptr& vrf);

    // Manage the ASBR Encap table configuration
    la_status configure_per_asbr_and_dpe_table(const la_prefix_object_base_wcptr& asbr_impl, const la_mpls_label_vec_t& labels);
    la_status teardown_per_asbr_and_dpe_table();
    la_status teardown_per_asbr_and_dpe_table_entry(const la_prefix_object_base_wcptr& asbr_impl);

    la_destination_pe_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_DESTINATION_PE_IMPL_H__
