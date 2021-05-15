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

#ifndef __LA_MPLS_VPN_ENCAP_IMPL_H__
#define __LA_MPLS_VPN_ENCAP_IMPL_H__

#include <array>

#include "api/npu/la_mpls_vpn_encap.h"
#include "hld_types.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_prefix_object_base.h"

namespace silicon_one
{

class la_device_impl;

class la_mpls_vpn_encap_impl : public la_mpls_vpn_encap
{
    //////////Serialization////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_mpls_vpn_encap_impl() = default;
    ///////////////////////////////////
public:
    explicit la_mpls_vpn_encap_impl(const la_device_impl_wptr& device);
    ~la_mpls_vpn_encap_impl() override;
    la_status initialize(la_object_id_t oid, la_mpls_vpn_encap_gid_t gid);
    la_status destroy();

    // la_mpls_vpn_encap API-s

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    la_mpls_vpn_encap_gid_t get_gid() const override;
    const la_l3_destination* get_destination() const override;
    la_status set_destination(const la_l3_destination* destination) override;
    la_status clear_destination();
    la_status set_nh_vpn_properties(const la_l3_destination* nh,
                                    la_ip_version_e ip_version,
                                    const la_mpls_label_vec_t& labels) override;
    la_status get_nh_vpn_properties(const la_l3_destination* nh,
                                    la_ip_version_e ip_version,
                                    la_mpls_label_vec_t& out_labels) const override;
    la_status get_all_nh_vpn_properties(la_mpls_vpn_properties_vec_t& out_nh_vpn_properties) const override;
    la_status clear_nh_vpn_properties(const la_l3_destination* nh, la_ip_version_e ip_version) override;

    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;

private:
    struct nh_info {
        la_mpls_label_vec_t v4_label;
        bool v4_valid;
        la_mpls_label_vec_t v6_label;
        bool v6_valid;
        nh_info() : v4_valid(false), v6_valid(false)
        {
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(nh_info)

    la_status configure_per_pe_and_prefix_vpn_table_entry(const la_l3_destination* nh, const nh_info& entry);
    la_status teardown_per_pe_and_prefix_table_entry(const la_l3_destination* nh);

    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Object GID
    la_mpls_vpn_encap_gid_t m_gid;

    // L3 destination
    la_l3_destination_wcptr m_destination;

    // next hop to label map
    std::map<la_l3_destination_wcptr, nh_info> m_nh_label_map;
};

} // namespace silicon_one

#endif // __LA_MPLS_VPN_ENCAP_IMPL_H__
