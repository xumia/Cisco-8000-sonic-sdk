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

#ifndef __LA_MPLS_VPN_DECAP_IMPL_H__
#define __LA_MPLS_VPN_DECAP_IMPL_H__

#include <array>

#include "api/npu/la_mpls_vpn_decap.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_mpls_vpn_decap_impl : public la_mpls_vpn_decap
{ //////////SERIALIZATION//////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_mpls_vpn_decap_impl() = default;
    //////////////////////////////////
public:
    explicit la_mpls_vpn_decap_impl(const la_device_impl_wptr& device);
    ~la_mpls_vpn_decap_impl() override;
    la_status initialize(la_object_id_t oid, la_mpls_label label, const la_vrf_wcptr& vrf);
    la_status destroy();

    // la_mpls_vpn_decap API-s
    la_mpls_label get_label() const override;
    const la_vrf* get_vrf() const override;
    la_status set_counter(la_counter_set* counter) override;
    la_status get_counter(la_counter_set*& out_counter) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

private:
    struct slice_data {
        npl_mpls_termination_em1_table_entry_wptr_t m_mpls_termination_entry = nullptr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data)
    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // VPN label
    la_mpls_label m_label;

    // Associated VRF object
    la_vrf_wcptr m_vrf;

    // Counter set for the decap
    la_counter_set_impl_wptr m_counter;

    // NPL table entry
    std::array<slice_data, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_slice_data;

private:
    // Manage the MPLS termination table
    la_status add_to_mpls_termination_table(const la_counter_set_wcptr& counter);
    la_status remove_from_mpls_termination_table();
    la_status remove_counter();
};

} // namespace silicon_one

#endif // __LA_MPLS_VPN_DECAP_IMPL_H__
