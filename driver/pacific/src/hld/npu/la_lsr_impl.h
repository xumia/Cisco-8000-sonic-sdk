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

#ifndef __LA_LSR_IMPL_H__
#define __LA_LSR_IMPL_H__

#include <map>

#include "api/npu/la_lsr.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

/// @addtogroup MPLS_NHLFE
/// @{

class la_lsr_impl : public la_lsr
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_lsr_impl() = default;
    //////////////////////////////

public:
    explicit la_lsr_impl(const la_device_impl_wptr& device);
    ~la_lsr_impl() override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_lsr API's
    la_status add_route(la_mpls_label label, const la_l3_destination* destination, la_user_data_t user_data) override;
    la_status add_route(la_mpls_label label,
                        const la_vrf* vrf,
                        const la_l3_destination* destination,
                        la_user_data_t user_data) override;
    la_status get_route(la_mpls_label label, la_mpls_route_info& out_mpls_route_info) const override;
    la_status modify_route(la_mpls_label label, const la_l3_destination* destination) override;
    la_status delete_route(la_mpls_label label) override;
    la_status clear_all_routes() override;
    la_status add_vpn_decap(la_mpls_label label, const la_vrf* vrf, la_mpls_vpn_decap*& out_mpls_vpn_decap) override;
    la_status modify_vpn_decap(la_mpls_label label, const la_vrf* vrf, la_mpls_vpn_decap* mpls_vpn_decap) override;
    la_status add_vpn_decap(la_mpls_label label,
                            const la_vrf* vrf,
                            la_uint_t rpdid,
                            bool bud_node,
                            la_mldp_vpn_decap*& out_mldp_vpn_decap) override;
    la_status modify_vpn_decap(la_mpls_label label,
                               const la_vrf* vrf,
                               la_uint_t rpdid,
                               bool bud_node,
                               la_mldp_vpn_decap* mldp_vpn_decap) override;

    la_status delete_vpn_decap(la_mpls_vpn_decap* mpls_vpn_decap) override;
    la_status delete_vpn_decap(la_mldp_vpn_decap* mldp_vpn_decap) override;
    // la_lsr_impl API-s
    la_status initialize(la_object_id_t oid);
    la_status destroy();

private:
    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Hold entry information
    struct internal_mpls_route_info {
        la_l3_destination_wcptr destination;
        la_vrf_gid_t vrf_gid;
        la_user_data_t user_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(internal_mpls_route_info)

    struct la_mpls_label_operator_less {
        inline bool operator()(const la_mpls_label& lhs, const la_mpls_label& rhs) const
        {
            return lhs.label < rhs.label;
        }
    };

    typedef std::map<la_mpls_label, internal_mpls_route_info, la_mpls_label_operator_less> entry_info_map_t;
    entry_info_map_t m_entry_info_map;

private:
    la_status do_add_route(la_mpls_label label,
                           const la_vrf_gid_t vrf_gid,
                           const la_l3_destination_wcptr& destination,
                           la_user_data_t user_data);
    la_status do_set_route(la_mpls_label label, const la_vrf_gid_t vrf_gid, const la_l3_destination_wcptr& destination);
    npl_nhlfe_type_e get_nhlfe_type(la_mpls_label label1, la_mpls_label label2);
    la_status set_label_unicast_entry_nhlfe(la_mpls_label label, const la_mpls_nhlfe_wcptr& nhlfe);
    la_status set_label_vrf_unicast_entry_nhlfe(la_mpls_label label, const la_vrf_gid_t vrf_gid, const la_mpls_nhlfe_wcptr& nhlfe);
    la_status set_label_unicast_entry_headend(la_mpls_label label, const la_l3_destination_wcptr& destination);
    la_status set_label_vrf_unicast_entry_headend(la_mpls_label label,
                                                  const la_vrf_gid_t vrf_gid,
                                                  const la_l3_destination_wcptr& destination);
    la_status populate_fwd_mpls_forwarding_table_nhlfe(const la_mpls_nhlfe_wcptr& nhlfe, npl_nhlfe_t& npl_nhlfe);
    la_status erase_route(const la_mpls_label label, const la_vrf_gid_t vrf_gid);
};

} // namespace silicon_one

#endif // __LA_LSR_IMPL_H__
