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

#ifndef __LA_VXLAN_NEXT_HOP_BASE_H__
#define __LA_VXLAN_NEXT_HOP_BASE_H__

#include <vector>

#include "api/npu/la_vxlan_next_hop.h"
#include "api/types/la_lb_types.h"
#include "common/profile_allocator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "nplapi/npl_table_types.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_vxlan_next_hop_base : public la_vxlan_next_hop, public dependency_listener

{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    explicit la_vxlan_next_hop_base(const la_device_impl_wptr& device);
    ~la_vxlan_next_hop_base() override;
    using l3vxlan_smac_msb_index_profile_t = profile_allocator<la_uint32_t>::profile_ptr;
    la_status initialize(la_object_id_t oid,
                         la_mac_addr_t nh_mac_addr,
                         const la_l3_port_wptr& port,
                         const la_l2_service_port_wptr& vxlan_port);
    la_status destroy();

    // IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // la_vxlan_next_hop API-s
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status get_router_port(la_l3_port*& out_port) const override;
    la_status get_vxlan_port(la_l2_port*& out_vxlan_port) const override;

    // la_object API-s
    la_object::object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    // Resolution API helpers
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);
    virtual lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const = 0;
    virtual destination_id get_destination_id(resolution_step_e prev_step) const = 0;
    la_status notify_change(dependency_management_op op) override;

protected:
    // Resolution API helpers
    // General functions
    la_vxlan_next_hop_base() = default;
    la_status update_l3relay_to_vni_table(la_mac_addr_t nh_mac_addr,
                                          const la_svi_port_base_wptr& svi_port,
                                          uint64_t sa_prefix_index,
                                          uint64_t overlay_nh_id);
    la_status configure_l3vxlan_nh(la_mac_addr_t nh_mac_addr, const la_l3_port_wptr& port, const la_l2_service_port_wptr& l2_port);
    la_status teardown_l3vxlan_nh();
    la_status allocate_sa_msb_index(la_mac_addr_t sa, uint64_t& index);
    la_status free_sa_msb_index();
    la_status find_vxlan_port(la_mac_addr_t nh_mac_addr,
                              const la_svi_port_base_wptr& svi_port,
                              la_l2_service_port_base_wptr& vxlan_port) const;
    void init_vxlan_nh(la_mac_addr_t nh_mac_addr,
                       const la_l3_port_wptr& port,
                       const la_l2_service_port_wptr& vxlan_port,
                       la_device_impl::vxlan_nh_t& nh);
    const la_vxlan_next_hop_wptr vxlan_lookup_nh(la_mac_addr_t nh_mac_addr,
                                                 const la_l3_port_wptr& port,
                                                 const la_l2_service_port_wptr& vxlan_port);
    void vxlan_add_nh(la_mac_addr_t nh_mac_addr, const la_l3_port_wptr& port, const la_l2_service_port_wptr& vxlan_port);
    void vxlan_remove_nh(la_mac_addr_t nh_mac_addr, const la_l3_port_wptr& port, const la_l2_service_port_wptr& vxlan_port);

    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // MAC address of the next hop station
    la_mac_addr_t m_mac_addr;

    /// l3 port
    la_l3_port_wptr m_l3_port;

    /// l2 port
    la_l2_service_port_wptr m_vxlan_port;

    /// l3vxlan smac msb index profile
    l3vxlan_smac_msb_index_profile_t m_l3vxlan_smac_msb_index_profile{};

    // Resolution related data
    struct resolution_data {
        // FEC wrapper object
        la_l3_fec_impl_sptr fec_impl; // Must be shared_ptr not weak_ptr
    } m_resolution_data;
    CEREAL_SUPPORT_PRIVATE_CLASS(resolution_data)
};

} // namesapce silicon_one

#endif // __LA_VXLAN_NEXT_HOP_BASE_H__
