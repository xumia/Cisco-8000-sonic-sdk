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

#ifndef __LA_NEXT_HOP_IMPL_COMMON_H__
#define __LA_NEXT_HOP_IMPL_COMMON_H__

#include "api/npu/la_next_hop.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_next_hop_impl_common
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_next_hop_impl_common() = default; // needed by cereal
    // la_next_hop_impl API-s
    explicit la_next_hop_impl_common(const la_device_impl_wptr& device);
    virtual ~la_next_hop_impl_common();
    la_status initialize(const la_object_wptr& parent,
                         la_next_hop_gid_t nh_gid,
                         la_mac_addr_t nh_mac_addr,
                         const la_l3_port_wptr& port);
    la_status update_next_hop_mac_addr(la_mac_addr_t nh_mac_addr);
    // called during mac move processing in svi object. Updated(by set_mac_entry) dsp associated with mac, will be  internally
    // fetched
    la_status update_next_hop_dsp();
    la_status clear_port_dependencies();
    la_status destroy();

    // IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // la_next_hop API-s
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const;
    virtual la_status get_router_port(la_l3_port_wptr& out_port) const;

    // la_object API-s
    virtual const la_device* get_device() const;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// @brief Return the L2 destination associated with this object
    la_status get_nh_l2_destination(la_l2_destination_wptr& out_l2_dest) const;

    /// @brief Return the NPP associated with this object
    la_status get_dsp_or_dspa(la_l2_port_gid_t& out_dsp_or_dspa, bool& out_is_aggregate) const;

    /// @brief Get the MAC address of the associated L3 port
    la_status get_l3_port_mac(la_mac_addr_t& out_mac_addr) const;

    /// @brief Get next hop's global ID.
    la_next_hop_gid_t get_gid() const;

    /// @brief Get the L3 port object.
    const la_l3_port_wptr get_l3_port() const;

    /// @brief Get a list of active slice-pairs
    ///
    /// @retval  A vector that holds the active slice-pairs
    la_slice_id_vec_t get_slices() const;
    std::vector<la_slice_pair_id_t> get_slice_pairs() const;

private:
    // Owner device
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Containing object
    la_next_hop_base_wptr m_next_hop;

    // Global next-hop ID
    la_next_hop_gid_t m_gid;

    // MAC address of the next hop station
    la_mac_addr_t m_mac_addr;

    // L3 port associated with the next hop
    la_l3_port_wptr m_l3_port;
};

} // namesapce silicon_one

#endif // __LA_NEXT_HOP_IMPL_COMMON_H__
