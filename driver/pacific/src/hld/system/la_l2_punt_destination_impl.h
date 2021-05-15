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

#ifndef __LA_L2_PUNT_DESTINATION_IMPL_H__
#define __LA_L2_PUNT_DESTINATION_IMPL_H__

/// @file
/// @brief Leaba Layer 2 Punt destination API-s.
///
/// Defines API-s for managing and using Layer 2 Punt destination.
///

#include "api/system/la_l2_punt_destination.h"
#include "api/system/la_punt_destination.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_l2_punt_destination_impl : public la_l2_punt_destination
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_l2_punt_destination_impl() = default;
    //////////////////////////////
public:
    explicit la_l2_punt_destination_impl(const la_device_impl_wptr& device);
    ~la_l2_punt_destination_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid,
                         la_l2_punt_destination_gid_t gid,
                         la_punt_inject_port_base* pi_port,
                         la_mac_addr_t mac_addr,
                         const la_vlan_tag_tci_t& vlan_tag);

    la_status initialize(la_object_id_t oid,
                         la_l2_punt_destination_gid_t gid,
                         la_stack_port_base* stack_port,
                         la_mac_addr_t mac_addr,
                         const la_vlan_tag_tci_t& vlan_tag);
    la_status destroy();

    // la_l2_punt_destination API-s
    la_l2_port_gid_t get_gid() const override;
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status get_vlan_tag(la_vlan_tag_tci_t& out_vlan_tag) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Implementation API-s
    /// @brief Get punt/inject port associated with this Punt destination.
    ///
    /// @return la_punt_inject_port_base* for this Punt destination.\n
    ///         nullptr if not initialized.
    const la_punt_inject_port_base* get_punt_inject_port() const;
    const la_stack_port_base* get_stack_port() const;
    destination_id get_destination_id(resolution_step_e prev_step) const;
    la_status get_punt_port_mac(la_mac_addr_t& out_mac_addr) const;

private:
    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// Port GID
    la_l2_punt_destination_gid_t m_gid;

    // Punt Inject port
    la_punt_inject_port_base_wptr m_pi_port;

    // MAC associated with the destination
    la_mac_addr_t m_mac_addr;

    // VLAN tag associated with the destination
    la_vlan_tag_tci_t m_vlan_tag;

    la_stack_port_base_wptr m_stack_port;
};
}

#endif // __LA_L2_PUNT_DESTINATION_IMPL_H__
