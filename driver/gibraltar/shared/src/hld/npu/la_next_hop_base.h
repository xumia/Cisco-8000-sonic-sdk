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

#ifndef __LA_NEXT_HOP_BASE_H__
#define __LA_NEXT_HOP_BASE_H__

#include "api/npu/la_next_hop.h"
#include "api/types/la_lb_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "nplapi/npl_table_types.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_next_hop_impl_common.h"
#include <vector>

namespace silicon_one
{

class la_next_hop_base : public la_next_hop, public dependency_listener
{
    friend class la_next_hop_impl_common;

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_next_hop_base(const la_device_impl_wptr& device);
    ~la_next_hop_base() override;
    virtual la_status initialize(la_object_id_t oid,
                                 la_next_hop_gid_t nh_gid,
                                 la_mac_addr_t nh_mac_addr,
                                 const la_l3_port_wptr& port,
                                 nh_type_e nh_type)
        = 0;
    virtual la_status destroy() = 0;

    // IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // la_next_hop API-s
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status get_nh_type(nh_type_e& out_nh_type) const override;
    la_status set_mac(la_mac_addr_t mac_addr) override;
    la_next_hop_gid_t get_gid() const override;
    la_status get_router_port(la_l3_port*& out_port) const override;
    virtual la_status get_lb_resolution(const la_lb_pak_fields_vec& lb_vector,
                                        size_t& member,
                                        const la_object*& out_object) const = 0;

    // la_object API-s
    la_object::object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// @brief Get a list of active slices
    ///
    /// @retval  A vector that holds the active slices
    std::vector<la_slice_id_t> get_slices() const;

    /// @brief Get a list of active slice-pairs
    ///
    /// @retval  A vector that holds the active slice-pairs
    std::vector<la_slice_pair_id_t> get_slice_pairs() const;

    /// @brief Return the NPP associated with this object
    la_status get_dsp_or_dspa(la_l2_port_gid_t& out_dsp_or_dspa, bool& out_is_aggregate) const;

    /// @brief Get the SA MAC address
    la_status get_l3_port_mac(la_mac_addr_t& out_mac_addr) const;

    // Resolution API helpers
    virtual la_status instantiate(resolution_step_e prev_step) = 0;
    virtual la_status uninstantiate(resolution_step_e prev_step) = 0;
    virtual resolution_table_index get_id(resolution_step_e prev_step) const = 0;
    virtual lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const = 0;
    virtual destination_id get_destination_id(resolution_step_e prev_step) const = 0;
    virtual la_status notify_change(dependency_management_op op) override = 0;
    virtual la_status modify_mac_move_dsp_or_dspa() = 0;

protected:
    la_next_hop_base() = default;
    // Resolution API helpers
    // General functions
    virtual resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const = 0;

    // Fully write the object to resolution, and helper functions
    virtual la_status configure_resolution_step(resolution_step_e res_step) = 0;

    // Delete the object from the resolution, and helper functions
    virtual la_status teardown_resolution_step(resolution_step_e res_step) = 0;

    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global next-hop ID
    la_next_hop_gid_t m_gid;

    // MAC address of the next hop station
    la_mac_addr_t m_mac_addr;

    // Type of the next hop
    nh_type_e m_nh_type;

    /// Common implementation object
    la_next_hop_impl_common m_next_hop_common;

    // l2 port when next_hop is svi
    la_l2_service_port_base_wptr m_l2_port;

    // Manage the TX table
    virtual la_status configure_global_tx_tables() = 0;
    virtual la_status do_configure_global_tx_tables(la_slice_pair_id_t slice_pair) = 0;
    virtual la_status update_global_tx_tables() = 0;
    virtual la_status do_update_global_tx_tables(la_slice_pair_id_t slice_pair) = 0;
    virtual la_status teardown_global_tx_tables() = 0;
    virtual la_status do_teardown_global_tx_tables(la_slice_pair_id_t slice_pair) = 0;
    la_status configure_per_slice_tx_tables(la_slice_id_t slice);
    la_status teardown_per_slice_tx_tables(la_slice_id_t slice);

    virtual la_status populate_nh_and_svi_payload(npl_nh_and_svi_payload_t& out_nh_and_svi_payload,
                                                  la_slice_pair_id_t pair_idx) const = 0;
    virtual la_status populate_nh_payload(npl_nh_payload_t& out_nh_payload,
                                          const la_l3_port_wptr& l3_port,
                                          la_slice_pair_id_t pair_idx) const = 0;
    virtual la_status populate_nh_payload_l2_info(npl_nh_payload_t& out_nh_payload,
                                                  const la_l3_port_wptr& l3_port,
                                                  la_slice_pair_id_t slice_pair) const = 0;
    la_status populate_nh_payload_l3_info(npl_nh_payload_t& out_nh_payload, const la_l3_port_wptr& l3_port) const;
    const la_l2_service_port_base_wptr get_nh_l2_port(const la_svi_port_base_wptr& svi_port) const;

    la_status set_nh_l2_port(const la_l2_service_port_base_wptr& l2_port);
    la_status set_svi_nh_type(nh_type_e nh_type);
    la_status modify_nh_l2_port();
};

} // namesapce leaba

#endif // __LA_NEXT_HOP_BASE_H__
