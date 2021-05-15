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

#ifndef __LA_L2_MIRROR_COMMAND_BASE_H__
#define __LA_L2_MIRROR_COMMAND_BASE_H__

#include "api/qos/la_meter_set.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/system/la_mirror_command.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_stack_port_base.h"

namespace silicon_one
{

class la_l2_mirror_command_base : public la_l2_mirror_command, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_l2_mirror_command_base(const la_device_impl_wptr& device);
    ~la_l2_mirror_command_base() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid,
                         la_mirror_gid_t mirror_gid,
                         const la_punt_inject_port_base_wptr& pi_port,
                         const la_system_port_base_wptr& system_port,
                         la_mac_addr_t mac_addr,
                         const la_vlan_tag_tci_t& vlan_tag,
                         la_uint_t voq_offset,
                         const la_meter_set_wptr& meter,
                         double probability);
    la_status initialize(la_object_id_t oid,
                         la_mirror_gid_t mirror_gid,
                         const la_ethernet_port_base_wptr& eth_port,
                         const la_system_port_base_wptr& system_port,
                         la_uint_t voq_offset,
                         double probability);
    la_status initialize(la_object_id_t oid,
                         la_mirror_gid_t mirror_gid,
                         const la_npu_host_port_base_wptr& npu_host_port,
                         la_uint_t voq_offset,
                         double probability);
    la_status initialize(la_object_id_t oid,
                         la_mirror_gid_t mirror_gid,
                         const la_punt_inject_port_base_wptr& pi_port,
                         la_uint_t voq_offset,
                         double probability);
    la_status destroy();

    // la_mirror_command API-s
    la_mirror_gid_t get_gid() const override;

    // la_l2_mirror_command API-s
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status get_vlan_tag(la_vlan_tag_tci_t& out_vlan_tag) const override;
    const la_punt_inject_port* get_punt_inject_port() const override;
    la_status set_probability(double probability) override;
    la_status get_probability(double& out_probability) const override;
    la_status set_voq_offset(la_uint_t offset) override;
    la_uint_t get_voq_offset() const override;
    la_status set_meter(const la_meter_set* meter) override;
    la_status get_meter(const la_meter_set*& out_meter) const override;
    la_status set_mirror_to_dest(bool mirror_to_dest);
    bool get_mirror_to_dest() const;
    bool get_truncate() const override;
    la_status set_counter(la_counter_set* counter) override;
    la_status get_counter(la_counter_set*& out_counter) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get all IFGs used by this SPA port.
    ///
    /// @return Vector of IFGs used.
    slice_ifg_vec_t get_ifgs() const;

    // Implementation API-s
    /// @brief Get system port associated with this Mirror command.
    ///
    /// @return la_system_port* for this Mirror command.\n
    ///         nullptr if not initialized.
    const la_system_port_base* get_system_port() const;

    /// @brief Get mirror type
    mirror_type_e get_mirror_type() const;

    // for stack port spa update
    la_status notify_change(dependency_management_op op) override;

protected:
    // used for configuring cud entries table
    enum pfc_mirror_e { MEASUREMENT, PILOT, NONE };

    la_l2_mirror_command_base() = default;
    virtual la_status populate_punt_encap_data(la_uint_t mirror_gid,
                                               npl_punt_encap_data_t& punt_encap_data,
                                               la_uint_t encap_ptr) const = 0;
    virtual la_status configure_cud_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr) = 0;
    virtual la_status teardown_cud_entry(la_uint_t mirror_hw_id) = 0;

    la_status initialize_common();
    la_status initialize_hw_id_and_encap_ptr(la_mirror_gid_t mirror_gid);
    la_status configure_redirect_encap(la_uint_t encap_ptr);
    la_status configure_recycle_slice_entry(la_uint_t mirror_hw_id);
    la_status teardown_recycle_slice_entry(la_uint_t mirror_hw_id);
    la_status configure_ibm_uc_cmd_to_encap_data_table(la_uint_t key);
    la_status teardown_ibm_uc_cmd_to_encap_data_table(la_uint_t key);
    virtual la_status configure_mirror_to_dsp_in_npu_soft_header_table(uint8_t value) = 0;
    virtual la_status teardown_mirror_to_dsp_in_npu_soft_header_table() = 0;
    la_status configure_ibm_command_and_rx_obm_table(la_uint_t sampline_rate);
    la_status configure_mirror_egress_attributes_table(la_slice_id_t slice, la_counter_set* counter);
    la_status teardown_mirror_egress_attributes_table(la_slice_id_t slice);
    la_slice_ifg get_actual_ifg() const;
    virtual la_status configure_rx_obm_punt_src_and_code(uint64_t punt_source, la_voq_gid_t voq_id) const = 0;
    virtual void populate_rx_obm_code_table_key(la_uint_t mirror_gid, npl_rx_obm_code_table_key_t& out_key) const = 0;
    virtual la_status configure_redirect_code(uint64_t redirect_code, npl_punt_nw_encap_type_e redirect_type, la_uint_t encap_ptr)
        = 0;

    virtual la_status configure_recycle_override_entry(la_uint_t mirror_hw_id) = 0;
    virtual la_status remove_recycle_override_entry(la_uint_t mirror_hw_id) = 0;

    // API helpers.
    la_status do_set_counter(la_counter_set* counter);
    la_status add_l2_mirror_command_counter(la_counter_set* counter);
    la_status remove_l2_mirror_command_counter();

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Mirror command GID
    la_mirror_gid_t m_mirror_gid;

    la_uint_t m_mirror_hw_id;

    // Mirror type
    mirror_type_e m_mirror_type;

    // PFC mirroring type
    pfc_mirror_e m_pfc_mirroring = pfc_mirror_e::NONE;

    la_uint_t m_encap_ptr;

    // Mirror port's GID
    la_system_port_gid_t m_system_port_gid;

    // Punt Inject port
    la_punt_inject_port_base_wptr m_pi_port;

    // Ethernet port
    la_ethernet_port_base_wptr m_eth_port;

    // System port
    la_system_port_base_wcptr m_system_port;

    // MAC associated with the destination
    la_mac_addr_t m_mac_addr;

    // VLAN tag associated with the destination
    la_vlan_tag_tci_t m_vlan_tag;

    // Offset from base VOQ for the mirror command
    la_uint_t m_voq_offset;

    // Meter associated with this mirror command
    la_meter_set_impl_wptr m_meter;

    // Sampling probability
    double m_probability;

    // Encap type
    npl_punt_nw_encap_type_e m_encap_type;

    // Whether to mirror to the destination
    bool m_mirror_to_dest;

    // Whether to truncate the copy.
    bool m_truncate;

    // Counter set for the mirror session
    la_counter_set_wptr m_counter;

    // Destination VOQ for the mirror command
    npl_destination_t m_destination;

    // For MC LPTS
    bool m_is_mc_lpts;

    // NPU host port
    la_npu_host_port_base_wptr m_npu_host_port;

    // Resolved final system port incase of remote mirroring with stacking, pcie/npu host port
    la_system_port_base_wcptr m_final_system_port;

    // Stack Port
    la_stack_port_base_wcptr m_stack_port;

    destination_id get_mirror_destination_id();
    la_status resolve_final_system_port();

    virtual la_status configure_stack_remote_mirror_destination_map(la_uint_t mirror_gid, npl_destination_t destination) = 0;
    virtual la_status teardown_stack_remote_mirror_destination_map(la_uint_t mirror_gid) = 0;
};
}

#endif // __LA_L2_MIRROR_COMMAND_BASE_H__
