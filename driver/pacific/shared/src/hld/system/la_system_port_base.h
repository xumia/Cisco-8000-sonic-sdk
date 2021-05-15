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

#ifndef __LA_SYSTEM_PORT_BASE_H__
#define __LA_SYSTEM_PORT_BASE_H__

#include "api/system/la_mac_port.h"
#include "api/system/la_system_port.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_security_group_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

#include <memory>

namespace silicon_one
{

class la_system_port_base : public la_system_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    /// @brief System port type.
    enum class port_type_e {
        INVALID,  ///< Invalid type
        MAC,      ///< System port above a local MAC port.
        PCI,      ///< System port above a local PCI port.
        NPU_HOST, ///< System port above a local NPU Host port.
        RECYCLE,  ///< System port above a local Recycle port.
        REMOTE,   ///< System port above a port on a remote device.
    };

    static constexpr la_port_extender_vid_t NON_EXTENDED_PORT = -1;

    static constexpr la_uint_t ECN_EXTENDED_SYSTEM_PORT_RANGE = 1 << 12;

    explicit la_system_port_base(const la_device_impl_wptr& device);
    ~la_system_port_base() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid,
                         const la_mac_port_wptr& mac_port,
                         la_system_port_gid_t gid,
                         const la_voq_set_wptr& voq_set,
                         const la_tc_profile_wcptr& tc_profile);
    la_status initialize(la_object_id_t oid,
                         const la_mac_port_wptr& mac_port,
                         la_port_extender_vid_t port_extender_vid,
                         la_system_port_gid_t gid,
                         const la_voq_set_wptr& voq_set,
                         const la_tc_profile_wcptr& tc_profile);
    la_status initialize(la_object_id_t oid,
                         const la_recycle_port_wptr& recycle_port,
                         la_system_port_gid_t gid,
                         const la_voq_set_wptr& voq_set,
                         const la_tc_profile_wcptr& tc_profile);
    la_status initialize(la_object_id_t oid,
                         const la_npu_host_port_base_wptr& npu_host_port,
                         la_system_port_gid_t gid,
                         const la_voq_set_wptr& voq_set,
                         const la_tc_profile_wcptr& tc_profile);
    la_status initialize(la_object_id_t oid,
                         const la_pci_port_wptr& pci_port,
                         la_system_port_gid_t gid,
                         const la_voq_set_wptr& voq_set,
                         const la_tc_profile_wcptr& tc_profile);
    la_status initialize(la_object_id_t oid,
                         const la_remote_port_wptr& remote_port,
                         la_system_port_gid_t gid,
                         const la_voq_set_wptr& voq_set,
                         const la_tc_profile_wcptr& tc_profile);
    virtual la_status destroy() = 0;

    // Inherited API-s
    la_system_port_gid_t get_gid() const override;
    la_status get_port_extended_vid(la_port_extender_vid_t& out_port_extender_vid) const override;
    la_system_port_scheduler* get_scheduler() const override;
    la_voq_set* get_voq_set() const override;
    la_status set_ect_voq_set(la_voq_set* voq_set) override;
    la_voq_set* get_ect_voq_set() const override;
    la_slice_id_t get_slice() const override;
    la_ifg_id_t get_ifg() const override;
    la_uint_t get_base_serdes() const override;
    la_uint_t get_base_pif() const override;
    la_status set_tc_profile(const la_tc_profile* tc_profile) override;
    const la_tc_profile* get_tc_profile() const override;
    la_object* get_underlying_port() const override;
    la_status mac_port_reconfig_handler(la_mac_port::port_speed_e mac_port_speed);

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_system_port_base API-s

    /// @brief Return the port's base VOQ.
    ///
    /// @brief The port's base VOQ.
    la_voq_gid_t get_base_voq() const;

    la_voq_gid_t get_ect_voq_base() const;

    /// @brief Drop the NPP attributes index setting for this system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status erase_source_pif_table_entries();

    /// @brief Get the underlying transport type to which this port is attached.
    ///
    /// @return The underlying transport type to which this port is attached.
    port_type_e get_port_type() const;

    /// @brief Configure Inbound Mirror command to destination entry.
    ///
    /// @param[in]  ibm_cmd           Inbound Mirror command index.
    /// @param[in]  sampling_rate     Sampling rate.
    /// @param[in]  mirror_to_dest    Mirror to the original destination.
    /// @param[in]  voq_offset        Offset from destination port BVN.

    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status configure_ibm_command(la_uint_t ibm_cmd,
                                            la_uint_t sampline_rate,
                                            bool mirror_to_dest,
                                            la_uint_t voq_offset) const = 0;

    /// @brief  Get the port's internal allocated NPP attributes index.
    ///
    /// @retval The port's NPP attributes index.
    uint64_t get_npp_attributes_index() const;

    /// @brief Set the mac af entry for this port.
    ///
    /// @param[in]  value               NPP attributes data written by the ethernet port above.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status set_mac_af_npp_attributes(const npl_mac_af_npp_attributes_table_t::value_type& value);

    /// @brief Set the Inject-Up entry for this port.
    ///
    /// @param[in]  initial_pd_nw_rx_data   Inject up data written.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_inject_up_entry(npl_initial_pd_nw_rx_data_t initial_pd_nw_rx_data) = 0;

    /// @brief Erase the Inject-Up entry for this port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status erase_inject_up_entry() = 0;

    /// @brief Set the Inject-Up entry for this recycle port.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_recycled_inject_up_entry() = 0;

    la_status set_mask_eve(bool mask_eve);
    la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode);
    la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const;
    la_status is_valid_voq_mapping(const la_voq_set_wptr& voq_set) const;
    virtual la_status program_voq_mapping(const la_voq_set_wptr& voq_set, bool is_lp) const = 0;
    la_status clear_voq_mapping(const la_voq_set_wptr& voq_set) const;

    virtual size_t get_base_oq() const;

    virtual la_status set_mtu(la_mtu_t mtu) = 0;
    la_mtu_t get_mtu() const;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    bool has_port_dependency() const;

    la_status set_decrement_ttl(bool decrement_ttl);
    bool get_decrement_ttl() const;

    la_status set_stack_prune(bool prune);
    la_status get_stack_prune(bool& prune) const;

    la_system_port_base_wcptr get_punt_recycle_port() const;

    virtual la_status initialize_for_pci(la_object_id_t oid,
                                         const la_pci_port_wptr& pci_port,
                                         la_system_port_gid_t gid,
                                         const la_voq_set_wptr& voq_set,
                                         const la_tc_profile_wcptr& tc_profile)
        = 0;

    static la_system_port_base_wcptr upcast_from_api(const la_device_impl_wptr& device, const la_system_port* ptr);
    static la_system_port_base_wcptr upcast_from_api(const la_device_impl_wptr& device, la_system_port_wcptr wptr);
    virtual la_status program_stack_control_traffic_voq_mapping(const la_voq_set_wptr& voq_set) const = 0;

    virtual la_slice_id_t get_default_punt_slice() const;
    la_status do_set_slice_rx_obm_code(const la_system_port_base_wcptr& recycle_sys_port);
    la_status do_erase_slice_rx_obm_code(const la_system_port_base_wcptr& recycle_sys_port);
    virtual la_status update_npp_sgt_attributes(la_sgt_t security_group_tag) = 0;
    virtual la_status update_dsp_sgt_attributes(bool security_group_policy_enforcement) = 0;

protected:
    la_system_port_base() = default;
    la_status pre_initialize(la_object_id_t oid,
                             const la_object_wptr& port,
                             la_system_port_gid_t gid,
                             const la_voq_set_wptr& voq_set);

    /// Common initialization for local system ports
    virtual la_status initialize_common_local(const la_object_wptr& port,
                                              const la_voq_set_wptr& voq_set,
                                              const la_tc_profile_wcptr& tc_profile);

    /// Common initialization for local and remote system ports
    la_status initialize_common(const la_object_wptr& port, const la_voq_set_wptr& voq_set, const la_tc_profile_wcptr& tc_profile);

    virtual la_status erase_pif_source_pif_table_entry(la_uint_t pif) = 0;
    virtual la_status erase_port_extender_map_rx_data_table() = 0;

    la_status configure_fwd_destination_to_tm_result_data_table();
    la_status erase_fwd_destination_to_tm_result_data_table();

    la_status set_slice_tx_dsp_attributes();
    la_status erase_slice_tx_dsp_attributes();

    virtual la_status populate_common_dsp_attributes(npl_dsp_attr_common_t& common_attributes) = 0;

    la_status set_voq_mapping(const la_voq_set_wptr& voq_set);
    virtual la_status set_tc_profile_core(const la_tc_profile_wcptr& tc_profile) = 0;
    virtual la_status teardown_tm_tables() = 0;
    la_status allocate_npp_attributes_index();
    la_status release_npp_attributes_index();

    la_status configure_slice_rx_map_npp_to_ssp();
    la_status erase_slice_rx_map_npp_to_ssp();

    virtual la_status calculate_network_txpp(npl_dsp_l2_attributes_table_t::key_type& key, la_uint_t pif_offset) = 0;
    virtual la_status calculate_network_txpp(npl_dsp_l3_attributes_table_t::key_type& key, la_uint_t pif_offset) = 0;

    la_status destroy_common_local();

    la_status is_test_mode_punt_to_egress(bool& test_mode_punt_to_egress);

    la_status set_slice_rx_obm_code();
    la_status erase_slice_rx_obm_code();
    la_status set_rx_obm_code_for_tests();
    la_status erase_rx_obm_code_for_tests();
    void populate_rx_obm_code_key_value(bool is_sched_rcy,
                                        npl_rx_obm_code_table_key_t& out_key,
                                        npl_rx_obm_code_table_value_t& out_value) const;

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Port GID
    la_system_port_gid_t m_gid;

    // Underlying transport: MAC/NPU Host/PCI/Recycle/Remote device
    port_type_e m_port_type;

    // MAC port servicing this system port
    la_mac_port_base_wptr m_mac_port;

    la_npu_host_port_base_wptr m_npu_host_port;

    la_pci_port_base_wptr m_pci_port;

    la_system_port_base_wcptr m_punt_recycle_port;

    la_recycle_port_base_wptr m_recycle_port;

    la_remote_port_impl_wptr m_remote_port;

    // Interface scheduler
    la_interface_scheduler_wptr m_intf_scheduler;

    // Destination device ID
    la_slice_id_t m_destination_device_id;

    // Slice ID
    la_slice_id_t m_slice_id;

    // Source group offset (for split VoQ)
    la_uint_t m_source_group_offset;

    // IFG ID
    la_ifg_id_t m_ifg_id;

    // Serdes base
    // This might include logical numbers that do not map to a real SerDes.
    la_uint_t m_serdes_base;

    // Number of SerDes elements
    size_t m_serdes_count;

    // PIF base
    // This might include logical numbers that do not map to a real pif.
    la_uint_t m_pif_base;

    // Number of PIF's
    size_t m_pif_count;

    // NPP index associated with this system port.
    uint64_t m_npp_attributes_index;

    // Base VOQ
    la_voq_set_wptr m_voq_set;

    // ECN capable transport VOQ (for addressing ECN)
    la_voq_set_wptr m_ect_voq_set;

    // TC profiles
    la_tc_profile_wcptr m_tc_profile;

    // System port scheduler
    la_system_port_scheduler_impl_wptr m_scheduler;

    // Pruning range
    uint64_t m_mc_pruning_high;
    uint64_t m_mc_pruning_low;

    // TTL propagation
    npl_ttl_mode_e m_ttl_inheritance_mode;

    // MTU
    la_mtu_t m_mtu;

    // port extended
    la_port_extender_vid_t m_port_extender_vid;
    size_t m_oq_pair_mac_id;

    // mask egress vlan editting
    bool m_mask_eve;

    virtual la_status update_mtu_macro_trigger_threshold(la_mtu_t old_mtu, la_mtu_t mtu) = 0;

    bool m_pfc_enabled;

    bool m_decrement_ttl;

    bool m_stack_prune;
};
}

/// @}

#endif
