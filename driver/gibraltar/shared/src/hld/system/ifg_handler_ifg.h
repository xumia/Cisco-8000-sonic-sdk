// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __IFG_HANDLER_IFG_H__
#define __IFG_HANDLER_IFG_H__

#include "system/ifg_handler_base.h"

namespace silicon_one
{

class la_device_impl;

class ifg_handler_ifg : public ifg_handler_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ifg_handler_ifg(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id);
    ~ifg_handler_ifg() override;

    la_status init_tcam_memories() override;

    la_status set_port_tc_for_custom_protocol_with_offset(la_uint_t mac_lane_base_id,
                                                          size_t mac_lanes_reserved_count,
                                                          la_ethertype_t protocol,
                                                          la_over_subscription_tc_t ostc,
                                                          la_initial_tc_t itc) override;

    la_status clear_port_tc_for_fixed_protocol(size_t mac_lane_base_id) override;

    /// @brief Write value to ifgb_tc_extract_cfg_reg_register.
    ///
    /// @param[in]      reg_value               Value to write to the register.
    /// @param[in]      mac_lane_base_id          First mac_port ID of the configured mac_port.
    /// @param[in]      mac_lanes_reserved_count            Number of mac_ports of the configured mac_port.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status write_tc_extract_cfg(const bit_vector& reg_value, la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count);

    la_status set_port_tc_for_fixed_protocol(la_uint_t mac_lane_base_id,
                                             la_mac_port::tc_protocol_e protocol,
                                             la_uint8_t lower_bound,
                                             la_uint8_t higher_bound,
                                             la_over_subscription_tc_t ostc,
                                             la_initial_tc_t itc) override;

    la_status read_fifo_soft_reset_config() override;
    void populate_link_error_info(la_uint_t mac_lane_base_id,
                                  size_t mac_lanes_reserved_count,
                                  lld_register_scptr interrupt_reg,
                                  size_t bit_i,
                                  link_error_interrupt_info& val_out) const override;
    la_status set_mac_link_error_interrupt_mask(la_uint_t mac_lane_base_id,
                                                size_t mac_lanes_reserved_count,
                                                bool enable_interrupt) const override;

    struct ifg_registers {
        lld_register_scptr fc_cfg0;
        lld_register_scptr rx_rstn_reg;
        lld_register_scptr tx_rstn_reg;
        lld_register_scptr tx_tsf_ovf_interrupt_reg;

        lld_register_array_scptr tx_fif_cfg;
        lld_register_array_scptr tc_extract_cfg_reg;
        lld_register_array_scptr rx_port_cgm_tc0_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc1_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc2_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc3_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc0_partial_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc1_partial_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc2_partial_drop_counter;
        lld_register_array_scptr rx_port_cgm_tc3_partial_drop_counter;

        std::vector<lld_memory_array_sptr> tc_tcam;
        std::vector<lld_memory_array_sptr> tc_tcam_mem;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ifg_registers);
    ifg_registers m_ifgb_registers;

    virtual void initialize_register_pointers() = 0;
    /// @brief Try to merge entries in the TC TCAM table and find room for the new range.
    ///
    /// @param[in]      mem_id                  Tcam to add the new entry.
    /// @param[in]      min_edge                Lower edge of the new range.
    /// @param[in]      max_edge                Higher edge of the new range.
    /// @param[in]      value                   Value of the new range.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status merge_tcam_entries(size_t mem_idx, la_uint_t min_edge, la_uint_t max_edge, la_uint_t value);

    /// @brief Insert vector of TCAM entries to the TC TCAM.
    ///
    /// @param[in]      mem_idx                 Memory to write the entries.
    /// @param[in]      entries                 Entries to insert to the TCAM.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status insert_port_tc_tcam(size_t mem_idx, const std::vector<tcam_entry>& entries);

    // For serialization purposes only
    ifg_handler_ifg() = default;
};
} // namespace silicon_one

#endif // __IFG_HANDLER_IFG_H__
