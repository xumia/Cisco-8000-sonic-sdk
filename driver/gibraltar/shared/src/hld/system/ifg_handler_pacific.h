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

#ifndef __IFG_HANDLER_PACIFIC_H__
#define __IFG_HANDLER_PACIFIC_H__

#include "api/system/la_mac_port.h"
#include "hld_types.h"
#include <memory>
#include <set>

#include "lld/pacific_tree.h"
#include "system/ifg_handler_ifg.h"
#include "system/la_mac_port_base.h"

namespace silicon_one
{

class la_device_impl;

class ifg_handler_pacific : public ifg_handler_ifg
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit ifg_handler_pacific(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id);
    ~ifg_handler_pacific() override;

    void pre_initialize() override;

    la_status initialize_topology() override;

    la_status initialize() override;

    la_status configure_lc_56_fabric_port(la_uint_t mac_lane_base_id,
                                          size_t mac_lanes_reserved_count,
                                          la_mac_port::port_speed_e speed,
                                          size_t mac_lanes_count,
                                          la_mac_port::mlp_mode_e mlp_mode,
                                          la_mac_port::fc_mode_e fc_mode) override;

    la_status configure_mlp_mode(la_uint_t mac_lane_base_id,
                                 la_mac_port::port_speed_e speed,
                                 size_t mac_lanes_count,
                                 la_mac_port::mlp_mode_e mlp_mode) override;

    la_status configure_lanes(la_uint_t mac_lane_base_id, size_t mac_lanes_count, la_mac_port::port_speed_e speed) override;

    la_status configure_fabric_ports(la_mac_port::fc_mode_e fc_mode) override;

    la_status reset_fifo_memory(size_t mac_lane_base,
                                size_t mac_lanes_reserved_count,
                                size_t mac_lanes_count,
                                la_mac_port_base::mac_reset_state_e reset) override;

    la_status configure_read_schedule_weight(la_uint_t mac_lane_base_id,
                                             size_t mac_lanes_reserved_count,
                                             la_mac_port::mlp_mode_e mlp_mode,
                                             la_mac_port::port_speed_e speed) override;

    void initialize_register_pointers() override;

    la_status reset_read_schedule_weight(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count) override;

    la_status set_port_periodic_timer_value(la_uint_t mac_lane_base_id,
                                            size_t mac_lanes_reserved_count,
                                            la_uint_t timer_value) override;
    la_status set_port_periodic_int_enable(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable) override;

    la_status set_ostc_quantizations(la_uint_t mac_lane_base_id,
                                     size_t mac_lanes_reserved_count,
                                     la_mac_port::port_speed_e speed,
                                     const la_mac_port::ostc_thresholds& thresholds) override;
    la_status get_ostc_quantizations(la_uint_t mac_lane_base_id,
                                     size_t mac_lanes_reserved_count,
                                     la_mac_port::port_speed_e speed,
                                     la_mac_port::ostc_thresholds& out_thresholds) const override;
    la_status set_default_port_tc(la_uint_t mac_lane_base_id,
                                  size_t mac_lanes_reserved_count,
                                  la_over_subscription_tc_t default_ostc,
                                  la_initial_tc_t default_itc) override;
    la_status get_default_port_tc(la_uint_t mac_lane_base_id,
                                  la_over_subscription_tc_t& out_default_ostc,
                                  la_initial_tc_t& out_default_itc) const override;

    la_status modify_port_tc_tpid(la_uint_t mac_lane_base_id,
                                  size_t mac_lanes_reserved_count,
                                  la_uint_t idx,
                                  la_tpid_t tpid) override;
    la_status remove_port_tc_tpid(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx) override;

    la_status set_port_tc_extract_offset(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t offset) override;

    la_status add_port_tc_custom_protocol(la_uint_t mac_lane_base_id,
                                          size_t mac_lanes_reserved_count,
                                          la_uint_t idx,
                                          la_ethertype_t protocol) override;
    la_status remove_port_tc_custom_protocol(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx) override;
    la_status read_ostc_counter(la_uint_t mac_lane_base_id,
                                la_over_subscription_tc_t ostc,
                                size_t& out_dropped_packets) const override;

    la_status set_rx_lane_swap() override;

    la_status read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) override;

    la_status get_fabric_port_number(la_uint_t first_serdes_id, la_uint_t& out_port_num) const override;

    la_status set_synce_default() override;

    la_status attach_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                  la_slice_id_t slice_id,
                                  la_ifg_id_t ifg_id,
                                  la_uint_t serdes_id,
                                  uint32_t divider) override;

    la_status get_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                               uint32_t synce_pin,
                               la_slice_id_t& out_slice_id,
                               la_ifg_id_t& out_ifg_id,
                               la_uint_t& out_serdes_id,
                               uint32_t& out_divider) const override;

    la_status detach_synce_output(la_device::synce_clock_sel_e prim_sec_clock, uint32_t synce_pin) override;

    la_status clear_synce_squelch_lock(la_device::synce_clock_sel_e prim_sec_clock) override;

    la_status set_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool squelch_enable) override;

    la_status get_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool& out_squelch_enable) override;

    size_t get_port_base_index() const override;

    la_status update_anlt_order(la_uint_t serdes_base_id, size_t serdes_count) override;

private:
    la_status reset_config();
    la_status reset_fifo_memory_lc56(size_t mac_lane_base,
                                     size_t mac_lanes_reserved_count,
                                     la_mac_port_base::mac_reset_state_e reset);

    la_status reset_rx_fifo_memory_allocation() override;
    la_status configure_rx_fifo_ports();
    la_status configure_rx_fifo_host_port(size_t host_lines);
    la_status configure_rx_fifo_out_of_band(size_t csms_lines, size_t fte_lines, size_t frm_lines);
    la_status configure_rx_out_of_band_cgm(size_t csms_lines, size_t fte_lines, size_t frm_lines);
    la_status configure_recycle_fifo() override;

    la_status allocate_rx_fifo_memory(size_t mac_lane_base, size_t buffer_units) override;
    la_status allocate_tx_fifo_memory_main_ports(size_t mac_lane_base, size_t buffer_units) override;
    la_status allocate_tx_fifo_memory_extra_ports(size_t mac_lane_base, size_t buffer_units) override;

    la_status configure_rx_cgm(size_t mac_lane_base, size_t mac_lanes_reserved_count, la_mac_port::port_speed_e speed) override;

    la_status reset_read_schedule_weight();
    la_status configure_read_schedule_weight_main_ports(la_uint_t mac_lane_base_id,
                                                        size_t mac_lanes_reserved_count,
                                                        uint64_t read_weight);
    la_status configure_read_schedule_weight_extra_ports(la_uint_t mac_lane_base_id,
                                                         size_t mac_lanes_reserved_count,
                                                         uint64_t read_weight);

    la_status init_fifo_memory();
    la_status configure_oob_inject_packet_counters() override;
    la_status configure_oob_extract_packet_counters() override;

    la_status update_lane_modes(la_uint_t mac_lane_base_id,
                                size_t mac_lanes_count,
                                uint64_t& two_lane_mode,
                                uint64_t& eight_lane_mode);

    la_status set_fc_mode_periodic(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable) override;
    la_status set_fc_mode_port(la_uint_t mac_lane_base_id,
                               size_t mac_lanes_reserved_count,
                               la_mac_port::port_speed_e speed,
                               la_mac_port::fc_mode_e fc_mode) override;

    la_status read_mib_counters(bool clear, la_uint_t serdes_idx, la_mac_port::mib_counters& out_mib_counters) const override;

    /// @brief Get TCAM key opcode and priorities length based on the poer & LUT results.
    ///
    /// The key to the TCAM is (opcode | priority) where opcode is the MSBs and priorities are the LSBs.
    ///
    /// @param[in]      mac_lane_base_id          Lowest entry.
    /// @param[in]      protocol                Packet's protocol.
    /// @param[out]     out_opcode              Mask for the key.
    /// @param[out]     out_length              Length of the priorities.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status get_port_tc_tcam_key_opcode(la_uint_t mac_lane_base_id,
                                          la_mac_port::tc_protocol_e protocol,
                                          la_uint32_t& out_opcode,
                                          la_uint32_t& out_length) const override;

    la_status configure_tx_calendar() override;

    pacific_tree_scptr m_pacific_tree;

    // Rx FIFO lines for each port
    size_t m_single_port_lines;

    // For serialization purposes only
    ifg_handler_pacific() = default;
};

} // namespace silicon_one

#endif // __IFG_HANDLER_PACIFIC_H__
