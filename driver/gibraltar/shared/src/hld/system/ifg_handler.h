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

#ifndef __IFG_HANDLER_H__
#define __IFG_HANDLER_H__

#include "api/system/la_mac_port.h"
#include "hld_types.h"

#include "system/la_mac_port_base.h"

#include "lld/lld_register.h"

namespace silicon_one
{

enum serdes_pool_type_e { pool_16 = 0, pool_18, pool_24, pool_36, NUM };

class la_device_impl;

class ifg_handler
{
public:
    virtual ~ifg_handler(){};

    virtual void pre_initialize() = 0;

    virtual la_status initialize_topology() = 0;

    virtual la_status initialize() = 0;

    virtual la_status init_tcam_memories() = 0;

    virtual la_status configure_port(la_uint_t mac_lane_base_id,
                                     size_t mac_lanes_reserved_count,
                                     la_mac_port::port_speed_e speed,
                                     size_t mac_lanes_count,
                                     la_mac_port::mlp_mode_e mlp_mode,
                                     la_mac_port::fc_mode_e fc_mode)
        = 0;

    virtual la_status configure_lc_56_fabric_port(la_uint_t serdes_base_id,
                                                  size_t serdes_count,
                                                  la_mac_port::port_speed_e speed,
                                                  size_t mac_lanes_count,
                                                  la_mac_port::mlp_mode_e mlp_mode,
                                                  la_mac_port::fc_mode_e fc_mode)
        = 0;

    virtual la_status configure_mlp_mode(la_uint_t mac_lane_base_id,
                                         la_mac_port::port_speed_e speed,
                                         size_t mac_lanes_count,
                                         la_mac_port::mlp_mode_e mlp_mode)
        = 0;

    virtual la_status configure_lanes(la_uint_t mac_lane_base_id, size_t mac_lanes_count, la_mac_port::port_speed_e speed) = 0;

    virtual la_status configure_fabric_ports(la_mac_port::fc_mode_e fc_mode) = 0;

    // The opposite to configure_port
    virtual la_status clear_port(la_uint_t mac_lane_base_id,
                                 size_t mac_lanes_reserved_count,
                                 la_mac_port::port_speed_e speed,
                                 size_t mac_lanes_count)
        = 0;

    virtual la_status allocate_fifo_memory(size_t mac_lane_base, la_mac_port::port_speed_e speed) = 0;
    virtual la_status reset_fifo_memory_allocation(size_t mac_lane_base, size_t mac_lanes_reserved_count) = 0;
    virtual la_status reset_fifo_memory(size_t mac_lane_base,
                                        size_t mac_lanes_reserved_count,
                                        size_t mac_lanes_count,
                                        la_mac_port_base::mac_reset_state_e reset)
        = 0;
    virtual la_status read_fifo_soft_reset_config() = 0;

    virtual la_status configure_read_schedule_weight(la_uint_t mac_lane_base_id,
                                                     size_t mac_lanes_reserved_count,
                                                     la_mac_port::mlp_mode_e mlp_mode,
                                                     la_mac_port::port_speed_e speed)
        = 0;
    virtual la_status reset_read_schedule_weight(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count) = 0;

    virtual la_status set_fc_mode(la_uint_t mac_lane_base_id,
                                  size_t mac_lanes_reserved_count,
                                  la_mac_port::port_speed_e speed,
                                  la_mac_port::fc_mode_e fc_mode)
        = 0;

    virtual la_status set_port_periodic_timer_value(la_uint_t serdes_base_id, size_t serdes_count, la_uint_t timer_value) = 0;
    virtual la_status set_port_periodic_int_enable(la_uint_t serdes_base_id, size_t serdes_count, bool enable) = 0;

    virtual la_status set_ostc_quantizations(la_uint_t mac_lane_base_id,
                                             size_t serdes_count,
                                             la_mac_port::port_speed_e speed,
                                             const la_mac_port::ostc_thresholds& thresholds)
        = 0;
    virtual la_status get_ostc_quantizations(la_uint_t mac_lane_base_id,
                                             size_t mac_lanes_reserved_count,
                                             la_mac_port::port_speed_e speed,
                                             la_mac_port::ostc_thresholds& out_thresholds) const = 0;
    virtual la_status set_default_port_tc(la_uint_t mac_lane_base_id,
                                          size_t mac_lanes_reserved_count,
                                          la_over_subscription_tc_t default_ostc,
                                          la_initial_tc_t default_itc)
        = 0;
    virtual la_status get_default_port_tc(la_uint_t mac_lane_base_id,
                                          la_over_subscription_tc_t& out_default_ostc,
                                          la_initial_tc_t& out_default_itc) const = 0;

    virtual la_status modify_port_tc_tpid(la_uint_t mac_lane_base_id,
                                          size_t mac_lanes_reserved_count,
                                          la_uint_t idx,
                                          la_tpid_t tpid)
        = 0;
    virtual la_status remove_port_tc_tpid(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx) = 0;

    virtual la_status set_port_tc_extract_offset(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t offset) = 0;

    virtual la_status add_port_tc_custom_protocol(la_uint_t mac_lane_base_id,
                                                  size_t mac_lanes_reserved_count,
                                                  la_uint_t idx,
                                                  la_ethertype_t protocol)
        = 0;
    virtual la_status remove_port_tc_custom_protocol(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx)
        = 0;
    virtual la_status reset_port_tc_custom_protocol_configuration(la_uint_t mac_lane_base_id, la_uint_t idx) = 0;

    virtual la_status set_port_tc_layer(la_uint_t mac_lane_base_id,
                                        la_uint_t tpid_idx,
                                        la_mac_port::tc_protocol_e protocol,
                                        la_layer_e layer)
        = 0;
    virtual la_status get_port_tc_layer(la_uint_t mac_lane_base_id,
                                        la_uint_t tpid_idx,
                                        la_mac_port::tc_protocol_e protocol,
                                        la_layer_e& out_layer) const = 0;
    virtual la_status set_port_tc_for_custom_protocol_with_offset(la_uint_t mac_lane_base_id,
                                                                  size_t mac_lanes_reserved_count,
                                                                  la_ethertype_t protocol,
                                                                  la_over_subscription_tc_t ostc,
                                                                  la_initial_tc_t itc)
        = 0;
    virtual la_status set_port_tc_for_custom_protocol(la_uint_t mac_lane_base_id,
                                                      la_tpid_t tpid,
                                                      la_uint_t idx,
                                                      la_over_subscription_tc_t ostc,
                                                      la_initial_tc_t itc)
        = 0;
    virtual la_status get_port_tc_for_custom_protocol(la_uint_t mac_lane_base_id,
                                                      la_tpid_t tpid,
                                                      la_uint_t idx,
                                                      la_over_subscription_tc_t& out_ostc,
                                                      la_initial_tc_t& out_itc) const = 0;
    virtual la_status set_port_tc_for_fixed_protocol(la_uint_t mac_lane_base_id,
                                                     la_mac_port::tc_protocol_e protocol,
                                                     la_uint8_t lower_bound,
                                                     la_uint8_t higher_bound,
                                                     la_over_subscription_tc_t ostc,
                                                     la_initial_tc_t itc)
        = 0;
    virtual la_status get_port_tc_for_fixed_protocol(la_uint_t mac_lane_base_id,
                                                     la_mac_port::tc_protocol_e protocol,
                                                     la_uint8_t priority,
                                                     la_over_subscription_tc_t& out_ostc,
                                                     la_initial_tc_t& out_itc) const = 0;

    virtual la_status clear_port_tc_for_fixed_protocol(size_t mac_lane_base_id) = 0;
    virtual la_status read_ostc_counter(la_uint_t mac_lane_base_id,
                                        la_over_subscription_tc_t ostc,
                                        size_t& out_dropped_packets) const = 0;

    virtual void populate_link_error_info(la_uint_t mac_lane_base_id,
                                          size_t mac_lanes_reserved_count,
                                          lld_register_scptr interrupt_reg,
                                          size_t bit_i,
                                          link_error_interrupt_info& val_out) const = 0;
    virtual la_status set_mac_link_error_interrupt_mask(la_uint_t mac_lane_base_id,
                                                        size_t mac_lanes_reserved_count,
                                                        bool enable_interrupt) const = 0;

    virtual la_status read_mib_counters(bool clear, la_uint_t serdes_idx, la_mac_port::mib_counters& out_mib_counters) const = 0;

    virtual la_status set_rx_lane_swap() = 0;

    virtual la_status read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) = 0;

    virtual size_t get_serdes_count() const = 0;
    virtual size_t get_num_total_existing_serdes() const = 0;
    virtual serdes_pool_type_e get_serdes_pool_type() const = 0;
    virtual size_t get_pif_count() const = 0;
    virtual la_status get_fabric_port_number(la_uint_t first_serdes_id, la_uint_t& out_port_num) const = 0;

    virtual la_status set_synce_default() = 0;

    virtual la_status attach_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                          la_slice_id_t slice_id,
                                          la_ifg_id_t ifg_id,
                                          la_uint_t serdes_id,
                                          uint32_t divider)
        = 0;

    virtual la_status get_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                       uint32_t synce_pin,
                                       la_slice_id_t& out_slice_id,
                                       la_ifg_id_t& out_ifg_id,
                                       la_uint_t& out_serdes_id,
                                       uint32_t& out_divider) const = 0;

    virtual la_status detach_synce_output(la_device::synce_clock_sel_e prim_sec_clock, uint32_t synce_pin) = 0;

    virtual la_status check_synce_attached(la_device::synce_clock_sel_e prim_sec_clock, bool& out_synce_attached) const = 0;

    virtual la_status clear_synce_squelch_lock(la_device::synce_clock_sel_e prim_sec_clock) = 0;

    virtual la_status set_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool squelch_enable) = 0;

    virtual la_status get_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool& out_squelch_enable) = 0;

    virtual size_t get_port_base_index() const = 0;

    virtual la_status update_anlt_order(la_uint_t serdes_base_id, size_t serdes_count) = 0;

    virtual la_status configure_tx_calendar() = 0;

    virtual la_status reset_oob_inj_credits(size_t mac_lane_base_id, int val) = 0;

    virtual la_status clear_tc_tcam_mem(size_t mem_idx) = 0;

    virtual la_status set_block_ingress_data(size_t mac_lane_base, size_t mac_lanes_reserved_count, bool enabled) = 0;
};

} // namespace silicon_one

#endif // __IFG_HANDLER_H__
