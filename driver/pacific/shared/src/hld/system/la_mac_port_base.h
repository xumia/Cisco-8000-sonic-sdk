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

#ifndef __LA_MAC_PORT_BASE_H__
#define __LA_MAC_PORT_BASE_H__

#include <memory>
#include <tuple>
#include <vector>

#include "api/system/la_mac_port.h"
#include "api/types/la_notification_types.h"
#include "api/types/la_system_types.h"
#include "common/ranged_index_generator.h"
#include "hld_utils.h"
#include "lld/interrupt_tree.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class mac_pool_port;
class la_rx_cgm_sq_profile_impl;

class la_mac_port_base : public la_mac_port
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        NUM_MAC_POOL2_BLOCKS = 1,
        NUM_SERDESES_IN_MAC_POOL2 = 2,
        NUM_MAC_POOL8_BLOCKS = 2,
        NUM_SERDESES_IN_MAC_POOL4 = 4,
        NUM_SERDESES_IN_MAC_POOL8 = 8,
        NUM_MAC_LANES_IN_MAC_POOL8 = 8,
        OSTC_NUM_CUSTOM_ETHERTYPES = 4,
        OSTC_NUM_TPIDS = 4,
        MAX_TC_EXTRACT_OFFSET = 23,
    };

    enum class mac_reset_state_e {
        RESET_ALL = 0,     ///< All layers are in reset state.
        RESET_MAC_RX_ONLY, ///< All layers/components, except MAC Rx are active, MAC Rx in reset.
        ACTIVE_ALL,        ///< All layers are in reset state.
    };

    enum {
        MAX_PFC_QUANTA = (1 << 16) - 1,
    };

    explicit la_mac_port_base(const la_device_impl_wptr& device);
    ~la_mac_port_base() override;

    // Object life-cycle API-s
    la_status initialize_network(la_object_id_t oid,
                                 la_slice_id_t slice_id,
                                 la_ifg_id_t ifg_id,
                                 la_uint_t serdes_base,
                                 size_t num_of_serdes,
                                 port_speed_e speed,
                                 bool is_extended,
                                 fc_mode_e rx_fc_mode,
                                 fc_mode_e tx_fc_mode,
                                 fec_mode_e fec_mode);

    la_status initialize_fabric(la_object_id_t oid,
                                la_slice_id_t slice_id,
                                la_ifg_id_t ifg_id,
                                la_uint_t serdes_base,
                                size_t num_of_serdes,
                                port_speed_e speed,
                                fc_mode_e fc_mode);

    la_status destroy();

    // Inherited API-s
    la_status set_debug_mode(bool enable) override;
    la_status get_debug_mode(bool& enable) const override;

    la_status set_serdes_tuning_mode(serdes_tuning_mode_e mode) override;
    la_status get_serdes_tuning_mode(serdes_tuning_mode_e& out_mode) const override;

    la_status set_serdes_continuous_tuning_enabled(bool enabled) override;
    la_status get_serdes_continuous_tuning_enabled(bool& out_enabled) const override;

    la_status set_serdes_parameter(la_uint_t serdes_idx,
                                   serdes_param_stage_e stage,
                                   serdes_param_e param,
                                   serdes_param_mode_e mode,
                                   int32_t value) override;
    la_status get_serdes_parameter(la_uint_t serdes_idx,
                                   serdes_param_stage_e stage,
                                   serdes_param_e param,
                                   serdes_param_mode_e& out_mode,
                                   int32_t& out_value) const override;
    la_status get_serdes_parameter_hardware_value(la_uint_t serdes_idx, serdes_param_e param, int32_t& out_value) override;
    la_status get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const override;
    la_status clear_serdes_parameter(la_uint_t serdes_idx, serdes_param_stage_e stage, serdes_param_e param) override;

    la_status set_speed_enabled(port_speed_e speed, bool enabled) override;
    la_status set_fec_mode_enabled(fec_mode_e fec_mode, bool enabled) override;

    la_status activate() override;
    la_status get_port_signal_ok(bool& out_signal_ok) override;
    la_status get_serdes_signal_ok(la_uint_t serdes_idx, bool& out_signal_ok) override;
    la_status tune(bool block) override;
    la_status get_tune_status(bool& out_completed) override;
    la_status reset() override;
    la_status stop() override;
    la_status set_block_ingress_data(bool enabled) override;
    la_status get_block_ingress_data(bool& out_enabled) const override;

    la_status get_state(state_e& out_state) const override;
    la_status get_an_enabled(bool& out_enabled) const override;
    la_status set_an_enabled(bool enabled) override;
    bool is_an_capable() const override;
    la_status get_state_histogram(bool clear, state_histogram& out_state_histogram) override;

    la_status get_link_down_histogram(bool clear, la_mac_port::link_down_interrupt_histogram& out_link_down_histogram) override;

    la_slice_id_t get_slice() const override;
    la_ifg_id_t get_ifg() const override;
    la_uint_t get_first_serdes_id() const override;
    size_t get_num_of_serdes() const override;
    la_uint_t get_first_pif_id() const override;
    la_uint_t get_first_pif_id_internal() const;
    size_t get_num_of_pif() const override;
    virtual la_status initialize_pif() = 0;

    struct location {
        la_slice_id_t slice_id;
        la_ifg_id_t ifg_id;
        la_uint_t first_serdes_id;
    };
    location get_location() const;

    la_status get_speed(la_mac_port::port_speed_e& out_speed) const override;
    la_status set_speed(la_mac_port::port_speed_e speed) override;
    la_status reconfigure(size_t num_of_serdes,
                          la_mac_port::port_speed_e speed,
                          la_mac_port::fc_mode_e rx_fc_mode,
                          la_mac_port::fc_mode_e tx_fc_mode,
                          la_mac_port::fec_mode_e fec_mode) override;
    la_status get_serdes_speed(la_mac_port::port_speed_e& out_speed) const override;
    la_status get_fec_mode(la_mac_port::fec_mode_e& out_fec_mode) const override;
    la_status set_fec_mode(la_mac_port::fec_mode_e fec_mode) override;
    la_status get_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e& out_fc_mode) const override;
    la_status set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode) override;
    la_status read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) const override;
    la_status read_mac_status(la_mac_port::mac_status& out_mac_status) const override;
    la_status read_mac_pcs_lane_mapping(la_mac_port::mac_pcs_lane_mapping& out_mac_pcs_lane_mapping) const override;
    la_status read_mib_counters(bool clear, la_mac_port::mib_counters& out_mib_counters) const override;
    la_status set_rs_fec_debug_enabled() override;
    la_status get_rs_fec_debug_enabled(bool& out_debug_status) const override;
    la_status read_rs_fec_debug_counters(rs_fec_debug_counters& out_debug_counters) const override;
    la_status read_rs_fec_debug_counters(bool clear, rs_fec_debug_counters& out_debug_counters) const override;
    la_status read_rs_fec_symbol_errors_counters(rs_fec_sym_err_counters& out_sym_err_counters) const override;
    la_status read_rs_fec_symbol_errors_counters(bool clear, rs_fec_sym_err_counters& out_sym_err_counters) const override;
    la_status read_ostc_counter(la_over_subscription_tc_t ostc, size_t& out_dropped_packets) const override;
    la_status read_counter(counter_e counter_type, size_t& out_counter) const override;
    la_status read_counter(bool clear, counter_e counter_type, size_t& out_counter) const override;
    la_status read_counter(serdes_counter_e counter_type, la_uint_t serdes_idx, size_t& out_counter) const override;
    la_status clear_counters() const override;

    la_interface_scheduler* get_scheduler() const override;

    la_status get_min_packet_size(la_uint_t& out_min_size) const override;
    la_status set_min_packet_size(la_uint_t min_size) override;
    la_status get_max_packet_size(la_uint_t& out_max_size) const override;
    la_status set_max_packet_size(la_uint_t max_size) override;

    la_status get_fec_bypass_mode(fec_bypass_e& out_fec_bp) const override;
    la_status set_fec_bypass_mode(fec_bypass_e fec_bp) override;

    la_status get_preamble_compression_enabled(bool& out_enabled) const override;
    la_status set_preamble_compression_enabled(bool enabled) override;
    la_status get_ipg(la_uint16_t& out_gap_len, la_uint16_t& out_gap_tx_bytes) const override;
    la_status set_ipg(la_uint16_t gap_len, la_uint16_t gap_tx_bytes) override;
    la_status get_crc_enabled(bool& out_enabled) const;
    la_status set_crc_enabled(bool enabled);

    la_status tx_refresh() override;

    la_status get_loopback_mode(loopback_mode_e& out_loopback_mode) const override;
    la_status set_loopback_mode(loopback_mode_e mode) override;

    la_status get_link_management_enabled(bool& out_enabled) const override;
    la_status set_link_management_enabled(bool enabled) override;

    la_status get_pcs_test_mode(pcs_test_mode_e& out_mode) const override;
    la_status set_pcs_test_mode(pcs_test_mode_e mode) override;
    la_status get_pcs_test_seed(la_uint128_t& out_seed) const override;
    la_status set_pcs_test_seed(la_uint128_t seed) override;

    la_status get_pma_test_mode(pma_test_mode_e& out_mode) const override;
    la_status set_pma_test_mode(pma_test_mode_e mode) override;
    la_status get_pma_test_seed(la_uint128_t& out_seed) const override;
    la_status set_pma_test_seed(la_uint128_t seed) override;
    la_status read_pma_test_ber(la_mac_port::mac_pma_ber& out_mac_pma_ber) const override;

    la_status get_serdes_test_mode(la_uint_t serdes_idx,
                                   la_serdes_direction_e direction,
                                   la_mac_port::serdes_test_mode_e& out_mode) const override;
    la_status get_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e& out_mode) const override;
    la_status set_serdes_test_mode(la_uint_t serdes_idx,
                                   la_serdes_direction_e direction,
                                   la_mac_port::serdes_test_mode_e mode) override;
    la_status set_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) override;
    la_status read_serdes_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) override;
    la_status read_serdes_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) const override;

    la_status set_ostc_quantizations(const ostc_thresholds& thresholds) override;
    la_status get_ostc_quantizations(ostc_thresholds& out_thresholds) const override;
    la_status set_default_port_tc(la_over_subscription_tc_t default_ostc, la_initial_tc_t default_itc) override;
    la_status get_default_port_tc(la_over_subscription_tc_t& out_default_ostc, la_initial_tc_t& out_default_itc) const override;

    la_status add_port_tc_tpid(la_tpid_t tpid) override;
    la_status remove_port_tc_tpid(la_tpid_t tpid) override;
    la_status get_port_tc_tpids(la_tpid_vec& out_tpids) const override;

    la_status set_port_tc_extract_offset(la_uint_t offset) override;
    la_status set_port_tc_for_custom_protocol_with_offset(la_ethertype_t protocol,
                                                          la_over_subscription_tc_t ostc,
                                                          la_initial_tc_t itc) override;
    la_status add_port_tc_custom_protocol(la_ethertype_t protocol) override;
    la_status remove_port_tc_custom_protocol(la_ethertype_t protocol) override;
    la_status get_port_tc_custom_protocols(la_ethertype_vec& out_protocols) const override;

    la_status set_port_tc_layer(la_tpid_t tpid, tc_protocol_e protocol, la_layer_e layer) override;
    la_status get_port_tc_layer(la_tpid_t tpid, tc_protocol_e protocol, la_layer_e& out_layer) const override;
    la_status set_port_tc_for_fixed_protocol(tc_protocol_e protocol,
                                             la_uint8_t lower_bound,
                                             la_uint8_t higher_bound,
                                             la_over_subscription_tc_t ostc,
                                             la_initial_tc_t itc) override;
    la_status get_port_tc_for_fixed_protocol(tc_protocol_e protocol,
                                             la_uint8_t priority,
                                             la_over_subscription_tc_t& out_ostc,
                                             la_initial_tc_t& out_itc) const override;
    la_status clear_port_tc_for_fixed_protocol() override;
    la_status set_port_tc_for_custom_protocol(la_tpid_t tpid,
                                              la_ethertype_t protocol,
                                              la_over_subscription_tc_t ostc,
                                              la_initial_tc_t itc) override;
    la_status get_port_tc_for_custom_protocol(la_tpid_t tpid,
                                              la_ethertype_t protocol,
                                              la_over_subscription_tc_t& out_ostc,
                                              la_initial_tc_t& out_itc) const override;
    la_status save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root) const override;
    la_status save_state(la_mac_port::port_debug_info_e info_type, std::string file_name) const override;
    la_status set_serdes_signal_control(la_uint_t serdes_idx,
                                        la_serdes_direction_e direction,
                                        la_mac_port::serdes_ctrl_e ctrl_type) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    la_status add_port_extension(la_port_extender_vid_t port_extended_vid, size_t& out_oq_pair_idx);
    la_status remove_port_extension(la_port_extender_vid_t port_extended_vid, size_t oq_pair_idx);

    bool is_channelized()
    {
        return m_is_extended;
    }

    /// Sets whether a reset is allowed
    void set_is_reset_allowed(bool is_reset_allowed);

    /// @brief Poll link state.
    bool poll_link_state();

    /// @brief Handle link down m_link_down_interrupt_histogram

    void handle_link_down_interrupt();

    /// @brief Handle link error interrupt
    void handle_link_error_interrupt(const interrupt_tree::cause_bits& link_error_bits) const;

    /// @brief Attempt to restore mac_port state to the last known state.
    ///
    /// Called during reconnect sequence while writes to device are disabled.
    la_status restore_state(state_e last_known_state);

    /// Reset implementation helpers
    virtual la_status do_reset() = 0;
    la_status do_reset_port();

    // SW PFC
    slice_ifg_vec_t get_pfc_counter_ifgs() const;

    // PFC
    la_status set_pfc_periodic_timer(std::chrono::nanoseconds period) override;
    la_status get_pfc_periodic_timer(std::chrono::nanoseconds& out_period) override;
    la_status set_pfc_src_mac(la_mac_addr_t mac_addr);
    la_status set_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                       la_rx_cgm_sq_profile* profile,
                                       la_uint_t group_index,
                                       la_uint_t drop_counter_index) override;
    la_status get_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                       la_rx_cgm_sq_profile*& out_profile,
                                       la_uint_t& out_group_index,
                                       la_uint_t& out_drop_counter_index) override;

    la_status set_pfc_oq_profile_tc_bitmap(la_uint8_t tc_bitmap) override;
    la_status get_pfc_oq_profile_tc_bitmap(la_uint8_t& out_tc_bitmap) override;

    // PFC watchdog
    la_status set_pfc_queue_watchdog_enabled(la_pfc_priority_t pfc_priority, bool enabled) override;
    la_status get_pfc_queue_watchdog_enabled(la_pfc_priority_t pfc_priority, bool& out_enabled) const override;
    la_status set_pfc_watchdog_polling_interval(std::chrono::milliseconds polling_interval) override;
    la_status get_pfc_watchdog_polling_interval(std::chrono::milliseconds& out_interval) const override;
    la_status set_pfc_queue_watchdog_polling_interval(la_pfc_priority_t pfc_priority,
                                                      std::chrono::milliseconds polling_interval) override;
    la_status get_pfc_queue_watchdog_polling_interval(la_pfc_priority_t pfc_priority,
                                                      std::chrono::milliseconds& out_interval) const override;
    la_status set_pfc_watchdog_recovery_interval(std::chrono::milliseconds polling_interval) override;
    la_status get_pfc_watchdog_recovery_interval(std::chrono::milliseconds& out_interval) const override;
    la_status set_pfc_queue_watchdog_recovery_interval(la_pfc_priority_t pfc_priority,
                                                       std::chrono::milliseconds polling_interval) override;
    la_status get_pfc_queue_watchdog_recovery_interval(la_pfc_priority_t pfc_priority,
                                                       std::chrono::milliseconds& out_interval) const override;
    la_status allocate_counter(la_oq_id_t oq_id) override;
    la_status deallocate_counter(la_oq_id_t oq_id) override;
    la_status read_pfc_queue_drain_counter(la_pfc_priority_t pfc_priority,
                                           bool clear_on_read,
                                           size_t& out_dropped_packets) override;
    la_status read_output_queue_uc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_counters) override;
    la_status read_output_queue_mc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_counters) override;
    la_status set_pfc_queue_configured_state(la_pfc_priority_t pfc_priority,
                                             pfc_config_queue_state_e state,
                                             bool& out_counter_allocated) override;
    la_status get_pfc_queue_configured_state(la_pfc_priority_t pfc_priority,
                                             pfc_config_queue_state_e& out_state,
                                             bool& out_counter_allocated) override;
    la_status get_pfc_queue_state(la_pfc_priority_t pfc_priority, pfc_queue_state_e& out_state) override;
    bool check_pfc_watchdog(std::chrono::microseconds interval);

protected:
    la_mac_port_base() = default; // Needed for cereal
    la_status single_port_init(fc_mode_e rx_fc_mode, fc_mode_e tx_fc_mode, fec_mode_e fec_mode);
    virtual la_status mlp_init(fc_mode_e rx_fc_mode, fc_mode_e tx_fc_mode, fec_mode_e fec_mode) = 0;

    virtual la_status configure_serdes_source_pif_table_extended_mac() = 0;
    virtual la_status erase_serdes_source_pif_table_extended_mac() = 0;

    virtual la_status update_pdoq_oq_ifc_mapping() = 0;

    /// Set port to "reset" state
    la_status set_reset_state_network_port(mac_reset_state_e state);

    /// Set fabric port to state
    virtual la_status set_reset_state_fabric_port(mac_reset_state_e state) = 0;

    /// Block till tune is complete (or default timeout elapsed)
    la_status block_tune_complete();

    void merge_mac_status(mac_status& orig, mac_status addend) const;
    void add_mib_counters(mib_counters& orig, const mib_counters& addend) const;
    la_status configure_network_scheduler();
    virtual la_status configure_fabric_scheduler() = 0;
    la_status get_custom_tpid_idx(la_tpid_t tpid, la_uint8_t& out_idx) const;
    la_status get_custom_protocol_idx(la_ethertype_t protocol, la_uint8_t& out_idx) const;

    la_status clear_mac_link_down_interrupt() const;

    la_status set_mac_link_up(bool up);

    void notify_link_down(const link_down_interrupt_info& info) const;
    void notify_link_up() const;
    void notify_speed_change(port_speed_e old_speed) const;

    la_status populate_link_error_info(const interrupt_tree::cause_bits& link_error_bits, link_error_interrupt_info& val_out) const;

    la_status update_link_down_histogram(const link_down_interrupt_info& info) const;

    la_system_port_wptr get_system_port() const;

    void add_link_down_histogram(size_t index, json_t* parent) const;

    la_status set_interface_scheduler(bool is_fabric);

    // PFC Watchdog
    la_status do_allocate_counter(la_oq_id_t oq_id);
    la_status do_deallocate_counter(la_oq_id_t oq_id);
    virtual la_status set_oqueue_state(la_pfc_priority_t pfc_priority, pfc_config_queue_state_e state) = 0;
    la_status get_oqueue_state(la_pfc_priority_t pfc_priority, pfc_queue_state_e& out_state, bool& out_pfc_rx);
    virtual la_status get_oqueue_ptr(la_pfc_priority_t pfc_priority, la_uint_t& out_q_rd_ptr, la_uint_t& out_q_wr_ptr) = 0;
    la_status pfc_watchdog_notify(la_pfc_priority_t pfc_priority, bool detected);
    virtual la_status read_oq_uc_counters(size_t counter_set_idx, output_queue_counters& oq_uc_counter) = 0;
    virtual la_status read_oq_mc_counters(size_t counter_set_idx, output_queue_counters& oq_mc_counter) = 0;
    virtual la_status set_oq_counter_set(la_pfc_priority_t pfc_priority, la_uint_t counter_set) = 0;
    virtual la_uint_t get_base_oq() const;
    virtual bool is_oq_drop_counter_set_valid(size_t counter_set) = 0;
    la_status do_read_pfc_queue_drain_counter(la_pfc_priority_t pfc_priority, bool clear_on_read, size_t& out_dropped_packets);
    la_status do_read_output_queue_uc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_uc_counters);
    la_status do_read_output_queue_mc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_mc_counters);
    la_status do_set_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                          const la_rx_cgm_sq_profile_impl_wptr& profile,
                                          la_uint_t group_index,
                                          la_uint_t drop_counter_index);

    // PFC
    bool is_pfc_enabled();
    virtual bool is_sw_based_pfc_enabled() const = 0;
    la_status do_pfc_enable(la_uint8_t tc_bitmap);
    la_status do_pfc_disable();
    la_status update_pfc_table();
    la_status set_pfc_ssp_slice_table(bool enabled);
    la_status populate_mp_data_payload(npl_pfc_mp_table_shared_payload_t& payload);
    la_status update_mp_table();
    la_status erase_mp_entry();

    // PFC
    virtual la_status init_pfc() = 0;
    virtual la_status get_pfc_status(la_pfc_priority_t pfc_priority, bool& out_state) = 0;

    virtual la_status set_sq_map_table_priority(la_uint_t map_mode) = 0;
    virtual la_status set_ssp_sub_port_map() = 0;
    virtual la_status set_source_if_to_port_map_fc_enable(bool fc_enable) = 0;
    virtual la_status set_fcm_prio_map_bitmap(la_uint8_t tc_bitmap) = 0;
    virtual la_status reset_rx_cgm_mapping() = 0;

    virtual la_status init_rxcgm() = 0;

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Port speed
    port_speed_e m_speed;

    // Slice ID
    la_slice_id_t m_slice_id;

    // IFG ID
    la_ifg_id_t m_ifg_id;

    // Indicates whether port-extention is supported
    bool m_is_extended;

    // For port extention supported PIF, hold the number of port_extentions - up to 4.
    ranged_index_generator m_system_ports_extended;

    // Serdes base
    la_uint_t m_serdes_base_id;

    // PIF base
    la_uint_t m_pif_base_id;

    // Mac lane base
    la_uint_t m_mac_lane_base_id;

    // Indicates whether this is a Fabric or Network MAC port. Each has different default configuration.
    la_slice_mode_e m_port_slice_mode;

    // Number of SerDes elements
    size_t m_serdes_count;

    // Number of PIF elements
    size_t m_pif_count;

    // Number of MAC lane elements
    size_t m_mac_lanes_count;

    // Number of Reserved MAC lane elements
    size_t m_mac_lanes_reserved_count;

    // Scheduler
    la_interface_scheduler_impl_wptr m_scheduler;

    // Up to two MAC pool ports
    std::vector<mac_pool_port_sptr> m_mac_pool_port;

    // Indicates whether resetting is allowed
    bool m_is_reset_allowed;

    // Custom protocols for OSTC
    using optional_ethertype = std::pair<bool, la_ethertype_t>;
    optional_ethertype m_ostc_protocols[OSTC_NUM_CUSTOM_ETHERTYPES];

    // Custom TPIDs for OSTC
    using optional_tpid = std::pair<bool, la_tpid_t>;
    optional_tpid m_ostc_tpids[OSTC_NUM_TPIDS];

    // Last external status
    bool m_link_up;

    // IFG ingress block state
    bool m_block_ingress;

    // Link down interrupt counts
    mutable link_down_interrupt_histogram m_link_down_interrupt_histogram;

    enum {
        INVALID_COUNTER_SET_IDX = 0,
        INVALID_OQ_PTR = 0xffffffff,
    };

    enum {
        NUM_PFC_QUANTA_BITS = 512,
    };

    la_meter_set_impl_wptr m_pfc_tx_meter;
    la_counter_set_impl_wptr m_pfc_rx_counter;
    index_handle m_npuh_id{};
    std::array<uint16_t, LA_NUM_PFC_PRIORITY_CLASSES> m_sw_pfc_quanta;

    // SW PFC enabled
    bool m_sw_pfc_enabled;

    // PFC enabled
    bool m_pfc_enabled;

    // PFC quanta
    la_uint_t m_pfc_quanta;

    // PFC TC bitmap
    la_uint8_t m_pfc_tc_bitmap;

    // HW PFC TC->SQ profile mapping
    struct tc_sq_mapping_val {
        la_rx_cgm_sq_profile_impl_wptr profile;
        la_uint_t group_index;
        la_uint_t drop_counter_index;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(tc_sq_mapping_val);

    map_alloc<la_traffic_class_t, tc_sq_mapping_val> m_tc_sq_mapping;

    // HW PFC periodic timer
    std::chrono::nanoseconds m_pfc_periodic_timer_value;

    // PFC Watchdog
    std::bitset<LA_NUM_PFC_PRIORITY_CLASSES> m_pfc_watchdog_oqs{0};
    std::array<size_t, LA_NUM_PFC_PRIORITY_CLASSES> m_counter_set{{}};
    std::array<std::chrono::milliseconds, LA_NUM_PFC_PRIORITY_CLASSES> m_pfc_watchdog_polling_interval_ms{{}};
    std::array<std::chrono::milliseconds, LA_NUM_PFC_PRIORITY_CLASSES> m_pfc_watchdog_recovery_interval_ms{{}};
    std::array<pfc_config_queue_state_e, LA_NUM_PFC_PRIORITY_CLASSES> m_queue_transmit_state{{}};
    std::array<std::chrono::microseconds, LA_NUM_PFC_PRIORITY_CLASSES> m_watchdog_countdown{{}};
    std::array<la_uint_t, LA_NUM_PFC_PRIORITY_CLASSES> m_prev_oq_rd_ptr{{}};
    std::array<la_uint_t, LA_NUM_PFC_PRIORITY_CLASSES> m_prev_oq_wr_ptr{{}};
    std::array<la_uint_t, LA_NUM_PFC_PRIORITY_CLASSES> m_dropped_packets{{}};
    std::array<output_queue_counters, LA_NUM_PFC_PRIORITY_CLASSES> m_uc_oq_counters{{}};
    std::array<output_queue_counters, LA_NUM_PFC_PRIORITY_CLASSES> m_mc_oq_counters{{}};
};
}

#endif // __LA_MAC_PORT_BASE_H__
