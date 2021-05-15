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

#ifndef __MAC_POOL_PORT_H__
#define __MAC_POOL_PORT_H__

#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "api/types/la_notification_types.h"
#include "common/fixed_deque.h"
#include "common/la_status.h"
#include "common/stopwatch.h"

#include "system/device_port_handler_base.h"
#include "system/la_mac_port_base.h"
#include "system/serdes_handler.h"

#include "reconnect_metadata.h"

#include <array>
#include <chrono>
#include <map>
#include <stddef.h>
namespace silicon_one
{

class la_device_impl;
class ll_device;

class lld_register;
class lld_register_array_container;

class serdes_handler;

class mac_pool_port : public std::enable_shared_from_this<mac_pool_port>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit mac_pool_port(const la_device_impl_wptr& device);
    virtual ~mac_pool_port();

    // Object life-cycle API-s
    virtual la_status initialize(la_slice_id_t slice_id,
                                 la_ifg_id_t ifg_id,
                                 la_uint_t serdes_base,
                                 size_t num_of_serdes,
                                 la_mac_port::port_speed_e speed,
                                 la_mac_port::fc_mode_e rx_fc_mode,
                                 la_mac_port::fc_mode_e tx_fc_mode,
                                 la_mac_port::fec_mode_e fec_mode,
                                 la_mac_port::mlp_mode_e mlp_mode,
                                 la_slice_mode_e port_slice_mode);
    la_status destroy();

    la_status set_debug_mode(bool enable);
    la_status get_debug_mode(bool& out_enable);

    la_status set_serdes_tuning_mode(la_mac_port::serdes_tuning_mode_e mode);
    la_status get_serdes_tuning_mode(la_mac_port::serdes_tuning_mode_e& out_mode);

    la_status set_serdes_continuous_tuning_enabled(bool enabled);
    la_status get_serdes_continuous_tuning_enabled(bool& out_enabled) const;

    la_status set_serdes_parameter(la_uint_t serdes_idx,
                                   la_mac_port::serdes_param_stage_e stage,
                                   la_mac_port::serdes_param_e param,
                                   la_mac_port::serdes_param_mode_e mode,
                                   int32_t value);
    la_status get_serdes_parameter(la_uint_t serdes_idx,
                                   la_mac_port::serdes_param_stage_e stage,
                                   la_mac_port::serdes_param_e param,
                                   la_mac_port::serdes_param_mode_e& out_mode,
                                   int32_t& out_value) const;
    la_status get_serdes_parameter_hardware_value(la_uint_t serdes_idx, la_mac_port::serdes_param_e param, int32_t& out_value);
    la_status get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const;
    la_status clear_serdes_parameter(la_uint_t serdes_idx,
                                     la_mac_port::serdes_param_stage_e stage,
                                     la_mac_port::serdes_param_e param);

    la_status set_speed_enabled(la_mac_port::port_speed_e speed, bool enabled);
    la_status set_fec_mode_enabled(la_mac_port::fec_mode_e fec_mode, bool enabled);

    la_status activate();
    la_status get_serdes_signal_ok(la_uint_t serdes_idx, bool& out_signal_ok);
    la_status tune();
    la_status get_tune_status(bool& out_completed);
    la_status poll_mac_up(bool& out_mac_up);
    la_status handle_mac_down();
    la_status stop();
    la_status set_an_enabled(bool enabled);
    la_status get_an_enabled(bool& out_enabled) const;
    la_status an_start();

    la_slice_id_t get_slice() const;
    la_ifg_id_t get_ifg() const;

    la_uint_t get_first_serdes_id() const;
    size_t get_num_of_serdes() const;

    la_mac_port::state_e get_state() const;
    la_status get_state_histogram(bool clear, la_mac_port::state_histogram& out_state_histogram);

    la_status reconfigure(size_t num_of_serdes,
                          la_mac_port::port_speed_e speed,
                          la_mac_port::fc_mode_e rx_fc_mode,
                          la_mac_port::fc_mode_e tx_fc_mode,
                          la_mac_port::fec_mode_e fec_mode);
    la_status get_speed(la_mac_port::port_speed_e& out_speed) const;
    la_status set_speed(la_mac_port::port_speed_e speed);
    la_status get_serdes_speed(la_mac_port::port_speed_e& out_speed) const;
    la_status get_fec_mode(la_mac_port::fec_mode_e& out_fec_mode) const;
    la_status set_fec_mode(la_mac_port::fec_mode_e fec_mode);
    la_status get_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e& out_fc_mode) const;
    virtual la_status set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode);
    la_status set_fc_rx_term_mode(bool enabled);
    la_status get_fc_rx_term_mode(bool& out_enabled) const;
    la_status read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) const;
    virtual la_status read_mac_status(la_mac_port::mac_status& out_mac_status) const = 0;
    virtual la_status read_mac_soft_reset_config() const = 0;
    la_status handle_wrong_am_lock_wa(la_mac_port::mac_status out_mac_status);

    virtual la_status set_xoff_timer_settings(la_uint8_t tc_bitmap, la_uint_t quanta) = 0;
    virtual la_status set_xon_timer_settings(la_uint8_t tc_bitmap, la_uint_t quanta) = 0;

    virtual la_status set_control_tx_mac_src(la_mac_addr_t mac_addr) = 0;
    virtual la_status get_control_tx_mac_src(la_mac_addr_t& out_mac_addr) const = 0;

    virtual la_status read_mac_link_down_interrupt(link_down_interrupt_info& val_out) const = 0;
    virtual la_status clear_mac_link_down_interrupt() const = 0;
    virtual la_status set_mac_link_down_interrupt_mask(bool enable_interrupt) const = 0;
    virtual la_status clear_rx_deskew_fifo_overflow_interrupt() const = 0;

    la_status check_link_down_info_rx_deskew_fifo_overflow(link_down_interrupt_info link_down_info, bool& overflow) const;
    virtual la_status set_mac_link_error_interrupt_mask(bool enable_interrupt) const = 0;
    virtual la_status set_delayed_mac_link_error_interrupt_mask(bool enable_interrupt) const = 0;
    virtual void populate_link_error_info(const interrupt_tree::cause_bits& link_error_bits,
                                          link_error_interrupt_info& val_out) const = 0;

    virtual la_status read_mac_pcs_lane_mapping(la_mac_port::mac_pcs_lane_mapping& out_mac_pcs_lane_mapping) const = 0;
    virtual la_status read_mib_counters(bool clear, la_mac_port::mib_counters& out_mib_counters) const = 0;
    virtual la_status set_rs_fec_debug_enabled() = 0;
    virtual la_status get_rs_fec_debug_enabled(bool& out_debug_status) const = 0;
    virtual la_status read_rs_fec_debug_counters(la_mac_port::rs_fec_debug_counters& out_debug_counters) const = 0;
    virtual la_status read_rs_fec_debug_counters(bool clear, la_mac_port::rs_fec_debug_counters& out_debug_counters) const = 0;
    virtual la_status read_rs_fec_symbol_errors_counters(la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const = 0;
    virtual la_status read_rs_fec_symbol_errors_counters(bool clear,
                                                         la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const = 0;
    la_status read_ostc_counter(la_over_subscription_tc_t ostc, size_t& out_dropped_packets) const;
    virtual la_status read_counter(la_mac_port::counter_e counter_type, size_t& out_counter) const = 0;
    virtual la_status read_counter(bool clear, la_mac_port::counter_e counter_type, size_t& out_counter) const = 0;
    virtual la_status read_counter(la_mac_port::serdes_counter_e counter_type, la_uint_t serdes_idx, size_t& out_counter) const = 0;
    virtual la_status clear_counters() const = 0;

    la_interface_scheduler* get_scheduler() const;

    la_status get_min_packet_size(la_uint_t& out_min_size) const;
    la_status set_min_packet_size(la_uint_t min_size);
    la_status get_max_packet_size(la_uint_t& out_max_size) const;
    la_status set_max_packet_size(la_uint_t max_size);
    la_status get_max_supported_packet_size(la_uint_t& out_max_size) const;
    la_status get_min_supported_packet_size(la_uint_t& out_min_size) const;

    la_status get_fec_bypass_mode(la_mac_port::fec_bypass_e& out_fec_bp) const;
    la_status set_fec_bypass_mode(la_mac_port::fec_bypass_e fec_bp);

    la_status get_preamble_compression_enabled(bool& out_enabled) const;
    la_status set_preamble_compression_enabled(bool enabled);
    virtual la_status get_ipg(la_uint16_t& out_gap_len, la_uint16_t& out_gap_tx_bytes) const = 0;
    virtual la_status set_ipg(la_uint16_t gap_len, la_uint16_t gap_tx_bytes) = 0;
    virtual la_status get_crc_enabled(bool& out_enabled) const = 0;
    virtual la_status set_crc_enabled(bool enabled) = 0;

    virtual bool is_loopback_mode_supported(la_mac_port::loopback_mode_e mode) = 0;
    virtual bool is_rx_lane_swapped();
    virtual la_status post_anlt_complete(const std::unique_ptr<serdes_handler>& serdes_handler_ptr);
    virtual la_status pre_tune_rx_pma_reset();

    la_status get_loopback_mode(la_mac_port::loopback_mode_e& out_loopback_mode) const;
    la_status set_loopback_mode(la_mac_port::loopback_mode_e mode);

    la_status get_link_management_enabled(bool& out_enabled) const;
    la_status set_link_management_enabled(bool enabled);

    la_status get_pcs_test_mode(la_mac_port::pcs_test_mode_e& out_mode) const;
    la_status set_pcs_test_mode(la_mac_port::pcs_test_mode_e mode);
    la_status get_pcs_test_seed(la_uint128_t& out_seed) const;
    la_status set_pcs_test_seed(la_uint128_t seed);

    la_status get_pma_test_mode(la_mac_port::pma_test_mode_e& out_mode) const;
    la_status set_pma_test_mode(la_mac_port::pma_test_mode_e mode);
    la_status get_pma_test_seed(la_uint128_t& out_seed) const;
    la_status set_pma_test_seed(la_uint128_t seed);
    virtual la_status read_pma_test_ber(la_mac_port::mac_pma_ber& out_mac_pma_ber) const = 0;

    la_status set_serdes_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode);
    la_status set_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode);
    la_status get_serdes_test_mode(la_uint_t serdes_idx,
                                   la_serdes_direction_e direction,
                                   la_mac_port::serdes_test_mode_e& out_mode) const;
    la_status get_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e& out_mode) const;
    la_status read_serdes_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber);
    la_status read_serdes_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber);
    la_status save_state(la_mac_port::port_debug_info_e info_type, json_t* parent);
    la_status set_serdes_signal_control(la_uint_t serdes_idx,
                                        la_serdes_direction_e direction,
                                        la_mac_port::serdes_ctrl_e ctrl_type);

    void add_state_histogram(json_t* parent);
    la_status add_state_transition_history(json_t* parent);
    la_status add_serdes_parameters(json_t* parent);
    la_status add_mac_port_soft_state(json_t* parent);
    la_status add_mac_port_config(json_t* parent);
    la_status add_fec_status(json_t* parent);
    la_status add_mib_counters(json_t* parent);
    la_status add_mac_port_status(json_t* parent);

    // implementation
    la_status set_reset(la_mac_port_base::mac_reset_state_e state);
    virtual la_status set_rx_reset(la_mac_port_base::mac_reset_state_e state) = 0;
    virtual la_status set_tx_reset(la_mac_port_base::mac_reset_state_e state) = 0;
    virtual la_status set_reset_fabric_port_pacific_a0(la_mac_port_base::mac_reset_state_e state) = 0;
    virtual la_status set_rx_pcs_sync_reset() = 0;
    virtual la_status set_rx_pcs_reset() = 0;
    virtual la_status reset_tx_pma(bool) = 0;
    virtual la_status reset_rx_pma(bool) = 0;
    virtual la_status set_sig_ok_overide(bool overide, bool val) = 0;

    // Toggle only MAC Rx reset bits (skip all workarounds)
    virtual la_status set_mac_rx_reset(la_mac_port_base::mac_reset_state_e state) = 0;

    const la_device_impl* get_device() const
    {
        return m_device.get();
    }

    // Called during reconnect with write-to-device disabled.
    la_status restore_state(la_mac_port::state_e last_known_state);

    // Called during reconnect with write-to-device enabled.
    la_status restore_serdes_handler();

    // Set the current state
    void set_state(la_mac_port::state_e state);

    size_t get_serdes_speed_in_gbps() const;

    // Return Speed Capability as defined in IEEE 802.3 CL73
    serdes_handler::an_capability_code_e get_an_spec_user_capabilities();

    // Return FEC request as defined in IEEE 802.3 CL73
    uint get_an_fec_request();

    // Return true if AN/LT is capable with the current configuration.
    bool is_an_capable();

    la_status is_link_up(bool& out_link_up);

    std::string to_string() const;
    la_status tx_refresh();
    size_t get_mac_lane_index() const;

protected:
    mac_pool_port() = default; // Needed for cereal
    enum {
        RX_PMA_MAX_BURST_WIDTH = 6,
        RS_FEC_LANE_PER_PORT = 4,
        RS_FEC_KR4_SYMBOLS_PER_CODEWORD = 528,
        RS_FEC_KP4_SYMBOLS_PER_CODEWORD = 544,
    };

    struct fec_engine_config_data {
        size_t fec_lane_per_engine;
        size_t fec_engine_count;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(fec_engine_config_data);

    // to be initialized by platform level (pacific/gibralter/ect..)
    std::map<la_mac_port::port_speed_e, fec_engine_config_data> m_fec_engine_config;

    // Helper functions
    la_status configure_ifgb();
    la_status reset_ifgb();

    la_status recalc_data_members();
    virtual la_status configure_lanes() = 0;
    virtual la_status configure_info_phy();

    virtual la_status reset_general_config() = 0;
    virtual la_status destroy_general_config() = 0;
    virtual la_status update_general_config() = 0;

    la_status reset_packet_sizes();
    virtual la_status get_packet_sizes(la_uint_t& out_min_size, la_uint_t& out_max_size) const = 0;
    virtual la_status set_packet_sizes(la_uint_t min_size, la_uint_t max_size) = 0;

    virtual la_status reset_mac_config() = 0;

    virtual la_status configure_info_loopback_mode(npl_loopback_mode_e info_loopback_mode);
    la_status configure_pma();
    virtual la_status configure_pma(device_port_handler_base::serdes_config_data config) = 0;
    virtual la_status calculate_pma_max_burst(uint32_t& pma_max_burst) = 0;
    virtual la_status configure_pma_max_burst(uint32_t pma_max_burst) = 0;

    virtual la_status clear_signal_ok_interrupt() = 0;
    virtual la_status get_signal_ok_interrupt(bool& out_trapped) = 0;

    virtual la_status configure_ber_fsm() = 0;

    virtual la_status configure_degraded_ser() = 0;

    virtual la_status update_rs_fec_config() = 0;
    virtual la_status reset_rs_fec_config() = 0;

    virtual la_status update_rx_krf_config() = 0;
    virtual la_status reset_rx_krf_config() = 0;

    virtual la_status reset_ipg() = 0;
    virtual la_status reset_xon_xoff_timers() = 0;

    la_status configure_loopback_mode();

    virtual la_status configure_pcs_test_mode() = 0;

    virtual la_status configure_pma_test_mode() = 0;

    // Toggle PDIF resets
    virtual la_status toggle_pdif_reset() = 0;

    bool is_serdes_in_range(size_t serdes_idx) const;

    virtual size_t get_serdes_index_in_mac_pool(size_t serdes_idx) const = 0;

    // Setup counter timer
    virtual la_status setup_counter_timer(bool enable, size_t clock_cycles) const = 0;

    // Wait for counter timer to elapse
    virtual la_status wait_counter_timer() const = 0;

    la_status get_alignment_marker(size_t& alignment_marker_rx, size_t& alignment_marker_tx) const;

    la_uint64_t get_codewords_sum(la_uint64_t codewords[], size_t size) const;

    la_uint64_t get_symbol_errors_sum(la_uint64_t codewords[], size_t size) const;

    void calculate_flr(la_uint64_t codeword[], la_uint64_t total_codewords, double& extrapolated_flr, double& flr_r) const;

    virtual la_status configure_loopback_mode(npl_loopback_mode_e mii_loopback_mode, npl_loopback_mode_e pma_loopback_mode) = 0;

    la_status set_interrupt_mask(std::vector<lld_register_scptr>& regs, bool enable_interrupt) const;
    la_status clear_interrupt(std::vector<lld_register_scptr>& regs) const;

protected:
    /// @brief SerDes parameters setting.
    struct serdes_param_setting {
        la_mac_port::serdes_param_mode_e mode; ///< SerDes parameter mode.
        int32_t value;                         ///< SerDes parameter value.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(serdes_param_setting);

    using serdes_param_map = std::map<la_mac_port::serdes_param_e, serdes_param_setting>;
    using serdes_stage_param_array = std::vector<serdes_param_map>;

    // Parent device
    la_device_impl_wptr m_device;

    // Serdes Debug mode
    bool m_serdes_debug_mode;

    // Serdes tuning mode
    la_mac_port::serdes_tuning_mode_e m_serdes_tuning_mode;

    // Serdes fine tuning enable
    bool m_serdes_continuous_tuning_enabled;

    // Port speed
    la_mac_port::port_speed_e m_speed;

    // FEC mode
    la_mac_port::fec_mode_e m_fec_mode;

    // FEC bypass mode
    la_mac_port::fec_bypass_e m_fec_bypass;

    // Flow Control mode
    la_mac_port::fc_mode_e m_rx_fc_mode;
    la_mac_port::fc_mode_e m_tx_fc_mode;
    bool m_rx_fc_term_mode;

    // Slice ID
    la_slice_id_t m_slice_id;

    // IFG ID
    la_ifg_id_t m_ifg_id;

    // SerDes base
    la_uint_t m_serdes_base_id;

    // Number of SerDes elements
    size_t m_serdes_count;

    // Port state
    la_mac_port::state_e m_port_state;

    // SerDes speed
    la_mac_port::port_speed_e m_serdes_speed;

    // SerDes speed in Gbps and accurate
    size_t m_serdes_speed_gbps;

    // MLP mode (multi-lane port - uses more than single MAC pool)
    la_mac_port::mlp_mode_e m_mlp_mode;

    // Number of MAC lanes - each MAC lane support upto 50Gbps
    size_t m_mac_lanes_count;

    // Number of MAC lanes reserved for this port - equals the number of MAC lanes in use and number of MAC lanes that cannot be
    // used
    size_t m_mac_lanes_reserved;

    // Number of PCS lanes per MAC lane
    size_t m_pcs_lanes_per_mac_lane;

    // Mac pool index - 0 for mac_pool2, 0 or 1 for mac_pool8
    size_t m_mac_pool_index;

    // MAC lane index in Mac Pool
    size_t m_mac_lane_index_in_mac_pool;

    // MAC lane index in IFGB
    size_t m_mac_lane_index_in_ifgb;

    // SerDes index
    size_t m_serdes_index_in_mac_pool;

    // Loopback mode
    la_mac_port::loopback_mode_e m_loopback_mode;

    bool m_link_management_enabled;

    // PCS test mode
    la_mac_port::pcs_test_mode_e m_pcs_test_mode;

    // PMA test mode
    la_mac_port::pma_test_mode_e m_pma_test_mode;

    // MAC port slice mode (network/fabric)
    la_slice_mode_e m_port_slice_mode;

    // mark when the link came up to measure when to enable delayed link_error interrupts
    std::chrono::steady_clock::time_point m_pcs_stable_timestamp;

    // ready unmasking of delayed link error interrupts at LINK_UP
    bool m_ready_delayed_interrupts;

    // Get bit mask for values of MAC pool interrupt registers
    uint64_t get_mac_pool_interrupt_mask() const;

private:
    // Update reconnect metadata for this mac_port
    void update_mac_port(reconnect_metadata::fabric_mac_port::attr_e attr, uint8_t val);

    // Return whether mac port has IEEE Spec or non-Spec Auto-Negotiation capability
    bool is_valid_an_capability();

    // Get FEC counter register according to type
    la_status get_fec_counter_reg(la_mac_port::counter_e counter_type, lld_register_scptr& out_counter_reg) const;

    la_status start_wait_for_peer();
    la_status stop_wait_for_peer();
    la_status is_tune_good();

    la_status enable_mac_rx();
    la_status disable_mac_rx();

    // The SerDes is active and should be configured and tuned.
    bool is_serdes_mode_active() const;

    // The SerDes is active but not really used for data transfer.
    bool is_serdes_mode_dummy() const;

    // The PCS layer is not used at all.
    bool is_pcs_mode_off() const;

    // The SerDes is not used at all.
    bool is_serdes_mode_off() const;

    // Is in mii, mii_serdes, pma, pma_serdes, or remote loopback
    bool is_mii_pma_remote_loopback() const;

    // Is link management enabled and PRBS disabled
    bool is_link_management_enabled() const;

    // Is in SerDes test mode.
    bool is_port_in_test_mode() const;

    // Is an_stop_valid
    bool is_an_stop_valid() const;

    la_status is_peer_detected(bool& out_detected);
    la_status is_tune_completed(bool& out_completed);
    la_status is_rx_ready(bool& out_rx_ready);
    la_status is_pcs_stable(bool& out_pcs_stable);
    la_status ready_delayed_interrupt_mask();
    la_status is_an_completed(bool& out_completed);
    la_status an_handler();
    la_status an_base_page_rcv();
    la_status an_next_page_rcv();
    la_status link_training_handler();
    la_status serdes_enable_low_power(bool enable);
    la_status restart_state_machine();
    la_status poll_start_state_machine();
    la_status recover_pma_tx();

    void print_am_lock_debug_message(const char* message, const la_mac_port::mac_status& mac_status);

    la_status initialize_serdes_handler();

    la_status save_mac_port_state(la_mac_port::port_debug_info_e info_type, json_t* parent);

    // Values for SerDes Rx PLL settings, used to validate correct setting is maintained
    // Stores the value of AVSD_ESB16_RX_PLL_GAIN interrupt, which contain Rx PLL BB & Rx PLL INT
    std::vector<int32_t> m_serdes_rxpll_value_vec;

    // Stores the value of AVAGO_INT_RX_PLL2 interrupt, which contain Rx PLL IFLT
    std::vector<int32_t> m_serdes_rxpll2_value_vec;

    // Stores the serdes_test_mode of each serdes in port.
    std::vector<la_mac_port::serdes_test_mode_e> m_serdes_lane_tx_test_mode;
    std::vector<la_mac_port::serdes_test_mode_e> m_serdes_lane_rx_test_mode;

    // Measure time for tune
    std::chrono::steady_clock::time_point m_tune_start_time;

    // Tune timeout informed.
    bool m_tune_timeout_informed;

    // Measure time from tune complete to PCS lock
    std::chrono::steady_clock::time_point m_tune_finish_time;

    // Measure time for PMD link training
    std::chrono::steady_clock::time_point m_link_training_start;

    // Measure time port is with PCS lock
    std::chrono::steady_clock::time_point m_pcs_lock_start_time;

    // Measure time of window start in PCS stable with for rx deskew fifo overrun interrupts
    std::chrono::steady_clock::time_point m_pcs_stable_rx_deskew_window_start_time;

    // Measure time for pcal_stop
    std::chrono::steady_clock::time_point m_pcal_stop_start_time;

    std::chrono::steady_clock::time_point m_link_up_timestamp;

    // Record number of deskew fifo overrun failure and samples count
    int m_pcs_stable_rx_deskew_failures;

    int m_tune_with_pcs_lock;

    std::chrono::seconds m_tune_timeout;
    std::chrono::seconds m_cdr_lock_timeout;
    std::chrono::milliseconds m_pcs_lock_time;

    int m_tune_and_pcs_lock_iter;
    int32_t m_bad_tunes;
    bool m_enable_eid;

    bool m_dfe_eid;
    bool m_ignore_long_tune;
    bool m_check_ser_ber;
    bool m_serdes_post_anlt_tune_disable;
    bool m_pcal_stop_rx_disabled;

    // Indicate whether Auto-negotiate enabled/disables
    bool m_is_an_enabled;

    std::vector<size_t> m_state_histogram;

    std::unique_ptr<serdes_handler> m_serdes_handler;

    struct sm_state_transition {
        la_mac_port::state_e new_state;
        std::string timestamp;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(sm_state_transition);
    fixed_deque<sm_state_transition> m_sm_state_transition_queue;
};
}

#endif // __MAC_POOL_PORT_H__
