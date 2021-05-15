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

#ifndef __SRM_SERDES_HANDLER_H__
#define __SRM_SERDES_HANDLER_H__

#include "api/types/la_common_types.h"
#include "api/types/la_notification_types.h"
#include "common/fixed_deque.h"
#include "common/la_status.h"
#include "common/stopwatch.h"
#include "hld_types_fwd.h"
#include "srm/srm_rules.h"
#include "system/serdes_handler.h"

#include <array>
#include <chrono>
#include <jansson.h>
#include <map>
#include <set>
#include <stddef.h>
namespace silicon_one
{

class srm_serdes_handler : public serdes_handler
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    srm_serdes_handler() = default;
    //////////////////////////////
    struct srm_pll_status {
        uint16_t top_init_req;
        uint16_t top_init_ack;
        bool pll_fsm_start;
        bool pll_out_of_lock;
        bool pll_lock;
        uint32_t baud_rate;
        uint32_t baud_rate_nn;
        uint32_t baud_rate_mm;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(srm_pll_status);

public:
    explicit srm_serdes_handler(const la_device_impl_wptr& device,
                                const srm_serdes_device_handler_wptr& serdes_device_handler,
                                la_slice_id_t slice_id,
                                la_ifg_id_t ifg_id,
                                la_uint_t serdes_base_id,
                                size_t serdes_count,
                                la_mac_port::port_speed_e speed,
                                la_mac_port::port_speed_e serdes_speed,
                                la_slice_mode_e serdes_slice_mode);
    ~srm_serdes_handler();

    la_status verify_firmware() override;
    la_status init() override;
    la_status enable_tx(bool tx_enable) override;
    la_status enable_rx(bool tx_enable) override;
    la_status refresh_tx() override;
    la_status stop() override;
    la_status reset() override;
    la_status wait_for_peer_start() override;
    la_status wait_for_peer_stop() override;
    la_status is_tune_good() override;
    la_status tune() override;
    la_status get_tune_complete(bool& out_completed) override;
    la_status periodic_tune_start() override;
    la_status periodic_tune_stop() override;
    la_status is_periodic_tune_stopped(bool& out_stopped) override;

    la_status an_start(la_mac_port::state_e& state) override;
    la_status an_stop() override;
    la_status link_training_start(la_mac_port::state_e& state) override;
    la_status is_an_good_check(bool& an_good_check, la_mac_port::state_e& state) override;
    la_status an_base_page_rcv(la_mac_port::state_e& state) override;
    la_status an_next_page_rcv(la_mac_port::state_e& state) override;
    la_status is_an_completed(bool& out_completed) override;
    la_status link_training_handler(la_mac_port::state_e& state) override;

    la_status set_serdes_parameter(la_uint_t serdes_idx,
                                   la_mac_port::serdes_param_stage_e stage,
                                   la_mac_port::serdes_param_e param,
                                   la_mac_port::serdes_param_mode_e mode,
                                   int value) override;
    la_status get_serdes_parameter(la_uint_t serdes_idx,
                                   la_mac_port::serdes_param_stage_e stage,
                                   la_mac_port::serdes_param_e param,
                                   la_mac_port::serdes_param_mode_e& out_mode,
                                   int& out_value) const override;
    la_status get_serdes_parameter_hardware_value(la_uint_t serdes_idx, la_mac_port::serdes_param_e param, int& out_value) override;
    la_status get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const override;
    la_status clear_serdes_parameter(la_uint_t serdes_idx,
                                     la_mac_port::serdes_param_stage_e stage,
                                     la_mac_port::serdes_param_e param) override;
    la_status update_loopback_mode(la_mac_port::loopback_mode_e loopback_mode) override;
    la_status set_loopback_mode(la_mac_port::loopback_mode_e loopback_mode) override;
    void print_tune_status_message(const char* message, la_logger_level_e severity) override;
    void save_serdes_debug_message(const char* message) override;
    void print_serdes_debug_message(const char* message) override;
    void print_pmd_status_message(const char* message, long duration) override;
    la_status set_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) override;
    la_status set_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) override;
    la_status setup_test_counter(la_mac_port::serdes_test_mode_e mode) override;
    la_status read_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) override;
    la_status read_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) override;

    la_status enable_low_power(bool enable) override;
    la_status set_serdes_speed_gbps(size_t serdes_speed_gbps) override;
    la_status set_anlt_capabilities(bool enable, an_capability_code_e an_spec_cap, size_t an_fec_request) override;
    la_status set_tuning_mode(la_mac_port::serdes_tuning_mode_e mode) override;
    la_status set_continuous_tuning_enabled(bool enabled) override;
    la_status set_debug_mode(bool mode) override;
    la_status save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root) override;
    la_status set_serdes_signal_control(la_uint_t serdes_idx,
                                        la_serdes_direction_e direction,
                                        la_mac_port::serdes_ctrl_e ctrl_type) override;
    la_status get_serdes_addr(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_serdes_addr) override;
    la_status get_continuous_tune_status(bool& out_status) override;
    la_status reenable_tx() override;
    la_status restore_state(bool enabled) override;
    la_status recenter_serdes_tx_fifo() override;

    const la_device_impl* get_device() const
    {
        return m_device.get();
    }
    void set_serdes_initialized(bool flag)
    {
        m_is_initialized = flag;
    }

private:
    void populate_default_serdes_parameters();

    int get_serdes_parameter_val(la_uint_t serdes_idx, la_mac_port::serdes_param_e param, int default_value) const;

    la_status init_plls(e_srm_baud_rates baud_rate);
    la_status init_rx();
    la_status is_port_tx_ready();

    la_status enable_pll_bleeders(la_uint_t die_addr, bool enable);

    la_status get_serdes_channel(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_channel);

    // Manual serializers for m_bundle by converting/loading to/from an array
    using srm_anlt_bundle_data = std::array<uint8_t, sizeof(srm_anlt_bundle_t)>;
    srm_anlt_bundle_data save_m_bundle() const;
    void load_m_bundle(const srm_anlt_bundle_data& data);

    // Parent device
    la_device_impl_wptr m_device;

    srm_serdes_device_handler_wptr m_serdes_device_handler;

    // Slice ID
    la_slice_id_t m_slice_id;

    // IFG ID
    la_ifg_id_t m_ifg_id;

    // SerDes base
    la_uint_t m_serdes_base_id;

    // Number of SerDes elements
    size_t m_serdes_count;

    // Port speed
    la_mac_port::port_speed_e m_speed;

    // SerDes speed
    la_mac_port::port_speed_e m_serdes_speed;

    // MAC port slice mode (network/fabric)
    la_slice_mode_e m_serdes_slice_mode;

    // Stores the serdes_test_mode of each serdes in port.
    std::vector<la_mac_port::serdes_test_mode_e> m_serdes_lane_test_mode;

    // Loopback mode
    la_mac_port::loopback_mode_e m_loopback_mode;

    // Speed in gbps, needed to get the correct baud rate
    size_t m_serdes_speed_gbps;

    // Serdes debug mode
    bool m_debug_mode;

    // Tuple containing the serdes index, die address, and direction.
    std::set<std::tuple<la_uint_t, la_uint_t, la_serdes_direction_e> > m_die_set;

    // pll init time map : die number, pll lock time (in milliseconds)
    std::map<la_uint_t, int> m_die_pll_lock_time;

    // SerDes are initialized
    bool m_is_initialized;

    /// @brief SerDes parameters setting.
    struct serdes_param_setting {
        la_mac_port::serdes_param_mode_e mode; ///< SerDes parameter mode.
        int value;                             ///< SerDes parameter value.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(serdes_param_setting);

    using serdes_param_map = std::map<la_mac_port::serdes_param_e, serdes_param_setting>;
    using serdes_stage_param_array = std::vector<serdes_param_map>;
    std::vector<serdes_stage_param_array> m_serdes_param_vec;

    srm_anlt_bundle_t m_bundle;

    // Holds port's Tx SerDes order - which port is active
    std::vector<uint> m_anlt_lane;

    bool m_is_an_enabled;
    serdes_handler::an_capability_code_e m_an_spec_cap;
    size_t m_an_fec_request;

    e_srm_anlt_an_status curr_an_status;
    int curr_tx_spare9_fsm_state[8]; // Keep track of up to 8 serdes per port
    std::vector<uint> tx_spare9_histogram;
    std::vector<uint> rx_spare9_histogram;

    // RX Serdes Spare9 and TX Serdes Spare9 transition history
    struct tx_sp9_state_transition {
        int rx_state;
        int tx_state[8];
        std::string timestamp;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(tx_sp9_state_transition);
    struct rx_sp9_state_transition {
        int rx_state;
        std::string timestamp;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(rx_sp9_state_transition);

    fixed_deque<tx_sp9_state_transition> m_tx_sp9_state_transition_queue;
    fixed_deque<rx_sp9_state_transition> m_rx_sp9_state_transition_queue;

    la_status build_anlt_bundle(srm_anlt_bundle_t& anlt_bundle);
    la_status get_serdes_state(const char* message);
    la_status set_anlt_tx_rules_default(srm_tx_bundle_rules_t& out_tx_rules);
    la_status set_anlt_rx_rules_default(srm_rx_bundle_rules_t& out_rx_rules);
    la_status set_anlt_tx_bundle_rules(srm_tx_bundle_rules_t& out_tx_rules);
    la_status set_anlt_rx_bundle_rules(srm_rx_bundle_rules_t& out_rx_rules);
    la_status enable_serdes_msg_gen();
    la_status read_srm_rx_snr();
    la_status csco_srm_anlt_init(srm_anlt_bundle_t* bundle, srm_anlt_rules_t* rules);
    la_status teardown_anlt();

    la_status print_srm_fsm_state(la_uint_t die);

    // Helper functions for save_serdes_debug_info.
    la_status add_link_status(json_t* json_node);
    la_status get_timestamp(std::string item_name,
                            la_uint_t entry,
                            la_uint_t total_entries,
                            la_uint16_t long_buf[],
                            json_t* json_timestamp);
    la_status add_anlt_status(json_t* json_node);
    la_status add_anlt_bundle(json_t* json_node);
    la_status add_link_config(json_t* json_node);
    la_status add_mcu_status(json_t* json_node, uint32_t loop_delay);
    la_status add_eye_capture(json_t* json_node);
    la_status add_serdes_reg_dump(json_t* json_node);
    la_status srm_pll_status_query(la_uint_t die, srm_pll_status& pll_status);

    void define_serdes_json_info(json_t* json_node, la_uint_t serdes_idx, la_uint_t die);
    void define_serdes_json_info(json_t* json_node, la_uint_t serdes_idx, la_uint_t die, la_uint_t channel);
    std::string create_serdes_label(la_uint_t serdes_idx, la_serdes_direction_e direction);
    std::string create_serdes_prefix(std::string prefix, la_uint_t serdes_idx, la_uint_t die, la_uint_t channel);
    std::string create_serdes_prefix(std::string prefix, la_uint_t serdes_idx, la_uint_t die);
    bool is_srm_dsp_mode_dfe(uint32_t dsp_mode);
};
}

#endif // __SRM_SERDES_HANDLER_H__
