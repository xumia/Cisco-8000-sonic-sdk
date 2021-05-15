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

#ifndef __DUMMY_SERDES_HANDLER_BASE_H__
#define __DUMMY_SERDES_HANDLER_BASE_H__

#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "hld_types_fwd.h"
#include "system/serdes_handler.h"

#include <array>
#include <chrono>
#include <map>
#include <stddef.h>
namespace silicon_one
{

class la_device_impl;

class dummy_serdes_handler_base : public serdes_handler
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    dummy_serdes_handler_base();
    dummy_serdes_handler_base(const la_device_impl_wptr& m_device,
                              la_slice_id_t slice_id,
                              la_ifg_id_t ifg_id,
                              la_uint_t serdes_base_id,
                              size_t serdes_count,
                              la_mac_port::port_speed_e speed,
                              la_mac_port::port_speed_e serdes_speed,
                              la_slice_mode_e serdes_slice_mode);
    ~dummy_serdes_handler_base();

    la_status verify_firmware() override;

    // Starts IEEE Auto-Negotiation on MAC port
    la_status an_start(la_mac_port::state_e& state) override;

    // Cleanup for Auto-Negotiation disable on MAC port
    la_status an_stop() override;

    // Configures and starts IEEE PMD link training on given SerDes Address
    la_status link_training_start(la_mac_port::state_e& state) override;

    // Checks if Auto-negotiation had common HCD and entered GOOD_CHECK state
    la_status is_an_good_check(bool& an_good_check, la_mac_port::state_e& state) override;

    // Auto-Negotiation task for Base page receiving and sending first Next page
    la_status an_base_page_rcv(la_mac_port::state_e& state) override;

    // Auto-Negotiation task for receiving Next page and sending the next Next page
    la_status an_next_page_rcv(la_mac_port::state_e& state) override;

    // Polling task of checking link training status
    la_status link_training_handler(la_mac_port::state_e& state) override;

    // Polling task of checking the Auto-Negotiation completion
    la_status is_an_completed(bool& out_completed) override;

    // SerDes reset
    la_status reset() override;

    // SerDes init
    la_status init() override;

    la_status enable_tx(bool tx_enable) override;
    la_status enable_rx(bool tx_enable) override;

    la_status refresh_tx() override;

    // Initiate SerDes Rx tune
    la_status tune() override;

    // Check if SerDes Rx tune complete
    la_status get_tune_complete(bool& out_completed) override;

    // Activate SerDes Rx periodic tune
    la_status periodic_tune_start() override;

    // Stop SerDes Rx periodic tune
    la_status periodic_tune_stop() override;

    la_status is_periodic_tune_stopped(bool& out_stopped) override;

    la_status update_loopback_mode(la_mac_port::loopback_mode_e loopback_mode) override;
    la_status set_loopback_mode(la_mac_port::loopback_mode_e loopback_mode) override;

    la_status stop() override;

    la_status set_serdes_parameter(la_uint_t serdes_idx,
                                   la_mac_port::serdes_param_stage_e stage,
                                   la_mac_port::serdes_param_e param,
                                   la_mac_port::serdes_param_mode_e mode,
                                   int32_t value) override;
    la_status get_serdes_parameter(la_uint_t serdes_idx,
                                   la_mac_port::serdes_param_stage_e stage,
                                   la_mac_port::serdes_param_e param,
                                   la_mac_port::serdes_param_mode_e& out_mode,
                                   int32_t& out_value) const override;
    la_status get_serdes_parameter_hardware_value(la_uint_t serdes_idx,
                                                  la_mac_port::serdes_param_e param,
                                                  int32_t& out_value) override;
    la_status get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const override;
    la_status clear_serdes_parameter(la_uint_t serdes_idx,
                                     la_mac_port::serdes_param_stage_e stage,
                                     la_mac_port::serdes_param_e param) override;

    la_status wait_for_peer_start() override;
    la_status wait_for_peer_stop() override;

    void print_tune_status_message(const char* message, la_logger_level_e severity) override;
    void save_serdes_debug_message(const char* message) override;
    void print_serdes_debug_message(const char* message) override;
    void print_pmd_status_message(const char* message, long duration) override;

    la_status is_tune_good() override;

    la_status set_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) override;
    la_status set_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) override;
    la_status setup_test_counter(la_mac_port::serdes_test_mode_e mode) override;
    la_status read_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) override;
    la_status read_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) override;

    la_status enable_low_power(bool enable) override;
    la_status set_serdes_speed_gbps(size_t serdes_speed_gbps) override;
    la_status set_anlt_capabilities(bool enable, serdes_handler::an_capability_code_e an_spec_cap, size_t an_fec_request) override;

    la_status set_tuning_mode(la_mac_port::serdes_tuning_mode_e mode) override;
    la_status set_continuous_tuning_enabled(bool enabled) override;
    la_status set_debug_mode(bool mode) override;
    la_status save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root) override;
    la_status set_serdes_signal_control(la_uint_t serdes_idx,
                                        la_serdes_direction_e direction,
                                        la_mac_port::serdes_ctrl_e ctrl_type) override;

    la_status get_serdes_addr(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_serdes_addr) override;

    static bool serdes_firmware_check(Aapl_t* aapl_handler, size_t serdes, int rev, int build);

    la_status get_continuous_tune_status(bool& out_status) override;

    la_status reenable_tx() override;
    la_status restore_state(bool enabled) override;

    la_status recenter_serdes_tx_fifo() override;

private:
    /// @brief SerDes parameters setting.
    struct serdes_param_setting {
        la_mac_port::serdes_param_mode_e mode; ///< SerDes parameter mode.
        int32_t value;                         ///< SerDes parameter value.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(serdes_param_setting);

    using serdes_param_map = std::map<la_mac_port::serdes_param_e, serdes_param_setting>;
    using serdes_stage_param_array = std::vector<serdes_param_map>;

    la_status init(bool init_tx, bool init_rx);

    // TODO: Remove. SerDes handler should not know the device
    // Parent device
    la_device_impl_wptr m_device;

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

    std::vector<serdes_stage_param_array> m_serdes_param_vec;

    // MAC port slice mode (network/fabric)
    la_slice_mode_e m_serdes_slice_mode;

    la_mac_port::loopback_mode_e m_loopback_mode;

    // Holds port's Tx SerDes order - which port is active
    std::vector<uint> m_anlt_lane;

    bool m_continuous_tuning_enabled;
    bool m_continuous_tuning_activated;
    bool m_is_an_enabled;
    serdes_handler::an_capability_code_e m_an_spec_cap;
    size_t m_an_fec_request;
    size_t m_serdes_speed_gbps;
    bool m_debug_mode;
    la_mac_port::serdes_tuning_mode_e m_tuning_mode;
};
}

#endif // __DUMMY_SERDES_HANDLER_BASE_H__
