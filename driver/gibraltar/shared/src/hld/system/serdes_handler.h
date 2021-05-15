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

#ifndef __SERDES_HANDLER_H__
#define __SERDES_HANDLER_H__

#include "api/system/la_log.h"
#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "common/la_status.h"

namespace silicon_one
{

class la_device_impl;

class serdes_handler
{
public:
    /// @brief Auto negotiation Technology Ability Field encoding according to 802.3 Table 73-4
    enum class an_capability_code_e {
        E_NO_TECHNOLOGY = 0x0000,
        E_1000BASE_KX = 0x0001,
        E_10GBASE_KX4 = 0x0002,
        E_10GBASE_KR = 0x0004,
        E_40GBASE_KR4 = 0x0008,
        E_40GBASE_CR4 = 0x0010,
        E_100GBASE_CR10 = 0x0020,
        E_100GBASE_KP4 = 0x0040,
        E_100GBASE_KR4 = 0x0080,
        E_100GBASE_CR4 = 0x0100,
        E_25GBASE_KRCR_S = 0x0200,
        E_25GBASE_KRCR = 0x0400,
        E_2_5GBASE_KX = 0x0800,
        E_5GBASE_KR = 0x1000,
        E_50GBASE_KR_CR = 0x2000,
        E_100GBASE_KR2_CR2 = 0x4000,
        E_200GBASE_KR4_CR4 = 0x8000,
    };

    virtual ~serdes_handler(){};

    /// @brief Verify correct firmware is loaded
    virtual la_status verify_firmware() = 0;

    /// @brief SerDes init
    virtual la_status init() = 0;

    /// @brief SerDes Enable/disable Tx output.
    virtual la_status enable_tx(bool tx_enable) = 0;

    /// @brief SerDes Enable/disable Rx output.
    virtual la_status enable_rx(bool rx_enable) = 0;

    /// @brief SerDes Refresh Tx (re-init and re-enable).
    virtual la_status refresh_tx() = 0;

    /// @brief SerDes TX/RX disbaled
    virtual la_status stop() = 0;

    /// @brief SerDes reset
    virtual la_status reset() = 0;

    /// @brief SerDes start peer detection
    virtual la_status wait_for_peer_start() = 0;

    /// @brief SerDes stop peer detection
    virtual la_status wait_for_peer_stop() = 0;

    /// @brief Initiate SerDes Rx tune
    virtual la_status tune() = 0;

    /// @brief Check if SerDes Rx tune complete
    virtual la_status get_tune_complete(bool& out_completed) = 0;

    /// @brief Activate SerDes Rx periodic tune
    virtual la_status periodic_tune_start() = 0;

    /// @brief Stop SerDes Rx periodic tune
    virtual la_status periodic_tune_stop() = 0;

    /// @brief Check if SerDes Rx periodec tune has stopped
    virtual la_status is_periodic_tune_stopped(bool& out_stopped) = 0;

    /// @brief Starts IEEE Auto-Negotiation on MAC port
    virtual la_status an_start(la_mac_port::state_e& state) = 0;

    /// @brief Stop Auto-Negotiation on MAC port
    virtual la_status an_stop() = 0;

    /// @brief Configures and starts IEEE PMD link training on given SerDes Address
    virtual la_status link_training_start(la_mac_port::state_e& state) = 0;

    /// @brief Checks if Auto-negotiation had common HCD and entered GOOD_CHECK state
    virtual la_status is_an_good_check(bool& an_good_check, la_mac_port::state_e& state) = 0;

    /// @brief Auto-Negotiation task for Base page receiving and sending first Next page
    virtual la_status an_base_page_rcv(la_mac_port::state_e& state) = 0;

    /// @brief Auto-Negotiation task for receiving Next page and sending the next Next page
    virtual la_status an_next_page_rcv(la_mac_port::state_e& state) = 0;

    /// @brief Polling task of checking the Auto-Negotiation completion
    virtual la_status is_an_completed(bool& out_completed) = 0;

    /// @brief Polling task of checking link training status
    virtual la_status link_training_handler(la_mac_port::state_e& state) = 0;

    /// @brief Set parameter to specific SerDes and stage
    virtual la_status set_serdes_parameter(la_uint_t serdes_idx,
                                           la_mac_port::serdes_param_stage_e stage,
                                           la_mac_port::serdes_param_e param,
                                           la_mac_port::serdes_param_mode_e mode,
                                           int32_t value)
        = 0;

    /// @brief Get parameter of specific SerDes and stage
    virtual la_status get_serdes_parameter(la_uint_t serdes_idx,
                                           la_mac_port::serdes_param_stage_e stage,
                                           la_mac_port::serdes_param_e param,
                                           la_mac_port::serdes_param_mode_e& out_mode,
                                           int32_t& out_value) const = 0;

    /// @brief Get parameter hardware value of specific SerDes
    virtual la_status get_serdes_parameter_hardware_value(la_uint_t serdes_idx,
                                                          la_mac_port::serdes_param_e param,
                                                          int32_t& out_value)
        = 0;

    /// @brief Get all parameters of specific SerDes and stage
    virtual la_status get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const = 0;

    /// @brief Remove parameter configuration from specific SerDes
    virtual la_status clear_serdes_parameter(la_uint_t serdes_idx,
                                             la_mac_port::serdes_param_stage_e stage,
                                             la_mac_port::serdes_param_e param)
        = 0;

    /// @brief Configure the SerDes remote loopback mode
    virtual la_status update_loopback_mode(la_mac_port::loopback_mode_e loopback_mode) = 0;

    /// @brief Configure the SerDes loopback mode
    virtual la_status set_loopback_mode(la_mac_port::loopback_mode_e loopback_mode) = 0;

    /// @brief Helper function for MAC_PORT save_state() to save a SerDes debug snapshot
    virtual void save_serdes_debug_message(const char* message) = 0;

    /// @brief Helper function for printing debug information
    virtual void print_tune_status_message(const char* message, la_logger_level_e severity) = 0;
    virtual void print_serdes_debug_message(const char* message) = 0;
    virtual void print_pmd_status_message(const char* message, long duration) = 0;

    /// @brief check if the mac port is tuned and with good quality
    /// Avago serdes tuning is best effort and it does not always return good eyes or DFE values
    /// a sub optimal tune can cause subsequence PCS_LOCK to fail.
    /// @retval     LA_STATUS_SUCCESS         port is tuned with good quality
    /// @retval     LA_STATUS_EINVAL          port serdes quality is not good
    virtual la_status is_tune_good() = 0;

    /// @brief Configure the test mode
    virtual la_status set_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
        = 0;
    virtual la_status set_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) = 0;
    virtual la_status setup_test_counter(la_mac_port::serdes_test_mode_e mode) = 0;

    /// @brief Get the Configured test mode
    virtual la_status read_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) = 0;
    virtual la_status read_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) = 0;

    /// @brief Enables low power mode
    virtual la_status enable_low_power(bool enable) = 0;

    /// @brief Set the SerDes speed in gbps
    virtual la_status set_serdes_speed_gbps(size_t serdes_speed_gbps) = 0;

    /// @brief Set Auto-negotiation and capabilities
    virtual la_status set_anlt_capabilities(bool enable, an_capability_code_e an_spec_cap, size_t an_fec_request) = 0;

    /// @brief Set tuning mode
    virtual la_status set_tuning_mode(la_mac_port::serdes_tuning_mode_e mode) = 0;

    /// @brief Set continuous tuning mode
    virtual la_status set_continuous_tuning_enabled(bool enabled) = 0;

    /// @brief Set serdes debug mode
    virtual la_status set_debug_mode(bool mode) = 0;

    /// @brief Helper function to get the SerDes address for internal handling.
    ///
    /// This address is used for by external SDK addresses, as well as SerDes specific APIs.
    ///
    /// @param[in]  serdes_idx                SerDes offset relative to SerDes in a port.
    /// @param[in]  serdes_dir                SerDes direction (TX/RX).
    /// @param[out] out_serdes_addr           Serdes address.
    ///
    /// @retval     LA_STATUS_SUCCESS         Returned valid SerDes address.
    /// @retval     LA_STATUS_EOUTOFRANGE     SerDes index is not valid for the port.
    virtual la_status get_serdes_addr(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, la_uint_t& out_serdes_addr) = 0;

    /// @brief Get debug information for a SerDes.
    virtual la_status save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root) = 0;

    /// @brief Control a SerDes setting at run-time.
    virtual la_status set_serdes_signal_control(la_uint_t serdes_idx,
                                                la_serdes_direction_e direction,
                                                la_mac_port::serdes_ctrl_e ctrl_type)
        = 0;

    virtual la_status get_continuous_tune_status(bool& out_status) = 0;

    /// @brief ReInit Serdes Tx
    virtual la_status reenable_tx() = 0;
    virtual la_status restore_state(bool enabled) = 0;

    /// @brief Recenter Serdex TX FIFO
    virtual la_status recenter_serdes_tx_fifo() = 0;
};
}

#endif // __SERDES_HANDLER_H__
