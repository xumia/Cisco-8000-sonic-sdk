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

#include "mac_pool_port.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/stopwatch.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "nplapi/npl_enums.h"
#include "system/ifg_handler.h"
#include "system/la_device_impl.h"
#include "system/reconnect_handler.h"
#include "system/serdes_handler.h"
#include "tm/la_interface_scheduler_impl.h"

#include <chrono>
#include <cmath>
#include <functional>
#include <jansson.h>
#include <numeric>
#include <set>
#include <sstream>
#include <thread>

using namespace std;

namespace silicon_one
{

enum {

    RS_FEC_KR4_FRAME_LEN_IN_BITS = 5280,
    RS_FEC_KP4_FRAME_LEN_IN_BITS = 5440,
    RS_FEC_KR4_UCW_SYMBOLS_CNT = 8,
    RS_FEC_KP4_UCW_SYMBOLS_CNT = 16,

    REFCLK_FREQUENCY = 156250, // in units of kHz
    // The Spec define NRZ link_fail_inhibit_timer to 510ms. But we define it to 1000ms as our polling task is slow
    AN_NRZ_LINK_FAIL_INHIBIT_TIMER = 1000,
    // The Spec define PAM4 link_fail_inhibit_timer to 1.7sec. But we define it to 2.5sec as our polling task is slow
    AN_PAM4_LINK_FAIL_INHIBIT_TIMER = 2500,
    CONSORTUIM_400G_NEXT_PAGE_OUI = 0x6a737d,
    BRCM_400G_NEXT_PAGE_OUI = 0xaf7,
    AN_NEXT_PAGE_OUI_MESSAGE_CODE = 0x5,
    CAP_400G_BIT_NEXT_PAGE_WORD2 = 0x4, // AN 400G capability bit for both BRCM and consortium
    MAX_PCAL_STOP_TIMEOUT = 2,
};

enum {
    PCS_STABLE_RX_DESKEW_FAILURE_THRESHOLD = 3,
    PCS_STABLE_RX_DESKEW_SAMPLE_WINDOW_MS = 1000,

    // WA for fabric max packet size: Writing all ones in the relevant register is 0x3FFF: means ignoring this configuration
    // Relevant register: mac_pool2_rx_mac_cfg1_register::fields::RX_MAX_PKT_SIZE_WIDTH
    MAX_FABRIC_PORT_PACKET_SIZE = 0x3FFF,
    MAX_NETWORK_PORT_PACKET_SIZE = 10012,
    MAX_STANDALONE_PORT_PACKET_SIZE = 10012,

    SERDES_PARAM_STAGES = (int)la_mac_port::serdes_param_stage_e::LAST + 1,
};

la_status
mac_pool_port::get_alignment_marker(size_t& alignment_marker_rx, size_t& alignment_marker_tx) const
{
    device_port_handler_base::mac_port_config_data config;
    if (m_device->m_device_port_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    m_device->m_device_port_handler->get_mac_port_config(m_speed, m_serdes_count, m_fec_mode, config);

    alignment_marker_rx = config.alignment_marker_rx;
    alignment_marker_tx = config.alignment_marker_tx;

    return LA_STATUS_SUCCESS;
}

mac_pool_port::mac_pool_port(const la_device_impl_wptr& device)
    : m_device(device),
      m_serdes_debug_mode(false),
      m_serdes_tuning_mode(la_mac_port::serdes_tuning_mode_e::ICAL),
      m_serdes_continuous_tuning_enabled(true),
      m_fec_bypass(la_mac_port::fec_bypass_e::NONE),
      m_rx_fc_term_mode(true),
      m_port_state(la_mac_port::state_e::PRE_INIT),
      m_loopback_mode(la_mac_port::loopback_mode_e::NONE),
      m_link_management_enabled(true),
      m_pcs_test_mode(la_mac_port::pcs_test_mode_e::NONE),
      m_pma_test_mode(la_mac_port::pma_test_mode_e::NONE),
      m_pcs_stable_timestamp(chrono::steady_clock::time_point::min()),
      m_ready_delayed_interrupts(true),
      m_tune_timeout_informed(false),
      m_pcs_stable_rx_deskew_failures(0),
      m_tune_with_pcs_lock(0),
      m_bad_tunes(0),
      m_pcal_stop_rx_disabled(false),
      m_is_an_enabled(false),
      m_serdes_handler(nullptr)
{
}

mac_pool_port::~mac_pool_port()
{
}

la_status
mac_pool_port::initialize(la_slice_id_t slice_id,
                          la_ifg_id_t ifg_id,
                          la_uint_t serdes_base,
                          size_t num_of_serdes,
                          la_mac_port::port_speed_e speed,
                          la_mac_port::fc_mode_e rx_fc_mode,
                          la_mac_port::fc_mode_e tx_fc_mode,
                          la_mac_port::fec_mode_e fec_mode,
                          la_mac_port::mlp_mode_e mlp_mode,
                          la_slice_mode_e port_slice_mode)
{
    m_slice_id = slice_id;
    m_ifg_id = ifg_id;
    m_serdes_base_id = serdes_base;
    m_serdes_count = num_of_serdes;
    m_speed = speed;
    m_rx_fc_mode = rx_fc_mode;
    m_tx_fc_mode = tx_fc_mode;
    m_fec_mode = fec_mode;
    m_mlp_mode = mlp_mode;
    m_port_slice_mode = port_slice_mode;

    m_state_histogram.resize(static_cast<uint>(la_mac_port::state_e::LAST) + 1, 0);

    m_tune_timeout = chrono::seconds(m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_TUNE_TIMEOUT].int_val);
    m_cdr_lock_timeout
        = chrono::seconds(m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT].int_val);
    m_pcs_lock_time
        = chrono::milliseconds(m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_PCS_LOCK_TIME].int_val);
    if (is_network_slice(m_port_slice_mode)) {
        m_tune_and_pcs_lock_iter
            = m_device->m_device_properties[(int)la_device_property_e::NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER].int_val;
    } else {
        m_tune_and_pcs_lock_iter
            = m_device->m_device_properties[(int)la_device_property_e::FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER].int_val;
    }

    // EID is relevant only in Pacific, in Gibraltar this is handled by the SerDes.
    m_enable_eid = m_device->m_ll_device->is_pacific()
                   && !m_device->m_device_properties[(int)la_device_property_e::DISABLE_ELECTRICAL_IDLE_DETECTION].bool_val;
    m_dfe_eid = m_device->m_device_properties[(int)la_device_property_e::SERDES_DFE_EID].bool_val;
    m_ignore_long_tune = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_IGNORE_LONG_TUNE].bool_val;
    m_check_ser_ber = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_ENABLE_SER_CHECK].bool_val;

    m_serdes_post_anlt_tune_disable
        = m_device->m_device_properties[(int)la_device_property_e::DISABLE_SERDES_POST_ANLT_TUNE].bool_val;

    if (!num_of_serdes) {
        log_err(MAC_PORT, "%s: %s num_of_serdes is 0", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    // Check valid configuration
    if (m_device->m_device_port_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (!m_device->m_device_port_handler->is_valid_config(speed, num_of_serdes, fec_mode)) {
        log_err(MAC_PORT,
                "%s: %s invalid configuraion, speed=%s, serdes_count=%ld, fec_mode=%s",
                __func__,
                this->to_string().c_str(),
                silicon_one::to_string(speed).c_str(),
                num_of_serdes,
                silicon_one::to_string(fec_mode).c_str());
        return LA_STATUS_EINVAL;
    }

    if ((serdes_base % num_of_serdes) != 0) {
        log_err(MAC_PORT,
                "%s: %s serdes_base=%d is not an integer multiple of num_of_serdes=%ld",
                __func__,
                this->to_string().c_str(),
                serdes_base,
                num_of_serdes);
        return LA_STATUS_EINVAL;
    }

    m_serdes_rxpll_value_vec.resize(m_serdes_count);
    m_serdes_rxpll2_value_vec.resize(m_serdes_count);

    m_serdes_lane_tx_test_mode.resize(m_serdes_count);
    m_serdes_lane_rx_test_mode.resize(m_serdes_count);
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        m_serdes_lane_tx_test_mode[serdes] = la_mac_port::serdes_test_mode_e::NONE;
        m_serdes_lane_rx_test_mode[serdes] = la_mac_port::serdes_test_mode_e::NONE;
    }

    la_status stat = recalc_data_members();
    return_on_error(stat);

    stat = set_reset(la_mac_port_base::mac_reset_state_e::RESET_ALL);
    return_on_error(stat);

    stat = configure_lanes();
    return_on_error(stat);

    stat = reset_general_config();
    return_on_error(stat);

    stat = reset_mac_config();
    return_on_error(stat);

    stat = reset_packet_sizes();
    return_on_error(stat);

    stat = reset_ipg();
    return_on_error(stat);

    stat = reset_xon_xoff_timers();
    return_on_error(stat);

    stat = configure_ber_fsm();
    return_on_error(stat);

    stat = configure_degraded_ser();
    return_on_error(stat);

    stat = update_rs_fec_config();
    return_on_error(stat);

    stat = update_rx_krf_config();
    return_on_error(stat);

    stat = configure_pma();
    return_on_error(stat);

    stat = configure_loopback_mode();
    return_on_error(stat);

    stat = configure_pcs_test_mode();
    return_on_error(stat);

    stat = configure_pma_test_mode();
    return_on_error(stat);

    for (la_uint_t index = 0; index < m_serdes_count; index++) {
        m_device->m_serdes_inuse[m_slice_id][m_ifg_id][m_serdes_base_id + index] = true;
    }

    stat = configure_info_phy();
    return_on_error(stat);

    if (is_network_slice(m_port_slice_mode)) {
        // Configure IFGB only for network slice, for fabric configure it on IFGB initialization
        la_mac_port::fc_mode_e fc_mode = rx_fc_mode;
        if (tx_fc_mode != la_mac_port::fc_mode_e::NONE) {
            // tx_fc_mode takes precedence over rx_fc_mode
            fc_mode = m_tx_fc_mode;
        }
        stat = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->configure_port(
            m_mac_lane_index_in_ifgb, m_mac_lanes_reserved, m_speed, m_mac_lanes_count, mlp_mode, fc_mode);
        return_on_error(stat);

        stat = set_reset(la_mac_port_base::mac_reset_state_e::RESET_MAC_RX_ONLY);
        return_on_error(stat);

        stat = toggle_pdif_reset();
        return_on_error(stat);
    } else {
        // Fabric
        if (m_device->m_ll_device->get_device_revision() == la_device_revision_e::PACIFIC_A0) {
            stat = set_reset(la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
            return_on_error(stat);
        } else {
            stat = set_reset(la_mac_port_base::mac_reset_state_e::RESET_MAC_RX_ONLY);
            return_on_error(stat);
        }
    }

    stat = initialize_serdes_handler();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::initialize_serdes_handler()
{
    serdes_handler* serdes_handler;
    if (m_device->m_serdes_device_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    la_status stat = m_device->m_serdes_device_handler->create_serdes_group_handler(
        m_slice_id, m_ifg_id, m_serdes_base_id, m_serdes_count, m_speed, m_serdes_speed, m_port_slice_mode, serdes_handler);
    return_on_error(stat);

    m_serdes_handler.reset(serdes_handler);

    stat = recalc_data_members();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::reset_ifgb()
{
    if (m_port_slice_mode == la_slice_mode_e::CARRIER_FABRIC) {
        // The following reset* calls undo config done by ifg_handlers::configure_port, which is not called by mac_pool for fabric
        // ports.
        // If these are to be called, need to consider LC_56_FABRIC_PORT_MODE, that is, the mac_pools m_slice_id, m_ifg_id,
        // m_serdes_base_id hold the lender's port.
        // Whereas most IFGB config takes places at the borrower IFG, except the FC mode, which still takes place at the lender IFG.
        return LA_STATUS_SUCCESS;
    }

    la_status stat = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->clear_port(
        m_mac_lane_index_in_ifgb, m_mac_lanes_reserved, m_speed, m_mac_lanes_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::recalc_data_members()
{
    device_port_handler_base::mac_port_config_data config;
    if (m_device->m_device_port_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    m_device->m_device_port_handler->get_mac_port_config(m_speed, m_serdes_count, m_fec_mode, config);

    m_mac_lanes_count = config.mac_lanes;
    m_mac_lanes_reserved = config.reserved_mac_lanes;

    m_serdes_speed = config.serdes_speed;
    m_serdes_speed_gbps = config.serdes_speed_gbps;
    m_pcs_lanes_per_mac_lane = config.pcs_lanes_per_mac_lane;

    if (m_serdes_handler != nullptr) {
        serdes_handler::an_capability_code_e an_spec_cap = get_an_spec_user_capabilities();
        size_t an_fec_request = get_an_fec_request();
        m_serdes_handler->set_anlt_capabilities(m_is_an_enabled, an_spec_cap, an_fec_request);
        m_serdes_handler->set_serdes_speed_gbps(m_serdes_speed_gbps);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::destroy()
{
    la_status stat = reset_ifgb();
    return_on_error(stat);

    stat = reset_rs_fec_config();
    return_on_error(stat);

    stat = reset_rx_krf_config();
    return_on_error(stat);

    stat = destroy_general_config();
    return_on_error(stat);

    for (la_uint_t index = 0; index < m_serdes_count; index++) {
        m_device->m_serdes_inuse[m_slice_id][m_ifg_id][m_serdes_base_id + index] = false;
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_debug_mode(bool mode)
{
    m_serdes_debug_mode = mode;
    m_serdes_handler->set_debug_mode(m_serdes_debug_mode);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_debug_mode(bool& out_mode)
{
    out_mode = m_serdes_debug_mode;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_serdes_tuning_mode(la_mac_port::serdes_tuning_mode_e mode)
{
    m_serdes_tuning_mode = mode;
    update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::SERDES_TUNING_MODE, (uint8_t)mode);

    m_serdes_handler->set_tuning_mode(mode);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_serdes_tuning_mode(la_mac_port::serdes_tuning_mode_e& out_mode)
{
    out_mode = m_serdes_tuning_mode;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_serdes_continuous_tuning_enabled(bool enabled)
{
    la_status status = LA_STATUS_SUCCESS;

    m_serdes_handler->set_continuous_tuning_enabled(enabled);

    if (m_port_state >= la_mac_port::state_e::PCS_STABLE || !m_link_management_enabled) {
        if (enabled) {
            status = m_serdes_handler->periodic_tune_start();
        } else {
            status = m_serdes_handler->periodic_tune_stop();
        }
    }
    if (status == LA_STATUS_SUCCESS) {
        m_serdes_continuous_tuning_enabled = enabled;
        update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::SERDES_CONTINUOUS_TUNING_ENABLED, enabled);
    }

    return status;
}

la_status
mac_pool_port::get_serdes_continuous_tuning_enabled(bool& out_enabled) const
{
    out_enabled = m_serdes_continuous_tuning_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_serdes_parameter(la_uint_t serdes_idx,
                                    la_mac_port::serdes_param_stage_e stage,
                                    la_mac_port::serdes_param_e param,
                                    la_mac_port::serdes_param_mode_e mode,
                                    int32_t value)
{
    la_status rc = m_serdes_handler->set_serdes_parameter(serdes_idx, stage, param, mode, value);
    return_on_error(rc);

    m_device->m_reconnect_handler->update_serdes_parameter(shared_from_this(), serdes_idx, stage, param, mode, value);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_serdes_parameter(la_uint_t serdes_idx,
                                    la_mac_port::serdes_param_stage_e stage,
                                    la_mac_port::serdes_param_e param,
                                    la_mac_port::serdes_param_mode_e& out_mode,
                                    int32_t& out_value) const
{
    return m_serdes_handler->get_serdes_parameter(serdes_idx, stage, param, out_mode, out_value);
}

la_status
mac_pool_port::get_serdes_parameter_hardware_value(la_uint_t serdes_idx, la_mac_port::serdes_param_e param, int32_t& out_value)
{
    return m_serdes_handler->get_serdes_parameter_hardware_value(serdes_idx, param, out_value);
}

la_status
mac_pool_port::get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const
{
    return m_serdes_handler->get_serdes_parameters(serdes_idx, out_param_array);
}

la_status
mac_pool_port::clear_serdes_parameter(la_uint_t serdes_idx,
                                      la_mac_port::serdes_param_stage_e stage,
                                      la_mac_port::serdes_param_e param)
{
    la_status rc = m_serdes_handler->clear_serdes_parameter(serdes_idx, stage, param);
    return_on_error(rc);

    m_device->m_reconnect_handler->clear_serdes_parameter(shared_from_this(), serdes_idx, stage, param);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_an_enabled(bool& out_enabled) const
{
    out_enabled = m_is_an_enabled;
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_an_enabled(bool enabled)
{
    if ((m_port_state != la_mac_port::state_e::PRE_INIT) && (m_port_state != la_mac_port::state_e::INACTIVE)) {
        log_err(MAC_PORT, "%s AN not supported on activated state. ", this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    if (!enabled && m_is_an_enabled) {
        // disable an mode
        la_status stat = m_serdes_handler->an_stop();
        return_on_error(stat);
    }

    if (!enabled) {
        m_is_an_enabled = enabled;
        return LA_STATUS_SUCCESS;
    }

    if (m_loopback_mode != la_mac_port::loopback_mode_e::NONE) {
        log_err(MAC_PORT, "%s AN not supported on loopback mode port. ", this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    if (!is_an_capable()) {
        log_err(MAC_PORT, "%s Port speed, FEC, and/or swapped-lanes doesn't support AN/LT. ", this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    m_is_an_enabled = enabled;
    la_status stat = recalc_data_members();

    return stat;
}

la_status
mac_pool_port::set_speed_enabled(la_mac_port::port_speed_e speed, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::set_fec_mode_enabled(la_mac_port::fec_mode_e fec_mode, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

serdes_handler::an_capability_code_e
mac_pool_port::get_an_spec_user_capabilities()
{
    device_port_handler_base::mac_port_config_data config;
    if (m_device->m_device_port_handler == nullptr) {
        return serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY;
    }

    m_device->m_device_port_handler->get_mac_port_config(m_speed, m_serdes_count, m_fec_mode, config);

    return config.an_capability;
}

bool
mac_pool_port::is_valid_an_capability()
{
    serdes_handler::an_capability_code_e an_cap = get_an_spec_user_capabilities();
    // TODO: If equation is updated, device_port_handler_base::get_valid_configs() needs to update as well.
    return (m_speed == la_mac_port::port_speed_e::E_400G || an_cap != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY);
}

bool
mac_pool_port::is_an_capable()
{
    // AN not supported on lane-swap ports in Pacific only.
    if (m_device->m_ll_device->is_pacific()) {
        for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
            size_t tx_serdes = m_serdes_base_id + serdes_id;
            size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
            if (tx_serdes != rx_serdes) {
                log_debug(MAC_PORT, "%s AN not supported on lane swapped port. ", this->to_string().c_str());
                return false;
            }
        }
    }

    bool is_valid_an_cap = is_valid_an_capability();
    if (!is_valid_an_cap) {
        log_debug(MAC_PORT, "%s Port speed and/or FEC doesn't support AN/LT. ", this->to_string().c_str());
        return false;
    }

    return true;
}

uint
mac_pool_port::get_an_fec_request()
{
    device_port_handler_base::mac_port_config_data config;
    if (m_device->m_device_port_handler == nullptr) {
        return (uint)-1;
    }

    m_device->m_device_port_handler->get_mac_port_config(m_speed, m_serdes_count, m_fec_mode, config);

    return config.an_fec_capability;
}

std::string
mac_pool_port::to_string() const
{
    std::stringstream log_message;
    log_message << "SerDes " << m_slice_id << "/" << m_ifg_id << "/" << m_serdes_base_id;
    return log_message.str();
}

void
mac_pool_port::set_state(la_mac_port::state_e state)
{
    if (m_port_state != state) {
        // get state names
        std::string former_state = silicon_one::to_string(m_port_state);
        std::string new_state = silicon_one::to_string(state);

        la_int_t max_num_sm_transitions;
        m_device->get_int_property(la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES, max_num_sm_transitions);
        m_sm_state_transition_queue.set_max_size(max_num_sm_transitions);
        // check if user wants state transition captured for save state
        if (max_num_sm_transitions > 0) {
            sm_state_transition state_transition_data{};
            size_t buffer_size = 100;

            char timestamp[buffer_size];
            add_timestamp(timestamp, sizeof(timestamp));

            state_transition_data.new_state = state;
            state_transition_data.timestamp = std::string(timestamp);

            m_sm_state_transition_queue.push(state_transition_data);
        }

        log_debug(MAC_PORT,
                  "State changed on SerDes %d/%d/%d: %s -> %s",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  former_state.c_str(),
                  new_state.c_str());

        m_port_state = state;
        m_device->m_reconnect_handler->update_mac_port_state(shared_from_this());
        m_state_histogram[static_cast<uint>(m_port_state)]++;
    }

    // Some time keeping
    if (state == la_mac_port::state_e::PCS_STABLE) {
        m_pcs_stable_rx_deskew_window_start_time = chrono::steady_clock::now();
        m_pcs_stable_rx_deskew_failures = 0;
        clear_rx_deskew_fifo_overflow_interrupt();
    }
}

la_mac_port::state_e
mac_pool_port::get_state() const
{
    return m_port_state;
}

bool
mac_pool_port::is_serdes_mode_active() const
{
    return ((m_loopback_mode == la_mac_port::loopback_mode_e::NONE)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES))
           || (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_PMA);
}

bool
mac_pool_port::is_serdes_mode_dummy() const
{
    return ((m_loopback_mode == la_mac_port::loopback_mode_e::MII_SRDS_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::PMA_SRDS_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::INFO_SRDS_CLK));
}

bool
mac_pool_port::is_pcs_mode_off() const
{
    return ((m_loopback_mode == la_mac_port::loopback_mode_e::MII_CORE_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::MII_SRDS_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::INFO_MAC_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::INFO_SRDS_CLK));
}

bool
mac_pool_port::is_serdes_mode_off() const
{
    return ((m_loopback_mode == la_mac_port::loopback_mode_e::MII_CORE_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::PMA_CORE_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::INFO_MAC_CLK));
}

bool
mac_pool_port::is_mii_pma_remote_loopback() const
{
    return ((m_loopback_mode == la_mac_port::loopback_mode_e::MII_CORE_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::MII_SRDS_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::PMA_CORE_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::PMA_SRDS_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_PMA)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::INFO_MAC_CLK)
            || (m_loopback_mode == la_mac_port::loopback_mode_e::INFO_SRDS_CLK));
}

bool
mac_pool_port::is_link_management_enabled() const
{
    return (m_link_management_enabled && !is_port_in_test_mode());
}

bool
mac_pool_port::is_port_in_test_mode() const
{
    if (m_pcs_test_mode != la_mac_port::pcs_test_mode_e::NONE || m_pma_test_mode != la_mac_port::pma_test_mode_e::NONE) {
        return true;
    }

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        if (m_serdes_lane_tx_test_mode[serdes] != la_mac_port::serdes_test_mode_e::NONE) {
            return true;
        }
        if (m_serdes_lane_rx_test_mode[serdes] != la_mac_port::serdes_test_mode_e::NONE) {
            return true;
        }
    }

    return false;
}

la_status
mac_pool_port::get_state_histogram(bool clear, la_mac_port::state_histogram& out_state_histogram)
{
    out_state_histogram = m_state_histogram;

    if (clear) {
        std::fill(m_state_histogram.begin(), m_state_histogram.end(), 0);
        m_state_histogram[static_cast<uint>(m_port_state)]++;
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::save_mac_port_state(la_mac_port::port_debug_info_e info_type, json_t* parent)
{
    la_status status;

    // Save MAC_PORT STATUS
    if (info_type == la_mac_port::port_debug_info_e::MAC_STATUS || info_type == la_mac_port::port_debug_info_e::ALL
        || info_type == la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG) {

        add_state_histogram(parent);

        status = add_mac_port_config(parent);
        return_on_error_log(status, MAC_PORT, ERROR, "add_mac_port_config");

        status = add_mac_port_status(parent);
        return_on_error_log(status, MAC_PORT, ERROR, "add_mac_port_status");

        status = add_mac_port_soft_state(parent);
        return_on_error_log(status, MAC_PORT, ERROR, "add_mac_port_soft_state");

        status = add_fec_status(parent);
        return_on_error_log(status, MAC_PORT, ERROR, "add_fec_status");

        status = add_mib_counters(parent);
        return_on_error_log(status, MAC_PORT, ERROR, "add_mib_counters");
    }

    // add state transition history if device property is enabled
    status = add_state_transition_history(parent);
    return_on_error_log(status, MAC_PORT, ERROR, "add_sm_transition_history");

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::add_mac_port_soft_state(json_t* parent)
{
    json_t* mac_port_soft_state_root = json_object();

    json_object_set_new(mac_port_soft_state_root, "an_enabled", json_boolean(m_is_an_enabled));
    json_object_set_new(mac_port_soft_state_root, "bad_tunes", json_integer(m_bad_tunes));
    json_object_set_new(mac_port_soft_state_root, "check_ser_ber", json_boolean(m_check_ser_ber));
    json_object_set_new(mac_port_soft_state_root, "continuous_tuning", json_boolean(m_serdes_continuous_tuning_enabled));
    json_object_set_new(mac_port_soft_state_root, "dfe_eid", json_boolean(m_dfe_eid));
    json_object_set_new(mac_port_soft_state_root, "enable_eid", json_boolean(m_enable_eid));
    json_object_set_new(mac_port_soft_state_root, "fec_bypass", json_string(silicon_one::to_string(m_fec_bypass).c_str()));
    json_object_set_new(mac_port_soft_state_root, "fec_mode", json_string(silicon_one::to_string(m_fec_mode).c_str()));
    json_object_set_new(mac_port_soft_state_root, "ignore_long_tune", json_boolean(m_ignore_long_tune));
    json_object_set_new(mac_port_soft_state_root, "link_management", json_boolean(m_link_management_enabled));
    json_object_set_new(mac_port_soft_state_root, "loopback_mode", json_string(silicon_one::to_string(m_loopback_mode).c_str()));
    json_object_set_new(mac_port_soft_state_root, "pcs_test_mode", json_string(silicon_one::to_string(m_pcs_test_mode).c_str()));
    json_object_set_new(mac_port_soft_state_root, "pma_test_mode", json_string(silicon_one::to_string(m_pma_test_mode).c_str()));
    json_object_set_new(
        mac_port_soft_state_root, "port_slice_mode", json_string(silicon_one::to_string(m_port_slice_mode).c_str()));
    json_object_set_new(mac_port_soft_state_root, "port_state", json_string(silicon_one::to_string(m_port_state).c_str()));
    json_object_set_new(mac_port_soft_state_root, "rx_fc_mode", json_string(silicon_one::to_string(m_rx_fc_mode).c_str()));
    json_object_set_new(mac_port_soft_state_root, "rx_fc_term_mode", json_boolean(m_rx_fc_term_mode));
    json_object_set_new(mac_port_soft_state_root, "serdes_post_anlt_tune_disable", json_boolean(m_serdes_post_anlt_tune_disable));
    json_object_set_new(mac_port_soft_state_root, "serdes_speed_gbps", json_integer(m_serdes_speed_gbps));
    json_object_set_new(mac_port_soft_state_root, "tune_and_pcs_lock_iter", json_integer(m_tune_and_pcs_lock_iter));
    json_object_set_new(mac_port_soft_state_root, "tune_timeout_inform", json_boolean(m_tune_timeout_informed));
    json_object_set_new(mac_port_soft_state_root, "tune_with_pcs_lock", json_integer(m_tune_with_pcs_lock));
    json_object_set_new(mac_port_soft_state_root, "tx_fc_mode", json_string(silicon_one::to_string(m_tx_fc_mode).c_str()));
    json_object_set_new(mac_port_soft_state_root, "pcal_stop_rx_disabled", json_boolean(m_pcal_stop_rx_disabled));

    json_object_set_new(parent, "mac_port_soft_state", mac_port_soft_state_root);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::add_state_transition_history(json_t* parent)
{
    int json_status = 0;
    la_int_t max_num_sm_transitions;

    // check if feature is enabled, if not clear all data if queue is not empty
    m_device->get_int_property(la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES, max_num_sm_transitions);
    m_sm_state_transition_queue.set_max_size(max_num_sm_transitions);
    if (max_num_sm_transitions == 0) {
        // feature is disabled
        return LA_STATUS_SUCCESS;
    }

    // nothing to do if queue is empty and feature is enabled
    if (m_sm_state_transition_queue.size() == 0) {
        log_debug(MAC_PORT, "%s : no state transition data to add to save state.", __func__);
        return LA_STATUS_SUCCESS;
    }

    // insert all transitions into a json array to support chronological order
    json_t* state_transition_array = json_array();

    // get most recent entry in the queue
    auto sm_transition_iter = m_sm_state_transition_queue.begin();
    // iterate from newest to oldest
    while (sm_transition_iter != m_sm_state_transition_queue.end()) {
        sm_state_transition& state_transition_data = *sm_transition_iter++;

        std::string new_state = silicon_one::to_string(state_transition_data.new_state);
        std::string& timestamp = state_transition_data.timestamp;

        // add transition json object to queue to add to save_state output
        json_t* state_transition_root = json_object();

        json_object_set_new(state_transition_root, "new_state", json_string(new_state.c_str()));
        json_object_set_new(state_transition_root, "timestamp", json_string(timestamp.c_str()));

        // insert to beginning of array to maintain order
        size_t insertion_index = 0;
        json_status = json_array_insert_new(state_transition_array, insertion_index, state_transition_root);
        if (json_status == -1) {
            log_err(MAC_PORT, "%s : failed to insert state transition data to json array", __func__);
            return LA_STATUS_EINVAL;
        }
    }

    json_status = json_object_set_new(parent, "state_transition_history", state_transition_array);
    if (json_status == -1) {
        log_err(MAC_PORT, "%s : failed to add state transition array to json object", __func__);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::add_serdes_parameters(json_t* parent)
{
    la_status status = LA_STATUS_SUCCESS;
    json_t* serdes_params_root = json_object();

    // iterate through all serdes
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        // create root serdes object to represent serdes lane
        json_t* serdes_root = json_object();
        std::string serdes_index_label = "index_" + std::to_string(serdes);

        // get parameters for current serdes
        la_mac_port::serdes_param_array parameters;
        status = m_serdes_handler->get_serdes_parameters(serdes, parameters);
        return_on_error(status);

        // add parameters to serdes lane object
        for (la_uint_t i = 0; i < parameters.size(); i++) {
            // create parameter object for serdes lane
            json_t* parameter_root = json_object();
            std::string parameter_name = silicon_one::to_string(parameters[i].parameter);
            std::string stage_name = silicon_one::to_string(parameters[i].stage);
            std::string mode_name = silicon_one::to_string(parameters[i].mode);

            // add values to object (stage, mode and value)
            json_object_set_new(parameter_root, "stage", json_string(stage_name.c_str()));
            json_object_set_new(parameter_root, "mode", json_string(mode_name.c_str()));
            json_object_set_new(parameter_root, "value", json_integer(parameters[i].value));

            json_object_set_new(serdes_root, parameter_name.c_str(), parameter_root);
        }

        json_object_set_new(serdes_params_root, serdes_index_label.c_str(), serdes_root);
    }

    json_object_set_new(parent, "serdes_parameters", serdes_params_root);

    return status;
}

void
mac_pool_port::add_state_histogram(json_t* parent)
{
    la_mac_port::state_histogram state_histogram{};
    get_state_histogram(false /* clear */, state_histogram);

    json_t* hist_root_json = json_object();
    json_object_set_new(hist_root_json, "bad_eye_retry", json_integer(m_bad_tunes));

    for (la_mac_port::state_e state = la_mac_port::state_e::PRE_INIT; state <= la_mac_port::state_e::LINK_UP;
         state = la_mac_port::state_e(to_utype(state) + 1)) {
        uint32_t hist_val = state_histogram[to_utype(state)];
        json_object_set_new(hist_root_json, silicon_one::to_string(state).c_str(), json_integer(hist_val));
    }

    // Append to parent and "loose" reference to the locally created json object.
    json_object_set_new(parent, "mac_state_histogram", hist_root_json);
}

la_status
mac_pool_port::add_mac_port_config(json_t* parent)
{
    la_mac_port::port_speed_e serdes_speed = m_serdes_speed;
    la_mac_port::fec_mode_e fec_mode = m_fec_mode;
    size_t num_of_serdes = get_num_of_serdes();
    json_t* mac_port_config_root = json_object();

    json_object_set_new(mac_port_config_root, "Slice", json_integer(m_slice_id));
    json_object_set_new(mac_port_config_root, "Ifg", json_integer(m_ifg_id));
    json_object_set_new(mac_port_config_root, "fec_mode", json_string(silicon_one::to_string(fec_mode).c_str()));
    json_object_set_new(mac_port_config_root, "serdes_speed", json_string(silicon_one::to_string(serdes_speed).c_str()));
    json_object_set_new(mac_port_config_root, "num_of_serdes", json_integer(num_of_serdes));

    for (size_t serdes_idx = 0; serdes_idx < m_serdes_count; ++serdes_idx) {
        const auto& serdes_info = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx];
        json_t* serdes_info_root = json_object();
        json_object_set_new(serdes_info_root, "rx_source", json_integer(serdes_info.rx_source));
        json_object_set_new(serdes_info_root, "anlt_order", json_integer(serdes_info.anlt_order));
        json_object_set_new(serdes_info_root, "rx_polarity_inversion", json_integer(serdes_info.rx_polarity_inversion));
        json_object_set_new(serdes_info_root, "tx_polarity_inversion", json_integer(serdes_info.tx_polarity_inversion));
        // Append to parent and "loose" reference to the locally created json object.
        string str = "serdes_info_" + std::to_string(m_serdes_base_id + serdes_idx);
        json_object_set_new(mac_port_config_root, str.c_str(), serdes_info_root);
    }

    // Append to parent and "loose" reference to the locally created json object.
    json_object_set_new(parent, "mac_port_config", mac_port_config_root);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::add_fec_status(json_t* parent)
{
    size_t correctable = 0;
    size_t uncorrectable = 0;
    bool fec_enabled = false;
    la_mac_port::rs_fec_debug_counters fec_counter{};
    la_status status;
    bool clear_counter = false;

    // get fec mode
    la_mac_port::fec_mode_e fec_mode = la_mac_port::fec_mode_e::NONE;
    status = get_fec_mode(fec_mode);
    return_on_error(status);

    if (fec_mode == la_mac_port::fec_mode_e::NONE) {
        // return if fec is disabled
        return status;
    }

    // get fec debug enabled
    status = get_rs_fec_debug_enabled(fec_enabled);
    return_on_error(status);

    // check if rs fec is enabled
    bool is_rs_fec = false;
    if (fec_mode == la_mac_port::fec_mode_e::RS_KR4 || fec_mode == la_mac_port::fec_mode_e::RS_KP4
        || fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI) {
        // only these fec modes are supported to get debug counters
        is_rs_fec = true;
    }

    // get fec counter values
    status = read_counter(clear_counter, la_mac_port::counter_e::FEC_CORRECTABLE, correctable);
    return_on_error(status);

    status = read_counter(clear_counter, la_mac_port::counter_e::FEC_UNCORRECTABLE, uncorrectable);
    return_on_error(status);

    json_t* fec_status_root = json_object();
    json_object_set_new(fec_status_root, "is_rs_fec", json_boolean(is_rs_fec));
    json_object_set_new(fec_status_root, "fec_debug_enabled", json_boolean(fec_enabled));
    json_object_set_new(fec_status_root, "correctable", json_integer(correctable));
    json_object_set_new(fec_status_root, "uncorrectable", json_integer(uncorrectable));

    // get fec stats
    if (fec_enabled && is_rs_fec) {
        status = read_rs_fec_debug_counters(false, fec_counter);
        return_on_error(status);

        la_uint64_t max_codewords_bin = (fec_mode == la_mac_port::fec_mode_e::RS_KR4) ? la_mac_port::MAX_RS_FEC_CW_SYMBOLS / 2
                                                                                      : la_mac_port::MAX_RS_FEC_CW_SYMBOLS;

        // total codewords is used to get Symbol Error Rate (SER), only correctable codewords are relevant
        la_uint64_t total_cws = 0;
        json_t* codeword_array = json_array();
        for (la_uint64_t i = 0; i < max_codewords_bin; i++) {
            total_cws += fec_counter.codeword[i];
            json_array_append_new(codeword_array, json_integer(fec_counter.codeword[i]));
        }
        la_uint64_t syms_per_cw
            = (fec_mode == la_mac_port::fec_mode_e::RS_KR4) ? RS_FEC_KR4_SYMBOLS_PER_CODEWORD : RS_FEC_KP4_SYMBOLS_PER_CODEWORD;

        // calculate total symbols to date, to find ratio of errors per lane
        la_uint64_t total_symbols = total_cws * syms_per_cw;

        // setup top level json object for symbol errors
        json_t* symbol_errors_root = json_object();

        // get symbol error count for each fec lane
        la_mac_port::rs_fec_sym_err_counters sym_lane_counter{};
        status = read_rs_fec_symbol_errors_counters(false, sym_lane_counter);

        // calculate and add SER (symbol error rate) for each fec lane
        size_t fec_lanes_per_fec_engine = m_fec_engine_config.at(m_speed).fec_lane_per_engine;
        size_t fec_engines = m_fec_engine_config.at(m_speed).fec_engine_count;
        size_t fec_lanes_per_serdes = (fec_lanes_per_fec_engine * fec_engines) / m_serdes_count;

        for (size_t i = 1; i <= fec_lanes_per_fec_engine * fec_engines; i += fec_lanes_per_serdes) {
            la_uint_t serdes_sym_err_count = 0;
            size_t serdes_index = 0;
            if (m_serdes_speed == la_mac_port::port_speed_e::E_50G) {
                // 50G serdes have 2 fec lanes per fec engine
                serdes_sym_err_count = sym_lane_counter.lane_errors[i - 1] + sym_lane_counter.lane_errors[i];
                serdes_index = (i - 1) / fec_lanes_per_serdes;
            } else {
                // 25G serdes have one fec lane per fec engine
                serdes_sym_err_count = sym_lane_counter.lane_errors[i - 1];
                serdes_index = i - 1;
            }

            double total_symbols_per_serdes_lane = (double)total_symbols / (double)m_serdes_count;
            double ser = (double)serdes_sym_err_count / total_symbols_per_serdes_lane;

            json_t* serdes_index_sym_err_root = json_object();
            json_object_set_new(serdes_index_sym_err_root, "symbol_err_counter", json_integer(serdes_sym_err_count));
            json_object_set_new(serdes_index_sym_err_root, "SER", json_real(ser));

            std::string serdes_index_label = "index_" + std::to_string(serdes_index);
            json_object_set_new(symbol_errors_root, serdes_index_label.c_str(), serdes_index_sym_err_root);
        }

        json_t* symbol_bursts_array = json_array();
        // first two values in symbol_burst are always equal to 0
        for (la_uint64_t i = 2; i < la_mac_port::MAX_RS_FEC_BURST; i++) {
            json_array_append_new(symbol_bursts_array, json_integer(fec_counter.symbol_burst[i]));
        }

        double extrapolated_ber = fec_counter.extrapolated_ber;
        double frame_loss_rate = fec_counter.extrapolated_flr;
        double frame_loss_accuracy_percentage = fec_counter.flr_r * 100.0;
        la_uint64_t uncorrectable_codewords = fec_counter.codeword_uncorrectable;

        json_object_set_new(fec_status_root, "codeword", codeword_array);
        json_object_set_new(fec_status_root, "symbol_burst", symbol_bursts_array);
        json_object_set_new(fec_status_root, "symbol_errors_per_lane", symbol_errors_root);
        json_object_set_new(fec_status_root, "extrapolated_ber", json_real(extrapolated_ber));
        json_object_set_new(fec_status_root, "uncorrectable_codewords", json_integer(uncorrectable_codewords));
        json_object_set_new(fec_status_root, "frame_loss_rate", json_real(frame_loss_rate));
        json_object_set_new(fec_status_root, "frame_loss_rate_accuracy", json_real(frame_loss_accuracy_percentage));
    }

    // Append to parent and "loose" reference to the locally created json object.
    json_object_set_new(parent, "fec_status", fec_status_root);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::add_mac_port_status(json_t* parent)
{
    la_status status;
    bool clear_counter = false;
    size_t pcs_ber = 0;
    status = read_counter(clear_counter, la_mac_port::counter_e::PCS_BER, pcs_ber);
    return_on_error(status);

    size_t pcs_block_err = 0;
    status = read_counter(clear_counter, la_mac_port::counter_e::PCS_BLOCK_ERROR, pcs_block_err);
    return_on_error(status);

    la_mac_port::mac_status mac_status{};
    status = read_mac_status(mac_status);
    return_on_error(status);

    bool tune_status;
    status = get_tune_status(tune_status);
    return_on_error(status);

    bool link_state = mac_status.link_state;
    bool pcs_status = mac_status.pcs_status;
    bool high_ber = mac_status.high_ber;

    json_t* am_lock_array = json_array();
    la_uint_t max_pcs_lanes = m_pcs_lanes_per_mac_lane * m_mac_lanes_count;
    for (la_uint_t i = 0; i < max_pcs_lanes; i++) {
        json_array_append_new(am_lock_array, json_boolean(mac_status.am_lock[i]));
    }

    json_t* mac_pcs_lanes_array = json_array();
    la_mac_port::mac_pcs_lane_mapping pcs_lane_mapping{};
    read_mac_pcs_lane_mapping(pcs_lane_mapping);
    for (la_uint_t i = 0; i < m_mac_lanes_count * m_pcs_lanes_per_mac_lane; i++) {
        json_array_append_new(mac_pcs_lanes_array, json_integer(pcs_lane_mapping.lane_map[i]));
    }

    json_t* mac_port_status_root = json_object();
    json_object_set_new(mac_port_status_root, "am_lock", am_lock_array);
    json_object_set_new(mac_port_status_root, "high_ber", json_boolean(high_ber));
    json_object_set_new(mac_port_status_root, "link_state", json_boolean(link_state));
    json_object_set_new(mac_port_status_root, "mac_pcs_lane_mapping", mac_pcs_lanes_array);
    json_object_set_new(mac_port_status_root, "pcs_ber", json_integer(pcs_ber));
    json_object_set_new(mac_port_status_root, "pcs_block_err", json_integer(pcs_block_err));
    json_object_set_new(mac_port_status_root, "pcs_status", json_boolean(pcs_status));
    json_object_set_new(mac_port_status_root, "tune_status", json_boolean(tune_status));

    // Append to parent and "loose" reference to the locally created json object.
    json_object_set_new(parent, "mac_port_status", mac_port_status_root);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::add_mib_counters(json_t* parent)
{
    bool clear = false;
    la_mac_port::mib_counters counter{};
    la_status status = LA_STATUS_SUCCESS;

    status = read_mib_counters(clear, counter);
    return_on_error(status);

    json_t* mib_counter_root = json_object();
    json_object_set_new(mib_counter_root, "tx_frames_ok", json_integer(counter.tx_frames_ok));
    json_object_set_new(mib_counter_root, "tx_bytes_ok", json_integer(counter.tx_bytes_ok));
    json_object_set_new(mib_counter_root, "tx_64b_frames", json_integer(counter.tx_64b_frames));
    json_object_set_new(mib_counter_root, "tx_65to127b_frames", json_integer(counter.tx_65to127b_frames));
    json_object_set_new(mib_counter_root, "tx_128to255b_frames", json_integer(counter.tx_128to255b_frames));
    json_object_set_new(mib_counter_root, "tx_256to511b_frames", json_integer(counter.tx_256to511b_frames));
    json_object_set_new(mib_counter_root, "tx_512to1023b_frames", json_integer(counter.tx_512to1023b_frames));
    json_object_set_new(mib_counter_root, "tx_1024to1518b_frames", json_integer(counter.tx_1024to1518b_frames));
    json_object_set_new(mib_counter_root, "tx_1519to2500b_frames", json_integer(counter.tx_1519to2500b_frames));
    json_object_set_new(mib_counter_root, "tx_2501to9000b_frames", json_integer(counter.tx_2501to9000b_frames));
    json_object_set_new(mib_counter_root, "tx_crc_errors", json_integer(counter.tx_crc_errors));
    json_object_set_new(mib_counter_root, "tx_mac_missing_eop_err", json_integer(counter.tx_mac_missing_eop_err));
    json_object_set_new(mib_counter_root, "tx_mac_underrun_err", json_integer(counter.tx_mac_underrun_err));
    json_object_set_new(mib_counter_root, "tx_mac_fc_frames_ok", json_integer(counter.tx_mac_fc_frames_ok));
    json_object_set_new(mib_counter_root, "tx_oob_mac_frames_ok", json_integer(counter.tx_oob_mac_frames_ok));
    json_object_set_new(mib_counter_root, "tx_oob_mac_crc_err", json_integer(counter.tx_oob_mac_crc_err));
    json_object_set_new(mib_counter_root, "rx_frames_ok", json_integer(counter.rx_frames_ok));
    json_object_set_new(mib_counter_root, "rx_bytes_ok", json_integer(counter.rx_bytes_ok));
    json_object_set_new(mib_counter_root, "rx_64b_frames", json_integer(counter.rx_64b_frames));
    json_object_set_new(mib_counter_root, "rx_65to127b_frames", json_integer(counter.rx_65to127b_frames));
    json_object_set_new(mib_counter_root, "rx_128to255b_frames", json_integer(counter.rx_128to255b_frames));
    json_object_set_new(mib_counter_root, "rx_256to511b_frames", json_integer(counter.rx_256to511b_frames));
    json_object_set_new(mib_counter_root, "rx_512to1023b_frames", json_integer(counter.rx_512to1023b_frames));
    json_object_set_new(mib_counter_root, "rx_1024to1518b_frames", json_integer(counter.rx_1024to1518b_frames));
    json_object_set_new(mib_counter_root, "rx_1519to2500b_frames", json_integer(counter.rx_1519to2500b_frames));
    json_object_set_new(mib_counter_root, "rx_2501to9000b_frames", json_integer(counter.rx_2501to9000b_frames));
    json_object_set_new(mib_counter_root, "rx_mac_invert", json_integer(counter.rx_mac_invert));
    json_object_set_new(mib_counter_root, "rx_crc_errors", json_integer(counter.rx_crc_errors));
    json_object_set_new(mib_counter_root, "rx_oversize_err", json_integer(counter.rx_oversize_err));
    json_object_set_new(mib_counter_root, "rx_undersize_err", json_integer(counter.rx_undersize_err));
    json_object_set_new(mib_counter_root, "rx_mac_code_err", json_integer(counter.rx_mac_code_err));
    json_object_set_new(mib_counter_root, "rx_mac_fc_frames_ok", json_integer(counter.rx_mac_fc_frames_ok));
    json_object_set_new(mib_counter_root, "rx_oob_mac_frames_ok", json_integer(counter.rx_oob_mac_frames_ok));
    json_object_set_new(mib_counter_root, "rx_oob_mac_invert_crc", json_integer(counter.rx_oob_mac_invert_crc));
    json_object_set_new(mib_counter_root, "rx_oob_mac_crc_err", json_integer(counter.rx_oob_mac_crc_err));
    json_object_set_new(mib_counter_root, "rx_oob_mac_code_err", json_integer(counter.rx_oob_mac_code_err));

    // Append to parent and "loose" reference to the locally created json object.
    json_object_set_new(parent, "mib_counters", mib_counter_root);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::activate()
{
    la_status stat;
    if (is_port_in_test_mode()) {
        log_warning(MAC_PORT,
                    "Port Serdes link(s) was in test mode Slice/IFG/SerDes %d/%d/%d. Reverting to link mode.",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id);
        // Clear any serdes_test_mode.
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            m_serdes_lane_tx_test_mode[serdes] = la_mac_port::serdes_test_mode_e::NONE;
            m_serdes_lane_rx_test_mode[serdes] = la_mac_port::serdes_test_mode_e::NONE;
        }
    }

    m_tune_with_pcs_lock = 0;

    if (is_serdes_mode_off() || m_device->is_simulated_or_emulated_device()) {
        // Nothing else to do
        set_state(la_mac_port::state_e::TUNED);
        m_tune_finish_time = chrono::steady_clock::now();
        stat = enable_mac_rx();
        return_on_error(stat);

        return LA_STATUS_SUCCESS;
    }

    // other loopback modes: NONE, PMA/MII SERDES Clock, PMA REMOTE, SERDES

    stopwatch sw_verify, sw_init;

    if (!m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        sw_verify.start();
        stat = m_serdes_handler->verify_firmware();
        sw_verify.stop();
    }

    return_on_error(stat);

    if (m_is_an_enabled) {
        stat = m_serdes_handler->reset();
        return_on_error(stat);
    }

    sw_init.start();
    stat = m_serdes_handler->init();
    sw_init.stop();
    return_on_error(stat);

    if (!m_is_an_enabled && !is_serdes_mode_dummy() && (m_loopback_mode != la_mac_port::loopback_mode_e::SERDES)) {
        // NOTE: Tx output_enable will be 0, but Tx and Rx enable will both be '1' due to init()
        // TODO: Move it after la_mac_port::reset() which is done in la_mac_port::activate()
        stat = m_serdes_handler->enable_tx(true);
        return_on_error(stat);
    }

    uint64_t verify = sw_verify.get_interval_time(stopwatch::time_unit_e::MS);
    uint64_t init = sw_init.get_interval_time(stopwatch::time_unit_e::MS);
    log_debug(MAC_PORT, "%s Activate times: verify %zd, init %zd", this->to_string().c_str(), (size_t)verify, (size_t)init);

    set_state(la_mac_port::state_e::ACTIVE);

    if (is_serdes_mode_dummy()) {
        // Currently, not doing anything else. May require SerDes activation.
        set_state(la_mac_port::state_e::TUNED);
        m_tune_finish_time = chrono::steady_clock::now();
        stat = enable_mac_rx();
        return_on_error(stat);

        return LA_STATUS_SUCCESS;
    }

    if (!m_link_management_enabled) {
        log_debug(MAC_PORT, "%s: done, link_management_enabled=false", __func__);
        return LA_STATUS_SUCCESS;
    }

    if (m_loopback_mode == la_mac_port::loopback_mode_e::NONE) {
        if (m_is_an_enabled) {
            m_tune_with_pcs_lock = 0;
            stat = an_start();
            return_on_error(stat);
        } else {
            stat = start_wait_for_peer();
            return_on_error(stat);
        }
    } else {
        // REMOTE or SERDES
        stat = tune();
        return_on_error(stat, MAC_PORT, ERROR, "%s activate start tune SerDes -> %d", this->to_string().c_str(), stat.value());
    }
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::an_start()
{
    la_status stat = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->update_anlt_order(m_serdes_base_id, m_serdes_count);
    return_on_error(stat);
    la_mac_port::state_e state;
    stat = m_serdes_handler->an_start(state);
    return_on_error(stat);

    set_state(state);
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_serdes_signal_ok(la_uint_t serdes_idx, bool& out_signal_ok)
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_signal_ok = false;

    size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source;

    if (m_port_state == la_mac_port::state_e::TUNED) {
        la_mac_port::serdes_status serdes_status;
        la_status stat = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->read_serdes_status(rx_serdes, serdes_status);
        out_signal_ok = serdes_status.signal_ok;
        return_on_error(stat);

        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::tune()
{
    if ((m_port_state == la_mac_port::state_e::PRE_INIT) || (m_port_state == la_mac_port::state_e::INACTIVE)) {
        return LA_STATUS_EINVAL;
    }

    log_debug(
        MAC_PORT, "%s: is_an_enabled=%d, is_link_management_enabled=%d", __func__, m_is_an_enabled, is_link_management_enabled());

    la_status stat;

    if (!m_is_an_enabled
        && ((m_loopback_mode == la_mac_port::loopback_mode_e::NONE) || (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_PMA)
            || m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES)) {
        stat = stop_wait_for_peer();
        return_on_error(stat);
    }

    // In GB, when a 50G mac_port was torn down and created with 10G/25G port, some ports do not link up.
    // This is seen in ANLT and non-ANLT cases.  Apply rx_pma_reset here to handle both cases.
    // In GB, rx_pma_reset is applied but other ASICs will be no-op in the function.
    pre_tune_rx_pma_reset();

    set_state(la_mac_port::state_e::TUNING);

    m_tune_start_time = chrono::steady_clock::now();
    m_tune_timeout_informed = false;

    if (!is_link_management_enabled()) {
        stat = enable_mac_rx();
        return_on_error(stat);
    }

    if (!is_serdes_mode_active() || m_device->is_simulated_or_emulated_device()) {
        set_state(la_mac_port::state_e::TUNED);
        return LA_STATUS_SUCCESS;
    }

    stat = m_serdes_handler->tune();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_tune_status(bool& out_completed)
{
    out_completed = false;
    if (m_port_state >= la_mac_port::state_e::TUNED) {
        out_completed = true;
    }

    if (is_link_management_enabled()) {
        return LA_STATUS_SUCCESS;
    }

    // This is required in case link management is not enabled to upgrade the state.
    return is_tune_completed(out_completed);
}

la_status
mac_pool_port::poll_mac_up(bool& out_completed)
{
    out_completed = false;

    if (!is_link_management_enabled()) {
        // Don't do anything, just check link status.
        la_mac_port::mac_status mac_status;
        la_status stat = read_mac_status(mac_status);
        return_on_error(stat);

        out_completed = mac_status.link_state;

        return LA_STATUS_SUCCESS;
    }

    la_mac_port::state_e start_state;

    do {
        bool completed;
        la_status stat;
        start_state = m_port_state;

        switch (m_port_state) {
        case la_mac_port::state_e::PRE_INIT:
        case la_mac_port::state_e::INACTIVE:
            return LA_STATUS_SUCCESS;
        case la_mac_port::state_e::PCAL_STOP:
            stat = poll_start_state_machine();
            break;
        case la_mac_port::state_e::AN_BASE_PAGE:
            stat = an_base_page_rcv();
            break;
        case la_mac_port::state_e::AN_NEXT_PAGE:
            stat = an_next_page_rcv();
            break;
        case la_mac_port::state_e::AN_POLL:
            stat = an_handler();
            break;
        case la_mac_port::state_e::LINK_TRAINING:
            stat = link_training_handler();
            break;
        case la_mac_port::state_e::AN_COMPLETE:
            stat = is_an_completed(completed);
            break;
        case la_mac_port::state_e::ACTIVE:
            return LA_STATUS_SUCCESS;
        case la_mac_port::state_e::WAITING_FOR_PEER:
            stat = is_peer_detected(completed);
            break;
        case la_mac_port::state_e::TUNING:
            stat = is_tune_completed(completed);
            break;
        case la_mac_port::state_e::TUNED:
            stat = is_rx_ready(completed);
            break;
        case la_mac_port::state_e::PCS_LOCK:
            stat = is_pcs_stable(completed);
            break;
        case la_mac_port::state_e::PCS_STABLE:
            stat = is_link_up(out_completed);
            break;
        case la_mac_port::state_e::LINK_UP:
            out_completed = true;
            stat = ready_delayed_interrupt_mask();
            break;
        }

        if (stat) {
            return stat;
        }

    } while (m_port_state > start_state);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::restart_state_machine()
{
    la_status stat = disable_mac_rx();
    return_on_error(stat);

    stat = m_serdes_handler->enable_low_power(false);
    return_on_error(stat);

    stat = m_serdes_handler->periodic_tune_stop();
    return_on_error(stat);

    set_state(la_mac_port::state_e::PCAL_STOP);

    m_pcal_stop_start_time = chrono::steady_clock::now();
    m_pcal_stop_rx_disabled = false;

    return stat;
}

la_status
mac_pool_port::poll_start_state_machine()
{
    bool pcal_stopped = false;
    la_status stat = m_serdes_handler->is_periodic_tune_stopped(pcal_stopped);
    return_on_error(stat);

    if (!pcal_stopped) {
        auto pcal_stop_span = chrono::steady_clock::now() - m_pcal_stop_start_time;
        if (pcal_stop_span > chrono::seconds(MAX_PCAL_STOP_TIMEOUT)) {
            if (!m_pcal_stop_rx_disabled) {
                m_serdes_handler->enable_rx(false);
                m_pcal_stop_rx_disabled = true;
            }
            log_debug(MAC_PORT,
                      "%s: Issued disabling RX after PCAL_STOP on Serdes %d/%d/%d.",
                      __func__,
                      m_slice_id,
                      m_ifg_id,
                      m_serdes_base_id);
        }
        return LA_STATUS_SUCCESS;
    }

    if (m_is_an_enabled) {
        stat = activate();
    } else {
        stat = start_wait_for_peer();
    }

    return stat;
}

la_status
mac_pool_port::set_reset(la_mac_port_base::mac_reset_state_e state)
{
    la_status stat;
    // for LB signal ok override should be kept as is
    if (m_loopback_mode == la_mac_port::loopback_mode_e::NONE) {
        stat = set_sig_ok_overide(true /* enable */, false /* value */);
        return_on_error(stat);
    }

    stat = set_tx_reset(state);
    return_on_error(stat);
    stat = set_rx_reset(state);
    return_on_error(stat);

    if (m_loopback_mode == la_mac_port::loopback_mode_e::NONE) {
        stat = set_sig_ok_overide(false /* enable */, true /* value */);
        return_on_error(stat);

        // Clear & enable signal OK interrupt
        stat = clear_signal_ok_interrupt();
        return_on_error(stat);
    }

    return stat;
}

la_status
mac_pool_port::stop()
{
    m_bad_tunes = 0;
    m_pcs_stable_timestamp = m_pcs_stable_timestamp.min();
    if (is_port_in_test_mode()) {
        log_warning(
            MAC_PORT, "Port Serdes link(s) are in test mode Slice/IFG/SerDes %d/%d/%d.", m_slice_id, m_ifg_id, m_serdes_base_id);
    }

    if (is_network_slice(m_port_slice_mode) || m_device->m_ll_device->get_device_revision() != la_device_revision_e::PACIFIC_A0) {
        la_status stat = set_reset(la_mac_port_base::mac_reset_state_e::RESET_ALL);
        return_on_error(stat);
    } else {
        la_status stat = set_reset_fabric_port_pacific_a0(la_mac_port_base::mac_reset_state_e::RESET_ALL);
        return_on_error(stat);
    }

    if (is_serdes_mode_off() || m_device->is_simulated_or_emulated_device()) {
        // Nothing else to do
        set_state(la_mac_port::state_e::INACTIVE);
        return LA_STATUS_SUCCESS;
    }

    if (m_port_state == la_mac_port::state_e::PRE_INIT) {
        // The port wasn't activated -> invalid to shutdown.
        return LA_STATUS_EINVAL;
    }

    if (m_is_an_enabled && is_an_stop_valid()) {
        // perform an stop procedure for states when an may be on
        la_status stat = m_serdes_handler->an_stop();
        return_on_error(stat);
    }

    if (m_port_state == la_mac_port::state_e::INACTIVE) {
        // The port is already stopped, nothing to do.
        return LA_STATUS_SUCCESS;
    }

    la_status stat = m_serdes_handler->enable_low_power(false);
    return_on_error(stat);

    stat = m_serdes_handler->periodic_tune_stop();
    return_on_error(stat);

    stat = m_serdes_handler->stop();
    return_on_error(stat);

    set_state(la_mac_port::state_e::INACTIVE);

    return LA_STATUS_SUCCESS;
}

la_slice_id_t
mac_pool_port::get_slice() const
{
    return m_slice_id;
}

la_ifg_id_t
mac_pool_port::get_ifg() const
{
    return m_ifg_id;
}

la_uint_t
mac_pool_port::get_first_serdes_id() const
{
    return m_serdes_base_id;
}

size_t
mac_pool_port::get_num_of_serdes() const
{
    return m_serdes_count;
}

la_status
mac_pool_port::read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) const
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source;

    la_status status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->read_serdes_status(rx_serdes, out_serdes_status);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_interrupt_mask(std::vector<lld_register_scptr>& regs, bool enable_interrupt) const
{
    uint64_t mask = get_mac_pool_interrupt_mask();
    bit_vector mask_bv(mask);

    const auto& interrupt_tree = m_device->get_notificator()->get_interrupt_tree();
    la_status rc;
    for (size_t i = 0; i < regs.size(); i++) {
        // If interrupt is disabled, it is also removed from interrupt dampening pool.
        rc = interrupt_tree->set_interrupt_enabled(regs[i], mask_bv, enable_interrupt, false /* clear */);
        return_on_error(rc);
    }
    // Special handling for ptp_time_stamp_error
    rc = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_mac_link_error_interrupt_mask(
        m_serdes_base_id, m_serdes_count, enable_interrupt);
    return_on_error(rc);
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::clear_interrupt(std::vector<lld_register_scptr>& regs) const
{
    la_status status;
    uint64_t mask = get_mac_pool_interrupt_mask();
    bit_vector mask_bv(mask);

    const auto& interrupt_tree = m_device->get_notificator()->get_interrupt_tree();
    la_status rc;
    for (size_t i = 0; i < regs.size(); i++) {
        rc = interrupt_tree->clear_interrupt(regs[i], mask_bv);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

uint64_t
mac_pool_port::get_mac_pool_interrupt_mask() const
{
    size_t lsb = m_mac_lane_index_in_mac_pool;
    size_t msb = lsb + m_mac_lanes_count - 1;
    uint64_t mask = bit_utils::set_bits(0, msb, lsb, -1ULL);

    return mask;
}

la_status
mac_pool_port::check_link_down_info_rx_deskew_fifo_overflow(link_down_interrupt_info link_down_info, bool& overflow) const
{
    // Check rx deskew fifo overflow failures
    for (int i = 0; i < la_mac_port_max_lanes_e::PCS; i++) {
        if (link_down_info.rx_deskew_fifo_overflow[i]) {
            overflow = true;
            return LA_STATUS_SUCCESS;
        }
    }
    overflow = false;
    return LA_STATUS_SUCCESS;
}

static void
linear_regress(std::vector<double> x, std::vector<double> y, double& out_a, double& out_b, double& out_r)
{
    size_t n = x.size();
    if (n == 1) {
        out_a = 0;
        out_b = y[0];
        out_r = 1;
        return;
    }

    const auto sum_x = std::accumulate(x.begin(), x.end(), 0.0);
    const auto sum_y = std::accumulate(y.begin(), y.end(), 0.0);
    const auto sum_xx = std::inner_product(x.begin(), x.end(), x.begin(), 0.0);
    const auto sum_yy = std::inner_product(y.begin(), y.end(), y.begin(), 0.0);
    const auto sum_xy = std::inner_product(x.begin(), x.end(), y.begin(), 0.0);
    out_a = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x * sum_x);
    out_b = (sum_y - out_a * sum_x) / n;
    out_r = abs((n * sum_xy - sum_x * sum_y) / sqrt((n * sum_xx - sum_x * sum_x) * (n * sum_yy - sum_y * sum_y)));
}

void
mac_pool_port::calculate_flr(la_uint64_t codeword[], la_uint64_t total_codewords, double& extrapolated_flr, double& flr_r) const
{
    std::vector<double> ber_cw_index_arr;
    std::vector<double> ber_log_arr;
    size_t max_non_zero_id = 0;
    for (size_t i = 1; i < la_mac_port::MAX_RS_FEC_CW_SYMBOLS; i++) {
        if (codeword[i] != 0) {
            max_non_zero_id = i;
        }
    }

    for (size_t i = 1; i <= max_non_zero_id; i++) {
        ber_cw_index_arr.push_back(i);
        // when codword[i]=0 the log is undefined -> 1 is chosen as the nearest minimal number of cw_errs 0
        size_t codeword_errs = max(codeword[i], 1ULL);
        ber_log_arr.push_back(log10(static_cast<double>(codeword_errs) / static_cast<double>(total_codewords)));
    }

    double slope = 0, intercept = 0;
    extrapolated_flr = 0;
    flr_r = 0;
    if (ber_cw_index_arr.size() > 1) {
        linear_regress(ber_cw_index_arr, ber_log_arr, slope, intercept, flr_r);
        uint ucw_symbols_cnt
            = (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4) ? RS_FEC_KR4_UCW_SYMBOLS_CNT : RS_FEC_KP4_UCW_SYMBOLS_CNT;
        extrapolated_flr = pow(10, ucw_symbols_cnt * slope + intercept);
    }
}

la_uint64_t
mac_pool_port::get_codewords_sum(la_uint64_t codewords[], size_t size) const
{
    la_uint64_t sum = 0;

    for (size_t index = 0; index < size; index++) {
        sum += codewords[index];
    }

    return sum;
}

la_uint64_t
mac_pool_port::get_symbol_errors_sum(la_uint64_t codewords[], size_t size) const
{
    la_uint64_t sum = 0;

    for (size_t index = 0; index < size; index++) {
        sum += index * codewords[index];
    }

    return sum;
}

la_status
mac_pool_port::read_ostc_counter(la_over_subscription_tc_t ostc, size_t& out_dropped_packets) const
{
    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->read_ostc_counter(m_mac_lane_index_in_ifgb, ostc, out_dropped_packets);
}

la_status
mac_pool_port::reconfigure(size_t num_of_serdes,
                           la_mac_port::port_speed_e speed,
                           la_mac_port::fc_mode_e rx_fc_mode,
                           la_mac_port::fc_mode_e tx_fc_mode,
                           la_mac_port::fec_mode_e fec_mode)
{
    int property_value;
    la_status status = m_device->get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, property_value);
    return_on_error(status);
    if (property_value > 1) {
        // port reconfiure not yet implemented on Matilda devices.
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    // Reconfigure mac port using the initialize()
    // All checks are done in initialize(), includes is_valid_config(), etc.

    // save packet_size; CSCvp30151 fix: User may update packet_size and reconfigure() should not reset the packet_size to default.
    la_uint_t min_size;
    la_uint_t max_size;
    la_status stat = get_packet_sizes(min_size, max_size);
    return_on_error(stat);

    la_mac_port::loopback_mode_e loopback_mode;
    stat = get_loopback_mode(loopback_mode);
    return_on_error(stat);

    stat = reset_ifgb();
    return_on_error(stat);

    stat = reset_rs_fec_config();
    return_on_error(stat);

    stat = reset_rx_krf_config();
    return_on_error(stat);

    stat = destroy_general_config();
    return_on_error(stat);

    stat = initialize(m_slice_id,
                      m_ifg_id,
                      m_serdes_base_id,
                      num_of_serdes,
                      speed,
                      rx_fc_mode,
                      tx_fc_mode,
                      fec_mode,
                      m_mlp_mode,
                      m_port_slice_mode);
    return_on_error(stat);

    // restore packet_size after re-initialize the mac_port.
    stat = set_packet_sizes(min_size, max_size);
    return_on_error(stat);

    stat = set_loopback_mode(loopback_mode);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_speed;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_speed(la_mac_port::port_speed_e speed)
{
    if (m_device->m_device_port_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (!m_device->m_device_port_handler->is_valid_config(speed, m_serdes_count, m_fec_mode)) {
        return LA_STATUS_EINVAL;
    }

    if (m_port_state != la_mac_port::state_e::PRE_INIT && m_port_state != la_mac_port::state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    m_speed = speed;
    update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::SPEED, (uint8_t)speed);

    la_status stat = recalc_data_members();
    return_on_error(stat);
    stat = update_general_config();
    return_on_error(stat);

    stat = configure_ber_fsm();
    return_on_error(stat);

    stat = configure_info_phy();
    return stat;
}

la_status
mac_pool_port::get_serdes_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_serdes_speed;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_fec_mode(la_mac_port::fec_mode_e& out_fec_mode) const
{
    out_fec_mode = m_fec_mode;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_fec_mode(la_mac_port::fec_mode_e fec_mode)
{
    if (m_device->m_device_port_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (!m_device->m_device_port_handler->is_valid_config(m_speed, m_serdes_count, fec_mode)) {
        return LA_STATUS_EINVAL;
    }

    if (m_port_state != la_mac_port::state_e::PRE_INIT && m_port_state != la_mac_port::state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    m_fec_mode = fec_mode;
    update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::FEC_MODE, (uint8_t)fec_mode);

    la_status stat = recalc_data_members();
    return_on_error(stat);
    stat = update_general_config();
    return_on_error(stat);

    stat = reset_mac_config();
    return_on_error(stat);

    stat = configure_degraded_ser();
    return_on_error(stat);

    stat = update_rs_fec_config();
    return_on_error(stat);

    stat = update_rx_krf_config();
    return_on_error(stat);

    stat = configure_loopback_mode();
    return_on_error(stat);

    stat = configure_info_phy();
    return stat;
}

la_status
mac_pool_port::get_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e& out_fc_mode) const
{
    la_status stat = LA_STATUS_SUCCESS;

    switch (fc_dir) {
    case la_mac_port::fc_direction_e::RX:
        out_fc_mode = m_rx_fc_mode;
        break;
    case la_mac_port::fc_direction_e::TX:
        out_fc_mode = m_tx_fc_mode;
        break;
    case la_mac_port::fc_direction_e::BIDIR:
        if (m_rx_fc_mode == m_tx_fc_mode) {
            out_fc_mode = m_rx_fc_mode;
        } else {
            /* rx and tx modes are different, return invalid */
            stat = LA_STATUS_EINVAL;
        }
        break;
    }

    return stat;
}

la_status
mac_pool_port::set_fc_rx_term_mode(bool terminate)
{
    m_rx_fc_term_mode = terminate;

    la_status stat = reset_mac_config();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_fc_rx_term_mode(bool& terminate) const
{
    terminate = m_rx_fc_term_mode;

    return LA_STATUS_SUCCESS;
}

la_interface_scheduler*
mac_pool_port::get_scheduler() const
{
    return nullptr;
}

la_status
mac_pool_port::get_min_packet_size(la_uint_t& out_min_size) const
{
    la_uint_t min_size;
    la_uint_t max_size;
    la_status stat = get_packet_sizes(min_size, max_size);
    return_on_error(stat);

    out_min_size = min_size;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_min_packet_size(la_uint_t min_size)
{
    la_uint_t min_supported_size;
    la_status stat = get_min_supported_packet_size(min_supported_size);
    if (stat != LA_STATUS_SUCCESS) {
        return stat;
    }
    if (min_size < min_supported_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t old_min_size;
    la_uint_t max_size;
    stat = get_packet_sizes(old_min_size, max_size);
    return_on_error(stat);

    stat = set_packet_sizes(min_size, max_size);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_max_packet_size(la_uint_t& out_max_size) const
{
    la_uint_t min_size;
    la_uint_t max_size;
    la_status stat = get_packet_sizes(min_size, max_size);
    return_on_error(stat);

    out_max_size = max_size;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_max_supported_packet_size(la_uint_t& out_max_size) const
{
    la_uint_t max_supported_size;
    if (is_network_slice(m_port_slice_mode)) {
        if (m_device->m_device_mode != device_mode_e::STANDALONE) {
            max_supported_size = MAX_NETWORK_PORT_PACKET_SIZE;
        } else {
            max_supported_size = MAX_STANDALONE_PORT_PACKET_SIZE;
        }
    } else {
        max_supported_size = MAX_FABRIC_PORT_PACKET_SIZE;
    }

    out_max_size = max_supported_size;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_min_supported_packet_size(la_uint_t& out_min_size) const
{
    la_uint_t min_supported_size;
    if (is_network_slice(m_port_slice_mode)) {
        min_supported_size = 64;
    } else {
        min_supported_size = 63;
    }

    out_min_size = min_supported_size;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_max_packet_size(la_uint_t max_size)
{
    la_uint_t max_supported_size;
    la_status stat = get_max_supported_packet_size(max_supported_size);
    if (stat != LA_STATUS_SUCCESS) {
        return stat;
    }

    if (max_size > max_supported_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t min_size;
    la_uint_t old_max_size;
    stat = get_packet_sizes(min_size, old_max_size);
    return_on_error(stat);

    stat = set_packet_sizes(min_size, max_size);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_fec_bypass_mode(la_mac_port::fec_bypass_e& out_fec_bp) const
{
    out_fec_bp = m_fec_bypass;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_fec_bypass_mode(la_mac_port::fec_bypass_e fec_bp)
{
    if (m_port_state != la_mac_port::state_e::PRE_INIT && m_port_state != la_mac_port::state_e::INACTIVE) {
        log_err(MAC_PORT, "%s : %s Port must be in reset", __func__, this->to_string().c_str());
        return LA_STATUS_EBUSY;
    }

    m_fec_bypass = fec_bp;
    update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::FEC_BYPASS_MODE, (uint8_t)fec_bp);

    la_status stat = recalc_data_members();
    return_on_error(stat);

    stat = update_general_config();
    return_on_error(stat);

    stat = update_rs_fec_config();
    return_on_error(stat);

    return stat;
}

la_status
mac_pool_port::get_preamble_compression_enabled(bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::set_preamble_compression_enabled(bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode)
{
    la_status stat;
    bool update_ifg = true;

    // for an RX direction update ensure the update is compatible
    if (fc_dir == la_mac_port::fc_direction_e::RX) {
        // ensure the modes are the same if they are not NONE
        if ((fc_mode != la_mac_port::fc_mode_e::NONE) && (m_tx_fc_mode != la_mac_port::fc_mode_e::NONE)
            && (fc_mode != m_tx_fc_mode)) {
            return LA_STATUS_EINVAL;
        }

        // check if we are disabling RX but TX is still enabled
        if ((fc_mode == la_mac_port::fc_mode_e::NONE) && (m_tx_fc_mode != la_mac_port::fc_mode_e::NONE)) {
            update_ifg = false;
        }
    }

    // for a TX direction update ensure the update is compatible
    if (fc_dir == la_mac_port::fc_direction_e::TX) {
        // ensure the modes are the same if they are not NONE
        if ((fc_mode != la_mac_port::fc_mode_e::NONE) && (m_rx_fc_mode != la_mac_port::fc_mode_e::NONE)
            && (fc_mode != m_tx_fc_mode)) {
            return LA_STATUS_EINVAL;
        }

        // check if we are disabling TX but RX is still enabled
        if ((fc_mode == la_mac_port::fc_mode_e::NONE) && (m_tx_fc_mode != la_mac_port::fc_mode_e::NONE)) {
            update_ifg = false;
        }
    }

    if (update_ifg) {
        // set flow control on the IFG
        stat = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_fc_mode(
            m_mac_lane_index_in_ifgb, m_mac_lanes_reserved, m_speed, fc_mode);
        return_on_error(stat);
    }

    switch (fc_dir) {
    case la_mac_port::fc_direction_e::RX:
        m_rx_fc_mode = fc_mode;
        update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::RX_FC_MODE, (uint8_t)fc_mode);
        break;

    case la_mac_port::fc_direction_e::TX:
        m_tx_fc_mode = fc_mode;
        update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::TX_FC_MODE, (uint8_t)fc_mode);
        break;

    case la_mac_port::fc_direction_e::BIDIR:
        m_rx_fc_mode = fc_mode;
        m_tx_fc_mode = fc_mode;
        update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::RX_FC_MODE, (uint8_t)fc_mode);
        update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::TX_FC_MODE, (uint8_t)fc_mode);
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_loopback_mode(la_mac_port::loopback_mode_e& out_loopback_mode) const
{
    out_loopback_mode = m_loopback_mode;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_loopback_mode(la_mac_port::loopback_mode_e mode)
{
    if (m_is_an_enabled && mode != la_mac_port::loopback_mode_e::NONE) {
        log_err(MAC_PORT, "%s Unable to set loopback if AN is enabled. ", this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    if (!is_loopback_mode_supported(mode)) {
        return LA_STATUS_EINVAL;
    }

    m_loopback_mode = mode;
    update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::LOOPBACK_MODE, (uint8_t)mode);

    la_status stat = configure_loopback_mode();
    return_on_error(stat);

    if (m_device->is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    stat = m_serdes_handler->update_loopback_mode(m_loopback_mode);

    if ((m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES) || (mode == la_mac_port::loopback_mode_e::REMOTE_SERDES)
        || (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES)
        || (mode == la_mac_port::loopback_mode_e::SERDES)) {
        // Need to change SerDes configuration as well
        stat = m_serdes_handler->set_loopback_mode(m_loopback_mode);
        return_on_error(stat);
    }

    // Update info lanes configuration
    stat = configure_info_phy();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

bool
mac_pool_port::is_rx_lane_swapped()
{
    size_t last_serdes = m_serdes_base_id + m_serdes_count - 1;
    for (size_t serdes_lane = 0; serdes_lane < m_serdes_count; serdes_lane++) {
        size_t tx_serdes = m_serdes_base_id + serdes_lane;
        size_t rx_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
        if (rx_source < m_serdes_base_id || rx_source > last_serdes) {
            log_debug(MAC_PORT, "%s: Rx lanes are swapped.", this->to_string().c_str());
            return true;
        }
    }

    return false;
}

bool
mac_pool_port::is_an_stop_valid() const
{
    bool an_stop_valid = true;

    // This check is to perserve the fixes for CSCvq95732 (PR#3135).
    if (m_device->m_ll_device->is_pacific()) {
        an_stop_valid = !(m_port_state >= la_mac_port::state_e::TUNING && m_port_state <= la_mac_port::state_e::LINK_UP);
    }

    return an_stop_valid;
}

la_status
mac_pool_port::post_anlt_complete(const std::unique_ptr<serdes_handler>& serdes_handler_ptr)
{
    log_xdebug(MAC_PORT, "%s: Calling base function", __func__);
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::pre_tune_rx_pma_reset()
{
    log_xdebug(MAC_PORT, "%s: Calling base function", __func__);
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_link_management_enabled(bool& out_enabled) const
{
    out_enabled = m_link_management_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_link_management_enabled(bool enabled)
{
    if (m_link_management_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_link_management_enabled = enabled;
    update_mac_port(reconnect_metadata::fabric_mac_port::attr_e::LINK_MANAGEMENT_ENABLED, enabled);

    la_status stat = LA_STATUS_SUCCESS;
    if (m_port_state == la_mac_port::state_e::ACTIVE) {
        if (m_loopback_mode == la_mac_port::loopback_mode_e::NONE) {
            if (enabled) {
                stat = restart_state_machine();
            } else {
                stat = stop_wait_for_peer();
            }
        }
    }

    return stat;
}

la_status
mac_pool_port::get_pcs_test_mode(la_mac_port::pcs_test_mode_e& out_mode) const
{
    out_mode = m_pcs_test_mode;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_pcs_test_mode(la_mac_port::pcs_test_mode_e mode)
{
    if ((m_fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI) && (mode != la_mac_port::pcs_test_mode_e::NONE)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_pcs_test_mode = mode;

    la_status stat = configure_pcs_test_mode();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_pcs_test_seed(la_uint128_t& out_seed) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::set_pcs_test_seed(la_uint128_t seed)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::get_pma_test_mode(la_mac_port::pma_test_mode_e& out_mode) const
{
    out_mode = m_pma_test_mode;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_pma_test_mode(la_mac_port::pma_test_mode_e mode)
{
    m_pma_test_mode = mode;

    la_status stat = configure_pma_test_mode();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_pma_test_seed(la_uint128_t& out_seed) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::set_pma_test_seed(la_uint128_t seed)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool_port::get_serdes_test_mode(la_uint_t serdes_idx,
                                    la_serdes_direction_e direction,
                                    la_mac_port::serdes_test_mode_e& out_mode) const
{
    // Check if valid serdes_idx
    if (serdes_idx >= m_serdes_count) {
        log_err(SERDES, "SerDes Index: %u is out of expected range [0-%lu]", serdes_idx, (m_serdes_count - 1));
        return LA_STATUS_EOUTOFRANGE;
    }

    if (direction == la_serdes_direction_e::TX) {
        out_mode = m_serdes_lane_tx_test_mode[serdes_idx];
    } else {
        out_mode = m_serdes_lane_rx_test_mode[serdes_idx];
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_serdes_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    if (mode > la_mac_port::serdes_test_mode_e::LAST) {
        return LA_STATUS_EINVAL;
    }

    la_status stat = m_serdes_handler->set_test_mode(serdes_idx, direction, mode);
    return_on_error(stat);

    if (mode == la_mac_port::serdes_test_mode_e::NONE) {
        log_info(MAC_PORT,
                 "%s %s: to restore Mac link, use set_serdes_test_mode(la_mac_port::serdes_test_mode_e mode) to recover PMA Tx.",
                 __func__,
                 this->to_string().c_str());
    }

    if (direction == la_serdes_direction_e::TX) {
        m_serdes_lane_tx_test_mode[serdes_idx] = mode;
    } else {
        m_serdes_lane_rx_test_mode[serdes_idx] = mode;
    }

    // Change to tuned state, with no change to serdes
    set_state(la_mac_port::state_e::TUNED);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::get_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e& out_mode) const
{
    std::vector<la_mac_port::serdes_test_mode_e> serdes_lane_test_mode;

    if (direction == la_serdes_direction_e::TX) {
        serdes_lane_test_mode = m_serdes_lane_tx_test_mode;
    } else {
        serdes_lane_test_mode = m_serdes_lane_rx_test_mode;
    }

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        if (serdes_lane_test_mode[0] != serdes_lane_test_mode[serdes]) {
            log_err(SERDES, "Not all serdes in same test mode!");
            return LA_STATUS_ENOTFOUND;
        }
    }

    out_mode = serdes_lane_test_mode[0];

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    if (mode > la_mac_port::serdes_test_mode_e::LAST) {
        return LA_STATUS_EINVAL;
    }

    la_status stat = m_serdes_handler->set_test_mode(direction, mode);
    return_on_error(stat);

    if (mode == la_mac_port::serdes_test_mode_e::NONE) {
        stat = recover_pma_tx();
        return_on_error(stat);
    }

    if (direction == la_serdes_direction_e::TX) {
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            m_serdes_lane_tx_test_mode[serdes] = mode;
        }
    } else {
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            m_serdes_lane_rx_test_mode[serdes] = mode;
        }
    }

    // Change to tuned state, with no change to serdes
    set_state(la_mac_port::state_e::TUNED);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::read_serdes_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    if (m_device->is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    return m_serdes_handler->read_test_ber(serdes_idx, out_serdes_prbs_ber);
}

la_status
mac_pool_port::read_serdes_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    if (m_device->is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    return m_serdes_handler->read_test_ber(out_serdes_prbs_ber);
}

la_status
mac_pool_port::reset_packet_sizes()
{
    la_uint_t min_pkt_size, max_pkt_size;
    la_status stat = get_min_supported_packet_size(min_pkt_size);

    if (stat != LA_STATUS_SUCCESS) {
        return stat;
    }

    stat = get_max_supported_packet_size(max_pkt_size);

    if (stat != LA_STATUS_SUCCESS) {
        return stat;
    }

    return set_packet_sizes(min_pkt_size, max_pkt_size);
}

la_status
mac_pool_port::configure_info_phy()
{
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::configure_pma()
{
    device_port_handler_base::serdes_config_data config;
    m_device->m_device_port_handler->get_serdes_config(m_serdes_speed, config);

    return configure_pma(config);
}

la_status
mac_pool_port::configure_info_loopback_mode(npl_loopback_mode_e info_loopback_mode)
{
    if (info_loopback_mode != NPL_LOOPBACK_MODE_NONE) {
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::configure_loopback_mode()
{
    log_debug(
        MAC_PORT, "%s: %s loopback_mode=%s", __func__, this->to_string().c_str(), silicon_one::to_string(m_loopback_mode).c_str());

    npl_loopback_mode_e mii_loopback_mode;
    npl_loopback_mode_e pma_loopback_mode;
    npl_loopback_mode_e info_loopback_mode;

    mii_loopback_mode = NPL_LOOPBACK_MODE_NONE;
    pma_loopback_mode = NPL_LOOPBACK_MODE_NONE;
    info_loopback_mode = NPL_LOOPBACK_MODE_NONE;

    switch (m_loopback_mode) {

    case la_mac_port::loopback_mode_e::MII_CORE_CLK:
        // For MII loopback, in both cases configure it to SRDS but for core clock set the PMA in core clock loopback.
        mii_loopback_mode = NPL_LOOPBACK_MODE_SRDS_CLK;
        pma_loopback_mode = NPL_LOOPBACK_MODE_CORE_CLK;
        break;

    case la_mac_port::loopback_mode_e::MII_SRDS_CLK:
        mii_loopback_mode = NPL_LOOPBACK_MODE_SRDS_CLK;
        break;

    case la_mac_port::loopback_mode_e::PMA_CORE_CLK:
        pma_loopback_mode = NPL_LOOPBACK_MODE_CORE_CLK;
        break;

    case la_mac_port::loopback_mode_e::PMA_SRDS_CLK:
        pma_loopback_mode = NPL_LOOPBACK_MODE_SRDS_CLK;
        break;

    case la_mac_port::loopback_mode_e::INFO_MAC_CLK:
        info_loopback_mode = NPL_LOOPBACK_MODE_CORE_CLK;
        break;

    case la_mac_port::loopback_mode_e::INFO_SRDS_CLK:
        info_loopback_mode = NPL_LOOPBACK_MODE_SRDS_CLK;
        break;

    case la_mac_port::loopback_mode_e::REMOTE_PMA:
        pma_loopback_mode = NPL_LOOPBACK_MODE_REMOTE;
        break;

    default:
        break;
    }

    log_debug(MAC_PORT,
              "%s: %s NPL-based configuration, is_simulated_device=%d, is_emulated_device=%d, device_revision=%d",
              __func__,
              this->to_string().c_str(),
              (int)m_device->is_simulated_device(),
              (int)m_device->is_emulated_device(),
              (int)m_device->m_ll_device->get_device_revision());

    // TODO: GR - LB should go through NPL tables
    la_device_revision_e device_rev = m_device->m_ll_device->get_device_revision();
    if ((m_device->is_emulated_device() && device_rev != la_device_revision_e::ASIC3_A0)
        || (device_rev == la_device_revision_e::ASIC3_A0 && !m_device->is_simulated_device())) {
        la_status stat = configure_info_loopback_mode(info_loopback_mode);
        return_on_error(stat);

        stat = configure_loopback_mode(mii_loopback_mode, pma_loopback_mode);
        return_on_error(stat);
    } else {
        const auto& mii_table(m_device->m_tables.mii_loopback_table[m_slice_id]);
        npl_mii_loopback_table_key_t mii_key;
        npl_mii_loopback_table_value_t mii_value;
        npl_mii_loopback_table_entry_t* mii_entry = nullptr;

        mii_key.device_packet_info_ifg = m_ifg_id;
        mii_value.payloads.mii_loopback_data.mode = mii_loopback_mode;

        for (size_t i = 0; i < m_mac_lanes_count; i++) {
            mii_key.device_packet_info_pif = m_serdes_base_id + i;
            la_status status = mii_table->set(mii_key, mii_value, mii_entry);
            return_on_error(status);
        }

        const auto& pma_table(m_device->m_tables.pma_loopback_table[m_slice_id]);
        npl_pma_loopback_table_key_t pma_key;
        npl_pma_loopback_table_value_t pma_value;
        npl_pma_loopback_table_entry_t* pma_entry = nullptr;

        pma_key.device_packet_info_ifg = m_ifg_id;
        pma_value.payloads.pma_loopback_data.mode = pma_loopback_mode;

        for (size_t i = 0; i < m_serdes_count; i++) {
            pma_key.device_packet_info_pif = m_serdes_base_id + i;
            la_status status = pma_table->set(pma_key, pma_value, pma_entry);
            return_on_error(status);
        }

        la_status status = configure_info_loopback_mode(info_loopback_mode);
        return_on_error(status);
    }

    la_status status = configure_pma();
    return_on_error(status);

    // Rx_pma_max_burst_cfg is a configuration for the maximal number of back to back reads that can be done
    // in the pma rx side in terms of 60b words.
    la_uint_t pma_max_burst;

    status = calculate_pma_max_burst(pma_max_burst);
    return_on_error(status);

    status = configure_pma_max_burst(pma_max_burst);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::recover_pma_tx()
{
    if (m_device->m_ll_device->is_gibraltar()) {
        la_status status;

        set_state(la_mac_port::state_e::WAITING_FOR_PEER);

        status = reset_tx_pma(true);
        return_on_error(status);

        status = m_serdes_handler->reenable_tx();
        return_on_error(status);

        status = reset_tx_pma(false);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

bool
mac_pool_port::is_serdes_in_range(size_t serdes_idx) const
{
    return ((m_serdes_index_in_mac_pool <= serdes_idx) && ((m_serdes_index_in_mac_pool + m_serdes_count) > serdes_idx));
}

la_status
mac_pool_port::start_wait_for_peer()
{
    // In SERDES loopback mode, we don't want to wait for a peer.  If we fall to this state,
    // simply set back to tuning mode and try to tune again.
    if (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) {
        return tune();
    }

    la_status stat = m_serdes_handler->enable_low_power(false);
    return_on_error(stat);

    stat = m_serdes_handler->wait_for_peer_start();
    return_on_error(stat);

    set_state(la_mac_port::state_e::WAITING_FOR_PEER);

    // Clear & enable signal OK interrupt
    stat = clear_signal_ok_interrupt();
    return_on_error(stat);

    m_tune_with_pcs_lock = 0;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::stop_wait_for_peer()
{
    set_state(la_mac_port::state_e::ACTIVE);

    la_status stat = m_serdes_handler->wait_for_peer_stop();
    return_on_error(stat);

    // Clear & enable signal OK interrupt
    stat = clear_signal_ok_interrupt();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::is_tune_good()
{
    // Check if the amount of bad tunes crossed the limit.
    int32_t max_retry = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_MAX_TUNE_RETRY].int_val;
    if (m_bad_tunes >= max_retry) {
        m_bad_tunes = 0;
        return LA_STATUS_SUCCESS;
    }

    la_status stat = m_serdes_handler->is_tune_good();
    if (stat != LA_STATUS_SUCCESS) {
        m_bad_tunes++;
        return stat;
    }

    // Tune is successful
    m_bad_tunes = 0;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::enable_mac_rx()
{
    // Activate MAC Rx path (A0: only for network, B0: for all)
    if (is_network_slice(m_port_slice_mode) || m_device->m_ll_device->get_device_revision() != la_device_revision_e::PACIFIC_A0) {
        // First activate the IFGB Rx, then take MAC Rx out of reset
        la_status status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->reset_fifo_memory(
            m_mac_lane_index_in_ifgb, m_mac_lanes_reserved, m_mac_lanes_count, la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
        return_on_error(status);

        status = set_mac_rx_reset(la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::disable_mac_rx()
{
    // Close MAC Rx path (A0: only for network, B0: for all)
    if (is_network_slice(m_port_slice_mode) || m_device->m_ll_device->get_device_revision() != la_device_revision_e::PACIFIC_A0) {
        // Bug WA for stuck link_state=True while PCS_state=False
        if (!is_network_slice(m_port_slice_mode)) {
            la_status status = set_rx_pcs_reset();
            return_on_error(status);
        }

        // First close MAC Rx and then, reset IFGB Rx
        la_status status = set_mac_rx_reset(la_mac_port_base::mac_reset_state_e::RESET_MAC_RX_ONLY);
        return_on_error(status);

        status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->reset_fifo_memory(
            m_mac_lane_index_in_ifgb,
            m_mac_lanes_reserved,
            m_mac_lanes_count,
            la_mac_port_base::mac_reset_state_e::RESET_MAC_RX_ONLY);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::is_peer_detected(bool& out_detected)
{
    la_status stat = LA_STATUS_SUCCESS;

    if (m_enable_eid) {
        // check signal_ok interrupt
        stat = get_signal_ok_interrupt(out_detected);
        return_on_error(stat);
    } else {
        out_detected = true;
    }

    // if detected -> start tune
    if (out_detected) {
        stat = tune();
    }

    return stat;
}

la_status
mac_pool_port::is_tune_completed(bool& out_completed)
{

    if (m_device->is_simulated_or_emulated_device()) {
        out_completed = true;
        return LA_STATUS_SUCCESS;
    }

    la_status stat = m_serdes_handler->get_tune_complete(out_completed);
    return_on_error(stat);

    if (!out_completed) {
        // Not completed - check timeout
        auto tune_span = chrono::steady_clock::now() - m_tune_start_time;
        if ((tune_span > m_tune_timeout) && is_link_management_enabled()) {
            // Tune timeout. Currently, we can't stop the tune, so we just issue a warning and continue to wait.
            if (!m_tune_timeout_informed) {
                m_serdes_handler->print_tune_status_message("Tune timeout", la_logger_level_e::WARNING);
                m_serdes_handler->print_serdes_debug_message("iCal");
                m_tune_timeout_informed = true;
                // Timeout on ANLT port should be re-activated instead of waiting for tune to finish
                if (m_is_an_enabled) {
                    stat = activate();
                }
            }
        }
        return stat;
    }

    // check the quality of the eye, if it is bad, redo another tune
    // also check if first dfeTAP is -0x1F for serdes_speed 25G, if yes, redo another tune
    if (is_tune_good() != LA_STATUS_SUCCESS) {
        m_tune_with_pcs_lock = 0;
        return restart_state_machine();
    }

    if (m_device->m_ll_device->is_gibraltar()) {
        stat = set_rx_pcs_sync_reset();
        return_on_error(stat);
    }

    // Tune completed
    set_state(la_mac_port::state_e::TUNED);
    m_serdes_handler->print_tune_status_message("Tune completed", la_logger_level_e::DEBUG);
    m_serdes_handler->print_serdes_debug_message("iCal");

    m_tune_finish_time = chrono::steady_clock::now();

    auto tune_time = m_tune_finish_time - m_tune_start_time;
    long tune_duration = chrono::duration_cast<chrono::duration<long, milli> >(m_tune_finish_time - m_tune_start_time).count();

    if (tune_time > m_tune_timeout) {
        log_warning(MAC_PORT,
                    "Tune on %s: completed after timeout - %zd ms - %s",
                    this->to_string().c_str(),
                    tune_duration,
                    m_ignore_long_tune ? "checking PCS status." : "re-tuning.");
        // If the tune took > 30 seconds AND we don't want to use specified number of iterations, re-tune.
        if (!m_ignore_long_tune && is_link_management_enabled()) {
            m_serdes_handler->save_serdes_debug_message("Long tune time");
            m_tune_with_pcs_lock = 0;
            return restart_state_machine();
        }
    } else {
        log_debug(MAC_PORT, "Tune on %s completed within %zd ms", this->to_string().c_str(), tune_duration);
    }

    return LA_STATUS_SUCCESS;
}

void
mac_pool_port::print_am_lock_debug_message(const char* message, const la_mac_port::mac_status& mac_status)
{
    logger& instance = logger::instance();
    if (instance.is_logging(
            silicon_one::get_device_id(), silicon_one::la_logger_component_e::MAC_PORT, silicon_one::la_logger_level_e::DEBUG)) {
        std::stringstream am_log_message;
        am_log_message << "[ ";
        for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
            for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
                am_log_message << mac_status.am_lock[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane] << ' ';
            }
        }
        am_log_message << "]";

        log_debug(MAC_PORT, "%s on %s: AM lock %s", message, this->to_string().c_str(), am_log_message.str().c_str());
    }
}

la_status
mac_pool_port::is_rx_ready(bool& out_rx_ready)
{
    la_mac_port::mac_status mac_status;
    la_status stat = read_mac_status(mac_status);
    std::chrono::seconds cdr_lock_timeout = m_cdr_lock_timeout;
    return_on_error(stat);

    out_rx_ready = false;
    // in simulation or PMA/MII loopback modes must not fail to wait for peer
    if (!(is_serdes_mode_off() || is_serdes_mode_dummy() || m_device->is_simulated_or_emulated_device())) {
        // check timeout
        auto pcs_lock_span = chrono::steady_clock::now() - m_tune_finish_time;

        //  rx_pma_sig_ok_loss_interrupt_register is not reliable so we need
        //  to decrease the cdr lock timeout value if we were sent here from
        //  PCS_STABLE. As a result of that, we can restart state machine
        //  earlier (i.e. < 1 sec).
        //
        //  NOTE: number of state transition is a device property. If it sets to
        //  less than 2, we won't be able to determine the prior state.
        //
        if (m_sm_state_transition_queue.size() > 2) {
            if (m_sm_state_transition_queue.at(1).new_state == la_mac_port::state_e::PCS_STABLE
                || m_sm_state_transition_queue.at(1).new_state == la_mac_port::state_e::LINK_UP) {
                cdr_lock_timeout = std::chrono::seconds(1);
            }
        }
        if (pcs_lock_span > cdr_lock_timeout) {
            // Timeout for PCS lock -> go back to wait for peer
            print_am_lock_debug_message("PCS lock timeout", mac_status);
            m_serdes_handler->save_serdes_debug_message("PCS_LOCK timeout");
            stat = restart_state_machine();
            return stat;
        }
    }

    if (mac_status.pcs_status || is_pcs_mode_off()) {
        // PCS is locked or not used
        out_rx_ready = true;
        m_pcs_lock_start_time = chrono::steady_clock::now();
        set_state(la_mac_port::state_e::PCS_LOCK);

        clear_mac_link_down_interrupt();

        m_tune_start_time = chrono::steady_clock::now();

        return LA_STATUS_SUCCESS;
    }

    stat = handle_wrong_am_lock_wa(mac_status);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::handle_wrong_am_lock_wa(la_mac_port::mac_status mac_status)
{
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            if (!mac_status.am_lock[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane]) {
                return LA_STATUS_SUCCESS;
            }
        }
    }

    la_mac_port::mac_pcs_lane_mapping mac_pcs_lane_mapping;
    la_status status = read_mac_pcs_lane_mapping(mac_pcs_lane_mapping);
    return_on_error(status);

    bool apply_wa = false;
    std::set<size_t> lane_mapping;
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            size_t pcs_lane_index = mac_pcs_lane_mapping.lane_map[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane];
            if (lane_mapping.count(pcs_lane_index) > 0) {
                apply_wa = true;
            }

            lane_mapping.insert(pcs_lane_index);
        }
    }

    if (apply_wa) {
        la_status status = set_rx_pcs_sync_reset();
        return_on_error(status);
        logger& instance = logger::instance();
        if (instance.is_logging(silicon_one::get_device_id(),
                                silicon_one::la_logger_component_e::MAC_PORT,
                                silicon_one::la_logger_level_e::DEBUG)) {
            std::stringstream am_mapping_log_message;
            am_mapping_log_message << "[ ";
            for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
                for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
                    am_mapping_log_message << mac_pcs_lane_mapping.lane_map[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane] << ' ';
                }
            }
            am_mapping_log_message << "]";

            log_debug(MAC_PORT,
                      "%s Reset PCS due to wrong PCS lane mapping which was: %s",
                      this->to_string().c_str(),
                      am_mapping_log_message.str().c_str());
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::is_pcs_stable(bool& out_pcs_stable)
{
    // PCS stable is:
    // 1. At least m_pcs_lock_time seconds with PCS_LOCK without "down" interrupts.
    // 2. At least m_tune_and_pcs_lock_iter - PCS stable after tune.

    dassert_crit(m_port_state >= la_mac_port::state_e::PCS_LOCK);

    out_pcs_stable = false;

    la_mac_port::mac_status mac_status;
    la_status stat = read_mac_status(mac_status);
    return_on_error(stat);

    if (!is_pcs_mode_off()) {
        // All the following checks are relevant only when PCS layer is in use, otherwise, skip the checks
        if (!mac_status.pcs_status) {
            // PCS layer is in use and there is no PCS lock, change state to tuned and wait for PCS lock.
            print_am_lock_debug_message("No PCS lock while in PCS_STABLE", mac_status);

            set_state(la_mac_port::state_e::TUNED);
            return LA_STATUS_SUCCESS;
        }

        // if locked, check interrupts
        link_down_interrupt_info link_down_info;
        stat = read_mac_link_down_interrupt(link_down_info);
        return_on_error(stat);

        // CDR lock loss can happen in *_SRDS_CLK loopback modes but it is not important.
        if (!is_mii_pma_remote_loopback()) {
            for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
                if (link_down_info.rx_pma_sig_ok_loss_interrupt_register[serdes]) {
                    // We lost CDR lock on this SerDes need to start all over again
                    clear_mac_link_down_interrupt();
                    stat = restart_state_machine();
                    return stat;
                }
            }
        }

        if (link_down_info.rx_pcs_link_status_down | link_down_info.rx_pcs_align_status_down
            | link_down_info.rsf_rx_high_ser_interrupt_register
            | link_down_info.rx_pcs_hi_ber_up) {
            // PCS lock was lost, change state to tuned and wait for PCS lock
            log_info(MAC_PORT,
                     "Interrupt while in PCS_STABLE on %s: %s",
                     this->to_string().c_str(),
                     silicon_one::to_string(link_down_info).c_str());

            if (m_is_an_enabled) {
                stat = restart_state_machine();
                return stat;
            }

            set_state(la_mac_port::state_e::TUNED);
            clear_mac_link_down_interrupt();
            return LA_STATUS_SUCCESS;
        }

        // Check PCS lock stopwatch, if > MIN time successful_tune++
        // check timeout
        auto stable_pcs_lock_span = chrono::steady_clock::now() - m_pcs_lock_start_time;
        if (stable_pcs_lock_span <= m_pcs_lock_time) {
            // Minimum time not elapsed yet => continue to wait
            return LA_STATUS_SUCCESS;
        }

        // PCS is stable
        m_tune_with_pcs_lock++;

        // Re-tune based on number of iterations specified by user.
        if (!m_is_an_enabled && m_tune_with_pcs_lock < m_tune_and_pcs_lock_iter) {
            log_debug(MAC_PORT,
                      "%s got %d PCS_LOCK out of %d => tune again",
                      this->to_string().c_str(),
                      m_tune_with_pcs_lock,
                      m_tune_and_pcs_lock_iter);
            stat = tune();
            return stat;
        }
    }

    out_pcs_stable = true;

    // ready unmasking of delayed link error interrupts
    m_ready_delayed_interrupts = true;
    m_pcs_stable_timestamp = std::chrono::steady_clock::now();

    set_state(la_mac_port::state_e::PCS_STABLE);
    m_tune_with_pcs_lock = 0;

    stat = enable_mac_rx();
    return_on_error(stat);

    if (!is_serdes_mode_active()) {
        return LA_STATUS_SUCCESS;
    }

    /*
     *   Once SERDES is configured and pcs stable, optionally enable Serdes low power mode.
     *       Avago expects SerDes low power mode is enabled after SerDes is configured,
     *       and disabled before any SerDes reconfiguration/re-tune is performed.
     */
    stat = m_serdes_handler->enable_low_power(true);
    return_on_error(stat);

    stat = m_serdes_handler->periodic_tune_start();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::is_link_up(bool& out_link_up)
{

    if (!is_link_management_enabled()) {
        return LA_STATUS_SUCCESS;
    }

    // Check interrupts
    struct link_down_interrupt_info link_down_info;
    la_status stat = read_mac_link_down_interrupt(link_down_info);
    return_on_error(stat);

    // CDR lock loss is relevent only when actually using SerDes for data.
    if (!is_mii_pma_remote_loopback()) {
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            if (link_down_info.rx_pma_sig_ok_loss_interrupt_register[serdes]) {
                log_debug(MAC_PORT, "CDR lock lost on SerDes %d/%d/%zd ", m_slice_id, m_ifg_id, m_serdes_base_id + serdes);
                // We lost CDR lock on this SerDes need to start all over again
                stat = restart_state_machine();
                out_link_up = false;
                return stat;
            }
        }
    }

    la_mac_port::mac_status mac_status;
    stat = read_mac_status(mac_status);
    return_on_error(stat);

    out_link_up = mac_status.link_state;

    if (mac_status.link_state) {
        // Link is UP
        set_state(la_mac_port::state_e::LINK_UP);
        m_link_up_timestamp = std::chrono::steady_clock::now();

    } else if (!mac_status.pcs_status) {
        if (m_is_an_enabled) {
            out_link_up = false;
            stat = restart_state_machine();
            return stat;
        }

        // Downgrade to tuned, and start to wait
        m_tune_finish_time = chrono::steady_clock::now();

        stat = disable_mac_rx();
        return_on_error(stat);

        stat = m_serdes_handler->enable_low_power(false);
        return_on_error(stat);

        stat = m_serdes_handler->periodic_tune_stop();
        return_on_error(stat);

        set_state(la_mac_port::state_e::TUNED);

    } else if (((mac_status.degraded_ser) || (mac_status.high_ber)) && (m_check_ser_ber && !m_is_an_enabled)) {
        // Degraded SER error or high BER, re-tune
        log_debug(MAC_PORT, "%s on %s ", mac_status.high_ber ? "High BER" : "Degraded SER", this->to_string().c_str());
        m_serdes_handler->save_serdes_debug_message("High BER and degraded SER");
        stat = restart_state_machine();
        out_link_up = false;
        return stat;
    } else {

        auto stable_pcs_span = chrono::steady_clock::now() - m_pcs_stable_rx_deskew_window_start_time;
        long stable_pcs_duration = chrono::duration_cast<chrono::duration<long, milli> >(stable_pcs_span).count();

        if (stable_pcs_duration > PCS_STABLE_RX_DESKEW_SAMPLE_WINDOW_MS) {

            bool overflow = false;

            stat = check_link_down_info_rx_deskew_fifo_overflow(link_down_info, overflow);
            return_on_error(stat);

            if (overflow) {
                m_pcs_stable_rx_deskew_failures++;
                clear_rx_deskew_fifo_overflow_interrupt();
            } else {
                m_pcs_stable_rx_deskew_failures = 0;
            }

            // Make decision to perform pcs sync reset
            if (m_pcs_stable_rx_deskew_failures >= PCS_STABLE_RX_DESKEW_FAILURE_THRESHOLD) {
                // consecutive failures
                log_info(MAC_PORT,
                         "%s rx deskew fifo overflow interrupt asserted %d times, pcs resync "
                         "workaround applied.",
                         this->to_string().c_str(),
                         m_pcs_stable_rx_deskew_failures);

                // Apply resync
                set_rx_pcs_sync_reset();
                m_pcs_stable_rx_deskew_failures = 0;
            } else if (m_pcs_stable_rx_deskew_failures) {
                // some failures were seen but not enough to resync
                log_debug(MAC_PORT,
                          "%s rx deskew fifo overflow interrupt asserted for %d times. No action.",
                          this->to_string().c_str(),
                          m_pcs_stable_rx_deskew_failures);
            }

            // Clear monitoring variables, start a new monitoring window
            m_pcs_stable_rx_deskew_window_start_time = chrono::steady_clock::now();
        }
    }

    return stat;
}

la_status
mac_pool_port::ready_delayed_interrupt_mask()
{
    la_status stat;

    if (m_ready_delayed_interrupts) {

        // check if 10 seconds have passed before trying to enable
        auto now = std::chrono::steady_clock::now();
        auto time_since_PCS_STABLE = std::chrono::duration_cast<std::chrono::seconds>(now - m_pcs_stable_timestamp);
        if (time_since_PCS_STABLE < std::chrono::seconds(10)) {
            return LA_STATUS_SUCCESS;
        }

        log_debug(MAC_PORT, "%s : unmasking delayed link error interrupts", __func__);
        // enable interrupts
        stat = set_delayed_mac_link_error_interrupt_mask(true /* enable */);
        return_on_error(stat);

        // disable check, interrupts are enabled
        m_ready_delayed_interrupts = false;
    }
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::handle_mac_down()
{
    if (m_port_state == la_mac_port::state_e::INACTIVE || !is_link_management_enabled()) {
        return LA_STATUS_SUCCESS;
    }

    // Both conditions are ensured by the caller
    if (m_port_state != la_mac_port::state_e::LINK_UP) {
        log_err(MAC_PORT, "%s: mac port link not up", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    auto time_since_LINK_UP = chrono::steady_clock::now() - m_link_up_timestamp;

    //
    // If the link goes down while it is in the LINK_UP state, it needs to transfter to waiting for peer state when
    // rx_pma_sig_ok_loss is detected.  Without this, the next state will be PCS_STABLE but since the interrupt
    // was cleared by the interrupt handler, PCS_STABLE state won't be able to see the rx_pma_sig_ok_loss interrupt
    // and continue to TUNING state and eventually go back to WAITING_FOR_PEER state.
    //
    link_down_interrupt_info link_down_info;
    la_status stat = read_mac_link_down_interrupt(link_down_info);
    return_on_error(stat);

    if (!is_mii_pma_remote_loopback()) {
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            if (link_down_info.rx_pma_sig_ok_loss_interrupt_register[serdes]) {
                // We lost CDR lock on this SerDes need to start all over again
                stat = restart_state_machine();
                return stat;
            }
        }
    }

    la_mac_port::mac_status mac_status;
    stat = read_mac_status(mac_status);
    return_on_error(stat);

    if (!mac_status.link_state) {
        // ready delayed unmasking of link error interrupts
        m_ready_delayed_interrupts = true;
        m_pcs_stable_timestamp = std::chrono::steady_clock::now();

        // Down one level down - next iteration will read interrupts and act upon
        set_state(la_mac_port::state_e::PCS_STABLE);
        // when Rx still in-sync, Tx refresh may needed to fix faulty Tx
        if (mac_status.pcs_status) {
            bool serdes_tx_refresh_enable
                = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_TX_REFRESH].bool_val;
            size_t link_up_time
                = m_device->m_device_properties[(int)la_device_property_e::LINKUP_TIME_BEFORE_SERDES_REFRESH].int_val;
            if (serdes_tx_refresh_enable && (time_since_LINK_UP > std::chrono::seconds(link_up_time))) {
                tx_refresh();
                log_err(MAC_PORT, "%s: SerDes Tx Refresh been applied to avoid faulty Tx", this->to_string().c_str());
            }
        }
    }

    return stat;
}

void
mac_pool_port::update_mac_port(reconnect_metadata::fabric_mac_port::attr_e attr, uint8_t val)
{
    m_device->m_reconnect_handler->update_mac_port_attr(shared_from_this(), attr, val);
}

la_status
mac_pool_port::restore_state(la_mac_port::state_e last_known_state)
{
    // Restore state requires that the mac port is just created (PRE_INIT)
    // and write-to-device is disabled.
    dassert_crit(m_port_state == la_mac_port::state_e::PRE_INIT);
    dassert_crit(!m_device->m_ll_device->get_write_to_device());

    log_debug(MAC_PORT,
              "%s: %s last_known_state=%s, link_management_enabled=%d, serdes_mode_active=%d",
              __func__,
              this->to_string().c_str(),
              silicon_one::to_string(last_known_state).c_str(),
              m_link_management_enabled,
              is_serdes_mode_active());

    if (!m_link_management_enabled) {
        m_port_state = last_known_state;
        return LA_STATUS_SUCCESS;
    }

    la_status rc = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->read_fifo_soft_reset_config();
    return_on_error(rc);

    rc = read_mac_soft_reset_config();
    return_on_error(rc);

    switch (last_known_state) {
    case la_mac_port::state_e::PCAL_STOP:
        m_port_state = last_known_state;
        m_pcal_stop_start_time = chrono::steady_clock::now();
        break;
    case la_mac_port::state_e::PRE_INIT:
    case la_mac_port::state_e::INACTIVE:
    case la_mac_port::state_e::AN_BASE_PAGE:
    case la_mac_port::state_e::AN_NEXT_PAGE:
    case la_mac_port::state_e::AN_POLL:
    case la_mac_port::state_e::LINK_TRAINING:
    case la_mac_port::state_e::AN_COMPLETE:
    case la_mac_port::state_e::ACTIVE:
    case la_mac_port::state_e::TUNING:
        m_port_state = last_known_state;
        m_tune_start_time = chrono::steady_clock::now();
        break;
    case la_mac_port::state_e::WAITING_FOR_PEER:
        // start_wait_for_peer() was called and signal OK interrupt was switched from CDR-lock to EID
        m_port_state = last_known_state;
        break;
    case la_mac_port::state_e::TUNED:
    case la_mac_port::state_e::PCS_LOCK:
    case la_mac_port::state_e::PCS_STABLE:
    case la_mac_port::state_e::LINK_UP:
        la_mac_port::mac_status mac_status;
        la_status rc = read_mac_status(mac_status);
        return_on_error(rc);

        if (mac_status.link_state) {
            m_port_state = la_mac_port::state_e::LINK_UP;
        } else if (mac_status.pcs_status) {
            m_port_state = la_mac_port::state_e::PCS_LOCK;
            m_pcs_lock_start_time = chrono::steady_clock::now();
        } else {
            m_port_state = la_mac_port::state_e::TUNED;
            m_tune_finish_time = chrono::steady_clock::now();
        }

        if (m_port_state >= la_mac_port::state_e::PCS_STABLE && is_serdes_mode_active()) {
            rc = m_serdes_handler->enable_low_power(true);
            return_on_error(rc);

            rc = m_serdes_handler->periodic_tune_start();
            return_on_error(rc);
        }

        break;
    }

    log_debug(MAC_PORT,
              "%s: %s last_known_state=%s, restored state=%s",
              __func__,
              this->to_string().c_str(),
              silicon_one::to_string(last_known_state).c_str(),
              silicon_one::to_string(m_port_state).c_str());

    return LA_STATUS_SUCCESS;
}

size_t
mac_pool_port::get_serdes_speed_in_gbps() const
{
    return m_serdes_speed_gbps;
}

la_status
mac_pool_port::is_an_completed(bool& out_completed)
{
    la_status stat = m_serdes_handler->is_an_completed(out_completed);
    return_on_error(stat);

    if (out_completed) {
        m_serdes_handler->print_serdes_debug_message("AN Completed");

        // After ANLT complete, reset TX PMA fifo, recenter fifo for GB.
        post_anlt_complete(m_serdes_handler);

        if (m_serdes_post_anlt_tune_disable) {
            log_debug(HLD, "ANLT Post Tune Disabled, Not ReTuning");
            set_state(la_mac_port::state_e::TUNED);
            m_tune_finish_time = chrono::steady_clock::now();
        } else {
            log_debug(HLD, "ANLT Post Tune Enabled, Going to Tune");
            tune();
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::an_handler()
{
    bool an_good_check = false;
    la_mac_port::state_e new_state = m_port_state;
    la_status stat = m_serdes_handler->is_an_good_check(an_good_check, new_state);
    return_on_error(stat);

    set_state(new_state);
    if (new_state == la_mac_port::state_e::INACTIVE) {
        stat = activate();
        return stat;
    }

    if (!an_good_check) {
        return LA_STATUS_SUCCESS;
    }

    // The following resets MAC except the Rx MAC. to avoid port SerDes's to be out-of-sync
    stat = set_reset(la_mac_port_base::mac_reset_state_e::RESET_ALL);
    return_on_error(stat);

    stat = set_reset(la_mac_port_base::mac_reset_state_e::RESET_MAC_RX_ONLY);
    return_on_error(stat);

    stat = m_serdes_handler->link_training_start(new_state);
    return_on_error(stat);

    set_state(new_state);
    if (new_state == la_mac_port::state_e::INACTIVE) {
        stat = activate();
        return stat;
    }

    return stat;
}

la_status
mac_pool_port::an_base_page_rcv()
{
    la_mac_port::state_e new_state = m_port_state;
    la_status stat = m_serdes_handler->an_base_page_rcv(new_state);
    return_on_error(stat);

    set_state(new_state);
    if (new_state == la_mac_port::state_e::INACTIVE) {
        stat = activate();
    }

    return stat;
}

la_status
mac_pool_port::an_next_page_rcv()
{
    la_mac_port::state_e new_state = m_port_state;
    la_status stat = m_serdes_handler->an_next_page_rcv(new_state);
    return_on_error(stat);

    set_state(new_state);
    if (new_state == la_mac_port::state_e::INACTIVE) {
        stat = activate();
    }

    return stat;
}

la_status
mac_pool_port::link_training_handler()
{
    la_mac_port::state_e new_state = m_port_state;
    la_status stat = m_serdes_handler->link_training_handler(new_state);
    return_on_error(stat);

    set_state(new_state);
    if (new_state == la_mac_port::state_e::INACTIVE) {
        stat = activate();
    }

    return stat;
}

la_status
mac_pool_port::save_state(la_mac_port::port_debug_info_e info_type, json_t* parent)
{
    la_status status;

    json_t* port_root_json = json_object();

    // Save MAC level info, then SerDes info.
    status = save_mac_port_state(info_type, port_root_json);
    return_on_error_log(status, MAC_PORT, ERROR, "save_mac_port_state");

    if (info_type == la_mac_port::port_debug_info_e::SERDES_CONFIG || info_type == la_mac_port::port_debug_info_e::ALL
        || info_type == la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG) {
        status = add_serdes_parameters(port_root_json);
        return_on_error_log(status, MAC_PORT, ERROR, "add_serdes_parameters");
    }

    status = m_serdes_handler->save_state(info_type, port_root_json);
    return_on_error_log(status, MAC_PORT, ERROR, "serdes_handler save_state");

    // Append to parent and "loose" reference to the locally created json object.
    // Setup a MAC Port JSON object name as -  mac_port_[slice]_[ifg]_[first_sd]
    string str = "mac_port_" + std::to_string(m_slice_id) + "_" + std::to_string(m_ifg_id) + "_" + std::to_string(m_serdes_base_id);
    json_object_set_new(parent, str.c_str(), port_root_json);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool_port::set_serdes_signal_control(la_uint_t serdes_idx,
                                         la_serdes_direction_e direction,
                                         la_mac_port::serdes_ctrl_e ctrl_type)
{
    // So far, only srm serdes support squelch.
    bool is_dev_support_squelch = m_device->m_ll_device->is_gibraltar();

    if (m_device->is_simulated_or_emulated_device() && (m_loopback_mode == la_mac_port::loopback_mode_e::NONE)
        && is_dev_support_squelch) {
        // Only for non-loopback mode simulation. This scope is to simulate the behavior of SQUELCH in simulation.
        // Note: SQUELCH is only implemented in gibraltar.

        if ((direction == la_serdes_direction_e::TX) && (ctrl_type == la_mac_port::serdes_ctrl_e::ENABLE_SQUELCH)) {
            if (m_port_state != la_mac_port::state_e::INACTIVE) {
                // When port is activate, and squelch is enable, stop the port and focus it to active state.
                // this will simulate tx squelch and link-down behavior
                stop();
                set_state(la_mac_port::state_e::ACTIVE);
            }
            // HW behavior when port is inactive: Since serdes is power down, squelch command doesn't affect the state of serdes.
            // Even thougth, squelch is enable. It will be disabled during serdes init, which is invoked by activate().
            // Therefore, no need to do anything in simulation or save the stage of squelch.
        } else if ((direction == la_serdes_direction_e::TX) && (ctrl_type == la_mac_port::serdes_ctrl_e::DISABLE_SQUELCH)) {
            if (m_port_state != la_mac_port::state_e::INACTIVE) {
                // When port is activate, and squelch is disable. We will restart the state machine with activate()
                // This will reduce interrupt from an link-up state and user sends a DISABLE_SQUELCH command.
                activate();
            }
        }
    }

    return m_serdes_handler->set_serdes_signal_control(serdes_idx, direction, ctrl_type);
}

la_status
mac_pool_port::tx_refresh()
{
    if ((m_port_state == la_mac_port::state_e::PRE_INIT) || (m_port_state == la_mac_port::state_e::INACTIVE)) {
        log_err(MAC_PORT, "%s: SerDes Tx Refresh cant be applied on INACTIVE or PRE_INIT Port state", this->to_string().c_str());
        return LA_STATUS_EUNKNOWN;
    }

    reset_tx_pma(true);
    m_serdes_handler->refresh_tx();
    reset_tx_pma(false);

    return LA_STATUS_SUCCESS;
}
size_t
mac_pool_port::get_mac_lane_index() const
{
    return m_mac_lane_index_in_ifgb;
}
}
