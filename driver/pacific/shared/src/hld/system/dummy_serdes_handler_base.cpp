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

#include "dummy_serdes_handler_base.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "system/la_device_impl.h"
#include "system/serdes_device_handler.h"

#include <chrono>
#include <cmath>
#include <functional>
#include <iomanip>
#include <jansson.h>
#include <numeric>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>

using namespace std;

namespace silicon_one
{

dummy_serdes_handler_base::dummy_serdes_handler_base()
{
}

dummy_serdes_handler_base::dummy_serdes_handler_base(const la_device_impl_wptr& device,
                                                     la_slice_id_t slice_id,
                                                     la_ifg_id_t ifg_id,
                                                     la_uint_t serdes_base_id,
                                                     size_t serdes_count,
                                                     la_mac_port::port_speed_e speed,
                                                     la_mac_port::port_speed_e serdes_speed,
                                                     la_slice_mode_e serdes_slice_mode)
    : m_device(device),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_serdes_base_id(serdes_base_id),
      m_serdes_count(serdes_count),
      m_speed(speed),
      m_serdes_speed(serdes_speed),
      m_serdes_slice_mode(serdes_slice_mode),
      m_debug_mode(false)
{
    m_loopback_mode = la_mac_port::loopback_mode_e::NONE;

    m_serdes_param_vec.resize(m_serdes_count);
    for (la_uint_t index = 0; index < m_serdes_count; index++) {
        m_serdes_param_vec[index].resize((la_uint_t)la_mac_port::serdes_param_stage_e::LAST + 1);
    }

    m_anlt_lane.resize(m_serdes_count, 0);
    size_t first_tx_lane = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id].anlt_order;
    for (size_t serdes_id = 1; serdes_id < m_serdes_count; serdes_id++) {
        size_t serdes = m_serdes_base_id + serdes_id;
        if (first_tx_lane > m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order) {
            first_tx_lane = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order;
        }
    }

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t serdes = m_serdes_base_id + serdes_id;
        m_anlt_lane[serdes_id]
            = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order - first_tx_lane + m_serdes_base_id;
    }

    m_serdes_param_vec.resize(m_serdes_count);
    for (la_uint_t index = 0; index < m_serdes_count; index++) {
        m_serdes_param_vec[index].resize((la_uint_t)la_mac_port::serdes_param_stage_e::LAST + 1);
    }
}

dummy_serdes_handler_base::~dummy_serdes_handler_base()
{
}

la_status
dummy_serdes_handler_base::set_serdes_parameter(la_uint_t serdes_idx,
                                                la_mac_port::serdes_param_stage_e stage,
                                                la_mac_port::serdes_param_e param,
                                                la_mac_port::serdes_param_mode_e mode,
                                                int32_t value)
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    serdes_param_setting param_st = {.mode = mode, .value = value};
    m_serdes_param_vec[serdes_idx][(size_t)stage][param] = param_st;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::get_serdes_parameter(la_uint_t serdes_idx,
                                                la_mac_port::serdes_param_stage_e stage,
                                                la_mac_port::serdes_param_e param,
                                                la_mac_port::serdes_param_mode_e& out_mode,
                                                int32_t& out_value) const
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    auto serdes_param = m_serdes_param_vec[serdes_idx][(size_t)stage].find(param);
    if (serdes_param == m_serdes_param_vec[serdes_idx][(size_t)stage].end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_mode = serdes_param->second.mode;
    out_value = serdes_param->second.value;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::get_serdes_parameter_hardware_value(la_uint_t serdes_idx,
                                                               la_mac_port::serdes_param_e param,
                                                               int32_t& out_value)
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_handler_base::get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    for (la_uint_t stage_index = 0; stage_index < (la_uint_t)la_mac_port::serdes_param_stage_e::LAST + 1; stage_index++) {
        for (auto param_ent : m_serdes_param_vec[serdes_idx][(size_t)stage_index]) {
            la_mac_port::serdes_parameter single_param = {.stage = static_cast<la_mac_port::serdes_param_stage_e>(stage_index),
                                                          .parameter = param_ent.first,
                                                          .mode = param_ent.second.mode,
                                                          .value = param_ent.second.value};
            out_param_array.push_back(single_param);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::clear_serdes_parameter(la_uint_t serdes_idx,
                                                  la_mac_port::serdes_param_stage_e stage,
                                                  la_mac_port::serdes_param_e param)
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    auto serdes_param = m_serdes_param_vec[serdes_idx][(size_t)stage].find(param);
    if (serdes_param == m_serdes_param_vec[serdes_idx][(size_t)stage].end()) {
        return LA_STATUS_ENOTFOUND;
    }

    m_serdes_param_vec[serdes_idx][(size_t)stage].erase(param);

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::an_start(la_mac_port::state_e& state)
{
    state = la_mac_port::state_e::AN_POLL;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::an_stop()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::reset()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::an_base_page_rcv(la_mac_port::state_e& state)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::an_next_page_rcv(la_mac_port::state_e& state)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::is_an_good_check(bool& an_good_check, la_mac_port::state_e& state)
{
    an_good_check = true;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::link_training_start(la_mac_port::state_e& state)
{
    state = la_mac_port::state_e::LINK_TRAINING;
    return LA_STATUS_SUCCESS;
}

void
dummy_serdes_handler_base::print_pmd_status_message(const char* message, long duration)
{
    logger& instance = logger::instance();
    if (instance.is_logging(
            silicon_one::get_device_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::DEBUG)) {
        std::stringstream pmd_log_message;
        pmd_log_message << "[ ";
        // Check PMD status
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            int pmd_stat = 0;
            pmd_log_message << "0x" << std::hex << pmd_stat << ' ';
        }
        pmd_log_message << "]";

        log_debug(SERDES,
                  "%s on SerDes %d/%d/%d: PMD status after %zd ms: %s",
                  message,
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  duration,
                  pmd_log_message.str().c_str());
    }
}

la_status
dummy_serdes_handler_base::link_training_handler(la_mac_port::state_e& state)
{
    state = la_mac_port::state_e::AN_COMPLETE;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::is_an_completed(bool& out_completed)
{
    out_completed = true;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::restore_state(bool enabled)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = enabled;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = enabled;
    }

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::recenter_serdes_tx_fifo()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_handler_base::init(bool init_tx, bool init_rx)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = true;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = true;
    }
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::init()
{
    la_status stat;
    stat = init(true, true);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::enable_tx(bool tx_enabled)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::enable_rx(bool rx_enabled)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::tune()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::get_tune_complete(bool& out_completed)
{
    out_completed = true;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::periodic_tune_start()
{
    m_continuous_tuning_activated = true;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::periodic_tune_stop()
{
    m_continuous_tuning_activated = false;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::is_periodic_tune_stopped(bool& out_stopped)
{
    out_stopped = true;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::get_continuous_tune_status(bool& out_status)
{
    out_status = m_continuous_tuning_activated;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::update_loopback_mode(la_mac_port::loopback_mode_e loopback_mode)
{
    m_loopback_mode = loopback_mode;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_loopback_mode(la_mac_port::loopback_mode_e loopback_mode)
{
    m_loopback_mode = loopback_mode;
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::stop()
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = false;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = false;
    }

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::verify_firmware()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::wait_for_peer_start()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::wait_for_peer_stop()
{
    return LA_STATUS_SUCCESS;
}

void
dummy_serdes_handler_base::print_tune_status_message(const char* message, la_logger_level_e severity)
{
    // Tune timeout. Currently, we can't stop the tune, so we just issue a warning and continue to wait.
    logger& instance = logger::instance();
    if (instance.is_logging(silicon_one::get_device_id(), la_logger_component_e::SERDES, severity)) {
        std::stringstream tune_log_message;
        tune_log_message << "[ ";
        // Check tune
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            // The address in dummy is the SerDes ID, SerDes ID starting from 1 (not 0).
            int tune_stat = 0;
            tune_log_message << "0x" << std::hex << tune_stat << ' ';
        }
        tune_log_message << "]";

        log_message(la_logger_component_e::SERDES,
                    severity,
                    "%s on SerDes %d/%d/%d: DFE status %s",
                    message,
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    tune_log_message.str().c_str());
    }
}

void
dummy_serdes_handler_base::save_serdes_debug_message(const char* message)
{
}

void
dummy_serdes_handler_base::print_serdes_debug_message(const char* message)
{
}

la_status
dummy_serdes_handler_base::setup_test_counter(la_mac_port::serdes_test_mode_e mode)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_test_mode(la_uint_t serdes_idx,
                                         la_serdes_direction_e direction,
                                         la_mac_port::serdes_test_mode_e mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_handler_base::set_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::read_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_handler_base::read_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    for (la_uint_t lane = 0; lane < m_serdes_count; lane++) {
        out_serdes_prbs_ber.lane_ber[lane] = -1.0;
        out_serdes_prbs_ber.count[lane] = 0;
        out_serdes_prbs_ber.errors[lane] = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::enable_low_power(bool enable)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_serdes_speed_gbps(size_t serdes_speed_gbps)
{
    m_serdes_speed_gbps = serdes_speed_gbps;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_anlt_capabilities(bool enable,
                                                 serdes_handler::an_capability_code_e an_spec_cap,
                                                 size_t an_fec_request)
{
    m_is_an_enabled = enable;
    m_an_spec_cap = an_spec_cap;
    m_an_fec_request = an_fec_request;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_tuning_mode(la_mac_port::serdes_tuning_mode_e mode)
{
    m_tuning_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_continuous_tuning_enabled(bool enabled)
{
    m_continuous_tuning_enabled = enabled;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::set_debug_mode(bool mode)
{
    m_debug_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::get_serdes_addr(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_serdes_addr)
{
    if (serdes_dir == la_serdes_direction_e::RX) {
        out_serdes_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source + 1;
    } else {
        out_serdes_addr = m_serdes_base_id + serdes_idx + 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_handler_base::set_serdes_signal_control(la_uint_t serdes_idx,
                                                     la_serdes_direction_e direction,
                                                     la_mac_port::serdes_ctrl_e ctrl_type)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_handler_base::reenable_tx()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::is_tune_good()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_handler_base::refresh_tx()
{
    return LA_STATUS_SUCCESS;
}
}
