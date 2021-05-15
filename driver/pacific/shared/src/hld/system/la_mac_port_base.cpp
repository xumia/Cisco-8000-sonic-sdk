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

#include "system/la_mac_port_base.h"

#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "hld_utils.h"
#include "lld/ll_device.h"
#include "nplapi/nplapi_tables.h"
#include "npu/counter_utils.h"
#include "npu/resolution_utils.h"
#include "qos/la_meter_set_impl.h"
#include "system/device_port_handler_base.h"
#include "system/hld_notification_base.h"
#include "system/ifg_handler.h"
#include "system/la_device_impl.h"
#include "system/mac_pool_port.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include "api_tracer.h"
#include "common/common_strings.h"
#include "common/defines.h"
#include "common/file_utils.h"
#include "common/logger.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "la_strings.h"

#include "state_writer.h"

#include <sstream>
#include <utility>

namespace silicon_one
{

enum {
    MAX_TUNE_RETRIES = 30,
    TUNE_SLEEP_MS = 1000,
};

la_mac_port_base::la_mac_port_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_is_extended(false),
      m_mac_pool_port(),
      m_is_reset_allowed(true),
      m_link_up(false),
      m_block_ingress(false),
      m_sw_pfc_enabled(false),
      m_pfc_enabled(false),
      m_pfc_quanta(MAX_PFC_QUANTA),
      m_pfc_tc_bitmap(0),
      m_pfc_periodic_timer_value(0)
{
    m_system_ports_extended = ranged_index_generator(0, MAX_PORT_EXTENDER_VIDS_PER_PIF);
    m_link_down_interrupt_histogram = {};
    for (la_pfc_priority_t tc = 0; tc < LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        m_pfc_watchdog_polling_interval_ms[tc] = std::chrono::milliseconds(100);
        m_pfc_watchdog_recovery_interval_ms[tc] = std::chrono::milliseconds(0);
    }
}

la_mac_port_base::~la_mac_port_base()
{
}

la_status
la_mac_port_base::initialize_network(la_object_id_t oid,
                                     la_slice_id_t slice_id,
                                     la_ifg_id_t ifg_id,
                                     la_uint_t serdes_base,
                                     size_t num_of_serdes,
                                     port_speed_e speed,
                                     bool is_extended,
                                     fc_mode_e rx_fc_mode,
                                     fc_mode_e tx_fc_mode,
                                     fec_mode_e fec_mode)
{
    m_oid = oid;
    m_slice_id = slice_id;
    m_ifg_id = ifg_id;
    m_serdes_base_id = serdes_base;
    m_serdes_count = num_of_serdes;
    m_speed = speed;
    device_port_handler_base::mac_port_config_data config;
    m_device->m_device_port_handler->get_mac_port_config(m_speed, m_serdes_count, fec_mode, config);
    m_mac_lanes_count = config.mac_lanes;
    m_mac_lanes_reserved_count = config.reserved_mac_lanes;

    m_is_extended = is_extended;
    m_port_slice_mode = la_slice_mode_e::NETWORK;
    for (size_t tpid_idx = 0; tpid_idx < OSTC_NUM_TPIDS - 1; tpid_idx++) {
        m_ostc_tpids[tpid_idx] = std::make_pair(false, RESERVED_ETHERTYPE);
    }

    m_ostc_tpids[OSTC_NUM_TPIDS - 1] = std::make_pair(true, RESERVED_ETHERTYPE);

    la_status status = LA_STATUS_SUCCESS;

    if (m_device->m_device_port_handler->is_mlp(m_serdes_count)) {
        status = mlp_init(rx_fc_mode, tx_fc_mode, fec_mode);
    } else {
        status = single_port_init(rx_fc_mode, tx_fc_mode, fec_mode);
    }

    return_on_error(status);

    m_mac_lane_base_id = m_mac_pool_port[0]->get_mac_lane_index();
    initialize_pif();

    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->initialize_interface(m_pif_base_id, m_pif_count);
    return_on_error(status);

    status = set_interface_scheduler(false /*is_fabric*/);
    return_on_error(status);

    status = update_pdoq_oq_ifc_mapping();
    return_on_error(status);

    if (m_is_extended) {
        status = configure_serdes_source_pif_table_extended_mac();
        return_on_error(status);
    }

    status = configure_network_scheduler();
    return_on_error(status);

    status = init_rxcgm();
    return_on_error(status);

    status = init_pfc();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_interface_scheduler(bool is_fabric)
{
    if (m_scheduler != nullptr) {
        m_device->remove_object_dependency(m_scheduler, this);
        m_device->do_destroy(m_scheduler);
        m_scheduler = nullptr;
    }

    la_interface_scheduler_impl_sptr scheduler;
    auto status = m_device->create_interface_scheduler(m_slice_id, m_ifg_id, m_pif_base_id, m_speed, is_fabric, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    m_device->add_object_dependency(scheduler, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::initialize_fabric(la_object_id_t oid,
                                    la_slice_id_t slice_id,
                                    la_ifg_id_t ifg_id,
                                    la_uint_t serdes_base,
                                    size_t num_of_serdes,
                                    port_speed_e speed,
                                    fc_mode_e fc_mode)
{
    m_oid = oid;
    device_port_handler_base::fabric_data fabric_data;
    m_device->m_device_port_handler->get_fabric_data(fabric_data);
    if (num_of_serdes != fabric_data.num_serdes_per_fabric_port) {
        log_err(MAC_PORT,
                "%s: mac_port %s Fabric ports only support %d serdes per port, however, num_of_serdes=%ld",
                __func__,
                this->to_string().c_str(),
                (int)fabric_data.num_serdes_per_fabric_port,
                num_of_serdes);
        return LA_STATUS_EINVAL;
    }

    m_slice_id = slice_id;
    m_ifg_id = ifg_id;
    m_serdes_base_id = serdes_base;
    m_serdes_count = num_of_serdes;
    m_speed = speed;
    m_port_slice_mode = la_slice_mode_e::CARRIER_FABRIC;

    la_status status = LA_STATUS_SUCCESS;
    la_device::fabric_mac_ports_mode_e fabric_mac_ports_mode;
    m_device->get_fabric_mac_ports_mode(fabric_mac_ports_mode);

    bool fec_mode_rs_kp4 = false;
    fec_mode_rs_kp4 = m_device->m_device_properties[(int)la_device_property_e::ENABLE_FABRIC_FEC_RS_KP4].bool_val
                      || fabric_mac_ports_mode == la_device::fabric_mac_ports_mode_e::E_4x50;
    fec_mode_e fec_mode = fec_mode_rs_kp4 ? fec_mode_e::RS_KP4 : fec_mode_e::RS_KP4_FI;

    device_port_handler_base::mac_port_config_data config;
    m_device->m_device_port_handler->get_mac_port_config(m_speed, m_serdes_count, fec_mode, config);
    m_mac_lanes_count = config.mac_lanes;
    m_mac_lanes_reserved_count = config.reserved_mac_lanes;

    status = LA_STATUS_SUCCESS;
    status = single_port_init(fc_mode, fc_mode, fec_mode);
    return_on_error(status);

    m_mac_lane_base_id = m_mac_pool_port[0]->get_mac_lane_index();
    initialize_pif();

    status = set_interface_scheduler(true /*is_fabric*/);
    return_on_error(status);

    la_slice_id_t servicing_slice_id = m_slice_id;
    la_ifg_id_t servicing_ifg_id = m_ifg_id;
    la_uint_t servicing_pif_base = m_pif_base_id;

    // In LC_56_FABRIC_PORT_MODE the borrowed ports are serviced by the borrowing IFG (which differs from the lender).
    la_device_impl::lc_56_fabric_port_info fabric_port_info
        = m_device->get_borrowed_fabric_port_info(slice_id, ifg_id, serdes_base);

    if (fabric_port_info.is_lc_56_fabric_port == true) {
        servicing_slice_id = fabric_port_info.slice_id;
        servicing_ifg_id = fabric_port_info.ifg_id;
        servicing_pif_base = fabric_port_info.serdes_base_id; // in Pacific serdes_base_id is same as pif_base_id
    }

    status = m_device->m_ifg_schedulers[servicing_slice_id][servicing_ifg_id]->initialize_fabric_interface(servicing_pif_base,
                                                                                                           m_pif_count);

    return_on_error(status);

    status = configure_fabric_scheduler();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::single_port_init(fc_mode_e rx_fc_mode, fc_mode_e tx_fc_mode, fec_mode_e fec_mode)
{
    mac_pool_port_sptr mp;
    m_device->m_device_port_handler->create_mac_pool(m_serdes_base_id, mp);
    m_mac_pool_port.push_back(mp);

    return m_mac_pool_port[0]->initialize(m_slice_id,
                                          m_ifg_id,
                                          m_serdes_base_id,
                                          m_serdes_count,
                                          m_speed,
                                          rx_fc_mode,
                                          tx_fc_mode,
                                          fec_mode,
                                          la_mac_port::mlp_mode_e::NONE,
                                          m_port_slice_mode);
}

void
la_mac_port_base::merge_mac_status(mac_status& orig, mac_status addend) const
{
    // The only case of merging mac_status is for 800G port which is two 400G ports
    // In that case there are two sets of 16 PCS lanes.
    // am_lock must be merged but block_lock (64/66 lock) is not applicable.
    for (size_t i = 0; i < 16; i++) {
        orig.am_lock[16 + i] = addend.am_lock[i];
    }

    orig.link_state = orig.link_state && addend.link_state;
    orig.pcs_status = orig.pcs_status && addend.pcs_status;
    orig.high_ber = orig.high_ber || addend.high_ber;
    orig.degraded_ser = orig.degraded_ser || addend.degraded_ser;
    orig.remote_degraded_ser = orig.remote_degraded_ser || addend.remote_degraded_ser;
}

void
la_mac_port_base::add_mib_counters(la_mac_port::mib_counters& orig, const la_mac_port::mib_counters& addend) const
{
    orig.tx_frames_ok += addend.tx_frames_ok;
    orig.tx_bytes_ok += addend.tx_bytes_ok;
    orig.tx_64b_frames += addend.tx_64b_frames;
    orig.tx_65to127b_frames += addend.tx_65to127b_frames;
    orig.tx_128to255b_frames += addend.tx_128to255b_frames;
    orig.tx_256to511b_frames += addend.tx_256to511b_frames;
    orig.tx_512to1023b_frames += addend.tx_512to1023b_frames;
    orig.tx_1024to1518b_frames += addend.tx_1024to1518b_frames;
    orig.tx_1519to2500b_frames += addend.tx_1519to2500b_frames;
    orig.tx_2501to9000b_frames += addend.tx_2501to9000b_frames;
    orig.tx_crc_errors += addend.tx_crc_errors;
    orig.tx_mac_missing_eop_err += addend.tx_mac_missing_eop_err;
    orig.tx_mac_underrun_err += addend.tx_mac_underrun_err;
    orig.tx_mac_fc_frames_ok += addend.tx_mac_fc_frames_ok;
    orig.tx_oob_mac_frames_ok += addend.tx_oob_mac_frames_ok;
    orig.tx_oob_mac_crc_err += addend.tx_oob_mac_crc_err;
    orig.rx_frames_ok += addend.rx_frames_ok;
    orig.rx_bytes_ok += addend.rx_bytes_ok;
    orig.rx_64b_frames += addend.rx_64b_frames;
    orig.rx_65to127b_frames += addend.rx_65to127b_frames;
    orig.rx_128to255b_frames += addend.rx_128to255b_frames;
    orig.rx_256to511b_frames += addend.rx_256to511b_frames;
    orig.rx_512to1023b_frames += addend.rx_512to1023b_frames;
    orig.rx_1024to1518b_frames += addend.rx_1024to1518b_frames;
    orig.rx_1519to2500b_frames += addend.rx_1519to2500b_frames;
    orig.rx_2501to9000b_frames += addend.rx_2501to9000b_frames;
    orig.rx_mac_invert += addend.rx_mac_invert;
    orig.rx_crc_errors += addend.rx_crc_errors;
    orig.rx_oversize_err += addend.rx_oversize_err;
    orig.rx_undersize_err += addend.rx_undersize_err;
    orig.rx_mac_code_err += addend.rx_mac_code_err;
    orig.rx_mac_fc_frames_ok += addend.rx_mac_fc_frames_ok;
    orig.rx_oob_mac_frames_ok += addend.rx_oob_mac_frames_ok;
    orig.rx_oob_mac_invert_crc += addend.rx_oob_mac_invert_crc;
    orig.rx_oob_mac_crc_err += addend.rx_oob_mac_crc_err;
    orig.rx_oob_mac_code_err += addend.rx_oob_mac_code_err;
}

la_status
la_mac_port_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    // remove off the polling loop.
    m_device->remove_pfc_watchdog_poll(m_device->get_sptr(this));

    la_status status = m_scheduler->set_oqs_enabled(false /* enabled */);
    return_on_error(status);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->destroy();
        return_on_error(status);
    }

    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->reset_fdoq_calendar(m_pif_base_id, m_pif_count);
    return_on_error(status);

    // Set the port to RESET as part of destroy.
    if (is_network_slice(m_port_slice_mode)) {
        la_status status = set_reset_state_network_port(la_mac_port_base::mac_reset_state_e::RESET_ALL);
        return_on_error(status);
    } else {
        la_status status = set_reset_state_fabric_port(la_mac_port_base::mac_reset_state_e::RESET_ALL);
        return_on_error(status);
    }

    if (m_is_extended) {
        la_status status = erase_serdes_source_pif_table_extended_mac();
        return_on_error(status);
    }

    if (is_pfc_enabled() && is_network_slice(m_port_slice_mode)) {
        set_pfc_disable();
    }

    if (m_pfc_rx_counter) {
        slice_ifg_vec_t ifg_vec = get_pfc_counter_ifgs();
        la_status status = m_pfc_rx_counter->remove_drop_counter(ifg_vec);
        return_on_error(status);
        m_device->remove_object_dependency(m_pfc_rx_counter, this);

        // Turn off the ability to receive PFC packets on rx.
        for (auto port : m_mac_pool_port) {
            status = port->set_fc_rx_term_mode(true);
            return_on_error(status);
        }
    }

    if (m_pfc_tx_meter) {
        la_status status = m_pfc_tx_meter->detach_user(m_device->get_sptr(this));
        return_on_error(status);
        m_device->remove_object_dependency(m_pfc_tx_meter, this);
    }

    status = reset_rx_cgm_mapping();
    return_on_error(status);

    m_device->remove_object_dependency(m_scheduler, this);
    m_device->do_destroy(m_scheduler);
    m_scheduler = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::reconfigure(size_t num_of_serdes,
                              la_mac_port::port_speed_e speed,
                              la_mac_port::fc_mode_e rx_fc_mode,
                              la_mac_port::fc_mode_e tx_fc_mode,
                              la_mac_port::fec_mode_e fec_mode)
{
    start_api_call("num_of_serdes=",
                   num_of_serdes,
                   "speed=",
                   speed,
                   "rx_fc_mode=",
                   rx_fc_mode,
                   "tx_fc_mode=",
                   tx_fc_mode,
                   "fec_mode=",
                   fec_mode);

    // Reconfiguration is only supported in Network slice at this moment.
    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // check if this is a 800G port, we don't support bundle ports reconfiguration since it may need reconfigure IFGB as well.
    if (m_mac_pool_port.size() != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // save the old m_serdes_count
    la_uint_t old_serdes_count = m_serdes_count;

    // Check if we need more SerDes, and there are enough free SerDes for us.
    if (m_serdes_count < num_of_serdes) {
        for (la_uint_t index = m_serdes_base_id + m_serdes_count; index < (m_serdes_base_id + num_of_serdes); index++) {
            if (m_device->m_serdes_inuse[m_slice_id][m_ifg_id][index]) {
                return LA_STATUS_ERESOURCE;
            }
        }
    }

    la_mac_port::port_speed_e old_speed = m_speed;

    // start reconfiguration by calling mac_pool_port.reconfigure();
    la_status status = m_mac_pool_port[0]->reconfigure(num_of_serdes, speed, rx_fc_mode, tx_fc_mode, fec_mode);

    // Update SerDes usage
    // make sure mac_port and mac_pool_port m_serdes_count and m_speed are exactly same
    m_serdes_count = m_mac_pool_port[0]->get_num_of_serdes();
    m_mac_pool_port[0]->get_speed(m_speed);

    // free up serdes even if it fails because m_serdes_count is updated by initialize() no matter fail or success.
    if (old_serdes_count > m_serdes_count) {
        la_uint_t serdes_free_base_id = m_serdes_base_id + m_serdes_count;
        for (la_uint_t index = 0; index < (old_serdes_count - m_serdes_count); index++) {
            m_device->m_serdes_inuse[m_slice_id][m_ifg_id][serdes_free_base_id + index] = false;
        }
    }

    return_on_error(status);

    status = set_interface_scheduler(false /*is_fabric*/);
    return_on_error(status);

    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->initialize_interface(m_pif_base_id, m_pif_count);
    return_on_error(status);

    if (is_pfc_enabled()) {
        status = m_scheduler->set_pfc(is_pfc_enabled());
        return_on_error(status);
    }

    status = update_pdoq_oq_ifc_mapping();
    return_on_error(status);

    if (m_is_extended) {
        status = configure_serdes_source_pif_table_extended_mac();
        return_on_error(status);
    }

    status = configure_network_scheduler();
    return_on_error(status);

    auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();
    if (sp != nullptr) {
        // If mac_port is associated with a system_port, reconfigure the speed in system_port as well.
        sp->mac_port_reconfig_handler(m_speed);
    }

    if (m_speed != old_speed) {
        notify_speed_change(old_speed);
    }

    return status;
}

la_status
la_mac_port_base::get_an_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status stat = m_mac_pool_port[0]->get_an_enabled(out_enabled);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_an_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    for (const auto& port : m_mac_pool_port) {
        la_status stat = port->set_an_enabled(enabled);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

bool
la_mac_port_base::is_an_capable() const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->is_an_capable();
}

la_status
la_mac_port_base::set_speed_enabled(port_speed_e speed, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::set_fec_mode_enabled(fec_mode_e fec_mode, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::activate()
{
    start_api_call("");

    la_status status = m_scheduler->set_oqs_enabled(false /* enabled */);
    return_on_error(status);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->activate();
        return_on_error(status);
    }

    status = do_reset();
    return_on_error(status);

    status = m_scheduler->set_oqs_enabled(true /* enabled */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_port_signal_ok(bool& out_signal_ok)
{
    start_api_getter_call();

    bool signal_ok = true;
    for (size_t i = 0; signal_ok && i < m_serdes_count; i++) {
        la_status status = get_serdes_signal_ok(i, signal_ok);
        return_on_error(status);
    }

    out_signal_ok = signal_ok;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_serdes_signal_ok(la_uint_t serdes_idx, bool& out_signal_ok)
{
    start_api_getter_call("serdes_idx", serdes_idx);

    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_mac_pool_port[mac_pool_port_idx]->get_serdes_signal_ok(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), out_signal_ok);
}

la_status
la_mac_port_base::get_state(la_mac_port::state_e& out_state) const
{
    start_api_getter_call();

    out_state = m_mac_pool_port[0]->get_state();
    for (const auto& port : m_mac_pool_port) {
        la_mac_port::state_e state = port->get_state();
        if (state < out_state) {
            out_state = state;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::restore_state(la_mac_port::state_e state)
{
    bool curr_mac_up = false;
    la_status stat;
    for (const auto& port : m_mac_pool_port) {
        stat = port->restore_state(state);
        return_on_error(stat);
        bool mac_up = state == la_mac_port::state_e::LINK_UP;
        curr_mac_up |= mac_up;
    }

    // Update 'm_link_up' and enable link_down interrupt
    if (curr_mac_up) {
        set_mac_link_up(true);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::tune(bool block)
{
    start_api_call("");
    for (const auto& port : m_mac_pool_port) {
        la_status status = port->tune();
        return_on_error(status);
    }

    if (!block) {
        return LA_STATUS_SUCCESS;
    }

    return block_tune_complete();
}

bool
la_mac_port_base::poll_link_state()
{
    if (m_device->m_disconnected) {
        return false;
    }

    // Poll MAC pool
    bool curr_mac_up = true;

    for (const auto& port : m_mac_pool_port) {
        bool mac_up = false;
        la_status status = port->poll_mac_up(mac_up);
        if (status != LA_STATUS_SUCCESS) {
            log_err(MAC_PORT, "mac_port %s failed poll (status = %s)", this->to_string().c_str(), la_status2str(status).c_str());
            return m_link_up;
        }

        curr_mac_up &= mac_up;
    }

    // Check if link state has toggled
    if (curr_mac_up == m_link_up) {
        // No change
        return m_link_up;
    }

    // Send notifications for simulated device
    if (m_device->is_simulated_device()) {
        if (curr_mac_up == false) {
            link_down_interrupt_info interrupt_info = {};
            interrupt_info.rx_link_status_down = true;
            notify_link_down(interrupt_info);
        } else {
            notify_link_up();
        }

        set_mac_link_up(curr_mac_up);
        return m_link_up;
    }

    if (!curr_mac_up) {
        // Link was UP and changed to down.
        // This scenario usually shouldn't happen since port will go down on interrupt handling.
        // But, if it happen, retrieve the interrupts again.
        handle_link_down_interrupt();
        return m_link_up;
    }

    // Clear MAC_LINK_DOWN interrupt cause registers for this mac_port.
    // Get rid of whatever was toggled during activation and tuning (e.g. sig_ok_loss).
    clear_mac_link_down_interrupt();

    // Need to read mac link state again as we may had link-down in middle of handling link-up
    curr_mac_up = true;
    for (const auto& port : m_mac_pool_port) {
        bool mac_up = false;
        port->is_link_up(mac_up);
        curr_mac_up &= mac_up;
    }

    if (!curr_mac_up) {
        log_debug(MAC_PORT, "mac_port %s link went down in middle of handling link-up", this->to_string().c_str());
        return m_link_up;
    }

    // Update 'm_link_up' and enable link_down interrupt
    set_mac_link_up(true);

    notify_link_up();

    return m_link_up;
}

la_status
la_mac_port_base::get_tune_status(bool& out_completed)
{
    start_api_getter_call("");

    out_completed = true;
    for (const auto& port : m_mac_pool_port) {
        bool mac_pool_tune_complete = true;
        la_status status = port->get_tune_status(mac_pool_tune_complete);
        return_on_error(status);
        if (!mac_pool_tune_complete) {
            out_completed = false;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::block_tune_complete()
{
    bool tune_complete = false;

    for (size_t tune_retry = 0; tune_retry < MAX_TUNE_RETRIES && !tune_complete; tune_retry++) {
        la_status status = get_tune_status(tune_complete);
        return_on_error(status);

        if (!tune_complete) {
            std::this_thread::sleep_for(std::chrono::milliseconds(TUNE_SLEEP_MS));
        }
    }

    // If timeout, do another check and be verbose
    if (!tune_complete) {
        la_status status = get_tune_status(tune_complete);
        return_on_error(status);
    }

    if (tune_complete) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EAGAIN;
}

la_status
la_mac_port_base::reset()
{
    start_api_call("");

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_reset_port()
{
    la_mac_port::loopback_mode_e loopback_mode;
    la_status status = m_mac_pool_port[0]->get_loopback_mode(loopback_mode);
    return_on_error(status);

    la_mac_port_base::mac_reset_state_e active_mode = la_mac_port_base::mac_reset_state_e::ACTIVE_ALL;

    if ((loopback_mode == la_mac_port::loopback_mode_e::NONE) || (loopback_mode == la_mac_port::loopback_mode_e::SERDES)) {
        if (!m_device->is_emulated_device()) {
            active_mode = la_mac_port_base::mac_reset_state_e::RESET_MAC_RX_ONLY;
        }
        // Emulated device will use ACTIVE_ALL instead of RESET_MAC_RX_ONLY
    }

    status = set_reset_state_network_port(la_mac_port_base::mac_reset_state_e::RESET_ALL);
    return_on_error(status);

    status = set_reset_state_network_port(active_mode);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_state_histogram(bool clear, state_histogram& out_state_histogram)
{
    start_api_getter_call("clear=", clear);

    return m_mac_pool_port[0]->get_state_histogram(clear, out_state_histogram);
}

la_status
la_mac_port_base::get_link_down_histogram(bool clear, la_mac_port::link_down_interrupt_histogram& out_link_down_histogram)
{
    start_api_getter_call("clear=", clear);

    out_link_down_histogram = m_link_down_interrupt_histogram;

    if (clear) {
        m_link_down_interrupt_histogram = {};
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_reset_state_network_port(mac_reset_state_e state)
{
    if ((state == mac_reset_state_e::RESET_ALL) && !m_is_reset_allowed) {
        return LA_STATUS_EBUSY;
    }

    // Reset order:
    // 1) MAC pool
    // 2) IFG buffer
    //
    // Activate order:
    // 1) IFG buffers
    // 2) MAC pool
    if (state != mac_reset_state_e::ACTIVE_ALL) {
        for (auto mac_pool_port : m_mac_pool_port) {
            la_status status = mac_pool_port->set_reset(state);
            return_on_error(status);
        }

        la_status status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->reset_fifo_memory(
            m_mac_lane_base_id, m_mac_lanes_reserved_count, m_mac_lanes_count, state);
        return_on_error(status);

        return LA_STATUS_SUCCESS;

    } else { // ACTIVE
        la_status status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->reset_fifo_memory(
            m_mac_lane_base_id, m_mac_lanes_reserved_count, m_mac_lanes_count, state);
        return_on_error(status);

        for (auto mac_pool_port : m_mac_pool_port) {
            la_status status = mac_pool_port->set_reset(state);
            return_on_error(status);
        }

        return LA_STATUS_SUCCESS;
    }
}

la_status
la_mac_port_base::stop()
{
    start_api_call("");

    // disable all the OQs when we stop the ports
    la_status status = m_scheduler->set_oqs_enabled(false);
    return_on_error(status);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->stop();
        return_on_error(status);
    }

    // clean up interrupt after stop
    handle_link_down_interrupt();

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_block_ingress_data(bool enabled)
{
    start_api_call("enabled=", enabled);
    la_status status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_block_ingress_data(
        m_mac_lane_base_id, m_mac_lanes_reserved_count, enabled);
    return_on_error(status);

    m_block_ingress = enabled;
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_block_ingress_data(bool& out_enabled) const
{
    start_api_getter_call();
    out_enabled = m_block_ingress;

    return LA_STATUS_SUCCESS;
}

la_slice_id_t
la_mac_port_base::get_slice() const
{
    return m_slice_id;
}

la_status
la_mac_port_base::add_port_extension(la_port_extender_vid_t port_extended_vid, size_t& out_oq_pair_idx)
{
    if (!m_is_extended) {
        return LA_STATUS_EUNKNOWN;
    }

    if (m_device->m_extended_port_vid_bitset[m_slice_id][port_extended_vid] == true) {
        return LA_STATUS_EEXIST;
    }

    bool is_free_index = m_system_ports_extended.allocate(out_oq_pair_idx);
    if (!is_free_index) {
        return LA_STATUS_ERESOURCE;
    }

    m_device->m_extended_port_vid_bitset[m_slice_id][port_extended_vid] = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::remove_port_extension(la_port_extender_vid_t port_extended_vid, size_t oq_pair_idx)
{
    if (!m_is_extended) {
        return LA_STATUS_EUNKNOWN;
    }

    if (m_system_ports_extended.available() == MAX_PORT_EXTENDER_VIDS_PER_PIF) {
        return LA_STATUS_EUNKNOWN;
    }

    if (m_device->m_extended_port_vid_bitset[m_slice_id][port_extended_vid] == false) {
        return LA_STATUS_EUNKNOWN;
    }

    m_device->m_extended_port_vid_bitset[m_slice_id][port_extended_vid] = false;
    m_system_ports_extended.release(oq_pair_idx);

    return LA_STATUS_SUCCESS;
}

la_ifg_id_t
la_mac_port_base::get_ifg() const
{
    return m_ifg_id;
}

la_uint_t
la_mac_port_base::get_first_serdes_id() const
{
    return m_serdes_base_id;
}

size_t
la_mac_port_base::get_num_of_serdes() const
{
    return m_serdes_count;
}

la_uint_t
la_mac_port_base::get_first_pif_id_internal() const
{
    return m_pif_base_id;
}

size_t
la_mac_port_base::get_num_of_pif() const
{
    return m_pif_count;
}

la_uint_t
la_mac_port_base::get_first_pif_id() const
{
    return get_first_pif_id_internal();
}

la_mac_port_base::location
la_mac_port_base::get_location() const
{
    return la_mac_port_base::location{m_slice_id, m_ifg_id, m_serdes_base_id};
}

la_status
la_mac_port_base::set_debug_mode(bool enable)
{
    start_api_call("enable=", enable);

    for (auto mac_pool_port : m_mac_pool_port) {
        la_status stat = mac_pool_port->set_debug_mode(enable);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_debug_mode(bool& out_enable) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_debug_mode(out_enable);
}

la_status
la_mac_port_base::set_serdes_tuning_mode(serdes_tuning_mode_e mode)
{
    start_api_call("mode=", mode);

    for (auto mac_pool_port : m_mac_pool_port) {
        la_status stat = mac_pool_port->set_serdes_tuning_mode(mode);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_serdes_tuning_mode(serdes_tuning_mode_e& out_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_serdes_tuning_mode(out_mode);
}

la_status
la_mac_port_base::set_serdes_continuous_tuning_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    for (auto mac_pool_port : m_mac_pool_port) {
        la_status stat = mac_pool_port->set_serdes_continuous_tuning_enabled(enabled);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_serdes_continuous_tuning_enabled(bool& out_enabled) const
{
    start_api_getter_call("out_enabled=", out_enabled);
    return m_mac_pool_port[0]->get_serdes_continuous_tuning_enabled(out_enabled);
}

la_status
la_mac_port_base::set_serdes_parameter(la_uint_t serdes_idx,
                                       serdes_param_stage_e stage,
                                       serdes_param_e param,
                                       serdes_param_mode_e mode,
                                       int32_t value)
{
    start_api_call("serdes_idx=", serdes_idx, "stage=", stage, "param=", param, "mode=", mode, "value=", value);
    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (stage < serdes_param_stage_e::FIRST || param < serdes_param_e::FIRST || mode < serdes_param_mode_e::FIRST) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (stage > serdes_param_stage_e::LAST || param > serdes_param_e::LAST || mode > serdes_param_mode_e::LAST) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_mac_pool_port[mac_pool_port_idx]->set_serdes_parameter(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), stage, param, mode, value);
}

la_status
la_mac_port_base::get_serdes_parameter(la_uint_t serdes_idx,
                                       serdes_param_stage_e stage,
                                       serdes_param_e param,
                                       serdes_param_mode_e& out_mode,
                                       int32_t& out_value) const
{
    start_api_getter_call("serdes_idx=", serdes_idx, "stage=", stage, "param=", param);
    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (stage < serdes_param_stage_e::FIRST || param < serdes_param_e::FIRST) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (stage > serdes_param_stage_e::LAST || param > serdes_param_e::LAST) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_mac_pool_port[mac_pool_port_idx]->get_serdes_parameter(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), stage, param, out_mode, out_value);
}

la_status
la_mac_port_base::get_serdes_parameter_hardware_value(la_uint_t serdes_idx, serdes_param_e param, int32_t& out_value)
{
    start_api_getter_call("serdes_idx=", serdes_idx, "param=", param);
    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_mac_pool_port[mac_pool_port_idx]->get_serdes_parameter_hardware_value(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), param, out_value);
}

la_status
la_mac_port_base::get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const
{
    start_api_getter_call("serdes_idx=", serdes_idx);
    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_mac_pool_port[mac_pool_port_idx]->get_serdes_parameters(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), out_param_array);
}

la_status
la_mac_port_base::clear_serdes_parameter(la_uint_t serdes_idx, serdes_param_stage_e stage, serdes_param_e param)
{
    start_api_call("serdes_idx=", serdes_idx, "stage=", stage, "param=", param);
    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (stage < serdes_param_stage_e::FIRST || param < serdes_param_e::FIRST) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (stage > serdes_param_stage_e::LAST || param > serdes_param_e::LAST) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_mac_pool_port[mac_pool_port_idx]->clear_serdes_parameter(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), stage, param);
}

la_status
la_mac_port_base::get_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_speed;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_speed(la_mac_port::port_speed_e speed)
{
    start_api_call("speed=", speed);
    // Only 800Gbps is valid configuration, so actually the speed never changes.
    if (speed != la_mac_port::port_speed_e::E_800G) {
        la_status status = m_mac_pool_port[0]->set_speed(speed);
        return_on_error(status);
        port_speed_e old_speed = m_speed;
        m_speed = speed;
        notify_speed_change(old_speed);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_serdes_speed(la_mac_port::port_speed_e& out_speed) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_serdes_speed(out_speed);
}

la_status
la_mac_port_base::read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) const
{
    start_api_call("serdes_idx=", serdes_idx);
    size_t mac_pool_port_idx = m_device->m_device_port_handler->get_mac_pool_id(serdes_idx);
    if (mac_pool_port_idx >= m_mac_pool_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    bzero(&out_serdes_status, sizeof(serdes_status));

    return m_mac_pool_port[mac_pool_port_idx]->read_serdes_status(
        m_device->m_device_port_handler->get_serdes_id_in_mac_pool(serdes_idx), out_serdes_status);
}

la_status
la_mac_port_base::read_mac_status(la_mac_port::mac_status& out_mac_status) const
{
    start_api_getter_call();
    bzero(&out_mac_status, sizeof(mac_status));

    la_status status = m_mac_pool_port[0]->read_mac_status(out_mac_status);
    return_on_error(status);

    if (m_mac_pool_port.size() == 1) {
        return LA_STATUS_SUCCESS;
    }

    la_mac_port::mac_status tmp_mac_stat;
    status = m_mac_pool_port[1]->read_mac_status(tmp_mac_stat);
    return_on_error(status);

    merge_mac_status(out_mac_status, tmp_mac_stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::clear_mac_link_down_interrupt() const
{
    log_debug(MAC_PORT, "%s: mac_port %s", __func__, this->to_string().c_str());

    la_status rc;
    for (auto mac_pool_port : m_mac_pool_port) {
        rc = mac_pool_port->clear_mac_link_down_interrupt();
        return_on_error(rc);
    }

    return rc;
}

la_status
la_mac_port_base::populate_link_error_info(const interrupt_tree::cause_bits& link_error_bits,
                                           link_error_interrupt_info& val_out) const
{
    log_debug(MAC_PORT, "%s: mac_port %s", __func__, this->to_string().c_str());

    m_mac_pool_port[0]->populate_link_error_info(link_error_bits, val_out);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_mac_link_up(bool up)
{
    log_debug(MAC_PORT, "%s: mac_port %s, up=%d", __func__, this->to_string().c_str(), up);

    for (const auto& port : m_mac_pool_port) {
        port->set_mac_link_down_interrupt_mask(up /* enable_interrupt */);
        port->set_mac_link_error_interrupt_mask(up /* enable_interrupt */);
        // only call to disable the interrupt
        if (!up) {
            port->set_delayed_mac_link_error_interrupt_mask(up /*enable_interrupt */);
        }
    }

    m_link_up = up;

    return LA_STATUS_SUCCESS;
}

void
la_mac_port_base::handle_link_down_interrupt()
{
    // If link is currently UP, check interrupts
    if (m_link_up) {
        // Read MAC_LINK_DOWN interrupt cause bits for this mac_port.
        link_down_interrupt_info interrupt_info = {};
        bool rx_link_status_down = false;
        bool rx_pcs_link_status_down = false;
        // TODO interrupt handling for MLP should be reviewed and tested
        for (const auto& port : m_mac_pool_port) {
            port->read_mac_link_down_interrupt(interrupt_info);
            rx_link_status_down |= interrupt_info.rx_link_status_down;
            rx_pcs_link_status_down |= interrupt_info.rx_pcs_link_status_down;
        }
        la_mac_port::mac_status mac_status;
        read_mac_status(mac_status);
        bool oobi_bug_wa = rx_pcs_link_status_down && mac_status.link_state && !mac_status.pcs_status;
        if (oobi_bug_wa) {
            log_err(MAC_PORT,
                    "mac_port %s applying OOBI WA on stuck link state: link_state=%d pcs_status=%d",
                    this->to_string().c_str(),
                    mac_status.link_state,
                    mac_status.pcs_status);
        }

        if (rx_link_status_down || oobi_bug_wa) {
            notify_link_down(interrupt_info);

            // Update 'm_link_up' and disable link_down interrupt
            set_mac_link_up(false);

            for (const auto& port : m_mac_pool_port) {
                la_status status = port->handle_mac_down();
                if (status != LA_STATUS_SUCCESS) {
                    log_err(MAC_PORT,
                            "mac_port %s failed mac down handling (status = %s)",
                            this->to_string().c_str(),
                            la_status2str(status).c_str());
                    return;
                }
            }
        } else {
            log_warning(MAC_PORT, "%s: %s, rx_link_status_down is already clear", this->to_string().c_str(), __func__);
        }
    } else {
        log_warning(MAC_PORT, "%s: %s, link is already down", this->to_string().c_str(), __func__);
        // We got a link-down interrupt even though the soft state is already "down".
        // Disable the mask (again)
        set_mac_link_up(false);
    }

    // Clear MAC_LINK_DOWN interrupt cause bits for this mac_port.
    clear_mac_link_down_interrupt();
}

void
la_mac_port_base::notify_link_down(const link_down_interrupt_info& info) const
{
    log_info(MAC_PORT, "mac_port %s changed state to DOWN (%s)", this->to_string().c_str(), silicon_one::to_string(info).c_str());

    attribute_management_details amd;
    amd.op = attribute_management_op::MAC_PORT_LINK_STATE_CHANGED;
    amd.is_mac_port_link_state_up = false;

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) {
        amd.is_mac_port_link_state_up = true;
        return amd;
    };
    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(MAC_PORT,
                "mac_port %s failed in notify attribute link changed state to DOWN (status = %s)",
                this->to_string().c_str(),
                la_status2str(status).c_str());
    }

    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.type = la_notification_type_e::LINK;
    desc.u.link.slice_id = m_slice_id;
    desc.u.link.ifg_id = m_ifg_id;
    desc.u.link.first_serdes_id = m_serdes_base_id;
    desc.u.link.type = la_link_notification_type_e::DOWN;
    desc.u.link.u.link_down = info;

    m_device->get_notificator()->notify(desc, hld_notification_base::notification_pipe_e::CRITICAL);

    update_link_down_histogram(info);
}

void
la_mac_port_base::notify_link_up() const
{
    log_info(MAC_PORT, "mac_port %s changed state to UP", this->to_string().c_str());

    attribute_management_details amd;
    amd.op = attribute_management_op::MAC_PORT_LINK_STATE_CHANGED;
    amd.is_mac_port_link_state_up = true;

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) {
        amd.is_mac_port_link_state_up = false;
        return amd;
    };
    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(MAC_PORT,
                "mac_port %s failed to notify attribute link changed state to UP (status = %s)",
                this->to_string().c_str(),
                la_status2str(status).c_str());
    }

    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.type = la_notification_type_e::LINK;
    desc.u.link.slice_id = m_slice_id;
    desc.u.link.ifg_id = m_ifg_id;
    desc.u.link.first_serdes_id = m_serdes_base_id;
    desc.u.link.type = la_link_notification_type_e::UP;

    m_device->get_notificator()->notify(desc, hld_notification_base::notification_pipe_e::CRITICAL);
}

void
la_mac_port_base::notify_speed_change(port_speed_e old_speed) const
{
    log_info(MAC_PORT, "mac_port %s speed changed to %s", this->to_string().c_str(), silicon_one::to_string(m_speed).c_str());

    attribute_management_details amd;
    amd.op = attribute_management_op::PORT_SPEED_CHANGED;
    amd.mac_port_speed = m_speed;

    la_amd_undo_callback_funct_t undo = [this, old_speed](attribute_management_details amd) mutable {
        amd.mac_port_speed = old_speed;
        return amd;
    };

    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(MAC_PORT,
                "mac_port %s failed to notify attribute speed changed to %s (status = %s)",
                this->to_string().c_str(),
                silicon_one::to_string(m_speed).c_str(),
                la_status2str(status).c_str());
    }
}

void
la_mac_port_base::handle_link_error_interrupt(const interrupt_tree::cause_bits& link_error_bits) const
{
    link_error_interrupt_info info = {};
    la_status rc = populate_link_error_info(link_error_bits, info);
    if (rc) {
        log_err(MAC_PORT, "could not populate LINK ERROR info, %s", this->to_string().c_str());
        return;
    }

    log_info(MAC_PORT, "mac_port %s LINK ERROR (%s)", this->to_string().c_str(), silicon_one::to_string(info).c_str());

    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.type = la_notification_type_e::LINK;
    desc.u.link.slice_id = m_slice_id;
    desc.u.link.ifg_id = m_ifg_id;
    desc.u.link.first_serdes_id = m_serdes_base_id;
    desc.u.link.type = la_link_notification_type_e::ERROR;
    desc.u.link.u.link_error = info;

    m_device->get_notificator()->notify(desc);
}

la_status
la_mac_port_base::update_link_down_histogram(const link_down_interrupt_info& info) const
{
    // Update the count if the interrupt bit is set.
    m_link_down_interrupt_histogram.rx_link_status_down_count += info.rx_link_status_down;
    m_link_down_interrupt_histogram.rx_pcs_link_status_down_count += info.rx_pcs_link_status_down;
    m_link_down_interrupt_histogram.rx_pcs_align_status_down_count += info.rx_pcs_align_status_down;
    m_link_down_interrupt_histogram.rx_pcs_hi_ber_up_count += info.rx_pcs_hi_ber_up;
    m_link_down_interrupt_histogram.rsf_rx_high_ser_interrupt_register_count += info.rsf_rx_high_ser_interrupt_register;

    if (info.rx_link_status_down) {
        m_link_down_interrupt_histogram.rx_local_link_status_down_count += !info.rx_remote_link_status_down;
        m_link_down_interrupt_histogram.rx_remote_link_status_down_count += info.rx_remote_link_status_down;
    }

    for (int lane = 0; lane < la_mac_port_max_lanes_e::PCS; lane++) {
        m_link_down_interrupt_histogram.rx_deskew_fifo_overflow_count[lane] += info.rx_deskew_fifo_overflow[lane];
    }

    for (int lane = 0; lane < la_mac_port_max_lanes_e::SERDES; lane++) {
        m_link_down_interrupt_histogram.rx_pma_sig_ok_loss_interrupt_register_count[lane]
            += info.rx_pma_sig_ok_loss_interrupt_register[lane];
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_mac_pcs_lane_mapping(la_mac_port::mac_pcs_lane_mapping& out_mac_pcs_lane_mapping) const
{
    start_api_getter_call();
    bzero(&out_mac_pcs_lane_mapping, sizeof(mac_pcs_lane_mapping));

    la_status status = m_mac_pool_port[0]->read_mac_pcs_lane_mapping(out_mac_pcs_lane_mapping);
    return_on_error(status);

    if (m_mac_pool_port.size() == 1) {
        return LA_STATUS_SUCCESS;
    }

    la_mac_port::mac_pcs_lane_mapping tmp_mac_pcs_lane_mapping;
    // bzero(&tmp_mac_pcs_lane_mapping, sizeof(mac_pcs_lane_mapping));

    status = m_mac_pool_port[1]->read_mac_pcs_lane_mapping(tmp_mac_pcs_lane_mapping);
    return_on_error(status);

    // The only case of merging mac_pcs_lane_mapping is for 800G port which is two 400G ports
    // In that case there are two sets of 16 PCS lanes.
    for (size_t i = 0; i < 16; i++) {
        out_mac_pcs_lane_mapping.lane_map[16 + i] = tmp_mac_pcs_lane_mapping.lane_map[i];
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_mib_counters(bool clear, mib_counters& out_mib_counters) const
{
    start_api_getter_call();
    bzero(&out_mib_counters, sizeof(mib_counters));

    la_status stat;
    mib_counters tmp;

    for (auto mac_pool_port : m_mac_pool_port) {
        stat = mac_pool_port->read_mib_counters(clear, tmp);
        return_on_error(stat);
        add_mib_counters(out_mib_counters, tmp);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_rs_fec_debug_enabled()
{
    start_api_call("");
    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_rs_fec_debug_enabled();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_rs_fec_debug_enabled(bool& out_debug_status) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_rs_fec_debug_enabled(out_debug_status);
}

la_status
la_mac_port_base::read_rs_fec_debug_counters(la_mac_port::rs_fec_debug_counters& out_debug_counters) const
{
    start_api_getter_call();

    // TODO: Consider how to handle MLP port
    //       One option is follow the MIB counter option and just sum the two structures but maybe we'll want them separated.
    //       Currently, return not implemented.

    return m_mac_pool_port[0]->read_rs_fec_debug_counters(true, out_debug_counters);
}

la_status
la_mac_port_base::read_rs_fec_debug_counters(bool clear, la_mac_port::rs_fec_debug_counters& out_debug_counters) const
{
    start_api_getter_call();

    // TODO: Consider how to handle MLP port
    //       One option is follow the MIB counter option and just sum the two structures but maybe we'll want them separated.
    //       Currently, return not implemented.

    return m_mac_pool_port[0]->read_rs_fec_debug_counters(clear, out_debug_counters);
}

la_status
la_mac_port_base::read_rs_fec_symbol_errors_counters(bool clear, la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const
{
    start_api_getter_call();

    // TODO: Consider how to handle MLP port
    //       One option is follow the MIB counter option and just sum the two structures but maybe we'll want them separated.
    //       Currently, return not implemented.

    return m_mac_pool_port[0]->read_rs_fec_symbol_errors_counters(clear, out_sym_err_counters);
}

la_status
la_mac_port_base::read_rs_fec_symbol_errors_counters(la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const
{
    start_api_getter_call();

    // TODO: Consider how to handle MLP port
    //       One option is follow the MIB counter option and just sum the two structures but maybe we'll want them separated.
    //       Currently, return not implemented.

    return m_mac_pool_port[0]->read_rs_fec_symbol_errors_counters(true, out_sym_err_counters);
}

la_status
la_mac_port_base::read_ostc_counter(la_over_subscription_tc_t ostc, size_t& out_dropped_packets) const
{
    start_api_getter_call("ostc=%u", ostc);
    out_dropped_packets = 0;
    size_t tmp;
    for (auto mac_pool_port : m_mac_pool_port) {
        la_status status = mac_pool_port->read_ostc_counter(ostc, tmp);
        return_on_error(status);
        out_dropped_packets += tmp;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_counter(counter_e counter_type, size_t& out_counter) const
{
    start_api_getter_call("counter_type=", counter_type);
    out_counter = 0;

    la_status stat;
    size_t tmp;

    for (auto mac_pool_port : m_mac_pool_port) {
        stat = mac_pool_port->read_counter(counter_type, tmp);
        return_on_error(stat);
        out_counter += tmp;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_counter(bool clear, counter_e counter_type, size_t& out_counter) const
{
    start_api_getter_call("clear=", clear, "counter_type=", counter_type);
    out_counter = 0;

    la_status stat;
    size_t tmp;

    for (auto mac_pool_port : m_mac_pool_port) {
        stat = mac_pool_port->read_counter(clear, counter_type, tmp);
        return_on_error(stat);
        out_counter += tmp;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_counter(serdes_counter_e counter_type, la_uint_t serdes_idx, size_t& out_counter) const
{
    start_api_getter_call("counter_type=", counter_type, "serdes_idx=", serdes_idx);
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t serdes_per_mac_pool = m_mac_pool_port[0]->get_num_of_serdes();
    size_t mac_pool_idx = serdes_idx / serdes_per_mac_pool;

    la_status stat = m_mac_pool_port[mac_pool_idx]->read_counter(counter_type, serdes_idx % serdes_per_mac_pool, out_counter);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::clear_counters() const
{
    start_api_call("");

    la_status stat;

    for (auto mac_pool_port : m_mac_pool_port) {
        stat = mac_pool_port->clear_counters();
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_fec_mode(la_mac_port::fec_mode_e& out_fec_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_fec_mode(out_fec_mode);
}

la_status
la_mac_port_base::set_fec_mode(la_mac_port::fec_mode_e fec_mode)
{
    start_api_call("fec_mode=", fec_mode);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_fec_mode(fec_mode);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e& out_fc_mode) const
{
    start_api_getter_call("fc_dir=", fc_dir);

    return m_mac_pool_port[0]->get_fc_mode(fc_dir, out_fc_mode);
}

la_status
la_mac_port_base::set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode)
{
    start_api_call("fc_dir=", fc_dir, "fc_mode=", fc_mode);

    fc_mode_e curr_fc_mode;
    la_status status = get_fc_mode(fc_dir, curr_fc_mode);
    return_on_error(status);

    if (is_pfc_enabled() && (fc_mode == fc_mode_e::PFC || curr_fc_mode == fc_mode_e::PFC)) {
        // If we have PFC TCs, ensure those SQs are cleared before setting to or from PFC mode
        // Otherwise, PFC can get stuck sending
        for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
            if (((1 << tc) & m_pfc_tc_bitmap) != 0) {
                size_t buffers = 0;
                status
                    = m_device->m_rx_cgm_handler->get_rx_cgm_sq_buffer_count(m_slice_id, m_ifg_id, m_serdes_base_id, tc, buffers);
                return_on_error(status);

                if (buffers != 0) {
                    return LA_STATUS_EAGAIN;
                }
            }
        }
    }

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_fc_mode(fc_dir, fc_mode);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_interface_scheduler*
la_mac_port_base::get_scheduler() const
{
    return m_scheduler.get();
}

la_status
la_mac_port_base::get_min_packet_size(la_uint_t& out_min_size) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_min_packet_size(out_min_size);
}

la_status
la_mac_port_base::set_min_packet_size(la_uint_t min_size)
{
    start_api_call("min_size=", min_size);
    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_min_packet_size(min_size);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_max_packet_size(la_uint_t& out_max_size) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_max_packet_size(out_max_size);
}

la_status
la_mac_port_base::set_max_packet_size(la_uint_t max_size)
{
    start_api_call("max_size=", max_size);
    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_max_packet_size(max_size);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_fec_bypass_mode(fec_bypass_e& out_fec_bp) const
{
    start_api_getter_call();
    la_status status = m_mac_pool_port[0]->get_fec_bypass_mode(out_fec_bp);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_fec_bypass_mode(fec_bypass_e fec_bp)
{
    start_api_call("fec_bp=", fec_bp);
    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_fec_bypass_mode(fec_bp);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_preamble_compression_enabled(bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::set_preamble_compression_enabled(bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::get_ipg(la_uint16_t& out_gap_len, la_uint16_t& out_gap_tx_bytes) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_ipg(out_gap_len, out_gap_tx_bytes);
}

la_status
la_mac_port_base::set_ipg(la_uint16_t gap_len, la_uint16_t gap_tx_bytes)
{
    start_api_call("ipg=", gap_len, "gap_tx_bytes=", gap_tx_bytes);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_ipg(gap_len, gap_tx_bytes);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_crc_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_crc_enabled(out_enabled);
}

la_status
la_mac_port_base::set_crc_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_crc_enabled(enabled);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_loopback_mode(loopback_mode_e& out_loopback_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_loopback_mode(out_loopback_mode);
}

la_status
la_mac_port_base::set_loopback_mode(loopback_mode_e mode)
{
    la_status status = LA_STATUS_SUCCESS;

    start_api_call("mode=", mode);
    for (const auto& port : m_mac_pool_port) {
        status = port->set_loopback_mode(mode);
        return_on_error(status);
    }

    if ((m_mac_pool_port[0]->get_state() == la_mac_port::state_e::PRE_INIT)
        || (m_mac_pool_port[0]->get_state() == la_mac_port::state_e::INACTIVE)) {
        // no stop activate needed at this stage
        return LA_STATUS_SUCCESS;
    }

    status = stop();
    return_on_error(status);

    status = activate();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_link_management_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_link_management_enabled(out_enabled);
}

la_status
la_mac_port_base::set_link_management_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_link_management_enabled(enabled);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pcs_test_mode(pcs_test_mode_e& out_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_pcs_test_mode(out_mode);
}

la_status
la_mac_port_base::set_pcs_test_mode(pcs_test_mode_e mode)
{
    start_api_call("mode=", mode);

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_pcs_test_mode(mode);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pcs_test_seed(la_uint128_t& out_seed) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::set_pcs_test_seed(la_uint128_t seed)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::get_pma_test_mode(pma_test_mode_e& out_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_pma_test_mode(out_mode);
}

la_status
la_mac_port_base::set_pma_test_mode(pma_test_mode_e mode)
{
    start_api_call("mode=", mode);
    for (const auto& port : m_mac_pool_port) {
        la_status status = port->set_pma_test_mode(mode);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pma_test_seed(la_uint128_t& out_seed) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::set_pma_test_seed(la_uint128_t seed)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_base::read_pma_test_ber(la_mac_port::mac_pma_ber& out_mac_pma_ber) const
{
    start_api_getter_call("");

    for (size_t i = 0; i < array_size(out_mac_pma_ber.lane_ber); i++) {
        out_mac_pma_ber.lane_ber[i] = -1;
    }

    la_status status = m_mac_pool_port[0]->read_pma_test_ber(out_mac_pma_ber);
    return_on_error(status);

    if (m_mac_pool_port.size() == 1) {
        return LA_STATUS_SUCCESS;
    }

    la_mac_port::mac_pma_ber tmp_mac_pma_ber;

    status = m_mac_pool_port[1]->read_pma_test_ber(tmp_mac_pma_ber);
    return_on_error(status);

    // The only case of merging mac_pma_ber is for 800G port which is two 400G ports
    // In that case there are two sets of 8 PMA lanes.
    for (size_t i = 0; i < 8; i++) {
        out_mac_pma_ber.lane_ber[8 + i] = tmp_mac_pma_ber.lane_ber[i];
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_serdes_test_mode(la_uint_t serdes_idx,
                                       la_serdes_direction_e direction,
                                       la_mac_port::serdes_test_mode_e& out_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_serdes_test_mode(serdes_idx, direction, out_mode);
}

la_status
la_mac_port_base::get_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e& out_mode) const
{
    start_api_getter_call();

    return m_mac_pool_port[0]->get_serdes_test_mode(direction, out_mode);
}

la_status
la_mac_port_base::set_serdes_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    start_api_call("mode=", mode);

    return m_mac_pool_port[0]->set_serdes_test_mode(serdes_idx, direction, mode);
}

la_status
la_mac_port_base::set_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    start_api_call("");
    return m_mac_pool_port[0]->set_serdes_test_mode(direction, mode);
}

la_status
la_mac_port_base::read_serdes_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    start_api_getter_call("");

    out_serdes_prbs_ber.lane_ber[serdes_idx] = -1;
    out_serdes_prbs_ber.count[serdes_idx] = 0;
    out_serdes_prbs_ber.errors[serdes_idx] = 0;
    out_serdes_prbs_ber.prbs_lock[serdes_idx] = 0;

    return m_mac_pool_port[0]->read_serdes_test_ber(serdes_idx, out_serdes_prbs_ber);
}

la_status
la_mac_port_base::read_serdes_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) const
{
    start_api_call("");
    for (size_t i = 0; i < array_size(out_serdes_prbs_ber.lane_ber); i++) {
        out_serdes_prbs_ber.lane_ber[i] = -1;
        out_serdes_prbs_ber.count[i] = 0;
        out_serdes_prbs_ber.errors[i] = 0;
        out_serdes_prbs_ber.prbs_lock[i] = 0;
    }

    return m_mac_pool_port[0]->read_serdes_test_ber(out_serdes_prbs_ber);
}

la_status
la_mac_port_base::set_ostc_quantizations(const ostc_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    // Check valid thresholds
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        if (thresholds.thresholds[index] < 0 || thresholds.thresholds[index] > 1) {
            return LA_STATUS_EINVAL;
        }
    }

    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }

    // Setting the thresholds
    if (m_port_slice_mode == la_slice_mode_e::CARRIER_FABRIC) {
        // The following reset* calls undo config done by ifg_handlers::configure_port, which is not called by mac_pool for fabric
        // ports.
        // If these are to be called, need to consider LC_56_FABRIC_PORT_MODE, that is, the mac_pools m_slice_id, m_ifg_id,
        // m_serdes_base_id hold the lender's port.
        // Whereas most IFGB config takes places at the borrower IFG, except the FC mode, which still takes place at the lender IFG.

        return LA_STATUS_SUCCESS;
    }

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_ostc_quantizations(
        m_mac_lane_base_id, m_mac_lanes_reserved_count, m_speed, thresholds);
    return status;
}

la_status
la_mac_port_base::get_ostc_quantizations(ostc_thresholds& out_thresholds) const
{
    start_api_getter_call();

    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->get_ostc_quantizations(
        m_mac_lane_base_id, m_mac_lanes_reserved_count, m_speed, out_thresholds);
}

la_status
la_mac_port_base::set_default_port_tc(la_over_subscription_tc_t default_ostc, la_initial_tc_t default_itc)
{
    start_api_call("default_ostc=", default_ostc, "default_itc=", default_itc);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Setting default TC on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    // Check valid TC
    if (default_ostc >= OSTC_TRAFFIC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    // Setting the default TC
    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_default_port_tc(
        m_mac_lane_base_id, m_mac_lanes_reserved_count, default_ostc, default_itc);
}

la_status
la_mac_port_base::get_default_port_tc(la_over_subscription_tc_t& out_default_ostc, la_initial_tc_t& out_default_itc) const
{
    start_api_getter_call();

    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->get_default_port_tc(
        m_mac_lane_base_id, out_default_ostc, out_default_itc);
}

la_status
la_mac_port_base::add_port_tc_tpid(la_tpid_t tpid)
{
    start_api_call("tpid=", tpid);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Adding TC tpid on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    if (tpid == RESERVED_ETHERTYPE) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t free_index;
    bool found = false;
    for (la_uint_t i = 0; i < OSTC_NUM_TPIDS; i++) {
        if (m_ostc_tpids[i].first) {
            if (m_ostc_tpids[i].second == tpid) {
                log_err(MAC_PORT, "%s: %s TPID %u already exists", __func__, this->to_string().c_str(), tpid);
                // This protocol is already monitored
                return LA_STATUS_EEXIST;
            }
            continue;
        }

        found = true;
        free_index = i;
    }

    if (!found) {
        log_err(MAC_PORT, "%s: %s No resources. TPID=%u", __func__, this->to_string().c_str(), tpid);
        return LA_STATUS_ERESOURCE;
    }

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->modify_port_tc_tpid(
        m_mac_lane_base_id, m_mac_lanes_reserved_count, free_index, tpid);
    return_on_error(status);

    m_ostc_tpids[free_index].first = true;
    m_ostc_tpids[free_index].second = tpid;
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::remove_port_tc_tpid(la_tpid_t tpid)
{
    start_api_call("tpid=", tpid);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Removing TC tpid on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    if (tpid == RESERVED_ETHERTYPE) {
        return LA_STATUS_EINVAL;
    }

    la_uint8_t index;
    status = get_custom_tpid_idx(tpid, index);
    return_on_error(status);
    dassert_crit(index < OSTC_NUM_TPIDS);

    m_ostc_tpids[index] = std::make_pair(false, RESERVED_ETHERTYPE);

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->remove_port_tc_tpid(m_mac_lane_base_id, m_mac_lanes_count, index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_port_tc_tpids(la_tpid_vec& out_tpids) const
{
    start_api_getter_call();

    out_tpids.clear();
    for (auto tpid : m_ostc_tpids) {
        if (tpid.first) {
            out_tpids.push_back(tpid.second);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_port_tc_extract_offset(la_uint_t offset)
{
    start_api_call("offset=", offset);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(
            MAC_PORT, "%s: %s Setting TC extract offset on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    if (offset > MAX_TC_EXTRACT_OFFSET) {
        log_err(MAC_PORT, "%s: maximal offset allowed is %d", __func__, MAX_TC_EXTRACT_OFFSET);
        return LA_STATUS_EEXIST;
    }

    status
        = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_tc_extract_offset(m_mac_lane_base_id, m_mac_lanes_count, offset);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_port_tc_for_custom_protocol_with_offset(la_ethertype_t protocol,
                                                              la_over_subscription_tc_t ostc,
                                                              la_initial_tc_t itc)
{
    start_api_call("protocol=", protocol, "ostc=", ostc, "itc=", itc);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if (protocol >= (1 << 8)) {
        log_err(MAC_PORT, "%s: size of extracted protocol is one byte", __func__);
        return LA_STATUS_EINVAL;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Setting TC on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_tc_for_custom_protocol_with_offset(
        m_mac_lane_base_id, m_mac_lanes_count, protocol, ostc, itc);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::add_port_tc_custom_protocol(la_ethertype_t protocol)
{
    start_api_call("protocol=", protocol);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(
            MAC_PORT, "%s: %s Adding TC custom protocol on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    la_uint_t free_index;
    bool found = false;
    for (la_uint_t i = 0; i < OSTC_NUM_CUSTOM_ETHERTYPES; i++) {
        if (m_ostc_protocols[i].first) {
            if (m_ostc_protocols[i].second == protocol) {
                log_err(MAC_PORT, "%s: mac_port %s protocol %u exists", __func__, this->to_string().c_str(), protocol);
                // This protocol is already monitored
                return LA_STATUS_EEXIST;
            }
            continue;
        }
        found = true;
        free_index = i;
    }

    if (!found) {
        log_err(MAC_PORT, "%s: mac_port %s No resources. protocol=%u", __func__, this->to_string().c_str(), protocol);
        return LA_STATUS_ERESOURCE;
    }

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->add_port_tc_custom_protocol(
        m_mac_lane_base_id, m_mac_lanes_count, free_index, protocol);
    return_on_error(status);

    m_ostc_protocols[free_index].first = true;
    m_ostc_protocols[free_index].second = protocol;
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::remove_port_tc_custom_protocol(la_ethertype_t protocol)
{
    start_api_call("protocol=", protocol);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT,
                "%s: %s Removing TC custom protocol on Odd PIF ID Port is not permitted.",
                __func__,
                this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    la_uint8_t index;
    status = get_custom_protocol_idx(protocol, index);
    return_on_error(status);

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->remove_port_tc_custom_protocol(
        m_mac_lane_base_id, m_mac_lanes_count, index);
    return_on_error(status);

    m_ostc_protocols[index].first = false;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_port_tc_custom_protocols(la_ethertype_vec& out_protocols) const
{
    start_api_getter_call();

    out_protocols.clear();
    for (auto protocol : m_ostc_protocols) {
        if (protocol.first) {
            out_protocols.push_back(protocol.second);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_port_tc_layer(la_tpid_t tpid, tc_protocol_e protocol, la_layer_e layer)
{
    start_api_call("tpid=", tpid, "protocol=", protocol, "layer=", layer);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Setting TC on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    la_uint8_t tpid_idx;
    status = get_custom_tpid_idx(tpid, tpid_idx);
    return_on_error(status);

    la_status stat
        = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_tc_layer(m_mac_lane_base_id, tpid_idx, protocol, layer);

    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_port_tc_layer(la_tpid_t tpid, tc_protocol_e protocol, la_layer_e& out_layer) const
{
    start_api_getter_call("tpid", tpid, "protocol", protocol);

    la_uint8_t tpid_idx;
    la_status status = get_custom_tpid_idx(tpid, tpid_idx);
    return_on_error(status);

    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->get_port_tc_layer(m_mac_lane_base_id, tpid_idx, protocol, out_layer);
}

la_status
la_mac_port_base::set_port_tc_for_fixed_protocol(tc_protocol_e protocol,
                                                 la_uint8_t lower_bound,
                                                 la_uint8_t higher_bound,
                                                 la_over_subscription_tc_t ostc,
                                                 la_initial_tc_t itc)
{
    start_api_call("protocol=", protocol, "lower_bound=", lower_bound, "higher_bound=", higher_bound, "ostc=", ostc, "itc=", itc);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    // Check valid TC
    if (ostc >= OSTC_TRAFFIC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    if (lower_bound > higher_bound) {
        return LA_STATUS_EINVAL;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Setting TC on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_tc_for_fixed_protocol(
        m_mac_lane_base_id, protocol, lower_bound, higher_bound, ostc, itc);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_port_tc_for_fixed_protocol(tc_protocol_e protocol,
                                                 la_uint8_t priority,
                                                 la_over_subscription_tc_t& out_ostc,
                                                 la_initial_tc_t& out_itc) const
{
    start_api_getter_call("protocol=", protocol, "priority=", priority);

    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->get_port_tc_for_fixed_protocol(
        m_mac_lane_base_id, protocol, priority, out_ostc, out_itc);
}

la_status
la_mac_port_base::clear_port_tc_for_fixed_protocol()
{
    start_api_call("");

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->clear_port_tc_for_fixed_protocol(m_mac_lane_base_id);
}

la_status
la_mac_port_base::set_port_tc_for_custom_protocol(la_tpid_t tpid,
                                                  la_ethertype_t protocol,
                                                  la_over_subscription_tc_t ostc,
                                                  la_initial_tc_t itc)
{
    start_api_call("tpid=", tpid, "protocol=", protocol, "ostc=", ostc, "itc=", itc);

    state_e state;
    la_status status = get_state(state);
    return_on_error(status);

    if (state > state_e::INACTIVE) {
        return LA_STATUS_EBUSY;
    }

    if ((m_mac_lane_base_id % 2) == 1) {
        log_err(MAC_PORT, "%s: %s Setting TC on Odd PIF ID Port is not permitted.", __func__, this->to_string().c_str());
        return LA_STATUS_EINVAL;
    }

    // Check valid TC
    if (ostc >= OSTC_TRAFFIC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    la_uint8_t index;
    status = get_custom_protocol_idx(protocol, index);
    return_on_error(status);

    la_uint8_t tpid_idx;
    status = get_custom_tpid_idx(tpid, tpid_idx);
    return_on_error(status);

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_tc_for_custom_protocol(
        m_mac_lane_base_id, tpid_idx, index, ostc, itc);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_port_tc_for_custom_protocol(la_tpid_t tpid,
                                                  la_ethertype_t protocol,
                                                  la_over_subscription_tc_t& out_ostc,
                                                  la_initial_tc_t& out_itc) const
{
    start_api_getter_call("tpid", tpid, "protocol", protocol);

    la_uint8_t tpid_idx;
    la_status status = get_custom_tpid_idx(tpid, tpid_idx);
    return_on_error(status);

    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->get_port_tc_for_custom_protocol(
        m_mac_lane_base_id, tpid_idx, protocol, out_ostc, out_itc);
}

la_status
la_mac_port_base::get_custom_tpid_idx(la_ethertype_t tpid, la_uint8_t& out_idx) const
{
    if ((m_mac_lane_base_id % 2) == 1) {
        la_mac_port* mp;
        la_status status = m_device->get_mac_port(m_slice_id, m_ifg_id, m_serdes_base_id - 1, mp);
        return_on_error(status);
        if (!mp) {
            return LA_STATUS_ENOTFOUND;
        }
        la_mac_port_base_wptr master_port = m_device->get_sptr<la_mac_port_base>(mp);
        master_port->get_custom_tpid_idx(tpid, out_idx);
        return LA_STATUS_SUCCESS;
    }
    for (la_uint_t i = 0; i < OSTC_NUM_TPIDS; i++) {
        if (m_ostc_tpids[i].first) {
            if (m_ostc_tpids[i].second == tpid) {
                out_idx = i;
                return LA_STATUS_SUCCESS;
            }
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_mac_port_base::save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root) const
{
    start_api_getter_call();

    for (size_t i = 0; i < m_mac_pool_port.size(); i++) {
        la_status rc = m_mac_pool_port[i]->save_state(info_type, out_root);
        return_on_error(rc);

        if (info_type == la_mac_port::port_debug_info_e::MAC_STATUS || info_type == la_mac_port::port_debug_info_e::ALL
            || info_type == la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG) {
            add_link_down_histogram(i, out_root);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::save_state(la_mac_port::port_debug_info_e info_type, std::string file_name) const
{
    start_api_getter_call();

    json_t* root_node = json_object();
    la_status stat = save_state(info_type, root_node);
    return_on_error(stat);

    stat = file_utils::write_json_to_file(root_node, file_name);
    json_decref(root_node);

    return stat;
}

void
la_mac_port_base::add_link_down_histogram(size_t index, json_t* parent) const
{
    json_t* json_link_down_histogram = json_object();
    json_object_set_new(json_link_down_histogram,
                        "rx_link_status_down_count",
                        json_integer(m_link_down_interrupt_histogram.rx_link_status_down_count));
    json_object_set_new(json_link_down_histogram,
                        "rx_remote_link_status_down_count",
                        json_integer(m_link_down_interrupt_histogram.rx_remote_link_status_down_count));
    json_object_set_new(json_link_down_histogram,
                        "rx_local_link_status_down_count",
                        json_integer(m_link_down_interrupt_histogram.rx_local_link_status_down_count));
    json_object_set_new(json_link_down_histogram,
                        "rx_pcs_link_status_down_count",
                        json_integer(m_link_down_interrupt_histogram.rx_pcs_link_status_down_count));
    json_object_set_new(json_link_down_histogram,
                        "rx_pcs_align_status_down_count",
                        json_integer(m_link_down_interrupt_histogram.rx_pcs_align_status_down_count));
    json_object_set_new(
        json_link_down_histogram, "rx_pcs_hi_ber_up_count", json_integer(m_link_down_interrupt_histogram.rx_pcs_hi_ber_up_count));
    json_object_set_new(json_link_down_histogram,
                        "rsf_rx_high_ser_interrupt_register_count",
                        json_integer(m_link_down_interrupt_histogram.rsf_rx_high_ser_interrupt_register_count));

    json_t* json_fifo_overflow_array = json_array();
    for (int lane = 0; lane < la_mac_port_max_lanes_e::PCS; lane++) {
        json_array_append_new(json_fifo_overflow_array,
                              json_integer(m_link_down_interrupt_histogram.rx_deskew_fifo_overflow_count[lane]));
    }

    json_t* json_pma_sig_loss_array = json_array();
    for (int lane = 0; lane < la_mac_port_max_lanes_e::SERDES; lane++) {
        json_array_append_new(json_pma_sig_loss_array,
                              json_integer(m_link_down_interrupt_histogram.rx_pma_sig_ok_loss_interrupt_register_count[lane]));
    }

    json_object_set_new(json_link_down_histogram, "rx_deskew_fifo_overflow_count", json_fifo_overflow_array);
    json_object_set_new(json_link_down_histogram, "rx_pma_sig_ok_loss_interrupt_register_count", json_pma_sig_loss_array);

    // Append to parent and "loose" reference to the locally created json object.
    std::string json_tag = "mac_port_" + std::to_string(m_mac_pool_port[index]->get_slice()) + "_"
                           + std::to_string(m_mac_pool_port[index]->get_ifg()) + "_"
                           + std::to_string(m_mac_pool_port[index]->get_first_serdes_id()) + ".link_down_histogram";

    json_object_set_new(parent, json_tag.c_str(), json_link_down_histogram);
}

la_status
la_mac_port_base::set_serdes_signal_control(la_uint_t serdes_idx,
                                            la_serdes_direction_e direction,
                                            la_mac_port::serdes_ctrl_e ctrl_type)
{
    start_api_call("set_serdes_signal_control");
    return m_mac_pool_port[0]->set_serdes_signal_control(serdes_idx, direction, ctrl_type);
}

la_status
la_mac_port_base::get_custom_protocol_idx(la_ethertype_t protocol, la_uint8_t& out_idx) const
{
    if ((m_mac_lane_base_id % 2) == 1) {
        la_mac_port* mp;
        la_status status = m_device->get_mac_port(m_slice_id, m_ifg_id, m_serdes_base_id - 1, mp);
        return_on_error(status);
        if (!mp) {
            return LA_STATUS_ENOTFOUND;
        }
        la_mac_port_base_wptr master_port = m_device->get_sptr<la_mac_port_base>(mp);
        master_port->get_custom_protocol_idx(protocol, out_idx);
        return LA_STATUS_SUCCESS;
    }

    for (la_uint_t i = 0; i < OSTC_NUM_CUSTOM_ETHERTYPES; i++) {
        if (m_ostc_protocols[i].first) {
            if (m_ostc_protocols[i].second == protocol) {
                out_idx = i;
                return LA_STATUS_SUCCESS;
            }
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_object::object_type_e
la_mac_port_base::type() const
{
    return object_type_e::MAC_PORT;
}

std::string
la_mac_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_mac_port_base(oid=" << m_oid << ")" << LOG_INFO_SEPARATOR << "SerDes " << m_slice_id << "/" << m_ifg_id
                << "/" << m_serdes_base_id << LOG_INFO_SEPARATOR;
    return log_message.str();
}

la_object_id_t
la_mac_port_base::oid() const
{
    return m_oid;
}

const la_device*
la_mac_port_base::get_device() const
{
    return m_device.get();
}

la_status
la_mac_port_base::configure_network_scheduler()
{
    la_status status;
    la_rate_t port_speed = (la_2_port_speed(m_speed)) * UNITS_IN_GIGA;

    status = m_scheduler->set_transmit_cir(port_speed);
    return_on_error(status);

    status = m_scheduler->set_transmit_eir_or_pir(port_speed, false /* is_eir */);
    return_on_error(status);

    status = m_scheduler->set_credit_cir(port_speed);
    return_on_error(status);

    status = m_scheduler->set_credit_eir_or_pir(port_speed, false /* is_eir */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_mac_port_base::set_is_reset_allowed(bool is_reset_allowed)
{
    start_api_call("is_reset_allowed=", is_reset_allowed);

    m_is_reset_allowed = is_reset_allowed;
}

la_system_port_wptr
la_mac_port_base::get_system_port() const
{
    std::vector<la_object*> mac_port_deps = m_device->get_dependent_objects(this);
    for (auto mac_port_objp : mac_port_deps) {
        if (mac_port_objp->type() == object_type_e::SYSTEM_PORT) {
            return m_device->get_sptr<la_system_port>(mac_port_objp);
        }
    }

    return nullptr;
}

slice_ifg_vec_t
la_mac_port_base::get_pfc_counter_ifgs() const
{
    slice_ifg_vec_t ifg_vec;
    la_slice_ifg slice_ifg;
    slice_ifg.slice = get_slice();
    slice_ifg.ifg = 1; // Needs to be hardcoded to 1 since pkts will be injected from host from IFG1
    ifg_vec.push_back(slice_ifg);
    return ifg_vec;
}

la_status
la_mac_port_base::get_oqueue_state(la_pfc_priority_t pfc_priority, pfc_queue_state_e& out_state, bool& out_pfc_rx)
{
    la_status status;
    la_uint_t q_rd_ptr, q_wr_ptr;

    out_state = pfc_queue_state_e::EMPTY;

    status = get_oqueue_ptr(pfc_priority, q_rd_ptr, q_wr_ptr);
    return_on_error(status);

    // Assume stuck is non-empty and the queue ptrs have not moved since last polling.
    if (q_rd_ptr == q_wr_ptr) {
        out_state = pfc_queue_state_e::EMPTY;
    } else if ((q_rd_ptr == m_prev_oq_rd_ptr[pfc_priority]) && (q_wr_ptr == m_prev_oq_wr_ptr[pfc_priority])) {
        out_state = pfc_queue_state_e::NOT_TRANSMITTING;
    } else {
        out_state = pfc_queue_state_e::TRANSMITTING;
    }

    status = get_pfc_status(pfc_priority, out_pfc_rx);
    return_on_error(status);

    if ((out_state == pfc_queue_state_e::NOT_TRANSMITTING) && out_pfc_rx) {
        // Modify the state if we received PFC BP in the last polling time.
        out_state = pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC;
    }

    // Cache the queue ptr.
    m_prev_oq_rd_ptr[pfc_priority] = q_rd_ptr;
    m_prev_oq_wr_ptr[pfc_priority] = q_wr_ptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::pfc_watchdog_notify(la_pfc_priority_t pfc_priority, bool detected)
{
    auto notification_desc = la_notification_desc();
    bzero(&notification_desc, sizeof(notification_desc));
    notification_desc.type = la_notification_type_e::PFC_WATCHDOG;
    notification_desc.u.pfc_watchdog.slice_id = get_slice();
    notification_desc.u.pfc_watchdog.ifg_id = get_ifg();
    notification_desc.u.pfc_watchdog.first_serdes_id = get_first_serdes_id();
    notification_desc.u.pfc_watchdog.pfc_priority = pfc_priority;
    notification_desc.u.pfc_watchdog.detected = detected;

    m_device->get_notificator()->notify(notification_desc, hld_notification_base::notification_pipe_e::CRITICAL);

    return LA_STATUS_SUCCESS;
}

bool
la_mac_port_base::check_pfc_watchdog(std::chrono::microseconds interval)
{
    la_status status;

    for (la_pfc_priority_t pfc_priority = 0; pfc_priority < LA_NUM_PFC_PRIORITY_CLASSES; pfc_priority++) {
        // Skip if not montoring this class.
        if (m_pfc_watchdog_oqs[pfc_priority] == 0) {
            continue;
        }
        // Get the state of the output queue.
        pfc_queue_state_e state = pfc_queue_state_e::EMPTY;
        bool pfc_rx = false;
        status = get_oqueue_state(pfc_priority, state, pfc_rx);
        // If the call failed assume not stuck and try again next polling time.
        if (status != LA_STATUS_SUCCESS) {
            state = pfc_queue_state_e::EMPTY;
        }

        pfc_config_queue_state_e cfg_state = m_queue_transmit_state[pfc_priority];
        switch (cfg_state) {
        case pfc_config_queue_state_e::ACTIVE:
            // Reset time if the state is not stuck.
            if (state != pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC) {
                m_watchdog_countdown[pfc_priority] = m_pfc_watchdog_polling_interval_ms[pfc_priority];
                continue;
            }

            // Check if the queue has been stuck for the configured period.
            m_watchdog_countdown[pfc_priority] -= interval;
            if (m_watchdog_countdown[pfc_priority] > std::chrono::microseconds(0)) {
                // keep polling
                continue;
            }

            // Notify that this PFC priority is stuck.
            pfc_watchdog_notify(pfc_priority, true);

            // No need to monitor this pfc_priority anymore.
            m_pfc_watchdog_oqs[pfc_priority] = 0;
            break;

        case pfc_config_queue_state_e::DROPPING:
            // Check if the queue has been stuck for the configured period.
            m_watchdog_countdown[pfc_priority] -= interval;
            if (m_watchdog_countdown[pfc_priority] > std::chrono::microseconds(0)) {
                // keep polling
                continue;
            }

            // Check if queue still stuck
            if (state == pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC) {
                m_watchdog_countdown[pfc_priority] = m_pfc_watchdog_recovery_interval_ms[pfc_priority];
                continue;
            }

            // Notify that this PFC priority is no longer stuck.
            pfc_watchdog_notify(pfc_priority, false);

            // No need to monitor this pfc_priority anymore.
            m_pfc_watchdog_oqs[pfc_priority] = 0;
            break;

        default:
            break;
        }
    }

    // Stop polling this mac_port if there are no more pfc_priority to monitor.
    return (m_pfc_watchdog_oqs.none());
}

la_status
la_mac_port_base::set_pfc_queue_watchdog_enabled(la_pfc_priority_t pfc_priority, bool enabled)
{
    start_api_call("pfc_priority=", pfc_priority, "enabled=", enabled);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // Don't allow enabling watchdog if pfc is not enabled.
    if ((!is_pfc_enabled()) && (enabled)) {
        return LA_STATUS_EINVAL;
    }

    // Don't allow enabling watchdog if there is no rx counter.
    if ((enabled) && (m_pfc_rx_counter == nullptr)) {
        return LA_STATUS_EINVAL;
    }

    if (enabled) {
        // check if this is the first pfc_priority enabled for watchdog monitoring.
        if (m_pfc_watchdog_oqs.none()) {
            // register handler for polling.
            m_device->add_pfc_watchdog_poll(m_device->get_sptr(this));
        }

        m_pfc_watchdog_oqs[pfc_priority] = 1;
        m_watchdog_countdown[pfc_priority] = m_pfc_watchdog_polling_interval_ms[pfc_priority];
        m_prev_oq_rd_ptr[pfc_priority] = INVALID_OQ_PTR;
        m_prev_oq_wr_ptr[pfc_priority] = INVALID_OQ_PTR;

    } else {
        m_pfc_watchdog_oqs[pfc_priority] = 0;

        // check if this was the last pfc_priority enabled for watchdog monitoring.
        if (m_pfc_watchdog_oqs.none()) {
            m_device->remove_pfc_watchdog_poll(m_device->get_sptr(this));
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_watchdog_polling_interval(std::chrono::milliseconds polling_interval)
{
    start_api_call("polling_interval=", polling_interval);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    for (la_pfc_priority_t tc = 0; tc < LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        m_pfc_watchdog_polling_interval_ms[tc] = polling_interval;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_watchdog_polling_interval(std::chrono::milliseconds& out_interval) const
{
    start_api_getter_call();

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // When requesting the polling interval w/o a pfc_priority, it
    // indicates that all the polling intervals on this port are identical.
    out_interval = m_pfc_watchdog_polling_interval_ms[0];
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_queue_watchdog_polling_interval(la_pfc_priority_t pfc_priority,
                                                          std::chrono::milliseconds polling_interval)
{
    start_api_call("pfc_priority=", pfc_priority, "polling_interval=", polling_interval);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_pfc_watchdog_polling_interval_ms[pfc_priority] = polling_interval;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_queue_watchdog_polling_interval(la_pfc_priority_t pfc_priority,
                                                          std::chrono::milliseconds& out_interval) const
{
    start_api_getter_call("pfc_priority=", pfc_priority);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    out_interval = m_pfc_watchdog_polling_interval_ms[pfc_priority];
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_watchdog_recovery_interval(std::chrono::milliseconds recovery_interval)
{
    start_api_call("recovery_interval=", recovery_interval);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    for (la_pfc_priority_t tc = 0; tc < LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        m_pfc_watchdog_recovery_interval_ms[tc] = recovery_interval;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_watchdog_recovery_interval(std::chrono::milliseconds& out_interval) const
{
    start_api_getter_call();

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // When requesting the recovery interval w/o a pfc_priority, it
    // indicates that all the recovery intervals on this port are identical.
    out_interval = m_pfc_watchdog_recovery_interval_ms[0];
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_queue_watchdog_recovery_interval(la_pfc_priority_t pfc_priority,
                                                           std::chrono::milliseconds recovery_interval)
{
    start_api_call("pfc_priority=", pfc_priority, "recovery_interval=", recovery_interval);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_pfc_watchdog_recovery_interval_ms[pfc_priority] = recovery_interval;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_queue_watchdog_recovery_interval(la_pfc_priority_t pfc_priority,
                                                           std::chrono::milliseconds& out_interval) const
{
    start_api_getter_call("pfc_priority=", pfc_priority);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // When requesting the recovery interval w/o a pfc_priority, it
    // indicates that all the recovery intervals on this port are identical.
    out_interval = m_pfc_watchdog_recovery_interval_ms[pfc_priority];
    return LA_STATUS_SUCCESS;
}

bool
la_mac_port_base::is_pfc_enabled()
{
    return ((m_sw_pfc_enabled) || (m_pfc_enabled));
}

la_status
la_mac_port_base::get_pfc_queue_watchdog_enabled(la_pfc_priority_t pfc_priority, bool& out_enabled) const
{
    start_api_getter_call("pfc_priority=", pfc_priority);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    out_enabled = m_pfc_watchdog_oqs[pfc_priority];

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_read_pfc_queue_drain_counter(la_pfc_priority_t pfc_priority, bool clear_on_read, size_t& out_dropped_packets)
{
    output_queue_counters uc_counters{};

    out_dropped_packets = m_dropped_packets[pfc_priority];

    // Read from hw only if we have allocated a counter and state is DROPPING.
    if (is_oq_drop_counter_set_valid(m_counter_set[pfc_priority])
        && m_queue_transmit_state[pfc_priority] == pfc_config_queue_state_e::DROPPING) {
        la_status status = read_oq_uc_counters(m_counter_set[pfc_priority], uc_counters);
        return_on_error(status);
    }

    // Note that total_count is the total dropped packets.
    out_dropped_packets += uc_counters.enqueue_packets;

    if (clear_on_read) {
        // Clear the cached value.
        m_dropped_packets[pfc_priority] = 0;
    } else {
        m_dropped_packets[pfc_priority] = out_dropped_packets;
    }

    // Update Unicast counters
    m_uc_oq_counters[pfc_priority].drop_bytes += uc_counters.drop_bytes;
    m_uc_oq_counters[pfc_priority].enqueue_bytes += uc_counters.enqueue_bytes;
    m_uc_oq_counters[pfc_priority].drop_packets += uc_counters.drop_packets;
    m_uc_oq_counters[pfc_priority].enqueue_packets += uc_counters.enqueue_packets;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_pfc_queue_drain_counter(la_pfc_priority_t pfc_priority, bool clear_on_read, size_t& out_dropped_packets)
{
    start_api_getter_call("pfc_priority=", pfc_priority, "clear_on_read=", clear_on_read);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // Don't allow if pfc is not enabled.
    if (!is_pfc_enabled()) {
        return LA_STATUS_EINVAL;
    }

    la_status status = do_read_pfc_queue_drain_counter(pfc_priority, clear_on_read, out_dropped_packets);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_read_output_queue_uc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_uc_counters)
{
    output_queue_counters uc_counters{};

    out_uc_counters = m_uc_oq_counters[oq_id];

    // Read from hw only if we have allocated a counter.
    if (is_oq_drop_counter_set_valid(m_counter_set[oq_id])) {
        la_status status = read_oq_uc_counters(m_counter_set[oq_id], uc_counters);
        return_on_error(status);
    }

    out_uc_counters.drop_bytes += uc_counters.drop_bytes;
    out_uc_counters.enqueue_bytes += uc_counters.enqueue_bytes;
    out_uc_counters.drop_packets += uc_counters.drop_packets;
    out_uc_counters.enqueue_packets += uc_counters.enqueue_packets;

    if (clear_on_read) {
        // Clear the cached value.
        m_uc_oq_counters[oq_id] = {};
    } else {
        m_uc_oq_counters[oq_id] = out_uc_counters;
    }

    // Update unicast drain counters if transmit state is DROPPING.
    if (pfc_config_queue_state_e::DROPPING == m_queue_transmit_state[oq_id]) {
        // Note that total_count is the total dropped packets.
        m_dropped_packets[oq_id] += uc_counters.enqueue_packets;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_set_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                              const la_rx_cgm_sq_profile_impl_wptr& profile,
                                              la_uint_t group_index,
                                              la_uint_t drop_counter_index)
{
    // Allocate on new slice
    la_slice_ifg ifg = {.slice = m_slice_id, .ifg = m_ifg_id};
    la_status status = profile->add_ifg(ifg);
    return_on_error(status);

    la_uint_t profile_id = profile->get_internal_id(m_slice_id);
    if (profile_id == (la_uint_t)-1) {
        // Invalid ID - should not occur
        return LA_STATUS_EUNKNOWN;
    }

    for (size_t serdes = m_serdes_base_id; serdes < m_serdes_base_id + m_serdes_count; serdes++) {
        status = m_device->m_rx_cgm_handler->set_rx_cgm_sq_mapping(
            m_slice_id, m_ifg_id, serdes, tc, profile_id, group_index, drop_counter_index);
        return_on_error(status);
    }

    auto it = m_tc_sq_mapping.find(tc);
    if (it != m_tc_sq_mapping.end()) {
        const la_rx_cgm_sq_profile_impl_wptr& old_profile = it->second.profile;
        dassert_crit(old_profile != nullptr);
        la_slice_ifg ifg = {.slice = m_slice_id, .ifg = m_ifg_id};
        status = old_profile->remove_ifg(ifg);
        return_on_error(status);
        if (!old_profile->is_default()) {
            m_device->remove_object_dependency(old_profile, this);
        }
    }

    m_tc_sq_mapping[tc] = {.profile = profile, .group_index = group_index, .drop_counter_index = drop_counter_index};

    if (!profile->is_default()) {
        m_device->add_object_dependency(profile, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                           la_rx_cgm_sq_profile* profile,
                                           la_uint_t group_index,
                                           la_uint_t drop_counter_index)
{
    start_api_call("tc=", tc, "profile=", profile, "group_index=", group_index, "drop_counter_index=", drop_counter_index);

    if (profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (profile->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (tc >= NUM_TC_CLASSES || group_index >= rx_cgm_handler::LA_RX_CGM_MAX_NUM_SQ_GROUPS
        || drop_counter_index >= rx_cgm_handler::LA_RX_CGM_MAX_NUM_DROP_COUNTERS) {
        return LA_STATUS_EINVAL;
    }

    la_status status
        = do_set_tc_rx_cgm_sq_mapping(tc, m_device->get_sptr<la_rx_cgm_sq_profile_impl>(profile), group_index, drop_counter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                           la_rx_cgm_sq_profile*& out_profile,
                                           la_uint_t& out_group_index,
                                           la_uint_t& out_drop_counter_index)
{
    start_api_getter_call();

    if (tc > NUM_TC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    auto it = m_tc_sq_mapping.find(tc);
    if (it == m_tc_sq_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_profile = it->second.profile.get();
    out_group_index = it->second.group_index;
    out_drop_counter_index = it->second.drop_counter_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_oq_profile_tc_bitmap(la_uint8_t tc_bitmap)
{
    start_api_call("tc_bitmap=", tc_bitmap);

    la_status status = m_scheduler->set_pfc_oq_profiles(tc_bitmap);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_oq_profile_tc_bitmap(la_uint8_t& out_tc_bitmap)
{
    start_api_getter_call();

    la_uint8_t bitmap;

    la_status status = m_scheduler->get_pfc_oq_profiles(bitmap);
    return_on_error(status);

    out_tc_bitmap = bitmap;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_output_queue_uc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_counters)
{
    start_api_getter_call("oq_id=", oq_id, "clear_on_read=", clear_on_read);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status status = do_read_output_queue_uc_counter(oq_id, clear_on_read, out_counters);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_pfc_enable(la_uint8_t tc_bitmap)
{
    la_status status = set_sq_map_table_priority(0 /* Priority Mode */);
    return_on_error(status);

    status = set_ssp_sub_port_map();
    return_on_error(status);

    status = set_source_if_to_port_map_fc_enable(true /* FC enable */);
    return_on_error(status);

    status = set_fcm_prio_map_bitmap(tc_bitmap);
    return_on_error(status);

    status = m_scheduler->set_pfc(true);
    return_on_error(status);

    for (auto port : m_mac_pool_port) {
        status = port->set_xoff_timer_settings(tc_bitmap, m_pfc_quanta);
        return_on_error(status);

        status = port->set_xon_timer_settings(tc_bitmap, 0 /* Xon timer value */);
        return_on_error(status);
    }

    status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_periodic_int_enable(m_serdes_base_id, m_serdes_count, true);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_read_output_queue_mc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_mc_counters)
{
    output_queue_counters mc_counters{};

    out_mc_counters = m_mc_oq_counters[oq_id];

    // Read from hw only if we have allocated a counter.
    if (is_oq_drop_counter_set_valid(m_counter_set[oq_id])) {
        la_status status = read_oq_mc_counters(m_counter_set[oq_id], mc_counters);
        return_on_error(status);
    }

    out_mc_counters.drop_bytes += mc_counters.drop_bytes;
    out_mc_counters.enqueue_bytes += mc_counters.enqueue_bytes;
    out_mc_counters.drop_packets += mc_counters.drop_packets;
    out_mc_counters.enqueue_packets += mc_counters.enqueue_packets;

    if (clear_on_read) {
        // Clear the cached value.
        m_mc_oq_counters[oq_id] = {};
    } else {
        m_mc_oq_counters[oq_id] = out_mc_counters;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_pfc_disable()
{
    la_status status
        = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_periodic_int_enable(m_serdes_base_id, m_serdes_count, false);
    return_on_error(status);

    status = set_sq_map_table_priority(2 /* No priority(0) Mode */);
    return_on_error(status);

    status = set_source_if_to_port_map_fc_enable(false /* FC enable */);
    return_on_error(status);

    status = set_fcm_prio_map_bitmap(0 /* TC bitmap */);
    return_on_error(status);

    status = m_scheduler->set_pfc(false);
    return_on_error(status);

    for (auto port : m_mac_pool_port) {
        status = port->set_xoff_timer_settings(0 /* No priorities enabled */, m_pfc_quanta);
        return_on_error(status);

        status = port->set_xon_timer_settings(0 /* No priorities enabled */, 0 /* Xon timer value */);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_src_mac(la_mac_addr_t mac_addr)
{
    for (auto port : m_mac_pool_port) {
        la_status status = port->set_control_tx_mac_src(mac_addr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::read_output_queue_mc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_counters)
{
    start_api_getter_call("oq_id=", oq_id, "clear_on_read=", clear_on_read);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status status = do_read_output_queue_mc_counter(oq_id, clear_on_read, out_counters);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_periodic_timer(std::chrono::nanoseconds period)
{
    start_api_call("period=", period);

    // convert time to a quanta value - 512b at line rate
    la_rate_t speed = la_2_port_speed(m_speed);
    uint32_t quanta = period.count() * speed / NUM_PFC_QUANTA_BITS;
    if (quanta >= MAX_PFC_QUANTA) {
        quanta = MAX_PFC_QUANTA;
    }

    la_status status
        = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->set_port_periodic_timer_value(m_serdes_base_id, m_serdes_count, quanta);
    return_on_error(status);

    m_pfc_periodic_timer_value = period;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_periodic_timer(std::chrono::nanoseconds& out_period)
{
    start_api_getter_call();

    out_period = m_pfc_periodic_timer_value;

    return LA_STATUS_SUCCESS;
}

la_uint_t
la_mac_port_base::get_base_oq() const
{
    return (m_ifg_id * NUM_OQ_PER_IFG + m_pif_base_id * NUM_OQ_PER_PIF);
}

la_status
la_mac_port_base::do_allocate_counter(la_oq_id_t oq_id)
{
    la_status status;

    // Check if the current counter_set is already allocated.
    if (is_oq_drop_counter_set_valid(m_counter_set[oq_id])) {
        // If the counter was already allocated, we just return success.
        return LA_STATUS_SUCCESS;
    }

    size_t counter_set_idx = INVALID_COUNTER_SET_IDX;
    bool allocated = m_device->m_index_generators.slice[m_slice_id].oq_drain_counters.allocate(counter_set_idx);

    m_counter_set[oq_id] = counter_set_idx;

    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    status = set_oq_counter_set(oq_id, counter_set_idx);
    return_on_error(status);

    // Clear the unicast counter.
    output_queue_counters oq_uc_counter;
    status = read_oq_uc_counters(counter_set_idx, oq_uc_counter);
    return_on_error(status);

    // Clear the multicast counter.
    output_queue_counters oq_mc_counter;
    status = read_oq_mc_counters(counter_set_idx, oq_mc_counter);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::allocate_counter(la_oq_id_t oq_id)
{
    start_api_call("oq_id=", oq_id);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status status = do_allocate_counter(oq_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::do_deallocate_counter(la_oq_id_t oq_id)
{
    // Set the oq counter to counter_set 0 which is the default.
    la_status status = set_oq_counter_set(oq_id, 0);
    return_on_error(status);

    // Check if the current counter_set is in the valid range.
    if (!is_oq_drop_counter_set_valid(m_counter_set[oq_id])) {
        // If the counter was not allocated, we just return success.
        m_counter_set[oq_id] = INVALID_COUNTER_SET_IDX;
        return LA_STATUS_SUCCESS;
    }

    // Cache the final count before releasing.
    output_queue_counters oq_uc_counter;
    size_t drop_packets;
    if (pfc_config_queue_state_e::DROPPING == m_queue_transmit_state[oq_id]) {
        status = do_read_pfc_queue_drain_counter(oq_id, false /*clear_on_read*/, drop_packets);
        return_on_error(status);
    } else {
        status = do_read_output_queue_uc_counter(oq_id, false /*clear_on_read*/, oq_uc_counter);
        return_on_error(status);
    }

    output_queue_counters oq_mc_counter;
    status = do_read_output_queue_mc_counter(oq_id, false /*clear_on_read*/, oq_mc_counter);

    m_device->m_index_generators.slice[m_slice_id].oq_drain_counters.release(m_counter_set[oq_id]);
    m_counter_set[oq_id] = INVALID_COUNTER_SET_IDX;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::deallocate_counter(la_oq_id_t oq_id)
{
    la_status status;

    start_api_call("oq_id=", oq_id);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    status = do_deallocate_counter(oq_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_queue_configured_state(la_pfc_priority_t pfc_priority,
                                                 pfc_config_queue_state_e state,
                                                 bool& out_counter_allocated)
{
    start_api_call("pfc_priority=", pfc_priority, "state=", state);

    out_counter_allocated = false;

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // Don't allow if pfc is not enabled.
    if (!is_pfc_enabled()) {
        return LA_STATUS_EINVAL;
    }

    la_status status;
    auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();

    switch (state) {
    case pfc_config_queue_state_e::ACTIVE:
        // remove the filter entry
        m_device->set_pfc_watchdog_filter(sp->get_gid(), pfc_priority, m_slice_id, false /*enable*/);

        // When we are enabling the queue, deallocate the drain counters.
        status = do_deallocate_counter(pfc_priority);
        return_on_error(status);
        break;
    case pfc_config_queue_state_e::DROPPING:
        // add a filter entry
        m_device->set_pfc_watchdog_filter(sp->get_gid(), pfc_priority, m_slice_id, true /*enable*/);

        // On disable, allocate the drain counter.
        status = do_allocate_counter(pfc_priority);
        if (status == LA_STATUS_SUCCESS) {
            out_counter_allocated = true;
        } else if (status != LA_STATUS_ERESOURCE) {
            // If we did not allocate a counter, then don't return error.
            return_on_error(status);
        }

        // If recovery interval set, then start pfc watchdog polling again
        // to monitor for queue recovered from PFC stuck state.
        if (m_pfc_watchdog_recovery_interval_ms[pfc_priority] != std::chrono::milliseconds(0)) {
            m_watchdog_countdown[pfc_priority] = m_pfc_watchdog_recovery_interval_ms[pfc_priority];
            m_pfc_watchdog_oqs[pfc_priority] = 1;
        }
        break;
    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    status = set_oqueue_state(pfc_priority, state);
    return_on_error(status);

    m_queue_transmit_state[pfc_priority] = state;
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_queue_configured_state(la_pfc_priority_t pfc_priority,
                                                 pfc_config_queue_state_e& out_state,
                                                 bool& out_counter_allocated)
{
    start_api_getter_call("pfc_priority=", pfc_priority);
    out_counter_allocated = false;

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    out_counter_allocated = is_oq_drop_counter_set_valid(m_counter_set[pfc_priority]);
    out_state = m_queue_transmit_state[pfc_priority];
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::get_pfc_queue_state(la_pfc_priority_t pfc_priority, pfc_queue_state_e& out_state)
{
    start_api_getter_call("pfc_priority=", pfc_priority);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status status;
    bool pfc_rx = false;

    status = get_oqueue_state(pfc_priority, out_state, pfc_rx);
    return_on_error(status);

    // If the application is polling the queue state it means that
    // this priority watchdogged. We do not want to resume unless we
    // are not receiving any PFC packets. Set the state  to stuck if
    // the queue is empty but we are still receiving BP due to PFC.
    if (pfc_rx && (out_state == pfc_queue_state_e::EMPTY)) {
        out_state = pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::set_pfc_ssp_slice_table(bool enabled)
{
    la_status status = LA_STATUS_SUCCESS;
    const auto& table(m_device->m_tables.pfc_ssp_slice_map_table);
    npl_pfc_ssp_slice_map_table_t::key_type key;
    npl_pfc_ssp_slice_map_table_t::key_type mask;
    npl_pfc_ssp_slice_map_table_t::entry_pointer_type out_entry = nullptr;
    size_t location = 0;

    auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();
    key.ssp = sp->get_gid();
    mask.ssp = 0xffff;

    if (enabled) {
        npl_pfc_ssp_slice_map_table_t::value_type value;

        // Note that we allocate 2 MP entries per session.
        value.payloads.pfc_ssp_info.mp_id = m_npuh_id * 2;
        value.payloads.pfc_ssp_info.slice = m_slice_id;

        status = table->locate_first_free_entry(location);

        if (status != LA_STATUS_SUCCESS) {
            if (status == LA_STATUS_ENOTFOUND) {
                return LA_STATUS_ERESOURCE;
            }
            return status;
        }

        status = table->insert(location, key, mask, value, out_entry);
        return_on_error(status);
    } else {
        status = table->find(key, mask, out_entry, location);
        return_on_error(status);

        status = table->erase(location);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::update_pfc_table()
{
    transaction txn;

    if (is_pfc_enabled()) {
        if (!m_npuh_id) {
            m_npuh_id = index_handle(m_device->m_index_generators.npuh_mep_ids);
            if (!m_npuh_id) {
                log_err(HLD, "Out of internal NPU host ids");
                return LA_STATUS_ERESOURCE;
            }
        }

        txn.status = update_mp_table();
        return_on_error(txn.status);
    } else {
        txn.status = erase_mp_entry();
        return_on_error(txn.status);
    }

    return txn.status;
}

la_status
la_mac_port_base::populate_mp_data_payload(npl_pfc_mp_table_shared_payload_t& out_payload)
{
    out_payload.inj_header.inject_header_type = NPL_INJECT_HEADER_TYPE_DOWN_RX_COUNT;

    auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();
    if (sp == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (m_pfc_tx_meter) {
        auto counter_ptr = populate_counter_ptr_slice(m_pfc_tx_meter, sp->get_slice(), COUNTER_DIRECTION_INGRESS);
        out_payload.inj_header.inject_header_specific_data.inject_header_app_specific_data.counter_ptr = counter_ptr;
    }

    auto& inject_down = out_payload.inj_header.inject_header_specific_data.inject_header_app_specific_data.inject_specific_data
                            .inject_data.inject_down_u.inject_down;
    inject_down.inject_down_encap_type = NPL_INJECT_DOWN_ENCAP_TYPE_NONE;
    inject_down.inject_phb.tc = 7; // Hardcode to 7

    auto dest = get_destination_id(sp, RESOLUTION_STEP_FIRST);

    inject_down.inject_destination.val = dest.val;

    if (sp) {
        // always use IFG 1 for inject
        out_payload.inject_ifg_id = sp->get_slice() * NUM_IFGS_PER_SLICE + 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::update_mp_table()
{
    npl_mp_data_table_t::key_type k{};
    npl_mp_data_table_t::value_type v{};
    npl_mp_data_table_t::entry_pointer_type e = nullptr;

    // Note that we allocate 2 MP entries per session.
    k.line_id.id = m_npuh_id * 2;

    la_status status = populate_mp_data_payload(v.payloads.mp_data_result.npu_host_mp_data.npu_host_mp_data.host_data
                                                    .overload_union_app_defined.app.mp_rd_data.mp_data_union.pfc);

    return_on_error(status);
    v.payloads.mp_data_result.aux_ptr = m_npuh_id;

    status = m_device->m_tables.mp_data_table->set(k, v, e);
    return_on_error(status);

    {
        /* Update the aux table */
        npl_mp_aux_data_table_t::key_type k{};
        npl_mp_aux_data_table_t::value_type v{};
        npl_mp_aux_data_table_t::entry_pointer_type e = nullptr;

        auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();

        if (sp == nullptr) {
            return LA_STATUS_ENOTFOUND;
        }

        k.aux_table_key.rd_address = m_npuh_id;

        auto payload = npl_pfc_aux_payload_t();
        payload.rx_counter = populate_counter_ptr_slice(m_pfc_rx_counter, sp->get_slice(), COUNTER_DIRECTION_INGRESS);
        v.payloads.aux_table_result.unpack(payload.pack()); // Can we have proper result structure?
        status = m_device->m_tables.mp_aux_data_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::erase_mp_entry()
{
    npl_mp_data_table_t::key_type k{};
    npl_mp_data_table_t::value_type v{};
    npl_mp_data_table_t::entry_pointer_type e = nullptr;

    k.line_id.id = m_npuh_id * 2;

    // Clear out the entry
    m_device->m_tables.mp_data_table->set(k, v, e);

    la_status status = m_device->m_tables.mp_data_table->erase(k);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    {
        /* Erase the aux table */
        npl_mp_aux_data_table_t::key_type k{};

        k.aux_table_key.rd_address = m_npuh_id;
        status = m_device->m_tables.mp_aux_data_table->erase(k);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_base::tx_refresh()
{
    start_api_call("");

    for (const auto& port : m_mac_pool_port) {
        la_status status = port->tx_refresh();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}
}
