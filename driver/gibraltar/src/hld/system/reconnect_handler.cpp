// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "reconnect_handler.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "la_device_impl.h"
#include "la_fabric_port_impl.h"
#include "la_strings.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "mac_pool_port.h"
#include "system/ifg_handler.h"
#include "system/slice_id_manager_base.h"

#include <cstddef>
#include <sstream>

using namespace std;

namespace silicon_one
{

static_assert(sizeof(reconnect_metadata::lc_to_min_links) == la_device_impl::MAX_DEVICES, "size mismatch");

// Convert metadata string that is not necessarily \0 terminated to a \0 terminated std::string.
template <size_t N>
std::string
buffer_to_string(const char (&buffer)[N])
{
    // Invoke string c'tor that takes first,last iterators as its arguments.
    return std::string(std::begin(buffer), std::end(buffer));
}

reconnect_handler::reconnect_handler(const la_device_impl_wptr& device)
    : m_device(device),
      m_ll_device(device->m_ll_device),
      m_in_flight_nesting_level(0),
      m_reconnect_in_progress(false),
      m_store_to_device_enabled(false)
{
    bzero(&m_metadata, sizeof(m_metadata));

    m_css_memory
        = (m_ll_device->is_gibraltar() ? m_device->m_gb_tree->sbif->css_mem_even : m_device->m_pacific_tree->sbif->css_mem_even);
    m_metadata.magic_start = reconnect_metadata::METADATA_START_MAGIC;
    m_metadata.magic_end = reconnect_metadata::METADATA_END_MAGIC;
    m_metadata.init_phase = la_device::init_phase_e::CREATED;

    snprintf(m_metadata.sdk_version, sizeof(m_metadata.sdk_version), "%s", la_get_version_string());
}

la_status
reconnect_handler::pre_initialize_ifgs()
{
    // m_device->m_serdes_info is initialized in la_device c'tor. Copy to metadata.
    slice_ifg_vec_t all_ifgs = m_device->get_slice_id_manager()->get_all_possible_ifgs();
    for (la_slice_ifg ifg : all_ifgs) {
        la_slice_id_t slice_id = ifg.slice;
        la_ifg_id_t ifg_id = ifg.ifg;
        size_t serdes_count = m_device->m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();

        for (la_uint_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
            auto& src_serdes_info = m_device->m_serdes_info[slice_id][ifg_id][serdes_id];
            auto& dst_serdes_info = m_metadata.ifg_serdes_info[slice_id][ifg_id].serdes_info[serdes_id];

            // Must copy individual fields (no memcpy), because dst_serdes_info and src_serdes_info have a different layout.
            dst_serdes_info.rx_source = src_serdes_info.rx_source;
            dst_serdes_info.anlt_order = src_serdes_info.anlt_order;
            dst_serdes_info.rx_polarity_inversion = src_serdes_info.rx_polarity_inversion;
            dst_serdes_info.tx_polarity_inversion = src_serdes_info.tx_polarity_inversion;
        }
    }
    return LA_STATUS_SUCCESS;
}

const la_device_impl*
reconnect_handler::get_device() const
{
    return m_device.get();
}

la_status
reconnect_handler::reconnect(bool ignore_in_flight)
{
    log_info(RECONNECT, "%s: version=%s, metadata size=0x%lx", __func__, la_get_version_string(), sizeof(reconnect_metadata));

    m_reconnect_in_progress = true;

    // Reset HW and SDK state of access engines.
    m_ll_device->reset_access_engines();

    // Terminate all writes in shadow, do not write to HW.
    m_ll_device->set_write_to_device(false);

    // All reads access HW (including non-volatile) and update the shadow.
    m_ll_device->set_shadow_read_enabled(false);

    // Read reconnect metadata from device
    la_status rc = load_from_device(ignore_in_flight);

    // Run restore sequence, with write-to-device disabled.
    rc = rc ?: restore();

    m_ll_device->set_shadow_read_enabled(true);
    m_ll_device->set_write_to_device(true);

    m_reconnect_in_progress = false;
    m_store_to_device_enabled = true;

    if (rc) {
        log_err(RECONNECT, "%s: %s", __func__, la_status2str(rc).c_str());
    } else {
        log_info(RECONNECT, "%s: OK", __func__);
    }

    return rc;
}

bool
reconnect_handler::is_reconnect_in_progress() const
{
    return m_reconnect_in_progress;
}

la_status
reconnect_handler::load_from_device(bool ignore_in_flight)
{
    log_debug(RECONNECT, "%s: entered", __func__);

    la_status rc = m_ll_device->read_memory(
        *m_css_memory, CSS_MEMORY_METADATA_BASE, sizeof(m_metadata) / 4 /* count */, sizeof(m_metadata), &m_metadata);
    return_on_error(rc, RECONNECT, ERROR, "Failed reading metadata");

    // Validate metadata
    if (m_metadata.magic_start != reconnect_metadata::METADATA_START_MAGIC) {
        log_err(RECONNECT, "%s: reconnect metadata is invalid, bad 'start' marker", __func__);
        return LA_STATUS_ENOTFOUND;
    }
    if (m_metadata.magic_end != reconnect_metadata::METADATA_END_MAGIC) {
        log_err(RECONNECT, "%s: reconnect metadata is invalid, bad 'end' marker", __func__);
        return LA_STATUS_ENOTFOUND;
    }
    if (m_metadata.in_flight.magic != reconnect_metadata::API_IN_FLIGHT_MAGIC && m_metadata.in_flight.magic != 0) {
        log_err(RECONNECT, "%s: reconnect metadata is invalid, bad 'in-flight' marker", __func__);
        return LA_STATUS_ENOTFOUND;
    }
    if (m_metadata.serdes_parameters_n > MAX_NUM_SERDES_PARAMETERS) {
        log_err(RECONNECT,
                "%s: reconnect metadata is invalid, too many serdes parameters, n=%d",
                __func__,
                m_metadata.serdes_parameters_n);
        return LA_STATUS_ENOTFOUND;
    }

    // Load serdes parameters, they appear immediately after the fixed size reconnect metadata
    m_serdes_parameters.resize(m_metadata.serdes_parameters_n);
    if (m_metadata.serdes_parameters_n) {
        size_t count = m_metadata.serdes_parameters_n * (sizeof(reconnect_metadata::serdes_parameter) / 4);
        size_t first_dword = sizeof(m_metadata) / 4;
        rc = m_ll_device->read_memory(
            *m_css_memory, CSS_MEMORY_METADATA_BASE + first_dword, count, count * 4 /* out_val_size */, m_serdes_parameters.data());
        return_on_error(rc, RECONNECT, ERROR, "Failed reading serdes parameters metadata");
    }

    log_metadata();

    // Are we in-flight?
    if (m_metadata.in_flight.magic == reconnect_metadata::API_IN_FLIGHT_MAGIC) {
        log_err(RECONNECT,
                "%s: device is dirty - an operation from previous session is in-flight: %s",
                __func__,
                buffer_to_string(m_metadata.in_flight.name).c_str());
        if (!ignore_in_flight) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    // Is this a matching SDK device?
    if (m_metadata.device_id != m_ll_device->get_device_id()) {
        log_err(RECONNECT,
                "%s: SDK device_id does not match, on-device=%d, in-sdk=%d",
                __func__,
                m_metadata.device_id,
                m_ll_device->get_device_id());
        return LA_STATUS_EUNKNOWN;
    }

    m_store_to_device_enabled = true;

    return LA_STATUS_SUCCESS;
}

void
reconnect_handler::log_metadata()
{
    size_t n_fabric_mac_ports = 0;
    size_t n_fabric_ports = 0;

    // Top level
    log_debug(RECONNECT, "%s: metadata size=%ld, metadata=%s", __func__, sizeof(m_metadata), to_string(m_metadata).c_str());

    // Fabric mac ports
    for (size_t i = 0; i < array_size(m_metadata.fabric_mac_ports); ++i) {
        const auto& port = m_metadata.fabric_mac_ports[i];
        if (!port.create_args.valid) {
            continue;
        }
        ++n_fabric_mac_ports;
        log_debug(RECONNECT, "%s: fabric_mac_port[%ld]=%s", __func__, i, to_string(port).c_str());
        if (port.create_args.has_fabric_port) {
            ++n_fabric_ports;
        }
    }
    log_debug(RECONNECT, "%s: n_fabric_mac_ports=%ld, n_fabric_ports=%ld", __func__, n_fabric_mac_ports, n_fabric_ports);
    for (la_slice_ifg ifg : m_device->get_used_ifgs()) {
        la_slice_id_t slice_id = ifg.slice;
        la_ifg_id_t ifg_id = ifg.ifg;
        size_t serdes_count = m_device->m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
        auto& ifg_serdes_info = m_metadata.ifg_serdes_info[slice_id][ifg_id];

        for (la_uint_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
            log_debug(RECONNECT,
                      "%s: serdes_info %d/%d/%d: rx_source=%d (is_set=%d), anlt_order=%d (is_set=%d), "
                      "rx_polarity_inversion=%d (is_set=%d), tx_polarity_inversion=%d (is_set=%d)",
                      __func__,
                      slice_id,
                      ifg_id,
                      serdes_id,
                      ifg_serdes_info.serdes_info[serdes_id].rx_source,
                      ifg_serdes_info.is_rx_source_set,
                      ifg_serdes_info.serdes_info[serdes_id].anlt_order,
                      ifg_serdes_info.is_anlt_order_set,
                      ifg_serdes_info.serdes_info[serdes_id].rx_polarity_inversion,
                      ifg_serdes_info.serdes_info[serdes_id].is_rx_polarity_inversion_set,
                      ifg_serdes_info.serdes_info[serdes_id].tx_polarity_inversion,
                      ifg_serdes_info.serdes_info[serdes_id].is_tx_polarity_inversion_set);
        }
    }
    for (const auto& param : m_serdes_parameters) {
        log_debug(RECONNECT, "%s: serdes_parameter=%s", __func__, silicon_one::to_string(param).c_str());
    }
    log_debug(RECONNECT, "%s: n_serdes_parameters=%ld", __func__, m_serdes_parameters.size());
}

la_status
reconnect_handler::initialize()
{
    log_debug(RECONNECT, "%s: enabling store_to_device", __func__);

    m_store_to_device_enabled = true;

    return store_to_device((const uint32_t*)&m_metadata, 0 /* first_dword */, sizeof(m_metadata) / 4 /* count */);
}

la_status
reconnect_handler::store_to_device(const uint32_t* in_val, size_t first_dword, size_t count)
{
    if (m_reconnect_in_progress || !m_store_to_device_enabled) {
        // Do not write reconnect metadata to HW during 'reconnect' itself.
        return LA_STATUS_SUCCESS;
    }

    log_xdebug(RECONNECT, "%s: first_dword=0x%lx, count=0x%lx", __func__, first_dword, count);

    return m_ll_device->write_memory(
        *m_css_memory, CSS_MEMORY_METADATA_BASE + first_dword, count, count * 4 /* in_val_sz */, in_val);
}

la_status
reconnect_handler::store_to_device(size_t i, const reconnect_metadata::serdes_parameter& param)
{
    static_assert(sizeof(param) % 4 == 0, "Must be DWORD aligned");
    size_t count = sizeof(param) / 4;

    // First dword after the fixed size reconnect_metadata
    size_t first_dword = sizeof(m_metadata) / 4;

    // serdes parameters are stored as a flat array, immediately after the fixed size reconnect_metadata
    first_dword += count * i;

    return store_to_device((const uint32_t*)&param, first_dword, count);
}

static inline bool
is_attr_set(const reconnect_metadata::fabric_mac_port& metadata, reconnect_metadata::fabric_mac_port::attr_e attr)
{
    return metadata.is_attr_set & (1 << (size_t)attr);
}

static inline void
set_attr(reconnect_metadata::fabric_mac_port& metadata, reconnect_metadata::fabric_mac_port::attr_e attr, uint8_t val)
{
    metadata.attr[(size_t)attr] = val;
    metadata.is_attr_set |= 1 << (size_t)attr;
}

string
to_string(const reconnect_metadata& metadata)
{
    stringstream ss;

    ss << "{in_flight=";
    if (metadata.in_flight.magic == reconnect_metadata::API_IN_FLIGHT_MAGIC) {
        ss << "yes|" << buffer_to_string(metadata.in_flight.name);
    } else if (metadata.in_flight.magic == 0) {
        ss << "no|" << buffer_to_string(metadata.in_flight.name);
    } else {
        ss << "unknown";
    }

    ss << ", init_phase=" << to_string(metadata.init_phase);
    ss << ", bool_device_properties={";
    for (bool property : metadata.bool_device_properties) {
        ss << to_string(property) << ", ";
    }
    ss << "}, int_device_properties={";
    for (bool property : metadata.int_device_properties) {
        ss << property << ", ";
    }
    ss << "}, ";
    ss << ", fe_fabric_reachability_enabled={ value=" << metadata.fe_fabric_reachability_enabled.value;
    ss << ", is_set=" << metadata.fe_fabric_reachability_enabled.is_set;
    ss << "}, sdk_version=" << buffer_to_string(metadata.sdk_version);

    return ss.str();
}

string
to_string(const reconnect_metadata::fabric_mac_port& metadata)
{
    stringstream ss;

    const auto& cargs = metadata.create_args;

    ss << "{ create_args={ slice/ifg/first_serdes/last_serdes=" << cargs.slice_id << "/" << cargs.ifg_id << "/"
       << cargs.first_serdes_id << "/" << cargs.last_serdes_id << ", speed=" << to_string((la_mac_port::port_speed_e)cargs.speed)
       << ", rx_fc_mode=" << to_string((la_mac_port::fc_mode_e)cargs.rx_fc_mode)
       << ", tx_fc_mode=" << to_string((la_mac_port::fc_mode_e)cargs.tx_fc_mode) << ", has_fabric_port=" << cargs.has_fabric_port
       << " }";

    ss << ", set_attributes={ ";
    for (size_t i = 0; i <= (size_t)reconnect_metadata::fabric_mac_port::attr_e::LAST; ++i) {
        if (is_attr_set(metadata, (reconnect_metadata::fabric_mac_port::attr_e)i)) {
            ss << to_string((reconnect_metadata::fabric_mac_port::attr_e)i) << "=" << (int)metadata.attr[i] << ", ";
        }
    }

    ss << "}, state=" << to_string(metadata.state) << "}";

    return ss.str();
}

string
to_string(reconnect_metadata::fabric_mac_port::attr_e attr)
{
    static const char* strs[(size_t)reconnect_metadata::fabric_mac_port::attr_e::LAST + 1] = {
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::SPEED] = "speed",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::RX_FC_MODE] = "rx_fc_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::TX_FC_MODE] = "tx_fc_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::FEC_MODE] = "fec_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::FEC_BYPASS_MODE] = "fec_bypass_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::SERDES_TUNING_MODE] = "serdes_tuning_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::SERDES_CONTINUOUS_TUNING_ENABLED]
            = "serdes_continuous_tuning_enabled",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::LINK_MANAGEMENT_ENABLED] = "link_management_enabled",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::LOOPBACK_MODE] = "loopback_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::PCS_TEST_MODE] = "pcs_test_mode",
            [(size_t)reconnect_metadata::fabric_mac_port::attr_e::PMA_TEST_MODE] = "pma_test_mode",
    };

    if ((size_t)attr >= array_size(strs)) {
        return "unknown";
    }

    return strs[(size_t)attr];
}

string
to_string(const reconnect_metadata::serdes_parameter& param)
{
    stringstream ss;

    ss << "{slice_id=" << param.slice_id;
    ss << ", ifg_id=" << param.ifg_id;
    ss << ", first_serdes_id=" << param.first_serdes_id;
    ss << ", serdes_idx=" << param.serdes_idx;
    ss << ", stage=" << (int)param.stage;
    ss << ", parameter=" << (int)param.parameter;
    ss << ", mode=" << (int)param.mode;
    ss << ", value=" << param.value;
    ss << ", is_set=" << param.is_set;
    ss << "}";

    return ss.str();
}

la_status
reconnect_handler::start_transaction_core(const char* name)
{
    ++m_in_flight_nesting_level;
    if (m_in_flight_nesting_level != 1) {
        // This is a nested transaction, do nothing.
        return LA_STATUS_SUCCESS;
    }

    // This is the outer-most transaction, update the metadata.
    m_metadata.in_flight.magic = reconnect_metadata::API_IN_FLIGHT_MAGIC;
    strncpy(m_metadata.in_flight.name, name, sizeof(m_metadata.in_flight.name));
    m_metadata.in_flight.name[sizeof(m_metadata.in_flight.name) - 1] = '\0';
    la_status rc = store_to_device(m_metadata.in_flight);

    return rc;
}

la_status
reconnect_handler::end_transaction_core()
{
    --m_in_flight_nesting_level;
    if (m_in_flight_nesting_level != 0) {
        // This is a nested transaction, do nothing.
        return LA_STATUS_SUCCESS;
    }

    // This is the outer-most transaction, update the metadata.
    m_metadata.in_flight.magic = 0;
    la_status rc = store_to_device(m_metadata.in_flight.magic);

    return rc;
}

la_status
reconnect_handler::update_device_id(la_device_id_t device_id)
{
    m_metadata.device_id = device_id;

    la_status rc = store_to_device(m_metadata.device_id);

    return rc;
}

la_status
reconnect_handler::update_init_phase(la_device::init_phase_e init_phase)
{
    m_metadata.init_phase = init_phase;

    la_status rc = store_to_device(m_metadata.init_phase);

    return rc;
}

la_status
reconnect_handler::update_device_property(la_device_property_e property, int val)
{
    la_status rc;
    device_property_type_e device_property_type = get_device_property_type(property);

    if (device_property_type == device_property_type_e::BOOLEAN) {
        auto& field = m_metadata.bool_device_properties[(int)property - (int)la_device_property_e::FIRST_BOOLEAN_PROPERTY];
        field = (bool)val;
        rc = store_to_device(field);
    } else if (device_property_type == device_property_type_e::INTEGER) {
        auto& field = m_metadata.int_device_properties[(int)property - (int)la_device_property_e::FIRST_INTEGER_PROPERTY];
        field = val;
        rc = store_to_device(field);
    } else {
        rc = LA_STATUS_EINVAL;
    }

    return rc;
}

la_status
reconnect_handler::get_fabric_mac_port_index_by_mac_port(const la_mac_port_base_wcptr& port,
                                                         size_t& out_index,
                                                         bool& out_entry_exists) const
{
    la_slice_id_t slice = port->get_slice();
    la_ifg_id_t ifg = port->get_ifg();
    la_uint_t first_serdes = port->get_first_serdes_id();

    return get_fabric_mac_port_index_by_serdes(slice, ifg, first_serdes, out_index, out_entry_exists);
}

la_status
reconnect_handler::get_fabric_mac_port_index_by_pool_port(const mac_pool_port_wcptr& port,
                                                          size_t& out_index,
                                                          bool& out_entry_exists) const
{
    la_slice_id_t slice = port->get_slice();
    la_ifg_id_t ifg = port->get_ifg();
    la_uint_t first_serdes = port->get_first_serdes_id();

    return get_fabric_mac_port_index_by_serdes(slice, ifg, first_serdes, out_index, out_entry_exists);
}

la_status
reconnect_handler::get_fabric_mac_port_index_by_serdes(la_slice_id_t slice,
                                                       la_ifg_id_t ifg,
                                                       la_uint_t first_serdes,
                                                       size_t& out_index,
                                                       bool& out_entry_exists) const
{
    la_uint_t port_num;

    la_slice_mode_e slice_mode;
    m_device->get_slice_mode(slice, slice_mode);

    bool lc_56_fabric_port_mode;
    la_status status = m_device->get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    return_on_error(status);

    if (is_network_slice(slice_mode) && !lc_56_fabric_port_mode) {
        log_debug(RECONNECT,
                  "%s: Cannot %s for slice=%d, ifg_id=%d, serdes=%d. Currently in %s mode.",
                  __func__,
                  __func__,
                  slice,
                  ifg,
                  first_serdes,
                  silicon_one::to_string(slice_mode).c_str());
        return LA_STATUS_EINVAL;
    }

    status = m_device->m_ifg_handlers[slice][ifg]->get_fabric_port_number(first_serdes, port_num);
    return_on_error(status);

    if (port_num == la_device_impl::INVALID_FABRIC_PORT_NUM) {
        log_err(HLD, "%s: slice=%d, ifg_id=%d, serdes=%d cannot be used for fabric port.", __func__, slice, ifg, first_serdes);
        return LA_STATUS_EINVAL;
    }

    out_index = port_num;
    out_entry_exists = m_metadata.fabric_mac_ports[out_index].create_args.valid == 1;
    log_debug(HLD, "%s: mac_port %d:%d:%d, index=%ld", __func__, slice, ifg, first_serdes, out_index);
    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::add_mac_port(const la_mac_port_base_wcptr& port)
{
    bool entry_exists;
    size_t index;
    la_status status = get_fabric_mac_port_index_by_mac_port(port, index, entry_exists);
    return_on_error(status);

    // When reconnecting, add_mac_port() must hit an existing entry in metadata.
    if (m_reconnect_in_progress) {
        return entry_exists ? LA_STATUS_SUCCESS : LA_STATUS_EUNKNOWN;
    }

    // During normal operation, add_mac_port() must hit an empty entry in metadata.
    if (entry_exists) {
        return LA_STATUS_EEXIST;
    }

    log_debug(RECONNECT, "%s: insert metadata for mac_port %s", __func__, to_string(port).c_str());

    auto& metadata = m_metadata.fabric_mac_ports[index];
    bzero(&metadata, sizeof(metadata));

    auto& cargs = metadata.create_args;
    cargs.valid = 1;
    cargs.slice_id = port->get_slice();
    cargs.ifg_id = port->get_ifg();
    cargs.first_serdes_id = port->get_first_serdes_id();
    cargs.last_serdes_id = cargs.first_serdes_id + port->get_num_of_serdes() - 1;

    la_mac_port::port_speed_e speed;
    port->get_speed(speed);
    cargs.speed = (uint8_t)speed;

    la_mac_port::fc_mode_e fc_mode;
    port->get_fc_mode(la_mac_port::fc_direction_e::RX, fc_mode);
    cargs.rx_fc_mode = (uint8_t)fc_mode;
    port->get_fc_mode(la_mac_port::fc_direction_e::TX, fc_mode);
    cargs.tx_fc_mode = (uint8_t)fc_mode;

    metadata.state = la_mac_port::state_e::PRE_INIT;

    la_status rc = store_to_device(metadata);

    return rc;
}

la_status
reconnect_handler::restore_mac_port_attribute(const la_mac_port_wptr& port,
                                              const reconnect_metadata::fabric_mac_port& metadata,
                                              reconnect_metadata::fabric_mac_port::attr_e attr)
{
    auto val = metadata.attr[(size_t)attr];

    switch (attr) {
    case reconnect_metadata::fabric_mac_port::attr_e::SPEED:
        return port->set_speed((la_mac_port::port_speed_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::RX_FC_MODE:
        return port->set_fc_mode(la_mac_port::fc_direction_e::RX, (la_mac_port::fc_mode_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::TX_FC_MODE:
        return port->set_fc_mode(la_mac_port::fc_direction_e::TX, (la_mac_port::fc_mode_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::FEC_MODE:
        return port->set_fec_mode((la_mac_port::fec_mode_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::FEC_BYPASS_MODE:
        return port->set_fec_bypass_mode((la_mac_port::fec_bypass_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::SERDES_TUNING_MODE:
        return port->set_serdes_tuning_mode((la_mac_port::serdes_tuning_mode_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::SERDES_CONTINUOUS_TUNING_ENABLED:
        return port->set_serdes_continuous_tuning_enabled((bool)val);
    case reconnect_metadata::fabric_mac_port::attr_e::LINK_MANAGEMENT_ENABLED:
        return port->set_link_management_enabled((bool)val);
    case reconnect_metadata::fabric_mac_port::attr_e::LOOPBACK_MODE:
        return port->set_loopback_mode((la_mac_port::loopback_mode_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::PCS_TEST_MODE:
        return port->set_pcs_test_mode((la_mac_port::pcs_test_mode_e)val);
    case reconnect_metadata::fabric_mac_port::attr_e::PMA_TEST_MODE:
        return port->set_pma_test_mode((la_mac_port::pma_test_mode_e)val);
    }

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::update_mac_port_attr(const mac_pool_port_wcptr& port,
                                        reconnect_metadata::fabric_mac_port::attr_e attr,
                                        uint8_t val)
{
    bool entry_exists;
    size_t index;
    la_status rc = get_fabric_mac_port_index_by_pool_port(port, index, entry_exists);
    return_on_error(rc);

    if (!entry_exists) {
        return LA_STATUS_ENOTFOUND;
    }

    log_debug(
        RECONNECT, "%s: update mac_port=%s, attr=%s, val=%d", __func__, to_string(port).c_str(), to_string(attr).c_str(), (int)val);

    auto& metadata = m_metadata.fabric_mac_ports[index];
    set_attr(metadata, attr, val);

    rc = store_to_device(metadata);

    return rc;
}

la_status
reconnect_handler::update_mac_port_state(const mac_pool_port_wcptr& port)
{
    bool entry_exists;
    size_t index;
    la_status rc = get_fabric_mac_port_index_by_pool_port(port, index, entry_exists);
    return_on_error(rc);
    if (!entry_exists) {
        return LA_STATUS_ENOTFOUND;
    }

    auto& metadata = m_metadata.fabric_mac_ports[index];
    metadata.state = port->get_state();

    log_debug(RECONNECT, "%s: mac_port=%s, state=%s", __func__, to_string(port).c_str(), to_string(metadata.state).c_str());

    rc = store_to_device(metadata.state);

    return rc;
}

la_status
reconnect_handler::remove_mac_port(const la_mac_port_base_wcptr& port)
{
    log_debug(RECONNECT, "%s: remove metadata for mac_port %s", __func__, to_string(port).c_str());

    bool entry_exists;
    size_t index;
    la_status rc = get_fabric_mac_port_index_by_mac_port(port, index, entry_exists);
    return_on_error(rc);
    if (!entry_exists) {
        return LA_STATUS_ENOTFOUND;
    }

    // Clear serdes parameters for this mac port.
    // The serdes parameters are stored in soft context as std::vector and in HW/metadata as a variable size array.
    // Don't resize, only mark as not set.
    for (size_t param_i = 0; param_i < m_serdes_parameters.size(); ++param_i) {
        auto& param = m_serdes_parameters[param_i];
        if (param.slice_id != port->get_slice() || param.ifg_id != port->get_ifg()
            || param.first_serdes_id != port->get_first_serdes_id()) {
            continue;
        }
        param.is_set = 0;
        rc = store_to_device(param_i, param);
        return_on_error(rc);
    }

    // Clear the mac port
    auto& metadata = m_metadata.fabric_mac_ports[index];
    metadata.create_args.valid = 0;

    rc = store_to_device(metadata.create_args);

    return rc;
}

la_status
reconnect_handler::add_fabric_port(const la_fabric_port_wcptr& fabric_port)
{
    auto mac_port = m_device->get_sptr(static_cast<const la_mac_port_base*>(fabric_port->get_mac_port()));

    bool entry_exists;
    size_t index;
    la_status rc = get_fabric_mac_port_index_by_mac_port(mac_port, index, entry_exists);
    return_on_error(rc);

    if (!entry_exists) {
        return LA_STATUS_ENOTFOUND;
    }

    if (m_reconnect_in_progress) {
        return LA_STATUS_SUCCESS;
    }

    auto& metadata = m_metadata.fabric_mac_ports[index];
    if (metadata.create_args.has_fabric_port) {
        log_err(RECONNECT, "%s: mac_port %s already has a fabric port", __func__, to_string(mac_port).c_str());
        return LA_STATUS_EEXIST;
    }

    metadata.create_args.has_fabric_port = 1;

    rc = store_to_device(metadata.create_args);

    return rc;
}

la_status
reconnect_handler::remove_fabric_port(const la_fabric_port_wcptr& fabric_port)
{
    bool entry_exists;
    size_t index;
    auto mac_port = static_cast<const la_mac_port_base*>(fabric_port->get_mac_port());
    auto mac_port_sptr = m_device->get_sptr(mac_port);
    la_status rc = get_fabric_mac_port_index_by_mac_port(mac_port_sptr, index, entry_exists);
    return_on_error(rc);
    if (!entry_exists) {
        return LA_STATUS_ENOTFOUND;
    }

    auto& metadata = m_metadata.fabric_mac_ports[index];
    metadata.create_args.has_fabric_port = 0;

    rc = store_to_device(metadata.create_args);

    return rc;
}

la_status
reconnect_handler::update_serdes_mapping(la_slice_id_t slice_id,
                                         la_ifg_id_t ifg_id,
                                         la_serdes_direction_e direction,
                                         std::vector<la_uint_t> serdes_mapping_vec)
{
    size_t num_serdes = 0;
    la_status rc = m_device->get_num_of_serdes(slice_id, ifg_id, num_serdes);
    return_on_error(rc);

    auto& ifg_serdes_info = m_metadata.ifg_serdes_info[slice_id][ifg_id];

    if (direction == la_serdes_direction_e::RX) {
        ifg_serdes_info.is_rx_source_set = 1;
    } else {
        ifg_serdes_info.is_anlt_order_set = 1;
    }

    for (size_t serdes_id = 0; serdes_id < num_serdes; serdes_id++) {
        if (direction == la_serdes_direction_e::RX) {
            ifg_serdes_info.serdes_info[serdes_id].rx_source = serdes_mapping_vec[serdes_id];
        } else {
            ifg_serdes_info.serdes_info[serdes_id].anlt_order = serdes_mapping_vec[serdes_id];
        }
    }
    rc = store_to_device(m_metadata.ifg_serdes_info);

    return rc;
}

la_status
reconnect_handler::update_serdes_polarity_inversion(la_slice_id_t slice_id,
                                                    la_ifg_id_t ifg_id,
                                                    la_uint_t serdes_id,
                                                    la_serdes_direction_e direction,
                                                    bool invert)
{
    if (direction == la_serdes_direction_e::RX) {
        m_metadata.ifg_serdes_info[slice_id][ifg_id].serdes_info[serdes_id].rx_polarity_inversion = invert ? 1 : 0;
        m_metadata.ifg_serdes_info[slice_id][ifg_id].serdes_info[serdes_id].is_rx_polarity_inversion_set = 1;
    } else {
        m_metadata.ifg_serdes_info[slice_id][ifg_id].serdes_info[serdes_id].tx_polarity_inversion = invert ? 1 : 0;
        m_metadata.ifg_serdes_info[slice_id][ifg_id].serdes_info[serdes_id].is_tx_polarity_inversion_set = 1;
    }
    la_status rc = store_to_device(m_metadata.ifg_serdes_info);

    return rc;
}

// Equality comparison, used with std::find()
inline bool
operator==(const reconnect_metadata::serdes_parameter& lhs, const reconnect_metadata::serdes_parameter& rhs)
{
    return std::tie(lhs.slice_id, lhs.ifg_id, lhs.first_serdes_id, lhs.serdes_idx, lhs.stage, lhs.parameter)
           == std::tie(rhs.slice_id, rhs.ifg_id, rhs.first_serdes_id, rhs.serdes_idx, rhs.stage, rhs.parameter);
}

la_status
reconnect_handler::update_serdes_parameter(const mac_pool_port_wcptr& port,
                                           la_uint_t serdes_idx,
                                           la_mac_port::serdes_param_stage_e stage,
                                           la_mac_port::serdes_param_e parameter,
                                           la_mac_port::serdes_param_mode_e mode,
                                           int32_t value)
{
    return do_update_or_clear_serdes_parameter(port, serdes_idx, stage, parameter, mode, value, false /* clear */);
}

la_status
reconnect_handler::clear_serdes_parameter(const mac_pool_port_wcptr& port,
                                          la_uint_t serdes_idx,
                                          la_mac_port::serdes_param_stage_e stage,
                                          la_mac_port::serdes_param_e parameter)
{
    return do_update_or_clear_serdes_parameter(
        port, serdes_idx, stage, parameter, la_mac_port::serdes_param_mode_e::FIRST, -1, true /* clear */);
}

la_status
reconnect_handler::do_update_or_clear_serdes_parameter(const mac_pool_port_wcptr& port,
                                                       la_uint_t serdes_idx,
                                                       la_mac_port::serdes_param_stage_e stage,
                                                       la_mac_port::serdes_param_e parameter,
                                                       la_mac_port::serdes_param_mode_e mode,
                                                       int32_t value,
                                                       bool clear)
{
    reconnect_metadata::serdes_parameter param{.slice_id = port->get_slice(),
                                               .ifg_id = port->get_ifg(),
                                               .first_serdes_id = port->get_first_serdes_id(),
                                               .serdes_idx = (uint8_t)serdes_idx,
                                               .stage = (uint8_t)stage,
                                               .parameter = (uint8_t)parameter,
                                               .mode = (uint8_t)mode,
                                               .is_set = (uint8_t)(clear ? 0 : 1),
                                               .reserved = 0,
                                               .value = value};

    // Find serdes_parameter with a matching key
    auto it = std::find(m_serdes_parameters.begin(), m_serdes_parameters.end(), param);
    size_t param_i = std::distance(m_serdes_parameters.begin(), it);

    log_debug(RECONNECT, "%s: param_i=%ld, param=%s", __func__, param_i, to_string(param).c_str());

    // Update existing or add new
    if (it == m_serdes_parameters.end()) {
        if (clear) {
            // Nothing to do, this parameter was never set - nothing to clear.
            return LA_STATUS_SUCCESS;
        }

        m_serdes_parameters.push_back(param);
    } else {
        it->value = value;
    }

    // Write the size of the array
    m_metadata.serdes_parameters_n = m_serdes_parameters.size();
    la_status rc = store_to_device(m_metadata.serdes_parameters_n);
    return_on_error(rc);

    // Write the array itself
    rc = store_to_device(param_i, param);

    return rc;
}

la_status
reconnect_handler::update_fe_fabric_reachability_enabled(bool enabled)
{
    m_metadata.fe_fabric_reachability_enabled.value = (uint32_t)enabled;
    m_metadata.fe_fabric_reachability_enabled.is_set = 1;
    la_status rc = store_to_device(m_metadata.fe_fabric_reachability_enabled);

    return rc;
}

la_status
reconnect_handler::update_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t num_links)
{
    m_metadata.lc_to_min_links[device_id].value = num_links;
    m_metadata.lc_to_min_links[device_id].is_set = 1;

    la_status rc = store_to_device(m_metadata.lc_to_min_links);

    return rc;
}

la_status
reconnect_handler::restore()
{
    if (m_metadata.init_phase == la_device::init_phase_e::CREATED) {
        log_err(RECONNECT, "%s: device was not initialized, nothing to restore", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    // All device properties can be 'set' when la_device's init phase is CREATED.
    // At more advanced phases some restrictions apply.
    // So, we restore device properties before anything else.
    la_status rc = restore_device_properties();
    return_on_error(rc);

    rc = restore_init_phase();
    return_on_error(rc);

    rc = m_device->restore_bundles();
    return_on_error(rc);

    rc = restore_fabric_mac_ports();
    return_on_error(rc);

    rc = restore_fe_fabric_reachability();
    return_on_error(rc);

    rc = restore_minimum_fabric_links_per_lc();
    return_on_error(rc);

    rc = m_device->restore_fe_smcid_to_mcid_mapping();
    return_on_error(rc);

    rc = restore_serdes_parameters();
    return_on_error(rc);

    rc = restore_mac_port_regs();
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::restore_mac_port_regs()
{
    bit_vector bv;

    if (m_ll_device->is_gibraltar()) {
        m_css_memory = m_device->m_gb_tree->sbif->css_mem_even;

        for (la_slice_id_t slice_id : m_device->get_used_slices()) {
            lld_block::lld_block_vec_t blocks;
            for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
                size_t serdes_count = m_device->m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
                auto ifg = m_ll_device->get_gibraltar_tree()->slice[slice_id]->ifg[ifg_id];
                if (serdes_count == 24) {
                    blocks.push_back(ifg->mac_pool8[0]);
                    blocks.push_back(ifg->mac_pool8[1]);
                    blocks.push_back(ifg->mac_pool8[2]);
                    blocks.push_back(ifg->ifgb);
                } else {
                    blocks.push_back(ifg->mac_pool8[0]);
                    blocks.push_back(ifg->mac_pool8[1]);
                    blocks.push_back(ifg->ifgb);
                }
                for (auto& block : blocks) {
                    for (const auto reg : block->get_registers()) {
                        if (reg->get_desc()->type == lld_register_type_e::CONFIG) {
                            m_ll_device->read_register(*reg, bv);
                        }
                    }
                }
            }
        }
        for (const auto block : m_ll_device->get_gibraltar_tree()->get_leaf_blocks()) {
            for (const auto reg : block->get_registers()) {
                if (reg->get_desc()->type == lld_register_type_e::INTERRUPT_MASK) {
                    m_ll_device->read_register(*reg, bv);
                }
            }
        }
    } else {
        m_css_memory = m_device->m_pacific_tree->sbif->css_mem_even;
        for (const auto& slice : m_device->m_pacific_tree->slice) {
            for (const auto& ifg : slice->ifg) {
                lld_block_scptr blocks[] = {ifg->mac_pool8[0], ifg->mac_pool8[1], ifg->mac_pool2, ifg->ifgb};

                for (const auto block : blocks) {
                    for (const auto reg : block->get_registers()) {
                        if (reg->get_desc()->type == lld_register_type_e::CONFIG) {
                            m_ll_device->read_register(*reg, bv);
                        }
                    }
                }
            }
        }

        for (const auto block : m_device->m_pacific_tree->get_leaf_blocks()) {
            for (const auto reg : block->get_registers()) {
                if (reg->get_desc()->type == lld_register_type_e::INTERRUPT_MASK) {
                    m_ll_device->read_register(*reg, bv);
                }
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::restore_device_properties()
{
    log_debug(RECONNECT, "%s", __func__);

    la_status rc = LA_STATUS_SUCCESS;
    bool supported = false;

    // not all the device properities are supported across devices
    for (int i = 0; !rc && i < (int)la_device_property_e::NUM_BOOLEAN_PROPERTIES; ++i) {
        la_device_property_e prop = (la_device_property_e)((int)la_device_property_e::FIRST_BOOLEAN_PROPERTY + i);
        rc = m_device->is_property_supported(prop, supported);
        return_on_error(rc);
        if (supported) {
            rc = m_device->set_bool_property(prop, m_metadata.bool_device_properties[i]);
        }
    }

    for (int i = 0; !rc && i < (int)la_device_property_e::NUM_INTEGER_PROPERTIES; ++i) {
        la_device_property_e prop = (la_device_property_e)((int)la_device_property_e::FIRST_INTEGER_PROPERTY + i);
        // Read only Property
        if (prop == la_device_property_e::EFUSE_REFCLK_SETTINGS) {
            continue;
        }

        rc = m_device->is_property_supported(prop, supported);
        return_on_error(rc);
        if (supported) {
            rc = m_device->set_int_property(prop, m_metadata.int_device_properties[i]);
        }
    }

    return rc;
}

la_status
reconnect_handler::restore_init_phase()
{
    // Replay init(TOPOLOGY) for FABRIC mode - this is the only supported 'init' for now.

    if (m_metadata.init_phase != la_device::init_phase_e::TOPOLOGY) {
        log_debug(RECONNECT, "%s: device was not initialized with init(TOPOLOGY), cannot restore.", __func__);
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    log_debug(RECONNECT, "%s: metadata init_phase=%s", __func__, to_string(m_metadata.init_phase).c_str());

    la_status rc = m_device->initialize(la_device::init_phase_e::DEVICE);
    return_on_error_log(rc, RECONNECT, ERROR, "%s: init(DEVICE) failed", __func__);
    for (la_slice_ifg ifg : m_device->get_used_ifgs()) {
        la_slice_id_t sid = ifg.slice;
        la_ifg_id_t ifg_id = ifg.ifg;

        size_t num_serdes = 0;
        la_status rc = m_device->get_num_of_serdes(sid, ifg_id, num_serdes);
        return_on_error(rc);

        std::vector<la_uint_t> serdes_rx_mapping_vec(num_serdes);
        std::vector<la_uint_t> serdes_anlt_order_vec(num_serdes);
        const auto& ifg_serdes_info = m_metadata.ifg_serdes_info[sid][ifg_id];

        for (la_uint_t serdes_id = 0; serdes_id < num_serdes; serdes_id++) {
            if (ifg_serdes_info.serdes_info[serdes_id].is_rx_polarity_inversion_set) {
                rc = m_device->set_serdes_polarity_inversion(sid,
                                                             ifg_id,
                                                             serdes_id,
                                                             la_serdes_direction_e::RX,
                                                             ifg_serdes_info.serdes_info[serdes_id].rx_polarity_inversion);
                return_on_error(rc);
            }
            if (ifg_serdes_info.serdes_info[serdes_id].is_tx_polarity_inversion_set) {
                rc = m_device->set_serdes_polarity_inversion(sid,
                                                             ifg_id,
                                                             serdes_id,
                                                             la_serdes_direction_e::TX,
                                                             ifg_serdes_info.serdes_info[serdes_id].tx_polarity_inversion);
                return_on_error(rc);
            }
            serdes_rx_mapping_vec[serdes_id] = ifg_serdes_info.serdes_info[serdes_id].rx_source;
            serdes_anlt_order_vec[serdes_id] = ifg_serdes_info.serdes_info[serdes_id].anlt_order;
        }

        if (ifg_serdes_info.is_rx_source_set) {
            rc = m_device->set_serdes_source(sid, ifg_id, serdes_rx_mapping_vec);
            return_on_error(rc);
        }
        if (ifg_serdes_info.is_anlt_order_set) {
            rc = m_device->set_serdes_anlt_order(sid, ifg_id, serdes_anlt_order_vec);
            return_on_error(rc);
        }
    }

    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        m_device->set_slice_mode(slice_id, la_slice_mode_e::CARRIER_FABRIC);
        m_device->set_fabric_slice_clos_direction(slice_id, la_clos_direction_e::DOWN);
    }

    rc = m_device->initialize(la_device::init_phase_e::TOPOLOGY);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::restore_fabric_mac_ports()
{
    size_t count = 0;
    for (const auto& metadata : m_metadata.fabric_mac_ports) {
        if (!metadata.create_args.valid) {
            continue;
        }

        la_status rc = restore_fabric_mac_port(metadata);
        return_on_error(rc);

        ++count;
    }

    log_debug(RECONNECT, "%s: restored %ld mac ports", __func__, count);

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::restore_fabric_mac_port(const reconnect_metadata::fabric_mac_port& metadata)
{
    log_debug(RECONNECT, "%s: %s", __func__, to_string(metadata).c_str());

    // Step 1: create a mac port
    const auto& cargs = metadata.create_args;
    la_mac_port* port_ptr = nullptr;
    la_status rc = m_device->create_fabric_mac_port(cargs.slice_id,
                                                    cargs.ifg_id,
                                                    cargs.first_serdes_id,
                                                    cargs.last_serdes_id,
                                                    (la_mac_port::port_speed_e)cargs.speed,
                                                    (la_mac_port::fc_mode_e)cargs.tx_fc_mode,
                                                    port_ptr);
    return_on_error_log(rc, RECONNECT, ERROR, "%s: failed to create a mac port for %s", __func__, to_string(metadata).c_str());

    auto port = m_device->get_sptr<la_mac_port_base>(port_ptr);
    auto sid = port->get_slice();
    auto ifg_id = port->get_ifg();
    for (auto serdes_id = port->get_first_serdes_id(); serdes_id < port->get_first_serdes_id() + port->get_num_of_serdes();
         serdes_id++) {
        la_mac_port::serdes_status serdes_status;
        la_uint_t mapped_serdes_id = m_device->m_serdes_info[sid][ifg_id][serdes_id].rx_source;

        rc = port->read_serdes_status(serdes_id - port->get_first_serdes_id(), serdes_status);
        return_on_error(rc);
        log_debug(RECONNECT,
                  "%s: %d/%d/%d(%d) : SDK cached tx/rx enable status: tx_enabled %d, rx_enabled %d, device tx/rx enable "
                  "status: tx_enabled %d, rx_enabled %d",
                  __func__,
                  sid,
                  ifg_id,
                  serdes_id,
                  mapped_serdes_id,
                  m_device->m_serdes_status[sid][ifg_id][mapped_serdes_id].tx_enabled,
                  m_device->m_serdes_status[sid][ifg_id][mapped_serdes_id].rx_enabled,
                  serdes_status.tx_ready,
                  serdes_status.rx_ready);
        m_device->m_serdes_status[sid][ifg_id][serdes_id].tx_enabled = serdes_status.tx_ready;
        m_device->m_serdes_status[sid][ifg_id][mapped_serdes_id].rx_enabled = serdes_status.rx_ready;
    }

    // Step 2: Create fabric port and restore its state.
    if (cargs.has_fabric_port) {
        log_debug(RECONNECT, "%s: create_fabric_port", __func__);

        la_fabric_port* fabric_port;
        rc = m_device->create_fabric_port(port.get(), fabric_port);
        return_on_error_log(
            rc, RECONNECT, ERROR, "%s: failed to create a fabric port for %s", __func__, to_string(metadata).c_str());

        log_debug(RECONNECT, "%s: restore fabric_port's state", __func__);
        rc = static_cast<la_fabric_port_impl*>(fabric_port)->restore_state();
        return_on_error_log(
            rc, RECONNECT, ERROR, "%s: failed to restore fabric port's state, %s", __func__, to_string(metadata).c_str());

        la_fabric_port::port_status status;
        rc = fabric_port->get_status(status);
        return_on_error_log(rc, RECONNECT, ERROR, "%s: failed to get status", __func__);

        log_debug(RECONNECT, "%s: peer_detected=%d, fabric_link_up=%d", __func__, status.peer_detected, status.fabric_link_up);
    }

    log_debug(RECONNECT, "%s: restore mac_port attributes", __func__);

    // Step 3: Restore attributes - call mac_port setters
    for (size_t i = 0; !rc && i <= (size_t)reconnect_metadata::fabric_mac_port::attr_e::LAST; ++i) {
        auto attr = (reconnect_metadata::fabric_mac_port::attr_e)i;
        if (is_attr_set(metadata, attr)) {
            rc = restore_mac_port_attribute(port, metadata, attr);
            return_on_error_log(rc,
                                RECONNECT,
                                ERROR,
                                "%s: %s: failed to set attr=%s",
                                __func__,
                                to_string(metadata).c_str(),
                                to_string(attr).c_str());
        }
    }

    log_debug(RECONNECT, "%s: mac_port's state", __func__);

    // Step 4: restore mac_port's state machine
    rc = port->restore_state(metadata.state);
    return_on_error_log(rc, RECONNECT, ERROR, "%s: failed to restore a mac port %s", __func__, to_string(metadata).c_str());

    log_debug(RECONNECT, "%s: OK, %s", __func__, to_string(metadata).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::restore_fe_fabric_reachability()
{
    if (!m_metadata.fe_fabric_reachability_enabled.is_set) {
        return LA_STATUS_SUCCESS;
    }

    la_status rc = m_device->set_fe_fabric_reachability_enabled((bool)m_metadata.fe_fabric_reachability_enabled.value);

    return rc;
}

la_status
reconnect_handler::restore_minimum_fabric_links_per_lc()
{
    for (size_t device_id = 0; device_id < la_device_impl::MAX_DEVICES; ++device_id) {
        if (m_metadata.lc_to_min_links[device_id].is_set) {
            la_status rc = m_device->set_minimum_fabric_links_per_lc(device_id, m_metadata.lc_to_min_links[device_id].value);
            return_on_error(rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::restore_serdes_parameters()
{
    for (const auto& p : m_serdes_parameters) {
        log_debug(RECONNECT, "%s: serdes_parameter=%s", __func__, to_string(p).c_str());
        if (!p.is_set) {
            continue;
        }

        la_mac_port* mac_port;
        la_status rc = m_device->get_mac_port(p.slice_id, p.ifg_id, p.first_serdes_id, mac_port);
        return_on_error(rc);

        rc = mac_port->set_serdes_parameter(p.serdes_idx,
                                            (la_mac_port::serdes_param_stage_e)p.stage,
                                            (la_mac_port::serdes_param_e)p.parameter,
                                            (la_mac_port::serdes_param_mode_e)p.mode,
                                            p.value);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
reconnect_handler::enable_interrupts()
{
    // Open internal SBIF masks but close root MSI mask.
    la_status rc = m_device->init_sbif_interrupts();

    // Open CIF masks, then clear SBIF interrupts, then open root MSI mask.
    rc = rc ?: m_device->init_interrupts();

    return rc;
}

// These can be removed when moving to c++17 since then we get some
// language support for new on overaligned types.
void*
reconnect_handler::operator new(size_t nbytes)
{
    void* p = nullptr;
    const int err = posix_memalign(&p, alignof(reconnect_metadata), nbytes);
    if (err) {
        throw std::bad_alloc();
    }
    return p;
}

void
reconnect_handler::operator delete(void* p)
{
    free(p);
}

} // namespace silicon_one
