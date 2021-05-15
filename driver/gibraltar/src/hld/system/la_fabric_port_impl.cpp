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

#include "system/la_fabric_port_impl.h"
#include "nplapi/npl_constants.h"
#include "system/ifg_handler_gibraltar.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "tm/la_fabric_port_scheduler_impl.h"

#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"

#include "hld_types.h"
#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <algorithm>
#include <sstream>

using namespace std;

namespace silicon_one
{

la_fabric_port_impl::la_fabric_port_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_slice_id((la_slice_id_t)-1),
      m_ifg_id((la_ifg_id_t)-1),
      m_serdes_base((la_uint_t)-1),
      m_pif_base((la_uint_t)-1),
      m_peer_dev_id(LA_DEVICE_ID_INVALID)
{
}

la_fabric_port_impl::~la_fabric_port_impl()
{
}

la_status
la_fabric_port_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status;

    status = deactivate_peer_discovery();
    return_on_error(status);

    status = deactivate_link_keepalive();
    return_on_error(status);

    status = erase_source_pif_hw_table();
    return_on_error(status);

    status = configure_all_reachable_vector(false /*all_reachable*/);
    return_on_error(status);

    // If the system works in manual fabric routing protocol mode, then remove all reachability from this port.
    bool advertise_device_on_fabric_enabled;
    status
        = m_device->get_bool_property(la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, advertise_device_on_fabric_enabled);
    return_on_error(status);

    if (advertise_device_on_fabric_enabled == false) {
        la_device_id_vec_t emtpy_vec;
        status = configure_frm_db_fabric_routing_table(emtpy_vec);
        return_on_error(status);

        status = configure_frm_db_rev_fabric_routing_table(emtpy_vec);
        return_on_error(status);

        // Sending FRT to blocks.
        status = m_device->trigger_frt_scan();
        return_on_error(status);
    }

    if (m_scheduler != nullptr) {
        m_device->do_destroy(m_scheduler);
        m_scheduler = nullptr;
    }

    unregister_dependency(m_mac_port.get());

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::initialize(la_object_id_t oid, la_mac_port* fabric_mac_port)
{
    m_oid = oid;
    m_mac_port = m_device->get_sptr<la_mac_port_base>(fabric_mac_port);
    register_dependency(m_mac_port.get());

    m_slice_id = m_mac_port->get_slice();
    m_ifg_id = m_mac_port->get_ifg();
    m_serdes_base = m_mac_port->get_first_serdes_id();
    device_port_handler_base::fabric_data fabric_data;
    m_device->m_device_port_handler->get_fabric_data(fabric_data);
    la_uint_t fab_intf_id = m_serdes_base / fabric_data.num_serdes_per_fabric_port;

    la_fabric_port_scheduler_impl_sptr scheduler;
    auto status = m_device->create_fabric_port_scheduler(m_slice_id, m_ifg_id, fab_intf_id, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    m_pif_base = m_mac_port->get_first_pif_id();

    status = configure_source_pif_hw_table();
    return_on_error(status);

    status = configure_all_reachable_vector(true /*all_reachable*/);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_fabric_port_impl::type() const
{
    return object_type_e::FABRIC_PORT;
}

const la_device*
la_fabric_port_impl::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_fabric_port_impl::oid() const
{
    return m_oid;
}

std::string
la_fabric_port_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_fabric_port_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_fabric_port_impl::get_adjacent_peer_info(adjacent_peer_info& out_adjacent_peer_info) const
{
    start_api_getter_call();

    gibraltar::fte_peer_delay_mem_memory peer_delay;

    la_status status = get_peer_delay_mem_entry(peer_delay);
    return_on_error(status);

    if (peer_delay.fields.link_peer_delay_valid != 1) {
        return LA_STATUS_ENOTFOUND;
    }

    out_adjacent_peer_info.device_id = peer_delay.fields.link_peer_device_id;
    out_adjacent_peer_info.port_num = peer_delay.fields.link_peer_link_num;

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::set_reachable_lc_devices(const la_device_id_vec_t& device_id_vec)
{
    start_api_call("device_id_vec=", device_id_vec);

    bool advertise_device_on_fabric_enabled;
    la_status status
        = m_device->get_bool_property(la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, advertise_device_on_fabric_enabled);
    return_on_error(status);

    if (advertise_device_on_fabric_enabled) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    status = do_set_reachable_lc_devices(device_id_vec);

    return status;
}

la_status
la_fabric_port_impl::do_set_reachable_lc_devices(const la_device_id_vec_t& device_id_vec)
{
    la_status status = configure_frm_db_fabric_routing_table(device_id_vec);
    return_on_error(status);

    status = configure_frm_db_rev_fabric_routing_table(device_id_vec);
    return_on_error(status);

    // Sending FRT to blocks.
    status = m_device->trigger_frt_scan();

    return status;
}

la_status
la_fabric_port_impl::get_reachable_lc_devices(la_device_id_vec_t& out_device_id_vec) const
{
    start_api_getter_call();

    la_uint_t fabric_port_num;
    la_status status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    // In GB, the rev routing table is splitted into two tables: low_rev_fabric_routing_table and high_rev_fabric_routing_table.
    // Each table contains 256 bits, which is MAX_DEVICES/2 (as in GB we support 512 devices).
    // entry_width is the width of one entry in one of the two tables (as they are of the same width).
    size_t entry_width = gibraltar::frm_low_rev_fabric_routing_table_memory::SIZE_IN_BITS_WO_ECC;
    bit_vector low_rev_table_result(0, entry_width);
    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->dmc->frm->low_rev_fabric_routing_table, fabric_port_num, low_rev_table_result);
    return_on_error(status);

    bit_vector high_rev_table_result(0, entry_width);
    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->dmc->frm->high_rev_fabric_routing_table, fabric_port_num, high_rev_table_result);
    return_on_error(status);

    for (la_device_id_t dev = 0; dev < entry_width; dev++) {
        bool dev_reachable = low_rev_table_result.bit(dev);
        if (dev_reachable) {
            out_device_id_vec.push_back(dev);
        }
        dev_reachable = high_rev_table_result.bit(dev);
        if (dev_reachable) {
            out_device_id_vec.push_back(entry_width + dev);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_fabric_port_scheduler*
la_fabric_port_impl::get_scheduler() const
{
    start_api_getter_call();

    return m_scheduler.get();
}

la_status
la_fabric_port_impl::get_fabric_port_num_in_device(la_uint_t& out_port_num) const
{
    return m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->get_fabric_port_number(m_serdes_base, out_port_num);
}

la_status
la_fabric_port_impl::get_fabric_port_num_in_slice(la_uint_t& out_port_num_in_slice) const
{
    // The fabric port number is counted differently in LC and FE.
    // In LC, we can create fabric ports in all even serdeses in all the last 3 slices, i.e. 64 ports.
    // (20 ports in slice 3, 20 in slice 4 and 24 in slice 5).
    // These ports are mapped to the MSBs of the routing table entry bitmap, which has 108 bits.
    // Hence, the fabric ports indices in LC start from 44 up to 107.
    // In FE, there are more sedeses (128) than supported fabric ports (108), so we use subset of the serdeses,
    // such that each slice has exactly 18 ports.
    if (m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        la_uint_t port_num_in_device;
        la_status status = get_fabric_port_num_in_device(port_num_in_device);
        return_on_error(status);
        out_port_num_in_slice = port_num_in_device % NPL_NUM_FABRIC_PORTS_IN_FE_SLICE;
    } else if (m_device->m_device_mode == device_mode_e::LINECARD) {
        size_t serdes_num_in_slice = m_serdes_base;
        // Add the serdeses in previous IFGs
        for (la_ifg_id_t ifg = 0; ifg < m_ifg_id; ifg++) {
            serdes_num_in_slice += m_device->m_ifg_handlers[m_slice_id][ifg]->get_serdes_count();
        }
        device_port_handler_base::fabric_data fabric_data;
        m_device->m_device_port_handler->get_fabric_data(fabric_data);
        out_port_num_in_slice = serdes_num_in_slice / fabric_data.num_serdes_per_fabric_port;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::configure_frm_db_fabric_routing_table(const la_device_id_vec_t& device_id_vec)
{
    la_status status;
    status = configure_frm_db_fabric_routing_table_hardware(device_id_vec);
    return_on_error(status);

    status = configure_frm_db_fabric_routing_table_npl(device_id_vec);

    return status;
}

la_status
la_fabric_port_impl::configure_frm_db_fabric_routing_table_npl(const la_device_id_vec_t& device_id_vec)
{
    // The fabric_routing_table is used by the NPL to get the set of links that reach a specific device ID
    // TODO - need to add support nsim_device_simulator::handle_special_requests for this table - such that all gibraltar_tree
    // updates
    // are translated to NPL table updates, and then remove this function.

    // Sort the vector for faster lookups
    la_device_id_vec_t sorted_dev_id_vec(device_id_vec);
    sort(sorted_dev_id_vec.begin(), sorted_dev_id_vec.end());

    la_uint_t fabric_port_num;
    la_status status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    // Table access variables
    const auto& table(m_device->m_tables.frm_db_fabric_routing_table);
    npl_frm_db_fabric_routing_table_t::key_type k;
    npl_frm_db_fabric_routing_table_t::value_type v;
    npl_frm_db_fabric_routing_table_t::entry_pointer_type e = nullptr;

    for (size_t egress_device_id = 0; egress_device_id < la_device_impl::MAX_DEVICES; egress_device_id++) {
        k.egress_device_id = egress_device_id;

        // Read current value
        la_status read_status = table->lookup(k, e);
        if (read_status != LA_STATUS_ENOTFOUND && read_status != LA_STATUS_SUCCESS) {
            return read_status;
        }
        if (read_status == LA_STATUS_SUCCESS) {
            v = e->value();
        }

        // Modify
        v.action = NPL_FRM_DB_FABRIC_ROUTING_TABLE_ACTION_WRITE;

        // Indicate reachability if the current egress_device_id is reachable by this port
        if (binary_search(sorted_dev_id_vec.begin(), sorted_dev_id_vec.end(), egress_device_id)) {
            v.payloads.frm_db_fabric_routing_table_result.fabric_routing_table_data[fabric_port_num]
                = NPL_FABRIC_PORT_CAN_REACH_DEVICE_TRUE;
        } else {
            v.payloads.frm_db_fabric_routing_table_result.fabric_routing_table_data[fabric_port_num]
                = NPL_FABRIC_PORT_CAN_REACH_DEVICE_FALSE;
        }

        // Write
        la_status write_status = table->set(k, v, e);

        return_on_error(write_status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::configure_frm_db_fabric_routing_table_hardware(const la_device_id_vec_t& device_id_vec)
{
    // The fabric_routing_table is used by the HW to get the set of links that reach a specific device ID

    // Sort the vector for faster lookups
    la_device_id_vec_t sorted_dev_id_vec(device_id_vec);
    sort(sorted_dev_id_vec.begin(), sorted_dev_id_vec.end());

    la_uint_t fabric_port_num;
    la_status status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    for (size_t egress_device_id = 0; egress_device_id < la_device_impl::MAX_DEVICES; egress_device_id++) {
        bit_vector links_bitmap(0, NUM_FABRIC_PORTS_IN_DEVICE);

        lld_memory_sptr fabric_routing_table(m_device->m_gb_tree->dmc->frm->fabric_routing_table);

        // Read current value
        status = m_device->m_ll_device->read_memory(fabric_routing_table, egress_device_id, links_bitmap);
        return_on_error(status);

        // Modify
        size_t cur_port_value = links_bitmap.bit(fabric_port_num);
        size_t new_port_value;

        if (binary_search(sorted_dev_id_vec.begin(), sorted_dev_id_vec.end(), egress_device_id)) {
            new_port_value = 1;
        } else {
            new_port_value = 0;
        }

        // Write
        if (new_port_value == cur_port_value) {
            continue;
        }

        links_bitmap.resize(fabric_routing_table->get_desc()->width_bits);

        links_bitmap.set_bit(fabric_port_num, new_port_value);

        // In order to indicate to the FRM HW that an update is required for this line (device), the first column data must be
        // different from the same info in the reverse (db_rev_fabric_routing_table) table.
        // This will cause two effects:
        // 1) The HW will issue an update on the reachability to the destined device.
        // 2) The correct info is taken from the reverse table, updated to this table (and all the replications throughout the
        // chip).
        // So the reverse table will hold the correct info and this table will have a flipped bit in the 1st column, for each line
        // that needs to be updated.
        bool link0_correct_reachability = links_bitmap.bit(0);
        links_bitmap.set_bit(0, !link0_correct_reachability);

        status = m_device->m_ll_device->write_memory(fabric_routing_table, egress_device_id, links_bitmap);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::configure_frm_db_rev_fabric_routing_table(const la_device_id_vec_t& device_id_vec)
{
    la_uint_t fabric_port_num;
    la_status status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    size_t entry_width = gibraltar::frm_low_rev_fabric_routing_table_memory::SIZE_IN_BITS_WO_ECC;
    bit_vector low_rev_table_bmp(0, entry_width);
    bit_vector high_rev_table_bmp(0, entry_width);

    for (const auto device_id : device_id_vec) {
        if (device_id < entry_width) {
            low_rev_table_bmp.set_bit(device_id, 1);
        } else {
            high_rev_table_bmp.set_bit(device_id - entry_width, 1);
        }
    }

    status = m_device->m_ll_device->write_memory(
        m_device->m_gb_tree->dmc->frm->low_rev_fabric_routing_table, fabric_port_num, low_rev_table_bmp);
    return_on_error(status);
    status = m_device->m_ll_device->write_memory(
        m_device->m_gb_tree->dmc->frm->high_rev_fabric_routing_table, fabric_port_num, high_rev_table_bmp);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::configure_source_pif_hw_table()
{
    npl_source_pif_hw_table_t::key_type k;
    npl_source_pif_hw_table_t::value_type v;
    npl_source_pif_hw_table_t::entry_pointer_type e = nullptr;

    size_t pif_count = m_mac_port->get_num_of_pif();

    const auto& table(m_device->m_tables.source_pif_hw_table[m_slice_id]);

    // Prepare key
    k.rxpp_npu_input_ifg = get_physical_ifg(m_slice_id, m_ifg_id);

    // Prepare value
    v.action = NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA;
    v.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_FABRIC;
    v.payloads.init_rx_data.first_header_is_layer = 1;

    npl_macro_e first_np_macro;

    switch (m_device->m_device_mode) {
    case device_mode_e::LINECARD:
        first_np_macro = NPL_FABRIC_RX_PROCESS_FABRIC_HEADER_MACRO;
        break;

    case device_mode_e::FABRIC_ELEMENT:
        first_np_macro = NPL_FABRIC_ELEMENT_RX_TERM_MACRO;
        break;

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    v.payloads.init_rx_data.np_macro_id = (first_np_macro & 0x3F);

    for (la_uint_t offset = 0; offset < pif_count; offset++) {
        // Prepare key
        k.rxpp_npu_input_ifg_rx_fd_source_pif = m_pif_base + offset;

        // Update table
        la_status status = table->insert(k, v, e);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::configure_all_reachable_vector(bool all_reachable)
{
    if (m_device->is_simulated_device()) {
        const auto& table(m_device->m_tables.all_reachable_vector);
        npl_all_reachable_vector_key_t key; // key is empty
        npl_all_reachable_vector_entry_t* entry = nullptr;

        la_status status = table->lookup(key, entry);
        return_on_error(status);

        npl_all_reachable_vector_value_t value = entry->value();

        value.action = NPL_ALL_REACHABLE_VECTOR_ACTION_WRITE;
        npl_all_devices_reachable_e reachable_value = all_reachable ? npl_all_devices_reachable_e::NPL_ALL_DEVICES_REACHABLE_TRUE
                                                                    : npl_all_devices_reachable_e::NPL_ALL_DEVICES_REACHABLE_FALSE;

        la_uint_t fabric_port_num;
        status = get_fabric_port_num_in_device(fabric_port_num);
        return_on_error(status);
        value.payloads.all_reachable_vector_result.reachable[fabric_port_num] = reachable_value;

        status = table->set(key, value, entry);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::erase_source_pif_hw_table()
{
    npl_source_pif_hw_table_t::key_type k;
    npl_source_pif_hw_table_t::value_type v;

    size_t pif_count = m_mac_port->get_num_of_pif();

    const auto& table(m_device->m_tables.source_pif_hw_table[m_slice_id]);

    // Prepare key
    k.rxpp_npu_input_ifg = get_physical_ifg(m_slice_id, m_ifg_id);

    for (la_uint_t offset = 0; offset < pif_count; offset++) {
        // Prepare key
        k.rxpp_npu_input_ifg_rx_fd_source_pif = m_pif_base + offset;

        // Erase table entry
        la_status status = table->erase(k);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::activate(link_protocol_e link_protocol)
{
    start_api_call("link_protocol=", link_protocol);

    switch (link_protocol) {
    case link_protocol_e::PEER_DISCOVERY: {
        la_status status = activate_peer_discovery();
        return status;
    }

    case link_protocol_e::LINK_KEEPALIVE: {
        la_status status = activate_link_keepalive();
        return status;
    }

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::activate_peer_discovery()
{
    la_status status;

    status = set_fabric_link_down_transition(true /*enable_link*/);
    return_on_error(status);

    status = do_peer_delay_measurement();
    return_on_error(status);

    la_uint_t fabric_port_num;
    status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);
    gibraltar::fte_peer_delay_mem_memory peer_delay;

    status = get_peer_delay_mem_entry(peer_delay);
    return_on_error(status);

    if (m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT && m_peer_dev_id == LA_DEVICE_ID_INVALID) {
        m_peer_dev_id = peer_delay.fields.link_peer_device_id;
        status = m_device->add_potential_link(fabric_port_num, m_peer_dev_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::activate_link_keepalive()
{
    bool is_fabric_time_synced;

    la_status status = m_device->get_fabric_time_sync_status(is_fabric_time_synced);
    return_on_error(status);

    if (is_fabric_time_synced == false) {
        log_err(HLD, "Fabric time sync failed");
        return LA_STATUS_EAGAIN;
    }

    status = set_keepalive_generation(true /*enable*/);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::deactivate(link_protocol_e link_protocol)
{
    start_api_call("link_protocol=", link_protocol);

    switch (link_protocol) {
    case link_protocol_e::PEER_DISCOVERY: {
        la_status status = deactivate_peer_discovery();
        return status;
    }

    case link_protocol_e::LINK_KEEPALIVE: {
        la_status status = deactivate_link_keepalive();
        return status;
    }

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::deactivate_peer_discovery()
{
    la_status status;

    status = set_fabric_link_down_transition(false /*enable_link*/);
    return_on_error(status);

    status = clear_peer_delay_measurement();
    return_on_error(status);

    la_uint_t fabric_port_num;
    status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);
    if (m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT && m_peer_dev_id != LA_DEVICE_ID_INVALID) {
        status = m_device->remove_potential_link(fabric_port_num, m_peer_dev_id);
        return_on_error(status);
        m_peer_dev_id = LA_DEVICE_ID_INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::deactivate_link_keepalive()
{
    la_status status;

    status = set_keepalive_generation(false /*enable*/);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::get_link_keepalive_activated(bool& out_activated) const
{
    start_api_getter_call();

    la_status rc = get_keepalive_generation(out_activated);

    return rc;
}

la_status
la_fabric_port_impl::get_status(port_status& out_port_status) const
{
    start_api_getter_call();

    la_status status;

    // Peering status
    gibraltar::fte_peer_delay_mem_memory peer_delay;

    status = get_peer_delay_mem_entry(peer_delay);
    return_on_error(status);

    out_port_status.peer_detected = peer_delay.fields.link_peer_delay_valid;

    // Link status
    gibraltar::ts_mon_link_status_reg_register tsmon_link;

    status = m_device->m_ll_device->peek_register((*m_device->m_gb_tree->ts_mon->link_status_reg)[m_slice_id], tsmon_link);
    return_on_error(status);

    la_uint_t fabric_port_num_in_slice;
    status = get_fabric_port_num_in_slice(fabric_port_num_in_slice);
    return_on_error(status);

    // Verify that the link is usable for all fabric traffic contextes
    bool uch_link_status = bit_utils::get_bit(tsmon_link.fields.uch_link_status, fabric_port_num_in_slice);
    bool ucl_link_status = bit_utils::get_bit(tsmon_link.fields.ucl_link_status, fabric_port_num_in_slice);
    bool mc_link_status = bit_utils::get_bit(tsmon_link.fields.mc_link_status, fabric_port_num_in_slice);

    out_port_status.fabric_link_up = uch_link_status && ucl_link_status && mc_link_status;

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::set_fabric_link_down_transition(bool enable_link)
{
    gibraltar::frm_fabric_link_down_transition_reg_register link_down_reg;

    la_status status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->dmc->frm->fabric_link_down_transition_reg, link_down_reg);
    return_on_error(status);

    la_uint_t fabric_port_num;
    status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    uint64_t val = enable_link ? 0 : 1;
    link_down_reg.fields.set_fabric_link_down_transition(fabric_port_num, val);

    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->dmc->frm->fabric_link_down_transition_reg, link_down_reg);

    return status;
}

la_status
la_fabric_port_impl::get_fabric_link_down_transition(bool& out_enabled) const
{
    gibraltar::frm_fabric_link_down_transition_reg_register link_down_reg;
    la_status rc
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->dmc->frm->fabric_link_down_transition_reg, link_down_reg);
    if (rc) {
        return rc;
    }

    la_uint_t fabric_port_num;
    rc = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(rc);
    uint64_t val = link_down_reg.fields.get_fabric_link_down_transition(fabric_port_num);
    out_enabled = val == 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::do_peer_delay_measurement()
{
    // Trigger this port to do link measurement, and verify that the measurement is compeleted correctly.
    // The triggering is done by pos-edge change of enable_reg.peer_delay_req_gen_en.
    // The measurement should take a few [ms] to finish.
    gibraltar::fte_enable_reg_register enable_reg;

    // Read full register
    la_status status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);

    // Write 0
    enable_reg.fields.peer_delay_req_gen_en = 0;
    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);

    // Trigger measurement start
    la_uint_t fabric_port_num;
    status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    enable_reg.fields.peer_delay_req_gen_en = 1;
    enable_reg.fields.peer_delay_req_gen_link_idx = fabric_port_num;

    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);

    gibraltar::fte_peer_delay_mem_memory peer_delay;
    status = get_peer_delay_mem_entry(peer_delay);
    return_on_error(status);

    if (peer_delay.fields.link_peer_delay_valid != 1) {
        log_err(HLD, "Peer delay measurement failed");
        return LA_STATUS_EAGAIN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::get_peer_delay_mem_entry(gibraltar::fte_peer_delay_mem_memory& out_peer_delay_mem_entry) const
{
    la_uint_t fabric_port_num;
    la_status status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->dmc->fte->peer_delay_mem, fabric_port_num, out_peer_delay_mem_entry);

    return status;
}

la_status
la_fabric_port_impl::set_keepalive_generation(bool enable)
{
    gibraltar::tsms_keepalive_gen_cfg_register keepalive_gen_cfg;
    la_status status;

    status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ts_ms->keepalive_gen_cfg, keepalive_gen_cfg);
    return_on_error(status);

    bit_vector keepalive_gen_enable(keepalive_gen_cfg.fields.keepalive_gen_enable);

    la_uint_t fabric_port_num_in_slice;
    status = get_fabric_port_num_in_slice(fabric_port_num_in_slice);
    return_on_error(status);

    keepalive_gen_enable.set_bit(fabric_port_num_in_slice, enable);

    keepalive_gen_cfg.fields.keepalive_gen_enable = keepalive_gen_enable.get_value();

    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[m_slice_id]->ts_ms->keepalive_gen_cfg,
                                                   keepalive_gen_cfg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::get_keepalive_generation(bool& out_enabled) const
{
    gibraltar::tsms_keepalive_gen_cfg_register keepalive_gen_cfg;
    la_status rc;

    rc = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ts_ms->keepalive_gen_cfg, keepalive_gen_cfg);
    return_on_error(rc);

    bit_vector keepalive_gen_enable(keepalive_gen_cfg.fields.keepalive_gen_enable);
    la_uint_t fabric_port_num_in_slice;
    rc = get_fabric_port_num_in_slice(fabric_port_num_in_slice);
    return_on_error(rc);

    out_enabled = keepalive_gen_enable.bit(fabric_port_num_in_slice);

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::clear_peer_delay_measurement()
{
    la_uint_t fabric_port_num;
    la_status status = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(m_device->m_gb_tree->dmc->fte->peer_delay_mem, fabric_port_num, 0);

    return status;
}

const la_mac_port*
la_fabric_port_impl::get_mac_port() const
{
    start_api_getter_call();

    return m_mac_port.get();
}

la_status
la_fabric_port_impl::restore_state()
{
    // Fabric port object is state-less, it is sufficient to read non-volatile
    // memories and registers to get the shadow in sync with HW.
    la_status rc = restore_non_volatile();

    // Adding fabric port to potential links to peer device if it has peer.
    la_uint_t fabric_port_num;
    rc = get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(rc);
    gibraltar::fte_peer_delay_mem_memory peer_delay;

    rc = get_peer_delay_mem_entry(peer_delay);
    return_on_error(rc);

    if (peer_delay.fields.link_peer_delay_valid) {
        m_peer_dev_id = peer_delay.fields.link_peer_device_id;
        m_device->m_device_to_potential_links[m_peer_dev_id].push_back(fabric_port_num);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_impl::restore_non_volatile()
{
    // fabric_port uses these non-volatile registers
    std::vector<lld_register_sptr> non_volatile_registers;
    non_volatile_registers.push_back(m_device->m_gb_tree->dmc->fte->enable_reg);
    non_volatile_registers.push_back(m_device->m_gb_tree->dmc->frm->debug_frtm_debug_reg);
    for (la_slice_id_t sid : m_device->get_used_slices()) {
        auto& slice = m_device->m_gb_tree->slice[sid];
        non_volatile_registers.push_back(slice->ts_ms->keepalive_gen_cfg);
    }

    la_status rc = LA_STATUS_SUCCESS;
    for (auto reg : non_volatile_registers) {
        bit_vector tmp;
        rc = m_device->m_ll_device->read_register(reg, tmp);
        return_on_error(rc);
    }

    return rc;
}

void
la_fabric_port_impl::register_dependency(const la_mac_port_base* fabric_mac_port)
{
    m_device->add_object_dependency(fabric_mac_port, this);

    bit_vector registered_attributes((la_uint64_t)attribute_management_op::MAC_PORT_LINK_STATE_CHANGED);
    m_device->add_attribute_dependency(fabric_mac_port, this, registered_attributes);
}

void
la_fabric_port_impl::unregister_dependency(const la_mac_port_base* fabric_mac_port)
{
    m_device->remove_object_dependency(fabric_mac_port, this);

    bit_vector registered_attributes((la_uint64_t)attribute_management_op::MAC_PORT_LINK_STATE_CHANGED);
    m_device->remove_attribute_dependency(fabric_mac_port, this, registered_attributes);
}

la_status
la_fabric_port_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);

    default:
        log_err(HLD, "%s: received unsupported notification (%s)", __PRETTY_FUNCTION__, silicon_one::to_string(op.type_e).c_str());

        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_fabric_port_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {

    case (attribute_management_op::MAC_PORT_LINK_STATE_CHANGED):
        if (op.action.attribute_management.is_mac_port_link_state_up) {
            // On link up the user manually brings up the fabric port
            return LA_STATUS_SUCCESS;
        }

        // link down event
        return update_mac_port_link_state_down();

    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_fabric_port_impl::update_mac_port_link_state_down()
{
    la_status status;

    // Indicate that this port can't reach any LC device
    status = do_set_reachable_lc_devices({});
    return_on_error(status);

    // Clear peer detection
    status = deactivate_peer_discovery();
    return_on_error(status);

    // Stop keepalive
    status = deactivate_link_keepalive();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
