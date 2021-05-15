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

#include "la_mac_port_gibraltar.h"

#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "npu/counter_utils.h"
#include "npu/resolution_utils.h"
#include "qos/la_meter_set_impl.h"
#include "system/ifg_handler.h"
#include "system/mac_pool_port.h"
#include "tm/tm_utils.h"

#include "api_tracer.h"

namespace silicon_one
{

la_mac_port_gibraltar::la_mac_port_gibraltar(const la_device_impl_wptr& device) : la_mac_port_pacgb(device)
{
}

la_mac_port_gibraltar::~la_mac_port_gibraltar()
{
}

la_status
la_mac_port_gibraltar::update_pdoq_oq_ifc_mapping()
{
    // update_pdoq table relies on a preconfiguration done by la_device_impl::configure_pdoq_oq_ifc_mapping_network
    for (la_uint_t pif_offset = 0; pif_offset < m_pif_count; pif_offset++) {
        la_uint_t oq_base = m_ifg_id * NUM_OQ_PER_IFG + (m_pif_base_id + pif_offset) * NUM_OQ_PER_PIF;
        for (la_uint_t oq_offset = 0; oq_offset < NUM_OQ_PER_PIF; oq_offset++) {
            const auto& table(m_device->m_tables.pdoq_oq_ifc_mapping[m_slice_id]);
            npl_pdoq_oq_ifc_mapping_key_t key;
            npl_pdoq_oq_ifc_mapping_value_t value;
            npl_pdoq_oq_ifc_mapping_entry_t* entry = nullptr;

            key.dest_oq = oq_base + oq_offset;
            la_status status = table->lookup(key, entry);
            return_on_error(status);
            value = entry->value();

            // For Non extended PIF the oq_pair field is always 0, meaning all 8 OQ are used
            value.payloads.pdoq_oq_ifc_mapping_result.txpp_map_data.parsed.oq_pair
                = (m_is_extended) ? oq_offset / NUM_OQ_PER_EXTENDED_PORT : 0;

            status = entry->update(value);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::do_reset()
{
    start_api_call("");

    la_status status;
    status = do_reset_port();
    return_on_error(status);

    if (m_device->m_device_mode == device_mode_e::LINECARD
        && m_device->m_slice_mode[m_slice_id] == la_slice_mode_e::CARRIER_FABRIC) {
        int credits;
        m_device->get_int_property(la_device_property_e::OOB_INJ_CREDITS, credits);
        status = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->reset_oob_inj_credits(m_mac_lane_base_id, credits);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::mlp_init(fc_mode_e rx_fc_mode, fc_mode_e tx_fc_mode, fec_mode_e fec_mode)
{
    // Check valid configuration
    if (((m_serdes_base_id != 0 && m_serdes_base_id != 8)) || (m_serdes_count != 16)
        || (m_speed != la_mac_port::port_speed_e::E_800G)) {
        return LA_STATUS_EINVAL;
    }

    // Allocate two ports
    mac_pool_port_sptr mp[2];
    m_device->m_device_port_handler->create_mac_pool(m_serdes_base_id, mp[0]);
    m_device->m_device_port_handler->create_mac_pool(m_serdes_base_id, mp[1]);
    m_mac_pool_port.push_back(mp[0]);
    m_mac_pool_port.push_back(mp[1]);

    la_status status = LA_STATUS_SUCCESS;

    for (int i = 0; (i < 2) && (status == LA_STATUS_SUCCESS); i++) {
        status = m_mac_pool_port[i]->initialize(m_slice_id,
                                                m_ifg_id,
                                                m_serdes_base_id + i * 8,
                                                8,
                                                la_mac_port::port_speed_e::E_400G,
                                                rx_fc_mode,
                                                tx_fc_mode,
                                                fec_mode,
                                                (i == 0) ? la_mac_port::mlp_mode_e::MLP_MASTER : la_mac_port::mlp_mode_e::MLP_SLAVE,
                                                m_port_slice_mode);
    }

    return status;
}

la_status
la_mac_port_gibraltar::set_oqueue_state(la_pfc_priority_t pfc_priority, pfc_config_queue_state_e state)
{
    la_status status;
    la_uint_t addr, queue;
    size_t pos;

    // Get the oq and the address and bit location in the oq drop memory.
    queue = get_base_oq() + pfc_priority;

    // Per memory location there are 8 queues. So calculate the address and bit location to set.
    constexpr size_t NUM_OQS = gibraltar::txcgm_oq_drop_bitmap_memory::fields::OQ_DROP_BITMAP_DATA_WIDTH;
    pos = queue % NUM_OQS;
    addr = queue / NUM_OQS;

    lld_memory_scptr oq_drop_bitmap(m_device->m_gb_tree->slice[m_slice_id]->tx->cgm->oq_drop_bitmap);
    gibraltar::txcgm_oq_drop_bitmap_memory val;

    // TODO This only disabling unicast queues. See set_oqs_enabled for mcast logic.
    status = m_device->m_ll_device->read_memory(oq_drop_bitmap, addr, val);
    return_on_error(status);

    bool is_drop = (state == pfc_config_queue_state_e::DROPPING);

    val.fields.oq_drop_bitmap_data = bit_utils::set_bit(val.fields.oq_drop_bitmap_data, pos, is_drop);
    status = m_device->m_ll_device->write_memory(oq_drop_bitmap, addr, val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
la_mac_port_gibraltar::is_oq_drop_counter_set_valid(size_t counter_set_idx)
{
    constexpr size_t NUM_OQ_DROP_COUNTERS = (1 << gibraltar::txcgm_counter_set_map_memory::fields::COUNTER_SET_MAP_DATA_WIDTH);

    return !((counter_set_idx == INVALID_COUNTER_SET_IDX) || (counter_set_idx >= NUM_OQ_DROP_COUNTERS));
}

la_status
la_mac_port_gibraltar::get_oqueue_ptr(la_pfc_priority_t pfc_priority, la_uint_t& out_q_rd_ptr, la_uint_t& out_q_wr_ptr)
{
    la_status status;
    la_uint_t queue;

    queue = get_base_oq() + pfc_priority;

    lld_memory_scptr oq_rdsn(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->rdsn);
    lld_memory_scptr oq_wrsn(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->wrsn);
    gibraltar::pdoq_wrsn_memory wr_ptr;
    gibraltar::pdoq_rdsn_memory rd_ptr;

    status = m_device->m_ll_device->read_memory(oq_rdsn, queue, rd_ptr);
    return_on_error(status);

    status = m_device->m_ll_device->read_memory(oq_wrsn, queue, wr_ptr);
    return_on_error(status);

    out_q_wr_ptr = wr_ptr.fields.wrsn_data;
    out_q_rd_ptr = rd_ptr.fields.rdsn_data;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_oq_counter_set(la_pfc_priority_t pfc_priority, la_uint_t counter_set_idx)
{
    la_status status;
    lld_memory_scptr counter_set_map(m_device->m_gb_tree->slice[m_slice_id]->tx->cgm->counter_set_map);
    gibraltar::txcgm_counter_set_map_memory val;
    la_uint_t queue = get_base_oq() + pfc_priority;

    val.fields.counter_set_map_data = counter_set_idx;

    // Set the queue to point to the drain counter.
    status = m_device->m_ll_device->write_memory(counter_set_map, queue, val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::read_oq_uc_counters(size_t counter_set_idx, output_queue_counters& oq_uc_counters)
{
    oq_uc_counters = {};

    if (!is_oq_drop_counter_set_valid(counter_set_idx)) {
        // Return error if the counter was not allocated.
        return LA_STATUS_ERESOURCE;
    }

    // Unicast byte counter
    const auto& counter_set_reg_byte = (*m_device->m_gb_tree->slice[m_slice_id]->tx->cgm->uc_byte_counter_set)[counter_set_idx];
    gibraltar::txcgm_uc_byte_counter_set_register counter_byte;

    // Read the counter to clear it.
    la_status status = m_device->m_ll_device->read_register(counter_set_reg_byte, counter_byte);
    return_on_error(status);

    oq_uc_counters.drop_bytes = counter_byte.fields.uc_byte_counter_set_drop_cnt;
    oq_uc_counters.enqueue_bytes = counter_byte.fields.uc_byte_counter_set_total_cnt;

    // Unicast packet counter
    const auto& counter_set_reg_pd = (*m_device->m_gb_tree->slice[m_slice_id]->tx->cgm->uc_pd_counter_set)[counter_set_idx];
    gibraltar::txcgm_uc_pd_counter_set_register counter_pd;

    // Read the counter to clear it.
    status = m_device->m_ll_device->read_register(counter_set_reg_pd, counter_pd);
    return_on_error(status);

    oq_uc_counters.drop_packets = counter_pd.fields.uc_pd_counter_set_drop_cnt;
    oq_uc_counters.enqueue_packets = counter_pd.fields.uc_pd_counter_set_total_cnt;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::read_oq_mc_counters(size_t counter_set_idx, output_queue_counters& oq_mc_counters)
{
    oq_mc_counters = {};

    if (!is_oq_drop_counter_set_valid(counter_set_idx)) {
        // Return error if the counter was not allocated.
        return LA_STATUS_ERESOURCE;
    }

    // Multicast byte counter
    const auto& counter_set_reg_byte = (*m_device->m_gb_tree->slice[m_slice_id]->tx->cgm->mc_byte_counter_set)[counter_set_idx];
    gibraltar::txcgm_mc_byte_counter_set_register counter_byte;

    // Read the counter to clear it.
    la_status status = m_device->m_ll_device->read_register(counter_set_reg_byte, counter_byte);
    return_on_error(status);

    oq_mc_counters.drop_bytes = counter_byte.fields.mc_byte_counter_set_drop_cnt;
    oq_mc_counters.enqueue_bytes = counter_byte.fields.mc_byte_counter_set_total_cnt;

    // Multicast packet counter
    const auto& counter_set_reg_pd = (*m_device->m_gb_tree->slice[m_slice_id]->tx->cgm->mc_pd_counter_set)[counter_set_idx];
    gibraltar::txcgm_mc_pd_counter_set_register counter_pd;

    // Read the counter to clear it.
    status = m_device->m_ll_device->read_register(counter_set_reg_pd, counter_pd);
    return_on_error(status);

    oq_mc_counters.drop_packets = counter_pd.fields.mc_pd_counter_set_drop_cnt;
    oq_mc_counters.enqueue_packets = counter_pd.fields.mc_pd_counter_set_total_cnt;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_reset_state_fabric_port(mac_reset_state_e state)
{
    la_status status = set_reset_state_network_port(state);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::configure_fabric_scheduler()
{
    // Nothing to do, it is configured by LBR init values.
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::get_pfc_enabled(bool& out_enabled, la_uint8_t& out_tc_bitmap) const
{
    start_api_getter_call();

    out_enabled = m_pfc_enabled;
    out_tc_bitmap = m_pfc_tc_bitmap;

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_pfc_counter(la_counter_set* rx_counter)
{
    start_api_call("rx_counter=", rx_counter);

    transaction txn;

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // Remove old counter
    if (m_pfc_rx_counter) {
        slice_ifg_vec_t ifg_vec = get_pfc_counter_ifgs();
        txn.status = m_pfc_rx_counter->remove_drop_counter(ifg_vec);
        return_on_error(txn.status);
        txn.on_fail([=]() { m_pfc_rx_counter->add_drop_counter(COUNTER_DIRECTION_INGRESS, ifg_vec); });
        m_device->remove_object_dependency(m_pfc_rx_counter, this);
        txn.on_fail([=]() { m_device->add_object_dependency(m_pfc_rx_counter, this); });

        // Turn off the ability to receive PFC packets on rx.
        for (auto port : m_mac_pool_port) {
            txn.status = port->set_fc_rx_term_mode(true);
            return_on_error(txn.status);
            txn.on_fail([=]() { port->set_fc_rx_term_mode(false); });
        }
    }

    auto old_counter = m_pfc_rx_counter;
    m_pfc_rx_counter = m_device->get_sptr<la_counter_set_impl>(rx_counter);
    txn.on_fail([&]() { m_pfc_rx_counter = old_counter; });

    // Add new counter
    if (m_pfc_rx_counter) {
        slice_ifg_vec_t ifg_vec = get_pfc_counter_ifgs();
        txn.status = m_pfc_rx_counter->add_drop_counter(COUNTER_DIRECTION_INGRESS, ifg_vec);
        txn.on_fail([=]() { m_pfc_rx_counter->remove_drop_counter(ifg_vec); });
        return_on_error(txn.status);
        m_device->add_object_dependency(m_pfc_rx_counter, this);
        txn.on_fail([=]() { m_device->remove_object_dependency(m_pfc_rx_counter, this); });

        // Turn on the ability to receive PFC packets on rx
        for (auto port : m_mac_pool_port) {
            txn.status = port->set_fc_rx_term_mode(false);
            return_on_error(txn.status);
            txn.on_fail([=]() { port->set_fc_rx_term_mode(true); });
        }
    }

    if (m_pfc_enabled) {
        txn.status = update_pfc_table();
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_pfc_meter(la_meter_set* tx_meter)
{
    start_api_call("tx_meter=", tx_meter);

    return LA_STATUS_EINVAL;
}

la_status
la_mac_port_gibraltar::get_pfc_counter(const la_counter_set*& out_counter) const
{
    start_api_getter_call();

    out_counter = m_pfc_rx_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::get_pfc_meter(const la_meter_set*& out_meter) const
{
    start_api_getter_call();

    return LA_STATUS_EINVAL;
}

la_status
la_mac_port_gibraltar::get_pfc_quanta(std::chrono::nanoseconds& out_xoff_time) const
{
    start_api_getter_call();

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_rate_t speed = la_2_port_speed(m_speed);
    out_xoff_time = std::chrono::nanoseconds{m_pfc_quanta * NUM_PFC_QUANTA_BITS / speed};
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_pfc_quanta(std::chrono::nanoseconds xoff_time)
{
    start_api_call("xoff_time=", xoff_time);

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // convert time to a quanta value - 512b at line rate
    la_rate_t speed = la_2_port_speed(m_speed);
    uint32_t quanta = xoff_time.count() * speed / NUM_PFC_QUANTA_BITS;
    if (quanta >= MAX_PFC_QUANTA) {
        quanta = MAX_PFC_QUANTA;
    }

    for (auto port : m_mac_pool_port) {
        la_status status = port->set_xoff_timer_settings(m_pfc_tc_bitmap, quanta);
        return_on_error(status);
    }

    m_pfc_quanta = quanta;

    return LA_STATUS_SUCCESS;
}

bool
la_mac_port_gibraltar::is_sw_based_pfc_enabled() const
{
    // SW based PFC is Pacific-only
    return false;
}

la_status
la_mac_port_gibraltar::set_pfc_enable(la_uint8_t tc_bitmap)
{
    start_api_call("tc_bitmap=", tc_bitmap);

    transaction txn;

    if (m_pfc_enabled) {
        return LA_STATUS_SUCCESS;
    }

    if (tc_bitmap == 0) {
        return LA_STATUS_EINVAL;
    }

    txn.status = do_pfc_enable(tc_bitmap);
    return_on_error(txn.status);

    m_pfc_tc_bitmap = tc_bitmap;
    m_pfc_enabled = true;

    txn.status = update_pfc_table();
    return_on_error(txn.status);

    auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();
    if (sp != nullptr) {
        txn.status = set_pfc_ssp_slice_table(true /* enabled */);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_pfc_disable()
{
    start_api_call("");

    if (!is_network_slice(m_port_slice_mode)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (!m_pfc_enabled) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = do_pfc_disable();
    return_on_error(status);

    m_pfc_tc_bitmap = 0;
    m_pfc_enabled = false;

    status = update_pfc_table();
    return_on_error(status);

    auto sp = get_system_port().weak_ptr_static_cast<la_system_port_base>();
    if (sp != nullptr) {
        status = set_pfc_ssp_slice_table(false /* enabled */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::init_pfc()
{
    m_counter_set.fill(INVALID_COUNTER_SET_IDX);
    m_queue_transmit_state.fill(pfc_config_queue_state_e::ACTIVE);
    m_prev_oq_rd_ptr.fill(INVALID_OQ_PTR);
    m_prev_oq_wr_ptr.fill(INVALID_OQ_PTR);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_sq_map_table_priority(la_uint_t map_mode)
{
    if (map_mode > 3) {
        return LA_STATUS_EINVAL;
    }

    auto sq_map_table = (*m_device->m_gb_tree->rx_cgm->sq_map_table)[m_slice_id];
    gibraltar::rx_cgm_sq_map_table_memory sq_map_table_entry;

    for (size_t serdes = m_serdes_base_id; serdes < m_serdes_base_id + m_serdes_count; serdes++) {
        la_uint_t line_idx = (tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS * m_ifg_id + serdes);
        la_status status = m_device->m_ll_device->read_memory(sq_map_table, line_idx, sq_map_table_entry);

        sq_map_table_entry.fields.slice_base_sq_counter = (line_idx)*8;
        sq_map_table_entry.fields.slice_map_mode = map_mode;

        status = m_device->m_ll_device->write_memory(sq_map_table, line_idx, sq_map_table_entry);
        return_on_error(status);
    }

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        auto sq_map_lut = (*m_device->m_gb_tree->rx_cgm->sq_map_lut)[slice];
        gibraltar::rx_cgm_sq_map_lut_memory sq_map_lut_entry;

        for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
            la_status status = m_device->m_ll_device->read_memory(sq_map_lut, tc << 2, sq_map_lut_entry);

            sq_map_lut_entry.fields.slice_counter_offset = tc;

            status = m_device->m_ll_device->write_memory(sq_map_lut, tc << 2, sq_map_lut_entry);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_ssp_sub_port_map()
{
    auto ssp_sub_port_map = (*m_device->m_gb_tree->rx_cgm->ssp_sub_port_map)[m_slice_id];
    gibraltar::rx_cgm_ssp_sub_port_map_memory ssp_sub_port_map_entry;

    for (size_t ind = 0; ind < ssp_sub_port_map->get_desc()->entries; ind++) {
        la_status status = m_device->m_ll_device->read_memory(ssp_sub_port_map, ind, ssp_sub_port_map_entry);

        ssp_sub_port_map_entry.fields.slice_ssp_sub_port_map = 0;

        status = m_device->m_ll_device->write_memory(ssp_sub_port_map, ind, ssp_sub_port_map_entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_source_if_to_port_map_fc_enable(bool fc_enable)
{
    auto source_if_to_port_map = (*m_device->m_gb_tree->rx_cgm->source_if_to_port_map)[m_slice_id];
    gibraltar::rx_cgm_source_if_to_port_map_memory source_if_to_port_map_entry;

    for (size_t serdes = m_serdes_base_id; serdes < m_serdes_base_id + m_serdes_count; serdes++) {
        la_uint_t line_idx = (tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS * m_ifg_id + serdes);

        la_status status = m_device->m_ll_device->read_memory(*source_if_to_port_map, line_idx, source_if_to_port_map_entry);
        return_on_error(status);

        source_if_to_port_map_entry.fields.slice_fc_enable = (fc_enable ? 1 : 0);

        status = m_device->m_ll_device->write_memory(source_if_to_port_map, line_idx, source_if_to_port_map_entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_fcm_prio_map_bitmap(la_uint8_t tc_bitmap)
{
    auto fcm_prio_map = m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fcm_prio_map;

    for (size_t serdes = m_serdes_base_id; serdes < m_serdes_base_id + m_serdes_count; serdes++) {
        bit_vector bv;
        for (size_t i = 0; i < NUM_TC_CLASSES; i++) {
            la_uint8_t prio = ((tc_bitmap & (1 << i)) == 0) ? 0 : (1 << i);
            la_status status = m_device->m_ll_device->read_memory(fcm_prio_map, i, bv);
            return_on_error(status);

            bv.set_bits((serdes * 8) + 7, (serdes * 8), prio);

            status = m_device->m_ll_device->write_memory(fcm_prio_map, i, bv);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::set_pfc_tc_xoff_rx_enable(la_uint8_t tc_bitmap)
{
    start_api_call("tc_bitmap=", tc_bitmap);

    for (la_pfc_priority_t tc = 0; tc < LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        for (size_t serdes = m_serdes_base_id; serdes < m_serdes_base_id + m_serdes_count; serdes++) {
            // Entry number is IFG | Serdes | TC. 4 entries per row
            constexpr la_uint_t num_entries_per_row = 4;
            la_uint_t entry_num = (m_ifg_id << 8) + (serdes << 3) + tc;
            la_uint_t row = entry_num / num_entries_per_row;
            la_uint_t column = entry_num % num_entries_per_row;

            gibraltar::pdoq_pfc_mapping_memory pfc_mapping;
            la_status status = m_device->m_ll_device->read_memory(
                m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pfc_mapping, row, pfc_mapping);
            return_on_error(status);

            if (((1 << tc) & tc_bitmap) != 0) {
                pfc_mapping.fields.pfc_tc_map |= 1 << (8 * column);
            } else {
                la_uint64_t disable_mask
                    = bit_utils::ones(gibraltar::pdoq_pfc_mapping_memory::fields::PFC_TC_MAP_WIDTH) ^ (0xff << (8 * column));
                pfc_mapping.fields.pfc_tc_map &= disable_mask;
            }

            status = m_device->m_ll_device->write_memory(
                m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pfc_mapping, row, pfc_mapping);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::init_rxcgm()
{
    la_rx_cgm_sq_profile* default_profile;
    la_status status = m_device->get_default_rx_cgm_sq_profile(default_profile);
    return_on_error(status);
    const auto& default_profile_impl = m_device->get_sptr<la_rx_cgm_sq_profile_impl>(default_profile);

    for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        for (size_t serdes = m_serdes_base_id; serdes < m_serdes_base_id + m_serdes_count; serdes++) {
            status = m_device->m_rx_cgm_handler->set_rx_cgm_sq_mapping(m_slice_id,
                                                                       m_ifg_id,
                                                                       serdes,
                                                                       tc,
                                                                       rx_cgm_handler::LA_RX_CGM_SQ_PROFILE_DEFAULT_ID,
                                                                       1 /* Default SQG Group */,
                                                                       0 /* Default drop counter */);
            return_on_error(status);
        }
        m_tc_sq_mapping[tc] = {.profile = default_profile_impl, .group_index = 1, .drop_counter_index = 0};
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::reset_rx_cgm_mapping()
{
    if (is_network_slice(m_port_slice_mode)) {
        // Reset RXCGM mapping
        la_rx_cgm_sq_profile* default_profile;
        la_status status = m_device->get_default_rx_cgm_sq_profile(default_profile);
        return_on_error(status);
        const auto& default_profile_sp = m_device->get_sptr<la_rx_cgm_sq_profile_impl>(default_profile);

        for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
            // Reset to defaults - default profile, group 1, counter 0
            status = do_set_tc_rx_cgm_sq_mapping(tc, default_profile_sp, 1, 0);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_gibraltar::get_pfc_status(la_pfc_priority_t pfc_priority, bool& out_state)
{
    la_status status;
    la_uint_t queue;

    queue = get_base_oq() + pfc_priority;

    // Current pfc status can only be read 32 queues at a time. Set the index to point to the correct queues.
    la_uint_t index = queue / 32;
    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pfc_debug_cfg, index);
    return_on_error(status);

    // Read the status
    gibraltar::pdoq_pfc_debug_register pfc;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pfc_debug, pfc);
    return_on_error(status);

    // Read it again to get the current status
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pfc_debug, pfc);
    return_on_error(status);

    if (pfc.fields.pfc_status & (1 << (queue & 0x1f))) {
        out_state = true;
    } else {
        out_state = false;
    }

    return LA_STATUS_SUCCESS;
}
}
