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

#include "la_meter_action_profile_impl.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "la_strings.h"
#include "lld/device_tree.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_meter_action_profile_impl::la_meter_action_profile_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_meter_action_profile_impl::~la_meter_action_profile_impl()
{
}

la_status
la_meter_action_profile_impl::initialize(la_object_id_t oid)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    // Set the default values for the per_color_pair_properties map.
    const la_qos_color_e colors[] = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};
    for (auto meter_color : colors) {
        for (auto rate_limiter_color : colors) {
            meter_rate_limiter_color_pair color_pair = std::make_pair(meter_color, rate_limiter_color);
            per_color_pair_properties per_color_properties = {
                .drop_enable = true, .mark_ecn = true, .packet_color = la_qos_color_e::RED, .rx_cgm_color = la_qos_color_e::YELLOW};
            m_action_profile_properties_map[color_pair] = per_color_properties;
        }
    }

    m_stat_bank_data.use_count = 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    for (auto ifg : m_ifg_use_count->get_ifgs()) {
        for (const auto& iter : m_action_profile_properties_map) {
            la_status status = exact_meter_decision_mapping_table_erase_entry(ifg, iter.first);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    default:
        log_err(HLD,
                "la_meter_action_profile_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_meter_action_profile_impl::get_allocation_in_exact_bank(la_slice_ifg slice_ifg, uint64_t& out_index) const
{
    if (!is_allocated_in_exact_bank(slice_ifg)) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    size_t g_ifg = m_ifg_use_count->get_index(slice_ifg);
    out_index = m_exact_meters_allocation[g_ifg].profile_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::get_allocation_in_statistical_banks(uint64_t& out_index) const
{
    if (!is_allocated_in_statistical_banks()) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    out_index = m_stat_bank_data.profile_index;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::set_action(la_qos_color_e meter_color,
                                         la_qos_color_e rate_limiter_color,
                                         bool drop_enable,
                                         bool mark_ecn,
                                         la_qos_color_e packet_color,
                                         la_qos_color_e rx_cgm_color)
{
    start_api_call("meter_color=",
                   meter_color,
                   "rate_limiter_color=",
                   rate_limiter_color,
                   "drop_enable=",
                   drop_enable,
                   "mark_ecn=",
                   mark_ecn,
                   "packet_color=",
                   packet_color,
                   "rx_cgm_color=",
                   rx_cgm_color);

    if (!(meter_color <= la_qos_color_e::RED) || !(rate_limiter_color <= la_qos_color_e::RED)
        || !(packet_color <= la_qos_color_e::RED)
        || !(rx_cgm_color <= la_qos_color_e::YELLOW)) {
        return LA_STATUS_EINVAL;
    }

    meter_rate_limiter_color_pair color_pair = std::make_pair(meter_color, rate_limiter_color);
    per_color_pair_properties per_color_properties
        = {.drop_enable = drop_enable, .mark_ecn = mark_ecn, .packet_color = packet_color, .rx_cgm_color = rx_cgm_color};
    m_action_profile_properties_map[color_pair] = per_color_properties;

    la_status status;
    for (auto ifg : m_ifg_use_count->get_ifgs()) {
        status = exact_meter_decision_mapping_table_configure_entry(ifg, color_pair, per_color_properties);
        return_on_error(status);
    }

    if (is_allocated_in_statistical_banks()) {
        status = statistical_meter_decision_mapping_table_configure_all_banks(color_pair, per_color_properties);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::get_action(la_qos_color_e meter_color,
                                         la_qos_color_e rate_limiter_color,
                                         bool& out_drop_enable,
                                         bool& out_mark_ecn,
                                         la_qos_color_e& out_packet_color,
                                         la_qos_color_e& out_rx_cgm_color) const
{
    start_api_call("meter_color=", meter_color, "rate_limiter_color=", rate_limiter_color);

    const auto& it = m_action_profile_properties_map.find(std::make_pair(meter_color, rate_limiter_color));

    if (it == m_action_profile_properties_map.end())
        return LA_STATUS_ENOTFOUND;

    out_drop_enable = it->second.drop_enable;
    out_mark_ecn = it->second.mark_ecn;
    out_packet_color = it->second.packet_color;
    out_rx_cgm_color = it->second.rx_cgm_color;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::add_ifg(la_slice_ifg ifg)
{
    transaction txn;
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([=]() {
        bool ifg_removed, slice_removed, slice_pair_removed;
        m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    });

    if (ifg_added) {
        size_t g_ifg = m_ifg_use_count->get_index(ifg);
        // first attachment to the ifg, need to allocate in table
        bool index_allocated = m_device->m_index_generators.exact_meter_action_profile_id[g_ifg].allocate(
            m_exact_meters_allocation[g_ifg].profile_index);
        txn.status = index_allocated ? LA_STATUS_SUCCESS : LA_STATUS_ERESOURCE;
        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }

        txn.on_fail([=]() {
            m_device->m_index_generators.exact_meter_action_profile_id[g_ifg].release(
                m_exact_meters_allocation[g_ifg].profile_index);
            m_exact_meters_allocation[g_ifg].profile_index = INVALID_INDEX;
        });
        for (const auto& iter : m_action_profile_properties_map) {
            txn.status = exact_meter_decision_mapping_table_configure_entry(ifg, iter.first, iter.second);
            if (txn.status != LA_STATUS_SUCCESS) {
                return txn.status;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::remove_ifg(la_slice_ifg ifg)
{

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    if (ifg_removed) {
        size_t g_ifg = m_ifg_use_count->get_index(ifg);
        // no more users in that ifg for this profile
        for (const auto& iter : m_action_profile_properties_map) {
            la_status status = exact_meter_decision_mapping_table_erase_entry(ifg, iter.first);
            return_on_error(status);
        }
        m_device->m_index_generators.exact_meter_action_profile_id[g_ifg].release(m_exact_meters_allocation[g_ifg].profile_index);
        m_exact_meters_allocation[g_ifg].profile_index = INVALID_INDEX;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::exact_meter_decision_mapping_table_configure_entry(la_slice_ifg ifg,
                                                                                 const meter_rate_limiter_color_pair& color_pair,
                                                                                 const per_color_pair_properties& properties)
{
    npl_rx_meter_exact_meter_decision_mapping_table_t::key_type k;
    npl_rx_meter_exact_meter_decision_mapping_table_t::value_type v;
    npl_rx_meter_exact_meter_decision_mapping_table_t::entry_pointer_type e = nullptr;

    size_t g_ifg = m_ifg_use_count->get_index(ifg);

    k.ifg.value = ifg.ifg;
    k.rate_limiter_result_color.value = la_2_meter_color(color_pair.second);
    populate_meter_decision_mapping_table_key_payload(
        color_pair.first, properties, m_exact_meters_allocation[g_ifg], k, v.payloads.rx_meter_exact_meter_decision_mapping_result);
    v.action = NPL_RX_METER_EXACT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE;

    return m_device->m_tables.rx_meter_exact_meter_decision_mapping_table[ifg.slice]->set(k, v, e);
}

la_status
la_meter_action_profile_impl::exact_meter_decision_mapping_table_erase_entry(la_slice_ifg ifg,
                                                                             const meter_rate_limiter_color_pair& color_pair)
{
    npl_rx_meter_exact_meter_decision_mapping_table_t::key_type k;

    size_t g_ifg = m_ifg_use_count->get_index(ifg);

    k.ifg.value = ifg.ifg;
    k.meter_result_color.value = la_2_meter_color(color_pair.first);
    k.rate_limiter_result_color.value = la_2_meter_color(color_pair.second);
    k.meter_action_profile_index.value = m_exact_meters_allocation[g_ifg].profile_index;

    return m_device->m_tables.rx_meter_exact_meter_decision_mapping_table[ifg.slice]->erase(k);
}

la_status
la_meter_action_profile_impl::attach_statistical_meter()
{
    transaction txn;

    if (is_allocated_in_statistical_banks()) {
        m_stat_bank_data.use_count++;
        return LA_STATUS_SUCCESS;
    }

    bool did_allocate = m_device->m_index_generators.statistical_meter_action_profile_id.allocate(m_stat_bank_data.profile_index);
    if (!did_allocate) {
        return LA_STATUS_ERESOURCE;
    }
    m_stat_bank_data.use_count++;

    txn.on_fail([=]() {
        m_device->m_index_generators.statistical_meter_action_profile_id.release(m_stat_bank_data.profile_index);
        m_stat_bank_data.profile_index = INVALID_INDEX;
        m_stat_bank_data.use_count--;
    });

    for (const auto& iter : m_action_profile_properties_map) {
        txn.status = statistical_meter_decision_mapping_table_configure_all_banks(iter.first, iter.second);
        return_on_error(txn.status);

        txn.on_fail([=]() { statistical_meter_decision_mapping_table_erase_all_banks(iter.first); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::detach_statistical_meter()
{
    m_stat_bank_data.use_count--;
    if (m_stat_bank_data.use_count > 0) {
        return LA_STATUS_SUCCESS;
    }

    for (const auto& iter : m_action_profile_properties_map) {
        la_status status = statistical_meter_decision_mapping_table_erase_all_banks(iter.first);
        return_on_error(status);
    }

    m_device->m_index_generators.statistical_meter_action_profile_id.release(m_stat_bank_data.profile_index);
    m_stat_bank_data.profile_index = INVALID_INDEX;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::statistical_meter_decision_mapping_table_configure_all_banks(
    const meter_rate_limiter_color_pair& color_pair,
    const per_color_pair_properties& properties)
{
    transaction txn;

    for (size_t bank_index = 0; bank_index < NUM_STATISTICAL_METER_BANKS; bank_index++) {
        txn.status = statistical_meter_decision_mapping_table_configure_entry(bank_index, color_pair, properties);
        return_on_error(txn.status);

        txn.on_fail([=]() { statistical_meter_decision_mapping_table_erase_entry(bank_index, color_pair); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::statistical_meter_decision_mapping_table_erase_all_banks(
    const meter_rate_limiter_color_pair& color_pair)
{
    for (size_t bank_index = 0; bank_index < NUM_STATISTICAL_METER_BANKS; bank_index++) {
        la_status status = statistical_meter_decision_mapping_table_erase_entry(bank_index, color_pair);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_action_profile_impl::statistical_meter_decision_mapping_table_configure_entry(
    size_t meter_bank_index,
    const meter_rate_limiter_color_pair& color_pair,
    const per_color_pair_properties& properties)
{
    npl_rx_meter_stat_meter_decision_mapping_table_t::key_type k;
    npl_rx_meter_stat_meter_decision_mapping_table_t::value_type v;
    npl_rx_meter_stat_meter_decision_mapping_table_t::entry_pointer_type e = nullptr;

    k.meter_bank_index.value = meter_bank_index;
    k.exact_meter_to_stat_meter_color.value = la_2_meter_color(color_pair.second);
    populate_meter_decision_mapping_table_key_payload(
        color_pair.first, properties, m_stat_bank_data, k, v.payloads.rx_meter_stat_meter_decision_mapping_result);
    v.action = NPL_RX_METER_STAT_METER_DECISION_MAPPING_TABLE_ACTION_WRITE;

    la_slice_id_vec_t nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (auto sid : nw_slices) {
        la_status status = m_device->m_tables.rx_meter_stat_meter_decision_mapping_table[sid]->set(k, v, e);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

template <typename _Key, typename _Payload>
void
la_meter_action_profile_impl::populate_meter_decision_mapping_table_key_payload(la_qos_color_e meter_result_color,
                                                                                per_color_pair_properties properties,
                                                                                allocation_data data,
                                                                                _Key& key,
                                                                                _Payload& payload) const
{
    key.meter_action_profile_index.value = data.profile_index;
    key.meter_result_color.value = la_2_meter_color(meter_result_color);

    payload.cgm_rx_dp = la_2_meter_color(properties.rx_cgm_color);
    payload.congestion_experienced = properties.mark_ecn;
    payload.meter_drop = properties.drop_enable;
    payload.outgoing_color.value = la_2_meter_color(properties.packet_color);
    payload.rx_counter_color.value = la_2_meter_color(properties.packet_color);
}

la_status
la_meter_action_profile_impl::statistical_meter_decision_mapping_table_erase_entry(size_t bank_index,
                                                                                   const meter_rate_limiter_color_pair& color_pair)
{
    npl_rx_meter_stat_meter_decision_mapping_table_t::key_type k;

    k.meter_bank_index.value = bank_index;
    k.meter_result_color.value = la_2_meter_color(color_pair.first);
    k.exact_meter_to_stat_meter_color.value = la_2_meter_color(color_pair.second);
    k.meter_action_profile_index.value = m_stat_bank_data.profile_index;

    la_slice_id_vec_t nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (auto sid : nw_slices) {
        la_status status = m_device->m_tables.rx_meter_stat_meter_decision_mapping_table[sid]->erase(k);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_meter_action_profile_impl::type() const
{
    return object_type_e::METER_ACTION_PROFILE;
}

const la_device*
la_meter_action_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_meter_action_profile_impl::oid() const
{
    return m_oid;
}

std::string
la_meter_action_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_meter_action_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

bool
la_meter_action_profile_impl::is_allocated_in_exact_bank(la_slice_ifg slice_ifg) const
{
    size_t g_ifg = m_ifg_use_count->get_index(slice_ifg);
    return (m_exact_meters_allocation[g_ifg].profile_index != INVALID_INDEX);
}

bool
la_meter_action_profile_impl::is_allocated_in_statistical_banks() const
{
    return (m_stat_bank_data.profile_index != INVALID_INDEX);
}

} // namespace silicon_one
