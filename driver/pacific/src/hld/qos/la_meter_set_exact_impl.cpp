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

#include "la_meter_set_exact_impl.h"
#include "api/npu/la_l2_port.h"
#include "api/npu/la_l3_port.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "la_meter_set_impl.h"
#include "la_strings.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/tm_utils.h"

#include <sstream>
#include <thread>
#include <unistd.h>

namespace silicon_one
{
la_meter_set_exact_impl::la_meter_set_exact_impl(const la_device_impl_wptr& device) : la_meter_set_impl(device)
{
}

la_meter_set_exact_impl::~la_meter_set_exact_impl()
{
}

la_status
la_meter_set_exact_impl::initialize(la_object_id_t oid, type_e meter_type, size_t size)
{
    la_status status = la_meter_set_impl::initialize(oid, meter_type, size);
    return_on_error(status);

    m_cached_packets.resize(size, {{}});
    m_cached_bytes.resize(size, {{}});
    m_allocations.resize(NUM_SLICE_PAIRS_PER_DEVICE);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_set_cir(size_t meter_index)
{
    la_status status = configure_meter_shaper_configuration_for_used_ifgs(meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_set_eir(size_t meter_index)
{
    la_status status = configure_meter_shaper_configuration_for_used_ifgs(meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::set_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t cir)
{
    start_api_call("meter_index=", meter_index, "ifg=", ifg, "cir=", cir);
    if (m_meter_type != type_e::PER_IFG_EXACT) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    npl_meter_weight_t out_weight;
    la_status status = populate_weight_from_cir_or_eir(meter_index, cir, true /*is_cir*/, out_weight);
    return_on_error(status);
    m_meters_properties[meter_index].cir_weight[g_ifg] = out_weight;
    m_meters_properties[meter_index].user_cir[g_ifg] = cir;

    if (!m_user_to_aggregation.empty() && m_ifg_use_count->is_ifg_in_use(ifg)) {
        status = configure_meter_shaper_configuration_entry(ifg, meter_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::get_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_cir) const
{
    start_api_getter_call();
    if (m_meter_type != type_e::PER_IFG_EXACT) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    npl_meter_weight_t cir_weight = m_meters_properties[meter_index].cir_weight[g_ifg];
    la_status status = populate_cir_or_eir_from_weight(meter_index, cir_weight, true /*is_cir*/, out_cir);
    return status;
}

la_status
la_meter_set_exact_impl::set_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t eir)
{
    start_api_call("meter_index=", meter_index, "ifg=", ifg, "eir=", eir);
    if (m_meter_type != type_e::PER_IFG_EXACT) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    npl_meter_weight_t out_weight;
    la_status status = populate_weight_from_cir_or_eir(meter_index, eir, false /*is_cir*/, out_weight);
    return_on_error(status);
    m_meters_properties[meter_index].eir_weight[g_ifg] = out_weight;
    m_meters_properties[meter_index].user_eir[g_ifg] = eir;

    if (!m_user_to_aggregation.empty() && m_ifg_use_count->is_ifg_in_use(ifg)) {
        status = configure_meter_shaper_configuration_entry(ifg, meter_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::get_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_eir) const
{
    start_api_getter_call();
    if (m_meter_type != type_e::PER_IFG_EXACT) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    npl_meter_weight_t eir_weight = m_meters_properties[meter_index].eir_weight[g_ifg];
    la_status status = populate_cir_or_eir_from_weight(meter_index, eir_weight, false /*is_cir*/, out_eir);
    return status;
}

la_status
la_meter_set_exact_impl::do_set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode)
{
    if (!m_user_to_aggregation.empty()) {
        la_status status = m_ifg_use_count->for_each_ifg(
            [this, meter_index](la_slice_ifg ifg) { return configure_meters_attribute_entry(ifg, meter_index); });
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_set_meter_profile(size_t meter_index, const la_meter_profile_impl_wptr& meter_profile_impl)
{
    la_meter_profile::meter_measure_mode_e measure_mode;
    auto status = meter_profile_impl->get_meter_measure_mode(measure_mode);
    return_on_error(status);

    m_device->add_ifg_dependency(this, meter_profile_impl);

    m_ifg_use_count->for_each_ifg([this, meter_index, meter_profile_impl](la_slice_ifg ifg) {
        la_status status = configure_meters_attribute_entry(ifg, meter_index);
        return_on_error(status);

        status = configure_meter_state_entry(ifg, meter_index);
        return_on_error(status);

        status = configure_meters_table_entry(ifg, meter_index);

        return status;
    });

    status = add_current_ifgs(this->m_ifg_use_count.get(), meter_profile_impl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_set_meter_action_profile(size_t meter_index,
                                                     const la_meter_action_profile_impl_wptr& meter_action_profile_impl)
{
    m_device->add_ifg_dependency(this, meter_action_profile_impl);

    la_status status = m_ifg_use_count->for_each_ifg([this, meter_index, meter_action_profile_impl](la_slice_ifg ifg) {
        la_status status = configure_meters_attribute_entry(ifg, meter_index);
        return_on_error(status);

        status = configure_meter_state_entry(ifg, meter_index);
        return status;
    });

    status = add_current_ifgs(this->m_ifg_use_count.get(), meter_action_profile_impl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_detach_meter_profile(size_t meter_index)
{
    auto meter_profile_impl = m_meters_properties[meter_index].meter_profile;
    m_device->remove_ifg_dependency(this, meter_profile_impl);

    la_status status = remove_current_ifgs(this->m_ifg_use_count.get(), meter_profile_impl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_detach_meter_action_profile(size_t meter_index)
{
    auto meter_action_profile_impl = m_meters_properties[meter_index].meter_action_profile;
    m_device->remove_ifg_dependency(this, meter_action_profile_impl);

    la_status status = remove_current_ifgs(this->m_ifg_use_count.get(), meter_action_profile_impl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_attach_user(const la_object_wcptr& user, bool is_aggregate)
{
    if (m_meter_type == type_e::EXACT) {
        la_status status;
        status = validate_new_user(user, is_aggregate);
        return_on_error(status);
    }

    slice_ifg_vec_t ifgs = ((user->type() == la_object::object_type_e::DEVICE) ||  /* trap/redirect meter */
                            (user->type() == la_object::object_type_e::METER_SET)) /* meter_set as global user */
                               ? get_all_network_ifgs(m_device)
                               : get_ifgs(user);
    for (auto ifg : ifgs) {
        la_status status = add_ifg(ifg, is_aggregate);
        return_on_error(status);
    }

    m_device->add_ifg_dependency(user, this);
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::configure_meter_state_entry(la_slice_ifg ifg, size_t meter_index)
{
    // This is a DYNAMIC table and each line contains 2 entries.
    size_t block_index, table_index, line_index, entry_index;
    la_status status
        = get_mem_line_params(ifg, meter_index, 2 /*entries_in_line*/, block_index, table_index, line_index, entry_index);
    return_on_error(status);

    lld_memory_scptr state_table = (*m_device->m_pacific_tree->rx_meter->block[block_index]->meters_state_table)[table_index];
    rx_meter_block_meters_state_table_memory entry;
    // Since this is a dynamic table, in simulator we will always get 0's vector.
    status = m_device->m_ll_device->read_memory(state_table, line_index, entry);
    return_on_error(status);

    status = populate_meter_state_entry(ifg, meter_index, entry);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(state_table, line_index, entry);

    return status;
}

la_status
la_meter_set_exact_impl::configure_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_block_meter_attribute_table_t::key_type k;
    npl_rx_meter_block_meter_attribute_table_t::value_type v;
    npl_rx_meter_block_meter_attribute_table_t::entry_pointer_type e = nullptr;

    populate_general_key(ifg, meter_index, k);

    la_status status = populate_meters_attribute_payload(ifg, meter_index, v.payloads.rx_meter_block_meter_attribute_result);
    return_on_error(status);
    v.action = NPL_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE_ACTION_WRITE;

    status = m_device->m_tables.rx_meter_block_meter_attribute_table->set(k, v, e);

    return status;
}

la_status
la_meter_set_exact_impl::erase_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_block_meter_attribute_table_t::key_type k;
    populate_general_key(ifg, meter_index, k);
    la_status status = m_device->m_tables.rx_meter_block_meter_attribute_table->erase(k);
    return status;
}

la_status
la_meter_set_exact_impl::configure_meter_shaper_configuration_for_used_ifgs(size_t meter_index)
{
    if (!m_user_to_aggregation.empty()) {
        la_status status = m_ifg_use_count->for_each_ifg(
            [this, meter_index](la_slice_ifg ifg) { return configure_meter_shaper_configuration_entry(ifg, meter_index); });
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::configure_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_block_meter_shaper_configuration_table_t::key_type k;
    npl_rx_meter_block_meter_shaper_configuration_table_t::value_type v;
    npl_rx_meter_block_meter_shaper_configuration_table_t::entry_pointer_type e = nullptr;

    populate_general_key(ifg, meter_index, k);

    la_status status = populate_meter_shaper_configuration_payload(
        ifg, meter_index, v.payloads.rx_meter_block_meter_shaper_configuration_result);
    return_on_error(status);
    v.action = NPL_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE_ACTION_WRITE;

    status = m_device->m_tables.rx_meter_block_meter_shaper_configuration_table->set(k, v, e);

    return status;
}

la_status
la_meter_set_exact_impl::erase_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_block_meter_shaper_configuration_table_t::key_type k;
    populate_general_key(ifg, meter_index, k);
    la_status status = m_device->m_tables.rx_meter_block_meter_shaper_configuration_table->erase(k);
    return status;
}

la_status
la_meter_set_exact_impl::configure_meters_table_entry(la_slice_ifg ifg, size_t meter_index)
{
    size_t block_index, table_index, line_index, entry_index;
    la_status status
        = get_mem_line_params(ifg, meter_index, 2 /*entries_in_line*/, block_index, table_index, line_index, entry_index);
    return_on_error(status);

    lld_memory_scptr meters_table = (*m_device->m_pacific_tree->rx_meter->block[block_index]->meters_table)[table_index];
    status = do_configure_meters_table_entry<rx_meter_block_meters_table_memory>(ifg, meter_index, meters_table, line_index);
    return status;
}

la_status
la_meter_set_exact_impl::get_mem_line_params(la_slice_ifg& ifg,
                                             size_t meter_index,
                                             size_t entries_in_line,
                                             size_t& block_index,
                                             size_t& table_index,
                                             size_t& line_index,
                                             size_t& entry_index)
{
    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    size_t bank_offset = g_ifg % 4;
    size_t bank_id = m_allocations[ifg.slice / 2]->get_bank_id();
    size_t alloc_index = m_allocations[ifg.slice / 2]->get_index();

    if (bank_id == ((size_t)-1) || alloc_index == ((size_t)-1)) {
        return LA_STATUS_EUNKNOWN;
    }

    size_t bank_index = bank_id + bank_offset;
    size_t exact_meter_index = alloc_index + meter_index;

    block_index = (bank_index - FIRST_EXACT_METER_BANK_INDEX) / 3;
    table_index = (bank_index - FIRST_EXACT_METER_BANK_INDEX) % 3;

    line_index = exact_meter_index / entries_in_line;
    entry_index = exact_meter_index % entries_in_line;
    return LA_STATUS_SUCCESS;
}

void
la_meter_set_exact_impl::get_bank_and_base_index(la_slice_ifg ifg, size_t& bank_index, size_t& set_base_index) const
{
    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    size_t bank_offset = g_ifg % 4;
    size_t _bank_index = m_allocations[ifg.slice / 2]->get_bank_id() + bank_offset;

    bank_index = _bank_index - FIRST_EXACT_METER_BANK_INDEX;
    set_base_index = m_allocations[ifg.slice / 2]->get_index();
}

la_status
la_meter_set_exact_impl::get_meter_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const
{
    la_status status = m_meters_properties[meter_index].meter_profile->get_allocation_in_exact_bank(ifg, out_index);
    return status;
}

la_status
la_meter_set_exact_impl::get_meter_action_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const
{
    la_status status = m_meters_properties[meter_index].meter_action_profile->get_allocation_in_exact_bank(ifg, out_index);
    return status;
}

la_status
la_meter_set_exact_impl::get_counter(la_counter_set*& out_counter) const
{
    // TODO: need to create/attach counter in creation phase?
    out_counter = m_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::read(size_t counter_index,
                              bool force_update,
                              bool clear_on_read,
                              la_qos_color_e color,
                              size_t& out_packets,
                              size_t& out_bytes)
{
    start_api_getter_call(
        "counter_index=", counter_index, "force_update=", force_update, "clear_on_read=", clear_on_read, " color=", color);

    if (counter_index >= m_set_size) {
        log_err(HLD, "counter_index is out of range index=%ld size=%ld", counter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    if ((size_t)color > (size_t)la_qos_color_e::RED) {
        // Can happen if called from Swig
        log_err(HLD, "Unknown color %lu", (size_t)color);
        return LA_STATUS_EINVAL;
    }

    out_packets = m_cached_packets[counter_index][(size_t)color];
    out_bytes = m_cached_bytes[counter_index][(size_t)color];

    for (size_t i = 0; i < m_allocations.size(); i++) {
        if (m_allocations[i] != nullptr) {
            const counter_allocation& alloc(*m_allocations[i]);
            size_t packets;
            size_t bytes;
            m_device->m_counter_bank_manager->read_meter(alloc, counter_index, color, force_update, clear_on_read, bytes, packets);
            out_packets += packets;
            out_bytes += bytes;
        }
    }

    if (clear_on_read) {
        m_cached_bytes[counter_index][(size_t)color] = 0;
        m_cached_packets[counter_index][(size_t)color] = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::read(la_slice_ifg ifg, size_t counter_index, la_qos_color_e color, size_t& out_packets, size_t& out_bytes)
{
    start_api_getter_call("counter_index=", counter_index, "ifg.slice=", ifg.slice, "ifg.ifg=", ifg.ifg, " color=", color);

    if ((size_t)color > (size_t)la_qos_color_e::RED) {
        // Can happen if called from Swig
        log_err(HLD, "Unknown color %lu", (size_t)color);
        return LA_STATUS_EINVAL;
    }
    la_status stat = m_slice_id_manager->is_slice_ifg_valid(ifg);
    return_on_error(stat);

    size_t gifg = m_slice_id_manager->slice_ifg_2_global_ifg(ifg);

    for (size_t i = 0; i < m_allocations.size(); i++) {
        if (m_allocations[i] != nullptr) {
            const counter_allocation& alloc(*m_allocations[i]);
            size_t alloc_gifg = m_slice_id_manager->slice_ifg_2_global_ifg(alloc.get_ifg());
            bool is_inside_alloc = (gifg >= alloc_gifg) && (gifg < alloc_gifg + alloc.get_num_of_ifgs());
            if (is_inside_alloc) {
                m_device->m_counter_bank_manager->read_meter_ifg(alloc, ifg, counter_index, color, out_bytes, out_packets);
                break;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::get_allocation(la_slice_ifg slice_ifg, counter_allocation& out_allocation) const
{
    la_slice_pair_id_t pair_idx = slice_ifg.slice / 2;

    if (m_allocations[pair_idx] == nullptr) {
        log_err(HLD, "Failed fetch for slice slice_ifg=%d/%d ", slice_ifg.slice, slice_ifg.ifg);
        return LA_STATUS_ENOTFOUND;
    }

    out_allocation = *m_allocations[pair_idx];

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::do_release_allocation(counter_allocation& allocation, la_slice_ifg ifg, bool slice_pair_removed)
{
    if (is_lpts_entry_meter()) {
        if (slice_pair_removed) {
            // LPTS allocations should be released when the LPTS instance is destroyed.
            size_t pair_idx = ifg.slice / 2;
            if (m_allocations[pair_idx] == nullptr) {
                return LA_STATUS_EUNKNOWN;
            }
            // Return the allocation back to the device.
            la_status status = m_device->release_lpts_counter_allocation(pair_idx, allocation);
            return_on_error(status);
            m_allocations[pair_idx].reset();
        }
        return LA_STATUS_SUCCESS;
    }

    if (slice_pair_removed) {

        m_device->m_counter_bank_manager->release(m_counter_user_type, allocation);

        // Remove the allocation from the allocations map
        size_t pair_idx = ifg.slice / 2;
        if (m_allocations[pair_idx] == nullptr) {
            return LA_STATUS_EUNKNOWN;
        }

        m_allocations[pair_idx].reset();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::release_allocation_on_remove_ifg(la_slice_ifg ifg, bool slice_pair_removed)
{
    // Get the corresponding allocation
    counter_allocation allocation;
    la_status status = get_allocation(ifg, allocation);
    return_on_error(status);

    // Update the counter cache
    for (size_t counter_index = 0; counter_index < m_set_size; counter_index++) {
        static const la_qos_color_e iter_colors[] = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};
        for (auto& color : iter_colors) {
            // Reading from all slices
            uint64_t bytes;
            uint64_t packets;

            m_device->m_counter_bank_manager->read_meter(
                allocation, counter_index, color, true /* force_update*/, true /*clear_on_read*/, bytes, packets);
            m_cached_bytes[counter_index][(size_t)color] += bytes;
            m_cached_packets[counter_index][(size_t)color] += packets;
        }
    }

    // Release the allocation
    status = do_release_allocation(allocation, ifg, slice_pair_removed);

    return status;
}

la_status
la_meter_set_exact_impl::do_detach_user(const la_object_wcptr& user)
{
    slice_ifg_vec_t ifgs = ((user->type() == la_object::object_type_e::DEVICE) ||  /* trap/redirect meter */
                            (user->type() == la_object::object_type_e::METER_SET)) /* meter_set as global user */
                               ? get_all_network_ifgs(m_device)
                               : get_ifgs(user);

    for (auto ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    m_device->remove_ifg_dependency(user, this);
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        switch (op.action.ifg_management.ifg_op) {
        case ifg_management_op::IFG_ADD:
            return add_ifg(op.action.ifg_management.ifg, op.dependee);
        case ifg_management_op::IFG_REMOVE:
            return remove_ifg(op.action.ifg_management.ifg);
        default:
            log_err(HLD, "%s: unknown ifg_management_op", __PRETTY_FUNCTION__);
            return LA_STATUS_EUNKNOWN;
        }

    default:
        log_err(HLD, "%s: received unsupported notification (%s)", __PRETTY_FUNCTION__, silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::add_ifg(la_slice_ifg ifg, bool is_aggregate)
{
    bool ifg_added, slice_added, slice_pair_added;
    transaction txn;

    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([=]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }

    txn.status = do_allocation_on_add_ifg(ifg, slice_pair_added, is_aggregate);
    return_on_error(txn.status);
    txn.on_fail([=]() {
        counter_allocation allocation;
        la_status status = get_allocation(ifg, allocation);
        return_on_error(status);
        status = do_release_allocation(allocation, ifg, slice_pair_added);
        return status;
    });

    // Notify users
    txn.status = m_device->notify_ifg_added(this, ifg);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_device->notify_ifg_removed(this, ifg); });

    txn.status = configure_metering(ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::remove_ifg(la_slice_ifg ifg)
{
    // Notify users
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (!ifg_removed) {
        return LA_STATUS_SUCCESS;
    }
    la_status status = wait_until_meter_is_full(ifg);
    return_on_error(status);

    status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(status);

    status = erase_metering(ifg);
    return_on_error(status);

    status = release_allocation_on_remove_ifg(ifg, slice_pair_removed);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Use this before add_ifg to get seperate accounting.
void
la_meter_set_exact_impl::set_counter_user_type(counter_user_type_e type)
{
    m_counter_user_type = type;
}

la_status
la_meter_set_exact_impl::do_allocation_on_add_ifg(la_slice_ifg ifg, bool slice_pair_added, bool is_aggregate)
{
    if (is_lpts_entry_meter()) {
        if (slice_pair_added) {
            // LPTS allocations should be done from the device.
            size_t pair_idx = ifg.slice / 2;
            auto ca = make_unique<counter_allocation>();
            la_status status = m_device->assign_lpts_counter_allocation(pair_idx, *ca);
            return_on_error(status);
            m_allocations[pair_idx] = std::move(ca);
            log_debug(HLD,
                      "%s: slice_ifg=%d/%d allocation=%s",
                      __func__,
                      ifg.slice,
                      ifg.ifg,
                      m_allocations[pair_idx]->to_string().c_str());
        }
        return LA_STATUS_SUCCESS;
    }

    if (slice_pair_added) {
        size_t num_of_ifgs = is_aggregate ? NUM_IFGS_PER_SLICE * 2 : 1;
        size_t pair_idx = ifg.slice / 2;
        auto ca = make_unique<counter_allocation>();
        size_t allocation_size = round_up(m_set_size, 2); // Each row in the meters-table holds 2 entries.
        // It's a dynamic table with side effects on writes, so
        // a row cannot be shared between different meter-sets.
        la_status status = m_device->m_counter_bank_manager->allocate(true /*is_slice_pair*/,
                                                                      COUNTER_DIRECTION_INGRESS, // Meters are ingress only
                                                                      allocation_size,
                                                                      ifg,
                                                                      num_of_ifgs,
                                                                      m_counter_user_type,
                                                                      *ca);
        return_on_error(status);
        m_allocations[pair_idx] = std::move(ca);
        log_debug(
            HLD, "%s: slice_ifg=%d/%d allocation=%s", __func__, ifg.slice, ifg.ifg, m_allocations[pair_idx]->to_string().c_str());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::get_ethernet_port_from_logical_port(const la_object_wcptr& logical_port,
                                                             la_ethernet_port_wcptr& out_eth_port)
{
    la_status status;
    object_type_e user_type = logical_port->type();

    if (user_type == la_object::object_type_e::L3_AC_PORT) {
        auto user_l3_port = logical_port.weak_ptr_static_cast<const la_l3_ac_port>();
        auto eth_port = user_l3_port->get_ethernet_port();
        out_eth_port = m_device->get_sptr(eth_port);
    } else if (user_type == la_object::object_type_e::L2_SERVICE_PORT) {
        auto user_l2_port = logical_port.weak_ptr_static_cast<const la_l2_service_port>();
        const la_ethernet_port* eth_port;
        status = user_l2_port->get_ethernet_port(eth_port);
        return_on_error(status);
        out_eth_port = m_device->get_sptr(eth_port);
    } else {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::validate_new_user(const la_object_wcptr& user, bool is_aggregate)
{
    if (is_aggregate) {
        log_err(HLD, "Aggregate user must not use EXACT meter");
        return LA_STATUS_EINVAL;
    }

    // If this is the first non aggregate user then we attach it without further validation
    if (m_user_to_aggregation.empty()) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    la_ethernet_port_wcptr user_eth_port = nullptr;
    la_ethernet_port_wcptr existing_eth_port = nullptr;

    status = get_ethernet_port_from_logical_port(user, user_eth_port);
    return_on_error(status, HLD, ERROR, "Attaching meter to new user not possible, doesn't have an ethernet port");

    auto existing_user_pair = m_user_to_aggregation.begin();
    status = get_ethernet_port_from_logical_port(existing_user_pair->first, existing_eth_port);
    return_on_error(status, HLD, ERROR, "Existing meter user doesn't have an ethernet port, cannot share meter with new user");

    if (user_eth_port != existing_eth_port) {
        log_err(HLD, "Cant attach meter, user is not on same ethernet port as previous user(s)");
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_exact_impl::wait_until_meter_is_full(la_slice_ifg ifg)
{
    rx_meter_block_meters_table_memory entry;
    la_status status;

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    size_t block_index;
    size_t table_index;
    size_t line_index;
    size_t entry_index;

    int usecs = 0;
    la_uint64_t cbs = 0;
    la_uint64_t ebs = 0;
    la_rate_t old_cir = 0;
    la_rate_t old_eir = 0;
    la_uint64_t last_cbs_read = 0;
    la_uint64_t last_ebs_read = 0;

    status = m_device->get_int_property(la_device_property_e::METER_BUCKET_REFILL_POLLING_DELAY, usecs);

    for (size_t meter_index = 0; meter_index < m_set_size; ++meter_index) {
        last_cbs_read = 0;
        last_ebs_read = 0;

        status = get_mem_line_params(ifg, meter_index, 2 /*entries_in_line*/, block_index, table_index, line_index, entry_index);
        return_on_error(status);

        lld_memory_scptr meters_table = (*m_device->m_pacific_tree->rx_meter->block[block_index]->meters_table)[table_index];

        if (m_meter_type != type_e::PER_IFG_EXACT) {
            // First, fetch the CBS / EBS.
            status = m_meters_properties[meter_index].meter_profile->get_cbs(cbs);
            return_on_error(status);

            status = m_meters_properties[meter_index].meter_profile->get_ebs_or_pbs(ebs);
            return_on_error(status);

            // Store old CIR to restore it after meters fill up.
            old_cir = m_meters_properties[meter_index].user_cir[SINGLE_ALLOCATION_IFG];
            old_eir = m_meters_properties[meter_index].user_eir[SINGLE_ALLOCATION_IFG];

            // Set high data rate so that meters fill up sooner
            status = set_cir(meter_index, FAST_REFILL_RATE);
            return_on_error(status);

            status = set_eir(meter_index, FAST_REFILL_RATE);
            return_on_error(status);
        } else {
            // First, fetch the CBS / EBS.
            status = m_meters_properties[meter_index].meter_profile->get_cbs(ifg, cbs);
            return_on_error(status);

            status = m_meters_properties[meter_index].meter_profile->get_ebs_or_pbs(ifg, ebs);
            return_on_error(status);

            // Store old CIR to restore it after meters fill up.
            old_cir = m_meters_properties[meter_index].user_cir[g_ifg];
            old_eir = m_meters_properties[meter_index].user_eir[g_ifg];

            // Set high data rate so that meters fill up sooner
            status = set_cir(meter_index, ifg, FAST_REFILL_RATE);
            return_on_error(status);

            status = set_eir(meter_index, ifg, FAST_REFILL_RATE);
            return_on_error(status);
        }

        // Wait until the meter fills up.
        for (int i = 0; i < 500 && (last_cbs_read < cbs || last_ebs_read < ebs); i++) {
            usleep(usecs);
            status = m_device->m_ll_device->read_memory(meters_table, line_index, entry);
            return_on_error(status);
            if ((meter_index % 2) == 0) {
                last_cbs_read = entry.fields.table_entry0_commited_meter;
                last_ebs_read = entry.fields.table_entry0_excess_meter;
            } else {
                last_cbs_read = entry.fields.table_entry1_commited_meter;
                last_ebs_read = entry.fields.table_entry1_excess_meter;
            }
        }

        // Return old IR's
        if (m_meter_type != type_e::PER_IFG_EXACT) {
            status = set_cir(meter_index, old_cir);
            return_on_error(status);

            status = set_eir(meter_index, old_eir);
            return_on_error(status);
        } else {
            status = set_cir(meter_index, ifg, old_cir);
            return_on_error(status);

            status = set_eir(meter_index, ifg, old_eir);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
