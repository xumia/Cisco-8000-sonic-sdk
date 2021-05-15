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

#include "la_meter_set_statistical_impl.h"
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
#include "tm/tm_utils.h"

#include <sstream>
#include <thread>
#include <unistd.h>

namespace silicon_one
{

constexpr size_t NUM_METERS_PER_LINE_IN_METERS_STATE_TABLE = 2;
constexpr size_t NUM_METERS_PER_LINE_IN_METERS_TABLE = 2;
constexpr size_t NUM_METERS_PER_LINE_IN_METERS_TOKEN_TABLE = 4;

la_meter_set_statistical_impl::la_meter_set_statistical_impl(const la_device_impl_wptr& device)
    : la_meter_set_impl(device), m_bank_index(INVALID_INDEX), m_set_base_index(INVALID_INDEX), m_exact_meter_set_impl(nullptr)
{
}

la_meter_set_statistical_impl::~la_meter_set_statistical_impl()
{
}

la_status
la_meter_set_statistical_impl::initialize(la_object_id_t oid, type_e meter_type, size_t size)
{
    SINGLE_ALLOCATION_SLICE_IFG = {.slice = m_device->first_active_slice_id(), .ifg = 0};
    la_status status = la_meter_set_impl::initialize(oid, meter_type, size);
    return_on_error(status);

    // TODO: the size here should be changed to NUM_STATISTICAL_METER_BANKS when we do allocation per bank.
    m_allocations.resize(1);
    m_token_sizes.resize(size);
    // The shaper's rate in distribution tokens is 1/8 [token/clock], and the device frequency is m_device_frequency_float_ghz
    // [clocks/second].
    // So, the shaper will distribute 1/8 [dist/clock] * 1.05 [Giga clocks / sec] times in a second.
    m_shaper_tokens_per_sec = m_device->m_device_frequency_float_ghz * SHAPER_DISTRIBUTION_RATE_PER_CLOCK;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_set_cir(size_t meter_index)
{
    la_status status = configure_meter_shaper_configuration_entry(SINGLE_ALLOCATION_SLICE_IFG, meter_index);
    return_on_error(status);

    status = configure_meters_token_table(meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_set_eir(size_t meter_index)
{
    la_status status = configure_meter_shaper_configuration_entry(SINGLE_ALLOCATION_SLICE_IFG, meter_index);
    return_on_error(status);

    status = configure_meters_token_table(meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::set_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t cir)
{
    start_api_call("meter_index=", meter_index, "ifg=", ifg, "cir=", cir);
    log_err(HLD, "Per-ifg function is called for non per-ifg meter");
    return LA_STATUS_EINVAL;
}

la_status
la_meter_set_statistical_impl::get_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_cir) const
{
    start_api_getter_call();
    log_err(HLD, "Per-ifg function is called for non per-ifg meter");
    return LA_STATUS_EINVAL;
}

la_status
la_meter_set_statistical_impl::set_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t eir)
{
    start_api_call("meter_index=", meter_index, "ifg=", ifg, "eir=", eir);
    log_err(HLD, "Per-ifg function is called for non per-ifg meter");
    return LA_STATUS_EINVAL;
}

la_status
la_meter_set_statistical_impl::get_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_eir) const
{
    start_api_getter_call();
    log_err(HLD, "Per-ifg function is called for non per-ifg meter");
    return LA_STATUS_EINVAL;
}

la_meter_set_statistical_impl::meters_token_entry_details_t
la_meter_set_statistical_impl::get_meters_token_table_entry_details(size_t meter_index) const
{
    meters_token_entry_details_t entry_details;

    size_t meter_phys_index = (m_set_base_index + meter_index);
    // Each line in the table contains 8 entries, and each meter should configure 2 entries: one for its cir and one for eir.
    entry_details.line_index = meter_phys_index / NUM_METERS_PER_LINE_IN_METERS_TOKEN_TABLE;
    // This is the index of first relevant entry to this meter, it configures the meter's cir, the one after it is for the eir.
    entry_details.entry_index = 2 * (meter_phys_index % NUM_METERS_PER_LINE_IN_METERS_TOKEN_TABLE);
    // We assume all entries have the same length
    constexpr size_t ENTRY_LENGTH = rx_meter_meters_token_table_memory::fields::TABLE_ENTRY0_TOKEN_SIZE_WIDTH;
    entry_details.cir_lsb = entry_details.entry_index * ENTRY_LENGTH;
    entry_details.cir_msb = entry_details.cir_lsb + ENTRY_LENGTH - 1;
    entry_details.eir_lsb = entry_details.cir_msb + 1;
    entry_details.eir_msb = entry_details.eir_lsb + ENTRY_LENGTH - 1;

    return entry_details;
}

la_status
la_meter_set_statistical_impl::configure_meters_token_table(size_t meter_index)
{
    if (!is_allocated()) {
        return LA_STATUS_SUCCESS;
    }

    lld_memory_scptr tokens_table = (*m_device->m_pacific_tree->rx_meter->top->meters_token_table)[m_bank_index];

    meters_token_entry_details_t entry_details = get_meters_token_table_entry_details(meter_index);
    bit_vector entry;
    la_status status = m_device->m_ll_device->read_memory(tokens_table, entry_details.line_index, entry);
    return_on_error(status);
    // We need this resize to avoid a warning message about unmatching lengths when we write to the table,
    // this happens because read_memory will align the bitvector to bytes (i.e. multiplier of 8) and in this case,
    // this will be longer than the table's line length.
    entry.resize(rx_meter_meters_token_table_memory::SIZE_IN_BITS_WO_ECC);

    entry.set_bits(entry_details.cir_msb, entry_details.cir_lsb, m_token_sizes[meter_index].cir_token_size);
    entry.set_bits(entry_details.eir_msb, entry_details.eir_lsb, m_token_sizes[meter_index].eir_token_size);

    status = m_device->m_ll_device->write_memory(tokens_table, entry_details.line_index, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode)
{
    if (!is_allocated()) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = configure_meters_attribute_entry(SINGLE_ALLOCATION_SLICE_IFG, meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_set_meter_profile(size_t meter_index, const la_meter_profile_impl_wptr& meter_profile_impl)
{
    la_status status = meter_profile_impl->attach_statistical_meter();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_set_meter_action_profile(size_t meter_index,
                                                           const la_meter_action_profile_impl_wptr& meter_action_profile_impl)
{
    la_status status = meter_action_profile_impl->attach_statistical_meter();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_detach_meter_profile(size_t meter_index)
{
    auto meter_profile_impl = m_meters_properties[meter_index].meter_profile;
    la_status status = meter_profile_impl->detach_statistical_meter();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_detach_meter_action_profile(size_t meter_index)
{
    auto meter_action_profile_impl = m_meters_properties[meter_index].meter_action_profile;
    la_status status = meter_action_profile_impl->detach_statistical_meter();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::notify_change(dependency_management_op op)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_meter_set_statistical_impl::configure_meter_state_entry(la_slice_ifg ifg, size_t meter_index)
{
    // MeterStateTable of statistical meters has 24 instances: 4 banks * 6 slices.
    // - Table 0  - belong to slice 0 bank 0
    // - Table 1  - belong to slice 0 bank 1
    // - Table 2  - belong to slice 0 bank 2
    // - ...
    // - Table 22 - belong to slice 5 bank 2
    // - Table 23 - belong to slice 5 bank 3
    // The tables that belong to the same bank should be identical, i.e. each meter is configured the same in all slices.
    // Hence, if we need to configure meter state table of a meter in bank b,
    // we need to update the instances: {4*sid + b} for sid=0,...,5

    size_t line_index = (m_set_base_index + meter_index) / NUM_METERS_PER_LINE_IN_METERS_STATE_TABLE;
    lld_memory_line_value_list_t write_list;
    la_meter_profile::cascade_mode_e meter_cascade_mode;
    la_status status = m_meters_properties[meter_index].meter_profile->get_cascade_mode(meter_cascade_mode);
    return_on_error(status);

    for (la_slice_id_t sid : m_device->get_used_slices()) {
        size_t table_instance = sid * NUM_STATISTICAL_METER_BANKS + m_bank_index;
        lld_memory_scptr state_table = (*m_device->m_pacific_tree->rx_meter->top->meters_state_table)[table_instance];
        rx_meter_meters_state_table_memory entry;
        status = m_device->m_ll_device->read_memory(state_table, line_index, entry);
        return_on_error(status);

        status = populate_meter_state_entry(ifg, meter_index, entry);
        return_on_error(status);
        if ((meter_index % 2) == 0) {
            entry.fields.meters_state_entry0_is_cascade = la_2_meter_cascade_mode(meter_cascade_mode);
        } else {
            entry.fields.meters_state_entry1_is_cascade = la_2_meter_cascade_mode(meter_cascade_mode);
        }

        write_list.push_back({{state_table, line_index}, entry});
    }

    status = lld_write_memory_line_list(m_device->m_ll_device, write_list);

    return status;
}

la_status
la_meter_set_statistical_impl::configure_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_meters_attribute_table_t::key_type k;
    npl_rx_meter_meters_attribute_table_t::value_type v;
    npl_rx_meter_meters_attribute_table_t::entry_pointer_type e = nullptr;

    populate_general_key(ifg, meter_index, k);

    la_status status = populate_meters_attribute_payload(ifg, meter_index, v.payloads.rx_meter_meters_attribute_result);
    return_on_error(status);

    v.action = NPL_RX_METER_METERS_ATTRIBUTE_TABLE_ACTION_WRITE;

    status = m_device->m_tables.rx_meter_meters_attribute_table->set(k, v, e);

    return status;
}

la_status
la_meter_set_statistical_impl::erase_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_meters_attribute_table_t::key_type k;
    populate_general_key(ifg, meter_index, k);
    la_status status = m_device->m_tables.rx_meter_meters_attribute_table->erase(k);
    return status;
}

la_status
la_meter_set_statistical_impl::configure_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_meter_shaper_configuration_table_t::key_type k;
    npl_rx_meter_meter_shaper_configuration_table_t::value_type v;
    npl_rx_meter_meter_shaper_configuration_table_t::entry_pointer_type e = nullptr;

    populate_general_key(ifg, meter_index, k);
    la_status status
        = populate_meter_shaper_configuration_payload(ifg, meter_index, v.payloads.rx_meter_meter_shaper_configuration_result);
    return_on_error(status);
    status = m_device->m_tables.rx_meter_meter_shaper_configuration_table->set(k, v, e);

    return status;
}

la_status
la_meter_set_statistical_impl::erase_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index)
{
    npl_rx_meter_meter_shaper_configuration_table_t::key_type k;
    populate_general_key(ifg, meter_index, k);
    la_status status = m_device->m_tables.rx_meter_meter_shaper_configuration_table->erase(k);
    return status;
}

la_status
la_meter_set_statistical_impl::configure_meters_table_entry(la_slice_ifg ifg, size_t meter_index)
{
    lld_memory_scptr meters_table = (*m_device->m_pacific_tree->rx_meter->top->meters_table)[m_bank_index];
    size_t line_index = (m_set_base_index + meter_index) / NUM_METERS_PER_LINE_IN_METERS_TABLE;

    la_status status = do_configure_meters_table_entry<rx_meter_meters_table_memory>(ifg, meter_index, meters_table, line_index);
    return status;
}

la_status
la_meter_set_statistical_impl::do_allocation()
{
    la_status status;
    // We always allocate an even number, because meters_table and meter_state are dynamic tables that each line in them
    // contains 2 entries. In this case, we can't allow two meter sets to share the same line, because if we do, we may update
    // one entry in a line and override the dynamic bits of the second entry in the line, this will cause an undefined behavior
    // of the HW.
    size_t allocation_size = round_up(m_set_size, 2);
    // There's an ECO that sets bit 1 of the counter/meter pointers on PD on odd numbered slices.
    // Unfortunately - the ECO does so for global meters too, which is wrong. Therefore the only
    // banks that can be used are those with bit 1 is set, i.e. - only banks that can be used are 2 and 3.
    for (size_t i : {2, 3}) {
        status = m_device->m_index_generators.statistical_meter_id[i].allocate(allocation_size, m_set_base_index);
        if (status == LA_STATUS_SUCCESS) {
            m_bank_index = i;
            break;
        }
    }

    if (m_bank_index == INVALID_INDEX) { // no allocation was found
        return LA_STATUS_ERESOURCE;
    }

    m_allocations[SINGLE_ALLOCATION_IFG] = make_unique<counter_allocation>();
    m_allocations[SINGLE_ALLOCATION_IFG]->phys_bank_index = m_bank_index + FIRST_STATISTICAL_METER_BANK_INDEX;
    m_allocations[SINGLE_ALLOCATION_IFG]->base_row_index = m_set_base_index;
    m_allocations[SINGLE_ALLOCATION_IFG]->set_size = m_set_size;
    m_allocations[SINGLE_ALLOCATION_IFG]->num_of_ifgs = 1;
    return LA_STATUS_SUCCESS;
}

const la_meter_set_exact_impl_wptr&
la_meter_set_statistical_impl::get_exact_meter_set_as_counter() const
{
    return m_exact_meter_set_impl;
}

la_status
la_meter_set_statistical_impl::alloc_exact_meter_set_as_counter(la_meter_set_exact_impl_wptr& out_exact_meter_set_impl)
{
    transaction txn;
    la_meter_set_impl_wptr meter_set;
    size_t meter_set_size = 1;

    txn.status = m_device->do_create_meter(la_meter_set::type_e::PER_IFG_EXACT, meter_set_size, meter_set);
    return_on_error(txn.status);
    auto exact_meter_set_impl = meter_set.weak_ptr_static_cast<la_meter_set_exact_impl>();

    size_t meter_index = 0;
    txn.status
        = exact_meter_set_impl->set_committed_bucket_coupling_mode(meter_index, la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_device->do_destroy(meter_set); });

    txn.status = exact_meter_set_impl->set_meter_profile(meter_index, m_device->m_exact_meter_profile.get());
    return_on_error(txn.status);

    txn.status = exact_meter_set_impl->set_meter_action_profile(meter_index, m_device->m_exact_meter_action_profile.get());
    return_on_error(txn.status);

    // Max meter rate to mimic counter behaviour.
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            la_slice_ifg slice_ifg{slice_id, ifg};
            la_rate_t meter_cir = (get_shaper_max_rate(meter_index, true) * UNITS_IN_GIGA);
            txn.status = exact_meter_set_impl->set_cir(meter_index, slice_ifg, meter_cir);
            return_on_error(txn.status);
            la_rate_t meter_eir = (get_shaper_max_rate(meter_index, false) * UNITS_IN_GIGA);
            txn.status = exact_meter_set_impl->set_eir(meter_index, slice_ifg, meter_eir);
            return_on_error(txn.status);
        }
    }

    out_exact_meter_set_impl = exact_meter_set_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_attach_user(const la_object_wcptr& user, bool is_aggregate)
{
    transaction txn;
    if (is_allocated()) {
        return LA_STATUS_SUCCESS;
    }

    txn.status = do_allocation();
    return_on_error(txn.status);

    txn.status = configure_metering(SINGLE_ALLOCATION_SLICE_IFG);
    return_on_error(txn.status);
    txn.on_fail([=]() {
        m_allocations[SINGLE_ALLOCATION_IFG].reset();
        if (m_exact_meter_set_impl != nullptr) {
            m_device->do_destroy(m_exact_meter_set_impl);
            m_exact_meter_set_impl = nullptr;
        }
    });

    for (size_t meter_index = 0; meter_index < m_set_size; meter_index++) {
        txn.status = configure_meters_token_table(meter_index);
        return_on_error(txn.status);
    }

    auto user_type = user->type();
    if ((user_type == la_object::object_type_e::DEVICE) || // Meter is attached to trap/redirect
        (user_type == la_object::object_type_e::L2_MIRROR_COMMAND)) {
        // also mirrors. may not need exact meters on all ifgs - but it simplifies the code
        if (m_exact_meter_set_impl == nullptr) {
            txn.status = alloc_exact_meter_set_as_counter(m_exact_meter_set_impl);
            return_on_error(txn.status);
            txn.status = m_exact_meter_set_impl->attach_user(m_device->get_sptr(this), true);
            return_on_error(txn.status);
            m_device->add_object_dependency(m_exact_meter_set_impl, this);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::do_detach_user(const la_object_wcptr& user)
{
    // check if this is the last user, if not, do nothing.
    if (m_user_to_aggregation.size() > 1) {
        return LA_STATUS_SUCCESS;
    }

    // Meter is detached from trap/redirect
    if (m_exact_meter_set_impl != nullptr) {
        m_device->remove_object_dependency(m_exact_meter_set_impl, this);
        la_status status = m_exact_meter_set_impl->detach_user(m_device->get_sptr(this));
        return_on_error(status);
        status = m_device->do_destroy(m_exact_meter_set_impl);
        return_on_error(status);
        m_exact_meter_set_impl = nullptr;
    }

    // Szikic: WA
    // Meter buckets need to be filled up before we're sure we can release the meter
    // Otherwise we risk the same hw meter being allocated again and being configured
    // while some traffic is still passing through and causing issues.

    la_status status = wait_until_meter_is_full();
    return_on_error(status);

    status = erase_metering(SINGLE_ALLOCATION_SLICE_IFG);
    return_on_error(status);

    status = release_allocation();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_statistical_impl::release_allocation()
{
    size_t allocation_size = round_up(m_set_size, 2);
    m_device->m_index_generators.statistical_meter_id[m_bank_index].release(allocation_size, m_set_base_index);
    m_allocations[SINGLE_ALLOCATION_IFG] = nullptr;
    m_set_base_index = INVALID_INDEX;
    m_bank_index = INVALID_INDEX;
    return LA_STATUS_SUCCESS;
}

void
la_meter_set_statistical_impl::get_bank_and_base_index(la_slice_ifg ifg, size_t& bank_index, size_t& set_base_index) const
{
    bank_index = m_bank_index;
    set_base_index = m_set_base_index;
}

la_status
la_meter_set_statistical_impl::get_meter_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const
{
    return m_meters_properties[meter_index].meter_profile->get_allocation_in_statistical_banks(out_index);
}

la_status
la_meter_set_statistical_impl::get_meter_action_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const
{
    return m_meters_properties[meter_index].meter_action_profile->get_allocation_in_statistical_banks(out_index);
}

la_status
la_meter_set_statistical_impl::get_counter(la_counter_set*& out_counter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_meter_set_statistical_impl::read(size_t counter_index,
                                    bool force_update,
                                    bool clear_on_read,
                                    la_qos_color_e color,
                                    size_t& out_packets,
                                    size_t& out_bytes)
{
    if (m_exact_meter_set_impl != nullptr) {
        la_status status = m_exact_meter_set_impl->read(counter_index, force_update, clear_on_read, color, out_packets, out_bytes);
        return_on_error(status);
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_meter_set_statistical_impl::read(la_slice_ifg ifg,
                                    size_t counter_index,
                                    la_qos_color_e color,
                                    size_t& out_packets,
                                    size_t& out_bytes)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_meter_set_statistical_impl::get_allocation(la_slice_ifg slice_ifg, counter_allocation& out_allocation) const
{
    if (m_allocations[SINGLE_ALLOCATION_IFG] == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_allocation = *m_allocations[SINGLE_ALLOCATION_IFG];

    return LA_STATUS_SUCCESS;
}

float
la_meter_set_statistical_impl::get_shaper_max_rate(size_t meter_index, bool is_cir) const
{
    size_t token_size;
    if (is_cir) {
        token_size = m_token_sizes[meter_index].cir_token_size;
    } else {
        token_size = m_token_sizes[meter_index].eir_token_size;
    }

    return (float)token_size * TOKEN_SIZE_RESOLUTION * m_shaper_tokens_per_sec;
}

bool
la_meter_set_statistical_impl::is_allocated() const
{
    return (m_bank_index != INVALID_INDEX && m_set_base_index != INVALID_INDEX);
}

la_status
la_meter_set_statistical_impl::wait_until_meter_is_full()
{
    const lld_memory_scptr& meters_table = (*m_device->m_pacific_tree->rx_meter->top->meters_table)[m_bank_index];
    rx_meter_meters_table_memory entry;
    la_status status;
    int usecs = 0;

    status = m_device->get_int_property(la_device_property_e::METER_BUCKET_REFILL_POLLING_DELAY, usecs);
    return_on_error(status);

    for (size_t meter_index = 0; meter_index < m_set_size; ++meter_index) {
        la_uint64_t cbs = 0;
        la_uint64_t ebs = 0;
        la_rate_t old_cir = 0;
        la_rate_t old_eir = 0;
        la_uint64_t last_cbs_read = 0;
        la_uint64_t last_ebs_read = 0;
        size_t line_index = (m_set_base_index + meter_index) / NUM_METERS_PER_LINE_IN_METERS_TABLE;

        // First, fetch the CBS / EBS.
        status = m_meters_properties[meter_index].meter_profile->get_cbs(cbs);
        return_on_error(status);

        status = m_meters_properties[meter_index].meter_profile->get_ebs_or_pbs(ebs);
        return_on_error(status);

        // Store old CIR to restore it after filling up
        old_cir = m_meters_properties[meter_index].user_cir[SINGLE_ALLOCATION_IFG];
        old_eir = m_meters_properties[meter_index].user_eir[SINGLE_ALLOCATION_IFG];

        // Set high data rate so that meters fill up sooner
        status = set_cir(meter_index, 1000000000 /*cir*/);
        return_on_error(status);

        status = set_eir(meter_index, 1000000000 /*eir*/);
        return_on_error(status);

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
        status = set_cir(meter_index, old_cir);
        return_on_error(status);

        status = set_eir(meter_index, old_eir);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
