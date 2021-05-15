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

#include "la_voq_set_impl.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "npu/la_counter_set_impl.h"
#include "system/la_device_impl.h"
#include "voq_counter_set.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/stopwatch.h"
#include "common/transaction.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "nplapi/npl_constants.h"

#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/slice_id_manager_base.h"

#include <sstream>

namespace silicon_one
{

static_assert(
    (size_t)ics_slice_last_dequeue_qsize_bytes_memory::SIZE_IN_BITS
        == (size_t)ics_slice_last_enqueue_qsize_bytes_memory::SIZE_IN_BITS,
    "ics_slice_last_dequeue_qsize_bytes_memory and ics_slice_last_enqueue_qsize_bytes_memory SIZE_IN_BITS does not match");

enum {
    NUM_CONTEXT_IN_GROUP = 64,
    HBM_CMD_FIFO_SIZE = 8,
    INVALID_VOQ_CONTEXT = -1,
};

static inline bit_vector
populate_vsc_voq_mapping_value(la_vsc_gid_t vsc, la_slice_id_t dest_slice, la_ifg_id_t dest_ifg)
{
    bit_vector voq_bv(0);

    voq_bv.set_bits(10, 0, vsc >> 4);
    voq_bv.set_bits(11, 11, dest_ifg);
    voq_bv.set_bits(14, 12, dest_slice);

    return voq_bv;
}

la_voq_set_impl::la_voq_set_impl(const la_device_impl_wptr& device)
    : la_voq_set_base(device),
      m_base_vsc_vec(ASIC_MAX_SLICES_PER_DEVICE_NUM, LA_VSC_GID_INVALID),
      m_voq_state(state_e::ACTIVE),
      m_force_local_voq(false),
      m_counter(nullptr),
      m_is_during_flush_process(false)
{
}

la_voq_set_impl::~la_voq_set_impl()
{
}

std::string
la_voq_set_impl::vsc_vec_to_string()
{
    std::stringstream log_message;
    log_message << "vsc-vector=";
    bool is_first = true;

    for (auto vsc : m_base_vsc_vec) {
        if (is_first) {
            is_first = false;
        } else {
            log_message << ",";
        }

        log_message << vsc;
    }

    return log_message.str();
}

la_status
la_voq_set_impl::map_voq_to_vsc()
{
    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice : nw_slices) {
        lld_memory_scptr voq_mem = nullptr;
        lld_memory_scptr dev_mem = nullptr;
        size_t line = 0;

        get_voq_map_info(m_base_voq, slice, voq_mem, line);

        bit_vector voq_bv = populate_vsc_voq_mapping_value(m_base_vsc_vec[slice], m_dest_slice, m_dest_ifg);

        la_status ret = m_device->m_ll_device->write_memory(*voq_mem, line, voq_bv);
        return_on_error(ret);

        get_dev_dest_map_info(m_base_voq, slice, dev_mem, line);

        if (dev_mem != nullptr) {
            if ((slice > la_device_impl::CSMS_ALL_DEV_SUPPORT_LAST_SLICE)
                && (m_dest_device > la_device_impl::CSMS_LAST_SUPPORTED_SUBSET_DEVICE)) {
                log_err(HLD, "Ingress slice %u cannot reach egress device %u", slice, m_dest_device);
                return LA_STATUS_EINVAL;
            }

            bit_vector dev_bv(m_dest_device);
            log_debug(HLD,
                      "%s: base_voq=%d dest_device=%d line=%zd dev_bv=%s",
                      __func__,
                      m_base_voq,
                      m_dest_device,
                      line,
                      dev_bv.to_string().c_str());
            ret = m_device->m_ll_device->write_memory(*dev_mem, line, dev_bv);
            return_on_error(ret);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::initialize(la_object_id_t oid,
                            la_voq_gid_t base_voq_id,
                            size_t set_size,
                            la_vsc_gid_vec_t base_vsc_vec,
                            la_device_id_t dest_device,
                            la_slice_id_t dest_slice,
                            la_ifg_id_t dest_ifg)
{
    m_oid = oid;
    m_base_voq = base_voq_id;
    m_set_size = set_size;
    m_base_vsc_vec = base_vsc_vec;
    m_dest_device = dest_device;
    m_dest_slice = dest_slice;
    m_dest_ifg = dest_ifg;

    m_cgm_profiles.resize(set_size, nullptr);
    if (m_device->m_device_mode == device_mode_e::LINECARD) {
        m_is_fabric_high_priority.resize(set_size, false /* low priority */);
    }

    m_voq_redirected.resize(set_size, false);
    m_per_voq_index_state.resize(set_size, state_e::ACTIVE);
    m_indx_is_during_flush_process.resize(set_size, false);
    m_flush_counters.resize(set_size + 1, std::make_pair(0, 0));

    la_status status = map_voq_to_vsc();
    return_on_error(status);

    // Initialize registers used for accounting flushed packets
    status = initialize_flush_counters();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    // VOQ must be in dropping state and empty before destruction. Otherwise, packets will can remain stuck in the destroyed VOQ.
    if (m_voq_state == state_e::ACTIVE) {
        return LA_STATUS_EINVAL;
    }

    bool is_voq_empty;
    la_status status = is_empty(is_voq_empty);
    return_on_error(status);

    if (!is_voq_empty) {
        return LA_STATUS_EAGAIN;
    }

    if (m_counter != nullptr) {
        m_device->remove_object_dependency(m_counter, this);
        m_counter = nullptr;
        m_device->destroy_voq_counter_set(m_base_voq, m_set_size);
    }

    for (size_t voq_index = 0; voq_index < m_set_size; voq_index++) {
        // Check and release auto credit machine if needed
        status = release_auto_credit_fsm(voq_index);
        return_on_error(status);

        if (m_cgm_profiles[voq_index] != nullptr) {
            m_device->remove_object_dependency(m_cgm_profiles[voq_index], this);
            la_status status = erase_voq_properties_table(voq_index);
            return_on_error(status);

            status = m_cgm_profiles[voq_index]->detach_voq();
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::acquire_auto_credit_fsm(size_t drain_rate_gbps, size_t start, size_t end)
{
    la_slice_id_t rep_sid = m_device->first_active_slice_id();
    gibraltar::ics_slice_auto_credit_fsm_register auto_credit_fsm_reg;
    la_status status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[rep_sid]->ics->auto_credit_fsm, auto_credit_fsm_reg);
    return_on_error(status);

    if (auto_credit_fsm_reg.fields.auto_credit_en) {
        if (auto_credit_fsm_reg.fields.start_voq == m_base_voq) {
            return LA_STATUS_SUCCESS;
        }

        const auto& auto_credit_user = m_device->m_voq_sets[auto_credit_fsm_reg.fields.start_voq];
        if (auto_credit_user != nullptr) {
            bool auto_credit_available;
            status = auto_credit_user->is_empty(auto_credit_available);
            return_on_error(status);

            if (!auto_credit_available) {
                return LA_STATUS_EAGAIN;
            }
        }
    }

    auto_credit_fsm_reg.fields.auto_credit_en = true;
    constexpr size_t CREDIT_SIZE_IN_BITS = 1024 * 8;
    size_t credit_period = m_device->m_device_frequency_float_ghz * CREDIT_SIZE_IN_BITS / drain_rate_gbps;
    auto_credit_fsm_reg.fields.credit_period = credit_period;
    auto_credit_fsm_reg.fields.start_voq = m_base_voq + start;
    auto_credit_fsm_reg.fields.end_voq = m_base_voq + end - 1;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        la_status status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[slice_id]->ics->auto_credit_fsm,
                                                                 auto_credit_fsm_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::release_auto_credit_fsm(size_t offset)
{
    la_slice_id_t rep_sid = m_device->first_active_slice_id();
    gibraltar::ics_slice_auto_credit_fsm_register auto_credit_fsm_reg;
    la_status status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[rep_sid]->ics->auto_credit_fsm, auto_credit_fsm_reg);
    return_on_error(status);

    if (auto_credit_fsm_reg.fields.auto_credit_en && auto_credit_fsm_reg.fields.start_voq == (m_base_voq + offset)) {
        auto_credit_fsm_reg.fields.auto_credit_en = false;
        la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
        for (auto slice_id : nw_slices) {
            la_status status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[slice_id]->ics->auto_credit_fsm,
                                                                     auto_credit_fsm_reg);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_voq_set_impl::type() const
{
    return object_type_e::VOQ_SET;
}

std::string
la_voq_set_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_voq_set_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_vsc_gid_vec_t
la_voq_set_impl::get_base_vsc_vec() const
{
    return m_base_vsc_vec;
}

la_status
la_voq_set_impl::get_base_vsc(la_slice_id_t slice, la_vsc_gid_t& out_base_vsc) const
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_valid(slice);
    return_on_error(stat);

    out_base_vsc = m_base_vsc_vec[slice];

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::set_cgm_profile(size_t voq_index, la_voq_cgm_profile* cgm_profile)
{
    start_api_call("voq_index=", voq_index, "cgm_profile=", cgm_profile);
    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (cgm_profile != nullptr && (!of_same_device(cgm_profile, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto voq_cgm_profile_impl = m_device->get_sptr<la_voq_cgm_profile_impl>(cgm_profile);
    if (m_cgm_profiles[voq_index] == voq_cgm_profile_impl) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    if (voq_cgm_profile_impl != nullptr) {
        bool is_mc = m_device->is_mc_voq_set(m_device->get_sptr(this));

        status = voq_cgm_profile_impl->attach_voq(is_mc);
        return_on_error(status);

        m_device->add_object_dependency(voq_cgm_profile_impl, this);
    }

    if (m_cgm_profiles[voq_index] != nullptr) {
        status = m_cgm_profiles[voq_index]->detach_voq();
        return_on_error(status);

        m_device->remove_object_dependency(m_cgm_profiles[voq_index], this);
    }

    m_cgm_profiles[voq_index] = voq_cgm_profile_impl;

    status = configure_voq_properties_table(voq_index);
    return_on_error(status);

    uint64_t id
        = (voq_cgm_profile_impl == nullptr) ? (uint64_t)la_device_impl::VOQ_CGM_DROP_PROFILE : voq_cgm_profile_impl->get_id();
    status = set_dynamic_cgm_profile(voq_index, id);
    return_on_error_log(status, HLD, NOTICE, "Could not update dynamic cgm profile");
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_cgm_profile(size_t voq_index, la_voq_cgm_profile*& out_cgm_profile) const
{
    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_cgm_profiles[voq_index] == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    out_cgm_profile = m_cgm_profiles[voq_index].get();

    return LA_STATUS_SUCCESS;
}

bool
la_voq_set_impl::all_cgm_profiles_assigned() const
{
    for (uint32_t voq = 0; voq < m_set_size; voq++) {
        if (m_cgm_profiles[voq] == nullptr) {
            return false;
        }
    }

    return true;
}

bool
la_voq_set_impl::is_during_flush() const
{
    // Check if any of the individual voq are flushing.
    if (std::any_of(m_indx_is_during_flush_process.cbegin(), m_indx_is_during_flush_process.cend(), [](bool i) { return i; })) {
        return true;
    }
    return m_is_during_flush_process;
}

la_status
la_voq_set_impl::redirect_voq_to_disabled_dest(size_t start, size_t end)
{
    transaction txn;
    txn.on_fail([=]() { m_voq_flush_orig_mappings.clear(); });

    // Only OQs that belong to system-port's base PIF are enabled, but PIF 1 is not expected to act as a base.
    // All OQs are disabled by default (see configuration of oq_drop_bitmap in init.cpp).
    // Following code makes sure it's indeed not used.
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        auto& oq_drop_bitmap_mem = (m_device->m_gb_tree->slice[m_dest_slice]->tx->cgm->oq_drop_bitmap);
        txcgm_oq_drop_bitmap_memory drop_bitmap{{0}};
        la_status status = m_device->m_ll_device->read_memory(oq_drop_bitmap_mem, DISABLED_PIF, drop_bitmap);
        return_on_error(status);
        if (drop_bitmap.fields.oq_drop_bitmap_data != 0xff) {
            // DISABLED PIF is not really disabled
            log_err(HLD, "DISABLED_PIF(%d) is active", DISABLED_PIF);
            return LA_STATUS_EBUSY;
        }
    }

    for (la_slice_id_t slice : get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC})) {
        const auto& table(m_device->m_tables.filb_voq_mapping[slice]);
        for (size_t voq_offset = start; voq_offset < end; voq_offset++) {
            npl_filb_voq_mapping_t::key_type k;
            npl_filb_voq_mapping_t::entry_pointer_type e = nullptr;
            k.rxpdr_output_voq_nr = m_base_voq + voq_offset;
            la_status status = table->lookup(k, e);
            return_on_error(status);
            auto v = e->value();
            auto orig_v = v;
            if (m_device->m_device_mode == device_mode_e::STANDALONE || !is_send_to_fabric()) {
                v.payloads.filb_voq_mapping_result.dest_oq = DISABLED_PIF * NUM_OQ_PER_PIF;
            } else if (m_device->m_device_mode == device_mode_e::LINECARD) {
                v.payloads.filb_voq_mapping_result.dest_dev = INVALID_DEST_DEV; // Invalid device
            }
            txn.status = e->update(v);
            return_on_error(txn.status);
            m_voq_flush_orig_mappings.push_back(orig_v);
            txn.on_fail([=]() { e->update(orig_v); });
            m_voq_redirected[voq_offset] = true;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::do_flush(size_t voq_index)
{
    if (m_per_voq_index_state.capacity() == 0) {
        log_err(HLD, "VOQ: state not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    // This function assumes that no ingress data enters the VOQs
    if (m_per_voq_index_state[voq_index] == state_e::ACTIVE) {
        log_err(HLD, "Cannot flush an active VOQ");
        return LA_STATUS_EINVAL;
    }

    // Map the VOQ to an inactive OQ
    la_status status = redirect_voq_to_disabled_dest(voq_index, voq_index + 1);
    if (status != LA_STATUS_SUCCESS) {
        log_warning(HLD, "VOQ redirection failed. Fallback to slow path");
    }

    // Redirecting the VOQ to a disabled destination allows higher drain rate.
    size_t drain_rate_gbps = m_voq_redirected[voq_index] ? 100 : 1;
    // Acquire the auto-credit generator
    status = acquire_auto_credit_fsm(drain_rate_gbps, voq_index, voq_index + 1);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::do_flush()
{
    // TODO-GB - VOQ flushing in GB should be implemented not using auto-credit mechanism.
    // For now it works, but ASIC team requested to rewrite.

    // This function assumes that no ingress data enters the VOQs
    if (m_voq_state == state_e::ACTIVE) {
        log_err(HLD, "Cannot flush an active VOQ");
        return LA_STATUS_EINVAL;
    }

    // Map the VOQ to an inactive OQ
    la_status status = redirect_voq_to_disabled_dest(0, m_set_size);
    if (status != LA_STATUS_SUCCESS) {
        log_warning(HLD, "VOQ redirection failed. Fallback to slow path");
    }

    // Redirecting the VOQ to a disabled destination allows higher drain rate.
    size_t drain_rate_gbps = m_voq_redirected[0] ? 100 : 1;
    // Acquire the auto-credit generator
    status = acquire_auto_credit_fsm(drain_rate_gbps, 0, m_set_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::return_from_flush(size_t start, size_t end)
{
    // Restore the VOQ->OQ mapping
    for (size_t voq_offset = start, mapping_index = 0; voq_offset < end; voq_offset++, mapping_index++) {
        if (m_voq_redirected[voq_offset]) {
            for (la_slice_id_t slice : get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC})) {
                const auto& table(m_device->m_tables.filb_voq_mapping[slice]);
                npl_filb_voq_mapping_t::key_type k;
                npl_filb_voq_mapping_t::entry_pointer_type e = nullptr;
                k.rxpdr_output_voq_nr = m_base_voq + voq_offset;
                la_status status = table->set(k, m_voq_flush_orig_mappings[mapping_index], e);
                return_on_error(status);
            }
        }

        m_voq_redirected[voq_offset] = false;
    }

    m_voq_flush_orig_mappings.clear();

    // Release the auto-credit generator
    return release_auto_credit_fsm(start);
}

// Block for a maximum of 200ms. Based on a maximum queue of 390MB drained at 100Gbps
// over 6 slices.
constexpr uint64_t MAX_FLUSH_TIME_MS = 200; // Block for a maximum of 200ms.

la_status
la_voq_set_impl::flush(bool block)
{
    start_api_call("block=", block);

    // Prevent a flush if there is a pending flush on another VOQ index.
    bool is_flush = is_during_flush();
    if (is_flush && !m_is_during_flush_process) {
        return LA_STATUS_EINVAL;
    }

    // Store byte count to be used for counting
    la_uint64_t pre_flush_byte_count = 0;
    voq_size tmp_size;
    auto nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (la_slice_id_t slice : nw_slices) {
        for (size_t voq_index = 0; voq_index < m_set_size; voq_index++) {
            la_status status = get_voq_size(voq_index, slice, tmp_size);
            return_on_error(status);

            pre_flush_byte_count += (tmp_size.sms_bytes + tmp_size.hbm_bytes);
        }
    }

    // Clear flush packet counters by reading
    size_t dummy;
    la_status status = get_flushed_packet_count(dummy);
    return_on_error(status);

    status = do_flush(block);
    return_on_error(status);

    size_t flushed_packets;
    status = get_flushed_packet_count(flushed_packets);
    return_on_error(status);

    auto entry = m_flush_counters[m_set_size];
    m_flush_counters[m_set_size] = std::make_pair(entry.first + flushed_packets, entry.second + pre_flush_byte_count);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::do_flush(bool block)
{
    la_status status;
    if (!is_during_flush()) {
        status = do_flush();
        return_on_error(status);

        m_is_during_flush_process = true;
    }

    // Check if VOQ is empty
    bool is_voq_empty;
    status = is_empty(is_voq_empty);
    return_on_error(status);
    if (!block && !is_voq_empty) {
        return LA_STATUS_EAGAIN;
    }

    stopwatch flush_check;
    uint64_t elapsed = 0;

    // Wait till the VOQ is drained
    while (!is_voq_empty && (elapsed < MAX_FLUSH_TIME_MS)) {
        flush_check.start();
        status = is_empty(is_voq_empty);
        return_on_error(status);
        flush_check.stop();
        elapsed = flush_check.get_total_elapsed_time(stopwatch::time_unit_e::MS);
    }

    // Restore state
    status = return_from_flush(0, m_set_size);
    return_on_error(status);

    m_is_during_flush_process = false;

    // If the flush was not successful, return error after we cleaned up the state.
    if (!is_voq_empty) {
        return LA_STATUS_EAGAIN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::flush(size_t voq_index, bool block)
{
    start_api_call("voq_index=", voq_index, "block=", block);

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Do not allow per voq index flushing if the voq_set is not active.
    if (m_voq_state != state_e::ACTIVE) {
        return LA_STATUS_EINVAL;
    }

    // Prevent a flush if there is a pending flush on another VOQ
    // or all VOQ from this set.
    bool is_flush = is_during_flush();
    if (is_flush && !m_indx_is_during_flush_process[voq_index]) {
        return LA_STATUS_EINVAL;
    }

    // Store byte count to be used for flush accounting
    la_uint64_t pre_flush_byte_count = 0;
    voq_size tmp_size;
    auto nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (la_slice_id_t slice : nw_slices) {
        la_status status = get_voq_size(voq_index, slice, tmp_size);
        return_on_error(status);

        pre_flush_byte_count += (tmp_size.sms_bytes + tmp_size.hbm_bytes);
    }

    // Clear flush packet counters by reading
    size_t dummy;
    la_status status = get_flushed_packet_count(dummy);
    return_on_error(status);

    if (!is_flush) {
        status = do_flush(voq_index);
        return_on_error(status);

        m_indx_is_during_flush_process[voq_index] = true;
    }

    // Check if VOQ is empty
    bool is_voq_empty;
    status = is_empty(voq_index, is_voq_empty);
    return_on_error(status);
    if (!block && !is_voq_empty) {
        return LA_STATUS_EAGAIN;
    }

    stopwatch flush_check;
    uint64_t elapsed = 0;

    // Wait till the VOQ is drained
    while (!is_voq_empty && (elapsed < MAX_FLUSH_TIME_MS)) {
        flush_check.start();
        status = is_empty(voq_index, is_voq_empty);
        return_on_error(status);
        flush_check.stop();
        elapsed = flush_check.get_total_elapsed_time(stopwatch::time_unit_e::MS);
    }

    // Restore state
    status = return_from_flush(voq_index, voq_index + 1);
    return_on_error(status);

    m_indx_is_during_flush_process[voq_index] = false;

    size_t flushed_packets;
    status = get_flushed_packet_count(flushed_packets);
    return_on_error(status);

    auto entry = m_flush_counters[voq_index];
    m_flush_counters[voq_index] = std::make_pair(entry.first + flushed_packets, entry.second + pre_flush_byte_count);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::read_disabled_oq_drop_counter(size_t& out_packets)
{
    // Unicast packet counter
    const auto& counter_set_reg_pd = (*m_device->m_gb_tree->slice[m_dest_slice]->tx->cgm->uc_pd_counter_set)[FLUSH_OQ_CTR_INDEX];
    gibraltar::txcgm_uc_pd_counter_set_register counter_pd;

    // Clear on read
    la_status status = m_device->m_ll_device->read_register(counter_set_reg_pd, counter_pd);
    return_on_error(status);

    out_packets = counter_pd.fields.uc_pd_counter_set_drop_cnt;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::initialize_flush_counters()
{
    // Initialize TXPDR debug counter, for use with non-SA systems
    if (m_device->m_device_mode != device_mode_e::STANDALONE && is_send_to_fabric()) {
        auto fabric_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::CARRIER_FABRIC});
        for (la_slice_id_t slice : fabric_slices) {
            // TXPDR debug pd counter configuration
            const auto& tx_pdr_debug_pd_field_value_cfg = *m_device->m_gb_tree->slice[slice]->tx->pdr->debug_pd_field_value_cfg;
            const auto& tx_pdr_debug_pd_field_mask_cfg = *m_device->m_gb_tree->slice[slice]->tx->pdr->debug_pd_field_mask_cfg;

            // Count packets destined to invalid device ID
            // On GB, device ID match field is at bit 108.
            bit_vector value_bv = bit_vector(0, gibraltar::txpdr_debug_pd_field_value_cfg_register::SIZE_IN_BITS);
            bit_vector mask_bv = bit_vector(0, gibraltar::txpdr_debug_pd_field_mask_cfg_register::SIZE_IN_BITS);
            value_bv.set_bits(117, 108, INVALID_DEST_DEV);
            mask_bv.set_bits(117, 108, 0x1FF);

            la_status status = m_device->m_ll_device->write_register(tx_pdr_debug_pd_field_value_cfg, value_bv);
            return_on_error(status);

            status = m_device->m_ll_device->write_register(tx_pdr_debug_pd_field_mask_cfg, mask_bv);
            return_on_error(status);
        }
    } else {
        // Initialize OQ drop counters for flush OQ
        for (size_t queue_num = 0; queue_num < NUM_OQ_PER_PIF; queue_num++) {
            // OQ counter 1 is reserved for flush accounting
            la_status status;
            const lld_memory& counter_set_map(*m_device->m_gb_tree->slice[m_dest_slice]->tx->cgm->counter_set_map);
            gibraltar::txcgm_counter_set_map_memory val;
            la_uint_t queue = (DISABLED_PIF * NUM_OQ_PER_PIF) + queue_num;

            val.fields.counter_set_map_data = FLUSH_OQ_CTR_INDEX;

            status = m_device->m_ll_device->write_memory(counter_set_map, queue, val);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::read_txpdr_debug_pd_counter(size_t& out_packets)
{
    size_t flushed_packets = 0;
    auto fabric_slices = get_slices(m_device, la_slice_mode_e::CARRIER_FABRIC);
    for (la_slice_id_t slice : fabric_slices) {
        // TXPDR debug pd counter
        const auto& tx_pdr_debug_pd_field_status = *m_device->m_gb_tree->slice[slice]->tx->pdr->debug_pd_field_status;
        gibraltar::txpdr_debug_pd_field_status_register field_status;

        // Will clear on read
        la_status status = m_device->m_ll_device->read_register(tx_pdr_debug_pd_field_status, field_status);
        return_on_error(status);

        flushed_packets += field_status.fields.debug_pd_field_cnt;
    }

    out_packets = flushed_packets;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_flushed_packet_count(size_t& out_packets)
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE || !is_send_to_fabric()) {
        // If we don't go to fabric, flushed packets are sent to disabled OQ - read those OQ drop counter
        la_status status = read_disabled_oq_drop_counter(out_packets);
        return_on_error(status);
    } else {
        // In LC mode, flushed packets are sent to unknown device. Use TXPDR debug counter to get packet count
        la_status status = read_txpdr_debug_pd_counter(out_packets);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::read_flush_counter(bool clear_on_read, la_uint64_t& out_packets, la_uint64_t& out_bytes)
{
    start_api_getter_call("clear_on_read=", clear_on_read);

    auto pair = m_flush_counters[m_set_size];

    out_packets = pair.first;
    out_bytes = pair.second;

    if (clear_on_read) {
        m_flush_counters[m_set_size] = std::make_pair(0, 0);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::read_flush_counter(size_t voq_index, bool clear_on_read, la_uint64_t& out_packets, la_uint64_t& out_bytes)
{
    start_api_getter_call("voq_index=", voq_index, "clear_on_read=", clear_on_read);

    if (voq_index >= m_set_size) {
        return LA_STATUS_EINVAL;
    }

    auto pair = m_flush_counters[voq_index];

    out_packets = pair.first;
    out_bytes = pair.second;

    if (clear_on_read) {
        m_flush_counters[voq_index] = std::make_pair(0, 0);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::restore(size_t voq_index)
{
    start_api_call("voq_index=", voq_index);

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // If we are not flushing, nothing to do.
    if (!m_indx_is_during_flush_process[voq_index]) {
        return LA_STATUS_SUCCESS;
    }

    // Do not allow to restore the queue if the voq_set is not active.
    if (m_voq_state != state_e::ACTIVE) {
        return LA_STATUS_EINVAL;
    }

    // Restore state
    la_status status = return_from_flush(voq_index, voq_index + 1);
    return_on_error(status);

    m_indx_is_during_flush_process[voq_index] = false;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::is_empty(bool& out_empty) const
{
    for (size_t voq_index = 0; voq_index < m_set_size; voq_index++) {
        la_status status = is_empty(voq_index, out_empty);
        return_on_error(status);
        if (!out_empty) {
            return LA_STATUS_SUCCESS;
        }
    }

    out_empty = true;
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::is_empty(size_t voq_index, bool& out_empty) const
{
    // Currently pending NPSUITE support.
    // Should run when NSIM supports reading knows to deal with TM.
    if (m_device->is_simulated_device()) {
        // Not real device - no diagnostics should be executed.
        out_empty = true;
        return LA_STATUS_SUCCESS;
    }

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        voq_size single_voq_size;
        bool is_in_hbm;
        la_status status = do_get_voq_size(voq_index, slice_id, is_in_hbm, single_voq_size);
        return_on_error(status);

        if ((single_voq_size.sms_bytes != 0) || is_in_hbm) {
            out_empty = false;
            return LA_STATUS_SUCCESS;
        }
    }

    out_empty = true;
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_candidate_context_id(size_t voq_num, la_slice_id_t slice, context_hw_id& out_context_id) const
{
    // Get the allocated context.
    gibraltar::pdvoq_slice_voq2context_memory voq2context;
    la_status status
        = m_device->m_ll_device->read_memory(m_device->m_gb_tree->slice[slice]->pdvoq->voq2context, voq_num, voq2context);
    return_on_error(status);

    out_context_id.id = voq2context.fields.voq2context_data;
    out_context_id.line = out_context_id.id / NUM_CONTEXT_IN_GROUP;
    out_context_id.bit = out_context_id.id % NUM_CONTEXT_IN_GROUP;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_voq_size(size_t voq_index, la_slice_id_t slice, voq_size& out_size) const
{
    start_api_getter_call();

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status stat = m_device->get_slice_id_manager()->is_slice_valid(slice);
    return_on_error(stat);

    bool is_in_hbm;
    return do_get_voq_size(voq_index, slice, is_in_hbm, out_size);
}

la_status
la_voq_set_impl::do_get_voq_size(size_t voq_index, la_slice_id_t slice, bool& out_is_in_hbm, voq_size& out_size) const
{
    size_t voq_num = m_base_voq + voq_index;

    context_hw_id context;
    la_status status = get_candidate_context_id(voq_num, slice, context);
    return_on_error(status);

    status = get_context_size_in_sms(context, slice, out_size.sms_bytes);
    return_on_error(status);

    status = is_smscontext_in_hbm(context, slice, out_is_in_hbm);
    return_on_error(status);

    if (out_is_in_hbm) {
        log_debug(HLD, "Context is in the HBM");
        status = get_context_size_in_hbm(context, slice, out_size.hbm_blocks, out_size.hbm_bytes);
        return_on_error(status);
    } else {
        out_size.hbm_blocks = 0;
        out_size.hbm_bytes = 0;
    }

    bool context_still_belongs_to_voq;
    status = verify_context_to_voq(context.id, voq_num, slice, context_still_belongs_to_voq);
    return_on_error(status);

    if (!context_still_belongs_to_voq) {
        log_debug(HLD, "Context has moved to another VOQ. VOQ is empty");
        out_size.sms_bytes = 0;
        out_size.hbm_blocks = 0;
        out_size.hbm_bytes = 0;
        out_is_in_hbm = false;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::verify_context_to_voq(size_t context, size_t voq_num, la_slice_id_t slice, bool& out_match) const
{
    gibraltar::pdvoq_slice_context2voq_memory context2voq;
    la_status status
        = m_device->m_ll_device->read_memory(m_device->m_gb_tree->slice[slice]->ics->context2voq, context, context2voq);
    return_on_error(status);

    if (context2voq.fields.context2voq_bits == voq_num) {
        out_match = true;
    } else {
        out_match = false;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_context_size_in_sms(const context_hw_id& context, la_slice_id_t slice, size_t& out_size) const
{
    // Check if we need to read last_enqueue_qsize_bytes or last_dequeue_qsize_bytes (XOR of last_queue_report_set and
    // last_queue_report_clr) and read it.
    // During traffic they will return almost same values. Otherwize, we will get correct result.
    gibraltar::ics_slice_last_queue_report_set_memory last_queue_report_set_res;
    la_status status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[slice]->ics->last_queue_report_set, context.line, last_queue_report_set_res);
    return_on_error(status);

    gibraltar::ics_slice_last_queue_report_clr_memory last_queue_report_clr_res;
    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[slice]->ics->last_queue_report_clr, context.line, last_queue_report_clr_res);
    return_on_error(status);

    uint64_t line_res
        = last_queue_report_set_res.fields.last_queue_report_bmp ^ last_queue_report_clr_res.fields.last_queue_report_clr_bmp;
    gibraltar::ics_slice_last_dequeue_qsize_bytes_memory size_in_bytes;
    if (bit_utils::get_bit(line_res, context.bit)) {
        status = m_device->m_ll_device->read_memory(
            m_device->m_gb_tree->slice[slice]->ics->last_enqueue_qsize_bytes, context.id, size_in_bytes);
    } else {
        status = m_device->m_ll_device->read_memory(
            m_device->m_gb_tree->slice[slice]->ics->last_dequeue_qsize_bytes, context.id, size_in_bytes);
    }

    return_on_error(status);

    out_size = size_in_bytes.fields.dequeue_qsize_bytes;
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::is_smscontext_in_hbm(const context_hw_id& context, la_slice_id_t slice, bool& out_is_in_hbm) const
{
    gibraltar::dics_context_msb_reg_register context_msb_reg;
    context_msb_reg.fields.context_msb = context.line;
    la_status status
        = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[slice]->ics->context_msb_reg, context_msb_reg);
    return_on_error(status);

    bit_vector queue_in_dram_bv;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[slice]->ics->queue_in_dram_reg, queue_in_dram_bv);
    return_on_error(status);

    out_is_in_hbm = queue_in_dram_bv.bit(context.bit);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_context_size_in_hbm(const context_hw_id& context,
                                         la_slice_id_t slice,
                                         size_t& out_size_blocks,
                                         size_t& out_size_bytes) const
{
    // Reading the context size from the DRAM
    gibraltar::ics_slice_queue2_dram_mem_memory ics_slice_queue2_dram_res;
    la_status status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[slice]->ics->queue2_dram_mem, context.id, ics_slice_queue2_dram_res);
    return_on_error(status);

    size_t dram_context = ics_slice_queue2_dram_res.fields.dram_queue_num;
    gibraltar::dvoq_qsm_memory dvoq_qsm_memory_res;
    status = m_device->m_ll_device->read_memory(m_device->m_gb_tree->dvoq->qsm, dram_context, dvoq_qsm_memory_res);
    return_on_error(status);

    gibraltar::dics_dramcontext2smscontext_memory dramcontext2smscontext;
    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->dics->dramcontext2smscontext, dram_context, dramcontext2smscontext);
    return_on_error(status);

    if ((dramcontext2smscontext.fields.smscontext == context.id) && (dramcontext2smscontext.fields.slicenum == slice)) {
        out_size_blocks = dvoq_qsm_memory_res.fields.dcm;
        out_size_bytes = dvoq_qsm_memory_res.fields.qsize_bytes;
    } else {
        log_debug(HLD, "HBM context is not mapped to the current SMS context");
        out_size_blocks = 0;
        out_size_bytes = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_voq_age(size_t voq_index, la_slice_id_t slice, size_t& out_age) const
{
    start_api_getter_call();

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = m_device->get_slice_id_manager()->is_slice_valid(slice);
    return_on_error(status);

    status = do_get_voq_age(voq_index, slice, out_age);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::do_get_voq_age(size_t voq_index, la_slice_id_t slice, size_t& out_age) const
{
    size_t voq_num = m_base_voq + voq_index;

    context_hw_id context;
    la_status status = get_candidate_context_id(voq_num, slice, context);
    return_on_error(status);

    bool is_in_hbm;
    status = is_smscontext_in_hbm(context, slice, is_in_hbm);
    return_on_error(status);

    if (is_in_hbm) {
        gibraltar::ics_slice_queue2_dram_mem_memory ics_slice_queue2_dram_res;
        la_status status = m_device->m_ll_device->read_memory(
            m_device->m_gb_tree->slice[slice]->ics->queue2_dram_mem, context.id, ics_slice_queue2_dram_res);
        return_on_error(status);

        size_t dram_context = ics_slice_queue2_dram_res.fields.dram_queue_num;
        gibraltar::dram_cgm_dram_context_age_memory dram_cgm_dram_context_age_mem;
        status = m_device->m_ll_device->read_memory(
            m_device->m_gb_tree->dram_cgm->dram_context_age, dram_context, dram_cgm_dram_context_age_mem);
        return_on_error(status);
        out_age = dram_cgm_dram_context_age_mem.fields.queue_age;
        return LA_STATUS_SUCCESS;
    }

    size_t sms_bytes;
    status = get_context_size_in_sms(context, slice, sms_bytes);
    return_on_error(status);

    if (sms_bytes == 0) {
        log_debug(HLD, "Empty VOQ context");
        out_age = 0;
        return LA_STATUS_SUCCESS;
    }

    gibraltar::pdvoq_slice_voq_tenq_head_rd_memory pdvoq_slice_voq_tenq_head_rd_mem;
    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[slice]->pdvoq->voq_tenq_head_rd, context.id, pdvoq_slice_voq_tenq_head_rd_mem);
    return_on_error(status);

    out_age = pdvoq_slice_voq_tenq_head_rd_mem.fields.t_enq;

    bool context_still_belongs_to_voq;
    status = verify_context_to_voq(context.id, voq_num, slice, context_still_belongs_to_voq);
    return_on_error(status);

    if (!context_still_belongs_to_voq) {
        log_debug(HLD, "Context has moved to another VOQ. VOQ is empty");
        out_age = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::set_fabric_priority(size_t voq_index, bool is_high_priority)
{
    // TODO - this function should be deprecated as API.

    start_api_call("voq_index=", voq_index, "is_high_priority=", is_high_priority);

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_fabric_priority(size_t voq_index, bool& out_is_high_priority) const
{
    // TODO - this function should be deprecated as API. For now still return a valid value.

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_is_high_priority = m_is_fabric_high_priority[voq_index];

    return LA_STATUS_SUCCESS;
}

void
la_voq_set_impl::get_voq_map_info(la_voq_gid_t voq, la_slice_id_t slice, lld_memory_scptr& out_voq_mem, size_t& out_line) const
{
    if (la_device_impl::is_multi_device_aware_slice(slice)) {
        out_voq_mem = (*m_device->m_gb_tree->csms->voq_vsc_dst_map_mem)[slice];
        uint32_t vsc_entries_num = out_voq_mem->get_desc()->entries / 2;
        out_line = (voq / NATIVE_VOQ_SET_SIZE) + vsc_entries_num;
    } else {
        out_voq_mem = (*m_device->m_gb_tree->csms->voq_dst_map_mem)[slice - la_device_impl::MAX_REMOTE_SLICE];
        out_line = voq / NATIVE_VOQ_SET_SIZE;
    }
}

void
la_voq_set_impl::get_dev_dest_map_info(la_voq_gid_t voq, la_slice_id_t slice, lld_memory_scptr& out_dev_mem, size_t& out_line) const
{
    if (slice > la_device_impl::CSMS_SUBSET_DEV_SUPPORT_SLICE) {
        out_dev_mem = nullptr;
        out_line = 0;

        return;
    }

    if (slice == la_device_impl::CSMS_SUBSET_DEV_SUPPORT_SLICE) {
        out_dev_mem = m_device->m_gb_tree->csms->dst_dev_map_mem_red;
    } else { // rest of slices
        out_dev_mem = (*m_device->m_gb_tree->csms->dst_dev_map_mem)[slice];
    }

    uint32_t vsc_entries_num
        = out_dev_mem->get_desc()->entries / 2; // Memory is split evenly between VSCs and VOQs. VSCs come first.
    out_line = voq / NATIVE_VOQ_SET_SIZE + vsc_entries_num;

    return;
}

la_status
la_voq_set_impl::set_dynamic_cgm_profile_per_slice(size_t voq_index,
                                                   uint64_t cgm_profile_id,
                                                   la_slice_id_t slice_id,
                                                   uint64_t& out_orig_pool_ret_th,
                                                   bool& out_orig_pool_ret_th_valid,
                                                   uint64_t& out_original_fullness,
                                                   bool& out_is_original_fullness_valid)
{
    out_is_original_fullness_valid = false;
    out_orig_pool_ret_th_valid = false;
    uint64_t voq_context = 0;
    bool is_voq_mapped = false;
    la_status status = establish_voq2context_mapping(
        voq_index, slice_id, is_voq_mapped, voq_context, out_orig_pool_ret_th, out_orig_pool_ret_th_valid);
    return_on_error_log(status,
                        HLD,
                        NOTICE,
                        "Could not establish voq2context mapping: %s, slice %u, voq_idx %lu",
                        status.message().c_str(),
                        slice_id,
                        voq_index);
    if (!is_voq_mapped) {
        log_debug(HLD, "(slice %u): The voq index %lu is not mapped", slice_id, voq_index);
        return LA_STATUS_SUCCESS;
    }
    status = update_ics_queue_profile(cgm_profile_id, slice_id, voq_context);
    return_on_error_log(status, HLD, NOTICE, "Could update ics queue profile: %s", status.message().c_str());
    status = update_pdvoq_voqcgm_profile(cgm_profile_id, slice_id, voq_context);
    return_on_error_log(status, HLD, NOTICE, "Could update voqcgm profile: %s", status.message().c_str());
    uint64_t dram_context = 0;
    bool dram_context_valid = false;
    status = establish_context2dram_context_mapping(
        slice_id, voq_context, out_original_fullness, out_is_original_fullness_valid, dram_context, dram_context_valid);
    return_on_error_log(status,
                        HLD,
                        NOTICE,
                        "Could establish context to dram mapping: %s, slice %u, voq_ctx %lu",
                        status.message().c_str(),
                        slice_id,
                        voq_context);
    if (dram_context_valid) {
        status = update_dram_contextinfo_table(dram_context, cgm_profile_id, voq_context);
        return_on_error_log(status,
                            HLD,
                            NOTICE,
                            "Could update dram_contextinfo table: %s, cgm_profile_id %lu, voq_ctx %lu",
                            status.message().c_str(),
                            cgm_profile_id,
                            voq_context);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::set_dynamic_cgm_profile(size_t voq_index, uint64_t cgm_profile_id)
{
    la_status status = LA_STATUS_SUCCESS;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        uint64_t orig_pool_ret_th = 0;
        bool orig_pool_ret_th_valid = false;
        bool is_original_fullness_valid = false;
        uint64_t original_fullness = 0;
        status = set_dynamic_cgm_profile_per_slice(voq_index,
                                                   cgm_profile_id,
                                                   slice_id,
                                                   orig_pool_ret_th,
                                                   orig_pool_ret_th_valid,
                                                   original_fullness,
                                                   is_original_fullness_valid);
        // We don't get out immediately in case of error, try to reset some registers first
        log_on_error(status,
                     HLD,
                     NOTICE,
                     "Could not set cgm profile for voq %lu, cgm profile id %lu, slice %u",
                     voq_index,
                     cgm_profile_id,
                     slice_id);
        if (is_original_fullness_valid) {
            uint64_t dummy_fullness = 0;
            // Best effort returning former fullness value. Even if this fails, we return original failure status
            la_status cleanup_status = update_pdvoq_slice_almost_full_conf_register(slice_id, original_fullness, dummy_fullness);
            log_on_error(cleanup_status,
                         HLD,
                         NOTICE,
                         "Slice %u: Cannot reset pdvoq_slice_almost_full_conf to %lu, status %s",
                         slice_id,
                         original_fullness,
                         cleanup_status.message().c_str());
            if (status == LA_STATUS_SUCCESS) {
                status = cleanup_status;
            }
        }
        if (orig_pool_ret_th_valid) {
            uint64_t dummy_old;
            bool dummy_old_valid;
            la_status cleanup_status = set_context_pool_ret_th(slice_id, orig_pool_ret_th, dummy_old, dummy_old_valid);
            if (status == LA_STATUS_SUCCESS) {
                status = cleanup_status;
            }
        }
    }
    return status;
}

la_status
la_voq_set_impl::set_context_pool_ret_th(la_slice_id_t slice, uint64_t new_val, uint64_t& out_old_val, bool& out_old_val_valid)
{
    la_status status;
    out_old_val_valid = false;

    gibraltar::pdvoq_slice_cmap_th_reg_register reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[slice]->pdvoq->cmap_th_reg, reg);
    return_on_error(status);

    out_old_val = reg.fields.context_pool_ret_th;
    out_old_val_valid = true;
    reg.fields.context_pool_ret_th = new_val;
    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[slice]->pdvoq->cmap_th_reg, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::establish_voq2context_mapping(size_t voq_index,
                                               la_slice_id_t slice,
                                               bool& out_is_voq_mapped,
                                               uint64_t& out_voq_context,
                                               uint64_t& orig_pool_ret_th,
                                               bool& orig_pool_ret_th_valid)
{
    // The pdvoq_slice_voq2context_memory mentions 1fff; however we don't read/write this value to ASIC.
    out_voq_context = INVALID_VOQ_CONTEXT;
    out_is_voq_mapped = false;
    size_t voq_num = m_base_voq + voq_index;

    lld_memory_scptr voq2context_mem = nullptr;
    lld_memory_scptr context_allocate_grant_set = nullptr;
    lld_memory_scptr context_allocate_grant_clr = nullptr;

    // Get the allocated context.
    voq2context_mem = m_device->m_gb_tree->slice[slice]->pdvoq->voq2context;
    context_allocate_grant_set = (m_device->m_gb_tree->slice[slice]->pdvoq->context_allocate_grant_set);
    context_allocate_grant_clr = (m_device->m_gb_tree->slice[slice]->pdvoq->context_allocate_grant_clr);

    la_status status;

    // Read modify write staticMapping at address == <CONTEXT[11:6]>.
    //  Set to 1 bit <CONTEXT[5:0]> and write back to memory.
    // This will lock all the context allocations.
    status = set_context_pool_ret_th(slice, 0 /*new_val*/, orig_pool_ret_th, orig_pool_ret_th_valid);
    return_on_error_log(status, HLD, NOTICE, "Could not set context pool ret th to 0");

    // Read context_allocate_grant_set and context_allocate_grant_clr at address
    // <VOQ_NUMBER[15:5]>, take bit <VOQ_NUMBER[4:0]> of both results and perform XOR between them.
    gibraltar::pdvoq_slice_context_allocate_grant_set_memory allocate_grant_set;
    gibraltar::pdvoq_slice_context_allocate_grant_clr_memory allocate_grant_clr;
    static_assert((uint64_t)gibraltar::pdvoq_slice_context_allocate_grant_set_memory::fields::BITMAP_E_WIDTH
                      == (uint64_t)gibraltar::pdvoq_slice_context_allocate_grant_clr_memory::fields::BITMAP_F_WIDTH,
                  "Mismatch of bitimap width in pdvoq_slice_context_allocate_grant set and clr memory.");

    status = m_device->m_ll_device->read_memory(
        *context_allocate_grant_set,
        voq_num / gibraltar::pdvoq_slice_context_allocate_grant_set_memory::fields::BITMAP_E_WIDTH,
        allocate_grant_set);
    return_on_error_log(status, HLD, NOTICE, "Could not read context_allocate_grant_set table %s", status.message().c_str());

    status = m_device->m_ll_device->read_memory(
        *context_allocate_grant_clr,
        voq_num / gibraltar::pdvoq_slice_context_allocate_grant_clr_memory::fields::BITMAP_F_WIDTH,
        allocate_grant_clr);
    return_on_error_log(status, HLD, NOTICE, "Could not read context_allocate_grant_clr table %s", status.message().c_str());

    bool set_clr_xor_bit
        = bit_utils::get_bit(allocate_grant_set.fields.bitmap_e ^ allocate_grant_clr.fields.bitmap_f,
                             voq_num % gibraltar::pdvoq_slice_context_allocate_grant_set_memory::fields::BITMAP_E_WIDTH);
    if (set_clr_xor_bit) {
        gibraltar::pdvoq_slice_voq2context_memory voq2context;
        status = m_device->m_ll_device->read_memory(*voq2context_mem, voq_num, voq2context);
        return_on_error_log(status, HLD, NOTICE, "Could not read voq2context table %s", status.message().c_str());
        out_voq_context = voq2context.fields.voq2context_data;
        out_is_voq_mapped = true;
    }

    return status;
}

la_status
la_voq_set_impl::update_ics_queue_profile(uint64_t cgm_profile_num, la_slice_id_t slice, uint64_t voq_context)
{
    lld_memory_value_list_t mem_val_list;

    gibraltar::ics_slice_queue_profile_memory ics_slice_queue_profile;
    ics_slice_queue_profile.fields.queue_profile_bits = cgm_profile_num;
    la_status status = m_device->m_ll_device->write_memory(
        m_device->m_gb_tree->slice[slice]->ics->queue_profile, voq_context, ics_slice_queue_profile);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::update_pdvoq_voqcgm_profile(uint64_t cgm_profile_num, la_slice_id_t slice, uint64_t voq_context)
{
    lld_memory_scptr voqcgm_profile_mem; ///< PDVOQ_SLICE: Dynamic CGM profile per context used by voq_cgm
    gibraltar::pdvoq_slice_voqcgm_profile_memory pdvoq_slice_voqcgm_profile;
    pdvoq_slice_voqcgm_profile.fields.cgm_profile = cgm_profile_num;
    voqcgm_profile_mem = m_device->m_gb_tree->slice[slice]->pdvoq->voqcgm_profile;
    la_status status = m_device->m_ll_device->write_memory(*voqcgm_profile_mem, voq_context, pdvoq_slice_voqcgm_profile);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::establish_context2dram_context_mapping(la_slice_id_t slice,
                                                        uint64_t voq_context,
                                                        uint64_t& out_original_fullness,
                                                        bool& out_original_fullness_valid,
                                                        uint64_t& out_dram_context,
                                                        bool& out_dram_context_valid)
{
    static constexpr size_t MAX_VOQ_UPDATE_RETRIES{10};

    out_dram_context_valid = false;
    out_original_fullness_valid = false;
    lld_register_scptr fifos_debug_reg = nullptr;

    fifos_debug_reg = m_device->m_gb_tree->slice[slice]->pdvoq->fifos_debug_reg;

    // Set PDVOQ_SLICE->AlmostFullConf.dram_release_alm_full_cfg == 32.
    // This prevents any VOQ from returning from DRAM.
    la_status status = update_pdvoq_slice_almost_full_conf_register(slice, 32 /*new_fullness*/, out_original_fullness);
    return_on_error(status);

    out_original_fullness_valid = true;
    size_t cnt = 0;
    gibraltar::pdvoq_slice_fifos_debug_reg_register fdr_reg;

    do { // Read PDVOQ_SLICE->FifosDebugReg.dram_release_fifo_stat and verify == 0.
         // TBD: Should be wait() function.
        if (++cnt >= MAX_VOQ_UPDATE_RETRIES) {
            log_err(HLD, "The value of dram_release_fifo_stat should have been 0");
            return LA_STATUS_EAGAIN;
        }
        status = m_device->m_ll_device->read_register(*fifos_debug_reg, fdr_reg);
        return_on_error(status);
    } while (fdr_reg.fields.dram_release_fifo_stat != 0);

    // Configure ICS_SLICE->ContextMsbReg.ContextMsb == <CONTEXT[11:6]>
    gibraltar::ics_slice_context_msb_reg_register cmsb_reg;
    cmsb_reg.fields.context_msb = bit_utils::get_bits(voq_context, 11, 6);
    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[slice]->ics->context_msb_reg, cmsb_reg);
    return_on_error(status);

    // Read ICS_SLICE->QueueInDramReg.QueueInDram and take bit at offset <CONTEXT[5:0]>.
    // If this bit is 0 the queue is not mapped to the DRAM, undo step 1. TBD ALOK SHOULD UNDO.
    // If this bit is 1 the queue is mapped to DRAM, continue to 5.
    gibraltar::ics_slice_queue_in_dram_reg_register qidr_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[slice]->ics->queue_in_dram_reg, qidr_reg);
    return_on_error(status);

    bool is_queue_mapped = bit_utils::get_bit(qidr_reg.fields.queue_in_dram, bit_utils::get_bits(voq_context, 5, 0));
    if (!is_queue_mapped) {
        // The queue is not mapped, should not set profile in dram->contextinfo.
        return LA_STATUS_SUCCESS;
    }

    // Read ICS_SLICE->Queue2DramMem at address == <CONTEXT>, the result is the DRAM CONTEXT.
    gibraltar::ics_slice_queue2_dram_mem_memory ics_slice_queue2_dram_mem_mem;
    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[slice]->ics->queue2_dram_mem, voq_context, ics_slice_queue2_dram_mem_mem);
    return_on_error(status);

    out_dram_context = ics_slice_queue2_dram_mem_mem.fields.dram_queue_num;
    out_dram_context_valid = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::update_pdvoq_slice_almost_full_conf_register(la_slice_id_t slice,
                                                              uint64_t new_fullness,
                                                              uint64_t& out_old_fullness)
{
    // PDVOQ_SLICE: almost full configurations.
    lld_register_scptr almost_full_conf = nullptr;
    almost_full_conf = m_device->m_gb_tree->slice[slice]->pdvoq->almost_full_conf;
    gibraltar::pdvoq_slice_almost_full_conf_register afc_reg;
    la_status status = m_device->m_ll_device->read_register(*almost_full_conf, afc_reg);
    return_on_error(status);

    out_old_fullness = afc_reg.fields.dram_release_alm_full_cfg;
    afc_reg.fields.dram_release_alm_full_cfg = new_fullness;
    status = m_device->m_ll_device->write_register(*almost_full_conf, afc_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::update_dram_contextinfo_table(uint64_t dram_context, uint64_t cgm_profile_num, uint64_t voq_context)
{
    gibraltar::dram_cgm_context_info_memory val;
    lld_memory_scptr dram_cgm_context_info = m_device->m_gb_tree->dram_cgm->context_info;
    la_status status = m_device->m_ll_device->read_memory(*dram_cgm_context_info, dram_context, val);
    return_on_error_log(status, HLD, ERROR, "Could not read dram_cgm.context_info");

    log_debug(HLD,
              "Current vals: prof_id %lu, voq_ctx %lx, new vals: prof_id %lu, voq_ctx %lx",
              val.fields.profile_num,
              val.fields.voq_context,
              cgm_profile_num,
              voq_context);

    val.fields.profile_num = cgm_profile_num;

    status = m_device->m_ll_device->write_memory(*dram_cgm_context_info, dram_context, val);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

uint64_t
la_voq_set_impl::get_voq_cgm_profile_id(size_t voq_index) const
{
    if (m_cgm_profiles[voq_index] == nullptr) {
        return la_device_impl::VOQ_CGM_DROP_PROFILE;
    }
    return m_cgm_profiles[voq_index]->get_id();
}

la_status
la_voq_set_impl::configure_voq_properties_table(size_t voq_index)
{
    if (m_per_voq_index_state.capacity() == 0) {
        log_err(HLD, "VOQ: state not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    // Choose table
    const auto& tables(m_device->m_tables.pdvoq_slice_voq_properties_table);

    // Prepare arguments
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::value_type v;

    uint64_t voq_scheduling_type;
    la_status status = get_pdvoq_voq_scheduling_type(voq_index, voq_scheduling_type);
    return_on_error(status);

    k.voq_num = m_base_voq + voq_index;
    if (m_voq_state == state_e::DROPPING || m_per_voq_index_state[voq_index] == state_e::DROPPING) {
        v.payloads.pdvoq_slice_voq_properties_result.profile.value = la_device_impl::VOQ_CGM_DROP_PROFILE;
    } else {
        v.payloads.pdvoq_slice_voq_properties_result.profile.value = get_voq_cgm_profile_id(voq_index);
    }

    v.payloads.pdvoq_slice_voq_properties_result.type = voq_scheduling_type;
    v.action = NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE;

    // Write
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_voq_set_impl::erase_voq_properties_table(size_t voq_index)
{
    // Choose table
    const auto& tables(m_device->m_tables.pdvoq_slice_voq_properties_table);

    // Prepare arguments
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::entry_pointer_type e;
    k.voq_num = m_base_voq + voq_index;

    // If an entry exists in one slice it should appear in all slices.

    size_t first_inst = m_device->first_active_slice_id();
    la_status status = tables[first_inst]->lookup(k, e);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    // Erase
    status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k);

    return status;
}

la_status
la_voq_set_impl::get_pdvoq_voq_scheduling_type(size_t voq_index, uint64_t& out_voq_scheduling_type)
{
    uint64_t local_traffic = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_LOCAL_L;
    // A standalone device VOQs are always local
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        out_voq_scheduling_type = local_traffic;

        return LA_STATUS_SUCCESS;
    }

    if (m_device->m_device_mode == device_mode_e::LINECARD) {
        // Linecard mode supports 2 sets of multicast VOQs, fabric and local
        if (is_lc_fabric_mc_voq_set(m_base_voq)) {
            out_voq_scheduling_type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_PLB_MC;
            return LA_STATUS_SUCCESS;
        }
        if (is_lc_network_mc_voq_set(m_base_voq)) {
            out_voq_scheduling_type = local_traffic;
            return LA_STATUS_SUCCESS;
        }
    }

    bool lc_force_forward_through_fabric_mode;
    la_status status = m_device->get_bool_property(la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE,
                                                   lc_force_forward_through_fabric_mode);
    return_on_error(status);

    bool send_to_fabric = ((m_dest_device != m_device->get_id()) || lc_force_forward_through_fabric_mode);
    if ((m_force_local_voq == true) || (send_to_fabric == false)) {
        out_voq_scheduling_type = local_traffic;

        return LA_STATUS_SUCCESS;
    }

    out_voq_scheduling_type
        = m_is_fabric_high_priority[voq_index] ? NPL_PDVOQ_VOQ_SCHEDULING_TYPE_PLB_UC_H : NPL_PDVOQ_VOQ_SCHEDULING_TYPE_PLB_UC_L;

    return LA_STATUS_SUCCESS;
}

bool
la_voq_set_impl::is_lc_fabric_mc_voq_set(size_t voq) const
{
    if ((voq >= la_device_impl::BASE_LC_FABRIC_MC_VOQ) && (voq < la_device_impl::LAST_LC_FABRIC_MC_VOQ)) {
        return true;
    }
    return false;
}

bool
la_voq_set_impl::is_lc_network_mc_voq_set(size_t voq) const
{
    // The below range check will need to be updated if not starting at 0
    static_assert(la_device_impl::BASE_LC_NETWORK_MC_VOQ == 0, "Range check needs to be updated");

    if (voq < la_device_impl::LAST_LC_NETWORK_MC_VOQ) {
        return true;
    }
    return false;
}

la_status
la_voq_set_impl::force_local_voq_enable(bool enable)
{
    if (m_force_local_voq == enable) {
        return LA_STATUS_SUCCESS;
    }

    m_force_local_voq = enable;

    for (size_t voq_index = 0; voq_index < m_set_size; voq_index++) {
        la_status status = configure_voq_properties_table(voq_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::set_state(state_e state)
{
    start_api_call("state=", state);

    if (m_voq_state == state) {
        return LA_STATUS_SUCCESS;
    }

    if ((m_voq_state == state_e::DROPPING) && is_during_flush()) {
        log_err(HLD, "Flush operation was not finished. Cannot activate the VOQ");
        return LA_STATUS_EBUSY;
    }

    m_voq_state = state;

    for (size_t voq_index = 0; voq_index < m_set_size; voq_index++) {
        la_status status = configure_voq_properties_table(voq_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::set_state(size_t voq_index, state_e state)
{
    start_api_call("voq_index=", voq_index, "state=", state);

    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_per_voq_index_state.capacity() == 0) {
        log_err(HLD, "VOQ: state not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    if (m_per_voq_index_state[voq_index] == state) {
        return LA_STATUS_SUCCESS;
    }

    if (m_voq_state == state_e::DROPPING) {
        log_err(HLD, "Only allow setting state of voq_index when the voq state is active");
        return LA_STATUS_EBUSY;
    }

    if ((m_per_voq_index_state[voq_index] == state_e::DROPPING) && is_during_flush()) {
        log_err(HLD, "Flush operation was not finished. Cannot activate the VOQ");
        return LA_STATUS_EBUSY;
    }

    m_per_voq_index_state[voq_index] = state;

    la_status status = configure_voq_properties_table(voq_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_state(state_e& out_state) const
{
    out_state = m_voq_state;
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::get_state(size_t voq_index, state_e& out_state) const
{
    if (voq_index >= m_set_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_state = m_per_voq_index_state[voq_index];
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_set_impl::set_counter(la_voq_set::voq_counter_type_e type, size_t group_size, la_counter_set* counter)
{
    start_api_call("type=", type, "group_size=", group_size, "counter=", counter);

    if (counter != nullptr) {
        if (m_counter != nullptr) {
            return LA_STATUS_EBUSY;
        }

        if (!of_same_device(counter, this)) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }

        la_status status = m_device->create_voq_counter_set(type, group_size, counter, m_base_voq, m_set_size);
        return_on_error(status);

        auto new_counter = m_device->get_sptr<la_counter_set_impl>(counter);

        new_counter->set_voq_base(m_base_voq);
        m_counter = new_counter;

        m_device->add_object_dependency(counter, this);

        return LA_STATUS_SUCCESS;
    } else {
        if (m_counter != nullptr) {
            m_device->remove_object_dependency(m_counter, this);
            m_counter = nullptr;

            return m_device->destroy_voq_counter_set(m_base_voq, m_set_size);
        }

        return LA_STATUS_EINVAL;
    }
}

la_status
la_voq_set_impl::get_counter(la_voq_set::voq_counter_type_e& out_voq_counter_type,
                             size_t& out_group_size,
                             la_counter_set*& out_counter) const
{
    start_api_call("");
    size_t voq_counter_set_id = m_base_voq / voq_counter_set::NUM_VOQS_IN_SET;

    voq_counter_set_sptr& vcs(m_device->m_voq_counter_sets[voq_counter_set_id]);
    if (!vcs) {
        return LA_STATUS_ENOTFOUND;
    }

    out_voq_counter_type = vcs->get_type();
    out_group_size = vcs->get_group_size();
    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

bool
la_voq_set_impl::is_send_to_fabric() const
{
    bool lc_force_forward_through_fabric_mode;
    la_status status = m_device->get_bool_property(la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE,
                                                   lc_force_forward_through_fabric_mode);
    if (status != LA_STATUS_SUCCESS) {
        // Should not occur
        return false;
    }

    bool send_to_fabric = ((m_dest_device != m_device->get_id()) || lc_force_forward_through_fabric_mode);

    return send_to_fabric;
}

} // namespace silicon_one
