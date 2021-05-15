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

#include "la_meter_profile_impl.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "la_strings.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_meter_profile_impl::la_meter_profile_impl(const la_device_impl_wptr& device,
                                             type_e meter_type,
                                             meter_measure_mode_e meter_measure_mode,
                                             meter_rate_mode_e meter_rate_mode,
                                             color_awareness_mode_e color_awareness_mode)
    : m_device(device),
      m_type(meter_type),
      m_measure_mode(meter_measure_mode),
      m_rate_mode(meter_rate_mode),
      m_color_awareness(color_awareness_mode),
      m_cascade_mode(cascade_mode_e::CASCADED)
{
}

la_meter_profile_impl::~la_meter_profile_impl()
{
}

la_status
la_meter_profile_impl::initialize(la_object_id_t oid)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    m_stat_bank_data.use_count = 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_meter_measure_mode(meter_measure_mode_e meter_measure_mode)
{
    start_api_call("meter_measure_mode=", meter_measure_mode);

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    for (const auto& data : m_ifg_data) {
        if ((data.cbs != 0) || (data.ebs_or_pbs != 0)) {
            // ebs/cbs precision depends on the measure mode
            log_err(HLD, "%s: cannot change measure mode when EBS or CBS are set", __func__);
            return LA_STATUS_EBUSY;
        }
    }

    m_measure_mode = meter_measure_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_meter_measure_mode(meter_measure_mode_e& out_meter_measure_mode) const
{
    start_api_getter_call();
    out_meter_measure_mode = m_measure_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_meter_rate_mode(meter_rate_mode_e meter_rate_mode)
{
    start_api_call("meter_rate_mode=", meter_rate_mode);

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    m_rate_mode = meter_rate_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_meter_rate_mode(meter_rate_mode_e& out_meter_rate_mode) const
{
    start_api_getter_call();
    out_meter_rate_mode = m_rate_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_color_awareness_mode(color_awareness_mode_e color_awareness_mode)
{
    start_api_call("color_awareness_mode=", color_awareness_mode);

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    m_color_awareness = color_awareness_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_color_awareness_mode(color_awareness_mode_e& out_color_awareness_mode) const
{
    start_api_getter_call();
    out_color_awareness_mode = m_color_awareness;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_cascade_mode(cascade_mode_e cascade_mode)
{
    start_api_call("cascade_mode=", cascade_mode);

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    m_cascade_mode = cascade_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_cascade_mode(cascade_mode_e& out_cascade_mode) const
{
    start_api_getter_call();
    out_cascade_mode = m_cascade_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_cbs(la_uint64_t cbs)
{
    start_api_call("cbs=", cbs);

    if (m_type == type_e::PER_IFG) {
        log_err(HLD, "Non per-ifg function is called for per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    la_uint64_t max_burst_size;
    m_device->get_limit(limit_type_e::METER_PROFILE__MAX_BURST_SIZE, max_burst_size);
    if (cbs > max_burst_size) {
        return LA_STATUS_EINVAL;
    }

    double burst_size_resolution;
    auto precision_type = (m_measure_mode == meter_measure_mode_e::BYTES)
                              ? la_precision_type_e::METER_PROFILE__CBS_RESOLUTION
                              : la_precision_type_e::METER_PROFILE__STATISTICAL_METER_CBS_RESOLUTION;
    la_status status = m_device->get_precision(precision_type, burst_size_resolution);
    return_on_error(status);
    if (cbs < burst_size_resolution) {
        log_err(HLD,
                "%s: CBS must be greater than burst size resolution. cbs=%llu burst_size_resolution=%llu.",
                __func__,
                cbs,
                (la_uint64_t)burst_size_resolution);
        return LA_STATUS_EINVAL;
    }

    for (size_t index = 0; index < NUM_IFGS_PER_DEVICE; ++index) {
        m_ifg_data[index].cbs = cbs;
    }

    m_stat_bank_data.cbs = cbs;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_cbs(la_uint64_t& out_cbs) const
{
    start_api_getter_call();

    if (m_type == type_e::PER_IFG) {
        log_err(HLD, "non per-ifg function is called for per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    out_cbs = m_ifg_data[0].cbs;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_ebs_or_pbs(la_uint64_t ebs_or_pbs)
{
    start_api_call("ebs_or_pbs=", ebs_or_pbs);

    if (m_type == type_e::PER_IFG) {
        log_err(HLD, "non per-ifg function is called for per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    la_uint64_t max_burst_size;
    m_device->get_limit(limit_type_e::METER_PROFILE__MAX_BURST_SIZE, max_burst_size);
    if (ebs_or_pbs > max_burst_size) {
        return LA_STATUS_EINVAL;
    }

    double burst_size_resolution;
    auto precision_type = (m_measure_mode == meter_measure_mode_e::BYTES)
                              ? la_precision_type_e::METER_PROFILE__EBS_RESOLUTION
                              : la_precision_type_e::METER_PROFILE__STATISTICAL_METER_EBS_RESOLUTION;
    la_status status = m_device->get_precision(precision_type, burst_size_resolution);
    return_on_error(status);
    if (ebs_or_pbs < burst_size_resolution) {
        log_err(HLD,
                "%s: EBS/PBS must be greater than burst size resolution. ebs_or_pbs=%llu burst_size_resolution=%llu.",
                __func__,
                ebs_or_pbs,
                (la_uint64_t)burst_size_resolution);
        return LA_STATUS_EINVAL;
    }

    for (size_t index = 0; index < NUM_IFGS_PER_DEVICE; ++index) {
        m_ifg_data[index].ebs_or_pbs = ebs_or_pbs;
    }
    m_stat_bank_data.ebs_or_pbs = ebs_or_pbs;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_ebs_or_pbs(la_uint64_t& out_ebs_or_pbs) const
{
    start_api_getter_call();

    if (m_type == type_e::PER_IFG) {
        log_err(HLD, "non per-ifg function is called for per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    out_ebs_or_pbs = m_ifg_data[0].ebs_or_pbs;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_cbs(la_slice_ifg ifg, la_uint64_t cbs)
{
    start_api_call("ifg=", ifg, "cbs=", cbs);

    if (m_type == type_e::GLOBAL) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    la_uint64_t max_burst_size;
    m_device->get_limit(limit_type_e::METER_PROFILE__MAX_BURST_SIZE, max_burst_size);
    if (cbs > max_burst_size) {
        return LA_STATUS_EINVAL;
    }

    double burst_size_resolution;
    la_status status = m_device->get_precision(la_precision_type_e::METER_PROFILE__CBS_RESOLUTION, burst_size_resolution);
    return_on_error(status);
    if (cbs < burst_size_resolution) {
        log_err(HLD,
                "%s: CBS must be greater than burst size resolution. cbs=%llu burst_size_resolution=%llu.",
                __func__,
                cbs,
                (la_uint64_t)burst_size_resolution);
        return LA_STATUS_EINVAL;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    m_ifg_data[g_ifg].cbs = cbs;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_cbs(la_slice_ifg ifg, la_uint64_t& out_cbs) const
{
    start_api_getter_call();

    if (m_type == type_e::GLOBAL) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    out_cbs = m_ifg_data[g_ifg].cbs;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::set_ebs_or_pbs(la_slice_ifg ifg, la_uint64_t ebs_or_pbs)
{
    start_api_call("ifg=", ifg, "ebs_or_pbs=", ebs_or_pbs);

    if (m_type == type_e::GLOBAL) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    if (m_device->is_in_use(this)) {
        log_err(HLD, "la_meter_profile is being used. cannot change settings while in use.");
        return LA_STATUS_EBUSY;
    }

    la_uint64_t max_burst_size;
    m_device->get_limit(limit_type_e::METER_PROFILE__MAX_BURST_SIZE, max_burst_size);
    if (ebs_or_pbs > max_burst_size) {
        return LA_STATUS_EINVAL;
    }

    double burst_size_resolution;
    la_status status = m_device->get_precision(la_precision_type_e::METER_PROFILE__EBS_RESOLUTION, burst_size_resolution);
    return_on_error(status);
    if (ebs_or_pbs < burst_size_resolution) {
        log_err(HLD,
                "EBS/PBS must be greater than burst size resolution ebs_or_pbs=%llu burst_size_resolution=%llu.",
                ebs_or_pbs,
                (la_uint64_t)burst_size_resolution);
        return LA_STATUS_EINVAL;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    m_ifg_data[g_ifg].ebs_or_pbs = ebs_or_pbs;

    if (!m_ifg_use_count->is_ifg_in_use(ifg)) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_ebs_or_pbs(la_slice_ifg ifg, la_uint64_t& out_ebs_or_pbs) const
{
    start_api_getter_call();

    if (m_type == type_e::GLOBAL) {
        log_err(HLD, "per-ifg function is called for non per-ifg meter profile");
        return LA_STATUS_EINVAL;
    }

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    out_ebs_or_pbs = m_ifg_data[g_ifg].ebs_or_pbs;

    return LA_STATUS_SUCCESS;
}

la_meter_profile::type_e
la_meter_profile_impl::get_type() const
{
    return m_type;
}

la_status
la_meter_profile_impl::notify_change(dependency_management_op op)
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
                "la_meter_profile_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_meter_profile_impl::get_allocation_in_exact_bank(la_slice_ifg slice_ifg, uint64_t& out_index) const
{
    if (!is_allocated_in_exact_bank(slice_ifg)) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    size_t g_ifg = m_ifg_use_count->get_index(slice_ifg);
    out_index = m_ifg_data[g_ifg].profile_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::get_allocation_in_statistical_banks(uint64_t& out_index) const
{
    if (!is_allocated_in_statistical_banks()) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    out_index = m_stat_bank_data.profile_index;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::add_ifg(la_slice_ifg ifg)
{
    transaction txn;
    bool ifg_added, slice_added, slice_pair_added;

    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([=]() {
        bool ifg_removed, slice_removed, slice_pair_removed;
        m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    });

    if (ifg_added) {
        // first attachment to the ifg, need to allocate in table
        size_t g_ifg = m_ifg_use_count->get_index(ifg);
        bool index_allocated = m_device->m_index_generators.exact_meter_profile_id[g_ifg].allocate(m_ifg_data[g_ifg].profile_index);
        if (!index_allocated) {
            txn.status = LA_STATUS_ERESOURCE;
            return txn.status;
        }
        txn.on_fail([=]() {
            m_device->m_index_generators.exact_meter_profile_id[g_ifg].release(m_ifg_data[g_ifg].profile_index);
            m_ifg_data[g_ifg].profile_index = INVALID_INDEX;
        });

        txn.status = exact_meter_profile_table_configure_entry(ifg);
        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::remove_ifg(la_slice_ifg ifg)
{

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    if (ifg_removed) {
        // no more users in that ifg for this profile
        la_status status = exact_meter_profile_table_erase_entry(ifg);
        return_on_error(status);

        size_t g_ifg = m_ifg_use_count->get_index(ifg);
        m_device->m_index_generators.exact_meter_profile_id[g_ifg].release(m_ifg_data[g_ifg].profile_index);
        m_ifg_data[g_ifg].profile_index = INVALID_INDEX;
    }

    return LA_STATUS_SUCCESS;
}

template <typename _Key, typename _Payload>
void
la_meter_profile_impl::populate_meter_profile_table_key_payload(size_t bank_index,
                                                                allocation_data data,
                                                                _Key& key,
                                                                _Payload& payload) const
{
    key.bank_index.value = bank_index;
    key.meter_profile_index.value = data.profile_index;

    payload.meter_count_mode.value = la_2_meter_measure_mode(m_measure_mode);
    payload.meter_mode.value = la_2_meter_rate_mode(m_rate_mode);
    payload.color_aware_mode.value = la_2_meter_color_aware_mode(m_color_awareness);
    la_meter_set::type_e meter_type
        = (m_measure_mode == meter_measure_mode_e::PACKETS) ? la_meter_set::type_e::STATISTICAL : la_meter_set::type_e::EXACT;
    payload.cbs.value = (data.cbs * m_device->get_meter_cir_eir_factor(meter_type)) / CBS_RESOLUTION;
    payload.ebs.value = (data.ebs_or_pbs * m_device->get_meter_cir_eir_factor(meter_type)) / EBS_OR_PBS_RESOLUTION;
}

la_status
la_meter_profile_impl::exact_meter_profile_table_configure_entry(la_slice_ifg ifg)
{
    npl_rx_meter_block_meter_profile_table_t::key_type k;
    npl_rx_meter_block_meter_profile_table_t::value_type v;
    npl_rx_meter_block_meter_profile_table_t::entry_pointer_type e = nullptr;

    size_t g_ifg = m_ifg_use_count->get_index(ifg);
    populate_meter_profile_table_key_payload(g_ifg, m_ifg_data[g_ifg], k, v.payloads.rx_meter_block_meter_profile_result);

    v.action = NPL_RX_METER_BLOCK_METER_PROFILE_TABLE_ACTION_WRITE;

    return m_device->m_tables.rx_meter_block_meter_profile_table->insert(k, v, e);
}

la_status
la_meter_profile_impl::exact_meter_profile_table_erase_entry(la_slice_ifg ifg)
{
    npl_rx_meter_block_meter_profile_table_t::key_type k;
    size_t g_ifg = m_ifg_use_count->get_index(ifg);

    k.bank_index.value = g_ifg;
    k.meter_profile_index.value = m_ifg_data[g_ifg].profile_index;

    return m_device->m_tables.rx_meter_block_meter_profile_table->erase(k);
}

la_object::object_type_e
la_meter_profile_impl::type() const
{
    return object_type_e::METER_PROFILE;
}

const la_device*
la_meter_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_meter_profile_impl::oid() const
{
    return m_oid;
}

std::string
la_meter_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_meter_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_meter_profile_impl::attach_statistical_meter()
{
    if (m_type != type_e::GLOBAL) {
        log_err(HLD, "%s: cannot attach non-global profile to statistical meter", __func__);
        return LA_STATUS_EINVAL;
    }

    if (m_measure_mode != meter_measure_mode_e::PACKETS) {
        log_err(HLD, "%s: cannot attach non-PPS profile to statistical meter", __func__);
        return LA_STATUS_EINVAL;
    }

    transaction txn;

    if (is_allocated_in_statistical_banks()) {
        m_stat_bank_data.use_count++;
        return LA_STATUS_SUCCESS;
    }

    bool did_allocate = m_device->m_index_generators.statistical_meter_profile_id.allocate(m_stat_bank_data.profile_index);
    if (!did_allocate) {
        return LA_STATUS_ERESOURCE;
    }
    m_stat_bank_data.use_count++;

    txn.on_fail([=]() {
        m_device->m_index_generators.statistical_meter_profile_id.release(m_stat_bank_data.profile_index);
        m_stat_bank_data.profile_index = INVALID_INDEX;
        m_stat_bank_data.use_count--;
    });

    txn.status = configure_statistical_meter_tables_entries();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::detach_statistical_meter()
{
    m_stat_bank_data.use_count--;
    if (m_stat_bank_data.use_count > 0) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = erase_statistical_meter_tables_entries();
    m_device->m_index_generators.statistical_meter_profile_id.release(m_stat_bank_data.profile_index);
    m_stat_bank_data.profile_index = INVALID_INDEX;
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::configure_statistical_meter_tables_entries()
{
    transaction txn;

    for (size_t bank_index = 0; bank_index < NUM_STATISTICAL_METER_BANKS; bank_index++) {
        txn.status = statistical_meter_profile_table_configure_entries(bank_index);
        return_on_error(txn.status);

        txn.on_fail([=]() { statistical_meter_profile_table_erase_entries(bank_index); });

        txn.status = distributed_meter_profile_table_configure_entries(bank_index);
        return_on_error(txn.status);

        txn.on_fail([=]() { distributed_meter_profile_table_erase_entries(bank_index); });
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::erase_statistical_meter_tables_entries()
{
    la_status status;
    for (size_t bank_index = 0; bank_index < NUM_STATISTICAL_METER_BANKS; bank_index++) {
        status = statistical_meter_profile_table_erase_entries(bank_index);
        return_on_error(status);

        status = distributed_meter_profile_table_erase_entries(bank_index);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_profile_impl::statistical_meter_profile_table_configure_entries(size_t bank_index)
{
    npl_rx_meter_meter_profile_table_t::key_type k;
    npl_rx_meter_meter_profile_table_t::value_type v;
    npl_rx_meter_meter_profile_table_t::entry_pointer_type e = nullptr;

    populate_meter_profile_table_key_payload(bank_index, m_stat_bank_data, k, v.payloads.rx_meter_meter_profile_result);
    v.action = NPL_RX_METER_METER_PROFILE_TABLE_ACTION_WRITE;

    return m_device->m_tables.rx_meter_meter_profile_table->insert(k, v, e);
}

la_status
la_meter_profile_impl::statistical_meter_profile_table_erase_entries(size_t bank_index)
{
    npl_rx_meter_meter_profile_table_t::key_type k;

    k.bank_index.value = bank_index;
    k.meter_profile_index.value = m_stat_bank_data.profile_index;

    return m_device->m_tables.rx_meter_meter_profile_table->erase(k);
}

la_status
la_meter_profile_impl::distributed_meter_profile_table_configure_entries(size_t bank_index)
{
    npl_rx_meter_distributed_meter_profile_table_t::key_type k;
    npl_rx_meter_distributed_meter_profile_table_t::value_type v;
    npl_rx_meter_distributed_meter_profile_table_t::entry_pointer_type e = nullptr;

    k.bank_index.value = bank_index;
    k.meter_profile_index.value = m_stat_bank_data.profile_index;

    v.payloads.rx_meter_distributed_meter_profile_result.is_distributed_meter = 0; // statistical meter
    v.payloads.rx_meter_distributed_meter_profile_result.is_cascade = la_2_meter_cascade_mode(m_cascade_mode);
    // The following properties are irrelevant for statistical meters.
    v.payloads.rx_meter_distributed_meter_profile_result.tx_message_template_index = 0;
    v.payloads.rx_meter_distributed_meter_profile_result.excess_token_release_thr = 0;
    v.payloads.rx_meter_distributed_meter_profile_result.excess_token_grant_thr = 0;
    v.payloads.rx_meter_distributed_meter_profile_result.committed_token_release_thr = 0;
    v.payloads.rx_meter_distributed_meter_profile_result.committed_token_grant_thr = 0;

    v.action = NPL_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE_ACTION_WRITE;

    return m_device->m_tables.rx_meter_distributed_meter_profile_table->insert(k, v, e);
}

la_status
la_meter_profile_impl::distributed_meter_profile_table_erase_entries(size_t bank_index)
{
    npl_rx_meter_distributed_meter_profile_table_t::key_type k;

    k.bank_index.value = bank_index;
    k.meter_profile_index.value = m_stat_bank_data.profile_index;

    return m_device->m_tables.rx_meter_distributed_meter_profile_table->erase(k);
}

bool
la_meter_profile_impl::is_allocated_in_exact_bank(la_slice_ifg slice_ifg) const
{
    size_t g_ifg = m_ifg_use_count->get_index(slice_ifg);
    return (m_ifg_data[g_ifg].profile_index != INVALID_INDEX);
}

bool
la_meter_profile_impl::is_allocated_in_statistical_banks() const
{
    return (m_stat_bank_data.profile_index != INVALID_INDEX);
}
} // namespace silicon_one
