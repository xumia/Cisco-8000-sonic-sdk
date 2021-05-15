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

#include "common/dassert.h"

#include "hld_utils.h"
#include "la_ifg_scheduler_impl.h"
#include "la_logical_port_scheduler_impl.h"
#include "la_output_queue_scheduler_impl.h"

#include "lld/ll_device.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"
#include "tm/la_credit_scheduler_enums.h"
#include "tm_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

// Entry of OqseMapCfg - OQSE mapping to LPSE
struct oqse_map_cfg_struct {
    uint16_t lpse_id : 5;        ///< Map OQSE to 1 of 20 LPSEs
    uint16_t cir_weight_idx : 3; ///< OqseCirWfqWeightIndex - Map OQSE to CIR Link List
    uint16_t eir_weight_idx : 3; ///< OqseEirWfqWeightIndex - Map OQSE to EIR Link List
    uint16_t padding : 5;        ///< TODO: remove - clean valgrind
    oqse_map_cfg_struct() : lpse_id(0), cir_weight_idx(0), eir_weight_idx(0), padding(0){};
};

la_logical_port_scheduler_impl::la_logical_port_scheduler_impl(const la_device_impl_wptr& device,
                                                               la_slice_id_t slice_id,
                                                               la_ifg_id_t ifg_id,
                                                               la_system_port_scheduler_id_t tid,
                                                               la_rate_t port_speed)
    : m_device(device),
      m_cs(nullptr),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_tid(tid),
      m_port_speed(port_speed),
      m_groups_cir_weights(size_t(NUM_OF_LPCS_GROUPS), 1),
      m_groups_eir_weights(size_t(NUM_OF_LPCS_GROUPS), 1)
{
    la_ifg_scheduler* ifg_sch = nullptr;

    m_device->get_ifg_scheduler(m_slice_id, m_ifg_id, ifg_sch);
    if (ifg_sch != nullptr) {
        m_cs = m_device->get_sptr<la_ifg_scheduler_impl>(ifg_sch);
    }

    if (m_slice_id < FIRST_HW_FABRIC_SLICE) {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch);
    } else {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->fabric_sch);
    }
}

la_logical_port_scheduler_impl::~la_logical_port_scheduler_impl()
{
}

la_status
la_logical_port_scheduler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_attached_oqcs(la_oq_pg_vec_t& out_oq_vector) const
{
    out_oq_vector.clear();
    // check each OQ for connection with the specific LP
    for (const auto& oqcs : m_oq_sch_set) {
        bit_vector tmp_bv;

        int oqse_id = oqcs->get_oqse_id();

        la_status status = m_device->m_ll_device->read_memory(*m_sch_oqse_map_cfg, oqse_id, tmp_bv);

        return_on_error(status);

        if (tmp_bv.bits(LPSE_MSB, LPSE_LSB).get_value() == m_tid) {
            la_oq_pg cur_iod;
            cur_iod.oqcs = oqcs.get();
            cur_iod.pg_cir = tmp_bv.bits(OQ_PG_CIR_MSB, OQ_PG_CIR_LSB).get_value();
            cur_iod.pg_eir = tmp_bv.bits(OQ_PG_EIR_MSB, OQ_PG_EIR_LSB).get_value();
            out_oq_vector.push_back(cur_iod);
        } else {
            log_crit(
                HLD, "oqse %d should have tid %d but has tid %ld", oqse_id, m_tid, tmp_bv.bits(LPSE_MSB, LPSE_LSB).get_value());
            return LA_STATUS_EUNKNOWN;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::attach_oqcs(la_output_queue_scheduler* oqcs_in, la_vsc_gid_t group_id)
{
    start_api_call("oqcs=", oqcs_in, "group_id=", group_id);
    auto oqcs = static_cast<la_output_queue_scheduler_impl*>(oqcs_in);
    if (group_id >= NUM_OF_LPCS_GROUPS) {
        log_err(
            HLD, "%s::%s(...); group_id=%d >= %d.", silicon_one::to_string(this).c_str(), __func__, group_id, NUM_OF_LPCS_GROUPS);
        return LA_STATUS_EINVAL;
    }

    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (oqcs->get_slice() != m_slice_id) {
        log_err(HLD,
                "%s::%s(...); oqcs is on slice %u, logical port scheduler is on slice %u.",
                silicon_one::to_string(this).c_str(),
                __func__,
                oqcs->get_slice(),
                m_slice_id);
        return LA_STATUS_EINVAL;
    }

    if (oqcs->get_ifg() != m_ifg_id) {
        log_err(HLD,
                "%s::%s(...); oqcs is on ifg %u, logical port scheduler is on ifg %u.",
                silicon_one::to_string(this).c_str(),
                __func__,
                oqcs->get_ifg(),
                m_ifg_id);
        return LA_STATUS_EINVAL;
    }

    auto oqcs_impl = m_device->get_sptr<la_output_queue_scheduler_impl>(oqcs);

    la_status status = do_attach_oqcs(oqcs_impl, group_id);
    return_on_error(status);

    status = do_set_oqcs_eir_or_pir_burst_size(oqcs_impl, tm_utils::DEFAULT_CREDIT_BUCKET_SIZE);
    return_on_error(status);

    status = do_set_oqcs_burst_size(oqcs_impl, tm_utils::DEFAULT_CREDIT_BUCKET_SIZE);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::do_attach_oqcs(const la_output_queue_scheduler_impl_wptr& oqcs_impl, size_t group_id)
{
    m_oq_sch_set.insert(oqcs_impl);

    // Set proper values at line oid in OqseMapCfg memory of SCH block
    // Each line consist of LpseId, OqseCirWfqWeightIndex, and OqseEirWfqWeightIndex

    struct oqse_map_cfg_struct val;
    val.lpse_id = m_tid;
    val.cir_weight_idx = group_id;
    val.eir_weight_idx = group_id;

    auto oqcs_id = oqcs_impl->get_oqse_id();

    la_status status = m_device->m_ll_device->write_memory(*m_sch_oqse_map_cfg, oqcs_id, 1, sizeof(val), &val);
    return_on_error(
        status, HLD, ERROR, "%s::%s(...); failed to config sch.oqse_map_cfg.", silicon_one::to_string(this).c_str(), __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::detach_oqcs(la_output_queue_scheduler* oqcs)
{
    start_api_call("oqcs=", oqcs);

    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    auto oqcs_sptr = m_device->get_sptr(oqcs);
    if (!is_oqcs_attached(oqcs_sptr)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = m_device->get_sptr<la_output_queue_scheduler_impl>(oqcs);

    la_status status = do_detach_oqcs(oqcs_impl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::do_detach_oqcs(const la_output_queue_scheduler_impl_wptr& oqcs_impl)
{
    // Set default values at line oid in OqseMapCfg memory of SCH block
    // Each line consist of LpseId, OqseCirWfqWeightIndex, and OqseEirWfqWeightIndex

    struct oqse_map_cfg_struct val;
    val.lpse_id = 0x0;
    val.cir_weight_idx = 0x0;
    val.eir_weight_idx = 0x0;

    auto oqcs_id = oqcs_impl->get_oqse_id();

    la_status status = m_device->m_ll_device->write_memory(*m_sch_oqse_map_cfg, oqcs_id, 1, sizeof(val), &val);
    return_on_error(
        status, HLD, ERROR, "%s::%s(...); failed to config sch.oqse_map_cfg.", silicon_one::to_string(this).c_str(), __func__);

    status = do_set_oqcs_eir_or_pir_burst_size(oqcs_impl, tm_utils::UNLIMITED_BUCKET_SIZE);
    return_on_error(status);

    status = do_set_oqcs_burst_size(oqcs_impl, tm_utils::UNLIMITED_BUCKET_SIZE);
    return_on_error(status);

    m_oq_sch_set.erase(oqcs_impl);

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_group_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const
{
    if (group_id >= NUM_OF_LPCS_GROUPS) {
        return LA_STATUS_EINVAL;
    }

    out_weight = m_groups_cir_weights[group_id];

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_group_actual_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const
{
    if (group_id >= NUM_OF_LPCS_GROUPS) {
        return LA_STATUS_EINVAL;
    }

    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_lpse_wfq_weight_map, m_tid, tmp_bv);

    return_on_error(stat);

    // Get proper values at line of tid in LpseWfqWeightMap memory of SCH block
    size_t lsb = group_id * sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH;
    size_t msb = lsb + sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH - 1;
    la_wfq_weight_t temp_out_weight = (la_wfq_weight_t)tmp_bv.bits(msb, lsb).get_value();
    if (temp_out_weight > tm_utils::TM_WEIGHT_MAX || temp_out_weight == 0) {
        return LA_STATUS_EUNKNOWN;
    }
    out_weight = temp_out_weight;

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::set_group_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t weight)
{
    start_api_call("group_id=", group_id, "weight=", weight);
    if ((group_id >= NUM_OF_LPCS_GROUPS) || (weight > tm_utils::TM_WEIGHT_MAX) || (weight == 0)) {
        return LA_STATUS_EINVAL;
    }

    m_groups_cir_weights[group_id] = weight;
    std::vector<la_rate_t> rates = tm_utils::convert_weight_2_rate_vector(
        m_groups_cir_weights, sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH);

    bit_vector bv_rates;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_lpse_wfq_weight_map, m_tid, bv_rates);
    return_on_error(stat);

    // Set proper values at line of tid in LpseWfqWeightMap memory of SCH block
    for (size_t i = 0; i < NUM_OF_LPCS_GROUPS; i++) {
        size_t lsb = i * sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH;
        size_t msb = lsb + sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH - 1;
        bv_rates.set_bits(msb, lsb, rates[i]);
    }

    return m_device->m_ll_device->write_memory(*m_sch_lpse_wfq_weight_map, m_tid, bv_rates);
}

la_status
la_logical_port_scheduler_impl::get_group_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const
{
    if (group_id >= NUM_OF_LPCS_GROUPS) {
        return LA_STATUS_EINVAL;
    }

    out_weight = m_groups_eir_weights[group_id];

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_group_actual_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const
{
    if (group_id >= NUM_OF_LPCS_GROUPS) {
        return LA_STATUS_EINVAL;
    }

    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_lpse_wfq_weight_map, m_tid, tmp_bv);

    return_on_error(stat);

    // Get proper values at line of tid in LpseWfqWeightMap memory of SCH block
    size_t lsb = group_id * sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH + tm_utils::EIR_WEIGHT_MAP_OFFSET;
    size_t msb = lsb + sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH - 1;
    la_wfq_weight_t temp_out_weight = (la_wfq_weight_t)tmp_bv.bits(msb, lsb).get_value();
    if (temp_out_weight > tm_utils::TM_WEIGHT_MAX || temp_out_weight == 0) {
        return LA_STATUS_EUNKNOWN;
    }
    out_weight = temp_out_weight;

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::set_group_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t weight)
{
    start_api_call("group_id=", group_id, "weight=", weight);
    if ((group_id >= NUM_OF_LPCS_GROUPS) || (weight > tm_utils::TM_WEIGHT_MAX) || (weight == 0)) {
        return LA_STATUS_EINVAL;
    }

    m_groups_eir_weights[group_id] = weight;
    std::vector<la_rate_t> rates = tm_utils::convert_weight_2_rate_vector(
        m_groups_eir_weights, sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH);

    bit_vector bv_rates;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_lpse_wfq_weight_map, m_tid, bv_rates);
    return_on_error(stat);

    // Set proper values at line of tid in LpseWfqWeightMap memory of SCH block
    for (size_t i = 0; i < NUM_OF_LPCS_GROUPS; i++) {
        size_t lsb = i * sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH + tm_utils::EIR_WEIGHT_MAP_OFFSET;
        size_t msb = lsb + sch_lpse_wfq_weight_map_memory::fields::LPSE_CIR_WEIGHT0_WIDTH - 1;
        bv_rates.set_bits(msb, lsb, rates[i]);
    }

    return m_device->m_ll_device->write_memory(*m_sch_lpse_wfq_weight_map, m_tid, bv_rates);
}

bool
la_logical_port_scheduler_impl::is_oqcs_attached(const la_output_queue_scheduler_wptr& oqcs) const
{
    auto oqcs_impl = oqcs.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
    return (m_oq_sch_set.find(oqcs_impl) != m_oq_sch_set.end());
}

la_status
la_logical_port_scheduler_impl::get_oqcs_cir(la_output_queue_scheduler* oqcs, la_rate_t& out_rate) const
{
    start_api_getter_call("");

    auto pqcs_sptr = m_device->get_sptr(oqcs);
    return do_get_oqcs_cir(pqcs_sptr, out_rate);
}

la_status
la_logical_port_scheduler_impl::do_get_oqcs_cir(const la_output_queue_scheduler_wptr& oqcs, la_rate_t& out_rate) const
{
    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_oqcs_attached(oqcs)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = oqcs.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
    auto oqcs_id = oqcs_impl->get_oqse_id();

    sch_oqse_cir_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_oqse_cir_token_bucket_cfg, oqcs_id, token_bucket_cfg);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to read rate ratio", silicon_one::to_string(this).c_str(), __func__);

    // If max_bucket_value is set to UNLIMITED it means that this shaper is disabled
    if (token_bucket_cfg.fields.oqse_cir_max_bucket_value == tm_utils::UNLIMITED_BUCKET_SIZE) {
        out_rate = LA_RATE_UNLIMITED;
        return LA_STATUS_SUCCESS;
    }

    la_rate_t tpse_rate;
    status = m_cs->get_cir(tpse_rate);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to get tpse cir", silicon_one::to_string(this).c_str(), __func__);

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.oqse_cir_rate_exponent,
                                                          token_bucket_cfg.fields.oqse_cir_rate_mantissa);
    out_rate = ratio * tpse_rate;

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::set_oqcs_cir(la_output_queue_scheduler* oqcs, la_rate_t rate)
{
    start_api_call("oqcs=", oqcs, "rate=", rate);

    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto oqcs_sptr = m_device->get_sptr(oqcs);
    if (!is_oqcs_attached(oqcs_sptr)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = static_cast<la_output_queue_scheduler_impl*>(oqcs);
    auto oqcs_id = oqcs_impl->get_oqse_id();

    la_rate_t tpse_rate;
    la_status status = m_cs->get_cir(tpse_rate);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to get tpse cir", silicon_one::to_string(this).c_str(), __func__);

    // rate cannot be higher than maximum LP rate
    if (rate > tpse_rate) {
        log_err(HLD,
                "%s::%s(...); rate=%llu is bigger than tpse_rate=%llu",
                silicon_one::to_string(this).c_str(),
                __func__,
                rate,
                tpse_rate);
        return LA_STATUS_EINVAL;
    }

    auto cached_credit_cir_burst_size = oqcs_impl->get_cached_credit_cir_burst_size();
    status = tm_utils::set_oqcs_rate(m_device,
                                     m_sch_oqse_cir_token_bucket_cfg,
                                     m_sch_oqse_cir_token_bucket,
                                     oqcs_id,
                                     rate,
                                     m_port_speed,
                                     tpse_rate,
                                     cached_credit_cir_burst_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_oqcs_burst_size(la_output_queue_scheduler* oqcs, size_t& out_burst) const
{
    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto oqcs_sptr = m_device->get_sptr(oqcs);
    if (!is_oqcs_attached(oqcs_sptr)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = static_cast<la_output_queue_scheduler_impl*>(oqcs);
    auto oqcs_id = oqcs_impl->get_oqse_id();

    sch_oqse_cir_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_oqse_cir_token_bucket_cfg, oqcs_id, token_bucket_cfg);
    return_on_error(status);

    out_burst = token_bucket_cfg.fields.oqse_cir_max_bucket_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::set_oqcs_burst_size(la_output_queue_scheduler* oqcs, size_t burst)
{
    start_api_call("oqcs=", oqcs, "burst=", burst);

    auto oqcs_wptr = m_device->get_sptr(oqcs);
    return do_set_oqcs_burst_size(oqcs_wptr, burst);
}

la_status
la_logical_port_scheduler_impl::do_set_oqcs_burst_size(const la_output_queue_scheduler_wptr& oqcs, size_t burst)
{
    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_oqcs_attached(oqcs)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = oqcs.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
    size_t mem_line = oqcs_impl->get_oqse_id();

    la_status status
        = tm_utils::set_burst_size(m_device, m_sch_oqse_cir_token_bucket_cfg, m_sch_oqse_cir_token_bucket, mem_line, burst);
    return_on_error(status);

    if (burst != tm_utils::UNLIMITED_BUCKET_SIZE) {
        oqcs_impl->cache_credit_cir_burst_size(burst);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_oqcs_eir_or_pir(la_output_queue_scheduler* oqcs, la_rate_t& out_rate, bool& out_is_eir) const
{
    start_api_getter_call("");

    auto oqcs_sptr = m_device->get_sptr(oqcs);
    return do_get_oqcs_eir_or_pir(oqcs_sptr, out_rate, out_is_eir);
}

la_status
la_logical_port_scheduler_impl::do_get_oqcs_eir_or_pir(const la_output_queue_scheduler_wptr& oqcs,
                                                       la_rate_t& out_rate,
                                                       bool& out_is_eir) const
{
    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_oqcs_attached(oqcs)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = oqcs.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
    auto oqcs_id = oqcs_impl->get_oqse_id();

    sch_oqse_eir_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_oqse_eir_token_bucket_cfg, oqcs_id, token_bucket_cfg);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to read rate ratio", silicon_one::to_string(this).c_str(), __func__);

    bit_vector mode_bv;
    status = m_device->m_ll_device->read_register(*m_sch_oqse_eir_pir_token_bucket_cfg, mode_bv);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to read is_eir", silicon_one::to_string(this).c_str(), __func__);
    out_is_eir = !mode_bv.bit(oqcs_id);

    // If max_bucket_value is set to UNLIMITED it means that this shaper is disabled
    if (token_bucket_cfg.fields.oqse_eir_max_bucket_value == tm_utils::UNLIMITED_BUCKET_SIZE) {
        out_rate = LA_RATE_UNLIMITED;
        return LA_STATUS_SUCCESS;
    }

    la_rate_t tpse_rate;
    status = m_cs->get_eir(tpse_rate);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to get tpse eir", silicon_one::to_string(this).c_str(), __func__);

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.oqse_eir_rate_exponent,
                                                          token_bucket_cfg.fields.oqse_eir_rate_mantissa);
    out_rate = ratio * tpse_rate;

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::set_oqcs_eir_or_pir(la_output_queue_scheduler* oqcs, la_rate_t rate, bool is_eir)
{
    start_api_call("oqcs=", oqcs, "rate=", rate, "is_eir=", is_eir);

    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);

        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_output_queue_scheduler_wptr& oqcs_wptr = m_device->get_sptr(oqcs);
    if (!is_oqcs_attached(oqcs_wptr)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = oqcs_wptr.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
    auto oqcs_id = oqcs_impl->get_oqse_id();

    la_rate_t tpse_rate;
    la_status status = m_cs->get_eir(tpse_rate);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to get tpse eir", silicon_one::to_string(this).c_str(), __func__);

    // rate cannot be higher than maximum LP rate
    if (rate > tpse_rate) {
        log_err(HLD,
                "%s::%s(...); rate=%llu is bigger than tpse_rate=%llu",
                silicon_one::to_string(this).c_str(),
                __func__,
                rate,
                tpse_rate);
        return LA_STATUS_EINVAL;
    }

    auto cached_credit_eir_or_pir_burst_size = oqcs_impl->get_cached_credit_eir_or_pir_burst_size();
    status = tm_utils::set_oqcs_rate(m_device,
                                     m_sch_oqse_eir_token_bucket_cfg,
                                     m_sch_oqse_eir_token_bucket,
                                     oqcs_id,
                                     rate,
                                     m_port_speed,
                                     tpse_rate,
                                     cached_credit_eir_or_pir_burst_size);
    return_on_error(status);

    status = m_device->m_ll_device->read_modify_write_register(*m_sch_oqse_eir_pir_token_bucket_cfg, oqcs_id, oqcs_id, !is_eir);
    return_on_error(status, HLD, ERROR, "%s::%s(...); failed to configure is_eir", silicon_one::to_string(this).c_str(), __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::get_oqcs_eir_or_pir_burst_size(la_output_queue_scheduler* oqcs, size_t& out_burst) const
{
    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto oqcs_sptr = m_device->get_sptr(oqcs);
    if (!is_oqcs_attached(oqcs_sptr)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = static_cast<la_output_queue_scheduler_impl*>(oqcs);
    auto oqcs_id = oqcs_impl->get_oqse_id();

    sch_oqse_eir_token_bucket_cfg_memory token_bucket_cfg;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_oqse_eir_token_bucket_cfg, oqcs_id, token_bucket_cfg);
    return_on_error(stat, HLD, ERROR, "%s::%s(...); failed to read rate ratio", silicon_one::to_string(this).c_str(), __func__);

    out_burst = token_bucket_cfg.fields.oqse_eir_max_bucket_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::set_oqcs_eir_or_pir_burst_size(la_output_queue_scheduler* oqcs, size_t burst)
{
    start_api_call("oqcs=", oqcs, "burst=", burst);

    auto oqcs_wptr = m_device->get_sptr(oqcs);
    return do_set_oqcs_eir_or_pir_burst_size(oqcs_wptr, burst);
}

la_status
la_logical_port_scheduler_impl::do_set_oqcs_eir_or_pir_burst_size(const la_output_queue_scheduler_wptr& oqcs, size_t burst)
{
    if (oqcs == nullptr) {
        log_err(HLD, "%s::%s(...); oqcs is null.", silicon_one::to_string(this).c_str(), __func__);

        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oqcs, this)) {
        log_err(HLD,
                "%s::%s(...); oqcs is on %s, this is on %s.",
                silicon_one::to_string(this).c_str(),
                __func__,
                silicon_one::to_string(oqcs->get_device()).c_str(),
                silicon_one::to_string(m_device).c_str());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_oqcs_attached(oqcs)) {
        log_err(HLD, "%s::%s(...); oqcs is not attached to this LPSE.", silicon_one::to_string(this).c_str(), __func__);
        return LA_STATUS_ENOTFOUND;
    }

    auto oqcs_impl = oqcs.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
    size_t mem_line = oqcs_impl->get_oqse_id();

    la_status status
        = tm_utils::set_burst_size(m_device, m_sch_oqse_eir_token_bucket_cfg, m_sch_oqse_eir_token_bucket, mem_line, burst);
    return_on_error(status);

    if (burst != tm_utils::UNLIMITED_BUCKET_SIZE) {
        oqcs_impl->cache_credit_eir_or_pir_burst_size(burst);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_logical_port_scheduler_impl::update_port_speed(la_mac_port::port_speed_e mac_port_speed,
                                                  const la_output_queue_scheduler_impl_wptr& eir_oqse,
                                                  const la_output_queue_scheduler_impl_wptr& cir_oqse)
{
    m_port_speed = (la_2_port_speed(mac_port_speed)) * UNITS_IN_GIGA;

    // Check if logical port is enabled.
    if (m_oq_sch_set.empty()) {
        return LA_STATUS_SUCCESS;
    }

    // Disable shaper if port speed is less than the configured shaper rate;
    for (const auto& oqcs : m_oq_sch_set) {
        la_rate_t rate;
        bool is_eir;
        la_status status;

        // Oqcs Cir
        if (oqcs != eir_oqse) {
            status = do_get_oqcs_cir(oqcs, rate);
            if (rate > m_port_speed) {
                status = do_set_oqcs_burst_size(oqcs, tm_utils::UNLIMITED_BUCKET_SIZE);
                return_on_error(status);
            }
        }

        // Oqcs Eir/Pir
        if (oqcs != cir_oqse) {
            status = do_get_oqcs_eir_or_pir(oqcs, rate, is_eir);
            if (rate > m_port_speed) {
                status = do_set_oqcs_eir_or_pir_burst_size(oqcs, tm_utils::UNLIMITED_BUCKET_SIZE);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_logical_port_scheduler_impl::type() const
{
    return object_type_e::LOGICAL_PORT_SCHEDULER;
}

std::string
la_logical_port_scheduler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_logical_port_scheduler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_logical_port_scheduler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_logical_port_scheduler_impl::get_device() const
{
    return m_device.get();
}
}
