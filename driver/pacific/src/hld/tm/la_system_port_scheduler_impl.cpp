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

#include <algorithm>

#include "common/gen_operators.h"
#include "hld_utils.h"
#include "la_ifg_scheduler_impl.h"
#include "la_interface_scheduler_impl.h"
#include "la_logical_port_scheduler_impl.h"
#include "la_output_queue_scheduler_impl.h"
#include "la_system_port_scheduler_impl.h"
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

// LSB bit of the value for the specific OQ
const size_t la_system_port_scheduler_impl::s_oq_lsb_bit[OQ_COUNT] = {0, 3, 6, 9, 12, 14, 16, BITS_PER_PORT};

// MSB bit of the value for the specific OQ
const size_t la_system_port_scheduler_impl::s_oq_msb_bit[OQ_COUNT] = {2, 5, 8, 11, 13, 15, 16, BITS_PER_PORT};

const int la_system_port_scheduler_impl::s_oq_oqpg_value[OQ_COUNT][(size_t)priority_group_e::NONE] = {
    {0, -1, -1, -1, 4, 5, 6, 7},     // map OQ 0: 0 = OQPG 0, 4-7 = OQPG 4-7
    {-1, 1, -1, -1, 4, 5, 6, 7},     // map OQ 1: 1 = OQPG 1, 4-7 = OQPG 4-7
    {-1, -1, 2, -1, 4, 5, 6, 7},     // map OQ 2: 2 = OQPG 2, 4-7 = OQPG 4-7
    {-1, -1, -1, 3, 4, 5, 6, 7},     // map OQ 3: 3 = OQPG 3, 4-7 = OQPG 4-7
    {-1, -1, -1, -1, 0, 1, 2, 3},    // map OQ 4: 0 = OQPG 4, 1 = OQPG 5,2 = OQPG 6, 3 = OQPG 7
    {-1, -1, -1, -1, -1, 1, 2, 3},   // map OQ 5: 1 = OQPG 5, 2 = OQPG 6,3 = OQPG 7
    {-1, -1, -1, -1, -1, -1, 0, 1},  // map OQ 6: 0 = OQGP 6, 1 = OQPG 7
    {-1, -1, -1, -1, -1, -1, -1, 0}, // OQ 7 is always mapped to OQPG 7
};
const uint32_t la_system_port_scheduler_impl::s_oq_base_pq[OQ_COUNT] = {0, 0, 0, 0, 4, 4, 6, 7};

la_system_port_scheduler_impl::la_system_port_scheduler_impl(const la_device_impl_wptr& device,
                                                             la_slice_id_t slice_id,
                                                             la_ifg_id_t ifg_id,
                                                             la_system_port_scheduler_id_t sp_sch_id)
    : m_device(device),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_intf_sch(nullptr),
      m_sp_sch_id(sp_sch_id),
      m_oq_sch_vec(),
      m_lp_sch(nullptr),
      m_logical_port_enabled(false),
      m_port_speed(0),
      m_requested_credit_oqpg_cir_burst_size(size_t(priority_group_e::NONE), tm_utils::UNLIMITED_BUCKET_SIZE),
      m_requested_transmit_oqpg_cir_burst_size(size_t(priority_group_e::NONE), tm_utils::UNLIMITED_BUCKET_SIZE),
      m_pg_weights(size_t(priority_group_e::NONE), 1)
{
    m_uc_mc_weights.resize(OQ_COUNT);
    for (la_oq_id_t oid = 0; oid < OQ_COUNT; oid++) {
        uint8_t last = to_utype(uc_mc_weights_e::LAST);
        m_uc_mc_weights[oid].resize(last);
        for (uint8_t idx = 0; idx < last; idx++) {
            m_uc_mc_weights[oid][idx] = 1;
        }
    }

    if (m_slice_id < FIRST_HW_FABRIC_SLICE) {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch);
    } else {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->fabric_sch);
    }
}

la_system_port_scheduler_impl::~la_system_port_scheduler_impl()
{
}

la_status
la_system_port_scheduler_impl::initialize(la_object_id_t oid, const la_interface_scheduler_wptr& intf_sch)
{
    m_oid = oid;
    la_status status;
    m_intf_sch = intf_sch.weak_ptr_static_cast<la_interface_scheduler_impl>();

    for (size_t i = 0; i < OQ_COUNT; i++) {
        la_output_queue_scheduler_impl_sptr oqcs;
        status = m_device->do_create_output_queue_scheduler(m_slice_id,
                                                            m_ifg_id,
                                                            index_handle(m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + i),
                                                            la_output_queue_scheduler::scheduling_mode_e::DIRECT_4SP,
                                                            oqcs);
        if (status != LA_STATUS_SUCCESS) {
            m_oq_sch_vec.clear();
            return status;
        }

        m_oq_sch_vec.push_back(oqcs);

        m_device->add_object_dependency(oqcs, this);
    }

    m_port_speed = (la_2_port_speed(m_intf_sch->get_port_speed())) * UNITS_IN_GIGA;

    la_logical_port_scheduler_impl_sptr lp_sch;
    status = m_device->create_logical_port_scheduler(m_slice_id, m_ifg_id, m_sp_sch_id, m_port_speed, lp_sch);
    return_on_error(status);
    m_lp_sch = lp_sch;

    // Configure the default weight between unicast and multicast.
    // TODO: Consider remove, the user should use the API.
    la_wfq_weight_t ucw = 1;
    la_wfq_weight_t mcw = 1;
    for (size_t oid = 0; oid < OQ_COUNT; oid++) {
        status = do_set_transmit_uc_mc_weight(oid, ucw, mcw);
        return_on_error(status);

        // Default bucket sizes
        // Allowing LA_STATUS_EACCES because memory can be stuck for some OQ/OQPG while for others they can be available.
        // TODO: implement reset to IFG scheduler in order to release and reuse them.
        status = do_set_credit_pir_burst_size(oid, tm_utils::DEFAULT_CREDIT_BUCKET_SIZE);
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_EACCES) {
            m_oq_sch_vec.clear();
            return status;
        }

        status = do_set_transmit_pir_burst_size(oid, tm_utils::DEFAULT_TRANSMIT_BUCKET_SIZE);
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_EACCES) {
            m_oq_sch_vec.clear();
            return status;
        }

        status = do_set_priority_group_credit_burst_size(oid, tm_utils::DEFAULT_CREDIT_BUCKET_SIZE);
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_EACCES) {
            m_oq_sch_vec.clear();
            return status;
        }

        status = do_set_priority_group_transmit_burst_size(oid, tm_utils::DEFAULT_TRANSMIT_BUCKET_SIZE);
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_EACCES) {
            m_oq_sch_vec.clear();
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::destroy()
{
    for (size_t id = 0; id < m_oq_sch_vec.size(); id++) {
        const auto& oq_sch = m_oq_sch_vec[id];

        m_device->remove_object_dependency(oq_sch, this);
        m_device->do_destroy(oq_sch);
        m_oq_sch_vec[id].reset();
    }
    m_oq_sch_vec.clear();

    m_device->do_destroy(m_lp_sch);
    m_lp_sch = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_priority_propagation(bool& out_enabled) const
{
    start_api_getter_call("");
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register(*m_sch_tpse_general_configuration, tmp_bv);
    return_on_error(stat);

    out_enabled = tmp_bv.bit(m_sp_sch_id + TPSE_PRIORITY_PROPAGATION_BASE);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_priority_propagation(bool enabled)
{
    start_api_call("enabled=", enabled);
    // Set field TpsePriorityPropagation[m_sp_sch_id] of register TpseGeneralConfiguration
    la_status stat = m_device->m_ll_device->read_modify_write_register(*m_sch_tpse_general_configuration,
                                                                       m_sp_sch_id + TPSE_PRIORITY_PROPAGATION_BASE,
                                                                       m_sp_sch_id + TPSE_PRIORITY_PROPAGATION_BASE,
                                                                       enabled);
    return_on_error(stat);

    // Set field TpsePriorityPropagation[m_sp_sch_id] of register TpseGeneralConfiguration[m_ifg_id]
    return m_device->m_ll_device->read_modify_write_register(
        *(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_general_configuration)[m_ifg_id],
        m_sp_sch_id,
        m_sp_sch_id,
        enabled);
}

la_status
la_system_port_scheduler_impl::get_logical_port_enabled(bool& out_enabled) const
{
    start_api_getter_call("");

    out_enabled = m_logical_port_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_logical_port_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_logical_port_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    if (enabled == false) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // Set field TpseMapLogicalPort[m_sp_sch_id] of register TpseGeneralConfiguration
    la_status status = m_device->m_ll_device->read_modify_write_register(*m_sch_tpse_general_configuration,
                                                                         m_sp_sch_id + TPSE_MAP_LOGICAL_PORT_BASE,
                                                                         m_sp_sch_id + TPSE_MAP_LOGICAL_PORT_BASE,
                                                                         enabled);
    return_on_error(status);

    status = pacific_oqcs_eir_cir_workaround();
    return_on_error(status);

    m_logical_port_enabled = enabled;

    return status;
}

la_status
la_system_port_scheduler_impl::pacific_oqcs_eir_cir_workaround()
{
    // Logical port EIR/CIR are connected to TM port's OQSE 0-1 in HW.
    // SDK attachs these OQSE to the logical port in order to keep credit flow available.
    // Due to HW bug OQSE1 must use only CIR path and OQSE0 only EIR path
    const auto& eir_oqse = m_oq_sch_vec[0];
    la_status status = eir_oqse->set_scheduling_mode(la_output_queue_scheduler::scheduling_mode_e::LP_SP_SP);
    return_on_error(status);

    status = m_lp_sch->do_attach_oqcs(eir_oqse, 0 /* group_id */);
    return_on_error(status);

    status = m_lp_sch->do_set_oqcs_eir_or_pir_burst_size(eir_oqse, tm_utils::DEFAULT_CREDIT_BUCKET_SIZE /* burst */);
    return_on_error(status);

    status = m_lp_sch->do_set_oqcs_burst_size(eir_oqse, 0 /* burst */);
    return_on_error(status);

    const auto& cir_oqse = m_oq_sch_vec[1];
    status = cir_oqse->set_scheduling_mode(la_output_queue_scheduler::scheduling_mode_e::LP_SP_SP);
    return_on_error(status);

    status = m_lp_sch->do_attach_oqcs(cir_oqse, 0 /* group_id */);
    return_on_error(status);

    status = m_lp_sch->do_set_oqcs_burst_size(cir_oqse, tm_utils::DEFAULT_CREDIT_BUCKET_SIZE /* burst */);
    return_on_error(status);

    status = m_lp_sch->do_set_oqcs_eir_or_pir_burst_size(cir_oqse, 0 /* burst */);

    return status;
}

la_status
la_system_port_scheduler_impl::get_oq_priority_group(la_oq_id_t oid, priority_group_e& out_pg) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    uint32_t val = 0;

    if (s_oq_msb_bit[oid] < BITS_PER_PORT) {
        bit_vector tmp_bv;
        la_status stat = m_device->m_ll_device->read_register(*m_sch_tpse_oqpg_mapping_configuration, tmp_bv);
        return_on_error(stat);

        int base = m_sp_sch_id * BITS_PER_PORT;
        val = tmp_bv.bits(base + s_oq_msb_bit[oid], base + s_oq_lsb_bit[oid]).get_value();
    }

    val += s_oq_base_pq[oid];

    out_pg = (priority_group_e)val;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_oq_priority_group(la_oq_id_t oid, priority_group_e pg)
{
    start_api_call("oid=", oid, "pg=", pg);
    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    if (s_oq_oqpg_value[oid][(size_t)pg] < 0) {
        return LA_STATUS_EINVAL;
    }

    if (s_oq_msb_bit[oid] < BITS_PER_PORT) {
        int base = m_sp_sch_id * BITS_PER_PORT;

        // Credit scheduler
        la_status stat = m_device->m_ll_device->read_modify_write_register(*m_sch_tpse_oqpg_mapping_configuration,
                                                                           base + s_oq_msb_bit[oid],
                                                                           base + s_oq_lsb_bit[oid],
                                                                           s_oq_oqpg_value[oid][(size_t)pg]);
        return_on_error(stat);

        // Transmit scheduler
        stat = m_device->m_ll_device->read_modify_write_register(
            *(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_oqpg_mapping_configuration)[m_ifg_id],
            base + s_oq_msb_bit[oid],
            base + s_oq_lsb_bit[oid],
            s_oq_oqpg_value[oid][(size_t)pg]);
        return_on_error(stat);
    }

    // Nothing to modify
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_credit_pir(la_oq_id_t oid, la_rate_t& out_rate) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    sch_oq_pir_token_bucket_cfg_memory token_bucket_cfg;
    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_oq_pir_token_bucket_cfg, mem_line, token_bucket_cfg);
    return_on_error(status);

    // If max_bucket_value is set to UNLIMITED it means that this shaper is disabled
    if (token_bucket_cfg.fields.oq_pir_max_bucket_value == tm_utils::UNLIMITED_BUCKET_SIZE) {
        out_rate = LA_RATE_UNLIMITED;
        return LA_STATUS_SUCCESS;
    }

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.oq_pir_rate_exponent,
                                                          token_bucket_cfg.fields.oq_pir_rate_mantissa);

    // The OQCS PIR is stored as a relative to IFG TPSE PIR, the ratio is as defined below
    la_rate_t tpse_pir = 0;
    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_eir(tpse_pir);
    return_on_error(status);

    out_rate = ratio * tpse_pir;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_credit_pir(la_oq_id_t oid, la_rate_t rate)
{
    start_api_call("oid=", oid, "rate=", rate);
    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;

    la_rate_t tpse_pir = 0;
    la_status status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_eir(tpse_pir);
    return_on_error(status);

    auto oqcs_impl = m_oq_sch_vec[oid].get();
    auto cached_credit_oq_pir_burst_size = oqcs_impl->get_cached_credit_oq_pir_burst_size();
    status = tm_utils::set_oqcs_rate(m_device,
                                     m_sch_oq_pir_token_bucket_cfg,
                                     m_sch_oq_pir_token_bucket,
                                     mem_line,
                                     rate,
                                     m_port_speed,
                                     tpse_pir,
                                     cached_credit_oq_pir_burst_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_credit_pir_burst_size(la_oq_id_t oid, size_t& out_burst) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    sch_oq_pir_token_bucket_cfg_memory token_bucket;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_oq_pir_token_bucket_cfg, mem_line, token_bucket);
    return_on_error(stat);

    out_burst = token_bucket.fields.oq_pir_max_bucket_value;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_credit_pir_burst_size(la_oq_id_t oid, size_t burst)
{
    start_api_call("oid=", oid, "burst=", burst);
    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    la_status status = do_set_credit_pir_burst_size(oid, burst);
    return status;
}

la_status
la_system_port_scheduler_impl::do_set_credit_pir_burst_size(la_oq_id_t oid, size_t burst)
{
    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    la_status status
        = tm_utils::set_burst_size(m_device, m_sch_oq_pir_token_bucket_cfg, m_sch_oq_pir_token_bucket, mem_line, burst);
    return_on_error(status);

    if (burst != tm_utils::UNLIMITED_BUCKET_SIZE) {
        auto oqcs_impl = m_oq_sch_vec[oid].get();
        oqcs_impl->cache_credit_oq_pir_burst_size(burst);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_transmit_pir(la_oq_id_t oid, la_rate_t& out_rate) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    pdoq_oq_pir_token_bucket_cfg_memory token_bucket_cfg;
    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    la_status status = m_device->m_ll_device->read_memory(
        *(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oq_pir_token_bucket_cfg)[m_ifg_id], mem_line, token_bucket_cfg);
    return_on_error(status);

    // If max_bucket_value is set to UNLIMITED it means that this shaper is disabled
    if (token_bucket_cfg.fields.oq_pir_max_bucket_value == tm_utils::UNLIMITED_BUCKET_SIZE) {
        out_rate = LA_RATE_UNLIMITED;
        return LA_STATUS_SUCCESS;
    }

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.oq_pir_rate_exponent,
                                                          token_bucket_cfg.fields.oq_pir_rate_mantissa);

    la_rate_t ifg_rate = 0;
    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_transmit_pir(ifg_rate);
    return_on_error(status);

    out_rate = ratio * ifg_rate;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_transmit_pir(la_oq_id_t oid, la_rate_t rate)
{
    start_api_call("oid=", oid, "rate=", rate);
    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    lld_memory_scptr cfg_mem = (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oq_pir_token_bucket_cfg)[m_ifg_id];
    lld_memory_scptr dynamic_mem = (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oq_pir_token_bucket)[m_ifg_id];

    la_rate_t ifg_rate = 0;
    la_status status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_transmit_pir(ifg_rate);
    return_on_error(status);

    auto oqcs_impl = m_oq_sch_vec[oid].get();
    auto cached_transmit_oq_pir_burst_size = oqcs_impl->get_cached_transmit_oq_pir_burst_size();
    status = tm_utils::set_oqcs_rate(
        m_device, cfg_mem, dynamic_mem, mem_line, rate, m_port_speed, ifg_rate, cached_transmit_oq_pir_burst_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_transmit_pir_burst_size(la_oq_id_t oid, size_t& out_burst) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    pdoq_oq_pir_token_bucket_cfg_memory token_bucket;
    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    la_status stat = m_device->m_ll_device->read_memory(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oq_pir_token_bucket_cfg)[m_ifg_id], mem_line, token_bucket);
    return_on_error(stat);

    out_burst = token_bucket.fields.oq_pir_max_bucket_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_transmit_pir_burst_size(la_oq_id_t oid, size_t burst)
{
    start_api_call("oid=", oid, "burst=", burst);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    return do_set_transmit_pir_burst_size(oid, burst);
}

la_status
la_system_port_scheduler_impl::do_set_transmit_pir_burst_size(la_oq_id_t oid, size_t burst)
{
    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    const auto& pdoq_top = m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top;
    la_status status = tm_utils::set_burst_size(
        m_device, (*pdoq_top->oq_pir_token_bucket_cfg)[m_ifg_id], (*pdoq_top->oq_pir_token_bucket)[m_ifg_id], mem_line, burst);
    return_on_error(status);

    if (burst != tm_utils::UNLIMITED_BUCKET_SIZE) {
        auto oqcs_impl = m_oq_sch_vec[oid].get();
        oqcs_impl->cache_transmit_oq_pir_burst_size(burst);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t& out_ucw, la_wfq_weight_t& out_mcw) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    out_ucw = m_uc_mc_weights[oid][to_utype(uc_mc_weights_e::UC_IDX)];
    out_mcw = m_uc_mc_weights[oid][to_utype(uc_mc_weights_e::MC_IDX)];

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t ucw, la_wfq_weight_t mcw)
{
    start_api_call("oid=", oid, "ucw=", ucw, "mcw=", mcw);
    if ((oid >= OQ_COUNT) || (ucw > tm_utils::TM_WFQ_WEIGHT_MAX) || (mcw > tm_utils::TM_WFQ_WEIGHT_MAX) || (ucw == 0)
        || (mcw == 0)) {
        return LA_STATUS_EINVAL;
    }

    return do_set_transmit_uc_mc_weight(oid, ucw, mcw);
}

la_status
la_system_port_scheduler_impl::do_set_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t ucw, la_wfq_weight_t mcw)
{
    pdoq_uc_mc_wfq_cfg_memory uc_mc_wfq_cfg;

    m_uc_mc_weights[oid][to_utype(uc_mc_weights_e::UC_IDX)] = ucw;
    m_uc_mc_weights[oid][to_utype(uc_mc_weights_e::MC_IDX)] = mcw;

    std::vector<la_rate_t> rates
        = tm_utils::convert_weight_2_rate_vector(m_uc_mc_weights[oid], pdoq_uc_mc_wfq_cfg_memory::fields::UC_WFQ_WEIGHT_WIDTH);

    uc_mc_wfq_cfg.fields.uc_wfq_weight = rates[to_utype(uc_mc_weights_e::UC_IDX)];
    uc_mc_wfq_cfg.fields.mc_wfq_weight = rates[to_utype(uc_mc_weights_e::MC_IDX)];

    size_t mem_line = m_sp_sch_id * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oid;
    return m_device->m_ll_device->write_memory(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->uc_mc_wfq_cfg)[m_ifg_id], mem_line, uc_mc_wfq_cfg);
}

la_status
la_system_port_scheduler_impl::get_priority_group_credit_cir(priority_group_e pg, la_rate_t& out_rate) const
{
    start_api_getter_call("pg=", pg);

    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    sch_oqpg_cir_token_bucket_cfg_memory token_bucket_cfg;
    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + (size_t)pg;
    la_status status = m_device->m_ll_device->read_memory(m_sch_oqpg_cir_token_bucket_cfg, mem_line, token_bucket_cfg);
    return_on_error(status);

    // If max_bucket_value is set to UNLIMITED it means that this shaper is disabled
    if (token_bucket_cfg.fields.oqpg_cir_max_bucket_value == tm_utils::UNLIMITED_BUCKET_SIZE) {
        out_rate = LA_RATE_UNLIMITED;
        return LA_STATUS_SUCCESS;
    }

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.oqpg_cir_rate_exponent,
                                                          token_bucket_cfg.fields.oqpg_cir_rate_mantissa);

    la_rate_t tpse_cir = 0;
    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_cir(tpse_cir);
    return_on_error(status);

    out_rate = ratio * tpse_cir;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_priority_group_credit_cir(priority_group_e pg, la_rate_t rate)
{
    start_api_call("pg=", pg, "rate=", rate);
    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + (size_t)pg;

    la_rate_t tpse_cir = 0;
    la_status status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_cir(tpse_cir);
    return_on_error(status);

    size_t cached_credit_oqpg_cir_burst_size = m_requested_credit_oqpg_cir_burst_size[size_t(pg)];
    status = tm_utils::set_oqcs_rate(m_device,
                                     m_sch_oqpg_cir_token_bucket_cfg,
                                     m_sch_oqpg_cir_token_bucket,
                                     mem_line,
                                     rate,
                                     m_port_speed,
                                     tpse_cir,
                                     cached_credit_oqpg_cir_burst_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_priority_group_credit_burst_size(priority_group_e pg, size_t& out_burst) const
{
    start_api_getter_call("pg=", pg);

    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + (size_t)pg;
    sch_oqpg_cir_token_bucket_cfg_memory token_bucket;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_oqpg_cir_token_bucket_cfg, mem_line, token_bucket);
    return_on_error(stat);

    out_burst = token_bucket.fields.oqpg_cir_max_bucket_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_priority_group_credit_burst_size(priority_group_e pg, size_t burst)
{
    start_api_call("pg=", pg, "burst=", burst);

    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    return do_set_priority_group_credit_burst_size((size_t)pg, burst);
}

la_status
la_system_port_scheduler_impl::do_set_priority_group_credit_burst_size(size_t pg, size_t burst)
{
    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + pg;
    la_status status
        = tm_utils::set_burst_size(m_device, m_sch_oqpg_cir_token_bucket_cfg, m_sch_oqpg_cir_token_bucket, mem_line, burst);
    return_on_error(status);

    if (burst != tm_utils::UNLIMITED_BUCKET_SIZE) {
        m_requested_credit_oqpg_cir_burst_size[pg] = burst;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_priority_group_transmit_cir(priority_group_e pg, la_rate_t& out_rate) const
{
    start_api_getter_call("pg=", pg);

    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    pdoq_oqpg_cir_token_bucket_cfg_memory token_bucket_cfg;
    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + (size_t)pg;
    la_status status = m_device->m_ll_device->read_memory(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oqpg_cir_token_bucket_cfg)[m_ifg_id], mem_line, token_bucket_cfg);
    return_on_error(status);

    // If max_bucket_value is set to UNLIMITED it means that this shaper is disabled
    if (token_bucket_cfg.fields.oqpg_cir_max_bucket_value == tm_utils::UNLIMITED_BUCKET_SIZE) {
        out_rate = LA_RATE_UNLIMITED;
        return LA_STATUS_SUCCESS;
    }

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.oqpg_cir_rate_exponent,
                                                          token_bucket_cfg.fields.oqpg_cir_rate_mantissa);

    la_rate_t ifg_rate = 0;
    status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_transmit_cir(ifg_rate);
    return_on_error(status);

    out_rate = ratio * ifg_rate;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_priority_group_transmit_cir(priority_group_e pg, la_rate_t rate)
{
    start_api_call("pg=", pg, "rate=", rate);
    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + (size_t)pg;
    lld_memory_scptr cfg_mem = (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oqpg_cir_token_bucket_cfg)[m_ifg_id];
    lld_memory_scptr dynamic_mem = (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oqpg_cir_token_bucket)[m_ifg_id];

    la_rate_t ifg_rate = 0;
    la_status status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_transmit_cir(ifg_rate);
    return_on_error(status);

    size_t cached_transmit_oqpg_cir_burst_size = m_requested_transmit_oqpg_cir_burst_size[size_t(pg)];
    status = tm_utils::set_oqcs_rate(
        m_device, cfg_mem, dynamic_mem, mem_line, rate, m_port_speed, ifg_rate, cached_transmit_oqpg_cir_burst_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_priority_group_transmit_burst_size(priority_group_e pg, size_t& out_burst) const
{
    start_api_getter_call("pg=", pg);

    pdoq_oqpg_cir_token_bucket_cfg_memory token_bucket_cfg;
    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + (size_t)pg;
    la_status stat = m_device->m_ll_device->read_memory(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->oqpg_cir_token_bucket_cfg)[m_ifg_id], mem_line, token_bucket_cfg);
    return_on_error(stat);

    out_burst = token_bucket_cfg.fields.oqpg_cir_max_bucket_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_priority_group_transmit_burst_size(priority_group_e pg, size_t burst)
{
    start_api_call("pg=", pg, "burst=", burst);
    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    return do_set_priority_group_transmit_burst_size((size_t)pg, burst);
}

la_status
la_system_port_scheduler_impl::do_set_priority_group_transmit_burst_size(size_t pg, size_t burst)
{
    size_t mem_line = m_sp_sch_id * (size_t)priority_group_e::NONE + pg;
    const auto& pdoq_top = m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top;
    la_status status = tm_utils::set_burst_size(
        m_device, (*pdoq_top->oqpg_cir_token_bucket_cfg)[m_ifg_id], (*pdoq_top->oqpg_cir_token_bucket)[m_ifg_id], mem_line, burst);
    return_on_error(status);

    if (burst != tm_utils::UNLIMITED_BUCKET_SIZE) {
        m_requested_transmit_oqpg_cir_burst_size[pg] = burst;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_priority_group_eir_weight(priority_group_e pg, la_wfq_weight_t& out_weight) const
{
    start_api_getter_call("pg=", pg);

    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    out_weight = m_pg_weights[size_t(pg)];
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_priority_group_eir_actual_weight(priority_group_e pg, la_wfq_weight_t& out_weight) const
{
    start_api_getter_call("pg=", pg);

    if (pg >= priority_group_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    // Credit scheduler
    bit_vector bv_rates;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_tpse_wfq_cfg, m_sp_sch_id, bv_rates);
    return_on_error(stat);

    size_t lsb = (size_t)pg * tm_utils::TM_WFQ_WEIGHT_WIDTH;
    size_t msb = lsb + tm_utils::TM_WFQ_WEIGHT_WIDTH - 1;
    out_weight = bit_utils::get_bits(bv_rates.get_value(), msb, lsb);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::set_priority_group_eir_weight(priority_group_e pg, la_wfq_weight_t weight)
{
    start_api_call("pg=", pg, "weight=", weight);
    // Set 6 bits from pg*6 to :
    // In TpseWfqCfg memory at port's line set the weight of the PG.
    // Each priority group has 6 bits
    // Write the line to the memory in the block_id

    if ((pg >= priority_group_e::NONE) || (weight == 0)) {
        return LA_STATUS_EINVAL;
    }

    m_pg_weights[size_t(pg)] = weight;
    std::vector<la_rate_t> rates = tm_utils::convert_weight_2_rate_vector(m_pg_weights, tm_utils::TM_WFQ_WEIGHT_WIDTH);

    bit_vector bv_rates;
    for (size_t i = 0; i < size_t(priority_group_e::NONE); i++) {
        size_t lsb = i * tm_utils::TM_WFQ_WEIGHT_WIDTH;
        size_t msb = lsb + tm_utils::TM_WFQ_WEIGHT_WIDTH - 1;
        bv_rates.set_bits(msb, lsb, rates[i]);
    }

    // Credit scheduler
    la_status stat = m_device->m_ll_device->write_memory(*m_sch_tpse_wfq_cfg, m_sp_sch_id, bv_rates);
    return_on_error(stat);

    // Transmit scheduler
    stat = m_device->m_ll_device->write_memory(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_wfq_cfg)[m_ifg_id], m_sp_sch_id, bv_rates);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::update_port_speed(la_mac_port::port_speed_e mac_port_speed)
{
    m_port_speed = (la_2_port_speed(mac_port_speed)) * UNITS_IN_GIGA;

    // Disable shaper if port speed is less than the configured shaper rate;
    for (size_t oid = 0; oid < OQ_COUNT; oid++) {
        la_rate_t rate;

        // Credit Pir
        la_status status = get_credit_pir(oid, rate);
        return_on_error(status);
        if (rate > m_port_speed) {
            status = do_set_credit_pir_burst_size(oid, tm_utils::UNLIMITED_BUCKET_SIZE);
            return_on_error(status);
        }

        // Transmit Pir
        status = get_transmit_pir(oid, rate);
        return_on_error(status);
        if (rate > m_port_speed) {
            status = do_set_transmit_pir_burst_size(oid, tm_utils::UNLIMITED_BUCKET_SIZE);
            return_on_error(status);
        }

        // Priority group Credit Cir
        status = get_priority_group_credit_cir((priority_group_e)oid, rate);
        return_on_error(status);
        if (rate > m_port_speed) {
            status = do_set_priority_group_credit_burst_size(oid, tm_utils::UNLIMITED_BUCKET_SIZE);
            return_on_error(status);
        }

        // Priority group Transmit Cir
        status = get_priority_group_transmit_cir((priority_group_e)oid, rate);
        return_on_error(status);
        if (rate > m_port_speed) {
            status = do_set_priority_group_transmit_burst_size(oid, tm_utils::UNLIMITED_BUCKET_SIZE);
            return_on_error(status);
        }
    }

    const auto& eir_oqse = m_oq_sch_vec[0];
    const auto& cir_oqse = m_oq_sch_vec[1];
    la_status status = m_lp_sch->update_port_speed(mac_port_speed, eir_oqse, cir_oqse);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_output_queue_scheduler(la_oq_id_t oid, la_output_queue_scheduler*& out_oq_sch) const
{
    start_api_getter_call("oid=", oid);

    if (oid >= OQ_COUNT) {
        return LA_STATUS_EINVAL;
    }

    out_oq_sch = m_oq_sch_vec[oid].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_scheduler_impl::get_logical_port_scheduler(la_logical_port_scheduler*& out_lp_sch) const
{
    start_api_getter_call("");

    // Check logical port is enabled
    // Get field TpseMapLogicalPort[m_sp_sch_id] of register TpseGeneralConfiguration
    bit_vector bv;
    la_status ret = m_device->m_ll_device->read_register(*m_sch_tpse_general_configuration, bv);
    return_on_error(ret);

    bool enabled = bv.bit(m_sp_sch_id + TPSE_MAP_LOGICAL_PORT_BASE);
    if (!enabled) {
        return LA_STATUS_EINVAL;
    }

    out_lp_sch = m_lp_sch.get();

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_system_port_scheduler_impl::type() const
{
    return object_type_e::SYSTEM_PORT_SCHEDULER;
}

std::string
la_system_port_scheduler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_system_port_scheduler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_system_port_scheduler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_system_port_scheduler_impl::get_device() const
{
    return m_device.get();
}

} // namespace silicon_one
