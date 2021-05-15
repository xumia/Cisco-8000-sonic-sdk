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

#include "common/math_utils.h"
#include "hld_utils.h"
#include "la_ifg_scheduler_impl.h"
#include "la_output_queue_scheduler_impl.h"

#include "la_system_port_scheduler_impl.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
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

enum {
    TXPDR_PORT = tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS, ///< TXPDR index in all relevant port register and memory arrays
    TXPDR_PORT_LP_OQ = 0,                                 ///< TXPDR Low-priority output queue index in various OQs arrays
    TXPDR_PORT_HP_OQ = 1,                                 ///< TXPDR High-priority output queue index in various OQs arrays
    DEFAULT_MAX_CREDIT_BUCKET_SIZE = tm_utils::MAX_CREDIT_BUCKET_SIZE, ///< SCH default max bucket size value for initialization.

    PDIF_FIFO_LINE_PER_PIF_NETWORK = 31,
    PDIF_FIFO_LINE_PER_PIF_FABRIC = 32,
    PDIF_FIFO_LINE_PER_DELETE = 180,

    TRANSMIT_SHAPER_MAX_RATE = 128,
    SA_SLOW_RATE_REG_VAL = 4000, ///< For SA mode, this is the validated value corresponding to IFG slow rate of 2.5G.
                                 ///< Explicitly not frequency-dependent, per design team request.
    LC_SLOW_RATE_REG_VAL = 6000, ///< For LC mode

    DEFAULT_IFG_BUCKET_SIZE = 1,            ///< Bucket size default value.
    DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR = 1, ///< Number of tokens to be given by shaper every cycle

    PACIFIC_B0_ENABLE_SLOW_RATE_BUG_FIX = 1,
    PACIFIC_B0_SLOW_RATE_RECYCLE_THRESHOLD = 800,
};

enum {
    TPSE_2_IFC_MAP_LSB = 24,         ///< Tpse2IfcMap field offset in IfseGeneralConfiguration register
    TPSE_2_IFC_MAP_SINGLE_WIDTH = 5, ///< Single port width in Tpse2IfcMap field in IfseGeneralConfiguration register
    FDOQ_IFG_CALENDAR_INVALID = 26,  ///< Marks the IFG FDOQ calendar slot as invalid.
};

const std::map<la_mac_port::port_speed_e, la_uint_t> la_ifg_scheduler_impl::s_pdif_fifo_threshold_profile_id
    // TODO-GB - when E_1200G is supported, it should use profile 0
    = {{la_mac_port::port_speed_e::E_10G, 6},
       {la_mac_port::port_speed_e::E_25G, 6},
       {la_mac_port::port_speed_e::E_40G, 6},
       {la_mac_port::port_speed_e::E_50G, 5},
       {la_mac_port::port_speed_e::E_100G, 4},
       {la_mac_port::port_speed_e::E_200G, 3},
       {la_mac_port::port_speed_e::E_400G, 2},
       {la_mac_port::port_speed_e::E_800G, 1}};

la_uint_t fdoq_ifg_calendar[]
    = {0, 8, 16, 4, 12, 20, 24, 2, 10, 18, 6, 14, 22, 25, 1, 9, 17, 5, 13, 21, 24, 3, 11, 19, 7, 15, 23, 25};

la_ifg_scheduler_impl::la_ifg_scheduler_impl(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : m_device(device), m_slice_id(slice_id), m_ifg_id(ifg_id), m_max_transmit_rate(-1), m_max_rx_shaper_burst(-1)
{
    initialize_sch_references(m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch);
}

la_ifg_scheduler_impl::~la_ifg_scheduler_impl()
{
}

la_status
la_ifg_scheduler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    auto status = initialize_lld_memories();
    return_on_error(status);

    status = initialize_fdoq_calendar();
    return_on_error(status);

    status = initialize_pdif_fifo();
    return_on_error(status);

    status = initialize_general_credit_shapers();
    return_on_error(status);

    status = initialize_general_transmit_shapers();
    return_on_error(status);

    status = initialize_oqcs();
    return_on_error(status);

    status = read_max_transmit_rate();
    return_on_error(status);

    status = read_max_rx_shaper_burst();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_scheduler_shapers_and_ifg_total_rate()
{
    // TODO GB - this function is not needed for GB
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::read_max_transmit_rate()
{
    gibraltar::pdoq_ifse_general_configuration_register ifse_general_cfg_reg;
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    m_max_transmit_rate = ifse_general_cfg_reg.fields.ifg_credit_generator_rate;

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::read_max_rx_shaper_burst()
{
    gibraltar::ifgb_24p_rx_shaper_cfg_register rx_shaper_reg;
    la_status status = m_device->m_ll_device->read_register(
        m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg, rx_shaper_reg);
    return_on_error(status);

    m_max_rx_shaper_burst = rx_shaper_reg.fields.rx_shaper_burst;

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_oqcs()
{
    // TODO: re-think about interface scheduler - required to configure CIR and PIR which are relative to interface configuration.
    la_output_queue_scheduler_impl_sptr txpdr_hp;
    auto status = m_device->do_create_output_queue_scheduler(
        m_slice_id,
        m_ifg_id,
        index_handle(TXPDR_PORT * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + TXPDR_PORT_HP_OQ),
        la_output_queue_scheduler::scheduling_mode_e::DIRECT_4SP,
        txpdr_hp);
    return_on_error(status);

    la_output_queue_scheduler_impl_sptr txpdr_lp;
    status = m_device->do_create_output_queue_scheduler(
        m_slice_id,
        m_ifg_id,
        index_handle(TXPDR_PORT * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + TXPDR_PORT_LP_OQ),
        la_output_queue_scheduler::scheduling_mode_e::DIRECT_4SP,
        txpdr_lp);
    return_on_error(status);

    m_txpdr_hp = txpdr_hp;
    m_txpdr_lp = txpdr_lp;

    m_device->add_object_dependency(m_txpdr_hp, this);
    m_device->add_object_dependency(m_txpdr_lp, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::destroy()
{
    m_device->remove_object_dependency(m_txpdr_hp, this);
    m_device->remove_object_dependency(m_txpdr_lp, this);
    m_device->do_destroy(m_txpdr_hp);
    m_device->do_destroy(m_txpdr_lp);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_interface(size_t pif_base, size_t pif_count)
{
    la_status status = set_tpse_to_interface_map(pif_base, pif_count);
    return_on_error(status);

    status = configure_fdoq_calendar(pif_base, pif_count);
    return_on_error(status);

    if (pif_base < MAX_NUM_PIF_PER_IFG) {
        status = allocate_pdif_fifo(pif_base, pif_count, false /*is_fabric*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_fabric_interface(size_t pif_base, size_t pif_count)
{
    la_status status = configure_fdoq_calendar(pif_base, pif_count);
    return_on_error(status);

    if (pif_base < MAX_NUM_PIF_PER_IFG) {
        status = allocate_pdif_fifo(pif_base, pif_count, true /*is_fabric*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_lld_memories()
{
    log_debug(HLD, "la_ifg_scheduler_impl::initialize_lld_memories()");

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_fdoq_calendar()
{
    for (size_t i = 0; i < array_size(fdoq_ifg_calendar); i++) {
        la_status status = m_device->m_ll_device->write_memory(
            (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->fdoq_ifg_calendar)[m_ifg_id], i, FDOQ_IFG_CALENDAR_INVALID);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::configure_fdoq_calendar(size_t pif_base, size_t pif_count)
{
    for (size_t i = 0; i < array_size(fdoq_ifg_calendar); i++) {
        if ((pif_base <= fdoq_ifg_calendar[i]) && ((pif_base + pif_count) > fdoq_ifg_calendar[i])) {
            la_status status = m_device->m_ll_device->write_memory(
                (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->fdoq_ifg_calendar)[m_ifg_id], i, pif_base);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::reset_fdoq_calendar(size_t pif_base, size_t pif_count)
{
    for (size_t i = 0; i < array_size(fdoq_ifg_calendar); i++) {
        if ((pif_base <= fdoq_ifg_calendar[i]) && ((pif_base + pif_count) > fdoq_ifg_calendar[i])) {
            la_status status = m_device->m_ll_device->write_memory(
                (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->fdoq_ifg_calendar)[m_ifg_id], i, FDOQ_IFG_CALENDAR_INVALID);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_pdif_fifo()
{
    la_status status;
    // TODO GB - This whole func should come from Init, so it is redundant in GB.
    //
    //    size_t start_fifo_line = m_ifg_id * (tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + 2) * PDIF_FIFO_LINE_PER_SERDES;
    //    for (la_uint_t port = 0; port < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; port++) {
    //        size_t mem_line = m_ifg_id * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + port;
    //        size_t fifo_lines = port < NUM_SERDES_PER_IFG ? PDIF_FIFO_LINE_PER_SERDES : 2 * PDIF_FIFO_LINE_PER_SERDES;
    //        la_uint_t profile_id = port < NUM_SERDES_PER_IFG
    //                                   ? s_pdif_fifo_threshold_profile_id[(size_t)la_mac_port::port_speed_e::E_10G]
    //                                   : s_pdif_fifo_threshold_profile_id[(size_t)la_mac_port::port_speed_e::E_100G];
    //        status = m_device->m_ll_device->write_memory(
    //            m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size, mem_line, fifo_lines);
    //        return_on_error(status);
    //
    //        status = m_device->m_ll_device->write_memory(
    //            m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size_start_addr, mem_line, start_fifo_line);
    //        return_on_error(status);
    //
    //        status = m_device->m_ll_device->write_memory(
    //            m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pd_if_fifos_thresholds_profile, mem_line, profile_id);
    //        return_on_error(status);
    //
    //        start_fifo_line += fifo_lines;
    //    }
    //
    //    status = m_device->m_ll_device->write_memory(
    //        m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size, 40 /* delete port */,
    //        PDIF_FIFO_LINE_PER_DELETE);
    //    return_on_error(status);
    //
    //    status = m_device->m_ll_device->write_memory(
    //        m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size_start_addr, 40 /* delete port */, 1100);
    //    return_on_error(status);
    //
    //    status
    //        =
    //        m_device->m_ll_device->write_memory(m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pd_if_fifos_thresholds_profile,
    //                                              40 /* delete port */,
    //                                              s_pdif_fifo_threshold_profile_id[(size_t)la_mac_port::port_speed_e::E_800G]);
    //    return_on_error(status);
    //
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::allocate_pdif_fifo(size_t pif_base, size_t pif_count, bool is_fabric)
{
    size_t mem_line = m_ifg_id * tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS + pif_base;
    size_t fifo_lines = pif_count * (is_fabric ? PDIF_FIFO_LINE_PER_PIF_FABRIC : PDIF_FIFO_LINE_PER_PIF_NETWORK);

    la_status status = m_device->m_ll_device->write_memory(
        m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size, mem_line, fifo_lines);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::reset_pdif_fifo(size_t pif_base, size_t pif_count)
{

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_credit_rate(la_rate_t& out_rate) const
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_credit_rate(la_rate_t rate)
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::do_set_credit_rate(la_uint32_t device_rate)
{
    // TODO GB - this function is not needed for GB
    //  sch_ifse_general_configuration_register ifse_general_cfg_reg;
    //
    //  la_status status = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    //  return_on_error(status);
    //
    //  ifse_general_cfg_reg.fields.ifg_credit_generator_rate = device_rate;
    //
    //  status = m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    //  return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_transmit_rate(la_rate_t& out_rate) const
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_transmit_rate(la_rate_t rate)
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_credit_burst_size(size_t& out_burst) const
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_credit_burst_size(size_t burst)
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::do_set_credit_burst_size(size_t burst)
{
    // TODO GB - this function is not needed for GB
    //  sch_ifse_general_configuration_register ifse_general_cfg_reg;
    //
    //  la_status stat = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    //  return_on_error(stat);
    //
    //  // Set field IfgCreditGeneratorMaxBucket of register IfseGeneralConfiguration[m_ifg_id]
    //  ifse_general_cfg_reg.fields.ifg_credit_generator_max_bucket = burst;
    //
    //  return m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_transmit_burst_size(size_t& out_burst) const
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_transmit_burst_size(size_t burst)
{
    // TODO - this function should be deprecated as API.
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::do_set_transmit_burst_size(size_t burst)
{
    gibraltar::pdoq_ifse_general_configuration_register ifse_general_cfg_reg;
    // TODO GB - this function is not needed for GB - should come from init

    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(stat);

    // Set field IfgCreditGeneratorMaxBucket of register IfseGeneralConfiguration[m_ifg_id]
    ifse_general_cfg_reg.fields.ifg_credit_generator_max_bucket = burst;

    return m_device->m_ll_device->write_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
}

la_status
la_ifg_scheduler_impl::do_set_transmit_rate(la_uint32_t device_rate)
{
    // TODO GB - this function is not needed for GB
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_max_transmit_rate_utilization(la_float_t max_rate_percent)
{
    start_api_call("max_rate_percent=", max_rate_percent);
    if ((max_rate_percent < 0) || (max_rate_percent > 1)) {
        return LA_STATUS_EINVAL;
    }

    if (m_max_transmit_rate == (la_uint32_t)-1) {
        log_err(HLD, "m_max_transmit_rate was not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    gibraltar::pdoq_ifse_general_configuration_register ifse_general_cfg_reg;
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    if (max_rate_percent == 0) {
        ifse_general_cfg_reg.fields.ifg_credit_generator_rate = 0;
    } else {
        ifse_general_cfg_reg.fields.ifg_credit_generator_rate = m_max_transmit_rate / max_rate_percent;
    }

    status = m_device->m_ll_device->write_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
    ;
}

la_status
la_ifg_scheduler_impl::get_max_transmit_rate_utilization(la_float_t& out_max_rate_percent) const
{
    start_api_getter_call();
    if (m_max_transmit_rate == (la_uint32_t)-1) {
        log_err(HLD, "m_max_transmit_rate was not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    gibraltar::pdoq_ifse_general_configuration_register ifse_general_cfg_reg;
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    if (ifse_general_cfg_reg.fields.ifg_credit_generator_rate == 0) {
        out_max_rate_percent = 0;
    } else {
        out_max_rate_percent = (la_float_t)m_max_transmit_rate / (la_float_t)ifse_general_cfg_reg.fields.ifg_credit_generator_rate;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_max_rx_rate_utilization(la_float_t max_rate_percent)
{
    start_api_call("max_rate_percent=", max_rate_percent);
    if ((max_rate_percent < 0) || (max_rate_percent > 1)) {
        return LA_STATUS_EINVAL;
    }

    if (m_max_rx_shaper_burst == (la_uint64_t)-1) {
        log_err(HLD, "m_max_rx_shaper_burst was not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    gibraltar::ifgb_24p_rx_shaper_cfg_register rx_shaper_reg;
    la_status status = m_device->m_ll_device->read_register(
        m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg, rx_shaper_reg);
    return_on_error(status);

    rx_shaper_reg.fields.rx_shaper_burst = max_rate_percent * m_max_rx_shaper_burst;

    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg,
                                                   rx_shaper_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_max_rx_rate_utilization(la_float_t& out_max_rate_percent) const
{
    start_api_getter_call();
    if (m_max_rx_shaper_burst == (la_uint64_t)-1) {
        log_err(HLD, "m_max_rx_shaper_burst was not initialized");
        return LA_STATUS_EUNKNOWN;
    }

    gibraltar::ifgb_24p_rx_shaper_cfg_register rx_shaper_reg;
    la_status status = m_device->m_ll_device->read_register(
        m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg, rx_shaper_reg);
    return_on_error(status);

    out_max_rate_percent = (la_float_t)rx_shaper_reg.fields.rx_shaper_burst / (la_float_t)m_max_rx_shaper_burst;

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_slow_rate()
{
    // TODO - this function is not needed for GB
    //
    //  // 8*CoreClockRate*1024*10^9 / R
    //  sch_slow_rate_configuration_register slow_rate_reg;
    //
    //  slow_rate_reg.fields.slow_rate_enable = 1;
    //  if (m_device->m_device_mode == device_mode_e::STANDALONE) {
    //      slow_rate_reg.fields.slow_rate = SA_SLOW_RATE_REG_VAL;
    //  } else {
    //      // LC (maybe FE also)
    //      slow_rate_reg.fields.slow_rate = LC_SLOW_RATE_REG_VAL;
    //  }
    //
    //  return m_device->m_ll_device->write_register(*m_sch_slow_rate_configuration, slow_rate_reg);
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_txpdr_cir(la_rate_t& out_rate) const
{
    // get IfseCirShaperRateConfiguration[TXPDR_PORT] register
    bit_vector tmp_bv;
    la_status status = m_device->m_ll_device->read_register((*m_sch_ifse_cir_shaper_rate_configuration)[TXPDR_PORT], tmp_bv);
    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    out_rate = tm_utils::convert_rate_from_device_val(
        tmp_bv.get_value(), credits_conf_reg.fields.crdt_in_bytes, m_device->m_device_frequency_int_khz);
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_txpdr_cir(la_rate_t rate)
{
    start_api_call("rate=", rate);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    la_status status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(
        rate, credits_conf_reg.fields.crdt_in_bytes, m_device->m_device_frequency_int_khz, rate_to_device);

    return_on_error(status);

    // set IfseCirShaperRateConfiguration[TXPDR_PORT] register
    return m_device->m_ll_device->write_register((*m_sch_ifse_cir_shaper_rate_configuration)[TXPDR_PORT], rate_to_device);
}

la_status
la_ifg_scheduler_impl::get_txpdr_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const
{

    // get IfsePirShaperConfiguration[TXPDR_PORT] register
    bit_vector tmp_bv;
    la_status status = m_device->m_ll_device->read_register((*m_sch_ifse_pir_shaper_configuration)[TXPDR_PORT], tmp_bv);
    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    out_rate = tm_utils::convert_rate_from_device_val(
        tmp_bv.get_value(), credits_conf_reg.fields.crdt_in_bytes, m_device->m_device_frequency_int_khz);

    // Get field IfseEirShaperMode[TXPDR_PORT] of register IfseGeneralConfiguration
    gibraltar::sch_ifse_general_configuration_register cfg_reg;
    status = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, cfg_reg);
    return_on_error(status);

    out_is_eir = cfg_reg.fields.get_ifse_eir_shaper_mode(TXPDR_PORT);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_txpdr_eir_or_pir(la_rate_t rate, bool is_eir)
{
    start_api_call("rate=", rate, "is_eir=", is_eir);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    la_status status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(
        rate, credits_conf_reg.fields.crdt_in_bytes, m_device->m_device_frequency_int_khz, rate_to_device);

    return_on_error(status);

    // set IfsePirShaperConfiguration[TXPDR_PORT] register
    la_status stat = m_device->m_ll_device->write_register((*m_sch_ifse_pir_shaper_configuration)[TXPDR_PORT], rate_to_device);

    return_on_error(stat);

    // Set field IfseEirShaperMode[TXPDR_PORT] of register IfseGeneralConfiguration
    gibraltar::sch_ifse_general_configuration_register cfg_reg;
    stat = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, cfg_reg);
    return_on_error(stat);

    cfg_reg.fields.set_ifse_eir_shaper_mode(TXPDR_PORT, is_eir);

    stat = m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, cfg_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_txpdr_cir_weight(la_wfq_weight_t& out_weight) const
{
    // get IfseWfqCirWeights[TXPDR_PORT] register
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register((*m_sch_ifse_wfq_cir_weights)[TXPDR_PORT], tmp_bv);
    return_on_error(stat);
    out_weight = tmp_bv.get_value();
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_txpdr_cir_weight(la_wfq_weight_t weight)
{
    start_api_call("weight=", weight);
    // set IfseWfqCirWeights[TXPDR_PORT] register
    return m_device->m_ll_device->write_register((*m_sch_ifse_wfq_cir_weights)[TXPDR_PORT], weight);
}

la_status
la_ifg_scheduler_impl::get_txpdr_eir_weight(la_wfq_weight_t& out_weight) const
{
    // get IfseWfqEirWeights[TXPDR_PORT] register
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register((*m_sch_ifse_wfq_eir_weights)[TXPDR_PORT], tmp_bv);
    return_on_error(stat);
    out_weight = tmp_bv.get_value();
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_txpdr_eir_weight(la_wfq_weight_t weight)
{
    start_api_call("weight=", weight);
    // set IfseWfqEirWeights[TXPDR_PORT] register
    return m_device->m_ll_device->write_register((*m_sch_ifse_wfq_eir_weights)[TXPDR_PORT], weight);
}

la_status
la_ifg_scheduler_impl::get_txpdr_hp_oqcs(la_output_queue_scheduler*& out_oq_sch) const
{
    out_oq_sch = m_txpdr_hp.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_txpdr_lp_oqcs(la_output_queue_scheduler*& out_oq_sch) const
{
    out_oq_sch = m_txpdr_lp.get();
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_ifg_scheduler_impl::type() const
{
    return object_type_e::IFG_SCHEDULER;
}

std::string
la_ifg_scheduler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ifg_scheduler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ifg_scheduler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_ifg_scheduler_impl::get_device() const
{
    return m_device.get();
}

/// @brief Get credit scheduler's cir rate.
la_status
la_ifg_scheduler_impl::get_cir(la_rate_t& out_rate)
{
    gibraltar::sch_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get cir shaper rate
    la_status status = m_device->m_ll_device->read_register(*m_sch_tpse_shaper_configuration, tpse_shaper_cfg_reg);

    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    out_rate = tm_utils::convert_rate_from_device_val(tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate,
                                                      tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value,
                                                      credits_conf_reg.fields.crdt_in_bytes,
                                                      m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

/// @brief Get credit scheduler's eir rate.
la_status
la_ifg_scheduler_impl::get_eir(la_rate_t& out_rate)
{
    gibraltar::sch_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get cir shaper rate
    la_status status = m_device->m_ll_device->read_register(*m_sch_tpse_shaper_configuration, tpse_shaper_cfg_reg);

    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    out_rate = tm_utils::convert_rate_from_device_val(tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate,
                                                      tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value,
                                                      credits_conf_reg.fields.crdt_in_bytes,
                                                      m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

/// @brief Get transmit scheduler's cir rate.
la_status
la_ifg_scheduler_impl::get_transmit_cir(la_rate_t& out_rate)
{
    gibraltar::pdoq_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get cir shaper rate
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->tpse_shaper_configuration)[m_ifg_id], tpse_shaper_cfg_reg);

    return_on_error(status);

    gibraltar::pdoq_pdoq_credit_value_register pdoq_pdoq_credit_value;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value,
                                                  pdoq_pdoq_credit_value);
    return_on_error(status);

    out_rate = tm_utils::convert_rate_from_device_val(tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate,
                                                      tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value,
                                                      pdoq_pdoq_credit_value.fields.credit_value,
                                                      m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

/// @brief Get transmit scheduler's pir rate.
la_status
la_ifg_scheduler_impl::get_transmit_pir(la_rate_t& out_rate)
{
    gibraltar::pdoq_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get pir shaper rate
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->tpse_shaper_configuration)[m_ifg_id], tpse_shaper_cfg_reg);
    return_on_error(status);

    gibraltar::pdoq_pdoq_credit_value_register pdoq_pdoq_credit_value;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value,
                                                  pdoq_pdoq_credit_value);
    return_on_error(status);

    out_rate = tm_utils::convert_rate_from_device_val(tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate,
                                                      tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value,
                                                      pdoq_pdoq_credit_value.fields.credit_value,
                                                      m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_general_credit_shapers()
{
    // TODO - this function is not needed for GB

    //  la_status status = initialize_slow_rate();
    //  return_on_error(status);
    //
    //  status = initialize_credit_tpse_shaper(CREDIT_SCH_STATIC_RATE);
    //  return_on_error(status);
    //
    //  status = initialize_oqse_shaper(CREDIT_SCH_STATIC_RATE);
    //  return_on_error(status);
    //
    //  status = initialize_lpse_shaper(CREDIT_SCH_STATIC_RATE);
    //  return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_credit_tpse_shaper(uint32_t device_rate)
{
    // TODO - this function is not needed for GB

    //  sch_tpse_shaper_configuration_register tpse_shaper_cfg_reg;
    //  bzero(&tpse_shaper_cfg_reg, sch_tpse_shaper_configuration_register::SIZE);
    //
    //  tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate = device_rate;
    //  tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    //  tpse_shaper_cfg_reg.fields.tpse_cir_shaper_max_bucket = 8;
    //  tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate = device_rate;
    //  tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    //  tpse_shaper_cfg_reg.fields.tpse_pir_shaper_max_bucket = 8;
    //
    //  // set cir shaper rate
    //  la_status stat = m_device->m_ll_device->write_register(
    //      *m_sch_tpse_shaper_configuration, sch_tpse_shaper_configuration_register::SIZE, &tpse_shaper_cfg_reg);
    //
    //  return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_oqse_shaper(uint32_t& out_device_rate)
{
    gibraltar::sch_oqse_shaper_configuration_register oqse_shaper_cfg_reg;

    // get cir shaper rate
    la_status stat = m_device->m_ll_device->read_register(*m_sch_oqse_shaper_configuration, oqse_shaper_cfg_reg);
    return_on_error(stat);

    out_device_rate = oqse_shaper_cfg_reg.fields.oqse_shaper_rate;

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_tpse_to_interface_map(la_uint_t intf_id, la_uint_t intf_count)
{
    gibraltar::pdoq_ifse_general_configuration_register pdoq_reg;
    gibraltar::sch_ifse_general_configuration_register sch_reg;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], pdoq_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, sch_reg);
    return_on_error(stat);

    pdoq_reg.fields.set_tpse2ifc_map(intf_id, intf_id);
    sch_reg.fields.set_tpse2ifc_map(intf_id, intf_id);

    const uint64_t INTF_ID_INVALID
        = bit_utils::ones(gibraltar::pdoq_ifse_general_configuration_register::fields::TPSE2IFC_MAP_WIDTH);
    for (la_uint_t i = 1; i < intf_count; i++) {
        pdoq_reg.fields.set_tpse2ifc_map(intf_id + i, INTF_ID_INVALID);
        sch_reg.fields.set_tpse2ifc_map(intf_id + i, INTF_ID_INVALID);
    }

    stat = m_device->m_ll_device->write_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], pdoq_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, sch_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_oqse_shaper(uint32_t device_rate)
{
    // TODO - this function is not needed for GB

    //  sch_oqse_shaper_configuration_register oqse_shaper_cfg_reg;
    //  bzero(&oqse_shaper_cfg_reg, sch_oqse_shaper_configuration_register::SIZE);
    //
    //  oqse_shaper_cfg_reg.fields.oqse_shaper_rate = device_rate;
    //  oqse_shaper_cfg_reg.fields.oqse_shaper_incr_value = 1;
    //  oqse_shaper_cfg_reg.fields.oqse_shaper_max_bucket = 8;
    //
    //  // get cir shaper rate
    //  la_status stat = m_device->m_ll_device->write_register(
    //      *m_sch_oqse_shaper_configuration, sch_oqse_shaper_configuration_register::SIZE, &oqse_shaper_cfg_reg);
    //
    //  return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_lpse_shaper(uint32_t device_rate)
{
    // TODO - this function is not needed for GB

    //  sch_lpse_shaper_configuration_register lpse_shaper_cfg_reg;
    //  bzero(&lpse_shaper_cfg_reg, sch_lpse_shaper_configuration_register::SIZE);
    //
    //  lpse_shaper_cfg_reg.fields.lpse_cir_shaper_rate = device_rate;
    //  lpse_shaper_cfg_reg.fields.lpse_cir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    //  lpse_shaper_cfg_reg.fields.lpse_cir_shaper_max_bucket = 8;
    //  lpse_shaper_cfg_reg.fields.lpse_eir_shaper_rate = device_rate;
    //  lpse_shaper_cfg_reg.fields.lpse_eir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    //  lpse_shaper_cfg_reg.fields.lpse_eir_shaper_max_bucket = 8;
    //
    //  // set cir shaper rate
    //  la_status stat = m_device->m_ll_device->write_register(
    //      *m_sch_lpse_shaper_configuration, sch_lpse_shaper_configuration_register::SIZE, &lpse_shaper_cfg_reg);
    //
    //  return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_general_transmit_shapers()
{
    //  la_status status = initialize_transmit_tpse_shaper(TRANSMIT_SHAPER_MAX_RATE);
    //  return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_transmit_tpse_shaper(uint32_t device_rate)
{
    // TODO - this function is not needed for GB

    gibraltar::pdoq_tpse_shaper_configuration_register tpse_shaper_cfg_reg{{0}};

    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate = device_rate;
    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value = 2;
    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_max_bucket = 8;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate = device_rate;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value = 2;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_max_bucket = 8;

    la_status stat = m_device->m_ll_device->write_register(
        (*m_device->m_gb_tree->slice[m_slice_id]->pdoq->top->tpse_shaper_configuration)[m_ifg_id], tpse_shaper_cfg_reg);

    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
