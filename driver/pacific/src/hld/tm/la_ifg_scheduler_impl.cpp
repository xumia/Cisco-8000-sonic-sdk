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
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
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

enum {
    TXPDR_PORT = tm_utils::IFG_SYSTEM_PORT_SCHEDULERS, ///< TXPDR index in all relevant port register and memory arrays
    TXPDR_PORT_HP_OQ = 0,                              ///< TXPDR High-priority output queue index in various OQs arrays
    TXPDR_PORT_LP_OQ = 1,                              ///< TXPDR Low-priority output queue index in various OQs arrays
    DEFAULT_MAX_CREDIT_BUCKET_SIZE = 20,               ///< SCH default max bucket size value for initialization.

    PDIF_FIFO_LINE_PER_NETWORK_PORT = 25,
    PDIF_FIFO_LINE_PER_CPU_PORT = 10,
    PDIF_FIFO_LINE_PER_RECYCLE_PORT = 30,
    PDIF_FIFO_LINE_PER_IFG
    = (NUM_PIF_PER_IFG * PDIF_FIFO_LINE_PER_NETWORK_PORT) + PDIF_FIFO_LINE_PER_CPU_PORT + PDIF_FIFO_LINE_PER_RECYCLE_PORT,
    PDIF_SLICE_DELETE_PORT_ID = 40,

    TRANSMIT_SCH_STATIC_RATE = tm_utils::TX_SCH_TOKEN_SIZE / 8, ///< Transmit value (in Bytes) / 8 clocks (1024B / 8)
    TRANSMIT_SHAPER_MAX_RATE = 128,
    SA_SLOW_RATE_REG_VAL = 4000, ///< For SA mode, this is the validated value corresponding to IFG slow rate of 2.5G.
                                 ///< Explicitly not frequency-dependent, per design team request.
    LC_SLOW_RATE_REG_VAL = 6000, ///< For LC mode

    DEFAULT_IFG_BUCKET_SIZE = 1,              ///< Bucket size default value.
    DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR = 1,   ///< Number of tokens to be given by credit shaper every cycle
    DEFAULT_TRANSMIT_SCH_NUM_TOKENS_INCR = 1, ///< Number of tokens to be given by transmit shaper every cycle

    PACIFIC_B0_ENABLE_SLOW_RATE_BUG_FIX = 1,
    PACIFIC_B0_SLOW_RATE_RECYCLE_THRESHOLD = 800,
};

enum {
    TPSE_2_IFC_MAP_LSB = 24,         ///< Tpse2IfcMap field offset in IfseGeneralConfiguration register
    TPSE_2_IFC_MAP_SINGLE_WIDTH = 5, ///< Single port width in Tpse2IfcMap field in IfseGeneralConfiguration register
    FDOQ_IFG_CALENDAR_INVALID = 20,  ///< Marks the IFG FDOQ calendar slot as invalid.
};

// 1200G = 900G (sum pf phys port rates) + 100G (host) + 100G (recycle) + 100G (mc)
// The TXPDR (MC) should be able to utilize the total 1000G IFG rate if no unicast traffic
const la_rate_t DEFAULT_TXPDR_CREDIT_RATE = 1000ULL * UNITS_IN_GIGA;

const std::map<la_mac_port::port_speed_e, la_uint_t> la_ifg_scheduler_impl::s_pdif_fifo_threshold_profile_id
    = {{la_mac_port::port_speed_e::E_10G, 6},
       {la_mac_port::port_speed_e::E_25G, 5},
       {la_mac_port::port_speed_e::E_40G, 4},
       {la_mac_port::port_speed_e::E_50G, 3},
       {la_mac_port::port_speed_e::E_100G, 2},
       {la_mac_port::port_speed_e::E_200G, 2},
       {la_mac_port::port_speed_e::E_400G, 1},
       {la_mac_port::port_speed_e::E_800G, 0}};

la_uint_t fdoq_ifg_calendar[] = {0, 8, 16, 4, 12, 2, 18, 10, 6, 14, 19, 1, 9, 17, 5, 13, 3, 18, 11, 7, 15, 19};

la_ifg_scheduler_impl::la_ifg_scheduler_impl(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : m_device(device), m_slice_id(slice_id), m_ifg_id(ifg_id)
{
    if (m_slice_id < FIRST_HW_FABRIC_SLICE) {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch);
    } else {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->fabric_sch);
    }
}

la_ifg_scheduler_impl::~la_ifg_scheduler_impl()
{
}

la_status
la_ifg_scheduler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    auto status = initialize_scheduler_shapers_and_ifg_total_rate();
    return_on_error(status);

    status = initialize_lld_memories();
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

    if (pif_base < NUM_PIF_PER_IFG) {
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

    if (pif_base < NUM_PIF_PER_IFG) {
        status = allocate_pdif_fifo(pif_base, pif_count, true /*is_fabric*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_scheduler_shapers_and_ifg_total_rate()
{
    log_debug(HLD, "la_ifg_scheduler_impl::initialize_scheduler_shapers_and_ifg_total_rate()");

    lld_register_value_list_t reg_val_list;
    bit_vector sch_spare_reg;
    la_status stat = m_device->m_ll_device->read_register(m_sch_spare_reg, sch_spare_reg);
    return_on_error(stat);

    reg_val_list.push_back({m_sch_soft_reset_configuration, 1});

    // Initialize shapers for all ports except the TXPDR
    for (la_uint_t port = 0; port < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; port++) {
        reg_val_list.push_back({(*m_sch_ifse_cir_shaper_max_bucket_configuration)[port], DEFAULT_MAX_CREDIT_BUCKET_SIZE});
        reg_val_list.push_back({(*m_sch_ifse_cir_shaper_rate_configuration)[port], 0});
        reg_val_list.push_back({(*m_sch_ifse_pir_shaper_max_bucket_configuration)[port], DEFAULT_MAX_CREDIT_BUCKET_SIZE});
        reg_val_list.push_back({(*m_sch_ifse_pir_shaper_configuration)[port], 0});
    }

    // Initialize shapers max bucket size for MC (TXPDR)
    reg_val_list.push_back(
        {(*m_sch_ifse_cir_shaper_max_bucket_configuration)[TXPDR_PORT], (uint64_t)DEFAULT_MAX_CREDIT_BUCKET_SIZE});
    reg_val_list.push_back(
        {(*m_sch_ifse_pir_shaper_max_bucket_configuration)[TXPDR_PORT], (uint64_t)DEFAULT_MAX_CREDIT_BUCKET_SIZE});

    la_device_revision_e revision = m_device->m_pacific_tree->get_revision();
    if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        // Enable slow rate bug fix
        sch_spare_reg.set_bit(0, !PACIFIC_B0_ENABLE_SLOW_RATE_BUG_FIX);        // Slow rate recycle disable - not enable
        sch_spare_reg.set_bit(1, PACIFIC_B0_ENABLE_SLOW_RATE_BUG_FIX);         // Slow rate recycle enable
        sch_spare_reg.set_bit(13, PACIFIC_B0_ENABLE_SLOW_RATE_BUG_FIX);        // Slow rate bug fix enable
        sch_spare_reg.set_bits(12, 2, PACIFIC_B0_SLOW_RATE_RECYCLE_THRESHOLD); // Threshold

        reg_val_list.push_back({m_sch_spare_reg, sch_spare_reg});
    }

    // Write all initialized regiters list so far
    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    // Initialize shapers rate for MC (TXPDR). This affects both SA MC, and LC net->fab MC
    status = set_txpdr_cir(DEFAULT_TXPDR_CREDIT_RATE);
    return_on_error(status);
    status = set_txpdr_eir_or_pir(DEFAULT_TXPDR_CREDIT_RATE, false /* is_eir */);
    return_on_error(status);

    int credit_in_bytes;
    status = m_device->get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
    return_on_error(status);

    const int TM_CREDIT_VAL = 128 * credit_in_bytes;

    // Initialize credit generator rate
    la_rate_t device_rate = ((m_device->m_device_frequency_int_khz * TM_CREDIT_VAL) / UNITS_IN_GIGA);
    status = do_set_credit_rate(device_rate);
    return_on_error(status);

    status = do_set_transmit_rate(TRANSMIT_SCH_STATIC_RATE);
    return_on_error(status);

    // Initialize credit generator bucket_size
    status = do_set_credit_burst_size(DEFAULT_IFG_BUCKET_SIZE);
    return_on_error(status);

    status = do_set_transmit_burst_size(DEFAULT_IFG_BUCKET_SIZE);
    return_on_error(status);

    return status;
}

la_status
la_ifg_scheduler_impl::read_max_transmit_rate()
{
    // TODO - this function is not needed for Pacific
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::read_max_rx_shaper_burst()
{
    // TODO - this function is not needed for Pacific
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_lld_memories()
{
    log_debug(HLD, "la_ifg_scheduler_impl::initialize_lld_memories()");
    auto& pdoq = m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top;

    lld_memory_value_list_t mem_val_list;

    // Credit scheduler config

    // Bit fields of this memory are identical for SCH and SCH_FAB
    sch_vsc_token_bucket_cfg_memory tb_cfg_unlimited;
    tb_cfg_unlimited.fields = {.vsc_rate_mantissa = 1,
                               .vsc_rate_exponent = 1,
                               .vsc_max_bucket_value = tm_utils::UNLIMITED_BUCKET_SIZE,
                               .hw_ecc = 0,
                               .dummy_padding = 0};

    // Bit fields of this memory are identical for SCH and SCH_FAB
    sch_oq_pir_token_bucket_cfg_memory cr_sch_tb_cfg_min;
    cr_sch_tb_cfg_min.fields = {.oq_pir_rate_mantissa = 1,
                                .oq_pir_rate_exponent = 1,
                                .oq_pir_max_bucket_value = tm_utils::DEFAULT_CREDIT_BUCKET_SIZE,
                                .hw_ecc = 0,
                                .dummy_padding = 0};

    sch_lpse_wfq_weight_map_memory lpse_wfq_weight_map;
    lpse_wfq_weight_map.fields.lpse_cir_weight0 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight1 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight2 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight3 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight4 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight5 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight6 = 1;
    lpse_wfq_weight_map.fields.lpse_cir_weight7 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight0 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight1 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight2 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight3 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight4 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight5 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight6 = 1;
    lpse_wfq_weight_map.fields.lpse_eir_weight7 = 1;

    mem_val_list.push_back({m_sch_vsc_token_bucket_cfg, tb_cfg_unlimited});
    mem_val_list.push_back({m_sch_oq_pir_token_bucket_cfg, cr_sch_tb_cfg_min});
    mem_val_list.push_back({m_sch_oqpg_cir_token_bucket_cfg, cr_sch_tb_cfg_min});
    mem_val_list.push_back({m_sch_oqse_cir_token_bucket_cfg, cr_sch_tb_cfg_min});
    mem_val_list.push_back({m_sch_oqse_eir_token_bucket_cfg, cr_sch_tb_cfg_min});
    mem_val_list.push_back({m_sch_lpse_wfq_weight_map, lpse_wfq_weight_map});

    // Transmit scheduler config

    pdoq_oq_pir_token_bucket_cfg_memory tx_sch_tb_cfg_min;
    tx_sch_tb_cfg_min.fields = {.oq_pir_rate_mantissa = 1,
                                .oq_pir_rate_exponent = 1,
                                .oq_pir_max_bucket_value = tm_utils::DEFAULT_TRANSMIT_BUCKET_SIZE,
                                .hw_ecc = 0,
                                .dummy_padding = 0};

    mem_val_list.push_back({(*pdoq->oq_pir_token_bucket_cfg)[m_ifg_id], tx_sch_tb_cfg_min});
    mem_val_list.push_back({(*pdoq->oqpg_cir_token_bucket_cfg)[m_ifg_id], tx_sch_tb_cfg_min});

    la_status status = lld_write_memory_list(m_device->m_ll_device, mem_val_list);
    return_on_error(status);

    for (size_t intf_id = 0; intf_id < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; intf_id++) {
        size_t mem_line = m_ifg_id * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + intf_id;

        status = m_device->m_ll_device->write_memory(pdoq->read_rate_limiter, mem_line, 0);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_fdoq_calendar()
{
    for (size_t i = 0; i < array_size(fdoq_ifg_calendar); i++) {
        la_status status = m_device->m_ll_device->write_memory(
            (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->fdoq_ifg_calendar)[m_ifg_id], i, FDOQ_IFG_CALENDAR_INVALID);
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
                (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->fdoq_ifg_calendar)[m_ifg_id], i, pif_base);
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
                (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->fdoq_ifg_calendar)[m_ifg_id],
                i,
                FDOQ_IFG_CALENDAR_INVALID);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_pdif_fifo()
{
    la_status status;

    size_t start_fifo_line = m_ifg_id * PDIF_FIFO_LINE_PER_IFG;
    size_t fifo_lines = PDIF_FIFO_LINE_PER_NETWORK_PORT;
    for (la_uint_t port = 0; port < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; port++) {
        la_uint_t profile_id = port < NUM_PIF_PER_IFG ? s_pdif_fifo_threshold_profile_id.at(la_mac_port::port_speed_e::E_10G)
                                                      : s_pdif_fifo_threshold_profile_id.at(la_mac_port::port_speed_e::E_100G);
        size_t mem_line = m_ifg_id * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + port;
        if (port >= NUM_PIF_PER_IFG) {
            if (port == HOST_PIF_ID) {
                fifo_lines = PDIF_FIFO_LINE_PER_CPU_PORT;
            } else if (port == RECYCLE_PIF_ID) {
                fifo_lines = PDIF_FIFO_LINE_PER_RECYCLE_PORT;
            }
        }

        status = m_device->m_ll_device->write_memory(
            m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pd_if_fifos_thresholds_profile, mem_line, profile_id);
        return_on_error(status);

        status = m_device->m_ll_device->write_memory(
            m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size, mem_line, fifo_lines);
        return_on_error(status);

        status = m_device->m_ll_device->write_memory(
            m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size_start_addr, mem_line, start_fifo_line);
        return_on_error(status);

        start_fifo_line += fifo_lines;
    }

    // Delete FIFO configuration
    status = m_device->m_ll_device->write_memory(m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size,
                                                 PDIF_SLICE_DELETE_PORT_ID,
                                                 la_device_impl::DELETE_FIFO_SIZE);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size_start_addr,
                                                 PDIF_SLICE_DELETE_PORT_ID,
                                                 PDIF_FIFO_LINE_PER_IFG * NUM_IFGS_PER_SLICE);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(
        m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pd_if_fifos_thresholds_profile,
        PDIF_SLICE_DELETE_PORT_ID,
        s_pdif_fifo_threshold_profile_id.at(la_mac_port::port_speed_e::E_800G));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::allocate_pdif_fifo(size_t pif_base, size_t pif_count, bool is_fabric /*dont care in pacific*/)
{
    size_t mem_line = m_ifg_id * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + pif_base;
    size_t fifo_lines = pif_count * PDIF_FIFO_LINE_PER_NETWORK_PORT;
    if (pif_base >= NUM_PIF_PER_IFG) {
        if (pif_base == HOST_PIF_ID) {
            fifo_lines = pif_count * PDIF_FIFO_LINE_PER_CPU_PORT;
        } else if (pif_base == RECYCLE_PIF_ID) {
            fifo_lines = pif_count * PDIF_FIFO_LINE_PER_RECYCLE_PORT;
        }
    }

    la_status status = m_device->m_ll_device->write_memory(
        m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_size, mem_line, fifo_lines);
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
    sch_ifse_general_configuration_register ifse_general_cfg_reg;

    la_status status = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    return_on_error(status);

    ifse_general_cfg_reg.fields.ifg_credit_generator_rate = device_rate;

    status = m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    return_on_error(status);

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
la_ifg_scheduler_impl::do_set_transmit_rate(la_uint32_t device_rate)
{
    pdoq_ifse_general_configuration_register ifse_general_cfg_reg;

    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    // Set field IfgCreditGeneratorRate of register IfseGeneralConfiguration[m_ifg_id]
    ifse_general_cfg_reg.fields.ifg_credit_generator_rate = device_rate;

    status = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

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
    sch_ifse_general_configuration_register ifse_general_cfg_reg;

    la_status status = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    return_on_error(status);

    // Set field IfgCreditGeneratorMaxBucket of register IfseGeneralConfiguration[m_ifg_id]
    ifse_general_cfg_reg.fields.ifg_credit_generator_max_bucket = burst;

    status = m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, ifse_general_cfg_reg);
    return_on_error(status);

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
    pdoq_ifse_general_configuration_register ifse_general_cfg_reg;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(stat);

    // Set field IfgCreditGeneratorMaxBucket of register IfseGeneralConfiguration[m_ifg_id]
    ifse_general_cfg_reg.fields.ifg_credit_generator_max_bucket = burst;

    return m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
}

la_status
la_ifg_scheduler_impl::set_max_transmit_rate_utilization(la_float_t max_rate_percent)
{
    start_api_call("max_rate_percent=", max_rate_percent);
    if ((max_rate_percent < 0) || (max_rate_percent > 1)) {
        return LA_STATUS_EINVAL;
    }

    pdoq_ifse_general_configuration_register ifse_general_cfg_reg;
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    if (max_rate_percent == 0) {
        ifse_general_cfg_reg.fields.ifg_credit_generator_rate = 0;
    } else {
        ifse_general_cfg_reg.fields.ifg_credit_generator_rate = TRANSMIT_SCH_STATIC_RATE / max_rate_percent;
    }

    status = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_max_transmit_rate_utilization(la_float_t& out_max_rate_percent) const
{
    start_api_getter_call();
    pdoq_ifse_general_configuration_register ifse_general_cfg_reg;
    la_status status = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], ifse_general_cfg_reg);
    return_on_error(status);

    if (ifse_general_cfg_reg.fields.ifg_credit_generator_rate == 0) {
        out_max_rate_percent = 0;
    } else {
        out_max_rate_percent
            = (la_float_t)TRANSMIT_SCH_STATIC_RATE / (la_float_t)ifse_general_cfg_reg.fields.ifg_credit_generator_rate;
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

    uint64_t max_burst;
    uint64_t odd_ifg_diff;
    la_device_revision_e revision = m_device->m_pacific_tree->get_revision();
    if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        max_burst = tm_utils::MAX_IFG_RX_SHAPER_BURST_PACIFIC_B0_B1;
        odd_ifg_diff = tm_utils::MAX_IFG_RX_SHAPER_ODD_IFG_DIFF_PACIFIC_B0_B1;
    } else { // PACIFIC::A0
        max_burst = tm_utils::MAX_IFG_RX_SHAPER_BURST_PACIFIC_A0;
        odd_ifg_diff = tm_utils::MAX_IFG_RX_SHAPER_ODD_IFG_DIFF_PACIFIC_A0;
    }
    if (m_ifg_id & 1) {
        max_burst = max_burst + odd_ifg_diff;
    }

    ifgb_rx_shaper_cfg_register rx_shaper_reg;
    la_status status = m_device->m_ll_device->read_register(
        m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg, rx_shaper_reg);
    return_on_error(status);

    rx_shaper_reg.fields.rx_shaper_burst = max_rate_percent * max_burst;

    status = m_device->m_ll_device->write_register(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg,
                                                   rx_shaper_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_max_rx_rate_utilization(la_float_t& out_max_rate_percent) const
{
    start_api_getter_call();
    ifgb_rx_shaper_cfg_register rx_shaper_reg;
    la_status status = m_device->m_ll_device->read_register(
        m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_shaper_cfg, rx_shaper_reg);
    return_on_error(status);

    uint64_t max_burst;
    uint64_t odd_ifg_diff;
    la_device_revision_e revision = m_device->m_pacific_tree->get_revision();
    if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        max_burst = tm_utils::MAX_IFG_RX_SHAPER_BURST_PACIFIC_B0_B1;
        odd_ifg_diff = tm_utils::MAX_IFG_RX_SHAPER_ODD_IFG_DIFF_PACIFIC_B0_B1;
    } else { // PACIFIC::A0
        max_burst = tm_utils::MAX_IFG_RX_SHAPER_BURST_PACIFIC_A0;
        odd_ifg_diff = tm_utils::MAX_IFG_RX_SHAPER_ODD_IFG_DIFF_PACIFIC_A0;
    }
    if (m_ifg_id & 1) {
        max_burst = max_burst + odd_ifg_diff;
    }
    out_max_rate_percent = (la_float_t)rx_shaper_reg.fields.rx_shaper_burst / (la_float_t)max_burst;

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_slow_rate()
{
    // 8*CoreClockRate*1024*10^9 / R
    sch_slow_rate_configuration_register slow_rate_reg;

    slow_rate_reg.fields.slow_rate_enable = 1;
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        slow_rate_reg.fields.slow_rate = SA_SLOW_RATE_REG_VAL;
    } else {
        // LC (maybe FE also)
        slow_rate_reg.fields.slow_rate = LC_SLOW_RATE_REG_VAL;
    }

    return m_device->m_ll_device->write_register(*m_sch_slow_rate_configuration, slow_rate_reg);
}

la_status
la_ifg_scheduler_impl::get_txpdr_cir(la_rate_t& out_rate) const
{
    // get IfseCirShaperRateConfiguration[TXPDR_PORT] register
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register((*m_sch_ifse_cir_shaper_rate_configuration)[TXPDR_PORT], tmp_bv);
    return_on_error(stat);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                credits_conf_reg);
    return_on_error(stat);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    out_rate = tm_utils::convert_rate_from_device_val(tmp_bv.get_value(), crdt_in_bytes, m_device->m_device_frequency_int_khz);
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_txpdr_cir(la_rate_t rate)
{
    start_api_call("rate=", rate);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    la_status status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                            credits_conf_reg);
    return_on_error(status);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(rate, crdt_in_bytes, m_device->m_device_frequency_int_khz, rate_to_device);
    return_on_error(status);

    // set IfseCirShaperRateConfiguration[TXPDR_PORT] register
    return m_device->m_ll_device->write_register((*m_sch_ifse_cir_shaper_rate_configuration)[TXPDR_PORT], rate_to_device);
}

la_status
la_ifg_scheduler_impl::get_txpdr_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const
{

    // get IfsePirShaperConfiguration[TXPDR_PORT] register
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register((*m_sch_ifse_pir_shaper_configuration)[TXPDR_PORT], tmp_bv);
    return_on_error(stat);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                credits_conf_reg);
    return_on_error(stat);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    out_rate = tm_utils::convert_rate_from_device_val(tmp_bv.get_value(), crdt_in_bytes, m_device->m_device_frequency_int_khz);

    // Get field IfseEirShaperMode[TXPDR_PORT] of register IfseGeneralConfiguration
    stat = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, tmp_bv);
    return_on_error(stat);
    out_is_eir = tmp_bv.bit(TXPDR_PORT + IFSE_EIR_SHAPE_MODE_BASE);
    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_txpdr_eir_or_pir(la_rate_t rate, bool is_eir)
{
    start_api_call("rate=", rate, "is_eir=", is_eir);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    la_status status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                            credits_conf_reg);
    return_on_error(status);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(rate, crdt_in_bytes, m_device->m_device_frequency_int_khz, rate_to_device);

    return_on_error(status);

    // set IfsePirShaperConfiguration[TXPDR_PORT] register
    status = m_device->m_ll_device->write_register((*m_sch_ifse_pir_shaper_configuration)[TXPDR_PORT], rate_to_device);

    return_on_error(status);

    // Set field IfseEirShaperMode[TXPDR_PORT] of register IfseGeneralConfiguration
    return m_device->m_ll_device->read_modify_write_register(
        *m_sch_ifse_general_configuration, TXPDR_PORT + IFSE_EIR_SHAPE_MODE_BASE, TXPDR_PORT + IFSE_EIR_SHAPE_MODE_BASE, is_eir);
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
    sch_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get cir shaper rate
    la_status stat = m_device->m_ll_device->read_register(*m_sch_tpse_shaper_configuration, tpse_shaper_cfg_reg);

    return_on_error(stat);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                credits_conf_reg);
    return_on_error(stat);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    out_rate = tm_utils::convert_rate_from_device_val(tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate,
                                                      tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value,
                                                      crdt_in_bytes,
                                                      m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

/// @brief Get credit scheduler's eir rate.
la_status
la_ifg_scheduler_impl::get_eir(la_rate_t& out_rate)
{
    sch_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get cir shaper rate
    la_status stat = m_device->m_ll_device->read_register(*m_sch_tpse_shaper_configuration, tpse_shaper_cfg_reg);

    return_on_error(stat);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                credits_conf_reg);
    return_on_error(stat);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    out_rate = tm_utils::convert_rate_from_device_val(tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate,
                                                      tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value,
                                                      crdt_in_bytes,
                                                      m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

/// @brief Get transmit scheduler's cir rate.
la_status
la_ifg_scheduler_impl::get_transmit_cir(la_rate_t& out_rate)
{
    pdoq_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get cir shaper rate
    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_shaper_configuration)[m_ifg_id], tpse_shaper_cfg_reg);
    return_on_error(stat);

    pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value,
                                                pdoq_credit_value_reg);
    return_on_error(stat);

    size_t credit_value = pdoq_credit_value_reg.fields.credit_value;

    out_rate = tm_utils::convert_rate_from_device_val(
        tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate, credit_value, m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

/// @brief Get transmit scheduler's pir rate.
la_status
la_ifg_scheduler_impl::get_transmit_pir(la_rate_t& out_rate)
{
    pdoq_tpse_shaper_configuration_register tpse_shaper_cfg_reg;

    // get pir shaper rate
    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_shaper_configuration)[m_ifg_id], tpse_shaper_cfg_reg);

    return_on_error(stat);

    pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value,
                                                pdoq_credit_value_reg);
    return_on_error(stat);

    size_t credit_value = pdoq_credit_value_reg.fields.credit_value;

    out_rate = tm_utils::convert_rate_from_device_val(
        tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate, credit_value, m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_general_credit_shapers()
{
    la_status status = initialize_slow_rate();
    return_on_error(status);

    int credit_in_bytes;
    status = m_device->get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
    return_on_error(status);

    ///< Credit value (in Bytes) / 8 clocks
    const int CREDIT_SCH_STATIC_RATE = credit_in_bytes / 8;

    status = initialize_credit_tpse_shaper(CREDIT_SCH_STATIC_RATE);
    return_on_error(status);

    status = initialize_oqse_shaper(CREDIT_SCH_STATIC_RATE);
    return_on_error(status);

    status = initialize_lpse_shaper(CREDIT_SCH_STATIC_RATE);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_credit_tpse_shaper(uint32_t device_rate)
{
    sch_tpse_shaper_configuration_register tpse_shaper_cfg_reg;
    bzero(&tpse_shaper_cfg_reg, sch_tpse_shaper_configuration_register::SIZE);

    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate = device_rate;
    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_max_bucket = 8;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate = device_rate;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_max_bucket = 8;

    // set cir shaper rate
    la_status stat = m_device->m_ll_device->write_register(*m_sch_tpse_shaper_configuration, tpse_shaper_cfg_reg);

    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::get_oqse_shaper(uint32_t& out_device_rate)
{
    sch_oqse_shaper_configuration_register oqse_shaper_cfg_reg;

    // get cir shaper rate
    la_status stat = m_device->m_ll_device->read_register(*m_sch_oqse_shaper_configuration, oqse_shaper_cfg_reg);
    return_on_error(stat);

    out_device_rate = oqse_shaper_cfg_reg.fields.oqse_shaper_rate;

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::set_tpse_to_interface_map(la_uint_t intf_id, la_uint_t intf_count)
{
    bit_vector pdoq_bv;
    bit_vector sch_bv;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], pdoq_bv);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, sch_bv);
    return_on_error(stat);

    size_t base_lsb = TPSE_2_IFC_MAP_LSB + TPSE_2_IFC_MAP_SINGLE_WIDTH * intf_id;
    pdoq_bv.set_bits(base_lsb + TPSE_2_IFC_MAP_SINGLE_WIDTH - 1, base_lsb, intf_id);
    sch_bv.set_bits(base_lsb + TPSE_2_IFC_MAP_SINGLE_WIDTH - 1, base_lsb, intf_id);

    for (la_uint_t i = 1; i < intf_count; i++) {
        size_t lsb = base_lsb + TPSE_2_IFC_MAP_SINGLE_WIDTH * i;
        pdoq_bv.set_bits(lsb + TPSE_2_IFC_MAP_SINGLE_WIDTH - 1, lsb, 0x1F);
        sch_bv.set_bits(lsb + TPSE_2_IFC_MAP_SINGLE_WIDTH - 1, lsb, 0x1F);
    }

    stat = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], pdoq_bv);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(*m_sch_ifse_general_configuration, sch_bv);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_oqse_shaper(uint32_t device_rate)
{
    sch_oqse_shaper_configuration_register oqse_shaper_cfg_reg;
    bzero(&oqse_shaper_cfg_reg, sch_oqse_shaper_configuration_register::SIZE);

    oqse_shaper_cfg_reg.fields.oqse_shaper_rate = device_rate;
    oqse_shaper_cfg_reg.fields.oqse_shaper_incr_value = 1;
    oqse_shaper_cfg_reg.fields.oqse_shaper_max_bucket = 8;

    // get cir shaper rate
    la_status stat = m_device->m_ll_device->write_register(*m_sch_oqse_shaper_configuration, oqse_shaper_cfg_reg);

    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_lpse_shaper(uint32_t device_rate)
{
    sch_lpse_shaper_configuration_register lpse_shaper_cfg_reg;
    bzero(&lpse_shaper_cfg_reg, sch_lpse_shaper_configuration_register::SIZE);

    lpse_shaper_cfg_reg.fields.lpse_cir_shaper_rate = device_rate;
    lpse_shaper_cfg_reg.fields.lpse_cir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    lpse_shaper_cfg_reg.fields.lpse_cir_shaper_max_bucket = 8;
    lpse_shaper_cfg_reg.fields.lpse_eir_shaper_rate = device_rate;
    lpse_shaper_cfg_reg.fields.lpse_eir_shaper_incr_value = DEFAULT_CREDIT_SCH_NUM_TOKENS_INCR;
    lpse_shaper_cfg_reg.fields.lpse_eir_shaper_max_bucket = 8;

    // set cir shaper rate
    la_status stat = m_device->m_ll_device->write_register(*m_sch_lpse_shaper_configuration, lpse_shaper_cfg_reg);

    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_general_transmit_shapers()
{
    la_status status = initialize_transmit_tpse_shaper(TRANSMIT_SHAPER_MAX_RATE);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ifg_scheduler_impl::initialize_transmit_tpse_shaper(uint32_t device_rate)
{
    pdoq_tpse_shaper_configuration_register tpse_shaper_cfg_reg;
    bzero(&tpse_shaper_cfg_reg, pdoq_tpse_shaper_configuration_register::SIZE);

    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_rate = device_rate;
    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_incr_value = DEFAULT_TRANSMIT_SCH_NUM_TOKENS_INCR;
    tpse_shaper_cfg_reg.fields.tpse_cir_shaper_max_bucket = 8;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_rate = device_rate;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_incr_value = DEFAULT_TRANSMIT_SCH_NUM_TOKENS_INCR;
    tpse_shaper_cfg_reg.fields.tpse_pir_shaper_max_bucket = 8;

    la_status stat = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_shaper_configuration)[m_ifg_id], tpse_shaper_cfg_reg);

    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
