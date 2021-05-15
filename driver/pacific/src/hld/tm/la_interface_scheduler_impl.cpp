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

#include "common/dassert.h"

#include "hld_utils.h"
#include "la_ifg_scheduler_impl.h"
#include "la_interface_scheduler_impl.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "system/la_device_impl.h"
#include "tm_utils.h"

#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

#include <sstream>

namespace silicon_one
{
// Limit the reads: 10G, 25G, 40, 50, 100, 200, 400, 800
std::map<la_mac_port::port_speed_e, la_uint_t> read_rate_limit = {{la_mac_port::port_speed_e::E_10G, 38},
                                                                  {la_mac_port::port_speed_e::E_25G, 13},
                                                                  {la_mac_port::port_speed_e::E_40G, 7},
                                                                  {la_mac_port::port_speed_e::E_50G, 5},
                                                                  {la_mac_port::port_speed_e::E_100G, 2},
                                                                  {la_mac_port::port_speed_e::E_200G, 2},
                                                                  {la_mac_port::port_speed_e::E_400G, 0},
                                                                  {la_mac_port::port_speed_e::E_800G, 0}};

// OQ profile, depends on port speed: 10G, 25G, 40, 50, 100, 200, 400, 800
std::map<la_mac_port::port_speed_e, la_uint_t> oq_profile_id = {{la_mac_port::port_speed_e::E_10G, 6},
                                                                {la_mac_port::port_speed_e::E_25G, 5},
                                                                {la_mac_port::port_speed_e::E_40G, 4},
                                                                {la_mac_port::port_speed_e::E_50G, 3},
                                                                {la_mac_port::port_speed_e::E_100G, 2},
                                                                {la_mac_port::port_speed_e::E_200G, 2},
                                                                {la_mac_port::port_speed_e::E_400G, 0},
                                                                {la_mac_port::port_speed_e::E_800G, 0}};

// Reorder profile, depends on port speed: 10G, 25G, 40, 50, 100, 200, 400, 800
std::map<la_mac_port::port_speed_e, la_uint_t> reorder_profile_map = {{la_mac_port::port_speed_e::E_10G, 0},
                                                                      {la_mac_port::port_speed_e::E_25G, 1},
                                                                      {la_mac_port::port_speed_e::E_40G, 2},
                                                                      {la_mac_port::port_speed_e::E_50G, 3},
                                                                      {la_mac_port::port_speed_e::E_100G, 4},
                                                                      {la_mac_port::port_speed_e::E_200G, 5},
                                                                      {la_mac_port::port_speed_e::E_400G, 6},
                                                                      {la_mac_port::port_speed_e::E_800G, 7}};

// IFG credit init values, depends on port speed: 10G, 25G, 40, 50, 100, 200, 400, 800
std::map<la_mac_port::port_speed_e, la_uint_t> ifg_credit_init_map = {{la_mac_port::port_speed_e::E_10G, 76},
                                                                      {la_mac_port::port_speed_e::E_25G, 76},
                                                                      {la_mac_port::port_speed_e::E_40G, 76},
                                                                      {la_mac_port::port_speed_e::E_50G, 76},
                                                                      {la_mac_port::port_speed_e::E_100G, 152},
                                                                      {la_mac_port::port_speed_e::E_200G, 152},
                                                                      {la_mac_port::port_speed_e::E_400G, 616},
                                                                      {la_mac_port::port_speed_e::E_800G, 616}};

const std::map<la_mac_port::port_speed_e, la_uint_t> la_interface_scheduler_impl::TX_CGM_PROFILE_MAP
    = {{la_mac_port::port_speed_e::E_10G, 7},
       {la_mac_port::port_speed_e::E_25G, 6},
       {la_mac_port::port_speed_e::E_40G, 5},
       {la_mac_port::port_speed_e::E_50G, 4},
       {la_mac_port::port_speed_e::E_100G, 3},
       {la_mac_port::port_speed_e::E_200G, 2},
       {la_mac_port::port_speed_e::E_400G, 1},
       {la_mac_port::port_speed_e::E_800G, 0}};

const std::map<la_mac_port::port_speed_e, la_uint_t> la_interface_scheduler_impl::TX_CGM_PROFILE_MAP_PFC
    = {{la_mac_port::port_speed_e::E_10G, 15},
       {la_mac_port::port_speed_e::E_25G, 14},
       {la_mac_port::port_speed_e::E_40G, 13},
       {la_mac_port::port_speed_e::E_50G, 12},
       {la_mac_port::port_speed_e::E_100G, 11},
       {la_mac_port::port_speed_e::E_200G, 10},
       {la_mac_port::port_speed_e::E_400G, 9},
       {la_mac_port::port_speed_e::E_800G, 8}};

la_interface_scheduler_impl::la_interface_scheduler_impl()
{
}

la_interface_scheduler_impl::la_interface_scheduler_impl(const la_device_impl_wptr& device,
                                                         la_slice_id_t slice_id,
                                                         la_ifg_id_t ifg_id,
                                                         la_uint_t pif_base,
                                                         la_mac_port::port_speed_e speed,
                                                         bool is_fabric)
    : m_device(device),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_pif_base(pif_base),
      m_speed(speed),
      m_is_fabric(is_fabric),
      m_pfc(false),
      m_pfc_tc_bitmap(0)
{
    if (is_fabric) {
        m_tm_port_id = m_pif_base / NUM_SERDES_PER_FABRIC_PORT;

        la_device_impl::lc_56_fabric_port_info fabric_port_info
            = m_device->get_borrowed_fabric_port_info(slice_id, ifg_id, pif_base);

        if (fabric_port_info.is_lc_56_fabric_port == true) {
            m_slice_id = fabric_port_info.slice_id;
            m_ifg_id = fabric_port_info.ifg_id;
            m_pif_base = fabric_port_info.serdes_base_id;
            m_tm_port_id = fabric_port_info.fabric_port_num;
        }
    } else {
        m_tm_port_id = m_pif_base;
    }

    // In a network port:
    // - m_tm_port_id == m_serdes_base
    // - m_slice_tm_port_id == m_slice_serdes_base
    //
    // In a fabric port the logic is in the code.

    m_slice_tm_port_id = m_ifg_id * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + m_tm_port_id;
    m_slice_pif_base = m_ifg_id * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + m_pif_base;

    if (m_slice_id < FIRST_HW_FABRIC_SLICE) {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch);
    } else {
        initialize_sch_references(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->fabric_sch);
    }
}

la_interface_scheduler_impl::~la_interface_scheduler_impl()
{
}

la_status
la_interface_scheduler_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    la_status status;
    auto& pdoq_top = m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top;
    auto& pdoq_fdoq = m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq;

    lld_register_value_list_t reg_val_list;

    // In fabric slices, m_serdes_base = 19 is used by the fabric ports of LC_56_FABRIC_PORT_MODE
    if ((m_device->m_slice_mode[m_slice_id] != la_slice_mode_e::CARRIER_FABRIC)
        && ((m_pif_base == RECYCLE_PIF_ID) || (m_pif_base == HOST_PIF_ID))) {
        la_rate_t port_speed = (la_2_port_speed(m_speed)) * UNITS_IN_GIGA;
        status = set_credit_cir(port_speed);
        return_on_error(status);

        status = set_credit_eir_or_pir(port_speed, false /* is_eir */);
        return_on_error(status);
    }

    // Set the credits for initial value
    pdoq_fdoq_ifg_credit_init_register ifg_credit_init_reg;
    ifg_credit_init_reg.fields.ifg_credit_init_value = ifg_credit_init_map.at(m_speed);
    ifg_credit_init_reg.fields.ifg_credit_init_enable = 1ULL << (m_slice_pif_base);
    if (m_speed == la_mac_port::port_speed_e::E_800G) {
        ifg_credit_init_reg.fields.ifg_credit_init_enable |= 1ULL << (m_slice_pif_base + 8);
    }

    reg_val_list.push_back({(pdoq_fdoq->ifg_credit_init), ifg_credit_init_reg});

    pdoq_fdoq_fdoq_general_configuration_register fdoq_general_cfg;

    status = m_device->m_ll_device->read_register(pdoq_fdoq->fdoq_general_configuration, fdoq_general_cfg);
    return_on_error(status);
    fdoq_general_cfg.fields.mlp_en
        = bit_utils::set_bit(fdoq_general_cfg.fields.mlp_en, m_ifg_id, m_speed == la_mac_port::port_speed_e::E_800G);
    reg_val_list.push_back({(pdoq_fdoq->fdoq_general_configuration), fdoq_general_cfg});

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    size_t mem_line = m_slice_pif_base;
    status = m_device->m_ll_device->write_memory(
        m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->pd_if_fifos_thresholds_profile,
        mem_line,
        la_ifg_scheduler_impl::s_pdif_fifo_threshold_profile_id.at(m_speed));
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(
        pdoq_top->read_rate_limiter,
        m_slice_tm_port_id,
        bit_vector(read_rate_limit.at(m_speed), pdoq_top->read_rate_limiter->get_desc()->width_bits));
    return_on_error(status);

    for (size_t oq = 0; oq < tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH; oq++) {
        // This uses the profiles defined in pacific_tree.slice[slice_id]->pdoq->top->oq_crbal_th_configuration
        status = m_device->m_ll_device->write_memory(
            pdoq_top->oq_profile,
            (m_slice_tm_port_id)*tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oq,
            bit_vector(oq_profile_id.at(m_speed), pdoq_top->oq_profile->get_desc()->width_bits));
        return_on_error(status);
    }

    status = initialize_reorder();
    return_on_error(status);

    status = initialize_pfc_mapping();
    return_on_error(status);

    status = initialize_txcgm();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::reset_fdoq_credits()
{
    // Set the credits for initial value
    pdoq_fdoq_ifg_credit_init_register ifg_credit_init_reg;
    ifg_credit_init_reg.fields.ifg_credit_init_value = ifg_credit_init_map.at(m_speed);
    ifg_credit_init_reg.fields.ifg_credit_init_enable = 1ULL << (m_slice_pif_base);
    if (m_speed == la_mac_port::port_speed_e::E_800G) {
        ifg_credit_init_reg.fields.ifg_credit_init_enable |= 1ULL << (m_slice_pif_base + 8);
    }

    la_status status = m_device->m_ll_device->write_register(
        m_device->m_pacific_tree->slice[m_slice_id]->pdoq->fdoq->ifg_credit_init, ifg_credit_init_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::initialize_reorder()
{
    la_device_revision_e revision = m_device->m_pacific_tree->get_revision();
    if ((revision != la_device_revision_e::PACIFIC_B0) && (revision != la_device_revision_e::PACIFIC_B1)) {
        // This is currently disabled, the profile is pre-configured to 6 in the initialization.
        return LA_STATUS_SUCCESS;
    }

    lld_memory_line_value_list_t mem_line_val_list;
    la_uint_t reorder_profile = reorder_profile_map.at(m_speed);

    lld_memory_scptr connection_profile_table
        = m_slice_id < 3 ? (*m_device->m_pacific_tree->slice[m_slice_id]->pp_reorder->connection_profile_table)[m_ifg_id]
                         : (m_device->m_pacific_tree->slice[m_slice_id]->nw_reorder_block[m_ifg_id]->connection_profile_table);

    size_t mem_start_line = m_pif_base * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH;
    for (size_t i = 0; i < tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH; i++) {
        size_t line = mem_start_line + i;
        mem_line_val_list.push_back({{connection_profile_table, line}, reorder_profile});
    }

    la_status status = lld_write_memory_line_list(m_device->get_ll_device_sptr(), mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::initialize_pfc_mapping()
{
    la_uint_t base_oq = (m_slice_tm_port_id)*NUM_OQ_PER_PIF;

    // There is allocation for 32 interfaces per IFG (actually used only 20), each interface uses two lines since 4 OQs per line
    size_t line_num = m_ifg_id * 32 * 2 + m_pif_base * 2;
    lld_memory_scptr pfc_mapping_table = (m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pfc_mapping);

    bit_vector line0_val(0, pfc_mapping_table->get_desc()->width_bits);
    bit_vector line1_val(0, pfc_mapping_table->get_desc()->width_bits);

    // 4 OQs per line
    for (size_t oq = 0; oq < 4; oq++) {
        // PfcOqNumber: each entry uses 9 bits
        size_t lsb = oq * 9;
        line0_val.set_bits(lsb + 8, lsb, base_oq + oq);
        line1_val.set_bits(lsb + 8, lsb, base_oq + oq + 4);

        // PfcTcMap: each entry uses 8 bits, base offset of PfcTcMap is 4x9=36
        lsb = 36 + oq * 8;
        line0_val.set_bits(lsb + 7, lsb, 1);
        line1_val.set_bits(lsb + 7, lsb, 1);
    }

    la_status status = LA_STATUS_SUCCESS;
    status = m_device->m_ll_device->write_memory(*pfc_mapping_table, line_num, line0_val);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(*pfc_mapping_table, line_num + 1, line1_val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::initialize_txcgm()
{
    lld_memory_line_value_list_t mem_line_val_list;

    lld_memory_scptr uc_oq_profile_map = (m_device->m_pacific_tree->slice[m_slice_id]->tx->cgm->uc_oq_profile_map);
    lld_memory_scptr mc_oq_profile_map = (m_device->m_pacific_tree->slice[m_slice_id]->tx->cgm->mc_oq_profile_map);
    lld_memory_scptr uc_oqg_profile_map = (m_device->m_pacific_tree->slice[m_slice_id]->tx->cgm->uc_oqg_profile_map);

    la_uint_t txcgm_profile = TX_CGM_PROFILE_MAP.at(m_speed);
    size_t num_of_speeds = (size_t)m_device->m_device_port_handler->get_supported_speeds().size();
    size_t oq_start_line = (m_slice_tm_port_id)*tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH;

    for (size_t oq = 0; oq < tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH; oq++) {
        // For PFC TC-s, use a seperate OQ profile
        if ((m_pfc_tc_bitmap & (1 << oq)) != 0) {
            la_uint_t pfc_txcgm_profile = TX_CGM_PROFILE_MAP_PFC.at(m_speed);
            mem_line_val_list.push_back({{uc_oq_profile_map, oq_start_line + oq}, pfc_txcgm_profile});
        } else {
            mem_line_val_list.push_back({{uc_oq_profile_map, oq_start_line + oq}, txcgm_profile});
        }

        la_uint_t mc_txcgm_profile = ((oq < 6) || m_is_fabric) ? txcgm_profile : (txcgm_profile + num_of_speeds);
        mem_line_val_list.push_back({{mc_oq_profile_map, oq_start_line + oq}, mc_txcgm_profile});
    }

    size_t oqg_line = m_slice_tm_port_id;
    la_mac_port::port_speed_e speed = m_speed;

    // When PFC is on, set the oq group threshold to the 800G entry, and set it to pass-through
    if (m_pfc) {
        speed = la_mac_port::port_speed_e::E_800G;

        auto uc_oqg_profile_reg = m_device->m_pacific_tree->slice[m_slice_id]->tx->cgm->uc_oqg_profile;
        txcgm_uc_oqg_profile_memory uc_oqg_profile;

        // FC bytes threshold should be 130K * 4 (OQ thresholds are 130K, threshold covers more than enough TC-s). Similar for
        // buffer thresholds.
        // flow_control_bytes_th is in 256 byte units.
        uc_oqg_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.flow_control_buffers_th = 2000;
        uc_oqg_profile.fields.flow_control_pds_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_PDS_TH_WIDTH);
        uc_oqg_profile.fields.drop_buffers_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BUFFERS_TH_WIDTH);
        uc_oqg_profile.fields.drop_pds_th = bit_utils::ones(uc_oqg_profile.fields.DROP_PDS_TH_WIDTH);
        uc_oqg_profile.fields.drop_bytes_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.fcn_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.fcn_buffers_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BUFFERS_TH_WIDTH);
        uc_oqg_profile.fields.fcn_pds_th = bit_utils::ones(uc_oqg_profile.fields.FCN_PDS_TH_WIDTH);

        la_status status = m_device->m_ll_device->write_memory(uc_oqg_profile_reg, TX_CGM_PROFILE_MAP.at(speed), uc_oqg_profile);
        return_on_error(status);
    }
    txcgm_profile = TX_CGM_PROFILE_MAP.at(speed);
    mem_line_val_list.push_back({{uc_oqg_profile_map, oqg_line}, txcgm_profile});

    la_status status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::get_transmit_cir(la_rate_t& out_rate) const
{
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_cir_shaper_rate_configuration)[m_slice_tm_port_id], tmp_bv);
    return_on_error(stat);

    uint64_t tmp_int = tmp_bv.get_value();

    pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value,
                                                pdoq_credit_value_reg);
    return_on_error(stat);

    size_t credit_value = pdoq_credit_value_reg.fields.credit_value;

    out_rate = tm_utils::convert_rate_from_device_val(tmp_int, credit_value, m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_transmit_cir(la_rate_t rate)
{
    start_api_call("rate=", rate);

    pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
    la_status status = m_device->m_ll_device->read_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value, pdoq_credit_value_reg);
    return_on_error(status);

    size_t credit_value = pdoq_credit_value_reg.fields.credit_value;

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(rate, credit_value, m_device->m_device_frequency_int_khz, rate_to_device);
    return_on_error(status);

    // set IfseCirShaperRateConfiguration[m_ifg_id * MAX_TM_PORT_TS + m_tm_port_id] register
    return m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_cir_shaper_rate_configuration)[m_slice_tm_port_id],
        rate_to_device);
}

la_status
la_interface_scheduler_impl::get_credit_cir(la_rate_t& out_rate) const
{
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register((*m_sch_ifse_cir_shaper_rate_configuration)[m_tm_port_id], tmp_bv);
    return_on_error(stat);

    uint64_t tmp_int = tmp_bv.get_value();

    ics_slice_credits_conf_reg_register credits_conf_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                credits_conf_reg);
    return_on_error(stat);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    out_rate = tm_utils::convert_rate_from_device_val(tmp_int, crdt_in_bytes, m_device->m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_credit_cir(la_rate_t rate)
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

    // set IfseCirShaperRateConfiguration[m_tm_port_id] register
    return m_device->m_ll_device->write_register((*m_sch_ifse_cir_shaper_rate_configuration)[m_tm_port_id], rate_to_device);
}

la_status
la_interface_scheduler_impl::get_credit_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const
{
    bit_vector rate_bv;
    bit_vector mode_bv;

    la_status stat = m_device->m_ll_device->read_register(*m_sch_ifse_general_configuration, mode_bv);
    return_on_error(stat);
    stat = m_device->m_ll_device->read_register((*m_sch_ifse_pir_shaper_configuration)[m_tm_port_id], rate_bv);
    return_on_error(stat);

    uint64_t tmp_int = rate_bv.get_value();

    ics_slice_credits_conf_reg_register credits_conf_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                credits_conf_reg);
    return_on_error(stat);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    out_rate = tm_utils::convert_rate_from_device_val(tmp_int, crdt_in_bytes, m_device->m_device_frequency_int_khz);

    out_is_eir = mode_bv.bit(m_tm_port_id + IFSE_EIR_SHAPE_MODE_BASE);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_credit_eir_or_pir(la_rate_t rate, bool is_eir)
{
    start_api_call("rate=", (rate), "is_eir=", is_eir);

    ics_slice_credits_conf_reg_register credits_conf_reg;
    la_status status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ics->credits_conf_reg,
                                                            credits_conf_reg);
    return_on_error(status);

    size_t crdt_in_bytes = credits_conf_reg.fields.crdt_in_bytes;

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(rate, crdt_in_bytes, m_device->m_device_frequency_int_khz, rate_to_device);

    return_on_error(status);

    // set IfsePirShaperConfiguration[m_tm_port_id] register
    status = m_device->m_ll_device->write_register((*m_sch_ifse_pir_shaper_configuration)[m_tm_port_id], rate_to_device);

    return_on_error(status);

    // Set field IfseEirShaperMode[m_tm_port_id] of register IfseGeneralConfiguration
    return m_device->m_ll_device->read_modify_write_register(*m_sch_ifse_general_configuration,
                                                             m_tm_port_id + IFSE_EIR_SHAPE_MODE_BASE,
                                                             m_tm_port_id + IFSE_EIR_SHAPE_MODE_BASE,
                                                             is_eir);
}

la_status
la_interface_scheduler_impl::get_transmit_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const
{
    bit_vector rate_bv;
    bit_vector mode_bv;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id], mode_bv);
    return_on_error(stat);
    stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_pir_shaper_configuration)[m_slice_tm_port_id], rate_bv);
    return_on_error(stat);

    uint32_t tmp_int = (uint32_t)rate_bv.get_value();

    pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value,
                                                pdoq_credit_value_reg);
    return_on_error(stat);

    size_t credit_value = pdoq_credit_value_reg.fields.credit_value;

    out_rate = tm_utils::convert_rate_from_device_val(tmp_int, credit_value, m_device->m_device_frequency_int_khz);

    out_is_eir = mode_bv.bit(m_tm_port_id + IFSE_EIR_SHAPE_MODE_BASE);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_transmit_eir_or_pir(la_rate_t rate, bool is_eir)
{
    start_api_call("rate=", (rate), "is_eir=", is_eir);

    pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
    la_status status = m_device->m_ll_device->read_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->pdoq_credit_value, pdoq_credit_value_reg);
    return_on_error(status);

    size_t credit_value = pdoq_credit_value_reg.fields.credit_value;

    // rate - credits_per_sec
    uint32_t rate_to_device;
    status = tm_utils::convert_rate_to_device_val(rate, credit_value, m_device->m_device_frequency_int_khz, rate_to_device);
    return_on_error(status);

    la_status ret = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_pir_shaper_configuration)[m_slice_tm_port_id],
        rate_to_device);
    return_on_error(ret);

    // Set field IfseEirShaperMode[m_tm_port_id] of register IfseGeneralConfiguration[m_ifg_id]
    return m_device->m_ll_device->read_modify_write_register(
        *(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_general_configuration)[m_ifg_id],
        m_tm_port_id + IFSE_EIR_SHAPE_MODE_BASE,
        m_tm_port_id + IFSE_EIR_SHAPE_MODE_BASE,
        is_eir);
}

la_status
la_interface_scheduler_impl::get_cir_weight(la_wfq_weight_t& out_weight) const
{
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_wfq_cir_weights)[m_slice_pif_base], tmp_bv);
    return_on_error(stat);

    out_weight = tmp_bv.get_value();

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_cir_weight(la_wfq_weight_t weight)
{
    start_api_call("weight=", weight);

    // set IfseWfqCirWeights[m_ifg_id * MAX_TM_PORT_TS + m_pif_base] register
    la_status stat = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_wfq_cir_weights)[m_slice_pif_base], weight);
    return_on_error(stat);

    // set IfseWfqCirWeights[m_pif_base] register
    stat = m_device->m_ll_device->write_register((*m_sch_ifse_wfq_cir_weights)[m_pif_base], weight);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::get_eir_weight(la_wfq_weight_t& out_weight) const
{
    bit_vector tmp_bv;
    la_status stat = m_device->m_ll_device->read_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_wfq_eir_weights)[m_slice_pif_base], tmp_bv);
    return_on_error(stat);

    out_weight = tmp_bv.get_value();

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_eir_weight(la_wfq_weight_t weight)
{
    start_api_call("weight=", weight);

    // set IfseWfqEirWeights[m_ifg_id * MAX_TM_PORT_TS + m_pif_base] register
    la_status stat = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->ifse_wfq_eir_weights)[m_slice_pif_base], weight);
    return_on_error(stat);

    // set IfseWfqEirWeights[m_pif_base] register
    stat = m_device->m_ll_device->write_register((*m_sch_ifse_wfq_eir_weights)[m_pif_base], weight);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::configure_rx_congestion()
{
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    ifgb_rx_link_cg_timer_cfg_register rx_link_cg_timer_cfg;

    rx_link_cg_timer_cfg.fields.link_cg_timer_gran = 128;
    rx_link_cg_timer_cfg.fields.link_cg_timer_cg_val = 16;
    rx_link_cg_timer_cfg.fields.link_cg_timer_no_cg_val = 4;

    status = m_device->m_ll_device->write_register(
        (*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_link_cg_timer_cfg)[m_tm_port_id],
        rx_link_cg_timer_cfg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_oqs_enabled(bool enabled)
{
    lld_memory_scptr oq_drop_bitmap(m_device->m_pacific_tree->slice[m_slice_id]->tx->cgm->oq_drop_bitmap);
    size_t num_uc_entries = oq_drop_bitmap->get_desc()->entries / 2;

    size_t uc_oq_line = m_slice_tm_port_id;
    size_t mc_oq_line = num_uc_entries + m_slice_tm_port_id;

    txcgm_oq_drop_bitmap_memory val;
    // Enable/disable all OQs. This behavior is assumed at la_voq_set_impl::flush.
    val.fields.oq_drop_bitmap_data = enabled ? 0x00 : 0xff;

    lld_memory_line_value_list_t mll;
    mll.push_back({{oq_drop_bitmap, uc_oq_line}, val});

    // Fabric MC traffic in LC fabric slice uses UC OQ, so don't open MC OQs.
    if ((m_device->m_device_mode != device_mode_e::LINECARD) || !m_is_fabric) {
        mll.push_back({{oq_drop_bitmap, mc_oq_line}, val});
    }

    la_status status = lld_write_memory_line_list(m_device->m_ll_device, mll);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_interface_scheduler_impl::type() const
{
    return object_type_e::INTERFACE_SCHEDULER;
}

la_mac_port::port_speed_e
la_interface_scheduler_impl::get_port_speed() const
{
    return m_speed;
}

std::string
la_interface_scheduler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_interface_scheduler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_interface_scheduler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_interface_scheduler_impl::get_device() const
{
    return m_device.get();
}

la_status
la_interface_scheduler_impl::set_pfc(bool pfc_on)
{
    la_status status;

    // Only modify scheduler parameters for PFC in 2.4T mode on the LC.
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    bool is_lc_type_2_4_t;
    status = m_device->get_bool_property(la_device_property_e::LC_TYPE_2_4_T, is_lc_type_2_4_t);
    return_on_error(status);

    // TODO: Temp remove gating
    if (true) {
        m_pfc = pfc_on;

        la_status status = initialize_txcgm();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::set_pfc_oq_profiles(la_uint8_t tc_bitmap)
{
    m_pfc_tc_bitmap = tc_bitmap;

    la_status status = initialize_txcgm();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_interface_scheduler_impl::get_pfc_oq_profiles(la_uint8_t& out_tc_bitmap)
{
    out_tc_bitmap = m_pfc_tc_bitmap;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
