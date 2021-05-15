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

#include "system/ifg_handler_pacific.h"
#include "common/bit_utils.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "hld_utils.h"
#include "hw_tables/memory_tcam.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_interface_scheduler_impl.h"

#include <cmath>
#include <iterator>

namespace silicon_one
{

static_assert((size_t)ifgb_rx_port0_cgm_sop_cfg_register::SIZE_IN_BITS == (size_t)ifgb_rx_port8_cgm_sop_cfg_register::SIZE_IN_BITS,
              "ifgb_rx_port0_cgm_sop_cfg_register and ifgb_rx_port8_cgm_sop_cfg_register dont match");

enum {
    // The shaper period used for frequency of 1200MHz
    DEFAULT_B0_OOBI_SHAPER_PERIOD = (150 * 1200000),
    TOTAL_FIFO_LINES = 3072,
    FTE_LINES = 16,
    FRM_LINES = 16,
    TX_FIFO_LINES_EXTRA_PIF = (1536 - 1232) / 4,
    MAC_POOL8_ENABLE_FC_BUG_FIX = 1,

    MAX_POLL_RX_FIFO = 10,
};

// Speed Gbps value in integer.
std::map<la_mac_port::port_speed_e, uint64_t> speed_value = {{la_mac_port::port_speed_e::E_10G, 10},
                                                             {la_mac_port::port_speed_e::E_25G, 25},
                                                             {la_mac_port::port_speed_e::E_40G, 40},
                                                             {la_mac_port::port_speed_e::E_50G, 50},
                                                             {la_mac_port::port_speed_e::E_100G, 100},
                                                             {la_mac_port::port_speed_e::E_200G, 200},
                                                             {la_mac_port::port_speed_e::E_400G, 400},
                                                             {la_mac_port::port_speed_e::E_800G, 800}};

ifg_handler_pacific::ifg_handler_pacific(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : ifg_handler_ifg(device, slice_id, ifg_id)
{
    m_pacific_tree = device->m_ll_device->get_pacific_tree_scptr();
    m_single_port_lines = 0;
    m_ifg_handler_common.m_num_port_tc_tcam_memories = 9;
    m_ifg_handler_common.m_tx_fifo_lines_main_pif = TX_FIFO_LINES_MAIN_PIF;
    m_ifg_handler_common.m_tc_tcam_key_width.resize(1);
    m_ifg_handler_common.m_tc_tcam_key_width[0] = ifgb_tc_tcam_memory::fields::TC_TCAM_KEY_WIDTH;
    m_ifg_handler_common.m_tc_ext_default_tc_width = ifgb_tc_extract_cfg_reg_register::fields::TC_EXT_DEFAULT_TC_WIDTH;

    synce_ifg_demap = {0, 1, 2, 3, 4, 5, 8, 7, 6, 11, 10, 9};
    synce_ifg_map = {0, 1, 2, 0, 1, 2, 2, 1, 0, 2, 1, 0};

    m_port_tc_tcam.resize(m_ifg_handler_common.m_num_port_tc_tcam_memories);
    m_ifgb_registers.tc_tcam.resize(1);
    m_ifgb_registers.tc_tcam_mem.resize(1);
}

void
ifg_handler_pacific::pre_initialize()
{

    m_ifg_handler_common.m_serdes_count = 18;
    m_ifg_handler_common.m_mac_lanes_reserved_count = 18;
    m_ifg_handler_common.m_pif_count = m_ifg_handler_common.m_serdes_count;
    m_ifg_handler_common.m_total_main_mac_lanes_reserved_count = 16;
    m_ifg_handler_common.m_pool_type = serdes_pool_type_e::pool_18;

    initialize_register_pointers();
}

ifg_handler_pacific::~ifg_handler_pacific()
{
}

la_status
ifg_handler_pacific::initialize()
{

    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(m_slice_id, m_ifg_id);
    return_on_error(stat);

    m_slice_mode = m_device->m_slice_mode[m_slice_id];

    stat = init_fifo_memory();
    return_on_error(stat);

    stat = reset_config();
    return_on_error(stat);

    stat = reset_fifo_memory_allocation();
    return_on_error(stat);

    stat = reset_read_schedule_weight();
    return_on_error(stat);

    stat = reset_oob_packet_counters();
    return_on_error(stat);

    stat = init_tcam_memories();
    return_on_error(stat);

    stat = set_synce_default();
    return_on_error(stat);

    m_synce_attached.fill(false);
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::initialize_topology()
{
    la_status status;

    mac_pool8_rstn_reg_register pool8_rstn_reg;
    mac_pool2_rstn_reg_register pool2_rstn_reg;

    bzero(&pool8_rstn_reg, mac_pool8_rstn_reg_register::SIZE);
    bzero(&pool2_rstn_reg, mac_pool2_rstn_reg_register::SIZE);

    pool8_rstn_reg.fields.rx_pma_rstn = 1;
    pool8_rstn_reg.fields.tx_pma_rstn = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn0 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn1 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn2 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn3 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn4 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn5 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn6 = 1;
    pool8_rstn_reg.fields.rx_rsf_rstn7 = 1;
    pool2_rstn_reg.fields.rx_pma_rstn = 1;
    pool2_rstn_reg.fields.tx_pma_rstn = 1;
    pool2_rstn_reg.fields.rx_rsf_rstn0 = 1;
    pool2_rstn_reg.fields.rx_rsf_rstn1 = 1;

    for (size_t mp8 = 0; mp8 < la_mac_port_base::NUM_MAC_POOL8_BLOCKS; mp8++) {
        status = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[mp8]->rstn_reg,
                                                       pool8_rstn_reg);
        return_on_error(status);

        if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
            status = m_device->m_ll_device->write_register(
                m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[mp8]->spare_reg, MAC_POOL8_ENABLE_FC_BUG_FIX);
            return_on_error(status);
        }
    }

    // mac_pool2
    status = m_device->m_ll_device->write_register(m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   pool2_rstn_reg);
    return_on_error(status);

    constexpr struct {
        size_t mac_pool8_0;
        size_t mac_pool8_1;
        size_t mac_pool2_0;
        size_t ifgb;
    } DEVICE_TIME_OFFSET_CFG[] = {
        {0x98, 0x9a, 0x97, 0x95},
        {0x8a, 0x8c, 0x89, 0x87},
        {0x7f, 0x81, 0x7e, 0x7c},
        {0x70, 0x72, 0x6f, 0x6d},
        {0x65, 0x67, 0x64, 0x62},
        {0x57, 0x59, 0x56, 0x54},
        {0x49, 0x4b, 0x48, 0x46},
        {0x3c, 0x3e, 0x3b, 0x39},
        {0x30, 0x32, 0x2f, 0x2d},
        {0x22, 0x24, 0x21, 0x1f},
        {0x16, 0x18, 0x15, 0x13},
        {0x09, 0x0b, 0x08, 0x06},
    };

    static_assert(array_size(DEVICE_TIME_OFFSET_CFG) == NUM_IFGS_PER_DEVICE,
                  "DEVICE_TIME_OFFSET_CFG table size does not match number of IFG-s.");

    // Predefined values were calculated for CALCULATED_VALUES_DEVICE_FREQUENCY. Need to adjust according to actual clock frequency.
    float device_freq_adjust = (float)CALCULATED_VALUES_DEVICE_FREQUENCY / m_device->m_device_frequency_int_khz;

    lld_register_value_list_t reg_val_list;
    size_t ifg_entry_num = (m_slice_id * 2) + m_ifg_id;
    reg_val_list.push_back({m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[0]->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].mac_pool8_0 * device_freq_adjust)});
    reg_val_list.push_back({m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[1]->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].mac_pool8_1 * device_freq_adjust)});
    reg_val_list.push_back({m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].mac_pool2_0 * device_freq_adjust)});
    reg_val_list.push_back({m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].ifgb * device_freq_adjust)});

    if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
        bool pacific_B0_changes_en;
        m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES, pacific_B0_changes_en);
        ifgb_rx_cfg0_register rx_cfg0_val{{0}};
        rx_cfg0_val.fields.rx_undersize_filter_en = 0xfffff;
        reg_val_list.push_back({m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_cfg0_val});

        ifgb_pacific_rev2_ifgb_fix_en_reg_register pacific_rev2_ifgb_fix_en_reg_val{{0}};
        pacific_rev2_ifgb_fix_en_reg_val.fields.rx_cgm_partial_drop_fix_en = bit_utils::ones(
            ifgb_pacific_rev2_ifgb_fix_en_reg_register::fields::RX_CGM_PARTIAL_DROP_FIX_EN_WIDTH); // bit per 400G port
        pacific_rev2_ifgb_fix_en_reg_val.fields.rx_cgm_sop_th_en
            = bit_utils::ones(ifgb_pacific_rev2_ifgb_fix_en_reg_register::fields::RX_CGM_SOP_TH_EN_WIDTH); // bit per 400G port
        pacific_rev2_ifgb_fix_en_reg_val.fields.rx_itc_fix = (pacific_B0_changes_en == false) ? 0x0 : 0x1;
        pacific_rev2_ifgb_fix_en_reg_val.fields.tx_o_obi_ts_pb_fix_en = 0x0;
        pacific_rev2_ifgb_fix_en_reg_val.fields.tx_400g_underrun_fix_en
            = bit_utils::ones(ifgb_pacific_rev2_ifgb_fix_en_reg_register::fields::TX_400G_UNDERRUN_FIX_EN_WIDTH);

        reg_val_list.push_back({m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->pacific_rev2_ifgb_fix_en_reg,
                                pacific_rev2_ifgb_fix_en_reg_val});

        ifgb_oobi_shaper_reg_register oobi_shaper_reg_val{{0}};
        oobi_shaper_reg_val.fields.oob_shaper_period = 0;
        oobi_shaper_reg_val.fields.oob_shaper_max_burst_size = DEFAULT_OOB_SHAPER_BURST_SIZE;
        for (int i = 0; i < NUM_OF_OOBI_SHAPERS; i++) {
            reg_val_list.push_back(
                {(*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->oobi_shaper_reg)[i], oobi_shaper_reg_val});
        }
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
ifg_handler_pacific::initialize_register_pointers()
{
    const auto& m_pacific_ifgb = m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb;

    m_ifgb_registers.fc_cfg0 = m_pacific_ifgb->fc_cfg0;
    m_ifgb_registers.rx_rstn_reg = m_pacific_ifgb->rx_rstn_reg;
    m_ifgb_registers.tx_rstn_reg = m_pacific_ifgb->tx_rstn_reg;
    m_ifgb_registers.tx_tsf_ovf_interrupt_reg = m_pacific_ifgb->tx_tsf_ovf_interrupt_reg;
    m_ifgb_registers.tc_tcam[0] = m_pacific_ifgb->tc_tcam;
    m_ifgb_registers.tc_tcam_mem[0] = m_pacific_ifgb->tc_tcam_mem;
    m_ifgb_registers.tx_fif_cfg = m_pacific_ifgb->tx_fif_cfg;
    m_ifgb_registers.tc_extract_cfg_reg = m_pacific_ifgb->tc_extract_cfg_reg;
    m_ifgb_registers.rx_port_cgm_tc0_drop_counter = m_pacific_ifgb->rx_port_cgm_tc0_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc1_drop_counter = m_pacific_ifgb->rx_port_cgm_tc1_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc2_drop_counter = m_pacific_ifgb->rx_port_cgm_tc2_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc3_drop_counter = m_pacific_ifgb->rx_port_cgm_tc3_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc0_partial_drop_counter = m_pacific_ifgb->rx_port_cgm_tc0_partial_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc1_partial_drop_counter = m_pacific_ifgb->rx_port_cgm_tc1_partial_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc2_partial_drop_counter = m_pacific_ifgb->rx_port_cgm_tc2_partial_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc3_partial_drop_counter = m_pacific_ifgb->rx_port_cgm_tc3_partial_drop_counter;
}

la_status
ifg_handler_pacific::configure_fabric_ports(la_mac_port::fc_mode_e fc_mode)
{
    // for each fabric port -> configure port
    for (size_t port = 0; port < NUM_FABRIC_PORTS_IN_NORMAL_IFG; port++) {
        la_status stat = configure_port(port * NUM_SERDES_PER_FABRIC_PORT,
                                        NUM_SERDES_PER_FABRIC_PORT,
                                        la_mac_port::port_speed_e::E_100G,
                                        NUM_SERDES_PER_FABRIC_PORT,
                                        la_mac_port::mlp_mode_e::NONE,
                                        fc_mode);
        return_on_error(stat);
    }

    bool is_borrower_ifg = m_device->is_borrower_ifg(m_slice_id, m_ifg_id);
    if (is_borrower_ifg) {
        ifgb_tx_10th_fab_link_cfg_register tx_10th_fab_link_cfg_reg{{0}};
        tx_10th_fab_link_cfg_reg.fields.tx_10th_flink_alm_empty_thd = ALMOST_EMPTY_THRESHOLD;

        la_status stat = m_device->m_ll_device->write_register(
            m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_10th_fab_link_cfg, tx_10th_fab_link_cfg_reg);
        return_on_error(stat);

        size_t port = IFG_BORROWED_FABRIC_PORT_NUM;
        stat = configure_lc_56_fabric_port(port * NUM_SERDES_PER_FABRIC_PORT,
                                           NUM_SERDES_PER_FABRIC_PORT,
                                           la_mac_port::port_speed_e::E_100G,
                                           NUM_SERDES_PER_FABRIC_PORT,
                                           la_mac_port::mlp_mode_e::NONE,
                                           fc_mode);
        return_on_error(stat);
    }

    if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
        bool pacific_oobi_en;
        m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING, pacific_oobi_en);
        ifgb_oobi_shaper_reg_register oobi_shaper_reg_val{{0}};
        size_t b0_shaper_period = DEFAULT_B0_OOBI_SHAPER_PERIOD / m_device->m_device_frequency_int_khz;
        oobi_shaper_reg_val.fields.oob_shaper_period = pacific_oobi_en ? b0_shaper_period : 0;
        oobi_shaper_reg_val.fields.oob_shaper_max_burst_size = DEFAULT_OOB_SHAPER_BURST_SIZE;
        for (int i = 0; i < NUM_OF_OOBI_SHAPERS; i++) {
            la_status stat = m_device->m_ll_device->write_register(
                (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->oobi_shaper_reg)[i], oobi_shaper_reg_val);
            return_on_error(stat);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_lc_56_fabric_port(la_uint_t mac_lane_base_id,
                                                 size_t mac_lanes_reserved_count,
                                                 la_mac_port::port_speed_e speed,
                                                 size_t mac_lanes_count,
                                                 la_mac_port::mlp_mode_e mlp_mode,
                                                 la_mac_port::fc_mode_e fc_mode)
{
    la_status stat;

    stat = configure_read_schedule_weight(mac_lane_base_id, mac_lanes_reserved_count, mlp_mode, speed);
    return_on_error(stat);

    // The FC and lanes should be configured on the lender IFG
    la_slice_id_t lender_slice_id = m_slice_id;
    la_ifg_id_t lender_ifg_id = m_ifg_id;
    la_uint_t lender_mac_lane_base_id = mac_lane_base_id;

    if ((m_slice_id == 3) && (m_ifg_id == 0)) {
        lender_slice_id = 2;
        lender_ifg_id = 1;
        lender_mac_lane_base_id = IFG_LENDED_SERDES_ID;
    }

    if ((m_slice_id == 5) && (m_ifg_id == 1)) {
        lender_slice_id = 0;
        lender_ifg_id = 0;
        lender_mac_lane_base_id = IFG_LENDED_SERDES_ID;
    }

    stat = m_device->m_ifg_handlers[lender_slice_id][lender_ifg_id]->set_fc_mode(
        lender_mac_lane_base_id, mac_lanes_reserved_count, speed, fc_mode);
    return_on_error(stat);

    stat = m_device->m_ifg_handlers[lender_slice_id][lender_ifg_id]->configure_mlp_mode(
        lender_mac_lane_base_id, speed, mac_lanes_count, mlp_mode);
    return_on_error(stat);

    stat = m_device->m_ifg_handlers[lender_slice_id][lender_ifg_id]->configure_lanes(
        lender_mac_lane_base_id, mac_lanes_count, speed);
    return_on_error(stat);

    if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
        bool pacific_oobi_en;
        m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING, pacific_oobi_en);
        ifgb_oobi_shaper_reg_register oobi_shaper_reg_val{{0}};
        size_t b0_shaper_period = DEFAULT_B0_OOBI_SHAPER_PERIOD / m_device->m_device_frequency_int_khz;
        oobi_shaper_reg_val.fields.oob_shaper_period = pacific_oobi_en ? b0_shaper_period : 0;
        oobi_shaper_reg_val.fields.oob_shaper_max_burst_size = DEFAULT_OOB_SHAPER_BURST_SIZE;
        stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[lender_slice_id]->ifg[lender_ifg_id]->ifgb->oobi_shaper_reg)[LENDED_IFG_LAST_SHAPER_ID],
            oobi_shaper_reg_val);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}
la_status
ifg_handler_pacific::configure_mlp_mode(la_uint_t mac_lane_base_id,
                                        la_mac_port::port_speed_e speed,
                                        size_t mac_lanes_count,
                                        la_mac_port::mlp_mode_e mlp_mode)
{
    ifgb_tx_cfg0_register tx_reg{{0}};
    ifgb_rx_cfg0_register rx_reg{{0}};
    la_status stat;

    // This MAC pool port control only part of the bits, need to read and modify only the relevant bits.
    stat = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    if (mlp_mode == la_mac_port::mlp_mode_e::MLP_MASTER) {
        tx_reg.fields.tx_mlp_en = 1;
        rx_reg.fields.rx_mlp_en = tx_reg.fields.tx_mlp_en;
    }

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_lanes(la_uint_t mac_lane_base_id, size_t mac_lanes_count, la_mac_port::port_speed_e speed)
{
    ifgb_tx_cfg0_register tx_reg{{0}};
    ifgb_rx_cfg0_register rx_reg{{0}};
    la_status stat;

    // This MAC pool port control only part of the bits, need to read and modify only the relevant bits.
    stat = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    uint64_t two_lane_mode = tx_reg.fields.tx_2l_mode;
    uint64_t eight_lane_mode = tx_reg.fields.tx_8l_mode;
    stat = update_lane_modes(mac_lane_base_id, mac_lanes_count, two_lane_mode, eight_lane_mode);
    return_on_error(stat);

    tx_reg.fields.tx_2l_mode = two_lane_mode;
    tx_reg.fields.tx_8l_mode = eight_lane_mode;

    rx_reg.fields.rx_2l_mode = tx_reg.fields.tx_2l_mode;
    rx_reg.fields.rx_8l_mode = tx_reg.fields.tx_8l_mode;

    if (m_device_revision == la_device_revision_e::PACIFIC_A0) {
        // The undersize filter should be enabled on all active port lanes.
        // Pacific A0 has two bugs related to this filter:
        // 1. 100G ports (both 2x50 and 4x25) may get corrupted if filter is on.
        // 2. 400G port on mac_lane 8-15 using bit[1] instead of bit[8]
        // Basically, if the first bug wasn't there we should have just turn on the undersize filter.
        // But, for 100G port we shouldn't. Unfortunately bit[1] is also relevant for 100G ports.
        // So, the solution, is to set bit[1] for 400G port which using mac_lane 8-15. This implies a limitation of using this port
        // and 100G port which uses mac_lane 1
        // for Pacific_B0 this is been set at device initialization
        uint64_t filter = bit_utils::get_range_mask(mac_lane_base_id, mac_lanes_count);
        if ((speed == la_mac_port::port_speed_e::E_400G) && (mac_lane_base_id == 8)) {
            filter = bit_utils::set_bit(filter, 1, true);
        }
        rx_reg.fields.rx_undersize_filter_en &= ~filter;
        if (speed != la_mac_port::port_speed_e::E_100G) {
            rx_reg.fields.rx_undersize_filter_en |= filter;
        }
    }

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::reset_fifo_memory(size_t mac_lane_base,
                                       size_t mac_lanes_reserved_count,
                                       size_t mac_lanes_count,
                                       la_mac_port_base::mac_reset_state_e reset)
{
    la_status status;
    bool is_lender_ifg = m_device->is_lender_ifg(m_slice_id, m_ifg_id);
    bool is_potentially_lended_port = (mac_lane_base == IFG_LENDED_SERDES_ID);
    // In LC_56_FABRIC_PORT_MODE fifo memory reset is different
    if (is_lender_ifg && is_potentially_lended_port) {

        la_status stat = reset_fifo_memory_lc56(mac_lane_base, mac_lanes_reserved_count, reset);
        return_on_error(stat);

    } else {

        // Read Rx & Tx reset registers
        bit_vector rx_rstn_reg;
        bit_vector tx_rstn_reg;

        status = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_rstn_reg,
                                                      rx_rstn_reg);
        return_on_error(status);

        status = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg,
                                                      tx_rstn_reg);
        return_on_error(status);

        bool tx_rstn_bit = (reset != la_mac_port_base::mac_reset_state_e::RESET_ALL);
        bool rx_rstn_bit = (reset == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);

        // Reset to single port mode
        for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
            // Due to a bug in A0 HW, the rx_lane_rstn in a fabric slice cannot move to reset single port.
            // Change Rx reset bit only for B0 or network port or to activate
            if ((m_device_revision != la_device_revision_e::PACIFIC_A0) || (m_slice_mode != la_slice_mode_e::CARRIER_FABRIC)
                || (reset == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL)) {
                rx_rstn_reg.set_bit(mac_lane_base + mac_lane, rx_rstn_bit);
            }

            tx_rstn_reg.set_bit(mac_lane_base + mac_lane, tx_rstn_bit);
        }

        // If changing to Rx reset, check that the Rx fifo is empty
        if (rx_rstn_bit) {
            ifgb_rx_fifo_wmk_register rx_fifo_wmk{{0}};

            for (int i = 0; i < MAX_POLL_RX_FIFO; i++) {
                status = m_device->m_ll_device->read_register(
                    (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_fifo_wmk)[mac_lane_base], rx_fifo_wmk);
                if (rx_fifo_wmk.fields.port_rx_fifo_wmk == 0) {
                    break;
                } else if (i > 0) {
                    log_err(HLD,
                            "Slice/IFG/SerDes (%d/%d/%zd) - IFGB Rx FIFO not empty ([%d] size %ld)",
                            m_slice_id,
                            m_ifg_id,
                            mac_lane_base,
                            i,
                            rx_fifo_wmk.fields.port_rx_fifo_wmk);
                }

                return_on_error(status);
            }
        }

        status = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_rstn_reg,
                                                       rx_rstn_reg);
        return_on_error(status);

        status = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg,
                                                       tx_rstn_reg);
        return_on_error(status);
    }

    if (reset == la_mac_port_base::mac_reset_state_e::RESET_ALL) {
        la_mac_port* mac_port;
        m_device->get_mac_port(m_slice_id, m_ifg_id, mac_lane_base, mac_port);
        if (mac_port) {
            la_interface_scheduler_impl* intf_sch = static_cast<la_interface_scheduler_impl*>(mac_port->get_scheduler());
            if (intf_sch) {
                intf_sch->reset_fdoq_credits();
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::reset_fifo_memory_lc56(size_t mac_lane_base,
                                            size_t mac_lanes_reserved_count,
                                            la_mac_port_base::mac_reset_state_e reset)
{
    // Read Rx & Tx reset registers
    la_status status;
    ifgb_rx_rstn_reg_register rx_rstn_reg{{0}};
    ifgb_general_rstn_reg_register general_rstn_reg{{0}};
    bit_vector tx_rstn_reg;

    la_device_impl::lc_56_fabric_port_info fabric_port_info
        = m_device->get_borrowed_fabric_port_info(m_slice_id, m_ifg_id, mac_lane_base);
    if (!fabric_port_info.is_lc_56_fabric_port) {
        return LA_STATUS_EUNKNOWN;
    }

    status = m_device->m_ll_device->read_register(
        m_pacific_tree->slice[fabric_port_info.slice_id]->ifg[fabric_port_info.ifg_id]->ifgb->rx_rstn_reg, rx_rstn_reg);
    return_on_error(status);

    status = m_device->m_ll_device->read_register(
        m_pacific_tree->slice[fabric_port_info.slice_id]->ifg[fabric_port_info.ifg_id]->ifgb->general_rstn_reg, general_rstn_reg);
    return_on_error(status);

    status = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg, tx_rstn_reg);
    return_on_error(status);

    // Due to a bug in A0 HW, the rx_lane_rstn in a fabric slice cannot move to reset single port.
    // Change Rx reset bit only for B0 or to activate
    bool rx_rstn_bit_val = (reset == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
    if ((m_device_revision != la_device_revision_e::PACIFIC_A0) || (reset == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL)) {
        rx_rstn_reg.fields.rx_ibi_rstn = rx_rstn_bit_val;
    }

    bool tx_rstn_bit = (reset != la_mac_port_base::mac_reset_state_e::RESET_ALL);
    general_rstn_reg.fields.rcy_rstn = tx_rstn_bit;
    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        tx_rstn_reg.set_bit(mac_lane_base + mac_lane, tx_rstn_bit);
    }

    status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[fabric_port_info.slice_id]->ifg[fabric_port_info.ifg_id]->ifgb->rx_rstn_reg, rx_rstn_reg);
    return_on_error(status);

    status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[fabric_port_info.slice_id]->ifg[fabric_port_info.ifg_id]->ifgb->general_rstn_reg, general_rstn_reg);
    return_on_error(status);

    status
        = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg, tx_rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_read_schedule_weight(la_uint_t mac_lane_base_id,
                                                    size_t mac_lanes_reserved_count,
                                                    la_mac_port::mlp_mode_e mlp_mode,
                                                    la_mac_port::port_speed_e speed)
{
    uint64_t read_weight = read_schedule_weight.at(speed);

    if (mac_lane_base_id < m_ifg_handler_common.m_total_main_mac_lanes_reserved_count) {
        if (mlp_mode == la_mac_port::mlp_mode_e::MLP_SLAVE) {
            // Must be 0 as well
            read_weight = 0;
        }
        return configure_read_schedule_weight_main_ports(mac_lane_base_id, mac_lanes_reserved_count, read_weight);
    } else {
        return configure_read_schedule_weight_extra_ports(mac_lane_base_id, mac_lanes_reserved_count, read_weight);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::reset_read_schedule_weight(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count)
{
    if (mac_lane_base_id < m_ifg_handler_common.m_total_main_mac_lanes_reserved_count) {
        return configure_read_schedule_weight_main_ports(mac_lane_base_id, mac_lanes_reserved_count, 0 /* read_weight */);
    } else {
        return configure_read_schedule_weight_extra_ports(mac_lane_base_id, mac_lanes_reserved_count, 0 /* read_weight */);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_tx_calendar()
{
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_fc_mode_periodic(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable)
{
    ifgb_fc_cfg0_register fc_cfg0_reg{{0}};

    la_status stat
        = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
    return_on_error(stat);

    uint64_t reg_val = fc_cfg0_reg.fields.periodic_int_en;

    bit_utils::set_bit(&reg_val, mac_lane_base_id, enable);
    for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        bit_utils::set_bit(&reg_val, mac_lane_base_id + mac_lane, false);
    }

    fc_cfg0_reg.fields.periodic_int_en = reg_val;

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_fc_mode_port(la_uint_t mac_lane_base_id,
                                      size_t mac_lanes_reserved_count,
                                      la_mac_port::port_speed_e speed,
                                      la_mac_port::fc_mode_e fc_mode)
{
    lld_register_value_list_t reg_val_list;

    ifgb_fc_port_cfg0_register fc_port_cfg0{{0}};
    ifgb_fc_port_cfg2_register fc_port_cfg2{{0}};

    fc_port_cfg0.fields.port_watch_dog_timer = s_fc_mode_periodic_config[(size_t)fc_mode].port_watch_dog_timer;
    fc_port_cfg0.fields.port_pause_mask = 0xFF;

    fc_port_cfg0.fields.port_fc_mode = flow_control_code[(size_t)fc_mode];

    fc_port_cfg0.fields.port_512bit_time = ceil(m_device->m_device_frequency_float_ghz * FLOW_CONTROL_BITS / speed_value.at(speed));
    fc_port_cfg2.fields.port_ostc_priority_map = flow_control_priority_map[(size_t)fc_mode];

    const auto& ifgb = m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb;

    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        // For PFC, user may overwrite default periodic timer value
        if (fc_mode == la_mac_port::fc_mode_e::PFC) {
            fc_port_cfg0.fields.port_periodic_timer = m_pfc_pif_periodic_timer_map[mac_lane_base_id + mac_lane];
        } else {
            fc_port_cfg0.fields.port_periodic_timer = s_fc_mode_periodic_config[(size_t)fc_mode].port_periodic_timer;
        }
        reg_val_list.push_back({(*ifgb->fc_port_cfg0)[mac_lane_base_id + mac_lane], fc_port_cfg0});
        reg_val_list.push_back({(*ifgb->fc_port_cfg2)[mac_lane_base_id + mac_lane], fc_port_cfg2});
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_port_periodic_timer_value(la_uint_t mac_lane_base_id,
                                                   size_t mac_lanes_reserved_count,
                                                   la_uint_t timer_value)
{
    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        auto fc_port_cfg_0 = (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_port_cfg0)[mac_lane_base_id + mac_lane];
        ifgb_fc_port_cfg0_register fc_port_cfg0{{0}};

        la_status status = m_device->m_ll_device->read_register(*fc_port_cfg_0, fc_port_cfg0);
        return_on_error(status);

        // Only update timer value in HW if we are in FC mode
        if (fc_port_cfg0.fields.port_fc_mode == (size_t)la_mac_port::fc_mode_e::PFC) {
            fc_port_cfg0.fields.port_periodic_timer = timer_value;
            status = m_device->m_ll_device->write_register(fc_port_cfg_0, fc_port_cfg0);
            return_on_error(status);
        }

        m_pfc_pif_periodic_timer_map[mac_lane_base_id + mac_lane] = timer_value;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_port_periodic_int_enable(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable)
{
    ifgb_fc_cfg0_register fc_cfg0_reg{{0}};
    la_status status
        = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
    return_on_error(status);

    ifgb_fc_port_cfg0_register fc_port_cfg0{{0}};
    status = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_port_cfg0)[mac_lane_base_id], fc_port_cfg0);

    if (fc_port_cfg0.fields.port_fc_mode == (size_t)la_mac_port::fc_mode_e::PFC) {

        uint64_t reg_val = fc_cfg0_reg.fields.periodic_int_en;

        bit_utils::set_bit(&reg_val, mac_lane_base_id, enable);
        for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
            bit_utils::set_bit(&reg_val, mac_lane_base_id + mac_lane, false);
        }

        fc_cfg0_reg.fields.periodic_int_en = reg_val;

        status
            = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
        return_on_error(status);
    }

    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        m_pfc_pif_en_periodic_send_map[mac_lane_base_id + mac_lane] = enable;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::allocate_rx_fifo_memory(size_t mac_lane_base, size_t buffer_units)
{
    /*******************************************************************************
     * The Rx buffer is shared for all the mac_lane's of the same port.
     * The buffer is the allocation per mac_lane times number of mac_lane in the port.
     *
     * The buffer is actually two buffers separated as following:
     * Buffer 0: ports 0-7, 16,17
     * Buffer 1: ports 8-15, Host port
     ******************************************************************************/
    ifgb_rx_port_fifo_cfg_register rx_port_reg{{0}};

    bzero(&rx_port_reg, ifgb_rx_port_fifo_cfg_register::SIZE);

    size_t start_idx = (mac_lane_base < 16) ? mac_lane_base % 8 : mac_lane_base - 8;
    rx_port_reg.fields.f_start_addr = start_idx * m_single_port_lines;
    rx_port_reg.fields.f_end_addr = rx_port_reg.fields.f_start_addr + buffer_units * m_single_port_lines - 1;

    for (size_t i = 0; i < buffer_units; i++) {
        la_status stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_fifo_cfg)[i + mac_lane_base], rx_port_reg);
        return_on_error(stat);
    }
    return LA_STATUS_SUCCESS;
}

/*******************************************************
 * Configure RX thresholds:
 * Threshold 0-3: 100% - 1
 * XOn  Threshold: flow_control_default_xon
 * XOff Threshold: flow_control_default_xoff
 */
la_status
ifg_handler_pacific::configure_rx_cgm(size_t mac_lane_base, size_t buffer_units, la_mac_port::port_speed_e speed)
{
    ifgb_rx_port_cgm_cfg_register rx_cgm_reg{{0}};

    size_t fifo_size = m_single_port_lines * buffer_units;
    size_t rx_cgm_max_threshold = (speed == la_mac_port::port_speed_e::E_400G) ? fifo_size - 10 : fifo_size - 1;

    rx_cgm_reg.fields.p_tc0_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_tc1_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_tc2_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_tc3_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_xon_th = (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) ? 220 : fifo_size * flow_control_default_xon;
    rx_cgm_reg.fields.p_xoff_th = (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) ? 240 : fifo_size * flow_control_default_xoff;

    for (size_t i = 0; i < buffer_units; i++) {
        la_status stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[i + mac_lane_base], rx_cgm_reg);
        return_on_error(stat);
    }

    if (((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1))
        && (speed == la_mac_port::port_speed_e::E_400G)) {
        ifgb_rx_port0_cgm_sop_cfg_register rx_port_cgm_sop_cfg_val;
        size_t sop_drop_threshold = rx_cgm_max_threshold - 8; // 8 word in Rx buffer. in units of 128B
        rx_port_cgm_sop_cfg_val.fields.p0_tc0_sop_drop_th = sop_drop_threshold;
        rx_port_cgm_sop_cfg_val.fields.p0_tc1_sop_drop_th = sop_drop_threshold;
        rx_port_cgm_sop_cfg_val.fields.p0_tc2_sop_drop_th = sop_drop_threshold;
        rx_port_cgm_sop_cfg_val.fields.p0_tc3_sop_drop_th = sop_drop_threshold;
        la_status stat = LA_STATUS_SUCCESS;
        if (mac_lane_base == 0) {
            stat = m_device->m_ll_device->write_register(
                m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port0_cgm_sop_cfg, rx_port_cgm_sop_cfg_val);
        } else if (mac_lane_base == 8) {
            stat = m_device->m_ll_device->write_register(
                m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port8_cgm_sop_cfg, rx_port_cgm_sop_cfg_val);
        }

        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::allocate_tx_fifo_memory_main_ports(size_t mac_lane_base, size_t mac_lanes_reserved_count)
{
    ifgb_tx_fif_cfg_register tx_fif_reg{{0}};

    bzero(&tx_fif_reg, ifgb_tx_fif_cfg_register::SIZE);

    tx_fif_reg.fields.tx_f_start_addr = m_ifg_handler_common.m_tx_fifo_lines_main_pif * mac_lane_base;
    tx_fif_reg.fields.tx_f_end_addr
        = tx_fif_reg.fields.tx_f_start_addr + m_ifg_handler_common.m_tx_fifo_lines_main_pif * mac_lanes_reserved_count - 1;
    tx_fif_reg.fields.tx_alm_empty_thd = ALMOST_EMPTY_THRESHOLD;

    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        la_status stat
            = m_device->m_ll_device->write_register((*m_ifgb_registers.tx_fif_cfg)[mac_lane_base + mac_lane], tx_fif_reg);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::allocate_tx_fifo_memory_extra_ports(size_t mac_lane_base, size_t mac_lanes_reserved_count)
{
    ifgb_tx_fif_cfg16_register tx_fif_reg{{0}};

    bzero(&tx_fif_reg, ifgb_tx_fif_cfg16_register::SIZE);

    tx_fif_reg.fields.tx_f16_start_addr
        = m_ifg_handler_common.m_tx_fifo_lines_main_pif * m_ifg_handler_common.m_total_main_mac_lanes_reserved_count
          + TX_FIFO_LINES_EXTRA_PIF * (mac_lane_base - m_ifg_handler_common.m_total_main_mac_lanes_reserved_count);
    tx_fif_reg.fields.tx_f16_end_addr
        = tx_fif_reg.fields.tx_f16_start_addr + TX_FIFO_LINES_EXTRA_PIF * mac_lanes_reserved_count - 1;
    tx_fif_reg.fields.tx_alm_empty_thd16 = ALMOST_EMPTY_THRESHOLD;

    lld_register_scptr device_tx_fif_reg = nullptr;

    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        switch (mac_lane + mac_lane_base) {
        case 16:
            device_tx_fif_reg = (m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_fif_cfg16);
            break;
        case 17:
            device_tx_fif_reg = (m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_fif_cfg17);
            break;
        case 18:
            // Next iteration does nothing - no need to restore to default value after assignment
            tx_fif_reg.fields.tx_alm_empty_thd16 = 0;
            device_tx_fif_reg = (m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_fif_cfg18);
            break;
        case 19:
            // mac_lane 18 is host port and configured as 2x50G. There is no configuration for mac_lane 19
            continue;
        default:
            return LA_STATUS_EINVAL;
        };

        la_status stat = m_device->m_ll_device->write_register(*device_tx_fif_reg, tx_fif_reg);
        if (stat != LA_STATUS_SUCCESS) {
            log_err(HLD,
                    "allocate_tx_fifo_memory_extra_ports: base=%ld, count=%ld, mac_lane=%ld",
                    mac_lane_base,
                    mac_lanes_reserved_count,
                    mac_lane);
            return stat;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::reset_config()
{
    log_debug(HLD, "ifg_handler_pacific::reset_config()");
    lld_register_value_list_t reg_val_list;

    ifgb_tx_cfg0_register tx_reg;
    ifgb_rx_cfg0_register rx_reg;

    bzero(&tx_reg, ifgb_tx_cfg0_register::SIZE);
    bzero(&rx_reg, ifgb_rx_cfg0_register::SIZE);

    rx_reg.fields.rx_8l_mode = tx_reg.fields.tx_8l_mode = 0;
    rx_reg.fields.rx_mlp_en = tx_reg.fields.tx_mlp_en = 0;
    tx_reg.fields.tx_fabric_10p_mode = 0;

    rx_reg.fields.rx_fifo_status_sel = tx_reg.fields.tx_fifo_status_sel = 0;
    if ((m_device_revision != la_device_revision_e::PACIFIC_B0) && (m_device_revision != la_device_revision_e::PACIFIC_B1)) {
        rx_reg.fields.rx_undersize_filter_en = 0;
    } else {
        rx_reg.fields.rx_undersize_filter_en = 0xfffff;
    }

    if (m_device->is_network_slice(m_slice_id)) {
        bool is_lender_ifg = m_device->is_lender_ifg(m_slice_id, m_ifg_id);

        tx_reg.fields.tx_2l_mode = 0;
        tx_reg.fields.tx_fabric_mode = 0;
        rx_reg.fields.rx_data_ecc_err_en = tx_reg.fields.tx_data_ecc_err_en = 0;
        rx_reg.fields.rx_oob_intrlv_en = tx_reg.fields.tx_oob_intrlv_en = 0;

        if (is_lender_ifg == true) {
            tx_reg.fields.tx_2l_mode = (1 << (IFG_LENDED_SERDES_ID / 2)); // == 0x100
            tx_reg.fields.tx_fabric_10p_mode = 1;

            bool pacific_oobi_en;
            m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING, pacific_oobi_en);
            if (((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1))
                && pacific_oobi_en) {
                // rx_oob_intrlv_en has bit per mac_lane. for lender ifg bits 18:19 should be set
                rx_reg.fields.rx_oob_intrlv_en = 0x3 << 18;
                // tx_oob_intrlv_en has bit per mac_lane. for lender ifg bits 16:17 should be set
                tx_reg.fields.tx_oob_intrlv_en = 0x3 << 16;
            }
        }
        // Header size configuration: Add a configurable size of header to received data. 0B-40B in 8B granularity. Must be 0-5.
        // Configure all ports to 5 (40 bytes)
        reg_val_list.push_back(
            {m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->header_size_reg, bit_vector("0x2DB6DB6DB6DB6DB6D")});
    } else {

        bool is_borrower_ifg = m_device->is_borrower_ifg(m_slice_id, m_ifg_id);

        // Fabric
        tx_reg.fields.tx_2l_mode = 0x1FF;
        tx_reg.fields.tx_fabric_mode = 1;
        bool pacific_oobi_en;
        m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING, pacific_oobi_en);
        // *x_oob_intrlv_en has bit per mac_lane. should be aligned with mac_pool*.*x_cfg0[i], i == mac_lane index
        // OOB interleave is disabled in Pacific A0 because of HW limitation
        if (m_device_revision == la_device_revision_e::PACIFIC_A0 || !pacific_oobi_en) {
            rx_reg.fields.rx_oob_intrlv_en = 0;
            tx_reg.fields.tx_oob_intrlv_en = 0;
        } else {
            rx_reg.fields.rx_oob_intrlv_en = 0xfffff;
            tx_reg.fields.tx_oob_intrlv_en = 0x3ffff;
        }

        rx_reg.fields.rx_data_ecc_err_en = tx_reg.fields.tx_data_ecc_err_en = 0;

        if (is_borrower_ifg == true) {
            tx_reg.fields.tx_fabric_10p_mode = 1;
        }

        // Header size configuration: Add a configurable size of header to received data. 0B-40B in 8B granularity. Must be 0-5.
        // Configure all ports to 0 (0 bytes)
        reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->header_size_reg), 0});
    }

    rx_reg.fields.rx_2l_mode = tx_reg.fields.tx_2l_mode;
    rx_reg.fields.rx_fabric_mode = tx_reg.fields.tx_fabric_mode;
    rx_reg.fields.rx_fabric_10p_mode = tx_reg.fields.tx_fabric_10p_mode;

    reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0), tx_reg});

    reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0), rx_reg});

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

/*******************************************************
 * Rx FIFO has actually two buffers:
 * Buffer 0: ports 0-7, 16,17, OOB
 * Buffer 1: ports 8-15, Host port, OOB
 */
la_status
ifg_handler_pacific::reset_rx_fifo_memory_allocation()
{
    log_debug(HLD, "ifg_handler_pacific::reset_rx_fifo_memory_allocation()");

    size_t total_lines_to_allocate = TOTAL_FIFO_LINES;
    size_t csms_lines = 0;
    size_t fte_lines = 0;
    size_t frm_lines = 0;
    size_t host_lines = 0;
    size_t host_ports = 0;
    size_t total_ports = 0;

    if (m_device->is_network_slice(m_slice_id)) {
        host_ports = 2;
    } else {
        host_ports = 2;
        csms_lines = CSMS_LINES;
        fte_lines = FTE_LINES;
        frm_lines = FRM_LINES;
    }

    total_ports = NUM_SERDES_PER_IFG + host_ports;
    total_lines_to_allocate -= 2 * (csms_lines + fte_lines + frm_lines); // There are 2 buffers
    m_single_port_lines = total_lines_to_allocate / total_ports;

    host_lines = m_single_port_lines * host_ports;

    la_status stat;

    stat = configure_rx_fifo_ports();
    return_on_error(stat);

    stat = configure_rx_fifo_host_port(host_lines);
    return_on_error(stat);

    stat = configure_rx_fifo_out_of_band(csms_lines, fte_lines, frm_lines);
    return_on_error(stat);

    stat = configure_recycle_fifo();
    return_on_error(stat);

    stat = configure_rx_out_of_band_cgm(csms_lines, fte_lines, frm_lines);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_rx_fifo_ports()
{
    ifgb_rx_port_fifo_cfg_register rx_port_reg{{0}};

    bzero(&rx_port_reg, ifgb_rx_port_fifo_cfg_register::SIZE);

    for (size_t i = 0; i < 8; i++) {
        rx_port_reg.fields.f_start_addr = i * m_single_port_lines;
        rx_port_reg.fields.f_end_addr = rx_port_reg.fields.f_start_addr + m_single_port_lines - 1;

        la_status stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_fifo_cfg)[i], rx_port_reg);
        return_on_error(stat);
        stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_fifo_cfg)[i + 8], rx_port_reg);
        return_on_error(stat);
    }

    for (size_t i = 16; i < NUM_SERDES_PER_IFG; i++) {
        rx_port_reg.fields.f_start_addr = (i - 8) * m_single_port_lines;
        rx_port_reg.fields.f_end_addr = rx_port_reg.fields.f_start_addr + m_single_port_lines - 1;

        la_status stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_fifo_cfg)[i], rx_port_reg);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_rx_fifo_host_port(size_t host_lines)
{
    lld_register_value_list_t reg_val_list;

    ifgb_rx_ibi_fifo_cfg_register rx_ibi_reg;
    ifgb_rx_port18_cgm_cfg_register rx_port18_cgm_reg;

    bzero(&rx_ibi_reg, ifgb_rx_ibi_fifo_cfg_register::SIZE);
    bzero(&rx_port18_cgm_reg, ifgb_rx_port18_cgm_cfg_register::SIZE);

    rx_ibi_reg.fields.ibif_start_addr = 8 * m_single_port_lines;
    rx_ibi_reg.fields.ibif_end_addr = rx_ibi_reg.fields.ibif_start_addr + host_lines - 1;

    reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_ibi_fifo_cfg), rx_ibi_reg});

    /*******************************************************
     * Configure RX CGM thresholds for host port:
     * Threshold: 100% - 1
     * XOn  Threshold: flow_control_default_xon
     * XOff Threshold: flow_control_default_xon
     */
    rx_port18_cgm_reg.fields.p18_drop_th = host_lines - 1;
    rx_port18_cgm_reg.fields.p18_xon_th = host_lines * flow_control_default_xon;
    rx_port18_cgm_reg.fields.p18_xoff_th = host_lines * flow_control_default_xoff;

    reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port18_cgm_cfg), rx_port18_cgm_reg});

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_rx_fifo_out_of_band(size_t csms_lines, size_t fte_lines, size_t frm_lines)
{
    lld_register_value_list_t reg_val_list;

    ifgb_rx_o_ob_fifo_cfg_register rx_oob_reg;
    ifgb_rx_oob_cgm_cfg_register rx_oob_cgm_reg;

    bzero(&rx_oob_reg, ifgb_rx_o_ob_fifo_cfg_register::SIZE);
    bzero(&rx_oob_cgm_reg, ifgb_rx_oob_cgm_cfg_register::SIZE);

    if (m_device->is_network_slice(m_slice_id)) {
        // Relevant only in fabric mode
        return LA_STATUS_SUCCESS;
    }

    size_t base = 10 * m_single_port_lines;

    rx_oob_reg.fields.csms_f_start_addr = base;
    base += csms_lines;
    rx_oob_reg.fields.csms_f_end_addr = base - 1;

    rx_oob_reg.fields.fte_f_start_addr = base;
    base += fte_lines;
    rx_oob_reg.fields.fte_f_end_addr = base - 1;

    rx_oob_reg.fields.frm_f_start_addr = base;
    base += frm_lines;
    rx_oob_reg.fields.frm_f_end_addr = base - 1;

    rx_oob_cgm_reg.fields.csms_drop_th = csms_lines / 2;
    rx_oob_cgm_reg.fields.fte_drop_th = fte_lines / 2;
    rx_oob_cgm_reg.fields.frm_drop_th = frm_lines / 2;

    for (size_t i = 0; i < 2; i++) {
        reg_val_list.push_back({(*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_o_ob_fifo_cfg)[i], rx_oob_reg});
        reg_val_list.push_back({(*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_oob_cgm_cfg)[i], rx_oob_cgm_reg});
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_rx_out_of_band_cgm(size_t csms_lines, size_t fte_lines, size_t frm_lines)
{
    ifgb_rx_oob_cgm_cfg_register rx_oob_cgm_reg{{0}};

    if (m_device->is_network_slice(m_slice_id)) {
        // Relevant only in fabric mode
        return LA_STATUS_SUCCESS;
    }

    // Configure the drop thresholds to be the max size of the buffer.
    rx_oob_cgm_reg.fields.csms_drop_th = csms_lines / 2;
    rx_oob_cgm_reg.fields.fte_drop_th = fte_lines / 2;
    rx_oob_cgm_reg.fields.frm_drop_th = frm_lines / 2;

    for (size_t i = 0; i < 2; i++) {
        la_status stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_oob_cgm_cfg)[i], rx_oob_cgm_reg);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_recycle_fifo()
{
    ifgb_rcy_fif_cfg_register rcy_fif_cfg_reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rcy_fif_cfg,
                                                          rcy_fif_cfg_reg);
    return_on_error(stat);

    rcy_fif_cfg_reg.fields.rcy_fif_mirror_wr_sop_thd = 86;
    rcy_fif_cfg_reg.fields.rcy_fif_redirect_wr_sop_thd = 86;
    rcy_fif_cfg_reg.fields.rcy_fif_sched_wr_sop_thd = 0x3FF;

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rcy_fif_cfg,
                                                 rcy_fif_cfg_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::reset_read_schedule_weight()
{
    log_debug(HLD, "ifg_handler_pacific::reset_read_schedule_weight()");

    ifgb_rx_read_sch_cfg0_register rx_read_sch0;
    ifgb_rx_read_sch_cfg1_register rx_read_sch1;
    ifgb_rx_read_sch_cfg2_register rx_read_sch2;

    bzero(&rx_read_sch0, ifgb_rx_read_sch_cfg0_register::SIZE);
    bzero(&rx_read_sch1, ifgb_rx_read_sch_cfg1_register::SIZE);
    bzero(&rx_read_sch2, ifgb_rx_read_sch_cfg2_register::SIZE);

    // Initialize all regular port to 0.
    // Initialize host and all recycle to 100Gbps.
    rx_read_sch2.fields.rd_sch_wt_p18 = read_schedule_weight.at(la_mac_port::port_speed_e::E_100G);
    rx_read_sch2.fields.rd_sch_wt_sch_rcy = read_schedule_weight.at(la_mac_port::port_speed_e::E_100G);
    rx_read_sch2.fields.rd_sch_wt_mirror_rcy = read_schedule_weight.at(la_mac_port::port_speed_e::E_100G);
    rx_read_sch2.fields.rd_sch_wt_redirect_rcy = read_schedule_weight.at(la_mac_port::port_speed_e::E_100G);
    rx_read_sch2.fields.rd_sch_wt_rcy_aggr = read_schedule_weight.at(la_mac_port::port_speed_e::E_100G);

    la_status stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg0,
                                                           rx_read_sch0);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg1,
                                                 rx_read_sch1);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg2,
                                                 rx_read_sch2);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_read_schedule_weight_main_ports(la_uint_t mac_lane_base_id,
                                                               size_t mac_lanes_reserved_count,
                                                               uint64_t read_weight)
{
    la_uint_t mac_pool_base_id = mac_lane_base_id % 8;

    ifgb_rx_read_sch_cfg0_register rx_read_sch{{0}};

    lld_register_scptr device_rx_read_sch_reg = nullptr;

    size_t reg_idx = mac_lane_base_id / 8;
    switch (reg_idx) {
    case 0:
        device_rx_read_sch_reg = (m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg0);
        break;
    case 1:
        device_rx_read_sch_reg = (m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg1);
        break;
    default:
        return LA_STATUS_EINVAL;
    };

    // Read
    la_status stat = m_device->m_ll_device->read_register(device_rx_read_sch_reg, rx_read_sch);
    return_on_error(stat);

    // Modify
    // Insert the total weight to the first one
    rx_read_sch.u8[mac_pool_base_id] = read_weight;
    // Zero out all the rest
    for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        rx_read_sch.u8[mac_pool_base_id + mac_lane] = 0;
    }

    // Write
    stat = m_device->m_ll_device->write_register(device_rx_read_sch_reg, rx_read_sch);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_read_schedule_weight_extra_ports(la_uint_t mac_lane_base_id,
                                                                size_t mac_lanes_reserved_count,
                                                                uint64_t read_weight)
{
    la_uint_t mac_pool_base_id = mac_lane_base_id % 8;

    ifgb_rx_read_sch_cfg2_register rx_read_sch{{0}};

    lld_register_scptr device_rx_read_sch_reg
        = (m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg2);

    // Read
    la_status stat = m_device->m_ll_device->read_register(device_rx_read_sch_reg, rx_read_sch);
    return_on_error(stat);

    // Modify
    // Insert the total weight to the first one
    rx_read_sch.u8[mac_pool_base_id] = read_weight;
    // Zero out all the rest
    for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        rx_read_sch.u8[mac_pool_base_id + mac_lane] = 0;
    }

    // Write
    stat = m_device->m_ll_device->write_register(device_rx_read_sch_reg, rx_read_sch);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_ostc_quantizations(la_uint_t mac_lane_base_id,
                                            size_t mac_lanes_reserved_count,
                                            la_mac_port::port_speed_e speed,
                                            const la_mac_port::ostc_thresholds& thresholds)
{
    size_t port_speed = la_2_port_speed(speed);
    size_t buffer_units = div_round_up(port_speed, FIFO_BUFFER_MAX_SPEED);

    // Read register
    ifgb_rx_port_cgm_cfg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[mac_lane_base_id], reg);
    return_on_error(stat);

    // Modify register
    bool is_400g_port = (speed == la_mac_port::port_speed_e::E_400G);
    size_t fifo_size = m_single_port_lines * buffer_units;
    size_t rx_cgm_max_threshold = is_400g_port ? fifo_size - 10 : fifo_size - 1;

    uint64_t values[la_mac_port::OSTC_TRAFFIC_CLASSES];
    for (size_t i = 0; i < la_mac_port::OSTC_TRAFFIC_CLASSES; i++) {
        values[i] = std::min((size_t)(fifo_size * thresholds.thresholds[i]), rx_cgm_max_threshold);
    }

    // These values were given by the HW team.
    size_t min_value = is_400g_port ? 13 : 3;
    if (values[0] < min_value) {
        return LA_STATUS_EINVAL;
    }

    reg.fields.p_tc0_drop_th = values[0];
    reg.fields.p_tc1_drop_th = values[1];
    reg.fields.p_tc2_drop_th = values[2];
    reg.fields.p_tc3_drop_th = values[3];

    // Write register
    for (size_t i = 0; i < mac_lanes_reserved_count; i++) {
        stat = m_device->m_ll_device->write_register(
            (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[i + mac_lane_base_id], reg);
        return_on_error(stat);
    }

    if (((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1))
        && is_400g_port) {
        for (size_t i = 0; i < la_mac_port::OSTC_TRAFFIC_CLASSES; i++) {
            values[i] -= 8;
        }

        ifgb_rx_port0_cgm_sop_cfg_register sop_reg{{0}};
        sop_reg.fields.p0_tc0_sop_drop_th = values[0];
        sop_reg.fields.p0_tc1_sop_drop_th = values[1];
        sop_reg.fields.p0_tc2_sop_drop_th = values[2];
        sop_reg.fields.p0_tc3_sop_drop_th = values[3];
        auto& ifgb = m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb;
        lld_register_scptr rx_port0_cgm_sop_cfg;
        if (mac_lane_base_id == 0) {
            rx_port0_cgm_sop_cfg = ifgb->rx_port0_cgm_sop_cfg;
        } else if (mac_lane_base_id == 8) {
            rx_port0_cgm_sop_cfg = ifgb->rx_port8_cgm_sop_cfg;
        } else {
            log_err(HLD, "%s: Got mac_lane_base_id=%u which is illegal for 400G port", __func__, mac_lane_base_id);
            return LA_STATUS_EUNKNOWN;
        }

        stat = m_device->m_ll_device->write_register(*rx_port0_cgm_sop_cfg, sop_reg);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::get_ostc_quantizations(la_uint_t mac_lane_base_id,
                                            size_t mac_lanes_reserved_count,
                                            la_mac_port::port_speed_e speed,
                                            la_mac_port::ostc_thresholds& out_thresholds) const
{
    size_t port_speed = la_2_port_speed(speed);
    size_t buffer_units = div_round_up(port_speed, FIFO_BUFFER_MAX_SPEED);

    // Read register
    ifgb_rx_port_cgm_cfg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[mac_lane_base_id], reg);
    return_on_error(stat);

    // Update output
    size_t fifo_size = m_single_port_lines * buffer_units;
    out_thresholds.thresholds[0] = (double)reg.fields.p_tc0_drop_th / fifo_size;
    out_thresholds.thresholds[1] = (double)reg.fields.p_tc1_drop_th / fifo_size;
    out_thresholds.thresholds[2] = (double)reg.fields.p_tc2_drop_th / fifo_size;
    out_thresholds.thresholds[3] = (double)reg.fields.p_tc3_drop_th / fifo_size;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_default_port_tc(la_uint_t mac_lane_base_id,
                                         size_t mac_lanes_reserved_count,
                                         la_over_subscription_tc_t default_ostc,
                                         la_initial_tc_t default_itc)
{
    // Read register
    ifgb_tc_extract_cfg_reg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    reg.fields.tc_ext_default_tc = combine_ostc_and_itc(default_ostc, default_itc);

    // Write register
    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::get_default_port_tc(la_uint_t mac_lane_base_id,
                                         la_over_subscription_tc_t& out_default_ostc,
                                         la_initial_tc_t& out_default_itc) const
{
    // Read register
    ifgb_tc_extract_cfg_reg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    split_value_to_ostc_and_itc(reg.fields.tc_ext_default_tc, out_default_ostc, out_default_itc);
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::modify_port_tc_tpid(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx, la_tpid_t tpid)
{
    dassert_crit(idx < static_cast<size_t>(la_mac_port_base::OSTC_NUM_TPIDS));

    // Read register
    ifgb_tc_extract_cfg_reg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    // Modify register
    switch (idx) {
    case 0:
        reg.fields.tc_ext_tpid0_ = tpid;
        break;
    case 1:
        reg.fields.tc_ext_tpid1_ = tpid;
        break;
    case 2:
        reg.fields.tc_ext_tpid2_ = tpid;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    // Write register
    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::remove_port_tc_tpid(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx)
{
    la_status status = modify_port_tc_tpid(mac_lane_base_id, mac_lanes_reserved_count, idx, la_mac_port::RESERVED_ETHERTYPE);
    return status;
}

la_status
ifg_handler_pacific::set_port_tc_extract_offset(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t offset)
{
    ifgb_tc_extract_cfg_reg_register reg;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    reg.fields.tc_ext_byte_os = offset;

    // Write register
    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::add_port_tc_custom_protocol(la_uint_t mac_lane_base_id,
                                                 size_t mac_lanes_reserved_count,
                                                 la_uint_t idx,
                                                 la_ethertype_t protocol)
{
    // Read register
    ifgb_tc_extract_cfg_reg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    // Modify register
    switch (idx) {
    case 0:
        reg.fields.tc_ext_eth_type0_ = protocol;
        break;
    case 1:
        reg.fields.tc_ext_eth_type1_ = protocol;
        break;
    case 2:
        reg.fields.tc_ext_eth_type2_ = protocol;
        break;
    case 3:
        reg.fields.tc_ext_eth_type3_ = protocol;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    // Write register
    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    stat = reset_port_tc_custom_protocol_configuration(mac_lane_base_id, idx);
    return stat;
}

la_status
ifg_handler_pacific::remove_port_tc_custom_protocol(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx)
{
    // Read register
    ifgb_tc_extract_cfg_reg_register reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    // Modify register
    switch (idx) {
    case 0:
        reg.fields.tc_ext_eth_type0_ = la_mac_port::RESERVED_ETHERTYPE;
        break;
    case 1:
        reg.fields.tc_ext_eth_type1_ = la_mac_port::RESERVED_ETHERTYPE;
        break;
    case 2:
        reg.fields.tc_ext_eth_type2_ = la_mac_port::RESERVED_ETHERTYPE;
        break;
    case 3:
        reg.fields.tc_ext_eth_type3_ = la_mac_port::RESERVED_ETHERTYPE;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    // Write register
    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::get_port_tc_tcam_key_opcode(la_uint_t mac_lane_base_id,
                                                 la_mac_port::tc_protocol_e protocol,
                                                 la_uint32_t& out_opcode,
                                                 la_uint32_t& out_length) const
{

    /*
     * HW Bug
     * Entries of Ethernet and MPLS protocols can have the same opcode for different ports (single lane ports on the same MAC pool),
     * for example:
     * Ethernet entry: port = 1 (odd mac_lane_base_id), PCP = 0xx, DEI = x --> 000000 1 0xx x (PCP can be 0-7, assuming 0xx for the
     * sake of this example)
     * MPLS entry: port = 0 (even mac_lane_base_id), MPLS-TC = xxx --> 0000001 0 xxx
     * which can cause one port to change another's TCAM entries.
     * For example: resetting MPLS priorities will change other port's Ethernet entries, clearing TCAM entries of one port will also
     * clear some of the other's etc.
     * No feasible SW WA.
     */
    switch (protocol) {
    case la_mac_port::tc_protocol_e::ETHERNET:
        out_length = 4;
        out_opcode = 0; // {6'b0, port, PCP[3:1], DEI}
        break;
    case la_mac_port::tc_protocol_e::IPV4:
        out_length = 8;
        out_opcode = (1 << (out_length + 1)); // {2'b1, port, DSCP[7:0]}
        break;
    case la_mac_port::tc_protocol_e::IPV6:
        out_length = 8;
        out_opcode = (2 << (out_length + 1)); // {2'b2, port, IPV6-TC[7:0]}
        break;
    case la_mac_port::tc_protocol_e::MPLS:
        out_length = 3;
        out_opcode = (1 << (out_length + 1)); // {7'b1, port, MPLS-TC[2:0]}
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    // We configure only even ports, therefore port bit will remain 0

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::update_lane_modes(la_uint_t mac_lane_base_id,
                                       size_t mac_lanes_count,
                                       uint64_t& two_lane_mode,
                                       uint64_t& eight_lane_mode)
{
    if (mac_lanes_count < 8) {
        bit_utils::set_bit(&two_lane_mode, (mac_lane_base_id / 2), (mac_lanes_count != 1));

        if (mac_lane_base_id < 16) {
            bit_utils::set_bit(&eight_lane_mode, (mac_lane_base_id / 8), 0);
        }
    } else {
        size_t lsb = mac_lane_base_id / 2;
        size_t msb = lsb;

        // Set the correct one in 8 lane mode.
        bit_utils::set_bit(&eight_lane_mode, (mac_lane_base_id / 8), 1);
        msb += 3;
        two_lane_mode = bit_utils::set_bits(two_lane_mode, msb, lsb, 0);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::configure_oob_inject_packet_counters()
{
    ifgb_oobi_pkt_type_cnt_en_register oobi_cnt_en_reg{{0}};

    // Enable all OOB injected packet counter types
    oobi_cnt_en_reg.fields.oobi_csms_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_frm_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_fte_pd_req_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_fte_pd_res_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_fte_fts_cnt_en = 1;

    la_status status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->oobi_pkt_type_cnt_en, oobi_cnt_en_reg);
    return status;
}

la_status
ifg_handler_pacific::configure_oob_extract_packet_counters()
{
    ifgb_oobe_pkt_type_cnt_en_register oobe_cnt_en_reg{{0}};

    // Enable all OOB extracted packet counter types
    oobe_cnt_en_reg.fields.oobe_csms_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_frm_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_fte_pd_req_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_fte_pd_res_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_fte_fts_cnt_en = 1;

    la_status status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->oobe_pkt_type_cnt_en, oobe_cnt_en_reg);
    return status;
}

la_status
ifg_handler_pacific::init_fifo_memory()
{
    ifgb_rx_rstn_reg_register rx_rstn_reg{{0}};
    ifgb_tx_rstn_reg_register tx_rstn_reg{{0}};
    la_status status;
    lld_register_value_list_t reg_val_list;

    bit_vector tx_lane_rstn(0, 20);
    tx_lane_rstn.set_bit(HOST_PIF_ID, true); // TODO: consider to disable
    tx_lane_rstn.set_bit(RECYCLE_PIF_ID, true);

    rx_rstn_reg.fields.rx_lane_rstn = 0;
    rx_rstn_reg.fields.rx_ibi_rstn = 1; // The default value, consider to disable it? (but not in LC_56_FABRIC_PORT_MODE)

    bool is_borrower_ifg = m_device->is_borrower_ifg(m_slice_id, m_ifg_id);
    if (is_borrower_ifg == true) {
        rx_rstn_reg.fields.rx_ibi_rstn = 1;
    }

    rx_rstn_reg.fields.rx_rstn = 1; //

    tx_rstn_reg.fields.tx_lane_rstn = tx_lane_rstn.get_value();
    tx_rstn_reg.fields.tx_rstn = 1;

    reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_rstn_reg), rx_rstn_reg});
    reg_val_list.push_back({(m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg), tx_rstn_reg});

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::read_ostc_counter(la_uint_t mac_lane_base_id,
                                       la_over_subscription_tc_t ostc,
                                       size_t& out_dropped_packets) const
{
    // TODO: scrub results periodically so no overflow will accour
    ifgb_rx_port_cgm_tc0_drop_counter_register reg1{{0}};
    ifgb_rx_port_cgm_tc0_partial_drop_counter_register reg2{{0}};
    la_status status1, status2;

    switch (ostc) {
    case 0:
        status1 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc0_drop_counter)[mac_lane_base_id], reg1);
        status2 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc0_partial_drop_counter)[mac_lane_base_id],
                                                       reg2);
        break;
    case 1:
        status1 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc1_drop_counter)[mac_lane_base_id], reg1);
        status2 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc1_partial_drop_counter)[mac_lane_base_id],
                                                       reg2);
        break;
    case 2:
        status1 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc2_drop_counter)[mac_lane_base_id], reg1);
        status2 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc2_partial_drop_counter)[mac_lane_base_id],
                                                       reg2);
        break;
    case 3:
        status1 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc3_drop_counter)[mac_lane_base_id], reg1);
        status2 = m_device->m_ll_device->read_register((*m_ifgb_registers.rx_port_cgm_tc3_partial_drop_counter)[mac_lane_base_id],
                                                       reg2);
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return_on_error(status1);

    return_on_error(status2);

    out_dropped_packets = reg1.fields.rx_port_cgm_tc0_drop_cnt + reg2.fields.rx_port_cgm_tc0_partial_drop_cnt;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_rx_lane_swap()
{
    // Update mac_lane_pool block
    bit_vector serdes_rx_lane_swap_config_register(0, serdes_pool18_serdes_rx_lane_swap_config_register::SIZE_IN_BITS);
    for (size_t serdes_id = 0; serdes_id < NUM_SERDES_PER_IFG; serdes_id++) {
        size_t lsb = serdes_id * 2;
        serdes_rx_lane_swap_config_register.set_bits(
            lsb + 1, lsb, m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_id].rx_source & 0x3);
    }

    la_status status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_rx_lane_swap_config,
        serdes_rx_lane_swap_config_register);
    return_on_error(status);

    // MAC pool (RxPmaCfg0) configuration is part of the port configuration

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status)
{
    serdes_pool18_serdes_status_register serdes_status;
    la_status stat = m_device->m_ll_device->read_register(
        (*m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_status)[serdes_idx], serdes_status);
    return_on_error(stat);

    out_serdes_status.rx_ready = serdes_status.fields.rx_rdy;
    out_serdes_status.tx_ready = serdes_status.fields.tx_rdy;
    out_serdes_status.signal_ok = serdes_status.fields.signal_ok;
    out_serdes_status.spico_ready = serdes_status.fields.spico_rdy;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::get_fabric_port_number(la_uint_t first_serdes_id, la_uint_t& out_port_num) const
{
    out_port_num = (m_slice_id * NUM_IFGS_PER_SLICE * NUM_SERDES_PER_IFG + m_ifg_id * NUM_SERDES_PER_IFG + first_serdes_id)
                   / NUM_SERDES_PER_FABRIC_PORT;
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::set_synce_default()
{
    // Set the default Divider to 32.
    la_status status;

    serdes_pool18_serdes_synce_control_register serdes_synce_reg = {{0}};

    status = m_device->m_ll_device->read_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);
    serdes_synce_reg.fields.synce_pri_clk_div = log2(SYNCE_DETACH_OUTPUT_DIV);
    serdes_synce_reg.fields.synce_sec_clk_div = log2(SYNCE_DETACH_OUTPUT_DIV);

    status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::attach_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                         la_slice_id_t slice_id,
                                         la_ifg_id_t ifg_id,
                                         la_uint_t serdes_id,
                                         uint32_t divider)
{
    uint32_t ifg_global;
    uint32_t ifg_synce_sel = 0;
    bool synce_attached;
    la_status status;

    serdes_pool18_serdes_synce_control_register serdes_synce_reg = {{0}};

    status = m_device->m_ll_device->read_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);

    status = check_synce_attached(prim_sec_clock, synce_attached);
    return_on_error_log(status, HLD, ERROR, "Failed to get SyncE clock status on %d/%d. ", m_slice_id, m_ifg_id);

    if (synce_attached) {
        log_err(HLD,
                "SyncE clock attach to %d/%d/%d on %d/%d failed. Detach recovered clock first.\n",
                slice_id,
                ifg_id,
                serdes_id,
                m_slice_id,
                m_ifg_id);
        return LA_STATUS_EBUSY;
    }

    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice_id, ifg_id);
    if (stat != LA_STATUS_SUCCESS) {
        log_err(HLD, "%s: slice=%d, ifg=%d is out of range", __func__, slice_id, ifg_id);
        return stat;
    }

    ifg_global = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(slice_id, ifg_id);

    ifg_synce_sel = synce_ifg_map[ifg_global];

    if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
        serdes_synce_reg.fields.synce_pri_ifg_sel_cfg = ifg_synce_sel;
        serdes_synce_reg.fields.synce_pri_clk_sel = serdes_id;
        serdes_synce_reg.fields.synce_pri_clk_div = log2(divider);
    } else {
        serdes_synce_reg.fields.synce_sec_ifg_sel_cfg = ifg_synce_sel;
        serdes_synce_reg.fields.synce_sec_clk_sel = serdes_id;
        serdes_synce_reg.fields.synce_sec_clk_div = log2(divider);
    }

    status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);

    m_synce_attached[(size_t)prim_sec_clock] = true;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::get_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                      uint32_t synce_pin,
                                      la_slice_id_t& out_slice_id,
                                      la_ifg_id_t& out_ifg_id,
                                      la_uint_t& out_serdes_id,
                                      uint32_t& out_divider) const
{
    uint32_t ifg_synce_sel;
    bool synce_attached;
    la_status status;

    serdes_pool18_serdes_synce_control_register serdes_synce_reg = {{0}};

    status = check_synce_attached(prim_sec_clock, synce_attached);
    return_on_error_log(status, HLD, ERROR, "Failed to get SyncE clock status on %d/%d. ", m_slice_id, m_ifg_id);

    if (!synce_attached) {
        log_err(HLD, "%d/%d recovered clock detached. ", m_slice_id, m_ifg_id);
        return LA_STATUS_ENOTFOUND;
    }

    status = m_device->m_ll_device->read_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);

    if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
        ifg_synce_sel = synce_pin * NUM_IFGS_PER_SYNCE_GROUP + serdes_synce_reg.fields.synce_pri_ifg_sel_cfg;
        out_serdes_id = serdes_synce_reg.fields.synce_pri_clk_sel;
        out_divider = (1 << serdes_synce_reg.fields.synce_pri_clk_div);
    } else {
        ifg_synce_sel = synce_pin * NUM_IFGS_PER_SYNCE_GROUP + serdes_synce_reg.fields.synce_sec_ifg_sel_cfg;
        out_serdes_id = serdes_synce_reg.fields.synce_sec_clk_sel;
        out_divider = (1 << serdes_synce_reg.fields.synce_sec_clk_div);
    }

    uint32_t ifg = synce_ifg_demap[ifg_synce_sel];

    auto s_ifg = m_device->get_slice_id_manager()->global_ifg_2_slice_ifg(ifg);
    out_slice_id = s_ifg.slice;
    out_ifg_id = s_ifg.ifg;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::detach_synce_output(la_device::synce_clock_sel_e prim_sec_clock, uint32_t synce_pin)
{
    la_status status;
    bool synce_attached;

    serdes_pool18_serdes_synce_control_register serdes_synce_reg = {{0}};

    status = check_synce_attached(prim_sec_clock, synce_attached);
    return_on_error_log(status, HLD, ERROR, "Failed to get SyncE clock status on %d/%d. ", m_slice_id, m_ifg_id);

    if (!synce_attached) {
        log_err(HLD, "%d/%d recovered clock already detached. ", m_slice_id, m_ifg_id);
        return LA_STATUS_ENOTFOUND;
    }

    status = m_device->m_ll_device->read_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);

    if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
        serdes_synce_reg.fields.synce_pri_ifg_sel_cfg = SYNCE_DETACH_OUTPUT_IFG;
        serdes_synce_reg.fields.synce_pri_clk_sel = SYNCE_DETACH_OUTPUT_SERDES;
        serdes_synce_reg.fields.synce_pri_clk_div = log2(SYNCE_DETACH_OUTPUT_DIV);
    } else {
        serdes_synce_reg.fields.synce_sec_ifg_sel_cfg = SYNCE_DETACH_OUTPUT_IFG;
        serdes_synce_reg.fields.synce_sec_clk_sel = SYNCE_DETACH_OUTPUT_SERDES;
        serdes_synce_reg.fields.synce_sec_clk_div = log2(SYNCE_DETACH_OUTPUT_DIV);
    }

    status = m_device->m_ll_device->write_register(
        m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool->serdes_synce_control, serdes_synce_reg);
    return_on_error(status);

    m_synce_attached[(size_t)prim_sec_clock] = false;
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_pacific::clear_synce_squelch_lock(la_device::synce_clock_sel_e prim_sec_clock)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
ifg_handler_pacific::set_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool squelch_enable)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
ifg_handler_pacific::get_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool& out_squelch_enable)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
ifg_handler_pacific::read_mib_counters(bool clear, la_uint_t serdes_idx, la_mac_port::mib_counters& out_mib_counters) const
{
    return LA_STATUS_SUCCESS;
}

size_t
ifg_handler_pacific::get_port_base_index() const
{
    return (m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(m_slice_id, m_ifg_id)) * NUM_SERDES_PER_IFG;
}

la_status
ifg_handler_pacific::update_anlt_order(la_uint_t serdes_base_id, size_t serdes_count)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
