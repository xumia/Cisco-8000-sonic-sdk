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

#include "system/ifg_handler_gibraltar.h"
#include "api/system/la_mac_port.h"
#include "common/bit_utils.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "hld_utils.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "nplapi/nplapi_tables.h"
#include "system/device_model_types.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_interface_scheduler_impl.h"

#include <algorithm>
#include <cmath>
#include <iterator>

namespace silicon_one
{

using namespace gibraltar;

enum {
    TX_FIFO_LINES_EXTRA_PIF = ((1692 - 1584) / 2),
    RX_FIFO_ENTRIES_PER_LANE = 160,

    FTE_LINES = 32,
    FRM_LINES = 32,

    MAC_POOL_SIZE = 8,

    // Static min/max packet size to protect RxPP from invalid packets.
    RX_MIN_PACKET_SIZE = 56,
    RX_MAX_PACKET_SIZE = 10500,

    SYNCE_OVERRIDE_LOCK_TRUE = 1,
    SYNCE_OVERRIDE_LOCK_FALSE = 0,

    RSTN_RX_PMA_CORE = 88,
};

// Flow Control Action enable per-FC mode. Enable on PAUSE and CFFC
uint64_t flow_control_action_enable[(size_t)la_mac_port::fc_mode_e::CFFC + 1] = {0, 1, 0, 1};

static const serdes_pool_type_e p16 = serdes_pool_type_e::pool_16;
static const serdes_pool_type_e p24 = serdes_pool_type_e::pool_24;
static const serdes_pool_type_e s_IFG_pool_type[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_IFGS_PER_SLICE]
    = {{p24, p24}, {p24, p16}, {p16, p24}, {p24, p16}, {p16, p24}, {p24, p24}};

static uint64_t s_serdes_pool_size[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_IFGS_PER_SLICE]
    = {{24, 24}, {24, 16}, {16, 24}, {24, 16}, {16, 24}, {24, 24}};

ifg_handler_gibraltar::ifg_handler_gibraltar(la_device_impl_wptr device, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : ifg_handler_ifg(device, slice_id, ifg_id)
{
    m_gibraltar_tree = device->m_ll_device->get_gibraltar_tree_scptr();
    m_ifg_handler_common.m_num_port_tc_tcam_memories = 12;
    m_ifg_handler_common.m_tc_tcam_key_width.resize(1);
    m_ifg_handler_common.m_tc_tcam_key_width[0] = ifgb_24p_tc_tcam_memory::fields::TC_TCAM_KEY_WIDTH;
    m_ifg_handler_common.m_tc_ext_default_tc_width = ifgb_24p_tc_extract_cfg_reg_register::fields::TC_EXT_DEFAULT_TC_WIDTH;
    m_ifg_handler_common.m_tx_fifo_lines_main_pif = TX_FIFO_LINES_MAIN_PIF;

    synce_ifg_demap = {0, 1, 2, 3, 4, 5, 8, 7, 6, 11, 10, 9};
    synce_ifg_map = {0, 1, 2, 0, 1, 2, 2, 1, 0, 2, 1, 0};

    m_port_tc_tcam.resize(m_ifg_handler_common.m_num_port_tc_tcam_memories);
    m_ifgb_registers.tc_tcam.resize(1);
    m_ifgb_registers.tc_tcam_mem.resize(1);
}

void
ifg_handler_gibraltar::pre_initialize()
{
    int matilda_model;
    m_device->get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, matilda_model);

    if (matilda_model == matilda_model_e::MATILDA_8T_A || matilda_model == matilda_model_e::MATILDA_8T_B) {
        s_serdes_pool_size[m_slice_id][m_ifg_id] = 16;
    }

    m_ifg_handler_common.m_serdes_count = s_serdes_pool_size[m_slice_id][m_ifg_id];
    m_ifg_handler_common.m_mac_lanes_reserved_count = s_serdes_pool_size[m_slice_id][m_ifg_id];
    m_ifg_handler_common.m_pif_count = m_ifg_handler_common.m_serdes_count;
    m_ifg_handler_common.m_total_main_mac_lanes_reserved_count = m_ifg_handler_common.m_mac_lanes_reserved_count;
    m_ifg_handler_common.m_pool_type = s_IFG_pool_type[m_slice_id][m_ifg_id];

    initialize_register_pointers();
}

ifg_handler_gibraltar::~ifg_handler_gibraltar()
{
}

size_t
ifg_handler_gibraltar::get_port_base_index() const
{
    size_t base = 0;
    for (size_t slice = 0; slice < m_slice_id; slice++) {
        for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            base += s_serdes_pool_size[slice][ifg];
        }
    }

    for (size_t ifg = 0; ifg < m_ifg_id; ifg++) {
        base += s_serdes_pool_size[m_slice_id][ifg];
    }

    return base;
}

la_status
ifg_handler_gibraltar::initialize()
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(m_slice_id, m_ifg_id);
    return_on_error(stat);

    m_slice_mode = m_device->m_slice_mode[m_slice_id];

    stat = init_pfc_port_values();
    return_on_error(stat);

    stat = set_reset_fifo_memory(fifo_memory_reset_state_e::RESET_ALL);
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

    stat = set_reset_fifo_memory(fifo_memory_reset_state_e::ACTIVATE_INBAND_ONLY);
    return_on_error(stat);

    stat = set_synce_default();
    return_on_error(stat);

    bit_vector rx_filter_ctrl;
    rx_filter_ctrl.set_bits(gibraltar::ifgb_24p_rx_filter_ctrl_register::SIZE_IN_BITS - 1, 0, 0);
    stat = m_device->m_ll_device->write_register((*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_filter_ctrl)[0],
                                                 rx_filter_ctrl);
    return_on_error(stat);

    m_synce_attached.fill(false);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::initialize_topology()
{
    la_status status;

    mac_pool8_rstn_reg_register pool8_rstn_reg;

    bzero(&pool8_rstn_reg, mac_pool8_rstn_reg_register::SIZE);
    if (m_device->m_ll_device->get_device_revision() == la_device_revision_e::GIBRALTAR_A0) {
        // WA for GB A0 PMA Rx MUX lane-swap issue
        // Unreset RX_PMA_CORE for all Serdes
        bit_vector(pool8_rstn_reg).set_bits(RSTN_RX_PMA_CORE + 7, RSTN_RX_PMA_CORE, 0xff);
    }

    size_t mac_pool_count = m_ifg_handler_common.m_mac_lanes_reserved_count / 8;
    for (size_t mp8 = 0; mp8 < mac_pool_count; mp8++) {
        status = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[mp8]->rstn_reg,
                                                       pool8_rstn_reg);
        return_on_error(status);
    }

    constexpr struct {
        size_t ifgb;
        size_t mac_pool8_0;
        size_t mac_pool8_1;
        size_t mac_pool8_2;
    } DEVICE_TIME_OFFSET_CFG[] = {
        {506, 506 + 2, 506 + 4, 506 + 6},
        {486, 486 + 2, 486 + 4, 486 + 6},
        {467, 467 + 2, 467 + 4, 467 + 6},
        {449, 449 + 2, 449 + 4, 449 + 6},
        {424, 424 + 2, 424 + 4, 424 + 6},
        {409, 409 + 2, 409 + 4, 409 + 6},
        {371, 371 + 2, 371 + 4, 371 + 6},
        {358, 358 + 2, 358 + 4, 358 + 6},
        {332, 332 + 2, 332 + 4, 332 + 6},
        {312, 312 + 2, 312 + 4, 312 + 6},
        {293, 293 + 2, 293 + 4, 293 + 6},
        {273, 273 + 2, 273 + 4, 273 + 6},
    };

    static_assert(array_size(DEVICE_TIME_OFFSET_CFG) == NUM_IFGS_PER_DEVICE,
                  "DEVICE_TIME_OFFSET_CFG table size does not match number of IFG-s.");

    // Predefined values were calculated for CALCULATED_VALUES_DEVICE_FREQUENCY. Need to adjust according to actual clock frequency.
    float device_freq_adjust = float(1) / m_device->m_device_frequency_float_ghz;

    lld_register_value_list_t reg_val_list;
    size_t ifg_entry_num = (m_slice_id * 2) + m_ifg_id;
    reg_val_list.push_back({m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[0]->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].mac_pool8_0 * device_freq_adjust)});
    reg_val_list.push_back({m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[1]->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].mac_pool8_1 * device_freq_adjust)});
    if (mac_pool_count == 3) {
        reg_val_list.push_back({m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[2]->device_time_offset_cfg,
                                round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].mac_pool8_2 * device_freq_adjust)});
    }
    reg_val_list.push_back({m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->device_time_offset_cfg,
                            round(DEVICE_TIME_OFFSET_CFG[ifg_entry_num].ifgb * device_freq_adjust)});

    ifgb_24p_rx_cfg0_register rx_cfg0_val{{0}};
    rx_cfg0_val.fields.rx_undersize_filter_en = 0xffffff;
    reg_val_list.push_back({m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_cfg0_val});

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    status = configure_rx_pma();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
ifg_handler_gibraltar::initialize_register_pointers()
{
    const auto& ifg = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id];

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        m_serdes_rx_lane_swap_config = ifg->serdes_pool16->serdes_rx_lane_swap_config;
        m_serdes_tx_lane_swap_config = ifg->serdes_pool16->serdes_tx_lane_swap_config;
        m_serdes_status = ifg->serdes_pool16->serdes_status;
        m_serdes_pll_status = ifg->serdes_pool16->serdes_pll_status;
        m_serdes_an_master_config = ifg->serdes_pool16->serdes_an_master_config;
        m_serdes_an_bitmap_config = ifg->serdes_pool16->serdes_an_bitmap_config;
    } else {
        m_serdes_rx_lane_swap_config = ifg->serdes_pool24->serdes_rx_lane_swap_config;
        m_serdes_tx_lane_swap_config = ifg->serdes_pool24->serdes_tx_lane_swap_config;
        m_serdes_status = ifg->serdes_pool24->serdes_status;
        m_serdes_pll_status = ifg->serdes_pool24->serdes_pll_status;
        m_serdes_an_master_config = ifg->serdes_pool24->serdes_an_master_config;
        m_serdes_an_bitmap_config = ifg->serdes_pool24->serdes_an_bitmap_config;
    }

    m_ifgb_registers.fc_cfg0 = ifg->ifgb->fc_cfg0;
    m_ifgb_registers.rx_rstn_reg = ifg->ifgb->rx_rstn_reg;
    m_ifgb_registers.tx_rstn_reg = ifg->ifgb->tx_rstn_reg;
    m_ifgb_registers.tx_tsf_ovf_interrupt_reg = ifg->ifgb->tx_tsf_ovf_interrupt_reg;
    m_ifgb_registers.tc_tcam[0] = ifg->ifgb->tc_tcam;
    m_ifgb_registers.tc_tcam_mem[0] = ifg->ifgb->tc_tcam_mem;
    m_ifgb_registers.tx_fif_cfg = ifg->ifgb->tx_fif_cfg;
    m_ifgb_registers.tc_extract_cfg_reg = ifg->ifgb->tc_extract_cfg_reg;
    m_ifgb_registers.rx_port_cgm_tc0_drop_counter = ifg->ifgb->rx_port_cgm_tc0_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc1_drop_counter = ifg->ifgb->rx_port_cgm_tc1_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc2_drop_counter = ifg->ifgb->rx_port_cgm_tc2_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc3_drop_counter = ifg->ifgb->rx_port_cgm_tc3_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc0_partial_drop_counter = ifg->ifgb->rx_port_cgm_tc0_partial_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc1_partial_drop_counter = ifg->ifgb->rx_port_cgm_tc1_partial_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc2_partial_drop_counter = ifg->ifgb->rx_port_cgm_tc2_partial_drop_counter;
    m_ifgb_registers.rx_port_cgm_tc3_partial_drop_counter = ifg->ifgb->rx_port_cgm_tc3_partial_drop_counter;
}

la_status
ifg_handler_gibraltar::configure_fabric_ports(la_mac_port::fc_mode_e fc_mode)
{
    // for each fabric port -> configure port
    device_port_handler_base::fabric_data fabric_data;
    m_device->m_device_port_handler->get_fabric_data(fabric_data);
    size_t num_fabric_ports = get_serdes_count() / fabric_data.num_serdes_per_fabric_port;
    for (size_t port = 0; port < num_fabric_ports; port++) {
        la_status stat = configure_port(port * fabric_data.num_serdes_per_fabric_port,
                                        fabric_data.num_serdes_per_fabric_port,
                                        fabric_data.speed,
                                        fabric_data.num_serdes_per_fabric_port,
                                        la_mac_port::mlp_mode_e::NONE,
                                        fc_mode);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_lc_56_fabric_port(la_uint_t mac_lane_base_id,
                                                   size_t mac_lanes_reserved_count,
                                                   la_mac_port::port_speed_e speed,
                                                   size_t mac_lanes_count,
                                                   la_mac_port::mlp_mode_e mlp_mode,
                                                   la_mac_port::fc_mode_e fc_mode)
{
    return LA_STATUS_EINVAL;
}

la_status
ifg_handler_gibraltar::configure_mlp_mode(la_uint_t mac_lane_base_id,
                                          la_mac_port::port_speed_e speed,
                                          size_t mac_lanes_count,
                                          la_mac_port::mlp_mode_e mlp_mode)
{
    ifgb_24p_tx_cfg0_register tx_reg;
    ifgb_24p_rx_cfg0_register rx_reg;
    la_status stat;

    // This MAC pool port control only part of the bits, need to read and modify only the relevant bits.
    stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    if (mlp_mode == la_mac_port::mlp_mode_e::MLP_MASTER) {
        tx_reg.fields.tx_mlp_mode = 1 + (mac_lane_base_id / 8);
        rx_reg.fields.rx_mlp_mode = tx_reg.fields.tx_mlp_mode;
    }

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_lanes(la_uint_t mac_lane_base_id, size_t mac_lanes_count, la_mac_port::port_speed_e speed)
{
    ifgb_24p_tx_cfg0_register tx_reg;
    ifgb_24p_rx_cfg0_register rx_reg;
    la_status stat;

    // This MAC pool port control only part of the bits, need to read and modify only the relevant bits.
    stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    uint64_t two_lane_mode = tx_reg.fields.tx_2l_mode;
    uint64_t four_lane_mode = tx_reg.fields.tx_4l_mode;
    uint64_t eight_lane_mode = tx_reg.fields.tx_8l_mode;
    stat = update_lane_modes(mac_lane_base_id, mac_lanes_count, two_lane_mode, four_lane_mode, eight_lane_mode);
    return_on_error(stat);

    tx_reg.fields.tx_2l_mode = two_lane_mode;
    tx_reg.fields.tx_4l_mode = four_lane_mode;
    tx_reg.fields.tx_8l_mode = eight_lane_mode;

    rx_reg.fields.rx_2l_mode = tx_reg.fields.tx_2l_mode;
    rx_reg.fields.rx_4l_mode = tx_reg.fields.tx_4l_mode;
    rx_reg.fields.rx_8l_mode = tx_reg.fields.tx_8l_mode;

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0, rx_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::reset_fifo_memory(size_t mac_lane_base,
                                         size_t mac_lanes_reserved_count,
                                         size_t mac_lanes_count,
                                         la_mac_port_base::mac_reset_state_e reset)
{

    // Read Rx & Tx reset registers
    la_status status;
    bit_vector rx_rstn_reg;
    bit_vector tx_rstn_reg;

    status
        = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_rstn_reg, rx_rstn_reg);
    return_on_error(status);

    status
        = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg, tx_rstn_reg);
    return_on_error(status);

    bool rx_rstn_bit = (reset == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
    bool tx_rstn_bit = (reset != la_mac_port_base::mac_reset_state_e::RESET_ALL);

    enum rstn_offset {
        RX_LANE = 0,
        TX_LANE = 0,
        RX_OOBE = 25,
        RX_PROTECT_PIF = 27,
        TX_PROTECT_PIF = 27,
    };

    // Once the first Port is being activated, RX_OOBE should be taken out of reset too
    size_t rx_lane
        = (size_t)(rx_rstn_reg.bits(gibraltar::ifgb_24p_rx_rstn_reg_register::fields::RX_LANE_RSTN_WIDTH - 1, 0).get_value());
    if (rx_lane == 0 && m_slice_mode == la_slice_mode_e::CARRIER_FABRIC && rx_rstn_bit) {
        rx_rstn_reg.set_bit(rstn_offset::RX_OOBE, 1);
    }

    // Reset to single port mode
    // TODO Rx OOBe rstn
    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        rx_rstn_reg.set_bit(rstn_offset::RX_LANE + mac_lane_base + mac_lane, rx_rstn_bit);
        tx_rstn_reg.set_bit(rstn_offset::TX_LANE + mac_lane_base + mac_lane, tx_rstn_bit);
        rx_rstn_reg.set_bit(rstn_offset::RX_PROTECT_PIF + mac_lane_base + mac_lane, tx_rstn_bit);
        tx_rstn_reg.set_bit(rstn_offset::TX_PROTECT_PIF + mac_lane_base + mac_lane, tx_rstn_bit);
    }

    // Once last port is being reset, OOBE should be put int reset too
    rx_lane = (size_t)(rx_rstn_reg.bits(gibraltar::ifgb_24p_rx_rstn_reg_register::fields::RX_LANE_RSTN_WIDTH - 1, 0).get_value());
    if (rx_lane == 0 && m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) {
        rx_rstn_reg.set_bit(rstn_offset::RX_OOBE, 0);
    }

    status
        = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_rstn_reg, rx_rstn_reg);
    return_on_error(status);

    status
        = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg, tx_rstn_reg);
    return_on_error(status);

    if (reset == la_mac_port_base::mac_reset_state_e::RESET_ALL && m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) {
        status = reset_oob_inj_credits(mac_lane_base, 0);
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
ifg_handler_gibraltar::reset_oob_inj_credits(size_t mac_lane_base, int val)
{
    uint32_t port_idx = (get_port_base_index() + mac_lane_base) / NUM_SERDES_PER_FABRIC_PORT;
    pier_oob_fabric_link_to_src_link_map_table_memory oob_fabric_link_to_src_link_map;
    la_status stat = m_device->m_ll_device->read_memory(
        m_gibraltar_tree->dmc->pier->oob_fabric_link_to_src_link_map_table, port_idx, oob_fabric_link_to_src_link_map);
    return_on_error(stat);
    uint32_t link = oob_fabric_link_to_src_link_map.fields.oob_fabric_link_to_src_link_map_data;

    pier_oob_inj_credit_init_reg_register oob_inj_credit_init_reg;
    oob_inj_credit_init_reg.fields.oob_inj_credit_init_en = 1;
    oob_inj_credit_init_reg.fields.oob_inj_credit_init_val = val;
    oob_inj_credit_init_reg.fields.oob_inj_credit_init_link = link;

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->dmc->pier->oob_inj_credit_init_reg, oob_inj_credit_init_reg);
    return_on_error(stat);

    oob_inj_credit_init_reg.fields.oob_inj_credit_init_en = 0;

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->dmc->pier->oob_inj_credit_init_reg, oob_inj_credit_init_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_block_ingress_data(size_t mac_lane_base, size_t mac_lanes_reserved_count, bool enabled)
{
    la_status status;
    bit_vector rx_filter_ctrl;
    status = m_device->m_ll_device->read_register((*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_filter_ctrl)[0],
                                                  rx_filter_ctrl);
    return_on_error(status);

    enum rstn_offset {
        RX_FILTER_EN = 0,
        RX_FILTER_DROP_EN = 1,
        RX_FILTER_PIF_EN = 2,
    };

    rx_filter_ctrl.set_bit(rstn_offset::RX_FILTER_EN, 1);
    rx_filter_ctrl.set_bit(rstn_offset::RX_FILTER_DROP_EN, 1);

    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        rx_filter_ctrl.set_bit(rstn_offset::RX_FILTER_PIF_EN + mac_lane_base + mac_lane, enabled);
    }

    status = m_device->m_ll_device->write_register((*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_filter_ctrl)[0],
                                                   rx_filter_ctrl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_read_schedule_weight(la_uint_t mac_lane_base_id,
                                                      size_t mac_lanes_reserved_count,
                                                      la_mac_port::mlp_mode_e mlp_mode,
                                                      la_mac_port::port_speed_e speed)
{
    if (mac_lane_base_id >= m_ifg_handler_common.m_mac_lanes_reserved_count) {
        return LA_STATUS_EINVAL;
    }

    uint64_t read_weight = read_schedule_weight.at(speed);

    if (mlp_mode == la_mac_port::mlp_mode_e::MLP_SLAVE) {
        // Must be 0 as well
        read_weight = 0;
    }

    return configure_read_schedule_weight(mac_lane_base_id, mac_lanes_reserved_count, read_weight);
}

la_status
ifg_handler_gibraltar::reset_read_schedule_weight(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count)
{
    if (mac_lane_base_id >= m_ifg_handler_common.m_mac_lanes_reserved_count) {
        return LA_STATUS_EINVAL;
    }

    return configure_read_schedule_weight(mac_lane_base_id, mac_lanes_reserved_count, 0 /* read_weight */);
}

la_status
ifg_handler_gibraltar::configure_tx_calendar()
{
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_fc_mode_fabric_extraction(la_uint_t mac_lane_base_id, bool enable)
{
    ifgb_24p_fc_cfg1_register fc_cfg1_reg;

    la_status stat
        = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg1, fc_cfg1_reg);
    return_on_error(stat);

    uint64_t reg_val = fc_cfg1_reg.fields.en_fc_ext_from_oob;

    la_uint_t fabric_link_idx = mac_lane_base_id / 2;
    bit_utils::set_bit(&reg_val, fabric_link_idx, enable);

    fc_cfg1_reg.fields.en_fc_ext_from_oob = reg_val;

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg1, fc_cfg1_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_fc_mode_periodic(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable)
{
    ifgb_24p_fc_cfg0_register fc_cfg0_reg;

    la_status stat
        = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
    return_on_error(stat);

    uint64_t reg_val = fc_cfg0_reg.fields.periodic_int_en;

    bit_utils::set_bit(&reg_val, mac_lane_base_id, enable);
    for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        bit_utils::set_bit(&reg_val, mac_lane_base_id + mac_lane, false);
    }

    fc_cfg0_reg.fields.periodic_int_en = reg_val;

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_fc_mode_port(la_uint_t mac_lane_base_id,
                                        size_t mac_lanes_reserved_count,
                                        la_mac_port::port_speed_e speed,
                                        la_mac_port::fc_mode_e fc_mode)
{
    lld_register_value_list_t reg_val_list;

    ifgb_24p_fc_port_cfg0_register fc_port_cfg0;
    ifgb_24p_fc_port_cfg2_register fc_port_cfg2;

    fc_port_cfg0.fields.port_pause_act_en = flow_control_action_enable[(size_t)fc_mode];
    fc_port_cfg0.fields.port_pause_mask = 0xFF;

    fc_port_cfg0.fields.port_watch_dog_timer = s_fc_mode_periodic_config[(size_t)fc_mode].port_watch_dog_timer;

    fc_port_cfg0.fields.port_fc_mode = flow_control_code[(size_t)fc_mode];

    fc_port_cfg0.fields.port_512bit_time
        = ceil(m_device->m_device_frequency_float_ghz * FLOW_CONTROL_BITS / la_2_port_speed(speed));
    fc_port_cfg2.fields.port_ostc_priority_map = flow_control_priority_map[(size_t)fc_mode];

    const auto& ifgb = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb;

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
ifg_handler_gibraltar::set_port_periodic_timer_value(la_uint_t mac_lane_base_id,
                                                     size_t mac_lanes_reserved_count,
                                                     la_uint_t timer_value)
{
    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        auto fc_port_cfg_0 = (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_port_cfg0)[mac_lane_base_id + mac_lane];
        gibraltar::ifgb_24p_fc_port_cfg0_register fc_port_cfg0;

        la_status status = m_device->m_ll_device->read_register(*fc_port_cfg_0, fc_port_cfg0);
        return_on_error(status);

        // Only update timer value in HW if we are in PFC mode
        if (fc_port_cfg0.fields.port_fc_mode == (size_t)la_mac_port::fc_mode_e::PFC) {
            fc_port_cfg0.fields.port_periodic_timer = timer_value;
            status = m_device->m_ll_device->write_register(*fc_port_cfg_0, fc_port_cfg0);
            return_on_error(status);
        }

        m_pfc_pif_periodic_timer_map[mac_lane_base_id + mac_lane] = timer_value;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_port_periodic_int_enable(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable)
{
    gibraltar::ifgb_24p_fc_cfg0_register fc_cfg0_reg;
    la_status status
        = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
    return_on_error(status);

    gibraltar::ifgb_24p_fc_port_cfg0_register fc_port_cfg0;
    status = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_port_cfg0)[mac_lane_base_id], fc_port_cfg0);
    return_on_error(status);

    if (fc_port_cfg0.fields.port_fc_mode == (size_t)la_mac_port::fc_mode_e::PFC) {
        uint64_t reg_val = fc_cfg0_reg.fields.periodic_int_en;

        bit_utils::set_bit(&reg_val, mac_lane_base_id, enable);
        for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
            bit_utils::set_bit(&reg_val, mac_lane_base_id + mac_lane, false);
        }

        fc_cfg0_reg.fields.periodic_int_en = reg_val;

        status
            = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->fc_cfg0, fc_cfg0_reg);
        return_on_error(status);
    }

    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        m_pfc_pif_en_periodic_send_map[mac_lane_base_id + mac_lane] = enable;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::allocate_rx_fifo_memory(size_t mac_lane_base, size_t buffer_units)
{
    /*******************************************************************************
     * The Rx buffer is shared for all the mac_lane's of the same port.
     * The buffer is the allocation per mac_lane times number of mac_lane in the port.
     *
     * The buffer is actually four buffers separated as following:
     * Buffer 0: ports 0-7
     * Buffer 1: ports 8-15
     * Buffer 2: ports 16-23
     * Buffer 3: Host port
     ******************************************************************************/
    ifgb_24p_rx_port_fifo_cfg_register rx_port_reg{{0}};

    size_t start_idx = mac_lane_base % 8;
    rx_port_reg.fields.f_start_addr = start_idx * RX_FIFO_ENTRIES_PER_LANE;
    rx_port_reg.fields.f_end_addr = rx_port_reg.fields.f_start_addr + buffer_units * RX_FIFO_ENTRIES_PER_LANE - 1;

    for (size_t i = 0; i < buffer_units; i++) {
        la_status stat = m_device->m_ll_device->write_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_fifo_cfg)[i + mac_lane_base], rx_port_reg);
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
ifg_handler_gibraltar::configure_rx_cgm(size_t mac_lane_base, size_t buffer_units, la_mac_port::port_speed_e speed)
{
    ifgb_24p_rx_port_cgm_cfg_register rx_cgm_reg{{0}};
    ifgb_24p_rx_port_cgm_sop_cfg_register rx_port_cgm_sop_cfg_val{{0}};

    size_t fifo_size = RX_FIFO_ENTRIES_PER_LANE * buffer_units;
    size_t rx_cgm_max_threshold = (speed == la_mac_port::port_speed_e::E_400G) ? fifo_size - 10 : fifo_size - 1;

    rx_cgm_reg.fields.p_tc0_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_tc1_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_tc2_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_tc3_drop_th = rx_cgm_max_threshold;
    rx_cgm_reg.fields.p_xon_th = (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) ? 220 : fifo_size * flow_control_default_xon;
    rx_cgm_reg.fields.p_xoff_th = (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) ? 240 : fifo_size * flow_control_default_xoff;

    size_t sop_drop_threshold = rx_cgm_max_threshold - 8; // 8 word in Rx buffer. in units of 128B
    rx_port_cgm_sop_cfg_val.fields.p_tc0_sop_drop_th = sop_drop_threshold;
    rx_port_cgm_sop_cfg_val.fields.p_tc1_sop_drop_th = sop_drop_threshold;
    rx_port_cgm_sop_cfg_val.fields.p_tc2_sop_drop_th = sop_drop_threshold;
    rx_port_cgm_sop_cfg_val.fields.p_tc3_sop_drop_th = sop_drop_threshold;

    for (size_t i = 0; i < buffer_units; i++) {
        la_status stat = m_device->m_ll_device->write_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[i + mac_lane_base], rx_cgm_reg);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_sop_cfg)[i + mac_lane_base],
            rx_port_cgm_sop_cfg_val);

        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::allocate_tx_fifo_memory_main_ports(size_t mac_lane_base, size_t mac_lanes_reserved_count)
{
    ifgb_24p_tx_fif_cfg_register tx_fif_reg{{0}};

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
ifg_handler_gibraltar::allocate_tx_fifo_memory_extra_ports(size_t mac_lane_base, size_t mac_lanes_reserved_count)
{
    ifgb_24p_tx_fif_cfg24_register tx_fif_reg{{0}};

    tx_fif_reg.fields.tx_f24_start_addr = m_ifg_handler_common.m_tx_fifo_lines_main_pif * MAX_NUM_PIF_PER_IFG;
    tx_fif_reg.fields.tx_f24_end_addr
        = tx_fif_reg.fields.tx_f24_start_addr + TX_FIFO_LINES_EXTRA_PIF * mac_lanes_reserved_count - 1;
    tx_fif_reg.fields.tx_alm_empty_thd24 = 0;

    la_status stat
        = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_fif_cfg24, tx_fif_reg);
    if (stat != LA_STATUS_SUCCESS) {
        log_err(HLD, "allocate_tx_fifo_memory_extra_ports: base=%ld, count=%ld", mac_lane_base, mac_lanes_reserved_count);
        return stat;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::reset_config()
{
    log_debug(HLD, "ifg_handler_gibraltar::reset_config()");
    lld_register_value_list_t reg_val_list;

    ifgb_24p_tx_cfg0_register tx_reg{{0}};
    ifgb_24p_rx_cfg0_register rx_reg{{0}};
    ifgb_24p_tx_prot_cfg1_register tx_prot_cfg1{{0}};
    ifgb_24p_tx_prot_cfg3_register tx_prot_cfg3{{0}};
    ifgb_24p_rx_prot_cfg4_register rx_prot_cfg4{{0}};

    la_status stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_prot_cfg1,
                                                          tx_prot_cfg1);
    return_on_error(stat);
    m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_prot_cfg3, tx_prot_cfg3);
    return_on_error(stat);

    rx_reg.fields.rx_8l_mode = tx_reg.fields.tx_8l_mode = 0;
    rx_reg.fields.rx_4l_mode = tx_reg.fields.tx_4l_mode = 0;
    rx_reg.fields.rx_mlp_mode = tx_reg.fields.tx_mlp_mode = 0;

    rx_reg.fields.rx_data_ecc_err_en = tx_reg.fields.tx_data_ecc_err_en = 0;
    rx_reg.fields.rx_fifo_status_sel = tx_reg.fields.tx_fifo_status_sel = 0;
    rx_reg.fields.rx_cnt_ka_en = tx_reg.fields.tx_cnt_ka_en = 0;
    rx_reg.fields.rx_undersize_filter_en = 0xffffff;

    tx_reg.fields.tx_flit_credit_cnt_status_sel = 0;

    if (m_device->is_network_slice(m_slice_id)) {

        tx_reg.fields.tx_2l_mode = 0;
        tx_reg.fields.tx_fabric_mode = 0;

        // Header size configuration: Add a configurable size of header to received data. 0B-64B in 8B granularity. Must be 0-8.
        // Configure all ports to 5 (40 bytes)
        reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->header_size_reg),
                                bit_vector("0x16D5555555555555555555555555")});
    } else {

        // Fabric
        tx_reg.fields.tx_2l_mode = 0xFFF;
        tx_reg.fields.tx_fabric_mode = 1;

        // Header size configuration: Add a configurable size of header to received data. 0B-40B in 8B granularity. Must be 0-5.
        // Configure all ports to 0 (0 bytes)
        reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->header_size_reg), 0});
    }

    rx_reg.fields.rx_2l_mode = tx_reg.fields.tx_2l_mode;
    rx_reg.fields.rx_fabric_mode = tx_reg.fields.tx_fabric_mode;

    rx_prot_cfg4.fields.rx_min_pkt_size = RX_MIN_PACKET_SIZE;
    rx_prot_cfg4.fields.rx_max_pkt_size = RX_MAX_PACKET_SIZE;

    tx_prot_cfg1.fields.tx_min_pkt_size_non_sop_err_prot_en = 0;
    tx_prot_cfg3.fields.tx_min_pkt_size_non_sop_err_cnt_en = 0;
    tx_prot_cfg1.fields.tx_min_pkt_size_sop_err_prot_en = 0;
    tx_prot_cfg3.fields.tx_min_pkt_size_sop_err_cnt_en = 0;

    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_cfg0), tx_reg});
    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_cfg0), rx_reg});
    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_prot_cfg1), tx_prot_cfg1});
    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_prot_cfg3), tx_prot_cfg3});
    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_prot_cfg4), rx_prot_cfg4});

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

/*******************************************************
 * Rx FIFO has actually four buffers:
 * Buffer 0: ports 0-7
 * Buffer 1: ports 8-15
 * Buffer 2: ports 16-23
 * Buffer 3: Host port
 */
la_status
ifg_handler_gibraltar::reset_rx_fifo_memory_allocation()
{
    log_debug(HLD, "ifg_handler_gibraltar::reset_rx_fifo_memory_allocation()");

    const size_t host_ports = 2;
    size_t host_lines = RX_FIFO_ENTRIES_PER_LANE * host_ports;

    la_status stat;

    stat = configure_rx_fifo_ports();
    return_on_error(stat);

    stat = configure_rx_fifo_host_port(host_lines);
    return_on_error(stat);

    stat = configure_rx_fifo_out_of_band(CSMS_LINES, FTE_LINES, FRM_LINES);
    return_on_error(stat);

    stat = configure_recycle_fifo();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_rx_fifo_ports()
{
    ifgb_24p_rx_port_fifo_cfg_register rx_port_reg{{0}};

    for (size_t i = 0; i < 8; i++) {
        rx_port_reg.fields.f_start_addr = i * RX_FIFO_ENTRIES_PER_LANE;
        rx_port_reg.fields.f_end_addr = rx_port_reg.fields.f_start_addr + RX_FIFO_ENTRIES_PER_LANE - 1;

        for (size_t mac_pool_idx = 0; mac_pool_idx < 3; mac_pool_idx++) {
            la_status stat = m_device->m_ll_device->write_register(
                (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_fifo_cfg)[i + mac_pool_idx * MAC_POOL_SIZE],
                rx_port_reg);
            return_on_error(stat);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_rx_fifo_host_port(size_t host_lines)
{
    lld_register_value_list_t reg_val_list;

    ifgb_24p_rx_ibi_fifo_cfg_register rx_ibi_reg{{0}};
    // TODO what about this
    // ifgb_24p_rx_port_cgm_cfg_register rx_port_cgm_reg{};

    rx_ibi_reg.fields.ibif_start_addr = 0;
    rx_ibi_reg.fields.ibif_end_addr = rx_ibi_reg.fields.ibif_start_addr + host_lines - 1;

    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_ibi_fifo_cfg), rx_ibi_reg});

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_rx_fifo_out_of_band(size_t csms_lines, size_t fte_lines, size_t frm_lines)
{
    lld_register_value_list_t reg_val_list;

    ifgb_24p_rx_csms_pkts_fifo_cfg_register rx_csms_fifo_reg{{0}};
    ifgb_24p_rx_frm_pkts_fifo_cfg_register rx_frm_fifo_reg{{0}};
    ifgb_24p_rx_fte_pkts_fifo_cfg_register rx_fte_fifo_reg{{0}};

    if (m_device->is_network_slice(m_slice_id)) {
        // Relevant only in fabric mode
        return LA_STATUS_SUCCESS;
    }

    size_t base = 0;

    rx_csms_fifo_reg.fields.f_csms_start_addr = base;
    base += csms_lines;
    rx_csms_fifo_reg.fields.f_csms_end_addr = base - 1;

    rx_fte_fifo_reg.fields.f_fte_start_addr = base;
    base += fte_lines;
    rx_fte_fifo_reg.fields.f_fte_end_addr = base - 1;

    rx_frm_fifo_reg.fields.f_frm_start_addr = base;
    base += frm_lines;
    rx_frm_fifo_reg.fields.f_frm_end_addr = base - 1;

    for (size_t i = 0; i < 3; i++) {
        reg_val_list.push_back(
            {(*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_csms_pkts_fifo_cfg)[i], rx_csms_fifo_reg});
        reg_val_list.push_back(
            {(*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_frm_pkts_fifo_cfg)[i], rx_frm_fifo_reg});
        reg_val_list.push_back(
            {(*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_fte_pkts_fifo_cfg)[i], rx_fte_fifo_reg});
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_rx_pma()
{
    bit_vector bv_rx_pma_cfg0(0, mac_pool8_rx_pma_cfg0_register::SIZE_IN_BITS);

    la_status stat;

    size_t mac_pool_count = m_ifg_handler_common.m_mac_lanes_reserved_count / 8;
    for (size_t mp8 = 0; mp8 < mac_pool_count; mp8++) {

        stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[mp8]->rx_pma_cfg0,
                                                    bv_rx_pma_cfg0);
        return_on_error(stat);

        // Update Rx mac_lane source
        for (size_t mac_lane_id = 0; mac_lane_id < MAC_POOL_SIZE; mac_lane_id++) {
            size_t rx_serdes_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][mac_lane_id + mp8 * MAC_POOL_SIZE].rx_source;
            size_t srd_src_lsb = mac_lane_id * 2;

            bv_rx_pma_cfg0.set_bits(srd_src_lsb + 1, srd_src_lsb, rx_serdes_source & 0x3);
        }

        stat = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[mp8]->rx_pma_cfg0, bv_rx_pma_cfg0);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_recycle_fifo()
{
    ifgb_24p_rcy_fif_cfg_register rcy_fif_cfg_reg{{0}};

    la_status stat = m_device->m_ll_device->read_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rcy_fif_cfg,
                                                          rcy_fif_cfg_reg);
    return_on_error(stat);

    rcy_fif_cfg_reg.fields.rcy_fif_mirror_start_addr = 0;
    rcy_fif_cfg_reg.fields.rcy_fif_mirror_end_addr = 114;
    rcy_fif_cfg_reg.fields.rcy_fif_mirror_wr_sop_thd = 86;
    rcy_fif_cfg_reg.fields.rcy_fif_redirect_start_addr = 115;
    rcy_fif_cfg_reg.fields.rcy_fif_redirect_end_addr = 229;
    rcy_fif_cfg_reg.fields.rcy_fif_redirect_wr_sop_thd = 86;
    rcy_fif_cfg_reg.fields.rcy_fif_sched_start_addr = 230;
    rcy_fif_cfg_reg.fields.rcy_fif_sched_end_addr = 679;
    rcy_fif_cfg_reg.fields.rcy_fif_sched_wr_sop_thd = 0x3FF;

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rcy_fif_cfg,
                                                 rcy_fif_cfg_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::reset_read_schedule_weight()
{
    log_debug(HLD, "ifg_handler_gibraltar::reset_read_schedule_weight()");

    ifgb_24p_rx_read_sch_cfg0_register rx_read_sch0{{0}};
    ifgb_24p_rx_read_sch_cfg1_register rx_read_sch1{{0}};
    ifgb_24p_rx_read_sch_cfg2_register rx_read_sch2{{0}};

    // Initialize all regular port to 0.
    // Initialize host and all recycle to 100Gbps or 200G if it is fabric 200Gbps
    device_port_handler_base::fabric_data fabric_data;
    m_device->m_device_port_handler->get_fabric_data(fabric_data);
    la_mac_port::port_speed_e speed = fabric_data.speed;
    // TODO: Host cfg seem to be missing ?
    // rx_read_sch2.fields.rd_sch_wt_p24 = read_schedule_weight.at(speed);
    rx_read_sch2.fields.rd_sch_wt_sch_rcy = read_schedule_weight.at(speed);
    rx_read_sch2.fields.rd_sch_wt_mirror_rcy = read_schedule_weight.at(speed);
    rx_read_sch2.fields.rd_sch_wt_redirect_rcy = read_schedule_weight.at(speed);
    rx_read_sch2.fields.rd_sch_wt_rcy_aggr = read_schedule_weight.at(speed);

    la_status stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg0, rx_read_sch0);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg1,
                                                 rx_read_sch1);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg2,
                                                 rx_read_sch2);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_read_schedule_weight(la_uint_t mac_lane_base_id,
                                                      size_t mac_lanes_reserved_count,
                                                      uint64_t read_weight)
{
    la_uint_t mac_pool_base_id = mac_lane_base_id % 8;

    ifgb_24p_rx_read_sch_cfg0_register rx_read_sch_cfg0;
    ifgb_24p_rx_read_sch_cfg2_register rx_read_sch_cfg2;

    lld_register_sptr device_rx_read_sch_reg = nullptr;

    size_t reg_idx = mac_lane_base_id / 8;
    switch (reg_idx) {
    case 0:
        device_rx_read_sch_reg = (m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg0);
        break;
    case 1:
        device_rx_read_sch_reg = (m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg1);
        break;
    case 2:
        device_rx_read_sch_reg = (m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_read_sch_cfg2);
        break;
    default:
        return LA_STATUS_EINVAL;
    };

    if (reg_idx == 2) {
        // Read
        la_status stat = m_device->m_ll_device->read_register(*device_rx_read_sch_reg, rx_read_sch_cfg2);
        return_on_error(stat);

        // Modify
        // Insert the total weight to the first one
        rx_read_sch_cfg2.u8[mac_pool_base_id] = read_weight;
        // Zero out all the rest
        for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
            rx_read_sch_cfg2.u8[mac_pool_base_id + mac_lane] = 0;
        }

        // Write
        stat = m_device->m_ll_device->write_register(*device_rx_read_sch_reg, rx_read_sch_cfg2);
        return_on_error(stat);
    } else {
        // Read
        la_status stat = m_device->m_ll_device->read_register(*device_rx_read_sch_reg, rx_read_sch_cfg0);
        return_on_error(stat);

        // Modify
        // Insert the total weight to the first one
        rx_read_sch_cfg0.u8[mac_pool_base_id] = read_weight;
        // Zero out all the rest
        for (size_t mac_lane = 1; mac_lane < mac_lanes_reserved_count; mac_lane++) {
            rx_read_sch_cfg0.u8[mac_pool_base_id + mac_lane] = 0;
        }

        // Write
        stat = m_device->m_ll_device->write_register(*device_rx_read_sch_reg, rx_read_sch_cfg0);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_ostc_quantizations(la_uint_t mac_lane_base_id,
                                              size_t mac_lanes_reserved_count,
                                              la_mac_port::port_speed_e speed,
                                              const la_mac_port::ostc_thresholds& thresholds)
{
    // Read register
    ifgb_24p_rx_port_cgm_cfg_register reg;
    ifgb_24p_rx_port_cgm_sop_cfg_register rx_port_cgm_sop_cfg_val;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[mac_lane_base_id], reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_sop_cfg)[mac_lane_base_id],
        rx_port_cgm_sop_cfg_val);
    return_on_error(stat);

    // Modify register
    size_t fifo_size = RX_FIFO_ENTRIES_PER_LANE * mac_lanes_reserved_count;
    size_t rx_cgm_max_threshold = (speed == la_mac_port::port_speed_e::E_400G) ? fifo_size - 10 : fifo_size - 1;

    uint64_t values[la_mac_port::OSTC_TRAFFIC_CLASSES];
    for (size_t i = 0; i < la_mac_port::OSTC_TRAFFIC_CLASSES; i++) {
        values[i] = std::min((size_t)(fifo_size * thresholds.thresholds[i]), rx_cgm_max_threshold);
    }

    reg.fields.p_tc0_drop_th = values[0];
    reg.fields.p_tc1_drop_th = values[1];
    reg.fields.p_tc2_drop_th = values[2];
    reg.fields.p_tc3_drop_th = values[3];

    // RxPortCgmCfg must be in sync with RxPortCgmSopCfg
    rx_port_cgm_sop_cfg_val.fields.p_tc0_sop_drop_th = values[0] - 8;
    rx_port_cgm_sop_cfg_val.fields.p_tc1_sop_drop_th = values[1] - 8;
    rx_port_cgm_sop_cfg_val.fields.p_tc2_sop_drop_th = values[2] - 8;
    rx_port_cgm_sop_cfg_val.fields.p_tc3_sop_drop_th = values[3] - 8;

    // Write register
    for (size_t i = 0; i < mac_lanes_reserved_count; i++) {
        stat = m_device->m_ll_device->write_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[i + mac_lane_base_id], reg);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_sop_cfg)[i + mac_lane_base_id],
            rx_port_cgm_sop_cfg_val);
        return_on_error(stat);
    }
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::modify_port_tc_tpid(la_uint_t mac_lane_base_id,
                                           size_t mac_lanes_reserved_count,
                                           la_uint_t idx,
                                           la_tpid_t tpid)
{
    dassert_crit(idx < static_cast<size_t>(la_mac_port_base::OSTC_NUM_TPIDS));

    // Read register
    ifgb_24p_tc_extract_cfg_reg_register reg;
    la_uint_t lane_idx = mac_lane_base_id / 2;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[lane_idx], reg);
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
ifg_handler_gibraltar::remove_port_tc_tpid(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx)
{
    la_status status = modify_port_tc_tpid(mac_lane_base_id, mac_lanes_reserved_count, idx, la_mac_port::RESERVED_ETHERTYPE);
    return status;
}

la_status
ifg_handler_gibraltar::get_ostc_quantizations(la_uint_t mac_lane_base_id,
                                              size_t mac_lanes_reserved_count,
                                              la_mac_port::port_speed_e speed,
                                              la_mac_port::ostc_thresholds& out_thresholds) const
{
    // Read register
    ifgb_24p_rx_port_cgm_cfg_register reg;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_port_cgm_cfg)[mac_lane_base_id], reg);
    return_on_error(stat);

    // Update output
    size_t fifo_size = RX_FIFO_ENTRIES_PER_LANE * mac_lanes_reserved_count;
    out_thresholds.thresholds[0] = (double)reg.fields.p_tc0_drop_th / fifo_size;
    out_thresholds.thresholds[1] = (double)reg.fields.p_tc1_drop_th / fifo_size;
    out_thresholds.thresholds[2] = (double)reg.fields.p_tc2_drop_th / fifo_size;
    out_thresholds.thresholds[3] = (double)reg.fields.p_tc3_drop_th / fifo_size;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_default_port_tc(la_uint_t mac_lane_base_id,
                                           size_t mac_lanes_reserved_count,
                                           la_over_subscription_tc_t default_ostc,
                                           la_initial_tc_t default_itc)
{
    // Read register
    ifgb_24p_tc_extract_cfg_reg_register reg;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    reg.fields.tc_ext_default_tc = combine_ostc_and_itc(default_ostc, default_itc);

    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::get_default_port_tc(la_uint_t mac_lane_base_id,
                                           la_over_subscription_tc_t& out_default_ostc,
                                           la_initial_tc_t& out_default_itc) const
{
    // Read register
    ifgb_24p_tc_extract_cfg_reg_register reg;
    la_uint_t lane_idx = mac_lane_base_id / 2;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[lane_idx], reg);
    return_on_error(stat);

    split_value_to_ostc_and_itc(reg.fields.tc_ext_default_tc, out_default_ostc, out_default_itc);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_port_tc_extract_offset(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t offset)
{
    ifgb_24p_tc_extract_cfg_reg_register reg;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[mac_lane_base_id / 2], reg);
    return_on_error(stat);

    reg.fields.tc_ext_byte_os = offset;

    // Write register
    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::add_port_tc_custom_protocol(la_uint_t mac_lane_base_id,
                                                   size_t mac_lanes_reserved_count,
                                                   la_uint_t idx,
                                                   la_ethertype_t protocol)
{
    // Read register
    ifgb_24p_tc_extract_cfg_reg_register reg;
    la_uint_t lane_idx = mac_lane_base_id / 2;
    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[lane_idx], reg);
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

    stat = write_tc_extract_cfg(reg, mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    stat = reset_port_tc_custom_protocol_configuration(mac_lane_base_id, idx);
    return_on_error(stat);
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::remove_port_tc_custom_protocol(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, la_uint_t idx)
{
    // Read register
    ifgb_24p_tc_extract_cfg_reg_register reg;
    la_uint_t lane_idx = mac_lane_base_id / 2;

    la_status stat = m_device->m_ll_device->read_register(
        (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tc_extract_cfg_reg)[lane_idx], reg);
    return_on_error(stat);

    // Modify register
    switch (idx) {
    case 0:
        reg.fields.tc_ext_eth_type0_ = 0xFFFF;
        break;
    case 1:
        reg.fields.tc_ext_eth_type1_ = 0xFFFF;
        break;
    case 2:
        reg.fields.tc_ext_eth_type2_ = 0xFFFF;
        break;
    case 3:
        reg.fields.tc_ext_eth_type3_ = 0xFFFF;
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
ifg_handler_gibraltar::get_port_tc_tcam_key_opcode(la_uint_t mac_lane_base_id,
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
ifg_handler_gibraltar::update_lane_modes(la_uint_t mac_lane_base_id,
                                         size_t mac_lanes_count,
                                         uint64_t& two_lane_mode,
                                         uint64_t& four_lane_mode,
                                         uint64_t& eight_lane_mode)
{
    switch (mac_lanes_count) {
    case 1:
    case 2:
        two_lane_mode = bit_utils::set_bit(two_lane_mode, (mac_lane_base_id / 2), (mac_lanes_count != 1));
        four_lane_mode = bit_utils::set_bit(four_lane_mode, (mac_lane_base_id / 4), 0);
        eight_lane_mode = bit_utils::set_bit(eight_lane_mode, (mac_lane_base_id / 8), 0);
        break;
    case 4:
        two_lane_mode = bit_utils::set_bits(two_lane_mode, (mac_lane_base_id / 2) + 1, (mac_lane_base_id / 2), 0);
        four_lane_mode = bit_utils::set_bit(four_lane_mode, (mac_lane_base_id / 4), 1);
        eight_lane_mode = bit_utils::set_bit(eight_lane_mode, (mac_lane_base_id / 8), 0);
        break;
    case 8:
        two_lane_mode = bit_utils::set_bits(two_lane_mode, (mac_lane_base_id / 2) + 3, (mac_lane_base_id / 2), 0);
        four_lane_mode = bit_utils::set_bits(four_lane_mode, (mac_lane_base_id / 4) + 1, (mac_lane_base_id / 4), 0);
        eight_lane_mode = bit_utils::set_bit(eight_lane_mode, (mac_lane_base_id / 8), 1);
        break;
    case 16:
        two_lane_mode = bit_utils::set_bits(two_lane_mode, (mac_lane_base_id / 2) + 7, (mac_lane_base_id / 2), 0);
        four_lane_mode = bit_utils::set_bits(four_lane_mode, (mac_lane_base_id / 4) + 3, (mac_lane_base_id / 4), 0);
        eight_lane_mode = bit_utils::set_bits(eight_lane_mode, (mac_lane_base_id / 8) + 1, (mac_lane_base_id / 8), 3);
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::configure_oob_inject_packet_counters()
{
    ifgb_24p_oobi_pkt_type_cnt_en_register oobi_cnt_en_reg{{0}};

    // Enable all OOB injected packet counter types
    oobi_cnt_en_reg.fields.oobi_csms_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_frm_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_fte_pd_req_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_fte_pd_res_cnt_en = 1;
    oobi_cnt_en_reg.fields.oobi_fte_fts_cnt_en = 1;

    la_status status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->oobi_pkt_type_cnt_en, oobi_cnt_en_reg);
    return status;
}

la_status
ifg_handler_gibraltar::configure_oob_extract_packet_counters()
{
    ifgb_24p_oobe_pkt_type_cnt_en_register oobe_cnt_en_reg{{0}};

    // Enable all OOB extracted packet counter types
    oobe_cnt_en_reg.fields.oobe_csms_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_frm_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_fte_pd_req_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_fte_pd_res_cnt_en = 1;
    oobe_cnt_en_reg.fields.oobe_fte_fts_cnt_en = 1;

    la_status status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->oobe_pkt_type_cnt_en, oobe_cnt_en_reg);
    return status;
}

la_status
ifg_handler_gibraltar::set_reset_fifo_memory(fifo_memory_reset_state_e state)
{
    ifgb_24p_rx_rstn_reg_register rx_rstn_reg{{0}};
    ifgb_24p_tx_rstn_reg_register tx_rstn_reg{{0}};
    la_status status;
    lld_register_value_list_t reg_val_list;

    bool ibi_active = (state == fifo_memory_reset_state_e::ACTIVATE_INBAND_ONLY);

    rx_rstn_reg.fields.rx_ibi_rstn = ibi_active;
    if (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC && state == fifo_memory_reset_state_e::ACTIVATE_INBAND_ONLY) {
        rx_rstn_reg.fields.rx_oobe_rstn = 1;
    } else {
        rx_rstn_reg.fields.rx_oobe_rstn = 0;
    }
    rx_rstn_reg.fields.rx_rstn = 1;
    // rx_protect_pif_rstn[0:25] bits are 0:23 for regular mac_lane's, bit24 for inband host, bit25 for recycle port
    // oob doesn't have rx protect as it's rx buffer is simple
    rx_rstn_reg.fields.rx_protect_pif_rstn
        = rx_rstn_reg.fields.rx_lane_rstn
          | (rx_rstn_reg.fields.rx_ibi_rstn << ifgb_24p_rx_rstn_reg_register::fields::RX_LANE_RSTN_WIDTH)
          | (ibi_active << (ifgb_24p_rx_rstn_reg_register::fields::RX_LANE_RSTN_WIDTH
                            + ifgb_24p_rx_rstn_reg_register::fields::RX_IBI_RSTN_WIDTH));

    bit_vector tx_lane_rstn(0, ifgb_24p_tx_rstn_reg_register::fields::TX_LANE_RSTN_WIDTH);

    tx_lane_rstn.set_bit(HOST_PIF_ID, ibi_active);
    tx_lane_rstn.set_bit(RECYCLE_PIF_ID, ibi_active);

    tx_rstn_reg.fields.tx_lane_rstn = tx_lane_rstn.get_value();
    tx_rstn_reg.fields.tx_rstn = 1;
    tx_rstn_reg.fields.tx_protect_pif_rstn = tx_rstn_reg.fields.tx_lane_rstn;

    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_rstn_reg), rx_rstn_reg});
    reg_val_list.push_back({(m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->tx_rstn_reg), tx_rstn_reg});

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::read_ostc_counter(la_uint_t mac_lane_base_id,
                                         la_over_subscription_tc_t ostc,
                                         size_t& out_dropped_packets) const
{
    // TODO: scrub results periodically so no overflow will accour
    ifgb_24p_rx_port_cgm_tc0_drop_counter_register reg1;
    ifgb_24p_rx_port_cgm_tc0_partial_drop_counter_register reg2;
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
ifg_handler_gibraltar::set_rx_lane_swap()
{
    // Update serdes_pool block

    size_t size_in_bits = (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16
                               ? (size_t)serdes_pool16_serdes_rx_lane_swap_config_register::SIZE_IN_BITS
                               : (size_t)serdes_pool24_serdes_rx_lane_swap_config_register::SIZE_IN_BITS);

    bit_vector serdes_rx_lane_swap_config_register(0, size_in_bits);
    bit_vector serdes_tx_lane_swap_config_register(0, size_in_bits);
    for (size_t serdes_id = 0; serdes_id < m_ifg_handler_common.m_mac_lanes_reserved_count; serdes_id++) {
        size_t rx_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_id].rx_source;
        serdes_rx_lane_swap_config_register.set_bits(serdes_id * 2 + 1, serdes_id * 2, rx_source & 0x3);
        serdes_tx_lane_swap_config_register.set_bits(rx_source * 2 + 1, rx_source * 2, serdes_id & 0x3);
    }

    la_status status = m_device->m_ll_device->write_register(*m_serdes_rx_lane_swap_config, serdes_rx_lane_swap_config_register);
    log_debug(HLD,
              "Set rx_lane_swap %d/%d %d: %lx",
              (int)m_slice_id,
              (int)m_ifg_id,
              (int)m_ifg_handler_common.m_mac_lanes_reserved_count,
              serdes_rx_lane_swap_config_register.get_value());
    return_on_error(status);

    status = m_device->m_ll_device->write_register(*m_serdes_tx_lane_swap_config, serdes_tx_lane_swap_config_register);
    log_debug(HLD,
              "Set tx_lane_swap %d/%d %d: %lx",
              (int)m_slice_id,
              (int)m_ifg_id,
              (int)m_ifg_handler_common.m_mac_lanes_reserved_count,
              serdes_tx_lane_swap_config_register.get_value());
    return_on_error(status);

    // MAC pool (RxPmaCfg0) configuration is part of the port configuration

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status)
{
    // Same size for serdes_pool16 and serdes_pool24
    serdes_pool16_serdes_status_register serdes_status;
    la_status stat = m_device->m_ll_device->read_register((*m_serdes_status)[serdes_idx], serdes_status);
    return_on_error(stat);

    out_serdes_status.rx_ready = serdes_status.fields.rx_rdy;
    out_serdes_status.signal_ok = serdes_status.fields.signal_ok;

    // Same size for serdes_pool16 and serdes_pool24
    // PLL status in gibraltar is shared for pair of SerDes
    serdes_pool16_serdes_pll_status_register pll_status;
    stat = m_device->m_ll_device->read_register((*m_serdes_pll_status)[serdes_idx / 2], pll_status);
    return_on_error(stat);

    out_serdes_status.tx_ready = pll_status.fields.pll_lock; // TODO get it from SerDes

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::get_fabric_port_number(la_uint_t first_serdes_id, la_uint_t& out_port_num) const
{
    gibraltar::pier_oob_fabric_link_to_src_link_map_table_memory entry;
    lld_memory_sptr fabric_link_to_src_link_map(m_gibraltar_tree->dmc->pier->oob_fabric_link_to_src_link_map_table);
    size_t serdes_index_in_device = get_port_base_index() + first_serdes_id;
    size_t fabric_serdes_index_in_device = serdes_index_in_device / 2;

    la_status status = m_device->m_ll_device->read_memory(fabric_link_to_src_link_map, fabric_serdes_index_in_device, entry);
    return_on_error(status);

    out_port_num = entry.fields.oob_fabric_link_to_src_link_map_data;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::read_mib_counters(bool clear, la_uint_t serdes_idx, la_mac_port::mib_counters& out_mib_counters) const
{
    ifgb_24p_rx_oobe_crc_err_counter_register rx_oob_crc_reg;

    la_status rc;
    // OOB registers are only for 100G/200G fabric ports, counter is shared by neighboring serdes.
    la_uint_t fabric_port_idx = serdes_idx / 2;
    if (clear) {
        rc = m_device->m_ll_device->read_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_oobe_crc_err_counter)[fabric_port_idx], rx_oob_crc_reg);
        return_on_error(rc);
    } else {
        rc = m_device->m_ll_device->peek_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->ifgb->rx_oobe_crc_err_counter)[fabric_port_idx], rx_oob_crc_reg);
        return_on_error(rc);
    }

    // rx_oob_mac_invert_crc and rx_oob_mac_crc_err are both read from the IFGB rx_oobe_port_crc_err_cnt in GB.
    // Only relevant for Fabric ports
    if (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC) {
        out_mib_counters.rx_oob_mac_invert_crc = rx_oob_crc_reg.fields.rx_oobe_port_crc_err_cnt;
        out_mib_counters.rx_oob_mac_crc_err = rx_oob_crc_reg.fields.rx_oobe_port_crc_err_cnt;
    } else {
        out_mib_counters.rx_oob_mac_invert_crc = 0;
        out_mib_counters.rx_oob_mac_crc_err = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_synce_default()
{
    // Set the default Divider to 32.
    la_status status;

    if (m_ifg_handler_common.m_pool_type == pool_16) {
        serdes_pool16_serdes_synce_control_register serdes16_synce_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);
        serdes16_synce_reg.fields.synce_pri_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
        serdes16_synce_reg.fields.synce_pri_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        serdes16_synce_reg.fields.synce_pri_clk_div = SYNCE_DETACH_OUTPUT_DIV;
        serdes16_synce_reg.fields.synce_sec_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
        serdes16_synce_reg.fields.synce_sec_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        serdes16_synce_reg.fields.synce_sec_clk_div = SYNCE_DETACH_OUTPUT_DIV;

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);
    } else {
        serdes_pool24_serdes_synce_control_register serdes24_synce_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);
        serdes24_synce_reg.fields.synce_pri_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
        serdes24_synce_reg.fields.synce_pri_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        serdes24_synce_reg.fields.synce_pri_clk_div = SYNCE_DETACH_OUTPUT_DIV;
        serdes24_synce_reg.fields.synce_sec_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
        serdes24_synce_reg.fields.synce_sec_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        serdes24_synce_reg.fields.synce_sec_clk_div = SYNCE_DETACH_OUTPUT_DIV;

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::attach_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                           la_slice_id_t slice_id,
                                           la_ifg_id_t ifg_id,
                                           la_uint_t serdes_id,
                                           uint32_t divider)
{
    uint32_t ifg_global;
    uint32_t ifg_synce_sel = 0;
    bool synce_attached;
    la_status status;

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

    status = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice_id, ifg_id);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "%s: slice=%d, ifg=%d is out of range or disabled.", __func__, slice_id, ifg_id);
        return status;
    }

    ifg_global = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(slice_id, ifg_id);

    ifg_synce_sel = synce_ifg_map[ifg_global];

    lld_register_scptr serdes_synce_unlock_clear;

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        serdes_pool16_serdes_synce_control_register serdes16_synce_reg = {{0}};
        serdes_pool16_serdes_synce_pri_unlock_clear_register unlock_clear_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes16_synce_reg.fields.synce_pri_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_FALSE;
            serdes16_synce_reg.fields.synce_pri_ifg_sel_cfg = ifg_synce_sel;
            serdes16_synce_reg.fields.synce_pri_clk_sel = serdes_id;
            serdes16_synce_reg.fields.synce_pri_clk_div = divider;

            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_pri_unlock_clear;
        } else {
            serdes16_synce_reg.fields.synce_sec_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_FALSE;
            serdes16_synce_reg.fields.synce_sec_ifg_sel_cfg = ifg_synce_sel;
            serdes16_synce_reg.fields.synce_sec_clk_sel = serdes_id;
            serdes16_synce_reg.fields.synce_sec_clk_div = divider;

            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_sec_unlock_clear;
        }

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);

        // Set unlock_clear_register to clear unlock status
        status = m_device->m_ll_device->read_register(serdes_synce_unlock_clear, unlock_clear_reg);
        return_on_error(status);

        unlock_clear_reg.fields.synce_pri_unlock_clear = 0;
        status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
        return_on_error(status);
        unlock_clear_reg.fields.synce_pri_unlock_clear = 1;
        status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
        return_on_error(status);

    } else {
        serdes_pool24_serdes_synce_control_register serdes24_synce_reg = {{0}};
        serdes_pool24_serdes_synce_pri_unlock_clear_register unlock_clear_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);

        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes24_synce_reg.fields.synce_pri_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_FALSE;
            serdes24_synce_reg.fields.synce_pri_ifg_sel_cfg = ifg_synce_sel;
            serdes24_synce_reg.fields.synce_pri_clk_sel = serdes_id;
            serdes24_synce_reg.fields.synce_pri_clk_div = divider;

            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_pri_unlock_clear;
        } else {
            serdes24_synce_reg.fields.synce_sec_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_FALSE;
            serdes24_synce_reg.fields.synce_sec_ifg_sel_cfg = ifg_synce_sel;
            serdes24_synce_reg.fields.synce_sec_clk_sel = serdes_id;
            serdes24_synce_reg.fields.synce_sec_clk_div = divider;

            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_sec_unlock_clear;
        }

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);

        // Set unlock_clear_register to clear unlock status
        status = m_device->m_ll_device->read_register(serdes_synce_unlock_clear, unlock_clear_reg);
        return_on_error(status);

        unlock_clear_reg.fields.synce_pri_unlock_clear = 0;
        status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
        return_on_error(status);
        unlock_clear_reg.fields.synce_pri_unlock_clear = 1;
        status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
        return_on_error(status);
    }

    m_synce_attached[(size_t)prim_sec_clock] = true;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::get_synce_output(la_device::synce_clock_sel_e prim_sec_clock,
                                        uint32_t synce_pin,
                                        la_slice_id_t& out_slice_id,
                                        la_ifg_id_t& out_ifg_id,
                                        la_uint_t& out_serdes_id,
                                        uint32_t& out_divider) const
{
    uint32_t ifg_synce_sel;
    bool synce_attached;
    la_status status;

    status = check_synce_attached(prim_sec_clock, synce_attached);
    return_on_error_log(status, HLD, ERROR, "Failed to get SyncE clock status on %d/%d. ", m_slice_id, m_ifg_id);

    if (!synce_attached) {
        log_err(HLD, "%d/%d recovered clock detached. ", m_slice_id, m_ifg_id);
        return LA_STATUS_ENOTFOUND;
    }

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        serdes_pool16_serdes_synce_control_register serdes16_synce_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);

        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            ifg_synce_sel = synce_pin * NUM_IFGS_PER_SYNCE_GROUP + serdes16_synce_reg.fields.synce_pri_ifg_sel_cfg;
            out_serdes_id = serdes16_synce_reg.fields.synce_pri_clk_sel;
            out_divider = serdes16_synce_reg.fields.synce_pri_clk_div;
        } else {
            ifg_synce_sel = synce_pin * NUM_IFGS_PER_SYNCE_GROUP + serdes16_synce_reg.fields.synce_sec_ifg_sel_cfg;
            out_serdes_id = serdes16_synce_reg.fields.synce_sec_clk_sel;
            out_divider = serdes16_synce_reg.fields.synce_sec_clk_div;
        }
    } else {
        serdes_pool24_serdes_synce_control_register serdes24_synce_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);

        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            ifg_synce_sel = synce_pin * NUM_IFGS_PER_SYNCE_GROUP + serdes24_synce_reg.fields.synce_pri_ifg_sel_cfg;
            out_serdes_id = serdes24_synce_reg.fields.synce_pri_clk_sel;
            out_divider = serdes24_synce_reg.fields.synce_pri_clk_div;
        } else {
            ifg_synce_sel = synce_pin * NUM_IFGS_PER_SYNCE_GROUP + serdes24_synce_reg.fields.synce_sec_ifg_sel_cfg;
            out_serdes_id = serdes24_synce_reg.fields.synce_sec_clk_sel;
            out_divider = serdes24_synce_reg.fields.synce_sec_clk_div;
        }
    }

    uint32_t ifg = synce_ifg_demap[ifg_synce_sel];

    auto s_ifg = m_device->get_slice_id_manager()->global_ifg_2_slice_ifg(ifg);
    out_slice_id = s_ifg.slice;
    out_ifg_id = s_ifg.ifg;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::detach_synce_output(la_device::synce_clock_sel_e prim_sec_clock, uint32_t synce_pin)
{
    la_status status;
    bool synce_attached;

    status = check_synce_attached(prim_sec_clock, synce_attached);
    return_on_error_log(status, HLD, ERROR, "Failed to get SyncE clock status on %d/%d. ", m_slice_id, m_ifg_id);

    if (!synce_attached) {
        log_err(HLD, "%d/%d recovered clock already detached. ", m_slice_id, m_ifg_id);
        return LA_STATUS_ENOTFOUND;
    }

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        serdes_pool16_serdes_synce_control_register serdes16_synce_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);

        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes16_synce_reg.fields.synce_pri_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
            serdes16_synce_reg.fields.synce_pri_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        } else {
            serdes16_synce_reg.fields.synce_sec_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
            serdes16_synce_reg.fields.synce_sec_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        }

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_control, serdes16_synce_reg);
        return_on_error(status);
    } else {
        serdes_pool24_serdes_synce_control_register serdes24_synce_reg = {{0}};

        status = m_device->m_ll_device->read_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);

        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes24_synce_reg.fields.synce_pri_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
            serdes24_synce_reg.fields.synce_pri_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        } else {
            serdes24_synce_reg.fields.synce_sec_ifg_override_lock_en = SYNCE_OVERRIDE_LOCK_TRUE;
            serdes24_synce_reg.fields.synce_sec_ifg_override_lock_value = SYNCE_OVERRIDE_LOCK_FALSE;
        }

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_control, serdes24_synce_reg);
        return_on_error(status);
    }

    m_synce_attached[(size_t)prim_sec_clock] = false;
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::clear_synce_squelch_lock(la_device::synce_clock_sel_e prim_sec_clock)
{
    lld_register_scptr serdes_synce_unlock_clear;
    // mac pool16 pri|sec & pool24 pri|sec has the same register mapping
    serdes_pool16_serdes_synce_pri_unlock_clear_register unlock_clear_reg = {{0}};

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_pri_unlock_clear;
        } else {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_sec_unlock_clear;
        }
    } else {
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_pri_unlock_clear;
        } else {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_sec_unlock_clear;
        }
    }

    // Set unlock_clear_register to clear unlock status
    la_status status = m_device->m_ll_device->read_register(serdes_synce_unlock_clear, unlock_clear_reg);
    return_on_error(status);

    unlock_clear_reg.fields.synce_pri_unlock_clear = 0;
    status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
    return_on_error(status);
    unlock_clear_reg.fields.synce_pri_unlock_clear = 1;
    status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::set_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool squelch_enable)
{
    lld_register_scptr serdes_synce_unlock_clear;
    // mac pool16 pri|sec & pool24 pri|sec has the same register mapping
    serdes_pool16_serdes_synce_pri_unlock_clear_register unlock_clear_reg = {{0}};

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_pri_unlock_clear;
        } else {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_sec_unlock_clear;
        }
    } else {
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_pri_unlock_clear;
        } else {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_sec_unlock_clear;
        }
    }

    // Set unlock_clear_register to enable/disable squelch mechanism
    la_status status = m_device->m_ll_device->read_register(serdes_synce_unlock_clear, unlock_clear_reg);
    return_on_error(status);

    unlock_clear_reg.fields.synce_pri_squelch_enable = squelch_enable;
    status = m_device->m_ll_device->write_register(serdes_synce_unlock_clear, unlock_clear_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::get_synce_auto_squelch(la_device::synce_clock_sel_e prim_sec_clock, bool& out_squelch_enable)
{
    lld_register_scptr serdes_synce_unlock_clear;
    // mac pool16 pri|sec & pool24 pri|sec has the same register mapping
    serdes_pool16_serdes_synce_pri_unlock_clear_register unlock_clear_reg = {{0}};

    if (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16) {
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_pri_unlock_clear;
        } else {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool16->serdes_synce_sec_unlock_clear;
        }
    } else {
        if (prim_sec_clock == la_device::synce_clock_sel_e::PRIMARY) {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_pri_unlock_clear;
        } else {
            serdes_synce_unlock_clear
                = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->serdes_pool24->serdes_synce_sec_unlock_clear;
        }
    }

    // Get squelch enable/disable status in unlock_clear_register
    la_status status = m_device->m_ll_device->read_register(serdes_synce_unlock_clear, unlock_clear_reg);
    return_on_error(status);

    out_squelch_enable = unlock_clear_reg.fields.synce_pri_squelch_enable;

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_gibraltar::update_anlt_order(la_uint_t serdes_base_id, size_t serdes_count)
{
    la_status status;
    // Get the first Serdes sorting by ANLT order
    size_t an_master_idx = serdes_base_id;
    size_t first_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_base_id].anlt_order;
    for (size_t serdes = 1; serdes < serdes_count; serdes++) {
        size_t serdes_idx = serdes + serdes_base_id;
        if (first_serdes > m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_idx].anlt_order) {
            first_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_idx].anlt_order;
            an_master_idx = serdes_idx;
        }
    }
    size_t an_master_rx = m_device->m_serdes_info[m_slice_id][m_ifg_id][an_master_idx].rx_source;

    size_t an_master_size_in_bits = (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16
                                         ? (size_t)serdes_pool16_serdes_an_master_config_register::SIZE_IN_BITS
                                         : (size_t)serdes_pool24_serdes_an_master_config_register::SIZE_IN_BITS);
    size_t an_bitmap_size_in_bits = (m_ifg_handler_common.m_pool_type == serdes_pool_type_e::pool_16
                                         ? (size_t)serdes_pool16_serdes_an_bitmap_config_register::SIZE_IN_BITS
                                         : (size_t)serdes_pool24_serdes_an_bitmap_config_register::SIZE_IN_BITS);
    bit_vector an_master_reg(0, an_master_size_in_bits);
    bit_vector an_bitmap_reg(0, an_bitmap_size_in_bits);
    status = m_device->m_ll_device->read_register(*m_serdes_an_master_config, an_master_reg);
    return_on_error(status);

    status = m_device->m_ll_device->read_register(*m_serdes_an_bitmap_config, an_bitmap_reg);
    return_on_error(status);

    // Find all Rx serdes in the bundle, sorting by Tx order.
    size_t bit_data = 0;
    for (size_t ii = 0; ii < serdes_count; ii++) {
        size_t rx_bundle_i = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_base_id + ii].rx_source;
        bit_data |= 1 << (rx_bundle_i % 8);
    }

    // Create the configuration data per IFG
    for (size_t serdes = 0; serdes < serdes_count; serdes++) {
        size_t serdes_idx = serdes_base_id + serdes;
        size_t rx_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_idx].rx_source;

        // Check to see if we need to put the data in the upper bits
        an_bitmap_reg.set_bits(rx_source * 8 + 7, rx_source * 8, bit_data);
        an_master_reg.set_bits(rx_source * 3 + 2, rx_source * 3, an_master_rx & 0x7);
    }

    status = m_device->m_ll_device->write_register(*m_serdes_an_master_config, an_master_reg);
    return_on_error(status);

    status = m_device->m_ll_device->write_register(*m_serdes_an_bitmap_config, an_bitmap_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
