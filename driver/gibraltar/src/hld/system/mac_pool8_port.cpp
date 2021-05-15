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

#include "mac_pool8_port.h"
#include "common/defines.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include <chrono>
#include <thread>

namespace silicon_one
{

using namespace gibraltar;
enum {
    RX_PMA_CFG0_PAM4_EN_OFFSET = 16,
    RX_PMA_CFG0_GREYCODE_OFFSET = 32,
    RX_PMA_CFG0_DWIDTH_OFFSET = 40,
    RX_PMA_CFG0_SIGNAL_OK_OVERRIDE_ENABLE_OFFSET = 48,
    RX_PMA_CFG0_SIGNAL_OK_OVERRIDE_VALUE_OFFSET = 56,

    TX_PMA_CFG0_PAM4_EN_OFFSET = 32,
    TX_PMA_CFG0_GREYCODE_OFFSET = 48,
    TX_PMA_CFG0_DWIDTH_OFFSET = 56,
};

enum rstn_offset {
    TX_MAC = 0,
    RX_MAC = 8,
    TX_RS = 16,
    RX_RS = 24,
    TX_PCS = 32,
    RX_PCS = 40,
    RX_PCS_SYNC = 48,
    TX_RSF = 56,
    RX_RSF = 64,
    TX_PMA = 72,
    TX_SERDES = 80,
    RX_PMA = 88,
    RX_SERDES = 96,
    TX_KR_FEC = 104,
    RX_KR_FEC = 112,

    STEP = 8,
    TX_PMA_CONFIGS = 2,
};

mac_pool8_port::mac_pool8_port(const la_device_impl_wptr& device) : gibraltar_mac_pool(device)
{
}

mac_pool8_port::~mac_pool8_port()
{
}

la_status
mac_pool8_port::initialize(la_slice_id_t slice_id,
                           la_ifg_id_t ifg_id,
                           la_uint_t serdes_base,
                           size_t num_of_serdes,
                           la_mac_port::port_speed_e speed,
                           la_mac_port::fc_mode_e rx_fc_mode,
                           la_mac_port::fc_mode_e tx_fc_mode,
                           la_mac_port::fec_mode_e fec_mode,
                           la_mac_port::mlp_mode_e mlp_mode,
                           la_slice_mode_e port_slice_mode)
{
    m_mac_pool_index = serdes_base / la_mac_port_base::NUM_SERDESES_IN_MAC_POOL8;
    m_serdes_index_in_mac_pool = get_serdes_index_in_mac_pool(serdes_base);
    m_mac_lane_index_in_mac_pool = m_serdes_index_in_mac_pool;
    m_mac_lane_index_in_ifgb = serdes_base;
    if (num_of_serdes > la_mac_port_base::NUM_SERDESES_IN_MAC_POOL8) {
        return LA_STATUS_EINVAL;
    }
    la_status stat = gibraltar_mac_pool::initialize(
        slice_id, ifg_id, serdes_base, num_of_serdes, speed, rx_fc_mode, tx_fc_mode, fec_mode, mlp_mode, port_slice_mode);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

size_t
mac_pool8_port::get_serdes_index_in_mac_pool(size_t serdes_idx) const
{
    return serdes_idx % la_mac_port_base::NUM_SERDESES_IN_MAC_POOL8;
}

la_status
mac_pool8_port::configure_lanes()
{
    mac_pool8_tx_mac_lanes_cfg_register tx_reg = {{0}};
    mac_pool8_rx_mac_lanes_cfg_register rx_reg = {{0}};
    mac_pool8_mlp_cfg_register mlp_reg = {{0}};

    // This MAC pool port control only part of the bits, need to read and modify only the relevant bits.
    // Since TX and RX are similar configuration, reads only one of them.
    la_status stat;
    stat = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->tx_mac_lanes_cfg, tx_reg);
    return_on_error(stat);
    uint64_t two_lane_mode = tx_reg.fields.tx_2_lanes_mode;
    uint64_t four_lane_mode = tx_reg.fields.tx_4_lanes_mode;
    uint64_t eight_lane_mode = tx_reg.fields.tx_8_lanes_mode;

    switch (m_mac_lanes_count) {
    case 1:
    case 2:
        bit_utils::set_bit(&two_lane_mode, (m_serdes_index_in_mac_pool / 2), (m_mac_lanes_count != 1));
        bit_utils::set_bit(&four_lane_mode, (m_serdes_index_in_mac_pool / 4), 0);
        bit_utils::set_bit(&eight_lane_mode, (m_serdes_index_in_mac_pool / 8), 0);
        break;
    case 4:
        two_lane_mode
            = bit_utils::set_bits(two_lane_mode, (m_serdes_index_in_mac_pool / 2) + 1, (m_serdes_index_in_mac_pool / 2), 0);
        bit_utils::set_bit(&four_lane_mode, (m_serdes_index_in_mac_pool / 4), 1);
        bit_utils::set_bit(&eight_lane_mode, (m_serdes_index_in_mac_pool / 8), 0);
        break;
    case 8:
        two_lane_mode = 0;
        four_lane_mode = 0;
        eight_lane_mode = 1;
        if (m_mlp_mode != la_mac_port::mlp_mode_e::NONE) {
            mlp_reg.fields.tx_mlp_en = 1;
            mlp_reg.fields.rx_mlp_en = 1;
        }
        break;
    }

    tx_reg.fields.tx_2_lanes_mode = two_lane_mode;
    tx_reg.fields.tx_4_lanes_mode = four_lane_mode;
    tx_reg.fields.tx_8_lanes_mode = eight_lane_mode;
    rx_reg.fields.rx_2_lanes_mode = two_lane_mode;
    rx_reg.fields.rx_4_lanes_mode = four_lane_mode;
    rx_reg.fields.rx_8_lanes_mode = eight_lane_mode;

    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->tx_mac_lanes_cfg, tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_mac_lanes_cfg, rx_reg);
    return_on_error(stat);

    // MLP
    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->mlp_cfg, mlp_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

void
mac_pool8_port::initialize_register_pointers()
{
    const auto& mac_pool8 = m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index];

    m_mac_pool_regs.counter_timer = mac_pool8->counter_timer;
    m_mac_pool_regs.counter_timer_trigger_reg = mac_pool8->counter_timer_trigger_reg;
    m_mac_pool_regs.am_cfg = mac_pool8->am_cfg;
    m_mac_pool_regs.mac_lanes_loopback_register = mac_pool8->mac_lanes_loopback_register;
    m_mac_pool_regs.pma_loopback_register = mac_pool8->pma_loopback_register;
    m_mac_pool_regs.rsf_degraded_ser_cfg0 = mac_pool8->rsf_degraded_ser_cfg0;
    m_mac_pool_regs.rx_ber_fsm_cfg = mac_pool8->rx_ber_fsm_cfg;
    m_mac_pool_regs.rx_cfg0 = mac_pool8->rx_cfg0;
    m_mac_pool_regs.rx_mac_cfg0 = mac_pool8->rx_mac_cfg0;
    m_mac_pool_regs.rx_mac_cfg1 = mac_pool8->rx_mac_cfg1;
    m_mac_pool_regs.rx_high_ser_fsm_cfg = mac_pool8->rx_high_ser_fsm_cfg;
    m_mac_pool_regs.rx_krf_status = mac_pool8->rx_krf_status;
    m_mac_pool_regs.rx_krf_cfg = mac_pool8->rx_krf_cfg;
    m_mac_pool_regs.rx_pcs_test_cfg0 = mac_pool8->rx_pcs_test_cfg0;
    m_mac_pool_regs.rx_pma_test_cfg0 = mac_pool8->rx_pma_test_cfg0;
    m_mac_pool_regs.rx_rsf_cfg0 = mac_pool8->rx_rsf_cfg0;
    m_mac_pool_regs.rx_status_register = mac_pool8->rx_status_register;
    m_mac_pool_regs.rx_status_lane_mapping = mac_pool8->rx_status_lane_mapping;
    m_mac_pool_regs.tx_cfg0 = mac_pool8->tx_cfg0;
    m_mac_pool_regs.tx_mac_cfg0 = mac_pool8->tx_mac_cfg0;
    m_mac_pool_regs.tx_mac_ctrl_sa = mac_pool8->tx_mac_ctrl_sa;
    m_mac_pool_regs.tx_mac_cfg_ipg = mac_pool8->tx_mac_cfg_ipg;
    m_mac_pool_regs.tx_mac_fc_per_xoff_timer = mac_pool8->tx_mac_fc_per_xoff_timer;
    m_mac_pool_regs.tx_mac_fc_xoff_timer = mac_pool8->tx_mac_fc_xoff_timer;
    m_mac_pool_regs.tx_mac_fc_per_xon_timer = mac_pool8->tx_mac_fc_per_xon_timer;
    m_mac_pool_regs.tx_mac_fc_xon_timer = mac_pool8->tx_mac_fc_xon_timer;
    m_mac_pool_regs.tx_pcs_test_cfg0 = mac_pool8->tx_pcs_test_cfg0;
    m_mac_pool_regs.tx_pma_test_cfg0 = mac_pool8->tx_pma_test_cfg0;
    m_mac_pool_regs.rsf_ck_cycles_per_1ms_reg = mac_pool8->rsf_ck_cycles_per_1ms_reg;
    m_mac_pool_regs.tx_oobi_cfg_reg = mac_pool8->tx_oobi_cfg;

    m_mac_pool_counters.rx_ber = mac_pool8->rx_ber_cnt_reg;
    m_mac_pool_counters.rx_errored_blocks = mac_pool8->rx_errored_blocks_cnt_reg;
    m_mac_pool_counters.pcs_test = mac_pool8->rx_pcs_test_counter;
    m_mac_pool_counters.pma_read = mac_pool8->rx_pma_rd_cnt_reg;
    m_mac_pool_counters.pma_write = mac_pool8->tx_pma_wr_cnt_reg;
    m_mac_pool_counters.pma_test = mac_pool8->rx_pma_test_counter;
    m_mac_pool_counters.port_mib = mac_pool8->port_mib_counter;
    m_mac_pool_counters.krf_cor = mac_pool8->rx_krf_cor_blocks_cnt_reg;
    m_mac_pool_counters.krf_uncor = mac_pool8->rx_krf_uncor_blocks_cnt_reg;
    m_mac_pool_counters.rsf_cor = mac_pool8->rx_cor_cw_reg;
    m_mac_pool_counters.rsf_uncor = mac_pool8->rx_uncor_cw_reg;
    m_mac_pool_counters.rsf_debug = mac_pool8->rx_rsf_dbg_cntrs_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[0] = mac_pool8->rx_symb_err_lane0_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[1] = mac_pool8->rx_symb_err_lane1_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[2] = mac_pool8->rx_symb_err_lane2_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[3] = mac_pool8->rx_symb_err_lane3_reg;

    m_mac_pool_interrupt_regs.rx_link_status_down = mac_pool8->rx_link_status_down;
    m_mac_pool_interrupt_regs.rx_link_status_down_mask = mac_pool8->rx_link_status_down_mask;
    m_mac_pool_interrupt_regs.rx_pcs_link_status_down = mac_pool8->rx_pcs_link_status_down;
    m_mac_pool_interrupt_regs.rx_pcs_link_status_down_mask = mac_pool8->rx_pcs_link_status_down_mask;
    m_mac_pool_interrupt_regs.rx_pcs_align_status_down = mac_pool8->rx_pcs_align_status_down;
    m_mac_pool_interrupt_regs.rx_pcs_hi_ber_up = mac_pool8->rx_pcs_hi_ber_up;
    m_mac_pool_interrupt_regs.rx_pma_sig_ok_loss_interrupt_register = mac_pool8->rx_pma_sig_ok_loss_interrupt_register;
    m_mac_pool_interrupt_regs.rsf_rx_high_ser_interrupt_register = mac_pool8->rsf_rx_high_ser_interrupt_register;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[0] = mac_pool8->rx_desk_fif_ovf_interrupt_register0;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[1] = mac_pool8->rx_desk_fif_ovf_interrupt_register1;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[2] = mac_pool8->rx_desk_fif_ovf_interrupt_register2;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[3] = mac_pool8->rx_desk_fif_ovf_interrupt_register3;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[4] = mac_pool8->rx_desk_fif_ovf_interrupt_register4;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[5] = mac_pool8->rx_desk_fif_ovf_interrupt_register5;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[6] = mac_pool8->rx_desk_fif_ovf_interrupt_register6;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[7] = mac_pool8->rx_desk_fif_ovf_interrupt_register7;

    m_mac_pool_interrupt_regs.rx_code_err_interrupt_register = mac_pool8->rx_code_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_crc_err_interrupt_register = mac_pool8->rx_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_invert_crc_err_interrupt_register = mac_pool8->rx_invert_crc_err_interrupt_register;
    // TODO GB
    // m_mac_pool_interrupt_regs.rx_oob_invert_crc_err_interrupt_register = mac_pool8->rx_oob_invert_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_oversize_err_interrupt_register = mac_pool8->rx_oversize_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_undersize_err_interrupt_register = mac_pool8->rx_undersize_err_interrupt_register;

    m_mac_pool_interrupt_regs.tx_crc_err_interrupt_register = mac_pool8->tx_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.tx_underrun_err_interrupt_register = mac_pool8->tx_underrun_err_interrupt_register;
    m_mac_pool_interrupt_regs.tx_missing_eop_err_interrupt_register = mac_pool8->tx_missing_eop_err_interrupt_register;

    m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register = mac_pool8->rsf_rx_degraded_ser_interrupt_register;
    m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register = mac_pool8->rsf_rx_rm_degraded_ser_interrupt_register;

    m_mac_pool_interrupt_regs.device_time_fif_ne_interrupt_register = mac_pool8->device_time_fif_ne_interrupt_register;
    m_mac_pool_interrupt_regs.device_time_override_interrupt_register = mac_pool8->device_time_override_interrupt_register;

    // Error interrupt mask
    m_mac_pool_interrupt_regs.rx_code_err_interrupt_register_mask = mac_pool8->rx_code_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_crc_err_interrupt_register_mask = mac_pool8->rx_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_invert_crc_err_interrupt_register_mask = mac_pool8->rx_invert_crc_err_interrupt_register_mask;
    // TODO GB
    // m_mac_pool_interrupt_regs.rx_oob_invert_crc_err_interrupt_register_mask
    //    = mac_pool8->rx_oob_invert_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_oversize_err_interrupt_register_mask = mac_pool8->rx_oversize_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_undersize_err_interrupt_register_mask = mac_pool8->rx_undersize_err_interrupt_register_mask;

    m_mac_pool_interrupt_regs.tx_crc_err_interrupt_register_mask = mac_pool8->tx_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.tx_underrun_err_interrupt_register_mask = mac_pool8->tx_underrun_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.tx_missing_eop_err_interrupt_register_mask = mac_pool8->tx_missing_eop_err_interrupt_register_mask;

    m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register_mask = mac_pool8->rsf_rx_degraded_ser_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register_mask
        = mac_pool8->rsf_rx_rm_degraded_ser_interrupt_register_mask;

    m_mac_pool_interrupt_regs.device_time_fif_ne_interrupt_register_mask = mac_pool8->device_time_fif_ne_interrupt_register_mask;
    m_mac_pool_interrupt_regs.device_time_override_interrupt_register_mask
        = mac_pool8->device_time_override_interrupt_register_mask;
}

la_status
mac_pool8_port::configure_pma(device_port_handler_base::serdes_config_data config)
{
    bit_vector bv_rx_pma_cfg0(0, mac_pool8_rx_pma_cfg0_register::SIZE_IN_BITS);
    bit_vector bv_tx_pma_cfg0(0, mac_pool8_tx_pma_cfg0_register::SIZE_IN_BITS);

    la_status stat;

    // Get
    stat = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->tx_pma_cfg0, bv_tx_pma_cfg0);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);

    bool override_signal_ok = m_loopback_mode == la_mac_port::loopback_mode_e::SERDES;

    // Update Rx SerDes source
    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t rx_serdes_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_id + m_serdes_base_id].rx_source;
        size_t srd_src_lsb = (serdes_id + m_serdes_index_in_mac_pool) * 2;

        // Change to set 2x, if 1 0 X X X X X X in rx_serdes_source, change to 0 1 X X X X X X
        // Change to set 4x, if 1 0 3 2 X X X X in rx_serdes source, change to 0 1 2 3 X X X X
        // Change to set 8x, if 1 0 3 2 3 1 2 0 in rx_serdes_source, change to 0 1 2 3 0 1 2 3
        if (m_loopback_mode == la_mac_port::loopback_mode_e::PMA_SRDS_CLK) {
            if (m_serdes_count >= 4) { // SerDes Count = 4 or 8
                bv_rx_pma_cfg0.set_bits(srd_src_lsb + 1, srd_src_lsb, serdes_id & 0x3);
            } else if (m_serdes_count == 2) {
                if ((m_serdes_index_in_mac_pool % 4) == 0 || (m_serdes_index_in_mac_pool % 4) == 1) {
                    bv_rx_pma_cfg0.set_bits(srd_src_lsb + 1, srd_src_lsb, serdes_id & 0x3);
                } else { // m_serdes_index_in_mac_pool % 4 == 2 || m_serdes_index_in_mac_pool %4 == 3
                    bv_rx_pma_cfg0.set_bits(srd_src_lsb + 1, srd_src_lsb, (serdes_id + 2) & 0x3);
                }
            } else { // m_serdes_count == 1
                bv_rx_pma_cfg0.set_bits(srd_src_lsb + 1, srd_src_lsb, rx_serdes_source & 0x3);
            }
        } else { // No Loopback Mode
            bv_rx_pma_cfg0.set_bits(srd_src_lsb + 1, srd_src_lsb, rx_serdes_source & 0x3);
        }

        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_DWIDTH_OFFSET, config.pam4_enable);
        bv_tx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + TX_PMA_CFG0_DWIDTH_OFFSET, config.pam4_enable);

        bv_rx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + RX_PMA_CFG0_PAM4_EN_OFFSET, config.pam4_enable);
        bv_tx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + TX_PMA_CFG0_PAM4_EN_OFFSET, config.pam4_enable);

        // Disable greycode, will be done in the SerDes for PAM4 links
        bv_rx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + RX_PMA_CFG0_GREYCODE_OFFSET, 0);
        bv_tx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + TX_PMA_CFG0_GREYCODE_OFFSET, 0);

        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_SIGNAL_OK_OVERRIDE_VALUE_OFFSET, 1);
        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_SIGNAL_OK_OVERRIDE_ENABLE_OFFSET, override_signal_ok);
    }

    // Set
    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->tx_pma_cfg0, bv_tx_pma_cfg0);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::clear_signal_ok_interrupt()
{
    bit_vector bv_rx_pma_sig_ok_loss(0, mac_pool8_rx_pma_sig_ok_loss_interrupt_register_register::SIZE_IN_BITS);

    la_status stat;

    // Set the bits to clear
    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        bv_rx_pma_sig_ok_loss.set_bit(m_serdes_index_in_mac_pool + serdes_id, 1);
    }

    // Clear
    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_sig_ok_loss_interrupt_register,
        bv_rx_pma_sig_ok_loss);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::get_signal_ok_interrupt(bool& out_trapped)
{
    out_trapped = false;
    bit_vector bv_rx_pma_sig_ok_loss(0, mac_pool8_rx_pma_sig_ok_loss_interrupt_register_register::SIZE_IN_BITS);

    la_status stat;

    // Read
    stat = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_sig_ok_loss_interrupt_register,
        bv_rx_pma_sig_ok_loss);
    return_on_error(stat);

    // Check
    size_t total_trapped = 0;
    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        total_trapped += bv_rx_pma_sig_ok_loss.bit(m_serdes_index_in_mac_pool + serdes_id);
    }

    out_trapped = total_trapped == m_serdes_count;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::configure_pma_max_burst(uint32_t max_burst)
{
    mac_pool8_rx_pma_max_burst_cfg_register rx_pma_max_burst;

    // Get
    la_status status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_max_burst_cfg, rx_pma_max_burst);
    return_on_error(status);

    // Update
    bit_vector bv_rx_pma_max_burst = rx_pma_max_burst;

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t lsb = (serdes_id + m_serdes_index_in_mac_pool) * RX_PMA_MAX_BURST_WIDTH;
        bv_rx_pma_max_burst.set_bits(lsb + RX_PMA_MAX_BURST_WIDTH - 1, lsb, max_burst);
    }

    // Set
    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_max_burst_cfg, bv_rx_pma_max_burst);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_sig_ok_overide(bool overide, bool val)
{
    bit_vector bv_rx_pma_cfg0(0, mac_pool8_rx_pma_cfg0_register::SIZE_IN_BITS);
    la_status stat = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t rx_serdes_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_id + m_serdes_base_id].rx_source;
        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_SIGNAL_OK_OVERRIDE_VALUE_OFFSET, val ? 1 : 0);
        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_SIGNAL_OK_OVERRIDE_ENABLE_OFFSET, overide ? 1 : 0);
    }

    stat = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_rx_reset(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;
    // GB add rs_rstn per lane
    // rsf_rstn - should be like other rstn
    bool non_mac_rx_active = (state != la_mac_port_base::mac_reset_state_e::RESET_ALL);
    bool mac_rx_active = (state == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
    bool rx_kr_active = non_mac_rx_active && (m_fec_mode == la_mac_port::fec_mode_e::KR);
    bool rx_rsf_active
        = non_mac_rx_active && !((m_fec_mode == la_mac_port::fec_mode_e::NONE) || (m_fec_mode == la_mac_port::fec_mode_e::KR));

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    // When reset - has to clear all the MAC lanes that can be relevant (according to SerDes count).
    // When not reset (activating) - turn only the amount of MAC lanes.
    size_t mac_lanes_to_set = state == la_mac_port_base::mac_reset_state_e::RESET_ALL ? m_serdes_count : m_mac_lanes_count;

    for (size_t i = 0; i < mac_lanes_to_set; i++) {
        // rx_rs, rx_pcs, rx_pcs_sync, rx_rsf
        rstn_reg.set_bit(rstn_offset::RX_RS + m_serdes_index_in_mac_pool + i, non_mac_rx_active);
        rstn_reg.set_bit(rstn_offset::RX_PCS + m_serdes_index_in_mac_pool + i, non_mac_rx_active);
        rstn_reg.set_bit(rstn_offset::RX_PCS_SYNC + m_serdes_index_in_mac_pool + i, non_mac_rx_active);
        rstn_reg.set_bit(rstn_offset::RX_RSF + m_serdes_index_in_mac_pool + i, rx_rsf_active);
    }

    for (size_t i = 0; i < m_serdes_count; i++) {
        // set: rx_pma_code_side, rx_pma_srd_side
        size_t rx_serdes_pre_swap = m_device->m_serdes_info[m_slice_id][m_ifg_id][i + m_serdes_base_id].rx_source;
        rstn_reg.set_bit(rstn_offset::RX_SERDES + (rx_serdes_pre_swap % 8), non_mac_rx_active);
        if (m_device->m_ll_device->get_device_revision() != la_device_revision_e::GIBRALTAR_A0) {
            // rx_pma_code_side is un-reseted in initialize_topology for GB A0
            rstn_reg.set_bit(rstn_offset::RX_PMA + (rx_serdes_pre_swap % 8), non_mac_rx_active);
        }
        rstn_reg.set_bit(rstn_offset::RX_KR_FEC + m_serdes_index_in_mac_pool + i, rx_kr_active);
    }

    // When doing RESET ALL, two write should be done on for RX MAC and one for all other
    // otherwise (in ACTIVATE) one write is enough
    if (!non_mac_rx_active) {
        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
        return_on_error(status);
    }

    for (size_t i = 0; i < mac_lanes_to_set; i++) {
        // set rx_mac
        rstn_reg.set_bit(rstn_offset::RX_MAC + m_serdes_index_in_mac_pool + i, mac_rx_active);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_tx_reset(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    bool active = (state != la_mac_port_base::mac_reset_state_e::RESET_ALL);
    bool tx_kr_active = active && (m_fec_mode == la_mac_port::fec_mode_e::KR);
    bool tx_rsf_active = active && !((m_fec_mode == la_mac_port::fec_mode_e::NONE) || (m_fec_mode == la_mac_port::fec_mode_e::KR));

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    // When reset - has to clear all the MAC lanes that can be relevant (according to SerDes count).
    // When not reset (activating) - turn only the amount of MAC lanes.
    size_t mac_lanes_to_set = state == la_mac_port_base::mac_reset_state_e::RESET_ALL ? m_serdes_count : m_mac_lanes_count;

    for (size_t i = 0; i < mac_lanes_to_set; i++) {
        // set tx_mac, tx_rs, tx_pcs, tx_rsf
        rstn_reg.set_bit(rstn_offset::TX_MAC + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_RS + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_PCS + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_RSF + m_serdes_index_in_mac_pool + i, tx_rsf_active);
    }

    for (size_t i = 0; i < m_serdes_count; i++) {
        // set: tx_pma_core_side, tx_pma_srd_side, tx_krf
        rstn_reg.set_bit(rstn_offset::TX_PMA + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_SERDES + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_KR_FEC + m_serdes_index_in_mac_pool + i, tx_kr_active);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_reset_fabric_port_pacific_a0(la_mac_port_base::mac_reset_state_e state)
{
    // TODO GB remove
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    // common: tx_pma_rstn, rx_pma

    enum rstn_offset {
        TX_PMA = 57,

        STEP = 8,
        TX_PMA_CONFIGS = 2, // tx_pma_core_side, tx_pma_srd_side
    };

    for (size_t i = 0; i < m_serdes_count; i++) {
        // set: tx_pma_core_side, tx_pma_srd_side
        for (size_t conf = 0; conf < rstn_offset::TX_PMA_CONFIGS; conf++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + conf * rstn_offset::STEP + m_serdes_index_in_mac_pool + i,
                             state != la_mac_port_base::mac_reset_state_e::RESET_ALL);
        }
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_mac_rx_reset(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    bool mac_rx_active = (state == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // set rx_mac
        rstn_reg.set_bit(rstn_offset::RX_MAC + m_serdes_index_in_mac_pool + i, mac_rx_active);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_rx_pcs_sync_reset()
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // assert reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS_SYNC + m_serdes_index_in_mac_pool + i, 0);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // release reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS_SYNC + m_serdes_index_in_mac_pool + i, 1);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_rx_pcs_reset()
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // assert reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS + m_serdes_index_in_mac_pool + i, 0);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // release reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS + m_serdes_index_in_mac_pool + i, 1);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::reset_tx_pma(bool enable)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    if (enable) {
        for (size_t i = 0; i < m_serdes_count; i++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + m_serdes_index_in_mac_pool + i, 0);
            rstn_reg.set_bit(rstn_offset::TX_SERDES + m_serdes_index_in_mac_pool + i, 0);
        }

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
        return_on_error(status);

    } else {

        for (size_t i = 0; i < m_serdes_count; i++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + m_serdes_index_in_mac_pool + i, 1);
            rstn_reg.set_bit(rstn_offset::TX_SERDES + m_serdes_index_in_mac_pool + i, 1);
        }

        status = m_device->m_ll_device->write_register(
            m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::reset_rx_pma(bool enable)
{
    la_status status;
    bit_vector rstn_reg;
    // size_t rst_bit = !enable;

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_serdes_count; i++) {
        size_t rx_serdes_pre_swap = m_device->m_serdes_info[m_slice_id][m_ifg_id][i + m_serdes_base_id].rx_source;
        rstn_reg.set_bit(rstn_offset::RX_PMA + (rx_serdes_pre_swap % 8), !enable);
    }

    status = m_device->m_ll_device->write_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::set_rs_fec_debug_enabled()
{
    // The rs fec debug counters always enabled for GB
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::get_rs_fec_debug_enabled(bool& out_debug_status) const
{
    // The rs fec debug counters always enabled for GB
    out_debug_status = true;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::configure_loopback_mode(npl_loopback_mode_e mii_loopback_mode, npl_loopback_mode_e pma_loopback_mode)
{
    mac_pool8_pma_loopback_register_register pma_loopback_reg{{0}};
    mac_pool8_mac_lanes_loopback_register_register mii_loopback_reg{{0}};

    pma_loopback_reg.fields.pma_loopback_mode = pma_loopback_mode;
    mii_loopback_reg.fields.mii_loopback_mode = mii_loopback_mode;

    la_status status;
    for (size_t i = 0; i < m_serdes_count; i++) {
        size_t serdes_index = m_serdes_index_in_mac_pool + i;
        status = m_device->m_ll_device->write_register(
            (*m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->pma_loopback_register)[serdes_index],
            pma_loopback_reg);
        return_on_error(status);

        status = m_device->m_ll_device->write_register((*m_gibraltar_tree->slice[m_slice_id]
                                                             ->ifg[m_ifg_id]
                                                             ->mac_pool8[m_mac_pool_index]
                                                             ->mac_lanes_loopback_register)[serdes_index],
                                                       mii_loopback_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool8_port::read_mac_soft_reset_config() const
{
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(
        m_gibraltar_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool8[m_mac_pool_index]->rstn_reg, rstn_reg);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
