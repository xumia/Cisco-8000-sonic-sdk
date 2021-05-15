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

#include "mac_pool2_port.h"
#include "common/defines.h"
#include "la_device_impl.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "system/la_mac_port_base.h"

namespace silicon_one
{

enum rstn_offset {
    TX_MAC = 0,
    RX_MAC = 2,
    TX_PCS = 4,
    RX_PCS = 6,
    RX_PCS_SYNC = 8,
    TX_RSF = 10,
    RX_RSF = 12,
    TX_PMA = 15,
    TX_SERDES = 17,
    RX_PMA = 20,
    RX_SERDES = 22,
    TX_KR_FEC = 24,
    RX_KR_FEC = 26,

    STEP = 2,
    PCS_CONFIGS = 5,
    TX_PMA_CONFIGS = 2,
    KR_FEC_CONFIGS = 2,
};

enum {
    RX_PMA_CFG0_PAM4_EN_OFFSET = 2,
    RX_PMA_CFG0_GREYCODE_OFFSET = 6,
    RX_PMA_CFG0_DWIDTH_OFFSET = 8,
    RX_PMA_CFG0_SIG_OK_OVRD_ENABLE_OFFSET = 13,
    RX_PMA_CFG0_SIG_OK_OVRD_VALUE_OFFSET = 15,

    TX_PMA_CFG0_PAM4_EN_OFFSET = 8,
    TX_PMA_CFG0_GREYCODE_OFFSET = 12,
    TX_PMA_CFG0_DWIDTH_OFFSET = 14,
};

mac_pool2_port::mac_pool2_port(const la_device_impl_wptr& device) : pacific_mac_pool(device)
{
}

mac_pool2_port::~mac_pool2_port()
{
}

la_status
mac_pool2_port::initialize(la_slice_id_t slice_id,
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

    if (num_of_serdes > la_mac_port_base::NUM_SERDESES_IN_MAC_POOL2) {
        return LA_STATUS_EOUTOFRANGE;
    }
    m_mac_pool_index = 0;
    m_serdes_index_in_mac_pool = get_serdes_index_in_mac_pool(serdes_base);
    m_mac_lane_index_in_mac_pool = m_serdes_index_in_mac_pool;
    m_mac_lane_index_in_ifgb = serdes_base;
    la_status stat = pacific_mac_pool::initialize(
        slice_id, ifg_id, serdes_base, num_of_serdes, speed, rx_fc_mode, tx_fc_mode, fec_mode, mlp_mode, port_slice_mode);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

size_t
mac_pool2_port::get_serdes_index_in_mac_pool(size_t serdes_idx) const
{
    return serdes_idx % la_mac_port_base::NUM_SERDESES_IN_MAC_POOL2;
}

la_status
mac_pool2_port::configure_lanes()
{
    mac_pool2_tx_mac_lanes_cfg_register tx_reg;
    mac_pool2_rx_mac_lanes_cfg_register rx_reg;

    bzero(&tx_reg, mac_pool2_tx_mac_lanes_cfg_register::SIZE);
    bzero(&rx_reg, mac_pool2_rx_mac_lanes_cfg_register::SIZE);

    uint16_t lane_mode = (m_mac_lanes_count == 2) ? 1 : 0;
    tx_reg.fields.tx_2_lanes_mode = lane_mode;
    rx_reg.fields.rx_2_lanes_mode = lane_mode;

    la_status stat = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->tx_mac_lanes_cfg,
        mac_pool2_tx_mac_lanes_cfg_register::SIZE,
        &tx_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_mac_lanes_cfg,
        mac_pool2_rx_mac_lanes_cfg_register::SIZE,
        &rx_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

void
mac_pool2_port::initialize_register_pointers()
{
    // TODO: use mac_pool2 shortcut in all the lines above
    const auto& mac_pool2 = m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2;

    m_mac_pool_regs.counter_timer = mac_pool2->counter_timer;
    m_mac_pool_regs.counter_timer_trigger_reg = mac_pool2->counter_timer_trigger_reg;
    m_mac_pool_regs.am_cfg = mac_pool2->am_cfg;
    m_mac_pool_regs.mac_lanes_loopback_register = mac_pool2->mac_lanes_loopback_register;
    m_mac_pool_regs.pma_loopback_register = mac_pool2->pma_loopback_register;
    m_mac_pool_regs.rsf_degraded_ser_cfg0 = mac_pool2->rsf_degraded_ser_cfg0;
    m_mac_pool_regs.rx_ber_fsm_cfg = mac_pool2->rx_ber_fsm_cfg;
    m_mac_pool_regs.rx_cfg0 = mac_pool2->rx_cfg0;
    m_mac_pool_regs.rx_high_ser_fsm_cfg = mac_pool2->rx_high_ser_fsm_cfg;
    m_mac_pool_regs.rx_krf_status = mac_pool2->rx_krf_status;
    m_mac_pool_regs.rx_krf_cfg = mac_pool2->rx_krf_cfg;
    m_mac_pool_regs.rx_mac_cfg0 = mac_pool2->rx_mac_cfg0;
    m_mac_pool_regs.rx_mac_cfg1 = mac_pool2->rx_mac_cfg1;
    m_mac_pool_regs.rx_pcs_test_cfg0 = mac_pool2->rx_pcs_test_cfg0;
    m_mac_pool_regs.rx_pma_test_cfg0 = mac_pool2->rx_pma_test_cfg0;
    m_mac_pool_regs.rx_rsf_cfg0 = mac_pool2->rx_rsf_cfg0;
    m_mac_pool_regs.rx_status_register = mac_pool2->rx_status_register;
    m_mac_pool_regs.rx_status_lane_mapping = mac_pool2->rx_status_lane_mapping;
    m_mac_pool_regs.tx_cfg0 = mac_pool2->tx_cfg0;
    m_mac_pool_regs.tx_mac_cfg0 = mac_pool2->tx_mac_cfg0;
    m_mac_pool_regs.tx_mac_ctrl_sa = mac_pool2->tx_mac_ctrl_sa;
    m_mac_pool_regs.tx_mac_cfg_ipg = mac_pool2->tx_mac_cfg_ipg;
    m_mac_pool_regs.tx_mac_fc_per_xoff_timer = mac_pool2->tx_mac_fc_per_xoff_timer;
    m_mac_pool_regs.tx_mac_fc_xoff_timer = mac_pool2->tx_mac_fc_xoff_timer;
    m_mac_pool_regs.tx_mac_fc_per_xon_timer = mac_pool2->tx_mac_fc_per_xon_timer;
    m_mac_pool_regs.tx_mac_fc_xon_timer = mac_pool2->tx_mac_fc_xon_timer;
    m_mac_pool_regs.tx_pcs_test_cfg0 = mac_pool2->tx_pcs_test_cfg0;
    m_mac_pool_regs.tx_pma_test_cfg0 = mac_pool2->tx_pma_test_cfg0;
    m_mac_pool_regs.rsf_ck_cycles_per_1ms_reg = mac_pool2->rsf_ck_cycles_per_1ms_reg;

    m_mac_pool_counters.rx_ber = mac_pool2->rx_ber_cnt_reg;
    m_mac_pool_counters.rx_errored_blocks = mac_pool2->rx_errored_blocks_cnt_reg;
    m_mac_pool_counters.pcs_test = mac_pool2->rx_pcs_test_counter;
    m_mac_pool_counters.pma_read = mac_pool2->rx_pma_rd_cnt_reg;
    m_mac_pool_counters.pma_write = mac_pool2->tx_pma_wr_cnt_reg;
    m_mac_pool_counters.pma_test = mac_pool2->rx_pma_test_counter;
    m_mac_pool_counters.port_mib = mac_pool2->port_mib_counter;
    m_mac_pool_counters.krf_cor = mac_pool2->rx_krf_cor_blocks_cnt_reg;
    m_mac_pool_counters.krf_uncor = mac_pool2->rx_krf_uncor_blocks_cnt_reg;
    m_mac_pool_counters.rsf_cor = mac_pool2->rx_cor_cw_reg;
    m_mac_pool_counters.rsf_uncor = mac_pool2->rx_uncor_cw_reg;
    m_mac_pool_counters.rsf_debug = mac_pool2->rx_rsf_dbg_cntrs_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[0] = mac_pool2->rx_symb_err_lane0_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[1] = mac_pool2->rx_symb_err_lane1_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[2] = mac_pool2->rx_symb_err_lane2_reg;
    m_mac_pool_counters.rx_symb_err_lane_regs[3] = mac_pool2->rx_symb_err_lane3_reg;

    m_mac_pool_interrupt_regs.rx_link_status_down = mac_pool2->rx_link_status_down;
    m_mac_pool_interrupt_regs.rx_link_status_down_mask = mac_pool2->rx_link_status_down_mask;
    m_mac_pool_interrupt_regs.rx_pcs_link_status_down = mac_pool2->rx_pcs_link_status_down;
    m_mac_pool_interrupt_regs.rx_pcs_link_status_down_mask = mac_pool2->rx_pcs_link_status_down_mask;
    m_mac_pool_interrupt_regs.rx_pcs_align_status_down = mac_pool2->rx_pcs_align_status_down;
    m_mac_pool_interrupt_regs.rx_pcs_hi_ber_up = mac_pool2->rx_pcs_hi_ber_up;
    m_mac_pool_interrupt_regs.rx_pma_sig_ok_loss_interrupt_register = mac_pool2->rx_pma_sig_ok_loss_interrupt_register;
    m_mac_pool_interrupt_regs.rsf_rx_high_ser_interrupt_register = mac_pool2->rsf_rx_high_ser_interrupt_register;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[0] = mac_pool2->rx_desk_fif_ovf_interrupt_register0;
    m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[1] = mac_pool2->rx_desk_fif_ovf_interrupt_register1;

    // Error interrupt
    m_mac_pool_interrupt_regs.rx_code_err_interrupt_register = mac_pool2->rx_code_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_crc_err_interrupt_register = mac_pool2->rx_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_invert_crc_err_interrupt_register = mac_pool2->rx_invert_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_oob_invert_crc_err_interrupt_register = mac_pool2->rx_oob_invert_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_oversize_err_interrupt_register = mac_pool2->rx_oversize_err_interrupt_register;
    m_mac_pool_interrupt_regs.rx_undersize_err_interrupt_register = mac_pool2->rx_undersize_err_interrupt_register;

    m_mac_pool_interrupt_regs.tx_crc_err_interrupt_register = mac_pool2->tx_crc_err_interrupt_register;
    m_mac_pool_interrupt_regs.tx_underrun_err_interrupt_register = mac_pool2->tx_underrun_err_interrupt_register;
    m_mac_pool_interrupt_regs.tx_missing_eop_err_interrupt_register = mac_pool2->tx_missing_eop_err_interrupt_register;

    m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register = mac_pool2->rsf_rx_degraded_ser_interrupt_register;
    m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register = mac_pool2->rsf_rx_rm_degraded_ser_interrupt_register;

    m_mac_pool_interrupt_regs.device_time_override_interrupt_register = mac_pool2->device_time_override_interrupt_register;

    // Error interrupt mask
    m_mac_pool_interrupt_regs.rx_code_err_interrupt_register_mask = mac_pool2->rx_code_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_crc_err_interrupt_register_mask = mac_pool2->rx_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_invert_crc_err_interrupt_register_mask = mac_pool2->rx_invert_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_oob_invert_crc_err_interrupt_register_mask
        = mac_pool2->rx_oob_invert_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_oversize_err_interrupt_register_mask = mac_pool2->rx_oversize_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rx_undersize_err_interrupt_register_mask = mac_pool2->rx_undersize_err_interrupt_register_mask;

    m_mac_pool_interrupt_regs.tx_crc_err_interrupt_register_mask = mac_pool2->tx_crc_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.tx_underrun_err_interrupt_register_mask = mac_pool2->tx_underrun_err_interrupt_register_mask;
    m_mac_pool_interrupt_regs.tx_missing_eop_err_interrupt_register_mask = mac_pool2->tx_missing_eop_err_interrupt_register_mask;

    m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register_mask = mac_pool2->rsf_rx_degraded_ser_interrupt_register_mask;
    m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register_mask
        = mac_pool2->rsf_rx_rm_degraded_ser_interrupt_register_mask;

    m_mac_pool_interrupt_regs.device_time_override_interrupt_register_mask
        = mac_pool2->device_time_override_interrupt_register_mask;
}

la_status
mac_pool2_port::configure_pma(device_port_handler_base::serdes_config_data config)
{
    bit_vector bv_rx_pma_cfg0(0, mac_pool2_rx_pma_cfg0_register::SIZE_IN_BITS);
    bit_vector bv_tx_pma_cfg0(0, mac_pool2_tx_pma_cfg0_register::SIZE_IN_BITS);

    la_status stat;

    // Get
    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->tx_pma_cfg0,
                                                bv_tx_pma_cfg0);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_cfg0,
                                                bv_rx_pma_cfg0);
    return_on_error(stat);

    // Update
    // Update Rx SerDes source
    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t rx_serdes_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_id + m_serdes_base_id].rx_source;
        size_t srd_src_lsb = serdes_id + m_serdes_index_in_mac_pool;
        size_t rx_pma_cfg0_dwidth_lsb = (rx_serdes_source % 2) * 2 + RX_PMA_CFG0_DWIDTH_OFFSET;
        size_t tx_pma_cfg0_dwidth_lsb = (serdes_id + m_serdes_index_in_mac_pool) * 2 + TX_PMA_CFG0_DWIDTH_OFFSET;
        bv_rx_pma_cfg0.set_bit(srd_src_lsb, rx_serdes_source & 0x1);
        bv_rx_pma_cfg0.set_bits(rx_pma_cfg0_dwidth_lsb + 1, rx_pma_cfg0_dwidth_lsb, config.dwidth_code);
        bv_tx_pma_cfg0.set_bits(tx_pma_cfg0_dwidth_lsb + 1, tx_pma_cfg0_dwidth_lsb, config.dwidth_code);

        bv_rx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + RX_PMA_CFG0_PAM4_EN_OFFSET, config.pam4_enable);
        bv_tx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + TX_PMA_CFG0_PAM4_EN_OFFSET, config.pam4_enable);

        // Disable greycode, will be done in the SerDes for PAM4 links
        bv_rx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + RX_PMA_CFG0_GREYCODE_OFFSET, 0);
        bv_tx_pma_cfg0.set_bit(serdes_id + m_serdes_index_in_mac_pool + TX_PMA_CFG0_GREYCODE_OFFSET, 0);
    }

    // Set
    stat = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->tx_pma_cfg0, bv_tx_pma_cfg0);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::configure_pma_max_burst(uint32_t max_burst)
{
    mac_pool2_rx_pma_max_burst_cfg_register rx_pma_max_burst;

    // Get
    la_status status = m_device->m_ll_device->read_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_max_burst_cfg,
        mac_pool2_rx_pma_max_burst_cfg_register::SIZE,
        &rx_pma_max_burst);
    return_on_error(status);

    // Update
    bit_vector bv_rx_pma_max_burst = rx_pma_max_burst;

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t lsb = (serdes_id + m_serdes_index_in_mac_pool) * RX_PMA_MAX_BURST_WIDTH;
        bv_rx_pma_max_burst.set_bits(lsb + RX_PMA_MAX_BURST_WIDTH - 1, lsb, max_burst);
    }

    // Set
    status = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_max_burst_cfg, bv_rx_pma_max_burst);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::clear_signal_ok_interrupt()
{
    bit_vector bv_rx_pma_sig_ok_loss(0, mac_pool2_rx_pma_sig_ok_loss_interrupt_register_register::SIZE_IN_BITS);

    la_status stat;

    // Set the bits to clear
    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        bv_rx_pma_sig_ok_loss.set_bit(m_serdes_index_in_mac_pool + serdes_id, 1);
    }

    // Clear
    stat = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_sig_ok_loss_interrupt_register,
        bv_rx_pma_sig_ok_loss);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::get_signal_ok_interrupt(bool& out_trapped)
{
    out_trapped = false;
    bit_vector bv_rx_pma_sig_ok_loss(0, mac_pool2_rx_pma_sig_ok_loss_interrupt_register_register::SIZE_IN_BITS);

    la_status stat;

    // Read
    stat = m_device->m_ll_device->read_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_sig_ok_loss_interrupt_register,
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
mac_pool2_port::set_sig_ok_overide(bool overide, bool val)
{
    bit_vector bv_rx_pma_cfg0(0, mac_pool2_rx_pma_cfg0_register::SIZE_IN_BITS);
    la_status stat = m_device->m_ll_device->read_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t rx_serdes_source = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes_id + m_serdes_base_id].rx_source;
        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_SIG_OK_OVRD_VALUE_OFFSET, val ? 1 : 0);
        bv_rx_pma_cfg0.set_bit((rx_serdes_source % 8) + RX_PMA_CFG0_SIG_OK_OVRD_ENABLE_OFFSET, overide ? 1 : 0);
    }

    stat = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_pma_cfg0, bv_rx_pma_cfg0);
    return_on_error(stat);
    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::set_rx_reset(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    bool non_mac_rx_active = (state != la_mac_port_base::mac_reset_state_e::RESET_ALL);
    bool mac_rx_active = (state == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);
    bool rx_kr_active = non_mac_rx_active & (m_fec_mode == la_mac_port::fec_mode_e::KR);

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    // When reset - has to clear all the MAC lanes that can be relevant (according to SerDes count).
    // When not reset (activating) - turn only the amount of MAC lanes.
    size_t mac_lanes_to_set = state == la_mac_port_base::mac_reset_state_e::RESET_ALL ? m_serdes_count : m_mac_lanes_count;

    for (size_t i = 0; i < mac_lanes_to_set; i++) {

        // rx_pcs, rx_pcs_sync rx_rsf
        rstn_reg.set_bit(rstn_offset::RX_PCS + m_serdes_index_in_mac_pool + i, non_mac_rx_active);
        rstn_reg.set_bit(rstn_offset::RX_PCS_SYNC + m_serdes_index_in_mac_pool + i, non_mac_rx_active);

        // BUG-B WORKAROUND:
        // There's a bug in reset connectivity, the implication is that we need to de-assert all rsfrx reset bits (8bits - 1 per
        // lane) instead of only the relevant ones. We still have the ability to reset a port by reset of pma, pcs_sync, pcs & mac
        // relevant parts.
        rstn_reg.set_bit(rstn_offset::RX_RSF + m_serdes_index_in_mac_pool + i, true);
    }

    for (size_t i = 0; i < m_serdes_count; i++) {
        // set: rx_pma_code_side, rx_pma_srd_side
        size_t rx_serdes_pre_swap = m_device->m_serdes_info[m_slice_id][m_ifg_id][i + m_serdes_base_id].rx_source;
        rstn_reg.set_bit(rstn_offset::RX_PMA + (rx_serdes_pre_swap % 2), non_mac_rx_active);
        rstn_reg.set_bit(rstn_offset::RX_SERDES + (rx_serdes_pre_swap % 2), non_mac_rx_active);

        rstn_reg.set_bit(rstn_offset::RX_KR_FEC + m_serdes_index_in_mac_pool + i, rx_kr_active);
    }

    // TODO: Remove - workaround!!! This reset all PMA lanes in the MAC pool.
    // Don't touch MAC bits
    // Remove also code in la_device_impl.cpp: apply_fabric_mac_port_workaround()
    if ((m_device->m_pacific_tree->get_revision() == la_device_revision_e::PACIFIC_A0) && non_mac_rx_active
        && (m_port_slice_mode != la_slice_mode_e::CARRIER_FABRIC)) {
        bit_vector rstn_reg_temp(rstn_reg);
        rstn_reg_temp.set_bits(mac_pool2_rstn_reg_register::SIZE_IN_BITS - 1, RX_MAC + STEP - 1, 0);
        // Disable reset - need to toggle the global PMA reset bits. So doing additional write.
        status = m_device->m_ll_device->write_register(
            *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg, rstn_reg_temp);
        return_on_error(status);
    }

    // When doing RESET ALL, two write should be done on for RX MAC and one for all other
    // otherwise (in ACTIVATE) one write is enough
    if (!non_mac_rx_active) {
        status = m_device->m_ll_device->write_register(
            *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg, rstn_reg);
        return_on_error(status);
    }

    for (size_t i = 0; i < mac_lanes_to_set; i++) {
        // BUG-A WORKAROUND:
        // In fabric ports the IFGB rx_rstn_reg.rx_lane_rstn cannot be 0 for a specific port - it affects nearby ports as well.
        // The workaround fix for the IFGB is not resetting rx_rstn_reg.rx_lane_rstn at all.
        // Since the IFGB RX serdes reset and RX MAC serdes reset should be synced, it means that the mac_pool rstn_reg.rx_mac_rstn
        // cannot be 0 as well.
        // So, this should not allow resetting rstn_reg.rx_mac_rstn.
        bool rx_mac_rstn_bit = rstn_reg.bit(rstn_offset::RX_MAC + m_serdes_index_in_mac_pool + i);
        rx_mac_rstn_bit |= (state == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);

        // set rx_mac
        rstn_reg.set_bit(rstn_offset::RX_MAC + m_serdes_index_in_mac_pool + i, mac_rx_active);

        // BUG-A WORKAROUND (continue):
        if ((m_device->m_pacific_tree->get_revision() == la_device_revision_e::PACIFIC_A0)
            && (m_port_slice_mode == la_slice_mode_e::CARRIER_FABRIC)) {
            rstn_reg.set_bit(rstn_offset::RX_MAC + m_serdes_index_in_mac_pool + i, rx_mac_rstn_bit);
        }
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::set_tx_reset(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    bool active = (state != la_mac_port_base::mac_reset_state_e::RESET_ALL);
    bool tx_kr_active = active & (m_fec_mode == la_mac_port::fec_mode_e::KR);
    bool tx_rsf_active = active && !((m_fec_mode == la_mac_port::fec_mode_e::NONE) || (m_fec_mode == la_mac_port::fec_mode_e::KR));

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    // When reset - has to clear all the MAC lanes that can be relevant (according to SerDes count).
    // When not reset (activating) - turn only the amount of MAC lanes.
    size_t mac_lanes_to_set = state == la_mac_port_base::mac_reset_state_e::RESET_ALL ? m_serdes_count : m_mac_lanes_count;

    for (size_t i = 0; i < mac_lanes_to_set; i++) {
        // set tx_mac, tx_pcs, tx_rsf
        rstn_reg.set_bit(rstn_offset::TX_MAC + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_PCS + m_serdes_index_in_mac_pool + i, active);
        rstn_reg.set_bit(rstn_offset::TX_RSF + m_serdes_index_in_mac_pool + i, tx_rsf_active);
    }

    for (size_t i = 0; i < m_serdes_count; i++) {
        // set: tx_pma_core_side, tx_pma_srd_side
        for (size_t conf = 0; conf < rstn_offset::TX_PMA_CONFIGS; conf++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + conf * rstn_offset::STEP + m_serdes_index_in_mac_pool + i, active);
        }

        rstn_reg.set_bit(rstn_offset::TX_KR_FEC + m_serdes_index_in_mac_pool + i, tx_kr_active);
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::set_rx_pcs_sync_reset()
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // assert reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS_SYNC + m_serdes_index_in_mac_pool + i, 0);
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // release reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS_SYNC + m_serdes_index_in_mac_pool + i, 1);
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::set_rx_pcs_reset()
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // assert reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS + m_serdes_index_in_mac_pool + i, 0);
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // release reset rx_pcs_sync
        rstn_reg.set_bit(rstn_offset::RX_PCS + m_serdes_index_in_mac_pool + i, 1);
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::reset_tx_pma(bool enable)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    if (enable) {
        for (size_t i = 0; i < m_serdes_count; i++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + m_serdes_index_in_mac_pool + i, 0);
            rstn_reg.set_bit(rstn_offset::TX_SERDES + m_serdes_index_in_mac_pool + i, 0);
        }

        status = m_device->m_ll_device->write_register(
            *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg, rstn_reg);
        return_on_error(status);
    } else {
        for (size_t i = 0; i < m_serdes_count; i++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + m_serdes_index_in_mac_pool + i, 1);
            rstn_reg.set_bit(rstn_offset::TX_SERDES + m_serdes_index_in_mac_pool + i, 1);
        }

        status = m_device->m_ll_device->write_register(
            *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg, rstn_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::reset_rx_pma(bool enable)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool2_port::set_reset_fabric_port_pacific_a0(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    // common: tx_pma_rstn, rx_pma

    enum rstn_offset {
        TX_PMA = 15,

        STEP = 2,
        TX_PMA_CONFIGS = 2, // tx_pma_core_side, tx_pma_srd_side
    };

    for (size_t i = 0; i < m_serdes_count; i++) {
        // set: tx_pma_core_side, tx_pma_srd_side
        for (size_t conf = 0; conf < rstn_offset::TX_PMA_CONFIGS; conf++) {
            rstn_reg.set_bit(rstn_offset::TX_PMA + conf * rstn_offset::STEP + m_serdes_index_in_mac_pool + i,
                             state != la_mac_port_base::mac_reset_state_e::RESET_ALL);
        }
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::set_mac_rx_reset(la_mac_port_base::mac_reset_state_e state)
{
    // read rstn reg
    la_status status;
    bit_vector rstn_reg;

    bool mac_rx_active = (state == la_mac_port_base::mac_reset_state_e::ACTIVE_ALL);

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);
    return_on_error(status);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        // set rx_mac
        rstn_reg.set_bit(rstn_offset::RX_MAC + m_serdes_index_in_mac_pool + i, mac_rx_active);
    }

    status = m_device->m_ll_device->write_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                   rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::set_rs_fec_debug_enabled()
{
    la_status status = m_device->m_ll_device->write_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_rsf_dbg_cfg, m_serdes_index_in_mac_pool);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::get_rs_fec_debug_enabled(bool& out_debug_status) const
{
    mac_pool2_rx_rsf_dbg_cfg_register reg;

    la_status status = m_device->m_ll_device->read_register(
        *m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rx_rsf_dbg_cfg, reg);
    return_on_error(status);

    out_debug_status = reg.fields.rx_rsf_dbg_port_sel == m_serdes_index_in_mac_pool;

    return LA_STATUS_SUCCESS;
}

la_status
mac_pool2_port::update_rx_krf_config()
{
    mac_pool2_rx_krf_cfg_register rx_krf_cfg{{0}};
    la_status stat = LA_STATUS_SUCCESS;
    bool enable_err_to_pcs = false;

    // if  KR_FEC, enable error reporting
    if (m_fec_mode == la_mac_port::fec_mode_e::KR) {
        enable_err_to_pcs = true;
    }

    // get register value
    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_krf_cfg)[m_serdes_index_in_mac_pool], rx_krf_cfg);
    return_on_error(stat);

    // write value to register
    rx_krf_cfg.fields.fec_en_err_to_pcs = enable_err_to_pcs;

    // write value to all serdes lanes
    for (size_t serdes_lane = 0; serdes_lane < m_serdes_count; serdes_lane++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_krf_cfg)[m_serdes_index_in_mac_pool + serdes_lane],
                                                     rx_krf_cfg);
        return_on_error(stat);
    }

    return stat;
}

la_status
mac_pool2_port::reset_rx_krf_config()
{
    mac_pool2_rx_krf_cfg_register rx_krf_cfg{{0}};
    la_status stat = LA_STATUS_SUCCESS;

    // get register value
    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_krf_cfg)[m_serdes_index_in_mac_pool], rx_krf_cfg);
    return_on_error(stat);

    // write value to register
    rx_krf_cfg.fields.fec_en_err_to_pcs = 0;

    // write value to all serdes lanes
    for (size_t serdes_lane = 0; serdes_lane < m_serdes_count; serdes_lane++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_krf_cfg)[m_serdes_index_in_mac_pool + serdes_lane],
                                                     rx_krf_cfg);
        return_on_error(stat);
    }

    return stat;
}

la_status
mac_pool2_port::configure_loopback_mode(npl_loopback_mode_e mii_loopback_mode, npl_loopback_mode_e pma_loopback_mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
mac_pool2_port::read_mac_soft_reset_config() const
{
    la_status status;
    bit_vector rstn_reg;

    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->slice[m_slice_id]->ifg[m_ifg_id]->mac_pool2->rstn_reg,
                                                  rstn_reg);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}
} // namespace silicon_one
