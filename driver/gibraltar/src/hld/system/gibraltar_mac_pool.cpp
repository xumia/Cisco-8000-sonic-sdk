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

#include "gibraltar_mac_pool.h"
#include "common/defines.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/ifg_handler.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include <cmath>

#include <thread>

namespace silicon_one
{

using namespace gibraltar;
enum {
    COUNTER_TIMER_CYCLES = 0xFFFFFFFF, // Amount of cycles to record counters
    COUNTER_TIMER_MAX_POLL = 100,
    PMA_WIDTH = 80,

    RS_FEC_KR4_FRAME_LEN_IN_BITS = 5280,
    RS_FEC_KP4_FRAME_LEN_IN_BITS = 5440,
};

static constexpr auto COUNTER_TIMER_POLL_INTERVAL_MILLISECONDS = std::chrono::milliseconds(100);

const std::map<la_mac_port::port_speed_e, uint64_t> tx_hw_speed_code = {{la_mac_port::port_speed_e::E_10G, 0},
                                                                        {la_mac_port::port_speed_e::E_25G, 1},
                                                                        {la_mac_port::port_speed_e::E_40G, 2},
                                                                        {la_mac_port::port_speed_e::E_50G, 3},
                                                                        {la_mac_port::port_speed_e::E_100G, 4},
                                                                        {la_mac_port::port_speed_e::E_200G, 5},
                                                                        {la_mac_port::port_speed_e::E_400G, 6},
                                                                        {la_mac_port::port_speed_e::E_800G, 7}};

// PMA MODE to PMA code used in Tx/Rx PMA test config
const uint64_t pma_test_mode_hw_code[(size_t)la_mac_port::pma_test_mode_e::SQUARE_WAVE + 1] = {0, 0, 1, 2, 3, 4, 5, 6, 7};

const std::map<la_mac_port::port_speed_e, uint64_t> rx_ber_timer_period_config = {{la_mac_port::port_speed_e::E_10G, 150000},
                                                                                  {la_mac_port::port_speed_e::E_25G, 2400000},
                                                                                  {la_mac_port::port_speed_e::E_40G, 1500000},
                                                                                  {la_mac_port::port_speed_e::E_50G, 1200000},
                                                                                  {la_mac_port::port_speed_e::E_100G, 600000},
                                                                                  {la_mac_port::port_speed_e::E_200G, 2000},
                                                                                  {la_mac_port::port_speed_e::E_400G, 1000}};

gibraltar_mac_pool::gibraltar_mac_pool(const la_device_impl_wptr& device) : mac_pool_port(device)
{
    m_gibraltar_tree = m_device->m_ll_device->get_gibraltar_tree_scptr();
    m_fec_engine_config = {{la_mac_port::port_speed_e::E_10G, {1, 1}},
                           {la_mac_port::port_speed_e::E_25G, {1, 1}},
                           {la_mac_port::port_speed_e::E_40G, {2, 1}},
                           {la_mac_port::port_speed_e::E_50G, {2, 1}},
                           {la_mac_port::port_speed_e::E_100G, {4, 1}},
                           {la_mac_port::port_speed_e::E_200G, {4, 2}},
                           {la_mac_port::port_speed_e::E_400G, {4, 4}}};
}

gibraltar_mac_pool::~gibraltar_mac_pool()
{
}

la_status
gibraltar_mac_pool::initialize(la_slice_id_t slice_id,
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
    m_slice_id = slice_id;
    m_ifg_id = ifg_id;
    m_mac_lane_index_in_ifgb = serdes_base;
    initialize_register_pointers();

    la_status stat = mac_pool_port::initialize(
        slice_id, ifg_id, serdes_base, num_of_serdes, speed, rx_fc_mode, tx_fc_mode, fec_mode, mlp_mode, port_slice_mode);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::reset_rs_fec_config()
{
    mac_pool8_rx_rsf_cfg0_register rx_rsf_cfg0_register{{0}};

    la_status stat = get_rs_fec_config(&rx_rsf_cfg0_register);
    return_on_error(stat);

    stat = reset_rs_fec_config(&rx_rsf_cfg0_register);
    return_on_error(stat);

    stat = set_rs_fec_config(&rx_rsf_cfg0_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_mib_counters(bool clear, la_mac_port::mib_counters& out_mib_counters) const
{
    mac_pool8_port_mib_counter_register reg;

    la_status stat;
    // Populate any MIB counters that are read from the IFGB
    stat = m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->read_mib_counters(clear, m_serdes_index_in_mac_pool, out_mib_counters);
    return_on_error(stat);

    la_status rc;
    if (clear) {
        rc = m_device->m_ll_device->read_register((*m_mac_pool_counters.port_mib)[m_serdes_index_in_mac_pool], reg);
        return_on_error(rc);
    } else {
        rc = m_device->m_ll_device->peek_register((*m_mac_pool_counters.port_mib)[m_serdes_index_in_mac_pool], reg);
        return_on_error(rc);
    }

    out_mib_counters.tx_frames_ok = reg.fields.tx_mac_frames_ok_cnt;
    out_mib_counters.tx_bytes_ok = reg.fields.tx_mac_bytes_ok_cnt;
    out_mib_counters.tx_64b_frames = reg.fields.tx_mac_64byte_pkt_cnt;
    out_mib_counters.tx_65to127b_frames = reg.fields.tx_mac_65byte_127byte_pkt_cnt;
    out_mib_counters.tx_128to255b_frames = reg.fields.tx_mac_128byte_255byte_pkt_cnt;
    out_mib_counters.tx_256to511b_frames = reg.fields.tx_mac_256byte_511byte_pkt_cnt;
    out_mib_counters.tx_512to1023b_frames = reg.fields.tx_mac_512byte_1023byte_pkt_cnt;
    out_mib_counters.tx_1024to1518b_frames = reg.fields.tx_mac_1024byte_1518byte_pkt_cnt;
    out_mib_counters.tx_1519to2500b_frames = reg.fields.tx_mac_1519byte_2500byte_pkt_cnt;
    out_mib_counters.tx_2501to9000b_frames = reg.fields.tx_mac_2501byte_9000byte_pkt_cnt;
    out_mib_counters.tx_crc_errors = reg.fields.tx_mac_crc_err_cnt;
    out_mib_counters.tx_mac_missing_eop_err = reg.fields.tx_mac_missing_eop_err_cnt;
    out_mib_counters.tx_mac_underrun_err = reg.fields.tx_mac_underrun_err_cnt;
    out_mib_counters.tx_mac_fc_frames_ok = reg.fields.tx_mac_fc_frames_ok_cnt;
    out_mib_counters.tx_oob_mac_frames_ok = reg.fields.tx_oob_mac_frames_ok_cnt;
    // This register is not supported in Gibraltar.
    out_mib_counters.tx_oob_mac_crc_err = 0;
    out_mib_counters.rx_frames_ok = reg.fields.rx_mac_frames_ok_cnt;
    out_mib_counters.rx_bytes_ok = reg.fields.rx_mac_bytes_ok_cnt;
    out_mib_counters.rx_64b_frames = reg.fields.rx_mac_64byte_pkt_cnt;
    out_mib_counters.rx_65to127b_frames = reg.fields.rx_mac_65byte_127byte_pkt_cnt;
    out_mib_counters.rx_128to255b_frames = reg.fields.rx_mac_128byte_255byte_pkt_cnt;
    out_mib_counters.rx_256to511b_frames = reg.fields.rx_mac_256byte_511byte_pkt_cnt;
    out_mib_counters.rx_512to1023b_frames = reg.fields.rx_mac_512byte_1023byte_pkt_cnt;
    out_mib_counters.rx_1024to1518b_frames = reg.fields.rx_mac_1024byte_1518byte_pkt_cnt;
    out_mib_counters.rx_1519to2500b_frames = reg.fields.rx_mac_1519byte_2500byte_pkt_cnt;
    out_mib_counters.rx_2501to9000b_frames = reg.fields.rx_mac_2501byte_9000byte_pkt_cnt;
    out_mib_counters.rx_mac_invert = reg.fields.rx_mac_invert_crc_cnt;
    out_mib_counters.rx_crc_errors = reg.fields.rx_mac_crc_err_cnt;
    out_mib_counters.rx_oversize_err = reg.fields.rx_mac_oversize_err_cnt;
    out_mib_counters.rx_undersize_err = reg.fields.rx_mac_undersize_err_cnt;
    out_mib_counters.rx_mac_code_err = reg.fields.rx_mac_code_err_cnt;
    out_mib_counters.rx_mac_fc_frames_ok = reg.fields.rx_mac_fc_frames_ok_cnt;
    out_mib_counters.rx_oob_mac_frames_ok = reg.fields.rx_oob_mac_frames_ok_cnt;
    // rx_oob_mac_invert_crc and rx_oob_mac_crc_err are both read from the IFGB rx_oobe_port_crc_err_cnt in GB.
    // out_mib_counters.rx_oob_mac_invert_crc = rx_oob_crc_reg.fields.rx_oobe_port_crc_err_cnt;
    // out_mib_counters.rx_oob_mac_crc_err = rx_oob_crc_reg.fields.rx_oobe_port_crc_err_cnt;
    out_mib_counters.rx_oob_mac_code_err = reg.fields.rx_oob_mac_code_err_cnt;

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_mac_config(mac_pool8_rx_mac_cfg0_register* rx_mac_cfg0_register,
                                   mac_pool8_tx_mac_cfg0_register* tx_mac_cfg0_register) const
{
    la_status stat;

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_mac_cfg0)[m_serdes_index_in_mac_pool], *rx_mac_cfg0_register);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.tx_mac_cfg0)[m_serdes_index_in_mac_pool], *tx_mac_cfg0_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_mac_config(mac_pool8_rx_mac_cfg0_register* rx_mac_cfg0_register,
                                   mac_pool8_tx_mac_cfg0_register* tx_mac_cfg0_register)
{
    la_status stat;

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_mac_cfg0)[m_serdes_index_in_mac_pool + serdes],
                                                     *rx_mac_cfg0_register);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_cfg0)[m_serdes_index_in_mac_pool + serdes],
                                                     *tx_mac_cfg0_register);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::reset_mac_config()
{
    mac_pool8_rx_mac_cfg0_register rx_mac_cfg0_register;
    mac_pool8_tx_mac_cfg0_register tx_mac_cfg0_register;

    bzero(&rx_mac_cfg0_register, mac_pool8_rx_mac_cfg0_register::SIZE);
    bzero(&tx_mac_cfg0_register, mac_pool8_tx_mac_cfg0_register::SIZE);

    /// MAC RX configurations 0
    rx_mac_cfg0_register.fields.rx_crc_check = 1;                   ///< CRC checking (0-disable, 1-enable).
    rx_mac_cfg0_register.fields.rx_crc_oob_check = 1;               ///< CRC checking (0-disable, 1-enable).
    rx_mac_cfg0_register.fields.rx_oob_intrlv_type_filt_en = 1;     ///< OOB interleaving type filt (0-disable, 1-enable).
    rx_mac_cfg0_register.fields.rx_oob_intrlv_inb_type_filt_en = 1; ///< OOB interleaving inband type filt (0-disable, 1-enable).
    rx_mac_cfg0_register.fields.rx_cnt_ka_en = 1;                   ///< Keep Alive packet counting (0-disable, 1-enable).
    rx_mac_cfg0_register.fields.rx_crc_strip = 1;                   ///< CRC strip (0-disable, 1-enable).
    ///< MAC FC packets termination (0-don't terminate, 1-terminate).
    // Set it to not terminate to be able to count PFC packets.
    if (is_network_slice(m_port_slice_mode)) {
        rx_mac_cfg0_register.fields.rx_ctrl_pkts_term = (m_rx_fc_term_mode) ? 1 : 0;
    } else {
        rx_mac_cfg0_register.fields.rx_ctrl_pkts_term = 1;
    }
    rx_mac_cfg0_register.fields.rx_fc_mode = (uint8_t)m_rx_fc_mode; ///< FC mode
    rx_mac_cfg0_register.fields.rx_link_interruption_en
        = 1; ///< Link interruption enabled (1-Act uppon link interruption in a similar way of local fault).

    /// MAC TX configurations 0
    // GB: check new fields should be kept with default values
    tx_mac_cfg0_register.fields.tx_crc_en = 1;                      ///< CRC append (0-disable, 1-enable).
    tx_mac_cfg0_register.fields.tx_crc_oob_en = 1;                  ///< CRC OOB append (0-disable, 1-enable).
    tx_mac_cfg0_register.fields.tx_cnt_ka_en = 1;                   ///< Keep Alive counting (0-disable, 1-enable).
    tx_mac_cfg0_register.fields.tx_fc_mode = (uint8_t)m_tx_fc_mode; ///< FC mode

    switch (m_speed) {
    case la_mac_port::port_speed_e::E_10G:
        tx_mac_cfg0_register.fields.tx_am_insert_amont = 0;
        break;
    case la_mac_port::port_speed_e::E_25G:
        tx_mac_cfg0_register.fields.tx_am_insert_amont = (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4) ? 4 : 0;
        break;
    case la_mac_port::port_speed_e::E_40G:
    case la_mac_port::port_speed_e::E_50G:
        tx_mac_cfg0_register.fields.tx_am_insert_amont = 4;
        break;
    case la_mac_port::port_speed_e::E_100G:
        tx_mac_cfg0_register.fields.tx_am_insert_amont = 20;
        break;
    case la_mac_port::port_speed_e::E_200G:
        tx_mac_cfg0_register.fields.tx_am_insert_amont = 16;
        break;
    case la_mac_port::port_speed_e::E_400G:
        tx_mac_cfg0_register.fields.tx_am_insert_amont = 32;
        break;
    default:
        log_err(MAC_PORT,
                "%s: %s unexpected port speed: %s",
                __func__,
                this->to_string().c_str(),
                silicon_one::to_string(m_speed).c_str());
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status rc = set_mac_config(&rx_mac_cfg0_register, &tx_mac_cfg0_register);

    return rc;
}

la_status
gibraltar_mac_pool::set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode)
{
    la_mac_port::fc_mode_e rx_fc_mode = la_mac_port::fc_mode_e::NONE;
    la_mac_port::fc_mode_e tx_fc_mode = la_mac_port::fc_mode_e::NONE;
    mac_pool8_rx_mac_cfg0_register rx_mac_cfg0_register;
    mac_pool8_tx_mac_cfg0_register tx_mac_cfg0_register;
    la_status stat = get_mac_config(&rx_mac_cfg0_register, &tx_mac_cfg0_register);
    return_on_error(stat);

    switch (fc_dir) {
    case la_mac_port::fc_direction_e::RX:
        rx_fc_mode = fc_mode;
        tx_fc_mode = (la_mac_port::fc_mode_e)tx_mac_cfg0_register.fields.tx_fc_mode;
        break;
    case la_mac_port::fc_direction_e::TX:
        rx_fc_mode = (la_mac_port::fc_mode_e)rx_mac_cfg0_register.fields.rx_fc_mode;
        tx_fc_mode = fc_mode;
        break;
    case la_mac_port::fc_direction_e::BIDIR:
        rx_fc_mode = fc_mode;
        tx_fc_mode = fc_mode;
        break;
    }

    rx_mac_cfg0_register.fields.rx_fc_mode = (uint8_t)rx_fc_mode;
    tx_mac_cfg0_register.fields.tx_fc_mode = (uint8_t)tx_fc_mode;

    stat = set_mac_config(&rx_mac_cfg0_register, &tx_mac_cfg0_register);
    return_on_error(stat);

    stat = mac_pool_port::set_fc_mode(fc_dir, fc_mode);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_ipg(la_uint16_t& out_gap_len, la_uint16_t& out_gap_tx_bytes) const
{
    mac_pool8_tx_mac_cfg_ipg_register tx_mac_cfg_ipg;

    la_status stat
        = m_device->m_ll_device->read_register((*m_mac_pool_regs.tx_mac_cfg_ipg)[m_serdes_index_in_mac_pool], tx_mac_cfg_ipg);
    return_on_error(stat);

    out_gap_len = tx_mac_cfg_ipg.fields.tx_ipg_burst;
    out_gap_tx_bytes = tx_mac_cfg_ipg.fields.tx_ipg_period;

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_ipg(la_uint16_t gap_len, la_uint16_t gap_tx_bytes)
{
    mac_pool8_tx_mac_cfg_ipg_register tx_mac_cfg_ipg;

    tx_mac_cfg_ipg.fields.tx_ipg_burst = gap_len;
    tx_mac_cfg_ipg.fields.tx_ipg_period = gap_tx_bytes;

    la_status stat;
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_cfg_ipg)[m_serdes_index_in_mac_pool + serdes],
                                                     tx_mac_cfg_ipg);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_crc_enabled(bool& out_enabled) const
{
    mac_pool8_rx_mac_cfg0_register rx_mac_cfg0_register;
    mac_pool8_tx_mac_cfg0_register tx_mac_cfg0_register;
    la_status stat = get_mac_config(&rx_mac_cfg0_register, &tx_mac_cfg0_register);
    return_on_error(stat);

    if ((rx_mac_cfg0_register.fields.rx_crc_check != rx_mac_cfg0_register.fields.rx_crc_strip)
        || (rx_mac_cfg0_register.fields.rx_crc_check != tx_mac_cfg0_register.fields.tx_crc_en)) {
        // Non coherent setting
        return LA_STATUS_EUNKNOWN;
    }

    out_enabled = rx_mac_cfg0_register.fields.rx_crc_check;

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_crc_enabled(bool enabled)
{
    mac_pool8_rx_mac_cfg0_register rx_mac_cfg0_register;
    mac_pool8_tx_mac_cfg0_register tx_mac_cfg0_register;
    la_status stat = get_mac_config(&rx_mac_cfg0_register, &tx_mac_cfg0_register);
    return_on_error(stat);

    rx_mac_cfg0_register.fields.rx_crc_check = enabled;
    rx_mac_cfg0_register.fields.rx_crc_strip = enabled;
    tx_mac_cfg0_register.fields.tx_crc_en = enabled;

    stat = set_mac_config(&rx_mac_cfg0_register, &tx_mac_cfg0_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::destroy_general_config()
{
    mac_pool8_tx_cfg0_register tx_cfg_register;
    mac_pool8_rx_cfg0_register rx_cfg_register;
    mac_pool8_am_cfg_register am_cfg_register;
    mac_pool8_rsf_ck_cycles_per_1ms_reg_register rsf_ck_cycles_reg;

    bzero(&tx_cfg_register, mac_pool8_tx_cfg0_register::SIZE);
    bzero(&rx_cfg_register, mac_pool8_rx_cfg0_register::SIZE);
    bzero(&am_cfg_register, mac_pool8_am_cfg_register::SIZE);
    bzero(&rsf_ck_cycles_reg, mac_pool8_rsf_ck_cycles_per_1ms_reg_register::SIZE);

    rsf_ck_cycles_reg.fields.rsf_ck_cycles_per_1ms = m_device->m_device_frequency_int_khz;

    tx_cfg_register.fields.tx_100g_frame_intrlv_en = 0;
    tx_cfg_register.fields.tx_bypass_scr = 0;
    tx_cfg_register.fields.tx_rsf_scr_enable = 0;
    tx_cfg_register.fields.tx_preamble_compression = 0;
    tx_cfg_register.fields.tx_oob_intrlv_en = 0;
    tx_cfg_register.fields.tx_fabric_mode = 0;
    tx_cfg_register.fields.tx_rsf_100g_am_cd_style = 0;
    tx_cfg_register.fields.tx_en_32b_alignment = 1;

    rx_cfg_register.fields.rx_en_32b_alignment = 1;
    rx_cfg_register.fields.rx_rsf_single_alm_empty_thd = 0x48;
    rx_cfg_register.fields.rx_am_invalid_cnt_thd = 0x5;
    rx_cfg_register.fields.rx_high_ber_fsm_act_en = 0x1;

    am_cfg_register.fields.rx_am_cfg = 0x03ffe;
    am_cfg_register.fields.tx_am_cfg = 0x27ff3;

    la_status stat = set_general_config(&tx_cfg_register, &rx_cfg_register, &am_cfg_register);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(*m_mac_pool_regs.rsf_ck_cycles_per_1ms_reg, rsf_ck_cycles_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::reset_general_config()
{
    mac_pool8_tx_cfg0_register tx_cfg_register;
    mac_pool8_rx_cfg0_register rx_cfg_register;
    mac_pool8_am_cfg_register am_cfg_register;
    mac_pool8_tx_oobi_cfg_register tx_oobi_cfg_register;
    mac_pool8_rsf_ck_cycles_per_1ms_reg_register rsf_ck_cycles_reg;

    bzero(&tx_cfg_register, mac_pool8_tx_cfg0_register::SIZE);
    bzero(&rx_cfg_register, mac_pool8_rx_cfg0_register::SIZE);
    bzero(&am_cfg_register, mac_pool8_am_cfg_register::SIZE);
    bzero(&tx_oobi_cfg_register, mac_pool8_tx_oobi_cfg_register::SIZE);
    bzero(&rsf_ck_cycles_reg, mac_pool8_rsf_ck_cycles_per_1ms_reg_register::SIZE);

    rsf_ck_cycles_reg.fields.rsf_ck_cycles_per_1ms = m_device->m_device_frequency_int_khz;

    /// General TX configurations. This register holds the main TX configurations per MAC lane.
    if (m_port_slice_mode == la_slice_mode_e::NETWORK) {
        // Allow Network Slice to have FEC RS_KP4_FI
        if (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI) {
            tx_cfg_register.fields.tx_100g_frame_intrlv_en = 1;
            tx_cfg_register.fields.tx_bypass_scr = 1;
            tx_cfg_register.fields.tx_rsf_scr_enable = 1;
            tx_cfg_register.fields.tx_rsf_100g_am_cd_style = 1;
        } else {
            tx_cfg_register.fields.tx_100g_frame_intrlv_en = 0;
            tx_cfg_register.fields.tx_bypass_scr = 0;
            tx_cfg_register.fields.tx_rsf_scr_enable = 0;
            tx_cfg_register.fields.tx_preamble_compression = 0;
            tx_cfg_register.fields.tx_oob_intrlv_en = 0;
            tx_cfg_register.fields.tx_fabric_mode = 0;
            tx_cfg_register.fields.tx_rsf_100g_am_cd_style = 0;
        }
    } else {
        // Fabric
        device_port_handler_base::fabric_data fabric_data;
        m_device->m_device_port_handler->get_fabric_data(fabric_data);
        tx_cfg_register.fields.tx_100g_frame_intrlv_en = fabric_data.speed == la_mac_port::port_speed_e::E_100G;
        tx_cfg_register.fields.tx_bypass_scr = 1;
        tx_cfg_register.fields.tx_rsf_scr_enable = 1;
        // Preamble compression is not yet checked by HW. Disable for now.
        //      tx_cfg_register.fields.tx_preamble_compression = 1;
        tx_cfg_register.fields.tx_preamble_compression = 0;

        bool pacific_oobi_en;
        m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING, pacific_oobi_en);
        if (pacific_oobi_en) {
            tx_cfg_register.fields.tx_oob_intrlv_en = 1; // Should be aligned with ifgb.tx_cfg0
            tx_oobi_cfg_register.fields.tx_oob_intrlv_head_room_flits = 17;
            tx_oobi_cfg_register.fields.oob_shaper_period = 80;
        } else {
            tx_cfg_register.fields.tx_oob_intrlv_en = 0;
        }

        tx_oobi_cfg_register.fields.oob_shaper_max_burst_size = 6;
        tx_cfg_register.fields.tx_fabric_mode = 1;
        tx_cfg_register.fields.tx_rsf_100g_am_cd_style = 1;
    }

    /// General RX configurations. This register holds the main RX configurations per MAC lane.
    if ((m_speed == la_mac_port::port_speed_e::E_200G) || (m_speed == la_mac_port::port_speed_e::E_400G)) {
        rx_cfg_register.fields.rx_high_ber_fsm_act_en = 0; // Disabled High BER FSM for 200G and 400G CSCvq68962
    } else {
        rx_cfg_register.fields.rx_high_ber_fsm_act_en = 1; // Enabled
    }

    la_status stat = recalc_general_config(&tx_cfg_register, &rx_cfg_register, &am_cfg_register);
    return_on_error(stat);

    stat = set_general_config(&tx_cfg_register, &rx_cfg_register, &am_cfg_register);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register(*m_mac_pool_regs.rsf_ck_cycles_per_1ms_reg, rsf_ck_cycles_reg);
    return_on_error(stat);

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_oobi_cfg_reg)[m_serdes_index_in_mac_pool + i],
                                                     tx_oobi_cfg_register);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::update_general_config()
{
    mac_pool8_tx_cfg0_register tx_cfg_register;
    mac_pool8_rx_cfg0_register rx_cfg_register;
    mac_pool8_am_cfg_register am_cfg_register;

    bzero(&tx_cfg_register, mac_pool8_tx_cfg0_register::SIZE);
    bzero(&rx_cfg_register, mac_pool8_rx_cfg0_register::SIZE);
    bzero(&am_cfg_register, mac_pool8_am_cfg_register::SIZE);

    la_status stat = get_general_config(&tx_cfg_register, &rx_cfg_register, &am_cfg_register);
    return_on_error(stat);

    stat = recalc_general_config(&tx_cfg_register, &rx_cfg_register, &am_cfg_register);
    return_on_error(stat);

    stat = set_general_config(&tx_cfg_register, &rx_cfg_register, &am_cfg_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::recalc_general_config(mac_pool8_tx_cfg0_register* tx_cfg_register,
                                          mac_pool8_rx_cfg0_register* rx_cfg_register,
                                          mac_pool8_am_cfg_register* am_cfg_register)
{
    // TODO GB rx_out_buff_shaper_cfg_reg to be enabled later
    // ask Arnon for details
    size_t alignment_marker_rx;
    size_t alignment_marker_tx;
    la_status stat = get_alignment_marker(alignment_marker_rx, alignment_marker_tx);
    return_on_error(stat);

    if (m_speed == la_mac_port::port_speed_e::E_40G && m_serdes_count == 2) {
        tx_cfg_register->fields.tx_port_speed = tx_hw_speed_code.at(la_mac_port::port_speed_e::E_50G);
    } else {
        tx_cfg_register->fields.tx_port_speed = tx_hw_speed_code.at(m_speed);
    }

    tx_cfg_register->fields.tx_port_nof_srd = int(log2(m_serdes_count));

    tx_cfg_register->fields.tx_en_32b_alignment
        = ((m_speed == la_mac_port::port_speed_e::E_10G) || (m_speed == la_mac_port::port_speed_e::E_25G)) ? 1 : 0;

    tx_cfg_register->fields.tx_fec_mode = (m_fec_mode != la_mac_port::fec_mode_e::RS_KP4_FI)
                                              ? ((uint16_t)m_fec_mode & 3)
                                              : ((uint16_t)la_mac_port::fec_mode_e::RS_KP4 & 3);

    if (m_fec_mode != la_mac_port::fec_mode_e::RS_KP4_FI) {
        tx_cfg_register->fields.tx_bypass_scr = ((m_pcs_test_mode == la_mac_port::pcs_test_mode_e::PRBS31)
                                                 || (m_pcs_test_mode == la_mac_port::pcs_test_mode_e::PRBS9))
                                                    ? 1
                                                    : 0;
    }

    if ((m_speed == la_mac_port::port_speed_e::E_200G) || (m_speed == la_mac_port::port_speed_e::E_400G)) {
        tx_cfg_register->fields.tx_bypass_scr = 1;
        tx_cfg_register->fields.tx_rsf_scr_enable = 1;
    }

    /// General RX configurations. This register holds the main RX configurations per MAC lane.
    rx_cfg_register->fields.rx_port_speed = tx_cfg_register->fields.tx_port_speed;
    rx_cfg_register->fields.rx_100g_frame_intrlv_en = tx_cfg_register->fields.tx_100g_frame_intrlv_en;
    rx_cfg_register->fields.rx_port_nof_srd = tx_cfg_register->fields.tx_port_nof_srd;
    rx_cfg_register->fields.rx_bypass_scr = tx_cfg_register->fields.tx_bypass_scr;
    rx_cfg_register->fields.rx_rsf_scr_enable = tx_cfg_register->fields.tx_rsf_scr_enable;
    rx_cfg_register->fields.rx_en_32b_alignment = tx_cfg_register->fields.tx_en_32b_alignment;
    rx_cfg_register->fields.rx_preamble_compression = tx_cfg_register->fields.tx_preamble_compression;
    rx_cfg_register->fields.rx_fec_mode = tx_cfg_register->fields.tx_fec_mode;

    // Enabled when no FEC or KR FEC
    rx_cfg_register->fields.rx_66b_w_lock_en
        = ((m_fec_mode == la_mac_port::fec_mode_e::NONE) || (m_fec_mode == la_mac_port::fec_mode_e::KR)) ? 1 : 0;

    rx_cfg_register->fields.rx_rsf_single_alm_empty_thd = 72;

    // The RS-FEC element in the HW works in 100G rate. So for ports speeds of 25G and 50G it might get shared by different ports.
    // The below configuration is needed to make sure the entire FEC frame is read.
    if ((m_speed == la_mac_port::port_speed_e::E_25G) && (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4)) {
        // TODO: Validate
        rx_cfg_register->fields.rx_rsf_single_alm_empty_thd = 80;
    } else if (((m_speed == la_mac_port::port_speed_e::E_25G) || (m_speed == la_mac_port::port_speed_e::E_50G))
               && ((m_fec_mode == la_mac_port::fec_mode_e::RS_KR4) || (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4))) {
        float frame_len = 0;
        size_t ser_speed_gbps = m_serdes_speed_gbps * m_serdes_count;
        if (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4) {
            frame_len = RS_FEC_KR4_FRAME_LEN_IN_BITS;
        } else if (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4) {
            frame_len = RS_FEC_KP4_FRAME_LEN_IN_BITS;
        }

        // The calculation elements are (The units are 60 bits):
        // FRAME_LEN / 60 - amount of 60 bits words in FEC frame
        // FRAME_LEN / 120 - amount of clock cycles to read a fec frame into the decoder
        // Above / freq - time in nanoseconds to read a fec frame into the decoder
        // * serdes_speed / 60 - amount of words written during the time above (+5 is needed spare)
        float words_per_frame = frame_len / 60;
        float words_per_nanosec = (float)ser_speed_gbps / 60;
        float time_in_nanosec_to_read_frame = frame_len / (120 * m_device->m_device_frequency_float_ghz);
        rx_cfg_register->fields.rx_rsf_single_alm_empty_thd
            = round(words_per_frame - (words_per_nanosec * time_in_nanosec_to_read_frame)) + 5;
    }

    rx_cfg_register->fields.rx_oob_intrlv_en = tx_cfg_register->fields.tx_oob_intrlv_en;
    rx_cfg_register->fields.rx_fabric_mode = tx_cfg_register->fields.tx_fabric_mode;

    /// Alignment markers spacing configuration register

    am_cfg_register->fields.rx_am_cfg = alignment_marker_rx;
    am_cfg_register->fields.tx_am_cfg = alignment_marker_tx;

    if (m_port_slice_mode == la_slice_mode_e::NETWORK) {
        switch (m_speed) {
        case la_mac_port::port_speed_e::E_10G:
        case la_mac_port::port_speed_e::E_40G:
            rx_cfg_register->fields.rx_rsf_err_ind_mark_mode = 0;
            break;
        case la_mac_port::port_speed_e::E_25G:
        case la_mac_port::port_speed_e::E_50G:
            rx_cfg_register->fields.rx_rsf_err_ind_mark_mode = 2;
            break;
        case la_mac_port::port_speed_e::E_100G:
            // According to the standard it should be 3 but seems there is some HW bug in GB A0 and setting this configuration
            // is a work around.
            rx_cfg_register->fields.rx_rsf_err_ind_mark_mode = 1;
            break;
        case la_mac_port::port_speed_e::E_200G:
        case la_mac_port::port_speed_e::E_400G:
            rx_cfg_register->fields.rx_rsf_err_ind_mark_mode = 1;
            break;
        case la_mac_port::port_speed_e::E_MGIG:
        case la_mac_port::port_speed_e::E_20G:
        case la_mac_port::port_speed_e::E_800G:
        case la_mac_port::port_speed_e::E_1200G:
        case la_mac_port::port_speed_e::E_1600G:
            return LA_STATUS_EINVAL;
        }
    } else {
        // Fabric
        rx_cfg_register->fields.rx_rsf_err_ind_mark_mode = 1;
    }

    if ((m_speed == la_mac_port::port_speed_e::E_400G) || (m_speed == la_mac_port::port_speed_e::E_200G)
        || (m_speed == la_mac_port::port_speed_e::E_100G)
        || (m_speed == la_mac_port::port_speed_e::E_50G)) {
        rx_cfg_register->fields.rx_am_invalid_cnt_thd = 5;
    } else if (m_fec_mode == la_mac_port::fec_mode_e::NONE) {
        rx_cfg_register->fields.rx_am_invalid_cnt_thd = 4;
    } else {
        rx_cfg_register->fields.rx_am_invalid_cnt_thd = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_general_config(mac_pool8_tx_cfg0_register* tx_cfg_register,
                                       mac_pool8_rx_cfg0_register* rx_cfg_register,
                                       mac_pool8_am_cfg_register* am_cfg_register) const
{
    la_status stat;

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.tx_cfg0)[m_serdes_index_in_mac_pool], *tx_cfg_register);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_cfg0)[m_serdes_index_in_mac_pool], *rx_cfg_register);
    return_on_error(stat);

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.am_cfg)[m_serdes_index_in_mac_pool], *am_cfg_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_general_config(mac_pool8_tx_cfg0_register* tx_cfg_register,
                                       mac_pool8_rx_cfg0_register* rx_cfg_register,
                                       mac_pool8_am_cfg_register* am_cfg_register)
{
    la_status stat;
    // There is a bug in the HW that requires the writing of FEC and speed in two separate writes, in spite them being fields in the
    // same register.
    // The first write should be the new FEC mode with other fields being default.
    // The second write should include all the correct values.

    // Initialize tx_cfg from default values, and take the FEC mode from the final cfg.
    mac_pool8_tx_cfg0_register tx_cfg_fec_only_register;
    const lld_register_desc_t* tx_cfg_desc = m_mac_pool_regs.tx_cfg0->get_desc();
    memcpy(&(tx_cfg_fec_only_register.u8), tx_cfg_desc->default_value.data(), tx_cfg_desc->width);
    tx_cfg_fec_only_register.fields.tx_fec_mode = tx_cfg_register->fields.tx_fec_mode;

    size_t mac_lanes_to_config = m_mac_lanes_count;
    if ((m_speed == la_mac_port::port_speed_e::E_40G) && (m_serdes_count == 4)) {
        // Some small HW inconsistency
        mac_lanes_to_config = 4;
    }
    for (size_t i = 0; i < mac_lanes_to_config; i++) {
        // Workaround - first write only the new FEC mode
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_cfg0)[m_serdes_index_in_mac_pool + i],
                                                     tx_cfg_fec_only_register);
        return_on_error(stat);

        // Workaround - second write the full correct values
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_cfg0)[m_serdes_index_in_mac_pool + i], *tx_cfg_register);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_cfg0)[m_serdes_index_in_mac_pool + i], *rx_cfg_register);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.am_cfg)[m_serdes_index_in_mac_pool + i], *am_cfg_register);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_packet_sizes(la_uint_t min_size, la_uint_t max_size)
{
    mac_pool8_rx_mac_cfg1_register rx_mac_cfg1_register;
    bzero(&rx_mac_cfg1_register, mac_pool8_rx_mac_cfg1_register::SIZE);

    /// MAC RX configurations 1
    rx_mac_cfg1_register.fields.rx_max_pkt_size = max_size;
    rx_mac_cfg1_register.fields.rx_min_pkt_size = min_size;

    la_status stat;

    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_mac_cfg1)[m_serdes_index_in_mac_pool + i],
                                                     rx_mac_cfg1_register);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_packet_sizes(la_uint_t& out_min_size, la_uint_t& out_max_size) const
{
    mac_pool8_rx_mac_cfg1_register rx_mac_cfg1_register;
    /// MAC RX configurations 1
    rx_mac_cfg1_register.fields.rx_max_pkt_size = 0;
    rx_mac_cfg1_register.fields.rx_min_pkt_size = 0;

    la_status stat;

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_mac_cfg1)[m_serdes_index_in_mac_pool], rx_mac_cfg1_register);
    return_on_error(stat);

    out_max_size = rx_mac_cfg1_register.fields.rx_max_pkt_size;
    out_min_size = rx_mac_cfg1_register.fields.rx_min_pkt_size;

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::update_rs_fec_config()
{
    mac_pool8_rx_rsf_cfg0_register rx_rsf_cfg0_register;

    bzero(&rx_rsf_cfg0_register, mac_pool8_rx_rsf_cfg0_register::SIZE);

    la_status stat = get_rs_fec_config(&rx_rsf_cfg0_register);
    return_on_error(stat);

    stat = recalc_rs_fec_config(&rx_rsf_cfg0_register);
    return_on_error(stat);

    stat = set_rs_fec_config(&rx_rsf_cfg0_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::update_rx_krf_config()
{
    mac_pool8_rx_krf_cfg_register rx_krf_cfg{{0}};
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
gibraltar_mac_pool::reset_rx_krf_config()
{
    mac_pool8_rx_krf_cfg_register rx_krf_cfg{{0}};
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
gibraltar_mac_pool::recalc_rs_fec_config(mac_pool8_rx_rsf_cfg0_register* rx_rsf_cfg0_register) const
{
    // Configure port 0 of the RS-FEC
    bool configure_port0 = (m_serdes_index_in_mac_pool % 2) == 0;

    // Configure port 1 of the RS-FEC
    bool configure_port1 = ((m_serdes_index_in_mac_pool % 2) == 1) || (m_speed >= la_mac_port::port_speed_e::E_100G);

    bool high_ser_fsm_en = m_speed == la_mac_port::port_speed_e::E_400G;

    rx_rsf_cfg0_register->fields.rx_high_ser_fsm_en_port0 = high_ser_fsm_en;
    rx_rsf_cfg0_register->fields.rx_high_ser_fsm_en_port1 = high_ser_fsm_en;

    // TODO: The following two register define if action should be taken in case of high SER,
    //       this should be high_ser_fsm_en but due to current port stability we disable it.
    //       Should be changed after port stabilized.
    //       Note: This workaround override high_ser_fsm_en for all ports.
    //             Currently this affects only 400G ports but in future it may affect others.
    rx_rsf_cfg0_register->fields.rx_high_ser_fsm_en_act_port0 = 0;
    rx_rsf_cfg0_register->fields.rx_high_ser_fsm_en_act_port1 = 0;

    if (configure_port0) {
        if ((m_fec_mode == la_mac_port::fec_mode_e::RS_KP4) || (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI)) {
            rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 |= 1; // set bit 0
        } else {
            rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 &= 2; // clear bit 0
        }

        rx_rsf_cfg0_register->fields.rx_port_bypass_cor &= 2;
        rx_rsf_cfg0_register->fields.rx_port_bypass_ind &= 2;
        rx_rsf_cfg0_register->fields.rx_port_bypass_cor |= static_cast<int>(m_fec_bypass) & 1;
        rx_rsf_cfg0_register->fields.rx_port_bypass_ind |= (static_cast<int>(m_fec_bypass) & 2) >> 1;
    }
    if (configure_port1) {
        if ((m_fec_mode == la_mac_port::fec_mode_e::RS_KP4) || (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI)) {
            rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 |= 2; // set bit 1
        } else {
            rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 &= 1; // clear bit 1
        }

        rx_rsf_cfg0_register->fields.rx_port_bypass_cor &= 1;
        rx_rsf_cfg0_register->fields.rx_port_bypass_ind &= 1;
        rx_rsf_cfg0_register->fields.rx_port_bypass_cor |= (static_cast<int>(m_fec_bypass) & 1) << 1;
        rx_rsf_cfg0_register->fields.rx_port_bypass_ind |= static_cast<int>(m_fec_bypass) & 2;
    }

    rx_rsf_cfg0_register->fields.rx_rsf_kp4 = (rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 != 0);
    rx_rsf_cfg0_register->fields.rx_bypass_cor = rx_rsf_cfg0_register->fields.rx_port_bypass_cor == 3;
    rx_rsf_cfg0_register->fields.rx_bypass_ind = rx_rsf_cfg0_register->fields.rx_port_bypass_ind == 3;

    if ((m_speed == la_mac_port::port_speed_e::E_25G) && (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4)) {
        rx_rsf_cfg0_register->fields.rx_rsf_single_lane_shaper_cfg = 49;
    } else {
        rx_rsf_cfg0_register->fields.rx_rsf_single_lane_shaper_cfg = 45;
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::reset_rs_fec_config(mac_pool8_rx_rsf_cfg0_register* rx_rsf_cfg0_register)
{
    // Configure port 0 of the RS-FEC
    bool configure_port0 = (m_serdes_index_in_mac_pool % 2) == 0;

    // Configure port 1 of the RS-FEC
    bool configure_port1 = ((m_serdes_index_in_mac_pool % 2) == 1) || (m_speed >= la_mac_port::port_speed_e::E_100G);

    if (configure_port0) {
        rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 &= 2; // clear bit 0
    }

    if (configure_port1) {
        rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 &= 1; // clear bit 1
    }

    rx_rsf_cfg0_register->fields.rx_rsf_kp4 = (rx_rsf_cfg0_register->fields.rx_rsf_port_kp4 != 0);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_rs_fec_config(mac_pool8_rx_rsf_cfg0_register* rx_rsf_cfg0_register) const
{
    la_status stat;

    stat = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_rsf_cfg0)[m_serdes_index_in_mac_pool / 2],
                                                *rx_rsf_cfg0_register);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_rs_fec_config(mac_pool8_rx_rsf_cfg0_register* rx_rsf_cfg0_register)
{
    size_t rs_fec_to_set = 1;

    if (m_speed == la_mac_port::port_speed_e::E_200G) {
        rs_fec_to_set = 2;
    } else if (m_speed == la_mac_port::port_speed_e::E_400G) {
        rs_fec_to_set = 4;
    }

    la_status stat;

    for (size_t rsf_i = 0; rsf_i < rs_fec_to_set; rsf_i++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_rsf_cfg0)[m_serdes_index_in_mac_pool / 2 + rsf_i],
                                                     *rx_rsf_cfg0_register);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::reset_ipg()
{
    mac_pool8_tx_mac_cfg_ipg_register tx_mac_cfg_ipg;
    bzero(&tx_mac_cfg_ipg, mac_pool8_tx_mac_cfg_ipg_register::SIZE);

    tx_mac_cfg_ipg.fields.tx_ipg_period = 0;

    if (m_port_slice_mode == la_slice_mode_e::NETWORK) {
        tx_mac_cfg_ipg.fields.tx_ipg_burst = 12;
    } else {
        // Fabric
        tx_mac_cfg_ipg.fields.tx_ipg_burst = 0;
    }

    la_status stat;
    stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_cfg_ipg)[m_serdes_index_in_mac_pool], tx_mac_cfg_ipg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::reset_xon_xoff_timers()
{
    mac_pool8_tx_mac_fc_xoff_timer_register xoff_reg;
    mac_pool8_tx_mac_fc_xon_timer_register xon_reg;

    bzero(&xoff_reg, mac_pool8_tx_mac_fc_xoff_timer_register::SIZE);
    bzero(&xon_reg, mac_pool8_tx_mac_fc_xon_timer_register::SIZE);

    xoff_reg.fields.tx_fc_xoff_en = 0xFF; // Enable all
    xoff_reg.fields.tx_fc_xoff_timer = 0xFFFF;
    xon_reg.fields.tx_fc_xon_en = 0xFF; // enabled all
    xon_reg.fields.tx_fc_xon_timer = 0;

    la_status stat;
    stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_per_xoff_timer)[m_serdes_index_in_mac_pool], xoff_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_xoff_timer)[m_serdes_index_in_mac_pool], xoff_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_per_xon_timer)[m_serdes_index_in_mac_pool], xon_reg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_xon_timer)[m_serdes_index_in_mac_pool], xon_reg);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::configure_pcs_test_mode()
{
    mac_pool8_tx_pcs_test_cfg0_register tx_pcs_test_cfg0;
    mac_pool8_rx_pcs_test_cfg0_register rx_pcs_test_cfg0;

    bzero(&tx_pcs_test_cfg0, mac_pool8_tx_pcs_test_cfg0_register::SIZE);
    bzero(&rx_pcs_test_cfg0, mac_pool8_rx_pcs_test_cfg0_register::SIZE);

    if (m_pcs_test_mode == la_mac_port::pcs_test_mode_e::NONE) {
        tx_pcs_test_cfg0.fields.tx_pcs_test_en = 0;
        rx_pcs_test_cfg0.fields.rx_pcs_test_en = 0;
    } else {
        tx_pcs_test_cfg0.fields.tx_pcs_test_en = 1;
        rx_pcs_test_cfg0.fields.rx_pcs_test_en = 1;

        switch (m_pcs_test_mode) {
        case la_mac_port::pcs_test_mode_e::SCRAMBLED:
            tx_pcs_test_cfg0.fields.tx_pcs_test_mode = 0;
            rx_pcs_test_cfg0.fields.rx_pcs_test_mode = 0;
            break;

        case la_mac_port::pcs_test_mode_e::RANDOM:
            tx_pcs_test_cfg0.fields.tx_pcs_test_mode = 1;
            tx_pcs_test_cfg0.fields.tx_pcs_data_pattern_sel = 0;
            rx_pcs_test_cfg0.fields.rx_pcs_test_mode = 1;
            rx_pcs_test_cfg0.fields.rx_pcs_data_pattern_sel = 0;
            break;

        case la_mac_port::pcs_test_mode_e::RANDOM_ZEROS:
            tx_pcs_test_cfg0.fields.tx_pcs_test_mode = 1;
            tx_pcs_test_cfg0.fields.tx_pcs_data_pattern_sel = 1;
            rx_pcs_test_cfg0.fields.rx_pcs_test_mode = 1;
            rx_pcs_test_cfg0.fields.rx_pcs_data_pattern_sel = 1;
            break;

        case la_mac_port::pcs_test_mode_e::PRBS31:
            tx_pcs_test_cfg0.fields.tx_pcs_test_mode = 2;
            rx_pcs_test_cfg0.fields.rx_pcs_test_mode = 2;
            break;

        case la_mac_port::pcs_test_mode_e::PRBS9:
            tx_pcs_test_cfg0.fields.tx_pcs_test_mode = 3;
            rx_pcs_test_cfg0.fields.rx_pcs_test_mode = 3;
            break;

        default:
            return LA_STATUS_EUNKNOWN;
        }
    }

    la_status stat;
    for (size_t i = 0; i < m_mac_lanes_count; i++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_pcs_test_cfg0)[m_serdes_index_in_mac_pool + i],
                                                     tx_pcs_test_cfg0);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_pcs_test_cfg0)[m_serdes_index_in_mac_pool + i],
                                                     rx_pcs_test_cfg0);
        return_on_error(stat);
    }

    // Update Rx/TxCfg0 - update BypassScr
    stat = update_general_config();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::configure_pma_test_mode()
{
    mac_pool8_tx_pma_test_cfg0_register tx_pma_test_cfg0;
    mac_pool8_rx_pma_test_cfg0_register rx_pma_test_cfg0;

    bzero(&tx_pma_test_cfg0, mac_pool8_tx_pma_test_cfg0_register::SIZE);
    bzero(&rx_pma_test_cfg0, mac_pool8_rx_pma_test_cfg0_register::SIZE);

    int pma_enable = (m_pma_test_mode != la_mac_port::pma_test_mode_e::NONE);
    tx_pma_test_cfg0.fields.tx_pma_test_en = pma_enable;
    rx_pma_test_cfg0.fields.rx_pma_test_en = pma_enable;

    tx_pma_test_cfg0.fields.tx_pma_test_mode = pma_test_mode_hw_code[(size_t)m_pma_test_mode];
    rx_pma_test_cfg0.fields.rx_pma_test_mode = pma_test_mode_hw_code[(size_t)m_pma_test_mode];

    la_status stat;
    for (size_t i = 0; i < m_serdes_count; i++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_pma_test_cfg0)[m_serdes_index_in_mac_pool + i],
                                                     tx_pma_test_cfg0);
        return_on_error(stat);

        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_pma_test_cfg0)[m_serdes_index_in_mac_pool + i],
                                                     rx_pma_test_cfg0);
        return_on_error(stat);
    }
    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::toggle_pdif_reset()
{
    la_status status;
    // PDIF reset register
    // This is "external" register, writing 1 to port reset the register and HW clearing this bit immediately.
    bit_vector pdif_reset_reg(0, pdoq_fdoq_pdif_fifo_reset_port_register::SIZE_IN_BITS);

    size_t port_num = m_ifg_id * (MAX_NUM_SERDES_PER_IFG + NUM_INTERNAL_IFCS_PER_IFG) + m_serdes_base_id;

    // Reset PDIF fifo.
    pdif_reset_reg.set_bit(port_num, 1);

    status = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[m_slice_id]->pdoq->fdoq->pdif_fifo_reset_port,
                                                   pdif_reset_reg);
    return_on_error(status);

    log_debug(MAC_PORT,
              "%s %s: toggled PDIF reset, bit %zd in FDOQ pdif_fifo_reset_port register.",
              __func__,
              this->to_string().c_str(),
              port_num);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_mac_status(la_mac_port::mac_status& out_mac_status) const
{
    if (m_device->is_simulated_device()) {
        return read_mac_status_simulated(out_mac_status);
    } else {
        return read_mac_status_hw(out_mac_status);
    }
}

la_status
gibraltar_mac_pool::read_mac_status_simulated(la_mac_port::mac_status& out_mac_status) const
{
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            out_mac_status.block_lock[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane] = true;
            out_mac_status.am_lock[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane] = true;
        }
    }

    // Take the MAC properties from the first register
    out_mac_status.link_state = true;
    out_mac_status.pcs_status = true;
    out_mac_status.high_ber = false;
    out_mac_status.degraded_ser = false;
    out_mac_status.remote_degraded_ser = false;
    out_mac_status.link_fault_status = la_mac_port::fault_state_e::NO_FAULT;

    if (m_fec_mode == la_mac_port::fec_mode_e::KR) {
        for (size_t serdes_lane = 0; serdes_lane < m_serdes_count; serdes_lane++) {
            out_mac_status.kr_fec_lock[serdes_lane] = true;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_mac_status_hw(la_mac_port::mac_status& out_mac_status) const
{
    mac_pool8_rx_status_register_register reg[8];

    // First read all data and then collect to one structure
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        la_status status;
        status = m_device->m_ll_device->read_register((*m_mac_pool_regs.rx_status_register)[m_serdes_index_in_mac_pool + mac_lane],
                                                      reg[mac_lane]);
        return_on_error(status);

        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            out_mac_status.block_lock[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane]
                = (reg[mac_lane].fields.rx_66b_w_lock_block_lock >> pcs_lane) & 1;
            out_mac_status.am_lock[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane]
                = (reg[mac_lane].fields.rx_am_lock >> pcs_lane) & 1;
        }
    }

    // Take the MAC properties from the first register
    out_mac_status.link_state = reg[0].fields.rx_link_status;
    out_mac_status.pcs_status = reg[0].fields.rx_pcs_status;
    out_mac_status.high_ber = reg[0].fields.rx_high_ber;
    out_mac_status.degraded_ser = reg[0].fields.rx_degraded_ser_status;
    out_mac_status.remote_degraded_ser = reg[0].fields.rx_rm_degraded_ser_status;
    out_mac_status.link_fault_status = (la_mac_port::fault_state_e)reg[0].fields.rx_link_fault_fsm_status;

    if (m_fec_mode == la_mac_port::fec_mode_e::KR) {
        // Collect KR FEC lock status from separate register
        mac_pool8_rx_krf_status_register kr_reg;

        for (size_t serdes_lane = 0; serdes_lane < m_serdes_count; serdes_lane++) {
            la_status status;
            status = m_device->m_ll_device->read_register(
                (*m_mac_pool_regs.rx_krf_status)[m_serdes_index_in_mac_pool + serdes_lane], kr_reg);
            return_on_error(status);

            out_mac_status.kr_fec_lock[serdes_lane] = kr_reg.fields.fec_block_lock;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_mac_link_down_interrupt(link_down_interrupt_info& val_out) const
{
    if (m_device->is_simulated_device()) {
        return read_mac_link_down_interrupt_simulated(val_out);
    } else {
        return read_mac_link_down_interrupt_hw(val_out);
    }
}

la_status
gibraltar_mac_pool::read_mac_link_down_interrupt_simulated(link_down_interrupt_info& val_out) const
{
    val_out.rx_link_status_down = false;
    val_out.rx_pcs_link_status_down = false;
    val_out.rx_pcs_align_status_down = false;
    val_out.rx_pcs_hi_ber_up = false;
    val_out.rsf_rx_high_ser_interrupt_register = false;
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        val_out.rx_pma_sig_ok_loss_interrupt_register[serdes] = false;
    }

    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            val_out.rx_deskew_fifo_overflow[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane] = false;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_mac_link_down_interrupt_hw(link_down_interrupt_info& val_out) const
{
    ll_device_sptr ldev = m_device->m_ll_device;
    bit_vector bv;
    la_status rc;
    uint64_t mask = get_mac_pool_interrupt_mask();

    struct {
        lld_register_scptr reg;
        bool* val_out;
    } reg_vals[] = {
        {m_mac_pool_interrupt_regs.rx_link_status_down, &val_out.rx_link_status_down},
        {m_mac_pool_interrupt_regs.rx_pcs_link_status_down, &val_out.rx_pcs_link_status_down},
        {m_mac_pool_interrupt_regs.rx_pcs_align_status_down, &val_out.rx_pcs_align_status_down},
        {m_mac_pool_interrupt_regs.rx_pcs_hi_ber_up, &val_out.rx_pcs_hi_ber_up},
        {m_mac_pool_interrupt_regs.rsf_rx_high_ser_interrupt_register, &val_out.rsf_rx_high_ser_interrupt_register},
    };

    for (auto reg_val : reg_vals) {
        rc = ldev->read_register(*reg_val.reg, bv);
        if (rc) {
            return rc;
        }
        *reg_val.val_out = (bv.get_value() & mask) != 0;
    }

    mac_pool8_rx_status_register_register reg_remote;

    rc = ldev->read_register((*m_mac_pool_regs.rx_status_register)[m_serdes_index_in_mac_pool], reg_remote);
    return_on_error(rc);

    la_mac_port::fault_state_e link_fault_status = (la_mac_port::fault_state_e)reg_remote.fields.rx_link_fault_fsm_status;
    val_out.rx_remote_link_status_down = link_fault_status == la_mac_port::fault_state_e::REMOTE_FAULT;

    // Special handling for rx_pma_sig_ok_loss_interrupt
    bzero(val_out.rx_pma_sig_ok_loss_interrupt_register, sizeof(val_out.rx_pma_sig_ok_loss_interrupt_register));

    rc = ldev->read_register(*m_mac_pool_interrupt_regs.rx_pma_sig_ok_loss_interrupt_register, bv);
    if (rc) {
        return rc;
    }

    uint64_t val = bv.get_value() & mask;
    for (size_t i = 0; i < m_mac_lanes_count; ++i) {
        val_out.rx_pma_sig_ok_loss_interrupt_register[i] = bit_utils::get_bit(val, m_serdes_index_in_mac_pool + i);
    }

    // Special handling for rx_desk_fif_ovf_interrupt
    bzero(val_out.rx_deskew_fifo_overflow, sizeof(val_out.rx_deskew_fifo_overflow));

    // First read all data and then collect to one structure
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        rc = ldev->read_register(
            *m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[m_serdes_index_in_mac_pool + mac_lane], bv);
        if (rc) {
            return rc;
        }

        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            val_out.rx_deskew_fifo_overflow[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane] = bv.bit(pcs_lane);
        }
    }

    return rc;
}

la_status
gibraltar_mac_pool::clear_mac_link_down_interrupt() const
{
    uint64_t mask = get_mac_pool_interrupt_mask();
    size_t width = m_mac_pool_interrupt_regs.rx_link_status_down->get_desc()->width_in_bits;
    bit_vector val(mask, width);

    lld_register_value_list_t reg_val_list;

    reg_val_list.push_back({m_mac_pool_interrupt_regs.rx_pcs_link_status_down, val});
    reg_val_list.push_back({m_mac_pool_interrupt_regs.rx_pcs_align_status_down, val});
    reg_val_list.push_back({m_mac_pool_interrupt_regs.rx_pcs_hi_ber_up, val});
    reg_val_list.push_back({m_mac_pool_interrupt_regs.rx_pma_sig_ok_loss_interrupt_register, val});
    reg_val_list.push_back({m_mac_pool_interrupt_regs.rsf_rx_high_ser_interrupt_register, val});
    reg_val_list.push_back({m_mac_pool_interrupt_regs.rx_link_status_down, val});

    la_status rc = lld_write_register_list(m_device->m_ll_device, reg_val_list);

    clear_rx_deskew_fifo_overflow_interrupt();

    return rc;
}

la_status
gibraltar_mac_pool::set_mac_link_down_interrupt_mask(bool enable_interrupt) const
{
    // CONFIG register, read_register is cheap
    bit_vector bv;
    la_status rc = m_device->m_ll_device->read_register(*m_mac_pool_interrupt_regs.rx_link_status_down_mask, bv);

    uint64_t mask = get_mac_pool_interrupt_mask();
    bit_vector mask_bv(mask);

    // Mask is active low, interrupt enabled == 0, interrupt disabled == 1
    if (enable_interrupt) {
        bv = bv & (~mask_bv);
    } else {
        bv = bv | mask_bv;
    }

    rc = m_device->m_ll_device->write_register(*m_mac_pool_interrupt_regs.rx_link_status_down_mask, bv);
    rc = m_device->m_ll_device->write_register(*m_mac_pool_interrupt_regs.rx_pcs_link_status_down_mask, bv);

    return rc;
}

la_status
gibraltar_mac_pool::clear_rx_deskew_fifo_overflow_interrupt() const
{
    la_status rc;
    ll_device_sptr ldev = m_device->m_ll_device;
    bit_vector pcs_bv(0);

    // Clear rx_desk_fif_ovf_interrupt
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        rc = ldev->read_register(
            *m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[m_serdes_index_in_mac_pool + mac_lane], pcs_bv);
        if (rc) {
            return rc;
        }

        if (!pcs_bv.is_zero()) {
            rc = ldev->write_register(
                *m_mac_pool_interrupt_regs.rx_desk_fif_ovf_interrupt_register[m_serdes_index_in_mac_pool + mac_lane], pcs_bv);
            if (rc) {
                return rc;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

void
gibraltar_mac_pool::populate_link_error_info(const interrupt_tree::cause_bits& link_error_bits,
                                             link_error_interrupt_info& val_out) const
{
    std::map<lld_register_scptr, bool*, lld_register_scptr_ops> reg_vals{
        {m_mac_pool_interrupt_regs.rx_code_err_interrupt_register, &val_out.rx_code_error},
        {m_mac_pool_interrupt_regs.rx_crc_err_interrupt_register, &val_out.rx_crc_error},
        {m_mac_pool_interrupt_regs.rx_invert_crc_err_interrupt_register, &val_out.rx_invert_crc_error},
        {m_mac_pool_interrupt_regs.rx_oversize_err_interrupt_register, &val_out.rx_oversize_error},
        {m_mac_pool_interrupt_regs.rx_undersize_err_interrupt_register, &val_out.rx_undersize_error},
        {m_mac_pool_interrupt_regs.tx_crc_err_interrupt_register, &val_out.tx_crc_error},
        {m_mac_pool_interrupt_regs.tx_underrun_err_interrupt_register, &val_out.tx_underrun_error},
        {m_mac_pool_interrupt_regs.tx_missing_eop_err_interrupt_register, &val_out.tx_missing_eop_error},
        {m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register, &val_out.rsf_rx_degraded_ser},
        {m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register, &val_out.rsf_rx_remote_degraded_ser},
        {m_mac_pool_interrupt_regs.device_time_fif_ne_interrupt_register, &val_out.device_time_fifo_not_empty},
        {m_mac_pool_interrupt_regs.device_time_override_interrupt_register, &val_out.device_time_override},
    };

    for (const auto link_error_bit : link_error_bits) {
        lld_register_scptr interrupt_reg = link_error_bit->parent->status;

        auto it = reg_vals.find(interrupt_reg);
        // If interrupt register matches to one of the link-error registers in the map, set the corresponding field in val_out
        // Otherwise - invoke ifgb_handler to check of the interrupt register corresponds to ptp_time_stamp_error
        if (it != reg_vals.end()) {
            *it->second = true;
        } else {
            m_device->m_ifg_handlers[m_slice_id][m_ifg_id]->populate_link_error_info(
                m_serdes_base_id, m_serdes_count, interrupt_reg, link_error_bit->bit_i, val_out);
        }
    }
}

la_status
gibraltar_mac_pool::set_mac_link_error_interrupt_mask(bool enable_interrupt) const
{
    std::vector<lld_register_scptr> regs = {
        m_mac_pool_interrupt_regs.rx_code_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.rx_crc_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.rx_invert_crc_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.rx_oversize_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.rx_undersize_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.tx_crc_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.tx_underrun_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.tx_missing_eop_err_interrupt_register_mask,
        m_mac_pool_interrupt_regs.device_time_fif_ne_interrupt_register_mask,
        m_mac_pool_interrupt_regs.device_time_override_interrupt_register_mask,
    };

    la_status rc = set_interrupt_mask(regs, enable_interrupt);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_delayed_mac_link_error_interrupt_mask(bool enable_interrupt) const
{
    std::vector<lld_register_scptr> regs = {
        m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register_mask,
        m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register_mask,
    };
    std::vector<lld_register_scptr> clear_degraded_ser_regs = {
        m_mac_pool_interrupt_regs.rsf_rx_degraded_ser_interrupt_register,
        m_mac_pool_interrupt_regs.rsf_rx_rm_degraded_ser_interrupt_register,
    };

    // check if user wants to enable
    bool mac_degraded_ser_en;
    m_device->get_bool_property(la_device_property_e::ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS, mac_degraded_ser_en);
    if (!mac_degraded_ser_en && enable_interrupt) {
        log_debug(HLD,
                  "%s : %s is disabled, will not enable.",
                  __func__,
                  silicon_one::to_string(la_device_property_e::ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS).c_str());
        return LA_STATUS_SUCCESS;
    }

    la_status rc = clear_interrupt(clear_degraded_ser_regs);
    return_on_error(rc);

    // enable degraded ser interrupts
    rc = set_interrupt_mask(regs, enable_interrupt);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_mac_pcs_lane_mapping(la_mac_port::mac_pcs_lane_mapping& out_mac_pcs_lane_mapping) const
{
    mac_pool8_rx_status_lane_mapping_register reg;
    bit_vector reg_bv;

    // First read all data and then collect to one structure
    for (size_t mac_lane = 0; mac_lane < m_mac_lanes_count; mac_lane++) {
        la_status status;
        status = m_device->m_ll_device->read_register(
            (*m_mac_pool_regs.rx_status_lane_mapping)[m_serdes_index_in_mac_pool + mac_lane], reg);
        return_on_error(status);

        reg_bv = reg;
        size_t field_width = reg.fields.RX_LANE_MAPPING0_WIDTH;
        for (size_t pcs_lane = 0; pcs_lane < m_pcs_lanes_per_mac_lane; pcs_lane++) {
            size_t lsb = field_width * pcs_lane;
            out_mac_pcs_lane_mapping.lane_map[mac_lane * m_pcs_lanes_per_mac_lane + pcs_lane]
                = (size_t)(reg_bv.bits(lsb + field_width - 1, lsb).get_value());
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_rs_fec_symbol_errors_counters(la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const
{
    return (read_rs_fec_symbol_errors_counters(true, out_sym_err_counters));
}

la_status
gibraltar_mac_pool::read_rs_fec_symbol_errors_counters(bool clear, la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const
{
    if (m_fec_mode == la_mac_port::fec_mode_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    if (m_fec_mode == la_mac_port::fec_mode_e::KR) {
        return LA_STATUS_EINVAL;
    }

    // Initialize symbol error counters
    for (size_t i = 0; i < la_mac_port_max_lanes_e::RS_FEC; i++) {
        out_sym_err_counters.lane_errors[i] = -1;
    }

    size_t fec_lanes_per_fec_engine = m_fec_engine_config.at(m_speed).fec_lane_per_engine;

    size_t fec_engines_count = m_fec_engine_config.at(m_speed).fec_engine_count;

    for (size_t fec_engines_index = 0; fec_engines_index < fec_engines_count; fec_engines_index++) {
        for (size_t fec_lane = 0; fec_lane < fec_lanes_per_fec_engine; fec_lane++) {

            mac_pool8_rx_symb_err_lane0_reg_register reg;
            la_status status;
            if (clear) {
                status = m_device->m_ll_device->read_register(
                    (*m_mac_pool_counters.rx_symb_err_lane_regs[fec_lane])[m_serdes_index_in_mac_pool + fec_engines_index], reg);
            } else {
                status = m_device->m_ll_device->peek_register(
                    (*m_mac_pool_counters.rx_symb_err_lane_regs[fec_lane])[m_serdes_index_in_mac_pool + fec_engines_index], reg);
            }
            return_on_error(status);

            out_sym_err_counters.lane_errors[RS_FEC_LANE_PER_PORT * fec_engines_index + fec_lane] = reg.fields.rx_symb_err_lane0;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_rs_fec_debug_counters(la_mac_port::rs_fec_debug_counters& out_debug_counters) const
{
    return read_rs_fec_debug_counters(true, out_debug_counters);
}

la_status
gibraltar_mac_pool::read_rs_fec_debug_counters(bool clear, la_mac_port::rs_fec_debug_counters& out_debug_counters) const
{
    if (m_fec_mode == la_mac_port::fec_mode_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    if (m_fec_mode == la_mac_port::fec_mode_e::KR) {
        return LA_STATUS_EINVAL;
    }

    mac_pool8_rx_rsf_dbg_cntrs_reg_register reg;

    la_status status;

    if (clear) {
        status = m_device->m_ll_device->read_register((*m_mac_pool_counters.rsf_debug)[m_serdes_index_in_mac_pool], reg);
    } else {
        status = m_device->m_ll_device->peek_register((*m_mac_pool_counters.rsf_debug)[m_serdes_index_in_mac_pool], reg);
    }
    return_on_error(status);

    out_debug_counters.codeword[0] = reg.fields.rx_cw_00_sym_cnt;
    out_debug_counters.codeword[1] = reg.fields.rx_cw_01_sym_cnt;
    out_debug_counters.codeword[2] = reg.fields.rx_cw_02_sym_cnt;
    out_debug_counters.codeword[3] = reg.fields.rx_cw_03_sym_cnt;
    out_debug_counters.codeword[4] = reg.fields.rx_cw_04_sym_cnt;
    out_debug_counters.codeword[5] = reg.fields.rx_cw_05_sym_cnt;
    out_debug_counters.codeword[6] = reg.fields.rx_cw_06_sym_cnt;
    out_debug_counters.codeword[7] = reg.fields.rx_cw_07_sym_cnt;
    out_debug_counters.codeword[8] = reg.fields.rx_cw_08_sym_cnt;
    out_debug_counters.codeword[9] = reg.fields.rx_cw_09_sym_cnt;
    out_debug_counters.codeword[10] = reg.fields.rx_cw_10_sym_cnt;
    out_debug_counters.codeword[11] = reg.fields.rx_cw_11_sym_cnt;
    out_debug_counters.codeword[12] = reg.fields.rx_cw_12_sym_cnt;
    out_debug_counters.codeword[13] = reg.fields.rx_cw_13_sym_cnt;
    out_debug_counters.codeword[14] = reg.fields.rx_cw_14_sym_cnt;
    out_debug_counters.codeword[15] = reg.fields.rx_cw_15_sym_cnt;
    out_debug_counters.codeword_uncorrectable = reg.fields.rx_cw_uncor_cnt;
    out_debug_counters.symbol_burst[0] = 0;
    out_debug_counters.symbol_burst[1] = 0;
    out_debug_counters.symbol_burst[2] = reg.fields.rx_2_sym_burst_cnt;
    out_debug_counters.symbol_burst[3] = reg.fields.rx_3_sym_burst_cnt;
    out_debug_counters.symbol_burst[4] = reg.fields.rx_4_sym_burst_cnt;
    out_debug_counters.symbol_burst[5] = reg.fields.rx_5_sym_burst_cnt;
    out_debug_counters.symbol_burst[6] = reg.fields.rx_6_sym_burst_cnt;

    la_uint64_t total_codewords = get_codewords_sum(out_debug_counters.codeword, array_size(out_debug_counters.codeword));

    if (total_codewords <= 0) {
        out_debug_counters.extrapolated_ber = -1;
        out_debug_counters.extrapolated_flr = -1;
        return LA_STATUS_SUCCESS;
    }

    la_uint64_t total_symbol_errors = get_symbol_errors_sum(out_debug_counters.codeword, array_size(out_debug_counters.codeword));

    la_uint64_t total_symbols = 0;

    if (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4) {
        total_symbols = total_codewords * RS_FEC_KR4_SYMBOLS_PER_CODEWORD;
    } else {
        // KP4 and KP4_FI FEC modes
        total_symbols = total_codewords * RS_FEC_KP4_SYMBOLS_PER_CODEWORD;
    }

    double extracted_ser = (double)total_symbol_errors / total_symbols;

    out_debug_counters.extrapolated_ber = 1 - pow(1 - extracted_ser, 0.1);
    calculate_flr(out_debug_counters.codeword, total_codewords, out_debug_counters.extrapolated_flr, out_debug_counters.flr_r);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_fec_counter_reg(la_mac_port::counter_e counter_type, lld_register_scptr& out_counter_reg) const
{
    switch (m_fec_mode) {
    case la_mac_port::fec_mode_e::NONE:
        return LA_STATUS_EINVAL;

    case la_mac_port::fec_mode_e::KR:
        if (counter_type == la_mac_port::counter_e::FEC_UNCORRECTABLE) {
            out_counter_reg = ((*m_mac_pool_counters.krf_uncor)[m_serdes_index_in_mac_pool]);
        } else {
            out_counter_reg = ((*m_mac_pool_counters.krf_cor)[m_serdes_index_in_mac_pool]);
        }
        break;

    case la_mac_port::fec_mode_e::RS_KR4:
    case la_mac_port::fec_mode_e::RS_KP4:
    case la_mac_port::fec_mode_e::RS_KP4_FI:
        if (counter_type == la_mac_port::counter_e::FEC_UNCORRECTABLE) {
            out_counter_reg = ((*m_mac_pool_counters.rsf_uncor)[m_serdes_index_in_mac_pool]);
        } else {
            out_counter_reg = ((*m_mac_pool_counters.rsf_cor)[m_serdes_index_in_mac_pool]);
        }
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_counter(la_mac_port::counter_e counter_type, size_t& out_counter) const
{
    return read_counter(true, counter_type, out_counter);
}

la_status
gibraltar_mac_pool::read_counter(bool clear, la_mac_port::counter_e counter_type, size_t& out_counter) const
{
    lld_register_scptr counter_reg = nullptr;
    la_status status;

    switch (counter_type) {
    case la_mac_port::counter_e::PCS_TEST_ERROR:
        counter_reg = ((*m_mac_pool_counters.pcs_test)[m_serdes_index_in_mac_pool]);
        break;

    case la_mac_port::counter_e::PCS_BLOCK_ERROR:
        counter_reg = ((*m_mac_pool_counters.rx_errored_blocks)[m_serdes_index_in_mac_pool]);
        break;

    case la_mac_port::counter_e::PCS_BER:
        counter_reg = ((*m_mac_pool_counters.rx_ber)[m_serdes_index_in_mac_pool]);
        break;

    case la_mac_port::counter_e::FEC_CORRECTABLE:
        status = get_fec_counter_reg(counter_type, counter_reg);
        return_on_error(status);

        break;

    case la_mac_port::counter_e::FEC_UNCORRECTABLE:
        status = get_fec_counter_reg(counter_type, counter_reg);
        return_on_error(status);

        break;
    }

    if (counter_reg == nullptr) {
        return LA_STATUS_EINVAL;
    }

    bit_vector tmp_bv;
    if (clear) {
        status = m_device->m_ll_device->read_register(*counter_reg, tmp_bv);
    } else {
        status = m_device->m_ll_device->peek_register(*counter_reg, tmp_bv);
    }
    return_on_error(status);

    out_counter = tmp_bv.get_value();

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_counter(la_mac_port::serdes_counter_e counter_type, la_uint_t serdes_idx, size_t& out_counter) const
{
    lld_register_scptr counter_reg = nullptr;

    size_t serdes_addr = m_serdes_index_in_mac_pool + serdes_idx;

    switch (counter_type) {
    case la_mac_port::serdes_counter_e::PMA_TEST_ERROR:
        counter_reg = ((*m_mac_pool_counters.pma_test)[serdes_addr]);
        break;

    case la_mac_port::serdes_counter_e::PMA_RX_READ:
        counter_reg = ((*m_mac_pool_counters.pma_read)[serdes_addr]);
        break;

    case la_mac_port::serdes_counter_e::PMA_TX_WRITE:
        counter_reg = ((*m_mac_pool_counters.pma_write)[serdes_addr]);
        break;
    }

    if (counter_reg == nullptr) {
        return LA_STATUS_EINVAL;
    }

    bit_vector tmp_bv;
    la_status status = m_device->m_ll_device->read_register(*counter_reg, tmp_bv);
    return_on_error(status);

    out_counter = tmp_bv.get_value();

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::clear_counters() const
{
    size_t dummy_counter;

    mac_pool8_rx_rsf_dbg_cntrs_reg_register reg;

    la_status status = m_device->m_ll_device->read_register((*m_mac_pool_counters.rsf_debug)[m_serdes_index_in_mac_pool], reg);
    return_on_error(status);

    if (m_fec_mode != la_mac_port::fec_mode_e::NONE && m_fec_mode != la_mac_port::fec_mode_e::KR) {
        la_mac_port::rs_fec_sym_err_counters dummy_fec_counter;

        status = read_rs_fec_symbol_errors_counters(true, dummy_fec_counter);
        return_on_error(status);
    }

    for (la_over_subscription_tc_t ostc = 0; ostc < la_mac_port::OSTC_TRAFFIC_CLASSES; ostc++) {
        status = read_ostc_counter(ostc, dummy_counter);
        return_on_error(status);
    }

    for (size_t counter_type = 0; counter_type <= (size_t)la_mac_port::counter_e::LAST; counter_type++) {

        status = read_counter(true, (la_mac_port::counter_e)counter_type, dummy_counter);
        return_on_error(status);
    }

    for (size_t serdes_counter = 0; serdes_counter <= (size_t)la_mac_port::serdes_counter_e::LAST; serdes_counter++) {
        for (la_uint_t serdes_idx = 0; serdes_idx < m_serdes_count; serdes_idx++) {
            status = read_counter((la_mac_port::serdes_counter_e)serdes_counter, serdes_idx, dummy_counter);

            return_on_error(status);
        }
    }

    la_mac_port::mib_counters dummy_mib_counters;
    status = read_mib_counters(true, dummy_mib_counters);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::read_pma_test_ber(la_mac_port::mac_pma_ber& out_mac_pma_ber) const
{
    la_status status = setup_counter_timer(true, COUNTER_TIMER_CYCLES);
    return_on_error(status);

    status = wait_counter_timer();
    return_on_error(status);

    status = setup_counter_timer(false, COUNTER_TIMER_CYCLES);
    return_on_error(status);

    for (size_t serdes_lane = 0; serdes_lane < m_serdes_count; serdes_lane++) {
        mac_pool8_rx_pma_test_counter_register error_counter;
        mac_pool8_rx_pma_rd_cnt_reg_register read_counter;

        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_lane].rx_source;

        // Read error count
        status = m_device->m_ll_device->read_register((*m_mac_pool_counters.pma_test)[m_serdes_index_in_mac_pool + serdes_lane],
                                                      error_counter);
        return_on_error(status);

        status = m_device->m_ll_device->read_register((*m_mac_pool_counters.pma_read)[get_serdes_index_in_mac_pool(rx_serdes)],
                                                      read_counter);
        return_on_error(status);
        out_mac_pma_ber.lane_ber[serdes_lane]
            = read_counter.fields.rx_async_fif_rd == 0
                  ? -1
                  : (float)error_counter.fields.rx_pma_test_errors_cnt / (PMA_WIDTH * read_counter.fields.rx_async_fif_rd);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::configure_ber_fsm()
{
    mac_pool8_rx_ber_fsm_cfg_register ber_fsm;

    // Below is the PCS High BER FSM configurations. The values are from HW team and depends on gibraltar clock.
    // There are two parts:
    // 1 - Period in clocks for the BER FSM timer: 10GE: 125us, 40GE: 1.25ms, 25GE: 2ms, 100GE: 500us (according to Eth standard)
    //     The main goal of BER FSM is to drop the link when the BER is high
    // 2 - Number of received invalid sync header to be received in a timer window for setting the high BER indication: 10GE: 16,
    //     25-100: 97, 200-:255

    switch (m_speed) {
    case la_mac_port::port_speed_e::E_10G:
        ber_fsm.fields.rx_max_ber_cnt_cfg = 16;
        break;
    case la_mac_port::port_speed_e::E_25G:
    case la_mac_port::port_speed_e::E_40G:
    case la_mac_port::port_speed_e::E_50G:
    case la_mac_port::port_speed_e::E_100G:
        ber_fsm.fields.rx_max_ber_cnt_cfg = 97;
        break;
    case la_mac_port::port_speed_e::E_200G:
    case la_mac_port::port_speed_e::E_400G:
        ber_fsm.fields.rx_max_ber_cnt_cfg = 255;
        break;
    case la_mac_port::port_speed_e::E_MGIG:
    case la_mac_port::port_speed_e::E_20G:
    case la_mac_port::port_speed_e::E_800G:
    case la_mac_port::port_speed_e::E_1200G:
    case la_mac_port::port_speed_e::E_1600G:
        return LA_STATUS_EINVAL;
    }

    switch (m_speed) {
    case la_mac_port::port_speed_e::E_10G:
    case la_mac_port::port_speed_e::E_25G:
    case la_mac_port::port_speed_e::E_40G:
    case la_mac_port::port_speed_e::E_50G:
    case la_mac_port::port_speed_e::E_100G:
        ber_fsm.fields.rx_ber_timer_period = (rx_ber_timer_period_config.at(m_speed)
                                              * ((float)m_device->m_device_frequency_int_khz / (float)DEFAULT_DEVICE_FREQUENCY));
        break;
    case la_mac_port::port_speed_e::E_200G:
    case la_mac_port::port_speed_e::E_400G:
        // BER timer isn't defined by IEEE for 200G and 400G. For these speeds the BER is handled within RS-FEC (mechanism called
        // degraded SER).
        // This actually will not drop the link (issue fixed by IEEE after we taped out). The workaround for this is when the error
        // rate is high
        // RS FEC will mark its output in a way that PCS hill trigger high BER FSM and the link will drop.
        // These given fixed numbers were verified.
        ber_fsm.fields.rx_ber_timer_period = rx_ber_timer_period_config.at(m_speed);
        break;
    case la_mac_port::port_speed_e::E_MGIG:
    case la_mac_port::port_speed_e::E_20G:
    case la_mac_port::port_speed_e::E_800G:
    case la_mac_port::port_speed_e::E_1200G:
    case la_mac_port::port_speed_e::E_1600G:
        return LA_STATUS_EINVAL;
    }

    la_status stat;
    for (size_t i = 0; i < m_serdes_count; i++) {
        stat = m_device->m_ll_device->write_register((*m_mac_pool_regs.rx_ber_fsm_cfg)[m_serdes_index_in_mac_pool + i], ber_fsm);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::configure_degraded_ser()
{
    mac_pool8_rsf_degraded_ser_cfg0_register rsf_degraded_ser_cfg0;
    mac_pool8_rx_high_ser_fsm_cfg_register rx_high_ser_fsm_cfg;

    lld_register_value_list_t reg_val_list;

    // Currently, we enable it only for 400G ports. Otherwise, we disable and set the values to default.
    bool enable_degraded_ser = false;

    if (m_speed == la_mac_port::port_speed_e::E_400G) {
        enable_degraded_ser = true;
    }

    rx_high_ser_fsm_cfg.fields.rx_high_ser_k_port0 = (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4) ? 6380 : 417;
    rx_high_ser_fsm_cfg.fields.rx_high_ser_k_port1 = rx_high_ser_fsm_cfg.fields.rx_high_ser_k_port0;
    rx_high_ser_fsm_cfg.fields.rx_high_ser_time_ms_port0 = 65;
    rx_high_ser_fsm_cfg.fields.rx_high_ser_time_ms_port1 = rx_high_ser_fsm_cfg.fields.rx_high_ser_time_ms_port0;
    rx_high_ser_fsm_cfg.fields.rx_high_ser_words_wind0 = 8191;
    rx_high_ser_fsm_cfg.fields.rx_high_ser_words_wind1 = rx_high_ser_fsm_cfg.fields.rx_high_ser_words_wind0;

    rsf_degraded_ser_cfg0.fields.rx_rsf_degraded_ser_en_port0 = enable_degraded_ser;
    rsf_degraded_ser_cfg0.fields.rx_rsf_degraded_ser_en_port1 = enable_degraded_ser;
    rsf_degraded_ser_cfg0.fields.rx_rsf_rm_degraded_ser_en_port0 = enable_degraded_ser;
    rsf_degraded_ser_cfg0.fields.rx_rsf_rm_degraded_ser_en_port1 = enable_degraded_ser;
    rsf_degraded_ser_cfg0.fields.rx_rsf_rm_degraded_ser_word_idx_port0 = enable_degraded_ser ? 7 : 4;
    rsf_degraded_ser_cfg0.fields.rx_rsf_rm_degraded_ser_word_idx_port1
        = rsf_degraded_ser_cfg0.fields.rx_rsf_rm_degraded_ser_word_idx_port0;
    rsf_degraded_ser_cfg0.fields.tx_rsf_degraded_ser_en_port0 = enable_degraded_ser;
    rsf_degraded_ser_cfg0.fields.tx_rsf_degraded_ser_en_port1 = enable_degraded_ser;

    size_t pair_count = (m_serdes_count + 1) / 2;
    for (size_t i = 0; i < pair_count; i++) {
        size_t pair_idx = m_serdes_index_in_mac_pool / 2 + i;
        reg_val_list.push_back({(*m_mac_pool_regs.rx_high_ser_fsm_cfg)[pair_idx], rx_high_ser_fsm_cfg});
        reg_val_list.push_back({(*m_mac_pool_regs.rsf_degraded_ser_cfg0)[pair_idx], rsf_degraded_ser_cfg0});
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::calculate_pma_max_burst(uint32_t& pma_max_burst)
{
    // When working in loopback in core clock the configuration is used to shape the traffic from the mac to
    // the RX buffers BW.
    if ((m_loopback_mode == la_mac_port::loopback_mode_e::PMA_CORE_CLK)
        || (m_loopback_mode == la_mac_port::loopback_mode_e::MII_CORE_CLK)) {
        float port_serdes_rate;
        if ((m_fec_mode == la_mac_port::fec_mode_e::RS_KP4) || (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI)) {
            port_serdes_rate = 53.125; // (68/64) * 50 Gbps
        } else {
            port_serdes_rate = 51.5625; // (66/64) * 50 Gbps
        }

        const size_t read_word_size = 60;
        float pma_shaper_target_rate = port_serdes_rate / ((float)read_word_size * m_device->m_device_frequency_float_ghz);
        // For the supported device frequencies of 1.0 GHz - 1.4 GHz, max value = 53.125 / 60*1.0 = 0.885
        // Min value = 51.5625 / 60*1.4 = 0.61. Shaper factor is calculated as pma_max_burst / pma_max_burst + 1
        // Shaper factor must be greater than the target rate, so possible values will be between 2/3 (0.66 > 0.61) and
        // 9/10 (0.9 > 0.885), meaning 2 <= pma_max_burst <= 9
        for (pma_max_burst = 2; pma_max_burst < 10; pma_max_burst++) {
            float shaper_factor = (float)pma_max_burst / (float)(pma_max_burst + 1.0);
            if (shaper_factor > pma_shaper_target_rate) {
                break;
            }
        }

        // Should be minimum 4 in the following configurations.
        if (((m_speed == la_mac_port::port_speed_e::E_200G) && (m_serdes_count == 8))
            || ((m_speed == la_mac_port::port_speed_e::E_100G) && (m_fec_mode == la_mac_port::fec_mode_e::NONE)
                && (m_serdes_count == 4))
            || ((m_speed == la_mac_port::port_speed_e::E_40G) && (m_serdes_count == 4))
            || ((m_speed == la_mac_port::port_speed_e::E_25G) && (m_fec_mode == la_mac_port::fec_mode_e::RS_KR4))) {
            if (pma_max_burst < 4) {
                pma_max_burst = 4;
            }
        }

        if ((m_fec_mode == la_mac_port::fec_mode_e::RS_KR4) && (m_serdes_count > 1)) {
            pma_max_burst = 0;
        }

        // In some modes an idle cycle is mandatory to allow zero padding of the frames towards the RS-FEC decoder logic.
        // When working in 400GE (RS-FEC KP4) there are 16 FEC lanes on which two interleaved frames of 5440b each are received.
        // The received block per FEC lane is of 5440b*2/16=680b long, which is 11.33 transactions of 60b.
        // This means that in every 12 clock cycles an idle must be present so the configuration needs to be 11.

    } else if (m_speed == la_mac_port::port_speed_e::E_400G) {
        pma_max_burst = 11;
        // In all other RS-FEC KP4 modes the calculation leads to a configuration of 22.
    } else if ((m_fec_mode == la_mac_port::fec_mode_e::RS_KP4) || (m_fec_mode == la_mac_port::fec_mode_e::RS_KP4_FI)) {
        pma_max_burst = 22;
    } else {
        pma_max_burst = 0; // Unlimited
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::setup_counter_timer(bool enable, size_t clock_cycles) const
{
    la_status status;
    mac_pool8_counter_timer_register counter_timer_reg;

    counter_timer_reg.fields.counter_timer_enable = enable;
    counter_timer_reg.fields.counter_timer_cycle = enable ? clock_cycles : 0;

    status = m_device->m_ll_device->write_register((*m_mac_pool_regs.counter_timer), counter_timer_reg);
    return_on_error(status);

    if (enable) {
        mac_pool8_counter_timer_trigger_reg_register trigger_reg;
        trigger_reg.fields.counter_timer_trigger = 1;
        status = m_device->m_ll_device->write_register((*m_mac_pool_regs.counter_timer_trigger_reg), trigger_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::wait_counter_timer() const
{
    if (m_device->is_simulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    mac_pool8_counter_timer_trigger_reg_register trigger_reg{{0}};
    size_t retry = 0;
    for (; retry < COUNTER_TIMER_MAX_POLL; ++retry) {
        std::this_thread::sleep_for(COUNTER_TIMER_POLL_INTERVAL_MILLISECONDS);
        la_status rc = m_device->m_ll_device->read_register((*m_mac_pool_regs.counter_timer_trigger_reg), trigger_reg);
        return_on_error(rc);
        if (!trigger_reg.fields.counter_timer_trigger) {
            return LA_STATUS_SUCCESS;
        }
    }

    log_err(MAC_PORT, "%s: timed out of %ld retries", __func__, retry);

    return LA_STATUS_EAGAIN;
}

bool
gibraltar_mac_pool::is_loopback_mode_supported(la_mac_port::loopback_mode_e mode)
{
    if (mode == la_mac_port::loopback_mode_e::INFO_MAC_CLK || mode == la_mac_port::loopback_mode_e::INFO_SRDS_CLK) {
        return false;
    }
    if (mode == la_mac_port::loopback_mode_e::SERDES || mode == la_mac_port::loopback_mode_e::PMA_SRDS_CLK
        || mode == la_mac_port::loopback_mode_e::PMA_CORE_CLK
        || mode == la_mac_port::loopback_mode_e::REMOTE_SERDES) {
        if (is_rx_lane_swapped()) {
            log_err(MAC_PORT,
                    "%s: %s loopback is not supported when Rx-Tx lanes are swapped outside the port",
                    this->to_string().c_str(),
                    silicon_one::to_string(mode).c_str());
            return false;
        }
    }

    return true;
}

la_status
gibraltar_mac_pool::post_anlt_complete(const std::unique_ptr<serdes_handler>& serdes_handler_ptr)
{
    // For GB, the o_tx_core_clk was interrupted after ANLT. Apply TX_PMA reset to reset PCS TX FIFOs
    // to bring back the clock.
    // No need to check for ASIC version because this code applies to GB only
    la_status stat = reset_tx_pma(true);
    return_on_error(stat);
    stat = reset_tx_pma(false);
    return_on_error(stat);
    // Recenter serdes FIFO and open up TX.
    stat = serdes_handler_ptr->recenter_serdes_tx_fifo();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::pre_tune_rx_pma_reset()
{
    la_device_revision_e device_rev = m_device->m_ll_device->get_device_revision();
    if (((device_rev == la_device_revision_e::GIBRALTAR_A0) && (!is_rx_lane_swapped() || (m_serdes_count >= 4)))
        || (device_rev == la_device_revision_e::GIBRALTAR_A1)
        || (device_rev == la_device_revision_e::GIBRALTAR_A2)) {
        log_xdebug(MAC_PORT, "%s: Apply RX_PMA Core reset.", __func__);
        // Reset RX core side
        la_status stat = reset_rx_pma(true);
        return_on_error(stat);
        stat = reset_rx_pma(false);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_xoff_timer_settings(la_uint8_t tc_bitmap, la_uint_t quanta)
{
    mac_pool8_tx_mac_fc_xoff_timer_register xoff_reg;

    bzero(&xoff_reg, mac_pool8_tx_mac_fc_xoff_timer_register::SIZE);

    xoff_reg.fields.tx_fc_xoff_en = tc_bitmap;
    xoff_reg.fields.tx_fc_xoff_timer = quanta;

    for (size_t serdes = m_serdes_index_in_mac_pool; serdes < m_serdes_index_in_mac_pool + m_serdes_count; serdes++) {
        la_status status;
        status = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_per_xoff_timer)[serdes], xoff_reg);
        return_on_error(status);

        status = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_xoff_timer)[serdes], xoff_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_xon_timer_settings(la_uint8_t tc_bitmap, la_uint_t quanta)
{
    mac_pool8_tx_mac_fc_xon_timer_register xon_reg;

    bzero(&xon_reg, mac_pool8_tx_mac_fc_xoff_timer_register::SIZE);

    xon_reg.fields.tx_fc_xon_en = tc_bitmap;
    xon_reg.fields.tx_fc_xon_timer = quanta;

    for (size_t serdes = m_serdes_index_in_mac_pool; serdes < m_serdes_index_in_mac_pool + m_serdes_count; serdes++) {
        la_status status;
        status = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_per_xon_timer)[serdes], xon_reg);
        return_on_error(status);

        status = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_fc_xon_timer)[serdes], xon_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::set_control_tx_mac_src(la_mac_addr_t mac_addr)
{
    for (size_t serdes = m_serdes_index_in_mac_pool; serdes < m_serdes_index_in_mac_pool + m_serdes_count; serdes++) {
        gibraltar::mac_pool8_tx_mac_ctrl_sa_register reg;

        reg.fields.tx_mac_sa = mac_addr.flat;

        la_status status = m_device->m_ll_device->write_register((*m_mac_pool_regs.tx_mac_ctrl_sa)[serdes], reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_mac_pool::get_control_tx_mac_src(la_mac_addr_t& out_mac_addr) const
{
    gibraltar::mac_pool8_tx_mac_ctrl_sa_register reg;

    la_status status = m_device->m_ll_device->read_register((*m_mac_pool_regs.tx_mac_ctrl_sa)[m_serdes_index_in_mac_pool], reg);
    return_on_error(status);

    out_mac_addr.flat = reg.fields.tx_mac_sa;

    return LA_STATUS_SUCCESS;
}
} // namespace silicon_one
