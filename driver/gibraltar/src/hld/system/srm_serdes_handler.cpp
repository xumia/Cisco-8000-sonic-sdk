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

// SRM headers
#include "srm/srm_api.h"
#include "srm/srm_rules.h"
#include "srm/srm_serdes_address.h"

// SDK headers
#include "common/logger.h"
#include "reconnect_handler.h"
#include "serdes_device_handler.h"
#include "srm_serdes_device_handler.h"
#include "srm_serdes_handler.h"
#include "system/la_device_impl.h"

#include <cmath>
#include <iomanip>
#include <jansson.h>
#include <pthread.h>
#include <set>
#include <unordered_map>

using namespace std;

namespace silicon_one
{

struct serdes_config_data {
    e_srm_baud_rates baud_rate;
    e_srm_subrate_ratio subrate_ratio;
    bool pam4_enable;
};

enum {
    SRM_FW_DWLD_TIMEOUT_MS = 0,
    SRM_NUM_DIRECTIONS = 2,
    SRM_HIST_DATA_SIZE = 160,
    SRM_TX_READY_RETRY = 100,
    SRM_TX_READY_SLEEP_MS = 1,
    SRM_PGA_GAIN_MASK = 0x1FF,
    SRM_AFE_TRIM_MASK = 0x1F,
    SRM_MAX_SRM_PER_SLICE = 0x1f,
    SRM_TXRX_CHANNEL_OFFSET = 0x800,
    SRM_RX_TO_TX_OFFSET = 0x1f00,
    ONE_SEC = 1000,
    SRM_AN_AN_PAUSE_ABILITY = 100,
    SRM_AN_AN_REMOTE_FAULT = 100,
    SRM_AN_RETRY_THRESHOLD = 10,
    SRM_LT_NRZ_TARGET_SNR = 24700,
    SRM_LT_PAM4_TARGET_SNR = 24700,
    SRM_LT_RETRY_THRESHOLD = 10,
    SRM_RX_DSP_PGA_HIGH_GAIN_STATUS_ADDRESS = 0x2884,
    SRM_RX_DSP_SIGNAL_DETECT_CODE_CFG_ADDRESS = 0x2830,
    SRM_RX_DSP_SIGNAL_DETECT_CODE_THRESHOLD_CFG_ADDRESS = 0x2831,
    SRM_RX_SDT_CODE_FALL_SHIFT = 5,
    SRM_RX_SDT_CODE_MASK = 0x1f,
    DEFAULT_INNER_EYE1 = 1000,
    DEFAULT_INNER_EYE2 = 2000,
    DEFAULT_AUTO_CTLE_CODE = 0x7F,
    DEFAULT_ANLT_AUTO_RX_PRECODE_THRESHOLD = 32,
    DISABLE_ANLT_AUTO_RX_PRECODE_THRESHOLD = 0xFF,
    SRM_TX_TXD_FIFO_CFG_REG = 0x4803,
    RECENTER_FIFO_B = (1 << 9),
    RECENTER_FIFO_A = (1 << 8),
    NUMBER_OF_TIMESTAMP_COPY = 4, // Number fo rotating timestamp buffers
    TX_FIR_PRE_TIMESTAMP_ENTRY = 28,
    TX_FIR_POST_TIMESTAMP_ENTRY = 30,
    SRM_RX_SPARE9_NUM_ENTRY = 5,
    SRM_TX_SPARE9_NUM_ENTRY = 23,
    SRM_TX_SPARE9_LAST_VALID_STATE = 20,
    SRM_TX_SPARE9_INVALID_STATE_ENTRY = 22,
    DIE_SLICE_IFG_MASK = 0xFF00,
    SRM_PLL_LOCK_WAIT = 1,
    SRM_PLL_LOCK_WAIT_LOOP = 2000,
    GB_SERDES_KP_KF_10G = 0x74, // For 10G control path
    GB_SERDES_KP_KF_DEFAULT = 0x96,
    SRM_KP_KF_CFG_ENABLE = 0x8000,
    SRM_CL136_PRESET_1_MODE = 1,
    SRM_CL136_PRESET_2_MODE = 2,
    SRM_CL136_PRESET_3_MODE = 3,
};

typedef std::unordered_map<size_t, serdes_config_data> serdes_speed_to_divider_t;

static const serdes_speed_to_divider_t s_serdes_speed_to_divider = {
    serdes_speed_to_divider_t::value_type(10, {SRM_BAUD_RATE_20p625G, SRM_SUBRATE_DIV_2, false}),
    serdes_speed_to_divider_t::value_type(20, {SRM_BAUD_RATE_20p625G, SRM_SUBRATE_BYPASS, false}),
    serdes_speed_to_divider_t::value_type(25, {SRM_BAUD_RATE_25p78125G, SRM_SUBRATE_BYPASS, false}),
    serdes_speed_to_divider_t::value_type(26, {SRM_BAUD_RATE_26p5625G, SRM_SUBRATE_BYPASS, false}),
    serdes_speed_to_divider_t::value_type(51, {SRM_BAUD_RATE_25p78125G, SRM_SUBRATE_BYPASS, true}),
    serdes_speed_to_divider_t::value_type(53, {SRM_BAUD_RATE_26p5625G, SRM_SUBRATE_BYPASS, true}),
};

struct serdes_test_mode_e_hasher {
    std::size_t operator()(const la_mac_port::serdes_test_mode_e& mode) const
    {
        return (std::hash<size_t>()((size_t)mode));
    }
};

struct serdes_test_mode_cfg {
    e_srm_prbs_pat prbs_pattern;
    e_srm_prbs_pat_mode pattern_mode;
};

const std::unordered_map<la_mac_port::serdes_test_mode_e, serdes_test_mode_cfg, serdes_test_mode_e_hasher> serdes_test_mode_data
    = {{
        {la_mac_port::serdes_test_mode_e::NONE, {SRM_PAT_NONE, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS7, {SRM_PAT_PRBS7, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS9_4, {SRM_PAT_PRBS9_4, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS9, {SRM_PAT_PRBS9_5, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS11, {SRM_PAT_PRBS11, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS13, {SRM_PAT_PRBS13, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS15, {SRM_PAT_PRBS15, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS16, {SRM_PAT_PRBS16, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS23, {SRM_PAT_PRBS23, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS31, {SRM_PAT_PRBS31, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::PRBS58, {SRM_PAT_PRBS58, SRM_PRBS_PATTERN_PRBS}},
        {la_mac_port::serdes_test_mode_e::JP03B, {SRM_PAT_NONE, SRM_PRBS_PATTERN_JP083B}},
        {la_mac_port::serdes_test_mode_e::PRBS_LIN, {SRM_PAT_NONE, SRM_PRBS_PATTERN_LIN}},
        {la_mac_port::serdes_test_mode_e::PRBS_CJT, {SRM_PAT_NONE, SRM_PRBS_PATTERN_CJT}},
        {la_mac_port::serdes_test_mode_e::SSPRQ, {SRM_PAT_NONE, SRM_PRBS_PATTERN_SSPRQ}},
    }};

// Use this table to get the serdes number to program ANLT rules for AN to work.
// *TODO*
typedef std::unordered_map<la_uint_t, la_uint_t> die_number_t;
static const die_number_t s_die_num
    = {die_number_t::value_type(0x0000, 0),   die_number_t::value_type(0x0100, 1),   die_number_t::value_type(0x0200, 2),
       die_number_t::value_type(0x0300, 3),   die_number_t::value_type(0x0400, 4),   die_number_t::value_type(0x0500, 5),
       die_number_t::value_type(0x0600, 6),   die_number_t::value_type(0x0700, 7),   die_number_t::value_type(0x0800, 8),
       die_number_t::value_type(0x0900, 9),   die_number_t::value_type(0x0a00, 10),  die_number_t::value_type(0x0b00, 11),
       die_number_t::value_type(0x1000, 12),  die_number_t::value_type(0x1100, 13),  die_number_t::value_type(0x1200, 14),
       die_number_t::value_type(0x1300, 15),  die_number_t::value_type(0x1400, 16),  die_number_t::value_type(0x1500, 17),
       die_number_t::value_type(0x1600, 18),  die_number_t::value_type(0x1700, 19),  die_number_t::value_type(0x1800, 20),
       die_number_t::value_type(0x1900, 21),  die_number_t::value_type(0x1a00, 22),  die_number_t::value_type(0x1b00, 23),
       die_number_t::value_type(0x2000, 24),  die_number_t::value_type(0x2100, 25),  die_number_t::value_type(0x2200, 26),
       die_number_t::value_type(0x2300, 27),  die_number_t::value_type(0x2400, 28),  die_number_t::value_type(0x2500, 29),
       die_number_t::value_type(0x2600, 30),  die_number_t::value_type(0x2700, 31),  die_number_t::value_type(0x2800, 32),
       die_number_t::value_type(0x2900, 33),  die_number_t::value_type(0x2a00, 34),  die_number_t::value_type(0x2b00, 35),
       die_number_t::value_type(0x3000, 36),  die_number_t::value_type(0x3100, 37),  die_number_t::value_type(0x3200, 38),
       die_number_t::value_type(0x3300, 39),  die_number_t::value_type(0x3400, 40),  die_number_t::value_type(0x3500, 41),
       die_number_t::value_type(0x3600, 42),  die_number_t::value_type(0x3700, 43),  die_number_t::value_type(0x4000, 44),
       die_number_t::value_type(0x4100, 45),  die_number_t::value_type(0x4200, 46),  die_number_t::value_type(0x4300, 47),
       die_number_t::value_type(0x4400, 48),  die_number_t::value_type(0x4500, 49),  die_number_t::value_type(0x4600, 50),
       die_number_t::value_type(0x4700, 51),  die_number_t::value_type(0x5000, 52),  die_number_t::value_type(0x5100, 53),
       die_number_t::value_type(0x5200, 54),  die_number_t::value_type(0x5300, 55),  die_number_t::value_type(0x5400, 56),
       die_number_t::value_type(0x5500, 57),  die_number_t::value_type(0x5600, 58),  die_number_t::value_type(0x5700, 59),
       die_number_t::value_type(0x5800, 60),  die_number_t::value_type(0x5900, 61),  die_number_t::value_type(0x5a00, 62),
       die_number_t::value_type(0x5b00, 63),  die_number_t::value_type(0x6000, 64),  die_number_t::value_type(0x6100, 65),
       die_number_t::value_type(0x6200, 66),  die_number_t::value_type(0x6300, 67),  die_number_t::value_type(0x6400, 68),
       die_number_t::value_type(0x6500, 69),  die_number_t::value_type(0x6600, 70),  die_number_t::value_type(0x6700, 71),
       die_number_t::value_type(0x6800, 72),  die_number_t::value_type(0x6900, 73),  die_number_t::value_type(0x6a00, 74),
       die_number_t::value_type(0x6b00, 75),  die_number_t::value_type(0x7000, 76),  die_number_t::value_type(0x7100, 77),
       die_number_t::value_type(0x7200, 78),  die_number_t::value_type(0x7300, 79),  die_number_t::value_type(0x7400, 80),
       die_number_t::value_type(0x7500, 81),  die_number_t::value_type(0x7600, 82),  die_number_t::value_type(0x7700, 83),
       die_number_t::value_type(0x8000, 84),  die_number_t::value_type(0x8100, 85),  die_number_t::value_type(0x8200, 86),
       die_number_t::value_type(0x8300, 87),  die_number_t::value_type(0x8400, 88),  die_number_t::value_type(0x8500, 89),
       die_number_t::value_type(0x8600, 90),  die_number_t::value_type(0x8700, 91),  die_number_t::value_type(0x9000, 92),
       die_number_t::value_type(0x9100, 93),  die_number_t::value_type(0x9200, 94),  die_number_t::value_type(0x9300, 95),
       die_number_t::value_type(0x9400, 96),  die_number_t::value_type(0x9500, 97),  die_number_t::value_type(0x9600, 98),
       die_number_t::value_type(0x9700, 99),  die_number_t::value_type(0x9800, 100), die_number_t::value_type(0x9900, 101),
       die_number_t::value_type(0x9a00, 102), die_number_t::value_type(0x9b00, 103), die_number_t::value_type(0xa000, 104),
       die_number_t::value_type(0xa100, 105), die_number_t::value_type(0xa200, 106), die_number_t::value_type(0xa300, 107),
       die_number_t::value_type(0xa400, 108), die_number_t::value_type(0xa500, 109), die_number_t::value_type(0xa600, 110),
       die_number_t::value_type(0xa700, 111), die_number_t::value_type(0xa800, 112), die_number_t::value_type(0xa900, 113),
       die_number_t::value_type(0xaa00, 114), die_number_t::value_type(0xab00, 115), die_number_t::value_type(0xb000, 116),
       die_number_t::value_type(0xb100, 117), die_number_t::value_type(0xb200, 118), die_number_t::value_type(0xb300, 119),
       die_number_t::value_type(0xb400, 120), die_number_t::value_type(0xb500, 121), die_number_t::value_type(0xb600, 122),
       die_number_t::value_type(0xb700, 123), die_number_t::value_type(0xb800, 124), die_number_t::value_type(0xb900, 125),
       die_number_t::value_type(0xba00, 126), die_number_t::value_type(0xbb00, 127)};

// the name and index are from srm_anlt_timestamp_print()
typedef struct {
    std::string ts_name;
    la_uint_t ts_index;
} timestamp_struct;
static std::list<timestamp_struct> timestamp_list = {{"lifetime", 0},       {"algo", 1},
                                                     {"trial", 2},          {"hcd", 3},
                                                     {"reconfig", 4},       {"pll_up", 5},
                                                     {"tx_up", 6},          {"rx_up", 7},
                                                     {"ctle_auto", 8},      {"ctle_start", 9},
                                                     {"ctle_dsp_gain", 10}, {"ctle_done", 11},
                                                     {"ctle_value", 12},    {"pset_req", 13},
                                                     {"frame_lock", 14},    {"pset_ack", 15},
                                                     {"cmd1_req", 16},      {"cmd1_ack", 17},
                                                     {"num_step", 18},      {"lt_term_reason", 19},
                                                     {"train_fom", 20},     {"rr_transmitted", 21},
                                                     {"rr_received", 22},   {"train_done", 23},
                                                     {"tx_open", 24},       {"rx_open", 25},
                                                     {"rx_slap", 26},       {"final_snr", 27},
                                                     {"tx_fir_pre", 28},    {"tx_fir_main", 29},
                                                     {"tx_fir_post", 30},   {"restart", 31},
                                                     {"an_to_lt_los", 32},  {"an_to_lt_sig", 33},
                                                     {"an_term_reason", 34}};

struct sdt_param_info {
    la_mac_port::serdes_param_e sdk_param;
    e_srm_rx_param srm_param;
};

static std::list<sdt_param_info> sdt_params_list = {{la_mac_port::serdes_param_e::RX_SDT_CODE_FALL, SRM_RX_PARAM_SDT_CODE_FALL},
                                                    {la_mac_port::serdes_param_e::RX_SDT_CODE_RISE, SRM_RX_PARAM_SDT_CODE_RISE},
                                                    {la_mac_port::serdes_param_e::RX_SDT_CODE_TH, SRM_RX_PARAM_SDT_CODE_TH},
                                                    {la_mac_port::serdes_param_e::RX_SDT_BLOCK_CNT, SRM_RX_PARAM_SDT_BLOCK_CNT}};

la_status
srm_serdes_handler::get_serdes_addr(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_serdes_addr)
{
    if (serdes_idx >= m_serdes_count) {
        log_err(SERDES, "SerDes %d/%d/%d not a valid index for this port.", m_slice_id, m_ifg_id, serdes_idx);
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status stat = m_device->get_serdes_addr(m_slice_id, m_ifg_id, m_serdes_base_id + serdes_idx, serdes_dir, out_serdes_addr);

    return stat;
}

la_status
srm_serdes_handler::get_serdes_channel(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_channel)
{
    la_uint_t serdes_lane;
    if (serdes_dir == la_serdes_direction_e::RX) {
        serdes_lane = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source;
    } else {
        serdes_lane = m_serdes_base_id + serdes_idx;
    }

    out_channel = serdes_lane % 2;

    return LA_STATUS_SUCCESS;
}

srm_serdes_handler::srm_serdes_handler(const la_device_impl_wptr& device,
                                       const srm_serdes_device_handler_wptr& serdes_device_handler,
                                       la_slice_id_t slice_id,
                                       la_ifg_id_t ifg_id,
                                       la_uint_t serdes_base_id,
                                       size_t serdes_count,
                                       la_mac_port::port_speed_e speed,
                                       la_mac_port::port_speed_e serdes_speed,
                                       la_slice_mode_e serdes_slice_mode)
    : m_device(device),
      m_serdes_device_handler(serdes_device_handler),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_serdes_base_id(serdes_base_id),
      m_serdes_count(serdes_count),
      m_speed(speed),
      m_serdes_speed(serdes_speed),
      m_serdes_slice_mode(serdes_slice_mode),
      m_debug_mode(false)
{
    m_serdes_param_vec.resize(m_serdes_count);

    m_serdes_lane_test_mode.resize(m_serdes_count);
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        m_serdes_lane_test_mode[serdes] = la_mac_port::serdes_test_mode_e::NONE;
    }

    m_loopback_mode = la_mac_port::loopback_mode_e::NONE;
    for (la_uint_t index = 0; index < m_serdes_count; index++) {
        m_serdes_param_vec[index].resize((la_uint_t)la_mac_port::serdes_param_stage_e::LAST + 1);
    }

    // Capture information for all SerDes in the SerDes handler.
    for (la_uint_t serdes_idx = 0; serdes_idx < m_serdes_count; serdes_idx++) {
        la_uint_t tx_die;
        la_uint_t rx_die;
        get_serdes_addr(serdes_idx, la_serdes_direction_e::TX, tx_die);
        get_serdes_addr(serdes_idx, la_serdes_direction_e::RX, rx_die);
        // Store the SerDes index, die and direction together to allow iterative access regardless of lane swapping.
        auto tx_tuple = std::make_tuple(serdes_idx, tx_die, la_serdes_direction_e::TX);
        auto rx_tuple = std::make_tuple(serdes_idx, rx_die, la_serdes_direction_e::RX);
        m_die_set.insert(tx_tuple);
        m_die_set.insert(rx_tuple);
    }
    m_is_initialized = false;

    // Keep a record of pll lock time
    m_die_pll_lock_time.clear();

    // Get the ANLT Order from the device.
    m_anlt_lane.resize(m_serdes_count, 0);
    std::vector<la_uint_t> anlt_sort;
    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t serdes = m_serdes_base_id + serdes_id;
        anlt_sort.push_back(m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order);
    }
    std::sort(anlt_sort.begin(), anlt_sort.end());

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t idx = 0;
        size_t serdes = 0;
        /* anlt_order : is the anlt Serdes number in order of Tx Serdes number
         * anlt_sort  : sort all the anlt Serdes number in the bundle
         * m_anlt_lane: is the Tx Serdes number in ascending order of anlt Serdes number */
        for (idx = 0; idx < m_serdes_count; idx++) {
            serdes = m_serdes_base_id + idx;
            if (anlt_sort[serdes_id] == m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order) {
                break;
            }
        }
        if (idx == m_serdes_count) {
            log_err(SERDES, "Unexpected error in creating m_anlt_lane table.");
        }

        m_anlt_lane[serdes_id] = serdes;
        log_debug(
            SERDES, "SerDes %d/%d/%d m_anlt_lane[%d] - %d", m_slice_id, m_ifg_id, m_serdes_base_id, (int)serdes_id, (int)serdes);
    }

    populate_default_serdes_parameters();
}

srm_serdes_handler::~srm_serdes_handler()
{
}

la_status
srm_serdes_handler::verify_firmware()
{
    std::set<la_uint_t> die_set;
    for (la_uint_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_uint_t tx_die;
        la_uint_t rx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        stat = get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);
        die_set.insert(tx_die);
        die_set.insert(rx_die);
    }

    for (auto die : die_set) {
        bool fw_downloaded = false;

        bool fw_ok;
        la_status stat = m_serdes_device_handler->check_firmware(die, fw_ok);
        return_on_error(stat);

        // SRM firmware must be running before initialization can occur.
        if (!fw_ok) {
            // TODO: Use non-blocking function.
            ip_status_t status = srm_dwld_fw(die, SRM_FW_DWLD_TIMEOUT_MS, true);
            log_err(SERDES, "SerDes %d/%d/%d FW download to die 0x%X.", m_slice_id, m_ifg_id, m_serdes_base_id, die);
            if (status != IP_OK) {
                return LA_STATUS_EUNKNOWN;
            }
            fw_downloaded = true;

            // Check FW again - if not OK, consider to fail.
            stat = m_serdes_device_handler->check_firmware(die, fw_ok);
            return_on_error(stat);
        }

        // Initialize the Syrma die - hardware calibration and firmware housekeeping.
        // Only initialize the die if it is not already initialized.
        if (fw_downloaded) {
            ip_status_t status = srm_init(die);
            log_err(SERDES, "SerDes %d/%d/%d init die 0x%X.", m_slice_id, m_ifg_id, m_serdes_base_id, die);
            if (status != IP_OK) {
                return LA_STATUS_EUNKNOWN;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::enable_pll_bleeders(la_uint_t die_addr, bool enable)
{
    uint32_t ldo_addr_base = SRM_BIAS_LDO_CNTL0_LOW__ADDRESS;

    // Bleeder value: 0x10 - off, 0x8 - bypass, 0x4 - not bypass

    uint32_t bleeder_val = enable ? 0x4 : 0x14;
    // Disable the bleeder on the PLL and RX/TX after bringup
    for (uint32_t ldo = 0; ldo < 5; ldo++) {
        srm_reg_write(die_addr, ldo_addr_base + ldo * 2, bleeder_val);
    }

    // Disable the bleeder on the RX/TX since they are in bypass
    for (uint32_t ldo = 5; ldo < 9; ldo++) {
        srm_reg_write(die_addr, ldo_addr_base + ldo * 2, 0x18);
    }

    // Disable LDO9, it's not used
    srm_reg_write(die_addr, ldo_addr_base + 9 * 2, 0x0);

    // Disable the bleeder on LDO10
    srm_reg_write(die_addr, ldo_addr_base + 10 * 2, 0x14);

    srm_reg_write(die_addr, SRM_BIAS_LDO_LTCH_EN_LOW__ADDRESS, 0xff);
    this_thread::sleep_for(chrono::milliseconds(100));
    srm_reg_write(die_addr, SRM_BIAS_LDO_LTCH_EN_LOW__ADDRESS, 0x0);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::init_plls(e_srm_baud_rates baud_rate)
{
    srm_pll_rules_t pll_rules;
    srm_pll_rules_set_default(&pll_rules);

    pll_rules.baud_rate = baud_rate;

    // Set of all the dies belong to the port.
    std::set<la_uint_t> pll_dies;

    // Build the set of all dies belong to this port.
    for (la_uint_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_uint_t tx_die;
        la_uint_t rx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        stat = get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);

        log_debug(SERDES,
                  "SerDes %d/%d/%d serdes %d => rx die 0x%X, Tx die 0x%X.",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  serdes,
                  rx_die,
                  tx_die);

        pll_dies.insert(tx_die);
        pll_dies.insert(rx_die);
    }

    std::set<la_uint_t> config_dies;

    // Check current configuration and state and build set of all dies require reconfiguration.
    for (auto pll_die : pll_dies) {
        srm_pll_rules_t tmp_pll_rules;
        bool need_config = true;
        ip_status_t status = srm_pll_rules_query(pll_die, &tmp_pll_rules);
        if ((status == IP_OK) && (pll_rules.baud_rate == tmp_pll_rules.baud_rate)) {
            need_config = false;
        } else {
            log_info(SERDES,
                     "Serdes %d/%d/%d PLL baud rate will be reconfigured. "
                     "Die 0x%x - Current baud rate configured to 0x%x. New baud rate to set 0x%x. ",
                     m_slice_id,
                     m_ifg_id,
                     m_serdes_base_id,
                     pll_die,
                     tmp_pll_rules.baud_rate,
                     pll_rules.baud_rate);
            m_die_pll_lock_time.erase(pll_die);
        }
        if (need_config) {
            config_dies.insert(pll_die);
        }
    }

    // Check current configuration and state and build set of all dies require reconfiguration.
    for (auto pll_die : config_dies) {
        ip_status_t status = srm_init(pll_die);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed during srm_init of die 0x%X.", m_slice_id, m_ifg_id, m_serdes_base_id, pll_die);
            return LA_STATUS_EUNKNOWN;
        }

        status = srm_init_pll(pll_die, &pll_rules);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed during PLL init of die 0x%X.", m_slice_id, m_ifg_id, m_serdes_base_id, pll_die);
            return LA_STATUS_EUNKNOWN;
        }
    }

    int retry = SRM_PLL_LOCK_WAIT_LOOP;

    do {
        bool is_pll_locked = true;
        for (auto pll_die : config_dies) {
            if (m_die_pll_lock_time.find(pll_die) == m_die_pll_lock_time.end()) {
                if (srm_is_pll_locked(pll_die)) {
                    // Keep pll lock time for save state
                    m_die_pll_lock_time[pll_die] = (int)(SRM_PLL_LOCK_WAIT_LOOP - retry) * SRM_PLL_LOCK_WAIT;
                } else {
                    is_pll_locked = false;
                }
            }
        }
        if (is_pll_locked == true)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(SRM_PLL_LOCK_WAIT));
    } while (--retry);

    if (retry == 0) {
        log_err(SERDES, "MacPort %d/%d/%d PLL lock check timeout !!!", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    } else {
        log_debug(SERDES,
                  "MacPort %d/%d/%d got all Serdes PLL locked in %d milliseconds.",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  (int)(SRM_PLL_LOCK_WAIT_LOOP - retry) * SRM_PLL_LOCK_WAIT);
    }

    for (auto pll_die : config_dies) {
        if (m_die_pll_lock_time[pll_die] > (SRM_PLL_LOCK_WAIT_LOOP * SRM_PLL_LOCK_WAIT / 20)) {
            // Time is longer than 5% of timeout
            log_warning(SERDES,
                        "MacPort %d/%d/%d die 0x%x Serdes PLL locked in %d milliseconds.",
                        m_slice_id,
                        m_ifg_id,
                        m_serdes_base_id,
                        pll_die,
                        m_die_pll_lock_time[pll_die]);
        }
    }

    for (auto pll_die : config_dies) {
        srm_rx_rules_t rx_rules;
        srm_rx_rules_set_default(&rx_rules);
        rx_rules.rxa_sequence = m_device->m_device_properties[(int)la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE].int_val;
        for (int ch = 0; ch < 2; ch++) {
            ip_status_t status = srm_init_rx(pll_die, ch, &rx_rules);
            if (status != IP_OK) {
                log_err(SERDES,
                        "SerDes %d/%d/%d die/ch %d/%d failed during WA RX init.",
                        m_slice_id,
                        m_ifg_id,
                        m_serdes_base_id,
                        pll_die,
                        ch);
                return LA_STATUS_EUNKNOWN;
            }
        }
    }

    for (auto pll_die : config_dies) {
        srm_serdes_address serdes_addr{.u32 = pll_die};
        la_uint_t even_lane = serdes_addr.fields.serdes_package << 1;
        uint32_t val = get_serdes_parameter_val(even_lane, la_mac_port::serdes_param_e::DTL_KP_KF, GB_SERDES_KP_KF_DEFAULT);

        srm_reg_write(pll_die, SRM_MCU_SPARE63__ADDRESS, (SRM_KP_KF_CFG_ENABLE | val));
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::init()
{
    // Create the rules structure for configuring the ASIC
    srm_tx_rules_t tx_rules;
    srm_tx_rules_set_default(&tx_rules);

    serdes_speed_to_divider_t::const_iterator config = s_serdes_speed_to_divider.find(m_serdes_speed_gbps);
    if (config == s_serdes_speed_to_divider.end()) {
        // Not found
        log_err(SERDES, "Failed to find speed config for: %zd", m_serdes_speed_gbps);
        return LA_STATUS_EINVAL;
    }

    la_status stat = init_plls(config->second.baud_rate);
    return_on_error(stat);

    // Tear down the AN and LT rules in case the port was initially enabled for ANLT.
    teardown_anlt();

    stat = init_rx();
    return_on_error(stat);

    serdes_config_data serdes_data = config->second;

    tx_rules.enable = true;
    if (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES) {
        tx_rules.src = SRM_TX_SRC_RX_LOOPBACK;
    } else if (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_PMA) {
        tx_rules.src = SRM_TX_SRC_RX_DEEP_LOOPBACK;
    } else {
        tx_rules.src = SRM_TX_SRC_CORE;
    }
    tx_rules.subrate_ratio = serdes_data.subrate_ratio;
    tx_rules.signalling = serdes_data.pam4_enable ? SRM_SIGNAL_MODE_PAM : SRM_SIGNAL_MODE_NRZ;

    tx_rules.squelch_lock = true;

    for (la_uint_t serdes = 0; serdes < m_serdes_count; serdes++) {
        ip_status_t status = IP_OK;

        la_uint_t tx_serdes = m_serdes_base_id + serdes;
        la_uint_t tx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);
        tx_rules.invert_chan = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].tx_polarity_inversion;

        tx_rules.gray_mapping = get_serdes_parameter_val(
            serdes, la_mac_port::serdes_param_e::DATAPATH_TX_GRAY_MAP, serdes_data.pam4_enable); // Needed for PAM4 support.

        // Get the LUT mode to determine 3TAP vs 7TAP.
        tx_rules.lut_mode = (e_srm_lut_mode)get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_LUT_MODE, 0);
        if (tx_rules.lut_mode == SRM_TX_LUT_3TAP) {
            // For SRM_TX_LUT_3TAP, fill index 0,1,2. Remaining entries are not used and were cleared by set_default function.
            tx_rules.fir_tap[0] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_PRE1, 0);
            tx_rules.fir_tap[1] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_MAIN, 0);
            tx_rules.fir_tap[2] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_POST, 0);
        } else {
            // Setting up all tap values.
            tx_rules.fir_tap[0] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_PRE3, 0);
            tx_rules.fir_tap[1] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_PRE2, 0);
            tx_rules.fir_tap[2] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_PRE1, 0);
            tx_rules.fir_tap[3] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_MAIN, 0);
            tx_rules.fir_tap[4] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_POST, 0);
            tx_rules.fir_tap[5] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_POST2, 0);
            tx_rules.fir_tap[6] = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_POST3, 0);
        }

        tx_rules.inner_eye1 = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_INNER_EYE1, DEFAULT_INNER_EYE1);
        tx_rules.inner_eye2 = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::TX_INNER_EYE2, DEFAULT_INNER_EYE2);
        // Additional gain stage after the TAPs.
        tx_rules.precoder_en = (bool)get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE, 0);

        // This configures bit order on the line.  Should always be true (IEEE bit order).
        tx_rules.ieee_demap = (bool)get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE, 0);

        log_debug(SERDES,
                  "SerDes %d/%d/%d srm_init_tx die=0x%X, channel=%d, invert=%d, src=%d.",
                  m_slice_id,
                  m_ifg_id,
                  tx_serdes,
                  tx_die,
                  tx_channel,
                  tx_rules.invert_chan,
                  tx_rules.src);
        status = srm_init_tx(tx_die, tx_channel, &tx_rules);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed during TX init.", m_slice_id, m_ifg_id, tx_serdes);
            return LA_STATUS_EUNKNOWN;
        }

        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = true;
    }

    // Block till Tx is ready
    // TODO: remove this blocking code and add it to the state machine. We can't reset Tx PMA till Tx is ready.
    stat = is_port_tx_ready();
    return_on_error(stat);

    // If SerDes init succeeded, set the active flag to high.
    m_is_initialized = true;

    // If SerDes loopback, set loopback with srm API
    if (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) {
        stat = set_loopback_mode(m_loopback_mode);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::enable_tx(bool tx_enable)
{
    if (!m_is_initialized) {
        return LA_STATUS_SUCCESS;
    }

    for (la_uint_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_uint_t tx_serdes = m_serdes_base_id + serdes;
        la_uint_t tx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);

        log_debug(SERDES,
                  "SerDes %d/%d/%d srm_tx_squelch_set die=0x%X, channel=%d, enable=%d.",
                  m_slice_id,
                  m_ifg_id,
                  tx_serdes,
                  tx_die,
                  tx_channel,
                  tx_enable);

        ip_status_t status = srm_tx_squelch_set(tx_die, tx_channel, !tx_enable);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed during srm_tx_squelch_set.", m_slice_id, m_ifg_id, tx_serdes);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::enable_rx(bool rx_enable)
{
    log_debug(SERDES, "%s: SerDes %d/%d/%d has not been implemented.", __func__, m_slice_id, m_ifg_id, m_serdes_base_id);
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::stop()
{
    if (!m_is_initialized) {
        return LA_STATUS_SUCCESS;
    }

    // When the port is stopped, SerDes are no longer considered active
    m_is_initialized = false;
    for (uint serdes = 0; serdes < m_serdes_count; serdes++) {
        ip_status_t status = IP_OK;

        la_uint_t tx_serdes = m_serdes_base_id + serdes;
        la_uint_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
        la_uint_t tx_die;
        la_uint_t rx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);
        stat = get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);
        la_uint_t rx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::RX, rx_channel);
        return_on_error(stat);
        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = false;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = false;

        status = srm_rx_power_down_set(rx_die, rx_channel);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d RX power down failed.", m_slice_id, m_ifg_id, rx_serdes);
            return LA_STATUS_EUNKNOWN;
        }
        status = srm_tx_power_down_set(tx_die, tx_channel);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d TX power down failed.", m_slice_id, m_ifg_id, tx_serdes);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::reset()
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::wait_for_peer_start()
{
    la_status stat = init_rx();
    return stat;
}

la_status
srm_serdes_handler::init_rx()
{
    srm_rx_rules_t rx_rules;
    srm_rx_rules_set_default(&rx_rules);
    rx_rules.src = (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) ? SRM_RX_SRC_TX_LOOPBACK : SRM_RX_SRC_SERIAL;
    serdes_speed_to_divider_t::const_iterator config = s_serdes_speed_to_divider.find(m_serdes_speed_gbps);
    if (config == s_serdes_speed_to_divider.end()) {
        // Not found
        log_err(SERDES, "Failed to find speed config for: %zd", m_serdes_speed_gbps);
        return LA_STATUS_EINVAL;
    }

    serdes_config_data serdes_data = config->second;
    rx_rules.enable = true;
    rx_rules.subrate_ratio = serdes_data.subrate_ratio;
    rx_rules.signalling = serdes_data.pam4_enable ? SRM_SIGNAL_MODE_PAM : SRM_SIGNAL_MODE_NRZ;

    rx_rules.ipp_en = false; // Idle Pattern Protection for non-scrambled data at low speeds.
    rx_rules.bypass_reftrim_fw = true;
    rx_rules.bypass_reftrim_finetune = true;
    rx_rules.rx_qc.dis = true;
    rx_rules.rx_qc.data_mode_dis = false;
    rx_rules.rx_qc.mse_min_threshold = 0;

    // Bit mask:
    //   bit 0 - Ripple power up/down the RXA (Analog blocks)
    //   bit 1 - Keep the RXA always powered up when srm_init_rx is called
    //   bit 2 - Power up the entire dual (two channels) when the RX is powered up (first call to srm_init_rx)
    // SRM_RXA_PWRUP_ON_DEMAND = 3'b000,
    // SRM_RXA_PWRUP_RIPPLE    (1 = Ripple power up/down the analog control bits)
    // SRM_RXA_PWRUP_ALWAYS_ON (2 = Leave the RX analog always on once powered up)
    // SRM_RXA_PWRUP_DUAL      (4 = Power up the entire dual (two channels) when the RX is powered up (first call to srm_init_rx)
    // SRM_RXA_PWRUP_DUAL + SRM_RXA_PWRUP_ALWAYS_ON ( Turn the RX analog supplies for the dual on and leave it on on the first call
    // to srm_init_rx)
    // SRM_RXA_PWRUP_DUAL + SRM_RXA_PWRUP_ALWAYS_ON + SRM_RXA_PWRUP_RIPPLE (Ripple power up the dual and leave it on)
    rx_rules.rxa_sequence = m_device->m_device_properties[(int)la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE].int_val;

    for (la_uint_t serdes = 0; serdes < m_serdes_count; serdes++) {
        ip_status_t status = IP_OK;

        la_uint_t tx_serdes = m_serdes_base_id + serdes;
        la_uint_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
        la_uint_t rx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);
        la_uint_t rx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::RX, rx_channel);

        rx_rules.gray_mapping = get_serdes_parameter_val(
            serdes, la_mac_port::serdes_param_e::DATAPATH_RX_GRAY_MAP, serdes_data.pam4_enable); // Needed for PAM4 support.

        rx_rules.invert_chan = m_device->m_serdes_info[m_slice_id][m_ifg_id][rx_serdes].rx_polarity_inversion;

        rx_rules.dsp_mode = (e_srm_dsp_mode)get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::RX_DSP_MODE, 0);

        la_mac_port::serdes_param_mode_e param_mode;
        int param_value;
        stat = get_serdes_parameter(serdes,
                                    la_mac_port::serdes_param_stage_e::ACTIVATE,
                                    la_mac_port::serdes_param_e::RX_CTLE_CODE,
                                    param_mode,
                                    param_value);
        return_on_error(stat);
        if (param_mode == la_mac_port::serdes_param_mode_e::ADAPTIVE)
            rx_rules.ctle_code = DEFAULT_AUTO_CTLE_CODE;
        else
            rx_rules.ctle_code = param_value;
        stat = get_serdes_parameter(
            serdes, la_mac_port::serdes_param_stage_e::ACTIVATE, la_mac_port::serdes_param_e::RX_AFE_TRIM, param_mode, param_value);
        return_on_error(stat);
        if (param_mode == la_mac_port::serdes_param_mode_e::ADAPTIVE) {
            rx_rules.afe_trim = SRM_AFE_TRIM_NEG_4dB;
            rx_rules.pga_att_en = true;
        } else {
            rx_rules.afe_trim = (e_srm_afe_trim)param_value;
            rx_rules.pga_att_en = false;
        }
        // Variable gain tracking.  Enable for higher loss channels.
        rx_rules.vga_tracking = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::RX_VGA_TRACKING, 0);
        rx_rules.ac_coupling_bypass = get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS, 0);
        rx_rules.dfe_precoder_en = (bool)get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE, 0);

        // This configures bit order on the line.  Should always be true (IEEE bit order).
        rx_rules.ieee_demap = (bool)get_serdes_parameter_val(serdes, la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE, 0);

        for (auto sdt_param : sdt_params_list) {
            int rx_sdt_val = 0;
            stat = get_serdes_parameter(
                serdes, la_mac_port::serdes_param_stage_e::ACTIVATE, sdt_param.sdk_param, param_mode, rx_sdt_val);
            if (stat == LA_STATUS_SUCCESS) {
                status = srm_rx_param_set(rx_die, rx_channel, sdt_param.srm_param, (uint32_t)rx_sdt_val);
            }
        }

        log_debug(SERDES,
                  "SerDes %d/%d/%d srm_init_rx die=0x%X, channel=%d, invert=%d, src=%d.",
                  m_slice_id,
                  m_ifg_id,
                  rx_serdes,
                  rx_die,
                  rx_channel,
                  rx_rules.invert_chan,
                  rx_rules.src);

        status = srm_init_rx(rx_die, rx_channel, &rx_rules);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed during RX init.", m_slice_id, m_ifg_id, rx_serdes);
            return LA_STATUS_EUNKNOWN;
        }
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = true;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::is_port_tx_ready()
{
    // Block till Tx is ready
    // TODO: remove this blocking code and add it to the state machine. We can't reset Tx PMA till Tx is ready.
    bool all_good = true;
    for (int i = 0; i < SRM_TX_READY_RETRY; i++) {
        all_good = true;
        for (uint serdes = 0; serdes < m_serdes_count; serdes++) {
            la_uint_t tx_die;
            la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
            return_on_error(stat);
            la_uint_t tx_channel;
            stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
            return_on_error(stat);

            bool tx_ready = srm_is_tx_ready(tx_die, tx_channel);
            all_good = all_good && tx_ready;
        }
        if (all_good) {
            log_debug(SERDES, "SerDes %d/%d/%d all_good = %d [%d].", m_slice_id, m_ifg_id, m_serdes_base_id, all_good, i);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(SRM_TX_READY_SLEEP_MS));
    }
    if (!all_good) {
        log_warning(SERDES, "Not all SerDes of %d/%d/%d are ready. ", m_slice_id, m_ifg_id, m_serdes_base_id);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::reenable_tx()
{
    la_status stat;
    ip_status_t srm_status;
    srm_tx_rules_t tx_rules;
    srm_tx_rules_set_default(&tx_rules);

    for (la_uint_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_uint_t tx_die;
        stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);

        srm_status = srm_tx_rules_query(tx_die, tx_channel, &tx_rules);
        if (srm_status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed to query tx rules.", m_slice_id, m_ifg_id, serdes);
            return LA_STATUS_EUNKNOWN;
        }

        srm_status = srm_init_tx(tx_die, tx_channel, &tx_rules);
        if (srm_status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed during TX init.", m_slice_id, m_ifg_id, serdes);
            return LA_STATUS_EUNKNOWN;
        }
    }

    stat = is_port_tx_ready();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::recenter_serdes_tx_fifo()
{
    ip_status_t srm_status;

    // Use Inphi's API to recenter the fifo and open up TX traffics from PMA
    srm_status = srm_anlt_recenter_tx_fifo(&m_bundle);
    if (srm_status != IP_OK) {
        log_err(SERDES, "SerDes %d/%d/%d failed to recenter TX FIFO.", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    srm_status = srm_anlt_open_tx(&m_bundle);
    if (srm_status != IP_OK) {
        log_err(SERDES, "SerDes %d/%d/%d failed to open TX path.", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::wait_for_peer_stop()
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::is_tune_good()
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::tune()
{
    // Re-tune after ANLT is done causes the link to fail PCS lock.
    if (m_is_an_enabled) {
        return LA_STATUS_SUCCESS;
    }

    for (la_uint_t serdes_idx = 0; serdes_idx < m_serdes_count; serdes_idx++) {
        la_status stat
            = set_serdes_signal_control(serdes_idx, la_serdes_direction_e::RX, la_mac_port::serdes_ctrl_e::ENABLE_SQUELCH);
        return_on_error(stat);
    }

    this_thread::sleep_for(chrono::milliseconds(1));

    for (la_uint_t serdes_idx = 0; serdes_idx < m_serdes_count; serdes_idx++) {
        la_status stat
            = set_serdes_signal_control(serdes_idx, la_serdes_direction_e::RX, la_mac_port::serdes_ctrl_e::DISABLE_SQUELCH);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::get_tune_complete(bool& out_completed)
{
    out_completed = false;

    if (!m_is_initialized) {
        return LA_STATUS_SUCCESS;
    }

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_uint_t tx_serdes = m_serdes_base_id + serdes;
        la_uint_t tx_die;
        la_uint_t rx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        stat = get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);
        la_uint_t rx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::RX, rx_channel);
        return_on_error(stat);

        bool is_ready = srm_is_tx_ready(tx_die, tx_channel);
        if (!is_ready) {
            log_debug(SERDES, "get_tune_complete: SerDes %d/%d/%d Tx not ready.", m_slice_id, m_ifg_id, tx_serdes);
            return LA_STATUS_SUCCESS;
        }

        if (m_loopback_mode == la_mac_port::loopback_mode_e::NONE) {
            is_ready = srm_is_rx_ready(rx_die, rx_channel);
            if (!is_ready) {
                log_debug(SERDES, "get_tune_complete: SerDes %d/%d/%d Rx not ready.", m_slice_id, m_ifg_id, tx_serdes);
                return LA_STATUS_SUCCESS;
            }
        }
    }

    out_completed = true;
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::periodic_tune_start()
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::periodic_tune_stop()
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::is_periodic_tune_stopped(bool& out_stopped)
{
    out_stopped = true;
    return LA_STATUS_SUCCESS;
}

void
srm_serdes_handler::populate_default_serdes_parameters()
{
    for (la_uint_t serdes_idx = 0; serdes_idx < m_serdes_count; serdes_idx++) {
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_LUT_MODE,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             SRM_TX_LUT_3TAP);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_POST,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             -65);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_PRE1,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             -70);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_MAIN,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             900);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_INNER_EYE1,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             DEFAULT_INNER_EYE1);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_INNER_EYE2,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             DEFAULT_INNER_EYE2);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_DSP_MODE,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             SRM_DSP_MODE_DFE1_RC_DFE2);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_CTLE_CODE,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             40);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_AFE_TRIM,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             SRM_AFE_TRIM_NEG_4dB);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_VGA_TRACKING,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             false);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::CTLE_TUNE,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             false);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             true);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::DTL_KP_KF,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             GB_SERDES_KP_KF_DEFAULT);
        // Value 255 will disable rx_precoder. To set precoder threshold for 0.5, calculate as follow:
        // int(0.5 * 64) = 32.  Set AUTO_RX_PRECODE_THRESHOLD to 32 (0x20). 64 is max threshold.
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::AUTO_RX_PRECODE_THRESHOLD,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             DEFAULT_ANLT_AUTO_RX_PRECODE_THRESHOLD); // default: 32
    }
}
la_status
srm_serdes_handler::set_serdes_parameter(la_uint_t serdes_idx,
                                         la_mac_port::serdes_param_stage_e stage,
                                         la_mac_port::serdes_param_e param,
                                         la_mac_port::serdes_param_mode_e mode,
                                         int value)

{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Check valid mode/value.
    switch (param) {
    case la_mac_port::serdes_param_e::DATAPATH_RX_GRAY_MAP:
    case la_mac_port::serdes_param_e::DATAPATH_TX_GRAY_MAP:
    case la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE:
    case la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE:
    case la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE:
    case la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE:
    case la_mac_port::serdes_param_e::TX_POST:
    case la_mac_port::serdes_param_e::TX_POST2:
    case la_mac_port::serdes_param_e::TX_POST3:
    case la_mac_port::serdes_param_e::TX_PRE1:
    case la_mac_port::serdes_param_e::TX_PRE2:
    case la_mac_port::serdes_param_e::TX_PRE3:
    case la_mac_port::serdes_param_e::TX_MAIN:
    case la_mac_port::serdes_param_e::TX_INNER_EYE1:
    case la_mac_port::serdes_param_e::TX_INNER_EYE2:
    case la_mac_port::serdes_param_e::TX_LUT_MODE:
    case la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS:
    case la_mac_port::serdes_param_e::RX_DSP_MODE:
    case la_mac_port::serdes_param_e::CTLE_TUNE:
    case la_mac_port::serdes_param_e::RX_VGA_TRACKING:
    case la_mac_port::serdes_param_e::DTL_KP_KF:
    case la_mac_port::serdes_param_e::AUTO_RX_PRECODE_THRESHOLD:
    case la_mac_port::serdes_param_e::RX_SDT_CODE_FALL:
    case la_mac_port::serdes_param_e::RX_SDT_CODE_RISE:
    case la_mac_port::serdes_param_e::RX_SDT_CODE_TH:
    case la_mac_port::serdes_param_e::RX_SDT_BLOCK_CNT:
        if ((mode != la_mac_port::serdes_param_mode_e::FIXED) || (stage != la_mac_port::serdes_param_stage_e::ACTIVATE)) {
            log_err(SERDES,
                    "Invalid SerDes parameter configuration for Slice/IFG/SerDes %d/%d/%d "
                    "parameter %s supported only on ACTIVATE and FIXED",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    to_string(param).c_str());
            return LA_STATUS_EINVAL;
        }
        break;
    case la_mac_port::serdes_param_e::RX_AFE_TRIM:
    case la_mac_port::serdes_param_e::RX_CTLE_CODE:
        if ((mode == la_mac_port::serdes_param_mode_e::STATIC) || (stage != la_mac_port::serdes_param_stage_e::ACTIVATE)) {
            log_err(SERDES,
                    "Invalid SerDes parameter configuration for Slice/IFG/SerDes %d/%d/%d "
                    "parameter %s supported only on ACTIVATE and FIXED/ADAPTIVE",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    to_string(param).c_str());
            return LA_STATUS_EINVAL;
        }
        break;
    default:
        log_err(SERDES,
                "Invalid SerDes parameter configuration for Slice/IFG/SerDes %d/%d/%d parameter %s not supported on this device.",
                m_slice_id,
                m_ifg_id,
                m_serdes_base_id,
                to_string(param).c_str());
        return LA_STATUS_EINVAL;
    }

    serdes_param_setting param_st = {.mode = mode, .value = value};
    m_serdes_param_vec[serdes_idx][(size_t)stage][param] = param_st;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::get_serdes_parameter(la_uint_t serdes_idx,
                                         la_mac_port::serdes_param_stage_e stage,
                                         la_mac_port::serdes_param_e param,
                                         la_mac_port::serdes_param_mode_e& out_mode,
                                         int& out_value) const
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    auto serdes_param = m_serdes_param_vec[serdes_idx][(size_t)stage].find(param);
    if (serdes_param == m_serdes_param_vec[serdes_idx][(size_t)stage].end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_mode = serdes_param->second.mode;
    out_value = serdes_param->second.value;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::get_serdes_parameter_hardware_value(la_uint_t serdes_idx, la_mac_port::serdes_param_e param, int& out_value)
{
    la_status status;
    la_uint32_t tx_die, rx_die;
    la_uint_t rx_channel, tx_channel;
    srm_tx_rules_t tx_rules;
    srm_rx_rules_t rx_rules;
    int srm_status;
    uint32_t sdt_code;

    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // get die addr
    status = get_serdes_addr(serdes_idx, la_serdes_direction_e::TX, tx_die);
    return_on_error(status);
    status = get_serdes_addr(serdes_idx, la_serdes_direction_e::RX, rx_die);
    return_on_error(status);

    // get channel
    status = get_serdes_channel(serdes_idx, la_serdes_direction_e::TX, tx_channel);
    return_on_error(status);
    status = get_serdes_channel(serdes_idx, la_serdes_direction_e::RX, rx_channel);
    return_on_error(status);

    // query rules
    srm_status = srm_tx_rules_query(tx_die, tx_channel, &tx_rules);
    if (srm_status != IP_OK) {
        return LA_STATUS_EINVAL;
    }

    srm_status = srm_rx_rules_query(rx_die, rx_channel, &rx_rules);
    if (srm_status != IP_OK) {
        return LA_STATUS_EINVAL;
    }

    // Check valid mode/value.
    switch (param) {
    case la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE:
        out_value = rx_rules.dfe_precoder_en;
        break;
    case la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE:
        out_value = tx_rules.precoder_en;
        break;
    case la_mac_port::serdes_param_e::TX_PRE1:
        // depending on mode, 3-TAP vs 7-TAP choose correct value
        out_value = tx_rules.lut_mode == SRM_TX_LUT_3TAP ? tx_rules.fir_tap[0] : tx_rules.fir_tap[4];
        break;
    case la_mac_port::serdes_param_e::TX_MAIN:
        // depending on mode, 3-TAP vs 7-TAP choose correct value
        out_value = tx_rules.lut_mode == SRM_TX_LUT_3TAP ? tx_rules.fir_tap[1] : tx_rules.fir_tap[5];
        break;
    case la_mac_port::serdes_param_e::TX_POST:
        // depending on mode, 3-TAP vs 7-TAP choose correct value
        out_value = tx_rules.lut_mode == SRM_TX_LUT_3TAP ? tx_rules.fir_tap[2] : tx_rules.fir_tap[6];
        break;
    case la_mac_port::serdes_param_e::TX_INNER_EYE1:
        out_value = tx_rules.inner_eye1;
        break;
    case la_mac_port::serdes_param_e::TX_INNER_EYE2:
        out_value = tx_rules.inner_eye2;
        break;
    case la_mac_port::serdes_param_e::TX_LUT_MODE:
        out_value = tx_rules.lut_mode;
        break;
    case la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS:
        out_value = rx_rules.ac_coupling_bypass;
        break;
    case la_mac_port::serdes_param_e::RX_AFE_TRIM:
        out_value = rx_rules.afe_trim;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_CODE:
        out_value = rx_rules.ctle_code;
        break;
    case la_mac_port::serdes_param_e::RX_DSP_MODE:
        out_value = rx_rules.dsp_mode;
        break;
    case la_mac_port::serdes_param_e::RX_VGA_TRACKING:
        out_value = rx_rules.vga_tracking;
        break;
    case la_mac_port::serdes_param_e::RX_SDT_CODE_FALL:
        sdt_code = srm_reg_read(rx_die, SRM_RX_DSP_SIGNAL_DETECT_CODE_CFG_ADDRESS + rx_channel * SRM_TXRX_CHANNEL_OFFSET);
        out_value = (sdt_code >> SRM_RX_SDT_CODE_FALL_SHIFT) & SRM_RX_SDT_CODE_MASK;
        break;
    case la_mac_port::serdes_param_e::RX_SDT_CODE_RISE:
        sdt_code = srm_reg_read(rx_die, SRM_RX_DSP_SIGNAL_DETECT_CODE_CFG_ADDRESS + rx_channel * SRM_TXRX_CHANNEL_OFFSET);
        out_value = sdt_code & SRM_RX_SDT_CODE_MASK;
        break;
    case la_mac_port::serdes_param_e::RX_SDT_CODE_TH:
        sdt_code = srm_reg_read(rx_die, SRM_RX_DSP_SIGNAL_DETECT_CODE_THRESHOLD_CFG_ADDRESS + rx_channel * SRM_TXRX_CHANNEL_OFFSET);
        out_value = sdt_code & SRM_RX_SDT_CODE_MASK;
        break;
    case la_mac_port::serdes_param_e::RX_SDT_BLOCK_CNT:
        sdt_code = srm_reg_read(rx_die, SRM_RX_DSP_SIGNAL_DETECT_CFG__ADDRESS + rx_channel * SRM_TXRX_CHANNEL_OFFSET);
        out_value = sdt_code & SRM_RX_DSP_SIGNAL_DETECT_CFG__SDT_BLOCK_CNT__MASK;
        break;

    default:
        log_err(SERDES, "%s : %s not implemented.", __func__, silicon_one::to_string(param).c_str());
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_SUCCESS;
}

int
srm_serdes_handler::get_serdes_parameter_val(la_uint_t serdes_idx, la_mac_port::serdes_param_e param, int default_value) const
{
    int tmp_val;
    la_mac_port::serdes_param_mode_e tmp_mode;

    la_status stat = get_serdes_parameter(serdes_idx, la_mac_port::serdes_param_stage_e::ACTIVATE, param, tmp_mode, tmp_val);
    if (stat == LA_STATUS_SUCCESS) {
        return tmp_val;
    }

    return default_value;
}

la_status
srm_serdes_handler::get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    for (la_uint_t stage_index = 0; stage_index < (la_uint_t)la_mac_port::serdes_param_stage_e::LAST + 1; stage_index++) {
        for (auto param_ent : m_serdes_param_vec[serdes_idx][(size_t)stage_index]) {
            la_mac_port::serdes_parameter single_param = {.stage = static_cast<la_mac_port::serdes_param_stage_e>(stage_index),
                                                          .parameter = param_ent.first,
                                                          .mode = param_ent.second.mode,
                                                          .value = param_ent.second.value};
            out_param_array.push_back(single_param);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::clear_serdes_parameter(la_uint_t serdes_idx,
                                           la_mac_port::serdes_param_stage_e stage,
                                           la_mac_port::serdes_param_e param)

{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    auto serdes_param = m_serdes_param_vec[serdes_idx][(size_t)stage].find(param);
    if (serdes_param == m_serdes_param_vec[serdes_idx][(size_t)stage].end()) {
        return LA_STATUS_ENOTFOUND;
    }

    m_serdes_param_vec[serdes_idx][(size_t)stage].erase(param);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::update_loopback_mode(la_mac_port::loopback_mode_e loopback_mode)
{
    m_loopback_mode = loopback_mode;
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_loopback_mode(la_mac_port::loopback_mode_e loopback_mode)
{
    if (m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        log_debug(SERDES, "%s: skip SerDes access during reconnect", __func__);
        m_loopback_mode = loopback_mode;
        return LA_STATUS_SUCCESS;
    }
    if (!m_is_initialized) {
        // In case the user sets loopback mode before activating the port, save the desired state.
        m_loopback_mode = loopback_mode;
        return LA_STATUS_SUCCESS;
    }

    bool enabe_serdes_loopback
        = (loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES || loopback_mode == la_mac_port::loopback_mode_e::SERDES);
    e_srm_loopback_mode srm_loopback_mode
        = loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES ? SRM_LOOPBACK_SERIAL_FAR : SRM_LOOPBACK_CORE_NEAR;

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_uint_t tx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);

        ip_status_t status = srm_loopback_set(tx_die, tx_channel, srm_loopback_mode, enabe_serdes_loopback);
        if (status != IP_OK) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    m_loopback_mode = loopback_mode;

    return LA_STATUS_SUCCESS;
}

void
srm_serdes_handler::print_tune_status_message(const char* message, la_logger_level_e severity)
{
    return;
}

void
srm_serdes_handler::save_serdes_debug_message(const char* message)
{
    // not implemented
    return;
}

void
srm_serdes_handler::print_serdes_debug_message(const char* message)
{
    log_debug(SERDES, "Slice/IFG/SerDes %d/%d/%d %s", m_slice_id, m_ifg_id, m_serdes_base_id, message);
    return;
}

void
srm_serdes_handler::print_pmd_status_message(const char* message, long duration)
{
    return;
}

bool
srm_serdes_handler::is_srm_dsp_mode_dfe(uint32_t dsp_mode)
{
    if (dsp_mode == SRM_DSP_MODE_DFE1 || dsp_mode == SRM_DSP_MODE_DFE1_RC_DFE2)
        return true;
    else
        return false;
}

la_status
srm_serdes_handler::build_anlt_bundle(srm_anlt_bundle_t& anlt_bundle)
{
    // Build the ports bundle info.
    anlt_bundle.num_followers = m_serdes_count;

    for (size_t lane_id = 0; lane_id < m_serdes_count; lane_id++) {
        size_t serdes_idx = m_anlt_lane[lane_id];
        size_t serdes = serdes_idx - m_serdes_base_id;

        la_uint_t tx_die;
        la_status stat = get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);

        la_uint_t rx_die;
        stat = get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);

        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);

        la_uint_t rx_channel;
        stat = get_serdes_channel(serdes, la_serdes_direction_e::RX, rx_channel);
        return_on_error(stat);
        if (lane_id == 0) {
            anlt_bundle.an_leader.tx_die = tx_die;
            anlt_bundle.an_leader.tx_channel = tx_channel;
            anlt_bundle.an_leader.rx_die = rx_die;
            anlt_bundle.an_leader.rx_channel = rx_channel;
        }
        anlt_bundle.lt_followers[lane_id].tx_die = tx_die;
        anlt_bundle.lt_followers[lane_id].tx_channel = tx_channel;
        anlt_bundle.lt_followers[lane_id].rx_die = rx_die;
        anlt_bundle.lt_followers[lane_id].rx_channel = rx_channel;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_anlt_tx_rules_default(srm_tx_bundle_rules_t& out_tx_rules)
{
    srm_tx_rules_t tx_rules;
    srm_tx_rules_set_default(&tx_rules);

    out_tx_rules.enable = tx_rules.enable;
    out_tx_rules.squelch_lock = tx_rules.squelch_lock;
    out_tx_rules.src = tx_rules.src;
    out_tx_rules.subrate_ratio = tx_rules.subrate_ratio;
    out_tx_rules.signalling = tx_rules.signalling;
    out_tx_rules.lut_mode = tx_rules.lut_mode;
    out_tx_rules.gray_mapping = tx_rules.gray_mapping;
    out_tx_rules.ieee_demap = tx_rules.ieee_demap;
    out_tx_rules.precoder_en = tx_rules.precoder_en;

    for (size_t i = 0; i < 8; i++) {
        out_tx_rules.invert_chan[i] = tx_rules.invert_chan;
        out_tx_rules.inner_eye1[i] = tx_rules.inner_eye1;
        out_tx_rules.inner_eye2[i] = tx_rules.inner_eye2;
        for (size_t j = 0; j < 7; j++) {
            out_tx_rules.fir_tap[i][j] = 0;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_anlt_rx_rules_default(srm_rx_bundle_rules_t& out_rx_rules)
{
    srm_rx_rules_t rx_rules;
    srm_rx_rules_set_default(&rx_rules);

    out_rx_rules.enable = rx_rules.enable;
    out_rx_rules.src = rx_rules.src;
    out_rx_rules.subrate_ratio = rx_rules.subrate_ratio;
    out_rx_rules.signalling = rx_rules.signalling;
    out_rx_rules.dsp_mode = rx_rules.dsp_mode;
    out_rx_rules.gray_mapping = rx_rules.gray_mapping;
    out_rx_rules.ieee_demap = rx_rules.ieee_demap;
    out_rx_rules.dfe_precoder_en = rx_rules.dfe_precoder_en;
    out_rx_rules.vga_tracking = rx_rules.vga_tracking;
    out_rx_rules.ipp_en = rx_rules.ipp_en;
    out_rx_rules.ac_coupling_bypass = rx_rules.ac_coupling_bypass;
    out_rx_rules.rx_qc.dis = rx_rules.rx_qc.dis;
    out_rx_rules.rx_qc.data_mode_dis = rx_rules.rx_qc.data_mode_dis;
    out_rx_rules.rx_qc.mse_min_threshold = rx_rules.rx_qc.mse_min_threshold;
    out_rx_rules.bypass_reftrim_fw = rx_rules.bypass_reftrim_fw;
    out_rx_rules.bypass_reftrim_finetune = rx_rules.bypass_reftrim_finetune;
    out_rx_rules.preamp_bias_ctrl = rx_rules.preamp_bias_ctrl;
    out_rx_rules.prbs_chk_en = rx_rules.prbs_chk_en;

    for (size_t i = 0; i < 8; i++) {
        out_rx_rules.ctle_code[i] = rx_rules.ctle_code;
        out_rx_rules.invert_chan[i] = rx_rules.invert_chan;
        out_rx_rules.afe_trim[i] = rx_rules.afe_trim;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_anlt_tx_bundle_rules(srm_tx_bundle_rules_t& out_tx_rules)
{
    set_anlt_tx_rules_default(out_tx_rules);

    serdes_speed_to_divider_t::const_iterator config = s_serdes_speed_to_divider.find(m_serdes_speed_gbps);
    if (config == s_serdes_speed_to_divider.end()) {
        // Not found
        log_err(SERDES, "Failed to find speed config for: %zd", m_serdes_speed_gbps);
        return LA_STATUS_EINVAL;
    }

    serdes_config_data serdes_data = config->second;

    int preset_sel = m_device->m_device_properties[(int)la_device_property_e::SERDES_CL136_PRESET_TYPE].int_val;

    for (size_t lane_id = 0; lane_id < m_bundle.num_followers; lane_id++) {
        // bundle is constructed based on the m_anlt_lane, need to follow the same order for the rules.
        size_t tx_serdes = m_anlt_lane[lane_id];

        // srm_tx_rules_t &tx_rules;
        if (lane_id == 0) {
            out_tx_rules.enable = true;
            out_tx_rules.squelch_lock = true;
            out_tx_rules.src
                = (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES) ? SRM_TX_SRC_RX_LOOPBACK : SRM_TX_SRC_CORE;
            out_tx_rules.subrate_ratio = serdes_data.subrate_ratio;
            out_tx_rules.signalling = serdes_data.pam4_enable ? SRM_SIGNAL_MODE_PAM : SRM_SIGNAL_MODE_NRZ;
            out_tx_rules.lut_mode = (e_srm_lut_mode)get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::TX_LUT_MODE, 0);
            out_tx_rules.ieee_demap = (bool)get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE, 0);
            out_tx_rules.gray_mapping = (bool)get_serdes_parameter_val(
                lane_id, la_mac_port::serdes_param_e::DATAPATH_TX_GRAY_MAP, serdes_data.pam4_enable);
            // Note: For ANLT, tx_rules.precoder_en is ignored by the firmware according to Inphi.
            // rx_rules.precoder enable bit is used to request its link partner to turn on its TX precoder.
            out_tx_rules.precoder_en = (bool)get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE, 0);
        }

        out_tx_rules.invert_chan[lane_id] = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].tx_polarity_inversion;

        out_tx_rules.inner_eye1[lane_id]
            = get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::TX_INNER_EYE1, DEFAULT_INNER_EYE1);
        out_tx_rules.inner_eye2[lane_id]
            = get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::TX_INNER_EYE2, DEFAULT_INNER_EYE2);

        // Confirmed with Inphi, only 7-TAP-LIN is supported for ANLT. This means we need to use 7-TAP-LIN for the lut_mode.
        // This is the case when switching from non-ANLT to ANLT using mp.set_an_enable().
        if (out_tx_rules.lut_mode == SRM_TX_LUT_3TAP) {
            out_tx_rules.lut_mode = SRM_TX_LUT_7TAP_LIN;
            log_info(SERDES,
                     "%s: %d/%d/%d LUT_MODE is changed from %d to %d for ANLT.",
                     __func__,
                     m_slice_id,
                     m_ifg_id,
                     (int)(m_serdes_base_id + lane_id),
                     SRM_TX_LUT_3TAP,
                     SRM_TX_LUT_7TAP_LIN);
        }
        if (serdes_data.pam4_enable && (preset_sel == SRM_CL136_PRESET_2_MODE)) {
            // IEEE Standard Preset2 values.
            out_tx_rules.fir_tap[lane_id][4] = -150; // TX_PRE1
            out_tx_rules.fir_tap[lane_id][5] = 750;  // TX_MAIN
            out_tx_rules.fir_tap[lane_id][6] = -100; // TX_POST
        } else {
            // Inphi recommended settings for AN
            out_tx_rules.fir_tap[lane_id][4] = 0;    // TX_PRE1
            out_tx_rules.fir_tap[lane_id][5] = 1000; // TX_MAIN
            out_tx_rules.fir_tap[lane_id][6] = 0;    // TX_POST
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_anlt_rx_bundle_rules(srm_rx_bundle_rules_t& out_rx_rules)
{
    set_anlt_rx_rules_default(out_rx_rules);

    serdes_speed_to_divider_t::const_iterator config = s_serdes_speed_to_divider.find(m_serdes_speed_gbps);
    if (config == s_serdes_speed_to_divider.end()) {
        // Not found
        log_err(SERDES, "Failed to find speed config for: %zd", m_serdes_speed_gbps);
        return LA_STATUS_EINVAL;
    }

    serdes_config_data serdes_data = config->second;

    // Initial RX configuration rules, using defaults and then update from the hardware
    for (size_t lane_id = 0; lane_id < m_bundle.num_followers; lane_id++) {
        // la_uint_t die, channel;
        // srm_rx_rules_t rx_rules;

        // bundle is constructed based on the m_anlt_lane, need to follow the same order for the rules.
        la_uint_t tx_serdes = m_anlt_lane[lane_id];
        la_uint_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        if (lane_id == 0) { // Entry 0 is leader, setup these fields from the leader.
            out_rx_rules.enable = true;
            out_rx_rules.rxa_sequence
                = m_device->m_device_properties[(int)la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE].int_val;
            out_rx_rules.src
                = (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) ? SRM_RX_SRC_TX_LOOPBACK : SRM_RX_SRC_SERIAL;
            out_rx_rules.subrate_ratio = serdes_data.subrate_ratio;
            out_rx_rules.signalling = serdes_data.pam4_enable ? SRM_SIGNAL_MODE_PAM : SRM_SIGNAL_MODE_NRZ;
            out_rx_rules.dsp_mode = SRM_DSP_MODE_DFE1_RC_DFE2;
            out_rx_rules.gray_mapping = (bool)get_serdes_parameter_val(
                lane_id, la_mac_port::serdes_param_e::DATAPATH_RX_GRAY_MAP, serdes_data.pam4_enable);
            out_rx_rules.ieee_demap = (bool)get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE, 0);
            out_rx_rules.dfe_precoder_en
                = (bool)get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE, 0);
            out_rx_rules.vga_tracking = get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::RX_VGA_TRACKING, 0);
            out_rx_rules.ipp_en = false;
            out_rx_rules.ac_coupling_bypass
                = get_serdes_parameter_val(lane_id, la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS, 0);
            out_rx_rules.rx_qc.dis = true; // Matching Inphi's defaults setting.
            out_rx_rules.rx_qc.data_mode_dis = false;
            out_rx_rules.rx_qc.mse_min_threshold = 0;
            out_rx_rules.bypass_reftrim_fw = false;
            out_rx_rules.bypass_reftrim_finetune = false;
            out_rx_rules.preamp_bias_ctrl = 0;
            out_rx_rules.prbs_chk_en = false;
            out_rx_rules.pga_att_en = true;
        }
        out_rx_rules.ctle_code[lane_id] = DEFAULT_AUTO_CTLE_CODE;
        out_rx_rules.invert_chan[lane_id] = m_device->m_serdes_info[m_slice_id][m_ifg_id][rx_serdes].rx_polarity_inversion;
        out_rx_rules.afe_trim[lane_id] = SRM_AFE_TRIM_NEG_4dB;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::enable_serdes_msg_gen()
{
    for (la_int_t i = 0; i < m_bundle.num_followers; i++) {

        // Reset and enable the LT message blocks
        // First the TX side
        // Turn on the RX and TX deserializers for the messages
        SRM_TX_ANLT_MSG_GEN_CFG__WRITE(m_bundle.lt_followers[i].tx_die, m_bundle.lt_followers[i].tx_channel, 0x3);

        // Write the registers required for TX to do LT
        SRM_TX_TXD_MISC_CFG__LT_MSG_CTL__WRITE(m_bundle.lt_followers[i].tx_die, m_bundle.lt_followers[i].tx_channel, 0x1);

        // Toggle the reset on the message blocks
        SRM_TX_ANLT_MSG_RESET__WRITE(m_bundle.lt_followers[i].tx_die, m_bundle.lt_followers[i].tx_channel, 0x503);
        SRM_TX_ANLT_MSG_RESET__WRITE(m_bundle.lt_followers[i].tx_die, m_bundle.lt_followers[i].tx_channel, 0x0);

        // Now the RX side
        // Turn on the RX and TX deserializers for the messages
        SRM_RX_ANLT_MSG_GEN_CFG__WRITE(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].rx_channel, 0x7);

        // Toggle the reset on the message blocks
        SRM_RX_ANLT_MSG_RESET__WRITE(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].rx_channel, 0x303);
        SRM_RX_ANLT_MSG_RESET__WRITE(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].rx_channel, 0x0);
    }

    this_thread::sleep_for(chrono::milliseconds(200));

    for (la_int_t i = 0; i < m_bundle.num_followers; i++) {
        // After everything is turned on, clear any false messages that
        // may be stuck in FIFOs. (may not need this step)
        if (SRM_TX_ANLT_MSG_RX_MSG_STATUS__READ(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].tx_channel) & 0x1) {
            SRM_TX_ANLT_MSG_RX_MSG_POP__WRITE(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].tx_channel, 1);
        }

        if (SRM_RX_ANLT_MSG_RX_MSG_STATUS__READ(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].rx_channel) & 0x1) {
            SRM_RX_ANLT_MSG_RX_MSG_POP__WRITE(m_bundle.lt_followers[i].rx_die, m_bundle.lt_followers[i].rx_channel, 1);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::an_start(la_mac_port::state_e& state)
{
    la_status stat = enable_tx(true);
    return_on_error(stat);

    // Clear and initialize histograms
    curr_an_status = SRM_AN_STATUS_COMPLETE;
    for (size_t i = 0; i < 8; i++)
        curr_tx_spare9_fsm_state[i] = -1;
    tx_spare9_histogram.resize(SRM_TX_SPARE9_NUM_ENTRY, 0);
    rx_spare9_histogram.resize(SRM_RX_SPARE9_NUM_ENTRY, 0);

    // Clear and initialize histograms
    // Setup the size of transition history queue. Use the same MAC_PORT device property for max_size.
    la_int_t max_num_sm_transitions;
    m_device->get_int_property(la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES, max_num_sm_transitions);
    m_tx_sp9_state_transition_queue.set_max_size(max_num_sm_transitions);
    m_rx_sp9_state_transition_queue.set_max_size(max_num_sm_transitions);

    // Build ANLT bundle.
    stat = build_anlt_bundle(m_bundle);
    return_on_error(stat);

    ip_status_t status = IP_OK;
    srm_anlt_rules_t rules;

    la_uint_t anlt_mode;
    la_uint_t die;
    la_uint_t channel;

    la_uint_t lane0_serdes_idx = m_anlt_lane[0] - m_serdes_base_id;

    serdes_speed_to_divider_t::const_iterator config = s_serdes_speed_to_divider.find(m_serdes_speed_gbps);
    if (config == s_serdes_speed_to_divider.end()) {
        // Not found
        log_err(SERDES, "Failed to find speed config for: %zd", m_serdes_speed_gbps);
        return LA_STATUS_EINVAL;
    }

    serdes_config_data serdes_data = config->second;

    // Setup default
    status = srm_anlt_rules_set_default(&rules);
    if (status != IP_OK) {
        log_err(SERDES, "SerDes %d/%d/%d failed srm_anlt_rules_set_default", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    anlt_mode = ((m_speed == la_mac_port::port_speed_e::E_400G)
                     ? SRM_AN_MODE_BROADCOM_NP
                     : ((m_speed == la_mac_port::port_speed_e::E_50G) && (m_serdes_count == 2)) ? SRM_AN_MODE_50G_CONSORTIUM_NP
                                                                                                : SRM_AN_MODE_IEEE);

    // Auto-neg rules for AN leader.
    rules.an.enable = true;
    rules.an.probe = false; // TRUE - Probe (AN) only.  FALSE - LT/Link up.
    rules.an.mode = (e_srm_anlt_mode)anlt_mode;
    rules.an.retry_threshold = SRM_AN_RETRY_THRESHOLD;
    rules.an.an_fec.capable = false; // // Deprecated according to Doc.
    rules.an.an_fec.request = false;

    int lt_timeout;
    if (serdes_data.pam4_enable) {
        // timeout unit in ms.
        lt_timeout = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT].int_val;
        // PAM4: (3s + 2%) as per 802.3cd_D2p5 (18th Sept 2018).
        lt_timeout += (lt_timeout * 0.02);
    } else {
        // timeout unit in ms.
        lt_timeout = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT].int_val;
    }
    rules.an.link_time_budget = lt_timeout;
    rules.an.an_pause_ability = SRM_AN_AN_PAUSE_ABILITY;
    rules.an.an_remote_fault = SRM_AN_AN_REMOTE_FAULT;
    rules.an.port_shut = false;
    rules.an.advanced[0] = 0x00; // hw queue
    rules.an.lt_timer_disable = false;
    rules.an.nonce_chk_disable = false;
    rules.an.llfec_con.lf1_capable = 0;
    rules.an.llfec_con.lf2_capable = 0;
    rules.an.llfec_con.lf3_capable = 0;
    rules.an.llfec_con.ll_rs272_request = 0;

    // Clear all advertise speeds.
    rules.an.an_10gbase_kr.advertise = false;
    rules.an.an_25gbase_kr.advertise = false;
    rules.an.an_40gbase_kr4.advertise = false;
    rules.an.an_40gbase_cr4.advertise = false;
    rules.an.an_50gbase_kr.advertise = false;
    rules.an.an_50gbase_kr2.advertise = false;
    rules.an.an_50gbase_cr2.advertise = false;
    rules.an.an_100gbase_kr2.advertise = false;
    rules.an.an_100gbase_kr4.advertise = false;
    rules.an.an_100gbase_cr4.advertise = false;
    rules.an.an_200gbase_kr4.advertise = false;
    rules.an.an_400gbase_kr8.advertise = false;

    switch (m_an_spec_cap) {
    case serdes_handler::an_capability_code_e::E_10GBASE_KR:
        rules.an.an_10gbase_kr.advertise = true;
        rules.an.an_10gbase_kr.fec[0].request = (m_an_fec_request == 1);
        rules.an.an_10gbase_kr.fec[0].capable = (m_an_fec_request == 1);
        rules.an.an_10gbase_kr.fec[1].request = false;
        rules.an.an_10gbase_kr.fec[1].capable = false;
        rules.an.an_10gbase_kr.fec[2].request = false;
        rules.an.an_10gbase_kr.fec[2].capable = false;
        break;
    case serdes_handler::an_capability_code_e::E_25GBASE_KRCR:
        rules.an.an_25gbase_kr.advertise = true;
        rules.an.an_25gbase_kr.fec[0].request = false;
        rules.an.an_25gbase_kr.fec[0].capable = false;
        rules.an.an_25gbase_kr.fec[1].request = (m_an_fec_request == 1);
        rules.an.an_25gbase_kr.fec[1].capable = (m_an_fec_request == 1);
        rules.an.an_25gbase_kr.fec[2].request = false;
        rules.an.an_25gbase_kr.fec[2].capable = false;
        break;
    case serdes_handler::an_capability_code_e::E_40GBASE_CR4:
        rules.an.an_40gbase_cr4.advertise = true;
        rules.an.an_40gbase_cr4.fec[0].request = false;
        rules.an.an_40gbase_cr4.fec[0].capable = false;
        rules.an.an_40gbase_cr4.fec[1].request = (m_an_fec_request == 1);
        rules.an.an_40gbase_cr4.fec[1].capable = (m_an_fec_request == 1);
        rules.an.an_40gbase_cr4.fec[2].request = false;
        rules.an.an_40gbase_cr4.fec[2].capable = false;
        break;
    case serdes_handler::an_capability_code_e::E_50GBASE_KR_CR:
        if (m_serdes_count == 1) {
            rules.an.an_50gbase_kr.advertise = true;
            rules.an.an_50gbase_kr.fec[0].request = false;
            rules.an.an_50gbase_kr.fec[0].capable = false;
            rules.an.an_50gbase_kr.fec[1].request = false;
            rules.an.an_50gbase_kr.fec[1].capable = false;
            rules.an.an_50gbase_kr.fec[2].request = (m_an_fec_request == 1);
            rules.an.an_50gbase_kr.fec[2].capable = (m_an_fec_request == 1);
        } else {
            // 50G, 2 serdes Consortium, use serdes_speed_gbps for FEC setting.
            if (m_serdes_speed_gbps == 25) {
                rules.an.an_50gbase_kr2.advertise = true;
                rules.an.an_50gbase_kr2.fec[0].request = false;
                rules.an.an_50gbase_kr2.fec[0].capable = false;
                rules.an.an_50gbase_kr2.fec[1].request = (m_an_fec_request == 1);
                rules.an.an_50gbase_kr2.fec[1].capable = (m_an_fec_request == 1);
                rules.an.an_50gbase_kr2.fec[2].request = false;
                rules.an.an_50gbase_kr2.fec[2].capable = false;
            } else { // m_serdes_speed_gbps = 26
                rules.an.an_50gbase_cr2.advertise = true;
                rules.an.an_50gbase_cr2.fec[0].request = false;
                rules.an.an_50gbase_cr2.fec[0].capable = false;
                rules.an.an_50gbase_cr2.fec[1].request = false;
                rules.an.an_50gbase_cr2.fec[1].capable = false;
                rules.an.an_50gbase_cr2.fec[2].request = (m_an_fec_request == 1);
                rules.an.an_50gbase_cr2.fec[2].capable = (m_an_fec_request == 1);
            }
        }
        break;
    case serdes_handler::an_capability_code_e::E_100GBASE_CR4:
        rules.an.an_100gbase_cr4.advertise = true;
        rules.an.an_100gbase_cr4.fec[0].request = false;
        rules.an.an_100gbase_cr4.fec[0].capable = false;
        rules.an.an_100gbase_cr4.fec[1].request = (m_an_fec_request == 1);
        rules.an.an_100gbase_cr4.fec[1].capable = (m_an_fec_request == 1);
        rules.an.an_100gbase_cr4.fec[2].request = false;
        rules.an.an_100gbase_cr4.fec[2].capable = false;
        break;
    case serdes_handler::an_capability_code_e::E_100GBASE_KR2_CR2:
        rules.an.an_100gbase_kr2.advertise = true;
        rules.an.an_100gbase_kr2.fec[0].request = false;
        rules.an.an_100gbase_kr2.fec[0].capable = false;
        rules.an.an_100gbase_kr2.fec[1].request = false;
        rules.an.an_100gbase_kr2.fec[1].capable = false;
        rules.an.an_100gbase_kr2.fec[2].request = (m_an_fec_request == 1);
        rules.an.an_100gbase_kr2.fec[2].capable = (m_an_fec_request == 1);
        break;
    case serdes_handler::an_capability_code_e::E_200GBASE_KR4_CR4:
        rules.an.an_200gbase_kr4.advertise = true;
        rules.an.an_200gbase_kr4.fec[0].request = false;
        rules.an.an_200gbase_kr4.fec[0].capable = false;
        rules.an.an_200gbase_kr4.fec[1].request = false;
        rules.an.an_200gbase_kr4.fec[1].capable = false;
        rules.an.an_200gbase_kr4.fec[2].request = (m_an_fec_request == 1);
        rules.an.an_200gbase_kr4.fec[2].capable = (m_an_fec_request == 1);
        break;
    default:
        if ((m_speed == la_mac_port::port_speed_e::E_400G)
            && (m_an_spec_cap == serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY)) {
            rules.an.an_400gbase_kr8.advertise = true;
            rules.an.an_400gbase_kr8.fec[0].request = false;
            rules.an.an_400gbase_kr8.fec[0].capable = false;
            rules.an.an_400gbase_kr8.fec[1].request = false;
            rules.an.an_400gbase_kr8.fec[1].capable = false;
            rules.an.an_400gbase_kr8.fec[2].request = (m_an_fec_request == 1);
            rules.an.an_400gbase_kr8.fec[2].capable = (m_an_fec_request == 1);
        } else {
            log_err(SERDES,
                    "Slice/IFG/SerDes %d/%d/%d Couldn't fill AN rules for this capability %d",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    int(m_an_spec_cap));
        }
        break;
    }

    // Link training rules for the LT followers.
    rules.lt.enable = true;
    rules.lt.tune_term = false;                     // Terminate training permaturely
    rules.lt.clk_src = SRM_ANLT_LT_LOCAL_REFERENCE; // SRM_ANLT_LT_LOCAL_REFERENCE or SRM_ANLT_LT_RECOVERED_CLOCK
    rules.lt.retry_threshold = SRM_LT_RETRY_THRESHOLD;
    rules.lt.target_snr = serdes_data.pam4_enable ? SRM_LT_PAM4_TARGET_SNR : SRM_LT_NRZ_TARGET_SNR;
    rules.lt.ctle_tune = true;
    rules.lt.extended_link_time = 0;      // Default value from sample code  DEFAULT=0
    rules.lt.algorithm = 0;               // Default value from sample code
    rules.lt.algo_cycle = 0x0000;         // Default value from sample code
    rules.lt.ctle_cache = true;           // Default value from sample code
    rules.lt.honor_ieee_link_time = true; // Default value from sample code
    rules.lt.auto_invert = false;
    rules.lt.bypass_fir_walk = false;

    if (serdes_data.pam4_enable) {
        int preset_sel = m_device->m_device_properties[(int)la_device_property_e::SERDES_CL136_PRESET_TYPE].int_val;
        switch (preset_sel) {
        // PRESET_2
        case 2:
            rules.lt.algo_cycle = 0x0000;
            rules.lt.algorithm = 0x14; // User defined.
            rules.lt.cl136_preset = (e_srm_anlt_lt_cl136_preset_type)preset_sel;
            rules.lt.bypass_fir_walk = true;
            rules.lt.target_snr = 18000;
            break;
        default: // PRESET_1 and PRESET_3
            rules.lt.cl136_preset = (e_srm_anlt_lt_cl136_preset_type)preset_sel;
            rules.lt.bypass_fir_walk = false;
            break;
        }
    }

    get_serdes_addr(lane0_serdes_idx, la_serdes_direction_e::TX, die);
    stat = get_serdes_channel(lane0_serdes_idx, la_serdes_direction_e::TX, channel);
    return_on_error(stat);

    // Build ANLT tx_rules and rx_rules
    stat = set_anlt_tx_bundle_rules(rules.tx);
    return_on_error(stat);

    stat = set_anlt_rx_bundle_rules(rules.rx);
    return_on_error(stat);

    // Use the dfe_precoder_en in RX rules which is already setup to either enable or disable precoder and update
    // the link-training-rules auto_rx_precode_threshold accordingly.  Precoder support for PAM4 only.
    bool enable_rx_precoder = rules.rx.dfe_precoder_en;
    int rx_precode_threshold = get_serdes_parameter_val(
        0, la_mac_port::serdes_param_e::AUTO_RX_PRECODE_THRESHOLD, DEFAULT_ANLT_AUTO_RX_PRECODE_THRESHOLD);
    rules.lt.auto_rx_precode_threshold
        = (enable_rx_precoder && serdes_data.pam4_enable) ? rx_precode_threshold : DISABLE_ANLT_AUTO_RX_PRECODE_THRESHOLD;

    // Use RX Die to get the PLL rule.
    die = m_bundle.lt_followers[0].rx_die;
    status = srm_pll_rules_query(die, &rules.pll);
    if (status != IP_OK) {
        log_err(SERDES, "SerDes %d/%d/%d failed srm_pll_rules_query", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    // Start the ANLT
    stat = csco_srm_anlt_init(&m_bundle, &rules);
    if (stat != LA_STATUS_SUCCESS) {
        log_err(SERDES, "SerDes %d/%d/%d failed csco_srm_anlt_init", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    state = la_mac_port::state_e::AN_COMPLETE;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::print_srm_fsm_state(la_uint_t die)
{

    srm_fsm_state_t dbg_state;
    srm_dbg_fsm_query(die, &dbg_state);

    log_xdebug(SERDES, "%d/%d/%d die: %d", m_slice_id, m_ifg_id, m_serdes_base_id, die);
    log_xdebug(SERDES, "chip_init: %d", dbg_state.chip_init);
    log_xdebug(SERDES, "pll_init: %d", dbg_state.pll_init);
    log_xdebug(SERDES, "tx_init[0]: %d tx_init[1]: %d", dbg_state.tx_init[0], dbg_state.tx_init[1]);
    log_xdebug(SERDES, "rx_init[0]: %d rx_init[1]: %d", dbg_state.rx_init[0], dbg_state.rx_init[1]);

    log_xdebug(SERDES, "tx_pmd_state[0]: %d tx_pmd_state[1]: %d", dbg_state.tx_pmd_state[0], dbg_state.tx_pmd_state[1]);
    log_xdebug(SERDES, "rx_pmd_state[0]: %d rx_pmd_state[1]: %d", dbg_state.rx_pmd_state[0], dbg_state.rx_pmd_state[1]);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::an_stop()
{
    la_status stat = teardown_anlt();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::link_training_start(la_mac_port::state_e& state)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::is_an_good_check(bool& an_good_check, la_mac_port::state_e& state)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::an_base_page_rcv(la_mac_port::state_e& state)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::an_next_page_rcv(la_mac_port::state_e& state)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::read_srm_rx_snr()
{

    if (!m_is_an_enabled)
        return LA_STATUS_SUCCESS;

    for (size_t i = 0; i < m_bundle.num_followers; i++) {
        uint32_t rx_die = m_bundle.lt_followers[i].rx_die;
        uint32_t rx_channel = m_bundle.lt_followers[i].rx_channel;

        if (!srm_rx_dsp_snr_mon_enabled(rx_die, rx_channel)) {
            srm_rx_dsp_snr_mon_cfg(rx_die, rx_channel, SRM_RX_DSP_ERR_GEN1_NO_RC, SRM_RX_SNR_SYMBOL_COUNT_2EXP16);
            srm_rx_dsp_snr_mon_en(rx_die, rx_channel, true);
        }

        float rx_snr_val = srm_rx_dsp_snr_read_db(rx_die, rx_channel);
        log_info(SERDES,
                 "%d/%d/%d RX_DIE: 0x%04X CH: %d SNR: %2.12f",
                 m_slice_id,
                 m_ifg_id,
                 (int)(m_serdes_base_id + i),
                 (int)rx_die,
                 (int)rx_channel,
                 rx_snr_val);
    }
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::is_an_completed(bool& out_completed)
{
    out_completed = false;
    e_srm_anlt_an_status an_status = srm_anlt_get_an_status(&m_bundle);

    // Updating the AN status histogram
    if (an_status != curr_an_status) {
        rx_spare9_histogram[(int)an_status]++;
        curr_an_status = an_status;

        // Do not add history if queue max_size is 0 or not set.
        if (m_rx_sp9_state_transition_queue.max_size() > 0) {
            rx_sp9_state_transition rx_serdes_state{};
            size_t buffer_size = 100;
            char timestamp[buffer_size];
            add_timestamp(timestamp, sizeof(timestamp));
            rx_serdes_state.rx_state = (int)an_status;
            rx_serdes_state.timestamp = std::string(timestamp);
            m_rx_sp9_state_transition_queue.push(rx_serdes_state);
        }
    }

    log_debug(SERDES,
              "Slice/IFG/SerDes %d/%d/%d an_status: %d - %s",
              m_slice_id,
              m_ifg_id,
              m_serdes_base_id,
              an_status,
              srm_anlt_dbg_an_status_translate(an_status));

    // Dump the FSM state for RX/TX die.
    logger& instance = logger::instance();
    if (instance.is_logging(
            silicon_one::get_device_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::XDEBUG)) {
        // DEBUG supports different RX and TX DIE for the leader in the bundle; print FSM state for both.
        log_xdebug(
            SERDES, "%s: %d/%d/%d - RX_DIE: 0x%04x", __func__, m_slice_id, m_ifg_id, m_serdes_base_id, m_bundle.an_leader.rx_die);
        print_srm_fsm_state(m_bundle.an_leader.rx_die);
        log_xdebug(
            SERDES, "%s: %d/%d/%d - TX_DIE: 0x%04x", __func__, m_slice_id, m_ifg_id, m_serdes_base_id, m_bundle.an_leader.tx_die);
        print_srm_fsm_state(m_bundle.an_leader.tx_die);
    }

    if (an_status == SRM_AN_STATUS_FAIL) {
        get_serdes_state("ERROR");
        return LA_STATUS_EUNKNOWN;
    } else if (an_status == SRM_AN_STATUS_COMPLETE) {
        get_serdes_state("ANLT COMPLETE");
        out_completed = true;
    } else {
        get_serdes_state("ANLT IN PROGRESS");
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::link_training_handler(la_mac_port::state_e& state)
{
    e_srm_anlt_an_status status;
    status = srm_anlt_get_an_status(&m_bundle);
    if (status == SRM_AN_STATUS_FAIL) {
        return LA_STATUS_EUNKNOWN;
    } else if (status >= SRM_AN_STATUS_LT_COMPLETE) {
        state = la_mac_port::state_e::AN_COMPLETE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    // Check if valid serdes_idx
    if (serdes_idx >= m_serdes_count) {
        log_err(SERDES, "SerDes Index: %u is out of expected range [0-%lu]", serdes_idx, (m_serdes_count - 1));
        return LA_STATUS_EOUTOFRANGE;
    }

    if (mode > la_mac_port::serdes_test_mode_e::LAST) {
        return LA_STATUS_EINVAL;
    }

    srm_prbs_gen_rules_t gen_rules;
    srm_prbs_chk_rules_t chk_rules;

    if (mode == la_mac_port::serdes_test_mode_e::NONE) {
        srm_prbs_gen_rules_set_default(&gen_rules);
        gen_rules.en = false;

        srm_prbs_chk_rules_set_default(&chk_rules);
        chk_rules.en = false;
    } else {
        srm_prbs_gen_rules_set_default(&gen_rules);
        gen_rules.en = true;
        gen_rules.gen_en_lsb = false; // This generates PRBS for MSB & LSB separately.
        gen_rules.prbs_mode = SRM_PRBS_MODE_COMBINED;

        auto elem = serdes_test_mode_data.find(mode);
        if (elem->first != mode)
            return LA_STATUS_EINVAL;

        gen_rules.prbs_pattern = elem->second.prbs_pattern;
        gen_rules.pattern_mode = elem->second.pattern_mode;

        srm_prbs_chk_rules_set_default(&chk_rules);
        chk_rules.prbs_mode = SRM_PRBS_MODE_COMBINED;
        chk_rules.en = true;
        chk_rules.prbs_pattern = elem->second.prbs_pattern;
    }

    la_uint_t tx_serdes = m_serdes_base_id + serdes_idx;
    if (direction == la_serdes_direction_e::TX) {
        la_uint_t tx_die;
        la_status stat = get_serdes_addr(serdes_idx, la_serdes_direction_e::TX, tx_die);
        return_on_error(stat);
        la_uint_t tx_channel;
        stat = get_serdes_channel(serdes_idx, la_serdes_direction_e::TX, tx_channel);
        return_on_error(stat);

        // Enable PRBS generator
        ip_status_t status = srm_prbs_gen_config(tx_die, tx_channel, SRM_INTF_SERIAL_TX, &gen_rules);
        if (status != IP_OK) {
            log_err(HLD, "SerDes %d/%d/%d failed initializing the PRBS generator", m_slice_id, m_ifg_id, tx_serdes);
            return LA_STATUS_EUNKNOWN;
        }
    } else {
        m_serdes_lane_test_mode[serdes_idx] = mode;

        la_uint_t rx_die;
        la_status stat = get_serdes_addr(serdes_idx, la_serdes_direction_e::RX, rx_die);
        return_on_error(stat);
        la_uint_t rx_channel;
        stat = get_serdes_channel(serdes_idx, la_serdes_direction_e::RX, rx_channel);
        return_on_error(stat);

        // Enable PRBS checker
        ip_status_t status = srm_prbs_chk_config(rx_die, rx_channel, SRM_INTF_SERIAL_RX, &chk_rules);
        if (status != IP_OK) {
            log_err(HLD, "SerDes %d/%d/%d failed initializing the PRBS checker", m_slice_id, m_ifg_id, tx_serdes);
            return LA_STATUS_EUNKNOWN;
        }

        if (mode == la_mac_port::serdes_test_mode_e::NONE) {
            if (srm_prbs_chk_is_enabled(rx_die, rx_channel, SRM_INTF_SERIAL_RX)) {
                log_err(HLD, "SerDes %d/%d/%d PRBS checker is still enabled.", m_slice_id, m_ifg_id, tx_serdes);
                return LA_STATUS_EUNKNOWN;
            }
        } else {
            if (!srm_prbs_chk_is_enabled(rx_die, rx_channel, SRM_INTF_SERIAL_RX)) {
                log_err(HLD, "SerDes %d/%d/%d PRBS checker is not enabled.", m_slice_id, m_ifg_id, tx_serdes);
                return LA_STATUS_EUNKNOWN;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_status stat = set_test_mode(serdes, direction, mode);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::read_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    // Check if valid serdes_idx
    if (serdes_idx >= m_serdes_count) {
        log_err(SERDES, "SerDes Index: %u is out of expected range [0-%lu]", serdes_idx, (m_serdes_count - 1));
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t rx_serdes = m_serdes_base_id + serdes_idx;
    la_uint_t rx_die;
    la_status stat = get_serdes_addr(serdes_idx, la_serdes_direction_e::RX, rx_die);
    return_on_error(stat);
    la_uint_t rx_channel;
    stat = get_serdes_channel(serdes_idx, la_serdes_direction_e::RX, rx_channel);
    return_on_error(stat);

    if (m_serdes_lane_test_mode[serdes_idx] == la_mac_port::serdes_test_mode_e::NONE) {
        log_debug(SERDES, "SerDes %d/%d/%d is not in serdes test mode.", m_slice_id, m_ifg_id, rx_serdes);

        out_serdes_prbs_ber.lane_ber[serdes_idx] = 0;
        out_serdes_prbs_ber.count[serdes_idx] = 0;
        out_serdes_prbs_ber.errors[serdes_idx] = 0;
        out_serdes_prbs_ber.prbs_lock[serdes_idx] = 0;
    } else {
        srm_prbs_chk_status_t chk_status;
        ip_status_t status = srm_prbs_chk_status(rx_die, rx_channel, SRM_INTF_SERIAL_RX, &chk_status);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed getting PRBS checker status", m_slice_id, m_ifg_id, rx_serdes);
            return LA_STATUS_EUNKNOWN;
        }

        // Calculate BER based on PRBS checker status structure
        double ber, ber_lsb;
        status = srm_prbs_chk_ber(&chk_status, &ber, &ber_lsb);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed calculating PRBS BER", m_slice_id, m_ifg_id, rx_serdes);
            return LA_STATUS_EUNKNOWN;
        }

        if (!chk_status.prbs_lock) {
            log_err(SERDES, "SerDes %d/%d/%d has no PRBS lock.", m_slice_id, m_ifg_id, rx_serdes);
            // Failure - no PRBS lock.
            return LA_STATUS_EUNKNOWN;
        }
        // Received PRBS pattern, PRBS invert status, Total bit counter saturation
        log_debug(SERDES,
                  "SerDes %d/%d/%d: \n"
                  "PRBS pattern: %d, PRBS invert status: %d, Total bit count saturated: %s\n"
                  "Errors: %d, Total bits: %ld, BER: %e, PRBS Lock: %s\n", // added %e for scientific notation
                  m_slice_id,
                  m_ifg_id,
                  rx_serdes,
                  (chk_status.prbs_pattern + 1),
                  chk_status.prbs_inv,
                  chk_status.prbs_total_bit_count_saturated ? "yes" : "no",
                  chk_status.prbs_error_bit_count,
                  chk_status.prbs_total_bit_count,
                  ber,
                  chk_status.prbs_lock ? "yes" : "no");

        // If total bit count is saturated, invalid result.
        if (chk_status.prbs_total_bit_count_saturated) {
            log_err(SERDES, "SerDes %d/%d/%d total bit count saturated.", m_slice_id, m_ifg_id, rx_serdes);
            ber = -1;
        }

        out_serdes_prbs_ber.lane_ber[serdes_idx] = ber;
        out_serdes_prbs_ber.count[serdes_idx] = chk_status.prbs_total_bit_count;
        out_serdes_prbs_ber.errors[serdes_idx] = chk_status.prbs_error_bit_count;
        out_serdes_prbs_ber.prbs_lock[serdes_idx] = chk_status.prbs_lock;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::read_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_status stat = read_test_ber(serdes, out_serdes_prbs_ber);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::enable_low_power(bool enable)
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_serdes_speed_gbps(size_t serdes_speed_gbps)
{
    m_serdes_speed_gbps = serdes_speed_gbps;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_anlt_capabilities(bool enable, an_capability_code_e an_spec_cap, size_t an_fec_request)
{
    m_is_an_enabled = enable;
    m_an_spec_cap = an_spec_cap;
    m_an_fec_request = an_fec_request;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_tuning_mode(la_mac_port::serdes_tuning_mode_e mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::set_debug_mode(bool mode)
{
    m_debug_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::get_serdes_state(const char* message)
{
    la_int_t rx_die_bundle_fsm[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    bool update_history = false;

    la_int_t tx_die_fsm = srm_reg_read(m_bundle.an_leader.tx_die,
                                       SRM_TX_AN_SPARE9__ADDRESS + (m_bundle.an_leader.tx_channel * SRM_TXRX_CHANNEL_OFFSET));

    for (size_t i = 0; i < m_serdes_count; i++) {
        rx_die_bundle_fsm[i]
            = srm_reg_read(m_bundle.lt_followers[i].rx_die,
                           SRM_TX_AN_SPARE9__ADDRESS + (m_bundle.lt_followers[i].rx_channel * SRM_TXRX_CHANNEL_OFFSET));
    }

    // Entry 0 is the leader
    if (rx_die_bundle_fsm[0] != curr_tx_spare9_fsm_state[0]) {
        if (rx_die_bundle_fsm[0] <= SRM_TX_SPARE9_LAST_VALID_STATE)
            // The read returns value ranging from -1..20.  Array index starts at 0, adjust the array index.
            tx_spare9_histogram[(rx_die_bundle_fsm[0] + 1)]++;
        else
            tx_spare9_histogram[SRM_TX_SPARE9_INVALID_STATE_ENTRY]++; // Should not come here. Unknown FSM entry
        curr_tx_spare9_fsm_state[0] = rx_die_bundle_fsm[0];
        update_history = true;
    }

    // Now check other serdes to see if one or more had changed state.
    // Update the new state for other serdes.
    for (size_t i = 1; i < m_serdes_count; i++) {
        if (rx_die_bundle_fsm[i] != curr_tx_spare9_fsm_state[i]) {
            update_history = true;
        }
        curr_tx_spare9_fsm_state[i] = rx_die_bundle_fsm[i];
    }

    if (update_history) {
        // Do not add history if queue max_size is 0 or not set.
        if (m_tx_sp9_state_transition_queue.max_size() > 0) {
            tx_sp9_state_transition tx_serdes_state{};
            size_t buffer_size = 100;
            char timestamp[buffer_size];
            add_timestamp(timestamp, sizeof(timestamp));
            tx_serdes_state.timestamp = std::string(timestamp);
            tx_serdes_state.rx_state = curr_an_status;
            for (size_t i = 0; i < m_serdes_count; i++) {
                tx_serdes_state.tx_state[i] = curr_tx_spare9_fsm_state[i];
            }
            m_tx_sp9_state_transition_queue.push(tx_serdes_state);
        }
    }

    log_debug(SERDES,
              "SERDES_STATE: %s: %d/%d/%d - RX_DIE: 0x%08X FSM: %d TX_DIE: 0x%08X FSM: %d",
              message,
              m_slice_id,
              m_ifg_id,
              m_serdes_base_id,
              m_bundle.an_leader.rx_die,
              (int)rx_die_bundle_fsm[0],
              m_bundle.an_leader.tx_die,
              (int)tx_die_fsm);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::set_continuous_tuning_enabled(bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::setup_test_counter(la_mac_port::serdes_test_mode_e mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

// save_state can provide debug information in 3 ways:
// 1. SerDes debug trace prints.
// 2. json_t pointer which provides the JSON tree with SerDes state information.
// 3. Through an output file, specified at the SDK API level which contains the json tree saved to a file.
la_status
srm_serdes_handler::save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root)
{
    if (!m_is_initialized) {
        return LA_STATUS_SUCCESS;
    }

    if (info_type > la_mac_port::port_debug_info_e::LAST) {
        log_err(SERDES, "Invalid debug option.\n");
        return LA_STATUS_EINVAL;
    }

    la_mac_port::port_debug_info_e num_debug_info;
    la_mac_port::port_debug_info_e info_type_start;
    // Provide support to save all debug information, or only 1 at a time.
    if (info_type == la_mac_port::port_debug_info_e::ALL || info_type == la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG) {
        num_debug_info = info_type;
        info_type_start = la_mac_port::port_debug_info_e::FIRST;
    } else {
        // If only one debug type, only go through the switch statement once.
        num_debug_info = (la_mac_port::port_debug_info_e)((la_uint_t)info_type + 1);
        info_type_start = info_type;
    }

    uint32_t loop_delay = num_debug_info <= la_mac_port::port_debug_info_e::ALL ? 1 : 1000; // in ms

    // ip_status_t status;
    la_status stat;
    // Query and store different debug data.
    for (size_t i = (la_uint_t)info_type_start; i < (la_uint_t)num_debug_info; i++) {
        info_type = (la_mac_port::port_debug_info_e)i;
        switch (info_type) {
        case la_mac_port::port_debug_info_e::SERDES_STATUS:
            stat = add_link_status(out_root);
            return_on_error(stat);
            stat = add_anlt_status(out_root);
            return_on_error(stat);
            break;
        case la_mac_port::port_debug_info_e::SERDES_CONFIG:
            stat = add_link_config(out_root);
            return_on_error(stat);
            stat = add_mcu_status(out_root, loop_delay);
            return_on_error(stat);
            stat = add_anlt_bundle(out_root);
            return_on_error(stat);
            break;
        case la_mac_port::port_debug_info_e::SERDES_EYE_CAPTURE:
            stat = add_eye_capture(out_root);
            return_on_error(stat);
            break;
        case la_mac_port::port_debug_info_e::SERDES_REG_DUMP:
            stat = add_serdes_reg_dump(out_root);
            return_on_error(stat);
            break;
        case la_mac_port::port_debug_info_e::ALL:
        case la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG:
            break;
        default:
            log_debug(SERDES, "Debug type %s not supported.\n", to_string(info_type).c_str());
            break;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::srm_pll_status_query(la_uint_t die, srm_pll_status& pll_status)
{
    uint32_t nn, mm, baud_rate, frac_div;

    uint16_t fsm_cfg0 = SRM_PLL_PLLD_FSM_CMD_CFG0__READ(die);
    uint16_t fsm_ints = SRM_PLL_PLLD_FSM_INTS__READ(die);
    uint16_t fsm_done = SRM_PLL_PLLD_FSM_CMD_FSM_DONE_STATUS0__READ(die);

    uint16_t top_init_req = SRM_TOP_INIT_REQ__READ(die);
    uint16_t top_init_ack = SRM_TOP_INIT_ACK__READ(die);

    bool pll_fsm_start = fsm_cfg0 & 0x1;
    bool pll_out_of_lock = fsm_ints & 0x1;
    bool pll_lock = fsm_done & 0x1;

    nn = SRM_PLL_PLLD_FBDSM_CFG0__READ(die) << 0;
    nn |= SRM_PLL_PLLD_FBDSM_CFG1__READ(die) << 8;
    nn |= SRM_PLL_PLLD_FBDSM_CFG2__READ(die) << 16;
    nn |= SRM_PLL_PLLD_FBDSM_CFG3__READ(die) << 24;

    mm = SRM_PLL_PLLD_FBDSM_CFG8__READ(die);

    frac_div = mm + (nn >> 24);
    baud_rate = 156250 * frac_div;

    pll_status.top_init_req = top_init_req;
    pll_status.top_init_ack = top_init_ack;
    pll_status.pll_fsm_start = pll_fsm_start;
    pll_status.pll_out_of_lock = pll_out_of_lock;
    pll_status.pll_lock = pll_lock;
    pll_status.baud_rate = baud_rate;
    pll_status.baud_rate_mm = mm;
    pll_status.baud_rate_nn = nn;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_link_status(json_t* json_node)
{
    json_t* serdes_status_root = json_object();

    for (auto die_tuple : m_die_set) {
        la_uint_t serdes_idx = std::get<0>(die_tuple);
        la_uint_t die = std::get<1>(die_tuple);
        la_serdes_direction_e direction = std::get<2>(die_tuple);
        la_uint_t channel;
        la_status stat = get_serdes_channel(serdes_idx, direction, channel);
        return_on_error(stat);

        // Create a node to store the SerDes PLL information.
        json_t* serdes_pll_root = json_object();

        srm_pll_status pll_status;
        stat = srm_pll_status_query(die, pll_status);
        return_on_error(stat);

        json_object_set_new(serdes_pll_root, "TOP_INIT_REQ", json_integer(pll_status.top_init_req));
        json_object_set_new(serdes_pll_root, "TOP_INIT_ACK", json_integer(pll_status.top_init_ack));
        json_object_set_new(serdes_pll_root, "PLL_FSM_STARTED", json_integer(pll_status.pll_fsm_start));
        json_object_set_new(serdes_pll_root, "PLL_OUT_OF_LOCK", json_integer(pll_status.pll_out_of_lock));
        json_object_set_new(serdes_pll_root, "PLL_LOCK", json_integer(pll_status.pll_lock));
        json_object_set_new(serdes_pll_root, "BAUD_RATE", json_integer(pll_status.baud_rate));
        json_object_set_new(serdes_pll_root, "BAUD_RATE_NN", json_integer(pll_status.baud_rate_nn));
        json_object_set_new(serdes_pll_root, "BAUD_RATE_MM", json_integer(pll_status.baud_rate_mm));

        // Place PLL lock time if record exists
        if (m_die_pll_lock_time.find(die) != m_die_pll_lock_time.end()) {
            json_object_set_new(serdes_pll_root, "PLL_LOCK_TIME_MS", json_integer(m_die_pll_lock_time[die]));
        }

        std::string pll_label = "index_" + std::to_string(serdes_idx) + "_PLL";
        json_object_set_new(serdes_status_root, pll_label.c_str(), serdes_pll_root);

        // Create a node to store the SerDes information.
        json_t* serdes_param_root = json_object();

        // Define the SerDes information.
        define_serdes_json_info(serdes_param_root, serdes_idx, die, channel);

        std::string serdes_prefix = create_serdes_prefix("SERDES_STATUS", serdes_idx, die, channel);

        srm_link_status_t link_status;
        ip_status_t status = srm_link_status_query(
            die, channel, (direction == la_serdes_direction_e::RX) ? SRM_INTF_DIR_RX : SRM_INTF_DIR_TX, &link_status);
        if (status != IP_OK) {
            log_err(SERDES, "%s: failed to query link status.", serdes_prefix.c_str());
            return LA_STATUS_EUNKNOWN;
        }

        if (direction == la_serdes_direction_e::RX) {
            // SNR
            double snr_db;
            snr_db = srm_rx_dsp_snr_read_db(die, channel);
            log_debug(SERDES, "%s: SNR(dB)=%f", serdes_prefix.c_str(), snr_db);

            json_object_set_new(serdes_param_root, "SNR", json_real(snr_db));

            // Create a node to store the Link Status information.
            json_t* link_status_json = json_object();
            log_debug(SERDES,
                      "%s: RX_SIG_DET=%d, RX_DSP_RDY=%d, RX_FW_LOCK=%d",
                      serdes_prefix.c_str(),
                      link_status.rx_sdt,
                      link_status.rx_dsp_ready,
                      link_status.rx_fw_lock);

            json_object_set_new(link_status_json, "RX_SIG_DET", json_integer(link_status.rx_sdt));
            json_object_set_new(link_status_json, "RX_DSP_RDY", json_integer(link_status.rx_dsp_ready));
            json_object_set_new(link_status_json, "RX_FW_LOCK", json_integer(link_status.rx_fw_lock));

            json_object_set_new(serdes_param_root, "LINK_STATUS", link_status_json);

            // Create a node to store the Rx FFE information.
            json_t* rx_ffe_root = json_object();

            int16_t ffe_tap[SRM_FFE_TAP_COUNT];
            uint32_t afe_trim = 0;
            uint32_t pga_gain = 0;
            uint32_t dfe_tap = 0;
            uint32_t ctle_peak = 0;
            float dfe_tap_f = 0.0;
            srm_rx_rules_t rx_rules;

            status = srm_rx_rules_query(die, channel, &rx_rules);
            if (status != IP_OK) {
                log_err(SERDES, "%s: failed to query rx rules.", serdes_prefix.c_str());
                return LA_STATUS_EUNKNOWN;
            }
            bool is_dsp_mode = is_srm_dsp_mode_dfe(rx_rules.dsp_mode);

            status = srm_rx_dsp_ffe_taps_query(die, channel, 0, ffe_tap);
            if (status != IP_OK) {
                log_err(SERDES, "%s: failed to query rx FFE taps.", serdes_prefix.c_str());
                return LA_STATUS_EUNKNOWN;
            }

            uint32_t dsp_pga_high_gain_status
                = srm_reg_read(die, SRM_RX_DSP_PGA_HIGH_GAIN_STATUS_ADDRESS + channel * SRM_TXRX_CHANNEL_OFFSET);
            afe_trim = (dsp_pga_high_gain_status >> 9) & SRM_AFE_TRIM_MASK;
            pga_gain = dsp_pga_high_gain_status & SRM_PGA_GAIN_MASK;

            ctle_peak = srm_reg_read(die, SRM_RX_RXA_AFE_CTL2_CFG__ADDRESS + channel * SRM_TXRX_CHANNEL_OFFSET);

            dfe_tap = srm_reg_read(die, SRM_RX_DSP_PAM4_DFE_F1_STATUS__ADDRESS + channel * SRM_TXRX_CHANNEL_OFFSET);
            dfe_tap_f = (float)dfe_tap / 64.00;

            log_debug(SERDES,
                      "%s, FFE_TAP_PRE_CURSOR_3=%d, FFE_TAP_PRE_CURSOR_2=%d"
                      ", FFE_TAP_PRE_CURSOR_1=%d, FFE_TAP_MAIN_CURSOR=%d"
                      ", FFE_TAP_POST_CURSOR_1=%d, FFE_TAP_POST_CURSOR_2=%d, FFE_TAP_POST_CURSOR_3=%d, "
                      ", FFE_TAP_POST_CURSOR_4=%d, FFE_TAP_POST_CURSOR_5=%d, FFE_TAP_POST_CURSOR_6=%d"
                      ", AFE_TRIM=%d, PGA_GAIN=%d, CTLE_PEAK=%d, DFE_TAP=%f",
                      serdes_prefix.c_str(),
                      ffe_tap[SRM_FFE_TAP_PRE_CURSOR_4],
                      ffe_tap[SRM_FFE_TAP_PRE_CURSOR_3],
                      ffe_tap[SRM_FFE_TAP_PRE_CURSOR_2],
                      ffe_tap[SRM_FFE_TAP_PRE_CURSOR_1],
                      ffe_tap[SRM_FFE_TAP_MAIN_CURSOR],
                      ffe_tap[SRM_FFE_TAP_POST_CURSOR_1],
                      ffe_tap[SRM_FFE_TAP_POST_CURSOR_2],
                      ffe_tap[SRM_FFE_TAP_POST_CURSOR_3],
                      ffe_tap[SRM_FFE_TAP_POST_CURSOR_4],
                      ffe_tap[SRM_FFE_TAP_POST_CURSOR_5],
                      afe_trim,
                      pga_gain,
                      ctle_peak,
                      dfe_tap_f);

            /*
             * FFE_TAP enum name mis-match. SRM API need to fix this.
             */
            json_object_set_new(rx_ffe_root, "FFE_TAP_PRE_CURSOR_3", json_integer(ffe_tap[SRM_FFE_TAP_PRE_CURSOR_4]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_PRE_CURSOR_2", json_integer(ffe_tap[SRM_FFE_TAP_PRE_CURSOR_3]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_PRE_CURSOR_1", json_integer(ffe_tap[SRM_FFE_TAP_PRE_CURSOR_2]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_MAIN_CURSOR", json_integer(ffe_tap[SRM_FFE_TAP_PRE_CURSOR_1]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_POST_CURSOR_1", json_integer(ffe_tap[SRM_FFE_TAP_MAIN_CURSOR]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_POST_CURSOR_2", json_integer(ffe_tap[SRM_FFE_TAP_POST_CURSOR_1]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_POST_CURSOR_3", json_integer(ffe_tap[SRM_FFE_TAP_POST_CURSOR_2]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_POST_CURSOR_4", json_integer(ffe_tap[SRM_FFE_TAP_POST_CURSOR_3]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_POST_CURSOR_5", json_integer(ffe_tap[SRM_FFE_TAP_POST_CURSOR_4]));
            json_object_set_new(rx_ffe_root, "FFE_TAP_POST_CURSOR_6", json_integer(ffe_tap[SRM_FFE_TAP_POST_CURSOR_5]));
            json_object_set_new(rx_ffe_root, "AFE_TRIM", json_integer(afe_trim));
            json_object_set_new(rx_ffe_root, "PGA_GAIN", json_integer(pga_gain));
            json_object_set_new(rx_ffe_root, "CTLE_PEAK", json_integer(ctle_peak));

            if (is_dsp_mode)
                json_object_set_new(rx_ffe_root, "DFE_TAP", json_real(dfe_tap_f));

            json_object_set_new(serdes_param_root, "RX_FFE", rx_ffe_root);

            // Add RX precoder enable
            json_t* rx_precoder_root = json_object();
            uint32_t rx_dsp_mode = srm_reg_read(die, SRM_RX_DSP_DSP_MODE_CONTROL_CFG__ADDRESS + channel * SRM_TXRX_CHANNEL_OFFSET);
            json_object_set_new(rx_precoder_root, "PAM4OPD_EN", json_integer((rx_dsp_mode >> 2) & 1));
            json_object_set_new(serdes_param_root, "rx_precoder", rx_precoder_root);

        } else {
            json_t* link_status_json = json_object();
            log_debug(SERDES,
                      "%s: TX_FW_LOCK=%d, "
                      "TX_FIFO_A_EMPTY_INTR=%d, TX_FIFO_A_FULL_INTR=%d, "
                      "TX_FIFO_B_EMPTY=%d, TX_FIFO_B_FULL_INTR=%d",
                      serdes_prefix.c_str(),
                      link_status.tx_fw_lock,
                      link_status.tx_fifoa_empty_int,
                      link_status.tx_fifoa_full_int,
                      link_status.tx_fifob_empty_int,
                      link_status.tx_fifob_full_int);

            json_object_set_new(link_status_json, "TX_FW_LOCK", json_integer(link_status.tx_fw_lock));
            json_object_set_new(link_status_json, "TX_FIFO_A EMPTY_INTR", json_integer(link_status.tx_fifoa_empty_int));
            json_object_set_new(link_status_json, "TX_FIFO_A FULL_INTR:", json_integer(link_status.tx_fifoa_full_int));
            json_object_set_new(link_status_json, "TX_FIFO_B EMPTY_INTR", json_integer(link_status.tx_fifob_empty_int));
            json_object_set_new(link_status_json, "TX_FIFO_B FULL_INTR", json_integer(link_status.tx_fifob_full_int));
            json_object_set_new(serdes_param_root, "LINK_STATUS", link_status_json);

            // Add TX precoder enable
            json_t* tx_precoder_root = json_object();
            uint32_t tx_txd_clken = srm_reg_read(die, SRM_TX_TXD_CLKEN__ADDRESS + channel * SRM_TXRX_CHANNEL_OFFSET);
            json_object_set_new(tx_precoder_root, "PRECODER", json_integer((tx_txd_clken >> 12) & 1));
            uint32_t tx_txd_misc_cfg = srm_reg_read(die, SRM_TX_TXD_MISC_CFG__ADDRESS + channel * SRM_TXRX_CHANNEL_OFFSET);
            json_object_set_new(tx_precoder_root, "PRECODE_EN", json_integer((tx_txd_misc_cfg >> 3) & 1));
            json_object_set_new(serdes_param_root, "tx_precoder", tx_precoder_root);
        }

        std::string serdes_label = create_serdes_label(serdes_idx, direction);
        json_object_set_new(serdes_status_root, serdes_label.c_str(), serdes_param_root);
    }

    json_object_set_new(json_node, "serdes_status", serdes_status_root);
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::get_timestamp(std::string item_name,
                                  la_uint_t entry,
                                  la_uint_t total_entries,
                                  la_uint16_t long_buf[],
                                  json_t* json_timestamp)
{
    size_t entries_per_copy = total_entries / NUMBER_OF_TIMESTAMP_COPY;

    json_t* json_timestamp_item = json_array();
    for (size_t i = 0; i < NUMBER_OF_TIMESTAMP_COPY; i++) {
        la_uint_t entry_offset = entry + (i * entries_per_copy);
        if ((entry >= TX_FIR_PRE_TIMESTAMP_ENTRY) && (entry <= TX_FIR_POST_TIMESTAMP_ENTRY)) { // Display FIR in signed integer.
            short ts = long_buf[entry_offset];
            json_array_append(json_timestamp_item, json_integer(ts));
        } else {
            la_uint16_t ts = long_buf[entry_offset];
            json_array_append(json_timestamp_item, json_integer(ts));
        }
    }
    json_object_set_new(json_timestamp, item_name.c_str(), json_timestamp_item);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_anlt_status(json_t* json_node)
{

    if (!m_is_an_enabled) {
        return LA_STATUS_SUCCESS;
    }

    static std::string rx_sp9_state_name[] = {"SRM_AN_STATUS_BUSY",
                                              "SRM_AN_STATUS_RESOLVED",
                                              "SRM_AN_STATUS_LT_COMPLETE",
                                              "SRM_AN_STATUS_COMPLETE",
                                              "SRM_AN_STATUS_FAIL"};

    static std::string tx_sp9_state_name[]
        = {"FSM_-1_STATE_AN_ERROR",          "FSM_00_STATE_AN_RESET_PD",     "FSM_01_STATE_AN_IDLE",
           "FSM_02_STATE_AN_PMD_IDLE",       "FSM_03_STATE_AN_PMD_10G_NRZ",  "FSM_04_STATE_AN_TX_DISABLE",
           "FSM_05_STATE_AN_ABILITY_DETECT", "FSM_06_STATE_AN_ACK_DETECT",   "FSM_07_STATE_AN_COMPLETE_ACK",
           "FSM_08_STATE_AN_GOOD_CHECK",     "FSM_09_STATE_AN_PMD_RECONFIG", "FSM_10_STATE_AN_PMD_RECONFIG_LINK_BREAK",
           "FSM_11_STATE_AN_PMD_DATA_MODE",  "FSM_12_STATE_AN_PMD_INTF_UP",  "FSM_13_STATE_AN_NP_WAIT",
           "FSM_14_STATE_AN_GOOD",           "FSM_15_STATE_AN_TRAIN_INIT",   "FSM_16_STATE_AN_TRAIN_ACK_INIT",
           "FSM_17_STATE_AN_TRAIN",          "FSM_18_STATE_AN_RESTART",      "FSM_19_STATE_AN_RESTART_LINK_BREAK",
           "FSM_20_STATE_AN_DO_START",       "FSM_21_STATE_AN_UNKNOWN"};

    //
    // Add ANLT timestamp
    //
    json_t* time_stamp_root = json_object();
    for (size_t i = 0; i < m_bundle.num_followers; i++) {
        json_t* time_stamp_node = json_object();
        size_t serdes_idx = m_anlt_lane[i] - m_serdes_base_id;
        la_uint_t rx_die = m_bundle.lt_followers[i].rx_die;
        la_uint_t rx_channel = m_bundle.lt_followers[i].rx_channel;
        la_uint16_t long_buf[176];
        la_uint32_t byte_count;
        srm_anlt_timestamp_query(rx_die, rx_channel, long_buf, &byte_count);
        int len = sizeof(long_buf) / sizeof(long_buf[0]);

        define_serdes_json_info(time_stamp_node, serdes_idx, rx_die, rx_channel);
        for (auto it = timestamp_list.begin(); it != timestamp_list.end(); ++it) {
            get_timestamp(it->ts_name, it->ts_index, len, long_buf, time_stamp_node);
        }
        std::string index_str = "index_" + std::to_string(i) + "_bundle";
        json_object_set_new(time_stamp_root, index_str.c_str(), time_stamp_node);
    }

    json_object_set_new(json_node, "anlt_timestamp", time_stamp_root);

    //
    // Gather the finale AN State FSM for RX and TX serdes.
    //
    json_t* spare9_obj = json_object();
    for (size_t i = 0; i < m_bundle.num_followers; i++) {
        la_uint_t reg_adr, rx_die, tx_die, rx_channel, tx_channel;
        la_uint16_t rx_state, tx_state;

        rx_die = m_bundle.lt_followers[i].rx_die;
        rx_channel = m_bundle.lt_followers[i].rx_channel;
        tx_die = m_bundle.lt_followers[i].tx_die;
        tx_channel = m_bundle.lt_followers[i].tx_channel;

        reg_adr = SRM_TX_AN_SPARE9__ADDRESS + (SRM_TXRX_CHANNEL_OFFSET * rx_channel);
        rx_state = srm_reg_read(rx_die, reg_adr);
        reg_adr = SRM_TX_AN_SPARE9__ADDRESS + (SRM_TXRX_CHANNEL_OFFSET * tx_channel);
        tx_state = srm_reg_read(tx_die, reg_adr);

        std::string rx_die_str = "RX_DIE_0x" + to_hex_string(rx_die) + "_CH" + std::to_string(rx_channel);
        std::string tx_die_str = "TX_DIE_0x" + to_hex_string(tx_die) + "_CH" + std::to_string(tx_channel);
        std::string str = rx_die_str + "_" + tx_die_str;
        char fsm_ch[20];
        sprintf(fsm_ch, "RX-%02d  TX-%02d", rx_state, tx_state);

        json_object_set_new(spare9_obj, str.c_str(), json_string(fsm_ch));
    }

    json_object_set_new(json_node, "anlt_spare9_fsm", spare9_obj);

    //
    // Add RX serdes Spare9 FSM histogram
    //
    json_t* rx_spare9_hist_obj = json_object();
    for (size_t i = 0; i < SRM_RX_SPARE9_NUM_ENTRY; i++) {
        json_object_set_new(rx_spare9_hist_obj, rx_sp9_state_name[i].c_str(), json_integer(rx_spare9_histogram[i]));
    }

    json_object_set_new(json_node, "rx_spare9_fsm_histogram", rx_spare9_hist_obj);

    //
    // Add RX serdes Spare9 state transition history
    //
    int json_status = 0;
    // insert all transitions into a json array to support chronological order
    json_t* state_transition_array = json_array();

    // get most recent entry in the queue
    auto rx_sm_transition_iter = m_rx_sp9_state_transition_queue.begin();
    // iterate from newest to oldest
    while (rx_sm_transition_iter != m_rx_sp9_state_transition_queue.end()) {
        rx_sp9_state_transition& state_transition_data = *rx_sm_transition_iter++;
        int rx_state = state_transition_data.rx_state;
        std::string& new_state = rx_sp9_state_name[rx_state];
        std::string& timestamp = state_transition_data.timestamp;

        // add transition json object to queue to add to save_state output
        json_t* state_transition_root = json_object();

        // Add info to the entry.
        json_object_set_new(state_transition_root, "rx_state", json_string(new_state.c_str()));
        json_object_set_new(state_transition_root, "timestamp", json_string(timestamp.c_str()));

        // insert to beginning of array to maintain order
        size_t insertion_index = 0;
        json_status = json_array_insert_new(state_transition_array, insertion_index, state_transition_root);
        if (json_status == -1) {
            log_err(MAC_PORT, "%s : failed to insert state transition data to json array", __func__);
            return LA_STATUS_EINVAL;
        }
    }

    json_status = json_object_set_new(json_node, "rxsp9_state_transition_history", state_transition_array);

    //
    // Add TX serdes Spare9 FSM histogram
    //
    json_t* tx_spare9_hist_obj = json_object();
    for (size_t i = 0; i < SRM_TX_SPARE9_NUM_ENTRY; i++) {
        json_object_set_new(tx_spare9_hist_obj, tx_sp9_state_name[i].c_str(), json_integer(tx_spare9_histogram[i]));
    }

    json_object_set_new(json_node, "tx_spare9_fsm_histogram", tx_spare9_hist_obj);

    //
    // Add TX serdes Spare9 state transition history
    //
    json_status = 0;
    // insert all transitions into a json array to support chronological order
    json_t* tx_state_transition_array = json_array();

    // get most recent entry in the queue
    auto tx_sm_transition_iter = m_tx_sp9_state_transition_queue.begin();
    // iterate from newest to oldest
    while (tx_sm_transition_iter != m_tx_sp9_state_transition_queue.end()) {
        tx_sp9_state_transition& state_transition_data = *tx_sm_transition_iter++;
        std::string& timestamp = state_transition_data.timestamp;

        json_t* state_transition_root = json_object();

        json_object_set_new(state_transition_root, "num_serdes", json_integer(m_serdes_count));
        int rx_state = state_transition_data.rx_state;
        std::string& new_state = rx_sp9_state_name[rx_state];
        json_object_set_new(state_transition_root, "rx_state", json_string(new_state.c_str()));

        // Add info to the entry.
        // add transition json object to queue to add to save_state output
        json_t* tx_fsm_serdes_state = json_array();
        for (size_t i = 0; i < m_serdes_count; i++) {
            int tx_state = state_transition_data.tx_state[i];
            std::string& new_state = tx_sp9_state_name[tx_state + 1];
            json_array_append(tx_fsm_serdes_state, json_string(new_state.c_str()));
        }
        json_object_set_new(state_transition_root, "tx_state", tx_fsm_serdes_state);

        json_object_set_new(state_transition_root, "timestamp", json_string(timestamp.c_str()));

        // insert to beginning of array to maintain order
        size_t insertion_index = 0;
        json_status = json_array_insert_new(tx_state_transition_array, insertion_index, state_transition_root);
        if (json_status == -1) {
            log_err(MAC_PORT, "%s : failed to insert state transition data to json array", __func__);
            return LA_STATUS_EINVAL;
        }
    }

    json_status = json_object_set_new(json_node, "txsp9_state_transition_history", tx_state_transition_array);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_anlt_bundle(json_t* json_node)
{
    if (m_is_an_enabled) {

        size_t serdes_idx = m_anlt_lane[0];
        la_uint_t die = m_bundle.an_leader.rx_die;

        json_t* anlt_bundle_root = json_object();
        std::string serdes_prefix = create_serdes_prefix("anlt_bundle", serdes_idx - m_serdes_base_id, die);

        log_debug(SERDES, "%s", serdes_prefix.c_str());

        json_object_set_new(anlt_bundle_root, "num_followers", json_integer(m_bundle.num_followers));
        std::string die_str = "0x" + to_hex_string(m_bundle.an_leader.rx_die);
        json_object_set_new(anlt_bundle_root, "an_leader_rx_die", json_string(die_str.c_str()));
        json_object_set_new(anlt_bundle_root, "an_leader_rx_channel", json_integer(m_bundle.an_leader.rx_channel));
        die_str = "0x" + to_hex_string(m_bundle.an_leader.tx_die);
        json_object_set_new(anlt_bundle_root, "an_leader_tx_die", json_string(die_str.c_str()));
        json_object_set_new(anlt_bundle_root, "an_leader_tx_channel", json_integer(m_bundle.an_leader.tx_channel));

        for (la_uint_t i = 0; i < m_bundle.num_followers; i++) {
            std::string die_str = "0x" + to_hex_string(m_bundle.lt_followers[i].rx_die);
            std::string follower_str = "lt_follower_" + std::to_string(i) + "_rx_die";
            json_object_set_new(anlt_bundle_root, follower_str.c_str(), json_string(die_str.c_str()));
            follower_str = "lt_follower_" + std::to_string(i) + "_rx_channel";
            json_object_set_new(anlt_bundle_root, follower_str.c_str(), json_integer(m_bundle.lt_followers[i].rx_channel));

            die_str = "0x" + to_hex_string(m_bundle.lt_followers[i].tx_die);
            follower_str = "lt_follower_" + std::to_string(i) + "_tx_die";
            json_object_set_new(anlt_bundle_root, follower_str.c_str(), json_string(die_str.c_str()));
            follower_str = "lt_follower_" + std::to_string(i) + "_tx_channel";
            json_object_set_new(anlt_bundle_root, follower_str.c_str(), json_integer(m_bundle.lt_followers[i].tx_channel));
        }

        json_object_set_new(json_node, "anlt_bundle", anlt_bundle_root);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_link_config(json_t* json_node)
{
    json_t* link_config_root = json_object();
    for (auto die_tuple : m_die_set) {
        la_uint_t serdes_idx = std::get<0>(die_tuple);
        la_uint_t die = std::get<1>(die_tuple);
        la_serdes_direction_e direction = std::get<2>(die_tuple);
        la_uint_t channel;
        la_status stat = get_serdes_channel(serdes_idx, direction, channel);
        return_on_error(stat);

        // Create a node to store the SerDes information.
        json_t* serdes_root = json_object();

        // Define the SerDes information.
        define_serdes_json_info(serdes_root, serdes_idx, die, channel);

        std::string prefix = (direction == la_serdes_direction_e::RX) ? "RX_RULES" : "TX_RULES";
        std::string serdes_prefix = create_serdes_prefix(prefix, serdes_idx, die, channel);

        // Dump the RX, TX & PLL Rules
        srm_pll_rules_t pll_rules;
        srm_rx_rules_t rx_rules;
        srm_tx_rules_t tx_rules;

        ip_status_t status = srm_pll_rules_query(die, &pll_rules);
        if (status != IP_OK) {
            log_err(SERDES, "SerDes %d/%d/%d failed to query pll rules.", m_slice_id, m_ifg_id, m_serdes_base_id + serdes_idx);
            return LA_STATUS_EUNKNOWN;
        }

        if (direction == la_serdes_direction_e::RX) {
            status = srm_rx_rules_query(die, channel, &rx_rules);
            if (status != IP_OK) {
                log_err(SERDES, "%s: failed to query rx rules.", serdes_prefix.c_str());
                return LA_STATUS_EUNKNOWN;
            }

        } else {
            status = srm_tx_rules_query(die, channel, &tx_rules);
            if (status != IP_OK) {
                log_err(SERDES, "%s: failed to query tx rules.", serdes_prefix.c_str());
                return LA_STATUS_EUNKNOWN;
            }
        }

        // add common variables for both TX/RX to string stream and json structure
        bool enable = (direction == la_serdes_direction_e::RX) ? rx_rules.enable : tx_rules.enable;
        la_int_t src = (direction == la_serdes_direction_e::RX) ? (la_int_t)rx_rules.src : (la_int_t)tx_rules.src;

        bool gray_mapping = (direction == la_serdes_direction_e::RX) ? rx_rules.gray_mapping : tx_rules.gray_mapping;
        bool ieee_demap = (direction == la_serdes_direction_e::RX) ? rx_rules.ieee_demap : tx_rules.ieee_demap;
        e_srm_subrate_ratio subrate_ratio
            = (direction == la_serdes_direction_e::RX) ? rx_rules.subrate_ratio : tx_rules.subrate_ratio;
        const char* signalling = (direction == la_serdes_direction_e::RX) ? srm_dbg_translate_signalling(rx_rules.signalling)
                                                                          : srm_dbg_translate_signalling(tx_rules.signalling);

        json_object_set_new(serdes_root, "BAUD_RATE", json_integer(pll_rules.baud_rate));
        json_object_set_new(serdes_root, "ENABLE", json_integer(enable));
        json_object_set_new(serdes_root, "SRC", json_integer(src));
        json_object_set_new(serdes_root, "SUB_RATIO", json_integer(subrate_ratio));
        json_object_set_new(serdes_root, "SIGNAL_MODE", json_string(signalling));
        json_object_set_new(serdes_root, "GRAY_MAP", json_integer(gray_mapping));
        json_object_set_new(serdes_root, "IEEE_DEMAP", json_integer(ieee_demap));

        std::stringstream stream;
        stream << serdes_prefix << " : "
               << "BAUD_RATE=" << std::to_string(pll_rules.baud_rate) << ", ENABLE=" << std::to_string(enable)
               << ", SRC=" << std::to_string(src) << ", GRAY_MAP=" << std::to_string(gray_mapping)
               << ", IEEE_DEMAP=" << std::to_string(ieee_demap) << ", SUB_RATIO=" << std::to_string(subrate_ratio)
               << ", SIGNAL_MODE=" << signalling;

        if (direction == la_serdes_direction_e::RX) {
            // print rx variables and write json structure
            log_debug(SERDES,
                      "%s, DSP_MODE=%s"
                      ", PRECODER_EN=%d, CTLE=%d, RX_INVERT=%d, AFE_TRIM=%d, PGA_ATT_EN=%d"
                      ", VGA_TRACKING=%d, IPP_EN=%d, AC_COUPLE_BYPASS=%d"
                      ", RX_QC_DIS=%d, RX_QC_DATA_MODE_DIS=%d, RX_QC_MSE_MIN_THRESH=%d"
                      ", REFTRIM_BYPASS_FW=%d, REFTRIM_BYPASS_FINE=%d",
                      stream.str().c_str(),
                      srm_dbg_translate_dsp_mode(rx_rules.dsp_mode),
                      rx_rules.dfe_precoder_en,
                      rx_rules.ctle_code,
                      rx_rules.invert_chan,
                      rx_rules.afe_trim,
                      rx_rules.pga_att_en,
                      rx_rules.vga_tracking,
                      rx_rules.ipp_en,
                      rx_rules.ac_coupling_bypass,
                      rx_rules.rx_qc.dis,
                      rx_rules.rx_qc.data_mode_dis,
                      rx_rules.rx_qc.mse_min_threshold,
                      rx_rules.bypass_reftrim_fw,
                      rx_rules.bypass_reftrim_finetune);

            json_object_set_new(serdes_root, "DSP_MODE", json_string(srm_dbg_translate_dsp_mode(rx_rules.dsp_mode)));
            json_object_set_new(serdes_root, "PRECODER_EN", json_integer(rx_rules.dfe_precoder_en));
            json_object_set_new(serdes_root, "CTLE", json_integer(rx_rules.ctle_code));
            json_object_set_new(serdes_root, "RX_INVERT", json_integer(rx_rules.invert_chan));
            json_object_set_new(serdes_root, "AFE_TRIM", json_integer(rx_rules.afe_trim));
            json_object_set_new(serdes_root, "PGA_ATT_EN", json_integer(rx_rules.pga_att_en));
            json_object_set_new(serdes_root, "VGA_TRACKING", json_integer(rx_rules.vga_tracking));
            json_object_set_new(serdes_root, "IPP_EN", json_integer(rx_rules.ipp_en));
            json_object_set_new(serdes_root, "AC_COUPLE_BYPASS", json_integer(rx_rules.ac_coupling_bypass));
            json_object_set_new(serdes_root, "RX_QC_DIS", json_integer(rx_rules.rx_qc.dis));
            json_object_set_new(serdes_root, "RX_QC_DATA_MODE_DIS", json_integer(rx_rules.rx_qc.data_mode_dis));
            json_object_set_new(serdes_root, "RX_QC_MSE_MIN_THRESH", json_integer(rx_rules.rx_qc.mse_min_threshold));
            json_object_set_new(serdes_root, "REFTRIM_BYPASS_FW", json_integer(rx_rules.bypass_reftrim_fw));
            json_object_set_new(serdes_root, "REFTRIM_BYPASS_FINE", json_integer(rx_rules.bypass_reftrim_finetune));

        } else if (direction == la_serdes_direction_e::TX) {
            // append common TX variables to string stream before deciding between 3TAP 7TAP TX
            stream << ", SQUELCH_LOCK=" << tx_rules.squelch_lock << ", LUT_MODE=" << srm_dbg_translate_lut_mode(tx_rules.lut_mode)
                   << ", PRECODER_EN=" << tx_rules.precoder_en << ", TX_INVERT=" << tx_rules.invert_chan
                   << ", INNER_EYE1=" << tx_rules.inner_eye1 << ", INNER_EYE2=" << tx_rules.inner_eye2;

            json_object_set_new(serdes_root, "SQUELCH_LOCK", json_integer(tx_rules.squelch_lock));
            json_object_set_new(serdes_root, "LUT_MODE", json_string(srm_dbg_translate_lut_mode(tx_rules.lut_mode)));
            json_object_set_new(serdes_root, "PRECODER_EN", json_integer(tx_rules.precoder_en));
            json_object_set_new(serdes_root, "TX_INVERT", json_integer(tx_rules.invert_chan));
            json_object_set_new(serdes_root, "INNER_EYE1", json_integer(tx_rules.inner_eye1));
            json_object_set_new(serdes_root, "INNER_EYE2", json_integer(tx_rules.inner_eye2));

            if (tx_rules.lut_mode == SRM_TX_LUT_3TAP) {

                log_debug(SERDES,
                          "%s, PRE1=%d, MAIN=%d, POST1=%d",
                          stream.str().c_str(),
                          tx_rules.fir_tap[0],
                          tx_rules.fir_tap[1],
                          tx_rules.fir_tap[2]);

                json_object_set_new(serdes_root, "PRE1", json_integer(tx_rules.fir_tap[0]));
                json_object_set_new(serdes_root, "MAIN", json_integer(tx_rules.fir_tap[1]));
                json_object_set_new(serdes_root, "POST1", json_integer(tx_rules.fir_tap[2]));
            } else {

                log_debug(SERDES,
                          "%s, FIR_TAP0=%d, FIR_TAP1=%d, FIR_TAP2=%d, "
                          "FIR_TAP3=%d, FIR_TAP4=%d, FIR_TAP5=%d, FIR_TAP6=%d",
                          stream.str().c_str(),
                          tx_rules.fir_tap[0],
                          tx_rules.fir_tap[1],
                          tx_rules.fir_tap[2],
                          tx_rules.fir_tap[3],
                          tx_rules.fir_tap[4],
                          tx_rules.fir_tap[5],
                          tx_rules.fir_tap[6]);

                json_object_set_new(serdes_root, "FIR_TAP0", json_integer(tx_rules.fir_tap[0]));
                json_object_set_new(serdes_root, "FIR_TAP1", json_integer(tx_rules.fir_tap[1]));
                json_object_set_new(serdes_root, "FIR_TAP2", json_integer(tx_rules.fir_tap[2]));
                json_object_set_new(serdes_root, "FIR_TAP3", json_integer(tx_rules.fir_tap[3]));
                json_object_set_new(serdes_root, "FIR_TAP4", json_integer(tx_rules.fir_tap[4]));
                json_object_set_new(serdes_root, "FIR_TAP5", json_integer(tx_rules.fir_tap[5]));
                json_object_set_new(serdes_root, "FIR_TAP6", json_integer(tx_rules.fir_tap[6]));
            }
        }

        std::string serdes_label = create_serdes_label(serdes_idx, direction);
        json_object_set_new(link_config_root, serdes_label.c_str(), serdes_root);
    }

    json_object_set_new(json_node, "link_config", link_config_root);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_mcu_status(json_t* json_node, uint32_t loop_delay)
{
    json_t* mcu_stat_root = json_object();

    std::map<la_uint_t, std::vector<std::vector<la_int_t> > > die_to_serdes_map;

    // group serdes based on their respective die and organize by channel and direction
    // die_to_serdes_map[die] = [ [CH0_RX, CH0_TX], [CH1_RX, CH1_TX] ]
    for (auto die_tuple : m_die_set) {
        la_uint_t serdes_idx = std::get<0>(die_tuple);
        la_uint_t die = std::get<1>(die_tuple);
        la_serdes_direction_e direction = std::get<2>(die_tuple);
        la_uint_t channel;
        la_status stat = get_serdes_channel(serdes_idx, direction, channel);
        return_on_error(stat);

        // check if die is already in map, if not initialize vector to -1
        if (die_to_serdes_map.find(die) == die_to_serdes_map.end()) {
            die_to_serdes_map[die] = std::vector<std::vector<la_int_t> >(SRM_NUM_CHANNELS);

            // initialize serdes number in channel vector to -1
            std::vector<std::vector<la_int_t> >& channels_vec = die_to_serdes_map[die];
            for (la_uint_t cur_chan = 0; cur_chan < channels_vec.size(); cur_chan++) {
                channels_vec[cur_chan] = std::vector<la_int_t>(SRM_NUM_DIRECTIONS, -1);
            }
        }
        la_int_t serdes_num = m_serdes_base_id + serdes_idx;
        // write serdes value into vector at correct position based on channel and direction
        std::vector<std::vector<la_int_t> >& serdes_vec = die_to_serdes_map[die];
        serdes_vec[channel][(la_int_t)direction] = serdes_num;
    }

    // iterate through each unique die and display / save MCU_STATUS
    for (auto it = die_to_serdes_map.begin(); it != die_to_serdes_map.end(); it++) {
        json_t* die_root = json_object();
        la_uint_t die = it->first;
        std::vector<std::vector<la_int_t> >& channels_vec = it->second;

        std::string die_label = "die_0x" + to_hex_string(die);
        std::string log_prefix = "MCU_STATUS (0x" + to_hex_string(die) + ")";

        srm_mcu_status_t mcu_status;

        ip_status_t status = srm_mcu_status_query(die, &mcu_status, loop_delay);

        if (status != IP_OK) {
            log_err(SERDES, "%s: failed to query mcu status.", log_prefix.c_str());
            return LA_STATUS_EUNKNOWN;
        }

        log_debug(SERDES,
                  "%s: FW_MODE=%s, FW_INSTALLED=%d, "
                  "PC_TRACE=(%d, %d, %d, %d, %d, %d, %d, %d, %d, %d), "
                  "LOOP_CNT=(%d, %d), LOOP_DELTA=%d, LOOP_DUR=%d, "
                  "MDIO_ADDR_ERR=%d, "
                  "APP_VER=%d, APP_MAJ_VER=%d, APP_MIN_VER=%d, APP_BLD_ID=%d, "
                  "API_VER=%d, API_VER_MAJ=%d, API_VER_MIN=%d, API_BLD_ID=%d, "
                  "CH0_SERDES={RX=%d, TX=%d}, CH1_SERDES={RX=%d, TX=%d}",
                  log_prefix.c_str(),
                  srm_dbg_translate_fw_mode(mcu_status.fw_mode),
                  mcu_status.runstall,
                  mcu_status.pc_trace[0],
                  mcu_status.pc_trace[1],
                  mcu_status.pc_trace[2],
                  mcu_status.pc_trace[3],
                  mcu_status.pc_trace[4],
                  mcu_status.pc_trace[5],
                  mcu_status.pc_trace[6],
                  mcu_status.pc_trace[7],
                  mcu_status.pc_trace[8],
                  mcu_status.pc_trace[9],
                  mcu_status.loop_count[0],
                  mcu_status.loop_count[1],
                  mcu_status.mdio_addr_err,
                  mcu_status.loop_delta,
                  mcu_status.loop_duration,
                  mcu_status.app_version,
                  mcu_status.app_version_major,
                  mcu_status.app_version_minor,
                  mcu_status.app_version_build,
                  mcu_status.api_version,
                  mcu_status.api_version_major,
                  mcu_status.api_version_minor,
                  mcu_status.api_version_build,
                  channels_vec[0][(la_int_t)la_serdes_direction_e::RX],
                  channels_vec[0][(la_int_t)la_serdes_direction_e::TX],
                  channels_vec[1][(la_int_t)la_serdes_direction_e::RX],
                  channels_vec[1][(la_int_t)la_serdes_direction_e::TX]);

        json_object_set_new(die_root, "FW_MODE", json_string(mcu_status.fw_mode_str));
        json_object_set_new(die_root, "FW_INSTALLED", json_integer(mcu_status.runstall));
        json_object_set_new(die_root, "PROGRAM_CNT0", json_integer(mcu_status.pc_trace[0]));
        json_object_set_new(die_root, "PROGRAM_CNT1", json_integer(mcu_status.pc_trace[1]));
        json_object_set_new(die_root, "PROGRAM_CNT2", json_integer(mcu_status.pc_trace[2]));
        json_object_set_new(die_root, "PROGRAM_CNT3", json_integer(mcu_status.pc_trace[3]));
        json_object_set_new(die_root, "PROGRAM_CNT4", json_integer(mcu_status.pc_trace[4]));
        json_object_set_new(die_root, "PROGRAM_CNT5", json_integer(mcu_status.pc_trace[5]));
        json_object_set_new(die_root, "PROGRAM_CNT6", json_integer(mcu_status.pc_trace[6]));
        json_object_set_new(die_root, "PROGRAM_CNT7", json_integer(mcu_status.pc_trace[7]));
        json_object_set_new(die_root, "PROGRAM_CNT8", json_integer(mcu_status.pc_trace[8]));
        json_object_set_new(die_root, "PROGRAM_CNT9", json_integer(mcu_status.pc_trace[9]));
        json_object_set_new(die_root, "LOOP_CNT0", json_integer(mcu_status.loop_count[0]));
        json_object_set_new(die_root, "LOOP_CNT1", json_integer(mcu_status.loop_count[1]));
        json_object_set_new(die_root, "LOOP_DELTA", json_integer(mcu_status.loop_delta));
        json_object_set_new(die_root, "LOOP_DUR", json_integer(mcu_status.loop_duration));
        json_object_set_new(die_root, "MDIO_ADDR_ERR", json_integer(mcu_status.mdio_addr_err));
        json_object_set_new(die_root, "APP_VER", json_integer(mcu_status.app_version));
        json_object_set_new(die_root, "APP_MAJ_VER", json_integer(mcu_status.app_version_major));
        json_object_set_new(die_root, "APP_MIN_VER", json_integer(mcu_status.app_version_minor));
        json_object_set_new(die_root, "APP_BLD_ID", json_integer(mcu_status.app_version_build));
        json_object_set_new(die_root, "API_VER", json_integer(mcu_status.api_version));
        json_object_set_new(die_root, "API_VER_MAJ", json_integer(mcu_status.api_version_major));
        json_object_set_new(die_root, "API_VER_MIN", json_integer(mcu_status.api_version_minor));
        json_object_set_new(die_root, "API_BLD_ID", json_integer(mcu_status.api_version_build));

        for (la_uint_t cur_chan = 0; cur_chan < channels_vec.size(); cur_chan++) {
            json_t* channel_root = json_object();
            std::string channel_label = "CH" + std::to_string(cur_chan) + "_SERDES";

            json_object_set_new(channel_root, "RX", json_integer(channels_vec[cur_chan][(la_int_t)la_serdes_direction_e::RX]));
            json_object_set_new(channel_root, "TX", json_integer(channels_vec[cur_chan][(la_int_t)la_serdes_direction_e::TX]));
            json_object_set_new(die_root, channel_label.c_str(), channel_root);
        }

        json_object_set_new(mcu_stat_root, die_label.c_str(), die_root);
    } // end for

    json_object_set_new(json_node, "mcu_status", mcu_stat_root);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_eye_capture(json_t* json_node)
{
    json_t* histogram_root = json_object();

    for (auto die_tuple : m_die_set) {
        la_uint_t serdes_idx = std::get<0>(die_tuple);
        la_uint_t die = std::get<1>(die_tuple);
        la_serdes_direction_e direction = std::get<2>(die_tuple);
        la_uint_t channel;
        la_status stat = get_serdes_channel(serdes_idx, direction, channel);
        return_on_error(stat);

        logger& log_instance = logger::instance();

        // Check RX ready/locked before checking histogram and our direction is RX
        if (!(srm_is_rx_ready(die, channel)) || !(direction == la_serdes_direction_e::RX)) {
            if (direction == la_serdes_direction_e::RX) {
                log_warning(SERDES, "Cannot get eye capture, RX is not ready for serdes_idx=%u die=0x%x", serdes_idx, die);
            }

            continue;
        }

        std::string serdes_label = "index_" + std::to_string(serdes_idx);
        std::string serdes_prefix = create_serdes_prefix("HISTOGRAM", serdes_idx, die, channel);

        // get histogram data from SRM API
        e_srm_rx_error_gen errgen = SRM_RX_DSP_ERR_GEN_USE_DEFAULT;
        ip_status_t status = IP_OK;
        uint32_t hist_data[SRM_HIST_DATA_SIZE];
        status = srm_rx_dsp_get_histogram(die, channel, errgen, hist_data);

        if (status == IP_OK) {
            json_t* json_graph_array = json_array();
            std::string histogram_border = "     "
                                           "|+---------------+---------------+---------------+---------------+---------------+-----"
                                           "----------+---------------+---------------+---------------+---------------+";
            std::string units_border = "     |-5              -4              -3              -2              -1              0    "
                                       "           1               2               3               4               5";

            // normalize histogram data to a logmarithmic scale for easier plotting
            // (2^20 - 1) is the maximum histogram value
            uint32_t max_y_value = pow(2, 20);
            // multiply by two to set resolution from full steps to half steps (0, 1), (0, .5, 1)
            uint16_t max_lines = log2(max_y_value) * 2;

            log_debug(SERDES, "%s", serdes_prefix.c_str());
            for (uint16_t line = max_lines; line > 0; line--) {
                std::stringstream stream;

                // resolution is in .5 increments from 0 to 20, resulting in 40 lines
                // every even number is the whole number; every odd is +/-.5
                if (line % 2 == 0) {
                    stream << "2^" << std::setw(2) << std::setfill('0') << line / 2 << " |";
                } else {
                    stream << "     |";
                }

                // fill in histogram for each colomn
                for (uint16_t col = 0; col < SRM_HIST_DATA_SIZE; col++) {
                    double plot_ampl = log2((double)hist_data[col]);
                    // multiply by 2 match higher resolution
                    if ((plot_ampl * 2) >= line) {
                        stream << "#";
                    } else {
                        stream << " ";
                    }
                }

                // add aggregated string to json array
                json_array_append(json_graph_array, json_string(stream.str().c_str()));

                // print histogram data to console
                if (log_instance.is_logging(
                        m_device->get_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::DEBUG)) {
                    log_debug(SERDES, "%s", stream.str().c_str());
                }
            }

            json_t* serdes_root = json_object();

            json_array_append(json_graph_array, json_string(histogram_border.c_str()));
            json_array_append(json_graph_array, json_string(units_border.c_str()));

            define_serdes_json_info(serdes_root, serdes_idx, die, channel);
            json_object_set_new(serdes_root, "graph", json_graph_array);

            // print histogram borders
            if (log_instance.is_logging(
                    m_device->get_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::DEBUG)) {
                log_debug(SERDES, "%s", histogram_border.c_str());
                log_debug(SERDES, "%s", units_border.c_str());
            }

            json_object_set_new(histogram_root, serdes_label.c_str(), serdes_root);
        } else {
            // error
            log_err(SERDES, "%s: failed to get histogram data.", serdes_label.c_str());
        }
    }

    json_object_set_new(json_node, "histogram", histogram_root);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::add_serdes_reg_dump(json_t* json_node)
{

    // got these values from srm's srm_diags_register_dump function
    const uint32_t register_ranges[][2] = {
        {0x0, 0x0},       {0x2, 0x59},      {0x100, 0x10c},   {0x200, 0x209},   {0x300, 0x314},   {0x320, 0x334},
        {0x340, 0x352},   {0x2000, 0x201a}, {0x2800, 0x296c}, {0x2a00, 0x2a08}, {0x2a40, 0x2a56}, {0x2a80, 0x2a8d},
        {0x2b00, 0x2b11}, {0x2c00, 0x2c18}, {0x2d00, 0x2d26}, {0x3000, 0x316c}, {0x3200, 0x3208}, {0x3240, 0x3256},
        {0x3280, 0x328d}, {0x3300, 0x3311}, {0x3400, 0x3418}, {0x3500, 0x3526}, {0x3800, 0x396c}, {0x3a00, 0x3a08},
        {0x3a40, 0x3a56}, {0x3a80, 0x3a8d}, {0x3b00, 0x3b11}, {0x3c00, 0x3c18}, {0x3d00, 0x3d26}, {0x4000, 0x400e},
        {0x4100, 0x411c}, {0x4800, 0x4837}, {0x4900, 0x492e}, {0x4940, 0x4953}, {0x4980, 0x498f}, {0x49c0, 0x49c6},
        {0x4a00, 0x4a11}, {0x4b00, 0x4b08}, {0x4c00, 0x4c26}, {0x5000, 0x5037}, {0x5100, 0x512e}, {0x5140, 0x5153},
        {0x5180, 0x518f}, {0x51c0, 0x51c6}, {0x5200, 0x5211}, {0x5300, 0x5308}, {0x5400, 0x5426}, {0x5800, 0x5837},
        {0x5900, 0x592e}, {0x5940, 0x5953}, {0x5980, 0x598f}, {0x59c0, 0x59c6}, {0x5a00, 0x5a11}, {0x5b00, 0x5b08},
        {0x5c00, 0x5c26}, {0x6000, 0x60e3}, {0x6100, 0x619a}, {0x6200, 0x629a}, {0xe000, 0xe0a7}, {0xe400, 0xe400},
        {0xe800, 0xe800}, {0xf000, 0xf041}, {0xf200, 0xf241}, {0xf400, 0xf441},

    };
    size_t reg_ranges_size = sizeof(register_ranges) / sizeof(register_ranges[0]);
    std::set<la_uint_t> die_queried;
    // generic object containing data for all die's
    json_t* die_regs_array = json_array();

    for (auto die_tuple : m_die_set) {
        la_uint_t die = std::get<1>(die_tuple);
        std::string die_hex_val = "0x" + to_hex_string(die);

        if (die_queried.find(die) != die_queried.end()) {
            // skip
            continue;
        }

        // mark as visited
        die_queried.insert(die);

        // lock die to get register data
        if (srm_lock(die) != IP_OK) {
            // free json memory
            json_decref(die_regs_array);

            log_err(SERDES, "%s : failed to lock die=0x%x", __func__, die);
            return LA_STATUS_ERESOURCE;
        }

        json_t* die_root = json_object();
        json_t* reg_data_root = json_object();
        json_object_set_new(die_root, "die", json_string(die_hex_val.c_str()));

        // iterate through all specified ranges
        for (size_t i = 0; i < reg_ranges_size; i++) {
            size_t start_addr = register_ranges[i][0];
            size_t end_addr = register_ranges[i][1];

            // iterate through register range by 1
            for (size_t addr = start_addr; addr <= end_addr; addr++) {
                uint32_t data = srm_reg_read(die, addr);
                std::string hex_addr = "0x" + to_hex_string(addr);
                std::string hex_val = "0x" + to_hex_string(data);

                // add data to JSON tree with the following structure "addr" : "value"
                json_object_set_new(reg_data_root, hex_addr.c_str(), json_string(hex_val.c_str()));
            }
        }

        // unlock die since we already read registers
        if (srm_unlock(die) != IP_OK) {
            json_decref(die_regs_array);
            json_decref(die_root);
            json_decref(reg_data_root);

            log_err(SERDES, "%s : failed to unlock die=0x%x", __func__, die);
            return LA_STATUS_ERESOURCE;
        }

        // add register data to die object
        json_object_set_new(die_root, "reg_data", reg_data_root);

        // append die object into JSON array
        json_array_append_new(die_regs_array, die_root);
    }

    json_object_set_new(json_node, "register_dump", die_regs_array);

    return LA_STATUS_SUCCESS;
}

std::string
srm_serdes_handler::create_serdes_label(la_uint_t serdes_idx, la_serdes_direction_e direction)
{
    return "index_" + std::to_string(serdes_idx) + "_" + to_string(direction);
}

std::string
srm_serdes_handler::create_serdes_prefix(std::string prefix, la_uint_t serdes_idx, la_uint_t die)
{
    std::stringstream stream;
    // format input into the format "<prefix> (Slice/Ifg/SerDes) (Die)"
    stream << prefix << " (" << to_string(m_slice_id, m_ifg_id, m_serdes_base_id + serdes_idx) << ") "
           << "(0x" << to_hex_string(die) << ")";

    return stream.str();
}

std::string
srm_serdes_handler::create_serdes_prefix(std::string prefix, la_uint_t serdes_idx, la_uint_t die, la_uint_t channel)
{
    std::stringstream stream;
    // format input into the format "<prefix> (Slice/Ifg/SerDes) (Die/Channel)"
    stream << prefix << " (" << to_string(m_slice_id, m_ifg_id, m_serdes_base_id + serdes_idx) << ") "
           << "(0x" << to_hex_string(die) << "/" << std::to_string(channel) << ")";

    return stream.str();
}

void
srm_serdes_handler::define_serdes_json_info(json_t* json_node, la_uint_t serdes_idx, la_uint_t die)
{
    json_object_set_new(json_node, "serdes", json_integer(m_serdes_base_id + serdes_idx));
    std::string die_str = "0x" + to_hex_string(die);
    json_object_set_new(json_node, "die", json_string(die_str.c_str()));
}

void
srm_serdes_handler::define_serdes_json_info(json_t* json_node, la_uint_t serdes_idx, la_uint_t die, la_uint_t channel)
{
    json_object_set_new(json_node, "serdes", json_integer(m_serdes_base_id + serdes_idx));
    std::string die_str = "0x" + to_hex_string(die);
    json_object_set_new(json_node, "die", json_string(die_str.c_str()));
    json_object_set_new(json_node, "channel", json_integer(channel));
}

la_status
srm_serdes_handler::set_serdes_signal_control(la_uint_t serdes_idx,
                                              la_serdes_direction_e direction,
                                              la_mac_port::serdes_ctrl_e ctrl_type)
{
    if (!m_is_initialized) {
        return LA_STATUS_SUCCESS;
    }

    la_uint_t die;
    ip_status_t status;
    la_uint_t serdes_lane;

    // Consider lane swaps.
    if (direction == la_serdes_direction_e::RX) {
        serdes_lane = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source;
    } else {
        serdes_lane = m_serdes_base_id + serdes_idx;
    }

    la_uint_t channel;
    la_status stat = get_serdes_channel(serdes_idx, direction, channel);
    return_on_error(stat);
    stat = get_serdes_addr(serdes_idx, direction, die);
    return_on_error(stat);

    switch (ctrl_type) {
    case la_mac_port::serdes_ctrl_e::ENABLE_SQUELCH:
        if (direction == la_serdes_direction_e::RX) {
            /* Force SDT low means force Rx SNR to 0
             * It acts like a Rx squelch which cause re-tune */
            SRM_RX_DSP_SIGNAL_DETECT_CFG__SDT_FORCE_HIGH__RMW(die, channel, 0);
            SRM_RX_DSP_SIGNAL_DETECT_CFG__SDT_FORCE_LOW__RMW(die, channel, 1);
        } else {
            status = srm_tx_squelch(die, channel, true);
            if (status != IP_OK) {
                log_err(SERDES, "SerDes %d/%d/%d failed enabling TX squelch.", m_slice_id, m_ifg_id, serdes_lane);
                return LA_STATUS_EUNKNOWN;
            }
        }
        break;
    case la_mac_port::serdes_ctrl_e::DISABLE_SQUELCH:
        if (direction == la_serdes_direction_e::RX) {
            SRM_RX_DSP_SIGNAL_DETECT_CFG__SDT_FORCE_LOW__RMW(die, channel, 0);
        } else {
            status = srm_tx_squelch(die, channel, false);
            if (status != IP_OK) {
                log_err(SERDES, "SerDes %d/%d/%d failed disabling TX squelch.", m_slice_id, m_ifg_id, serdes_lane);
                return LA_STATUS_EUNKNOWN;
            }
        }
        break;
    default:
        return LA_STATUS_EINVAL;
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::get_continuous_tune_status(bool& out_status)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_handler::restore_state(bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

//
// The defines and srm_serdes_handler::csco_srm_anlt_init() is a local fix of SRM code.
// Need to update/remove once a permanent solution is in place.
//
#define CSCO_SRM_LOCK(die)                                                                                                         \
    {                                                                                                                              \
        if (srm_lock(die) != IP_OK)                                                                                                \
            return LA_STATUS_EUNKNOWN;                                                                                             \
    }
#define CSCO_SRM_UNLOCK(die)                                                                                                       \
    {                                                                                                                              \
        if (srm_unlock(die) != IP_OK)                                                                                              \
            return LA_STATUS_EUNKNOWN;                                                                                             \
    }

la_status
srm_serdes_handler::csco_srm_anlt_init(srm_anlt_bundle_t* bundle, srm_anlt_rules_t* rules)
{

    ip_status_t srm_status;
    la_uint16_t follower_rules[8];
    la_uint16_t anlt_rules_0;
    la_uint16_t anlt_rules_10;

    std::map<la_uint_t, la_uint16_t> die_to_masks;

    anlt_rules_0 = 0;
    memset(follower_rules, 0, sizeof(la_uint16_t) * 8);

    // Build the mask for all die in the bundle
    die_to_masks.clear();
    die_to_masks[bundle->an_leader.rx_die] = 0;
    die_to_masks[bundle->an_leader.rx_die] |= (1 << (bundle->an_leader.rx_channel + 8));
    die_to_masks[bundle->an_leader.tx_die] |= (1 << (bundle->an_leader.tx_channel + 12));
    for (size_t i = 0; i < bundle->num_followers; i++) {
        die_to_masks[bundle->lt_followers[i].rx_die] |= (1 << (bundle->lt_followers[i].rx_channel + 0));
        die_to_masks[bundle->lt_followers[i].tx_die] |= (1 << (bundle->lt_followers[i].tx_channel + 4));
    }

    // Bit 16-24 - Select device ID, support up to 512 device.
    // Mask off the Device ID and index field since we only need to find the die index within an ASIC.
    auto die_idx_entry = s_die_num.find(bundle->an_leader.rx_die & DIE_SLICE_IFG_MASK);
    if (die_idx_entry == s_die_num.end()) {
        log_err(SERDES, "Failed to find DIE index for DIE 0x%X.", bundle->an_leader.rx_die);
        return LA_STATUS_ENOTFOUND;
    }

    anlt_rules_0
        = ((0x80 | ((die_idx_entry->second & 0x1f) << 2) | bundle->an_leader.rx_channel) << 8) | (bundle->num_followers - 1);

    for (size_t i = 0; i < bundle->num_followers; i++) {
        la_uint16_t rx_serdes_idx, tx_serdes_idx;
        die_idx_entry = s_die_num.find(bundle->lt_followers[i].rx_die & DIE_SLICE_IFG_MASK);
        if (die_idx_entry == s_die_num.end()) {
            log_err(SERDES, "Failed to find DIE index for DIE 0x%X.", bundle->an_leader.rx_die);
            return LA_STATUS_ENOTFOUND;
        }
        rx_serdes_idx = die_idx_entry->second & 0x1f;
        die_idx_entry = s_die_num.find(bundle->lt_followers[i].tx_die & DIE_SLICE_IFG_MASK);
        if (die_idx_entry == s_die_num.end()) {
            log_err(SERDES, "Failed to find DIE index for DIE 0x%X.", bundle->an_leader.rx_die);
            return LA_STATUS_ENOTFOUND;
        }
        tx_serdes_idx = die_idx_entry->second & 0x1f;
        follower_rules[i] = ((0x80 | (rx_serdes_idx << 2) | (bundle->lt_followers[i].rx_channel & 0x3)) << 8)
                            | ((0x80 | (tx_serdes_idx << 2) | (bundle->lt_followers[i].tx_channel & 0x3)) << 0);

        // Need these for AN to work. Inphi investigage.
        // Initializes the device with universal ID. From the user guide, "all devices with the same ERU
        // should have the same upper 11-bits, i.e [15:5]"  Make the upper bits the same for the bundle before
        // OR with the serdes index number.
        srm_init_uid(bundle->lt_followers[i].rx_die, (bundle->lt_followers[i].rx_die & 0xF0FF) | rx_serdes_idx);
        if (bundle->lt_followers[i].rx_die != bundle->lt_followers[i].tx_die)
            srm_init_uid(bundle->lt_followers[i].tx_die, (bundle->lt_followers[i].tx_die & 0xF0FF) | tx_serdes_idx);
    }

    anlt_rules_10 = ((rules->an.advanced[0] << 2) & 0x0ffc) | (rules->an.nonce_chk_disable << 1) | rules->an.lt_timer_disable
                    | (rules->an.llfec_con.lf1_capable << 12) | (rules->an.llfec_con.lf2_capable << 13)
                    | (rules->an.llfec_con.lf3_capable << 14) | (rules->an.llfec_con.ll_rs272_request << 15);

    // Teardown all rules
    for (auto it = die_to_masks.begin(); it != die_to_masks.end(); it++) {
        CSCO_SRM_LOCK(it->first);
        srm_status = srm_anlt_wait_for_ack_clear(it->first);
        if (srm_status == IP_OK) {
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_1__ADDRESS, it->second); // first=DIE_ID, second=MASK
            srm_anlt_req_cmd(it->first, 2);                                      // SRM_ANLT_CMD_ANLT_TEARDOWN);
        }
        CSCO_SRM_UNLOCK(it->first);
        if (srm_status != IP_OK) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    ////////////////////////////////////////////////
    ////////////////////////////////////////////////
    //
    //    3. Download all TX_PMD
    //
    ////////////////////////////////////////////////
    ////////////////////////////////////////////////
    srm_tx_rules_t tx_rules;

    // Since TX PMD rules are passed before ANLT rules,
    // it is possible for the TX PMD to skip DME STATE
    // and prematurely go into DATA_MODE. We set it to
    // false here and let srm_anlt_rules_recv(..) take
    // care of it in the FW.
    rules->tx.enable = false;

    srm_status = srm_cp_tx_rules_bundle_to_channel(&(rules->tx), &tx_rules, -1);
    for (int i = 0; i < bundle->num_followers; i++) {
        la_uint_t die_num = bundle->lt_followers[i].tx_die;
        int ch = bundle->lt_followers[i].tx_channel;

        srm_status |= srm_cp_tx_rules_bundle_to_channel(&(rules->tx), &tx_rules, i);

        log_debug(SERDES, "tx_init die=0x%08x, channel=%d\n", die_num, ch);
        srm_status |= srm_init_tx(die_num, ch, &tx_rules);

        if (srm_status != IP_OK) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    ////////////////////////////////////////////////
    ////////////////////////////////////////////////
    //
    //    4. Download all RX_PMD
    //
    ////////////////////////////////////////////////
    ////////////////////////////////////////////////
    // Download all RX_PMD except Leader RX, this is done later
    srm_rx_rules_t rx_rules;

    // Since RX PMD rules are passed before ANLT rules,
    // it is possible for the RX PMD to skip DME STATE
    // We set it to false here and let
    // srm_anlt_rules_recv(..) take care of it in the FW.
    rules->rx.enable = false;

    srm_status = srm_cp_rx_rules_bundle_to_channel(&(rules->rx), &rx_rules, -1);
    for (int i = 1; i < bundle->num_followers; i++) { // skipping RX master which will be done later.
        la_uint_t die_num = bundle->lt_followers[i].rx_die;
        int ch = bundle->lt_followers[i].rx_channel;

        srm_status |= srm_cp_rx_rules_bundle_to_channel(&(rules->rx), &rx_rules, i);

        log_debug(SERDES, "rx_init die=0x%08x, channel=%d\n", die_num, ch);
        srm_status |= srm_init_rx(die_num, ch, &rx_rules);

        if (srm_status != IP_OK) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    la_uint16_t rx_leader_mask = (1 << (bundle->an_leader.rx_channel + 8)) | (1 << (bundle->an_leader.rx_channel + 0));
    die_to_masks[bundle->an_leader.rx_die] = die_to_masks[bundle->an_leader.rx_die] & ~rx_leader_mask;
    // Download all ANLT rules except RX Leader
    for (auto it = die_to_masks.begin(); it != die_to_masks.end(); it++) {
        CSCO_SRM_LOCK(it->first);
        srm_status |= srm_anlt_wait_for_ack_clear(it->first);

        if (srm_status == IP_OK) {
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_0__ADDRESS, anlt_rules_0);
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_1__ADDRESS, it->second);
            srm_reg_write(
                it->first, SRM_MCU_ANLT_RULES_2__ADDRESS, follower_rules[0]); // Might be overkill to write to all registers but
            srm_reg_write(it->first,
                          SRM_MCU_ANLT_RULES_3__ADDRESS,
                          follower_rules[1]); // but there's valid bit in register. Clear it if not setup.
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_4__ADDRESS, follower_rules[2]);
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_5__ADDRESS, follower_rules[3]);
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_6__ADDRESS, follower_rules[4]);
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_7__ADDRESS, follower_rules[5]);
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_8__ADDRESS, follower_rules[6]);
            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_9__ADDRESS, follower_rules[7]);

            srm_reg_write(it->first, SRM_MCU_ANLT_RULES_10__ADDRESS, anlt_rules_10);
            srm_status |= srm_anlt_cp_an_to_overlays(it->first, rules);
            srm_status |= srm_anlt_cp_lt_to_overlays(it->first, rules);

            srm_anlt_req_cmd(it->first, 4); // SRM_ANLT_CMD_ANLT_INIT);
        }

        CSCO_SRM_UNLOCK(it->first);
        if (srm_status != IP_OK) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    // Now download the RX leader.
    die_to_masks[bundle->an_leader.rx_die] = rx_leader_mask;

    // init Rx PMD last
    srm_status |= srm_cp_rx_rules_bundle_to_channel(&(rules->rx), &rx_rules, -1);
    srm_status |= srm_cp_rx_rules_bundle_to_channel(&(rules->rx), &rx_rules, 0);
    log_debug(SERDES, "leader rx_init die=0x%08x, channel=%d\n", bundle->an_leader.rx_die, bundle->an_leader.rx_channel);
    srm_init_rx(bundle->an_leader.rx_die, bundle->an_leader.rx_channel, &rx_rules);
    CSCO_SRM_LOCK(bundle->an_leader.rx_die);
    srm_status |= srm_anlt_wait_for_ack_clear(bundle->an_leader.rx_die);
    if (srm_status == IP_OK) {
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_0__ADDRESS, anlt_rules_0);
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_1__ADDRESS, die_to_masks[bundle->an_leader.rx_die]);
        srm_reg_write(bundle->an_leader.rx_die,
                      SRM_MCU_ANLT_RULES_2__ADDRESS,
                      follower_rules[0]); // Might be overkill to write to all registers but
        srm_reg_write(bundle->an_leader.rx_die,
                      SRM_MCU_ANLT_RULES_3__ADDRESS,
                      follower_rules[1]); // but there's valid bit in register. Clear it if not setup.
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_4__ADDRESS, follower_rules[2]);
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_5__ADDRESS, follower_rules[3]);
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_6__ADDRESS, follower_rules[4]);
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_7__ADDRESS, follower_rules[5]);
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_8__ADDRESS, follower_rules[6]);
        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_9__ADDRESS, follower_rules[7]);

        srm_reg_write(bundle->an_leader.rx_die, SRM_MCU_ANLT_RULES_10__ADDRESS, anlt_rules_10);
        srm_status |= srm_anlt_cp_an_to_overlays(bundle->an_leader.rx_die, rules);
        srm_status |= srm_anlt_cp_lt_to_overlays(bundle->an_leader.rx_die, rules);

        srm_anlt_req_cmd(bundle->an_leader.rx_die, 4); // SRM_ANLT_CMD_ANLT_INIT);
    }

    CSCO_SRM_UNLOCK(bundle->an_leader.rx_die);

    if (srm_status != IP_OK) {
        log_err(SERDES, "SerDes %d/%d/%d Failed to initialize for ANLT.", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::teardown_anlt()
{
    ip_status_t srm_status = IP_OK;
    srm_anlt_bundle_t tmp_bundle;
    srm_anlt_rules_t anlt_rules;

    la_status stat = build_anlt_bundle(tmp_bundle);
    return_on_error(stat);

    srm_anlt_rules_set_default(&anlt_rules);
    // Use the Inphi API srm_anlt_int() to tear down the ANLT rules because it has the implementation
    // Important, an.enable and lt.enalbe must set to FALSE for it to skip ANLT init.
    anlt_rules.an.enable = false;
    anlt_rules.lt.enable = false;
    srm_status = srm_anlt_init(&tmp_bundle, &anlt_rules);
    if (srm_status != IP_OK) {
        log_err(SERDES, "SerDes %d/%d/%d Failed to teardown RX ANLT rules.", m_slice_id, m_ifg_id, m_serdes_base_id);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_handler::refresh_tx()
{
    return LA_STATUS_SUCCESS;
}

srm_serdes_handler::srm_anlt_bundle_data
srm_serdes_handler::save_m_bundle() const
{
    srm_anlt_bundle_data data;
    memcpy(data.data(), &m_bundle, data.size());
    return data;
}

void
srm_serdes_handler::load_m_bundle(const srm_serdes_handler::srm_anlt_bundle_data& data)
{
    memcpy(&m_bundle, data.data(), data.size());
}
}
