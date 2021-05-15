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

#include "avago_serdes_handler.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "common/stopwatch.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "reconnect_handler.h"
#include "serdes_device_handler.h"
#include "system/ifg_handler.h"
#include "system/la_device_impl.h"

#include "aapl/aapl.h"
#include "aapl/serdes.h"
#include "aapl/serdes_core.h"
#include "aapl/serdes_dma.h"
#include "aapl_impl.h"
#include "la_device_impl.h"

#include <chrono>
#include <cmath>
#include <functional>
#include <iomanip>
#include <jansson.h>
#include <numeric>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>

using namespace std;

namespace silicon_one
{

enum { SERDES_ICAL_DEBUG_BUILD = 0x2081, SERDES_ICAL_REGULAR_BUILD = 0x208d };

enum { MAX_RX_INIT_RETRIES = 10, MIN_EYE_HEIGHT = 16, MAX_IFG_COUNT = 12, MAX_SERDES_COUNT = 18 };

enum {
    AVAGO_INT_READ = 0x4000,
    AVAGO_INT_WRITE = 0x8000,
    AVAGO_INT_RX_PLL2 = 0x85,
    AVAGO_INT_PMD_CONTROL = 0x0004,

    ///< First enum is the AN Config INT number, the rest are it's code[11:8]
    AVAGO_INT_AN_CONFIG = 0x0007,
    AVAGO_INT_AN_CONFIG_ENABLE = AVAGO_INT_AN_CONFIG,
    AVAGO_INT_AN_CONFIG_TIMER_INDEX_WORD0 = (AVAGO_INT_AN_CONFIG | (0x02 << 8)),
    AVAGO_INT_AN_CONFIG_TIMER_INDEX_WORD1 = (AVAGO_INT_AN_CONFIG | (0x03 << 8)),
    AVAGO_INT_AN_CONFIG_TIMER_TYPE = (AVAGO_INT_AN_CONFIG | (0x04 << 8)),
    AVAGO_INT_AN_CONFIG_NEXT_PAGE_LOADED = (AVAGO_INT_AN_CONFIG | (0x05 << 8)),
    AVAGO_INT_AN_CONFIG_READ_STATUS = (AVAGO_INT_AN_CONFIG | (0x07 << 8)),
    AVAGO_INT_AN_CONFIG_AN_FSM = (AVAGO_INT_AN_CONFIG | (0x08 << 8)),

    AVAGO_AN_FSM_AN_GOOD_STATE = 0x20,

    AVAGO_INT_AN_CONFIG_AN_CURRENT_STATE = 0x0001,
    AVAGO_INT_AN_CONFIG_AN_STICKY_STATES = 0x0002,

    AVAGO_INT_AN_CONFIG_LINK_FAIL_INHIBIT_TIMER_NRZ = 0x10,
    AVAGO_INT_AN_CONFIG_LINK_FAIL_INHIBIT_TIMER_PAM4 = 0x20,

    ///< First enum is the DME Page INT number, the rest are it's code[11:8]
    AVAGO_INT_AN_DME_PAGE = 0x0029,
    AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD0 = (AVAGO_INT_AN_DME_PAGE | (0x03 << 8)),
    AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD1 = (AVAGO_INT_AN_DME_PAGE | (0x04 << 8)),
    AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD2 = (AVAGO_INT_AN_DME_PAGE | (0x05 << 8)),
    AVAGO_INT_AN_BASE_PAGE_READ = (AVAGO_INT_AN_DME_PAGE | (0x06 << 8)),
    AVAGO_INT_AN_NEXT_PAGE_READ = (AVAGO_INT_AN_DME_PAGE | (0x07 << 8)),

    AVAGO_INT_RX_EQ_CONTROL = 0xa,

    AVAGO_MSB_CORE_STATUS = 0x69,

    AVAGO_HAL_MEMBER_TX_PLL = 0x00,
    AVAGO_HAL_MEMBER_RX_PLL = 0x01,
    AVAGO_HAL_MEMBER_PCAL_EFFORT = 0xd,
    AVAGO_HAL_MEMBER_TUNE_EFFORT = 0x18,
    AVAGO_HAL_MEMBER_RETRY_STATUS = 0x1B,
    AVAGO_HAL_MEMBER_SIGNAL_OK = 0x1c,
    AVAGO_HAL_MEMBER_NRZ_THRESHOLD = 0x1d,
    AVAGO_HAL_SIGNAL_OK_EID = 0xfff3,
    AVAGO_HAL_SIGNAL_OK_DFE_EID = 0x157,
    AVAGO_HAL_TUNE_EFFORT_SHORT = 0,   ///< Short tune
    AVAGO_HAL_TUNE_EFFORT_FULL = 1,    ///< Full tune - best tune but takes up to 30 seconds.
    AVAGO_HAL_TUNE_EFFORT_FAST = 0x10, ///< Fast tune - better than short and complete within 1 sec.

    AVAGO_HAL_MEMBER_TX_ATTN_COLD = 0x01,
    AVAGO_HAL_MEMBER_TX_ATTN_HOT = 0x02,

    AVAGO_HYSTERESIS_POST1_POSETIVE_MASK = 1 << 7,
    AVAGO_HYSTERESIS_POST1_NEGATIVE_MASK = 1 << 8,

    AVAGO_ELECTRICAL_IDLE_THRESHOLD = 8,
    AVAGO_ELECTRICAL_IDLE_ENABLE_DETECT = 0x200,
    AVAGO_ELECTRICAL_IDLE_DISABLE_DETECT = 0x100,

    AVAGO_SERDES_AN_TX_RX_WIDTH = 20,
    AVAGO_SERDES_AN_DIVIDER = 8,
    AVAGO_SERDES_AN_NO_TECHNOLOGY = 0x1f,

    REFCLK_FREQUENCY = 156250, // in units of kHz
    // The Spec define NRZ link_fail_inhibit_timer to 510ms. But we define it to 1000ms as our polling task is slow
    AN_NRZ_LINK_FAIL_INHIBIT_TIMER = 1000,
    // The Spec define PAM4 link_fail_inhibit_timer to 1.7sec. But we define it to 2.5sec as our polling task is slow
    AN_PAM4_LINK_FAIL_INHIBIT_TIMER = 2500,
    CONSORTUIM_400G_NEXT_PAGE_OUI = 0x6a737d,
    BRCM_400G_NEXT_PAGE_OUI = 0xaf7,
    AN_NEXT_PAGE_OUI_MESSAGE_CODE = 0x5,
    CAP_400G_BIT_NEXT_PAGE_WORD2 = 0x4, // AN 400G capability bit for both BRCM and consortium
    AN_BASE_PAGE_SELECTOR_MASK = 0x1f,
    AN_BASE_PAGE_SELECTOR = 1,
    AN_BASE_PAGE_NP_MASK = 0x8000,

    // Tx / Rx Baud Rate
    AVAGO_TX_BAUD_RATE = 0x05,
    AVAGO_RX_BAUD_RATE = 0x06,
    // Select REFCLK1 as the TxPLL reference clock
    AVAGO_TX_BAUD_RATE_REFCLK1_SELECT = 1 << 14,
    AVAGO_TX_BAUD_RATE_NOT_REFCLK_SYNC_SLAVE = 1 << 12,
    AVAGO_TX_BAUD_RATE_APPLY_TO_TX_AND_RX = 1 << 15,
    // Select REFCLK1 as the RxPLL reference clock
    AVAGO_RX_BAUD_RATE_REFCLK1_SELECT = 1 << 14,

    AVAGO_SERDES_PMD_CONTROL = 0x52,

    AVAGO_DELTA_CAL_FAIL_MASK = 7 << 12,
    AVAGO_DELTA_CAL_FAIL_VALUE = 0x7000,

    // Used to read Link Training Tune Time
    // "That is an internal debug register we added for this purpose specifically. It is not shown in the documentation.
    // Interrupt 0x126 0x6200 reads a register that is set to 0 when iCal begins. During iCal it is incremented once every 250,000
    // refclk cycles. For a 156.25MHz reference clock that means it gets incremented once every 1.6ms (250,000/156,250,000 =
    // 0.0016s)." - Avago Aaron
    AVAGO_INT_READ_SET_RX_EQ = 0x126,
    AVAGO_ICAL_TIMER = 0x6200,
};

struct serdes_config_data {
    uint32_t data_width;
    uint32_t data_width_code;
    bool pam4_enable;
};

const std::map<la_mac_port::port_speed_e, serdes_config_data> s_serdes_config = {
    // 10G
    {la_mac_port::port_speed_e::E_10G, {20, 0, false}},
    // 25G
    {la_mac_port::port_speed_e::E_25G, {40, 1, false}},
    // 50G
    {la_mac_port::port_speed_e::E_50G, {80, 2, true}}};

// Defines the Rx and Tx divider for each serdes speed.
// Key is SerDes speed in Gbps and value is divider value.
typedef std::unordered_map<size_t, size_t> serdes_speed_to_divider_t;

static const serdes_speed_to_divider_t s_serdes_speed_to_divider = {
    serdes_speed_to_divider_t::value_type(10, 66),
    serdes_speed_to_divider_t::value_type(20, 132),
    serdes_speed_to_divider_t::value_type(25, 165),
    serdes_speed_to_divider_t::value_type(26, 170),
    serdes_speed_to_divider_t::value_type(51, 165),
    serdes_speed_to_divider_t::value_type(53, 170),
    serdes_speed_to_divider_t::value_type(56, 180),
};

struct serdes_test_mode_e_hasher {
    std::size_t operator()(const la_mac_port::serdes_test_mode_e& mode) const
    {
        return (std::hash<size_t>()((size_t)mode));
    }
};

// Tx Slip values from Tomer Osi 3/27/2020 based on sweep tests
const char tx_slip_config[MAX_IFG_COUNT][MAX_SERDES_COUNT]{
    {14, 13, 14, 15, 14, 16, 16, 17, 14, 15, 14, 15, 15, 16, 15, 16, 15, 17},
    {0, 17, 16, 16, 15, 15, 15, 14, 13, 13, 13, 13, 12, 13, 13, 14, 14, 15},
    {0, 17, 16, 16, 15, 15, 15, 15, 13, 13, 13, 13, 12, 13, 13, 14, 14, 15},
    {15, 14, 15, 14, 14, 15, 15, 17, 13, 15, 13, 15, 14, 15, 15, 15, 17, 19},
    {13, 13, 13, 13, 13, 14, 13, 13, 14, 13, 13, 12, 13, 13, 13, 13, 16, 14},
    {13, 13, 13, 13, 13, 13, 13, 12, 13, 13, 13, 13, 12, 12, 12, 13, 12, 12},
    {13, 13, 13, 13, 13, 13, 13, 12, 13, 13, 13, 13, 12, 13, 13, 13, 13, 12},
    {13, 12, 13, 13, 13, 14, 13, 13, 14, 13, 13, 12, 13, 13, 13, 13, 17, 14},
    {16, 14, 15, 14, 14, 15, 16, 17, 13, 15, 14, 15, 14, 15, 15, 15, 17, 19},
    {1, 17, 16, 16, 15, 15, 15, 14, 13, 13, 13, 13, 13, 13, 13, 14, 14, 15},
    {0, 17, 16, 16, 15, 15, 15, 14, 13, 13, 13, 13, 12, 13, 13, 14, 14, 15},
    {14, 13, 14, 15, 14, 16, 16, 17, 14, 15, 15, 15, 15, 16, 15, 16, 15, 17}};

struct serdes_test_mode_cfg {
    Avago_serdes_tx_data_sel_t tx_data;
    Avago_serdes_rx_cmp_data_t rx_data;
    Avago_serdes_rx_cmp_mode_t rx_mode;
};

const std::unordered_map<la_mac_port::serdes_test_mode_e, serdes_test_mode_cfg, serdes_test_mode_e_hasher> serdes_test_mode_data
    = {{
        {la_mac_port::serdes_test_mode_e::NONE,
         {AVAGO_SERDES_TX_DATA_SEL_CORE, AVAGO_SERDES_RX_CMP_DATA_OFF, AVAGO_SERDES_RX_CMP_MODE_OFF}},
        {la_mac_port::serdes_test_mode_e::PRBS7,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS7, AVAGO_SERDES_RX_CMP_DATA_PRBS7, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
        {la_mac_port::serdes_test_mode_e::PRBS9,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS9, AVAGO_SERDES_RX_CMP_DATA_PRBS9, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
        {la_mac_port::serdes_test_mode_e::PRBS11,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS11, AVAGO_SERDES_RX_CMP_DATA_PRBS11, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
        {la_mac_port::serdes_test_mode_e::PRBS13,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS13, AVAGO_SERDES_RX_CMP_DATA_PRBS13, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
        {la_mac_port::serdes_test_mode_e::PRBS15,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS15, AVAGO_SERDES_RX_CMP_DATA_PRBS15, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
        {la_mac_port::serdes_test_mode_e::PRBS23,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS23, AVAGO_SERDES_RX_CMP_DATA_PRBS23, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
        {la_mac_port::serdes_test_mode_e::PRBS31,
         {AVAGO_SERDES_TX_DATA_SEL_PRBS31, AVAGO_SERDES_RX_CMP_DATA_PRBS31, AVAGO_SERDES_RX_CMP_MODE_MAIN_PATGEN}},
    }};

/// @brief Each triplet define a next page of 48 bits. Each value is 16b word. 802.3 Annex 73A NULL page.
const avago_serdes_handler::an_page_data_t s_null_next_page = {{0x2001, 0x0, 0x0}}; // 0x2000 = MP (MessagePage bit)

/// @brief Broadcom and Consortium 400G_CR8 Next pages
const std::vector<avago_serdes_handler::an_page_data_t> s_outbound_an_pages
    = {{{0xA005, 0x0, 0x2BD}},   // Broadcom 400G Next Page 1
       {{0x8600, 0x0, 0x4}},     // Broadcom 400G Next Page 2
       {{0xA005, 0x353, 0x4DF}}, // Consortium 400G Next Page 1
       {{0x8203, 0x330, 0x4}},   // Consortium 400G Next Page 2
       s_null_next_page};        // NULL page for AN ACK2 signaling

avago_serdes_handler::avago_serdes_handler()
{
}

avago_serdes_handler::avago_serdes_handler(const la_device_impl_wptr& device,
                                           Aapl_t* aapl_handler,
                                           la_slice_id_t slice_id,
                                           la_ifg_id_t ifg_id,
                                           la_uint_t serdes_base_id,
                                           size_t serdes_count,
                                           la_mac_port::port_speed_e speed,
                                           la_mac_port::port_speed_e serdes_speed,
                                           la_slice_mode_e serdes_slice_mode)
    : m_device(device),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_serdes_base_id(serdes_base_id),
      m_serdes_count(serdes_count),
      m_speed(speed),
      m_serdes_speed(serdes_speed),
      m_serdes_slice_mode(serdes_slice_mode),
      m_anlt_debug_snapshot_queue(5)
{
    m_enable_eid = !m_device->m_device_properties[(int)la_device_property_e::DISABLE_ELECTRICAL_IDLE_DETECTION].bool_val;

    m_dfe_eid = m_device->m_device_properties[(int)la_device_property_e::SERDES_DFE_EID].bool_val;
    m_loopback_mode = la_mac_port::loopback_mode_e::NONE;

    m_serdes_rxpll_value_vec.resize(m_serdes_count);
    m_serdes_rxpll2_value_vec.resize(m_serdes_count);

    m_serdes_param_vec.resize(m_serdes_count);
    for (la_uint_t index = 0; index < m_serdes_count; index++) {
        m_serdes_param_vec[index].resize((la_uint_t)la_mac_port::serdes_param_stage_e::LAST + 1);
    }

    m_anlt_lane.resize(m_serdes_count, 0);
    size_t first_tx_lane = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id].anlt_order;
    for (size_t serdes_id = 1; serdes_id < m_serdes_count; serdes_id++) {
        size_t serdes = m_serdes_base_id + serdes_id;
        if (first_tx_lane > m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order) {
            first_tx_lane = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order;
        }
    }

    for (size_t serdes_id = 0; serdes_id < m_serdes_count; serdes_id++) {
        size_t serdes = m_serdes_base_id + serdes_id;
        m_anlt_lane[serdes_id]
            = m_device->m_serdes_info[m_slice_id][m_ifg_id][serdes].anlt_order - first_tx_lane + m_serdes_base_id;
    }

    m_aapl_handler = aapl_handler;
    m_tuning_mode = la_mac_port::serdes_tuning_mode_e::ICAL;
    m_debug_mode = false;
    m_continuous_tuning_enabled = true;
    m_continuous_tuning_activated = false;
    m_bad_an_base_page_print = false;

    populate_default_serdes_parameters();
}

avago_serdes_handler::~avago_serdes_handler()
{
}

void
avago_serdes_handler::populate_default_serdes_parameters()
{
    bool pam4_enable = s_serdes_config.at(m_serdes_speed).pam4_enable;

    for (la_uint_t serdes_idx = 0; serdes_idx < m_serdes_count; serdes_idx++) {
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_PLL_BB,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             2);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_PLL_IFLT,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             6);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_PLL_INT,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             7);
        // Use 27 (9MHz) for east side dies in Slice2/Slice3
        // Excludes SerDes 2-7 on IFG4/7
        la_uint_t abs_serdes = m_serdes_base_id + serdes_idx;
        if ((m_slice_id == 2 && !((m_ifg_id == 0) && (abs_serdes >= 2 && abs_serdes <= 7)))
            || (m_slice_id == 3 && !((m_ifg_id == 1) && (abs_serdes >= 2 && abs_serdes <= 7)))) {
            set_serdes_parameter(serdes_idx,
                                 la_mac_port::serdes_param_stage_e::ACTIVATE,
                                 la_mac_port::serdes_param_e::TX_PLL_BB,
                                 la_mac_port::serdes_param_mode_e::FIXED,
                                 27);
        } else {
            set_serdes_parameter(serdes_idx,
                                 la_mac_port::serdes_param_stage_e::ACTIVATE,
                                 la_mac_port::serdes_param_e::TX_PLL_BB,
                                 la_mac_port::serdes_param_mode_e::FIXED,
                                 25);
        }
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_PLL_IFLT,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             1);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_PLL_INT,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             7);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_CTLE_LF,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             0x8);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_CTLE_HF,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             0xf);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::RX_CTLE_BW,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             0xf);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_ATTN_COLD_SIG_ENVELOPE,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             120);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::ACTIVATE,
                             la_mac_port::serdes_param_e::TX_ATTN_HOT_SIG_ENVELOPE,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             70);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::PRE_ICAL,
                             la_mac_port::serdes_param_e::RX_CTLE_HF,
                             la_mac_port::serdes_param_mode_e::ADAPTIVE,
                             0x0);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::PRE_ICAL,
                             la_mac_port::serdes_param_e::RX_CTLE_BW,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             0x0);
        set_serdes_parameter(serdes_idx,
                             la_mac_port::serdes_param_stage_e::PRE_PCAL,
                             la_mac_port::serdes_param_e::RX_PCAL_EFFORT,
                             la_mac_port::serdes_param_mode_e::FIXED,
                             0x1);
        if (pam4_enable) {
            set_serdes_parameter(serdes_idx,
                                 la_mac_port::serdes_param_stage_e::PRE_ICAL,
                                 la_mac_port::serdes_param_e::RX_CTLE_LF,
                                 la_mac_port::serdes_param_mode_e::ADAPTIVE,
                                 4);
            set_serdes_parameter(serdes_idx,
                                 la_mac_port::serdes_param_stage_e::PRE_PCAL,
                                 la_mac_port::serdes_param_e::RX_CTLE_LF,
                                 la_mac_port::serdes_param_mode_e::STATIC,
                                 4);
        } else {
            set_serdes_parameter(serdes_idx,
                                 la_mac_port::serdes_param_stage_e::PRE_ICAL,
                                 la_mac_port::serdes_param_e::RX_CTLE_LF,
                                 la_mac_port::serdes_param_mode_e::ADAPTIVE,
                                 0x8);
        }
    }
}

la_status
avago_serdes_handler::set_serdes_parameter(la_uint_t serdes_idx,
                                           la_mac_port::serdes_param_stage_e stage,
                                           la_mac_port::serdes_param_e param,
                                           la_mac_port::serdes_param_mode_e mode,
                                           int32_t value)
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Check valid mode/value.
    switch (param) {
    case la_mac_port::serdes_param_e::RX_CTLE_LF:
    case la_mac_port::serdes_param_e::RX_CTLE_HF:
    case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE1:
    case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE2:
    case la_mac_port::serdes_param_e::RX_CTLE_SHORT_CHANNEL_EN:
    case la_mac_port::serdes_param_e::RX_FFE_PRE2:
    case la_mac_port::serdes_param_e::RX_FFE_PRE1:
    case la_mac_port::serdes_param_e::RX_FFE_POST:
    case la_mac_port::serdes_param_e::RX_FFE_BFLF:
    case la_mac_port::serdes_param_e::RX_FFE_BFHF:
    case la_mac_port::serdes_param_e::RX_FFE_SHORT_CHANNEL_EN:
        break;
    case la_mac_port::serdes_param_e::HYSTERESIS_POST1_NEGATIVE:
    case la_mac_port::serdes_param_e::HYSTERESIS_POST1_POSETIVE:
        if ((mode != la_mac_port::serdes_param_mode_e::FIXED) || (stage != la_mac_port::serdes_param_stage_e::PRE_PCAL)) {
            log_err(SERDES,
                    "Invalid SerDes parameter configuration for Slice/IFG/SerDes %d/%d/%d "
                    "parameter %s supported only on PRE_PCAL and FIXED",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    to_string(param).c_str());
            return LA_STATUS_EINVAL;
        }
        break;
    case la_mac_port::serdes_param_e::RX_PCAL_EFFORT:
        if (stage != la_mac_port::serdes_param_stage_e::PRE_PCAL) {
            log_err(SERDES,
                    "Invalid SerDes parameter configuration for Slice/IFG/SerDes %d/%d/%d "
                    "parameter %s supported only on PRE_PCAL",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    to_string(param).c_str());
            return LA_STATUS_EINVAL;
        }
        break;
    case la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE:
    case la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE:
    case la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE:
    case la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE:
    case la_mac_port::serdes_param_e::DIVIDER:
    case la_mac_port::serdes_param_e::ELECTRICAL_IDLE_THRESHOLD:
    case la_mac_port::serdes_param_e::RX_CTLE_HF_MAX:
    case la_mac_port::serdes_param_e::RX_CTLE_HF_MIN:
    case la_mac_port::serdes_param_e::RX_CTLE_LF_MAX:
    case la_mac_port::serdes_param_e::RX_CTLE_LF_MIN:
    case la_mac_port::serdes_param_e::RX_CTLE_DC:
    case la_mac_port::serdes_param_e::RX_CTLE_BW:
    case la_mac_port::serdes_param_e::RX_FFE_PRE1_MAX:
    case la_mac_port::serdes_param_e::RX_FFE_PRE1_MIN:
    case la_mac_port::serdes_param_e::RX_FFE_PRE2_MAX:
    case la_mac_port::serdes_param_e::RX_FFE_PRE2_MIN:
    case la_mac_port::serdes_param_e::RX_PLL_BB:
    case la_mac_port::serdes_param_e::RX_PLL_IFLT:
    case la_mac_port::serdes_param_e::RX_PLL_INT:
    case la_mac_port::serdes_param_e::RX_NRZ_EYE_THRESHOLD:
    case la_mac_port::serdes_param_e::RX_TERM:
    case la_mac_port::serdes_param_e::TX_ATTN:
    case la_mac_port::serdes_param_e::TX_ATTN_COLD_SIG_ENVELOPE:
    case la_mac_port::serdes_param_e::TX_ATTN_HOT_SIG_ENVELOPE:
    case la_mac_port::serdes_param_e::TX_PLL_BB:
    case la_mac_port::serdes_param_e::TX_PLL_IFLT:
    case la_mac_port::serdes_param_e::TX_PLL_INT:
    case la_mac_port::serdes_param_e::TX_POST:
    case la_mac_port::serdes_param_e::TX_PRE1:
    case la_mac_port::serdes_param_e::TX_PRE2:
    case la_mac_port::serdes_param_e::TX_PRE3:
    case la_mac_port::serdes_param_e::TX_CLK_REFSEL:
    case la_mac_port::serdes_param_e::RX_CLK_REFSEL:
    case la_mac_port::serdes_param_e::RX_FAST_TUNE:

        if (mode != la_mac_port::serdes_param_mode_e::FIXED) {
            log_err(SERDES,
                    "Only serdes_param_mode_e::FIXED is supported for SerDes parameter Slice/IFG/SerDes %d/%d/%d for "
                    "stage %s, parameter %s",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    to_string(stage).c_str(),
                    to_string(param).c_str());
            return LA_STATUS_EINVAL;
        }
        break;
    default:
        log_err(SERDES,
                "Invalid SerDes parameter configuration for Slice/IFG/SerDes %d/%d/%d "
                "parameter %s is not supported on this device.",
                m_slice_id,
                m_ifg_id,
                m_serdes_base_id,
                to_string(param).c_str());
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    serdes_param_setting param_st = {.mode = mode, .value = value};
    m_serdes_param_vec[serdes_idx][(size_t)stage][param] = param_st;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::get_serdes_parameter(la_uint_t serdes_idx,
                                           la_mac_port::serdes_param_stage_e stage,
                                           la_mac_port::serdes_param_e param,
                                           la_mac_port::serdes_param_mode_e& out_mode,
                                           int32_t& out_value) const
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
avago_serdes_handler::get_serdes_parameter_hardware_value(la_uint_t serdes_idx,
                                                          la_mac_port::serdes_param_e param,
                                                          int32_t& out_value)
{
    if (serdes_idx >= m_serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
avago_serdes_handler::get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const
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
avago_serdes_handler::clear_serdes_parameter(la_uint_t serdes_idx,
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

void
avago_serdes_handler::print_anlt_status(const char* message,
                                        uint serdes,
                                        uint msb_core_status,
                                        uint lsb_core_status,
                                        float link_training_tune_time)
{
    logger& instance = logger::instance();
    std::string status_str = "";

    if (instance.is_logging(
            silicon_one::get_device_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::XDEBUG)) {
        uint32_t core_status = (msb_core_status << 16) | (lsb_core_status & 0xFFFF);
        for (uint32_t index = 0; index < 26; index++) {
            char temp_str[35];
            uint char_count = 0;
            uint status = (core_status >> index) & 1;
            switch (index) {
            case 0:
                char_count = sprintf(temp_str, "0:LT Fail-%1d  ", status);
                break;
            case 1:
                char_count = sprintf(temp_str, "1:(0=CMPLT)-%1d  ", status);
                break;
            case 2:
                char_count = sprintf(temp_str, "2:RX TRAINED-%1d  ", status);
                break;
            case 4:
                char_count = sprintf(temp_str, "4:SIG OK-%1d  ", status);
                break;
            case 5:
                char_count = sprintf(temp_str, "5:FW & SPICO RDY-%1d  ", status);
                break;
            case 16:
                char_count = sprintf(temp_str, "16:RCV FEC REQ-%1d  ", status);
                break;
            case 17:
                char_count = sprintf(temp_str, "17:RCV FEC CAP-%1d  ", status);
                break;
            case 18:
                char_count = sprintf(temp_str, "18:RMT RX RDY-%1d  ", status);
                break;
            case 19:
                char_count = sprintf(temp_str, "19:AN CMPLT-%1d  ", status);
                break;
            case 20:
                char_count = sprintf(temp_str, "20:AN LINK GOOD-%1d  ", status);
                break;
            case 24:
                char_count = sprintf(temp_str, "24:FEC EN-%1d  ", status);
                break;
            case 25:
                char_count = sprintf(temp_str, "25:RSFEC EN-%1d  ", status);
                break;
            }
            if (char_count > 0)
                status_str += temp_str;
        }
        log_xdebug(SERDES,
                   "%s - Serdes slice/ifg/serdes=%d/%d/%d core_status=0x%08x. BITS %s Link Training Tune Time (ms) %f",
                   message,
                   m_slice_id,
                   m_ifg_id,
                   serdes,
                   core_status,
                   status_str.c_str(),
                   link_training_tune_time);
    }
}
size_t
avago_serdes_handler::get_ifg_reflck() const
{
    int refclk_per_ifg;
    m_device->get_int_property(la_device_property_e::DEV_REFCLK_SEL, refclk_per_ifg);
    // Total 12 bits, single bit for each IFG.
    return (refclk_per_ifg >> (m_slice_id * 2 + m_ifg_id)) & 0x1;
}

la_status
avago_serdes_handler::an_link_training_configure(bool is_an)
{
    uint width = is_an ? (uint)AVAGO_SERDES_AN_TX_RX_WIDTH : s_serdes_config.at(m_serdes_speed).data_width;
    uint default_divider = s_serdes_speed_to_divider.find(m_serdes_speed_gbps)->second;
    uint divider = is_an ? (uint)AVAGO_SERDES_AN_DIVIDER : default_divider;
    bool is_pam4 = !is_an && (m_serdes_speed == la_mac_port::port_speed_e::E_50G);
    Avago_serdes_line_encoding_t serdes_encoding = is_pam4 ? AVAGO_SERDES_PAM4 : AVAGO_SERDES_NRZ;

    size_t refclk = get_ifg_reflck();
    for (size_t lane = 0; lane < m_anlt_lane.size(); lane++) {

        size_t serdes_index = m_anlt_lane[lane] - m_serdes_base_id;

        int rx_clk_sel = get_serdes_parameter_per_lane(serdes_index, la_mac_port::serdes_param_e::RX_CLK_REFSEL, 0 /* default */);
        int tx_clk_sel = get_serdes_parameter_per_lane(serdes_index, la_mac_port::serdes_param_e::TX_CLK_REFSEL, refclk);

        size_t serdes_addr = m_anlt_lane[lane] + 1;
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, FALSE, FALSE, FALSE); // Disable serdes TX/RX

        // Set Tx divider
        int div_val = AVAGO_TX_BAUD_RATE_NOT_REFCLK_SYNC_SLAVE | AVAGO_TX_BAUD_RATE_APPLY_TO_TX_AND_RX | divider;
        if (tx_clk_sel) {
            div_val |= AVAGO_TX_BAUD_RATE_REFCLK1_SELECT;
        }
        avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_TX_BAUD_RATE, div_val); // set serdes bit/ref ratio
        // Set Rx divider
        div_val = divider;
        if (rx_clk_sel) {
            div_val |= AVAGO_RX_BAUD_RATE_REFCLK1_SELECT;
        }
        avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_RX_BAUD_RATE, div_val); // set serdes bit/ref ratio
        avago_serdes_set_tx_rx_width_pam(m_aapl_handler, serdes_addr, width, width, serdes_encoding, serdes_encoding);

        // enable serdes RX/TX, and enable TX output for AN SerDes Lane0 only
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, TRUE, TRUE, is_an);
        if (is_an) {
            break;
        }
    }

    return LA_STATUS_SUCCESS;
}

void
avago_serdes_handler::serdes_inhibit_timer_configure()
{
    uint lane0_serdes_addr = m_anlt_lane[0] + 1;

    // Configure Link Fail Inhibit Timer to Avago SerDes
    // The Spec define link_fail_inhibit_timer to 510ms for NRZ and 1.7s for PAM4. But we redefine them to 1s and 2.5s
    // due to slow SDK polling task, which takes more time to identify AN GOOD CHECK, SerDes configuration and Link training start
    const size_t spec_timer
        = (m_serdes_speed == la_mac_port::port_speed_e::E_50G) ? AN_PAM4_LINK_FAIL_INHIBIT_TIMER : AN_NRZ_LINK_FAIL_INHIBIT_TIMER;
    size_t timer_index = REFCLK_FREQUENCY * spec_timer;
    avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_TIMER_INDEX_WORD0, timer_index & 0xffff);
    avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_TIMER_INDEX_WORD1, timer_index >> 16);
    avago_spico_int(m_aapl_handler,
                    lane0_serdes_addr,
                    AVAGO_INT_AN_CONFIG_TIMER_TYPE,
                    (m_serdes_speed == la_mac_port::port_speed_e::E_50G) ? AVAGO_INT_AN_CONFIG_LINK_FAIL_INHIBIT_TIMER_PAM4
                                                                         : AVAGO_INT_AN_CONFIG_LINK_FAIL_INHIBIT_TIMER_NRZ);
}

la_status
avago_serdes_handler::an_start(la_mac_port::state_e& state)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t serdes_addr = m_serdes_base_id + serdes + 1;
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, FALSE, FALSE, FALSE); // Disable serdes
    }

    uint lane0_serdes_addr = m_anlt_lane[0] + 1;

    // Avoid automatic sending of last loaded Next Page
    avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_NEXT_PAGE_LOADED, 0);
    // Disable Auto-Negotiation
    avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_ENABLE, 0x0);

    serdes_inhibit_timer_configure();

    an_link_training_configure(true);

    Avago_serdes_an_config_t* config = avago_serdes_an_config_construct(m_aapl_handler);

    // On non-spec AN port we do want to send next pages. On Spec AN only we don't care about the next page and let the FW take care
    // of it.
    // For non-spec AN (e.g. 400G) there is no standard capabilities. So we use Next pages
    config->np_continuous_load = (m_an_spec_cap != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY) ? 1 : 0;
    config->np_enable = (m_an_spec_cap != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY) ? 0 : 1;
    config->user_cap = static_cast<unsigned int>(m_an_spec_cap);
    config->fec_request = m_an_fec_request;
    config->fec_ability = (config->fec_request == 1);

    avago_serdes_an_start(m_aapl_handler, lane0_serdes_addr, config); // Enable Auto-Negotiation
    avago_serdes_an_config_destruct(m_aapl_handler, config);

    if (m_an_spec_cap == serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY) {
        m_inbound_an_pages.clear();
        state = la_mac_port::state_e::AN_BASE_PAGE;
    } else {
        state = la_mac_port::state_e::AN_POLL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::an_stop()
{
    log_debug(SERDES, "Stopping AN for Slice/IFG/SerDes %d/%d/%d", m_slice_id, m_ifg_id, m_serdes_base_id);

    // Needed as a workaround for CSCvq95732
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t tx_addr = tx_serdes + 1;

        // Force clear any previous AN config, Force TX to stop.
        avago_serdes_mem_wr(m_aapl_handler, tx_addr, AVAGO_DMEM, AVAGO_SERDES_PMD_CONTROL, 0);

        // Disable AN State Machine
        avago_spico_int(m_aapl_handler, tx_addr, AVAGO_AUTO_NEGOTIATION, 0);
    }
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::reset()
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        Avago_addr_t addr_struct;
        bool res = avago_addr_to_struct(serdes + m_serdes_base_id + 1, &addr_struct);
        if (!res) {
            return LA_STATUS_EUNKNOWN;
        }

        bool skip_crc = true;
        int ret = avago_parallel_serdes_base_init(m_aapl_handler, &addr_struct, skip_crc);
        if (ret < 0) {
            log_err(SERDES,
                    "Failed avago_parallel_serdes_base_init Slice/IFG/SerDes %d/%d/%d -> %d",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    ret);
            return LA_STATUS_EUNKNOWN;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::an_base_page_rcv(la_mac_port::state_e& state)
{
    uint lane0_serdes_addr = m_anlt_lane[0] + 1;
    uint status = avago_serdes_an_read_status(m_aapl_handler, lane0_serdes_addr, AVAGO_SERDES_AN_BASE_PAGE_RX);
    if (status == 0) {
        return LA_STATUS_SUCCESS;
    }

    // Base page has been received => read the base page.
    an_page_data_t an_base_page;
    for (int word = 0; word < 3; word++) {
        an_base_page.word[word] = avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_BASE_PAGE_READ, word);
    }

    if ((an_base_page.word[0] & AN_BASE_PAGE_SELECTOR_MASK) != AN_BASE_PAGE_SELECTOR
        || (an_base_page.word[0] & AN_BASE_PAGE_NP_MASK) == 0) {
        anlt_debug_snapshot anlt_snapshot{};

        // populate AN/LT snapshot
        add_timestamp(anlt_snapshot.timestamp, sizeof(anlt_snapshot.timestamp));
        anlt_snapshot.error_type = anlt_err_type_e::AN_BASE_PAGE_ERROR;
        sprintf(anlt_snapshot.cause, "Base page received invalid");
        anlt_snapshot.base_page_word = an_base_page;

        // add snapshot to queue
        m_anlt_debug_snapshot_queue.push(anlt_snapshot);

        state = la_mac_port::state_e::INACTIVE;
        if (!m_bad_an_base_page_print) {
            log_warning(SERDES,
                        "base page received with invalid Selector or Next Page fields: slice/ifg/serdes/lane_serdes=%d/%d/%d/%d "
                        "bp_32_47=0x%x bp_16_31=0x%x bp_0_15=0x%x",
                        m_slice_id,
                        m_ifg_id,
                        m_serdes_base_id,
                        m_anlt_lane[0],
                        an_base_page.word[2],
                        an_base_page.word[1],
                        an_base_page.word[0]);
            m_bad_an_base_page_print = true;
        }

        return LA_STATUS_SUCCESS;
    }

    m_inbound_an_pages.push_back(an_base_page);

    log_debug(SERDES,
              "base page received: slice/ifg/serdes/lane_serdes=%d/%d/%d/%d bp_32_47=0x%x bp_16_31=0x%x bp_0_15=0x%x",
              m_slice_id,
              m_ifg_id,
              m_serdes_base_id,
              m_anlt_lane[0],
              an_base_page.word[2],
              an_base_page.word[1],
              an_base_page.word[0]);

    an_page_data_t formatted_next_page = s_outbound_an_pages[0];
    avago_spico_int(
        m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD0, formatted_next_page.word[0]); /* bit[15:0] */
    avago_spico_int(
        m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD1, formatted_next_page.word[1]); /* bit [31:16] */
    avago_spico_int(
        m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD2, formatted_next_page.word[2]); /* bit [47:32] */
    avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_NEXT_PAGE_LOADED, 1);

    state = la_mac_port::state_e::AN_NEXT_PAGE;
    m_outbound_an_pages_idx = 1;

    // Clear AN Sticky state
    // Used to check if AN FSM move to AN_GOOD_CHECK after receiving last Next Page
    avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_AN_FSM, 2);

    // Start timer for AN Next Page receive time
    m_an_next_page_start = chrono::steady_clock::now();

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::an_next_page_rcv(la_mac_port::state_e& state)
{
    uint lane0_serdes_addr = m_anlt_lane[0] + 1;
    // Next Page received can be identified by either the AN_NEXT_PAGE_RX signal, or if we entered the AN_GOOD_CHECK
    // state which will fail to DISABLE_TRANSMIT state and clear the signal due to no HCD chosen by the SerDes
    uint status
        = avago_serdes_an_read_status(m_aapl_handler, lane0_serdes_addr, AVAGO_SERDES_AN_NEXT_PAGE_RX)
          || (avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_AN_FSM, 2) & AVAGO_AN_FSM_AN_GOOD_STATE);
    if (status == 0) {
        int next_page_timeout_ms = 0;
        m_device->get_int_property(la_device_property_e::MAC_PORT_AUTO_NEGOTIATION_TIMEOUT, next_page_timeout_ms);

        if (chrono::steady_clock::now() > (m_an_next_page_start + chrono::milliseconds(next_page_timeout_ms))) {
            // on timeout restart auto negotiation
            state = la_mac_port::state_e::INACTIVE;
            log_debug(SERDES,
                      "next page not received: slice/ifg/serdes/lane_serdes=%d/%d/%d/%d timeout %d ms, restarting auto neg.",
                      m_slice_id,
                      m_ifg_id,
                      m_serdes_base_id,
                      m_anlt_lane[0],
                      next_page_timeout_ms);
        }
        return LA_STATUS_SUCCESS;
    }

    // on succssful receive update AN Next Page receive time
    m_an_next_page_start = chrono::steady_clock::now();

    // Next page is ready => read it.
    an_page_data_t an_next_page;
    for (int word = 0; word < 3; word++) {
        an_next_page.word[word] = avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_READ, word);
    }

    bool ack2 = false;
    uint message_code = an_next_page.word[0] & 0x7ff;
    if (message_code != 0x1) {
        // Next page is not NULL next
        m_inbound_an_pages.push_back(an_next_page);
        ack2 = true;
    }

    // Check if another next page is available.
    bool next_page_np = (an_next_page.word[0] >> 15) & 0x1;

    log_debug(SERDES,
              "next page received: slice/ifg/serdes/lane_serdes=%d/%d/%d/%d np_32_47=0x%x np_16_31=0x%x np_0_15=0x%x",
              m_slice_id,
              m_ifg_id,
              m_serdes_base_id,
              m_anlt_lane[0],
              an_next_page.word[2],
              an_next_page.word[1],
              an_next_page.word[0]);

    an_page_data_t next_page;
    if (m_outbound_an_pages_idx < s_outbound_an_pages.size()) {
        next_page = s_outbound_an_pages[m_outbound_an_pages_idx];
    } else {
        // If all pages sent but need to continue to send next page -> send NULL next page.
        next_page = s_null_next_page;
    }

    if (ack2) {
        // Set ACK2 bit
        next_page.word[0] |= 1 << 12;
    }

    if (m_outbound_an_pages_idx < s_outbound_an_pages.size() || next_page_np || ack2) {
        log_debug(SERDES,
                  "next page loaded: slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d np_32_47=0x%x np_16_31=0x%x np_0_15=0x%x",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  m_anlt_lane[0],
                  next_page.word[2],
                  next_page.word[1],
                  next_page.word[0]);
        avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD0, next_page.word[0]); /* bit[15:0] */
        avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD1, next_page.word[1]); /* bit [31:16] */
        avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_NEXT_PAGE_WRITE_WORD2, next_page.word[2]); /* bit [47:32] */
        avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_NEXT_PAGE_LOADED, 0x1);

        if (m_outbound_an_pages_idx < s_outbound_an_pages.size()) {
            m_outbound_an_pages_idx++;
        }

    } else {
        log_debug(SERDES,
                  "no more next pages: slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  m_anlt_lane[0]);
        bool cap_400G_CR8 = false;
        anlt_debug_snapshot anlt_snapshot{};

        // resize snapshot vector because it is dynamic size
        anlt_snapshot.next_page_vec.resize(m_inbound_an_pages.size() - 1);

        // calculate common capabilities
        for (uint i = 0; i < (m_inbound_an_pages.size() - 1); i++) {
            an_page_data_t page = m_inbound_an_pages[i];
            an_page_data_t next_page = m_inbound_an_pages[i + 1];
            uint message_code = page.word[0] & 0x7ff;
            uint oui_code = ((page.word[1] & 0x7ff) << 13) | ((page.word[2] & 0x7ff) << 2) | ((next_page.word[0] >> 9) & 0x3);

            // populate snapshot data
            anlt_snapshot.next_page_vec[i].base_page = page;
            anlt_snapshot.next_page_vec[i].next_page = next_page;
            anlt_snapshot.next_page_vec[i].message_code = message_code;
            anlt_snapshot.next_page_vec[i].oui_code = oui_code;

            if (message_code == AN_NEXT_PAGE_OUI_MESSAGE_CODE
                && (oui_code == BRCM_400G_NEXT_PAGE_OUI || oui_code == CONSORTUIM_400G_NEXT_PAGE_OUI)) {
                cap_400G_CR8 |= next_page.word[2] & CAP_400G_BIT_NEXT_PAGE_WORD2;
            }
        }

        // move forward to AN POLL or backward to AN start
        if (cap_400G_CR8) {
            state = la_mac_port::state_e::AN_POLL;
        } else {

            // finish populating snapshot information
            anlt_snapshot.error_type = anlt_err_type_e::AN_NEXT_PAGE_ERROR;
            add_timestamp(anlt_snapshot.timestamp, sizeof(anlt_snapshot.timestamp));
            sprintf(anlt_snapshot.cause, "Next page receive error");

            // add snapshot into queue
            m_anlt_debug_snapshot_queue.push(anlt_snapshot);

            state = la_mac_port::state_e::INACTIVE;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::is_an_good_check(bool& an_good_check, la_mac_port::state_e& state)
{
    uint an_hcd = AVAGO_SERDES_AN_NO_TECHNOLOGY;
    uint lane0_serdes_addr = m_anlt_lane[0] + 1;
    if (m_an_spec_cap != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY) {
        uint status = avago_serdes_read_an_status(m_aapl_handler, lane0_serdes_addr, AVAGO_SERDES_AN_GOOD);
        log_debug(SERDES,
                  "AN poll: slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d -> %d\n",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  m_anlt_lane[0],
                  status);

        if (status == 0) {
            return LA_STATUS_SUCCESS; // Successfully retrieved AN status but status is incomplete
        }

        if (status != 1) {
            log_err(SERDES,
                    "AN poll failed on slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d HW FSM=0x%x sticky FSM=0x%x",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    m_anlt_lane[0],
                    avago_spico_int(
                        m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_AN_FSM, AVAGO_INT_AN_CONFIG_AN_CURRENT_STATE),
                    avago_spico_int(
                        m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_AN_FSM, AVAGO_INT_AN_CONFIG_AN_STICKY_STATES));
            return LA_STATUS_EUNKNOWN;
        }

        log_debug(SERDES,
                  "AN poll: slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d => AN GOOD\n",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  m_anlt_lane[0]);

        an_hcd = avago_serdes_read_an_status(m_aapl_handler, lane0_serdes_addr, AVAGO_SERDES_AN_READ_HCD);

        log_debug(SERDES,
                  "AN slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d hcd=%d base page: 15:0=0x%x, 31:16=0x%x, 47:32=0x%x",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  m_anlt_lane[0],
                  an_hcd,
                  avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_BASE_PAGE_READ, 0x0000),
                  avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_BASE_PAGE_READ, 0x0001),
                  avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_BASE_PAGE_READ, 0x0002));

        if (an_hcd == AVAGO_SERDES_AN_NO_TECHNOLOGY) {
            anlt_debug_snapshot anlt_snapshot{};

            log_info(SERDES,
                     "%s AN got unexpected hcd=0x%x slice/ifg/serdes=%d/%d/%d",
                     __func__,
                     an_hcd,
                     m_slice_id,
                     m_ifg_id,
                     m_serdes_base_id);

            // populate snapshot data
            add_timestamp(anlt_snapshot.timestamp, sizeof(anlt_snapshot.timestamp));
            anlt_snapshot.error_type = anlt_err_type_e::AN_HCD_NOT_SUPPORTED;
            sprintf(anlt_snapshot.cause, "AN got unexpected hcd");
            anlt_snapshot.an_hcd = an_hcd;

            // add snapshot to queue
            m_anlt_debug_snapshot_queue.push(anlt_snapshot);

            state = la_mac_port::state_e::INACTIVE;
            return LA_STATUS_SUCCESS;
        }

        if (m_an_fec_request) {
            Avago_serdes_an_status_t an_status
                = (m_an_fec_request & 0x2) ? AVAGO_SERDES_AN_READ_RSFEC_ENABLE : AVAGO_SERDES_AN_READ_FEC_ENABLE;
            uint status = avago_serdes_read_an_status(m_aapl_handler, lane0_serdes_addr, an_status);
            if (status != 1) {
                anlt_debug_snapshot anlt_snapshot{};

                log_info(SERDES,
                         "Failed to assert FEC Enable (fec_request=%ld) on slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d",
                         m_an_fec_request,
                         m_slice_id,
                         m_ifg_id,
                         m_serdes_base_id,
                         m_anlt_lane[0]);

                // populate snapshot data
                add_timestamp(anlt_snapshot.timestamp, sizeof(anlt_snapshot.timestamp));
                anlt_snapshot.error_type = anlt_err_type_e::AN_HCD_NOT_SUPPORTED;
                sprintf(anlt_snapshot.cause, "FEC is not supported");
                anlt_snapshot.an_hcd = an_hcd;

                // add snapshot to queue
                m_anlt_debug_snapshot_queue.push(anlt_snapshot);

                state = la_mac_port::state_e::INACTIVE;
                return LA_STATUS_SUCCESS;
            }
        }
    } else {
        // Stop Auto-Negotiation for Non-Spec (e.g. 400G) port after the AN is completed since the SerDes can't handle no HCD case
        avago_spico_int(m_aapl_handler, lane0_serdes_addr, AVAGO_INT_AN_CONFIG_ENABLE, 0x0);
    }

    an_link_training_configure(false);
    an_good_check = true;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::link_training_start(la_mac_port::state_e& state)
{
    uint lane0_serdes_addr = m_anlt_lane[0] + 1;

    // Non-Spec AN shouldn't assert link status as it's already been stopped
    if (m_an_spec_cap != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY) {
        uint an_hcd = avago_serdes_read_an_status(m_aapl_handler, lane0_serdes_addr, AVAGO_SERDES_AN_READ_HCD);
        int status = avago_serdes_an_assert_link_status(m_aapl_handler, lane0_serdes_addr, an_hcd);
        if (status == -1) {
            log_info(SERDES,
                     "AN assert failed an_hcd=0x%x slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d",
                     an_hcd,
                     m_slice_id,
                     m_ifg_id,
                     m_serdes_base_id,
                     m_anlt_lane[0]);
            state = la_mac_port::state_e::INACTIVE;
            return LA_STATUS_SUCCESS;
        }
    }

    Avago_serdes_pmd_config_t* pmd_config = avago_serdes_pmd_config_construct(m_aapl_handler);
    pmd_config->train_mode = AVAGO_PMD_TRAIN;
    switch (m_speed) {
    case la_mac_port::port_speed_e::E_10G:
    case la_mac_port::port_speed_e::E_25G:
        pmd_config->clause = AVAGO_PMD_CL72;
        break;
    case la_mac_port::port_speed_e::E_40G:
        pmd_config->clause = AVAGO_PMD_CL92;
        break;
    case la_mac_port::port_speed_e::E_50G:
    case la_mac_port::port_speed_e::E_200G:
    case la_mac_port::port_speed_e::E_400G:
        pmd_config->clause = AVAGO_PMD_CL136;
        break;
    case la_mac_port::port_speed_e::E_100G:
        if (m_serdes_count == 2) {
            pmd_config->clause = AVAGO_PMD_CL136;
        } else {
            pmd_config->clause = AVAGO_PMD_CL92;
        }
        break;
    default:
        break;
    }

    // Skip apply pre_ICAL for 40G serdes.
    bool skip_apply_ical = (m_speed == la_mac_port::port_speed_e::E_40G) && (m_serdes_count == 4);
    // Apply the ICAL values for link training if device property is set.  DEFAULT: TRUE
    bool apply_ical = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT].bool_val;
    for (uint lane = 0; lane < m_serdes_count; lane++) {
        uint serdes_addr = m_anlt_lane[lane] + 1;
        // Link training reset
        uint res = avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_INT_PMD_CONTROL, 0x0);
        if (res == 0) {
            log_err(SERDES,
                    "PMD link training reset failed: %d/%d/%d/%d -> %d",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    m_anlt_lane[0],
                    res);
        }

        if (apply_ical && !skip_apply_ical) {
            la_status stat = apply_serdes_parameters(lane, la_mac_port::serdes_param_stage_e::PRE_ICAL);
            return_on_error(stat);
        }

        // Set Link training tuning effort to 0x10 (Fast)
        avago_serdes_hal_set(
            m_aapl_handler, serdes_addr, AVAGO_HAL_GLOBAL_TUNE_PARAMS, AVAGO_HAL_MEMBER_TUNE_EFFORT, AVAGO_HAL_TUNE_EFFORT_FAST);

        pmd_config->sbus_addr = serdes_addr;
        pmd_config->lane = lane % 4;

        if (m_serdes_speed == la_mac_port::port_speed_e::E_10G) {
            log_debug(SERDES,
                      "%s: Serdes Speed is %s. Disabling AAPL Link Training timeout timer.",
                      __func__,
                      silicon_one::to_string(m_serdes_speed).c_str());
            pmd_config->disable_timeout = true;
        } else {
            pmd_config->disable_timeout = false;
        }

        avago_serdes_pmd_train(m_aapl_handler, pmd_config);
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, TRUE, TRUE, TRUE); // enable serdes for next operations
    }

    avago_serdes_pmd_config_destruct(m_aapl_handler, pmd_config);

    m_link_training_start = chrono::steady_clock::now();

    state = la_mac_port::state_e::LINK_TRAINING;

    return LA_STATUS_SUCCESS;
}

void
avago_serdes_handler::print_pmd_status_message(const char* message, long duration)
{
    logger& instance = logger::instance();
    if (instance.is_logging(
            silicon_one::get_device_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::DEBUG)) {
        std::stringstream pmd_log_message;
        pmd_log_message << "[ ";
        // Check PMD status
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            size_t serdes_addr = serdes + 1;
            // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
            int pmd_stat = avago_serdes_pmd_status(m_aapl_handler, serdes_addr);
            pmd_log_message << "0x" << std::hex << pmd_stat << ' ';
        }
        pmd_log_message << "]";

        log_debug(SERDES,
                  "%s on SerDes %d/%d/%d: PMD status after %zd ms: %s",
                  message,
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  duration,
                  pmd_log_message.str().c_str());
    }
}

la_status
avago_serdes_handler::link_training_handler(la_mac_port::state_e& state)
{
    uint serdes_cnt = 0;
    for (uint serdes = 0; serdes < m_serdes_count; serdes++) {
        uint serdes_addr = serdes + m_serdes_base_id + 1;
        int status = avago_serdes_pmd_status(m_aapl_handler, serdes_addr);
        log_debug(SERDES,
                  "PMD status %d slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d",
                  status,
                  m_slice_id,
                  m_ifg_id,
                  serdes_addr - 1,
                  m_anlt_lane[0]);
        if (status == 0) { // link training failed
            anlt_debug_snapshot anlt_snapshot{};
            uint o_core_status = avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_INT_READ | AVSD_LSB_CORE_STATUS, 0x0);
            uint o_msb_core_status = avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_INT_READ | AVAGO_MSB_CORE_STATUS, 0x0);
            // Read the LT time
            float link_training_tune_time
                = avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_INT_READ_SET_RX_EQ, AVAGO_ICAL_TIMER) * 1.6;

            // populate AN/LT snapshot
            add_timestamp(anlt_snapshot.timestamp, sizeof(anlt_snapshot.timestamp));
            anlt_snapshot.error_type = anlt_err_type_e::LT_FAILED;
            sprintf(anlt_snapshot.cause, "Link training failed");
            anlt_snapshot.o_core = o_core_status;
            anlt_snapshot.msb_core = o_msb_core_status;
            for (uint serdes = 0; serdes < m_serdes_count; serdes++) {
                uint serdes_addr = serdes + m_serdes_base_id + 1;
                float link_training_tune_time
                    = avago_spico_int(m_aapl_handler, serdes_addr, AVAGO_INT_READ_SET_RX_EQ, AVAGO_ICAL_TIMER) * 1.6;
                anlt_snapshot.link_training_tune_time.push_back(link_training_tune_time);
            }

            // add snapshot to queue
            m_anlt_debug_snapshot_queue.push(anlt_snapshot);

            log_debug(SERDES,
                      "PMD status failed slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d o_core_status=0x%04x_%04x "
                      "Link Training Tune Time (ms)= %f",
                      m_slice_id,
                      m_ifg_id,
                      serdes_addr - 1,
                      m_anlt_lane[0],
                      o_msb_core_status,
                      o_core_status,
                      link_training_tune_time);

            print_anlt_status("LT Failed", serdes_addr - 1, o_msb_core_status, o_core_status, link_training_tune_time);
            save_serdes_debug_message("Link training failed");
            state = la_mac_port::state_e::INACTIVE;
            return LA_STATUS_SUCCESS;
        }

        if (status == 1) { // link training succeeded
            serdes_cnt++;
        }
    }

    auto link_training_span = chrono::steady_clock::now() - m_link_training_start;
    if (link_training_span > m_link_training_timeout) {
        long link_training_duration = chrono::duration_cast<chrono::duration<long, milli> >(link_training_span).count();
        print_pmd_status_message("PMD timeout", link_training_duration);
        state = la_mac_port::state_e::INACTIVE;
        return LA_STATUS_SUCCESS;
    }

    // one or more SerDes link training still in progress
    if (serdes_cnt != m_serdes_count) {
        return LA_STATUS_SUCCESS;
    }

    state = la_mac_port::state_e::AN_COMPLETE;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::is_an_completed(bool& out_completed)
{
    out_completed = false;
    // Non-Spec AN shouldn't check AN Complete status, as it's already been stopped
    if (m_an_spec_cap != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY) {
        uint lane0_serdes_addr = m_anlt_lane[0] + 1;
        uint status = avago_serdes_read_an_status(m_aapl_handler, lane0_serdes_addr, AVAGO_SERDES_AN_COMPLETE);
        if (status == 0) {
            return LA_STATUS_SUCCESS;
        }

        if (status != 1) {
            log_err(SERDES,
                    "AN complete failed slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    m_anlt_lane[0]);
            return LA_STATUS_EUNKNOWN;
        }

        log_debug(SERDES,
                  "AN complete DONE slice/ifg/serdes/lane0_serdes=%d/%d/%d/%d",
                  m_slice_id,
                  m_ifg_id,
                  m_serdes_base_id,
                  m_anlt_lane[0]);
    }

    out_completed = true;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::restore_state(bool enabled)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = enabled;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = enabled;
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::recenter_serdes_tx_fifo()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
avago_serdes_handler::init(bool init_tx, bool init_rx)
{
    // construct the config struct
    Avago_serdes_init_config_t* serdes_config = avago_serdes_init_config_construct(m_aapl_handler);

    serdes_speed_to_divider_t::const_iterator config = s_serdes_speed_to_divider.find(m_serdes_speed_gbps);
    if (config == s_serdes_speed_to_divider.end()) {
        // Not found
        log_err(SERDES, "Failed to find speed config for: %zd", m_serdes_speed_gbps);
        return LA_STATUS_EINVAL;
    }

    // config
    uint default_divider = config->second;
    bool pam4_enable = s_serdes_config.at(m_serdes_speed).pam4_enable;

    // NA values
    serdes_config->burst_mode = false;
    serdes_config->rate_sel = 1;

    serdes_config->sbus_reset = true;
    serdes_config->spico_reset = true;
    serdes_config->init_tx = init_tx;
    serdes_config->init_rx = init_rx;
    serdes_config->init_mode
        = (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) ? AVAGO_CORE_DATA_ILB : AVAGO_CORE_DATA_ELB;
    serdes_config->skip_crc = true;
    serdes_config->rx_divider = serdes_config->tx_divider = default_divider;
    serdes_config->rx_encoding = serdes_config->tx_encoding = pam4_enable ? AVAGO_SERDES_PAM4 : AVAGO_SERDES_NRZ;
    serdes_config->rx_datapath.gray_enable = serdes_config->tx_datapath.gray_enable = pam4_enable;
    serdes_config->rx_datapath.precode_enable = serdes_config->tx_datapath.precode_enable = 0;
    serdes_config->rx_datapath.swizzle_enable = serdes_config->tx_datapath.swizzle_enable = 0;
    serdes_config->rx_datapath.mask = serdes_config->tx_datapath.mask = 0xF;
    serdes_config->tx_output_en = false;
    serdes_config->rx_width = serdes_config->tx_width = s_serdes_config.at(m_serdes_speed).data_width;
    serdes_config->tx_phase_cal = false;
    serdes_config->refclk_sync_master = true;
    serdes_config->signal_ok_en = false;
    serdes_config->signal_ok_threshold = 0; // disable EI (Electrical Idle) detection
    serdes_config->fail_code = 0;

    struct serdes_config_t {
        uint divider;
        int datapath_rx_precode;
        int datapath_tx_precode;
        int datapath_rx_swizzle;
        int datapath_tx_swizzle;
        int rx_clk_sel;
        int tx_clk_sel;
    };

    bool serdes_tx_slip_enable = false;
    serdes_tx_slip_enable = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_TX_SLIP].bool_val;

    // Build SerDes maps - SerDes ID and specific SerDes configuration.
    std::map<size_t, serdes_config_t> serdes_tx_map;
    std::map<size_t, serdes_config_t> serdes_rx_map;

    size_t refclk = get_ifg_reflck();
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        serdes_config_t serdes_config_tmp;
        serdes_config_tmp.divider = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::DIVIDER, default_divider);
        serdes_config_tmp.datapath_rx_precode
            = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE, 0 /* default */);
        serdes_config_tmp.datapath_tx_precode
            = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE, 0 /* default */);
        serdes_config_tmp.datapath_rx_swizzle
            = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE, 0 /* default */);
        serdes_config_tmp.datapath_tx_swizzle
            = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE, 0 /* default */);
        serdes_config_tmp.rx_clk_sel
            = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::RX_CLK_REFSEL, 0 /* default */);
        serdes_config_tmp.tx_clk_sel = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::TX_CLK_REFSEL, refclk);
        serdes_tx_map[tx_serdes] = serdes_config_tmp;
        serdes_rx_map[rx_serdes] = serdes_config_tmp;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = true;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = true;
    }

    if (init_tx) {
        // Program Tx Slip value for all serdes of the port
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            size_t tx_serdes = m_serdes_base_id + serdes;
            la_uint_t tx_slip = 0;

            if (m_serdes_speed != la_mac_port::port_speed_e::E_10G && serdes_tx_slip_enable) {
                // loopkup tx slip value for serdes
                tx_slip = tx_slip_config[m_slice_id * 2 + m_ifg_id][tx_serdes];
                avago_serdes_slip_tx_phase(m_aapl_handler, tx_serdes + 1, tx_slip, true);
                log_xdebug(SERDES,
                           "%s slice/ifg/serdes %d/%d/%d: setting tx slip %d.",
                           __func__,
                           m_slice_id,
                           m_ifg_id,
                           (la_uint_t)tx_serdes,
                           tx_slip);
            } else {
                // clear tx slip
                avago_serdes_slip_tx_phase(m_aapl_handler, tx_serdes + 1, 0, false);
            }
        }

        if (init_tx) {
            // Avago specifies disabling low power mode when configuring & tuning SerDes.
            // Disable low power mode before reconfiguring and activating SerDes.
            la_status stat = enable_low_power(false);
            return_on_error(stat);
        }

        // Start init
        // Currently the initialization is sequential but probably can be changed to parallel using avago_parallel_serdes_init.
        for (auto tx_serdes_ent : serdes_tx_map) {
            // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
            size_t tx_serdes = tx_serdes_ent.first;
            size_t tx_addr = tx_serdes + 1;

            // Force clear any previous AN config, Force TX to stop.
            avago_serdes_mem_wr(m_aapl_handler, tx_addr, AVAGO_DMEM, AVAGO_SERDES_PMD_CONTROL, 0);

            // Disable AN State Machine
            avago_spico_int(m_aapl_handler, tx_addr, AVAGO_AUTO_NEGOTIATION, 0);

            if (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) {
                // In SerDes loopback, no polarity inversion
                serdes_config->rx_datapath.polarity_invert = false;
                serdes_config->tx_datapath.polarity_invert = false;
            } else {
                // Different value per SerDes
                serdes_config->rx_datapath.polarity_invert
                    = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_polarity_inversion;
                serdes_config->tx_datapath.polarity_invert
                    = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].tx_polarity_inversion;
            }

            serdes_config->tx_divider = tx_serdes_ent.second.divider;
            serdes_config->tx_datapath.precode_enable = tx_serdes_ent.second.datapath_tx_precode;
            serdes_config->tx_datapath.swizzle_enable = tx_serdes_ent.second.datapath_tx_swizzle;
            serdes_config->tx_refclk1 = tx_serdes_ent.second.tx_clk_sel ? true : false;

            int res = avago_serdes_tx_init(m_aapl_handler, tx_addr, serdes_config);
            if (res != 0) {
                log_err(SERDES,
                        "Failed serdes_tx_init of Slice/IFG/SerDes %d/%d/%zd (addr %zd) -> %d, %d",
                        m_slice_id,
                        m_ifg_id,
                        tx_serdes,
                        tx_addr,
                        res,
                        serdes_config->fail_code);
            }
        }
    }

    if (init_rx) {
        for (auto rx_serdes_ent : serdes_rx_map) {
            // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
            size_t rx_serdes = rx_serdes_ent.first;
            size_t rx_addr = rx_serdes + 1;
            size_t serdes = rx_serdes % m_serdes_count;

            bool pam4_en = s_serdes_config.at(m_serdes_speed).pam4_enable;
            bool enable_fast_tune;
            if (pam4_en == false) { // NRZ
                enable_fast_tune = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_NRZ_FAST_TUNE].bool_val;
            } else {
                if (is_network_slice(m_serdes_slice_mode)) { // NETWORK PAM4
                    enable_fast_tune
                        = m_device->m_device_properties[(int)la_device_property_e::ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE].bool_val;
                } else { // FABRIC PAM4
                    enable_fast_tune
                        = m_device->m_device_properties[(int)la_device_property_e::ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE].bool_val;
                }
            }

            enable_fast_tune = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::RX_FAST_TUNE, enable_fast_tune);

            if (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) {
                // In SerDes loopback, no polarity inversion
                serdes_config->rx_datapath.polarity_invert = false;
                serdes_config->tx_datapath.polarity_invert = false;
            } else {
                // Different value per SerDes
                serdes_config->rx_datapath.polarity_invert
                    = m_device->m_serdes_info[m_slice_id][m_ifg_id][rx_serdes].rx_polarity_inversion;
                serdes_config->tx_datapath.polarity_invert
                    = m_device->m_serdes_info[m_slice_id][m_ifg_id][rx_serdes].tx_polarity_inversion;
            }

            serdes_config->rx_divider = rx_serdes_ent.second.divider;
            serdes_config->rx_datapath.precode_enable = rx_serdes_ent.second.datapath_rx_precode;
            serdes_config->rx_datapath.swizzle_enable = rx_serdes_ent.second.datapath_rx_swizzle;
            serdes_config->rx_refclk1 = rx_serdes_ent.second.rx_clk_sel ? true : false;

            int res, retry = MAX_RX_INIT_RETRIES;
            for (int i = 0; i < retry; i++) {
                res = avago_serdes_rx_init(m_aapl_handler, rx_addr, serdes_config);
                if (res == 0) {
                    break;
                }
            }
            if (res != 0) {
                log_err(SERDES,
                        "Failed serdes_rx_init of Slice/IFG/SerDes %d/%d/%zd (addr %zd) -> %d, %d",
                        m_slice_id,
                        m_ifg_id,
                        rx_serdes,
                        rx_addr,
                        res,
                        serdes_config->fail_code);
            }

            res = avago_serdes_hal_set(m_aapl_handler,
                                       rx_addr,
                                       AVAGO_HAL_GLOBAL_TUNE_PARAMS,
                                       AVAGO_HAL_MEMBER_TUNE_EFFORT,
                                       (enable_fast_tune || m_is_an_enabled) ? AVAGO_HAL_TUNE_EFFORT_FAST
                                                                             : AVAGO_HAL_TUNE_EFFORT_FULL);
        }
    }

    // destruct config struct
    avago_serdes_init_config_destruct(m_aapl_handler, serdes_config);

    if (init_rx) {
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            size_t tx_serdes = m_serdes_base_id + serdes;
            size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
            size_t rx_addr = rx_serdes + 1;

            // Reset SerDes Rx FFE settings to default
            avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_RX_EQ_CONTROL, 0xFFFF);

            la_status stat = apply_serdes_parameters(serdes, la_mac_port::serdes_param_stage_e::ACTIVATE);
            return_on_error(stat);
        }
    }

    if (init_tx) {
        if (m_loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES) {
            for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
                // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
                size_t tx_serdes = m_serdes_base_id + serdes;
                size_t serdes_addr = tx_serdes + 1;

                int res = avago_serdes_set_tx_pll_clk_src(m_aapl_handler, serdes_addr, AVAGO_SERDES_TX_PLL_RX_DIVX);

                if (res != 0) {
                    log_err(SERDES,
                            "Failed avago_serdes_set_tx_pll_clk_src on Slice/IFG/SerDes %d/%d/%zd (addr %zd) -> %d",
                            m_slice_id,
                            m_ifg_id,
                            serdes,
                            serdes_addr,
                            res);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::init()
{
    la_status stat;
    stat = init(true, true);
    return_on_error(stat);

    // Move here from the constructor so the new value can be updated
    m_link_training_timeout
        = chrono::seconds(m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_LINK_TRAINING_TIMEOUT].int_val);

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::enable_tx(bool tx_enabled)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = tx_serdes + 1;

        bool rx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].rx_enabled;
        int res = avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, rx_enabled, tx_enabled);
        la_logger_level_e level = res ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG;
        log_message(la_logger_component_e::SERDES,
                    level,
                    "%s: %s, serdes_set_tx_rx_enable of Slice/IFG/SerDes %d/%d/%zd (addr %zd) Tx %d, Rx %d-> %d",
                    __func__,
                    res ? "ERROR" : "OK",
                    m_slice_id,
                    m_ifg_id,
                    tx_serdes,
                    serdes_addr,
                    tx_enabled,
                    rx_enabled,
                    res);
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::enable_rx(bool rx_enabled)
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = rx_serdes + 1;

        bool tx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].tx_enabled;
        int res = avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, rx_enabled, tx_enabled);
        la_logger_level_e level = res ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG;
        log_message(la_logger_component_e::SERDES,
                    level,
                    "%s: %s, serdes_set_tx_rx_enable of Slice/IFG/SerDes %d/%d/%zd (addr %zd) Tx %d, Rx %d-> %d",
                    __func__,
                    res ? "ERROR" : "OK",
                    m_slice_id,
                    m_ifg_id,
                    tx_serdes,
                    serdes_addr,
                    tx_enabled,
                    rx_enabled,
                    res);
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::apply_serdes_parameters_ctle(la_mac_port::serdes_param_e param,
                                                   serdes_param_setting val,
                                                   Avago_serdes_ctle_t& ctle_val,
                                                   uint64_t& ctle_fixed)
{
    int32_t value = val.value;
    // Fixed here is non-adaptive and this includes STATIC & FIXED
    bool fixed = (val.mode != la_mac_port::serdes_param_mode_e::ADAPTIVE);

    switch (param) {
    case la_mac_port::serdes_param_e::RX_CTLE_DC:
        ctle_val.dc = value;
        bit_utils::set_bit(&ctle_fixed, 0, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_LF:
        bit_utils::set_bit(&ctle_fixed, 1, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_LF_MAX:
    case la_mac_port::serdes_param_e::RX_CTLE_LF_MIN:
    case la_mac_port::serdes_param_e::RX_CTLE_HF_MAX:
    case la_mac_port::serdes_param_e::RX_CTLE_HF_MIN:
        // No op
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_HF:
        bit_utils::set_bit(&ctle_fixed, 2, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE1:
        bit_utils::set_bit(&ctle_fixed, 4, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE2:
        bit_utils::set_bit(&ctle_fixed, 5, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_SHORT_CHANNEL_EN:
        bit_utils::set_bit(&ctle_fixed, 6, fixed);
        break;
    default:
        // We should never get here.
        return LA_STATUS_EUNKNOWN;
    }

    if (val.mode == la_mac_port::serdes_param_mode_e::STATIC) {
        // Skip setting the value
        return LA_STATUS_SUCCESS;
    }

    switch (param) {
    case la_mac_port::serdes_param_e::RX_CTLE_LF:
        ctle_val.lf = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_LF_MAX:
        ctle_val.lf_max = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_LF_MIN:
        ctle_val.lf_min = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_HF:
        ctle_val.hf = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_HF_MAX:
        ctle_val.hf_max = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_HF_MIN:
        ctle_val.hf_min = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_BW:
        ctle_val.bw = value;
        bit_utils::set_bit(&ctle_fixed, 3, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE1:
        ctle_val.gainshape1 = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE2:
        ctle_val.gainshape2 = value;
        break;
    case la_mac_port::serdes_param_e::RX_CTLE_SHORT_CHANNEL_EN:
        ctle_val.short_channel_en = value;
        break;
    default:
        // We should never get here.
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::apply_serdes_parameters_rxffe(la_mac_port::serdes_param_e param,
                                                    serdes_param_setting val,
                                                    Avago_serdes_rxffe_t& rxffe_val,
                                                    uint64_t& rxffe_fixed)
{
    int value = val.value;
    // Fixed here is non-adaptive and this includes STATIC & FIXED
    bool fixed = (val.mode != la_mac_port::serdes_param_mode_e::ADAPTIVE);

    switch (param) {
    case la_mac_port::serdes_param_e::RX_FFE_PRE2:
        bit_utils::set_bit(&rxffe_fixed, 0, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE2_MAX:
    case la_mac_port::serdes_param_e::RX_FFE_PRE2_MIN:
    case la_mac_port::serdes_param_e::RX_FFE_PRE1_MAX:
    case la_mac_port::serdes_param_e::RX_FFE_PRE1_MIN:
        // No op
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE1:
        bit_utils::set_bit(&rxffe_fixed, 1, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_FFE_POST:
        bit_utils::set_bit(&rxffe_fixed, 2, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_FFE_BFLF:
        bit_utils::set_bit(&rxffe_fixed, 3, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_FFE_BFHF:
        bit_utils::set_bit(&rxffe_fixed, 4, fixed);
        break;
    case la_mac_port::serdes_param_e::RX_FFE_SHORT_CHANNEL_EN:
        bit_utils::set_bit(&rxffe_fixed, 5, fixed);
        break;
    default:
        // We should never get here.
        return LA_STATUS_EUNKNOWN;
    }

    if (val.mode == la_mac_port::serdes_param_mode_e::STATIC) {
        // Skip setting the value
        return LA_STATUS_SUCCESS;
    }

    switch (param) {
    case la_mac_port::serdes_param_e::RX_FFE_PRE2:
        rxffe_val.pre2 = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE2_MAX:
        rxffe_val.pre2_max = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE2_MIN:
        rxffe_val.pre2_min = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE1:
        rxffe_val.pre1 = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE1_MAX:
        rxffe_val.pre1_max = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_PRE1_MIN:
        rxffe_val.pre1_min = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_POST:
        rxffe_val.post1 = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_BFLF:
        rxffe_val.bflf = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_BFHF:
        rxffe_val.bfhf = value;
        break;
    case la_mac_port::serdes_param_e::RX_FFE_SHORT_CHANNEL_EN:
        rxffe_val.short_channel_en = value;
        break;
    default:
        // We should never get here.
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::apply_serdes_parameters_tx_eq(la_mac_port::serdes_param_e param,
                                                    serdes_param_setting val,
                                                    Avago_serdes_tx_eq_t& tx_eq)
{
    int value = val.value;

    switch (param) {
    case la_mac_port::serdes_param_e::TX_ATTN:
        tx_eq.atten = value;
        break;
    case la_mac_port::serdes_param_e::TX_POST:
        tx_eq.post = value;
        break;
    case la_mac_port::serdes_param_e::TX_PRE1:
        tx_eq.pre = value;
        break;
    case la_mac_port::serdes_param_e::TX_PRE2:
        tx_eq.pre2 = value;
        break;
    case la_mac_port::serdes_param_e::TX_PRE3:
        tx_eq.pre3 = value;
        break;
    default:
        // We should never get here.
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::apply_serdes_parameters_gradient_inputs(la_mac_port::serdes_param_e param,
                                                              serdes_param_setting val,
                                                              uint32_t& apply_gradient_inputs_mask,
                                                              Avago_serdes_gradient_inputs_t& gradient_inputs)
{
    int value = val.value;

    switch (param) {
    case la_mac_port::serdes_param_e::HYSTERESIS_POST1_NEGATIVE:
        gradient_inputs.pcal_hysteresis_post1_neg = value;
        apply_gradient_inputs_mask |= AVAGO_HYSTERESIS_POST1_NEGATIVE_MASK;
        break;
    case la_mac_port::serdes_param_e::HYSTERESIS_POST1_POSETIVE:
        gradient_inputs.pcal_hysteresis_post1_pos = value;
        apply_gradient_inputs_mask |= AVAGO_HYSTERESIS_POST1_POSETIVE_MASK;
        break;
    default:
        // We neve should get here.
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::apply_serdes_parameters(size_t serdes_idx, la_mac_port::serdes_param_stage_e stage)
{
    bool reconnect_in_progress = m_device->m_reconnect_handler->is_reconnect_in_progress();

    // Declare Values for Settings
    Avago_serdes_rxffe_t rxffe_val{};
    Avago_serdes_ctle_t ctle_val{};
    Avago_serdes_global_tune_params_t hal_global_params_val{};
    Avago_serdes_tx_eq_t tx_eq{};
    Avago_serdes_gradient_inputs_t gradient_inputs{};

    // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
    size_t tx_serdes = m_serdes_base_id + serdes_idx;
    size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source;
    size_t tx_addr = tx_serdes + 1;
    size_t rx_addr = rx_serdes + 1;

    if (reconnect_in_progress) {
        m_device->m_ll_device->set_write_to_device(true);
    }

    // read and modify the structures on the first SerDes
    avago_serdes_rxffe_read(m_aapl_handler, rx_addr, &rxffe_val);
    avago_serdes_ctle_read(m_aapl_handler, rx_addr, &ctle_val);
    avago_serdes_global_tune_params_read(m_aapl_handler, rx_addr, &hal_global_params_val);
    avago_serdes_gradient_inputs_read(m_aapl_handler, rx_addr, &gradient_inputs);
    avago_serdes_get_tx_eq(m_aapl_handler, tx_addr, &tx_eq);

    // Read Register for Read Modified Write
    const uint64_t rxpll_rd = avago_serdes_hal_get(m_aapl_handler, rx_addr, AVAGO_HAL_USER_PLL_GAINS, AVAGO_HAL_MEMBER_RX_PLL);
    const uint64_t rxpll2_rd = avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_READ | AVAGO_INT_RX_PLL2, 0x0);
    const uint64_t txpll_rd = avago_serdes_hal_get(m_aapl_handler, tx_addr, AVAGO_HAL_USER_PLL_GAINS, AVAGO_HAL_MEMBER_TX_PLL);

    if (reconnect_in_progress) {
        m_device->m_ll_device->set_write_to_device(false);
    }

    uint64_t rxpll_wr = rxpll_rd;
    uint64_t rxpll2_wr = rxpll2_rd;
    uint64_t txpll_wr = txpll_rd;

    uint64_t ctle_fixed = hal_global_params_val.ctle_fixed;
    uint64_t rxffe_fixed = hal_global_params_val.rxffe_fixed;

    bool apply_rxpll = false;
    bool apply_txpll = false;
    bool apply_rxffe = false;
    bool apply_ctle = false;
    bool apply_pcal_effort = false;
    bool apply_tx_eq = false;
    uint32_t apply_gradient_inputs_mask = 0;

    for (auto kv : m_serdes_param_vec[serdes_idx][(size_t)stage]) {
        int value = kv.second.value;

        switch (kv.first) {
        case la_mac_port::serdes_param_e::HYSTERESIS_POST1_NEGATIVE:
        case la_mac_port::serdes_param_e::HYSTERESIS_POST1_POSETIVE:
            apply_serdes_parameters_gradient_inputs(kv.first, kv.second, apply_gradient_inputs_mask, gradient_inputs);
            break;

        case la_mac_port::serdes_param_e::RX_CTLE_DC:
        case la_mac_port::serdes_param_e::RX_CTLE_LF:
        case la_mac_port::serdes_param_e::RX_CTLE_LF_MAX:
        case la_mac_port::serdes_param_e::RX_CTLE_LF_MIN:
        case la_mac_port::serdes_param_e::RX_CTLE_HF:
        case la_mac_port::serdes_param_e::RX_CTLE_HF_MAX:
        case la_mac_port::serdes_param_e::RX_CTLE_HF_MIN:
        case la_mac_port::serdes_param_e::RX_CTLE_BW:
        case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE1:
        case la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE2:
        case la_mac_port::serdes_param_e::RX_CTLE_SHORT_CHANNEL_EN:
            apply_serdes_parameters_ctle(kv.first, kv.second, ctle_val, ctle_fixed);
            apply_ctle = true;
            break;

        case la_mac_port::serdes_param_e::RX_FFE_PRE2:
        case la_mac_port::serdes_param_e::RX_FFE_PRE2_MAX:
        case la_mac_port::serdes_param_e::RX_FFE_PRE2_MIN:
        case la_mac_port::serdes_param_e::RX_FFE_PRE1:
        case la_mac_port::serdes_param_e::RX_FFE_PRE1_MAX:
        case la_mac_port::serdes_param_e::RX_FFE_PRE1_MIN:
        case la_mac_port::serdes_param_e::RX_FFE_POST:
        case la_mac_port::serdes_param_e::RX_FFE_BFLF:
        case la_mac_port::serdes_param_e::RX_FFE_BFHF:
        case la_mac_port::serdes_param_e::RX_FFE_SHORT_CHANNEL_EN:
            apply_serdes_parameters_rxffe(kv.first, kv.second, rxffe_val, rxffe_fixed);
            apply_rxffe = true;
            break;

        case la_mac_port::serdes_param_e::RX_PLL_BB:
            rxpll_wr = bit_utils::set_bits(rxpll_wr, 7, 0, value);
            apply_rxpll = true;
            break;
        case la_mac_port::serdes_param_e::RX_PCAL_EFFORT:
            hal_global_params_val.pCal_loops = (short)value;
            apply_pcal_effort = true;
            break;
        case la_mac_port::serdes_param_e::RX_PLL_IFLT:
            rxpll2_wr = bit_utils::set_bits(rxpll2_wr, 14, 7, value);
            apply_rxpll = true;
            break;
        case la_mac_port::serdes_param_e::RX_PLL_INT:
            rxpll_wr = bit_utils::set_bits(rxpll_wr, 15, 8, value);
            apply_rxpll = true;
            break;

        case la_mac_port::serdes_param_e::TX_PLL_BB:
            txpll_wr = bit_utils::set_bits(txpll_wr, 7, 0, value);
            apply_txpll = true;
            break;
        case la_mac_port::serdes_param_e::TX_PLL_IFLT:
            txpll_wr = bit_utils::set_bits(txpll_wr, 21, 13, value);
            apply_txpll = true;
            break;
        case la_mac_port::serdes_param_e::TX_PLL_INT:
            txpll_wr = bit_utils::set_bits(txpll_wr, 12, 8, value);
            apply_txpll = true;
            break;

        case la_mac_port::serdes_param_e::RX_TERM:
            avago_serdes_set_rx_term(m_aapl_handler, rx_addr, (Avago_serdes_rx_term_t)value);
            break;

        case la_mac_port::serdes_param_e::RX_NRZ_EYE_THRESHOLD:
            avago_serdes_hal_set(m_aapl_handler, rx_addr, AVAGO_HAL_GLOBAL_TUNE_PARAMS, AVAGO_HAL_MEMBER_NRZ_THRESHOLD, value);
            break;

        case la_mac_port::serdes_param_e::TX_ATTN:
        case la_mac_port::serdes_param_e::TX_POST:
        case la_mac_port::serdes_param_e::TX_PRE1:
        case la_mac_port::serdes_param_e::TX_PRE2:
        case la_mac_port::serdes_param_e::TX_PRE3:
            apply_serdes_parameters_tx_eq(kv.first, kv.second, tx_eq);
            apply_tx_eq = true;
            break;
        case la_mac_port::serdes_param_e::TX_ATTN_COLD_SIG_ENVELOPE:
            avago_serdes_hal_set(m_aapl_handler, tx_addr, AVAGO_HAL_TX_ATTN_SIG_ENVELOPE, AVAGO_HAL_MEMBER_TX_ATTN_COLD, value);
            break;
        case la_mac_port::serdes_param_e::TX_ATTN_HOT_SIG_ENVELOPE:
            avago_serdes_hal_set(m_aapl_handler, tx_addr, AVAGO_HAL_TX_ATTN_SIG_ENVELOPE, AVAGO_HAL_MEMBER_TX_ATTN_HOT, value);
            break;
        case la_mac_port::serdes_param_e::DIVIDER:
        case la_mac_port::serdes_param_e::DATAPATH_RX_PRECODE:
        case la_mac_port::serdes_param_e::DATAPATH_TX_PRECODE:
        case la_mac_port::serdes_param_e::DATAPATH_RX_SWIZZLE:
        case la_mac_port::serdes_param_e::DATAPATH_TX_SWIZZLE:
        case la_mac_port::serdes_param_e::RX_CLK_REFSEL:
        case la_mac_port::serdes_param_e::TX_CLK_REFSEL:
        case la_mac_port::serdes_param_e::RX_FAST_TUNE:
        // Skip, applied in serdes_init.
        case la_mac_port::serdes_param_e::ELECTRICAL_IDLE_THRESHOLD:
            // Skip, applied in peer detect
            break;

        default:
            log_debug(SERDES,
                      "Set SerDes parameter on Slice/IFG/SerDes %d/%d/%d for %s to %d not supported",
                      m_slice_id,
                      m_ifg_id,
                      m_serdes_base_id,
                      to_string(kv.first).c_str(),
                      (int)kv.second.value);
        }
    }

    hal_global_params_val.ctle_fixed = (short)ctle_fixed;
    hal_global_params_val.rxffe_fixed = (short)rxffe_fixed;

    m_serdes_rxpll_value_vec[serdes_idx] = rxpll_wr;
    m_serdes_rxpll2_value_vec[serdes_idx] = rxpll2_wr;

    if (reconnect_in_progress) {
        log_debug(SERDES, "%s: skip SerDes access during reconnect", __func__);
        return LA_STATUS_SUCCESS;
    }

    // Write params
    if (apply_rxffe) {
        avago_serdes_rxffe_write(m_aapl_handler, rx_addr, &rxffe_val);
    }
    if (apply_ctle) {
        avago_serdes_ctle_write(m_aapl_handler, rx_addr, &ctle_val);
    }
    if (apply_rxffe || apply_ctle || apply_pcal_effort) {
        avago_serdes_global_tune_params_write(m_aapl_handler, rx_addr, &hal_global_params_val);
    }
    if (apply_tx_eq) {
        avago_serdes_set_tx_eq(m_aapl_handler, tx_addr, &tx_eq);
    }
    if (apply_gradient_inputs_mask) {
        avago_serdes_gradient_inputs_apply(m_aapl_handler, rx_addr, apply_gradient_inputs_mask, &gradient_inputs);
    }
    if (apply_txpll) {
        avago_serdes_hal_set(m_aapl_handler, tx_addr, AVAGO_HAL_USER_PLL_GAINS, AVAGO_HAL_MEMBER_TX_PLL, txpll_wr);
        avago_spico_int(m_aapl_handler, tx_addr, AVAGO_INT_WRITE | AVSD_ESB16_TX_PLL_GAIN, txpll_wr);
    }

    if (apply_rxpll) {
        avago_serdes_hal_set(
            m_aapl_handler, rx_addr, AVAGO_HAL_USER_PLL_GAINS, AVAGO_HAL_MEMBER_RX_PLL, m_serdes_rxpll_value_vec[serdes_idx]);
        avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_WRITE | AVSD_ESB16_RX_PLL_GAIN, m_serdes_rxpll_value_vec[serdes_idx]);
        avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_WRITE | AVAGO_INT_RX_PLL2, m_serdes_rxpll2_value_vec[serdes_idx]);
    }

    return LA_STATUS_SUCCESS;
}

int
avago_serdes_handler::get_serdes_parameter_per_lane(size_t serdes_idx, la_mac_port::serdes_param_e param, int default_value)
{
    // Enable to override a divider, currently, same divider for all SerDes of the port and taken from SerDes 0.
    auto divider_param = m_serdes_param_vec[serdes_idx][(size_t)la_mac_port::serdes_param_stage_e::ACTIVATE].find(param);
    if (divider_param != m_serdes_param_vec[serdes_idx][(size_t)la_mac_port::serdes_param_stage_e::ACTIVATE].end()) {
        return divider_param->second.value;
    }

    return default_value;
}

la_status
avago_serdes_handler::validate_rxpll()
{
    if (m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        return LA_STATUS_SUCCESS;
    }

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;

        int rxpll_rd = avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_READ | AVSD_ESB16_RX_PLL_GAIN, 0x0);
        if (rxpll_rd != m_serdes_rxpll_value_vec[serdes]) {
            int hal_rxpll_rd = avago_serdes_hal_get(m_aapl_handler, rx_addr, AVAGO_HAL_USER_PLL_GAINS, AVAGO_HAL_MEMBER_RX_PLL);
            log_warning(SERDES,
                        "Correcting wrong Rx PLL setting of Slice/IFG/SerDes %d/%d/%zd - 0x%X -> 0x%X, HAL 0x%X",
                        m_slice_id,
                        m_ifg_id,
                        rx_serdes,
                        rxpll_rd,
                        m_serdes_rxpll_value_vec[serdes],
                        hal_rxpll_rd);
            avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_WRITE | AVSD_ESB16_RX_PLL_GAIN, m_serdes_rxpll_value_vec[serdes]);
        }

        int rxpll2_rd = avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_READ | AVAGO_INT_RX_PLL2, 0x0);
        if (rxpll2_rd != m_serdes_rxpll2_value_vec[serdes]) {
            log_warning(SERDES,
                        "Correcting wrong Rx PLL2 setting of Slice/IFG/SerDes %d/%d/%zd - 0x%X -> 0x%X",
                        m_slice_id,
                        m_ifg_id,
                        rx_serdes,
                        rxpll2_rd,
                        m_serdes_rxpll2_value_vec[serdes]);
            avago_spico_int(m_aapl_handler, rx_addr, AVAGO_INT_WRITE | AVAGO_INT_RX_PLL2, m_serdes_rxpll2_value_vec[serdes]);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::tune()
{
    la_status stat = enable_low_power(false);
    return_on_error(stat);

    // Note: The SerDes tune is tuning only the Rx SerDes.
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        la_status stat = apply_serdes_parameters(serdes, la_mac_port::serdes_param_stage_e::PRE_ICAL);
        return_on_error(stat);

        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;

        bool pam4_en = s_serdes_config.at(m_serdes_speed).pam4_enable;
        bool enable_fast_tune;
        if (pam4_en == false) { // NRZ
            enable_fast_tune = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_NRZ_FAST_TUNE].bool_val;
        } else {
            if (is_network_slice(m_serdes_slice_mode)) { // NETWORK PAM4
                enable_fast_tune
                    = m_device->m_device_properties[(int)la_device_property_e::ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE].bool_val;
            } else { // FABRIC PAM4
                enable_fast_tune
                    = m_device->m_device_properties[(int)la_device_property_e::ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE].bool_val;
            }
        }

        enable_fast_tune = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::RX_FAST_TUNE, enable_fast_tune);

        // Set the proper tune effort
        avago_serdes_hal_set(m_aapl_handler,
                             rx_addr,
                             AVAGO_HAL_GLOBAL_TUNE_PARAMS,
                             AVAGO_HAL_MEMBER_TUNE_EFFORT,
                             enable_fast_tune ? AVAGO_HAL_TUNE_EFFORT_FAST : AVAGO_HAL_TUNE_EFFORT_FULL);
    }

    // construct the tune struct
    Avago_serdes_dfe_tune_t serdes_tune;
    avago_serdes_tune_init(m_aapl_handler, &serdes_tune);

    // Configure tuning parameters
    switch (m_tuning_mode) {
    case la_mac_port::serdes_tuning_mode_e::ICAL_ONLY:
        serdes_tune.tune_mode = AVAGO_DFE_ICAL_ONLY;
        break;

    case la_mac_port::serdes_tuning_mode_e::ICAL:
        serdes_tune.tune_mode = AVAGO_DFE_ICAL;
        break;

    case la_mac_port::serdes_tuning_mode_e::PCAL:
        serdes_tune.tune_mode = AVAGO_DFE_PCAL;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    // Start tune
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        // The SerDes is the Rx SerDes.
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;
        bool res = avago_serdes_tune(m_aapl_handler, rx_addr, &serdes_tune);
        if (!res) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::get_tune_complete(bool& out_completed)
{
    // Note: The SerDes tune is tuning only the Rx SerDes.

    // Check tune
    out_completed = true;
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t rx_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source + 1;
        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        int tune_stat = avago_serdes_get_dfe_status(m_aapl_handler, rx_addr);
        if (tune_stat & AVAGO_SERDES_DFE_IS_RUNNING) {
            // Some DFE is running
            out_completed = false;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::periodic_tune_start()
{
    bool do_periodic_tune = m_continuous_tuning_enabled && (m_loopback_mode != la_mac_port::loopback_mode_e::SERDES);

    if (!do_periodic_tune) {
        return LA_STATUS_SUCCESS;
    }

    if (m_device->is_simulated_or_emulated_device()) {
        m_continuous_tuning_activated = true;
        return LA_STATUS_SUCCESS;
    }

    /* move the enable_low_power out of this function
     * take care of low_power mode at proper state - */

    la_status stat = validate_rxpll();
    return_on_error(stat);

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        stat = apply_serdes_parameters(serdes, la_mac_port::serdes_param_stage_e::PRE_PCAL);
        return_on_error(stat);
    }

    if (m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        m_continuous_tuning_activated = true;
        return LA_STATUS_SUCCESS;
    }

    Avago_serdes_dfe_tune_t serdes_tune;
    avago_serdes_tune_init(m_aapl_handler, &serdes_tune);
    serdes_tune.tune_mode = AVAGO_DFE_START_ADAPTIVE;

    // Start continuous tuning
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;

        // Activate continuous pCal.
        bool res = avago_serdes_tune(m_aapl_handler, rx_addr, &serdes_tune);
        if (!res) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    m_continuous_tuning_activated = true;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::periodic_tune_stop()
{
    if (!m_continuous_tuning_activated) {
        // Not in continuous tuning mode, no need to stop
        return LA_STATUS_SUCCESS;
    }

    /* move the enable_low_power out of this function
     * take care of low_power mode at proper state - */

    Avago_serdes_dfe_tune_t serdes_tune;
    avago_serdes_tune_init(m_aapl_handler, &serdes_tune);
    serdes_tune.tune_mode = AVAGO_DFE_STOP_ADAPTIVE;

    // Stop continuous tuning
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;

        // Stop continuous pCal.
        bool res = avago_serdes_tune(m_aapl_handler, rx_addr, &serdes_tune);
        if (!res) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    m_continuous_tuning_activated = false;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::is_periodic_tune_stopped(bool& out_stopped)
{
    out_stopped = true;

    // Check if continuous tuning stopped
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;

        int tune_stat = avago_serdes_get_dfe_status(m_aapl_handler, rx_addr);
        if (tune_stat & (AVAGO_SERDES_PCAL_IN_PROGRESS | AVAGO_SERDES_PCAL_SCHEDULED)) {
            out_stopped = false;
        }

        log_debug(SERDES,
                  "Tuning status after periodic stop of SerDes %d/%d/%zd (Slice/IFG/Tx SerDes/Rx SerDes) failed, status is 0x%X",
                  m_slice_id,
                  m_ifg_id,
                  rx_addr - 1,
                  tune_stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::get_continuous_tune_status(bool& out_status)
{
    out_status = m_continuous_tuning_activated;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::update_loopback_mode(la_mac_port::loopback_mode_e loopback_mode)
{
    m_loopback_mode = loopback_mode;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_loopback_mode(la_mac_port::loopback_mode_e loopback_mode)
{
    if (m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        log_debug(SERDES, "%s: skip SerDes access during reconnect", __func__);
        m_loopback_mode = loopback_mode;
        return LA_STATUS_SUCCESS;
    }

    bool serdes_loopback = loopback_mode == la_mac_port::loopback_mode_e::SERDES;
    Avago_serdes_tx_pll_clk_t tx_clk_src = (loopback_mode == la_mac_port::loopback_mode_e::REMOTE_PMA
                                            || loopback_mode == la_mac_port::loopback_mode_e::REMOTE_SERDES)
                                               ? AVAGO_SERDES_TX_PLL_RX_DIVX
                                               : AVAGO_SERDES_TX_PLL_REFCLK;

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = m_serdes_base_id + serdes + 1;

        int res = avago_serdes_set_rx_input_loopback(m_aapl_handler, serdes_addr, serdes_loopback);

        if (res != 0) {
            log_err(SERDES,
                    "Failed avago_serdes_set_rx_input_loopback of Slice/IFG/SerDes %d/%d/%zd (addr %zd) -> %d",
                    m_slice_id,
                    m_ifg_id,
                    serdes,
                    serdes_addr,
                    res);
        }
        res = avago_serdes_set_tx_pll_clk_src(m_aapl_handler, serdes_addr, tx_clk_src);

        if (res != 0) {
            log_err(SERDES,
                    "Failed avago_serdes_set_tx_pll_clk_src on Slice/IFG/SerDes %d/%d/%zd (addr %zd) -> %d",
                    m_slice_id,
                    m_ifg_id,
                    serdes,
                    serdes_addr,
                    res);
        }
    }

    m_loopback_mode = loopback_mode;
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::stop()
{
    // Build SerDes set - SerDes can be used by Tx, Rx or both
    std::set<size_t> serdes_rx_tx_set;

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][tx_serdes].tx_enabled = false;
        m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled = false;
        serdes_rx_tx_set.insert(tx_serdes);
        serdes_rx_tx_set.insert(rx_serdes);
    }

    for (auto serdes : serdes_rx_tx_set) {
        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = serdes + 1;

        bool tx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][serdes].tx_enabled;
        bool rx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][serdes].rx_enabled;
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, rx_enabled, tx_enabled);
    }

    m_bad_an_base_page_print = false;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::verify_firmware()
{
    // Build SerDes set - SerDes can be used by Tx, Rx or both
    std::set<size_t> serdes_set;

    // SerDes set the requires FW upload
    std::set<size_t> serdes_upload_set;

    stopwatch sw_check1;
    stopwatch sw_check2;
    stopwatch sw_upload;
    stopwatch sw_init;

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        serdes_set.insert(m_serdes_base_id + serdes);                                                          // Tx SerDes
        serdes_set.insert(m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source); // Rx SerDes
    }

    Avago_addr_t addr_struct_head;
    Avago_addr_t* addr_struct_cur = &addr_struct_head;
    addr_struct_cur->next = nullptr;
    int revision;
    int build_id;
    std::string filename;
    std::string filepath;
    m_device->get_int_property(la_device_property_e::SERDES_FW_REVISION, revision);
    m_device->get_int_property(la_device_property_e::SERDES_FW_BUILD, build_id);
    m_device->get_string_property(la_device_property_e::SERDES_FW_FILE_NAME, filename);
    filepath = find_resource_file(SERDES_FILE_ENVVAR.c_str(), filename.c_str());

    // Check FW on all relevant SerDes
    for (auto serdes : serdes_set) {
        sw_check1.start();
        bool res = serdes_firmware_check(m_aapl_handler, serdes + 1, revision, build_id);
        sw_check1.stop();
        if (!res) {
            // TODO: add to list and set
            serdes_upload_set.insert(serdes);

            addr_struct_cur->next = new Avago_addr_t();
            addr_struct_cur = addr_struct_cur->next;
            addr_struct_cur->next = nullptr;
            bool b_res = avago_addr_to_struct(serdes + 1, addr_struct_cur);
            if (!b_res) {
                return LA_STATUS_EUNKNOWN;
            }
        }
    }

    // Parallel FW upload
    if (addr_struct_head.next != nullptr) {
        sw_upload.start();
        int ret = avago_parallel_spico_upload_file(
            m_aapl_handler, addr_struct_head.next, la_device_impl::SERDES_PERFORM_SPICO_RAM_BIST, filepath.c_str());
        sw_upload.stop();
        if (ret < 0) {
            log_err(SERDES,
                    "Failed avago_parallel_spico_upload_file Slice/IFG/SerDes %d/%d/%d -> %d",
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    ret);
            return LA_STATUS_EUNKNOWN;
        }

        for (auto serdes : serdes_upload_set) {
            // Invalidate revision cache in AAPL structure
            aapl_set_ip_type(m_aapl_handler, serdes + 1);

            // TODO: work with the list used for FW upload, currently fail.
            Avago_addr_t addr_struct;
            bool b_res = avago_addr_to_struct(serdes + 1, &addr_struct);
            if (!b_res) {
                return LA_STATUS_EUNKNOWN;
            }

            bool skip_crc = true;
            sw_init.start();
            ret = avago_parallel_serdes_base_init(m_aapl_handler, &addr_struct, skip_crc);
            sw_init.stop();
            if (ret < 0) {
                log_err(SERDES,
                        "Failed avago_parallel_serdes_base_init Slice/IFG/SerDes %d/%d/%d -> %d",
                        m_slice_id,
                        m_ifg_id,
                        m_serdes_base_id,
                        ret);
                return LA_STATUS_EUNKNOWN;
            }
        }

        for (addr_struct_cur = addr_struct_head.next; addr_struct_cur != nullptr;) {
            Avago_addr_t* tmp = addr_struct_cur;
            addr_struct_cur = addr_struct_cur->next;
            delete (tmp);
        }

        // Check FW again
        for (auto serdes : serdes_upload_set) {
            sw_check2.start();
            bool res = serdes_firmware_check(m_aapl_handler, serdes + 1, revision, build_id);
            sw_check2.stop();
            if (!res) {
                return LA_STATUS_EUNKNOWN;
            }
        }
    }

    log_debug(SERDES,
              "Verify times: check1 %zd, upload %zd, init %zd check2 %zd",
              (size_t)sw_check1.get_total_elapsed_time(stopwatch::time_unit_e::MS),
              (size_t)sw_upload.get_total_elapsed_time(stopwatch::time_unit_e::MS),
              (size_t)sw_init.get_total_elapsed_time(stopwatch::time_unit_e::MS),
              (size_t)sw_check2.get_total_elapsed_time(stopwatch::time_unit_e::MS));
    return LA_STATUS_SUCCESS;
}

bool
avago_serdes_handler::serdes_firmware_check(Aapl_t* aapl_handler, size_t serdes, int rev, int build)
{
    int cur_rev = avago_firmware_get_rev(aapl_handler, serdes);
    if (cur_rev != rev) {
        log_warning(
            SERDES, "Serdes %d firmware revision mismatched. Expected: 0x%04X Received: 0x%04X", (uint)(serdes - 1), rev, cur_rev);
        return false;
    }

    int cur_build = avago_firmware_get_build_id(aapl_handler, serdes);
    if (cur_build != build) {
        log_warning(
            SERDES, "Serdes %d firmware build mismatched. Expected: 0x%04X Received: 0x%04X", (uint)(serdes - 1), build, cur_build);
        return false;
    }

    cur_rev = aapl_get_firmware_rev(aapl_handler, serdes);
    if (cur_rev != rev) {
        // The actual revision seems to be correct but the "cached" is wrong.
        // Invalidate revision cache in AAPL structure.
        aapl_set_ip_type(aapl_handler, serdes);
    }

    return true;
}

la_status
avago_serdes_handler::wait_for_peer_start()
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = rx_serdes + 1;

        bool tx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].tx_enabled;
        bool rx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled;
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, false, tx_enabled);

        avago_serdes_set_rx_input_loopback(m_aapl_handler, serdes_addr, true);

        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, rx_enabled, tx_enabled);
    }

    // Tune for DFE based EID
    Avago_serdes_dfe_tune_t serdes_tune;
    avago_serdes_tune_init(m_aapl_handler, &serdes_tune);

    // Change signal OK interrupt to EID
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = rx_serdes + 1;

        if (m_dfe_eid) {
            // Do initial short tune
            // Set that tune to be short
            avago_serdes_hal_set(m_aapl_handler,
                                 serdes_addr,
                                 AVAGO_HAL_GLOBAL_TUNE_PARAMS,
                                 AVAGO_HAL_MEMBER_TUNE_EFFORT,
                                 AVAGO_HAL_TUNE_EFFORT_SHORT);
            avago_serdes_tune(m_aapl_handler, serdes_addr, &serdes_tune);
        } else {
            // enable EI detect
            avago_spico_int(
                m_aapl_handler, serdes_addr, AVAGO_INT_WRITE | AVSD_ESB16_RX_EI_THRESHOLD, AVAGO_ELECTRICAL_IDLE_ENABLE_DETECT);

            // set threshold
            int threshold = get_serdes_parameter_per_lane(
                serdes, la_mac_port::serdes_param_e::ELECTRICAL_IDLE_THRESHOLD, AVAGO_ELECTRICAL_IDLE_THRESHOLD);
            avago_serdes_initialize_signal_ok(m_aapl_handler, serdes_addr, threshold);
        }

        // signal_ok config select
        // enable it to track EID and selects the method
        avago_serdes_hal_set(m_aapl_handler,
                             serdes_addr,
                             AVAGO_HAL_GLOBAL_TUNE_PARAMS,
                             AVAGO_HAL_MEMBER_SIGNAL_OK,
                             m_dfe_eid ? AVAGO_HAL_SIGNAL_OK_DFE_EID : AVAGO_HAL_SIGNAL_OK_EID);
    }

    // Validate correct Rx PLL settings
    validate_rxpll();

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::wait_for_peer_stop()
{
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = rx_serdes + 1;

        bool tx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].tx_enabled;
        bool rx_enabled = m_device->m_serdes_status[m_slice_id][m_ifg_id][rx_serdes].rx_enabled;
        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, false, tx_enabled);

        avago_serdes_set_rx_input_loopback(m_aapl_handler, serdes_addr, false);

        avago_serdes_set_tx_rx_enable(m_aapl_handler, serdes_addr, tx_enabled, rx_enabled, tx_enabled);
    }

    // Change signal OK interrupt to CDR lock
    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        size_t tx_serdes = m_serdes_base_id + serdes;
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][tx_serdes].rx_source;

        bool pam4_en = s_serdes_config.at(m_serdes_speed).pam4_enable;
        bool enable_fast_tune;
        if (pam4_en == false) { // NRZ
            enable_fast_tune = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_NRZ_FAST_TUNE].bool_val;
        } else {
            if (is_network_slice(m_serdes_slice_mode)) { // NETWORK PAM4
                enable_fast_tune
                    = m_device->m_device_properties[(int)la_device_property_e::ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE].bool_val;
            } else { // FABRIC PAM4
                enable_fast_tune
                    = m_device->m_device_properties[(int)la_device_property_e::ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE].bool_val;
            }
        }

        enable_fast_tune = get_serdes_parameter_per_lane(serdes, la_mac_port::serdes_param_e::RX_FAST_TUNE, enable_fast_tune);

        // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
        size_t serdes_addr = rx_serdes + 1;

        if (!m_dfe_eid) {
            // disable EI detect
            avago_spico_int(
                m_aapl_handler, serdes_addr, AVAGO_INT_WRITE | AVSD_ESB16_RX_EI_THRESHOLD, AVAGO_ELECTRICAL_IDLE_DISABLE_DETECT);
        }

        // signal_ok config select
        // Disable it to track EID
        avago_serdes_hal_set(m_aapl_handler, serdes_addr, AVAGO_HAL_GLOBAL_TUNE_PARAMS, AVAGO_HAL_MEMBER_SIGNAL_OK, 0);
        avago_serdes_hal_set(m_aapl_handler,
                             serdes_addr,
                             AVAGO_HAL_GLOBAL_TUNE_PARAMS,
                             AVAGO_HAL_MEMBER_TUNE_EFFORT,
                             enable_fast_tune ? AVAGO_HAL_TUNE_EFFORT_FAST : AVAGO_HAL_TUNE_EFFORT_FULL);
    }

    return LA_STATUS_SUCCESS;
}

void
avago_serdes_handler::print_tune_status_message(const char* message, la_logger_level_e severity)
{
    // Tune timeout. Currently, we can't stop the tune, so we just issue a warning and continue to wait.
    logger& instance = logger::instance();
    if (instance.is_logging(silicon_one::get_device_id(), la_logger_component_e::SERDES, severity)) {
        std::stringstream tune_log_message;
        tune_log_message << "[ ";
        // Check tune
        for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
            size_t rx_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source + 1;
            // The address in Avago is the SerDes ID, SerDes ID starting from 1 (not 0).
            int tune_stat = avago_serdes_get_dfe_status(m_aapl_handler, rx_addr);
            tune_log_message << "0x" << std::hex << tune_stat << ' ';
        }
        tune_log_message << "]";

        log_message(la_logger_component_e::SERDES,
                    severity,
                    "%s on SerDes %d/%d/%d: DFE status %s",
                    message,
                    m_slice_id,
                    m_ifg_id,
                    m_serdes_base_id,
                    tune_log_message.str().c_str());
    }
}

void
avago_serdes_handler::save_serdes_debug_message(const char* message)
{
    if (m_device->is_simulated_or_emulated_device()) {
        log_debug(SERDES, "%s : simulated or emulated device - cannot get SERDES debug data", __func__);
        return;
    }

    logger& instance = logger::instance();
    std::vector<serdes_debug_snapshot> serdes_snapshots;
    la_int_t max_num_of_snapshots;

    // check if we will capture a snapshot for save_state
    m_device->get_int_property(la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS, max_num_of_snapshots);

    // update queue size since it can by dynamic
    m_serdes_debug_snapshot_queue.set_max_size(max_num_of_snapshots);

    bool capture_snapshot = max_num_of_snapshots > 0;
    bool send_to_log = instance.is_logging(
        silicon_one::get_device_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::XDEBUG);

    // only get data if we are going to use it
    if (capture_snapshot || send_to_log) {
        get_serdes_debug_snapshots(message, serdes_snapshots);
    }

    if (send_to_log) {
        print_serdes_debug_snapshots(serdes_snapshots);
    }

    if (capture_snapshot) {
        m_serdes_debug_snapshot_queue.push(serdes_snapshots);
    }
}

void
avago_serdes_handler::print_serdes_debug_message(const char* message)
{
    logger& instance = logger::instance();
    std::vector<serdes_debug_snapshot> serdes_snapshots;

    if (m_device->is_simulated_or_emulated_device()) {
        log_debug(SERDES, "%s : simulated or emulated device - cannot get SERDES debug data", __func__);
        return;
    }

    bool send_to_log = instance.is_logging(
        silicon_one::get_device_id(), silicon_one::la_logger_component_e::SERDES, silicon_one::la_logger_level_e::XDEBUG);

    if (send_to_log) {
        get_serdes_debug_snapshots(message, serdes_snapshots);
        print_serdes_debug_snapshots(serdes_snapshots);
    }
}

void
avago_serdes_handler::print_serdes_debug_snapshots(std::vector<serdes_debug_snapshot>& serdes_snapshots)
{

    for (size_t serdes = 0; serdes < serdes_snapshots.size(); serdes++) {
        serdes_debug_snapshot& snapshot = serdes_snapshots[serdes];
        Avago_serdes_dfe_state_t& dfe_state = snapshot.dfe_state;
        la_int_t& delta_cal_fail = snapshot.delta_cal_fail;
        std::string& signal_ok_enable = snapshot.signal_ok_enable;

        // string stream is debug log of the form below
        // 'ctle: # # # # # # # rxFFE: # # # # # # # ...'
        std::stringstream dump_log_info;

        dump_log_info << "SerDes " << snapshot.serdes_id << ", ";

        dump_log_info << "ctle:";
        dump_log_info << dfe_state.dc << " ";
        dump_log_info << dfe_state.lf << " ";
        dump_log_info << dfe_state.hf << " ";
        dump_log_info << dfe_state.bw << " ";
        dump_log_info << dfe_state.gainshape1 << " ";
        dump_log_info << dfe_state.gainshape2 << " ";
        dump_log_info << dfe_state.short_channel_en;
        dump_log_info << ", rxFFE:";

        for (int i = 0; i < 7; i++) {
            dump_log_info << dfe_state.rxFFE[i] << " ";
        }

        dump_log_info << ", eyeH:";

        for (int i = 0; i < 6; i++) {
            dump_log_info << std::hex << dfe_state.eyeHeights[i] << " ";
        }
        dump_log_info << ", sts:";

        dump_log_info << std::hex << dfe_state.state << " ";
        dump_log_info << std::hex << dfe_state.status << " ";

        dump_log_info << ", d_cal: 0x";
        dump_log_info << std::hex << delta_cal_fail;

        dump_log_info << ", signal_ok_enable:";
        dump_log_info << signal_ok_enable;

        log_xdebug(SERDES, "%s %s", snapshot.message.c_str(), dump_log_info.str().c_str());

        // Check to see if Delta Cal Fail (Uncorrectable code words in PAM4 mode)
        // When Delta Cal fails, avago sets 1st nibble to '7'
        if ((delta_cal_fail & AVAGO_DELTA_CAL_FAIL_MASK) == AVAGO_DELTA_CAL_FAIL_VALUE) {
            log_err(SERDES, "Delta Cal Failure Detected on SerDes: %s : %x ", snapshot.serdes_id.c_str(), delta_cal_fail);
        }
    }
}

la_status
avago_serdes_handler::get_serdes_debug_snapshots(const char* message,
                                                 std::vector<serdes_debug_snapshot>& out_serdes_debug_snapshots)
{
    if (m_device->is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    out_serdes_debug_snapshots.resize(m_serdes_count, serdes_debug_snapshot{});

    for (size_t serdes = 0; serdes < out_serdes_debug_snapshots.size(); serdes++) {

        size_t rx_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source + 1;
        Avago_serdes_dfe_state_t dfe_state{};
        serdes_debug_snapshot& snapshot = out_serdes_debug_snapshots[serdes];

        // get snapshot data
        // -----------------
        // Read Avago registers for the dfe state structure. This structure contains some of data in array format.
        avago_serdes_get_dfe_state(m_aapl_handler, rx_addr, &dfe_state);

        int delta_cal_fail
            = avago_serdes_hal_get(m_aapl_handler, rx_addr, AVAGO_HAL_GLOBAL_TUNE_PARAMS, AVAGO_HAL_MEMBER_RETRY_STATUS);

        la_uint_t freq_lock = avago_serdes_get_frequency_lock(m_aapl_handler, rx_addr);

        // get signal okay and sticky bit to analyze link
        uint8_t signal_ok_enable = avago_serdes_get_signal_ok_enable(m_aapl_handler, rx_addr);
        uint8_t sticky_signal_ok_enable = avago_serdes_get_signal_ok_enable(m_aapl_handler, rx_addr);
        std::stringstream signal_ok_enable_stream;
        signal_ok_enable_stream << std::to_string(signal_ok_enable) << std::to_string(sticky_signal_ok_enable);

        json_t* rx_eye_root = json_object();
        json_t* rx_reg_root = json_object();
        if (m_debug_mode) {
            add_serdes_eye_capture(rx_eye_root, rx_addr);
            add_serdes_reg_dump(rx_reg_root, rx_addr);
        }

        // get timestamp
        size_t buffer_size = 100;
        char timestamp[buffer_size];
        add_timestamp(timestamp, sizeof(timestamp));

        // create snapshot of data
        // -----------------------
        snapshot.message = std::string(message);
        snapshot.serdes_id = silicon_one::to_string(m_slice_id, m_ifg_id, rx_addr - 1);
        snapshot.timestamp = std::string(timestamp);
        snapshot.dfe_state = dfe_state;
        snapshot.frequency_lock = freq_lock;
        snapshot.delta_cal_fail = delta_cal_fail;
        snapshot.signal_ok_enable = signal_ok_enable_stream.str();
        if (m_debug_mode) {
            snapshot.eye_capture = rx_eye_root;
            snapshot.reg_capture = rx_reg_root;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::configure_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    auto elem = serdes_test_mode_data.find(mode);
    if (elem->first != mode) {
        return LA_STATUS_EINVAL;
    }
    if (m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        log_debug(SERDES, "%s: skip SerDes access during reconnect", __func__);
        return LA_STATUS_SUCCESS;
    }

    if (direction == la_serdes_direction_e::TX) {
        for (la_uint_t lane = m_serdes_base_id; lane < (m_serdes_base_id + m_serdes_count); lane++) {
            uint tx_addr;

            tx_addr = lane + 1;

            // Tx PRBS settings
            avago_serdes_set_tx_data_sel(m_aapl_handler, tx_addr, elem->second.tx_data);
        }
    } else {
        for (la_uint_t lane = m_serdes_base_id; lane < (m_serdes_base_id + m_serdes_count); lane++) {
            uint rx_addr;

            // Take swap information into account
            rx_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][lane].rx_source + 1;

            // Rx PRBS settings
            avago_serdes_set_rx_cmp_data(m_aapl_handler, rx_addr, elem->second.rx_data);
            avago_serdes_set_rx_cmp_mode(m_aapl_handler, rx_addr, elem->second.rx_mode);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::setup_test_counter(la_mac_port::serdes_test_mode_e mode)
{
    int avago_stat;
    la_status rc = LA_STATUS_SUCCESS;
    la_uint_t lane;

    if (m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        log_debug(SERDES, "%s: skip SerDes access during reconnect", __func__);
        return LA_STATUS_SUCCESS;
    }

    for (lane = m_serdes_base_id; lane < (m_serdes_base_id + m_serdes_count); lane++) {
        uint tx_addr = lane + 1;

        if (m_continuous_tuning_activated) {
            if (mode == la_mac_port::serdes_test_mode_e::NONE) {
                avago_stat = avago_serdes_aux_counter_disable(m_aapl_handler, tx_addr);
                if (avago_stat < 0) {
                    log_err(SERDES,
                            "Failed avago_serdes_aux_counter_disable of Slice/IFG/SerDes %d/%d/%d (addr %d) ",
                            m_slice_id,
                            m_ifg_id,
                            lane,
                            tx_addr);
                    rc = LA_STATUS_EINVAL;
                }
            } else {
                avago_stat = avago_serdes_aux_counter_start(m_aapl_handler, tx_addr);
                if (avago_stat < 0) {
                    log_err(SERDES,
                            "Failed avago_serdes_aux_counter_start of Slice/IFG/SerDes %d/%d/%d (addr %d) ",
                            m_slice_id,
                            m_ifg_id,
                            lane,
                            tx_addr);
                    rc = LA_STATUS_EINVAL;
                }
            }
        } else {
            avago_stat = avago_serdes_error_reset(m_aapl_handler, tx_addr);
            if (avago_stat < 0) {
                log_err(SERDES,
                        "Failed avago_serdes_error_reset of Slice/IFG/SerDes %d/%d/%d (addr %d) ",
                        m_slice_id,
                        m_ifg_id,
                        lane,
                        tx_addr);
                rc = LA_STATUS_EINVAL;
            }
        }
    }
    return rc;
}

la_status
avago_serdes_handler::set_test_mode(la_uint_t serdes_idx, la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
avago_serdes_handler::set_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode)
{
    if (mode > la_mac_port::serdes_test_mode_e::LAST) {
        return LA_STATUS_EINVAL;
    }

    if (m_continuous_tuning_enabled == true && (mode != la_mac_port::serdes_test_mode_e::NONE)) {
        log_err(SERDES,
                "Slice/IFG/SerDes %d/%d/%d continuous tuning (pCal) should be disabled before configuring SerDes test mode.",
                m_slice_id,
                m_ifg_id,
                m_serdes_base_id);
        return LA_STATUS_EINVAL;
    }

    la_status stat = configure_test_mode(direction, mode);
    if (stat != LA_STATUS_SUCCESS) {
        return stat;
    }

    stat = setup_test_counter(mode);
    if (stat != LA_STATUS_SUCCESS) {
        return stat;
    }

    if (m_serdes_test_stopwatch.is_running()) {
        m_serdes_test_stopwatch.stop();
    }

    if (mode != la_mac_port::serdes_test_mode_e::NONE) {
        m_serdes_test_stopwatch.start();
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::read_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
avago_serdes_handler::read_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber)
{
    long elapsed_ms;

    // stop the stopwatch
    m_serdes_test_stopwatch.stop();

    // compute elapsed time in ms
    elapsed_ms = (long)m_serdes_test_stopwatch.get_total_elapsed_time(stopwatch::time_unit_e::MS);

    for (la_uint_t lane = 0; lane < m_serdes_count; lane++) {
        uint rx_serdes, rx_addr;
        Avago_serdes_pll_state_t pll_state;
        Avago_serdes_line_encoding_t pam_rx;
        Avago_serdes_line_encoding_t dummy;

        // Take swap information into account
        rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][lane].rx_source;
        rx_addr = rx_serdes + 1;

        avago_serdes_get_signal_ok(m_aapl_handler, rx_addr, true);

        // Get PLL state, which contains the estimated bitrate
        avago_serdes_get_tx_pll_state(m_aapl_handler, rx_addr, &pll_state);
        avago_serdes_get_tx_rx_line_encoding(m_aapl_handler, rx_addr, &dummy, &pam_rx);

        bool sig_ok = avago_serdes_get_signal_ok(m_aapl_handler, rx_addr, false);

        // default invalid values
        out_serdes_prbs_ber.lane_ber[lane] = -1.0;
        out_serdes_prbs_ber.count[lane] = 0;
        out_serdes_prbs_ber.errors[lane] = 0;

        log_debug(SERDES, "Lane %d is Slice/IFG/SerDes %d/%d/%d", lane, m_slice_id, m_ifg_id, rx_serdes);

        if (!sig_ok) {
            // signal not ok, zero out results and print warning
            log_debug(SERDES, "Signal not ok for Slice/IFG/SerDes %d/%d/%d - no BER", m_slice_id, m_ifg_id, rx_serdes);
            continue;
        }

        uint64_t est_rate = pll_state.est_rate * ((pam_rx == AVAGO_SERDES_PAM4) + 1);

        if (est_rate == 0) {
            // check to avoid divide by 0
            log_err(SERDES, "Estimated rate 0 for Slice/IFG/SerDes %d/%d/%d - no BER calculated", m_slice_id, m_ifg_id, rx_serdes);
            continue;
        }

        // Read PRBS bit error count
        if (m_continuous_tuning_activated) {
            // pCal on, use auxiliary counter
            out_serdes_prbs_ber.errors[lane] = avago_serdes_aux_counter_read(m_aapl_handler, rx_addr);
        } else {
            // nomal error counter
            out_serdes_prbs_ber.errors[lane] = avago_serdes_get_errors(m_aapl_handler, rx_addr, AVAGO_LSB, 1);
        }

        // Esitmate bit count
        out_serdes_prbs_ber.count[lane] = (est_rate * elapsed_ms) / 1000;

        // Compute BER
        out_serdes_prbs_ber.lane_ber[lane] = (float)out_serdes_prbs_ber.errors[lane] / out_serdes_prbs_ber.count[lane];
    }

    // restart stopwatch
    m_serdes_test_stopwatch.start();

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::enable_low_power(bool enable)
{
    log_xdebug(SERDES,
               "%s slice/ifg/serdes %d/%d/%d: entered %s low power mode.",
               __func__,
               m_slice_id,
               m_ifg_id,
               m_serdes_base_id,
               enable ? "enable" : "disable");

    bool serdes_low_power_en = 0;
    serdes_low_power_en = m_device->m_device_properties[(int)la_device_property_e::ENABLE_SERDES_LOW_POWER].bool_val;
    if (!serdes_low_power_en) {
        return LA_STATUS_SUCCESS;
    }

    // Low power SerDes mode not supported in SerDes loopback mode and not in remote PMA loopback mode.
    if ((m_loopback_mode != la_mac_port::loopback_mode_e::NONE)
        && (m_loopback_mode != la_mac_port::loopback_mode_e::REMOTE_SERDES)) {
        return LA_STATUS_SUCCESS;
    }

    if (m_device->is_simulated_or_emulated_device() || m_device->m_reconnect_handler->is_reconnect_in_progress()) {
        return LA_STATUS_SUCCESS;
    }

    for (size_t lane = m_serdes_base_id; lane < m_serdes_count + m_serdes_base_id; lane++) {
        // Consider lane swaps outside the port.
        size_t serdes_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][lane].rx_source + 1;

        avago_serdes_enable_low_power_mode(m_aapl_handler, serdes_addr, enable);
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_serdes_speed_gbps(size_t serdes_speed_gbps)
{
    m_serdes_speed_gbps = serdes_speed_gbps;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_anlt_capabilities(bool enable, serdes_handler::an_capability_code_e an_spec_cap, size_t an_fec_request)
{
    m_is_an_enabled = enable;
    m_an_spec_cap = an_spec_cap;
    m_an_fec_request = an_fec_request;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_tuning_mode(la_mac_port::serdes_tuning_mode_e mode)
{
    m_tuning_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_debug_mode(bool mode)
{
    m_debug_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_continuous_tuning_enabled(bool enabled)
{
    m_continuous_tuning_enabled = enabled;

    return LA_STATUS_SUCCESS;
}

// Return the SerDes address used by the aapl_handler.
la_status
avago_serdes_handler::get_serdes_addr(la_uint_t serdes_idx, la_serdes_direction_e serdes_dir, uint32_t& out_serdes_addr)
{
    if (serdes_dir == la_serdes_direction_e::RX) {
        out_serdes_addr = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes_idx].rx_source + 1;
    } else {
        out_serdes_addr = m_serdes_base_id + serdes_idx + 1;
    }

    return LA_STATUS_SUCCESS;
}

void
avago_serdes_handler::add_serdes_debug_snapshots(json_t* out_root)
{
    la_int_t max_num_of_snapshots;

    // update queue size since it can by dynamic
    m_device->get_int_property(la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS, max_num_of_snapshots);
    m_serdes_debug_snapshot_queue.set_max_size(max_num_of_snapshots);

    // user has disabled this  feature
    if (max_num_of_snapshots == 0) {
        return;
    }

    if (m_serdes_debug_snapshot_queue.size() == 0) {
        log_debug(SERDES, "%s : No SerDes tune data to add to save_state.", __func__);
        return;
    }

    json_t* fifo_snapshots_array = json_array();

    // get pointer to first most recent entry in queue
    auto snapshot_iter = m_serdes_debug_snapshot_queue.begin();

    // iterate through all of the snapshots in the queue
    while (snapshot_iter != m_serdes_debug_snapshot_queue.end()) {

        // each vector has a debug snapshot for all of the available serdes
        std::vector<serdes_debug_snapshot>& all_serdes_debug_snapshots = *snapshot_iter++;

        json_t* snapshot_root = json_object();

        for (size_t serdes_snapshot_idx = 0; serdes_snapshot_idx < all_serdes_debug_snapshots.size(); serdes_snapshot_idx++) {
            // snapshot_data contains a snapshot of all serdes in the mac port
            serdes_debug_snapshot& serdes_debug_snapshot = all_serdes_debug_snapshots[serdes_snapshot_idx];
            Avago_serdes_dfe_state_t& dfe_state = serdes_debug_snapshot.dfe_state;
            json_t* serdes_snapshot_root = json_object();

            // General Information
            // -------------------
            json_object_set_new(serdes_snapshot_root, "serdes_id", json_string(serdes_debug_snapshot.serdes_id.c_str()));
            json_object_set_new(serdes_snapshot_root, "cause", json_string(serdes_debug_snapshot.message.c_str()));
            json_object_set_new(serdes_snapshot_root, "timestamp", json_string(serdes_debug_snapshot.timestamp.c_str()));

            // CTLE Information
            // ----------------
            json_t* ctle_snapshot_root = json_object();
            json_object_set_new(ctle_snapshot_root, "bw", json_integer(dfe_state.bw));
            json_object_set_new(ctle_snapshot_root, "dc", json_integer(dfe_state.dc));
            json_object_set_new(ctle_snapshot_root, "hf", json_integer(dfe_state.hf));
            json_object_set_new(ctle_snapshot_root, "lf", json_integer(dfe_state.lf));
            json_object_set_new(ctle_snapshot_root, "gainshape1", json_integer(dfe_state.gainshape1));
            json_object_set_new(ctle_snapshot_root, "gainshape2", json_integer(dfe_state.gainshape2));
            json_object_set_new(ctle_snapshot_root, "short_channel_en", json_integer(dfe_state.short_channel_en));

            json_object_set_new(serdes_snapshot_root, "ctle", ctle_snapshot_root);

            // RxFFE Information
            // ----------------------
            json_t* rxFFE_snapshot_array = json_array();
            for (size_t i = 0; i < 7; i++) {
                std::string hex_val = convert_to_signed_hex(dfe_state.rxFFE[i]);
                json_array_append_new(rxFFE_snapshot_array, json_string(hex_val.c_str()));
            }
            json_object_set_new(serdes_snapshot_root, "rxFFE", rxFFE_snapshot_array);

            // VOS Information
            // ----------------------
            json_t* vos_snapshot_array = json_array();
            for (size_t i = 0; i < 10; i++) {
                std::string hex_val = convert_to_signed_hex(dfe_state.vos[i]);
                json_array_append_new(vos_snapshot_array, json_string(hex_val.c_str()));
            }
            json_object_set_new(serdes_snapshot_root, "vos", vos_snapshot_array);

            // Vernier Information
            // ----------------------
            json_t* vernier_snapshot_array = json_array();
            for (size_t i = 0; i < 11; i++) {
                json_array_append_new(vernier_snapshot_array,
                                      json_string(convert_to_signed_hex(dfe_state.vernierDelay[i]).c_str()));
            }
            json_object_set_new(serdes_snapshot_root, "vernierDelay", vernier_snapshot_array);

            // DFE Information
            // ----------------------
            json_t* dfe_snapshot_array = json_array();
            for (size_t i = 0; i < AVAGO_DFE_TAP_COUNT; i++) {
                json_array_append_new(dfe_snapshot_array, json_string(convert_to_signed_hex(dfe_state.dfeTAP[i]).c_str()));
            }
            json_object_set_new(serdes_snapshot_root, "dfeTAP", dfe_snapshot_array);

            // Eye Information
            // ----------------------
            json_t* eyeHeights_snapshot_array = json_array();
            for (size_t i = 0; i < 6; i++) {
                std::string hex_val = convert_to_signed_hex(dfe_state.eyeHeights[i]);
                json_array_append_new(eyeHeights_snapshot_array, json_string(hex_val.c_str()));
            }
            json_object_set_new(serdes_snapshot_root, "eyeHeights", eyeHeights_snapshot_array);

            // Add single data fields
            // ----------------------
            json_object_set_new(serdes_snapshot_root, "state", json_string(convert_to_hex(dfe_state.state).c_str()));
            json_object_set_new(serdes_snapshot_root, "status", json_string(convert_to_hex(dfe_state.status).c_str()));
            json_object_set_new(serdes_snapshot_root, "frequency_lock", json_integer(serdes_debug_snapshot.frequency_lock));
            json_object_set_new(
                serdes_snapshot_root, "delta_cal_fail", json_string(convert_to_hex(serdes_debug_snapshot.delta_cal_fail).c_str()));
            json_object_set_new(
                serdes_snapshot_root, "signal_ok_enable", json_string(serdes_debug_snapshot.signal_ok_enable.c_str()));
            if (m_debug_mode) {
                json_object_set_new(serdes_snapshot_root, "eye_capture", serdes_debug_snapshot.eye_capture);
                json_object_set_new(serdes_snapshot_root, "reg_dump", serdes_debug_snapshot.reg_capture);
            }

            // Append SerDes information into the snapshot structure
            // -----------------------------------------------------
            std::string serdes_snapshot_key = "index_" + std::to_string(serdes_snapshot_idx);
            json_object_set_new(snapshot_root, serdes_snapshot_key.c_str(), serdes_snapshot_root);
        }

        // add snapshot to object that is ordered from newest to oldest
        // ------------------------------------------------------------
        json_array_append_new(fifo_snapshots_array, snapshot_root);
    }

    json_object_set_new(out_root, "serdes_failed_tunes", fifo_snapshots_array);
}

void
avago_serdes_handler::add_serdes_tx_param(json_t* out_root, uint32_t addr)
{
    Aapl_t* aapl_handler = m_aapl_handler;
    if (aapl_handler == nullptr) {
        return;
    }

    uint32_t refclk_reg_offset = 0xd1;
    uint16_t refclk_mask = 0x8000;
    Avago_serdes_tx_state_t tx{};
    Avago_serdes_rx_state_t rx{};
    Avago_serdes_pll_state_t tx_pll_state{};
    Avago_serdes_datapath_t tx_datapath{};

    // Use Avago API to get key information
    avago_serdes_get_tx_rx_ready(aapl_handler, addr, &tx.enable, &rx.enable);
    avago_serdes_get_tx_rx_width(aapl_handler, addr, &tx.width, &rx.width);
    avago_serdes_get_tx_eq(aapl_handler, addr, &tx.eq);
    avago_serdes_get_tx_datapath(aapl_handler, addr, &tx_datapath);
    la_int_t ref_clk = avago_serdes_mem_rd(aapl_handler, addr, AVAGO_LSB, refclk_reg_offset);
    ref_clk = (ref_clk & refclk_mask) ? 1 : 0;

    /// Initialize Avago_serdes_tx_state_t structure
    tx.output_enable = avago_serdes_get_tx_output_enable(aapl_handler, addr);
    tx.data_sel = avago_serdes_get_tx_data_sel(aapl_handler, addr);
    tx.pll_clk_source = avago_serdes_get_tx_pll_clk_src(aapl_handler, addr);
    tx.fw_revision = avago_firmware_get_rev(aapl_handler, addr);
    tx.fw_build_id = avago_firmware_get_build_id(aapl_handler, addr);
    tx.encoding = (Avago_serdes_line_encoding_t)avago_serdes_get_tx_line_encoding(aapl_handler, addr);

    // Get TX PLL information
    avago_serdes_get_tx_pll_state(aapl_handler, addr, &tx_pll_state);
    tx.divider = tx_pll_state.divider;
    if (!tx.enable) {
        tx.divider = 0;
    }

    // Avago documentation multiplies this value by 1000
    double rate = tx_pll_state.line_rate_div / 1000.0;
    // est_rate is in Hz, need to convert to GHz
    double estimated_ghz = tx_pll_state.est_rate / 1000000000.0;
    if (tx.encoding == AVAGO_SERDES_PAM4) {
        estimated_ghz = estimated_ghz * 2;
    }

    // standard DSC for TX
    json_t* tx_parameters_root = json_object();
    json_object_set_new(tx_parameters_root, "enable", json_integer(tx.enable));
    json_object_set_new(tx_parameters_root, "width", json_integer(tx.width));
    json_object_set_new(tx_parameters_root, "encoding", json_string((tx.encoding == AVAGO_SERDES_PAM4 ? "PAM-4" : "PAM-2")));
    json_object_set_new(tx_parameters_root, "polarity_invert", json_string(aapl_onoff_to_str(tx_datapath.polarity_invert)));
    json_object_set_new(tx_parameters_root, "gray_enable", json_string(aapl_onoff_to_str(tx_datapath.gray_enable)));
    json_object_set_new(tx_parameters_root, "precode_enable", json_string(aapl_onoff_to_str(tx_datapath.precode_enable)));
    json_object_set_new(tx_parameters_root, "swizzle_enable", json_string(aapl_onoff_to_str(tx_datapath.swizzle_enable)));
    json_object_set_new(tx_parameters_root, "cal_code", json_integer(tx_pll_state.cal_code));
    json_object_set_new(tx_parameters_root, "line_rate", json_real(rate));
    json_object_set_new(tx_parameters_root, "divider", json_integer(tx_pll_state.divider));
    json_object_set_new(tx_parameters_root, "estimated_Gbps", json_real(estimated_ghz));
    json_object_set_new(tx_parameters_root, "data_sel", json_string(aapl_data_sel_to_str(tx.data_sel)));
    json_object_set_new(tx_parameters_root, "output_enable", json_integer(tx.output_enable));
    json_object_set_new(tx_parameters_root, "pre3", json_integer(tx.eq.pre3));
    json_object_set_new(tx_parameters_root, "pre2", json_integer(tx.eq.pre2));
    json_object_set_new(tx_parameters_root, "pre", json_integer(tx.eq.pre));
    json_object_set_new(tx_parameters_root, "atten", json_integer(tx.eq.atten));
    json_object_set_new(tx_parameters_root, "post", json_integer(tx.eq.post));
    json_object_set_new(tx_parameters_root, "vert", json_integer(tx.eq.vert));
    json_object_set_new(tx_parameters_root, "amp", json_integer(tx.eq.amp));
    json_object_set_new(tx_parameters_root, "slew", json_integer(tx.eq.slew));
    json_object_set_new(tx_parameters_root, "t2", json_integer(tx.eq.t2));

    std::string fw_build_id = to_hex_string(tx.fw_build_id);
    std::string fw_revision = to_hex_string(tx.fw_revision);
    json_object_set_new(tx_parameters_root, "fw_build_id", json_string(fw_build_id.c_str()));
    json_object_set_new(tx_parameters_root, "fw_revision", json_string(fw_revision.c_str()));
    json_object_set_new(tx_parameters_root, "ref_clk", json_integer(ref_clk));
    json_object_set_new(tx_parameters_root, "pll_clk_source", json_string(aapl_pll_clk_to_str(tx.pll_clk_source)));
    json_object_set_new(tx_parameters_root, "bbGAIN", json_integer(tx_pll_state.bbGAIN));
    json_object_set_new(tx_parameters_root, "intGAIN", json_integer(tx_pll_state.intGAIN));
    json_object_set_new(tx_parameters_root, "atten_lsb", json_integer(tx.eq.atten_lsb));
    json_object_set_new(tx_parameters_root, "atten_msb", json_integer(tx.eq.atten_msb));
    json_object_set_new(tx_parameters_root, "post_lsb", json_integer(tx.eq.post_lsb));
    json_object_set_new(tx_parameters_root, "post_msb", json_integer(tx.eq.post_msb));
    json_object_set_new(tx_parameters_root, "pre2_lsb", json_integer(tx.eq.pre2_lsb));
    json_object_set_new(tx_parameters_root, "pre2_msb", json_integer(tx.eq.pre2_msb));
    json_object_set_new(tx_parameters_root, "pre_lsb", json_integer(tx.eq.pre_lsb));
    json_object_set_new(tx_parameters_root, "pre_msb", json_integer(tx.eq.pre_msb));

    json_object_set_new(out_root, "tx_parameters", tx_parameters_root);
}

void
avago_serdes_handler::add_serdes_rx_param(json_t* out_root, uint32_t addr)
{
    Aapl_t* aapl_handler = m_aapl_handler;
    if (aapl_handler == nullptr) {
        return;
    }

    uint32_t refclk_reg_offset = 0x85;
    uint16_t refclk_mask = 0x0020;
    uint8_t o_core_status_reg_offset = 0x27;
    Avago_serdes_tx_state_t tx{};
    Avago_serdes_rx_state_t rx{};
    Avago_serdes_pll_state_t rx_pll_state{};
    Avago_serdes_datapath_t rx_datapath{};
    std::string electrical_idle = "Dis";
    bool reset = false;

    // Use avago api to get key information
    Avago_serdes_data_qual_t data_qual = avago_serdes_get_data_qual(aapl_handler, addr);
    la_int_t o_core_status = avago_serdes_mem_rd(aapl_handler, addr, AVAGO_LSB, o_core_status_reg_offset);
    la_int_t error_flag = avago_serdes_get_error_flag(aapl_handler, addr, reset);
    la_uint_t freq_lock = avago_serdes_get_frequency_lock(aapl_handler, addr);
    la_int_t ref_clk = avago_serdes_mem_rd(aapl_handler, addr, AVAGO_LSB, refclk_reg_offset);
    la_int_t ei_threshold = avago_serdes_get_signal_ok_threshold(aapl_handler, addr);
    avago_serdes_get_rx_datapath(aapl_handler, addr, &rx_datapath);
    ref_clk = (ref_clk & refclk_mask) ? 1 : 0;

    // Initialize Avago_serdes_rx_state_t structure
    avago_serdes_get_tx_rx_ready(aapl_handler, addr, &tx.enable, &rx.enable);
    avago_serdes_get_tx_rx_width(aapl_handler, addr, &tx.width, &rx.width);
    avago_serdes_get_rx_pll_state(aapl_handler, addr, &rx_pll_state);

    // get fast tune setting
    bool fast_tune_enabled = false;
    int fast_tune_reg = avago_serdes_hal_get(aapl_handler, addr, AVAGO_HAL_GLOBAL_TUNE_PARAMS, AVAGO_HAL_MEMBER_TUNE_EFFORT);
    if (fast_tune_reg == AVAGO_HAL_TUNE_EFFORT_FAST) {
        fast_tune_enabled = true;
    }

    rx.divider = rx_pll_state.divider;
    if (!rx.enable) {
        rx.divider = 0;
    }
    rx.polarity_invert = avago_serdes_get_rx_invert(aapl_handler, addr);
    rx.input_loopback = avago_serdes_get_rx_input_loopback(aapl_handler, addr);
    rx.pcs_fifo_clk_divider = avago_serdes_get_pcs_fifo_clk_div(aapl_handler, addr);
    rx.term = avago_serdes_get_rx_term(aapl_handler, addr);
    rx.cmp_data = avago_serdes_get_rx_cmp_data(aapl_handler, addr);
    rx.cmp_mode = avago_serdes_get_rx_cmp_mode(aapl_handler, addr);
    rx.encoding = (Avago_serdes_line_encoding_t)avago_serdes_get_rx_line_encoding(aapl_handler, addr);
    rx.signal_ok_enable = avago_serdes_get_signal_ok_enable(aapl_handler, addr);
    rx.signal_ok_threshold = avago_serdes_get_signal_ok_threshold(aapl_handler, addr);

    // Get two reads for signal ok to verify that signal is present
    // this is going to hold two reads of the signal state [4:7] = first read, [0:3] = second read
    uint8_t signal_ok_enable = avago_serdes_get_signal_ok_enable(aapl_handler, addr);
    std::stringstream signal_ok_enable_stream;
    signal_ok_enable_stream << std::to_string(rx.signal_ok_enable) << std::to_string(signal_ok_enable);
    // get live value to check if the signal is okay
    if (avago_serdes_get_signal_ok_enable(aapl_handler, addr)) {
        la_int_t electr_idle = avago_serdes_get_electrical_idle(aapl_handler, addr);
        electrical_idle = std::to_string(electr_idle);
    }

    // get RX PLL information
    avago_serdes_get_rx_pll_state(aapl_handler, addr, &rx_pll_state);
    rx.divider = rx_pll_state.divider;
    if (!rx.enable) {
        rx.divider = 0;
    }
    double rate = rx_pll_state.line_rate_div / 1000.0;
    // divide est_rate by 1,000,000,000
    double estimated_ghz = rx_pll_state.est_rate / 1000000000.0;
    if (rx.encoding == AVAGO_SERDES_PAM4) {
        estimated_ghz = estimated_ghz * 2;
    }

    json_t* rx_parameters_root = json_object();
    // standard DSC dump for RX
    json_object_set_new(rx_parameters_root, "enable", json_integer(rx.enable));
    json_object_set_new(rx_parameters_root, "width", json_integer(rx.width));
    json_object_set_new(rx_parameters_root, "encoding", json_string((rx.encoding == AVAGO_SERDES_PAM4 ? "PAM-4" : "PAM-2")));
    json_object_set_new(rx_parameters_root, "polarity_invert", json_string(aapl_onoff_to_str(rx_datapath.polarity_invert)));
    json_object_set_new(rx_parameters_root, "gray_enable", json_string(aapl_onoff_to_str(rx_datapath.gray_enable)));
    json_object_set_new(rx_parameters_root, "precode_enable", json_string(aapl_onoff_to_str(rx_datapath.precode_enable)));
    json_object_set_new(rx_parameters_root, "swizzle_enable", json_string(aapl_onoff_to_str(rx_datapath.swizzle_enable)));
    json_object_set_new(rx_parameters_root, "cal_code", json_integer(rx_pll_state.cal_code));
    json_object_set_new(rx_parameters_root, "line_rate", json_real(rate));
    json_object_set_new(rx_parameters_root, "divider", json_integer(rx_pll_state.divider));
    json_object_set_new(rx_parameters_root, "estimated_Gbps", json_real(estimated_ghz));
    json_object_set_new(rx_parameters_root, "cmp_data", json_string(aapl_cmp_data_to_str(rx.cmp_data)));
    json_object_set_new(rx_parameters_root, "data_qual", json_string(aapl_data_qual_to_str(data_qual)));
    json_object_set_new(rx_parameters_root, "cmp_mode", json_string(aapl_cmp_mode_to_str(rx.cmp_mode)));
    json_object_set_new(rx_parameters_root, "electrical_idle", json_string(electrical_idle.c_str()));
    json_object_set_new(rx_parameters_root, "signal_ok_enable", json_string(signal_ok_enable_stream.str().c_str()));
    json_object_set_new(rx_parameters_root, "frequency_lock", json_integer(freq_lock));
    json_object_set_new(rx_parameters_root, "o_core_status", json_string(to_hex_string(o_core_status).c_str()));
    json_object_set_new(rx_parameters_root, "term", json_string(aapl_term_to_str(rx.term)));
    json_object_set_new(rx_parameters_root, "error_flag", json_integer(error_flag));

    json_object_set_new(rx_parameters_root, "bbGAIN", json_integer(rx_pll_state.bbGAIN));
    json_object_set_new(rx_parameters_root, "intGAIN", json_integer(rx_pll_state.intGAIN));
    json_object_set_new(rx_parameters_root, "EI_threshold", json_integer(ei_threshold));
    json_object_set_new(rx_parameters_root, "fast_tune_enabled", json_boolean(fast_tune_enabled));
    json_object_set_new(rx_parameters_root, "ref_clk", json_integer(ref_clk));
    json_object_set_new(rx_parameters_root, "divider", json_integer(rx.divider));
    json_object_set_new(rx_parameters_root, "input_loopback", json_integer(rx.input_loopback));
    json_object_set_new(rx_parameters_root, "pcs_fifo_clk_divider", json_integer(rx.pcs_fifo_clk_divider));

    json_object_set_new(out_root, "rx_parameters", rx_parameters_root);
}

void
avago_serdes_handler::add_serdes_ctle_info(json_t* out_root, uint32_t addr)
{
    Aapl_t* aapl_handler = m_aapl_handler;
    if (aapl_handler == nullptr) {
        return;
    }

    // Create a node to store the SerDes information.
    json_t* serdes_root = json_object();
    Avago_serdes_ctle_t ctle{};

    // Read Avago registers for the ctle structure.
    avago_serdes_ctle_read(aapl_handler, addr, &ctle);

    json_object_set_new(serdes_root, "bw", json_integer(ctle.bw));
    json_object_set_new(serdes_root, "dc", json_integer(ctle.dc));
    json_object_set_new(serdes_root, "gainshape1", json_integer(ctle.gainshape1));
    json_object_set_new(serdes_root, "gainshape2", json_integer(ctle.gainshape2));
    json_object_set_new(serdes_root, "hf", json_integer(ctle.hf));
    json_object_set_new(serdes_root, "hf_max", json_integer(ctle.hf_max));
    json_object_set_new(serdes_root, "hf_min", json_integer(ctle.hf_min));
    json_object_set_new(serdes_root, "lf", json_integer(ctle.lf));
    json_object_set_new(serdes_root, "lf_max", json_integer(ctle.lf_max));
    json_object_set_new(serdes_root, "lf_min", json_integer(ctle.lf_min));
    json_object_set_new(serdes_root, "short_channel_en", json_integer(ctle.short_channel_en));

    json_object_set_new(out_root, "ctle_info", serdes_root);
}

la_status
avago_serdes_handler::is_tune_good()
{
    bool is_tune_good = true;
    bool pam4_en = s_serdes_config.at(m_serdes_speed).pam4_enable;
    bool check_25g_dfetap_en = false;
    int min_eye_height;

    if (m_loopback_mode == la_mac_port::loopback_mode_e::SERDES) {
        // There is no eye height in SERDES loopback
        return (LA_STATUS_SUCCESS);
    }

    if (pam4_en) { // PAM4
        min_eye_height = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_MIN_EYE_HEIGHT].int_val;
    } else { // NRZ
        if (m_serdes_speed == la_mac_port::port_speed_e::E_10G) {
            min_eye_height = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT].int_val;
        } else {
            min_eye_height = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_NRZ_MIN_EYE_HEIGHT].int_val;
        }
    }

    check_25g_dfetap_en = m_device->m_device_properties[(int)la_device_property_e::MAC_PORT_ENABLE_25G_DFETAP_CHECK].bool_val;

    for (size_t serdes = 0; serdes < m_serdes_count && is_tune_good; serdes++) {
        size_t rx_serdes = m_device->m_serdes_info[m_slice_id][m_ifg_id][m_serdes_base_id + serdes].rx_source;
        size_t rx_addr = rx_serdes + 1;
        Avago_serdes_dfe_state_t dfe_state{};

        avago_serdes_get_dfe_state(m_aapl_handler, rx_addr, &dfe_state);
        // check the eye height
        for (int i = 0; i < 6; i++) {
            if (dfe_state.eyeHeights[i] < min_eye_height) {
                log_debug(SERDES,
                          "Slice/IFG/SerDes %d/%d/%ld: eye [%d] %d is too small. min_eye_height threshold: %d",
                          m_slice_id,
                          m_ifg_id,
                          rx_serdes,
                          i,
                          dfe_state.eyeHeights[i],
                          min_eye_height);
                is_tune_good = false;
                print_tune_status_message("Tune bad eye height", la_logger_level_e::DEBUG);
                save_serdes_debug_message("iCal bad eye height");
                break;
            }
        }
        if (check_25g_dfetap_en && (m_serdes_speed == la_mac_port::port_speed_e::E_25G)) {
            // if first value of dfeTAP is -0x1F, retune
            if (dfe_state.dfeTAP[0] == -0x1F) {
                log_debug(SERDES,
                          "Slice/IFG/SerDes %d/%d/%ld: 25G SerDes has dfeTAP[0] = -0x1F. Retune.",
                          m_slice_id,
                          m_ifg_id,
                          rx_serdes);
                is_tune_good = false;
                print_tune_status_message("25G SerDes has dfeTAP[0] = -0x1F", la_logger_level_e::DEBUG);
                save_serdes_debug_message("25G SerDes has dfeTAP[0] = -0x1F");
                break;
            }
        }
    }
    return is_tune_good ? LA_STATUS_SUCCESS : LA_STATUS_EINVAL;
}

void
avago_serdes_handler::add_serdes_dfe_state_info(json_t* out_root, uint32_t addr)
{
    Aapl_t* aapl_handler = m_aapl_handler;
    if (aapl_handler == nullptr) {
        return;
    }

    json_t* dfe_info_root = json_object();
    Avago_serdes_dfe_state_t dfe_state{};

    // Read Avago registers for the dfe state structure. This structure contains some data in array format.
    avago_serdes_get_dfe_state(aapl_handler, addr, &dfe_state);

    json_object_set_new(dfe_info_root, "dc", json_string(convert_to_hex(dfe_state.dc & 0xff).c_str()));
    json_object_set_new(dfe_info_root, "lf", json_string(convert_to_hex(dfe_state.lf).c_str()));
    json_object_set_new(dfe_info_root, "hf", json_string(convert_to_hex(dfe_state.hf).c_str()));
    json_object_set_new(dfe_info_root, "bw", json_string(convert_to_hex(dfe_state.bw).c_str()));
    json_object_set_new(dfe_info_root, "gainshape1", json_string(convert_to_hex(dfe_state.gainshape1).c_str()));
    json_object_set_new(dfe_info_root, "gainshape2", json_string(convert_to_hex(dfe_state.gainshape2).c_str()));
    json_object_set_new(dfe_info_root, "short_channel_en", json_string(convert_to_hex(dfe_state.short_channel_en).c_str()));
    json_object_set_new(dfe_info_root, "dfeGAIN", json_string(convert_to_hex(dfe_state.dfeGAIN).c_str()));
    json_object_set_new(dfe_info_root, "dfeGAIN2", json_string(convert_to_hex(dfe_state.dfeGAIN2).c_str()));
    json_object_set_new(dfe_info_root, "fixed_dc", json_integer(dfe_state.fixed_dc));
    json_object_set_new(dfe_info_root, "fixed_lf", json_integer(dfe_state.fixed_lf));
    json_object_set_new(dfe_info_root, "fixed_hf", json_integer(dfe_state.fixed_hf));
    json_object_set_new(dfe_info_root, "fixed_bw", json_integer(dfe_state.fixed_bw));
    json_object_set_new(dfe_info_root, "seeded_dc", json_boolean(dfe_state.seeded_dc));
    json_object_set_new(dfe_info_root, "seeded_lf", json_boolean(dfe_state.seeded_lf));
    json_object_set_new(dfe_info_root, "seeded_hf", json_boolean(dfe_state.seeded_hf));
    json_object_set_new(dfe_info_root, "seedDC", json_string(convert_to_hex(dfe_state.seedDC).c_str()));
    json_object_set_new(dfe_info_root, "seedLF", json_string(convert_to_hex(dfe_state.seedLF).c_str()));
    json_object_set_new(dfe_info_root, "seedHF", json_string(convert_to_hex(dfe_state.seedHF).c_str()));
    json_object_set_new(dfe_info_root, "dfe_disable", json_integer(dfe_state.dfe_disable));
    json_object_set_new(dfe_info_root, "bw_tune_en", json_boolean(dfe_state.bw_tune_en));
    json_object_set_new(dfe_info_root, "tune_mode", json_integer(dfe_state.tune_mode));
    json_object_set_new(dfe_info_root, "dfeTAP1", json_string(convert_to_hex(dfe_state.dfeTAP1).c_str()));
    json_object_set_new(dfe_info_root, "dwell_bits", json_string(convert_to_hex(dfe_state.dwell_bits).c_str()));
    json_object_set_new(dfe_info_root, "error_threshold", json_string(convert_to_hex(dfe_state.error_threshold).c_str()));
    json_object_set_new(dfe_info_root, "dfeGAIN_min", json_string(convert_to_hex(dfe_state.dfeGAIN_min).c_str()));
    json_object_set_new(dfe_info_root, "dfeGAIN_max", json_string(convert_to_hex(dfe_state.dfeGAIN_max).c_str()));
    json_object_set_new(dfe_info_root, "state", json_string(convert_to_hex(dfe_state.state).c_str()));
    json_object_set_new(dfe_info_root, "status", json_string(convert_to_hex(dfe_state.status).c_str()));

    json_t* vos_array = json_array();
    for (size_t i = 0; i < 10; i++) {
        json_array_append_new(vos_array, json_string(convert_to_signed_hex(dfe_state.vos[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "vos", vos_array);

    json_t* vosMID_array = json_array();
    for (size_t i = 0; i < 10; i++) {
        json_array_append_new(vosMID_array, json_integer(dfe_state.vosMID[i]));
    }
    json_object_set_new(dfe_info_root, "vosMID", vosMID_array);

    json_t* dfeTAP_array = json_array();
    for (size_t i = 0; i < AVAGO_DFE_TAP_COUNT; i++) {
        json_array_append_new(dfeTAP_array, json_string(convert_to_hex(dfe_state.dfeTAP[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "dfeTAP", dfeTAP_array);

    json_t* dfeTAP_o_array = json_array();
    for (size_t i = 0; i < AVAGO_DFE_TAP_COUNT; i++) {
        json_array_append_new(dfeTAP_o_array, json_string(convert_to_hex(dfe_state.dfeTAP_o[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "dfeTAP_o", dfeTAP_o_array);

    json_t* dataLEV_array = json_array();
    for (size_t i = 0; i < 8; i++) {
        json_array_append_new(dataLEV_array, json_string(convert_to_hex(dfe_state.dataLEV[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "dataLEV", dataLEV_array);

    json_t* testLEV_array = json_array();
    for (size_t i = 0; i < 8; i++) {
        json_array_append_new(testLEV_array, json_string(convert_to_hex(dfe_state.testLEV[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "testLEV", testLEV_array);

    json_t* eyeHeights_array = json_array();
    for (size_t i = 0; i < 6; i++) {
        json_array_append_new(eyeHeights_array, json_string(convert_to_hex(dfe_state.eyeHeights[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "eyeHeights", eyeHeights_array);

    json_t* vernierDelay_array = json_array();
    for (size_t i = 0; i < 11; i++) {
        json_array_append_new(vernierDelay_array, json_string(convert_to_signed_hex(dfe_state.vernierDelay[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "vernierDelay", vernierDelay_array);

    json_t* dfe_tap_disable_array = json_array();
    for (size_t i = 0; i < AVAGO_DFE_TAP_COUNT + 1; i++) {
        json_array_append_new(dfe_tap_disable_array, json_boolean(dfe_state.dfe_tap_disable[i]));
    }
    json_object_set_new(dfe_info_root, "dfe_tap_disable", dfe_tap_disable_array);

    json_t* rxFFE_array = json_array();
    for (size_t i = 0; i < 7; i++) {
        json_array_append_new(rxFFE_array, json_string(convert_to_signed_hex(dfe_state.rxFFE[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "rxFFE", rxFFE_array);

    json_t* dfeTAP_offset_array = json_array();
    for (size_t i = 0; i < 8; i++) {
        json_array_append_new(dfeTAP_offset_array, json_string(convert_to_hex(dfe_state.dfeTAP_offset[i]).c_str()));
    }
    json_object_set_new(dfe_info_root, "dfeTAP_offset", dfeTAP_offset_array);

    json_object_set_new(out_root, "dfe_state_info", dfe_info_root);
}

void
avago_serdes_handler::add_serdes_soft_state(json_t* parent)
{
    // Soft state
    json_t* json_soft_state_root = json_object();
    json_object_set_new(json_soft_state_root, "enable_eid", json_boolean(m_enable_eid));
    json_object_set_new(json_soft_state_root, "dfe_eid", json_boolean(m_dfe_eid));
    json_object_set_new(json_soft_state_root, "loopback_mode", json_string(silicon_one::to_string(m_loopback_mode).c_str()));
    json_object_set_new(json_soft_state_root, "is_an_enabled", json_boolean(m_is_an_enabled));
    json_object_set_new(json_soft_state_root, "an_spec_cap", json_integer((int)m_an_spec_cap));
    json_object_set_new(json_soft_state_root, "an_fec_request", json_integer(m_an_fec_request));
    json_object_set_new(json_soft_state_root, "serdes_speed_gbps", json_integer(m_serdes_speed_gbps));
    json_object_set_new(json_soft_state_root, "tuning_mode", json_string(silicon_one::to_string(m_tuning_mode).c_str()));
    json_object_set_new(json_soft_state_root, "continuous_tuning_enabled", json_boolean(m_continuous_tuning_enabled));
    json_object_set_new(json_soft_state_root, "continuous_tuning_activated", json_boolean(m_continuous_tuning_activated));
    json_object_set_new(json_soft_state_root, "bad_an_base_page_print", json_boolean(m_bad_an_base_page_print));

    json_object_set_new(parent, "serdes_soft_state", json_soft_state_root);
}

void
avago_serdes_handler::add_serdes_global_tune_param(json_t* out_root, uint32_t addr)
{
    Aapl_t* aapl_handler = m_aapl_handler;
    if (aapl_handler == nullptr) {
        return;
    }

    json_t* global_tune_param = json_object();
    Avago_serdes_global_tune_params_t params{};

    // Read Avago registers to for Avago_serdes_global_tune_params_t structure.
    avago_serdes_global_tune_params_read(aapl_handler, addr, &params);

    json_object_set_new(global_tune_param, "ctle_dc_max_min", json_string(convert_to_hex(params.ctle_dc_max_min).c_str()));
    json_object_set_new(global_tune_param, "ctle_fixed", json_string(convert_to_hex(params.ctle_fixed).c_str()));
    json_object_set_new(global_tune_param, "ctle_lfhf_max_min", json_string(convert_to_hex(params.ctle_lfhf_max_min).c_str()));
    json_object_set_new(global_tune_param, "dcr_pcal_dwell_1ex", json_string(convert_to_hex(params.dcr_pcal_dwell_1ex).c_str()));
    json_object_set_new(global_tune_param, "delta_cal_fail", json_string(convert_to_hex(params.delta_cal_fail).c_str()));
    json_object_set_new(global_tune_param, "dfe_fixed", json_string(convert_to_hex(params.dfe_fixed).c_str()));
    json_object_set_new(
        global_tune_param, "disable_one_shot_pcal", json_string(convert_to_hex(params.disable_one_shot_pcal).c_str()));
    json_object_set_new(global_tune_param, "error_threshold", json_string(convert_to_hex(params.error_threshold).c_str()));
    json_object_set_new(global_tune_param, "eye_oversample", json_string(convert_to_hex(params.eye_oversample).c_str()));
    json_object_set_new(global_tune_param, "gaintap2_max_min", json_string(convert_to_hex(params.gaintap2_max_min).c_str()));
    json_object_set_new(global_tune_param, "gaintap_max_min", json_string(convert_to_hex(params.gaintap_max_min).c_str()));
    json_object_set_new(global_tune_param, "gradient_options", json_string(convert_to_hex(params.gradient_options).c_str()));
    json_object_set_new(global_tune_param, "ical_effort", json_string(convert_to_hex(params.ical_effort).c_str()));
    json_object_set_new(
        global_tune_param, "iq_cal_interleave_disable", json_string(convert_to_hex(params.iq_cal_interleave_disable).c_str()));
    json_object_set_new(global_tune_param, "latch_fail", json_string(convert_to_hex(params.latch_fail).c_str()));
    json_object_set_new(global_tune_param, "lms_dwell_1ex", json_string(convert_to_hex(params.lms_dwell_1ex).c_str()));
    json_object_set_new(global_tune_param, "lms_pcal_dwell_1ex", json_string(convert_to_hex(params.lms_pcal_dwell_1ex).c_str()));
    json_object_set_new(global_tune_param, "nrz_ctle_dwell_1ex", json_string(convert_to_hex(params.nrz_ctle_dwell_1ex).c_str()));
    json_object_set_new(
        global_tune_param, "nrz_ctle_lf_dwell_shift", json_string(convert_to_hex(params.nrz_ctle_lf_dwell_shift).c_str()));
    json_object_set_new(global_tune_param, "pam4_ctle_dwell_1ex", json_string(convert_to_hex(params.pam4_ctle_dwell_1ex).c_str()));
    json_object_set_new(global_tune_param, "pam4_dvos_dwell_1ex", json_string(convert_to_hex(params.pam4_dvos_dwell_1ex).c_str()));
    json_object_set_new(
        global_tune_param, "pam4_dvos_pcal_dwell_1ex", json_string(convert_to_hex(params.pam4_dvos_pcal_dwell_1ex).c_str()));
    json_object_set_new(global_tune_param, "pCal_delay", json_string(convert_to_hex(params.pCal_delay).c_str()));
    json_object_set_new(global_tune_param, "pCal_loops", json_string(convert_to_hex(params.pCal_loops).c_str()));
    json_object_set_new(global_tune_param, "prbs_tune_mode", json_string(convert_to_hex(params.prbs_tune_mode).c_str()));
    json_object_set_new(global_tune_param, "rxffe_fixed", json_string(convert_to_hex(params.rxffe_fixed).c_str()));
    json_object_set_new(
        global_tune_param, "use_rx_clock_cal_values", json_string(convert_to_hex(params.use_rx_clock_cal_values).c_str()));
    json_object_set_new(global_tune_param, "vernier_fixed", json_string(convert_to_hex(params.vernier_fixed).c_str()));

    json_object_set_new(out_root, "global_tune_params", global_tune_param);
}

static void
reg_dump_log_fn(Aapl_t* aapl, Aapl_log_type_t log_sel, const char* buf, size_t new_item_length)
{
    // store buffer into log_buffer
    std::shared_ptr<void> get_ptr
        = silicon_one::aapl_bind_get_wrapper(aapl, silicon_one::client_data_label::CLIENT_DATA_LOG_BUFFER);
    std::vector<std::string>* log_buffer_vec = static_pointer_cast<std::vector<std::string> >(get_ptr).get();
    log_buffer_vec->push_back(buf);
}

void
avago_serdes_handler::add_serdes_reg_dump(json_t* out_root, uint32_t addr)
{
    if (m_aapl_handler == nullptr) {
        return;
    }

    Avago_diag_config_t* config = avago_diag_config_construct(m_aapl_handler);
    config->binary = true;
    config->columns = true;
    config->serdes_init_only = false;
    config->state_dump = false;
    config->sbus_dump = true;
    config->dma_dump = true;
    config->dmem_dump = false;
    int device_build_number;
    m_device->get_int_property(la_device_property_e::SERDES_FW_BUILD, device_build_number);
    // ICAL capture if serdes build number is x2081
    if (device_build_number == SERDES_ICAL_DEBUG_BUILD) {
        config->imem_dump = true;
    } else {
        config->imem_dump = false;
    }
    config->cycles = 20;
    config->refclk = 156250000;

    // set client_data ptr to aapl_logging_vector
    silicon_one::aapl_client_data_struct<la_aapl_user>* get_client_data
        = static_cast<silicon_one::aapl_client_data_struct<la_aapl_user>*>(aapl_bind_get(m_aapl_handler));
    get_client_data->log_buffer.reset(new std::vector<std::string>());

    aapl_register_logging_fn(m_aapl_handler, &reg_dump_log_fn, 0, 0);
    int res = avago_diag(m_aapl_handler, addr, config);

    // storing it in local vector for easy parsing
    aapl_logging_vector = (get_client_data->log_buffer).get()[0];

    // parse through aapl_logging_vector to put into json format
    if (res == 0) {
        int size = aapl_logging_vector.size();
        json_t* log_array = json_array();
        for (int i = 0; i < size; i++) {
            std::string temps = aapl_logging_vector[i];
            // this skips saving the unnecessary label that is printed out each time the diag function is called.
            std::string skip = "AAPL diag started.";
            std::string::size_type cur = temps.find(skip);
            if (cur != std::string::npos) {
                i += 8;
                continue;
            }
            // removes new line char
            temps.erase(std::remove(temps.begin(), temps.end(), '\n'), temps.end());
            // removes beginning INFO: label
            std::string inf = "INFO: ";
            cur = temps.find(inf);
            if (cur != std::string::npos) {
                temps.erase(cur, inf.length());
            }
            json_array_append_new(log_array, json_string(temps.c_str()));
        }
        json_object_set_new(out_root, "reg_dump", log_array);
    }

    // clean-up
    aapl_logging_vector.clear();
    avago_diag_config_destruct(m_aapl_handler, config);
}

void
avago_serdes_handler::add_serdes_eye_capture(json_t* out_root, uint32_t addr)
{
    if (m_aapl_handler == nullptr) {
        return;
    }

    Avago_serdes_eye_config_t* eye_config = avago_serdes_eye_config_construct(m_aapl_handler);
    Avago_serdes_eye_data_t* eye_data = avago_serdes_eye_data_construct(m_aapl_handler);
    int32_t rc;
    char* eye_plot = NULL;

    /* Configure a fast, low resolution capture: */
    eye_config->ec_no_sbm = true;
    eye_config->ec_x_resolution = 128;   /* Low x resolution */
    eye_config->ec_x_auto_scale = FALSE; /* Don't auto-scale x resolution */
    eye_config->ec_y_step_size = 2;      /* Low y resolution, auto-scale */

    // get eye data
    rc = avago_serdes_eye_get(m_aapl_handler, addr, eye_config, eye_data);

    // if valid data, format data into a plot format
    if (rc == 0) {
        eye_plot = avago_serdes_eye_plot_format(eye_data);
    }

    if (eye_plot != NULL) {
        json_t* plot_array = json_array();
        // parse plot and format into array format deliminated by new-line
        // using strtok_r because strtok is not thread-safe.
        char* token = NULL;
        char* saveptr;
        token = strtok_r(eye_plot, "\n", &saveptr);
        while (token != NULL) {
            json_array_append_new(plot_array, json_string(token));
            token = strtok_r(NULL, "\n", &saveptr);
        }

        // add data to JSON tree
        json_t* eye_capture_root = json_object();
        json_object_set_new(eye_capture_root, "plot", plot_array);
        json_object_set_new(out_root, "eye_capture", eye_capture_root);
    }

    // clean-up
    free(eye_plot);
    avago_serdes_eye_config_destruct(m_aapl_handler, eye_config);
    avago_serdes_eye_data_destruct(m_aapl_handler, eye_data);
}

void
avago_serdes_handler::add_anlt_debug_snapshots(json_t* out_root)
{
    if (m_anlt_debug_snapshot_queue.size() == 0) {
        // nothing to add
        return;
    }

    json_t* anlt_snapshots_root = json_object();

    // get pointer to first most recent entry in queue
    auto snapshot_iter = m_anlt_debug_snapshot_queue.begin();

    // iterate through all of the snapshots in the queue
    la_int_t snapshot_idx = 0;
    while (snapshot_iter != m_anlt_debug_snapshot_queue.end()) {
        json_t* snapshot_root = json_object();
        anlt_debug_snapshot& anlt_snapshot = *snapshot_iter++;

        json_object_set_new(snapshot_root, "cause", json_string(anlt_snapshot.cause));
        json_object_set_new(snapshot_root, "timestamp", json_string(anlt_snapshot.timestamp));
        switch (anlt_snapshot.error_type) {
        case anlt_err_type_e::AN_BASE_PAGE_ERROR: {
            an_page_data_t& base_page = anlt_snapshot.base_page_word;
            json_t* word_array = json_array();

            for (size_t i = 0; i < 3; i++) {
                std::string hex_val = convert_to_hex(base_page.word[i]);
                json_array_append_new(word_array, json_string(hex_val.c_str()));
            }

            json_object_set_new(snapshot_root, "base_page", word_array);
            break;
        }
        case anlt_err_type_e::AN_NEXT_PAGE_ERROR: {
            json_t* snapshot_array = json_array();
            std::vector<an_next_page_debug>& next_page_vec = anlt_snapshot.next_page_vec;
            for (auto it : next_page_vec) {
                json_t* next_page_root = json_object();
                an_next_page_debug& next_page_debug = it;
                an_page_data_t& base_page = next_page_debug.base_page;
                an_page_data_t& next_page = next_page_debug.next_page;
                la_uint_t& oui_code = next_page_debug.oui_code;
                la_uint_t& message_code = next_page_debug.message_code;

                json_t* base_page_array = json_array();
                json_t* next_page_array = json_array();

                // populate page data for base_page and next_page in hex format
                for (size_t i = 0; i < 3; i++) {
                    std::string base_page_hex = convert_to_hex(base_page.word[i]);
                    json_array_append_new(base_page_array, json_string(base_page_hex.c_str()));

                    std::string next_page_hex = convert_to_hex(next_page.word[i]);
                    json_array_append_new(next_page_array, json_string(next_page_hex.c_str()));
                }

                std::string oui_hex = convert_to_hex(oui_code);
                std::string message_hex = convert_to_hex(message_code);

                json_object_set_new(next_page_root, "base_page", base_page_array);
                json_object_set_new(next_page_root, "next_page", next_page_array);
                json_object_set_new(next_page_root, "oui_code", json_string(oui_hex.c_str()));
                json_object_set_new(next_page_root, "message_code", json_string(message_hex.c_str()));

                json_array_append_new(snapshot_array, next_page_root);
            }

            json_object_set_new(snapshot_root, "inbound_pages", snapshot_array);
            break;
        }
        case anlt_err_type_e::AN_HCD_NOT_SUPPORTED: {
            std::string hex_val = convert_to_hex(anlt_snapshot.an_hcd);
            json_object_set_new(snapshot_root, "hcd", json_string(hex_val.c_str()));
            break;
        }
        case anlt_err_type_e::LT_FAILED: {
            std::string o_core_hex = convert_to_hex(anlt_snapshot.o_core);
            std::string msb_core_hex = convert_to_hex(anlt_snapshot.msb_core);

            json_t* link_training_tune_time_array = json_array();
            for (size_t i = 0; i < m_serdes_count; i++) {
                json_array_append_new(link_training_tune_time_array, json_real(anlt_snapshot.link_training_tune_time[i]));
            }

            json_object_set_new(snapshot_root, "o_core", json_string(o_core_hex.c_str()));
            json_object_set_new(snapshot_root, "msb_core", json_string(msb_core_hex.c_str()));
            json_object_set_new(snapshot_root, "link_training_tune_time_ms", link_training_tune_time_array);

            break;
        }
        }

        std::string snapshot_tag = "snapshot_" + std::to_string(snapshot_idx);
        snapshot_idx += 1;
        json_object_set_new(anlt_snapshots_root, snapshot_tag.c_str(), snapshot_root);
    }
    json_object_set_new(out_root, "anlt_snapshots", anlt_snapshots_root);
}

la_status
avago_serdes_handler::save_state(la_mac_port::port_debug_info_e info_type, json_t* out_root)
{
    if (info_type > la_mac_port::port_debug_info_e::LAST) {
        log_err(SERDES, "Invalid debug option.\n");
        return LA_STATUS_EINVAL;
    }

    // add SERDES soft state if user requests it
    if (info_type == la_mac_port::port_debug_info_e::SERDES_CONFIG || info_type == la_mac_port::port_debug_info_e::ALL
        || info_type == la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG) {
        add_serdes_soft_state(out_root);
    }

    if (m_device->is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    // add captured SERDES snapshots if user activated device property
    add_serdes_debug_snapshots(out_root);
    add_anlt_debug_snapshots(out_root);

    la_mac_port::port_debug_info_e info_type_last;
    la_mac_port::port_debug_info_e info_type_first;
    // Provide support to save all debug information, or only 1 at a time.
    if (info_type == la_mac_port::port_debug_info_e::ALL || info_type == la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG) {
        info_type_last = info_type;
        info_type_first = la_mac_port::port_debug_info_e::FIRST;
    } else {
        info_type_last = info_type;
        info_type_first = info_type;
    }

    json_t* rx_info_root = json_object();
    json_t* tx_info_root = json_object();

    for (size_t serdes = 0; serdes < m_serdes_count; serdes++) {
        json_t* rx_serdes_root = json_object();
        json_t* tx_serdes_root = json_object();
        uint32_t rx_addr, tx_addr;
        la_int_t rx_fw_rev, tx_fw_rev;

        // get Avago serdes addr (both values have a +1 modifier)
        get_serdes_addr(serdes, la_serdes_direction_e::RX, rx_addr);
        get_serdes_addr(serdes, la_serdes_direction_e::TX, tx_addr);

        // add physical serdes address
        json_object_set_new(rx_serdes_root, "serdes", json_integer(rx_addr - 1));
        json_object_set_new(tx_serdes_root, "serdes", json_integer(tx_addr - 1));

        for (size_t i = (size_t)info_type_first; i <= (size_t)info_type_last; i++) {
            info_type = (la_mac_port::port_debug_info_e)i;
            switch (info_type) {
            case la_mac_port::port_debug_info_e::SERDES_CONFIG:
                // get Avago firmware revision
                rx_fw_rev = aapl_get_firmware_rev(m_aapl_handler, rx_addr);
                tx_fw_rev = aapl_get_firmware_rev(m_aapl_handler, tx_addr);

                json_object_set_new(rx_serdes_root, "fw_revision", json_string(convert_to_hex(rx_fw_rev).c_str()));
                json_object_set_new(tx_serdes_root, "fw_revision", json_string(convert_to_hex(tx_fw_rev).c_str()));

                add_serdes_rx_param(rx_serdes_root, rx_addr);
                add_serdes_tx_param(tx_serdes_root, tx_addr);
                break;
            case la_mac_port::port_debug_info_e::SERDES_STATUS:
                add_serdes_global_tune_param(rx_serdes_root, rx_addr);

                add_serdes_ctle_info(rx_serdes_root, rx_addr);

                add_serdes_dfe_state_info(rx_serdes_root, rx_addr);
                break;
            case la_mac_port::port_debug_info_e::SERDES_EYE_CAPTURE:
                add_serdes_eye_capture(rx_serdes_root, rx_addr);
                break;
            case la_mac_port::port_debug_info_e::SERDES_REG_DUMP:
                add_serdes_reg_dump(rx_serdes_root, rx_addr);
                break;
            case la_mac_port::port_debug_info_e::MAC_STATUS:
            case la_mac_port::port_debug_info_e::ALL:
            case la_mac_port::port_debug_info_e::SERDES_EXTENDED_DEBUG:
                // nothing to do
                break;
            default:
                log_debug(SERDES, "Debug type %s not supported.\n", to_string(info_type).c_str());
                break;
            }
        }

        std::string str = "index_" + std::to_string(int(serdes));

        // check if no objects don't contain data to avoid adding empty JSON objects
        bool destroy_rx = json_object_size(rx_serdes_root) <= 1;
        bool destroy_tx = json_object_size(tx_serdes_root) <= 1;
        const char* rx_serdes_key = destroy_rx ? nullptr : str.c_str();
        const char* tx_serdes_key = destroy_tx ? nullptr : str.c_str();

        json_object_set_new(rx_info_root, rx_serdes_key, rx_serdes_root);
        json_object_set_new(tx_info_root, tx_serdes_key, tx_serdes_root);
    }

    // check if no objects don't contain data to avoid adding empty JSON objects
    bool destroy_rx = json_object_size(rx_info_root) == 0;
    bool destroy_tx = json_object_size(tx_info_root) == 0;
    const char* rx_key = destroy_rx ? nullptr : "rx_info";
    const char* tx_key = destroy_tx ? nullptr : "tx_info";

    json_object_set_new(out_root, rx_key, rx_info_root);
    json_object_set_new(out_root, tx_key, tx_info_root);

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_handler::set_serdes_signal_control(la_uint_t serdes_idx,
                                                la_serdes_direction_e direction,
                                                la_mac_port::serdes_ctrl_e ctrl_type)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
avago_serdes_handler::reenable_tx()
{
    return LA_STATUS_SUCCESS;
}

std::string
avago_serdes_handler::convert_to_hex(la_uint_t val)
{
    std::string hex_string = "0x" + to_hex_string(val);
    return hex_string;
}

std::string
avago_serdes_handler::convert_to_signed_hex(la_int_t val)
{
    std::stringstream hex_string_stream;
    hex_string_stream << ((val < 0) ? "-0x" : "0x") << to_hex_string(abs(val));
    return hex_string_stream.str();
}

la_status
avago_serdes_handler::refresh_tx()
{
    la_status stat;
    stat = init(true, false);
    return_on_error(stat);

    stat = enable_tx(true);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}
}
