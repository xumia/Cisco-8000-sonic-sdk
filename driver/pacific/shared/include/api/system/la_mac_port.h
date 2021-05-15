// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_MAC_PORT_H__
#define __LA_MAC_PORT_H__

/// @file
/// @brief Leaba MAC Port API-s.
///
/// Defines API-s for managing MAC port.
///

#include "api/types/la_common_types.h"
#include "api/types/la_counter_or_meter_set.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"

#include <chrono>
#include <vector>

/// @addtogroup PORT_MAC
/// @{

namespace silicon_one
{

class la_rx_cgm_sq_profile;

/// @brief Over subscription traffic class.
typedef la_uint_t la_over_subscription_tc_t;

/// @brief Initial traffic class.
typedef la_uint_t la_initial_tc_t;

/// @brief A MAC port is defined above one or more network interface SerDes elements.
///
/// It is used to define MAC level attributes like speed (10GE/40GE/100GE/400GE/Auto)
/// flow control (Link level or PFC), Forward Error Correction etc.
///
class la_mac_port : public la_object
{
public:
    enum {
        OSTC_TRAFFIC_CLASSES = 4,   ///< Number of over subscription traffic classes.
        RESERVED_ETHERTYPE = 0,     ///< Ethertype for unknown protocol/TPID.
        MAX_RS_FEC_CW_SYMBOLS = 16, ///< Maximum number of RS-FEC code words symbol errors.
        MAX_RS_FEC_BURST = 7,       ///< Maximum number of consecutive RS-FEC symbols of the same frame.
    };

    /// @brief MAC port type.
    enum class port_type_e {
        NETWORK, ///< Network-facing MAC port.
        FABRIC   ///< Carrier fabric-facing MAC port.
    };

    /// @brief MAC port supported speed.
    enum class port_speed_e {
        E_MGIG = 0, ///< Port speed set to multigigabit ethernet (mGIG).
        E_10G,      ///< Port speed set to 10G ethernet.
        E_20G,      ///< Port speed set to 20G ethernet.
        E_25G,      ///< Port speed set to 25G ethernet.
        E_40G,      ///< Port speed set to 40G ethernet.
        E_50G,      ///< Port speed set to 50G ethernet.
        E_100G,     ///< Port speed set to 100G ethernet.
        E_200G,     ///< Port speed set to 200G ethernet.
        E_400G,     ///< Port speed set to 400G ethernet.
        E_800G,     ///< Port speed set to 800G ethernet.
        E_1200G,    ///< Port speed set to 1200G ethernet
        E_1600G,    ///< Port speed set to 1600G ethernet
        LAST = E_1600G
    };

    /// @brief MAC Forward Error Correction modes.
    enum class fec_mode_e {
        NONE = 0,  ///< No FEC on the MAC port.
        KR,        ///< KR-FEC (firecode, clause 74).
        RS_KR4,    ///< RS-FEC KR4 (clause 91, 528/514).
        RS_KP4,    ///< RS-FEC KP4 (clause 91, 544/514).
        RS_KP4_FI, ///< Proprietary mode of RS-FEC KP4 with Frame Interleaving.
        LAST = RS_KP4_FI
    };

    /// @brief MAC Forward Error Correction bypass modes.
    ///
    /// Relevant if FEC mode is either RS_KR4 or RS_KP4.
    enum class fec_bypass_e {
        NONE = 0,   ///< FEC with no bypass (default).
        CORRECTION, ///< FEC will bypass correction, do indication.
        INDICATION, ///< FEC will bypass indication, do correction.
        ALL,        ///< FEC will bypass correction and indication.
    };

    /// @brief MAC port supported Flow control modes.
    enum class fc_mode_e {
        NONE = 0, ///< No Flow control on the MAC port.
        PAUSE,    ///< PAUSE link level flow control.
        PFC,      ///< Priority Flow Control.
        CFFC,     ///< Proprietary carrier-fabric flow conrol.
        LAST = CFFC
    };

    /// @brief MAC port supported Flow direction modes.
    enum class fc_direction_e {
        RX = 0, ///< Receive direction.
        TX,     ///< Transmit direction.
        BIDIR,  ///< Both receive and transmit direction.
    };

    /// @brief Key source used for channel selection in channelized system port.
    enum class channelization_key_source_e {
        NONE = 0,   ///< Port is not channelized.
        OUTER_VLAN, ///< Port channelization key is Outer VLAN ID.
        CUSTOM_1,   ///< Port channelization key is Custom Key 1.
        CUSTOM_2,   ///< Port channelization key is Custom Key 2.
        CUSTOM_3,   ///< Port channelization key is Custom Key 3.
    };

    /// @brief EtherType.
    enum class tc_protocol_e {
        ETHERNET, ///< ETHERNET
        IPV4,     ///< IPv4 protocol
        IPV6,     ///< IPv6 protocol
        MPLS,     ///< MPLS
        LAST = MPLS
    };

    /// @brief Serdes tuning mode.
    enum class serdes_tuning_mode_e {
        ICAL_ONLY, ///< Initial calibration; coarse tuning without PCAL.
        ICAL,      ///< Initial calibration; coarse+file tuning.
        PCAL,      ///< One time periodic calibration; fine tuning, no LF, HF adjustments.
        LAST = PCAL
    };

    /// @brief MAC MLP modes.
    enum class mlp_mode_e {
        NONE = 0,   ///< MAC port not part of MLP.
        MLP_MASTER, ///< MAC port part of MLP and it's first mac pool.
        MLP_SLAVE,  ///< MAC port part of MLP and it's not first mac pool.
        LAST = MLP_SLAVE
    };

    /// @brief MAC fault type.
    enum class fault_state_e {
        NO_FAULT = 0, ///< No link fault.
        LOCAL_FAULT,  ///< Link fault on the device.
        REMOTE_FAULT, ///< Fault on the remote link.
        LAST = REMOTE_FAULT
    };

    /// @brief MAC status information.
    struct mac_status {
        bool block_lock[la_mac_port_max_lanes_e::PCS]; ///< PCS lane's block lock status
        bool am_lock[la_mac_port_max_lanes_e::PCS];    ///< PCS lane's align marker lock status.
        bool link_state;                               ///< True if MAC link is up, false otherwise.
        fault_state_e link_fault_status;               ///< 0-No fault. 1-local fault. 2-remote fault.
        bool pcs_status;          ///< True if not high BER and block lock on single lane or align marker lock on multi-lane.
        bool high_ber;            ///< True if Bit-Error-Rate > 10^-4
        bool degraded_ser;        ///< RS-FEC degraded SER.
        bool remote_degraded_ser; ///< Remote RS-FEC degraded SER.
        bool kr_fec_lock[la_mac_port_max_lanes_e::KR]; ///< KR FEC lock status.
    };

    /// @brief SerDes status information.
    struct serdes_status {
        bool tx_ready;    ///< TX ready.
        bool rx_ready;    ///< RX ready.
        bool signal_ok;   ///< Signal OK.
        bool spico_ready; ///< Firmware has been downloaded and Spico is ready.
    };

    /// @brief MAC PCS lanes mapping to de-skew FIFOs.
    struct mac_pcs_lane_mapping {
        size_t lane_map[la_mac_port_max_lanes_e::PCS]; ///< PCS lane index mapped to FIFO at array's location.
    };

    /// @brief MAC PMA test mode BER.
    struct mac_pma_ber {
        float lane_ber[la_mac_port_max_lanes_e::PCS]; ///< PMA lane BER.
    };

    /// @brief SerDes test mode BER, bit count, bit error count and PRBS lock status.
    struct serdes_prbs_ber {
        float lane_ber[la_mac_port_max_lanes_e::SERDES];     ///< SerDes lane BER.
        la_uint64_t count[la_mac_port_max_lanes_e::SERDES];  ///< SerDes lane bits.
        la_uint64_t errors[la_mac_port_max_lanes_e::SERDES]; ///< SerDes lane error bits.
        bool prbs_lock[la_mac_port_max_lanes_e::SERDES];     ///< SerDes lane PRBS lock status.
    };

    /// @brief MAC port MIB counters.
    struct mib_counters {
        la_uint64_t tx_frames_ok;           ///< TX legal frames counter.
        la_uint64_t tx_bytes_ok;            ///< TX legal bytes counter.
        la_uint64_t tx_64b_frames;          ///< TX legal frames with 64 bytes.
        la_uint64_t tx_65to127b_frames;     ///< TX legal frames with 65-127 bytes.
        la_uint64_t tx_128to255b_frames;    ///< TX legal frames with 128-255 bytes.
        la_uint64_t tx_256to511b_frames;    ///< TX legal frames with 256-511 bytes.
        la_uint64_t tx_512to1023b_frames;   ///< TX legal frames with 512-1023 bytes.
        la_uint64_t tx_1024to1518b_frames;  ///< TX legal frames with 1024-1518 bytes.
        la_uint64_t tx_1519to2500b_frames;  ///< TX legal frames with 1519-2500 bytes.
        la_uint64_t tx_2501to9000b_frames;  ///< TX legal frames with 2501-9000 bytes.
        la_uint64_t tx_crc_errors;          ///< TX frames with CRC error.
        la_uint64_t tx_mac_missing_eop_err; ///< TX internal error: packets missing the end-of-packet.
        la_uint64_t tx_mac_underrun_err;    ///< TX internal error: under run packets.
        la_uint64_t tx_mac_fc_frames_ok;    ///< TX legal flow control packets.
        la_uint64_t tx_oob_mac_frames_ok;   ///< TX out-of-band packets transmitted.
        la_uint64_t tx_oob_mac_crc_err;     ///< TX internal error: out-of-band packets with CRC error.
        la_uint64_t rx_frames_ok;           ///< RX legal frames.
        la_uint64_t rx_bytes_ok;            ///< RX legal bytes.
        la_uint64_t rx_64b_frames;          ///< RX legal frames with 64 bytes.
        la_uint64_t rx_65to127b_frames;     ///< RX legal frames with 65-127 bytes.
        la_uint64_t rx_128to255b_frames;    ///< RX legal frames with 128-255 bytes.
        la_uint64_t rx_256to511b_frames;    ///< RX legal frames with 256-511 bytes.
        la_uint64_t rx_512to1023b_frames;   ///< RX legal frames with 511-1023 bytes.
        la_uint64_t rx_1024to1518b_frames;  ///< RX legal frames with 1024-1518 bytes.
        la_uint64_t rx_1519to2500b_frames;  ///< RX legal frames with 1519-2500 bytes.
        la_uint64_t rx_2501to9000b_frames;  ///< RX legal frames with 2501-9000 bytes.
        la_uint64_t rx_mac_invert;          ///< RX received frames with inverted CRC.
        la_uint64_t rx_crc_errors;          ///< RX packets received with CRC errors.
        la_uint64_t rx_oversize_err;        ///< RX packet received larger from max packet size.
        la_uint64_t rx_undersize_err;       ///< RX packet received smaller from min packet size.
        la_uint64_t rx_mac_code_err;        ///< RX packets with code error.
        la_uint64_t rx_mac_fc_frames_ok;    ///< RX legal flow control packets.
        la_uint64_t rx_oob_mac_frames_ok;   ///< RX out-of-band packets received.
        la_uint64_t rx_oob_mac_invert_crc;  ///< RX packets received with inverted CRC.
        la_uint64_t rx_oob_mac_crc_err;     ///< RX out-of-band packets with CRC error.
        la_uint64_t rx_oob_mac_code_err;    ///< RX out-of-band packets with code error.
    };

    /// @brief MAC port RS-FEC debug counters.
    struct rs_fec_debug_counters {
        la_uint64_t codeword[MAX_RS_FEC_CW_SYMBOLS]; ///< Number of RS-FEC code words with index symbol errors.
        la_uint64_t codeword_uncorrectable;          ///< Number of RS-FEC code words with 16 or more symbol errors.
        la_uint64_t symbol_burst[MAX_RS_FEC_BURST];  ///< Number of bursts of index consecutive RS-FEC symbols of the same frame.
                                                     ///< Note: Values in index 0 and 1 are invalid and always 0.
        double extrapolated_ber; ///< BER extrapolated from codeword counters. -1 when BER unavailable. 0 for BER lower than 1e-16.
        double extrapolated_flr; ///< FLR extrapolated from codeword counters. -1 when FLR unavaliable.
        double
            flr_r; ///< FLR statistics R value. 1 when the extrapolated flr is accurate, 0 when the extrapolated flr is inaccurate.
    };

    /// @brief MAC port RS-FEC symbol error counters.
    struct rs_fec_sym_err_counters {
        la_uint64_t lane_errors[la_mac_port_max_lanes_e::RS_FEC]; ///< Array of RS-FEC symbol error counter per FEC lane.
    };

    struct output_queue_counters {
        la_uint64_t drop_bytes;
        la_uint64_t enqueue_bytes;
        la_uint64_t drop_packets;
        la_uint64_t enqueue_packets;
    };

    /// @brief MAC port state.
    enum class state_e : uint8_t {
        PRE_INIT = 0,     ///< Initial state.
        INACTIVE,         ///< All configured but not activated.
        PCAL_STOP,        ///< Wait for SerDes Rx periodec tune to be stopped.
        AN_BASE_PAGE,     ///< Wait for auto-negotiation base page to be received.
        AN_NEXT_PAGE,     ///< Wait for auto-negotiation next page to be reveived.
        AN_POLL,          ///< AN started, wait for AN_GOOD.
        LINK_TRAINING,    ///< PMD Link Training started. wait for PMD Link Training done/failure.
        AN_COMPLETE,      ///< Autonegotiation HCD has been asserted, wait for autonegotiation completion.
        ACTIVE,           ///< Activated.
        WAITING_FOR_PEER, ///< Waiting for peer.
        TUNING,           ///< Peer identified, tuning.
        TUNED,            ///< iCal complete - wait for PCS lock.
        PCS_LOCK,         ///< PCS lock is complete.
        PCS_STABLE,       ///< PCS lock is stable, wait for link UP.
        LINK_UP,          ///< Link is UP.
        LAST = LINK_UP
    };

    /// @brief MAC port loopback modes.
    enum class loopback_mode_e {
        NONE = 0,      ///< Loopback disabled on the MAC port.
        MII_CORE_CLK,  ///< Loopback at MAC port's MII level, using core rate.
        MII_SRDS_CLK,  ///< Loopback at MAC port's MII level, using SerDes rate.
        INFO_MAC_CLK,  ///< Loopback at MAC port's INFO level, using MAC rate.
        INFO_SRDS_CLK, ///< Loopback at MAC port's INFO level, using calculated SerDes rate.
        PMA_CORE_CLK,  ///< Loopback at MAC port's PMA level, using core rate.
        PMA_SRDS_CLK,  ///< Loopback at MAC port's PMA level, using SerDes rate.
        SERDES,        ///< Loopback at SerDes level.
        REMOTE_PMA,    ///< Remote PMA Loopback - what ever received, sent back in PMA using the extracted rate.
        REMOTE_SERDES, ///< Remote SERDES Loopback - what ever received, sent back in SerDes using the extracted rate.
        LAST = REMOTE_SERDES
    };

    /// @brief PCS test modes.
    enum class pcs_test_mode_e {
        NONE = 0,     ///< MAC port working normally, no test pattern.
        SCRAMBLED,    ///< Scrambled-idle test pattern. Part of the 100GE / 40GE standard(82.2.10).
        RANDOM,       ///< Pseudo random mode using local fault data pattern, part of the 10GE standard (49.2.8).
        RANDOM_ZEROS, ///< Pseudo random mode using zeros data pattern, part of the 10GE standard (49.2.8).
        PRBS31,       ///< PRBS31 (proprietary mode, sends 64b of PRBS with a data sync header).
        PRBS9,        ///< PRBS9 (proprietary mode, sends 64b of PRBS with a data sync header).
        LAST = PRBS9
    };

    /// @brief PMA test modes.
    enum class pma_test_mode_e {
        NONE = 0,    ///< MAC port working normally, no test pattern.
        RANDOM,      ///< Pseudo random mode using local fault data pattern, part of the 10GE standard (49.2.8).
        PRBS31,      ///< PRBS31 (proprietary mode, sends 64b of PRBS with a data sync header).
        PRBS9,       ///< PRBS9 (proprietary mode, sends 64b of PRBS with a data sync header).
        PRBS15,      ///< PRBS15 (proprietary mode, sends 64b of PRBS with a data sync header).
        PRBS13,      ///< PRBS13 (proprietary mode, sends 64b of PRBS with a data sync header).
        JP03B,       ///< Use TX pattern configuration, with pattern made of 15 consecutive repetitions of 0xB.
        SSPRQ,       ///< SSPRQ (proprietary mode, sends SSPRQ pattern).
        SQUARE_WAVE, ///< Square wave (quaternary).
        LAST = SQUARE_WAVE
    };

    enum class serdes_test_mode_e {
        NONE = 0, ///< SerDes working normally, no test pattern.
        PRBS7,    ///< PRBS7  SerDes lane test pattern.
        PRBS9_4,  ///< PRBS9_4  SerDes lane test pattern, x^9 + x^4 + 1.
        PRBS9,    ///< PRBS9  SerDes lane test pattern, x^9 + x^5 + 1.
        PRBS11,   ///< PRBS11 SerDes lane test pattern.
        PRBS13,   ///< PRBS13 SerDes lane test pattern.
        PRBS15,   ///< PRBS15 SerDes lane test pattern.
        PRBS16,   ///< PRBS15 SerDes lane test pattern.
        PRBS23,   ///< PRBS23 SerDes lane test pattern.
        PRBS31,   ///< PRBS31 SerDes lane test pattern.
        PRBS58,   ///< PRBS58 SerDes lane test pattern.
        JP03B,    ///< JP083B SerDes lane test pattern, IEEE 802.3bs Clause 120.5.10.2.2.
        PRBS_LIN, ///< PRBS_LIN SerDes lane test pattern, IEEE 802.3bs Clause 120.5.10.2.4.
        PRBS_CJT, ///< PRBS_CJT SerDes lane test pattern, OIF_CEI-3.1 Sections 2.1.1.1 and 2.5.1.1.
        SSPRQ,    ///< SSPRQ SerDes lane test pattern, IEEE 802.3bs Clause 120.5.11.2.3.
        LAST = SSPRQ
    };

    /// @brief Ports various counters.
    enum class counter_e {
        PCS_TEST_ERROR = 0, ///< PCS test mode error counter.
        PCS_BLOCK_ERROR,    ///< PCS errored block counter.
        PCS_BER,            ///< PCS synchronization header BER counter.
        FEC_CORRECTABLE,    ///< FEC correctable codeword counter.
        FEC_UNCORRECTABLE,  ///< FEC un-correctable codeword counter.
        LAST = FEC_UNCORRECTABLE,
    };

    /// @brief Ports SerDes counters - separate counter for each SerDes in the port.
    enum class serdes_counter_e {
        PMA_TEST_ERROR = 0, ///< PMA test mode error counter.
        PMA_RX_READ,        ///< PMA Rx read counter.
        PMA_TX_WRITE,       ///< PMA Tx write counter.
        LAST = PMA_TX_WRITE,
    };

    /// @brief The stage to apply the SerDes parameter.
    enum class serdes_param_stage_e {
        ACTIVATE = 0, ///< Parameter set during SerDes activation.
        PRE_ICAL,     ///< Parameter set before initial calibration.
        PRE_PCAL,     ///< Parameter set before periodic calibration.
        FIRST = ACTIVATE,
        LAST = PRE_PCAL,
    };

    /// @brief SerDes parameter mode.
    enum class serdes_param_mode_e {
        ADAPTIVE = 0, ///< Parameter will be adaptive.
        FIXED,        ///< Parameter will be fixed.
        STATIC,       ///< Parameter will not be set but will not adapt as well.
        FIRST = ADAPTIVE,
        LAST = STATIC,
    };

    enum class serdes_param_e {
        DATAPATH_RX_GRAY_MAP = 0,  ///< RX gray mapping enable.
        DATAPATH_RX_PRECODE,       ///< SerDes datapath Rx pre-code.
        DATAPATH_RX_SWIZZLE,       ///< SerDes datapath Rx swizzle.
        DATAPATH_TX_GRAY_MAP,      ///< TX gray mapping enable.
        DATAPATH_TX_PRECODE,       ///< SerDes datapath Tx pre-code.
        DATAPATH_TX_SWIZZLE,       ///< SerDes datapath Tx swizzle.
        DIVIDER,                   ///< SerDes divider (Rx & Tx).
        ELECTRICAL_IDLE_THRESHOLD, ///< Electrical Idle threshold.
        HYSTERESIS_POST1_NEGATIVE, ///< hysteresis_post1_neg
        HYSTERESIS_POST1_POSETIVE, ///< hysteresis_post1_pos
        RX_CTLE_GAINSHAPE1,        ///< Rx Gainshape 1.
        RX_CTLE_GAINSHAPE2,        ///< Rx Gainshape 2.
        RX_CTLE_HF,                ///< CTLE HF.
        RX_CTLE_HF_MAX,            ///< CTLE HF range max.
        RX_CTLE_HF_MIN,            ///< CTLE HF range min.
        RX_CTLE_LF,                ///< CTLE LF.
        RX_CTLE_LF_MAX,            ///< CTLE LF range max.
        RX_CTLE_LF_MIN,            ///< CTLE LF range min.
        RX_CTLE_SHORT_CHANNEL_EN,  ///< CTLE Short channel enable.
        RX_CTLE_DC,                ///< CTLE DC restore value.
        RX_CTLE_BW,                ///< CTLE Bandwidth setting.
        RX_FFE_BFHF,               ///< Rx FFE BFHF.
        RX_FFE_BFLF,               ///< Rx FFE BFLF.
        RX_FFE_POST,               ///< Rx FFE Post cursor.
        RX_FFE_PRE1,               ///< Rx FFE Pre1 cursor.
        RX_FFE_PRE2,               ///< Rx FFE Pre2 cursor.
        RX_FFE_PRE1_MAX,           ///< Rx FFE Pre1 range max.
        RX_FFE_PRE1_MIN,           ///< Rx FFE Pre1 range min.
        RX_FFE_PRE2_MAX,           ///< Rx FFE Pre2 range max.
        RX_FFE_PRE2_MIN,           ///< Rx FFE Pre2 range min.
        RX_FFE_SHORT_CHANNEL_EN,   ///< Rx FFE Short channel enable.
        RX_PCAL_EFFORT,            ///< Rx PCAL effort 0 or 1.
        RX_PLL_BB,                 ///< Rx PLL BB.
        RX_PLL_IFLT,               ///< Rx PLL IFLT.
        RX_PLL_INT,                ///< Rx PLL INT.
        RX_NRZ_EYE_THRESHOLD,      ///< Rx NRZ eye threshold
        RX_TERM,                   ///< Rx termination.
        TX_ATTN,                   ///< Tx Attenuator.
        TX_ATTN_COLD_SIG_ENVELOPE, ///< Tx attenuation cold signal envelope.
        TX_ATTN_HOT_SIG_ENVELOPE,  ///< Tx attenuation hot  signal envelope.
        TX_PLL_BB,                 ///< Tx PLL BB.
        TX_PLL_IFLT,               ///< Tx PLL IFLT.
        TX_PLL_INT,                ///< Tx PLL INT.
        TX_POST,                   ///< Tx Post cursor 1.
        TX_POST2,                  ///< Tx Post cursor 2.
        TX_POST3,                  ///< Tx Post cursor 3.
        TX_PRE1,                   ///< Tx Pre cursor 1.
        TX_PRE2,                   ///< Tx Pre cursor 2.
        TX_PRE3,                   ///< Tx Pre cursor 3.

        RX_FAST_TUNE,          ///< Rx Fast Tune.
        RX_CLK_REFSEL,         ///< Rx Clk selector for refclk 0 or 1
        TX_CLK_REFSEL,         ///< Tx Clk selector for refclk 0 or 1
        RX_AC_COUPLING_BYPASS, ///< Rx AC coupling bypass.
        RX_AFE_TRIM,           ///< Rx AFE trim.
        RX_CTLE_CODE,          ///< Rx CTLE code.
        RX_DSP_MODE,           ///< Rx DSP mode.
        RX_VGA_TRACKING,       ///< Rx Variable Gain Amplifier tracking enable.

        CTLE_TUNE, ///< Enable CTLE tune until SNR improves

        AUTO_RX_PRECODE_THRESHOLD, ///< Auto RX precode threshold

        TX_INNER_EYE1, ///< Tx PAM lower inner eye.
        TX_INNER_EYE2, ///< Tx PAM upper inner eye.
        TX_LUT_MODE,   ///< Tx LUT mode.
        TX_MAIN,       ///< Tx Main cursor.
        DTL_KP_KF,     ///< DTL Time Recovery Kp/Kf Setting.

        RX_SDT_CODE_FALL, ///< Rx SDT Fall code threshold.
        RX_SDT_CODE_RISE, ///< Rx SDT Rise code threshold.
        RX_SDT_CODE_TH,   ///< Rx SDT code threshold.
        RX_SDT_BLOCK_CNT, ///< Rx SDT block code

        TX_FFE_ARRAY_COEFFS_USER_OVERRIDE, ///< Tx coarse-fine FFE method enable.
        TX_FFE_BYPASS_ENABLED,             ///< Tx FFE bypass.
        TX_FFE_BYPASS_NRZ,                 /// < DAC code for NRZ (in case FFE is bypassed).
        TX_FFE_BYPASS_PAM4,                ///< DAC code for PAM4 (in case FFE is bypassed).
        TX_FFE_BYPASS_PAM4_THP,            ///< DAC code for PAM4 THP (in case FFE is bypassed).
        TX_DIG_GAIN,                       ///< Tx Digital gain.

        TX_FFE_COARSE1, ///< FFE coarse 1.
        TX_FFE_COARSE2, ///< FFE coarse 2.
        TX_FFE_COARSE3, ///< FFE coarse 3.
        TX_FFE_FINE1,   ///< FFE fine 1.
        TX_FFE_FINE2,   ///< FFE fine 2.
        TX_FFE_FINE3,   ///< FFE fine 3.

        // TODO: what should be done with these?
        TX_FFE_LEAD_TAP_LOC,
        TX_FFE_COEFF_0,  ///< FFE tap 0
        TX_FFE_COEFF_1,  ///< FFE tap 1
        TX_FFE_COEFF_2,  ///< FFE tap 2
        TX_FFE_COEFF_3,  ///< FFE tap 3
        TX_DRIVER_SWING, ///< TX driver swing
        //

        TX_DIFF_ENCODER_EN,   ///< Differential encoder enable
        TX_PARITY_ENCODER_EN, ///< Parity encoder enable
        TX_THP_EN,            ///< Tomlinson-Harashima precoding enable

        TX_DCC_CTRL_NB,
        TX_MSB_CALIB_EN,
        TX_MSB_CALIB_VAL_OV,

        RX_CHANNEL_REACH, ///< Channel reach

        // TODO: couldn't find beagle op SET_RX_ROW_PARAMS
        RX_SET_EXPLICIT_INSTG_PARAMS, ///< Set explicit input stage parameters
        RX_CTLE_RCTRL,                ///< Ctle res ctrl
        RX_CTLE_CCTRL,                ///< Ctle cap ctrl
        RX_RTRIM,                     ///< Ctle and VGA Rtrim
        RX_VGA_GAIN,                  ///< VGA gain
        //

        RX_DIFF_ENCODER_EN,          ///< Differential encoder enable
        RX_PARITY_ENCODER_EN,        ///< Parity encoder enable
        RX_THP_EN,                   ///< Tomlinson-Harashima precoding enable
        RX_FS_BO_TARGET_OVERRIDE_EN, ///< Enable override FW value
        RX_FS_BO_TARGET,

        RX_LDO_CALIB_EN,
        RX_LDO_CALIB_VAL_OV,

        RX_FFE_ACTIVATE_COEF_BMP,           ///< Number of Rx FFE to use within 28 coeffs.
        RX_FFE_LMS_DECIMATION_FACTOR,       ///< FFE LMS decimation factor.
        RX_FFE_ACTIVE_COEF_SETS,            ///< FFE number of coef sets.
        RX_FBF_LMS_ENABLE,                  ///< Enable DFE adaptation.
        RX_FBF_ACTIVE_COEF_SETS,            ///< DFE number of coef sets.
        RX_FBF_COEF_INIT_VAL,               ///< Initial value for DFE.
        RX_FBF_FREEZE_AFTER_LINK_ESTABLISH, ///< Fixed DFE coef during maintenance mode after link establish.

        RX_INSTG_TABLE_START_ROW, ///< Input stage table start row
        RX_INSTG_TABLE_END_ROW,   ///< Input stage table end row

        FIRST = DATAPATH_RX_GRAY_MAP,
        LAST = RX_INSTG_TABLE_END_ROW
    };

    /// @brief SerDes parameters setting.
    struct serdes_parameter {
        la_mac_port::serdes_param_stage_e stage; ///< SerDes parameter stage.
        la_mac_port::serdes_param_e parameter;   ///< SerDes parameter.
        la_mac_port::serdes_param_mode_e mode;   ///< SerDes parameter mode.
        int32_t value;                           ///< SerDes parameter value.
    };

    /// @brief SerDes debug query options.
    enum class port_debug_info_e {
        MAC_STATUS,                  ///< Information about the MAC_PORT status
        SERDES_STATUS,               ///< Information about the link status.
        SERDES_CONFIG,               ///< Information about the link configuration.
        ALL,                         ///< Select all non-intensive debug info options.
        SERDES_EYE_CAPTURE,          ///< Get a histogram of the lane eye.
        SERDES_REG_DUMP,             ///< Collect register state of the SerDes.
        SERDES_EXTENDED_DEBUG,       ///< Like ALL but includes eye capture and reg dump.
        FIRST = MAC_STATUS,          ///< FIRST=MAC_STATUS
        LAST = SERDES_EXTENDED_DEBUG ///< LAST=SERDES_EXTENDED_DEBUG
    };

    /// @brief SerDes run-time control options.
    enum class serdes_ctrl_e {
        ENABLE_SQUELCH,  ///< Squelch the SerDes.
        DISABLE_SQUELCH, ///< Unsquelch the SerDes.
        LAST = DISABLE_SQUELCH
    };

    /// @brief MAC link_down interrupt information histogram.
    struct link_down_interrupt_histogram {
        size_t rx_link_status_down_count;                                   ///< MAC link down counter.
        size_t rx_remote_link_status_down_count;                            ///< MAC remote fault counter.
        size_t rx_local_link_status_down_count;                             ///< MAC local fault counter.
        size_t rx_pcs_link_status_down_count;                               ///< PCS link down counter.
        size_t rx_pcs_align_status_down_count;                              ///< Alignment marker down counter.
        size_t rx_pcs_hi_ber_up_count;                                      ///< PCS high BER counter.
        size_t rsf_rx_high_ser_interrupt_register_count;                    ///< RS-FEC high SER counter.
        size_t rx_deskew_fifo_overflow_count[la_mac_port_max_lanes_e::PCS]; ///< PCS Rx deskew fifo overflow counter.
        size_t rx_pma_sig_ok_loss_interrupt_register_count[la_mac_port_max_lanes_e::SERDES]; ///< CDR lock loss counter.
    };

    /// @brief	Basic configuration of MAC port.
    struct mac_config {
        port_speed_e port_speed; ///< Port speed.
        size_t serdes_count;     ///< Number of SerDes lanes.
        fec_mode_e fec_mode;     ///< FEC mode.
        bool an_capable;         ///< Auto-negotiation capable.
    };

    using mac_config_vec = std::vector<mac_config>;

    using serdes_param_array = std::vector<serdes_parameter>;

    typedef std::vector<size_t> state_histogram;

    /// @brief Quantization thresholds for OSTC.
    ///
    /// Over subscription traffic class thresholds of the physical queue size. Thresholds represent the filled part of the buffer.
    /// For every threshold
    /// i: 0 <= threshold[i] <= 1 && threshold[i] <= threshold[i+1].
    struct ostc_thresholds {
        double thresholds[OSTC_TRAFFIC_CLASSES];
    };

    /// @name General
    /// @{

    /// @brief Set MAC port debug mode.
    ///
    /// Sets debug mode for the MAC port. The mode will be used to dump extra info. during API calls
    ///
    /// @param[in]  mode                True/False.
    ///
    /// @retval     LA_STATUS_SUCCESS   Debug mode set succesfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_debug_mode(bool mode) = 0;

    /// @brief Get MAC port debug mode.
    ///
    /// Gets debug mode for the MAC port. The mode will be used to dump extra info. during API calls
    ///
    /// @param[out]  out_mode           True/False.
    ///
    /// @retval     LA_STATUS_SUCCESS   Debug mode set succesfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_debug_mode(bool& out_mode) const = 0;

    /// @brief Set Serdes tuning mode.
    ///
    /// Default is ICAL_ONLY for 50G Serdes, ICAL for 25G Serdes.
    /// Sets behavior for all Serdes in this port.
    ///
    /// @param[in]  mode                Serdes tuning mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Tuning mode set succesfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_serdes_tuning_mode(serdes_tuning_mode_e mode) = 0;

    /// @brief Get Serdes tuning mode.
    ///
    /// @param[out] out_mode            Serdes tuning mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mode contains the port's Serdes tuning mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_tuning_mode(serdes_tuning_mode_e& out_mode) const = 0;

    /// @brief Set SerDes continuous tuning enable or not.
    ///
    /// Enables continuous periodic fine tuning. Default is True.
    /// Sets behavior for all SerDes in this port.
    ///
    /// @param[in]  enabled             True to enable continuous tuning, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_serdes_continuous_tuning_enabled(bool enabled) = 0;

    /// @brief Get SerDes continuous tuning enable.
    ///
    /// @param[out]  out_enabled         SerDes continuous tuning mode - true if enabled, false otherwise.
    ///
    /// @retval      LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval      LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_continuous_tuning_enabled(bool& out_enabled) const = 0;

    /// @brief Set SerDes parameter.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[in]  stage                   Stage to apply the parameter to the SerDes.
    /// @param[in]  param                   SerDes parameter to modify.
    /// @param[in]  mode                    SerDes parameter mode.
    /// @param[in]  value                   SerDes parameter value.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully
    /// @retval     LA_STATUS_EINVAL        Invalid parameter setting.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_serdes_parameter(la_uint_t serdes_idx,
                                           serdes_param_stage_e stage,
                                           serdes_param_e param,
                                           serdes_param_mode_e mode,
                                           int32_t value)
        = 0;

    /// @brief Get SerDes parameter.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[in]  stage                   Stage to query the parameter.
    /// @param[in]  param                   SerDes parameter to query.
    /// @param[out] out_mode                SerDes parameter mode.
    /// @param[out] out_value               SerDes parameter value.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     Parameter value not set.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_serdes_parameter(la_uint_t serdes_idx,
                                           serdes_param_stage_e stage,
                                           serdes_param_e param,
                                           serdes_param_mode_e& out_mode,
                                           int32_t& out_value) const = 0;

    /// @brief Get SerDes parameter stored in hardware.
    ///
    /// @param[in]  serdes_idx                    SerDes index in the port.
    /// @param[in]  param                         SerDes parameter to query.
    /// @param[out] out_value                     SerDes parameter value.
    ///
    /// @retval     LA_STATUS_SUCCESS             Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED     Parameter not implemented.
    /// @retval     LA_STATUS_EINVAL              Error in getting value.
    /// @retval     LA_STATUS_EOUTOFRANGE         SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN            An unknown error occurred.
    virtual la_status get_serdes_parameter_hardware_value(la_uint_t serdes_idx, serdes_param_e param, int32_t& out_value) = 0;

    /// @brief Get all parameters associated with this SerDes lane.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[out] out_param_array         SerDes parameter array.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     Parameter value not set.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_serdes_parameters(la_uint_t serdes_idx, la_mac_port::serdes_param_array& out_param_array) const = 0;

    /// @brief Clear SerDes parameter setting.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[in]  stage                   Stage to clear the parameter from.
    /// @param[in]  param                   SerDes parameter to clear.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status clear_serdes_parameter(la_uint_t serdes_idx, serdes_param_stage_e stage, serdes_param_e param) = 0;

    /// @brief Get MAC port's auto-negotiation mode (enabled/disabled).
    ///
    /// @param[out]  out_enabled            True if MAC port auto-negotiation is enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port auto-negotiation enabled retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_an_enabled(bool& out_enabled) const = 0;

    /// @brief Set MAC port's auto-negotiation mode (enabled/disabled).
    ///
    /// @param[in]  enabled             True to enable MAC port auto-negotiation, false to disable.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_an_enabled(bool enabled) = 0;

    /// @brief Check if auto-negotiation mode is supported.
    ///
    /// @retval     True if auto-negotiation mode can be enabled with current MAC port configuration; false otherwise.
    virtual bool is_an_capable() const = 0;

    /// @brief Set MAC port speed as enabled or not. To be used in auto-negotiate.
    ///
    /// @param[in]  speed               MAC port speed.
    /// @param[in]  enabled             True to enable the specified speed, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EINVAL    Speed is invalid for the created port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_speed_enabled(port_speed_e speed, bool enabled) = 0;

    /// @brief Set FEC mode for MAC port as enabled or not. To be used in auto-negotiate.
    ///
    /// @param[in]  fec_mode            FEC mode.
    /// @param[in]  enabled             True to enable the specified FEC mode, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC mode set successfully.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EINVAL    FEC mode is not aligned with other port configuration.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fec_mode_enabled(fec_mode_e fec_mode, bool enabled) = 0;

    /// @brief Start MAC port activation.
    /// If more than single speed and/or FEC are configured, perform auto-negotiation.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port state change started successfully.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EINVAL    Configuration is incomplete.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status activate() = 0;

    /// @brief Check MAC port signal status.
    ///
    /// @param[out] out_signal_ok       True if signal detected on all port's SerDes, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Signal check completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_port_signal_ok(bool& out_signal_ok) = 0;

    /// @brief Check signal OK of specific SerDes.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[out] out_signal_ok           True if signal detected, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS       Signal OK check completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_serdes_signal_ok(la_uint_t serdes_idx, bool& out_signal_ok) = 0;

    /// @brief Start MAC port SerDes tuning.
    ///
    /// Must be done after port activated successfully.
    ///
    /// @param[in]  block               If true, block till tune completes; otherwise, return after tune initiated.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port tune initiated successfully.
    /// @retval     LA_STATUS_EINVAL    Configuration is incomplete.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status tune(bool block) = 0;

    /// @brief Check MAC port SerDes tuning status.
    ///
    /// @param[out] out_completed       True if tune completed, false if tune is still in progress.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port tune status retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Configuration is incomplete or tune failed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_tune_status(bool& out_completed) = 0;

    /// @brief Start MAC port reset.
    ///
    /// @deprecated reset function will be deprecated.
    ///
    /// If port has multiple speeds/FEC modes enabled, auto-negotiation is performed.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port state change started successfully.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EINVAL    Configuration is incomplete.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status reset() = 0;

    /// @brief Stop MAC port.
    ///
    /// Change port state to inactive.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port state change started successfully.
    /// @retval     LA_STATUS_EINVAL    Port is inactive.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status stop() = 0;

    /// @brief Block/unblock ingress data on MAC port.
    ///
    /// Blocks or unblocks ingress data into the MAC port.
    ///
    /// @param[in]  enabled             True to enable blocking ingress data, false to unblock it.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_block_ingress_data(bool enabled) = 0;

    /// @brief Get Block ingress traffic state of MAC port.
    ///
    /// Get Block ingress traffic state.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port ingress block state retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_block_ingress_data(bool& out_enabled) const = 0;

    /// @brief Get MAC port state.
    ///
    /// @param[out] out_state           MAC port state.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_state(state_e& out_state) const = 0;

    /// @brief Get MAC port state histogram.
    ///
    /// Counts number of times port entered to each state.
    ///
    /// @param[in]  clear               Clear counters after read.
    /// @param[out] out_state_histogram Counter for each MAC port state.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_state_histogram(bool clear, state_histogram& out_state_histogram) = 0;

    /// @brief Get MAC link down histogram.
    ///
    /// Counts the triggers for the link down notifications.
    ///
    /// @param[in]  clear                   Clear counters after read.
    /// @param[out] out_link_down_histogram MAC link down histogram.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_link_down_histogram(bool clear, link_down_interrupt_histogram& out_link_down_histogram) = 0;

    /// @brief Get slice used by this MAC port.
    ///
    /// @return #la_slice_id_t.
    virtual la_slice_id_t get_slice() const = 0;

    /// @brief Get IFG used by this MAC port.
    ///
    /// @return #la_ifg_id_t.
    virtual la_ifg_id_t get_ifg() const = 0;

    /// @brief Get ID of first SerDes element.
    ///
    /// @return First SerDes ID.
    virtual la_uint_t get_first_serdes_id() const = 0;

    /// @brief Get number of SerDes elements.
    ///
    /// @return Number of SerDes elements.
    virtual size_t get_num_of_serdes() const = 0;

    /// @brief Get ID of first PIF.
    ///
    /// @return First PIF ID.
    virtual la_uint_t get_first_pif_id() const = 0;

    /// @brief Get number of PIF's.
    ///
    /// @return Number of PIF's.
    virtual size_t get_num_of_pif() const = 0;

    /// @brief Get port's speed.
    ///
    /// @param[out] out_speed           Port's speed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Speed retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_speed(la_mac_port::port_speed_e& out_speed) const = 0;

    /// @brief Get single SerDes speed.
    ///
    /// @param[out] out_speed           SerDes speed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Speed retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_speed(la_mac_port::port_speed_e& out_speed) const = 0;

    /// @brief Set port speed.
    ///
    /// @param[in]  speed       Speed to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EBUSY     Speed cannot be changed on an active port.
    /// @retval     LA_STATUS_EINVAL    Speed is invalid for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_speed(la_mac_port::port_speed_e speed) = 0;

    /// @brief  Re-configure MAC port.
    ///
    /// Re-configure MAC port with new SerDes counts, speed, FEC and flow control.
    ///
    /// @param[in]      num_of_serdes   Number of SerDes.
    /// @param[in]      speed           MAC port speed.
    /// @param[in]      rx_fc_mode      RX Flow control mode.
    /// @param[in]      tx_fc_mode      TX Flow control mode.
    /// @param[in]      fec_mode        FEC mode.
    ///
    /// @retval     LA_STATUS_SUCCESS           MAC port re-configured successfully.
    /// @retval     LA_STATUS_EBUSY             Port can't be reconfigured while active.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Settings are not supported.
    /// @retval     LA_STATUS_EINVAL            Settings are invalid.
    /// @retval     LA_STATUS_ERESOURCE         Lack of SerDes resources for reconfiguration.
    virtual la_status reconfigure(size_t num_of_serdes,
                                  la_mac_port::port_speed_e speed,
                                  la_mac_port::fc_mode_e rx_fc_mode,
                                  la_mac_port::fc_mode_e tx_fc_mode,
                                  la_mac_port::fec_mode_e fec_mode)
        = 0;

    /// @brief Get port's Forward Error Correction mode.
    ///
    /// @param[out] out_fec_mode        Port's FEC mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fec_mode(la_mac_port::fec_mode_e& out_fec_mode) const = 0;

    /// @brief Set Forward Error Correction mode.
    ///
    /// @param[in]  fec_mode    FEC mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EBUSY     FEC mode cannot be changed on an active port.
    /// @retval     LA_STATUS_EINVAL    FEC mode is invalid for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fec_mode(la_mac_port::fec_mode_e fec_mode) = 0;

    /// @brief Get port's Flow Control mode.
    ///
    /// @param[in]  fc_dir              Flow control direction.
    /// @param[out] out_fc_mode         Port's flow control mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   FC mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e& out_fc_mode) const = 0;

    /// @brief Set port flow control mode.
    ///
    /// @param[in]  fc_dir      Flow control direction to set.
    /// @param[in]  fc_mode     Flow control mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EBUSY     FC mode cannot be changed on an active port.
    /// @retval     LA_STATUS_EINVAL    FC mode is invalid for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Before setting to or from PFC mode, the source queue counters for this port should be empty.
    virtual la_status set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode) = 0;

    /// @brief Read SerDes status.
    ///
    /// @param[in]  serdes_idx           SerDes index in the port.
    /// @param[out] out_serdes_status    Contains Serdes status information.
    ///
    /// @retval     LA_STATUS_SUCCESS      Read completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE  SerDes index out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status read_serdes_status(la_uint_t serdes_idx, la_mac_port::serdes_status& out_serdes_status) const = 0;

    /// @brief Read MAC port status.
    ///
    /// @param[out] out_mac_status      Contains MAC port status information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Read completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_mac_status(la_mac_port::mac_status& out_mac_status) const = 0;

    /// @brief Read MAC PCS lane mapping.
    ///
    /// @param[out] out_mac_pcs_lane_mapping    Contains MAC PCS lane mappings.
    ///
    /// @retval     LA_STATUS_SUCCESS   Read completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_mac_pcs_lane_mapping(la_mac_port::mac_pcs_lane_mapping& out_mac_pcs_lane_mapping) const = 0;

    /// @brief Read port's MIB counters.
    ///
    /// The entire counter set is read from the device in a single operation. All counters values are sampled simultaneously.
    ///
    /// @param[in]  clear               Clear counters after read.
    /// @param[out] out_mib_counters    Contains the port's MIB counter values.
    ///
    /// @retval     LA_STATUS_SUCCESS   Contains the port's MIB counter values.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_mib_counters(bool clear, la_mac_port::mib_counters& out_mib_counters) const = 0;

    /// @brief Enable RS-FEC debug counters.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's RS-FEC debug enabled successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note The debug counters is a resource which may be shared by multiple ports.
    virtual la_status set_rs_fec_debug_enabled() = 0;

    /// @brief Get RS-FEC debug counters status.
    ///
    /// @param[out] out_debug_status  Contains the port's RS-FEC debug counter status - true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's RS-FEC debug retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note The debug counters is a resource which may be shared by multiple ports.
    virtual la_status get_rs_fec_debug_enabled(bool& out_debug_status) const = 0;

    /// @brief Read port's RS-FEC debug counters.
    ///
    /// @deprecated read_counter function without boolean clear flag will be deprecated.
    ///
    /// The entire counter set is read from the device in a single operation. All counters values are sampled simultaneously.
    ///
    /// @param[out] out_debug_counters  Contains the port's RS-FEC debug counter values and extrapolated BER.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's RS-FEC debug counter values retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Debug is currently not enabled for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Debug counters should be enabled on the port. The debug counters is a resource which may be shared by multiple ports.
    virtual la_status read_rs_fec_debug_counters(rs_fec_debug_counters& out_debug_counters) const = 0;

    /// @brief Read port's RS-FEC debug counters.
    ///
    /// The entire counter set is read from the device in a single operation. All counters values are sampled simultaneously.
    ///
    /// @param[in]  clear               Clear counters after read.
    /// @param[out] out_debug_counters  Contains the port's RS-FEC debug counter values and extrapolated BER.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's RS-FEC debug counter values retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Debug is currently not enabled for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Debug counters should be enabled on the port. The debug counters is a resource which may be shared by multiple ports.
    virtual la_status read_rs_fec_debug_counters(bool clear, rs_fec_debug_counters& out_debug_counters) const = 0;

    /// @brief Read symbol error counters per FEC lane.
    ///
    /// @deprecated read_counter function without boolean clear flag will be deprecated.
    ///
    /// @param[out] out_sym_err_counters  Contains the port's RS-FEC symbol errors counters values.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's RS-FEC symbol errors counters values retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    RS-FEC is currently not enabled for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Debug counters should be enabled on the port.
    virtual la_status read_rs_fec_symbol_errors_counters(rs_fec_sym_err_counters& out_sym_err_counters) const = 0;

    /// @brief Read symbol error counters per FEC lane.
    ///
    /// @param[in]  clear                 Clear counters after read.
    /// @param[out] out_sym_err_counters  Contains the port's RS-FEC symbol errors counters values.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's RS-FEC symbol errors counters values retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    RS-FEC is currently not enabled for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Debug counters should be enabled on the port.

    virtual la_status read_rs_fec_symbol_errors_counters(bool clear, rs_fec_sym_err_counters& out_sym_err_counters) const = 0;
    /// @brief Read port's OSTC counter.
    ///
    /// Read dropped packets count due to OSTC thresholds for a given traffic class.
    ///
    /// @param[in]  ostc                    Traffic class to read its counters.
    /// @param[out] out_dropped_packets     Contains the port's dropped packets counter's value.
    ///
    /// @retval     LA_STATUS_SUCCESS       Read completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status read_ostc_counter(la_over_subscription_tc_t ostc, size_t& out_dropped_packets) const = 0;

    /// @brief Read port counter (clear on read).
    ///
    /// @deprecated read_counter function without boolean clear flag will be deprecated.
    ///
    /// @param[in]  counter_type        Counter type.
    /// @param[out] out_counter         Counter value.
    ///
    /// @retval     LA_STATUS_SUCCESS   Counter retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Counter is not applicable for current state.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_counter(counter_e counter_type, size_t& out_counter) const = 0;

    /// @brief Read port counter with clear option.
    ///
    /// @param[in]  clear               Clear counters after read.
    /// @param[in]  counter_type        Counter type.
    /// @param[out] out_counter         Counter value.
    ///
    /// @retval     LA_STATUS_SUCCESS   Counter retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Counter is not applicable for current state.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_counter(bool clear, counter_e counter_type, size_t& out_counter) const = 0;

    /// @brief Read counter of specific SerDes of the port.
    ///
    /// @param[in]  counter_type            Counter type.
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[out] out_counter             Counter value.
    ///
    /// @retval     LA_STATUS_SUCCESS       Counter retrieved successfully.
    /// @retval     LA_STATUS_EINVAL        Counter is not applicable for current state.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status read_counter(serdes_counter_e counter_type, la_uint_t serdes_idx, size_t& out_counter) const = 0;

    /// @brief Clear all counters of the port.
    ///
    /// @retval     LA_STATUS_SUCCESS       Counters cleared successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status clear_counters() const = 0;

    /// @}
    /// @name TM settings
    /// @{

    /// @brief Return interface scheduler for this MAC port.
    ///
    /// @return Interface scheduler object.
    virtual la_interface_scheduler* get_scheduler() const = 0;

    /// @}
    /// @name MAC port settings
    /// @{

    /// @brief Get port's minimum packet size.
    ///
    /// @param[out] out_min_size        Minimum packet size.
    ///
    /// @retval     LA_STATUS_SUCCESS   Minimum packet size retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_min_packet_size(la_uint_t& out_min_size) const = 0;

    /// @brief Set minimum packet size for MAC port.
    ///
    /// @param[in]  min_size            Minimum packet size.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EINVAL    Packet size is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_min_packet_size(la_uint_t min_size) = 0;

    /// @brief Get port's maximum packet size.
    ///
    /// @param[out] out_max_size        Maximum packet size.
    ///
    /// @retval     LA_STATUS_SUCCESS   Maximum packet size retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_max_packet_size(la_uint_t& out_max_size) const = 0;

    /// @brief Set maximum packet size for MAC port.
    ///
    /// @param[in]  max_size            Maximum packet size.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EINVAL    Packet size is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_max_packet_size(la_uint_t max_size) = 0;

    /// @brief Get port's FEC bypass mode.
    ///
    /// @param[out] out_fec_bp          FEC bypass mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC bypass mode retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    FEC bypass mode is not applicable to port configurations.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fec_bypass_mode(fec_bypass_e& out_fec_bp) const = 0;

    /// @brief Set FEC bypass mode for MAC port.
    ///
    /// @param[in]  fec_bp              FEC bypass mode, by default no bypass.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC bypass mode set successfully.
    /// @retval     LA_STATUS_EINVAL    FEC bypass mode is not aligned with other port configurations.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fec_bypass_mode(fec_bypass_e fec_bp) = 0;

    /// @brief Get port's Preamble compression enabled or not.
    ///
    /// @param[out] out_enabled         True if preamble compression enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Preamble compression mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_preamble_compression_enabled(bool& out_enabled) const = 0;

    /// @brief Set Preamble compression for MAC port is enabled or not.
    ///
    /// Disabled by default. Can be enabled on links where both ends support this feature.
    ///
    /// @param[in]  enabled             True to enable preamble compression, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_preamble_compression_enabled(bool enabled) = 0;

    /// @brief Get port's Inter-Packet Gap configuration.
    ///
    /// @param[out] out_gap_len         Inter-Packet Gap length in bytes (idle time).
    /// @param[out] out_gap_tx_bytes    Number of bytes to be transmitted before inserting Inter-Packet Gap.
    ///                                 If 0, insert Inter-Packet Gap every packet.
    ///
    /// @retval     LA_STATUS_SUCCESS   IPG retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipg(la_uint16_t& out_gap_len, la_uint16_t& out_gap_tx_bytes) const = 0;

    /// @brief Set Inter-Packet Gap configuration of the MAC port.
    ///
    /// By default, Inter-Packet Gap is between every packet, with idle time of 12 bytes.
    ///
    /// @param[in]  gap_len             Inter-Packet Gap length in bytes (idle time).
    /// @param[in]  gap_tx_bytes        Number of bytes to be transmitted before inserting Inter-Packet Gap.
    ///                                 If 0, insert Inter-Packet Gap every packet.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EINVAL    gap_len or gap_tx_bytes are invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipg(la_uint16_t gap_len, la_uint16_t gap_tx_bytes) = 0;

    /// @brief Refresh MAC port Tx.
    ///
    /// Reinitialize the MAC port's SerDes's and the Tx PMA
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port Tx refresh successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status tx_refresh() = 0;

    /// @}
    /// @name Loopback and test settings
    /// @{

    /// @brief Get port's loopback mode.
    ///
    /// @param[out] out_loopback_mode   MAC port loopback mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Loopback mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_loopback_mode(loopback_mode_e& out_loopback_mode) const = 0;

    /// @brief Set loopback mode of the MAC port.
    ///
    /// @param[in]  mode                MAC port loopback mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_loopback_mode(loopback_mode_e mode) = 0;

    /// @brief Get if MAC port's link management enabled.
    ///
    /// @param[out]  out_enabled        MAC port link management enabled.
    ///
    /// @retval     LA_STATUS_SUCCESS   Link management enabled retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_link_management_enabled(bool& out_enabled) const = 0;

    /// @brief Set automatic link management of the MAC port enabled or not.
    ///
    /// @param[in]  enabled             MAC port link management enabled.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_link_management_enabled(bool enabled) = 0;

    /// @brief Get port's PCS test mode.
    ///
    /// @param[out]  out_mode           MAC port PCS test mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   PCS test mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pcs_test_mode(pcs_test_mode_e& out_mode) const = 0;

    /// @brief Set PCS test mode of the MAC port.
    ///
    /// @param[in]  mode                MAC port PCS test mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pcs_test_mode(pcs_test_mode_e mode) = 0;

    /// @brief Get port's seed for the PCS test pattern.
    /// Relevant only if test mode is #silicon_one::la_mac_port::pcs_test_mode_e::RANDOM.
    ///
    /// @param[out] out_seed            PCS test pattern seed.
    ///
    /// @retval     LA_STATUS_SUCCESS   PCS test pattern seed retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    PCS test pattern seed is not applicable for current PCS test mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pcs_test_seed(la_uint128_t& out_seed) const = 0;

    /// @brief Set the seed for the PCS transmit test pattern of the MAC port.
    /// Relevant only if test mode is #silicon_one::la_mac_port::pcs_test_mode_e::RANDOM.
    ///
    /// @param[in]  seed        MAC port PCS test pattern seed.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pcs_test_seed(la_uint128_t seed) = 0;

    /// @brief Get port's PMA test mode.
    ///
    /// @param[out]  out_mode           MAC port PMA test mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   PMA test mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pma_test_mode(pma_test_mode_e& out_mode) const = 0;

    /// @brief Set PMA test mode of the MAC port.
    ///
    /// @param[in]  mode        MAC port PCS test mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pma_test_mode(pma_test_mode_e mode) = 0;

    /// @brief Get port's seed for the PMA test pattern.
    /// Relevant only if test mode is #silicon_one::la_mac_port::pma_test_mode_e::RANDOM.
    ///
    /// @param[out] out_seed            PMA test pattern seed.
    ///
    /// @retval     LA_STATUS_SUCCESS   PMA test pattern seed retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    PMA test pattern seed is not applicable for current PCS test mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pma_test_seed(la_uint128_t& out_seed) const = 0;

    /// @brief Set the seed for the PMA transmit test pattern of the MAC port.
    /// Relevant only if test mode is #silicon_one::la_mac_port::pma_test_mode_e::RANDOM.
    ///
    /// @param[in]  seed        MAC port PMA test pattern seed.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pma_test_seed(la_uint128_t seed) = 0;

    /// @brief Read PMA BER for all SerDes lanes of the port.
    ///
    /// @param[out] out_mac_pma_ber     SerDes PMA BER result.
    ///
    /// @retval     LA_STATUS_SUCCESS   Read completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Calling this API may reset all port counters for other ports on this IFG.
    virtual la_status read_pma_test_ber(la_mac_port::mac_pma_ber& out_mac_pma_ber) const = 0;

    /// @brief Set SerDes test mode for a specific SerDes in the port.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[in]  direction               SerDes test mode direction Tx or Rx.
    /// @param[in]  mode                    SerDes test mode for the SerDes lane.
    ///
    /// @retval     LA_STATUS_SUCCESS       SerDes test mode updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EINVAL        SerDes test mode is not a valid value/selection.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_serdes_test_mode(la_uint_t serdes_idx,
                                           la_serdes_direction_e direction,
                                           la_mac_port::serdes_test_mode_e mode)
        = 0;

    /// @brief Get SerDes test mode for a specific SerDes in the port.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[in]  direction               SerDes test mode direction Tx or Rx.
    /// @param[in]  out_mode                SerDes test mode for the SerDes lane.
    ///
    /// @retval     LA_STATUS_SUCCESS       SerDes test mode retrieved successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    virtual la_status get_serdes_test_mode(la_uint_t serdes_idx,
                                           la_serdes_direction_e direction,
                                           la_mac_port::serdes_test_mode_e& out_mode) const = 0;

    /// @brief Set SerDes test mode for all SerDes lanes in the port.
    ///
    /// @param[in]  direction               SerDes test mode direction Tx or Rx.
    /// @param[in]  mode                    SerDes test mode.
    ///
    /// @retval     LA_STATUS_SUCCESS       SerDes test mode updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EINVAL        SerDes test mode is not a valid value/selection.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e mode) = 0;

    /// @brief Get port's SerDes test mode for all SerDes lanes in the port.
    ///
    /// @param[in]   direction              SerDes test mode direction Tx or Rx.
    /// @param[out]  out_mode               SerDes test mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes test mode retrieved successfully.
    /// @retval     LA_STATUS_ENOTFOUND Not all SerDes in port are set to the same test mode. No test mode returned.
    virtual la_status get_serdes_test_mode(la_serdes_direction_e direction, la_mac_port::serdes_test_mode_e& out_mode) const = 0;

    /// @brief Read SerDes PRBS BER for a specific SerDes in the port.
    ///
    /// Performs a clearing read operation and keeps a track of time since last read.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[out] out_serdes_prbs_ber     SerDes PRBS BER, bit count, error count, and PRBS lock status result since last read.
    ///
    /// @retval     LA_STATUS_SUCCESS       Read completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range for this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    ///
    /// @note Calling this API will clear PRBS error counter. The bit count is extrapolated from datarate.
    /// @note serdes_idx will be the index written to in out_serdes_prbs_ber struct.
    virtual la_status read_serdes_test_ber(la_uint_t serdes_idx, la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) = 0;

    /// @brief Read SerDes PRBS BER for all SerDes lanes of the port.
    ///
    /// Performs a clearing read operation and keeps a track of time since last read.
    ///
    /// @param[out] out_serdes_prbs_ber         SerDes PRBS BER, bit count, error count, and PRBS lock status result since last
    /// read.
    ///
    /// @retval     LA_STATUS_SUCCESS   Read completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note Calling this API will clear PRBS error counter. The bit count is extrapolated from datarate.
    virtual la_status read_serdes_test_ber(la_mac_port::serdes_prbs_ber& out_serdes_prbs_ber) const = 0;

    /// @brief Set the OSTC quantization thresholds.
    ///
    /// Set the threshold to every OSTC. If the buffer is more congested than the packet's OSTC's threshold the packet will be
    /// dropped.
    ///
    /// @param[in]  thresholds          Buffer size thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Thresholds were updated successfully.
    /// @retval     LA_STATUS_EINVAL    Thresholds are out of range or not increasing monotonically.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ostc_quantizations(const ostc_thresholds& thresholds) = 0;

    /// @brief Get the OSTC quantization thresholds.
    ///
    /// @param[out] out_thresholds      Thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ostc_quantizations(ostc_thresholds& out_thresholds) const = 0;

    /// @brief Set the default OSTC and ITC for packets on the port.
    ///
    /// Set default OSTC and ITC if behaviour of the packet's protocol and priority was not defined.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  default_ostc        Default OSTC.
    /// @param[in]  default_itc         Default ITC.
    ///
    /// @retval     LA_STATUS_SUCCESS   Default OSTC and ITC were updated successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid TC, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_EBUSY     MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_default_port_tc(la_over_subscription_tc_t default_ostc, la_initial_tc_t default_itc) = 0;

    /// @brief Get the default OSTC and ITC for the port.
    ///
    /// @param[out] out_default_ostc    Default OSTC.
    /// @param[out] out_default_itc     Default ITC.
    ///
    /// @retval     LA_STATUS_SUCCESS   Default OSTC and ITC were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_default_port_tc(la_over_subscription_tc_t& out_default_ostc, la_initial_tc_t& out_default_itc) const = 0;

    /// @brief Add custom TPID for TC mechanism.
    ///
    /// Add TPID to port TC comparators. It allows to classify packets using this TPID not by the default TC.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  tpid                TPID to add.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        TPID is already configured, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_ERESOURCE     All comparators are in use.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status add_port_tc_tpid(la_tpid_t tpid) = 0;

    /// @brief Remove TPID from port TC mechanism.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  tpid                TPID to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_ENOTFOUND     TPID was not found.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status remove_port_tc_tpid(la_tpid_t tpid) = 0;

    /// @brief Get the configured port TC TPIDs.
    ///
    /// @param[out] out_tpids               TPIDs vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_port_tc_tpids(la_tpid_vec& out_tpids) const = 0;

    /// @brief Set port TC extract offset.
    ///
    /// Set port TC extract offset in bytes between 0-23 relative to the start of the Ethernet packet header.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  offset                  New offset to be set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Offset is greater than allowed, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_port_tc_extract_offset(la_uint_t offset) = 0;

    /// @brief Set port TC for custom protocol with offset.
    ///
    /// The protocol is the byte which is extracted from packet header according to pre-configured offset.
    /// No need to add the protocol before calling this function.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  protocol                Packet's protocol's first byte.
    /// @param[in]  ostc                    Packet's OSTC.
    /// @param[in]  itc                     Packet's ITC.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protocol is greater than allowed, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_port_tc_for_custom_protocol_with_offset(la_ethertype_t protocol,
                                                                  la_over_subscription_tc_t ostc,
                                                                  la_initial_tc_t itc)
        = 0;

    /// @brief Add custom protocol to port TC mechanism.
    ///
    /// Add protocol to port TC comparators. It allows to classify packets using this protocol not by the default TC.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  protocol                Ethernet type to add.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protocol is already configured, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_ERESOURCE     All comparators are in use.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status add_port_tc_custom_protocol(la_ethertype_t protocol) = 0;

    /// @brief Remove custom protocol from port TC mechanism.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  protocol                Ethernet type to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_ENOTFOUND     Protocol was not found.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status remove_port_tc_custom_protocol(la_ethertype_t protocol) = 0;

    /// @brief Get the configured port TC custom protocols.
    ///
    /// @param[out] out_protocols           Ethernet type vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_port_tc_custom_protocols(la_ethertype_vec& out_protocols) const = 0;

    /// @brief Set which layer header to look at when resolving the port TC.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  tpid                    Packet's TPID.
    /// @param[in]  protocol                Packet's protocol.
    /// @param[in]  layer                   Layer to use for port TC resolution.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protocol is not known L3 protocol, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_port_tc_layer(la_tpid_t tpid, tc_protocol_e protocol, la_layer_e layer) = 0;

    /// @brief Get the port's layer header for port TC resolution.
    ///
    /// @param[in]  tpid                    Packet's TPID.
    /// @param[in]  protocol                Packet's protocol.
    /// @param[out] out_layer               Layer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protocol is not known L3 protocol.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_port_tc_layer(la_tpid_t tpid, tc_protocol_e protocol, la_layer_e& out_layer) const = 0;

    /// @brief Set the port TC for a given hard-coded protocol.
    ///
    /// Sets the port TC on the port for a given protocol and all priorities from lower_bound to higher_bound. If buffer is more
    /// congested than the labeled TC threshold the packet is dropped.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  protocol                Packet's protocol which will get the OSTC.
    /// @param[in]  lower_bound             Packet's first priority which will get the OSTC.
    /// @param[in]  higher_bound            Packet's last priority which will get the OSTC.
    /// @param[in]  ostc                    OSTC to set to all packets with matching protocol and priorities.
    /// @param[in]  itc                     ITC to set to all packets with matching protocol and priorities.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid priority bounds, OSTC or ITC, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_port_tc_for_fixed_protocol(tc_protocol_e protocol,
                                                     la_uint8_t lower_bound,
                                                     la_uint8_t higher_bound,
                                                     la_over_subscription_tc_t ostc,
                                                     la_initial_tc_t itc)
        = 0;

    /// @brief Get the port TC for a given hard-coded protocol and its priority.
    ///
    /// @param[in]  protocol                Packet's protocol.
    /// @param[in]  priority                Packet's priority.
    /// @param[out] out_ostc                OSTC to populate.
    /// @param[out] out_itc                 ITC to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid priority bounds.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_port_tc_for_fixed_protocol(tc_protocol_e protocol,
                                                     la_uint8_t priority,
                                                     la_over_subscription_tc_t& out_ostc,
                                                     la_initial_tc_t& out_itc) const = 0;

    /// @brief Clear all port's TC TCAM entries
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY       MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status clear_port_tc_for_fixed_protocol() = 0;

    /// @brief Set the port TC for a given configured protocol and its TPID.
    ///
    /// Sets the port TC on the port for a given protocol and TPID. Configuring port TC for custom protocol does not use priority.
    ///
    /// Each two consecutive breakout ports share the same TC configuration.
    /// Odd PIF ID Port setting is not allowed.
    ///
    /// @param[in]  tpid                    Packet's TPID.
    /// @param[in]  protocol                Packet's protocol.
    /// @param[in]  ostc                    Packet's OSTC.
    /// @param[in]  itc                     Packet's ITC.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid tpid, protocol, OSTC or ITC, or function is called on a port with odd PIF ID.
    /// @retval     LA_STATUS_EBUSY         MAC port is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_port_tc_for_custom_protocol(la_tpid_t tpid,
                                                      la_ethertype_t protocol,
                                                      la_over_subscription_tc_t ostc,
                                                      la_initial_tc_t itc)
        = 0;

    /// @brief Get the port TC for a given configured protocol and its TPID.
    ///
    /// @param[in]  tpid                    Packet's TPID.
    /// @param[in]  protocol                Packet's protocol.
    /// @param[out] out_ostc                OSTC to populate.
    /// @param[out] out_itc                 ITC to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid tpid ort priority.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_port_tc_for_custom_protocol(la_tpid_t tpid,
                                                      la_ethertype_t protocol,
                                                      la_over_subscription_tc_t& out_ostc,
                                                      la_initial_tc_t& out_itc) const = 0;

    /// @}
    /// @brief Get SerDes debug information for a SerDes within the port.
    ///
    /// @param[in]  info_type               Type of debug information to collect.
    /// @param[out] out_root                JSON node containing serdes debug information.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid debug info type.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status save_state(port_debug_info_e info_type, json_t* out_root) const = 0;

    /// @}
    /// @brief Get SerDes debug information for a SerDes within the port and save into a file.
    ///
    /// @param[in]  info_type               Type of debug information to collect.
    /// @param[out] file_name               File to write out SerDes debug information.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid debug info type.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status save_state(port_debug_info_e info_type, std::string file_name) const = 0;

    /// @}
    /// @brief Toggle SerDes settings to change run-time behavior.  Debug API, not persistent over port state changes.
    ///
    /// @param[in]  serdes_idx              SerDes index in the port.
    /// @param[in]  direction               SerDes direction.
    /// @param[in]  ctrl_type               Type of control to assert.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid debug info type.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_EOUTOFRANGE   SerDes index is out of range.
    virtual la_status set_serdes_signal_control(la_uint_t serdes_idx, la_serdes_direction_e direction, serdes_ctrl_e ctrl_type) = 0;

    /// @}
    /// @name Priority flow control
    /// @{

    /// @brief Priority flow control priority.
    typedef la_uint8_t la_pfc_priority_t;

    /// @brief Defines the number of IDs used in PFC.
    enum {
        LA_NUM_PFC_PRIORITY_CLASSES = 8, ///< Number of PFC priority classes.
    };

    /// @brief PFC configured queue state.
    enum class pfc_config_queue_state_e {
        ACTIVE,   ///< Queue is active.
        DROPPING, ///< Queue is set to drop.
    };

    /// @brief PFC dynamic queue state.
    enum class pfc_queue_state_e {
        EMPTY,                       ///< Queue is empty.
        TRANSMITTING,                ///< Queue is transmitting.
        NOT_TRANSMITTING,            ///< Queue is non empty but has not transmitted since last poll.
        NOT_TRANSMITTING_DUE_TO_PFC, ///< Queue is not transmitting due to being blocked by PFC.
    };

    /// @brief Enable PFC on this port.
    ///
    /// @param[in] tc_bitmap         Bitmap of traffic classes to enable as priority TC-s. For Pacific SW PFC, this should be set to
    /// 0.
    ///
    /// @retval     LA_STATUS_SUCCESS          PFC successfully enabled.
    /// @retval     LA_STATUS_EINVAL           Invalid parameter supplied.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_pfc_enable(la_uint8_t tc_bitmap) = 0;

    /// @brief Disable PFC on a port
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    An unknown error occurred.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_disable() = 0;

    /// @brief Get PFC enabled on a port.
    ///
    /// @param[out]  out_enabled        True if PFC is enabled; false otherwise.
    /// @param[out]  out_tc_bitmap      Bitmap of TC-s that PFC is enabled for. 0 in case of software-based PFC.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    An unknown error occurred.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_enabled(bool& out_enabled, la_uint8_t& out_tc_bitmap) const = 0;

    /// @brief Set PFC counter on a port.
    ///
    /// @param[out]  rx_counter        Counter object
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    An unknown error occurred.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_counter(la_counter_set* rx_counter) = 0;

    /// @brief Get PFC counter on a port.
    ///
    /// @param[out]  out_counter        Counter object
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    An unknown error occurred.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_counter(const la_counter_set*& out_counter) const = 0;

    /// @brief Set PFC TX meter on a port.
    ///
    /// TX meter is only valid for Pacific SW-based PFC.
    ///
    /// @param[out]  tx_meter        Meter object
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS Meter does not belong to same device as port.
    /// @retval     LA_STATUS_EINVAL          SW PFC is not enabled/supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_pfc_meter(la_meter_set* tx_meter) = 0;

    /// @brief Get PFC TX meter on a port.
    ///
    /// @param[out]  out_meter        Meter object
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    SW PFC is not enabled/supported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_meter(const la_meter_set*& out_meter) const = 0;

    /// @brief Get PFC quanta value on a port.
    ///
    /// @param[out]  out_xoff_time       xoff time in the PFC message.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_quanta(std::chrono::nanoseconds& out_xoff_time) const = 0;

    /// @brief Set PFC quanta value on a port.
    ///
    /// @param[in]   xoff_time           xoff time in the PFC message.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_pfc_quanta(std::chrono::nanoseconds xoff_time) = 0;

    /// @brief Set the PFC periodic timer for this port.
    ///
    /// @param[in] period   Period to set for periodic timer. Given in microseconds.
    ///
    /// @retval     LA_STATUS_SUCCESS          Timer successfully set.
    /// @retval     LA_STATUS_EINVAL           Invalid parameter supplied.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  HW based PFC is not enabled at a device level.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_pfc_periodic_timer(std::chrono::nanoseconds period) = 0;

    /// @brief   Get the PFC periodic timer value for this port.
    ///
    /// @param[out] out_period        Period set for periodic timer. Given in microseconds.
    ///
    /// @retval     LA_STATUS_SUCCESS          Timer value successfully retrieved.
    /// @retval     LA_STATUS_EINVAL           Invalid parameter supplied.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  HW based PFC is not enabled at a device level.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_pfc_periodic_timer(std::chrono::nanoseconds& out_period) = 0;

    /// @brief   Set the OQ profiles to the PFC OQ profile for every TC in the TC bitmap.
    ///
    /// By default, all ports use the OQ profile configured in #silicon_one::la_device::set_tx_cgm_port_oq_profile_thresholds.
    /// If this API is set, any TC-s in the TC bitmap are configured to use the OQ profile specified in
    /// #silicon_one::la_device::set_tx_cgm_pfc_port_oq_profile_thresholds.
    ///
    /// @param[in] tc_bitmap        Bitmap of TC-s to configure OQ profiles for.
    ///
    /// @retval     LA_STATUS_SUCCESS       Profiles configured successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_pfc_oq_profile_tc_bitmap(la_uint8_t tc_bitmap) = 0;

    /// @brief   Get the TC-s for which the PFC OQ profile is configured.
    ///
    /// @param[out] out_tc_bitmap        Bitmap to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Profiles retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_pfc_oq_profile_tc_bitmap(la_uint8_t& out_tc_bitmap) = 0;

    /// @brief   Set the mapping for a given RXCGM source queue to an SQ profile, SQ group, and drop
    /// counter
    ///
    /// A source queue, defined by the TC, can be mapped to a profile, a group, and a drop
    /// counter. The SQ profile defines thresholds and policies to take based on various thresholds. The group
    /// defines additional thresholds. The drop counter defines which counter to increment on drops for this SQ.
    ///
    /// @param[in] tc                           Traffic class to set mapping for.
    /// @param[in] profile                      SQ profile to set for given TC.
    /// @param[in] group_index                  The index of the SQG to set for given TC.
    /// @param[in] drop_counter_index           The index of the drop counter to set for the given TC.
    ///
    /// @retval     LA_STATUS_SUCCESS     Mapping successfully set.
    /// @retval     LA_STATUS_EINVAL      Invalid parameter supplied.
    /// @retval     LA_STATUS_ERESOURCE   Maximum number of SQ profiles on this slice used.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                               la_rx_cgm_sq_profile* profile,
                                               la_uint_t group_index,
                                               la_uint_t drop_counter_index)
        = 0;

    /// @brief   Get the mapping for a given RXCGM source queue to an SQ profile, SQ group, and drop
    /// counter
    ///
    /// @param[in]    tc                      Traffic class to get mapping for.
    /// @param[out] out_profile               SQ profile set for given TC.
    /// @param[out] out_group_index           The index of the SQG set for given TC.
    /// @param[out] out_drop_counter_index    The index of the drop counter set for the given TC.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mapping successfully retrieved.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter supplied.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_tc_rx_cgm_sq_mapping(la_traffic_class_t tc,
                                               la_rx_cgm_sq_profile*& out_profile,
                                               la_uint_t& out_group_index,
                                               la_uint_t& out_drop_counter_index)
        = 0;

    /// @brief Set PFC watchdog monitoring for a given output queue.
    ///
    /// Enabling PFC watchdog queue monitoring starts the monitoring of an outputq, based upon the configured
    /// polling interval. It monitors whether a queue becomes stuck due to excessive PFC packets being received.
    /// The definition of a stuck outputq is:
    /// Queue is non-empty.
    /// Queue has not transmitted anything since the previous polling interval.
    /// PFC packets have been received for that class that maps to that queue.
    /// If the queue is stuck a notification, PFC_WATCHDOG, is sent to the application.
    /// Once the notification is sent, monitoring is automatically disabled for that class.
    ///
    /// @param[in]   pfc_priority        PFC priority to monitor.
    /// @param[in]   enabled             True to enable watchdog monitoring; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_queue_watchdog_enabled(la_pfc_priority_t pfc_priority, bool enabled) = 0;

    /// @brief Get PFC watchdog monitoring state for a given PFC priority.
    ///
    /// @param[in]   pfc_priority        PFC priority
    /// @param[out]  out_enabled         True if watchdog monitoring is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_queue_watchdog_enabled(la_pfc_priority_t pfc_priority, bool& out_enabled) const = 0;

    /// @brief Set PFC watchdog polling interval.
    /// Note that this function also restarts the timer.
    ///
    /// @param[in]   polling_interval        Polling interval for monitoring stuck queue. Will be rounded up to a multiple of 100ms.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_watchdog_polling_interval(std::chrono::milliseconds polling_interval) = 0;

    /// @brief Set PFC watchdog polling interval for a traffic class.
    ///
    /// @param[in]   pfc_priority            Traffic class to set the PFC wdog polling interval value.
    /// @param[in]   polling_interval        Polling interval for monitoring stuck queue. Will be rounded up to a multiple of 100ms.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_queue_watchdog_polling_interval(la_pfc_priority_t pfc_priority,
                                                              std::chrono::milliseconds polling_interval)
        = 0;

    /// @brief Get PFC watchdog polling interval.
    ///
    /// @param[out]  out_interval             Polling interval for monitoring stuck queue.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_watchdog_polling_interval(std::chrono::milliseconds& out_interval) const = 0;

    /// @brief Get PFC watchdog polling interval for a traffic class.
    ///
    /// @param[in]   pfc_priority             Traffic class to get the PFC wdog polling interval.
    /// @param[out]  out_interval             Polling interval for monitoring stuck queue.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_queue_watchdog_polling_interval(la_pfc_priority_t pfc_priority,
                                                              std::chrono::milliseconds& out_interval) const = 0;

    /// @brief Set PFC watchdog recovery interval.
    ///
    /// @param[in]   recovery_interval        Recovery interval for monitoring stuck queue. Will be rounded up to a multiple of
    /// 100ms.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_watchdog_recovery_interval(std::chrono::milliseconds recovery_interval) = 0;

    /// @brief Set PFC watchdog recovery interval for a traffic class.
    ///
    /// @param[in]   pfc_priority             Traffic class to set the PFC wdog recovery interval.
    /// @param[in]   recovery_interval        Recovery interval for monitoring stuck queue. Will be rounded up to a multiple of
    /// 100ms.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_queue_watchdog_recovery_interval(la_pfc_priority_t pfc_priority,
                                                               std::chrono::milliseconds recovery_interval)
        = 0;

    /// @brief Get PFC watchdog recovery interval.
    ///
    /// @param[out]  out_interval             Recovery interval for monitoring stuck queue.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_watchdog_recovery_interval(std::chrono::milliseconds& out_interval) const = 0;

    /// @brief Get PFC watchdog recovery interval for a traffic class.
    ///
    /// @param[in]   pfc_priority             Traffic class to get the PFC wdog polling interval.
    /// @param[out]  out_interval             Recovery interval for monitoring stuck queue.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_queue_watchdog_recovery_interval(la_pfc_priority_t pfc_priority,
                                                               std::chrono::milliseconds& out_interval) const = 0;

    /// @brief Read dropped packet count for a queue that is in queue state DROPPING for a given PFC priority class.
    ///
    /// @param[in]   pfc_priority        PFC priority to monitor.
    /// @param[in]   clear_on_read       Reset the counter after reading.
    /// @param[out]  out_dropped_packets Packet count of dropped packets.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE   Counter was not allocated.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status read_pfc_queue_drain_counter(la_pfc_priority_t pfc_priority, bool clear_on_read, size_t& out_dropped_packets)
        = 0;

    /// @brief  Allocate a counter set for an output queue. This api allocates a set of unicast and multicast counters for a
    /// given queue.
    ///
    /// @param[in]   oq_id        output queue id to monitor.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE       Counter was not allocated.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Port's slice mode is not Network.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status allocate_counter(la_oq_id_t oq_id) = 0;

    /// @brief  Deallocate a counter set for an output queue. This api deallocates a set of unicast and multicast counters
    /// allocated to a given queue.
    ///
    /// @param[in]   oq_id        output queue id to monitor.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Port's slice mode is not Network.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status deallocate_counter(la_oq_id_t oq_id) = 0;

    /// @brief Read unicast byte and packet queue counters for a given output queue.
    ///
    /// @param[in]   oq_id            output queue to read counters for.
    /// @param[in]   clear_on_read    Reset the counter after reading.
    /// @param[out]  out_counters     Unicast byte and packet counters.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Port's slice mode is not Network.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status read_output_queue_uc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_counters) = 0;

    /// @brief Read  multicast byte and packet queue counters for a given output queue.
    ///
    /// @param[in]   oq_id            output queue to read counters for.
    /// @param[in]   clear_on_read    Reset the counters after reading.
    /// @param[out]  out_counters     Unicast byte and packet counters.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Port's slice mode is not Network.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status read_output_queue_mc_counter(la_oq_id_t oq_id, bool clear_on_read, output_queue_counters& out_counters) = 0;
    /// @brief Set output queue state for a given PFC priority class.
    ///
    /// When setting the queue state to DROPPING, a counter will be allocated which can be read via a read_pfc_queue_drain_counter
    /// API.
    /// The counter is released when the queue state is returned to ACTIVE.
    ///
    /// @param[in]   pfc_priority          PFC priority.
    /// @param[in]   state                 State of the queue for a given PFC priority.
    /// @param[out]  out_counter_allocated True if a counter was allocated for counting drops; False otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_queue_configured_state(la_pfc_priority_t pfc_priority,
                                                     pfc_config_queue_state_e state,
                                                     bool& out_counter_allocated)
        = 0;

    /// @brief Get output queue state for a given PFC priority.
    ///
    /// @param[in]   pfc_priority        PFC priority.
    /// @param[out]  out_state           State of the queue for a given PFC priority.
    /// @param[out]  out_counter_allocated True if a counter was allocated for counting drops; False otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_queue_configured_state(la_pfc_priority_t pfc_priority,
                                                     pfc_config_queue_state_e& out_state,
                                                     bool& out_counter_allocated)
        = 0;

    /// @brief Get the dynamic queue state from the last polling period for a given PFC priority class.
    /// @param[in]   pfc_priority        PFC priority.
    /// @param[out]  out_state           Dynamic queue state.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE Parameter is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_queue_state(la_pfc_priority_t pfc_priority, pfc_queue_state_e& out_state) = 0;

    /// @brief Set for which priority classes incoming PFC XOFF packets should be respected (i.e. stop sending traffic)
    /// By default, all priorities are enabled. This API should only be called when no traffic is flowing.
    ///
    /// @param[in]  tc_bitmap             Bitmap of traffic classes to enable receiving XOFF packets for.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occured.
    virtual la_status set_pfc_tc_xoff_rx_enable(la_uint8_t tc_bitmap) = 0;

    /// @}

protected:
    ~la_mac_port() override = default;
};
}

/// @}

#endif
