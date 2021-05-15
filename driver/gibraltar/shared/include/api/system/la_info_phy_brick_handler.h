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

#ifndef __INFO_PHY_BRICK_HANDLER_H__
#define __INFO_PHY_BRICK_HANDLER_H__

#include "api/types/la_common_types.h"
#include "common/la_status.h"

/// @file
/// @brief InFO Brick handler.
///
/// @details An InFO brick handler to control and manage specific InFO brick.
///

namespace silicon_one
{

class la_info_phy_brick_handler
{
public:
    /// @brief PRBS mode.
    enum info_pmd_prbs_mode_e {
        PRBS7 = 0,
        PRBS9 = 1,
        PRBS15 = 2,
        PRBS31 = 3,
    };

    /// @brief Link operational Mode.
    enum info_pmd_link_mode_e {
        LANE_TRAINING = 0,
        MISSION_MODE = 1,
        PRBS = 2,
        CONSTANT_CFG_PATTERN = 3,
    };

    /// @brief PR position' calibration mode.
    enum pr_cal_mode {
        SINGLE_LANE_CAL = 0,
        FULL_CAL = 1,
    };

    /// @brief Brick location.
    enum class info_brick_location_e {
        MAIN_DIE = 0, ///< INFO PHY Brick located in Main Die.
        CHIPLET       ///< INFO PHY Brick located in Chiplet Die.
    };

    /// @brief Lane direction.
    enum class info_lane_direction_e {
        TX = 0, ///< Transmit.
        RX = 1  ///< Receive.
    };

    /// @brief InFo Limits.
    enum class info_limits_e { MAX_LINKS = 0, MAX_DATA_LANES, MAX_REDUNDANT_LANES };

    /// @brief link counters.
    struct info_link_counters {
        la_uint64_t link_prbs_err_cnt;
        la_uint64_t link_crc_err_cnt;
        la_uint64_t link_ecc2_err_cnt;
        la_uint64_t link_ecc1_err_cnt;
    };

    /// @brief lane counters.
    struct info_lane_counters {
        la_uint64_t link_lanes_prbs_err_cnt;
    };

    /// @brief Get InFO Brick limit information.
    ///
    /// General Getter for InFO Brick info.
    ///
    /// @param[in]  limit               limit type to be queried.
    /// @param[out] out_val             queried value.
    ///
    /// @retval LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status get_limit(info_limits_e limit, size_t& out_val) const = 0;

    /// @brief Initialize Set Spare Lane.
    ///
    /// @param[in]  link         Link of lane to be spared.
    /// @param[in]  lane         Lane to be spared.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Lane out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_spare_lane(size_t link, size_t lane) = 0;

    /// @brief Retrieve spare lane of a specific link.
    ///
    /// @param[out]  out_link         Link of Spared lane.
    /// @param[out]  out_lane         Spared Lane.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Lane out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_spare_lane(size_t& out_link, size_t& out_lane) const = 0;

    /// @brief Get InFO Phy Brick ID.
    ///
    /// @retval     Brick ID.
    virtual size_t get_brick_id() const = 0;

    /// @brief Initialize InFO Brick PLL.
    ///
    /// @param[in]  freq_in_mhz           Clock Frequency in MHz.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status initialize_pll(size_t freq_in_mhz) = 0;

    /// @brief Get PLL lock status.
    ///
    /// @param[out] out_lock             queried lock status.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pll_locked(bool& out_lock) const = 0;

    /// @brief Initialize analog.
    ///
    /// @param[in]  direction           lane direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status initialize_analog(info_lane_direction_e direction) = 0;

    /// @brief Initialize digital.
    ///
    /// @param[in]  direction           lane direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status initialize_digital(info_lane_direction_e direction) = 0;

    /// @brief Activate Bricks.
    ///
    /// @param[in]  direction           lane direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status activate(info_lane_direction_e direction) = 0;

    /// @brief Set Analog Register.
    ///
    /// @param[in]  direction           lane direction.
    /// @param[in]  addr                Address to be set.
    /// @param[in]  data                Data to be set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_analog_indirect(info_lane_direction_e direction, size_t addr, size_t data) = 0;

    /// @brief Get Analog Register.
    ///
    /// @param[in]   direction          lane direction.
    /// @param[in]   addr               Address to be get.
    /// @param[out]  out_data           Data to be get.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_analog_indirect(info_lane_direction_e direction, size_t addr, size_t& out_data) = 0;

    /// @brief Get Check Analog set done.
    ///
    /// @param[in]   direction          lane direction.
    /// @param[out]  out_done           Indirection command done.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status is_analog_indirect_done(info_lane_direction_e direction, bool& out_done) = 0;

    /// @brief Get Poll Analog indirection Completion.
    ///
    /// @param[in]   direction          lane direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status wait_for_analog_indirect_done(info_lane_direction_e direction) = 0;

    /// @brief Enable Analog Clocks of all Lanes in the Brick.
    ///
    /// @param[in]   direction          lane direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status enable_clocks(info_lane_direction_e direction) = 0;

    /// @brief Set Tx lane PRBS mode.
    ///
    /// @param[in]  lane           lane ID.
    /// @param[in]  prbs_mode      PRBS mode.
    /// @param[in]  seed           PRBS's seed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tx_lane_prbs_mode(size_t lane, info_pmd_prbs_mode_e prbs_mode, size_t seed) = 0;

    /// @brief Set Rx lane PRBS mode.
    ///
    /// @param[in]  lane           lane ID.
    /// @param[in]  prbs_mode      PRBS mode.
    /// @param[in]  locked         PRBS locked.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_rx_lane_prbs_mode(size_t lane, info_pmd_prbs_mode_e prbs_mode, size_t locked) = 0;

    /// @brief Set Tx lane PRBS mode.
    ///
    /// @param[in]  prbs_mode      PRBS mode.
    /// @param[in]  seed           PRBS seed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tx_lane_prbs_mode(info_pmd_prbs_mode_e prbs_mode, size_t seed) = 0;

    /// @brief Set Rx lane PRBS mode.
    ///
    /// @param[in]  prbs_mode      PRBS mode.
    /// @param[in]  locked         PRBS locked.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_rx_lane_prbs_mode(info_pmd_prbs_mode_e prbs_mode, size_t locked) = 0;

    /// @brief Set Tx lane PRBS Constant Pattern.
    ///
    /// @param[in]  lane           Lane ID.
    /// @param[in]  const_pattern  PRBS constant pattern.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tx_lane_prbs_const_pattern(size_t lane, size_t const_pattern) = 0;

    /// @brief Enable RS-FEC.
    ///
    /// @param[in]  link      Link.
    /// @param[in]  enable    Enable or Disable RS-FEC.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status enable_rs_fec(size_t link, bool enable) = 0;

    /// @brief Read RS-FEC Counters.
    ///
    /// @param[in]  link            Link.
    /// @param[out] out_counters    RS-FEC Counters.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_rs_fec_counter(size_t link, info_link_counters& out_counters) const = 0;

    /// @brief Set Link Alignment Marker Period.
    ///
    /// @param[in]  link            Link.
    /// @param[in]  lane            Lane.
    /// @param[in]  period          Alignment Marker Period.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_link_alignment_marker_period(size_t link, size_t lane, size_t period) = 0;

    /// @brief Get Lane Word Lock.
    ///
    /// @param[in]  link            Link.
    /// @param[in]  lane            Lane.
    /// @param[out] out_lock        Word Lock indication.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_word_lock(size_t link, size_t lane, bool& out_lock) const = 0;

    /// @brief Wait for Lane Word Lock for all lanes in Brick.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status wait_for_word_lock() const = 0;

    /// @brief Set Brick to Mission mode.
    ///
    /// @param[in]   direction          lane direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mission_mode(info_lane_direction_e direction) = 0;

    /// @brief Set Brick to Specific Link Mode.
    ///
    /// @param[in]   direction          lane direction.
    /// @param[in]   link_mode          link mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_link_mode(info_lane_direction_e direction, info_pmd_link_mode_e link_mode) = 0;

    /// @brief Set specific Brick link to specific link mode.
    ///
    /// @param[in]   link               link ID.
    /// @param[in]   direction          lane direction.
    /// @param[in]   link_mode          link mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_link_mode(size_t link, info_lane_direction_e direction, info_pmd_link_mode_e link_mode) = 0;

    /// @brief Reset link.
    ///
    /// @param[in]  link           link ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status reset_link(size_t link) = 0;

    /// @brief Set Enable or Disable Analog Synchronization Chain.
    ///
    /// @param[in]   direction          lane direction.
    /// @param[in]   enable             Enable or Disable.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status enable_synchronization_chain(info_lane_direction_e direction, bool enable) = 0;

    /// @brief Set Comparator Voltage Offset.
    ///
    /// @param[in]   offset             Comparator Voltage Offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_comparator_voltage_offset(size_t offset) = 0;

    /// @brief Set Lane's IQ Control.
    ///
    /// @param[in]   lane             Lane ID.
    /// @param[in]   iq_contrl        IQ Control.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_iq_control(size_t lane, size_t iq_contrl) = 0;

    /// @brief Set IQ Control for all Lanes.
    ///
    /// @param[in]   iq_contrl        IQ Control.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_iq_control(size_t iq_contrl) = 0;

    /// @brief Calibrate Phase Rotator IQ Control.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status calibrate_phase_rotator_iq() = 0;

    /// @brief Calibrate Phase Rotator Position.
    ///
    /// @param[in]  cal_mode            Calibration Mode.
    /////
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status calibrate_phase_rotator_position(pr_cal_mode cal_mode) = 0;

    /// @brief Calibrate Single Lane Phase Rotator Position.
    ///
    /// @param[in]  lane                Lane ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status calibrate_phase_rotator_position_single_lane(size_t lane) = 0;

    /// @brief Measure Phase Rotator IQ Control.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status measure_phase_rotator_iq() = 0;

    /// @brief Set Phase Rotator Position.
    ///
    /// @param[in]  pr_pos                Phase Rotator Position.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_phase_rotator_position(size_t pr_pos) = 0;

    /// @brief Measure Phase Rotator Bath Tub for All Lanes.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status measure_bath_tub() = 0;

    /// @brief Measure Phase Rotator Bath Tub.
    ///
    /// @param[in]  lane_id             Lane ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status measure_bath_tub(size_t lane_id) = 0;

    /// @brief Set Enable Mission mode Link PRBS.
    ///
    /// @param[in]   link               Link ID.
    /// @param[in]   direction          Lane direction.
    /// @param[in]   enable             Enable.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mission_mode_prbs(size_t link, info_lane_direction_e direction, bool enable) = 0;

    /// @brief Read Rx Link Counters.
    ///
    /// @param[in]   link                       Link ID.
    /// @param[out]  out_info_link_counters     Rx Link Counters.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_rx_link_counters(size_t link, info_link_counters& out_info_link_counters) = 0;

    /// @brief Set Tx Link Error Injection.
    ///
    /// @param[in]   link               Link ID.
    /// @param[in]   enable             Enable.
    /// @param[in]   cycles             Error Injection Cycles.
    /// @param[in]   burst              Error Injection Burst.
    /// @param[in]   mask_map           Error Injection Mask Map.
    /// @param[in]   mask_p0            Error Injection Mask P0.
    /// @param[in]   mask_p1            Error Injection Mask P1.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status
    set_tx_link_err_inject(size_t link, bool enable, size_t cycles, size_t burst, size_t mask_map, size_t mask_p0, size_t mask_p1)
        = 0;

    /// @brief Dump and Print Analog Data to a File.
    ///
    /// @param[in]   file_name                 File name to dump the Data to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status print_bath_tub_data(std::string file_name) = 0;

protected:
    virtual ~la_info_phy_brick_handler() = default;
};
}

#endif // __LA_INFO_PHY_BRICK_HANDLER_H__
