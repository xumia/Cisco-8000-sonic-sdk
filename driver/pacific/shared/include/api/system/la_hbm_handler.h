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

#ifndef __LA_HBM_HANDLER_H__
#define __LA_HBM_HANDLER_H__

/// @file
/// @brief Leaba HBM Handler API-s.
///
/// Defines API-s for managing and using HBM.
///

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "common/bit_vector.h"
#include <chrono>

/// @addtogroup SYSTEM
/// @{

namespace silicon_one
{

/// @brief An HBM handler.
///
/// @details An HBM handler used to control and manage HBM interfaces.
///
class la_hbm_handler : public la_object
{
public:
    /// @brief HBM error counters.
    struct error_counters {
        la_uint16_t write_data_parity;              ///< Write data parity errors indicated by HBM die.
        la_uint16_t write_data_parity_per_dword[4]; ///< Write data parity errors per dword in channel indicated by HBM die.

        la_uint16_t addr_parity; ///< Address (row or column) parity errors indicated by HBM die.

        la_uint16_t one_bit_ecc; ///< 1b ECC errors on HBM interface.
        la_uint16_t two_bit_ecc; ///< 2b ECC errors on HBM interface.

        la_uint16_t read_data_parity; ///< Read data parity errors.

        la_uint16_t pseudo_channel_one_bit_ecc[2];      ///< 1b ECC errors on HBM interface per pseudo-channel.
        la_uint16_t pseudo_channel_read_data_parity[2]; ///< Read data parity errors on HBM inteface per pseudo-channel.
        la_uint16_t pseudo_channel_crc_error[2];        ///< CRC-8 errors on HBM inteface per pseudo-channel.
    };

    /// @brief HBM DRAM buffer cell.
    struct dram_buffer_cell {
        uint8_t bank;    ///< Bank of the HBM DRAM buffer.
        uint8_t channel; ///< Channel of the HBM DRAM buffer.
        uint16_t row;    ///< Row of the HBM DRAM buffer.
        uint8_t column;  ///< Column of the HBM DRAM buffer.
    };

    /// @brief Execute Memory Built-In Self-Test test on HBM interfaces.
    ///
    /// @param[in]  repair              True to repair, false just test.
    ///
    /// @retval     LA_STATUS_SUCCESS   Test completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  Test failed. Detailed failure information exists in the log.
    virtual la_status run_mbist(bool repair) = 0;

    /// @brief Read error counters for HBM interface & channel.
    ///
    /// @param[in]  hbm_interface       HBM interface index.
    /// @param[in]  channel             Channel ID on the HBM interface to read from.
    /// @param[out] out_err_counters    Contains HBM channel's error counter values.
    ///
    /// @retval     LA_STATUS_SUCCESS   Contains the HBM channel's error counter values.
    /// @retval     LA_STATUS_EINVAL    Invalid HBM channel ID.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_error_counters(size_t hbm_interface,
                                          size_t channel,
                                          la_hbm_handler::error_counters& out_err_counters) const = 0;

    /// @brief Upload firmware file.
    ///
    /// @note  This API is exposed for debug use only.
    ///
    /// @param[in]  file_path           Firmware file path.
    ///
    /// @retval     LA_STATUS_SUCCESS   Firmware file uploaded successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status upload_firmware(const char* file_path) = 0;

    /// @brief Retrieve firmware version ID.
    ///
    /// @param[out] out_fw_id           Firmware version ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Firmware version ID retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_firmware_version_id(la_uint_t& out_fw_id) = 0;

    /// @brief Retrieve firmware build ID.
    ///
    /// @param[out] out_build_id        Firmware build ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Firmware build ID retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_firmware_build_id(la_uint_t& out_build_id) = 0;

    /// @brief Enable or disable HBM IEEE1500 die-level interfaces.
    ///
    /// @param[in]  enabled     true if HBM IEEE1500 die-level interfaces should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation succeeded.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_die_ieee1500_enabled(bool enabled) = 0;

    /// @brief  Check if HBM IEEE1500 die-level interfaces are enabled or disabled.
    ///
    /// @retval true if HBM IEEE1500 die-level interfaces is enabled; false otherwise.
    virtual bool get_die_ieee1500_enabled() const = 0;

    /// @brief Write to HBM die through IEEE1500.
    ///
    /// @param[in]  hbm_interface   Index of HBM interface.
    /// @param[in]  reg_addr        Register address.
    /// @param[in]  channel_addr    Physical channel within HBM memory.
    /// @param[in]  width_bits      Width of the input data in bits.
    /// @param[in]  in_bv           Input data.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation succeeded.
    /// @retval     LA_STATUS_EINVAL            Invalid arguments.
    /// @retval     LA_STATUS_ENOTINITIALIZED   IEEE1500 is not enabled.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status die_ieee1500_write(size_t hbm_interface,
                                         uint32_t reg_addr,
                                         uint32_t channel_addr,
                                         size_t width_bits,
                                         const bit_vector& in_bv)
        = 0;

    /// @brief Read from HBM die through IEEE1500.
    ///
    /// @param[in]  hbm_interface   Index of HBM interface.
    /// @param[in]  reg_addr        Register address.
    /// @param[in]  channel_addr    Physical channel within HBM memory.
    /// @param[in]  width_bits      Width of the output data in bits.
    /// @param[in]  reverse         Whether to reverse the output bits.
    /// @param[out] out_bv          Output data.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation succeeded.
    /// @retval     LA_STATUS_EINVAL            Invalid arguments.
    /// @retval     LA_STATUS_ENOTINITIALIZED   IEEE1500 is not enabled.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status die_ieee1500_read(size_t hbm_interface,
                                        uint32_t reg_addr,
                                        uint32_t channel_addr,
                                        size_t width_bits,
                                        bool reverse,
                                        bit_vector& out_bv)
        = 0;

    /// @brief Limit the rate of traffic to the HBM.
    ///
    ///
    /// @param[in]  rate_limit      Limit rate in bits per second (bps).
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation succeeded.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_rate_limit(const la_rate_t rate_limit) = 0;

    /// @brief Get the rate limit for the traffic to the HBM.
    ///
    ///
    /// @param[out]  out_rate_limit Limit rate in bits per second (bps).
    virtual void get_rate_limit(la_rate_t& out_rate_limit) const = 0;

    /// @brief Start measuring traffic rate to the HBM.
    ///
    /// @param[in]  duration                   Rate measuring duration.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation succeeded.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred
    virtual la_status start_rate_measurement(const std::chrono::seconds duration) = 0;

    /// @brief Check if result of rate measurement can be retrived.
    ///
    ///
    /// @retval     true    There is a result to retrive
    /// @retval     false   There is no available result to retrive
    virtual bool is_rate_measurement_completed() const = 0;

    /// @brief Read last result of trafic rate measurement to the HBM.
    ///
    /// @note Use with #silicon_one::la_hbm_handler::is_rate_measurement_completed.
    ///
    /// @param[in]  clear_on_read   Clear last result
    /// @param[out] out_rate        The last caclulated rate in bits per second (bps).
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation succeeded.
    /// @retval     LA_STATUS_EAGAIN           Result not available at the moment.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status read_rate(bool clear_on_read, la_rate_t& out_rate) = 0;

    /// @brief Callback function will be called for measurement completion.
    typedef la_status (*on_done_function_t)(la_rate_t&);

    /// @brief Set on done callback function.
    ///
    /// @param[in]  on_done_cb    Function to be called when measurement is done, can be nullptr/None (C++/Python).
    virtual void register_read_cb(on_done_function_t on_done_cb) = 0;

    /// @brief Write DRAM buffer.
    ///
    /// @note  This API is exposed for debug use only.
    ///
    /// @param[in]  cell    DRAM buffer cell.
    /// @param[in]  in_bv   Input data.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation succeeded.
    /// @retval     LA_STATUS_EINVAL            Invalid arguments.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status dram_buffer_write(const dram_buffer_cell& cell, const bit_vector& in_bv) = 0;

    /// @brief Read DRAM buffer
    ///
    /// @note  This API is exposed for debug use only.
    ///
    /// @param[in]  cell    DRAM buffer cell.
    /// @param[out] out_bv  Output data.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation succeeded.
    /// @retval     LA_STATUS_EINVAL            Invalid arguments.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status dram_buffer_read(const dram_buffer_cell& cell, bit_vector& out_bv) = 0;

protected:
    ~la_hbm_handler() override = default;
};
}

/// @}

#endif // __LA_HBM_HANDLER_H__
