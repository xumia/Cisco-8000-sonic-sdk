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

#ifndef __LA_PTP_HANDLER_H__
#define __LA_PTP_HANDLER_H__

/// @file
/// @brief Silicon One PTP Handler API-s.
///
/// Defines API-s for managing and using PTP commands.
///

#include "api/types/la_object.h"
#include "api/types/la_system_types.h"

/// @addtogroup SYSTEM
/// @{

namespace silicon_one
{

/// @brief Precision Time Protocol (PTP) Handler.
///
/// @details A PTP handler that controls and manages PTP commands.
///
class la_ptp_handler : public la_object
{
public:
    /// @brief PTP Pad configuration register.
    struct ptp_pads_config {
        bool device_time_load_enable;          ///< Enable DEVICE_TIME_LOAD pad.
        la_uint16_t device_time_load_delay;    ///< Delay for DEVICE_TIME_LOAD in clock cycles.
        bool device_time_sync_ck_enable;       ///< Enable DEVICE_TIME_SYNC_CK pad.
        la_uint16_t device_time_sync_ck_delay; ///< Delay for clock time sync in clock cycles.
    };

    /// @brief PTP network times.
    struct ptp_time {
        uint64_t device_time; ///< Device Time value in nanoseconds.
        uint64_t time_of_day; ///< Time of Day value in seconds.
    };

    /// @brief Values to update PTP rate.
    struct ptp_time_unit {
        uint64_t frequency;             ///< Frequency, in hz, at which to update device time. Ex) 1GHz = 1ns increment per period.
        uint8_t clock_frac_comp_val;    ///< Compensation value to add every compensation period.
        uint8_t clock_frac_comp_period; ///< Compensation period clock time.
    };

    /// @brief Values to update PTP rate.
    struct ptp_sw_tuning_config {
        bool increment;  ///< Set tuning module to increment or stall the device time.
        uint64_t period; ///< Define the number of clock cycles to wait before applying stall or increment to device time.
        uint64_t repeat; ///< Define how many times to repeat tuning.
    };

    /// @brief  Set device in a mode that will trigger DEVICE_TIME_LOAD event after any PTP API call.
    ///
    /// @param[in]   enabled          When set to true, CPU acts in place of external signal DEVICE_TIME_LOAD.
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status enable_load_event_generation(bool enabled) = 0;

    /// @brief  Set PTP pads configuration.
    ///
    /// @param[in]  config            Values to configure PTP pads.
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_pad_config(ptp_pads_config config) const = 0;

    /// @brief  Get PTP pads configuration.
    ///
    /// @param[out]  out_config       Returns config values for pads.
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_pad_config(ptp_pads_config& out_config) const = 0;

    /// @brief  Set PTP Load Time Offset value.
    ///
    /// @param[in]   offset           Offset to compensate for DEVICE_TIME_LOAD delay in sub-nanoseconds (2^20 sub-ns == 1 ns).
    ///
    /// @retval LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval LA_STATUS_EOUTOFRANGE      Value provided is out of range.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_load_time_offset(la_uint64_t offset) const = 0;

    /// @brief  Get current PTP Load Time Offset value.
    ///
    /// @param[out]   out_offset      Offset set for DEVICE_TIME_LOAD varience in sub-nanoseconds (2^20 sub-ns == 1 ns).
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_load_time_offset(la_uint64_t& out_offset) const = 0;

    /// @brief  Adjust PTP Load Time using SW-TUNING.
    ///
    /// @param[in]   adjustment       Value to stall / increment Device Time by in nanoseconds
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_EOUTOFRANGE      Value provided is out of range.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status adjust_device_time(ptp_sw_tuning_config adjustment) const = 0;

    /// @brief Update PTP network times.
    ///
    /// @param[in]  load_time           Network times to load into device.
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_EOUTOFRANGE      Network time is out of range.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status load_new_time(ptp_time load_time) const = 0;

    /// @brief  Get device network times.
    ///
    /// @param[out]  out_load_time    Network times captured at DEVICE_TIME_LOAD rising edge.
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status capture_time(ptp_time& out_load_time) const = 0;

    /// @brief  Update PTP rate.
    ///
    /// @param[in] time_unit          Structure holding frequency and fraction compensation values
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_EOUTOFRANGE      Value provided is out of range.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status load_new_time_unit(ptp_time_unit time_unit) const = 0;

    /// @brief  Get PTP rate.
    ///
    /// @param[in] out_time_unit      Structure holding frequency and fraction compensation values
    ///
    /// @retval LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval LA_STATUS_EOUTOFRANGE      Value provided is out of range.
    /// @retval LA_STATUS_ENOTIMPLEMENTED  Funcionality is not implemented.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_time_unit(ptp_time_unit& out_time_unit) const = 0;

protected:
    ~la_ptp_handler() override = default;
};
}

/// @}

#endif // __LA_PTP_HANDLER_H__
