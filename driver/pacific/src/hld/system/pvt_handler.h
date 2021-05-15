// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __PVT_HANDLER_H__
#define __PVT_HANDLER_H__

#include "api/types/la_system_types.h"

namespace silicon_one
{

class pvt_handler
{
public:
    static constexpr la_temperature_t SIMULATED_TEMPERATURE = 35.0;        ///< Temperature to report for a simulated device.
    static constexpr la_temperature_t MIN_EXPECTED_TEMPERATURE = -100.0;   ///< Minumum expected temperature is -100C.
    static constexpr la_temperature_t INVALID_CACHED_TEMPERATURE = -273.0; ///< Invalid temperature value.

    static constexpr la_voltage_t SIMULATED_VOLTAGE = 1.0;          ///< Voltage to report for a simulated device.
    static constexpr la_voltage_t MIN_EXPECTED_VOLTAGE = 0.0;       ///< Minimum expected voltage is 0.
    static constexpr la_voltage_t INVALID_CACHED_VOLTAGE = -1000.0; ///< Invalid voltage value.

    virtual ~pvt_handler(){};

    virtual la_status initialize() = 0;
    virtual void periodic_poll_sensors() = 0;
    virtual la_status get_temperature(la_temperature_sensor_e sensor, la_temperature_t& temperature_out) = 0;
    virtual la_status get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage) = 0;
};

} // namespace silicon_one

#endif // __PVT_HANDLER_H__
