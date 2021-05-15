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

#ifndef __PACIFIC_PVT_HANDLER_H__
#define __PACIFIC_PVT_HANDLER_H__

#include "hld_types_fwd.h"
#include "pvt_handler.h"
#include <chrono>

namespace silicon_one
{

class pacific_pvt_handler : public pvt_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit pacific_pvt_handler(la_device_impl_wptr dev);
    virtual ~pacific_pvt_handler();

    la_device_id_t get_device_id() const;

    la_status initialize() override;
    void periodic_poll_sensors() override;
    la_status get_temperature(la_temperature_sensor_e sensor, la_temperature_t& temperature_out) override;
    la_status get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage) override;

private:
    la_device_impl_wptr m_device;

    enum {
        MAX_CACHED_TEMPERATURE_SENSORS = 2,
        MAX_CACHED_VOLTAGE_SENSORS = 4,
        MAX_AVAGO_SBUS_RINGS = 2,
    };

    std::chrono::time_point<std::chrono::steady_clock> m_next_poll_time;
    std::chrono::time_point<std::chrono::steady_clock> m_fail_temp_time[MAX_CACHED_TEMPERATURE_SENSORS];
    la_temperature_t m_cached_temp_sensor[MAX_CACHED_TEMPERATURE_SENSORS];
    la_voltage_t m_cached_volt_sensor[MAX_CACHED_VOLTAGE_SENSORS];

    std::chrono::time_point<std::chrono::steady_clock> m_sensor_poll_time;

    enum class sensor_stage_e {
        SBUS_SENSOR_FIRST = 0,
        SBUS_SENSOR_TEMP_START = SBUS_SENSOR_FIRST,
        SBUS_SENSOR_TEMP_READ,
        SBUS_SENSOR_VOLT_START,
        SBUS_SENSOR_VOLT_READ,
        SBUS_SENSOR_VOLT2_START,
        SBUS_SENSOR_VOLT2_READ,
        SBUS_SENSOR_LAST = SBUS_SENSOR_VOLT2_READ,
    };

    sensor_stage_e m_sensor_stage;

    // For serialization purposes only
    pacific_pvt_handler() = default;
};

} // namespace silicon_one

#endif // __PACIFIC_PVT_HANDLER_H__
