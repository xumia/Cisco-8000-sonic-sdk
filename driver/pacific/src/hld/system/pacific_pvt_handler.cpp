// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "pacific_pvt_handler.h"
#include "aapl/aapl.h"
#include "aapl_impl.h"
#include "api_tracer.h"
#include "avago_serdes_device_handler.h"
#include "common/logger.h"
#include "la_device_impl.h"

#include <chrono>

using namespace std;

namespace silicon_one
{

struct pacific_sensor_params {
    la_slice_id_t slice_id;
    la_ifg_id_t ifg_id;
    la_uint_t addr;
    la_int_t sensor;
    la_uint_t frequency;
};

// Array with temp sensors parameters
static pacific_sensor_params temp_sensors_params[(size_t)la_temperature_sensor_e::PACIFIC_LAST + 1] = {
    // Sensor in slice2
    {.slice_id = 2, .ifg_id = 0, .addr = 91, .sensor = 0, .frequency = 0},
    // Sensor in slice3
    {.slice_id = 3, .ifg_id = 1, .addr = 19, .sensor = 0, .frequency = 0}};

// Array with voltage sensors parameters
static pacific_sensor_params voltage_sensors_params[(size_t)la_voltage_sensor_e::PACIFIC_LAST + 1] = {
    // Sensor in slice2 = PACIFIC_SENSOR_1_VDD
    {.slice_id = 2, .ifg_id = 0, .addr = 91, .sensor = 0, .frequency = 0},
    // Sensor in slice2 = PACIFIC_SENSOR_1_AVDD
    {.slice_id = 2, .ifg_id = 0, .addr = 91, .sensor = 2, .frequency = 0},
    // Sensor in slice3 = PACIFIC_SENSOR_2_VDD
    {.slice_id = 3, .ifg_id = 1, .addr = 19, .sensor = 0, .frequency = 0},
    // Sensor in slice3 = PACIFIC_SENSOR_2_AVDD
    {.slice_id = 3, .ifg_id = 1, .addr = 19, .sensor = 2, .frequency = 0}};

pacific_pvt_handler::pacific_pvt_handler(la_device_impl_wptr dev) : m_device(dev)
{
    int interval;
    m_device->get_int_property(la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS, interval);

    auto now = chrono::steady_clock::now();
    for (size_t sensor = 0; sensor < array_size(m_cached_temp_sensor); ++sensor) {
        m_fail_temp_time[sensor] = now + chrono::milliseconds(interval);
        m_cached_temp_sensor[sensor] = INVALID_CACHED_TEMPERATURE;
    }

    for (size_t sensor = 0; sensor < array_size(m_cached_volt_sensor); ++sensor) {
        m_cached_volt_sensor[sensor] = INVALID_CACHED_VOLTAGE;
    }

    m_sensor_poll_time = now;
    m_sensor_stage = sensor_stage_e::SBUS_SENSOR_TEMP_START;
}

pacific_pvt_handler::~pacific_pvt_handler()
{
}

la_status
pacific_pvt_handler::initialize()
{
    return LA_STATUS_SUCCESS;
}

la_device_id_t
pacific_pvt_handler::get_device_id() const
{
    return m_device->m_ll_device->get_device_id();
}

la_status
pacific_pvt_handler::get_temperature(la_temperature_sensor_e sensor, la_temperature_t& out_temperature)
{
    if (sensor > la_temperature_sensor_e::PACIFIC_LAST) {
        log_err(PVT, "%s: sensor='%s'(%d) is not supported.", __func__, silicon_one::to_string(sensor).c_str(), (int)sensor);
        return LA_STATUS_EINVAL;
    }

    la_temperature_t temperature;

    if (m_device->is_simulated_or_emulated_device()) {
        temperature = pvt_handler::SIMULATED_TEMPERATURE;
    } else if (sensor <= la_temperature_sensor_e::PACIFIC_SENSOR_2) {
        temperature = m_cached_temp_sensor[(size_t)sensor];
        if (temperature == INVALID_CACHED_TEMPERATURE) {
            log_err(PVT, "%s: sensor=%s - invalid cached temperature", __func__, silicon_one::to_string(sensor).c_str());
            return LA_STATUS_EINVAL;
        }
    } else if (sensor <= la_temperature_sensor_e::PACIFIC_SENSOR_2_DIRECT) {

        bool poll_enabled = false;
        m_device->get_bool_property(la_device_property_e::ENABLE_SENSOR_POLL, poll_enabled);

        if (poll_enabled) {
            out_temperature = INVALID_CACHED_TEMPERATURE;
            log_err(PVT,
                    "%s: sensor=%s - direct access to sensors is not allowed when sensors polling is enabled",
                    __func__,
                    silicon_one::to_string(sensor).c_str());
            return LA_STATUS_EBUSY;
        }

        Aapl_t* aapl_handler;
        pacific_sensor_params current_sensor
            = temp_sensors_params[(size_t)sensor - (size_t)la_temperature_sensor_e::PACIFIC_SENSOR_1_DIRECT];
        la_status status = m_device->get_ifg_aapl_handler(current_sensor.slice_id, current_sensor.ifg_id, aapl_handler);
        return_on_error(status);

        temperature
            = avago_sensor_get_temperature(aapl_handler, current_sensor.addr, current_sensor.sensor, current_sensor.frequency);
        temperature /= 1000; // Convert to Celsius
        if (temperature < MIN_EXPECTED_TEMPERATURE) {
            log_err(PVT, "%s: sensor=%s - bad value", __func__, silicon_one::to_string(sensor).c_str());
            return LA_STATUS_EUNKNOWN;
        }

    } else {
        // HBM temperature sensor
        Aapl_t* aapl_handler;
        size_t hbm_idx = (sensor == la_temperature_sensor_e::PACIFIC_HBM_SENSOR_1 ? 0 : 1);
        la_status status = m_device->get_hbm_aapl_handler(hbm_idx, aapl_handler);
        return_on_error(status);

        temperature = avago_hbm_read_device_temp(aapl_handler, AVAGO_SPICO_BROADCAST);
        if (temperature < 0) {
            log_err(PVT, "%s: sensor=%s - bad value", __func__, silicon_one::to_string(sensor).c_str());
            return LA_STATUS_EUNKNOWN;
        }
    }

    log_debug(PVT, "%s: sensor=%s, value=%f", __func__, silicon_one::to_string(sensor).c_str(), temperature);
    out_temperature = temperature;

    return LA_STATUS_SUCCESS;
}

la_status
pacific_pvt_handler::get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage)
{
    if (sensor > la_voltage_sensor_e::PACIFIC_LAST) {
        return LA_STATUS_EINVAL;
    }

    la_voltage_t voltage;

    if (m_device->is_simulated_or_emulated_device()) {
        voltage = pvt_handler::SIMULATED_VOLTAGE;
    } else {
        voltage = m_cached_volt_sensor[(size_t)sensor];
    }

    if (voltage == INVALID_CACHED_VOLTAGE) {
        log_err(PVT, "%s: sensor=%s - invalid cached voltage", __func__, silicon_one::to_string(sensor).c_str());
        return LA_STATUS_EINVAL;
    }

    log_debug(PVT, "%s: sensor=%s, value=%f", __func__, silicon_one::to_string(sensor).c_str(), voltage);
    out_voltage = voltage;

    return LA_STATUS_SUCCESS;
}

void
pacific_pvt_handler::periodic_poll_sensors()
{
    // TODO: The below code should go away if polling at constant intervals is replaced with an event queue.
    int interval = 0;
    m_device->get_int_property(la_device_property_e::SENSOR_POLL_INTERVAL_MILLISECONDS, interval);

    bool enable_poll = false;
    m_device->get_bool_property(la_device_property_e::ENABLE_SENSOR_POLL, enable_poll);
    if (!enable_poll) {
        return;
    }

    auto now = chrono::steady_clock::now();
    std::chrono::time_point<std::chrono::steady_clock> next_temp_poll_time = m_sensor_poll_time + chrono::milliseconds(interval);
    if (now < next_temp_poll_time) {
        return;
    }
    m_sensor_poll_time = now;

    int ret = 0;

    Aapl_t* aapl_handler[MAX_AVAGO_SBUS_RINGS];
    la_temperature_sensor_e temp_sensor_list[MAX_AVAGO_SBUS_RINGS];
    la_voltage_sensor_e volt_sensor_list[MAX_AVAGO_SBUS_RINGS];

    la_status status;

    switch (m_sensor_stage) {

    case sensor_stage_e::SBUS_SENSOR_TEMP_START:
    case sensor_stage_e::SBUS_SENSOR_TEMP_READ:
        temp_sensor_list[0] = la_temperature_sensor_e::PACIFIC_SENSOR_1;
        temp_sensor_list[1] = la_temperature_sensor_e::PACIFIC_SENSOR_2;
        break;
    case sensor_stage_e::SBUS_SENSOR_VOLT_START:
    case sensor_stage_e::SBUS_SENSOR_VOLT_READ:
        volt_sensor_list[0] = la_voltage_sensor_e::PACIFIC_SENSOR_1_VDD;
        volt_sensor_list[1] = la_voltage_sensor_e::PACIFIC_SENSOR_2_VDD;
        break;
    case sensor_stage_e::SBUS_SENSOR_VOLT2_START:
    case sensor_stage_e::SBUS_SENSOR_VOLT2_READ:
        volt_sensor_list[0] = la_voltage_sensor_e::PACIFIC_SENSOR_1_AVDD;
        volt_sensor_list[1] = la_voltage_sensor_e::PACIFIC_SENSOR_2_AVDD;
        break;
    default:
        log_err(HLD, "%s: invalid sensor stage %d.", __func__, (int)m_sensor_stage);
        return;
    }

    switch (m_sensor_stage) {

    case sensor_stage_e::SBUS_SENSOR_TEMP_START:
    case sensor_stage_e::SBUS_SENSOR_TEMP_READ:
        for (int sensor = 0; sensor < MAX_AVAGO_SBUS_RINGS; sensor++) {
            auto current_sensor = temp_sensors_params[(int)temp_sensor_list[sensor]];
            status = m_device->get_ifg_aapl_handler(current_sensor.slice_id, current_sensor.ifg_id, aapl_handler[sensor]);
            return_void_on_error_log(
                status, HLD, DEBUG, "failed to get aapl handler for temperature sensor %d.", (int)temp_sensor_list[sensor]);
        }
        break;

    case sensor_stage_e::SBUS_SENSOR_VOLT_START:
    case sensor_stage_e::SBUS_SENSOR_VOLT_READ:
    case sensor_stage_e::SBUS_SENSOR_VOLT2_START:
    case sensor_stage_e::SBUS_SENSOR_VOLT2_READ:
        for (int sensor = 0; sensor < MAX_AVAGO_SBUS_RINGS; sensor++) {
            auto current_sensor = voltage_sensors_params[(int)volt_sensor_list[sensor]];
            status = m_device->get_ifg_aapl_handler(current_sensor.slice_id, current_sensor.ifg_id, aapl_handler[sensor]);
            return_void_on_error_log(
                status, HLD, DEBUG, "failed to get aapl handler for voltage sensor %d.", (int)volt_sensor_list[sensor]);
        }
        break;
    }

    // NOTE: No other sbus master read should occur in the background, this can result in read errors
    switch (m_sensor_stage) {

    case sensor_stage_e::SBUS_SENSOR_TEMP_START:
        for (int sensor = (int)la_temperature_sensor_e::PACIFIC_SENSOR_1; sensor <= (int)la_temperature_sensor_e::PACIFIC_SENSOR_2;
             sensor++) {
            avago_sbm_spico_int_start(aapl_handler[sensor], AVAGO_SBUS_MASTER_ADDRESS, 0x17 /* Get Temperature Data int*/, 0x0);
        }
        break;

    case sensor_stage_e::SBUS_SENSOR_TEMP_READ:
        for (int sensor = (int)la_temperature_sensor_e::PACIFIC_SENSOR_1; sensor <= (int)la_temperature_sensor_e::PACIFIC_SENSOR_2;
             sensor++) {

            // Read back sbus master value
            ret = avago_sbm_spico_int_read(aapl_handler[sensor], AVAGO_SBUS_MASTER_ADDRESS);

            // Check if result is available
            if ((ret & 0x8000) && (ret != 0xffffff)) {
                int temp = 0;

                if (ret & 0x800) {
                    temp = ret | ~0x7ff; // negative sign extension
                } else {
                    temp = ret & 0x7ff;
                }

                // update the sensor cache
                m_cached_temp_sensor[sensor] = temp / 8.0;

                // update the fail_temp_time
                m_device->get_int_property(la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS, interval);
                m_fail_temp_time[sensor] = now + chrono::milliseconds(interval);

                log_xdebug(HLD, "%s: temp sensor %d read %.2f.", __func__, sensor, m_cached_temp_sensor[sensor]);
            } else {

                if (now > m_fail_temp_time[sensor]) {
                    m_device->get_int_property(la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS,
                                               interval);
                    log_err(HLD,
                            "%s: failure on sensor %d, timeout due to consecutive errors for %d ms.",
                            __func__,
                            (int)sensor,
                            interval);

                    // next failure time should be in the future
                    m_fail_temp_time[sensor] = now + chrono::milliseconds(interval);

                    // mark the temperature as invalid
                    m_cached_temp_sensor[sensor] = (float)INVALID_CACHED_TEMPERATURE;
                }

                log_debug(HLD, "%s: temp sensor %d read failed.", __func__, sensor);
            }
        }
        break;
    case sensor_stage_e::SBUS_SENSOR_VOLT_START:
    case sensor_stage_e::SBUS_SENSOR_VOLT2_START:
        for (int sensor = 0; sensor < MAX_AVAGO_SBUS_RINGS; sensor++) {
            auto current_sensor = voltage_sensors_params[(size_t)volt_sensor_list[sensor]];
            int int_data = current_sensor.sensor << 12;
            avago_sbm_spico_int_start(aapl_handler[sensor], AVAGO_SBUS_MASTER_ADDRESS, 0x18 /* Get Voltage Data int*/, int_data);
        }
        break;

    case sensor_stage_e::SBUS_SENSOR_VOLT_READ:
    case sensor_stage_e::SBUS_SENSOR_VOLT2_READ:
        for (int sensor = 0; sensor < MAX_AVAGO_SBUS_RINGS; sensor++) {
            /* Read back sbus master value */
            ret = avago_sbm_spico_int_read(aapl_handler[sensor], AVAGO_SBUS_MASTER_ADDRESS);

            /* Check if result is available */
            if (ret & 0x8000) {
                m_cached_volt_sensor[(size_t)volt_sensor_list[sensor]] = (float)(ret & 0x3fff) * 0.5 / 1000.0;
                log_xdebug(HLD,
                           "%s: voltage sensor %d read %.3fv",
                           __func__,
                           (int)volt_sensor_list[sensor],
                           m_cached_volt_sensor[(size_t)volt_sensor_list[sensor]]);
            } else {
                m_cached_volt_sensor[(size_t)volt_sensor_list[sensor]] = (float)INVALID_CACHED_VOLTAGE;
                log_debug(HLD, "%s: voltage sensor %d read failed.", __func__, (int)volt_sensor_list[sensor]);
            }
        }
        break;

    default:
        log_err(HLD, "%s: invalid sensor stage %d.", __func__, (int)m_sensor_stage);
        return;
        break;
    }

    // advance the temp sensor read state machine
    m_sensor_stage = static_cast<sensor_stage_e>(static_cast<int>(m_sensor_stage) + 1);
    if (m_sensor_stage > sensor_stage_e::SBUS_SENSOR_LAST) {
        m_sensor_stage = sensor_stage_e::SBUS_SENSOR_FIRST;
    }
    return;
}

} // namespace silicon_one
