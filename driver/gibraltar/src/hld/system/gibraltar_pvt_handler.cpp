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

#include "gibraltar_pvt_handler.h"
#include "apb/apb.h"
#include "api_tracer.h"
#include "common/logger.h"
#include "cpu2jtag/cpu2jtag.h"
#include "la_device_impl.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"

#include <math.h>

#include <chrono>
#include <thread>

using namespace std;

namespace silicon_one
{

// Temperature sensors conversion time is ~1second
static constexpr std::chrono::milliseconds INTERVAL_TEMPERATURE_TRIGGER_TO_READOUT{1000};

// Voltage sensors conversion time is ~2milliseconds
// However, we do not want to poll PVT too frequently and use interval of 1 second here as well.
static constexpr std::chrono::milliseconds INTERVAL_VOLTAGE_TRIGGER_TO_READOUT{1000};

// Minimum idle interval of PVT poller.
static constexpr std::chrono::milliseconds INTERVAL_IDLE_MIN{1000};

// Minimum period of PVT state machine - the sum of intervals.
static constexpr std::chrono::milliseconds INTERVALS_ALL
    = INTERVAL_TEMPERATURE_TRIGGER_TO_READOUT + INTERVAL_VOLTAGE_TRIGGER_TO_READOUT + INTERVAL_IDLE_MIN;

static constexpr auto HBM_USE_IEEE_BRIDGE_DELAY = chrono::microseconds(10);

static inline size_t
to_index(la_temperature_sensor_e sensor)
{
    return (size_t)sensor - (size_t)la_temperature_sensor_e::GIBRALTAR_FIRST;
}

static inline size_t
to_index(la_voltage_sensor_e sensor)
{
    return (size_t)sensor - (size_t)la_voltage_sensor_e::GIBRALTAR_FIRST;
}

gibraltar_pvt_handler::gibraltar_pvt_handler(la_device_impl_wptr dev)
    : m_device(dev), m_cpu2jtag(nullptr), m_poller_state(poller_state_e::IDLE)
{
    bool sim = m_device->is_simulated_or_emulated_device();

    la_temperature_t temp_init = (sim ? SIMULATED_TEMPERATURE : INVALID_CACHED_TEMPERATURE);
    la_voltage_t volt_init = (sim ? SIMULATED_VOLTAGE : INVALID_CACHED_VOLTAGE);

    std::fill(m_temperatures.begin(), m_temperatures.end(), temp_init);
    std::fill(m_voltages.begin(), m_voltages.end(), volt_init);

    m_next_poll_time = chrono::steady_clock::now();
}

gibraltar_pvt_handler::~gibraltar_pvt_handler()
{
}

la_device_id_t
gibraltar_pvt_handler::get_device_id() const
{
    return m_device->get_id();
}

la_status
gibraltar_pvt_handler::initialize()
{
    if (m_device->is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    // Initialize cpu2jtag_handler on the first invocation of the poller.
    m_cpu2jtag = m_device->get_cpu2jtag_handler_sptr();
    if (m_cpu2jtag == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    // Store the initial values of sensors to CSS.
    store_to_css();

    return LA_STATUS_SUCCESS;
}

void
gibraltar_pvt_handler::periodic_poll_sensors()
{
    if (!m_cpu2jtag || m_device->is_simulated_or_emulated_device()) {
        return;
    }

    bool enable_sensor_poll = false;
    m_device->get_bool_property(la_device_property_e::ENABLE_SENSOR_POLL, enable_sensor_poll);
    if (!enable_sensor_poll) {
        m_poller_state = poller_state_e::IDLE;
        return;
    }

    auto now = chrono::steady_clock::now();
    if (now < m_next_poll_time) {
        return;
    }

    log_debug(PVT, "%s: state=%d", __func__, (int)m_poller_state);

    bool update_css = false;

    // Voltage and temperature sensors have a conversion time.
    // For temperature, it's around 1 second.
    // For voltage, it's 2 milliseconds.
    // Because of the long conversion time, we read the sensors asynchronously (trigger, then read after a while).
    //
    // We read both voltage and temperature with the same state machine.
    // It is critical that temperature is sampled all the time.
    // Voltage is not expected to fluctuate, it can be sampled less frequently (TODO)
    //

    chrono::milliseconds interval;
    if (m_poller_state == poller_state_e::IDLE) {
        do_trigger_temperature_readout();

        m_poller_state = poller_state_e::TRIGGERED_TEMPERATURE_READOUT;
        interval = INTERVAL_TEMPERATURE_TRIGGER_TO_READOUT;
    } else if (m_poller_state == poller_state_e::TRIGGERED_TEMPERATURE_READOUT) {
        do_read_temperature();
        update_css = true;
        do_trigger_voltage_readout();

        m_poller_state = poller_state_e::TRIGGERED_VOLTAGE_READOUT;
        interval = INTERVAL_VOLTAGE_TRIGGER_TO_READOUT;
    } else {
        do_read_voltage();
        update_css = true;

        m_poller_state = poller_state_e::IDLE;
        interval = INTERVAL_IDLE_MIN;

        int val = 0;
        m_device->get_int_property(la_device_property_e::SENSOR_POLL_INTERVAL_MILLISECONDS, val);
        auto val_chrono = std::chrono::milliseconds(val);
        if (val_chrono > INTERVALS_ALL) {
            interval += val_chrono - INTERVALS_ALL;
        }
    }

    if (update_css) {
        store_to_css();
    }

    m_next_poll_time = chrono::steady_clock::now() + interval;
}

la_status
gibraltar_pvt_handler::get_temperature(la_temperature_sensor_e sensor, la_temperature_t& out_temperature)
{
    if (sensor < la_temperature_sensor_e::GIBRALTAR_FIRST || sensor > la_temperature_sensor_e::GIBRALTAR_LAST) {
        log_err(PVT, "%s: sensor='%s'(%d) is not supported.", __func__, silicon_one::to_string(sensor).c_str(), (int)sensor);
        return LA_STATUS_EINVAL;
    }

    auto val = m_temperatures[to_index(sensor)];
    if (val == INVALID_CACHED_TEMPERATURE) {
        log_err(PVT, "%s: sensor=%s is not ready.", __func__, silicon_one::to_string(sensor).c_str());
        return LA_STATUS_EAGAIN;
    }

    out_temperature = val;

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_pvt_handler::get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage)
{
    if (sensor < la_voltage_sensor_e::GIBRALTAR_FIRST || sensor > la_voltage_sensor_e::GIBRALTAR_LAST) {
        log_err(PVT, "%s: sensor='%s'(%d) is not supported.", __func__, silicon_one::to_string(sensor).c_str(), (int)sensor);
        return LA_STATUS_EINVAL;
    }

    auto val = m_voltages[to_index(sensor)];
    if (val == INVALID_CACHED_VOLTAGE) {
        log_err(PVT, "%s: sensor=%s is not ready.", __func__, silicon_one::to_string(sensor).c_str());
        return LA_STATUS_EAGAIN;
    }

    out_voltage = val;

    return LA_STATUS_SUCCESS;
}

enum { JTAG_PVT_DR_LENGTH_BITS = 586 };

la_status
gibraltar_pvt_handler::jtag_pvt_instruction_no_tdo(const bit_vector& dr_data)
{
    if (!m_cpu2jtag) {
        return LA_STATUS_EAGAIN;
    }

    la_status rc = m_cpu2jtag->load_ir_dr_no_tdo((uint64_t)cpu2jtag::jtag_ir_e::PVT, JTAG_PVT_DR_LENGTH_BITS, dr_data);

    return rc;
}

la_status
gibraltar_pvt_handler::jtag_pvt_instruction(const bit_vector& dr_data, bit_vector& test_data_out)
{
    if (!m_cpu2jtag) {
        return LA_STATUS_EAGAIN;
    }

    la_status rc = m_cpu2jtag->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::PVT, JTAG_PVT_DR_LENGTH_BITS, dr_data, test_data_out);

    return rc;
}

static float
get_temperature_from_code(uint32_t code32)
{

    float a2 = -1.8800e-05;
    float a1 = 2.8946e-01;
    float a0 = -6.5995e+01;
    float code = (float)code32;
    float temperature = a2 * pow(code, 2) + a1 * code + a0;

    return temperature;
}

static float
get_voltage_from_code(uint32_t code32)
{
    float a1 = 7.1388e-04;
    float a0 = 4.5598e-01;
    float code = (float)code32;
    float voltage = a1 * code + a0;

    return voltage;
}

la_status
gibraltar_pvt_handler::do_trigger_temperature_readout()
{
    log_debug(PVT, "%s: configuring the clock divider and the sensor", __func__);
    static const bit_vector dr_data_config("0x1c0000000000000380000000000000700000000000000e000000000000efc000000000003bf000000"
                                           "000000efc000000000001df80000000000077e000000000001df8000");
    la_status rc = jtag_pvt_instruction_no_tdo(dr_data_config);
    return_on_error(rc);

    log_debug(PVT, "%s: enabling the sensor", __func__);
    static const bit_vector dr_data_enable_sensors("0x1e00000000000003c0000000000000780000000000000f000000000000efe000000000003"
                                                   "bf800000000000efe000000000001dfc0000000000077f000000000001dfc000");
    rc = jtag_pvt_instruction_no_tdo(dr_data_enable_sensors);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

enum { SENSOR_VALUE_WIDTH = 10 };

la_status
gibraltar_pvt_handler::read_hbm_temperature()
{
    bool hbm_exists = false;
    la_status rc = m_device->hbm_exists(hbm_exists);
    return_on_error(rc);

    if (!hbm_exists) {
        return LA_STATUS_SUCCESS;
    }
    apb* apb;
    rc = m_device->get_apb_handler(apb_interface_type_e::HBM, apb);
    return_on_error(rc);

    gibraltar::hbm_hbm_clock_config_register hbm_clock_config;
    m_device->m_ll_device->read_register(m_device->m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);
    hbm_clock_config.fields.use_ieee_bridge = 1;
    m_device->m_ll_device->write_register(m_device->m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);
    m_device->m_ll_device->write_register(m_device->m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
    this_thread::sleep_for(chrono::microseconds(HBM_USE_IEEE_BRIDGE_DELAY));

    // The below code turns HBM/ieee1500 access on then off.
    // We do it under HBM/apb mutex, because currently this is the only use of HBM/ieee1500.
    // TODO: re-consider HBM/APB vs HBM/EEE1500 synchronization policy if HBM/ieee1500 is used in other places too.
    std::lock_guard<std::recursive_mutex> lock(apb->get_lock());

    // take ieee1500 out of reset
    apb->write(0x3, 0x80, 7);

    // flush
    bit_vector tmp;
    apb->read(1, 1, tmp);
    apb->read(2, 1, tmp);

    // read temperature
    for (size_t ch = 0; ch < 2; ch++) {
        m_device->m_ll_device->write_memory(m_device->m_gb_tree->hbm->db[ch]->ieee1500, 0xf, 0);
        m_device->m_ll_device->read_memory(m_device->m_gb_tree->hbm->db[ch]->ieee1500, 0xf, tmp);
        m_temperatures[to_index(la_temperature_sensor_e::GIBRALTAR_HBM_SENSOR_0) + ch] = tmp.get_value();

        m_device->m_ll_device->write_memory(m_device->m_gb_tree->hbm->db[ch]->ieee1500, 0xc, 0);
        m_device->m_ll_device->read_memory(m_device->m_gb_tree->hbm->db[ch]->ieee1500, 0xc, tmp);
    }

    // put ieee1500 in reset
    apb->write(0x3, 0x80, 3);

    // flush
    apb->read(1, 1, tmp);
    apb->read(2, 1, tmp);

    hbm_clock_config.fields.use_ieee_bridge = 0;
    m_device->m_ll_device->write_register(m_device->m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);
    m_device->m_ll_device->write_register(m_device->m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_pvt_handler::read_internal_temperature()
{
    log_debug(PVT, "%s: disabling the sensor and reading the result", __func__);

    la_status status = LA_STATUS_SUCCESS;

    bit_vector tdo;
    static const bit_vector dr_data_disable_sensors("0x1c0000000000000380000000000000700000000000000e000000000000efc00000000000"
                                                    "3bf000000000000efc000000000001df80000000000077e000000000001df8000");
    la_status rc = jtag_pvt_instruction(dr_data_disable_sensors, tdo);
    return_on_error(rc);

    struct {
        la_temperature_sensor_e sensor;
        size_t lsb;
    } sensors[] = {
        // RXPP-0,1,2,3,4,5 == SENSOR-0,1,2,3,4,5
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_2, 47},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_1, 105},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_0, 163},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_3, 222},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_4, 280},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_5, 338},
        // GPIO-0,1,2,3 == SENSOR-6,7,8,9
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_9, 397},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_8, 456},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_7, 515},
        {la_temperature_sensor_e::GIBRALTAR_SENSOR_6, 574},
    };

    for (auto s : sensors) {
        bool valid = tdo.bit(s.lsb + SENSOR_VALUE_WIDTH);
        float value;
        if (valid) {
            value = get_temperature_from_code((uint32_t)tdo.bits(s.lsb + SENSOR_VALUE_WIDTH - 1, s.lsb).get_value());
            log_debug(PVT, "%s: %s=%lf", __func__, silicon_one::to_string(s.sensor).c_str(), value);
        } else {
            value = INVALID_CACHED_TEMPERATURE;
            log_debug(PVT,
                      "%s: %s=NaN, invalid reading (0x%X = %lf), last cached reading %lf",
                      __func__,
                      silicon_one::to_string(s.sensor).c_str(),
                      (uint32_t)tdo.bits(s.lsb + SENSOR_VALUE_WIDTH - 1, s.lsb).get_value(),
                      get_temperature_from_code((uint32_t)tdo.bits(s.lsb + SENSOR_VALUE_WIDTH - 1, s.lsb).get_value()),
                      m_temperatures[to_index(s.sensor)]);
            status = LA_STATUS_EAGAIN;
        }

        m_temperatures[to_index(s.sensor)] = value;
    }

    return status;
}

la_status
gibraltar_pvt_handler::do_read_temperature()
{
    la_status rc = read_internal_temperature();
    return_on_error(rc);

    rc = read_hbm_temperature();
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_pvt_handler::do_trigger_voltage_readout()
{
    log_debug(PVT, "%s: configuring the clock divider and the sensor", __func__);
    static const bit_vector dr_data_config("0x1c3c0800000000038781000000000070f020000000000e1e0400000000efc3c0800000003bf0f0200"
                                           "000000efc3c0800000001df87810000000077e1e0400000001df8781");
    la_status rc = jtag_pvt_instruction_no_tdo(dr_data_config);
    return_on_error(rc);

    log_debug(PVT, "%s: enabling the sensor", __func__);
    static const bit_vector dr_data_enable_sensors("0x1e3c080000000003c781000000000078f020000000000f1e0400000000efe3c0800000003"
                                                   "bf8f0200000000efe3c0800000001dfc7810000000077f1e0400000001dfc781");
    rc = jtag_pvt_instruction_no_tdo(dr_data_enable_sensors);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
gibraltar_pvt_handler::do_read_voltage()
{
    log_debug(PVT, "%s: disabling the sensor and reading the result", __func__);

    la_status status = LA_STATUS_SUCCESS;

    bit_vector tdo;
    static const bit_vector dr_data_disable_sensors("0x1c3c0800000000038781000000000070f020000000000e1e0400000000efc3c080000000"
                                                    "3bf0f0200000000efc3c0800000001df87810000000077e1e0400000001df8781");
    la_status rc = jtag_pvt_instruction(dr_data_disable_sensors, tdo);
    return_on_error(rc);

    struct {
        la_voltage_sensor_e sensor;
        size_t lsb;
    } sensors[] = {
        // RXPP-0,1,2,3,4,5 == SENSOR-0,1,2,3,4,5
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_2, 47},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_1, 105},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_0, 163},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_3, 222},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_4, 280},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_5, 338},
        // GPIO-0,1,2,3 == SENSOR-6,7,8,9
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_9, 397},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_8, 456},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_7, 515},
        {la_voltage_sensor_e::GIBRALTAR_SENSOR_6, 574},
    };

    for (auto s : sensors) {
        bool valid = tdo.bit(s.lsb + SENSOR_VALUE_WIDTH);
        float value;
        if (valid) {
            value = get_voltage_from_code((uint32_t)tdo.bits(s.lsb + SENSOR_VALUE_WIDTH - 1, s.lsb).get_value());
            log_debug(PVT, "%s: %s=%lf", __func__, silicon_one::to_string(s.sensor).c_str(), value);
        } else {
            value = INVALID_CACHED_VOLTAGE;
            log_debug(PVT,
                      "%s: %s=NaN, invalid reading (0x%X = %lf), last cached reading %lf",
                      __func__,
                      silicon_one::to_string(s.sensor).c_str(),
                      (uint32_t)tdo.bits(s.lsb + SENSOR_VALUE_WIDTH - 1, s.lsb).get_value(),
                      get_voltage_from_code((uint32_t)tdo.bits(s.lsb + SENSOR_VALUE_WIDTH - 1, s.lsb).get_value()),
                      m_voltages[to_index(s.sensor)]);
            status = LA_STATUS_EAGAIN;
        }

        m_voltages[to_index(s.sensor)] = value;
    }

    return status;
}

void
gibraltar_pvt_handler::store_to_css()
{
    // Write to HW in fixed point format. We translate from floating point degrees and volts to integer millidegrees and millivolts.
    pvt_samples pvt{{0}};
    for (size_t i = 0; i < m_temperatures.size(); i++) {
        pvt.temperature[i] = static_cast<uint32_t>(m_temperatures[i] * 1000);
    }
    for (size_t i = 0; i < m_voltages.size(); i++) {
        pvt.voltage[i] = static_cast<uint32_t>(m_voltages[i] * 1000);
    }

    m_device->m_ll_device->write_memory(*m_device->m_gb_tree->sbif->css_mem_even,
                                        CSS_MEMORY_PVT_BASE,
                                        sizeof(pvt) / 4 /* count */,
                                        sizeof(pvt) /* in_val_sz */,
                                        &pvt);
}

} // namespace silicon_one
