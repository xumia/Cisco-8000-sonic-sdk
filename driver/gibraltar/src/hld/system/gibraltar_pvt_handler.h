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

#ifndef __GIBRALTAR_PVT_HANDLER_H__
#define __GIBRALTAR_PVT_HANDLER_H__

#include "api/system/la_css_memory_layout.h"
#include "common/bit_vector.h"
#include "cpu2jtag/cpu2jtag.h"
#include "cpu2jtag/cpu2jtag_fwd.h"
#include "hld_types_fwd.h"
#include "pvt_handler.h"

#include <chrono>

namespace silicon_one
{

class gibraltar_pvt_handler : public pvt_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit gibraltar_pvt_handler(la_device_impl_wptr dev);
    virtual ~gibraltar_pvt_handler();

    la_device_id_t get_device_id() const;

    la_status initialize() override;
    void periodic_poll_sensors() override;
    la_status get_temperature(la_temperature_sensor_e sensor, la_temperature_t& temperature_out) override;
    la_status get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage) override;

private:
    la_device_impl_wptr m_device;
    cpu2jtag_wptr m_cpu2jtag;

    // Temperature poller (we poll only for temperature, not for anything else in PVT).
    enum class poller_state_e {
        IDLE,
        TRIGGERED_TEMPERATURE_READOUT,
        TRIGGERED_VOLTAGE_READOUT,
    };
    poller_state_e m_poller_state;

    std::chrono::time_point<std::chrono::steady_clock> m_next_poll_time;
    std::array<la_temperature_t, (size_t)la_temperature_sensor_e::GIBRALTAR_NUM_SENSORS> m_temperatures;
    std::array<la_voltage_t, (size_t)la_voltage_sensor_e::GIBRALTAR_NUM_SENSORS> m_voltages;

    // Poller state machine helpers
    la_status do_trigger_temperature_readout();
    la_status do_read_temperature();
    la_status read_internal_temperature();
    la_status read_hbm_temperature();
    la_status do_trigger_voltage_readout();
    la_status do_read_voltage();

    // CPU2JTAG PVT instruction
    la_status jtag_pvt_instruction_no_tdo(const bit_vector& dr_data);
    la_status jtag_pvt_instruction(const bit_vector& dr_data, bit_vector& test_data_out);

    // Store PVT samples to CSS memory - this emulates the future PVT polling by ARC.
    void store_to_css();

    struct LA_PACKED pvt_samples {
        // 16 dwords for temperature
        uint32_t temperature[(size_t)la_temperature_sensor_e::GIBRALTAR_NUM_SENSORS]; // 12 dwords
        uint32_t reserved0[4];
        // 16 dwords for voltage
        uint32_t voltage[(size_t)la_voltage_sensor_e::GIBRALTAR_NUM_SENSORS]; // 10 dwords
        uint32_t reserved1[6];
        // 16 dwords reserved for future use
        uint32_t reserved2[16];
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(pvt_samples);
    static_assert(sizeof(pvt_samples) == 3 * 16 * sizeof(uint32_t), "");
    static_assert(sizeof(pvt_samples) <= (size_t)la_css_memory_layout_e::PVT_SAMPLES_SIZE_MAX,
                  "PVT samples do not fit in CSS memory");

    // The index of the first DWORD of 'pvt_samples' in CSS memory.
    static constexpr size_t CSS_MEMORY_PVT_BASE = (size_t)la_css_memory_layout_e::PVT_SAMPLES / 4;

    // For serialization purposes only
    gibraltar_pvt_handler() = default;
};

} // namespace silicon_one

#endif // __GIBRALTAR_PVT_HANDLER_H__
