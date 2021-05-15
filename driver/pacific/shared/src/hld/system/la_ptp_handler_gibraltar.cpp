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

#include "la_ptp_handler_gibraltar.h"
#include "common/stopwatch.h"
#include "system/la_device_impl.h"

#include "lld/gibraltar_reg_structs.h"

#include <cmath>
#include <sstream>

using namespace silicon_one::gibraltar;

namespace silicon_one
{

la_ptp_handler_gibraltar::la_ptp_handler_gibraltar(const la_device_impl_wptr& device)
{
    m_device = device;
    m_use_debug_device_time_load = false;
    m_ll_device = device->get_ll_device_sptr();
    m_gb_tree = m_ll_device->get_gibraltar_tree_scptr();
}

la_ptp_handler_gibraltar::~la_ptp_handler_gibraltar()
{
}

la_status
la_ptp_handler_gibraltar::set_pad_config(ptp_pads_config config) const
{
    fte_device_time_sync_reg_register dev_time_sync_reg;

    la_status status = m_ll_device->read_register(*m_gb_tree->dmc->fte->device_time_sync_reg, dev_time_sync_reg);
    return_on_error(status);

    // set enaable bits
    dev_time_sync_reg.fields.device_time_load_pad_en = config.device_time_load_enable;
    dev_time_sync_reg.fields.device_time_sync_ck_pad_en = config.device_time_sync_ck_enable;

    // set delay values
    dev_time_sync_reg.fields.device_time_load_pad_delay = config.device_time_load_delay;
    dev_time_sync_reg.fields.device_time_sync_ck_pad_delay = config.device_time_sync_ck_delay;

    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->device_time_sync_reg, dev_time_sync_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::get_pad_config(ptp_pads_config& out_config) const
{
    fte_device_time_sync_reg_register dev_time_sync_reg;

    la_status status = m_ll_device->read_register(*m_gb_tree->dmc->fte->device_time_sync_reg, dev_time_sync_reg);
    return_on_error(status);

    out_config.device_time_load_enable = dev_time_sync_reg.fields.device_time_load_pad_en;
    out_config.device_time_sync_ck_enable = dev_time_sync_reg.fields.device_time_sync_ck_pad_en;

    out_config.device_time_load_delay = dev_time_sync_reg.fields.device_time_load_pad_delay;
    out_config.device_time_sync_ck_delay = dev_time_sync_reg.fields.device_time_sync_ck_pad_delay;

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::load_new_time(ptp_time load_time) const
{
    la_status status;
    fte_new_time_load_reg_register new_time_reg;

    status = m_ll_device->read_register(*m_gb_tree->dmc->fte->new_time_load_reg, new_time_reg);
    return_on_error(status);

    // ready new ToD and Device Time to apply
    new_time_reg.fields.device_time_new_load = load_time.device_time;
    new_time_reg.fields.time_of_day_new_load = load_time.time_of_day;

    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->new_time_load_reg, new_time_reg);
    return_on_error(status);

    status = write_command(fte_commands::LOAD_NEW_TIME);

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::capture_time(ptp_time& out_load_time) const
{
    la_status status;
    fte_time_capture_reg_register time_capture_reg;

    write_command(fte_commands::CAPTURE_TIME);

    status = write_command_wait();
    return_on_error(status);

    status = m_ll_device->read_register(*m_gb_tree->dmc->fte->time_capture_reg, time_capture_reg);
    return_on_error(status);

    out_load_time.device_time = time_capture_reg.fields.device_time_capture;
    out_load_time.time_of_day = time_capture_reg.fields.time_of_day_capture;

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::adjust_device_time(ptp_sw_tuning_config adjustment) const
{
    la_status status;
    fte_device_time_sw_tuning_reg_register sw_tuning_reg;

    sw_tuning_reg.fields.sw_tuning_inc_stall = adjustment.increment;
    sw_tuning_reg.fields.sw_tuning_repeat = adjustment.repeat;
    sw_tuning_reg.fields.sw_tuning_period = adjustment.period;

    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->device_time_sw_tuning_reg, sw_tuning_reg);
    return_on_error(status);

    status = write_command(fte_commands::SW_TUNING);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::set_load_time_offset(la_uint64_t offset) const
{
    fte_new_time_load_reg_register new_time_load_reg;
    la_status status;

    if (offset > pow(2.0, fte_new_time_load_reg_register::fields::DEVICE_TIME_NEW_LOAD_OFFSET_WIDTH)) {
        log_err(HLD,
                "%s : offset out of range, max value is 2^%d",
                __func__,
                fte_new_time_load_reg_register::fields::DEVICE_TIME_NEW_LOAD_OFFSET_WIDTH);
        return LA_STATUS_EOUTOFRANGE;
    }

    status = m_ll_device->read_register(*m_gb_tree->dmc->fte->new_time_load_reg, new_time_load_reg);
    return_on_error(status);

    new_time_load_reg.fields.device_time_new_load_offset = offset;

    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->new_time_load_reg, new_time_load_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::get_load_time_offset(la_uint64_t& out_offset) const
{
    fte_new_time_load_reg_register new_time_load_reg;
    la_status status;

    status = m_ll_device->read_register(*m_gb_tree->dmc->fte->new_time_load_reg, new_time_load_reg);
    return_on_error(status);

    out_offset = new_time_load_reg.fields.device_time_new_load_offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::load_new_time_unit(ptp_time_unit time_unit) const
{
    fte_device_time_new_unit_reg_register new_time_unit_reg;
    la_status status;

    double period = (1.0 / (float)time_unit.frequency) * 1e9;

    // range checking
    if (period > 17.0) {
        log_err(HLD, "%s : period (1/%lu) is greater than or equal to 17 ns", __func__, time_unit.frequency);
        return LA_STATUS_EOUTOFRANGE;
    } else if (time_unit.clock_frac_comp_val > 32 || time_unit.clock_frac_comp_period > 32) {
        log_err(HLD, "%s : clock_frac_comp_val or clock_frac_comp_period is greater than 32", __func__);
        return LA_STATUS_EOUTOFRANGE;
    }

    // Fabric time clock values configuration in nanosecond
    uint64_t ns_whole = floor(period);
    double ns_fraction = period - (float)ns_whole;
    // Get CLOCK_INC_FRAC_VALUE_WIDTH bits after binary point
    uint64_t subns_fraction = floor(ns_fraction * pow(2.0, fte_clock_inc_reg_register::fields::CLOCK_INC_FRAC_VALUE_WIDTH));

    new_time_unit_reg.fields.device_time_clock_new_inc_ns_value = ns_whole;
    new_time_unit_reg.fields.device_time_clock_new_inc_frac_value = subns_fraction;
    new_time_unit_reg.fields.device_time_clock_new_frac_comp_val = time_unit.clock_frac_comp_val;
    new_time_unit_reg.fields.device_time_clock_new_frac_comp_period = time_unit.clock_frac_comp_period;

    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->device_time_new_unit_reg, new_time_unit_reg);
    return_on_error(status);

    write_command(fte_commands::LOAD_NEW_TIME_UNIT);
    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::get_time_unit(ptp_time_unit& out_time_unit) const
{
    la_status status;
    fte_device_time_unit_reg_register time_unit_reg;
    la_uint64_t inc_ns_val, inc_frac_val, comp_period, comp_val;

    status = m_ll_device->read_register(*m_gb_tree->dmc->fte->device_time_unit_reg, time_unit_reg);
    return_on_error(status);
    la_uint64_t ns_to_subns = pow(2, fte_clock_inc_reg_register::fields::CLOCK_INC_FRAC_VALUE_WIDTH);
    inc_ns_val = time_unit_reg.fields.device_time_clock_inc_ns_value;
    inc_frac_val = time_unit_reg.fields.device_time_clock_inc_frac_value;
    comp_val = time_unit_reg.fields.device_time_clock_frac_comp_val;
    comp_period = time_unit_reg.fields.device_time_clock_frac_comp_period;

    // avoid divide by 0
    double subns_comp_frac = 0;
    if (comp_period != 0) {
        subns_comp_frac = (double)comp_val / (double)comp_period;
    }
    double subns_frac = inc_frac_val + subns_comp_frac;
    double ns_frac = (double)subns_frac / ns_to_subns;
    double period = inc_ns_val + ns_frac;

    out_time_unit.frequency = (1.0 / period) * 1.0e9;
    out_time_unit.clock_frac_comp_val = comp_val;
    out_time_unit.clock_frac_comp_period = comp_period;

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::write_command(fte_commands command) const
{
    fte_device_time_load_command_reg_register command_reg;
    la_status status;

    command_reg.fields.device_time_load_command = command;
    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->device_time_load_command_reg, command_reg);
    return_on_error(status);

    if (m_use_debug_device_time_load) {
        send_cpu_device_time_load();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::send_cpu_device_time_load() const
{
    la_status status;
    fte_debug_device_time_event_gen_reg_register debug_device_time;

    status = m_ll_device->read_register(*m_gb_tree->dmc->fte->debug_device_time_event_gen_reg, debug_device_time);

    if (debug_device_time.fields.debug_device_time_event_gen_load_cmnd == 1) {
        // need to set to zero first
        debug_device_time.fields.debug_device_time_event_gen_load_cmnd = 0;
        status = m_ll_device->write_register(*m_gb_tree->dmc->fte->debug_device_time_event_gen_reg, debug_device_time);
    }

    // need to trigger a rising edge manually
    debug_device_time.fields.debug_device_time_event_gen_load_cmnd = 1;
    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->debug_device_time_event_gen_reg, debug_device_time);

    debug_device_time.fields.debug_device_time_event_gen_load_cmnd = 0;
    status = m_ll_device->write_register(*m_gb_tree->dmc->fte->debug_device_time_event_gen_reg, debug_device_time);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_gibraltar::write_command_wait() const
{
    fte_device_time_load_command_reg_register command_reg;
    la_status status;

    // trigger should execute when issued
    if (m_use_debug_device_time_load) {
        return LA_STATUS_SUCCESS;
    }

    // sleep for one second
    stopwatch timer;
    bool completed = false;
    const la_uint_t second_in_ns = 1000000000;
    la_uint_t elapsed_time_ns = 0;
    la_uint_t load_command = 0;

    do {
        timer.start();
        status = m_ll_device->read_register(*m_gb_tree->dmc->fte->device_time_load_command_reg, command_reg);
        return_on_error(status);
        load_command = command_reg.fields.device_time_load_command;

        if (!load_command) {
            completed = true;
        }

        elapsed_time_ns += timer.stop();
    } while (!completed && elapsed_time_ns < second_in_ns);

    if (load_command != 0) {
        log_err(HLD, "DEVICE_TIME_LOAD did not trigger, cannot process command.");
        return LA_STATUS_ENOTINITIALIZED;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
