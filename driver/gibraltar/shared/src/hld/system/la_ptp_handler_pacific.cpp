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

#include "la_ptp_handler_pacific.h"
#include "common/stopwatch.h"
#include "system/la_device_impl.h"

#include "lld/pacific_reg_structs.h"

#include <cmath>
#include <sstream>

namespace silicon_one
{

la_ptp_handler_pacific::la_ptp_handler_pacific(const la_device_impl_wptr& device)
{
    m_device = device;
    m_use_debug_device_time_load = false;
    m_ll_device = device->get_ll_device_sptr();
    m_pc_tree = m_ll_device->get_pacific_tree_scptr();
}

la_ptp_handler_pacific::~la_ptp_handler_pacific()
{
}

la_status
la_ptp_handler_pacific::enable_load_event_generation(bool enabled)
{
    log_err(HLD, "No hardware support for this feature.");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_pacific::set_pad_config(ptp_pads_config config) const
{
    fte_device_time_sync_reg_register dev_time_sync_reg;

    la_status status = m_ll_device->read_register(*m_pc_tree->dmc->fte->device_time_sync_reg, dev_time_sync_reg);
    return_on_error(status);

    // set enaable bits
    dev_time_sync_reg.fields.device_time_load_pad_en = config.device_time_load_enable;
    dev_time_sync_reg.fields.device_time_sync_ck_pad_en = config.device_time_sync_ck_enable;

    // set delay values
    dev_time_sync_reg.fields.device_time_load_pad_delay = config.device_time_load_delay;
    dev_time_sync_reg.fields.device_time_sync_ck_pad_delay = config.device_time_sync_ck_delay;

    status = m_ll_device->write_register(*m_pc_tree->dmc->fte->device_time_sync_reg, dev_time_sync_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_pacific::get_pad_config(ptp_pads_config& out_config) const
{
    fte_device_time_sync_reg_register dev_time_sync_reg;

    la_status status = m_ll_device->read_register(*m_pc_tree->dmc->fte->device_time_sync_reg, dev_time_sync_reg);
    return_on_error(status);

    out_config.device_time_load_enable = dev_time_sync_reg.fields.device_time_load_pad_en;
    out_config.device_time_sync_ck_enable = dev_time_sync_reg.fields.device_time_sync_ck_pad_en;

    out_config.device_time_load_delay = dev_time_sync_reg.fields.device_time_load_pad_delay;
    out_config.device_time_sync_ck_delay = dev_time_sync_reg.fields.device_time_sync_ck_pad_delay;

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_pacific::set_load_time_offset(la_uint64_t offset) const
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

    status = m_ll_device->read_register(*m_pc_tree->dmc->fte->new_time_load_reg, new_time_load_reg);
    return_on_error(status);

    new_time_load_reg.fields.device_time_new_load_offset = offset;

    status = m_ll_device->write_register(*m_pc_tree->dmc->fte->new_time_load_reg, new_time_load_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_pacific::get_load_time_offset(la_uint64_t& out_offset) const
{
    fte_new_time_load_reg_register new_time_load_reg;
    la_status status;

    status = m_ll_device->read_register(*m_pc_tree->dmc->fte->new_time_load_reg, new_time_load_reg);
    return_on_error(status);

    out_offset = new_time_load_reg.fields.device_time_new_load_offset;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
