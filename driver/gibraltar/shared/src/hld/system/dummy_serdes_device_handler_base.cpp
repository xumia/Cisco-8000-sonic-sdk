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

#include "common/defines.h"
#include "hld_types.h"
#include <common/la_status.h>

#include "dummy_serdes_device_handler_base.h"
#include "dummy_serdes_handler_base.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

dummy_serdes_device_handler_base::dummy_serdes_device_handler_base(const la_device_impl_wptr& device)
    : m_device(device), m_handler_initilized(false)
{
}

la_status
dummy_serdes_device_handler_base::init(bool reconnect)
{
    m_handler_initilized = true;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_device_handler_base::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_device_handler_base::create_serdes_group_handler(la_slice_id_t slice_id,
                                                              la_ifg_id_t ifg_id,
                                                              la_uint_t serdes_base_id,
                                                              size_t serdes_count,
                                                              la_mac_port::port_speed_e speed,
                                                              la_mac_port::port_speed_e serdes_speed,
                                                              la_slice_mode_e serdes_slice_mode,
                                                              serdes_handler*& out_serdes_handler)
{
    out_serdes_handler = new dummy_serdes_handler_base(
        m_device, slice_id, ifg_id, serdes_base_id, serdes_count, speed, serdes_speed, serdes_slice_mode);
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_device_handler_base::get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_device_handler_base::get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_device_handler_base::mbist_activate(bool repair)
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_device_handler_base::mbist_clear()
{
    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_device_handler_base::mbist_read(bool report_failures, size_t& total_tested, size_t& total_pass, size_t& total_failed)
{
    total_tested = 97; // random number
    total_pass = 97;
    total_failed = 0;

    return LA_STATUS_SUCCESS;
}

la_status
dummy_serdes_device_handler_base::get_serdes_addr(la_slice_id_t slice,
                                                  la_ifg_id_t ifg,
                                                  la_uint_t serdes_idx,
                                                  la_serdes_direction_e direction,
                                                  uint32_t& out_serdes_addr)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_serdes_device_handler_base::get_component_health(la_component_health_vec_t& out_component_health) const
{
    return LA_STATUS_SUCCESS;
}
}
