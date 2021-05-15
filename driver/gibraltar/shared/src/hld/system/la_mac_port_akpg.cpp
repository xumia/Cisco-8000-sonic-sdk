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

#include "la_mac_port_akpg.h"

#include "hld_utils.h"
#include "qos/la_meter_set_impl.h"
#include "system/ifg_handler.h"
#include "system/mac_pool_port.h"
#include "tm/tm_utils.h"

#include "api_tracer.h"

namespace silicon_one
{

la_mac_port_akpg::la_mac_port_akpg(const la_device_impl_wptr& device) : la_mac_port_base(device)
{
}

la_mac_port_akpg::~la_mac_port_akpg()
{
}

la_status
la_mac_port_akpg::do_reset()
{
    start_api_call("");

    la_status status;
    status = do_reset_port();
    return status;
}

la_status
la_mac_port_akpg::set_reset_state_fabric_port(mac_reset_state_e state)
{
    la_status status = set_reset_state_network_port(state);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_akpg::configure_fabric_scheduler()
{
    // Nothing to do, it is configured by LBR init values.
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_akpg::configure_serdes_source_pif_table_extended_mac()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_akpg::set_ssp_sub_port_map()
{
    return LA_STATUS_SUCCESS;
}
}
