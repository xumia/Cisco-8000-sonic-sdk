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

#include "la_vxlan_next_hop_pacific.h"
#include "api/npu/la_l3_port.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "npu/counter_utils.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_switch_impl.h"
#include "npu/resolution_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_vxlan_next_hop_pacific::la_vxlan_next_hop_pacific(const la_device_impl_wptr& device) : la_vxlan_next_hop_base(device)
{
}

la_vxlan_next_hop_pacific::~la_vxlan_next_hop_pacific()
{
}

resolution_step_e
la_vxlan_next_hop_pacific::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        return RESOLUTION_STEP_NATIVE_FEC;
    }

    return RESOLUTION_STEP_INVALID;
}

lpm_destination_id
la_vxlan_next_hop_pacific::get_lpm_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_NATIVE_FEC: {
        lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(m_resolution_data.fec_impl, prev_step);
        return lpm_dest_id;
    }

    default: {
        return LPM_DESTINATION_ID_INVALID;
    }
    }
}

destination_id
la_vxlan_next_hop_pacific::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_NATIVE_FEC: {
        return silicon_one::get_destination_id(m_resolution_data.fec_impl, prev_step);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

} // namespace silicon_one
