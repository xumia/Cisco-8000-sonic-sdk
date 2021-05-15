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

#include "system/la_recycle_port_akpg.h"
#include "system/la_device_impl.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"

namespace silicon_one
{

la_recycle_port_akpg::la_recycle_port_akpg(const la_device_impl_wptr& device) : la_recycle_port_base(device)
{
}

la_recycle_port_akpg::~la_recycle_port_akpg()
{
}

la_status
la_recycle_port_akpg::initialize(la_object_id_t oid, la_slice_id_t slice, la_ifg_id_t ifg)
{
    m_oid = oid;
    m_slice = slice;
    m_ifg = ifg;

    // Configure source PIF entries
    la_status status = set_slice_source_pif_entry();
    return_on_error(status);

    la_uint_t intf_id;
    status = get_intf_id(intf_id);
    return_on_error(status);

    la_interface_scheduler_impl_sptr scheduler;
    status = m_device->create_interface_scheduler(m_slice, m_ifg, intf_id, m_speed, false /* is_fabric */, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    status = m_device->m_ifg_schedulers[m_slice][m_ifg]->initialize_interface(intf_id, 1 /* m_pif_count */);
    return_on_error(status);

    status = m_scheduler->set_oqs_enabled(true /* enabled */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}
}
