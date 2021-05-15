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

#include "la_npu_host_port_akpg.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "system/la_device_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/la_system_port_akpg.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include <sstream>

namespace silicon_one
{

la_npu_host_port_akpg::la_npu_host_port_akpg(la_device_impl_wptr device) : la_npu_host_port_base(device)
{
}

la_npu_host_port_akpg::~la_npu_host_port_akpg()
{
}

la_status
la_npu_host_port_akpg::initialize_remote(la_remote_device* remote_device,
                                         la_system_port_gid_t system_port_gid,
                                         la_voq_set* voq_set,
                                         const la_tc_profile* tc_profile)
{
    la_remote_port* remote_port;
    la_slice_ifg s_ifg = m_device->get_slice_id_manager()->get_npu_host_port_ifg();
    auto status
        = m_device->create_remote_port(remote_device, s_ifg.slice, s_ifg.ifg, HOST_PIF_ID, HOST_PIF_ID + 1, m_speed, remote_port);
    return_on_error(status);
    m_remote_port = m_device->get_sptr<la_remote_port_impl>(remote_port);

    la_system_port* system_port;
    status = m_device->create_system_port(system_port_gid, m_remote_port.get(), voq_set, tc_profile, system_port);
    return_on_error(status);
    m_system_port = m_device->get_sptr<la_system_port_base>(system_port);

    m_device->add_object_dependency(m_remote_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_npu_host_port_akpg::initialize(la_object_id_t oid,
                                  la_remote_device* remote_device,
                                  la_system_port_gid_t system_port_gid,
                                  la_voq_set* voq_set,
                                  const la_tc_profile* tc_profile)
{

    m_oid = oid; // m_oid need to be assigned before calling get_sptr(this) !

    la_status status = (remote_device == nullptr) ? initialize_local(system_port_gid, voq_set, tc_profile)
                                                  : initialize_remote(remote_device, system_port_gid, voq_set, tc_profile);
    return_on_error(status);

    m_device->add_object_dependency(m_system_port, this);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
