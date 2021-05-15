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

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/la_ip_addr.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "lld/ll_device.h"

#include "api_tracer.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "la_device_impl_base.h"
#include "system/hld_notification_base.h"
#include "system/resource_handler.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_output_queue_scheduler_impl.h"

namespace silicon_one
{
la_device_impl_base::la_device_impl_base(ll_device_sptr ldevice)
    : m_ll_device(ldevice), m_resource_handler(nullptr), m_device_mode(device_mode_e::INVALID)
{
}

la_device_impl_base::~la_device_impl_base()
{
}

la_status
la_device_impl_base::pre_initialize(slice_id_manager_base_sptr slice_id_manager)
{
    m_slice_id_manager.initialize(slice_id_manager);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl_base::warm_boot_get_base_revision(la_uint32_t& wb_revision)
{
    if (m_base_wb_revision == WB_INVALID_REVISION) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    wb_revision = m_base_wb_revision;
    return LA_STATUS_SUCCESS;
}

la_device_id_t
la_device_impl_base::get_id() const
{
    return m_ll_device->get_device_id();
}

la_slice_id_t
la_device_impl_base::first_active_slice_id() const
{
    return m_slice_id_manager->get_an_active_slice_id(0);
}
la_status
la_device_impl_base::get_device_bool_capabilities(std::vector<bool>& out_device_bool_capabilities) const
{
    out_device_bool_capabilities.resize((int)device_bool_capability_e::LAST + 1);

    // first capability - does HBM exist
    bool has_hbm = false;
    la_status status = hbm_exists(has_hbm);
    return_on_error(status);
    out_device_bool_capabilities[(int)device_bool_capability_e::HAS_HBM] = has_hbm;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl_base::get_device_int_capabilities(std::vector<uint32_t>& out_device_int_capabilities) const
{
    out_device_int_capabilities.resize((int)device_int_capability_e::LAST + 1, 0);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl_base::get_device_string_capabilities(std::vector<std::string>& out_device_string_capabilities) const
{
    out_device_string_capabilities.resize((int)device_string_capability_e::LAST + 1, "");
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl_base::initialize_first(bool reconnect_in_progress)
{
    if (reconnect_in_progress) {
        // should allready have been called from la_device_impl::reconnect() , befor m_reconnect_handler->reconnect() was called;
        return LA_STATUS_SUCCESS;
    }

    la_status status = initialize_slice_id_manager();
    return_on_error(status);
    status = initialize_first_ifgs();
    return status;
}

la_status
la_device_impl_base::initialize_slice_id_manager()
{
    m_slice_id_manager.get_mgr()->initialize(get_sptr());
    return LA_STATUS_SUCCESS;
}

const slice_manager_smart_ptr&
la_device_impl_base::get_slice_id_manager() const
{
    return m_slice_id_manager;
}

la_device::init_phase_e
la_device_impl_base::get_init_phase() const
{
    return m_init_phase;
}

la_status
la_device_impl_base::open_scheduler_auto_grants()
{
    start_api_call("");

    if (m_device_mode != device_mode_e::LINECARD) {
        log_err(HLD, "open_scheduler_auto_grants API can be called on linecard device only.");
        return LA_STATUS_EINVAL;
    }

    bit_vector reachable_devices_bv;
    la_status status = get_reachable_devices(reachable_devices_bv);
    return_on_error(status);

    auto oq_sch_objs = get_objects(object_type_e::OUTPUT_QUEUE_SCHEDULER);
    for (auto oq_sch : oq_sch_objs) {
        const auto& oq_sch_impl = static_cast<la_output_queue_scheduler_impl*>(oq_sch);
        status = oq_sch_impl->set_static_go(reachable_devices_bv);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
