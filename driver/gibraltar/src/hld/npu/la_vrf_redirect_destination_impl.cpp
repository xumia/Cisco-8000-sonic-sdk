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

#include "npu/la_vrf_redirect_destination_impl.h"
#include "npu/la_vrf_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "nplapi/npl_constants.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_vrf_redirect_destination_impl::la_vrf_redirect_destination_impl(const la_device_impl_wptr& device)
    : m_device(device), m_vrf(nullptr)
{
}

la_vrf_redirect_destination_impl::~la_vrf_redirect_destination_impl()
{
}

la_status
la_vrf_redirect_destination_impl::initialize(la_object_id_t oid, const la_vrf* vrf)
{
    m_oid = oid;
    m_vrf = m_device->get_sptr<const la_vrf_impl>(vrf);
    // Update object dependencies
    m_device->add_object_dependency(m_vrf, this);
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_redirect_destination_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }
    // Update object dependencies
    m_device->remove_object_dependency(m_vrf, this);
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_vrf_redirect_destination_impl::type() const
{
    return object_type_e::VRF_REDIRECT_DESTINATION;
}

const la_device*
la_vrf_redirect_destination_impl::get_device() const
{
    return m_device.get();
}

std::string
la_vrf_redirect_destination_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_vrf_redirect_destination_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_vrf_redirect_destination_impl::oid() const
{
    return m_oid;
}

const la_vrf*
la_vrf_redirect_destination_impl::get_vrf() const
{
    return m_vrf.get();
}

lpm_destination_id
la_vrf_redirect_destination_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    // NPL looks at prefix 5'b11011 for VRF redirect
    return lpm_destination_id(NPL_DESTINATION_MASK_VRF_REDIRECT | m_vrf.get()->get_gid());
}

destination_id
la_vrf_redirect_destination_impl::get_destination_id(resolution_step_e prev_step) const
{
    // NPL looks at prefix 5'b11011 for VRF redirect
    return destination_id(NPL_DESTINATION_MASK_VRF_REDIRECT | m_vrf.get()->get_gid());
}
}
