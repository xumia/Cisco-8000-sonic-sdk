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

#include "la_mpls_label_destination_impl.h"
#include "nplapi/npl_constants.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_mpls_label_destination_impl::la_mpls_label_destination_impl(const la_device_impl_wptr& device)
    : m_device(device), m_vpn_label_ptr(LA_L3_DESTINATION_GID_INVALID), m_destination(nullptr)
{
}

la_mpls_label_destination_impl::~la_mpls_label_destination_impl()
{
}

const la_device*
la_mpls_label_destination_impl::get_device() const
{
    return m_device.get();
}

la_object::object_type_e
la_mpls_label_destination_impl::type() const
{
    return la_object::object_type_e::MPLS_LABEL_DESTINATION;
}

std::string
la_mpls_label_destination_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_mpls_label_destination_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_mpls_label_destination_impl::oid() const
{
    return m_oid;
}

la_mpls_label
la_mpls_label_destination_impl::get_label() const
{
    return m_label;
}

la_l3_destination*
la_mpls_label_destination_impl::get_destination() const
{
    return m_destination.get();
}

la_l3_destination_gid_t
la_mpls_label_destination_impl::get_gid() const
{
    return m_vpn_label_ptr;
}

la_status
la_mpls_label_destination_impl::initialize(la_object_id_t oid,
                                           size_t native_ce_ptr_table_index,
                                           la_l3_destination_gid_t vpn_label_ptr,
                                           la_mpls_label label,
                                           const la_l3_destination_wptr& destination)
{
    m_oid = oid;
    m_vpn_label_ptr = vpn_label_ptr;
    m_label = label;
    m_destination = destination;

    m_device->add_object_dependency(destination, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_label_destination_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    m_device->remove_object_dependency(m_destination, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_label_destination_impl::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_label_destination_impl::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
