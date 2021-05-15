// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "system/la_npu_host_destination_impl.h"

#include "system/la_device_impl.h"
#include "system/la_npu_host_port_base.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_npu_host_destination_impl::la_npu_host_destination_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_npu_host_destination_impl::~la_npu_host_destination_impl() = default;

la_status
la_npu_host_destination_impl::initialize(la_object_id_t oid, la_npu_host_port* npu_host_port)
{
    m_oid = oid;
    if (npu_host_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    m_npu_host_port = m_device->get_sptr<la_npu_host_port_base>(npu_host_port);

    // Update object dependencies
    m_device->add_object_dependency(npu_host_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_npu_host_destination_impl::destroy()
{
    if (m_npu_host_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // Remove object dependencies
    m_device->remove_object_dependency(m_npu_host_port, this);
    m_npu_host_port = nullptr;

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_npu_host_destination_impl::type() const
{
    return object_type_e::NPU_HOST_DESTINATION;
}

const la_device*
la_npu_host_destination_impl::get_device() const
{
    return m_device.get();
}

std::string
la_npu_host_destination_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_npu_host_destination_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_npu_host_destination_impl::oid() const
{
    return m_oid;
}

const la_npu_host_port_base*
la_npu_host_destination_impl::get_npu_host_port() const
{
    return m_npu_host_port.get();
}
} // namespace silicon_one
