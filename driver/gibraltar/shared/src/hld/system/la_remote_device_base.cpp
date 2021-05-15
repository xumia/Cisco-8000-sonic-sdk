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

#include "system/la_remote_device_base.h"
#include "system/la_device_impl.h"

#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_remote_device_base::la_remote_device_base(const la_device_impl_wptr& device)
    : m_device(device), m_remote_device_id(LA_DEVICE_ID_INVALID), m_remote_device_revision(la_device_revision_e::NONE)
{
}

la_remote_device_base::~la_remote_device_base()
{
}

la_status
la_remote_device_base::initialize(la_object_id_t oid, la_device_id_t remote_device_id, la_device_revision_e remote_device_revision)
{
    m_oid = oid;
    m_remote_device_id = remote_device_id;
    m_remote_device_revision = remote_device_revision;

    return LA_STATUS_SUCCESS;
}

la_status
la_remote_device_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_remote_device_base::type() const
{
    return object_type_e::REMOTE_DEVICE;
}

const la_device*
la_remote_device_base::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_remote_device_base::oid() const
{
    return m_oid;
}

std::string
la_remote_device_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_remote_device(oid=" << m_oid << ")";
    return log_message.str();
}

la_device_id_t
la_remote_device_base::get_remote_device_id() const
{
    return m_remote_device_id;
}

la_device_revision_e
la_remote_device_base::get_remote_device_revision() const
{
    return m_remote_device_revision;
}
}
