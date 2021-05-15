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

#include "system/la_remote_port_impl.h"
#include "system/la_device_impl.h"
#include "system/la_remote_device_base.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_remote_port_impl::la_remote_port_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_remote_slice(LA_SLICE_ID_INVALID),
      m_remote_ifg(LA_IFG_ID_INVALID),
      m_remote_serdes_base(LA_SERDES_INVALID),
      m_remote_serdes_count(LA_SERDES_INVALID),
      m_remote_pif_base(LA_PIF_INVALID),
      m_remote_pif_count(LA_PIF_INVALID)
{
}

la_remote_port_impl::~la_remote_port_impl()
{
}

la_status
la_remote_port_impl::initialize(la_object_id_t oid,
                                la_remote_device* remote_device,
                                la_slice_id_t remote_slice_id,
                                la_ifg_id_t remote_ifg_id,
                                la_uint_t remote_first_serdes_id,
                                la_uint_t remote_last_serdes_id,
                                la_uint_t remote_first_pif_id,
                                la_uint_t remote_last_pif_id,
                                la_mac_port::port_speed_e remote_port_speed)
{
    if (remote_device == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    m_remote_device = m_device->get_sptr(remote_device);
    m_oid = oid;
    m_remote_slice = remote_slice_id;
    m_remote_ifg = remote_ifg_id;
    m_remote_serdes_base = remote_first_serdes_id;
    m_remote_serdes_count = remote_last_serdes_id - remote_first_serdes_id;
    m_remote_pif_base = remote_first_pif_id;
    m_remote_pif_count = remote_last_pif_id - remote_first_pif_id;
    m_speed = remote_port_speed;

    m_device->add_object_dependency(remote_device, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_remote_port_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    if (m_remote_device != nullptr) {
        m_device->remove_object_dependency(m_remote_device, this);
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_remote_port_impl::type() const
{
    return object_type_e::REMOTE_PORT;
}

const la_device*
la_remote_port_impl::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_remote_port_impl::oid() const
{
    return m_oid;
}

std::string
la_remote_port_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_remote_port(oid=" << m_oid << ")";
    return log_message.str();
}

const la_remote_device*
la_remote_port_impl::get_remote_device() const
{
    return m_remote_device.get();
}

la_device_revision_e
la_remote_port_impl::get_remote_device_revision() const
{
    return m_remote_device->get_remote_device_revision();
}

la_slice_id_t
la_remote_port_impl::get_remote_slice() const
{
    return m_remote_slice;
}

la_ifg_id_t
la_remote_port_impl::get_remote_ifg() const
{
    return m_remote_ifg;
}

la_uint_t
la_remote_port_impl::get_remote_first_serdes_id() const
{
    return m_remote_serdes_base;
}

size_t
la_remote_port_impl::get_remote_num_of_serdes() const
{
    return m_remote_serdes_count;
}

la_uint_t
la_remote_port_impl::get_remote_first_pif_id() const
{
    return m_remote_pif_base;
}

size_t
la_remote_port_impl::get_remote_num_of_pif() const
{
    return m_remote_pif_count;
}

la_status
la_remote_port_impl::get_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_speed;

    return LA_STATUS_SUCCESS;
}
}
