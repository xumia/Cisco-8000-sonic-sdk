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

#include "system/la_l2_punt_destination_impl.h"
#include "npu/la_stack_port_base.h"
#include "system/la_device_impl.h"
#include "system/la_punt_inject_port_base.h"

#include "nplapi/npl_constants.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_l2_punt_destination_impl::la_l2_punt_destination_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_gid(LA_L2_PUNT_DESTINATION_GID_INVALID),
      m_pi_port(nullptr),
      m_mac_addr(),
      m_vlan_tag(),
      m_stack_port(nullptr)
{
}

la_l2_punt_destination_impl::~la_l2_punt_destination_impl()
{
}

la_status
la_l2_punt_destination_impl::initialize(la_object_id_t oid,
                                        la_l2_punt_destination_gid_t gid,
                                        la_punt_inject_port_base* pi_port,
                                        la_mac_addr_t mac_addr,
                                        const la_vlan_tag_tci_t& vlan_tag)
{
    m_oid = oid;
    if (m_pi_port != nullptr) {
        return LA_STATUS_EINVAL;
    }

    m_gid = gid;
    m_mac_addr.flat = mac_addr.flat;
    m_pi_port = m_device->get_sptr(pi_port);
    m_vlan_tag = vlan_tag;

    la_mac_addr_t port_mac_addr;
    la_status status = pi_port->get_mac(port_mac_addr);
    return_on_error(status);

    status = m_device->configure_redirect_eth_encap(m_gid, m_mac_addr, port_mac_addr, m_vlan_tag);
    return_on_error(status);

    // Update object dependencies
    m_device->add_object_dependency(pi_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_punt_destination_impl::initialize(la_object_id_t oid,
                                        la_l2_punt_destination_gid_t gid,
                                        la_stack_port_base* stack_port,
                                        la_mac_addr_t mac_addr,
                                        const la_vlan_tag_tci_t& vlan_tag)
{
    if (m_stack_port != nullptr) {
        return LA_STATUS_EINVAL;
    }

    m_oid = oid;
    m_gid = gid;
    m_mac_addr.flat = mac_addr.flat;
    m_stack_port = m_device->get_sptr(stack_port);
    m_vlan_tag = vlan_tag;

    la_mac_addr_t port_mac_addr;
    la_status status = m_stack_port->get_remote_punt_mac(port_mac_addr);
    return_on_error(status);

    status = m_device->configure_redirect_eth_encap(m_gid, m_mac_addr, port_mac_addr, m_vlan_tag);
    return_on_error(status);

    // Update object dependencies
    m_device->add_object_dependency(stack_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_punt_destination_impl::destroy()
{
    if ((m_pi_port == nullptr) && (m_stack_port == nullptr)) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->clear_redirect_eth_encap(m_gid);
    return_on_error(status);

    // Remove object dependencies
    if (m_pi_port != nullptr) {
        m_device->remove_object_dependency(m_pi_port, this);
    }

    if (m_stack_port != nullptr) {
        m_device->remove_object_dependency(m_stack_port, this);
    }
    m_pi_port = nullptr;
    m_stack_port = nullptr;

    return LA_STATUS_SUCCESS;
}

la_l2_punt_destination_gid_t
la_l2_punt_destination_impl::get_gid() const
{
    start_api_getter_call("");
    return m_gid;
}

la_status
la_l2_punt_destination_impl::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr.flat = m_mac_addr.flat;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_punt_destination_impl::get_vlan_tag(la_vlan_tag_tci_t& out_vlan_tag) const
{
    out_vlan_tag.raw = m_vlan_tag.raw;

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_l2_punt_destination_impl::type() const
{
    return object_type_e::L2_PUNT_DESTINATION;
}

const la_device*
la_l2_punt_destination_impl::get_device() const
{
    return m_device.get();
}

std::string
la_l2_punt_destination_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l2_punt_destination_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l2_punt_destination_impl::oid() const
{
    return m_oid;
}

const la_punt_inject_port_base*
la_l2_punt_destination_impl::get_punt_inject_port() const
{
    return m_pi_port.get();
}

const la_stack_port_base*
la_l2_punt_destination_impl::get_stack_port() const
{
    return m_stack_port.get();
}

destination_id
la_l2_punt_destination_impl::get_destination_id(resolution_step_e prev_step) const
{
    if (m_stack_port != nullptr) {
        return m_stack_port.get()->get_destination_id(prev_step);
    } else if (m_pi_port != nullptr) {
        return m_pi_port.get()->get_destination_id(prev_step);
    } else {
        return DESTINATION_ID_INVALID;
    }
}

la_status
la_l2_punt_destination_impl::get_punt_port_mac(la_mac_addr_t& out_mac_addr) const
{
    if (m_stack_port != nullptr) {
        return m_stack_port.get()->get_remote_punt_mac(out_mac_addr);
    } else if (m_pi_port != nullptr) {
        return m_pi_port.get()->get_mac(out_mac_addr);
    } else {
        return LA_STATUS_EINVAL;
    }
}
}
