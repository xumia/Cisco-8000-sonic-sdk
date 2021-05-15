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

#include "la_security_group_cell_base.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "npu/counter_utils.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_security_group_cell_base::la_security_group_cell_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_sgt(0),
      m_dgt(0),
      m_ip_version(la_ip_version_e::IPV4),
      m_sgacl(nullptr),
      m_allow_drop(false),
      m_sgacl_id(0),
      m_sgacl_bincode(0)
{
}

la_security_group_cell_base::~la_security_group_cell_base()
{
}

la_status
la_security_group_cell_base::initialize(la_object_id_t oid,
                                        la_sgt_t sgt,
                                        la_dgt_t dgt,
                                        la_ip_version_e ip_version,
                                        const la_counter_set_wptr& counter)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::set_counter(la_counter_set* counter)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::get_counter(la_counter_set*& out_counter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::set_monitor_mode(bool allow_drop)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::get_monitor_mode(bool& out_allow_drop) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::set_acl(la_acl* sgacl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::clear_acl()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::get_acl(la_acl*& out_sgacl) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

const la_device*
la_security_group_cell_base::get_device() const
{
    // return m_device;
    return m_device.get();
}

la_object::object_type_e
la_security_group_cell_base::type() const
{
    return la_object::object_type_e::SECURITY_GROUP_CELL;
}

std::string
la_security_group_cell_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_security_group_cell_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_security_group_cell_base::oid() const
{
    return m_oid;
}

la_status
la_security_group_cell_base::set_bincode(la_uint32_t bincode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_security_group_cell_base::get_bincode(la_uint32_t& out_bincode) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
