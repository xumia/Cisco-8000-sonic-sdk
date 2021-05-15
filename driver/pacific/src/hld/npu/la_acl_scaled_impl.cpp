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

#include "la_acl_scaled_impl.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_destination.h"
//#include "la_acl_ingress_sec_scaled_ipv4.h"
#include "la_acl_scaled_delegate.h"
#include "nplapi/npl_types.h"
#include "system/la_device_impl.h"

#include "hld_utils.h"
#include "nplapi/npl_table_types.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_acl_scaled_impl::la_acl_scaled_impl(silicon_one::la_device_impl_wptr device) : m_device(device), m_delegate(nullptr)
{
}

la_acl_scaled_impl::~la_acl_scaled_impl() = default;

la_status
la_acl_scaled_impl::initialize(la_object_id_t oid, stage_e stage, type_e acl_type)
{
    m_oid = oid;
    if (m_delegate != nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (acl_type == la_acl::type_e::UNIFIED) {
        // m_delegate = make_unique<la_acl_ingress_sec_scaled_ipv4>(m_device, this);
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_delegate == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_delegate->initialize(stage, acl_type);
    if (status != LA_STATUS_SUCCESS) {
        m_delegate.reset();
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_scaled_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    return m_delegate->destroy();
}

// la_object API-s
la_object::object_type_e
la_acl_scaled_impl::type() const
{
    return object_type_e::ACL_SCALED;
}

std::string
la_acl_scaled_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_acl_scaled_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_acl_scaled_impl::oid() const
{
    return m_oid;
}

// la_acl API-s
const la_device*
la_acl_scaled_impl::get_device() const
{
    return m_device.get();
}

// la_acl API-s
la_status
la_acl_scaled_impl::get_type(type_e& out_type) const
{
    return m_delegate->get_type(out_type);
}

la_status
la_acl_scaled_impl::get_acl_key_profile(const la_acl_key_profile*& out_acl_key_profile) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_acl_scaled_impl::get_acl_command_profile(const la_acl_command_profile*& out_acl_command_profile) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

const la_acl_delegate_wptr
la_acl_scaled_impl::get_delegate() const
{
    return m_delegate;
}

la_status
la_acl_scaled_impl::get_count(size_t& out_count) const
{
    return m_delegate->get_count(out_count);
}

la_status
la_acl_scaled_impl::append(const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    start_api_call("key_val=", "NOT IMPLEMENTED LOG", "cmd=", "NOT IMPLEMENTED LOG");
    return m_delegate->append(key_val, cmd);
}

la_status
la_acl_scaled_impl::insert(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    start_api_call("position=", position, "key_val=", "NOT IMPLEMENTED LOG", "cmd=", "NOT IMPLEMENTED LOG");
    return m_delegate->insert(position, key_val, cmd);
}

la_status
la_acl_scaled_impl::set(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    start_api_call("position=", position, "key_val=", "NOT IMPLEMENTED LOG", "cmd=", "NOT IMPLEMENTED LOG");
    return m_delegate->set(position, key_val, cmd);
}

la_status
la_acl_scaled_impl::erase(size_t position)
{
    start_api_call("position=", position);
    return m_delegate->erase(position);
}

la_status
la_acl_scaled_impl::clear()
{
    start_api_call("");
    return m_delegate->clear();
}

la_status
la_acl_scaled_impl::get(size_t position, acl_entry_desc& out_acl_entry_desc) const
{
    return m_delegate->get(position, out_acl_entry_desc);
}

// la_acl_scaled API-s
la_status
la_acl_scaled_impl::get_count(scale_field_e scale_field, size_t& out_count) const
{
    return m_delegate->get_count(scale_field, out_count);
}

la_status
la_acl_scaled_impl::append(scale_field_e scale_field, const la_acl_scale_field_key& sf_key, const la_acl_scale_field_val& sf_val)
{
    start_api_call("scale_field=", scale_field, "sf_key=NOT IMPLEMENTED LOG", "sf_val=", sf_val);
    return m_delegate->append(scale_field, sf_key, sf_val);
}

la_status
la_acl_scaled_impl::insert(scale_field_e scale_field,
                           size_t position,
                           const la_acl_scale_field_key& sf_key,
                           const la_acl_scale_field_val& sf_val)
{
    start_api_call("scale_field=", scale_field, "position=", position, "sf_key=", "NOT IMPLEMENTED LOG", "sf_val=", sf_val);
    return m_delegate->insert(scale_field, position, sf_key, sf_val);
}

la_status
la_acl_scaled_impl::set(scale_field_e scale_field,
                        size_t position,
                        const la_acl_scale_field_key& sf_key,
                        const la_acl_scale_field_val& sf_val)
{
    start_api_call("scale_field=", scale_field, "position=", position, "sf_key=", "NOT IMPLEMENTED LOG", "sf_val=", sf_val);
    return m_delegate->set(scale_field, position, sf_key, sf_val);
}

la_status
la_acl_scaled_impl::erase(scale_field_e scale_field, size_t position)
{
    start_api_call("scale_field=", scale_field, "position=", position);
    return m_delegate->erase(scale_field, position);
}

la_status
la_acl_scaled_impl::get(scale_field_e scale_field,
                        size_t position,
                        const la_acl_scale_field_key*& out_sf_key,
                        const la_acl_scale_field_val*& out_sf_val) const
{
    if ((scale_field == scale_field_e::UNDEF) || (scale_field >= scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    return m_delegate->get(scale_field, position, out_sf_key, out_sf_val);
}

la_status
la_acl_scaled_impl::get_max_available_space(size_t& out_available_space) const
{
    return m_delegate->get_tcam_max_available_space(out_available_space);
}

} // namespace silicon_one
