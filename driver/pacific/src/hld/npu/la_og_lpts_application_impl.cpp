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

#include "la_og_lpts_application_impl.h"
#include "api/npu/la_pcl.h"
#include "api/types/la_lpts_types.h"
#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"
#include "npu/la_vrf_impl.h"
#include "system/la_device_impl.h"

namespace silicon_one
{
la_og_lpts_application_impl::la_og_lpts_application_impl(const la_device_impl_wptr& device)
    : m_device(device), m_oid(LA_OBJECT_ID_INVALID)
{
}

la_og_lpts_application_impl::~la_og_lpts_application_impl() = default;

la_status
la_og_lpts_application_impl::populate_lpts_og_application_table_entry()
{
    uint64_t index = static_cast<uint64_t>(m_app_id);
    npl_lpts_og_application_table_t::key_type key;
    npl_lpts_og_application_table_t::key_type mask;
    npl_lpts_og_application_table_t::value_type value;
    npl_lpts_og_application_table_t::entry_type* entry;

    key.ip_version = static_cast<uint64_t>(m_app_properties.val.ip_version);
    key.ipv4_l4_protocol = static_cast<uint64_t>(m_app_properties.val.protocol);
    key.ipv6_l4_protocol = static_cast<uint64_t>(m_app_properties.val.protocol);
    key.l4_ports.src_port = m_app_properties.val.ports.sport;
    key.l4_ports.dst_port = m_app_properties.val.ports.dport;
    key.fragmented = m_app_properties.val.fragment;

    mask.ip_version = static_cast<uint64_t>(m_app_properties.mask.ip_version);
    if (m_app_properties.val.ip_version == la_ip_version_e::IPV6) {
        mask.ipv6_l4_protocol = static_cast<uint64_t>(m_app_properties.mask.protocol);
    } else {
        mask.ipv4_l4_protocol = static_cast<uint64_t>(m_app_properties.mask.protocol);
    }
    mask.l4_ports.src_port = m_app_properties.mask.ports.sport;
    mask.l4_ports.dst_port = m_app_properties.mask.ports.dport;
    mask.fragmented = m_app_properties.mask.fragment;

    value.payloads.og_app_config.app_data.lpts_og_app_id = static_cast<uint64_t>(m_app_id);
    if (m_src_pcl == nullptr) {
        value.payloads.og_app_config.src.compress = false;
    } else {
        value.payloads.og_app_config.src.compress = true;
        la_pcl_gid_t pcl_id;
        la_status status = m_src_pcl->get_pcl_gid(pcl_id);
        return_on_error(status);
        value.payloads.og_app_config.src.pcl_id.val = static_cast<uint64_t>(pcl_id);
    }

    la_status status;
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }
        status = m_device->m_tables.lpts_og_application_table[slice_id]->insert(index, key, mask, value, entry);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_og_lpts_application_impl::destroy_lpts_og_application_table_entry()
{
    uint64_t index = static_cast<uint64_t>(m_app_id);
    la_status status;
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }
        status = m_device->m_tables.lpts_og_application_table[slice_id]->erase(index);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_og_lpts_application_impl::initialize(la_object_id_t oid, const la_lpts_app_properties& properties, const la_pcl_wptr& src_pcl)
{
    m_oid = oid;
    m_src_pcl = src_pcl;
    m_app_properties = properties;

    la_status status = app_id_alloc(m_app_id);
    return_on_error(status);

    status = populate_lpts_og_application_table_entry();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_og_lpts_application_impl::type() const
{
    return object_type_e::OG_LPTS_APPLICATION;
}

std::string
la_og_lpts_application_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_og_lpts_application_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_og_lpts_application_impl::oid() const
{
    return m_oid;
}

const la_device*
la_og_lpts_application_impl::get_device() const
{
    return m_device.get();
}

la_status
la_og_lpts_application_impl::get_properties(la_lpts_app_properties& out_properties) const
{
    start_api_getter_call();
    out_properties = m_app_properties;
    return LA_STATUS_SUCCESS;
}

la_status
la_og_lpts_application_impl::get_src_pcl(la_pcl*& out_src_pcl) const
{
    start_api_getter_call();
    out_src_pcl = m_src_pcl.get();
    return LA_STATUS_SUCCESS;
}

la_lpts_app_gid_t
la_og_lpts_application_impl::get_app_id() const
{
    start_api_getter_call();
    return m_app_id;
}

la_status
la_og_lpts_application_impl::app_id_alloc(la_lpts_app_gid_t& id)
{
    size_t tmp_id;
    bool allocated = m_device->m_og_lpts_app_ids.allocate(tmp_id);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    m_device->m_og_lpts_app_ids_allocated++;

    m_app_id = tmp_id;
    id = m_app_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_og_lpts_application_impl::app_id_free(la_lpts_app_gid_t id)
{
    if (m_device->m_og_lpts_app_ids_allocated <= 0) {
        return LA_STATUS_EINVAL;
    }

    m_device->m_og_lpts_app_ids.release(id);
    m_device->m_og_lpts_app_ids_allocated--;

    return LA_STATUS_SUCCESS;
}

la_status
la_og_lpts_application_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }
    la_status status = destroy_lpts_og_application_table_entry();
    return_on_error(status);

    return app_id_free(m_app_id);
}
}
