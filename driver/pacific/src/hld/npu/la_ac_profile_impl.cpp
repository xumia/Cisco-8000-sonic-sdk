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

#include "la_ac_profile_impl.h"
#include "hld_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_ac_profile_impl::la_ac_profile_impl(const la_device_impl_wptr& device)
    : m_device(device), m_index(0), m_need_fallback(false), m_selector_type_pvlan_enabled(false)
{
}

la_ac_profile_impl::~la_ac_profile_impl()
{
}

la_status
la_ac_profile_impl::initialize(la_object_id_t oid, uint64_t ac_profile_index)
{
    m_oid = oid;
    m_index = ac_profile_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::destroy()
{
    const auto& table(m_device->m_tables.vlan_format_table);
    size_t max_size = table->max_size();
    for (int i = max_size - 1; i >= 0; i--) {
        size_t location = (size_t)i;
        npl_vlan_format_table_t::entry_pointer_type entry = nullptr;
        la_status status = table->get_entry(location, entry);
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
            return status;
        }
        if (entry == nullptr) {
            continue;
        }
        if (entry->key().vlan_profile == m_index) {
            table->pop(location);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::get_key_selector_per_format(la_packet_vlan_format_t tag_format, key_selector_e& out_key_selector)
{
    size_t entry_location;
    npl_vlan_format_table_t::value_type entry_value;

    // Lookup Vlan format table.
    la_status status = lookup_vlan_format_table(tag_format, entry_location, entry_value);
    return_on_error(status);

    switch (entry_value.payloads.update.sm_selector) {
    case NPL_SERVICE_MAPPING_SELECTOR_AC_PORT:
        out_key_selector = key_selector_e::PORT;
        break;

    case NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG:
        if (m_selector_type_pvlan_enabled) {
            out_key_selector = key_selector_e::PORT_PVLAN;
        } else {
            out_key_selector = key_selector_e::PORT_VLAN;
        }
        break;

    case NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG_TAG:
        out_key_selector = key_selector_e::PORT_VLAN_VLAN;
        break;

    case NPL_SERVICE_MAPPING_SELECTOR_AC_DOUBLE_ACCESS:
        out_key_selector = key_selector_e::PORT_VLAN_VLAN_WITH_FALLBACK;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::set_pwe_key_selector()
{
    la_packet_vlan_format_t pvf = {.outer_vlan_is_priority = false, .tpid1 = 0x0, .tpid2 = 0x0}; // Ignore the TPIDs

    la_status status = set_key_selector_per_format_with_pwe(pvf, la_ac_profile::key_selector_e::PORT, true /* is_pwe */);

    return status;
}

la_status
la_ac_profile_impl::set_key_selector_per_format(la_packet_vlan_format_t tag_format, key_selector_e key_selector)
{
    start_api_call("tag_format=", tag_format, "key_selector=", key_selector);
    la_status status = set_key_selector_per_format_with_pwe(tag_format, key_selector, false /*is_pwe*/);

    return status;
}

la_status
la_ac_profile_impl::set_key_selector_per_format_with_pwe(la_packet_vlan_format_t tag_format,
                                                         key_selector_e key_selector,
                                                         bool is_pwe)
{
    size_t location;
    npl_vlan_format_table_t::value_type entry_value;

    // Ensure key does not yet exist
    // Lookup Vlan format table.
    la_status status = lookup_vlan_format_table(tag_format, location, entry_value);

    if (status == LA_STATUS_SUCCESS) {
        return LA_STATUS_EEXIST;
    }

    if (status != LA_STATUS_ENOTFOUND) {
        return LA_STATUS_EUNKNOWN;
    }

    bool is_in_use = m_device->is_in_use(this);

    // If this ac_profile should support PORT_VLAN_VLAN_WITH_FALLBACK then all existing AC-ports of
    // the type PORT_VLAN, that reside on ethernet-ports that use this ac_profile, should also register
    // in the fallback table. Therefore - if this profile is already in use then setting a fallback-selector
    // will have to be propagated to all the users of the profile. To avoid that -
    // Refuse to set a fallback-selector in a profile that is already being used; except for cases
    // when a fallback-selector is already set (m_need_fallback == true)
    if ((key_selector == key_selector_e::PORT_VLAN_VLAN_WITH_FALLBACK) && !m_need_fallback && is_in_use) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // Ensure we have enough resources
    const auto& table(m_device->m_tables.vlan_format_table);
    size_t num_entries = table->size();
    size_t max_entries = table->max_size();

    if (num_entries == max_entries) {
        return LA_STATUS_ERESOURCE;
    }

    // Iterate over VLAN format table and find insertion point
    npl_vlan_format_table_t::key_type key, mask;
    npl_vlan_format_table_t::value_type value;

    status = build_kmv(tag_format, key_selector, key, mask, value, is_pwe);
    return_on_error(status);

    location = 0;

    while (location < num_entries) {
        npl_vlan_format_table_t::entry_pointer_type entry = nullptr;
        table->get_entry(location, entry);

        if (entry == nullptr) {
            log_err(HLD, "VLAN format table not contiguous.");
            return LA_STATUS_EUNKNOWN;
        }

        size_t new_num_tags = num_tags(key);
        const npl_vlan_format_table_t::key_type& entry_key = entry->key();
        size_t curr_num_tags = num_tags(entry_key);
        if (new_num_tags > curr_num_tags) {
            break;
        }

        location++;
    }

    // Update entry
    npl_vlan_format_table_t::entry_pointer_type dummy_entry = nullptr;
    status = table->push(location, key, mask, value, dummy_entry);
    return_on_error(status);

    if (key_selector == key_selector_e::PORT_VLAN_VLAN_WITH_FALLBACK) {
        m_need_fallback = true;
    }

    if (key_selector == key_selector_e::PORT_PVLAN) {
        m_selector_type_pvlan_enabled = true;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::set_default_vid_per_format_enabled(la_packet_vlan_format_t tag_format, bool enabled)
{
    start_api_call("tag_format=", tag_format, "enabled=", enabled);

    // Lookup vlan format table.
    size_t entry_location;
    npl_vlan_format_table_t::value_type entry_value;

    la_status status = lookup_vlan_format_table(tag_format, entry_location, entry_value);
    return_on_error(status);

    // Get key & mask information for a given tag_format.
    npl_vlan_format_table_t::key_type key, mask;
    npl_vlan_format_table_t::value_type dummy_value;

    status = build_kmv(tag_format, key_selector_e::PORT, key, mask, dummy_value, false /* is_pwe */);
    return_on_error(status);

    // Update entry_value with default vlan_id control flag.
    entry_value.payloads.update.vid_from_port = enabled;

    // Update entry.
    const auto& table(m_device->m_tables.vlan_format_table);
    npl_vlan_format_table_t::entry_pointer_type dummy_entry = nullptr;
    status = table->set(entry_location, key, mask, entry_value, dummy_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::get_qos_mode_per_format(la_packet_vlan_format_t tag_format, qos_mode_e& out_qos_mode)
{
    start_api_getter_call();

    size_t location;
    npl_vlan_format_table_t::value_type value;

    // Lookup Vlan format table.
    la_status status = lookup_vlan_format_table(tag_format, location, value);
    return_on_error(status);

    out_qos_mode = (value.payloads.update.enable_l3_qos) ? qos_mode_e::L3 : qos_mode_e::L2;

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::set_qos_mode_per_format(la_packet_vlan_format_t tag_format, qos_mode_e qos_mode)
{
    start_api_call("tag_format=", tag_format, "qos_mode=", qos_mode);

    size_t location;
    npl_vlan_format_table_t::value_type value;

    // Lookup Vlan format table.
    la_status status = lookup_vlan_format_table(tag_format, location, value);
    return_on_error(status);

    npl_vlan_format_table_t::key_type key, mask;
    npl_vlan_format_table_t::value_type dummy_value;

    // Build key and mask. We will use the value from obtained from above lookup.
    // Value is irrelevant, any key_selector_e::* will work here.
    status = build_kmv(tag_format, key_selector_e::PORT, key, mask, dummy_value, false /* is_pwe */);
    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_ENOTFOUND;
    }

    value.payloads.update.enable_l3_qos = (qos_mode == qos_mode_e::L3);

    const auto& table(m_device->m_tables.vlan_format_table);
    npl_vlan_format_table_t::entry_pointer_type dummy_entry = nullptr;

    // Update entry
    status = table->push(location, key, mask, value, dummy_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::lookup_vlan_format_table(la_packet_vlan_format_t tag_format,
                                             size_t& entry_location,
                                             npl_vlan_format_table_t::value_type& entry_value) const
{
    // Iterate over VLAN format table and find the entry.
    const auto& table(m_device->m_tables.vlan_format_table);
    size_t num_entries = table->size();

    npl_vlan_format_table_t::key_type key, mask;
    npl_vlan_format_table_t::value_type value;

    // Search for an entry with the same key and mask.
    // Value is irrelevant, any key_selector_e::* will work here.
    la_status status = build_kmv(tag_format, key_selector_e::PORT, key, mask, value, false /* is_pwe */);
    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_ENOTFOUND;
    }

    size_t location = 0;
    npl_vlan_format_table_t::entry_pointer_type entry = nullptr;
    npl_vlan_format_table_t::key_type entry_key, entry_mask;

    while (location < num_entries) {
        table->get_entry(location, entry);

        if (entry == nullptr) {
            log_err(HLD, "VLAN format table not contiguous.");
            return LA_STATUS_EUNKNOWN;
        }

        entry_key = entry->key();
        entry_mask = entry->mask();
        if (vlan_format_table_key_equal(entry_key, key) && vlan_format_table_key_equal(entry_mask, mask)) {
            break;
        }

        location++;
    }

    if (location == num_entries) {
        return LA_STATUS_ENOTFOUND;
    }

    entry_location = location;
    entry_value = entry->value();

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::get_default_pcpdei_per_format_enabled(la_packet_vlan_format_t tag_format, bool& out_enabled)
{
    start_api_getter_call();

    size_t entry_location;
    npl_vlan_format_table_t::value_type entry_value;

    // Lookup vlan format table.
    la_status status = lookup_vlan_format_table(tag_format, entry_location, entry_value);
    return_on_error(status);

    out_enabled = entry_value.payloads.update.pcp_dei_from_port;

    return LA_STATUS_SUCCESS;
}

la_status
la_ac_profile_impl::set_default_pcpdei_per_format_enabled(la_packet_vlan_format_t tag_format, bool enabled)
{
    start_api_call("tag_format=", tag_format, "enabled=", enabled);

    // Lookup vlan format table.
    size_t entry_location;
    npl_vlan_format_table_t::value_type entry_value;

    la_status status = lookup_vlan_format_table(tag_format, entry_location, entry_value);
    return_on_error(status);

    // Get key & mask information for a given tag_format.
    npl_vlan_format_table_t::key_type key, mask;
    npl_vlan_format_table_t::value_type dummy_value;

    status = build_kmv(tag_format, key_selector_e::PORT, key, mask, dummy_value, false /* is_pwe */);
    return_on_error(status);

    // Update entry_value with PCPDEI control flag.
    entry_value.payloads.update.pcp_dei_from_port = enabled;

    // Update entry.
    const auto& table(m_device->m_tables.vlan_format_table);
    npl_vlan_format_table_t::entry_pointer_type dummy_entry = nullptr;

    status = table->set(entry_location, key, mask, entry_value, dummy_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_ac_profile_impl::type() const
{
    return object_type_e::AC_PROFILE;
}

std::string
la_ac_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ac_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ac_profile_impl::oid() const
{
    return m_oid;
}

const la_device*
la_ac_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_ac_profile_impl::get_id() const
{
    return m_index;
}

la_status
la_ac_profile_impl::build_kmv(la_packet_vlan_format_t tag_format,
                              key_selector_e selector,
                              npl_vlan_format_table_t::key_type& key,
                              npl_vlan_format_table_t::key_type& mask,
                              npl_vlan_format_table_t::value_type& value,
                              bool is_pwe) const
{
    key.vlan_profile = m_index;
    key.is_priority = tag_format.outer_vlan_is_priority;
    key.header_1_type = ethtype_to_npl_protocol_type(tag_format.tpid1);
    key.header_2_type = ethtype_to_npl_protocol_type(tag_format.tpid2);

    mask.vlan_profile = 0xf;
    mask.is_priority = (tag_format.outer_vlan_is_priority) ? 0x1 : 0x0;
    mask.header_1_type = (npl_protocol_type_e)((key.header_1_type == NPL_PROTOCOL_TYPE_UNKNOWN) ? 0x0 : 0x1f);
    mask.header_2_type = (npl_protocol_type_e)((key.header_2_type == NPL_PROTOCOL_TYPE_UNKNOWN) ? 0x0 : 0x1f);

    value.action = NPL_VLAN_FORMAT_TABLE_ACTION_UPDATE;
    value.payloads.update.vid_from_port = (selector == key_selector_e::PORT_PVLAN);

    if ((tag_format.tpid1 == LA_TPID_INVALID) && (tag_format.tpid2 == LA_TPID_INVALID)) {
        value.payloads.update.pcp_dei_from_port = true;
    }

    if (is_pwe) {
        value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_PWE_TAG;
        value.payloads.update.sm_logical_db = NPL_SM_LDB_PWE_TAG;

        return LA_STATUS_SUCCESS;
    }

    switch (selector) {
    case key_selector_e::PORT:
        value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_AC_PORT;
        value.payloads.update.sm_logical_db = NPL_SM_LDB_AC_PORT;
        break;

    case key_selector_e::PORT_PVLAN:
        value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG;
        value.payloads.update.sm_logical_db = NPL_SM_LDB_AC_PORT_TAG;
        break;

    case key_selector_e::PORT_VLAN:
        value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG;
        value.payloads.update.sm_logical_db = NPL_SM_LDB_AC_PORT_TAG;
        break;

    case key_selector_e::PORT_VLAN_VLAN:
        value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG_TAG;
        value.payloads.update.sm_logical_db = NPL_SM_LDB_AC_PORT_TAG_TAG_OR_DOUBLE_ACCESS;
        break;

    case key_selector_e::PORT_VLAN_VLAN_WITH_FALLBACK:
        value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_AC_DOUBLE_ACCESS;
        value.payloads.update.sm_logical_db = NPL_SM_LDB_AC_PORT_TAG_TAG_OR_DOUBLE_ACCESS;
        break;

    default:
        log_err(HLD, "Unknown key_selector_e value.");
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

bool
la_ac_profile_impl::vlan_format_table_key_equal(const npl_vlan_format_table_t::key_type& key1,
                                                const npl_vlan_format_table_t::key_type& key2) const
{
    return (key1.vlan_profile == key2.vlan_profile && key1.is_priority == key2.is_priority
            && key1.header_1_type == key2.header_1_type
            && key1.header_2_type == key2.header_2_type);
}

size_t
la_ac_profile_impl::num_tags(const npl_vlan_format_table_t::key_type& key) const
{
    size_t tag1 = (key.header_1_type != NPL_PROTOCOL_TYPE_UNKNOWN) ? 1 : 0;
    size_t tag2 = (key.header_2_type != NPL_PROTOCOL_TYPE_UNKNOWN) ? 1 : 0;

    return (tag1 + tag2);
}

bool
la_ac_profile_impl::need_fallback()
{
    return m_need_fallback;
}

} // namespace silicon_one
