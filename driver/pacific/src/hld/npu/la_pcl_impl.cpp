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

#include "la_pcl_impl.h"
#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"
#include "npu/la_vrf_impl.h"
#include "system/la_device_impl.h"

namespace silicon_one
{
la_pcl_impl::la_pcl_impl(const la_device_impl_wptr& device) : m_device(device), m_oid(LA_OBJECT_ID_INVALID)
{
}

la_pcl_impl::~la_pcl_impl() = default;

la_status
la_pcl_impl::get_type(pcl_type_e& out_type) const
{
    start_api_getter_call();
    out_type = m_pcl_type;
    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::get_feature(pcl_feature_type_e& out_feature) const
{
    start_api_getter_call();
    out_feature = m_feature;
    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::get_pcl_gid(la_pcl_gid_t& out_pcl_gid) const
{
    start_api_getter_call();
    out_pcl_gid = m_pcl_gid;
    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::get_prefixes(la_pcl_v4_vec_t& out_prefixes) const
{
    start_api_getter_call();
    out_prefixes = m_v4_prefixes;

    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::get_prefixes(la_pcl_v6_vec_t& out_prefixes) const
{
    start_api_getter_call();
    out_prefixes = m_v6_prefixes;

    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::add_prefixes(const la_pcl_v4_vec_t& prefixes)
{
    start_api_call("prefixes=", prefixes);
    la_status status;
    if (m_feature != pcl_feature_type_e::LPTS) {
        return LA_STATUS_EINVAL;
    }

    const auto& table_v4_og_lpts_em_table(m_device->m_tables.ipv4_og_pcl_em_table);
    const auto& table_v4_og_lpts_lpm_table(m_device->m_tables.ipv4_og_pcl_lpm_table);
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == 32) {
            status
                = add_og_em_entry(table_v4_og_lpts_em_table, prefix.prefix, prefix.bincode, 0 /* user_data */, false /* modify */);
        } else {
            status = add_og_lpm_entry(
                table_v4_og_lpts_lpm_table, prefix.prefix, prefix.bincode, 0 /* user_data */, false /* modify */);
        }
        return_on_error(status);
        m_v4_prefixes.push_back(prefix);
    }
    return status;
}

la_status
la_pcl_impl::add_prefixes(const la_pcl_v6_vec_t& prefixes)
{
    start_api_call("prefixes=", prefixes);
    la_status status;
    if (m_feature != pcl_feature_type_e::LPTS) {
        return LA_STATUS_EINVAL;
    }

    const auto& table_v6_og_lpts_em_table(m_device->m_tables.ipv6_og_pcl_em_table);
    const auto& table_v6_og_lpts_lpm_table(m_device->m_tables.ipv6_og_pcl_lpm_table);
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == 128) {
            status
                = add_og_em_entry(table_v6_og_lpts_em_table, prefix.prefix, prefix.bincode, 0 /* user_data */, false /* modify */);
        } else {
            status = add_og_lpm_entry(
                table_v6_og_lpts_lpm_table, prefix.prefix, prefix.bincode, 0 /* user_data */, false /* modify */);
        }
        return_on_error(status);
        m_v6_prefixes.push_back(prefix);
    }
    return status;
}

la_status
la_pcl_impl::remove_prefixes(const la_pcl_v4_vec_t& prefixes)
{
    start_api_call("prefixes=", prefixes);
    la_status status;
    if (m_feature != pcl_feature_type_e::LPTS) {
        return LA_STATUS_EINVAL;
    }

    const auto& table_v4_og_lpts_em_table(m_device->m_tables.ipv4_og_pcl_em_table);
    const auto& table_v4_og_lpts_lpm_table(m_device->m_tables.ipv4_og_pcl_lpm_table);
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == 32) {
            status = remove_og_em_entry(table_v4_og_lpts_em_table, prefix.prefix);
        } else {
            status = remove_og_lpm_entry(table_v4_og_lpts_lpm_table, prefix.prefix, prefix.prefix.length);
        }
        return_on_error(status);
        la_ipv4_prefix_t prefix_to_delete = prefix.prefix;
        auto it
            = std::find_if(m_v4_prefixes.begin(), m_v4_prefixes.end(), [&prefix_to_delete](const la_pcl_v4& pcl_prefix) -> bool {
                  return prefix_to_delete == pcl_prefix.prefix;
              });
        if (it == m_v4_prefixes.end()) {
            return LA_STATUS_ENOTFOUND;
        }
        m_v4_prefixes.erase(it);
    }
    return status;
}

la_status
la_pcl_impl::remove_prefixes(const la_pcl_v6_vec_t& prefixes)
{
    start_api_call("prefixes=", prefixes);
    la_status status;
    if (m_feature != pcl_feature_type_e::LPTS) {
        return LA_STATUS_EINVAL;
    }

    const auto& table_v6_og_lpts_em_table(m_device->m_tables.ipv6_og_pcl_em_table);
    const auto& table_v6_og_lpts_lpm_table(m_device->m_tables.ipv6_og_pcl_lpm_table);
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == 128) {
            status = remove_og_em_entry(table_v6_og_lpts_em_table, prefix.prefix);
        } else {
            status = remove_og_lpm_entry(table_v6_og_lpts_lpm_table, prefix.prefix, prefix.prefix.length);
        }
        return_on_error(status);
        la_ipv6_prefix_t prefix_to_delete = prefix.prefix;
        auto it
            = std::find_if(m_v6_prefixes.begin(), m_v6_prefixes.end(), [&prefix_to_delete](const la_pcl_v6& pcl_prefix) -> bool {
                  return prefix_to_delete == pcl_prefix.prefix;
              });
        if (it == m_v6_prefixes.end()) {
            return LA_STATUS_ENOTFOUND;
        }
        m_v6_prefixes.erase(it);
    }
    return status;
}

la_status
la_pcl_impl::replace_prefixes(const la_pcl_v4_vec_t& prefixes)
{
    la_pcl_v4_vec_t prefixes_to_remove = m_v4_prefixes;
    la_status status = remove_prefixes(prefixes_to_remove);
    return_on_error(status);
    status = add_prefixes(prefixes);
    return status;
}

la_status
la_pcl_impl::replace_prefixes(const la_pcl_v6_vec_t& prefixes)
{
    la_pcl_v6_vec_t prefixes_to_remove = m_v6_prefixes;
    la_status status = remove_prefixes(prefixes_to_remove);
    return_on_error(status);
    status = add_prefixes(prefixes);
    return status;
}

la_status
la_pcl_impl::modify_prefixes(const la_pcl_v4_vec_t& prefixes)
{
    start_api_call("prefixes=", prefixes);
    la_status status;
    if (m_feature != pcl_feature_type_e::LPTS) {
        return LA_STATUS_EINVAL;
    }
    const auto& table_v4_og_lpts_em_table(m_device->m_tables.ipv4_og_pcl_em_table);
    const auto& table_v4_og_lpts_lpm_table(m_device->m_tables.ipv4_og_pcl_lpm_table);
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == 32) {
            status
                = add_og_em_entry(table_v4_og_lpts_em_table, prefix.prefix, prefix.bincode, 0 /* user_data */, true /* modify */);
        } else {
            status
                = add_og_lpm_entry(table_v4_og_lpts_lpm_table, prefix.prefix, prefix.bincode, 0 /* user_data */, true /* modify */);
        }
        return_on_error(status);
        for (auto& pcl_v4_prefix : m_v4_prefixes) {
            if (pcl_v4_prefix.prefix == prefix.prefix) {
                pcl_v4_prefix.bincode = prefix.bincode;
            }
        }
    }
    return status;
}

la_status
la_pcl_impl::modify_prefixes(const la_pcl_v6_vec_t& prefixes)
{
    start_api_call("prefixes=", prefixes);
    la_status status;
    if (m_feature != pcl_feature_type_e::LPTS) {
        return LA_STATUS_EINVAL;
    }
    const auto& table_v6_og_lpts_em_table(m_device->m_tables.ipv6_og_pcl_em_table);
    const auto& table_v6_og_lpts_lpm_table(m_device->m_tables.ipv6_og_pcl_lpm_table);
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == 128) {
            status
                = add_og_em_entry(table_v6_og_lpts_em_table, prefix.prefix, prefix.bincode, 0 /* user_data */, true /* modify */);
        } else {
            status
                = add_og_lpm_entry(table_v6_og_lpts_lpm_table, prefix.prefix, prefix.bincode, 0 /* user_data */, true /* modify */);
        }
        return_on_error(status);
        for (auto& pcl_v6_prefix : m_v6_prefixes) {
            if (pcl_v6_prefix.prefix == prefix.prefix) {
                pcl_v6_prefix.bincode = prefix.bincode;
            }
        }
    }
    return status;
}

la_status
la_pcl_impl::get_max_pcl_gids(int& max_pcl_gids) const
{
    la_status status = m_device->get_int_property(la_device_property_e::MAX_NUM_PCL_GIDS, max_pcl_gids);
    return_on_error(status);
    if (max_pcl_gids == 0) {
        return LA_STATUS_ERESOURCE;
    }
    return LA_STATUS_SUCCESS;
}

// allocate_pcl_gid, allocate a PCL ID from the pool of:
// MIN_PCL_VRF_RANGE - MAX_PCL_VRF_RANGE.
// This is actually a small range of VRFs that has been
// allocated from the top end of the VRF pool.
// The pcl id is actually a special VRF ID, that is reserved for
// use only with PCLs.
la_status
la_pcl_impl::allocate_pcl_gid(void)
{
    int max_pcl_gids;
    la_status status = get_max_pcl_gids(max_pcl_gids);
    return_on_error(status);

    size_t tmp_id;
    bool allocated = m_device->m_pcl_gids.allocate(tmp_id);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    m_pcl_gid = tmp_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::free_pcl_gid(void)
{
    int max_pcl_gids;
    la_status status = get_max_pcl_gids(max_pcl_gids);
    return_on_error(status);

    m_device->m_pcl_gids.release(m_pcl_gid);

    return LA_STATUS_SUCCESS;
}

void
la_pcl_impl::populate_lpm_key(la_ipv4_addr_t addr, npl_ipv4_og_pcl_lpm_table_key_t& out_key) const
{
    // The key must range from 0 - 127
    out_key.pcl_id.val = m_pcl_gid;
    out_key.ip_address = addr.s_addr;
}

void
la_pcl_impl::populate_lpm_key(la_ipv6_addr_t addr, npl_ipv6_og_pcl_lpm_table_key_t& out_key) const
{

    // The key must range from 0 - 127
    out_key.pcl_id.val = m_pcl_gid;
    out_key.ip_address[0] = addr.q_addr[0];
    out_key.ip_address[1] = addr.q_addr[1];
}

void
la_pcl_impl::populate_em_key(la_ipv4_addr_t addr, npl_ipv4_og_pcl_em_table_key_t& out_key) const
{

    // The key must range from 0 - 127
    out_key.pcl_id.val = m_pcl_gid;
    out_key.ip_address_31_20 = (addr.s_addr >> 20) & 0xfff;
    out_key.ip_address_19_0 = addr.s_addr & 0xfffff;
}

void
la_pcl_impl::populate_em_key(la_ipv6_addr_t addr, npl_ipv6_og_pcl_em_table_key_t& out_key) const
{

    // The key must range from 0 - 127
    out_key.pcl_id.val = m_pcl_gid;
    out_key.ip_address[0] = addr.q_addr[0];
    out_key.ip_address[1] = addr.q_addr[1];
}

template <class _PrefixType>
bool
la_pcl_impl::is_prefix_valid(_PrefixType prefix) const
{
    _PrefixType dummy = prefix;
    apply_prefix_mask(dummy.addr, prefix.length);
    bool is_valid = (memcmp(&dummy.addr, &prefix.addr, sizeof(dummy.addr)) == 0);
    return is_valid;
}

template <class _TableType, class _PrefixType>
la_status
la_pcl_impl::add_og_lpm_entry(const std::shared_ptr<_TableType>& table,
                              _PrefixType prefix,
                              la_uint_t bincode,
                              la_user_data_t user_data,
                              bool modify) const
{
    npl_og_lpm_compression_code_t formatted_bincode;

    if (!is_prefix_valid(prefix)) {
        return LA_STATUS_EINVAL;
    }
    // Format the bincode as required, then add each
    // prefix/bincode pair to the LPM table. The format
    // of the bincode for placing in the LPM is as follows:
    // bits 0-17: bincode bits 0-17.
    // bit 18: always 0
    // bits 19-n: bincode bits 18 and above.
    // On pacific, n == 19, on GB, n == 24
    formatted_bincode.bits_17_0 = bincode;
    formatted_bincode.zero = 0;
    formatted_bincode.bits_n_18 = bincode >> 18;

    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_type* entry = {};

    populate_lpm_key(prefix.addr, key);
    value.payloads.lpm_code = formatted_bincode;
    if (modify) {
        if (m_feature == pcl_feature_type_e::ACL) {
            return LA_STATUS_EINVAL;
        }
        la_status status = table->find(key, prefix.length, entry);
        return_on_error(status);
        return table->set_entry_value(entry, value);
    } else {
        return table->insert(key, prefix.length, value, user_data, true /* latency_sensitive */, entry);
    }
}

template <class _TableType, class _PrefixType>
la_status
la_pcl_impl::add_og_em_entry(const std::shared_ptr<_TableType>& table,
                             _PrefixType prefix,
                             la_uint_t bincode,
                             la_user_data_t user_data,
                             bool modify) const
{
    npl_og_lpm_compression_code_t formatted_bincode;

    if (!is_prefix_valid(prefix)) {
        return LA_STATUS_EINVAL;
    }
    // Format the bincode as required, then add each
    // prefix/bincode pair to the LPM table. The format
    // of the bincode for placing in the LPM is as follows:
    // bits 0-17: bincode bits 0-17.
    // bit 18: always 0
    // bits 19-n: bincode bits 18 and above.
    // On pacific, n == 19, on GB, n == 23
    formatted_bincode.bits_17_0 = bincode;
    formatted_bincode.zero = 0;
    formatted_bincode.bits_n_18 = bincode >> 18;

    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_type* entry = {};

    populate_em_key(prefix.addr, key);
    if (m_feature == pcl_feature_type_e::ACL) {
        value.payloads.og_em_lookup_result.result.lpm_code_or_dest.lpm_code = formatted_bincode;
    } else if (m_feature == pcl_feature_type_e::LPTS) {
        value.payloads.og_em_lookup_result.result.lpm_code_or_dest.lpts_code.id = bincode;
    }

    la_status status;
    if (modify) {
        if (m_feature == pcl_feature_type_e::ACL) {
            return LA_STATUS_EINVAL;
        }
        status = table->set(key, value, entry);
    } else {
        status = table->insert(key, value, entry);
    }

    return status;
}

template <class _TableType, class _PrefixType>
la_status
la_pcl_impl::remove_og_em_entry(const std::shared_ptr<_TableType>& table, _PrefixType prefix) const
{
    if (!is_prefix_valid(prefix)) {
        return LA_STATUS_EINVAL;
    }
    typename _TableType::key_type key;
    populate_em_key(prefix.addr, key);
    la_status status = table->erase(key);
    return status;
}

template <class _TableType, class _PrefixType>
la_status
la_pcl_impl::remove_og_lpm_entry(const std::shared_ptr<_TableType>& table, _PrefixType prefix, size_t prefix_length) const
{
    if (!is_prefix_valid(prefix)) {
        return LA_STATUS_EINVAL;
    }
    typename _TableType::key_type key;
    populate_lpm_key(prefix.addr, key);
    la_status status = table->erase(key, prefix_length);
    return status;
}

// init_common.  Common logic that handles both IPV4 and IPV6
// PCL initialization, as well as populating each given
// prefix/bincode pair in the LPM table.
template <class _lpmTableType, class _emTableType, class _PrefixType>
la_status
la_pcl_impl::init_common(la_object_id_t oid,
                         const std::shared_ptr<_lpmTableType>& lpm_table,
                         const std::shared_ptr<_emTableType>& em_table,
                         const _PrefixType& prefixes,
                         la_uint_t em_size)
{
    la_status status;

    m_oid = oid;
    bool has_default = false;
    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == em_size) {
            status = add_og_em_entry(em_table, prefix.prefix, prefix.bincode, 0 /* user_data */, false /* modify */);
        } else {
            status = add_og_lpm_entry(lpm_table, prefix.prefix, prefix.bincode, 0 /* user_data */, false /* modify */);
        }
        return_on_error(status);
        if (prefix.prefix.length == 0) {
            has_default = true;
        }
    }

    if (!has_default) {
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::initialize(la_object_id_t oid, const la_pcl_v4_vec_t& prefixes, const pcl_feature_type_e& feature)
{
    m_oid = oid;
    // Save away the prefix compression list and indicate the type.
    // There must be at least 1 entry in the vector, for it to be valid.
    if ((prefixes.size() == 0) && (feature == pcl_feature_type_e::ACL)) {
        return LA_STATUS_EOUTOFRANGE;
    }
    m_v4_prefixes = prefixes;
    m_pcl_type = la_pcl::pcl_type_e::IPV4;
    m_feature = feature;
    const auto& lpm_table(m_device->m_tables.ipv4_og_pcl_lpm_table);
    const auto& em_table(m_device->m_tables.ipv4_og_pcl_em_table);

    // Allocate a PCL ID for this PCL
    la_status status = allocate_pcl_gid();
    return_on_error(status);

    status = init_common(oid, lpm_table, em_table, prefixes, 32 /* em_size*/);
    if (status != LA_STATUS_SUCCESS) {
        npl_ipv4_og_pcl_lpm_table_key_t lpm_key;
        clear_all_og_acl_lpm_entries(lpm_table, lpm_key);
        clear_all_og_acl_em_entries(em_table, m_v4_prefixes, 32 /* em_size*/);
        free_pcl_gid();
        return status;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::initialize(la_object_id_t oid, const la_pcl_v6_vec_t& prefixes, const pcl_feature_type_e& feature)
{
    // Save away the prefix compression list and indicate the type
    // There must be at least 1 entry in the vector, for it to be valid.
    if ((prefixes.size() == 0) && (feature == pcl_feature_type_e::ACL)) {
        return LA_STATUS_EOUTOFRANGE;
    }
    m_v6_prefixes = prefixes;
    m_pcl_type = la_pcl::pcl_type_e::IPV6;
    m_feature = feature;
    const auto& lpm_table(m_device->m_tables.ipv6_og_pcl_lpm_table);
    const auto& em_table(m_device->m_tables.ipv6_og_pcl_em_table);

    // Allocate a PCL ID for this PCL
    la_status status = allocate_pcl_gid();
    return_on_error(status);

    status = init_common(oid, lpm_table, em_table, prefixes, 128 /* em_size*/);
    if (status != LA_STATUS_SUCCESS) {
        npl_ipv6_og_pcl_lpm_table_key_t lpm_key;
        clear_all_og_acl_lpm_entries(lpm_table, lpm_key);
        clear_all_og_acl_em_entries(em_table, m_v6_prefixes, 128 /* em_size*/);
        free_pcl_gid();
        return status;
    }
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_pcl_impl::type() const
{
    return object_type_e::PCL;
}

std::string
la_pcl_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_pcl_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_pcl_impl::oid() const
{
    return m_oid;
}

const la_device*
la_pcl_impl::get_device() const
{
    return m_device.get();
}

template <class _TableType, class _KeyType>
la_status
la_pcl_impl::clear_all_og_acl_lpm_entries(const std::shared_ptr<_TableType>& table, _KeyType key)
{
    // This routine has 2 loops for a reason.  Since we need to remove
    // entries from "table", we cannot remove them while iterating on
    //"table", therefore the intermediate results are stored in
    // the "entries_to_remove" vector.  Next, we iterate on the
    //"entries_to_remove" vector, and remove the necessary entries
    // from "table".
    vector_alloc<typename _TableType::entry_pointer_type> entries_to_remove;
    for (auto entry : *table) {
        const _KeyType key = entry->key();

        if (key.pcl_id.val != m_pcl_gid) {
            continue;
        }
        entries_to_remove.push_back(entry.get());
    }
    for (auto entry : entries_to_remove) {
        _KeyType key = entry->key();
        size_t prefix_length = entry->length();
        la_status status = table->erase(key, prefix_length);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _PrefixType>
la_status
la_pcl_impl::clear_all_og_acl_em_entries(const std::shared_ptr<_TableType>& table, const _PrefixType& prefixes, la_uint_t em_size)
{
    typename _TableType::key_type key;
    typename _TableType::entry_pointer_type entry = {};

    for (auto& prefix : prefixes) {
        if (prefix.prefix.length == em_size) {
            populate_em_key(prefix.prefix.addr, key);
            la_status status = table->lookup(key, entry);
            if (status == LA_STATUS_SUCCESS) {
                status = table->erase(key);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_pcl_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }
    la_status status;
    if (m_pcl_type == la_pcl::pcl_type_e::IPV4) {
        const auto& lpm_table(m_device->m_tables.ipv4_og_pcl_lpm_table);
        npl_ipv4_og_pcl_lpm_table_key_t lpm_key;
        status = clear_all_og_acl_lpm_entries(lpm_table, lpm_key);
        return_on_error(status);
        const auto& em_table(m_device->m_tables.ipv4_og_pcl_em_table);
        status = clear_all_og_acl_em_entries(em_table, m_v4_prefixes, 32 /* em_size*/);
        return_on_error(status);
    } else {
        const auto& lpm_table_v6(m_device->m_tables.ipv6_og_pcl_lpm_table);
        npl_ipv6_og_pcl_lpm_table_key_t lpm_key_v6;
        status = clear_all_og_acl_lpm_entries(lpm_table_v6, lpm_key_v6);
        return_on_error(status);
        const auto& em_table_v6(m_device->m_tables.ipv6_og_pcl_em_table);
        status = clear_all_og_acl_em_entries(em_table_v6, m_v6_prefixes, 128 /* em_size*/);
        return_on_error(status);
    }
    status = free_pcl_gid();
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}
}
