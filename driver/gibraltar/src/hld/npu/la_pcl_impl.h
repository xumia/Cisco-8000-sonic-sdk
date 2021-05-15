// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_PCL_IMPL_H__
#define __LA_PCL_IMPL_H__

#include "api/npu/la_pcl.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "hld_types_fwd.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_device_impl;

class la_pcl_impl : public la_pcl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_pcl_impl(const la_device_impl_wptr& device);
    ~la_pcl_impl() override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;
    la_status get_type(pcl_type_e& out_type) const override;
    template <class _lpmTableType, class _emTableType, class _PrefixType>
    la_status init_common(la_object_id_t oid,
                          const std::shared_ptr<_lpmTableType>& lpm_table,
                          const std::shared_ptr<_emTableType>& em_table,
                          const _PrefixType& prefixes,
                          la_uint_t em_size);
    template <class _TableType, class _PrefixType>
    la_status init_common_lpts(_TableType& table, const _PrefixType& prefixes);
    virtual la_status initialize(la_object_id_t oid, const la_pcl_v4_vec_t& prefixes, const pcl_feature_type_e& feature);
    virtual la_status initialize(la_object_id_t oid, const la_pcl_v6_vec_t& prefixes, const pcl_feature_type_e& feature);
    virtual la_status destroy();
    // Get Ipv4/Ipv6 Prefixes for this PCL
    virtual la_status get_prefixes(la_pcl_v4_vec_t& out_prefixes) const override;
    virtual la_status get_prefixes(la_pcl_v6_vec_t& out_prefixes) const override;
    // Get global ID for a PCL
    la_status get_pcl_gid(la_pcl_gid_t& out_pcl_gid) const override;

private:
    // Device this PCL belongs to
    la_device_impl_wptr m_device;
    // Object ID
    la_object_id_t m_oid;
    // PCL type: IPV4 or IPV6
    pcl_type_e m_pcl_type;
    // Global ID associated with this PCL
    la_pcl_gid_t m_pcl_gid;
    // IPV4 prefix/bincode list associated with this PCL
    la_pcl_v4_vec_t m_v4_prefixes;
    // IPV4 prefix/bincode list associated with this PCL
    la_pcl_v6_vec_t m_v6_prefixes;
    // PCL feature type
    pcl_feature_type_e m_feature;
    // Common logic handling both Ipv4 and IPv6 PCL initialization
    template <class _lpmTableType, class _emTableType, class _PrefixType>
    la_status init_common(_lpmTableType& lpm_table, _emTableType& em_table, const _PrefixType& prefixes, la_uint_t em_size);
    // Allocate a PCL Global ID
    la_status allocate_pcl_gid(void);
    // Free a PCL Global ID
    la_status free_pcl_gid(void);
    // Check to see if Ipv4/Ipv6 prefix is valid
    template <class _PrefixType>
    bool is_prefix_valid(_PrefixType prefix) const;
    // Create an LPM table key for Ipv4 prefixes
    void populate_lpm_key(la_ipv4_addr_t addr, npl_ipv4_og_pcl_lpm_table_key_t& out_key) const;
    // Create an LPM table key for Ipv6 prefixes
    void populate_lpm_key(la_ipv6_addr_t addr, npl_ipv6_og_pcl_lpm_table_key_t& out_key) const;
    // Create an EM table key for Ipv4 prefixes
    void populate_em_key(la_ipv4_addr_t addr, npl_ipv4_og_pcl_em_table_key_t& out_key) const;
    // Create an EM table key for Ipv6 prefixes
    void populate_em_key(la_ipv6_addr_t addr, npl_ipv6_og_pcl_em_table_key_t& out_key) const;
    // Add an Ipv4/Ipv6 PCL entry to the OG LPM table
    template <class _TableType, class _PrefixType>
    la_status add_og_lpm_entry(const std::shared_ptr<_TableType>& table,
                               _PrefixType prefix,
                               la_uint_t bincode,
                               la_user_data_t user_data,
                               bool modify) const;
    // Add an Ipv4/Ipv6 PCL entry to the OG EM table
    template <class _TableType, class _PrefixType>
    la_status add_og_em_entry(const std::shared_ptr<_TableType>& table,
                              _PrefixType prefix,
                              la_uint_t bincode,
                              la_user_data_t user_data,
                              bool modify) const;
    // Retrieve current max number of PCL global Ids.
    la_status get_max_pcl_gids(int& max_pcl_gids) const;
    virtual la_status add_prefixes(const la_pcl_v4_vec_t& prefixes) override;
    virtual la_status add_prefixes(const la_pcl_v6_vec_t& prefixes) override;
    virtual la_status remove_prefixes(const la_pcl_v4_vec_t& prefixes) override;
    virtual la_status remove_prefixes(const la_pcl_v6_vec_t& prefixes) override;
    virtual la_status replace_prefixes(const la_pcl_v4_vec_t& prefixes) override;
    virtual la_status replace_prefixes(const la_pcl_v6_vec_t& prefixes) override;
    virtual la_status modify_prefixes(const la_pcl_v4_vec_t& prefixes) override;
    virtual la_status modify_prefixes(const la_pcl_v6_vec_t& prefixes) override;
    virtual la_status get_feature(pcl_feature_type_e& out_feature) const override;
    template <class _TableType, class _PrefixType>
    la_status remove_og_em_entry(const std::shared_ptr<_TableType>& table, _PrefixType prefix) const;
    template <class _TableType, class _PrefixType>
    la_status remove_og_lpm_entry(const std::shared_ptr<_TableType>& table, _PrefixType prefix, size_t prefix_length) const;
    // Clear all LPM entries associated with this PCL
    template <class _TableType, class _KeyType>
    la_status clear_all_og_acl_lpm_entries(const std::shared_ptr<_TableType>& table, _KeyType key);
    // Clear all EM entries associated with this PCL
    template <class _TableType, class _PrefixType>
    la_status clear_all_og_acl_em_entries(const std::shared_ptr<_TableType>& table, const _PrefixType& prefixes, la_uint_t em_size);

    la_pcl_impl() = default; // For serialization purposes.
};
}

#endif // __LA_PCL_IMPL_H__
