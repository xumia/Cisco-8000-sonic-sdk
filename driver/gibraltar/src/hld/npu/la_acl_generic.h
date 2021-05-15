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

#ifndef __LA_ACL_GENERIC_H__
#define __LA_ACL_GENERIC_H__

#include "common/common_fwd.h"
#include "la_acl_delegate.h"
#include "la_acl_key_utils.h"

namespace silicon_one
{

template <typename acl_trait>
class la_acl_generic : public la_acl_delegate
{
public:
    explicit la_acl_generic(const la_device_impl_wptr& device, la_acl_sptr parent) : la_acl_delegate(device, parent)
    {
        auto tables = acl_trait::get_table(device);
        for (la_slice_id_t sid = 0; sid < m_npl_table.size(); sid++) {
            m_npl_table[sid] = tables[sid];
        }
    }

    ~la_acl_generic() override = default;

    la_status initialize(const la_acl_key_profile_base_wcptr& acl_key_profile,
                         const la_acl_command_profile_base_wcptr& acl_command_profile) override
    {
        m_acl_key_profile = acl_key_profile;
        m_acl_command_profile = acl_command_profile;

        m_acl_key_profile->get_key_definition(m_key_def);

        return LA_STATUS_SUCCESS;
    }

    la_status destroy() override
    {
        return clear();
    }

    /** Cereal functions **/
    la_acl_generic() = default; // For serialization purposes only

    template <class Archive>
    void save_impl(Archive& ar) const
    {
        const la_acl_delegate* this_base = static_cast<const la_acl_delegate*>(this);
        save(ar, *this_base);
        ar(m_key_def);
        ar(m_npl_table);
    }

    template <class Archive>
    void load_impl(Archive& ar)
    {
        la_acl_delegate* this_base = static_cast<la_acl_delegate*>(this);
        load(ar, *this_base);
        ar(m_key_def);
        ar(m_npl_table);
    }

protected:
    la_status get_tcam_max_available_space(la_slice_id_t slice, size_t& out_space) const override
    {
        return m_npl_table[slice]->get_available_entries(out_space);
    }

private:
    using npl_table_t = typename acl_trait::npl_table_t;
    using npl_table_key_t = typename npl_table_t::key_type;
    using npl_table_value_t = typename npl_table_t::value_type;
    using npl_table_entry_t = typename npl_table_t::entry_pointer_type;
    using npl_table_entry_desc_t = typename npl_table_t::npl_entry_desc;

    la_status get_tcam_line(la_slice_id_t slice,
                            size_t tcam_line,
                            la_acl_key& out_key_val,
                            la_acl_command_actions& out_cmd) const override
    {
        npl_table_entry_t e = nullptr;
        la_status status = m_npl_table[slice]->get_entry(tcam_line, e);
        return_on_error(status);

        npl_table_key_t k = e->key();
        npl_table_key_t m = e->mask();
        npl_table_value_t v = e->value();

        status = copy_npl_to_key_mask(m_key_def, k, m, out_key_val);
        return_on_error(status);

        auto& npl_payload = v.payloads.rtf_payload;
        copy_npl_to_acl_command(npl_payload.rtf_result_profile.rtf_result_profile_0, out_cmd);

        return LA_STATUS_SUCCESS;
    }

    size_t get_tcam_size(la_slice_id_t slice) const override
    {
        return m_npl_table[slice]->max_size();
    }

    size_t get_tcam_fullness(la_slice_id_t slice) const override
    {
        return m_npl_table[slice]->size();
    }

    la_status copy_entry_to_npl(la_slice_id_t slice,
                                const la_acl_key& key_val,
                                const la_acl_command_actions& cmd,
                                npl_table_key_t& k,
                                npl_table_key_t& m,
                                npl_table_value_t& v)
    {
        la_acl_id_t acl_id = m_slice_pair_data[slice / 2].acl_id;
        la_status status = copy_key_mask_to_npl(slice, acl_id, acl_trait::acl_id_mask, m_key_def, key_val, k, m);
        return_on_error(status);

        auto& npl_payload = v.payloads.rtf_payload;
        status = copy_acl_command_to_npl(slice, cmd, npl_payload);
        return_on_error(status);

        return LA_STATUS_SUCCESS;
    }

    la_status set_tcam_line(la_slice_id_t slice,
                            size_t tcam_line,
                            bool is_push,
                            const la_acl_key& key_val,
                            const la_acl_command_actions& cmd) override
    {
        npl_table_key_t k{};
        npl_table_key_t m{};
        npl_table_value_t v{};
        npl_table_entry_t e = nullptr;

        la_status status = copy_entry_to_npl(slice, key_val, cmd, k, m, v);
        return_on_error(status);

        if (is_push) {
            status = m_npl_table[slice]->push(tcam_line, k, m, v, e);
        } else {
            status = m_npl_table[slice]->set(tcam_line, k, m, v, e);
        }
        return status;
    }

    la_status push_tcam_lines(la_slice_id_t slice,
                              size_t first_tcam_line,
                              size_t entries_num,
                              const vector_alloc<acl_entry_desc>& entries) override
    {
        vector_alloc<npl_table_entry_desc_t> entries_info(entries_num);

        for (size_t i = 0; i < entries_num; i++) {
            npl_table_key_t k{};
            npl_table_key_t m{};
            npl_table_value_t v{};

            la_status status = copy_entry_to_npl(slice, entries[i].key_val, entries[i].cmd_actions, k, m, v);
            return_on_error(status);

            entries_info[i].key = k;
            entries_info[i].mask = m;
            entries_info[i].value = v;
        }

        la_status status = m_npl_table[slice]->push_bulk(first_tcam_line, entries_num, entries_info);

        return status;
    }

    la_status locate_free_tcam_line_after_last_entry(la_slice_id_t slice, size_t& position) const override
    {
        return m_npl_table[slice]->get_free_tcam_line_after_last_entry(position);
    }

    la_status is_tcam_line_contains_ace(la_slice_id_t slice, size_t tcam_line, bool& contains) const override
    {
        npl_table_entry_t e = nullptr;
        la_status status = m_npl_table[slice]->get_entry(tcam_line, e);

        if (status == LA_STATUS_ENOTFOUND) {
            // Empty
            contains = false;
            return LA_STATUS_SUCCESS;
        }

        return_on_error(status);

        la_acl_id_t npl_acl_id = get_npl_acl_id(m_key_def, e->key());
        contains = npl_acl_id == m_slice_pair_data[slice / 2].acl_id;

        return LA_STATUS_SUCCESS;
    }

    la_status erase_tcam_line(la_slice_id_t slice, size_t tcam_line) override
    {
        return m_npl_table[slice]->pop(tcam_line);
    }

    la_status clear_tcam_line(la_slice_id_t slice, size_t tcam_line) override
    {
        npl_table_entry_t e = nullptr;
        la_status status = m_npl_table[slice]->get_entry(tcam_line, e);
        if (status == LA_STATUS_ENOTFOUND) {
            return LA_STATUS_SUCCESS;
        }

        return_on_error(status);

        status = m_npl_table[slice]->erase(tcam_line);
        return_on_error(status);

        return LA_STATUS_SUCCESS;
    }

    la_status locate_free_tcam_entry(la_slice_id_t slice, size_t start, size_t& position) const override
    {
        return m_npl_table[slice]->locate_free_entry(start, position);
    }

    la_status allocate_acl_id(la_slice_pair_id_t slice_pair) override
    {
        ranged_index_generator* index_generator = acl_trait::get_index_generator(m_device, slice_pair);
        if (index_generator == nullptr) {
            return LA_STATUS_SUCCESS;
        }

        la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
        bool allocated = index_generator->allocate(acl_id);
        if (!allocated) {
            log_err(HLD, "Failed to allocate ACL id in slice_pair: %d", slice_pair);
            return LA_STATUS_ERESOURCE;
        }

        m_slice_pair_data[slice_pair].acl_id = acl_id;

        if (m_acl_type == la_acl::type_e::UNIFIED) {
            return m_device->set_acl_scaled_enabled(slice_pair, acl_id, false);
        }

        return LA_STATUS_SUCCESS;
    }

    la_status release_acl_id(la_slice_pair_id_t slice_pair) override
    {
        ranged_index_generator* index_generator = acl_trait::get_index_generator(m_device, slice_pair);

        if (index_generator) {
            index_generator->release(m_slice_pair_data[slice_pair].acl_id);
            m_slice_pair_data[slice_pair].acl_id = la_device_impl::ACL_INVALID_ID;
        }

        return LA_STATUS_SUCCESS;
    }

    /*
    * Update the appropriate acl1 pcl_configs table entry, given the slice_pair,
    * aclid, and ip_ver. Compression is disabled when there is no pcl
    * configured.
    */
    template <class _TableType>
    la_status update_acl_pcl_configs_table_entry(const std::shared_ptr<_TableType>& pcl_configs_table,
                                                 la_slice_pair_id_t slice_pair,
                                                 la_acl_id_t acl_id,
                                                 npl_ip_version_e ip_ver,
                                                 npl_bool_e use_dest_class)
    {
        typename _TableType::key_type k;
        typename _TableType::value_type v;
        typename _TableType::entry_type* e = nullptr;
        k.ip_version = ip_ver;
        k.acl_id.value = acl_id;
        la_status status;

        if (m_src_pcl == nullptr) {
            v.payloads.pcl_configs.og_pcl_configs.src.compress = 0;
        } else {
            la_pcl_gid_t src_pcl_gid;
            v.payloads.pcl_configs.og_pcl_configs.src.compress = 1;
            status = m_src_pcl->get_pcl_gid(src_pcl_gid);
            return_on_error(status);
            v.payloads.pcl_configs.og_pcl_configs.src.pcl_id.val = src_pcl_gid;
        }
        if (m_dst_pcl == nullptr) {
            v.payloads.pcl_configs.og_pcl_configs.dest.compress = 0;
        } else {
            la_pcl_gid_t dst_pcl_gid;
            v.payloads.pcl_configs.og_pcl_configs.dest.compress = 1;
            status = m_dst_pcl->get_pcl_gid(dst_pcl_gid);
            return_on_error(status);
            v.payloads.pcl_configs.og_pcl_configs.dest.pcl_id.val = dst_pcl_gid;
        }
        v.payloads.pcl_configs.use_dest_class.val = use_dest_class;

        status = pcl_configs_table->set(k, v, e);
        return_on_error(status);
        return LA_STATUS_SUCCESS;
    }

    // Data members
    std::array<std::shared_ptr<npl_table_t>, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_npl_table;
    la_acl_key_def_vec_t m_key_def;
};

struct acl_ingress_rtf_eth_db1_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_eth_db1_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_eth_db1_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_eth_db1_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_eth_db2_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_eth_db2_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_eth_db2_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_eth_db2_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db1_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db1_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db1_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db1_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db2_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db2_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db2_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db2_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db3_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db3_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db3_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db3_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db4_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db4_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db4_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db4_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db1_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db1_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db1_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db1_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db2_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db2_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db2_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db2_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db3_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db3_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db3_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db3_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv4_db4_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv4_db4_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV4;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv4_db4_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv4_db4_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db1_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db1_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db1_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db1_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db2_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db2_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db2_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db2_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db3_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db3_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db3_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db3_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db4_160_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db4_160_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db4_160_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db4_160_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db1_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db1_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db1_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db1_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db2_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db2_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db2_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db2_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db3_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db3_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db3_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db3_320_f0_acl_ids;
    }
};

struct acl_ingress_rtf_ipv6_db4_320_f0_trait {
    using npl_table_t = npl_ingress_rtf_ipv6_db4_320_f0_table_t;
    static constexpr npl_ip_version_e npl_ip_version = NPL_IP_VERSION_IPV6;
    static constexpr bool is_udk = true;
    static constexpr bool is_og = false;
    static constexpr la_acl_id_t acl_id_mask = 0x7F;

    static std::shared_ptr<npl_table_t>* get_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.ingress_rtf_ipv6_db4_320_f0_table;
    }

    static ranged_index_generator* get_index_generator(const la_device_impl_wptr& device, la_slice_pair_id_t slice_pair)
    {
        return &device->m_index_generators.slice_pair[slice_pair].ingress_ipv6_db4_320_f0_acl_ids;
    }
};

} // namespace silicon_one
#endif // __LA_ACL_GENERIC_H
