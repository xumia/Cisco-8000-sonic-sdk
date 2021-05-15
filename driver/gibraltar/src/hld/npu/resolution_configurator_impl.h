// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __RESOLUTION_CONFIGURATOR_IMPL_H__
#define __RESOLUTION_CONFIGURATOR_IMPL_H__

#include "api/types/la_object.h"
#include "nplapi/device_tables.h"
#include "npu/la_asbr_lsp_impl.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_ip_tunnel_destination_impl.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_prefix_object_gibraltar.h"
#include "npu/la_te_tunnel_impl.h"
#include "resolution_configurator.h"
#include "system/la_device_impl.h"
#include <list>
#include <map>

#if 0
#define RES_DEBUG_PRINT(fmt, ...) printf("%-30s:%d) " fmt, __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define RES_DEBUG_PRINT(fmt, ...)
#endif

namespace silicon_one
{

// Helper class that provies resource management for assoc-data table entries
// Resource (Entry) are allocated/released on SW only (no allocation in HW of any type)
class resolution_ad_entry_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit resolution_ad_entry_allocator(la_uint32_t ad_table_size);
    resolution_ad_entry_allocator() = default; // for serialization purposes only

    la_status allocate(npl_resolution_assoc_data_entry_type_e entry_type, resolution_assoc_data_table_addr_t& out_entry_addr);
    la_status release(const resolution_assoc_data_table_addr_t& entry_addr);
    bool is_line_allocated(la_uint32_t index) const;
    la_status get_line_entry_type(la_uint32_t line_index, npl_resolution_assoc_data_entry_type_e& out_entry_type) const;
    static la_uint8_t get_line_entries_num_per_type(const npl_resolution_assoc_data_entry_type_e entry_type);

private:
    struct ad_table_line_t {
        npl_resolution_assoc_data_entry_type_e type; // type of line entries
        la_uint8_t allocated_entries_mask;           // mask of used entry indices
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ad_table_line_t)

    la_status alloc_line_entry(ad_table_line_t& table_line,
                               const npl_resolution_assoc_data_entry_type_e entry_type,
                               la_uint8_t& select);

    static constexpr la_uint8_t NARROW_ENTRIES_PER_LINE = 4;
    static constexpr la_uint8_t WIDE_ENTRIES_PER_LINE = 2;
    static constexpr la_uint8_t NARROW_PROTECTED_ENTRIES_PER_LINE = 2;
    static constexpr la_uint8_t WIDE_PRTOECTED_ENTRIES_PER_LINE = 1;

    la_uint32_t m_table_size;
    std::map<la_uint32_t, ad_table_line_t> m_occupied_lines;
};

// Implementation class for the public resolution_configurator defined in the H file
template <typename stage_trait>
class resolution_configurator_impl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit resolution_configurator_impl(const la_device_impl_wptr& device);

    template <typename table_value_type>
    la_status configure_dest_map_entry(const destination_id& dest,
                                       const table_value_type& value,
                                       resolution_cfg_handle_t& cfg_handle,
                                       const npl_em_common_data_t& common_data = npl_em_common_data_t{{0}});

    template <typename table_value_type>
    la_status configure_lb_entry(const la_uint32_t group_id,
                                 const la_uint32_t member_id,
                                 const table_value_type& value,
                                 resolution_cfg_handle_t& cfg_handle,
                                 const npl_em_common_data_t& common_data = npl_em_common_data_t{{0}});

    la_status configure_in_stage_lb_entry(const la_uint32_t group_id,
                                          const la_uint32_t member_id,
                                          const la_object_wcptr& in_stage_dest,
                                          resolution_cfg_handle_t& cfg_handle,
                                          bool use_dest_common_data,
                                          const npl_em_common_data_t& common_data = npl_em_common_data_t{{0}});

    la_status unconfigure_entry(resolution_cfg_handle_t& cfg_handle);

    la_status set_group_size(const la_uint32_t group_id, const la_uint32_t group_size, npl_lb_consistency_mode_e consistency_mode);

    la_status get_group_size(const la_uint32_t group_id,
                             la_uint32_t& out_group_size,
                             npl_lb_consistency_mode_e& out_consistency_mode);

    la_status erase_group_size(const la_uint32_t group_id);

    la_status configure_protection_monitor(const la_protection_monitor_gid_t& monitor_id,
                                           npl_resolution_protection_selector_e selector);

    la_status unconfigure_protection_monitor(const la_protection_monitor_gid_t& monitor_id);

    template <class Archive>
    void serialize(Archive& ar);

private:
    resolution_configurator_impl() = default; // for serialization purposes only

    using em_table_sptr = std::shared_ptr<typename stage_trait::em_table_type>;
    using em_key_t = typename stage_trait::em_table_type::key_type;
    using em_value_t = typename stage_trait::em_table_type::value_type;
    using em_entry_t = typename stage_trait::em_table_type::entry_wptr_type;

    using ad_table_sptr = std::shared_ptr<typename stage_trait::ad_table_type>;
    using ad_key_t = typename stage_trait::ad_table_type::key_type;
    using ad_value_t = typename stage_trait::ad_table_type::value_type;
    using ad_entry_t = typename stage_trait::ad_table_type::entry_wptr_type;

    using group_size_table_sptr = std::shared_ptr<typename stage_trait::group_size_table_type>;
    using group_size_key_t = typename stage_trait::group_size_table_type::key_type;
    using group_size_value_t = typename stage_trait::group_size_table_type::value_type;
    using group_size_entry_t = typename stage_trait::group_size_table_type::entry_wptr_type;

    using protection_table_sptr = std::shared_ptr<typename stage_trait::protection_table_type>;
    using protection_key_t = typename stage_trait::protection_table_type::key_type;
    using protection_value_t = typename stage_trait::protection_table_type::value_type;
    using protection_entry_t = typename stage_trait::protection_table_type::entry_wptr_type;

    template <typename table_value_type>
    la_status configure_resolution_stage_entry(const em_key_t& key,
                                               const table_value_type& value,
                                               resolution_cfg_handle_t& cfg_handle,
                                               const npl_em_common_data_t& common_data);

    template <typename table_value_type>
    la_status configure_resolution_in_stage_lb_entry(const em_key_t& key,
                                                     const la_object_wcptr& in_stage_dest,
                                                     resolution_cfg_handle_t& cfg_handle,
                                                     const npl_em_common_data_t& common_data);

    la_status get_in_stage_resolution_cfg_handle(la_object_wcptr in_stage_dest, const resolution_cfg_handle_t*& cfg_handle);
    void add_in_stage_dependency(const la_object_wcptr& in_stage_dest, const em_key_t& dependent_em_key);
    void remove_in_stage_dependencies(const em_key_t& em_key);
    void update_in_stage_dependents(const em_key_t& dependent_em_key, const resolution_cfg_handle_t& dependee_cfg_handle);

    la_uint8_t entry_select_to_npl(la_uint8_t logical_entry_select, npl_resolution_assoc_data_entry_type_e entry_type);
    la_uint8_t entry_select_from_npl(la_uint8_t npl_entry_select, npl_resolution_assoc_data_entry_type_e entry_type);

    resolution_ad_entry_allocator m_ad_entry_allocator;
    la_device_impl_wptr m_device;

    struct em_key_less {
        bool operator()(const em_key_t& l, const em_key_t& r)
        {
            return l.pack().get_value() < r.pack().get_value();
        }
    };
    std::map<em_key_t, std::list<em_key_t>, em_key_less> m_in_stage_dependency;

    static constexpr unsigned MAX_ENTRIES_PER_AD_TABLE_LINE = 4;
};

// Trait structs describing the different stages and their tables
struct resolution_stage0_trait_t {
    typedef npl_stage0_em_table_t em_table_type;
    typedef npl_stage0_assoc_data_table_t ad_table_type;
    typedef npl_stage0_group_size_table_t group_size_table_type;
    typedef npl_stage0_protection_table_t protection_table_type;

    enum { STAGE_INDEX = 0 };
    enum { ASSOC_DATA_TABLE_SIZE = 48 * 1024 };
    static npl_stage0_assoc_data_table_sptr_t get_ad_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage0_assoc_data_table;
    }
    static npl_stage0_em_table_sptr_t get_em_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage0_em_table;
    }
    static npl_stage0_group_size_table_sptr_t get_group_size_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage0_group_size_table;
    }
    static npl_stage0_protection_table_sptr_t get_protection_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage0_protection_table;
    }
    static constexpr npl_stage0_assoc_data_table_action_e AD_TABLE_ACTION = NPL_STAGE0_ASSOC_DATA_TABLE_ACTION_LINE;
    static constexpr npl_stage0_em_table_action_e EM_TABLE_ACTION = NPL_STAGE0_EM_TABLE_ACTION_ENTRY;
    static constexpr npl_stage0_group_size_table_action_e GROUP_SIZE_TABLE_ACTION = NPL_STAGE0_GROUP_SIZE_TABLE_ACTION_WRITE;
};

struct resolution_stage1_trait_t {
    typedef npl_stage1_em_table_t em_table_type;
    typedef npl_stage1_assoc_data_table_t ad_table_type;
    typedef npl_stage1_group_size_table_t group_size_table_type;
    typedef npl_stage1_protection_table_t protection_table_type;

    enum { STAGE_INDEX = 1 };
    enum { ASSOC_DATA_TABLE_SIZE = 8 * 1024 };
    static npl_stage1_assoc_data_table_sptr_t get_ad_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage1_assoc_data_table;
    };
    static npl_stage1_em_table_sptr_t get_em_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage1_em_table;
    };
    static npl_stage1_group_size_table_sptr_t get_group_size_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage1_group_size_table;
    }
    static npl_stage1_protection_table_sptr_t get_protection_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage1_protection_table;
    }
    static constexpr npl_stage1_em_table_action_e EM_TABLE_ACTION = NPL_STAGE1_EM_TABLE_ACTION_ENTRY;
    static constexpr npl_stage1_assoc_data_table_action_e AD_TABLE_ACTION = NPL_STAGE1_ASSOC_DATA_TABLE_ACTION_LINE;
    static constexpr npl_stage1_group_size_table_action_e GROUP_SIZE_TABLE_ACTION = NPL_STAGE1_GROUP_SIZE_TABLE_ACTION_WRITE;
};

struct resolution_stage2_trait_t {
    typedef npl_stage2_em_table_t em_table_type;
    typedef npl_stage2_assoc_data_table_t ad_table_type;
    typedef npl_stage2_group_size_table_t group_size_table_type;
    typedef npl_stage2_protection_table_t protection_table_type;

    enum { STAGE_INDEX = 2 };
    enum { ASSOC_DATA_TABLE_SIZE = 8 * 1024 };
    static npl_stage2_assoc_data_table_sptr_t get_ad_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage2_assoc_data_table;
    };
    static npl_stage2_em_table_sptr_t get_em_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage2_em_table;
    };
    static npl_stage2_group_size_table_sptr_t get_group_size_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage2_group_size_table;
    }
    static npl_stage2_protection_table_sptr_t get_protection_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage2_protection_table;
    }
    static constexpr npl_stage2_em_table_action_e EM_TABLE_ACTION = NPL_STAGE2_EM_TABLE_ACTION_ENTRY;
    static constexpr npl_stage2_assoc_data_table_action_e AD_TABLE_ACTION = NPL_STAGE2_ASSOC_DATA_TABLE_ACTION_LINE;
    static constexpr npl_stage2_group_size_table_action_e GROUP_SIZE_TABLE_ACTION = NPL_STAGE2_GROUP_SIZE_TABLE_ACTION_WRITE;
};

struct resolution_stage3_trait_t {
    typedef npl_stage3_em_table_t em_table_type;
    typedef npl_stage3_assoc_data_table_t ad_table_type;
    typedef npl_stage3_group_size_table_t group_size_table_type;
    typedef npl_stage3_protection_table_t protection_table_type;

    enum { STAGE_INDEX = 3 };
    enum { ASSOC_DATA_TABLE_SIZE = 3 * 1024 };
    static npl_stage3_assoc_data_table_sptr_t get_ad_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage3_assoc_data_table;
    };
    static npl_stage3_em_table_sptr_t get_em_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage3_em_table;
    };
    static npl_stage3_group_size_table_sptr_t get_group_size_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage3_group_size_table;
    }
    static npl_stage3_protection_table_sptr_t get_protection_table(const la_device_impl_wptr& device)
    {
        return device->m_tables.stage3_protection_table;
    }
    static constexpr npl_stage3_em_table_action_e EM_TABLE_ACTION = NPL_STAGE3_EM_TABLE_ACTION_ENTRY;
    static constexpr npl_stage3_assoc_data_table_action_e AD_TABLE_ACTION = NPL_STAGE3_ASSOC_DATA_TABLE_ACTION_LINE;
    static constexpr npl_stage3_group_size_table_action_e GROUP_SIZE_TABLE_ACTION = NPL_STAGE3_GROUP_SIZE_TABLE_ACTION_WRITE;
};

// Trait structs describing the different types of resolution tables entries (narrow/wide/narrow-protected/wide-protected)
template <typename table_value_type>
struct resolution_ad_table_entry_trait_t {
};

template <>
struct resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_narrow_entry_t> {
    static constexpr npl_resolution_assoc_data_entry_type_e type = NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW;
    static void set_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line,
                                  const npl_resolution_stage_assoc_data_narrow_entry_t& entry,
                                  la_uint8_t entry_index)
    {
        line.narrow.entry[entry_index] = entry;
        line.narrow.type = NPL_RESOLUTION_ASSOC_DATA_ENTRY_NORMAL;
    }
    static void clear_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line, la_uint8_t entry_index)
    {
        memset(&line.narrow.entry[entry_index], 0, sizeof(line.narrow.entry[entry_index]));
    }
};

template <>
struct resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_wide_entry_t> {
    static constexpr npl_resolution_assoc_data_entry_type_e type = NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE;
    static void set_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line,
                                  const npl_resolution_stage_assoc_data_wide_entry_t& entry,
                                  la_uint8_t entry_index)
    {
        line.wide.entry[entry_index] = entry;
        line.wide.type = NPL_RESOLUTION_ASSOC_DATA_ENTRY_NORMAL;
    }
    static void clear_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line, la_uint8_t entry_index)
    {
        memset(&line.wide.entry[entry_index], 0, sizeof(line.wide.entry[entry_index]));
    }
};

template <>
struct resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_narrow_protection_record_t> {
    static constexpr npl_resolution_assoc_data_entry_type_e type = NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW_PROTECTION;
    static void set_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line,
                                  const npl_resolution_stage_assoc_data_narrow_protection_record_t& entry,
                                  la_uint8_t entry_index)
    {
        line.narrow_protection.record[entry_index] = entry;
        line.narrow_protection.type = NPL_RESOLUTION_ASSOC_DATA_ENTRY_PROTECTION;
    }
    static void clear_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line, la_uint8_t entry_index)
    {
        memset(&line.narrow_protection.record[entry_index], 0, sizeof(line.narrow_protection.record[entry_index]));
    }
};

template <>
struct resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_wide_protection_record_t> {
    static constexpr npl_resolution_assoc_data_entry_type_e type = NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE_PROTECTION;
    static void set_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line,
                                  const npl_resolution_stage_assoc_data_wide_protection_record_t& entry,
                                  la_uint8_t /*entry_index*/)
    {
        line.wide_protection.record = entry;
        line.wide_protection.type = NPL_RESOLUTION_ASSOC_DATA_ENTRY_PROTECTION;
    }
    static void clear_ad_line_entry(npl_resolution_stage_assoc_data_result_t& line)
    {
        memset(&line.wide_protection.record, 0, sizeof(line.wide_protection.record));
    }
};

/**************************** Template classess implementation starts here ****************************/
template <typename stage_trait>
resolution_configurator_impl<stage_trait>::resolution_configurator_impl(const la_device_impl_wptr& device)
    : m_ad_entry_allocator(stage_trait::ASSOC_DATA_TABLE_SIZE), m_device(device)
{
}

template <typename stage_trait>
template <typename Archive>
void
resolution_configurator_impl<stage_trait>::serialize(Archive& ar)
{
    ar(m_ad_entry_allocator);
    ar(m_device);
    ar(m_in_stage_dependency);
}

template <typename stage_trait>
template <typename table_value_type>
la_status
resolution_configurator_impl<stage_trait>::configure_dest_map_entry(const destination_id& dest,
                                                                    const table_value_type& value,
                                                                    resolution_cfg_handle_t& cfg_handle,
                                                                    const npl_em_common_data_t& common_data)
{
    em_key_t em_key;
    em_key.key.dest_or_lb = NPL_RESOLUTION_EM_SELECT_DEST_MAP;
    em_key.key.key = dest.val;

    RES_DEBUG_PRINT("Configuring EM-DIRECT-MAP ENTRY in stage %u, dest=0x%05x, value=%s\n",
                    stage_trait::STAGE_INDEX,
                    dest.val,
                    value.pack().to_string().c_str());
    return configure_resolution_stage_entry(em_key, value, cfg_handle, common_data);
}

template <typename stage_trait>
template <typename table_value_type>
la_status
resolution_configurator_impl<stage_trait>::configure_lb_entry(const la_uint32_t group_id,
                                                              const la_uint32_t member_id,
                                                              const table_value_type& value,
                                                              resolution_cfg_handle_t& cfg_handle,
                                                              const npl_em_common_data_t& common_data)
{
    em_key_t em_key;
    npl_resolution_stage_em_table_lb_key_t lb_key;

    lb_key.dest_or_lb = NPL_RESOLUTION_EM_SELECT_LB;
    lb_key.group_id = group_id;
    lb_key.member_id = member_id;

    em_key.unpack(lb_key.pack());
    RES_DEBUG_PRINT("Configuring EM-LB(VALUE) ENTRY (stage=%u, group_id=%u, member_id=%u), key=%s, value=%s\n",
                    stage_trait::STAGE_INDEX,
                    group_id,
                    member_id,
                    em_key.pack().to_string().c_str(),
                    value.pack().to_string().c_str());
    return configure_resolution_stage_entry(em_key, value, cfg_handle, common_data);
}

template <typename stage_trait>
void
resolution_configurator_impl<stage_trait>::add_in_stage_dependency(const la_object_wcptr& dependee,
                                                                   const em_key_t& dependent_em_key)
{
    // First remove any previuos dependencies involving the given dependent_em_key
    // dependent can depend on only one dependee
    remove_in_stage_dependencies(dependent_em_key);

    const resolution_cfg_handle_t* cfg_handle;
    la_status status = get_in_stage_resolution_cfg_handle(dependee, cfg_handle);
    if (status != LA_STATUS_SUCCESS) {
        return;
    }

    em_entry_t em_table_entry;
    if (cfg_handle->em_table_entry.which() != 0) {
        em_table_entry = boost::get<em_entry_t>(cfg_handle->em_table_entry);
    }
    const em_key_t& dependee_key = em_table_entry->key();

    m_in_stage_dependency[dependee_key].push_back(dependent_em_key);
}

template <typename stage_trait>
void
resolution_configurator_impl<stage_trait>::remove_in_stage_dependencies(const em_key_t& em_key)
{
    // Remove it as a dependent
    const auto& em_key_equals = [&em_key](const em_key_t& other) { return em_key.pack().get_value() == other.pack().get_value(); };
    for (auto it = m_in_stage_dependency.begin(); it != m_in_stage_dependency.end();) {
        auto pair_it = std::find_if(std::begin(it->second), std::end(it->second), em_key_equals);
        if (pair_it != it->second.end()) {
            it->second.erase(pair_it);
        }
        if (it->second.size() == 0) {
            // Remove the dependee if that was the last dependent
            it = m_in_stage_dependency.erase(it);
        } else {
            ++it;
        }
    }
}

template <typename stage_trait>
void
resolution_configurator_impl<stage_trait>::update_in_stage_dependents(const em_key_t& dependee_em_key,
                                                                      const resolution_cfg_handle_t& dependee_cfg_handle)
{
    em_table_sptr em_table(stage_trait::get_em_table(m_device));
    la_status status;

    for (auto dependent : m_in_stage_dependency[dependee_em_key]) {
        em_value_t v;
        em_entry_t e;
        npl_resolution_assoc_data_entry_type_e entry_type;

        m_ad_entry_allocator.get_line_entry_type(dependee_cfg_handle.ad_entry_addr.index, entry_type);
        v.payloads.entry.common_data.raw.common_data = dependee_cfg_handle.common_data;
        v.payloads.entry.entry_select = entry_select_to_npl(dependee_cfg_handle.ad_entry_addr.select, entry_type);
        v.payloads.entry.addr = dependee_cfg_handle.ad_entry_addr.index;

        status = em_table->set(dependent, v, e);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Failed to update depenedent in-stage entry");
        }
    }
}

template <typename stage_trait>
la_uint8_t
resolution_configurator_impl<stage_trait>::entry_select_to_npl(la_uint8_t logical_entry_select,
                                                               npl_resolution_assoc_data_entry_type_e entry_type)
{
    return logical_entry_select * MAX_ENTRIES_PER_AD_TABLE_LINE / m_ad_entry_allocator.get_line_entries_num_per_type(entry_type);
}

template <typename stage_trait>
la_uint8_t
resolution_configurator_impl<stage_trait>::entry_select_from_npl(la_uint8_t npl_entry_select,
                                                                 npl_resolution_assoc_data_entry_type_e entry_type)
{
    return npl_entry_select * m_ad_entry_allocator.get_line_entries_num_per_type(entry_type) / MAX_ENTRIES_PER_AD_TABLE_LINE;
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::configure_in_stage_lb_entry(const la_uint32_t group_id,
                                                                       const la_uint32_t member_id,
                                                                       const la_object_wcptr& in_stage_dest,
                                                                       resolution_cfg_handle_t& cfg_handle,
                                                                       bool use_dest_common_data,
                                                                       const npl_em_common_data_t& common_data)
{
    resolution_assoc_data_table_addr_t ad_entry_addr;
    em_table_sptr em_table(stage_trait::get_em_table(m_device));
    em_value_t em_value;
    em_key_t em_key;
    em_entry_t em_table_entry;
    npl_resolution_stage_em_table_lb_key_t lb_key;
    npl_resolution_assoc_data_entry_type_e entry_type;
    const resolution_cfg_handle_t* dest_cfg_handle;
    la_status status;

    // Changing existing entry from stand-alone mapping to in-stage destination
    // mapping
    if (cfg_handle.is_valid() && cfg_handle.ad_entry_addr.is_valid()) {
        m_ad_entry_allocator.release(cfg_handle.ad_entry_addr);
        cfg_handle.ad_entry_addr.set_invalid();
    }

    status = get_in_stage_resolution_cfg_handle(in_stage_dest, dest_cfg_handle);
    return_on_error(status);

    m_ad_entry_allocator.get_line_entry_type(dest_cfg_handle->ad_entry_addr.index, entry_type);
    em_value.payloads.entry.addr = dest_cfg_handle->ad_entry_addr.index;
    em_value.payloads.entry.entry_select = entry_select_to_npl(dest_cfg_handle->ad_entry_addr.select, entry_type);
    if (use_dest_common_data) {
        em_value.payloads.entry.common_data.raw.common_data = dest_cfg_handle->common_data;
        cfg_handle.common_data = dest_cfg_handle->common_data;
    } else {
        em_value.payloads.entry.common_data = common_data;
        cfg_handle.common_data = common_data.pack().get_value();
    }
    em_value.action = stage_trait::EM_TABLE_ACTION;

    lb_key.dest_or_lb = NPL_RESOLUTION_EM_SELECT_LB;
    lb_key.member_id = member_id;
    lb_key.group_id = group_id;
    em_key.unpack(lb_key.pack());
    status = em_table->set(em_key, em_value, em_table_entry);
    return_on_error(status);

    if (use_dest_common_data) {
        add_in_stage_dependency(in_stage_dest, em_key);
    }

    cfg_handle.in_stage_dest = in_stage_dest;
    cfg_handle.stage_index = stage_trait::STAGE_INDEX;
    cfg_handle.em_table_entry = em_table_entry;
    RES_DEBUG_PRINT("Configuring EM (in-stage) entry (stage=%u, addr=0x%x, select=0x%x, key=%s), value: %s, common=%s\n",
                    stage_trait::STAGE_INDEX,
                    dest_cfg_handle->ad_entry_addr.index,
                    dest_cfg_handle->ad_entry_addr.select,
                    em_key.pack().to_string().c_str(),
                    em_value.pack().to_string().c_str(),
                    em_value.payloads.entry.common_data.pack().to_string().c_str());

    return status;
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::unconfigure_entry(resolution_cfg_handle_t& cfg_handle)
{
    if (!cfg_handle.is_valid()) {
        return LA_STATUS_EUNKNOWN;
    }

    ad_table_sptr ad_table(stage_trait::get_ad_table(m_device));
    ad_entry_t ad_table_entry;
    if (cfg_handle.ad_table_entry.which() != 0) {
        ad_table_entry = boost::get<ad_entry_t>(cfg_handle.ad_table_entry);
    }
    ad_value_t ad_line;

    em_table_sptr em_table(stage_trait::get_em_table(m_device));
    em_entry_t em_table_entry;
    if (cfg_handle.em_table_entry.which() != 0) {
        em_table_entry = boost::get<em_entry_t>(cfg_handle.em_table_entry);
    }

    RES_DEBUG_PRINT(
        "Unconfiguring entry (stage=%u, EM-key=0x%s)\n", cfg_handle.stage_index, em_table_entry->key().pack().to_string().c_str());

    if (!cfg_handle.in_stage_dest) {
        if (cfg_handle.ad_entry_addr.is_valid()) {
            m_ad_entry_allocator.release(cfg_handle.ad_entry_addr);
        }

        if (ad_table_entry) {

            if (m_ad_entry_allocator.is_line_allocated(cfg_handle.ad_entry_addr.index)) {
                npl_resolution_assoc_data_entry_type_e entry_type;
                m_ad_entry_allocator.get_line_entry_type(cfg_handle.ad_entry_addr.index, entry_type);
                ad_line = ad_table_entry->value();

                la_uint8_t npl_entry_select = entry_select_to_npl(cfg_handle.ad_entry_addr.select, entry_type);
                npl_resolution_stage_assoc_data_result_t& ad_line_data(ad_line.payloads.line.data);

                switch (entry_type) {
                case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW:
                    resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_narrow_entry_t>::clear_ad_line_entry(
                        ad_line_data, npl_entry_select);
                    break;
                case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE:
                    resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_wide_entry_t>::clear_ad_line_entry(
                        ad_line_data, npl_entry_select);
                    break;
                case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW_PROTECTION:
                    resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_narrow_protection_record_t>::
                        clear_ad_line_entry(ad_line_data, npl_entry_select);
                    break;
                case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE_PROTECTION:
                    resolution_ad_table_entry_trait_t<npl_resolution_stage_assoc_data_wide_protection_record_t>::
                        clear_ad_line_entry(ad_line_data);
                    break;
                }

                ad_table_entry->update(ad_line);
            } else {
                ad_table->erase(ad_table_entry->key());
            }
        }
        cfg_handle.ad_table_entry = boost::blank();
    }

    if (em_table_entry) {
        remove_in_stage_dependencies(em_table_entry->key());

        em_table->erase(em_table_entry->key());
        cfg_handle.em_table_entry = boost::blank();
    }

    cfg_handle.set_invalid();
    return LA_STATUS_SUCCESS;
}

template <typename stage_trait>
template <typename table_value_type>
la_status
resolution_configurator_impl<stage_trait>::configure_resolution_stage_entry(
    const typename stage_trait::em_table_type::key_type& key,
    const table_value_type& value,
    resolution_cfg_handle_t& cfg_handle,
    const npl_em_common_data_t& common_data)
{
    resolution_assoc_data_table_addr_t ad_entry_addr;
    ad_table_sptr ad_table(stage_trait::get_ad_table(m_device));
    ad_key_t ad_key;
    ad_value_t ad_value;
    ad_entry_t ad_table_entry;

    em_table_sptr em_table(stage_trait::get_em_table(m_device));
    em_value_t em_value;
    em_entry_t em_table_entry;
    npl_resolution_assoc_data_entry_type_e entry_type = resolution_ad_table_entry_trait_t<table_value_type>::type;
    bool update_dependents = false;
    la_status status = LA_STATUS_SUCCESS;

    if (cfg_handle.is_valid() && (cfg_handle.in_stage_dest != nullptr)) {
        // Entry is being changed from in-stage destination mapping to
        // stand-alone mapping
        remove_in_stage_dependencies(key);
        update_dependents = true;
    } else {
        // If key already exists in EM no need to allocate new assoc-data entry
        // unless the type of entry has changed
        status = em_table->lookup(key, em_table_entry);
        if (status == LA_STATUS_SUCCESS) {
            update_dependents = true;
            npl_resolution_assoc_data_entry_type_e exisitng_entry_type;
            la_uint32_t line_index = em_table_entry->value().payloads.entry.addr;
            la_uint8_t entry_select = entry_select_from_npl(em_table_entry->value().payloads.entry.entry_select, entry_type);

            m_ad_entry_allocator.get_line_entry_type(line_index, exisitng_entry_type);
            if (entry_type != exisitng_entry_type) {
                resolution_assoc_data_table_addr_t entry_to_del;

                entry_to_del.index = line_index;
                entry_to_del.select = entry_select;
                m_ad_entry_allocator.release(entry_to_del);
            } else {
                ad_entry_addr.index = line_index;
                ad_entry_addr.select = entry_select;
            }
        }
    }

    // First time this key is inserted or the value entry type has changed
    if (!ad_entry_addr.is_valid()) {
        status = m_ad_entry_allocator.allocate(entry_type, ad_entry_addr);
        return_on_error(status);
    }

    cfg_handle.stage_index = stage_trait::STAGE_INDEX;
    cfg_handle.ad_entry_addr = ad_entry_addr;
    cfg_handle.common_data = common_data.pack().get_value();
    em_value.payloads.entry.addr = ad_entry_addr.index;
    em_value.payloads.entry.entry_select = entry_select_to_npl(ad_entry_addr.select, entry_type);
    em_value.payloads.entry.common_data = common_data;
    em_value.action = stage_trait::EM_TABLE_ACTION;

    // update assoc-data table
    ad_key.addr = ad_entry_addr.index;
    status = ad_table->lookup(ad_key, ad_table_entry);
    if (status == LA_STATUS_SUCCESS) {
        ad_value = ad_table_entry->value();
    }

    ad_value.action = stage_trait::AD_TABLE_ACTION;
    resolution_ad_table_entry_trait_t<table_value_type>::set_ad_line_entry(
        ad_value.payloads.line.data, value, ad_entry_addr.select);

    RES_DEBUG_PRINT("Writing to AD table (stage=%u, addr=0x%x, select=0x%x), key=0x%s, value: %s\n",
                    stage_trait::STAGE_INDEX,
                    ad_entry_addr.index,
                    ad_entry_addr.select,
                    ad_key.pack().to_string().c_str(),
                    ad_value.pack().to_string().c_str());

    status = ad_table->set(ad_key, ad_value, ad_table_entry);
    return_on_error(status);
    cfg_handle.ad_table_entry = ad_table_entry;

    // update EM table
    RES_DEBUG_PRINT("Writing to EM table (stage=%u, addr=0x%x, select=0x%x), key=0x%s, value: %s, common=%s\n",
                    stage_trait::STAGE_INDEX,
                    ad_entry_addr.index,
                    ad_entry_addr.select,
                    key.pack().to_string().c_str(),
                    em_value.pack().to_string().c_str(),
                    common_data.pack().to_string().c_str());
    status = em_table->set(key, em_value, em_table_entry);
    return_on_error(status);
    cfg_handle.em_table_entry = em_table_entry;

    if (update_dependents) {
        update_in_stage_dependents(key, cfg_handle);
    }

    return status;
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::set_group_size(const la_uint32_t group_id,
                                                          const la_uint32_t group_size,
                                                          npl_lb_consistency_mode_e consistency_mode)
{
    group_size_key_t k;
    group_size_value_t v;
    group_size_entry_t existing_entry_ptr;

    // Set key
    k.group_id = group_id;

    // Set value
    v.action = stage_trait::GROUP_SIZE_TABLE_ACTION;
    v.payloads.resolution_lb_size_table_result.group_size = group_size;
    v.payloads.resolution_lb_size_table_result.consistency_mode = consistency_mode;

    RES_DEBUG_PRINT("Setting EM group size, stage=%u, group_id=0x%x, size=%u\n", stage_trait::STAGE_INDEX, group_id, group_size);

    // Write to table
    return stage_trait::get_group_size_table(m_device)->set(k, v, existing_entry_ptr);
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::get_group_size(const la_uint32_t group_id,
                                                          la_uint32_t& out_group_size,
                                                          npl_lb_consistency_mode_e& out_consistency_mode)
{
    group_size_key_t k;
    group_size_entry_t existing_entry_ptr;

    // Set key
    k.group_id = group_id;

    // Read from table
    la_status status = stage_trait::get_group_size_table(m_device)->lookup(k, existing_entry_ptr);
    if (existing_entry_ptr) {
        out_group_size = existing_entry_ptr->value().payloads.resolution_lb_size_table_result.group_size;
        out_consistency_mode = existing_entry_ptr->value().payloads.resolution_lb_size_table_result.consistency_mode;
    }

    return status;
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::erase_group_size(const la_uint32_t group_id)
{
    group_size_key_t k;

    // Set key
    RES_DEBUG_PRINT("Erasing EM group size stage=%u, group=0x%x\n", stage_trait::STAGE_INDEX, group_id);

    k.group_id = group_id;
    return stage_trait::get_group_size_table(m_device)->erase(k);
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::configure_protection_monitor(const la_protection_monitor_gid_t& monitor_id,
                                                                        npl_resolution_protection_selector_e selector)
{
    protection_key_t k;
    protection_value_t v;
    protection_entry_t existing_entry_ptr;

    k.id = monitor_id;
    v.payloads.resolution_protection_result.sel = selector;

    RES_DEBUG_PRINT(
        "configuring portection table, stage=%u, monitor_id=0x%x, selector=%u\n", stage_trait::STAGE_INDEX, monitor_id, selector);
    return stage_trait::get_protection_table(m_device)->set(k, v, existing_entry_ptr);
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::unconfigure_protection_monitor(const la_protection_monitor_gid_t& monitor_id)
{

    protection_key_t k;
    k.id = monitor_id;

    RES_DEBUG_PRINT("unconfiguring protection monitor, stage=%u, monitor_id=0x%x\n", stage_trait::STAGE_INDEX, monitor_id);
    return stage_trait::get_protection_table(m_device)->erase(k);
}

template <typename stage_trait>
la_status
resolution_configurator_impl<stage_trait>::get_in_stage_resolution_cfg_handle(la_object_wcptr in_stage_dest,
                                                                              const resolution_cfg_handle_t*& cfg_handle)
{
    la_object::object_type_e type = in_stage_dest->type();
    la_status status;

    if (type == la_object::object_type_e::TE_TUNNEL) {
        auto te_tunnel = in_stage_dest.weak_ptr_static_cast<const la_te_tunnel_impl>();
        in_stage_dest = m_device->get_sptr<const la_object>(te_tunnel->get_destination());
        type = in_stage_dest->type();
    }

    switch (type) {
    case la_object::object_type_e::L3_PROTECTION_GROUP: {
        auto l3_protection_group = in_stage_dest.weak_ptr_static_cast<const la_l3_protection_group_impl>();
        status = l3_protection_group->get_resolution_cfg_handle(cfg_handle);
        break;
    }

    case la_object::object_type_e::PREFIX_OBJECT: {
        auto prefix_object = in_stage_dest.weak_ptr_static_cast<const la_prefix_object_gibraltar>();
        status = prefix_object->get_resolution_cfg_handle(cfg_handle);
        break;
    }

    case la_object::object_type_e::IP_TUNNEL_DESTINATION: {
        auto tunnel_object = in_stage_dest.weak_ptr_static_cast<const la_ip_tunnel_destination_impl>();
        status = tunnel_object->get_resolution_cfg_handle(cfg_handle);
        break;
    }

    case la_object::object_type_e::ASBR_LSP: {
        auto asbr_lsp = in_stage_dest.weak_ptr_static_cast<const la_asbr_lsp_impl>();
        status = asbr_lsp->get_resolution_cfg_handle(cfg_handle);
        break;
    }

    case la_object::object_type_e::DESTINATION_PE: {
        auto dpe = in_stage_dest.weak_ptr_static_cast<const la_destination_pe_impl>();
        status = dpe->get_resolution_cfg_handle(cfg_handle);
        break;
    }

    default:
        status = LA_STATUS_EUNKNOWN;
    }

    if (status == LA_STATUS_SUCCESS) {
        if (cfg_handle->stage_index != stage_trait::STAGE_INDEX) {
            dassert_crit(false);
            status = LA_STATUS_EUNKNOWN;
        }
    }

    return status;
}

} // namespace silicon_one

#undef RES_DEBUG_PRINT

#endif // __RESOLUTION_CONFIGURATOR_IMPL_H__
