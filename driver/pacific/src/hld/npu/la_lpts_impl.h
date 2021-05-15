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

#ifndef __LA_LPTS_IMPL_H__
#define __LA_LPTS_IMPL_H__

#include <array>
#include <deque>
#include <map>

#include "api/npu/la_lpts.h"
#include "common/profile_allocator.h"
#include "system/counter_allocation.h"

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_lpts_impl : public la_lpts
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Maximum LPTS flow_type supported
    enum { MAX_LPTS_FLOW_TYPE = 0xf };

    explicit la_lpts_impl(const la_device_impl_wptr& device);
    virtual ~la_lpts_impl();

    // Object life-cycle API-s
    virtual la_status initialize(la_object_id_t oid, lpts_type_e type);
    virtual la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_lpts API-s
    la_status get_lpts_type(lpts_type_e& out_type) const override;
    la_status get_count(size_t& out_count) const override;
    la_status append(const la_lpts_key& key_val, const la_lpts_result& result) override;
    la_status push(size_t position, const la_lpts_key& key_val, const la_lpts_result& result) override;
    la_status set(size_t position, const la_lpts_key& key_val, const la_lpts_result& result) override;
    la_status pop(size_t position) override;
    la_status clear() override;
    la_status get(size_t position, lpts_entry_desc& out_lpts_entry_desc) const override;
    la_status get_max_available_space(size_t& out_available_space) const override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

private:
    using lpts_compressed_meter_profile = profile_allocator<la_meter_set_wcptr>::profile_ptr;
    using lpts_em_entry_data = npl_lpts_payload_t;
    using lpts_em_profile = profile_allocator<lpts_em_entry_data>::profile_ptr;

    // LPTS entry cache data
    struct lpts_entry_data {
        lpts_entry_desc entry_desc;
        lpts_em_profile em_sptr;
        lpts_compressed_meter_profile meter_sptr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(lpts_entry_data);

    // Device this switch belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Type of the LPTS instance.
    lpts_type_e m_type;

    // Shadow of configured LPTS entries
    std::deque<lpts_entry_data> m_entries;

    // Meter to use-count map
    std::map<la_meter_set_wcptr, size_t> m_meter_to_use_count;

    // allocator profile of nullprt meter.
    lpts_compressed_meter_profile m_null_meter_profile;

    // Meter descriptor for null entery meter, mapped by slice-pair-id
    std::vector<std::unique_ptr<counter_allocation> > m_null_allocations;

    // Helper functions
    la_status get_tcam_size(la_slice_id_t slice, size_t& size) const;
    la_status get_tcam_fullness(la_slice_id_t slice, size_t& size) const;
    la_status get_tcam_line_index(la_slice_id_t slice, size_t position, size_t& tcam_line_index) const;
    la_status is_tcam_line_contains_entry(la_slice_id_t slice, size_t tcam_line, bool& contains) const;
    la_status set_tcam_line_v4(la_slice_id_t slice,
                               size_t tcam_line,
                               bool is_push,
                               npl_ipv4_lpts_table_t::key_type k1,
                               npl_ipv4_lpts_table_t::key_type m1,
                               npl_ipv4_lpts_table_t::value_type v1,
                               const la_lpts_result& result,
                               lpts_em_profile& lpts_em_ptr);
    la_status set_tcam_line_v6(la_slice_id_t slice,
                               size_t tcam_line,
                               bool is_push,
                               npl_ipv6_lpts_table_t::key_type k1,
                               npl_ipv6_lpts_table_t::key_type m1,
                               npl_ipv6_lpts_table_t::value_type v1,
                               const la_lpts_result& result,
                               lpts_em_profile& lpts_em_ptr);
    la_status copy_v4_key_mask_to_npl(const la_lpts_key_ipv4& key_mask,
                                      npl_ipv4_lpts_table_t::key_type& npl_key_mask,
                                      bool is_mask) const;
    la_status copy_v6_key_mask_to_npl(const la_lpts_key_ipv6& key_mask,
                                      npl_ipv6_lpts_table_t::key_type& npl_key_mask,
                                      bool is_mask) const;
    la_status copy_v4_lpts_result_to_npl(const la_lpts_result& lpts_result,
                                         npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t& first_lookup_result,
                                         lpts_em_profile& lpts_em_ptr,
                                         lpts_compressed_meter_profile& meter_profile);
    la_status copy_v6_lpts_result_to_npl(const la_lpts_result& lpts_result,
                                         npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t& first_lookup_result,
                                         lpts_em_profile& lpts_em_ptr,
                                         lpts_compressed_meter_profile& meter_profile);
    la_status allocate_lpts_em_id(const la_lpts_result& lpts_result, lpts_em_profile& lpts_em_ptr);
    la_status pop_lpts_tcam_table_entry(la_slice_id_t slice, size_t tcam_line);
    la_status erase_lpts_2nd_lookup_table_entry(size_t lpts_em_id);
    la_status rollback_lpts_2nd_lookup_table_and_meters(const lpts_em_profile& lpts_em_ptr, const la_lpts_result& result);
    la_status configure_lpts_meter_table(const la_meter_set_wcptr& meter, uint64_t meter_index);
    la_status attach_meter(const la_meter_set_wcptr& meter, bool is_lpts_entry_meter);
    la_status detach_meter(const la_meter_set_wcptr& meter);
    la_status validate_lpts_result(const la_lpts_result& result);
    la_status detach_all_meters(const la_lpts_result& result);

    la_lpts_impl() = default; // For serialization purposes only.
};
}

#endif // __LA_LPTS_IMPL_H__
