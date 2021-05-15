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

#ifndef __LA_ACL_SECURITY_GROUP_H__
#define __LA_ACL_SECURITY_GROUP_H__

#include "la_acl_delegate.h"

namespace silicon_one
{

class la_device_impl;

class la_acl_security_group : public la_acl_delegate
{
    /////////Serialization////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_acl_security_group() = default;
    //////////////////////////////////
public:
    la_acl_security_group(const la_device_impl_wptr& device, const la_acl_wptr& parent);
    ~la_acl_security_group() override;

    // Object life-cycle API-s
    la_status initialize(const la_acl_key_profile_base_wcptr& acl_key_profile,
                         const la_acl_command_profile_base_wcptr& acl_command_profile) override;
    la_status destroy() override;

    la_status allocate_acl_id(la_slice_pair_id_t slice_pair) override;
    la_status release_acl_id(la_slice_pair_id_t slice_pair) override;
    la_uint32_t get_sgacl_id() override;
    la_status set_unknown_sgacl_id() override;
    la_status set_default_sgacl_id() override;

    la_uint32_t m_sgacl_id;

protected:
    using npl_table_t = npl_sgacl_table_t;

    la_status get_tcam_max_available_space(la_slice_id_t slice, size_t& out_space) const override;

    // Helper functions
    la_status copy_field_to_npl(const la_acl_field acl_field,
                                npl_table_t::key_type& npl_key,
                                npl_table_t::key_type& npl_mask) const;
    la_status copy_key_mask_to_npl(la_slice_id_t slice,
                                   const la_acl_key& key_mask,
                                   npl_table_t::key_type& npl_key,
                                   npl_table_t::key_type& npl_mask) const;
    la_status copy_npl_to_field(const npl_table_t::key_type& npl_key,
                                const npl_table_t::key_type& npl_mask,
                                la_acl_field_def acl_field_def,
                                la_acl_field& acl_field) const;
    la_status copy_npl_to_key_mask(const npl_table_t::key_type& npl_key,
                                   const npl_table_t::key_type& npl_mask,
                                   la_acl_key& out_key_mask) const;
    la_status get_tcam_line(la_slice_id_t slice,
                            size_t tcam_line,
                            la_acl_key& out_key_val,
                            la_acl_command_actions& out_cmd) const override;

    size_t get_tcam_size(la_slice_id_t slice) const override;
    size_t get_tcam_fullness(la_slice_id_t slice) const override;
    la_status copy_entry_to_npl(la_slice_id_t slice,
                                const la_acl_key& key_val,
                                const la_acl_command_actions& cmd,
                                npl_table_t::key_type& key,
                                npl_table_t::key_type& mask,
                                npl_table_t::value_type& value);
    la_status set_tcam_line(la_slice_id_t slice,
                            size_t tcam_line,
                            bool is_push,
                            const la_acl_key& key_val,
                            const la_acl_command_actions& cmd) override;
    /// @brief Push ACEs starting from a specific TCAM line.
    ///
    /// @param[in]  slice               Slice to push ACEs to.
    /// @param[in]  first_tcam_line     First TCAM line of the required ACEs.
    /// @param[in]  entries_num         Number of ACEs to push.
    /// @param[in]  entries             ACL key values and commands to push.
    la_status push_tcam_lines(la_slice_id_t slice,
                              size_t first_tcam_line,
                              size_t entries_num,
                              const vector_alloc<acl_entry_desc>& entries) override;

    /// @brief Locate the first free line after the last entry in the TCAM table used by this ACL on a given slice
    ///
    /// @param[in]  slice        Slice to search
    /// @param[out] position     TCAM line index which is free
    la_status locate_free_tcam_line_after_last_entry(la_slice_id_t slice, size_t& position) const override;
    la_status is_tcam_line_contains_ace(la_slice_id_t slice, size_t tcam_line, bool& contains) const override;
    la_status erase_tcam_line(la_slice_id_t slice, size_t tcam_line) override;
    la_status clear_tcam_line(la_slice_id_t slice, size_t tcam_line) override;
    la_status locate_free_tcam_entry(la_slice_id_t slice, size_t start, size_t& position) const override;
};
}

#endif // __LA_ACL_SECURITY_GROUP_H__
