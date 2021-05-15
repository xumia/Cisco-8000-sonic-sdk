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

#ifndef __LA_ACL_SCALED_DELEGATE_H__
#define __LA_ACL_SCALED_DELEGATE_H__

#include "api/npu/la_acl_scaled.h"

#include "la_acl_delegate.h"

namespace silicon_one
{

class la_device_impl;

class la_acl_scaled_delegate : public la_acl_delegate
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_acl_scaled_delegate(const la_device_impl_wptr& device, const la_acl_wptr& parent);
    ~la_acl_scaled_delegate() override;

    // Object life-cycle API-s
    virtual la_status initialize(la_acl::stage_e stage, la_acl::type_e acl_type) = 0;

    // la_acl API-s
    using la_acl_delegate::get_count;
    using la_acl_delegate::append;
    using la_acl_delegate::insert;
    using la_acl_delegate::set;
    using la_acl_delegate::erase;
    using la_acl_delegate::get;
    using la_acl_delegate::initialize;
    using la_acl_delegate::get_tcam_size;
    using la_acl_delegate::get_tcam_fullness;
    using la_acl_delegate::set_tcam_line;
    using la_acl_delegate::push_tcam_lines;
    using la_acl_delegate::locate_free_tcam_line_after_last_entry;
    using la_acl_delegate::erase_tcam_line;
    using la_acl_delegate::locate_free_tcam_entry;
    using la_acl_delegate::get_tcam_max_available_space;

    la_status clear() override;

    // la_acl_scaled API-s
    virtual la_status get_count(la_acl_scaled::scale_field_e scale_field, size_t& out_count) const;
    la_status append(la_acl_scaled::scale_field_e scale_field,
                     const la_acl_scale_field_key& sf_key,
                     const la_acl_scale_field_val& sf_val);
    la_status insert(la_acl_scaled::scale_field_e scale_field,
                     size_t position,
                     const la_acl_scale_field_key& sf_key,
                     const la_acl_scale_field_val& sf_val);
    la_status set(la_acl_scaled::scale_field_e scale_field,
                  size_t position,
                  const la_acl_scale_field_key& sf_key,
                  const la_acl_scale_field_val& sf_val);
    la_status erase(la_acl_scaled::scale_field_e scale_field, size_t position);
    la_status get(la_acl_scaled::scale_field_e scale_field,
                  size_t position,
                  const la_acl_scale_field_key*& out_sf_key,
                  const la_acl_scale_field_val*& out_sf_val);

private:
    using scale_field_entry = std::pair<la_acl_scale_field_key, la_acl_scale_field_val>;

    virtual size_t get_tcam_size(la_slice_id_t slice, la_acl_scaled::scale_field_e scale_field) const = 0;
    virtual size_t get_tcam_fullness(la_slice_id_t slice, la_acl_scaled::scale_field_e scale_field) const = 0;

    /// @brief Locate the TCAM line of a specific ACE of the ACL.
    ///
    /// @param[in]  position            ACE index.
    /// @param[out] tcam_line_index     TCAM line index of the required ACE.
    la_status get_tcam_line_index(la_slice_id_t slice,
                                  la_acl_scaled::scale_field_e scale_field,
                                  size_t position,
                                  size_t& tcam_line_index) const;

    /// @brief Set an ACE at a specific TCAM line.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    /// @param[in]  is_push     If true, and current line in-use, will push all entries down before insert.
    /// @param[in]  key_val     ACL key value to set.
    /// @param[in]  cmd         ACL command to set.
    virtual la_status set_tcam_line(la_slice_id_t slice,
                                    la_acl_scaled::scale_field_e scale_field,
                                    size_t tcam_line,
                                    bool is_push,
                                    const la_acl_scale_field_key& sf_key,
                                    const la_acl_scale_field_val& sf_val)
        = 0;

    /// @brief Check if specific TCAM line contains an ACE of the ACL.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    /// @param[out] contains    TCAM line contains an ACE.
    virtual la_status is_tcam_line_contains(la_slice_id_t slice,
                                            la_acl_scaled::scale_field_e scale_field,
                                            size_t tcam_line,
                                            bool& contains) const = 0;

    /// @brief Erase ACE at a specific TCAM line.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    virtual la_status erase_tcam_line(la_slice_id_t slice, la_acl_scaled::scale_field_e scale_field, size_t tcam_line) = 0;

    virtual la_status locate_free_tcam_entry(la_slice_id_t slice,
                                             la_acl_scaled::scale_field_e scale_field,
                                             size_t start,
                                             size_t& position) const = 0;

    la_status add_tcam_entries_to_slice(la_slice_id_t slice) override;
    la_status remove_tcam_entries_from_slice(la_slice_id_t slice) override;

    std::deque<scale_field_entry> m_scale_field_entries[(int)la_acl_scaled::scale_field_e::LAST];

    la_acl_scaled_delegate() = default;
};
}

#endif // __LA_ACL_SCALED_DELEGATE_H__
