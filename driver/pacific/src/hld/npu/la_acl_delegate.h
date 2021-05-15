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

#ifndef __LA_ACL_DELEGATE_H__
#define __LA_ACL_DELEGATE_H__

#include <array>
#include <deque>

#include "api/npu/la_acl.h"

#include "hld_types.h"
#include "ifg_use_count.h"
#include "la_acl_impl.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

namespace silicon_one
{
class la_acl_delegate : public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_acl_delegate(const la_device_impl_wptr& device, const la_acl_wptr& parent);
    virtual ~la_acl_delegate();

    // Object life-cycle API-s
    virtual la_status initialize(const la_acl_key_profile_base_wcptr& acl_key_profile,
                                 const la_acl_command_profile_base_wcptr& acl_command_profile)
        = 0;
    virtual la_status initialize_pcls(const la_pcl_wptr& src_pcl, const la_pcl_wptr& dst_pcl);
    virtual la_status destroy() = 0;

    // la_acl API-s
    la_status get_type(la_acl::type_e& out_type) const;
    const la_pcl_wcptr get_src_pcl() const;
    const la_pcl_wcptr get_dst_pcl() const;
    la_status get_count(size_t& out_count) const;
    la_status append(const la_acl_key& key_val, const la_acl_command_actions& cmd);
    la_status insert(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd);
    la_status set(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd);
    la_status erase(size_t position);
    la_status get(size_t position, acl_entry_desc& out_acl_entry_desc) const;
    la_status reserve();
    virtual la_status clear();

    const la_acl_wptr& get_acl_parent() const;

    /// IFG management
    la_status notify_change(dependency_management_op op);
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);
    slice_ifg_vec_t get_ifgs() const;

    /// Set a the qos policy id, used for qos id
    void set_qos_id(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id);
    void clear_qos_id();
    // Implementation

    /// @brief Retrieve ACL ID.
    ///
    /// @param[out] out_id              Retrieved ACL ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Key retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status get_id(la_slice_id_t slice, la_acl_id_t& out_id) const;

    virtual la_uint32_t get_sgacl_id();

    const la_device_impl* get_device() const
    {
        return m_device.get();
    }

    la_status get_tcam_max_available_space(size_t& out_space) const;

    la_status get_acl_command_profile(const la_acl_command_actions& acl_cmd_actions,
                                      npl_rtf_profile_type_e& out_command_profile) const;

protected:
    la_status copy_acl_command_to_npl(la_slice_id_t slice,
                                      const la_acl_command_actions& acl_cmd_actions,
                                      npl_egress_sec_acl_result_t& out_npl_sec) const;
    la_status copy_acl_command_to_npl(la_slice_id_t slice,
                                      const la_acl_command_actions& acl_cmd_actions,
                                      npl_rtf_payload_t& out_npl) const;
    la_status copy_security_group_acl_command_to_npl(la_slice_id_t slice,
                                                     const la_acl_command_actions& acl_cmd,
                                                     npl_sgacl_payload_t& npl_sgacl) const;

    void copy_npl_to_acl_command(const npl_rtf_result_profile_0_t& npl_result, la_acl_command_actions& out_acl_cmd) const;
    void copy_npl_to_acl_command(const npl_egress_sec_acl_result_t& npl_sec, la_acl_command_actions& out_acl_cmd) const;
    void copy_npl_to_security_group_acl_command(const npl_sgacl_payload_t& npl_sgacl, la_acl_command_actions& out_acl_cmd) const;

    virtual la_status update_acl_properties_table(la_slice_pair_id_t slice_pair, bool is_valid);

    /// @brief Program tcam entries for the ACL on slice where it was not previously programmed.
    ///
    /// @param[in]  slice       ID of new slice
    virtual la_status add_tcam_entries_to_slice(la_slice_id_t slice);

    /// @brief Remove tcam entries from slice where they already exist
    ///
    /// @param[in]  slice       ID of new slice
    virtual la_status remove_tcam_entries_from_slice(la_slice_id_t slice);

    la_status allocate_l2_egress_sec_acl_id(la_slice_pair_id_t slice_pair);
    la_status release_l2_egress_sec_acl_id(la_slice_pair_id_t slice_pair);

    la_status allocate_ipv4_egress_sec_acl_id(la_slice_pair_id_t slice_pair);
    la_status release_ipv4_egress_sec_acl_id(la_slice_pair_id_t slice_pair);
    la_status allocate_ipv6_egress_sec_acl_id(la_slice_pair_id_t slice_pair);
    la_status release_ipv6_egress_sec_acl_id(la_slice_pair_id_t slice_pair);

    virtual la_status get_tcam_max_available_space(la_slice_id_t slice, size_t& out_space) const = 0;

    // Device this acl belongs to
    la_device_impl_wptr m_device;

    struct slice_pair_data {
        la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data);

    std::array<slice_pair_data, NUM_SLICE_PAIRS_PER_DEVICE> m_slice_pair_data;

    // IFG management
    ifg_use_count_uptr m_ifg_use_count;

    // Stage of the ACL.
    la_acl::stage_e m_stage;

    // Type of the ACL.
    la_acl::type_e m_acl_type;

    // ACL key profile.
    la_acl_key_profile_base_wcptr m_acl_key_profile;

    // ACL command profile.
    la_acl_command_profile_base_wcptr m_acl_command_profile;

    // Parent object
    la_acl_wptr m_parent;

    // Counts inserted commands with QoS action
    la_uint_t m_qos_cmd_count;

protected:
    virtual size_t get_tcam_size(la_slice_id_t slice) const = 0;
    virtual size_t get_tcam_fullness(la_slice_id_t slice) const = 0;

    /// @brief Set an ACE at a specific TCAM line.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    /// @param[in]  is_push     If true, and current line in-use, will push all entries down before insert.
    /// @param[in]  key_val     ACL key value to set.
    /// @param[in]  cmd         ACL command to set.
    virtual la_status set_tcam_line(la_slice_id_t slice,
                                    size_t tcam_line,
                                    bool is_push,
                                    const la_acl_key& key_val,
                                    const la_acl_command_actions& cmd)
        = 0;

    /// @brief Push ACEs starting from a specific TCAM line.
    ///
    /// @param[in]  slice               Slice to push ACEs to.
    /// @param[in]  first_tcam_line     First TCAM line of the required ACEs.
    /// @param[in]  entries_num         Number of ACEs to push.
    /// @param[in]  entries             ACL key values and commands to push.
    virtual la_status push_tcam_lines(la_slice_id_t slice,
                                      size_t first_tcam_line,
                                      size_t entries_num,
                                      const vector_alloc<acl_entry_desc>& entries)
        = 0;

    /// @brief Erase ACE at a specific TCAM line.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    virtual la_status erase_tcam_line(la_slice_id_t slice, size_t tcam_line) = 0;

    /// @brief Locate the first free entry in the TCAM table used by this ACL on a given slice
    ///
    /// @param[in]  slice        Slice to search
    /// @param[in]  start        Position to start searching from
    /// @param[out] position     TCAM line index which is free
    virtual la_status locate_free_tcam_entry(la_slice_id_t slice, size_t start, size_t& position) const = 0;

    /// @brief Locate the first free line after the last entry in the TCAM table used by this ACL on a given slice
    ///
    /// @param[in]  slice        Slice to search
    /// @param[out] position     TCAM line index which is free
    virtual la_status locate_free_tcam_line_after_last_entry(la_slice_id_t slice, size_t& position) const = 0;

    la_acl_delegate() = default; // For serialization purposes only.

    // Source and destination PCL values
    la_pcl_wptr m_src_pcl;
    la_pcl_wptr m_dst_pcl;

private:
    // Shadow of configured ACE's, for application to new slices.
    std::deque<acl_entry_desc> m_aces;

    virtual la_status get_tcam_line(la_slice_id_t slice,
                                    size_t tcam_line,
                                    la_acl_key& out_key_val,
                                    la_acl_command_actions& out_cmd) const = 0;

    /// @brief Locate the TCAM line of a specific ACE of the ACL.
    ///
    /// @param[in]  position            ACE index.
    /// @param[out] tcam_line_index     TCAM line index of the required ACE.
    la_status get_tcam_line_index(la_slice_id_t slice, size_t position, size_t& tcam_line_index) const;

    /// @brief Check if specific TCAM line contains an ACE of the ACL.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    /// @param[out] contains    TCAM line contains an ACE.
    virtual la_status is_tcam_line_contains_ace(la_slice_id_t, size_t tcam_line, bool& contains) const = 0;

    /// @brief Erase ACE at a specific TCAM line if already exists.
    ///
    /// @param[in]  tcam_line   TCAM line of the required ACE.
    virtual la_status clear_tcam_line(la_slice_id_t, size_t tcam_line) = 0;

    /// @brief Allocate an ACL id for the requested slice pair and update m_slice_pair_data.
    ///
    /// @param[in]  slice_pair  Slice pair index on which to allocate an id.
    virtual la_status allocate_acl_id(la_slice_pair_id_t slice_pair) = 0;

    /// @brief Release ACL id for the requested slice pair and update m_slice_pair_data
    ///
    /// @param[in]  slice_pair  Slice pair index on which to release an id.
    virtual la_status release_acl_id(la_slice_pair_id_t slice_pair) = 0;

    // Handling of acl command
    la_status add_entry_command(la_acl_direction_e dir, const la_acl_command_actions& cmd);

    la_status remove_entry_command(la_acl_direction_e dir, const la_acl_command_actions& cmd);

    // Handling of egress cartesian product (sec x qos) tables
    la_status find_l2_egress_free_acl_id(la_slice_pair_id_t slice_pair);
    la_status reserve_l2_egress_acl_id(la_slice_pair_id_t slice_pair,
                                       npl_mac_sec_acl_type_e sec_key,
                                       npl_mac_qos_acl_type_e qos_key);
};
}

#endif // __LA_ACL_DELEGATE_H__
