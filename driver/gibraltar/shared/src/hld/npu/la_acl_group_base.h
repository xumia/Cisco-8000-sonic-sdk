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

#ifndef __LA_ACL_GROUP_BASE_H__
#define __LA_ACL_GROUP_BASE_H__

#include <vector>

#include "api/npu/la_acl_group.h"
#include "common/profile_allocator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_device_impl;

typedef la_uint64_t acl_group_rtf_conf_set_id_t;
using la_acl_wptr_vec_t = std::vector<la_acl_wptr>;
static const acl_group_rtf_conf_set_id_t RTF_CONF_SET_ID_INVALID = (acl_group_rtf_conf_set_id_t)(0);

class la_acl_group_base : public la_acl_group
{
    //////// Serialization ////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    ///////////////////////////////
public:
    la_acl_group_base(const la_device_impl_wptr& device);
    ~la_acl_group_base() override;
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_acl_group API-s
    la_status set_acls(la_acl_packet_format_e packet_format, const la_acl_vec_t& acls) override;
    la_status get_acls(la_acl_packet_format_e packet_format, la_acl_vec_t& out_acls) const override;

    // Implementation
    la_status do_set_acls(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls);
    la_status do_get_acls(la_acl_packet_format_e packet_format, la_acl_wptr_vec_t& out_acls) const;
    la_status get_rtf_conf_set_id(acl_group_rtf_conf_set_id_t& out_rtf_conf_set_id) const;
    virtual npl_rtf_stage_and_type_e get_next_rtf_stage(la_acl_packet_format_e packet_format,
                                                        const la_acl_wptr_vec_t& acls,
                                                        uint16_t acl_index) const = 0;
    npl_init_rtf_stage_and_type_e get_init_ip_rtf_stage(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls) const;
    virtual npl_rtf_stage_and_type_e get_init_eth_rtf_stage(la_acl_packet_format_e packet_format,
                                                            const la_acl_wptr_vec_t& acls) const = 0;
    virtual la_status get_post_fwd_rtf_stage(la_acl_packet_format_e packet_format,
                                             const la_acl_wptr_vec_t& acls,
                                             npl_rtf_stage_and_type_e& post_fwd_rtf_stage) const = 0;

    la_status config_l2_rtf_conf_set(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id);
    la_status config_rtf_conf_set_to_post_fwd_stage(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id);
    la_status config_rtf_conf_set_to_og_pcl_configs(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id);
    void notify_acl_group_change(la_acl_packet_format_e packet_format) const;
    la_status allocate_rtf_conf_set_id_and_config_mapping(la_slice_id_vec_t slices);
    la_status get_real_acls(la_acl_packet_format_e packet_format, la_acl_wptr_vec_t& out_real_acls) const;

protected:
    // Containing device
    la_device_impl_wptr m_device;

    la_acl_group_base() = default; // Needed for cereal

private:
    void extract_real_acls(const la_acl_wptr_vec_t& acls, la_acl_wptr_vec_t& real_acls);
    profile_allocator<acl_group_info_t>::profile_ptr m_acl_group_profile{};

    la_status allocate_rtf_conf_set_id(acl_group_rtf_conf_set_id_t& out_rtf_conf_set_id);
    la_status validate_acls(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls) const;

    la_status config_eth_rtf_conf_set_mapping(la_slice_id_t slice,
                                              acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                              const la_acl_wptr_vec_t& acls) const;
    la_status config_ipv4_rtf_conf_set_mapping(la_slice_id_t slice,
                                               acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                               const la_acl_wptr_vec_t& acls) const;
    la_status config_ipv6_rtf_conf_set_mapping(la_slice_id_t slice,
                                               acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                               const la_acl_wptr_vec_t& acls) const;

    la_status config_eth_rtf_conf_set_mapping_entry(la_slice_id_t slice,
                                                    acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                    uint64_t step,
                                                    la_acl_id_t acl_id,
                                                    npl_fwd0_table_index_e table_index,
                                                    npl_rtf_stage_and_type_e next_rtf_stage,
                                                    uint64_t stop_on_step) const;

    la_status config_ipv4_rtf_conf_set_mapping_entry(la_slice_id_t slice,
                                                     acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                     uint64_t step,
                                                     la_acl_id_t acl_id,
                                                     npl_fwd0_table_index_e table_index,
                                                     npl_rtf_stage_and_type_e next_rtf_stage,
                                                     uint64_t stop_on_step) const;

    la_status config_ipv6_rtf_conf_set_mapping_entry(la_slice_id_t slice,
                                                     acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                     uint64_t step,
                                                     la_acl_id_t acl_id,
                                                     npl_fwd0_table_index_e table_index,
                                                     npl_rtf_stage_and_type_e next_rtf_stage,
                                                     uint64_t stop_on_step) const;

    la_status config_l2_rtf_conf_set_and_init_stages(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id);

    la_status reset_acl_group_cfg(acl_group_rtf_conf_set_id_t rtf_conf_set_id);

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // ethernet acls
    la_acl_wptr_vec_t m_ethernet_acls{};
    la_acl_wptr_vec_t m_real_ethernet_acls{};

    // ipv4 acls
    la_acl_wptr_vec_t m_ipv4_acls{};
    la_acl_wptr_vec_t m_real_ipv4_acls{};

    // ipv6 acls
    la_acl_wptr_vec_t m_ipv6_acls{};
    la_acl_wptr_vec_t m_real_ipv6_acls{};
};

} // namespace silicon_one

#endif //  __LA_ACL_GROUP_BASE_H__
