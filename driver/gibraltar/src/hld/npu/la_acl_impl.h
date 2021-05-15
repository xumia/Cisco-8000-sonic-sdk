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

#ifndef __LA_ACL_IMPL_H__
#define __LA_ACL_IMPL_H__

#include "api/npu/la_acl.h"
#include "api/npu/la_pcl.h"

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_acl_command_profile_base.h"
#include "npu/la_acl_key_profile_base.h"
#include <deque>
#include <memory>

#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

class la_device_impl;
class la_acl_key_profile_base;
class la_acl_command_profile_base;
class la_acl_delegate;

class la_acl_impl : public la_acl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_acl_impl(const la_device_impl_wptr& device);
    ~la_acl_impl() override;

    // Object life-cycle API-s
    virtual la_status initialize(la_object_id_t oid,
                                 const la_acl_key_profile_base* acl_key_profile,
                                 const la_acl_command_profile_base* acl_command_profile,
                                 const la_pcl_wptr& src_pcl,
                                 const la_pcl_wptr& dst_pcl);
    virtual la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_acl API-s
    la_status get_type(type_e& out_type) const override;
    la_status get_acl_key_profile(const la_acl_key_profile*& out_acl_key_profile) const override;
    la_status get_acl_command_profile(const la_acl_command_profile*& out_acl_command_profile) const override;
    la_status get_count(size_t& out_count) const override;
    la_status append(const la_acl_key& key_val, const la_acl_command_actions& cmd) override;
    la_status insert(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd) override;
    la_status set(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd) override;
    la_status erase(size_t position) override;
    la_status clear() override;
    la_status get(size_t position, acl_entry_desc& out_acl_entry_desc) const override;
    la_status get_max_available_space(size_t& out_available_space) const override;

    // Implementation
    const la_acl_delegate_wptr get_delegate() const;
    la_status get_rtf_stage(la_acl_packet_processing_stage_e& out_stage) const;
    bool is_og_acl() const;
    bool is_class_id_enabled() const;

    const la_pcl_wcptr get_src_pcl() const;
    const la_pcl_wcptr get_dst_pcl() const;
    la_status reserve();

private:
    // Device this ACL belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    la_acl_delegate_sptr m_delegate;

    // ACL key profile
    la_acl_key_profile_base_wcptr m_acl_key_profile;

    // ACL command profile
    la_acl_command_profile_base_wcptr m_acl_command_profile;

    // is object group acl
    bool m_is_og_acl;

    // is class_id enabled
    bool m_is_class_id_enabled;

    la_acl_impl() = default; // For serialization purposes only.
};
}

#endif // __LA_ACL_IMPL_H__
