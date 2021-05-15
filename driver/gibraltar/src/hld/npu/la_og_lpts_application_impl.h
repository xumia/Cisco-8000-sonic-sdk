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

#ifndef __LA_OG_LPTS_APPLICATION_IMPL_H__
#define __LA_OG_LPTS_APPLICATION_IMPL_H__

#include "api/npu/la_og_lpts_application.h"
#include "api/npu/la_pcl.h"
#include "api/types/la_common_types.h"
#include "api/types/la_lpts_types.h"
#include "api/types/la_object.h"
#include "hld_types_fwd.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_og_lpts_application_impl : public la_og_lpts_application
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_og_lpts_application_impl(const la_device_impl_wptr& device);
    ~la_og_lpts_application_impl() override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    virtual la_status initialize(la_object_id_t oid, const la_lpts_app_properties& properties, const la_pcl_wptr& src_pcl);
    virtual la_status destroy();

    // Inherited API-s
    virtual la_status get_properties(la_lpts_app_properties& out_properties) const override;
    virtual la_status get_src_pcl(la_pcl*& out_src_pcl) const override;
    virtual la_lpts_app_gid_t get_app_id() const override;

private:
    la_status app_id_alloc(la_lpts_app_gid_t& id);
    la_status app_id_free(la_lpts_app_gid_t id);
    la_status populate_lpts_og_application_table_entry();
    la_status destroy_lpts_og_application_table_entry();

    // Device this PCL belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid;

    // Application ID
    la_lpts_app_gid_t m_app_id;

    // Application properties
    la_lpts_app_properties m_app_properties;

    // Source PCL
    la_pcl_wptr m_src_pcl;

    la_og_lpts_application_impl() = default; // For serialization purposes only.
};
}

#endif // __LA_OG_LPTS_APPLICATION_IMPL_H__
