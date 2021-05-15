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

#ifndef __LA_VOQ_CGM_EVICTED_PROFILE_IMPL_H__
#define __LA_VOQ_CGM_EVICTED_PROFILE_IMPL_H__

#include "api/cgm/la_voq_cgm_evicted_profile.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

enum class limit_type_e;

class la_voq_cgm_evicted_profile_impl : public la_voq_cgm_evicted_profile
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_voq_cgm_evicted_profile_impl(const la_device_impl_wptr& device);
    virtual ~la_voq_cgm_evicted_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, uint64_t voq_cgm_evicted_profile_index);
    la_status destroy();

    // Inherited API-s
    la_status set_sms_evicted_buffers_drop_behavior(const la_voq_sms_evicted_buffers_key& key,
                                                    const la_voq_sms_evicted_buffers_drop_val& val) override;
    la_status get_sms_evicted_buffers_drop_behavior(const la_voq_sms_evicted_buffers_key& key,
                                                    la_voq_sms_evicted_buffers_drop_val& out_val) const override;
    la_status set_default_behavior() override;

    // la_object API-s
    virtual object_type_e type() const override;
    virtual const la_device* get_device() const override;
    virtual la_object_id_t oid() const override;
    virtual std::string to_string() const override;

    /// @brief Get profile ID.
    ///
    /// @return Profile ID in hardware.
    uint64_t get_id() const;

    // Helper APIs.
    la_status do_set_default_behavior();

private:
    // Helper functions.
    la_status ensure_sms_evicted_buffers_key_valid(const la_voq_sms_evicted_buffers_key& key) const;
    la_status do_set_sms_evicted_buffers_drop_behavior(la_quantization_region_t evicted_buffers_region,
                                                       la_quantization_region_t sms_voqs_total_bytes_region,
                                                       la_quantization_region_t sms_bytes_region,
                                                       la_qos_color_e drop_color_level);

    // Device this VOQ profile belongs to
    la_device_impl_wptr m_device;

    // Object index
    uint64_t m_index;

    // Object ID
    la_object_id_t m_oid;

    la_voq_cgm_evicted_profile_impl() = default; // For serialization only.
};

} // silicon_one

#endif
