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

#ifndef __LA_VRF_REDIRECT_DESTINATION_IMPL_H__
#define __LA_VRF_REDIRECT_DESTINATION_IMPL_H__

#include "hld_types.h"
#include "hld_utils.h"

namespace silicon_one
{

class la_vrf;
class la_vrf_impl;

class la_vrf_redirect_destination_impl : public la_vrf_redirect_destination
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_vrf_redirect_destination_impl() = default;
    //////////////////////////////
public:
    explicit la_vrf_redirect_destination_impl(const la_device_impl_wptr& device);
    ~la_vrf_redirect_destination_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, const la_vrf* vrf);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;

    const la_vrf* get_vrf() const override;

private:
    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    /// VRF, given by the user
    la_vrf_impl_wcptr m_vrf;
};

} // namespace silicon_one

#endif // __LA_VRF_REDIRECT_DESTINATION_IMPL_H__
