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

#ifndef __LA_FORUS_DESTINATION_IMPL_H_
#define __LA_FORUS_DESTINATION_IMPL_H_

/// @file
/// @brief Leaba For-us destination API-s.
///
/// Defines API-s for managing and using a Layer 3 for-us destination.
///

#include "api/npu/la_forus_destination.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_forus_destination_impl : public la_forus_destination
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_forus_destination_impl() = default;
    //////////////////////////////
public:
    explicit la_forus_destination_impl(const la_device_impl_wptr& device);
    ~la_forus_destination_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid);
    la_status initialize(la_object_id_t oid, la_uint_t bincode);
    la_status destroy();

    // la_forus_destination API-s

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;

    la_uint_t get_bincode() const override;

private:
    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Object group code for destination
    la_uint_t m_bincode;
};
}

#endif // __LA_FORUS_DESTINATION_IMPL_H_
