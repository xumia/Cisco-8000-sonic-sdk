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

#ifndef __LA_REMOTE_DEVICE_IMPL_H__
#define __LA_REMOTE_DEVICE_IMPL_H__

#include <memory>

#include "api/system/la_remote_device.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_remote_device_base : public la_remote_device
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_remote_device_base() = default;
    //////////////////////////////
public:
    explicit la_remote_device_base(const la_device_impl_wptr& device);
    ~la_remote_device_base() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_device_id_t remote_device_id, la_device_revision_e remote_device_revision);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Inherited API-s
    la_device_id_t get_remote_device_id() const override;
    la_device_revision_e get_remote_device_revision() const override;

private:
    // Device which this object was created on. This is not the remote device.
    la_device_impl_wptr m_device;

    // Object ID.
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // The remote device ID.
    la_device_id_t m_remote_device_id;

    // Remote device revision.
    la_device_revision_e m_remote_device_revision;
};
}

/// @}

#endif // __LA_REMOTE_DEVICE_IMPL_H__
