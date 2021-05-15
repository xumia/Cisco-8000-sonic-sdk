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

#ifndef __LA_REMOTE_PORT_IMPL_H__
#define __LA_REMOTE_PORT_IMPL_H__

#include <memory>

#include "api/system/la_mac_port.h"
#include "api/system/la_remote_device.h"
#include "api/system/la_remote_port.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_remote_port_impl : public la_remote_port
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_remote_port_impl() = default;
    //////////////////////////////
public:
    explicit la_remote_port_impl(const la_device_impl_wptr& device);
    ~la_remote_port_impl() override;

    /// @brief Get the remote device revision of this port.
    ///
    /// @return #la_device_revision_e.
    la_device_revision_e get_remote_device_revision() const;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid,
                         la_remote_device* remote_device,
                         la_slice_id_t remote_slice_id,
                         la_ifg_id_t remote_ifg_id,
                         la_uint_t remote_first_serdes_id,
                         la_uint_t remote_last_serdes_id,
                         la_uint_t remote_first_pif_id,
                         la_uint_t remote_last_pif_id,
                         la_mac_port::port_speed_e remote_speed);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Inherited API-s
    const la_remote_device* get_remote_device() const override;
    la_slice_id_t get_remote_slice() const override;
    la_ifg_id_t get_remote_ifg() const override;
    la_uint_t get_remote_first_serdes_id() const override;
    size_t get_remote_num_of_serdes() const override;
    la_uint_t get_remote_first_pif_id() const override;
    size_t get_remote_num_of_pif() const override;
    la_status get_speed(la_mac_port::port_speed_e& out_speed) const override;

private:
    // Device this object is created on. This is not the remote device on which this port physically exists.
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // #la_remote_device object on which this port physically exists.
    la_remote_device_wptr m_remote_device;

    // Remote slice ID
    la_slice_id_t m_remote_slice;

    // Remote IFG ID
    la_ifg_id_t m_remote_ifg;

    // First SerDes  ID on the remote device
    la_uint_t m_remote_serdes_base;

    // Number of SerDes  elements on the remote device, currently unused
    size_t m_remote_serdes_count;

    // First PIF ID on the remote device
    la_uint_t m_remote_pif_base;

    // Number of PIF elements on the remote device, currently unused
    size_t m_remote_pif_count;

    // Port speed
    la_mac_port::port_speed_e m_speed;
};
}

/// @}

#endif // __LA_REMOTE_PORT_IMPL_H__
