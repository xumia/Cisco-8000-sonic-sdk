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

#ifndef __LA_RECYCLE_PORT_BASE_H__
#define __LA_RECYCLE_PORT_BASE_H__

#include <memory>

#include "api/system/la_mac_port.h"
#include "api/system/la_recycle_port.h"
#include "hld_types_fwd.h"

namespace silicon_one
{
class la_recycle_port_base : public la_recycle_port
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_recycle_port_base(const la_device_impl_wptr& device);
    ~la_recycle_port_base() override;

    // Object life-cycle API-s
    virtual la_status initialize(la_object_id_t oid, la_slice_id_t slice, la_ifg_id_t ifg) = 0;
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;
    la_interface_scheduler* get_scheduler() const override;

    // Inherited API-s
    la_slice_id_t get_slice() const override;
    la_ifg_id_t get_ifg() const override;

    la_status get_speed(la_mac_port::port_speed_e& out_speed) const;

protected:
    la_recycle_port_base() = default; // Needed for cereal

    virtual la_status set_slice_source_pif_entry() = 0;
    virtual la_status erase_slice_source_pif_entry() = 0;

    virtual la_status get_intf_id(la_uint_t& out_intf_id) const;

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Slice ID
    la_slice_id_t m_slice;

    // IFG ID
    la_ifg_id_t m_ifg;

    // Scheduler
    la_interface_scheduler_impl_wptr m_scheduler;

    // Port speed
    la_mac_port::port_speed_e m_speed;
};
}

/// @}

#endif // __LA_RECYCLE_PORT_BASE_H__
