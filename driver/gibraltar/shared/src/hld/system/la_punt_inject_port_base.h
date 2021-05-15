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

#ifndef __LA_PUNT_INJECT_PORT_BASE_H__
#define __LA_PUNT_INJECT_PORT_BASE_H__

#include "api/system/la_punt_inject_port.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "nplapi/nplapi_tables.h"
#include "npu/resolution_utils.h"

#include "system/la_system_port_base.h"

namespace silicon_one
{

class la_punt_inject_port_base : public la_punt_inject_port
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_punt_inject_port_base(const la_device_impl_wptr& device);
    ~la_punt_inject_port_base() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_system_port_base* system_port, la_mac_addr_t mac_addr);
    la_status destroy();

    // Inherited API-s
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Implementation API-s
    /// @brief Get system port associated with this Punt/Inject port.
    ///
    /// @return la_system_port_base* for this Punt/Inject port.\n
    ///         nullptr if not initialized.
    const la_system_port* get_system_port() const override;

    virtual destination_id get_destination_id(resolution_step_e prev_step) const = 0;
    virtual la_system_port_wcptr get_actual_system_port() const = 0;
    virtual slice_ifg_vec_t get_ifgs() const = 0;

protected:
    la_punt_inject_port_base() = default;
    virtual la_status set_slice_source_pif_entry(la_slice_id_t slice) = 0;
    la_status erase_slice_source_pif_entry(la_slice_id_t slice);
    virtual la_status handle_punt_inject_over_mac_at_init() = 0;
    virtual la_status handle_punt_inject_over_mac_at_destroy() = 0;

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // System port
    la_system_port_base_wptr m_system_port;

    // MAC associated with the port
    la_mac_addr_t m_mac_addr;
};
}

/// @}

#endif // __LA_PUNT_INJECT_PORT_BASE_H__
