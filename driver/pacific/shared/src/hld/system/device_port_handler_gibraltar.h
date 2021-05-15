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

#ifndef __DEVICE_PORT_HANDLER_GIBRALTAR_H__
#define __DEVICE_PORT_HANDLER_GIBRALTAR_H__

#include "api/system/la_device.h"
#include "api/system/la_mac_port.h"
#include "hld_types_fwd.h"
#include "system/device_model_types.h"
#include "system/device_port_handler_base.h"
#include "system/serdes_handler.h"
#include <unordered_map>

namespace silicon_one
{

class device_port_handler_gibraltar : public device_port_handler_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    device_port_handler_gibraltar() = default; // Needed for cereal
public:
    device_port_handler_gibraltar(const la_device_impl_wptr& device);
    virtual ~device_port_handler_gibraltar();

    void initialize() override;
    const std::vector<la_mac_port::port_speed_e> get_supported_speeds() override;
    la_status create_mac_pool(size_t serdes_base_id, mac_pool_port_sptr& mac_pool_port) override;

    la_status set_fabric_mode(la_device::fabric_mac_ports_mode_e fabric_mac_ports_mode) override;
};
}

#endif // __DEVICE_PORT_HANDLER_GIBRALTAR_H__
