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

#ifndef __LA_MAC_PORT_PACGB_H__
#define __LA_MAC_PORT_PACGB_H__

#include "system/la_mac_port_base.h"

namespace silicon_one
{

class la_mac_port_pacgb : public la_mac_port_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    ~la_mac_port_pacgb() override;

protected:
    explicit la_mac_port_pacgb(const la_device_impl_wptr& device);
    la_mac_port_pacgb() = default; // Needed for cereal
    la_status configure_serdes_source_pif_table_extended_mac() override;
    la_status erase_serdes_source_pif_table_extended_mac() override;

    la_status initialize_pif() override;
};
}

#endif // __LA_MAC_PORT_PACGB_H__
