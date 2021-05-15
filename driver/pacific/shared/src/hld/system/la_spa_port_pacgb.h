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

#ifndef __LA_SPA_PORT_PACGB_H__
#define __LA_SPA_PORT_PACGB_H__

#include "la_spa_port_base.h"

namespace silicon_one
{

class la_device_impl;
class la_system_port_base;

class la_spa_port_pacgb : public la_spa_port_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_spa_port_pacgb(const la_device_impl_wptr& device);
    ~la_spa_port_pacgb() override;

    la_status set_source_pif_table(npl_source_pif_hw_table_value_t value);
    la_status clear_source_pif() override;
    la_status add(const la_system_port* system_port) override;
    la_status remove(const la_system_port* system_port) override;

protected:
    la_spa_port_pacgb() = default; // Needed for cereal
    npl_source_pif_hw_table_value_t m_source_pif_hw_table_value;
    bool m_source_pif_hw_table_value_valid;

private:
    la_status configure_system_port_source_pif_table(const la_system_port* system_port, bool enabled) override;
};
}

/// @}

#endif
