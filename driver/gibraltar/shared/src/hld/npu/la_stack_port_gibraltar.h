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

#ifndef __LA_STACK_PORT_GIBRALTAR_H__
#define __LA_STACK_PORT_GIBRALTAR_H__

#include "la_stack_port_base.h"

namespace silicon_one
{

class la_stack_port_gibraltar : public la_stack_port_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_stack_port_gibraltar(const la_device_impl_wptr& device);
    ~la_stack_port_gibraltar() override;

private:
    la_stack_port_gibraltar() = default; // Needed for serialization.
    la_status set_source_pif_entry() override;
    npl_initial_pd_nw_rx_data_t populate_initial_pd_nw_rx_data() const override;
    la_status set_peer_device_reachable_stack_port_destination() override;
};
}
/// @}

#endif
