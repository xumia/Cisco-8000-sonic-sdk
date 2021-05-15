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

#ifndef __LA_PUNT_INJECT_PORT_PACGB_H__
#define __LA_PUNT_INJECT_PORT_PACGB_H__

#include "la_punt_inject_port_base.h"

namespace silicon_one
{

class la_punt_inject_port_pacgb : public la_punt_inject_port_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    explicit la_punt_inject_port_pacgb(const la_device_impl_wptr& device);
    ~la_punt_inject_port_pacgb() override;

    destination_id get_destination_id(resolution_step_e prev_step) const override;
    la_system_port_wcptr get_actual_system_port() const override;
    slice_ifg_vec_t get_ifgs() const override;

protected:
    la_punt_inject_port_pacgb() = default;

private:
    la_status handle_punt_inject_over_mac_at_init() override;
    la_status handle_punt_inject_over_mac_at_destroy() override;
    //
    la_system_port_base_wcptr m_system_recycle_port;
};

} // namespace silicon_one

#endif // __LA_PUNT_INJECT_PORT_PACGB_H__
