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

#ifndef __DUMMY_SERDES_DEVICE_HANDLER_BASE_H__
#define __DUMMY_SERDES_DEVICE_HANDLER_BASE_H__

#include "hld_types_fwd.h"
#include "system/serdes_device_handler.h"

namespace silicon_one
{

class la_device_impl;

class dummy_serdes_device_handler_base : public serdes_device_handler
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    dummy_serdes_device_handler_base() = default;
    //////////////////////////////
public:
    dummy_serdes_device_handler_base(const la_device_impl_wptr& device);
    ~dummy_serdes_device_handler_base(){};

    la_status init(bool reconnect) override;

    la_status destroy() override;

    la_status create_serdes_group_handler(la_slice_id_t slice_id,
                                          la_ifg_id_t ifg_id,
                                          la_uint_t serdes_base_id,
                                          size_t serdes_count,
                                          la_mac_port::port_speed_e speed,
                                          la_mac_port::port_speed_e serdes_speed,
                                          la_slice_mode_e serdes_slice_mode,
                                          serdes_handler*& out_serdes_handler) override;

    la_status get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) override;

    la_status get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) override;

    la_status mbist_activate(bool repair) override;

    la_status mbist_clear() override;

    la_status mbist_read(bool report_failures, size_t& total_tested, size_t& total_pass, size_t& total_failed) override;

    la_status get_serdes_addr(la_slice_id_t slice,
                              la_ifg_id_t ifg,
                              la_uint_t serdes_idx,
                              la_serdes_direction_e direction,
                              uint32_t& out_serdes_addr) override;

    la_status get_component_health(la_component_health_vec_t& out_component_health) const override;

    const la_device_impl* get_device() const
    {
        return m_device.get();
    }

private:
    la_device_impl_wptr m_device;
    bool m_handler_initilized;
};
}

#endif // __DUMMY_SERDES_DEVICE_HANDLER_BASE_H__
