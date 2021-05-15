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

#ifndef __LA_PTP_HANDLER_BASE_H__
#define __LA_PTP_HANDLER_BASE_H__

#include "api/system/la_ptp_handler.h"

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

namespace silicon_one
{

class la_device_impl;

class la_ptp_handler_base : public la_ptp_handler
{
    // CEREAL
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_ptp_handler_base(const la_device_impl_wptr& device);
    ~la_ptp_handler_base();

    virtual la_status enable_load_event_generation(bool enabled) override;

    virtual la_status set_pad_config(ptp_pads_config config) const override;
    virtual la_status get_pad_config(ptp_pads_config& out_config) const override;

    virtual la_status set_load_time_offset(la_uint64_t offset) const override;
    virtual la_status get_load_time_offset(la_uint64_t& out_offset) const override;

    virtual la_status adjust_device_time(ptp_sw_tuning_config adjustment) const override;

    virtual la_status load_new_time(ptp_time load_time) const override;
    virtual la_status capture_time(ptp_time& out_load_time) const override;

    virtual la_status load_new_time_unit(ptp_time_unit time_unit) const override;
    virtual la_status get_time_unit(ptp_time_unit& out_time_unit) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_device API's
    virtual la_status initialize(la_object_id_t oid);
    virtual la_status destroy();

protected:
    enum fte_commands {
        NOP,
        SW_TUNING,
        LOAD_NEW_TIME,
        LOAD_NEW_TIME_UNIT,
        CAPTURE_TIME,
    };

    virtual la_status send_cpu_device_time_load() const;

    // when set to true, CPU will mimic DEVICE_TIME_LOAD signal to FTE
    bool m_use_debug_device_time_load;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    la_device_impl_wptr m_device;

    ll_device_sptr m_ll_device;

    la_ptp_handler_base() = default;
};
}

/// @}

#endif
