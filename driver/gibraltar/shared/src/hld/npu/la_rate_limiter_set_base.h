// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_RATE_LIMITER_SET_BASE_H__
#define __LA_RATE_LIMITER_SET_BASE_H__

#include "api/npu/la_rate_limiter_set.h"
#include "common/cereal_utils.h"
#include "hld_types_fwd.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"
#include "tm/tm_utils.h"

namespace silicon_one
{

class la_device_impl;

class la_rate_limiter_set_base : public la_rate_limiter_set
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_rate_limiter_set_base(la_device_impl_wptr device);
    ~la_rate_limiter_set_base() override;
    la_status destroy();

    virtual la_status initialize(la_object_id_t oid, const la_system_port_wptr& system_port);

    la_status get_system_port(la_system_port*& out_system_port) const override;

    la_status set_cir(la_rate_limiters_packet_type_e packet_type, la_rate_t cir) override;

    la_status get_cir(la_rate_limiters_packet_type_e packet_type, la_rate_t& out_cir) const override;

    virtual la_status get_pass_count(la_rate_limiters_packet_type_e packet_type,
                                     bool clear_on_read,
                                     size_t& out_packets,
                                     size_t& out_bytes) const override = 0;

    virtual la_status get_drop_count(la_rate_limiters_packet_type_e packet_type,
                                     bool clear_on_read,
                                     size_t& out_packets,
                                     size_t& out_bytes) const override = 0;

    // la_object API-s
    object_type_e type() const override;
    la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

protected:
    la_rate_limiter_set_base() = default; // Needed for cereal
    npl_meter_weight_t m_cir[(la_uint_t)la_rate_limiters_packet_type_e::LAST];
    la_system_port_base_wptr m_system_port;

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    la_status do_set_cir(la_rate_limiters_packet_type_e packet_type);

    // Programs RateLimiterShaperConfigurationTable entry
    la_status configure_rate_limiters_shaper_configuration_entry(la_slice_id_t slice_id,
                                                                 la_ifg_id_t ifg_id,
                                                                 la_uint_t port_id,
                                                                 la_rate_limiters_packet_type_e packet_type);

    la_rate_t user_rate_to_meter_rate(la_rate_t rate) const;

    la_rate_t meter_rate_to_user_rate(la_rate_t rate) const;

    npl_meter_weight_t la_rate_2_npl_meter_weight(la_rate_t rate, float shaper_max_rate) const;
    la_rate_t la_npl_meter_weight_2_rate(npl_meter_weight_t weight, float shaper_max_rate) const;
};

/// @}
}

#endif
