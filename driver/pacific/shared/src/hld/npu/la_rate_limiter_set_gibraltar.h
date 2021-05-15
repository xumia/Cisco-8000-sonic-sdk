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

#ifndef __LA_RATE_LIMITER_SET_GIBRALTAR_H__
#define __LA_RATE_LIMITER_SET_GIBRALTAR_H__

#include "la_rate_limiter_set_base.h"

namespace silicon_one
{

class la_rate_limiter_set_gibraltar : public la_rate_limiter_set_base
{
public:
    explicit la_rate_limiter_set_gibraltar(la_device_impl_wptr device);
    la_rate_limiter_set_gibraltar() = default; // Needed for cereal
    ~la_rate_limiter_set_gibraltar() override;

    la_status get_pass_count(la_rate_limiters_packet_type_e packet_type,
                             bool clear_on_read,
                             size_t& out_packets,
                             size_t& out_bytes) const override;

    la_status get_drop_count(la_rate_limiters_packet_type_e packet_type,
                             bool clear_on_read,
                             size_t& out_packets,
                             size_t& out_bytes) const override;
};
}

#endif
