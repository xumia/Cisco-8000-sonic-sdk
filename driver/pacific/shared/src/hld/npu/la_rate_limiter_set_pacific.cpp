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

#include "la_rate_limiter_set_pacific.h"
#include "api_tracer.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
namespace silicon_one
{

la_rate_limiter_set_pacific::la_rate_limiter_set_pacific(la_device_impl_wptr device) : la_rate_limiter_set_base(device)
{
}

la_rate_limiter_set_pacific::~la_rate_limiter_set_pacific()
{
}

la_status
la_rate_limiter_set_pacific::get_pass_count(la_rate_limiters_packet_type_e packet_type,
                                            bool clear_on_read,
                                            size_t& out_packets,
                                            size_t& out_bytes) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_rate_limiter_set_pacific::get_drop_count(la_rate_limiters_packet_type_e packet_type,
                                            bool clear_on_read,
                                            size_t& out_packets,
                                            size_t& out_bytes) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
}
