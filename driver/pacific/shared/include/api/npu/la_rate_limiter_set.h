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

#ifndef __LA_RATE_LIMITER_SET_H__
#define __LA_RATE_LIMITER_SET_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Rate Limiter Set API-s.
///
/// Defines API-s for managing set of rate limiters. A rate limiter is used to limit traffic for a packet type.

namespace silicon_one
{

class la_rate_limiter_set : public la_object
{
public:
    /// @brief Get the system port for rate limiters object.
    ///
    /// @param[out]  out_system_port        System port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_system_port(la_system_port*& out_system_port) const = 0;

    /// @brief Set the Committed Information Rate for the packet type
    ///
    /// The committed information rate defines the rate at which tokens fill the committed bucket, in bps for the specified
    /// packet type.
    /// In the Pacific, the rate is implemented with variable precision.
    ///
    /// @param[in]  packet_type   Packet type
    /// @param[in]  cir           Committed information rate in bps
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL     Invalid committed information rate.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    ///
    virtual la_status set_cir(la_rate_limiters_packet_type_e packet_type, la_rate_t cir) = 0;

    /// @brief Gets the Committed Information Rate for the packet type
    ///
    /// @param[in]  packet_type   Packet type
    /// @param[out] out_cir       Committed information rate in bps
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    ///
    virtual la_status get_cir(la_rate_limiters_packet_type_e packet_type, la_rate_t& out_cir) const = 0;

    /// @brief Gets the pass packet and pass byte count for rate limiter set for a given packet type
    ///
    /// @param[in]   packet_type     Packet type
    /// @param[in]   clear_on_read   Reset the counters after reading.
    /// @param[out]  out_packets     Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes       Reference to size_t to be populated with the bytes count.
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    ///
    virtual la_status get_pass_count(la_rate_limiters_packet_type_e packet_type,
                                     bool clear_on_read,
                                     size_t& out_packets,
                                     size_t& out_bytes) const = 0;

    /// @brief Gets the drop packet and drop byte count for rate limiter set for a given packet type
    ///
    /// @param[in]   packet_type      Packet type
    /// @param[in]   clear_on_read    Reset the counters after reading.
    /// @param[out]  out_packets      Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes        Reference to size_t to be populated with the bytes count.
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    ///
    virtual la_status get_drop_count(la_rate_limiters_packet_type_e packet_type,
                                     bool clear_on_read,
                                     size_t& out_packets,
                                     size_t& out_bytes) const = 0;

protected:
    ~la_rate_limiter_set() override = default;
};
}

#endif
