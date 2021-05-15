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

#ifndef __LA_FLOW_CACHE_HANDLER_H__
#define __LA_FLOW_CACHE_HANDLER_H__

/// @file
/// @brief Leaba Flow Cache Handler API-s.
///
/// Defines API-s for managing and using flow cache.
///

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_system_types.h"

/// @addtogroup SYSTEM
/// @{

namespace silicon_one
{

/// @brief An Flow cache handler.
///
/// @details An Flow cache handler used to control and manage flow cache.
///
class la_flow_cache_handler : public la_object
{
public:
    /// @brief Flow cache counters.
    struct flow_cache_counters {
        la_uint64_t hit_counter;  ///< Counts the amount of packets which hit the flow cache.
        la_uint64_t miss_counter; ///< Counts the amount of packets which misses the flow cache (reasons can be: first packet of
                                  /// specific flow, flow cache entry is erased).
        la_uint64_t dont_use_cache_counter; ///< Counts the amount of packets which didn't use the cache (this specific flow is not
                                            /// cached at all).
    };

    /// @brief Check whether a flow cache is enabled.
    ///
    /// @param[out] out_enabled         True if flow cache is enabled; false otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_flow_cache_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable flow cache.
    ///
    /// @param[in]  enabled            True if flow cache should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_flow_cache_enabled(bool enabled) = 0;

    /// @brief Get flow cache counters.
    ///
    /// @param[out] out_flow_cache_counters     Contains flow cache counters values.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_flow_cache_counters(la_flow_cache_handler::flow_cache_counters& out_flow_cache_counters) const = 0;

protected:
    ~la_flow_cache_handler() override = default;
};
}

/// @}

#endif // __LA_FLOW_CACHE_HANDLER_H__
