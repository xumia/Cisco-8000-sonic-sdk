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

#ifndef __LA_COUNTER_SET_H__
#define __LA_COUNTER_SET_H__

/// @file
/// @brief Leaba Counter-Set API-s.
///
/// Defines API-s for managing a #silicon_one::la_counter_set object.
/// Counter sets are used for counting traffic (number of packets/bytes) associated with a specific interface or event.

#include "api/types/la_common_types.h"
#include "api/types/la_counter_or_meter_set.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_tm_types.h"
#include "common/la_status.h"

namespace silicon_one
{

/// @addtogroup COUNTERS
/// @{
///
/// @brief Counter set class.
///
/// @details A counter set supplies the storage for programmable counters. All counter types except
/// #silicon_one::la_counter_set::type_e::METER can be associated with different events in order to measure the packet/byte count
/// for these events, e.g. sub-interface received/transmitted traffic, traps, etc. A type-meter counter is associated
/// automatically with a meter.
///
/// For some cases, counting is differentiated to sub-counters, e.g PCP/L3 protocl values, QoS counters etc.
/// For these, a counter set of the relevant size needs to be created by the user.
///
/// A color-aware logical counter counts events grouping them by the packet #silicon_one::la_qos_color_e that triggered the event. A
/// color-aware logical counter has three gauges, each counting a specific color: green, yellow and red. A gauge measures both
/// number of packet and number of bytes.

class la_counter_set : public la_counter_or_meter_set
{

public:
    /// Available counter types.
    enum class type_e {
        INVALID,             ///< Typeless counter.
        DROP,                ///< Drop counter.
        QOS,                 ///< QoS counter.
        PORT,                ///< Port counter.
        VOQ,                 ///< VOQ counter.
        METER,               ///< A Meter associated counter.
        BFD,                 ///< A BFD session counter.
        ERSPAN,              ///< A ERSPAN session counter.
        MPLS_DECAP,          ///< MPLS Decap counter.
        VNI,                 ///< VNI counter.
        IP_TUNNEL,           ///< IP tunnel transit counter
        MCG,                 ///< MCG counter.
        MPLS_LABEL,          ///< MPLS LABEL counter.
        MPLS_PER_PROTOCOL,   ///< MPLS per protocol label counter.
        MPLS_TRAFFIC_MATRIX, ///< MPLS traffic matrix label counter.
        SECURITY_GROUP_CELL, ///< Security Group Cell counter.
    };

    /// @brief Returns the counter-set size.
    ///
    /// @retval The counter-set size.
    virtual size_t get_set_size() const = 0;

    /// @brief Retrieve a counter value.
    ///
    /// Counter values are periodically fetched from the device and updated in the counter set's storage.
    /// Reading a fresh counter value from the device has a performance penalty associated with it.
    ///
    /// @param[in]   counter_index        Index of the counter to read.
    /// @param[in]   force_update         Force update from HW counters.
    /// @param[in]   clear_on_read        Reset the counters after reading.
    /// @param[out]  out_packets          Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes            Reference to size_t to be populated with the bytes count.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EOUTOFRANGE  Index is out-of-range.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status read(size_t counter_index, bool force_update, bool clear_on_read, size_t& out_packets, size_t& out_bytes) = 0;

    /// @brief Retrieve a counter from from a specific Slice/IFG.
    ///
    ///
    /// @param[in]   ifg                  IFG to read from.
    /// @param[in]   counter_index        Index of the counter to read.
    /// @param[in]   force_update         Force update from HW counters.
    /// @param[in]   clear_on_read        Reset the counters after reading.
    /// @param[out]  out_packets          Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes            Reference to size_t to be populated with the bytes count.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EOUTOFRANGE  Illegal IFG.
    /// @retval    LA_STATUS_EOUTOFRANGE  Index is out-of-range.
    /// @retval    LA_STATUS_INVAL        Operation is not supported for the given counter type.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status read(la_slice_ifg ifg,
                           size_t counter_index,
                           bool force_update,
                           bool clear_on_read,
                           size_t& out_packets,
                           size_t& out_bytes)
        = 0;

    /// @brief Retrieve a counter value for counter set type VOQ, for a given slice.
    ///
    /// Counter values are periodically fetched from the device and updated in the counter set's storage.
    /// Reading a fresh counter value from the device has a performance penalty associated with it.
    ///
    /// @param[in]   slice_id             Slice to read from.
    /// @param[in]   counter_index        Index of the counter to read.
    /// @param[in]   force_update         Force update from HW counters.
    /// @param[in]   clear_on_read        Reset the counters after reading.
    /// @param[out]  out_packets          Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes            Reference to size_t to be populated with the bytes count.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EOUTOFRANGE  Index is out-of-range.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status read(la_slice_id_t slice_id,
                           size_t counter_index,
                           bool force_update,
                           bool clear_on_read,
                           size_t& out_packets,
                           size_t& out_bytes)
        = 0;

protected:
    ~la_counter_set() override = default;
};

} // namespace silicon_one

/// @}

#endif // __LA_COUNTER_SET_H__
