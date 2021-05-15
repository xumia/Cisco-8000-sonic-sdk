// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_SYSTEM_PORT_H__
#define __LA_SYSTEM_PORT_H__

#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba System Port API-s.
///
/// Defines API-s for managing a system port #la_system_port.

/// @addtogroup PORT_SYSTEM
/// @{

namespace silicon_one
{

/// A system port is the source and destination of a switched packet in the system. It is used to define the processing type
/// required for received packets, initial QoS values, queuing, scheduling etc. A system port can be defined above a:
/// - Network interface (MAC port)
/// - PCI function/address (Control CPU)
/// - Internal Host (OAM)
/// - Recycle interface/channel
/// - Remote port
///
/// System ports defined above network, recycle and remote port interfaces can be aggregated to system port aggregate
/// (#silicon_one::la_spa_port). In this case some of the system port attributes are common to all aggregate members (e.g.
/// Processing
/// type and QoS) while other attributes (queue mapping) remain a system port attribute.
///
class la_system_port : public la_object
{
public:
    /// @brief Max delay watermark experienced by the sytem port.
    struct egress_max_delay_watermark {
        size_t max_delay;                           ///< Maximum delay experienced in nanoseconds.
        la_cgm_congestion_level_t congestion_level; ///< Congestion level at maximum delay.
    };

    /// @brief Max congestion watermark experienced by the sytem port.
    struct egress_max_congestion_watermark {
        la_cgm_congestion_level_t max_congestion_level; ///< Maximum congestion level experienced.
        size_t delay;                                   ///< Delay in nanoseconds at maximum congestion level.
    };

    /// @brief Get system port's Global ID.
    ///
    /// @return Global ID of system port.
    virtual la_system_port_gid_t get_gid() const = 0;

    /// @brief Get system port's port_extender_vid for extended mode.
    /// @param[out] out_port_extender_vid     Reference to this system port extended VID.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port vid retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    System port is not extended system port.
    virtual la_status get_port_extended_vid(la_port_extender_vid_t& out_port_extender_vid) const = 0;

    /// @brief Return system port scheduler attached to this port.
    ///
    /// A system port defined above local ports have a scheduler.
    /// A system port defined above a remote port doesn't have a scheduler.
    ///
    /// @return System port scheduler object, or nullptr if defined above a remote port.
    virtual la_system_port_scheduler* get_scheduler() const = 0;

    /// @brief Return VOQ set associated with this port.
    ///
    /// @return VOQ set associated with this port.
    virtual la_voq_set* get_voq_set() const = 0;

    /// @brief Attach a ECN capable transport VOQ set to the port.
    ///
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    ///
    /// @retval     LA_STATUS_EINVAL    nullptr argument provided or the VOQ set has different
    ///                                 device/slice/ifg than the system port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    virtual la_status set_ect_voq_set(la_voq_set* voq_set) = 0;

    /// @brief Return the ECN capable transport VOQ set associated with this port.
    ///
    /// @return ECN capable transport VOQ set associated with this port.
    virtual la_voq_set* get_ect_voq_set() const = 0;

    /// @brief Get size in bytes for the system port's output queue.
    ///
    /// @param[in]  oq_offset           Output queue offset.
    /// @param[out] out_size            Output queue size in bytes.
    ///
    /// @retval LA_STATUS_EOUTOFRANGE   Output queue offset is out of range.
    /// @retval LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval LA_STATUS_SUCCESS       Operation completed successfully
    virtual la_status get_output_queue_size(la_oq_id_t oq_offset, size_t& out_size) const = 0;

    /// @brief Get fcn enabled status for the system port's output queue. Returns true if enabled, false otherwise.
    ///
    /// @param[in]  oq_offset           Output queue offset.
    /// @param[out] out_fcn_enabled     Output queue's fcn enabled status, true if enabled, false otherwise.
    ///
    /// @retval LA_STATUS_EOUTOFRANGE   Output queue offset is out of range.
    /// @retval LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval LA_STATUS_SUCCESS       Operation completed successfully
    virtual la_status get_output_queue_fcn_enabled(la_oq_id_t oq_offset, bool& out_fcn_enabled) const = 0;

    /// @brief Get slice used by this system port.
    ///
    /// @return #la_slice_id_t.
    virtual la_slice_id_t get_slice() const = 0;

    /// @brief Get IFG used by this system port.
    ///
    /// @return #la_ifg_id_t.
    virtual la_ifg_id_t get_ifg() const = 0;

    /// @brief Get ID of first SerDes element.
    ///
    /// @deprecated This API is deprecated new API is get_base_pif.
    ///
    /// @return First SerDes ID.
    virtual la_uint_t get_base_serdes() const = 0;

    /// @brief Get ID of first PIF element.
    ///
    /// @return First PIF ID.
    virtual la_uint_t get_base_pif() const = 0;

    /// @brief Change the TC profile.
    ///
    /// @param[in]      tc_profile      TC profile to attach to this port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    TC profile is corrupted/nullptr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tc_profile(const la_tc_profile* tc_profile) = 0;

    /// @brief Return TC profile associated with this port.
    ///
    /// @return TC profile associated with this port.
    virtual const la_tc_profile* get_tc_profile() const = 0;

    ///@brief Return the underlying port associated to this system port.
    ///
    ///@return The underlying port associated to this system port.
    virtual const la_object* get_underlying_port() const = 0;

    /// @brief Get egress maximum congestion experienced watermark information.
    ///
    /// @param[in]      tc                              Priority queue to get congestion watermark from.
    /// #silicon_one::la_traffic_class_t
    /// @param[in]      clear_on_read                   Clear counter on read.
    ///
    /// @param[out]     out_cong_wm                     Maximum Congestion experienced watermark
    /// #silicon_one::la_system_port::egress_max_congestion_watermark
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STAUS_EINVAL                 Invalid tc provided.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       API is not implemented.
    virtual la_status read_egress_congestion_watermark(la_traffic_class_t tc,
                                                       bool clear_on_read,
                                                       egress_max_congestion_watermark& out_cong_wm)
        = 0;

    /// @brief Get egress maximum delay experienced watermark information.
    ///
    /// @param[in]      tc                              Priority queue to get delay watermark from. #silicon_one::la_traffic_class_t
    /// @param[in]      clear_on_read                   Clear counter on read.
    ///
    /// @param[out]     out_delay_wm                    Maximum Delay experienced watermark.
    /// #silicon_one::la_system_port::egress_max_delay_watermark
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STAUS_EINVAL                 Invalid tc provided.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       API is not implemented.
    virtual la_status read_egress_delay_watermark(la_traffic_class_t tc,
                                                  bool clear_on_read,
                                                  egress_max_delay_watermark& out_delay_wm)
        = 0;

protected:
    ~la_system_port() override = default;
};
}

/// @}

#endif
