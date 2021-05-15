// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_VOQ_SET_H__
#define __LA_VOQ_SET_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Virtual Output Queue API-s.
///
/// Defines API-s for managing a Virtual Output Queue's objects.

/// @addtogroup TM_VOQ
/// @{

namespace silicon_one
{

/// @brief      Virtual Output Queue Set.
///
/// @details    A VOQ set (Virtual Output Queue set) provides the basic scheduling group for packets.
///             Each VOQ in the set maps to a single VSC (Virtual Scheduler Connection), and a single output queue.

class la_voq_set : public la_object
{
public:
    /// @brief VOQ set state.
    enum class state_e {
        ACTIVE,   ///< VOQ-s are active.
        DROPPING, ///< VOQ-s are dropping incoming and outgoing traffic.
    };

    /// VOQ counter types
    enum class voq_counter_type_e {
        ENQUEUED = 0, ///< Enqueued
        DROPPED,      ///< Dropped
        BOTH,         ///< Both
    };

    /// @brief VOQ size.
    struct voq_size {
        size_t sms_bytes;  ///< Size in bytes of the VOQ in the SMS.
        size_t hbm_blocks; ///< Size in blocks of the VOQ in the HBM.
        size_t hbm_bytes;  ///< Size in bytes of the VOQ in the HBM.
    };

    /// @brief Return the destination device.
    virtual la_device_id_t get_destination_device() const = 0;

    /// @brief Return the destination slice.
    virtual la_slice_id_t get_destination_slice() const = 0;

    /// @brief Return the destination IFG.
    virtual la_ifg_id_t get_destination_ifg() const = 0;

    /// @brief Return the VOQ ID.
    virtual la_voq_gid_t get_base_voq_id() const = 0;

    /// @brief Return the number of VOQs in the set.
    virtual size_t get_set_size() const = 0;

    /// @brief Return VSC vector.
    virtual la_vsc_gid_vec_t get_base_vsc_vec() const = 0;

    /// @brief Get base VSC.
    ///
    /// @param[in]  slice               Slice.
    /// @param[out] out_base_vsc        Base VSC on the given slice.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EINVAL       Invalid slice.
    virtual la_status get_base_vsc(la_slice_id_t slice, la_vsc_gid_t& out_base_vsc) const = 0;

    /// @brief Set the congestion-management (CGM) profile of the given member.
    ///
    /// @param[in] voq_index            Index of the VOQ which will be associated with the given profile.
    /// @param[in] cgm_profile          CGM profile.
    ///
    /// @note A CGM profile cannot be shared between both UC and MC VOQs. A MC VOQ does not support CGM profiles that evict to HBM.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EBUSY        The CGM profile is already attached to a different UC/MC VOQ kind.
    /// @retval  LA_STATUS_EINVAL       The CGM profile configuration is unsupported by this VOQ.
    /// @retval  LA_STATUS_EOUTOFRANGE  The given index is out of set's size.
    virtual la_status set_cgm_profile(size_t voq_index, la_voq_cgm_profile* cgm_profile) = 0;

    /// @brief Get the congestion-management (CGM) profile of the given member.
    ///
    /// @param[in]  voq_index           Index of the VOQ which will be associated with the given profile.
    /// @param[out] out_cgm_profile     CGM profile to populate.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE  The given index is out of set's size.
    virtual la_status get_cgm_profile(size_t voq_index, la_voq_cgm_profile*& out_cgm_profile) const = 0;

    /// @brief Flush all VOQ-s in this VOQ set.
    ///
    /// @param[in]  block               Block until flush completes if true; perform background flush if false.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @see #silicon_one::la_voq_set::is_empty.
    virtual la_status flush(bool block) = 0;

    /// @brief Flush a VOQ index in this VOQ set.
    ///
    /// @param[in]  voq_index           Index of the VOQ which will be flushed.
    /// @param[in]  block               Block until flush completes if true; perform background flush if false.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE  Invalid index.
    /// @retval  LA_STATUS_EINVAL       Invalid current state of the queue.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @see #silicon_one::la_voq_set::is_empty.
    virtual la_status flush(size_t voq_index, bool block) = 0;

    /// @brief Retrieve counter for packets flushed via flush API.
    /// Can only count packets flushed in blocking mode.
    ///
    /// @param[in]   clear_on_read      Reset the counters after reading.
    /// @param[out]  out_packets        Number of packets flushed.
    /// @param[out]  out_bytes          Number of bytes flushed.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occured.
    virtual la_status read_flush_counter(bool clear_on_read, la_uint64_t& out_packets, la_uint64_t& out_bytes) = 0;

    /// @brief Retrieve counter for packets flushed via per-index flush API.
    /// Can only count packets flushed in blocking mode.
    ///
    /// @param[in]   voq_index          Index of the VOQ to read counter for.
    /// @param[in]   clear_on_read      Reset the counters after reading.
    /// @param[out]  out_packets        Number of packets flushed.
    /// @param[out]  out_bytes          Number of bytes flushed.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occured.
    virtual la_status read_flush_counter(size_t voq_index, bool clear_on_read, la_uint64_t& out_packets, la_uint64_t& out_bytes)
        = 0;

    /// @brief Restore a VOQ index in this VOQ set.
    /// Restore a queue state if a flush attempt was not successful.
    /// If the API is called after a successful flush, then it will return success.
    ///
    /// @param[in]  voq_index           Index of the VOQ to be restored.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE  Invalid index.
    /// @retval  LA_STATUS_EINVAL       Invalid current state of the queue.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @see #silicon_one::la_voq_set::flush.
    virtual la_status restore(size_t voq_index) = 0;

    /// @brief Check if all VOQ-s are empty.
    ///
    /// @param[out] out_empty           True,if there is any traffic in one of the VOQs, false otherwise.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @see #silicon_one::la_voq_set::flush
    virtual la_status is_empty(bool& out_empty) const = 0;

    /// @brief Check if a specific VOQ is empty.
    ///
    /// @param[in]  voq_index           Index of the VOQ to check.
    /// @param[out] out_empty           True,if there is any traffic in the VOQ, false otherwise.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @see #silicon_one::la_voq_set::flush
    virtual la_status is_empty(size_t voq_index, bool& out_empty) const = 0;

    /// @brief Check size of a specific VOQ.
    ///
    /// @param[in]  voq_index           Index of the VOQ to read its size.
    /// @param[in]  slice               The Slice hosting the VOQ.
    /// @param[out] out_size            Struct describing the VOQ size.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE  The given index is out of set's size.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @note If the VOQ has moved between SMS and HBM during this call the result is undefined.
    virtual la_status get_voq_size(size_t voq_index, la_slice_id_t slice, voq_size& out_size) const = 0;

    /// @brief Check age of a specific VOQ.
    ///
    /// @param[in]  voq_index           Index of the VOQ to read its size.
    /// @param[in]  slice               The Slice hosting the VOQ.
    /// @param[out] out_age             VOQ age to populate.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE  The given index is out of set's size.
    /// @retval  LA_STATUS_EUNKNOWN     An unknown error occurred.
    ///
    /// @note If the VOQ has moved between SMS and HBM during this call the result is undefined.
    virtual la_status get_voq_age(size_t voq_index, la_slice_id_t slice, size_t& out_age) const = 0;

    /// @brief Set the priority of traffic from the specified VOQ when traversing the fabric.
    ///
    /// @deprecated This API is deprecated.
    ///
    /// @param[in]  voq_index           Index of the VOQ which will be associated with the given profile.
    /// @param[in]  is_high_priority    true if high priority; false otherwise.
    ///
    /// @retval  LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE  The given index is out of set's size.
    virtual la_status set_fabric_priority(size_t voq_index, bool is_high_priority) = 0;

    /// @brief Get the priority of traffic from the specified VOQ when traversing the fabric.
    ///
    /// @deprecated This API is deprecated.
    ///
    /// @param[in]  voq_index               Index of the VOQ which will be associated with the given profile.
    /// @param[out] out_is_high_priority    bool to be populated with true if high priority; FALSE otherwise.
    ///
    /// @retval  LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval  LA_STATUS_EOUTOFRANGE      The given index is out of set's size.
    virtual la_status get_fabric_priority(size_t voq_index, bool& out_is_high_priority) const = 0;

    /// @brief Set the VOQ state to active/dropping.
    ///
    /// When voq_set is in dropping state all VOQ-s drop their traffic: both incoming packets and outgoing packets.
    ///
    /// @param[in]  state                   VOQ state to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_state(state_e state) = 0;

    /// @brief Set the VOQ state for a single index to active/dropping.
    ///
    /// When a VOQ index in a voq_set is in dropping state, that index will drop their traffic: both incoming packets and
    /// outgoing packets. Note that this API can be called only when the state of the entire voq_set is active.
    ///
    /// @param[in]  voq_index               Index of the VOQ to set.
    /// @param[in]  state                   VOQ state to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Invalid index.
    /// @retval     LA_STATUS_EBUSY         Invalid state of the voq_set or index.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_state(size_t voq_index, state_e state) = 0;

    /// @brief Get the VOQ state.
    ///
    /// @param[out] out_state               VOQ state of the VOQ index.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Invalid index.
    virtual la_status get_state(state_e& out_state) const = 0;

    /// @brief Get the state for a VOQ index.
    ///
    /// @param[in]  voq_index               Index of the VOQ.
    /// @param[out] out_state               VOQ-s state.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_state(size_t voq_index, state_e& out_state) const = 0;

    /// @brief Set counter for the VOQ-set.
    ///
    /// The VOQ-s can be counted in groups of 1/2/4/8 VOQ-s. Same counter will count all the VOQ members of a certain group.
    ///
    /// @param[in]  type                      VOQ counter type.
    /// @param[in]  group_size                # of VOQs in a group.
    /// @param[in]  counter                   Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS Counter is on a different device.
    /// @retval     LA_STATUS_EBUSY           If a counter is already associated with the VOQ set.
    /// @retval     LA_STATUS_EINVAL          Invalid group size.
    /// @retval     LA_STATUS_EINVAL          Invalid set size, group size combination.
    /// @retval     LA_STATUS_EINVAL          Group size specified does not match the group size for existing VOQ set(s) in block of
    /// 64 VOQs.
    /// @retval     LA_STATUS_EINVAL          When clearing the counter if invoked multiple times for same VOQ set.
    virtual la_status set_counter(voq_counter_type_e type, size_t group_size, la_counter_set* counter) = 0;

    /// @brief Get VOQ-set counter.
    ///
    /// @param[out]  out_voq_counter_type VOQ counter type.
    /// @param[out]  out_counter          Counter object to populate.
    /// @param[out]  out_group_size       # of VOQs in a group.
    ///
    /// @retval      LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval      LA_STATUS_ENOTFOUND No counter is set.
    virtual la_status get_counter(voq_counter_type_e& out_voq_counter_type,
                                  size_t& out_group_size,
                                  la_counter_set*& out_counter) const = 0;

protected:
    ~la_voq_set() override = default;
}; // class la_voq_set

} // namespace silicon_one

/// @}

#endif // __LA_VOQ_SET_H__
