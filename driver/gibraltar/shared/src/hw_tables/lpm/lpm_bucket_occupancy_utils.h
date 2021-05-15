// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LPM_BUCKET_OCCUPANCY_UTILS_H__
#define __LEABA_LPM_BUCKET_OCCUPANCY_UTILS_H__

#include "common/math_utils.h"
#include "lpm_bucket.h"
#include "lpm_common.h"

/// @file

namespace silicon_one
{

class ll_device;

namespace lpm_bucket_occupancy_utils
{

/// @brief Get occupancy of the given bucket.
///
/// Return #silicon_one::lpm_bucket::occupancy_data containing number of single/double/total entries.
///
/// @param[in]      bucket                      Bucket to calculate its occupancy.
/// @param[in]      double_entry_threshold      Threshold between single and double entries.
/// @param[in]      check_double_entries        Optimization indicating if the bucket support double entries to skip the check.
///
/// @return Occupacy data.
static inline lpm_bucket::occupancy_data
get_bucket_occupancy(const lpm_bucket* bucket, size_t double_entry_threshold, bool check_double_entries)
{
    lpm_bucket::occupancy_data ret;
    ret.total_entries = bucket->size();
    if (check_double_entries) {
        size_t double_entries = 0;
        const lpm_key_payload_vec& entries = bucket->get_entries();
        for (const auto& entry : entries) {
            if (double_entry_threshold < entry.key.get_width()) {
                double_entries++;
            }
        }

        ret.double_entries = double_entries;
    }

    ret.single_entries = ret.total_entries - ret.double_entries;
    return ret;
}

/// @brief Get the HW occupancy of the logical occupancy.
///
/// Based on project and level, it returns the actual required HW space to write bucket with the given occupancy.
///
/// @param[in]      ldevice                     ll_device containing the HW revision.
/// @param[in]      level                       Level of the bucket with the given occupancy.
/// @param[in]      occupancy                   Occupancy containing number of single/double entries.
///
/// @return HW space required for the occupacy data.
static inline lpm_bucket::occupancy_data
logical_occupancy_to_hardware_occupancy(const ll_device_sptr& ldevice, lpm_level_e level, lpm_bucket::occupancy_data occupancy)
{
    // For L2 in all projects excluding Pacific we count occupancy in "group" units.
    if ((level != lpm_level_e::L2) || (is_pacific_revision(ldevice))) {
        return occupancy;
    }

    occupancy.single_entries = round_up(occupancy.single_entries, 2);
    return occupancy;
}

/// @brief Get the shared resource usage in the HW.
///
/// Based on project and level, it returns the actual required HW space to write bucket with the given occupancy.
/// For L2 in Pacific when HBM is disabled we use different call at #silicon_one::lpm_hw_index_doubles_allocator_pacific.
///
/// @param[in]      ldevice                     ll_device containing the HW revision.
/// @param[in]      level                       Level of the bucket with the given occupancy.
/// @param[in]      occupancy                   Occupancy containing number of single/double entries.
///
/// @return HW space required for the occupacy data.
static inline size_t
logical_occupancy_to_hw_resource(const ll_device_sptr& ldevice, lpm_level_e level, lpm_bucket::occupancy_data occupancy)
{
    if ((level == lpm_level_e::L1) || (is_pacific_revision(ldevice))) {
        return occupancy.single_entries;
    }

    size_t ret = div_round_up(occupancy.single_entries, 2) + occupancy.double_entries;
    return ret;
}

/// @brief Get the HW occupancy of a bucket.
///
/// Based on project, it returns the actual required HW space to write the given bucket.
///
/// @param[in]      ldevice                     ll_device containing the HW revision.
/// @param[in]      bucket                      Bucket to calculate its occupancy.
/// @param[in]      double_entry_threshold      Threshold between single and double entries.
/// @param[in]      check_double_entries        Optimization indicating if the bucket support double entries to skip the check.
///
/// @return HW space required for the bucket.
static inline lpm_bucket::occupancy_data
get_bucket_hw_occupancy(const ll_device_sptr& ldevice,
                        const lpm_bucket* bucket,
                        size_t double_entry_threshold,
                        bool check_double_entries)
{
    lpm_bucket::occupancy_data logical_occupancy = get_bucket_occupancy(bucket, double_entry_threshold, check_double_entries);
    lpm_level_e bucket_level = bucket->get_level();
    lpm_bucket::occupancy_data ret = logical_occupancy_to_hardware_occupancy(ldevice, bucket_level, logical_occupancy);
    return ret;
}

} // namespace lpm_bucket_occupancy_utils
} // namespace silicon_one

#endif
