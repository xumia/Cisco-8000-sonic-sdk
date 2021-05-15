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

#ifndef __LEABA_LPM_COMMON_H__
#define __LEABA_LPM_COMMON_H__

#include "lld/ll_device.h"
#include "lpm_internal_types.h"

/// @file

namespace silicon_one
{

/// @brief Check if a key is contained in another key.
///
/// Key is contained (shorter) if its bits are the MSBs of the containing (longer) key.
///
/// @param[in]      key1     Key to check if contained in key2.
/// @param[in]      key2     Key to check if containing key1.
///
/// @return true if key1 is contained in key2, false otherwise.
static inline bool
is_contained(const lpm_key_t& key1, const lpm_key_t& key2)
{
    return key1 == key2.bits_from_msb(0, key1.get_width());
}

/// @brief Check if we are currently running with Pacific configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is Pacific
static inline bool
is_pacific_revision(const ll_device_sptr& ldevice)
{
    return ldevice->is_pacific();
}

/// @brief Check if we are currently running with Gibraltar configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is Gibraltar
static inline bool
is_gibraltar_revision(const ll_device_sptr& ldevice)
{
    return ldevice->is_gibraltar();
}

/// @brief Check if we are currently running with Asic4 configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is Asic4
static inline bool
is_asic4_revision(const ll_device_sptr& ldevice)
{
    return ldevice->is_asic4();
}

/// @brief Check if we are currently running with Asic5 configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is Asic5.
static inline bool
is_asic5_revision(const ll_device_sptr& ldevice)
{
    return ldevice->is_asic5();
}

/// @brief Check if we are currently running with asic3 configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is asic3
static inline bool
is_asic3_revision(const ll_device_sptr& ldevice)
{
    return ldevice->is_asic3();
}

/// @brief Check if we are currently running with AKPG configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is one of AKPG devices.
static inline bool
is_akpg_revision(const ll_device_sptr& ldevice)
{
    return ldevice->is_asic3() || ldevice->is_asic5() || ldevice->is_asic4();
}

/// @brief Check if we are currently running with Pacific or Gibraltar configuration.
///
/// @param[in]      ldevice  Pointer to the ll_device.
///
/// @return true if ll_device's revision is Pacific or Gibraltar.
static inline bool
is_pacific_or_gibraltar_revision(const ll_device_sptr& ldevice)
{
    return (ldevice->is_pacific() || ldevice->is_gibraltar());
}

/// @brief Get maximal length key that's contained in two keys.
///
/// @param[in]      key1     First key.
/// @param[in]      key2     Second key.
///
/// @return Common key.
lpm_key_t common_key(const lpm_key_t& key1, const lpm_key_t& key2);

/// @brief Less than operator for LPM key.
///
/// Compares width of two keys, if equal, compares value.
struct key_less_operator {
    bool operator()(const lpm_key_t& lkey, const lpm_key_t& rkey) const
    {
        size_t lwidth = lkey.get_width();
        size_t rwidth = rkey.get_width();

        if (lwidth != rwidth) {
            return lwidth < rwidth;
        }

        const uint8_t* lbyte_array = lkey.byte_array();
        const uint8_t* rbyte_array = rkey.byte_array();
        size_t width_in_bytes = lkey.get_width_in_bytes();

        for (size_t i = 0; i < width_in_bytes; i++) {
            if (lbyte_array[i] != rbyte_array[i]) {
                return lbyte_array[i] < rbyte_array[i];
            }
        }

        return false;
    }
};

/// @brief Check if bucket's HW index is in HBM.
///
/// @param[in]     level                Level of the requested bucket location.
/// @param[in]     hw_index             Bucket's HW index.
/// @param[in]     hbm_address_offset   HBM address offset.
///
/// @return true if index is in HBM, false otherwise.
static inline bool
is_location_in_hbm(lpm_level_e level, lpm_bucket_index_t hw_index, size_t hbm_address_offset)
{
    dassert_crit(hw_index >= 0);
    if (level != lpm_level_e::L2) {
        return false;
    }

    return (static_cast<size_t>(hw_index) >= hbm_address_offset);
}

/// @brief Get Complementary HW index.
///
/// @param[in]      hw_index        HW index to get complementary of.
///
/// @return Complementary HW index.
lpm_bucket_index_t comp_hw_index(lpm_bucket_index_t hw_index);

/// @brief Check if two indices constitute a pair.
///
/// @param[in]      hw_index1       First HW index.
/// @param[in]      hw_index2       Second HW index.
///
/// @return true if a pair, false otherwise.
bool are_hw_indices_paired(lpm_bucket_index_t hw_index1, lpm_bucket_index_t hw_index2);

/// @brief Check if key represents wide entry.
///
/// @param[in]      key             Key to check.
///
/// @return true if wide, false otherwise.
bool is_wide_key(const lpm_key_t& key);

/// @brief Encode LPM key by pusing 1'b0 to v4 IP bit 20 due to a hardware bug.
///
/// @prarm[in]      key       LPM key to be encoded.
///
/// @return Encoded LPM key.
lpm_key_t encode_lpm_key(const lpm_key_t& key);

/// @brief Decode LPM key by removing the additional 1'b0 in bit 20.
///
/// @prarm[in]      key       LPM key to be decoded.
///
/// @return Decoded LPM key.
lpm_key_t decode_lpm_key(const lpm_key_t& key);

} // namespace silicon_one

#endif
