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

//
#ifndef _LPM_SETTINGS_H_
#define _LPM_SETTINGS_H_

#include "lld/ll_device.h"

namespace silicon_one
{

struct lpm_settings {
    /// Members
    size_t num_cores;                     ///< Number of cores in logical LPM.
    size_t num_distributor_lines;         ///< Number of entries in the distributor TCAM.
    size_t distributor_row_width;         ///< The number of comparable bits in distributor TCAM.
    size_t l2_double_bucket_size;         ///< The size of a pair of L2 buckets.
    size_t l2_max_bucket_size;            ///< The maximum size of L2 bucket in on-die SRAM.
    size_t hbm_max_bucket_size;           ///< The maximum size of L2 bucket in HBM.
    size_t l1_double_bucket_size;         ///< The size of a pair of L1 buckets.
    size_t l1_max_sram_buckets;           ///< The maximum number of L1 buckets.
    size_t l1_max_bucket_size;            ///< The maximum size of L1 bucket.
    size_t max_bucket_depth;              ///< The number of comparable bits in bucket.
    size_t tcam_max_quad_entries;         ///< The maximum allowed number of quad entries in TCAM.
    size_t l2_buckets_per_sram_row;       ///< Number of L2 buckets in SRAM row.
    size_t l2_max_number_of_sram_buckets; ///< The maximum number of L2 buckets in on-die SRAM.
    size_t l2_max_number_of_hbm_buckets;  ///< The maximum number of L2 buckets in HBM.
    size_t tcam_num_banksets;             ///< The number of banksets in the core TCAM.
    size_t tcam_bank_size;                ///< The number of rows in TCAM bank.
    size_t tcam_single_width_key_weight;  ///< Weighted load on TCAM of a single width key.
    size_t tcam_double_width_key_weight;  ///< Weighted load on TCAM of a double width key.
    size_t tcam_quad_width_key_weight;    ///< Weighted load on TCAM of a quad width key.
    size_t trap_destination;              ///< Payload of destination to raise a trap.
    size_t l1_buckets_per_sram_row;       ///< Number of L1 buckets in SRAM row.
};

/// @brief Create a #silicon_one::lpm_settings object based on project.
lpm_settings create_lpm_settings(const ll_device_sptr& ldevice);
}

#endif
