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

#ifndef __LEABA_LPM_BUCKETING_DATA_H__
#define __LEABA_LPM_BUCKETING_DATA_H__

#include "lpm_internal_types.h"

/// @file
/// @brief Bucketing data struct.

namespace silicon_one
{

/// @brief Bucketing data of the node.
///
/// @details Bucketing algorithm decides in both bucketing/unbucketing what to do based on the node and its childrens'
/// bucketing_data.
struct lpm_bucketing_data {
    /// @brief Default constructor.
    lpm_bucketing_data() = default;

    /// @brief Bucketing state of the node.
    enum class node_bucketing_state {
        BELONGS_TO_L1_L2_BUCKETS, ///< This node either belong or in range of L2 bucket written in the bucketing data.
        BELONGS_TO_L1_BUCKET,     ///< This node doesn't belong to any L2 bucket but in range of L1 bucket beneath.
        DOES_NOT_BELONG,          ///< This node can't be inserted to any L1/L2 bucket below.
        UNBUCKETED,               ///< This node was unbucketed and should be rebucket.
    };

    node_bucketing_state bucketing_state = node_bucketing_state::UNBUCKETED; ///< Bucketing state of the node;
    lpm_nodes_bucket_wptr l2_bucket = nullptr;                               ///< L2 bucket that starts at this node.
    lpm_buckets_bucket_wptr l1_bucket = nullptr;                             ///< L1 bucket that starts at this node.
    size_t group = GROUP_ID_NONE;            ///< Group ID in case this node is group root, GROUP_ID_NONE otherwise.
    bool is_balanced = false;                ///< Predicate indicates whether the subtree below this node is maximum utilized.
    bool is_sram_only = false;               ///< Predicate indicates whether this node must be in the SRAM.
    lpm_payload_t payload = INVALID_PAYLOAD; ///< Payload of node.
    bool is_user_prefix = false;             ///< True if node is entered by user.
};

} // namespace silicon_one

#endif // __LEABA_LPM_BUCKETING_DATA_H__
