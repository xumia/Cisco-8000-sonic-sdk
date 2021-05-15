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

#ifndef __LEABA_LPM_BUCKETS_BUCKET_H__
#define __LEABA_LPM_BUCKETS_BUCKET_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm_bucket.h"
#include "lpm_common.h"
#include "lpm_internal_types.h"
#include <list>

/// @file

namespace silicon_one
{

/// @brief LPM buckets bucket.
///
/// Describes a single LPM bucket of buckets, as represented in memory.
/// This type of bucket owns buckets as its entries.
class lpm_buckets_bucket : public lpm_bucket
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct an empty LPM bucket.
    ///
    /// @param[in]      index                           Index of bucket.
    explicit lpm_buckets_bucket(lpm_bucket_index_t index);

    /// @brief Insert lpm_nodes_bucket as entry of this bucket.
    ///
    /// Update lpm_nodes_bucket's m_containing_bucket and add it to the list of sub-buckets.
    ///
    /// @param[in]      bucket            Bucket to insert.
    void insert(const lpm_nodes_bucket_sptr& bucket);

    /// @brief Remove lpm_nodes_bucket from the bucket.
    ///
    /// Update lpm_nodes_bucket's m_containing_bucket and remove it from the list of sub-buckets.
    ///
    /// @param[in]      bucket            Bucket to be removed.
    void remove(const lpm_nodes_bucket_sptr& bucket);

    /// @brief Remove lpm_nodes_bucket from the bucket.
    ///
    /// Update lpm_nodes_bucket's m_containing_bucket and remove it from the list of sub-buckets.
    /// Allows using weak_ptr to avoid costly casting.
    ///
    /// @param[in]      bucket            Bucket to be removed.
    void remove(const lpm_nodes_bucket_wptr& bucket);

    /// @brief Get all the sub-buckets under this bucket.
    ///
    /// @return list of lpm_nodes_bucket pointers.
    const lpm_bucket_ptr_list& get_members() const;

    /// @brief Merge with other lpm_buckets_buckets.
    ///
    /// @param[in]      other_bucket            Buckets to merge its nodes.
    void merge_bucket_members(lpm_buckets_bucket* other_bucket);

    /// @brief Remove all the nodes from the bucket.
    void clear_sub_buckets()
    {
        m_sub_buckets.clear();
        m_num_of_entries = 0;
        m_max_width = 0;
    }

    // lpm_bucket.h API-s
    size_t get_root_width() const override;
    lpm_key_payload_vec get_entries() const override;
    size_t get_max_width() const override;
    void reset() override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_buckets_bucket() = default;

    // Data members
    lpm_bucket_ptr_list m_sub_buckets;
};

} // namespace silicon_one

#endif
