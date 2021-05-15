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

#ifndef __LEABA_LPM_TYPES_H__
#define __LEABA_LPM_TYPES_H__

#include "common/bit_vector.h"

/// @file
/// @brief LPM types required for API-s.

namespace silicon_one
{

typedef bit_vector192_t lpm_key_t;
typedef uint32_t lpm_payload_t;
typedef bit_vector128_t lpm_entry_group_t;

/// @brief Level of the data_structure/algorithm.
enum class lpm_level_e {
    L1 = 0,     ///< Level 1.
    L2,         ///< Level 2.
    NUM_LEVELS, ///< Last element.
};

constexpr size_t LEVEL1 = static_cast<size_t>(lpm_level_e::L1);
constexpr size_t LEVEL2 = static_cast<size_t>(lpm_level_e::L2);
static constexpr size_t NUM_LEVELS = static_cast<size_t>(lpm_level_e::NUM_LEVELS);

/// @brief LPM action enum.
enum class lpm_action_e {
    INSERT, ///< Insert entry.
    REMOVE, ///< Remove entry.
    MODIFY, ///< Modify payload.
};

/// @brief LPM action descriptor.
///
/// Specify an action: action, key and payload.
struct lpm_action_desc {

    /// @brief Construct a (action, key, payload, index) action descriptor.
    ///
    /// @param[in]      action          Action type.
    /// @param[in]      key             Prefix to perform action on.
    /// @param[in]      payload         Payload of action.
    /// @param[in]      index           Index of action.
    lpm_action_desc(lpm_action_e action, const lpm_key_t& key, lpm_payload_t payload)
        : m_action(action), m_key(key), m_payload(payload), m_latency_sensitive(false)
    {
    }

    /// @brief Construct a (action, key) action descriptor.
    ///
    /// @param[in]      action          Action type.
    /// @param[in]      key             Prefix to perform action on.
    lpm_action_desc(lpm_action_e action, const lpm_key_t& key)
        : m_action(action), m_key(key), m_payload(), m_latency_sensitive(false)
    {
    }

    /// @brief Construct an empty action descriptor.
    lpm_action_desc()
    {
    }

    lpm_action_e m_action;    ///< Action type.
    lpm_key_t m_key;          ///< Prefix to perform action on.
    lpm_payload_t m_payload;  ///< Action payload.
    bool m_latency_sensitive; ///< Indicates whether this prefix is high-priority prefix.
};

using lpm_action_desc_vec_t = std::vector<lpm_action_desc, allocator_wrapper<lpm_action_desc> >;

/// @brief Statistics per type of LPM actions.
struct lpm_action_statistics {
    size_t insertions;
    size_t removals;
    size_t modifications;
    size_t refreshes;
    size_t unbuckets;

    lpm_action_statistics()
    {
        reset();
    }

    void reset()
    {
        insertions = 0;
        removals = 0;
        modifications = 0;
        refreshes = 0;
        unbuckets = 0;
    }
};

enum class lpm_ip_protocol_e {
    IPV4 = 0,
    IPV6 = 1,
};

} // namespace silicon_one

#endif
