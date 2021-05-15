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

#ifndef __LPM_DB_H__
#define __LPM_DB_H__

#include "common/bit_vector.h"
#include "common/la_status.h"
#include "lld/lld_fwd.h"

#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/lpm_types.h"

#include <stddef.h>

namespace silicon_one
{

class logical_lpm;

/// @brief LPM interface implementation for LPM4 and LPM6.
///
class lpm_db
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    struct lpm_db_action_desc {
        /// @brief Construct an empty action descriptor.
        lpm_db_action_desc()
        {
        }

        lpm_action_e action;    ///< Action type.
        bit_vector key;         ///< Prefix in bit vector.
        size_t length;          ///< Prefix length.
        bit_vector payload;     ///< Action payload in bit vector.
        bool latency_sensitive; ///< Predicate to indicate priority.
    };

    using lpm_db_action_desc_vec_t = vector_alloc<lpm_db_action_desc>;

    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  prefix_len          An constant addition to LPM length.
    /// @param[in]  ip_protocol         Protocol of the logical table above this lpm_db.
    /// tables.
    /// @param[in]  lpm                 LPM core handle.
    lpm_db(const ll_device_sptr& ldevice, size_t prefix_len, lpm_ip_protocol_e ip_protocol, const logical_lpm_wptr& lpm);
    ~lpm_db();

    void key_translate(const bit_vector& key, size_t length, lpm_key_t& out_lpm_key);
    la_status insert(const bit_vector& key, size_t length, const bit_vector& payload);
    la_status update(const bit_vector& key, size_t length, const bit_vector& payload);
    la_status erase(const bit_vector& key, size_t length);
    la_status bulk_updates(lpm_db_action_desc_vec_t& actions, size_t& out_count_success);
    size_t max_size() const;
    size_t get_physical_usage(size_t number_of_logical_entries_in_table) const;
    size_t get_available_entries() const;

private:
    lpm_db() = default; // For serialization purposes only.
    // Forbid copy
    lpm_db(const lpm_db&);
    lpm_db& operator=(const lpm_db&);

private:
    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    // An constant addition to LPM length for all LPM operations.
    size_t m_prefix_len;

    // Protocol of the logical table above this lpm_db.
    lpm_ip_protocol_e m_protocol;

    // LPM core
    logical_lpm_wptr m_lpm;

    // LPM bulk actions vector
    lpm_action_desc_vec_t m_actions;

    size_t protocol_bit;
};

} // namespace silicon_one

#endif // __LPM_DB_H__
