// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __MC_EMDB_H__
#define __MC_EMDB_H__

#include "api/types/la_common_types.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/physical_locations.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"
#include "lld/lld_register.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

/// @brief Implementation of #silicon_one::mc_emdb.
///
/// MC-EMDB has two physical tables per device.
/// Its table selection logic is based on the following rule,
///
/// XOR{MCID[15:0],Entr[10:0]}
///
/// MCID located at [26, 11]
/// Entr located at [10, 0]
class mc_emdb : public logical_em
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  ems                 Reference to logical_em vector.
    /// @param[in]  key_width           Table key width in bits.
    /// @param[in]  value_width         Table value width in bits.
    mc_emdb(const ll_device_sptr& ldevice, const std::vector<logical_em_sptr>& ems);
    mc_emdb(const mc_emdb&) = delete;

    // Logical EM API-s
    la_status insert(const bit_vector& key, const bit_vector& payload) override;
    la_status update(const bit_vector& key, const bit_vector& payload) override;
    la_status erase(const bit_vector& key) override;
    size_t max_size() const override;
    la_status set_resource_monitor(const resource_monitor_sptr& monitor) override;
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const override;
    size_t size() const override;
    la_status erase(const bit_vector& key, size_t payload_width) override;
    bool is_flexible_entry_supported() const override;
    la_status get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const override;
    la_status get_available_entries(size_t& out_available_entries) const override;

private:
    mc_emdb& operator=(const mc_emdb&);

    // MC-EMDB specfic table selection logic
    size_t which_em(const bit_vector& key) const;

private:
    mc_emdb() = default; // For serialization purposes only.
    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    // List of logical EMs
    std::vector<logical_em_sptr> m_ems;

    // Resource monitor
    resource_monitor_sptr m_resource_monitor;
    size_t m_num_entries;
};
} // namespace silicon_one

#endif // __MC_EMDB_H__
