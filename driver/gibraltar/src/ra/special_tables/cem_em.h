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

#ifndef __CEM_EM_H__
#define __CEM_EM_H__

#include "hw_tables/cem.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/physical_locations.h"
#include "lld/lld_register.h"

namespace silicon_one
{

class ll_device;

/// @brief Exact Match Interface implementation.
///
/// Central Exact Match is managed by HW. Access from CPU is done via ARC control register
///
class cem_em : public logical_em
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  cem_db              Pointer to CEM instance.
    /// @param[in]  type                Table type.
    cem_em(const ll_device_sptr& ldevice, const cem_sptr& cem_db, cem::entry_type_e type);

    // Logical EM API-s

    la_status insert(const bit_vector& key, const bit_vector& payload) override;
    la_status update(const bit_vector& key, const bit_vector& payload) override;
    la_status erase(const bit_vector& key) override;
    size_t max_size() const override;
    la_status get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const override;
    la_status get_available_entries(size_t& out_available_entries) const override;
    la_status set_resource_monitor(const resource_monitor_sptr& monitor) override;
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const override;
    size_t size() const override;
    la_status erase(const bit_vector& key, size_t payload_width) override;
    bool is_flexible_entry_supported() const override;

private:
    cem_em() = default; // For serialization purposes only.
    // Forbid copy
    cem_em(const cem_em&);
    cem_em& operator=(const cem_em&);

private:
    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    // Pointer to cem db instance.
    cem_wptr m_cem;

    // Table type.
    cem::entry_type_e m_type;
};

} // namespace silicon_one

#endif // __CEM_EM_H__
