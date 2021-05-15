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

#ifndef __LA_DEVICE_IMPL_BASE_H__
#define __LA_DEVICE_IMPL_BASE_H__

#include "api/system/la_device.h"
#include "common/cereal_utils.h"
#include "hld_types_fwd.h"
#include "lld/device_simulator.h"
#include "lld/lld_utils.h"
#include "system/slice_manager_smart_ptr_base.h"
#include <array>
#include <atomic>
#include <bitset>
#include <chrono>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

namespace silicon_one
{

static constexpr la_uint32_t WB_INVALID_REVISION = 0xffffffff;

class la_device_impl_base : public la_device
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_device_impl_base(ll_device_sptr ldevice);

    // Disallow copy c'tor
    la_device_impl_base(la_device_impl_base&) = delete;

    ~la_device_impl_base() override;

    virtual la_status warm_boot_get_base_revision(la_uint32_t& wb_revision) override;

    /// @brief Initialize the active slices and serdices
    ///
    /// @return Status code.
    /// it is called automaticly by initialize() - except in some testing scenarios
    la_status initialize_first(bool is_reconnect);
    virtual la_status initialize_slice_id_manager();
    virtual la_status initialize_first_ifgs() = 0;
    const slice_manager_smart_ptr& get_slice_id_manager() const;

    la_device_id_t get_id() const override;

    la_slice_id_t first_active_slice_id() const;
    init_phase_e get_init_phase() const override;
    virtual la_status hbm_exists(bool& out_exists) const = 0;
    la_status get_device_bool_capabilities(std::vector<bool>& out_device_bool_capabilities) const override;
    la_status get_device_int_capabilities(std::vector<uint32_t>& out_device_int_capabilities) const override;
    la_status get_device_string_capabilities(std::vector<std::string>& out_device_string_capabilities) const override;

    la_status open_scheduler_auto_grants() override;

public:
    // public members
    /// Low level device.
    ll_device_sptr m_ll_device;

    /// Resource manager
    resource_handler_sptr m_resource_handler;

    slice_manager_smart_ptr_owner m_slice_id_manager;
    /// Initialization level for this device
    init_phase_e m_init_phase = init_phase_e::CREATED;

    // Get all remote devices reachable from this device
    virtual la_status get_reachable_devices(bit_vector& out_reachable_dev_bv) = 0;

    /// Device mode
    device_mode_e m_device_mode;

protected:
    la_status pre_initialize(slice_id_manager_base_sptr slice_id_manager);
    la_device_impl_base() = default; // Needed for cereal
    virtual la_device_impl_base_sptr get_sptr() = 0;

    // warm boot versioning
    la_uint32_t m_base_wb_revision = WB_INVALID_REVISION;

}; // class la_device_impl_base
}
#endif // __LA_DEVICE_IMPL_BASE_H__
