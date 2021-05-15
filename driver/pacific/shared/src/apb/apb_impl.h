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

#ifndef __LEABA_APB_IMPL_H__
#define __LEABA_APB_IMPL_H__

#include "apb/apb.h"
#include "common/cereal_utils.h"
#include "common/la_lock_guard.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

namespace silicon_one
{

#define start_apb_call(...)                                                                                                        \
    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_mutex, m_ll_device->get_device_id());                                  \
    log_debug(APB, __VA_ARGS__)

class apb_impl;
class apb_impl : public apb
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    apb_impl(ll_device_sptr ldev, apb_interface_type_e interface_type);
    virtual ~apb_impl() = default;

    /// @brief Overrides
    la_device_id_t get_device_id() const override;
    apb_interface_type_e get_interface_type() const override;
    std::recursive_mutex& get_lock() const override;

    // TODO: Move NUM_IFGS_PER_DEVICE (and other constants) from src/hld/hld_utils.h to a cross-modules shared header
    enum {
        NUM_SLICES_PER_DEVICE_GR = 8,
        NUM_IFGS_PER_SLICE_GR = 2,
        NUM_SLICES_PER_DEVICE_GB = 6,
        NUM_IFGS_PER_SLICE_GB = 2,
        NUM_SLICES_PER_DEVICE_PL = 6,
        NUM_IFGS_PER_SLICE_PL = 2,
        NUM_BEAGLES_PER_IFG_GR = 8,
    };

    static apb* create_gibraltar(ll_device_sptr ldev, apb_interface_type_e type);
    static apb* create_asic3(ll_device_sptr ldev, apb_interface_type_e type);
    static apb* create_asic4(ll_device_sptr ldev, apb_interface_type_e type);

protected:
    apb_impl(); // For serialization purposes only

    ll_device_sptr m_ll_device;
    const apb_interface_type_e m_interface_type;
    mutable std::recursive_mutex m_mutex;
};

/// @brief Simulated device
class apb_impl_simulated : public apb_impl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    apb_impl_simulated(ll_device_sptr ldev, apb_interface_type_e type);
    virtual ~apb_impl_simulated() = default;

    /// @brief Overrides
    la_status configure(uint32_t clk_div) override;
    la_status write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv) override;
    la_status read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv) override;

protected:
    apb_impl_simulated() = default; // For serialization purposes only
};

} // namespace silicon_one

#endif
