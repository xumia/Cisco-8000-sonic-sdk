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

#ifndef __LEABA_LLD_D2D_IFACE_IMPL_H__
#define __LEABA_LLD_D2D_IFACE_IMPL_H__

#include "lld/d2d_iface.h"
#include "lld_types_internal.h"

namespace silicon_one
{
class d2d_iface_impl : public d2d_iface
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Unit id boundaries
    struct unit_id_boundaries {
        la_entry_addr_t start_block; ///< Start block unit id
        la_entry_addr_t end_block;   ///< End block unit id
    };
    /// @brief Static vector of unit id boundaries
    static std::vector<unit_id_boundaries> s_unit_id_boundaries;

    /// @brief  Non-default c'tor
    ///
    /// @note   Assume that the low-level device object is already initialized.
    ///
    /// @param[in] ldev Pointer to a low-level device.
    explicit d2d_iface_impl(ll_device_sptr ldev);

    // Disallow copy c'tor. Default construct is private, in order to support serialization
    d2d_iface_impl(const d2d_iface&) = delete;

    /// @brief  Initialize D2D interface
    ///
    /// @return Status code
    la_status initialize() override;

    /// @brief  Check wheater D2D interface is initialized
    ///
    /// @retval true if initialized, otherwise false
    bool is_initialized() override;

    /// @brief  Reset D2D master
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    la_status master_out_of_reset(uint8_t chiplet_idx) override;

    /// @brief  Reset D2D slave (chiplet)
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    la_status slave_out_of_reset(uint8_t chiplet_idx) override;

    /// @brief  Reset rest of the chiplet blocks
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    la_status chiplet_reset(uint8_t chiplet_idx) override;

    /// @brief  Set default access timeout values
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    la_status set_timeouts(uint8_t chiplet_idx) override;

    /// @brief  Store unit ids per slice into D2D master unit ids table and set them as valid
    ///
    /// @note Unit ids are automatically calculated from s_unit_id_boundaries vector
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    la_status initialize_unit_ids(uint8_t chiplet_idx) override;

    /// @brief  Set specific unit id to valid/invalid
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[in] unit_id Specific unit id in slice
    /// @param[in] valid true-valid, false-invalid
    /// @return Status code
    la_status set_unit_id_valid(uint8_t chiplet_idx, uint16_t unit_id, bool valid) override;

    /// @brief  Set all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] in_unit_ids Vector of all unit ids [0..31]
    ///
    /// @return Status code
    la_status set_all_unit_ids(uint8_t chiplet_idx, std::vector<uint16_t> in_unit_ids) override;

    /// @brief  Get valid status for specific unit id
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[in] unit_id Specific unit id in slice
    /// @param[out] out_valid true-valid, false-invalid
    /// @return Status code
    la_status get_unit_id_valid(uint8_t chiplet_idx, uint16_t unit_id, bool& out_valid) override;

    /// @brief  Get all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] out_unit_ids Vector of all unit ids [0..31]
    ///
    /// @return Status code
    la_status get_all_unit_ids(uint8_t chiplet_idx, std::vector<uint16_t>& out_unit_ids) override;

    /// @brief  Get valid vector for all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] out_valid_mask Vector of unit valid bits. Each bit corresponds to one unit id entry
    ///
    /// @return Status code
    la_status get_all_unit_ids_valid(uint8_t chiplet_idx, uint32_t& out_valid_mask) override;

    /// @brief  Set valid vector for all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] in_valid Vector of unit valid bits. Each bit corresponds to one unit id entry
    ///
    /// @return Status code
    la_status set_all_unit_ids_valid(uint8_t chiplet_idx, uint32_t in_valid) override;

private:
    asic3_tree_scptr m_tree;
    ll_device_sptr m_ll_device;
    bool m_initialized;

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    d2d_iface_impl() = default;
};

} // namespace silicon_one

#endif
