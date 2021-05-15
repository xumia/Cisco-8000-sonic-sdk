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

#ifndef __LEABA_LLD_D2D_IFACE_H__
#define __LEABA_LLD_D2D_IFACE_H__

#include "lld/ll_device.h"
#include "lld/lld_fwd.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

namespace silicon_one
{
class d2d_iface
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief  Initialize D2D interface
    ///
    /// @return Status code
    virtual la_status initialize() = 0;

    /// @brief  Check wheater D2D interface is initialized
    ///
    /// @retval true if initialized, otherwise false
    virtual bool is_initialized() = 0;

    /// @brief  Reset D2D master
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    virtual la_status master_out_of_reset(uint8_t chiplet_idx) = 0;

    /// @brief  Reset D2D slave (chiplet)
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    virtual la_status slave_out_of_reset(uint8_t chiplet_idx) = 0;

    /// @brief  Reset rest of the chiplet blocks
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    virtual la_status chiplet_reset(uint8_t chiplet_idx) = 0;

    /// @brief  Set default access timeout values
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    virtual la_status set_timeouts(uint8_t chiplet_idx) = 0;

    /// @brief  Store unit ids per slice into D2D master unit ids table and set them as valid
    ///
    /// @note Unit ids are automatically calculated from s_unit_id_boundaries vector
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    ///
    /// @return Status code
    virtual la_status initialize_unit_ids(uint8_t chiplet_idx) = 0;

    /// @brief  Set specific unit id to valid/invalid
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[in] unit_id Specific unit id in slice
    /// @param[in] valid true-valid, false-invalid
    /// @return Status code
    virtual la_status set_unit_id_valid(uint8_t chiplet_idx, uint16_t unit_id, bool valid) = 0;

    /// @brief  Set all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] in_unit_ids Vector of all unit ids [0..31]
    ///
    /// @return Status code
    virtual la_status set_all_unit_ids(uint8_t chiplet_idx, std::vector<uint16_t> in_unit_ids) = 0;

    /// @brief  Get valid status for specific unit id
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[in] unit_id Specific unit id in slice
    /// @param[out] out_valid true-valid, false-invalid
    /// @return Status code
    virtual la_status get_unit_id_valid(uint8_t chiplet_idx, uint16_t unit_id, bool& out_valid) = 0;

    /// @brief  Get all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] out_unit_ids Vector of all unit ids [0..31]
    ///
    /// @return Status code
    virtual la_status get_all_unit_ids(uint8_t chiplet_idx, std::vector<uint16_t>& out_unit_ids) = 0;

    /// @brief  Get valid vector for all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] out_valid_mask Vector of unit valid bits. Each bit corresponds to one unit id entry
    ///
    /// @return Status code
    virtual la_status get_all_unit_ids_valid(uint8_t chiplet_idx, uint32_t& out_valid_mask) = 0;

    /// @brief  Set valid vector for all unit ids
    ///
    /// @param[in] chiplet_idx Chiplet index [0..7]
    /// @param[out] in_valid Vector of unit valid bits. Each bit corresponds to one unit id entry
    ///
    /// @return Status code
    virtual la_status set_all_unit_ids_valid(uint8_t chiplet_idx, uint32_t in_valid) = 0;

    /// @brief Create d2d_iface object.
    ///
    /// @param[in]  lld                    Pointer to ll_device attached to this d2d_iface object
    ///
    /// @retval                            Pointer to d2d_iface object.
    static d2d_iface_sptr create(ll_device_sptr lld);

    virtual ~d2d_iface() = default;
};

} // namespace silicon_one

#endif
