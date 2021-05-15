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

#ifndef __LEABA_APB_H__
#define __LEABA_APB_H__

#include "apb_types.h"
#include "lld/lld_fwd.h"

/// @file
/// @brief Leaba APB API.
///
/// Defines API for accessing APB interface.

namespace silicon_one
{

class apb
{
public:
    /// @name Initialization and life-cycle
    /// @{

    /// @brief D'tor
    virtual ~apb() = default;

    /// @brief APB PCIe select.
    enum class pcie_apb_select_e { CORE = 1 << 0, PHY = 1 << 1, ALL = CORE | PHY };

#ifndef SWIG
    /// @brief Initialize all APB interfaces associated with a specified device.
    ///
    /// @param[in]  ldev        Low-level device.
    /// @param[in]  type        APB interface type.
    ///
    /// @return  Pointer to APB object.
    static apb* create(ll_device_sptr ldev, apb_interface_type_e type);

    /// @brief Encodes SerDes package details into a SerDes package address
    ///
    /// @param[in]  ll_device       Low-level device.
    /// @param[in]  slice           Slice number.
    /// @param[in]  ifg             IFG number.
    /// @param[in]  serdes_package  SerDes package number.
    /// @param[out] apb_select      SerDes package address.
    ///
    /// @return  SerDes package address representation in uint32_t.
    static la_status encode_apb_select(ll_device_sptr ll_device, uint slice, uint ifg, uint serdes_package, uint32_t& apb_select);
#endif

    /// @brief Get device ID of the associated low-level device.
    ///
    /// @retval      Device ID.
    virtual la_device_id_t get_device_id() const = 0;

    /// @brief Get APB interface type.
    ///
    /// @retval      Interface type.
    virtual apb_interface_type_e get_interface_type() const = 0;

    /// @brief Configure APB interface and set core-to-APB clock divider.
    ///
    /// @param[in] clk_div  Core-to-APB clock divider.
    ///
    /// @retval      Interface type.
    virtual la_status configure(uint32_t clk_div) = 0;

    /// @}

    /// @name APB read/write
    /// @{

    /// @brief Write to APB target
    ///
    /// @param[in] apb_select   APB select.
    /// @param[in] addr         Address.
    /// @param[in] in_bv        Input value.
    ///
    /// @return     LA_STATUS_SUCCESS   Command completed successfully.
    /// @return     LA_STATUS_ENODEV    Device is not present.
    virtual la_status write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv) = 0;

    /// @brief Read from APB target
    ///
    /// @param[in]  apb_select   APB select.
    /// @param[in]  addr         Address.
    /// @param[out] out_bv       Output value.
    ///
    /// @return     LA_STATUS_SUCCESS   Command completed successfully.
    /// @return     LA_STATUS_ENODEV    Device is not present.
    virtual la_status read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv) = 0;

    /// @}

    virtual std::recursive_mutex& get_lock() const = 0;
};

} // namespace silicon_one

#endif
