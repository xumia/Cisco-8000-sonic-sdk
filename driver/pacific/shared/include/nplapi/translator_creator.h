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

#ifndef __TRANSLATOR_CREATOR_H__
#define __TRANSLATOR_CREATOR_H__

#include "api/types/la_common_types.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

#include "lld/lld_fwd.h"

#include <vector>

namespace silicon_one
{

class ll_device;
class translator_creator;

/// @brief Translator creator object.
///
/// @details Interfaces of a functional object that provides creation services for npl_table translators.
class translator_creator
{
public:
    translator_creator() = default;

    /// @brief Translator creator constructor
    ///
    /// @param[in]  lld                     Low-level device.
    /// @param[in]  npl_context_slices      NPL context mode of slices.
    translator_creator(ll_device_sptr lld, const std::vector<npl_context_e>& npl_context_slices);

    // d'tor
    virtual ~translator_creator();

    /// @brief Gets low level device object
    ///
    /// @retval     Pointer to ll_device
    virtual ll_device_sptr get_ll_device() const;

    /// @brief Initializes HW resources required for proper table initialization.
    ///
    /// @retval     status code.
    virtual la_status pre_table_init();

    /// @brief Initializes HW resources after all tables are initialized.
    ///
    /// @retval     status code.
    virtual la_status post_table_init();

    /// @brief Get slice context
    ///
    /// @param[in] slice_index  Slice index
    ///
    /// @retval context
    virtual npl_context_e get_slice_context(size_t slice_index);

    /// @brief Loads microcode of the provided context to the list of slices.
    ///
    /// @param[in]  slices      List of slice indices to load microcode.
    /// @param[in]  context     Slice context (fabric, network, etc).
    ///
    /// @retval     status code.
    virtual la_status load_microcode(const std::vector<size_t>& slices, npl_context_e context);

    /// @brief Initializes table with underlying translators.
    ///
    /// @param[in]  table                       #npl_table/#npl_ternary_table/#npl_lpm_table,
    ///                                         to be initialized. Table type should correspond to provided #table_type.
    /// @param[in]  table_type                  Table type.
    /// @param[in]  indices                     Slices to initialize table for.
    ///
    /// @retval     LA_STATUS_SUCCESS           if initialization is succeeded
    /// @retval     LA_STATUS_ENOTINITIALIZED   if translator_creator is not initialized properly to create needed translator
    ///
    /// @note Table becomes the owner of the created translator objects and responsible for their deletion.
    virtual la_status initialize_table(void* table, npl_tables_e table_type, const std::vector<size_t>& indices) = 0;

protected:
    std::vector<npl_context_e> m_npl_context_slices;

private:
    ll_device_sptr m_ll_device;
};

} // namespace silicon_one

#endif // __TRANSLATOR_CREATOR_H__
