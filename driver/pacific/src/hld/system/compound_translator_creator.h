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

#ifndef __COMPOUND_TRANSLATOR_CREATOR_H__
#define __COMPOUND_TRANSLATOR_CREATOR_H__

#include <string.h>

#include "common/allocator_wrapper.h"
#include "common/logger.h"
#include "nplapi/nplapi_fwd.h"
#include "nplapi/translator_creator.h"

namespace silicon_one
{

/// @brief Compound translator creator implementation for SDK application.
class compound_translator_creator : public translator_creator
{
public:
    /// @brief compound translator creator constructor
    ///
    /// @param[in]  lld                     Low-level device.
    /// @param[in]  npl_context_slices      NPL context mode of slices.
    compound_translator_creator(ll_device_sptr lld,
                                const std::vector<npl_context_e>& npl_context_slices,
                                vector_alloc<translator_creator_sptr> creators_vec);

    /// @brief compound translator creator destructor
    ~compound_translator_creator();

    /// @brief Initializes HW resources required for proper table initialization.
    ///
    /// @retval     status code.
    la_status pre_table_init() override;

    /// @brief Initializes HW resources after all tables are initialized.
    ///
    /// @retval     status code.
    la_status post_table_init() override;

    /// @brief Loads microcode of the provided context to the list of slices.
    ///
    /// @param[in]  slices      List of slice indices to load microcode.
    /// @param[in]  context     Slice context (fabric, network, etc).
    ///
    /// @retval     status code.
    la_status load_microcode(const std::vector<size_t>& slices, npl_context_e context) override;

    /// @brief Get slice context
    ///
    /// @param[in] slice_index  Slice index
    ///
    /// @retval context
    npl_context_e get_slice_context(size_t slice_index) override;

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
    la_status initialize_table(void* table, npl_tables_e table_type, const std::vector<size_t>& indices) override;

private:
    vector_alloc<translator_creator_sptr> m_translator_creators;
};

} // namespace silicon_one

#endif // __COMPOUND_TRANSLATOR_CREATOR_H__
