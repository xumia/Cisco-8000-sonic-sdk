// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_core_tcam_akpg.h"
#include "common/logger.h"
#include "lpm_core_tcam_allocator_akpg.h"
#include "lpm_core_tcam_utils_akpg.h"

namespace silicon_one
{

lpm_core_tcam_akpg::lpm_core_tcam_akpg(std::string name,
                                       size_t num_banksets,
                                       size_t num_cells_per_bank,
                                       const lpm_core_tcam_utils_scptr& core_tcam_utils)
    : lpm_core_tcam(name,
                    num_banksets,
                    num_cells_per_bank,
                    num_banksets * lpm_core_tcam_allocator::NUM_BANKS_PER_BANKSET / 4 * num_cells_per_bank,
                    core_tcam_utils)
{
    m_tcam_allocator = std::make_shared<lpm_core_tcam_allocator_akpg>(name + "::Allocator", num_banksets, num_cells_per_bank);
    lpm_core_tcam_allocator_akpg::allocator_instruction_vec instructions;
    m_tcam_allocator->initialize(true /* block_last_block_group */, instructions);

    for (const auto& instruction : instructions) {
        hardware_instruction_vec dummy_instructions;
        la_status status = perform_allocator_instruction(instruction, dummy_instructions);
        dassert_crit(status == LA_STATUS_SUCCESS);
        dassert_crit(dummy_instructions.empty());
    }

    for (auto& logical_tcam : m_logical_tcams) {
        logical_tcam.commit();
    }
}

} // namespace silicon_one
