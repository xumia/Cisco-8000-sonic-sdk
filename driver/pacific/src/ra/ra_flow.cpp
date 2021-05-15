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

#include "lld/ll_device.h"
#include "lld/lld_memory.h"
#include "lld/lld_utils.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{
size_t NUM_SLICES_PER_DEVICE_WALKAROUND = 6;
void
init_buggy_dynamic_memories(const ll_device_sptr& ldevice)
{
    const pacific_tree* tree = ldevice->get_pacific_tree();
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    for (size_t slice = 0; slice < NUM_SLICES_PER_DEVICE_WALKAROUND; ++slice) {
        lld_memory_scptr contextfbm_bmp = nullptr;
        lld_memory_scptr voqcgm_profile = nullptr;

        if (slice < 4) {
            contextfbm_bmp = tree->slice[slice]->pdvoq->contextfbm_bmp;
            voqcgm_profile = tree->slice[slice]->pdvoq->voqcgm_profile;
        } else {
            contextfbm_bmp = tree->slice[slice]->fabric_pdvoq->contextfbm_bmp;
            voqcgm_profile = tree->slice[slice]->fabric_pdvoq->voqcgm_profile;
        }
        // Initialize context free bitmap to all free and mark last context as not free.
        mem_val_list.push_back({contextfbm_bmp, bit_vector("0xFFFFFFFFFFFFFFFF")});
        mem_line_val_list.push_back({{contextfbm_bmp, contextfbm_bmp->get_desc()->entries - 1}, bit_vector("0x7FFFFFFFFFFFFFFF")});

        mem_line_val_list.push_back({{voqcgm_profile, voqcgm_profile->get_desc()->entries - 1}, 0});

        const lld_memory_scptr& context2voq = tree->slice[slice]->ics->context2voq;
        mem_line_val_list.push_back({{context2voq, context2voq->get_desc()->entries - 1}, 0xFFFF});
    }

    const lld_memory_scptr& dram_context_pool = tree->ics_top->dram_context_pool;
    mem_val_list.push_back({dram_context_pool, bit_vector("0xFFFFFFFFFFFFFFFF", dram_context_pool->get_desc()->width_bits)});

    for (size_t slice = 0; slice < 4; slice++) {

        const lld_memory_scptr& fabric_reachability_mem = tree->slice[slice]->filb->fabric_reachability;
        mem_val_list.push_back({fabric_reachability_mem, bit_vector(0, fabric_reachability_mem->get_desc()->width_bits)});
    }

    lld_write_memory_list(ldevice, mem_val_list);
    lld_write_memory_line_list(ldevice, mem_line_val_list);
}
}
