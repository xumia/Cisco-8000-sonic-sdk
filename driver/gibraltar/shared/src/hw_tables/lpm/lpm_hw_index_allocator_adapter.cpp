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

#include "lpm/lpm_hw_index_allocator_adapter.h"
#include "lpm/lpm_hw_index_allocator_adapter_hbm.h"
#include "lpm/lpm_hw_index_allocator_adapter_sram.h"
#include "lpm/lpm_hw_index_doubles_allocator_pacific.h"

#include "lpm_bucket.h"

namespace silicon_one
{

lpm_hw_index_allocator_adapter_sptr
create_hw_index_allocator_adapter(std::string name,
                                  ll_device_sptr ldevice,
                                  lpm_level_e level,
                                  size_t num_of_sram_lines,
                                  size_t num_buckets_per_sram_line,
                                  size_t num_of_hbm_buckets,
                                  size_t num_fixed_entries_per_bucket,
                                  size_t num_shared_entries_per_double_bucket)
{
    bool hbm_enabled = (num_of_hbm_buckets > 0);
    if (is_pacific_revision(ldevice) && (level == lpm_level_e::L2) && (!hbm_enabled) && (num_buckets_per_sram_line == 2)) {
        lpm_hw_index_allocator_adapter_sptr adapter = std::make_shared<lpm_hw_index_doubles_allocator_pacific>(
            name, num_of_sram_lines, num_fixed_entries_per_bucket, num_shared_entries_per_double_bucket);
        return adapter;
    }

    lpm_hw_index_allocator_adapter_sptr adapter;
    if (hbm_enabled) {
        adapter = std::make_shared<lpm_hw_index_allocator_adapter_hbm>(name, ldevice, num_of_sram_lines, num_of_hbm_buckets);
    } else {

        // Remove after we create real bucket to line 0.
        size_t first_line = 0;
        if (level == lpm_level_e::L1) {
            first_line++;
            num_of_sram_lines--;
        }

        adapter = std::make_shared<lpm_hw_index_allocator_adapter_sram>(name,
                                                                        ldevice,
                                                                        level,
                                                                        first_line,
                                                                        num_of_sram_lines,
                                                                        num_buckets_per_sram_line,
                                                                        num_fixed_entries_per_bucket,
                                                                        num_shared_entries_per_double_bucket);
    }

    return adapter;
}

} // namespace silicon_one
