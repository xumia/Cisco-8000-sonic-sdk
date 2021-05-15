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

#include "service_lp_attribute_config.h"

#include "common/defines.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

size_t
service_lp_attribute_config::get_sram_core_idx(size_t slice_pair_idx, size_t idx) const
{
    size_t representative_slice_idx = slice_pair_idx * 2;
    size_t port_idx = get_sram_core_port_idx(representative_slice_idx, idx);

    if (port_idx == IDX_NOVAL) {
        return IDX_NOVAL;
    }
    return port_idx / PORTS_PER_CORE;
}

size_t
service_lp_attribute_config::get_section_start_line(size_t sram_core_idx, size_t section_idx) const
{
    // all even sections start at 0, regardless of SRAM core size
    if (section_idx % 2 == 0) {
        return 0;
    }

    size_t core_size = get_core_size(sram_core_idx);

    if (core_size == SECTION_SIZE) {
        // for SRAM cores of 16k, all sections start at 0
        return 0;
    }

    // odd sections of large cores start at 16k
    return SECTION_SIZE;
}

la_status
service_lp_attribute_config::configure_hw(const ll_device_sptr& ldevice) const
{
    pacific_tree_scptr device_tree = ldevice->get_pacific_tree_scptr();

    auto& config_regs = *device_tree->sdb->mac->central_lp_db_per_access_select_lp_core_index;

    for (size_t slice_idx = 0; slice_idx < NUM_CONFIG_REGS; ++slice_idx) {
        for (size_t lp_core_enc = 0; lp_core_enc < NUM_CORES; ++lp_core_enc) {
            size_t port_idx = get_sram_core_port_idx(slice_idx, lp_core_enc);
            if (port_idx == IDX_NOVAL) {
                port_idx = 0;
            }

            bit_vector port_idx_bv(port_idx, 3 /*width*/);
            la_status ret = ldevice->write_memory(*config_regs[slice_idx], lp_core_enc, port_idx_bv);
            return_on_error(ret);
        }
    }
    return LA_STATUS_SUCCESS;
}

size_t
service_lp_attribute_config::get_sram_core_port_idx(size_t slice_idx, size_t section_idx) const
{
    dassert_crit(slice_idx < NUM_CONFIG_REGS);
    dassert_crit(section_idx < NUM_CORES);

    // In default implementation, each slice gets 32k entries (shared for slice pair. Therefore, access to larger addresses will
    // result in "out of range"
    static const size_t slice_lpid_map[NUM_CONFIG_REGS][4] = {
        {0, 6, IDX_NOVAL, IDX_NOVAL},
        {1, 7, IDX_NOVAL, IDX_NOVAL},
        {2, 2, IDX_NOVAL, IDX_NOVAL},
        {3, 3, IDX_NOVAL, IDX_NOVAL},
        {4, 4, IDX_NOVAL, IDX_NOVAL},
        {5, 5, IDX_NOVAL, IDX_NOVAL},
    };

    return slice_lpid_map[slice_idx][section_idx];
}

size_t
service_lp_attribute_config::get_core_size(size_t core_idx) const
{
    // 16k, 32k, 32k, 16k
    static const size_t CORE_SIZE[NUM_CORES] = {1 << 14, 1 << 15, 1 << 15, 1 << 14};

    if (core_idx >= NUM_CORES) {
        return 0;
    }

    return CORE_SIZE[core_idx];
}

} // namespace silicon_one
