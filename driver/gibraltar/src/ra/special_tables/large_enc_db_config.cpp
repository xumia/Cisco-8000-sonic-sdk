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

#include "large_enc_db_config.h"

#include "common/defines.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

static const size_t s_large_enc_db_config_port_slice_map[large_enc_db_config::NUM_PORTS] = {0, 1, 2, 3, 4, 5, 0, 1};

la_status
large_enc_db_config::configure_hw(const ll_device_sptr& ldevice) const
{
    pacific_tree_scptr device_tree = ldevice->get_pacific_tree_scptr();

    const lld_register_array_container& config_regs = *device_tree->sdb->enc->large_enc_per_em_core_selected_access_index_cfg;

    for (size_t port_idx = 0; port_idx < NUM_CONFIG_REGS; ++port_idx) {
        size_t slice_idx = s_large_enc_db_config_port_slice_map[port_idx];
        sdb_enc_large_enc_per_em_core_selected_access_index_cfg_register slice_idx_val = {.u8 = {0}};
        slice_idx_val.fields.large_enc_per_em_core_selected_access_index = slice_idx;
        la_status ret = ldevice->write_register(*config_regs[port_idx], slice_idx_val);
        return_on_error(ret);
    }
    return LA_STATUS_SUCCESS;
}

std::vector<size_t>
large_enc_db_config::get_em_cores(size_t slice_pair_idx) const
{
    dassert_crit(slice_pair_idx < NUM_CONFIG_REG_ACCESSES / 2);

    std::vector<size_t> ret;
    for (size_t port_idx = 0; port_idx < NUM_PORTS; port_idx += PORTS_PER_CORE) {
        size_t slice_idx = s_large_enc_db_config_port_slice_map[port_idx];
        if (slice_idx / 2 == slice_pair_idx) {
            ret.push_back(port_idx / 2);
        }
    }
    return ret;
}

} // namespace silicon_one
