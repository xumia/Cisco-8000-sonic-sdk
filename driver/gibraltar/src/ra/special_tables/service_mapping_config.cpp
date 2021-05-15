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

#include "service_mapping_config.h"

#include "common/defines.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

//**************************************
// service_mapping_config
//**************************************

static const size_t s_service_mapping_config_config_reg_val[service_mapping_config::NUM_EM_CORES]
    = {0 /*short core*/, 1, 2, 0 /*short core*/, 3 /*short core*/, 4, 5, 3 /*short core*/};

service_mapping_config::service_mapping_config()
{
    init_active_banks();
}

// Num-of-EM-Cores: 16, Num-of-access: 12.
// Valid values are [0..11]
// Selected-index = 0 -> Slice-0, Key-0
// Selected-index = 1 -> Slice-0, Key-1
//

// Selected-index = 11 -> Slice-5, Key-1
la_status
service_mapping_config::configure_hw(const ll_device_sptr& ldevice) const
{
    pacific_tree_scptr device_tree = ldevice->get_pacific_tree_scptr();

    const lld_register_array_container& config_regs = *device_tree->sdb->mac->sm_per_em_core_selected_access_index_cfg;

    for (size_t reg_idx = 0; reg_idx < NUM_CONFIG_REGS; ++reg_idx) {
        size_t core_idx = reg_idx / NUM_PORTS;
        size_t key_idx = reg_idx % NUM_PORTS;

        size_t slice_idx = s_service_mapping_config_config_reg_val[core_idx];
        size_t value = slice_idx * NUM_PORTS + key_idx;
        dassert_crit(value < NUM_CONFIG_REG_ACCESSES);

        sdb_mac_sm_per_em_core_selected_access_index_cfg_register config_reg_val = {.u8 = {0}};
        config_reg_val.fields.sm_per_em_core_selected_access_index = value;
        la_status ret = ldevice->write_register(*config_regs[reg_idx], config_reg_val);
        return_on_error(ret);
    }

    return LA_STATUS_SUCCESS;
}

std::vector<size_t>
service_mapping_config::get_em_cores(size_t slice_idx) const
{
    std::vector<size_t> ret;

    for (size_t core_idx = 0; core_idx < NUM_EM_CORES; ++core_idx) {
        if (slice_idx == s_service_mapping_config_config_reg_val[core_idx]) {
            ret.push_back(core_idx);
        }
    }

    return ret;
}

bit_vector
service_mapping_config::get_active_banks(size_t em_core, size_t port_idx) const
{
    dassert_crit(port_idx < NUM_PORTS);
    dassert_crit(em_core < NUM_EM_CORES);

    if (port_idx == 0) {
        return m_active_banks[em_core];
    }
    // Key 1 gets inversed from Key 0 assignment.
    return ~m_active_banks[em_core];
}

void
service_mapping_config::init_active_banks()
{
    bit_vector small_core_banks(0xf, NUM_SMALL_EM_CORE_BANKS);
    bit_vector large_core_banks(0xf, NUM_LARGE_EM_CORE_BANKS);

    // This is default configuration for symetric assignment.
    // Small cores are assigned completely to one of the keys.
    // Large cores are assigned 50-50.
    m_active_banks[0] = small_core_banks;
    m_active_banks[1] = large_core_banks;
    m_active_banks[2] = large_core_banks;
    m_active_banks[3] = ~small_core_banks;
    m_active_banks[4] = small_core_banks;
    m_active_banks[5] = large_core_banks;
    m_active_banks[6] = large_core_banks;
    m_active_banks[7] = ~small_core_banks;
}

} // namespace silicon_one
