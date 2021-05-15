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

#include "loopback_table_sram.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_register.h"

namespace silicon_one
{

loopback_table_sram::loopback_table_sram(const ll_device_sptr& ldevice, npl_tables_e table_id, la_slice_id_t slice) : m_lld(ldevice)
{
    auto tree = ldevice->get_gibraltar_tree_scptr();
    if (table_id == NPL_TABLES_MII_LOOPBACK_TABLE) {
        m_registers = {{tree->slice[slice]->ifg[0]->mac_pool8[0]->mac_lanes_loopback_register,
                        tree->slice[slice]->ifg[0]->mac_pool8[1]->mac_lanes_loopback_register,
                        tree->slice[slice]->ifg[0]->mac_pool8[2]->mac_lanes_loopback_register,
                        tree->slice[slice]->ifg[1]->mac_pool8[0]->mac_lanes_loopback_register,
                        tree->slice[slice]->ifg[1]->mac_pool8[1]->mac_lanes_loopback_register,
                        tree->slice[slice]->ifg[1]->mac_pool8[2]->mac_lanes_loopback_register}};
    } else if (table_id == NPL_TABLES_PMA_LOOPBACK_TABLE) {
        m_registers = {{tree->slice[slice]->ifg[0]->mac_pool8[0]->pma_loopback_register,
                        tree->slice[slice]->ifg[0]->mac_pool8[1]->pma_loopback_register,
                        tree->slice[slice]->ifg[0]->mac_pool8[2]->pma_loopback_register,
                        tree->slice[slice]->ifg[1]->mac_pool8[0]->pma_loopback_register,
                        tree->slice[slice]->ifg[1]->mac_pool8[1]->pma_loopback_register,
                        tree->slice[slice]->ifg[1]->mac_pool8[2]->pma_loopback_register}};
    } else {
        dassert_crit(!"Unsupported table type");
    }
}

la_status
loopback_table_sram::write(size_t line, const bit_vector& value)
{
    size_t ifg = (line >> 5) & 0x1;
    size_t pif = line & ((1 << 5) - 1);

    size_t pool_index = pif / 8;
    size_t index_in_pool = pif % 8;

    const lld_register_array_sptr& reg_array = m_registers[ifg * NUM_REGS_PER_IFG + pool_index];
    const lld_register_sptr& reg((*reg_array)[index_in_pool]);

    la_status status = m_lld->write_register(reg, value);

    return status;
}

size_t
loopback_table_sram::max_size() const
{
    // Dummy table
    return 0;
}

} // namespace silicon_one
