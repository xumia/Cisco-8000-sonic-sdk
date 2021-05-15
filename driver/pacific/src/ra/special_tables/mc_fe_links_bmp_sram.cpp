// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "mc_fe_links_bmp_sram.h"

#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

mc_fe_links_bmp_sram::mc_fe_links_bmp_sram(const ll_device_sptr& ll_device) : mc_fe_links_bmp_sram_base(ll_device)
{
}

lld_memory_sptr
mc_fe_links_bmp_sram::get_rx_pdr_mc_db_memory(uint64_t shared_db_num, uint64_t shared_db_verifier_mem_num)
{
    pacific_tree_scptr pt = m_ll_device->get_pacific_tree_scptr();
    return (*pt->rx_pdr_mc_db[shared_db_num]->shared_db_verifier)[shared_db_verifier_mem_num];
}
}
