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

#include "parse_context.h"
#include "lld/device_tree.h"

using namespace silicon_one;
using namespace std;

parse_context::parse_context(ll_device* ll_dev) : nodes(0), bits(0), registers(0), json_fname("")
{
    m_is_pacific = ll_dev->is_pacific();
    m_is_gibraltar = ll_dev->is_gibraltar();

    if (m_is_gibraltar) {
        m_gibraltar_tree = ll_dev->get_gibraltar_tree_scptr();
        sbif_block_id = m_gibraltar_tree->sbif->get_block_id();
        json_fname = "/res/gibraltar_interrupt_tree.json";
    } else {
        m_pacific_tree = ll_dev->get_pacific_tree_scptr();
        json_fname = "/res/pacific_interrupt_tree.json";
        sbif_block_id = m_pacific_tree->sbif->get_block_id();
    }
}

parse_context::~parse_context()
{
}

lld_register_scptr
parse_context::get_register_from_tree(la_block_id_t block_id, la_entry_addr_t addr) const
{
    if (m_is_gibraltar) {
        return m_gibraltar_tree->get_register(block_id, addr);
    } else if (m_is_pacific) {
        return m_pacific_tree->get_register(block_id, addr);
    }
    return nullptr;
}
