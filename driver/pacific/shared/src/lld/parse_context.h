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

#ifndef __PARSE_CONTEXT_H__
#define __PARSE_CONTEXT_H__

#include "lld/interrupt_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

#include "lld_types_internal.h"

/*#include "common/bit_utils.h"
#include "common/common_strings.h"
#include "common/file_utils.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/lld_strings.h"
#include "lld/lld_utils.h"
*/

#include <map>
#include <string>

using namespace std;

namespace silicon_one
{

class parse_context
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    std::map<uint64_t, interrupt_tree::node_scptr> map_address_to_node;
    la_block_id_t sbif_block_id;

    // parse counters
    size_t nodes;
    size_t bits;
    size_t registers;

    string json_fname;

    /// @brief C'tor, the actual initialization in init().
    explicit parse_context(ll_device* ll_dev);

    /// @brief Copy c'tor - disallowed.
    parse_context(const parse_context&) = delete;

    /// @brief Destruct leaba module device.
    ~parse_context();

    lld_register_scptr get_register_from_tree(la_block_id_t block_id, la_entry_addr_t addr) const;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    parse_context() = default;

private:
    std::shared_ptr<const pacific_tree> m_pacific_tree;
    std::shared_ptr<const gibraltar_tree> m_gibraltar_tree;

    bool m_is_pacific;
    bool m_is_gibraltar;
};
} // namespace silicon_one
#endif
