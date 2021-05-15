// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <string.h>

#include "common/logger.h"
#include "lld/device_tree.h"
#include "lld/lld_storage.h"

#include "lld/lld_block.h"

namespace silicon_one
{

la_block_id_t
lld_storage::get_block_id() const
{
    return m_parent_block->get_block_id();
}

bool
lld_storage::is_valid() const
{
    return m_is_valid && m_parent_block->is_valid();
}

std::string
lld_storage::get_name() const
{
    return m_parent_block->get_name() + "." + m_name;
}

lld_field_desc
lld_storage::get_field(std::vector<lld_field_desc> const& fields, size_t pos)
{
    for (const auto& field : fields) {
        if (pos >= field.lsb && pos < field.lsb + field.width_in_bits) {
            return field;
        }
    }

    return lld_field_desc{};
}

size_t
lld_storage::get_index() const
{
    return m_index;
}

} // namespace silicon_one
