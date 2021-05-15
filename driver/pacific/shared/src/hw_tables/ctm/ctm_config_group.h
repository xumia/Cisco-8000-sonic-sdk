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

#ifndef __CTM_CONFIG_GROUP_H__
#define __CTM_CONFIG_GROUP_H__

#include "common/allocator_wrapper.h"
#include "common/cereal_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "ctm_common_tcam.h"

#include <stddef.h>

namespace silicon_one
{
using namespace ctm;
class ctm_config_group
{
    ////For serialization purposes////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////////
public:
    ctm_config_group(const group_desc& group);

    ctm_config_group() = default; // Serialization purposes only.

    void add_tcam(size_t ring_idx, size_t subring_idx, size_t msb_tcam_idx, size_t lsb_tcam_idx);

    void remove_tcam(size_t ring_idx, size_t subring_idx, size_t msb_tcam_idx, size_t lsb_tcam_idx);

    const std::vector<tcam_desc>& get_msb_tcams() const;

    const std::vector<tcam_desc>& get_lsb_tcams() const;

    group_desc get_group_desc() const;

    ~ctm_config_group() = default;

private:
    void add_tcam_to_sorted_vector(tcam_desc tcam, std::vector<tcam_desc>& vector);

    group_desc m_group_desc;

    std::vector<tcam_desc> m_msb_tcams;
    std::vector<tcam_desc> m_lsb_tcams;
};

} // namespace silicon_one

#endif
