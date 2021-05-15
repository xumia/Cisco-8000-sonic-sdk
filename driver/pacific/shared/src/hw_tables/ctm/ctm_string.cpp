// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "ctm_string.h"

#include <sstream>

namespace silicon_one
{

std::string
to_string(ctm::table_desc table)
{
    std::stringstream s;
    s << "table(slice_id=" << table.slice_id << ", table_id=" << static_cast<size_t>(table.table_id) << ")";
    return s.str();
}

std::string
to_string(ctm::group_desc group)
{
    std::string group_name;

    switch (group.interface) {
    case ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW:
        group_name = "GROUP_IFS_FW0_NARROW";
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_FW1_NARROW:
        group_name = "GROUP_IFS_FW1_NARROW";
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE:
        group_name = "GROUP_IFS_FW_WIDE";
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW:
        group_name = "GROUP_IFS_TX0_NARROW";
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TX1_NARROW:
        group_name = "GROUP_IFS_TX1_NARROW";
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TX_WIDE:
        group_name = "GROUP_IFS_TX_WIDE";
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TERM:
        group_name = "GROUP_IFS_TERM";
        break;
    case ctm::group_desc::group_ifs_e::NUMBER_OF_GROUPS_IFS:
        group_name = "NUMBER_OF_GROUPS_IFS";
        break;
    }

    std::stringstream s;
    s << "group(slice_id=" << group.slice_idx << ", interface=" << group_name << ")";
    return s.str();
}

std::string
to_string(const tcam_desc& tcam)
{
    std::stringstream s;
    s << "TCAM(ring_idx=" << tcam.ring_idx << ", subring_idx=" << tcam.subring_idx << ", idx=" << tcam.tcam_idx << ")";
    return s.str();
}

std::string
to_string(const tcams_container_vec& tcam_containers_vector)
{
    std::stringstream ss;
    for (const tcams_container& tcam_container : tcam_containers_vector) {
        ss << "[ ";
        for (const tcam_desc& tcam : tcam_container) {
            ss << to_string(tcam) << " ";
        }
        ss << "]";
    }

    return ss.str();
}

} // namespace silicon_one
