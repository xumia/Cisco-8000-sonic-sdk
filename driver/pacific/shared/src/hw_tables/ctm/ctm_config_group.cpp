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

#include "ctm_config_group.h"
#include "common/dassert.h"
#include "ctm_common.h"
namespace silicon_one
{
using namespace ctm;
ctm_config_group::ctm_config_group(const group_desc& group) : m_group_desc(group)
{
}

void
ctm_config_group::add_tcam(size_t ring_idx, size_t subring_idx, size_t msb_tcam_idx, size_t lsb_tcam_idx)
{
    dassert_crit(m_group_desc.is_wide() || lsb_tcam_idx == IDX_INVAL);
    tcam_desc msb_tcam_location(ring_idx, subring_idx, msb_tcam_idx);
    dassert_crit(!contains(m_msb_tcams, msb_tcam_location));
    add_tcam_to_sorted_vector(msb_tcam_location, m_msb_tcams);

    if (m_group_desc.is_wide()) {
        dassert_crit(lsb_tcam_idx != IDX_INVAL);
        tcam_desc lsb_tcam_location(ring_idx, subring_idx, lsb_tcam_idx);
        dassert_crit(!contains(m_lsb_tcams, lsb_tcam_location));
        add_tcam_to_sorted_vector(lsb_tcam_location, m_lsb_tcams);
    }
}

void
ctm_config_group::remove_tcam(size_t ring_idx, size_t subring_idx, size_t msb_tcam_idx, size_t lsb_tcam_idx)
{
    dassert_crit(m_group_desc.is_wide() || lsb_tcam_idx == IDX_INVAL);
    tcam_desc msb_tcam_location(ring_idx, subring_idx, msb_tcam_idx);
    dassert_crit(contains(m_msb_tcams, msb_tcam_location));
    const std::vector<tcam_desc>::iterator& msb_it = std::find(m_msb_tcams.begin(), m_msb_tcams.end(), msb_tcam_location);
    m_msb_tcams.erase(msb_it);

    if (m_group_desc.is_wide()) {
        dassert_crit(lsb_tcam_idx != IDX_INVAL);
        tcam_desc lsb_tcam_location(ring_idx, subring_idx, lsb_tcam_idx);
        dassert_crit(contains(m_lsb_tcams, lsb_tcam_location));
        const std::vector<tcam_desc>::iterator& lsb_it = std::find(m_lsb_tcams.begin(), m_lsb_tcams.end(), lsb_tcam_location);
        m_lsb_tcams.erase(lsb_it);
    }
}

const std::vector<tcam_desc>&
ctm_config_group::get_msb_tcams() const
{
    return m_msb_tcams;
}

const std::vector<tcam_desc>&
ctm_config_group::get_lsb_tcams() const
{
    return m_lsb_tcams;
}

group_desc
ctm_config_group::get_group_desc() const
{
    return m_group_desc;
}

void
ctm_config_group::add_tcam_to_sorted_vector(tcam_desc tcam, std::vector<tcam_desc>& vector)
{
    for (std::vector<tcam_desc>::iterator it = vector.begin(); it != vector.end(); it++) {
        if (tcam > *it) {
            vector.insert(it, tcam);
            return;
        }
    }

    vector.push_back(tcam);
}

} // namespace silicon_one
