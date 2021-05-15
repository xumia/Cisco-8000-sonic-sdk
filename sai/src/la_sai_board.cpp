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

#include "la_sai_board.h"

namespace silicon_one
{
namespace sai
{

void
lsai_serdes_key_counters_t::inc(const lsai_serdes_media_type_e& media_type)
{
    switch (media_type) {
    case lsai_serdes_media_type_e::NOT_PRESENT:
        not_present++;
        break;
    case lsai_serdes_media_type_e::COPPER:
        copper++;
        break;
    case lsai_serdes_media_type_e::OPTIC:
        optic++;
        break;
    case lsai_serdes_media_type_e::CHIP2CHIP:
        chip2chip++;
        break;
    case lsai_serdes_media_type_e::LOOPBACK:
        loopback++;
        break;
    default:
        error_cnt++;
    }
}

la_uint32_t
lsai_serdes_key_counters_t::total()
{
    return not_present + copper + optic + chip2chip + loopback;
}

lsai_port_cfg_t::lsai_port_cfg_t(const uint32_t& pif, const uint32_t& num_of_lanes, std::vector<sai_attribute_t>& attrs)
    : m_attrs(attrs)
{
    for (uint32_t idx = 0; idx < num_of_lanes; idx++) {
        m_pif_lanes.push_back(pif + idx);
    }
}
}
}
