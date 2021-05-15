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

#ifndef __RA_TERNARY_TABLE_MAPPING_H__
#define __RA_TERNARY_TABLE_MAPPING_H__

#include "api/types/la_acl_types.h"
#include "ctm/ctm_common.h"
#include "lld/lld_memory.h"

namespace silicon_one
{

class ra_ternary_table_mapping
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    struct table_to_group_desc {
        size_t npl_table_id; ///< NPL table ID.
        ctm::group_desc::group_ifs_e m_interface;
        size_t logical_id; ///< Table logical ID.
        bool is_valid;
    };

    CEREAL_SUPPORT_PRIVATE_CLASS(table_to_group_desc)

    // C'tor
    ra_ternary_table_mapping(const ll_device_sptr& ldevice);

    ra_ternary_table_mapping() = default; // Serialization purposes only.

    // D'tor
    ~ra_ternary_table_mapping() = default;

    void update_mapping();
    bool get_table_mapping(size_t npl_table_id, table_to_group_desc& table_map_out);

private:
    // Low Level device
    ll_device_sptr m_ll_device;
    std::vector<table_to_group_desc> m_table_to_group_mapping;
};

} // namespace silicon_one

#endif // __RA_TERNARY_TABLE_MAPPING_H__
