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

#include "ra_ternary_table_mapping.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{
// C'tor
ra_ternary_table_mapping::ra_ternary_table_mapping(const ll_device_sptr& ldevice)
    : m_ll_device(ldevice),
      // clang-format off
m_table_to_group_mapping{
    {NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE,  ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_ETH_RTF_DB1_160,  true},  // ingress ethernet
    {NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE,  ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_ETH_RTF_DB2_160,  true},  // ingress ethernet
    {NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB1_160,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB1_320,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB2_160,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB2_320,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB3_160,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB3_320,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB4_160,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB4_320,      true},  // ingress ipv4
    {NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB1_160,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB1_320,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB2_160,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB2_320,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB3_160,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB3_320,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_ACL_RTF_DB4_160,      true},  // ingress ipv6
    {NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_INGRESS_ACL_RTF_DB4_320,      true},  // ingress ipv6
    {NPL_TABLES_IPV4_LPTS_TABLE,                   ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_LPTS_TABLE_ID_IPV4,           true},  // ipv4 lpts
    {NPL_TABLES_IPV6_LPTS_TABLE,                   ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE,    NPL_FWD0_LPTS_TABLE_ID_IPV6,           true},  // ipv6 lpts
    {NPL_TABLES_DEFAULT_EGRESS_IPV4_SEC_ACL_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW, NPL_EGRESS_ACL_DB_IPV4_SEC_DEFAULT,    true},  // egress ipv4 sec
    {NPL_TABLES_DEFAULT_EGRESS_IPV6_ACL_SEC_TABLE, ctm::group_desc::group_ifs_e::GROUP_IFS_TX_WIDE,    NPL_EGRESS_ACL_DB_IPV6_MASTER_DEFAULT, true},  // egress ipv6 sec
    {NPL_TABLES_IPV6_SIP_COMPRESSION_TABLE,        ctm::group_desc::group_ifs_e::GROUP_IFS_TERM,       NPL_TERM_ACL_DB_IPV6_SIP_COMPRESSION,  true},  // term ipv6 sip compression
    {NPL_TABLES_L2_LPTS_MAC_TABLE,                 ctm::group_desc::group_ifs_e::GROUP_IFS_TERM,       NPL_TERM_ACL_DB_L2_LPTS_MAC,           true},  // term ipv4 l2 lpts mac
    {NPL_TABLES_L2_LPTS_IPV4_TABLE,                ctm::group_desc::group_ifs_e::GROUP_IFS_TERM,       NPL_TERM_ACL_DB_L2_LPTS_IPV4,          true},  // term ipv4 l2 lpts ipv4
    {NPL_TABLES_L2_LPTS_IPV6_TABLE,                ctm::group_desc::group_ifs_e::GROUP_IFS_TERM,       NPL_TERM_ACL_DB_L2_LPTS_IPV6,          true},  // term ipv4 l2 lpts ipv6
    {NPL_TABLES_SGACL_TABLE,                       ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW, NPL_FWD0_INGRESS_SGACL_DB_160,         false}, // ingress SGACL
    }
// clang-format on
{
}

void
ra_ternary_table_mapping::update_mapping()
{
    // set table_id, key_size, npl table id and logical table id
    // V4
    for (size_t map_idx = 0; map_idx < m_table_to_group_mapping.size(); map_idx++) {
        table_to_group_desc& table_map = m_table_to_group_mapping[map_idx];

        if (is_gibraltar(m_ll_device->get_device_revision()) && (table_map.npl_table_id == NPL_TABLES_SGACL_TABLE)) {
            table_map.is_valid = true;
        }
    }
}
bool
ra_ternary_table_mapping::get_table_mapping(size_t npl_table_id, table_to_group_desc& table_map_out)
{
    for (size_t map_idx = 0; map_idx < m_table_to_group_mapping.size(); map_idx++) {
        table_map_out = m_table_to_group_mapping[map_idx];
        if ((npl_table_id == table_map_out.npl_table_id) && (table_map_out.is_valid)) {
            return true;
        }
    }
    return false;
}

} // namespace silicon_one
