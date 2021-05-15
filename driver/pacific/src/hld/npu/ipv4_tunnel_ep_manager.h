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

#ifndef _IPV4_TUNNEL_EP_MANAGER_H_
#define _IPV4_TUNNEL_EP_MANAGER_H_

#include "hld_types.h"
#include "hld_types_fwd.h"
#include <map>
#include <stdint.h>

#include "nplapi/nplapi_tables.h"

///
/// Manages the entries in the my_ipv4_table, which are shared among tunnels,
/// including GRE/IPinIP/VXLAN
///

namespace silicon_one
{

class la_device_impl;

class ipv4_tunnel_ep_manager
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit ipv4_tunnel_ep_manager(const la_device_impl_wptr& device);
    ~ipv4_tunnel_ep_manager() = default;

    const la_device_impl_wptr& get_device() const;

    /// @brief Add ipv4 tunnel endpoint.
    /// @param[in]  local_ip_prefix             The IPv4 prefix of the endpoint.
    /// @param[in]  vrf                         The VRF of the endpoint.
    /// @param[in]  sip_index                   SIP index of the endpoint.
    /// @param[in]  l4_protocol_type            L4 protocol type of the endpoint.
    /// @param[in]  db                          Logical termination database to use.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            SIP index not match.
    la_status add_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                 const la_vrf_wcptr& vrf,
                                 uint64_t sip_index,
                                 npl_protocol_type_e l4_protocol_type,
                                 npl_termination_logical_db_e db);

    /// @brief Remove ipv4 tunnel endpoint.
    /// @param[in]  local_ip_prefix             The IPv4 prefix of the endpoint.
    /// @param[in]  vrf                         The VRF of the endpoint.
    /// @param[in]  l4_protocol_type            L4 protocol type of the endpoint.
    /// @param[in]  sip_index                   SIP index of the endpoint.
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            SIP index not match.
    la_status remove_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                    const la_vrf_wcptr& vrf,
                                    npl_protocol_type_e l4_protocol_type,
                                    uint64_t sip_index);

    /// @brief get the number of tunnel endpoints
    /// @return     the number of tunnel endpoints
    size_t size();

    /// @brief Get local ep info for a given local_ip and vrf
    /// @param[in]  local_ip_prefix             The IPv4 prefix of the endpoint.
    /// @param[in]  vrf                         The VRF of the endpoint.
    /// @param[in]  l4_protocol_type            L4 protocol type of the endpoint.
    /// @param[out] ref_cnt                     The ref count for the local ep entry
    /// @param[out] term_db                     The termination type for the local ep entry
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         Entry was not found.
    la_status get_local_ep_entry_info(la_ipv4_prefix_t local_ip_prefix,
                                      const la_vrf_wcptr& vrf,
                                      npl_protocol_type_e l4_protocol_type,
                                      uint32_t& ref_cnt,
                                      uint64_t& sip_index,
                                      npl_termination_logical_db_e& term_db);

    /// @brief Add ipv4 tunnel endpoint.
    /// @param[in]  local_ip_prefix             The IPv4 prefix of the endpoint.
    /// @param[in]  vrf                         The VRF of the endpoint.
    /// @param[in]  sip_index_or_local_slp_id   The per slice sip index or local slp id.
    /// @param[in]  l4_protocol_type            L4 protocol type of the endpoint.
    /// @param[in]  db                          Logical termination database to use.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            SIP index not match.
    la_status add_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                 const la_vrf_wcptr& vrf,
                                 std::vector<uint64_t> sip_index_or_local_slp_id,
                                 npl_protocol_type_e l4_protocol_type,
                                 npl_termination_logical_db_e db);

    /// @brief Remove ipv4 tunnel endpoint.
    /// @param[in]  local_ip_prefix             The IPv4 prefix of the endpoint.
    /// @param[in]  vrf                         The VRF of the endpoint.
    /// @param[in]  l4_protocol_type            L4 protocol type of the endpoint.
    /// @param[in]  sip_index_or_local_slp_id   The per slice sip index or local slp id.
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            SIP index not match.
    la_status remove_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                    const la_vrf_wcptr& vrf,
                                    npl_protocol_type_e l4_protocol_type,
                                    std::vector<uint64_t> sip_index_or_local_slp_id);

    /// @brief Get local ep info for a given local_ip and vrf
    /// @param[in]  local_ip_prefix             The IPv4 prefix of the endpoint.
    /// @param[in]  vrf                         The VRF of the endpoint.
    /// @param[in]  l4_protocol_type            L4 protocol type of the endpoint.
    /// @param[out] ref_cnt                     The ref count for the local ep entry
    /// @param[out] sip_index_or_local_slp_id   The per slice sip index or local slp id
    /// @param[out] term_db                     The termination type for the local ep entry
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         Entry was not found.
    la_status get_local_ep_entry_info(la_ipv4_prefix_t local_ip_prefix,
                                      const la_vrf_wcptr& vrf,
                                      npl_protocol_type_e l4_protocol_type,
                                      uint32_t& ref_cnt,
                                      std::vector<uint64_t>& sip_index_or_local_slp_id,
                                      npl_termination_logical_db_e& term_db);

private:
    /// The creating device
    la_device_impl_wptr m_device;

    typedef struct ipv4_tunnel_ep_t_s {
        la_vrf_gid_t relay_id;
        la_ipv4_prefix_t ipv4_prefix;
        uint8_t l4_protocol_sel;
    } ipv4_tunnel_ep_t;
    CEREAL_SUPPORT_PRIVATE_CLASS(ipv4_tunnel_ep_t_s);

    struct ipv4_tunnel_ep_lt {
        bool operator()(const ipv4_tunnel_ep_t& ep1, const ipv4_tunnel_ep_t& ep2) const
        {
            return (std::tie(ep1.ipv4_prefix.addr.s_addr, ep1.ipv4_prefix.length, ep1.relay_id, ep1.l4_protocol_sel)
                    < std::tie(ep2.ipv4_prefix.addr.s_addr, ep2.ipv4_prefix.length, ep2.relay_id, ep2.l4_protocol_sel));
        }
    };

    struct ipv4_tunnel_entry_t {
        npl_my_ipv4_table_t::entry_wptr_type entry;
        size_t loc[ASIC_MAX_SLICES_PER_DEVICE_NUM];
        uint32_t ref_cnt;
        uint64_t sip_index;
        std::vector<uint64_t> sip_index_or_local_slp_id;
        npl_termination_logical_db_e db;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ipv4_tunnel_entry_t);

    std::map<ipv4_tunnel_ep_t, ipv4_tunnel_entry_t, ipv4_tunnel_ep_lt> m_ipv4_tunnel_ep_map;

    ipv4_tunnel_ep_manager() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // _IPV4_TUNNEL_EP_MANAGER_H_
