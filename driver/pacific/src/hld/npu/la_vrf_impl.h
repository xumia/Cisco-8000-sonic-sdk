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

#ifndef __LA_VRF_IMPL_H__
#define __LA_VRF_IMPL_H__

#include <map>
#include <tuple>
#include <unordered_set>

#include "api/npu/la_vrf.h"
#include "api/types/la_event_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_device_impl;
class la_ethernet_port;
class la_acl_impl;

class la_vrf_impl : public la_vrf
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_vrf_impl() = default;
    //////////////////////////////

public:
    /// @brief Constructor
    ///
    /// @param[in]  device      Creating device
    explicit la_vrf_impl(const la_device_impl_wptr& device);
    ~la_vrf_impl() override;

    // la_vrf API
    la_vrf_gid_t get_gid() const override;
    la_status delete_ipv4_route(la_ipv4_prefix_t prefix) override;
    la_status clear_all_ipv4_routes() override;
    la_status add_ipv4_route(la_ipv4_prefix_t prefix,
                             const la_l3_destination* destination,
                             la_user_data_t user_data,
                             bool latency_sensitive) override;
    la_status modify_ipv4_route(la_ipv4_prefix_t prefix, const la_l3_destination* destination, la_user_data_t user_data) override;
    la_status modify_ipv4_route(la_ipv4_prefix_t prefix, const la_l3_destination* destination) override;
    la_status ipv4_route_bulk_updates(la_ipv4_route_entry_parameters_vec route_entry_vec, size_t& out_count_success) override;
    la_status get_ipv4_route(la_ipv4_addr_t ip_addr, la_ip_route_info& out_ip_route_info) const override;
    la_status get_ipv4_routing_entry(la_ipv4_prefix_t prefix, la_ip_route_info& out_ip_route_info) const override;
    la_status get_ipv4_route_entries_count(la_uint32_t& out_count) const override;
    la_status get_ipv4_route_entries(la_ipv4_route_entry_vec& out_route_entries) override;

    la_status delete_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr) override;
    la_status clear_all_ipv4_multicast_routes() override;
    la_status add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                       la_ipv4_addr_t gaddr,
                                       la_ip_multicast_group* mcg,
                                       const la_l3_port* rpf,
                                       bool punt_on_rpf_fail,
                                       bool punt_and_forward,
                                       la_counter_set* counter) override;
    la_status add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                       la_ipv4_addr_t gaddr,
                                       la_ip_multicast_group* mcg,
                                       const la_l3_port* rpf,
                                       bool punt_on_rpf_fail,
                                       bool punt_and_forward,
                                       bool enable_rpf_check,
                                       la_counter_set* counter) override;
    la_status add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                       la_ipv4_addr_t gaddr,
                                       la_ip_multicast_group* mcg,
                                       la_uint_t rpfid,
                                       bool punt_on_rpf_fail,
                                       bool punt_and_forward,
                                       bool enable_rpf_check,
                                       la_counter_set* counter) override;
    la_status modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                          la_ipv4_addr_t gaddr,
                                          la_ip_multicast_group* mcg,
                                          const la_l3_port* rpf,
                                          bool punt_on_rpf_fail,
                                          bool punt_and_forward,
                                          la_counter_set* counter) override;
    la_status modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                          la_ipv4_addr_t gaddr,
                                          la_ip_multicast_group* mcg,
                                          const la_l3_port* rpf,
                                          bool punt_on_rpf_fail,
                                          bool punt_and_forward,
                                          bool enable_rpf_check,
                                          la_counter_set* counter) override;
    la_status modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                          la_ipv4_addr_t gaddr,
                                          la_ip_multicast_group* mcg,
                                          la_uint_t rpfid,
                                          bool punt_on_rpf_fail,
                                          bool punt_and_forward,
                                          bool enable_rpf_check,
                                          la_counter_set* counter) override;
    la_status get_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                       la_ipv4_addr_t gaddr,
                                       la_ip_mc_route_info& out_ip_mc_route_info) const override;

    la_status set_fallback_vrf(const la_vrf* fallback_vrf) override;
    la_status get_fallback_vrf(const la_vrf*& out_vrf) const override;

    la_status delete_ipv6_route(la_ipv6_prefix_t prefix) override;
    la_status clear_all_ipv6_routes() override;
    la_status add_ipv6_route(la_ipv6_prefix_t prefix,
                             const la_l3_destination* destination,
                             la_user_data_t user_data,
                             bool latency_sensitive) override;
    la_status modify_ipv6_route(la_ipv6_prefix_t prefix, const la_l3_destination* destination, la_user_data_t user_data) override;
    la_status modify_ipv6_route(la_ipv6_prefix_t prefix, const la_l3_destination* destination) override;
    la_status ipv6_route_bulk_updates(la_ipv6_route_entry_parameters_vec route_entry_vec, size_t& out_count_success) override;
    la_status get_ipv6_routing_entry(la_ipv6_prefix_t prefix, la_ip_route_info& out_ip_route_info) const override;
    la_status get_ipv6_route(la_ipv6_addr_t ip_addr, la_ip_route_info& out_ip_route_info) const override;
    la_status get_ipv6_route_entries_count(la_uint32_t& out_count) const override;
    la_status get_ipv6_route_entries(la_ipv6_route_entry_vec& out_route_entries) override;

    la_status delete_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr) override;
    la_status clear_all_ipv6_multicast_routes() override;
    la_status add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                       la_ipv6_addr_t gaddr,
                                       la_ip_multicast_group* mcg,
                                       const la_l3_port* rpf,
                                       bool punt_on_rpf_fail,
                                       bool punt_and_forward,
                                       la_counter_set* counter) override;
    la_status add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                       la_ipv6_addr_t gaddr,
                                       la_ip_multicast_group* mcg,
                                       const la_l3_port* rpf,
                                       bool punt_on_rpf_fail,
                                       bool punt_and_forward,
                                       bool enable_rpf_check,
                                       la_counter_set* counter) override;
    la_status add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                       la_ipv6_addr_t gaddr,
                                       la_ip_multicast_group* mcg,
                                       la_uint_t rpfid,
                                       bool punt_on_rpf_fail,
                                       bool punt_and_forward,
                                       bool enable_rpf_check,
                                       la_counter_set* counter) override;
    la_status modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                          la_ipv6_addr_t gaddr,
                                          la_ip_multicast_group* mcg,
                                          const la_l3_port* rpf,
                                          bool punt_on_rpf_fail,
                                          bool punt_and_forward,
                                          la_counter_set* counter) override;
    la_status modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                          la_ipv6_addr_t gaddr,
                                          la_ip_multicast_group* mcg,
                                          const la_l3_port* rpf,
                                          bool punt_on_rpf_fail,
                                          bool punt_and_forward,
                                          bool enable_rpf_check,
                                          la_counter_set* counter) override;
    la_status modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                          la_ipv6_addr_t gaddr,
                                          la_ip_multicast_group* mcg,
                                          la_uint_t rpfid,
                                          bool punt_on_rpf_fail,
                                          bool punt_and_forward,
                                          bool enable_rpf_check,
                                          la_counter_set* counter) override;
    la_status get_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                       la_ipv6_addr_t gaddr,
                                       la_ip_mc_route_info& out_ip_mc_route_info) const override;
    la_status get_ipv4_pbr_acl(la_acl*& out_ipv4_pbr_acl) override;
    la_status get_ipv6_pbr_acl(la_acl*& out_ipv6_pbr_acl) override;
    la_status set_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix, bool punt_enabled) override;
    la_status get_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix, bool& out_punt_enabled) const override;
    la_status clear_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix) override;
    la_status set_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix, bool punt_enabled) override;
    la_status get_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix, bool& out_punt_enabled) const override;
    la_status clear_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix) override;
    la_status get_max_vrf_gids(la_uint_t& out_max_vrf_gids) const;

    la_status add_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t sgt) override;
    la_status modify_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t sgt) override;
    la_status delete_security_group_tag(la_ipv4_prefix_t prefix) override;
    la_status get_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t& out_sgt) const override;

    la_status add_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t sgt) override;
    la_status modify_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t sgt) override;
    la_status delete_security_group_tag(la_ipv6_prefix_t prefix) override;
    la_status get_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t& out_sgt) const override;
    la_status set_urpf_allow_default(bool enable) override;
    bool get_urpf_allow_default() const override;

    // la_object API
    la_object::object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // additional, specific API

    /// @brief Add a route for an IPV4 subnet.
    ///
    /// @param[in]  subnet      The subnet to be added.
    /// @param[in]  l3_port     Routing destination of a subnet is a L3 port.
    ///
    /// @retval    LA_STATUS_SUCCESS   The route was added successuly.
    /// @retval    LA_STATUS_EEXIST    The given subnet already exists in the VRF's FIB.
    /// @retval    LA_STATUS_EUNKNOWN  Unknown error.
    la_status add_ipv4_subnet(la_ipv4_prefix_t subnet, const la_l3_port_wptr& l3_port);

    /// @brief Add a route for an IPV6 subnet.
    ///
    /// @param[in]  subnet      The subnet to be added.
    /// @param[in]  l3_port     Routing destination of a subnet is a L3 port.
    ///
    /// @retval    LA_STATUS_SUCCESS   The route was added successuly.
    /// @retval    LA_STATUS_EEXIST    The given subnet already exists in the VRF's FIB.
    /// @retval    LA_STATUS_EUNKNOWN  Unknown error.
    la_status add_ipv6_subnet(la_ipv6_prefix_t subnet, const la_l3_port_wptr& l3_port);

    la_status delete_ipv4_subnet(la_ipv4_prefix_t subnet);
    la_status delete_ipv6_subnet(la_ipv6_prefix_t subnet);

    /// @brief Initializes the VRF object
    ///
    /// @param[in]  gid         Global ID of VRF, given by the user
    ///
    /// @retval     LA_STATUS_SUCCESS   VRF object initialized successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status initialize(la_object_id_t oid, la_vrf_gid_t gid);

    /// @brief Destroys the VRF object
    ///
    /// @retval     LA_STATUS_SUCCESS   VRF object destroyed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status destroy();

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// @brief Modify the given IPv4 subnet
    la_status update_ipv4_subnet(la_ipv4_prefix_t subnet, const la_l3_port_wcptr& l3_port);

    /// @brief Modify the given IPv6 subnet
    la_status update_ipv6_subnet(la_ipv6_prefix_t subnet, const la_l3_port_wcptr& l3_port);

    /// @brief Update the IPv4 multicast route for this VRF
    la_status update_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr);

    /// @brief Update the IPv6 multicast route for this VRF
    la_status update_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr);

private:
    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// Global ID of VRF, given by the user
    la_vrf_gid_t m_gid;

    // Fallback VRF for cases when lookup failed.
    la_vrf_wcptr m_fallback_vrf;

    // Default entries
    npl_ipv4_lpm_table_entry_wptr_t m_ipv4_default_entry;
    npl_ipv6_lpm_table_entry_wptr_t m_ipv6_default_entry;

    // User defined default MC entry set
    bool m_ipv4_implicit_mc_catch_all_configured;
    bool m_ipv6_implicit_mc_catch_all_configured;

    // IPv4 entries located in EM
    struct ipv4_less_op {
        inline bool operator()(const la_ipv4_addr_t& lhs, const la_ipv4_addr_t& rhs) const
        {
            return lhs.s_addr < rhs.s_addr;
        }
    };

    // IPv6 entries located in EM
    struct ipv6_less_op {
        inline bool operator()(const la_ipv6_addr_t& lhs, const la_ipv6_addr_t& rhs) const
        {
            return lhs.s_addr < rhs.s_addr;
        }
    };

    std::map<la_ipv4_addr_t, la_l3_destination_wcptr, ipv4_less_op> m_ipv4_em_entries;
    std::map<la_ipv6_addr_t, la_l3_destination_wcptr, ipv6_less_op> m_ipv6_em_entries;

    // MC route details
    struct mc_route_desc {
        la_ip_multicast_group_wptr mcg;
        la_l3_port_wcptr rpf;
        bool punt_on_rpf_fail;
        bool punt_and_forward;
        la_counter_set_wptr counter;
        uint64_t v6_compressed_sip;
        bool use_rpfid;
        la_uint_t rpfid;
        bool enable_rpf_check;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(mc_route_desc);

    struct ipv4_mc_route_map_key_t {
        ipv4_mc_route_map_key_t() // Needed for cereal
        {
            saddr.s_addr = 0;
            gaddr.s_addr = 0;
        }
        ipv4_mc_route_map_key_t(la_ipv4_addr_t s, la_ipv4_addr_t g) : saddr(s), gaddr(g)
        {
        }
        bool operator<(const ipv4_mc_route_map_key_t& other) const
        {
            return std::tie(saddr.s_addr, gaddr.s_addr) < std::tie(other.saddr.s_addr, other.gaddr.s_addr);
        }
        la_ipv4_addr_t saddr;
        la_ipv4_addr_t gaddr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ipv4_mc_route_map_key_t);

    struct ipv6_mc_route_map_key_t {
        ipv6_mc_route_map_key_t() // Needed for cereal
        {
            saddr.s_addr = 0;
            gaddr.s_addr = 0;
        }
        ipv6_mc_route_map_key_t(la_ipv6_addr_t s, la_ipv6_addr_t g) : saddr(s), gaddr(g)
        {
        }
        bool operator<(const ipv6_mc_route_map_key_t& other) const
        {
            // Don't allow multiple entries with same 32 LSbits in gaddr
            return std::tie(saddr.s_addr, gaddr.d_addr[0]) < std::tie(other.saddr.s_addr, other.gaddr.d_addr[0]);
        }
        la_ipv6_addr_t saddr;
        la_ipv6_addr_t gaddr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ipv6_mc_route_map_key_t);

    std::map<ipv4_mc_route_map_key_t, mc_route_desc> m_ipv4_mc_route_desc_map;
    std::map<ipv6_mc_route_map_key_t, mc_route_desc> m_ipv6_mc_route_desc_map;

    // Helper function for finding an element in the IPv6 MC route map, when full gaddr is needed
    std::map<ipv6_mc_route_map_key_t, mc_route_desc>::iterator find_ipv6_mc_route_map_entry_full_gaddr(
        const ipv6_mc_route_map_key_t& map_key);
    std::map<ipv6_mc_route_map_key_t, mc_route_desc>::const_iterator find_ipv6_mc_route_map_entry_full_gaddr(
        const ipv6_mc_route_map_key_t& map_key) const;

    // PBR ACLs
    la_acl_impl_wptr m_pbr_v4_acl{};
    la_acl_impl_wptr m_pbr_v6_acl{};

    // Bulk entries to program.
    npl_lpm_bulk_entries_vec<npl_ipv4_lpm_table_functional_traits_t> m_ipv4_bulk_entries_vec;
    npl_lpm_bulk_entries_vec<npl_ipv6_lpm_table_functional_traits_t> m_ipv6_bulk_entries_vec;

    // Old destinations
    vector_alloc<la_l3_destination_wcptr> m_bulk_old_destinations;

    struct hash_ipv4_prefix {
        size_t operator()(const la_ipv4_prefix_t& pfx) const;
    };

    struct hash_ipv6_prefix {
        size_t operator()(const la_ipv6_prefix_t& pfx) const;
    };

    // Prefix hash
    std::unordered_set<la_ipv4_prefix_t, hash_ipv4_prefix> m_ipv4_bulk_prefix_set;
    std::unordered_set<la_ipv6_prefix_t, hash_ipv6_prefix> m_ipv6_bulk_prefix_set;

    // Allow default route in uRPF
    bool m_urpf_allow_default;

private:
    // Verify parameters to multicast functions
    la_status verify_mc_route_parameters(size_t max_gid,
                                         const la_ip_multicast_group_wcptr& mcg,
                                         const la_l3_port_wcptr& rpf,
                                         const la_counter_set_wcptr& counter,
                                         const bool use_rpfid,
                                         const la_uint_t rpfid);

    // Verify parameters to multicast unmatched punt functions
    la_status verify_unmatched_multicast_punt_prefix(la_ipv4_prefix_t group_prefix) const;
    la_status verify_unmatched_multicast_punt_prefix(la_ipv6_prefix_t group_prefix) const;

    // Helper functions to handle one action
    la_status do_ipv4_route_action(const la_route_entry_action_e action,
                                   const la_ipv4_prefix_t& prefix,
                                   const la_l3_destination_wcptr& destination,
                                   const bool is_user_data_set,
                                   const la_user_data_t user_data,
                                   const bool latency_sensitive);
    la_status do_ipv6_route_action(const la_route_entry_action_e action,
                                   const la_ipv6_prefix_t& prefix,
                                   const la_l3_destination_wcptr& destination,
                                   const bool is_user_data_set,
                                   const la_user_data_t user_data,
                                   const bool latency_sensitive);

    // Helper functions to handle default multicast unmatched punt entries
    bool is_implicit_mc_catch_all_configured(la_ipv4_prefix_t default_prefix) const;
    bool is_implicit_mc_catch_all_configured(la_ipv6_prefix_t default_prefix) const;
    void configure_implicit_mc_catch_all(la_ipv4_prefix_t default_prefix, bool value);
    void configure_implicit_mc_catch_all(la_ipv6_prefix_t default_prefix, bool value);

    // Helper functions for working with default entries
    void get_default_entry(npl_ipv4_lpm_table_entry_wptr_t& out_entry) const;
    void get_default_entry(npl_ipv6_lpm_table_entry_wptr_t& out_entry) const;
    void set_default_entry(const npl_ipv4_lpm_table_entry_wptr_t& entry);
    void set_default_entry(const npl_ipv6_lpm_table_entry_wptr_t& entry);

    // Default routes are marked by setting their destination's MSB
    enum { NUM_OF_BITS_IN_LPM_DESTINATION = 20 };
    enum { DEFAULT_ROUTE_DESTINATION_BIT_MASK = 1 << (NUM_OF_BITS_IN_LPM_DESTINATION - 1) };
    enum { DROP_UNMATCHED_MC_LPM_DESTINATION = DEFAULT_ROUTE_DESTINATION_BIT_MASK };
    enum { PUNT_UNMATCHED_MC_LPM_DESTINATION = 0 };
    enum { MAX_IPV4_PREFIX_LENGTH = 32 };
    enum { MAX_IPV6_PREFIX_LENGTH = 128 };

    // Template functions to support operations that are common for both IPv4 and IPv6
    template <class _TableType, class _PrefixType>
    la_status delete_ip_subnet(const std::shared_ptr<_TableType>& table, const _PrefixType& subnet);

    template <class _TableType>
    la_status remove_lpm_entry(const std::shared_ptr<_TableType>& table,
                               const typename _TableType::entry_wptr_type& entry,
                               bool do_clear_catch_all_entry);

    template <class _LpmTableType, class _EmTableType>
    la_status clear_all_ip_routes(const std::shared_ptr<_LpmTableType>& lpm_table,
                                  const std::shared_ptr<_EmTableType>& em_table,
                                  bool do_clear_catch_all_entry);

    template <class _TableType>
    la_status clear_all_ip_lpm_routes(const std::shared_ptr<_TableType>& table, bool do_clear_catch_all_entry);

    la_status clear_all_ip_em_routes(std::shared_ptr<npl_ipv4_vrf_dip_em_table_t> v4_em_table);
    la_status clear_all_ip_em_routes(std::shared_ptr<npl_ipv6_vrf_dip_em_table_t> v6_em_table);

    template <class _TableType, class _PrefixType>
    la_status add_lpm_entry(const std::shared_ptr<_TableType>& table,
                            _PrefixType prefix,
                            npl_destination_t dest,
                            la_user_data_t user_data,
                            bool latency_sensitive);

    template <class _TableType, class _AddrType>
    la_status add_em_entry(const std::shared_ptr<_TableType>& table, _AddrType addr, const la_l3_destination_wcptr& dest);

    template <class _TableType, class _AddrType>
    la_status add_em_entry(const std::shared_ptr<_TableType>& table,
                           _AddrType addr,
                           npl_destination_t dest,
                           const la_l3_port_wcptr& l3_port);

    template <class _TableType, class _AddrType>
    la_status modify_em_entry(const std::shared_ptr<_TableType>& table, const _AddrType& addr, const la_l3_destination_wcptr& dest);

    template <class _TableType, class _AddrType>
    la_status delete_em_entry(const std::shared_ptr<_TableType>& table, _AddrType addr);

    template <class _LpmTableType, class _EmTableType, class _AddrType>
    la_status get_route_info_from_addr(const std::shared_ptr<_LpmTableType>& lpm_table,
                                       const std::shared_ptr<_EmTableType>& em_table,
                                       _AddrType ip_addr,
                                       la_ip_route_info& out_ip_route_info) const;

    template <class _LpmTableType, class _EmTableType, class _PrefixType>
    la_status get_route_info_from_prefix(const std::shared_ptr<_LpmTableType>& lpm_table,
                                         const std::shared_ptr<_EmTableType>& em_table,
                                         _PrefixType prefix,
                                         la_ip_route_info& out_ip_route_info) const;

    template <class _EntryType>
    la_status get_route_info_from_table_entry(weak_ptr_unsafe<_EntryType> entry, la_ip_route_info& out_ip_route_info) const;

    template <class _EntryType>
    la_status get_l3_destination_from_table_entry(weak_ptr_unsafe<_EntryType> entry, const la_l3_destination*& out_l3_dest) const;

    template <class _EmTableType, class _AddrType>
    la_status get_route_info_from_em(const std::shared_ptr<_EmTableType>& em_table,
                                     const _AddrType& addr,
                                     la_ip_route_info& out_ip_route_info) const;

    bool is_em_eligible(const la_ipv4_prefix_t& prefix) const;
    bool is_em_eligible(const la_ipv6_prefix_t& prefix) const;

    template <class _PrefixType>
    bool is_prefix_valid(_PrefixType prefix) const;

    bool is_prefix_multicast(la_ipv4_prefix_t prefix) const;
    bool is_prefix_multicast(la_ipv6_prefix_t prefix) const;

    template <class _TableType, class _PrefixType>
    la_status set_unmatched_multicast_punt_enabled(const std::shared_ptr<_TableType>& table,
                                                   _PrefixType prefix,
                                                   bool punt_enabled,
                                                   _PrefixType default_prefix);

    template <class _TableType, class _PrefixType>
    la_status clear_unmatched_multicast_punt_enabled(const std::shared_ptr<_TableType>& table,
                                                     _PrefixType prefix,
                                                     _PrefixType default_prefix);

    template <class _TableType, class _PrefixType>
    la_status get_unmatched_multicast_punt_enabled(const std::shared_ptr<_TableType>& table,
                                                   _PrefixType prefix,
                                                   _PrefixType default_prefix,
                                                   bool& out_punt_enabled) const;

    // Functions for populating LPM table key
    void populate_lpm_key(la_ipv4_addr_t addr, npl_ipv4_lpm_table_key_t& out_key) const;
    void populate_lpm_key(la_ipv6_addr_t addr, npl_ipv6_lpm_table_key_t& out_key) const;

    void update_em_entry_shadow(la_ipv4_addr_t addr, const la_l3_destination_wcptr& dest);
    void update_em_entry_shadow(la_ipv6_addr_t addr, const la_l3_destination_wcptr& dest);

    void delete_em_entry_shadow(la_ipv4_addr_t addr);
    void delete_em_entry_shadow(la_ipv6_addr_t addr);

    la_status get_route_info_from_em_shadow(la_ipv4_addr_t addr, la_ip_route_info& out_ip_route_info) const;
    la_status get_route_info_from_em_shadow(la_ipv6_addr_t addr, la_ip_route_info& out_ip_route_info) const;

    // Functions for retrieving the VRF GID from a given key
    la_vrf_gid_t get_vrf_gid_from_key(const npl_ipv4_lpm_table_key_t& key) const;
    la_vrf_gid_t get_vrf_gid_from_key(const npl_ipv6_lpm_table_key_t& key) const;

    // Helper functions for g/s_g table management
    la_status add_to_ipv4_s_g_table(la_ipv4_addr_t saddr,
                                    la_ipv4_addr_t gaddr,
                                    const la_ip_multicast_group_wcptr& mcg,
                                    const la_l3_port_wcptr& rpf,
                                    bool punt_on_rpf_fail,
                                    bool punt_and_forward,
                                    const bool use_rpfid,
                                    const la_uint_t rpfid,
                                    bool enable_rpf_check);
    la_status add_to_ipv4_g_table(la_ipv4_addr_t gaddr,
                                  const la_ip_multicast_group_wcptr& mcg,
                                  const la_l3_port_wcptr& rpf,
                                  bool punt_and_forward,
                                  const bool use_rpfid,
                                  const la_uint_t rpfid,
                                  bool enable_rpf_check);
    la_status add_to_ipv6_s_g_table(la_ipv6_addr_t saddr,
                                    la_ipv6_addr_t gaddr,
                                    const la_ip_multicast_group_wcptr& mcg,
                                    const la_l3_port_wcptr& rpf,
                                    bool punt_on_rpf_fail,
                                    bool punt_and_forward,
                                    bool use_rpfid,
                                    la_uint_t rpfid,
                                    uint64_t compressed_sip,
                                    bool enable_rpf_check);
    la_status add_to_ipv6_g_table(la_ipv6_addr_t gaddr,
                                  const la_ip_multicast_group_wcptr& mcg,
                                  const la_l3_port_wcptr& rpf,
                                  bool punt_and_forward,
                                  bool use_rpfid,
                                  la_uint_t rpfid,
                                  bool enable_rpf_check);
    la_status delete_from_ipv6_s_g_table(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr);
    la_status delete_from_ipv6_g_table(la_ipv6_addr_t gaddr);

    // Helper function for MC-route counter assignment
    la_status configure_mc_route_counter(const la_counter_set_wptr& counter);
    la_status teardown_mc_route_counter(const la_counter_set_wptr& counter);

    // Update MC desriptor after modify-route functions
    void update_mc_desc(mc_route_desc& desc,
                        const la_ip_multicast_group_wptr& mcg,
                        const la_l3_port_wcptr& rpf,
                        bool punt_on_rpf_fail,
                        bool punt_and_forward,
                        const la_counter_set_wptr& counter,
                        bool use_rpfid,
                        la_uint_t rpfid,
                        bool enable_rpf_check);

    // Helper functions for deleting a single MC route
    la_status do_delete_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr);
    la_status do_delete_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr);

    // Helper functions for PBR ACLs
    la_status do_create_pbr_acl(bool is_ipv4);
    la_status do_destroy_pbr_acl(bool is_ipv4);
    la_status destory_pbr_acls();

    la_status get_lpm_destination_from_l3_destination(const la_l3_destination_wcptr& destination,
                                                      npl_destination_t& out_lpm_dest) const;
    la_status is_destination_resolution_forwarding_supported(const la_l3_destination_wcptr& destination);
    template <class _LpmTableType, class _EmTableType, class _RouteEntry>
    la_status common_pre_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                     const std::shared_ptr<_EmTableType>& em_table,
                                     _RouteEntry& route_entry,
                                     npl_destination_t& out_lpm_dest,
                                     la_l3_destination_wcptr& out_old_destination,
                                     la_user_data_t& out_old_user_data);
    template <class _RouteEntry>
    void common_post_bulk_update(_RouteEntry& route_entry, const la_l3_destination_wcptr& old_destination);

    template <class _LpmTableType, class _RouteEntry>
    la_status do_pre_bulk_default_route(const std::shared_ptr<_LpmTableType>& lpm_table,
                                        _RouteEntry& route_entry,
                                        npl_destination_t& out_lpm_dest);
    template <class _LpmTableType, class _RouteEntry>
    void do_post_bulk_default_route(const std::shared_ptr<_LpmTableType>& lpm_table, _RouteEntry& route_entry);
    npl_action_e translate_route_entry_action(const la_route_entry_action_e action) const;
    template <class _LpmTableType, class _EmTableType, class _RouteEntry>
    la_status do_lpm_pre_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                     const std::shared_ptr<_EmTableType>& em_table,
                                     _RouteEntry& route_entry,
                                     npl_destination_t& out_lpm_dest,
                                     la_l3_destination_wcptr& old_destination,
                                     la_user_data_t& out_old_user_data);
    template <class _LpmTableType, class _RouteEntry>
    void do_lpm_post_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                 _RouteEntry& route_entry,
                                 const la_l3_destination_wcptr& old_destination);
    template <class _RouteEntry>
    void do_lpm_bulk_update_failed(_RouteEntry& route_entry);

    template <class _LpmTableType, class _EmTableType, class _RouteEntryVec, class _LpmEntriesBulk>
    la_status lpm_pre_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                   const std::shared_ptr<_EmTableType>& em_table,
                                   _RouteEntryVec& route_entry_vec,
                                   _LpmEntriesBulk& lpm_entries_bulk,
                                   const uint32_t start_batch,
                                   const uint32_t end_batch,
                                   size_t& out_count_success);
    template <class _LpmTableType, class _RouteEntryVec, class _LpmEntriesBulk>
    void lpm_post_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                               _RouteEntryVec& route_entry_vec,
                               _LpmEntriesBulk& lpm_entries_bulk,
                               const uint32_t start_batch,
                               const uint32_t end_batch);
    template <class _RouteEntryVec>
    void lpm_bulk_updates_failed(_RouteEntryVec& route_entry_vec,
                                 const uint32_t start_batch,
                                 const size_t count_success,
                                 const size_t pre_count_success);

    template <class _LpmTableType, class _EmTableType, class _RouteEntryVec, class _LpmEntriesBulk>
    la_status ip_lpm_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                  const std::shared_ptr<_EmTableType>& em_table,
                                  _RouteEntryVec& route_entry_vec,
                                  _LpmEntriesBulk& lpm_entries_bulk,
                                  const uint32_t start_batch,
                                  const uint32_t end_batch,
                                  size_t& out_count_success);
    template <class _LpmTableType, class _EmTableType, class _RouteEntryVec>
    la_status ip_em_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                const std::shared_ptr<_EmTableType>& em_table,
                                _RouteEntryVec& route_entry_vec,
                                const uint32_t index,
                                size_t& out_count_success);
    template <class _LpmTableType, class _EmTableType, class _RouteEntryVec, class _LpmEntriesBulk, class _LpmBulkPfx>
    la_status ip_route_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                    const std::shared_ptr<_EmTableType>& em_table,
                                    _RouteEntryVec& route_entry_vec,
                                    _LpmEntriesBulk& lpm_entries_bulk,
                                    _LpmBulkPfx& lpm_bulk_pfx,
                                    size_t& out_count_success);

    template <class _TableType, class _PrefixType>
    la_status update_ip_subnet(const std::shared_ptr<_TableType>& table, _PrefixType subnet, const la_l3_port_wcptr& l3_port);

    template <class _TableType>
    la_status get_all_ipv4_lpm_routes(std::shared_ptr<_TableType>& table, la_ipv4_route_entry_vec& out_route_entries);
    la_status get_all_ipv4_em_routes(std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& v4_em_table,
                                     la_ipv4_route_entry_vec& out_route_entries);

    template <class _TableType>
    la_status get_all_ipv6_lpm_routes(std::shared_ptr<_TableType>& table, la_ipv6_route_entry_vec& out_route_entries);
    la_status get_all_ipv6_em_routes(std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& v6_em_table,
                                     la_ipv6_route_entry_vec& out_route_entries);
};

} // namespace silicon_one

#endif // __LA_VRF_IMPL_H__
