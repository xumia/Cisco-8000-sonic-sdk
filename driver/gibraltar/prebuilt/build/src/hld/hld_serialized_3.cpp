#define AUTO_SERIALIZE_CODE
#include "common/cereal_utils.h"

#ifdef CEREAL_DISABLE_OPTIMIZATION
// Disable optimizations as clang, GCC choke on this file in -O3 mode.
#ifdef __GNUC__
    #ifdef __clang__
        #pragma clang optimize off
    #else
        #pragma GCC optimize ("O0")
    #endif
#endif
#endif
#if CEREAL_MODE == CEREAL_MODE_BINARY
#include <cereal/archives/binary.hpp>
#elif CEREAL_MODE == CEREAL_MODE_JSON
#include <cereal/archives/json.hpp>
#elif CEREAL_MODE == CEREAL_MODE_XML
#include <cereal/archives/xml.hpp>
#endif
#include <cereal/types/array.hpp>
#include <cereal/types/atomic.hpp>
#include <cereal/types/base_class.hpp>
#include <cereal/types/bitset.hpp>
#include <cereal/types/chrono.hpp>
#include <cereal/types/forward_list.hpp>
#include <cereal/types/functional.hpp>
#include <cereal/types/list.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/types/queue.hpp>
#include <cereal/types/set.hpp>
#include <cereal/types/stack.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/utility.hpp>
#include <cereal/types/vector.hpp>

#include "hld/runtime_flexibility_library.h"
#include "hld/runtime_flexibility_types.h"
#include "cgm/la_voq_cgm_evicted_profile_impl.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "hld_serialization.h"
#include "hld_types.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_generic.h"
#include "npu/la_acl_security_group.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ip_tunnel_destination_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_mldp_vpn_decap_impl.h"
#include "npu/la_mpls_vpn_decap_impl.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_redirect_destination_impl.h"
#include "npu/mc_copy_id_manager.h"
#include "npu/resolution_configurator.h"
#include "npu/resolution_configurator_impl.h"
#include "qos/la_meter_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "qos/la_meter_set_statistical_impl.h"
#include "system/arc_handler_gibraltar.h"
#include "system/counter_bank_utils.h"
#include "system/counter_logical_bank.h"
#include "system/counter_manager.h"
#include "system/gibraltar_mac_pool.h"
#include "system/gibraltar_pvt_handler.h"
#include "system/la_device_impl.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_flow_cache_handler_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/mac_pool8_port.h"
#include "system/npu_static_config.h"
#include "system/srm_serdes_device_handler.h"
#include "system/srm_serdes_handler.h"
#include "tm/la_logical_port_scheduler_impl.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/la_system_port_scheduler_impl.h"
#include "tm/la_voq_set_impl.h"
#include "tm/restricted_voq_set_impl.h"
#include "tm/tm_utils.h"
#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/voq_cgm_handler.h"
#include "ifg_use_count.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/ipv4_tunnel_ep_manager.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_egress_sec_ipv4.h"
#include "npu/la_acl_egress_sec_ipv6.h"
#include "npu/la_acl_impl.h"
#include "npu/la_acl_scaled_delegate.h"
#include "npu/la_acl_scaled_impl.h"
#include "npu/la_asbr_lsp_impl.h"
#include "npu/la_fabric_multicast_group_impl.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_forus_destination_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_lpts_impl.h"
#include "npu/la_lsr_impl.h"
#include "npu/la_mpls_label_destination_impl.h"
#include "npu/la_mpls_multicast_group_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_mpls_vpn_encap_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_og_lpts_application_impl.h"
#include "npu/la_pbts_group_impl.h"
#include "npu/la_pcl_impl.h"
#include "npu/la_switch_impl.h"
#include "npu/la_te_tunnel_impl.h"
#include "npu/mac_address_manager.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_action_profile_impl.h"
#include "qos/la_meter_markdown_profile_impl.h"
#include "qos/la_meter_set_exact_impl.h"
#include "system/counter_allocation.h"
#include "system/cud_range_manager.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_pbts_map_profile_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/mac_pool_port.h"
#include "system/pvt_handler.h"
#include "system/ranged_sequential_indices_generator.h"
#include "system/reconnect_handler.h"
#include "system/reconnect_metadata.h"
#include "system/resource_handler.h"
#include "system/serdes_device_handler.h"
#include "tm/la_fabric_port_scheduler_impl.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/voq_counter_set.h"
#include "../device_context/la_slice_mapper_base.h"
#include "npu/copc_protocol_manager_base.h"
#include "npu/copc_protocol_manager_gibraltar.h"
#include "npu/la_acl_command_profile_base.h"
#include "npu/la_acl_group_base.h"
#include "npu/la_acl_group_gibraltar.h"
#include "npu/la_acl_key_profile_base.h"
#include "npu/la_acl_key_profile_gibraltar.h"
#include "npu/la_bfd_session_base.h"
#include "npu/la_bfd_session_gibraltar.h"
#include "npu/la_copc_base.h"
#include "npu/la_copc_gibraltar.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ethernet_port_gibraltar.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_ip_multicast_group_gibraltar.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_multicast_group_gibraltar.h"
#include "npu/la_l2_protection_group_base.h"
#include "npu/la_l2_protection_group_gibraltar.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l2_service_port_gibraltar.h"
#include "npu/la_l2_service_port_pacgb.h"
#include "npu/la_multicast_group_common_base.h"
#include "npu/la_multicast_group_common_gibraltar.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_next_hop_gibraltar.h"
#include "npu/la_next_hop_pacgb.h"
#include "npu/la_prefix_object_base.h"
#include "npu/la_prefix_object_gibraltar.h"
#include "npu/la_rate_limiter_set_base.h"
#include "npu/la_rate_limiter_set_gibraltar.h"
#include "npu/la_security_group_cell_base.h"
#include "npu/la_security_group_cell_gibraltar.h"
#include "npu/la_stack_port_base.h"
#include "npu/la_stack_port_gibraltar.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_svi_port_gibraltar.h"
#include "npu/la_vrf_port_common_base.h"
#include "npu/la_vrf_port_common_gibraltar.h"
#include "npu/la_vrf_port_common_pacgb.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "npu/la_vxlan_next_hop_gibraltar.h"
#include "qos/la_meter_set_base.h"
#include "system/arc_handler_base.h"
#include "system/device_configurator_base.h"
#include "system/device_port_handler_base.h"
#include "system/device_port_handler_gibraltar.h"
#include "system/dummy_serdes_device_handler_base.h"
#include "system/dummy_serdes_handler_base.h"
#include "system/hld_notification_base.h"
#include "system/hld_notification_gibraltar.h"
#include "system/ifg_handler.h"
#include "system/ifg_handler_base.h"
#include "system/ifg_handler_gibraltar.h"
#include "system/ifg_handler_ifg.h"
#include "system/init_performance_helper_base.h"
#include "system/la_device_impl_base.h"
#include "system/la_erspan_mirror_command_base.h"
#include "system/la_erspan_mirror_command_gibraltar.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/la_l2_mirror_command_gibraltar.h"
#include "system/la_l2_mirror_command_pacgb.h"
#include "system/la_mac_port_base.h"
#include "system/la_mac_port_gibraltar.h"
#include "system/la_mac_port_pacgb.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_npu_host_port_gibraltar.h"
#include "system/la_pci_port_base.h"
#include "system/la_pci_port_gibraltar.h"
#include "system/la_ptp_handler_base.h"
#include "system/la_ptp_handler_gibraltar.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_punt_inject_port_gibraltar.h"
#include "system/la_punt_inject_port_pacgb.h"
#include "system/la_recycle_port_base.h"
#include "system/la_recycle_port_gibraltar.h"
#include "system/la_remote_device_base.h"
#include "system/la_spa_port_base.h"
#include "system/la_spa_port_gibraltar.h"
#include "system/la_spa_port_pacgb.h"
#include "system/la_system_port_base.h"
#include "system/la_system_port_gibraltar.h"
#include "system/la_system_port_pacgb.h"
#include "system/npu_host_event_queue_base.h"
#include "system/npu_host_event_queue_gibraltar.h"
#include "system/serdes_handler.h"
#include "system/slice_id_manager_base.h"
#include "system/slice_id_manager_gibraltar.h"
#include "system/slice_manager_smart_ptr_base.h"
#include "system/slice_mapping_base.h"
#include "tm/la_voq_set_base.h"

template <class T>
static T&
cereal_gen_remove_const(const T& t)
{
    return const_cast<T&>(t);
}

#define CEREAL_GEN_COPY_ARRAY(from, to, size) \
for (size_t i = 0; i < size; ++i) {\
    to[i] = from[i];\
}

#define CEREAL_GEN_COMMA() ,
namespace cereal {
    template <class Archive, class T>
    struct specialize<Archive, silicon_one::fixed_deque<T>, specialization::member_serialize> {};
}
#include "api/tm/la_unicast_tc_profile.h"
#include "apb/apb.h"
#include "cpu2jtag/cpu2jtag.h"
#include "system/cud_range_manager.h"
#include "system/reconnect_handler.h"
#include "system/resource_handler.h"
#include "system/counter_allocation.h"
#include "npu/mc_copy_id_manager.h"
#include "cgm/voq_cgm_handler.h"
#include "ra/resource_manager.h"
#include "cgm/la_voq_cgm_evicted_profile_impl.h"
#include "lld/pacific_tree.h"
#include <cereal/types/boost_variant.hpp> // needed for supporting serialization of boost::variant
namespace cereal {
    template <class Archive> static void save(Archive&, const boost::blank&) {}
    template <class Archive> static void load(Archive&, boost::blank&) {}
}
// Manulal registration of polymorphic templates, not supported by the tool
namespace cereal {
template <class Archive> void save(Archive&, const silicon_one::delayed_ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::delayed_ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::bfd_packet_intervals&);
template <class Archive> void load(Archive&, silicon_one::bfd_packet_intervals&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const bfd_rx_entry_data_t&);
template <class Archive> void load(Archive&, bfd_rx_entry_data_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::oam_encap_info_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::oam_encap_info_t&);

template <class Archive> void save(Archive&, const npl_lpts_payload_t&);
template <class Archive> void load(Archive&, npl_lpts_payload_t&);

template <class Archive> void save(Archive&, const l2_slp_acl_info_t&);
template <class Archive> void load(Archive&, l2_slp_acl_info_t&);

template <class Archive> void save(Archive&, const silicon_one::acl_group_info_t&);
template <class Archive> void load(Archive&, silicon_one::acl_group_info_t&);

}

CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::ipv4_sip_index_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::l3vxlan_smac_msb_index_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::npu_host_max_ccm_counters_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::npu_host_packet_intervals_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::bfd_local_ipv6_addresses_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::npu_host_detection_times_profile_allocator)
// The tool does generate a proper registration for profile_allocators::lpts_meters_profile_allocator
//CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::lpts_meters_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::lpts_em_entries_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::bfd_rx_entries_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::oam_punt_encap_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::voq_probability_profile_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::l2_slp_acl_indices_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::acl_group_entries_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_ipv4_prefix_t>,
			             silicon_one::la_device_impl::profile_allocators::ipv4_sip_index_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<la_uint32_t>,
                                     silicon_one::la_device_impl::profile_allocators::l3vxlan_smac_msb_index_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<std::chrono::microseconds>,
                                     silicon_one::la_device_impl::profile_allocators::npu_host_max_ccm_counters_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::bfd_packet_intervals>,
                                     silicon_one::la_device_impl::profile_allocators::npu_host_packet_intervals_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_ipv6_addr_t>,
                                     silicon_one::la_device_impl::profile_allocators::bfd_local_ipv6_addresses_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<std::chrono::microseconds>,
                                     silicon_one::la_device_impl::profile_allocators::npu_host_detection_times_profile_allocator)
//CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_meter_set_wcptr>,
//                                     silicon_one::la_device_impl::profile_allocators::lpts_meters_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_device_impl::profile_allocators::lpts_em_entry_data>,
                                     silicon_one::la_device_impl::profile_allocators::lpts_em_entries_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<bfd_rx_entry_data_t>,
                                     silicon_one::la_device_impl::profile_allocators::bfd_rx_entries_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_device_impl::oam_encap_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::oam_punt_encap_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<double>,
                                     silicon_one::la_device_impl::profile_allocators::voq_probability_profile_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<l2_slp_acl_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::l2_slp_acl_indices_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::acl_group_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::acl_group_entries_profile_allocator)
#include "hld/hld_serialized_fwd_declarations.h"

namespace cereal {

extern unsigned g_hld_serialization_version;

template <class Archive> void save(Archive&, const boost::blank&);
template <class Archive> void load(Archive&, boost::blank&);

template <class Archive> void save(Archive&, const la_slice_ifg&);
template <class Archive> void load(Archive&, la_slice_ifg&);

template <class Archive> void save(Archive&, const npl_meter_weight_t&);
template <class Archive> void load(Archive&, npl_meter_weight_t&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_impl&);
template <class Archive> void load(Archive&, silicon_one::la_acl_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_ip_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l2_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_fec&);
template <class Archive> void load(Archive&, silicon_one::la_l3_fec&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_protection_group&);
template <class Archive> void load(Archive&, silicon_one::la_l3_protection_group&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_action_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_action_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_base&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_base&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_exact_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_exact_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_statistical_impl::meter_token_size_data&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_statistical_impl::meter_token_size_data&);

template <class Archive> void save(Archive&, const silicon_one::la_mldp_vpn_decap&);
template <class Archive> void load(Archive&, silicon_one::la_mldp_vpn_decap&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_vpn_decap&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_vpn_decap&);

template <class Archive> void save(Archive&, const silicon_one::la_object&);
template <class Archive> void load(Archive&, silicon_one::la_object&);

template <class Archive> void save(Archive&, const silicon_one::la_protection_monitor&);
template <class Archive> void load(Archive&, silicon_one::la_protection_monitor&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf&);
template <class Archive> void load(Archive&, silicon_one::la_vrf&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_redirect_destination&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_redirect_destination&);

template <class Archive> void save(Archive&, const silicon_one::npl_ipv4_lpm_table_functional_traits_t&);
template <class Archive> void load(Archive&, silicon_one::npl_ipv4_lpm_table_functional_traits_t&);

template <class Archive> void save(Archive&, const silicon_one::npl_ipv6_lpm_table_functional_traits_t&);
template <class Archive> void load(Archive&, silicon_one::npl_ipv6_lpm_table_functional_traits_t&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template<>
class serializer_class<silicon_one::la_l3_ac_port_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l3_ac_port_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("lp_attributes_entry", m.lp_attributes_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l3_ac_port_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("lp_attributes_entry", m.lp_attributes_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l3_ac_port_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_l3_ac_port_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l3_ac_port_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l3_ac_port_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_l3_ac_port_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l3_ac_port_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_l3_fec_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l3_fec_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_is_wrapper", m.m_is_wrapper));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_destination", m.m_l3_destination));
            archive(::cereal::make_nvp("m_l2_destination", m.m_l2_destination));
            archive(::cereal::make_nvp("m_fec_table_entry", m.m_fec_table_entry));
            archive(::cereal::make_nvp("m_rpf_fec_table_entry", m.m_rpf_fec_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l3_fec_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_is_wrapper", m.m_is_wrapper));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_destination", m.m_l3_destination));
            archive(::cereal::make_nvp("m_l2_destination", m.m_l2_destination));
            archive(::cereal::make_nvp("m_fec_table_entry", m.m_fec_table_entry));
            archive(::cereal::make_nvp("m_rpf_fec_table_entry", m.m_rpf_fec_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l3_fec_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l3_fec>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l3_fec_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l3_fec_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l3_fec_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l3_fec>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l3_fec_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l3_fec_impl&);



template<>
class serializer_class<silicon_one::la_l3_protection_group_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l3_protection_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_primary_destination", m.m_primary_destination));
            archive(::cereal::make_nvp("m_backup_destination", m.m_backup_destination));
            archive(::cereal::make_nvp("m_protection_monitor", m.m_protection_monitor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l3_protection_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_primary_destination", m.m_primary_destination));
            archive(::cereal::make_nvp("m_backup_destination", m.m_backup_destination));
            archive(::cereal::make_nvp("m_protection_monitor", m.m_protection_monitor));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l3_protection_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l3_protection_group>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l3_protection_group_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l3_protection_group_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l3_protection_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l3_protection_group>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l3_protection_group_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l3_protection_group_impl&);



template<>
class serializer_class<silicon_one::la_mldp_vpn_decap_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mldp_vpn_decap_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_rpfid", m.m_rpfid));
            archive(::cereal::make_nvp("m_bud_node", m.m_bud_node));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mldp_vpn_decap_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_rpfid", m.m_rpfid));
            archive(::cereal::make_nvp("m_bud_node", m.m_bud_node));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mldp_vpn_decap_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mldp_vpn_decap>(&m));
    serializer_class<silicon_one::la_mldp_vpn_decap_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mldp_vpn_decap_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mldp_vpn_decap_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mldp_vpn_decap>(&m));
    serializer_class<silicon_one::la_mldp_vpn_decap_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mldp_vpn_decap_impl&);



template<>
class serializer_class<silicon_one::la_mldp_vpn_decap_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mldp_vpn_decap_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("m_mldp_termination_entry", m.m_mldp_termination_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mldp_vpn_decap_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("m_mldp_termination_entry", m.m_mldp_termination_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mldp_vpn_decap_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_mldp_vpn_decap_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mldp_vpn_decap_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mldp_vpn_decap_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_mldp_vpn_decap_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mldp_vpn_decap_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_mpls_vpn_decap_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_vpn_decap_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_vpn_decap_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_vpn_decap_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_vpn_decap>(&m));
    serializer_class<silicon_one::la_mpls_vpn_decap_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_vpn_decap_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_vpn_decap_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_vpn_decap>(&m));
    serializer_class<silicon_one::la_mpls_vpn_decap_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_vpn_decap_impl&);



template<>
class serializer_class<silicon_one::la_mpls_vpn_decap_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_vpn_decap_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("m_mpls_termination_entry", m.m_mpls_termination_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_vpn_decap_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("m_mpls_termination_entry", m.m_mpls_termination_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_vpn_decap_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_mpls_vpn_decap_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_vpn_decap_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_vpn_decap_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_mpls_vpn_decap_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_vpn_decap_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_protection_monitor_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_protection_monitor_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_stage0_cfg_handle", m.m_stage0_cfg_handle));
            archive(::cereal::make_nvp("m_stage1_cfg_handle", m.m_stage1_cfg_handle));
            archive(::cereal::make_nvp("m_state", m.m_state));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_protection_monitor_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_stage0_cfg_handle", m.m_stage0_cfg_handle));
            archive(::cereal::make_nvp("m_stage1_cfg_handle", m.m_stage1_cfg_handle));
            archive(::cereal::make_nvp("m_state", m.m_state));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_protection_monitor_impl& m)
{
    archive(cereal::base_class<silicon_one::la_protection_monitor>(&m));
    serializer_class<silicon_one::la_protection_monitor_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_protection_monitor_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_protection_monitor_impl& m)
{
    archive(cereal::base_class<silicon_one::la_protection_monitor>(&m));
    serializer_class<silicon_one::la_protection_monitor_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_protection_monitor_impl&);



template<>
class serializer_class<silicon_one::la_protection_monitor_impl::resolution_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_protection_monitor_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_protection_monitor_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_protection_monitor_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_protection_monitor_impl::resolution_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_protection_monitor_impl::resolution_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_protection_monitor_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_protection_monitor_impl::resolution_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_protection_monitor_impl::resolution_data&);



template<>
class serializer_class<silicon_one::la_vrf_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ipv4_implicit_mc_catch_all_configured", m.m_ipv4_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv6_implicit_mc_catch_all_configured", m.m_ipv6_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv4_em_entries", m.m_ipv4_em_entries));
            archive(::cereal::make_nvp("m_ipv6_em_entries", m.m_ipv6_em_entries));
            archive(::cereal::make_nvp("m_ipv4_mc_route_desc_map", m.m_ipv4_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv6_mc_route_desc_map", m.m_ipv6_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv4_bulk_entries_vec", m.m_ipv4_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv6_bulk_entries_vec", m.m_ipv6_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv4_bulk_prefix_set", m.m_ipv4_bulk_prefix_set));
            archive(::cereal::make_nvp("m_ipv6_bulk_prefix_set", m.m_ipv6_bulk_prefix_set));
            archive(::cereal::make_nvp("m_urpf_allow_default", m.m_urpf_allow_default));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_fallback_vrf", m.m_fallback_vrf));
            archive(::cereal::make_nvp("m_ipv4_default_entry", m.m_ipv4_default_entry));
            archive(::cereal::make_nvp("m_ipv6_default_entry", m.m_ipv6_default_entry));
            archive(::cereal::make_nvp("m_pbr_v4_acl", m.m_pbr_v4_acl));
            archive(::cereal::make_nvp("m_pbr_v6_acl", m.m_pbr_v6_acl));
            archive(::cereal::make_nvp("m_bulk_old_destinations", m.m_bulk_old_destinations));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ipv4_implicit_mc_catch_all_configured", m.m_ipv4_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv6_implicit_mc_catch_all_configured", m.m_ipv6_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv4_em_entries", m.m_ipv4_em_entries));
            archive(::cereal::make_nvp("m_ipv6_em_entries", m.m_ipv6_em_entries));
            archive(::cereal::make_nvp("m_ipv4_mc_route_desc_map", m.m_ipv4_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv6_mc_route_desc_map", m.m_ipv6_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv4_bulk_entries_vec", m.m_ipv4_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv6_bulk_entries_vec", m.m_ipv6_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv4_bulk_prefix_set", m.m_ipv4_bulk_prefix_set));
            archive(::cereal::make_nvp("m_ipv6_bulk_prefix_set", m.m_ipv6_bulk_prefix_set));
            archive(::cereal::make_nvp("m_urpf_allow_default", m.m_urpf_allow_default));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_fallback_vrf", m.m_fallback_vrf));
            archive(::cereal::make_nvp("m_ipv4_default_entry", m.m_ipv4_default_entry));
            archive(::cereal::make_nvp("m_ipv6_default_entry", m.m_ipv6_default_entry));
            archive(::cereal::make_nvp("m_pbr_v4_acl", m.m_pbr_v4_acl));
            archive(::cereal::make_nvp("m_pbr_v6_acl", m.m_pbr_v6_acl));
            archive(::cereal::make_nvp("m_bulk_old_destinations", m.m_bulk_old_destinations));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl& m)
{
    archive(cereal::base_class<silicon_one::la_vrf>(&m));
    serializer_class<silicon_one::la_vrf_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl& m)
{
    archive(cereal::base_class<silicon_one::la_vrf>(&m));
    serializer_class<silicon_one::la_vrf_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl&);



template<>
class serializer_class<silicon_one::la_vrf_impl::ip_em_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::ip_em_entry& m) {
            archive(::cereal::make_nvp("user_data", m.user_data));
            archive(::cereal::make_nvp("dest", m.dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::ip_em_entry& m) {
            archive(::cereal::make_nvp("user_data", m.user_data));
            archive(::cereal::make_nvp("dest", m.dest));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::ip_em_entry& m)
{
    serializer_class<silicon_one::la_vrf_impl::ip_em_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::ip_em_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::ip_em_entry& m)
{
    serializer_class<silicon_one::la_vrf_impl::ip_em_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::ip_em_entry&);



template<>
class serializer_class<silicon_one::la_vrf_impl::mc_route_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::mc_route_desc& m) {
            archive(::cereal::make_nvp("punt_on_rpf_fail", m.punt_on_rpf_fail));
            archive(::cereal::make_nvp("punt_and_forward", m.punt_and_forward));
            archive(::cereal::make_nvp("v6_compressed_sip", m.v6_compressed_sip));
            archive(::cereal::make_nvp("use_rpfid", m.use_rpfid));
            archive(::cereal::make_nvp("rpfid", m.rpfid));
            archive(::cereal::make_nvp("enable_rpf_check", m.enable_rpf_check));
            archive(::cereal::make_nvp("mcg", m.mcg));
            archive(::cereal::make_nvp("rpf", m.rpf));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::mc_route_desc& m) {
            archive(::cereal::make_nvp("punt_on_rpf_fail", m.punt_on_rpf_fail));
            archive(::cereal::make_nvp("punt_and_forward", m.punt_and_forward));
            archive(::cereal::make_nvp("v6_compressed_sip", m.v6_compressed_sip));
            archive(::cereal::make_nvp("use_rpfid", m.use_rpfid));
            archive(::cereal::make_nvp("rpfid", m.rpfid));
            archive(::cereal::make_nvp("enable_rpf_check", m.enable_rpf_check));
            archive(::cereal::make_nvp("mcg", m.mcg));
            archive(::cereal::make_nvp("rpf", m.rpf));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::mc_route_desc& m)
{
    serializer_class<silicon_one::la_vrf_impl::mc_route_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::mc_route_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::mc_route_desc& m)
{
    serializer_class<silicon_one::la_vrf_impl::mc_route_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::mc_route_desc&);



template<>
class serializer_class<silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t&);



template<>
class serializer_class<silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t&);



template<>
class serializer_class<silicon_one::la_vrf_redirect_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_redirect_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_redirect_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_redirect_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_vrf_redirect_destination>(&m));
    serializer_class<silicon_one::la_vrf_redirect_destination_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_redirect_destination_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_redirect_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_vrf_redirect_destination>(&m));
    serializer_class<silicon_one::la_vrf_redirect_destination_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_redirect_destination_impl&);



template<>
class serializer_class<silicon_one::mc_copy_id_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mc_copy_id_manager& m) {
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_index_gen", m.m_index_gen));
            archive(::cereal::make_nvp("m_entries", m.m_entries));
            archive(::cereal::make_nvp("m_stack_mc_copyid", m.m_stack_mc_copyid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mc_copy_id_manager& m) {
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_index_gen", m.m_index_gen));
            archive(::cereal::make_nvp("m_entries", m.m_entries));
            archive(::cereal::make_nvp("m_stack_mc_copyid", m.m_stack_mc_copyid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mc_copy_id_manager& m)
{
    serializer_class<silicon_one::mc_copy_id_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mc_copy_id_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::mc_copy_id_manager& m)
{
    serializer_class<silicon_one::mc_copy_id_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mc_copy_id_manager&);



template<>
class serializer_class<silicon_one::resolution_assoc_data_table_addr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_assoc_data_table_addr_t& m) {
            archive(::cereal::make_nvp("index", m.index));
            archive(::cereal::make_nvp("select", m.select));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_assoc_data_table_addr_t& m) {
            archive(::cereal::make_nvp("index", m.index));
            archive(::cereal::make_nvp("select", m.select));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_assoc_data_table_addr_t& m)
{
    serializer_class<silicon_one::resolution_assoc_data_table_addr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_assoc_data_table_addr_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_assoc_data_table_addr_t& m)
{
    serializer_class<silicon_one::resolution_assoc_data_table_addr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_assoc_data_table_addr_t&);



template<>
class serializer_class<silicon_one::resolution_cfg_handle_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_cfg_handle_t& m) {
            archive(::cereal::make_nvp("stage_index", m.stage_index));
            archive(::cereal::make_nvp("common_data", m.common_data));
            archive(::cereal::make_nvp("ad_entry_addr", m.ad_entry_addr));
            archive(::cereal::make_nvp("in_stage_dest", m.in_stage_dest));
            archive(::cereal::make_nvp("ad_table_entry", m.ad_table_entry));
            archive(::cereal::make_nvp("em_table_entry", m.em_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_cfg_handle_t& m) {
            archive(::cereal::make_nvp("stage_index", m.stage_index));
            archive(::cereal::make_nvp("common_data", m.common_data));
            archive(::cereal::make_nvp("ad_entry_addr", m.ad_entry_addr));
            archive(::cereal::make_nvp("in_stage_dest", m.in_stage_dest));
            archive(::cereal::make_nvp("ad_table_entry", m.ad_table_entry));
            archive(::cereal::make_nvp("em_table_entry", m.em_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_cfg_handle_t& m)
{
    serializer_class<silicon_one::resolution_cfg_handle_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_cfg_handle_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_cfg_handle_t& m)
{
    serializer_class<silicon_one::resolution_cfg_handle_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_cfg_handle_t&);



template<>
class serializer_class<silicon_one::resolution_configurator> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_configurator& m) {
            archive(::cereal::make_nvp("m_stage0_impl", m.m_stage0_impl));
            archive(::cereal::make_nvp("m_stage1_impl", m.m_stage1_impl));
            archive(::cereal::make_nvp("m_stage2_impl", m.m_stage2_impl));
            archive(::cereal::make_nvp("m_stage3_impl", m.m_stage3_impl));
            archive(::cereal::make_nvp("m_stage", m.m_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_configurator& m) {
            archive(::cereal::make_nvp("m_stage0_impl", m.m_stage0_impl));
            archive(::cereal::make_nvp("m_stage1_impl", m.m_stage1_impl));
            archive(::cereal::make_nvp("m_stage2_impl", m.m_stage2_impl));
            archive(::cereal::make_nvp("m_stage3_impl", m.m_stage3_impl));
            archive(::cereal::make_nvp("m_stage", m.m_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_configurator& m)
{
    serializer_class<silicon_one::resolution_configurator>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_configurator&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_configurator& m)
{
    serializer_class<silicon_one::resolution_configurator>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_configurator&);



template<>
class serializer_class<silicon_one::resolution_ad_entry_allocator> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_ad_entry_allocator& m) {
            archive(::cereal::make_nvp("m_table_size", m.m_table_size));
            archive(::cereal::make_nvp("m_occupied_lines", m.m_occupied_lines));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_ad_entry_allocator& m) {
            archive(::cereal::make_nvp("m_table_size", m.m_table_size));
            archive(::cereal::make_nvp("m_occupied_lines", m.m_occupied_lines));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_ad_entry_allocator& m)
{
    serializer_class<silicon_one::resolution_ad_entry_allocator>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_ad_entry_allocator&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_ad_entry_allocator& m)
{
    serializer_class<silicon_one::resolution_ad_entry_allocator>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_ad_entry_allocator&);



template<>
class serializer_class<silicon_one::resolution_ad_entry_allocator::ad_table_line_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_ad_entry_allocator::ad_table_line_t& m) {
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("allocated_entries_mask", m.allocated_entries_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_ad_entry_allocator::ad_table_line_t& m) {
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("allocated_entries_mask", m.allocated_entries_mask));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_ad_entry_allocator::ad_table_line_t& m)
{
    serializer_class<silicon_one::resolution_ad_entry_allocator::ad_table_line_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_ad_entry_allocator::ad_table_line_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_ad_entry_allocator::ad_table_line_t& m)
{
    serializer_class<silicon_one::resolution_ad_entry_allocator::ad_table_line_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_ad_entry_allocator::ad_table_line_t&);



template<>
class serializer_class<silicon_one::la_meter_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_profile_impl& m) {
            archive(::cereal::make_nvp("m_ifg_data", m.m_ifg_data));
            archive(::cereal::make_nvp("m_stat_bank_data", m.m_stat_bank_data));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_measure_mode", m.m_measure_mode));
            archive(::cereal::make_nvp("m_rate_mode", m.m_rate_mode));
            archive(::cereal::make_nvp("m_color_awareness", m.m_color_awareness));
            archive(::cereal::make_nvp("m_cascade_mode", m.m_cascade_mode));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_profile_impl& m) {
            archive(::cereal::make_nvp("m_ifg_data", m.m_ifg_data));
            archive(::cereal::make_nvp("m_stat_bank_data", m.m_stat_bank_data));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_measure_mode", m.m_measure_mode));
            archive(::cereal::make_nvp("m_rate_mode", m.m_rate_mode));
            archive(::cereal::make_nvp("m_color_awareness", m.m_color_awareness));
            archive(::cereal::make_nvp("m_cascade_mode", m.m_cascade_mode));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_profile_impl&);



template<>
class serializer_class<silicon_one::la_meter_profile_impl::allocation_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_profile_impl::allocation_data& m) {
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("ebs_or_pbs", m.ebs_or_pbs));
            archive(::cereal::make_nvp("profile_index", m.profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_profile_impl::allocation_data& m) {
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("ebs_or_pbs", m.ebs_or_pbs));
            archive(::cereal::make_nvp("profile_index", m.profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_profile_impl::allocation_data& m)
{
    serializer_class<silicon_one::la_meter_profile_impl::allocation_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_profile_impl::allocation_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_profile_impl::allocation_data& m)
{
    serializer_class<silicon_one::la_meter_profile_impl::allocation_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_profile_impl::allocation_data&);



template<>
class serializer_class<silicon_one::la_meter_profile_impl::stat_bank_allocation_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile_impl::allocation_data>(&m));
    serializer_class<silicon_one::la_meter_profile_impl::stat_bank_allocation_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_profile_impl::stat_bank_allocation_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile_impl::allocation_data>(&m));
    serializer_class<silicon_one::la_meter_profile_impl::stat_bank_allocation_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_profile_impl::stat_bank_allocation_data&);



template<>
class serializer_class<silicon_one::la_meter_set_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_impl& m) {
            archive(::cereal::make_nvp("SINGLE_ALLOCATION_SLICE_IFG", m.SINGLE_ALLOCATION_SLICE_IFG));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_meter_type", m.m_meter_type));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_meters_properties", m.m_meters_properties));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_lpts_entry_meter", m.m_lpts_entry_meter));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_user_to_aggregation", m.m_user_to_aggregation));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_impl& m) {
            archive(::cereal::make_nvp("SINGLE_ALLOCATION_SLICE_IFG", m.SINGLE_ALLOCATION_SLICE_IFG));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_meter_type", m.m_meter_type));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_meters_properties", m.m_meters_properties));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_lpts_entry_meter", m.m_lpts_entry_meter));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_user_to_aggregation", m.m_user_to_aggregation));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_base>(&m));
    serializer_class<silicon_one::la_meter_set_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_base>(&m));
    serializer_class<silicon_one::la_meter_set_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_impl&);



template<>
class serializer_class<silicon_one::la_meter_set_impl::meter_properties> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_impl::meter_properties& m) {
            archive(::cereal::make_nvp("coupling_mode", m.coupling_mode));
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
            archive(::cereal::make_nvp("eir_weight", m.eir_weight));
            archive(::cereal::make_nvp("user_cir", m.user_cir));
            archive(::cereal::make_nvp("user_eir", m.user_eir));
            archive(::cereal::make_nvp("meter_offset_index", m.meter_offset_index));
            archive(::cereal::make_nvp("meter_profile", m.meter_profile));
            archive(::cereal::make_nvp("meter_action_profile", m.meter_action_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_impl::meter_properties& m) {
            archive(::cereal::make_nvp("coupling_mode", m.coupling_mode));
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
            archive(::cereal::make_nvp("eir_weight", m.eir_weight));
            archive(::cereal::make_nvp("user_cir", m.user_cir));
            archive(::cereal::make_nvp("user_eir", m.user_eir));
            archive(::cereal::make_nvp("meter_offset_index", m.meter_offset_index));
            archive(::cereal::make_nvp("meter_profile", m.meter_profile));
            archive(::cereal::make_nvp("meter_action_profile", m.meter_action_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_impl::meter_properties& m)
{
    serializer_class<silicon_one::la_meter_set_impl::meter_properties>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_impl::meter_properties&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_impl::meter_properties& m)
{
    serializer_class<silicon_one::la_meter_set_impl::meter_properties>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_impl::meter_properties&);



template<>
class serializer_class<silicon_one::la_meter_set_statistical_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_statistical_impl& m) {
            archive(::cereal::make_nvp("m_bank_index", m.m_bank_index));
            archive(::cereal::make_nvp("m_set_base_index", m.m_set_base_index));
            archive(::cereal::make_nvp("m_token_sizes", m.m_token_sizes));
            archive(::cereal::make_nvp("m_shaper_tokens_per_sec", m.m_shaper_tokens_per_sec));
            archive(::cereal::make_nvp("m_cached_packets", m.m_cached_packets));
            archive(::cereal::make_nvp("m_cached_bytes", m.m_cached_bytes));
            archive(::cereal::make_nvp("m_previous_hw_packets", m.m_previous_hw_packets));
            archive(::cereal::make_nvp("m_previous_hw_bytes", m.m_previous_hw_bytes));
            archive(::cereal::make_nvp("m_exact_meter_set_impl", m.m_exact_meter_set_impl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_statistical_impl& m) {
            archive(::cereal::make_nvp("m_bank_index", m.m_bank_index));
            archive(::cereal::make_nvp("m_set_base_index", m.m_set_base_index));
            archive(::cereal::make_nvp("m_token_sizes", m.m_token_sizes));
            archive(::cereal::make_nvp("m_shaper_tokens_per_sec", m.m_shaper_tokens_per_sec));
            archive(::cereal::make_nvp("m_cached_packets", m.m_cached_packets));
            archive(::cereal::make_nvp("m_cached_bytes", m.m_cached_bytes));
            archive(::cereal::make_nvp("m_previous_hw_packets", m.m_previous_hw_packets));
            archive(::cereal::make_nvp("m_previous_hw_bytes", m.m_previous_hw_bytes));
            archive(::cereal::make_nvp("m_exact_meter_set_impl", m.m_exact_meter_set_impl));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_statistical_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_impl>(&m));
    serializer_class<silicon_one::la_meter_set_statistical_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_statistical_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_statistical_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_impl>(&m));
    serializer_class<silicon_one::la_meter_set_statistical_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_statistical_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_l3_fec_impl var0;
    ar(var0);
    silicon_one::la_l3_protection_group_impl var1;
    ar(var1);
    silicon_one::la_mldp_vpn_decap_impl var2;
    ar(var2);
    silicon_one::la_mpls_vpn_decap_impl var3;
    ar(var3);
    silicon_one::la_protection_monitor_impl var4;
    ar(var4);
    silicon_one::la_vrf_impl var5;
    ar(var5);
    silicon_one::la_vrf_redirect_destination_impl var6;
    ar(var6);
    silicon_one::la_meter_profile_impl var7;
    ar(var7);
    silicon_one::la_meter_set_statistical_impl var8;
    ar(var8);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_l3_fec_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_l3_protection_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_mldp_vpn_decap_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_mpls_vpn_decap_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_protection_monitor_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_vrf_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_vrf_redirect_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_set_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_set_statistical_impl);

#pragma GCC diagnostic pop

