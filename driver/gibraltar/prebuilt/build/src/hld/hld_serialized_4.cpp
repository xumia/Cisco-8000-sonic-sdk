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

template <class Archive> void save(Archive&, const la_fabric_congested_links_thresholds&);
template <class Archive> void load(Archive&, la_fabric_congested_links_thresholds&);

template <class Archive> void save(Archive&, const la_fabric_valid_links_thresholds&);
template <class Archive> void load(Archive&, la_fabric_valid_links_thresholds&);

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const la_slice_ifg&);
template <class Archive> void load(Archive&, la_slice_ifg&);

template <class Archive> void save(Archive&, const runtime_flexibility_library&);
template <class Archive> void load(Archive&, runtime_flexibility_library&);

template <class Archive> void save(Archive&, const silicon_one::apb&);
template <class Archive> void load(Archive&, silicon_one::apb&);

template <class Archive> void save(Archive&, const silicon_one::arc_handler_base&);
template <class Archive> void load(Archive&, silicon_one::arc_handler_base&);

template <class Archive> void save(Archive&, const silicon_one::copc_protocol_manager_base&);
template <class Archive> void load(Archive&, silicon_one::copc_protocol_manager_base&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::cpu2jtag&);
template <class Archive> void load(Archive&, silicon_one::cpu2jtag&);

template <class Archive> void save(Archive&, const silicon_one::cud_range_manager&);
template <class Archive> void load(Archive&, silicon_one::cud_range_manager&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::destination_id&);
template <class Archive> void load(Archive&, silicon_one::destination_id&);

template <class Archive> void save(Archive&, const silicon_one::device_configurator_base&);
template <class Archive> void load(Archive&, silicon_one::device_configurator_base&);

template <class Archive> void save(Archive&, const silicon_one::device_port_handler_base&);
template <class Archive> void load(Archive&, silicon_one::device_port_handler_base&);

template <class Archive> void save(Archive&, const silicon_one::device_tables&);
template <class Archive> void load(Archive&, silicon_one::device_tables&);

template <class Archive> void save(Archive&, const silicon_one::gibraltar_tree&);
template <class Archive> void load(Archive&, silicon_one::gibraltar_tree&);

template <class Archive> void save(Archive&, const silicon_one::hld_notification_base&);
template <class Archive> void load(Archive&, silicon_one::hld_notification_base&);

template <class Archive> void save(Archive&, const silicon_one::ifg_handler&);
template <class Archive> void load(Archive&, silicon_one::ifg_handler&);

template <class Archive> void save(Archive&, const silicon_one::init_performance_helper_base&);
template <class Archive> void load(Archive&, silicon_one::init_performance_helper_base&);

template <class Archive> void save(Archive&, const silicon_one::ipv4_sip_index_manager&);
template <class Archive> void load(Archive&, silicon_one::ipv4_sip_index_manager&);

template <class Archive> void save(Archive&, const silicon_one::ipv4_tunnel_ep_manager&);
template <class Archive> void load(Archive&, silicon_one::ipv4_tunnel_ep_manager&);

template <class Archive> void save(Archive&, const silicon_one::la_ac_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ac_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl&);
template <class Archive> void load(Archive&, silicon_one::la_acl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_action_def&);
template <class Archive> void load(Archive&, silicon_one::la_acl_action_def&);

template <class Archive> void save(Archive&, const silicon_one::la_asbr_lsp&);
template <class Archive> void load(Archive&, silicon_one::la_asbr_lsp&);

template <class Archive> void save(Archive&, const silicon_one::la_bfd_session_base&);
template <class Archive> void load(Archive&, silicon_one::la_bfd_session_base&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_or_meter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_or_meter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_destination_pe&);
template <class Archive> void load(Archive&, silicon_one::la_destination_pe&);

template <class Archive> void save(Archive&, const silicon_one::la_device::la_heartbeat_t&);
template <class Archive> void load(Archive&, silicon_one::la_device::la_heartbeat_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::_index_generators&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::_index_generators&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::device_property_val&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::device_property_val&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::ipv4_tunnel_id_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::ipv4_tunnel_id_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::ipv6_compressed_sip_desc&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::ipv6_compressed_sip_desc&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::la_snoop_config_entry&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::la_snoop_config_entry&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::la_trap_config_entry&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::la_trap_config_entry&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::mc_allocated_mcid&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::mc_allocated_mcid&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::mldp_bud_info&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::mldp_bud_info&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::native_voq_set_desc&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::native_voq_set_desc&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::profile_allocators&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::profile_allocators&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::pwe_tagged_local_label_desc&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::pwe_tagged_local_label_desc&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::resource_monitors&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::resource_monitors&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::save_state_runtime&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::save_state_runtime&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::security_group_cell_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::security_group_cell_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::security_group_cell_t_lt&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::security_group_cell_t_lt&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::serdes_info_desc&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::serdes_info_desc&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::serdes_status&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::serdes_status&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::vsc_ownership_map_key&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::vsc_ownership_map_key&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::vsc_ownership_map_val&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::vsc_ownership_map_val&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::vxlan_nh_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::vxlan_nh_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::vxlan_vni_profile&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::vxlan_vni_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl_base&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl_base&);

template <class Archive> void save(Archive&, const silicon_one::la_egress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_egress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_multicast_group_impl&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_multicast_group_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_port_impl&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_port_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_filter_group_impl&);
template <class Archive> void load(Archive&, silicon_one::la_filter_group_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_flow_cache_handler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_flow_cache_handler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_forus_destination_impl&);
template <class Archive> void load(Archive&, silicon_one::la_forus_destination_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_hbm_handler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_hbm_handler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ifg_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ifg_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ingress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ingress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_multicast_group_gibraltar&);
template <class Archive> void load(Archive&, silicon_one::la_ip_multicast_group_gibraltar&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l2_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_multicast_group_gibraltar&);
template <class Archive> void load(Archive&, silicon_one::la_l2_multicast_group_gibraltar&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_punt_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l2_punt_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_service_port&);
template <class Archive> void load(Archive&, silicon_one::la_l2_service_port&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_protection_group&);
template <class Archive> void load(Archive&, silicon_one::la_l3_protection_group&);

template <class Archive> void save(Archive&, const silicon_one::la_lsr_impl&);
template <class Archive> void load(Archive&, silicon_one::la_lsr_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port_base::location&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port_base::location&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_action_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_action_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_markdown_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_markdown_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_multicast_group_impl&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_multicast_group_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_vpn_encap&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_vpn_encap&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_base&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_base&);

template <class Archive> void save(Archive&, const silicon_one::la_npu_host_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_npu_host_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_object&);
template <class Archive> void load(Archive&, silicon_one::la_object&);

template <class Archive> void save(Archive&, const silicon_one::la_pci_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_pci_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object&);

template <class Archive> void save(Archive&, const silicon_one::la_protection_monitor&);
template <class Archive> void load(Archive&, silicon_one::la_protection_monitor&);

template <class Archive> void save(Archive&, const silicon_one::la_ptp_handler_gibraltar&);
template <class Archive> void load(Archive&, silicon_one::la_ptp_handler_gibraltar&);

template <class Archive> void save(Archive&, const silicon_one::la_recycle_port_gibraltar&);
template <class Archive> void load(Archive&, silicon_one::la_recycle_port_gibraltar&);

template <class Archive> void save(Archive&, const silicon_one::la_rx_cgm_sq_profile&);
template <class Archive> void load(Archive&, silicon_one::la_rx_cgm_sq_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_security_group_cell&);
template <class Archive> void load(Archive&, silicon_one::la_security_group_cell&);

template <class Archive> void save(Archive&, const silicon_one::la_spa_port_gibraltar&);
template <class Archive> void load(Archive&, silicon_one::la_spa_port_gibraltar&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_gibraltar&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_gibraltar&);

template <class Archive> void save(Archive&, const silicon_one::la_tc_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_tc_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_te_tunnel&);
template <class Archive> void load(Archive&, silicon_one::la_te_tunnel&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_cgm_evicted_profile&);
template <class Archive> void load(Archive&, silicon_one::la_voq_cgm_evicted_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_cgm_profile&);
template <class Archive> void load(Archive&, silicon_one::la_voq_cgm_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_set&);
template <class Archive> void load(Archive&, silicon_one::la_voq_set&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_voq_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_impl&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_redirect_destination&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_redirect_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_vxlan_next_hop&);
template <class Archive> void load(Archive&, silicon_one::la_vxlan_next_hop&);

template <class Archive> void save(Archive&, const silicon_one::lld_register&);
template <class Archive> void load(Archive&, silicon_one::lld_register&);

template <class Archive> void save(Archive&, const silicon_one::lld_register_array_container&);
template <class Archive> void load(Archive&, silicon_one::lld_register_array_container&);

template <class Archive> void save(Archive&, const silicon_one::mac_address_manager&);
template <class Archive> void load(Archive&, silicon_one::mac_address_manager&);

template <class Archive> void save(Archive&, const silicon_one::mac_pool_port&);
template <class Archive> void load(Archive&, silicon_one::mac_pool_port&);

template <class Archive> void save(Archive&, const silicon_one::mc_copy_id_manager&);
template <class Archive> void load(Archive&, silicon_one::mc_copy_id_manager&);

template <class Archive> void save(Archive&, const silicon_one::npu_host_event_queue_base&);
template <class Archive> void load(Archive&, silicon_one::npu_host_event_queue_base&);

template <class Archive> void save(Archive&, const silicon_one::pacific_tree&);
template <class Archive> void load(Archive&, silicon_one::pacific_tree&);

template <class Archive> void save(Archive&, const silicon_one::pvt_handler&);
template <class Archive> void load(Archive&, silicon_one::pvt_handler&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::reconnect_handler&);
template <class Archive> void load(Archive&, silicon_one::reconnect_handler&);

template <class Archive> void save(Archive&, const silicon_one::resolution_configurator&);
template <class Archive> void load(Archive&, silicon_one::resolution_configurator&);

template <class Archive> void save(Archive&, const silicon_one::resource_manager&);
template <class Archive> void load(Archive&, silicon_one::resource_manager&);

template <class Archive> void save(Archive&, const silicon_one::resource_monitor&);
template <class Archive> void load(Archive&, silicon_one::resource_monitor&);

template <class Archive> void save(Archive&, const silicon_one::rx_cgm_handler&);
template <class Archive> void load(Archive&, silicon_one::rx_cgm_handler&);

template <class Archive> void save(Archive&, const silicon_one::serdes_device_handler&);
template <class Archive> void load(Archive&, silicon_one::serdes_device_handler&);

template <class Archive> void save(Archive&, const silicon_one::voq_cgm_handler&);
template <class Archive> void load(Archive&, silicon_one::voq_cgm_handler&);

template <class Archive> void save(Archive&, const silicon_one::voq_counter_set&);
template <class Archive> void load(Archive&, silicon_one::voq_counter_set&);

template <class Archive> void save(Archive&, const std::chrono::_V2::steady_clock&);
template <class Archive> void load(Archive&, std::chrono::_V2::steady_clock&);

template<>
class serializer_class<silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t& m) {
            archive(::cereal::make_nvp("line_index", m.line_index));
            archive(::cereal::make_nvp("entry_index", m.entry_index));
            archive(::cereal::make_nvp("cir_msb", m.cir_msb));
            archive(::cereal::make_nvp("cir_lsb", m.cir_lsb));
            archive(::cereal::make_nvp("eir_msb", m.eir_msb));
            archive(::cereal::make_nvp("eir_lsb", m.eir_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t& m) {
            archive(::cereal::make_nvp("line_index", m.line_index));
            archive(::cereal::make_nvp("entry_index", m.entry_index));
            archive(::cereal::make_nvp("cir_msb", m.cir_msb));
            archive(::cereal::make_nvp("cir_lsb", m.cir_lsb));
            archive(::cereal::make_nvp("eir_msb", m.eir_msb));
            archive(::cereal::make_nvp("eir_lsb", m.eir_lsb));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t& m)
{
    serializer_class<silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t& m)
{
    serializer_class<silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_statistical_impl::meters_token_entry_details_t&);



template<>
class serializer_class<silicon_one::la_meter_set_statistical_impl::meter_token_size_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_statistical_impl::meter_token_size_data& m) {
            archive(::cereal::make_nvp("cir_token_size", m.cir_token_size));
            archive(::cereal::make_nvp("eir_token_size", m.eir_token_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_statistical_impl::meter_token_size_data& m) {
            archive(::cereal::make_nvp("cir_token_size", m.cir_token_size));
            archive(::cereal::make_nvp("eir_token_size", m.eir_token_size));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_statistical_impl::meter_token_size_data& m)
{
    serializer_class<silicon_one::la_meter_set_statistical_impl::meter_token_size_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_statistical_impl::meter_token_size_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_statistical_impl::meter_token_size_data& m)
{
    serializer_class<silicon_one::la_meter_set_statistical_impl::meter_token_size_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_statistical_impl::meter_token_size_data&);



template<>
class serializer_class<silicon_one::arc_handler_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::arc_handler_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::arc_handler_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::arc_handler_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::arc_handler_base>(&m));
    serializer_class<silicon_one::arc_handler_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::arc_handler_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::arc_handler_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::arc_handler_base>(&m));
    serializer_class<silicon_one::arc_handler_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::arc_handler_gibraltar&);



template<>
class serializer_class<silicon_one::counter_bank_utils> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::counter_bank_utils& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::counter_bank_utils& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::counter_bank_utils& m)
{
    serializer_class<silicon_one::counter_bank_utils>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::counter_bank_utils&);

template <class Archive>
void
load(Archive& archive, silicon_one::counter_bank_utils& m)
{
    serializer_class<silicon_one::counter_bank_utils>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::counter_bank_utils&);



template<>
class serializer_class<silicon_one::physical_bank_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::physical_bank_entry& m) {
            archive(::cereal::make_nvp("is_enabled", m.is_enabled));
            archive(::cereal::make_nvp("bytes_count", m.bytes_count));
            archive(::cereal::make_nvp("packet_count", m.packet_count));
            archive(::cereal::make_nvp("m_token_size", m.m_token_size));
            archive(::cereal::make_nvp("m_counter_address", m.m_counter_address));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::physical_bank_entry& m) {
            archive(::cereal::make_nvp("is_enabled", m.is_enabled));
            archive(::cereal::make_nvp("bytes_count", m.bytes_count));
            archive(::cereal::make_nvp("packet_count", m.packet_count));
            archive(::cereal::make_nvp("m_token_size", m.m_token_size));
            archive(::cereal::make_nvp("m_counter_address", m.m_counter_address));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::physical_bank_entry& m)
{
    serializer_class<silicon_one::physical_bank_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::physical_bank_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::physical_bank_entry& m)
{
    serializer_class<silicon_one::physical_bank_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::physical_bank_entry&);



template<>
class serializer_class<silicon_one::physical_bank_entry::counter_read_address_field> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::physical_bank_entry::counter_read_address_field& m) {
            archive(::cereal::make_nvp("c", m.c));
            archive(::cereal::make_nvp("flat", m.flat));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::physical_bank_entry::counter_read_address_field& m) {
            archive(::cereal::make_nvp("c", m.c));
            archive(::cereal::make_nvp("flat", m.flat));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::physical_bank_entry::counter_read_address_field& m)
{
    serializer_class<silicon_one::physical_bank_entry::counter_read_address_field>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::physical_bank_entry::counter_read_address_field&);

template <class Archive>
void
load(Archive& archive, silicon_one::physical_bank_entry::counter_read_address_field& m)
{
    serializer_class<silicon_one::physical_bank_entry::counter_read_address_field>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::physical_bank_entry::counter_read_address_field&);



template<>
class serializer_class<silicon_one::physical_bank_entry::counter_read_address_field::_c> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::physical_bank_entry::counter_read_address_field::_c& m) {
        uint32_t m_offset_in_bank = m.offset_in_bank;
        uint32_t m_bank_id = m.bank_id;
            archive(::cereal::make_nvp("offset_in_bank", m_offset_in_bank));
            archive(::cereal::make_nvp("bank_id", m_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::physical_bank_entry::counter_read_address_field::_c& m) {
        uint32_t m_offset_in_bank;
        uint32_t m_bank_id;
            archive(::cereal::make_nvp("offset_in_bank", m_offset_in_bank));
            archive(::cereal::make_nvp("bank_id", m_bank_id));
        m.offset_in_bank = m_offset_in_bank;
        m.bank_id = m_bank_id;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::physical_bank_entry::counter_read_address_field::_c& m)
{
    serializer_class<silicon_one::physical_bank_entry::counter_read_address_field::_c>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::physical_bank_entry::counter_read_address_field::_c&);

template <class Archive>
void
load(Archive& archive, silicon_one::physical_bank_entry::counter_read_address_field::_c& m)
{
    serializer_class<silicon_one::physical_bank_entry::counter_read_address_field::_c>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::physical_bank_entry::counter_read_address_field::_c&);



template<>
class serializer_class<silicon_one::counter_logical_bank> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::counter_logical_bank& m) {
            archive(::cereal::make_nvp("m_phys_entries", m.m_phys_entries));
            archive(::cereal::make_nvp("m_first_index", m.m_first_index));
            archive(::cereal::make_nvp("m_first_slice", m.m_first_slice));
            archive(::cereal::make_nvp("m_allowed_user_types", m.m_allowed_user_types));
            archive(::cereal::make_nvp("m_direction", m.m_direction));
            archive(::cereal::make_nvp("m_num_of_slices", m.m_num_of_slices));
            archive(::cereal::make_nvp("m_num_of_busy_phys_entries", m.m_num_of_busy_phys_entries));
            archive(::cereal::make_nvp("m_num_logical_rows_in_bank", m.m_num_logical_rows_in_bank));
            archive(::cereal::make_nvp("m_num_physical_rows_in_bank", m.m_num_physical_rows_in_bank));
            archive(::cereal::make_nvp("m_num_allocated_entries", m.m_num_allocated_entries));
            archive(::cereal::make_nvp("m_last_shadow_update", m.m_last_shadow_update));
            archive(::cereal::make_nvp("m_physical_bank_shadow", m.m_physical_bank_shadow));
            archive(::cereal::make_nvp("m_last_clear_bank", m.m_last_clear_bank));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::counter_logical_bank& m) {
            archive(::cereal::make_nvp("m_phys_entries", m.m_phys_entries));
            archive(::cereal::make_nvp("m_first_index", m.m_first_index));
            archive(::cereal::make_nvp("m_first_slice", m.m_first_slice));
            archive(::cereal::make_nvp("m_allowed_user_types", m.m_allowed_user_types));
            archive(::cereal::make_nvp("m_direction", m.m_direction));
            archive(::cereal::make_nvp("m_num_of_slices", m.m_num_of_slices));
            archive(::cereal::make_nvp("m_num_of_busy_phys_entries", m.m_num_of_busy_phys_entries));
            archive(::cereal::make_nvp("m_num_logical_rows_in_bank", m.m_num_logical_rows_in_bank));
            archive(::cereal::make_nvp("m_num_physical_rows_in_bank", m.m_num_physical_rows_in_bank));
            archive(::cereal::make_nvp("m_num_allocated_entries", m.m_num_allocated_entries));
            archive(::cereal::make_nvp("m_last_shadow_update", m.m_last_shadow_update));
            archive(::cereal::make_nvp("m_physical_bank_shadow", m.m_physical_bank_shadow));
            archive(::cereal::make_nvp("m_last_clear_bank", m.m_last_clear_bank));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::counter_logical_bank& m)
{
    serializer_class<silicon_one::counter_logical_bank>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::counter_logical_bank&);

template <class Archive>
void
load(Archive& archive, silicon_one::counter_logical_bank& m)
{
    serializer_class<silicon_one::counter_logical_bank>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::counter_logical_bank&);



template<>
class serializer_class<silicon_one::counter_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::counter_manager& m) {
            archive(::cereal::make_nvp("m_busy_phys_banks", m.m_busy_phys_banks));
            archive(::cereal::make_nvp("m_resource_monitor", m.m_resource_monitor));
            archive(::cereal::make_nvp("m_banks", m.m_banks));
            archive(::cereal::make_nvp("m_mcg_bank_profiles", m.m_mcg_bank_profiles));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_logical_banks", m.m_logical_banks));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::counter_manager& m) {
            archive(::cereal::make_nvp("m_busy_phys_banks", m.m_busy_phys_banks));
            archive(::cereal::make_nvp("m_resource_monitor", m.m_resource_monitor));
            archive(::cereal::make_nvp("m_banks", m.m_banks));
            archive(::cereal::make_nvp("m_mcg_bank_profiles", m.m_mcg_bank_profiles));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_logical_banks", m.m_logical_banks));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::counter_manager& m)
{
    serializer_class<silicon_one::counter_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::counter_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::counter_manager& m)
{
    serializer_class<silicon_one::counter_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::counter_manager&);



template<>
class serializer_class<silicon_one::gibraltar_mac_pool> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::gibraltar_mac_pool& m) {
            archive(::cereal::make_nvp("m_mac_pool_regs", m.m_mac_pool_regs));
            archive(::cereal::make_nvp("m_mac_pool_counters", m.m_mac_pool_counters));
            archive(::cereal::make_nvp("m_mac_pool_interrupt_regs", m.m_mac_pool_interrupt_regs));
            archive(::cereal::make_nvp("m_gibraltar_tree", m.m_gibraltar_tree));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::gibraltar_mac_pool& m) {
            archive(::cereal::make_nvp("m_mac_pool_regs", m.m_mac_pool_regs));
            archive(::cereal::make_nvp("m_mac_pool_counters", m.m_mac_pool_counters));
            archive(::cereal::make_nvp("m_mac_pool_interrupt_regs", m.m_mac_pool_interrupt_regs));
            archive(::cereal::make_nvp("m_gibraltar_tree", m.m_gibraltar_tree));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::gibraltar_mac_pool& m)
{
    archive(cereal::base_class<silicon_one::mac_pool_port>(&m));
    serializer_class<silicon_one::gibraltar_mac_pool>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::gibraltar_mac_pool&);

template <class Archive>
void
load(Archive& archive, silicon_one::gibraltar_mac_pool& m)
{
    archive(cereal::base_class<silicon_one::mac_pool_port>(&m));
    serializer_class<silicon_one::gibraltar_mac_pool>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::gibraltar_mac_pool&);



template<>
class serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_regs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::gibraltar_mac_pool::_mac_pool_regs_t& m) {
            archive(::cereal::make_nvp("counter_timer", m.counter_timer));
            archive(::cereal::make_nvp("counter_timer_trigger_reg", m.counter_timer_trigger_reg));
            archive(::cereal::make_nvp("rsf_ck_cycles_per_1ms_reg", m.rsf_ck_cycles_per_1ms_reg));
            archive(::cereal::make_nvp("am_cfg", m.am_cfg));
            archive(::cereal::make_nvp("mac_lanes_loopback_register", m.mac_lanes_loopback_register));
            archive(::cereal::make_nvp("pma_loopback_register", m.pma_loopback_register));
            archive(::cereal::make_nvp("rsf_degraded_ser_cfg0", m.rsf_degraded_ser_cfg0));
            archive(::cereal::make_nvp("rx_ber_fsm_cfg", m.rx_ber_fsm_cfg));
            archive(::cereal::make_nvp("rx_cfg0", m.rx_cfg0));
            archive(::cereal::make_nvp("rx_high_ser_fsm_cfg", m.rx_high_ser_fsm_cfg));
            archive(::cereal::make_nvp("rx_krf_status", m.rx_krf_status));
            archive(::cereal::make_nvp("rx_krf_cfg", m.rx_krf_cfg));
            archive(::cereal::make_nvp("rx_mac_cfg0", m.rx_mac_cfg0));
            archive(::cereal::make_nvp("rx_mac_cfg1", m.rx_mac_cfg1));
            archive(::cereal::make_nvp("rx_pcs_test_cfg0", m.rx_pcs_test_cfg0));
            archive(::cereal::make_nvp("rx_pma_test_cfg0", m.rx_pma_test_cfg0));
            archive(::cereal::make_nvp("rx_rsf_cfg0", m.rx_rsf_cfg0));
            archive(::cereal::make_nvp("rx_status_register", m.rx_status_register));
            archive(::cereal::make_nvp("rx_status_lane_mapping", m.rx_status_lane_mapping));
            archive(::cereal::make_nvp("tx_cfg0", m.tx_cfg0));
            archive(::cereal::make_nvp("tx_mac_cfg0", m.tx_mac_cfg0));
            archive(::cereal::make_nvp("tx_mac_ctrl_sa", m.tx_mac_ctrl_sa));
            archive(::cereal::make_nvp("tx_mac_cfg_ipg", m.tx_mac_cfg_ipg));
            archive(::cereal::make_nvp("tx_mac_fc_per_xoff_timer", m.tx_mac_fc_per_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xoff_timer", m.tx_mac_fc_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_per_xon_timer", m.tx_mac_fc_per_xon_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xon_timer", m.tx_mac_fc_xon_timer));
            archive(::cereal::make_nvp("tx_pcs_test_cfg0", m.tx_pcs_test_cfg0));
            archive(::cereal::make_nvp("tx_pma_test_cfg0", m.tx_pma_test_cfg0));
            archive(::cereal::make_nvp("tx_oobi_cfg_reg", m.tx_oobi_cfg_reg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::gibraltar_mac_pool::_mac_pool_regs_t& m) {
            archive(::cereal::make_nvp("counter_timer", m.counter_timer));
            archive(::cereal::make_nvp("counter_timer_trigger_reg", m.counter_timer_trigger_reg));
            archive(::cereal::make_nvp("rsf_ck_cycles_per_1ms_reg", m.rsf_ck_cycles_per_1ms_reg));
            archive(::cereal::make_nvp("am_cfg", m.am_cfg));
            archive(::cereal::make_nvp("mac_lanes_loopback_register", m.mac_lanes_loopback_register));
            archive(::cereal::make_nvp("pma_loopback_register", m.pma_loopback_register));
            archive(::cereal::make_nvp("rsf_degraded_ser_cfg0", m.rsf_degraded_ser_cfg0));
            archive(::cereal::make_nvp("rx_ber_fsm_cfg", m.rx_ber_fsm_cfg));
            archive(::cereal::make_nvp("rx_cfg0", m.rx_cfg0));
            archive(::cereal::make_nvp("rx_high_ser_fsm_cfg", m.rx_high_ser_fsm_cfg));
            archive(::cereal::make_nvp("rx_krf_status", m.rx_krf_status));
            archive(::cereal::make_nvp("rx_krf_cfg", m.rx_krf_cfg));
            archive(::cereal::make_nvp("rx_mac_cfg0", m.rx_mac_cfg0));
            archive(::cereal::make_nvp("rx_mac_cfg1", m.rx_mac_cfg1));
            archive(::cereal::make_nvp("rx_pcs_test_cfg0", m.rx_pcs_test_cfg0));
            archive(::cereal::make_nvp("rx_pma_test_cfg0", m.rx_pma_test_cfg0));
            archive(::cereal::make_nvp("rx_rsf_cfg0", m.rx_rsf_cfg0));
            archive(::cereal::make_nvp("rx_status_register", m.rx_status_register));
            archive(::cereal::make_nvp("rx_status_lane_mapping", m.rx_status_lane_mapping));
            archive(::cereal::make_nvp("tx_cfg0", m.tx_cfg0));
            archive(::cereal::make_nvp("tx_mac_cfg0", m.tx_mac_cfg0));
            archive(::cereal::make_nvp("tx_mac_ctrl_sa", m.tx_mac_ctrl_sa));
            archive(::cereal::make_nvp("tx_mac_cfg_ipg", m.tx_mac_cfg_ipg));
            archive(::cereal::make_nvp("tx_mac_fc_per_xoff_timer", m.tx_mac_fc_per_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xoff_timer", m.tx_mac_fc_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_per_xon_timer", m.tx_mac_fc_per_xon_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xon_timer", m.tx_mac_fc_xon_timer));
            archive(::cereal::make_nvp("tx_pcs_test_cfg0", m.tx_pcs_test_cfg0));
            archive(::cereal::make_nvp("tx_pma_test_cfg0", m.tx_pma_test_cfg0));
            archive(::cereal::make_nvp("tx_oobi_cfg_reg", m.tx_oobi_cfg_reg));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::gibraltar_mac_pool::_mac_pool_regs_t& m)
{
    serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_regs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::gibraltar_mac_pool::_mac_pool_regs_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::gibraltar_mac_pool::_mac_pool_regs_t& m)
{
    serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_regs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::gibraltar_mac_pool::_mac_pool_regs_t&);



template<>
class serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_counters_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::gibraltar_mac_pool::_mac_pool_counters_t& m) {
            archive(::cereal::make_nvp("rx_ber", m.rx_ber));
            archive(::cereal::make_nvp("rx_errored_blocks", m.rx_errored_blocks));
            archive(::cereal::make_nvp("port_mib", m.port_mib));
            archive(::cereal::make_nvp("pcs_test", m.pcs_test));
            archive(::cereal::make_nvp("pma_read", m.pma_read));
            archive(::cereal::make_nvp("pma_write", m.pma_write));
            archive(::cereal::make_nvp("pma_test", m.pma_test));
            archive(::cereal::make_nvp("krf_cor", m.krf_cor));
            archive(::cereal::make_nvp("krf_uncor", m.krf_uncor));
            archive(::cereal::make_nvp("rsf_cor", m.rsf_cor));
            archive(::cereal::make_nvp("rsf_uncor", m.rsf_uncor));
            archive(::cereal::make_nvp("rsf_debug", m.rsf_debug));
            archive(::cereal::make_nvp("rx_symb_err_lane_regs", m.rx_symb_err_lane_regs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::gibraltar_mac_pool::_mac_pool_counters_t& m) {
            archive(::cereal::make_nvp("rx_ber", m.rx_ber));
            archive(::cereal::make_nvp("rx_errored_blocks", m.rx_errored_blocks));
            archive(::cereal::make_nvp("port_mib", m.port_mib));
            archive(::cereal::make_nvp("pcs_test", m.pcs_test));
            archive(::cereal::make_nvp("pma_read", m.pma_read));
            archive(::cereal::make_nvp("pma_write", m.pma_write));
            archive(::cereal::make_nvp("pma_test", m.pma_test));
            archive(::cereal::make_nvp("krf_cor", m.krf_cor));
            archive(::cereal::make_nvp("krf_uncor", m.krf_uncor));
            archive(::cereal::make_nvp("rsf_cor", m.rsf_cor));
            archive(::cereal::make_nvp("rsf_uncor", m.rsf_uncor));
            archive(::cereal::make_nvp("rsf_debug", m.rsf_debug));
            archive(::cereal::make_nvp("rx_symb_err_lane_regs", m.rx_symb_err_lane_regs));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::gibraltar_mac_pool::_mac_pool_counters_t& m)
{
    serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_counters_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::gibraltar_mac_pool::_mac_pool_counters_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::gibraltar_mac_pool::_mac_pool_counters_t& m)
{
    serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_counters_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::gibraltar_mac_pool::_mac_pool_counters_t&);



template<>
class serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t& m) {
            archive(::cereal::make_nvp("rx_link_status_down", m.rx_link_status_down));
            archive(::cereal::make_nvp("rx_link_status_down_mask", m.rx_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_link_status_down", m.rx_pcs_link_status_down));
            archive(::cereal::make_nvp("rx_pcs_link_status_down_mask", m.rx_pcs_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_align_status_down", m.rx_pcs_align_status_down));
            archive(::cereal::make_nvp("rx_pcs_hi_ber_up", m.rx_pcs_hi_ber_up));
            archive(::cereal::make_nvp("rx_pma_sig_ok_loss_interrupt_register", m.rx_pma_sig_ok_loss_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_high_ser_interrupt_register", m.rsf_rx_high_ser_interrupt_register));
            archive(::cereal::make_nvp("rx_desk_fif_ovf_interrupt_register", m.rx_desk_fif_ovf_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register", m.rx_code_err_interrupt_register));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register", m.rx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register", m.rx_invert_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register", m.rx_oversize_err_interrupt_register));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register", m.rx_undersize_err_interrupt_register));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register", m.tx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register", m.tx_underrun_err_interrupt_register));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register", m.tx_missing_eop_err_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register", m.rsf_rx_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register", m.rsf_rx_rm_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("device_time_fif_ne_interrupt_register", m.device_time_fif_ne_interrupt_register));
            archive(::cereal::make_nvp("device_time_override_interrupt_register", m.device_time_override_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register_mask", m.rx_code_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register_mask", m.rx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register_mask", m.rx_invert_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register_mask", m.rx_oversize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register_mask", m.rx_undersize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register_mask", m.tx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register_mask", m.tx_underrun_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register_mask", m.tx_missing_eop_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register_mask", m.rsf_rx_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register_mask", m.rsf_rx_rm_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("device_time_fif_ne_interrupt_register_mask", m.device_time_fif_ne_interrupt_register_mask));
            archive(::cereal::make_nvp("device_time_override_interrupt_register_mask", m.device_time_override_interrupt_register_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t& m) {
            archive(::cereal::make_nvp("rx_link_status_down", m.rx_link_status_down));
            archive(::cereal::make_nvp("rx_link_status_down_mask", m.rx_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_link_status_down", m.rx_pcs_link_status_down));
            archive(::cereal::make_nvp("rx_pcs_link_status_down_mask", m.rx_pcs_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_align_status_down", m.rx_pcs_align_status_down));
            archive(::cereal::make_nvp("rx_pcs_hi_ber_up", m.rx_pcs_hi_ber_up));
            archive(::cereal::make_nvp("rx_pma_sig_ok_loss_interrupt_register", m.rx_pma_sig_ok_loss_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_high_ser_interrupt_register", m.rsf_rx_high_ser_interrupt_register));
            archive(::cereal::make_nvp("rx_desk_fif_ovf_interrupt_register", m.rx_desk_fif_ovf_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register", m.rx_code_err_interrupt_register));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register", m.rx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register", m.rx_invert_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register", m.rx_oversize_err_interrupt_register));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register", m.rx_undersize_err_interrupt_register));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register", m.tx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register", m.tx_underrun_err_interrupt_register));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register", m.tx_missing_eop_err_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register", m.rsf_rx_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register", m.rsf_rx_rm_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("device_time_fif_ne_interrupt_register", m.device_time_fif_ne_interrupt_register));
            archive(::cereal::make_nvp("device_time_override_interrupt_register", m.device_time_override_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register_mask", m.rx_code_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register_mask", m.rx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register_mask", m.rx_invert_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register_mask", m.rx_oversize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register_mask", m.rx_undersize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register_mask", m.tx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register_mask", m.tx_underrun_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register_mask", m.tx_missing_eop_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register_mask", m.rsf_rx_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register_mask", m.rsf_rx_rm_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("device_time_fif_ne_interrupt_register_mask", m.device_time_fif_ne_interrupt_register_mask));
            archive(::cereal::make_nvp("device_time_override_interrupt_register_mask", m.device_time_override_interrupt_register_mask));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t& m)
{
    serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t& m)
{
    serializer_class<silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::gibraltar_mac_pool::_mac_pool_interrupt_regs_t&);



template<>
class serializer_class<silicon_one::gibraltar_pvt_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::gibraltar_pvt_handler& m) {
            archive(::cereal::make_nvp("m_poller_state", m.m_poller_state));
            archive(::cereal::make_nvp("m_next_poll_time", m.m_next_poll_time));
            archive(::cereal::make_nvp("m_temperatures", m.m_temperatures));
            archive(::cereal::make_nvp("m_voltages", m.m_voltages));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_cpu2jtag", m.m_cpu2jtag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::gibraltar_pvt_handler& m) {
            archive(::cereal::make_nvp("m_poller_state", m.m_poller_state));
            archive(::cereal::make_nvp("m_next_poll_time", m.m_next_poll_time));
            archive(::cereal::make_nvp("m_temperatures", m.m_temperatures));
            archive(::cereal::make_nvp("m_voltages", m.m_voltages));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_cpu2jtag", m.m_cpu2jtag));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::gibraltar_pvt_handler& m)
{
    archive(cereal::base_class<silicon_one::pvt_handler>(&m));
    serializer_class<silicon_one::gibraltar_pvt_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::gibraltar_pvt_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::gibraltar_pvt_handler& m)
{
    archive(cereal::base_class<silicon_one::pvt_handler>(&m));
    serializer_class<silicon_one::gibraltar_pvt_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::gibraltar_pvt_handler&);



template<>
class serializer_class<silicon_one::gibraltar_pvt_handler::pvt_samples> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::gibraltar_pvt_handler::pvt_samples& m) {
        unsigned int m_temperature[12];
        CEREAL_GEN_COPY_ARRAY(m.temperature, m_temperature, 12)
        unsigned int m_reserved0[4];
        CEREAL_GEN_COPY_ARRAY(m.reserved0, m_reserved0, 4)
        unsigned int m_voltage[10];
        CEREAL_GEN_COPY_ARRAY(m.voltage, m_voltage, 10)
        unsigned int m_reserved1[6];
        CEREAL_GEN_COPY_ARRAY(m.reserved1, m_reserved1, 6)
        unsigned int m_reserved2[16];
        CEREAL_GEN_COPY_ARRAY(m.reserved2, m_reserved2, 16)
            archive(::cereal::make_nvp("temperature", m_temperature));
            archive(::cereal::make_nvp("reserved0", m_reserved0));
            archive(::cereal::make_nvp("voltage", m_voltage));
            archive(::cereal::make_nvp("reserved1", m_reserved1));
            archive(::cereal::make_nvp("reserved2", m_reserved2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::gibraltar_pvt_handler::pvt_samples& m) {
        unsigned int m_temperature[12];
        unsigned int m_reserved0[4];
        unsigned int m_voltage[10];
        unsigned int m_reserved1[6];
        unsigned int m_reserved2[16];
            archive(::cereal::make_nvp("temperature", m_temperature));
            archive(::cereal::make_nvp("reserved0", m_reserved0));
            archive(::cereal::make_nvp("voltage", m_voltage));
            archive(::cereal::make_nvp("reserved1", m_reserved1));
            archive(::cereal::make_nvp("reserved2", m_reserved2));
        CEREAL_GEN_COPY_ARRAY(m_temperature, m.temperature, 12)
        CEREAL_GEN_COPY_ARRAY(m_reserved0, m.reserved0, 4)
        CEREAL_GEN_COPY_ARRAY(m_voltage, m.voltage, 10)
        CEREAL_GEN_COPY_ARRAY(m_reserved1, m.reserved1, 6)
        CEREAL_GEN_COPY_ARRAY(m_reserved2, m.reserved2, 16)
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::gibraltar_pvt_handler::pvt_samples& m)
{
    serializer_class<silicon_one::gibraltar_pvt_handler::pvt_samples>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::gibraltar_pvt_handler::pvt_samples&);

template <class Archive>
void
load(Archive& archive, silicon_one::gibraltar_pvt_handler::pvt_samples& m)
{
    serializer_class<silicon_one::gibraltar_pvt_handler::pvt_samples>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::gibraltar_pvt_handler::pvt_samples&);



template<>
class serializer_class<bfd_rx_entry_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const bfd_rx_entry_data_t& m) {
            archive(::cereal::make_nvp("local_discr_msb", m.local_discr_msb));
            archive(::cereal::make_nvp("udp_port", m.udp_port));
            archive(::cereal::make_nvp("protocol", m.protocol));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, bfd_rx_entry_data_t& m) {
            archive(::cereal::make_nvp("local_discr_msb", m.local_discr_msb));
            archive(::cereal::make_nvp("udp_port", m.udp_port));
            archive(::cereal::make_nvp("protocol", m.protocol));
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const bfd_rx_entry_data_t& m)
{
    serializer_class<bfd_rx_entry_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const bfd_rx_entry_data_t&);

template <class Archive>
void
load(Archive& archive, bfd_rx_entry_data_t& m)
{
    serializer_class<bfd_rx_entry_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, bfd_rx_entry_data_t&);



template<>
class serializer_class<l2_slp_acl_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const l2_slp_acl_info_t& m) {
            archive(::cereal::make_nvp("v4_acl_oid", m.v4_acl_oid));
            archive(::cereal::make_nvp("v6_acl_oid", m.v6_acl_oid));
            archive(::cereal::make_nvp("mac_acl_oid", m.mac_acl_oid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, l2_slp_acl_info_t& m) {
            archive(::cereal::make_nvp("v4_acl_oid", m.v4_acl_oid));
            archive(::cereal::make_nvp("v6_acl_oid", m.v6_acl_oid));
            archive(::cereal::make_nvp("mac_acl_oid", m.mac_acl_oid));
    }
};
template <class Archive>
void
save(Archive& archive, const l2_slp_acl_info_t& m)
{
    serializer_class<l2_slp_acl_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const l2_slp_acl_info_t&);

template <class Archive>
void
load(Archive& archive, l2_slp_acl_info_t& m)
{
    serializer_class<l2_slp_acl_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, l2_slp_acl_info_t&);



template<>
class serializer_class<silicon_one::acl_group_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_group_info_t& m) {
            archive(::cereal::make_nvp("ethernet_acls_size", m.ethernet_acls_size));
            archive(::cereal::make_nvp("ipv4_acls_size", m.ipv4_acls_size));
            archive(::cereal::make_nvp("ipv6_acls_size", m.ipv6_acls_size));
            archive(::cereal::make_nvp("ethernet_acls", m.ethernet_acls));
            archive(::cereal::make_nvp("ipv4_acls", m.ipv4_acls));
            archive(::cereal::make_nvp("ipv6_acls", m.ipv6_acls));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_group_info_t& m) {
            archive(::cereal::make_nvp("ethernet_acls_size", m.ethernet_acls_size));
            archive(::cereal::make_nvp("ipv4_acls_size", m.ipv4_acls_size));
            archive(::cereal::make_nvp("ipv6_acls_size", m.ipv6_acls_size));
            archive(::cereal::make_nvp("ethernet_acls", m.ethernet_acls));
            archive(::cereal::make_nvp("ipv4_acls", m.ipv4_acls));
            archive(::cereal::make_nvp("ipv6_acls", m.ipv6_acls));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_group_info_t& m)
{
    serializer_class<silicon_one::acl_group_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_group_info_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_group_info_t& m)
{
    serializer_class<silicon_one::acl_group_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_group_info_t&);



template<>
class serializer_class<silicon_one::la_device_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl& m) {
            archive(::cereal::make_nvp("ccm_interval", cereal_gen_remove_const(m.ccm_interval)));
            archive(::cereal::make_nvp("RX_DROP_DSP", cereal_gen_remove_const(m.RX_DROP_DSP)));
            archive(::cereal::make_nvp("RX_NOT_CNT_DROP_DSP", cereal_gen_remove_const(m.RX_NOT_CNT_DROP_DSP)));
            archive(::cereal::make_nvp("m_disconnected", m.m_disconnected));
            archive(::cereal::make_nvp("m_warm_boot_disconnected", m.m_warm_boot_disconnected));
            archive(::cereal::make_nvp("m_sdk_version", cereal_gen_remove_const(m.m_sdk_version)));
            archive(::cereal::make_nvp("m_profile_allocators", m.m_profile_allocators));
            archive(::cereal::make_nvp("m_slice_mode", m.m_slice_mode));
            archive(::cereal::make_nvp("m_hbm_handler", m.m_hbm_handler));
            archive(::cereal::make_nvp("m_ptp_handler", m.m_ptp_handler));
            archive(::cereal::make_nvp("m_pvt_handler", m.m_pvt_handler));
            archive(::cereal::make_nvp("m_cpu2jtag_handler", m.m_cpu2jtag_handler));
            archive(::cereal::make_nvp("m_apb_handlers", m.m_apb_handlers));
            archive(::cereal::make_nvp("m_ifg_handlers", m.m_ifg_handlers));
            archive(::cereal::make_nvp("m_serdes_info", m.m_serdes_info));
            archive(::cereal::make_nvp("m_serdes_inuse", m.m_serdes_inuse));
            archive(::cereal::make_nvp("m_serdes_status", m.m_serdes_status));
            archive(::cereal::make_nvp("m_extended_port_vid_bitset", m.m_extended_port_vid_bitset));
            archive(::cereal::make_nvp("m_pcl_gids", m.m_pcl_gids));
            archive(::cereal::make_nvp("m_pcl_ids_allocated", m.m_pcl_ids_allocated));
            archive(::cereal::make_nvp("m_og_lpts_app_ids", m.m_og_lpts_app_ids));
            archive(::cereal::make_nvp("m_og_lpts_app_ids_allocated", m.m_og_lpts_app_ids_allocated));
            archive(::cereal::make_nvp("m_native_lp_table_format", m.m_native_lp_table_format));
            archive(::cereal::make_nvp("m_ifg_schedulers", m.m_ifg_schedulers));
            archive(::cereal::make_nvp("m_voq_counter_sets", m.m_voq_counter_sets));
            archive(::cereal::make_nvp("m_pwe_tagged_local_labels_map", m.m_pwe_tagged_local_labels_map));
            archive(::cereal::make_nvp("m_vxlan_vni_profile", m.m_vxlan_vni_profile));
            archive(::cereal::make_nvp("m_tables", m.m_tables));
            archive(::cereal::make_nvp("m_resource_manager", m.m_resource_manager));
            archive(::cereal::make_nvp("m_index_generators", m.m_index_generators));
            archive(::cereal::make_nvp("m_resolution_configurators", m.m_resolution_configurators));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_reconnect_handler", m.m_reconnect_handler));
            archive(::cereal::make_nvp("m_init_performance_helper", m.m_init_performance_helper));
            archive(::cereal::make_nvp("m_voq_cgm_handler", m.m_voq_cgm_handler));
            archive(::cereal::make_nvp("m_rx_cgm_handler", m.m_rx_cgm_handler));
            archive(::cereal::make_nvp("m_mac_addr_manager", m.m_mac_addr_manager));
            archive(::cereal::make_nvp("m_copc_protocol_manager", m.m_copc_protocol_manager));
            archive(::cereal::make_nvp("m_ipv4_tunnel_ep_manager", m.m_ipv4_tunnel_ep_manager));
            archive(::cereal::make_nvp("m_ipv4_sip_index_manager", m.m_ipv4_sip_index_manager));
            archive(::cereal::make_nvp("m_counter_bank_manager", m.m_counter_bank_manager));
            archive(::cereal::make_nvp("m_cud_range_manager", m.m_cud_range_manager));
            archive(::cereal::make_nvp("m_mc_copy_id_manager", m.m_mc_copy_id_manager));
            archive(::cereal::make_nvp("m_lsr", m.m_lsr));
            archive(::cereal::make_nvp("m_ttl_inheritance_mode", m.m_ttl_inheritance_mode));
            archive(::cereal::make_nvp("m_forus_destination", m.m_forus_destination));
            archive(::cereal::make_nvp("m_flow_cache_handler", m.m_flow_cache_handler));
            archive(::cereal::make_nvp("m_acl_scaled_enabled", m.m_acl_scaled_enabled));
            archive(::cereal::make_nvp("m_l2pt_trap_enabled", m.m_l2pt_trap_enabled));
            archive(::cereal::make_nvp("m_udk_library", m.m_udk_library));
            archive(::cereal::make_nvp("m_inject_up_mac", m.m_inject_up_mac));
            archive(::cereal::make_nvp("m_fabric_ports_initialized", m.m_fabric_ports_initialized));
            archive(::cereal::make_nvp("m_fabric_fc_mode", m.m_fabric_fc_mode));
            archive(::cereal::make_nvp("m_ecmp_hash_seed", m.m_ecmp_hash_seed));
            archive(::cereal::make_nvp("m_spa_hash_seed", m.m_spa_hash_seed));
            archive(::cereal::make_nvp("m_load_balancing_node_id", m.m_load_balancing_node_id));
            archive(::cereal::make_nvp("m_device_frequency_int_khz", m.m_device_frequency_int_khz));
            archive(::cereal::make_nvp("m_device_frequency_float_ghz", m.m_device_frequency_float_ghz));
            archive(::cereal::make_nvp("m_device_clock_interval", m.m_device_clock_interval));
            archive(::cereal::make_nvp("m_tck_frequency_mhz", m.m_tck_frequency_mhz));
            archive(::cereal::make_nvp("m_meter_shaper_rate", m.m_meter_shaper_rate));
            archive(::cereal::make_nvp("m_rate_limiters_shaper_rate", m.m_rate_limiters_shaper_rate));
            archive(::cereal::make_nvp("m_pfc_tuning_enabled", m.m_pfc_tuning_enabled));
            archive(::cereal::make_nvp("m_device_properties", m.m_device_properties));
            archive(::cereal::make_nvp("m_ipv6_compressed_sip_map", m.m_ipv6_compressed_sip_map));
            archive(::cereal::make_nvp("m_serdes_device_handler", m.m_serdes_device_handler));
            archive(::cereal::make_nvp("m_device_port_handler", m.m_device_port_handler));
            archive(::cereal::make_nvp("m_vsc_ownership_map", m.m_vsc_ownership_map));
            archive(::cereal::make_nvp("m_encap_ptr_smac_map", m.m_encap_ptr_smac_map));
            archive(::cereal::make_nvp("m_mc_smcid_to_local_mcid", m.m_mc_smcid_to_local_mcid));
            archive(::cereal::make_nvp("m_links_bitmap_to_allocated_mcid", m.m_links_bitmap_to_allocated_mcid));
            archive(::cereal::make_nvp("m_mcid_to_links_bitmap", m.m_mcid_to_links_bitmap));
            archive(::cereal::make_nvp("m_device_to_links", m.m_device_to_links));
            archive(::cereal::make_nvp("m_device_to_potential_links", m.m_device_to_potential_links));
            archive(::cereal::make_nvp("m_bundles", m.m_bundles));
            archive(::cereal::make_nvp("m_acl_command_profiles", m.m_acl_command_profiles));
            archive(::cereal::make_nvp("m_mcg_tx_npu_host_ports", m.m_mcg_tx_npu_host_ports));
            archive(::cereal::make_nvp("m_acl_created", m.m_acl_created));
            archive(::cereal::make_nvp("m_save_state_runt", m.m_save_state_runt));
            archive(::cereal::make_nvp("m_trap_entries", m.m_trap_entries));
            archive(::cereal::make_nvp("m_lpts_allocation_cache", m.m_lpts_allocation_cache));
            archive(::cereal::make_nvp("m_sgacl_allocation_cache", m.m_sgacl_allocation_cache));
            archive(::cereal::make_nvp("m_snoop_entries", m.m_snoop_entries));
            archive(::cereal::make_nvp("m_supported_tpid_pairs", m.m_supported_tpid_pairs));
            archive(::cereal::make_nvp("m_native_voq_sets", m.m_native_voq_sets));
            archive(::cereal::make_nvp("m_vsc_is_busy", m.m_vsc_is_busy));
            archive(::cereal::make_nvp("m_tm_slice_mode", m.m_tm_slice_mode));
            archive(::cereal::make_nvp("m_notification", m.m_notification));
            archive(::cereal::make_nvp("m_fuse_userbits", m.m_fuse_userbits));
            archive(::cereal::make_nvp("m_matilda_eFuse_type", m.m_matilda_eFuse_type));
            archive(::cereal::make_nvp("m_heartbeat", m.m_heartbeat));
            archive(::cereal::make_nvp("m_fe_mode", m.m_fe_mode));
            archive(::cereal::make_nvp("m_slice_clos_direction", m.m_slice_clos_direction));
            archive(::cereal::make_nvp("m_fe_fabric_reachability_enabled", m.m_fe_fabric_reachability_enabled));
            archive(::cereal::make_nvp("m_lookup_error_drop_dsp_counter", m.m_lookup_error_drop_dsp_counter));
            archive(::cereal::make_nvp("m_rx_drop_dsp_counter", m.m_rx_drop_dsp_counter));
            archive(::cereal::make_nvp("m_fe_routing_table_last_pool_time_point", m.m_fe_routing_table_last_pool_time_point));
            archive(::cereal::make_nvp("m_valid_links_thresholds", m.m_valid_links_thresholds));
            archive(::cereal::make_nvp("m_congested_links_thresholds", m.m_congested_links_thresholds));
            archive(::cereal::make_nvp("m_learn_mode", m.m_learn_mode));
            archive(::cereal::make_nvp("m_mac_aging_interval", m.m_mac_aging_interval));
            archive(::cereal::make_nvp("m_mc_copy_id_table_use_count", m.m_mc_copy_id_table_use_count));
            archive(::cereal::make_nvp("m_lpts_allocation_cache_initialized", m.m_lpts_allocation_cache_initialized));
            archive(::cereal::make_nvp("m_pfc_tc_latency", m.m_pfc_tc_latency));
            archive(::cereal::make_nvp("m_pfc_watchdog_countdown", m.m_pfc_watchdog_countdown));
            archive(::cereal::make_nvp("m_valid_ifgs_for_mcg_counters", m.m_valid_ifgs_for_mcg_counters));
            archive(::cereal::make_nvp("m_valid_ifg_for_mcg_counter_ptr", m.m_valid_ifg_for_mcg_counter_ptr));
            archive(::cereal::make_nvp("m_is_in_pacific_mode", m.m_is_in_pacific_mode));
            archive(::cereal::make_nvp("m_fabric_mac_ports_mode", m.m_fabric_mac_ports_mode));
            archive(::cereal::make_nvp("m_ttl_decrement_enabled", m.m_ttl_decrement_enabled));
            archive(::cereal::make_nvp("m_l3_termination_classify_ip_tunnels_table", m.m_l3_termination_classify_ip_tunnels_table));
            archive(::cereal::make_nvp("m_global_min_fabric_links_threshold", m.m_global_min_fabric_links_threshold));
            archive(::cereal::make_nvp("m_device_configurator", m.m_device_configurator));
            archive(::cereal::make_nvp("m_is_builtin_objects", m.m_is_builtin_objects));
            archive(::cereal::make_nvp("m_egress_multicast_fabric_replication_voq_set", m.m_egress_multicast_fabric_replication_voq_set));
            archive(::cereal::make_nvp("m_npu_host_eventq", m.m_npu_host_eventq));
            archive(::cereal::make_nvp("m_sda_mode", m.m_sda_mode));
            archive(::cereal::make_nvp("m_punt_recycle_port_exist", m.m_punt_recycle_port_exist));
            archive(::cereal::make_nvp("m_mldp_bud_info", m.m_mldp_bud_info));
            archive(::cereal::make_nvp("m_objects", m.m_objects));
            archive(::cereal::make_nvp("m_resource_monitors", m.m_resource_monitors));
            archive(::cereal::make_nvp("m_mirror_commands", m.m_mirror_commands));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
            archive(::cereal::make_nvp("m_asbr_lsp_map", m.m_asbr_lsp_map));
            archive(::cereal::make_nvp("m_bfd_sessions", m.m_bfd_sessions));
            archive(::cereal::make_nvp("m_voq_sets", m.m_voq_sets));
            archive(::cereal::make_nvp("m_voq_cgm_profiles", m.m_voq_cgm_profiles));
            archive(::cereal::make_nvp("m_voq_cgm_evicted_profiles", m.m_voq_cgm_evicted_profiles));
            archive(::cereal::make_nvp("m_ipv4_tunnel_map", m.m_ipv4_tunnel_map));
            archive(::cereal::make_nvp("m_vxlan_port_map", m.m_vxlan_port_map));
            archive(::cereal::make_nvp("m_vxlan_vni_map", m.m_vxlan_vni_map));
            archive(::cereal::make_nvp("m_vxlan_nh_map", m.m_vxlan_nh_map));
            archive(::cereal::make_nvp("m_security_group_cell_map", m.m_security_group_cell_map));
            archive(::cereal::make_nvp("m_pacific_tree", m.m_pacific_tree));
            archive(::cereal::make_nvp("m_gb_tree", m.m_gb_tree));
            archive(::cereal::make_nvp("m_per_ifg_recycle_sp", m.m_per_ifg_recycle_sp));
            archive(::cereal::make_nvp("m_exact_meter_profile", m.m_exact_meter_profile));
            archive(::cereal::make_nvp("m_exact_meter_action_profile", m.m_exact_meter_action_profile));
            archive(::cereal::make_nvp("m_mcg_counter_tc_profile", m.m_mcg_counter_tc_profile));
            archive(::cereal::make_nvp("m_default_rx_cgm_sq_profile", m.m_default_rx_cgm_sq_profile));
            archive(::cereal::make_nvp("m_trap_counters_or_meters", m.m_trap_counters_or_meters));
            archive(::cereal::make_nvp("m_l2_destinations", m.m_l2_destinations));
            archive(::cereal::make_nvp("m_l2_punt_destinations", m.m_l2_punt_destinations));
            archive(::cereal::make_nvp("m_object_dependencies", m.m_object_dependencies));
            archive(::cereal::make_nvp("m_ifg_dependencies", m.m_ifg_dependencies));
            archive(::cereal::make_nvp("m_attribute_dependencies", m.m_attribute_dependencies));
            archive(::cereal::make_nvp("m_mac_ports", m.m_mac_ports));
            archive(::cereal::make_nvp("m_l2_multicast_groups", m.m_l2_multicast_groups));
            archive(::cereal::make_nvp("m_ip_multicast_groups", m.m_ip_multicast_groups));
            archive(::cereal::make_nvp("m_mpls_multicast_groups", m.m_mpls_multicast_groups));
            archive(::cereal::make_nvp("m_fabric_multicast_groups", m.m_fabric_multicast_groups));
            archive(::cereal::make_nvp("m_ip_tunnel_transit_counter", m.m_ip_tunnel_transit_counter));
            archive(::cereal::make_nvp("m_oam_delay_arm", m.m_oam_delay_arm));
            archive(::cereal::make_nvp("m_internal_error_counters", m.m_internal_error_counters));
            archive(::cereal::make_nvp("m_pfc_watchdog_poll", m.m_pfc_watchdog_poll));
            archive(::cereal::make_nvp("m_pci_ports", m.m_pci_ports));
            archive(::cereal::make_nvp("m_recycle_ports", m.m_recycle_ports));
            archive(::cereal::make_nvp("m_system_ports", m.m_system_ports));
            archive(::cereal::make_nvp("m_rcy_system_ports", m.m_rcy_system_ports));
            archive(::cereal::make_nvp("m_spa_ports", m.m_spa_ports));
            archive(::cereal::make_nvp("m_fabric_ports", m.m_fabric_ports));
            archive(::cereal::make_nvp("m_ac_profiles", m.m_ac_profiles));
            archive(::cereal::make_nvp("m_filter_groups", m.m_filter_groups));
            archive(::cereal::make_nvp("m_ingress_qos_profiles", m.m_ingress_qos_profiles));
            archive(::cereal::make_nvp("m_egress_qos_profiles", m.m_egress_qos_profiles));
            archive(::cereal::make_nvp("m_vrfs", m.m_vrfs));
            archive(::cereal::make_nvp("m_switches", m.m_switches));
            archive(::cereal::make_nvp("m_l2_ports", m.m_l2_ports));
            archive(::cereal::make_nvp("m_pwe_ports", m.m_pwe_ports));
            archive(::cereal::make_nvp("m_next_hops", m.m_next_hops));
            archive(::cereal::make_nvp("m_l3_ports", m.m_l3_ports));
            archive(::cereal::make_nvp("m_protection_monitors", m.m_protection_monitors));
            archive(::cereal::make_nvp("m_l3_protected_entries", m.m_l3_protected_entries));
            archive(::cereal::make_nvp("m_prefix_objects", m.m_prefix_objects));
            archive(::cereal::make_nvp("m_mpls_vpn_encap", m.m_mpls_vpn_encap));
            archive(::cereal::make_nvp("m_destination_pes", m.m_destination_pes));
            archive(::cereal::make_nvp("m_te_tunnels", m.m_te_tunnels));
            archive(::cereal::make_nvp("m_meter_markdown_profiles", m.m_meter_markdown_profiles));
            archive(::cereal::make_nvp("m_vrf_redir_dests", m.m_vrf_redir_dests));
            archive(::cereal::make_nvp("m_egress_multicast_slice_replication_voq_set", m.m_egress_multicast_slice_replication_voq_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl& m) {
            archive(::cereal::make_nvp("ccm_interval", cereal_gen_remove_const(m.ccm_interval)));
            archive(::cereal::make_nvp("RX_DROP_DSP", cereal_gen_remove_const(m.RX_DROP_DSP)));
            archive(::cereal::make_nvp("RX_NOT_CNT_DROP_DSP", cereal_gen_remove_const(m.RX_NOT_CNT_DROP_DSP)));
            archive(::cereal::make_nvp("m_disconnected", m.m_disconnected));
            archive(::cereal::make_nvp("m_warm_boot_disconnected", m.m_warm_boot_disconnected));
            archive(::cereal::make_nvp("m_sdk_version", cereal_gen_remove_const(m.m_sdk_version)));
            archive(::cereal::make_nvp("m_profile_allocators", m.m_profile_allocators));
            archive(::cereal::make_nvp("m_slice_mode", m.m_slice_mode));
            archive(::cereal::make_nvp("m_hbm_handler", m.m_hbm_handler));
            archive(::cereal::make_nvp("m_ptp_handler", m.m_ptp_handler));
            archive(::cereal::make_nvp("m_pvt_handler", m.m_pvt_handler));
            archive(::cereal::make_nvp("m_cpu2jtag_handler", m.m_cpu2jtag_handler));
            archive(::cereal::make_nvp("m_apb_handlers", m.m_apb_handlers));
            archive(::cereal::make_nvp("m_ifg_handlers", m.m_ifg_handlers));
            archive(::cereal::make_nvp("m_serdes_info", m.m_serdes_info));
            archive(::cereal::make_nvp("m_serdes_inuse", m.m_serdes_inuse));
            archive(::cereal::make_nvp("m_serdes_status", m.m_serdes_status));
            archive(::cereal::make_nvp("m_extended_port_vid_bitset", m.m_extended_port_vid_bitset));
            archive(::cereal::make_nvp("m_pcl_gids", m.m_pcl_gids));
            archive(::cereal::make_nvp("m_pcl_ids_allocated", m.m_pcl_ids_allocated));
            archive(::cereal::make_nvp("m_og_lpts_app_ids", m.m_og_lpts_app_ids));
            archive(::cereal::make_nvp("m_og_lpts_app_ids_allocated", m.m_og_lpts_app_ids_allocated));
            archive(::cereal::make_nvp("m_native_lp_table_format", m.m_native_lp_table_format));
            archive(::cereal::make_nvp("m_ifg_schedulers", m.m_ifg_schedulers));
            archive(::cereal::make_nvp("m_voq_counter_sets", m.m_voq_counter_sets));
            archive(::cereal::make_nvp("m_pwe_tagged_local_labels_map", m.m_pwe_tagged_local_labels_map));
            archive(::cereal::make_nvp("m_vxlan_vni_profile", m.m_vxlan_vni_profile));
            archive(::cereal::make_nvp("m_tables", m.m_tables));
            archive(::cereal::make_nvp("m_resource_manager", m.m_resource_manager));
            archive(::cereal::make_nvp("m_index_generators", m.m_index_generators));
            archive(::cereal::make_nvp("m_resolution_configurators", m.m_resolution_configurators));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_reconnect_handler", m.m_reconnect_handler));
            archive(::cereal::make_nvp("m_init_performance_helper", m.m_init_performance_helper));
            archive(::cereal::make_nvp("m_voq_cgm_handler", m.m_voq_cgm_handler));
            archive(::cereal::make_nvp("m_rx_cgm_handler", m.m_rx_cgm_handler));
            archive(::cereal::make_nvp("m_mac_addr_manager", m.m_mac_addr_manager));
            archive(::cereal::make_nvp("m_copc_protocol_manager", m.m_copc_protocol_manager));
            archive(::cereal::make_nvp("m_ipv4_tunnel_ep_manager", m.m_ipv4_tunnel_ep_manager));
            archive(::cereal::make_nvp("m_ipv4_sip_index_manager", m.m_ipv4_sip_index_manager));
            archive(::cereal::make_nvp("m_counter_bank_manager", m.m_counter_bank_manager));
            archive(::cereal::make_nvp("m_cud_range_manager", m.m_cud_range_manager));
            archive(::cereal::make_nvp("m_mc_copy_id_manager", m.m_mc_copy_id_manager));
            archive(::cereal::make_nvp("m_lsr", m.m_lsr));
            archive(::cereal::make_nvp("m_ttl_inheritance_mode", m.m_ttl_inheritance_mode));
            archive(::cereal::make_nvp("m_forus_destination", m.m_forus_destination));
            archive(::cereal::make_nvp("m_flow_cache_handler", m.m_flow_cache_handler));
            archive(::cereal::make_nvp("m_acl_scaled_enabled", m.m_acl_scaled_enabled));
            archive(::cereal::make_nvp("m_l2pt_trap_enabled", m.m_l2pt_trap_enabled));
            archive(::cereal::make_nvp("m_udk_library", m.m_udk_library));
            archive(::cereal::make_nvp("m_inject_up_mac", m.m_inject_up_mac));
            archive(::cereal::make_nvp("m_fabric_ports_initialized", m.m_fabric_ports_initialized));
            archive(::cereal::make_nvp("m_fabric_fc_mode", m.m_fabric_fc_mode));
            archive(::cereal::make_nvp("m_ecmp_hash_seed", m.m_ecmp_hash_seed));
            archive(::cereal::make_nvp("m_spa_hash_seed", m.m_spa_hash_seed));
            archive(::cereal::make_nvp("m_load_balancing_node_id", m.m_load_balancing_node_id));
            archive(::cereal::make_nvp("m_device_frequency_int_khz", m.m_device_frequency_int_khz));
            archive(::cereal::make_nvp("m_device_frequency_float_ghz", m.m_device_frequency_float_ghz));
            archive(::cereal::make_nvp("m_device_clock_interval", m.m_device_clock_interval));
            archive(::cereal::make_nvp("m_tck_frequency_mhz", m.m_tck_frequency_mhz));
            archive(::cereal::make_nvp("m_meter_shaper_rate", m.m_meter_shaper_rate));
            archive(::cereal::make_nvp("m_rate_limiters_shaper_rate", m.m_rate_limiters_shaper_rate));
            archive(::cereal::make_nvp("m_pfc_tuning_enabled", m.m_pfc_tuning_enabled));
            archive(::cereal::make_nvp("m_device_properties", m.m_device_properties));
            archive(::cereal::make_nvp("m_ipv6_compressed_sip_map", m.m_ipv6_compressed_sip_map));
            archive(::cereal::make_nvp("m_serdes_device_handler", m.m_serdes_device_handler));
            archive(::cereal::make_nvp("m_device_port_handler", m.m_device_port_handler));
            archive(::cereal::make_nvp("m_vsc_ownership_map", m.m_vsc_ownership_map));
            archive(::cereal::make_nvp("m_encap_ptr_smac_map", m.m_encap_ptr_smac_map));
            archive(::cereal::make_nvp("m_mc_smcid_to_local_mcid", m.m_mc_smcid_to_local_mcid));
            archive(::cereal::make_nvp("m_links_bitmap_to_allocated_mcid", m.m_links_bitmap_to_allocated_mcid));
            archive(::cereal::make_nvp("m_mcid_to_links_bitmap", m.m_mcid_to_links_bitmap));
            archive(::cereal::make_nvp("m_device_to_links", m.m_device_to_links));
            archive(::cereal::make_nvp("m_device_to_potential_links", m.m_device_to_potential_links));
            archive(::cereal::make_nvp("m_bundles", m.m_bundles));
            archive(::cereal::make_nvp("m_acl_command_profiles", m.m_acl_command_profiles));
            archive(::cereal::make_nvp("m_mcg_tx_npu_host_ports", m.m_mcg_tx_npu_host_ports));
            archive(::cereal::make_nvp("m_acl_created", m.m_acl_created));
            archive(::cereal::make_nvp("m_save_state_runt", m.m_save_state_runt));
            archive(::cereal::make_nvp("m_trap_entries", m.m_trap_entries));
            archive(::cereal::make_nvp("m_lpts_allocation_cache", m.m_lpts_allocation_cache));
            archive(::cereal::make_nvp("m_sgacl_allocation_cache", m.m_sgacl_allocation_cache));
            archive(::cereal::make_nvp("m_snoop_entries", m.m_snoop_entries));
            archive(::cereal::make_nvp("m_supported_tpid_pairs", m.m_supported_tpid_pairs));
            archive(::cereal::make_nvp("m_native_voq_sets", m.m_native_voq_sets));
            archive(::cereal::make_nvp("m_vsc_is_busy", m.m_vsc_is_busy));
            archive(::cereal::make_nvp("m_tm_slice_mode", m.m_tm_slice_mode));
            archive(::cereal::make_nvp("m_notification", m.m_notification));
            archive(::cereal::make_nvp("m_fuse_userbits", m.m_fuse_userbits));
            archive(::cereal::make_nvp("m_matilda_eFuse_type", m.m_matilda_eFuse_type));
            archive(::cereal::make_nvp("m_heartbeat", m.m_heartbeat));
            archive(::cereal::make_nvp("m_fe_mode", m.m_fe_mode));
            archive(::cereal::make_nvp("m_slice_clos_direction", m.m_slice_clos_direction));
            archive(::cereal::make_nvp("m_fe_fabric_reachability_enabled", m.m_fe_fabric_reachability_enabled));
            archive(::cereal::make_nvp("m_lookup_error_drop_dsp_counter", m.m_lookup_error_drop_dsp_counter));
            archive(::cereal::make_nvp("m_rx_drop_dsp_counter", m.m_rx_drop_dsp_counter));
            archive(::cereal::make_nvp("m_fe_routing_table_last_pool_time_point", m.m_fe_routing_table_last_pool_time_point));
            archive(::cereal::make_nvp("m_valid_links_thresholds", m.m_valid_links_thresholds));
            archive(::cereal::make_nvp("m_congested_links_thresholds", m.m_congested_links_thresholds));
            archive(::cereal::make_nvp("m_learn_mode", m.m_learn_mode));
            archive(::cereal::make_nvp("m_mac_aging_interval", m.m_mac_aging_interval));
            archive(::cereal::make_nvp("m_mc_copy_id_table_use_count", m.m_mc_copy_id_table_use_count));
            archive(::cereal::make_nvp("m_lpts_allocation_cache_initialized", m.m_lpts_allocation_cache_initialized));
            archive(::cereal::make_nvp("m_pfc_tc_latency", m.m_pfc_tc_latency));
            archive(::cereal::make_nvp("m_pfc_watchdog_countdown", m.m_pfc_watchdog_countdown));
            archive(::cereal::make_nvp("m_valid_ifgs_for_mcg_counters", m.m_valid_ifgs_for_mcg_counters));
            archive(::cereal::make_nvp("m_valid_ifg_for_mcg_counter_ptr", m.m_valid_ifg_for_mcg_counter_ptr));
            archive(::cereal::make_nvp("m_is_in_pacific_mode", m.m_is_in_pacific_mode));
            archive(::cereal::make_nvp("m_fabric_mac_ports_mode", m.m_fabric_mac_ports_mode));
            archive(::cereal::make_nvp("m_ttl_decrement_enabled", m.m_ttl_decrement_enabled));
            archive(::cereal::make_nvp("m_l3_termination_classify_ip_tunnels_table", m.m_l3_termination_classify_ip_tunnels_table));
            archive(::cereal::make_nvp("m_global_min_fabric_links_threshold", m.m_global_min_fabric_links_threshold));
            archive(::cereal::make_nvp("m_device_configurator", m.m_device_configurator));
            archive(::cereal::make_nvp("m_is_builtin_objects", m.m_is_builtin_objects));
            archive(::cereal::make_nvp("m_egress_multicast_fabric_replication_voq_set", m.m_egress_multicast_fabric_replication_voq_set));
            archive(::cereal::make_nvp("m_npu_host_eventq", m.m_npu_host_eventq));
            archive(::cereal::make_nvp("m_sda_mode", m.m_sda_mode));
            archive(::cereal::make_nvp("m_punt_recycle_port_exist", m.m_punt_recycle_port_exist));
            archive(::cereal::make_nvp("m_mldp_bud_info", m.m_mldp_bud_info));
            archive(::cereal::make_nvp("m_objects", m.m_objects));
            archive(::cereal::make_nvp("m_resource_monitors", m.m_resource_monitors));
            archive(::cereal::make_nvp("m_mirror_commands", m.m_mirror_commands));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
            archive(::cereal::make_nvp("m_asbr_lsp_map", m.m_asbr_lsp_map));
            archive(::cereal::make_nvp("m_bfd_sessions", m.m_bfd_sessions));
            archive(::cereal::make_nvp("m_voq_sets", m.m_voq_sets));
            archive(::cereal::make_nvp("m_voq_cgm_profiles", m.m_voq_cgm_profiles));
            archive(::cereal::make_nvp("m_voq_cgm_evicted_profiles", m.m_voq_cgm_evicted_profiles));
            archive(::cereal::make_nvp("m_ipv4_tunnel_map", m.m_ipv4_tunnel_map));
            archive(::cereal::make_nvp("m_vxlan_port_map", m.m_vxlan_port_map));
            archive(::cereal::make_nvp("m_vxlan_vni_map", m.m_vxlan_vni_map));
            archive(::cereal::make_nvp("m_vxlan_nh_map", m.m_vxlan_nh_map));
            archive(::cereal::make_nvp("m_security_group_cell_map", m.m_security_group_cell_map));
            archive(::cereal::make_nvp("m_pacific_tree", m.m_pacific_tree));
            archive(::cereal::make_nvp("m_gb_tree", m.m_gb_tree));
            archive(::cereal::make_nvp("m_per_ifg_recycle_sp", m.m_per_ifg_recycle_sp));
            archive(::cereal::make_nvp("m_exact_meter_profile", m.m_exact_meter_profile));
            archive(::cereal::make_nvp("m_exact_meter_action_profile", m.m_exact_meter_action_profile));
            archive(::cereal::make_nvp("m_mcg_counter_tc_profile", m.m_mcg_counter_tc_profile));
            archive(::cereal::make_nvp("m_default_rx_cgm_sq_profile", m.m_default_rx_cgm_sq_profile));
            archive(::cereal::make_nvp("m_trap_counters_or_meters", m.m_trap_counters_or_meters));
            archive(::cereal::make_nvp("m_l2_destinations", m.m_l2_destinations));
            archive(::cereal::make_nvp("m_l2_punt_destinations", m.m_l2_punt_destinations));
            archive(::cereal::make_nvp("m_object_dependencies", m.m_object_dependencies));
            archive(::cereal::make_nvp("m_ifg_dependencies", m.m_ifg_dependencies));
            archive(::cereal::make_nvp("m_attribute_dependencies", m.m_attribute_dependencies));
            archive(::cereal::make_nvp("m_mac_ports", m.m_mac_ports));
            archive(::cereal::make_nvp("m_l2_multicast_groups", m.m_l2_multicast_groups));
            archive(::cereal::make_nvp("m_ip_multicast_groups", m.m_ip_multicast_groups));
            archive(::cereal::make_nvp("m_mpls_multicast_groups", m.m_mpls_multicast_groups));
            archive(::cereal::make_nvp("m_fabric_multicast_groups", m.m_fabric_multicast_groups));
            archive(::cereal::make_nvp("m_ip_tunnel_transit_counter", m.m_ip_tunnel_transit_counter));
            archive(::cereal::make_nvp("m_oam_delay_arm", m.m_oam_delay_arm));
            archive(::cereal::make_nvp("m_internal_error_counters", m.m_internal_error_counters));
            archive(::cereal::make_nvp("m_pfc_watchdog_poll", m.m_pfc_watchdog_poll));
            archive(::cereal::make_nvp("m_pci_ports", m.m_pci_ports));
            archive(::cereal::make_nvp("m_recycle_ports", m.m_recycle_ports));
            archive(::cereal::make_nvp("m_system_ports", m.m_system_ports));
            archive(::cereal::make_nvp("m_rcy_system_ports", m.m_rcy_system_ports));
            archive(::cereal::make_nvp("m_spa_ports", m.m_spa_ports));
            archive(::cereal::make_nvp("m_fabric_ports", m.m_fabric_ports));
            archive(::cereal::make_nvp("m_ac_profiles", m.m_ac_profiles));
            archive(::cereal::make_nvp("m_filter_groups", m.m_filter_groups));
            archive(::cereal::make_nvp("m_ingress_qos_profiles", m.m_ingress_qos_profiles));
            archive(::cereal::make_nvp("m_egress_qos_profiles", m.m_egress_qos_profiles));
            archive(::cereal::make_nvp("m_vrfs", m.m_vrfs));
            archive(::cereal::make_nvp("m_switches", m.m_switches));
            archive(::cereal::make_nvp("m_l2_ports", m.m_l2_ports));
            archive(::cereal::make_nvp("m_pwe_ports", m.m_pwe_ports));
            archive(::cereal::make_nvp("m_next_hops", m.m_next_hops));
            archive(::cereal::make_nvp("m_l3_ports", m.m_l3_ports));
            archive(::cereal::make_nvp("m_protection_monitors", m.m_protection_monitors));
            archive(::cereal::make_nvp("m_l3_protected_entries", m.m_l3_protected_entries));
            archive(::cereal::make_nvp("m_prefix_objects", m.m_prefix_objects));
            archive(::cereal::make_nvp("m_mpls_vpn_encap", m.m_mpls_vpn_encap));
            archive(::cereal::make_nvp("m_destination_pes", m.m_destination_pes));
            archive(::cereal::make_nvp("m_te_tunnels", m.m_te_tunnels));
            archive(::cereal::make_nvp("m_meter_markdown_profiles", m.m_meter_markdown_profiles));
            archive(::cereal::make_nvp("m_vrf_redir_dests", m.m_vrf_redir_dests));
            archive(::cereal::make_nvp("m_egress_multicast_slice_replication_voq_set", m.m_egress_multicast_slice_replication_voq_set));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl& m)
{
    archive(cereal::base_class<silicon_one::la_device_impl_base>(&m));
    serializer_class<silicon_one::la_device_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl& m)
{
    archive(cereal::base_class<silicon_one::la_device_impl_base>(&m));
    serializer_class<silicon_one::la_device_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::arc_handler_gibraltar var0;
    ar(var0);
    silicon_one::gibraltar_pvt_handler var1;
    ar(var1);
    silicon_one::la_device_impl var2;
    ar(var2);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::arc_handler_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::gibraltar_mac_pool);
CEREAL_REGISTER_TYPE(silicon_one::gibraltar_pvt_handler);
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl);

#pragma GCC diagnostic pop

