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

template <class Archive> void save(Archive&, const bfd_rx_entry_data_t&);
template <class Archive> void load(Archive&, bfd_rx_entry_data_t&);

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const microcode_write&);
template <class Archive> void load(Archive&, microcode_write&);

template <class Archive> void save(Archive&, const silicon_one::acl_group_info_t&);
template <class Archive> void load(Archive&, silicon_one::acl_group_info_t&);

template <class Archive> void save(Archive&, const silicon_one::bfd_packet_intervals&);
template <class Archive> void load(Archive&, silicon_one::bfd_packet_intervals&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::index_handle&);
template <class Archive> void load(Archive&, silicon_one::index_handle&);

template <class Archive> void save(Archive&, const silicon_one::la_ac_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ac_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl&);
template <class Archive> void load(Archive&, silicon_one::la_acl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_action_def&);
template <class Archive> void load(Archive&, silicon_one::la_acl_action_def&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_command_profile&);
template <class Archive> void load(Archive&, silicon_one::la_acl_command_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_field_def&);
template <class Archive> void load(Archive&, silicon_one::la_acl_field_def&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_group&);
template <class Archive> void load(Archive&, silicon_one::la_acl_group&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_key_profile&);
template <class Archive> void load(Archive&, silicon_one::la_acl_key_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_bfd_flags&);
template <class Archive> void load(Archive&, silicon_one::la_bfd_flags&);

template <class Archive> void save(Archive&, const silicon_one::la_bfd_session&);
template <class Archive> void load(Archive&, silicon_one::la_bfd_session&);

template <class Archive> void save(Archive&, const silicon_one::la_control_plane_classifier&);
template <class Archive> void load(Archive&, silicon_one::la_control_plane_classifier&);

template <class Archive> void save(Archive&, const silicon_one::la_control_plane_classifier::entry_desc&);
template <class Archive> void load(Archive&, silicon_one::la_control_plane_classifier::entry_desc&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ethernet_port&);
template <class Archive> void load(Archive&, silicon_one::la_ethernet_port&);

template <class Archive> void save(Archive&, const silicon_one::la_ethernet_port_base::ac_port_key&);
template <class Archive> void load(Archive&, silicon_one::la_ethernet_port_base::ac_port_key&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_tos&);
template <class Archive> void load(Archive&, silicon_one::la_ip_tos&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_ac_port_impl&);
template <class Archive> void load(Archive&, silicon_one::la_l3_ac_port_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_base&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_base&);

template <class Archive> void save(Archive&, const silicon_one::la_object&);
template <class Archive> void load(Archive&, silicon_one::la_object&);

template <class Archive> void save(Archive&, const silicon_one::la_punt_destination&);
template <class Archive> void load(Archive&, silicon_one::la_punt_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_slice_mapper&);
template <class Archive> void load(Archive&, silicon_one::la_slice_mapper&);

template <class Archive> void save(Archive&, const silicon_one::la_spa_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_spa_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_tc_profile&);
template <class Archive> void load(Archive&, silicon_one::la_tc_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_vlan_pcpdei&);
template <class Archive> void load(Archive&, silicon_one::la_vlan_pcpdei&);

template <class Archive> void save(Archive&, const silicon_one::single_idx_mapping&);
template <class Archive> void load(Archive&, silicon_one::single_idx_mapping&);

template <class Archive> void save(Archive&, const silicon_one::slice_mapping&);
template <class Archive> void load(Archive&, silicon_one::slice_mapping&);

template <class Archive> void save(Archive&, const udk_translation_info&);
template <class Archive> void load(Archive&, udk_translation_info&);

template<>
class serializer_class<silicon_one::la_tc_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_tc_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_id", m.m_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_tc_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_id", m.m_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_tc_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_tc_profile>(&m));
    serializer_class<silicon_one::la_tc_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_tc_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_tc_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_tc_profile>(&m));
    serializer_class<silicon_one::la_tc_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_tc_profile_impl&);



template<>
class serializer_class<silicon_one::voq_counter_set> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::voq_counter_set& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_num_physical_counters", m.m_num_physical_counters));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_voq_msbs", m.m_voq_msbs));
            archive(::cereal::make_nvp("m_group_size", m.m_group_size));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_voq_counter_set_users", m.m_voq_counter_set_users));
            archive(::cereal::make_nvp("m_counter_cache", m.m_counter_cache));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::voq_counter_set& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_num_physical_counters", m.m_num_physical_counters));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_voq_msbs", m.m_voq_msbs));
            archive(::cereal::make_nvp("m_group_size", m.m_group_size));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_voq_counter_set_users", m.m_voq_counter_set_users));
            archive(::cereal::make_nvp("m_counter_cache", m.m_counter_cache));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::voq_counter_set& m)
{
    serializer_class<silicon_one::voq_counter_set>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::voq_counter_set&);

template <class Archive>
void
load(Archive& archive, silicon_one::voq_counter_set& m)
{
    serializer_class<silicon_one::voq_counter_set>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::voq_counter_set&);



template<>
class serializer_class<silicon_one::voq_counter_set::per_slice_counter_cache> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::voq_counter_set::per_slice_counter_cache& m) {
            archive(::cereal::make_nvp("is_valid", m.is_valid));
            archive(::cereal::make_nvp("cached_packets", m.cached_packets));
            archive(::cereal::make_nvp("cached_bytes", m.cached_bytes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::voq_counter_set::per_slice_counter_cache& m) {
            archive(::cereal::make_nvp("is_valid", m.is_valid));
            archive(::cereal::make_nvp("cached_packets", m.cached_packets));
            archive(::cereal::make_nvp("cached_bytes", m.cached_bytes));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::voq_counter_set::per_slice_counter_cache& m)
{
    serializer_class<silicon_one::voq_counter_set::per_slice_counter_cache>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::voq_counter_set::per_slice_counter_cache&);

template <class Archive>
void
load(Archive& archive, silicon_one::voq_counter_set::per_slice_counter_cache& m)
{
    serializer_class<silicon_one::voq_counter_set::per_slice_counter_cache>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::voq_counter_set::per_slice_counter_cache&);



template<>
class serializer_class<silicon_one::la_slice_mapper_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_slice_mapper_base& m) {
            archive(::cereal::make_nvp("m_num_mappable_ifgs", m.m_num_mappable_ifgs));
            archive(::cereal::make_nvp("m_num_mappable_slices", m.m_num_mappable_slices));
            archive(::cereal::make_nvp("m_num_mappable_pairs", m.m_num_mappable_pairs));
            archive(::cereal::make_nvp("m_enabled_slices", m.m_enabled_slices));
            archive(::cereal::make_nvp("m_enabled_slices_logical", m.m_enabled_slices_logical));
            archive(::cereal::make_nvp("m_use_mapping", m.m_use_mapping));
            archive(::cereal::make_nvp("m_slice_mappings", m.m_slice_mappings));
            archive(::cereal::make_nvp("m_back_slice_mappings", m.m_back_slice_mappings));
            archive(::cereal::make_nvp("m_slice_pair_map", m.m_slice_pair_map));
            archive(::cereal::make_nvp("m_slice_pair_map_back", m.m_slice_pair_map_back));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_slice_mapper_base& m) {
            archive(::cereal::make_nvp("m_num_mappable_ifgs", m.m_num_mappable_ifgs));
            archive(::cereal::make_nvp("m_num_mappable_slices", m.m_num_mappable_slices));
            archive(::cereal::make_nvp("m_num_mappable_pairs", m.m_num_mappable_pairs));
            archive(::cereal::make_nvp("m_enabled_slices", m.m_enabled_slices));
            archive(::cereal::make_nvp("m_enabled_slices_logical", m.m_enabled_slices_logical));
            archive(::cereal::make_nvp("m_use_mapping", m.m_use_mapping));
            archive(::cereal::make_nvp("m_slice_mappings", m.m_slice_mappings));
            archive(::cereal::make_nvp("m_back_slice_mappings", m.m_back_slice_mappings));
            archive(::cereal::make_nvp("m_slice_pair_map", m.m_slice_pair_map));
            archive(::cereal::make_nvp("m_slice_pair_map_back", m.m_slice_pair_map_back));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_slice_mapper_base& m)
{
    archive(cereal::base_class<silicon_one::la_slice_mapper>(&m));
    serializer_class<silicon_one::la_slice_mapper_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_slice_mapper_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_slice_mapper_base& m)
{
    archive(cereal::base_class<silicon_one::la_slice_mapper>(&m));
    serializer_class<silicon_one::la_slice_mapper_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_slice_mapper_base&);



template<>
class serializer_class<silicon_one::copc_protocol_manager_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::copc_protocol_manager_base& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::copc_protocol_manager_base& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::copc_protocol_manager_base& m)
{
    serializer_class<silicon_one::copc_protocol_manager_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::copc_protocol_manager_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::copc_protocol_manager_base& m)
{
    serializer_class<silicon_one::copc_protocol_manager_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::copc_protocol_manager_base&);



template<>
class serializer_class<silicon_one::copc_protocol_manager_base::copc_protocol_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::copc_protocol_manager_base::copc_protocol_entry& m) {
            archive(::cereal::make_nvp("l3_protocol", m.l3_protocol));
            archive(::cereal::make_nvp("l4_protocol", m.l4_protocol));
            archive(::cereal::make_nvp("dst_port", m.dst_port));
            archive(::cereal::make_nvp("mac_da_use_copc", m.mac_da_use_copc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::copc_protocol_manager_base::copc_protocol_entry& m) {
            archive(::cereal::make_nvp("l3_protocol", m.l3_protocol));
            archive(::cereal::make_nvp("l4_protocol", m.l4_protocol));
            archive(::cereal::make_nvp("dst_port", m.dst_port));
            archive(::cereal::make_nvp("mac_da_use_copc", m.mac_da_use_copc));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::copc_protocol_manager_base::copc_protocol_entry& m)
{
    serializer_class<silicon_one::copc_protocol_manager_base::copc_protocol_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::copc_protocol_manager_base::copc_protocol_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::copc_protocol_manager_base::copc_protocol_entry& m)
{
    serializer_class<silicon_one::copc_protocol_manager_base::copc_protocol_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::copc_protocol_manager_base::copc_protocol_entry&);



template<>
class serializer_class<silicon_one::copc_protocol_manager_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::copc_protocol_manager_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::copc_protocol_manager_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::copc_protocol_manager_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::copc_protocol_manager_base>(&m));
    serializer_class<silicon_one::copc_protocol_manager_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::copc_protocol_manager_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::copc_protocol_manager_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::copc_protocol_manager_base>(&m));
    serializer_class<silicon_one::copc_protocol_manager_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::copc_protocol_manager_gibraltar&);



template<>
class serializer_class<silicon_one::la_acl_command_profile_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_command_profile_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_acl_command", m.m_acl_command));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_command_profile_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_acl_command", m.m_acl_command));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_command_profile_base& m)
{
    archive(cereal::base_class<silicon_one::la_acl_command_profile>(&m));
    serializer_class<silicon_one::la_acl_command_profile_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_command_profile_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_command_profile_base& m)
{
    archive(cereal::base_class<silicon_one::la_acl_command_profile>(&m));
    serializer_class<silicon_one::la_acl_command_profile_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_command_profile_base&);



template<>
class serializer_class<silicon_one::la_acl_group_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_group_base& m) {
            archive(::cereal::make_nvp("m_acl_group_profile", m.m_acl_group_profile));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_ethernet_acls", m.m_ethernet_acls));
            archive(::cereal::make_nvp("m_real_ethernet_acls", m.m_real_ethernet_acls));
            archive(::cereal::make_nvp("m_ipv4_acls", m.m_ipv4_acls));
            archive(::cereal::make_nvp("m_real_ipv4_acls", m.m_real_ipv4_acls));
            archive(::cereal::make_nvp("m_ipv6_acls", m.m_ipv6_acls));
            archive(::cereal::make_nvp("m_real_ipv6_acls", m.m_real_ipv6_acls));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_group_base& m) {
            archive(::cereal::make_nvp("m_acl_group_profile", m.m_acl_group_profile));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_ethernet_acls", m.m_ethernet_acls));
            archive(::cereal::make_nvp("m_real_ethernet_acls", m.m_real_ethernet_acls));
            archive(::cereal::make_nvp("m_ipv4_acls", m.m_ipv4_acls));
            archive(::cereal::make_nvp("m_real_ipv4_acls", m.m_real_ipv4_acls));
            archive(::cereal::make_nvp("m_ipv6_acls", m.m_ipv6_acls));
            archive(::cereal::make_nvp("m_real_ipv6_acls", m.m_real_ipv6_acls));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_acl_group>(&m));
    serializer_class<silicon_one::la_acl_group_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_group_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_acl_group>(&m));
    serializer_class<silicon_one::la_acl_group_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_group_base&);



template<>
class serializer_class<silicon_one::la_acl_group_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_group_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_group_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_group_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_acl_group_base>(&m));
    serializer_class<silicon_one::la_acl_group_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_group_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_group_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_acl_group_base>(&m));
    serializer_class<silicon_one::la_acl_group_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_group_gibraltar&);



template<>
class serializer_class<silicon_one::la_acl_key_profile_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_key_profile_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_acl_key", m.m_acl_key));
            archive(::cereal::make_nvp("m_key_type", m.m_key_type));
            archive(::cereal::make_nvp("m_dir", m.m_dir));
            archive(::cereal::make_nvp("m_key_size", m.m_key_size));
            archive(::cereal::make_nvp("m_tcam_pool_id", m.m_tcam_pool_id));
            archive(::cereal::make_nvp("m_microcode_writes", m.m_microcode_writes));
            archive(::cereal::make_nvp("m_trans_info", m.m_trans_info));
            archive(::cereal::make_nvp("m_udk_table_id", m.m_udk_table_id));
            archive(::cereal::make_nvp("m_fwd0_table_index", m.m_fwd0_table_index));
            archive(::cereal::make_nvp("m_fwd1_table_index", m.m_fwd1_table_index));
            archive(::cereal::make_nvp("m_eth_rtf_macro_table_id", m.m_eth_rtf_macro_table_id));
            archive(::cereal::make_nvp("m_ipv4_rtf_macro_table_id", m.m_ipv4_rtf_macro_table_id));
            archive(::cereal::make_nvp("m_ipv6_rtf_macro_table_id", m.m_ipv6_rtf_macro_table_id));
            archive(::cereal::make_nvp("m_npl_table_e", m.m_npl_table_e));
            archive(::cereal::make_nvp("m_allocated_table_id", m.m_allocated_table_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_key_profile_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_acl_key", m.m_acl_key));
            archive(::cereal::make_nvp("m_key_type", m.m_key_type));
            archive(::cereal::make_nvp("m_dir", m.m_dir));
            archive(::cereal::make_nvp("m_key_size", m.m_key_size));
            archive(::cereal::make_nvp("m_tcam_pool_id", m.m_tcam_pool_id));
            archive(::cereal::make_nvp("m_microcode_writes", m.m_microcode_writes));
            archive(::cereal::make_nvp("m_trans_info", m.m_trans_info));
            archive(::cereal::make_nvp("m_udk_table_id", m.m_udk_table_id));
            archive(::cereal::make_nvp("m_fwd0_table_index", m.m_fwd0_table_index));
            archive(::cereal::make_nvp("m_fwd1_table_index", m.m_fwd1_table_index));
            archive(::cereal::make_nvp("m_eth_rtf_macro_table_id", m.m_eth_rtf_macro_table_id));
            archive(::cereal::make_nvp("m_ipv4_rtf_macro_table_id", m.m_ipv4_rtf_macro_table_id));
            archive(::cereal::make_nvp("m_ipv6_rtf_macro_table_id", m.m_ipv6_rtf_macro_table_id));
            archive(::cereal::make_nvp("m_npl_table_e", m.m_npl_table_e));
            archive(::cereal::make_nvp("m_allocated_table_id", m.m_allocated_table_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_key_profile_base& m)
{
    archive(cereal::base_class<silicon_one::la_acl_key_profile>(&m));
    serializer_class<silicon_one::la_acl_key_profile_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_key_profile_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_key_profile_base& m)
{
    archive(cereal::base_class<silicon_one::la_acl_key_profile>(&m));
    serializer_class<silicon_one::la_acl_key_profile_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_key_profile_base&);



template<>
class serializer_class<silicon_one::la_acl_key_profile_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_key_profile_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_key_profile_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_key_profile_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_acl_key_profile_base>(&m));
    serializer_class<silicon_one::la_acl_key_profile_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_key_profile_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_key_profile_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_acl_key_profile_base>(&m));
    serializer_class<silicon_one::la_acl_key_profile_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_key_profile_gibraltar&);



template<>
class serializer_class<silicon_one::la_bfd_session_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_bfd_session_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_npuh_id", m.m_npuh_id));
            archive(::cereal::make_nvp("m_session_id", m.m_session_id));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_local_discriminator", m.m_local_discriminator));
            archive(::cereal::make_nvp("m_remote_discriminator", m.m_remote_discriminator));
            archive(::cereal::make_nvp("m_detection_timer_armed", m.m_detection_timer_armed));
            archive(::cereal::make_nvp("m_delay_arm_timer", m.m_delay_arm_timer));
            archive(::cereal::make_nvp("m_tos", m.m_tos));
            archive(::cereal::make_nvp("m_protocol", m.m_protocol));
            archive(::cereal::make_nvp("m_packet_intervals", m.m_packet_intervals));
            archive(::cereal::make_nvp("m_transmit_interval", m.m_transmit_interval));
            archive(::cereal::make_nvp("m_detection_time", m.m_detection_time));
            archive(::cereal::make_nvp("m_local_ipv6_addr", m.m_local_ipv6_addr));
            archive(::cereal::make_nvp("m_local_ipv4_addr", m.m_local_ipv4_addr));
            archive(::cereal::make_nvp("m_remote_ipv4_addr", m.m_remote_ipv4_addr));
            archive(::cereal::make_nvp("m_remote_ipv6_addr", m.m_remote_ipv6_addr));
            archive(::cereal::make_nvp("m_rx_entry", m.m_rx_entry));
            archive(::cereal::make_nvp("m_local_diag_code", m.m_local_diag_code));
            archive(::cereal::make_nvp("m_local_flags", m.m_local_flags));
            archive(::cereal::make_nvp("m_remote_flags", m.m_remote_flags));
            archive(::cereal::make_nvp("m_phase_count", m.m_phase_count));
            archive(::cereal::make_nvp("m_echo_mode_enabled", m.m_echo_mode_enabled));
            archive(::cereal::make_nvp("m_punt_destination_remote", m.m_punt_destination_remote));
            archive(::cereal::make_nvp("m_tc", m.m_tc));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_label_ttl", m.m_label_ttl));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_punt_destination", m.m_punt_destination));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_l3_port", m.m_l3_port));
            archive(::cereal::make_nvp("m_next_hop", m.m_next_hop));
            archive(::cereal::make_nvp("m_inject_up_source_port", m.m_inject_up_source_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_bfd_session_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_npuh_id", m.m_npuh_id));
            archive(::cereal::make_nvp("m_session_id", m.m_session_id));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_local_discriminator", m.m_local_discriminator));
            archive(::cereal::make_nvp("m_remote_discriminator", m.m_remote_discriminator));
            archive(::cereal::make_nvp("m_detection_timer_armed", m.m_detection_timer_armed));
            archive(::cereal::make_nvp("m_delay_arm_timer", m.m_delay_arm_timer));
            archive(::cereal::make_nvp("m_tos", m.m_tos));
            archive(::cereal::make_nvp("m_protocol", m.m_protocol));
            archive(::cereal::make_nvp("m_packet_intervals", m.m_packet_intervals));
            archive(::cereal::make_nvp("m_transmit_interval", m.m_transmit_interval));
            archive(::cereal::make_nvp("m_detection_time", m.m_detection_time));
            archive(::cereal::make_nvp("m_local_ipv6_addr", m.m_local_ipv6_addr));
            archive(::cereal::make_nvp("m_local_ipv4_addr", m.m_local_ipv4_addr));
            archive(::cereal::make_nvp("m_remote_ipv4_addr", m.m_remote_ipv4_addr));
            archive(::cereal::make_nvp("m_remote_ipv6_addr", m.m_remote_ipv6_addr));
            archive(::cereal::make_nvp("m_rx_entry", m.m_rx_entry));
            archive(::cereal::make_nvp("m_local_diag_code", m.m_local_diag_code));
            archive(::cereal::make_nvp("m_local_flags", m.m_local_flags));
            archive(::cereal::make_nvp("m_remote_flags", m.m_remote_flags));
            archive(::cereal::make_nvp("m_phase_count", m.m_phase_count));
            archive(::cereal::make_nvp("m_echo_mode_enabled", m.m_echo_mode_enabled));
            archive(::cereal::make_nvp("m_punt_destination_remote", m.m_punt_destination_remote));
            archive(::cereal::make_nvp("m_tc", m.m_tc));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_label_ttl", m.m_label_ttl));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_punt_destination", m.m_punt_destination));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_l3_port", m.m_l3_port));
            archive(::cereal::make_nvp("m_next_hop", m.m_next_hop));
            archive(::cereal::make_nvp("m_inject_up_source_port", m.m_inject_up_source_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_bfd_session_base& m)
{
    archive(cereal::base_class<silicon_one::la_bfd_session>(&m));
    serializer_class<silicon_one::la_bfd_session_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_bfd_session_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_bfd_session_base& m)
{
    archive(cereal::base_class<silicon_one::la_bfd_session>(&m));
    serializer_class<silicon_one::la_bfd_session_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_bfd_session_base&);



template<>
class serializer_class<silicon_one::la_bfd_session_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_bfd_session_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_bfd_session_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_bfd_session_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_bfd_session_base>(&m));
    serializer_class<silicon_one::la_bfd_session_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_bfd_session_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_bfd_session_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_bfd_session_base>(&m));
    serializer_class<silicon_one::la_bfd_session_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_bfd_session_gibraltar&);



template<>
class serializer_class<silicon_one::la_copc_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_entries", m.m_entries));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_entries", m.m_entries));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base& m)
{
    archive(cereal::base_class<silicon_one::la_control_plane_classifier>(&m));
    serializer_class<silicon_one::la_copc_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base& m)
{
    archive(cereal::base_class<silicon_one::la_control_plane_classifier>(&m));
    serializer_class<silicon_one::la_copc_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_key_l4_ports_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_key_l4_ports_t& m) {
            archive(::cereal::make_nvp("src_port", m.src_port));
            archive(::cereal::make_nvp("dst_port", m.dst_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_key_l4_ports_t& m) {
            archive(::cereal::make_nvp("src_port", m.src_port));
            archive(::cereal::make_nvp("dst_port", m.dst_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_key_l4_ports_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_l4_ports_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_key_l4_ports_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_key_l4_ports_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_l4_ports_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_key_l4_ports_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_key_ipv4_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_key_ipv4_t& m) {
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("protocol", m.protocol));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("l2_service_port_attributes", m.l2_service_port_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("ttl", m.ttl));
            archive(::cereal::make_nvp("my_mac", m.my_mac));
            archive(::cereal::make_nvp("is_svi", m.is_svi));
            archive(::cereal::make_nvp("has_vlan_tag", m.has_vlan_tag));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_key_ipv4_t& m) {
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("protocol", m.protocol));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("l2_service_port_attributes", m.l2_service_port_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("ttl", m.ttl));
            archive(::cereal::make_nvp("my_mac", m.my_mac));
            archive(::cereal::make_nvp("is_svi", m.is_svi));
            archive(::cereal::make_nvp("has_vlan_tag", m.has_vlan_tag));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_key_ipv4_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_ipv4_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_key_ipv4_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_key_ipv4_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_ipv4_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_key_ipv4_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_key_ipv6_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_key_ipv6_t& m) {
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("next_header", m.next_header));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("l2_service_port_attributes", m.l2_service_port_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("hop_limit", m.hop_limit));
            archive(::cereal::make_nvp("my_mac", m.my_mac));
            archive(::cereal::make_nvp("is_svi", m.is_svi));
            archive(::cereal::make_nvp("has_vlan_tag", m.has_vlan_tag));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_key_ipv6_t& m) {
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("next_header", m.next_header));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("l2_service_port_attributes", m.l2_service_port_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("hop_limit", m.hop_limit));
            archive(::cereal::make_nvp("my_mac", m.my_mac));
            archive(::cereal::make_nvp("is_svi", m.is_svi));
            archive(::cereal::make_nvp("has_vlan_tag", m.has_vlan_tag));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_key_ipv6_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_ipv6_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_key_ipv6_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_key_ipv6_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_ipv6_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_key_ipv6_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_key_mac_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_key_mac_t& m) {
            archive(::cereal::make_nvp("mac_da", m.mac_da));
            archive(::cereal::make_nvp("ether_type", m.ether_type));
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("l2_service_port_attributes", m.l2_service_port_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("my_mac", m.my_mac));
            archive(::cereal::make_nvp("is_svi", m.is_svi));
            archive(::cereal::make_nvp("has_vlan_tag", m.has_vlan_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_key_mac_t& m) {
            archive(::cereal::make_nvp("mac_da", m.mac_da));
            archive(::cereal::make_nvp("ether_type", m.ether_type));
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("l2_service_port_attributes", m.l2_service_port_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("my_mac", m.my_mac));
            archive(::cereal::make_nvp("is_svi", m.is_svi));
            archive(::cereal::make_nvp("has_vlan_tag", m.has_vlan_tag));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_key_mac_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_mac_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_key_mac_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_key_mac_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_mac_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_key_mac_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_key_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_key_fields_t& m) {
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
            archive(::cereal::make_nvp("mac", m.mac));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_key_fields_t& m) {
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
            archive(::cereal::make_nvp("mac", m.mac));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_key_fields_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_key_fields_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_key_fields_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_key_fields_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("val", m.val));
            archive(::cereal::make_nvp("mask", m.mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("val", m.val));
            archive(::cereal::make_nvp("mask", m.mask));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_key_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_key_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_key_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_key_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_result_t& m) {
            archive(::cereal::make_nvp("event", m.event));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_result_t& m) {
            archive(::cereal::make_nvp("event", m.event));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_result_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_result_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_result_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_result_t&);



template<>
class serializer_class<silicon_one::la_copc_base::copc_entry_desc_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_base::copc_entry_desc_t& m) {
            archive(::cereal::make_nvp("key_val", m.key_val));
            archive(::cereal::make_nvp("result", m.result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_base::copc_entry_desc_t& m) {
            archive(::cereal::make_nvp("key_val", m.key_val));
            archive(::cereal::make_nvp("result", m.result));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_base::copc_entry_desc_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_entry_desc_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_base::copc_entry_desc_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_base::copc_entry_desc_t& m)
{
    serializer_class<silicon_one::la_copc_base::copc_entry_desc_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_base::copc_entry_desc_t&);



template<>
class serializer_class<silicon_one::la_copc_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_copc_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_copc_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_copc_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_copc_base>(&m));
    serializer_class<silicon_one::la_copc_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_copc_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_copc_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_copc_base>(&m));
    serializer_class<silicon_one::la_copc_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_copc_gibraltar&);



template<>
class serializer_class<silicon_one::la_ethernet_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ethernet_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_id", m.m_id));
            archive(::cereal::make_nvp("m_port_type", m.m_port_type));
            archive(::cereal::make_nvp("m_copc_profile", m.m_copc_profile));
            archive(::cereal::make_nvp("m_transparent_ptp_enabled", m.m_transparent_ptp_enabled));
            archive(::cereal::make_nvp("m_traffic_matrix_type", m.m_traffic_matrix_type));
            archive(::cereal::make_nvp("m_mtu", m.m_mtu));
            archive(::cereal::make_nvp("m_svi_egress_tag_mode", m.m_svi_egress_tag_mode));
            archive(::cereal::make_nvp("m_service_mapping_type", m.m_service_mapping_type));
            archive(::cereal::make_nvp("m_port_vid", m.m_port_vid));
            archive(::cereal::make_nvp("m_default_pcpdei", m.m_default_pcpdei));
            archive(::cereal::make_nvp("m_decrement_ttl", m.m_decrement_ttl));
            archive(::cereal::make_nvp("m_security_group_tag", m.m_security_group_tag));
            archive(::cereal::make_nvp("m_security_group_policy_enforcement", m.m_security_group_policy_enforcement));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_spa_port", m.m_spa_port));
            archive(::cereal::make_nvp("m_ac_profile", m.m_ac_profile));
            archive(::cereal::make_nvp("m_ac_ports_entries", m.m_ac_ports_entries));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ethernet_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_id", m.m_id));
            archive(::cereal::make_nvp("m_port_type", m.m_port_type));
            archive(::cereal::make_nvp("m_copc_profile", m.m_copc_profile));
            archive(::cereal::make_nvp("m_transparent_ptp_enabled", m.m_transparent_ptp_enabled));
            archive(::cereal::make_nvp("m_traffic_matrix_type", m.m_traffic_matrix_type));
            archive(::cereal::make_nvp("m_mtu", m.m_mtu));
            archive(::cereal::make_nvp("m_svi_egress_tag_mode", m.m_svi_egress_tag_mode));
            archive(::cereal::make_nvp("m_service_mapping_type", m.m_service_mapping_type));
            archive(::cereal::make_nvp("m_port_vid", m.m_port_vid));
            archive(::cereal::make_nvp("m_default_pcpdei", m.m_default_pcpdei));
            archive(::cereal::make_nvp("m_decrement_ttl", m.m_decrement_ttl));
            archive(::cereal::make_nvp("m_security_group_tag", m.m_security_group_tag));
            archive(::cereal::make_nvp("m_security_group_policy_enforcement", m.m_security_group_policy_enforcement));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_spa_port", m.m_spa_port));
            archive(::cereal::make_nvp("m_ac_profile", m.m_ac_profile));
            archive(::cereal::make_nvp("m_ac_ports_entries", m.m_ac_ports_entries));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ethernet_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_ethernet_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ethernet_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ethernet_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ethernet_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_ethernet_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ethernet_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ethernet_port_base&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_tc_profile_impl var0;
    ar(var0);
    silicon_one::la_slice_mapper_base var1;
    ar(var1);
    silicon_one::la_acl_command_profile_base var2;
    ar(var2);
    silicon_one::la_acl_group_gibraltar var3;
    ar(var3);
    silicon_one::la_acl_key_profile_gibraltar var4;
    ar(var4);
    silicon_one::la_bfd_session_gibraltar var5;
    ar(var5);
    silicon_one::la_copc_base var6;
    ar(var6);
    silicon_one::la_copc_gibraltar var7;
    ar(var7);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_tc_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_slice_mapper_base);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_command_profile_base);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_group_base);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_group_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_key_profile_base);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_key_profile_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_bfd_session_base);
CEREAL_REGISTER_TYPE(silicon_one::la_bfd_session_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_copc_base);
CEREAL_REGISTER_TYPE(silicon_one::la_copc_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_ethernet_port_base);

#pragma GCC diagnostic pop

