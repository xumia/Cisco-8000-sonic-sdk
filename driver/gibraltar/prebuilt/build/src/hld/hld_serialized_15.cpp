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

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const la_vlan_tag_t&);
template <class Archive> void load(Archive&, la_vlan_tag_t&);

template <class Archive> void save(Archive&, const la_vlan_tag_tci_t&);
template <class Archive> void load(Archive&, la_vlan_tag_tci_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::gibraltar_tree&);
template <class Archive> void load(Archive&, silicon_one::gibraltar_tree&);

template <class Archive> void save(Archive&, const silicon_one::ifg_handler&);
template <class Archive> void load(Archive&, silicon_one::ifg_handler&);

template <class Archive> void save(Archive&, const silicon_one::index_handle&);
template <class Archive> void load(Archive&, silicon_one::index_handle&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device&);
template <class Archive> void load(Archive&, silicon_one::la_device&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_erspan_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_erspan_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_ethernet_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_ethernet_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_interface_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_interface_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_addr&);
template <class Archive> void load(Archive&, silicon_one::la_ip_addr&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_dscp&);
template <class Archive> void load(Archive&, silicon_one::la_ip_dscp&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_l2_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port::link_down_interrupt_histogram&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port::link_down_interrupt_histogram&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port::output_queue_counters&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port::output_queue_counters&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_npu_host_port&);
template <class Archive> void load(Archive&, silicon_one::la_npu_host_port&);

template <class Archive> void save(Archive&, const silicon_one::la_punt_inject_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_punt_inject_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_remote_port_impl&);
template <class Archive> void load(Archive&, silicon_one::la_remote_port_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_rx_cgm_sq_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_rx_cgm_sq_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_stack_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_stack_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port&);
template <class Archive> void load(Archive&, silicon_one::la_system_port&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_base&);

template <class Archive> void save(Archive&, const silicon_one::ll_device&);
template <class Archive> void load(Archive&, silicon_one::ll_device&);

template <class Archive> void save(Archive&, const silicon_one::lld_memory_array_container&);
template <class Archive> void load(Archive&, silicon_one::lld_memory_array_container&);

template <class Archive> void save(Archive&, const silicon_one::lld_register&);
template <class Archive> void load(Archive&, silicon_one::lld_register&);

template <class Archive> void save(Archive&, const silicon_one::lld_register_array_container&);
template <class Archive> void load(Archive&, silicon_one::lld_register_array_container&);

template <class Archive> void save(Archive&, const silicon_one::mac_pool_port&);
template <class Archive> void load(Archive&, silicon_one::mac_pool_port&);

template <class Archive> void save(Archive&, const silicon_one::memory_tcam&);
template <class Archive> void load(Archive&, silicon_one::memory_tcam&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::resource_handler&);
template <class Archive> void load(Archive&, silicon_one::resource_handler&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr_owner&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr_owner&);

template<>
class serializer_class<silicon_one::ifg_handler_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_base& m) {
            archive(::cereal::make_nvp("s_fc_mode_periodic_config", m.s_fc_mode_periodic_config));
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_slice_mode", m.m_slice_mode));
            archive(::cereal::make_nvp("m_ifg_handler_common", m.m_ifg_handler_common));
            archive(::cereal::make_nvp("read_schedule_weight", m.read_schedule_weight));
            archive(::cereal::make_nvp("flow_control_code", m.flow_control_code));
            archive(::cereal::make_nvp("flow_control_priority_map", m.flow_control_priority_map));
            archive(::cereal::make_nvp("synce_ifg_demap", m.synce_ifg_demap));
            archive(::cereal::make_nvp("synce_ifg_map", m.synce_ifg_map));
            archive(::cereal::make_nvp("flow_control_default_xon", m.flow_control_default_xon));
            archive(::cereal::make_nvp("flow_control_default_xoff", m.flow_control_default_xoff));
            archive(::cereal::make_nvp("m_port_tc_tcam", m.m_port_tc_tcam));
            archive(::cereal::make_nvp("m_synce_attached", m.m_synce_attached));
            archive(::cereal::make_nvp("m_pfc_pif_periodic_timer_map", m.m_pfc_pif_periodic_timer_map));
            archive(::cereal::make_nvp("m_pfc_pif_en_periodic_send_map", m.m_pfc_pif_en_periodic_send_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_base& m) {
            archive(::cereal::make_nvp("s_fc_mode_periodic_config", m.s_fc_mode_periodic_config));
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_slice_mode", m.m_slice_mode));
            archive(::cereal::make_nvp("m_ifg_handler_common", m.m_ifg_handler_common));
            archive(::cereal::make_nvp("read_schedule_weight", m.read_schedule_weight));
            archive(::cereal::make_nvp("flow_control_code", m.flow_control_code));
            archive(::cereal::make_nvp("flow_control_priority_map", m.flow_control_priority_map));
            archive(::cereal::make_nvp("synce_ifg_demap", m.synce_ifg_demap));
            archive(::cereal::make_nvp("synce_ifg_map", m.synce_ifg_map));
            archive(::cereal::make_nvp("flow_control_default_xon", m.flow_control_default_xon));
            archive(::cereal::make_nvp("flow_control_default_xoff", m.flow_control_default_xoff));
            archive(::cereal::make_nvp("m_port_tc_tcam", m.m_port_tc_tcam));
            archive(::cereal::make_nvp("m_synce_attached", m.m_synce_attached));
            archive(::cereal::make_nvp("m_pfc_pif_periodic_timer_map", m.m_pfc_pif_periodic_timer_map));
            archive(::cereal::make_nvp("m_pfc_pif_en_periodic_send_map", m.m_pfc_pif_en_periodic_send_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_base& m)
{
    archive(cereal::base_class<silicon_one::ifg_handler>(&m));
    serializer_class<silicon_one::ifg_handler_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_base& m)
{
    archive(cereal::base_class<silicon_one::ifg_handler>(&m));
    serializer_class<silicon_one::ifg_handler_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_base&);



template<>
class serializer_class<silicon_one::ifg_handler_base::fc_mode_periodic_config_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_base::fc_mode_periodic_config_data& m) {
            archive(::cereal::make_nvp("port_periodic_timer", m.port_periodic_timer));
            archive(::cereal::make_nvp("port_watch_dog_timer", m.port_watch_dog_timer));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_base::fc_mode_periodic_config_data& m) {
            archive(::cereal::make_nvp("port_periodic_timer", m.port_periodic_timer));
            archive(::cereal::make_nvp("port_watch_dog_timer", m.port_watch_dog_timer));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_base::fc_mode_periodic_config_data& m)
{
    serializer_class<silicon_one::ifg_handler_base::fc_mode_periodic_config_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_base::fc_mode_periodic_config_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_base::fc_mode_periodic_config_data& m)
{
    serializer_class<silicon_one::ifg_handler_base::fc_mode_periodic_config_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_base::fc_mode_periodic_config_data&);



template<>
class serializer_class<silicon_one::ifg_handler_base::ifg_handler_common> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_base::ifg_handler_common& m) {
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_pif_count", m.m_pif_count));
            archive(::cereal::make_nvp("m_mac_lanes_reserved_count", m.m_mac_lanes_reserved_count));
            archive(::cereal::make_nvp("m_tc_ext_default_tc_width", m.m_tc_ext_default_tc_width));
            archive(::cereal::make_nvp("m_num_port_tc_tcam_memories", m.m_num_port_tc_tcam_memories));
            archive(::cereal::make_nvp("m_total_main_mac_lanes_reserved_count", m.m_total_main_mac_lanes_reserved_count));
            archive(::cereal::make_nvp("m_tx_fifo_lines_main_serdes", m.m_tx_fifo_lines_main_serdes));
            archive(::cereal::make_nvp("m_pool_type", m.m_pool_type));
            archive(::cereal::make_nvp("m_tx_fifo_lines_main_pif", m.m_tx_fifo_lines_main_pif));
            archive(::cereal::make_nvp("m_tc_tcam_key_width", m.m_tc_tcam_key_width));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_base::ifg_handler_common& m) {
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_pif_count", m.m_pif_count));
            archive(::cereal::make_nvp("m_mac_lanes_reserved_count", m.m_mac_lanes_reserved_count));
            archive(::cereal::make_nvp("m_tc_ext_default_tc_width", m.m_tc_ext_default_tc_width));
            archive(::cereal::make_nvp("m_num_port_tc_tcam_memories", m.m_num_port_tc_tcam_memories));
            archive(::cereal::make_nvp("m_total_main_mac_lanes_reserved_count", m.m_total_main_mac_lanes_reserved_count));
            archive(::cereal::make_nvp("m_tx_fifo_lines_main_serdes", m.m_tx_fifo_lines_main_serdes));
            archive(::cereal::make_nvp("m_pool_type", m.m_pool_type));
            archive(::cereal::make_nvp("m_tx_fifo_lines_main_pif", m.m_tx_fifo_lines_main_pif));
            archive(::cereal::make_nvp("m_tc_tcam_key_width", m.m_tc_tcam_key_width));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_base::ifg_handler_common& m)
{
    serializer_class<silicon_one::ifg_handler_base::ifg_handler_common>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_base::ifg_handler_common&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_base::ifg_handler_common& m)
{
    serializer_class<silicon_one::ifg_handler_base::ifg_handler_common>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_base::ifg_handler_common&);



template<>
class serializer_class<silicon_one::ifg_handler_base::tcam_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_base::tcam_entry& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mask", m.mask));
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_base::tcam_entry& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mask", m.mask));
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_base::tcam_entry& m)
{
    serializer_class<silicon_one::ifg_handler_base::tcam_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_base::tcam_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_base::tcam_entry& m)
{
    serializer_class<silicon_one::ifg_handler_base::tcam_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_base::tcam_entry&);



template<>
class serializer_class<silicon_one::ifg_handler_base::range_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_base::range_entry& m) {
            archive(::cereal::make_nvp("low", m.low));
            archive(::cereal::make_nvp("high", m.high));
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_base::range_entry& m) {
            archive(::cereal::make_nvp("low", m.low));
            archive(::cereal::make_nvp("high", m.high));
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_base::range_entry& m)
{
    serializer_class<silicon_one::ifg_handler_base::range_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_base::range_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_base::range_entry& m)
{
    serializer_class<silicon_one::ifg_handler_base::range_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_base::range_entry&);



template<>
class serializer_class<silicon_one::ifg_handler_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_gibraltar& m) {
            archive(::cereal::make_nvp("m_gibraltar_tree", m.m_gibraltar_tree));
            archive(::cereal::make_nvp("m_fabric_port_base", m.m_fabric_port_base));
            archive(::cereal::make_nvp("m_serdes_rx_lane_swap_config", m.m_serdes_rx_lane_swap_config));
            archive(::cereal::make_nvp("m_serdes_tx_lane_swap_config", m.m_serdes_tx_lane_swap_config));
            archive(::cereal::make_nvp("m_serdes_status", m.m_serdes_status));
            archive(::cereal::make_nvp("m_serdes_pll_status", m.m_serdes_pll_status));
            archive(::cereal::make_nvp("m_serdes_an_master_config", m.m_serdes_an_master_config));
            archive(::cereal::make_nvp("m_serdes_an_bitmap_config", m.m_serdes_an_bitmap_config));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_gibraltar& m) {
            archive(::cereal::make_nvp("m_gibraltar_tree", m.m_gibraltar_tree));
            archive(::cereal::make_nvp("m_fabric_port_base", m.m_fabric_port_base));
            archive(::cereal::make_nvp("m_serdes_rx_lane_swap_config", m.m_serdes_rx_lane_swap_config));
            archive(::cereal::make_nvp("m_serdes_tx_lane_swap_config", m.m_serdes_tx_lane_swap_config));
            archive(::cereal::make_nvp("m_serdes_status", m.m_serdes_status));
            archive(::cereal::make_nvp("m_serdes_pll_status", m.m_serdes_pll_status));
            archive(::cereal::make_nvp("m_serdes_an_master_config", m.m_serdes_an_master_config));
            archive(::cereal::make_nvp("m_serdes_an_bitmap_config", m.m_serdes_an_bitmap_config));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::ifg_handler_ifg>(&m));
    serializer_class<silicon_one::ifg_handler_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::ifg_handler_ifg>(&m));
    serializer_class<silicon_one::ifg_handler_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_gibraltar&);



template<>
class serializer_class<silicon_one::ifg_handler_ifg> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_ifg& m) {
            archive(::cereal::make_nvp("m_ifgb_registers", m.m_ifgb_registers));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_ifg& m) {
            archive(::cereal::make_nvp("m_ifgb_registers", m.m_ifgb_registers));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_ifg& m)
{
    archive(cereal::base_class<silicon_one::ifg_handler_base>(&m));
    serializer_class<silicon_one::ifg_handler_ifg>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_ifg&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_ifg& m)
{
    archive(cereal::base_class<silicon_one::ifg_handler_base>(&m));
    serializer_class<silicon_one::ifg_handler_ifg>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_ifg&);



template<>
class serializer_class<silicon_one::ifg_handler_ifg::ifg_registers> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler_ifg::ifg_registers& m) {
            archive(::cereal::make_nvp("fc_cfg0", m.fc_cfg0));
            archive(::cereal::make_nvp("rx_rstn_reg", m.rx_rstn_reg));
            archive(::cereal::make_nvp("tx_rstn_reg", m.tx_rstn_reg));
            archive(::cereal::make_nvp("tx_tsf_ovf_interrupt_reg", m.tx_tsf_ovf_interrupt_reg));
            archive(::cereal::make_nvp("tx_fif_cfg", m.tx_fif_cfg));
            archive(::cereal::make_nvp("tc_extract_cfg_reg", m.tc_extract_cfg_reg));
            archive(::cereal::make_nvp("rx_port_cgm_tc0_drop_counter", m.rx_port_cgm_tc0_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc1_drop_counter", m.rx_port_cgm_tc1_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc2_drop_counter", m.rx_port_cgm_tc2_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc3_drop_counter", m.rx_port_cgm_tc3_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc0_partial_drop_counter", m.rx_port_cgm_tc0_partial_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc1_partial_drop_counter", m.rx_port_cgm_tc1_partial_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc2_partial_drop_counter", m.rx_port_cgm_tc2_partial_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc3_partial_drop_counter", m.rx_port_cgm_tc3_partial_drop_counter));
            archive(::cereal::make_nvp("tc_tcam", m.tc_tcam));
            archive(::cereal::make_nvp("tc_tcam_mem", m.tc_tcam_mem));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler_ifg::ifg_registers& m) {
            archive(::cereal::make_nvp("fc_cfg0", m.fc_cfg0));
            archive(::cereal::make_nvp("rx_rstn_reg", m.rx_rstn_reg));
            archive(::cereal::make_nvp("tx_rstn_reg", m.tx_rstn_reg));
            archive(::cereal::make_nvp("tx_tsf_ovf_interrupt_reg", m.tx_tsf_ovf_interrupt_reg));
            archive(::cereal::make_nvp("tx_fif_cfg", m.tx_fif_cfg));
            archive(::cereal::make_nvp("tc_extract_cfg_reg", m.tc_extract_cfg_reg));
            archive(::cereal::make_nvp("rx_port_cgm_tc0_drop_counter", m.rx_port_cgm_tc0_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc1_drop_counter", m.rx_port_cgm_tc1_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc2_drop_counter", m.rx_port_cgm_tc2_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc3_drop_counter", m.rx_port_cgm_tc3_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc0_partial_drop_counter", m.rx_port_cgm_tc0_partial_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc1_partial_drop_counter", m.rx_port_cgm_tc1_partial_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc2_partial_drop_counter", m.rx_port_cgm_tc2_partial_drop_counter));
            archive(::cereal::make_nvp("rx_port_cgm_tc3_partial_drop_counter", m.rx_port_cgm_tc3_partial_drop_counter));
            archive(::cereal::make_nvp("tc_tcam", m.tc_tcam));
            archive(::cereal::make_nvp("tc_tcam_mem", m.tc_tcam_mem));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler_ifg::ifg_registers& m)
{
    serializer_class<silicon_one::ifg_handler_ifg::ifg_registers>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler_ifg::ifg_registers&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler_ifg::ifg_registers& m)
{
    serializer_class<silicon_one::ifg_handler_ifg::ifg_registers>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler_ifg::ifg_registers&);



template<>
class serializer_class<silicon_one::init_performance_helper_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::init_performance_helper_base& m) {
            archive(::cereal::make_nvp("m_optimization_enabled", m.m_optimization_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::init_performance_helper_base& m) {
            archive(::cereal::make_nvp("m_optimization_enabled", m.m_optimization_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::init_performance_helper_base& m)
{
    serializer_class<silicon_one::init_performance_helper_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::init_performance_helper_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::init_performance_helper_base& m)
{
    serializer_class<silicon_one::init_performance_helper_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::init_performance_helper_base&);



template<>
class serializer_class<silicon_one::init_performance_helper_base::init_metadata> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::init_performance_helper_base::init_metadata& m) {
        uint32_t m_boot_state = m.boot_state;
            archive(::cereal::make_nvp("boot_state", m_boot_state));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::init_performance_helper_base::init_metadata& m) {
        uint32_t m_boot_state;
            archive(::cereal::make_nvp("boot_state", m_boot_state));
        m.boot_state = m_boot_state;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::init_performance_helper_base::init_metadata& m)
{
    serializer_class<silicon_one::init_performance_helper_base::init_metadata>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::init_performance_helper_base::init_metadata&);

template <class Archive>
void
load(Archive& archive, silicon_one::init_performance_helper_base::init_metadata& m)
{
    serializer_class<silicon_one::init_performance_helper_base::init_metadata>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::init_performance_helper_base::init_metadata&);



template<>
class serializer_class<silicon_one::la_device_impl_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl_base& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_resource_handler", m.m_resource_handler));
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_init_phase", m.m_init_phase));
            archive(::cereal::make_nvp("m_device_mode", m.m_device_mode));
            archive(::cereal::make_nvp("m_base_wb_revision", m.m_base_wb_revision));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl_base& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_resource_handler", m.m_resource_handler));
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_init_phase", m.m_init_phase));
            archive(::cereal::make_nvp("m_device_mode", m.m_device_mode));
            archive(::cereal::make_nvp("m_base_wb_revision", m.m_base_wb_revision));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl_base& m)
{
    archive(cereal::base_class<silicon_one::la_device>(&m));
    serializer_class<silicon_one::la_device_impl_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl_base& m)
{
    archive(cereal::base_class<silicon_one::la_device>(&m));
    serializer_class<silicon_one::la_device_impl_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl_base&);



template<>
class serializer_class<silicon_one::la_erspan_mirror_command_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_erspan_mirror_command_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_mirror_gid", m.m_mirror_gid));
            archive(::cereal::make_nvp("m_mirror_hw_id", m.m_mirror_hw_id));
            archive(::cereal::make_nvp("m_mirror_type", m.m_mirror_type));
            archive(::cereal::make_nvp("m_encap_ptr", m.m_encap_ptr));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_session_id", m.m_session_id));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_source_mac_addr", m.m_source_mac_addr));
            archive(::cereal::make_nvp("m_vlan_tag", m.m_vlan_tag));
            archive(::cereal::make_nvp("m_tunnel_dest_addr", m.m_tunnel_dest_addr));
            archive(::cereal::make_nvp("m_tunnel_source_addr", m.m_tunnel_source_addr));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_dscp", m.m_dscp));
            archive(::cereal::make_nvp("m_sport", m.m_sport));
            archive(::cereal::make_nvp("m_dport", m.m_dport));
            archive(::cereal::make_nvp("m_voq_offset", m.m_voq_offset));
            archive(::cereal::make_nvp("m_probability", m.m_probability));
            archive(::cereal::make_nvp("m_truncate", m.m_truncate));
            archive(::cereal::make_nvp("m_ip_version", m.m_ip_version));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
            archive(::cereal::make_nvp("m_dsp", m.m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_erspan_mirror_command_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_mirror_gid", m.m_mirror_gid));
            archive(::cereal::make_nvp("m_mirror_hw_id", m.m_mirror_hw_id));
            archive(::cereal::make_nvp("m_mirror_type", m.m_mirror_type));
            archive(::cereal::make_nvp("m_encap_ptr", m.m_encap_ptr));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_session_id", m.m_session_id));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_source_mac_addr", m.m_source_mac_addr));
            archive(::cereal::make_nvp("m_vlan_tag", m.m_vlan_tag));
            archive(::cereal::make_nvp("m_tunnel_dest_addr", m.m_tunnel_dest_addr));
            archive(::cereal::make_nvp("m_tunnel_source_addr", m.m_tunnel_source_addr));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_dscp", m.m_dscp));
            archive(::cereal::make_nvp("m_sport", m.m_sport));
            archive(::cereal::make_nvp("m_dport", m.m_dport));
            archive(::cereal::make_nvp("m_voq_offset", m.m_voq_offset));
            archive(::cereal::make_nvp("m_probability", m.m_probability));
            archive(::cereal::make_nvp("m_truncate", m.m_truncate));
            archive(::cereal::make_nvp("m_ip_version", m.m_ip_version));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
            archive(::cereal::make_nvp("m_dsp", m.m_dsp));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_erspan_mirror_command_base& m)
{
    archive(cereal::base_class<silicon_one::la_erspan_mirror_command>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_erspan_mirror_command_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_erspan_mirror_command_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_erspan_mirror_command_base& m)
{
    archive(cereal::base_class<silicon_one::la_erspan_mirror_command>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_erspan_mirror_command_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_erspan_mirror_command_base&);



template<>
class serializer_class<silicon_one::la_erspan_mirror_command_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_erspan_mirror_command_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_erspan_mirror_command_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_erspan_mirror_command_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_erspan_mirror_command_base>(&m));
    serializer_class<silicon_one::la_erspan_mirror_command_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_erspan_mirror_command_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_erspan_mirror_command_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_erspan_mirror_command_base>(&m));
    serializer_class<silicon_one::la_erspan_mirror_command_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_erspan_mirror_command_gibraltar&);



template<>
class serializer_class<silicon_one::la_l2_mirror_command_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_mirror_command_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_mirror_gid", m.m_mirror_gid));
            archive(::cereal::make_nvp("m_mirror_hw_id", m.m_mirror_hw_id));
            archive(::cereal::make_nvp("m_mirror_type", m.m_mirror_type));
            archive(::cereal::make_nvp("m_pfc_mirroring", m.m_pfc_mirroring));
            archive(::cereal::make_nvp("m_encap_ptr", m.m_encap_ptr));
            archive(::cereal::make_nvp("m_system_port_gid", m.m_system_port_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_vlan_tag", m.m_vlan_tag));
            archive(::cereal::make_nvp("m_voq_offset", m.m_voq_offset));
            archive(::cereal::make_nvp("m_probability", m.m_probability));
            archive(::cereal::make_nvp("m_encap_type", m.m_encap_type));
            archive(::cereal::make_nvp("m_mirror_to_dest", m.m_mirror_to_dest));
            archive(::cereal::make_nvp("m_truncate", m.m_truncate));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_is_mc_lpts", m.m_is_mc_lpts));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_pi_port", m.m_pi_port));
            archive(::cereal::make_nvp("m_eth_port", m.m_eth_port));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
            archive(::cereal::make_nvp("m_npu_host_port", m.m_npu_host_port));
            archive(::cereal::make_nvp("m_final_system_port", m.m_final_system_port));
            archive(::cereal::make_nvp("m_stack_port", m.m_stack_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_mirror_command_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_mirror_gid", m.m_mirror_gid));
            archive(::cereal::make_nvp("m_mirror_hw_id", m.m_mirror_hw_id));
            archive(::cereal::make_nvp("m_mirror_type", m.m_mirror_type));
            archive(::cereal::make_nvp("m_pfc_mirroring", m.m_pfc_mirroring));
            archive(::cereal::make_nvp("m_encap_ptr", m.m_encap_ptr));
            archive(::cereal::make_nvp("m_system_port_gid", m.m_system_port_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_vlan_tag", m.m_vlan_tag));
            archive(::cereal::make_nvp("m_voq_offset", m.m_voq_offset));
            archive(::cereal::make_nvp("m_probability", m.m_probability));
            archive(::cereal::make_nvp("m_encap_type", m.m_encap_type));
            archive(::cereal::make_nvp("m_mirror_to_dest", m.m_mirror_to_dest));
            archive(::cereal::make_nvp("m_truncate", m.m_truncate));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_is_mc_lpts", m.m_is_mc_lpts));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_pi_port", m.m_pi_port));
            archive(::cereal::make_nvp("m_eth_port", m.m_eth_port));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
            archive(::cereal::make_nvp("m_npu_host_port", m.m_npu_host_port));
            archive(::cereal::make_nvp("m_final_system_port", m.m_final_system_port));
            archive(::cereal::make_nvp("m_stack_port", m.m_stack_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_mirror_command_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_mirror_command>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l2_mirror_command_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_mirror_command_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_mirror_command_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_mirror_command>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l2_mirror_command_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_mirror_command_base&);



template<>
class serializer_class<silicon_one::la_l2_mirror_command_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_mirror_command_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_mirror_command_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_mirror_command_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_l2_mirror_command_pacgb>(&m));
    serializer_class<silicon_one::la_l2_mirror_command_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_mirror_command_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_mirror_command_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_l2_mirror_command_pacgb>(&m));
    serializer_class<silicon_one::la_l2_mirror_command_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_mirror_command_gibraltar&);



template<>
class serializer_class<silicon_one::la_l2_mirror_command_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_mirror_command_pacgb& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_mirror_command_pacgb& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_mirror_command_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_l2_mirror_command_base>(&m));
    serializer_class<silicon_one::la_l2_mirror_command_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_mirror_command_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_mirror_command_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_l2_mirror_command_base>(&m));
    serializer_class<silicon_one::la_l2_mirror_command_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_mirror_command_pacgb&);



template<>
class serializer_class<silicon_one::la_mac_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mac_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_is_extended", m.m_is_extended));
            archive(::cereal::make_nvp("m_system_ports_extended", m.m_system_ports_extended));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_pif_base_id", m.m_pif_base_id));
            archive(::cereal::make_nvp("m_mac_lane_base_id", m.m_mac_lane_base_id));
            archive(::cereal::make_nvp("m_port_slice_mode", m.m_port_slice_mode));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_pif_count", m.m_pif_count));
            archive(::cereal::make_nvp("m_mac_lanes_count", m.m_mac_lanes_count));
            archive(::cereal::make_nvp("m_mac_lanes_reserved_count", m.m_mac_lanes_reserved_count));
            archive(::cereal::make_nvp("m_mac_pool_port", m.m_mac_pool_port));
            archive(::cereal::make_nvp("m_is_reset_allowed", m.m_is_reset_allowed));
            archive(::cereal::make_nvp("m_ostc_protocols", m.m_ostc_protocols));
            archive(::cereal::make_nvp("m_ostc_tpids", m.m_ostc_tpids));
            archive(::cereal::make_nvp("m_link_up", m.m_link_up));
            archive(::cereal::make_nvp("m_block_ingress", m.m_block_ingress));
            archive(::cereal::make_nvp("m_link_down_interrupt_histogram", m.m_link_down_interrupt_histogram));
            archive(::cereal::make_nvp("m_npuh_id", m.m_npuh_id));
            archive(::cereal::make_nvp("m_sw_pfc_quanta", m.m_sw_pfc_quanta));
            archive(::cereal::make_nvp("m_sw_pfc_enabled", m.m_sw_pfc_enabled));
            archive(::cereal::make_nvp("m_pfc_enabled", m.m_pfc_enabled));
            archive(::cereal::make_nvp("m_pfc_quanta", m.m_pfc_quanta));
            archive(::cereal::make_nvp("m_pfc_tc_bitmap", m.m_pfc_tc_bitmap));
            archive(::cereal::make_nvp("m_tc_sq_mapping", m.m_tc_sq_mapping));
            archive(::cereal::make_nvp("m_pfc_periodic_timer_value", m.m_pfc_periodic_timer_value));
            archive(::cereal::make_nvp("m_pfc_watchdog_oqs", m.m_pfc_watchdog_oqs));
            archive(::cereal::make_nvp("m_counter_set", m.m_counter_set));
            archive(::cereal::make_nvp("m_pfc_watchdog_polling_interval_ms", m.m_pfc_watchdog_polling_interval_ms));
            archive(::cereal::make_nvp("m_pfc_watchdog_recovery_interval_ms", m.m_pfc_watchdog_recovery_interval_ms));
            archive(::cereal::make_nvp("m_queue_transmit_state", m.m_queue_transmit_state));
            archive(::cereal::make_nvp("m_watchdog_countdown", m.m_watchdog_countdown));
            archive(::cereal::make_nvp("m_prev_oq_rd_ptr", m.m_prev_oq_rd_ptr));
            archive(::cereal::make_nvp("m_prev_oq_wr_ptr", m.m_prev_oq_wr_ptr));
            archive(::cereal::make_nvp("m_dropped_packets", m.m_dropped_packets));
            archive(::cereal::make_nvp("m_uc_oq_counters", m.m_uc_oq_counters));
            archive(::cereal::make_nvp("m_mc_oq_counters", m.m_mc_oq_counters));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
            archive(::cereal::make_nvp("m_pfc_tx_meter", m.m_pfc_tx_meter));
            archive(::cereal::make_nvp("m_pfc_rx_counter", m.m_pfc_rx_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mac_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_is_extended", m.m_is_extended));
            archive(::cereal::make_nvp("m_system_ports_extended", m.m_system_ports_extended));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_pif_base_id", m.m_pif_base_id));
            archive(::cereal::make_nvp("m_mac_lane_base_id", m.m_mac_lane_base_id));
            archive(::cereal::make_nvp("m_port_slice_mode", m.m_port_slice_mode));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_pif_count", m.m_pif_count));
            archive(::cereal::make_nvp("m_mac_lanes_count", m.m_mac_lanes_count));
            archive(::cereal::make_nvp("m_mac_lanes_reserved_count", m.m_mac_lanes_reserved_count));
            archive(::cereal::make_nvp("m_mac_pool_port", m.m_mac_pool_port));
            archive(::cereal::make_nvp("m_is_reset_allowed", m.m_is_reset_allowed));
            archive(::cereal::make_nvp("m_ostc_protocols", m.m_ostc_protocols));
            archive(::cereal::make_nvp("m_ostc_tpids", m.m_ostc_tpids));
            archive(::cereal::make_nvp("m_link_up", m.m_link_up));
            archive(::cereal::make_nvp("m_block_ingress", m.m_block_ingress));
            archive(::cereal::make_nvp("m_link_down_interrupt_histogram", m.m_link_down_interrupt_histogram));
            archive(::cereal::make_nvp("m_npuh_id", m.m_npuh_id));
            archive(::cereal::make_nvp("m_sw_pfc_quanta", m.m_sw_pfc_quanta));
            archive(::cereal::make_nvp("m_sw_pfc_enabled", m.m_sw_pfc_enabled));
            archive(::cereal::make_nvp("m_pfc_enabled", m.m_pfc_enabled));
            archive(::cereal::make_nvp("m_pfc_quanta", m.m_pfc_quanta));
            archive(::cereal::make_nvp("m_pfc_tc_bitmap", m.m_pfc_tc_bitmap));
            archive(::cereal::make_nvp("m_tc_sq_mapping", m.m_tc_sq_mapping));
            archive(::cereal::make_nvp("m_pfc_periodic_timer_value", m.m_pfc_periodic_timer_value));
            archive(::cereal::make_nvp("m_pfc_watchdog_oqs", m.m_pfc_watchdog_oqs));
            archive(::cereal::make_nvp("m_counter_set", m.m_counter_set));
            archive(::cereal::make_nvp("m_pfc_watchdog_polling_interval_ms", m.m_pfc_watchdog_polling_interval_ms));
            archive(::cereal::make_nvp("m_pfc_watchdog_recovery_interval_ms", m.m_pfc_watchdog_recovery_interval_ms));
            archive(::cereal::make_nvp("m_queue_transmit_state", m.m_queue_transmit_state));
            archive(::cereal::make_nvp("m_watchdog_countdown", m.m_watchdog_countdown));
            archive(::cereal::make_nvp("m_prev_oq_rd_ptr", m.m_prev_oq_rd_ptr));
            archive(::cereal::make_nvp("m_prev_oq_wr_ptr", m.m_prev_oq_wr_ptr));
            archive(::cereal::make_nvp("m_dropped_packets", m.m_dropped_packets));
            archive(::cereal::make_nvp("m_uc_oq_counters", m.m_uc_oq_counters));
            archive(::cereal::make_nvp("m_mc_oq_counters", m.m_mc_oq_counters));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
            archive(::cereal::make_nvp("m_pfc_tx_meter", m.m_pfc_tx_meter));
            archive(::cereal::make_nvp("m_pfc_rx_counter", m.m_pfc_rx_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mac_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_mac_port>(&m));
    serializer_class<silicon_one::la_mac_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mac_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mac_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_mac_port>(&m));
    serializer_class<silicon_one::la_mac_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mac_port_base&);



template<>
class serializer_class<silicon_one::la_mac_port_base::location> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mac_port_base::location& m) {
            archive(::cereal::make_nvp("slice_id", m.slice_id));
            archive(::cereal::make_nvp("ifg_id", m.ifg_id));
            archive(::cereal::make_nvp("first_serdes_id", m.first_serdes_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mac_port_base::location& m) {
            archive(::cereal::make_nvp("slice_id", m.slice_id));
            archive(::cereal::make_nvp("ifg_id", m.ifg_id));
            archive(::cereal::make_nvp("first_serdes_id", m.first_serdes_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mac_port_base::location& m)
{
    serializer_class<silicon_one::la_mac_port_base::location>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mac_port_base::location&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mac_port_base::location& m)
{
    serializer_class<silicon_one::la_mac_port_base::location>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mac_port_base::location&);



template<>
class serializer_class<silicon_one::la_mac_port_base::tc_sq_mapping_val> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mac_port_base::tc_sq_mapping_val& m) {
            archive(::cereal::make_nvp("group_index", m.group_index));
            archive(::cereal::make_nvp("drop_counter_index", m.drop_counter_index));
            archive(::cereal::make_nvp("profile", m.profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mac_port_base::tc_sq_mapping_val& m) {
            archive(::cereal::make_nvp("group_index", m.group_index));
            archive(::cereal::make_nvp("drop_counter_index", m.drop_counter_index));
            archive(::cereal::make_nvp("profile", m.profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mac_port_base::tc_sq_mapping_val& m)
{
    serializer_class<silicon_one::la_mac_port_base::tc_sq_mapping_val>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mac_port_base::tc_sq_mapping_val&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mac_port_base::tc_sq_mapping_val& m)
{
    serializer_class<silicon_one::la_mac_port_base::tc_sq_mapping_val>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mac_port_base::tc_sq_mapping_val&);



template<>
class serializer_class<silicon_one::la_mac_port_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mac_port_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mac_port_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mac_port_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_mac_port_pacgb>(&m));
    serializer_class<silicon_one::la_mac_port_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mac_port_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mac_port_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_mac_port_pacgb>(&m));
    serializer_class<silicon_one::la_mac_port_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mac_port_gibraltar&);



template<>
class serializer_class<silicon_one::la_mac_port_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mac_port_pacgb& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mac_port_pacgb& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mac_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_mac_port_base>(&m));
    serializer_class<silicon_one::la_mac_port_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mac_port_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mac_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_mac_port_base>(&m));
    serializer_class<silicon_one::la_mac_port_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mac_port_pacgb&);



template<>
class serializer_class<silicon_one::la_npu_host_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_npu_host_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_remote_port", m.m_remote_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_npu_host_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_remote_port", m.m_remote_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_npu_host_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_npu_host_port>(&m));
    serializer_class<silicon_one::la_npu_host_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_npu_host_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_npu_host_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_npu_host_port>(&m));
    serializer_class<silicon_one::la_npu_host_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_npu_host_port_base&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::ifg_handler_gibraltar var0;
    ar(var0);
    silicon_one::la_erspan_mirror_command_gibraltar var1;
    ar(var1);
    silicon_one::la_l2_mirror_command_gibraltar var2;
    ar(var2);
    silicon_one::la_mac_port_gibraltar var3;
    ar(var3);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::ifg_handler_base);
CEREAL_REGISTER_TYPE(silicon_one::ifg_handler_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::ifg_handler_ifg);
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl_base);
CEREAL_REGISTER_TYPE(silicon_one::la_erspan_mirror_command_base);
CEREAL_REGISTER_TYPE(silicon_one::la_erspan_mirror_command_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_mirror_command_base);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_mirror_command_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_mirror_command_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_mac_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_mac_port_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_mac_port_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_npu_host_port_base);

#pragma GCC diagnostic pop

