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

template <class Archive> void save(Archive&, const npl_base_l3_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_base_l3_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_additional_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_additional_attributes_t&);

template <class Archive> void save(Archive&, const npl_meter_weight_t&);
template <class Archive> void load(Archive&, npl_meter_weight_t&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_delegate&);
template <class Archive> void load(Archive&, silicon_one::la_acl_delegate&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_group&);
template <class Archive> void load(Archive&, silicon_one::la_acl_group&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_egress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_egress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_filter_group_impl&);
template <class Archive> void load(Archive&, silicon_one::la_filter_group_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ingress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ingress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_service_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_l2_service_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_fec_impl&);
template <class Archive> void load(Archive&, silicon_one::la_l3_fec_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_multicast_protection_monitor&);
template <class Archive> void load(Archive&, silicon_one::la_multicast_protection_monitor&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_impl_common&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_impl_common&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object&);

template <class Archive> void save(Archive&, const silicon_one::la_rate_limiter_set&);
template <class Archive> void load(Archive&, silicon_one::la_rate_limiter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_security_group_cell&);
template <class Archive> void load(Archive&, silicon_one::la_security_group_cell&);

template <class Archive> void save(Archive&, const silicon_one::la_spa_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_spa_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_stack_port&);
template <class Archive> void load(Archive&, silicon_one::la_stack_port&);

template <class Archive> void save(Archive&, const silicon_one::la_svi_port&);
template <class Archive> void load(Archive&, silicon_one::la_svi_port&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port&);
template <class Archive> void load(Archive&, silicon_one::la_system_port&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_te_tunnel_impl&);
template <class Archive> void load(Archive&, silicon_one::la_te_tunnel_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_set&);
template <class Archive> void load(Archive&, silicon_one::la_voq_set&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_impl&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_impl&);

template <class Archive> void save(Archive&, const silicon_one::resolution_cfg_handle_t&);
template <class Archive> void load(Archive&, silicon_one::resolution_cfg_handle_t&);

template<>
class serializer_class<silicon_one::la_multicast_protection_monitor_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_protection_monitor_base& m) {
            archive(::cereal::make_nvp("m_primary_state", m.m_primary_state));
            archive(::cereal::make_nvp("m_backup_state", m.m_backup_state));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_monitor_gid", m.m_monitor_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_protection_monitor_base& m) {
            archive(::cereal::make_nvp("m_primary_state", m.m_primary_state));
            archive(::cereal::make_nvp("m_backup_state", m.m_backup_state));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_monitor_gid", m.m_monitor_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_protection_monitor_base& m)
{
    archive(cereal::base_class<silicon_one::la_multicast_protection_monitor>(&m));
    serializer_class<silicon_one::la_multicast_protection_monitor_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_protection_monitor_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_protection_monitor_base& m)
{
    archive(cereal::base_class<silicon_one::la_multicast_protection_monitor>(&m));
    serializer_class<silicon_one::la_multicast_protection_monitor_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_protection_monitor_base&);



template<>
class serializer_class<silicon_one::la_next_hop_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_next_hop_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_nh_type", m.m_nh_type));
            archive(::cereal::make_nvp("m_next_hop_common", m.m_next_hop_common));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l2_port", m.m_l2_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_next_hop_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_nh_type", m.m_nh_type));
            archive(::cereal::make_nvp("m_next_hop_common", m.m_next_hop_common));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l2_port", m.m_l2_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_next_hop_base& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_next_hop_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_next_hop_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_next_hop_base& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_next_hop_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_next_hop_base&);



template<>
class serializer_class<silicon_one::la_next_hop_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_next_hop_gibraltar& m) {
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_next_hop_gibraltar& m) {
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_next_hop_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop_pacgb>(&m));
    serializer_class<silicon_one::la_next_hop_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_next_hop_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_next_hop_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop_pacgb>(&m));
    serializer_class<silicon_one::la_next_hop_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_next_hop_gibraltar&);



template<>
class serializer_class<silicon_one::la_next_hop_gibraltar::resolution_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_next_hop_gibraltar::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("fec_impl", m.fec_impl));
            archive(::cereal::make_nvp("cfg_handle", m.cfg_handle));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_next_hop_gibraltar::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("fec_impl", m.fec_impl));
            archive(::cereal::make_nvp("cfg_handle", m.cfg_handle));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_next_hop_gibraltar::resolution_data& m)
{
    serializer_class<silicon_one::la_next_hop_gibraltar::resolution_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_next_hop_gibraltar::resolution_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_next_hop_gibraltar::resolution_data& m)
{
    serializer_class<silicon_one::la_next_hop_gibraltar::resolution_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_next_hop_gibraltar::resolution_data&);



template<>
class serializer_class<silicon_one::la_next_hop_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_next_hop_pacgb& m) {
            archive(::cereal::make_nvp("m_nh_direct0_entry", m.m_nh_direct0_entry));
            archive(::cereal::make_nvp("m_nh_direct1_entry", m.m_nh_direct1_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_next_hop_pacgb& m) {
            archive(::cereal::make_nvp("m_nh_direct0_entry", m.m_nh_direct0_entry));
            archive(::cereal::make_nvp("m_nh_direct1_entry", m.m_nh_direct1_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_next_hop_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop_base>(&m));
    serializer_class<silicon_one::la_next_hop_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_next_hop_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_next_hop_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop_base>(&m));
    serializer_class<silicon_one::la_next_hop_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_next_hop_pacgb&);



template<>
class serializer_class<silicon_one::la_prefix_object_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_prefix_gid", m.m_prefix_gid));
            archive(::cereal::make_nvp("m_global_lsp_prefix_info", m.m_global_lsp_prefix_info));
            archive(::cereal::make_nvp("m_vpn_enabled", m.m_vpn_enabled));
            archive(::cereal::make_nvp("m_global_lsp_prefix", m.m_global_lsp_prefix));
            archive(::cereal::make_nvp("m_ipv6_explicit_null_enabled", m.m_ipv6_explicit_null_enabled));
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_mpls_em_entry_map", m.m_mpls_em_entry_map));
            archive(::cereal::make_nvp("m_te_pfx_obj_em_entry_map", m.m_te_pfx_obj_em_entry_map));
            archive(::cereal::make_nvp("m_vpn_entry_map", m.m_vpn_entry_map));
            archive(::cereal::make_nvp("m_prefix_nh_pairs", m.m_prefix_nh_pairs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_prefix_gid", m.m_prefix_gid));
            archive(::cereal::make_nvp("m_global_lsp_prefix_info", m.m_global_lsp_prefix_info));
            archive(::cereal::make_nvp("m_vpn_enabled", m.m_vpn_enabled));
            archive(::cereal::make_nvp("m_global_lsp_prefix", m.m_global_lsp_prefix));
            archive(::cereal::make_nvp("m_ipv6_explicit_null_enabled", m.m_ipv6_explicit_null_enabled));
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_mpls_em_entry_map", m.m_mpls_em_entry_map));
            archive(::cereal::make_nvp("m_te_pfx_obj_em_entry_map", m.m_te_pfx_obj_em_entry_map));
            archive(::cereal::make_nvp("m_vpn_entry_map", m.m_vpn_entry_map));
            archive(::cereal::make_nvp("m_prefix_nh_pairs", m.m_prefix_nh_pairs));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base& m)
{
    archive(cereal::base_class<silicon_one::la_prefix_object>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_prefix_object_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base& m)
{
    archive(cereal::base_class<silicon_one::la_prefix_object>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_prefix_object_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base&);



template<>
class serializer_class<silicon_one::la_prefix_object_base::prefix_nh_pair> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base::prefix_nh_pair& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_prefix", m.m_prefix));
            archive(::cereal::make_nvp("m_nh", cereal_gen_remove_const(m.m_nh)));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base::prefix_nh_pair& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_prefix", m.m_prefix));
            archive(::cereal::make_nvp("m_nh", cereal_gen_remove_const(m.m_nh)));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base::prefix_nh_pair& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_prefix_object_base::prefix_nh_pair>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base::prefix_nh_pair&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base::prefix_nh_pair& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_prefix_object_base::prefix_nh_pair>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base::prefix_nh_pair&);



template<>
class serializer_class<silicon_one::la_prefix_object_base::mpls_em_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base::mpls_em_info& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("more_labels_index_valid", m.more_labels_index_valid));
            archive(::cereal::make_nvp("more_labels_index", m.more_labels_index));
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("counter_mode", m.counter_mode));
            archive(::cereal::make_nvp("ifgs", m.ifgs));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base::mpls_em_info& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("more_labels_index_valid", m.more_labels_index_valid));
            archive(::cereal::make_nvp("more_labels_index", m.more_labels_index));
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("counter_mode", m.counter_mode));
            archive(::cereal::make_nvp("ifgs", m.ifgs));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base::mpls_em_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::mpls_em_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base::mpls_em_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base::mpls_em_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::mpls_em_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base::mpls_em_info&);



template<>
class serializer_class<silicon_one::la_prefix_object_base::lsp_configuration_params> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base::lsp_configuration_params& m) {
            archive(::cereal::make_nvp("multi_counter_enabled", m.multi_counter_enabled));
            archive(::cereal::make_nvp("sr_dm_accounting_enabled", m.sr_dm_accounting_enabled));
            archive(::cereal::make_nvp("program_additional_labels_table", m.program_additional_labels_table));
            archive(::cereal::make_nvp("lsp_payload_with_3_labels", m.lsp_payload_with_3_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base::lsp_configuration_params& m) {
            archive(::cereal::make_nvp("multi_counter_enabled", m.multi_counter_enabled));
            archive(::cereal::make_nvp("sr_dm_accounting_enabled", m.sr_dm_accounting_enabled));
            archive(::cereal::make_nvp("program_additional_labels_table", m.program_additional_labels_table));
            archive(::cereal::make_nvp("lsp_payload_with_3_labels", m.lsp_payload_with_3_labels));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base::lsp_configuration_params& m)
{
    serializer_class<silicon_one::la_prefix_object_base::lsp_configuration_params>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base::lsp_configuration_params&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base::lsp_configuration_params& m)
{
    serializer_class<silicon_one::la_prefix_object_base::lsp_configuration_params>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base::lsp_configuration_params&);



template<>
class serializer_class<silicon_one::la_prefix_object_base::mpls_global_em_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base::mpls_global_em_info& m) {
            archive(::cereal::make_nvp("em_info", m.em_info));
            archive(::cereal::make_nvp("entry_present", m.entry_present));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base::mpls_global_em_info& m) {
            archive(::cereal::make_nvp("em_info", m.em_info));
            archive(::cereal::make_nvp("entry_present", m.entry_present));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base::mpls_global_em_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::mpls_global_em_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base::mpls_global_em_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base::mpls_global_em_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::mpls_global_em_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base::mpls_global_em_info&);



template<>
class serializer_class<silicon_one::la_prefix_object_base::te_pfx_obj_em_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base::te_pfx_obj_em_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base::te_pfx_obj_em_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base::te_pfx_obj_em_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::te_pfx_obj_em_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base::te_pfx_obj_em_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base::te_pfx_obj_em_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::te_pfx_obj_em_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base::te_pfx_obj_em_info&);



template<>
class serializer_class<silicon_one::la_prefix_object_base::vpn_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_base::vpn_info& m) {
            archive(::cereal::make_nvp("ipv4_labels", m.ipv4_labels));
            archive(::cereal::make_nvp("ipv4_valid", m.ipv4_valid));
            archive(::cereal::make_nvp("ipv6_labels", m.ipv6_labels));
            archive(::cereal::make_nvp("ipv6_valid", m.ipv6_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_base::vpn_info& m) {
            archive(::cereal::make_nvp("ipv4_labels", m.ipv4_labels));
            archive(::cereal::make_nvp("ipv4_valid", m.ipv4_valid));
            archive(::cereal::make_nvp("ipv6_labels", m.ipv6_labels));
            archive(::cereal::make_nvp("ipv6_valid", m.ipv6_valid));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_base::vpn_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::vpn_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_base::vpn_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_base::vpn_info& m)
{
    serializer_class<silicon_one::la_prefix_object_base::vpn_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_base::vpn_info&);



template<>
class serializer_class<silicon_one::la_prefix_object_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_prefix_object_gibraltar& m) {
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_prefix_object_gibraltar& m) {
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_prefix_object_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_prefix_object_base>(&m));
    serializer_class<silicon_one::la_prefix_object_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_prefix_object_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_prefix_object_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_prefix_object_base>(&m));
    serializer_class<silicon_one::la_prefix_object_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_prefix_object_gibraltar&);



template<>
class serializer_class<silicon_one::la_rate_limiter_set_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_rate_limiter_set_base& m) {
            archive(::cereal::make_nvp("m_cir", m.m_cir));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_rate_limiter_set_base& m) {
            archive(::cereal::make_nvp("m_cir", m.m_cir));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_rate_limiter_set_base& m)
{
    archive(cereal::base_class<silicon_one::la_rate_limiter_set>(&m));
    serializer_class<silicon_one::la_rate_limiter_set_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_rate_limiter_set_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_rate_limiter_set_base& m)
{
    archive(cereal::base_class<silicon_one::la_rate_limiter_set>(&m));
    serializer_class<silicon_one::la_rate_limiter_set_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_rate_limiter_set_base&);



template<>
class serializer_class<silicon_one::la_rate_limiter_set_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_rate_limiter_set_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_rate_limiter_set_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_rate_limiter_set_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_rate_limiter_set_base>(&m));
    serializer_class<silicon_one::la_rate_limiter_set_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_rate_limiter_set_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_rate_limiter_set_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_rate_limiter_set_base>(&m));
    serializer_class<silicon_one::la_rate_limiter_set_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_rate_limiter_set_gibraltar&);



template<>
class serializer_class<silicon_one::la_security_group_cell_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_security_group_cell_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_sgt", m.m_sgt));
            archive(::cereal::make_nvp("m_dgt", m.m_dgt));
            archive(::cereal::make_nvp("m_ip_version", m.m_ip_version));
            archive(::cereal::make_nvp("m_allow_drop", m.m_allow_drop));
            archive(::cereal::make_nvp("m_sgacl_id", m.m_sgacl_id));
            archive(::cereal::make_nvp("m_sgacl_bincode", m.m_sgacl_bincode));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_sgacl", m.m_sgacl));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_security_group_cell_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_sgt", m.m_sgt));
            archive(::cereal::make_nvp("m_dgt", m.m_dgt));
            archive(::cereal::make_nvp("m_ip_version", m.m_ip_version));
            archive(::cereal::make_nvp("m_allow_drop", m.m_allow_drop));
            archive(::cereal::make_nvp("m_sgacl_id", m.m_sgacl_id));
            archive(::cereal::make_nvp("m_sgacl_bincode", m.m_sgacl_bincode));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_sgacl", m.m_sgacl));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_security_group_cell_base& m)
{
    archive(cereal::base_class<silicon_one::la_security_group_cell>(&m));
    serializer_class<silicon_one::la_security_group_cell_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_security_group_cell_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_security_group_cell_base& m)
{
    archive(cereal::base_class<silicon_one::la_security_group_cell>(&m));
    serializer_class<silicon_one::la_security_group_cell_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_security_group_cell_base&);



template<>
class serializer_class<silicon_one::la_security_group_cell_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_security_group_cell_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_security_group_cell_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_security_group_cell_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_security_group_cell_base>(&m));
    serializer_class<silicon_one::la_security_group_cell_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_security_group_cell_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_security_group_cell_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_security_group_cell_base>(&m));
    serializer_class<silicon_one::la_security_group_cell_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_security_group_cell_gibraltar&);



template<>
class serializer_class<silicon_one::la_stack_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_stack_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_remote_punt_mac", m.m_remote_punt_mac));
            archive(::cereal::make_nvp("m_peer_device_id", m.m_peer_device_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_spa_port", m.m_spa_port));
            archive(::cereal::make_nvp("m_remote_punt_system_port", m.m_remote_punt_system_port));
            archive(::cereal::make_nvp("m_local_punt_system_port", m.m_local_punt_system_port));
            archive(::cereal::make_nvp("m_control_traffic_voq_map", m.m_control_traffic_voq_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_stack_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_remote_punt_mac", m.m_remote_punt_mac));
            archive(::cereal::make_nvp("m_peer_device_id", m.m_peer_device_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
            archive(::cereal::make_nvp("m_spa_port", m.m_spa_port));
            archive(::cereal::make_nvp("m_remote_punt_system_port", m.m_remote_punt_system_port));
            archive(::cereal::make_nvp("m_local_punt_system_port", m.m_local_punt_system_port));
            archive(::cereal::make_nvp("m_control_traffic_voq_map", m.m_control_traffic_voq_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_stack_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_stack_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_stack_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_stack_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_stack_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_stack_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_stack_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_stack_port_base&);



template<>
class serializer_class<silicon_one::la_stack_port_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_stack_port_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_stack_port_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_stack_port_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_stack_port_base>(&m));
    serializer_class<silicon_one::la_stack_port_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_stack_port_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_stack_port_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_stack_port_base>(&m));
    serializer_class<silicon_one::la_stack_port_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_stack_port_gibraltar&);



template<>
class serializer_class<silicon_one::la_svi_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_vxlan_shared_overlay_nh_count", m.m_vxlan_shared_overlay_nh_count));
            archive(::cereal::make_nvp("m_vxlan_shared_overlay_nh_mac", m.m_vxlan_shared_overlay_nh_mac));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_virtual_mac_addr", m.m_virtual_mac_addr));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_mac_move_map", m.m_mac_move_map));
            archive(::cereal::make_nvp("m_rcy_sm_vid1", m.m_rcy_sm_vid1));
            archive(::cereal::make_nvp("m_rcy_sm_vid2", m.m_rcy_sm_vid2));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_sw", m.m_sw));
            archive(::cereal::make_nvp("m_vxlan_encap_counter", m.m_vxlan_encap_counter));
            archive(::cereal::make_nvp("m_inject_up_port", m.m_inject_up_port));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_vxlan_shared_overlay_nh_count", m.m_vxlan_shared_overlay_nh_count));
            archive(::cereal::make_nvp("m_vxlan_shared_overlay_nh_mac", m.m_vxlan_shared_overlay_nh_mac));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_virtual_mac_addr", m.m_virtual_mac_addr));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_mac_move_map", m.m_mac_move_map));
            archive(::cereal::make_nvp("m_rcy_sm_vid1", m.m_rcy_sm_vid1));
            archive(::cereal::make_nvp("m_rcy_sm_vid2", m.m_rcy_sm_vid2));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_sw", m.m_sw));
            archive(::cereal::make_nvp("m_vxlan_encap_counter", m.m_vxlan_encap_counter));
            archive(::cereal::make_nvp("m_inject_up_port", m.m_inject_up_port));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_svi_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_svi_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_svi_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_svi_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base&);



template<>
class serializer_class<silicon_one::la_svi_port_base::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base::slice_data& m) {
            archive(::cereal::make_nvp("mac_termination_em_table_entry", m.mac_termination_em_table_entry));
            archive(::cereal::make_nvp("mac_termination_mc_table_entry", m.mac_termination_mc_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base::slice_data& m) {
            archive(::cereal::make_nvp("mac_termination_em_table_entry", m.mac_termination_em_table_entry));
            archive(::cereal::make_nvp("mac_termination_mc_table_entry", m.mac_termination_mc_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base::slice_data& m)
{
    serializer_class<silicon_one::la_svi_port_base::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base::slice_data& m)
{
    serializer_class<silicon_one::la_svi_port_base::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base::slice_data&);



template<>
class serializer_class<silicon_one::la_svi_port_base::la_ipv4_hosts_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base::la_ipv4_hosts_t& m) {
            archive(::cereal::make_nvp("host", m.host));
            archive(::cereal::make_nvp("class_id", m.class_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base::la_ipv4_hosts_t& m) {
            archive(::cereal::make_nvp("host", m.host));
            archive(::cereal::make_nvp("class_id", m.class_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base::la_ipv4_hosts_t& m)
{
    serializer_class<silicon_one::la_svi_port_base::la_ipv4_hosts_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base::la_ipv4_hosts_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base::la_ipv4_hosts_t& m)
{
    serializer_class<silicon_one::la_svi_port_base::la_ipv4_hosts_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base::la_ipv4_hosts_t&);



template<>
class serializer_class<silicon_one::la_svi_port_base::la_ipv6_hosts_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base::la_ipv6_hosts_t& m) {
            archive(::cereal::make_nvp("host", m.host));
            archive(::cereal::make_nvp("class_id", m.class_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base::la_ipv6_hosts_t& m) {
            archive(::cereal::make_nvp("host", m.host));
            archive(::cereal::make_nvp("class_id", m.class_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base::la_ipv6_hosts_t& m)
{
    serializer_class<silicon_one::la_svi_port_base::la_ipv6_hosts_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base::la_ipv6_hosts_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base::la_ipv6_hosts_t& m)
{
    serializer_class<silicon_one::la_svi_port_base::la_ipv6_hosts_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base::la_ipv6_hosts_t&);



template<>
class serializer_class<silicon_one::la_svi_port_base::ipv4_address_key_less> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base::ipv4_address_key_less& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base::ipv4_address_key_less& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base::ipv4_address_key_less& m)
{
    serializer_class<silicon_one::la_svi_port_base::ipv4_address_key_less>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base::ipv4_address_key_less&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base::ipv4_address_key_less& m)
{
    serializer_class<silicon_one::la_svi_port_base::ipv4_address_key_less>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base::ipv4_address_key_less&);



template<>
class serializer_class<silicon_one::la_svi_port_base::ipv6_address_key_less> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base::ipv6_address_key_less& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base::ipv6_address_key_less& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base::ipv6_address_key_less& m)
{
    serializer_class<silicon_one::la_svi_port_base::ipv6_address_key_less>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base::ipv6_address_key_less&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base::ipv6_address_key_less& m)
{
    serializer_class<silicon_one::la_svi_port_base::ipv6_address_key_less>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base::ipv6_address_key_less&);



template<>
class serializer_class<silicon_one::la_svi_port_base::la_nhs_hosts> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_base::la_nhs_hosts& m) {
            archive(::cereal::make_nvp("ipv4_hosts", m.ipv4_hosts));
            archive(::cereal::make_nvp("ipv6_hosts", m.ipv6_hosts));
            archive(::cereal::make_nvp("nhs", m.nhs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_base::la_nhs_hosts& m) {
            archive(::cereal::make_nvp("ipv4_hosts", m.ipv4_hosts));
            archive(::cereal::make_nvp("ipv6_hosts", m.ipv6_hosts));
            archive(::cereal::make_nvp("nhs", m.nhs));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_base::la_nhs_hosts& m)
{
    serializer_class<silicon_one::la_svi_port_base::la_nhs_hosts>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_base::la_nhs_hosts&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_base::la_nhs_hosts& m)
{
    serializer_class<silicon_one::la_svi_port_base::la_nhs_hosts>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_base::la_nhs_hosts&);



template<>
class serializer_class<silicon_one::la_svi_port_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_svi_port_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_svi_port_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_svi_port_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_svi_port_base>(&m));
    serializer_class<silicon_one::la_svi_port_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_svi_port_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_svi_port_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_svi_port_base>(&m));
    serializer_class<silicon_one::la_svi_port_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_svi_port_gibraltar&);



template<>
class serializer_class<silicon_one::la_vrf_port_common_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_protocols", m.m_protocols));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_subnet_ipv4", m.m_subnet_ipv4));
            archive(::cereal::make_nvp("m_subnet_ipv6", m.m_subnet_ipv6));
            archive(::cereal::make_nvp("m_tag1", m.m_tag1));
            archive(::cereal::make_nvp("m_tag2", m.m_tag2));
            archive(::cereal::make_nvp("m_is_active", m.m_is_active));
            archive(::cereal::make_nvp("m_l3_lp_attributes", m.m_l3_lp_attributes));
            archive(::cereal::make_nvp("m_l3_lp_additional_attributes", m.m_l3_lp_additional_attributes));
            archive(::cereal::make_nvp("m_slp_based_forwarding_mpls_label_present", m.m_slp_based_forwarding_mpls_label_present));
            archive(::cereal::make_nvp("m_slp_based_forwarding_mpls_label", m.m_slp_based_forwarding_mpls_label));
            archive(::cereal::make_nvp("m_enable_ecn_remark", m.m_enable_ecn_remark));
            archive(::cereal::make_nvp("m_enable_ecn_counting", m.m_enable_ecn_counting));
            archive(::cereal::make_nvp("m_egress_port_mirror_type", m.m_egress_port_mirror_type));
            archive(::cereal::make_nvp("m_delegate_acls", m.m_delegate_acls));
            archive(::cereal::make_nvp("m_egress_acl_drop_offset", m.m_egress_acl_drop_offset));
            archive(::cereal::make_nvp("m_pbr_enabled", m.m_pbr_enabled));
            archive(::cereal::make_nvp("m_egress_sflow_enabled", m.m_egress_sflow_enabled));
            archive(::cereal::make_nvp("m_is_recycle_ac", m.m_is_recycle_ac));
            archive(::cereal::make_nvp("m_egress_dhcp_snooping", m.m_egress_dhcp_snooping));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_sw", m.m_sw));
            archive(::cereal::make_nvp("m_slp_based_forwarding_destination", m.m_slp_based_forwarding_destination));
            archive(::cereal::make_nvp("m_p_counter", m.m_p_counter));
            archive(::cereal::make_nvp("m_q_counter", m.m_q_counter));
            archive(::cereal::make_nvp("m_egress_mirror_cmd", m.m_egress_mirror_cmd));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
            archive(::cereal::make_nvp("m_ingress_acl_group", m.m_ingress_acl_group));
            archive(::cereal::make_nvp("m_egress_acl_group", m.m_egress_acl_group));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_protocols", m.m_protocols));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_subnet_ipv4", m.m_subnet_ipv4));
            archive(::cereal::make_nvp("m_subnet_ipv6", m.m_subnet_ipv6));
            archive(::cereal::make_nvp("m_tag1", m.m_tag1));
            archive(::cereal::make_nvp("m_tag2", m.m_tag2));
            archive(::cereal::make_nvp("m_is_active", m.m_is_active));
            archive(::cereal::make_nvp("m_l3_lp_attributes", m.m_l3_lp_attributes));
            archive(::cereal::make_nvp("m_l3_lp_additional_attributes", m.m_l3_lp_additional_attributes));
            archive(::cereal::make_nvp("m_slp_based_forwarding_mpls_label_present", m.m_slp_based_forwarding_mpls_label_present));
            archive(::cereal::make_nvp("m_slp_based_forwarding_mpls_label", m.m_slp_based_forwarding_mpls_label));
            archive(::cereal::make_nvp("m_enable_ecn_remark", m.m_enable_ecn_remark));
            archive(::cereal::make_nvp("m_enable_ecn_counting", m.m_enable_ecn_counting));
            archive(::cereal::make_nvp("m_egress_port_mirror_type", m.m_egress_port_mirror_type));
            archive(::cereal::make_nvp("m_delegate_acls", m.m_delegate_acls));
            archive(::cereal::make_nvp("m_egress_acl_drop_offset", m.m_egress_acl_drop_offset));
            archive(::cereal::make_nvp("m_pbr_enabled", m.m_pbr_enabled));
            archive(::cereal::make_nvp("m_egress_sflow_enabled", m.m_egress_sflow_enabled));
            archive(::cereal::make_nvp("m_is_recycle_ac", m.m_is_recycle_ac));
            archive(::cereal::make_nvp("m_egress_dhcp_snooping", m.m_egress_dhcp_snooping));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_sw", m.m_sw));
            archive(::cereal::make_nvp("m_slp_based_forwarding_destination", m.m_slp_based_forwarding_destination));
            archive(::cereal::make_nvp("m_p_counter", m.m_p_counter));
            archive(::cereal::make_nvp("m_q_counter", m.m_q_counter));
            archive(::cereal::make_nvp("m_egress_mirror_cmd", m.m_egress_mirror_cmd));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
            archive(::cereal::make_nvp("m_ingress_acl_group", m.m_ingress_acl_group));
            archive(::cereal::make_nvp("m_egress_acl_group", m.m_egress_acl_group));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_base& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_vrf_port_common_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_base& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_vrf_port_common_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_base&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_multicast_protection_monitor_base var0;
    ar(var0);
    silicon_one::la_next_hop_gibraltar var1;
    ar(var1);
    silicon_one::la_prefix_object_base::prefix_nh_pair var2;
    ar(var2);
    silicon_one::la_prefix_object_gibraltar var3;
    ar(var3);
    silicon_one::la_rate_limiter_set_gibraltar var4;
    ar(var4);
    silicon_one::la_security_group_cell_gibraltar var5;
    ar(var5);
    silicon_one::la_stack_port_gibraltar var6;
    ar(var6);
    silicon_one::la_svi_port_gibraltar var7;
    ar(var7);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_multicast_protection_monitor_base);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_base);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_prefix_object_base);
CEREAL_REGISTER_TYPE(silicon_one::la_prefix_object_base::prefix_nh_pair);
CEREAL_REGISTER_TYPE(silicon_one::la_prefix_object_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_rate_limiter_set_base);
CEREAL_REGISTER_TYPE(silicon_one::la_rate_limiter_set_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_security_group_cell_base);
CEREAL_REGISTER_TYPE(silicon_one::la_security_group_cell_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_stack_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_stack_port_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_svi_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_svi_port_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_vrf_port_common_base);

#pragma GCC diagnostic pop

