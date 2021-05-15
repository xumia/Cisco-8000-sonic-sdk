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

template <class Archive> void save(Archive&, const npl_base_l3_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_base_l3_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_additional_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_additional_attributes_t&);

template <class Archive> void save(Archive&, const npl_lpts_payload_t&);
template <class Archive> void load(Archive&, npl_lpts_payload_t&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_egress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_egress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_filter_group&);
template <class Archive> void load(Archive&, silicon_one::la_filter_group&);

template <class Archive> void save(Archive&, const silicon_one::la_forus_destination&);
template <class Archive> void load(Archive&, silicon_one::la_forus_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_gre_port&);
template <class Archive> void load(Archive&, silicon_one::la_gre_port&);

template <class Archive> void save(Archive&, const silicon_one::la_gue_port&);
template <class Archive> void load(Archive&, silicon_one::la_gue_port&);

template <class Archive> void save(Archive&, const silicon_one::la_ingress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ingress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_over_ip_tunnel_port&);
template <class Archive> void load(Archive&, silicon_one::la_ip_over_ip_tunnel_port&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_tos&);
template <class Archive> void load(Archive&, silicon_one::la_ip_tos&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_l2_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_lpts&);
template <class Archive> void load(Archive&, silicon_one::la_lpts&);

template <class Archive> void save(Archive&, const silicon_one::la_lpts_app_properties&);
template <class Archive> void load(Archive&, silicon_one::la_lpts_app_properties&);

template <class Archive> void save(Archive&, const silicon_one::la_lsr&);
template <class Archive> void load(Archive&, silicon_one::la_lsr&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label_destination&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_nhlfe&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_nhlfe&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_vpn_encap&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_vpn_encap&);

template <class Archive> void save(Archive&, const silicon_one::la_multicast_group_common_base&);
template <class Archive> void load(Archive&, silicon_one::la_multicast_group_common_base&);

template <class Archive> void save(Archive&, const silicon_one::la_multicast_group_common_base::group_member_desc&);
template <class Archive> void load(Archive&, silicon_one::la_multicast_group_common_base::group_member_desc&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_base&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_base&);

template <class Archive> void save(Archive&, const silicon_one::la_og_lpts_application&);
template <class Archive> void load(Archive&, silicon_one::la_og_lpts_application&);

template <class Archive> void save(Archive&, const silicon_one::la_pbts_group&);
template <class Archive> void load(Archive&, silicon_one::la_pbts_group&);

template <class Archive> void save(Archive&, const silicon_one::la_pbts_map_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_pbts_map_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_pcl&);
template <class Archive> void load(Archive&, silicon_one::la_pcl&);

template <class Archive> void save(Archive&, const silicon_one::la_pcl_v4&);
template <class Archive> void load(Archive&, silicon_one::la_pcl_v4&);

template <class Archive> void save(Archive&, const silicon_one::la_pcl_v6&);
template <class Archive> void load(Archive&, silicon_one::la_pcl_v6&);

template <class Archive> void save(Archive&, const silicon_one::la_spa_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_spa_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_switch&);
template <class Archive> void load(Archive&, silicon_one::la_switch&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl::slice_data&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl::slice_data&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl::slice_pair_data&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl::slice_pair_data&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl::vni_profile_data&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl::vni_profile_data&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port&);
template <class Archive> void load(Archive&, silicon_one::la_system_port&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_impl&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_port_common_base&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_port_common_base&);

template <class Archive> void save(Archive&, const silicon_one::lpts_entry_desc&);
template <class Archive> void load(Archive&, silicon_one::lpts_entry_desc&);

template<>
class serializer_class<silicon_one::la_filter_group_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_filter_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_filter_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_filter_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_filter_group>(&m));
    serializer_class<silicon_one::la_filter_group_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_filter_group_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_filter_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_filter_group>(&m));
    serializer_class<silicon_one::la_filter_group_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_filter_group_impl&);



template<>
class serializer_class<silicon_one::la_forus_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_forus_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_bincode", m.m_bincode));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_forus_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_bincode", m.m_bincode));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_forus_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_forus_destination>(&m));
    serializer_class<silicon_one::la_forus_destination_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_forus_destination_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_forus_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_forus_destination>(&m));
    serializer_class<silicon_one::la_forus_destination_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_forus_destination_impl&);



template<>
class serializer_class<silicon_one::la_gre_port_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_gre_port_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_tunnel_mode", m.m_tunnel_mode));
            archive(::cereal::make_nvp("m_local_ip_prefix", m.m_local_ip_prefix));
            archive(::cereal::make_nvp("m_remote_ip_prefix", m.m_remote_ip_prefix));
            archive(::cereal::make_nvp("m_lp_attribute_inheritance_mode", m.m_lp_attribute_inheritance_mode));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_decrement_inner_ttl", m.m_decrement_inner_ttl));
            archive(::cereal::make_nvp("m_encap_qos_mode", m.m_encap_qos_mode));
            archive(::cereal::make_nvp("m_encap_tos", m.m_encap_tos));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_key", m.m_key));
            archive(::cereal::make_nvp("m_sequence_number", m.m_sequence_number));
            archive(::cereal::make_nvp("m_termination_type", m.m_termination_type));
            archive(::cereal::make_nvp("m_dip_entropy_mode", m.m_dip_entropy_mode));
            archive(::cereal::make_nvp("m_npl_dip_entropy_mode", m.m_npl_dip_entropy_mode));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_sip_index", m.m_sip_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_vrf", m.m_underlay_vrf));
            archive(::cereal::make_nvp("m_overlay_vrf", m.m_overlay_vrf));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_gre_port_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_tunnel_mode", m.m_tunnel_mode));
            archive(::cereal::make_nvp("m_local_ip_prefix", m.m_local_ip_prefix));
            archive(::cereal::make_nvp("m_remote_ip_prefix", m.m_remote_ip_prefix));
            archive(::cereal::make_nvp("m_lp_attribute_inheritance_mode", m.m_lp_attribute_inheritance_mode));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_decrement_inner_ttl", m.m_decrement_inner_ttl));
            archive(::cereal::make_nvp("m_encap_qos_mode", m.m_encap_qos_mode));
            archive(::cereal::make_nvp("m_encap_tos", m.m_encap_tos));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_key", m.m_key));
            archive(::cereal::make_nvp("m_sequence_number", m.m_sequence_number));
            archive(::cereal::make_nvp("m_termination_type", m.m_termination_type));
            archive(::cereal::make_nvp("m_dip_entropy_mode", m.m_dip_entropy_mode));
            archive(::cereal::make_nvp("m_npl_dip_entropy_mode", m.m_npl_dip_entropy_mode));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_sip_index", m.m_sip_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_vrf", m.m_underlay_vrf));
            archive(::cereal::make_nvp("m_overlay_vrf", m.m_overlay_vrf));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_gre_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_gre_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_gre_port_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_gre_port_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_gre_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_gre_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_gre_port_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_gre_port_impl&);



template<>
class serializer_class<silicon_one::la_gre_port_impl::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_gre_port_impl::slice_data& m) {
            archive(::cereal::make_nvp("base_l3_atrrib", m.base_l3_atrrib));
            archive(::cereal::make_nvp("additional_attribs", m.additional_attribs));
            archive(::cereal::make_nvp("ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry", m.ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry));
            archive(::cereal::make_nvp("ipv4_gre_tunnel_termination_dip_index_tt0_table_entry", m.ipv4_gre_tunnel_termination_dip_index_tt0_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_gre_port_impl::slice_data& m) {
            archive(::cereal::make_nvp("base_l3_atrrib", m.base_l3_atrrib));
            archive(::cereal::make_nvp("additional_attribs", m.additional_attribs));
            archive(::cereal::make_nvp("ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry", m.ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry));
            archive(::cereal::make_nvp("ipv4_gre_tunnel_termination_dip_index_tt0_table_entry", m.ipv4_gre_tunnel_termination_dip_index_tt0_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_gre_port_impl::slice_data& m)
{
    serializer_class<silicon_one::la_gre_port_impl::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_gre_port_impl::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_gre_port_impl::slice_data& m)
{
    serializer_class<silicon_one::la_gre_port_impl::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_gre_port_impl::slice_data&);



template<>
class serializer_class<silicon_one::la_gre_port_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_gre_port_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("large_encap_ip_tunnel_table_entry", m.large_encap_ip_tunnel_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_gre_port_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("large_encap_ip_tunnel_table_entry", m.large_encap_ip_tunnel_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_gre_port_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_gre_port_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_gre_port_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_gre_port_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_gre_port_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_gre_port_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_gue_port_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_gue_port_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_remote_ip_addr", m.m_remote_ip_addr));
            archive(::cereal::make_nvp("m_local_prefix", m.m_local_prefix));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_addl_l3_lp_attributes", m.m_addl_l3_lp_attributes));
            archive(::cereal::make_nvp("m_my_ipv4_index", m.m_my_ipv4_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_vrf", m.m_underlay_vrf));
            archive(::cereal::make_nvp("m_overlay_vrf", m.m_overlay_vrf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_gue_port_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_remote_ip_addr", m.m_remote_ip_addr));
            archive(::cereal::make_nvp("m_local_prefix", m.m_local_prefix));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_addl_l3_lp_attributes", m.m_addl_l3_lp_attributes));
            archive(::cereal::make_nvp("m_my_ipv4_index", m.m_my_ipv4_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_vrf", m.m_underlay_vrf));
            archive(::cereal::make_nvp("m_overlay_vrf", m.m_overlay_vrf));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_gue_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_gue_port>(&m));
    serializer_class<silicon_one::la_gue_port_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_gue_port_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_gue_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_gue_port>(&m));
    serializer_class<silicon_one::la_gue_port_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_gue_port_impl&);



template<>
class serializer_class<silicon_one::la_gue_port_impl::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_gue_port_impl::slice_data& m) {
            archive(::cereal::make_nvp("my_ipv4_table_entry_location", m.my_ipv4_table_entry_location));
            archive(::cereal::make_nvp("m_base_l3_lp_attributes", m.m_base_l3_lp_attributes));
            archive(::cereal::make_nvp("my_ipv4_table_entry", m.my_ipv4_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_gue_port_impl::slice_data& m) {
            archive(::cereal::make_nvp("my_ipv4_table_entry_location", m.my_ipv4_table_entry_location));
            archive(::cereal::make_nvp("m_base_l3_lp_attributes", m.m_base_l3_lp_attributes));
            archive(::cereal::make_nvp("my_ipv4_table_entry", m.my_ipv4_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_gue_port_impl::slice_data& m)
{
    serializer_class<silicon_one::la_gue_port_impl::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_gue_port_impl::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_gue_port_impl::slice_data& m)
{
    serializer_class<silicon_one::la_gue_port_impl::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_gue_port_impl::slice_data&);



template<>
class serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ip_over_ip_tunnel_port_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_tunnel_mode", m.m_tunnel_mode));
            archive(::cereal::make_nvp("m_ip_addr", m.m_ip_addr));
            archive(::cereal::make_nvp("m_prefix", m.m_prefix));
            archive(::cereal::make_nvp("m_lp_attribute_inheritance_mode", m.m_lp_attribute_inheritance_mode));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_decrement_inner_ttl", m.m_decrement_inner_ttl));
            archive(::cereal::make_nvp("m_encap_qos_mode", m.m_encap_qos_mode));
            archive(::cereal::make_nvp("m_encap_tos", m.m_encap_tos));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_dip_entropy_mode", m.m_dip_entropy_mode));
            archive(::cereal::make_nvp("m_npl_dip_entropy_mode", m.m_npl_dip_entropy_mode));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_addl_l3_lp_attributes", m.m_addl_l3_lp_attributes));
            archive(::cereal::make_nvp("m_my_ipv4_index", m.m_my_ipv4_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_vrf", m.m_underlay_vrf));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ip_over_ip_tunnel_port_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_tunnel_mode", m.m_tunnel_mode));
            archive(::cereal::make_nvp("m_ip_addr", m.m_ip_addr));
            archive(::cereal::make_nvp("m_prefix", m.m_prefix));
            archive(::cereal::make_nvp("m_lp_attribute_inheritance_mode", m.m_lp_attribute_inheritance_mode));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_decrement_inner_ttl", m.m_decrement_inner_ttl));
            archive(::cereal::make_nvp("m_encap_qos_mode", m.m_encap_qos_mode));
            archive(::cereal::make_nvp("m_encap_tos", m.m_encap_tos));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_dip_entropy_mode", m.m_dip_entropy_mode));
            archive(::cereal::make_nvp("m_npl_dip_entropy_mode", m.m_npl_dip_entropy_mode));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_addl_l3_lp_attributes", m.m_addl_l3_lp_attributes));
            archive(::cereal::make_nvp("m_my_ipv4_index", m.m_my_ipv4_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_vrf", m.m_underlay_vrf));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ip_over_ip_tunnel_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ip_over_ip_tunnel_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ip_over_ip_tunnel_port_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ip_over_ip_tunnel_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ip_over_ip_tunnel_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ip_over_ip_tunnel_port_impl&);



template<>
class serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data& m) {
            archive(::cereal::make_nvp("my_ipv4_table_entry_location", m.my_ipv4_table_entry_location));
            archive(::cereal::make_nvp("m_base_l3_lp_attributes", m.m_base_l3_lp_attributes));
            archive(::cereal::make_nvp("my_ipv4_table_entry", m.my_ipv4_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data& m) {
            archive(::cereal::make_nvp("my_ipv4_table_entry_location", m.my_ipv4_table_entry_location));
            archive(::cereal::make_nvp("m_base_l3_lp_attributes", m.m_base_l3_lp_attributes));
            archive(::cereal::make_nvp("my_ipv4_table_entry", m.my_ipv4_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data& m)
{
    serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data& m)
{
    serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ip_over_ip_tunnel_port_impl::slice_data&);



template<>
class serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("large_encap_ip_tunnel_table_entry", m.large_encap_ip_tunnel_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("large_encap_ip_tunnel_table_entry", m.large_encap_ip_tunnel_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ip_over_ip_tunnel_port_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_lpts_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_lpts_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_entries", m.m_entries));
            archive(::cereal::make_nvp("m_null_allocations", m.m_null_allocations));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_meter_to_use_count", m.m_meter_to_use_count));
            archive(::cereal::make_nvp("m_null_meter_profile", m.m_null_meter_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_lpts_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_entries", m.m_entries));
            archive(::cereal::make_nvp("m_null_allocations", m.m_null_allocations));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_meter_to_use_count", m.m_meter_to_use_count));
            archive(::cereal::make_nvp("m_null_meter_profile", m.m_null_meter_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_lpts_impl& m)
{
    archive(cereal::base_class<silicon_one::la_lpts>(&m));
    serializer_class<silicon_one::la_lpts_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_lpts_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_lpts_impl& m)
{
    archive(cereal::base_class<silicon_one::la_lpts>(&m));
    serializer_class<silicon_one::la_lpts_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_lpts_impl&);



template<>
class serializer_class<silicon_one::la_lpts_impl::lpts_entry_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_lpts_impl::lpts_entry_data& m) {
            archive(::cereal::make_nvp("entry_desc", m.entry_desc));
            archive(::cereal::make_nvp("em_sptr", m.em_sptr));
            archive(::cereal::make_nvp("meter_sptr", m.meter_sptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_lpts_impl::lpts_entry_data& m) {
            archive(::cereal::make_nvp("entry_desc", m.entry_desc));
            archive(::cereal::make_nvp("em_sptr", m.em_sptr));
            archive(::cereal::make_nvp("meter_sptr", m.meter_sptr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_lpts_impl::lpts_entry_data& m)
{
    serializer_class<silicon_one::la_lpts_impl::lpts_entry_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_lpts_impl::lpts_entry_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_lpts_impl::lpts_entry_data& m)
{
    serializer_class<silicon_one::la_lpts_impl::lpts_entry_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_lpts_impl::lpts_entry_data&);



template<>
class serializer_class<silicon_one::la_lsr_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_lsr_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_entry_info_map", m.m_entry_info_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_lsr_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_entry_info_map", m.m_entry_info_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_lsr_impl& m)
{
    archive(cereal::base_class<silicon_one::la_lsr>(&m));
    serializer_class<silicon_one::la_lsr_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_lsr_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_lsr_impl& m)
{
    archive(cereal::base_class<silicon_one::la_lsr>(&m));
    serializer_class<silicon_one::la_lsr_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_lsr_impl&);



template<>
class serializer_class<silicon_one::la_lsr_impl::internal_mpls_route_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_lsr_impl::internal_mpls_route_info& m) {
            archive(::cereal::make_nvp("vrf_gid", m.vrf_gid));
            archive(::cereal::make_nvp("user_data", m.user_data));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_lsr_impl::internal_mpls_route_info& m) {
            archive(::cereal::make_nvp("vrf_gid", m.vrf_gid));
            archive(::cereal::make_nvp("user_data", m.user_data));
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_lsr_impl::internal_mpls_route_info& m)
{
    serializer_class<silicon_one::la_lsr_impl::internal_mpls_route_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_lsr_impl::internal_mpls_route_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_lsr_impl::internal_mpls_route_info& m)
{
    serializer_class<silicon_one::la_lsr_impl::internal_mpls_route_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_lsr_impl::internal_mpls_route_info&);



template<>
class serializer_class<silicon_one::la_mpls_label_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_label_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_vpn_label_ptr", m.m_vpn_label_ptr));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_label_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_vpn_label_ptr", m.m_vpn_label_ptr));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_label_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_label_destination>(&m));
    serializer_class<silicon_one::la_mpls_label_destination_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_label_destination_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_label_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_label_destination>(&m));
    serializer_class<silicon_one::la_mpls_label_destination_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_label_destination_impl&);



template<>
class serializer_class<silicon_one::la_mpls_multicast_group_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_multicast_group_impl& m) {
            archive(::cereal::make_nvp("m_slice_use_count", m.m_slice_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_members", m.m_members));
            archive(::cereal::make_nvp("m_protected_members", m.m_protected_members));
            archive(::cereal::make_nvp("m_mc_common", m.m_mc_common));
            archive(::cereal::make_nvp("m_punt_enabled", m.m_punt_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mc_copy_id_mapping", m.m_mc_copy_id_mapping));
            archive(::cereal::make_nvp("m_dsp_mapping", m.m_dsp_mapping));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_multicast_group_impl& m) {
            archive(::cereal::make_nvp("m_slice_use_count", m.m_slice_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_members", m.m_members));
            archive(::cereal::make_nvp("m_protected_members", m.m_protected_members));
            archive(::cereal::make_nvp("m_mc_common", m.m_mc_common));
            archive(::cereal::make_nvp("m_punt_enabled", m.m_punt_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mc_copy_id_mapping", m.m_mc_copy_id_mapping));
            archive(::cereal::make_nvp("m_dsp_mapping", m.m_dsp_mapping));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_multicast_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_multicast_group>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_mpls_multicast_group_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_multicast_group_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_multicast_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_multicast_group>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_mpls_multicast_group_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_multicast_group_impl&);



template<>
class serializer_class<silicon_one::la_mpls_nhlfe_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_nhlfe_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_action", m.m_action));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_mp_label", m.m_mp_label));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_destination", m.m_l3_destination));
            archive(::cereal::make_nvp("m_dsp", m.m_dsp));
            archive(::cereal::make_nvp("m_spa", m.m_spa));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_nhlfe_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_action", m.m_action));
            archive(::cereal::make_nvp("m_label", m.m_label));
            archive(::cereal::make_nvp("m_mp_label", m.m_mp_label));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_destination", m.m_l3_destination));
            archive(::cereal::make_nvp("m_dsp", m.m_dsp));
            archive(::cereal::make_nvp("m_spa", m.m_spa));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_nhlfe_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_nhlfe>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_mpls_nhlfe_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_nhlfe_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_nhlfe_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_nhlfe>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_mpls_nhlfe_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_nhlfe_impl&);



template<>
class serializer_class<silicon_one::la_mpls_nhlfe_impl::resolution_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_nhlfe_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_nhlfe_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_nhlfe_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_mpls_nhlfe_impl::resolution_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_nhlfe_impl::resolution_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_nhlfe_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_mpls_nhlfe_impl::resolution_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_nhlfe_impl::resolution_data&);



template<>
class serializer_class<silicon_one::la_mpls_vpn_encap_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_vpn_encap_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_nh_label_map", m.m_nh_label_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_vpn_encap_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_nh_label_map", m.m_nh_label_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_vpn_encap_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_vpn_encap>(&m));
    serializer_class<silicon_one::la_mpls_vpn_encap_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_vpn_encap_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_vpn_encap_impl& m)
{
    archive(cereal::base_class<silicon_one::la_mpls_vpn_encap>(&m));
    serializer_class<silicon_one::la_mpls_vpn_encap_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_vpn_encap_impl&);



template<>
class serializer_class<silicon_one::la_mpls_vpn_encap_impl::nh_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_mpls_vpn_encap_impl::nh_info& m) {
            archive(::cereal::make_nvp("v4_label", m.v4_label));
            archive(::cereal::make_nvp("v4_valid", m.v4_valid));
            archive(::cereal::make_nvp("v6_label", m.v6_label));
            archive(::cereal::make_nvp("v6_valid", m.v6_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_mpls_vpn_encap_impl::nh_info& m) {
            archive(::cereal::make_nvp("v4_label", m.v4_label));
            archive(::cereal::make_nvp("v4_valid", m.v4_valid));
            archive(::cereal::make_nvp("v6_label", m.v6_label));
            archive(::cereal::make_nvp("v6_valid", m.v6_valid));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_mpls_vpn_encap_impl::nh_info& m)
{
    serializer_class<silicon_one::la_mpls_vpn_encap_impl::nh_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_mpls_vpn_encap_impl::nh_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_mpls_vpn_encap_impl::nh_info& m)
{
    serializer_class<silicon_one::la_mpls_vpn_encap_impl::nh_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_mpls_vpn_encap_impl::nh_info&);



template<>
class serializer_class<silicon_one::la_next_hop_impl_common> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_next_hop_impl_common& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_next_hop", m.m_next_hop));
            archive(::cereal::make_nvp("m_l3_port", m.m_l3_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_next_hop_impl_common& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_next_hop", m.m_next_hop));
            archive(::cereal::make_nvp("m_l3_port", m.m_l3_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_next_hop_impl_common& m)
{
    serializer_class<silicon_one::la_next_hop_impl_common>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_next_hop_impl_common&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_next_hop_impl_common& m)
{
    serializer_class<silicon_one::la_next_hop_impl_common>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_next_hop_impl_common&);



template<>
class serializer_class<silicon_one::la_og_lpts_application_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_og_lpts_application_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_app_id", m.m_app_id));
            archive(::cereal::make_nvp("m_app_properties", m.m_app_properties));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_src_pcl", m.m_src_pcl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_og_lpts_application_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_app_id", m.m_app_id));
            archive(::cereal::make_nvp("m_app_properties", m.m_app_properties));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_src_pcl", m.m_src_pcl));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_og_lpts_application_impl& m)
{
    archive(cereal::base_class<silicon_one::la_og_lpts_application>(&m));
    serializer_class<silicon_one::la_og_lpts_application_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_og_lpts_application_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_og_lpts_application_impl& m)
{
    archive(cereal::base_class<silicon_one::la_og_lpts_application>(&m));
    serializer_class<silicon_one::la_og_lpts_application_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_og_lpts_application_impl&);



template<>
class serializer_class<silicon_one::la_pbts_group_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_pbts_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_first_dest_gid", m.m_first_dest_gid));
            archive(::cereal::make_nvp("m_gid_valid", m.m_gid_valid));
            archive(::cereal::make_nvp("m_user_count", m.m_user_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_profile", m.m_profile));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_pbts_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_first_dest_gid", m.m_first_dest_gid));
            archive(::cereal::make_nvp("m_gid_valid", m.m_gid_valid));
            archive(::cereal::make_nvp("m_user_count", m.m_user_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_profile", m.m_profile));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_pbts_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_pbts_group>(&m));
    serializer_class<silicon_one::la_pbts_group_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_pbts_group_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_pbts_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_pbts_group>(&m));
    serializer_class<silicon_one::la_pbts_group_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_pbts_group_impl&);



template<>
class serializer_class<silicon_one::la_pcl_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_pcl_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_pcl_type", m.m_pcl_type));
            archive(::cereal::make_nvp("m_pcl_gid", m.m_pcl_gid));
            archive(::cereal::make_nvp("m_v4_prefixes", m.m_v4_prefixes));
            archive(::cereal::make_nvp("m_v6_prefixes", m.m_v6_prefixes));
            archive(::cereal::make_nvp("m_feature", m.m_feature));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_pcl_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_pcl_type", m.m_pcl_type));
            archive(::cereal::make_nvp("m_pcl_gid", m.m_pcl_gid));
            archive(::cereal::make_nvp("m_v4_prefixes", m.m_v4_prefixes));
            archive(::cereal::make_nvp("m_v6_prefixes", m.m_v6_prefixes));
            archive(::cereal::make_nvp("m_feature", m.m_feature));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_pcl_impl& m)
{
    archive(cereal::base_class<silicon_one::la_pcl>(&m));
    serializer_class<silicon_one::la_pcl_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_pcl_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_pcl_impl& m)
{
    archive(cereal::base_class<silicon_one::la_pcl>(&m));
    serializer_class<silicon_one::la_pcl_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_pcl_impl&);



template<>
class serializer_class<silicon_one::la_switch_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_switch_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_max_switch_mac_addresses", m.m_max_switch_mac_addresses));
            archive(::cereal::make_nvp("m_encap_vni", m.m_encap_vni));
            archive(::cereal::make_nvp("m_encap_vni_use_count", m.m_encap_vni_use_count));
            archive(::cereal::make_nvp("m_decap_vni", m.m_decap_vni));
            archive(::cereal::make_nvp("m_vni_profile_data", m.m_vni_profile_data));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_relay_attributes_entry", m.m_relay_attributes_entry));
            archive(::cereal::make_nvp("m_vxlan_encap_counter", m.m_vxlan_encap_counter));
            archive(::cereal::make_nvp("m_vxlan_decap_counter", m.m_vxlan_decap_counter));
            archive(::cereal::make_nvp("m_ipv4_em_entries", m.m_ipv4_em_entries));
            archive(::cereal::make_nvp("m_ipv6_em_entries", m.m_ipv6_em_entries));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_switch_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_max_switch_mac_addresses", m.m_max_switch_mac_addresses));
            archive(::cereal::make_nvp("m_encap_vni", m.m_encap_vni));
            archive(::cereal::make_nvp("m_encap_vni_use_count", m.m_encap_vni_use_count));
            archive(::cereal::make_nvp("m_decap_vni", m.m_decap_vni));
            archive(::cereal::make_nvp("m_vni_profile_data", m.m_vni_profile_data));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_relay_attributes_entry", m.m_relay_attributes_entry));
            archive(::cereal::make_nvp("m_vxlan_encap_counter", m.m_vxlan_encap_counter));
            archive(::cereal::make_nvp("m_vxlan_decap_counter", m.m_vxlan_decap_counter));
            archive(::cereal::make_nvp("m_ipv4_em_entries", m.m_ipv4_em_entries));
            archive(::cereal::make_nvp("m_ipv6_em_entries", m.m_ipv6_em_entries));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_switch_impl& m)
{
    archive(cereal::base_class<silicon_one::la_switch>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_switch_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_switch_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_switch_impl& m)
{
    archive(cereal::base_class<silicon_one::la_switch>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_switch_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_switch_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_filter_group_impl var0;
    ar(var0);
    silicon_one::la_forus_destination_impl var1;
    ar(var1);
    silicon_one::la_gre_port_impl var2;
    ar(var2);
    silicon_one::la_gue_port_impl var3;
    ar(var3);
    silicon_one::la_ip_over_ip_tunnel_port_impl var4;
    ar(var4);
    silicon_one::la_lpts_impl var5;
    ar(var5);
    silicon_one::la_lsr_impl var6;
    ar(var6);
    silicon_one::la_mpls_label_destination_impl var7;
    ar(var7);
    silicon_one::la_mpls_multicast_group_impl var8;
    ar(var8);
    silicon_one::la_mpls_nhlfe_impl var9;
    ar(var9);
    silicon_one::la_mpls_vpn_encap_impl var10;
    ar(var10);
    silicon_one::la_next_hop_impl_common var11;
    ar(var11);
    silicon_one::la_og_lpts_application_impl var12;
    ar(var12);
    silicon_one::la_pbts_group_impl var13;
    ar(var13);
    silicon_one::la_pcl_impl var14;
    ar(var14);
    silicon_one::la_switch_impl var15;
    ar(var15);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_filter_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_forus_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_gre_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_gue_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ip_over_ip_tunnel_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_lpts_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_lsr_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_mpls_label_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_mpls_multicast_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_mpls_nhlfe_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_mpls_vpn_encap_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_impl_common);
CEREAL_REGISTER_TYPE(silicon_one::la_og_lpts_application_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_pbts_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_pcl_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_switch_impl);

#pragma GCC diagnostic pop

