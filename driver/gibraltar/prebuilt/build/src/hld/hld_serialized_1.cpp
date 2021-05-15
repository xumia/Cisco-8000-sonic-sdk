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

unsigned g_hld_serialization_version = 1;
void cereal_gen_set_serialization_version_hld(unsigned int version) {g_hld_serialization_version = version;}

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_delegate&);
template <class Archive> void load(Archive&, silicon_one::la_acl_delegate&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_cgm_evicted_profile&);
template <class Archive> void load(Archive&, silicon_one::la_voq_cgm_evicted_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_cgm_profile&);
template <class Archive> void load(Archive&, silicon_one::la_voq_cgm_profile&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr&);

template<>
class serializer_class<runtime_flexibility_library> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const runtime_flexibility_library& m) {
            archive(::cereal::make_nvp("m_is_placing_for_nsim", m.m_is_placing_for_nsim));
            archive(::cereal::make_nvp("m_is_placing_for_hw", m.m_is_placing_for_hw));
            archive(::cereal::make_nvp("m_library_id", m.m_library_id));
            archive(::cereal::make_nvp("m_tables_key_parts", m.m_tables_key_parts));
            archive(::cereal::make_nvp("m_udk_components", m.m_udk_components));
            archive(::cereal::make_nvp("m_udk_placement_buckets", m.m_udk_placement_buckets));
            archive(::cereal::make_nvp("m_udk_tables_components", m.m_udk_tables_components));
            archive(::cereal::make_nvp("m_processed_udk_tables_components", m.m_processed_udk_tables_components));
            archive(::cereal::make_nvp("m_processed_component_index_to_original_indices_and_offset", m.m_processed_component_index_to_original_indices_and_offset));
            archive(::cereal::make_nvp("m_udk_data_str_outputs", m.m_udk_data_str_outputs));
            archive(::cereal::make_nvp("m_verbose", m.m_verbose));
            archive(::cereal::make_nvp("m_components_fragmentization_enable", m.m_components_fragmentization_enable));
            archive(::cereal::make_nvp("m_log_level", m.m_log_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, runtime_flexibility_library& m) {
            archive(::cereal::make_nvp("m_is_placing_for_nsim", m.m_is_placing_for_nsim));
            archive(::cereal::make_nvp("m_is_placing_for_hw", m.m_is_placing_for_hw));
            archive(::cereal::make_nvp("m_library_id", m.m_library_id));
            archive(::cereal::make_nvp("m_tables_key_parts", m.m_tables_key_parts));
            archive(::cereal::make_nvp("m_udk_components", m.m_udk_components));
            archive(::cereal::make_nvp("m_udk_placement_buckets", m.m_udk_placement_buckets));
            archive(::cereal::make_nvp("m_udk_tables_components", m.m_udk_tables_components));
            archive(::cereal::make_nvp("m_processed_udk_tables_components", m.m_processed_udk_tables_components));
            archive(::cereal::make_nvp("m_processed_component_index_to_original_indices_and_offset", m.m_processed_component_index_to_original_indices_and_offset));
            archive(::cereal::make_nvp("m_udk_data_str_outputs", m.m_udk_data_str_outputs));
            archive(::cereal::make_nvp("m_verbose", m.m_verbose));
            archive(::cereal::make_nvp("m_components_fragmentization_enable", m.m_components_fragmentization_enable));
            archive(::cereal::make_nvp("m_log_level", m.m_log_level));
    }
};
template <class Archive>
void
save(Archive& archive, const runtime_flexibility_library& m)
{
    serializer_class<runtime_flexibility_library>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const runtime_flexibility_library&);

template <class Archive>
void
load(Archive& archive, runtime_flexibility_library& m)
{
    serializer_class<runtime_flexibility_library>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, runtime_flexibility_library&);



template<>
class serializer_class<runtime_flexibility_library::udk_component_internal> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const runtime_flexibility_library::udk_component_internal& m) {
            archive(::cereal::make_nvp("component", m.component));
            archive(::cereal::make_nvp("index", m.index));
            archive(::cereal::make_nvp("component_index_in_place_udk_vec_per_table", m.component_index_in_place_udk_vec_per_table));
            archive(::cereal::make_nvp("component_fragment_offset", m.component_fragment_offset));
            archive(::cereal::make_nvp("number_of_tables_used_in", m.number_of_tables_used_in));
            archive(::cereal::make_nvp("fragmented_component_parent_skip_placement", m.fragmented_component_parent_skip_placement));
            archive(::cereal::make_nvp("fragmented_component_child", m.fragmented_component_child));
            archive(::cereal::make_nvp("lsb_penalty", m.lsb_penalty));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, runtime_flexibility_library::udk_component_internal& m) {
            archive(::cereal::make_nvp("component", m.component));
            archive(::cereal::make_nvp("index", m.index));
            archive(::cereal::make_nvp("component_index_in_place_udk_vec_per_table", m.component_index_in_place_udk_vec_per_table));
            archive(::cereal::make_nvp("component_fragment_offset", m.component_fragment_offset));
            archive(::cereal::make_nvp("number_of_tables_used_in", m.number_of_tables_used_in));
            archive(::cereal::make_nvp("fragmented_component_parent_skip_placement", m.fragmented_component_parent_skip_placement));
            archive(::cereal::make_nvp("fragmented_component_child", m.fragmented_component_child));
            archive(::cereal::make_nvp("lsb_penalty", m.lsb_penalty));
    }
};
template <class Archive>
void
save(Archive& archive, const runtime_flexibility_library::udk_component_internal& m)
{
    serializer_class<runtime_flexibility_library::udk_component_internal>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const runtime_flexibility_library::udk_component_internal&);

template <class Archive>
void
load(Archive& archive, runtime_flexibility_library::udk_component_internal& m)
{
    serializer_class<runtime_flexibility_library::udk_component_internal>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, runtime_flexibility_library::udk_component_internal&);



template<>
class serializer_class<runtime_flexibility_library::udk_components_group> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const runtime_flexibility_library::udk_components_group& m) {
            archive(::cereal::make_nvp("components", m.components));
            archive(::cereal::make_nvp("msb_offset", m.msb_offset));
            archive(::cereal::make_nvp("offset_to_lsb_with_penalty", m.offset_to_lsb_with_penalty));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, runtime_flexibility_library::udk_components_group& m) {
            archive(::cereal::make_nvp("components", m.components));
            archive(::cereal::make_nvp("msb_offset", m.msb_offset));
            archive(::cereal::make_nvp("offset_to_lsb_with_penalty", m.offset_to_lsb_with_penalty));
    }
};
template <class Archive>
void
save(Archive& archive, const runtime_flexibility_library::udk_components_group& m)
{
    serializer_class<runtime_flexibility_library::udk_components_group>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const runtime_flexibility_library::udk_components_group&);

template <class Archive>
void
load(Archive& archive, runtime_flexibility_library::udk_components_group& m)
{
    serializer_class<runtime_flexibility_library::udk_components_group>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, runtime_flexibility_library::udk_components_group&);



template<>
class serializer_class<runtime_flexibility_library::udk_placement_bucket> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const runtime_flexibility_library::udk_placement_bucket& m) {
            archive(::cereal::make_nvp("available_width", m.available_width));
            archive(::cereal::make_nvp("used_width", m.used_width));
            archive(::cereal::make_nvp("field_select", m.field_select));
            archive(::cereal::make_nvp("bucket_type", m.bucket_type));
            archive(::cereal::make_nvp("placed_fields", m.placed_fields));
            archive(::cereal::make_nvp("placed_component_groups", m.placed_component_groups));
            archive(::cereal::make_nvp("max_msb_penalty", m.max_msb_penalty));
            archive(::cereal::make_nvp("tables_in", m.tables_in));
            archive(::cereal::make_nvp("bucket_index", m.bucket_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, runtime_flexibility_library::udk_placement_bucket& m) {
            archive(::cereal::make_nvp("available_width", m.available_width));
            archive(::cereal::make_nvp("used_width", m.used_width));
            archive(::cereal::make_nvp("field_select", m.field_select));
            archive(::cereal::make_nvp("bucket_type", m.bucket_type));
            archive(::cereal::make_nvp("placed_fields", m.placed_fields));
            archive(::cereal::make_nvp("placed_component_groups", m.placed_component_groups));
            archive(::cereal::make_nvp("max_msb_penalty", m.max_msb_penalty));
            archive(::cereal::make_nvp("tables_in", m.tables_in));
            archive(::cereal::make_nvp("bucket_index", m.bucket_index));
    }
};
template <class Archive>
void
save(Archive& archive, const runtime_flexibility_library::udk_placement_bucket& m)
{
    serializer_class<runtime_flexibility_library::udk_placement_bucket>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const runtime_flexibility_library::udk_placement_bucket&);

template <class Archive>
void
load(Archive& archive, runtime_flexibility_library::udk_placement_bucket& m)
{
    serializer_class<runtime_flexibility_library::udk_placement_bucket>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, runtime_flexibility_library::udk_placement_bucket&);



template<>
class serializer_class<runtime_flexibility_library::key_part> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const runtime_flexibility_library::key_part& m) {
            archive(::cereal::make_nvp("max_width", m.max_width));
            archive(::cereal::make_nvp("used_width", m.used_width));
            archive(::cereal::make_nvp("udk_placement_buckets_indices", m.udk_placement_buckets_indices));
            archive(::cereal::make_nvp("udk_placement_buckets", m.udk_placement_buckets));
            archive(::cereal::make_nvp("range_compression_components", m.range_compression_components));
            archive(::cereal::make_nvp("number_of_buckets_supporting_udf", m.number_of_buckets_supporting_udf));
            archive(::cereal::make_nvp("number_of_constant_bits", m.number_of_constant_bits));
            archive(::cereal::make_nvp("max_number_of_buckets", m.max_number_of_buckets));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, runtime_flexibility_library::key_part& m) {
            archive(::cereal::make_nvp("max_width", m.max_width));
            archive(::cereal::make_nvp("used_width", m.used_width));
            archive(::cereal::make_nvp("udk_placement_buckets_indices", m.udk_placement_buckets_indices));
            archive(::cereal::make_nvp("udk_placement_buckets", m.udk_placement_buckets));
            archive(::cereal::make_nvp("range_compression_components", m.range_compression_components));
            archive(::cereal::make_nvp("number_of_buckets_supporting_udf", m.number_of_buckets_supporting_udf));
            archive(::cereal::make_nvp("number_of_constant_bits", m.number_of_constant_bits));
            archive(::cereal::make_nvp("max_number_of_buckets", m.max_number_of_buckets));
    }
};
template <class Archive>
void
save(Archive& archive, const runtime_flexibility_library::key_part& m)
{
    serializer_class<runtime_flexibility_library::key_part>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const runtime_flexibility_library::key_part&);

template <class Archive>
void
load(Archive& archive, runtime_flexibility_library::key_part& m)
{
    serializer_class<runtime_flexibility_library::key_part>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, runtime_flexibility_library::key_part&);



template<>
class serializer_class<runtime_flexibility_library::udk_component_pointer> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const runtime_flexibility_library::udk_component_pointer& m) {
            archive(::cereal::make_nvp("original_index", m.original_index));
            archive(::cereal::make_nvp("offset_to_add", m.offset_to_add));
            archive(::cereal::make_nvp("width", m.width));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, runtime_flexibility_library::udk_component_pointer& m) {
            archive(::cereal::make_nvp("original_index", m.original_index));
            archive(::cereal::make_nvp("offset_to_add", m.offset_to_add));
            archive(::cereal::make_nvp("width", m.width));
    }
};
template <class Archive>
void
save(Archive& archive, const runtime_flexibility_library::udk_component_pointer& m)
{
    serializer_class<runtime_flexibility_library::udk_component_pointer>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const runtime_flexibility_library::udk_component_pointer&);

template <class Archive>
void
load(Archive& archive, runtime_flexibility_library::udk_component_pointer& m)
{
    serializer_class<runtime_flexibility_library::udk_component_pointer>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, runtime_flexibility_library::udk_component_pointer&);



template<>
class serializer_class<field_select_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const field_select_info& m) {
            archive(::cereal::make_nvp("fs_index", m.fs_index));
            archive(::cereal::make_nvp("fs_allocated_width", m.fs_allocated_width));
            archive(::cereal::make_nvp("offset_in_ucode", m.offset_in_ucode));
            archive(::cereal::make_nvp("num_of_bits_in_ucode", m.num_of_bits_in_ucode));
            archive(::cereal::make_nvp("first_channel", m.first_channel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, field_select_info& m) {
            archive(::cereal::make_nvp("fs_index", m.fs_index));
            archive(::cereal::make_nvp("fs_allocated_width", m.fs_allocated_width));
            archive(::cereal::make_nvp("offset_in_ucode", m.offset_in_ucode));
            archive(::cereal::make_nvp("num_of_bits_in_ucode", m.num_of_bits_in_ucode));
            archive(::cereal::make_nvp("first_channel", m.first_channel));
    }
};
template <class Archive>
void
save(Archive& archive, const field_select_info& m)
{
    serializer_class<field_select_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const field_select_info&);

template <class Archive>
void
load(Archive& archive, field_select_info& m)
{
    serializer_class<field_select_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, field_select_info&);



template<>
class serializer_class<table_line_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const table_line_info_t& m) {
            archive(::cereal::make_nvp("line_num", m.line_num));
            archive(::cereal::make_nvp("calculated_field_id_to_fs_index", m.calculated_field_id_to_fs_index));
            archive(::cereal::make_nvp("calculated_field_id_to_fs_index_per_row", m.calculated_field_id_to_fs_index_per_row));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, table_line_info_t& m) {
            archive(::cereal::make_nvp("line_num", m.line_num));
            archive(::cereal::make_nvp("calculated_field_id_to_fs_index", m.calculated_field_id_to_fs_index));
            archive(::cereal::make_nvp("calculated_field_id_to_fs_index_per_row", m.calculated_field_id_to_fs_index_per_row));
    }
};
template <class Archive>
void
save(Archive& archive, const table_line_info_t& m)
{
    serializer_class<table_line_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const table_line_info_t&);

template <class Archive>
void
load(Archive& archive, table_line_info_t& m)
{
    serializer_class<table_line_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, table_line_info_t&);



template<>
class serializer_class<microcode_pointers> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const microcode_pointers& m) {
            archive(::cereal::make_nvp("block_name", m.block_name));
            archive(::cereal::make_nvp("table_name", m.table_name));
            archive(::cereal::make_nvp("array_index", m.array_index));
            archive(::cereal::make_nvp("table_lines", m.table_lines));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, microcode_pointers& m) {
            archive(::cereal::make_nvp("block_name", m.block_name));
            archive(::cereal::make_nvp("table_name", m.table_name));
            archive(::cereal::make_nvp("array_index", m.array_index));
            archive(::cereal::make_nvp("table_lines", m.table_lines));
    }
};
template <class Archive>
void
save(Archive& archive, const microcode_pointers& m)
{
    serializer_class<microcode_pointers>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const microcode_pointers&);

template <class Archive>
void
load(Archive& archive, microcode_pointers& m)
{
    serializer_class<microcode_pointers>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, microcode_pointers&);



template<>
class serializer_class<calculated_field_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const calculated_field_info_t& m) {
            archive(::cereal::make_nvp("field_width", m.field_width));
            archive(::cereal::make_nvp("key_part_index", m.key_part_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, calculated_field_info_t& m) {
            archive(::cereal::make_nvp("field_width", m.field_width));
            archive(::cereal::make_nvp("key_part_index", m.key_part_index));
    }
};
template <class Archive>
void
save(Archive& archive, const calculated_field_info_t& m)
{
    serializer_class<calculated_field_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const calculated_field_info_t&);

template <class Archive>
void
load(Archive& archive, calculated_field_info_t& m)
{
    serializer_class<calculated_field_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, calculated_field_info_t&);



template<>
class serializer_class<udk_table_properties> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_table_properties& m) {
            archive(::cereal::make_nvp("max_number_of_field_selects_for_each_key_part", m.max_number_of_field_selects_for_each_key_part));
            archive(::cereal::make_nvp("m_key_sizes_per_key_part", m.m_key_sizes_per_key_part));
            archive(::cereal::make_nvp("m_constant_bits_per_key_part", m.m_constant_bits_per_key_part));
            archive(::cereal::make_nvp("lookup_keys_construction_table_pointers", m.lookup_keys_construction_table_pointers));
            archive(::cereal::make_nvp("table_calculated_fields", m.table_calculated_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_table_properties& m) {
            archive(::cereal::make_nvp("max_number_of_field_selects_for_each_key_part", m.max_number_of_field_selects_for_each_key_part));
            archive(::cereal::make_nvp("m_key_sizes_per_key_part", m.m_key_sizes_per_key_part));
            archive(::cereal::make_nvp("m_constant_bits_per_key_part", m.m_constant_bits_per_key_part));
            archive(::cereal::make_nvp("lookup_keys_construction_table_pointers", m.lookup_keys_construction_table_pointers));
            archive(::cereal::make_nvp("table_calculated_fields", m.table_calculated_fields));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_table_properties& m)
{
    serializer_class<udk_table_properties>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_table_properties&);

template <class Archive>
void
load(Archive& archive, udk_table_properties& m)
{
    serializer_class<udk_table_properties>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_table_properties&);



template<>
class serializer_class<udk_resources> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_resources& m) {
            archive(::cereal::make_nvp("macro_id", m.macro_id));
            archive(::cereal::make_nvp("field_selects", m.field_selects));
            archive(::cereal::make_nvp("tables_properties", m.tables_properties));
            archive(::cereal::make_nvp("scoper_macro_table_pointer", m.scoper_macro_table_pointer));
            archive(::cereal::make_nvp("lookup_keys_construction_macro_table_pointer", m.lookup_keys_construction_macro_table_pointer));
            archive(::cereal::make_nvp("field_select_index_width_in_bits", m.field_select_index_width_in_bits));
            archive(::cereal::make_nvp("field_select_not_used_value", m.field_select_not_used_value));
            archive(::cereal::make_nvp("offset_of_field_selects_in_key_construction_microcode_line", m.offset_of_field_selects_in_key_construction_microcode_line));
            archive(::cereal::make_nvp("first_lsb_channel_with_no_pd_support", m.first_lsb_channel_with_no_pd_support));
            archive(::cereal::make_nvp("first_bypass_channel_with_pd_support", m.first_bypass_channel_with_pd_support));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_resources& m) {
            archive(::cereal::make_nvp("macro_id", m.macro_id));
            archive(::cereal::make_nvp("field_selects", m.field_selects));
            archive(::cereal::make_nvp("tables_properties", m.tables_properties));
            archive(::cereal::make_nvp("scoper_macro_table_pointer", m.scoper_macro_table_pointer));
            archive(::cereal::make_nvp("lookup_keys_construction_macro_table_pointer", m.lookup_keys_construction_macro_table_pointer));
            archive(::cereal::make_nvp("field_select_index_width_in_bits", m.field_select_index_width_in_bits));
            archive(::cereal::make_nvp("field_select_not_used_value", m.field_select_not_used_value));
            archive(::cereal::make_nvp("offset_of_field_selects_in_key_construction_microcode_line", m.offset_of_field_selects_in_key_construction_microcode_line));
            archive(::cereal::make_nvp("first_lsb_channel_with_no_pd_support", m.first_lsb_channel_with_no_pd_support));
            archive(::cereal::make_nvp("first_bypass_channel_with_pd_support", m.first_bypass_channel_with_pd_support));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_resources& m)
{
    serializer_class<udk_resources>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_resources&);

template <class Archive>
void
load(Archive& archive, udk_resources& m)
{
    serializer_class<udk_resources>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_resources&);



template<>
class serializer_class<microcode_write> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const microcode_write& m) {
            archive(::cereal::make_nvp("block", m.block));
            archive(::cereal::make_nvp("name", m.name));
            archive(::cereal::make_nvp("array_index", m.array_index));
            archive(::cereal::make_nvp("line", m.line));
            archive(::cereal::make_nvp("offset", m.offset));
            archive(::cereal::make_nvp("width", m.width));
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, microcode_write& m) {
            archive(::cereal::make_nvp("block", m.block));
            archive(::cereal::make_nvp("name", m.name));
            archive(::cereal::make_nvp("array_index", m.array_index));
            archive(::cereal::make_nvp("line", m.line));
            archive(::cereal::make_nvp("offset", m.offset));
            archive(::cereal::make_nvp("width", m.width));
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const microcode_write& m)
{
    serializer_class<microcode_write>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const microcode_write&);

template <class Archive>
void
load(Archive& archive, microcode_write& m)
{
    serializer_class<microcode_write>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, microcode_write&);



template<>
class serializer_class<udk_component> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_component& m) {
            archive(::cereal::make_nvp("m_udk_type", m.m_udk_type));
            archive(::cereal::make_nvp("m_data", m.m_data));
            archive(::cereal::make_nvp("m_width_in_bits", m.m_width_in_bits));
            archive(::cereal::make_nvp("offset_in_bits", m.offset_in_bits));
            archive(::cereal::make_nvp("m_description", m.m_description));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_component& m) {
            archive(::cereal::make_nvp("m_udk_type", m.m_udk_type));
            archive(::cereal::make_nvp("m_data", m.m_data));
            archive(::cereal::make_nvp("m_width_in_bits", m.m_width_in_bits));
            archive(::cereal::make_nvp("offset_in_bits", m.offset_in_bits));
            archive(::cereal::make_nvp("m_description", m.m_description));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_component& m)
{
    serializer_class<udk_component>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_component&);

template <class Archive>
void
load(Archive& archive, udk_component& m)
{
    serializer_class<udk_component>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_component&);



template<>
class serializer_class<udk_component::udf_from_packet_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_component::udf_from_packet_desc& m) {
            archive(::cereal::make_nvp("protocol_layer", m.protocol_layer));
            archive(::cereal::make_nvp("header", m.header));
            archive(::cereal::make_nvp("is_relative", m.is_relative));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_component::udf_from_packet_desc& m) {
            archive(::cereal::make_nvp("protocol_layer", m.protocol_layer));
            archive(::cereal::make_nvp("header", m.header));
            archive(::cereal::make_nvp("is_relative", m.is_relative));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_component::udf_from_packet_desc& m)
{
    serializer_class<udk_component::udf_from_packet_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_component::udf_from_packet_desc&);

template <class Archive>
void
load(Archive& archive, udk_component::udf_from_packet_desc& m)
{
    serializer_class<udk_component::udf_from_packet_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_component::udf_from_packet_desc&);



template<>
class serializer_class<udk_component::data_u> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_component::data_u& m) {
            archive(::cereal::make_nvp("udf_from_packet_instance", m.udf_from_packet_instance));
            archive(::cereal::make_nvp("m_calculated_field_instance", m.m_calculated_field_instance));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_component::data_u& m) {
            archive(::cereal::make_nvp("udf_from_packet_instance", m.udf_from_packet_instance));
            archive(::cereal::make_nvp("m_calculated_field_instance", m.m_calculated_field_instance));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_component::data_u& m)
{
    serializer_class<udk_component::data_u>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_component::data_u&);

template <class Archive>
void
load(Archive& archive, udk_component::data_u& m)
{
    serializer_class<udk_component::data_u>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_component::data_u&);



template<>
class serializer_class<udk_component::data_u::calculated_field> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_component::data_u::calculated_field& m) {
            archive(::cereal::make_nvp("field_id", m.field_id));
            archive(::cereal::make_nvp("field_select_index", m.field_select_index));
            archive(::cereal::make_nvp("key_part_index", m.key_part_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_component::data_u::calculated_field& m) {
            archive(::cereal::make_nvp("field_id", m.field_id));
            archive(::cereal::make_nvp("field_select_index", m.field_select_index));
            archive(::cereal::make_nvp("key_part_index", m.key_part_index));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_component::data_u::calculated_field& m)
{
    serializer_class<udk_component::data_u::calculated_field>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_component::data_u::calculated_field&);

template <class Archive>
void
load(Archive& archive, udk_component::data_u::calculated_field& m)
{
    serializer_class<udk_component::data_u::calculated_field>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_component::data_u::calculated_field&);



template<>
class serializer_class<udk_table_id_and_components> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_table_id_and_components& m) {
            archive(::cereal::make_nvp("udk_table_id", m.udk_table_id));
            archive(::cereal::make_nvp("udk_components", m.udk_components));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_table_id_and_components& m) {
            archive(::cereal::make_nvp("udk_table_id", m.udk_table_id));
            archive(::cereal::make_nvp("udk_components", m.udk_components));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_table_id_and_components& m)
{
    serializer_class<udk_table_id_and_components>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_table_id_and_components&);

template <class Archive>
void
load(Archive& archive, udk_table_id_and_components& m)
{
    serializer_class<udk_table_id_and_components>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_table_id_and_components&);



template<>
class serializer_class<place_udk_info_per_table> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const place_udk_info_per_table& m) {
            archive(::cereal::make_nvp("udk_table_id", m.udk_table_id));
            archive(::cereal::make_nvp("number_of_udk_components", m.number_of_udk_components));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, place_udk_info_per_table& m) {
            archive(::cereal::make_nvp("udk_table_id", m.udk_table_id));
            archive(::cereal::make_nvp("number_of_udk_components", m.number_of_udk_components));
    }
};
template <class Archive>
void
save(Archive& archive, const place_udk_info_per_table& m)
{
    serializer_class<place_udk_info_per_table>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const place_udk_info_per_table&);

template <class Archive>
void
load(Archive& archive, place_udk_info_per_table& m)
{
    serializer_class<place_udk_info_per_table>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, place_udk_info_per_table&);



template<>
class serializer_class<place_udk_command> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const place_udk_command& m) {
            archive(::cereal::make_nvp("macro_id", m.macro_id));
            archive(::cereal::make_nvp("number_of_udk_tables", m.number_of_udk_tables));
            archive(::cereal::make_nvp("number_of_udk_components", m.number_of_udk_components));
            archive(::cereal::make_nvp("place_udk_tables_info", m.place_udk_tables_info));
            archive(::cereal::make_nvp("values", m.values));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, place_udk_command& m) {
            archive(::cereal::make_nvp("macro_id", m.macro_id));
            archive(::cereal::make_nvp("number_of_udk_tables", m.number_of_udk_tables));
            archive(::cereal::make_nvp("number_of_udk_components", m.number_of_udk_components));
            archive(::cereal::make_nvp("place_udk_tables_info", m.place_udk_tables_info));
            archive(::cereal::make_nvp("values", m.values));
    }
};
template <class Archive>
void
save(Archive& archive, const place_udk_command& m)
{
    serializer_class<place_udk_command>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const place_udk_command&);

template <class Archive>
void
load(Archive& archive, place_udk_command& m)
{
    serializer_class<place_udk_command>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, place_udk_command&);



template<>
class serializer_class<udk_translation_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_translation_info& m) {
            archive(::cereal::make_nvp("placement_info", m.placement_info));
            archive(::cereal::make_nvp("number_of_components", m.number_of_components));
            archive(::cereal::make_nvp("physical_key_width", m.physical_key_width));
            archive(::cereal::make_nvp("constant_bits_per_key_part", m.constant_bits_per_key_part));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_translation_info& m) {
            archive(::cereal::make_nvp("placement_info", m.placement_info));
            archive(::cereal::make_nvp("number_of_components", m.number_of_components));
            archive(::cereal::make_nvp("physical_key_width", m.physical_key_width));
            archive(::cereal::make_nvp("constant_bits_per_key_part", m.constant_bits_per_key_part));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_translation_info& m)
{
    serializer_class<udk_translation_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_translation_info&);

template <class Archive>
void
load(Archive& archive, udk_translation_info& m)
{
    serializer_class<udk_translation_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_translation_info&);



template<>
class serializer_class<udk_translation_info::placement_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_translation_info::placement_info_t& m) {
            archive(::cereal::make_nvp("fragments_vec", m.fragments_vec));
            archive(::cereal::make_nvp("description", m.description));
            archive(::cereal::make_nvp("minimal_offset", m.minimal_offset));
            archive(::cereal::make_nvp("total_width", m.total_width));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_translation_info::placement_info_t& m) {
            archive(::cereal::make_nvp("fragments_vec", m.fragments_vec));
            archive(::cereal::make_nvp("description", m.description));
            archive(::cereal::make_nvp("minimal_offset", m.minimal_offset));
            archive(::cereal::make_nvp("total_width", m.total_width));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_translation_info::placement_info_t& m)
{
    serializer_class<udk_translation_info::placement_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_translation_info::placement_info_t&);

template <class Archive>
void
load(Archive& archive, udk_translation_info::placement_info_t& m)
{
    serializer_class<udk_translation_info::placement_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_translation_info::placement_info_t&);



template<>
class serializer_class<udk_translation_info::placement_info_t::fragment_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const udk_translation_info::placement_info_t::fragment_info_t& m) {
            archive(::cereal::make_nvp("offset", m.offset));
            archive(::cereal::make_nvp("width", m.width));
            archive(::cereal::make_nvp("processed_index", m.processed_index));
            archive(::cereal::make_nvp("offset_in_component", m.offset_in_component));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, udk_translation_info::placement_info_t::fragment_info_t& m) {
            archive(::cereal::make_nvp("offset", m.offset));
            archive(::cereal::make_nvp("width", m.width));
            archive(::cereal::make_nvp("processed_index", m.processed_index));
            archive(::cereal::make_nvp("offset_in_component", m.offset_in_component));
    }
};
template <class Archive>
void
save(Archive& archive, const udk_translation_info::placement_info_t::fragment_info_t& m)
{
    serializer_class<udk_translation_info::placement_info_t::fragment_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const udk_translation_info::placement_info_t::fragment_info_t&);

template <class Archive>
void
load(Archive& archive, udk_translation_info::placement_info_t::fragment_info_t& m)
{
    serializer_class<udk_translation_info::placement_info_t::fragment_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, udk_translation_info::placement_info_t::fragment_info_t&);



template<>
class serializer_class<silicon_one::la_voq_cgm_evicted_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_voq_cgm_evicted_profile_impl& m) {
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_voq_cgm_evicted_profile_impl& m) {
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_voq_cgm_evicted_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_cgm_evicted_profile>(&m));
    serializer_class<silicon_one::la_voq_cgm_evicted_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_voq_cgm_evicted_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_voq_cgm_evicted_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_cgm_evicted_profile>(&m));
    serializer_class<silicon_one::la_voq_cgm_evicted_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_voq_cgm_evicted_profile_impl&);



template<>
class serializer_class<silicon_one::la_voq_cgm_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_voq_cgm_profile_impl& m) {
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_voq_cgm_pd_counter", m.m_voq_cgm_pd_counter));
            archive(::cereal::make_nvp("m_use_count", m.m_use_count));
            archive(::cereal::make_nvp("m_drop_prob_select_profile", m.m_drop_prob_select_profile));
            archive(::cereal::make_nvp("m_mark_prob_select_profile", m.m_mark_prob_select_profile));
            archive(::cereal::make_nvp("m_drop_dram_wred_lut", m.m_drop_dram_wred_lut));
            archive(::cereal::make_nvp("m_mark_dram_wred_lut", m.m_mark_dram_wred_lut));
            archive(::cereal::make_nvp("m_table_first_instance", m.m_table_first_instance));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_evicted_profile", m.m_evicted_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_voq_cgm_profile_impl& m) {
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_voq_cgm_pd_counter", m.m_voq_cgm_pd_counter));
            archive(::cereal::make_nvp("m_use_count", m.m_use_count));
            archive(::cereal::make_nvp("m_drop_prob_select_profile", m.m_drop_prob_select_profile));
            archive(::cereal::make_nvp("m_mark_prob_select_profile", m.m_mark_prob_select_profile));
            archive(::cereal::make_nvp("m_drop_dram_wred_lut", m.m_drop_dram_wred_lut));
            archive(::cereal::make_nvp("m_mark_dram_wred_lut", m.m_mark_dram_wred_lut));
            archive(::cereal::make_nvp("m_table_first_instance", m.m_table_first_instance));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_evicted_profile", m.m_evicted_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_voq_cgm_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_cgm_profile>(&m));
    serializer_class<silicon_one::la_voq_cgm_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_voq_cgm_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_voq_cgm_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_cgm_profile>(&m));
    serializer_class<silicon_one::la_voq_cgm_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_voq_cgm_profile_impl&);



template<>
class serializer_class<silicon_one::rx_cgm_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::rx_cgm_handler& m) {
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_hr_management_mode", m.m_hr_management_mode));
            archive(::cereal::make_nvp("m_profile_id_generator", m.m_profile_id_generator));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::rx_cgm_handler& m) {
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_hr_management_mode", m.m_hr_management_mode));
            archive(::cereal::make_nvp("m_profile_id_generator", m.m_profile_id_generator));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::rx_cgm_handler& m)
{
    serializer_class<silicon_one::rx_cgm_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::rx_cgm_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::rx_cgm_handler& m)
{
    serializer_class<silicon_one::rx_cgm_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::rx_cgm_handler&);



template<>
class serializer_class<silicon_one::all_acl_generic_types> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::all_acl_generic_types& m) {
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db1_160_f0", m._acl_ingress_rtf_eth_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db2_160_f0", m._acl_ingress_rtf_eth_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_160_f0", m._acl_ingress_rtf_ipv4_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_160_f0", m._acl_ingress_rtf_ipv4_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_160_f0", m._acl_ingress_rtf_ipv4_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_160_f0", m._acl_ingress_rtf_ipv4_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_320_f0", m._acl_ingress_rtf_ipv4_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_320_f0", m._acl_ingress_rtf_ipv4_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_320_f0", m._acl_ingress_rtf_ipv4_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_320_f0", m._acl_ingress_rtf_ipv4_db4_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_160_f0", m._acl_ingress_rtf_ipv6_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_160_f0", m._acl_ingress_rtf_ipv6_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_160_f0", m._acl_ingress_rtf_ipv6_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_160_f0", m._acl_ingress_rtf_ipv6_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_320_f0", m._acl_ingress_rtf_ipv6_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_320_f0", m._acl_ingress_rtf_ipv6_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_320_f0", m._acl_ingress_rtf_ipv6_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_320_f0", m._acl_ingress_rtf_ipv6_db4_320_f0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::all_acl_generic_types& m) {
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db1_160_f0", m._acl_ingress_rtf_eth_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db2_160_f0", m._acl_ingress_rtf_eth_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_160_f0", m._acl_ingress_rtf_ipv4_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_160_f0", m._acl_ingress_rtf_ipv4_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_160_f0", m._acl_ingress_rtf_ipv4_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_160_f0", m._acl_ingress_rtf_ipv4_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_320_f0", m._acl_ingress_rtf_ipv4_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_320_f0", m._acl_ingress_rtf_ipv4_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_320_f0", m._acl_ingress_rtf_ipv4_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_320_f0", m._acl_ingress_rtf_ipv4_db4_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_160_f0", m._acl_ingress_rtf_ipv6_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_160_f0", m._acl_ingress_rtf_ipv6_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_160_f0", m._acl_ingress_rtf_ipv6_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_160_f0", m._acl_ingress_rtf_ipv6_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_320_f0", m._acl_ingress_rtf_ipv6_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_320_f0", m._acl_ingress_rtf_ipv6_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_320_f0", m._acl_ingress_rtf_ipv6_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_320_f0", m._acl_ingress_rtf_ipv6_db4_320_f0));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::all_acl_generic_types& m)
{
    serializer_class<silicon_one::all_acl_generic_types>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::all_acl_generic_types&);

template <class Archive>
void
load(Archive& archive, silicon_one::all_acl_generic_types& m)
{
    serializer_class<silicon_one::all_acl_generic_types>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::all_acl_generic_types&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_voq_cgm_evicted_profile_impl var0;
    ar(var0);
    silicon_one::la_voq_cgm_profile_impl var1;
    ar(var1);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait> var2;
    ar(var2);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait> var3;
    ar(var3);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait> var4;
    ar(var4);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait> var5;
    ar(var5);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait> var6;
    ar(var6);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait> var7;
    ar(var7);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait> var8;
    ar(var8);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait> var9;
    ar(var9);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait> var10;
    ar(var10);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait> var11;
    ar(var11);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait> var12;
    ar(var12);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait> var13;
    ar(var13);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait> var14;
    ar(var14);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait> var15;
    ar(var15);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait> var16;
    ar(var16);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait> var17;
    ar(var17);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait> var18;
    ar(var18);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait> var19;
    ar(var19);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_voq_cgm_evicted_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_voq_cgm_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait>);

#pragma GCC diagnostic pop

