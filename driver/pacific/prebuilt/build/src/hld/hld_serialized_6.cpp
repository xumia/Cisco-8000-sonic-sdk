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
#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "cgm/voq_cgm_handler.h"
#include "hld_serialization.h"
#include "hld_types.h"
#include "ifg_use_count.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/ipv4_tunnel_ep_manager.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_egress_sec_ipv4.h"
#include "npu/la_acl_egress_sec_ipv6.h"
#include "npu/la_acl_generic.h"
#include "npu/la_acl_impl.h"
#include "npu/la_acl_scaled_delegate.h"
#include "npu/la_acl_scaled_impl.h"
#include "npu/la_asbr_lsp_impl.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_fabric_multicast_group_impl.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_forus_destination_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_ip_tunnel_destination_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_lpts_impl.h"
#include "npu/la_lsr_impl.h"
#include "npu/la_mldp_vpn_decap_impl.h"
#include "npu/la_mpls_label_destination_impl.h"
#include "npu/la_mpls_multicast_group_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_mpls_vpn_decap_impl.h"
#include "npu/la_mpls_vpn_encap_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_og_lpts_application_impl.h"
#include "npu/la_pbts_group_impl.h"
#include "npu/la_pcl_impl.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/la_switch_impl.h"
#include "npu/la_te_tunnel_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/mac_address_manager.h"
#include "npu/mc_copy_id_manager.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_action_profile_impl.h"
#include "qos/la_meter_markdown_profile_impl.h"
#include "qos/la_meter_profile_impl.h"
#include "qos/la_meter_set_exact_impl.h"
#include "qos/la_meter_set_impl.h"
#include "qos/la_meter_set_statistical_impl.h"
#include "system/arc_handler_pacific.h"
#include "system/counter_allocation.h"
#include "system/counter_bank_utils.h"
#include "system/counter_logical_bank.h"
#include "system/counter_manager.h"
#include "system/cud_range_manager.h"
#include "system/fabric_init_handler.h"
#include "system/la_device_impl.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_pbts_map_profile_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/mac_pool2_port.h"
#include "system/mac_pool8_port.h"
#include "system/mac_pool_port.h"
#include "system/npu_static_config.h"
#include "system/pacific_mac_pool.h"
#include "system/pacific_pvt_handler.h"
#include "system/pvt_handler.h"
#include "system/ranged_sequential_indices_generator.h"
#include "system/reconnect_handler.h"
#include "system/reconnect_metadata.h"
#include "system/resource_handler.h"
#include "system/serdes_device_handler.h"
#include "tm/la_fabric_port_scheduler_impl.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_logical_port_scheduler_impl.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/la_system_port_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"
#include "tm/tm_utils.h"
#include "tm/voq_counter_set.h"
#include "../device_context/la_slice_mapper_base.h"
#include "npu/copc_protocol_manager_base.h"
#include "npu/copc_protocol_manager_pacific.h"
#include "npu/la_acl_command_profile_base.h"
#include "npu/la_acl_group_base.h"
#include "npu/la_acl_group_pacific.h"
#include "npu/la_acl_key_profile_base.h"
#include "npu/la_acl_key_profile_pacific.h"
#include "npu/la_bfd_session_base.h"
#include "npu/la_bfd_session_pacific.h"
#include "npu/la_copc_base.h"
#include "npu/la_copc_pacific.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ethernet_port_pacific.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_ip_multicast_group_pacific.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_multicast_group_pacific.h"
#include "npu/la_l2_protection_group_base.h"
#include "npu/la_l2_protection_group_pacific.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l2_service_port_pacgb.h"
#include "npu/la_l2_service_port_pacific.h"
#include "npu/la_multicast_group_common_base.h"
#include "npu/la_multicast_group_common_pacific.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_next_hop_pacgb.h"
#include "npu/la_next_hop_pacific.h"
#include "npu/la_prefix_object_base.h"
#include "npu/la_prefix_object_pacific.h"
#include "npu/la_rate_limiter_set_base.h"
#include "npu/la_rate_limiter_set_pacific.h"
#include "npu/la_security_group_cell_base.h"
#include "npu/la_security_group_cell_pacific.h"
#include "npu/la_stack_port_base.h"
#include "npu/la_stack_port_pacific.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_svi_port_pacific.h"
#include "npu/la_vrf_port_common_base.h"
#include "npu/la_vrf_port_common_pacgb.h"
#include "npu/la_vrf_port_common_pacific.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "npu/la_vxlan_next_hop_pacific.h"
#include "qos/la_meter_set_base.h"
#include "system/arc_handler_base.h"
#include "system/device_configurator_base.h"
#include "system/device_port_handler_base.h"
#include "system/device_port_handler_pacific.h"
#include "system/dummy_serdes_device_handler_base.h"
#include "system/dummy_serdes_handler_base.h"
#include "system/hld_notification_base.h"
#include "system/hld_notification_pacific.h"
#include "system/ifg_handler.h"
#include "system/ifg_handler_base.h"
#include "system/ifg_handler_ifg.h"
#include "system/ifg_handler_pacific.h"
#include "system/init_performance_helper_base.h"
#include "system/la_device_impl_base.h"
#include "system/la_erspan_mirror_command_base.h"
#include "system/la_erspan_mirror_command_pacific.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/la_l2_mirror_command_pacgb.h"
#include "system/la_l2_mirror_command_pacific.h"
#include "system/la_mac_port_base.h"
#include "system/la_mac_port_pacgb.h"
#include "system/la_mac_port_pacific.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_npu_host_port_pacific.h"
#include "system/la_pci_port_base.h"
#include "system/la_pci_port_pacific.h"
#include "system/la_ptp_handler_base.h"
#include "system/la_ptp_handler_pacific.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_punt_inject_port_pacgb.h"
#include "system/la_punt_inject_port_pacific.h"
#include "system/la_recycle_port_base.h"
#include "system/la_recycle_port_pacific.h"
#include "system/la_remote_device_base.h"
#include "system/la_spa_port_base.h"
#include "system/la_spa_port_pacgb.h"
#include "system/la_spa_port_pacific.h"
#include "system/la_system_port_base.h"
#include "system/la_system_port_pacgb.h"
#include "system/la_system_port_pacific.h"
#include "system/npu_host_event_queue_base.h"
#include "system/npu_host_event_queue_pacific.h"
#include "system/serdes_handler.h"
#include "system/slice_id_manager_base.h"
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
#include "cgm/voq_cgm_handler.h"
#include "ra/resource_manager.h"
#include "api/tm/la_unicast_tc_profile.h"
#include "apb/apb.h"
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

template <class Archive> void save(Archive&, const npl_meter_weight_t&);
template <class Archive> void load(Archive&, npl_meter_weight_t&);

template <class Archive> void save(Archive&, const runtime_flexibility_library&);
template <class Archive> void load(Archive&, runtime_flexibility_library&);

template <class Archive> void save(Archive&, const silicon_one::arc_handler_base&);
template <class Archive> void load(Archive&, silicon_one::arc_handler_base&);

template <class Archive> void save(Archive&, const silicon_one::copc_protocol_manager_base&);
template <class Archive> void load(Archive&, silicon_one::copc_protocol_manager_base&);

template <class Archive> void save(Archive&, const silicon_one::cpu2jtag&);
template <class Archive> void load(Archive&, silicon_one::cpu2jtag&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::destination_id&);
template <class Archive> void load(Archive&, silicon_one::destination_id&);

template <class Archive> void save(Archive&, const silicon_one::device_port_handler_base&);
template <class Archive> void load(Archive&, silicon_one::device_port_handler_base&);

template <class Archive> void save(Archive&, const silicon_one::device_tables&);
template <class Archive> void load(Archive&, silicon_one::device_tables&);

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

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::aapl_firmware_info&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::aapl_firmware_info&);

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

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::mc_links_key_equal&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::mc_links_key_equal&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::mc_links_key_hash&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::mc_links_key_hash&);

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

template <class Archive> void save(Archive&, const silicon_one::la_forus_destination_impl&);
template <class Archive> void load(Archive&, silicon_one::la_forus_destination_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_hbm_handler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_hbm_handler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ifg_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ifg_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ingress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ingress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_multicast_group_pacific&);
template <class Archive> void load(Archive&, silicon_one::la_ip_multicast_group_pacific&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l2_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_multicast_group_pacific&);
template <class Archive> void load(Archive&, silicon_one::la_l2_multicast_group_pacific&);

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

template <class Archive> void save(Archive&, const silicon_one::la_meter_action_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_action_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_markdown_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_markdown_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_exact_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_exact_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_impl&);

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

template <class Archive> void save(Archive&, const silicon_one::la_output_queue_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_output_queue_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_pci_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_pci_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object&);

template <class Archive> void save(Archive&, const silicon_one::la_protection_monitor&);
template <class Archive> void load(Archive&, silicon_one::la_protection_monitor&);

template <class Archive> void save(Archive&, const silicon_one::la_ptp_handler_pacific&);
template <class Archive> void load(Archive&, silicon_one::la_ptp_handler_pacific&);

template <class Archive> void save(Archive&, const silicon_one::la_recycle_port_pacific&);
template <class Archive> void load(Archive&, silicon_one::la_recycle_port_pacific&);

template <class Archive> void save(Archive&, const silicon_one::la_rx_cgm_sq_profile&);
template <class Archive> void load(Archive&, silicon_one::la_rx_cgm_sq_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_spa_port_pacific&);
template <class Archive> void load(Archive&, silicon_one::la_spa_port_pacific&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_pacific&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_pacific&);

template <class Archive> void save(Archive&, const silicon_one::la_tc_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_tc_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_te_tunnel&);
template <class Archive> void load(Archive&, silicon_one::la_te_tunnel&);

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

template <class Archive> void save(Archive&, const silicon_one::mac_address_manager&);
template <class Archive> void load(Archive&, silicon_one::mac_address_manager&);

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
            archive(::cereal::make_nvp("m_exact_meter_set_impl", m.m_exact_meter_set_impl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_statistical_impl& m) {
            archive(::cereal::make_nvp("m_bank_index", m.m_bank_index));
            archive(::cereal::make_nvp("m_set_base_index", m.m_set_base_index));
            archive(::cereal::make_nvp("m_token_sizes", m.m_token_sizes));
            archive(::cereal::make_nvp("m_shaper_tokens_per_sec", m.m_shaper_tokens_per_sec));
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
class serializer_class<silicon_one::arc_handler_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::arc_handler_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::arc_handler_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::arc_handler_pacific& m)
{
    archive(cereal::base_class<silicon_one::arc_handler_base>(&m));
    serializer_class<silicon_one::arc_handler_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::arc_handler_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::arc_handler_pacific& m)
{
    archive(cereal::base_class<silicon_one::arc_handler_base>(&m));
    serializer_class<silicon_one::arc_handler_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::arc_handler_pacific&);



template<>
class serializer_class<silicon_one::counter_allocation> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::counter_allocation& m) {
            archive(::cereal::make_nvp("set_size", m.set_size));
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("num_of_ifgs", m.num_of_ifgs));
            archive(::cereal::make_nvp("base_row_index", m.base_row_index));
            archive(::cereal::make_nvp("phys_bank_index", m.phys_bank_index));
            archive(::cereal::make_nvp("bank", m.bank));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::counter_allocation& m) {
            archive(::cereal::make_nvp("set_size", m.set_size));
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("num_of_ifgs", m.num_of_ifgs));
            archive(::cereal::make_nvp("base_row_index", m.base_row_index));
            archive(::cereal::make_nvp("phys_bank_index", m.phys_bank_index));
            archive(::cereal::make_nvp("bank", m.bank));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::counter_allocation& m)
{
    serializer_class<silicon_one::counter_allocation>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::counter_allocation&);

template <class Archive>
void
load(Archive& archive, silicon_one::counter_allocation& m)
{
    serializer_class<silicon_one::counter_allocation>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::counter_allocation&);



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
class serializer_class<silicon_one::counter_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::counter_manager& m) {
            archive(::cereal::make_nvp("m_busy_phys_banks", m.m_busy_phys_banks));
            archive(::cereal::make_nvp("m_resource_monitor", m.m_resource_monitor));
            archive(::cereal::make_nvp("m_num_of_network_slices", m.m_num_of_network_slices));
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
            archive(::cereal::make_nvp("m_num_of_network_slices", m.m_num_of_network_slices));
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
class serializer_class<silicon_one::cud_range_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::cud_range_manager& m) {
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_is_initialized", m.m_is_initialized));
            archive(::cereal::make_nvp("m_index_gen", m.m_index_gen));
            archive(::cereal::make_nvp("m_is_used", m.m_is_used));
            archive(::cereal::make_nvp("m_is_wide", m.m_is_wide));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::cud_range_manager& m) {
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_is_initialized", m.m_is_initialized));
            archive(::cereal::make_nvp("m_index_gen", m.m_index_gen));
            archive(::cereal::make_nvp("m_is_used", m.m_is_used));
            archive(::cereal::make_nvp("m_is_wide", m.m_is_wide));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::cud_range_manager& m)
{
    serializer_class<silicon_one::cud_range_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::cud_range_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::cud_range_manager& m)
{
    serializer_class<silicon_one::cud_range_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::cud_range_manager&);



template<>
class serializer_class<silicon_one::fabric_init_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::fabric_init_handler& m) {
            archive(::cereal::make_nvp("m_base_mc_vsc_vec", m.m_base_mc_vsc_vec));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mc_voq_set", m.m_mc_voq_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::fabric_init_handler& m) {
            archive(::cereal::make_nvp("m_base_mc_vsc_vec", m.m_base_mc_vsc_vec));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mc_voq_set", m.m_mc_voq_set));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::fabric_init_handler& m)
{
    serializer_class<silicon_one::fabric_init_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::fabric_init_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::fabric_init_handler& m)
{
    serializer_class<silicon_one::fabric_init_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::fabric_init_handler&);



template<>
class serializer_class<silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u& m) {
            archive(::cereal::make_nvp("fields", m.fields));
            archive(::cereal::make_nvp("flat", m.flat));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u& m) {
            archive(::cereal::make_nvp("fields", m.fields));
            archive(::cereal::make_nvp("flat", m.flat));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u& m)
{
    serializer_class<silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u&);

template <class Archive>
void
load(Archive& archive, silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u& m)
{
    serializer_class<silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u&);



template<>
class serializer_class<silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s& m) {
        uint64_t m_oq0 = m.oq0;
        uint64_t m_oq1 = m.oq1;
        uint64_t m_oq2 = m.oq2;
        uint64_t m_oq3 = m.oq3;
        uint64_t m_oq4 = m.oq4;
        uint64_t m_oq5 = m.oq5;
        uint64_t m_oq6 = m.oq6;
            archive(::cereal::make_nvp("oq0", m_oq0));
            archive(::cereal::make_nvp("oq1", m_oq1));
            archive(::cereal::make_nvp("oq2", m_oq2));
            archive(::cereal::make_nvp("oq3", m_oq3));
            archive(::cereal::make_nvp("oq4", m_oq4));
            archive(::cereal::make_nvp("oq5", m_oq5));
            archive(::cereal::make_nvp("oq6", m_oq6));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s& m) {
        uint64_t m_oq0;
        uint64_t m_oq1;
        uint64_t m_oq2;
        uint64_t m_oq3;
        uint64_t m_oq4;
        uint64_t m_oq5;
        uint64_t m_oq6;
            archive(::cereal::make_nvp("oq0", m_oq0));
            archive(::cereal::make_nvp("oq1", m_oq1));
            archive(::cereal::make_nvp("oq2", m_oq2));
            archive(::cereal::make_nvp("oq3", m_oq3));
            archive(::cereal::make_nvp("oq4", m_oq4));
            archive(::cereal::make_nvp("oq5", m_oq5));
            archive(::cereal::make_nvp("oq6", m_oq6));
        m.oq0 = m_oq0;
        m.oq1 = m_oq1;
        m.oq2 = m_oq2;
        m.oq3 = m_oq3;
        m.oq4 = m_oq4;
        m.oq5 = m_oq5;
        m.oq6 = m_oq6;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s& m)
{
    serializer_class<silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s& m)
{
    serializer_class<silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::fabric_init_handler::tpse_oqpg_map_tm_port_u::fields_s&);



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
            archive(::cereal::make_nvp("m_revision", m.m_revision));
            archive(::cereal::make_nvp("m_profile_allocators", m.m_profile_allocators));
            archive(::cereal::make_nvp("m_is_builtin_objects", m.m_is_builtin_objects));
            archive(::cereal::make_nvp("m_slice_mode", m.m_slice_mode));
            archive(::cereal::make_nvp("m_hbm_handler", m.m_hbm_handler));
            archive(::cereal::make_nvp("m_ptp_handler", m.m_ptp_handler));
            archive(::cereal::make_nvp("m_pvt_handler", m.m_pvt_handler));
            archive(::cereal::make_nvp("m_cpu2jtag_handler", m.m_cpu2jtag_handler));
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
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_hbm_fw_info", m.m_hbm_fw_info));
            archive(::cereal::make_nvp("m_hbm_mbist_fw_info", m.m_hbm_mbist_fw_info));
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
            archive(::cereal::make_nvp("m_lsr", m.m_lsr));
            archive(::cereal::make_nvp("m_ttl_inheritance_mode", m.m_ttl_inheritance_mode));
            archive(::cereal::make_nvp("m_forus_destination", m.m_forus_destination));
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
            archive(::cereal::make_nvp("m_voq_flush_oq_sch", m.m_voq_flush_oq_sch));
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
            archive(::cereal::make_nvp("m_lpts_meter_map", m.m_lpts_meter_map));
            archive(::cereal::make_nvp("m_snoop_entries", m.m_snoop_entries));
            archive(::cereal::make_nvp("m_supported_tpid_pairs", m.m_supported_tpid_pairs));
            archive(::cereal::make_nvp("m_native_voq_sets", m.m_native_voq_sets));
            archive(::cereal::make_nvp("m_vsc_is_busy", m.m_vsc_is_busy));
            archive(::cereal::make_nvp("m_tm_slice_mode", m.m_tm_slice_mode));
            archive(::cereal::make_nvp("m_notification", m.m_notification));
            archive(::cereal::make_nvp("m_fuse_userbits", m.m_fuse_userbits));
            archive(::cereal::make_nvp("m_heartbeat", m.m_heartbeat));
            archive(::cereal::make_nvp("m_fabric_init_handler", m.m_fabric_init_handler));
            archive(::cereal::make_nvp("m_fe_mode", m.m_fe_mode));
            archive(::cereal::make_nvp("m_slice_clos_direction", m.m_slice_clos_direction));
            archive(::cereal::make_nvp("m_fe_fabric_reachability_enabled", m.m_fe_fabric_reachability_enabled));
            archive(::cereal::make_nvp("m_lookup_error_drop_dsp_counter", m.m_lookup_error_drop_dsp_counter));
            archive(::cereal::make_nvp("m_rx_drop_dsp_counter", m.m_rx_drop_dsp_counter));
            archive(::cereal::make_nvp("m_fe_routing_table_last_pool_time_point", m.m_fe_routing_table_last_pool_time_point));
            archive(::cereal::make_nvp("m_lc_to_min_links", m.m_lc_to_min_links));
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
            archive(::cereal::make_nvp("m_ttl_decrement_enabled", m.m_ttl_decrement_enabled));
            archive(::cereal::make_nvp("m_l3_termination_classify_ip_tunnels_table", m.m_l3_termination_classify_ip_tunnels_table));
            archive(::cereal::make_nvp("m_global_min_fabric_links_threshold", m.m_global_min_fabric_links_threshold));
            archive(::cereal::make_nvp("m_arc_hdlr", m.m_arc_hdlr));
            archive(::cereal::make_nvp("m_npu_host_eventq", m.m_npu_host_eventq));
            archive(::cereal::make_nvp("m_cpu_eventq_polling", m.m_cpu_eventq_polling));
            archive(::cereal::make_nvp("m_punt_recycle_port_exist", m.m_punt_recycle_port_exist));
            archive(::cereal::make_nvp("m_objects", m.m_objects));
            archive(::cereal::make_nvp("m_mldp_bud_info", m.m_mldp_bud_info));
            archive(::cereal::make_nvp("m_resource_monitors", m.m_resource_monitors));
            archive(::cereal::make_nvp("m_mirror_commands", m.m_mirror_commands));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
            archive(::cereal::make_nvp("m_asbr_lsp_map", m.m_asbr_lsp_map));
            archive(::cereal::make_nvp("m_bfd_sessions", m.m_bfd_sessions));
            archive(::cereal::make_nvp("m_system_ports", m.m_system_ports));
            archive(::cereal::make_nvp("m_spa_ports", m.m_spa_ports));
            archive(::cereal::make_nvp("m_voq_sets", m.m_voq_sets));
            archive(::cereal::make_nvp("m_voq_cgm_profiles", m.m_voq_cgm_profiles));
            archive(::cereal::make_nvp("m_ipv4_tunnel_map", m.m_ipv4_tunnel_map));
            archive(::cereal::make_nvp("m_vxlan_port_map", m.m_vxlan_port_map));
            archive(::cereal::make_nvp("m_vxlan_vni_map", m.m_vxlan_vni_map));
            archive(::cereal::make_nvp("m_vxlan_nh_map", m.m_vxlan_nh_map));
            archive(::cereal::make_nvp("m_pacific_tree", m.m_pacific_tree));
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
            archive(::cereal::make_nvp("m_rcy_system_ports", m.m_rcy_system_ports));
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
            archive(::cereal::make_nvp("m_egress_multicast_fabric_replication_voq_set", m.m_egress_multicast_fabric_replication_voq_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl& m) {
            archive(::cereal::make_nvp("ccm_interval", cereal_gen_remove_const(m.ccm_interval)));
            archive(::cereal::make_nvp("RX_DROP_DSP", cereal_gen_remove_const(m.RX_DROP_DSP)));
            archive(::cereal::make_nvp("RX_NOT_CNT_DROP_DSP", cereal_gen_remove_const(m.RX_NOT_CNT_DROP_DSP)));
            archive(::cereal::make_nvp("m_disconnected", m.m_disconnected));
            archive(::cereal::make_nvp("m_warm_boot_disconnected", m.m_warm_boot_disconnected));
            archive(::cereal::make_nvp("m_revision", m.m_revision));
            archive(::cereal::make_nvp("m_profile_allocators", m.m_profile_allocators));
            archive(::cereal::make_nvp("m_is_builtin_objects", m.m_is_builtin_objects));
            archive(::cereal::make_nvp("m_slice_mode", m.m_slice_mode));
            archive(::cereal::make_nvp("m_hbm_handler", m.m_hbm_handler));
            archive(::cereal::make_nvp("m_ptp_handler", m.m_ptp_handler));
            archive(::cereal::make_nvp("m_pvt_handler", m.m_pvt_handler));
            archive(::cereal::make_nvp("m_cpu2jtag_handler", m.m_cpu2jtag_handler));
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
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_hbm_fw_info", m.m_hbm_fw_info));
            archive(::cereal::make_nvp("m_hbm_mbist_fw_info", m.m_hbm_mbist_fw_info));
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
            archive(::cereal::make_nvp("m_lsr", m.m_lsr));
            archive(::cereal::make_nvp("m_ttl_inheritance_mode", m.m_ttl_inheritance_mode));
            archive(::cereal::make_nvp("m_forus_destination", m.m_forus_destination));
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
            archive(::cereal::make_nvp("m_voq_flush_oq_sch", m.m_voq_flush_oq_sch));
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
            archive(::cereal::make_nvp("m_lpts_meter_map", m.m_lpts_meter_map));
            archive(::cereal::make_nvp("m_snoop_entries", m.m_snoop_entries));
            archive(::cereal::make_nvp("m_supported_tpid_pairs", m.m_supported_tpid_pairs));
            archive(::cereal::make_nvp("m_native_voq_sets", m.m_native_voq_sets));
            archive(::cereal::make_nvp("m_vsc_is_busy", m.m_vsc_is_busy));
            archive(::cereal::make_nvp("m_tm_slice_mode", m.m_tm_slice_mode));
            archive(::cereal::make_nvp("m_notification", m.m_notification));
            archive(::cereal::make_nvp("m_fuse_userbits", m.m_fuse_userbits));
            archive(::cereal::make_nvp("m_heartbeat", m.m_heartbeat));
            archive(::cereal::make_nvp("m_fabric_init_handler", m.m_fabric_init_handler));
            archive(::cereal::make_nvp("m_fe_mode", m.m_fe_mode));
            archive(::cereal::make_nvp("m_slice_clos_direction", m.m_slice_clos_direction));
            archive(::cereal::make_nvp("m_fe_fabric_reachability_enabled", m.m_fe_fabric_reachability_enabled));
            archive(::cereal::make_nvp("m_lookup_error_drop_dsp_counter", m.m_lookup_error_drop_dsp_counter));
            archive(::cereal::make_nvp("m_rx_drop_dsp_counter", m.m_rx_drop_dsp_counter));
            archive(::cereal::make_nvp("m_fe_routing_table_last_pool_time_point", m.m_fe_routing_table_last_pool_time_point));
            archive(::cereal::make_nvp("m_lc_to_min_links", m.m_lc_to_min_links));
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
            archive(::cereal::make_nvp("m_ttl_decrement_enabled", m.m_ttl_decrement_enabled));
            archive(::cereal::make_nvp("m_l3_termination_classify_ip_tunnels_table", m.m_l3_termination_classify_ip_tunnels_table));
            archive(::cereal::make_nvp("m_global_min_fabric_links_threshold", m.m_global_min_fabric_links_threshold));
            archive(::cereal::make_nvp("m_arc_hdlr", m.m_arc_hdlr));
            archive(::cereal::make_nvp("m_npu_host_eventq", m.m_npu_host_eventq));
            archive(::cereal::make_nvp("m_cpu_eventq_polling", m.m_cpu_eventq_polling));
            archive(::cereal::make_nvp("m_punt_recycle_port_exist", m.m_punt_recycle_port_exist));
            archive(::cereal::make_nvp("m_objects", m.m_objects));
            archive(::cereal::make_nvp("m_mldp_bud_info", m.m_mldp_bud_info));
            archive(::cereal::make_nvp("m_resource_monitors", m.m_resource_monitors));
            archive(::cereal::make_nvp("m_mirror_commands", m.m_mirror_commands));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
            archive(::cereal::make_nvp("m_asbr_lsp_map", m.m_asbr_lsp_map));
            archive(::cereal::make_nvp("m_bfd_sessions", m.m_bfd_sessions));
            archive(::cereal::make_nvp("m_system_ports", m.m_system_ports));
            archive(::cereal::make_nvp("m_spa_ports", m.m_spa_ports));
            archive(::cereal::make_nvp("m_voq_sets", m.m_voq_sets));
            archive(::cereal::make_nvp("m_voq_cgm_profiles", m.m_voq_cgm_profiles));
            archive(::cereal::make_nvp("m_ipv4_tunnel_map", m.m_ipv4_tunnel_map));
            archive(::cereal::make_nvp("m_vxlan_port_map", m.m_vxlan_port_map));
            archive(::cereal::make_nvp("m_vxlan_vni_map", m.m_vxlan_vni_map));
            archive(::cereal::make_nvp("m_vxlan_nh_map", m.m_vxlan_nh_map));
            archive(::cereal::make_nvp("m_pacific_tree", m.m_pacific_tree));
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
            archive(::cereal::make_nvp("m_rcy_system_ports", m.m_rcy_system_ports));
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
            archive(::cereal::make_nvp("m_egress_multicast_fabric_replication_voq_set", m.m_egress_multicast_fabric_replication_voq_set));
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
    silicon_one::la_meter_set_statistical_impl var0;
    ar(var0);
    silicon_one::arc_handler_pacific var1;
    ar(var1);
    silicon_one::la_device_impl var2;
    ar(var2);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_meter_set_statistical_impl);
CEREAL_REGISTER_TYPE(silicon_one::arc_handler_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl);

#pragma GCC diagnostic pop

