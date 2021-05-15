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

template <class Archive> void save(Archive&, const l2_slp_acl_info_t&);
template <class Archive> void load(Archive&, l2_slp_acl_info_t&);

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const la_slice_ifg&);
template <class Archive> void load(Archive&, la_slice_ifg&);

template <class Archive> void save(Archive&, const npl_ive_profile_and_data_t&);
template <class Archive> void load(Archive&, npl_ive_profile_and_data_t&);

template <class Archive> void save(Archive&, const npl_mc_slice_bitmap_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_slice_bitmap_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_slice_bitmap_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_slice_bitmap_table_value_t&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_ac_port_common&);
template <class Archive> void load(Archive&, silicon_one::la_ac_port_common&);

template <class Archive> void save(Archive&, const silicon_one::la_ac_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ac_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl&);
template <class Archive> void load(Archive&, silicon_one::la_acl&);

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

template <class Archive> void save(Archive&, const silicon_one::la_ethernet_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_ethernet_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_filter_group_impl&);
template <class Archive> void load(Archive&, silicon_one::la_filter_group_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ingress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ingress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_ip_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_multicast_group_base&);
template <class Archive> void load(Archive&, silicon_one::la_ip_multicast_group_base&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l2_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_l2_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_protection_group&);
template <class Archive> void load(Archive&, silicon_one::la_l2_protection_group&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_service_port&);
template <class Archive> void load(Archive&, silicon_one::la_l2_service_port&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_multicast_protection_group&);
template <class Archive> void load(Archive&, silicon_one::la_multicast_protection_group&);

template <class Archive> void save(Archive&, const silicon_one::la_multicast_protection_monitor&);
template <class Archive> void load(Archive&, silicon_one::la_multicast_protection_monitor&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_impl_common&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_impl_common&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_pacific::resolution_data&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_pacific::resolution_data&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object&);

template <class Archive> void save(Archive&, const silicon_one::la_protection_monitor_impl&);
template <class Archive> void load(Archive&, silicon_one::la_protection_monitor_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_stack_port&);
template <class Archive> void load(Archive&, silicon_one::la_stack_port&);

template <class Archive> void save(Archive&, const silicon_one::la_switch_impl&);
template <class Archive> void load(Archive&, silicon_one::la_switch_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port&);
template <class Archive> void load(Archive&, silicon_one::la_system_port&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf&);
template <class Archive> void load(Archive&, silicon_one::la_vrf&);

template<>
class serializer_class<silicon_one::la_ip_multicast_group_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ip_multicast_group_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ip_multicast_group_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ip_multicast_group_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_ip_multicast_group_base>(&m));
    serializer_class<silicon_one::la_ip_multicast_group_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ip_multicast_group_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ip_multicast_group_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_ip_multicast_group_base>(&m));
    serializer_class<silicon_one::la_ip_multicast_group_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ip_multicast_group_pacific&);



template<>
class serializer_class<silicon_one::la_l2_multicast_group_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_multicast_group_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_members", m.m_members));
            archive(::cereal::make_nvp("m_slice_use_count", m.m_slice_use_count));
            archive(::cereal::make_nvp("m_mc_common", m.m_mc_common));
            archive(::cereal::make_nvp("m_ref_count", m.m_ref_count));
            archive(::cereal::make_nvp("m_mc_copy_id_mapping", m.m_mc_copy_id_mapping));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_dsp_mapping", m.m_dsp_mapping));
            archive(::cereal::make_nvp("m_mmcg_l3_port", m.m_mmcg_l3_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_multicast_group_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_members", m.m_members));
            archive(::cereal::make_nvp("m_slice_use_count", m.m_slice_use_count));
            archive(::cereal::make_nvp("m_mc_common", m.m_mc_common));
            archive(::cereal::make_nvp("m_ref_count", m.m_ref_count));
            archive(::cereal::make_nvp("m_mc_copy_id_mapping", m.m_mc_copy_id_mapping));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_dsp_mapping", m.m_dsp_mapping));
            archive(::cereal::make_nvp("m_mmcg_l3_port", m.m_mmcg_l3_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_multicast_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_multicast_group>(&m));
    serializer_class<silicon_one::la_l2_multicast_group_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_multicast_group_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_multicast_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_multicast_group>(&m));
    serializer_class<silicon_one::la_l2_multicast_group_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_multicast_group_base&);



template<>
class serializer_class<silicon_one::la_l2_multicast_group_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_multicast_group_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_multicast_group_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_multicast_group_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_l2_multicast_group_base>(&m));
    serializer_class<silicon_one::la_l2_multicast_group_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_multicast_group_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_multicast_group_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_l2_multicast_group_base>(&m));
    serializer_class<silicon_one::la_l2_multicast_group_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_multicast_group_pacific&);



template<>
class serializer_class<silicon_one::la_l2_protection_group_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_protection_group_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_primary_destination", m.m_primary_destination));
            archive(::cereal::make_nvp("m_backup_destination", m.m_backup_destination));
            archive(::cereal::make_nvp("m_protection_monitor", m.m_protection_monitor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_protection_group_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_primary_destination", m.m_primary_destination));
            archive(::cereal::make_nvp("m_backup_destination", m.m_backup_destination));
            archive(::cereal::make_nvp("m_protection_monitor", m.m_protection_monitor));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_protection_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_protection_group>(&m));
    serializer_class<silicon_one::la_l2_protection_group_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_protection_group_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_protection_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_protection_group>(&m));
    serializer_class<silicon_one::la_l2_protection_group_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_protection_group_base&);



template<>
class serializer_class<silicon_one::la_l2_protection_group_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_protection_group_pacific& m) {
            archive(::cereal::make_nvp("m_table_entry", m.m_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_protection_group_pacific& m) {
            archive(::cereal::make_nvp("m_table_entry", m.m_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_protection_group_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_l2_protection_group_base>(&m));
    serializer_class<silicon_one::la_l2_protection_group_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_protection_group_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_protection_group_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_l2_protection_group_base>(&m));
    serializer_class<silicon_one::la_l2_protection_group_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_protection_group_pacific&);



template<>
class serializer_class<silicon_one::la_l2_service_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_port_type", m.m_port_type));
            archive(::cereal::make_nvp("m_port_gid", m.m_port_gid));
            archive(::cereal::make_nvp("m_ac_npl_eve_command", m.m_ac_npl_eve_command));
            archive(::cereal::make_nvp("m_ac_npl_ive_command", m.m_ac_npl_ive_command));
            archive(::cereal::make_nvp("m_stp_state", m.m_stp_state));
            archive(::cereal::make_nvp("m_learning_mode", m.m_learning_mode));
            archive(::cereal::make_nvp("m_ingress_mirror_type", m.m_ingress_mirror_type));
            archive(::cereal::make_nvp("m_egress_mirror_type", m.m_egress_mirror_type));
            archive(::cereal::make_nvp("m_recycle_label", m.m_recycle_label));
            archive(::cereal::make_nvp("m_slice_data_b", m.m_slice_data_b));
            archive(::cereal::make_nvp("m_slice_pair_data_b", m.m_slice_pair_data_b));
            archive(::cereal::make_nvp("m_ac_port_common", m.m_ac_port_common));
            archive(::cereal::make_nvp("m_acls", m.m_acls));
            archive(::cereal::make_nvp("m_local_label", m.m_local_label));
            archive(::cereal::make_nvp("m_remote_label", m.m_remote_label));
            archive(::cereal::make_nvp("m_pwe_gid", m.m_pwe_gid));
            archive(::cereal::make_nvp("m_flow_label_enable", m.m_flow_label_enable));
            archive(::cereal::make_nvp("m_control_word_enable", m.m_control_word_enable));
            archive(::cereal::make_nvp("m_drop_counter_offset", m.m_drop_counter_offset));
            archive(::cereal::make_nvp("m_local_ip_addr", m.m_local_ip_addr));
            archive(::cereal::make_nvp("m_local_ip_prefix", m.m_local_ip_prefix));
            archive(::cereal::make_nvp("m_remote_ip_addr", m.m_remote_ip_addr));
            archive(::cereal::make_nvp("m_compressed_vxlan_dlp_id", m.m_compressed_vxlan_dlp_id));
            archive(::cereal::make_nvp("m_cur_ovl_nh_id", m.m_cur_ovl_nh_id));
            archive(::cereal::make_nvp("m_sip_index", m.m_sip_index));
            archive(::cereal::make_nvp("m_ingress_sflow_enabled", m.m_ingress_sflow_enabled));
            archive(::cereal::make_nvp("m_egress_feature_mode", m.m_egress_feature_mode));
            archive(::cereal::make_nvp("m_ttl_mode", m.m_ttl_mode));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_delegate_acls", m.m_delegate_acls));
            archive(::cereal::make_nvp("m_rtf_conf_set_ptr", m.m_rtf_conf_set_ptr));
            archive(::cereal::make_nvp("m_down_mep_level", m.m_down_mep_level));
            archive(::cereal::make_nvp("m_down_mep_enabled", m.m_down_mep_enabled));
            archive(::cereal::make_nvp("m_up_mep_level", m.m_up_mep_level));
            archive(::cereal::make_nvp("m_up_mep_enabled", m.m_up_mep_enabled));
            archive(::cereal::make_nvp("m_tunnel_mode", m.m_tunnel_mode));
            archive(::cereal::make_nvp("m_group_policy_encap", m.m_group_policy_encap));
            archive(::cereal::make_nvp("m_encap_vni_map", m.m_encap_vni_map));
            archive(::cereal::make_nvp("m_copc_profile", m.m_copc_profile));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_ac_ethernet_port", m.m_ac_ethernet_port));
            archive(::cereal::make_nvp("m_ingress_mirror_cmd", m.m_ingress_mirror_cmd));
            archive(::cereal::make_nvp("m_egress_mirror_cmd", m.m_egress_mirror_cmd));
            archive(::cereal::make_nvp("m_attached_switch", m.m_attached_switch));
            archive(::cereal::make_nvp("m_recycle_destination", m.m_recycle_destination));
            archive(::cereal::make_nvp("m_attached_destination", m.m_attached_destination));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
            archive(::cereal::make_nvp("m_l3_destination", m.m_l3_destination));
            archive(::cereal::make_nvp("m_p_counter", m.m_p_counter));
            archive(::cereal::make_nvp("m_q_counter", m.m_q_counter));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_ingress_acl_group", m.m_ingress_acl_group));
            archive(::cereal::make_nvp("m_egress_acl_group", m.m_egress_acl_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_base& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_port_type", m.m_port_type));
            archive(::cereal::make_nvp("m_port_gid", m.m_port_gid));
            archive(::cereal::make_nvp("m_ac_npl_eve_command", m.m_ac_npl_eve_command));
            archive(::cereal::make_nvp("m_ac_npl_ive_command", m.m_ac_npl_ive_command));
            archive(::cereal::make_nvp("m_stp_state", m.m_stp_state));
            archive(::cereal::make_nvp("m_learning_mode", m.m_learning_mode));
            archive(::cereal::make_nvp("m_ingress_mirror_type", m.m_ingress_mirror_type));
            archive(::cereal::make_nvp("m_egress_mirror_type", m.m_egress_mirror_type));
            archive(::cereal::make_nvp("m_recycle_label", m.m_recycle_label));
            archive(::cereal::make_nvp("m_slice_data_b", m.m_slice_data_b));
            archive(::cereal::make_nvp("m_slice_pair_data_b", m.m_slice_pair_data_b));
            archive(::cereal::make_nvp("m_ac_port_common", m.m_ac_port_common));
            archive(::cereal::make_nvp("m_acls", m.m_acls));
            archive(::cereal::make_nvp("m_local_label", m.m_local_label));
            archive(::cereal::make_nvp("m_remote_label", m.m_remote_label));
            archive(::cereal::make_nvp("m_pwe_gid", m.m_pwe_gid));
            archive(::cereal::make_nvp("m_flow_label_enable", m.m_flow_label_enable));
            archive(::cereal::make_nvp("m_control_word_enable", m.m_control_word_enable));
            archive(::cereal::make_nvp("m_drop_counter_offset", m.m_drop_counter_offset));
            archive(::cereal::make_nvp("m_local_ip_addr", m.m_local_ip_addr));
            archive(::cereal::make_nvp("m_local_ip_prefix", m.m_local_ip_prefix));
            archive(::cereal::make_nvp("m_remote_ip_addr", m.m_remote_ip_addr));
            archive(::cereal::make_nvp("m_compressed_vxlan_dlp_id", m.m_compressed_vxlan_dlp_id));
            archive(::cereal::make_nvp("m_cur_ovl_nh_id", m.m_cur_ovl_nh_id));
            archive(::cereal::make_nvp("m_sip_index", m.m_sip_index));
            archive(::cereal::make_nvp("m_ingress_sflow_enabled", m.m_ingress_sflow_enabled));
            archive(::cereal::make_nvp("m_egress_feature_mode", m.m_egress_feature_mode));
            archive(::cereal::make_nvp("m_ttl_mode", m.m_ttl_mode));
            archive(::cereal::make_nvp("m_ttl", m.m_ttl));
            archive(::cereal::make_nvp("m_delegate_acls", m.m_delegate_acls));
            archive(::cereal::make_nvp("m_rtf_conf_set_ptr", m.m_rtf_conf_set_ptr));
            archive(::cereal::make_nvp("m_down_mep_level", m.m_down_mep_level));
            archive(::cereal::make_nvp("m_down_mep_enabled", m.m_down_mep_enabled));
            archive(::cereal::make_nvp("m_up_mep_level", m.m_up_mep_level));
            archive(::cereal::make_nvp("m_up_mep_enabled", m.m_up_mep_enabled));
            archive(::cereal::make_nvp("m_tunnel_mode", m.m_tunnel_mode));
            archive(::cereal::make_nvp("m_group_policy_encap", m.m_group_policy_encap));
            archive(::cereal::make_nvp("m_encap_vni_map", m.m_encap_vni_map));
            archive(::cereal::make_nvp("m_copc_profile", m.m_copc_profile));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_ac_ethernet_port", m.m_ac_ethernet_port));
            archive(::cereal::make_nvp("m_ingress_mirror_cmd", m.m_ingress_mirror_cmd));
            archive(::cereal::make_nvp("m_egress_mirror_cmd", m.m_egress_mirror_cmd));
            archive(::cereal::make_nvp("m_attached_switch", m.m_attached_switch));
            archive(::cereal::make_nvp("m_recycle_destination", m.m_recycle_destination));
            archive(::cereal::make_nvp("m_attached_destination", m.m_attached_destination));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
            archive(::cereal::make_nvp("m_l3_destination", m.m_l3_destination));
            archive(::cereal::make_nvp("m_p_counter", m.m_p_counter));
            archive(::cereal::make_nvp("m_q_counter", m.m_q_counter));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
            archive(::cereal::make_nvp("m_ingress_qos_profile", m.m_ingress_qos_profile));
            archive(::cereal::make_nvp("m_egress_qos_profile", m.m_egress_qos_profile));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_ingress_acl_group", m.m_ingress_acl_group));
            archive(::cereal::make_nvp("m_egress_acl_group", m.m_egress_acl_group));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_service_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l2_service_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_l2_service_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l2_service_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_base&);



template<>
class serializer_class<silicon_one::la_l2_service_port_base::slice_data_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_base::slice_data_base& m) {
            archive(::cereal::make_nvp("pwe_port_tag_entry_location", m.pwe_port_tag_entry_location));
            archive(::cereal::make_nvp("pwe_port_tag_entry", m.pwe_port_tag_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_base::slice_data_base& m) {
            archive(::cereal::make_nvp("pwe_port_tag_entry_location", m.pwe_port_tag_entry_location));
            archive(::cereal::make_nvp("pwe_port_tag_entry", m.pwe_port_tag_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_base::slice_data_base& m)
{
    serializer_class<silicon_one::la_l2_service_port_base::slice_data_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_base::slice_data_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_base::slice_data_base& m)
{
    serializer_class<silicon_one::la_l2_service_port_base::slice_data_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_base::slice_data_base&);



template<>
class serializer_class<silicon_one::la_l2_service_port_base::slice_pair_data_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_base::slice_pair_data_base& m) {
            archive(::cereal::make_nvp("acl_profile", m.acl_profile));
            archive(::cereal::make_nvp("l2_dlp_entry", m.l2_dlp_entry));
            archive(::cereal::make_nvp("vxlan_l2_dlp_entry", m.vxlan_l2_dlp_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_base::slice_pair_data_base& m) {
            archive(::cereal::make_nvp("acl_profile", m.acl_profile));
            archive(::cereal::make_nvp("l2_dlp_entry", m.l2_dlp_entry));
            archive(::cereal::make_nvp("vxlan_l2_dlp_entry", m.vxlan_l2_dlp_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_base::slice_pair_data_base& m)
{
    serializer_class<silicon_one::la_l2_service_port_base::slice_pair_data_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_base::slice_pair_data_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_base::slice_pair_data_base& m)
{
    serializer_class<silicon_one::la_l2_service_port_base::slice_pair_data_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_base::slice_pair_data_base&);



template<>
class serializer_class<silicon_one::la_l2_service_port_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_pacgb& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_pacgb& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_l2_service_port_base>(&m));
    serializer_class<silicon_one::la_l2_service_port_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_l2_service_port_base>(&m));
    serializer_class<silicon_one::la_l2_service_port_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_pacgb&);



template<>
class serializer_class<silicon_one::la_l2_service_port_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_pacific& m) {
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ac_profile_for_pwe", m.m_ac_profile_for_pwe));
            archive(::cereal::make_nvp("m_native_l2_table_entry", m.m_native_l2_table_entry));
            archive(::cereal::make_nvp("m_pwe_l3_dest_entry", m.m_pwe_l3_dest_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_pacific& m) {
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ac_profile_for_pwe", m.m_ac_profile_for_pwe));
            archive(::cereal::make_nvp("m_native_l2_table_entry", m.m_native_l2_table_entry));
            archive(::cereal::make_nvp("m_pwe_l3_dest_entry", m.m_pwe_l3_dest_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_l2_service_port_pacgb>(&m));
    serializer_class<silicon_one::la_l2_service_port_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_l2_service_port_pacgb>(&m));
    serializer_class<silicon_one::la_l2_service_port_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_pacific&);



template<>
class serializer_class<silicon_one::la_l2_service_port_pacific::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_pacific::slice_data& m) {
            archive(::cereal::make_nvp("pwe_port_tag_entry_location", m.pwe_port_tag_entry_location));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
            archive(::cereal::make_nvp("pwe_port_tag_entry", m.pwe_port_tag_entry));
            archive(::cereal::make_nvp("mpls_termination_entry", m.mpls_termination_entry));
            archive(::cereal::make_nvp("lp_attributes_entry", m.lp_attributes_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_pacific::slice_data& m) {
            archive(::cereal::make_nvp("pwe_port_tag_entry_location", m.pwe_port_tag_entry_location));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
            archive(::cereal::make_nvp("pwe_port_tag_entry", m.pwe_port_tag_entry));
            archive(::cereal::make_nvp("mpls_termination_entry", m.mpls_termination_entry));
            archive(::cereal::make_nvp("lp_attributes_entry", m.lp_attributes_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_pacific::slice_data& m)
{
    serializer_class<silicon_one::la_l2_service_port_pacific::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_pacific::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_pacific::slice_data& m)
{
    serializer_class<silicon_one::la_l2_service_port_pacific::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_pacific::slice_data&);



template<>
class serializer_class<silicon_one::la_l2_service_port_pacific::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_service_port_pacific::slice_pair_data& m) {
            archive(::cereal::make_nvp("l2_dlp_entry", m.l2_dlp_entry));
            archive(::cereal::make_nvp("vxlan_l2_dlp_entry", m.vxlan_l2_dlp_entry));
            archive(::cereal::make_nvp("pwe_encap_entry", m.pwe_encap_entry));
            archive(::cereal::make_nvp("pwe_vpls_label_entry", m.pwe_vpls_label_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_service_port_pacific::slice_pair_data& m) {
            archive(::cereal::make_nvp("l2_dlp_entry", m.l2_dlp_entry));
            archive(::cereal::make_nvp("vxlan_l2_dlp_entry", m.vxlan_l2_dlp_entry));
            archive(::cereal::make_nvp("pwe_encap_entry", m.pwe_encap_entry));
            archive(::cereal::make_nvp("pwe_vpls_label_entry", m.pwe_vpls_label_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_service_port_pacific::slice_pair_data& m)
{
    serializer_class<silicon_one::la_l2_service_port_pacific::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_service_port_pacific::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_service_port_pacific::slice_pair_data& m)
{
    serializer_class<silicon_one::la_l2_service_port_pacific::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_service_port_pacific::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_base& m) {
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_local_mcid", m.m_local_mcid));
            archive(::cereal::make_nvp("m_is_scale_mode_smcid", m.m_is_scale_mode_smcid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_mc_fabric_slice_bitmap_table_value", m.m_mc_fabric_slice_bitmap_table_value));
            archive(::cereal::make_nvp("m_mc_network_slice_bitmap_table_value", m.m_mc_network_slice_bitmap_table_value));
            archive(::cereal::make_nvp("m_mc_slice_bitmap_table_key", m.m_mc_slice_bitmap_table_key));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_ir_data", m.m_ir_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_base& m) {
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_local_mcid", m.m_local_mcid));
            archive(::cereal::make_nvp("m_is_scale_mode_smcid", m.m_is_scale_mode_smcid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_mc_fabric_slice_bitmap_table_value", m.m_mc_fabric_slice_bitmap_table_value));
            archive(::cereal::make_nvp("m_mc_network_slice_bitmap_table_value", m.m_mc_network_slice_bitmap_table_value));
            archive(::cereal::make_nvp("m_mc_slice_bitmap_table_key", m.m_mc_slice_bitmap_table_key));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_ir_data", m.m_ir_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_base& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_base& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_base&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_base::protected_member_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_base::protected_member_info& m) {
            archive(::cereal::make_nvp("is_primary", m.is_primary));
            archive(::cereal::make_nvp("prot_group", m.prot_group));
            archive(::cereal::make_nvp("next_hop", m.next_hop));
            archive(::cereal::make_nvp("monitor", m.monitor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_base::protected_member_info& m) {
            archive(::cereal::make_nvp("is_primary", m.is_primary));
            archive(::cereal::make_nvp("prot_group", m.prot_group));
            archive(::cereal::make_nvp("next_hop", m.next_hop));
            archive(::cereal::make_nvp("monitor", m.monitor));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_base::protected_member_info& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::protected_member_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_base::protected_member_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_base::protected_member_info& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::protected_member_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_base::protected_member_info&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_base::group_member_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_base::group_member_desc& m) {
            archive(::cereal::make_nvp("is_punt", m.is_punt));
            archive(::cereal::make_nvp("vxlan_type", m.vxlan_type));
            archive(::cereal::make_nvp("prot_info", m.prot_info));
            archive(::cereal::make_nvp("counter_slice_ifg", m.counter_slice_ifg));
            archive(::cereal::make_nvp("l3_port", m.l3_port));
            archive(::cereal::make_nvp("l2_dest", m.l2_dest));
            archive(::cereal::make_nvp("l2_mcg", m.l2_mcg));
            archive(::cereal::make_nvp("ip_mcg", m.ip_mcg));
            archive(::cereal::make_nvp("mpls_mcg", m.mpls_mcg));
            archive(::cereal::make_nvp("next_hop", m.next_hop));
            archive(::cereal::make_nvp("prefix_object", m.prefix_object));
            archive(::cereal::make_nvp("stackport", m.stackport));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_base::group_member_desc& m) {
            archive(::cereal::make_nvp("is_punt", m.is_punt));
            archive(::cereal::make_nvp("vxlan_type", m.vxlan_type));
            archive(::cereal::make_nvp("prot_info", m.prot_info));
            archive(::cereal::make_nvp("counter_slice_ifg", m.counter_slice_ifg));
            archive(::cereal::make_nvp("l3_port", m.l3_port));
            archive(::cereal::make_nvp("l2_dest", m.l2_dest));
            archive(::cereal::make_nvp("l2_mcg", m.l2_mcg));
            archive(::cereal::make_nvp("ip_mcg", m.ip_mcg));
            archive(::cereal::make_nvp("mpls_mcg", m.mpls_mcg));
            archive(::cereal::make_nvp("next_hop", m.next_hop));
            archive(::cereal::make_nvp("prefix_object", m.prefix_object));
            archive(::cereal::make_nvp("stackport", m.stackport));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_base::group_member_desc& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::group_member_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_base::group_member_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_base::group_member_desc& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::group_member_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_base::group_member_desc&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_base::ir_member> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_base::ir_member& m) {
            archive(::cereal::make_nvp("mcid", m.mcid));
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("member", m.member));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_base::ir_member& m) {
            archive(::cereal::make_nvp("mcid", m.mcid));
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("member", m.member));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_base::ir_member& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::ir_member>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_base::ir_member&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_base::ir_member& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::ir_member>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_base::ir_member&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_base::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_base::slice_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("mc_em_entries", m.mc_em_entries));
            archive(::cereal::make_nvp("mc_em_entries_map", m.mc_em_entries_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_base::slice_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("mc_em_entries", m.mc_em_entries));
            archive(::cereal::make_nvp("mc_em_entries_map", m.mc_em_entries_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_base::slice_data& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_base::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_base::slice_data& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_base::slice_data&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_base::ir_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_base::ir_data& m) {
            archive(::cereal::make_nvp("mc_em_entries", m.mc_em_entries));
            archive(::cereal::make_nvp("mc_em_entries_map", m.mc_em_entries_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_base::ir_data& m) {
            archive(::cereal::make_nvp("mc_em_entries", m.mc_em_entries));
            archive(::cereal::make_nvp("mc_em_entries_map", m.mc_em_entries_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_base::ir_data& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::ir_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_base::ir_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_base::ir_data& m)
{
    serializer_class<silicon_one::la_multicast_group_common_base::ir_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_base::ir_data&);



template<>
class serializer_class<silicon_one::la_multicast_group_common_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_group_common_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_group_common_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_group_common_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_multicast_group_common_base>(&m));
    serializer_class<silicon_one::la_multicast_group_common_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_group_common_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_group_common_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_multicast_group_common_base>(&m));
    serializer_class<silicon_one::la_multicast_group_common_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_group_common_pacific&);



template<>
class serializer_class<silicon_one::la_multicast_protection_group_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_multicast_protection_group_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_primary_dest", m.m_primary_dest));
            archive(::cereal::make_nvp("m_backup_dest", m.m_backup_dest));
            archive(::cereal::make_nvp("m_primary_sys_port", m.m_primary_sys_port));
            archive(::cereal::make_nvp("m_backup_sys_port", m.m_backup_sys_port));
            archive(::cereal::make_nvp("m_monitor", m.m_monitor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_multicast_protection_group_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_primary_dest", m.m_primary_dest));
            archive(::cereal::make_nvp("m_backup_dest", m.m_backup_dest));
            archive(::cereal::make_nvp("m_primary_sys_port", m.m_primary_sys_port));
            archive(::cereal::make_nvp("m_backup_sys_port", m.m_backup_sys_port));
            archive(::cereal::make_nvp("m_monitor", m.m_monitor));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_multicast_protection_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_multicast_protection_group>(&m));
    serializer_class<silicon_one::la_multicast_protection_group_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_multicast_protection_group_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_multicast_protection_group_base& m)
{
    archive(cereal::base_class<silicon_one::la_multicast_protection_group>(&m));
    serializer_class<silicon_one::la_multicast_protection_group_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_multicast_protection_group_base&);



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
class serializer_class<silicon_one::la_next_hop_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_next_hop_pacific& m) {
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_next_hop_pacific& m) {
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_next_hop_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop_pacgb>(&m));
    serializer_class<silicon_one::la_next_hop_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_next_hop_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_next_hop_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_next_hop_pacgb>(&m));
    serializer_class<silicon_one::la_next_hop_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_next_hop_pacific&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_ip_multicast_group_pacific var0;
    ar(var0);
    silicon_one::la_l2_multicast_group_pacific var1;
    ar(var1);
    silicon_one::la_l2_protection_group_pacific var2;
    ar(var2);
    silicon_one::la_l2_service_port_pacific var3;
    ar(var3);
    silicon_one::la_multicast_group_common_pacific var4;
    ar(var4);
    silicon_one::la_multicast_protection_group_base var5;
    ar(var5);
    silicon_one::la_multicast_protection_monitor_base var6;
    ar(var6);
    silicon_one::la_next_hop_pacific var7;
    ar(var7);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_ip_multicast_group_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_multicast_group_base);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_multicast_group_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_protection_group_base);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_protection_group_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_service_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_service_port_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_service_port_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_multicast_group_common_base);
CEREAL_REGISTER_TYPE(silicon_one::la_multicast_group_common_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_multicast_protection_group_base);
CEREAL_REGISTER_TYPE(silicon_one::la_multicast_protection_monitor_base);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_base);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_next_hop_pacific);

#pragma GCC diagnostic pop

