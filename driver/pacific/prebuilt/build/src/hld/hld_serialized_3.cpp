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

template <class Archive> void save(Archive&, const npl_base_l3_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_base_l3_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_additional_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_additional_attributes_t&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_acl&);
template <class Archive> void load(Archive&, silicon_one::la_acl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_command_profile_base&);
template <class Archive> void load(Archive&, silicon_one::la_acl_command_profile_base&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_delegate&);
template <class Archive> void load(Archive&, silicon_one::la_acl_delegate&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_key_profile_base&);
template <class Archive> void load(Archive&, silicon_one::la_acl_key_profile_base&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_scale_field_key&);
template <class Archive> void load(Archive&, silicon_one::la_acl_scale_field_key&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_scaled&);
template <class Archive> void load(Archive&, silicon_one::la_acl_scaled&);

template <class Archive> void save(Archive&, const silicon_one::la_asbr_lsp&);
template <class Archive> void load(Archive&, silicon_one::la_asbr_lsp&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_destination_pe&);
template <class Archive> void load(Archive&, silicon_one::la_destination_pe&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ecmp_group&);
template <class Archive> void load(Archive&, silicon_one::la_ecmp_group&);

template <class Archive> void save(Archive&, const silicon_one::la_egress_qos_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_egress_qos_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_multicast_group&);

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

template <class Archive> void save(Archive&, const silicon_one::la_ip_tunnel_destination&);
template <class Archive> void load(Archive&, silicon_one::la_ip_tunnel_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_exact_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_exact_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object_base&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object_base&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_impl&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_port_common_base&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_port_common_base&);

template <class Archive> void save(Archive&, const silicon_one::resolution_table_index&);
template <class Archive> void load(Archive&, silicon_one::resolution_table_index&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr&);

template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait&);



template<>
class serializer_class<silicon_one::la_acl_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_delegate", m.m_delegate));
            archive(::cereal::make_nvp("m_is_og_acl", m.m_is_og_acl));
            archive(::cereal::make_nvp("m_is_class_id_enabled", m.m_is_class_id_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acl_key_profile", m.m_acl_key_profile));
            archive(::cereal::make_nvp("m_acl_command_profile", m.m_acl_command_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_delegate", m.m_delegate));
            archive(::cereal::make_nvp("m_is_og_acl", m.m_is_og_acl));
            archive(::cereal::make_nvp("m_is_class_id_enabled", m.m_is_class_id_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acl_key_profile", m.m_acl_key_profile));
            archive(::cereal::make_nvp("m_acl_command_profile", m.m_acl_command_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_impl& m)
{
    archive(cereal::base_class<silicon_one::la_acl>(&m));
    serializer_class<silicon_one::la_acl_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_impl& m)
{
    archive(cereal::base_class<silicon_one::la_acl>(&m));
    serializer_class<silicon_one::la_acl_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_impl&);



template<>
class serializer_class<silicon_one::la_acl_scaled_delegate> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_scaled_delegate& m) {
            archive(::cereal::make_nvp("m_scale_field_entries", m.m_scale_field_entries));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_scaled_delegate& m) {
            archive(::cereal::make_nvp("m_scale_field_entries", m.m_scale_field_entries));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_scaled_delegate& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_scaled_delegate>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_scaled_delegate&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_scaled_delegate& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_scaled_delegate>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_scaled_delegate&);



template<>
class serializer_class<silicon_one::la_acl_scaled_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_scaled_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_delegate", m.m_delegate));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_scaled_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_delegate", m.m_delegate));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_scaled_impl& m)
{
    archive(cereal::base_class<silicon_one::la_acl_scaled>(&m));
    serializer_class<silicon_one::la_acl_scaled_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_scaled_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_scaled_impl& m)
{
    archive(cereal::base_class<silicon_one::la_acl_scaled>(&m));
    serializer_class<silicon_one::la_acl_scaled_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_scaled_impl&);



template<>
class serializer_class<silicon_one::la_asbr_lsp_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_asbr_lsp_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_asbr", m.m_asbr));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_primary_nh", m.m_primary_nh));
            archive(::cereal::make_nvp("m_backup_nh", m.m_backup_nh));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_asbr_lsp_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_asbr", m.m_asbr));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_primary_nh", m.m_primary_nh));
            archive(::cereal::make_nvp("m_backup_nh", m.m_backup_nh));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_asbr_lsp_impl& m)
{
    archive(cereal::base_class<silicon_one::la_asbr_lsp>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_asbr_lsp_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_asbr_lsp_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_asbr_lsp_impl& m)
{
    archive(cereal::base_class<silicon_one::la_asbr_lsp>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_asbr_lsp_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_asbr_lsp_impl&);



template<>
class serializer_class<silicon_one::la_counter_set_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_counter_set_impl& m) {
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_direction", m.m_direction));
            archive(::cereal::make_nvp("m_user_type", m.m_user_type));
            archive(::cereal::make_nvp("m_counter_type", m.m_counter_type));
            archive(::cereal::make_nvp("m_is_aggregate", m.m_is_aggregate));
            archive(::cereal::make_nvp("m_base_voq", m.m_base_voq));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_cached_packets", m.m_cached_packets));
            archive(::cereal::make_nvp("m_cached_bytes", m.m_cached_bytes));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_counter_set_impl& m) {
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_direction", m.m_direction));
            archive(::cereal::make_nvp("m_user_type", m.m_user_type));
            archive(::cereal::make_nvp("m_counter_type", m.m_counter_type));
            archive(::cereal::make_nvp("m_is_aggregate", m.m_is_aggregate));
            archive(::cereal::make_nvp("m_base_voq", m.m_base_voq));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_cached_packets", m.m_cached_packets));
            archive(::cereal::make_nvp("m_cached_bytes", m.m_cached_bytes));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_meter", m.m_meter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_counter_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_counter_set>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_counter_set_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_counter_set_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_counter_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_counter_set>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_counter_set_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_counter_set_impl&);



template<>
class serializer_class<silicon_one::la_counter_set_impl::allocation_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_counter_set_impl::allocation_desc& m) {
            archive(::cereal::make_nvp("is_valid", m.is_valid));
            archive(::cereal::make_nvp("allocation", m.allocation));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_counter_set_impl::allocation_desc& m) {
            archive(::cereal::make_nvp("is_valid", m.is_valid));
            archive(::cereal::make_nvp("allocation", m.allocation));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_counter_set_impl::allocation_desc& m)
{
    serializer_class<silicon_one::la_counter_set_impl::allocation_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_counter_set_impl::allocation_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_counter_set_impl::allocation_desc& m)
{
    serializer_class<silicon_one::la_counter_set_impl::allocation_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_counter_set_impl::allocation_desc&);



template<>
class serializer_class<silicon_one::la_destination_pe_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_destination_pe_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_vpn_enabled", m.m_vpn_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_vpn_entry_map", m.m_vpn_entry_map));
            archive(::cereal::make_nvp("m_asbr_entry_map", m.m_asbr_entry_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_destination_pe_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_vpn_enabled", m.m_vpn_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_vpn_entry_map", m.m_vpn_entry_map));
            archive(::cereal::make_nvp("m_asbr_entry_map", m.m_asbr_entry_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_destination_pe_impl& m)
{
    archive(cereal::base_class<silicon_one::la_destination_pe>(&m));
    serializer_class<silicon_one::la_destination_pe_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_destination_pe_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_destination_pe_impl& m)
{
    archive(cereal::base_class<silicon_one::la_destination_pe>(&m));
    serializer_class<silicon_one::la_destination_pe_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_destination_pe_impl&);



template<>
class serializer_class<silicon_one::la_destination_pe_impl::vpn_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_destination_pe_impl::vpn_info& m) {
            archive(::cereal::make_nvp("ipv4_labels", m.ipv4_labels));
            archive(::cereal::make_nvp("ipv4_valid", m.ipv4_valid));
            archive(::cereal::make_nvp("ipv6_labels", m.ipv6_labels));
            archive(::cereal::make_nvp("ipv6_valid", m.ipv6_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_destination_pe_impl::vpn_info& m) {
            archive(::cereal::make_nvp("ipv4_labels", m.ipv4_labels));
            archive(::cereal::make_nvp("ipv4_valid", m.ipv4_valid));
            archive(::cereal::make_nvp("ipv6_labels", m.ipv6_labels));
            archive(::cereal::make_nvp("ipv6_valid", m.ipv6_valid));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_destination_pe_impl::vpn_info& m)
{
    serializer_class<silicon_one::la_destination_pe_impl::vpn_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_destination_pe_impl::vpn_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_destination_pe_impl::vpn_info& m)
{
    serializer_class<silicon_one::la_destination_pe_impl::vpn_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_destination_pe_impl::vpn_info&);



template<>
class serializer_class<silicon_one::la_destination_pe_impl::asbr_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_destination_pe_impl::asbr_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_destination_pe_impl::asbr_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_destination_pe_impl::asbr_info& m)
{
    serializer_class<silicon_one::la_destination_pe_impl::asbr_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_destination_pe_impl::asbr_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_destination_pe_impl::asbr_info& m)
{
    serializer_class<silicon_one::la_destination_pe_impl::asbr_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_destination_pe_impl::asbr_info&);



template<>
class serializer_class<silicon_one::la_ecmp_group_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ecmp_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_level", m.m_level));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_is_ip_tunnel", m.m_is_ip_tunnel));
            archive(::cereal::make_nvp("m_is_drop", m.m_is_drop));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ecmp_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_level", m.m_level));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_is_ip_tunnel", m.m_is_ip_tunnel));
            archive(::cereal::make_nvp("m_is_drop", m.m_is_drop));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_destinations", m.m_l3_destinations));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ecmp_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ecmp_group>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ecmp_group_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ecmp_group_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ecmp_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ecmp_group>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ecmp_group_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ecmp_group_impl&);



template<>
class serializer_class<silicon_one::la_ecmp_group_impl::resolution_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ecmp_group_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("id_in_step", m.id_in_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ecmp_group_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("id_in_step", m.id_in_step));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ecmp_group_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_ecmp_group_impl::resolution_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ecmp_group_impl::resolution_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ecmp_group_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_ecmp_group_impl::resolution_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ecmp_group_impl::resolution_data&);



template<>
class serializer_class<silicon_one::la_fabric_multicast_group_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_fabric_multicast_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_local_mcid", m.m_local_mcid));
            archive(::cereal::make_nvp("m_is_scale_mode_smcid", m.m_is_scale_mode_smcid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_devices", m.m_devices));
            archive(::cereal::make_nvp("m_links_bitmap", m.m_links_bitmap));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_fabric_multicast_group_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_local_mcid", m.m_local_mcid));
            archive(::cereal::make_nvp("m_is_scale_mode_smcid", m.m_is_scale_mode_smcid));
            archive(::cereal::make_nvp("m_rep_paradigm", m.m_rep_paradigm));
            archive(::cereal::make_nvp("m_devices", m.m_devices));
            archive(::cereal::make_nvp("m_links_bitmap", m.m_links_bitmap));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_fabric_multicast_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_fabric_multicast_group>(&m));
    serializer_class<silicon_one::la_fabric_multicast_group_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_fabric_multicast_group_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_fabric_multicast_group_impl& m)
{
    archive(cereal::base_class<silicon_one::la_fabric_multicast_group>(&m));
    serializer_class<silicon_one::la_fabric_multicast_group_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_fabric_multicast_group_impl&);



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
class serializer_class<silicon_one::la_ip_tunnel_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ip_tunnel_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ip_tunnel_destination_gid", m.m_ip_tunnel_destination_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_destination", m.m_underlay_destination));
            archive(::cereal::make_nvp("m_ip_tunnel_port", m.m_ip_tunnel_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ip_tunnel_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ip_tunnel_destination_gid", m.m_ip_tunnel_destination_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_destination", m.m_underlay_destination));
            archive(::cereal::make_nvp("m_ip_tunnel_port", m.m_ip_tunnel_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ip_tunnel_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ip_tunnel_destination>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ip_tunnel_destination_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ip_tunnel_destination_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ip_tunnel_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ip_tunnel_destination>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ip_tunnel_destination_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ip_tunnel_destination_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_acl_impl var0;
    ar(var0);
    silicon_one::la_acl_scaled_impl var1;
    ar(var1);
    silicon_one::la_asbr_lsp_impl var2;
    ar(var2);
    silicon_one::la_counter_set_impl var3;
    ar(var3);
    silicon_one::la_destination_pe_impl var4;
    ar(var4);
    silicon_one::la_ecmp_group_impl var5;
    ar(var5);
    silicon_one::la_fabric_multicast_group_impl var6;
    ar(var6);
    silicon_one::la_filter_group_impl var7;
    ar(var7);
    silicon_one::la_forus_destination_impl var8;
    ar(var8);
    silicon_one::la_gre_port_impl var9;
    ar(var9);
    silicon_one::la_gue_port_impl var10;
    ar(var10);
    silicon_one::la_ip_over_ip_tunnel_port_impl var11;
    ar(var11);
    silicon_one::la_ip_tunnel_destination_impl var12;
    ar(var12);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_acl_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_scaled_delegate);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_scaled_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_asbr_lsp_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_counter_set_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_destination_pe_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ecmp_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_fabric_multicast_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_filter_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_forus_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_gre_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_gue_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ip_over_ip_tunnel_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ip_tunnel_destination_impl);

#pragma GCC diagnostic pop

