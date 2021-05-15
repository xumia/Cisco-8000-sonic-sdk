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

template <class Archive> void save(Archive&, const la_vsc_oq&);
template <class Archive> void load(Archive&, la_vsc_oq&);

template <class Archive> void save(Archive&, const npl_filb_voq_mapping_value_t&);
template <class Archive> void load(Archive&, npl_filb_voq_mapping_value_t&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::index_handle&);
template <class Archive> void load(Archive&, silicon_one::index_handle&);

template <class Archive> void save(Archive&, const silicon_one::la_ac_profile&);
template <class Archive> void load(Archive&, silicon_one::la_ac_profile&);

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

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_ifg_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_ifg_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_interface_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_interface_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_logical_port_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_logical_port_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop&);

template <class Archive> void save(Archive&, const silicon_one::la_output_queue_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_output_queue_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object&);

template <class Archive> void save(Archive&, const silicon_one::la_rx_cgm_policy_status&);
template <class Archive> void load(Archive&, silicon_one::la_rx_cgm_policy_status&);

template <class Archive> void save(Archive&, const silicon_one::la_rx_cgm_sq_profile&);
template <class Archive> void load(Archive&, silicon_one::la_rx_cgm_sq_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_rx_cgm_sq_profile_thresholds&);
template <class Archive> void load(Archive&, silicon_one::la_rx_cgm_sq_profile_thresholds&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_cgm_profile_impl&);
template <class Archive> void load(Archive&, silicon_one::la_voq_cgm_profile_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_set_base&);
template <class Archive> void load(Archive&, silicon_one::la_voq_set_base&);

template <class Archive> void save(Archive&, const silicon_one::lld_memory&);
template <class Archive> void load(Archive&, silicon_one::lld_memory&);

template <class Archive> void save(Archive&, const silicon_one::lld_register&);
template <class Archive> void load(Archive&, silicon_one::lld_register&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr&);

template<>
class serializer_class<silicon_one::srm_serdes_handler::tx_sp9_state_transition> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::srm_serdes_handler::tx_sp9_state_transition& m) {
            archive(::cereal::make_nvp("rx_state", m.rx_state));
            archive(::cereal::make_nvp("tx_state", m.tx_state));
            archive(::cereal::make_nvp("timestamp", m.timestamp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::srm_serdes_handler::tx_sp9_state_transition& m) {
            archive(::cereal::make_nvp("rx_state", m.rx_state));
            archive(::cereal::make_nvp("tx_state", m.tx_state));
            archive(::cereal::make_nvp("timestamp", m.timestamp));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::srm_serdes_handler::tx_sp9_state_transition& m)
{
    serializer_class<silicon_one::srm_serdes_handler::tx_sp9_state_transition>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::srm_serdes_handler::tx_sp9_state_transition&);

template <class Archive>
void
load(Archive& archive, silicon_one::srm_serdes_handler::tx_sp9_state_transition& m)
{
    serializer_class<silicon_one::srm_serdes_handler::tx_sp9_state_transition>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::srm_serdes_handler::tx_sp9_state_transition&);



template<>
class serializer_class<silicon_one::srm_serdes_handler::rx_sp9_state_transition> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::srm_serdes_handler::rx_sp9_state_transition& m) {
            archive(::cereal::make_nvp("rx_state", m.rx_state));
            archive(::cereal::make_nvp("timestamp", m.timestamp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::srm_serdes_handler::rx_sp9_state_transition& m) {
            archive(::cereal::make_nvp("rx_state", m.rx_state));
            archive(::cereal::make_nvp("timestamp", m.timestamp));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::srm_serdes_handler::rx_sp9_state_transition& m)
{
    serializer_class<silicon_one::srm_serdes_handler::rx_sp9_state_transition>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::srm_serdes_handler::rx_sp9_state_transition&);

template <class Archive>
void
load(Archive& archive, silicon_one::srm_serdes_handler::rx_sp9_state_transition& m)
{
    serializer_class<silicon_one::srm_serdes_handler::rx_sp9_state_transition>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::srm_serdes_handler::rx_sp9_state_transition&);



template<>
class serializer_class<silicon_one::la_logical_port_scheduler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_logical_port_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_tid", m.m_tid));
            archive(::cereal::make_nvp("m_port_speed", m.m_port_speed));
            archive(::cereal::make_nvp("m_groups_cir_weights", m.m_groups_cir_weights));
            archive(::cereal::make_nvp("m_groups_eir_weights", m.m_groups_eir_weights));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_cs", m.m_cs));
            archive(::cereal::make_nvp("m_oq_sch_set", m.m_oq_sch_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_logical_port_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_tid", m.m_tid));
            archive(::cereal::make_nvp("m_port_speed", m.m_port_speed));
            archive(::cereal::make_nvp("m_groups_cir_weights", m.m_groups_cir_weights));
            archive(::cereal::make_nvp("m_groups_eir_weights", m.m_groups_eir_weights));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_cs", m.m_cs));
            archive(::cereal::make_nvp("m_oq_sch_set", m.m_oq_sch_set));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_logical_port_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_logical_port_scheduler>(&m));
    serializer_class<silicon_one::la_logical_port_scheduler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_logical_port_scheduler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_logical_port_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_logical_port_scheduler>(&m));
    serializer_class<silicon_one::la_logical_port_scheduler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_logical_port_scheduler_impl&);



template<>
class serializer_class<silicon_one::la_output_queue_scheduler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_output_queue_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_sch_oqse_cfg", m.m_sch_oqse_cfg));
            archive(::cereal::make_nvp("m_sch_vsc_map_cfg", m.m_sch_vsc_map_cfg));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket", m.m_sch_vsc_token_bucket));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket_cfg", m.m_sch_vsc_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket_empty", m.m_sch_vsc_token_bucket_empty));
            archive(::cereal::make_nvp("m_oqse_shaper_configuration", m.m_oqse_shaper_configuration));
            archive(::cereal::make_nvp("m_oqse_id", m.m_oqse_id));
            archive(::cereal::make_nvp("m_scheduling_mode", m.m_scheduling_mode));
            archive(::cereal::make_nvp("m_groups_weights", m.m_groups_weights));
            archive(::cereal::make_nvp("m_requested_credit_cir_burst_size", m.m_requested_credit_cir_burst_size));
            archive(::cereal::make_nvp("m_requested_credit_eir_or_pir_burst_size", m.m_requested_credit_eir_or_pir_burst_size));
            archive(::cereal::make_nvp("m_requested_credit_oq_pir_burst_size", m.m_requested_credit_oq_pir_burst_size));
            archive(::cereal::make_nvp("m_requested_transmit_oq_pir_burst_size", m.m_requested_transmit_oq_pir_burst_size));
            archive(::cereal::make_nvp("m_attached_vscs", m.m_attached_vscs));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_output_queue_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_sch_oqse_cfg", m.m_sch_oqse_cfg));
            archive(::cereal::make_nvp("m_sch_vsc_map_cfg", m.m_sch_vsc_map_cfg));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket", m.m_sch_vsc_token_bucket));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket_cfg", m.m_sch_vsc_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket_empty", m.m_sch_vsc_token_bucket_empty));
            archive(::cereal::make_nvp("m_oqse_shaper_configuration", m.m_oqse_shaper_configuration));
            archive(::cereal::make_nvp("m_oqse_id", m.m_oqse_id));
            archive(::cereal::make_nvp("m_scheduling_mode", m.m_scheduling_mode));
            archive(::cereal::make_nvp("m_groups_weights", m.m_groups_weights));
            archive(::cereal::make_nvp("m_requested_credit_cir_burst_size", m.m_requested_credit_cir_burst_size));
            archive(::cereal::make_nvp("m_requested_credit_eir_or_pir_burst_size", m.m_requested_credit_eir_or_pir_burst_size));
            archive(::cereal::make_nvp("m_requested_credit_oq_pir_burst_size", m.m_requested_credit_oq_pir_burst_size));
            archive(::cereal::make_nvp("m_requested_transmit_oq_pir_burst_size", m.m_requested_transmit_oq_pir_burst_size));
            archive(::cereal::make_nvp("m_attached_vscs", m.m_attached_vscs));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_output_queue_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_output_queue_scheduler>(&m));
    serializer_class<silicon_one::la_output_queue_scheduler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_output_queue_scheduler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_output_queue_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_output_queue_scheduler>(&m));
    serializer_class<silicon_one::la_output_queue_scheduler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_output_queue_scheduler_impl&);



template<>
class serializer_class<silicon_one::la_system_port_scheduler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_system_port_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_sch_tpse_general_configuration", m.m_sch_tpse_general_configuration));
            archive(::cereal::make_nvp("m_sch_tpse_oqpg_mapping_configuration", m.m_sch_tpse_oqpg_mapping_configuration));
            archive(::cereal::make_nvp("m_sch_tpse_cir_shaper_update_cfg", m.m_sch_tpse_cir_shaper_update_cfg));
            archive(::cereal::make_nvp("m_sch_tpse_pir_shaper_update_cfg", m.m_sch_tpse_pir_shaper_update_cfg));
            archive(::cereal::make_nvp("m_sch_oqpg_cir_token_bucket", m.m_sch_oqpg_cir_token_bucket));
            archive(::cereal::make_nvp("m_sch_oqpg_cir_token_bucket_cfg", m.m_sch_oqpg_cir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oq_pir_token_bucket", m.m_sch_oq_pir_token_bucket));
            archive(::cereal::make_nvp("m_sch_oq_pir_token_bucket_cfg", m.m_sch_oq_pir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_tpse_wfq_cfg", m.m_sch_tpse_wfq_cfg));
            archive(::cereal::make_nvp("m_sp_sch_id", m.m_sp_sch_id));
            archive(::cereal::make_nvp("m_logical_port_enabled", m.m_logical_port_enabled));
            archive(::cereal::make_nvp("m_port_speed", m.m_port_speed));
            archive(::cereal::make_nvp("m_requested_credit_oqpg_cir_burst_size", m.m_requested_credit_oqpg_cir_burst_size));
            archive(::cereal::make_nvp("m_requested_transmit_oqpg_cir_burst_size", m.m_requested_transmit_oqpg_cir_burst_size));
            archive(::cereal::make_nvp("m_pg_weights", m.m_pg_weights));
            archive(::cereal::make_nvp("m_uc_mc_weights", m.m_uc_mc_weights));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_intf_sch", m.m_intf_sch));
            archive(::cereal::make_nvp("m_oq_sch_vec", m.m_oq_sch_vec));
            archive(::cereal::make_nvp("m_lp_sch", m.m_lp_sch));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_system_port_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_sch_tpse_general_configuration", m.m_sch_tpse_general_configuration));
            archive(::cereal::make_nvp("m_sch_tpse_oqpg_mapping_configuration", m.m_sch_tpse_oqpg_mapping_configuration));
            archive(::cereal::make_nvp("m_sch_tpse_cir_shaper_update_cfg", m.m_sch_tpse_cir_shaper_update_cfg));
            archive(::cereal::make_nvp("m_sch_tpse_pir_shaper_update_cfg", m.m_sch_tpse_pir_shaper_update_cfg));
            archive(::cereal::make_nvp("m_sch_oqpg_cir_token_bucket", m.m_sch_oqpg_cir_token_bucket));
            archive(::cereal::make_nvp("m_sch_oqpg_cir_token_bucket_cfg", m.m_sch_oqpg_cir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oq_pir_token_bucket", m.m_sch_oq_pir_token_bucket));
            archive(::cereal::make_nvp("m_sch_oq_pir_token_bucket_cfg", m.m_sch_oq_pir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_tpse_wfq_cfg", m.m_sch_tpse_wfq_cfg));
            archive(::cereal::make_nvp("m_sp_sch_id", m.m_sp_sch_id));
            archive(::cereal::make_nvp("m_logical_port_enabled", m.m_logical_port_enabled));
            archive(::cereal::make_nvp("m_port_speed", m.m_port_speed));
            archive(::cereal::make_nvp("m_requested_credit_oqpg_cir_burst_size", m.m_requested_credit_oqpg_cir_burst_size));
            archive(::cereal::make_nvp("m_requested_transmit_oqpg_cir_burst_size", m.m_requested_transmit_oqpg_cir_burst_size));
            archive(::cereal::make_nvp("m_pg_weights", m.m_pg_weights));
            archive(::cereal::make_nvp("m_uc_mc_weights", m.m_uc_mc_weights));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_intf_sch", m.m_intf_sch));
            archive(::cereal::make_nvp("m_oq_sch_vec", m.m_oq_sch_vec));
            archive(::cereal::make_nvp("m_lp_sch", m.m_lp_sch));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_system_port_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_system_port_scheduler>(&m));
    serializer_class<silicon_one::la_system_port_scheduler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_system_port_scheduler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_system_port_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_system_port_scheduler>(&m));
    serializer_class<silicon_one::la_system_port_scheduler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_system_port_scheduler_impl&);



template<>
class serializer_class<silicon_one::la_voq_set_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_voq_set_impl& m) {
            archive(::cereal::make_nvp("m_base_vsc_vec", m.m_base_vsc_vec));
            archive(::cereal::make_nvp("m_per_voq_index_state", m.m_per_voq_index_state));
            archive(::cereal::make_nvp("m_indx_is_during_flush_process", m.m_indx_is_during_flush_process));
            archive(::cereal::make_nvp("m_voq_state", m.m_voq_state));
            archive(::cereal::make_nvp("m_is_fabric_high_priority", m.m_is_fabric_high_priority));
            archive(::cereal::make_nvp("m_force_local_voq", m.m_force_local_voq));
            archive(::cereal::make_nvp("m_is_during_flush_process", m.m_is_during_flush_process));
            archive(::cereal::make_nvp("m_voq_redirected", m.m_voq_redirected));
            archive(::cereal::make_nvp("m_voq_flush_orig_mappings", m.m_voq_flush_orig_mappings));
            archive(::cereal::make_nvp("m_flush_counters", m.m_flush_counters));
            archive(::cereal::make_nvp("m_cgm_profiles", m.m_cgm_profiles));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_voq_set_impl& m) {
            archive(::cereal::make_nvp("m_base_vsc_vec", m.m_base_vsc_vec));
            archive(::cereal::make_nvp("m_per_voq_index_state", m.m_per_voq_index_state));
            archive(::cereal::make_nvp("m_indx_is_during_flush_process", m.m_indx_is_during_flush_process));
            archive(::cereal::make_nvp("m_voq_state", m.m_voq_state));
            archive(::cereal::make_nvp("m_is_fabric_high_priority", m.m_is_fabric_high_priority));
            archive(::cereal::make_nvp("m_force_local_voq", m.m_force_local_voq));
            archive(::cereal::make_nvp("m_is_during_flush_process", m.m_is_during_flush_process));
            archive(::cereal::make_nvp("m_voq_redirected", m.m_voq_redirected));
            archive(::cereal::make_nvp("m_voq_flush_orig_mappings", m.m_voq_flush_orig_mappings));
            archive(::cereal::make_nvp("m_flush_counters", m.m_flush_counters));
            archive(::cereal::make_nvp("m_cgm_profiles", m.m_cgm_profiles));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_voq_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_set_base>(&m));
    serializer_class<silicon_one::la_voq_set_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_voq_set_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_voq_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_set_base>(&m));
    serializer_class<silicon_one::la_voq_set_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_voq_set_impl&);



template<>
class serializer_class<silicon_one::la_voq_set_impl::context_hw_id> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_voq_set_impl::context_hw_id& m) {
            archive(::cereal::make_nvp("id", m.id));
            archive(::cereal::make_nvp("line", m.line));
            archive(::cereal::make_nvp("bit", m.bit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_voq_set_impl::context_hw_id& m) {
            archive(::cereal::make_nvp("id", m.id));
            archive(::cereal::make_nvp("line", m.line));
            archive(::cereal::make_nvp("bit", m.bit));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_voq_set_impl::context_hw_id& m)
{
    serializer_class<silicon_one::la_voq_set_impl::context_hw_id>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_voq_set_impl::context_hw_id&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_voq_set_impl::context_hw_id& m)
{
    serializer_class<silicon_one::la_voq_set_impl::context_hw_id>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_voq_set_impl::context_hw_id&);



template<>
class serializer_class<silicon_one::restricted_voq_set_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::restricted_voq_set_impl& m) {
            archive(::cereal::make_nvp("m_cgm_profile_ids", m.m_cgm_profile_ids));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::restricted_voq_set_impl& m) {
            archive(::cereal::make_nvp("m_cgm_profile_ids", m.m_cgm_profile_ids));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::restricted_voq_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_set_impl>(&m));
    serializer_class<silicon_one::restricted_voq_set_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::restricted_voq_set_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::restricted_voq_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_voq_set_impl>(&m));
    serializer_class<silicon_one::restricted_voq_set_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::restricted_voq_set_impl&);



template<>
class serializer_class<silicon_one::tm_utils> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::tm_utils& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::tm_utils& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::tm_utils& m)
{
    serializer_class<silicon_one::tm_utils>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::tm_utils&);

template <class Archive>
void
load(Archive& archive, silicon_one::tm_utils& m)
{
    serializer_class<silicon_one::tm_utils>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::tm_utils&);



template<>
class serializer_class<silicon_one::tm_utils::token_bucket_ratio_cfg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::tm_utils::token_bucket_ratio_cfg_t& m) {
            archive(::cereal::make_nvp("flat", m.flat));
            archive(::cereal::make_nvp("fields", m.fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::tm_utils::token_bucket_ratio_cfg_t& m) {
            archive(::cereal::make_nvp("flat", m.flat));
            archive(::cereal::make_nvp("fields", m.fields));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::tm_utils::token_bucket_ratio_cfg_t& m)
{
    serializer_class<silicon_one::tm_utils::token_bucket_ratio_cfg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::tm_utils::token_bucket_ratio_cfg_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::tm_utils::token_bucket_ratio_cfg_t& m)
{
    serializer_class<silicon_one::tm_utils::token_bucket_ratio_cfg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::tm_utils::token_bucket_ratio_cfg_t&);



template<>
class serializer_class<silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s& m) {
        uint32_t m_mantissa = m.mantissa;
        uint32_t m_exponent = m.exponent;
            archive(::cereal::make_nvp("mantissa", m_mantissa));
            archive(::cereal::make_nvp("exponent", m_exponent));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s& m) {
        uint32_t m_mantissa;
        uint32_t m_exponent;
            archive(::cereal::make_nvp("mantissa", m_mantissa));
            archive(::cereal::make_nvp("exponent", m_exponent));
        m.mantissa = m_mantissa;
        m.exponent = m_exponent;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s& m)
{
    serializer_class<silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s& m)
{
    serializer_class<silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::tm_utils::token_bucket_ratio_cfg_t::fields_s&);



template<>
class serializer_class<silicon_one::la_rx_cgm_sq_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_rx_cgm_sq_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_profile_id", m.m_profile_id));
            archive(::cereal::make_nvp("m_is_default", m.m_is_default));
            archive(::cereal::make_nvp("m_thresholds", m.m_thresholds));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_rx_cgm_policy_map", m.m_rx_cgm_policy_map));
            archive(::cereal::make_nvp("m_hr_timer_or_threshold_value", m.m_hr_timer_or_threshold_value));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_rx_cgm_sq_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_profile_id", m.m_profile_id));
            archive(::cereal::make_nvp("m_is_default", m.m_is_default));
            archive(::cereal::make_nvp("m_thresholds", m.m_thresholds));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_rx_cgm_policy_map", m.m_rx_cgm_policy_map));
            archive(::cereal::make_nvp("m_hr_timer_or_threshold_value", m.m_hr_timer_or_threshold_value));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_rx_cgm_sq_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_rx_cgm_sq_profile>(&m));
    serializer_class<silicon_one::la_rx_cgm_sq_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_rx_cgm_sq_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_rx_cgm_sq_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_rx_cgm_sq_profile>(&m));
    serializer_class<silicon_one::la_rx_cgm_sq_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_rx_cgm_sq_profile_impl&);



template<>
class serializer_class<silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op& m)
{
    serializer_class<silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op& m)
{
    serializer_class<silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_rx_cgm_sq_profile_impl::policy_less_op&);



template<>
class serializer_class<silicon_one::la_rx_cgm_sq_profile_impl::pfc_action> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_rx_cgm_sq_profile_impl::pfc_action& m) {
            archive(::cereal::make_nvp("flow_control", m.flow_control));
            archive(::cereal::make_nvp("drop_yellow", m.drop_yellow));
            archive(::cereal::make_nvp("drop_green", m.drop_green));
            archive(::cereal::make_nvp("fc_trig", m.fc_trig));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_rx_cgm_sq_profile_impl::pfc_action& m) {
            archive(::cereal::make_nvp("flow_control", m.flow_control));
            archive(::cereal::make_nvp("drop_yellow", m.drop_yellow));
            archive(::cereal::make_nvp("drop_green", m.drop_green));
            archive(::cereal::make_nvp("fc_trig", m.fc_trig));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_rx_cgm_sq_profile_impl::pfc_action& m)
{
    serializer_class<silicon_one::la_rx_cgm_sq_profile_impl::pfc_action>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_rx_cgm_sq_profile_impl::pfc_action&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_rx_cgm_sq_profile_impl::pfc_action& m)
{
    serializer_class<silicon_one::la_rx_cgm_sq_profile_impl::pfc_action>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_rx_cgm_sq_profile_impl::pfc_action&);



template<>
class serializer_class<silicon_one::voq_cgm_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::voq_cgm_handler& m) {
            archive(::cereal::make_nvp("m_evicted_buffers_default_behavior", m.m_evicted_buffers_default_behavior));
            archive(::cereal::make_nvp("m_sms_voqs_age_time_ns", m.m_sms_voqs_age_time_ns));
            archive(::cereal::make_nvp("ecn_level_prob_map", m.ecn_level_prob_map));
            archive(::cereal::make_nvp("cgm_ecn_num_levels", m.cgm_ecn_num_levels));
            archive(::cereal::make_nvp("cgm_ecn_num_probability", m.cgm_ecn_num_probability));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::voq_cgm_handler& m) {
            archive(::cereal::make_nvp("m_evicted_buffers_default_behavior", m.m_evicted_buffers_default_behavior));
            archive(::cereal::make_nvp("m_sms_voqs_age_time_ns", m.m_sms_voqs_age_time_ns));
            archive(::cereal::make_nvp("ecn_level_prob_map", m.ecn_level_prob_map));
            archive(::cereal::make_nvp("cgm_ecn_num_levels", m.cgm_ecn_num_levels));
            archive(::cereal::make_nvp("cgm_ecn_num_probability", m.cgm_ecn_num_probability));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::voq_cgm_handler& m)
{
    serializer_class<silicon_one::voq_cgm_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::voq_cgm_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::voq_cgm_handler& m)
{
    serializer_class<silicon_one::voq_cgm_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::voq_cgm_handler&);



template<>
class serializer_class<silicon_one::ifg_use_count> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_use_count& m) {
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_use_count& m) {
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_use_count& m)
{
    serializer_class<silicon_one::ifg_use_count>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_use_count&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_use_count& m)
{
    serializer_class<silicon_one::ifg_use_count>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_use_count&);



template<>
class serializer_class<silicon_one::ipv4_sip_index_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_sip_index_manager& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_sip_index_manager& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_sip_index_manager& m)
{
    serializer_class<silicon_one::ipv4_sip_index_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_sip_index_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_sip_index_manager& m)
{
    serializer_class<silicon_one::ipv4_sip_index_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_sip_index_manager&);



template<>
class serializer_class<silicon_one::ipv4_tunnel_ep_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager& m) {
            archive(::cereal::make_nvp("m_ipv4_tunnel_ep_map", m.m_ipv4_tunnel_ep_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager& m) {
            archive(::cereal::make_nvp("m_ipv4_tunnel_ep_map", m.m_ipv4_tunnel_ep_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_tunnel_ep_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_tunnel_ep_manager&);



template<>
class serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("ipv4_prefix", m.ipv4_prefix));
            archive(::cereal::make_nvp("l4_protocol_sel", m.l4_protocol_sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("ipv4_prefix", m.ipv4_prefix));
            archive(::cereal::make_nvp("l4_protocol_sel", m.l4_protocol_sel));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s&);



template<>
class serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m) {
            archive(::cereal::make_nvp("loc", m.loc));
            archive(::cereal::make_nvp("ref_cnt", m.ref_cnt));
            archive(::cereal::make_nvp("sip_index", m.sip_index));
            archive(::cereal::make_nvp("sip_index_or_local_slp_id", m.sip_index_or_local_slp_id));
            archive(::cereal::make_nvp("db", m.db));
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m) {
            archive(::cereal::make_nvp("loc", m.loc));
            archive(::cereal::make_nvp("ref_cnt", m.ref_cnt));
            archive(::cereal::make_nvp("sip_index", m.sip_index));
            archive(::cereal::make_nvp("sip_index_or_local_slp_id", m.sip_index_or_local_slp_id));
            archive(::cereal::make_nvp("db", m.db));
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t&);



template<>
class serializer_class<silicon_one::la_ac_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ac_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_need_fallback", m.m_need_fallback));
            archive(::cereal::make_nvp("m_selector_type_pvlan_enabled", m.m_selector_type_pvlan_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ac_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_need_fallback", m.m_need_fallback));
            archive(::cereal::make_nvp("m_selector_type_pvlan_enabled", m.m_selector_type_pvlan_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ac_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ac_profile>(&m));
    serializer_class<silicon_one::la_ac_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ac_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ac_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ac_profile>(&m));
    serializer_class<silicon_one::la_ac_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ac_profile_impl&);



template<>
class serializer_class<silicon_one::la_acl_egress_sec_ipv4> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv4& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_egress_sec_ipv4& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv4& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv4>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_egress_sec_ipv4&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_egress_sec_ipv4& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv4>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_egress_sec_ipv4&);



template<>
class serializer_class<silicon_one::la_acl_egress_sec_ipv6> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv6& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_egress_sec_ipv6& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv6& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv6>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_egress_sec_ipv6&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_egress_sec_ipv6& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv6>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_egress_sec_ipv6&);



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



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_logical_port_scheduler_impl var0;
    ar(var0);
    silicon_one::la_output_queue_scheduler_impl var1;
    ar(var1);
    silicon_one::la_system_port_scheduler_impl var2;
    ar(var2);
    silicon_one::la_voq_set_impl var3;
    ar(var3);
    silicon_one::restricted_voq_set_impl var4;
    ar(var4);
    silicon_one::la_rx_cgm_sq_profile_impl var5;
    ar(var5);
    silicon_one::la_ac_profile_impl var6;
    ar(var6);
    silicon_one::la_acl_egress_sec_ipv4 var7;
    ar(var7);
    silicon_one::la_acl_egress_sec_ipv6 var8;
    ar(var8);
    silicon_one::la_acl_impl var9;
    ar(var9);
    silicon_one::la_acl_scaled_impl var10;
    ar(var10);
    silicon_one::la_asbr_lsp_impl var11;
    ar(var11);
    silicon_one::la_fabric_multicast_group_impl var12;
    ar(var12);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_logical_port_scheduler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_output_queue_scheduler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_system_port_scheduler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_voq_set_impl);
CEREAL_REGISTER_TYPE(silicon_one::restricted_voq_set_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_rx_cgm_sq_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ac_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_egress_sec_ipv4);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_egress_sec_ipv6);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_scaled_delegate);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_scaled_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_asbr_lsp_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_fabric_multicast_group_impl);

#pragma GCC diagnostic pop

