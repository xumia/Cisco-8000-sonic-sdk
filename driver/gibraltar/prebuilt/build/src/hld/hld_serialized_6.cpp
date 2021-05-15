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

template <class Archive> void save(Archive&, const la_component_health_t&);
template <class Archive> void load(Archive&, la_component_health_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_classify_ip_tunnels_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_termination_classify_ip_tunnels_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_classify_ip_tunnels_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_termination_classify_ip_tunnels_table_value_t&);

template <class Archive> void save(Archive&, const silicon_one::apb&);
template <class Archive> void load(Archive&, silicon_one::apb&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::gibraltar_mac_pool&);
template <class Archive> void load(Archive&, silicon_one::gibraltar_mac_pool&);

template <class Archive> void save(Archive&, const silicon_one::gibraltar_tree&);
template <class Archive> void load(Archive&, silicon_one::gibraltar_tree&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_or_meter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_or_meter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_device::save_state_options&);
template <class Archive> void load(Archive&, silicon_one::la_device::save_state_options&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::oam_encap_info_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::oam_encap_info_t&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_port&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_port&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_port_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_port_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_flow_cache_handler&);
template <class Archive> void load(Archive&, silicon_one::la_flow_cache_handler&);

template <class Archive> void save(Archive&, const silicon_one::la_hbm_handler&);
template <class Archive> void load(Archive&, silicon_one::la_hbm_handler&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_output_queue_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_output_queue_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_punt_destination&);
template <class Archive> void load(Archive&, silicon_one::la_punt_destination&);

template <class Archive> void save(Archive&, const silicon_one::ll_device&);
template <class Archive> void load(Archive&, silicon_one::ll_device&);

template <class Archive> void save(Archive&, const silicon_one::lld_memory&);
template <class Archive> void load(Archive&, silicon_one::lld_memory&);

template <class Archive> void save(Archive&, const silicon_one::lld_register&);
template <class Archive> void load(Archive&, silicon_one::lld_register&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::resource_monitor&);
template <class Archive> void load(Archive&, silicon_one::resource_monitor&);

template <class Archive> void save(Archive&, const silicon_one::serdes_device_handler&);
template <class Archive> void load(Archive&, silicon_one::serdes_device_handler&);

template <class Archive> void save(Archive&, const silicon_one::serdes_handler&);
template <class Archive> void load(Archive&, silicon_one::serdes_handler&);

template <class Archive> void save(Archive&, const silicon_one::srm_serdes_handler::rx_sp9_state_transition&);
template <class Archive> void load(Archive&, silicon_one::srm_serdes_handler::rx_sp9_state_transition&);

template <class Archive> void save(Archive&, const silicon_one::srm_serdes_handler::tx_sp9_state_transition&);
template <class Archive> void load(Archive&, silicon_one::srm_serdes_handler::tx_sp9_state_transition&);

template<>
class serializer_class<silicon_one::la_device_impl::_index_generators::_slice> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice& m) {
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("oq_drain_counters", m.oq_drain_counters));
            archive(::cereal::make_nvp("my_ipv4_table_id", m.my_ipv4_table_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice& m) {
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("oq_drain_counters", m.oq_drain_counters));
            archive(::cereal::make_nvp("my_ipv4_table_id", m.my_ipv4_table_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::_index_generators::_slice&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::_index_generators::_slice&);



template<>
class serializer_class<silicon_one::la_device_impl::_index_generators::_slice_pair> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice_pair& m) {
            archive(::cereal::make_nvp("service_port_slps", m.service_port_slps));
            archive(::cereal::make_nvp("ingress_eth_db1_160_f0_acl_ids", m.ingress_eth_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_eth_db2_160_f0_acl_ids", m.ingress_eth_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_160_f0_acl_ids", m.ingress_ipv4_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_160_f0_acl_ids", m.ingress_ipv4_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_160_f0_acl_ids", m.ingress_ipv4_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_160_f0_acl_ids", m.ingress_ipv4_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_320_f0_acl_ids", m.ingress_ipv4_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_320_f0_acl_ids", m.ingress_ipv4_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_320_f0_acl_ids", m.ingress_ipv4_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_320_f0_acl_ids", m.ingress_ipv4_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_160_f0_acl_ids", m.ingress_ipv6_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_160_f0_acl_ids", m.ingress_ipv6_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_160_f0_acl_ids", m.ingress_ipv6_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_160_f0_acl_ids", m.ingress_ipv6_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_320_f0_acl_ids", m.ingress_ipv6_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_320_f0_acl_ids", m.ingress_ipv6_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_320_f0_acl_ids", m.ingress_ipv6_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_320_f0_acl_ids", m.ingress_ipv6_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("service_port_pwe", m.service_port_pwe));
            archive(::cereal::make_nvp("ingress_ipv4_mirror_acl_ids", m.ingress_ipv4_mirror_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_mirror_acl_ids", m.ingress_ipv6_mirror_acl_ids));
            archive(::cereal::make_nvp("egress_ipv4_acl_ids", m.egress_ipv4_acl_ids));
            archive(::cereal::make_nvp("egress_ipv6_acl_ids", m.egress_ipv6_acl_ids));
            archive(::cereal::make_nvp("ingress_qos_profiles", m.ingress_qos_profiles));
            archive(::cereal::make_nvp("egress_qos_profiles", m.egress_qos_profiles));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice_pair& m) {
            archive(::cereal::make_nvp("service_port_slps", m.service_port_slps));
            archive(::cereal::make_nvp("ingress_eth_db1_160_f0_acl_ids", m.ingress_eth_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_eth_db2_160_f0_acl_ids", m.ingress_eth_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_160_f0_acl_ids", m.ingress_ipv4_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_160_f0_acl_ids", m.ingress_ipv4_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_160_f0_acl_ids", m.ingress_ipv4_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_160_f0_acl_ids", m.ingress_ipv4_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_320_f0_acl_ids", m.ingress_ipv4_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_320_f0_acl_ids", m.ingress_ipv4_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_320_f0_acl_ids", m.ingress_ipv4_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_320_f0_acl_ids", m.ingress_ipv4_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_160_f0_acl_ids", m.ingress_ipv6_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_160_f0_acl_ids", m.ingress_ipv6_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_160_f0_acl_ids", m.ingress_ipv6_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_160_f0_acl_ids", m.ingress_ipv6_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_320_f0_acl_ids", m.ingress_ipv6_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_320_f0_acl_ids", m.ingress_ipv6_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_320_f0_acl_ids", m.ingress_ipv6_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_320_f0_acl_ids", m.ingress_ipv6_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("service_port_pwe", m.service_port_pwe));
            archive(::cereal::make_nvp("ingress_ipv4_mirror_acl_ids", m.ingress_ipv4_mirror_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_mirror_acl_ids", m.ingress_ipv6_mirror_acl_ids));
            archive(::cereal::make_nvp("egress_ipv4_acl_ids", m.egress_ipv4_acl_ids));
            archive(::cereal::make_nvp("egress_ipv6_acl_ids", m.egress_ipv6_acl_ids));
            archive(::cereal::make_nvp("ingress_qos_profiles", m.ingress_qos_profiles));
            archive(::cereal::make_nvp("egress_qos_profiles", m.egress_qos_profiles));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice_pair& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice_pair>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::_index_generators::_slice_pair&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice_pair& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice_pair>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::_index_generators::_slice_pair&);



template<>
class serializer_class<silicon_one::la_device_impl::device_property_val> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::device_property_val& m) {
            archive(::cereal::make_nvp("bool_val", m.bool_val));
            archive(::cereal::make_nvp("int_val", m.int_val));
            archive(::cereal::make_nvp("string_val", m.string_val));
            archive(::cereal::make_nvp("supported", m.supported));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::device_property_val& m) {
            archive(::cereal::make_nvp("bool_val", m.bool_val));
            archive(::cereal::make_nvp("int_val", m.int_val));
            archive(::cereal::make_nvp("string_val", m.string_val));
            archive(::cereal::make_nvp("supported", m.supported));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::device_property_val& m)
{
    serializer_class<silicon_one::la_device_impl::device_property_val>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::device_property_val&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::device_property_val& m)
{
    serializer_class<silicon_one::la_device_impl::device_property_val>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::device_property_val&);



template<>
class serializer_class<silicon_one::la_device_impl::ipv6_compressed_sip_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::ipv6_compressed_sip_desc& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("code", m.code));
            archive(::cereal::make_nvp("npl_table_entry", m.npl_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::ipv6_compressed_sip_desc& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("code", m.code));
            archive(::cereal::make_nvp("npl_table_entry", m.npl_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::ipv6_compressed_sip_desc& m)
{
    serializer_class<silicon_one::la_device_impl::ipv6_compressed_sip_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::ipv6_compressed_sip_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::ipv6_compressed_sip_desc& m)
{
    serializer_class<silicon_one::la_device_impl::ipv6_compressed_sip_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::ipv6_compressed_sip_desc&);



template<>
class serializer_class<silicon_one::la_device_impl::vsc_ownership_map_key> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::vsc_ownership_map_key& m) {
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("vsc", m.vsc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::vsc_ownership_map_key& m) {
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("vsc", m.vsc));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::vsc_ownership_map_key& m)
{
    serializer_class<silicon_one::la_device_impl::vsc_ownership_map_key>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::vsc_ownership_map_key&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::vsc_ownership_map_key& m)
{
    serializer_class<silicon_one::la_device_impl::vsc_ownership_map_key>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::vsc_ownership_map_key&);



template<>
class serializer_class<silicon_one::la_device_impl::vsc_ownership_map_val> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::vsc_ownership_map_val& m) {
            archive(::cereal::make_nvp("device_id", m.device_id));
            archive(::cereal::make_nvp("oqs", m.oqs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::vsc_ownership_map_val& m) {
            archive(::cereal::make_nvp("device_id", m.device_id));
            archive(::cereal::make_nvp("oqs", m.oqs));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::vsc_ownership_map_val& m)
{
    serializer_class<silicon_one::la_device_impl::vsc_ownership_map_val>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::vsc_ownership_map_val&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::vsc_ownership_map_val& m)
{
    serializer_class<silicon_one::la_device_impl::vsc_ownership_map_val>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::vsc_ownership_map_val&);



template<>
class serializer_class<silicon_one::la_device_impl::lc_56_fabric_port_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::lc_56_fabric_port_info& m) {
            archive(::cereal::make_nvp("is_lc_56_fabric_port", m.is_lc_56_fabric_port));
            archive(::cereal::make_nvp("slice_id", m.slice_id));
            archive(::cereal::make_nvp("ifg_id", m.ifg_id));
            archive(::cereal::make_nvp("serdes_base_id", m.serdes_base_id));
            archive(::cereal::make_nvp("fabric_port_num", m.fabric_port_num));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::lc_56_fabric_port_info& m) {
            archive(::cereal::make_nvp("is_lc_56_fabric_port", m.is_lc_56_fabric_port));
            archive(::cereal::make_nvp("slice_id", m.slice_id));
            archive(::cereal::make_nvp("ifg_id", m.ifg_id));
            archive(::cereal::make_nvp("serdes_base_id", m.serdes_base_id));
            archive(::cereal::make_nvp("fabric_port_num", m.fabric_port_num));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::lc_56_fabric_port_info& m)
{
    serializer_class<silicon_one::la_device_impl::lc_56_fabric_port_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::lc_56_fabric_port_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::lc_56_fabric_port_info& m)
{
    serializer_class<silicon_one::la_device_impl::lc_56_fabric_port_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::lc_56_fabric_port_info&);



template<>
class serializer_class<silicon_one::la_device_impl::mc_allocated_mcid> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::mc_allocated_mcid& m) {
            archive(::cereal::make_nvp("in_use", m.in_use));
            archive(::cereal::make_nvp("mcid", m.mcid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::mc_allocated_mcid& m) {
            archive(::cereal::make_nvp("in_use", m.in_use));
            archive(::cereal::make_nvp("mcid", m.mcid));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::mc_allocated_mcid& m)
{
    serializer_class<silicon_one::la_device_impl::mc_allocated_mcid>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::mc_allocated_mcid&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::mc_allocated_mcid& m)
{
    serializer_class<silicon_one::la_device_impl::mc_allocated_mcid>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::mc_allocated_mcid&);



template<>
class serializer_class<silicon_one::la_device_impl::resource_monitors> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::resource_monitors& m) {
            archive(::cereal::make_nvp("next_hop_resource_monitor", m.next_hop_resource_monitor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::resource_monitors& m) {
            archive(::cereal::make_nvp("next_hop_resource_monitor", m.next_hop_resource_monitor));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::resource_monitors& m)
{
    serializer_class<silicon_one::la_device_impl::resource_monitors>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::resource_monitors&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::resource_monitors& m)
{
    serializer_class<silicon_one::la_device_impl::resource_monitors>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::resource_monitors&);



template<>
class serializer_class<silicon_one::la_device_impl::save_state_runtime> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::save_state_runtime& m) {
            archive(::cereal::make_nvp("period", m.period));
            archive(::cereal::make_nvp("param_initialized", m.param_initialized));
            archive(::cereal::make_nvp("options", m.options));
            archive(::cereal::make_nvp("file_name_prefix", m.file_name_prefix));
            archive(::cereal::make_nvp("old_file_names", m.old_file_names));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::save_state_runtime& m) {
            archive(::cereal::make_nvp("period", m.period));
            archive(::cereal::make_nvp("param_initialized", m.param_initialized));
            archive(::cereal::make_nvp("options", m.options));
            archive(::cereal::make_nvp("file_name_prefix", m.file_name_prefix));
            archive(::cereal::make_nvp("old_file_names", m.old_file_names));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::save_state_runtime& m)
{
    serializer_class<silicon_one::la_device_impl::save_state_runtime>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::save_state_runtime&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::save_state_runtime& m)
{
    serializer_class<silicon_one::la_device_impl::save_state_runtime>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::save_state_runtime&);



template<>
class serializer_class<silicon_one::la_device_impl::la_trap_config_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::la_trap_config_entry& m) {
            archive(::cereal::make_nvp("trap", m.trap));
            archive(::cereal::make_nvp("priority", m.priority));
            archive(::cereal::make_nvp("skip_inject_up_packets", m.skip_inject_up_packets));
            archive(::cereal::make_nvp("skip_p2p_packets", m.skip_p2p_packets));
            archive(::cereal::make_nvp("overwrite_phb", m.overwrite_phb));
            archive(::cereal::make_nvp("tc", m.tc));
            archive(::cereal::make_nvp("oam_encap", m.oam_encap));
            archive(::cereal::make_nvp("counter_or_meter", m.counter_or_meter));
            archive(::cereal::make_nvp("punt_dest", m.punt_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::la_trap_config_entry& m) {
            archive(::cereal::make_nvp("trap", m.trap));
            archive(::cereal::make_nvp("priority", m.priority));
            archive(::cereal::make_nvp("skip_inject_up_packets", m.skip_inject_up_packets));
            archive(::cereal::make_nvp("skip_p2p_packets", m.skip_p2p_packets));
            archive(::cereal::make_nvp("overwrite_phb", m.overwrite_phb));
            archive(::cereal::make_nvp("tc", m.tc));
            archive(::cereal::make_nvp("oam_encap", m.oam_encap));
            archive(::cereal::make_nvp("counter_or_meter", m.counter_or_meter));
            archive(::cereal::make_nvp("punt_dest", m.punt_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::la_trap_config_entry& m)
{
    serializer_class<silicon_one::la_device_impl::la_trap_config_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::la_trap_config_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::la_trap_config_entry& m)
{
    serializer_class<silicon_one::la_device_impl::la_trap_config_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::la_trap_config_entry&);



template<>
class serializer_class<silicon_one::la_device_impl::la_snoop_config_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::la_snoop_config_entry& m) {
            archive(::cereal::make_nvp("snoop", m.snoop));
            archive(::cereal::make_nvp("priority", m.priority));
            archive(::cereal::make_nvp("mirror_cmd", m.mirror_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::la_snoop_config_entry& m) {
            archive(::cereal::make_nvp("snoop", m.snoop));
            archive(::cereal::make_nvp("priority", m.priority));
            archive(::cereal::make_nvp("mirror_cmd", m.mirror_cmd));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::la_snoop_config_entry& m)
{
    serializer_class<silicon_one::la_device_impl::la_snoop_config_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::la_snoop_config_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::la_snoop_config_entry& m)
{
    serializer_class<silicon_one::la_device_impl::la_snoop_config_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::la_snoop_config_entry&);



template<>
class serializer_class<silicon_one::la_device_impl::native_voq_set_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::native_voq_set_desc& m) {
            archive(::cereal::make_nvp("dest_device", m.dest_device));
            archive(::cereal::make_nvp("dest_slice", m.dest_slice));
            archive(::cereal::make_nvp("dest_ifg", m.dest_ifg));
            archive(::cereal::make_nvp("base_vsc_vec", m.base_vsc_vec));
            archive(::cereal::make_nvp("is_busy", m.is_busy));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::native_voq_set_desc& m) {
            archive(::cereal::make_nvp("dest_device", m.dest_device));
            archive(::cereal::make_nvp("dest_slice", m.dest_slice));
            archive(::cereal::make_nvp("dest_ifg", m.dest_ifg));
            archive(::cereal::make_nvp("base_vsc_vec", m.base_vsc_vec));
            archive(::cereal::make_nvp("is_busy", m.is_busy));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::native_voq_set_desc& m)
{
    serializer_class<silicon_one::la_device_impl::native_voq_set_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::native_voq_set_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::native_voq_set_desc& m)
{
    serializer_class<silicon_one::la_device_impl::native_voq_set_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::native_voq_set_desc&);



template<>
class serializer_class<silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mask", m.mask));
            archive(::cereal::make_nvp("value", m.value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mask", m.mask));
            archive(::cereal::make_nvp("value", m.value));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t& m)
{
    serializer_class<silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t& m)
{
    serializer_class<silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::npl_l3_termination_classify_ip_tunnels_table_key_value_t&);



template<>
class serializer_class<silicon_one::la_device_impl::mldp_bud_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::mldp_bud_info& m) {
            archive(::cereal::make_nvp("recycle_mldp_bud_refcnt", m.recycle_mldp_bud_refcnt));
            archive(::cereal::make_nvp("mpls_mc_copy_id", m.mpls_mc_copy_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::mldp_bud_info& m) {
            archive(::cereal::make_nvp("recycle_mldp_bud_refcnt", m.recycle_mldp_bud_refcnt));
            archive(::cereal::make_nvp("mpls_mc_copy_id", m.mpls_mc_copy_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::mldp_bud_info& m)
{
    serializer_class<silicon_one::la_device_impl::mldp_bud_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::mldp_bud_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::mldp_bud_info& m)
{
    serializer_class<silicon_one::la_device_impl::mldp_bud_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::mldp_bud_info&);



template<>
class serializer_class<silicon_one::la_fabric_port_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_fabric_port_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base", m.m_serdes_base));
            archive(::cereal::make_nvp("m_pif_base", m.m_pif_base));
            archive(::cereal::make_nvp("m_peer_dev_id", m.m_peer_dev_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mac_port", m.m_mac_port));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_fabric_port_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base", m.m_serdes_base));
            archive(::cereal::make_nvp("m_pif_base", m.m_pif_base));
            archive(::cereal::make_nvp("m_peer_dev_id", m.m_peer_dev_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mac_port", m.m_mac_port));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_fabric_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_fabric_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_fabric_port_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_fabric_port_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_fabric_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_fabric_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_fabric_port_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_fabric_port_impl&);



template<>
class serializer_class<silicon_one::la_flow_cache_handler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_flow_cache_handler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_flow_cache_enabled", m.m_flow_cache_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_flow_cache_handler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_flow_cache_enabled", m.m_flow_cache_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_flow_cache_handler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_flow_cache_handler>(&m));
    serializer_class<silicon_one::la_flow_cache_handler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_flow_cache_handler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_flow_cache_handler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_flow_cache_handler>(&m));
    serializer_class<silicon_one::la_flow_cache_handler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_flow_cache_handler_impl&);



template<>
class serializer_class<silicon_one::la_hbm_handler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_hbm_handler_impl& m) {
            archive(::cereal::make_nvp("m_device_model_id", m.m_device_model_id));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gb_tree", m.m_gb_tree));
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_does_hbm_exist", m.m_does_hbm_exist));
            archive(::cereal::make_nvp("m_rate_limit", m.m_rate_limit));
            archive(::cereal::make_nvp("m_measured_rate", m.m_measured_rate));
            archive(::cereal::make_nvp("m_is_completed", m.m_is_completed));
            archive(::cereal::make_nvp("m_task_handle", m.m_task_handle));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_apb", m.m_apb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_hbm_handler_impl& m) {
            archive(::cereal::make_nvp("m_device_model_id", m.m_device_model_id));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gb_tree", m.m_gb_tree));
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_does_hbm_exist", m.m_does_hbm_exist));
            archive(::cereal::make_nvp("m_rate_limit", m.m_rate_limit));
            archive(::cereal::make_nvp("m_measured_rate", m.m_measured_rate));
            archive(::cereal::make_nvp("m_is_completed", m.m_is_completed));
            archive(::cereal::make_nvp("m_task_handle", m.m_task_handle));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_apb", m.m_apb));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_hbm_handler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_hbm_handler>(&m));
    serializer_class<silicon_one::la_hbm_handler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_hbm_handler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_hbm_handler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_hbm_handler>(&m));
    serializer_class<silicon_one::la_hbm_handler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_hbm_handler_impl&);



template<>
class serializer_class<silicon_one::mac_pool8_port> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_pool8_port& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_pool8_port& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_pool8_port& m)
{
    archive(cereal::base_class<silicon_one::gibraltar_mac_pool>(&m));
    serializer_class<silicon_one::mac_pool8_port>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool8_port&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool8_port& m)
{
    archive(cereal::base_class<silicon_one::gibraltar_mac_pool>(&m));
    serializer_class<silicon_one::mac_pool8_port>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool8_port&);



template<>
class serializer_class<silicon_one::npu_static_config> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_static_config& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_slice_config", m.m_slice_config));
            archive(::cereal::make_nvp("m_reg_vals", m.m_reg_vals));
            archive(::cereal::make_nvp("m_mem_vals", m.m_mem_vals));
            archive(::cereal::make_nvp("m_mem_line_vals", m.m_mem_line_vals));
            archive(::cereal::make_nvp("m_tcam_line_vals", m.m_tcam_line_vals));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_tree", m.m_tree));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_static_config& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_slice_config", m.m_slice_config));
            archive(::cereal::make_nvp("m_reg_vals", m.m_reg_vals));
            archive(::cereal::make_nvp("m_mem_vals", m.m_mem_vals));
            archive(::cereal::make_nvp("m_mem_line_vals", m.m_mem_line_vals));
            archive(::cereal::make_nvp("m_tcam_line_vals", m.m_tcam_line_vals));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_tree", m.m_tree));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_static_config& m)
{
    serializer_class<silicon_one::npu_static_config>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_static_config&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_static_config& m)
{
    serializer_class<silicon_one::npu_static_config>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_static_config&);



template<>
class serializer_class<silicon_one::npu_static_config::slice_config> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_static_config::slice_config& m) {
            archive(::cereal::make_nvp("slice_mode", m.slice_mode));
            archive(::cereal::make_nvp("sna_slice_mode", m.sna_slice_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_static_config::slice_config& m) {
            archive(::cereal::make_nvp("slice_mode", m.slice_mode));
            archive(::cereal::make_nvp("sna_slice_mode", m.sna_slice_mode));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_static_config::slice_config& m)
{
    serializer_class<silicon_one::npu_static_config::slice_config>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_static_config::slice_config&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_static_config::slice_config& m)
{
    serializer_class<silicon_one::npu_static_config::slice_config>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_static_config::slice_config&);



template<>
class serializer_class<silicon_one::srm_serdes_device_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::srm_serdes_device_handler& m) {
            archive(::cereal::make_nvp("m_fw_version_major", m.m_fw_version_major));
            archive(::cereal::make_nvp("m_fw_version_minor", m.m_fw_version_minor));
            archive(::cereal::make_nvp("m_fw_version_build", m.m_fw_version_build));
            archive(::cereal::make_nvp("m_handler_initilized", m.m_handler_initilized));
            archive(::cereal::make_nvp("m_die_health", m.m_die_health));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::srm_serdes_device_handler& m) {
            archive(::cereal::make_nvp("m_fw_version_major", m.m_fw_version_major));
            archive(::cereal::make_nvp("m_fw_version_minor", m.m_fw_version_minor));
            archive(::cereal::make_nvp("m_fw_version_build", m.m_fw_version_build));
            archive(::cereal::make_nvp("m_handler_initilized", m.m_handler_initilized));
            archive(::cereal::make_nvp("m_die_health", m.m_die_health));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::srm_serdes_device_handler& m)
{
    archive(cereal::base_class<silicon_one::serdes_device_handler>(&m));
    serializer_class<silicon_one::srm_serdes_device_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::srm_serdes_device_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::srm_serdes_device_handler& m)
{
    archive(cereal::base_class<silicon_one::serdes_device_handler>(&m));
    serializer_class<silicon_one::srm_serdes_device_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::srm_serdes_device_handler&);



template<>
class serializer_class<silicon_one::srm_serdes_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::srm_serdes_handler& m) {
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_serdes_speed", m.m_serdes_speed));
            archive(::cereal::make_nvp("m_serdes_slice_mode", m.m_serdes_slice_mode));
            archive(::cereal::make_nvp("m_serdes_lane_test_mode", m.m_serdes_lane_test_mode));
            archive(::cereal::make_nvp("m_loopback_mode", m.m_loopback_mode));
            archive(::cereal::make_nvp("m_serdes_speed_gbps", m.m_serdes_speed_gbps));
            archive(::cereal::make_nvp("m_debug_mode", m.m_debug_mode));
            archive(::cereal::make_nvp("m_die_set", m.m_die_set));
            archive(::cereal::make_nvp("m_die_pll_lock_time", m.m_die_pll_lock_time));
            archive(::cereal::make_nvp("m_is_initialized", m.m_is_initialized));
            archive(::cereal::make_nvp("m_serdes_param_vec", m.m_serdes_param_vec));
            archive(::cereal::make_nvp("m_bundle", m.save_m_bundle()));
            archive(::cereal::make_nvp("m_anlt_lane", m.m_anlt_lane));
            archive(::cereal::make_nvp("m_is_an_enabled", m.m_is_an_enabled));
            archive(::cereal::make_nvp("m_an_spec_cap", m.m_an_spec_cap));
            archive(::cereal::make_nvp("m_an_fec_request", m.m_an_fec_request));
            archive(::cereal::make_nvp("curr_an_status", m.curr_an_status));
            archive(::cereal::make_nvp("curr_tx_spare9_fsm_state", m.curr_tx_spare9_fsm_state));
            archive(::cereal::make_nvp("tx_spare9_histogram", m.tx_spare9_histogram));
            archive(::cereal::make_nvp("rx_spare9_histogram", m.rx_spare9_histogram));
            archive(::cereal::make_nvp("m_tx_sp9_state_transition_queue", m.m_tx_sp9_state_transition_queue));
            archive(::cereal::make_nvp("m_rx_sp9_state_transition_queue", m.m_rx_sp9_state_transition_queue));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_serdes_device_handler", m.m_serdes_device_handler));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::srm_serdes_handler& m) {
        std::array<unsigned char, 148> m_m_bundle;
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_serdes_speed", m.m_serdes_speed));
            archive(::cereal::make_nvp("m_serdes_slice_mode", m.m_serdes_slice_mode));
            archive(::cereal::make_nvp("m_serdes_lane_test_mode", m.m_serdes_lane_test_mode));
            archive(::cereal::make_nvp("m_loopback_mode", m.m_loopback_mode));
            archive(::cereal::make_nvp("m_serdes_speed_gbps", m.m_serdes_speed_gbps));
            archive(::cereal::make_nvp("m_debug_mode", m.m_debug_mode));
            archive(::cereal::make_nvp("m_die_set", m.m_die_set));
            archive(::cereal::make_nvp("m_die_pll_lock_time", m.m_die_pll_lock_time));
            archive(::cereal::make_nvp("m_is_initialized", m.m_is_initialized));
            archive(::cereal::make_nvp("m_serdes_param_vec", m.m_serdes_param_vec));
            archive(::cereal::make_nvp("m_bundle", m_m_bundle));
            archive(::cereal::make_nvp("m_anlt_lane", m.m_anlt_lane));
            archive(::cereal::make_nvp("m_is_an_enabled", m.m_is_an_enabled));
            archive(::cereal::make_nvp("m_an_spec_cap", m.m_an_spec_cap));
            archive(::cereal::make_nvp("m_an_fec_request", m.m_an_fec_request));
            archive(::cereal::make_nvp("curr_an_status", m.curr_an_status));
            archive(::cereal::make_nvp("curr_tx_spare9_fsm_state", m.curr_tx_spare9_fsm_state));
            archive(::cereal::make_nvp("tx_spare9_histogram", m.tx_spare9_histogram));
            archive(::cereal::make_nvp("rx_spare9_histogram", m.rx_spare9_histogram));
            archive(::cereal::make_nvp("m_tx_sp9_state_transition_queue", m.m_tx_sp9_state_transition_queue));
            archive(::cereal::make_nvp("m_rx_sp9_state_transition_queue", m.m_rx_sp9_state_transition_queue));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_serdes_device_handler", m.m_serdes_device_handler));
        m.load_m_bundle(m_m_bundle);
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::srm_serdes_handler& m)
{
    archive(cereal::base_class<silicon_one::serdes_handler>(&m));
    serializer_class<silicon_one::srm_serdes_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::srm_serdes_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::srm_serdes_handler& m)
{
    archive(cereal::base_class<silicon_one::serdes_handler>(&m));
    serializer_class<silicon_one::srm_serdes_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::srm_serdes_handler&);



template<>
class serializer_class<silicon_one::srm_serdes_handler::srm_pll_status> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::srm_serdes_handler::srm_pll_status& m) {
            archive(::cereal::make_nvp("top_init_req", m.top_init_req));
            archive(::cereal::make_nvp("top_init_ack", m.top_init_ack));
            archive(::cereal::make_nvp("pll_fsm_start", m.pll_fsm_start));
            archive(::cereal::make_nvp("pll_out_of_lock", m.pll_out_of_lock));
            archive(::cereal::make_nvp("pll_lock", m.pll_lock));
            archive(::cereal::make_nvp("baud_rate", m.baud_rate));
            archive(::cereal::make_nvp("baud_rate_nn", m.baud_rate_nn));
            archive(::cereal::make_nvp("baud_rate_mm", m.baud_rate_mm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::srm_serdes_handler::srm_pll_status& m) {
            archive(::cereal::make_nvp("top_init_req", m.top_init_req));
            archive(::cereal::make_nvp("top_init_ack", m.top_init_ack));
            archive(::cereal::make_nvp("pll_fsm_start", m.pll_fsm_start));
            archive(::cereal::make_nvp("pll_out_of_lock", m.pll_out_of_lock));
            archive(::cereal::make_nvp("pll_lock", m.pll_lock));
            archive(::cereal::make_nvp("baud_rate", m.baud_rate));
            archive(::cereal::make_nvp("baud_rate_nn", m.baud_rate_nn));
            archive(::cereal::make_nvp("baud_rate_mm", m.baud_rate_mm));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::srm_serdes_handler::srm_pll_status& m)
{
    serializer_class<silicon_one::srm_serdes_handler::srm_pll_status>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::srm_serdes_handler::srm_pll_status&);

template <class Archive>
void
load(Archive& archive, silicon_one::srm_serdes_handler::srm_pll_status& m)
{
    serializer_class<silicon_one::srm_serdes_handler::srm_pll_status>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::srm_serdes_handler::srm_pll_status&);



template<>
class serializer_class<silicon_one::srm_serdes_handler::serdes_param_setting> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::srm_serdes_handler::serdes_param_setting& m) {
            archive(::cereal::make_nvp("mode", m.mode));
            archive(::cereal::make_nvp("value", m.value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::srm_serdes_handler::serdes_param_setting& m) {
            archive(::cereal::make_nvp("mode", m.mode));
            archive(::cereal::make_nvp("value", m.value));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::srm_serdes_handler::serdes_param_setting& m)
{
    serializer_class<silicon_one::srm_serdes_handler::serdes_param_setting>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::srm_serdes_handler::serdes_param_setting&);

template <class Archive>
void
load(Archive& archive, silicon_one::srm_serdes_handler::serdes_param_setting& m)
{
    serializer_class<silicon_one::srm_serdes_handler::serdes_param_setting>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::srm_serdes_handler::serdes_param_setting&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_fabric_port_impl var0;
    ar(var0);
    silicon_one::la_flow_cache_handler_impl var1;
    ar(var1);
    silicon_one::la_hbm_handler_impl var2;
    ar(var2);
    silicon_one::mac_pool8_port var3;
    ar(var3);
    silicon_one::srm_serdes_device_handler var4;
    ar(var4);
    silicon_one::srm_serdes_handler var5;
    ar(var5);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_fabric_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_flow_cache_handler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_hbm_handler_impl);
CEREAL_REGISTER_TYPE(silicon_one::mac_pool8_port);
CEREAL_REGISTER_TYPE(silicon_one::srm_serdes_device_handler);
CEREAL_REGISTER_TYPE(silicon_one::srm_serdes_handler);

#pragma GCC diagnostic pop

