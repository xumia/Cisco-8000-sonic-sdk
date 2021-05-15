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

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const la_vlan_tag_tci_t&);
template <class Archive> void load(Archive&, la_vlan_tag_tci_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_classify_ip_tunnels_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_termination_classify_ip_tunnels_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_classify_ip_tunnels_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_termination_classify_ip_tunnels_table_value_t&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

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

template <class Archive> void save(Archive&, const silicon_one::la_hbm_handler&);
template <class Archive> void load(Archive&, silicon_one::la_hbm_handler&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_punt_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l2_punt_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_mirror_command&);
template <class Archive> void load(Archive&, silicon_one::la_mirror_command&);

template <class Archive> void save(Archive&, const silicon_one::la_npu_host_destination&);
template <class Archive> void load(Archive&, silicon_one::la_npu_host_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_npu_host_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_npu_host_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_output_queue_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_output_queue_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_pbts_destination_offset&);
template <class Archive> void load(Archive&, silicon_one::la_pbts_destination_offset&);

template <class Archive> void save(Archive&, const silicon_one::la_pbts_map_profile&);
template <class Archive> void load(Archive&, silicon_one::la_pbts_map_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_punt_destination&);
template <class Archive> void load(Archive&, silicon_one::la_punt_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_punt_inject_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_punt_inject_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_remote_device&);
template <class Archive> void load(Archive&, silicon_one::la_remote_device&);

template <class Archive> void save(Archive&, const silicon_one::la_remote_port&);
template <class Archive> void load(Archive&, silicon_one::la_remote_port&);

template <class Archive> void save(Archive&, const silicon_one::la_stack_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_stack_port_base&);

template <class Archive> void save(Archive&, const silicon_one::mac_pool_port::fec_engine_config_data&);
template <class Archive> void load(Archive&, silicon_one::mac_pool_port::fec_engine_config_data&);

template <class Archive> void save(Archive&, const silicon_one::mac_pool_port::sm_state_transition&);
template <class Archive> void load(Archive&, silicon_one::mac_pool_port::sm_state_transition&);

template <class Archive> void save(Archive&, const silicon_one::pacific_mac_pool&);
template <class Archive> void load(Archive&, silicon_one::pacific_mac_pool&);

template <class Archive> void save(Archive&, const silicon_one::resource_monitor&);
template <class Archive> void load(Archive&, silicon_one::resource_monitor&);

template <class Archive> void save(Archive&, const silicon_one::serdes_handler&);
template <class Archive> void load(Archive&, silicon_one::serdes_handler&);

template <class Archive> void save(Archive&, const std::chrono::_V2::steady_clock&);
template <class Archive> void load(Archive&, std::chrono::_V2::steady_clock&);

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
class serializer_class<silicon_one::la_device_impl::mc_links_key_hash> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::mc_links_key_hash& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::mc_links_key_hash& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::mc_links_key_hash& m)
{
    serializer_class<silicon_one::la_device_impl::mc_links_key_hash>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::mc_links_key_hash&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::mc_links_key_hash& m)
{
    serializer_class<silicon_one::la_device_impl::mc_links_key_hash>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::mc_links_key_hash&);



template<>
class serializer_class<silicon_one::la_device_impl::mc_links_key_equal> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::mc_links_key_equal& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::mc_links_key_equal& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::mc_links_key_equal& m)
{
    serializer_class<silicon_one::la_device_impl::mc_links_key_equal>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::mc_links_key_equal&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::mc_links_key_equal& m)
{
    serializer_class<silicon_one::la_device_impl::mc_links_key_equal>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::mc_links_key_equal&);



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
            archive(::cereal::make_nvp("m_is_lc_56_fabric_port", m.m_is_lc_56_fabric_port));
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
            archive(::cereal::make_nvp("m_is_lc_56_fabric_port", m.m_is_lc_56_fabric_port));
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
class serializer_class<silicon_one::la_hbm_handler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_hbm_handler_impl& m) {
            archive(::cereal::make_nvp("m_device_model_id", m.m_device_model_id));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_hbm_rate", m.m_hbm_rate));
            archive(::cereal::make_nvp("m_pll_div", m.m_pll_div));
            archive(::cereal::make_nvp("m_hbm_read_cycles", m.m_hbm_read_cycles));
            archive(::cereal::make_nvp("m_hbm_write_cycles", m.m_hbm_write_cycles));
            archive(::cereal::make_nvp("m_hbm_min_move_to_read", m.m_hbm_min_move_to_read));
            archive(::cereal::make_nvp("m_hbm_lpm_favor_mode", m.m_hbm_lpm_favor_mode));
            archive(::cereal::make_nvp("m_hbm_move_to_read_on_empty", m.m_hbm_move_to_read_on_empty));
            archive(::cereal::make_nvp("m_hbm_move_to_write_on_empty", m.m_hbm_move_to_write_on_empty));
            archive(::cereal::make_nvp("m_hbm_phy_t_rdlat_offset", m.m_hbm_phy_t_rdlat_offset));
            archive(::cereal::make_nvp("m_rate_limit", m.m_rate_limit));
            archive(::cereal::make_nvp("m_duration", m.m_duration));
            archive(::cereal::make_nvp("m_measured_rate", m.m_measured_rate));
            archive(::cereal::make_nvp("m_is_done", m.m_is_done));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_hbm_handler_impl& m) {
            archive(::cereal::make_nvp("m_device_model_id", m.m_device_model_id));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device_revision", m.m_device_revision));
            archive(::cereal::make_nvp("m_hbm_rate", m.m_hbm_rate));
            archive(::cereal::make_nvp("m_pll_div", m.m_pll_div));
            archive(::cereal::make_nvp("m_hbm_read_cycles", m.m_hbm_read_cycles));
            archive(::cereal::make_nvp("m_hbm_write_cycles", m.m_hbm_write_cycles));
            archive(::cereal::make_nvp("m_hbm_min_move_to_read", m.m_hbm_min_move_to_read));
            archive(::cereal::make_nvp("m_hbm_lpm_favor_mode", m.m_hbm_lpm_favor_mode));
            archive(::cereal::make_nvp("m_hbm_move_to_read_on_empty", m.m_hbm_move_to_read_on_empty));
            archive(::cereal::make_nvp("m_hbm_move_to_write_on_empty", m.m_hbm_move_to_write_on_empty));
            archive(::cereal::make_nvp("m_hbm_phy_t_rdlat_offset", m.m_hbm_phy_t_rdlat_offset));
            archive(::cereal::make_nvp("m_rate_limit", m.m_rate_limit));
            archive(::cereal::make_nvp("m_duration", m.m_duration));
            archive(::cereal::make_nvp("m_measured_rate", m.m_measured_rate));
            archive(::cereal::make_nvp("m_is_done", m.m_is_done));
            archive(::cereal::make_nvp("m_device", m.m_device));
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
class serializer_class<silicon_one::la_l2_punt_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l2_punt_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_vlan_tag", m.m_vlan_tag));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_pi_port", m.m_pi_port));
            archive(::cereal::make_nvp("m_stack_port", m.m_stack_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l2_punt_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_vlan_tag", m.m_vlan_tag));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_pi_port", m.m_pi_port));
            archive(::cereal::make_nvp("m_stack_port", m.m_stack_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l2_punt_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l2_punt_destination>(&m));
    serializer_class<silicon_one::la_l2_punt_destination_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l2_punt_destination_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l2_punt_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l2_punt_destination>(&m));
    serializer_class<silicon_one::la_l2_punt_destination_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l2_punt_destination_impl&);



template<>
class serializer_class<silicon_one::la_npu_host_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_npu_host_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_npu_host_port", m.m_npu_host_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_npu_host_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_npu_host_port", m.m_npu_host_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_npu_host_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_npu_host_destination>(&m));
    serializer_class<silicon_one::la_npu_host_destination_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_npu_host_destination_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_npu_host_destination_impl& m)
{
    archive(cereal::base_class<silicon_one::la_npu_host_destination>(&m));
    serializer_class<silicon_one::la_npu_host_destination_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_npu_host_destination_impl&);



template<>
class serializer_class<silicon_one::la_pbts_map_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_pbts_map_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_level", m.m_level));
            archive(::cereal::make_nvp("m_max_offset", m.m_max_offset));
            archive(::cereal::make_nvp("m_mapping", m.m_mapping));
            archive(::cereal::make_nvp("m_profile_id", m.m_profile_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_pbts_map_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_level", m.m_level));
            archive(::cereal::make_nvp("m_max_offset", m.m_max_offset));
            archive(::cereal::make_nvp("m_mapping", m.m_mapping));
            archive(::cereal::make_nvp("m_profile_id", m.m_profile_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_pbts_map_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_pbts_map_profile>(&m));
    serializer_class<silicon_one::la_pbts_map_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_pbts_map_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_pbts_map_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_pbts_map_profile>(&m));
    serializer_class<silicon_one::la_pbts_map_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_pbts_map_profile_impl&);



template<>
class serializer_class<silicon_one::la_remote_port_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_remote_port_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_remote_slice", m.m_remote_slice));
            archive(::cereal::make_nvp("m_remote_ifg", m.m_remote_ifg));
            archive(::cereal::make_nvp("m_remote_serdes_base", m.m_remote_serdes_base));
            archive(::cereal::make_nvp("m_remote_serdes_count", m.m_remote_serdes_count));
            archive(::cereal::make_nvp("m_remote_pif_base", m.m_remote_pif_base));
            archive(::cereal::make_nvp("m_remote_pif_count", m.m_remote_pif_count));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_remote_device", m.m_remote_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_remote_port_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_remote_slice", m.m_remote_slice));
            archive(::cereal::make_nvp("m_remote_ifg", m.m_remote_ifg));
            archive(::cereal::make_nvp("m_remote_serdes_base", m.m_remote_serdes_base));
            archive(::cereal::make_nvp("m_remote_serdes_count", m.m_remote_serdes_count));
            archive(::cereal::make_nvp("m_remote_pif_base", m.m_remote_pif_base));
            archive(::cereal::make_nvp("m_remote_pif_count", m.m_remote_pif_count));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_remote_device", m.m_remote_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_remote_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_remote_port>(&m));
    serializer_class<silicon_one::la_remote_port_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_remote_port_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_remote_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_remote_port>(&m));
    serializer_class<silicon_one::la_remote_port_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_remote_port_impl&);



template<>
class serializer_class<silicon_one::mac_pool2_port> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_pool2_port& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_pool2_port& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_pool2_port& m)
{
    archive(cereal::base_class<silicon_one::pacific_mac_pool>(&m));
    serializer_class<silicon_one::mac_pool2_port>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool2_port&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool2_port& m)
{
    archive(cereal::base_class<silicon_one::pacific_mac_pool>(&m));
    serializer_class<silicon_one::mac_pool2_port>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool2_port&);



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
    archive(cereal::base_class<silicon_one::pacific_mac_pool>(&m));
    serializer_class<silicon_one::mac_pool8_port>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool8_port&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool8_port& m)
{
    archive(cereal::base_class<silicon_one::pacific_mac_pool>(&m));
    serializer_class<silicon_one::mac_pool8_port>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool8_port&);



template<>
class serializer_class<silicon_one::mac_pool_port> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_pool_port& m) {
            archive(::cereal::make_nvp("m_fec_engine_config", m.m_fec_engine_config));
            archive(::cereal::make_nvp("m_serdes_debug_mode", m.m_serdes_debug_mode));
            archive(::cereal::make_nvp("m_serdes_tuning_mode", m.m_serdes_tuning_mode));
            archive(::cereal::make_nvp("m_serdes_continuous_tuning_enabled", m.m_serdes_continuous_tuning_enabled));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_fec_mode", m.m_fec_mode));
            archive(::cereal::make_nvp("m_fec_bypass", m.m_fec_bypass));
            archive(::cereal::make_nvp("m_rx_fc_mode", m.m_rx_fc_mode));
            archive(::cereal::make_nvp("m_tx_fc_mode", m.m_tx_fc_mode));
            archive(::cereal::make_nvp("m_rx_fc_term_mode", m.m_rx_fc_term_mode));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_port_state", m.m_port_state));
            archive(::cereal::make_nvp("m_serdes_speed", m.m_serdes_speed));
            archive(::cereal::make_nvp("m_serdes_speed_gbps", m.m_serdes_speed_gbps));
            archive(::cereal::make_nvp("m_mlp_mode", m.m_mlp_mode));
            archive(::cereal::make_nvp("m_mac_lanes_count", m.m_mac_lanes_count));
            archive(::cereal::make_nvp("m_mac_lanes_reserved", m.m_mac_lanes_reserved));
            archive(::cereal::make_nvp("m_pcs_lanes_per_mac_lane", m.m_pcs_lanes_per_mac_lane));
            archive(::cereal::make_nvp("m_mac_pool_index", m.m_mac_pool_index));
            archive(::cereal::make_nvp("m_mac_lane_index_in_mac_pool", m.m_mac_lane_index_in_mac_pool));
            archive(::cereal::make_nvp("m_mac_lane_index_in_ifgb", m.m_mac_lane_index_in_ifgb));
            archive(::cereal::make_nvp("m_serdes_index_in_mac_pool", m.m_serdes_index_in_mac_pool));
            archive(::cereal::make_nvp("m_loopback_mode", m.m_loopback_mode));
            archive(::cereal::make_nvp("m_link_management_enabled", m.m_link_management_enabled));
            archive(::cereal::make_nvp("m_pcs_test_mode", m.m_pcs_test_mode));
            archive(::cereal::make_nvp("m_pma_test_mode", m.m_pma_test_mode));
            archive(::cereal::make_nvp("m_port_slice_mode", m.m_port_slice_mode));
            archive(::cereal::make_nvp("m_pcs_stable_timestamp", m.m_pcs_stable_timestamp));
            archive(::cereal::make_nvp("m_ready_delayed_interrupts", m.m_ready_delayed_interrupts));
            archive(::cereal::make_nvp("m_serdes_rxpll_value_vec", m.m_serdes_rxpll_value_vec));
            archive(::cereal::make_nvp("m_serdes_rxpll2_value_vec", m.m_serdes_rxpll2_value_vec));
            archive(::cereal::make_nvp("m_serdes_lane_tx_test_mode", m.m_serdes_lane_tx_test_mode));
            archive(::cereal::make_nvp("m_serdes_lane_rx_test_mode", m.m_serdes_lane_rx_test_mode));
            archive(::cereal::make_nvp("m_tune_start_time", m.m_tune_start_time));
            archive(::cereal::make_nvp("m_tune_timeout_informed", m.m_tune_timeout_informed));
            archive(::cereal::make_nvp("m_tune_finish_time", m.m_tune_finish_time));
            archive(::cereal::make_nvp("m_link_training_start", m.m_link_training_start));
            archive(::cereal::make_nvp("m_pcs_lock_start_time", m.m_pcs_lock_start_time));
            archive(::cereal::make_nvp("m_pcs_stable_rx_deskew_window_start_time", m.m_pcs_stable_rx_deskew_window_start_time));
            archive(::cereal::make_nvp("m_pcal_stop_start_time", m.m_pcal_stop_start_time));
            archive(::cereal::make_nvp("m_link_up_timestamp", m.m_link_up_timestamp));
            archive(::cereal::make_nvp("m_pcs_stable_rx_deskew_failures", m.m_pcs_stable_rx_deskew_failures));
            archive(::cereal::make_nvp("m_tune_with_pcs_lock", m.m_tune_with_pcs_lock));
            archive(::cereal::make_nvp("m_tune_timeout", m.m_tune_timeout));
            archive(::cereal::make_nvp("m_cdr_lock_timeout", m.m_cdr_lock_timeout));
            archive(::cereal::make_nvp("m_pcs_lock_time", m.m_pcs_lock_time));
            archive(::cereal::make_nvp("m_tune_and_pcs_lock_iter", m.m_tune_and_pcs_lock_iter));
            archive(::cereal::make_nvp("m_bad_tunes", m.m_bad_tunes));
            archive(::cereal::make_nvp("m_enable_eid", m.m_enable_eid));
            archive(::cereal::make_nvp("m_dfe_eid", m.m_dfe_eid));
            archive(::cereal::make_nvp("m_ignore_long_tune", m.m_ignore_long_tune));
            archive(::cereal::make_nvp("m_check_ser_ber", m.m_check_ser_ber));
            archive(::cereal::make_nvp("m_serdes_post_anlt_tune_disable", m.m_serdes_post_anlt_tune_disable));
            archive(::cereal::make_nvp("m_pcal_stop_rx_disabled", m.m_pcal_stop_rx_disabled));
            archive(::cereal::make_nvp("m_is_an_enabled", m.m_is_an_enabled));
            archive(::cereal::make_nvp("m_state_histogram", m.m_state_histogram));
            archive(::cereal::make_nvp("m_serdes_handler", m.m_serdes_handler));
            archive(::cereal::make_nvp("m_sm_state_transition_queue", m.m_sm_state_transition_queue));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_pool_port& m) {
            archive(::cereal::make_nvp("m_fec_engine_config", m.m_fec_engine_config));
            archive(::cereal::make_nvp("m_serdes_debug_mode", m.m_serdes_debug_mode));
            archive(::cereal::make_nvp("m_serdes_tuning_mode", m.m_serdes_tuning_mode));
            archive(::cereal::make_nvp("m_serdes_continuous_tuning_enabled", m.m_serdes_continuous_tuning_enabled));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_fec_mode", m.m_fec_mode));
            archive(::cereal::make_nvp("m_fec_bypass", m.m_fec_bypass));
            archive(::cereal::make_nvp("m_rx_fc_mode", m.m_rx_fc_mode));
            archive(::cereal::make_nvp("m_tx_fc_mode", m.m_tx_fc_mode));
            archive(::cereal::make_nvp("m_rx_fc_term_mode", m.m_rx_fc_term_mode));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_port_state", m.m_port_state));
            archive(::cereal::make_nvp("m_serdes_speed", m.m_serdes_speed));
            archive(::cereal::make_nvp("m_serdes_speed_gbps", m.m_serdes_speed_gbps));
            archive(::cereal::make_nvp("m_mlp_mode", m.m_mlp_mode));
            archive(::cereal::make_nvp("m_mac_lanes_count", m.m_mac_lanes_count));
            archive(::cereal::make_nvp("m_mac_lanes_reserved", m.m_mac_lanes_reserved));
            archive(::cereal::make_nvp("m_pcs_lanes_per_mac_lane", m.m_pcs_lanes_per_mac_lane));
            archive(::cereal::make_nvp("m_mac_pool_index", m.m_mac_pool_index));
            archive(::cereal::make_nvp("m_mac_lane_index_in_mac_pool", m.m_mac_lane_index_in_mac_pool));
            archive(::cereal::make_nvp("m_mac_lane_index_in_ifgb", m.m_mac_lane_index_in_ifgb));
            archive(::cereal::make_nvp("m_serdes_index_in_mac_pool", m.m_serdes_index_in_mac_pool));
            archive(::cereal::make_nvp("m_loopback_mode", m.m_loopback_mode));
            archive(::cereal::make_nvp("m_link_management_enabled", m.m_link_management_enabled));
            archive(::cereal::make_nvp("m_pcs_test_mode", m.m_pcs_test_mode));
            archive(::cereal::make_nvp("m_pma_test_mode", m.m_pma_test_mode));
            archive(::cereal::make_nvp("m_port_slice_mode", m.m_port_slice_mode));
            archive(::cereal::make_nvp("m_pcs_stable_timestamp", m.m_pcs_stable_timestamp));
            archive(::cereal::make_nvp("m_ready_delayed_interrupts", m.m_ready_delayed_interrupts));
            archive(::cereal::make_nvp("m_serdes_rxpll_value_vec", m.m_serdes_rxpll_value_vec));
            archive(::cereal::make_nvp("m_serdes_rxpll2_value_vec", m.m_serdes_rxpll2_value_vec));
            archive(::cereal::make_nvp("m_serdes_lane_tx_test_mode", m.m_serdes_lane_tx_test_mode));
            archive(::cereal::make_nvp("m_serdes_lane_rx_test_mode", m.m_serdes_lane_rx_test_mode));
            archive(::cereal::make_nvp("m_tune_start_time", m.m_tune_start_time));
            archive(::cereal::make_nvp("m_tune_timeout_informed", m.m_tune_timeout_informed));
            archive(::cereal::make_nvp("m_tune_finish_time", m.m_tune_finish_time));
            archive(::cereal::make_nvp("m_link_training_start", m.m_link_training_start));
            archive(::cereal::make_nvp("m_pcs_lock_start_time", m.m_pcs_lock_start_time));
            archive(::cereal::make_nvp("m_pcs_stable_rx_deskew_window_start_time", m.m_pcs_stable_rx_deskew_window_start_time));
            archive(::cereal::make_nvp("m_pcal_stop_start_time", m.m_pcal_stop_start_time));
            archive(::cereal::make_nvp("m_link_up_timestamp", m.m_link_up_timestamp));
            archive(::cereal::make_nvp("m_pcs_stable_rx_deskew_failures", m.m_pcs_stable_rx_deskew_failures));
            archive(::cereal::make_nvp("m_tune_with_pcs_lock", m.m_tune_with_pcs_lock));
            archive(::cereal::make_nvp("m_tune_timeout", m.m_tune_timeout));
            archive(::cereal::make_nvp("m_cdr_lock_timeout", m.m_cdr_lock_timeout));
            archive(::cereal::make_nvp("m_pcs_lock_time", m.m_pcs_lock_time));
            archive(::cereal::make_nvp("m_tune_and_pcs_lock_iter", m.m_tune_and_pcs_lock_iter));
            archive(::cereal::make_nvp("m_bad_tunes", m.m_bad_tunes));
            archive(::cereal::make_nvp("m_enable_eid", m.m_enable_eid));
            archive(::cereal::make_nvp("m_dfe_eid", m.m_dfe_eid));
            archive(::cereal::make_nvp("m_ignore_long_tune", m.m_ignore_long_tune));
            archive(::cereal::make_nvp("m_check_ser_ber", m.m_check_ser_ber));
            archive(::cereal::make_nvp("m_serdes_post_anlt_tune_disable", m.m_serdes_post_anlt_tune_disable));
            archive(::cereal::make_nvp("m_pcal_stop_rx_disabled", m.m_pcal_stop_rx_disabled));
            archive(::cereal::make_nvp("m_is_an_enabled", m.m_is_an_enabled));
            archive(::cereal::make_nvp("m_state_histogram", m.m_state_histogram));
            archive(::cereal::make_nvp("m_serdes_handler", m.m_serdes_handler));
            archive(::cereal::make_nvp("m_sm_state_transition_queue", m.m_sm_state_transition_queue));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_pool_port& m)
{
    serializer_class<silicon_one::mac_pool_port>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool_port&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool_port& m)
{
    serializer_class<silicon_one::mac_pool_port>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool_port&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_fabric_port_impl var0;
    ar(var0);
    silicon_one::la_hbm_handler_impl var1;
    ar(var1);
    silicon_one::la_l2_punt_destination_impl var2;
    ar(var2);
    silicon_one::la_npu_host_destination_impl var3;
    ar(var3);
    silicon_one::la_pbts_map_profile_impl var4;
    ar(var4);
    silicon_one::la_remote_port_impl var5;
    ar(var5);
    silicon_one::mac_pool2_port var6;
    ar(var6);
    silicon_one::mac_pool8_port var7;
    ar(var7);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_fabric_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_hbm_handler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_l2_punt_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_npu_host_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_pbts_map_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_remote_port_impl);
CEREAL_REGISTER_TYPE(silicon_one::mac_pool2_port);
CEREAL_REGISTER_TYPE(silicon_one::mac_pool8_port);
CEREAL_REGISTER_TYPE(silicon_one::mac_pool_port);

#pragma GCC diagnostic pop

