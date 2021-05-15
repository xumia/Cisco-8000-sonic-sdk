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

template <class Archive> void save(Archive&, const la_slice_ifg&);
template <class Archive> void load(Archive&, la_slice_ifg&);

template <class Archive> void save(Archive&, const npl_egress_qos_result_t&);
template <class Archive> void load(Archive&, npl_egress_qos_result_t&);

template <class Archive> void save(Archive&, const npl_ingress_ip_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_ip_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_delegate&);
template <class Archive> void load(Archive&, silicon_one::la_acl_delegate&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_impl&);
template <class Archive> void load(Archive&, silicon_one::la_acl_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set_impl&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_egress_qos_profile&);
template <class Archive> void load(Archive&, silicon_one::la_egress_qos_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_ingress_qos_profile&);
template <class Archive> void load(Archive&, silicon_one::la_ingress_qos_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_multicast_group&);
template <class Archive> void load(Archive&, silicon_one::la_ip_multicast_group&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_action_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_action_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_markdown_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_markdown_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_profile&);
template <class Archive> void load(Archive&, silicon_one::la_meter_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_base&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_base&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_impl::meter_properties&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_impl::meter_properties&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_next_hop_base&);
template <class Archive> void load(Archive&, silicon_one::la_next_hop_base&);

template <class Archive> void save(Archive&, const silicon_one::la_object&);
template <class Archive> void load(Archive&, silicon_one::la_object&);

template <class Archive> void save(Archive&, const silicon_one::la_te_tunnel&);
template <class Archive> void load(Archive&, silicon_one::la_te_tunnel&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf&);
template <class Archive> void load(Archive&, silicon_one::la_vrf&);

template <class Archive> void save(Archive&, const silicon_one::npl_ipv4_lpm_table_functional_traits_t&);
template <class Archive> void load(Archive&, silicon_one::npl_ipv4_lpm_table_functional_traits_t&);

template <class Archive> void save(Archive&, const silicon_one::npl_ipv6_lpm_table_functional_traits_t&);
template <class Archive> void load(Archive&, silicon_one::npl_ipv6_lpm_table_functional_traits_t&);

template <class Archive> void save(Archive&, const silicon_one::resolution_table_index&);
template <class Archive> void load(Archive&, silicon_one::resolution_table_index&);

template<>
class serializer_class<silicon_one::la_switch_impl::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_switch_impl::slice_data& m) {
            archive(::cereal::make_nvp("vni_table_entry", m.vni_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_switch_impl::slice_data& m) {
            archive(::cereal::make_nvp("vni_table_entry", m.vni_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_switch_impl::slice_data& m)
{
    serializer_class<silicon_one::la_switch_impl::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_switch_impl::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_switch_impl::slice_data& m)
{
    serializer_class<silicon_one::la_switch_impl::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_switch_impl::slice_data&);



template<>
class serializer_class<silicon_one::la_switch_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_switch_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("mac_relay_to_vni_table_entry", m.mac_relay_to_vni_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_switch_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("mac_relay_to_vni_table_entry", m.mac_relay_to_vni_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_switch_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_switch_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_switch_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_switch_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_switch_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_switch_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_switch_impl::vni_profile_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_switch_impl::vni_profile_data& m) {
            archive(::cereal::make_nvp("vni_profile_allocated", m.vni_profile_allocated));
            archive(::cereal::make_nvp("vni_profile", m.vni_profile));
            archive(::cereal::make_nvp("vni_profile_index", m.vni_profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_switch_impl::vni_profile_data& m) {
            archive(::cereal::make_nvp("vni_profile_allocated", m.vni_profile_allocated));
            archive(::cereal::make_nvp("vni_profile", m.vni_profile));
            archive(::cereal::make_nvp("vni_profile_index", m.vni_profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_switch_impl::vni_profile_data& m)
{
    serializer_class<silicon_one::la_switch_impl::vni_profile_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_switch_impl::vni_profile_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_switch_impl::vni_profile_data& m)
{
    serializer_class<silicon_one::la_switch_impl::vni_profile_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_switch_impl::vni_profile_data&);



template<>
class serializer_class<silicon_one::la_te_tunnel_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_te_tunnel_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_te_tunnel_gid", m.m_te_tunnel_gid));
            archive(::cereal::make_nvp("m_tunnel_type", m.m_tunnel_type));
            archive(::cereal::make_nvp("m_ipv6_explicit_null_enabled", m.m_ipv6_explicit_null_enabled));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_te_em_entry_map", m.m_te_em_entry_map));
            archive(::cereal::make_nvp("m_ldp_over_te_em_entry_map", m.m_ldp_over_te_em_entry_map));
            archive(::cereal::make_nvp("m_tunnel_nh_pairs", m.m_tunnel_nh_pairs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_te_tunnel_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_te_tunnel_gid", m.m_te_tunnel_gid));
            archive(::cereal::make_nvp("m_tunnel_type", m.m_tunnel_type));
            archive(::cereal::make_nvp("m_ipv6_explicit_null_enabled", m.m_ipv6_explicit_null_enabled));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_destination", m.m_destination));
            archive(::cereal::make_nvp("m_te_em_entry_map", m.m_te_em_entry_map));
            archive(::cereal::make_nvp("m_ldp_over_te_em_entry_map", m.m_ldp_over_te_em_entry_map));
            archive(::cereal::make_nvp("m_tunnel_nh_pairs", m.m_tunnel_nh_pairs));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_te_tunnel_impl& m)
{
    archive(cereal::base_class<silicon_one::la_te_tunnel>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_te_tunnel_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_te_tunnel_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_te_tunnel_impl& m)
{
    archive(cereal::base_class<silicon_one::la_te_tunnel>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_te_tunnel_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_te_tunnel_impl&);



template<>
class serializer_class<silicon_one::la_te_tunnel_impl::tunnel_nh_pair> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_te_tunnel_impl::tunnel_nh_pair& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_tunnel", m.m_tunnel));
            archive(::cereal::make_nvp("m_nh", m.m_nh));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_te_tunnel_impl::tunnel_nh_pair& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_tunnel", m.m_tunnel));
            archive(::cereal::make_nvp("m_nh", m.m_nh));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_te_tunnel_impl::tunnel_nh_pair& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_te_tunnel_impl::tunnel_nh_pair>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_te_tunnel_impl::tunnel_nh_pair&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_te_tunnel_impl::tunnel_nh_pair& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_te_tunnel_impl::tunnel_nh_pair>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_te_tunnel_impl::tunnel_nh_pair&);



template<>
class serializer_class<silicon_one::la_te_tunnel_impl::lsp_configuration_params> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_te_tunnel_impl::lsp_configuration_params& m) {
            archive(::cereal::make_nvp("multi_counter_enabled", m.multi_counter_enabled));
            archive(::cereal::make_nvp("program_additional_labels_table", m.program_additional_labels_table));
            archive(::cereal::make_nvp("lsp_payload_with_3_labels", m.lsp_payload_with_3_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_te_tunnel_impl::lsp_configuration_params& m) {
            archive(::cereal::make_nvp("multi_counter_enabled", m.multi_counter_enabled));
            archive(::cereal::make_nvp("program_additional_labels_table", m.program_additional_labels_table));
            archive(::cereal::make_nvp("lsp_payload_with_3_labels", m.lsp_payload_with_3_labels));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_te_tunnel_impl::lsp_configuration_params& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::lsp_configuration_params>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_te_tunnel_impl::lsp_configuration_params&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_te_tunnel_impl::lsp_configuration_params& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::lsp_configuration_params>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_te_tunnel_impl::lsp_configuration_params&);



template<>
class serializer_class<silicon_one::la_te_tunnel_impl::resolution_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_te_tunnel_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("id_in_step", m.id_in_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_te_tunnel_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("id_in_step", m.id_in_step));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_te_tunnel_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::resolution_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_te_tunnel_impl::resolution_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_te_tunnel_impl::resolution_data& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::resolution_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_te_tunnel_impl::resolution_data&);



template<>
class serializer_class<silicon_one::la_te_tunnel_impl::te_em_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_te_tunnel_impl::te_em_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("more_labels_index_valid", m.more_labels_index_valid));
            archive(::cereal::make_nvp("more_labels_index", m.more_labels_index));
            archive(::cereal::make_nvp("ifgs", m.ifgs));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_te_tunnel_impl::te_em_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("more_labels_index_valid", m.more_labels_index_valid));
            archive(::cereal::make_nvp("more_labels_index", m.more_labels_index));
            archive(::cereal::make_nvp("ifgs", m.ifgs));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_te_tunnel_impl::te_em_info& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::te_em_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_te_tunnel_impl::te_em_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_te_tunnel_impl::te_em_info& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::te_em_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_te_tunnel_impl::te_em_info&);



template<>
class serializer_class<silicon_one::la_te_tunnel_impl::ldp_over_te_em_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_te_tunnel_impl::ldp_over_te_em_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_te_tunnel_impl::ldp_over_te_em_info& m) {
            archive(::cereal::make_nvp("labels", m.labels));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_te_tunnel_impl::ldp_over_te_em_info& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::ldp_over_te_em_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_te_tunnel_impl::ldp_over_te_em_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_te_tunnel_impl::ldp_over_te_em_info& m)
{
    serializer_class<silicon_one::la_te_tunnel_impl::ldp_over_te_em_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_te_tunnel_impl::ldp_over_te_em_info&);



template<>
class serializer_class<silicon_one::la_vrf_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ipv4_implicit_mc_catch_all_configured", m.m_ipv4_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv6_implicit_mc_catch_all_configured", m.m_ipv6_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv4_mc_route_desc_map", m.m_ipv4_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv6_mc_route_desc_map", m.m_ipv6_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv4_bulk_entries_vec", m.m_ipv4_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv6_bulk_entries_vec", m.m_ipv6_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv4_bulk_prefix_set", m.m_ipv4_bulk_prefix_set));
            archive(::cereal::make_nvp("m_ipv6_bulk_prefix_set", m.m_ipv6_bulk_prefix_set));
            archive(::cereal::make_nvp("m_urpf_allow_default", m.m_urpf_allow_default));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_fallback_vrf", m.m_fallback_vrf));
            archive(::cereal::make_nvp("m_ipv4_default_entry", m.m_ipv4_default_entry));
            archive(::cereal::make_nvp("m_ipv6_default_entry", m.m_ipv6_default_entry));
            archive(::cereal::make_nvp("m_ipv4_em_entries", m.m_ipv4_em_entries));
            archive(::cereal::make_nvp("m_ipv6_em_entries", m.m_ipv6_em_entries));
            archive(::cereal::make_nvp("m_pbr_v4_acl", m.m_pbr_v4_acl));
            archive(::cereal::make_nvp("m_pbr_v6_acl", m.m_pbr_v6_acl));
            archive(::cereal::make_nvp("m_bulk_old_destinations", m.m_bulk_old_destinations));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ipv4_implicit_mc_catch_all_configured", m.m_ipv4_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv6_implicit_mc_catch_all_configured", m.m_ipv6_implicit_mc_catch_all_configured));
            archive(::cereal::make_nvp("m_ipv4_mc_route_desc_map", m.m_ipv4_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv6_mc_route_desc_map", m.m_ipv6_mc_route_desc_map));
            archive(::cereal::make_nvp("m_ipv4_bulk_entries_vec", m.m_ipv4_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv6_bulk_entries_vec", m.m_ipv6_bulk_entries_vec));
            archive(::cereal::make_nvp("m_ipv4_bulk_prefix_set", m.m_ipv4_bulk_prefix_set));
            archive(::cereal::make_nvp("m_ipv6_bulk_prefix_set", m.m_ipv6_bulk_prefix_set));
            archive(::cereal::make_nvp("m_urpf_allow_default", m.m_urpf_allow_default));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_fallback_vrf", m.m_fallback_vrf));
            archive(::cereal::make_nvp("m_ipv4_default_entry", m.m_ipv4_default_entry));
            archive(::cereal::make_nvp("m_ipv6_default_entry", m.m_ipv6_default_entry));
            archive(::cereal::make_nvp("m_ipv4_em_entries", m.m_ipv4_em_entries));
            archive(::cereal::make_nvp("m_ipv6_em_entries", m.m_ipv6_em_entries));
            archive(::cereal::make_nvp("m_pbr_v4_acl", m.m_pbr_v4_acl));
            archive(::cereal::make_nvp("m_pbr_v6_acl", m.m_pbr_v6_acl));
            archive(::cereal::make_nvp("m_bulk_old_destinations", m.m_bulk_old_destinations));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl& m)
{
    archive(cereal::base_class<silicon_one::la_vrf>(&m));
    serializer_class<silicon_one::la_vrf_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl& m)
{
    archive(cereal::base_class<silicon_one::la_vrf>(&m));
    serializer_class<silicon_one::la_vrf_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl&);



template<>
class serializer_class<silicon_one::la_vrf_impl::mc_route_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::mc_route_desc& m) {
            archive(::cereal::make_nvp("punt_on_rpf_fail", m.punt_on_rpf_fail));
            archive(::cereal::make_nvp("punt_and_forward", m.punt_and_forward));
            archive(::cereal::make_nvp("v6_compressed_sip", m.v6_compressed_sip));
            archive(::cereal::make_nvp("use_rpfid", m.use_rpfid));
            archive(::cereal::make_nvp("rpfid", m.rpfid));
            archive(::cereal::make_nvp("enable_rpf_check", m.enable_rpf_check));
            archive(::cereal::make_nvp("mcg", m.mcg));
            archive(::cereal::make_nvp("rpf", m.rpf));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::mc_route_desc& m) {
            archive(::cereal::make_nvp("punt_on_rpf_fail", m.punt_on_rpf_fail));
            archive(::cereal::make_nvp("punt_and_forward", m.punt_and_forward));
            archive(::cereal::make_nvp("v6_compressed_sip", m.v6_compressed_sip));
            archive(::cereal::make_nvp("use_rpfid", m.use_rpfid));
            archive(::cereal::make_nvp("rpfid", m.rpfid));
            archive(::cereal::make_nvp("enable_rpf_check", m.enable_rpf_check));
            archive(::cereal::make_nvp("mcg", m.mcg));
            archive(::cereal::make_nvp("rpf", m.rpf));
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::mc_route_desc& m)
{
    serializer_class<silicon_one::la_vrf_impl::mc_route_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::mc_route_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::mc_route_desc& m)
{
    serializer_class<silicon_one::la_vrf_impl::mc_route_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::mc_route_desc&);



template<>
class serializer_class<silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::ipv4_mc_route_map_key_t&);



template<>
class serializer_class<silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m) {
            archive(::cereal::make_nvp("saddr", m.saddr));
            archive(::cereal::make_nvp("gaddr", m.gaddr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_impl::ipv6_mc_route_map_key_t&);



template<>
class serializer_class<silicon_one::mac_address_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_address_manager& m) {
            archive(::cereal::make_nvp("m_msbs", m.m_msbs));
            archive(::cereal::make_nvp("m_msbs_refcount", m.m_msbs_refcount));
            archive(::cereal::make_nvp("m_first_dynamic_prefix_index", m.m_first_dynamic_prefix_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_address_manager& m) {
            archive(::cereal::make_nvp("m_msbs", m.m_msbs));
            archive(::cereal::make_nvp("m_msbs_refcount", m.m_msbs_refcount));
            archive(::cereal::make_nvp("m_first_dynamic_prefix_index", m.m_first_dynamic_prefix_index));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_address_manager& m)
{
    serializer_class<silicon_one::mac_address_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_address_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_address_manager& m)
{
    serializer_class<silicon_one::mac_address_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_address_manager&);



template<>
class serializer_class<silicon_one::mc_copy_id_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mc_copy_id_manager& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mc_copy_id_manager& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mc_copy_id_manager& m)
{
    serializer_class<silicon_one::mc_copy_id_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mc_copy_id_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::mc_copy_id_manager& m)
{
    serializer_class<silicon_one::mc_copy_id_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mc_copy_id_manager&);



template<>
class serializer_class<silicon_one::la_egress_qos_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_egress_qos_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_qos_map", m.m_qos_map));
            archive(::cereal::make_nvp("m_marking_source", m.m_marking_source));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_egress_qos_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_qos_map", m.m_qos_map));
            archive(::cereal::make_nvp("m_marking_source", m.m_marking_source));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_egress_qos_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_egress_qos_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_egress_qos_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_egress_qos_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_egress_qos_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_egress_qos_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_egress_qos_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_egress_qos_profile_impl&);



template<>
class serializer_class<silicon_one::la_egress_qos_profile_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_egress_qos_profile_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("qos_id", m.qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_egress_qos_profile_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("qos_id", m.qos_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_egress_qos_profile_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_egress_qos_profile_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_egress_qos_profile_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_egress_qos_profile_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_egress_qos_profile_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_egress_qos_profile_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_ingress_qos_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ingress_qos_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_enable_ingress_remark", m.m_enable_ingress_remark));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ip_qos_map", m.m_ip_qos_map));
            archive(::cereal::make_nvp("m_ipv6_qos_map", m.m_ipv6_qos_map));
            archive(::cereal::make_nvp("m_mac_qos_map", m.m_mac_qos_map));
            archive(::cereal::make_nvp("m_mpls_qos_map", m.m_mpls_qos_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acls", m.m_acls));
            archive(::cereal::make_nvp("m_meter_markdown_profile", m.m_meter_markdown_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ingress_qos_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_enable_ingress_remark", m.m_enable_ingress_remark));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ip_qos_map", m.m_ip_qos_map));
            archive(::cereal::make_nvp("m_ipv6_qos_map", m.m_ipv6_qos_map));
            archive(::cereal::make_nvp("m_mac_qos_map", m.m_mac_qos_map));
            archive(::cereal::make_nvp("m_mpls_qos_map", m.m_mpls_qos_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acls", m.m_acls));
            archive(::cereal::make_nvp("m_meter_markdown_profile", m.m_meter_markdown_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ingress_qos_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ingress_qos_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ingress_qos_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ingress_qos_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ingress_qos_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ingress_qos_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_ingress_qos_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ingress_qos_profile_impl&);



template<>
class serializer_class<silicon_one::la_ingress_qos_profile_impl::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ingress_qos_profile_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("qos_id", m.qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ingress_qos_profile_impl::slice_pair_data& m) {
            archive(::cereal::make_nvp("qos_id", m.qos_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ingress_qos_profile_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_ingress_qos_profile_impl::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ingress_qos_profile_impl::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ingress_qos_profile_impl::slice_pair_data& m)
{
    serializer_class<silicon_one::la_ingress_qos_profile_impl::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ingress_qos_profile_impl::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_meter_action_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_action_profile_impl& m) {
            archive(::cereal::make_nvp("m_action_profile_properties_map", m.m_action_profile_properties_map));
            archive(::cereal::make_nvp("m_exact_meters_allocation", m.m_exact_meters_allocation));
            archive(::cereal::make_nvp("m_stat_bank_data", m.m_stat_bank_data));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_action_profile_impl& m) {
            archive(::cereal::make_nvp("m_action_profile_properties_map", m.m_action_profile_properties_map));
            archive(::cereal::make_nvp("m_exact_meters_allocation", m.m_exact_meters_allocation));
            archive(::cereal::make_nvp("m_stat_bank_data", m.m_stat_bank_data));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_action_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_action_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_action_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_action_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_action_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_action_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_action_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_action_profile_impl&);



template<>
class serializer_class<silicon_one::la_meter_action_profile_impl::per_color_pair_properties> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_action_profile_impl::per_color_pair_properties& m) {
            archive(::cereal::make_nvp("drop_enable", m.drop_enable));
            archive(::cereal::make_nvp("mark_ecn", m.mark_ecn));
            archive(::cereal::make_nvp("packet_color", m.packet_color));
            archive(::cereal::make_nvp("rx_cgm_color", m.rx_cgm_color));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_action_profile_impl::per_color_pair_properties& m) {
            archive(::cereal::make_nvp("drop_enable", m.drop_enable));
            archive(::cereal::make_nvp("mark_ecn", m.mark_ecn));
            archive(::cereal::make_nvp("packet_color", m.packet_color));
            archive(::cereal::make_nvp("rx_cgm_color", m.rx_cgm_color));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_action_profile_impl::per_color_pair_properties& m)
{
    serializer_class<silicon_one::la_meter_action_profile_impl::per_color_pair_properties>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_action_profile_impl::per_color_pair_properties&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_action_profile_impl::per_color_pair_properties& m)
{
    serializer_class<silicon_one::la_meter_action_profile_impl::per_color_pair_properties>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_action_profile_impl::per_color_pair_properties&);



template<>
class serializer_class<silicon_one::la_meter_action_profile_impl::allocation_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_action_profile_impl::allocation_data& m) {
            archive(::cereal::make_nvp("profile_index", m.profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_action_profile_impl::allocation_data& m) {
            archive(::cereal::make_nvp("profile_index", m.profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_action_profile_impl::allocation_data& m)
{
    serializer_class<silicon_one::la_meter_action_profile_impl::allocation_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_action_profile_impl::allocation_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_action_profile_impl::allocation_data& m)
{
    serializer_class<silicon_one::la_meter_action_profile_impl::allocation_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_action_profile_impl::allocation_data&);



template<>
class serializer_class<silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data& m)
{
    archive(cereal::base_class<silicon_one::la_meter_action_profile_impl::allocation_data>(&m));
    serializer_class<silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data& m)
{
    archive(cereal::base_class<silicon_one::la_meter_action_profile_impl::allocation_data>(&m));
    serializer_class<silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_action_profile_impl::stat_bank_allocation_data&);



template<>
class serializer_class<silicon_one::la_meter_markdown_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_markdown_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_markdown_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_markdown_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_markdown_profile>(&m));
    serializer_class<silicon_one::la_meter_markdown_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_markdown_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_markdown_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_markdown_profile>(&m));
    serializer_class<silicon_one::la_meter_markdown_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_markdown_profile_impl&);



template<>
class serializer_class<silicon_one::la_meter_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_profile_impl& m) {
            archive(::cereal::make_nvp("m_ifg_data", m.m_ifg_data));
            archive(::cereal::make_nvp("m_stat_bank_data", m.m_stat_bank_data));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_measure_mode", m.m_measure_mode));
            archive(::cereal::make_nvp("m_rate_mode", m.m_rate_mode));
            archive(::cereal::make_nvp("m_color_awareness", m.m_color_awareness));
            archive(::cereal::make_nvp("m_cascade_mode", m.m_cascade_mode));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_profile_impl& m) {
            archive(::cereal::make_nvp("m_ifg_data", m.m_ifg_data));
            archive(::cereal::make_nvp("m_stat_bank_data", m.m_stat_bank_data));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_type", m.m_type));
            archive(::cereal::make_nvp("m_measure_mode", m.m_measure_mode));
            archive(::cereal::make_nvp("m_rate_mode", m.m_rate_mode));
            archive(::cereal::make_nvp("m_color_awareness", m.m_color_awareness));
            archive(::cereal::make_nvp("m_cascade_mode", m.m_cascade_mode));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_profile_impl&);



template<>
class serializer_class<silicon_one::la_meter_profile_impl::allocation_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_profile_impl::allocation_data& m) {
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("ebs_or_pbs", m.ebs_or_pbs));
            archive(::cereal::make_nvp("profile_index", m.profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_profile_impl::allocation_data& m) {
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("ebs_or_pbs", m.ebs_or_pbs));
            archive(::cereal::make_nvp("profile_index", m.profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_profile_impl::allocation_data& m)
{
    serializer_class<silicon_one::la_meter_profile_impl::allocation_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_profile_impl::allocation_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_profile_impl::allocation_data& m)
{
    serializer_class<silicon_one::la_meter_profile_impl::allocation_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_profile_impl::allocation_data&);



template<>
class serializer_class<silicon_one::la_meter_profile_impl::stat_bank_allocation_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile_impl::allocation_data>(&m));
    serializer_class<silicon_one::la_meter_profile_impl::stat_bank_allocation_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_profile_impl::stat_bank_allocation_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_profile_impl::stat_bank_allocation_data& m)
{
    archive(cereal::base_class<silicon_one::la_meter_profile_impl::allocation_data>(&m));
    serializer_class<silicon_one::la_meter_profile_impl::stat_bank_allocation_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_profile_impl::stat_bank_allocation_data&);



template<>
class serializer_class<silicon_one::la_meter_set_exact_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_exact_impl& m) {
            archive(::cereal::make_nvp("m_counter_user_type", m.m_counter_user_type));
            archive(::cereal::make_nvp("m_cached_packets", m.m_cached_packets));
            archive(::cereal::make_nvp("m_cached_bytes", m.m_cached_bytes));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_exact_impl& m) {
            archive(::cereal::make_nvp("m_counter_user_type", m.m_counter_user_type));
            archive(::cereal::make_nvp("m_cached_packets", m.m_cached_packets));
            archive(::cereal::make_nvp("m_cached_bytes", m.m_cached_bytes));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_exact_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_impl>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_set_exact_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_exact_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_exact_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_impl>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_meter_set_exact_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_exact_impl&);



template<>
class serializer_class<silicon_one::la_meter_set_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_impl& m) {
            archive(::cereal::make_nvp("SINGLE_ALLOCATION_SLICE_IFG", m.SINGLE_ALLOCATION_SLICE_IFG));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_meter_type", m.m_meter_type));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_meters_properties", m.m_meters_properties));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_lpts_entry_meter", m.m_lpts_entry_meter));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_user_to_aggregation", m.m_user_to_aggregation));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_impl& m) {
            archive(::cereal::make_nvp("SINGLE_ALLOCATION_SLICE_IFG", m.SINGLE_ALLOCATION_SLICE_IFG));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_meter_type", m.m_meter_type));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_meters_properties", m.m_meters_properties));
            archive(::cereal::make_nvp("m_allocations", m.m_allocations));
            archive(::cereal::make_nvp("m_lpts_entry_meter", m.m_lpts_entry_meter));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_user_to_aggregation", m.m_user_to_aggregation));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_base>(&m));
    serializer_class<silicon_one::la_meter_set_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_impl& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set_base>(&m));
    serializer_class<silicon_one::la_meter_set_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_te_tunnel_impl var0;
    ar(var0);
    silicon_one::la_te_tunnel_impl::tunnel_nh_pair var1;
    ar(var1);
    silicon_one::la_vrf_impl var2;
    ar(var2);
    silicon_one::la_egress_qos_profile_impl var3;
    ar(var3);
    silicon_one::la_ingress_qos_profile_impl var4;
    ar(var4);
    silicon_one::la_meter_action_profile_impl var5;
    ar(var5);
    silicon_one::la_meter_markdown_profile_impl var6;
    ar(var6);
    silicon_one::la_meter_profile_impl var7;
    ar(var7);
    silicon_one::la_meter_set_exact_impl var8;
    ar(var8);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_te_tunnel_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_te_tunnel_impl::tunnel_nh_pair);
CEREAL_REGISTER_TYPE(silicon_one::la_vrf_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_egress_qos_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ingress_qos_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_action_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_markdown_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_set_exact_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_set_impl);

#pragma GCC diagnostic pop

