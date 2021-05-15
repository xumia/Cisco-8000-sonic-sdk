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

template <class Archive> void save(Archive&, const silicon_one::acl_entry_desc&);
template <class Archive> void load(Archive&, silicon_one::acl_entry_desc&);

template <class Archive> void save(Archive&, const silicon_one::counter_allocation&);
template <class Archive> void load(Archive&, silicon_one::counter_allocation&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_acl&);
template <class Archive> void load(Archive&, silicon_one::la_acl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_command_profile_base&);
template <class Archive> void load(Archive&, silicon_one::la_acl_command_profile_base&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_key_profile_base&);
template <class Archive> void load(Archive&, silicon_one::la_acl_key_profile_base&);

template <class Archive> void save(Archive&, const silicon_one::la_counter_set&);
template <class Archive> void load(Archive&, silicon_one::la_counter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_destination_pe&);
template <class Archive> void load(Archive&, silicon_one::la_destination_pe&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ecmp_group&);
template <class Archive> void load(Archive&, silicon_one::la_ecmp_group&);

template <class Archive> void save(Archive&, const silicon_one::la_ethernet_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_ethernet_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_filter_group_impl&);
template <class Archive> void load(Archive&, silicon_one::la_filter_group_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ip_tunnel_destination&);
template <class Archive> void load(Archive&, silicon_one::la_ip_tunnel_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_ac_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_ac_port&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_ac_port_impl::slice_pair_data&);
template <class Archive> void load(Archive&, silicon_one::la_l3_ac_port_impl::slice_pair_data&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_destination&);
template <class Archive> void load(Archive&, silicon_one::la_l3_destination&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set_exact_impl&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set_exact_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mpls_label&);
template <class Archive> void load(Archive&, silicon_one::la_mpls_label&);

template <class Archive> void save(Archive&, const silicon_one::la_object&);
template <class Archive> void load(Archive&, silicon_one::la_object&);

template <class Archive> void save(Archive&, const silicon_one::la_pcl&);
template <class Archive> void load(Archive&, silicon_one::la_pcl&);

template <class Archive> void save(Archive&, const silicon_one::la_prefix_object_base&);
template <class Archive> void load(Archive&, silicon_one::la_prefix_object_base&);

template <class Archive> void save(Archive&, const silicon_one::la_switch&);
template <class Archive> void load(Archive&, silicon_one::la_switch&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port&);
template <class Archive> void load(Archive&, silicon_one::la_system_port&);

template <class Archive> void save(Archive&, const silicon_one::la_tc_profile&);
template <class Archive> void load(Archive&, silicon_one::la_tc_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_set&);
template <class Archive> void load(Archive&, silicon_one::la_voq_set&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_impl&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_port_common_base&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_port_common_base&);

template <class Archive> void save(Archive&, const silicon_one::resolution_cfg_handle_t&);
template <class Archive> void load(Archive&, silicon_one::resolution_cfg_handle_t&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr&);

template<>
class serializer_class<silicon_one::destination_id> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::destination_id& m) {
        la_uint32_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::destination_id& m) {
        la_uint32_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::destination_id& m)
{
    serializer_class<silicon_one::destination_id>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::destination_id&);

template <class Archive>
void
load(Archive& archive, silicon_one::destination_id& m)
{
    serializer_class<silicon_one::destination_id>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::destination_id&);



template<>
class serializer_class<silicon_one::lpm_destination_id> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::lpm_destination_id& m) {
        la_uint32_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::lpm_destination_id& m) {
        la_uint32_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::lpm_destination_id& m)
{
    serializer_class<silicon_one::lpm_destination_id>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::lpm_destination_id&);

template <class Archive>
void
load(Archive& archive, silicon_one::lpm_destination_id& m)
{
    serializer_class<silicon_one::lpm_destination_id>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::lpm_destination_id&);



template<>
class serializer_class<silicon_one::resolution_table_index> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_table_index& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_table_index& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_table_index& m)
{
    serializer_class<silicon_one::resolution_table_index>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_table_index&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_table_index& m)
{
    serializer_class<silicon_one::resolution_table_index>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_table_index&);



template<>
class serializer_class<silicon_one::dependency_listener> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::dependency_listener& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::dependency_listener& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::dependency_listener& m)
{
    serializer_class<silicon_one::dependency_listener>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::dependency_listener&);

template <class Archive>
void
load(Archive& archive, silicon_one::dependency_listener& m)
{
    serializer_class<silicon_one::dependency_listener>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::dependency_listener&);



template<>
class serializer_class<silicon_one::bfd_packet_intervals> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::bfd_packet_intervals& m) {
            archive(::cereal::make_nvp("desired_min_tx_interval", m.desired_min_tx_interval));
            archive(::cereal::make_nvp("required_min_rx_interval", m.required_min_rx_interval));
            archive(::cereal::make_nvp("detection_time_multiplier", m.detection_time_multiplier));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::bfd_packet_intervals& m) {
            archive(::cereal::make_nvp("desired_min_tx_interval", m.desired_min_tx_interval));
            archive(::cereal::make_nvp("required_min_rx_interval", m.required_min_rx_interval));
            archive(::cereal::make_nvp("detection_time_multiplier", m.detection_time_multiplier));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::bfd_packet_intervals& m)
{
    serializer_class<silicon_one::bfd_packet_intervals>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::bfd_packet_intervals&);

template <class Archive>
void
load(Archive& archive, silicon_one::bfd_packet_intervals& m)
{
    serializer_class<silicon_one::bfd_packet_intervals>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::bfd_packet_intervals&);



template<>
class serializer_class<silicon_one::la_ac_port_common> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ac_port_common& m) {
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_vid1", m.m_vid1));
            archive(::cereal::make_nvp("m_vid2", m.m_vid2));
            archive(::cereal::make_nvp("m_attached_p2p_pwe", m.m_attached_p2p_pwe));
            archive(::cereal::make_nvp("m_attached_p2p_pwe_gid", m.m_attached_p2p_pwe_gid));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_mapped_vids", m.m_mapped_vids));
            archive(::cereal::make_nvp("m_port_state", m.m_port_state));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_eth_port", m.m_eth_port));
            archive(::cereal::make_nvp("m_attached_switch", m.m_attached_switch));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ac_port_common& m) {
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_vid1", m.m_vid1));
            archive(::cereal::make_nvp("m_vid2", m.m_vid2));
            archive(::cereal::make_nvp("m_attached_p2p_pwe", m.m_attached_p2p_pwe));
            archive(::cereal::make_nvp("m_attached_p2p_pwe_gid", m.m_attached_p2p_pwe_gid));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_mapped_vids", m.m_mapped_vids));
            archive(::cereal::make_nvp("m_port_state", m.m_port_state));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_eth_port", m.m_eth_port));
            archive(::cereal::make_nvp("m_attached_switch", m.m_attached_switch));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ac_port_common& m)
{
    serializer_class<silicon_one::la_ac_port_common>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ac_port_common&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ac_port_common& m)
{
    serializer_class<silicon_one::la_ac_port_common>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ac_port_common&);



template<>
class serializer_class<silicon_one::la_ac_port_common::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ac_port_common::slice_pair_data& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
            archive(::cereal::make_nvp("em0_ac_entry", m.em0_ac_entry));
            archive(::cereal::make_nvp("em0_ac_tag_entry", m.em0_ac_tag_entry));
            archive(::cereal::make_nvp("em0_ac_tag_tag_entry", m.em0_ac_tag_tag_entry));
            archive(::cereal::make_nvp("em1_ac_tag_entry", m.em1_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_entry", m.tcam_ac_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_entry", m.tcam_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_tag_entry", m.tcam_ac_tag_tag_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ac_port_common::slice_pair_data& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
            archive(::cereal::make_nvp("em0_ac_entry", m.em0_ac_entry));
            archive(::cereal::make_nvp("em0_ac_tag_entry", m.em0_ac_tag_entry));
            archive(::cereal::make_nvp("em0_ac_tag_tag_entry", m.em0_ac_tag_tag_entry));
            archive(::cereal::make_nvp("em1_ac_tag_entry", m.em1_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_entry", m.tcam_ac_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_entry", m.tcam_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_tag_entry", m.tcam_ac_tag_tag_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ac_port_common::slice_pair_data& m)
{
    serializer_class<silicon_one::la_ac_port_common::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ac_port_common::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ac_port_common::slice_pair_data& m)
{
    serializer_class<silicon_one::la_ac_port_common::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ac_port_common::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_acl_delegate> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_delegate& m) {
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_stage", m.m_stage));
            archive(::cereal::make_nvp("m_acl_type", m.m_acl_type));
            archive(::cereal::make_nvp("m_qos_cmd_count", m.m_qos_cmd_count));
            archive(::cereal::make_nvp("m_aces", m.m_aces));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acl_key_profile", m.m_acl_key_profile));
            archive(::cereal::make_nvp("m_acl_command_profile", m.m_acl_command_profile));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
            archive(::cereal::make_nvp("m_src_pcl", m.m_src_pcl));
            archive(::cereal::make_nvp("m_dst_pcl", m.m_dst_pcl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_delegate& m) {
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_stage", m.m_stage));
            archive(::cereal::make_nvp("m_acl_type", m.m_acl_type));
            archive(::cereal::make_nvp("m_qos_cmd_count", m.m_qos_cmd_count));
            archive(::cereal::make_nvp("m_aces", m.m_aces));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acl_key_profile", m.m_acl_key_profile));
            archive(::cereal::make_nvp("m_acl_command_profile", m.m_acl_command_profile));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
            archive(::cereal::make_nvp("m_src_pcl", m.m_src_pcl));
            archive(::cereal::make_nvp("m_dst_pcl", m.m_dst_pcl));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_delegate& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_acl_delegate>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_delegate&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_delegate& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_acl_delegate>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_delegate&);



template<>
class serializer_class<silicon_one::la_acl_delegate::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_delegate::slice_pair_data& m) {
            archive(::cereal::make_nvp("acl_id", m.acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_delegate::slice_pair_data& m) {
            archive(::cereal::make_nvp("acl_id", m.acl_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_delegate::slice_pair_data& m)
{
    serializer_class<silicon_one::la_acl_delegate::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_delegate::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_delegate::slice_pair_data& m)
{
    serializer_class<silicon_one::la_acl_delegate::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_delegate::slice_pair_data&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait&);



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
class serializer_class<silicon_one::la_acl_security_group> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_security_group& m) {
            archive(::cereal::make_nvp("m_sgacl_id", m.m_sgacl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_security_group& m) {
            archive(::cereal::make_nvp("m_sgacl_id", m.m_sgacl_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_security_group& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_security_group>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_security_group&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_security_group& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_security_group>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_security_group&);



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
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
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
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
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
            archive(::cereal::make_nvp("cfg_handles", m.cfg_handles));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ecmp_group_impl::resolution_data& m) {
            archive(::cereal::make_nvp("users_for_step", m.users_for_step));
            archive(::cereal::make_nvp("id_in_step", m.id_in_step));
            archive(::cereal::make_nvp("cfg_handles", m.cfg_handles));
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
class serializer_class<silicon_one::la_ip_tunnel_destination_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ip_tunnel_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ip_tunnel_destination_gid", m.m_ip_tunnel_destination_gid));
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_underlay_destination", m.m_underlay_destination));
            archive(::cereal::make_nvp("m_ip_tunnel_port", m.m_ip_tunnel_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ip_tunnel_destination_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ip_tunnel_destination_gid", m.m_ip_tunnel_destination_gid));
            archive(::cereal::make_nvp("m_res_cfg_handle", m.m_res_cfg_handle));
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



template<>
class serializer_class<silicon_one::la_l3_ac_port_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_l3_ac_port_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_mldp_budnode_terminate", m.m_mldp_budnode_terminate));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_ac_port_common", m.m_ac_port_common));
            archive(::cereal::make_nvp("m_service_mapping_type", m.m_service_mapping_type));
            archive(::cereal::make_nvp("m_stack_remote_lp_queueing", m.m_stack_remote_lp_queueing));
            archive(::cereal::make_nvp("m_voq_map", m.m_voq_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_ethernet_port", m.m_ethernet_port));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_tc_profile", m.m_tc_profile));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_l3_ac_port_impl& m) {
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_mldp_budnode_terminate", m.m_mldp_budnode_terminate));
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_vrf_port_common", m.m_vrf_port_common));
            archive(::cereal::make_nvp("m_ac_port_common", m.m_ac_port_common));
            archive(::cereal::make_nvp("m_service_mapping_type", m.m_service_mapping_type));
            archive(::cereal::make_nvp("m_stack_remote_lp_queueing", m.m_stack_remote_lp_queueing));
            archive(::cereal::make_nvp("m_voq_map", m.m_voq_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_ethernet_port", m.m_ethernet_port));
            archive(::cereal::make_nvp("m_vrf", m.m_vrf));
            archive(::cereal::make_nvp("m_tc_profile", m.m_tc_profile));
            archive(::cereal::make_nvp("m_filter_group", m.m_filter_group));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_l3_ac_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l3_ac_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l3_ac_port_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_l3_ac_port_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_l3_ac_port_impl& m)
{
    archive(cereal::base_class<silicon_one::la_l3_ac_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_l3_ac_port_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_l3_ac_port_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_acl_security_group var0;
    ar(var0);
    silicon_one::la_counter_set_impl var1;
    ar(var1);
    silicon_one::la_destination_pe_impl var2;
    ar(var2);
    silicon_one::la_ecmp_group_impl var3;
    ar(var3);
    silicon_one::la_ip_tunnel_destination_impl var4;
    ar(var4);
    silicon_one::la_l3_ac_port_impl var5;
    ar(var5);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::dependency_listener);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_delegate);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_security_group);
CEREAL_REGISTER_TYPE(silicon_one::la_counter_set_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_destination_pe_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ecmp_group_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ip_tunnel_destination_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_l3_ac_port_impl);

#pragma GCC diagnostic pop

