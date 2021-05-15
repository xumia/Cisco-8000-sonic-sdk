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

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::interrupt_tree&);
template <class Archive> void load(Archive&, silicon_one::interrupt_tree&);

template <class Archive> void save(Archive&, const silicon_one::interrupt_tree::bit&);
template <class Archive> void load(Archive&, silicon_one::interrupt_tree::bit&);

template <class Archive> void save(Archive&, const silicon_one::interrupt_tree::node&);
template <class Archive> void load(Archive&, silicon_one::interrupt_tree::node&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_l2_service_port&);
template <class Archive> void load(Archive&, silicon_one::la_l2_service_port&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_fec_impl&);
template <class Archive> void load(Archive&, silicon_one::la_l3_fec_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_l3_port&);
template <class Archive> void load(Archive&, silicon_one::la_l3_port&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_port_common_base&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_port_common_base&);

template <class Archive> void save(Archive&, const silicon_one::la_vxlan_next_hop&);
template <class Archive> void load(Archive&, silicon_one::la_vxlan_next_hop&);

template <class Archive> void save(Archive&, const silicon_one::ll_device&);
template <class Archive> void load(Archive&, silicon_one::ll_device&);

template <class Archive> void save(Archive&, const silicon_one::pipe&);
template <class Archive> void load(Archive&, silicon_one::pipe&);

template <class Archive> void save(Archive&, const silicon_one::serdes_device_handler&);
template <class Archive> void load(Archive&, silicon_one::serdes_device_handler&);

template <class Archive> void save(Archive&, const silicon_one::serdes_handler&);
template <class Archive> void load(Archive&, silicon_one::serdes_handler&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr&);

template <class Archive> void save(Archive&, const std::chrono::_V2::steady_clock&);
template <class Archive> void load(Archive&, std::chrono::_V2::steady_clock&);

template<>
class serializer_class<silicon_one::la_vrf_port_common_base::subnet_count_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t& m) {
            archive(::cereal::make_nvp("bytes_in_address", m.bytes_in_address));
            archive(::cereal::make_nvp("prefix_length", m.prefix_length));
            archive(::cereal::make_nvp("u", m.u));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t& m) {
            archive(::cereal::make_nvp("bytes_in_address", m.bytes_in_address));
            archive(::cereal::make_nvp("prefix_length", m.prefix_length));
            archive(::cereal::make_nvp("u", m.u));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_port_common_base::subnet_count_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t& m)
{
    serializer_class<silicon_one::la_vrf_port_common_base::subnet_count_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t&);



template<>
class serializer_class<silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u& m) {
            archive(::cereal::make_nvp("addr", m.addr));
            archive(::cereal::make_nvp("ipv4_addr", m.ipv4_addr));
            archive(::cereal::make_nvp("ipv6_addr", m.ipv6_addr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u& m) {
            archive(::cereal::make_nvp("addr", m.addr));
            archive(::cereal::make_nvp("ipv4_addr", m.ipv4_addr));
            archive(::cereal::make_nvp("ipv6_addr", m.ipv6_addr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u& m)
{
    serializer_class<silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u& m)
{
    serializer_class<silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t::_u&);



template<>
class serializer_class<silicon_one::la_vrf_port_common_base::ip_host_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_base::ip_host_data& m) {
            archive(::cereal::make_nvp("mac_addr", m.mac_addr));
            archive(::cereal::make_nvp("class_id", m.class_id));
            archive(::cereal::make_nvp("is_set_class_id", m.is_set_class_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_base::ip_host_data& m) {
            archive(::cereal::make_nvp("mac_addr", m.mac_addr));
            archive(::cereal::make_nvp("class_id", m.class_id));
            archive(::cereal::make_nvp("is_set_class_id", m.is_set_class_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_base::ip_host_data& m)
{
    serializer_class<silicon_one::la_vrf_port_common_base::ip_host_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_base::ip_host_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_base::ip_host_data& m)
{
    serializer_class<silicon_one::la_vrf_port_common_base::ip_host_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_base::ip_host_data&);



template<>
class serializer_class<silicon_one::la_vrf_port_common_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_vrf_port_common_pacgb>(&m));
    serializer_class<silicon_one::la_vrf_port_common_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_vrf_port_common_pacgb>(&m));
    serializer_class<silicon_one::la_vrf_port_common_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_gibraltar&);



template<>
class serializer_class<silicon_one::la_vrf_port_common_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_pacgb& m) {
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_pacgb& m) {
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_vrf_port_common_base>(&m));
    serializer_class<silicon_one::la_vrf_port_common_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_vrf_port_common_base>(&m));
    serializer_class<silicon_one::la_vrf_port_common_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_pacgb&);



template<>
class serializer_class<silicon_one::la_vrf_port_common_pacgb::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vrf_port_common_pacgb::slice_pair_data& m) {
            archive(::cereal::make_nvp("l3_dlp_table_entry", m.l3_dlp_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vrf_port_common_pacgb::slice_pair_data& m) {
            archive(::cereal::make_nvp("l3_dlp_table_entry", m.l3_dlp_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vrf_port_common_pacgb::slice_pair_data& m)
{
    serializer_class<silicon_one::la_vrf_port_common_pacgb::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vrf_port_common_pacgb::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vrf_port_common_pacgb::slice_pair_data& m)
{
    serializer_class<silicon_one::la_vrf_port_common_pacgb::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vrf_port_common_pacgb::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_vxlan_next_hop_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vxlan_next_hop_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_l3vxlan_smac_msb_index_profile", m.m_l3vxlan_smac_msb_index_profile));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_port", m.m_l3_port));
            archive(::cereal::make_nvp("m_vxlan_port", m.m_vxlan_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vxlan_next_hop_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_l3vxlan_smac_msb_index_profile", m.m_l3vxlan_smac_msb_index_profile));
            archive(::cereal::make_nvp("m_resolution_data", m.m_resolution_data));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_l3_port", m.m_l3_port));
            archive(::cereal::make_nvp("m_vxlan_port", m.m_vxlan_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vxlan_next_hop_base& m)
{
    archive(cereal::base_class<silicon_one::la_vxlan_next_hop>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_vxlan_next_hop_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vxlan_next_hop_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vxlan_next_hop_base& m)
{
    archive(cereal::base_class<silicon_one::la_vxlan_next_hop>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_vxlan_next_hop_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vxlan_next_hop_base&);



template<>
class serializer_class<silicon_one::la_vxlan_next_hop_base::resolution_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vxlan_next_hop_base::resolution_data& m) {
            archive(::cereal::make_nvp("fec_impl", m.fec_impl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vxlan_next_hop_base::resolution_data& m) {
            archive(::cereal::make_nvp("fec_impl", m.fec_impl));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vxlan_next_hop_base::resolution_data& m)
{
    serializer_class<silicon_one::la_vxlan_next_hop_base::resolution_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vxlan_next_hop_base::resolution_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vxlan_next_hop_base::resolution_data& m)
{
    serializer_class<silicon_one::la_vxlan_next_hop_base::resolution_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vxlan_next_hop_base::resolution_data&);



template<>
class serializer_class<silicon_one::la_vxlan_next_hop_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_vxlan_next_hop_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_vxlan_next_hop_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_vxlan_next_hop_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_vxlan_next_hop_base>(&m));
    serializer_class<silicon_one::la_vxlan_next_hop_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_vxlan_next_hop_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_vxlan_next_hop_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::la_vxlan_next_hop_base>(&m));
    serializer_class<silicon_one::la_vxlan_next_hop_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_vxlan_next_hop_gibraltar&);



template<>
class serializer_class<silicon_one::la_meter_set_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_meter_set_base& m) {
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_meter_set_base& m) {
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_meter_set_base& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set>(&m));
    serializer_class<silicon_one::la_meter_set_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_meter_set_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_meter_set_base& m)
{
    archive(cereal::base_class<silicon_one::la_meter_set>(&m));
    serializer_class<silicon_one::la_meter_set_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_meter_set_base&);



template<>
class serializer_class<silicon_one::arc_handler_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::arc_handler_base& m) {
            archive(::cereal::make_nvp("m_arc_enabled", m.m_arc_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::arc_handler_base& m) {
            archive(::cereal::make_nvp("m_arc_enabled", m.m_arc_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::arc_handler_base& m)
{
    serializer_class<silicon_one::arc_handler_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::arc_handler_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::arc_handler_base& m)
{
    serializer_class<silicon_one::arc_handler_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::arc_handler_base&);



template<>
class serializer_class<silicon_one::device_configurator_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_configurator_base& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_device_mode", m.m_device_mode));
            archive(::cereal::make_nvp("m_slices_type", m.m_slices_type));
            archive(::cereal::make_nvp("m_used_slices", m.m_used_slices));
            archive(::cereal::make_nvp("m_num_of_slices", m.m_num_of_slices));
            archive(::cereal::make_nvp("m_system_vars", m.m_system_vars));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_configurator_base& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_device_mode", m.m_device_mode));
            archive(::cereal::make_nvp("m_slices_type", m.m_slices_type));
            archive(::cereal::make_nvp("m_used_slices", m.m_used_slices));
            archive(::cereal::make_nvp("m_num_of_slices", m.m_num_of_slices));
            archive(::cereal::make_nvp("m_system_vars", m.m_system_vars));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_configurator_base& m)
{
    serializer_class<silicon_one::device_configurator_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_configurator_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_configurator_base& m)
{
    serializer_class<silicon_one::device_configurator_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_configurator_base&);



template<>
class serializer_class<silicon_one::device_configurator_base::system_init_vars> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_configurator_base::system_init_vars& m) {
            archive(::cereal::make_nvp("frequency", m.frequency));
            archive(::cereal::make_nvp("device_id", m.device_id));
            archive(::cereal::make_nvp("is_hbm", m.is_hbm));
            archive(::cereal::make_nvp("is_100g_fabric", m.is_100g_fabric));
            archive(::cereal::make_nvp("numnwk", m.numnwk));
            archive(::cereal::make_nvp("numfab", m.numfab));
            archive(::cereal::make_nvp("is_MAT_6_4T", m.is_MAT_6_4T));
            archive(::cereal::make_nvp("is_MAT_3_2T_A", m.is_MAT_3_2T_A));
            archive(::cereal::make_nvp("is_MAT_3_2T_B", m.is_MAT_3_2T_B));
            archive(::cereal::make_nvp("credit_in_bytes", m.credit_in_bytes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_configurator_base::system_init_vars& m) {
            archive(::cereal::make_nvp("frequency", m.frequency));
            archive(::cereal::make_nvp("device_id", m.device_id));
            archive(::cereal::make_nvp("is_hbm", m.is_hbm));
            archive(::cereal::make_nvp("is_100g_fabric", m.is_100g_fabric));
            archive(::cereal::make_nvp("numnwk", m.numnwk));
            archive(::cereal::make_nvp("numfab", m.numfab));
            archive(::cereal::make_nvp("is_MAT_6_4T", m.is_MAT_6_4T));
            archive(::cereal::make_nvp("is_MAT_3_2T_A", m.is_MAT_3_2T_A));
            archive(::cereal::make_nvp("is_MAT_3_2T_B", m.is_MAT_3_2T_B));
            archive(::cereal::make_nvp("credit_in_bytes", m.credit_in_bytes));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_configurator_base::system_init_vars& m)
{
    serializer_class<silicon_one::device_configurator_base::system_init_vars>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_configurator_base::system_init_vars&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_configurator_base::system_init_vars& m)
{
    serializer_class<silicon_one::device_configurator_base::system_init_vars>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_configurator_base::system_init_vars&);



template<>
class serializer_class<silicon_one::device_configurator_base::reg_mem_init_vars> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_configurator_base::reg_mem_init_vars& m) {
            archive(::cereal::make_nvp("instance", m.instance));
            archive(::cereal::make_nvp("num_instances", m.num_instances));
            archive(::cereal::make_nvp("line", m.line));
            archive(::cereal::make_nvp("num_lines", m.num_lines));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_configurator_base::reg_mem_init_vars& m) {
            archive(::cereal::make_nvp("instance", m.instance));
            archive(::cereal::make_nvp("num_instances", m.num_instances));
            archive(::cereal::make_nvp("line", m.line));
            archive(::cereal::make_nvp("num_lines", m.num_lines));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_configurator_base::reg_mem_init_vars& m)
{
    serializer_class<silicon_one::device_configurator_base::reg_mem_init_vars>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_configurator_base::reg_mem_init_vars&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_configurator_base::reg_mem_init_vars& m)
{
    serializer_class<silicon_one::device_configurator_base::reg_mem_init_vars>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_configurator_base::reg_mem_init_vars&);



template<>
class serializer_class<silicon_one::device_port_handler_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base& m) {
            archive(::cereal::make_nvp("m_fabric_data", m.m_fabric_data));
            archive(::cereal::make_nvp("m_valid_configurations", m.m_valid_configurations));
            archive(::cereal::make_nvp("m_serdes_configurations", m.m_serdes_configurations));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base& m) {
            archive(::cereal::make_nvp("m_fabric_data", m.m_fabric_data));
            archive(::cereal::make_nvp("m_valid_configurations", m.m_valid_configurations));
            archive(::cereal::make_nvp("m_serdes_configurations", m.m_serdes_configurations));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base& m)
{
    serializer_class<silicon_one::device_port_handler_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base& m)
{
    serializer_class<silicon_one::device_port_handler_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base&);



template<>
class serializer_class<silicon_one::device_port_handler_base::mac_port_config_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::mac_port_config_data& m) {
            archive(::cereal::make_nvp("serdes_speed", m.serdes_speed));
            archive(::cereal::make_nvp("serdes_speed_gbps", m.serdes_speed_gbps));
            archive(::cereal::make_nvp("mac_lanes", m.mac_lanes));
            archive(::cereal::make_nvp("reserved_mac_lanes", m.reserved_mac_lanes));
            archive(::cereal::make_nvp("pcs_lanes_per_mac_lane", m.pcs_lanes_per_mac_lane));
            archive(::cereal::make_nvp("alignment_marker_rx", m.alignment_marker_rx));
            archive(::cereal::make_nvp("alignment_marker_tx", m.alignment_marker_tx));
            archive(::cereal::make_nvp("an_capability", m.an_capability));
            archive(::cereal::make_nvp("an_fec_capability", m.an_fec_capability));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::mac_port_config_data& m) {
            archive(::cereal::make_nvp("serdes_speed", m.serdes_speed));
            archive(::cereal::make_nvp("serdes_speed_gbps", m.serdes_speed_gbps));
            archive(::cereal::make_nvp("mac_lanes", m.mac_lanes));
            archive(::cereal::make_nvp("reserved_mac_lanes", m.reserved_mac_lanes));
            archive(::cereal::make_nvp("pcs_lanes_per_mac_lane", m.pcs_lanes_per_mac_lane));
            archive(::cereal::make_nvp("alignment_marker_rx", m.alignment_marker_rx));
            archive(::cereal::make_nvp("alignment_marker_tx", m.alignment_marker_tx));
            archive(::cereal::make_nvp("an_capability", m.an_capability));
            archive(::cereal::make_nvp("an_fec_capability", m.an_fec_capability));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::mac_port_config_data& m)
{
    serializer_class<silicon_one::device_port_handler_base::mac_port_config_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::mac_port_config_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::mac_port_config_data& m)
{
    serializer_class<silicon_one::device_port_handler_base::mac_port_config_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::mac_port_config_data&);



template<>
class serializer_class<silicon_one::device_port_handler_base::serdes_config_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::serdes_config_data& m) {
            archive(::cereal::make_nvp("serdes_speed", m.serdes_speed));
            archive(::cereal::make_nvp("dwidth", m.dwidth));
            archive(::cereal::make_nvp("dwidth_code", m.dwidth_code));
            archive(::cereal::make_nvp("fec_lane_speed", m.fec_lane_speed));
            archive(::cereal::make_nvp("fec_lane_speed_code", m.fec_lane_speed_code));
            archive(::cereal::make_nvp("pam4_enable", m.pam4_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::serdes_config_data& m) {
            archive(::cereal::make_nvp("serdes_speed", m.serdes_speed));
            archive(::cereal::make_nvp("dwidth", m.dwidth));
            archive(::cereal::make_nvp("dwidth_code", m.dwidth_code));
            archive(::cereal::make_nvp("fec_lane_speed", m.fec_lane_speed));
            archive(::cereal::make_nvp("fec_lane_speed_code", m.fec_lane_speed_code));
            archive(::cereal::make_nvp("pam4_enable", m.pam4_enable));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::serdes_config_data& m)
{
    serializer_class<silicon_one::device_port_handler_base::serdes_config_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::serdes_config_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::serdes_config_data& m)
{
    serializer_class<silicon_one::device_port_handler_base::serdes_config_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::serdes_config_data&);



template<>
class serializer_class<silicon_one::device_port_handler_base::fabric_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::fabric_data& m) {
            archive(::cereal::make_nvp("num_serdes_per_fabric_port", m.num_serdes_per_fabric_port));
            archive(::cereal::make_nvp("speed", m.speed));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::fabric_data& m) {
            archive(::cereal::make_nvp("num_serdes_per_fabric_port", m.num_serdes_per_fabric_port));
            archive(::cereal::make_nvp("speed", m.speed));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::fabric_data& m)
{
    serializer_class<silicon_one::device_port_handler_base::fabric_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::fabric_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::fabric_data& m)
{
    serializer_class<silicon_one::device_port_handler_base::fabric_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::fabric_data&);



template<>
class serializer_class<silicon_one::device_port_handler_base::mac_port_config_key> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::mac_port_config_key& m) {
            archive(::cereal::make_nvp("speed", m.speed));
            archive(::cereal::make_nvp("serdes_count", m.serdes_count));
            archive(::cereal::make_nvp("fec_mode", m.fec_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::mac_port_config_key& m) {
            archive(::cereal::make_nvp("speed", m.speed));
            archive(::cereal::make_nvp("serdes_count", m.serdes_count));
            archive(::cereal::make_nvp("fec_mode", m.fec_mode));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::mac_port_config_key& m)
{
    serializer_class<silicon_one::device_port_handler_base::mac_port_config_key>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::mac_port_config_key&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::mac_port_config_key& m)
{
    serializer_class<silicon_one::device_port_handler_base::mac_port_config_key>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::mac_port_config_key&);



template<>
class serializer_class<silicon_one::device_port_handler_base::mac_port_config_key_hasher> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::mac_port_config_key_hasher& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::mac_port_config_key_hasher& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::mac_port_config_key_hasher& m)
{
    serializer_class<silicon_one::device_port_handler_base::mac_port_config_key_hasher>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::mac_port_config_key_hasher&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::mac_port_config_key_hasher& m)
{
    serializer_class<silicon_one::device_port_handler_base::mac_port_config_key_hasher>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::mac_port_config_key_hasher&);



template<>
class serializer_class<silicon_one::device_port_handler_base::serdes_config_key> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::serdes_config_key& m) {
            archive(::cereal::make_nvp("speed", m.speed));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::serdes_config_key& m) {
            archive(::cereal::make_nvp("speed", m.speed));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::serdes_config_key& m)
{
    serializer_class<silicon_one::device_port_handler_base::serdes_config_key>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::serdes_config_key&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::serdes_config_key& m)
{
    serializer_class<silicon_one::device_port_handler_base::serdes_config_key>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::serdes_config_key&);



template<>
class serializer_class<silicon_one::device_port_handler_base::serdes_config_key_hasher> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_base::serdes_config_key_hasher& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_base::serdes_config_key_hasher& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_base::serdes_config_key_hasher& m)
{
    serializer_class<silicon_one::device_port_handler_base::serdes_config_key_hasher>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_base::serdes_config_key_hasher&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_base::serdes_config_key_hasher& m)
{
    serializer_class<silicon_one::device_port_handler_base::serdes_config_key_hasher>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_base::serdes_config_key_hasher&);



template<>
class serializer_class<silicon_one::device_port_handler_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_port_handler_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_port_handler_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_port_handler_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::device_port_handler_base>(&m));
    serializer_class<silicon_one::device_port_handler_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_port_handler_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_port_handler_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::device_port_handler_base>(&m));
    serializer_class<silicon_one::device_port_handler_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_port_handler_gibraltar&);



template<>
class serializer_class<silicon_one::dummy_serdes_device_handler_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::dummy_serdes_device_handler_base& m) {
            archive(::cereal::make_nvp("m_handler_initilized", m.m_handler_initilized));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::dummy_serdes_device_handler_base& m) {
            archive(::cereal::make_nvp("m_handler_initilized", m.m_handler_initilized));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::dummy_serdes_device_handler_base& m)
{
    archive(cereal::base_class<silicon_one::serdes_device_handler>(&m));
    serializer_class<silicon_one::dummy_serdes_device_handler_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::dummy_serdes_device_handler_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::dummy_serdes_device_handler_base& m)
{
    archive(cereal::base_class<silicon_one::serdes_device_handler>(&m));
    serializer_class<silicon_one::dummy_serdes_device_handler_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::dummy_serdes_device_handler_base&);



template<>
class serializer_class<silicon_one::dummy_serdes_handler_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::dummy_serdes_handler_base& m) {
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_serdes_speed", m.m_serdes_speed));
            archive(::cereal::make_nvp("m_serdes_param_vec", m.m_serdes_param_vec));
            archive(::cereal::make_nvp("m_serdes_slice_mode", m.m_serdes_slice_mode));
            archive(::cereal::make_nvp("m_loopback_mode", m.m_loopback_mode));
            archive(::cereal::make_nvp("m_anlt_lane", m.m_anlt_lane));
            archive(::cereal::make_nvp("m_continuous_tuning_enabled", m.m_continuous_tuning_enabled));
            archive(::cereal::make_nvp("m_continuous_tuning_activated", m.m_continuous_tuning_activated));
            archive(::cereal::make_nvp("m_is_an_enabled", m.m_is_an_enabled));
            archive(::cereal::make_nvp("m_an_spec_cap", m.m_an_spec_cap));
            archive(::cereal::make_nvp("m_an_fec_request", m.m_an_fec_request));
            archive(::cereal::make_nvp("m_serdes_speed_gbps", m.m_serdes_speed_gbps));
            archive(::cereal::make_nvp("m_debug_mode", m.m_debug_mode));
            archive(::cereal::make_nvp("m_tuning_mode", m.m_tuning_mode));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::dummy_serdes_handler_base& m) {
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base_id", m.m_serdes_base_id));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_serdes_speed", m.m_serdes_speed));
            archive(::cereal::make_nvp("m_serdes_param_vec", m.m_serdes_param_vec));
            archive(::cereal::make_nvp("m_serdes_slice_mode", m.m_serdes_slice_mode));
            archive(::cereal::make_nvp("m_loopback_mode", m.m_loopback_mode));
            archive(::cereal::make_nvp("m_anlt_lane", m.m_anlt_lane));
            archive(::cereal::make_nvp("m_continuous_tuning_enabled", m.m_continuous_tuning_enabled));
            archive(::cereal::make_nvp("m_continuous_tuning_activated", m.m_continuous_tuning_activated));
            archive(::cereal::make_nvp("m_is_an_enabled", m.m_is_an_enabled));
            archive(::cereal::make_nvp("m_an_spec_cap", m.m_an_spec_cap));
            archive(::cereal::make_nvp("m_an_fec_request", m.m_an_fec_request));
            archive(::cereal::make_nvp("m_serdes_speed_gbps", m.m_serdes_speed_gbps));
            archive(::cereal::make_nvp("m_debug_mode", m.m_debug_mode));
            archive(::cereal::make_nvp("m_tuning_mode", m.m_tuning_mode));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::dummy_serdes_handler_base& m)
{
    archive(cereal::base_class<silicon_one::serdes_handler>(&m));
    serializer_class<silicon_one::dummy_serdes_handler_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::dummy_serdes_handler_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::dummy_serdes_handler_base& m)
{
    archive(cereal::base_class<silicon_one::serdes_handler>(&m));
    serializer_class<silicon_one::dummy_serdes_handler_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::dummy_serdes_handler_base&);



template<>
class serializer_class<silicon_one::dummy_serdes_handler_base::serdes_param_setting> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::dummy_serdes_handler_base::serdes_param_setting& m) {
            archive(::cereal::make_nvp("mode", m.mode));
            archive(::cereal::make_nvp("value", m.value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::dummy_serdes_handler_base::serdes_param_setting& m) {
            archive(::cereal::make_nvp("mode", m.mode));
            archive(::cereal::make_nvp("value", m.value));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::dummy_serdes_handler_base::serdes_param_setting& m)
{
    serializer_class<silicon_one::dummy_serdes_handler_base::serdes_param_setting>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::dummy_serdes_handler_base::serdes_param_setting&);

template <class Archive>
void
load(Archive& archive, silicon_one::dummy_serdes_handler_base::serdes_param_setting& m)
{
    serializer_class<silicon_one::dummy_serdes_handler_base::serdes_param_setting>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::dummy_serdes_handler_base::serdes_param_setting&);



template<>
class serializer_class<silicon_one::hld_notification_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::hld_notification_base& m) {
            archive(::cereal::make_nvp("m_notification_pipes", m.m_notification_pipes));
            archive(::cereal::make_nvp("m_notification_pipes_errors", m.m_notification_pipes_errors));
            archive(::cereal::make_nvp("m_notify_mask", m.m_notify_mask));
            archive(::cereal::make_nvp("m_worker_interrupt", m.m_worker_interrupt));
            archive(::cereal::make_nvp("m_notification_id", m.m_notification_id));
            archive(::cereal::make_nvp("m_next_restore_interrupt_masks", m.m_next_restore_interrupt_masks));
            archive(::cereal::make_nvp("m_next_reset_interrupt_counters", m.m_next_reset_interrupt_counters));
            archive(::cereal::make_nvp("m_next_poll_non_wired_interrupts", m.m_next_poll_non_wired_interrupts));
            archive(::cereal::make_nvp("m_mac_pool_serdes_bases", m.m_mac_pool_serdes_bases));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_interrupt_tree", m.m_interrupt_tree));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::hld_notification_base& m) {
            archive(::cereal::make_nvp("m_notification_pipes", m.m_notification_pipes));
            archive(::cereal::make_nvp("m_notification_pipes_errors", m.m_notification_pipes_errors));
            archive(::cereal::make_nvp("m_notify_mask", m.m_notify_mask));
            archive(::cereal::make_nvp("m_worker_interrupt", m.m_worker_interrupt));
            archive(::cereal::make_nvp("m_notification_id", m.m_notification_id));
            archive(::cereal::make_nvp("m_next_restore_interrupt_masks", m.m_next_restore_interrupt_masks));
            archive(::cereal::make_nvp("m_next_reset_interrupt_counters", m.m_next_reset_interrupt_counters));
            archive(::cereal::make_nvp("m_next_poll_non_wired_interrupts", m.m_next_poll_non_wired_interrupts));
            archive(::cereal::make_nvp("m_mac_pool_serdes_bases", m.m_mac_pool_serdes_bases));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_interrupt_tree", m.m_interrupt_tree));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::hld_notification_base& m)
{
    serializer_class<silicon_one::hld_notification_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::hld_notification_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::hld_notification_base& m)
{
    serializer_class<silicon_one::hld_notification_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::hld_notification_base&);



template<>
class serializer_class<silicon_one::hld_notification_base::worker> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::hld_notification_base::worker& m) {
            archive(::cereal::make_nvp("self_pipe", m.self_pipe));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::hld_notification_base::worker& m) {
            archive(::cereal::make_nvp("self_pipe", m.self_pipe));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::hld_notification_base::worker& m)
{
    serializer_class<silicon_one::hld_notification_base::worker>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::hld_notification_base::worker&);

template <class Archive>
void
load(Archive& archive, silicon_one::hld_notification_base::worker& m)
{
    serializer_class<silicon_one::hld_notification_base::worker>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::hld_notification_base::worker&);



template<>
class serializer_class<silicon_one::hld_notification_base::mac_pool_serdes_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::hld_notification_base::mac_pool_serdes_base& m) {
            archive(::cereal::make_nvp("slice_i", m.slice_i));
            archive(::cereal::make_nvp("ifg_i", m.ifg_i));
            archive(::cereal::make_nvp("serdes_base", m.serdes_base));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::hld_notification_base::mac_pool_serdes_base& m) {
            archive(::cereal::make_nvp("slice_i", m.slice_i));
            archive(::cereal::make_nvp("ifg_i", m.ifg_i));
            archive(::cereal::make_nvp("serdes_base", m.serdes_base));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::hld_notification_base::mac_pool_serdes_base& m)
{
    serializer_class<silicon_one::hld_notification_base::mac_pool_serdes_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::hld_notification_base::mac_pool_serdes_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::hld_notification_base::mac_pool_serdes_base& m)
{
    serializer_class<silicon_one::hld_notification_base::mac_pool_serdes_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::hld_notification_base::mac_pool_serdes_base&);



template<>
class serializer_class<silicon_one::hld_notification_base::interrupt_groups> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::hld_notification_base::interrupt_groups& m) {
            archive(::cereal::make_nvp("mem_protect_nodes", m.mem_protect_nodes));
            archive(::cereal::make_nvp("lpm_sram_mem_protect", m.lpm_sram_mem_protect));
            archive(::cereal::make_nvp("max_counter_group", m.max_counter_group));
            archive(::cereal::make_nvp("credit_dev_unreachable", m.credit_dev_unreachable));
            archive(::cereal::make_nvp("queue_aged_out", m.queue_aged_out));
            archive(::cereal::make_nvp("mmu_has_error_buffer", m.mmu_has_error_buffer));
            archive(::cereal::make_nvp("link_down_ports", m.link_down_ports));
            archive(::cereal::make_nvp("link_error_ports", m.link_error_ports));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::hld_notification_base::interrupt_groups& m) {
            archive(::cereal::make_nvp("mem_protect_nodes", m.mem_protect_nodes));
            archive(::cereal::make_nvp("lpm_sram_mem_protect", m.lpm_sram_mem_protect));
            archive(::cereal::make_nvp("max_counter_group", m.max_counter_group));
            archive(::cereal::make_nvp("credit_dev_unreachable", m.credit_dev_unreachable));
            archive(::cereal::make_nvp("queue_aged_out", m.queue_aged_out));
            archive(::cereal::make_nvp("mmu_has_error_buffer", m.mmu_has_error_buffer));
            archive(::cereal::make_nvp("link_down_ports", m.link_down_ports));
            archive(::cereal::make_nvp("link_error_ports", m.link_error_ports));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::hld_notification_base::interrupt_groups& m)
{
    serializer_class<silicon_one::hld_notification_base::interrupt_groups>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::hld_notification_base::interrupt_groups&);

template <class Archive>
void
load(Archive& archive, silicon_one::hld_notification_base::interrupt_groups& m)
{
    serializer_class<silicon_one::hld_notification_base::interrupt_groups>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::hld_notification_base::interrupt_groups&);



template<>
class serializer_class<silicon_one::hld_notification_gibraltar> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::hld_notification_gibraltar& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::hld_notification_gibraltar& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::hld_notification_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::hld_notification_base>(&m));
    serializer_class<silicon_one::hld_notification_gibraltar>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::hld_notification_gibraltar&);

template <class Archive>
void
load(Archive& archive, silicon_one::hld_notification_gibraltar& m)
{
    archive(cereal::base_class<silicon_one::hld_notification_base>(&m));
    serializer_class<silicon_one::hld_notification_gibraltar>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::hld_notification_gibraltar&);



template<>
class serializer_class<silicon_one::ifg_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_handler& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_handler& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_handler& m)
{
    serializer_class<silicon_one::ifg_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_handler& m)
{
    serializer_class<silicon_one::ifg_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_handler&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_vrf_port_common_gibraltar var0;
    ar(var0);
    silicon_one::la_vxlan_next_hop_gibraltar var1;
    ar(var1);
    silicon_one::device_port_handler_gibraltar var2;
    ar(var2);
    silicon_one::dummy_serdes_device_handler_base var3;
    ar(var3);
    silicon_one::dummy_serdes_handler_base var4;
    ar(var4);
    silicon_one::hld_notification_gibraltar var5;
    ar(var5);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_vrf_port_common_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_vrf_port_common_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_vxlan_next_hop_base);
CEREAL_REGISTER_TYPE(silicon_one::la_vxlan_next_hop_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::la_meter_set_base);
CEREAL_REGISTER_TYPE(silicon_one::arc_handler_base);
CEREAL_REGISTER_TYPE(silicon_one::device_port_handler_base);
CEREAL_REGISTER_TYPE(silicon_one::device_port_handler_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::dummy_serdes_device_handler_base);
CEREAL_REGISTER_TYPE(silicon_one::dummy_serdes_handler_base);
CEREAL_REGISTER_TYPE(silicon_one::hld_notification_base);
CEREAL_REGISTER_TYPE(silicon_one::hld_notification_gibraltar);
CEREAL_REGISTER_TYPE(silicon_one::ifg_handler);

#pragma GCC diagnostic pop

